from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import harness_product.l0 as l0
from harness_product import Outcome, evaluate
from harness_product.durable import DurableStore
from tests.test_durable import (
    ExactNoEffectVerifier,
    ExactVerifier,
    _bootstrap_raw,
    _consume_from_payload,
    _digest,
    _issue_raw,
    _m1_request,
    _verification_source,
)
from tests.test_l0 import valid_raw


class L0CommittedIntentStageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="harness-l0-stage-")
        self.database = Path(self.temporary.name) / "durable.sqlite3"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def profile(self) -> l0.CompiledL0Profile:
        result = l0.compile_profile(valid_raw())
        self.assertEqual(result.outcome, l0.L0Outcome.COMPILED_DRAFT)
        self.assertIsNotNone(result.profile)
        return result.profile

    def stage_setup(self) -> tuple[l0.CompiledL0Profile, DurableStore, object, str, int, dict[str, object], str]:
        profile = self.profile()
        content = "updated"
        scope = l0._hash_text(l0._canonical({"kind": "PATH_EXACT", "value": "/staging/artifact.txt"}))
        bootstrap = _bootstrap_raw()
        bootstrap["budgets"][0]["scope_digest"] = scope
        request = _m1_request()
        for field in ("proposal", "manifest", "policy", "physical_ceiling", "trusted_facts"):
            request[field]["operation_id"] = "stage-write-v1"
        request["proposal"]["principal_id"] = "agent_worker-1"
        request["proposal"]["material_digest"] = l0._hash_text(content)
        request["trusted_facts"]["material_digest"] = l0._hash_text(content)
        request["proposal"]["authority"]["selector"] = {"kind": "PATH_EXACT", "value": "/staging/artifact.txt"}
        for field in ("manifest", "policy", "physical_ceiling", "trusted_facts"):
            request[field]["authority"][0]["selector"] = {"kind": "PATH_PREFIX", "value": "/staging"}
        evaluated = evaluate(request)
        self.assertEqual(evaluated.decision.outcome, Outcome.ALLOW, evaluated)
        issue = _issue_raw()
        issue.update(
            request=request,
            audience_id="executor-3",
            profile_digest=profile.profile_digest,
            session_id="session-1",
            budget=[{**issue["budget"][0], "scope_digest": scope}],
        )
        verifier = ExactVerifier()
        store = DurableStore(
            str(self.database), verifier, no_effect_verifier=ExactNoEffectVerifier(), executor_claim_verifier=verifier
        )
        self.assertTrue(store.bootstrap(bootstrap).committed)
        issued = store.issue(issue)
        self.assertTrue(issued.committed, issued)
        import sqlite3
        import json

        with sqlite3.connect(self.database) as connection:
            payload = json.loads(connection.execute("SELECT payload_json FROM capabilities").fetchone()[0])
        self.assertTrue(store.consume(_consume_from_payload(issued.capability_id, payload)).committed)
        claim = store.claim_dispatch(
            {"transaction_id": "transaction-0001", "observed_at": "2026-08-25T12:02:00Z", "executor_verification": _verification_source()}
        )
        self.assertTrue(claim.committed)
        self.assertIsNotNone(claim.dispatch_claim)
        root = Path(self.temporary.name) / "root"
        root.mkdir(mode=0o700)
        os.chmod(root, 0o700)
        target = root / "artifact.txt"
        target.write_text("old", encoding="utf-8")
        descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        binding = l0.resolve_target(
            profile,
            descriptor,
            {"canonical_path": "/staging/artifact.txt", "descriptor_id": "stage-target", "root_id": "stage-root", "resolution_epoch": 1},
        )
        self.assertIsNotNone(binding.binding)
        return profile, store, claim.dispatch_claim, content, descriptor, binding.binding.data(), str(target)

    def stage_raw(self, claim: object, content: str, binding: dict[str, object]) -> dict[str, object]:
        return {
            "transaction_id": claim.transaction_id,
            "claim_digest": claim.claim_digest,
            "operation": "WRITE_FILE_REPLACE",
            "content": content,
            "content_digest": l0._hash_text(content),
            "target_binding": binding,
        }

    def test_exact_claim_stages_once_inside_temp_0700_root_and_replay_never_writes_again(self) -> None:
        profile, _, claim, content, descriptor, binding, target = self.stage_setup()
        try:
            raw = self.stage_raw(claim, content, binding)
            result = l0.stage_committed_intent(profile, claim, descriptor, raw, executor_claim_verifier=ExactVerifier())
            self.assertEqual((result.outcome, result.reason), (l0.L0Outcome.STAGED, l0.L0Reason.STAGED))
            self.assertIsNotNone(result.record)
            self.assertEqual(Path(target).read_text(encoding="utf-8"), content)
            replay = l0.stage_committed_intent(profile, claim, descriptor, raw, executor_claim_verifier=ExactVerifier())
            self.assertEqual(replay.outcome, l0.L0Outcome.STOP)
            self.assertEqual(Path(target).read_text(encoding="utf-8"), content)
        finally:
            os.close(descriptor)

    def test_forged_claim_bindings_profile_material_and_target_are_rejected_before_effect(self) -> None:
        profile, _, claim, content, descriptor, binding, target = self.stage_setup()
        try:
            raw = self.stage_raw(claim, content, binding)
            cases = (
                (profile, True, raw, None),
                (profile, replace(claim, audience_id="other-executor"), raw, ExactVerifier()),
                (replace(profile, profile_digest=_digest("f")), claim, raw, ExactVerifier()),
                (profile, claim, {**raw, "content_digest": _digest("e")}, ExactVerifier()),
                (profile, claim, {**raw, "target_binding": {**binding, "final_digest": _digest("d")}}, ExactVerifier()),
                (profile, claim, raw, None),
            )
            for tested_profile, tested_claim, tested_raw, verifier in cases:
                with self.subTest(tested_claim=tested_claim, verifier=verifier):
                    result = l0.stage_committed_intent(
                        tested_profile, tested_claim, descriptor, deepcopy(tested_raw), executor_claim_verifier=verifier
                    )
                    self.assertEqual(result.outcome, l0.L0Outcome.STOP)
                    self.assertIsNone(result.record)
                    self.assertEqual(Path(target).read_text(encoding="utf-8"), "old")
        finally:
            os.close(descriptor)

    def test_post_effect_fault_is_quarantined_and_cannot_retry_the_same_binding(self) -> None:
        profile, _, claim, content, descriptor, binding, target = self.stage_setup()
        try:
            raw = self.stage_raw(claim, content, binding)
            with patch.object(l0.os, "fsync", side_effect=OSError("forced post-write failure")):
                uncertain = l0.stage_committed_intent(profile, claim, descriptor, raw, executor_claim_verifier=ExactVerifier())
            self.assertEqual((uncertain.outcome, uncertain.reason), (l0.L0Outcome.QUARANTINED, l0.L0Reason.STAGE_OUTCOME_UNKNOWN))
            self.assertEqual(Path(target).read_text(encoding="utf-8"), content)
            retry = l0.stage_committed_intent(profile, claim, descriptor, raw, executor_claim_verifier=ExactVerifier())
            self.assertEqual(retry.outcome, l0.L0Outcome.STOP)
        finally:
            os.close(descriptor)


if __name__ == "__main__":
    unittest.main()
