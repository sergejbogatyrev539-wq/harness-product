from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import os
from pathlib import Path
import sqlite3
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
from tests.test_l0_supply import ExactSupplyVerifier
import tests.test_l0_supply as l0_supply_tests


class L0CommittedIntentStageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="harness-l0-stage-")
        self.database = Path(self.temporary.name) / "durable.sqlite3"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def supply(self, *, expires_at: str = "2026-08-25T13:00:00Z") -> tuple[l0.CompiledL0Profile, l0.SupplyVerification]:
        """Create an externally verified fixture; the frozen record is rechecked at staging."""

        fixture = l0_supply_tests.L0SupplyBoundaryTests(methodName="runTest")
        fixture.setUp()
        try:
            profile, measurement, raw, descriptors, _ = fixture.fixture()
            raw["placement"]["expires_at"] = expires_at
            with patch.object(l0, "_runtime_output", return_value=l0.RUNTIME_VERSION):
                result = l0.verify_supply(profile, measurement, raw, verifier=ExactSupplyVerifier())
            self.assertEqual((result.outcome, result.reason), (l0.L0Outcome.VERIFIED, l0.L0Reason.SUPPLY_VERIFIED))
            self.assertIsNotNone(result.verification)
            return profile, result.verification
        finally:
            fixture.close(descriptors)
            fixture.tearDown()

    def stage_setup(
        self, *, supply_expires_at: str = "2026-08-25T13:00:00Z"
    ) -> tuple[l0.CompiledL0Profile, l0.SupplyVerification, DurableStore, object, str, int, dict[str, object], str]:
        profile, supply = self.supply(expires_at=supply_expires_at)
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
            placement_digest=supply.placement_digest,
            session_id="session-1",
            revocation_epoch=supply.revocation_epoch,
            fencing_epoch=supply.fencing_epoch,
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
        return profile, supply, store, claim.dispatch_claim, content, descriptor, binding.binding.data(), str(target)

    def stage_raw(self, claim: object, content: str, binding: dict[str, object]) -> dict[str, object]:
        return {
            "transaction_id": claim.transaction_id,
            "claim_digest": claim.claim_digest,
            "operation": "WRITE_FILE_REPLACE",
            "content": content,
            "content_digest": l0._hash_text(content),
            "target_binding": binding,
            "stage_authorization_digest": _digest("a"),
            "observed_at": "2026-08-25T12:02:10Z",
        }

    def stage(
        self,
        profile: object,
        claim: object,
        supply: object,
        descriptor: int,
        raw: object,
        *,
        durable_store: object | None = None,
        claim_verifier: object | None = None,
        supply_verifier: object | None = None,
        fault: object | None = None,
    ) -> l0.StageResult:
        with patch.object(l0, "_runtime_output", return_value=l0.RUNTIME_VERSION):
            return l0.stage_committed_intent(
                profile,
                claim,
                supply,
                descriptor,
                raw,
                durable_store=durable_store,
                executor_claim_verifier=claim_verifier,
                supply_verifier=supply_verifier,
                _fault=fault,
            )

    def test_exact_claim_without_m4_authorization_never_stages_or_replays(self) -> None:
        profile, supply, _, claim, content, descriptor, binding, target = self.stage_setup()
        try:
            raw = self.stage_raw(claim, content, binding)
            result = self.stage(profile, claim, supply, descriptor, raw, claim_verifier=ExactVerifier(), supply_verifier=ExactSupplyVerifier())
            self.assertEqual(
                (result.outcome, result.reason),
                (l0.L0Outcome.STOP, l0.L0Reason.STAGE_AUTHORIZATION_REQUIRED),
            )
            self.assertIsNone(result.record)
            self.assertEqual(Path(target).read_text(encoding="utf-8"), "old")
            replay = self.stage(profile, claim, supply, descriptor, raw, claim_verifier=ExactVerifier(), supply_verifier=ExactSupplyVerifier())
            self.assertEqual(replay.outcome, l0.L0Outcome.STOP)
            self.assertEqual(Path(target).read_text(encoding="utf-8"), "old")
        finally:
            os.close(descriptor)

    def test_direct_stage_without_current_durable_authorization_stops_unchanged(self) -> None:
        profile, supply, _, claim, content, descriptor, binding, target = self.stage_setup()
        try:
            with sqlite3.connect(self.database) as connection:
                before = (
                    connection.execute(
                        "SELECT remaining, reserved, spent FROM budgets"
                    ).fetchone(),
                    connection.execute("SELECT COUNT(*) FROM journal_entries").fetchone(),
                    connection.execute("SELECT COUNT(*) FROM m4_transactions").fetchone(),
                )
            result = self.stage(
                profile,
                claim,
                supply,
                descriptor,
                self.stage_raw(claim, content, binding),
                claim_verifier=ExactVerifier(),
                supply_verifier=ExactSupplyVerifier(),
            )
            with sqlite3.connect(self.database) as connection:
                after = (
                    connection.execute(
                        "SELECT remaining, reserved, spent FROM budgets"
                    ).fetchone(),
                    connection.execute("SELECT COUNT(*) FROM journal_entries").fetchone(),
                    connection.execute("SELECT COUNT(*) FROM m4_transactions").fetchone(),
                )
            self.assertEqual(result.outcome, l0.L0Outcome.STOP)
            self.assertEqual(result.reason, l0.L0Reason.STAGE_AUTHORIZATION_REQUIRED)
            self.assertIsNone(result.record)
            self.assertEqual(Path(target).read_text(encoding="utf-8"), "old")
            self.assertEqual(after, before)
        finally:
            os.close(descriptor)

    def test_claim_and_supply_substitutions_are_rejected_before_effect(self) -> None:
        profile, supply, _, claim, content, descriptor, binding, target = self.stage_setup()
        try:
            raw = self.stage_raw(claim, content, binding)
            cases = (
                (profile, True, supply, raw, ExactVerifier(), ExactSupplyVerifier()),
                (profile, replace(claim, audience_id="other-executor"), supply, raw, ExactVerifier(), ExactSupplyVerifier()),
                (replace(profile, profile_digest=_digest("f")), claim, supply, raw, ExactVerifier(), ExactSupplyVerifier()),
                (profile, claim, supply, {**raw, "content_digest": _digest("e")}, ExactVerifier(), ExactSupplyVerifier()),
                (profile, claim, supply, {**raw, "target_binding": {**binding, "final_digest": _digest("d")}}, ExactVerifier(), ExactSupplyVerifier()),
                (profile, claim, None, raw, ExactVerifier(), ExactSupplyVerifier()),
                (profile, claim, replace(supply, supply_digest=_digest("b")), raw, ExactVerifier(), ExactSupplyVerifier()),
                (profile, claim, replace(supply, placement_digest=_digest("c")), raw, ExactVerifier(), ExactSupplyVerifier()),
                (profile, claim, replace(supply, session_id="other-session"), raw, ExactVerifier(), ExactSupplyVerifier()),
                (profile, claim, replace(supply, fencing_epoch=12), raw, ExactVerifier(), ExactSupplyVerifier()),
                (profile, claim, replace(supply, revocation_epoch=8), raw, ExactVerifier(), ExactSupplyVerifier()),
                (profile, claim, supply, raw, None, ExactSupplyVerifier()),
                (profile, claim, supply, raw, ExactVerifier(), None),
            )
            for tested_profile, tested_claim, tested_supply, tested_raw, claim_verifier, supply_verifier in cases:
                with self.subTest(tested_claim=tested_claim, tested_supply=tested_supply):
                    result = self.stage(
                        tested_profile,
                        tested_claim,
                        tested_supply,
                        descriptor,
                        deepcopy(tested_raw),
                        claim_verifier=claim_verifier,
                        supply_verifier=supply_verifier,
                    )
                    self.assertEqual(result.outcome, l0.L0Outcome.STOP)
                    self.assertIsNone(result.record)
                    self.assertEqual(Path(target).read_text(encoding="utf-8"), "old")
        finally:
            os.close(descriptor)

    def test_stale_externally_verified_supply_stops_before_staging_effect(self) -> None:
        profile, supply, _, claim, content, descriptor, binding, target = self.stage_setup(supply_expires_at="2026-08-25T12:01:00Z")
        try:
            result = self.stage(
                profile,
                claim,
                supply,
                descriptor,
                self.stage_raw(claim, content, binding),
                claim_verifier=ExactVerifier(),
                supply_verifier=ExactSupplyVerifier(),
            )
            self.assertEqual(result.outcome, l0.L0Outcome.STOP)
            self.assertIsNone(result.record)
            self.assertEqual(Path(target).read_text(encoding="utf-8"), "old")
        finally:
            os.close(descriptor)

    def test_missing_authorization_stops_before_post_effect_fault_seam(self) -> None:
        profile, supply, _, claim, content, descriptor, binding, target = self.stage_setup()
        try:
            raw = self.stage_raw(claim, content, binding)
            reached: list[str] = []

            def fault(point: str) -> None:
                reached.append(point)
                if point == "stage_after_write":
                    raise OSError("post-effect seam must be unreachable")

            stopped = self.stage(
                profile,
                claim,
                supply,
                descriptor,
                raw,
                claim_verifier=ExactVerifier(),
                supply_verifier=ExactSupplyVerifier(),
                fault=fault,
            )
            self.assertEqual(
                (stopped.outcome, stopped.reason),
                (l0.L0Outcome.STOP, l0.L0Reason.STAGE_AUTHORIZATION_REQUIRED),
            )
            self.assertNotIn("stage_after_write", reached)
            self.assertEqual(Path(target).read_text(encoding="utf-8"), "old")
        finally:
            os.close(descriptor)


if __name__ == "__main__":
    unittest.main()
