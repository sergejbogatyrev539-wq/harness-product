from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import errno
import fcntl
import json
import os
from pathlib import Path
import resource
import select
import signal
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

import harness_product
import harness_product.durable as durable
import harness_product.l0 as l0
import harness_product.m4 as m4
import harness_product.publisher as publisher
from harness_product.durable import DurableStore, canonical_digest

from tests import test_durable as m2
from tests import test_l0_supply as supply_tests
from tests.test_l0_supply import ExactSupplyVerifier
from tests.test_m4_durable import _DynamicM4Source, _inventory


class _GrantRuntimeFake:
    def __init__(
        self,
        *,
        wrong_observer_subject: bool = False,
        wrong_publication_key: bool = False,
        tamper_continuity: str | None = None,
    ) -> None:
        self.preflight_calls: list[dict[str, object]] = []
        self.stage_grants: list[durable.StageExecutionGrant] = []
        self.events: list[str] = []
        self.publisher: publisher.TrustedPublisher | None = None
        self.wrong_observer_subject = wrong_observer_subject
        self.wrong_publication_key = wrong_publication_key
        self.tamper_continuity = tamper_continuity

    def attach_publisher(self, value: publisher.TrustedPublisher) -> None:
        self.publisher = value

    def preflight(
        self,
        profile: l0.CompiledL0Profile,
        claim: durable.DispatchClaim,
        supply: l0.SupplyVerification,
        staging_binding: l0.PathBinding,
        observed_at: str,
    ) -> m4.RuntimeContinuity:
        payload = {
            "runtime_version": "1.0.0",
            "outcome": "READY",
            "transaction_id": claim.transaction_id,
            "claim_digest": claim.claim_digest,
            "profile_digest": profile.profile_digest,
            "placement_digest": supply.placement_digest,
            "session_id": claim.session_id,
            "revocation_epoch": claim.revocation_epoch,
            "fencing_epoch": claim.fencing_epoch,
            "executor_principal": claim.audience_id,
            "executor_session": "executor-session-1",
            "staging_binding_digest": staging_binding.composite_binding_digest,
            "observed_at": observed_at,
            "expires_at": supply.expires_at,
        }
        self.preflight_calls.append(payload)
        self.events.append("PREFLIGHT")
        return m4.RuntimeContinuity(payload, m2._verification_source())

    def stage(
        self,
        profile: l0.CompiledL0Profile,
        claim: durable.DispatchClaim,
        supply: l0.SupplyVerification,
        root_descriptor: int,
        stage_request: dict[str, object],
        stage_execution_grant: durable.StageExecutionGrant,
        claim_verifier_factory: object,
        supply_verifier_factory: object,
        m4_verifier_factory: object,
    ) -> m4.RuntimeStageExecution:
        self.stage_grants.append(stage_execution_grant)
        result = l0.stage_committed_intent(
            profile,
            claim,
            supply,
            root_descriptor,
            stage_request,
            stage_execution_grant=stage_execution_grant,
            m4_verifier=m4_verifier_factory(),
            executor_claim_verifier=claim_verifier_factory(),
            supply_verifier=supply_verifier_factory(),
        )
        if result.record is None:
            raise RuntimeError(result.reason.value)
        self.events.append("STAGE")
        return m4.RuntimeStageExecution(result.record, os.getpid(), os.getsid(0))

    def observe(
        self,
        profile: l0.CompiledL0Profile,
        snapshot_descriptor: int,
        snapshot: m4.M4Snapshot,
        receipt_body: dict[str, object],
    ) -> m4.RuntimeObserverReceipt:
        pid, session, uid, gid, proposal_digest = m4._postcheck_child(
            profile, snapshot_descriptor, snapshot
        )
        body = {
            **receipt_body,
            "outcome": "PASS",
            "observer_subject": receipt_body["observer_subject"],
            "proposal_digest": proposal_digest,
        }
        receipt = {**body, "receipt_digest": canonical_digest(body)}
        if self.wrong_observer_subject:
            receipt["observer_subject"] = {
                **receipt["observer_subject"],
                "principal_id": "publisher-1",
            }
            receipt["receipt_digest"] = canonical_digest(
                {key: receipt[key] for key in receipt if key != "receipt_digest"}
            )
        self.events.append("OBSERVE")
        return m4.RuntimeObserverReceipt(
            receipt,
            m2._verification_source(),
            pid,
            session,
            uid,
            gid,
        )

    def publish(
        self,
        snapshot_descriptor: int,
        authorization: dict[str, object],
        authorization_verification: dict[str, object],
        observed_at: str,
        fault: object | None,
    ) -> m4.RuntimePublicationReceipt:
        if self.publisher is None or fault is not None:
            raise RuntimeError("publisher unavailable")
        result = self.publisher.publish(
            snapshot_descriptor,
            authorization,
            authorization_verification,
            observed_at,
        )
        if result.fact is None:
            raise RuntimeError(result.reason.value)
        self.events.append("PUBLISH")
        source = m2._verification_source()
        if self.wrong_publication_key:
            source = {**source, "key_id": "wrong-key"}
        return m4.RuntimePublicationReceipt(result.fact, source)

    def continuity(
        self,
        purpose: str,
        payload: dict[str, object],
    ) -> m4.RuntimeContinuity:
        if self.publisher is None or not self.publisher.continuity():
            raise RuntimeError("continuity lost")
        self.events.append(purpose)
        value = dict(payload)
        if self.tamper_continuity == purpose:
            value["publication_root_anchor_digest"] = m2._digest("9")
        return m4.RuntimeContinuity(value, m2._verification_source())


def _contract(issue: dict[str, object], scope_digest: str) -> dict[str, object]:
    body: dict[str, object] = {
        "contract_version": "2.0.0",
        "authority_domain_id": "dev-stageable-local",
        "journal_lineage_id": "journal-lineage-1",
        "root_contract_digest": m2._digest("b"),
        "parent_contract_digest": None,
        "lineage_root": m2.LINEAGE,
        "authority_digest": canonical_digest(issue["request"]["proposal"]["authority"]),
        "target_authority_digest": issue["target_authority_digest"],
        "profile_digest": issue["profile_digest"],
        "operation_kind": "STAGEABLE_FILESYSTEM",
        "external_branch": "DENY",
        "max_iterations": 1,
        "joined_iteration": 0,
        "postcheck_required": True,
        "independent_observer_required": True,
        "budget_vector": [
            {
                "name": "writes",
                "unit": "FILES",
                "scope_digest": scope_digest,
                "lineage_root": m2.LINEAGE,
                "limit": 10,
            }
        ],
        "issued_at": "2026-08-25T11:59:00Z",
        "expires_at": "2026-08-25T12:04:00Z",
        "revocation_epoch": 7,
        "fencing_epoch": 11,
    }
    body["contract_digest"] = canonical_digest(body)
    return body


class M4CoordinatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="harness-m4-")
        self.root = Path(self.temporary.name)
        self.database = self.root / "durable.sqlite3"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def supply(self) -> tuple[l0.CompiledL0Profile, l0.SupplyVerification]:
        fixture = supply_tests.L0SupplyBoundaryTests(methodName="runTest")
        fixture.setUp()
        try:
            profile, measurement, raw, descriptors, _ = fixture.fixture()
            raw["placement"]["expires_at"] = "2026-08-25T13:00:00Z"
            with patch.object(l0, "_runtime_output", return_value=l0.RUNTIME_VERSION):
                result = l0.verify_supply(
                    profile, measurement, raw, verifier=ExactSupplyVerifier()
                )
            self.assertEqual(result.outcome, l0.L0Outcome.VERIFIED)
            self.assertIsNotNone(result.verification)
            return profile, result.verification
        finally:
            fixture.close(descriptors)
            fixture.tearDown()

    def row(self, statement: str) -> tuple[object, ...]:
        with sqlite3.connect(self.database) as connection:
            value = connection.execute(statement).fetchone()
        self.assertIsNotNone(value)
        return value

    @staticmethod
    def runtime_raw(chain: dict[str, object]) -> dict[str, object]:
        return {
            "runtime_version": "1.0.0",
            "transaction_id": chain["raw"]["transaction_id"],
            "d2_frontier_digest": chain["raw"]["d2_frontier_digest"],
            "stage_request": chain["raw"]["stage_request"],
            "observed_at": chain["raw"]["observed_at"],
        }

    def test_m4_effect_primitives_are_not_public_api(self) -> None:
        forbidden = {
            "M4Coordinator",
            "TrustedPublisher",
            "publish",
            "stage_committed_intent",
        }
        self.assertTrue(forbidden.isdisjoint(harness_product.__all__))
        self.assertTrue(all(not hasattr(harness_product, name) for name in forbidden))
        self.assertNotIn("stage_committed_intent", l0.__all__)

    def test_publication_namespace_identity_does_not_follow_nsfs_magic_link(
        self,
    ) -> None:
        with (
            patch.object(
                publisher.os,
                "stat",
                side_effect=AssertionError("namespace magic link was followed"),
            ),
            patch.object(
                publisher.os,
                "readlink",
                return_value="mnt:[4026531832]",
            ),
        ):
            self.assertEqual(
                publisher._mount_namespace_id(),
                "mntns:4026531832",
            )
        with patch.object(publisher.os, "readlink", return_value="mnt:[0]"):
            with self.assertRaises(publisher._Stop):
                publisher._mount_namespace_id()

    def test_controller_without_exact_publisher_boundary_cannot_start(self) -> None:
        chain = self.setup_chain()
        root_descriptor = os.open(
            chain["target"].parent,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
        )
        common = {
            "store": chain["store"],
            "profile": chain["profile"],
            "staging_root_descriptor": root_descriptor,
            "topology_verification": m2._verification_source(),
            "executor_claim_verifier_factory": m2.ExactVerifier,
            "supply_verifier_factory": ExactSupplyVerifier,
            "external_verifier_factory": m2.ExactVerifier,
            "principals": m4.M4Principals(
                controller_principal="controller-1",
                controller_session="controller-session-1",
                observer_principal="observer-1",
                observer_session="observer-session-1",
            ),
        }
        try:
            for name, topology, boundary in (
                ("missing-topology", None, chain["publisher"]),
                ("missing-publisher", chain["topology"], None),
                ("generic-publisher", chain["topology"], object()),
            ):
                with self.subTest(case=name), self.assertRaises(ValueError):
                    m4.M4Coordinator(
                        **common,
                        topology=topology,
                        trusted_publisher=boundary,
                    )
            original = chain["publisher"]._topology
            chain["publisher"]._topology = replace(original, topology_id="other-topology")
            try:
                with self.subTest(case="mismatched-publisher"), self.assertRaises(
                    ValueError
                ):
                    m4.M4Coordinator(
                        **common,
                        topology=chain["topology"],
                        trusted_publisher=chain["publisher"],
                    )
            finally:
                chain["publisher"]._topology = original
        finally:
            os.close(root_descriptor)
        self.assertEqual(chain["target"].read_text(encoding="utf-8"), "old\n")
        self.assertEqual(
            chain["publication_target"].read_text(encoding="utf-8"),
            "published-old\n",
        )
        self.assertEqual(self.row("SELECT COUNT(*) FROM m4_transactions"), (0,))

    def writer_attempt(self, target: Path) -> int:
        read_descriptor, write_descriptor = os.pipe2(os.O_CLOEXEC)
        pid = os.fork()
        if pid == 0:
            try:
                os.close(read_descriptor)
                try:
                    descriptor = os.open(
                        target,
                        os.O_WRONLY | os.O_NONBLOCK | os.O_CLOEXEC,
                    )
                except OSError as error:
                    result = error.errno
                else:
                    os.close(descriptor)
                    result = 0
                os.write(write_descriptor, str(result).encode("ascii"))
                os._exit(0)
            except BaseException:
                os._exit(125)
        os.close(write_descriptor)
        try:
            readable, _, _ = select.select([read_descriptor], [], [], 3.0)
            if not readable:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
                self.fail("bounded writer attempt did not finish")
            result = int(os.read(read_descriptor, 32).decode("ascii"))
            _, status = os.waitpid(pid, 0)
            self.assertTrue(os.WIFEXITED(status))
            self.assertEqual(os.WEXITSTATUS(status), 0)
            return result
        finally:
            os.close(read_descriptor)

    def setup_chain(
        self,
        *,
        assurance_scope: str = "CODE_MODEL_FIXTURE",
        m4_verification_provider: object | None = None,
        runtime_boundary: object | None = None,
        external_verification_provider: object | None = None,
    ) -> dict[str, object]:
        profile, supply = self.supply()
        content = "m4-sealed-output\n"
        path = "/staging/artifact.txt"
        scope = canonical_digest({"kind": "PATH_EXACT", "value": path})
        request = m2._m1_request()
        for field in ("proposal", "manifest", "policy", "physical_ceiling", "trusted_facts"):
            request[field]["operation_id"] = "stage-write-v1"
        request["proposal"]["principal_id"] = "agent_worker-1"
        request["proposal"]["material_digest"] = l0._hash_text(content)
        request["trusted_facts"]["material_digest"] = l0._hash_text(content)
        request["proposal"]["authority"]["selector"] = {"kind": "PATH_EXACT", "value": path}
        for field in ("manifest", "policy", "physical_ceiling", "trusted_facts"):
            request[field]["authority"][0]["selector"] = {"kind": "PATH_PREFIX", "value": "/staging"}

        stage_root = self.root / "stage"
        stage_root.mkdir(mode=0o700)
        target = stage_root / "artifact.txt"
        target.write_text("old\n", encoding="utf-8")
        publication_root = self.root / "publication"
        publication_root.mkdir(mode=0o700)
        publication_target = publication_root / "artifact.txt"
        publication_target.write_text("published-old\n", encoding="utf-8")
        root_descriptor = os.open(stage_root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        publication_root_descriptor = os.open(
            publication_root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
        )
        resolved = l0.resolve_target(
            profile,
            root_descriptor,
            {
                "canonical_path": path,
                "descriptor_id": "stage-target-1",
                "root_id": "stage-root-1",
                "resolution_epoch": 1,
            },
        )
        published_resolved = l0.resolve_target(
            profile,
            publication_root_descriptor,
            {
                "canonical_path": path,
                "descriptor_id": "publication-target-1",
                "root_id": "publication-root-1",
                "resolution_epoch": 1,
            },
        )
        self.assertEqual(resolved.outcome, l0.L0Outcome.RESOLVED)
        self.assertEqual(published_resolved.outcome, l0.L0Outcome.RESOLVED)
        source_binding = resolved.binding.data()
        publication_binding = published_resolved.binding.data()
        subjects = {
            role: {
                "principal_id": principal,
                "session_id": session,
                "uid": 1100 + index,
                "gid": 2100 + index,
                "security_label": role.lower() + "-label-1",
                "credential_namespace": role.lower() + "-credentials-1",
                "namespace_id": role.lower() + "-namespace-1",
                "executable_digest": m2._digest(str(index)),
            }
            for index, (role, principal, session) in enumerate(
                (
                    ("WORKER", "agent_worker-1", supply.session_id),
                    ("CONTROLLER", "controller-1", "controller-session-1"),
                    ("EXECUTOR", "executor-3", "executor-session-1"),
                    ("OBSERVER", "observer-1", "observer-session-1"),
                    ("PUBLISHER", "publisher-1", "publisher-session-1"),
                ),
                1,
            )
        }
        if runtime_boundary is not None:
            subjects["PUBLISHER"]["uid"] = os.geteuid()
            subjects["PUBLISHER"]["gid"] = os.getegid()
        topology_body = {
            "topology_version": 1,
            "assurance_scope": assurance_scope,
            "topology_id": "m4-topology-1",
            "observed_at": "2026-08-25T12:00:00Z",
            "expires_at": "2026-08-25T12:04:00Z",
            "profile_digest": profile.profile_digest,
            "placement_digest": supply.placement_digest,
            "session_id": supply.session_id,
            "revocation_epoch": supply.revocation_epoch,
            "fencing_epoch": supply.fencing_epoch,
            "staging_binding": source_binding,
            "publication_target_binding": publication_binding,
            "publication_root_anchor": publisher._measure_publication_root(
                publication_root_descriptor
            ).data(),
            "subjects": subjects,
            "sole_writer_principal": "publisher-1",
            "denied_writer_principals": sorted(
                subjects[role]["principal_id"]
                for role in ("WORKER", "CONTROLLER", "EXECUTOR", "OBSERVER")
            ),
            "git_authority": "DENY",
            "transport": "SEALED_FD_ONLY",
        }
        topology_raw = {
            **topology_body,
            "topology_digest": canonical_digest(topology_body),
        }
        compiled_topology = publisher.compile_topology(topology_raw)
        self.assertEqual(compiled_topology.outcome, publisher.PublisherOutcome.READY)
        topology = compiled_topology.topology
        self.assertIsNotNone(topology)

        issue = m2._issue_raw()
        issue.update(
            request=request,
            audience_id="executor-3",
            profile_digest=profile.profile_digest,
            placement_digest=supply.placement_digest,
            session_id=supply.session_id,
            revocation_epoch=supply.revocation_epoch,
            fencing_epoch=supply.fencing_epoch,
            budget=[{**issue["budget"][0], "scope_digest": scope}],
            target_authority_digest=topology.topology_digest,
        )
        contract = _contract(issue, scope)
        issue["contract_digest"] = contract["contract_digest"]
        verifier = m2.ExactVerifier()
        store = DurableStore(
            str(self.database),
            verifier,
            executor_claim_verifier=verifier,
            m4_verifier=verifier,
            m4_verification_provider=m4_verification_provider,
        )
        bootstrap = m2._bootstrap_raw()
        bootstrap["budgets"] = [
            {
                "name": "writes",
                "unit": "FILES",
                "scope_digest": scope,
                "lineage_root": m2.LINEAGE,
                "limit": 10,
            }
        ]
        self.assertTrue(store.bootstrap(bootstrap).committed)
        self.assertTrue(
            store.activate_m4_contract(
                {
                    "contract": contract,
                    "observed_at": "2026-08-25T12:00:00Z",
                    "resolver_verification": m2._verification_source(),
                }
            ).committed
        )
        issued = store.issue(issue)
        self.assertTrue(issued.committed)
        payload = json.loads(self.row("SELECT payload_json FROM capabilities")[0])
        self.assertTrue(store.consume(m2._consume_from_payload(issued.capability_id, payload)).committed)
        claimed = store.claim_dispatch(
            {
                "transaction_id": "transaction-0001",
                "observed_at": "2026-08-25T12:02:00Z",
                "executor_verification": m2._verification_source(),
            }
        )
        self.assertTrue(claimed.committed)
        claim = claimed.dispatch_claim
        self.assertIsNotNone(claim)
        intent_text, intent_digest = self.row(
            "SELECT intent_json, intent_digest FROM dispatch_intents"
        )
        intent = json.loads(intent_text)
        frontier: dict[str, object] = {
            "frontier_version": "2.0.0",
            "contract_digest": contract["contract_digest"],
            "contract_version": "2.0.0",
            "authority_domain_id": contract["authority_domain_id"],
            "journal_lineage_id": contract["journal_lineage_id"],
            "root_contract_digest": contract["root_contract_digest"],
            "parent_contract_digest": None,
            "journal_sequence": self.row("SELECT journal_head_sequence FROM store_meta")[0],
            "attempt_cursor": 0,
            "joined_iteration": 0,
            "iteration": 1,
            "fencing_epoch": 11,
            "issued_at": "2026-08-25T12:02:00Z",
            "expires_at": "2026-08-25T12:04:00Z",
            "inventory": _inventory(
                issued.capability_id, payload, intent, intent_digest, claim.claim_digest
            ),
        }
        frontier["frontier_record_digest"] = canonical_digest(frontier)
        bound = store.bind_m4_frontier(
            {
                "transaction_id": claim.transaction_id,
                "observed_at": "2026-08-25T12:02:01Z",
                "frontier": frontier,
                "frontier_verification": m2._verification_source(),
            }
        )
        self.assertTrue(bound.committed)

        trusted_publisher = publisher.TrustedPublisher(
            profile=profile,
            root_descriptor=publication_root_descriptor,
            topology=topology,
            topology_verification=m2._verification_source(),
            verifier_factory=m2.ExactVerifier,
        )
        if runtime_boundary is not None:
            runtime_boundary.attach_publisher(trusted_publisher)
        coordinator = m4.M4Coordinator(
            store=store,
            profile=profile,
            staging_root_descriptor=root_descriptor,
            topology=topology,
            topology_verification=m2._verification_source(),
            trusted_publisher=(
                None if assurance_scope == "DEPLOYMENT_ATTESTED" else trusted_publisher
            ),
            executor_claim_verifier_factory=m2.ExactVerifier,
            supply_verifier_factory=ExactSupplyVerifier,
            external_verifier_factory=m2.ExactVerifier,
            principals=m4.M4Principals(
                controller_principal="controller-1",
                controller_session="controller-session-1",
                observer_principal="observer-1",
                observer_session="observer-session-1",
            ),
            runtime_boundary=runtime_boundary,
            m4_verifier_factory=m2.ExactVerifier,
            external_verification_provider=external_verification_provider,
        )
        os.close(root_descriptor)
        os.close(publication_root_descriptor)
        times = {
            state: "2026-08-25T12:02:10Z"
            for state in (
                "BEGIN", "STAGED", "QUIESCED", "SEALED", "POSTCHECKED",
                "COMMITTED", "JOINED", "QUARANTINED", "RECONCILING",
            )
        }
        verifications = {
            state: m2._verification_source()
            for state in (
                "STAGED", "QUIESCED", "SEALED", "POSTCHECKED", "COMMITTED",
                "JOINED", "QUARANTINED", "RECONCILING",
            )
        }
        raw = {
            "transaction_id": claim.transaction_id,
            "d2_frontier_digest": bound.d2_frontier_digest,
            "stage_request": {
                "transaction_id": claim.transaction_id,
                "claim_digest": claim.claim_digest,
                "operation": "WRITE_FILE_REPLACE",
                "content": content,
                "content_digest": l0._hash_text(content),
            },
            "observed_at": times,
            "verifications": verifications,
            "external_verifications": {
                "OBSERVER_RECEIPT": m2._verification_source(),
                "PUBLICATION_AUTHORIZATION": m2._verification_source(),
                "PUBLICATION_RECEIPT": m2._verification_source(),
            },
        }
        return {
            "profile": profile,
            "supply": supply,
            "store": store,
            "claim": claim,
            "coordinator": coordinator,
            "raw": raw,
            "target": target,
            "publication_root": publication_root,
            "publication_target": publication_target,
            "topology": topology,
            "publisher": trusted_publisher,
            "content": content,
        }

    def test_exact_stage_seal_postcheck_commit_join(self) -> None:
        chain = self.setup_chain()
        with patch.object(l0, "_runtime_output", return_value=l0.RUNTIME_VERSION):
            result = chain["coordinator"].execute(
                chain["claim"], chain["supply"], chain["raw"]
            )
        self.assertEqual((result.outcome, result.state), (m4.M4Outcome.JOINED, "JOINED"))
        self.assertEqual(chain["target"].read_text(encoding="utf-8"), chain["content"])
        self.assertEqual(
            chain["publication_target"].read_text(encoding="utf-8"), chain["content"]
        )
        self.assertEqual(
            result.snapshot.kernel_seals,
            (fcntl.F_SEAL_GROW, fcntl.F_SEAL_SEAL, fcntl.F_SEAL_SHRINK, fcntl.F_SEAL_WRITE),
        )
        self.assertTrue(result.snapshot.write_denied)
        self.assertTrue(result.snapshot.truncate_denied)
        self.assertNotEqual(result.executor_pid, os.getpid())
        self.assertNotEqual(result.observer_pid, os.getpid())
        self.assertNotEqual(result.observer_session, os.getsid(0))
        self.assertEqual(self.row("SELECT remaining, reserved, spent FROM budgets"), (9, 0, 1))
        self.assertEqual(self.row("SELECT state FROM m4_transactions"), ("JOINED",))
        self.assertEqual(
            self.row(
                "SELECT COUNT(*) FROM journal_entries "
                "WHERE event_type='M4_STAGE_AUTHORIZATION_CONSUMED'"
            ),
            (1,),
        )

    def test_stage_authorization_rejects_alternate_root_and_replay(self) -> None:
        chain = self.setup_chain()
        source = chain["topology"].staging_binding
        begun = chain["store"].begin_m4_transaction(
            {
                "transaction_id": chain["claim"].transaction_id,
                "d2_frontier_digest": chain["raw"]["d2_frontier_digest"],
                "target_binding": source.data(),
                "publication_target_binding_digest": chain[
                    "topology"
                ].publication_target_binding.composite_binding_digest,
                "publication_root_anchor_digest": chain[
                    "topology"
                ].publication_root_anchor.anchor_digest,
                "observed_at": chain["raw"]["observed_at"]["BEGIN"],
                "stage_authorization_verification": chain["raw"]["verifications"][
                    "STAGED"
                ],
            }
        )
        self.assertTrue(begun.committed, begun)
        self.assertIsNotNone(begun.record_digest)

        alternate_root = self.root / "alternate-stage"
        alternate_root.mkdir(mode=0o700)
        alternate_target = alternate_root / "artifact.txt"
        alternate_target.write_text("alternate-old\n", encoding="utf-8")
        descriptor = os.open(
            alternate_root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
        )
        try:
            resolved = l0.resolve_target(
                chain["profile"],
                descriptor,
                {
                    "canonical_path": source.canonical_path,
                    "descriptor_id": "alternate-stage-target",
                    "root_id": "alternate-stage-root",
                    "resolution_epoch": source.resolution_epoch,
                },
            )
            self.assertIsNotNone(resolved.binding)
            with sqlite3.connect(self.database) as connection:
                before = (
                    connection.execute(
                        "SELECT remaining,reserved,spent FROM budgets"
                    ).fetchone(),
                    connection.execute("SELECT COUNT(*) FROM journal_entries").fetchone(),
                    connection.execute(
                        "SELECT COUNT(*) FROM m4_transition_records"
                    ).fetchone(),
                )
            stage_raw = {
                **chain["raw"]["stage_request"],
                "target_binding": resolved.binding.data(),
                "stage_authorization_digest": begun.record_digest,
                "observed_at": chain["raw"]["observed_at"]["STAGED"],
            }
            with patch.object(l0, "_runtime_output", return_value=l0.RUNTIME_VERSION):
                rejected = l0.stage_committed_intent(
                    chain["profile"],
                    chain["claim"],
                    chain["supply"],
                    descriptor,
                    stage_raw,
                    durable_store=chain["store"],
                    executor_claim_verifier=m2.ExactVerifier(),
                    supply_verifier=ExactSupplyVerifier(),
                )
            with sqlite3.connect(self.database) as connection:
                after = (
                    connection.execute(
                        "SELECT remaining,reserved,spent FROM budgets"
                    ).fetchone(),
                    connection.execute("SELECT COUNT(*) FROM journal_entries").fetchone(),
                    connection.execute(
                        "SELECT COUNT(*) FROM m4_transition_records"
                    ).fetchone(),
                )
            self.assertEqual(rejected.outcome, l0.L0Outcome.STOP)
            self.assertEqual(alternate_target.read_text(encoding="utf-8"), "alternate-old\n")
            self.assertEqual(after, before)

            consumed = chain["store"].consume_m4_stage_authorization(
                {
                    "transaction_id": chain["claim"].transaction_id,
                    "stage_authorization_digest": begun.record_digest,
                    "target_binding": source.data(),
                    "observed_at": chain["raw"]["observed_at"]["STAGED"],
                }
            )
            self.assertTrue(consumed.committed, consumed)
            journal_before_replay = self.row(
                "SELECT COUNT(*) FROM journal_entries"
            )
            replay = chain["store"].consume_m4_stage_authorization(
                {
                    "transaction_id": chain["claim"].transaction_id,
                    "stage_authorization_digest": begun.record_digest,
                    "target_binding": source.data(),
                    "observed_at": chain["raw"]["observed_at"]["STAGED"],
                }
            )
            self.assertFalse(replay.committed)
            self.assertEqual(
                self.row("SELECT COUNT(*) FROM journal_entries"), journal_before_replay
            )
        finally:
            os.close(descriptor)

    def test_reconciling_transaction_blocks_direct_stage_without_mutation(self) -> None:
        chain = self.setup_chain()

        def fault(point: str) -> None:
            if point == "after_commit":
                raise RuntimeError(point)

        with patch.object(l0, "_runtime_output", return_value=l0.RUNTIME_VERSION):
            result = chain["coordinator"].execute(
                chain["claim"], chain["supply"], chain["raw"], _fault=fault
            )
        self.assertEqual((result.outcome, result.state), (m4.M4Outcome.QUARANTINED, "RECONCILING"))

        dispatch_event = json.loads(
            self.row(
                "SELECT payload_json FROM journal_entries "
                "WHERE event_type='M4_DISPATCH_BOUND'"
            )[0]
        )
        authorization_digest = dispatch_event["stage_authorization"][
            "authorization_digest"
        ]
        alternate_root = self.root / "reconciling-alternate"
        alternate_root.mkdir(mode=0o700)
        alternate_target = alternate_root / "artifact.txt"
        alternate_target.write_text("reconciling-old\n", encoding="utf-8")
        descriptor = os.open(
            alternate_root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
        )
        try:
            resolved = l0.resolve_target(
                chain["profile"],
                descriptor,
                {
                    "canonical_path": chain["topology"].staging_binding.canonical_path,
                    "descriptor_id": "reconciling-stage-target",
                    "root_id": "reconciling-stage-root",
                    "resolution_epoch": 1,
                },
            )
            self.assertIsNotNone(resolved.binding)
            with sqlite3.connect(self.database) as connection:
                before = (
                    connection.execute(
                        "SELECT remaining,reserved,spent FROM budgets"
                    ).fetchone(),
                    connection.execute("SELECT COUNT(*) FROM journal_entries").fetchone(),
                    connection.execute(
                        "SELECT COUNT(*) FROM m4_transition_records"
                    ).fetchone(),
                )
            stage_raw = {
                **chain["raw"]["stage_request"],
                "target_binding": resolved.binding.data(),
                "stage_authorization_digest": authorization_digest,
                "observed_at": chain["raw"]["observed_at"]["STAGED"],
            }
            with patch.object(l0, "_runtime_output", return_value=l0.RUNTIME_VERSION):
                rejected = l0.stage_committed_intent(
                    chain["profile"],
                    chain["claim"],
                    chain["supply"],
                    descriptor,
                    stage_raw,
                    durable_store=chain["store"],
                    executor_claim_verifier=m2.ExactVerifier(),
                    supply_verifier=ExactSupplyVerifier(),
                )
            with sqlite3.connect(self.database) as connection:
                after = (
                    connection.execute(
                        "SELECT remaining,reserved,spent FROM budgets"
                    ).fetchone(),
                    connection.execute("SELECT COUNT(*) FROM journal_entries").fetchone(),
                    connection.execute(
                        "SELECT COUNT(*) FROM m4_transition_records"
                    ).fetchone(),
                )
            self.assertEqual(rejected.outcome, l0.L0Outcome.STOP)
            self.assertEqual(
                alternate_target.read_text(encoding="utf-8"), "reconciling-old\n"
            )
            self.assertEqual(after, before)
        finally:
            os.close(descriptor)

    def test_deployment_scope_requires_exact_runtime_boundary(self) -> None:
        with self.assertRaisesRegex(ValueError, "deployment runtime boundary absent"):
            self.setup_chain(assurance_scope="DEPLOYMENT_ATTESTED")

    def test_deployment_executor_receives_one_signed_grant_and_no_store(self) -> None:
        provider = _DynamicM4Source()
        external_provider = _DynamicM4Source()
        runtime = _GrantRuntimeFake()
        chain = self.setup_chain(
            assurance_scope="DEPLOYMENT_ATTESTED",
            m4_verification_provider=provider,
            runtime_boundary=runtime,
            external_verification_provider=external_provider,
        )
        runtime_raw = self.runtime_raw(chain)
        with patch.object(l0, "_runtime_output", return_value=l0.RUNTIME_VERSION):
            result = chain["coordinator"].execute(
                chain["claim"], chain["supply"], runtime_raw
            )
        self.assertEqual(len(runtime.preflight_calls), 1)
        self.assertEqual(len(runtime.stage_grants), 1)
        self.assertIsInstance(runtime.stage_grants[0], durable.StageExecutionGrant)
        self.assertEqual(chain["target"].read_text(encoding="utf-8"), chain["content"])
        self.assertEqual(
            self.row(
                "SELECT COUNT(*) FROM journal_entries "
                "WHERE event_type='M4_STAGE_AUTHORIZATION_CONSUMED'"
            ),
            (1,),
        )
        self.assertEqual((result.outcome, result.state), (m4.M4Outcome.JOINED, "JOINED"))
        self.assertEqual(
            runtime.events,
            ["PREFLIGHT", "STAGE", "OBSERVE", "PUBLISH", "PRE_COMMIT", "PRE_JOIN"],
        )
        self.assertEqual(
            [call[0] for call in external_provider.calls],
            ["M4_PUBLICATION_AUTHORIZATION"],
        )

    def test_deployment_rejects_caller_proof_dictionaries_before_begin(self) -> None:
        provider = _DynamicM4Source()
        runtime = _GrantRuntimeFake()
        chain = self.setup_chain(
            assurance_scope="DEPLOYMENT_ATTESTED",
            m4_verification_provider=provider,
            runtime_boundary=runtime,
            external_verification_provider=_DynamicM4Source(),
        )
        with patch.object(l0, "_runtime_output", return_value=l0.RUNTIME_VERSION):
            result = chain["coordinator"].execute(
                chain["claim"], chain["supply"], chain["raw"]
            )
        self.assertEqual(
            (result.outcome, result.reason, result.state),
            (m4.M4Outcome.STOPPED, m4.M4Reason.MALFORMED_INPUT, "STOPPED"),
        )
        self.assertEqual(runtime.events, [])
        self.assertEqual(chain["target"].read_text(encoding="utf-8"), "old\n")
        self.assertEqual(chain["publication_target"].read_text(encoding="utf-8"), "published-old\n")
        self.assertEqual(self.row("SELECT COUNT(*) FROM m4_transactions"), (0,))

    def test_deployment_observer_subject_substitution_stops_before_publication(self) -> None:
        runtime = _GrantRuntimeFake(wrong_observer_subject=True)
        chain = self.setup_chain(
            assurance_scope="DEPLOYMENT_ATTESTED",
            m4_verification_provider=_DynamicM4Source(),
            runtime_boundary=runtime,
            external_verification_provider=_DynamicM4Source(),
        )
        with patch.object(l0, "_runtime_output", return_value=l0.RUNTIME_VERSION):
            result = chain["coordinator"].execute(
                chain["claim"], chain["supply"], self.runtime_raw(chain)
            )
        self.assertEqual((result.outcome, result.state), (m4.M4Outcome.QUARANTINED, "QUARANTINED"))
        self.assertEqual(runtime.events, ["PREFLIGHT", "STAGE", "OBSERVE"])
        self.assertEqual(chain["publication_target"].read_text(encoding="utf-8"), "published-old\n")
        self.assertEqual(
            self.row(
                "SELECT COUNT(*) FROM m4_transition_records "
                "WHERE state IN ('COMMITTED','JOINED')"
            ),
            (0,),
        )

    def test_deployment_wrong_publisher_key_never_joins_after_effect(self) -> None:
        runtime = _GrantRuntimeFake(wrong_publication_key=True)
        chain = self.setup_chain(
            assurance_scope="DEPLOYMENT_ATTESTED",
            m4_verification_provider=_DynamicM4Source(),
            runtime_boundary=runtime,
            external_verification_provider=_DynamicM4Source(),
        )
        with patch.object(l0, "_runtime_output", return_value=l0.RUNTIME_VERSION):
            result = chain["coordinator"].execute(
                chain["claim"], chain["supply"], self.runtime_raw(chain)
            )
        self.assertEqual((result.outcome, result.state), (m4.M4Outcome.QUARANTINED, "QUARANTINED"))
        self.assertEqual(runtime.events, ["PREFLIGHT", "STAGE", "OBSERVE", "PUBLISH"])
        self.assertEqual(chain["publication_target"].read_text(encoding="utf-8"), chain["content"])
        self.assertEqual(self.row("SELECT COUNT(*) FROM m4_transition_records WHERE state='JOINED'"), (0,))
        recovery = chain["store"].recover().m4_recovery[0]
        self.assertFalse(recovery.retry_allowed)

    def test_deployment_tampered_pre_join_continuity_enters_reconciling(self) -> None:
        runtime = _GrantRuntimeFake(tamper_continuity="PRE_JOIN")
        chain = self.setup_chain(
            assurance_scope="DEPLOYMENT_ATTESTED",
            m4_verification_provider=_DynamicM4Source(),
            runtime_boundary=runtime,
            external_verification_provider=_DynamicM4Source(),
        )
        with patch.object(l0, "_runtime_output", return_value=l0.RUNTIME_VERSION):
            result = chain["coordinator"].execute(
                chain["claim"], chain["supply"], self.runtime_raw(chain)
            )
        self.assertEqual(
            (result.outcome, result.reason, result.state),
            (m4.M4Outcome.QUARANTINED, m4.M4Reason.RECONCILING, "RECONCILING"),
        )
        self.assertEqual(runtime.events[-2:], ["PRE_COMMIT", "PRE_JOIN"])
        self.assertEqual(chain["publication_target"].read_text(encoding="utf-8"), chain["content"])
        self.assertEqual(self.row("SELECT COUNT(*) FROM m4_transition_records WHERE state='JOINED'"), (0,))
        recovery = chain["store"].recover().m4_recovery[0]
        self.assertFalse(recovery.resume_allowed)
        self.assertFalse(recovery.retry_allowed)

    def test_topology_rejects_shared_subject_missing_writer_and_git_target(self) -> None:
        chain = self.setup_chain()
        baseline = chain["topology"].data()

        def git_target(value: dict[str, object]) -> None:
            for field in ("staging_binding", "publication_target_binding"):
                binding = value[field]
                binding["canonical_path"] = "/project/.git/config"

        mutations = {
            "shared-uid": lambda value: value["subjects"]["OBSERVER"].update(
                uid=value["subjects"]["CONTROLLER"]["uid"]
            ),
            "shared-gid": lambda value: value["subjects"]["OBSERVER"].update(
                gid=value["subjects"]["CONTROLLER"]["gid"]
            ),
            "shared-label": lambda value: value["subjects"]["OBSERVER"].update(
                security_label=value["subjects"]["CONTROLLER"]["security_label"]
            ),
            "shared-credentials": lambda value: value["subjects"]["OBSERVER"].update(
                credential_namespace=value["subjects"]["CONTROLLER"][
                    "credential_namespace"
                ]
            ),
            "shared-namespace": lambda value: value["subjects"]["OBSERVER"].update(
                namespace_id=value["subjects"]["CONTROLLER"]["namespace_id"]
            ),
            "missing-denied-writer": lambda value: value[
                "denied_writer_principals"
            ].remove("controller-1"),
            "wrong-sole-writer": lambda value: value.update(
                sole_writer_principal="controller-1"
            ),
            "git-authority": lambda value: value.update(git_authority="ALLOW"),
            "git-target": git_target,
            "unknown": lambda value: value.update(verified=True),
        }
        for name, mutate in mutations.items():
            with self.subTest(mutation=name):
                raw = json.loads(json.dumps(baseline))
                mutate(raw)
                for field in ("staging_binding", "publication_target_binding"):
                    binding = raw[field]
                    binding["composite_binding_digest"] = canonical_digest(
                        {
                            key: binding[key]
                            for key in binding
                            if key != "composite_binding_digest"
                        }
                    )
                raw["topology_digest"] = canonical_digest(
                    {key: raw[key] for key in raw if key != "topology_digest"}
                )
                result = publisher.compile_topology(raw)
                self.assertEqual(result.outcome, publisher.PublisherOutcome.STOP)
                self.assertIsNone(result.topology)

    def test_trusted_publisher_rejects_physical_anchor_substitution(self) -> None:
        chain = self.setup_chain()
        baseline = chain["topology"].data()
        mutations = {
            "mount-namespace": lambda anchor: anchor.update(
                mount_namespace_id="mntns:1:1"
            ),
            "mountpoint": lambda anchor: anchor.update(mountpoint="/relocated"),
            "basename": lambda anchor: anchor.update(basename="other-root"),
            "root-identity": lambda anchor: anchor.update(
                root_identity=m2._digest("9")
            ),
            "mount-id": lambda anchor: anchor.update(mount_id="mnt:999999"),
            "parent-ancestry": lambda anchor: anchor["ancestry"][0].update(
                inode=anchor["ancestry"][0]["inode"] + 1
            ),
            "physical-git-ancestry": lambda anchor: anchor.update(
                root_path=anchor["root_path"] + "/.git/publication",
                basename="publication",
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(mutation=name):
                raw = deepcopy(baseline)
                anchor = raw["publication_root_anchor"]
                mutate(anchor)
                anchor["anchor_digest"] = canonical_digest(
                    {key: anchor[key] for key in anchor if key != "anchor_digest"}
                )
                raw["topology_digest"] = canonical_digest(
                    {key: raw[key] for key in raw if key != "topology_digest"}
                )
                compiled = publisher.compile_topology(raw)
                if compiled.outcome is publisher.PublisherOutcome.STOP:
                    continue
                self.assertIsNotNone(compiled.topology)
                root_descriptor = os.open(
                    chain["publication_root"],
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
                )
                try:
                    with self.assertRaises(ValueError):
                        publisher.TrustedPublisher(
                            profile=chain["profile"],
                            root_descriptor=root_descriptor,
                            topology=compiled.topology,
                            topology_verification=m2._verification_source(),
                            verifier_factory=m2.ExactVerifier,
                        )
                finally:
                    os.close(root_descriptor)

    def test_read_only_observer_descriptor_reports_kernel_write_denial(self) -> None:
        target = self.root / "read-only-snapshot"
        target.write_bytes(b"sealed")
        descriptor = os.open(target, os.O_RDONLY | os.O_CLOEXEC)
        try:
            self.assertTrue(m4._denied(lambda: os.pwrite(descriptor, b"x", 0)))
            self.assertTrue(m4._denied(lambda: os.ftruncate(descriptor, 0)))
        finally:
            os.close(descriptor)

    def test_m4_sec_004_high_fd_is_closed_without_proc_inventory(self) -> None:
        self.assertGreater(resource.getrlimit(resource.RLIMIT_NOFILE)[1], 2048)
        read_descriptor, write_descriptor = os.pipe2(os.O_CLOEXEC)
        pid = os.fork()
        if pid == 0:
            try:
                os.close(read_descriptor)
                os.dup2(write_descriptor, 2048, inheritable=False)
                with patch.object(
                    m4.os,
                    "listdir",
                    side_effect=OSError(errno.EACCES, "proc inventory unavailable"),
                ):
                    m4._close_except({write_descriptor})
                try:
                    fcntl.fcntl(2048, fcntl.F_GETFD)
                except OSError as error:
                    outcome = b"CLOSED" if error.errno == errno.EBADF else b"WRONG_ERROR"
                else:
                    outcome = b"LEAKED"
                os.write(write_descriptor, outcome)
                os._exit(0)
            except BaseException:
                os._exit(125)
        os.close(write_descriptor)
        try:
            self.assertEqual(os.read(read_descriptor, 32), b"CLOSED")
            _, status = os.waitpid(pid, 0)
        finally:
            os.close(read_descriptor)
        self.assertTrue(os.WIFEXITED(status))
        self.assertEqual(os.WEXITSTATUS(status), 0)

    def test_m4_sec_004_fd_above_lowered_hard_limit_is_closed(self) -> None:
        self.assertGreater(resource.getrlimit(resource.RLIMIT_NOFILE)[1], 2048)
        original_close = m4._close_except

        def close_after_lowering_limit(keep: set[int]) -> None:
            resource.setrlimit(resource.RLIMIT_NOFILE, (1024, 1024))
            original_close(keep)
            for descriptor in keep:
                fcntl.fcntl(descriptor, fcntl.F_GETFD)
            try:
                fcntl.fcntl(2048, fcntl.F_GETFD)
            except OSError as error:
                if error.errno != errno.EBADF:
                    raise
            else:
                raise OSError(errno.EBADF, "inherited descriptor survived closure")

        chain = self.setup_chain()
        source = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
        os.dup2(source, 2048, inheritable=False)
        try:
            with (
                patch.object(l0, "_runtime_output", return_value=l0.RUNTIME_VERSION),
                patch.object(m4, "_close_except", side_effect=close_after_lowering_limit),
            ):
                stage_result = chain["coordinator"].execute(
                    chain["claim"], chain["supply"], chain["raw"]
                )
        finally:
            os.close(2048)
            os.close(source)
        self.assertEqual(
            (stage_result.outcome, stage_result.state),
            (m4.M4Outcome.JOINED, "JOINED"),
        )

        fixture = M4CoordinatorTests(methodName="runTest")
        fixture.setUp()
        try:
            chain = fixture.setup_chain()
            original_postcheck = m4._postcheck_child

            def postcheck_with_high_fd(*args: object) -> object:
                source = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
                os.dup2(source, 2048, inheritable=False)
                try:
                    return original_postcheck(*args)
                finally:
                    os.close(2048)
                    os.close(source)

            with (
                patch.object(l0, "_runtime_output", return_value=l0.RUNTIME_VERSION),
                patch.object(m4, "_close_except", side_effect=close_after_lowering_limit),
                patch.object(m4, "_postcheck_child", side_effect=postcheck_with_high_fd),
            ):
                observer_result = chain["coordinator"].execute(
                    chain["claim"], chain["supply"], chain["raw"]
                )
            self.assertEqual(
                (observer_result.outcome, observer_result.state),
                (m4.M4Outcome.JOINED, "JOINED"),
            )
        finally:
            fixture.tearDown()

    def test_m4_sec_004_close_range_failure_blocks_stage_and_observer(self) -> None:
        chain = self.setup_chain()
        with (
            patch.object(l0, "_runtime_output", return_value=l0.RUNTIME_VERSION),
            patch.object(
                m4,
                "_linux_close_range",
                side_effect=OSError(errno.ENOSYS, "close_range unavailable"),
            ),
        ):
            stage_result = chain["coordinator"].execute(
                chain["claim"], chain["supply"], chain["raw"]
            )
        self.assertEqual(
            (stage_result.outcome, stage_result.state),
            (m4.M4Outcome.QUARANTINED, "QUARANTINED"),
        )
        self.assertEqual(chain["target"].read_text(encoding="utf-8"), "old\n")
        self.assertEqual(
            chain["publication_target"].read_text(encoding="utf-8"), "published-old\n"
        )
        self.assertEqual(
            self.row("SELECT COUNT(*) FROM m4_transition_records WHERE state='STAGED'"),
            (0,),
        )

        fixture = M4CoordinatorTests(methodName="runTest")
        fixture.setUp()
        try:
            chain = fixture.setup_chain()
            original_postcheck = m4._postcheck_child

            def fail_closed_postcheck(*args: object) -> object:
                with patch.object(
                    m4,
                    "_linux_close_range",
                    side_effect=OSError(errno.ENOSYS, "close_range unavailable"),
                ):
                    return original_postcheck(*args)

            with (
                patch.object(l0, "_runtime_output", return_value=l0.RUNTIME_VERSION),
                patch.object(m4, "_postcheck_child", side_effect=fail_closed_postcheck),
            ):
                observer_result = chain["coordinator"].execute(
                    chain["claim"], chain["supply"], chain["raw"]
                )
            self.assertEqual(
                (observer_result.outcome, observer_result.state),
                (m4.M4Outcome.QUARANTINED, "QUARANTINED"),
            )
            self.assertEqual(chain["target"].read_text(encoding="utf-8"), chain["content"])
            self.assertEqual(
                chain["publication_target"].read_text(encoding="utf-8"),
                "published-old\n",
            )
            self.assertEqual(
                fixture.row(
                    "SELECT COUNT(*) FROM m4_transition_records "
                    "WHERE state IN ('POSTCHECKED','COMMITTED','JOINED')"
                ),
                (0,),
            )
        finally:
            fixture.tearDown()

    def test_m4_sec_001_alternate_root_is_closed_input(self) -> None:
        chain = self.setup_chain()
        alternate_root = self.root / "alternate-stage"
        alternate_root.mkdir(mode=0o700)
        alternate_target = alternate_root / "artifact.txt"
        alternate_target.write_text("alternate-old\n", encoding="utf-8")
        alternate_descriptor = os.open(
            alternate_root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
        )
        try:
            resolved = l0.resolve_target(
                chain["profile"],
                alternate_descriptor,
                {
                    "canonical_path": "/staging/artifact.txt",
                    "descriptor_id": "alternate-stage-target-1",
                    "root_id": "alternate-stage-root-1",
                    "resolution_epoch": 1,
                },
            )
            self.assertEqual(resolved.outcome, l0.L0Outcome.RESOLVED)
            raw = dict(chain["raw"])
            raw["root_descriptor"] = alternate_descriptor
            raw["source_object_binding"] = resolved.binding.data()
            result = chain["coordinator"].execute(
                chain["claim"], chain["supply"], raw
            )
        finally:
            os.close(alternate_descriptor)
        self.assertEqual(
            (result.outcome, result.reason, result.state),
            (m4.M4Outcome.STOPPED, m4.M4Reason.MALFORMED_INPUT, "STOPPED"),
        )
        self.assertEqual(chain["target"].read_text(encoding="utf-8"), "old\n")
        self.assertEqual(alternate_target.read_text(encoding="utf-8"), "alternate-old\n")
        self.assertEqual(
            chain["publication_target"].read_text(encoding="utf-8"), "published-old\n"
        )
        self.assertEqual(self.row("SELECT COUNT(*) FROM m4_transactions"), (0,))
        self.assertEqual(
            self.row("SELECT COUNT(*) FROM m4_transition_records WHERE state='JOINED'"),
            (0,),
        )

    def test_unknown_input_and_claim_substitution_stop_before_m4_dispatch(self) -> None:
        chain = self.setup_chain()
        raw = dict(chain["raw"])
        raw["unknown"] = True
        result = chain["coordinator"].execute(chain["claim"], chain["supply"], raw)
        self.assertEqual((result.outcome, result.state), (m4.M4Outcome.STOPPED, "STOPPED"))
        self.assertEqual(self.row("SELECT COUNT(*) FROM m4_transactions"), (0,))
        self.assertEqual(chain["target"].read_text(encoding="utf-8"), "old\n")

        other = M4CoordinatorTests(methodName="runTest")
        other.setUp()
        try:
            chain = other.setup_chain()
            forged = replace(chain["claim"], audience_id=chain["claim"].principal_id)
            result = chain["coordinator"].execute(forged, chain["supply"], chain["raw"])
            self.assertEqual((result.outcome, result.state), (m4.M4Outcome.STOPPED, "STOPPED"))
            self.assertEqual(other.row("SELECT COUNT(*) FROM m4_transactions"), (0,))
            self.assertEqual(chain["target"].read_text(encoding="utf-8"), "old\n")
        finally:
            other.tearDown()

    def test_fault_after_dispatch_quarantines_escrow_without_retry(self) -> None:
        chain = self.setup_chain()

        def fault(point: str) -> None:
            if point == "after_dispatch":
                raise RuntimeError(point)

        result = chain["coordinator"].execute(
            chain["claim"], chain["supply"], chain["raw"], _fault=fault
        )
        self.assertEqual(
            (result.outcome, result.state),
            (m4.M4Outcome.QUARANTINED, "QUARANTINED"),
        )
        self.assertEqual(
            self.row("SELECT disposition FROM budget_reservations"),
            ("QUARANTINED_ESCROW",),
        )
        recovered = chain["store"].recover().m4_recovery[0]
        self.assertFalse(recovered.resume_allowed)
        self.assertFalse(recovered.retry_allowed)
        self.assertEqual(chain["target"].read_text(encoding="utf-8"), "old\n")

    def test_fault_after_stage_quarantines_changed_staging_without_retry(self) -> None:
        chain = self.setup_chain()

        def fault(point: str) -> None:
            if point == "after_stage":
                raise RuntimeError(point)

        with patch.object(l0, "_runtime_output", return_value=l0.RUNTIME_VERSION):
            result = chain["coordinator"].execute(
                chain["claim"], chain["supply"], chain["raw"], _fault=fault
            )
        self.assertEqual(
            (result.outcome, result.state),
            (m4.M4Outcome.QUARANTINED, "QUARANTINED"),
        )
        self.assertEqual(chain["target"].read_text(encoding="utf-8"), chain["content"])
        self.assertEqual(self.row("SELECT remaining,reserved,spent FROM budgets"), (9, 1, 0))
        recovered = chain["store"].recover().m4_recovery[0]
        self.assertFalse(recovered.resume_allowed)
        self.assertFalse(recovered.retry_allowed)

    def test_existing_writer_fd_quarantines_without_join(self) -> None:
        chain = self.setup_chain()
        ready_read, ready_write = os.pipe2(os.O_CLOEXEC)
        release_read, release_write = os.pipe2(os.O_CLOEXEC)
        holder_pid = -1

        def fault(point: str) -> None:
            nonlocal holder_pid
            if point != "after_stage":
                return
            holder_pid = os.fork()
            if holder_pid == 0:
                try:
                    os.close(ready_read)
                    os.close(release_write)
                    descriptor = os.open(
                        chain["target"], os.O_WRONLY | os.O_CLOEXEC
                    )
                    os.write(ready_write, b"1")
                    os.read(release_read, 1)
                    os.close(descriptor)
                    os._exit(0)
                except BaseException:
                    os._exit(125)
            os.close(ready_write)
            os.close(release_read)
            readable, _, _ = select.select([ready_read], [], [], 3.0)
            if not readable or os.read(ready_read, 1) != b"1":
                raise RuntimeError("writer holder failed")

        try:
            with patch.object(l0, "_runtime_output", return_value=l0.RUNTIME_VERSION):
                result = chain["coordinator"].execute(
                    chain["claim"], chain["supply"], chain["raw"], _fault=fault
                )
        finally:
            try:
                os.write(release_write, b"1")
            except OSError:
                pass
            for descriptor in (ready_read, release_write):
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            if holder_pid > 0:
                os.waitpid(holder_pid, 0)
        self.assertEqual(
            (result.outcome, result.reason, result.state),
            (m4.M4Outcome.QUARANTINED, m4.M4Reason.QUIESCENCE_FAILED, "QUARANTINED"),
        )
        self.assertEqual(self.row("SELECT state FROM m4_transactions"), ("QUARANTINED",))
        self.assertEqual(self.row("SELECT remaining,reserved,spent FROM budgets"), (9, 1, 0))
        recovered = chain["store"].recover().m4_recovery[0]
        self.assertFalse(recovered.resume_allowed)
        self.assertFalse(recovered.retry_allowed)

    def test_writer_race_breaks_lease_and_quarantines(self) -> None:
        for point in ("seal_after_copy", "after_seal", "after_postcheck"):
            with self.subTest(point=point):
                fixture = M4CoordinatorTests(methodName="runTest")
                fixture.setUp()
                try:
                    chain = fixture.setup_chain()
                    observed: list[int] = []

                    def fault(actual: str) -> None:
                        if actual == point:
                            observed.append(fixture.writer_attempt(chain["target"]))

                    with patch.object(l0, "_runtime_output", return_value=l0.RUNTIME_VERSION):
                        result = chain["coordinator"].execute(
                            chain["claim"], chain["supply"], chain["raw"], _fault=fault
                        )
                    self.assertEqual(observed, [errno.EAGAIN])
                    self.assertEqual(
                        (result.outcome, result.reason, result.state),
                        (
                            m4.M4Outcome.QUARANTINED,
                            m4.M4Reason.QUIESCENCE_FAILED,
                            "QUARANTINED",
                        ),
                    )
                    recovered = chain["store"].recover().m4_recovery[0]
                    self.assertFalse(recovered.resume_allowed)
                    self.assertFalse(recovered.retry_allowed)
                finally:
                    fixture.tearDown()

    def test_no_fallible_security_hook_runs_after_durable_join(self) -> None:
        chain = self.setup_chain()
        observed: list[int] = []

        def fault(point: str) -> None:
            if point == "after_join_record":
                observed.append(self.writer_attempt(chain["target"]))

        with patch.object(l0, "_runtime_output", return_value=l0.RUNTIME_VERSION):
            result = chain["coordinator"].execute(
                chain["claim"], chain["supply"], chain["raw"], _fault=fault
            )
        self.assertEqual(observed, [])
        self.assertEqual(
            (result.outcome, result.reason, result.state),
            (m4.M4Outcome.JOINED, m4.M4Reason.JOINED, "JOINED"),
        )
        self.assertEqual(self.row("SELECT remaining,reserved,spent FROM budgets"), (9, 0, 1))
        self.assertEqual(
            self.row(
                "SELECT COUNT(*) FROM journal_entries WHERE event_type='BUDGET_TERMINAL_SPENT'"
            ),
            (1,),
        )
        recovered = chain["store"].recover().m4_recovery[0]
        self.assertEqual(recovered.state, "JOINED")
        self.assertFalse(recovered.resume_allowed)
        self.assertFalse(recovered.retry_allowed)

    def test_read_lease_break_after_commit_reconciles_before_join(self) -> None:
        chain = self.setup_chain()
        observed: list[int] = []

        def fault(point: str) -> None:
            if point == "after_commit":
                observed.append(self.writer_attempt(chain["target"]))

        with patch.object(l0, "_runtime_output", return_value=l0.RUNTIME_VERSION):
            result = chain["coordinator"].execute(
                chain["claim"], chain["supply"], chain["raw"], _fault=fault
            )
        self.assertEqual(observed, [errno.EAGAIN])
        self.assertEqual(
            (result.outcome, result.reason, result.state),
            (m4.M4Outcome.QUARANTINED, m4.M4Reason.RECONCILING, "RECONCILING"),
        )
        self.assertEqual(
            self.row("SELECT COUNT(*) FROM m4_transition_records WHERE state='JOINED'"),
            (0,),
        )
        recovered = chain["store"].recover().m4_recovery[0]
        self.assertEqual(recovered.state, "RECONCILING")
        self.assertFalse(recovered.resume_allowed)
        self.assertFalse(recovered.retry_allowed)

    def test_forced_lease_loss_and_unsupported_filesystem_quarantine(self) -> None:
        chain = self.setup_chain()
        original_assert = m4._assert_read_lease
        calls = 0

        def force_loss(profile: object, lease: object, binding: object) -> None:
            nonlocal calls
            calls += 1
            if calls == 4:
                fcntl.fcntl(lease.descriptor, fcntl.F_SETLEASE, fcntl.F_UNLCK)
            original_assert(profile, lease, binding)

        with (
            patch.object(l0, "_runtime_output", return_value=l0.RUNTIME_VERSION),
            patch.object(m4, "_assert_read_lease", side_effect=force_loss),
        ):
            result = chain["coordinator"].execute(
                chain["claim"], chain["supply"], chain["raw"]
            )
        self.assertEqual(
            (result.outcome, result.reason, result.state),
            (m4.M4Outcome.QUARANTINED, m4.M4Reason.QUIESCENCE_FAILED, "QUARANTINED"),
        )

        fixture = M4CoordinatorTests(methodName="runTest")
        fixture.setUp()
        try:
            chain = fixture.setup_chain()
            real_fcntl = fcntl.fcntl

            def unsupported(descriptor: int, command: int, *args: object) -> object:
                if command == fcntl.F_SETLEASE and args == (fcntl.F_RDLCK,):
                    raise OSError(errno.EOPNOTSUPP, "leases unsupported")
                return real_fcntl(descriptor, command, *args)

            with (
                patch.object(l0, "_runtime_output", return_value=l0.RUNTIME_VERSION),
                patch.object(m4.fcntl, "fcntl", side_effect=unsupported),
            ):
                result = chain["coordinator"].execute(
                    chain["claim"], chain["supply"], chain["raw"]
                )
            self.assertEqual(
                (result.outcome, result.reason, result.state),
                (
                    m4.M4Outcome.QUARANTINED,
                    m4.M4Reason.QUIESCENCE_FAILED,
                    "QUARANTINED",
                ),
            )
        finally:
            fixture.tearDown()

    def test_inode_and_path_substitution_fail_closed(self) -> None:
        chain = self.setup_chain()
        detached = chain["target"].with_name("detached-inode")
        chain["target"].rename(detached)
        chain["target"].write_text("substitute\n", encoding="utf-8")
        result = chain["coordinator"].execute(
            chain["claim"], chain["supply"], chain["raw"]
        )
        self.assertEqual((result.outcome, result.state), (m4.M4Outcome.STOPPED, "STOPPED"))
        self.assertEqual(self.row("SELECT COUNT(*) FROM m4_transactions"), (0,))

        fixture = M4CoordinatorTests(methodName="runTest")
        fixture.setUp()
        try:
            chain = fixture.setup_chain()
            detached = chain["target"].with_name("post-stage-inode")

            def fault(point: str) -> None:
                if point == "after_stage":
                    chain["target"].rename(detached)
                    chain["target"].write_text("path substitute\n", encoding="utf-8")

            with patch.object(l0, "_runtime_output", return_value=l0.RUNTIME_VERSION):
                result = chain["coordinator"].execute(
                    chain["claim"], chain["supply"], chain["raw"], _fault=fault
                )
            self.assertEqual(
                (result.outcome, result.reason, result.state),
                (
                    m4.M4Outcome.QUARANTINED,
                    m4.M4Reason.QUIESCENCE_FAILED,
                    "QUARANTINED",
                ),
            )
            self.assertEqual(detached.read_text(encoding="utf-8"), chain["content"])
            recovered = chain["store"].recover().m4_recovery[0]
            self.assertFalse(recovered.resume_allowed)
            self.assertFalse(recovered.retry_allowed)
        finally:
            fixture.tearDown()

    def test_m4_sec_002_rename_after_quiesce_quarantines(self) -> None:
        chain = self.setup_chain()
        detached = chain["target"].with_name("leased-detached-inode")

        def fault(point: str) -> None:
            if point == "seal_after_copy":
                chain["target"].rename(detached)
                chain["target"].write_text("post-quiesce substitute\n", encoding="utf-8")

        with patch.object(l0, "_runtime_output", return_value=l0.RUNTIME_VERSION):
            result = chain["coordinator"].execute(
                chain["claim"], chain["supply"], chain["raw"], _fault=fault
            )
        self.assertEqual(
            (result.outcome, result.reason, result.state),
            (
                m4.M4Outcome.QUARANTINED,
                m4.M4Reason.QUIESCENCE_FAILED,
                "QUARANTINED",
            ),
        )
        self.assertEqual(detached.read_text(encoding="utf-8"), chain["content"])
        self.assertEqual(
            chain["target"].read_text(encoding="utf-8"), "post-quiesce substitute\n"
        )
        self.assertEqual(
            chain["publication_target"].read_text(encoding="utf-8"), "published-old\n"
        )
        self.assertEqual(
            self.row("SELECT COUNT(*) FROM m4_transition_records WHERE state='JOINED'"),
            (0,),
        )
        recovered = chain["store"].recover().m4_recovery[0]
        self.assertFalse(recovered.resume_allowed)
        self.assertFalse(recovered.retry_allowed)

    def test_m4_sec_002_substitute_before_publish_and_publisher_target_swap(self) -> None:
        for point in ("after_postcheck", "publisher_before_replace"):
            with self.subTest(point=point):
                fixture = M4CoordinatorTests(methodName="runTest")
                fixture.setUp()
                try:
                    chain = fixture.setup_chain()
                    publication_target = chain["publication_target"]
                    detached = publication_target.with_name("detached-" + point)
                    outside = publication_target.with_name("outside-canary")
                    outside.write_text("outside-stable\n", encoding="utf-8")

                    def fault(actual: str) -> None:
                        if actual == point:
                            publication_target.rename(detached)
                            publication_target.write_text(
                                "publication substitute\n", encoding="utf-8"
                            )

                    with patch.object(
                        l0, "_runtime_output", return_value=l0.RUNTIME_VERSION
                    ):
                        result = chain["coordinator"].execute(
                            chain["claim"],
                            chain["supply"],
                            chain["raw"],
                            _fault=fault,
                        )
                    self.assertEqual(
                        (result.outcome, result.reason, result.state),
                        (
                            m4.M4Outcome.QUARANTINED,
                            m4.M4Reason.PUBLICATION_FAILED,
                            "QUARANTINED",
                        ),
                    )
                    self.assertEqual(
                        publication_target.read_text(encoding="utf-8"),
                        "publication substitute\n",
                    )
                    self.assertEqual(
                        detached.read_text(encoding="utf-8"), "published-old\n"
                    )
                    self.assertEqual(outside.read_text(encoding="utf-8"), "outside-stable\n")
                    self.assertEqual(chain["target"].read_text(encoding="utf-8"), chain["content"])
                    self.assertEqual(
                        fixture.row("SELECT remaining,reserved,spent FROM budgets"),
                        (9, 1, 0),
                    )
                    self.assertEqual(
                        fixture.row(
                            "SELECT COUNT(*) FROM m4_transition_records "
                            "WHERE state IN ('COMMITTED','JOINED')"
                        ),
                        (0,),
                    )
                    self.assertEqual(
                        list(publication_target.parent.glob(".harness-m4-*.tmp")), []
                    )
                finally:
                    fixture.tearDown()

    def test_m4_sec_002_publication_root_relocation_under_git_quarantines(self) -> None:
        chain = self.setup_chain()
        git_directory = self.root / "synthetic-repository" / ".git"
        git_directory.mkdir(parents=True, mode=0o700)
        relocated_root = git_directory / "publication"
        os.rename(chain["publication_root"], relocated_root)

        with patch.object(l0, "_runtime_output", return_value=l0.RUNTIME_VERSION):
            result = chain["coordinator"].execute(
                chain["claim"], chain["supply"], chain["raw"]
            )

        self.assertEqual(
            (result.outcome, result.state),
            (m4.M4Outcome.QUARANTINED, "QUARANTINED"),
        )
        self.assertEqual(
            (relocated_root / "artifact.txt").read_text(encoding="utf-8"),
            "published-old\n",
        )
        self.assertEqual(
            self.row(
                "SELECT COUNT(*) FROM m4_transition_records "
                "WHERE state IN ('COMMITTED','JOINED')"
            ),
            (0,),
        )
        self.assertEqual(
            self.row("SELECT remaining, reserved, spent FROM budgets"),
            (9, 1, 0),
        )

        race = M4CoordinatorTests(methodName="runTest")
        race.setUp()
        try:
            racing = race.setup_chain()
            git_directory = race.root / "race-repository" / ".git"
            git_directory.mkdir(parents=True, mode=0o700)
            relocated_root = git_directory / "publication"

            def relocate_before_replace(point: str) -> None:
                if point == "publisher_before_replace":
                    os.rename(racing["publication_root"], relocated_root)

            with patch.object(l0, "_runtime_output", return_value=l0.RUNTIME_VERSION):
                racing_result = racing["coordinator"].execute(
                    racing["claim"],
                    racing["supply"],
                    racing["raw"],
                    _fault=relocate_before_replace,
                )
            self.assertEqual(
                (racing_result.outcome, racing_result.state),
                (m4.M4Outcome.QUARANTINED, "QUARANTINED"),
            )
            self.assertEqual(
                (relocated_root / "artifact.txt").read_text(encoding="utf-8"),
                "published-old\n",
            )
            self.assertEqual(
                race.row("SELECT remaining, reserved, spent FROM budgets"),
                (9, 1, 0),
            )
        finally:
            race.tearDown()

        fixture = M4CoordinatorTests(methodName="runTest")
        fixture.setUp()
        try:
            unchanged = fixture.setup_chain()
            with patch.object(l0, "_runtime_output", return_value=l0.RUNTIME_VERSION):
                unchanged_result = unchanged["coordinator"].execute(
                    unchanged["claim"], unchanged["supply"], unchanged["raw"]
                )
            self.assertEqual(
                (unchanged_result.outcome, unchanged_result.state),
                (m4.M4Outcome.JOINED, "JOINED"),
            )
        finally:
            fixture.tearDown()

    def test_publication_unknown_after_replace_quarantines_without_retry(self) -> None:
        chain = self.setup_chain()
        outside = chain["publication_target"].with_name("outside-canary")
        outside.write_text("outside-stable\n", encoding="utf-8")

        def fault(point: str) -> None:
            if point == "publisher_after_replace":
                raise RuntimeError(point)

        with patch.object(l0, "_runtime_output", return_value=l0.RUNTIME_VERSION):
            result = chain["coordinator"].execute(
                chain["claim"], chain["supply"], chain["raw"], _fault=fault
            )
        self.assertEqual(
            (result.outcome, result.reason, result.state),
            (
                m4.M4Outcome.QUARANTINED,
                m4.M4Reason.PUBLICATION_FAILED,
                "QUARANTINED",
            ),
        )
        self.assertEqual(
            chain["publication_target"].read_text(encoding="utf-8"), chain["content"]
        )
        self.assertEqual(outside.read_text(encoding="utf-8"), "outside-stable\n")
        self.assertEqual(self.row("SELECT remaining,reserved,spent FROM budgets"), (9, 1, 0))
        self.assertEqual(
            self.row("SELECT COUNT(*) FROM m4_transition_records WHERE state='JOINED'"),
            (0,),
        )
        recovered = chain["store"].recover().m4_recovery[0]
        self.assertEqual(recovered.state, "QUARANTINED")
        self.assertFalse(recovered.resume_allowed)
        self.assertFalse(recovered.retry_allowed)

    def test_external_authorizers_are_separate_and_fail_closed(self) -> None:
        for boundary, expected_publication, expected_reason in (
            (
                "OBSERVER_RECEIPT",
                "published-old\n",
                m4.M4Reason.POSTCHECK_FAILED,
            ),
            (
                "PUBLICATION_AUTHORIZATION",
                "published-old\n",
                m4.M4Reason.PUBLICATION_FAILED,
            ),
            (
                "PUBLICATION_RECEIPT",
                "m4-sealed-output\n",
                m4.M4Reason.PUBLICATION_FAILED,
            ),
        ):
            with self.subTest(boundary=boundary):
                fixture = M4CoordinatorTests(methodName="runTest")
                fixture.setUp()
                try:
                    chain = fixture.setup_chain()
                    raw = deepcopy(chain["raw"])
                    raw["external_verifications"][boundary]["proof"] = m2._digest("9")
                    with patch.object(
                        l0, "_runtime_output", return_value=l0.RUNTIME_VERSION
                    ):
                        result = chain["coordinator"].execute(
                            chain["claim"], chain["supply"], raw
                        )
                    self.assertEqual(
                        (result.outcome, result.reason, result.state),
                        (m4.M4Outcome.QUARANTINED, expected_reason, "QUARANTINED"),
                    )
                    self.assertEqual(
                        chain["publication_target"].read_text(encoding="utf-8"),
                        expected_publication,
                    )
                    self.assertEqual(
                        fixture.row(
                            "SELECT COUNT(*) FROM m4_transition_records "
                            "WHERE state IN ('COMMITTED','JOINED')"
                        ),
                        (0,),
                    )
                    recovered = chain["store"].recover().m4_recovery[0]
                    self.assertFalse(recovered.resume_allowed)
                    self.assertFalse(recovered.retry_allowed)
                finally:
                    fixture.tearDown()

    def test_fault_after_seal_postcheck_and_commit_never_joins_or_retries(self) -> None:
        for point, expected_state, expected_budget in (
            ("after_seal", "QUARANTINED", (9, 1, 0)),
            ("after_postcheck", "QUARANTINED", (9, 1, 0)),
            ("after_commit", "RECONCILING", (9, 0, 1)),
        ):
            with self.subTest(test_id="T-Q45-STAGEABLE-CRASH-QUARANTINES", point=point):
                fixture = M4CoordinatorTests(methodName="runTest")
                fixture.setUp()
                try:
                    chain = fixture.setup_chain()

                    def fault(actual: str) -> None:
                        if actual == point:
                            raise RuntimeError(actual)

                    with patch.object(l0, "_runtime_output", return_value=l0.RUNTIME_VERSION):
                        result = chain["coordinator"].execute(
                            chain["claim"], chain["supply"], chain["raw"], _fault=fault
                        )
                    self.assertEqual(result.outcome, m4.M4Outcome.QUARANTINED)
                    self.assertEqual(result.state, expected_state)
                    self.assertEqual(
                        fixture.row("SELECT remaining,reserved,spent FROM budgets"),
                        expected_budget,
                    )
                    self.assertEqual(
                        fixture.row(
                            "SELECT COUNT(*) FROM m4_transition_records WHERE state='JOINED'"
                        ),
                        (0,),
                    )
                    recovered = chain["store"].recover().m4_recovery[0]
                    self.assertFalse(recovered.resume_allowed)
                    self.assertFalse(recovered.retry_allowed)
                finally:
                    fixture.tearDown()

    def test_process_crash_reopens_nonresumable_then_quarantines_without_retry(self) -> None:
        chain = self.setup_chain()

        def crash(point: str) -> None:
            if point == "after_postcheck":
                os._exit(77)

        with patch.object(l0, "_runtime_output", return_value=l0.RUNTIME_VERSION):
            pid = os.fork()
            if pid == 0:
                chain["coordinator"].execute(
                    chain["claim"], chain["supply"], chain["raw"], _fault=crash
                )
                os._exit(0)
            _, status = os.waitpid(pid, 0)
        self.assertTrue(os.WIFEXITED(status))
        self.assertEqual(os.WEXITSTATUS(status), 77)
        recovery = chain["store"].recover()
        self.assertEqual(recovery.m4_recovery[0].state, "POSTCHECKED")
        self.assertFalse(recovery.m4_recovery[0].resume_allowed)
        self.assertFalse(recovery.m4_recovery[0].retry_allowed)
        quarantined = chain["store"].advance_m4(
            {
                "transaction_id": chain["claim"].transaction_id,
                "expected_state": "POSTCHECKED",
                "state": "QUARANTINED",
                "observed_at": chain["raw"]["observed_at"]["QUARANTINED"],
                "evidence": {
                    "evidence_version": 1,
                    "uncertainty": "M4_PROCESS_CRASH",
                    "evidence_digest": canonical_digest(
                        {"evidence_version": 1, "uncertainty": "M4_PROCESS_CRASH"}
                    ),
                },
                "verification": chain["raw"]["verifications"]["QUARANTINED"],
            }
        )
        self.assertTrue(quarantined.committed)
        recovered = chain["store"].recover().m4_recovery[0]
        self.assertEqual(recovered.state, "QUARANTINED")
        self.assertFalse(recovered.resume_allowed)
        self.assertFalse(recovered.retry_allowed)
        self.assertEqual(self.row("SELECT remaining,reserved,spent FROM budgets"), (9, 1, 0))
        self.assertEqual(
            self.row("SELECT COUNT(*) FROM m4_transition_records WHERE state='JOINED'"),
            (0,),
        )

    def test_t_q48_endpoint_request_is_denied_before_m4_dispatch(self) -> None:
        chain = self.setup_chain()
        request = json.loads(chain["claim"].request_json)
        entries = [request["proposal"]["authority"]]
        entries.extend(
            request[name]["authority"][0]
            for name in ("manifest", "policy", "physical_ceiling", "trusted_facts")
        )
        for entry in entries:
            entry.update(
                effect="COMMUNICATE",
                resource="ENDPOINT",
                operation="SEND",
                selector={"kind": "ENDPOINT_EXACT", "value": "https://example.invalid/sink"},
                quantity_unit="MESSAGES",
            )
        forged = replace(
            chain["claim"],
            request_json=json.dumps(request, sort_keys=True, separators=(",", ":")),
        )
        with self.subTest(test_id="T-Q48-POLICY-SCOPE-KIND-CROSS-MATRIX"):
            result = chain["coordinator"].execute(
                forged, chain["supply"], chain["raw"]
            )
        self.assertEqual(
            (result.outcome, result.reason, result.state),
            (m4.M4Outcome.STOPPED, m4.M4Reason.EXTERNAL_BRANCH_DENIED, "STOPPED"),
        )
        self.assertEqual(self.row("SELECT COUNT(*) FROM m4_transactions"), (0,))
        self.assertEqual(chain["target"].read_text(encoding="utf-8"), "old\n")


if __name__ == "__main__":
    unittest.main()
