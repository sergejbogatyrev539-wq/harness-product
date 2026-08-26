from __future__ import annotations

from dataclasses import replace
import errno
import fcntl
import json
import os
from pathlib import Path
import select
import signal
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

import harness_product.durable as durable
import harness_product.l0 as l0
import harness_product.m4 as m4
from harness_product.durable import DurableStore, canonical_digest

from tests import test_durable as m2
from tests import test_l0_supply as supply_tests
from tests.test_l0_supply import ExactSupplyVerifier
from tests.test_m4_durable import _inventory


def _contract(issue: dict[str, object], scope_digest: str) -> dict[str, object]:
    body: dict[str, object] = {
        "contract_version": "1.0.0",
        "authority_domain_id": "dev-stageable-local",
        "journal_lineage_id": "journal-lineage-1",
        "root_contract_digest": m2._digest("b"),
        "parent_contract_digest": None,
        "lineage_root": m2.LINEAGE,
        "authority_digest": canonical_digest(issue["request"]["proposal"]["authority"]),
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

    def setup_chain(self) -> dict[str, object]:
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
        )
        contract = _contract(issue, scope)
        issue["contract_digest"] = contract["contract_digest"]
        verifier = m2.ExactVerifier()
        store = DurableStore(
            str(self.database),
            verifier,
            executor_claim_verifier=verifier,
            m4_verifier=verifier,
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
            "frontier_version": "1.0.0",
            "contract_digest": contract["contract_digest"],
            "contract_version": "1.0.0",
            "authority_domain_id": contract["authority_domain_id"],
            "journal_lineage_id": contract["journal_lineage_id"],
            "root_contract_digest": contract["root_contract_digest"],
            "parent_contract_digest": None,
            "journal_sequence": self.row("SELECT journal_head_sequence FROM store_meta")[0],
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

        stage_root = self.root / "stage"
        stage_root.mkdir(mode=0o700)
        target = stage_root / "artifact.txt"
        target.write_text("old\n", encoding="utf-8")
        root_descriptor = os.open(
            stage_root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
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
        self.assertEqual(resolved.outcome, l0.L0Outcome.RESOLVED)
        source_binding = resolved.binding.data()
        coordinator = m4.M4Coordinator(
            store=store,
            profile=profile,
            executor_claim_verifier_factory=m2.ExactVerifier,
            supply_verifier_factory=ExactSupplyVerifier,
            principals=m4.M4Principals(
                controller_principal="controller-1",
                controller_session="controller-session-1",
                observer_principal="observer-1",
                observer_session="observer-session-1",
            ),
        )
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
            "root_descriptor": root_descriptor,
            "source_object_binding": source_binding,
            "stage_request": {
                "transaction_id": claim.transaction_id,
                "claim_digest": claim.claim_digest,
                "operation": "WRITE_FILE_REPLACE",
                "content": content,
                "content_digest": l0._hash_text(content),
                "target_binding": source_binding,
            },
            "observed_at": times,
            "verifications": verifications,
        }
        return {
            "profile": profile,
            "supply": supply,
            "store": store,
            "claim": claim,
            "coordinator": coordinator,
            "raw": raw,
            "root_descriptor": root_descriptor,
            "target": target,
            "content": content,
        }

    def test_exact_stage_seal_postcheck_commit_join(self) -> None:
        chain = self.setup_chain()
        root_identity = os.fstat(chain["root_descriptor"])
        with patch.object(l0, "_runtime_output", return_value=l0.RUNTIME_VERSION):
            result = chain["coordinator"].execute(
                chain["claim"], chain["supply"], chain["raw"]
            )
        self.assertEqual((result.outcome, result.state), (m4.M4Outcome.JOINED, "JOINED"))
        self.assertEqual(chain["target"].read_text(encoding="utf-8"), chain["content"])
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
        try:
            current = os.fstat(chain["root_descriptor"])
        except OSError as error:
            self.assertEqual(error.errno, errno.EBADF)
        else:
            self.assertNotEqual(
                (current.st_dev, current.st_ino),
                (root_identity.st_dev, root_identity.st_ino),
            )

    def test_read_only_observer_descriptor_reports_kernel_write_denial(self) -> None:
        target = self.root / "read-only-snapshot"
        target.write_bytes(b"sealed")
        descriptor = os.open(target, os.O_RDONLY | os.O_CLOEXEC)
        try:
            self.assertTrue(m4._denied(lambda: os.pwrite(descriptor, b"x", 0)))
            self.assertTrue(m4._denied(lambda: os.ftruncate(descriptor, 0)))
        finally:
            os.close(descriptor)

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

    def test_join_record_race_is_not_returned_as_joined(self) -> None:
        chain = self.setup_chain()
        observed: list[int] = []

        def fault(point: str) -> None:
            if point == "after_join_record":
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
        self.assertEqual(self.row("SELECT remaining,reserved,spent FROM budgets"), (9, 0, 1))
        self.assertEqual(
            self.row(
                "SELECT COUNT(*) FROM journal_entries WHERE event_type='BUDGET_TERMINAL_SPENT'"
            ),
            (1,),
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
        os.close(chain["root_descriptor"])
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
