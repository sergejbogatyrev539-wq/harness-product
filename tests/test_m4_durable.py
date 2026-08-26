from __future__ import annotations

from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

import harness_product.durable as durable_module
from harness_product.durable import DurableOutcome, DurableReason, DurableStore, canonical_digest

from tests import test_durable as m2


class _Fault:
    def __init__(self, point: str) -> None:
        self.point = point

    def __call__(self, point: str) -> None:
        if point == self.point:
            raise RuntimeError(point)


def _contract(issue: dict[str, object]) -> dict[str, object]:
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
                "scope_digest": m2.SCOPE,
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


def _artifact(artifact_id: str, artifact_digest: str, iteration: int = 1) -> dict[str, object]:
    return {"artifact_id": artifact_id, "artifact_digest": artifact_digest, "iteration": iteration}


def _inventory(
    capability_id: str,
    payload: dict[str, object],
    intent: dict[str, object],
    intent_digest: str,
    claim_digest: str,
) -> dict[str, list[dict[str, object]]]:
    reservation = payload["budget_vector"][0]
    reservation_digest = canonical_digest(reservation)
    frame_digest = canonical_digest(
        {
            "record_type": "M4_TRANSACTION_FRAME",
            "transaction_id": intent["transaction_id"],
            "contract_digest": payload["contract_digest"],
            "claim_digest": claim_digest,
            "fencing_epoch": payload["fencing_epoch"],
            "iteration": 1,
        }
    )
    values: dict[str, list[dict[str, object]]] = {name: [] for name in durable_module._D2_CLASSES}
    values["CAPABILITY"] = [_artifact(capability_id, capability_id)]
    values["BUDGET_RESERVATION"] = [_artifact(reservation_digest, reservation_digest)]
    values["TARGET_BINDING"] = [
        _artifact("target/transaction-0001", intent["target_scope_digest"])
    ]
    values["DISPATCH_INTENT"] = [_artifact("transaction-0001", intent_digest)]
    values["STAGED_OUTPUT"] = [
        _artifact("staged-output/transaction-0001", intent["material_digest"])
    ]
    values["PERSISTED_STATE"] = [_artifact("m4-frame/transaction-0001", frame_digest)]
    values["CONTROLLER_TOKEN"] = [_artifact("claim/transaction-0001", claim_digest)]
    return values


def _path_binding(final_digest: str) -> dict[str, object]:
    body: dict[str, object] = {
        "canonical_path": "/project/reports/report.txt",
        "descriptor_id": "stage-target-1",
        "root_id": "stage-root-1",
        "root_identity": m2._digest("c"),
        "mount_id": "mnt:41",
        "mount_identity": m2._digest("d"),
        "resolution_epoch": 1,
        "final_device": 41,
        "final_inode": 73,
        "final_type": "REGULAR_FILE",
        "final_digest": final_digest,
    }
    body["composite_binding_digest"] = canonical_digest(body)
    return body


def _claimed_chain(
    store: DurableStore,
    row: object,
) -> dict[str, object]:
    assert store.bootstrap(m2._bootstrap_raw()).committed
    issue = m2._issue_raw()
    contract = _contract(issue)
    issue["contract_digest"] = contract["contract_digest"]
    activated = store.activate_m4_contract(
        {
            "contract": contract,
            "observed_at": "2026-08-25T12:00:00Z",
            "resolver_verification": m2._verification_source(),
        }
    )
    assert activated.committed
    issued = store.issue(issue)
    assert issued.committed and issued.capability_id is not None
    payload = json.loads(row("SELECT payload_json FROM capabilities")[0])
    assert store.consume(m2._consume_from_payload(issued.capability_id, payload)).committed
    claimed = store.claim_dispatch(
        {
            "transaction_id": "transaction-0001",
            "observed_at": "2026-08-25T12:02:00Z",
            "executor_verification": m2._verification_source(),
        }
    )
    assert claimed.committed
    intent_text, intent_digest, claim_digest = row(
        "SELECT i.intent_json, i.intent_digest, c.claim_digest FROM dispatch_intents i "
        "JOIN dispatch_attempt_claims c USING (transaction_id)"
    )
    intent = json.loads(intent_text)
    return {
        "store": store,
        "contract": contract,
        "payload": payload,
        "capability_id": issued.capability_id,
        "claim_digest": claim_digest,
        "intent": intent,
        "intent_digest": intent_digest,
    }


def _frontier(claimed: dict[str, object], row: object) -> dict[str, object]:
    contract = claimed["contract"]
    frontier: dict[str, object] = {
        "frontier_version": "1.0.0",
        "contract_digest": contract["contract_digest"],
        "contract_version": "1.0.0",
        "authority_domain_id": contract["authority_domain_id"],
        "journal_lineage_id": contract["journal_lineage_id"],
        "root_contract_digest": contract["root_contract_digest"],
        "parent_contract_digest": None,
        "journal_sequence": row("SELECT journal_head_sequence FROM store_meta")[0],
        "joined_iteration": 0,
        "iteration": 1,
        "fencing_epoch": 11,
        "issued_at": "2026-08-25T12:02:00Z",
        "expires_at": "2026-08-25T12:04:00Z",
        "inventory": _inventory(
            claimed["capability_id"],
            claimed["payload"],
            claimed["intent"],
            claimed["intent_digest"],
            claimed["claim_digest"],
        ),
    }
    frontier["frontier_record_digest"] = canonical_digest(frontier)
    return frontier


def _begin_chain(
    store: DurableStore,
    row: object,
) -> dict[str, object]:
    claimed = _claimed_chain(store, row)
    frontier = _frontier(claimed, row)
    bound = store.bind_m4_frontier(
        {
            "transaction_id": "transaction-0001",
            "observed_at": "2026-08-25T12:02:01Z",
            "frontier": frontier,
            "frontier_verification": m2._verification_source(),
        }
    )
    assert bound.committed and bound.d2_frontier_digest is not None
    begun = store.begin_m4_transaction(
        {
            "transaction_id": "transaction-0001",
            "d2_frontier_digest": bound.d2_frontier_digest,
            "observed_at": "2026-08-25T12:02:02Z",
        }
    )
    assert begun.committed and begun.m4_state == "DISPATCHED"
    return {
        **claimed,
        "frontier": frontier,
        "d2_frontier_digest": bound.d2_frontier_digest,
        "before": _path_binding(m2._digest("e")),
        "staged": _path_binding(m2._digest("a")),
        "state": "DISPATCHED",
        "records": {},
    }


class M4DurableLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "m4.sqlite3"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def store(self) -> DurableStore:
        return DurableStore(
            str(self.path),
            m2.ExactVerifier(),
            executor_claim_verifier=m2.ExactVerifier(),
            m4_verifier=m2.ExactVerifier(),
        )

    def store_at(
        self,
        name: str,
        *,
        m4_verifier: object | None = None,
        fault: object | None = None,
    ) -> tuple[Path, DurableStore]:
        path = Path(self.temporary.name) / (name + ".sqlite3")
        return path, DurableStore(
            str(path),
            m2.ExactVerifier(),
            executor_claim_verifier=m2.ExactVerifier(),
            m4_verifier=m4_verifier or m2.ExactVerifier(),
            _fault=fault,
        )

    def row_at(
        self,
        path: Path,
        statement: str,
        parameters: tuple[object, ...] = (),
    ) -> tuple[object, ...]:
        with sqlite3.connect(path) as connection:
            value = connection.execute(statement, parameters).fetchone()
        self.assertIsNotNone(value)
        return value

    def row(self, statement: str, parameters: tuple[object, ...] = ()) -> tuple[object, ...]:
        with sqlite3.connect(self.path) as connection:
            value = connection.execute(statement, parameters).fetchone()
        self.assertIsNotNone(value)
        return value

    def chain(self) -> dict[str, object]:
        return _begin_chain(self.store(), self.row)

    def evidence(self, chain: dict[str, object], state: str) -> dict[str, object]:
        before = chain["before"]
        staged = chain["staged"]
        records = chain["records"]
        if state == "STAGED":
            stage: dict[str, object] = {
                "transaction_id": "transaction-0001",
                "claim_digest": chain["claim_digest"],
                "binding_digest": before["composite_binding_digest"],
                "before_digest": before["final_digest"],
                "after_digest": staged["final_digest"],
                "bytes_written": 17,
            }
            stage["record_digest"] = canonical_digest(stage)
            return {
                "evidence_version": 1,
                "stage_record": stage,
                "source_object_binding": before,
                "staged_object_binding": staged,
            }
        if state == "QUIESCED":
            return {
                "evidence_version": 1,
                "process_tree_id": "process-tree-1",
                "session_id": "session-0001",
                "writer_fencing_epoch": 11,
                "revoked_writer_fds": [9],
                "remaining_writer_fds": [],
                "writer_leases_revoked": True,
                "process_tree_quiesced": True,
                "evidence_digest": m2._digest("1"),
            }
        if state == "SEALED":
            return {
                "evidence_version": 1,
                "seal_type": "LINUX_MEMFD",
                "source_object_binding": staged,
                "snapshot_id": "sealed-snapshot-1",
                "snapshot_device": 1,
                "snapshot_inode": 81,
                "snapshot_size": 17,
                "snapshot_digest": staged["final_digest"],
                "kernel_seals": ["F_SEAL_GROW", "F_SEAL_SEAL", "F_SEAL_SHRINK", "F_SEAL_WRITE"],
                "sealer_principal": "controller-1",
                "sealer_session": "controller-session-1",
                "evidence_digest": m2._digest("2"),
            }
        if state == "POSTCHECKED":
            return {
                "evidence_version": 1,
                "seal_record_digest": records["SEALED"],
                "snapshot_id": "sealed-snapshot-1",
                "snapshot_device": 1,
                "snapshot_inode": 81,
                "snapshot_size": 17,
                "snapshot_digest": staged["final_digest"],
                "observer_principal": "observer-1",
                "observer_session": "observer-session-1",
                "observer_uid": 4001,
                "observer_gid": 5001,
                "observer_writer_fds": [],
                "outcome": "PASS",
                "postcheck_digest": m2._digest("3"),
                "evidence_digest": m2._digest("4"),
            }
        if state == "COMMITTED":
            return {
                "evidence_version": 1,
                "seal_record_digest": records["SEALED"],
                "postcheck_record_digest": records["POSTCHECKED"],
                "snapshot_id": "sealed-snapshot-1",
                "snapshot_device": 1,
                "snapshot_inode": 81,
                "snapshot_size": 17,
                "snapshot_digest": staged["final_digest"],
                "object_binding": staged,
                "committer_principal": "controller-1",
                "committer_session": "controller-session-1",
                "evidence_digest": m2._digest("5"),
            }
        if state == "JOINED":
            return {
                "evidence_version": 1,
                "commit_record_digest": records["COMMITTED"],
                "joined_iteration": 1,
                "frontier_record_digest": chain["frontier"]["frontier_record_digest"],
                "controller_principal": "controller-1",
                "controller_session": "controller-session-1",
                "evidence_digest": m2._digest("6"),
            }
        if state == "DISCARDED":
            return {
                "evidence_version": 1,
                "seal_record_digest": records["SEALED"],
                "disposition": "NO_EFFECT_VERIFIED",
                "evidence_digest": m2._digest("7"),
            }
        if state == "QUARANTINED":
            return {
                "evidence_version": 1,
                "uncertainty": "CRASH_AFTER_" + chain["state"],
                "evidence_digest": m2._digest("8"),
            }
        if state == "RECONCILING":
            return {
                "evidence_version": 1,
                "quarantine_record_digest": records[chain["state"]],
                "evidence_digest": m2._digest("9"),
            }
        raise AssertionError(state)

    def advance(
        self,
        chain: dict[str, object],
        state: str,
        *,
        evidence: dict[str, object] | None = None,
        store: DurableStore | None = None,
    ) -> object:
        actual_store = store or chain["store"]
        result = actual_store.advance_m4(
            {
                "transaction_id": "transaction-0001",
                "expected_state": chain["state"],
                "state": state,
                "observed_at": "2026-08-25T12:02:10Z",
                "evidence": evidence if evidence is not None else self.evidence(chain, state),
                "verification": m2._verification_source(),
            }
        )
        if result.committed:
            chain["state"] = state
            chain["records"][state] = result.record_digest
        return result

    def advance_through(self, target: str) -> dict[str, object]:
        chain = self.chain()
        for state in ("STAGED", "QUIESCED", "SEALED", "POSTCHECKED", "COMMITTED", "JOINED"):
            result = self.advance(chain, state)
            self.assertEqual((result.outcome, result.m4_state), (DurableOutcome.COMMITTED, state))
            if state == target:
                break
        return chain

    def test_exact_stage_to_join_chain_is_atomic_fenced_and_budget_preserving(self) -> None:
        chain = self.advance_through("JOINED")
        self.assertEqual(self.row("SELECT remaining, reserved, spent FROM budgets"), (9, 0, 1))
        recovered = self.store().recover()
        self.assertEqual(recovered.m4_recovery[0].state, "JOINED")
        self.assertFalse(recovered.m4_recovery[0].resume_allowed)
        self.assertFalse(recovered.m4_recovery[0].retry_allowed)
        self.assertEqual(chain["state"], "JOINED")

    def test_contract_and_d2_records_fail_closed_on_q40_q44_mutations(self) -> None:
        contract_cases = {
            "missing": lambda value: value.pop("external_branch"),
            "external": lambda value: value.update(operation_kind="ENDPOINT", external_branch="ALLOW"),
            "stale": lambda value: value.update(expires_at="2026-08-25T12:00:00Z"),
            "T-Q44-CONTRACT-SUBSTITUTION": lambda value: value.update(
                lineage_root=m2._digest("9")
            ),
            "T-Q50-BUDGET-SCOPE-IDENTITY-SUBSTITUTION": lambda value: value[
                "budget_vector"
            ][0].update(scope_digest=m2._digest("8")),
            "T-Q50-BUDGET-LINEAGE-IDENTITY-SUBSTITUTION": lambda value: value[
                "budget_vector"
            ][0].update(lineage_root=m2._digest("9")),
        }
        for name, mutate in contract_cases.items():
            with self.subTest(contract=name):
                path, store = self.store_at("contract-" + name)
                self.assertTrue(store.bootstrap(m2._bootstrap_raw()).committed)
                contract = _contract(m2._issue_raw())
                mutate(contract)
                if frozenset(contract) == durable_module._ACTIVE_CONTRACT_KEYS:
                    body = {key: contract[key] for key in contract if key != "contract_digest"}
                    contract["contract_digest"] = canonical_digest(body)
                result = store.activate_m4_contract(
                    {
                        "contract": contract,
                        "observed_at": "2026-08-25T12:00:00Z",
                        "resolver_verification": m2._verification_source(),
                    }
                )
                self.assertIn(result.outcome, {DurableOutcome.DENY, DurableOutcome.STOP})
                self.assertEqual(self.row_at(path, "SELECT COUNT(*) FROM active_contracts"), (0,))

        frontier_cases = {
            "T-Q40-D2-EMPTY": lambda value: value.update(
                inventory={key: [] for key in durable_module._D2_CLASSES}
            ),
            "T-Q40-D2-STALE": lambda value: value.update(journal_sequence=value["journal_sequence"] - 1),
            "T-Q40-D2-HIDDEN_N_PLUS_2": lambda value: value["inventory"]["CANDIDATE"].append(
                _artifact("candidate-2", m2._digest("8"), 2)
            ),
            "T-Q40-D2-REQUIRED-ARTIFACT-MISSING": lambda value: value["inventory"].update(
                CAPABILITY=[]
            ),
        }
        for index, (name, mutate) in enumerate(frontier_cases.items()):
            with self.subTest(frontier=name):
                path, store = self.store_at("frontier-" + str(index))
                claimed = _claimed_chain(
                    store,
                    lambda statement: self.row_at(path, statement),
                )
                frontier = _frontier(claimed, lambda statement: self.row_at(path, statement))
                before_sequence = self.row_at(path, "SELECT journal_head_sequence FROM store_meta")[0]
                mutate(frontier)
                frontier["frontier_record_digest"] = canonical_digest(
                    {key: frontier[key] for key in frontier if key != "frontier_record_digest"}
                )
                result = store.bind_m4_frontier(
                    {
                        "transaction_id": "transaction-0001",
                        "observed_at": "2026-08-25T12:02:01Z",
                        "frontier": frontier,
                        "frontier_verification": m2._verification_source(),
                    }
                )
                self.assertIn(result.outcome, {DurableOutcome.DENY, DurableOutcome.STOP})
                self.assertEqual(self.row_at(path, "SELECT COUNT(*) FROM d2_frontiers"), (0,))
                self.assertEqual(
                    self.row_at(path, "SELECT journal_head_sequence FROM store_meta"),
                    (before_sequence,),
                )

    def test_same_object_writer_observer_and_typed_chain_mutations_are_denied(self) -> None:
        """T-Q49-COMMIT-TYPED-EVIDENCE-FORGE and T-Q49-JOIN-TYPED-EVIDENCE-FORGE."""
        chain = self.chain()
        stage = self.advance(chain, "STAGED")
        self.assertTrue(stage.committed)
        quiesce = self.evidence(chain, "QUIESCED")
        quiesce["remaining_writer_fds"] = [9]
        self.assertEqual(self.advance(chain, "QUIESCED", evidence=quiesce).outcome, DurableOutcome.DENY)
        self.assertEqual(chain["state"], "STAGED")
        self.assertTrue(self.advance(chain, "QUIESCED").committed)

        seal = self.evidence(chain, "SEALED")
        seal["source_object_binding"] = deepcopy(seal["source_object_binding"])
        seal["source_object_binding"]["final_inode"] += 1
        seal["source_object_binding"]["composite_binding_digest"] = canonical_digest(
            {
                key: seal["source_object_binding"][key]
                for key in seal["source_object_binding"]
                if key != "composite_binding_digest"
            }
        )
        self.assertEqual(self.advance(chain, "SEALED", evidence=seal).outcome, DurableOutcome.DENY)
        self.assertTrue(self.advance(chain, "SEALED").committed)

        postcheck = self.evidence(chain, "POSTCHECKED")
        postcheck["observer_principal"] = chain["payload"]["audience_id"]
        self.assertEqual(
            self.advance(chain, "POSTCHECKED", evidence=postcheck).outcome,
            DurableOutcome.DENY,
        )
        postcheck = self.evidence(chain, "POSTCHECKED")
        postcheck["snapshot_inode"] += 1
        self.assertEqual(
            self.advance(chain, "POSTCHECKED", evidence=postcheck).outcome,
            DurableOutcome.DENY,
        )
        self.assertTrue(self.advance(chain, "POSTCHECKED").committed)

        commit = self.evidence(chain, "COMMITTED")
        commit["object_binding"] = deepcopy(commit["object_binding"])
        commit["object_binding"]["resolution_epoch"] += 1
        commit["object_binding"]["composite_binding_digest"] = canonical_digest(
            {
                key: commit["object_binding"][key]
                for key in commit["object_binding"]
                if key != "composite_binding_digest"
            }
        )
        self.assertEqual(self.advance(chain, "COMMITTED", evidence=commit).outcome, DurableOutcome.DENY)
        self.assertEqual(self.row("SELECT remaining, reserved, spent FROM budgets"), (9, 1, 0))
        self.assertTrue(self.advance(chain, "COMMITTED").committed)
        self.assertEqual(self.row("SELECT remaining, reserved, spent FROM budgets"), (9, 0, 1))

        join = self.evidence(chain, "JOINED")
        join["commit_record_digest"] = m2._digest("9")
        self.assertEqual(self.advance(chain, "JOINED", evidence=join).outcome, DurableOutcome.DENY)
        self.assertTrue(self.advance(chain, "JOINED").committed)

    def test_duplicate_commit_join_and_m2_settle_cannot_spend_twice(self) -> None:
        chain = self.advance_through("COMMITTED")
        budget = self.row("SELECT remaining, reserved, spent FROM budgets")
        duplicate = chain["store"].advance_m4(
            {
                "transaction_id": "transaction-0001",
                "expected_state": "POSTCHECKED",
                "state": "COMMITTED",
                "observed_at": "2026-08-25T12:02:10Z",
                "evidence": self.evidence(chain, "COMMITTED"),
                "verification": m2._verification_source(),
            }
        )
        self.assertEqual((duplicate.outcome, duplicate.reason), (DurableOutcome.DENY, DurableReason.ILLEGAL_TRANSITION))
        self.assertEqual(self.row("SELECT remaining, reserved, spent FROM budgets"), budget)
        bypass = chain["store"].settle(
            {
                "transaction_id": "transaction-0001",
                "disposition": "SPENT",
                "observed_at": "2026-08-25T12:02:10Z",
                "evidence": {"evidence_digest": m2._digest("7")},
            }
        )
        self.assertEqual((bypass.outcome, bypass.reason), (DurableOutcome.DENY, DurableReason.ILLEGAL_TRANSITION))
        self.assertTrue(self.advance(chain, "JOINED").committed)
        duplicate_join = chain["store"].advance_m4(
            {
                "transaction_id": "transaction-0001",
                "expected_state": "COMMITTED",
                "state": "JOINED",
                "observed_at": "2026-08-25T12:02:10Z",
                "evidence": self.evidence(chain, "JOINED"),
                "verification": m2._verification_source(),
            }
        )
        self.assertEqual(duplicate_join.outcome, DurableOutcome.DENY)
        self.assertEqual(self.row("SELECT remaining, reserved, spent FROM budgets"), budget)
        self.assertEqual(
            self.row("SELECT COUNT(*) FROM journal_entries WHERE event_type='BUDGET_TERMINAL_SPENT'"),
            (1,),
        )

    def test_joined_uncertainty_reconciles_without_a_second_budget_terminal(self) -> None:
        chain = self.advance_through("JOINED")
        spent = self.row("SELECT remaining, reserved, spent FROM budgets")
        reconciled = self.advance(chain, "RECONCILING")
        self.assertEqual(
            (reconciled.outcome, reconciled.m4_state),
            (DurableOutcome.COMMITTED, "RECONCILING"),
        )
        self.assertEqual(self.row("SELECT remaining, reserved, spent FROM budgets"), spent)
        self.assertEqual(
            self.row("SELECT COUNT(*) FROM journal_entries WHERE event_type='BUDGET_TERMINAL_SPENT'"),
            (1,),
        )
        recovered = chain["store"].recover().m4_recovery[0]
        self.assertEqual(recovered.state, "RECONCILING")
        self.assertFalse(recovered.resume_allowed)
        self.assertFalse(recovered.retry_allowed)

    def test_four_part_budget_identity_is_immutable_in_every_transition(self) -> None:
        """T-Q50-BUDGET-FOUR-PART-KEY-PRESERVED across every M4 record."""
        self.advance_through("JOINED")
        expected = [("writes", "FILES", m2.SCOPE, m2.LINEAGE, 1)]
        with sqlite3.connect(self.path) as connection:
            reservation = connection.execute(
                "SELECT name, unit, scope_digest, lineage_root, amount FROM budget_reservations"
            ).fetchall()
            records = connection.execute(
                "SELECT record_json FROM m4_transition_records ORDER BY transition_index"
            ).fetchall()
        self.assertEqual(reservation, expected)
        for (record_text,) in records:
            record = json.loads(record_text)
            self.assertEqual(
                record["budget_vector"],
                [
                    {
                        "name": "writes",
                        "unit": "FILES",
                        "scope_digest": m2.SCOPE,
                        "lineage_root": m2.LINEAGE,
                        "amount": 1,
                    }
                ],
            )

    def test_faults_before_commit_roll_back_and_lost_ack_reopens_complete_state(self) -> None:
        phases = {
            "STAGED": (),
            "SEALED": ("STAGED", "QUIESCED"),
            "POSTCHECKED": ("STAGED", "QUIESCED", "SEALED"),
            "COMMITTED": ("STAGED", "QUIESCED", "SEALED", "POSTCHECKED"),
            "JOINED": ("STAGED", "QUIESCED", "SEALED", "POSTCHECKED", "COMMITTED"),
        }
        for state, prerequisites in phases.items():
            for boundary in ("after_event", "after_commit_before_ack"):
                with self.subTest(state=state, boundary=boundary):
                    name = "fault-" + state.lower() + "-" + boundary
                    path, normal = self.store_at(name)
                    fetch = lambda statement: self.row_at(path, statement)
                    chain = _begin_chain(normal, fetch)
                    for prerequisite in prerequisites:
                        self.assertTrue(self.advance(chain, prerequisite, store=normal).committed)
                    prior_state = chain["state"]
                    prior_budget = self.row_at(path, "SELECT remaining, reserved, spent FROM budgets")
                    _, faulted = self.store_at(
                        name,
                        fault=_Fault("m4_" + state.lower() + "_" + boundary),
                    )
                    result = self.advance(chain, state, store=faulted)
                    self.assertEqual(result.outcome, DurableOutcome.STOP)
                    reopen = DurableStore(
                        str(path),
                        m2.ExactVerifier(),
                        executor_claim_verifier=m2.ExactVerifier(),
                        m4_verifier=m2.ExactVerifier(),
                    )
                    recovered = reopen.recover()
                    expected = state if boundary == "after_commit_before_ack" else prior_state
                    self.assertEqual(recovered.m4_recovery[0].state, expected)
                    self.assertFalse(recovered.m4_recovery[0].resume_allowed)
                    self.assertFalse(recovered.m4_recovery[0].retry_allowed)
                    if boundary == "after_event":
                        self.assertEqual(
                            self.row_at(path, "SELECT remaining, reserved, spent FROM budgets"),
                            prior_budget,
                        )
                    elif state in {"COMMITTED", "JOINED"}:
                        self.assertEqual(
                            self.row_at(path, "SELECT remaining, reserved, spent FROM budgets"),
                            (9, 0, 1),
                        )

    def test_dispatch_fault_and_stage_crash_quarantine_without_retry(self) -> None:
        for boundary in ("m4_begin_after_event", "m4_begin_after_commit_before_ack"):
            with self.subTest(boundary=boundary):
                name = "dispatch-" + boundary
                path, normal = self.store_at(name)
                fetch = lambda statement: self.row_at(path, statement)
                claimed = _claimed_chain(normal, fetch)
                frontier = _frontier(claimed, fetch)
                bound = normal.bind_m4_frontier(
                    {
                        "transaction_id": "transaction-0001",
                        "observed_at": "2026-08-25T12:02:01Z",
                        "frontier": frontier,
                        "frontier_verification": m2._verification_source(),
                    }
                )
                self.assertTrue(bound.committed)
                _, faulted = self.store_at(name, fault=_Fault(boundary))
                result = faulted.begin_m4_transaction(
                    {
                        "transaction_id": "transaction-0001",
                        "d2_frontier_digest": bound.d2_frontier_digest,
                        "observed_at": "2026-08-25T12:02:02Z",
                    }
                )
                self.assertEqual(result.outcome, DurableOutcome.STOP)
                expected = 1 if boundary.endswith("after_commit_before_ack") else 0
                self.assertEqual(self.row_at(path, "SELECT COUNT(*) FROM m4_transactions"), (expected,))

        chain = self.advance_through("STAGED")
        quarantined = self.advance(chain, "QUARANTINED")
        self.assertEqual((quarantined.outcome, quarantined.m4_state), (DurableOutcome.COMMITTED, "QUARANTINED"))
        self.assertEqual(self.row("SELECT remaining, reserved, spent FROM budgets"), (9, 1, 0))
        self.assertEqual(
            self.row("SELECT disposition FROM budget_reservations"),
            ("QUARANTINED_ESCROW",),
        )
        recovery = self.store().recover()
        self.assertEqual(recovery.m4_recovery[0].state, "QUARANTINED")
        self.assertFalse(recovery.m4_recovery[0].resume_allowed)
        self.assertFalse(recovery.m4_recovery[0].retry_allowed)
        self.assertTrue(self.advance(chain, "RECONCILING").committed)

    def test_verifier_freshness_revocation_and_fence_are_rechecked_at_every_transition(self) -> None:
        chain = self.chain()
        forged = deepcopy(self.evidence(chain, "STAGED"))
        result = chain["store"].advance_m4(
            {
                "transaction_id": "transaction-0001",
                "expected_state": "DISPATCHED",
                "state": "STAGED",
                "observed_at": "2026-08-25T12:02:10Z",
                "evidence": forged,
                "verification": {
                    **m2._verification_source(),
                    "proof": m2._digest("4"),
                },
            }
        )
        self.assertEqual((result.outcome, result.reason), (DurableOutcome.DENY, DurableReason.M4_EVIDENCE_INVALID))
        stale = chain["store"].advance_m4(
            {
                "transaction_id": "transaction-0001",
                "expected_state": "DISPATCHED",
                "state": "STAGED",
                "observed_at": "2026-08-25T12:04:00Z",
                "evidence": forged,
                "verification": m2._verification_source(),
            }
        )
        self.assertEqual((stale.outcome, stale.reason), (DurableOutcome.DENY, DurableReason.EXPIRED))
        rejected = DurableStore(
            str(self.path),
            m2.ExactVerifier(),
            executor_claim_verifier=m2.ExactVerifier(),
            m4_verifier=m2.ExactVerifier(status=durable_module.VerificationStatus.REJECTED),
        )
        denied = self.advance(chain, "STAGED", store=rejected)
        self.assertEqual((denied.outcome, denied.reason), (DurableOutcome.DENY, DurableReason.M4_EVIDENCE_INVALID))
        self.assertEqual(self.row("SELECT state FROM m4_transactions"), ("DISPATCHED",))

        self.assertTrue(chain["store"].advance_fence(
            {
                "expected_fencing_epoch": 11,
                "new_fencing_epoch": 12,
                "reason_digest": m2._digest("c"),
            }
        ).committed)
        fenced = self.advance(chain, "STAGED")
        self.assertEqual((fenced.outcome, fenced.reason), (DurableOutcome.DENY, DurableReason.M4_EVIDENCE_INVALID))

    def test_concurrent_transition_has_one_winner_and_one_record(self) -> None:
        chain = self.chain()
        raw = {
            "transaction_id": "transaction-0001",
            "expected_state": "DISPATCHED",
            "state": "STAGED",
            "observed_at": "2026-08-25T12:02:10Z",
            "evidence": self.evidence(chain, "STAGED"),
            "verification": m2._verification_source(),
        }

        def attempt() -> object:
            return self.store().advance_m4(deepcopy(raw))

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: attempt(), range(2)))
        self.assertEqual(sum(result.committed for result in results), 1)
        self.assertEqual(sum(result.outcome is DurableOutcome.DENY for result in results), 1)
        self.assertEqual(self.row("SELECT state FROM m4_transactions"), ("STAGED",))
        self.assertEqual(self.row("SELECT COUNT(*) FROM m4_transition_records"), (1,))
        self.assertEqual(self.row("SELECT remaining, reserved, spent FROM budgets"), (9, 1, 0))

    def test_discard_releases_only_verified_sealed_no_effect_and_commit_cannot_discard(self) -> None:
        chain = self.advance_through("SEALED")
        discarded = self.advance(chain, "DISCARDED")
        self.assertEqual((discarded.outcome, discarded.m4_state), (DurableOutcome.COMMITTED, "DISCARDED"))
        self.assertEqual(self.row("SELECT remaining, reserved, spent FROM budgets"), (10, 0, 0))
        self.assertEqual(self.row("SELECT disposition FROM budget_reservations"), ("RELEASED",))
        self.assertEqual(self.store().recover().m4_recovery[0].state, "DISCARDED")

        path, store = self.store_at("committed-no-discard")
        fetch = lambda statement: self.row_at(path, statement)
        other = _begin_chain(store, fetch)
        for state in ("STAGED", "QUIESCED", "SEALED", "POSTCHECKED", "COMMITTED"):
            self.assertTrue(self.advance(other, state, store=store).committed)
        attempt = store.advance_m4(
            {
                "transaction_id": "transaction-0001",
                "expected_state": "COMMITTED",
                "state": "DISCARDED",
                "observed_at": "2026-08-25T12:02:10Z",
                "evidence": {
                    "evidence_version": 1,
                    "seal_record_digest": other["records"]["SEALED"],
                    "disposition": "NO_EFFECT_VERIFIED",
                    "evidence_digest": m2._digest("7"),
                },
                "verification": m2._verification_source(),
            }
        )
        self.assertEqual((attempt.outcome, attempt.reason), (DurableOutcome.DENY, DurableReason.ILLEGAL_TRANSITION))
        self.assertEqual(self.row_at(path, "SELECT disposition FROM budget_reservations"), ("SPENT",))

    def test_m4_record_mutation_is_detected_fail_closed_on_reopen(self) -> None:
        self.advance_through("SEALED")
        with sqlite3.connect(self.path) as connection:
            text = connection.execute(
                "SELECT record_json FROM m4_transition_records WHERE state='SEALED'"
            ).fetchone()[0]
            record = json.loads(text)
            record["evidence"]["snapshot_inode"] += 1
            connection.execute(
                "UPDATE m4_transition_records SET record_json=? WHERE state='SEALED'",
                (json.dumps(record, sort_keys=True, separators=(",", ":")),),
            )
        reopened = self.store()
        result = reopened.recover()
        self.assertEqual((result.outcome, result.reason), (DurableOutcome.STOP, DurableReason.CORRUPT_STORE))


if __name__ == "__main__":
    unittest.main()
