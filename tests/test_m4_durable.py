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
        "target_authority_digest": issue["target_authority_digest"],
        "profile_digest": issue["profile_digest"],
        "operation_kind": "STAGEABLE_FILESYSTEM",
        "external_branch": "DENY",
        "max_iterations": 2,
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
    *,
    iteration: int = 1,
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
            "iteration": iteration,
        }
    )
    values: dict[str, list[dict[str, object]]] = {name: [] for name in durable_module._D2_CLASSES}
    values["CAPABILITY"] = [_artifact(capability_id, capability_id, iteration)]
    values["BUDGET_RESERVATION"] = [
        _artifact(reservation_digest, reservation_digest, iteration)
    ]
    values["TARGET_BINDING"] = [
        _artifact(
            "target/" + intent["transaction_id"],
            intent["target_authority_digest"],
            iteration,
        )
    ]
    values["DISPATCH_INTENT"] = [
        _artifact(intent["transaction_id"], intent_digest, iteration)
    ]
    values["STAGED_OUTPUT"] = [
        _artifact(
            "staged-output/" + intent["transaction_id"],
            intent["material_digest"],
            iteration,
        )
    ]
    values["PERSISTED_STATE"] = [
        _artifact("m4-frame/" + intent["transaction_id"], frame_digest, iteration)
    ]
    values["CONTROLLER_TOKEN"] = [
        _artifact("claim/" + intent["transaction_id"], claim_digest, iteration)
    ]
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


def _publication_binding(final_digest: str, inode: int) -> dict[str, object]:
    body = _path_binding(final_digest)
    body.update(
        descriptor_id="publication-target-1",
        root_id="publication-root-1",
        root_identity=m2._digest("7"),
        mount_identity=m2._digest("8"),
        final_inode=inode,
    )
    body["composite_binding_digest"] = canonical_digest(
        {key: body[key] for key in body if key != "composite_binding_digest"}
    )
    return body


def _external_record(payload: dict[str, object]) -> dict[str, object]:
    source = m2._verification_source()
    return {
        "verification_version": 1,
        "verifier_id": source["verifier_id"],
        "issuer_id": source["issuer_id"],
        "key_id": source["key_id"],
        "payload_digest": canonical_digest(payload),
        "bindings": payload,
        "proof": source["proof"],
    }


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


def _frontier(
    claimed: dict[str, object],
    row: object,
    *,
    joined_iteration: int = 0,
    iteration: int = 1,
) -> dict[str, object]:
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
        "joined_iteration": joined_iteration,
        "iteration": iteration,
        "fencing_epoch": 11,
        "issued_at": "2026-08-25T12:02:00Z",
        "expires_at": "2026-08-25T12:04:00Z",
        "inventory": _inventory(
            claimed["capability_id"],
            claimed["payload"],
            claimed["intent"],
            claimed["intent_digest"],
            claimed["claim_digest"],
            iteration=iteration,
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
        "publication_before": _publication_binding(m2._digest("e"), 91),
        "published": _publication_binding(m2._digest("a"), 92),
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
        target_authority = chain["payload"]["target_authority_digest"]
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
            subject = {
                "principal_id": "observer-1",
                "session_id": "observer-session-1",
                "uid": 4001,
                "gid": 5001,
                "security_label": "observer-label-1",
                "credential_namespace": "observer-credentials-1",
                "namespace_id": "observer-namespace-1",
                "executable_digest": m2._digest("3"),
            }
            receipt_body = {
                "receipt_version": 1,
                "outcome": "PASS",
                "transaction_id": "transaction-0001",
                "capability_id": chain["capability_id"],
                "claim_digest": chain["claim_digest"],
                "intent_digest": chain["intent_digest"],
                "decision_digest": chain["payload"]["decision_digest"],
                "authorized_envelope_digest": chain["payload"][
                    "authorized_envelope_digest"
                ],
                "target_authority_digest": target_authority,
                "profile_digest": chain["payload"]["profile_digest"],
                "placement_digest": chain["payload"]["placement_digest"],
                "session_id": chain["payload"]["session_id"],
                "seal_record_digest": records["SEALED"],
                "snapshot_id": "sealed-snapshot-1",
                "snapshot_device": 1,
                "snapshot_inode": 81,
                "snapshot_size": 17,
                "snapshot_digest": staged["final_digest"],
                "observer_subject": subject,
                "proposal_digest": m2._digest("3"),
                "revocation_epoch": 7,
                "fencing_epoch": 11,
                "observed_at": "2026-08-25T12:02:10Z",
            }
            receipt = {
                **receipt_body,
                "receipt_digest": canonical_digest(receipt_body),
            }
            return {
                "evidence_version": 1,
                "seal_record_digest": records["SEALED"],
                "snapshot_id": "sealed-snapshot-1",
                "snapshot_device": 1,
                "snapshot_inode": 81,
                "snapshot_size": 17,
                "snapshot_digest": staged["final_digest"],
                "observer_receipt": receipt,
                "observer_verification": _external_record(receipt),
                "evidence_digest": m2._digest("4"),
            }
        if state == "COMMITTED":
            publisher_subject = {
                "principal_id": "publisher-1",
                "session_id": "publisher-session-1",
                "uid": 4002,
                "gid": 5002,
                "security_label": "publisher-label-1",
                "credential_namespace": "publisher-credentials-1",
                "namespace_id": "publisher-namespace-1",
                "executable_digest": m2._digest("4"),
            }
            receipt_body = {
                "receipt_version": 1,
                "outcome": "PUBLISHED",
                "transaction_id": "transaction-0001",
                "target_authority_digest": target_authority,
                "snapshot_id": "sealed-snapshot-1",
                "snapshot_digest": staged["final_digest"],
                "snapshot_size": 17,
                "before_binding": chain["publication_before"],
                "published_binding": chain["published"],
                "publisher_subject": publisher_subject,
                "authorization_digest": m2._digest("5"),
                "publication_method": "ATOMIC_REPLACE_FSYNC",
                "observed_at": "2026-08-25T12:02:10Z",
            }
            authorization_body = {
                "authorization_version": 1,
                "transaction_id": "transaction-0001",
                "decision_digest": chain["payload"]["decision_digest"],
                "authorized_envelope_digest": chain["payload"][
                    "authorized_envelope_digest"
                ],
                "claim_digest": chain["claim_digest"],
                "intent_digest": chain["intent_digest"],
                "capability_id": chain["capability_id"],
                "contract_digest": chain["contract"]["contract_digest"],
                "d2_frontier_digest": chain["d2_frontier_digest"],
                "iteration": 1,
                "target_authority_digest": target_authority,
                "publication_target_binding_digest": chain["publication_before"][
                    "composite_binding_digest"
                ],
                "snapshot_id": "sealed-snapshot-1",
                "snapshot_digest": staged["final_digest"],
                "snapshot_size": 17,
                "seal_record_digest": records["SEALED"],
                "postcheck_record_digest": records["POSTCHECKED"],
                "profile_digest": chain["payload"]["profile_digest"],
                "placement_digest": chain["payload"]["placement_digest"],
                "session_id": chain["payload"]["session_id"],
                "revocation_epoch": 7,
                "fencing_epoch": 11,
                "publisher_principal": "publisher-1",
                "publisher_session": "publisher-session-1",
                "observed_at": "2026-08-25T12:02:10Z",
                "expires_at": "2026-08-25T12:04:00Z",
            }
            authorization = {
                **authorization_body,
                "authorization_digest": canonical_digest(authorization_body),
            }
            receipt = {
                **receipt_body,
                "authorization_digest": authorization["authorization_digest"],
                "receipt_digest": canonical_digest(
                    {
                        **receipt_body,
                        "authorization_digest": authorization["authorization_digest"],
                    }
                ),
            }
            return {
                "evidence_version": 1,
                "seal_record_digest": records["SEALED"],
                "postcheck_record_digest": records["POSTCHECKED"],
                "snapshot_id": "sealed-snapshot-1",
                "snapshot_device": 1,
                "snapshot_inode": 81,
                "snapshot_size": 17,
                "snapshot_digest": staged["final_digest"],
                "publication_authorization": authorization,
                "publication_authorization_verification": _external_record(authorization),
                "publication_receipt": receipt,
                "publication_verification": _external_record(receipt),
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
        postcheck["observer_receipt"]["observer_subject"]["principal_id"] = chain["payload"]["audience_id"]
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
        commit["publication_receipt"] = deepcopy(commit["publication_receipt"])
        commit["publication_receipt"]["published_binding"]["resolution_epoch"] += 1
        commit["publication_receipt"]["published_binding"]["composite_binding_digest"] = canonical_digest(
            {
                key: commit["publication_receipt"]["published_binding"][key]
                for key in commit["publication_receipt"]["published_binding"]
                if key != "composite_binding_digest"
            }
        )
        self.assertEqual(self.advance(chain, "COMMITTED", evidence=commit).outcome, DurableOutcome.DENY)
        self.assertEqual(self.row("SELECT remaining, reserved, spent FROM budgets"), (9, 1, 0))
        committed = self.advance(chain, "COMMITTED")
        self.assertTrue(
            committed.committed,
            (committed.outcome, committed.reason, committed.m4_state),
        )
        self.assertEqual(self.row("SELECT remaining, reserved, spent FROM budgets"), (9, 0, 1))

        join = self.evidence(chain, "JOINED")
        join["commit_record_digest"] = m2._digest("9")
        self.assertEqual(self.advance(chain, "JOINED", evidence=join).outcome, DurableOutcome.DENY)
        self.assertTrue(self.advance(chain, "JOINED").committed)

    def test_observer_receipt_full_binding_mutations_fail_closed(self) -> None:
        chain = self.advance_through("SEALED")
        cases = {
            "missing-capability": lambda receipt: receipt.pop("capability_id"),
            "capability": lambda receipt: receipt.update(capability_id=m2._digest("9")),
            "claim": lambda receipt: receipt.update(claim_digest=m2._digest("9")),
            "intent": lambda receipt: receipt.update(intent_digest=m2._digest("9")),
            "decision": lambda receipt: receipt.update(decision_digest=m2._digest("9")),
            "envelope": lambda receipt: receipt.update(
                authorized_envelope_digest=m2._digest("9")
            ),
            "target-authority": lambda receipt: receipt.update(
                target_authority_digest=m2._digest("9")
            ),
            "profile": lambda receipt: receipt.update(profile_digest=m2._digest("9")),
            "placement": lambda receipt: receipt.update(placement_digest=m2._digest("9")),
            "session": lambda receipt: receipt.update(session_id="session-other"),
            "snapshot": lambda receipt: receipt.update(snapshot_digest=m2._digest("9")),
            "observer": lambda receipt: receipt["observer_subject"].update(
                principal_id=chain["payload"]["principal_id"]
            ),
            "time": lambda receipt: receipt.update(observed_at="2026-08-25T12:02:09Z"),
            "revocation": lambda receipt: receipt.update(revocation_epoch=8),
            "fence": lambda receipt: receipt.update(fencing_epoch=12),
            "unknown": lambda receipt: receipt.update(verified=True),
        }
        for name, mutate in cases.items():
            with self.subTest(field=name):
                evidence = self.evidence(chain, "POSTCHECKED")
                receipt = evidence["observer_receipt"]
                mutate(receipt)
                receipt["receipt_digest"] = canonical_digest(
                    {key: receipt[key] for key in receipt if key != "receipt_digest"}
                )
                evidence["observer_verification"] = _external_record(receipt)
                result = self.advance(chain, "POSTCHECKED", evidence=evidence)
                self.assertIn(result.outcome, {DurableOutcome.DENY, DurableOutcome.STOP})
                self.assertEqual(chain["state"], "SEALED")

        for field in ("proof", "key_id"):
            with self.subTest(verification=field):
                verification = m2._verification_source()
                verification[field] = m2._digest("9") if field == "proof" else "wrong-key"
                denied = chain["store"].advance_m4(
                    {
                        "transaction_id": "transaction-0001",
                        "expected_state": "SEALED",
                        "state": "POSTCHECKED",
                        "observed_at": "2026-08-25T12:02:10Z",
                        "evidence": self.evidence(chain, "POSTCHECKED"),
                        "verification": verification,
                    }
                )
                self.assertEqual(denied.outcome, DurableOutcome.DENY)
        self.assertTrue(self.advance(chain, "POSTCHECKED").committed)

    def test_publication_authorization_and_receipt_binding_mutations_fail_closed(self) -> None:
        chain = self.advance_through("POSTCHECKED")

        authorization_cases = {
            "transaction": lambda value: value.update(transaction_id="transaction-other"),
            "decision": lambda value: value.update(decision_digest=m2._digest("9")),
            "envelope": lambda value: value.update(
                authorized_envelope_digest=m2._digest("9")
            ),
            "claim": lambda value: value.update(claim_digest=m2._digest("9")),
            "intent": lambda value: value.update(intent_digest=m2._digest("9")),
            "capability": lambda value: value.update(capability_id=m2._digest("9")),
            "contract": lambda value: value.update(contract_digest=m2._digest("9")),
            "frontier": lambda value: value.update(d2_frontier_digest=m2._digest("9")),
            "iteration": lambda value: value.update(iteration=2),
            "target-authority": lambda value: value.update(
                target_authority_digest=m2._digest("9")
            ),
            "target-binding": lambda value: value.update(
                publication_target_binding_digest=m2._digest("9")
            ),
            "snapshot-id": lambda value: value.update(snapshot_id="snapshot-other"),
            "snapshot-digest": lambda value: value.update(snapshot_digest=m2._digest("9")),
            "snapshot-size": lambda value: value.update(snapshot_size=18),
            "seal": lambda value: value.update(seal_record_digest=m2._digest("9")),
            "postcheck": lambda value: value.update(postcheck_record_digest=m2._digest("9")),
            "profile": lambda value: value.update(profile_digest=m2._digest("9")),
            "placement": lambda value: value.update(placement_digest=m2._digest("9")),
            "session": lambda value: value.update(session_id="session-other"),
            "revocation": lambda value: value.update(revocation_epoch=8),
            "fence": lambda value: value.update(fencing_epoch=12),
            "publisher": lambda value: value.update(publisher_principal="publisher-other"),
            "publisher-session": lambda value: value.update(
                publisher_session="publisher-session-other"
            ),
            "time": lambda value: value.update(observed_at="2026-08-25T12:02:09Z"),
            "expiry": lambda value: value.update(expires_at="2026-08-25T12:02:10Z"),
            "unknown": lambda value: value.update(verified=True),
        }
        for name, mutate in authorization_cases.items():
            with self.subTest(record="authorization", field=name):
                evidence = deepcopy(self.evidence(chain, "COMMITTED"))
                authorization = evidence["publication_authorization"]
                mutate(authorization)
                authorization["authorization_digest"] = canonical_digest(
                    {
                        key: authorization[key]
                        for key in authorization
                        if key != "authorization_digest"
                    }
                )
                evidence["publication_authorization_verification"] = _external_record(
                    authorization
                )
                receipt = evidence["publication_receipt"]
                receipt["authorization_digest"] = authorization["authorization_digest"]
                receipt["receipt_digest"] = canonical_digest(
                    {key: receipt[key] for key in receipt if key != "receipt_digest"}
                )
                evidence["publication_verification"] = _external_record(receipt)
                denied = self.advance(chain, "COMMITTED", evidence=evidence)
                self.assertIn(denied.outcome, {DurableOutcome.DENY, DurableOutcome.STOP})
                self.assertEqual(chain["state"], "POSTCHECKED")

        def rebound(binding: dict[str, object]) -> None:
            binding["composite_binding_digest"] = canonical_digest(
                {
                    key: binding[key]
                    for key in binding
                    if key != "composite_binding_digest"
                }
            )

        receipt_cases = {
            "transaction": lambda value: value.update(transaction_id="transaction-other"),
            "target-authority": lambda value: value.update(
                target_authority_digest=m2._digest("9")
            ),
            "snapshot-id": lambda value: value.update(snapshot_id="snapshot-other"),
            "snapshot-digest": lambda value: value.update(snapshot_digest=m2._digest("9")),
            "snapshot-size": lambda value: value.update(snapshot_size=18),
            "before-path": lambda value: (
                value["before_binding"].update(canonical_path="/staging/other.txt"),
                rebound(value["before_binding"]),
            ),
            "published-root": lambda value: (
                value["published_binding"].update(root_identity=m2._digest("9")),
                rebound(value["published_binding"]),
            ),
            "published-mount": lambda value: (
                value["published_binding"].update(mount_identity=m2._digest("9")),
                rebound(value["published_binding"]),
            ),
            "published-digest": lambda value: (
                value["published_binding"].update(final_digest=m2._digest("9")),
                rebound(value["published_binding"]),
            ),
            "publisher": lambda value: value["publisher_subject"].update(
                principal_id=chain["payload"]["principal_id"]
            ),
            "authorization": lambda value: value.update(authorization_digest=m2._digest("9")),
            "method": lambda value: value.update(publication_method="PLAIN_RENAME"),
            "time": lambda value: value.update(observed_at="2026-08-25T12:02:09Z"),
            "unknown": lambda value: value.update(verified=True),
        }
        for name, mutate in receipt_cases.items():
            with self.subTest(record="receipt", field=name):
                evidence = deepcopy(self.evidence(chain, "COMMITTED"))
                receipt = evidence["publication_receipt"]
                mutate(receipt)
                receipt["receipt_digest"] = canonical_digest(
                    {key: receipt[key] for key in receipt if key != "receipt_digest"}
                )
                evidence["publication_verification"] = _external_record(receipt)
                denied = self.advance(chain, "COMMITTED", evidence=evidence)
                self.assertIn(denied.outcome, {DurableOutcome.DENY, DurableOutcome.STOP})
                self.assertEqual(chain["state"], "POSTCHECKED")

        self.assertEqual(self.row("SELECT remaining, reserved, spent FROM budgets"), (9, 1, 0))
        committed = self.advance(chain, "COMMITTED")
        self.assertTrue(
            committed.committed,
            (committed.outcome, committed.reason, committed.m4_state),
        )

    def test_external_receipt_records_are_mandatory_and_reverified(self) -> None:
        chain = self.advance_through("SEALED")
        missing = self.evidence(chain, "POSTCHECKED")
        missing.pop("observer_verification")
        self.assertEqual(
            self.advance(chain, "POSTCHECKED", evidence=missing).outcome,
            DurableOutcome.STOP,
        )
        invalid = self.evidence(chain, "POSTCHECKED")
        invalid["observer_verification"]["proof"] = m2._digest("9")
        self.assertEqual(
            self.advance(chain, "POSTCHECKED", evidence=invalid).outcome,
            DurableOutcome.DENY,
        )
        rebound = self.evidence(chain, "POSTCHECKED")
        rebound["observer_verification"]["bindings"] = {
            **rebound["observer_receipt"],
            "snapshot_digest": m2._digest("9"),
        }
        rebound["observer_verification"]["payload_digest"] = canonical_digest(
            rebound["observer_verification"]["bindings"]
        )
        self.assertEqual(
            self.advance(chain, "POSTCHECKED", evidence=rebound).outcome,
            DurableOutcome.DENY,
        )
        self.assertTrue(self.advance(chain, "POSTCHECKED").committed)

        commit = self.evidence(chain, "COMMITTED")
        commit.pop("publication_authorization_verification")
        self.assertEqual(
            self.advance(chain, "COMMITTED", evidence=commit).outcome,
            DurableOutcome.STOP,
        )
        swapped = self.evidence(chain, "COMMITTED")
        swapped["publication_authorization_verification"] = deepcopy(
            swapped["publication_verification"]
        )
        self.assertEqual(
            self.advance(chain, "COMMITTED", evidence=swapped).outcome,
            DurableOutcome.DENY,
        )
        invalid = self.evidence(chain, "COMMITTED")
        invalid["publication_verification"]["proof"] = m2._digest("9")
        self.assertEqual(
            self.advance(chain, "COMMITTED", evidence=invalid).outcome,
            DurableOutcome.DENY,
        )
        self.assertTrue(self.advance(chain, "COMMITTED").committed)
        recovered = self.store().recover().m4_recovery[0]
        self.assertEqual(recovered.state, "COMMITTED")
        self.assertFalse(recovered.resume_allowed)
        self.assertFalse(recovered.retry_allowed)

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

    def test_m4_sec_005_reconciling_fences_next_iteration_across_reopen(self) -> None:
        store = self.store()
        first = _begin_chain(store, self.row)

        def prepare(number: int, *, claim: bool) -> dict[str, object]:
            transaction_id = f"transaction-000{number}"
            issue = m2._issue_raw(
                nonce=f"nonce-000{number}",
                idempotency_key_digest=m2._digest("0123456789abcdef"[number]),
            )
            issue["contract_digest"] = first["contract"]["contract_digest"]
            issue["target_authority_digest"] = first["contract"][
                "target_authority_digest"
            ]
            issued = store.issue(issue)
            self.assertTrue(issued.committed)
            payload = json.loads(
                self.row(
                    "SELECT payload_json FROM capabilities WHERE capability_id=?",
                    (issued.capability_id,),
                )[0]
            )
            consumed = store.consume(
                m2._consume_from_payload(
                    issued.capability_id, payload, transaction_id=transaction_id
                )
            )
            self.assertTrue(consumed.committed)
            result: dict[str, object] = {
                "store": store,
                "contract": first["contract"],
                "payload": payload,
                "capability_id": issued.capability_id,
            }
            if claim:
                claimed = store.claim_dispatch(
                    {
                        "transaction_id": transaction_id,
                        "observed_at": "2026-08-25T12:02:00Z",
                        "executor_verification": m2._verification_source(),
                    }
                )
                self.assertTrue(claimed.committed)
                intent_text, intent_digest, claim_digest = self.row(
                    "SELECT i.intent_json, i.intent_digest, c.claim_digest "
                    "FROM dispatch_intents i JOIN dispatch_attempt_claims c "
                    "USING (transaction_id) WHERE i.transaction_id=?",
                    (transaction_id,),
                )
                result.update(
                    intent=json.loads(intent_text),
                    intent_digest=intent_digest,
                    claim_digest=claim_digest,
                )
            return result

        bound_candidate = prepare(2, claim=True)
        unclaimed_candidate = prepare(3, claim=False)
        frontier_candidate = prepare(4, claim=True)

        for state in ("STAGED", "QUIESCED", "SEALED", "POSTCHECKED", "COMMITTED", "JOINED"):
            self.assertTrue(self.advance(first, state).committed)
        second_frontier = _frontier(
            bound_candidate, self.row, joined_iteration=1, iteration=2
        )
        bound = store.bind_m4_frontier(
            {
                "transaction_id": "transaction-0002",
                "observed_at": "2026-08-25T12:02:10Z",
                "frontier": second_frontier,
                "frontier_verification": m2._verification_source(),
            }
        )
        self.assertTrue(bound.committed)
        self.assertTrue(self.advance(first, "RECONCILING").committed)
        before_budget = self.row("SELECT remaining, reserved, spent FROM budgets")
        before_events = self.row("SELECT journal_head_sequence FROM store_meta")

        reopened = self.store()
        fresh_issue = m2._issue_raw(
            nonce="nonce-0005", idempotency_key_digest=m2._digest("e")
        )
        fresh_issue["contract_digest"] = first["contract"]["contract_digest"]
        fresh_issue["target_authority_digest"] = first["contract"][
            "target_authority_digest"
        ]
        self.assertEqual(reopened.issue(fresh_issue).outcome, DurableOutcome.DENY)
        self.assertEqual(
            reopened.claim_dispatch(
                {
                    "transaction_id": "transaction-0003",
                    "observed_at": "2026-08-25T12:02:10Z",
                    "executor_verification": m2._verification_source(),
                }
            ).outcome,
            DurableOutcome.DENY,
        )
        blocked_frontier = _frontier(
            frontier_candidate, self.row, joined_iteration=1, iteration=2
        )
        self.assertEqual(
            reopened.bind_m4_frontier(
                {
                    "transaction_id": "transaction-0004",
                    "observed_at": "2026-08-25T12:02:10Z",
                    "frontier": blocked_frontier,
                    "frontier_verification": m2._verification_source(),
                }
            ).outcome,
            DurableOutcome.DENY,
        )
        self.assertEqual(
            reopened.begin_m4_transaction(
                {
                    "transaction_id": "transaction-0002",
                    "d2_frontier_digest": bound.d2_frontier_digest,
                    "observed_at": "2026-08-25T12:02:10Z",
                }
            ).outcome,
            DurableOutcome.DENY,
        )
        self.assertEqual(self.row("SELECT joined_iteration FROM active_contracts"), (1,))
        self.assertEqual(self.row("SELECT remaining, reserved, spent FROM budgets"), before_budget)
        self.assertEqual(self.row("SELECT journal_head_sequence FROM store_meta"), before_events)
        recovered = reopened.recover().m4_recovery
        self.assertEqual(recovered[0].state, "RECONCILING")
        self.assertTrue(all(not item.resume_allowed and not item.retry_allowed for item in recovered))

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
