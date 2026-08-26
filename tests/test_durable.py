from __future__ import annotations

from copy import deepcopy
from dataclasses import is_dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

import harness_product
import harness_product.durable as durable_module

from harness_product.durable import (
    DurableOutcome,
    DurableReason,
    DurableStore,
    VerificationResult,
    VerificationStatus,
)


def _digest(character: str) -> str:
    return "sha256:" + character * 64


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256(value: bytes) -> str:
    return "sha256:" + sha256(value).hexdigest()


def _clause(
    *,
    selector_kind: str = "PATH_PREFIX",
    selector_value: str = "/project/reports",
    not_before: str = "2026-08-25T00:00:00Z",
    not_after: str = "2026-08-26T00:00:00Z",
    max_duration_ms: int = 60_000,
    max_quantity: int = 10,
    max_concurrency: int = 4,
) -> dict[str, object]:
    return {
        "effect": "MUTATE",
        "resource": "FILE",
        "operation": "WRITE",
        "selector": {"kind": selector_kind, "value": selector_value},
        "facets": ["EXECUTE_EFFECT"],
        "not_before": not_before,
        "not_after": not_after,
        "max_duration_ms": max_duration_ms,
        "quantity_unit": "FILES",
        "max_quantity": max_quantity,
        "max_concurrency": max_concurrency,
    }


def _m1_request() -> dict[str, object]:
    requested = _clause(
        selector_kind="PATH_EXACT",
        selector_value="/project/reports/report.txt",
        not_before="2026-08-25T11:00:00Z",
        not_after="2026-08-25T13:00:00Z",
        max_duration_ms=30_000,
        max_quantity=1,
        max_concurrency=2,
    )
    source = {"operation_id": "write-report/v1", "authority": [_clause()]}
    return {
        "evaluation_time": "2026-08-25T12:00:00Z",
        "proposal": {
            "operation_id": "write-report/v1",
            "principal_id": "worker-1",
            "material_digest": _digest("a"),
            "authority": requested,
        },
        "manifest": deepcopy(source),
        "policy": deepcopy(source),
        "physical_ceiling": deepcopy(source),
        "trusted_facts": {
            "operation_id": "write-report/v1",
            "material_digest": _digest("a"),
            "observed_at": "2026-08-25T11:59:00Z",
            "expires_at": "2026-08-25T12:05:00Z",
            "authority": [_clause()],
        },
    }


LINEAGE = _digest("1")
SCOPE = _sha256(_canonical({"kind": "PATH_EXACT", "value": "/project/reports/report.txt"}))


def _verification_source() -> dict[str, str]:
    return {
        "verifier_id": "test-verifier/v1",
        "issuer_id": "test-issuer/v1",
        "key_id": "test-key/v1",
        "proof": _digest("3"),
    }


def _bootstrap_raw(*, limit: int = 10) -> dict[str, object]:
    return {
        "lineage_root": LINEAGE,
        "revocation_epoch": 7,
        "fencing_epoch": 11,
        "budgets": [
            {
                "name": "writes",
                "unit": "FILES",
                "scope_digest": SCOPE,
                "lineage_root": LINEAGE,
                "limit": limit,
            }
        ],
    }


def _issue_raw(
    *,
    nonce: str = "nonce-0001",
    idempotency_key_digest: str | None = None,
) -> dict[str, object]:
    return {
        "request": _m1_request(),
        "audience_id": "executor-1",
        "purpose": "stageable-report-write",
        "contract_digest": _digest("4"),
        "registry_digest": _digest("5"),
        "profile_digest": _digest("6"),
        "placement_digest": _digest("7"),
        "session_id": "session-0001",
        "lineage_root": LINEAGE,
        "nonce": nonce,
        "issued_at": "2026-08-25T12:00:00Z",
        "not_before": "2026-08-25T11:00:00Z",
        "expires_at": "2026-08-25T12:04:00Z",
        "revocation_epoch": 7,
        "fencing_epoch": 11,
        "idempotency_key_digest": idempotency_key_digest or _digest("8"),
        "budget": [
            {
                "name": "writes",
                "unit": "FILES",
                "scope_digest": SCOPE,
                "lineage_root": LINEAGE,
                "amount": 1,
            }
        ],
        "verification": _verification_source(),
    }


def _consume_from_payload(
    capability_id: str,
    payload: dict[str, object],
    *,
    transaction_id: str = "transaction-0001",
) -> dict[str, object]:
    return {
        "capability_id": capability_id,
        "transaction_id": transaction_id,
        "nonce": payload["nonce"],
        "principal_id": payload["principal_id"],
        "audience_id": payload["audience_id"],
        "purpose": payload["purpose"],
        "decision_digest": payload["decision_digest"],
        "request_digest": payload["request_digest"],
        "authorized_envelope_digest": payload["authorized_envelope_digest"],
        "manifest_digest": payload["manifest_digest"],
        "policy_digest": payload["policy_digest"],
        "physical_ceiling_digest": payload["physical_ceiling_digest"],
        "trusted_facts_digest": payload["trusted_facts_digest"],
        "contract_digest": payload["contract_digest"],
        "registry_digest": payload["registry_digest"],
        "profile_digest": payload["profile_digest"],
        "placement_digest": payload["placement_digest"],
        "session_id": payload["session_id"],
        "lineage_root": payload["lineage_root"],
        "observed_at": "2026-08-25T12:01:00Z",
        "revocation_epoch": payload["revocation_epoch"],
        "fencing_epoch": payload["fencing_epoch"],
        "idempotency_key_digest": payload["idempotency_key_digest"],
        "budget": deepcopy(payload["budget_vector"]),
    }


class ExactVerifier:
    """Test-only boundary: only this exact full record may verify."""

    def __init__(self, *, status: VerificationStatus = VerificationStatus.VERIFIED) -> None:
        self.status = status
        self.calls: list[tuple[bytes, bytes, str]] = []

    def verify(self, payload: bytes, record: bytes, observed_at: str) -> VerificationResult:
        self.calls.append((payload, record, observed_at))
        if type(payload) is not bytes or type(record) is not bytes or type(observed_at) is not str:
            raise AssertionError("durable verifier boundary received non-canonical values")
        try:
            payload_value = json.loads(payload)
            record_value = json.loads(record)
        except (UnicodeDecodeError, json.JSONDecodeError):
            payload_value = None
            record_value = None
        source = _verification_source()
        if (
            type(payload_value) is not dict
            or type(record_value) is not dict
            or frozenset(record_value)
            != frozenset(
                {
                    "verification_version",
                    "verifier_id",
                    "issuer_id",
                    "key_id",
                    "payload_digest",
                    "bindings",
                    "proof",
                }
            )
            or record_value["bindings"] != payload_value
            or record_value["payload_digest"] != _sha256(payload)
            or any(record_value[key] != source[key] for key in source)
        ):
            return VerificationResult(
                status=VerificationStatus.REJECTED,
                verifier_id="test-verifier/v1",
                payload_digest=_sha256(payload),
                record_digest=_sha256(record),
            )
        return VerificationResult(
            status=self.status,
            verifier_id="test-verifier/v1",
            payload_digest=_sha256(payload),
            record_digest=_sha256(record),
        )


class RaisingVerifier:
    def verify(self, payload: bytes, record: bytes, observed_at: str) -> VerificationResult:
        raise RuntimeError("test verifier fault")


class MalformedVerifier:
    def verify(self, payload: bytes, record: bytes, observed_at: str) -> object:
        return {"verified": True}


class ExactNoEffectVerifier:
    """Test-only no-effect boundary; production code receives no permissive default."""

    def __init__(self, *, status: VerificationStatus = VerificationStatus.VERIFIED) -> None:
        self.status = status
        self.calls: list[tuple[bytes, bytes, str]] = []

    def verify(self, payload: bytes, record: bytes, observed_at: str) -> VerificationResult:
        self.calls.append((payload, record, observed_at))
        return VerificationResult(
            status=self.status,
            verifier_id="test-no-effect/v1",
            payload_digest=_sha256(payload),
            record_digest=_sha256(record),
        )


class InjectedFault(RuntimeError):
    pass


class FaultAt:
    def __init__(self, point: str) -> None:
        self.point = point
        self.seen: list[str] = []

    def __call__(self, point: str) -> None:
        self.seen.append(point)
        if point == self.point:
            raise InjectedFault(point)


class BarrierAt:
    """A deterministic test-only rendezvous at the store's pre-transaction hook."""

    def __init__(self, parties: int) -> None:
        self.barrier = threading.Barrier(parties)
        self.seen: list[str] = []
        self.lock = threading.Lock()

    def __call__(self, point: str) -> None:
        with self.lock:
            self.seen.append(point)
        if point == "before_transaction":
            self.barrier.wait(timeout=5)


def _claim_raw(transaction_id: str = "transaction-0001", *, observed_at: str = "2026-08-25T12:02:00Z") -> dict[str, object]:
    return {
        "transaction_id": transaction_id,
        "observed_at": observed_at,
        "executor_verification": _verification_source(),
    }


def _verify_claim_raw(claim: object, *, observed_at: str = "2026-08-25T12:02:30Z") -> dict[str, object]:
    return {
        "transaction_id": claim.transaction_id,
        "claim_digest": claim.claim_digest,
        "audience_id": claim.audience_id,
        "placement_digest": claim.placement_digest,
        "session_id": claim.session_id,
        "revocation_epoch": claim.revocation_epoch,
        "fencing_epoch": claim.fencing_epoch,
        "observed_at": observed_at,
    }


class ClaimBarrier:
    def __init__(self, parties: int) -> None:
        self.barrier = threading.Barrier(parties)

    def __call__(self, point: str) -> None:
        if point == "claim_before_transaction":
            self.barrier.wait(timeout=5)


class DurableStoreIssueTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temporary.name) / "durable.sqlite3"
        self.verifier = ExactVerifier()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def store(
        self,
        verifier: object | None = None,
        *,
        no_effect_verifier: object | None = None,
        fault: object | None = None,
    ) -> DurableStore:
        # Constructor is a closed result boundary: a missing/corrupt DB must not leak an exception.
        return DurableStore(
            str(self.db_path),
            self.verifier if verifier is None else verifier,
            no_effect_verifier=no_effect_verifier,
            _fault=fault,
        )

    def assert_result(self, result: object, *, committed: bool) -> None:
        self.assertTrue(is_dataclass(result), type(result))
        self.assertTrue(type(result).__dataclass_params__.frozen)
        self.assertIs(type(result.outcome), DurableOutcome)
        self.assertIs(type(result.reason), DurableReason)
        self.assertIs(type(result.committed), bool)
        self.assertEqual(result.committed, committed)
        self.assertTrue(hasattr(result, "capability_id"))
        self.assertTrue(hasattr(result, "journal_sequence"))

    def assert_stopped(self, result: object) -> None:
        self.assert_result(result, committed=False)
        self.assertIn(result.outcome, {DurableOutcome.DENY, DurableOutcome.STOP})
        self.assertIsNone(result.capability_id)

    def query_one(self, sql: str, parameters: tuple[object, ...] = ()) -> tuple[object, ...]:
        with sqlite3.connect(self.db_path) as connection:
            row = connection.execute(sql, parameters).fetchone()
        self.assertIsNotNone(row, sql)
        return row

    def populated_database(self, name: str, *, disposition: str | None = None) -> Path:
        database = Path(self.temporary.name) / f"{name}.sqlite3"
        no_effect = ExactNoEffectVerifier()
        store = DurableStore(str(database), ExactVerifier(), no_effect_verifier=no_effect)
        self.assert_result(store.bootstrap(_bootstrap_raw()), committed=True)
        issued = store.issue(_issue_raw())
        self.assert_result(issued, committed=True)
        with sqlite3.connect(database) as connection:
            payload = json.loads(
                connection.execute(
                    "SELECT payload_json FROM capabilities WHERE capability_id=?",
                    (issued.capability_id,),
                ).fetchone()[0]
            )
        self.assert_result(store.consume(_consume_from_payload(issued.capability_id, payload)), committed=True)
        if disposition is not None:
            evidence = (
                {
                    "verifier_id": "test-no-effect/v1",
                    "observer_id": "independent-observer/v1",
                    "key_id": "test-no-effect-key/v1",
                    "proof": _digest("d"),
                }
                if disposition == "RELEASED"
                else {"evidence_digest": _digest("d")}
            )
            self.assert_result(
                store.settle(
                    {
                        "transaction_id": "transaction-0001",
                        "disposition": disposition,
                        "observed_at": "2026-08-25T12:02:00Z",
                        "evidence": evidence,
                    }
                ),
                committed=True,
            )
        return database

    def rewrite_chains(self, connection: sqlite3.Connection) -> None:
        journal_previous: str | None = None
        outbox_previous: str | None = None
        rows = connection.execute(
            "SELECT sequence, event_type, subject_id, payload_json "
            "FROM journal_entries ORDER BY sequence"
        ).fetchall()
        for sequence, event_type, subject_id, payload_text in rows:
            payload = json.loads(payload_text)
            journal_body = {
                "sequence": sequence,
                "previous_digest": journal_previous,
                "event_type": event_type,
                "subject_id": subject_id,
                "payload": payload,
            }
            journal_digest = _sha256(_canonical(journal_body))
            outbox_payload = {"journal_digest": journal_digest, "event": payload}
            outbox_body = {
                "sequence": sequence,
                "previous_digest": outbox_previous,
                "event_type": event_type,
                "subject_id": subject_id,
                "payload": outbox_payload,
            }
            outbox_digest = _sha256(_canonical(outbox_body))
            connection.execute(
                "UPDATE journal_entries SET previous_digest=?, entry_digest=? WHERE sequence=?",
                (journal_previous, journal_digest, sequence),
            )
            connection.execute(
                "UPDATE outbox_events SET previous_digest=?, event_type=?, subject_id=?, "
                "payload_json=?, event_digest=? WHERE sequence=?",
                (
                    outbox_previous,
                    event_type,
                    subject_id,
                    _canonical(outbox_payload).decode(),
                    outbox_digest,
                    sequence,
                ),
            )
            journal_previous = journal_digest
            outbox_previous = outbox_digest
        connection.execute(
            "UPDATE store_meta SET journal_head_sequence=?, journal_head_digest=?, "
            "outbox_head_sequence=?, outbox_head_digest=? WHERE id=1",
            (len(rows), journal_previous, len(rows), outbox_previous),
        )

    def assert_corrupt_and_stopped(self, database: Path) -> None:
        with sqlite3.connect(database) as connection:
            before = connection.execute(
                "SELECT (SELECT COUNT(*) FROM capabilities), "
                "(SELECT COUNT(*) FROM dispatch_intents), "
                "(SELECT COUNT(*) FROM journal_entries), "
                "(SELECT COUNT(*) FROM outbox_events)"
            ).fetchone()
        corrupted = DurableStore(str(database), ExactVerifier())
        health = corrupted.health()
        self.assertEqual((health.outcome, health.reason), (DurableOutcome.STOP, DurableReason.CORRUPT_STORE))
        stopped = corrupted.consume({})
        self.assertEqual((stopped.outcome, stopped.reason), (DurableOutcome.STOP, DurableReason.CORRUPT_STORE))
        with sqlite3.connect(database) as connection:
            after = connection.execute(
                "SELECT (SELECT COUNT(*) FROM capabilities), "
                "(SELECT COUNT(*) FROM dispatch_intents), "
                "(SELECT COUNT(*) FROM journal_entries), "
                "(SELECT COUNT(*) FROM outbox_events)"
            ).fetchone()
        self.assertEqual(after, before)

    def issue_capability(self, store: DurableStore, **kwargs: object) -> str:
        self.assert_result(store.bootstrap(_bootstrap_raw()), committed=True)
        result = store.issue(_issue_raw(**kwargs))
        self.assert_result(result, committed=True)
        self.assertEqual(result.outcome, DurableOutcome.COMMITTED)
        self.assertIsInstance(result.capability_id, str)
        return result.capability_id

    def payload_for(self, capability_id: str) -> dict[str, object]:
        (payload,) = self.query_one("SELECT payload_json FROM capabilities WHERE capability_id = ?", (capability_id,))
        value = json.loads(payload)
        self.assertIs(type(value), dict)
        return value

    def consume_raw(
        self,
        capability_id: str,
        *,
        transaction_id: str = "transaction-0001",
    ) -> dict[str, object]:
        return _consume_from_payload(capability_id, self.payload_for(capability_id), transaction_id=transaction_id)

    def assert_unconsumed(self, *, journal_entries: int = 2) -> None:
        self.assertEqual(self.query_one("SELECT state, consumed_transaction_id FROM capabilities"), ("ISSUED", None))
        self.assertEqual(self.query_one("SELECT remaining, reserved, spent FROM budgets"), (10, 0, 0))
        self.assertEqual(self.query_one("SELECT COUNT(*) FROM dispatch_intents"), (0,))
        self.assertEqual(self.query_one("SELECT COUNT(*) FROM budget_reservations"), (0,))
        self.assertEqual(self.query_one("SELECT COUNT(*) FROM journal_entries"), (journal_entries,))
        self.assertEqual(self.query_one("SELECT COUNT(*) FROM outbox_events"), (journal_entries,))

    def assert_consumed_with_reservation(self, transaction_id: str = "transaction-0001") -> None:
        self.assertEqual(
            self.query_one("SELECT state, consumed_transaction_id FROM capabilities"),
            ("CONSUMED", transaction_id),
        )
        self.assertEqual(self.query_one("SELECT remaining, reserved, spent FROM budgets"), (9, 1, 0))
        self.assertEqual(self.query_one("SELECT COUNT(*) FROM dispatch_intents"), (1,))
        self.assertEqual(self.query_one("SELECT COUNT(*) FROM budget_reservations"), (1,))
        self.assertEqual(self.query_one("SELECT COUNT(*) FROM journal_entries"), (3,))
        self.assertEqual(self.query_one("SELECT COUNT(*) FROM outbox_events"), (3,))

    def test_constructor_health_schema_pragmas_bootstrap_and_reopen_are_closed(self) -> None:
        store = self.store()
        self.assert_result(store.health(), committed=False)
        bootstrap = store.bootstrap(_bootstrap_raw())
        self.assert_result(bootstrap, committed=True)

        with sqlite3.connect(self.db_path) as connection:
            tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            self.assertEqual(
                tables,
                {
                    "store_meta",
                    "budgets",
                    "capabilities",
                    "dispatch_intents",
                    "dispatch_attempt_claims",
                    "execution_sessions",
                    "active_contracts",
                    "d2_frontiers",
                    "m4_transactions",
                    "m4_transition_records",
                    "budget_reservations",
                    "journal_entries",
                    "outbox_events",
                },
            )
            self.assertEqual(connection.execute("PRAGMA journal_mode").fetchone()[0].lower(), "delete")
            self.assertTrue(connection.execute("PRAGMA foreign_key_list(capabilities)").fetchall())
            strict = {
                row[1]: row[5]
                for row in connection.execute("PRAGMA table_list")
                if row[1] in tables
            }
            self.assertTrue(strict)
            self.assertTrue(all(strict.values()))
            version = connection.execute("SELECT schema_version FROM store_meta").fetchone()
            self.assertEqual(version, (4,))

        reopened = self.store()
        self.assert_result(reopened.health(), committed=False)
        epoch, fence, remaining, reserved, spent = self.query_one(
            "SELECT m.revocation_epoch, m.fencing_epoch, b.remaining, b.reserved, b.spent "
            "FROM store_meta AS m JOIN budgets AS b ON b.lineage_root=m.lineage_root"
        )
        self.assertEqual((epoch, fence, remaining, reserved, spent), (7, 11, 10, 0, 0))

    def test_issue_persists_full_canonical_m1_input_payload_verification_journal_and_outbox(self) -> None:
        store = self.store()
        self.assert_result(store.bootstrap(_bootstrap_raw()), committed=True)
        raw = _issue_raw()
        result = store.issue(raw)
        self.assert_result(result, committed=True)
        self.assertEqual(result.outcome, DurableOutcome.COMMITTED)
        self.assertIsInstance(result.capability_id, str)
        self.assertEqual(result.journal_sequence, 2)
        self.assertEqual(len(self.verifier.calls), 1)

        capability_id = result.capability_id
        m1_input, payload, verification, state, nonce, lineage = self.query_one(
            "SELECT request_json, payload_json, verification_json, state, nonce, lineage_root "
            "FROM capabilities WHERE capability_id = ?",
            (capability_id,),
        )
        self.assertEqual(m1_input.encode(), _canonical(json.loads(m1_input)))
        self.assertEqual(payload.encode(), _canonical(json.loads(payload)))
        self.assertEqual(verification.encode(), _canonical(json.loads(verification)))
        self.assertEqual(state, "ISSUED")
        self.assertEqual((nonce, lineage), (raw["nonce"], LINEAGE))
        parsed_payload = json.loads(payload)
        parsed_verification = json.loads(verification)
        self.assertEqual(parsed_payload["audience_id"], "executor-1")
        self.assertEqual(parsed_payload["principal_id"], "worker-1")
        self.assertEqual(parsed_payload["decision"]["outcome"], "ALLOW")
        self.assertEqual(parsed_payload["authorized_envelope"]["clauses"][0], raw["request"]["proposal"]["authority"])
        self.assertEqual(parsed_verification["bindings"], parsed_payload)
        self.assertEqual(parsed_verification["payload_digest"], capability_id)
        self.assertEqual(self.query_one("SELECT COUNT(*) FROM journal_entries"), (2,))
        self.assertEqual(self.query_one("SELECT COUNT(*) FROM outbox_events"), (2,))

    def test_duplicate_nonce_or_idempotency_never_creates_a_second_capability_or_event(self) -> None:
        store = self.store()
        store.bootstrap(_bootstrap_raw())
        first = store.issue(_issue_raw())
        self.assert_result(first, committed=True)
        for raw in (
            _issue_raw(),
            _issue_raw(nonce="nonce-0002", idempotency_key_digest=_digest("8")),
        ):
            with self.subTest(raw=raw):
                self.assert_stopped(store.issue(raw))
        self.assertEqual(self.query_one("SELECT COUNT(*) FROM capabilities"), (1,))
        self.assertEqual(self.query_one("SELECT COUNT(*) FROM journal_entries"), (2,))
        self.assertEqual(self.query_one("SELECT COUNT(*) FROM outbox_events"), (2,))

    def test_closed_malformed_unknown_stale_and_m1_mismatch_issue_inputs_do_not_write(self) -> None:
        store = self.store()
        store.bootstrap(_bootstrap_raw())
        cases: list[dict[str, object]] = []

        missing = _issue_raw()
        del missing["purpose"]
        cases.append(missing)
        extra = _issue_raw()
        extra["unknown"] = "not admitted"
        cases.append(extra)
        malformed = _issue_raw()
        malformed["issued_at"] = 1
        cases.append(malformed)
        stale = _issue_raw()
        stale["expires_at"] = "2026-08-25T12:00:00Z"
        cases.append(stale)
        stale_m1 = _issue_raw()
        stale_m1["request"]["trusted_facts"]["expires_at"] = "2026-08-25T12:00:00Z"
        cases.append(stale_m1)
        m1_mismatch = _issue_raw()
        m1_mismatch["request"]["manifest"]["operation_id"] = "substituted/v1"
        cases.append(m1_mismatch)

        for raw in cases:
            with self.subTest(raw=raw):
                self.assert_stopped(store.issue(raw))
                self.assertEqual(self.query_one("SELECT COUNT(*) FROM capabilities"), (0,))
                self.assertEqual(self.query_one("SELECT COUNT(*) FROM journal_entries"), (1,))
                self.assertEqual(self.query_one("SELECT COUNT(*) FROM outbox_events"), (1,))

    def test_audience_must_differ_from_m1_principal_and_verification_failure_never_partially_issues(self) -> None:
        cases: list[tuple[str, object, dict[str, object]]] = []
        audience = _issue_raw()
        audience["audience_id"] = "worker-1"
        cases.append(("audience", ExactVerifier(), audience))
        cases.append(("reject", ExactVerifier(status=VerificationStatus.REJECTED), _issue_raw()))
        cases.append(("exception", RaisingVerifier(), _issue_raw()))
        cases.append(("malformed-result", MalformedVerifier(), _issue_raw()))
        malformed_record = _issue_raw()
        malformed_record["verification"] = {"verifier_id": "test-verifier/v1"}
        cases.append(("malformed-record", ExactVerifier(), malformed_record))

        for name, verifier, raw in cases:
            with self.subTest(name=name):
                isolated = Path(self.temporary.name) / f"{name}.sqlite3"
                target = DurableStore(str(isolated), verifier)
                self.assert_result(target.bootstrap(_bootstrap_raw()), committed=True)
                self.assert_stopped(target.issue(raw))
                with sqlite3.connect(isolated) as connection:
                    self.assertEqual(connection.execute("SELECT COUNT(*) FROM capabilities").fetchone(), (0,))
                    self.assertEqual(connection.execute("SELECT COUNT(*) FROM journal_entries").fetchone(), (1,))
                    self.assertEqual(connection.execute("SELECT COUNT(*) FROM outbox_events").fetchone(), (1,))

    def test_epoch_fence_lineage_budget_vector_and_duplicate_or_cross_key_mutations_stop_without_state_change(self) -> None:
        store = self.store()
        store.bootstrap(_bootstrap_raw())
        cases: list[tuple[str, dict[str, object]]] = []
        for field, value in (("revocation_epoch", 8), ("fencing_epoch", 12), ("lineage_root", _digest("9"))):
            raw = _issue_raw()
            raw[field] = value
            cases.append((field, raw))
        missing_budget = _issue_raw()
        missing_budget["budget"] = []
        cases.append(("missing-budget", missing_budget))
        duplicate_budget = _issue_raw()
        duplicate_budget["budget"].append(deepcopy(duplicate_budget["budget"][0]))
        cases.append(("duplicate-budget", duplicate_budget))
        cross_scope = _issue_raw()
        cross_scope["budget"][0]["scope_digest"] = _digest("a")
        cases.append(("cross-scope", cross_scope))
        cross_lineage = _issue_raw()
        cross_lineage["budget"][0]["lineage_root"] = _digest("b")
        cases.append(("cross-lineage", cross_lineage))
        nonpositive = _issue_raw()
        nonpositive["budget"][0]["amount"] = 0
        cases.append(("nonpositive", nonpositive))
        unknown_unit = _issue_raw()
        unknown_unit["budget"][0]["unit"] = "WIDGETS"
        cases.append(("unknown-unit", unknown_unit))

        for name, raw in cases:
            with self.subTest(name=name):
                self.assert_stopped(store.issue(raw))
                self.assertEqual(self.query_one("SELECT COUNT(*) FROM capabilities"), (0,))
                self.assertEqual(self.query_one("SELECT COUNT(*) FROM journal_entries"), (1,))
                self.assertEqual(self.query_one("SELECT COUNT(*) FROM outbox_events"), (1,))
                self.assertEqual(
                    self.query_one("SELECT remaining, reserved, spent FROM budgets"),
                    (10, 0, 0),
                )

    def test_consume_atomically_reserves_budget_commits_intent_event_and_survives_reopen(self) -> None:
        store = self.store()
        capability_id = self.issue_capability(store)
        result = store.consume(self.consume_raw(capability_id))
        self.assert_result(result, committed=True)
        self.assertEqual(result.outcome, DurableOutcome.COMMITTED)
        self.assertEqual(result.capability_id, capability_id)
        self.assertEqual(result.transaction_id, "transaction-0001")
        self.assertEqual(result.journal_sequence, 3)
        self.assertEqual(len(self.verifier.calls), 2)
        self.assert_consumed_with_reservation()

        reopened = self.store()
        self.assert_result(reopened.health(), committed=False)
        self.assert_consumed_with_reservation()
        self.assertEqual(self.query_one("SELECT COUNT(*) FROM dispatch_intents"), (1,))
        self.assertEqual(self.query_one("SELECT COUNT(*) FROM outbox_events"), (3,))

    def test_consume_requires_every_exact_binding_freshness_nonce_and_budget_vector_without_mutation(self) -> None:
        store = self.store()
        capability_id = self.issue_capability(store)
        base = self.consume_raw(capability_id)
        cases: list[tuple[str, dict[str, object]]] = []
        for field in (
            "capability_id",
            "nonce",
            "principal_id",
            "audience_id",
            "purpose",
            "decision_digest",
            "request_digest",
            "authorized_envelope_digest",
            "manifest_digest",
            "policy_digest",
            "physical_ceiling_digest",
            "trusted_facts_digest",
            "contract_digest",
            "registry_digest",
            "profile_digest",
            "placement_digest",
            "session_id",
            "lineage_root",
            "revocation_epoch",
            "fencing_epoch",
            "idempotency_key_digest",
        ):
            raw = deepcopy(base)
            raw[field] = _digest("f") if field.endswith("digest") or field == "lineage_root" else "substituted"
            if field in {"revocation_epoch", "fencing_epoch"}:
                raw[field] = int(base[field]) + 1
            cases.append((field, raw))
        expired = deepcopy(base)
        expired["observed_at"] = "2026-08-25T12:04:00Z"
        cases.append(("expired", expired))
        missing_budget = deepcopy(base)
        missing_budget["budget"] = []
        cases.append(("missing-budget", missing_budget))
        duplicate_budget = deepcopy(base)
        duplicate_budget["budget"].append(deepcopy(duplicate_budget["budget"][0]))
        cases.append(("duplicate-budget", duplicate_budget))
        cross_key = deepcopy(base)
        cross_key["budget"][0]["scope_digest"] = _digest("f")
        cases.append(("cross-key", cross_key))

        for name, raw in cases:
            with self.subTest(name=name):
                self.assert_stopped(store.consume(raw))
                self.assert_unconsumed()

    def test_consume_rechecks_the_full_stored_verification_record_without_partial_mutation(self) -> None:
        store = self.store()
        capability_id = self.issue_capability(store)
        self.assertEqual(len(self.verifier.calls), 1)
        self.verifier.status = VerificationStatus.REJECTED

        self.assert_stopped(store.consume(self.consume_raw(capability_id)))

        self.assertEqual(len(self.verifier.calls), 2)
        payload, record, observed_at = self.verifier.calls[-1]
        parsed_record = json.loads(record)
        self.assertEqual(parsed_record["bindings"], json.loads(payload))
        self.assertEqual(parsed_record["payload_digest"], capability_id)
        self.assertEqual(observed_at, "2026-08-25T12:01:00Z")
        self.assert_unconsumed()

    def test_replay_and_over_budget_reservation_cannot_create_another_intent(self) -> None:
        store = self.store()
        self.assert_result(store.bootstrap(_bootstrap_raw(limit=1)), committed=True)
        first = store.issue(_issue_raw())
        second = store.issue(_issue_raw(nonce="nonce-0002", idempotency_key_digest=_digest("9")))
        self.assert_result(first, committed=True)
        self.assert_result(second, committed=True)
        first_raw = self.consume_raw(first.capability_id)
        self.assert_result(store.consume(first_raw), committed=True)
        self.assertEqual(self.query_one("SELECT remaining, reserved, spent FROM budgets"), (0, 1, 0))
        self.assertEqual(self.query_one("SELECT COUNT(*) FROM dispatch_intents"), (1,))

        replay = deepcopy(first_raw)
        replay["transaction_id"] = "transaction-replay"
        self.assert_stopped(store.consume(replay))
        second_raw = self.consume_raw(second.capability_id, transaction_id="transaction-0002")
        self.assert_stopped(store.consume(second_raw))
        self.assertEqual(self.query_one("SELECT COUNT(*) FROM dispatch_intents"), (1,))
        self.assertEqual(self.query_one("SELECT COUNT(*) FROM budget_reservations"), (1,))
        self.assertEqual(self.query_one("SELECT remaining, reserved, spent FROM budgets"), (0, 1, 0))

    def test_revocation_before_consume_is_the_sequential_winner(self) -> None:
        store = self.store()
        capability_id = self.issue_capability(store)
        revoke = store.revoke(
            {
                "capability_id": capability_id,
                "expected_revocation_epoch": 7,
                "new_revocation_epoch": 8,
                "fencing_epoch": 11,
                "reason_digest": _digest("c"),
            }
        )
        self.assert_result(revoke, committed=True)
        self.assertEqual(revoke.outcome, DurableOutcome.COMMITTED)
        self.assert_stopped(store.consume(self.consume_raw(capability_id)))
        self.assertEqual(self.query_one("SELECT revocation_epoch FROM store_meta"), (8,))
        self.assertEqual(self.query_one("SELECT state, consumed_transaction_id FROM capabilities"), ("REVOKED", None))
        self.assertEqual(self.query_one("SELECT remaining, reserved, spent FROM budgets"), (10, 0, 0))
        self.assertEqual(self.query_one("SELECT COUNT(*) FROM dispatch_intents"), (0,))
        self.assertEqual(self.query_one("SELECT COUNT(*) FROM journal_entries"), (3,))
        self.assertEqual(self.query_one("SELECT COUNT(*) FROM outbox_events"), (3,))

    def test_stale_fence_rejects_consume_without_reserving_budget(self) -> None:
        store = self.store()
        capability_id = self.issue_capability(store)
        fence = store.advance_fence(
            {
                "expected_fencing_epoch": 11,
                "new_fencing_epoch": 12,
                "reason_digest": _digest("c"),
            }
        )
        self.assert_result(fence, committed=True)
        self.assertEqual(fence.outcome, DurableOutcome.COMMITTED)
        self.assert_stopped(store.consume(self.consume_raw(capability_id)))
        self.assertEqual(self.query_one("SELECT fencing_epoch FROM store_meta"), (12,))
        self.assert_unconsumed(journal_entries=3)

    def test_spend_release_and_quarantine_preserve_component_conservation_across_reopen(self) -> None:
        expected = {
            "SPENT": (9, 0, 1),
            "RELEASED": (10, 0, 0),
            "QUARANTINED_ESCROW": (9, 1, 0),
        }
        for disposition, accounting in expected.items():
            with self.subTest(disposition=disposition):
                database = Path(self.temporary.name) / f"{disposition}.sqlite3"
                no_effect = ExactNoEffectVerifier()
                store = DurableStore(str(database), ExactVerifier(), no_effect_verifier=no_effect)
                self.assert_result(store.bootstrap(_bootstrap_raw()), committed=True)
                issued = store.issue(_issue_raw())
                self.assert_result(issued, committed=True)
                payload = json.loads(
                    sqlite3.connect(database).execute(
                        "SELECT payload_json FROM capabilities WHERE capability_id=?", (issued.capability_id,)
                    ).fetchone()[0]
                )
                consumed = store.consume(_consume_from_payload(issued.capability_id, payload))
                self.assert_result(consumed, committed=True)
                evidence: dict[str, str]
                if disposition == "RELEASED":
                    evidence = {
                        "verifier_id": "test-no-effect/v1",
                        "observer_id": "independent-observer/v1",
                        "key_id": "test-no-effect-key/v1",
                        "proof": _digest("d"),
                    }
                else:
                    evidence = {"evidence_digest": _digest("d")}
                settled = store.settle(
                    {
                        "transaction_id": "transaction-0001",
                        "disposition": disposition,
                        "observed_at": "2026-08-25T12:02:00Z",
                        "evidence": evidence,
                    }
                )
                self.assert_result(settled, committed=True)
                if disposition == "RELEASED":
                    self.assertEqual(len(no_effect.calls), 1)
                    intent_bytes, record_bytes, observed_at = no_effect.calls[0]
                    record = json.loads(record_bytes)
                    self.assertEqual(record["intent"], json.loads(intent_bytes))
                    self.assertEqual(record["transaction_id"], "transaction-0001")
                    self.assertEqual(record["target_scope_digest"], SCOPE)
                    self.assertEqual(record["fencing_epoch"], 11)
                    self.assertEqual(observed_at, "2026-08-25T12:02:00Z")
                with sqlite3.connect(database) as connection:
                    self.assertEqual(
                        connection.execute("SELECT remaining, reserved, spent FROM budgets").fetchone(),
                        accounting,
                    )
                    self.assertEqual(
                        connection.execute("SELECT disposition FROM budget_reservations").fetchone(),
                        (disposition,),
                    )
                reopened = DurableStore(str(database), ExactVerifier(), no_effect_verifier=no_effect)
                self.assert_result(reopened.health(), committed=False)

    def test_failed_or_missing_no_effect_proof_quarantines_but_malformed_settle_does_not_mutate(self) -> None:
        for name, verifier, evidence, expected_commit in (
            (
                "missing-verifier",
                None,
                {
                    "verifier_id": "test-no-effect/v1",
                    "observer_id": "independent-observer/v1",
                    "key_id": "test-no-effect-key/v1",
                    "proof": _digest("d"),
                },
                True,
            ),
            (
                "rejected",
                ExactNoEffectVerifier(status=VerificationStatus.REJECTED),
                {
                    "verifier_id": "test-no-effect/v1",
                    "observer_id": "independent-observer/v1",
                    "key_id": "test-no-effect-key/v1",
                    "proof": _digest("d"),
                },
                True,
            ),
            ("malformed", ExactNoEffectVerifier(), {"proof": _digest("d")}, False),
        ):
            with self.subTest(name=name):
                database = Path(self.temporary.name) / f"{name}.sqlite3"
                store = DurableStore(str(database), ExactVerifier(), no_effect_verifier=verifier)
                self.assert_result(store.bootstrap(_bootstrap_raw()), committed=True)
                issued = store.issue(_issue_raw())
                self.assert_result(issued, committed=True)
                payload = json.loads(
                    sqlite3.connect(database).execute(
                        "SELECT payload_json FROM capabilities WHERE capability_id=?", (issued.capability_id,)
                    ).fetchone()[0]
                )
                self.assert_result(store.consume(_consume_from_payload(issued.capability_id, payload)), committed=True)
                settled = store.settle(
                    {
                        "transaction_id": "transaction-0001",
                        "disposition": "RELEASED",
                        "observed_at": "2026-08-25T12:02:00Z",
                        "evidence": evidence,
                    }
                )
                self.assert_result(settled, committed=expected_commit)
                with sqlite3.connect(database) as connection:
                    row = connection.execute(
                        "SELECT disposition FROM budget_reservations WHERE transaction_id='transaction-0001'"
                    ).fetchone()
                self.assertEqual(row, ("QUARANTINED_ESCROW" if expected_commit else None,))

    def test_duplicate_terminal_disposition_and_recovery_never_retry_or_mutate(self) -> None:
        store = self.store()
        capability_id = self.issue_capability(store)
        self.assert_result(store.consume(self.consume_raw(capability_id)), committed=True)
        first = store.settle(
            {
                "transaction_id": "transaction-0001",
                "disposition": "SPENT",
                "observed_at": "2026-08-25T12:02:00Z",
                "evidence": {"evidence_digest": _digest("d")},
            }
        )
        self.assert_result(first, committed=True)
        before = self.query_one("SELECT remaining, reserved, spent FROM budgets")
        self.assert_stopped(
            store.settle(
                {
                    "transaction_id": "transaction-0001",
                    "disposition": "QUARANTINED_ESCROW",
                    "observed_at": "2026-08-25T12:03:00Z",
                    "evidence": {"evidence_digest": _digest("e")},
                }
            )
        )
        self.assertEqual(self.query_one("SELECT remaining, reserved, spent FROM budgets"), before)

        # Recovery is read-only: a pending intent remains pending and no retry/intents are created.
        issued = store.issue(_issue_raw(nonce="nonce-0002", idempotency_key_digest=_digest("9")))
        self.assert_result(issued, committed=True)
        self.assert_result(
            store.consume(self.consume_raw(issued.capability_id, transaction_id="transaction-0002")),
            committed=True,
        )
        before_recovery = self.query_one("SELECT COUNT(*) FROM dispatch_intents")
        second_store = self.store()
        recovery = second_store.recover()
        self.assert_result(recovery, committed=False)
        self.assertEqual((recovery.outcome.value, recovery.reason.value), ("OK", "RECOVERED"))
        self.assertIs(type(recovery.recovery_intents), tuple)
        self.assertIn("transaction-0002", repr(recovery.recovery_intents))
        self.assertEqual(self.query_one("SELECT COUNT(*) FROM dispatch_intents"), before_recovery)

    def test_fault_boundaries_roll_back_or_preserve_the_full_committed_consume_transition(self) -> None:
        rollback_points = (
            "before_transaction",
            "after_begin",
            "after_budget_reservation",
            "after_capability_consume",
            "after_intent",
            "after_event",
        )
        for point in rollback_points + ("after_commit_before_ack",):
            with self.subTest(point=point):
                database = Path(self.temporary.name) / f"fault-{point}.sqlite3"
                fault = FaultAt(point)
                setup_store = DurableStore(str(database), ExactVerifier())
                self.assert_result(setup_store.bootstrap(_bootstrap_raw()), committed=True)
                issued = setup_store.issue(_issue_raw())
                self.assert_result(issued, committed=True)
                with sqlite3.connect(database) as connection:
                    payload = json.loads(
                        connection.execute(
                            "SELECT payload_json FROM capabilities WHERE capability_id=?", (issued.capability_id,)
                        ).fetchone()[0]
                    )
                store = DurableStore(str(database), ExactVerifier(), _fault=fault)
                result = store.consume(_consume_from_payload(issued.capability_id, payload))
                self.assert_stopped(result)
                self.assertIn(point, fault.seen)
                reopened = DurableStore(str(database), ExactVerifier())
                self.assert_result(reopened.health(), committed=False)
                with sqlite3.connect(database) as connection:
                    state = connection.execute("SELECT state FROM capabilities").fetchone()
                    budget = connection.execute("SELECT remaining, reserved, spent FROM budgets").fetchone()
                    intents = connection.execute("SELECT COUNT(*) FROM dispatch_intents").fetchone()
                    journals = connection.execute("SELECT COUNT(*) FROM journal_entries").fetchone()
                    outbox = connection.execute("SELECT COUNT(*) FROM outbox_events").fetchone()
                if point == "after_commit_before_ack":
                    self.assertEqual((state, budget, intents, journals, outbox), (("CONSUMED",), (9, 1, 0), (1,), (3,), (3,)))
                else:
                    self.assertEqual((state, budget, intents, journals, outbox), (("ISSUED",), (10, 0, 0), (0,), (2,), (2,)))

    def test_two_connections_concurrently_consume_one_capability_only_once(self) -> None:
        setup = self.store()
        capability_id = self.issue_capability(setup)
        raw = self.consume_raw(capability_id)
        barrier = BarrierAt(2)
        stores = [self.store(fault=barrier), self.store(fault=barrier)]
        results: list[object] = []
        errors: list[BaseException] = []

        def consume(store: DurableStore, transaction_id: str) -> None:
            try:
                request = deepcopy(raw)
                request["transaction_id"] = transaction_id
                results.append(store.consume(request))
            except BaseException as error:  # pragma: no cover - proves a leaked boundary error.
                errors.append(error)

        threads = [
            threading.Thread(target=consume, args=(stores[0], "transaction-a")),
            threading.Thread(target=consume, args=(stores[1], "transaction-b")),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
            self.assertFalse(thread.is_alive(), "consume race deadlocked")
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 2)
        self.assertEqual(sum(result.outcome is DurableOutcome.COMMITTED for result in results), 1)
        self.assertEqual(sum(result.outcome in {DurableOutcome.DENY, DurableOutcome.STOP} for result in results), 1)
        self.assertEqual(barrier.seen.count("before_transaction"), 2)
        self.assertEqual(self.query_one("SELECT COUNT(*) FROM dispatch_intents"), (1,))
        self.assertEqual(self.query_one("SELECT COUNT(*) FROM outbox_events"), (3,))
        self.assertEqual(self.query_one("SELECT remaining, reserved, spent FROM budgets"), (9, 1, 0))

    def test_two_component_budget_reservation_is_component_wise_under_concurrency(self) -> None:
        bootstrap = _bootstrap_raw(limit=1)
        bootstrap["budgets"].append(
            {
                "name": "bytes",
                "unit": "BYTES",
                "scope_digest": SCOPE,
                "lineage_root": LINEAGE,
                "limit": 10,
            }
        )
        setup = self.store()
        self.assert_result(setup.bootstrap(bootstrap), committed=True)

        def issue_two_component(nonce: str, digest: str) -> object:
            raw = _issue_raw(nonce=nonce, idempotency_key_digest=digest)
            raw["budget"].append(
                {
                    "name": "bytes",
                    "unit": "BYTES",
                    "scope_digest": SCOPE,
                    "lineage_root": LINEAGE,
                    "amount": 1,
                }
            )
            result = setup.issue(raw)
            self.assert_result(result, committed=True)
            return result

        first = issue_two_component("nonce-two-a", _digest("c"))
        second = issue_two_component("nonce-two-b", _digest("d"))
        barrier = BarrierAt(2)
        stores = [self.store(fault=barrier), self.store(fault=barrier)]
        raws = [
            self.consume_raw(first.capability_id, transaction_id="two-component-a"),
            self.consume_raw(second.capability_id, transaction_id="two-component-b"),
        ]
        results: list[object] = []
        threads = [threading.Thread(target=lambda store=store, raw=raw: results.append(store.consume(raw))) for store, raw in zip(stores, raws)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
            self.assertFalse(thread.is_alive(), "component race deadlocked")
        self.assertEqual(len(results), 2)
        self.assertEqual(sum(result.outcome is DurableOutcome.COMMITTED for result in results), 1)
        self.assertEqual(
            self.query_one("SELECT name, remaining, reserved, spent FROM budgets ORDER BY name"),
            ("bytes", 9, 1, 0),
        )
        with sqlite3.connect(self.db_path) as connection:
            self.assertEqual(
                connection.execute("SELECT name, remaining, reserved, spent FROM budgets ORDER BY name").fetchall(),
                [("bytes", 9, 1, 0), ("writes", 0, 1, 0)],
            )
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM dispatch_intents").fetchone(), (1,))

    def test_separate_connections_serialize_revoke_against_consume(self) -> None:
        setup = self.store()
        capability_id = self.issue_capability(setup)
        barrier = BarrierAt(2)
        consumer = self.store(fault=barrier)
        revoker = self.store(fault=barrier)
        results: list[object] = []
        errors: list[BaseException] = []

        def consume() -> None:
            try:
                results.append(consumer.consume(self.consume_raw(capability_id)))
            except BaseException as error:  # pragma: no cover - proves a leaked boundary error.
                errors.append(error)

        def revoke() -> None:
            try:
                results.append(
                    revoker.revoke(
                        {
                            "capability_id": capability_id,
                            "expected_revocation_epoch": 7,
                            "new_revocation_epoch": 8,
                            "fencing_epoch": 11,
                            "reason_digest": _digest("c"),
                        }
                    )
                )
            except BaseException as error:  # pragma: no cover - proves a leaked boundary error.
                errors.append(error)

        threads = [threading.Thread(target=consume), threading.Thread(target=revoke)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
            self.assertFalse(thread.is_alive(), "revoke/consume race deadlocked")
        self.assertEqual(errors, [])
        self.assertEqual(sum(result.outcome is DurableOutcome.COMMITTED for result in results), 1)
        (state,) = self.query_one("SELECT state FROM capabilities")
        if state == "CONSUMED":
            self.assertEqual(self.query_one("SELECT revocation_epoch FROM store_meta"), (7,))
            self.assertEqual(self.query_one("SELECT COUNT(*) FROM dispatch_intents"), (1,))
            self.assertEqual(self.query_one("SELECT remaining, reserved, spent FROM budgets"), (9, 1, 0))
        else:
            self.assertEqual(state, "REVOKED")
            self.assertEqual(self.query_one("SELECT revocation_epoch FROM store_meta"), (8,))
            self.assertEqual(self.query_one("SELECT COUNT(*) FROM dispatch_intents"), (0,))
            self.assertEqual(self.query_one("SELECT remaining, reserved, spent FROM budgets"), (10, 0, 0))

    def test_duplicate_delivery_after_reopen_is_rejected_without_new_intent_or_event(self) -> None:
        store = self.store()
        capability_id = self.issue_capability(store)
        raw = self.consume_raw(capability_id)
        self.assert_result(store.consume(raw), committed=True)
        reopened = self.store()
        duplicate = deepcopy(raw)
        duplicate["transaction_id"] = "duplicate-after-reopen"
        self.assert_stopped(reopened.consume(duplicate))
        self.assertEqual(self.query_one("SELECT COUNT(*) FROM dispatch_intents"), (1,))
        self.assertEqual(self.query_one("SELECT COUNT(*) FROM outbox_events"), (3,))

    def test_subprocess_crashes_leave_no_precommit_parts_and_preserve_postcommit_transition(self) -> None:
        child = """
import json
import os
import sqlite3
import sys
from tests.test_durable import ExactVerifier, _bootstrap_raw, _consume_from_payload, _issue_raw
from harness_product.durable import DurableStore

class ExitAt:
    def __init__(self, target):
        self.target = target
    def __call__(self, point):
        if point == self.target:
            os._exit(86)

path, point = sys.argv[1:]
setup = DurableStore(path, ExactVerifier())
setup.bootstrap(_bootstrap_raw())
issued = setup.issue(_issue_raw())
with sqlite3.connect(path) as connection:
    payload = json.loads(connection.execute(
        "SELECT payload_json FROM capabilities WHERE capability_id=?", (issued.capability_id,)
    ).fetchone()[0])
store = DurableStore(path, ExactVerifier(), _fault=ExitAt(point))
store.consume(_consume_from_payload(issued.capability_id, payload))
os._exit(87)
"""
        project_root = Path(__file__).resolve().parents[1]
        source_root = project_root / "src"
        child_environment = dict(os.environ)
        child_environment["PYTHONPATH"] = os.pathsep.join((str(source_root), str(project_root)))
        for point in ("before_transaction", "after_intent", "after_commit_before_ack"):
            with self.subTest(point=point):
                database = Path(self.temporary.name) / f"subprocess-{point}.sqlite3"
                completed = subprocess.run(
                    [sys.executable, "-c", child, str(database), point],
                    cwd=project_root,
                    env=child_environment,
                    check=False,
                    timeout=15,
                )
                self.assertEqual(completed.returncode, 86)
                reopened = DurableStore(str(database), ExactVerifier())
                self.assert_result(reopened.health(), committed=False)
                with sqlite3.connect(database) as connection:
                    state = connection.execute("SELECT state FROM capabilities").fetchone()
                    budget = connection.execute("SELECT remaining, reserved, spent FROM budgets").fetchone()
                    intents = connection.execute("SELECT COUNT(*) FROM dispatch_intents").fetchone()
                    events = connection.execute("SELECT COUNT(*) FROM outbox_events").fetchone()
                if point == "after_commit_before_ack":
                    self.assertEqual((state, budget, intents, events), (("CONSUMED",), (9, 1, 0), (1,), (3,)))
                else:
                    self.assertEqual((state, budget, intents, events), (("ISSUED",), (10, 0, 0), (0,), (2,)))

    def test_multikey_limits_and_duplicate_durable_budget_primary_key_fail_closed(self) -> None:
        invalid_limits: list[tuple[str, object]] = [
            ("max-plus-one", 1 << 63),
            ("negative", -1),
            ("bool", True),
            ("string", "1"),
        ]
        for name, limit in invalid_limits:
            with self.subTest(name=name):
                database = Path(self.temporary.name) / f"bad-limit-{name}.sqlite3"
                result = DurableStore(str(database), ExactVerifier()).bootstrap(_bootstrap_raw(limit=limit))
                self.assert_result(result, committed=False)
                with sqlite3.connect(database) as connection:
                    self.assertEqual(connection.execute("SELECT COUNT(*) FROM budgets").fetchone(), (0,))

        store = self.store()
        self.assert_result(store.bootstrap(_bootstrap_raw()), committed=True)
        with sqlite3.connect(self.db_path) as connection:
            connection.execute("PRAGMA foreign_keys=ON")
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute("INSERT INTO budgets SELECT * FROM budgets")
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM budgets").fetchone(), (1,))

    def test_mandatory_outbox_foreign_keys_prevent_deletion_and_match_committed_intent(self) -> None:
        store = self.store()
        capability_id = self.issue_capability(store)
        self.assert_result(store.consume(self.consume_raw(capability_id)), committed=True)
        with sqlite3.connect(self.db_path) as connection:
            connection.execute("PRAGMA foreign_keys=ON")
            matching = connection.execute(
                "SELECT d.transaction_id, j.subject_id, o.subject_id, j.outbox_sequence, o.journal_sequence "
                "FROM dispatch_intents AS d "
                "JOIN journal_entries AS j ON j.sequence=d.journal_sequence "
                "JOIN outbox_events AS o ON o.sequence=j.outbox_sequence "
                "WHERE d.transaction_id='transaction-0001'"
            ).fetchone()
            self.assertEqual(matching, ("transaction-0001", "transaction-0001", "transaction-0001", 3, 3))
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute("DELETE FROM outbox_events WHERE sequence=3")
                connection.commit()
            connection.rollback()
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM outbox_events").fetchone(), (3,))

    def test_journal_outbox_digest_sequence_fork_and_truncation_mutations_fail_closed(self) -> None:
        mutations: tuple[tuple[str, tuple[tuple[str, tuple[object, ...]], ...]], ...] = (
            (
                "journal-digest",
                (("UPDATE journal_entries SET entry_digest=? WHERE sequence=3", (_digest("e"),)),),
            ),
            (
                "outbox-digest",
                (("UPDATE outbox_events SET event_digest=? WHERE sequence=3", (_digest("f"),)),),
            ),
            (
                "sequence-gap",
                (("UPDATE journal_entries SET sequence=30 WHERE sequence=3", ()),),
            ),
            (
                "forked-predecessor",
                (("UPDATE journal_entries SET previous_digest=? WHERE sequence=3", (_digest("d"),)),),
            ),
            (
                "outbox-payload",
                (("UPDATE outbox_events SET payload_json='{}' WHERE sequence=3", ()),),
            ),
            (
                "lost-outbox",
                (("DELETE FROM outbox_events WHERE sequence=3", ()),),
            ),
            (
                "truncated-tail",
                (
                    ("DELETE FROM outbox_events WHERE sequence=3", ()),
                    ("DELETE FROM journal_entries WHERE sequence=3", ()),
                ),
            ),
            (
                "mismatched-head",
                (("UPDATE store_meta SET journal_head_digest=? WHERE id=1", (_digest("c"),)),),
            ),
        )
        for name, statements in mutations:
            with self.subTest(name=name):
                database = self.populated_database(f"chain-{name}")
                with sqlite3.connect(database) as connection:
                    connection.execute("PRAGMA foreign_keys=OFF")
                    connection.execute("PRAGMA ignore_check_constraints=ON")
                    for statement, parameters in statements:
                        connection.execute(statement, parameters)
                self.assert_corrupt_and_stopped(database)

        database = self.populated_database("duplicate-sequence")
        with sqlite3.connect(database) as connection:
            connection.execute("PRAGMA foreign_keys=ON")
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    "INSERT INTO journal_entries SELECT * FROM journal_entries WHERE sequence=3"
                )
            connection.rollback()
        healthy = DurableStore(str(database), ExactVerifier())
        self.assertEqual(
            (healthy.health().outcome, healthy.health().reason),
            (DurableOutcome.OK, DurableReason.READY),
        )

    def test_closed_records_exact_events_epochs_and_schema_mutations_fail_closed(self) -> None:
        for name, sequence, mutation in (
            ("issue-event", 2, lambda value: value.update({"unknown": True})),
            ("consume-event", 3, lambda value: value.pop("intent")),
            (
                "terminal-event",
                4,
                lambda value: value.update({"terminal_record_digest": _digest("f")}),
            ),
        ):
            with self.subTest(name=name):
                database = self.populated_database(
                    f"semantic-{name}",
                    disposition="SPENT" if sequence == 4 else None,
                )
                with sqlite3.connect(database) as connection:
                    payload = json.loads(
                        connection.execute(
                            "SELECT payload_json FROM journal_entries WHERE sequence=?",
                            (sequence,),
                        ).fetchone()[0]
                    )
                    mutation(payload)
                    connection.execute(
                        "UPDATE journal_entries SET payload_json=? WHERE sequence=?",
                        (_canonical(payload).decode(), sequence),
                    )
                    self.rewrite_chains(connection)
                self.assert_corrupt_and_stopped(database)

        database = self.populated_database("closed-verification")
        with sqlite3.connect(database) as connection:
            verification = json.loads(
                connection.execute("SELECT verification_json FROM capabilities").fetchone()[0]
            )
            verification["unknown"] = True
            verification_text = _canonical(verification).decode()
            verification_digest = _sha256(verification_text.encode())
            connection.execute(
                "UPDATE capabilities SET verification_json=?, verification_digest=?",
                (verification_text, verification_digest),
            )
            event = json.loads(
                connection.execute(
                    "SELECT payload_json FROM journal_entries WHERE sequence=2"
                ).fetchone()[0]
            )
            event["verification_digest"] = verification_digest
            connection.execute(
                "UPDATE journal_entries SET payload_json=? WHERE sequence=2",
                (_canonical(event).decode(),),
            )
            self.rewrite_chains(connection)
        self.assert_corrupt_and_stopped(database)

        database = self.populated_database("closed-terminal", disposition="SPENT")
        with sqlite3.connect(database) as connection:
            terminal = json.loads(
                connection.execute(
                    "SELECT terminal_record_json FROM budget_reservations"
                ).fetchone()[0]
            )
            terminal["unknown"] = True
            terminal_text = _canonical(terminal).decode()
            terminal_digest = _sha256(terminal_text.encode())
            connection.execute(
                "UPDATE budget_reservations SET terminal_record_json=?, terminal_record_digest=?",
                (terminal_text, terminal_digest),
            )
            event = json.loads(
                connection.execute(
                    "SELECT payload_json FROM journal_entries WHERE sequence=4"
                ).fetchone()[0]
            )
            event["terminal_record_digest"] = terminal_digest
            connection.execute(
                "UPDATE journal_entries SET payload_json=? WHERE sequence=4",
                (_canonical(event).decode(),),
            )
            self.rewrite_chains(connection)
        self.assert_corrupt_and_stopped(database)

        for name, statement in (
            ("epoch-without-history", "UPDATE store_meta SET revocation_epoch=8 WHERE id=1"),
            ("missing-schema-index", "DROP INDEX reservations_disposition"),
        ):
            with self.subTest(name=name):
                database = self.populated_database(f"semantic-{name}")
                with sqlite3.connect(database) as connection:
                    connection.execute(statement)
                self.assert_corrupt_and_stopped(database)

    def test_issue_and_consume_have_no_socket_process_shell_or_target_open_surface(self) -> None:
        store = self.store()
        self.assert_result(store.bootstrap(_bootstrap_raw()), committed=True)
        forbidden = AssertionError("M2 durable state attempted an external effect")
        with (
            patch("builtins.open", side_effect=forbidden),
            patch("os.open", side_effect=forbidden),
            patch("os.system", side_effect=forbidden),
            patch("socket.socket", side_effect=forbidden),
            patch("subprocess.Popen", side_effect=forbidden),
            patch("subprocess.run", side_effect=forbidden),
        ):
            issued = store.issue(_issue_raw())
            self.assert_result(issued, committed=True)
            self.assert_result(store.consume(self.consume_raw(issued.capability_id)), committed=True)

    def test_root_public_surface_still_excludes_effect_and_capability_symbols(self) -> None:
        for name in ("Broker", "Capability", "Executor", "DispatchReceipt"):
            self.assertFalse(hasattr(harness_product, name), name)


class DurableClaimDispatchTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temporary.name) / "claims.sqlite3"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def store(self, *, executor: object | None = None, fault: object | None = None) -> DurableStore:
        return DurableStore(
            str(self.db_path),
            ExactVerifier(),
            no_effect_verifier=ExactNoEffectVerifier(),
            executor_claim_verifier=executor,
            _fault=fault,
        )

    def prepared(self, store: DurableStore) -> str:
        self.assertTrue(store.bootstrap(_bootstrap_raw()).committed)
        issued = store.issue(_issue_raw())
        self.assertTrue(issued.committed)
        with sqlite3.connect(self.db_path) as connection:
            payload = json.loads(connection.execute("SELECT payload_json FROM capabilities").fetchone()[0])
        consumed = store.consume(_consume_from_payload(issued.capability_id, payload))
        self.assertEqual((consumed.outcome, consumed.reason), (DurableOutcome.COMMITTED, DurableReason.INTENT_COMMITTED))
        return issued.capability_id

    def assert_claim_stop(self, result: object, reason: DurableReason | None = None) -> None:
        self.assertIs(type(result.outcome), DurableOutcome)
        self.assertIn(result.outcome, {DurableOutcome.DENY, DurableOutcome.STOP})
        if reason is not None:
            self.assertEqual(result.reason, reason)
        self.assertFalse(result.committed)
        self.assertIsNone(result.dispatch_claim)

    def test_claim_is_atomic_durable_evented_and_reopen_is_attempt_claimed_without_default_verifier(self) -> None:
        absent = self.store()
        self.prepared(absent)
        self.assert_claim_stop(absent.claim_dispatch(_claim_raw()), DurableReason.EXECUTOR_VERIFIER_ABSENT)
        verifier = ExactVerifier()
        store = self.store(executor=verifier)
        result = store.claim_dispatch(_claim_raw())
        self.assertEqual((result.outcome, result.reason), (DurableOutcome.COMMITTED, DurableReason.DISPATCH_ATTEMPT_CLAIMED))
        self.assertEqual(result.journal_sequence, 4)
        self.assertIsNotNone(result.dispatch_claim)
        with sqlite3.connect(self.db_path) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM dispatch_attempt_claims").fetchone(), (1,))
            self.assertEqual(
                connection.execute("SELECT event_type, subject_id FROM journal_entries WHERE sequence=4").fetchone(),
                ("DISPATCH_ATTEMPT_CLAIMED", "transaction-0001"),
            )
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM outbox_events WHERE sequence=4").fetchone(), (1,))
        reopened = self.store(executor=ExactVerifier())
        recovered = reopened.recover()
        self.assertEqual(recovered.recovery_intents[0].state, "ATTEMPT_CLAIMED")
        self.assert_claim_stop(reopened.claim_dispatch(_claim_raw()), DurableReason.REPLAY)

    def test_stored_claim_is_reverified_read_only_and_every_substitution_fails_closed(self) -> None:
        store = self.store(executor=ExactVerifier())
        self.prepared(store)
        claimed = store.claim_dispatch(_claim_raw())
        self.assertTrue(claimed.committed)
        raw = _verify_claim_raw(claimed.dispatch_claim)
        verified = store.verify_dispatch_claim(raw)
        self.assertEqual(
            (verified.outcome, verified.reason, verified.dispatch_claim),
            (DurableOutcome.OK, DurableReason.DISPATCH_CLAIM_VERIFIED, claimed.dispatch_claim),
        )
        with sqlite3.connect(self.db_path) as connection:
            before = tuple(
                connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                for table in ("capabilities", "dispatch_intents", "dispatch_attempt_claims", "journal_entries", "outbox_events")
            )
        mutations = [{}, {**raw, "unknown": True}, {**raw, "fencing_epoch": True}]
        for field, value in (
            ("claim_digest", _digest("substitute-claim")),
            ("audience_id", "agent_worker-1"),
            ("placement_digest", _digest("substitute-placement")),
            ("session_id", "session-substitute"),
            ("revocation_epoch", raw["revocation_epoch"] + 1),
            ("fencing_epoch", raw["fencing_epoch"] + 1),
        ):
            mutations.append({**raw, field: value})
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                result = store.verify_dispatch_claim(mutation)
                self.assertIn(result.outcome, {DurableOutcome.DENY, DurableOutcome.STOP})
                self.assertIsNone(result.dispatch_claim)
        self.assertEqual(
            self.store().verify_dispatch_claim(raw).reason,
            DurableReason.EXECUTOR_VERIFIER_ABSENT,
        )
        with sqlite3.connect(self.db_path) as connection:
            after = tuple(
                connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                for table in ("capabilities", "dispatch_intents", "dispatch_attempt_claims", "journal_entries", "outbox_events")
            )
        self.assertEqual(after, before)

    def test_stored_claim_reverification_rejects_expiry_current_fence_and_revocation(self) -> None:
        store = self.store(executor=ExactVerifier())
        self.prepared(store)
        claimed = store.claim_dispatch(_claim_raw())
        raw = _verify_claim_raw(claimed.dispatch_claim)
        self.assertEqual(
            store.verify_dispatch_claim({**raw, "observed_at": "2026-08-25T12:05:00Z"}).reason,
            DurableReason.EXPIRED,
        )
        advanced = store.advance_fence(
            {
                "expected_fencing_epoch": raw["fencing_epoch"],
                "new_fencing_epoch": raw["fencing_epoch"] + 1,
                "reason_digest": _digest("e"),
            }
        )
        self.assertEqual(
            (advanced.outcome, advanced.reason),
            (DurableOutcome.COMMITTED, DurableReason.FENCE_ADVANCED),
        )
        self.assertEqual(store.verify_dispatch_claim(raw).reason, DurableReason.STALE_FENCE)

        self.db_path = Path(self.temporary.name) / "verify-revocation.sqlite3"
        revoked = self.store(executor=ExactVerifier())
        self.prepared(revoked)
        claimed = revoked.claim_dispatch(_claim_raw())
        sibling = revoked.issue(
            _issue_raw(nonce="nonce-verify-revocation", idempotency_key_digest=_digest("f"))
        )
        self.assertTrue(sibling.committed)
        self.assertTrue(
            revoked.revoke(
                {
                    "capability_id": sibling.capability_id,
                    "expected_revocation_epoch": claimed.dispatch_claim.revocation_epoch,
                    "new_revocation_epoch": claimed.dispatch_claim.revocation_epoch + 1,
                    "fencing_epoch": claimed.dispatch_claim.fencing_epoch,
                    "reason_digest": _digest("e"),
                }
            ).committed
        )
        self.assertEqual(
            revoked.verify_dispatch_claim(_verify_claim_raw(claimed.dispatch_claim)).reason,
            DurableReason.STALE_REVOCATION,
        )

    def test_claim_closed_terminal_expired_stale_and_verifier_rejections_do_not_claim(self) -> None:
        verifier = ExactVerifier()
        store = self.store(executor=verifier)
        self.prepared(store)
        for raw in ({}, {**_claim_raw(), "unknown": True}, {**_claim_raw(), "observed_at": "2026-08-25T12:05:00Z"}):
            with self.subTest(raw=raw):
                self.assert_claim_stop(store.claim_dispatch(raw))
                with sqlite3.connect(self.db_path) as connection:
                    self.assertEqual(connection.execute("SELECT COUNT(*) FROM dispatch_attempt_claims").fetchone(), (0,))
        rejected = self.store(executor=ExactVerifier(status=VerificationStatus.REJECTED))
        self.assert_claim_stop(rejected.claim_dispatch(_claim_raw()), DurableReason.CAPABILITY_INVALID)
        self.assertTrue(store.advance_fence({"expected_fencing_epoch": 11, "new_fencing_epoch": 12, "reason_digest": _digest("e")}).committed)
        self.assert_claim_stop(store.claim_dispatch(_claim_raw()), DurableReason.STALE_FENCE)

        self.db_path = Path(self.temporary.name) / "stale-revocation.sqlite3"
        stale_revocation = self.store(executor=ExactVerifier())
        self.prepared(stale_revocation)
        second = stale_revocation.issue(
            _issue_raw(nonce="nonce-revocation", idempotency_key_digest=_digest("f"))
        )
        self.assertTrue(second.committed)
        self.assertTrue(
            stale_revocation.revoke(
                {
                    "capability_id": second.capability_id,
                    "expected_revocation_epoch": 7,
                    "new_revocation_epoch": 8,
                    "fencing_epoch": 11,
                    "reason_digest": _digest("e"),
                }
            ).committed
        )
        self.assert_claim_stop(
            stale_revocation.claim_dispatch(_claim_raw()),
            DurableReason.STALE_REVOCATION,
        )
        self.db_path = Path(self.temporary.name) / "terminal.sqlite3"
        terminal = self.store(executor=ExactVerifier())
        self.prepared(terminal)
        self.assertTrue(
            terminal.settle(
                {
                    "transaction_id": "transaction-0001",
                    "disposition": "SPENT",
                    "observed_at": "2026-08-25T12:03:00Z",
                    "evidence": {"evidence_digest": _digest("c")},
                }
            ).committed
        )
        self.assert_claim_stop(terminal.claim_dispatch(_claim_raw()), DurableReason.ILLEGAL_TRANSITION)

    def test_claim_faults_roll_back_or_remain_durably_replayed_after_commit(self) -> None:
        for point in ("claim_before_transaction", "claim_after_begin", "claim_after_verification", "claim_after_insert", "claim_after_event"):
            with self.subTest(point=point):
                self.db_path = Path(self.temporary.name) / f"{point}.sqlite3"
                normal = self.store(executor=ExactVerifier())
                self.prepared(normal)
                faulted = self.store(executor=ExactVerifier(), fault=FaultAt(point))
                self.assert_claim_stop(faulted.claim_dispatch(_claim_raw()))
                with sqlite3.connect(self.db_path) as connection:
                    self.assertEqual(connection.execute("SELECT COUNT(*) FROM dispatch_attempt_claims").fetchone(), (0,))
                    self.assertEqual(connection.execute("SELECT COUNT(*) FROM journal_entries").fetchone(), (3,))
        self.db_path = Path(self.temporary.name) / "after-commit.sqlite3"
        normal = self.store(executor=ExactVerifier())
        self.prepared(normal)
        unknown = self.store(executor=ExactVerifier(), fault=FaultAt("claim_after_commit_before_ack")).claim_dispatch(_claim_raw())
        self.assert_claim_stop(unknown, DurableReason.ACKNOWLEDGEMENT_UNKNOWN)
        reopened = self.store(executor=ExactVerifier())
        self.assert_claim_stop(reopened.claim_dispatch(_claim_raw()), DurableReason.REPLAY)
        self.assertEqual(reopened.recover().recovery_intents[0].state, "ATTEMPT_CLAIMED")

    def test_concurrent_claim_and_claim_binding_mutations_fail_closed(self) -> None:
        setup = self.store(executor=ExactVerifier())
        self.prepared(setup)
        barrier = ClaimBarrier(2)
        stores = [self.store(executor=ExactVerifier(), fault=barrier) for _ in range(2)]
        results: list[object] = []
        workers = [threading.Thread(target=lambda current=current: results.append(current.claim_dispatch(_claim_raw()))) for current in stores]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=5)
            self.assertFalse(worker.is_alive())
        self.assertEqual(sum(result.committed for result in results), 1)
        self.assertEqual(sum(result.reason is DurableReason.REPLAY for result in results), 1)
        for table, statement in (
            ("dispatch_attempt_claims", "UPDATE dispatch_attempt_claims SET claim_json='{}'"),
            ("capabilities", "UPDATE capabilities SET audience_id='tampered'"),
            ("dispatch_intents", "UPDATE dispatch_intents SET intent_digest='sha256:" + "0" * 64 + "'"),
            ("journal_entries", "UPDATE journal_entries SET payload_json='{}' WHERE sequence=4"),
            ("outbox_events", "UPDATE outbox_events SET payload_json='{}' WHERE sequence=4"),
        ):
            with self.subTest(table=table):
                self.db_path = Path(self.temporary.name) / f"corrupt-{table}.sqlite3"
                seeded = self.store(executor=ExactVerifier())
                self.prepared(seeded)
                self.assertTrue(seeded.claim_dispatch(_claim_raw()).committed)
                with sqlite3.connect(self.db_path) as connection:
                    connection.execute(statement)
                corrupted = self.store(executor=ExactVerifier())
                self.assertEqual(corrupted.health().reason, DurableReason.CORRUPT_STORE)

    def test_exact_v1_store_migrates_atomically_and_corrupt_v1_never_partially_migrates(self) -> None:
        for corrupted in (False, True):
            with self.subTest(corrupted=corrupted):
                self.db_path = Path(self.temporary.name) / f"legacy-{corrupted}.sqlite3"
                original = self.store(executor=ExactVerifier())
                self.prepared(original)
                with sqlite3.connect(self.db_path) as connection:
                    for table in (
                        "m4_transition_records",
                        "m4_transactions",
                        "d2_frontiers",
                        "active_contracts",
                    ):
                        connection.execute(f"DROP TABLE {table}")
                    connection.execute("DROP TABLE execution_sessions")
                    connection.execute("DROP TABLE dispatch_attempt_claims")
                    connection.execute("ALTER TABLE store_meta RENAME TO store_meta_v2")
                    connection.execute(durable_module._SCHEMA_V1[0])
                    connection.execute(
                        """
                        INSERT INTO store_meta
                        SELECT id, 1, lineage_root, revocation_epoch, fencing_epoch,
                               dispatch_counter, journal_head_sequence, journal_head_digest,
                               outbox_head_sequence, outbox_head_digest
                        FROM store_meta_v2
                        """
                    )
                    connection.execute("DROP TABLE store_meta_v2")
                    connection.execute("PRAGMA user_version=1")
                    if corrupted:
                        connection.execute("UPDATE dispatch_intents SET intent_json='{}'")
                reopened = self.store(executor=ExactVerifier())
                if corrupted:
                    self.assertEqual(reopened.health().reason, DurableReason.CORRUPT_STORE)
                    with sqlite3.connect(self.db_path) as connection:
                        self.assertEqual(connection.execute("PRAGMA user_version").fetchone(), (1,))
                        tables = {
                            row[0]
                            for row in connection.execute(
                                "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                            )
                        }
                    self.assertNotIn("dispatch_attempt_claims", tables)
                else:
                    self.assertEqual(reopened.health().reason, DurableReason.READY)
                    self.assertEqual(reopened.recover().recovery_intents[0].state, "PENDING")
                    with sqlite3.connect(self.db_path) as connection:
                        self.assertEqual(connection.execute("PRAGMA user_version").fetchone(), (4,))
                        self.assertEqual(
                            connection.execute("SELECT schema_version FROM store_meta").fetchone(),
                            (4,),
                        )


if __name__ == "__main__":
    unittest.main()
