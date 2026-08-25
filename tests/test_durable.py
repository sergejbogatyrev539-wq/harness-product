from __future__ import annotations

from copy import deepcopy
from dataclasses import is_dataclass
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

import harness_product

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


class DurableStoreIssueTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temporary.name) / "durable.sqlite3"
        self.verifier = ExactVerifier()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def store(self, verifier: object | None = None) -> DurableStore:
        # Constructor is a closed result boundary: a missing/corrupt DB must not leak an exception.
        return DurableStore(str(self.db_path), self.verifier if verifier is None else verifier)

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
            self.assertEqual(version, (1,))

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

    def test_root_public_surface_still_excludes_effect_and_capability_symbols(self) -> None:
        for name in ("Broker", "Capability", "Executor", "DispatchReceipt"):
            self.assertFalse(hasattr(harness_product, name), name)


if __name__ == "__main__":
    unittest.main()
