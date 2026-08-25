"""Fail-closed durable authority state for milestone M2.

The store records exact capability bindings and powerless dispatch intent.  It
does not contain an executor, connector, network client, shell command, target
filesystem operation, clock, randomness, or production trust root.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import json
import re
import sqlite3
import unicodedata
from typing import Protocol

from .kernel import classify, decide, derive, evaluate, normalize, transition
from .model import (
    AuthoritySource,
    ClassifiedInput,
    Decision,
    DerivedAuthority,
    KernelResult,
    KernelState,
    NormalizedInput,
    Outcome,
    PowerlessProposal,
    ProposalAuthority,
    QuantityUnit,
    Reason,
    Stage,
    TrustedFacts,
    canonical_digest,
    clause_data,
    decision_data,
    proposal_data,
    selector_data,
)


FORMAT_VERSION = 1
_APPLICATION_ID = 0x48524E53
_MAX_INTEGER = (1 << 63) - 1
_MAX_VECTOR = 256
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_BUDGET_NAME = re.compile(r"^[a-z][a-z0-9._/-]{0,127}$")
_UTC_TIME = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_TABLES = frozenset(
    {
        "budget_reservations",
        "budgets",
        "capabilities",
        "dispatch_intents",
        "journal_entries",
        "outbox_events",
        "store_meta",
    }
)
_CAPABILITY_PAYLOAD_KEYS = frozenset(
    {
        "capability_version",
        "decision",
        "decision_digest",
        "request_digest",
        "principal_id",
        "audience_id",
        "purpose",
        "authorized_envelope",
        "authorized_envelope_digest",
        "manifest_digest",
        "policy_digest",
        "physical_ceiling_digest",
        "trusted_facts_digest",
        "source_clause_digests",
        "contract_digest",
        "registry_digest",
        "profile_digest",
        "placement_digest",
        "session_id",
        "lineage_root",
        "nonce",
        "issued_at",
        "not_before",
        "expires_at",
        "revocation_epoch",
        "fencing_epoch",
        "idempotency_key_digest",
        "budget_vector",
        "budget_vector_digest",
    }
)
_VERIFICATION_RECORD_KEYS = frozenset(
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
_INTENT_KEYS = frozenset(
    {
        "intent_version",
        "transaction_id",
        "capability_id",
        "capability_payload_digest",
        "decision_digest",
        "request_digest",
        "principal_id",
        "audience_id",
        "purpose",
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
        "nonce",
        "observed_at",
        "revocation_epoch",
        "fencing_epoch",
        "idempotency_key_digest",
        "target_scope_digest",
        "material_digest",
        "budget_vector",
        "budget_vector_digest",
        "dispatch_counter",
    }
)


class DurableOutcome(str, Enum):
    OK = "OK"
    COMMITTED = "COMMITTED"
    DENY = "DENY"
    STOP = "STOP"


class DurableReason(str, Enum):
    READY = "READY"
    BOOTSTRAPPED = "BOOTSTRAPPED"
    CAPABILITY_ISSUED = "CAPABILITY_ISSUED"
    INTENT_COMMITTED = "INTENT_COMMITTED"
    REVOKED = "REVOKED"
    FENCE_ADVANCED = "FENCE_ADVANCED"
    SPENT = "SPENT"
    RELEASED = "RELEASED"
    QUARANTINED_ESCROW = "QUARANTINED_ESCROW"
    RECOVERED = "RECOVERED"
    MALFORMED_INPUT = "MALFORMED_INPUT"
    UNKNOWN_INPUT = "UNKNOWN_INPUT"
    UNBOUNDED_INPUT = "UNBOUNDED_INPUT"
    M1_REJECTED = "M1_REJECTED"
    BINDING_MISMATCH = "BINDING_MISMATCH"
    CAPABILITY_INVALID = "CAPABILITY_INVALID"
    EXPIRED = "EXPIRED"
    REPLAY = "REPLAY"
    UNKNOWN_CAPABILITY = "UNKNOWN_CAPABILITY"
    STALE_REVOCATION = "STALE_REVOCATION"
    STALE_FENCE = "STALE_FENCE"
    BUDGET_MISMATCH = "BUDGET_MISMATCH"
    BUDGET_EXCEEDED = "BUDGET_EXCEEDED"
    ILLEGAL_TRANSITION = "ILLEGAL_TRANSITION"
    NO_EFFECT_UNVERIFIED = "NO_EFFECT_UNVERIFIED"
    NOT_BOOTSTRAPPED = "NOT_BOOTSTRAPPED"
    ALREADY_BOOTSTRAPPED = "ALREADY_BOOTSTRAPPED"
    STORE_BUSY = "STORE_BUSY"
    CORRUPT_STORE = "CORRUPT_STORE"
    ACKNOWLEDGEMENT_UNKNOWN = "ACKNOWLEDGEMENT_UNKNOWN"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class VerificationStatus(str, Enum):
    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"


@dataclass(frozen=True, slots=True)
class VerificationResult:
    status: VerificationStatus
    verifier_id: str
    payload_digest: str
    record_digest: str


class CapabilityVerifier(Protocol):
    def verify(
        self,
        payload: bytes,
        record: bytes,
        observed_at: str,
    ) -> VerificationResult: ...


@dataclass(frozen=True, slots=True)
class RecoveryIntent:
    transaction_id: str
    capability_id: str
    intent_digest: str
    idempotency_key_digest: str
    state: str
    fencing_epoch: int


@dataclass(frozen=True, slots=True)
class DurableResult:
    outcome: DurableOutcome
    reason: DurableReason
    capability_id: str | None = None
    transaction_id: str | None = None
    journal_sequence: int | None = None
    recovery_intents: tuple[RecoveryIntent, ...] = ()

    @property
    def committed(self) -> bool:
        return self.outcome is DurableOutcome.COMMITTED


@dataclass(frozen=True, slots=True)
class _BudgetRow:
    name: str
    unit: str
    scope_digest: str
    lineage_root: str
    amount: int

    @property
    def key(self) -> tuple[str, str, str, str]:
        return (self.name, self.unit, self.scope_digest, self.lineage_root)

    def data(self, amount_name: str = "amount") -> dict[str, object]:
        return {
            "name": self.name,
            "unit": self.unit,
            "scope_digest": self.scope_digest,
            "lineage_root": self.lineage_root,
            amount_name: self.amount,
        }


@dataclass(frozen=True, slots=True)
class _PreparedIssue:
    capability_id: str
    payload: dict[str, object]
    payload_text: str
    request_text: str
    decision_text: str
    envelope_text: str
    source_clause_digests_text: str
    budget_rows: tuple[_BudgetRow, ...]
    budget_text: str
    verification: dict[str, object]
    verification_text: str
    verification_digest: str


@dataclass(frozen=True, slots=True)
class _PreparedConsume:
    raw: dict[str, object]
    budget_rows: tuple[_BudgetRow, ...]
    budget_text: str
    observed_at: datetime


class _Rejected(Exception):
    def __init__(self, outcome: DurableOutcome, reason: DurableReason) -> None:
        super().__init__(reason.value)
        self.outcome = outcome
        self.reason = reason


class _StoreCorrupt(Exception):
    pass


def _result(outcome: DurableOutcome, reason: DurableReason) -> DurableResult:
    return DurableResult(outcome, reason)


def _canonical_text(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _canonical_bytes(value: object) -> bytes:
    return _canonical_text(value).encode("utf-8")


def _closed_dict(value: object, keys: frozenset[str]) -> bool:
    return type(value) is dict and all(type(key) is str for key in value) and frozenset(value) == keys


def _bounded_integer(value: object, minimum: int = 0) -> bool:
    return type(value) is int and minimum <= value <= _MAX_INTEGER


def _valid_identifier(value: object) -> bool:
    return type(value) is str and _IDENTIFIER.fullmatch(value) is not None


def _valid_digest(value: object) -> bool:
    return type(value) is str and _DIGEST.fullmatch(value) is not None


def _valid_proof(value: object) -> bool:
    return (
        type(value) is str
        and 1 <= len(value) <= 8192
        and not any(unicodedata.category(character) in {"Cc", "Cf"} for character in value)
    )


def _parse_time(value: object) -> datetime | None:
    if type(value) is not str or _UTC_TIME.fullmatch(value) is None:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _time_text(value: datetime) -> str:
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def _source_data(value: AuthoritySource) -> dict[str, object]:
    return {
        "operation_id": value.operation_id,
        "authority": [clause_data(item) for item in value.clauses],
    }


def _facts_data(value: TrustedFacts) -> dict[str, object]:
    return {
        "operation_id": value.operation_id,
        "material_digest": value.material_digest,
        "observed_at": _time_text(value.observed_at),
        "expires_at": _time_text(value.expires_at),
        "authority": [clause_data(item) for item in value.clauses],
    }


def _normalized_data(value: NormalizedInput) -> dict[str, object]:
    return {
        "evaluation_time": _time_text(value.evaluation_time),
        "proposal": proposal_data(value.proposal),
        "manifest": _source_data(value.manifest),
        "policy": _source_data(value.policy),
        "physical_ceiling": _source_data(value.physical_ceiling),
        "trusted_facts": _facts_data(value.trusted_facts),
    }


def _json_value(text: object) -> object:
    if type(text) is not str:
        raise _StoreCorrupt("non-text canonical value")
    try:
        value = json.loads(text)
    except json.JSONDecodeError as error:
        raise _StoreCorrupt("invalid canonical JSON") from error
    if _canonical_text(value) != text:
        raise _StoreCorrupt("non-canonical JSON")
    return value


def _parse_budget_vector(
    raw: object,
    *,
    amount_name: str,
    expected_lineage: str,
) -> tuple[_BudgetRow, ...]:
    if type(raw) is not list or not raw or len(raw) > _MAX_VECTOR:
        reason = DurableReason.UNBOUNDED_INPUT if raw in (None, []) else DurableReason.MALFORMED_INPUT
        raise _Rejected(DurableOutcome.STOP, reason)
    keys = frozenset({"name", "unit", "scope_digest", "lineage_root", amount_name})
    rows: list[_BudgetRow] = []
    for item in raw:
        if not _closed_dict(item, keys):
            raise _Rejected(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
        if type(item["name"]) is not str or _BUDGET_NAME.fullmatch(item["name"]) is None:
            raise _Rejected(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
        if type(item["unit"]) is not str:
            raise _Rejected(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
        if item["unit"] not in QuantityUnit._value2member_map_:
            raise _Rejected(DurableOutcome.STOP, DurableReason.UNKNOWN_INPUT)
        if not _valid_digest(item["scope_digest"]) or not _valid_digest(item["lineage_root"]):
            raise _Rejected(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
        if item["lineage_root"] != expected_lineage:
            raise _Rejected(DurableOutcome.DENY, DurableReason.BINDING_MISMATCH)
        if not _bounded_integer(item[amount_name], 1):
            raise _Rejected(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
        rows.append(
            _BudgetRow(
                item["name"],
                item["unit"],
                item["scope_digest"],
                item["lineage_root"],
                item[amount_name],
            )
        )
    ordered = tuple(sorted(rows, key=lambda item: item.key))
    if len({item.key for item in ordered}) != len(ordered):
        raise _Rejected(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
    return ordered


_SCHEMA = (
    """
    CREATE TABLE store_meta (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        schema_version INTEGER NOT NULL CHECK (schema_version = 1),
        lineage_root TEXT,
        revocation_epoch INTEGER NOT NULL CHECK (revocation_epoch >= 0),
        fencing_epoch INTEGER NOT NULL CHECK (fencing_epoch >= 0),
        dispatch_counter INTEGER NOT NULL CHECK (dispatch_counter >= 0),
        journal_head_sequence INTEGER NOT NULL CHECK (journal_head_sequence >= 0),
        journal_head_digest TEXT,
        outbox_head_sequence INTEGER NOT NULL CHECK (outbox_head_sequence >= 0),
        outbox_head_digest TEXT,
        CHECK ((journal_head_sequence = 0 AND journal_head_digest IS NULL)
            OR (journal_head_sequence > 0 AND journal_head_digest IS NOT NULL)),
        CHECK ((outbox_head_sequence = 0 AND outbox_head_digest IS NULL)
            OR (outbox_head_sequence > 0 AND outbox_head_digest IS NOT NULL))
    ) STRICT
    """,
    """
    CREATE TABLE budgets (
        name TEXT NOT NULL,
        unit TEXT NOT NULL,
        scope_digest TEXT NOT NULL,
        lineage_root TEXT NOT NULL,
        limit_amount INTEGER NOT NULL CHECK (limit_amount >= 0),
        remaining INTEGER NOT NULL CHECK (remaining >= 0),
        reserved INTEGER NOT NULL CHECK (reserved >= 0),
        spent INTEGER NOT NULL CHECK (spent >= 0),
        PRIMARY KEY (name, unit, scope_digest, lineage_root),
        CHECK (limit_amount = remaining + reserved + spent)
    ) STRICT
    """,
    """
    CREATE TABLE capabilities (
        capability_id TEXT PRIMARY KEY,
        payload_digest TEXT NOT NULL UNIQUE CHECK (payload_digest = capability_id),
        nonce TEXT NOT NULL UNIQUE,
        state TEXT NOT NULL CHECK (state IN ('ISSUED', 'CONSUMED', 'REVOKED')),
        decision_digest TEXT NOT NULL,
        request_digest TEXT NOT NULL,
        principal_id TEXT NOT NULL,
        audience_id TEXT NOT NULL,
        purpose TEXT NOT NULL,
        authorized_envelope_digest TEXT NOT NULL,
        manifest_digest TEXT NOT NULL,
        policy_digest TEXT NOT NULL,
        physical_ceiling_digest TEXT NOT NULL,
        trusted_facts_digest TEXT NOT NULL,
        contract_digest TEXT NOT NULL,
        registry_digest TEXT NOT NULL,
        profile_digest TEXT NOT NULL,
        placement_digest TEXT NOT NULL,
        session_id TEXT NOT NULL,
        lineage_root TEXT NOT NULL,
        issued_at TEXT NOT NULL,
        not_before TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        revocation_epoch INTEGER NOT NULL CHECK (revocation_epoch >= 0),
        fencing_epoch INTEGER NOT NULL CHECK (fencing_epoch >= 0),
        idempotency_key_digest TEXT NOT NULL UNIQUE,
        budget_vector_digest TEXT NOT NULL,
        request_json TEXT NOT NULL,
        decision_json TEXT NOT NULL,
        authorized_envelope_json TEXT NOT NULL,
        source_clause_digests_json TEXT NOT NULL,
        budget_vector_json TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        verification_json TEXT NOT NULL,
        verification_digest TEXT NOT NULL,
        consumed_transaction_id TEXT UNIQUE,
        issued_journal_sequence INTEGER NOT NULL UNIQUE,
        CHECK ((state = 'CONSUMED' AND consumed_transaction_id IS NOT NULL)
            OR (state IN ('ISSUED', 'REVOKED') AND consumed_transaction_id IS NULL)),
        FOREIGN KEY (consumed_transaction_id) REFERENCES dispatch_intents(transaction_id)
            DEFERRABLE INITIALLY DEFERRED,
        FOREIGN KEY (issued_journal_sequence) REFERENCES journal_entries(sequence)
            DEFERRABLE INITIALLY DEFERRED
    ) STRICT
    """,
    """
    CREATE TABLE dispatch_intents (
        transaction_id TEXT PRIMARY KEY,
        capability_id TEXT NOT NULL UNIQUE REFERENCES capabilities(capability_id),
        state TEXT NOT NULL CHECK (state IN ('PENDING', 'SPENT', 'RELEASED', 'QUARANTINED_ESCROW')),
        intent_digest TEXT NOT NULL UNIQUE,
        idempotency_key_digest TEXT NOT NULL UNIQUE,
        fencing_epoch INTEGER NOT NULL CHECK (fencing_epoch >= 0),
        dispatch_counter INTEGER NOT NULL UNIQUE CHECK (dispatch_counter > 0),
        intent_json TEXT NOT NULL,
        journal_sequence INTEGER NOT NULL UNIQUE REFERENCES journal_entries(sequence)
            DEFERRABLE INITIALLY DEFERRED
    ) STRICT
    """,
    """
    CREATE TABLE budget_reservations (
        transaction_id TEXT NOT NULL REFERENCES dispatch_intents(transaction_id),
        name TEXT NOT NULL,
        unit TEXT NOT NULL,
        scope_digest TEXT NOT NULL,
        lineage_root TEXT NOT NULL,
        amount INTEGER NOT NULL CHECK (amount > 0),
        disposition TEXT CHECK (disposition IN ('SPENT', 'RELEASED', 'QUARANTINED_ESCROW')),
        terminal_record_json TEXT,
        terminal_record_digest TEXT,
        PRIMARY KEY (transaction_id, name, unit, scope_digest, lineage_root),
        FOREIGN KEY (name, unit, scope_digest, lineage_root)
            REFERENCES budgets(name, unit, scope_digest, lineage_root),
        CHECK ((disposition IS NULL AND terminal_record_json IS NULL AND terminal_record_digest IS NULL)
            OR (disposition IS NOT NULL AND terminal_record_json IS NOT NULL
                AND terminal_record_digest IS NOT NULL))
    ) STRICT
    """,
    """
    CREATE TABLE journal_entries (
        sequence INTEGER PRIMARY KEY CHECK (sequence > 0),
        previous_digest TEXT,
        event_type TEXT NOT NULL,
        subject_id TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        entry_digest TEXT NOT NULL UNIQUE,
        outbox_sequence INTEGER NOT NULL UNIQUE,
        CHECK (outbox_sequence = sequence),
        FOREIGN KEY (outbox_sequence) REFERENCES outbox_events(sequence)
            DEFERRABLE INITIALLY DEFERRED
    ) STRICT
    """,
    """
    CREATE TABLE outbox_events (
        sequence INTEGER PRIMARY KEY CHECK (sequence > 0),
        previous_digest TEXT,
        event_type TEXT NOT NULL,
        subject_id TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        event_digest TEXT NOT NULL UNIQUE,
        journal_sequence INTEGER NOT NULL UNIQUE,
        CHECK (journal_sequence = sequence),
        FOREIGN KEY (journal_sequence) REFERENCES journal_entries(sequence)
            DEFERRABLE INITIALLY DEFERRED
    ) STRICT
    """,
    "CREATE INDEX capabilities_state_expiry ON capabilities(state, expires_at)",
    "CREATE INDEX capabilities_lineage_state ON capabilities(lineage_root, state)",
    "CREATE INDEX reservations_disposition ON budget_reservations(disposition)",
)


class DurableStore:
    """One-lineage SQLite durability domain with no effect execution surface."""

    def __init__(
        self,
        path: str,
        verifier: CapabilityVerifier,
        *,
        no_effect_verifier: object | None = None,
        _fault: object | None = None,
    ) -> None:
        self._path = path if type(path) is str else ""
        self._verifier = verifier
        self._no_effect_verifier = no_effect_verifier
        self._fault = _fault
        self._usable = False
        self._stopped_reason = DurableReason.MALFORMED_INPUT
        if not self._path or self._path == ":memory:" or self._path.startswith("file:") or "\x00" in self._path:
            return
        try:
            connection = self._connect()
            try:
                self._initialize_or_validate_schema(connection)
                self._audit(connection)
            finally:
                connection.close()
        except Exception:
            self._stopped_reason = DurableReason.CORRUPT_STORE
            return
        self._usable = True
        self._stopped_reason = DurableReason.READY

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._path, isolation_level=None, timeout=10.0)
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("PRAGMA busy_timeout=10000")
            mode = connection.execute("PRAGMA journal_mode=DELETE").fetchone()[0]
            connection.execute("PRAGMA synchronous=FULL")
            foreign_keys = connection.execute("PRAGMA foreign_keys").fetchone()[0]
            synchronous = connection.execute("PRAGMA synchronous").fetchone()[0]
            if str(mode).lower() != "delete" or foreign_keys != 1 or synchronous != 2:
                raise _StoreCorrupt("required SQLite durability pragmas unavailable")
            return connection
        except Exception:
            connection.close()
            raise

    def _initialize_or_validate_schema(self, connection: sqlite3.Connection) -> None:
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        application_id = connection.execute("PRAGMA application_id").fetchone()[0]
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        if not tables and version == 0 and application_id == 0:
            connection.execute("BEGIN IMMEDIATE")
            try:
                for statement in _SCHEMA:
                    connection.execute(statement)
                connection.execute(
                    "INSERT INTO store_meta VALUES (1, ?, NULL, 0, 0, 0, 0, NULL, 0, NULL)",
                    (FORMAT_VERSION,),
                )
                connection.execute(f"PRAGMA application_id={_APPLICATION_ID}")
                connection.execute(f"PRAGMA user_version={FORMAT_VERSION}")
                connection.commit()
            except Exception:
                connection.rollback()
                raise
            return
        if version != FORMAT_VERSION or application_id != _APPLICATION_ID or tables != _TABLES:
            raise _StoreCorrupt("unknown durable store schema")

    def _audit(self, connection: sqlite3.Connection) -> None:
        if connection.execute("PRAGMA user_version").fetchone()[0] != FORMAT_VERSION:
            raise _StoreCorrupt("schema version mismatch")
        if connection.execute("PRAGMA application_id").fetchone()[0] != _APPLICATION_ID:
            raise _StoreCorrupt("application id mismatch")
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        if tables != _TABLES:
            raise _StoreCorrupt("schema inventory mismatch")
        self._audit_schema(connection)
        if tuple(connection.execute("PRAGMA quick_check").fetchone()) != ("ok",):
            raise _StoreCorrupt("SQLite quick check failed")
        if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise _StoreCorrupt("foreign key mismatch")
        meta_rows = connection.execute("SELECT * FROM store_meta").fetchall()
        if len(meta_rows) != 1 or meta_rows[0]["id"] != 1 or meta_rows[0]["schema_version"] != FORMAT_VERSION:
            raise _StoreCorrupt("invalid store metadata")
        meta = meta_rows[0]
        lineage = meta["lineage_root"]
        if lineage is not None and not _valid_digest(lineage):
            raise _StoreCorrupt("invalid lineage root")
        for field in (
            "revocation_epoch",
            "fencing_epoch",
            "dispatch_counter",
            "journal_head_sequence",
            "outbox_head_sequence",
        ):
            if not _bounded_integer(meta[field]):
                raise _StoreCorrupt("invalid monotonic metadata")
        self._audit_budgets(connection, lineage)
        self._audit_chains(connection, meta)
        self._audit_history(connection, meta)
        self._audit_capabilities(connection, lineage)
        self._audit_dispatch(connection, meta)

    def _audit_schema(self, connection: sqlite3.Connection) -> None:
        expected: dict[str, str] = {}
        for statement in _SCHEMA:
            normalized = " ".join(statement.split())
            match = re.match(r"^CREATE (?:TABLE|INDEX) ([A-Za-z_][A-Za-z0-9_]*) ", normalized)
            if match is None:
                raise _StoreCorrupt("invalid embedded schema")
            expected[match.group(1)] = normalized
        actual = {
            row[0]: " ".join(row[1].split())
            for row in connection.execute(
                """
                SELECT name, sql FROM sqlite_schema
                WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%'
                """
            )
        }
        if actual != expected:
            raise _StoreCorrupt("schema definition mismatch")
        strict = {
            row[1]: row[5]
            for row in connection.execute("PRAGMA table_list")
            if row[1] in _TABLES
        }
        if set(strict) != _TABLES or any(value != 1 for value in strict.values()):
            raise _StoreCorrupt("non-STRICT durable table")

    def _audit_budgets(self, connection: sqlite3.Connection, lineage: str | None) -> None:
        rows = connection.execute("SELECT * FROM budgets").fetchall()
        if lineage is None and rows:
            raise _StoreCorrupt("budget exists before bootstrap")
        for row in rows:
            if (
                type(row["name"]) is not str
                or _BUDGET_NAME.fullmatch(row["name"]) is None
                or row["unit"] not in QuantityUnit._value2member_map_
                or not _valid_digest(row["scope_digest"])
                or row["lineage_root"] != lineage
            ):
                raise _StoreCorrupt("invalid budget key")
            values = tuple(row[name] for name in ("limit_amount", "remaining", "reserved", "spent"))
            if not all(_bounded_integer(item) for item in values):
                raise _StoreCorrupt("invalid budget value")
            if row["limit_amount"] != row["remaining"] + row["reserved"] + row["spent"]:
                raise _StoreCorrupt("budget conservation failure")

    def _audit_chains(self, connection: sqlite3.Connection, meta: sqlite3.Row) -> None:
        journal = connection.execute("SELECT * FROM journal_entries ORDER BY sequence").fetchall()
        outbox = connection.execute("SELECT * FROM outbox_events ORDER BY sequence").fetchall()
        if (
            len(journal) != meta["journal_head_sequence"]
            or len(outbox) != meta["outbox_head_sequence"]
            or len(journal) != len(outbox)
        ):
            raise _StoreCorrupt("chain truncation or cardinality mismatch")
        journal_previous: str | None = None
        outbox_previous: str | None = None
        for expected, (entry, event) in enumerate(zip(journal, outbox, strict=True), 1):
            if entry["sequence"] != expected or event["sequence"] != expected:
                raise _StoreCorrupt("non-contiguous chain")
            if entry["previous_digest"] != journal_previous or event["previous_digest"] != outbox_previous:
                raise _StoreCorrupt("chain predecessor mismatch")
            payload = _json_value(entry["payload_json"])
            journal_body = {
                "sequence": expected,
                "previous_digest": journal_previous,
                "event_type": entry["event_type"],
                "subject_id": entry["subject_id"],
                "payload": payload,
            }
            journal_digest = canonical_digest(journal_body)
            if entry["entry_digest"] != journal_digest or entry["outbox_sequence"] != expected:
                raise _StoreCorrupt("journal digest or link mismatch")
            outbox_payload = _json_value(event["payload_json"])
            if outbox_payload != {"journal_digest": journal_digest, "event": payload}:
                raise _StoreCorrupt("outbox payload mismatch")
            outbox_body = {
                "sequence": expected,
                "previous_digest": outbox_previous,
                "event_type": event["event_type"],
                "subject_id": event["subject_id"],
                "payload": outbox_payload,
            }
            outbox_digest = canonical_digest(outbox_body)
            if (
                event["event_digest"] != outbox_digest
                or event["journal_sequence"] != expected
                or event["event_type"] != entry["event_type"]
                or event["subject_id"] != entry["subject_id"]
            ):
                raise _StoreCorrupt("outbox digest or link mismatch")
            journal_previous = journal_digest
            outbox_previous = outbox_digest
        if (
            journal_previous != meta["journal_head_digest"]
            or outbox_previous != meta["outbox_head_digest"]
        ):
            raise _StoreCorrupt("chain head mismatch")

    def _audit_history(self, connection: sqlite3.Connection, meta: sqlite3.Row) -> None:
        entries = connection.execute(
            "SELECT event_type, subject_id, payload_json FROM journal_entries ORDER BY sequence"
        ).fetchall()
        lineage = meta["lineage_root"]
        if lineage is None:
            if entries or connection.execute("SELECT 1 FROM budgets").fetchone() is not None:
                raise _StoreCorrupt("state exists before bootstrap")
            return
        if not entries or entries[0]["event_type"] != "STORE_BOOTSTRAPPED":
            raise _StoreCorrupt("missing bootstrap history")
        bootstrap = _json_value(entries[0]["payload_json"])
        if (
            not _closed_dict(
                bootstrap,
                frozenset({"lineage_root", "revocation_epoch", "fencing_epoch", "budgets"}),
            )
            or entries[0]["subject_id"] != lineage
            or bootstrap.get("lineage_root") != lineage
            or not _bounded_integer(bootstrap.get("revocation_epoch"))
            or not _bounded_integer(bootstrap.get("fencing_epoch"))
        ):
            raise _StoreCorrupt("bootstrap history mismatch")
        durable_budgets = [
            {
                "name": row["name"],
                "unit": row["unit"],
                "scope_digest": row["scope_digest"],
                "lineage_root": row["lineage_root"],
                "limit": row["limit_amount"],
            }
            for row in connection.execute(
                "SELECT * FROM budgets ORDER BY name, unit, scope_digest, lineage_root"
            )
        ]
        if bootstrap.get("budgets") != durable_budgets:
            raise _StoreCorrupt("bootstrap budget history mismatch")
        revocation_epoch = bootstrap["revocation_epoch"]
        fencing_epoch = bootstrap["fencing_epoch"]
        allowed = {
            "CAPABILITY_ISSUED",
            "CAPABILITY_CONSUMED_WITH_INTENT",
            "CAPABILITY_REVOKED",
            "FENCE_ADVANCED",
            "BUDGET_TERMINAL_SPENT",
            "BUDGET_TERMINAL_RELEASED",
            "BUDGET_TERMINAL_QUARANTINED_ESCROW",
        }
        for entry in entries[1:]:
            event_type = entry["event_type"]
            payload = _json_value(entry["payload_json"])
            if event_type not in allowed:
                raise _StoreCorrupt("unknown journal transition")
            if event_type == "CAPABILITY_REVOKED":
                revoked = connection.execute(
                    "SELECT state, revocation_epoch, fencing_epoch FROM capabilities "
                    "WHERE capability_id=?",
                    (entry["subject_id"],),
                ).fetchone()
                if (
                    not _closed_dict(
                        payload,
                        frozenset(
                            {
                                "capability_id",
                                "previous_revocation_epoch",
                                "revocation_epoch",
                                "fencing_epoch",
                                "reason_digest",
                            }
                        ),
                    )
                    or payload.get("previous_revocation_epoch") != revocation_epoch
                    or payload.get("revocation_epoch") != revocation_epoch + 1
                    or payload.get("capability_id") != entry["subject_id"]
                    or payload.get("fencing_epoch") != fencing_epoch
                    or not _valid_digest(payload.get("reason_digest"))
                    or revoked is None
                    or tuple(revoked) != ("REVOKED", revocation_epoch, fencing_epoch)
                ):
                    raise _StoreCorrupt("revocation history mismatch")
                revocation_epoch = payload["revocation_epoch"]
            elif event_type == "FENCE_ADVANCED":
                if (
                    not _closed_dict(
                        payload,
                        frozenset(
                            {
                                "lineage_root",
                                "previous_fencing_epoch",
                                "fencing_epoch",
                                "reason_digest",
                            }
                        ),
                    )
                    or payload.get("previous_fencing_epoch") != fencing_epoch
                    or payload.get("fencing_epoch") != fencing_epoch + 1
                    or payload.get("lineage_root") != lineage
                    or entry["subject_id"] != lineage
                    or not _valid_digest(payload.get("reason_digest"))
                ):
                    raise _StoreCorrupt("fence history mismatch")
                fencing_epoch = payload["fencing_epoch"]
            elif event_type in {"CAPABILITY_ISSUED", "CAPABILITY_CONSUMED_WITH_INTENT"}:
                if payload.get("revocation_epoch", revocation_epoch) != revocation_epoch:
                    raise _StoreCorrupt("event revocation history mismatch")
                if payload.get("fencing_epoch") != fencing_epoch:
                    raise _StoreCorrupt("event fencing history mismatch")
        if revocation_epoch != meta["revocation_epoch"] or fencing_epoch != meta["fencing_epoch"]:
            raise _StoreCorrupt("monotonic metadata/history mismatch")
        counts = {
            row["event_type"]: row["amount"]
            for row in connection.execute(
                "SELECT event_type, COUNT(*) AS amount FROM journal_entries GROUP BY event_type"
            )
        }
        terminal_count = sum(
            counts.get("BUDGET_TERMINAL_" + disposition, 0)
            for disposition in ("SPENT", "RELEASED", "QUARANTINED_ESCROW")
        )
        expected_counts = (
            connection.execute("SELECT COUNT(*) FROM capabilities").fetchone()[0],
            connection.execute("SELECT COUNT(*) FROM dispatch_intents").fetchone()[0],
            connection.execute("SELECT COUNT(*) FROM capabilities WHERE state='REVOKED'").fetchone()[0],
            connection.execute("SELECT COUNT(*) FROM dispatch_intents WHERE state!='PENDING'").fetchone()[0],
        )
        observed_counts = (
            counts.get("CAPABILITY_ISSUED", 0),
            counts.get("CAPABILITY_CONSUMED_WITH_INTENT", 0),
            counts.get("CAPABILITY_REVOKED", 0),
            terminal_count,
        )
        if observed_counts != expected_counts:
            raise _StoreCorrupt("transition history cardinality mismatch")

    def _audit_capabilities(self, connection: sqlite3.Connection, lineage: str | None) -> None:
        for row in connection.execute("SELECT * FROM capabilities"):
            request = _json_value(row["request_json"])
            decision = _json_value(row["decision_json"])
            envelope = _json_value(row["authorized_envelope_json"])
            source_digests = _json_value(row["source_clause_digests_json"])
            budget = _json_value(row["budget_vector_json"])
            payload = _json_value(row["payload_json"])
            verification = _json_value(row["verification_json"])
            try:
                budget_rows = _parse_budget_vector(
                    budget,
                    amount_name="amount",
                    expected_lineage=row["lineage_root"],
                )
            except _Rejected as error:
                raise _StoreCorrupt("invalid capability budget vector") from error
            if (
                not _closed_dict(payload, _CAPABILITY_PAYLOAD_KEYS)
                or not _closed_dict(verification, _VERIFICATION_RECORD_KEYS)
                or payload.get("capability_version") != FORMAT_VERSION
                or verification.get("verification_version") != FORMAT_VERSION
                or not all(
                    _valid_identifier(payload.get(field))
                    for field in ("principal_id", "audience_id", "purpose", "session_id", "nonce")
                )
                or not all(
                    _valid_identifier(verification.get(field))
                    for field in ("verifier_id", "issuer_id", "key_id")
                )
                or not _valid_proof(verification.get("proof"))
                or not all(
                    _valid_digest(payload.get(field))
                    for field in (
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
                        "lineage_root",
                        "idempotency_key_digest",
                        "budget_vector_digest",
                    )
                )
                or type(source_digests) is not list
                or not source_digests
                or len(source_digests) > _MAX_VECTOR
                or not all(_valid_digest(item) for item in source_digests)
                or [item.data() for item in budget_rows] != budget
                or payload.get("decision") != decision
                or payload.get("authorized_envelope") != envelope
                or payload.get("source_clause_digests") != source_digests
                or payload.get("budget_vector") != budget
                or canonical_digest(request) != row["request_digest"]
                or canonical_digest(decision) != row["decision_digest"]
                or canonical_digest(envelope) != row["authorized_envelope_digest"]
                or canonical_digest(budget) != row["budget_vector_digest"]
                or canonical_digest(payload) != row["payload_digest"]
                or row["capability_id"] != row["payload_digest"]
                or canonical_digest(verification) != row["verification_digest"]
                or verification.get("payload_digest") != row["payload_digest"]
                or verification.get("bindings") != payload
                or row["lineage_root"] != lineage
                or not _bounded_integer(payload.get("revocation_epoch"))
                or not _bounded_integer(payload.get("fencing_epoch"))
            ):
                raise _StoreCorrupt("capability binding mismatch")
            issued_at = _parse_time(payload["issued_at"])
            not_before = _parse_time(payload["not_before"])
            expires_at = _parse_time(payload["expires_at"])
            if (
                issued_at is None
                or not_before is None
                or expires_at is None
                or not (not_before <= issued_at < expires_at)
            ):
                raise _StoreCorrupt("capability time mismatch")
            column_bindings = {
                "decision_digest": "decision_digest",
                "request_digest": "request_digest",
                "principal_id": "principal_id",
                "audience_id": "audience_id",
                "purpose": "purpose",
                "authorized_envelope_digest": "authorized_envelope_digest",
                "manifest_digest": "manifest_digest",
                "policy_digest": "policy_digest",
                "physical_ceiling_digest": "physical_ceiling_digest",
                "trusted_facts_digest": "trusted_facts_digest",
                "contract_digest": "contract_digest",
                "registry_digest": "registry_digest",
                "profile_digest": "profile_digest",
                "placement_digest": "placement_digest",
                "session_id": "session_id",
                "lineage_root": "lineage_root",
                "nonce": "nonce",
                "issued_at": "issued_at",
                "not_before": "not_before",
                "expires_at": "expires_at",
                "revocation_epoch": "revocation_epoch",
                "fencing_epoch": "fencing_epoch",
                "idempotency_key_digest": "idempotency_key_digest",
                "budget_vector_digest": "budget_vector_digest",
            }
            if any(payload.get(payload_name) != row[column] for payload_name, column in column_bindings.items()):
                raise _StoreCorrupt("capability column mismatch")
            issued = connection.execute(
                "SELECT event_type, subject_id, payload_json FROM journal_entries WHERE sequence=?",
                (row["issued_journal_sequence"],),
            ).fetchone()
            expected_issue_event = {
                "capability_id": row["capability_id"],
                "payload_digest": row["payload_digest"],
                "verification_digest": row["verification_digest"],
                "decision_digest": row["decision_digest"],
                "request_digest": row["request_digest"],
                "budget_vector_digest": row["budget_vector_digest"],
                "lineage_root": row["lineage_root"],
                "nonce": row["nonce"],
                "revocation_epoch": row["revocation_epoch"],
                "fencing_epoch": row["fencing_epoch"],
            }
            if (
                issued is None
                or tuple(issued[:2]) != ("CAPABILITY_ISSUED", row["capability_id"])
                or _json_value(issued["payload_json"]) != expected_issue_event
                or connection.execute(
                    "SELECT COUNT(*) FROM journal_entries "
                    "WHERE event_type='CAPABILITY_ISSUED' AND subject_id=?",
                    (row["capability_id"],),
                ).fetchone()[0]
                != 1
            ):
                raise _StoreCorrupt("capability issuance event mismatch")
            revoked_events = connection.execute(
                "SELECT COUNT(*) FROM journal_entries "
                "WHERE event_type='CAPABILITY_REVOKED' AND subject_id=?",
                (row["capability_id"],),
            ).fetchone()[0]
            if revoked_events != (1 if row["state"] == "REVOKED" else 0):
                raise _StoreCorrupt("capability revocation event mismatch")

    def _terminal_record_is_valid(
        self,
        intent_row: sqlite3.Row,
        intent: dict[str, object],
        disposition: str,
        record: object,
    ) -> bool:
        if type(record) is not dict:
            return False
        if (
            record.get("transaction_id") != intent_row["transaction_id"]
            or record.get("intent_digest") != intent_row["intent_digest"]
            or record.get("fencing_epoch") != intent_row["fencing_epoch"]
            or _parse_time(record.get("observed_at")) is None
        ):
            return False
        evidence_keys = frozenset(
            {
                "record_type",
                "transaction_id",
                "intent_digest",
                "fencing_epoch",
                "observed_at",
                "evidence_digest",
            }
        )
        if disposition == "SPENT":
            return (
                _closed_dict(record, evidence_keys)
                and record["record_type"] == disposition
                and _valid_digest(record["evidence_digest"])
            )
        if disposition == "QUARANTINED_ESCROW":
            if _closed_dict(record, evidence_keys):
                return record["record_type"] == disposition and _valid_digest(record["evidence_digest"])
            failed_release_keys = frozenset(
                {
                    "record_type",
                    "reason",
                    "transaction_id",
                    "intent_digest",
                    "fencing_epoch",
                    "observed_at",
                    "attempted_no_effect_record_digest",
                }
            )
            return (
                _closed_dict(record, failed_release_keys)
                and record["record_type"] == disposition
                and record["reason"] == DurableReason.NO_EFFECT_UNVERIFIED.value
                and _valid_digest(record["attempted_no_effect_record_digest"])
            )
        release_keys = frozenset(
            {
                "verification_version",
                "record_type",
                "verifier_id",
                "observer_id",
                "key_id",
                "transaction_id",
                "intent_digest",
                "intent",
                "target_scope_digest",
                "fencing_epoch",
                "observed_at",
                "proof",
            }
        )
        return (
            disposition == "RELEASED"
            and _closed_dict(record, release_keys)
            and record["verification_version"] == FORMAT_VERSION
            and record["record_type"] == "NO_EFFECT"
            and all(
                _valid_identifier(record[field])
                for field in ("verifier_id", "observer_id", "key_id")
            )
            and record["intent"] == intent
            and record["target_scope_digest"] == intent.get("target_scope_digest")
            and _valid_digest(record["target_scope_digest"])
            and _valid_proof(record["proof"])
        )

    def _audit_dispatch(self, connection: sqlite3.Connection, meta: sqlite3.Row) -> None:
        intents = connection.execute("SELECT * FROM dispatch_intents ORDER BY dispatch_counter").fetchall()
        if len(intents) != meta["dispatch_counter"]:
            raise _StoreCorrupt("dispatch counter truncation")
        expected_reserved: dict[tuple[str, str, str, str], int] = {}
        expected_spent: dict[tuple[str, str, str, str], int] = {}
        for expected_counter, intent_row in enumerate(intents, 1):
            if intent_row["dispatch_counter"] != expected_counter:
                raise _StoreCorrupt("non-contiguous dispatch counter")
            intent = _json_value(intent_row["intent_json"])
            if (
                not _closed_dict(intent, _INTENT_KEYS)
                or intent.get("intent_version") != FORMAT_VERSION
                or not all(
                    _valid_identifier(intent.get(field))
                    for field in (
                        "transaction_id",
                        "principal_id",
                        "audience_id",
                        "purpose",
                        "session_id",
                        "nonce",
                    )
                )
                or not all(
                    _valid_digest(intent.get(field))
                    for field in (
                        "capability_id",
                        "capability_payload_digest",
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
                        "lineage_root",
                        "idempotency_key_digest",
                        "target_scope_digest",
                        "material_digest",
                        "budget_vector_digest",
                    )
                )
                or _parse_time(intent.get("observed_at")) is None
                or not _bounded_integer(intent.get("revocation_epoch"))
                or not _bounded_integer(intent.get("fencing_epoch"))
                or not _bounded_integer(intent.get("dispatch_counter"), 1)
                or canonical_digest(intent) != intent_row["intent_digest"]
            ):
                raise _StoreCorrupt("intent digest mismatch")
            for field in (
                "transaction_id",
                "capability_id",
                "idempotency_key_digest",
                "fencing_epoch",
                "dispatch_counter",
            ):
                if intent.get(field) != intent_row[field]:
                    raise _StoreCorrupt("intent column mismatch")
            capability = connection.execute(
                "SELECT * FROM capabilities WHERE capability_id=?",
                (intent_row["capability_id"],),
            ).fetchone()
            capability_bindings = {
                "capability_payload_digest": "payload_digest",
                "decision_digest": "decision_digest",
                "request_digest": "request_digest",
                "principal_id": "principal_id",
                "audience_id": "audience_id",
                "purpose": "purpose",
                "authorized_envelope_digest": "authorized_envelope_digest",
                "manifest_digest": "manifest_digest",
                "policy_digest": "policy_digest",
                "physical_ceiling_digest": "physical_ceiling_digest",
                "trusted_facts_digest": "trusted_facts_digest",
                "contract_digest": "contract_digest",
                "registry_digest": "registry_digest",
                "profile_digest": "profile_digest",
                "placement_digest": "placement_digest",
                "session_id": "session_id",
                "lineage_root": "lineage_root",
                "nonce": "nonce",
                "revocation_epoch": "revocation_epoch",
                "fencing_epoch": "fencing_epoch",
                "idempotency_key_digest": "idempotency_key_digest",
                "budget_vector_digest": "budget_vector_digest",
            }
            if (
                capability is None
                or capability["state"] != "CONSUMED"
                or capability["consumed_transaction_id"] != intent_row["transaction_id"]
                or _json_value(capability["budget_vector_json"]) != intent.get("budget_vector")
                or any(
                    intent.get(intent_field) != capability[column]
                    for intent_field, column in capability_bindings.items()
                )
            ):
                raise _StoreCorrupt("consumed capability mismatch")
            try:
                intent_budget_rows = _parse_budget_vector(
                    intent["budget_vector"],
                    amount_name="amount",
                    expected_lineage=capability["lineage_root"],
                )
            except _Rejected as error:
                raise _StoreCorrupt("invalid intent budget vector") from error
            if (
                [item.data() for item in intent_budget_rows] != intent["budget_vector"]
                or any(item.scope_digest != intent["target_scope_digest"] for item in intent_budget_rows)
            ):
                raise _StoreCorrupt("intent target/budget mismatch")
            event = connection.execute(
                "SELECT event_type, subject_id, payload_json FROM journal_entries WHERE sequence=?",
                (intent_row["journal_sequence"],),
            ).fetchone()
            if event is None or tuple(event[:2]) != (
                "CAPABILITY_CONSUMED_WITH_INTENT",
                intent_row["transaction_id"],
            ):
                raise _StoreCorrupt("intent journal event mismatch")
            event_payload = _json_value(event["payload_json"])
            expected_intent_event = {
                "transaction_id": intent_row["transaction_id"],
                "capability_id": intent_row["capability_id"],
                "intent_digest": intent_row["intent_digest"],
                "idempotency_key_digest": intent_row["idempotency_key_digest"],
                "budget_vector_digest": capability["budget_vector_digest"],
                "dispatch_counter": intent_row["dispatch_counter"],
                "fencing_epoch": intent_row["fencing_epoch"],
                "intent": intent,
            }
            if (
                event_payload != expected_intent_event
                or connection.execute(
                    "SELECT COUNT(*) FROM journal_entries "
                    "WHERE event_type='CAPABILITY_CONSUMED_WITH_INTENT' AND subject_id=?",
                    (intent_row["transaction_id"],),
                ).fetchone()[0]
                != 1
            ):
                raise _StoreCorrupt("intent event binding mismatch")
            reservations = connection.execute(
                """
                SELECT * FROM budget_reservations
                WHERE transaction_id=? ORDER BY name, unit, scope_digest, lineage_root
                """,
                (intent_row["transaction_id"],),
            ).fetchall()
            expected_vector = intent.get("budget_vector")
            if type(expected_vector) is not list or len(reservations) != len(expected_vector):
                raise _StoreCorrupt("reservation vector cardinality mismatch")
            observed_vector = [
                {
                    "name": row["name"],
                    "unit": row["unit"],
                    "scope_digest": row["scope_digest"],
                    "lineage_root": row["lineage_root"],
                    "amount": row["amount"],
                }
                for row in reservations
            ]
            if observed_vector != expected_vector:
                raise _StoreCorrupt("reservation vector mismatch")
            expected_disposition = None if intent_row["state"] == "PENDING" else intent_row["state"]
            terminal_value: dict[str, object] | None = None
            terminal_digest_value: str | None = None
            for reservation in reservations:
                if reservation["disposition"] != expected_disposition:
                    raise _StoreCorrupt("reservation terminal mismatch")
                terminal_text = reservation["terminal_record_json"]
                terminal_digest = reservation["terminal_record_digest"]
                if expected_disposition is None:
                    if terminal_text is not None or terminal_digest is not None:
                        raise _StoreCorrupt("pending reservation has terminal record")
                else:
                    terminal = _json_value(terminal_text)
                    if (
                        canonical_digest(terminal) != terminal_digest
                        or not self._terminal_record_is_valid(
                            intent_row,
                            intent,
                            expected_disposition,
                            terminal,
                        )
                    ):
                        raise _StoreCorrupt("terminal record digest mismatch")
                    if terminal_value is None:
                        terminal_value = terminal
                        terminal_digest_value = terminal_digest
                    elif terminal != terminal_value or terminal_digest != terminal_digest_value:
                        raise _StoreCorrupt("inconsistent terminal records")
                key = (
                    reservation["name"],
                    reservation["unit"],
                    reservation["scope_digest"],
                    reservation["lineage_root"],
                )
                if expected_disposition in (None, "QUARANTINED_ESCROW"):
                    expected_reserved[key] = expected_reserved.get(key, 0) + reservation["amount"]
                elif expected_disposition == "SPENT":
                    expected_spent[key] = expected_spent.get(key, 0) + reservation["amount"]
            terminal_events = connection.execute(
                "SELECT event_type, subject_id, payload_json FROM journal_entries "
                "WHERE subject_id=? AND event_type LIKE 'BUDGET_TERMINAL_%'",
                (intent_row["transaction_id"],),
            ).fetchall()
            if expected_disposition is None:
                if terminal_events:
                    raise _StoreCorrupt("pending intent has terminal event")
            else:
                expected_terminal_event = {
                    "transaction_id": intent_row["transaction_id"],
                    "intent_digest": intent_row["intent_digest"],
                    "disposition": expected_disposition,
                    "terminal_record_digest": terminal_digest_value,
                    "fencing_epoch": intent_row["fencing_epoch"],
                }
                if (
                    terminal_value is None
                    or terminal_digest_value is None
                    or len(terminal_events) != 1
                    or tuple(terminal_events[0][:2])
                    != ("BUDGET_TERMINAL_" + expected_disposition, intent_row["transaction_id"])
                    or _json_value(terminal_events[0]["payload_json"]) != expected_terminal_event
                ):
                    raise _StoreCorrupt("terminal event binding mismatch")
        consumed = connection.execute("SELECT COUNT(*) FROM capabilities WHERE state='CONSUMED'").fetchone()[0]
        if consumed != len(intents):
            raise _StoreCorrupt("consumed capability cardinality mismatch")
        for budget in connection.execute("SELECT * FROM budgets"):
            key = (budget["name"], budget["unit"], budget["scope_digest"], budget["lineage_root"])
            if budget["reserved"] != expected_reserved.get(key, 0) or budget["spent"] != expected_spent.get(key, 0):
                raise _StoreCorrupt("budget ledger/reservation mismatch")

    def _append_event(
        self,
        connection: sqlite3.Connection,
        event_type: str,
        subject_id: str,
        payload: dict[str, object],
    ) -> int:
        meta = connection.execute("SELECT * FROM store_meta WHERE id=1").fetchone()
        if meta is None or meta["journal_head_sequence"] != meta["outbox_head_sequence"]:
            raise _StoreCorrupt("chain sequence mismatch")
        sequence = meta["journal_head_sequence"] + 1
        if not _bounded_integer(sequence, 1):
            raise _StoreCorrupt("journal sequence overflow")
        journal_body = {
            "sequence": sequence,
            "previous_digest": meta["journal_head_digest"],
            "event_type": event_type,
            "subject_id": subject_id,
            "payload": payload,
        }
        journal_digest = canonical_digest(journal_body)
        outbox_payload = {"journal_digest": journal_digest, "event": payload}
        outbox_body = {
            "sequence": sequence,
            "previous_digest": meta["outbox_head_digest"],
            "event_type": event_type,
            "subject_id": subject_id,
            "payload": outbox_payload,
        }
        outbox_digest = canonical_digest(outbox_body)
        connection.execute(
            "INSERT INTO journal_entries VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                sequence,
                meta["journal_head_digest"],
                event_type,
                subject_id,
                _canonical_text(payload),
                journal_digest,
                sequence,
            ),
        )
        connection.execute(
            "INSERT INTO outbox_events VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                sequence,
                meta["outbox_head_digest"],
                event_type,
                subject_id,
                _canonical_text(outbox_payload),
                outbox_digest,
                sequence,
            ),
        )
        connection.execute(
            """
            UPDATE store_meta
            SET journal_head_sequence=?, journal_head_digest=?,
                outbox_head_sequence=?, outbox_head_digest=?
            WHERE id=1
            """,
            (sequence, journal_digest, sequence, outbox_digest),
        )
        return sequence

    def _hit(self, point: str) -> None:
        if self._fault is not None:
            self._fault(point)  # type: ignore[operator]

    def _mark_corrupt(self) -> DurableResult:
        self._usable = False
        self._stopped_reason = DurableReason.CORRUPT_STORE
        return _result(DurableOutcome.STOP, DurableReason.CORRUPT_STORE)

    def health(self) -> DurableResult:
        if not self._usable:
            return _result(DurableOutcome.STOP, self._stopped_reason)
        try:
            connection = self._connect()
            try:
                self._audit(connection)
            finally:
                connection.close()
        except Exception:
            return self._mark_corrupt()
        return _result(DurableOutcome.OK, DurableReason.READY)

    def bootstrap(self, raw: object) -> DurableResult:
        if not self._usable:
            return _result(DurableOutcome.STOP, self._stopped_reason)
        try:
            if not _closed_dict(
                raw,
                frozenset({"lineage_root", "revocation_epoch", "fencing_epoch", "budgets"}),
            ):
                raise _Rejected(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
            lineage = raw["lineage_root"]
            if not _valid_digest(lineage):
                raise _Rejected(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
            if not _bounded_integer(raw["revocation_epoch"]) or not _bounded_integer(raw["fencing_epoch"]):
                raise _Rejected(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
            budgets = _parse_budget_vector(raw["budgets"], amount_name="limit", expected_lineage=lineage)
        except _Rejected as rejection:
            return _result(rejection.outcome, rejection.reason)
        connection: sqlite3.Connection | None = None
        try:
            self._hit("before_transaction")
            connection = self._connect()
            connection.execute("BEGIN IMMEDIATE")
            self._hit("after_begin")
            self._audit(connection)
            meta = connection.execute("SELECT * FROM store_meta WHERE id=1").fetchone()
            if meta is None:
                raise _StoreCorrupt("missing metadata")
            if meta["lineage_root"] is not None:
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.ALREADY_BOOTSTRAPPED)
            connection.execute(
                "UPDATE store_meta SET lineage_root=?, revocation_epoch=?, fencing_epoch=? WHERE id=1",
                (lineage, raw["revocation_epoch"], raw["fencing_epoch"]),
            )
            for row in budgets:
                connection.execute(
                    "INSERT INTO budgets VALUES (?, ?, ?, ?, ?, ?, 0, 0)",
                    (*row.key, row.amount, row.amount),
                )
            payload = {
                "lineage_root": lineage,
                "revocation_epoch": raw["revocation_epoch"],
                "fencing_epoch": raw["fencing_epoch"],
                "budgets": [row.data("limit") for row in budgets],
            }
            sequence = self._append_event(connection, "STORE_BOOTSTRAPPED", lineage, payload)
            self._hit("after_event")
            connection.commit()
            connection.close()
            connection = None
            try:
                self._hit("after_commit_before_ack")
            except Exception:
                return _result(DurableOutcome.STOP, DurableReason.ACKNOWLEDGEMENT_UNKNOWN)
            return DurableResult(
                DurableOutcome.COMMITTED,
                DurableReason.BOOTSTRAPPED,
                journal_sequence=sequence,
            )
        except _StoreCorrupt:
            if connection is not None:
                connection.rollback()
            return self._mark_corrupt()
        except sqlite3.OperationalError as error:
            if connection is not None:
                connection.rollback()
            if "locked" in str(error).lower() or "busy" in str(error).lower():
                return _result(DurableOutcome.STOP, DurableReason.STORE_BUSY)
            return self._mark_corrupt()
        except Exception:
            if connection is not None:
                connection.rollback()
            return _result(DurableOutcome.STOP, DurableReason.INTERNAL_ERROR)
        finally:
            if connection is not None:
                connection.close()

    def _prepare_issue(self, raw: object) -> _PreparedIssue:
        keys = frozenset(
            {
                "request",
                "audience_id",
                "purpose",
                "contract_digest",
                "registry_digest",
                "profile_digest",
                "placement_digest",
                "session_id",
                "lineage_root",
                "nonce",
                "issued_at",
                "not_before",
                "expires_at",
                "revocation_epoch",
                "fencing_epoch",
                "idempotency_key_digest",
                "budget",
                "verification",
            }
        )
        if not _closed_dict(raw, keys):
            raise _Rejected(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
        for field in ("audience_id", "purpose", "session_id", "nonce"):
            if not _valid_identifier(raw[field]):
                raise _Rejected(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
        for field in (
            "contract_digest",
            "registry_digest",
            "profile_digest",
            "placement_digest",
            "lineage_root",
            "idempotency_key_digest",
        ):
            if not _valid_digest(raw[field]):
                raise _Rejected(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
        if not _bounded_integer(raw["revocation_epoch"]) or not _bounded_integer(raw["fencing_epoch"]):
            raise _Rejected(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
        issued_at = _parse_time(raw["issued_at"])
        not_before = _parse_time(raw["not_before"])
        expires_at = _parse_time(raw["expires_at"])
        if issued_at is None or not_before is None or expires_at is None or not (not_before <= issued_at < expires_at):
            raise _Rejected(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
        verification_source = raw["verification"]
        if not _closed_dict(
            verification_source,
            frozenset({"verifier_id", "issuer_id", "key_id", "proof"}),
        ):
            raise _Rejected(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
        if not all(_valid_identifier(verification_source[field]) for field in ("verifier_id", "issuer_id", "key_id")):
            raise _Rejected(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
        if not _valid_proof(verification_source["proof"]):
            raise _Rejected(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)

        kernel_result = evaluate(raw["request"], KernelState())
        if type(kernel_result) is not KernelResult:
            raise _Rejected(DurableOutcome.STOP, DurableReason.M1_REJECTED)
        if kernel_result.decision.outcome is not Outcome.ALLOW:
            outcome = DurableOutcome.DENY if kernel_result.decision.outcome is Outcome.DENY else DurableOutcome.STOP
            raise _Rejected(outcome, DurableReason.M1_REJECTED)
        if (
            kernel_result.decision.stage is not Stage.DECIDE
            or kernel_result.decision.reason is not Reason.AUTHORIZED_EXACT_BOUND
            or not kernel_result.transition.accepted
            or len(kernel_result.transition.proposals) != 1
            or type(kernel_result.transition.proposals[0]) is not PowerlessProposal
            or kernel_result.transition.proposals[0].authority is not ProposalAuthority.NONE
        ):
            raise _Rejected(DurableOutcome.STOP, DurableReason.M1_REJECTED)

        normalized = normalize(raw["request"])
        if type(normalized) is not NormalizedInput:
            raise _Rejected(DurableOutcome.STOP, DurableReason.M1_REJECTED)
        classified = classify(normalized)
        if type(classified) is not ClassifiedInput:
            raise _Rejected(DurableOutcome.STOP, DurableReason.M1_REJECTED)
        derived = derive(classified)
        if type(derived) is not DerivedAuthority:
            raise _Rejected(DurableOutcome.STOP, DurableReason.M1_REJECTED)
        decision = decide(derived)
        if type(decision) is not Decision or decision != kernel_result.decision:
            raise _Rejected(DurableOutcome.STOP, DurableReason.M1_REJECTED)
        projected = transition(KernelState(), decision)
        if projected != kernel_result.transition:
            raise _Rejected(DurableOutcome.STOP, DurableReason.M1_REJECTED)
        if raw["audience_id"] == normalized.proposal.principal_id:
            raise _Rejected(DurableOutcome.DENY, DurableReason.BINDING_MISMATCH)
        if issued_at != normalized.evaluation_time:
            raise _Rejected(DurableOutcome.DENY, DurableReason.BINDING_MISMATCH)
        if (
            not_before < normalized.proposal.authority.not_before
            or expires_at > normalized.proposal.authority.not_after
            or expires_at > normalized.trusted_facts.expires_at
        ):
            raise _Rejected(DurableOutcome.DENY, DurableReason.EXPIRED)

        scope_digest = canonical_digest(selector_data(normalized.proposal.authority.selector))
        budget_rows = _parse_budget_vector(
            raw["budget"],
            amount_name="amount",
            expected_lineage=raw["lineage_root"],
        )
        if any(item.scope_digest != scope_digest for item in budget_rows):
            raise _Rejected(DurableOutcome.DENY, DurableReason.BUDGET_MISMATCH)
        if not any(
            item.unit == normalized.proposal.authority.quantity_unit.value
            and item.amount == normalized.proposal.authority.max_quantity
            for item in budget_rows
        ):
            raise _Rejected(DurableOutcome.DENY, DurableReason.BUDGET_MISMATCH)

        request_data = _normalized_data(normalized)
        request_digest = canonical_digest(request_data)
        envelope = {"clauses": [clause_data(derived.effective)]}
        envelope_digest = canonical_digest(envelope)
        manifest_digest = canonical_digest(_source_data(normalized.manifest))
        policy_digest = canonical_digest(_source_data(normalized.policy))
        physical_digest = canonical_digest(_source_data(normalized.physical_ceiling))
        facts_digest = canonical_digest(_facts_data(normalized.trusted_facts))
        decision_projection = decision_data(
            decision.outcome,
            decision.reason,
            decision.stage,
            decision.proposal_digest,
            decision.proposals,
        )
        if canonical_digest(decision_projection) != decision.decision_digest:
            raise _Rejected(DurableOutcome.STOP, DurableReason.M1_REJECTED)
        budget_data = [row.data() for row in budget_rows]
        budget_digest = canonical_digest(budget_data)
        source_clause_digests = list(derived.source_clause_digests)
        payload: dict[str, object] = {
            "capability_version": FORMAT_VERSION,
            "decision": decision_projection,
            "decision_digest": decision.decision_digest,
            "request_digest": request_digest,
            "principal_id": normalized.proposal.principal_id,
            "audience_id": raw["audience_id"],
            "purpose": raw["purpose"],
            "authorized_envelope": envelope,
            "authorized_envelope_digest": envelope_digest,
            "manifest_digest": manifest_digest,
            "policy_digest": policy_digest,
            "physical_ceiling_digest": physical_digest,
            "trusted_facts_digest": facts_digest,
            "source_clause_digests": source_clause_digests,
            "contract_digest": raw["contract_digest"],
            "registry_digest": raw["registry_digest"],
            "profile_digest": raw["profile_digest"],
            "placement_digest": raw["placement_digest"],
            "session_id": raw["session_id"],
            "lineage_root": raw["lineage_root"],
            "nonce": raw["nonce"],
            "issued_at": raw["issued_at"],
            "not_before": raw["not_before"],
            "expires_at": raw["expires_at"],
            "revocation_epoch": raw["revocation_epoch"],
            "fencing_epoch": raw["fencing_epoch"],
            "idempotency_key_digest": raw["idempotency_key_digest"],
            "budget_vector": budget_data,
            "budget_vector_digest": budget_digest,
        }
        capability_id = canonical_digest(payload)
        verification = {
            "verification_version": FORMAT_VERSION,
            "verifier_id": verification_source["verifier_id"],
            "issuer_id": verification_source["issuer_id"],
            "key_id": verification_source["key_id"],
            "payload_digest": capability_id,
            "bindings": payload,
            "proof": verification_source["proof"],
        }
        return _PreparedIssue(
            capability_id,
            payload,
            _canonical_text(payload),
            _canonical_text(request_data),
            _canonical_text(decision_projection),
            _canonical_text(envelope),
            _canonical_text(source_clause_digests),
            budget_rows,
            _canonical_text(budget_data),
            verification,
            _canonical_text(verification),
            canonical_digest(verification),
        )

    def _verification_is_valid(self, prepared: _PreparedIssue, observed_at: str) -> bool:
        try:
            verifier = self._verifier
            result = verifier.verify(
                prepared.payload_text.encode("utf-8"),
                prepared.verification_text.encode("utf-8"),
                observed_at,
            )
            return (
                type(result) is VerificationResult
                and result.status is VerificationStatus.VERIFIED
                and result.verifier_id == prepared.verification["verifier_id"]
                and result.payload_digest == prepared.capability_id
                and result.record_digest == prepared.verification_digest
            )
        except Exception:
            return False

    def issue(self, raw: object) -> DurableResult:
        if not self._usable:
            return _result(DurableOutcome.STOP, self._stopped_reason)
        try:
            prepared = self._prepare_issue(raw)
        except _Rejected as rejection:
            return _result(rejection.outcome, rejection.reason)
        except Exception:
            return _result(DurableOutcome.STOP, DurableReason.INTERNAL_ERROR)
        connection: sqlite3.Connection | None = None
        try:
            self._hit("before_transaction")
            connection = self._connect()
            connection.execute("BEGIN IMMEDIATE")
            self._hit("after_begin")
            self._audit(connection)
            meta = connection.execute("SELECT * FROM store_meta WHERE id=1").fetchone()
            if meta is None:
                raise _StoreCorrupt("missing metadata")
            if meta["lineage_root"] is None:
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.NOT_BOOTSTRAPPED)
            if prepared.payload["lineage_root"] != meta["lineage_root"]:
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.BINDING_MISMATCH)
            if prepared.payload["revocation_epoch"] != meta["revocation_epoch"]:
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.STALE_REVOCATION)
            if prepared.payload["fencing_epoch"] != meta["fencing_epoch"]:
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.STALE_FENCE)
            if connection.execute(
                "SELECT 1 FROM capabilities WHERE nonce=? OR capability_id=? OR idempotency_key_digest=?",
                (
                    prepared.payload["nonce"],
                    prepared.capability_id,
                    prepared.payload["idempotency_key_digest"],
                ),
            ).fetchone() is not None:
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.REPLAY)
            for row in prepared.budget_rows:
                durable = connection.execute(
                    """
                    SELECT limit_amount FROM budgets
                    WHERE name=? AND unit=? AND scope_digest=? AND lineage_root=?
                    """,
                    row.key,
                ).fetchone()
                if durable is None:
                    connection.rollback()
                    return _result(DurableOutcome.DENY, DurableReason.BUDGET_MISMATCH)
                if row.amount > durable["limit_amount"]:
                    connection.rollback()
                    return _result(DurableOutcome.DENY, DurableReason.BUDGET_EXCEEDED)
            if not self._verification_is_valid(prepared, prepared.payload["issued_at"]):
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.CAPABILITY_INVALID)
            sequence = meta["journal_head_sequence"] + 1
            connection.execute(
                """
                INSERT INTO capabilities (
                    capability_id, payload_digest, nonce, state, decision_digest, request_digest,
                    principal_id, audience_id, purpose, authorized_envelope_digest,
                    manifest_digest, policy_digest, physical_ceiling_digest, trusted_facts_digest,
                    contract_digest, registry_digest, profile_digest, placement_digest, session_id,
                    lineage_root, issued_at, not_before, expires_at, revocation_epoch, fencing_epoch,
                    idempotency_key_digest, budget_vector_digest, request_json, decision_json,
                    authorized_envelope_json, source_clause_digests_json, budget_vector_json,
                    payload_json, verification_json, verification_digest,
                    consumed_transaction_id, issued_journal_sequence
                ) VALUES (
                    ?, ?, ?, 'ISSUED', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?
                )
                """,
                (
                    prepared.capability_id,
                    prepared.capability_id,
                    prepared.payload["nonce"],
                    prepared.payload["decision_digest"],
                    prepared.payload["request_digest"],
                    prepared.payload["principal_id"],
                    prepared.payload["audience_id"],
                    prepared.payload["purpose"],
                    prepared.payload["authorized_envelope_digest"],
                    prepared.payload["manifest_digest"],
                    prepared.payload["policy_digest"],
                    prepared.payload["physical_ceiling_digest"],
                    prepared.payload["trusted_facts_digest"],
                    prepared.payload["contract_digest"],
                    prepared.payload["registry_digest"],
                    prepared.payload["profile_digest"],
                    prepared.payload["placement_digest"],
                    prepared.payload["session_id"],
                    prepared.payload["lineage_root"],
                    prepared.payload["issued_at"],
                    prepared.payload["not_before"],
                    prepared.payload["expires_at"],
                    prepared.payload["revocation_epoch"],
                    prepared.payload["fencing_epoch"],
                    prepared.payload["idempotency_key_digest"],
                    prepared.payload["budget_vector_digest"],
                    prepared.request_text,
                    prepared.decision_text,
                    prepared.envelope_text,
                    prepared.source_clause_digests_text,
                    prepared.budget_text,
                    prepared.payload_text,
                    prepared.verification_text,
                    prepared.verification_digest,
                    sequence,
                ),
            )
            event_payload = {
                "capability_id": prepared.capability_id,
                "payload_digest": prepared.capability_id,
                "verification_digest": prepared.verification_digest,
                "decision_digest": prepared.payload["decision_digest"],
                "request_digest": prepared.payload["request_digest"],
                "budget_vector_digest": prepared.payload["budget_vector_digest"],
                "lineage_root": prepared.payload["lineage_root"],
                "nonce": prepared.payload["nonce"],
                "revocation_epoch": prepared.payload["revocation_epoch"],
                "fencing_epoch": prepared.payload["fencing_epoch"],
            }
            observed_sequence = self._append_event(
                connection,
                "CAPABILITY_ISSUED",
                prepared.capability_id,
                event_payload,
            )
            if observed_sequence != sequence:
                raise _StoreCorrupt("issue sequence mismatch")
            self._hit("after_event")
            connection.commit()
            connection.close()
            connection = None
            try:
                self._hit("after_commit_before_ack")
            except Exception:
                return _result(DurableOutcome.STOP, DurableReason.ACKNOWLEDGEMENT_UNKNOWN)
            return DurableResult(
                DurableOutcome.COMMITTED,
                DurableReason.CAPABILITY_ISSUED,
                capability_id=prepared.capability_id,
                journal_sequence=sequence,
            )
        except _StoreCorrupt:
            if connection is not None:
                connection.rollback()
            return self._mark_corrupt()
        except sqlite3.OperationalError as error:
            if connection is not None:
                connection.rollback()
            if "locked" in str(error).lower() or "busy" in str(error).lower():
                return _result(DurableOutcome.STOP, DurableReason.STORE_BUSY)
            return self._mark_corrupt()
        except Exception:
            if connection is not None:
                connection.rollback()
            return _result(DurableOutcome.STOP, DurableReason.INTERNAL_ERROR)
        finally:
            if connection is not None:
                connection.close()

    def _prepare_consume(self, raw: object) -> _PreparedConsume:
        keys = frozenset(
            {
                "capability_id",
                "transaction_id",
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
                "observed_at",
                "revocation_epoch",
                "fencing_epoch",
                "idempotency_key_digest",
                "budget",
            }
        )
        if not _closed_dict(raw, keys):
            raise _Rejected(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
        for field in (
            "transaction_id",
            "nonce",
            "principal_id",
            "audience_id",
            "purpose",
            "session_id",
        ):
            if not _valid_identifier(raw[field]):
                raise _Rejected(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
        for field in (
            "capability_id",
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
            "lineage_root",
            "idempotency_key_digest",
        ):
            if not _valid_digest(raw[field]):
                raise _Rejected(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
        if not _bounded_integer(raw["revocation_epoch"]) or not _bounded_integer(raw["fencing_epoch"]):
            raise _Rejected(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
        observed_at = _parse_time(raw["observed_at"])
        if observed_at is None:
            raise _Rejected(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
        budget_rows = _parse_budget_vector(
            raw["budget"],
            amount_name="amount",
            expected_lineage=raw["lineage_root"],
        )
        return _PreparedConsume(raw, budget_rows, _canonical_text([row.data() for row in budget_rows]), observed_at)

    def _stored_verification_is_valid(self, capability: sqlite3.Row, observed_at: str) -> bool:
        try:
            payload = _json_value(capability["payload_json"])
            verification = _json_value(capability["verification_json"])
            if (
                verification.get("bindings") != payload
                or verification.get("payload_digest") != capability["capability_id"]
                or canonical_digest(verification) != capability["verification_digest"]
            ):
                return False
            result = self._verifier.verify(
                capability["payload_json"].encode("utf-8"),
                capability["verification_json"].encode("utf-8"),
                observed_at,
            )
            return (
                type(result) is VerificationResult
                and result.status is VerificationStatus.VERIFIED
                and result.verifier_id == verification.get("verifier_id")
                and result.payload_digest == capability["capability_id"]
                and result.record_digest == capability["verification_digest"]
            )
        except Exception:
            return False

    def consume(self, raw: object) -> DurableResult:
        """Atomically consume one capability, reserve its vector, and persist intent/event."""

        if not self._usable:
            return _result(DurableOutcome.STOP, self._stopped_reason)
        try:
            prepared = self._prepare_consume(raw)
        except _Rejected as rejection:
            return _result(rejection.outcome, rejection.reason)
        except Exception:
            return _result(DurableOutcome.STOP, DurableReason.INTERNAL_ERROR)
        connection: sqlite3.Connection | None = None
        try:
            self._hit("before_transaction")
            connection = self._connect()
            connection.execute("BEGIN IMMEDIATE")
            self._hit("after_begin")
            self._audit(connection)
            meta = connection.execute("SELECT * FROM store_meta WHERE id=1").fetchone()
            capability = connection.execute(
                "SELECT * FROM capabilities WHERE capability_id=?",
                (prepared.raw["capability_id"],),
            ).fetchone()
            if meta is None:
                raise _StoreCorrupt("missing metadata")
            if capability is None:
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.UNKNOWN_CAPABILITY)
            if capability["state"] == "CONSUMED":
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.REPLAY)
            if capability["state"] == "REVOKED":
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.STALE_REVOCATION)
            exact_fields = (
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
            )
            if any(prepared.raw[field] != capability[field] for field in exact_fields):
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.BINDING_MISMATCH)
            if prepared.raw["lineage_root"] != meta["lineage_root"]:
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.BINDING_MISMATCH)
            if (
                prepared.raw["revocation_epoch"] != meta["revocation_epoch"]
                or capability["revocation_epoch"] != meta["revocation_epoch"]
            ):
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.STALE_REVOCATION)
            if (
                prepared.raw["fencing_epoch"] != meta["fencing_epoch"]
                or capability["fencing_epoch"] != meta["fencing_epoch"]
            ):
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.STALE_FENCE)
            not_before = _parse_time(capability["not_before"])
            expires_at = _parse_time(capability["expires_at"])
            if not_before is None or expires_at is None:
                raise _StoreCorrupt("invalid capability time")
            if not (not_before <= prepared.observed_at < expires_at):
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.EXPIRED)
            if prepared.budget_text != capability["budget_vector_json"]:
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.BUDGET_MISMATCH)
            if not self._stored_verification_is_valid(capability, prepared.raw["observed_at"]):
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.CAPABILITY_INVALID)
            if connection.execute(
                "SELECT 1 FROM dispatch_intents WHERE transaction_id=? OR idempotency_key_digest=?",
                (prepared.raw["transaction_id"], prepared.raw["idempotency_key_digest"]),
            ).fetchone() is not None:
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.REPLAY)
            for budget in prepared.budget_rows:
                cursor = connection.execute(
                    """
                    UPDATE budgets
                    SET remaining=remaining-?, reserved=reserved+?
                    WHERE name=? AND unit=? AND scope_digest=? AND lineage_root=?
                      AND remaining>=? AND reserved<=?
                    """,
                    (budget.amount, budget.amount, *budget.key, budget.amount, _MAX_INTEGER - budget.amount),
                )
                if cursor.rowcount != 1:
                    connection.rollback()
                    return _result(DurableOutcome.DENY, DurableReason.BUDGET_EXCEEDED)
            self._hit("after_budget_reservation")
            counter = meta["dispatch_counter"] + 1
            sequence = meta["journal_head_sequence"] + 1
            if not _bounded_integer(counter, 1) or not _bounded_integer(sequence, 1):
                raise _StoreCorrupt("monotonic counter overflow")
            capability_payload = _json_value(capability["payload_json"])
            target_scope = prepared.budget_rows[0].scope_digest
            intent = {
                "intent_version": FORMAT_VERSION,
                "transaction_id": prepared.raw["transaction_id"],
                "capability_id": capability["capability_id"],
                "capability_payload_digest": capability["payload_digest"],
                "decision_digest": capability["decision_digest"],
                "request_digest": capability["request_digest"],
                "principal_id": capability["principal_id"],
                "audience_id": capability["audience_id"],
                "purpose": capability["purpose"],
                "authorized_envelope_digest": capability["authorized_envelope_digest"],
                "manifest_digest": capability["manifest_digest"],
                "policy_digest": capability["policy_digest"],
                "physical_ceiling_digest": capability["physical_ceiling_digest"],
                "trusted_facts_digest": capability["trusted_facts_digest"],
                "contract_digest": capability["contract_digest"],
                "registry_digest": capability["registry_digest"],
                "profile_digest": capability["profile_digest"],
                "placement_digest": capability["placement_digest"],
                "session_id": capability["session_id"],
                "lineage_root": capability["lineage_root"],
                "nonce": capability["nonce"],
                "observed_at": prepared.raw["observed_at"],
                "revocation_epoch": capability["revocation_epoch"],
                "fencing_epoch": capability["fencing_epoch"],
                "idempotency_key_digest": capability["idempotency_key_digest"],
                "target_scope_digest": target_scope,
                "material_digest": capability_payload["decision"]["proposals"][0]["proposal"]["material_digest"],
                "budget_vector": [item.data() for item in prepared.budget_rows],
                "budget_vector_digest": capability["budget_vector_digest"],
                "dispatch_counter": counter,
            }
            intent_text = _canonical_text(intent)
            intent_digest = canonical_digest(intent)
            updated = connection.execute(
                """
                UPDATE capabilities SET state='CONSUMED', consumed_transaction_id=?
                WHERE capability_id=? AND state='ISSUED' AND consumed_transaction_id IS NULL
                """,
                (prepared.raw["transaction_id"], capability["capability_id"]),
            )
            if updated.rowcount != 1:
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.REPLAY)
            self._hit("after_capability_consume")
            connection.execute(
                "INSERT INTO dispatch_intents VALUES (?, ?, 'PENDING', ?, ?, ?, ?, ?, ?)",
                (
                    prepared.raw["transaction_id"],
                    capability["capability_id"],
                    intent_digest,
                    capability["idempotency_key_digest"],
                    capability["fencing_epoch"],
                    counter,
                    intent_text,
                    sequence,
                ),
            )
            for budget in prepared.budget_rows:
                connection.execute(
                    """
                    INSERT INTO budget_reservations
                    VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, NULL)
                    """,
                    (prepared.raw["transaction_id"], *budget.key, budget.amount),
                )
            self._hit("after_intent")
            connection.execute("UPDATE store_meta SET dispatch_counter=? WHERE id=1", (counter,))
            event_payload = {
                "transaction_id": prepared.raw["transaction_id"],
                "capability_id": capability["capability_id"],
                "intent_digest": intent_digest,
                "idempotency_key_digest": capability["idempotency_key_digest"],
                "budget_vector_digest": capability["budget_vector_digest"],
                "dispatch_counter": counter,
                "fencing_epoch": capability["fencing_epoch"],
                "intent": intent,
            }
            observed_sequence = self._append_event(
                connection,
                "CAPABILITY_CONSUMED_WITH_INTENT",
                prepared.raw["transaction_id"],
                event_payload,
            )
            if observed_sequence != sequence:
                raise _StoreCorrupt("consume sequence mismatch")
            self._hit("after_event")
            connection.commit()
            connection.close()
            connection = None
            try:
                self._hit("after_commit_before_ack")
            except Exception:
                return _result(DurableOutcome.STOP, DurableReason.ACKNOWLEDGEMENT_UNKNOWN)
            return DurableResult(
                DurableOutcome.COMMITTED,
                DurableReason.INTENT_COMMITTED,
                capability_id=capability["capability_id"],
                transaction_id=prepared.raw["transaction_id"],
                journal_sequence=sequence,
            )
        except _StoreCorrupt:
            if connection is not None:
                connection.rollback()
            return self._mark_corrupt()
        except sqlite3.OperationalError as error:
            if connection is not None:
                connection.rollback()
            if "locked" in str(error).lower() or "busy" in str(error).lower():
                return _result(DurableOutcome.STOP, DurableReason.STORE_BUSY)
            return self._mark_corrupt()
        except Exception:
            if connection is not None:
                connection.rollback()
            return _result(DurableOutcome.STOP, DurableReason.INTERNAL_ERROR)
        finally:
            if connection is not None:
                connection.close()

    def revoke(self, raw: object) -> DurableResult:
        if not self._usable:
            return _result(DurableOutcome.STOP, self._stopped_reason)
        if not _closed_dict(
            raw,
            frozenset(
                {
                    "capability_id",
                    "expected_revocation_epoch",
                    "new_revocation_epoch",
                    "fencing_epoch",
                    "reason_digest",
                }
            ),
        ):
            return _result(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
        if not _valid_digest(raw["capability_id"]) or not _valid_digest(raw["reason_digest"]):
            return _result(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
        for field in ("expected_revocation_epoch", "new_revocation_epoch", "fencing_epoch"):
            if not _bounded_integer(raw[field]):
                return _result(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
        if (
            raw["expected_revocation_epoch"] == _MAX_INTEGER
            or raw["new_revocation_epoch"] != raw["expected_revocation_epoch"] + 1
        ):
            return _result(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
        connection: sqlite3.Connection | None = None
        try:
            self._hit("before_transaction")
            connection = self._connect()
            connection.execute("BEGIN IMMEDIATE")
            self._hit("after_begin")
            self._audit(connection)
            meta = connection.execute("SELECT * FROM store_meta WHERE id=1").fetchone()
            capability = connection.execute(
                "SELECT state, revocation_epoch, fencing_epoch FROM capabilities WHERE capability_id=?",
                (raw["capability_id"],),
            ).fetchone()
            if meta is None:
                raise _StoreCorrupt("missing metadata")
            if capability is None:
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.UNKNOWN_CAPABILITY)
            if capability["state"] != "ISSUED":
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.ILLEGAL_TRANSITION)
            if (
                meta["revocation_epoch"] != raw["expected_revocation_epoch"]
                or capability["revocation_epoch"] != raw["expected_revocation_epoch"]
            ):
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.STALE_REVOCATION)
            if meta["fencing_epoch"] != raw["fencing_epoch"] or capability["fencing_epoch"] != raw["fencing_epoch"]:
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.STALE_FENCE)
            connection.execute(
                "UPDATE capabilities SET state='REVOKED' WHERE capability_id=? AND state='ISSUED'",
                (raw["capability_id"],),
            )
            connection.execute(
                "UPDATE store_meta SET revocation_epoch=? WHERE id=1",
                (raw["new_revocation_epoch"],),
            )
            sequence = self._append_event(
                connection,
                "CAPABILITY_REVOKED",
                raw["capability_id"],
                {
                    "capability_id": raw["capability_id"],
                    "previous_revocation_epoch": raw["expected_revocation_epoch"],
                    "revocation_epoch": raw["new_revocation_epoch"],
                    "fencing_epoch": raw["fencing_epoch"],
                    "reason_digest": raw["reason_digest"],
                },
            )
            self._hit("after_event")
            connection.commit()
            connection.close()
            connection = None
            try:
                self._hit("after_commit_before_ack")
            except Exception:
                return _result(DurableOutcome.STOP, DurableReason.ACKNOWLEDGEMENT_UNKNOWN)
            return DurableResult(
                DurableOutcome.COMMITTED,
                DurableReason.REVOKED,
                capability_id=raw["capability_id"],
                journal_sequence=sequence,
            )
        except _StoreCorrupt:
            if connection is not None:
                connection.rollback()
            return self._mark_corrupt()
        except sqlite3.OperationalError as error:
            if connection is not None:
                connection.rollback()
            if "locked" in str(error).lower() or "busy" in str(error).lower():
                return _result(DurableOutcome.STOP, DurableReason.STORE_BUSY)
            return self._mark_corrupt()
        except Exception:
            if connection is not None:
                connection.rollback()
            return _result(DurableOutcome.STOP, DurableReason.INTERNAL_ERROR)
        finally:
            if connection is not None:
                connection.close()

    def advance_fence(self, raw: object) -> DurableResult:
        if not self._usable:
            return _result(DurableOutcome.STOP, self._stopped_reason)
        if not _closed_dict(
            raw,
            frozenset({"expected_fencing_epoch", "new_fencing_epoch", "reason_digest"}),
        ):
            return _result(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
        if not _valid_digest(raw["reason_digest"]):
            return _result(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
        if not _bounded_integer(raw["expected_fencing_epoch"]) or not _bounded_integer(raw["new_fencing_epoch"]):
            return _result(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
        if (
            raw["expected_fencing_epoch"] == _MAX_INTEGER
            or raw["new_fencing_epoch"] != raw["expected_fencing_epoch"] + 1
        ):
            return _result(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
        connection: sqlite3.Connection | None = None
        try:
            self._hit("before_transaction")
            connection = self._connect()
            connection.execute("BEGIN IMMEDIATE")
            self._hit("after_begin")
            self._audit(connection)
            meta = connection.execute("SELECT * FROM store_meta WHERE id=1").fetchone()
            if meta is None:
                raise _StoreCorrupt("missing metadata")
            if meta["fencing_epoch"] != raw["expected_fencing_epoch"]:
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.STALE_FENCE)
            connection.execute(
                "UPDATE store_meta SET fencing_epoch=? WHERE id=1",
                (raw["new_fencing_epoch"],),
            )
            sequence = self._append_event(
                connection,
                "FENCE_ADVANCED",
                meta["lineage_root"],
                {
                    "lineage_root": meta["lineage_root"],
                    "previous_fencing_epoch": raw["expected_fencing_epoch"],
                    "fencing_epoch": raw["new_fencing_epoch"],
                    "reason_digest": raw["reason_digest"],
                },
            )
            self._hit("after_event")
            connection.commit()
            connection.close()
            connection = None
            try:
                self._hit("after_commit_before_ack")
            except Exception:
                return _result(DurableOutcome.STOP, DurableReason.ACKNOWLEDGEMENT_UNKNOWN)
            return DurableResult(
                DurableOutcome.COMMITTED,
                DurableReason.FENCE_ADVANCED,
                journal_sequence=sequence,
            )
        except _StoreCorrupt:
            if connection is not None:
                connection.rollback()
            return self._mark_corrupt()
        except sqlite3.OperationalError as error:
            if connection is not None:
                connection.rollback()
            if "locked" in str(error).lower() or "busy" in str(error).lower():
                return _result(DurableOutcome.STOP, DurableReason.STORE_BUSY)
            return self._mark_corrupt()
        except Exception:
            if connection is not None:
                connection.rollback()
            return _result(DurableOutcome.STOP, DurableReason.INTERNAL_ERROR)
        finally:
            if connection is not None:
                connection.close()

    def _no_effect_record(
        self,
        intent: sqlite3.Row,
        evidence: dict[str, object],
        observed_at: str,
    ) -> tuple[dict[str, object], bool]:
        intent_value = _json_value(intent["intent_json"])
        record = {
            "verification_version": FORMAT_VERSION,
            "record_type": "NO_EFFECT",
            "verifier_id": evidence["verifier_id"],
            "observer_id": evidence["observer_id"],
            "key_id": evidence["key_id"],
            "transaction_id": intent["transaction_id"],
            "intent_digest": intent["intent_digest"],
            "intent": intent_value,
            "target_scope_digest": intent_value["target_scope_digest"],
            "fencing_epoch": intent["fencing_epoch"],
            "observed_at": observed_at,
            "proof": evidence["proof"],
        }
        record_text = _canonical_text(record)
        try:
            if self._no_effect_verifier is None:
                return record, False
            result = self._no_effect_verifier.verify(
                intent["intent_json"].encode("utf-8"),
                record_text.encode("utf-8"),
                observed_at,
            )
            valid = (
                type(result) is VerificationResult
                and result.status is VerificationStatus.VERIFIED
                and result.verifier_id == evidence["verifier_id"]
                and result.payload_digest == intent["intent_digest"]
                and result.record_digest == canonical_digest(record)
            )
            return record, valid
        except Exception:
            return record, False

    def settle(self, raw: object) -> DurableResult:
        if not self._usable:
            return _result(DurableOutcome.STOP, self._stopped_reason)
        if not _closed_dict(raw, frozenset({"transaction_id", "disposition", "observed_at", "evidence"})):
            return _result(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
        if not _valid_identifier(raw["transaction_id"]) or _parse_time(raw["observed_at"]) is None:
            return _result(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
        if type(raw["disposition"]) is not str or raw["disposition"] not in {
            "SPENT",
            "RELEASED",
            "QUARANTINED_ESCROW",
        }:
            reason = DurableReason.UNKNOWN_INPUT if type(raw["disposition"]) is str else DurableReason.MALFORMED_INPUT
            return _result(DurableOutcome.STOP, reason)
        evidence = raw["evidence"]
        if raw["disposition"] in {"SPENT", "QUARANTINED_ESCROW"}:
            if not _closed_dict(evidence, frozenset({"evidence_digest"})) or not _valid_digest(evidence["evidence_digest"]):
                return _result(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
        else:
            if not _closed_dict(
                evidence,
                frozenset({"verifier_id", "observer_id", "key_id", "proof"}),
            ):
                return _result(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
            if not all(_valid_identifier(evidence[field]) for field in ("verifier_id", "observer_id", "key_id")):
                return _result(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
            if not _valid_proof(evidence["proof"]):
                return _result(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
        connection: sqlite3.Connection | None = None
        try:
            self._hit("before_transaction")
            connection = self._connect()
            connection.execute("BEGIN IMMEDIATE")
            self._hit("after_begin")
            self._audit(connection)
            intent = connection.execute(
                "SELECT * FROM dispatch_intents WHERE transaction_id=?",
                (raw["transaction_id"],),
            ).fetchone()
            if intent is None:
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.ILLEGAL_TRANSITION)
            if intent["state"] != "PENDING":
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.ILLEGAL_TRANSITION)
            reservations = connection.execute(
                """
                SELECT * FROM budget_reservations WHERE transaction_id=?
                ORDER BY name, unit, scope_digest, lineage_root
                """,
                (raw["transaction_id"],),
            ).fetchall()
            if not reservations or any(row["disposition"] is not None for row in reservations):
                raise _StoreCorrupt("pending intent reservation mismatch")
            actual = raw["disposition"]
            if actual == "RELEASED":
                attempted, verified = self._no_effect_record(intent, evidence, raw["observed_at"])
                if verified:
                    terminal_record = attempted
                else:
                    actual = "QUARANTINED_ESCROW"
                    terminal_record = {
                        "record_type": "QUARANTINED_ESCROW",
                        "reason": DurableReason.NO_EFFECT_UNVERIFIED.value,
                        "transaction_id": intent["transaction_id"],
                        "intent_digest": intent["intent_digest"],
                        "fencing_epoch": intent["fencing_epoch"],
                        "observed_at": raw["observed_at"],
                        "attempted_no_effect_record_digest": canonical_digest(attempted),
                    }
            else:
                terminal_record = {
                    "record_type": actual,
                    "transaction_id": intent["transaction_id"],
                    "intent_digest": intent["intent_digest"],
                    "fencing_epoch": intent["fencing_epoch"],
                    "observed_at": raw["observed_at"],
                    "evidence_digest": evidence["evidence_digest"],
                }
            terminal_text = _canonical_text(terminal_record)
            terminal_digest = canonical_digest(terminal_record)
            for reservation in reservations:
                key = (
                    reservation["name"],
                    reservation["unit"],
                    reservation["scope_digest"],
                    reservation["lineage_root"],
                )
                if actual == "SPENT":
                    cursor = connection.execute(
                        """
                        UPDATE budgets SET reserved=reserved-?, spent=spent+?
                        WHERE name=? AND unit=? AND scope_digest=? AND lineage_root=?
                          AND reserved>=? AND spent<=?
                        """,
                        (
                            reservation["amount"],
                            reservation["amount"],
                            *key,
                            reservation["amount"],
                            _MAX_INTEGER - reservation["amount"],
                        ),
                    )
                    if cursor.rowcount != 1:
                        raise _StoreCorrupt("spend conservation failure")
                elif actual == "RELEASED":
                    cursor = connection.execute(
                        """
                        UPDATE budgets SET reserved=reserved-?, remaining=remaining+?
                        WHERE name=? AND unit=? AND scope_digest=? AND lineage_root=?
                          AND reserved>=? AND remaining<=?
                        """,
                        (
                            reservation["amount"],
                            reservation["amount"],
                            *key,
                            reservation["amount"],
                            _MAX_INTEGER - reservation["amount"],
                        ),
                    )
                    if cursor.rowcount != 1:
                        raise _StoreCorrupt("release conservation failure")
            updated = connection.execute(
                """
                UPDATE budget_reservations
                SET disposition=?, terminal_record_json=?, terminal_record_digest=?
                WHERE transaction_id=? AND disposition IS NULL
                """,
                (actual, terminal_text, terminal_digest, raw["transaction_id"]),
            )
            if updated.rowcount != len(reservations):
                raise _StoreCorrupt("terminal reservation update mismatch")
            changed = connection.execute(
                "UPDATE dispatch_intents SET state=? WHERE transaction_id=? AND state='PENDING'",
                (actual, raw["transaction_id"]),
            )
            if changed.rowcount != 1:
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.ILLEGAL_TRANSITION)
            sequence = self._append_event(
                connection,
                "BUDGET_TERMINAL_" + actual,
                raw["transaction_id"],
                {
                    "transaction_id": raw["transaction_id"],
                    "intent_digest": intent["intent_digest"],
                    "disposition": actual,
                    "terminal_record_digest": terminal_digest,
                    "fencing_epoch": intent["fencing_epoch"],
                },
            )
            self._hit("after_event")
            connection.commit()
            connection.close()
            connection = None
            try:
                self._hit("after_commit_before_ack")
            except Exception:
                return _result(DurableOutcome.STOP, DurableReason.ACKNOWLEDGEMENT_UNKNOWN)
            return DurableResult(
                DurableOutcome.COMMITTED,
                DurableReason(actual),
                transaction_id=raw["transaction_id"],
                journal_sequence=sequence,
            )
        except _StoreCorrupt:
            if connection is not None:
                connection.rollback()
            return self._mark_corrupt()
        except sqlite3.OperationalError as error:
            if connection is not None:
                connection.rollback()
            if "locked" in str(error).lower() or "busy" in str(error).lower():
                return _result(DurableOutcome.STOP, DurableReason.STORE_BUSY)
            return self._mark_corrupt()
        except Exception:
            if connection is not None:
                connection.rollback()
            return _result(DurableOutcome.STOP, DurableReason.INTERNAL_ERROR)
        finally:
            if connection is not None:
                connection.close()

    def recover(self) -> DurableResult:
        """Return durable pending/quarantined intent state without dispatch or retry."""

        if not self._usable:
            return _result(DurableOutcome.STOP, self._stopped_reason)
        try:
            connection = self._connect()
            try:
                self._audit(connection)
                rows = connection.execute(
                    """
                    SELECT transaction_id, capability_id, intent_digest,
                           idempotency_key_digest, state, fencing_epoch
                    FROM dispatch_intents
                    WHERE state IN ('PENDING', 'QUARANTINED_ESCROW')
                    ORDER BY dispatch_counter
                    """
                ).fetchall()
                intents = tuple(
                    RecoveryIntent(
                        row["transaction_id"],
                        row["capability_id"],
                        row["intent_digest"],
                        row["idempotency_key_digest"],
                        row["state"],
                        row["fencing_epoch"],
                    )
                    for row in rows
                )
            finally:
                connection.close()
            return DurableResult(
                DurableOutcome.OK,
                DurableReason.RECOVERED,
                recovery_intents=intents,
            )
        except sqlite3.OperationalError as error:
            if "locked" in str(error).lower() or "busy" in str(error).lower():
                return _result(DurableOutcome.STOP, DurableReason.STORE_BUSY)
            return self._mark_corrupt()
        except Exception:
            return self._mark_corrupt()
