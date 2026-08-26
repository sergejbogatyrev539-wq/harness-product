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
STORE_SCHEMA_VERSION = 4
_APPLICATION_ID = 0x48524E53
_MAX_INTEGER = (1 << 63) - 1
_MAX_VECTOR = 256
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_BUDGET_NAME = re.compile(r"^[a-z][a-z0-9._/-]{0,127}$")
_UTC_TIME = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_TABLES_V3 = frozenset(
    {
        "budget_reservations",
        "budgets",
        "capabilities",
        "dispatch_attempt_claims",
        "dispatch_intents",
        "execution_sessions",
        "journal_entries",
        "outbox_events",
        "store_meta",
    }
)
_TABLES = _TABLES_V3 | frozenset(
    {"active_contracts", "d2_frontiers", "m4_transactions", "m4_transition_records"}
)
_D2_CLASSES = (
    "PLAN",
    "PROMPT",
    "CONTEXT",
    "CANDIDATE",
    "REUSABLE_BRANCH",
    "TOOL_BINDING",
    "CAPABILITY",
    "BUDGET_RESERVATION",
    "LOCK",
    "TARGET_BINDING",
    "DISPATCH_INTENT",
    "EXTERNAL_AUTHORIZATION",
    "STAGED_OUTPUT",
    "PERSISTED_STATE",
    "CONTROLLER_TOKEN",
)
_M4_STATES = (
    "DISPATCHED",
    "STAGED",
    "QUIESCED",
    "SEALED",
    "POSTCHECKED",
    "COMMITTED",
    "JOINED",
    "DISCARDED",
    "QUARANTINED",
    "RECONCILING",
)
_M4_NEXT = {
    "DISPATCHED": frozenset({"STAGED", "QUARANTINED"}),
    "STAGED": frozenset({"QUIESCED", "QUARANTINED"}),
    "QUIESCED": frozenset({"SEALED", "QUARANTINED"}),
    "SEALED": frozenset({"POSTCHECKED", "DISCARDED", "QUARANTINED"}),
    "POSTCHECKED": frozenset({"COMMITTED", "DISCARDED", "QUARANTINED"}),
    "COMMITTED": frozenset({"JOINED", "RECONCILING"}),
    "QUARANTINED": frozenset({"RECONCILING"}),
}
_M4_TERMINAL = frozenset({"JOINED", "DISCARDED", "RECONCILING"})
_M4_VERIFICATION_SOURCE_KEYS = frozenset({"verifier_id", "issuer_id", "key_id", "proof"})
_ACTIVE_CONTRACT_KEYS = frozenset(
    {
        "contract_version",
        "authority_domain_id",
        "journal_lineage_id",
        "root_contract_digest",
        "parent_contract_digest",
        "contract_digest",
        "lineage_root",
        "authority_digest",
        "profile_digest",
        "operation_kind",
        "external_branch",
        "max_iterations",
        "joined_iteration",
        "postcheck_required",
        "independent_observer_required",
        "budget_vector",
        "issued_at",
        "expires_at",
        "revocation_epoch",
        "fencing_epoch",
    }
)
_D2_ARTIFACT_KEYS = frozenset({"artifact_id", "artifact_digest", "iteration"})
_D2_FRONTIER_KEYS = frozenset(
    {
        "frontier_version",
        "contract_digest",
        "contract_version",
        "authority_domain_id",
        "journal_lineage_id",
        "root_contract_digest",
        "parent_contract_digest",
        "journal_sequence",
        "joined_iteration",
        "iteration",
        "fencing_epoch",
        "issued_at",
        "expires_at",
        "inventory",
        "frontier_record_digest",
    }
)
_PATH_BINDING_KEYS = frozenset(
    {
        "canonical_path",
        "descriptor_id",
        "root_id",
        "root_identity",
        "mount_id",
        "mount_identity",
        "resolution_epoch",
        "final_device",
        "final_inode",
        "final_type",
        "final_digest",
        "composite_binding_digest",
    }
)
_STAGE_RECORD_KEYS = frozenset(
    {
        "transaction_id",
        "claim_digest",
        "binding_digest",
        "before_digest",
        "after_digest",
        "bytes_written",
        "record_digest",
    }
)
_M4_EVIDENCE_KEYS = {
    "STAGED": frozenset(
        {"evidence_version", "stage_record", "source_object_binding", "staged_object_binding"}
    ),
    "QUIESCED": frozenset(
        {
            "evidence_version",
            "process_tree_id",
            "session_id",
            "writer_fencing_epoch",
            "revoked_writer_fds",
            "remaining_writer_fds",
            "writer_leases_revoked",
            "process_tree_quiesced",
            "evidence_digest",
        }
    ),
    "SEALED": frozenset(
        {
            "evidence_version",
            "seal_type",
            "source_object_binding",
            "snapshot_id",
            "snapshot_device",
            "snapshot_inode",
            "snapshot_size",
            "snapshot_digest",
            "kernel_seals",
            "sealer_principal",
            "sealer_session",
            "evidence_digest",
        }
    ),
    "POSTCHECKED": frozenset(
        {
            "evidence_version",
            "seal_record_digest",
            "snapshot_id",
            "snapshot_device",
            "snapshot_inode",
            "snapshot_size",
            "snapshot_digest",
            "observer_principal",
            "observer_session",
            "observer_uid",
            "observer_gid",
            "observer_writer_fds",
            "outcome",
            "postcheck_digest",
            "evidence_digest",
        }
    ),
    "COMMITTED": frozenset(
        {
            "evidence_version",
            "seal_record_digest",
            "postcheck_record_digest",
            "snapshot_id",
            "snapshot_device",
            "snapshot_inode",
            "snapshot_size",
            "snapshot_digest",
            "object_binding",
            "committer_principal",
            "committer_session",
            "evidence_digest",
        }
    ),
    "JOINED": frozenset(
        {
            "evidence_version",
            "commit_record_digest",
            "joined_iteration",
            "frontier_record_digest",
            "controller_principal",
            "controller_session",
            "evidence_digest",
        }
    ),
    "DISCARDED": frozenset(
        {"evidence_version", "seal_record_digest", "disposition", "evidence_digest"}
    ),
    "QUARANTINED": frozenset(
        {"evidence_version", "uncertainty", "evidence_digest"}
    ),
    "RECONCILING": frozenset(
        {"evidence_version", "quarantine_record_digest", "evidence_digest"}
    ),
}
_M4_RECORD_KEYS = frozenset(
    {
        "record_version",
        "record_type",
        "state",
        "transaction_id",
        "transition_index",
        "contract_digest",
        "d2_frontier_digest",
        "iteration",
        "capability_id",
        "claim_digest",
        "intent_digest",
        "decision_digest",
        "authorized_envelope_digest",
        "lineage_root",
        "object_binding_digest",
        "budget_vector",
        "budget_vector_digest",
        "revocation_epoch",
        "fencing_epoch",
        "previous_record_digest",
        "observed_at",
        "contract",
        "frontier",
        "capability",
        "capability_verification",
        "claim",
        "claim_verification",
        "intent",
        "evidence",
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
_CLAIM_KEYS = frozenset(
    {
        "claim_version",
        "transaction_id",
        "capability_id",
        "intent_digest",
        "idempotency_key_digest",
        "principal_id",
        "audience_id",
        "purpose",
        "profile_digest",
        "placement_digest",
        "session_id",
        "lineage_root",
        "nonce",
        "revocation_epoch",
        "fencing_epoch",
        "observed_at",
        "target_scope_digest",
        "material_digest",
        "request",
        "decision",
        "authorized_envelope",
        "capability_payload",
        "capability_verification",
        "intent",
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
    DISPATCH_ATTEMPT_CLAIMED = "DISPATCH_ATTEMPT_CLAIMED"
    DISPATCH_CLAIM_VERIFIED = "DISPATCH_CLAIM_VERIFIED"
    RUNTIME_SESSION_PREPARED = "RUNTIME_SESSION_PREPARED"
    RUNTIME_SESSION_STOPPED = "RUNTIME_SESSION_STOPPED"
    RUNTIME_SESSION_TIMED_OUT = "RUNTIME_SESSION_TIMED_OUT"
    RUNTIME_SESSION_QUARANTINED = "RUNTIME_SESSION_QUARANTINED"
    ACTIVE_CONTRACT_BOUND = "ACTIVE_CONTRACT_BOUND"
    D2_FRONTIER_BOUND = "D2_FRONTIER_BOUND"
    M4_DISPATCH_BOUND = "M4_DISPATCH_BOUND"
    M4_STAGED = "M4_STAGED"
    M4_QUIESCED = "M4_QUIESCED"
    M4_SEALED = "M4_SEALED"
    M4_POSTCHECKED = "M4_POSTCHECKED"
    M4_COMMITTED = "M4_COMMITTED"
    M4_JOINED = "M4_JOINED"
    M4_DISCARDED = "M4_DISCARDED"
    M4_QUARANTINED = "M4_QUARANTINED"
    M4_RECONCILING = "M4_RECONCILING"
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
    UNKNOWN_INTENT = "UNKNOWN_INTENT"
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
    EXECUTOR_VERIFIER_ABSENT = "EXECUTOR_VERIFIER_ABSENT"
    RUNTIME_VERIFIER_ABSENT = "RUNTIME_VERIFIER_ABSENT"
    M4_VERIFIER_ABSENT = "M4_VERIFIER_ABSENT"
    CONTRACT_BINDING_MISMATCH = "CONTRACT_BINDING_MISMATCH"
    D2_INVENTORY_INVALID = "D2_INVENTORY_INVALID"
    M4_EVIDENCE_INVALID = "M4_EVIDENCE_INVALID"
    OBJECT_BINDING_MISMATCH = "OBJECT_BINDING_MISMATCH"
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


class ExecutorClaimVerifier(Protocol):
    def verify(
        self,
        payload: bytes,
        record: bytes,
        observed_at: str,
    ) -> VerificationResult: ...


class RuntimeSessionVerifier(Protocol):
    """External verifier boundary for an exact pre-exec runtime placement."""

    def verify(
        self,
        payload: bytes,
        record: bytes,
        observed_at: str,
    ) -> VerificationResult: ...


class M4Verifier(Protocol):
    """Shared external verifier boundary for contract, D2 and M4 records."""

    def verify(
        self,
        payload: bytes,
        record: bytes,
        observed_at: str,
    ) -> VerificationResult: ...


@dataclass(frozen=True, slots=True)
class DispatchClaim:
    transaction_id: str
    claim_digest: str
    intent_digest: str
    capability_id: str
    idempotency_key_digest: str
    principal_id: str
    audience_id: str
    purpose: str
    profile_digest: str
    placement_digest: str
    session_id: str
    lineage_root: str
    nonce: str
    revocation_epoch: int
    fencing_epoch: int
    observed_at: str
    target_scope_digest: str
    material_digest: str
    request_json: str
    decision_json: str
    authorized_envelope_json: str
    capability_payload_json: str
    capability_verification_json: str
    intent_json: str
    claim_json: str
    executor_verification_json: str


@dataclass(frozen=True, slots=True)
class RecoveryIntent:
    transaction_id: str
    capability_id: str
    intent_digest: str
    idempotency_key_digest: str
    state: str
    fencing_epoch: int


@dataclass(frozen=True, slots=True)
class RuntimeSession:
    session_record_id: str
    transaction_id: str
    claim_digest: str
    state: str
    profile_digest: str
    placement_digest: str
    executor_id: str
    session_id: str
    fencing_epoch: int
    prepared_at: str
    runtime_bindings_json: str
    runtime_verification_json: str


@dataclass(frozen=True, slots=True)
class RecoverySession:
    session_record_id: str
    transaction_id: str
    claim_digest: str
    state: str
    fencing_epoch: int


@dataclass(frozen=True, slots=True)
class M4Recovery:
    transaction_id: str
    state: str
    contract_digest: str
    d2_frontier_digest: str
    fencing_epoch: int
    resume_allowed: bool = False
    retry_allowed: bool = False


@dataclass(frozen=True, slots=True)
class DurableResult:
    outcome: DurableOutcome
    reason: DurableReason
    capability_id: str | None = None
    transaction_id: str | None = None
    journal_sequence: int | None = None
    recovery_intents: tuple[RecoveryIntent, ...] = ()
    dispatch_claim: DispatchClaim | None = None
    runtime_session: RuntimeSession | None = None
    recovery_sessions: tuple[RecoverySession, ...] = ()
    contract_digest: str | None = None
    d2_frontier_digest: str | None = None
    record_digest: str | None = None
    m4_state: str | None = None
    m4_recovery: tuple[M4Recovery, ...] = ()

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


_RUNTIME_BINDING_KEYS = frozenset(
    {
        "binding_version", "process", "namespaces", "cgroup", "mounts",
        "writable_scope", "broker_ipc", "fd_allowlist", "cleanup",
    }
)
_RUNTIME_PROCESS_KEYS = frozenset(
    {
        "session_record_id", "process_tree_id", "transaction_id", "claim_digest", "lineage_root", "session_id",
        "subject_instance_id", "worker_principal", "broker_principal", "executor_principal",
        "broker_session", "executor_session", "fencing_epoch", "revocation_epoch",
        "profile_digest", "measurement_digest", "supply_digest", "placement_digest",
        "runtime_digest",
    }
)
_RUNTIME_NAMESPACE_KEYS = frozenset(
    {
        "worker_principal", "worker_session", "uid", "gid", "security_label",
        "credential_namespace", "namespace_ids", "user_namespace_binding_digest",
    }
)
_RUNTIME_NAMESPACE_ID_KEYS = frozenset({"user", "mount", "pid", "ipc", "uts", "network", "cgroup"})
_RUNTIME_CGROUP_KEYS = frozenset(
    {"path", "controllers", "device_major", "device_minor", "delegated", "identity_digest"}
)
_RUNTIME_MOUNT_KEYS = frozenset(
    {"rootfs", "read_only_inputs", "worker_writable_mounts", "staging_visible_to_worker"}
)
_RUNTIME_DIRECTORY_KEYS = frozenset(
    {"kind", "descriptor", "descriptor_id", "device", "inode", "mount_id", "mode", "type"}
)
_RUNTIME_REGULAR_KEYS = _RUNTIME_DIRECTORY_KEYS | frozenset({"size", "bytes_digest"})
_RUNTIME_INPUT_KEYS = _RUNTIME_REGULAR_KEYS | frozenset({"mount_path"})
_RUNTIME_PIPE_KEYS = frozenset({"kind", "descriptor", "device", "inode", "type"})
_RUNTIME_USER_NAMESPACE_KEYS = frozenset(
    {
        "kind", "descriptor", "descriptor_id", "device", "inode", "identity",
        "uid_map", "gid_map", "setgroups", "max_user_namespaces", "type",
    }
)
_RUNTIME_WRITABLE_KEYS = frozenset(
    {"root_id", "root_identity", "mount_id", "mount_identity", "files", "inodes", "bytes"}
)
_RUNTIME_SOCKET_PEER_KEYS = frozenset({"pid", "uid", "gid"})
_RUNTIME_SOCKET_KEYS = frozenset(
    {
        "kind", "descriptor", "descriptor_id", "device", "inode", "cookie", "type",
        "family", "socket_type", "address_mode", "pass_credentials", "creation_peer",
    }
)
_RUNTIME_BROKER_KEYS = frozenset(
    {
        "kind", "endpoint_mode", "transport", "worker_endpoint", "broker_endpoint",
        "worker_principal", "broker_principal", "worker_session", "broker_session",
        "worker_security_label", "broker_security_label", "worker_socket_identity",
        "broker_socket_identity", "operation_id", "nonce", "fencing_epoch",
        "revocation_epoch", "issued_at", "expires_at", "sender_authentication",
        "message_binding_digest", "pair_binding_digest",
    }
)
_RUNTIME_CLEANUP_KEYS = frozenset(
    {"cleanup_id", "staging_root_id", "reuse_forbidden", "require_cgroup_empty", "quarantine_on_failure"}
)


def _valid_descriptor_row(value: object, keys: frozenset[str], kinds: frozenset[str]) -> bool:
    return (
        _closed_dict(value, keys)
        and type(value.get("kind")) is str
        and value.get("kind") in kinds
        and _bounded_integer(value.get("descriptor"))
        and _bounded_integer(value.get("device"))
        and _bounded_integer(value.get("inode"))
        and type(value.get("type")) is str
    )


def _valid_id_map(value: object, namespace_id: object) -> bool:
    if type(value) is not str or type(namespace_id) is not int or len(value) > 256 or not value.endswith("\n"):
        return False
    try:
        rows = [tuple(int(field) for field in line.split(" ")) for line in value.splitlines()]
    except (TypeError, ValueError):
        return False
    return (
        len(rows) == 2
        and all(len(row) == 3 and all(type(item) is int and 0 <= item <= _MAX_INTEGER for item in row) for row in rows)
        and rows[0][0] == 0
        and rows[1][0] == namespace_id
        and rows[0][1] >= 1
        and rows[1][1] >= 1
        and rows[0][1] != rows[1][1]
        and rows[0][2] == rows[1][2] == 1
    )


def _valid_socket_endpoint(value: object, kind: str, pass_credentials: bool) -> bool:
    return (
        _closed_dict(value, _RUNTIME_SOCKET_KEYS)
        and value.get("kind") == kind
        and _valid_identifier(value.get("descriptor_id"))
        and all(_bounded_integer(value.get(field)) for field in ("descriptor", "device", "inode", "cookie"))
        and value.get("type") == "SOCKET"
        and value.get("family") == "AF_UNIX"
        and value.get("socket_type") == "SOCK_SEQPACKET"
        and value.get("address_mode") == "ANONYMOUS_CONNECTED"
        and value.get("pass_credentials") is pass_credentials
        and _closed_dict(value.get("creation_peer"), _RUNTIME_SOCKET_PEER_KEYS)
        and all(_bounded_integer(value["creation_peer"].get(field)) for field in _RUNTIME_SOCKET_PEER_KEYS)
    )


def _valid_runtime_bindings(value: object) -> bool:
    """Accept one closed full runtime object inventory, never digest-only claims."""

    if not _closed_dict(value, _RUNTIME_BINDING_KEYS) or value.get("binding_version") != FORMAT_VERSION:
        return False
    process = value.get("process")
    namespaces = value.get("namespaces")
    cgroup = value.get("cgroup")
    mounts = value.get("mounts")
    writable = value.get("writable_scope")
    broker = value.get("broker_ipc")
    inventory = value.get("fd_allowlist")
    cleanup = value.get("cleanup")
    if (
        not _closed_dict(process, _RUNTIME_PROCESS_KEYS)
        or not all(
            _valid_identifier(process.get(field))
            for field in (
                "session_record_id", "process_tree_id", "transaction_id", "session_id", "subject_instance_id",
                "worker_principal", "broker_principal", "executor_principal", "broker_session",
                "executor_session",
            )
        )
        or not all(
            _valid_digest(process.get(field))
            for field in (
                "claim_digest", "lineage_root", "profile_digest", "measurement_digest",
                "supply_digest", "placement_digest", "runtime_digest",
            )
        )
        or not _bounded_integer(process.get("fencing_epoch"), 1)
        or not _bounded_integer(process.get("revocation_epoch"))
        or len({process["worker_principal"], process["broker_principal"], process["executor_principal"]}) != 3
        or len({process["session_id"], process["broker_session"], process["executor_session"]}) != 3
    ):
        return False
    if (
        not _closed_dict(namespaces, _RUNTIME_NAMESPACE_KEYS)
        or not _closed_dict(namespaces.get("namespace_ids"), _RUNTIME_NAMESPACE_ID_KEYS)
        or not all(_valid_identifier(namespaces.get(field)) for field in ("worker_principal", "worker_session", "security_label", "credential_namespace"))
        or not all(_bounded_integer(namespaces.get(field), 1) for field in ("uid", "gid"))
        or not all(_valid_identifier(item) for item in namespaces["namespace_ids"].values())
        or len(set(namespaces["namespace_ids"].values())) != len(_RUNTIME_NAMESPACE_ID_KEYS)
        or not _valid_digest(namespaces.get("user_namespace_binding_digest"))
    ):
        return False
    if (
        not _closed_dict(cgroup, _RUNTIME_CGROUP_KEYS)
        or type(cgroup.get("path")) is not str
        or not cgroup["path"].startswith("/")
        or type(cgroup.get("controllers")) is not list
        or cgroup["controllers"] != ["cpu", "io", "memory", "pids"]
        or cgroup.get("delegated") is not True
        or not all(_bounded_integer(cgroup.get(field)) for field in ("device_major", "device_minor"))
        or not _valid_digest(cgroup.get("identity_digest"))
    ):
        return False
    if (
        not _closed_dict(mounts, _RUNTIME_MOUNT_KEYS)
        or not _valid_descriptor_row(mounts.get("rootfs"), _RUNTIME_DIRECTORY_KEYS, frozenset({"ROOTFS"}))
        or mounts["rootfs"].get("type") != "DIRECTORY"
        or type(mounts.get("read_only_inputs")) is not list
        or len(mounts["read_only_inputs"]) > 16
        or any(
            not _valid_descriptor_row(row, _RUNTIME_INPUT_KEYS, frozenset({"READ_ONLY_INPUT"}))
            or not _valid_identifier(row.get("descriptor_id"))
            or not _valid_digest(row.get("bytes_digest"))
            or type(row.get("mount_path")) is not str
            for row in mounts["read_only_inputs"]
        )
        or mounts.get("worker_writable_mounts") != []
        or mounts.get("staging_visible_to_worker") is not False
    ):
        return False
    if (
        not _closed_dict(writable, _RUNTIME_WRITABLE_KEYS)
        or not all(_valid_identifier(writable.get(field)) for field in ("root_id", "mount_id"))
        or not all(_valid_digest(writable.get(field)) for field in ("root_identity", "mount_identity"))
        or not all(_bounded_integer(writable.get(field), 1) for field in ("files", "inodes", "bytes"))
    ):
        return False
    if not _closed_dict(broker, _RUNTIME_BROKER_KEYS):
        return False
    worker_socket = broker.get("worker_socket_identity")
    broker_socket = broker.get("broker_socket_identity")
    pair_preimage = {key: broker[key] for key in broker if key != "pair_binding_digest"}
    issued_at = _parse_time(broker.get("issued_at"))
    expires_at = _parse_time(broker.get("expires_at"))
    if (
        broker.get("kind") != "UNIX_CONNECTED_PAIR"
        or broker.get("endpoint_mode") != "UNIX_CONNECTED_PAIR"
        or broker.get("transport") != "UNIX_SEQPACKET"
        or broker.get("sender_authentication") != "SCM_CREDENTIALS_PLUS_ENDPOINT_HOLDER_ATTESTATION"
        or not all(
            _valid_identifier(broker.get(field))
            for field in (
                "worker_endpoint", "broker_endpoint", "worker_principal", "broker_principal",
                "worker_session", "broker_session", "worker_security_label", "broker_security_label",
                "operation_id", "nonce",
            )
        )
        or broker["worker_endpoint"] == broker["broker_endpoint"]
        or broker["worker_principal"] == broker["broker_principal"]
        or broker["worker_session"] == broker["broker_session"]
        or broker["worker_principal"] != process["worker_principal"]
        or broker["broker_principal"] != process["broker_principal"]
        or broker["worker_session"] != process["session_id"]
        or broker["broker_session"] != process["broker_session"]
        or broker["worker_security_label"] != namespaces["security_label"]
        or broker["fencing_epoch"] != process["fencing_epoch"]
        or broker["revocation_epoch"] != process["revocation_epoch"]
        or not _bounded_integer(broker.get("fencing_epoch"), 1)
        or not _bounded_integer(broker.get("revocation_epoch"))
        or issued_at is None
        or expires_at is None
        or issued_at >= expires_at
        or not _valid_digest(broker.get("message_binding_digest"))
        or not _valid_digest(broker.get("pair_binding_digest"))
        or canonical_digest(pair_preimage) != broker["pair_binding_digest"]
        or not _valid_socket_endpoint(worker_socket, "BROKER_IPC_WORKER_END", False)
        or not _valid_socket_endpoint(broker_socket, "BROKER_IPC_BROKER_END", True)
        or worker_socket["descriptor"] == broker_socket["descriptor"]
        or worker_socket["cookie"] == broker_socket["cookie"]
    ):
        return False
    if type(inventory) is not list or len(inventory) < 12 or len(inventory) > 28:
        return False
    descriptors: list[int] = []
    user_namespace: dict[str, object] | None = None
    by_kind: dict[str, dict[str, object]] = {}
    for row in inventory:
        if type(row) is not dict:
            return False
        kind = row.get("kind")
        if kind == "ROOTFS":
            valid = _valid_descriptor_row(row, _RUNTIME_DIRECTORY_KEYS, frozenset({kind}))
        elif kind == "BROKER_IPC_WORKER_END":
            valid = _valid_socket_endpoint(row, kind, False) and row == worker_socket
        elif kind == "BROKER_IPC_BROKER_END":
            valid = _valid_socket_endpoint(row, kind, True) and row == broker_socket
        elif kind == "READ_ONLY_INPUT":
            valid = _valid_descriptor_row(row, _RUNTIME_INPUT_KEYS, frozenset({kind})) and _valid_digest(row.get("bytes_digest"))
        elif kind in {"SECCOMP_PROFILE", "WORKER_TOOL"}:
            valid = _valid_descriptor_row(row, _RUNTIME_REGULAR_KEYS, frozenset({kind})) and _valid_digest(row.get("bytes_digest"))
        elif kind in {
            "START_GATE", "START_GATE_RELEASE", "WORKER_START_GATE", "WORKER_START_RELEASE",
            "STATUS_SOURCE", "STATUS_SINK",
        }:
            valid = _valid_descriptor_row(row, _RUNTIME_PIPE_KEYS, frozenset({kind})) and row.get("type") == "PIPE"
        elif kind == "USER_NAMESPACE":
            valid = (
                _valid_descriptor_row(row, _RUNTIME_USER_NAMESPACE_KEYS, frozenset({kind}))
                and row.get("type") == "NAMESPACE"
                and _valid_identifier(row.get("descriptor_id"))
                and row.get("identity") == f"user:[{row.get('inode')}]"
                and _valid_id_map(row.get("uid_map"), namespaces["uid"])
                and _valid_id_map(row.get("gid_map"), namespaces["gid"])
                and row.get("setgroups") == "deny"
                and type(row.get("max_user_namespaces")) is int
                and row.get("max_user_namespaces") == 0
            )
            user_namespace = row if valid else None
        else:
            valid = False
        if not valid:
            return False
        if kind != "READ_ONLY_INPUT":
            if kind in by_kind:
                return False
            by_kind[kind] = row
        descriptors.append(row["descriptor"])
    required_kinds = {
        "USER_NAMESPACE", "ROOTFS", "BROKER_IPC_WORKER_END", "BROKER_IPC_BROKER_END",
        "SECCOMP_PROFILE", "WORKER_TOOL",
        "START_GATE", "START_GATE_RELEASE", "WORKER_START_GATE", "WORKER_START_RELEASE",
        "STATUS_SOURCE", "STATUS_SINK",
    }
    pipe_pairs = (
        ("START_GATE", "START_GATE_RELEASE"),
        ("WORKER_START_GATE", "WORKER_START_RELEASE"),
        ("STATUS_SOURCE", "STATUS_SINK"),
    )
    if (
        len(set(descriptors)) != len(descriptors)
        or user_namespace is None
        or canonical_digest(user_namespace) != namespaces["user_namespace_binding_digest"]
        or set(by_kind) != required_kinds
        or any(by_kind[left]["inode"] != by_kind[right]["inode"] for left, right in pipe_pairs)
        or len({by_kind[left]["inode"] for left, _ in pipe_pairs}) != len(pipe_pairs)
    ):
        return False
    return (
        _closed_dict(cleanup, _RUNTIME_CLEANUP_KEYS)
        and _valid_identifier(cleanup.get("cleanup_id"))
        and _valid_identifier(cleanup.get("staging_root_id"))
        and cleanup.get("reuse_forbidden") is True
        and cleanup.get("require_cgroup_empty") is True
        and cleanup.get("quarantine_on_failure") is True
        and process["worker_principal"] == namespaces["worker_principal"]
        and process["session_id"] == namespaces["worker_session"]
        and writable["root_id"] == cleanup["staging_root_id"]
    )


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


def _valid_verification_source(value: object) -> bool:
    return (
        _closed_dict(value, _M4_VERIFICATION_SOURCE_KEYS)
        and all(_valid_identifier(value[field]) for field in ("verifier_id", "issuer_id", "key_id"))
        and _valid_proof(value["proof"])
    )


def _verification_for(
    payload: dict[str, object], source: dict[str, object]
) -> tuple[str, str, dict[str, object], str, str]:
    payload_text = _canonical_text(payload)
    payload_digest = canonical_digest(payload)
    verification = {
        "verification_version": FORMAT_VERSION,
        "verifier_id": source["verifier_id"],
        "issuer_id": source["issuer_id"],
        "key_id": source["key_id"],
        "payload_digest": payload_digest,
        "bindings": payload,
        "proof": source["proof"],
    }
    verification_text = _canonical_text(verification)
    return (
        payload_text,
        payload_digest,
        verification,
        verification_text,
        canonical_digest(verification),
    )


def _parse_active_contract(raw: object, observed_at: str) -> tuple[dict[str, object], tuple[_BudgetRow, ...]]:
    if not _closed_dict(raw, _ACTIVE_CONTRACT_KEYS):
        raise _Rejected(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
    if raw["contract_version"] != "1.0.0":
        raise _Rejected(DurableOutcome.STOP, DurableReason.UNKNOWN_INPUT)
    if not all(
        _valid_identifier(raw[field])
        for field in ("authority_domain_id", "journal_lineage_id")
    ):
        raise _Rejected(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
    if not all(
        _valid_digest(raw[field])
        for field in (
            "root_contract_digest",
            "contract_digest",
            "lineage_root",
            "authority_digest",
            "profile_digest",
        )
    ):
        raise _Rejected(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
    if raw["parent_contract_digest"] is not None and not _valid_digest(raw["parent_contract_digest"]):
        raise _Rejected(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
    if raw["operation_kind"] != "STAGEABLE_FILESYSTEM" or raw["external_branch"] != "DENY":
        raise _Rejected(DurableOutcome.DENY, DurableReason.CONTRACT_BINDING_MISMATCH)
    if raw["postcheck_required"] is not True or raw["independent_observer_required"] is not True:
        raise _Rejected(DurableOutcome.DENY, DurableReason.CONTRACT_BINDING_MISMATCH)
    if (
        not _bounded_integer(raw["max_iterations"], 1)
        or raw["joined_iteration"] != 0
    ):
        raise _Rejected(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
    issued = _parse_time(raw["issued_at"])
    expires = _parse_time(raw["expires_at"])
    observed = _parse_time(observed_at)
    if issued is None or expires is None or observed is None:
        raise _Rejected(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
    if not (issued <= observed < expires):
        raise _Rejected(DurableOutcome.DENY, DurableReason.EXPIRED)
    if not _bounded_integer(raw["revocation_epoch"]) or not _bounded_integer(raw["fencing_epoch"]):
        raise _Rejected(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
    budgets = _parse_budget_vector(
        raw["budget_vector"], amount_name="limit", expected_lineage=raw["lineage_root"]
    )
    if raw["budget_vector"] != [row.data("limit") for row in budgets]:
        raise _Rejected(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
    body = {key: raw[key] for key in raw if key != "contract_digest"}
    if canonical_digest(body) != raw["contract_digest"]:
        raise _Rejected(DurableOutcome.DENY, DurableReason.CONTRACT_BINDING_MISMATCH)
    return raw, budgets


def _valid_path_binding(value: object) -> bool:
    if not _closed_dict(value, _PATH_BINDING_KEYS):
        return False
    path = value["canonical_path"]
    if (
        type(path) is not str
        or not path.startswith("/")
        or path == "/"
        or "\x00" in path
        or "\\" in path
        or "//" in path
        or any(part in {"", ".", ".."} for part in path.split("/")[1:])
    ):
        return False
    if not all(_valid_identifier(value[field]) for field in ("descriptor_id", "root_id", "mount_id")):
        return False
    if not all(
        _valid_digest(value[field])
        for field in ("root_identity", "mount_identity", "final_digest", "composite_binding_digest")
    ):
        return False
    if (
        not _bounded_integer(value["resolution_epoch"], 1)
        or not _bounded_integer(value["final_device"])
        or not _bounded_integer(value["final_inode"], 1)
        or value["final_type"] != "REGULAR_FILE"
    ):
        return False
    body = {key: value[key] for key in value if key != "composite_binding_digest"}
    return canonical_digest(body) == value["composite_binding_digest"]


def _valid_stage_record(
    value: object,
    transaction_id: str,
    claim_digest: str,
    source: dict[str, object],
    staged: dict[str, object],
) -> bool:
    if not _closed_dict(value, _STAGE_RECORD_KEYS):
        return False
    if (
        value["transaction_id"] != transaction_id
        or value["claim_digest"] != claim_digest
        or value["binding_digest"] != source["composite_binding_digest"]
        or value["before_digest"] != source["final_digest"]
        or value["after_digest"] != staged["final_digest"]
        or not _bounded_integer(value["bytes_written"])
        or not _valid_digest(value["record_digest"])
    ):
        return False
    if any(
        source[field] != staged[field]
        for field in _PATH_BINDING_KEYS
        if field not in {"final_digest", "composite_binding_digest"}
    ):
        return False
    body = {key: value[key] for key in value if key != "record_digest"}
    return canonical_digest(body) == value["record_digest"]


def _same_snapshot(left: object, right: object) -> bool:
    fields = (
        "snapshot_id",
        "snapshot_device",
        "snapshot_inode",
        "snapshot_size",
        "snapshot_digest",
    )
    return type(left) is dict and type(right) is dict and all(left.get(key) == right.get(key) for key in fields)


def _m4_evidence_object_digest(
    state: str,
    evidence: object,
    transaction: sqlite3.Row,
    capability: dict[str, object],
    intent: dict[str, object],
    frontier: dict[str, object],
    prior: dict[str, tuple[str, dict[str, object]]],
) -> str | None:
    """Validate one closed stage record and return its continuing object binding."""

    if state not in _M4_EVIDENCE_KEYS or not _closed_dict(evidence, _M4_EVIDENCE_KEYS[state]):
        raise _Rejected(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
    if evidence["evidence_version"] != FORMAT_VERSION:
        raise _Rejected(DurableOutcome.STOP, DurableReason.UNKNOWN_INPUT)
    current = transaction["object_binding_digest"]
    if state == "STAGED":
        source = evidence["source_object_binding"]
        staged = evidence["staged_object_binding"]
        stage_record = evidence["stage_record"]
        if (
            not _valid_path_binding(source)
            or not _valid_path_binding(staged)
            or not _valid_stage_record(
                stage_record,
                transaction["transaction_id"],
                transaction["claim_digest"],
                source,
                staged,
            )
            or stage_record["after_digest"] != intent["material_digest"]
            or canonical_digest(
                {"kind": "PATH_EXACT", "value": staged["canonical_path"]}
            )
            != intent["target_scope_digest"]
        ):
            raise _Rejected(DurableOutcome.DENY, DurableReason.OBJECT_BINDING_MISMATCH)
        return staged["composite_binding_digest"]
    if state == "QUIESCED":
        if (
            current is None
            or not all(
                _valid_identifier(evidence[field])
                for field in ("process_tree_id", "session_id")
            )
            or evidence["session_id"] != capability["session_id"]
            or evidence["writer_fencing_epoch"] != transaction["fencing_epoch"]
            or type(evidence["revoked_writer_fds"]) is not list
            or not evidence["revoked_writer_fds"]
            or len(set(evidence["revoked_writer_fds"])) != len(evidence["revoked_writer_fds"])
            or not all(_bounded_integer(item) for item in evidence["revoked_writer_fds"])
            or evidence["remaining_writer_fds"] != []
            or evidence["writer_leases_revoked"] is not True
            or evidence["process_tree_quiesced"] is not True
            or not _valid_digest(evidence["evidence_digest"])
        ):
            raise _Rejected(DurableOutcome.DENY, DurableReason.M4_EVIDENCE_INVALID)
        return current
    if state == "SEALED":
        staged = evidence["source_object_binding"]
        if (
            current is None
            or not _valid_path_binding(staged)
            or staged["composite_binding_digest"] != current
            or evidence["seal_type"] != "LINUX_MEMFD"
            or not _valid_identifier(evidence["snapshot_id"])
            or not _bounded_integer(evidence["snapshot_device"])
            or not _bounded_integer(evidence["snapshot_inode"], 1)
            or not _bounded_integer(evidence["snapshot_size"])
            or evidence["snapshot_size"] != prior["STAGED"][1]["evidence"]["stage_record"]["bytes_written"]
            or evidence["snapshot_digest"] != staged["final_digest"]
            or evidence["kernel_seals"]
            != ["F_SEAL_GROW", "F_SEAL_SEAL", "F_SEAL_SHRINK", "F_SEAL_WRITE"]
            or not all(
                _valid_identifier(evidence[field])
                for field in ("sealer_principal", "sealer_session")
            )
            or evidence["sealer_principal"] in {capability["principal_id"], capability["audience_id"]}
            or evidence["sealer_session"] == capability["session_id"]
            or not _valid_digest(evidence["evidence_digest"])
        ):
            raise _Rejected(DurableOutcome.DENY, DurableReason.M4_EVIDENCE_INVALID)
        return current
    if state == "POSTCHECKED":
        sealed_digest, sealed = prior["SEALED"]
        sealed_evidence = sealed["evidence"]
        if (
            current is None
            or evidence["seal_record_digest"] != sealed_digest
            or not _same_snapshot(evidence, sealed_evidence)
            or not all(
                _valid_identifier(evidence[field])
                for field in ("observer_principal", "observer_session")
            )
            or evidence["observer_principal"]
            in {
                capability["principal_id"],
                capability["audience_id"],
                sealed_evidence["sealer_principal"],
            }
            or evidence["observer_session"]
            in {capability["session_id"], sealed_evidence["sealer_session"]}
            or not _bounded_integer(evidence["observer_uid"], 1)
            or not _bounded_integer(evidence["observer_gid"], 1)
            or evidence["observer_writer_fds"] != []
            or evidence["outcome"] != "PASS"
            or not _valid_digest(evidence["postcheck_digest"])
            or not _valid_digest(evidence["evidence_digest"])
        ):
            raise _Rejected(DurableOutcome.DENY, DurableReason.M4_EVIDENCE_INVALID)
        return current
    if state == "COMMITTED":
        seal_digest, sealed = prior["SEALED"]
        postcheck_digest, postchecked = prior["POSTCHECKED"]
        binding = evidence["object_binding"]
        if (
            current is None
            or evidence["seal_record_digest"] != seal_digest
            or evidence["postcheck_record_digest"] != postcheck_digest
            or not _same_snapshot(evidence, sealed["evidence"])
            or not _same_snapshot(evidence, postchecked["evidence"])
            or not _valid_path_binding(binding)
            or binding["composite_binding_digest"] != current
            or binding["final_digest"] != evidence["snapshot_digest"]
            or not all(
                _valid_identifier(evidence[field])
                for field in ("committer_principal", "committer_session")
            )
            or evidence["committer_principal"] in {capability["principal_id"], capability["audience_id"]}
            or evidence["committer_session"] == capability["session_id"]
            or not _valid_digest(evidence["evidence_digest"])
        ):
            raise _Rejected(DurableOutcome.DENY, DurableReason.M4_EVIDENCE_INVALID)
        return current
    if state == "JOINED":
        commit_digest, _ = prior["COMMITTED"]
        if (
            current is None
            or evidence["commit_record_digest"] != commit_digest
            or evidence["joined_iteration"] != transaction["iteration"]
            or evidence["frontier_record_digest"] != frontier["frontier_record_digest"]
            or not all(
                _valid_identifier(evidence[field])
                for field in ("controller_principal", "controller_session")
            )
            or evidence["controller_principal"] in {capability["principal_id"], capability["audience_id"]}
            or evidence["controller_session"] == capability["session_id"]
            or not _valid_digest(evidence["evidence_digest"])
        ):
            raise _Rejected(DurableOutcome.DENY, DurableReason.M4_EVIDENCE_INVALID)
        return current
    if state == "DISCARDED":
        if (
            "SEALED" not in prior
            or evidence["seal_record_digest"] != prior["SEALED"][0]
            or evidence["disposition"] != "NO_EFFECT_VERIFIED"
            or not _valid_digest(evidence["evidence_digest"])
        ):
            raise _Rejected(DurableOutcome.DENY, DurableReason.M4_EVIDENCE_INVALID)
        return current
    if state == "QUARANTINED":
        if not _valid_identifier(evidence["uncertainty"]) or not _valid_digest(evidence["evidence_digest"]):
            raise _Rejected(DurableOutcome.DENY, DurableReason.M4_EVIDENCE_INVALID)
        return current
    if state == "RECONCILING":
        if (
            evidence["quarantine_record_digest"] != transaction["current_record_digest"]
            or not _valid_digest(evidence["evidence_digest"])
        ):
            raise _Rejected(DurableOutcome.DENY, DurableReason.M4_EVIDENCE_INVALID)
        return current
    raise _Rejected(DurableOutcome.STOP, DurableReason.UNKNOWN_INPUT)


_SCHEMA_V3 = (
    """
    CREATE TABLE store_meta (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        schema_version INTEGER NOT NULL CHECK (schema_version = 3),
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
    CREATE TABLE dispatch_attempt_claims (
        transaction_id TEXT PRIMARY KEY REFERENCES dispatch_intents(transaction_id),
        claim_digest TEXT NOT NULL UNIQUE,
        intent_digest TEXT NOT NULL UNIQUE,
        capability_id TEXT NOT NULL UNIQUE REFERENCES capabilities(capability_id),
        audience_id TEXT NOT NULL,
        placement_digest TEXT NOT NULL,
        session_id TEXT NOT NULL,
        revocation_epoch INTEGER NOT NULL CHECK (revocation_epoch >= 0),
        fencing_epoch INTEGER NOT NULL CHECK (fencing_epoch >= 0),
        observed_at TEXT NOT NULL,
        claim_json TEXT NOT NULL,
        executor_verification_json TEXT NOT NULL,
        executor_verification_digest TEXT NOT NULL,
        journal_sequence INTEGER NOT NULL UNIQUE REFERENCES journal_entries(sequence)
            DEFERRABLE INITIALLY DEFERRED
    ) STRICT
    """,
    """
    CREATE TABLE execution_sessions (
        session_record_id TEXT PRIMARY KEY,
        transaction_id TEXT NOT NULL UNIQUE REFERENCES dispatch_attempt_claims(transaction_id),
        claim_digest TEXT NOT NULL UNIQUE,
        state TEXT NOT NULL CHECK (state IN ('PREPARED', 'STOPPED', 'TIMED_OUT', 'QUARANTINED')),
        profile_digest TEXT NOT NULL,
        placement_digest TEXT NOT NULL,
        executor_id TEXT NOT NULL,
        session_id TEXT NOT NULL,
        fencing_epoch INTEGER NOT NULL CHECK (fencing_epoch >= 0),
        prepared_at TEXT NOT NULL,
        runtime_bindings_json TEXT NOT NULL,
        runtime_bindings_digest TEXT NOT NULL,
        runtime_verification_json TEXT NOT NULL,
        runtime_verification_digest TEXT NOT NULL,
        prepared_journal_sequence INTEGER NOT NULL UNIQUE REFERENCES journal_entries(sequence)
            DEFERRABLE INITIALLY DEFERRED,
        terminal_at TEXT,
        terminal_reason TEXT,
        terminal_journal_sequence INTEGER UNIQUE REFERENCES journal_entries(sequence)
            DEFERRABLE INITIALLY DEFERRED,
        CHECK ((state = 'PREPARED' AND terminal_at IS NULL AND terminal_reason IS NULL
                AND terminal_journal_sequence IS NULL)
            OR (state IN ('STOPPED', 'TIMED_OUT', 'QUARANTINED')
                AND terminal_at IS NOT NULL AND terminal_reason IS NOT NULL
                AND terminal_journal_sequence IS NOT NULL))
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

_M4_SCHEMA = (
    """
    CREATE TABLE active_contracts (
        contract_digest TEXT PRIMARY KEY,
        authority_domain_id TEXT NOT NULL,
        journal_lineage_id TEXT NOT NULL,
        root_contract_digest TEXT NOT NULL,
        parent_contract_digest TEXT,
        lineage_root TEXT NOT NULL,
        max_iterations INTEGER NOT NULL CHECK (max_iterations > 0),
        joined_iteration INTEGER NOT NULL CHECK (joined_iteration >= 0),
        contract_json TEXT NOT NULL,
        resolver_verification_json TEXT NOT NULL,
        resolver_verification_digest TEXT NOT NULL,
        activated_at TEXT NOT NULL,
        revocation_epoch INTEGER NOT NULL CHECK (revocation_epoch >= 0),
        fencing_epoch INTEGER NOT NULL CHECK (fencing_epoch >= 0),
        journal_sequence INTEGER NOT NULL UNIQUE REFERENCES journal_entries(sequence)
            DEFERRABLE INITIALLY DEFERRED,
        UNIQUE (authority_domain_id, root_contract_digest, journal_lineage_id),
        CHECK (joined_iteration <= max_iterations)
    ) STRICT
    """,
    """
    CREATE TABLE d2_frontiers (
        d2_frontier_digest TEXT PRIMARY KEY,
        transaction_id TEXT NOT NULL UNIQUE REFERENCES dispatch_attempt_claims(transaction_id),
        contract_digest TEXT NOT NULL REFERENCES active_contracts(contract_digest),
        iteration INTEGER NOT NULL CHECK (iteration > 0),
        joined_iteration INTEGER NOT NULL CHECK (joined_iteration >= 0),
        source_journal_sequence INTEGER NOT NULL CHECK (source_journal_sequence > 0),
        fencing_epoch INTEGER NOT NULL CHECK (fencing_epoch >= 0),
        inventory_json TEXT NOT NULL,
        frontier_json TEXT NOT NULL,
        verification_json TEXT NOT NULL,
        verification_digest TEXT NOT NULL,
        bound_at TEXT NOT NULL,
        event_journal_sequence INTEGER NOT NULL UNIQUE REFERENCES journal_entries(sequence)
            DEFERRABLE INITIALLY DEFERRED,
        UNIQUE (contract_digest, iteration),
        CHECK (iteration = joined_iteration + 1)
    ) STRICT
    """,
    """
    CREATE TABLE m4_transactions (
        transaction_id TEXT PRIMARY KEY REFERENCES dispatch_attempt_claims(transaction_id),
        state TEXT NOT NULL CHECK (state IN (
            'DISPATCHED', 'STAGED', 'QUIESCED', 'SEALED', 'POSTCHECKED',
            'COMMITTED', 'JOINED', 'DISCARDED', 'QUARANTINED', 'RECONCILING'
        )),
        contract_digest TEXT NOT NULL REFERENCES active_contracts(contract_digest),
        d2_frontier_digest TEXT NOT NULL UNIQUE REFERENCES d2_frontiers(d2_frontier_digest),
        iteration INTEGER NOT NULL CHECK (iteration > 0),
        capability_id TEXT NOT NULL UNIQUE REFERENCES capabilities(capability_id),
        claim_digest TEXT NOT NULL UNIQUE,
        intent_digest TEXT NOT NULL UNIQUE,
        decision_digest TEXT NOT NULL,
        authorized_envelope_digest TEXT NOT NULL,
        lineage_root TEXT NOT NULL,
        object_binding_digest TEXT,
        revocation_epoch INTEGER NOT NULL CHECK (revocation_epoch >= 0),
        fencing_epoch INTEGER NOT NULL CHECK (fencing_epoch >= 0),
        budget_vector_json TEXT NOT NULL,
        budget_vector_digest TEXT NOT NULL,
        current_record_digest TEXT,
        started_at TEXT NOT NULL,
        started_journal_sequence INTEGER NOT NULL UNIQUE REFERENCES journal_entries(sequence)
            DEFERRABLE INITIALLY DEFERRED,
        CHECK ((state = 'DISPATCHED' AND object_binding_digest IS NULL
                AND current_record_digest IS NULL)
            OR state IN ('QUARANTINED', 'RECONCILING')
            OR (object_binding_digest IS NOT NULL AND current_record_digest IS NOT NULL))
    ) STRICT
    """,
    """
    CREATE TABLE m4_transition_records (
        transaction_id TEXT NOT NULL REFERENCES m4_transactions(transaction_id),
        transition_index INTEGER NOT NULL CHECK (transition_index > 0),
        state TEXT NOT NULL CHECK (state IN (
            'STAGED', 'QUIESCED', 'SEALED', 'POSTCHECKED', 'COMMITTED',
            'JOINED', 'DISCARDED', 'QUARANTINED', 'RECONCILING'
        )),
        previous_record_digest TEXT,
        record_digest TEXT NOT NULL UNIQUE,
        record_json TEXT NOT NULL,
        verification_json TEXT NOT NULL,
        verification_digest TEXT NOT NULL,
        observed_at TEXT NOT NULL,
        journal_sequence INTEGER NOT NULL UNIQUE REFERENCES journal_entries(sequence)
            DEFERRABLE INITIALLY DEFERRED,
        PRIMARY KEY (transaction_id, transition_index),
        UNIQUE (transaction_id, state),
        CHECK ((transition_index = 1 AND previous_record_digest IS NULL)
            OR (transition_index > 1 AND previous_record_digest IS NOT NULL))
    ) STRICT
    """,
    "CREATE INDEX m4_transactions_state ON m4_transactions(state)",
    "CREATE INDEX m4_frontiers_contract_iteration ON d2_frontiers(contract_digest, iteration)",
)

_SCHEMA = tuple(
    statement.replace("schema_version = 3", "schema_version = 4")
    for statement in _SCHEMA_V3
) + _M4_SCHEMA

_TABLES_V2 = _TABLES_V3 - {"execution_sessions"}
_TABLES_V1 = _TABLES_V2 - {"dispatch_attempt_claims"}
_SCHEMA_V2 = tuple(
    statement.replace("schema_version = 3", "schema_version = 2")
    for statement in _SCHEMA_V3
    if "execution_sessions" not in statement
)
_SCHEMA_V1 = tuple(
    statement.replace("schema_version = 2", "schema_version = 1")
    for statement in _SCHEMA_V2
    if "dispatch_attempt_claims" not in statement
)


class DurableStore:
    """One-lineage SQLite durability domain with no effect execution surface."""

    def __init__(
        self,
        path: str,
        verifier: CapabilityVerifier,
        *,
        no_effect_verifier: object | None = None,
        executor_claim_verifier: ExecutorClaimVerifier | None = None,
        runtime_session_verifier: RuntimeSessionVerifier | None = None,
        m4_verifier: M4Verifier | None = None,
        _fault: object | None = None,
    ) -> None:
        self._path = path if type(path) is str else ""
        self._verifier = verifier
        self._no_effect_verifier = no_effect_verifier
        self._executor_claim_verifier = executor_claim_verifier
        self._runtime_session_verifier = runtime_session_verifier
        self._m4_verifier = m4_verifier
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
                    (STORE_SCHEMA_VERSION,),
                )
                connection.execute(f"PRAGMA application_id={_APPLICATION_ID}")
                connection.execute(f"PRAGMA user_version={STORE_SCHEMA_VERSION}")
                connection.commit()
            except Exception:
                connection.rollback()
                raise
            return
        if version == 1 and application_id == _APPLICATION_ID and tables == _TABLES_V1:
            self._migrate_v1_to_v2(connection)
            self._migrate_v2_to_v3(connection)
            self._migrate_v3_to_v4(connection)
            return
        if version == 2 and application_id == _APPLICATION_ID and tables == _TABLES_V2:
            self._migrate_v2_to_v3(connection)
            self._migrate_v3_to_v4(connection)
            return
        if version == 3 and application_id == _APPLICATION_ID and tables == _TABLES_V3:
            self._migrate_v3_to_v4(connection)
            return
        if version != STORE_SCHEMA_VERSION or application_id != _APPLICATION_ID or tables != _TABLES:
            raise _StoreCorrupt("unknown durable store schema")

    def _migrate_v1_to_v2(self, connection: sqlite3.Connection) -> None:
        self._audit_legacy_v1(connection)
        connection.execute("BEGIN IMMEDIATE")
        try:
            self._audit_legacy_v1(connection)
            connection.execute("ALTER TABLE store_meta RENAME TO store_meta_v1")
            connection.execute(_SCHEMA_V2[0])
            connection.execute(
                """
                INSERT INTO store_meta
                SELECT id, ?, lineage_root, revocation_epoch, fencing_epoch,
                       dispatch_counter, journal_head_sequence, journal_head_digest,
                       outbox_head_sequence, outbox_head_digest
                FROM store_meta_v1
                """,
                (2,),
            )
            connection.execute("DROP TABLE store_meta_v1")
            claim_schema = next(statement for statement in _SCHEMA_V2 if "dispatch_attempt_claims" in statement)
            connection.execute(claim_schema)
            connection.execute("PRAGMA user_version=2")
            connection.commit()
        except Exception:
            connection.rollback()
            raise

    def _migrate_v2_to_v3(self, connection: sqlite3.Connection) -> None:
        """Add the pre-exec session table atomically after a v2 integrity audit."""

        self._audit_legacy_v2(connection)
        connection.execute("BEGIN IMMEDIATE")
        try:
            self._audit_legacy_v2(connection)
            connection.execute("ALTER TABLE store_meta RENAME TO store_meta_v2")
            connection.execute(_SCHEMA_V3[0])
            connection.execute(
                """
                INSERT INTO store_meta
                SELECT id, ?, lineage_root, revocation_epoch, fencing_epoch,
                       dispatch_counter, journal_head_sequence, journal_head_digest,
                       outbox_head_sequence, outbox_head_digest
                FROM store_meta_v2
                """,
                (3,),
            )
            connection.execute("DROP TABLE store_meta_v2")
            session_schema = next(statement for statement in _SCHEMA_V3 if "execution_sessions" in statement)
            connection.execute(session_schema)
            connection.execute("PRAGMA user_version=3")
            connection.commit()
        except Exception:
            connection.rollback()
            raise

    def _migrate_v3_to_v4(self, connection: sqlite3.Connection) -> None:
        """Add the M4 contract/frontier/lifecycle tables after a full v3 audit."""

        self._audit_legacy_v3(connection)
        connection.execute("BEGIN IMMEDIATE")
        try:
            self._audit_legacy_v3(connection)
            connection.execute("ALTER TABLE store_meta RENAME TO store_meta_v3")
            connection.execute(_SCHEMA[0])
            connection.execute(
                """
                INSERT INTO store_meta
                SELECT id, ?, lineage_root, revocation_epoch, fencing_epoch,
                       dispatch_counter, journal_head_sequence, journal_head_digest,
                       outbox_head_sequence, outbox_head_digest
                FROM store_meta_v3
                """,
                (STORE_SCHEMA_VERSION,),
            )
            connection.execute("DROP TABLE store_meta_v3")
            for statement in _M4_SCHEMA:
                connection.execute(statement)
            connection.execute(f"PRAGMA user_version={STORE_SCHEMA_VERSION}")
            connection.commit()
        except Exception:
            connection.rollback()
            raise

    def _audit_legacy_v1(self, connection: sqlite3.Connection) -> None:
        if connection.execute("PRAGMA user_version").fetchone()[0] != 1:
            raise _StoreCorrupt("legacy schema version mismatch")
        if connection.execute("PRAGMA application_id").fetchone()[0] != _APPLICATION_ID:
            raise _StoreCorrupt("legacy application id mismatch")
        self._audit_schema(connection, schema=_SCHEMA_V1, tables=_TABLES_V1)
        if tuple(connection.execute("PRAGMA quick_check").fetchone()) != ("ok",):
            raise _StoreCorrupt("legacy SQLite quick check failed")
        if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise _StoreCorrupt("legacy foreign key mismatch")
        meta_rows = connection.execute("SELECT * FROM store_meta").fetchall()
        if len(meta_rows) != 1 or meta_rows[0]["id"] != 1 or meta_rows[0]["schema_version"] != 1:
            raise _StoreCorrupt("invalid legacy metadata")
        meta = meta_rows[0]
        lineage = meta["lineage_root"]
        if lineage is not None and not _valid_digest(lineage):
            raise _StoreCorrupt("invalid legacy lineage")
        for field in (
            "revocation_epoch",
            "fencing_epoch",
            "dispatch_counter",
            "journal_head_sequence",
            "outbox_head_sequence",
        ):
            if not _bounded_integer(meta[field]):
                raise _StoreCorrupt("invalid legacy monotonic metadata")
        self._audit_budgets(connection, lineage)
        self._audit_chains(connection, meta)
        self._audit_history(connection, meta)
        self._audit_capabilities(connection, lineage)
        self._audit_dispatch(connection, meta)

    def _audit_legacy_v2(self, connection: sqlite3.Connection) -> None:
        if connection.execute("PRAGMA user_version").fetchone()[0] != 2:
            raise _StoreCorrupt("legacy v2 schema version mismatch")
        if connection.execute("PRAGMA application_id").fetchone()[0] != _APPLICATION_ID:
            raise _StoreCorrupt("legacy v2 application id mismatch")
        self._audit_schema(connection, schema=_SCHEMA_V2, tables=_TABLES_V2)
        if tuple(connection.execute("PRAGMA quick_check").fetchone()) != ("ok",):
            raise _StoreCorrupt("legacy v2 SQLite quick check failed")
        if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise _StoreCorrupt("legacy v2 foreign key mismatch")
        meta_rows = connection.execute("SELECT * FROM store_meta").fetchall()
        if len(meta_rows) != 1 or meta_rows[0]["id"] != 1 or meta_rows[0]["schema_version"] != 2:
            raise _StoreCorrupt("invalid legacy v2 metadata")
        meta = meta_rows[0]
        lineage = meta["lineage_root"]
        if lineage is not None and not _valid_digest(lineage):
            raise _StoreCorrupt("invalid legacy v2 lineage")
        for field in (
            "revocation_epoch", "fencing_epoch", "dispatch_counter",
            "journal_head_sequence", "outbox_head_sequence",
        ):
            if not _bounded_integer(meta[field]):
                raise _StoreCorrupt("invalid legacy v2 monotonic metadata")
        self._audit_budgets(connection, lineage)
        self._audit_chains(connection, meta)
        self._audit_history(connection, meta)
        self._audit_capabilities(connection, lineage)
        self._audit_dispatch(connection, meta)
        self._audit_claims(connection, meta)

    def _audit_legacy_v3(self, connection: sqlite3.Connection) -> None:
        if connection.execute("PRAGMA user_version").fetchone()[0] != 3:
            raise _StoreCorrupt("legacy v3 schema version mismatch")
        if connection.execute("PRAGMA application_id").fetchone()[0] != _APPLICATION_ID:
            raise _StoreCorrupt("legacy v3 application id mismatch")
        self._audit_schema(connection, schema=_SCHEMA_V3, tables=_TABLES_V3)
        if tuple(connection.execute("PRAGMA quick_check").fetchone()) != ("ok",):
            raise _StoreCorrupt("legacy v3 SQLite quick check failed")
        if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise _StoreCorrupt("legacy v3 foreign key mismatch")
        meta_rows = connection.execute("SELECT * FROM store_meta").fetchall()
        if len(meta_rows) != 1 or meta_rows[0]["id"] != 1 or meta_rows[0]["schema_version"] != 3:
            raise _StoreCorrupt("invalid legacy v3 metadata")
        meta = meta_rows[0]
        lineage = meta["lineage_root"]
        if lineage is not None and not _valid_digest(lineage):
            raise _StoreCorrupt("invalid legacy v3 lineage")
        for field in (
            "revocation_epoch", "fencing_epoch", "dispatch_counter",
            "journal_head_sequence", "outbox_head_sequence",
        ):
            if not _bounded_integer(meta[field]):
                raise _StoreCorrupt("invalid legacy v3 monotonic metadata")
        self._audit_budgets(connection, lineage)
        self._audit_chains(connection, meta)
        self._audit_history(connection, meta)
        self._audit_capabilities(connection, lineage)
        self._audit_dispatch(connection, meta)
        self._audit_claims(connection, meta)
        self._audit_sessions(connection, meta)

    def _audit(self, connection: sqlite3.Connection) -> None:
        if connection.execute("PRAGMA user_version").fetchone()[0] != STORE_SCHEMA_VERSION:
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
        if (
            len(meta_rows) != 1
            or meta_rows[0]["id"] != 1
            or meta_rows[0]["schema_version"] != STORE_SCHEMA_VERSION
        ):
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
        self._audit_claims(connection, meta)
        self._audit_sessions(connection, meta)
        self._audit_m4(connection, meta)

    def _audit_schema(
        self,
        connection: sqlite3.Connection,
        *,
        schema: tuple[str, ...] = _SCHEMA,
        tables: frozenset[str] = _TABLES,
    ) -> None:
        expected: dict[str, str] = {}
        for statement in schema:
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
            if row[1] in tables
        }
        if set(strict) != tables or any(value != 1 for value in strict.values()):
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
            "DISPATCH_ATTEMPT_CLAIMED",
            "RUNTIME_SESSION_PREPARED",
            "RUNTIME_SESSION_STOPPED",
            "RUNTIME_SESSION_TIMED_OUT",
            "RUNTIME_SESSION_QUARANTINED",
            "CAPABILITY_REVOKED",
            "FENCE_ADVANCED",
            "BUDGET_TERMINAL_SPENT",
            "BUDGET_TERMINAL_RELEASED",
            "BUDGET_TERMINAL_QUARANTINED_ESCROW",
            "ACTIVE_CONTRACT_BOUND",
            "D2_FRONTIER_BOUND",
            "M4_DISPATCH_BOUND",
            "M4_STAGED",
            "M4_QUIESCED",
            "M4_SEALED",
            "M4_POSTCHECKED",
            "M4_COMMITTED",
            "M4_JOINED",
            "M4_DISCARDED",
            "M4_QUARANTINED",
            "M4_RECONCILING",
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
            elif event_type in {
                "CAPABILITY_ISSUED",
                "CAPABILITY_CONSUMED_WITH_INTENT",
                "DISPATCH_ATTEMPT_CLAIMED",
                "RUNTIME_SESSION_PREPARED",
                "ACTIVE_CONTRACT_BOUND",
                "D2_FRONTIER_BOUND",
                "M4_DISPATCH_BOUND",
                "M4_STAGED",
                "M4_QUIESCED",
                "M4_SEALED",
                "M4_POSTCHECKED",
                "M4_COMMITTED",
                "M4_JOINED",
                "M4_DISCARDED",
                "M4_QUARANTINED",
                "M4_RECONCILING",
            }:
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
        if connection.execute("PRAGMA user_version").fetchone()[0] != STORE_SCHEMA_VERSION:
            return
        session_counts = {
            row["event_type"]: row["amount"]
            for row in connection.execute(
                "SELECT event_type, COUNT(*) AS amount FROM journal_entries "
                "WHERE event_type LIKE 'RUNTIME_SESSION_%' GROUP BY event_type"
            )
        }
        session_rows = connection.execute("SELECT state FROM execution_sessions").fetchall()
        if session_counts.get("RUNTIME_SESSION_PREPARED", 0) != len(session_rows):
            raise _StoreCorrupt("runtime session prepare cardinality mismatch")
        for state in ("STOPPED", "TIMED_OUT", "QUARANTINED"):
            if session_counts.get("RUNTIME_SESSION_" + state, 0) != sum(
                row["state"] == state for row in session_rows
            ):
                raise _StoreCorrupt("runtime session terminal cardinality mismatch")

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
        if disposition in {"SPENT", "RELEASED"} and _closed_dict(record, evidence_keys):
            return (
                record["record_type"] == disposition
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

    def _audit_claims(self, connection: sqlite3.Connection, meta: sqlite3.Row) -> None:
        rows = connection.execute("SELECT * FROM dispatch_attempt_claims").fetchall()
        for row in rows:
            claim = _json_value(row["claim_json"])
            verification = _json_value(row["executor_verification_json"])
            intent_row = connection.execute(
                "SELECT * FROM dispatch_intents WHERE transaction_id=?",
                (row["transaction_id"],),
            ).fetchone()
            capability = connection.execute(
                "SELECT * FROM capabilities WHERE capability_id=?",
                (row["capability_id"],),
            ).fetchone()
            if intent_row is None or capability is None:
                raise _StoreCorrupt("orphan dispatch claim")
            intent = _json_value(intent_row["intent_json"])
            request = _json_value(capability["request_json"])
            decision = _json_value(capability["decision_json"])
            envelope = _json_value(capability["authorized_envelope_json"])
            payload = _json_value(capability["payload_json"])
            capability_verification = _json_value(capability["verification_json"])
            if (
                not _closed_dict(claim, _CLAIM_KEYS)
                or not _closed_dict(verification, _VERIFICATION_RECORD_KEYS)
                or claim.get("claim_version") != FORMAT_VERSION
                or verification.get("verification_version") != FORMAT_VERSION
                or canonical_digest(claim) != row["claim_digest"]
                or canonical_digest(verification) != row["executor_verification_digest"]
                or verification.get("payload_digest") != row["claim_digest"]
                or verification.get("bindings") != claim
                or not all(
                    _valid_identifier(claim.get(field))
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
                    _valid_identifier(verification.get(field))
                    for field in ("verifier_id", "issuer_id", "key_id")
                )
                or not _valid_proof(verification.get("proof"))
                or not all(
                    _valid_digest(claim.get(field))
                    for field in (
                        "capability_id",
                        "intent_digest",
                        "idempotency_key_digest",
                        "profile_digest",
                        "placement_digest",
                        "lineage_root",
                        "target_scope_digest",
                        "material_digest",
                    )
                )
                or not _bounded_integer(claim.get("revocation_epoch"))
                or not _bounded_integer(claim.get("fencing_epoch"))
                or _parse_time(claim.get("observed_at")) is None
                or claim.get("principal_id") == claim.get("audience_id")
                or claim.get("intent") != intent
                or claim.get("request") != request
                or claim.get("decision") != decision
                or claim.get("authorized_envelope") != envelope
                or claim.get("capability_payload") != payload
                or claim.get("capability_verification") != capability_verification
            ):
                raise _StoreCorrupt("dispatch claim binding mismatch")
            claim_columns = {
                "transaction_id": "transaction_id",
                "capability_id": "capability_id",
                "intent_digest": "intent_digest",
                "audience_id": "audience_id",
                "placement_digest": "placement_digest",
                "session_id": "session_id",
                "revocation_epoch": "revocation_epoch",
                "fencing_epoch": "fencing_epoch",
                "observed_at": "observed_at",
            }
            if any(claim.get(claim_name) != row[column] for claim_name, column in claim_columns.items()):
                raise _StoreCorrupt("dispatch claim column mismatch")
            intent_bindings = {
                "transaction_id": "transaction_id",
                "capability_id": "capability_id",
                "idempotency_key_digest": "idempotency_key_digest",
                "principal_id": "principal_id",
                "audience_id": "audience_id",
                "purpose": "purpose",
                "profile_digest": "profile_digest",
                "placement_digest": "placement_digest",
                "session_id": "session_id",
                "lineage_root": "lineage_root",
                "nonce": "nonce",
                "revocation_epoch": "revocation_epoch",
                "fencing_epoch": "fencing_epoch",
                "target_scope_digest": "target_scope_digest",
                "material_digest": "material_digest",
            }
            if (
                intent_row["capability_id"] != capability["capability_id"]
                or claim.get("intent_digest") != intent_row["intent_digest"]
                or capability["state"] != "CONSUMED"
                or capability["consumed_transaction_id"] != row["transaction_id"]
                or row["journal_sequence"] <= intent_row["journal_sequence"]
                or any(claim.get(claim_name) != intent.get(intent_name) for claim_name, intent_name in intent_bindings.items())
            ):
                raise _StoreCorrupt("dispatch claim intent mismatch")
            event = connection.execute(
                "SELECT event_type, subject_id, payload_json FROM journal_entries WHERE sequence=?",
                (row["journal_sequence"],),
            ).fetchone()
            expected_event = {
                "transaction_id": row["transaction_id"],
                "capability_id": row["capability_id"],
                "intent_digest": row["intent_digest"],
                "claim_digest": row["claim_digest"],
                "executor_verification_digest": row["executor_verification_digest"],
                "audience_id": row["audience_id"],
                "placement_digest": row["placement_digest"],
                "session_id": row["session_id"],
                "revocation_epoch": row["revocation_epoch"],
                "fencing_epoch": row["fencing_epoch"],
                "claim": claim,
            }
            if (
                event is None
                or tuple(event[:2]) != ("DISPATCH_ATTEMPT_CLAIMED", row["transaction_id"])
                or _json_value(event["payload_json"]) != expected_event
                or connection.execute(
                    "SELECT COUNT(*) FROM journal_entries "
                    "WHERE event_type='DISPATCH_ATTEMPT_CLAIMED' AND subject_id=?",
                    (row["transaction_id"],),
                ).fetchone()[0]
                != 1
            ):
                raise _StoreCorrupt("dispatch claim event mismatch")
        event_count = connection.execute(
            "SELECT COUNT(*) FROM journal_entries WHERE event_type='DISPATCH_ATTEMPT_CLAIMED'"
        ).fetchone()[0]
        if event_count != len(rows) or len(rows) > meta["dispatch_counter"]:
            raise _StoreCorrupt("dispatch claim cardinality mismatch")

    def _audit_sessions(self, connection: sqlite3.Connection, meta: sqlite3.Row) -> None:
        rows = connection.execute("SELECT * FROM execution_sessions").fetchall()
        for row in rows:
            bindings = _json_value(row["runtime_bindings_json"])
            verification = _json_value(row["runtime_verification_json"])
            claim_row = connection.execute(
                "SELECT * FROM dispatch_attempt_claims WHERE transaction_id=?",
                (row["transaction_id"],),
            ).fetchone()
            if claim_row is None or not _valid_runtime_bindings(bindings):
                raise _StoreCorrupt("runtime session binding mismatch")
            claim = _json_value(claim_row["claim_json"])
            process = bindings["process"]
            payload = {
                "runtime_session_version": FORMAT_VERSION,
                "session_record_id": row["session_record_id"],
                "transaction_id": row["transaction_id"],
                "claim_digest": row["claim_digest"],
                "profile_digest": row["profile_digest"],
                "placement_digest": row["placement_digest"],
                "executor_id": row["executor_id"],
                "session_id": row["session_id"],
                "fencing_epoch": row["fencing_epoch"],
                "prepared_at": row["prepared_at"],
                "runtime_bindings": bindings,
                "claim": claim,
            }
            if (
                not _closed_dict(verification, _VERIFICATION_RECORD_KEYS)
                or verification.get("verification_version") != FORMAT_VERSION
                or canonical_digest(bindings) != row["runtime_bindings_digest"]
                or canonical_digest(verification) != row["runtime_verification_digest"]
                or verification.get("payload_digest") != canonical_digest(payload)
                or verification.get("bindings") != payload
                or not all(_valid_identifier(verification.get(field)) for field in ("verifier_id", "issuer_id", "key_id"))
                or not _valid_proof(verification.get("proof"))
                or row["claim_digest"] != claim_row["claim_digest"]
                or row["profile_digest"] != claim.get("profile_digest")
                or row["placement_digest"] != claim.get("placement_digest")
                or row["session_id"] != claim.get("session_id")
                or row["fencing_epoch"] != claim.get("fencing_epoch")
                or row["executor_id"] != claim.get("audience_id")
                or process.get("transaction_id") != row["transaction_id"]
                or process.get("session_record_id") != row["session_record_id"]
                or process.get("claim_digest") != row["claim_digest"]
                or process.get("lineage_root") != claim.get("lineage_root")
                or process.get("profile_digest") != row["profile_digest"]
                or process.get("placement_digest") != row["placement_digest"]
                or process.get("session_id") != row["session_id"]
                or process.get("fencing_epoch") != row["fencing_epoch"]
                or process.get("revocation_epoch") != claim.get("revocation_epoch")
                or process.get("executor_principal") != row["executor_id"]
                or process.get("worker_principal") != claim.get("principal_id")
                or _parse_time(row["prepared_at"]) is None
            ):
                raise _StoreCorrupt("runtime session record mismatch")
            event = connection.execute(
                "SELECT event_type, subject_id, payload_json FROM journal_entries WHERE sequence=?",
                (row["prepared_journal_sequence"],),
            ).fetchone()
            expected_prepare = {
                "session_record_id": row["session_record_id"],
                "transaction_id": row["transaction_id"],
                "claim_digest": row["claim_digest"],
                "revocation_epoch": claim["revocation_epoch"],
                "fencing_epoch": row["fencing_epoch"],
                "runtime_session": payload,
                "runtime_verification_digest": row["runtime_verification_digest"],
            }
            if (
                event is None or tuple(event[:2]) != ("RUNTIME_SESSION_PREPARED", row["session_record_id"])
                or _json_value(event["payload_json"]) != expected_prepare
            ):
                raise _StoreCorrupt("runtime session prepare event mismatch")
            if row["state"] == "PREPARED":
                continue
            if row["state"] not in {"STOPPED", "TIMED_OUT", "QUARANTINED"}:
                raise _StoreCorrupt("runtime session state mismatch")
            terminal_event = connection.execute(
                "SELECT event_type, subject_id, payload_json FROM journal_entries WHERE sequence=?",
                (row["terminal_journal_sequence"],),
            ).fetchone()
            expected_terminal = {
                "session_record_id": row["session_record_id"],
                "transaction_id": row["transaction_id"],
                "claim_digest": row["claim_digest"],
                "state": row["state"],
                "disposition": row["terminal_reason"],
                "observed_at": row["terminal_at"],
                "revocation_epoch": claim["revocation_epoch"],
                "fencing_epoch": row["fencing_epoch"],
            }
            if (
                _parse_time(row["terminal_at"]) is None
                or row["terminal_reason"] not in {"RELEASED", "QUARANTINED_ESCROW"}
                or terminal_event is None
                or tuple(terminal_event[:2]) != ("RUNTIME_SESSION_" + row["state"], row["session_record_id"])
                or _json_value(terminal_event["payload_json"]) != expected_terminal
            ):
                raise _StoreCorrupt("runtime session terminal event mismatch")
        if len(rows) > meta["dispatch_counter"]:
            raise _StoreCorrupt("runtime session cardinality mismatch")

    def _audit_m4(self, connection: sqlite3.Connection, meta: sqlite3.Row) -> None:
        contracts = connection.execute("SELECT * FROM active_contracts").fetchall()
        for row in contracts:
            contract = _json_value(row["contract_json"])
            verification = _json_value(row["resolver_verification_json"])
            if type(contract) is not dict or type(verification) is not dict:
                raise _StoreCorrupt("invalid M4 contract value")
            try:
                parsed, budgets = _parse_active_contract(contract, row["activated_at"])
            except _Rejected as error:
                raise _StoreCorrupt("invalid M4 contract") from error
            payload = {"record_type": "ACTIVE_CONTRACT", "contract": parsed}
            event = connection.execute(
                "SELECT event_type, subject_id, payload_json FROM journal_entries WHERE sequence=?",
                (row["journal_sequence"],),
            ).fetchone()
            expected_event = {
                "contract": contract,
                "resolver_verification_digest": row["resolver_verification_digest"],
                "observed_at": row["activated_at"],
                "revocation_epoch": row["revocation_epoch"],
                "fencing_epoch": row["fencing_epoch"],
            }
            if (
                not _closed_dict(verification, _VERIFICATION_RECORD_KEYS)
                or verification.get("verification_version") != FORMAT_VERSION
                or verification.get("bindings") != payload
                or verification.get("payload_digest") != canonical_digest(payload)
                or canonical_digest(verification) != row["resolver_verification_digest"]
                or contract["contract_digest"] != row["contract_digest"]
                or contract["authority_domain_id"] != row["authority_domain_id"]
                or contract["journal_lineage_id"] != row["journal_lineage_id"]
                or contract["root_contract_digest"] != row["root_contract_digest"]
                or contract["parent_contract_digest"] != row["parent_contract_digest"]
                or contract["lineage_root"] != row["lineage_root"]
                or contract["max_iterations"] != row["max_iterations"]
                or row["joined_iteration"] < contract["joined_iteration"]
                or row["joined_iteration"] > row["max_iterations"]
                or contract["revocation_epoch"] != row["revocation_epoch"]
                or contract["fencing_epoch"] != row["fencing_epoch"]
                or contract["budget_vector"] != [item.data("limit") for item in budgets]
                or event is None
                or tuple(event[:2]) != ("ACTIVE_CONTRACT_BOUND", row["contract_digest"])
                or _json_value(event["payload_json"]) != expected_event
            ):
                raise _StoreCorrupt("M4 contract binding mismatch")
        if connection.execute(
            "SELECT COUNT(*) FROM journal_entries WHERE event_type='ACTIVE_CONTRACT_BOUND'"
        ).fetchone()[0] != len(contracts):
            raise _StoreCorrupt("M4 contract event cardinality mismatch")
        frontiers = connection.execute("SELECT * FROM d2_frontiers").fetchall()
        for row in frontiers:
            frontier = _json_value(row["frontier_json"])
            inventory = _json_value(row["inventory_json"])
            verification = _json_value(row["verification_json"])
            if type(frontier) is not dict or type(inventory) is not dict or type(verification) is not dict:
                raise _StoreCorrupt("invalid M4 frontier value")
            contract = connection.execute(
                "SELECT * FROM active_contracts WHERE contract_digest=?", (row["contract_digest"],)
            ).fetchone()
            claim = connection.execute(
                "SELECT * FROM dispatch_attempt_claims WHERE transaction_id=?", (row["transaction_id"],)
            ).fetchone()
            if contract is None or claim is None:
                raise _StoreCorrupt("missing M4 frontier source")
            capability = connection.execute(
                "SELECT * FROM capabilities WHERE capability_id=?", (claim["capability_id"],)
            ).fetchone()
            if capability is None:
                raise _StoreCorrupt("missing M4 frontier capability")
            try:
                authoritative = self._authoritative_d2_inventory(
                    connection, row["transaction_id"], row["iteration"]
                )
            except _Rejected as error:
                raise _StoreCorrupt("invalid M4 frontier inventory") from error
            payload = self._d2_payload(connection, row["transaction_id"], frontier)
            preimage = {key: frontier[key] for key in frontier if key != "frontier_record_digest"}
            event = connection.execute(
                "SELECT event_type, subject_id, payload_json FROM journal_entries WHERE sequence=?",
                (row["event_journal_sequence"],),
            ).fetchone()
            expected_event = {
                "transaction_id": row["transaction_id"],
                "contract_digest": row["contract_digest"],
                "d2_frontier_digest": row["d2_frontier_digest"],
                "frontier_record_digest": frontier.get("frontier_record_digest"),
                "source_journal_sequence": row["source_journal_sequence"],
                "iteration": row["iteration"],
                "revocation_epoch": capability["revocation_epoch"],
                "fencing_epoch": row["fencing_epoch"],
                "verification_digest": row["verification_digest"],
                "observed_at": row["bound_at"],
            }
            if (
                not _closed_dict(frontier, _D2_FRONTIER_KEYS)
                or frontier["frontier_version"] != "1.0.0"
                or frontier["inventory"] != inventory
                or inventory != authoritative
                or canonical_digest(preimage) != frontier["frontier_record_digest"]
                or canonical_digest(frontier) != row["d2_frontier_digest"]
                or frontier["contract_digest"] != row["contract_digest"]
                or frontier["iteration"] != row["iteration"]
                or frontier["joined_iteration"] != row["joined_iteration"]
                or frontier["journal_sequence"] != row["source_journal_sequence"]
                or frontier["fencing_epoch"] != row["fencing_epoch"]
                or row["source_journal_sequence"] >= row["event_journal_sequence"]
                or not _closed_dict(verification, _VERIFICATION_RECORD_KEYS)
                or verification.get("bindings") != payload
                or verification.get("payload_digest") != canonical_digest(payload)
                or canonical_digest(verification) != row["verification_digest"]
                or event is None
                or tuple(event[:2]) != ("D2_FRONTIER_BOUND", row["transaction_id"])
                or _json_value(event["payload_json"]) != expected_event
            ):
                raise _StoreCorrupt("M4 frontier binding mismatch")
        if connection.execute(
            "SELECT COUNT(*) FROM journal_entries WHERE event_type='D2_FRONTIER_BOUND'"
        ).fetchone()[0] != len(frontiers):
            raise _StoreCorrupt("M4 frontier event cardinality mismatch")
        transactions = connection.execute("SELECT * FROM m4_transactions").fetchall()
        for row in transactions:
            frontier = connection.execute(
                "SELECT * FROM d2_frontiers WHERE d2_frontier_digest=?",
                (row["d2_frontier_digest"],),
            ).fetchone()
            claim = connection.execute(
                "SELECT * FROM dispatch_attempt_claims WHERE transaction_id=?",
                (row["transaction_id"],),
            ).fetchone()
            intent = connection.execute(
                "SELECT * FROM dispatch_intents WHERE transaction_id=?",
                (row["transaction_id"],),
            ).fetchone()
            capability = connection.execute(
                "SELECT * FROM capabilities WHERE capability_id=?", (row["capability_id"],)
            ).fetchone()
            if frontier is None or claim is None or intent is None or capability is None:
                raise _StoreCorrupt("missing M4 transaction source")
            budget_vector = _json_value(row["budget_vector_json"])
            reservations = [
                {
                    "name": item["name"],
                    "unit": item["unit"],
                    "scope_digest": item["scope_digest"],
                    "lineage_root": item["lineage_root"],
                    "amount": item["amount"],
                }
                for item in connection.execute(
                    "SELECT name, unit, scope_digest, lineage_root, amount FROM budget_reservations "
                    "WHERE transaction_id=? ORDER BY name, unit, scope_digest, lineage_root",
                    (row["transaction_id"],),
                )
            ]
            event = connection.execute(
                "SELECT event_type, subject_id, payload_json FROM journal_entries WHERE sequence=?",
                (row["started_journal_sequence"],),
            ).fetchone()
            expected_event = {
                "transaction_id": row["transaction_id"],
                "contract_digest": row["contract_digest"],
                "d2_frontier_digest": row["d2_frontier_digest"],
                "capability_id": row["capability_id"],
                "claim_digest": row["claim_digest"],
                "intent_digest": row["intent_digest"],
                "decision_digest": row["decision_digest"],
                "authorized_envelope_digest": row["authorized_envelope_digest"],
                "lineage_root": row["lineage_root"],
                "iteration": row["iteration"],
                "budget_vector": budget_vector,
                "budget_vector_digest": row["budget_vector_digest"],
                "revocation_epoch": row["revocation_epoch"],
                "fencing_epoch": row["fencing_epoch"],
                "observed_at": row["started_at"],
            }
            if (
                row["state"] not in _M4_STATES
                or row["contract_digest"] != frontier["contract_digest"]
                or row["iteration"] != frontier["iteration"]
                or row["capability_id"] != capability["capability_id"]
                or row["claim_digest"] != claim["claim_digest"]
                or row["intent_digest"] != intent["intent_digest"]
                or row["decision_digest"] != capability["decision_digest"]
                or row["authorized_envelope_digest"] != capability["authorized_envelope_digest"]
                or row["lineage_root"] != capability["lineage_root"]
                or row["revocation_epoch"] != capability["revocation_epoch"]
                or row["fencing_epoch"] != capability["fencing_epoch"]
                or budget_vector != reservations
                or canonical_digest(budget_vector) != row["budget_vector_digest"]
                or event is None
                or tuple(event[:2]) != ("M4_DISPATCH_BOUND", row["transaction_id"])
                or _json_value(event["payload_json"]) != expected_event
            ):
                raise _StoreCorrupt("M4 transaction binding mismatch")
            transitions = connection.execute(
                "SELECT * FROM m4_transition_records WHERE transaction_id=? ORDER BY transition_index",
                (row["transaction_id"],),
            ).fetchall()
            if row["state"] == "DISPATCHED":
                if transitions or row["object_binding_digest"] is not None or row["current_record_digest"] is not None:
                    raise _StoreCorrupt("M4 dispatched state mismatch")
                continue
            if not transitions:
                raise _StoreCorrupt("missing M4 transition")
            frontier_value = _json_value(frontier["frontier_json"])
            capability_value = _json_value(capability["payload_json"])
            capability_verification = _json_value(capability["verification_json"])
            claim_value = _json_value(claim["claim_json"])
            claim_verification = _json_value(claim["executor_verification_json"])
            intent_value = _json_value(intent["intent_json"])
            contract_row = connection.execute(
                "SELECT * FROM active_contracts WHERE contract_digest=?", (row["contract_digest"],)
            ).fetchone()
            if contract_row is None:
                raise _StoreCorrupt("missing M4 transaction contract")
            contract_value = _json_value(contract_row["contract_json"])
            if not all(
                type(value) is dict
                for value in (
                    frontier_value,
                    capability_value,
                    capability_verification,
                    claim_value,
                    claim_verification,
                    intent_value,
                    contract_value,
                )
            ):
                raise _StoreCorrupt("invalid M4 transaction source value")
            previous_state = "DISPATCHED"
            previous_digest: str | None = None
            previous_time = _parse_time(row["started_at"])
            current_object: str | None = None
            prior: dict[str, tuple[str, dict[str, object]]] = {}
            if previous_time is None:
                raise _StoreCorrupt("invalid M4 transaction start time")
            for expected_index, transition_row in enumerate(transitions, 1):
                record = _json_value(transition_row["record_json"])
                verification = _json_value(transition_row["verification_json"])
                observed = _parse_time(transition_row["observed_at"])
                state = transition_row["state"]
                event = connection.execute(
                    "SELECT event_type, subject_id, payload_json FROM journal_entries WHERE sequence=?",
                    (transition_row["journal_sequence"],),
                ).fetchone()
                audit_transaction = dict(row)
                audit_transaction["object_binding_digest"] = current_object
                audit_transaction["current_record_digest"] = previous_digest
                try:
                    expected_object = _m4_evidence_object_digest(
                        state,
                        record.get("evidence") if type(record) is dict else None,
                        audit_transaction,
                        capability_value,
                        intent_value,
                        frontier_value,
                        prior,
                    )
                except (KeyError, _Rejected) as error:
                    raise _StoreCorrupt("invalid M4 transition evidence") from error
                expected_event = {
                    "transaction_id": row["transaction_id"],
                    "state": state,
                    "record_digest": transition_row["record_digest"],
                    "verification_digest": transition_row["verification_digest"],
                    "object_binding_digest": expected_object,
                    "contract_digest": row["contract_digest"],
                    "d2_frontier_digest": row["d2_frontier_digest"],
                    "budget_vector_digest": row["budget_vector_digest"],
                    "revocation_epoch": row["revocation_epoch"],
                    "fencing_epoch": row["fencing_epoch"],
                    "observed_at": transition_row["observed_at"],
                }
                if (
                    not _closed_dict(record, _M4_RECORD_KEYS)
                    or record["record_version"] != FORMAT_VERSION
                    or record["record_type"] != "M4_TRANSITION"
                    or record["state"] != state
                    or state not in _M4_NEXT.get(previous_state, frozenset())
                    or transition_row["transition_index"] != expected_index
                    or record["transition_index"] != expected_index
                    or transition_row["previous_record_digest"] != previous_digest
                    or record["previous_record_digest"] != previous_digest
                    or observed is None
                    or observed < previous_time
                    or record["observed_at"] != transition_row["observed_at"]
                    or canonical_digest(record) != transition_row["record_digest"]
                    or not _closed_dict(verification, _VERIFICATION_RECORD_KEYS)
                    or verification.get("verification_version") != FORMAT_VERSION
                    or verification.get("bindings") != record
                    or verification.get("payload_digest") != transition_row["record_digest"]
                    or canonical_digest(verification) != transition_row["verification_digest"]
                    or record["transaction_id"] != row["transaction_id"]
                    or record["contract_digest"] != row["contract_digest"]
                    or record["d2_frontier_digest"] != row["d2_frontier_digest"]
                    or record["iteration"] != row["iteration"]
                    or record["capability_id"] != row["capability_id"]
                    or record["claim_digest"] != row["claim_digest"]
                    or record["intent_digest"] != row["intent_digest"]
                    or record["decision_digest"] != row["decision_digest"]
                    or record["authorized_envelope_digest"] != row["authorized_envelope_digest"]
                    or record["lineage_root"] != row["lineage_root"]
                    or record["object_binding_digest"] != expected_object
                    or record["budget_vector"] != budget_vector
                    or record["budget_vector_digest"] != row["budget_vector_digest"]
                    or record["revocation_epoch"] != row["revocation_epoch"]
                    or record["fencing_epoch"] != row["fencing_epoch"]
                    or record["contract"] != contract_value
                    or record["frontier"] != frontier_value
                    or record["capability"] != capability_value
                    or record["capability_verification"] != capability_verification
                    or record["claim"] != claim_value
                    or record["claim_verification"] != claim_verification
                    or record["intent"] != intent_value
                    or event is None
                    or tuple(event[:2]) != ("M4_" + state, row["transaction_id"])
                    or _json_value(event["payload_json"]) != expected_event
                ):
                    raise _StoreCorrupt("M4 transition binding mismatch")
                prior[state] = (transition_row["record_digest"], record)
                previous_state = state
                previous_digest = transition_row["record_digest"]
                previous_time = observed
                current_object = expected_object
            if (
                previous_state != row["state"]
                or previous_digest != row["current_record_digest"]
                or current_object != row["object_binding_digest"]
            ):
                raise _StoreCorrupt("M4 transaction head mismatch")
            state_event_count = connection.execute(
                "SELECT COUNT(*) FROM journal_entries WHERE subject_id=? AND event_type IN "
                "('M4_STAGED','M4_QUIESCED','M4_SEALED','M4_POSTCHECKED','M4_COMMITTED',"
                "'M4_JOINED','M4_DISCARDED','M4_QUARANTINED','M4_RECONCILING')",
                (row["transaction_id"],),
            ).fetchone()[0]
            if state_event_count != len(transitions):
                raise _StoreCorrupt("M4 transition event cardinality mismatch")
            dispositions = {
                item["disposition"]
                for item in connection.execute(
                    "SELECT disposition FROM budget_reservations WHERE transaction_id=?",
                    (row["transaction_id"],),
                )
            }
            expected_disposition = None
            if "COMMITTED" in prior:
                expected_disposition = "SPENT"
            elif "DISCARDED" in prior:
                expected_disposition = "RELEASED"
            elif "QUARANTINED" in prior:
                expected_disposition = "QUARANTINED_ESCROW"
            if expected_disposition is None:
                if dispositions != {None} or intent["state"] != "PENDING":
                    raise _StoreCorrupt("M4 pending budget mismatch")
            elif dispositions != {expected_disposition} or intent["state"] != expected_disposition:
                raise _StoreCorrupt("M4 terminal budget mismatch")
            if "JOINED" in prior and contract_row["joined_iteration"] != row["iteration"]:
                raise _StoreCorrupt("M4 JOIN contract mismatch")
        if connection.execute(
            "SELECT COUNT(*) FROM journal_entries WHERE event_type='M4_DISPATCH_BOUND'"
        ).fetchone()[0] != len(transactions):
            raise _StoreCorrupt("M4 dispatch event cardinality mismatch")
        transition_count = connection.execute("SELECT COUNT(*) FROM m4_transition_records").fetchone()[0]
        if transition_count != sum(
            connection.execute(
                "SELECT COUNT(*) FROM m4_transition_records WHERE transaction_id=?", (row["transaction_id"],)
            ).fetchone()[0]
            for row in transactions
        ):
            raise _StoreCorrupt("orphan M4 transition")

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

    def _m4_verification_is_valid(
        self,
        payload_text: str,
        payload_digest: str,
        verification: dict[str, object],
        verification_text: str,
        verification_digest: str,
        observed_at: str,
    ) -> bool:
        try:
            if self._m4_verifier is None:
                return False
            result = self._m4_verifier.verify(
                payload_text.encode("utf-8"), verification_text.encode("utf-8"), observed_at
            )
            return (
                type(result) is VerificationResult
                and result.status is VerificationStatus.VERIFIED
                and result.verifier_id == verification["verifier_id"]
                and result.payload_digest == payload_digest
                and result.record_digest == verification_digest
            )
        except Exception:
            return False

    def _load_verified_contract(
        self,
        connection: sqlite3.Connection,
        contract_digest: str,
        observed_at: str,
        capability_payload: dict[str, object] | None = None,
    ) -> tuple[sqlite3.Row, dict[str, object]] | None:
        row = connection.execute(
            "SELECT * FROM active_contracts WHERE contract_digest=?", (contract_digest,)
        ).fetchone()
        if row is None:
            return None
        contract = _json_value(row["contract_json"])
        verification = _json_value(row["resolver_verification_json"])
        if type(contract) is not dict or type(verification) is not dict:
            raise _StoreCorrupt("invalid active contract value")
        try:
            parsed, budget_rows = _parse_active_contract(contract, observed_at)
        except _Rejected:
            return None
        payload = {"record_type": "ACTIVE_CONTRACT", "contract": parsed}
        payload_text = _canonical_text(payload)
        payload_digest = canonical_digest(payload)
        if (
            not _closed_dict(verification, _VERIFICATION_RECORD_KEYS)
            or canonical_digest(verification) != row["resolver_verification_digest"]
            or verification.get("payload_digest") != payload_digest
            or verification.get("bindings") != payload
            or not self._m4_verification_is_valid(
                payload_text,
                payload_digest,
                verification,
                row["resolver_verification_json"],
                row["resolver_verification_digest"],
                observed_at,
            )
        ):
            return None
        meta = connection.execute("SELECT * FROM store_meta WHERE id=1").fetchone()
        if meta is None:
            raise _StoreCorrupt("missing metadata")
        durable_budgets = [
            {
                "name": item["name"],
                "unit": item["unit"],
                "scope_digest": item["scope_digest"],
                "lineage_root": item["lineage_root"],
                "limit": item["limit_amount"],
            }
            for item in connection.execute(
                "SELECT * FROM budgets ORDER BY name, unit, scope_digest, lineage_root"
            )
        ]
        if (
            contract["contract_digest"] != row["contract_digest"]
            or contract["authority_domain_id"] != row["authority_domain_id"]
            or contract["journal_lineage_id"] != row["journal_lineage_id"]
            or contract["root_contract_digest"] != row["root_contract_digest"]
            or contract["parent_contract_digest"] != row["parent_contract_digest"]
            or contract["lineage_root"] != row["lineage_root"]
            or contract["max_iterations"] != row["max_iterations"]
            or row["joined_iteration"] < contract["joined_iteration"]
            or row["joined_iteration"] > row["max_iterations"]
            or contract["revocation_epoch"] != row["revocation_epoch"]
            or contract["fencing_epoch"] != row["fencing_epoch"]
            or contract["lineage_root"] != meta["lineage_root"]
            or contract["revocation_epoch"] != meta["revocation_epoch"]
            or contract["fencing_epoch"] != meta["fencing_epoch"]
            or contract["budget_vector"] != durable_budgets
            or contract["budget_vector"] != [item.data("limit") for item in budget_rows]
        ):
            return None
        if capability_payload is not None:
            request = capability_payload.get("request")
            proposal = request.get("proposal") if type(request) is dict else None
            authority = proposal.get("authority") if type(proposal) is dict else None
            capability_budget = capability_payload.get("budget_vector")
            if type(capability_budget) is not list:
                return None
            try:
                demanded = _parse_budget_vector(
                    capability_budget,
                    amount_name="amount",
                    expected_lineage=contract["lineage_root"],
                )
            except _Rejected:
                return None
            limits = {item.key: item.amount for item in budget_rows}
            if (
                capability_payload.get("contract_digest") != contract["contract_digest"]
                or capability_payload.get("lineage_root") != contract["lineage_root"]
                or capability_payload.get("profile_digest") != contract["profile_digest"]
                or capability_payload.get("revocation_epoch") != contract["revocation_epoch"]
                or capability_payload.get("fencing_epoch") != contract["fencing_epoch"]
                or type(authority) is not dict
                or canonical_digest(authority) != contract["authority_digest"]
                or set(item.key for item in demanded) != set(limits)
                or any(item.amount > limits[item.key] for item in demanded)
            ):
                return None
        return row, contract

    def activate_m4_contract(self, raw: object) -> DurableResult:
        """Atomically resolve one externally verified stageable-only loop contract."""

        if not self._usable:
            return _result(DurableOutcome.STOP, self._stopped_reason)
        if self._m4_verifier is None:
            return _result(DurableOutcome.STOP, DurableReason.M4_VERIFIER_ABSENT)
        if not _closed_dict(raw, frozenset({"contract", "observed_at", "resolver_verification"})):
            return _result(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
        if _parse_time(raw["observed_at"]) is None or not _valid_verification_source(raw["resolver_verification"]):
            return _result(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
        try:
            contract, budget_rows = _parse_active_contract(raw["contract"], raw["observed_at"])
            payload = {"record_type": "ACTIVE_CONTRACT", "contract": contract}
            payload_text, payload_digest, verification, verification_text, verification_digest = _verification_for(
                payload, raw["resolver_verification"]
            )
        except _Rejected as rejection:
            return _result(rejection.outcome, rejection.reason)
        except Exception:
            return _result(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
        connection: sqlite3.Connection | None = None
        try:
            self._hit("m4_contract_before_transaction")
            connection = self._connect()
            connection.execute("BEGIN IMMEDIATE")
            self._hit("m4_contract_after_begin")
            self._audit(connection)
            meta = connection.execute("SELECT * FROM store_meta WHERE id=1").fetchone()
            if meta is None or meta["lineage_root"] is None:
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.NOT_BOOTSTRAPPED)
            if connection.execute(
                "SELECT 1 FROM active_contracts WHERE contract_digest=? OR "
                "(authority_domain_id=? AND root_contract_digest=? AND journal_lineage_id=?)",
                (
                    contract["contract_digest"],
                    contract["authority_domain_id"],
                    contract["root_contract_digest"],
                    contract["journal_lineage_id"],
                ),
            ).fetchone() is not None:
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.REPLAY)
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
            if (
                contract["lineage_root"] != meta["lineage_root"]
                or contract["revocation_epoch"] != meta["revocation_epoch"]
                or contract["fencing_epoch"] != meta["fencing_epoch"]
                or contract["budget_vector"] != durable_budgets
                or contract["budget_vector"] != [row.data("limit") for row in budget_rows]
            ):
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.CONTRACT_BINDING_MISMATCH)
            if not self._m4_verification_is_valid(
                payload_text,
                payload_digest,
                verification,
                verification_text,
                verification_digest,
                raw["observed_at"],
            ):
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.CONTRACT_BINDING_MISMATCH)
            sequence = self._append_event(
                connection,
                "ACTIVE_CONTRACT_BOUND",
                contract["contract_digest"],
                {
                    "contract": contract,
                    "resolver_verification_digest": verification_digest,
                    "observed_at": raw["observed_at"],
                    "revocation_epoch": contract["revocation_epoch"],
                    "fencing_epoch": contract["fencing_epoch"],
                },
            )
            connection.execute(
                """INSERT INTO active_contracts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    contract["contract_digest"],
                    contract["authority_domain_id"],
                    contract["journal_lineage_id"],
                    contract["root_contract_digest"],
                    contract["parent_contract_digest"],
                    contract["lineage_root"],
                    contract["max_iterations"],
                    contract["joined_iteration"],
                    _canonical_text(contract),
                    verification_text,
                    verification_digest,
                    raw["observed_at"],
                    contract["revocation_epoch"],
                    contract["fencing_epoch"],
                    sequence,
                ),
            )
            self._hit("m4_contract_after_event")
            connection.commit()
            connection.close()
            connection = None
            try:
                self._hit("m4_contract_after_commit_before_ack")
            except Exception:
                return _result(DurableOutcome.STOP, DurableReason.ACKNOWLEDGEMENT_UNKNOWN)
            return DurableResult(
                DurableOutcome.COMMITTED,
                DurableReason.ACTIVE_CONTRACT_BOUND,
                journal_sequence=sequence,
                contract_digest=contract["contract_digest"],
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

    def _authoritative_d2_inventory(
        self,
        connection: sqlite3.Connection,
        transaction_id: str,
        iteration: int,
    ) -> dict[str, list[dict[str, object]]]:
        intent_row = connection.execute(
            "SELECT * FROM dispatch_intents WHERE transaction_id=?", (transaction_id,)
        ).fetchone()
        claim_row = connection.execute(
            "SELECT * FROM dispatch_attempt_claims WHERE transaction_id=?", (transaction_id,)
        ).fetchone()
        if intent_row is None or claim_row is None:
            raise _Rejected(DurableOutcome.DENY, DurableReason.UNKNOWN_INTENT)
        capability = connection.execute(
            "SELECT * FROM capabilities WHERE capability_id=?", (intent_row["capability_id"],)
        ).fetchone()
        if capability is None:
            raise _StoreCorrupt("missing D2 capability")
        intent = _json_value(intent_row["intent_json"])
        payload = _json_value(capability["payload_json"])
        if type(intent) is not dict or type(payload) is not dict:
            raise _StoreCorrupt("invalid D2 source")
        reservations = connection.execute(
            "SELECT name, unit, scope_digest, lineage_root, amount FROM budget_reservations "
            "WHERE transaction_id=? ORDER BY name, unit, scope_digest, lineage_root",
            (transaction_id,),
        ).fetchall()
        values: dict[str, list[dict[str, object]]] = {name: [] for name in _D2_CLASSES}

        def artifact(artifact_id: str, artifact_digest: str) -> dict[str, object]:
            return {
                "artifact_id": artifact_id,
                "artifact_digest": artifact_digest,
                "iteration": iteration,
            }

        values["CAPABILITY"] = [artifact(capability["capability_id"], capability["capability_id"])]
        for reservation in reservations:
            row = {
                "name": reservation["name"],
                "unit": reservation["unit"],
                "scope_digest": reservation["scope_digest"],
                "lineage_root": reservation["lineage_root"],
                "amount": reservation["amount"],
            }
            digest = canonical_digest(row)
            values["BUDGET_RESERVATION"].append(artifact(digest, digest))
        values["TARGET_BINDING"] = [
            artifact("target/" + transaction_id, intent["target_scope_digest"])
        ]
        values["DISPATCH_INTENT"] = [artifact(transaction_id, intent_row["intent_digest"])]
        values["STAGED_OUTPUT"] = [
            artifact("staged-output/" + transaction_id, intent["material_digest"])
        ]
        frame = {
            "record_type": "M4_TRANSACTION_FRAME",
            "transaction_id": transaction_id,
            "contract_digest": capability["contract_digest"],
            "claim_digest": claim_row["claim_digest"],
            "fencing_epoch": capability["fencing_epoch"],
            "iteration": iteration,
        }
        values["PERSISTED_STATE"] = [
            artifact("m4-frame/" + transaction_id, canonical_digest(frame))
        ]
        values["CONTROLLER_TOKEN"] = [
            artifact("claim/" + transaction_id, claim_row["claim_digest"])
        ]
        return values

    def _d2_payload(
        self,
        connection: sqlite3.Connection,
        transaction_id: str,
        frontier: dict[str, object],
    ) -> dict[str, object]:
        intent_row = connection.execute(
            "SELECT * FROM dispatch_intents WHERE transaction_id=?", (transaction_id,)
        ).fetchone()
        claim_row = connection.execute(
            "SELECT * FROM dispatch_attempt_claims WHERE transaction_id=?", (transaction_id,)
        ).fetchone()
        contract_row = connection.execute(
            "SELECT * FROM active_contracts WHERE contract_digest=?", (frontier["contract_digest"],)
        ).fetchone()
        if intent_row is None or claim_row is None or contract_row is None:
            raise _StoreCorrupt("missing D2 payload source")
        capability = connection.execute(
            "SELECT * FROM capabilities WHERE capability_id=?", (intent_row["capability_id"],)
        ).fetchone()
        if capability is None:
            raise _StoreCorrupt("missing D2 payload capability")
        return {
            "record_type": "D2_FRONTIER",
            "contract": _json_value(contract_row["contract_json"]),
            "contract_resolver_verification": _json_value(contract_row["resolver_verification_json"]),
            "frontier": frontier,
            "capability": _json_value(capability["payload_json"]),
            "capability_verification": _json_value(capability["verification_json"]),
            "claim": _json_value(claim_row["claim_json"]),
            "claim_verification": _json_value(claim_row["executor_verification_json"]),
            "intent": _json_value(intent_row["intent_json"]),
        }

    def _load_verified_frontier(
        self,
        connection: sqlite3.Connection,
        d2_frontier_digest: str,
        observed_at: str,
    ) -> tuple[sqlite3.Row, dict[str, object]] | None:
        row = connection.execute(
            "SELECT * FROM d2_frontiers WHERE d2_frontier_digest=?", (d2_frontier_digest,)
        ).fetchone()
        if row is None:
            return None
        frontier = _json_value(row["frontier_json"])
        verification = _json_value(row["verification_json"])
        if type(frontier) is not dict or type(verification) is not dict:
            raise _StoreCorrupt("invalid D2 record")
        payload = self._d2_payload(connection, row["transaction_id"], frontier)
        payload_text = _canonical_text(payload)
        payload_digest = canonical_digest(payload)
        if (
            canonical_digest(frontier) != row["d2_frontier_digest"]
            or not _closed_dict(verification, _VERIFICATION_RECORD_KEYS)
            or verification.get("bindings") != payload
            or verification.get("payload_digest") != payload_digest
            or canonical_digest(verification) != row["verification_digest"]
            or not self._m4_verification_is_valid(
                payload_text,
                payload_digest,
                verification,
                row["verification_json"],
                row["verification_digest"],
                observed_at,
            )
        ):
            return None
        return row, frontier

    def bind_m4_frontier(self, raw: object) -> DurableResult:
        """Bind one complete controller-derived D2 frontier without creating an effect."""

        if not self._usable:
            return _result(DurableOutcome.STOP, self._stopped_reason)
        if self._m4_verifier is None:
            return _result(DurableOutcome.STOP, DurableReason.M4_VERIFIER_ABSENT)
        keys = frozenset({"transaction_id", "observed_at", "frontier", "frontier_verification"})
        if not _closed_dict(raw, keys):
            return _result(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
        if (
            not _valid_identifier(raw["transaction_id"])
            or _parse_time(raw["observed_at"]) is None
            or not _valid_verification_source(raw["frontier_verification"])
            or not _closed_dict(raw["frontier"], _D2_FRONTIER_KEYS)
        ):
            return _result(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
        frontier = raw["frontier"]
        if (
            frontier["frontier_version"] != "1.0.0"
            or not all(
                _valid_identifier(frontier[field])
                for field in ("authority_domain_id", "journal_lineage_id")
            )
            or not all(
                _valid_digest(frontier[field])
                for field in ("contract_digest", "root_contract_digest", "frontier_record_digest")
            )
            or (frontier["parent_contract_digest"] is not None and not _valid_digest(frontier["parent_contract_digest"]))
            or not all(
                _bounded_integer(frontier[field])
                for field in ("journal_sequence", "joined_iteration", "fencing_epoch")
            )
            or not _bounded_integer(frontier["iteration"], 1)
            or _parse_time(frontier["issued_at"]) is None
            or _parse_time(frontier["expires_at"]) is None
            or type(frontier["inventory"]) is not dict
            or frozenset(frontier["inventory"]) != frozenset(_D2_CLASSES)
        ):
            return _result(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
        try:
            preimage = {key: frontier[key] for key in frontier if key != "frontier_record_digest"}
            if canonical_digest(preimage) != frontier["frontier_record_digest"]:
                return _result(DurableOutcome.DENY, DurableReason.D2_INVENTORY_INVALID)
            for name in _D2_CLASSES:
                rows = frontier["inventory"][name]
                if type(rows) is not list or len(rows) > _MAX_VECTOR:
                    return _result(DurableOutcome.STOP, DurableReason.UNBOUNDED_INPUT)
                for item in rows:
                    if (
                        not _closed_dict(item, _D2_ARTIFACT_KEYS)
                        or not _valid_identifier(item["artifact_id"])
                        or not _valid_digest(item["artifact_digest"])
                        or not _bounded_integer(item["iteration"], 1)
                    ):
                        return _result(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
                if rows != sorted(rows, key=lambda item: (item["artifact_id"], item["artifact_digest"])):
                    return _result(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
                if len({item["artifact_id"] for item in rows}) != len(rows):
                    return _result(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
        except Exception:
            return _result(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
        connection: sqlite3.Connection | None = None
        try:
            self._hit("m4_frontier_before_transaction")
            connection = self._connect()
            connection.execute("BEGIN IMMEDIATE")
            self._hit("m4_frontier_after_begin")
            self._audit(connection)
            meta = connection.execute("SELECT * FROM store_meta WHERE id=1").fetchone()
            claim_row = connection.execute(
                "SELECT * FROM dispatch_attempt_claims WHERE transaction_id=?", (raw["transaction_id"],)
            ).fetchone()
            if meta is None:
                raise _StoreCorrupt("missing metadata")
            if claim_row is None:
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.UNKNOWN_INTENT)
            if connection.execute(
                "SELECT 1 FROM d2_frontiers WHERE transaction_id=? OR d2_frontier_digest=?",
                (raw["transaction_id"], canonical_digest(frontier)),
            ).fetchone() is not None:
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.REPLAY)
            intent_row = connection.execute(
                "SELECT * FROM dispatch_intents WHERE transaction_id=?", (raw["transaction_id"],)
            ).fetchone()
            capability = connection.execute(
                "SELECT * FROM capabilities WHERE capability_id=?",
                (claim_row["capability_id"],),
            ).fetchone()
            if intent_row is None or capability is None or intent_row["state"] != "PENDING":
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.ILLEGAL_TRANSITION)
            capability_payload = _json_value(capability["payload_json"])
            if type(capability_payload) is not dict:
                raise _StoreCorrupt("invalid D2 capability payload")
            contract_payload = dict(capability_payload)
            contract_payload["request"] = _json_value(capability["request_json"])
            loaded = self._load_verified_contract(
                connection, frontier["contract_digest"], raw["observed_at"], contract_payload
            )
            if loaded is None:
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.CONTRACT_BINDING_MISMATCH)
            contract_row, contract = loaded
            issued = _parse_time(frontier["issued_at"])
            expires = _parse_time(frontier["expires_at"])
            observed = _parse_time(raw["observed_at"])
            if issued is None or expires is None or observed is None or not (issued <= observed < expires):
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.EXPIRED)
            expected_inventory = self._authoritative_d2_inventory(
                connection, raw["transaction_id"], frontier["iteration"]
            )
            if (
                frontier["contract_version"] != contract["contract_version"]
                or frontier["authority_domain_id"] != contract["authority_domain_id"]
                or frontier["journal_lineage_id"] != contract["journal_lineage_id"]
                or frontier["root_contract_digest"] != contract["root_contract_digest"]
                or frontier["parent_contract_digest"] != contract["parent_contract_digest"]
                or frontier["journal_sequence"] != meta["journal_head_sequence"]
                or frontier["joined_iteration"] != contract_row["joined_iteration"]
                or frontier["iteration"] != contract_row["joined_iteration"] + 1
                or frontier["iteration"] > contract_row["max_iterations"]
                or frontier["fencing_epoch"] != meta["fencing_epoch"]
                or frontier["fencing_epoch"] != contract["fencing_epoch"]
                or frontier["inventory"] != expected_inventory
                or any(
                    item["iteration"] != frontier["iteration"]
                    for rows in frontier["inventory"].values()
                    for item in rows
                )
            ):
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.D2_INVENTORY_INVALID)
            payload = self._d2_payload(connection, raw["transaction_id"], frontier)
            payload_text, payload_digest, verification, verification_text, verification_digest = _verification_for(
                payload, raw["frontier_verification"]
            )
            if not self._m4_verification_is_valid(
                payload_text,
                payload_digest,
                verification,
                verification_text,
                verification_digest,
                raw["observed_at"],
            ):
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.D2_INVENTORY_INVALID)
            d2_digest = canonical_digest(frontier)
            sequence = self._append_event(
                connection,
                "D2_FRONTIER_BOUND",
                raw["transaction_id"],
                {
                    "transaction_id": raw["transaction_id"],
                    "contract_digest": frontier["contract_digest"],
                    "d2_frontier_digest": d2_digest,
                    "frontier_record_digest": frontier["frontier_record_digest"],
                    "source_journal_sequence": frontier["journal_sequence"],
                    "iteration": frontier["iteration"],
                    "revocation_epoch": capability["revocation_epoch"],
                    "fencing_epoch": frontier["fencing_epoch"],
                    "verification_digest": verification_digest,
                    "observed_at": raw["observed_at"],
                },
            )
            connection.execute(
                """INSERT INTO d2_frontiers VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    d2_digest,
                    raw["transaction_id"],
                    frontier["contract_digest"],
                    frontier["iteration"],
                    frontier["joined_iteration"],
                    frontier["journal_sequence"],
                    frontier["fencing_epoch"],
                    _canonical_text(frontier["inventory"]),
                    _canonical_text(frontier),
                    verification_text,
                    verification_digest,
                    raw["observed_at"],
                    sequence,
                ),
            )
            self._hit("m4_frontier_after_event")
            connection.commit()
            connection.close()
            connection = None
            try:
                self._hit("m4_frontier_after_commit_before_ack")
            except Exception:
                return _result(DurableOutcome.STOP, DurableReason.ACKNOWLEDGEMENT_UNKNOWN)
            return DurableResult(
                DurableOutcome.COMMITTED,
                DurableReason.D2_FRONTIER_BOUND,
                transaction_id=raw["transaction_id"],
                journal_sequence=sequence,
                contract_digest=frontier["contract_digest"],
                d2_frontier_digest=d2_digest,
            )
        except _Rejected as rejection:
            if connection is not None:
                connection.rollback()
            return _result(rejection.outcome, rejection.reason)
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

    def begin_m4_transaction(self, raw: object) -> DurableResult:
        """Durably bind one claimed dispatch to its contract and D2 frontier."""

        if not self._usable:
            return _result(DurableOutcome.STOP, self._stopped_reason)
        if self._m4_verifier is None:
            return _result(DurableOutcome.STOP, DurableReason.M4_VERIFIER_ABSENT)
        if not _closed_dict(
            raw, frozenset({"transaction_id", "d2_frontier_digest", "observed_at"})
        ):
            return _result(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
        if (
            not _valid_identifier(raw["transaction_id"])
            or not _valid_digest(raw["d2_frontier_digest"])
            or _parse_time(raw["observed_at"]) is None
        ):
            return _result(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
        connection: sqlite3.Connection | None = None
        try:
            self._hit("m4_begin_before_transaction")
            connection = self._connect()
            connection.execute("BEGIN IMMEDIATE")
            self._hit("m4_begin_after_begin")
            self._audit(connection)
            meta = connection.execute("SELECT * FROM store_meta WHERE id=1").fetchone()
            if meta is None:
                raise _StoreCorrupt("missing metadata")
            if connection.execute(
                "SELECT 1 FROM m4_transactions WHERE transaction_id=?", (raw["transaction_id"],)
            ).fetchone() is not None:
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.REPLAY)
            loaded = self._load_verified_frontier(
                connection, raw["d2_frontier_digest"], raw["observed_at"]
            )
            if loaded is None:
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.D2_INVENTORY_INVALID)
            frontier_row, frontier = loaded
            if frontier_row["transaction_id"] != raw["transaction_id"]:
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.D2_INVENTORY_INVALID)
            intent = connection.execute(
                "SELECT * FROM dispatch_intents WHERE transaction_id=?", (raw["transaction_id"],)
            ).fetchone()
            claim = connection.execute(
                "SELECT * FROM dispatch_attempt_claims WHERE transaction_id=?", (raw["transaction_id"],)
            ).fetchone()
            if intent is None or claim is None:
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.UNKNOWN_INTENT)
            capability = connection.execute(
                "SELECT * FROM capabilities WHERE capability_id=?", (intent["capability_id"],)
            ).fetchone()
            if (
                capability is None
                or capability["state"] != "CONSUMED"
                or capability["consumed_transaction_id"] != raw["transaction_id"]
                or intent["state"] != "PENDING"
            ):
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.ILLEGAL_TRANSITION)
            observed = _parse_time(raw["observed_at"])
            not_before = _parse_time(capability["not_before"])
            expires = _parse_time(capability["expires_at"])
            if observed is None or not_before is None or expires is None or not (not_before <= observed < expires):
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.EXPIRED)
            claim_value = _json_value(claim["claim_json"])
            claim_verification = _json_value(claim["executor_verification_json"])
            capability_payload = _json_value(capability["payload_json"])
            if not all(type(value) is dict for value in (claim_value, claim_verification, capability_payload)):
                raise _StoreCorrupt("invalid M4 dispatch source")
            contract_payload = dict(capability_payload)
            contract_payload["request"] = _json_value(capability["request_json"])
            if (
                capability["revocation_epoch"] != meta["revocation_epoch"]
                or any(
                    item != meta["fencing_epoch"]
                    for item in (capability["fencing_epoch"], intent["fencing_epoch"], claim["fencing_epoch"])
                )
                or frontier["fencing_epoch"] != meta["fencing_epoch"]
                or frontier["contract_digest"] != capability["contract_digest"]
                or self._load_verified_contract(
                    connection,
                    capability["contract_digest"],
                    raw["observed_at"],
                    contract_payload,
                ) is None
                or not self._stored_verification_is_valid(capability, raw["observed_at"])
                or not self._executor_claim_verification_is_valid(
                    claim["claim_json"],
                    claim["claim_digest"],
                    claim_verification,
                    claim["executor_verification_json"],
                    claim["executor_verification_digest"],
                    raw["observed_at"],
                )
            ):
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.M4_EVIDENCE_INVALID)
            reservations = connection.execute(
                "SELECT name, unit, scope_digest, lineage_root, amount FROM budget_reservations "
                "WHERE transaction_id=? ORDER BY name, unit, scope_digest, lineage_root",
                (raw["transaction_id"],),
            ).fetchall()
            if not reservations:
                raise _StoreCorrupt("missing M4 reservation")
            budget_vector = [
                {
                    "name": row["name"],
                    "unit": row["unit"],
                    "scope_digest": row["scope_digest"],
                    "lineage_root": row["lineage_root"],
                    "amount": row["amount"],
                }
                for row in reservations
            ]
            if budget_vector != _json_value(capability["budget_vector_json"]):
                raise _StoreCorrupt("M4 budget vector mismatch")
            budget_digest = canonical_digest(budget_vector)
            event_payload = {
                "transaction_id": raw["transaction_id"],
                "contract_digest": capability["contract_digest"],
                "d2_frontier_digest": raw["d2_frontier_digest"],
                "capability_id": capability["capability_id"],
                "claim_digest": claim["claim_digest"],
                "intent_digest": intent["intent_digest"],
                "decision_digest": capability["decision_digest"],
                "authorized_envelope_digest": capability["authorized_envelope_digest"],
                "lineage_root": capability["lineage_root"],
                "iteration": frontier["iteration"],
                "budget_vector": budget_vector,
                "budget_vector_digest": budget_digest,
                "revocation_epoch": capability["revocation_epoch"],
                "fencing_epoch": capability["fencing_epoch"],
                "observed_at": raw["observed_at"],
            }
            sequence = self._append_event(
                connection, "M4_DISPATCH_BOUND", raw["transaction_id"], event_payload
            )
            connection.execute(
                """INSERT INTO m4_transactions (
                       transaction_id, state, contract_digest, d2_frontier_digest,
                       iteration, capability_id, claim_digest, intent_digest,
                       decision_digest, authorized_envelope_digest, lineage_root,
                       object_binding_digest, revocation_epoch, fencing_epoch,
                       budget_vector_json, budget_vector_digest, current_record_digest,
                       started_at, started_journal_sequence
                   ) VALUES (?, 'DISPATCHED', ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, NULL, ?, ?)""",
                (
                    raw["transaction_id"],
                    capability["contract_digest"],
                    raw["d2_frontier_digest"],
                    frontier["iteration"],
                    capability["capability_id"],
                    claim["claim_digest"],
                    intent["intent_digest"],
                    capability["decision_digest"],
                    capability["authorized_envelope_digest"],
                    capability["lineage_root"],
                    capability["revocation_epoch"],
                    capability["fencing_epoch"],
                    _canonical_text(budget_vector),
                    budget_digest,
                    raw["observed_at"],
                    sequence,
                ),
            )
            self._hit("m4_begin_after_event")
            connection.commit()
            connection.close()
            connection = None
            try:
                self._hit("m4_begin_after_commit_before_ack")
            except Exception:
                return _result(DurableOutcome.STOP, DurableReason.ACKNOWLEDGEMENT_UNKNOWN)
            return DurableResult(
                DurableOutcome.COMMITTED,
                DurableReason.M4_DISPATCH_BOUND,
                transaction_id=raw["transaction_id"],
                journal_sequence=sequence,
                contract_digest=capability["contract_digest"],
                d2_frontier_digest=raw["d2_frontier_digest"],
                m4_state="DISPATCHED",
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

    def _terminalize_m4_budget(
        self,
        connection: sqlite3.Connection,
        transaction: sqlite3.Row,
        state: str,
        observed_at: str,
        record_digest: str,
    ) -> int | None:
        disposition = {
            "COMMITTED": "SPENT",
            "DISCARDED": "RELEASED",
            "QUARANTINED": "QUARANTINED_ESCROW",
        }.get(state)
        if disposition is None:
            return None
        intent = connection.execute(
            "SELECT * FROM dispatch_intents WHERE transaction_id=?",
            (transaction["transaction_id"],),
        ).fetchone()
        reservations = connection.execute(
            "SELECT * FROM budget_reservations WHERE transaction_id=? "
            "ORDER BY name, unit, scope_digest, lineage_root",
            (transaction["transaction_id"],),
        ).fetchall()
        if (
            intent is None
            or intent["state"] != "PENDING"
            or not reservations
            or any(row["disposition"] is not None for row in reservations)
        ):
            raise _StoreCorrupt("M4 terminal budget source mismatch")
        for reservation in reservations:
            key = (
                reservation["name"],
                reservation["unit"],
                reservation["scope_digest"],
                reservation["lineage_root"],
            )
            if disposition == "SPENT":
                cursor = connection.execute(
                    "UPDATE budgets SET reserved=reserved-?, spent=spent+? "
                    "WHERE name=? AND unit=? AND scope_digest=? AND lineage_root=? "
                    "AND reserved>=? AND spent<=?",
                    (
                        reservation["amount"],
                        reservation["amount"],
                        *key,
                        reservation["amount"],
                        _MAX_INTEGER - reservation["amount"],
                    ),
                )
            elif disposition == "RELEASED":
                cursor = connection.execute(
                    "UPDATE budgets SET reserved=reserved-?, remaining=remaining+? "
                    "WHERE name=? AND unit=? AND scope_digest=? AND lineage_root=? "
                    "AND reserved>=? AND remaining<=?",
                    (
                        reservation["amount"],
                        reservation["amount"],
                        *key,
                        reservation["amount"],
                        _MAX_INTEGER - reservation["amount"],
                    ),
                )
            else:
                cursor = None
            if cursor is not None and cursor.rowcount != 1:
                raise _StoreCorrupt("M4 terminal budget conservation failure")
        terminal_record = {
            "record_type": disposition,
            "transaction_id": transaction["transaction_id"],
            "intent_digest": transaction["intent_digest"],
            "fencing_epoch": transaction["fencing_epoch"],
            "observed_at": observed_at,
            "evidence_digest": record_digest,
        }
        terminal_text = _canonical_text(terminal_record)
        terminal_digest = canonical_digest(terminal_record)
        changed = connection.execute(
            "UPDATE budget_reservations SET disposition=?, terminal_record_json=?, "
            "terminal_record_digest=? WHERE transaction_id=? AND disposition IS NULL",
            (
                disposition,
                terminal_text,
                terminal_digest,
                transaction["transaction_id"],
            ),
        )
        if changed.rowcount != len(reservations):
            raise _StoreCorrupt("M4 terminal reservation update mismatch")
        changed = connection.execute(
            "UPDATE dispatch_intents SET state=? WHERE transaction_id=? AND state='PENDING'",
            (disposition, transaction["transaction_id"]),
        )
        if changed.rowcount != 1:
            raise _StoreCorrupt("M4 terminal intent update mismatch")
        return self._append_event(
            connection,
            "BUDGET_TERMINAL_" + disposition,
            transaction["transaction_id"],
            {
                "transaction_id": transaction["transaction_id"],
                "intent_digest": transaction["intent_digest"],
                "disposition": disposition,
                "terminal_record_digest": terminal_digest,
                "fencing_epoch": transaction["fencing_epoch"],
            },
        )

    def advance_m4(self, raw: object) -> DurableResult:
        """Atomically verify and append one exact M4 stage transition."""

        if not self._usable:
            return _result(DurableOutcome.STOP, self._stopped_reason)
        if self._m4_verifier is None:
            return _result(DurableOutcome.STOP, DurableReason.M4_VERIFIER_ABSENT)
        keys = frozenset(
            {"transaction_id", "expected_state", "state", "observed_at", "evidence", "verification"}
        )
        if not _closed_dict(raw, keys):
            return _result(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
        if (
            not _valid_identifier(raw["transaction_id"])
            or type(raw["expected_state"]) is not str
            or type(raw["state"]) is not str
            or raw["expected_state"] not in _M4_STATES
            or raw["state"] not in _M4_STATES
            or _parse_time(raw["observed_at"]) is None
            or not _valid_verification_source(raw["verification"])
        ):
            return _result(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
        connection: sqlite3.Connection | None = None
        try:
            state = raw["state"]
            self._hit("m4_" + state.lower() + "_before_transaction")
            connection = self._connect()
            connection.execute("BEGIN IMMEDIATE")
            self._hit("m4_" + state.lower() + "_after_begin")
            self._audit(connection)
            meta = connection.execute("SELECT * FROM store_meta WHERE id=1").fetchone()
            transaction = connection.execute(
                "SELECT * FROM m4_transactions WHERE transaction_id=?",
                (raw["transaction_id"],),
            ).fetchone()
            if meta is None:
                raise _StoreCorrupt("missing M4 metadata")
            if transaction is None:
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.UNKNOWN_INTENT)
            if transaction["state"] != raw["expected_state"]:
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.ILLEGAL_TRANSITION)
            if state not in _M4_NEXT.get(transaction["state"], frozenset()):
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.ILLEGAL_TRANSITION)
            capability_row = connection.execute(
                "SELECT * FROM capabilities WHERE capability_id=?",
                (transaction["capability_id"],),
            ).fetchone()
            claim_row = connection.execute(
                "SELECT * FROM dispatch_attempt_claims WHERE transaction_id=?",
                (raw["transaction_id"],),
            ).fetchone()
            intent_row = connection.execute(
                "SELECT * FROM dispatch_intents WHERE transaction_id=?",
                (raw["transaction_id"],),
            ).fetchone()
            if capability_row is None or claim_row is None or intent_row is None:
                raise _StoreCorrupt("missing M4 transition source")
            capability = _json_value(capability_row["payload_json"])
            capability_verification = _json_value(capability_row["verification_json"])
            claim = _json_value(claim_row["claim_json"])
            claim_verification = _json_value(claim_row["executor_verification_json"])
            intent = _json_value(intent_row["intent_json"])
            if not all(
                type(value) is dict
                for value in (capability, capability_verification, claim, claim_verification, intent)
            ):
                raise _StoreCorrupt("invalid M4 transition source")
            observed = _parse_time(raw["observed_at"])
            started = _parse_time(transaction["started_at"])
            not_before = _parse_time(capability_row["not_before"])
            expires = _parse_time(capability_row["expires_at"])
            if (
                observed is None
                or started is None
                or not_before is None
                or expires is None
                or not (not_before <= started <= observed < expires)
            ):
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.EXPIRED)
            contract_payload = dict(capability)
            contract_payload["request"] = _json_value(capability_row["request_json"])
            loaded_contract = self._load_verified_contract(
                connection, transaction["contract_digest"], raw["observed_at"], contract_payload
            )
            loaded_frontier = self._load_verified_frontier(
                connection, transaction["d2_frontier_digest"], raw["observed_at"]
            )
            if loaded_contract is None or loaded_frontier is None:
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.M4_EVIDENCE_INVALID)
            contract_row, contract = loaded_contract
            frontier_row, frontier = loaded_frontier
            expected_intent_state = {
                "COMMITTED": "SPENT",
                "QUARANTINED": "QUARANTINED_ESCROW",
            }.get(transaction["state"], "PENDING")
            if (
                capability_row["state"] != "CONSUMED"
                or capability_row["consumed_transaction_id"] != raw["transaction_id"]
                or intent_row["state"] != expected_intent_state
                or frontier_row["transaction_id"] != raw["transaction_id"]
                or any(
                    value != meta["fencing_epoch"]
                    for value in (
                        transaction["fencing_epoch"],
                        capability_row["fencing_epoch"],
                        claim_row["fencing_epoch"],
                        intent_row["fencing_epoch"],
                        frontier["fencing_epoch"],
                    )
                )
                or any(
                    value != meta["revocation_epoch"]
                    for value in (
                        transaction["revocation_epoch"],
                        capability_row["revocation_epoch"],
                        claim_row["revocation_epoch"],
                        contract["revocation_epoch"],
                    )
                )
                or transaction["contract_digest"] != contract_row["contract_digest"]
                or transaction["iteration"] != frontier["iteration"]
                or canonical_digest(capability) != capability_row["payload_digest"]
                or canonical_digest(claim) != claim_row["claim_digest"]
                or canonical_digest(intent) != intent_row["intent_digest"]
                or not self._stored_verification_is_valid(capability_row, raw["observed_at"])
                or not self._executor_claim_verification_is_valid(
                    claim_row["claim_json"],
                    claim_row["claim_digest"],
                    claim_verification,
                    claim_row["executor_verification_json"],
                    claim_row["executor_verification_digest"],
                    raw["observed_at"],
                )
            ):
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.M4_EVIDENCE_INVALID)
            transition_rows = connection.execute(
                "SELECT * FROM m4_transition_records WHERE transaction_id=? ORDER BY transition_index",
                (raw["transaction_id"],),
            ).fetchall()
            prior: dict[str, tuple[str, dict[str, object]]] = {}
            previous_digest: str | None = None
            previous_time = started
            for index, row in enumerate(transition_rows, 1):
                record = _json_value(row["record_json"])
                verification = _json_value(row["verification_json"])
                record_time = _parse_time(row["observed_at"])
                if (
                    type(record) is not dict
                    or type(verification) is not dict
                    or row["transition_index"] != index
                    or row["previous_record_digest"] != previous_digest
                    or record.get("previous_record_digest") != previous_digest
                    or canonical_digest(record) != row["record_digest"]
                    or verification.get("bindings") != record
                    or verification.get("payload_digest") != row["record_digest"]
                    or canonical_digest(verification) != row["verification_digest"]
                    or record_time is None
                    or record_time < previous_time
                    or not self._m4_verification_is_valid(
                        row["record_json"],
                        row["record_digest"],
                        verification,
                        row["verification_json"],
                        row["verification_digest"],
                        raw["observed_at"],
                    )
                ):
                    connection.rollback()
                    return _result(DurableOutcome.DENY, DurableReason.M4_EVIDENCE_INVALID)
                prior[row["state"]] = (row["record_digest"], record)
                previous_digest = row["record_digest"]
                previous_time = record_time
            if observed < previous_time:
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.EXPIRED)
            object_binding_digest = _m4_evidence_object_digest(
                state, raw["evidence"], transaction, capability, intent, frontier, prior
            )
            budget_vector = _json_value(transaction["budget_vector_json"])
            if type(budget_vector) is not list or canonical_digest(budget_vector) != transaction["budget_vector_digest"]:
                raise _StoreCorrupt("invalid M4 budget vector")
            transition_index = len(transition_rows) + 1
            record = {
                "record_version": FORMAT_VERSION,
                "record_type": "M4_TRANSITION",
                "state": state,
                "transaction_id": raw["transaction_id"],
                "transition_index": transition_index,
                "contract_digest": transaction["contract_digest"],
                "d2_frontier_digest": transaction["d2_frontier_digest"],
                "iteration": transaction["iteration"],
                "capability_id": transaction["capability_id"],
                "claim_digest": transaction["claim_digest"],
                "intent_digest": transaction["intent_digest"],
                "decision_digest": transaction["decision_digest"],
                "authorized_envelope_digest": transaction["authorized_envelope_digest"],
                "lineage_root": transaction["lineage_root"],
                "object_binding_digest": object_binding_digest,
                "budget_vector": budget_vector,
                "budget_vector_digest": transaction["budget_vector_digest"],
                "revocation_epoch": transaction["revocation_epoch"],
                "fencing_epoch": transaction["fencing_epoch"],
                "previous_record_digest": previous_digest,
                "observed_at": raw["observed_at"],
                "contract": contract,
                "frontier": frontier,
                "capability": capability,
                "capability_verification": capability_verification,
                "claim": claim,
                "claim_verification": claim_verification,
                "intent": intent,
                "evidence": raw["evidence"],
            }
            record_text, record_digest, verification, verification_text, verification_digest = _verification_for(
                record, raw["verification"]
            )
            if not self._m4_verification_is_valid(
                record_text,
                record_digest,
                verification,
                verification_text,
                verification_digest,
                raw["observed_at"],
            ):
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.M4_EVIDENCE_INVALID)
            self._hit("m4_" + state.lower() + "_after_verification")
            event_payload = {
                "transaction_id": raw["transaction_id"],
                "state": state,
                "record_digest": record_digest,
                "verification_digest": verification_digest,
                "object_binding_digest": object_binding_digest,
                "contract_digest": transaction["contract_digest"],
                "d2_frontier_digest": transaction["d2_frontier_digest"],
                "budget_vector_digest": transaction["budget_vector_digest"],
                "revocation_epoch": transaction["revocation_epoch"],
                "fencing_epoch": transaction["fencing_epoch"],
                "observed_at": raw["observed_at"],
            }
            sequence = self._append_event(
                connection, "M4_" + state, raw["transaction_id"], event_payload
            )
            connection.execute(
                "INSERT INTO m4_transition_records VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    raw["transaction_id"],
                    transition_index,
                    state,
                    previous_digest,
                    record_digest,
                    record_text,
                    verification_text,
                    verification_digest,
                    raw["observed_at"],
                    sequence,
                ),
            )
            if state == "JOINED":
                changed = connection.execute(
                    "UPDATE active_contracts SET joined_iteration=? WHERE contract_digest=? "
                    "AND joined_iteration=? AND max_iterations>=?",
                    (
                        transaction["iteration"],
                        transaction["contract_digest"],
                        transaction["iteration"] - 1,
                        transaction["iteration"],
                    ),
                )
                if changed.rowcount != 1:
                    raise _StoreCorrupt("M4 JOIN iteration mismatch")
            terminal_sequence = self._terminalize_m4_budget(
                connection, transaction, state, raw["observed_at"], record_digest
            )
            self._hit("m4_" + state.lower() + "_after_budget")
            changed = connection.execute(
                "UPDATE m4_transactions SET state=?, object_binding_digest=?, "
                "current_record_digest=? WHERE transaction_id=? AND state=?",
                (
                    state,
                    object_binding_digest,
                    record_digest,
                    raw["transaction_id"],
                    raw["expected_state"],
                ),
            )
            if changed.rowcount != 1:
                raise _StoreCorrupt("M4 state update mismatch")
            self._hit("m4_" + state.lower() + "_after_event")
            connection.commit()
            connection.close()
            connection = None
            try:
                self._hit("m4_" + state.lower() + "_after_commit_before_ack")
            except Exception:
                return _result(DurableOutcome.STOP, DurableReason.ACKNOWLEDGEMENT_UNKNOWN)
            return DurableResult(
                DurableOutcome.COMMITTED,
                DurableReason["M4_" + state],
                transaction_id=raw["transaction_id"],
                journal_sequence=terminal_sequence or sequence,
                contract_digest=transaction["contract_digest"],
                d2_frontier_digest=transaction["d2_frontier_digest"],
                record_digest=record_digest,
                m4_state=state,
            )
        except _Rejected as rejection:
            if connection is not None:
                connection.rollback()
            return _result(rejection.outcome, rejection.reason)
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
            if self._m4_verifier is not None:
                contract_payload = dict(prepared.payload)
                contract_payload["request"] = _json_value(prepared.request_text)
                if self._load_verified_contract(
                    connection,
                    prepared.payload["contract_digest"],
                    prepared.payload["issued_at"],
                    contract_payload,
                ) is None:
                    connection.rollback()
                    return _result(DurableOutcome.DENY, DurableReason.CONTRACT_BINDING_MISMATCH)
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
            if self._m4_verifier is not None:
                contract_payload = _json_value(capability["payload_json"])
                if type(contract_payload) is not dict:
                    raise _StoreCorrupt("invalid capability payload")
                contract_payload = dict(contract_payload)
                contract_payload["request"] = _json_value(capability["request_json"])
                if self._load_verified_contract(
                    connection,
                    capability["contract_digest"],
                    prepared.raw["observed_at"],
                    contract_payload,
                ) is None:
                    connection.rollback()
                    return _result(DurableOutcome.DENY, DurableReason.CONTRACT_BINDING_MISMATCH)
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

    def _executor_claim_verification_is_valid(
        self,
        claim_text: str,
        claim_digest: str,
        verification: dict[str, object],
        verification_text: str,
        verification_digest: str,
        observed_at: str,
    ) -> bool:
        try:
            verifier = self._executor_claim_verifier
            if verifier is None:
                return False
            result = verifier.verify(
                claim_text.encode("utf-8"),
                verification_text.encode("utf-8"),
                observed_at,
            )
            return (
                type(result) is VerificationResult
                and result.status is VerificationStatus.VERIFIED
                and result.verifier_id == verification["verifier_id"]
                and result.payload_digest == claim_digest
                and result.record_digest == verification_digest
            )
        except Exception:
            return False

    def claim_dispatch(self, raw: object) -> DurableResult:
        """Atomically claim one committed intent; never execute or retry it."""

        if not self._usable:
            return _result(DurableOutcome.STOP, self._stopped_reason)
        keys = frozenset({"transaction_id", "observed_at", "executor_verification"})
        verification_keys = frozenset({"verifier_id", "issuer_id", "key_id", "proof"})
        if not _closed_dict(raw, keys):
            return _result(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
        if not _valid_identifier(raw["transaction_id"]) or _parse_time(raw["observed_at"]) is None:
            return _result(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
        source = raw["executor_verification"]
        if not _closed_dict(source, verification_keys):
            return _result(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
        if not all(_valid_identifier(source[field]) for field in ("verifier_id", "issuer_id", "key_id")):
            return _result(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
        if not _valid_proof(source["proof"]):
            return _result(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
        if self._executor_claim_verifier is None:
            return _result(DurableOutcome.STOP, DurableReason.EXECUTOR_VERIFIER_ABSENT)
        connection: sqlite3.Connection | None = None
        try:
            self._hit("claim_before_transaction")
            connection = self._connect()
            connection.execute("BEGIN IMMEDIATE")
            self._hit("claim_after_begin")
            self._audit(connection)
            meta = connection.execute("SELECT * FROM store_meta WHERE id=1").fetchone()
            intent_row = connection.execute(
                "SELECT * FROM dispatch_intents WHERE transaction_id=?",
                (raw["transaction_id"],),
            ).fetchone()
            if meta is None:
                raise _StoreCorrupt("missing metadata")
            if intent_row is None:
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.UNKNOWN_INTENT)
            if connection.execute(
                "SELECT 1 FROM dispatch_attempt_claims WHERE transaction_id=?",
                (raw["transaction_id"],),
            ).fetchone() is not None:
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.REPLAY)
            if intent_row["state"] != "PENDING":
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.ILLEGAL_TRANSITION)
            capability = connection.execute(
                "SELECT * FROM capabilities WHERE capability_id=?",
                (intent_row["capability_id"],),
            ).fetchone()
            if (
                capability is None
                or capability["state"] != "CONSUMED"
                or capability["consumed_transaction_id"] != raw["transaction_id"]
            ):
                raise _StoreCorrupt("claim capability mismatch")
            if capability["revocation_epoch"] != meta["revocation_epoch"]:
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.STALE_REVOCATION)
            if (
                capability["fencing_epoch"] != meta["fencing_epoch"]
                or intent_row["fencing_epoch"] != meta["fencing_epoch"]
            ):
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.STALE_FENCE)
            observed = _parse_time(raw["observed_at"])
            intent = _json_value(intent_row["intent_json"])
            intent_observed = _parse_time(intent.get("observed_at"))
            not_before = _parse_time(capability["not_before"])
            expires_at = _parse_time(capability["expires_at"])
            if observed is None or intent_observed is None or not_before is None or expires_at is None:
                raise _StoreCorrupt("claim time mismatch")
            if not (not_before <= intent_observed <= observed < expires_at):
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.EXPIRED)
            if not self._stored_verification_is_valid(capability, raw["observed_at"]):
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.CAPABILITY_INVALID)
            payload = _json_value(capability["payload_json"])
            request = _json_value(capability["request_json"])
            decision = _json_value(capability["decision_json"])
            envelope = _json_value(capability["authorized_envelope_json"])
            capability_verification = _json_value(capability["verification_json"])
            if type(payload) is not dict or type(request) is not dict:
                raise _StoreCorrupt("invalid claim capability payload")
            if self._m4_verifier is not None:
                contract_payload = dict(payload)
                contract_payload["request"] = request
                if self._load_verified_contract(
                    connection,
                    capability["contract_digest"],
                    raw["observed_at"],
                    contract_payload,
                ) is None:
                    connection.rollback()
                    return _result(DurableOutcome.DENY, DurableReason.CONTRACT_BINDING_MISMATCH)
            if payload.get("principal_id") == payload.get("audience_id"):
                raise _StoreCorrupt("self-audience capability")
            claim = {
                "claim_version": FORMAT_VERSION,
                "transaction_id": intent["transaction_id"],
                "capability_id": intent["capability_id"],
                "intent_digest": intent_row["intent_digest"],
                "idempotency_key_digest": intent["idempotency_key_digest"],
                "principal_id": intent["principal_id"],
                "audience_id": intent["audience_id"],
                "purpose": intent["purpose"],
                "profile_digest": intent["profile_digest"],
                "placement_digest": intent["placement_digest"],
                "session_id": intent["session_id"],
                "lineage_root": intent["lineage_root"],
                "nonce": intent["nonce"],
                "revocation_epoch": intent["revocation_epoch"],
                "fencing_epoch": intent["fencing_epoch"],
                "observed_at": raw["observed_at"],
                "target_scope_digest": intent["target_scope_digest"],
                "material_digest": intent["material_digest"],
                "request": request,
                "decision": decision,
                "authorized_envelope": envelope,
                "capability_payload": payload,
                "capability_verification": capability_verification,
                "intent": intent,
            }
            claim_text = _canonical_text(claim)
            claim_digest = canonical_digest(claim)
            verification = {
                "verification_version": FORMAT_VERSION,
                "verifier_id": source["verifier_id"],
                "issuer_id": source["issuer_id"],
                "key_id": source["key_id"],
                "payload_digest": claim_digest,
                "bindings": claim,
                "proof": source["proof"],
            }
            verification_text = _canonical_text(verification)
            verification_digest = canonical_digest(verification)
            if not self._executor_claim_verification_is_valid(
                claim_text,
                claim_digest,
                verification,
                verification_text,
                verification_digest,
                raw["observed_at"],
            ):
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.CAPABILITY_INVALID)
            self._hit("claim_after_verification")
            sequence = meta["journal_head_sequence"] + 1
            if not _bounded_integer(sequence, 1):
                raise _StoreCorrupt("claim sequence overflow")
            connection.execute(
                """
                INSERT INTO dispatch_attempt_claims VALUES
                (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    raw["transaction_id"],
                    claim_digest,
                    intent_row["intent_digest"],
                    capability["capability_id"],
                    capability["audience_id"],
                    capability["placement_digest"],
                    capability["session_id"],
                    capability["revocation_epoch"],
                    capability["fencing_epoch"],
                    raw["observed_at"],
                    claim_text,
                    verification_text,
                    verification_digest,
                    sequence,
                ),
            )
            self._hit("claim_after_insert")
            event_payload = {
                "transaction_id": raw["transaction_id"],
                "capability_id": capability["capability_id"],
                "intent_digest": intent_row["intent_digest"],
                "claim_digest": claim_digest,
                "executor_verification_digest": verification_digest,
                "audience_id": capability["audience_id"],
                "placement_digest": capability["placement_digest"],
                "session_id": capability["session_id"],
                "revocation_epoch": capability["revocation_epoch"],
                "fencing_epoch": capability["fencing_epoch"],
                "claim": claim,
            }
            observed_sequence = self._append_event(
                connection,
                "DISPATCH_ATTEMPT_CLAIMED",
                raw["transaction_id"],
                event_payload,
            )
            if observed_sequence != sequence:
                raise _StoreCorrupt("claim sequence mismatch")
            self._hit("claim_after_event")
            connection.commit()
            connection.close()
            connection = None
            try:
                self._hit("claim_after_commit_before_ack")
            except Exception:
                return _result(DurableOutcome.STOP, DurableReason.ACKNOWLEDGEMENT_UNKNOWN)
            dispatch_claim = DispatchClaim(
                transaction_id=raw["transaction_id"],
                claim_digest=claim_digest,
                intent_digest=intent_row["intent_digest"],
                capability_id=capability["capability_id"],
                idempotency_key_digest=capability["idempotency_key_digest"],
                principal_id=capability["principal_id"],
                audience_id=capability["audience_id"],
                purpose=capability["purpose"],
                profile_digest=capability["profile_digest"],
                placement_digest=capability["placement_digest"],
                session_id=capability["session_id"],
                lineage_root=capability["lineage_root"],
                nonce=capability["nonce"],
                revocation_epoch=capability["revocation_epoch"],
                fencing_epoch=capability["fencing_epoch"],
                observed_at=raw["observed_at"],
                target_scope_digest=intent["target_scope_digest"],
                material_digest=intent["material_digest"],
                request_json=capability["request_json"],
                decision_json=capability["decision_json"],
                authorized_envelope_json=capability["authorized_envelope_json"],
                capability_payload_json=capability["payload_json"],
                capability_verification_json=capability["verification_json"],
                intent_json=intent_row["intent_json"],
                claim_json=claim_text,
                executor_verification_json=verification_text,
            )
            return DurableResult(
                DurableOutcome.COMMITTED,
                DurableReason.DISPATCH_ATTEMPT_CLAIMED,
                capability_id=capability["capability_id"],
                transaction_id=raw["transaction_id"],
                journal_sequence=sequence,
                dispatch_claim=dispatch_claim,
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

    def verify_dispatch_claim(self, raw: object) -> DurableResult:
        """Revalidate the one stored claim and current epochs without mutation."""

        if not self._usable:
            return _result(DurableOutcome.STOP, self._stopped_reason)
        keys = frozenset(
            {
                "transaction_id", "claim_digest", "audience_id", "placement_digest",
                "session_id", "revocation_epoch", "fencing_epoch", "observed_at",
            }
        )
        if not _closed_dict(raw, keys):
            return _result(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
        if (
            not all(
                _valid_identifier(raw[key])
                for key in ("transaction_id", "audience_id", "session_id")
            )
            or not _valid_digest(raw["claim_digest"])
            or not _valid_digest(raw["placement_digest"])
            or not _bounded_integer(raw["revocation_epoch"], 0)
            or not _bounded_integer(raw["fencing_epoch"], 1)
            or _parse_time(raw["observed_at"]) is None
        ):
            return _result(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
        if self._executor_claim_verifier is None:
            return _result(DurableOutcome.STOP, DurableReason.EXECUTOR_VERIFIER_ABSENT)
        try:
            connection = self._connect()
            try:
                self._audit(connection)
                meta = connection.execute("SELECT * FROM store_meta WHERE id=1").fetchone()
                claim_row = connection.execute(
                    "SELECT * FROM dispatch_attempt_claims WHERE transaction_id=?",
                    (raw["transaction_id"],),
                ).fetchone()
                intent_row = connection.execute(
                    "SELECT * FROM dispatch_intents WHERE transaction_id=?",
                    (raw["transaction_id"],),
                ).fetchone()
                if meta is None:
                    raise _StoreCorrupt("missing metadata")
                if claim_row is None or intent_row is None:
                    return _result(DurableOutcome.DENY, DurableReason.UNKNOWN_INTENT)
                capability = connection.execute(
                    "SELECT * FROM capabilities WHERE capability_id=?",
                    (intent_row["capability_id"],),
                ).fetchone()
                if (
                    capability is None
                    or capability["state"] != "CONSUMED"
                    or capability["consumed_transaction_id"] != raw["transaction_id"]
                    or intent_row["state"] != "PENDING"
                ):
                    return _result(DurableOutcome.DENY, DurableReason.ILLEGAL_TRANSITION)
                if capability["revocation_epoch"] != meta["revocation_epoch"]:
                    return _result(DurableOutcome.DENY, DurableReason.STALE_REVOCATION)
                if (
                    capability["fencing_epoch"] != meta["fencing_epoch"]
                    or intent_row["fencing_epoch"] != meta["fencing_epoch"]
                ):
                    return _result(DurableOutcome.DENY, DurableReason.STALE_FENCE)
                if (
                    raw["claim_digest"] != claim_row["claim_digest"]
                    or raw["audience_id"] != claim_row["audience_id"]
                    or raw["placement_digest"] != claim_row["placement_digest"]
                    or raw["session_id"] != claim_row["session_id"]
                    or raw["revocation_epoch"] != claim_row["revocation_epoch"]
                    or raw["fencing_epoch"] != claim_row["fencing_epoch"]
                ):
                    return _result(DurableOutcome.DENY, DurableReason.BINDING_MISMATCH)
                observed = _parse_time(raw["observed_at"])
                claim_observed = _parse_time(claim_row["observed_at"])
                not_before = _parse_time(capability["not_before"])
                expires_at = _parse_time(capability["expires_at"])
                if (
                    observed is None
                    or claim_observed is None
                    or not_before is None
                    or expires_at is None
                    or not (not_before <= claim_observed <= observed < expires_at)
                ):
                    return _result(DurableOutcome.DENY, DurableReason.EXPIRED)
                if not self._stored_verification_is_valid(capability, raw["observed_at"]):
                    return _result(DurableOutcome.DENY, DurableReason.CAPABILITY_INVALID)
                claim_value = _json_value(claim_row["claim_json"])
                verification = _json_value(claim_row["executor_verification_json"])
                if (
                    canonical_digest(claim_value) != claim_row["claim_digest"]
                    or canonical_digest(verification) != claim_row["executor_verification_digest"]
                    or verification.get("payload_digest") != claim_row["claim_digest"]
                    or verification.get("bindings") != claim_value
                    or not self._executor_claim_verification_is_valid(
                        claim_row["claim_json"],
                        claim_row["claim_digest"],
                        verification,
                        claim_row["executor_verification_json"],
                        claim_row["executor_verification_digest"],
                        claim_row["observed_at"],
                    )
                ):
                    return _result(DurableOutcome.DENY, DurableReason.CAPABILITY_INVALID)
                intent = _json_value(intent_row["intent_json"])
                dispatch_claim = DispatchClaim(
                    transaction_id=raw["transaction_id"],
                    claim_digest=claim_row["claim_digest"],
                    intent_digest=intent_row["intent_digest"],
                    capability_id=capability["capability_id"],
                    idempotency_key_digest=capability["idempotency_key_digest"],
                    principal_id=capability["principal_id"],
                    audience_id=capability["audience_id"],
                    purpose=capability["purpose"],
                    profile_digest=capability["profile_digest"],
                    placement_digest=capability["placement_digest"],
                    session_id=capability["session_id"],
                    lineage_root=capability["lineage_root"],
                    nonce=capability["nonce"],
                    revocation_epoch=capability["revocation_epoch"],
                    fencing_epoch=capability["fencing_epoch"],
                    observed_at=claim_row["observed_at"],
                    target_scope_digest=intent["target_scope_digest"],
                    material_digest=intent["material_digest"],
                    request_json=capability["request_json"],
                    decision_json=capability["decision_json"],
                    authorized_envelope_json=capability["authorized_envelope_json"],
                    capability_payload_json=capability["payload_json"],
                    capability_verification_json=capability["verification_json"],
                    intent_json=intent_row["intent_json"],
                    claim_json=claim_row["claim_json"],
                    executor_verification_json=claim_row["executor_verification_json"],
                )
            finally:
                connection.close()
            return DurableResult(
                DurableOutcome.OK,
                DurableReason.DISPATCH_CLAIM_VERIFIED,
                capability_id=dispatch_claim.capability_id,
                transaction_id=dispatch_claim.transaction_id,
                dispatch_claim=dispatch_claim,
            )
        except _StoreCorrupt:
            return self._mark_corrupt()
        except sqlite3.OperationalError as error:
            if "locked" in str(error).lower() or "busy" in str(error).lower():
                return _result(DurableOutcome.STOP, DurableReason.STORE_BUSY)
            return self._mark_corrupt()
        except Exception:
            return _result(DurableOutcome.STOP, DurableReason.INTERNAL_ERROR)

    def _runtime_session_verification_is_valid(
        self,
        payload_text: str,
        payload_digest: str,
        verification: dict[str, object],
        verification_text: str,
        verification_digest: str,
        observed_at: str,
    ) -> bool:
        try:
            verifier = self._runtime_session_verifier
            if verifier is None:
                return False
            result = verifier.verify(
                payload_text.encode("utf-8"), verification_text.encode("utf-8"), observed_at
            )
            return (
                type(result) is VerificationResult
                and result.status is VerificationStatus.VERIFIED
                and result.verifier_id == verification["verifier_id"]
                and result.payload_digest == payload_digest
                and result.record_digest == verification_digest
            )
        except Exception:
            return False

    def prepare_runtime_session(self, raw: object) -> DurableResult:
        """Durably bind an exact runtime placement before any untrusted exec.

        This operation only records a session.  It never creates processes, sockets,
        mounts, or a retry; the injected verifier is the only authority boundary.
        """

        if not self._usable:
            return _result(DurableOutcome.STOP, self._stopped_reason)
        keys = frozenset(
            {
                "session_record_id", "transaction_id", "observed_at", "executor_id",
                "profile_digest", "placement_digest", "session_id", "fencing_epoch",
                "runtime_bindings", "runtime_verification",
            }
        )
        verification_keys = frozenset({"verifier_id", "issuer_id", "key_id", "proof"})
        if not _closed_dict(raw, keys):
            return _result(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
        if (
            not all(_valid_identifier(raw[field]) for field in ("session_record_id", "transaction_id", "executor_id", "session_id"))
            or _parse_time(raw["observed_at"]) is None
            or not all(_valid_digest(raw[field]) for field in ("profile_digest", "placement_digest"))
            or not _bounded_integer(raw["fencing_epoch"])
            or not _valid_runtime_bindings(raw["runtime_bindings"])
            or not _closed_dict(raw["runtime_verification"], verification_keys)
            or not all(_valid_identifier(raw["runtime_verification"][field]) for field in ("verifier_id", "issuer_id", "key_id"))
            or not _valid_proof(raw["runtime_verification"]["proof"])
        ):
            return _result(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
        if self._runtime_session_verifier is None:
            return _result(DurableOutcome.STOP, DurableReason.RUNTIME_VERIFIER_ABSENT)
        bindings = raw["runtime_bindings"]
        process = bindings["process"]
        compared = {
            "session_id": raw["session_id"],
            "profile_digest": raw["profile_digest"],
            "placement_digest": raw["placement_digest"],
            "fencing_epoch": raw["fencing_epoch"],
            "executor_principal": raw["executor_id"],
            "transaction_id": raw["transaction_id"],
            "session_record_id": raw["session_record_id"],
        }
        if any(process[field] != expected for field, expected in compared.items()):
            return _result(DurableOutcome.DENY, DurableReason.BINDING_MISMATCH)
        connection: sqlite3.Connection | None = None
        try:
            self._hit("runtime_session_before_transaction")
            connection = self._connect()
            connection.execute("BEGIN IMMEDIATE")
            self._hit("runtime_session_after_begin")
            self._audit(connection)
            meta = connection.execute("SELECT * FROM store_meta WHERE id=1").fetchone()
            claim_row = connection.execute(
                "SELECT * FROM dispatch_attempt_claims WHERE transaction_id=?", (raw["transaction_id"],)
            ).fetchone()
            intent = connection.execute(
                "SELECT * FROM dispatch_intents WHERE transaction_id=?", (raw["transaction_id"],)
            ).fetchone()
            if meta is None:
                raise _StoreCorrupt("missing metadata")
            if claim_row is None or intent is None:
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.UNKNOWN_INTENT)
            if connection.execute(
                "SELECT 1 FROM execution_sessions WHERE transaction_id=? OR session_record_id=?",
                (raw["transaction_id"], raw["session_record_id"]),
            ).fetchone() is not None:
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.REPLAY)
            capability = connection.execute(
                "SELECT * FROM capabilities WHERE capability_id=?", (intent["capability_id"],)
            ).fetchone()
            if (
                capability is None or intent["state"] != "PENDING"
                or capability["state"] != "CONSUMED"
                or capability["consumed_transaction_id"] != raw["transaction_id"]
            ):
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.ILLEGAL_TRANSITION)
            if capability["revocation_epoch"] != meta["revocation_epoch"]:
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.STALE_REVOCATION)
            if any(
                value != meta["fencing_epoch"]
                for value in (capability["fencing_epoch"], intent["fencing_epoch"], claim_row["fencing_epoch"], raw["fencing_epoch"])
            ):
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.STALE_FENCE)
            claim = _json_value(claim_row["claim_json"])
            if (
                raw["profile_digest"] != claim["profile_digest"]
                or raw["placement_digest"] != claim_row["placement_digest"]
                or raw["session_id"] != claim_row["session_id"]
                or raw["executor_id"] != claim_row["audience_id"]
                or process["claim_digest"] != claim_row["claim_digest"]
                or process["lineage_root"] != claim["lineage_root"]
                or process["revocation_epoch"] != claim["revocation_epoch"]
                or process["worker_principal"] != claim["principal_id"]
            ):
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.BINDING_MISMATCH)
            observed = _parse_time(raw["observed_at"])
            not_before = _parse_time(capability["not_before"])
            expires_at = _parse_time(capability["expires_at"])
            if observed is None or not_before is None or expires_at is None or not (not_before <= observed < expires_at):
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.EXPIRED)
            if (
                not self._stored_verification_is_valid(capability, raw["observed_at"])
                or not self._executor_claim_verification_is_valid(
                    claim_row["claim_json"], claim_row["claim_digest"],
                    _json_value(claim_row["executor_verification_json"]),
                    claim_row["executor_verification_json"], claim_row["executor_verification_digest"],
                    raw["observed_at"],
                )
            ):
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.CAPABILITY_INVALID)
            payload = {
                "runtime_session_version": FORMAT_VERSION,
                "session_record_id": raw["session_record_id"],
                "transaction_id": raw["transaction_id"],
                "claim_digest": claim_row["claim_digest"],
                "profile_digest": raw["profile_digest"],
                "placement_digest": raw["placement_digest"],
                "executor_id": raw["executor_id"],
                "session_id": raw["session_id"],
                "fencing_epoch": raw["fencing_epoch"],
                "prepared_at": raw["observed_at"],
                "runtime_bindings": bindings,
                "claim": claim,
            }
            payload_text = _canonical_text(payload)
            payload_digest = canonical_digest(payload)
            verification = {
                "verification_version": FORMAT_VERSION,
                "verifier_id": raw["runtime_verification"]["verifier_id"],
                "issuer_id": raw["runtime_verification"]["issuer_id"],
                "key_id": raw["runtime_verification"]["key_id"],
                "payload_digest": payload_digest,
                "bindings": payload,
                "proof": raw["runtime_verification"]["proof"],
            }
            verification_text = _canonical_text(verification)
            verification_digest = canonical_digest(verification)
            if not self._runtime_session_verification_is_valid(
                payload_text, payload_digest, verification, verification_text, verification_digest, raw["observed_at"]
            ):
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.CAPABILITY_INVALID)
            sequence = meta["journal_head_sequence"] + 1
            connection.execute(
                """INSERT INTO execution_sessions (
                       session_record_id, transaction_id, claim_digest, state,
                       profile_digest, placement_digest, executor_id, session_id,
                       fencing_epoch, prepared_at, runtime_bindings_json,
                       runtime_bindings_digest, runtime_verification_json,
                       runtime_verification_digest, prepared_journal_sequence
                   ) VALUES (?, ?, ?, 'PREPARED', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    raw["session_record_id"], raw["transaction_id"], claim_row["claim_digest"],
                    raw["profile_digest"], raw["placement_digest"], raw["executor_id"], raw["session_id"],
                    raw["fencing_epoch"], raw["observed_at"], _canonical_text(bindings), canonical_digest(bindings),
                    verification_text, verification_digest, sequence,
                ),
            )
            event_payload = {
                "session_record_id": raw["session_record_id"], "transaction_id": raw["transaction_id"],
                "claim_digest": claim_row["claim_digest"], "revocation_epoch": claim["revocation_epoch"],
                "fencing_epoch": raw["fencing_epoch"], "runtime_session": payload,
                "runtime_verification_digest": verification_digest,
            }
            if self._append_event(connection, "RUNTIME_SESSION_PREPARED", raw["session_record_id"], event_payload) != sequence:
                raise _StoreCorrupt("runtime session sequence mismatch")
            self._hit("runtime_session_after_event")
            connection.commit()
            connection.close()
            connection = None
            try:
                self._hit("runtime_session_after_commit_before_ack")
            except Exception:
                return _result(DurableOutcome.STOP, DurableReason.ACKNOWLEDGEMENT_UNKNOWN)
            runtime_session = RuntimeSession(
                raw["session_record_id"], raw["transaction_id"], claim_row["claim_digest"], "PREPARED",
                raw["profile_digest"], raw["placement_digest"], raw["executor_id"], raw["session_id"],
                raw["fencing_epoch"], raw["observed_at"], _canonical_text(bindings), verification_text,
            )
            return DurableResult(
                DurableOutcome.COMMITTED, DurableReason.RUNTIME_SESSION_PREPARED,
                transaction_id=raw["transaction_id"], journal_sequence=sequence, runtime_session=runtime_session,
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

    def finalize_runtime_session(self, raw: object) -> DurableResult:
        """Close one prepared session and atomically release or quarantine its budget.

        A stopped session releases only with independently verified no-effect
        evidence.  Timeout and cleanup uncertainty are always escrowed.
        """

        if not self._usable:
            return _result(DurableOutcome.STOP, self._stopped_reason)
        keys = frozenset({"session_record_id", "observed_at", "state", "evidence"})
        if not _closed_dict(raw, keys) or not _valid_identifier(raw["session_record_id"]) or _parse_time(raw["observed_at"]) is None:
            return _result(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
        if type(raw["state"]) is not str or raw["state"] not in {"STOPPED", "TIMED_OUT", "QUARANTINED"}:
            return _result(DurableOutcome.STOP, DurableReason.UNKNOWN_INPUT if type(raw["state"]) is str else DurableReason.MALFORMED_INPUT)
        evidence = raw["evidence"]
        no_effect_keys = frozenset({"verifier_id", "observer_id", "key_id", "proof"})
        digest_keys = frozenset({"evidence_digest"})
        required = no_effect_keys if raw["state"] == "STOPPED" else digest_keys
        if not _closed_dict(evidence, required):
            return _result(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
        if required is no_effect_keys:
            if not all(_valid_identifier(evidence[field]) for field in ("verifier_id", "observer_id", "key_id")) or not _valid_proof(evidence["proof"]):
                return _result(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
        elif not _valid_digest(evidence["evidence_digest"]):
            return _result(DurableOutcome.STOP, DurableReason.MALFORMED_INPUT)
        connection: sqlite3.Connection | None = None
        try:
            self._hit("runtime_finalize_before_transaction")
            connection = self._connect()
            connection.execute("BEGIN IMMEDIATE")
            self._hit("runtime_finalize_after_begin")
            self._audit(connection)
            session = connection.execute(
                "SELECT * FROM execution_sessions WHERE session_record_id=?", (raw["session_record_id"],)
            ).fetchone()
            if session is None:
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.UNKNOWN_INTENT)
            if session["state"] != "PREPARED":
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.ILLEGAL_TRANSITION)
            intent = connection.execute(
                "SELECT * FROM dispatch_intents WHERE transaction_id=?", (session["transaction_id"],)
            ).fetchone()
            if intent is None or intent["state"] != "PENDING":
                raise _StoreCorrupt("runtime session intent mismatch")
            reservations = connection.execute(
                "SELECT * FROM budget_reservations WHERE transaction_id=? ORDER BY name, unit, scope_digest, lineage_root",
                (session["transaction_id"],),
            ).fetchall()
            if not reservations or any(row["disposition"] is not None for row in reservations):
                raise _StoreCorrupt("runtime session reservation mismatch")
            actual = "QUARANTINED_ESCROW"
            if raw["state"] == "STOPPED":
                attempted, verified = self._no_effect_record(intent, evidence, raw["observed_at"])
                if verified:
                    actual = "RELEASED"
                    terminal_record = attempted
                else:
                    terminal_record = {
                        "record_type": "QUARANTINED_ESCROW", "reason": DurableReason.NO_EFFECT_UNVERIFIED.value,
                        "transaction_id": intent["transaction_id"], "intent_digest": intent["intent_digest"],
                        "fencing_epoch": intent["fencing_epoch"], "observed_at": raw["observed_at"],
                        "attempted_no_effect_record_digest": canonical_digest(attempted),
                    }
            else:
                terminal_record = {
                    "record_type": "QUARANTINED_ESCROW", "transaction_id": intent["transaction_id"],
                    "intent_digest": intent["intent_digest"], "fencing_epoch": intent["fencing_epoch"],
                    "observed_at": raw["observed_at"], "evidence_digest": evidence["evidence_digest"],
                }
            terminal_text = _canonical_text(terminal_record)
            terminal_digest = canonical_digest(terminal_record)
            if actual == "RELEASED":
                for reservation in reservations:
                    key = (reservation["name"], reservation["unit"], reservation["scope_digest"], reservation["lineage_root"])
                    changed = connection.execute(
                        """UPDATE budgets SET reserved=reserved-?, remaining=remaining+?
                           WHERE name=? AND unit=? AND scope_digest=? AND lineage_root=?
                             AND reserved>=? AND remaining<=?""",
                        (reservation["amount"], reservation["amount"], *key, reservation["amount"], _MAX_INTEGER - reservation["amount"]),
                    )
                    if changed.rowcount != 1:
                        raise _StoreCorrupt("runtime release conservation failure")
            changed = connection.execute(
                """UPDATE budget_reservations SET disposition=?, terminal_record_json=?, terminal_record_digest=?
                   WHERE transaction_id=? AND disposition IS NULL""",
                (actual, terminal_text, terminal_digest, session["transaction_id"]),
            )
            if changed.rowcount != len(reservations):
                raise _StoreCorrupt("runtime terminal reservation update mismatch")
            if connection.execute(
                "UPDATE dispatch_intents SET state=? WHERE transaction_id=? AND state='PENDING'",
                (actual, session["transaction_id"]),
            ).rowcount != 1:
                raise _StoreCorrupt("runtime terminal intent update mismatch")
            terminal_sequence = self._append_event(
                connection, "RUNTIME_SESSION_" + raw["state"], raw["session_record_id"],
                {
                    "session_record_id": raw["session_record_id"], "transaction_id": session["transaction_id"],
                    "claim_digest": session["claim_digest"], "state": raw["state"],
                    "disposition": actual, "observed_at": raw["observed_at"],
                    "revocation_epoch": _json_value(
                        connection.execute("SELECT claim_json FROM dispatch_attempt_claims WHERE transaction_id=?", (session["transaction_id"],)).fetchone()["claim_json"]
                    )["revocation_epoch"],
                    "fencing_epoch": session["fencing_epoch"],
                },
            )
            self._append_event(
                connection, "BUDGET_TERMINAL_" + actual, session["transaction_id"],
                {
                    "transaction_id": session["transaction_id"], "intent_digest": intent["intent_digest"],
                    "disposition": actual, "terminal_record_digest": terminal_digest,
                    "fencing_epoch": intent["fencing_epoch"],
                },
            )
            if connection.execute(
                """UPDATE execution_sessions SET state=?, terminal_at=?, terminal_reason=?, terminal_journal_sequence=?
                   WHERE session_record_id=? AND state='PREPARED'""",
                (raw["state"], raw["observed_at"], actual, terminal_sequence, raw["session_record_id"]),
            ).rowcount != 1:
                raise _StoreCorrupt("runtime terminal session update mismatch")
            self._hit("runtime_finalize_after_event")
            connection.commit()
            connection.close()
            connection = None
            try:
                self._hit("runtime_finalize_after_commit_before_ack")
            except Exception:
                return _result(DurableOutcome.STOP, DurableReason.ACKNOWLEDGEMENT_UNKNOWN)
            return DurableResult(
                DurableOutcome.COMMITTED, DurableReason(actual), transaction_id=session["transaction_id"],
                journal_sequence=terminal_sequence,
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
            if connection.execute(
                "SELECT 1 FROM m4_transactions WHERE transaction_id=?",
                (raw["transaction_id"],),
            ).fetchone() is not None:
                connection.rollback()
                return _result(DurableOutcome.DENY, DurableReason.ILLEGAL_TRANSITION)
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
                    SELECT i.transaction_id, i.capability_id, i.intent_digest,
                           i.idempotency_key_digest,
                           CASE
                               WHEN i.state='PENDING' AND s.session_record_id IS NOT NULL
                               THEN 'RUNTIME_SESSION_PREPARED'
                               WHEN i.state='PENDING' AND c.transaction_id IS NOT NULL
                               THEN 'ATTEMPT_CLAIMED'
                               ELSE i.state
                           END AS recovery_state,
                           i.fencing_epoch
                    FROM dispatch_intents AS i
                    LEFT JOIN dispatch_attempt_claims AS c
                      ON c.transaction_id=i.transaction_id
                    LEFT JOIN execution_sessions AS s
                      ON s.transaction_id=i.transaction_id
                    WHERE i.state IN ('PENDING', 'QUARANTINED_ESCROW')
                    ORDER BY i.dispatch_counter
                    """
                ).fetchall()
                intents = tuple(
                    RecoveryIntent(
                        row["transaction_id"],
                        row["capability_id"],
                        row["intent_digest"],
                        row["idempotency_key_digest"],
                        row["recovery_state"],
                        row["fencing_epoch"],
                    )
                    for row in rows
                )
                session_rows = connection.execute(
                    """SELECT session_record_id, transaction_id, claim_digest, state, fencing_epoch
                       FROM execution_sessions ORDER BY prepared_journal_sequence"""
                ).fetchall()
                sessions = tuple(
                    RecoverySession(
                        row["session_record_id"], row["transaction_id"], row["claim_digest"],
                        row["state"], row["fencing_epoch"],
                    )
                    for row in session_rows
                )
                m4_rows = connection.execute(
                    "SELECT transaction_id, state, contract_digest, d2_frontier_digest, fencing_epoch "
                    "FROM m4_transactions ORDER BY started_journal_sequence"
                ).fetchall()
                m4_recovery = tuple(
                    M4Recovery(
                        row["transaction_id"],
                        row["state"],
                        row["contract_digest"],
                        row["d2_frontier_digest"],
                        row["fencing_epoch"],
                    )
                    for row in m4_rows
                )
            finally:
                connection.close()
            return DurableResult(
                DurableOutcome.OK,
                DurableReason.RECOVERED,
                recovery_intents=intents,
                recovery_sessions=sessions,
                m4_recovery=m4_recovery,
            )
        except sqlite3.OperationalError as error:
            if "locked" in str(error).lower() or "busy" in str(error).lower():
                return _result(DurableOutcome.STOP, DurableReason.STORE_BUSY)
            return self._mark_corrupt()
        except Exception:
            return self._mark_corrupt()
