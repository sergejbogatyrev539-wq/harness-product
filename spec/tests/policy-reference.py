"""Executable specification model for exact-bound admission and lifecycles.

This is a pure model, not a runtime, signature verifier, path resolver,
journal, isolation mechanism, or attester. Trusted facts are model inputs.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from pathlib import PurePosixPath
import re
import unicodedata
from typing import Any, Mapping


EFFECTS = frozenset({"COMPUTE", "OBSERVE", "MUTATE", "COMMUNICATE", "DELEGATE", "REFLECT"})
SIDE_EFFECTS = frozenset({"MUTATE", "COMMUNICATE", "DELEGATE", "REFLECT"})
# Single closed relation shared with admission-candidate.schema.json.  An
# effect/resource/operation atom is never admitted by independent allowlists.
EFFECT_RESOURCE_OPERATIONS = frozenset({
    ("COMPUTE", "PROCESS", "EXECUTE"), ("COMPUTE", "COMPUTE_RESOURCE", "ALLOCATE"),
    ("OBSERVE", "FILE", "READ"), ("OBSERVE", "FILE", "LIST"),
    ("OBSERVE", "DIRECTORY", "READ"), ("OBSERVE", "DIRECTORY", "LIST"),
    ("OBSERVE", "MEMORY", "READ"), ("OBSERVE", "MEMORY", "LIST"),
    ("OBSERVE", "PROMPT", "READ"), ("OBSERVE", "PROMPT", "LIST"),
    ("OBSERVE", "POLICY", "READ"), ("OBSERVE", "POLICY", "LIST"),
    ("OBSERVE", "REGISTRY", "READ"), ("OBSERVE", "REGISTRY", "LIST"),
    ("MUTATE", "FILE", "WRITE"), ("MUTATE", "FILE", "CREATE"), ("MUTATE", "FILE", "DELETE"),
    ("MUTATE", "DIRECTORY", "WRITE"), ("MUTATE", "DIRECTORY", "CREATE"), ("MUTATE", "DIRECTORY", "DELETE"),
    ("MUTATE", "ENDPOINT", "UPDATE"), ("MUTATE", "MEMORY", "UPDATE"), ("MUTATE", "PROMPT", "UPDATE"),
    ("MUTATE", "POLICY", "UPDATE"), ("MUTATE", "REGISTRY", "UPDATE"),
    ("COMMUNICATE", "ENDPOINT", "SEND"), ("COMMUNICATE", "PRINCIPAL", "SEND"),
    ("DELEGATE", "PRINCIPAL", "SPAWN"), ("DELEGATE", "PRINCIPAL", "BIND"),
    ("REFLECT", "MEMORY", "READ"), ("REFLECT", "MEMORY", "UPDATE"),
    ("REFLECT", "PROMPT", "READ"), ("REFLECT", "PROMPT", "UPDATE"),
    ("REFLECT", "POLICY", "READ"), ("REFLECT", "POLICY", "UPDATE"),
    ("REFLECT", "REGISTRY", "READ"), ("REFLECT", "REGISTRY", "UPDATE"),
})
FACETS = frozenset({"EXECUTE_EFFECT", "AUTHORIZE_EFFECT", "DECLASSIFY_DATA", "ENDORSE_DATA", "PERSIST_SCHEDULE", "ALLOCATE_RESOURCE"})
COMPONENT_CLASSES = frozenset({"IMAGE", "RUNTIME", "KERNEL_POLICY", "TOOL", "MODEL", "PROMPT", "DEPENDENCIES", "SBOM"})
RESOURCE_CLASSES = frozenset({"CPU_TIME", "CPU_RATE", "WALL_TIME", "MEMORY", "SWAP", "PIDS", "BLOCK_IO_READ", "BLOCK_IO_WRITE", "FILES", "INODES", "OPEN_FDS", "OUTPUT_BYTES", "GPU_TIME", "GPU_MEMORY"})
# These are deliberately closed relations.  Accepting a valid unit and a valid
# enforcer independently is not sufficient: the pair must describe the
# mechanism that actually meters that resource.
RESOURCE_UNIT_ENFORCER = {
    "CPU_TIME": ("MILLISECONDS", "CGROUP_V2"), "CPU_RATE": ("MILLICORES", "CGROUP_V2"),
    "WALL_TIME": ("MILLISECONDS", "SUPERVISOR"),
    "MEMORY": ("MIB", "CGROUP_V2"),
    "SWAP": ("MIB", "CGROUP_V2"),
    "PIDS": ("COUNT", "CGROUP_V2"),
    "BLOCK_IO_READ": ("IOPS", "DEVICE_SCHEDULER"), "BLOCK_IO_WRITE": ("IOPS", "DEVICE_SCHEDULER"),
    "FILES": ("COUNT", "FILESYSTEM_QUOTA"),
    "INODES": ("COUNT", "FILESYSTEM_QUOTA"),
    "OPEN_FDS": ("COUNT", "RLIMIT"),
    "OUTPUT_BYTES": ("BYTES", "FILESYSTEM_QUOTA"),
    "GPU_TIME": ("MILLISECONDS", "DEVICE_SCHEDULER"), "GPU_MEMORY": ("MIB", "DEVICE_SCHEDULER"),
}
BROKER_IPC_ATTESTATION_FIELDS = frozenset({"attestation_digest", "isolation_profile_digest", "broker_ipc_binding_digest", "runtime_session_id", "worker_principal", "broker_principal", "worker_subject", "broker_subject", "socket_identity", "worker_fd", "broker_fd", "worker_fd_allowlist_digest", "broker_fd_allowlist_digest", "worker_endpoint_holder", "broker_endpoint_holder", "broker_observed_sender", "sender_authentication", "transport", "message_schema_digest", "operation_id", "nonce", "session_fencing_epoch", "issued_at", "expires_at", "revocation_epoch", "signature"})


def _broker_ipc_payload(attestation: Mapping[str, Any]) -> dict[str, Any]:
    return {key: deepcopy(value) for key, value in attestation.items() if key not in {"attestation_digest", "signature"}}
D2_FLAGS = ("controller_visible", "persisted", "staged", "tool_bound", "budgeted", "reusable")
D2_CLASSES = frozenset({"PLAN", "PROMPT", "CONTEXT", "CANDIDATE", "REUSABLE_BRANCH", "TOOL_BINDING", "CAPABILITY", "BUDGET_RESERVATION", "LOCK", "TARGET_BINDING", "DISPATCH_INTENT", "EXTERNAL_AUTHORIZATION", "STAGED_OUTPUT", "PERSISTED_STATE", "CONTROLLER_TOKEN"})
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{22,128}$")
ZERO_DIGEST = "sha256:" + "0" * 64
EPOCH = "1970-01-01T00:00:00Z"
ENDPOINT_BINDING_FIELDS = (
    "endpoint_id", "canonical_endpoint", "connector_id", "connector_digest",
    "method", "idempotency_key_digest", "endpoint_binding_digest",
)
ITERATION_SLOT_FIELDS = (
    "slot_id", "slot_key_digest", "authority_domain_id", "root_contract_digest",
    "journal_lineage_id", "iteration", "owner_request_digest", "fencing_epoch",
    "state", "claimed_at", "expires_at", "slot_record_digest",
)


def _iteration_slot_valid(candidate: Mapping[str, Any], trusted_facts: Mapping[str, Any]) -> bool:
    """Require an externally verified, current exclusive owner for this iteration."""
    slot = _mapping(candidate.get("iteration_slot"))
    if slot is None or set(slot) != set(ITERATION_SLOT_FIELDS):
        return False
    key = canonical_digest({key: slot.get(key) for key in ("authority_domain_id", "root_contract_digest", "journal_lineage_id", "iteration")})
    unsigned = {key: slot.get(key) for key in ITERATION_SLOT_FIELDS if key != "slot_record_digest"}
    if not (
        isinstance(slot.get("slot_id"), str) and slot.get("slot_id")
        and slot.get("slot_key_digest") == key
        and _valid_digest(slot.get("root_contract_digest"))
        and _valid_digest(slot.get("owner_request_digest"))
        and isinstance(slot.get("authority_domain_id"), str) and slot.get("authority_domain_id")
        and isinstance(slot.get("journal_lineage_id"), str) and slot.get("journal_lineage_id")
        and isinstance(slot.get("iteration"), int) and not isinstance(slot.get("iteration"), bool) and slot["iteration"] >= 1
        and isinstance(slot.get("fencing_epoch"), int) and not isinstance(slot.get("fencing_epoch"), bool) and slot["fencing_epoch"] >= 1
        and slot.get("state") == "CLAIMED"
        and slot.get("owner_request_digest") == candidate.get("request_digest")
        and slot.get("slot_record_digest") == canonical_digest(unsigned)
    ):
        return False
    claimed, expires, now = _parse_time(slot.get("claimed_at")), _parse_time(slot.get("expires_at")), _parse_time(trusted_facts.get("trusted_time"))
    records = _mapping(trusted_facts.get("active_iteration_slots")) or {}
    external = _mapping(records.get(key))
    authoritative = _mapping(external.get("slot")) if external else None
    return bool(
        claimed is not None and expires is not None and now is not None and claimed <= now < expires
        and external is not None and authoritative == slot
        and external.get("signature_verified") is True and external.get("not_revoked") is True
        and external.get("current_fence") is True and external.get("freshness_verified") is True
        and external.get("fencing_epoch") == trusted_facts.get("current_fencing_epoch") == slot.get("fencing_epoch")
        and external.get("owner_request_digest") == candidate.get("request_digest")
    )


def _trusted_admitted_iteration_slot(state: Mapping[str, Any], slot_digest: Any, request_digest: Any) -> bool:
    """Require the admitted slot to remain the current trusted exclusive claim."""
    store = _mapping(state.get("trusted_store")) or {}
    fence = state.get("fencing_epoch")
    records = _mapping(store.get("iteration_slot_verifications")) or {}
    record = _mapping(records.get(f"{slot_digest}:{fence}"))
    slot = _mapping((record or {}).get("slot"))
    if not _valid_digest(slot_digest) or not _valid_digest(request_digest) or slot is None or set(slot) != set(ITERATION_SLOT_FIELDS):
        return False
    unsigned = {key: slot.get(key) for key in ITERATION_SLOT_FIELDS if key != "slot_record_digest"}
    now, claimed, expires = _parse_time(store.get("trusted_time")), _parse_time(slot.get("claimed_at")), _parse_time(slot.get("expires_at"))
    return bool(
        slot.get("slot_record_digest") == slot_digest == canonical_digest(unsigned)
        and slot.get("owner_request_digest") == request_digest
        and slot.get("state") == "CLAIMED"
        and isinstance(slot.get("fencing_epoch"), int) and not isinstance(slot.get("fencing_epoch"), bool)
        and record is not None and record.get("slot_record_digest") == slot_digest
        and record.get("owner_request_digest") == request_digest
        and record.get("slot_fencing_epoch") == slot.get("fencing_epoch")
        and record.get("fencing_epoch") == record.get("current_fencing_epoch") == fence
        and record.get("signature_verified") is True and record.get("not_revoked") is True
        and record.get("freshness_verified") is True and record.get("current_fence") is True
        and now is not None and claimed is not None and expires is not None and claimed <= now < expires
    )


def _trusted_admitted_broker_ipc(state: Mapping[str, Any]) -> bool:
    store = _mapping(state.get("trusted_store")) or {}
    digest_value = state.get("admitted_broker_ipc_attestation_digest")
    record = _mapping((_mapping(store.get("broker_ipc_attestations")) or {}).get(digest_value))
    attestation = _mapping((record or {}).get("attestation"))
    signature = _mapping((attestation or {}).get("signature")) or {}
    unsigned = _broker_ipc_payload(attestation or {})
    now, issued, expires = (_parse_time(value) for value in (store.get("trusted_time"), (attestation or {}).get("issued_at"), (attestation or {}).get("expires_at")))
    return bool(record and attestation and set(attestation) == BROKER_IPC_ATTESTATION_FIELDS and digest_value == attestation.get("attestation_digest") == canonical_digest(unsigned) and signature.get("payload_digest") == canonical_digest(unsigned) and attestation.get("broker_ipc_binding_digest") == state.get("admitted_broker_ipc_binding_digest") and attestation.get("runtime_session_id") == (_mapping(state.get("execution_binding")) or {}).get("session_id", state.get("admitted_runtime_session_id")) and attestation.get("session_fencing_epoch") == record.get("current_fencing_epoch") == state.get("admitted_broker_ipc_fencing_epoch") and attestation.get("revocation_epoch") == record.get("current_revocation_epoch") and record.get("signed_payload") == unsigned and record.get("signed_payload_digest") == canonical_digest(unsigned) and record.get("key_id") == signature.get("key_id") and record.get("algorithm") == signature.get("algorithm") and record.get("verified_by") == signature.get("verified_by") and record.get("signature_verified") is True and record.get("freshness_verified") is True and record.get("revocation_checked") is True and record.get("not_revoked") is True and record.get("current_key") is True and now and issued and expires and issued <= now < expires)


def canonical_digest(value: Any) -> str:
    try:
        payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError):
        payload = b"<unserializable>"
    return "sha256:" + sha256(payload).hexdigest()


def _mapping(value: Any) -> Mapping[str, Any] | None:
    return value if isinstance(value, Mapping) else None


def _valid_digest(value: Any) -> bool:
    return isinstance(value, str) and DIGEST_RE.fullmatch(value) is not None


def _endpoint_binding_valid(value: Any) -> bool:
    binding = _mapping(value)
    if binding is None or set(binding) != set(ENDPOINT_BINDING_FIELDS):
        return False
    unsigned = {key: binding[key] for key in ENDPOINT_BINDING_FIELDS if key != "endpoint_binding_digest"}
    endpoint = binding.get("canonical_endpoint")
    return bool(
        isinstance(binding.get("endpoint_id"), str) and binding.get("endpoint_id")
        and isinstance(endpoint, str) and endpoint.startswith("https://") and "%" not in endpoint
        and isinstance(binding.get("connector_id"), str) and binding.get("connector_id")
        and _valid_digest(binding.get("connector_digest"))
        and isinstance(binding.get("method"), str) and re.fullmatch(r"[A-Z]{3,16}", binding["method"])
        and _valid_digest(binding.get("idempotency_key_digest"))
        and binding.get("endpoint_binding_digest") == canonical_digest(unsigned)
    )


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


REMEDIATION_REPORT_FIELDS = (
    "report_id", "packet_digest", "reported_at", "finding_ids", "readiness_impact",
    "affected_status_claims", "recommended_patch", "consequence_if_unresolved",
    "report_authority", "permitted_effects_from_report",
    "controller_state_after_report", "report_digest",
)
READINESS_IMPACTS = frozenset({
    "BLOCKS_CLAIM", "HUMAN_RISK_DECISION_REQUIRED", "NONBLOCKING", "NONE",
})
STATUS_CLAIMS = frozenset({"SPECIFIED", "IMPLEMENTED", "VERIFIED", "READY"})
CONTINUATION_CLASSES = frozenset({"PATCH", "FREEZE", "REVIEW"})
CONTINUATION_REQUEST_FIELDS = (
    "grant_id", "grant_digest", "transition_class", "report_id", "report_digest",
    "packet_digest", "finding_ids", "scope_digest", "budget_digest", "attempt", "nonce",
)
CONTINUATION_GRANT_FIELDS = (
    "grant_id", "transition_class", "report_id", "report_digest", "packet_digest",
    "finding_ids", "scope_digest", "budget_digest", "max_attempts", "nonce",
    "issued_at", "expires_at", "signature", "grant_digest",
)
CONTINUATION_GRANT_RECORD_FIELDS = (
    "grant", "grant_digest", "signed_payload_digest", "signature", "signature_verified",
    "freshness_verified", "revocation_checked", "not_revoked", "current_key", "verified_by",
    "authorization_source", "authorized_subject", "authority_role", "explicit_user_instruction_verified",
)


def _nonempty_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _sorted_unique_strings(value: Any) -> bool:
    return isinstance(value, list) and all(_nonempty_text(item) for item in value) and value == sorted(set(value))


def _remediation_report_valid(report: Any) -> bool:
    """Validate the closed, non-authorizing remediation-report projection."""
    report = _mapping(report)
    if report is None or set(report) != set(REMEDIATION_REPORT_FIELDS):
        return False
    findings, claims, impact = report.get("finding_ids"), report.get("affected_status_claims"), report.get("readiness_impact")
    if not (
        _nonempty_text(report.get("report_id"))
        and _valid_digest(report.get("packet_digest"))
        and _parse_time(report.get("reported_at")) is not None
        and _sorted_unique_strings(findings)
        and _sorted_unique_strings(claims)
        and set(claims).issubset(STATUS_CLAIMS)
        and impact in READINESS_IMPACTS
        and _nonempty_text(report.get("recommended_patch"))
        and _nonempty_text(report.get("consequence_if_unresolved"))
        and report.get("report_authority") == "NONE"
        and report.get("permitted_effects_from_report") == []
        and report.get("controller_state_after_report") == "STOPPED_AWAITING_EXPLICIT_USER_INSTRUCTION"
    ):
        return False
    # A nonblocking item may be reported, but it must not make a status claim
    # unavailable.  A no-op report has neither findings nor affected claims.
    if impact in {"BLOCKS_CLAIM", "HUMAN_RISK_DECISION_REQUIRED"}:
        relation_valid = bool(findings) and bool(claims)
    elif impact == "NONBLOCKING":
        relation_valid = bool(findings) and not claims
    else:
        relation_valid = not findings and not claims
    unsigned = {key: report[key] for key in REMEDIATION_REPORT_FIELDS if key != "report_digest"}
    return bool(relation_valid and report.get("report_digest") == canonical_digest(unsigned))


def _continuation_stop(detail: str) -> dict[str, Any]:
    if detail == "REMEDIATION_REPORT_INVALID":
        reason_code = "RC_REPORT_INVALID"
    elif detail == "EXPLICIT_CONTINUATION_REQUEST_REQUIRED":
        reason_code = "RC_REPORT_NONAUTHORIZING"
    else:
        reason_code = "RC_CONTINUATION_GRANT_INVALID"
    return {
        "decision": "STOP",
        "reason_code": reason_code,
        "detail": detail,
        "state": "STOPPED_AWAITING_EXPLICIT_USER_INSTRUCTION",
        "authorized_transition": None,
        "next_trusted_facts": None,
    }


def _continuation_grant_valid(grant: Any, record: Any, trusted_facts: Mapping[str, Any]) -> bool:
    grant, record = _mapping(grant), _mapping(record)
    if grant is None or record is None or set(grant) != set(CONTINUATION_GRANT_FIELDS) or set(record) != set(CONTINUATION_GRANT_RECORD_FIELDS):
        return False
    unsigned = {key: grant[key] for key in CONTINUATION_GRANT_FIELDS if key != "grant_digest"}
    issued, expires, now = _parse_time(grant.get("issued_at")), _parse_time(grant.get("expires_at")), _parse_time(trusted_facts.get("trusted_time"))
    trusted_verifiers = trusted_facts.get("trusted_continuation_verifiers")
    return bool(
        _nonempty_text(grant.get("grant_id"))
        and grant.get("transition_class") in CONTINUATION_CLASSES
        and _nonempty_text(grant.get("report_id"))
        and _valid_digest(grant.get("report_digest")) and _valid_digest(grant.get("packet_digest"))
        and _sorted_unique_strings(grant.get("finding_ids")) and bool(grant["finding_ids"])
        and _valid_digest(grant.get("scope_digest")) and _valid_digest(grant.get("budget_digest"))
        and grant.get("max_attempts") == 1
        and isinstance(grant.get("nonce"), str) and NONCE_RE.fullmatch(grant["nonce"]) is not None
        and _nonempty_text(grant.get("signature"))
        and grant.get("grant_digest") == canonical_digest(unsigned)
        and record.get("grant") == grant
        and record.get("grant_digest") == grant["grant_digest"] == record.get("signed_payload_digest")
        and record.get("signature") == grant["signature"]
        and all(record.get(key) is True for key in ("signature_verified", "freshness_verified", "revocation_checked", "not_revoked", "current_key"))
        and record.get("authorization_source") == "EXPLICIT_USER_INSTRUCTION"
        and _nonempty_text(record.get("authorized_subject"))
        and record.get("authority_role") == "USER"
        and record.get("explicit_user_instruction_verified") is True
        and isinstance(trusted_verifiers, list) and record.get("verified_by") in trusted_verifiers
        and issued is not None and expires is not None and now is not None and issued <= now < expires
    )


def decide_review_continuation(report: Any, request: Any, trusted_facts: Any) -> dict[str, Any]:
    """Model an atomic exact-bound continuation transition.

    The function is pure: success returns the durable post-consumption facts that
    a controller must commit atomically with the authorized transition.
    """
    if not _remediation_report_valid(report):
        return _continuation_stop("REMEDIATION_REPORT_INVALID")
    if request is None:
        return _continuation_stop("EXPLICIT_CONTINUATION_REQUEST_REQUIRED")
    request, facts = _mapping(request), _mapping(trusted_facts)
    if request is None or set(request) != set(CONTINUATION_REQUEST_FIELDS):
        return _continuation_stop("CONTINUATION_REQUEST_INVALID")
    if not (
        _nonempty_text(request.get("grant_id")) and _valid_digest(request.get("grant_digest"))
        and request.get("transition_class") in CONTINUATION_CLASSES
        and _nonempty_text(request.get("report_id")) and _valid_digest(request.get("report_digest"))
        and _valid_digest(request.get("packet_digest")) and _sorted_unique_strings(request.get("finding_ids")) and bool(request["finding_ids"])
        and _valid_digest(request.get("scope_digest")) and _valid_digest(request.get("budget_digest"))
        and isinstance(request.get("attempt"), int) and not isinstance(request.get("attempt"), bool) and request["attempt"] >= 1
        and isinstance(request.get("nonce"), str) and NONCE_RE.fullmatch(request["nonce"]) is not None
    ):
        return _continuation_stop("CONTINUATION_REQUEST_INVALID")
    if request["report_id"] != report["report_id"] or request["report_digest"] != report["report_digest"]:
        return _continuation_stop("CONTINUATION_REPORT_BINDING_MISMATCH")
    if request["packet_digest"] != report["packet_digest"]:
        return _continuation_stop("CONTINUATION_PACKET_BINDING_MISMATCH")
    if not set(request["finding_ids"]).issubset(report["finding_ids"]):
        return _continuation_stop("CONTINUATION_FINDING_SCOPE_INVALID")
    if facts is None:
        return _continuation_stop("EXTERNAL_CONTINUATION_GRANT_INVALID")
    if any(facts.get(field) != request[request_field] for field, request_field in (
        ("current_packet_digest", "packet_digest"),
        ("current_scope_digest", "scope_digest"),
        ("current_budget_digest", "budget_digest"),
        ("current_attempt", "attempt"),
    )):
        return _continuation_stop("CONTINUATION_CURRENT_STATE_MISMATCH")
    grants = _mapping(facts.get("verified_continuation_grants"))
    consumed_ids, consumed_nonces = facts.get("consumed_continuation_grant_ids"), facts.get("consumed_continuation_nonces")
    if grants is None or not isinstance(consumed_ids, list) or not isinstance(consumed_nonces, list):
        return _continuation_stop("EXTERNAL_CONTINUATION_GRANT_INVALID")
    record = _mapping(grants.get(request["grant_id"]))
    grant = _mapping((record or {}).get("grant"))
    if not _continuation_grant_valid(grant, record, facts):
        return _continuation_stop("EXTERNAL_CONTINUATION_GRANT_INVALID")
    if _parse_time(grant.get("issued_at")) <= _parse_time(report.get("reported_at")):
        return _continuation_stop("CONTINUATION_GRANT_PREDATES_REPORT")
    if grant["grant_id"] in consumed_ids:
        return _continuation_stop("CONTINUATION_GRANT_ALREADY_CONSUMED")
    if grant["nonce"] in consumed_nonces:
        return _continuation_stop("CONTINUATION_NONCE_REPLAYED")
    exact_fields = (
        "grant_id", "grant_digest", "transition_class", "report_id", "report_digest",
        "packet_digest", "finding_ids", "scope_digest", "budget_digest", "nonce",
    )
    if any(request[field] != grant[field] for field in exact_fields):
        return _continuation_stop("CONTINUATION_GRANT_BINDING_MISMATCH")
    if request["attempt"] > grant["max_attempts"]:
        return _continuation_stop("CONTINUATION_ATTEMPT_LIMIT_EXCEEDED")
    next_facts = deepcopy(dict(facts))
    next_facts["consumed_continuation_grant_ids"] = sorted(set(consumed_ids) | {grant["grant_id"]})
    next_facts["consumed_continuation_nonces"] = sorted(set(consumed_nonces) | {grant["nonce"]})
    return {
        "decision": "AUTHORIZE_CONTINUATION",
        "reason_code": "RC_CONTINUATION_EXACT_BOUND",
        "detail": "EXACT_EXTERNAL_SINGLE_USE_GRANT_VERIFIED",
        "state": "AUTHORIZED_EXPLICIT_CONTINUATION",
        "authorized_transition": {
            "transition_class": request["transition_class"],
            "grant_id": grant["grant_id"],
            "grant_digest": grant["grant_digest"],
            "report_digest": report["report_digest"],
            "packet_digest": report["packet_digest"],
        },
        "next_trusted_facts": next_facts,
    }


def _self_digest_valid(value: Mapping[str, Any], field: str) -> bool:
    unsigned = dict(value)
    claimed = unsigned.pop(field, None)
    return claimed == canonical_digest(unsigned)


def _control_content_digest(artifact: Mapping[str, Any], digest_field: str, activation_field: str) -> str:
    """Exclude only self-referential digest/activation bindings from control content."""
    def strip_self(value: Any) -> Any:
        if isinstance(value, Mapping):
            risk_evidence = "evidence_id" in value and "risk_id" in value
            return {
                key: ({nested_key: strip_self(nested_value) for nested_key, nested_value in item.items() if nested_key != "payload_digest"} if risk_evidence and key == "signed_payload" and isinstance(item, Mapping) else strip_self(item))
                for key, item in value.items() if key != digest_field
            }
        if isinstance(value, list):
            return [strip_self(item) for item in value]
        return value
    payload = deepcopy(dict(artifact))
    payload.pop(activation_field, None)
    return canonical_digest(strip_self(payload))


def _typed_effect_row_valid(row: Any) -> bool:
    """Apply the one closed effect/resource/operation relation to every row shape."""
    if not isinstance(row, Mapping):
        return False
    operations = row.get("operations")
    if operations is None:
        operations = [row.get("operation")]
    scope = _mapping(row.get("scope")) or {}
    return (
        isinstance(operations, list) and bool(operations)
        and len(operations) == len(set(operations))
        and all((row.get("effect"), row.get("resource_kind"), operation) in EFFECT_RESOURCE_OPERATIONS for operation in operations)
        and (scope.get("kind") != "PATH" or isinstance(scope.get("values"), list) and bool(scope["values"]) and all(_canonical_path(value) for value in scope["values"]))
    )


def _budget_map(rows: Any, field: str, *, reject_duplicates: bool = True) -> dict[tuple[str, str, str, str], int] | None:
    if not isinstance(rows, list):
        return None
    result: dict[tuple[str, str, str, str], int] = {}
    for row in rows:
        if not isinstance(row, Mapping):
            return None
        name, unit, amount = row.get("name"), row.get("unit"), row.get(field)
        if not isinstance(name, str) or not isinstance(unit, str) or not isinstance(amount, int) or isinstance(amount, bool) or amount < 0:
            return None
        scope_digest, lineage_root = row.get("scope_digest"), row.get("lineage_root")
        if not _valid_digest(scope_digest) or not isinstance(lineage_root, str) or not lineage_root:
            return None
        key = (name, unit, scope_digest, lineage_root)
        if reject_duplicates and key in result:
            return None
        result[key] = result.get(key, 0) + amount
    return result


def _remaining_escrow(limits: Any, spent: Any, reserved: Any) -> dict[tuple[str, str, str, str], int] | None:
    """Return per-key remaining escrow; absent or overspent keys are invalid."""
    limit_map = _budget_map(limits, "amount")
    spent_map = _budget_map(spent, "amount")
    reserved_map = _budget_map(reserved, "amount")
    if limit_map is None or spent_map is None or reserved_map is None:
        return None
    if any(key not in limit_map for key in set(spent_map) | set(reserved_map)):
        return None
    remaining = {key: limit - spent_map.get(key, 0) - reserved_map.get(key, 0) for key, limit in limit_map.items()}
    return remaining if all(amount >= 0 for amount in remaining.values()) else None


def _delegation_escrow_valid(rows: Any, child_budgets: Any) -> bool:
    if not isinstance(rows, list) or not isinstance(child_budgets, list):
        return False
    limits, spent, reserved = [], [], []
    for row in rows:
        if not isinstance(row, Mapping) or set(row) != {"name", "unit", "scope_digest", "lineage_root", "limit", "spent", "reserved", "remaining"}:
            return False
        base = {key: row.get(key) for key in ("name", "unit", "scope_digest", "lineage_root")}
        limits.append({**base, "amount": row.get("limit")})
        spent.append({**base, "amount": row.get("spent")})
        reserved.append({**base, "amount": row.get("reserved")})
    remaining = _remaining_escrow(limits, spent, reserved)
    children = _budget_map(child_budgets, "amount", reject_duplicates=False)
    return bool(remaining is not None and children is not None and all(row.get("remaining") == remaining.get((row["name"], row["unit"], row["scope_digest"], row["lineage_root"])) for row in rows) and all(amount <= remaining.get(key, -1) for key, amount in children.items()))


def _ledger_children_within_escrow(children: Any, capability_id: Any, child_budgets: Any, escrow: Any) -> bool:
    """Aggregate durable sibling reservations by the full budget key, never scalar totals."""
    if not isinstance(children, list) or not isinstance(capability_id, str):
        return False
    limits, spent, reserved = [], [], []
    for row in escrow if isinstance(escrow, list) else []:
        if not isinstance(row, Mapping):
            return False
        base = {key: row.get(key) for key in ("name", "unit", "scope_digest", "lineage_root")}
        limits.append({**base, "amount": row.get("limit")})
        spent.append({**base, "amount": row.get("spent")})
        reserved.append({**base, "amount": row.get("reserved")})
    remaining = _remaining_escrow(limits, spent, reserved)
    if remaining is None or len({row.get("capability_id") for row in children if isinstance(row, Mapping)}) != len(children):
        return False
    totals: dict[tuple[str, str, str, str], int] = {}
    for row in children:
        if not isinstance(row, Mapping) or not isinstance(row.get("capability_id"), str):
            return False
        if row["capability_id"] == capability_id:
            mapped = _budget_map(child_budgets, "amount", reject_duplicates=False)
            if mapped is None or ("amount" in row and row.get("amount") != sum(mapped.values())):
                return False
        elif isinstance(row.get("budget_escrow"), list):
            mapped = _budget_map(row["budget_escrow"], "amount", reject_duplicates=False)
            if mapped is None:
                return False
        elif row.get("amount") == 0:  # Legacy zero-reservation marker has no authority to spend a key.
            mapped = {}
        else:
            return False
        for key, amount in mapped.items():
            totals[key] = totals.get(key, 0) + amount
    return all(amount <= remaining.get(key, -1) for key, amount in totals.items())


def budget_reservations(demands: Any, *bounds: tuple[Any, str]) -> tuple[dict[str, Any], ...] | None:
    """Aggregate demand duplicates; reject duplicate bounds; preserve quantity."""
    demand_map = _budget_map(demands, "amount", reject_duplicates=False)
    if not demand_map:
        return None
    bound_maps = []
    for rows, field in bounds:
        mapped = _budget_map(rows, field, reject_duplicates=True)
        if mapped is None:
            return None
        bound_maps.append(mapped)
    if any(any(key not in bound or amount > bound[key] for bound in bound_maps) for key, amount in demand_map.items()):
        return None
    return tuple({"name": name, "unit": unit, "scope_digest": scope_digest, "lineage_root": lineage_root, "amount": demand_map[(name, unit, scope_digest, lineage_root)]} for name, unit, scope_digest, lineage_root in sorted(demand_map))


def _canonical_path(value: Any) -> bool:
    if not isinstance(value, str) or not value.startswith("/") or value.startswith("//") or "\\" in value or "%" in value:
        return False
    if any(unicodedata.category(char) in {"Cc", "Cf"} or char in {"\u2044", "\u2215", "\uff0f", "\uff3c"} for char in value):
        return False
    if any(part in {".", ".."} for part in value.split("/")):
        return False
    return (value == "/workspace" or value.startswith("/workspace/")) and (str(PurePosixPath(value)) == value.rstrip("/") or value == "/workspace")


def _activation_valid(artifact: Mapping[str, Any], digest_field: str, activation_field: str, trusted_records: Any, registry_reference: Any, now: Any) -> bool:
    """A complete control artifact is usable only through its fresh trusted activation."""
    activation = _mapping(artifact.get(activation_field))
    digest = artifact.get(digest_field)
    trusted = _mapping((_mapping(trusted_records) or {}).get(digest))
    issued, expires, now = _parse_time((activation or {}).get("issued_at")), _parse_time((activation or {}).get("expires_at")), _parse_time(now)
    return bool(
        activation and trusted and _valid_digest(digest) and digest == _control_content_digest(artifact, digest_field, activation_field)
        and activation.get("content_digest") == digest
        and isinstance(activation.get("registry_reference"), str) and activation.get("registry_reference") and (registry_reference is None or activation.get("registry_reference") == registry_reference)
        and isinstance(activation.get("generation"), int) and isinstance(activation.get("rollback_floor"), int)
        and activation["generation"] >= activation["rollback_floor"]
        and issued and expires and now and issued <= now < expires
        and _valid_digest(activation.get("signature")) and activation.get("external_verification") is True
        and all(trusted.get(key) == activation.get(key) for key in ("content_digest", "generation", "rollback_floor", "registry_reference"))
        and trusted.get("signature") == activation.get("signature") and trusted.get("signature_verified") is True and trusted.get("not_revoked") is True and trusted.get("freshness_verified") is True and trusted.get("revocation_checked") is True and trusted.get("verified_by")
    )


def validate_authority_entry(entry: Any) -> bool:
    if not isinstance(entry, Mapping):
        return False
    effect, kind, operation = entry.get("effect"), entry.get("resource_kind"), entry.get("operation")
    facets, selector, constraints = entry.get("facets"), _mapping(entry.get("selector")), _mapping(entry.get("constraints"))
    if (effect, kind, operation) not in EFFECT_RESOURCE_OPERATIONS or not isinstance(facets, list) or not facets or len(facets) != len(set(facets)) or not set(facets) <= FACETS or selector is None or constraints is None:
        return False
    temporal, quantity = _mapping(constraints.get("temporal")), _mapping(constraints.get("quantity"))
    start, end = _parse_time((temporal or {}).get("not_before")), _parse_time((temporal or {}).get("not_after"))
    label, flows, obligations = _mapping(constraints.get("data_label")), constraints.get("flows"), constraints.get("obligations")
    if constraints.get("direction") not in {"IN", "OUT", "INTERNAL", "BIDIRECTIONAL"} or label is None or temporal is None or quantity is None or start is None or end is None or start >= end:
        return False
    if not isinstance(temporal.get("max_duration_ms"), int) or temporal["max_duration_ms"] < 1 or not isinstance(quantity.get("limit"), int) or quantity["limit"] < 0 or not isinstance(quantity.get("unit"), str) or not isinstance(constraints.get("max_concurrency"), int) or constraints["max_concurrency"] < 1:
        return False
    if not isinstance(flows, list) or not all(isinstance(item, Mapping) for item in flows) or not isinstance(obligations, list) or len(obligations) != len(set(obligations)) or not all(isinstance(item, str) for item in obligations):
        return False
    if effect == "OBSERVE" and (operation not in {"READ", "LIST"} or kind not in {"FILE", "DIRECTORY", "MEMORY", "PROMPT", "POLICY", "REGISTRY"}):
        return False
    if effect == "COMMUNICATE" and (operation != "SEND" or kind not in {"ENDPOINT", "PRINCIPAL"}):
        return False
    if kind in {"FILE", "DIRECTORY"}:
        return bool(selector.get("kind") == "PATH_DESCRIPTOR" and _canonical_path(selector.get("canonical_path", selector.get("canonical_value"))) and isinstance(selector.get("descriptor_id", selector.get("reference")), str) and selector.get("resolution") == "DESCRIPTOR_PROVEN_BENEATH_NO_MAGICLINKS" and _valid_digest(selector.get("physical_target_digest")))
    if kind == "ENDPOINT":
        return bool(selector.get("kind") == "ENDPOINT_DESCRIPTOR" and selector.get("resolution") == "PINNED_EXACT_ENDPOINT" and _endpoint_binding_valid({key: selector.get(key) for key in ENDPOINT_BINDING_FIELDS}))
    return selector.get("kind") == "LOCAL_RESOURCE" and selector.get("resolution") == "EXACT_REGISTRY_ID"


def _selected_authority(candidate: Mapping[str, Any]) -> list[dict[str, Any]] | None:
    alternatives, selected = candidate.get("authority_alternatives"), candidate.get("selected_alternative_id")
    if not isinstance(alternatives, list):
        return None
    ids = [item.get("alternative_id") for item in alternatives if isinstance(item, Mapping)]
    if len(ids) != len(alternatives) or len(ids) != len(set(ids)) or ids.count(selected) != 1:
        return None
    entries = alternatives[ids.index(selected)].get("entries")
    if not isinstance(entries, list) or not entries or not all(validate_authority_entry(item) for item in entries):
        return None
    entry_ids = [item.get("entry_id") for item in entries]
    return deepcopy(entries) if len(entry_ids) == len(set(entry_ids)) else None


def _selected_target_binding_valid(entries: Any, bindings: Any) -> bool:
    """Bind the selected alternative, not array position, to one target kind."""
    bindings = _mapping(bindings)
    if not isinstance(entries, list) or not entries or bindings is None:
        return False
    endpoint_entries = [item for item in entries if isinstance(item, Mapping) and item.get("resource_kind") == "ENDPOINT"]
    if endpoint_entries:
        digest = bindings.get("endpoint_binding_digest")
        selected_digests = {
            ((_mapping((_mapping(item.get("selector")) or {}).get("endpoint_binding")) or _mapping(item.get("selector")) or {}).get("endpoint_binding_digest"))
            for item in endpoint_entries
        }
        return bool(
            len(endpoint_entries) == len(entries)
            and _valid_digest(digest)
            and "descriptor_binding_digest" not in bindings
            and selected_digests == {digest}
        )
    digest = bindings.get("descriptor_binding_digest")
    filesystem_entries = [item for item in entries if isinstance(item, Mapping) and item.get("resource_kind") in {"FILE", "DIRECTORY"}]
    return bool(
        _valid_digest(digest)
        and "endpoint_binding_digest" not in bindings
        and (not filesystem_entries or {(_mapping(item.get("selector")) or {}).get("descriptor_binding_digest") for item in filesystem_entries} == {digest})
    )


def _decision_entry(entry: Mapping[str, Any]) -> dict[str, Any]:
    selector = entry["selector"]
    if selector["kind"] == "PATH_DESCRIPTOR":
        reference, value = selector["descriptor_id"], selector["canonical_path"]
    elif selector["kind"] == "ENDPOINT_DESCRIPTOR":
        reference, value = selector["endpoint_id"], selector["canonical_endpoint"]
    else:
        reference = value = selector["resource_id"]
    canonical_selector = {"kind": selector["kind"], "reference": reference, "canonical_value": value, "resolution": selector["resolution"]}
    if selector["kind"] == "PATH_DESCRIPTOR":
        canonical_selector.update(descriptor_binding_digest=selector.get("descriptor_binding_digest"), physical_target_digest=selector.get("physical_target_digest"))
    elif selector["kind"] == "ENDPOINT_DESCRIPTOR":
        canonical_selector["endpoint_binding"] = {key: selector.get(key) for key in ENDPOINT_BINDING_FIELDS}
    return {"entry_id": entry["entry_id"], "effect": entry["effect"], "resource_kind": entry["resource_kind"], "operation": entry["operation"], "selector": canonical_selector, "facets": list(entry["facets"]), "constraints": deepcopy(entry["constraints"])}


def validate_d2_frontier(candidate: Mapping[str, Any], durable_facts: Mapping[str, Any]) -> bool:
    frontier, iteration = _mapping(candidate.get("d2_frontier")), candidate.get("iteration")
    if frontier is None or not isinstance(iteration, int) or isinstance(iteration, bool):
        return False
    joined, maximum, inventory = frontier.get("joined_iteration"), frontier.get("max_iteration"), frontier.get("inventory")
    if not isinstance(joined, int) or isinstance(joined, bool) or not isinstance(maximum, int) or isinstance(maximum, bool) or not isinstance(inventory, list) or iteration != joined + 1 or iteration > maximum:
        return False
    authoritative = _mapping(durable_facts.get("authoritative_d2_frontier"))
    if authoritative is None or not isinstance(authoritative.get("inventory"), list) or not authoritative.get("inventory"):
        return False
    bindings = _mapping(candidate.get("bindings")) or {}
    identity_fields = (
        "contract_digest", "contract_version", "authority_domain_id",
        "journal_lineage_id", "root_contract_digest", "parent_contract_digest",
        "journal_sequence", "fencing_epoch", "durable_state_digest",
        "joined_iteration", "max_iteration", "inventory",
    )
    unsigned = {key: deepcopy(value) for key, value in frontier.items() if key != "frontier_record_digest"}
    if (
        frontier.get("contract_digest") != bindings.get("contract_digest")
        or frontier.get("contract_version") != "1.0.0"
        or not all(isinstance(frontier.get(key), str) and frontier.get(key) for key in ("authority_domain_id", "journal_lineage_id"))
        or not all(_valid_digest(frontier.get(key)) for key in ("contract_digest", "root_contract_digest", "frontier_record_digest"))
        or frontier.get("parent_contract_digest") is not None and not _valid_digest(frontier.get("parent_contract_digest"))
        or not isinstance(frontier.get("journal_sequence"), int) or isinstance(frontier.get("journal_sequence"), bool) or frontier.get("journal_sequence") < 0
        or not isinstance(frontier.get("fencing_epoch"), int) or isinstance(frontier.get("fencing_epoch"), bool) or frontier.get("fencing_epoch") < 1
        or frontier.get("fencing_epoch") != durable_facts.get("current_fencing_epoch")
        or frontier.get("frontier_record_digest") != canonical_digest(unsigned)
        or frontier.get("frontier_record_digest") != durable_facts.get("d2_frontier_digest")
        or any(authoritative.get(key) != frontier.get(key) for key in identity_fields)
        or authoritative.get("frontier_record_digest") != frontier.get("frontier_record_digest")
        or authoritative.get("signature_verified") is not True
        or authoritative.get("not_revoked") is not True
        or authoritative.get("freshness_verified") is not True
        or not authoritative.get("verified_by")
    ):
        return False
    required = durable_facts.get("required_d2_artifacts")
    if not isinstance(required, list) or not required or any(not isinstance(item, Mapping) or not isinstance(item.get("artifact_id"), str) or not isinstance(item.get("class"), str) for item in required):
        return False
    if frontier.get("durable_state_digest") != canonical_digest(frontier.get("inventory")) or frontier.get("durable_state_digest") != authoritative.get("durable_state_digest"):
        return False
    present = {(item.get("artifact_id"), item.get("class")) for item in inventory if isinstance(item, Mapping)}
    authoritative_present = {(item.get("artifact_id"), item.get("class")) for item in authoritative.get("inventory", []) if isinstance(item, Mapping)}
    required_keys = {(item["artifact_id"], item["class"]) for item in required}
    return required_keys <= present and required_keys <= authoritative_present and all(isinstance(item, Mapping) and item.get("class") in D2_CLASSES and isinstance(item.get("iteration"), int) and item["iteration"] < joined + 2 for item in inventory)


def _trusted_roots_digest(candidate: Mapping[str, Any], isolation_profile: Mapping[str, Any], trusted_facts: Mapping[str, Any]) -> str | None:
    """Return the one trusted root identity shared by candidate/profile/facts."""
    candidate_root = (_mapping(candidate.get("supply_chain")) or {}).get("trusted_roots_digest")
    profile_root = (_mapping(isolation_profile.get("supply_chain")) or {}).get("trusted_roots_digest")
    if not _valid_digest(candidate_root) or not _valid_digest(profile_root) or candidate_root != profile_root:
        return None
    external = []
    for key in ("trusted_roots_digest", "trusted_root_digest", "trusted_supply_roots_digest", "verified_trusted_roots_digest"):
        value = trusted_facts.get(key)
        if value is not None:
            external.append(value)
    records = _mapping(trusted_facts.get("verified_supply_components")) or {}
    for record in records.values():
        if not isinstance(record, Mapping) or record.get("trusted_roots_digest") != candidate_root:
            return None
        for key in ("trusted_roots_digest", "trusted_root_digest", "trust_roots_digest", "root_digest"):
            if record.get(key) is not None:
                external.append(record.get(key))
    if not external or any(not _valid_digest(value) for value in external) or any(value != candidate_root for value in external):
        return None
    return candidate_root


def validate_supply_chain(candidate: Mapping[str, Any], isolation_profile: Mapping[str, Any] | None = None, trusted_facts: Mapping[str, Any] | None = None) -> bool:
    supply, bindings = _mapping(candidate.get("supply_chain")), _mapping(candidate.get("bindings")) or {}
    facts = _mapping(trusted_facts) or {}
    if supply is None or not isinstance(supply.get("components"), list) or not isinstance(isolation_profile, Mapping):
        return False
    roots_digest = _trusted_roots_digest(candidate, isolation_profile, facts)
    if roots_digest is None:
        return False
    components = supply["components"]
    classes = [item.get("component") for item in components if isinstance(item, Mapping)]
    if set(classes) != COMPONENT_CLASSES or len(classes) != len(set(classes)):
        return False
    required_revocation, rollback_floor = supply.get("required_revocation_epoch"), supply.get("required_rollback_floor")
    if not isinstance(required_revocation, int) or not isinstance(rollback_floor, int):
        return False
    trusted_components = _mapping(facts.get("verified_supply_components")) or {}
    if not trusted_components:
        return False
    for item in components:
        if item.get("signature_verified") is not True or not _valid_digest(item.get("exact_bytes_digest")) or item.get("revocation_epoch", -1) < required_revocation or item.get("rollback_floor") != rollback_floor or item.get("registry_generation", -1) < rollback_floor:
            return False
        trusted = _mapping(trusted_components.get(item.get("component")))
        registry_digest = supply.get("registry_snapshot_digest", _mapping((isolation_profile or {}).get("supply_chain")) .get("registry_snapshot_digest") if _mapping((isolation_profile or {}).get("supply_chain")) else None)
        if trusted is None or trusted.get("component") != item.get("component") or trusted.get("component_digest") != canonical_digest(item) or trusted.get("exact_bytes_digest") != item.get("exact_bytes_digest") or trusted.get("provenance_digest") != item.get("provenance_digest") or trusted.get("registry_digest") != registry_digest or trusted.get("revocation_epoch") != item.get("revocation_epoch") or trusted.get("registry_generation") != item.get("registry_generation") or trusted.get("rollback_floor") != item.get("rollback_floor") or trusted.get("loaded_bytes_digest") != item.get("exact_bytes_digest") or trusted.get("placement_measurement_digest") != supply.get("composite_measurement_digest") or trusted.get("signature_verified") is not True or trusted.get("not_revoked") is not True:
            return False
    # The root identity is part of the measured preimage.  Otherwise an
    # attacker can substitute a different trust root while preserving the
    # component list digest.
    measured = canonical_digest({"trusted_roots_digest": roots_digest, "components": components})
    placement = _mapping(candidate.get("placement_attestation")) or {}
    session = _mapping(candidate.get("session_attestation")) or {}
    profile_supply = _mapping((isolation_profile or {}).get("supply_chain")) or {}
    return (
        supply.get("composite_measurement_digest") == measured == bindings.get("supply_chain_measurement_digest")
        and placement.get("measurement_digest") == measured
        and session.get("measurement_digest") == measured
        and profile_supply.get("composite_measurement_digest") == measured
        and profile_supply.get("trusted_roots_digest") == roots_digest
    )


def validate_attestations(candidate: Mapping[str, Any], trusted_facts: Mapping[str, Any]) -> bool:
    bindings = _mapping(candidate.get("bindings")) or {}
    placement, session, now = _mapping(candidate.get("placement_attestation")), _mapping(candidate.get("session_attestation")), _parse_time(candidate.get("evaluated_at"))
    if placement is None or session is None or now is None:
        return False
    if placement.get("attestation_digest") != bindings.get("placement_attestation_digest") or session.get("attestation_digest") != bindings.get("session_attestation_digest") or placement.get("isolation_profile_digest") != bindings.get("isolation_profile_digest") or session.get("placement_attestation_digest") != placement.get("attestation_digest") or session.get("contract_digest") != bindings.get("contract_digest") or session.get("subject_instance_id") != placement.get("subject_instance_id") or placement.get("epoch") != session.get("epoch") or placement.get("nonce") == session.get("nonce") or placement.get("measurement_digest") != session.get("measurement_digest"):
        return False
    for item, expected_session, expected_placement in ((placement, None, placement.get("attestation_digest")), (session, session.get("session_id"), placement.get("attestation_digest"))):
        issued, expires, signature = _parse_time(item.get("issued_at")), _parse_time(item.get("expires_at")), _mapping(item.get("signature"))
        if issued is None or expires is None or not issued <= now < expires or signature is None or not isinstance(signature.get("verified_by"), str) or not _valid_digest(signature.get("payload_digest")):
            return False
        facts = _mapping((_mapping(trusted_facts.get("verified_attestations")) or {}).get(item.get("attestation_digest"))) or {}
        if facts.get("signature_verified") is not True or facts.get("key_id") != signature.get("key_id") or facts.get("payload_digest") != signature.get("payload_digest") or facts.get("subject") != item.get("subject_instance_id") or facts.get("measurement_digest") != item.get("measurement_digest") or facts.get("placement_digest") != expected_placement or (expected_session is not None and facts.get("session_id") != expected_session) or facts.get("freshness_verified") is not True or facts.get("revocation_checked") is not True or not isinstance(facts.get("trust_root"), str):
            return False
        # Every accepted attestor record binds the complete unsigned payload.
        # Partial verifier records would let a caller refresh signed fields.
        aliases = {
            "attestation_digest": ("attestation_digest",), "subject_instance_id": ("subject_instance_id", "subject"),
            "host_id": ("host_id", "host"), "nonce": ("nonce", "placement_nonce", "session_nonce"), "epoch": ("epoch", "fence_epoch", "fencing_epoch"),
            "issued_at": ("issued_at",), "expires_at": ("expires_at",),
            "isolation_profile_digest": ("isolation_profile_digest",), "measurement_digest": ("measurement_digest",),
            "session_id": ("session_id",), "placement_attestation_digest": ("placement_attestation_digest",),
            "contract_digest": ("contract_digest",),
        }
        for field, record_fields in aliases.items():
            if field not in item:
                continue
            record_field = next((key for key in record_fields if key in facts), None)
            if record_field is not None and facts.get(record_field) != item.get(field):
                return False
        if facts.get("algorithm") != signature.get("algorithm") or facts.get("verified_by") != signature.get("verified_by"):
            return False
        signed_projection = _mapping(facts.get("signed_payload")) or _mapping(facts.get("signed_fields"))
        unsigned = {key: deepcopy(value) for key, value in item.items() if key != "signature"}
        expected_signed_digest = facts.get("signed_payload_digest")
        if signed_projection != unsigned or expected_signed_digest != signature.get("payload_digest") or expected_signed_digest != canonical_digest(unsigned):
            return False
    return True


def _approval_receipt_digest(receipt: Mapping[str, Any]) -> str:
    """Digest the complete closed receipt; the schema intentionally has no digest field."""
    return canonical_digest(receipt)


def _approval_material_digest(receipt: Mapping[str, Any]) -> str:
    return canonical_digest(receipt.get("material_terms"))


def _approval_view_preimage(receipt: Mapping[str, Any]) -> dict[str, Any]:
    terms = deepcopy(_mapping(receipt.get("material_terms")) or {})
    for key in ("presentation", "teach_back", "freshness"):
        terms.pop(key, None)
    return {"intent": deepcopy(receipt.get("intent")), "targets": deepcopy(receipt.get("targets")), "effects": deepcopy(receipt.get("effects")), "budgets": deepcopy(receipt.get("budgets")), "material_terms": terms}


def _approval_teach_back(receipt: Mapping[str, Any]) -> dict[str, str]:
    terms = _mapping(receipt.get("material_terms")) or {}
    return {
        "target_summary": json.dumps(receipt.get("targets"), sort_keys=True, separators=(",", ":"), ensure_ascii=False),
        "aggregate_maximum": json.dumps(terms.get("aggregate_maxima"), sort_keys=True, separators=(",", ":"), ensure_ascii=False),
        "flow_recipients": json.dumps({"data_flows": terms.get("data_flows"), "recipients": terms.get("recipients")}, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
        "reversibility": str(terms.get("irreversibility")),
        "captured_at": str((_mapping(receipt.get("comprehension_evidence")) or {}).get("captured_at")),
    }


def _approval_strings_clean(value: Any) -> bool:
    if isinstance(value, str):
        # Unicode format characters include bidi overrides, zero-width and
        # other invisible controls that make the rendered target ambiguous.
        if any(unicodedata.category(char) == "Cf" or unicodedata.bidirectional(char) in {"RLO", "LRO", "RLE", "LRE", "PDF", "RLI", "LRI", "FSI", "PDI"} for char in value):
            return False
        has_latin = any("LATIN" in unicodedata.name(char, "") for char in value)
        has_cyrillic = any("CYRILLIC" in unicodedata.name(char, "") for char in value)
        return not (has_latin and has_cyrillic)
    if isinstance(value, Mapping):
        return all(_approval_strings_clean(key) and _approval_strings_clean(item) for key, item in value.items())
    if isinstance(value, list):
        return all(_approval_strings_clean(item) for item in value)
    return True


def _trusted_approval_signature(receipt: Mapping[str, Any], trusted_facts: Mapping[str, Any]) -> Mapping[str, Any] | None:
    digest = _approval_receipt_digest(receipt)
    for field in ("verified_approval_signatures", "verified_approval_receipts"):
        rows = _mapping(trusted_facts.get(field)) or {}
        record = _mapping(rows.get(digest))
        if record is not None:
            return record
    return None


def _approved_envelope(receipt: Mapping[str, Any]) -> dict[str, Any]:
    terms = _mapping(receipt.get("material_terms")) or {}
    return {"effects": deepcopy(receipt.get("effects")), "targets": deepcopy(receipt.get("targets")), "budgets": deepcopy(receipt.get("budgets")), "flows": deepcopy(terms.get("data_flows"))}


def _authenticated_approvers_valid(receipt: Mapping[str, Any], facts: Mapping[str, Any]) -> bool:
    approvers, evidence = receipt.get("approvers"), receipt.get("human_authentication_evidence")
    quorum = receipt.get("quorum_required")
    if quorum is None:
        quorum = (_mapping(receipt.get("quorum")) or {}).get("required")
    required_quorum = facts.get("required_approval_quorum")
    verified = _mapping(facts.get("verified_approver_authentications")) or {}
    if not isinstance(approvers, list) or not isinstance(evidence, list) or not isinstance(quorum, int) or not isinstance(required_quorum, int) or quorum != required_quorum or len(approvers) < quorum:
        return False
    bind_fields = ("approver_id", "subject", "role", "session_id", "independence_group") + (("incident_digest", "profile_digest", "target_set_digest") if receipt.get("receipt_type") == "BREAK_GLASS" else ())
    unique_fields = ("approver_id", "subject", "session_id", "independence_group")
    if {row.get("approver_id") for row in evidence if isinstance(row, Mapping)} != set(approvers) or len(evidence) != len(approvers):
        return False
    for field in unique_fields:
        values = [row.get(field) for row in evidence if isinstance(row, Mapping)]
        if len(values) != len(evidence) or len(values) != len(set(values)):
            return False
    for row in evidence:
        trusted = _mapping(verified.get(row.get("evidence_digest"))) if isinstance(row, Mapping) else None
        if not isinstance(row, Mapping) or trusted is None or any(trusted.get(key) != row.get(key) for key in (*bind_fields, "method", "authenticated_at", "evidence_digest")) or trusted.get("receipt_id") != receipt.get("receipt_id") or trusted.get("signature_verified") is not True or trusted.get("not_revoked") is not True or not trusted.get("verified_by"):
            return False
    return True


def validate_break_glass(receipt: Any, trusted_facts: Mapping[str, Any], *, expected_incident: str | None = None, expected_profile: str | None = None, expected_target_set: str | None = None) -> bool:
    if not isinstance(receipt, Mapping) or receipt.get("receipt_type") != "BREAK_GLASS":
        return False
    emergency = _mapping(receipt.get("break_glass")) or {}
    evidence = receipt.get("human_authentication_evidence")
    approvers = receipt.get("approvers")
    now = _parse_time(trusted_facts.get("trusted_time"))
    issued, expires = _parse_time(receipt.get("issued_at")), _parse_time(receipt.get("expires_at"))
    if not (isinstance(evidence, list) and isinstance(approvers, list) and len(evidence) == len(approvers) and len(evidence) >= 2 and now and issued and expires):
        return False
    incident = expected_incident or trusted_facts.get("break_glass_incident_digest")
    profile = expected_profile or trusted_facts.get("break_glass_profile_digest")
    target_set = expected_target_set or trusted_facts.get("break_glass_target_set_digest")
    if any(value is not None and emergency.get(key) != value for key, value in (("incident_digest", incident), ("emergency_profile_digest", profile), ("target_set_digest", target_set))):
        return False
    subjects, sessions, groups, roles = set(), set(), set(), set()
    emergency_roles, resource_roles = {"INCIDENT_COMMANDER", "SECURITY_AUTHORIZER"}, {"RESOURCE_AUTHORIZER", "SERVICE_AUTHORIZER"}
    for row, approver in zip(evidence, approvers):
        if not isinstance(row, Mapping) or row.get("subject") != approver or row.get("approver_id") != approver or row.get("role") not in emergency_roles | resource_roles:
            return False
        if any(row.get(key) != emergency.get(receipt_key) for key, receipt_key in (("incident_digest", "incident_digest"), ("profile_digest", "emergency_profile_digest"), ("target_set_digest", "target_set_digest"))):
            return False
        if row.get("subject") in subjects or row.get("session_id") in sessions or row.get("independence_group") in groups or row.get("role") in roles:
            return False
        auth_time = _parse_time(row.get("authenticated_at"))
        if auth_time is None or auth_time > now:
            return False
        subjects.add(row.get("subject")); sessions.add(row.get("session_id")); groups.add(row.get("independence_group")); roles.add(row.get("role"))
    ttl = emergency.get("ttl_seconds")
    return bool(roles & emergency_roles and roles & resource_roles and emergency.get("inside_platform_ceiling") is True and emergency.get("real_time_alert_required") is True and emergency.get("postmortem_required") is True and isinstance(ttl, int) and ttl >= 1 and now < expires and (expires - issued).total_seconds() <= ttl and now <= issued + timedelta(seconds=ttl))


def validate_approval_receipt(receipt: Any, *, expected_nonce: str | None = None, trusted_facts: Mapping[str, Any] | None = None) -> bool:
    """Accept only a receipt corroborated by caller-supplied external facts."""
    facts = _mapping(trusted_facts)
    if facts is None or not isinstance(receipt, Mapping) or receipt.get("decision") != "APPROVE" or receipt.get("state") != "ISSUED":
        return False
    if expected_nonce is not None and receipt.get("approval_nonce") != expected_nonce:
        return False
    approvers, quorum = receipt.get("approvers"), _mapping(receipt.get("quorum"))
    sod, comprehension, terms, signature, lifecycle = (_mapping(receipt.get(key)) for key in ("separation_of_duties", "comprehension_evidence", "material_terms", "service_signature", "lifecycle"))
    if not isinstance(approvers, list) or len(approvers) != len(set(approvers)) or quorum is None or sod is None or comprehension is None or terms is None or signature is None or lifecycle is None:
        return False
    if quorum.get("met") is not True or quorum.get("present") != len(approvers) or quorum.get("present", 0) < quorum.get("required", 1) or receipt.get("requester") in approvers or receipt.get("executor") in approvers:
        return False
    if any(sod.get(key) is not True for key in ("requester_not_approver", "executor_not_approver", "verified")) or any(comprehension.get(key) is not True for key in ("effect_summary_acknowledged", "target_summary_acknowledged", "budget_summary_acknowledged", "irreversibility_acknowledged")):
        return False
    if receipt.get("uncertainty") != "BOUNDED" or not _approval_strings_clean(_approval_payload(receipt)):
        return False
    approved = _approved_envelope(receipt)
    if receipt.get("approved_envelope") != approved or receipt.get("approved_envelope_digest") != canonical_digest(approved) or not _authenticated_approvers_valid(receipt, facts):
        return False
    issued, expires, not_before = _parse_time(receipt.get("issued_at")), _parse_time(receipt.get("expires_at")), _parse_time(facts.get("trusted_time"))
    if issued is None or expires is None or not_before is None or not issued < expires or not issued <= not_before < expires:
        return False
    if lifecycle.get("phase") != "ISSUED" or lifecycle.get("not_before") != receipt.get("issued_at") or lifecycle.get("activation_not_after") != receipt.get("expires_at") or lifecycle.get("grant_expires_at") != receipt.get("expires_at"):
        return False
    epoch = facts.get("current_revocation_epoch")
    if not isinstance(epoch, int) or lifecycle.get("revocation_epoch") != epoch or terms.get("freshness", {}).get("revocation_epoch") != epoch:
        return False
    payload_digest = canonical_digest(_approval_payload(receipt))
    material_digest = _approval_material_digest(receipt)
    if receipt.get("canonical_payload_digest") != payload_digest or signature.get("payload_digest") != payload_digest or signature.get("canonical_payload_digest") != payload_digest or signature.get("material_terms_digest") != material_digest or signature.get("payload_scope") != "COMPLETE_CANONICAL_PAYLOAD":
        return False
    if terms.get("freshness") != {"not_before": receipt.get("issued_at"), "activation_not_after": receipt.get("expires_at"), "grant_expires_at": receipt.get("expires_at"), "revocation_epoch": epoch, "revocation_binding_digest": terms.get("freshness", {}).get("revocation_binding_digest"), "clock_binding_digest": terms.get("freshness", {}).get("clock_binding_digest")}:
        return False
    if terms.get("freshness", {}).get("clock_binding_digest") != canonical_digest({"issued_at": receipt.get("issued_at"), "expires_at": receipt.get("expires_at")}):
        return False
    if terms.get("freshness", {}).get("revocation_binding_digest") != canonical_digest({"receipt_id": receipt.get("receipt_id"), "approval_nonce": receipt.get("approval_nonce"), "revocation_epoch": epoch}):
        return False
    expected_view = _approval_view_preimage(receipt)
    presentation = _mapping(terms.get("presentation")); shown = _mapping(comprehension.get("presentation")); teach = _mapping(terms.get("teach_back")); shown_teach = _mapping(comprehension.get("teach_back"))
    if presentation is None or shown is None or teach is None or shown_teach is None or presentation != shown or teach != shown_teach or presentation.get("anti_confusable_digest") != canonical_digest(expected_view) or comprehension.get("canonical_view_digest") != canonical_digest(expected_view) or teach != _approval_teach_back(receipt):
        return False
    batch = terms.get("batch")
    if batch is not None and (not isinstance(batch, Mapping) or batch.get("homogeneity") != "HOMOGENEOUS" or batch.get("effect_vector_digest") != canonical_digest(receipt.get("effects")) or batch.get("target_set_digest") != canonical_digest(receipt.get("targets")) or batch.get("item_count", 0) < 1):
        return False
    if receipt.get("receipt_type") == "BREAK_GLASS" and not validate_break_glass(receipt, facts):
        return False
    trusted = _trusted_approval_signature(receipt, facts)
    receipt_digest = _approval_receipt_digest(receipt)
    consumed = set(facts.get("consumed_approval_receipts", []))
    return bool(trusted and trusted.get("receipt_digest", receipt_digest) == receipt_digest and trusted.get("signature_verified") is True and trusted.get("signed_payload_digest", trusted.get("payload_digest")) == payload_digest and trusted.get("material_terms_digest") == material_digest and trusted.get("service_identity") == signature.get("service_identity") and trusted.get("key_id") == signature.get("key_id") and trusted.get("algorithm") == signature.get("algorithm") and trusted.get("freshness_verified") is True and trusted.get("revocation_checked") is True and trusted.get("revocation_epoch", epoch) == epoch and receipt_digest not in consumed)


def _approval_payload(receipt: Mapping[str, Any]) -> dict[str, Any]:
    return {key: deepcopy(value) for key, value in receipt.items() if key not in {"receipt_digest", "service_verification", "canonical_payload_digest", "service_signature"}}


def validate_authoritative_approval(receipt: Any, candidate: Mapping[str, Any], envelope: list[dict[str, Any]], reservations: tuple[dict[str, Any], ...], durable_facts: Mapping[str, Any]) -> bool:
    """Validate the closed admission projection of a separately verified human receipt."""
    facts = _mapping(durable_facts)
    if facts is None or not isinstance(receipt, Mapping) or receipt.get("decision") != "APPROVE" or receipt.get("state") != "ISSUED":
        return False
    receipt_digest = receipt.get("receipt_digest")
    verification = _mapping(receipt.get("service_verification")) or {}
    trusted = _mapping((_mapping(facts.get("verified_approval_receipts")) or {}).get(receipt_digest)) or {}
    challenge = (_mapping(facts.get("approval_challenges")) or {}).get(candidate.get("request_digest"))
    now, issued, expires = map(_parse_time, (facts.get("trusted_time"), receipt.get("issued_at"), receipt.get("expires_at")))
    approvers = receipt.get("approvers")
    if not (_valid_digest(receipt_digest) and isinstance(approvers, list) and len(approvers) == len(set(approvers)) and len(approvers) >= receipt.get("quorum_required", 1) and now and issued and expires and issued <= now < expires):
        return False
    candidate_bindings = _mapping(candidate.get("bindings")) or {}
    return bool(
        receipt.get("nonce") == challenge
        and receipt.get("request_digest") == candidate.get("request_digest")
        and trusted.get("approved_envelope_digest") == receipt.get("authorized_envelope_digest") == canonical_digest(envelope)
        and receipt.get("budget_vector_digest") == canonical_digest(list(reservations))
        and receipt.get("revocation_epoch") == facts.get("current_revocation_epoch")
        and receipt.get("fencing_epoch") == facts.get("current_fencing_epoch")
        and receipt.get("consumed") is False and receipt.get("material_change") is False
        and verification.get("signature_verified") is True
        and trusted.get("approval_facts_digest") == canonical_digest(receipt)
        and trusted.get("receipt_digest") == receipt_digest
        and _valid_digest(trusted.get("approved_envelope_digest"))
        and ("full_receipt_digest" not in trusted or trusted.get("full_receipt_digest") == receipt_digest)
        and trusted.get("binding_set_digest") == receipt.get("binding_set_digest")
        and trusted.get("candidate_bindings_digest") == canonical_digest(candidate_bindings)
        and trusted.get("signed_payload_digest") == verification.get("signed_payload_digest")
        and trusted.get("verified_by") == verification.get("verified_by")
        and trusted.get("key_id") == verification.get("key_id")
        and trusted.get("algorithm") == verification.get("algorithm")
        and trusted.get("signature_verified") is True
        and trusted.get("full_receipt_valid") is True
        and trusted.get("separation_of_duties_verified") is True
        and trusted.get("comprehension_verified") is True
        and trusted.get("freshness_verified") is True
        and trusted.get("revocation_checked") is True
        and trusted.get("not_revoked") is True
        and receipt_digest not in set(facts.get("consumed_approval_receipts", []))
    )


def _risk_scope_digest(profile: Mapping[str, Any], risk: Mapping[str, Any]) -> str:
    return canonical_digest({"profile_id": profile.get("profile_id"), "profile_version": profile.get("profile_version"), "risk_id": risk.get("id"), "category": risk.get("category"), "claim": risk.get("claim")})


def _validate_risk_dispositions(profile: Mapping[str, Any], trusted_facts: Mapping[str, Any] | None) -> bool:
    risks = profile.get("residual_risks")
    evidence = profile.get("risk_disposition_evidence")
    if not isinstance(risks, list) or not isinstance(evidence, list):
        return False
    by_risk: dict[str, Mapping[str, Any]] = {}
    evidence_forms = {
        "ACCEPTANCE_REQUIRED": ("ACCEPTANCE_RECORD", {"acceptance_record_id"}),
        "STRONGER_PROFILE_REQUIRED": ("STRONGER_PROFILE_RECORD", {"required_profile_digest"}),
        "MONITOR": ("MONITORING_RECORD", {"telemetry_digest", "escalation_threshold"}),
        "OUT_OF_SCOPE": ("OUT_OF_SCOPE_PROOF", {"scope_exclusion_digest"}),
    }
    for item in evidence:
        if not isinstance(item, Mapping) or not isinstance(item.get("risk_id"), str) or item.get("risk_id") in by_risk:
            return False
        by_risk[item["risk_id"]] = item
        if item.get("profile_id") != profile.get("profile_id") or item.get("profile_digest") != profile.get("profile_digest"):
            return False
        risk = next((row for row in risks if isinstance(row, Mapping) and row.get("id") == item.get("risk_id")), None)
        if risk is None or item.get("scope_digest") != _risk_scope_digest(profile, risk):
            return False
        expected_form = evidence_forms.get(item.get("disposition"))
        disposition_payload = _mapping(item.get("disposition_payload"))
        if expected_form is None or item.get("evidence_type") != expected_form[0] or disposition_payload is None or set(disposition_payload) != expected_form[1] or any(not disposition_payload.get(key) for key in expected_form[1]):
            return False
        if any(key.endswith("digest") and not _valid_digest(disposition_payload.get(key)) for key in disposition_payload):
            return False
        signed = _mapping(item.get("signed_payload")) or {}
        verification = _mapping(item.get("external_verification")) or {}
        payload = {key: deepcopy(value) for key, value in item.items() if key not in {"signed_payload", "external_verification"}}
        if signed.get("payload_digest") != canonical_digest(payload) or not signed.get("key_id") or not signed.get("signature") or verification.get("signature_verified") is not True or verification.get("not_revoked") is not True:
            return False
        issued, expires, review = _parse_time(item.get("issued_at")), _parse_time(item.get("expires_at")), _parse_time(item.get("review_at"))
        now = _parse_time((trusted_facts or {}).get("trusted_time"))
        if issued is None or expires is None or review is None or issued >= expires or review < issued or review > expires or now is None or not issued <= now < expires:
            return False
        trusted = _mapping((_mapping(trusted_facts or {}).get("verified_risk_dispositions") or {}).get(item.get("evidence_id")))
        if trusted is None or trusted.get("risk_id") != item.get("risk_id") or trusted.get("profile_id") != item.get("profile_id") or trusted.get("profile_digest") != item.get("profile_digest") or trusted.get("scope_digest") != item.get("scope_digest") or trusted.get("evidence_type") != item.get("evidence_type") or trusted.get("disposition_payload") != disposition_payload or trusted.get("signed_payload_digest") != signed.get("payload_digest") or trusted.get("verified_by") != verification.get("verified_by") or trusted.get("not_revoked") is not True or trusted.get("revocation_checked") is not True:
            return False
    for risk in risks:
        if not isinstance(risk, Mapping):
            return False
        disposition = risk.get("disposition")
        item = by_risk.get(risk.get("id"))
        if item is None or item.get("disposition") != disposition:
            return False
        if disposition == "STRONGER_PROFILE_REQUIRED" and (profile.get("risk_class") != "STRONG_SEPARATION_REQUIRED" or (trusted_facts or {}).get("stronger_profile_proven") is not True):
            return False
        if disposition not in {"ACCEPTANCE_REQUIRED", "STRONGER_PROFILE_REQUIRED", "MONITOR", "OUT_OF_SCOPE"}:
            return False
    return True


def _role_subjects_valid(profile: Mapping[str, Any], trusted_facts: Mapping[str, Any]) -> bool:
    required = {"process_id", "uid", "gid", "mount_namespace", "pid_namespace", "network_namespace", "security_label", "credential_namespace", "session_id", "ipc_endpoint", "inherited_fd_digest"}
    principals = profile.get("principal_envelopes")
    verified = _mapping(trusted_facts.get("verified_role_subjects")) or {}
    if not isinstance(principals, list) or len(principals) != 5:
        return False
    subjects = []
    for principal in principals:
        subject = _mapping(principal.get("os_subject")) if isinstance(principal, Mapping) else None
        trusted = _mapping(verified.get(principal.get("principal"))) if isinstance(principal, Mapping) else None
        if subject is None or trusted is None or set(subject) != required or any(not subject.get(key) for key in required - {"uid", "gid"}) or any(not isinstance(subject.get(key), int) or isinstance(subject.get(key), bool) or subject[key] < 1 for key in {"uid", "gid"}):
            return False
        if any(trusted.get(key) != subject.get(key) for key in required) or trusted.get("profile_digest") != profile.get("profile_digest") or trusted.get("signature_verified") is not True or trusted.get("not_revoked") is not True or not trusted.get("verified_by"):
            return False
        subjects.append(subject)
    # Symbolic roles are insufficient: each authority domain has an independent
    # OS subject, namespace, credential/session and IPC endpoint.
    return all(len({subject[key] for subject in subjects}) == len(subjects) for key in ("process_id", "uid", "gid", "mount_namespace", "pid_namespace", "network_namespace", "security_label", "credential_namespace", "session_id", "ipc_endpoint", "inherited_fd_digest"))


def _broker_ipc_binding_valid(profile: Mapping[str, Any]) -> bool:
    fields = {"worker_principal", "broker_principal", "worker_endpoint", "broker_endpoint", "transport", "endpoint_mode", "fd_delivery", "sender_authentication", "worker_network_namespace", "broker_network_namespace", "binding_digest"}
    binding = _mapping(profile.get("broker_ipc_binding"))
    principals = profile.get("principal_envelopes")
    if binding is None or set(binding) != fields or not isinstance(principals, list):
        return False
    by_role = {item.get("role"): item for item in principals if isinstance(item, Mapping)}
    worker, broker = _mapping(by_role.get("AGENT_WORKER")), _mapping(by_role.get("BROKER"))
    unsigned = {key: binding.get(key) for key in fields - {"binding_digest"}}
    return bool(
        worker is not None and broker is not None
        and binding.get("worker_principal") == worker.get("principal")
        and binding.get("broker_principal") == broker.get("principal")
        and binding.get("worker_endpoint") == (_mapping(worker.get("os_subject")) or {}).get("ipc_endpoint")
        and binding.get("broker_endpoint") == (_mapping(broker.get("os_subject")) or {}).get("ipc_endpoint")
        and binding.get("worker_network_namespace") == (_mapping(worker.get("os_subject")) or {}).get("network_namespace")
        and binding.get("broker_network_namespace") == (_mapping(broker.get("os_subject")) or {}).get("network_namespace")
        and binding.get("transport") == "UNIX_SEQPACKET"
        and binding.get("endpoint_mode") == "UNIX_CONNECTED_PAIR"
        and binding.get("fd_delivery") == "SUPERVISOR_TYPED_ALLOWLIST"
        and binding.get("sender_authentication") == "SCM_CREDENTIALS_PLUS_ENDPOINT_HOLDER_ATTESTATION"
        and binding.get("binding_digest") == canonical_digest(unsigned)
    )


def validate_broker_ipc_attestation(candidate: Mapping[str, Any], profile: Mapping[str, Any], trusted_facts: Mapping[str, Any]) -> bool:
    """Accept one externally verified IPC session, never caller-supplied fragments."""
    attestation, bindings = _mapping(candidate.get("broker_ipc_attestation")), _mapping(candidate.get("bindings")) or {}
    ipc = _mapping(profile.get("broker_ipc_binding")) or {}
    session = _mapping(candidate.get("session_attestation")) or {}
    if attestation is None or set(attestation) != BROKER_IPC_ATTESTATION_FIELDS:
        return False
    digest_value = attestation.get("attestation_digest")
    record = _mapping((_mapping(trusted_facts.get("verified_broker_ipc_attestations")) or {}).get(digest_value))
    signature = _mapping(attestation.get("signature")) or {}
    unsigned = _broker_ipc_payload(attestation)
    roles = {item.get("principal"): _mapping(item.get("os_subject")) for item in profile.get("principal_envelopes", []) if isinstance(item, Mapping)}
    worker, broker = roles.get(ipc.get("worker_principal")), roles.get(ipc.get("broker_principal"))
    now, issued, expires = (_parse_time(value) for value in (candidate.get("evaluated_at"), attestation.get("issued_at"), attestation.get("expires_at")))
    holders = (("worker_subject", "worker_endpoint_holder"), ("broker_subject", "broker_endpoint_holder"))
    socket_identity = _mapping(attestation.get("socket_identity")) or {}
    worker_endpoint = _mapping(socket_identity.get("worker_endpoint")) or {}
    broker_endpoint = _mapping(socket_identity.get("broker_endpoint")) or {}
    return bool(
        record and worker and broker and attestation.get("attestation_digest") == canonical_digest(unsigned) == bindings.get("broker_ipc_attestation_digest") and signature.get("payload_digest") == canonical_digest(unsigned)
        and attestation.get("isolation_profile_digest") == bindings.get("isolation_profile_digest") == profile.get("profile_digest")
        and attestation.get("broker_ipc_binding_digest") == bindings.get("broker_ipc_binding_digest") == ipc.get("binding_digest")
        and attestation.get("runtime_session_id") == session.get("session_id")
        and attestation.get("worker_principal") == ipc.get("worker_principal") and attestation.get("broker_principal") == ipc.get("broker_principal")
        and attestation.get("worker_subject") == worker and attestation.get("broker_subject") == broker
        and all(_mapping(attestation.get(subject)) and _mapping(attestation.get(holder)) and all(attestation[holder].get(key) == attestation[subject].get(key) for key in ("process_id", "uid", "gid", "session_id")) for subject, holder in holders)
        and _mapping(attestation.get("broker_observed_sender"))
        and all(attestation["broker_observed_sender"].get(key) == attestation["worker_subject"].get(key) for key in ("process_id", "uid", "gid", "session_id"))
        and attestation.get("sender_authentication") == ipc.get("sender_authentication") == "SCM_CREDENTIALS_PLUS_ENDPOINT_HOLDER_ATTESTATION"
        and attestation.get("transport") == ipc.get("transport") == "UNIX_SEQPACKET" and attestation.get("operation_id") == candidate.get("operation_id")
        and isinstance(attestation.get("worker_fd"), int) and isinstance(attestation.get("broker_fd"), int) and attestation["worker_fd"] >= 0 and attestation["broker_fd"] >= 0
        and all(_valid_digest(attestation.get(key)) for key in ("worker_fd_allowlist_digest", "broker_fd_allowlist_digest", "message_schema_digest"))
        and set(socket_identity) == {"kind", "worker_endpoint", "broker_endpoint", "pair_binding_digest"}
        and socket_identity.get("kind") == "UNIX_CONNECTED_PAIR"
        and all(set(endpoint) == {"device_id", "inode", "cookie"} and isinstance(endpoint.get("device_id"), str) and bool(endpoint["device_id"]) and isinstance(endpoint.get("inode"), int) and not isinstance(endpoint.get("inode"), bool) and endpoint["inode"] >= 1 and isinstance(endpoint.get("cookie"), int) and not isinstance(endpoint.get("cookie"), bool) and endpoint["cookie"] >= 1 for endpoint in (worker_endpoint, broker_endpoint))
        and worker_endpoint != broker_endpoint
        and socket_identity.get("pair_binding_digest") == canonical_digest({"worker_endpoint": worker_endpoint, "broker_endpoint": broker_endpoint})
        and now and issued and expires and issued <= now < expires and attestation.get("revocation_epoch") == trusted_facts.get("current_revocation_epoch")
        and attestation.get("session_fencing_epoch") == trusted_facts.get("current_fencing_epoch") == session.get("epoch")
        and attestation.get("nonce") == trusted_facts.get("current_broker_ipc_nonce")
        and record.get("signed_payload") == unsigned and record.get("signed_payload_digest") == canonical_digest(unsigned)
        and record.get("attestation_digest") == digest_value and record.get("isolation_profile_digest") == attestation.get("isolation_profile_digest") and record.get("broker_ipc_binding_digest") == attestation.get("broker_ipc_binding_digest")
        and record.get("trust_root") and record.get("key_id") == signature.get("key_id") and record.get("algorithm") == signature.get("algorithm") and record.get("verified_by") == signature.get("verified_by")
        and record.get("signature_verified") is True and record.get("freshness_verified") is True and record.get("revocation_checked") is True and record.get("not_revoked") is True and record.get("current_key") is True
    )


def validate_isolation_profile(profile: Any, trusted_facts: Mapping[str, Any] | None = None) -> bool:
    if not isinstance(profile, Mapping) or profile.get("status") != "ACTIVE" or not isinstance(profile.get("principal_envelopes"), list):
        return False
    principals = profile["principal_envelopes"]
    roles = [item.get("role") for item in principals if isinstance(item, Mapping)]
    principal_ids = [item.get("principal") for item in principals if isinstance(item, Mapping)]
    if set(roles) != {"AGENT_WORKER", "BROKER", "EXECUTOR", "MODEL_GATEWAY", "OBSERVER"} or len(roles) != len(set(roles)) or len(principal_ids) != len(principals) or len(principal_ids) != len(set(principal_ids)):
        return False
    worker = principals[roles.index("AGENT_WORKER")]
    if worker.get("ambient_authority") is not False or worker.get("network_mode") != "DISCONNECTED" or worker.get("credential_mode") != "NONE" or set(worker.get("effect_ceiling", [])) - {"COMPUTE", "OBSERVE"}:
        return False
    filesystem = _mapping(profile.get("filesystem")) or {}
    if filesystem.get("rootfs_read_only") is not True or filesystem.get("private_mounts") is not True or filesystem.get("outputs") not in {"WRITE_ONLY_STAGING", "READ_WRITE_STAGING"} or filesystem.get("tmpfs_quota_bytes", 0) < 1 or filesystem.get("inode_limit", 0) < 1:
        return False
    compiled = profile.get("compiled_envelopes")
    if not isinstance(compiled, list) or len(compiled) != 2 or len({item.get("principal") for item in compiled if isinstance(item, Mapping)}) != 2 or any(not isinstance(item, Mapping) or not item.get("allowed_effects") or not item.get("allowed_resource_kinds") or not item.get("allowed_operations") for item in compiled):
        return False
    for item in compiled:
        rows, kinds = item.get("effect_resource_operations"), set(item.get("allowed_resource_kinds", []))
        if not isinstance(rows, list) or not rows or not all(_typed_effect_row_valid(row) for row in rows) or {row["effect"] for row in rows} - set(item["allowed_effects"]) or {row["resource_kind"] for row in rows} - kinds or {row["operation"] for row in rows} - set(item["allowed_operations"]):
            return False
        if kinds == {"ENDPOINT"}:
            bindings = item.get("endpoint_bindings")
            if item.get("allowed_scopes") is not None or item.get("filesystem_targets") is not None or not isinstance(bindings, list) or not bindings or not all(_endpoint_binding_valid(binding) for binding in bindings):
                return False
        else:
            scopes = item.get("allowed_scopes")
            if "ENDPOINT" in kinds or item.get("endpoint_bindings") is not None or not isinstance(scopes, list) or not scopes or not all(_canonical_path(scope) for scope in scopes):
                return False
            if kinds & {"FILE", "DIRECTORY"} and (not isinstance(item.get("filesystem_targets"), list) or not item["filesystem_targets"] or {target.get("canonical_path") for target in item["filesystem_targets"] if isinstance(target, Mapping)} != set(scopes)):
                return False
    resources = profile.get("resources")
    resource_names = [item.get("resource") for item in resources if isinstance(item, Mapping)] if isinstance(resources, list) else []
    if not isinstance(resources, list) or any(not isinstance(item, Mapping) for item in resources) or len(resource_names) != len(set(resource_names)):
        return False
    for item in resources:
        resource = item.get("resource")
        expected = RESOURCE_UNIT_ENFORCER.get(resource)
        if expected is None or (item.get("unit"), item.get("enforcement")) != expected:
            return False
    network, process = _mapping(profile.get("network")) or {}, _mapping(profile.get("process")) or {}
    network_fields = ("worker_default", "loopback", "ipv4", "ipv6", "dns", "unix_sockets", "metadata_service", "connected_fd_policy", "external_sink_fds")
    attestation, supply, facts = _mapping(profile.get("attestation")) or {}, _mapping(profile.get("supply_chain")) or {}, _mapping(trusted_facts) or {}
    expected_network = {"worker_default": "DISCONNECTED", "loopback": "DISABLED", "ipv4": "DISABLED", "ipv6": "DISABLED", "dns": "DISABLED", "unix_sockets": "BROKER_CONNECTED_PAIR_ONLY", "metadata_service": "BLOCKED", "connected_fd_policy": "EXACT_OPERATION_SCOPED_PAIR_ONLY", "external_sink_fds": "NONE"}
    gpu = {item.get("resource"): item.get("limit") for item in resources}
    gpu_pair = (gpu.get("GPU_TIME"), gpu.get("GPU_MEMORY"))
    return bool(set(resource_names) == RESOURCE_CLASSES and len(resource_names) == len(set(resource_names)) and (gpu_pair == (0, 0) or all(isinstance(value, int) and value > 0 for value in gpu_pair)) and process.get("rootless_user_mapping") is True and {key: network.get(key) for key in network_fields} == expected_network and network.get("inherited_fds_closed") is True and _broker_ipc_binding_valid(profile) and all(attestation.get(key) is True for key in ("placement_required", "session_receipt_required", "independent_verification_required")) and supply.get("signed_artifacts") is True and supply.get("exact_byte_binding") is True and supply.get("registry_generation", -1) >= supply.get("rollback_floor", 0) and _activation_valid(profile, "profile_digest", "profile_activation", facts.get("verified_profile_activations"), None, facts.get("trusted_time")) and _role_subjects_valid(profile, facts) and _validate_risk_dispositions(profile, facts))


def _canonical_selector_value(selector: Mapping[str, Any]) -> tuple[str, str] | None:
    kind = selector.get("kind")
    if kind == "PATH_DESCRIPTOR":
        value = selector.get("canonical_path")
        return (kind, value) if _canonical_path(value) else None
    if kind == "ENDPOINT_DESCRIPTOR":
        value = selector.get("canonical_endpoint")
        return (kind, value) if isinstance(value, str) and value.startswith("https://") and "%" not in value else None
    if kind == "LOCAL_RESOURCE":
        value = selector.get("resource_id")
        return (kind, value) if isinstance(value, str) and value else None
    return None


def _selector_contained(entry: Mapping[str, Any], envelope: Mapping[str, Any]) -> bool:
    selector = _mapping(entry.get("selector"))
    normalized = _canonical_selector_value(selector or {}) if selector is not None else None
    if normalized is None:
        return False
    kind, value = normalized
    if entry.get("resource_kind") == "ENDPOINT":
        candidate_binding = {key: (selector or {}).get(key) for key in ENDPOINT_BINDING_FIELDS}
        bindings = envelope.get("endpoint_bindings")
        return bool(kind == "ENDPOINT_DESCRIPTOR" and _endpoint_binding_valid(candidate_binding) and isinstance(bindings, list) and candidate_binding in bindings and all(_endpoint_binding_valid(binding) for binding in bindings))
    scopes = envelope.get("allowed_scopes")
    if not isinstance(scopes, list) or not all(isinstance(scope, str) and scope for scope in scopes):
        return False
    if entry.get("resource_kind") in {"FILE", "DIRECTORY"}:
        if kind != "PATH_DESCRIPTOR" or not all(_canonical_path(scope) for scope in scopes):
            return False
        return any(value == scope or value.startswith(scope.rstrip("/") + "/") for scope in scopes)
    return any(value == scope for scope in scopes)


def _manifest_trusted(manifest: Mapping[str, Any], expected_digest: str, trusted_facts: Mapping[str, Any]) -> bool:
    trusted = _mapping((_mapping(trusted_facts.get("verified_manifests")) or {}).get(expected_digest))
    signer = _mapping((_mapping(manifest.get("tool")) or {}).get("signer")) or {}
    lifecycle = _mapping(manifest.get("lifecycle")) or {}
    runtime = _mapping(manifest.get("runtime_requirements")) or {}
    if trusted is None:
        return False
    now, issued, expires = _parse_time(trusted.get("trusted_time")), _parse_time(lifecycle.get("issued_at")), _parse_time(trusted.get("expires_at"))
    ambient = {"ambient_dependencies": runtime.get("ambient_dependencies"), "credentials": runtime.get("credentials")}
    return bool(
        trusted.get("manifest_digest") == expected_digest == canonical_digest(manifest)
        and trusted.get("signed_payload_digest") == canonical_digest(manifest)
        and trusted.get("signer") == signer.get("key_id")
        and trusted.get("key_id") == signer.get("key_id")
        and trusted.get("algorithm") == signer.get("algorithm")
        and trusted.get("signature_verified") is True
        and trusted.get("not_revoked") is True
        and now is not None and issued is not None and expires is not None and issued <= now < expires
        and trusted.get("rollback_floor") == lifecycle.get("rollback_floor")
        and trusted.get("dependency_closure_digest") == canonical_digest((_mapping(manifest.get("tool")) or {}).get("dependencies", []))
        and trusted.get("ambient_closure_digest") == canonical_digest(ambient)
        and trusted.get("dependency_closure_measured") is True
        and trusted.get("ambient_closure_measured") is True
    )


def _manifest_covers(manifest: Mapping[str, Any], entry: Mapping[str, Any]) -> bool:
    constraints = _mapping(entry.get("constraints")) or {}
    requested_time, requested_quantity = _mapping(constraints.get("temporal")) or {}, _mapping(constraints.get("quantity")) or {}
    manifest_flows = {canonical_digest(item) for item in manifest.get("flow_rules", []) if isinstance(item, Mapping)}
    requested_flows = {canonical_digest(item) for item in constraints.get("flows", []) if isinstance(item, Mapping)}
    manifest_obligations = set((_mapping(manifest.get("assurance")) or {}).get("obligations", []))
    if not set(entry.get("facets", [])) <= set(manifest.get("authority_facets", [])) or not requested_flows <= manifest_flows or not set(constraints.get("obligations", [])) <= manifest_obligations:
        return False
    for effect_bound in manifest.get("effect_bounds", []):
        if not isinstance(effect_bound, Mapping) or effect_bound.get("effect") != entry.get("effect") or effect_bound.get("uncertainty") == "UNKNOWN":
            continue
        for resource in effect_bound.get("resources", []):
            if not isinstance(resource, Mapping) or resource.get("resource_kind") != entry.get("resource_kind") or entry.get("operation") not in resource.get("operations", []):
                continue
            selector, candidate_selector = _mapping(resource.get("selector")) or {}, _mapping(entry.get("selector")) or {}
            expected_selector_kinds = {
                "FILE": {"PATH_EXACT", "PATH_PREFIX"}, "DIRECTORY": {"PATH_EXACT", "PATH_PREFIX"},
                "PROCESS": {"PROCESS_EXECUTABLE"}, "ENDPOINT": {"ENDPOINT_EXACT"},
                "PRINCIPAL": {"PRINCIPAL_EXACT"}, "MEMORY": {"MEMORY_NAMESPACE"},
                "PROMPT": {"PROMPT_COMPONENT"}, "POLICY": {"POLICY_OBJECT"},
                "REGISTRY": {"LOCAL_RESOURCE"}, "SECRET": {"LOCAL_RESOURCE"},
                "COMPUTE_RESOURCE": {"LOCAL_RESOURCE"},
            }
            # Check the typed relation before extracting a string.  Otherwise
            # an incompatible selector can authorize by raw lexical equality.
            if selector.get("kind") not in expected_selector_kinds.get(entry.get("resource_kind"), set()):
                continue
            candidate_kind = candidate_selector.get("kind")
            if entry.get("resource_kind") in {"FILE", "DIRECTORY"} and candidate_kind != "PATH_DESCRIPTOR":
                continue
            if entry.get("resource_kind") == "ENDPOINT" and candidate_kind != "ENDPOINT_DESCRIPTOR":
                continue
            value, bound = candidate_selector.get("canonical_path", candidate_selector.get("canonical_endpoint", candidate_selector.get("resource_id"))), selector.get("value")
            manifest_time, manifest_quantity = _mapping(resource.get("temporal")) or {}, _mapping(resource.get("quantity")) or {}
            requested_start, requested_end = _parse_time(requested_time.get("not_before")), _parse_time(requested_time.get("not_after"))
            manifest_start, manifest_end = _parse_time(manifest_time.get("not_before")), _parse_time(manifest_time.get("not_after"))
            full_constraints_covered = (
                constraints.get("direction") == resource.get("direction")
                and constraints.get("data_label") == resource.get("data_label")
                and requested_start is not None and requested_end is not None and manifest_start is not None and manifest_end is not None
                and manifest_start <= requested_start < requested_end <= manifest_end
                and requested_time.get("max_duration_ms", 0) <= manifest_time.get("max_duration_ms", -1)
                and requested_quantity.get("unit") == manifest_quantity.get("unit")
                and requested_quantity.get("limit", -1) <= manifest_quantity.get("limit", -1)
                and constraints.get("max_concurrency", 0) <= resource.get("max_concurrency", -1)
            )
            if not full_constraints_covered:
                continue
            if selector.get("kind") == "PATH_PREFIX" and entry.get("resource_kind") in {"FILE", "DIRECTORY"} and _canonical_path(value) and _canonical_path(bound) and selector.get("descriptor_binding_digest") == candidate_selector.get("descriptor_binding_digest") and selector.get("physical_target_digest") == candidate_selector.get("physical_target_digest") and (value == bound or value.startswith(bound.rstrip("/") + "/")):
                return True
            if selector.get("kind") == "ENDPOINT_EXACT":
                manifest_binding = _mapping(selector.get("endpoint_binding")) or {}
                candidate_binding = {key: candidate_selector.get(key) for key in ENDPOINT_BINDING_FIELDS}
                if _endpoint_binding_valid(manifest_binding) and _endpoint_binding_valid(candidate_binding) and manifest_binding == candidate_binding and value == bound == manifest_binding.get("canonical_endpoint"):
                    return True
                continue
            if selector.get("kind") in {"PATH_EXACT", "PRINCIPAL_EXACT", "MEMORY_NAMESPACE", "PROMPT_COMPONENT", "POLICY_OBJECT", "LOCAL_RESOURCE"} and isinstance(value, str) and value == bound and (selector.get("kind") != "PATH_EXACT" or (selector.get("descriptor_binding_digest") == candidate_selector.get("descriptor_binding_digest") and selector.get("physical_target_digest") == candidate_selector.get("physical_target_digest"))):
                return True
    return False


def _manifest_derived_closure(manifest: Mapping[str, Any], seed: Any) -> list[Mapping[str, Any]] | None:
    """Resolve finite clause-ID edges; effect names are never closure authority."""
    bounds = manifest.get("effect_bounds")
    if not isinstance(bounds, list) or not bounds:
        return None
    by_id: dict[str, Mapping[str, Any]] = {}
    for bound in bounds:
        clause_id = bound.get("clause_id") if isinstance(bound, Mapping) else None
        if not isinstance(bound, Mapping) or not isinstance(clause_id, str) or not clause_id or clause_id in by_id or not isinstance(bound.get("resources"), list) or not bound["resources"] or bound.get("uncertainty") == "UNKNOWN" or not isinstance(bound.get("derived_effects"), list):
            return None
        by_id[clause_id] = bound
    if isinstance(seed, list):
        seeds = {clause_id for clause_id, bound in by_id.items() if any(_manifest_covers({**manifest, "effect_bounds": [bound]}, entry) for entry in seed)}
        if len(seeds) == 0:
            return None
    elif isinstance(seed, set) and all(isinstance(item, str) for item in seed):
        # Compatibility only for direct callers; admission always seeds typed clauses.
        seeds = {clause_id for clause_id, bound in by_id.items() if bound.get("effect") in seed}
    else:
        return None
    closure, visiting, visited = [], set(), set()
    def visit(clause_id: str) -> bool:
        if clause_id in visiting or clause_id not in by_id: return False
        if clause_id in visited: return True
        visiting.add(clause_id)
        for edge in by_id[clause_id]["derived_effects"]:
            if not isinstance(edge, str) or not visit(edge): return False
        visiting.remove(clause_id); visited.add(clause_id); closure.append(by_id[clause_id]); return True
    return closure if all(visit(clause_id) for clause_id in seeds) else None


def _manifest_clause_atoms_covered(manifest: Mapping[str, Any], clause: Mapping[str, Any], entries: list[Mapping[str, Any]]) -> bool:
    """Each reachable resource/operation atom needs an exact selected entry."""
    for resource in clause.get("resources", []):
        for operation in resource.get("operations", []):
            atom = deepcopy(dict(clause)); atom["resources"] = [deepcopy(dict(resource))]; atom["resources"][0]["operations"] = [operation]
            if not any(_manifest_covers({**manifest, "effect_bounds": [atom]}, entry) for entry in entries):
                return False
    return True


def _policy_covers(policy: Mapping[str, Any], operation_id: str, selected_id: str, entry: Mapping[str, Any]) -> bool:
    selector = _mapping(entry.get("selector")) or {}
    value = selector.get("canonical_path", selector.get("canonical_endpoint", selector.get("resource_id")))
    for bound in policy.get("authority_map", []):
        if not _typed_effect_row_valid(bound) or bound.get("correlation_id") != selected_id or bound.get("operation_id") != operation_id or bound.get("effect") != entry.get("effect") or bound.get("resource_kind") != entry.get("resource_kind") or entry.get("operation") not in bound.get("operations", []) or not set(entry.get("facets", [])) <= set(bound.get("facets", [])) or bound.get("authority_constraints_digest") != canonical_digest(entry.get("constraints")):
            continue
        scope = _mapping(bound.get("scope")) or {}
        expected_scope_kind = {"FILE": "PATH", "DIRECTORY": "PATH", "ENDPOINT": "ENDPOINT", "PRINCIPAL": "PRINCIPAL", "MEMORY": "MEMORY", "PROMPT": "PROMPT", "POLICY": "POLICY", "PROCESS": "PROCESS", "REGISTRY": "LOCAL_RESOURCE", "COMPUTE_RESOURCE": "LOCAL_RESOURCE"}.get(entry.get("resource_kind"))
        if scope.get("kind") != expected_scope_kind:
            continue
        if scope.get("kind") == "PATH" and (scope.get("descriptor_binding_digest") != selector.get("descriptor_binding_digest") or scope.get("physical_target_digest") != selector.get("physical_target_digest")):
            continue
        if scope.get("kind") == "PATH" and isinstance(value, str) and any(value == prefix or value.startswith(str(prefix).rstrip("/") + "/") for prefix in scope.get("values", [])):
            return True
        if scope.get("kind") == "ENDPOINT":
            policy_binding = _mapping(scope.get("endpoint_binding")) or {}
            candidate_binding = {key: selector.get(key) for key in ENDPOINT_BINDING_FIELDS}
            if _endpoint_binding_valid(policy_binding) and _endpoint_binding_valid(candidate_binding) and policy_binding == candidate_binding and scope.get("values") == [value] and value == policy_binding.get("canonical_endpoint"):
                return True
            continue
        if value in scope.get("values", []):
            return True
    return False


def _trusted_descriptor(entry: Mapping[str, Any], facts: Mapping[str, Any]) -> bool:
    selector = _mapping(entry.get("selector")) or {}
    descriptor_id = selector.get("descriptor_id")
    trusted = _mapping((_mapping(facts.get("trusted_descriptors")) or {}).get(descriptor_id))
    if trusted is None:
        return False
    return bool(
        trusted.get("descriptor_id") == descriptor_id
        and trusted.get("canonical_path", trusted.get("canonical_endpoint", trusted.get("resource_id"))) == selector.get("canonical_path", selector.get("canonical_endpoint", selector.get("resource_id")))
        and isinstance(trusted.get("root_identity"), str)
        and isinstance(trusted.get("mount_identity"), str)
        and isinstance(trusted.get("epoch"), int)
        and trusted.get("signature_verified") is True
        and trusted.get("not_revoked") is True
        and selector.get("descriptor_binding_digest") == canonical_digest({"descriptor_id": descriptor_id, "root_identity": trusted.get("root_identity"), "mount_identity": trusted.get("mount_identity"), "epoch": trusted.get("epoch")})
    )


def _verified_filesystem_target(target: Mapping[str, Any], digest: Any, records: Any) -> bool:
    record = _mapping((_mapping(records) or {}).get(digest))
    unsigned = {key: value for key, value in target.items() if key != "composite_binding_digest"}
    return bool(
        _valid_digest(digest) and target.get("composite_binding_digest") == digest == canonical_digest(unsigned)
        and record is not None and record.get("physical_target_digest") == digest
        and all(record.get(key) == target.get(key) for key in target)
        and record.get("signature_verified") is True and record.get("not_revoked") is True
        and record.get("verified_by") and record.get("key_id") and record.get("trust_root")
        and record.get("algorithm") in {"ED25519", "ECDSA_P256_SHA256"}
    )


def _capability_filesystem_target_digests(capability: Mapping[str, Any], identity: Mapping[str, Any]) -> set[str]:
    return {
        selector.get("physical_target_digest")
        for effect in capability.get("effects", []) if isinstance(effect, Mapping)
        for selector in [_mapping(effect.get("selector")) or {}]
        if effect.get("resource_kind") in {"FILE", "DIRECTORY"}
        and selector.get("kind") == "PATH_DESCRIPTOR"
        and selector.get("reference") == identity.get("descriptor_id")
        and _valid_digest(selector.get("physical_target_digest"))
    }


def _capability_endpoint_binding_digests(capability: Mapping[str, Any]) -> set[str]:
    return {
        binding.get("endpoint_binding_digest")
        for effect in capability.get("effects", []) if isinstance(effect, Mapping) and effect.get("resource_kind") == "ENDPOINT"
        for selector in [_mapping(effect.get("selector")) or {}]
        for binding in [_mapping(selector.get("endpoint_binding")) or {}]
        if _endpoint_binding_valid(binding)
    }


def _verified_endpoint_binding(binding: Mapping[str, Any], records: Any, trusted_time: Any) -> bool:
    digest = binding.get("endpoint_binding_digest")
    record = _mapping((_mapping(records) or {}).get(digest))
    now, verified, expires = _parse_time(trusted_time), _parse_time((record or {}).get("verified_at")), _parse_time((record or {}).get("expires_at"))
    return bool(
        _endpoint_binding_valid(binding) and record
        and all(record.get(key) == binding.get(key) for key in ENDPOINT_BINDING_FIELDS)
        and record.get("signature_verified") is True and record.get("not_revoked") is True and record.get("current_key") is True
        and record.get("verified_by") and record.get("key_id") and record.get("trust_root")
        and record.get("algorithm") in {"ED25519", "ECDSA_P256_SHA256"}
        and now is not None and verified is not None and expires is not None and verified <= now < expires
    )


def _compiled_filesystem_target(entry: Mapping[str, Any], routes: tuple[Any, ...], facts: Mapping[str, Any]) -> bool:
    if entry.get("resource_kind") not in {"FILE", "DIRECTORY"}:
        return True
    selector = _mapping(entry.get("selector")) or {}
    descriptor = _mapping((_mapping(facts.get("trusted_descriptors")) or {}).get(selector.get("descriptor_id"))) or {}
    path = selector.get("canonical_path")
    def route_matches(route: Any) -> bool:
        for target in (_mapping(route) or {}).get("filesystem_targets", []):
            if not isinstance(target, Mapping):
                continue
            if target.get("canonical_path") == path and target.get("descriptor_id") == selector.get("descriptor_id") and target.get("root_id") == descriptor.get("root_id") and target.get("root_identity") == descriptor.get("root_identity") and target.get("mount_id") == descriptor.get("mount_id") and target.get("mount_identity") == descriptor.get("mount_identity") and target.get("resolution_epoch") == descriptor.get("epoch") and selector.get("physical_target_digest") == target.get("composite_binding_digest") and _verified_filesystem_target(target, selector.get("physical_target_digest"), facts.get("verified_filesystem_targets")):
                return True
        return False
    return all(route_matches(route) for route in routes)


def validate_loop_contract(contract: Any, trusted_facts: Mapping[str, Any] | None = None) -> bool:
    """Validate the complete signed loop-control object, never a summary projection."""
    contract, facts = _mapping(contract), _mapping(trusted_facts) or {}
    if contract is None:
        return False
    required = {"schema_version", "contract_id", "contract_version", "contract_digest", "status", "principal", "audience", "authority_domain", "allowed_effects", "allowed_operations", "aggregate_budgets", "iteration_bound", "d2", "artifact_bindings", "postcheck", "human_confirmation", "lifecycle", "material_change_invalidates"}
    if set(contract) != required or contract.get("schema_version") != "1.0.0" or contract.get("status") != "ACTIVE" or contract.get("material_change_invalidates") is not True:
        return False
    if contract.get("contract_digest") != canonical_digest({key: value for key, value in contract.items() if key != "contract_digest"}):
        return False
    domain, bound, d2 = _mapping(contract.get("authority_domain")) or {}, _mapping(contract.get("iteration_bound")) or {}, _mapping(contract.get("d2")) or {}
    postcheck, human, lifecycle = _mapping(contract.get("postcheck")) or {}, _mapping(contract.get("human_confirmation")) or {}, _mapping(contract.get("lifecycle")) or {}
    artifacts, records = _mapping(contract.get("artifact_bindings")) or {}, _mapping(facts.get("verified_loop_contracts")) or {}
    external = _mapping(records.get(contract.get("contract_digest")))
    authoritative = _mapping(external.get("contract")) if external else None
    issued, start, expires, now = _parse_time(lifecycle.get("issued_at")), _parse_time(lifecycle.get("not_before")), _parse_time(lifecycle.get("expires_at")), _parse_time(facts.get("trusted_time"))
    return bool(
        isinstance(contract.get("contract_id"), str) and contract.get("contract_id") and isinstance(contract.get("principal"), str) and contract.get("principal") and isinstance(contract.get("audience"), str) and contract.get("audience")
        and isinstance(contract.get("contract_version"), int) and contract["contract_version"] >= 1
        and set(domain) == {"domain_id", "definition_status", "journal_lineage_id"} and domain.get("definition_status") == "PROVISIONAL" and all(isinstance(domain.get(key), str) and domain.get(key) for key in ("domain_id", "journal_lineage_id"))
        and set(bound) == {"max_iterations", "counter_source", "monotonic", "durable", "reset_on_restart", "reset_on_retry", "reset_on_nested_contract"} and isinstance(bound.get("max_iterations"), int) and bound["max_iterations"] >= 1 and bound.get("counter_source") == "CANONICAL_DURABLE_JOURNAL" and all(bound.get(key) is value for key, value in (("monotonic", True), ("durable", True), ("reset_on_restart", False), ("reset_on_retry", False), ("reset_on_nested_contract", False)))
        and d2 == {"definition_status": "PROVISIONAL", "operational_bound": "NO_CONTROLLER_VISIBLE_PERSISTED_STAGED_TOOL_BOUND_BUDGETED_REUSABLE_N_PLUS_2_BEFORE_JOIN_N_PLUS_1", "private_ephemeral_tokens_excluded": True}
        and isinstance(contract.get("allowed_effects"), list) and bool(contract["allowed_effects"]) and set(contract["allowed_effects"]) <= EFFECTS
        and isinstance(contract.get("allowed_operations"), list) and bool(contract["allowed_operations"]) and all(isinstance(row, Mapping) and set(row) == {"operation_id", "manifest_digest", "effects", "scopes", "approval_class"} and isinstance(row.get("operation_id"), str) and _valid_digest(row.get("manifest_digest")) and isinstance(row.get("effects"), list) and bool(row["effects"]) and set(row["effects"]) <= set(contract["allowed_effects"]) and isinstance(row.get("scopes"), list) and bool(row["scopes"]) and row.get("approval_class") in {"NONE", "PREAUTHORIZED_EXACT", "HUMAN_SINGLE", "HUMAN_DUAL"} for row in contract["allowed_operations"])
        and _budget_map([{**row, "amount": row.get("limit")} for row in contract.get("aggregate_budgets", [])], "amount") is not None
        and set(artifacts) == {"policy_digest", "registry_digest", "isolation_profile_digest", "prompt_digest", "context_digest", "model_digest", "toolset_digest"} and all(_valid_digest(artifacts.get(key)) for key in artifacts)
        and postcheck.get("required_each_iteration") is True and postcheck.get("independent_observer") is True and _valid_digest(postcheck.get("plan_digest")) and postcheck.get("failure_result") == "STOPPED_NEW_TRANSACTION_REQUIRED"
        and human.get("mode") in {"NOT_REQUIRED", "PER_CONTRACT_AGGREGATE"} and human.get("machine_join_each_iteration") is True and human.get("may_expand_physical_ceiling") is False and ((human.get("mode") == "NOT_REQUIRED" and human.get("receipt_digest") is None) or (human.get("mode") == "PER_CONTRACT_AGGREGATE" and _valid_digest(human.get("receipt_digest"))))
        and all(isinstance(lifecycle.get(key), int) and not isinstance(lifecycle.get(key), bool) and lifecycle[key] >= 0 for key in ("revocation_epoch",)) and issued is not None and start is not None and expires is not None and issued <= start < expires and now is not None and start <= now < expires
        and authoritative == contract and external.get("signature_verified") is True and external.get("not_revoked") is True and external.get("freshness_verified") is True and external.get("current_key") is True and external.get("current_revocation_epoch") == lifecycle.get("revocation_epoch") == facts.get("current_revocation_epoch")
    )


def _trusted_contract(candidate: Mapping[str, Any], entries: list[Mapping[str, Any]], facts: Mapping[str, Any]) -> bool:
    bindings = _mapping(candidate.get("bindings")) or {}
    digest, contract_id = bindings.get("contract_digest"), bindings.get("contract_id")
    contract = _mapping((_mapping(facts.get("trusted_loop_contracts")) or {}).get(digest))
    if contract is None or not validate_loop_contract(contract, facts) or contract.get("contract_digest") != digest or contract.get("contract_id") != contract_id:
        return False
    frontier = _mapping(candidate.get("d2_frontier")) or {}
    operation = next((row for row in contract.get("allowed_operations", []) if isinstance(row, Mapping) and row.get("operation_id") == candidate.get("operation_id") and row.get("manifest_digest") == bindings.get("manifest_digest")), None)
    aggregate = _budget_map([{**row, "amount": row.get("limit")} for row in contract.get("aggregate_budgets", [])], "amount")
    demands = _budget_map(candidate.get("budget_demands"), "amount")
    selector_values = {
        value for entry in entries for selector in [_mapping(entry.get("selector")) or {}]
        for value in [selector.get("canonical_path") or selector.get("canonical_endpoint") or selector.get("canonical_value")]
        if isinstance(value, str)
    }
    return bool(
        contract.get("principal") == candidate.get("principal")
        and contract.get("audience") == candidate.get("audience")
        and operation is not None and {entry.get("effect") for entry in entries} <= set(operation.get("effects", [])) and selector_values <= {value for scope in operation.get("scopes", []) if isinstance(scope, Mapping) for value in scope.get("values", [])}
        and aggregate is not None and demands is not None and all(amount <= aggregate.get(key, -1) for key, amount in demands.items())
        and contract["iteration_bound"].get("max_iterations", 0) >= candidate.get("iteration", 0)
        and contract["authority_domain"].get("domain_id") == frontier.get("authority_domain_id") and contract["authority_domain"].get("journal_lineage_id") == frontier.get("journal_lineage_id") and digest == frontier.get("root_contract_digest")
        and all(contract["artifact_bindings"].get(key) == bindings.get(key) for key in ("policy_digest", "registry_digest", "isolation_profile_digest"))
        and _iteration_slot_valid(candidate, facts)
    )


def _executor_audience(candidate: Mapping[str, Any], profile: Mapping[str, Any], facts: Mapping[str, Any], effect: str) -> bool:
    if effect != "MUTATE":
        return True
    if candidate.get("principal") == candidate.get("audience"):
        return False
    roles = {item.get("principal"): item.get("role") for item in profile.get("principal_envelopes", []) if isinstance(item, Mapping)}
    if roles.get(candidate.get("audience")) != "EXECUTOR":
        return False
    sessions = _mapping(facts.get("attested_executor_sessions")) or {}
    return sessions.get(candidate.get("audience")) == (_mapping(candidate.get("session_attestation")) or {}).get("session_id")


def _result(decision: str, reason: str, candidate: Mapping[str, Any] | None, envelope: list[dict[str, Any]] | None = None, reservations: tuple[dict[str, Any], ...] = (), obligations: tuple[str, ...] = ()) -> dict[str, Any]:
    candidate = candidate or {}
    bindings = _mapping(candidate.get("bindings")) or {}
    allowed = decision == "ALLOW"
    approval = _mapping(candidate.get("approval_receipt"))
    approval_mode = "REQUIRED" if decision == "REQUIRE_HUMAN" or approval is not None else "NOT_REQUIRED"
    approval_digest = approval.get("receipt_digest") if approval is not None and approval.get("decision") == "APPROVE" and _valid_digest(approval.get("receipt_digest")) else None
    target_evaluation = ({"endpoint_binding_digest": bindings.get("endpoint_binding_digest", ZERO_DIGEST)} if "endpoint_binding_digest" in bindings else {"descriptor_binding_digest": bindings.get("descriptor_binding_digest", ZERO_DIGEST)})
    result: dict[str, Any] = {
        "schema_version": "1.0.0", "decision": decision, "reason_codes": [reason],
        "authorized_effects": sorted({item["effect"] for item in envelope or []}) if allowed else [],
        "authorized_envelope": envelope if allowed and envelope else [], "obligations": sorted(set(obligations)) if allowed else [],
        "reservations": list(reservations) if allowed else [], "capability_issuance": allowed, "approval_receipt_digest": approval_digest if allowed else None,
        "next_state": "ADMITTED" if allowed else ("HUMAN_PENDING" if decision == "REQUIRE_HUMAN" else "STOPPED"),
        "evaluation": {"request_digest": candidate.get("request_digest", ZERO_DIGEST), "manifest_digest": bindings.get("manifest_digest", ZERO_DIGEST), "policy_digest": bindings.get("policy_digest", ZERO_DIGEST), "contract_id": bindings.get("contract_id", "contract:invalid"), "contract_digest": bindings.get("contract_digest", ZERO_DIGEST), "iteration_slot_digest": (_mapping(candidate.get("iteration_slot")) or {}).get("slot_record_digest", ZERO_DIGEST), "d2_frontier_digest": (_mapping(candidate.get("d2_frontier")) or {}).get("frontier_record_digest", ZERO_DIGEST), "d2_frontier_record": deepcopy(candidate.get("d2_frontier")), "capability_digest": None, "approval_mode": approval_mode, "approval_receipt_digest": approval_digest if allowed else None, "registry_digest": bindings.get("registry_digest", ZERO_DIGEST), "isolation_profile_digest": bindings.get("isolation_profile_digest", ZERO_DIGEST), "placement_attestation_digest": bindings.get("placement_attestation_digest", ZERO_DIGEST), "session_attestation_digest": bindings.get("session_attestation_digest", ZERO_DIGEST), "broker_ipc_attestation_digest": bindings.get("broker_ipc_attestation_digest", ZERO_DIGEST), "broker_ipc_binding_digest": bindings.get("broker_ipc_binding_digest", ZERO_DIGEST), "resource_vector_digest": bindings.get("resource_vector_digest", ZERO_DIGEST), "supply_chain_measurement_digest": bindings.get("supply_chain_measurement_digest", ZERO_DIGEST), **target_evaluation, "evaluated_at": candidate.get("evaluated_at", EPOCH)},
    }
    result["decision_digest"] = canonical_digest(result)
    return result


def decision_digest_valid(decision: Any) -> bool:
    return isinstance(decision, Mapping) and _self_digest_valid(decision, "decision_digest")


def decide(candidate: Any, manifest: Any, policy: Any, isolation_profile: Any, durable_facts: Any) -> dict[str, Any]:
    candidate_m, manifest_m, policy_m, isolation_m, facts_m = map(_mapping, (candidate, manifest, policy, isolation_profile, durable_facts))
    try:
        if None in (candidate_m, manifest_m, policy_m, isolation_m, facts_m):
            return _result("STOP", "MALFORMED_INPUT", candidate_m)
        assert candidate_m is not None and manifest_m is not None and policy_m is not None and isolation_m is not None and facts_m is not None
        if manifest_m.get("status") != "ACTIVE" or policy_m.get("status") != "ACTIVE" or not validate_isolation_profile(isolation_m, facts_m):
            return _result("DENY", "INACTIVE_OR_INVALID_CONTROL_ARTIFACT", candidate_m)
        runtime_requirements = _mapping(manifest_m.get("runtime_requirements")) or {}
        if runtime_requirements.get("isolation_profile_id") != isolation_m.get("profile_id") or runtime_requirements.get("isolation_profile_digest") != isolation_m.get("profile_digest"):
            return _result("STOP", "PROFILE_MISMATCH", candidate_m)
        physical_ceiling = _mapping(policy_m.get("physical_ceiling")) or {}
        if physical_ceiling.get("isolation_profile_id") != isolation_m.get("profile_id") or physical_ceiling.get("isolation_profile_digest") != isolation_m.get("profile_digest"):
            return _result("STOP", "PROFILE_MISMATCH", candidate_m)
        registry_digest = (_mapping(policy_m.get("registry_snapshot")) or {}).get("digest")
        if not _activation_valid(policy_m, "policy_digest", "policy_activation", facts_m.get("verified_policy_activations"), None, facts_m.get("trusted_time")):
            return _result("DENY", "POLICY_ACTIVATION_INVALID", candidate_m)
        bindings = _mapping(candidate_m.get("bindings")) or {}
        if facts_m.get("host_recovery_required") and not _trusted_host_recovery_valid(facts_m, facts_m.get("host_recovery_evidence_ref"), facts_m.get("current_fencing_epoch")):
            return _result("STOP", "HOST_RECOVERY_GATE_REQUIRED", candidate_m)
        expected = {"manifest_digest": canonical_digest(manifest_m), "policy_digest": _control_content_digest(policy_m, "policy_digest", "policy_activation"), "registry_digest": registry_digest, "isolation_profile_digest": _control_content_digest(isolation_m, "profile_digest", "profile_activation")}
        if any(bindings.get(key) != value for key, value in expected.items()):
            return _result("DENY", "MATERIAL_BINDING_MISMATCH", candidate_m)
        if candidate_m.get("operation_id") != manifest_m.get("operation_id"):
            return _result("DENY", "OPERATION_MISMATCH", candidate_m)
        if not _manifest_trusted(manifest_m, bindings.get("manifest_digest"), facts_m):
            return _result("DENY", "MANIFEST_TRUST_INVALID", candidate_m)
        if not validate_attestations(candidate_m, facts_m):
            return _result("DENY", "PLACEMENT_OR_SESSION_ATTESTATION_INVALID", candidate_m)
        if not validate_broker_ipc_attestation(candidate_m, isolation_m, facts_m):
            return _result("DENY", "BROKER_IPC_ATTESTATION_INVALID", candidate_m)
        if bindings.get("resource_vector_digest") != canonical_digest(isolation_m.get("resources")):
            return _result("DENY", "RESOURCE_VECTOR_BINDING_INVALID", candidate_m)
        if not validate_supply_chain(candidate_m, isolation_m, facts_m):
            return _result("DENY", "SUPPLY_CHAIN_MEASUREMENT_INVALID", candidate_m)
        if not validate_d2_frontier(candidate_m, facts_m):
            return _result("DENY", "D2_TYPED_FRONTIER_VIOLATION", candidate_m)
        compiled = isolation_m.get("compiled_envelopes")
        if not isinstance(compiled, list) or len(compiled) != 2:
            return _result("STOP", "ISOLATION_ENVELOPE_MISSING", candidate_m)
        role_by_principal = {item.get("principal"): item for item in isolation_m.get("principal_envelopes", []) if isinstance(item, Mapping)}
        for route in compiled:
            if not isinstance(route, Mapping):
                return _result("DENY", "COMPILED_EFFECT_EXCEEDS_PRINCIPAL_CEILING", candidate_m)
            ceiling = set((role_by_principal.get(route.get("principal")) or {}).get("effect_ceiling", []))
            if not set(route.get("allowed_effects", [])) <= ceiling:
                return _result("DENY", "COMPILED_EFFECT_EXCEEDS_PRINCIPAL_CEILING", candidate_m)
        principal_env = next((item for item in compiled if isinstance(item, Mapping) and item.get("principal") == candidate_m.get("principal")), None)
        audience_env = next((item for item in compiled if isinstance(item, Mapping) and item.get("audience") == candidate_m.get("audience")), None)
        if principal_env is None or audience_env is None:
            return _result("DENY", "ISOLATION_PRINCIPAL_AUDIENCE_MISMATCH", candidate_m)
        entries = _selected_authority(candidate_m)
        if entries is None:
            return _result("STOP", "AUTHORITY_ALTERNATIVE_MALFORMED", candidate_m)
        if not _selected_target_binding_valid(entries, bindings):
            return _result("DENY", "TARGET_BINDING_MISMATCH", candidate_m)
        required_clauses = _manifest_derived_closure(manifest_m, entries)
        if required_clauses is None:
            return _result("STOP", "MANIFEST_DERIVED_CLOSURE_INVALID", candidate_m)
        if not all(_manifest_clause_atoms_covered(manifest_m, clause, entries) for clause in required_clauses):
            return _result("DENY", "DERIVED_CLAUSE_UNAUTHORIZED", candidate_m)
        demands = candidate_m.get("budget_demands")
        if isinstance(demands, list) and len({(item.get("name"), item.get("unit"), item.get("scope_digest"), item.get("lineage_root")) for item in demands if isinstance(item, Mapping)}) != len(demands):
            return _result("DENY", "BUDGET_EXCEEDED_OR_DUPLICATE_BOUND", candidate_m)
        selected_id = candidate_m["selected_alternative_id"]
        rules = [item for item in policy_m.get("authority_map", []) if isinstance(item, Mapping) and item.get("correlation_id") == selected_id and item.get("operation_id") == candidate_m.get("operation_id")]
        if any(item.get("approval_class") == "DENY" for item in rules):
            return _result("DENY", "EXPLICIT_POLICY_DENY", candidate_m)
        for entry in entries:
            if not _executor_audience(candidate_m, isolation_m, facts_m, entry.get("effect")):
                return _result("DENY", "MUTATION_AUDIENCE_INVALID", candidate_m)
            if (entry.get("effect") not in principal_env.get("allowed_effects", []) or entry.get("effect") not in audience_env.get("allowed_effects", []) or entry.get("resource_kind") not in principal_env.get("allowed_resource_kinds", []) or entry.get("resource_kind") not in audience_env.get("allowed_resource_kinds", []) or entry.get("operation") not in principal_env.get("allowed_operations", []) or entry.get("operation") not in audience_env.get("allowed_operations", []) or not _selector_contained(entry, principal_env) or not _selector_contained(entry, audience_env)):
                return _result("DENY", "ISOLATION_ENVELOPE_MISMATCH", candidate_m)
            if entry.get("resource_kind") in {"FILE", "DIRECTORY"}:
                if not _trusted_descriptor(entry, facts_m):
                    return _result("DENY", "DESCRIPTOR_IDENTITY_INVALID", candidate_m)
                if not _compiled_filesystem_target(entry, (principal_env, audience_env), facts_m):
                    return _result("STOP", "COMPILED_FILESYSTEM_TARGET_MISMATCH", candidate_m)
            elif entry.get("resource_kind") == "ENDPOINT":
                endpoint = {key: (_mapping(entry.get("selector")) or {}).get(key) for key in ENDPOINT_BINDING_FIELDS}
                if not _verified_endpoint_binding(endpoint, facts_m.get("verified_endpoint_bindings"), facts_m.get("trusted_time")):
                    return _result("DENY", "ENDPOINT_IDENTITY_INVALID", candidate_m)
            if not _manifest_covers(manifest_m, entry):
                return _result("DENY", "SCOPE_EXCEEDS_MANIFEST", candidate_m)
            if not _policy_covers(policy_m, candidate_m["operation_id"], selected_id, entry):
                return _result("DENY", "SCOPE_EXCEEDS_CORRELATED_POLICY", candidate_m)
            if entry["effect"] not in set((_mapping(policy_m.get("physical_ceiling")) or {}).get("mediated_sink_effects", [])):
                return _result("DENY", "EFFECT_EXCEEDS_PHYSICAL_CEILING", candidate_m)
        reservations = budget_reservations(candidate_m.get("budget_demands"), (manifest_m.get("resource_envelope"), "limit"), (policy_m.get("budgets"), "limit"), (facts_m.get("remaining_budgets"), "amount"))
        if reservations is None:
            return _result("DENY", "BUDGET_EXCEEDED_OR_DUPLICATE_BOUND", candidate_m)
        required_budget_names = {name for item in rules for name in item.get("budget_names", [])}
        if {(item["name"], item["unit"], item["scope_digest"], item["lineage_root"]) for item in reservations} != {(item["name"], item["unit"], item["scope_digest"], item["lineage_root"]) for item in candidate_m.get("budget_demands", [])} or {item["name"] for item in reservations} != required_budget_names:
            return _result("DENY", "BUDGET_VECTOR_BINDING_MISMATCH", candidate_m)
        if not _trusted_contract(candidate_m, entries, facts_m):
            return _result("DENY", "LOOP_CONTRACT_TRUST_INVALID", candidate_m)
        if facts_m.get("telemetry_ready") is not True and any(entry["effect"] in SIDE_EFFECTS for entry in entries):
            return _result("STOP", "TELEMETRY_MISSING", candidate_m)
        envelope = [_decision_entry(entry) for entry in entries]
        if any(item.get("approval_class") in {"HUMAN_SINGLE", "HUMAN_DUAL"} for item in rules):
            if not validate_authoritative_approval(candidate_m.get("approval_receipt"), candidate_m, envelope, reservations, facts_m):
                return _result("REQUIRE_HUMAN", "EXACT_APPROVAL_REQUIRED", candidate_m)
        obligations = tuple(sorted({ob for item in rules for ob in item.get("obligations", [])})) + ("durable.atomic_dispatch", "event.authoritative_unsampled", "descriptor.runtime_enforced")
        return _result("ALLOW", "AUTHORIZED_EXACT_BOUND", candidate_m, envelope, reservations, obligations)
    except (AssertionError, KeyError, TypeError, ValueError, OverflowError, RecursionError):
        return _result("STOP", "INTERNAL_EVALUATION_ERROR", candidate_m)


def mint_capability(decision: Any, candidate: Any, *, issuer: str = "broker:reference") -> dict[str, Any] | None:
    if not isinstance(decision, Mapping) or not isinstance(candidate, Mapping) or decision.get("decision") != "ALLOW" or not decision_digest_valid(decision) or not decision.get("authorized_envelope"):
        return None
    selected_entries = _selected_authority(candidate)
    if selected_entries is None or not _selected_target_binding_valid(selected_entries, candidate.get("bindings")) or not _selected_target_binding_valid(decision.get("authorized_envelope"), candidate.get("bindings")):
        return None
    evaluation = _mapping(decision.get("evaluation")) or {}
    approval = _mapping(candidate.get("approval_receipt"))
    approval_mode, approval_digest = evaluation.get("approval_mode"), evaluation.get("approval_receipt_digest")
    if decision.get("approval_receipt_digest") != approval_digest or approval_mode not in {"NOT_REQUIRED", "REQUIRED"}:
        return None
    if approval_mode == "REQUIRED" and (approval is None or approval_digest != approval.get("receipt_digest") or not _valid_digest(approval_digest)):
        return None
    if approval_mode == "NOT_REQUIRED" and (approval is not None or approval_digest is not None):
        return None
    bindings, placement, session = _mapping(candidate.get("bindings")) or {}, _mapping(candidate.get("placement_attestation")) or {}, _mapping(candidate.get("session_attestation")) or {}
    endpoint_digest, descriptor_digest = bindings.get("endpoint_binding_digest"), bindings.get("descriptor_binding_digest")
    if (_valid_digest(endpoint_digest)) is (_valid_digest(descriptor_digest)):
        return None
    target_binding = {"endpoint_binding_digest": endpoint_digest} if _valid_digest(endpoint_digest) else {"descriptor_binding_digest": descriptor_digest}
    capability: dict[str, Any] = {
        "schema_version": "1.0.0", "capability_id": "cap:" + candidate["request_id"].replace(":", "."), "issuer": issuer,
        "principal": candidate["principal"], "audience": candidate["audience"], "purpose": candidate["purpose"],
        "bindings": {"contract_id": bindings["contract_id"], "contract_digest": bindings["contract_digest"], "iteration_slot_digest": evaluation["iteration_slot_digest"], "d2_frontier_digest": evaluation["d2_frontier_digest"], "manifest_digest": bindings["manifest_digest"], "policy_digest": bindings["policy_digest"], "request_digest": candidate["request_digest"], "decision_digest": decision["decision_digest"], "authorized_envelope_digest": canonical_digest(decision["authorized_envelope"]), "approval_mode": decision.get("evaluation", {}).get("approval_mode", "NOT_REQUIRED"), "approval_receipt_digest": decision.get("evaluation", {}).get("approval_receipt_digest"), "registry_digest": bindings["registry_digest"], "isolation_profile_digest": bindings["isolation_profile_digest"], "placement_attestation_digest": bindings["placement_attestation_digest"], "session_attestation_digest": bindings["session_attestation_digest"], "broker_ipc_attestation_digest": bindings["broker_ipc_attestation_digest"], "broker_ipc_binding_digest": bindings["broker_ipc_binding_digest"], "resource_vector_digest": bindings["resource_vector_digest"], "supply_chain_measurement_digest": bindings["supply_chain_measurement_digest"], **target_binding},
        "execution_binding": {"subject_instance_id": placement["subject_instance_id"], "session_id": session["session_id"], "placement_nonce": placement["nonce"], "placement_epoch": placement["epoch"], "session_nonce": session["nonce"], "session_epoch": session["epoch"]},
        "effects": deepcopy(decision["authorized_envelope"]), "budgets": deepcopy(decision["reservations"]),
        "nonce": sha256((candidate["request_digest"] + decision["decision_digest"]).encode()).hexdigest()[:32],
        "lineage": {"contract_id": bindings["contract_id"], "session_id": session["session_id"], "iteration": candidate["iteration"], "call_id": candidate["request_id"], "parent_capability_digest": None, "fencing_epoch": session["epoch"]},
        "issued_at": candidate["evaluated_at"], "not_before": candidate["evaluated_at"], "expires_at": session["expires_at"], "revocation_epoch": session["epoch"],
        "single_use": True, "nonreplayable": True, "nontransferable": True, "short_lived": True, "state": "ISSUED", "consumption": None,
    }
    signed_claims_digest = canonical_digest(capability)
    capability["issuer_verification"] = {"verified_by": "verifier:capability", "key_id": "key:capability", "algorithm": "ED25519", "signed_claims_digest": signed_claims_digest, "signature_verified": True, "verified_at": candidate["evaluated_at"], "revocation_epoch": session["epoch"], "fencing_epoch": session["epoch"]}
    capability["capability_digest"] = canonical_digest(capability)
    return capability


def _capability_signed_claims(capability: Mapping[str, Any]) -> dict[str, Any]:
    return {key: deepcopy(value) for key, value in capability.items() if key not in {"capability_digest", "issuer_verification"}}


def capability_verifier_record(capability: Mapping[str, Any]) -> dict[str, Any]:
    """Projection held by an external durable verifier; caller claims are not authority."""
    return {
        "capability_digest": capability.get("capability_digest"),
        "signed_claims_digest": (_mapping(capability.get("issuer_verification")) or {}).get("signed_claims_digest"),
        "issuer": capability.get("issuer"), "principal": capability.get("principal"),
        "audience": capability.get("audience"), "purpose": capability.get("purpose"),
        "contract_digest": (_mapping(capability.get("bindings")) or {}).get("contract_digest"),
        "lineage_digest": canonical_digest(capability.get("lineage")),
        "delegation_digest": canonical_digest(capability.get("delegation")) if capability.get("delegation") is not None else None,
        "bindings_digest": canonical_digest(capability.get("bindings")),
        "effects_digest": canonical_digest(capability.get("effects")),
        "budgets_digest": canonical_digest(capability.get("budgets")),
        "signature_verified": True, "not_revoked": True, "full_claims_verified": True,
        "verified_by": (_mapping(capability.get("issuer_verification")) or {}).get("verified_by"),
    }


def _trusted_delegation_record(store: Mapping[str, Any], capability: Mapping[str, Any], revoked_digests: Any = ()) -> bool:
    lineage, delegation = _mapping(capability.get("lineage")) or {}, _mapping(capability.get("delegation"))
    parent_digest = lineage.get("parent_capability_digest")
    if parent_digest is None:
        return delegation is None
    record = _mapping((_mapping(store.get("delegations")) or {}).get(capability.get("capability_digest")))
    status = _mapping((_mapping(store.get("parent_statuses")) or {}).get(parent_digest))
    verifier = _mapping((_mapping(store.get("parent_status_verifiers")) or {}).get((status or {}).get("verified_by")))
    current_fence = (_mapping(store.get("current_parent_fencing_epochs")) or {}).get(parent_digest)
    current_revocation_epoch = (_mapping(store.get("current_parent_revocation_epochs")) or {}).get(parent_digest)
    now, verified, expires = _parse_time(store.get("trusted_time")), _parse_time((status or {}).get("verified_at")), _parse_time((status or {}).get("expires_at"))
    unsigned = {key: deepcopy(value) for key, value in (status or {}).items() if key != "status_digest"}
    return bool(
        delegation and record and status and verifier
        and delegation.get("parent_capability_digest") == parent_digest
        and parent_digest not in set(revoked_digests or ())
        and record.get("delegation_digest") == canonical_digest(delegation)
        and all(record.get(key) == delegation.get(key) for key in ("parent_capability_id", "parent_capability_digest", "parent_envelope_digest", "parent_delegation_clause_digest", "root_lineage_digest", "edge_nonce", "child_principal", "child_audience", "fencing_epoch"))
        and record.get("parent_state") == "ISSUED"
        and record.get("ancestor_revoked") is False
        and record.get("not_revoked") is True
        and record.get("verified_by")
        and status.get("parent_capability_id") == delegation.get("parent_capability_id")
        and status.get("parent_capability_digest") == parent_digest
        and status.get("delegation_digest") == canonical_digest(delegation)
        and all(status.get(key) == delegation.get(key) for key in ("parent_envelope_digest", "parent_delegation_clause_digest", "root_lineage_digest", "fencing_epoch"))
        and status.get("parent_state") == "ISSUED" and status.get("ancestor_revoked") is False
        and status.get("parent_fencing_epoch") == current_fence == delegation.get("fencing_epoch")
        and status.get("current_revocation_epoch") == current_revocation_epoch
        and status.get("signature_verified") is True and status.get("not_revoked") is True
        and status.get("verifier_key_id") and status.get("verifier_trust_root") and status.get("verifier_algorithm") in {"ED25519", "ECDSA_P256_SHA256"} and isinstance(status.get("verifier_signature"), str) and bool(status.get("verifier_signature"))
        and all(verifier.get(key) == status.get(key) for key in ("verified_by", "verifier_key_id", "verifier_trust_root", "verifier_algorithm"))
        and verifier.get("signature_verified") is True and verifier.get("not_revoked") is True and verifier.get("current_key") is True
        and _valid_digest(status.get("status_digest")) and status.get("status_digest") == canonical_digest(unsigned)
        and now is not None and verified is not None and expires is not None and verified <= now < expires
    )


def _d2_frontier_record_valid(frontier: Mapping[str, Any]) -> bool:
    fields = {"definition_status", "contract_digest", "contract_version", "authority_domain_id", "journal_lineage_id", "root_contract_digest", "parent_contract_digest", "journal_sequence", "fencing_epoch", "frontier_record_digest", "joined_iteration", "max_iteration", "durable_state_digest", "inventory"}
    artifact_fields = {"artifact_id", "class", "iteration", "controller_visible", "persisted", "staged", "tool_bound", "budgeted", "reusable"}
    inventory = frontier.get("inventory")
    return bool(
        set(frontier) == fields
        and frontier.get("definition_status") == "PROVISIONAL_OPERATIONAL" and frontier.get("contract_version") == "1.0.0"
        and all(_valid_digest(frontier.get(key)) for key in ("contract_digest", "root_contract_digest", "frontier_record_digest", "durable_state_digest"))
        and (frontier.get("parent_contract_digest") is None or _valid_digest(frontier.get("parent_contract_digest")))
        and all(isinstance(frontier.get(key), str) and frontier.get(key) for key in ("authority_domain_id", "journal_lineage_id"))
        and all(isinstance(frontier.get(key), int) and not isinstance(frontier.get(key), bool) and frontier.get(key) >= 0 for key in ("journal_sequence", "fencing_epoch", "joined_iteration"))
        and isinstance(frontier.get("max_iteration"), int) and not isinstance(frontier.get("max_iteration"), bool) and frontier.get("max_iteration") >= 1
        and isinstance(inventory, list)
        and all(isinstance(item, Mapping) and set(item) == artifact_fields and isinstance(item.get("artifact_id"), str) and item.get("class") in D2_CLASSES and isinstance(item.get("iteration"), int) and not isinstance(item.get("iteration"), bool) and all(isinstance(item.get(key), bool) for key in artifact_fields - {"artifact_id", "class", "iteration"}) for item in inventory)
    )


def _trusted_runtime_d2_frontier(state: Mapping[str, Any], frontier_record: Any, contract_digest: Any) -> Mapping[str, Any] | None:
    """Resolve the current externally verified D2 binding for this transaction fence."""
    store = _mapping(state.get("trusted_store")) or {}
    frontier = _mapping(frontier_record)
    fence, transaction_id, sequence = state.get("fencing_epoch"), state.get("transaction_id"), state.get("journal_sequence")
    if frontier is None or not _d2_frontier_record_valid(frontier):
        return None
    frontier_digest = frontier.get("frontier_record_digest")
    records = _mapping(store.get("d2_frontier_verifications")) or {}
    record = _mapping(records.get(f"{frontier_digest}:{fence}"))
    if record is None:
        return None
    verifier = _mapping((_mapping(store.get("d2_frontier_verifiers")) or {}).get(record.get("verified_by")))
    unsigned_frontier = {key: deepcopy(value) for key, value in frontier.items() if key != "frontier_record_digest"}
    unsigned_record = {key: deepcopy(value) for key, value in record.items() if key != "verification_digest"}
    now, verified, expires = _parse_time(store.get("trusted_time")), _parse_time(record.get("verified_at")), _parse_time(record.get("expires_at"))
    expected = {"d2_frontier_digest": frontier_digest, "d2_frontier_record": frontier, "contract_digest": contract_digest, "transaction_id": transaction_id, "fencing_epoch": fence, "runtime_journal_sequence": sequence}
    return record if (
        all(record.get(key) == value for key, value in expected.items())
        and frontier.get("contract_digest") == contract_digest
        and frontier.get("frontier_record_digest") == canonical_digest(unsigned_frontier)
        and frontier.get("durable_state_digest") == canonical_digest(frontier.get("inventory"))
        and record.get("signature_verified") is True
        and record.get("not_revoked") is True
        and record.get("verifier_key_id") and record.get("verifier_trust_root") and record.get("verifier_algorithm") in {"ED25519", "ECDSA_P256_SHA256"} and isinstance(record.get("verifier_signature"), str) and bool(record.get("verifier_signature"))
        and verifier is not None and all(verifier.get(key) == record.get(key) for key in ("verified_by", "verifier_key_id", "verifier_trust_root", "verifier_algorithm"))
        and verifier.get("signature_verified") is True and verifier.get("not_revoked") is True and verifier.get("current_key") is True
        and _valid_digest(record.get("verification_digest")) and record.get("verification_digest") == canonical_digest(unsigned_record)
        and now is not None and verified is not None and expires is not None and verified <= now < expires
    ) else None


def validate_capability(capability: Any, decision: Any, candidate: Any, trusted_facts: Any) -> bool:
    if not isinstance(capability, Mapping) or not isinstance(decision, Mapping) or not isinstance(candidate, Mapping) or not _self_digest_valid(capability, "capability_digest") or not decision_digest_valid(decision):
        return False
    selected_entries = _selected_authority(candidate)
    if selected_entries is None or not _selected_target_binding_valid(selected_entries, candidate.get("bindings")) or not _selected_target_binding_valid(decision.get("authorized_envelope"), candidate.get("bindings")):
        return False
    facts = _mapping(trusted_facts) or {}
    bindings, execution, verification = _mapping(capability.get("bindings")) or {}, _mapping(capability.get("execution_binding")) or {}, _mapping(capability.get("issuer_verification")) or {}
    placement, session = _mapping(candidate.get("placement_attestation")) or {}, _mapping(candidate.get("session_attestation")) or {}
    # Recheck the external attestation projection at capability use; admission
    # freshness alone must not become a mutable caller-controlled cache.
    if not validate_attestations(candidate, facts):
        return False
    candidate_bindings = _mapping(candidate.get("bindings")) or {}
    approval = _mapping(candidate.get("approval_receipt"))
    approval_mode = (_mapping(decision.get("evaluation")) or {}).get("approval_mode")
    approval_digest = (_mapping(decision.get("evaluation")) or {}).get("approval_receipt_digest")
    approval_binding_ok = (approval_mode == "NOT_REQUIRED" and approval is None and approval_digest is None) or (approval_mode == "REQUIRED" and approval is not None and approval_digest == approval.get("receipt_digest") and _valid_digest(approval_digest))
    target_binding = ({"endpoint_binding_digest": candidate_bindings.get("endpoint_binding_digest")} if "endpoint_binding_digest" in candidate_bindings else {"descriptor_binding_digest": candidate_bindings.get("descriptor_binding_digest")})
    expected_bindings = {"contract_id": candidate_bindings.get("contract_id"), "contract_digest": candidate_bindings.get("contract_digest"), "iteration_slot_digest": (_mapping(candidate.get("iteration_slot")) or {}).get("slot_record_digest"), "d2_frontier_digest": (_mapping(candidate.get("d2_frontier")) or {}).get("frontier_record_digest"), "manifest_digest": candidate_bindings.get("manifest_digest"), "policy_digest": candidate_bindings.get("policy_digest"), "request_digest": candidate.get("request_digest"), "decision_digest": decision.get("decision_digest"), "authorized_envelope_digest": canonical_digest(decision.get("authorized_envelope")), "approval_mode": decision.get("evaluation", {}).get("approval_mode"), "approval_receipt_digest": decision.get("evaluation", {}).get("approval_receipt_digest"), "registry_digest": candidate_bindings.get("registry_digest"), "isolation_profile_digest": candidate_bindings.get("isolation_profile_digest"), "placement_attestation_digest": candidate_bindings.get("placement_attestation_digest"), "session_attestation_digest": candidate_bindings.get("session_attestation_digest"), "broker_ipc_attestation_digest": candidate_bindings.get("broker_ipc_attestation_digest"), "broker_ipc_binding_digest": candidate_bindings.get("broker_ipc_binding_digest"), "resource_vector_digest": candidate_bindings.get("resource_vector_digest"), "supply_chain_measurement_digest": candidate_bindings.get("supply_chain_measurement_digest"), **target_binding}
    expected_execution = {"subject_instance_id": placement.get("subject_instance_id"), "session_id": session.get("session_id"), "placement_nonce": placement.get("nonce"), "placement_epoch": placement.get("epoch"), "session_nonce": session.get("nonce"), "session_epoch": session.get("epoch")}
    signed_digest = canonical_digest(_capability_signed_claims(capability))
    trusted = (_mapping(facts.get("verified_capability_claims")) or {}).get(capability.get("capability_id"))
    now, not_before, expires = _parse_time(facts.get("trusted_time")), _parse_time(capability.get("not_before")), _parse_time(capability.get("expires_at"))
    delegation = _mapping(capability.get("delegation"))
    lineage = _mapping(capability.get("lineage")) or {}
    descendant = lineage.get("parent_capability_digest") is not None
    expected_lineage = {"contract_id": candidate_bindings.get("contract_id"), "session_id": session.get("session_id"), "iteration": candidate.get("iteration"), "call_id": candidate.get("request_id"), "parent_capability_digest": delegation.get("parent_capability_digest") if descendant and delegation else None, "fencing_epoch": session.get("epoch")}
    delegation_ok = not descendant and delegation is None
    if descendant:
        live_parents = _mapping(facts.get("live_parent_capabilities")) or {}
        parent = _mapping(live_parents.get(delegation.get("parent_capability_digest"))) if delegation else None
        parent_effects = _mapping(facts.get("parent_envelopes")) or {}
        parent_budgets = _mapping(facts.get("parent_budgets")) or {}
        parent_effect_rows = parent_effects.get(delegation.get("parent_capability_digest")) if delegation else None
        parent_budget_rows = parent_budgets.get(delegation.get("parent_capability_digest")) if delegation else None
        child_effects_digest = canonical_digest(capability.get("effects"))
        child_budgets_digest = canonical_digest(capability.get("budgets"))
        child_effects = capability.get("effects")
        child_budgets = capability.get("budgets")
        ledger = _mapping((_mapping(facts.get("parent_budget_ledgers")) or {}).get(delegation.get("parent_capability_digest"))) or {}
        sibling_rows = ledger.get("children")
        edge = _mapping((_mapping(facts.get("delegation_edges")) or {}).get(capability.get("capability_id"))) or {}
        delegation_clause = next((item for item in (parent_effect_rows or []) if isinstance(item, Mapping) and item.get("effect") == "DELEGATE" and item.get("resource_kind") == "PRINCIPAL" and item.get("operation") in {"SPAWN", "BIND"} and canonical_digest(item) == (delegation or {}).get("parent_delegation_clause_digest")), None)
        delegation_selector = _mapping((delegation_clause or {}).get("selector")) or {}
        delegation_ok = bool(
            delegation and parent and parent.get("state") == "ISSUED"
            and delegation.get("parent_capability_id") == parent.get("capability_id")
            and delegation.get("parent_state") == "ISSUED"
            and delegation.get("target_principal") == capability.get("audience")
            and delegation.get("child_principal") == capability.get("principal")
            and delegation.get("child_audience") == capability.get("audience")
            and delegation.get("parent_envelope_digest") == canonical_digest(parent_effect_rows)
            and delegation.get("parent_delegation_clause_digest") == canonical_digest(delegation_clause)
            and delegation_selector.get("kind") == "LOCAL_RESOURCE" and delegation_selector.get("resolution") == "EXACT_REGISTRY_ID"
            and delegation_selector.get("reference") == delegation.get("target_principal") == delegation_selector.get("canonical_value")
            and validate_authority_entry(delegation_clause)
            and "EXECUTE_EFFECT" in delegation_clause.get("facets", [])
            and all(delegation_clause.get("constraints") == item.get("constraints") for item in (child_effects or []) if isinstance(item, Mapping))
            and delegation.get("parent_effects_digest") == canonical_digest(parent_effect_rows)
            and delegation.get("parent_budget_digest") == canonical_digest(parent_budget_rows)
            and delegation.get("parent_budget_escrow_digest") == canonical_digest(delegation.get("budget_escrow"))
            and _delegation_escrow_valid(delegation.get("budget_escrow"), child_budgets)
            and isinstance(delegation.get("transfer_fence"), int) and delegation.get("transfer_fence") >= 1 and delegation.get("transfer_fence") == ledger.get("transfer_fence")
            and delegation.get("sibling_reservations_digest") == canonical_digest(sibling_rows)
            and _ledger_children_within_escrow(sibling_rows, capability.get("capability_id"), child_budgets, delegation.get("budget_escrow"))
            and delegation.get("depth", 0) <= delegation.get("max_depth", 0)
            and delegation.get("fanout", 0) <= delegation.get("max_fanout", 0)
            and delegation.get("cycle_guard") is True
            and isinstance(delegation.get("ancestry"), list)
            and len(delegation["ancestry"]) == len(set(delegation["ancestry"]))
            and delegation.get("parent_capability_digest") not in delegation.get("ancestry", [])
            and _effects_contained(child_effects, parent_effect_rows)
            and all(edge.get(key) == delegation.get(key) for key in ("parent_capability_id", "parent_capability_digest", "parent_envelope_digest", "parent_delegation_clause_digest", "root_lineage_digest", "edge_nonce", "child_principal", "child_audience", "fencing_epoch"))
            and delegation.get("fencing_epoch") == facts.get("current_fencing_epoch") == session.get("epoch")
            and delegation.get("cascade_revocation_digest") == (_mapping(facts.get("cascade_revocation_facts")) or {}).get(delegation.get("parent_capability_digest"))
            and delegation.get("parent_capability_digest") not in set(facts.get("revoked_capability_digests", []))
            and _valid_digest(child_effects_digest) and _valid_digest(child_budgets_digest)
        )
    external_record_ok = isinstance(trusted, Mapping) and all(trusted.get(key) == expected for key, expected in capability_verifier_record(capability).items())
    return bool(
        capability.get("state") == "ISSUED" and capability.get("consumption") is None
        and capability.get("issuer") == facts.get("expected_capability_issuer")
        and capability.get("principal") == candidate.get("principal") and capability.get("audience") == (delegation.get("target_principal") if descendant and delegation else candidate.get("audience")) and capability.get("purpose") == candidate.get("purpose")
        and approval_binding_ok and decision.get("approval_receipt_digest") == approval_digest
        and bindings == expected_bindings and execution == expected_execution and capability.get("effects") == decision.get("authorized_envelope") and capability.get("budgets") == decision.get("reservations") and capability.get("lineage") == expected_lineage
        and capability.get("nonce") == sha256((candidate["request_digest"] + decision["decision_digest"]).encode()).hexdigest()[:32]
        and all(capability.get(key) is True for key in ("single_use", "nonreplayable", "nontransferable", "short_lived"))
        and verification.get("signature_verified") is True and verification.get("signed_claims_digest") == signed_digest
        and external_record_ok
        and now is not None and not_before is not None and expires is not None and not_before <= now < expires
        and capability.get("revocation_epoch") == verification.get("revocation_epoch") == facts.get("current_revocation_epoch")
        and execution.get("session_epoch") == verification.get("fencing_epoch") == facts.get("current_fencing_epoch")
        and capability.get("capability_digest") not in set(facts.get("revoked_capability_digests", []))
        and delegation_ok
    )


def _effect_set(rows: Any) -> set[str] | None:
    return {canonical_digest(item) for item in rows} if isinstance(rows, list) and all(_typed_effect_row_valid(item) for item in rows) else None


def _effect_row_contained(child: Mapping[str, Any], parent: Mapping[str, Any]) -> bool:
    """Typed effect containment; operations are a set, never raw-string only."""
    if not _typed_effect_row_valid(child) or not _typed_effect_row_valid(parent) or child.get("effect") != parent.get("effect") or child.get("resource_kind") != parent.get("resource_kind"):
        return False
    child_scope, parent_scope = _mapping(child.get("scope")) or {}, _mapping(parent.get("scope")) or {}
    child_operations = child.get("operations", [child.get("operation")])
    parent_operations = parent.get("operations", [parent.get("operation")])
    if not set(child_operations) <= set(parent_operations) or not set(child.get("facets", [])) <= set(parent.get("facets", [])):
        return False
    if "constraints" in child or "constraints" in parent:
        child_constraints, parent_constraints = _mapping(child.get("constraints")) or {}, _mapping(parent.get("constraints")) or {}
        child_time, parent_time = _mapping(child_constraints.get("temporal")) or {}, _mapping(parent_constraints.get("temporal")) or {}
        child_quantity, parent_quantity = _mapping(child_constraints.get("quantity")) or {}, _mapping(parent_constraints.get("quantity")) or {}
        child_start, child_end = _parse_time(child_time.get("not_before")), _parse_time(child_time.get("not_after"))
        parent_start, parent_end = _parse_time(parent_time.get("not_before")), _parse_time(parent_time.get("not_after"))
        if not (
            child_constraints.get("direction") == parent_constraints.get("direction")
            and child_constraints.get("data_label") == parent_constraints.get("data_label")
            and child_start is not None and child_end is not None and parent_start is not None and parent_end is not None
            and parent_start <= child_start < child_end <= parent_end
            and child_time.get("max_duration_ms", -1) <= parent_time.get("max_duration_ms", -1)
            and child_quantity.get("unit") == parent_quantity.get("unit") and child_quantity.get("limit", -1) <= parent_quantity.get("limit", -1)
            and child_constraints.get("max_concurrency", 0) <= parent_constraints.get("max_concurrency", -1)
            and {canonical_digest(flow) for flow in child_constraints.get("flows", [])} <= {canonical_digest(flow) for flow in parent_constraints.get("flows", [])}
            and set(child_constraints.get("obligations", [])) <= set(parent_constraints.get("obligations", []))
        ):
            return False
    child_values, parent_values = child_scope.get("values"), parent_scope.get("values")
    if not isinstance(child_values, list) or not isinstance(parent_values, list):
        return child.get("selector") == parent.get("selector")
    if child_scope.get("kind") != parent_scope.get("kind"):
        return False
    if child_scope.get("kind") == "PATH":
        return all(any(value == bound or (isinstance(value, str) and isinstance(bound, str) and value.startswith(bound.rstrip("/") + "/")) for bound in parent_values) for value in child_values)
    return set(child_values) <= set(parent_values)


def _effects_contained(child_rows: Any, parent_rows: Any) -> bool:
    return isinstance(child_rows, list) and isinstance(parent_rows, list) and all(
        isinstance(child, Mapping) and any(isinstance(parent, Mapping) and _effect_row_contained(child, parent) for parent in parent_rows)
        for child in child_rows
    )


def _effect_receipt_payload_digest(receipt: Mapping[str, Any]) -> str:
    payload = deepcopy(dict(receipt)); payload.pop("authoritative_verifier", None)
    return canonical_digest(payload)


def _object_identity_valid(identity: Any, *, object_id: Any, object_digest: Any) -> bool:
    identity = _mapping(identity)
    required = {"descriptor_id", "root_id", "mount_id", "resolution_epoch", "final_object_id", "final_object_digest"}
    return bool(identity and set(identity) == required and all(identity.get(key) for key in required if key != "resolution_epoch") and isinstance(identity.get("resolution_epoch"), int) and identity["resolution_epoch"] >= 0 and identity.get("final_object_id") == object_id and identity.get("final_object_digest") == object_digest and _valid_digest(identity.get("final_object_digest")))


def _target_identity_valid(identity: Any, *, object_id: Any, object_digest: Any) -> bool:
    binding = _mapping(identity)
    return _object_identity_valid(identity, object_id=object_id, object_digest=object_digest) or bool(
        binding and _endpoint_binding_valid(binding)
        and binding.get("endpoint_id") == object_id
        and binding.get("endpoint_binding_digest") == object_digest
    )


def _chain_topology_valid(chain: Any, heads: Any) -> bool:
    chain = _mapping(chain)
    if chain is None:
        return False
    source_id = chain.get("source_id")
    head = _mapping((_mapping(heads) or {}).get(source_id))
    previous_key = "previous_receipt_digest" if "previous_receipt_digest" in chain else "previous_event_digest"
    if not isinstance(source_id, str) or head is None or not isinstance(chain.get("epoch"), int) or not isinstance(chain.get("sequence"), int) or chain["sequence"] < 0 or not isinstance(chain.get("genesis"), bool):
        return False
    return bool(
        chain.get("epoch") == head.get("epoch")
        and chain.get("sequence") == head.get("next_sequence")
        and chain.get("predecessor_digest") == head.get("predecessor_digest")
        and chain.get(previous_key) == chain.get("predecessor_digest")
        and chain.get("genesis") is (chain.get("predecessor_digest") is None)
        and ((chain["genesis"] and chain.get("predecessor_digest") is None) or (not chain["genesis"] and _valid_digest(chain.get("predecessor_digest"))))
    )


def _stage_evidence_valid(record: Any, evidence_type: str, *, transaction_id: Any, capability_digest: Any, session_id: Any, object_identity: Any, fencing_epoch: Any, trusted_record: Any = None) -> bool:
    record = _mapping(record)
    unsigned = {key: value for key, value in (record or {}).items() if key != "record_digest"}
    if record is None or record.get("record_type") != evidence_type or record.get("transaction_id") != transaction_id or record.get("capability_digest") != capability_digest or record.get("session_id") != session_id or record.get("object_identity") != object_identity or record.get("epoch") != fencing_epoch or not record.get("observer_id") or not _valid_digest(record.get("record_digest")) or record.get("signature_verified") is not True or record.get("record_digest") != canonical_digest(unsigned):
        return False
    trusted = _mapping(trusted_record)
    return trusted is None or trusted.get("evidence_type") == record.get("record_type") and all(trusted.get(key) == record.get(key) for key in ("transaction_id", "capability_digest", "session_id", "object_identity")) and trusted.get("fencing_epoch") == record.get("epoch") and trusted.get("observer") == record.get("observer_id") and trusted.get("evidence_digest") == record.get("record_digest") and trusted.get("signature_verified") is True and trusted.get("not_revoked") is True and trusted.get("verified_by")


def _trusted_stage_evidence_valid(store: Mapping[str, Any], reference: Any, evidence_type: str, *, transaction_id: Any, capability_digest: Any, session_id: Any, object_identity: Any, fencing_epoch: Any) -> Mapping[str, Any] | None:
    record = _mapping((_mapping(store.get("stage_evidence")) or {}).get(reference))
    if record is None or record.get("evidence_type") != evidence_type or not _valid_digest(record.get("evidence_digest")) or any(record.get(key) != value for key, value in {"transaction_id": transaction_id, "capability_digest": capability_digest, "session_id": session_id, "object_identity": object_identity, "fencing_epoch": fencing_epoch}.items()) or not record.get("observer") or record.get("signature_verified") is not True or record.get("not_revoked") is not True or not record.get("verified_by"):
        return None
    return record


def _trusted_host_recovery_valid(store: Mapping[str, Any], reference: Any, fencing_epoch: Any) -> bool:
    record = _mapping((_mapping(store.get("verified_host_recoveries")) or {}).get(reference))
    unsigned = {key: value for key, value in (record or {}).items() if key != "record_digest"}
    return bool(record and record.get("fencing_epoch") == fencing_epoch and _valid_digest(record.get("orphan_inventory_digest")) and _valid_digest(record.get("recovered_ids_digest")) and record.get("cleanup_verified") is True and _valid_digest(record.get("absence_proof_digest")) and record.get("stale_writers_absent") is True and record.get("residue_absent") is True and record.get("signature_verified") is True and record.get("not_revoked") is True and record.get("verified_by") and record.get("record_digest") == canonical_digest(unsigned))


def _capability_scoped_effect(effect: Mapping[str, Any]) -> dict[str, Any] | None:
    selector = _mapping(effect.get("selector")) or {}
    scope_kind = {"FILE": "PATH", "DIRECTORY": "PATH", "ENDPOINT": "ENDPOINT", "PRINCIPAL": "PRINCIPAL", "MEMORY": "MEMORY", "PROMPT": "PROMPT", "POLICY": "POLICY", "PROCESS": "PROCESS", "REGISTRY": "LOCAL_RESOURCE", "COMPUTE_RESOURCE": "LOCAL_RESOURCE"}.get(effect.get("resource_kind"))
    value = selector.get("canonical_value", selector.get("canonical_path", selector.get("canonical_endpoint", selector.get("resource_id"))))
    if scope_kind is None or not isinstance(value, str) or not value:
        return None
    return {"effect": effect.get("effect"), "resource_kind": effect.get("resource_kind"), "operations": [effect.get("operation")], "scope": {"kind": scope_kind, "values": [value]}}


def _trusted_compensation_authorization(state: Mapping[str, Any], disposition: Mapping[str, Any]) -> Mapping[str, Any] | None:
    authorization = _mapping(disposition.get("compensation_authorization"))
    if authorization is None or set(authorization) != {"transaction_id", "decision_digest", "capability_digest", "authorized_envelope_digest", "state"}:
        return None
    authorization_digest = canonical_digest(authorization)
    store = _mapping(state.get("trusted_store")) or {}
    record = _mapping((_mapping(store.get("compensation_authorizations")) or {}).get(authorization_digest))
    verifier = _mapping((_mapping(store.get("compensation_authorization_verifiers")) or {}).get((record or {}).get("verified_by")))
    now, admitted, expires = _parse_time(store.get("trusted_time")), _parse_time((record or {}).get("admitted_at")), _parse_time((record or {}).get("expires_at"))
    unsigned = {key: deepcopy(value) for key, value in (record or {}).items() if key != "record_digest"}
    return record if (
        authorization.get("state") == "ADMITTED"
        and authorization.get("transaction_id") != state.get("transaction_id")
        and all(_valid_digest(authorization.get(key)) for key in ("decision_digest", "capability_digest", "authorized_envelope_digest"))
        and authorization.get("decision_digest") != state.get("admitted_decision_digest")
        and authorization.get("capability_digest") != state.get("capability_digest")
        and authorization.get("authorized_envelope_digest") != state.get("admitted_envelope_digest")
        and record is not None and verifier is not None
        and all(record.get(key) == authorization.get(key) for key in authorization)
        and record.get("authorization_digest") == authorization_digest
        and record.get("source_transaction_id") == state.get("transaction_id")
        and record.get("failure_disposition_digest") == canonical_digest(disposition)
        and record.get("signature_verified") is True and record.get("not_revoked") is True
        and record.get("verified_by") and record.get("verifier_key_id") and record.get("verifier_trust_root")
        and record.get("verifier_algorithm") in {"ED25519", "ECDSA_P256_SHA256"}
        and isinstance(record.get("verifier_signature"), str) and bool(record.get("verifier_signature"))
        and all(verifier.get(key) == record.get(key) for key in ("verified_by", "verifier_key_id", "verifier_trust_root", "verifier_algorithm"))
        and verifier.get("signature_verified") is True and verifier.get("not_revoked") is True and verifier.get("current_key") is True
        and record.get("record_digest") == canonical_digest(unsigned)
        and now is not None and admitted is not None and expires is not None and admitted <= now < expires
    ) else None


def _failure_disposition_valid(state: Mapping[str, Any], disposition: Any) -> bool:
    disposition = _mapping(disposition)
    if disposition is None or set(disposition) != {"effect_dispositions", "budget_dispositions", "automatic_retry_allowed", "next_state", "compensation_authorization"} or disposition.get("automatic_retry_allowed") is not False or disposition.get("next_state") != "COMPENSATION_PENDING":
        return False
    effect_rows, budget_rows = disposition.get("effect_dispositions"), disposition.get("budget_dispositions")
    capability = _mapping(state.get("issued_capability")) or {}
    expected_effects = [_capability_scoped_effect(item) for item in capability.get("effects", []) if isinstance(item, Mapping)]
    if not isinstance(effect_rows, list) or not effect_rows or any(item is None for item in expected_effects):
        return False
    if any(not isinstance(row, Mapping) or set(row) != {"component_id", "effect", "disposition"} or row.get("disposition") not in {"NO_EFFECT", "PARTIAL_EFFECT", "RESIDUAL_EFFECT"} for row in effect_rows):
        return False
    if len({row.get("component_id") for row in effect_rows}) != len(effect_rows) or not any(row.get("disposition") in {"PARTIAL_EFFECT", "RESIDUAL_EFFECT"} for row in effect_rows):
        return False
    if sorted(canonical_digest(row.get("effect")) for row in effect_rows) != sorted(canonical_digest(item) for item in expected_effects):
        return False
    if not isinstance(budget_rows, list) or not budget_rows:
        return False
    expected_budget = {key: amount for key, amount in (_mapping(state.get("budget_reserved_by_key")) or {}).items() if amount > 0}
    observed_budget: dict[tuple[str, str, str, str], int] = {}
    for row in budget_rows:
        if not isinstance(row, Mapping) or set(row) != {"name", "unit", "scope_digest", "lineage_root", "amount", "disposition"} or row.get("disposition") not in {"SPENT", "QUARANTINED_ESCROW"}:
            return False
        mapped = _budget_map([{key: row.get(key) for key in ("name", "unit", "scope_digest", "lineage_root", "amount")}], "amount")
        if not mapped or next(iter(mapped.values())) <= 0:
            return False
        key, amount = next(iter(mapped.items()))
        if key in observed_budget:
            return False
        observed_budget[key] = amount
    return observed_budget == expected_budget and _trusted_compensation_authorization(state, disposition) is not None


def _trusted_reconciliation_evidence(state: Mapping[str, Any], event: Mapping[str, Any], outcome: str) -> Mapping[str, Any] | None:
    store = _mapping(state.get("trusted_store")) or {}
    record = _mapping((_mapping(store.get("reconciliation")) or {}).get(event.get("reconciliation_evidence_ref")))
    verifier = _mapping((_mapping(store.get("reconciliation_verifiers")) or {}).get((record or {}).get("verified_by")))
    if record is None:
        return None
    unsigned = {key: deepcopy(value) for key, value in record.items() if key != "evidence_digest"}
    now, verified, expires = _parse_time(store.get("trusted_time")), _parse_time(record.get("verified_at")), _parse_time(record.get("expires_at"))
    expected = {
        "evidence_type": "EXTERNAL_RECONCILIATION", "outcome": outcome,
        "transaction_id": state.get("transaction_id"), "decision_digest": state.get("admitted_decision_digest"),
        "capability_digest": state.get("capability_digest"), "envelope_digest": state.get("admitted_envelope_digest"),
        "contract_digest": state.get("contract_digest"), "lineage_digest": state.get("capability_lineage_digest"),
        "dispatch_intent_digest": state.get("dispatch_intent_digest"), "idempotency_key_digest": state.get("idempotency_key_digest"),
        "object_identity": state.get("object_identity"), "fencing_epoch": state.get("fencing_epoch"),
        "connector_id": state.get("connector_id"), "chain_digest": state.get("source_chain_digest"),
    }
    failure_disposition = record.get("failure_disposition")
    failure_binding_valid = _failure_disposition_valid(state, failure_disposition) if outcome == "FAILURE_WITH_RESIDUAL_EFFECT" else failure_disposition is None
    return record if (
        all(record.get(key) == value for key, value in expected.items())
        and failure_binding_valid
        and _valid_digest(record.get("connector_evidence_digest"))
        and record.get("signature_verified") is True and record.get("not_revoked") is True and record.get("verified_by")
        and record.get("verifier_key_id") and record.get("verifier_trust_root") and record.get("verifier_algorithm") in {"ED25519", "ECDSA_P256_SHA256"} and isinstance(record.get("verifier_signature"), str) and bool(record.get("verifier_signature"))
        and verifier is not None
        and all(verifier.get(key) == record.get(key) for key in ("verified_by", "verifier_key_id", "verifier_trust_root", "verifier_algorithm"))
        and verifier.get("signature_verified") is True and verifier.get("not_revoked") is True and verifier.get("current_key") is True
        and _valid_digest(record.get("evidence_digest")) and record.get("evidence_digest") == canonical_digest(unsigned)
        and record.get("evidence_digest") not in set(state.get("consumed_reconciliation_evidence_digests", []))
        and now is not None and verified is not None and expires is not None and verified <= now < expires
    ) else None


def validate_effect_receipt(receipt: Any, trusted_facts: Mapping[str, Any] | None = None) -> bool:
    if not isinstance(receipt, Mapping):
        return False
    def stage(name: str) -> list[Mapping[str, Any]] | None:
        value = _mapping(receipt.get(name))
        if value is None or set(value) - {"status", "entries", "reason"} or set(value) - {"status", "entries"} - ({"reason"} if value.get("status") in {"UNKNOWN", "ABSENT"} else set()) or value.get("status") not in {"KNOWN", "UNKNOWN", "ABSENT", "NOT_APPLICABLE"} or not isinstance(value.get("entries"), list):
            return None
        if value["status"] == "KNOWN" and not value["entries"]:
            return None
        if value["status"] in {"UNKNOWN", "ABSENT"} and (not isinstance(value.get("reason"), str) or not value["reason"] or value["entries"]):
            return None
        return value["entries"]
    staged = {name: stage(name) for name in ("authorized", "attempted", "blocked", "actual", "committed", "observed", "verified")}
    if any(value is None for value in staged.values()):
        return False
    authorized, committed = _effect_set(staged["authorized"]), _effect_set(staged["committed"])
    if authorized is None or committed is None or not committed <= authorized:
        return False
    privacy = _mapping(receipt.get("privacy")) or {}
    if any(not privacy.get(key) for key in ("arg_digest", "output_digest", "integrity", "provenance", "purpose", "retention", "access_policy")) or not isinstance(privacy.get("taints"), list):
        return False
    verifier = _mapping(receipt.get("authoritative_verifier")) or {}
    trusted_receipts = _mapping((trusted_facts or {}).get("verified_effect_receipts")) or {}
    trusted = _mapping(trusted_receipts.get(canonical_digest(receipt))) or {}
    trusted_verifier = _mapping(trusted.get("authoritative_verifier")) or {}
    bindings = _mapping(receipt.get("bindings")) or {}
    identity = receipt.get("object_identity")
    dispatch = _mapping(receipt.get("dispatch")) or {}
    if not _target_identity_valid(identity, object_id=receipt.get("object_id"), object_digest=receipt.get("object_digest")) or dispatch.get("object_identity") != identity or not _chain_topology_valid(receipt.get("chain"), (trusted_facts or {}).get("receipt_chain_heads")):
        return False
    stage_args = {"transaction_id": receipt.get("transaction_id"), "capability_digest": bindings.get("capability_digest"), "session_id": bindings.get("session_id"), "object_identity": identity, "fencing_epoch": dispatch.get("fencing_epoch")}
    trusted_stages = [record for record in (_mapping((trusted_facts or {}).get("stage_evidence")) or {}).values() if isinstance(record, Mapping)]
    if not all(any(_stage_evidence_valid(receipt.get(field), evidence_type, **stage_args, trusted_record=trusted) for trusted in trusted_stages) for field, evidence_type in (("quiesce_evidence", "QUIESCE"), ("seal_evidence", "SEAL"), ("postcheck_evidence", "POSTCHECK"))):
        return False
    if bindings.get("approval_mode") not in {"NOT_REQUIRED", "REQUIRED"} or (bindings.get("approval_mode") == "REQUIRED" and not _valid_digest(bindings.get("approval_receipt_digest"))) or (bindings.get("approval_mode") == "NOT_REQUIRED" and bindings.get("approval_receipt_digest") is not None):
        return False
    if isinstance(trusted_facts, Mapping) and (trusted_facts.get("approval_mode") is not None or trusted_facts.get("approval_receipt_digest") is not None) and (bindings.get("approval_mode") != trusted_facts.get("approval_mode") or bindings.get("approval_receipt_digest") != trusted_facts.get("approval_receipt_digest")):
        return False
    if not trusted or trusted.get("receipt_digest") != canonical_digest(receipt) or trusted.get("payload_digest") != _effect_receipt_payload_digest(receipt) or trusted.get("object_id") != receipt.get("object_id") or trusted.get("object_digest") != receipt.get("object_digest") or trusted.get("object_identity") != identity or trusted.get("session_id") != bindings.get("session_id") or trusted.get("decision_digest") != bindings.get("decision_digest") or trusted.get("capability_digest") != bindings.get("capability_digest") or trusted.get("dispatch_intent_digest") != dispatch.get("intent_digest") or trusted_verifier != verifier or verifier.get("payload_digest") != trusted.get("payload_digest"):
        return False
    if receipt.get("outcome") == "KNOWN_SUCCESS" and (not staged["actual"] or not staged["observed"] or not staged["verified"] or verifier.get("signature_verified") is not True or verifier.get("freshness_verified") is not True or verifier.get("revocation_checked") is not True or verifier.get("subject") != receipt.get("principal") or verifier.get("session_id") != receipt.get("bindings", {}).get("session_id")):
        return False
    if receipt.get("outcome") == "KNOWN_FAILURE" and (not staged["actual"] or _mapping(receipt.get("actual")).get("status") != "KNOWN"):
        return False
    if committed:
        seal, postcheck, attestation, chain = _mapping(receipt.get("seal")) or {}, _mapping(receipt.get("postcheck")) or {}, _mapping(receipt.get("executor_attestation")) or {}, _mapping(receipt.get("chain")) or {}
        if not (seal.get("required") is True and seal.get("writers_quiesced") is True and _valid_digest(seal.get("snapshot_digest")) and postcheck.get("state") == "PASSED" and _valid_digest(postcheck.get("plan_digest")) and _valid_digest(postcheck.get("attestation_digest")) and attestation.get("verified_by") and _valid_digest(attestation.get("payload_digest")) and chain.get("anti_rollback_proven") is True and _valid_digest(chain.get("witness_digest")) and _stage_evidence_valid(receipt.get("quiesce_evidence"), "QUIESCE", **stage_args) and _stage_evidence_valid(receipt.get("seal_evidence"), "SEAL", **stage_args) and _stage_evidence_valid(receipt.get("postcheck_evidence"), "POSTCHECK", **stage_args)):
            return False
    if receipt.get("outcome") == "UNKNOWN_OUTCOME":
        postcheck = _mapping(receipt.get("postcheck")) or {}
        reconciliation = _mapping(receipt.get("reconciliation")) or {}
        if postcheck.get("state") != "RECONCILING" or postcheck.get("automatic_retry_allowed") is not False or not reconciliation.get("reconciliation_id") or reconciliation.get("automatic_retry_allowed") is not False or not reconciliation.get("evidence_digests") or any(_mapping(receipt.get(name)).get("status") == "KNOWN" for name in ("actual", "committed", "verified")):
            return False
    return True


def validate_safety_event(event: Any, trusted_facts: Mapping[str, Any] | None = None) -> bool:
    if not isinstance(event, Mapping):
        return False
    stages, emitter, chain = _mapping(event.get("effect_stages")) or {}, _mapping(event.get("emitter")) or {}, _mapping(event.get("chain")) or {}
    bindings = _mapping(event.get("bindings")) or {}
    identity = event.get("object_identity")
    if not _target_identity_valid(identity, object_id=event.get("object_id"), object_digest=event.get("object_digest")) or not _chain_topology_valid(event.get("chain"), (trusted_facts or {}).get("event_chain_heads")):
        return False
    trusted_emitters = _mapping((trusted_facts or {}).get("verified_event_emitters")) or {}
    emitter_trust = _mapping(trusted_emitters.get(emitter.get("authority_attestation_digest")))
    if emitter_trust is None or emitter_trust.get("principal") != emitter.get("principal") or emitter_trust.get("component") != emitter.get("component") or emitter_trust.get("authority_attestation_digest") != emitter.get("authority_attestation_digest") or emitter_trust.get("signature_verified") is not True or emitter_trust.get("freshness_verified") is not True or emitter_trust.get("revocation_checked") is not True or not isinstance(emitter_trust.get("key_id"), str):
        return False
    if bindings.get("approval_mode") not in {"NOT_REQUIRED", "REQUIRED"} or (bindings.get("approval_mode") == "REQUIRED" and not _valid_digest(bindings.get("approval_receipt_digest"))) or (bindings.get("approval_mode") == "NOT_REQUIRED" and bindings.get("approval_receipt_digest") is not None):
        return False
    if isinstance(trusted_facts, Mapping) and (trusted_facts.get("approval_mode") is not None or trusted_facts.get("approval_receipt_digest") is not None) and (bindings.get("approval_mode") != trusted_facts.get("approval_mode") or bindings.get("approval_receipt_digest") != trusted_facts.get("approval_receipt_digest")):
        return False
    def stage_entries(name: str) -> list[Mapping[str, Any]] | None:
        stage = _mapping(stages.get(name))
        if stage is None or stage.get("status") not in {"KNOWN", "UNKNOWN", "NOT_APPLICABLE", "ABSENT"} or not isinstance(stage.get("entries"), list):
            return None
        if stage.get("status") == "KNOWN" and not stage["entries"]:
            return None
        if stage.get("status") in {"UNKNOWN", "ABSENT"} and (not stage.get("reason") or stage["entries"]):
            return None
        return stage["entries"]
    authorized_entries, committed_entries = stage_entries("authorized"), stage_entries("committed")
    if authorized_entries is None or committed_entries is None:
        return False
    manifested_stage = _mapping(stages.get("manifested"))
    if manifested_stage is None or manifested_stage.get("status") != "KNOWN" or not _effects_contained(authorized_entries, manifested_stage.get("entries")):
        return False
    # ``derived`` is the physical ceiling projection in the event model when
    # present.  Older fixtures mark it NOT_APPLICABLE; in that case the
    # trusted physical projection may be supplied by the observer facts.
    physical_entries = None
    derived_stage = _mapping(stages.get("derived"))
    if derived_stage is not None and derived_stage.get("status") == "KNOWN":
        physical_entries = derived_stage.get("entries")
    else:
        physical_entries = (trusted_facts or {}).get("physical_effects") if isinstance(trusted_facts, Mapping) else None
    if physical_entries is None or not _effects_contained(authorized_entries, physical_entries):
        return False
    attempted_stage = _mapping(stages.get("attempted"))
    blocked_stage = _mapping(stages.get("blocked"))
    if attempted_stage is not None and attempted_stage.get("status") == "KNOWN":
        excess = [row for row in attempted_stage.get("entries", []) if isinstance(row, Mapping) and not any(_effect_row_contained(row, authorized) for authorized in authorized_entries if isinstance(authorized, Mapping))]
        if excess and (blocked_stage is None or blocked_stage.get("status") != "KNOWN" or not _effects_contained(excess, blocked_stage.get("entries"))):
            return False
    event_preimage = deepcopy(dict(event))
    event_chain = _mapping(event_preimage.get("chain")) or {}
    event_chain.pop("event_digest", None)
    event_preimage["chain"] = event_chain
    if chain.get("event_digest") != canonical_digest(event_preimage) or emitter_trust.get("event_digest") != chain.get("event_digest"):
        return False
    # If the observer supplies a durable stage-binding projection, every
    # binding represented in the event must agree with it.  Local digest
    # recomputation cannot replace this external authority.
    trusted_stage_record = None
    for field in ("verified_event_bindings", "trusted_stage_bindings", "verified_event_stages"):
        rows = _mapping((trusted_facts or {}).get(field)) if isinstance(trusted_facts, Mapping) else None
        if rows:
            trusted_stage_record = _mapping(rows.get(chain.get("event_digest")) or rows.get(event.get("event_id")))
            if trusted_stage_record is not None:
                break
    if trusted_stage_record is None:
        return False
    for key in ("manifest_digest", "policy_digest", "contract_digest", "iteration_slot_digest", "request_digest", "decision_digest", "authorized_envelope_digest", "capability_digest", "registry_digest", "placement_attestation_digest", "session_attestation_digest", "supply_chain_measurement_digest"):
        if trusted_stage_record.get(key) != bindings.get(key):
            return False
    if (
        trusted_stage_record.get("event_digest") != chain.get("event_digest")
        or trusted_stage_record.get("manifested_effects_digest") != canonical_digest(manifested_stage.get("entries"))
        or trusted_stage_record.get("physical_effects_digest") != canonical_digest(physical_entries)
        or trusted_stage_record.get("authorized_effects_digest") != canonical_digest(authorized_entries)
        or trusted_stage_record.get("committed_effects_digest") != canonical_digest(committed_entries)
        or trusted_stage_record.get("object_identity") != identity
    ):
        return False
    if event.get("event_type") == "UNKNOWN_OUTCOME":
        reconciliation = _mapping(event.get("reconciliation")) or {}
        if event.get("outcome") != "UNKNOWN" or not reconciliation.get("reconciliation_id") or reconciliation.get("state") not in {"RECONCILING", "QUARANTINED"} or not reconciliation.get("evidence_digests") or reconciliation.get("automatic_retry_allowed") is not False:
            return False
        if any(_mapping(stages.get(name)).get("status") == "KNOWN" for name in ("actual", "committed", "verified")):
            return False
    authorized, committed = _effect_set(authorized_entries), _effect_set(committed_entries)
    if authorized is None or committed is None or not _effects_contained(committed_entries, authorized_entries) or not committed <= authorized or emitter.get("trusted_identity_verified") is not True or not _valid_digest(emitter.get("authority_attestation_digest")):
        return False
    expected_envelope = event.get("bindings", {}).get("authorized_envelope_digest")
    for stage_name, stage in stages.items():
        rows = stage.get("entries", []) if isinstance(stage, Mapping) else []
        for row in rows:
            # Blocked/attempted probes may be recorded before an effect object
            # exists; their typed scope is still checked above.  Committed and
            # authorized stages always require the trusted object chain.
            if stage_name in {"attempted", "blocked"} and isinstance(row, Mapping) and not any(key in row for key in ("object_id", "object_digest", "envelope_digest")):
                continue
            if row.get("object_id") != event.get("object_id") or row.get("object_digest") != event.get("object_digest") or row.get("object_identity") != identity or row.get("envelope_digest") != expected_envelope:
                return False
    if event.get("event_type") in {"COMMIT", "JOIN"} and any(_mapping(stages.get(name)).get("status") != "KNOWN" for name in ("authorized", "attempted", "actual", "committed", "observed", "verified")):
        return False
    if event.get("event_type") in {"COMMIT", "JOIN"} and (event.get("transaction_id") is None or event.get("chain", {}).get("previous_event_digest") is None and event.get("event_type") == "JOIN"):
        return False
    if event.get("outcome") in {"COMMITTED", "VERIFIED"} or event.get("event_type") == "JOIN":
        if not event.get("evidence_digests") or chain.get("anti_rollback_proven") is not True or not _valid_digest(chain.get("witness_digest")):
            return False
    return event.get("event_type") != "JOIN" or event.get("outcome") == "VERIFIED"


_BUDGET_MAP_FIELDS = ("budget_total_by_key", "budget_remaining_by_key", "budget_reserved_by_key", "budget_spent_by_key")


def _budget_rows(values: Mapping[tuple[str, str, str, str], int]) -> list[dict[str, Any]]:
    return [
        {"name": key[0], "unit": key[1], "scope_digest": key[2], "lineage_root": key[3], "amount": values[key]}
        for key in sorted(values)
    ]


def _sync_budget_scalars(state: dict[str, Any]) -> None:
    state["budget_total"] = sum((_mapping(state.get("budget_total_by_key")) or {}).values())
    state["budget_remaining"] = sum((_mapping(state.get("budget_remaining_by_key")) or {}).values())
    state["budget_reserved"] = sum((_mapping(state.get("budget_reserved_by_key")) or {}).values())
    state["budget_spent"] = sum((_mapping(state.get("budget_spent_by_key")) or {}).values())
    state["unknown_escrow"] = sum((_mapping(state.get("unknown_escrow_by_key")) or {}).values())


def _move_reserved(state: dict[str, Any], destination: str) -> dict[tuple[str, str, str, str], int]:
    reserved = dict(_mapping(state.get("budget_reserved_by_key")) or {})
    target = state[f"budget_{destination}_by_key"]
    for key, amount in reserved.items():
        target[key] += amount
        state["budget_reserved_by_key"][key] = 0
        state["unknown_escrow_by_key"][key] = 0
    _sync_budget_scalars(state)
    return reserved


def _quarantine_reserved(state: dict[str, Any]) -> dict[tuple[str, str, str, str], int]:
    state["unknown_escrow_by_key"] = deepcopy(state["budget_reserved_by_key"])
    _sync_budget_scalars(state)
    return deepcopy(state["unknown_escrow_by_key"])


def _apply_residual_budget_disposition(state: dict[str, Any], rows: list[Mapping[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    spent: dict[tuple[str, str, str, str], int] = {}
    escrow: dict[tuple[str, str, str, str], int] = {key: 0 for key in state["budget_reserved_by_key"]}
    for row in rows:
        key = (row["name"], row["unit"], row["scope_digest"], row["lineage_root"])
        amount = row["amount"]
        if row["disposition"] == "SPENT":
            state["budget_reserved_by_key"][key] -= amount
            state["budget_spent_by_key"][key] += amount
            spent[key] = spent.get(key, 0) + amount
        else:
            escrow[key] += amount
    state["unknown_escrow_by_key"] = escrow
    _sync_budget_scalars(state)
    return {"spent": _budget_rows(spent), "quarantined_escrow": _budget_rows(escrow)}


def _budget_snapshot(state: Mapping[str, Any]) -> dict[str, list[dict[str, Any]]]:
    return {
        name.removeprefix("budget_").removesuffix("_by_key"): _budget_rows(dict(_mapping(state.get(name)) or {}))
        for name in _BUDGET_MAP_FIELDS
    }


def _conserved(state: Mapping[str, Any]) -> bool:
    maps = [_mapping(state.get(name)) for name in _BUDGET_MAP_FIELDS]
    unknown = _mapping(state.get("unknown_escrow_by_key"))
    if any(item is None for item in maps) or unknown is None:
        return False
    total, remaining, reserved, spent = (dict(item) for item in maps if item is not None)
    keys = set(total)
    if any(set(item) != keys for item in (remaining, reserved, spent, dict(unknown))):
        return False
    if any(not isinstance(key, tuple) or len(key) != 4 or not all(isinstance(part, str) and part for part in key) for key in keys):
        return False
    if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for item in (total, remaining, reserved, spent, dict(unknown)) for value in item.values()):
        return False
    if any(remaining[key] + reserved[key] + spent[key] != total[key] or unknown[key] > reserved[key] for key in keys):
        return False
    scalar_checks = {
        "budget_total": sum(total.values()), "budget_remaining": sum(remaining.values()),
        "budget_reserved": sum(reserved.values()), "budget_spent": sum(spent.values()),
        "unknown_escrow": sum(unknown.values()),
    }
    return all(state.get(name) == value for name, value in scalar_checks.items())


def _reject(state: Mapping[str, Any] | None, reason: str) -> dict[str, Any]:
    base = deepcopy(dict(state)) if state is not None else {}
    durable_record = None
    # A reservation exists before capability issuance.  An invalid issuance
    # must close it in the same model transition; otherwise STOPPED leaves
    # budget_reserved stranded and the next proposal cannot conserve budget.
    if base.get("phase") == "BUDGET_RESERVED" and base.get("budget_reserved", 0) > 0:
        released_map = _move_reserved(base, "remaining")
        released = sum(released_map.values())
        base["phase"] = "STOPPED"
        durable_record = {"reservation_disposition": "RELEASED", "reservation_release": released, "reservation_release_by_key": _budget_rows(released_map), "reservation_release_vector": deepcopy(base.get("reservation_vector", [])), "reservation_release_vector_digest": base.get("reservation_vector_digest"), "atomic_serializable_transition": True}
    elif base.get("phase") in {"CAPABILITY_ISSUED", "PRECHECKED"} and base.get("budget_reserved", 0) > 0:
        escrow_map = _quarantine_reserved(base)
        base["quarantined"] = True
        base["phase"] = "QUARANTINED"
        durable_record = {"reservation_disposition": "QUARANTINED_ESCROW", "reservation_escrow": sum(escrow_map.values()), "reservation_escrow_by_key": _budget_rows(escrow_map), "reservation_vector": deepcopy(base.get("reservation_vector", [])), "reservation_vector_digest": base.get("reservation_vector_digest"), "atomic_serializable_transition": True}
    else:
        base["phase"] = base.get("phase") if base.get("phase") in {"COMMITTED", "COMMITTED_RECOVERY_PENDING", "COMPENSATION_PENDING"} else ("QUARANTINED" if base.get("capability_status") == "CONSUMED" and base.get("phase") not in {"JOINED", "STOPPED"} else "STOPPED")
    base["controller_outcome"] = "STOPPED"
    base["automatic_retry_allowed"] = False
    return {"accepted": False, "reason_code": reason, "state": base, "durable_record": durable_record, "specification_model_only": True}


TRANSITIONS = {
    ("ANY", "STOPPED", "PROPOSE"): "PROPOSED",
    ("ANY", "PROPOSED", "NORMALIZE"): "NORMALIZED",
    ("ANY", "NORMALIZED", "CLASSIFY"): "CLASSIFIED",
    ("ANY", "CLASSIFIED", "ADMIT"): "ADMITTED",
    ("ANY", "ADMITTED", "CALCULATE_RESERVATION"): "BUDGET_RESERVED",
    ("ANY", "BUDGET_RESERVED", "ISSUE_CAPABILITY"): "CAPABILITY_ISSUED",
    ("EXTERNAL", "CAPABILITY_ISSUED", "PRECHECK_EXTERNAL"): "PRECHECKED",
    ("STAGEABLE", "CAPABILITY_ISSUED", "DURABLE_DISPATCH"): "EXECUTING",
    ("COMPENSATION", "CAPABILITY_ISSUED", "DURABLE_DISPATCH"): "EXECUTING",
    ("EXTERNAL", "PRECHECKED", "DURABLE_DISPATCH"): "EXECUTING",
    ("STAGEABLE", "EXECUTING", "QUIESCE"): "QUIESCED",
    ("STAGEABLE", "QUIESCED", "SEAL"): "SEALED",
    ("STAGEABLE", "SEALED", "POSTCHECK_PASS"): "POSTCHECKED",
    ("STAGEABLE", "SEALED", "POSTCHECK_FAIL"): "DISCARDED",
    ("STAGEABLE", "POSTCHECKED", "COMMIT"): "COMMITTED",
    ("EXTERNAL", "EXECUTING", "OUTCOME_SUCCESS"): "KNOWN_SUCCESS",
    ("EXTERNAL", "EXECUTING", "OUTCOME_FAILURE"): "KNOWN_FAILURE",
    ("EXTERNAL", "EXECUTING", "OUTCOME_UNKNOWN"): "QUARANTINED",
    ("EXTERNAL", "KNOWN_SUCCESS", "RECONCILE_SUCCESS"): "RECONCILED",
    ("EXTERNAL", "KNOWN_FAILURE", "RECORD_FAILURE"): "FAILURE_RECORDED",
    ("EXTERNAL", "QUARANTINED", "RECONCILE_SUCCESS"): "RECONCILED",
    ("EXTERNAL", "QUARANTINED", "RECONCILE_FAILURE"): "FAILURE_RECORDED",
    ("COMPENSATION", "EXECUTING", "COMPENSATION_VERIFIED"): "COMPENSATED_VERIFIED",
    ("COMPENSATION", "EXECUTING", "COMPENSATION_RESIDUAL"): "RESIDUAL_EFFECT",
    ("COMPENSATION", "EXECUTING", "COMPENSATION_FAILED"): "COMPENSATION_FAILED",
    ("ANY", "COMMITTED", "JOIN"): "JOINED",
    ("ANY", "COMMITTED_RECOVERY_PENDING", "JOIN"): "JOINED",
    ("ANY", "RECONCILED", "JOIN"): "JOINED",
    ("ANY", "JOINED", "STOP"): "STOPPED",
    ("ANY", "DISCARDED", "STOP"): "STOPPED",
    ("ANY", "FAILURE_RECORDED", "STOP"): "STOPPED",
    ("ANY", "COMPENSATED_VERIFIED", "STOP"): "STOPPED",
    ("ANY", "RESIDUAL_EFFECT", "STOP"): "STOPPED",
    ("ANY", "COMPENSATION_FAILED", "STOP"): "STOPPED",
}


def reduce_transition(state: Any, event: Any) -> dict[str, Any]:
    """Serializable lifecycle model; durable replay sets survive STOP."""
    state_m, event_m = _mapping(state), _mapping(event)
    try:
        if state_m is None or event_m is None or not _conserved(state_m):
            return _reject(state_m, "MALFORMED_OR_NONCONSERVING_STATE")
        branch, phase, event_type = state_m.get("branch"), state_m.get("phase"), event_m.get("type")
        if event_type == "AUTO_RETRY":
            return _reject(state_m, "AUTOMATIC_RETRY_FORBIDDEN")
        if event_type == "HOST_CRASH":
            nxt = deepcopy(dict(state_m)); nxt["host_recovery_required"] = True
            return {"accepted": True, "reason_code": "HOST_RECOVERY_REQUIRED", "state": nxt, "durable_record": {"host_recovery_required": True}, "specification_model_only": True}
        if event_type == "REVOKE":
            nxt = deepcopy(dict(state_m)); digest = nxt.get("capability_digest")
            if not _valid_digest(digest) or nxt.get("capability_status") != "ISSUED":
                return _reject(state_m, "REVOCATION_TARGET_NOT_LIVE")
            nxt["revoked_capability_digests"] = sorted(set(nxt["revoked_capability_digests"]) | {digest})
            released = _move_reserved(nxt, "remaining")
            nxt["capability_status"], nxt["phase"] = "REVOKED", "STOPPED"
            return {"accepted": True, "reason_code": "CAPABILITY_REVOKED", "state": nxt, "durable_record": {"revoked_capability_digest": digest, "reservation_release_by_key": _budget_rows(released), "atomic_serializable_transition": True}, "specification_model_only": True}
        if event_type == "CRASH":
            if phase in {"STOPPED", "JOINED"}:
                return _reject(state_m, "NO_LIVE_TRANSACTION_TO_RECOVER")
            nxt = deepcopy(dict(state_m)); nxt["pre_crash_phase"] = phase; nxt["phase"] = "COMMITTED_RECOVERY_PENDING" if phase == "COMMITTED" else "RECOVERING"; nxt["fencing_epoch"] += 1
            return {"accepted": True, "reason_code": "CRASH_FENCED", "state": nxt, "durable_record": {"fencing_epoch": nxt["fencing_epoch"]}, "specification_model_only": True}
        if event_type == "RECOVER_ORPHAN":
            if phase not in {"RECOVERING", "COMMITTED_RECOVERY_PENDING"} or event_m.get("observed_fencing_epoch") != state_m.get("fencing_epoch"):
                return _reject(state_m, "RECOVERY_FENCE_MISMATCH")
            if _trusted_runtime_d2_frontier(state_m, state_m.get("admitted_d2_frontier_record"), state_m.get("contract_digest")) is None:
                return _reject(state_m, "RECOVERY_D2_FRONTIER_VERIFICATION_REQUIRED")
            if not _trusted_admitted_iteration_slot(state_m, state_m.get("admitted_iteration_slot_digest"), state_m.get("admitted_request_digest")):
                return _reject(state_m, "RECOVERY_ITERATION_SLOT_VERIFICATION_REQUIRED")
            nxt = deepcopy(dict(state_m))
            if phase == "COMMITTED_RECOVERY_PENDING":
                if event_m.get("same_object_chain_verified") is not True:
                    return _reject(state_m, "COMMITTED_RECOVERY_CHAIN_REQUIRED")
                nxt["phase"] = "COMMITTED"
            elif nxt.get("pre_crash_phase") == "COMPENSATION_PENDING":
                nxt["phase"], nxt["quarantined"] = "COMPENSATION_PENDING", True
            elif nxt.get("dispatch_intent_digest") and branch == "EXTERNAL":
                nxt["phase"], nxt["quarantined"] = "QUARANTINED", True
                _quarantine_reserved(nxt)
            elif nxt.get("dispatch_intent_digest"):
                proof = _mapping(event_m.get("no_effect_proof")) or {}
                trusted_proof = _mapping(event_m.get("trusted_no_effect_verification")) or {}
                no_effect = proof.get("signature_verified") is True and proof.get("verified_by") and proof.get("observed_effects") == [] and proof.get("observed_effects_digest") == canonical_digest([]) and _valid_digest(proof.get("payload_digest")) and trusted_proof.get("payload_digest") == proof.get("payload_digest") and trusted_proof.get("signature_verified") is True and trusted_proof.get("no_effect_verified") is True
                if no_effect:
                    _move_reserved(nxt, "remaining"); nxt["phase"] = "DISCARDED"
                else:
                    nxt["phase"], nxt["quarantined"] = "QUARANTINED", True
                    _quarantine_reserved(nxt)
            else:
                _move_reserved(nxt, "remaining"); nxt["phase"] = "STOPPED"
            return {"accepted": True, "reason_code": "ORPHAN_RECOVERED", "state": nxt, "durable_record": {"recovered_phase": nxt["phase"]}, "specification_model_only": True}
        target = TRANSITIONS.get((str(branch), str(phase), str(event_type))) or TRANSITIONS.get(("ANY", str(phase), str(event_type)))
        if target is None:
            return _reject(state_m, "ILLEGAL_TRANSITION")
        nxt, record = deepcopy(dict(state_m)), None
        if event_type == "PROPOSE":
            if not isinstance(event_m.get("transaction_id"), str): return _reject(state_m, "TRANSACTION_ID_MISSING")
            if state_m.get("host_recovery_required") and not _trusted_host_recovery_valid(_mapping(state_m.get("trusted_store")) or {}, event_m.get("host_recovery_evidence_ref"), state_m.get("fencing_epoch")): return _reject(state_m, "HOST_RECOVERY_GATE_REQUIRED")
            for key in ("admitted_decision_digest", "admitted_envelope_digest", "admitted_reservation_vector", "admitted_reservation_vector_digest", "admitted_request_digest", "admitted_iteration_slot_digest", "admitted_d2_frontier_digest", "admitted_d2_frontier_record", "admitted_target_kind", "admitted_target_binding_digest", "approval_receipt_digest", "capability_effects_digest", "capability_budgets_digest", "capability_status", "capability_digest", "issued_capability", "capability_verification_digest", "capability_lineage_digest", "contract_digest", "iteration_slot_digest", "execution_binding", "capability_expires_at", "capability_revocation_epoch", "capability_fencing_epoch", "supply_chain_measurement_digest", "reservation_vector", "reservation_vector_digest", "dispatch_intent_digest", "target_kind", "idempotency_key_digest", "connector_id", "source_chain_digest", "reconciliation_evidence_digest", "failure_disposition", "compensation_authorization", "quiescence_attestation_digest", "seal_digest", "postcheck_attestation_digest", "quiesce_evidence_ref", "seal_evidence_ref", "postcheck_evidence_ref", "object_identity", "object_id", "object_digest", "receipt_chain_digest"):
                nxt[key] = "NONE" if key == "capability_status" else ([] if key == "reservation_vector" else None)
            nxt["approval_mode"] = "NOT_REQUIRED"
            keys = nxt["budget_total_by_key"]
            nxt["budget_reserved_by_key"] = {key: 0 for key in keys}
            nxt["unknown_escrow_by_key"] = {key: 0 for key in keys}
            _sync_budget_scalars(nxt)
            nxt["quarantined"], nxt["automatic_retry_allowed"] = False, False
            nxt["host_recovery_required"] = False
            nxt["trusted_pep_receipts"] = deepcopy(event_m.get("trusted_pep_receipts", {}))
            nxt["transaction_id"] = event_m["transaction_id"]
        elif event_type == "ADMIT":
            decision = _mapping(event_m.get("decision"))
            if decision is None or decision.get("decision") != "ALLOW" or not decision_digest_valid(decision): return _reject(state_m, "ADMIT_REQUIRES_VALID_ALLOW_DECISION")
            pep = _mapping(event_m.get("trusted_pep_verification")) or {}
            trusted_pep = _mapping(state_m.get("trusted_pep_receipts", {})).get(pep.get("receipt_digest"))
            if not (trusted_pep == pep and pep.get("signature_verified") is True and pep.get("verified_by") and pep.get("decision_digest") == decision.get("decision_digest") and pep.get("request_digest") == decision.get("evaluation", {}).get("request_digest") and pep.get("authorized_envelope_digest") == canonical_digest(decision.get("authorized_envelope")) and pep.get("reservation_vector_digest") == canonical_digest(decision.get("reservations")) and pep.get("manifest_digest") == decision.get("evaluation", {}).get("manifest_digest") and pep.get("policy_digest") == decision.get("evaluation", {}).get("policy_digest") and pep.get("receipt_digest") == canonical_digest({key: value for key, value in pep.items() if key != "receipt_digest"})): return _reject(state_m, "ADMIT_EXTERNAL_PEP_VERIFICATION_FAILED")
            nxt["admitted_decision_digest"] = decision["decision_digest"]; nxt["admitted_envelope_digest"] = canonical_digest(decision["authorized_envelope"])
            nxt["admitted_reservation_vector"], nxt["admitted_reservation_vector_digest"] = deepcopy(decision["reservations"]), canonical_digest(decision["reservations"])
            evaluation = _mapping(decision.get("evaluation")) or {}
            admitted_frontier = _mapping(evaluation.get("d2_frontier_record"))
            if admitted_frontier is None or evaluation.get("d2_frontier_digest") != admitted_frontier.get("frontier_record_digest") or not _valid_digest(evaluation.get("d2_frontier_digest")):
                return _reject(state_m, "ADMIT_D2_FRONTIER_BINDING_INVALID")
            if any(admitted_frontier.get(key) != state_m.get(key) for key in ("journal_sequence", "fencing_epoch", "joined_iteration")):
                return _reject(state_m, "ADMIT_D2_FRONTIER_REDUCER_STATE_MISMATCH")
            if _trusted_runtime_d2_frontier(state_m, admitted_frontier, evaluation.get("contract_digest")) is None:
                return _reject(state_m, "ADMIT_D2_FRONTIER_VERIFICATION_REQUIRED")
            slot_digest = evaluation.get("iteration_slot_digest")
            request_digest = evaluation.get("request_digest")
            if not _valid_digest(slot_digest) or not _trusted_admitted_iteration_slot(state_m, slot_digest, request_digest): return _reject(state_m, "ADMIT_ITERATION_SLOT_VERIFICATION_REQUIRED")
            slot_record = _mapping((_mapping((_mapping(state_m.get("trusted_store")) or {}).get("iteration_slot_verifications")) or {}).get(f"{slot_digest}:{state_m.get('fencing_epoch')}")) or {}
            if (_mapping(slot_record.get("slot")) or {}).get("iteration") != state_m.get("joined_iteration", 0) + 1:
                return _reject(state_m, "ADMIT_ITERATION_SLOT_FRONTIER_MISMATCH")
            nxt["admitted_request_digest"], nxt["admitted_iteration_slot_digest"], nxt["admitted_d2_frontier_digest"], nxt["admitted_d2_frontier_record"] = request_digest, slot_digest, evaluation["d2_frontier_digest"], deepcopy(admitted_frontier)
            if not all(_valid_digest(evaluation.get(key)) for key in ("broker_ipc_attestation_digest", "broker_ipc_binding_digest", "resource_vector_digest")):
                return _reject(state_m, "ADMIT_BROKER_IPC_BINDING_INVALID")
            nxt["admitted_broker_ipc_attestation_digest"], nxt["admitted_broker_ipc_binding_digest"], nxt["resource_vector_digest"] = evaluation["broker_ipc_attestation_digest"], evaluation["broker_ipc_binding_digest"], evaluation["resource_vector_digest"]
            broker_records = _mapping((_mapping(state_m.get("trusted_store")) or {}).get("broker_ipc_attestations")) or {}
            record = _mapping(broker_records.get(nxt["admitted_broker_ipc_attestation_digest"])) or {}
            nxt["admitted_runtime_session_id"], nxt["admitted_broker_ipc_fencing_epoch"] = (_mapping(record.get("attestation")) or {}).get("runtime_session_id"), (_mapping(record.get("attestation")) or {}).get("session_fencing_epoch")
            if not _trusted_admitted_broker_ipc(nxt): return _reject(state_m, "ADMIT_BROKER_IPC_ATTESTATION_REQUIRED")
            if evaluation.get("approval_mode") not in {"NOT_REQUIRED", "REQUIRED"} or (evaluation.get("approval_mode") == "REQUIRED" and not _valid_digest(evaluation.get("approval_receipt_digest"))) or (evaluation.get("approval_mode") == "NOT_REQUIRED" and evaluation.get("approval_receipt_digest") is not None):
                return _reject(state_m, "ADMIT_APPROVAL_BINDING_INVALID")
            endpoint_digest, descriptor_digest = evaluation.get("endpoint_binding_digest"), evaluation.get("descriptor_binding_digest")
            if _valid_digest(endpoint_digest) == _valid_digest(descriptor_digest):
                return _reject(state_m, "ADMIT_TARGET_BINDING_INVALID")
            nxt["admitted_target_kind"] = "ENDPOINT" if _valid_digest(endpoint_digest) else "FILESYSTEM"
            nxt["admitted_target_binding_digest"] = endpoint_digest if _valid_digest(endpoint_digest) else descriptor_digest
            nxt["approval_mode"], nxt["approval_receipt_digest"] = evaluation.get("approval_mode"), evaluation.get("approval_receipt_digest")
        elif event_type == "CALCULATE_RESERVATION":
            vector = event_m.get("reservation_vector")
            mapped = _budget_map(vector, "amount", reject_duplicates=True)
            if vector != nxt.get("admitted_reservation_vector") or event_m.get("reservation_vector_digest") != nxt.get("admitted_reservation_vector_digest") or not mapped or any(key not in nxt["budget_remaining_by_key"] or amount <= 0 or amount > nxt["budget_remaining_by_key"][key] for key, amount in mapped.items()): return _reject(state_m, "BUDGET_RESERVATION_INVALID")
            for key, amount in mapped.items():
                nxt["budget_remaining_by_key"][key] -= amount
                nxt["budget_reserved_by_key"][key] += amount
            _sync_budget_scalars(nxt)
            nxt["reservation_vector"], nxt["reservation_vector_digest"] = deepcopy(vector), canonical_digest(vector)
            record = {"budget_transition": {"kind": "RESERVE", "delta": _budget_rows(mapped), "after": _budget_snapshot(nxt)}, "atomic_serializable_transition": True}
        elif event_type == "ISSUE_CAPABILITY":
            cap = _mapping(event_m.get("capability"))
            if cap is None or cap.get("state") != "ISSUED" or not _self_digest_valid(cap, "capability_digest"): return _reject(state_m, "CAPABILITY_INVALID")
            digest, bindings = cap["capability_digest"], _mapping(cap.get("bindings")) or {}
            target_field = "endpoint_binding_digest" if nxt.get("admitted_target_kind") == "ENDPOINT" else "descriptor_binding_digest"
            forbidden_target_field = "descriptor_binding_digest" if target_field == "endpoint_binding_digest" else "endpoint_binding_digest"
            if bindings.get("decision_digest") != nxt.get("admitted_decision_digest") or bindings.get("iteration_slot_digest") != nxt.get("admitted_iteration_slot_digest") or bindings.get("d2_frontier_digest") != nxt.get("admitted_d2_frontier_digest") or bindings.get("authorized_envelope_digest") != nxt.get("admitted_envelope_digest") or canonical_digest(cap.get("effects")) != nxt.get("admitted_envelope_digest") or cap.get("budgets") != nxt.get("admitted_reservation_vector") or bindings.get("approval_mode") != nxt.get("approval_mode") or bindings.get("approval_receipt_digest") != nxt.get("approval_receipt_digest") or bindings.get("broker_ipc_attestation_digest") != nxt.get("admitted_broker_ipc_attestation_digest") or bindings.get("broker_ipc_binding_digest") != nxt.get("admitted_broker_ipc_binding_digest") or bindings.get("resource_vector_digest") != nxt.get("resource_vector_digest") or bindings.get(target_field) != nxt.get("admitted_target_binding_digest") or forbidden_target_field in bindings: return _reject(state_m, "CAPABILITY_ADMISSION_BINDING_MISMATCH")
            if digest in nxt["consumed_capability_digests"] or digest in nxt["revoked_capability_digests"]: return _reject(state_m, "CAPABILITY_REPLAY")
            store = _mapping(state_m.get("trusted_store")) or {}
            capability_store = _mapping(store.get("capabilities")) or {}
            trusted = _mapping(capability_store.get(event_m.get("capability_verification_ref"))) or {}
            verification = _mapping(cap.get("issuer_verification")) or {}
            external_record = trusted
            now, not_before, expires = _parse_time(trusted.get("trusted_time")), _parse_time(cap.get("not_before")), _parse_time(cap.get("expires_at"))
            expected_external = {key: value for key, value in capability_verifier_record(cap).items() if key in {"capability_digest", "signed_claims_digest", "issuer", "principal", "audience", "purpose", "contract_digest", "lineage_digest", "delegation_digest", "bindings_digest", "effects_digest", "budgets_digest", "signature_verified", "not_revoked", "full_claims_verified", "verified_by"}}
            if not (all(external_record.get(key) == expected for key, expected in expected_external.items()) and _trusted_delegation_record(store, cap, nxt.get("revoked_capability_digests")) and trusted.get("signature_verified") is True and trusted.get("not_revoked") is True and trusted.get("capability_digest") == digest and trusted.get("signed_claims_digest") == verification.get("signed_claims_digest") and trusted.get("verified_by") == verification.get("verified_by") and trusted.get("effects_digest") == canonical_digest(cap.get("effects")) and trusted.get("budgets_digest") == canonical_digest(cap.get("budgets")) and now and not_before and expires and not_before <= now < expires and trusted.get("current_revocation_epoch") == cap.get("revocation_epoch") == verification.get("revocation_epoch") and trusted.get("current_fencing_epoch") == (_mapping(cap.get("execution_binding")) or {}).get("session_epoch") == verification.get("fencing_epoch")):
                return _reject(state_m, "CAPABILITY_TRUSTED_VALIDATION_FAILED")
            nxt["capability_status"], nxt["capability_digest"], nxt["issued_capability"], nxt["execution_binding"] = "ISSUED", digest, deepcopy(cap), deepcopy(cap.get("execution_binding"))
            nxt["capability_expires_at"], nxt["capability_revocation_epoch"], nxt["capability_fencing_epoch"] = cap.get("expires_at"), cap.get("revocation_epoch"), verification.get("fencing_epoch")
            nxt["capability_effects_digest"], nxt["capability_budgets_digest"] = canonical_digest(cap.get("effects")), canonical_digest(cap.get("budgets"))
            nxt["capability_verification_digest"] = canonical_digest(expected_external)
            nxt["supply_chain_measurement_digest"] = bindings.get("supply_chain_measurement_digest")
            nxt["contract_digest"], nxt["iteration_slot_digest"], nxt["capability_lineage_digest"] = bindings.get("contract_digest"), bindings.get("iteration_slot_digest"), canonical_digest(cap.get("lineage"))
        elif event_type == "DURABLE_DISPATCH":
            digest = event_m.get("capability_digest")
            if nxt.get("capability_status") != "ISSUED" or digest != nxt.get("capability_digest"): return _reject(state_m, "DISPATCH_CAPABILITY_MISMATCH")
            if digest in nxt["consumed_capability_digests"]: return _reject(state_m, "CAPABILITY_REPLAY")
            if event_m.get("decision_digest") != nxt.get("admitted_decision_digest") or event_m.get("iteration_slot_digest") != nxt.get("admitted_iteration_slot_digest") or event_m.get("d2_frontier_digest") != nxt.get("admitted_d2_frontier_digest") or event_m.get("authorized_envelope_digest") != nxt.get("admitted_envelope_digest") or event_m.get("supply_chain_measurement_digest") != nxt.get("supply_chain_measurement_digest") or event_m.get("broker_ipc_attestation_digest") != nxt.get("admitted_broker_ipc_attestation_digest") or event_m.get("broker_ipc_binding_digest") != nxt.get("admitted_broker_ipc_binding_digest") or event_m.get("resource_vector_digest") != nxt.get("resource_vector_digest") or event_m.get("approval_mode") != nxt.get("approval_mode") or event_m.get("approval_receipt_digest") != nxt.get("approval_receipt_digest"): return _reject(state_m, "DISPATCH_DECISION_BINDING_MISMATCH")
            if not _trusted_admitted_broker_ipc(nxt): return _reject(state_m, "DISPATCH_BROKER_IPC_ATTESTATION_REQUIRED")
            if event_m.get("execution_binding") != nxt.get("execution_binding"): return _reject(state_m, "DISPATCH_PLACEMENT_SESSION_BINDING_MISMATCH")
            if event_m.get("reservation_vector") != nxt.get("reservation_vector") or event_m.get("reservation_vector_digest") != nxt.get("reservation_vector_digest") or event_m.get("capability_effects_digest") != nxt.get("capability_effects_digest") or event_m.get("capability_budgets_digest") != nxt.get("capability_budgets_digest"): return _reject(state_m, "DISPATCH_BUDGET_VECTOR_MISMATCH")
            if not _trusted_admitted_iteration_slot(nxt, nxt.get("admitted_iteration_slot_digest"), nxt.get("admitted_request_digest")): return _reject(state_m, "DISPATCH_ITERATION_SLOT_VERIFICATION_REQUIRED")
            store = _mapping(state_m.get("trusted_store")) or {}
            trusted = _mapping((_mapping(store.get("dispatch")) or {}).get(event_m.get("dispatch_verification_ref"))) or {}
            identity = _mapping(event_m.get("object_identity")) or {}
            issued_capability = _mapping(nxt.get("issued_capability")) or {}
            effects = issued_capability.get("effects") if isinstance(issued_capability.get("effects"), list) else []
            resource_kinds = {effect.get("resource_kind") for effect in effects if isinstance(effect, Mapping)}
            target_kind = "FILESYSTEM" if effects and resource_kinds <= {"FILE", "DIRECTORY"} else ("ENDPOINT" if effects and resource_kinds == {"ENDPOINT"} else None)
            if target_kind is None or target_kind != nxt.get("admitted_target_kind"):
                return _reject(state_m, "DISPATCH_TARGET_KIND_AMBIGUOUS")
            if (branch == "EXTERNAL") != (target_kind == "ENDPOINT"):
                return _reject(state_m, "DISPATCH_BRANCH_TARGET_KIND_MISMATCH")
            if target_kind == "FILESYSTEM":
                if any(event_m.get(key) is not None for key in ("idempotency_key_digest", "connector_id", "source_chain_digest")) or trusted.get("endpoint_binding") is not None:
                    return _reject(state_m, "DISPATCH_CROSS_KIND_TARGET_EVIDENCE")
                if not _object_identity_valid(identity, object_id=identity.get("final_object_id"), object_digest=identity.get("final_object_digest")):
                    return _reject(state_m, "DISPATCH_OBJECT_IDENTITY_INVALID")
                physical_target = _mapping(trusted.get("physical_target")) or {}
                target_unsigned = {key: value for key, value in physical_target.items() if key != "composite_binding_digest"}
                capability_target_digests = _capability_filesystem_target_digests(issued_capability, identity)
                if not (physical_target.get("canonical_path") and physical_target.get("descriptor_id") == identity.get("descriptor_id") and physical_target.get("root_id") == identity.get("root_id") and physical_target.get("mount_id") == identity.get("mount_id") and physical_target.get("resolution_epoch") == identity.get("resolution_epoch") and physical_target.get("final_object_id") == identity.get("final_object_id") and physical_target.get("final_object_digest") == identity.get("final_object_digest") and physical_target.get("composite_binding_digest") == canonical_digest(target_unsigned) and physical_target.get("composite_binding_digest") in capability_target_digests and _verified_filesystem_target(physical_target, physical_target.get("composite_binding_digest"), store.get("verified_filesystem_targets"))):
                    return _reject(state_m, "DISPATCH_PHYSICAL_TARGET_MISMATCH")
            else:
                if trusted.get("physical_target") is not None or not _endpoint_binding_valid(identity):
                    return _reject(state_m, "DISPATCH_ENDPOINT_IDENTITY_INVALID")
                capability_bindings = _mapping(issued_capability.get("bindings")) or {}
                endpoint_digests = _capability_endpoint_binding_digests(issued_capability)
                if endpoint_digests != {identity.get("endpoint_binding_digest")} or capability_bindings.get("endpoint_binding_digest") != identity.get("endpoint_binding_digest") or capability_bindings.get("descriptor_binding_digest") is not None:
                    return _reject(state_m, "DISPATCH_ENDPOINT_TARGET_MISMATCH")
                if event_m.get("connector_id") != identity.get("connector_id") or event_m.get("idempotency_key_digest") != identity.get("idempotency_key_digest") or not _valid_digest(event_m.get("source_chain_digest")):
                    return _reject(state_m, "DISPATCH_EXTERNAL_BINDING_INVALID")
                if not _verified_endpoint_binding(identity, store.get("verified_endpoint_bindings"), store.get("trusted_time")):
                    return _reject(state_m, "DISPATCH_ENDPOINT_VERIFICATION_REQUIRED")
            now, expires = _parse_time(trusted.get("trusted_time")), _parse_time(nxt.get("capability_expires_at"))
            immutable_claims = {key: trusted.get(key) for key in ("capability_digest", "signed_claims_digest", "issuer", "principal", "audience", "purpose", "contract_digest", "lineage_digest", "delegation_digest", "bindings_digest", "effects_digest", "budgets_digest", "signature_verified", "not_revoked", "full_claims_verified", "verified_by")}
            if not (canonical_digest(immutable_claims) == nxt.get("capability_verification_digest") and _trusted_delegation_record(store, _mapping(nxt.get("issued_capability")) or {}, nxt.get("revoked_capability_digests")) and trusted.get("not_revoked") is True and trusted.get("capability_digest") == digest and trusted.get("object_identity") == event_m.get("object_identity") and now and expires and now < expires and trusted.get("current_revocation_epoch") == nxt.get("capability_revocation_epoch") and trusted.get("current_fencing_epoch") == nxt.get("capability_fencing_epoch")):
                return _reject(state_m, "DISPATCH_CAPABILITY_STALE_OR_REVOKED")
            if _trusted_runtime_d2_frontier(nxt, nxt.get("admitted_d2_frontier_record"), nxt.get("contract_digest")) is None:
                return _reject(state_m, "DISPATCH_D2_FRONTIER_VERIFICATION_REQUIRED")
            dispatch = event_m.get("dispatch_intent_digest")
            if not _valid_digest(dispatch): return _reject(state_m, "DISPATCH_DIGEST_INVALID")
            nxt["capability_status"] = "CONSUMED"; nxt["consumed_capability_digests"] = sorted(set(nxt["consumed_capability_digests"]) | {digest}); nxt["dispatch_intent_digest"] = dispatch; nxt["target_kind"] = target_kind; nxt["object_identity"] = deepcopy(event_m["object_identity"])
            nxt["idempotency_key_digest"] = event_m.get("idempotency_key_digest"); nxt["connector_id"] = event_m.get("connector_id"); nxt["source_chain_digest"] = event_m.get("source_chain_digest")
            nxt["iteration_counter"] += 1; nxt["journal_sequence"] += 1; nxt["fencing_epoch"] += 1
            record = {"transaction_id": nxt["transaction_id"], "capability_consumption": digest, "budget_reservation": nxt["budget_reserved"], "budget_reservation_by_key": _budget_rows(nxt["budget_reserved_by_key"]), "budget_reservation_vector": deepcopy(nxt["reservation_vector"]), "budget_reservation_vector_digest": nxt["reservation_vector_digest"], "iteration_slot_digest": nxt["admitted_iteration_slot_digest"], "d2_frontier_digest": nxt["admitted_d2_frontier_digest"], "broker_ipc_attestation_digest": nxt["admitted_broker_ipc_attestation_digest"], "broker_ipc_binding_digest": nxt["admitted_broker_ipc_binding_digest"], "resource_vector_digest": nxt["resource_vector_digest"], "dispatch_intent": dispatch, "target_kind": target_kind, "object_identity": deepcopy(nxt["object_identity"]), "idempotency_key_digest": nxt["idempotency_key_digest"], "source_chain_digest": nxt["source_chain_digest"], "decision_digest": nxt["admitted_decision_digest"], "authorized_envelope_digest": nxt["admitted_envelope_digest"], "approval_mode": nxt.get("approval_mode"), "approval_receipt_digest": nxt.get("approval_receipt_digest"), "execution_binding": deepcopy(nxt["execution_binding"]), "monotonic_counter": nxt["iteration_counter"], "journal_sequence": nxt["journal_sequence"], "fencing_epoch": nxt["fencing_epoch"], "atomic_serializable_transition": True}
        elif event_type in {"QUIESCE", "SEAL", "POSTCHECK_PASS"}:
            key, ref_key, evidence_type = {"QUIESCE": ("quiescence_attestation_digest", "quiesce_evidence_ref", "QUIESCE"), "SEAL": ("seal_digest", "seal_evidence_ref", "SEAL"), "POSTCHECK_PASS": ("postcheck_attestation_digest", "postcheck_evidence_ref", "POSTCHECK")} [event_type]
            trusted = _trusted_stage_evidence_valid(_mapping(state_m.get("trusted_store")) or {}, event_m.get(ref_key), evidence_type, transaction_id=nxt.get("transaction_id"), capability_digest=nxt.get("capability_digest"), session_id=(_mapping(nxt.get("execution_binding")) or {}).get("session_id"), object_identity=nxt.get("object_identity"), fencing_epoch=nxt.get("fencing_epoch"))
            if trusted is None or event_m.get(key) != trusted.get("evidence_digest"): return _reject(state_m, "TRUSTED_EVIDENCE_MISSING")
            nxt[key], nxt[ref_key] = trusted["evidence_digest"], event_m[ref_key]
        elif event_type == "POSTCHECK_FAIL":
            proof = _mapping(event_m.get("no_effect_proof")) or {}
            if event_m.get("no_effect_proven") is not True or proof.get("signature_verified") is not True or not proof.get("verified_by") or proof.get("observed_effects") != [] or proof.get("observed_effects_digest") != canonical_digest([]) or not _valid_digest(proof.get("payload_digest")):
                return _reject(state_m, "POSTCHECK_NO_EFFECT_PROOF_REQUIRED")
            released_map = _move_reserved(nxt, "remaining")
            released = sum(released_map.values())
            record = {"reservation_release": released, "reservation_release_by_key": _budget_rows(released_map), "reservation_release_vector": deepcopy(nxt.get("reservation_vector", [])), "reservation_release_vector_digest": nxt.get("reservation_vector_digest"), "no_effect_proof_digest": proof.get("payload_digest"), "atomic_serializable_transition": True}
        elif event_type == "COMMIT":
            if not all(_valid_digest(nxt.get(key)) for key in ("quiescence_attestation_digest", "seal_digest", "postcheck_attestation_digest")): return _reject(state_m, "COMMIT_EVIDENCE_GUARD_FAILED")
            store = _mapping(nxt.get("trusted_store")) or {}
            stage_checks = (("quiesce_evidence_ref", "QUIESCE", "quiescence_attestation_digest"), ("seal_evidence_ref", "SEAL", "seal_digest"), ("postcheck_evidence_ref", "POSTCHECK", "postcheck_attestation_digest"))
            if any((stage_record := _trusted_stage_evidence_valid(store, nxt.get(reference), evidence_type, transaction_id=nxt.get("transaction_id"), capability_digest=nxt.get("capability_digest"), session_id=(_mapping(nxt.get("execution_binding")) or {}).get("session_id"), object_identity=nxt.get("object_identity"), fencing_epoch=nxt.get("fencing_epoch"))) is None or stage_record.get("evidence_digest") != nxt.get(digest) for reference, evidence_type, digest in stage_checks): return _reject(state_m, "COMMIT_STAGE_EVIDENCE_INVALID")
            if not isinstance(event_m.get("object_id"), str) or not all(_valid_digest(event_m.get(key)) for key in ("object_digest", "receipt_chain_digest")): return _reject(state_m, "COMMIT_OBJECT_CHAIN_REQUIRED")
            if not _object_identity_valid(nxt.get("object_identity"), object_id=event_m.get("object_id"), object_digest=event_m.get("object_digest")): return _reject(state_m, "COMMIT_OBJECT_IDENTITY_MISMATCH")
            if event_m.get("transaction_id") != nxt.get("transaction_id"): return _reject(state_m, "COMMIT_TRANSACTION_MISMATCH")
            evidence = _mapping((_mapping((_mapping(state_m.get("trusted_store")) or {}).get("commit")) or {}).get(event_m.get("commit_evidence_ref"))) or {}
            unsigned = {key: value for key, value in evidence.items() if key != "evidence_digest"}
            if evidence.get("evidence_type") != "COMMIT" or evidence.get("transaction_id") != nxt.get("transaction_id") or evidence.get("decision_digest") != nxt.get("admitted_decision_digest") or evidence.get("capability_digest") != nxt.get("capability_digest") or evidence.get("envelope_digest") != nxt.get("admitted_envelope_digest") or evidence.get("object_id") != event_m.get("object_id") or evidence.get("object_digest") != event_m.get("object_digest") or evidence.get("chain_digest") != event_m.get("receipt_chain_digest") or evidence.get("signature_verified") is not True or not evidence.get("verified_by") or evidence.get("evidence_digest") != canonical_digest(unsigned): return _reject(state_m, "COMMIT_TRUSTED_EVIDENCE_REQUIRED")
            nxt["object_id"], nxt["object_digest"], nxt["receipt_chain_digest"] = event_m["object_id"], event_m["object_digest"], event_m["receipt_chain_digest"]
            spent_map = _move_reserved(nxt, "spent")
            record = {"budget_transition": {"kind": "COMMIT_SPEND", "delta": _budget_rows(spent_map), "after": _budget_snapshot(nxt)}, "atomic_serializable_transition": True}
        elif event_type == "OUTCOME_UNKNOWN":
            nxt["quarantined"] = True
            escrow_map = _quarantine_reserved(nxt)
            record = {"budget_transition": {"kind": "QUARANTINE_ESCROW", "delta": _budget_rows(escrow_map), "after": _budget_snapshot(nxt)}, "atomic_serializable_transition": True}
        elif event_type in {"OUTCOME_SUCCESS", "OUTCOME_FAILURE"}:
            record = {"observed_outcome": "SUCCESS" if event_type == "OUTCOME_SUCCESS" else "FAILURE", "atomic_serializable_transition": True}
        elif event_type in {"RECONCILE_SUCCESS", "RECONCILE_FAILURE", "RECORD_FAILURE"}:
            if event_type == "RECONCILE_SUCCESS":
                expected_outcome = "SUCCESS"
            else:
                candidate_record = _mapping((_mapping((_mapping(nxt.get("trusted_store")) or {}).get("reconciliation")) or {}).get(event_m.get("reconciliation_evidence_ref"))) or {}
                expected_outcome = candidate_record.get("outcome")
                if expected_outcome not in {"FAILURE_NO_EFFECT", "FAILURE_WITH_RESIDUAL_EFFECT"}:
                    return _reject(state_m, "TRUSTED_RECONCILIATION_EVIDENCE_REQUIRED")
            evidence = _trusted_reconciliation_evidence(nxt, event_m, expected_outcome)
            if evidence is None:
                return _reject(state_m, "TRUSTED_RECONCILIATION_EVIDENCE_REQUIRED")
            if expected_outcome == "SUCCESS":
                delta = _move_reserved(nxt, "spent")
                kind = "RECONCILED_SPEND"
            elif expected_outcome == "FAILURE_NO_EFFECT":
                delta = _move_reserved(nxt, "remaining")
                kind = "RECONCILED_NO_EFFECT_RELEASE"
            else:
                disposition = _mapping(evidence.get("failure_disposition")) or {}
                disposition_delta = _apply_residual_budget_disposition(nxt, disposition["budget_dispositions"])
                delta = {}
                kind = "RECONCILED_RESIDUAL_EFFECT"
                target = "COMPENSATION_PENDING"
                nxt["quarantined"] = True
                nxt["failure_disposition"] = deepcopy(disposition)
                nxt["compensation_authorization"] = deepcopy(disposition.get("compensation_authorization"))
            nxt["reconciliation_evidence_digest"] = evidence["evidence_digest"]
            nxt["consumed_reconciliation_evidence_digests"] = sorted(set(nxt["consumed_reconciliation_evidence_digests"]) | {evidence["evidence_digest"]})
            record = {"reconciliation_evidence_digest": evidence["evidence_digest"], "budget_transition": {"kind": kind, "delta": disposition_delta if expected_outcome == "FAILURE_WITH_RESIDUAL_EFFECT" else _budget_rows(delta), "after": _budget_snapshot(nxt)}, "failure_disposition": deepcopy(evidence.get("failure_disposition")), "atomic_serializable_transition": True}
        elif event_type in {"COMPENSATION_VERIFIED", "COMPENSATION_RESIDUAL", "COMPENSATION_FAILED"}:
            spent_map = _move_reserved(nxt, "spent")
            record = {"budget_transition": {"kind": "COMPENSATION_SPEND", "delta": _budget_rows(spent_map), "after": _budget_snapshot(nxt)}, "atomic_serializable_transition": True}
        elif event_type == "JOIN":
            evidence = _mapping(event_m.get("join_evidence")) or {}
            if any(evidence.get(key) is not True for key in ("committed_subset_authorized", "quiescence", "seal", "postcheck", "trusted_attestation", "digest_chain", "anti_rollback")): return _reject(state_m, "JOIN_EVIDENCE_GUARD_FAILED")
            if any(evidence.get(key) != nxt.get(expected) for key, expected in (("transaction_id", "transaction_id"), ("object_id", "object_id"), ("object_digest", "object_digest"), ("chain_digest", "receipt_chain_digest"))): return _reject(state_m, "JOIN_SAME_OBJECT_CHAIN_MISMATCH")
            if not _object_identity_valid(nxt.get("object_identity"), object_id=nxt.get("object_id"), object_digest=nxt.get("object_digest")) or event_m.get("object_identity") != nxt.get("object_identity") or evidence.get("object_identity") != nxt.get("object_identity"): return _reject(state_m, "JOIN_OBJECT_IDENTITY_MISMATCH")
            if any(evidence.get(key) != nxt.get(key) for key in ("quiesce_evidence_ref", "seal_evidence_ref", "postcheck_evidence_ref", "quiescence_attestation_digest", "seal_digest", "postcheck_attestation_digest")): return _reject(state_m, "JOIN_STAGE_EVIDENCE_MISMATCH")
            if event_m.get("decision_digest") != nxt.get("admitted_decision_digest"): return _reject(state_m, "JOIN_DIGEST_CHAIN_MISMATCH")
            if event_m.get("iteration_slot_digest") != nxt.get("admitted_iteration_slot_digest") or evidence.get("iteration_slot_digest") != nxt.get("admitted_iteration_slot_digest"): return _reject(state_m, "JOIN_ITERATION_SLOT_MISMATCH")
            if event_m.get("d2_frontier_digest") != nxt.get("admitted_d2_frontier_digest") or evidence.get("d2_frontier_digest") != nxt.get("admitted_d2_frontier_digest"): return _reject(state_m, "JOIN_D2_FRONTIER_MISMATCH")
            if event_m.get("broker_ipc_attestation_digest") != nxt.get("admitted_broker_ipc_attestation_digest") or event_m.get("broker_ipc_binding_digest") != nxt.get("admitted_broker_ipc_binding_digest") or event_m.get("resource_vector_digest") != nxt.get("resource_vector_digest") or any(evidence.get(key) != nxt.get(expected) for key, expected in (("broker_ipc_attestation_digest", "admitted_broker_ipc_attestation_digest"), ("broker_ipc_binding_digest", "admitted_broker_ipc_binding_digest"), ("resource_vector_digest", "resource_vector_digest"))): return _reject(state_m, "JOIN_BROKER_IPC_BINDING_MISMATCH")
            if not _trusted_admitted_iteration_slot(nxt, nxt.get("admitted_iteration_slot_digest"), nxt.get("admitted_request_digest")): return _reject(state_m, "JOIN_ITERATION_SLOT_VERIFICATION_REQUIRED")
            if not _trusted_admitted_broker_ipc(nxt): return _reject(state_m, "JOIN_BROKER_IPC_ATTESTATION_REQUIRED")
            if _trusted_runtime_d2_frontier(nxt, nxt.get("admitted_d2_frontier_record"), nxt.get("contract_digest")) is None: return _reject(state_m, "JOIN_D2_FRONTIER_VERIFICATION_REQUIRED")
            store = _mapping(nxt.get("trusted_store")) or {}
            stage_checks = (("quiesce_evidence_ref", "QUIESCE", "quiescence_attestation_digest"), ("seal_evidence_ref", "SEAL", "seal_digest"), ("postcheck_evidence_ref", "POSTCHECK", "postcheck_attestation_digest"))
            if any((stage_record := _trusted_stage_evidence_valid(store, nxt.get(reference), evidence_type, transaction_id=nxt.get("transaction_id"), capability_digest=nxt.get("capability_digest"), session_id=(_mapping(nxt.get("execution_binding")) or {}).get("session_id"), object_identity=nxt.get("object_identity"), fencing_epoch=nxt.get("fencing_epoch"))) is None or stage_record.get("evidence_digest") != nxt.get(digest) for reference, evidence_type, digest in stage_checks): return _reject(state_m, "JOIN_STAGE_EVIDENCE_INVALID")
            trusted = _mapping((_mapping(store.get("join")) or {}).get(event_m.get("join_evidence_ref"))) or {}
            unsigned = {key: value for key, value in trusted.items() if key != "evidence_digest"}
            if trusted.get("evidence_type") != "JOIN" or trusted.get("transaction_id") != nxt.get("transaction_id") or trusted.get("decision_digest") != nxt.get("admitted_decision_digest") or trusted.get("d2_frontier_digest") != nxt.get("admitted_d2_frontier_digest") or trusted.get("capability_digest") != nxt.get("capability_digest") or trusted.get("envelope_digest") != nxt.get("admitted_envelope_digest") or trusted.get("object_id") != evidence.get("object_id") or trusted.get("object_digest") != evidence.get("object_digest") or trusted.get("object_identity") != nxt.get("object_identity") or trusted.get("chain_digest") != evidence.get("chain_digest") or any(trusted.get(key) != nxt.get(key) for key in ("quiesce_evidence_ref", "seal_evidence_ref", "postcheck_evidence_ref", "quiescence_attestation_digest", "seal_digest", "postcheck_attestation_digest")) or trusted.get("signature_verified") is not True or not trusted.get("verified_by") or trusted.get("evidence_digest") != canonical_digest(unsigned): return _reject(state_m, "JOIN_TRUSTED_EVIDENCE_REQUIRED")
            nxt["joined_iteration"] = nxt["iteration_counter"]
        elif event_type == "STOP":
            nxt["controller_outcome"] = "STOPPED"; nxt["capability_status"], nxt["capability_digest"], nxt["execution_binding"] = "NONE", None, None
        nxt["phase"] = target
        if target == "QUARANTINED": nxt["quarantined"] = True
        if not _conserved(nxt): return _reject(state_m, "BUDGET_CONSERVATION_BROKEN")
        return {"accepted": True, "reason_code": "TRANSITION_ACCEPTED", "state": nxt, "durable_record": record, "specification_model_only": True}
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError):
        return _reject(state_m, "TRANSITION_REDUCER_ERROR")


def initial_state(branch: str, budget_total: int = 100000, trusted_store: Mapping[str, Any] | None = None, budget_vector: Any = None) -> dict[str, Any]:
    totals = _budget_map(budget_vector, "amount", reject_duplicates=True) if budget_vector is not None else None
    if totals is None:
        totals = {("LEGACY", "UNITS", ZERO_DIGEST, "lineage:legacy"): budget_total}
    zeros = {key: 0 for key in totals}
    state = {"phase": "STOPPED", "branch": branch, "controller_outcome": "STOPPED", "transaction_id": None, "trusted_store": deepcopy(dict(trusted_store or {})), "trusted_pep_receipts": {}, "admitted_decision_digest": None, "admitted_envelope_digest": None, "admitted_reservation_vector": [], "admitted_reservation_vector_digest": None, "admitted_request_digest": None, "admitted_iteration_slot_digest": None, "admitted_d2_frontier_digest": None, "admitted_d2_frontier_record": None, "admitted_target_kind": None, "admitted_target_binding_digest": None, "approval_mode": "NOT_REQUIRED", "approval_receipt_digest": None, "capability_effects_digest": None, "capability_budgets_digest": None, "capability_status": "NONE", "capability_digest": None, "issued_capability": None, "capability_verification_digest": None, "capability_lineage_digest": None, "contract_digest": None, "iteration_slot_digest": None, "execution_binding": None, "capability_expires_at": None, "capability_revocation_epoch": None, "capability_fencing_epoch": None, "supply_chain_measurement_digest": None, "consumed_capability_digests": [], "revoked_capability_digests": [], "consumed_reconciliation_evidence_digests": [], "budget_total_by_key": deepcopy(totals), "budget_remaining_by_key": deepcopy(totals), "budget_reserved_by_key": deepcopy(zeros), "budget_spent_by_key": deepcopy(zeros), "unknown_escrow_by_key": deepcopy(zeros), "budget_total": 0, "budget_remaining": 0, "budget_reserved": 0, "budget_spent": 0, "reservation_vector": [], "reservation_vector_digest": None, "unknown_escrow": 0, "iteration_counter": 0, "joined_iteration": 0, "journal_sequence": 0, "fencing_epoch": 1, "dispatch_intent_digest": None, "target_kind": None, "idempotency_key_digest": None, "connector_id": None, "source_chain_digest": None, "reconciliation_evidence_digest": None, "failure_disposition": None, "compensation_authorization": None, "quarantined": False, "automatic_retry_allowed": False, "quiescence_attestation_digest": None, "seal_digest": None, "postcheck_attestation_digest": None, "quiesce_evidence_ref": None, "seal_evidence_ref": None, "postcheck_evidence_ref": None, "object_identity": None, "object_id": None, "object_digest": None, "receipt_chain_digest": None, "host_recovery_required": False}
    state.update(admitted_broker_ipc_attestation_digest=None, admitted_broker_ipc_binding_digest=None, admitted_runtime_session_id=None, admitted_broker_ipc_fencing_epoch=None, resource_vector_digest=None)
    _sync_budget_scalars(state)
    return state


HOST_TRANSITIONS = {("UNALLOCATED", "ALLOCATE"): "ALLOCATED", ("ALLOCATED", "ATTEST_PLACEMENT"): "PLACEMENT_ATTESTED", ("PLACEMENT_ATTESTED", "START_SESSION"): "RUNNING", ("RUNNING", "HEARTBEAT"): "RUNNING", ("RUNNING", "CRASH"): "ORPHANED", ("ORPHANED", "FENCE"): "FENCED", ("FENCED", "RECOVER_ORPHAN"): "RECOVERED", ("RECOVERED", "TERMINATE"): "TERMINATED", ("RUNNING", "TERMINATE"): "TERMINATED"}


def initial_host_state(trusted_store: Mapping[str, Any] | None = None) -> dict[str, Any]:
    return {"phase": "UNALLOCATED", "host_id": None, "instance_id": None, "placement_digest": None, "session_id": None, "epoch": 0, "nonce": None, "heartbeat_sequence": 0, "orphan_inventory": [], "trusted_store": deepcopy(dict(trusted_store or {}))}


def reduce_host(state: Any, event: Any) -> dict[str, Any]:
    if not isinstance(state, Mapping) or not isinstance(event, Mapping): return {"accepted": False, "reason_code": "HOST_MALFORMED", "state": deepcopy(dict(state)) if isinstance(state, Mapping) else {}}
    target = HOST_TRANSITIONS.get((state.get("phase"), event.get("type")))
    if target is None: return {"accepted": False, "reason_code": "HOST_ILLEGAL_TRANSITION", "state": deepcopy(dict(state))}
    nxt = deepcopy(dict(state)); kind = event["type"]
    if kind == "ALLOCATE":
        if not isinstance(event.get("host_id"), str) or not isinstance(event.get("instance_id"), str) or not NONCE_RE.fullmatch(str(event.get("nonce"))): return {"accepted": False, "reason_code": "HOST_ALLOCATION_BINDING_INVALID", "state": deepcopy(dict(state))}
        nxt.update(host_id=event["host_id"], instance_id=event["instance_id"], nonce=event["nonce"], epoch=state.get("epoch", 0) + 1)
    elif kind == "ATTEST_PLACEMENT":
        if not _valid_digest(event.get("placement_digest")) or event.get("instance_id") != state.get("instance_id") or event.get("epoch") != state.get("epoch") or event.get("nonce") != state.get("nonce"): return {"accepted": False, "reason_code": "HOST_PLACEMENT_BINDING_INVALID", "state": deepcopy(dict(state))}
        nxt["placement_digest"] = event["placement_digest"]
    elif kind == "START_SESSION":
        if not isinstance(event.get("session_id"), str) or event.get("placement_digest") != state.get("placement_digest"): return {"accepted": False, "reason_code": "HOST_SESSION_BINDING_INVALID", "state": deepcopy(dict(state))}
        nxt["session_id"] = event["session_id"]
    elif kind == "HEARTBEAT":
        trusted = _mapping((_mapping(state.get("trusted_store")) or {}).get("verified_host_heartbeats")) or {}
        record = _mapping(trusted.get(event.get("heartbeat_evidence_ref"))) or {}
        unsigned = {key: value for key, value in record.items() if key != "record_digest"}
        if event.get("sequence") != state.get("heartbeat_sequence", 0) + 1 or event.get("epoch") != state.get("epoch") or any(record.get(key) != expected for key, expected in {"host_id": state.get("host_id"), "instance_id": state.get("instance_id"), "session_id": state.get("session_id"), "epoch": state.get("epoch"), "sequence": event.get("sequence")}.items()) or record.get("signature_verified") is not True or record.get("not_revoked") is not True or not record.get("verified_by") or record.get("record_digest") != canonical_digest(unsigned): return {"accepted": False, "reason_code": "HOST_HEARTBEAT_UNTRUSTED", "state": deepcopy(dict(state))}
        nxt["heartbeat_sequence"] = event["sequence"]
    elif kind == "CRASH": nxt["orphan_inventory"] = deepcopy(event.get("orphan_inventory", []))
    elif kind == "FENCE": nxt["epoch"] = state.get("epoch", 0) + 1
    elif kind == "RECOVER_ORPHAN":
        trusted = _mapping((_mapping(state.get("trusted_store")) or {}).get("verified_host_recoveries")) or {}
        record = _mapping(trusted.get(event.get("recovery_evidence_ref"))) or {}
        unsigned = {key: value for key, value in record.items() if key != "record_digest"}
        expected = {"host_id": state.get("host_id"), "instance_id": state.get("instance_id"), "session_id": state.get("session_id"), "fencing_epoch": state.get("epoch"), "orphan_inventory_digest": canonical_digest(state.get("orphan_inventory", [])), "recovered_ids_digest": canonical_digest(event.get("recovered_ids", []))}
        if event.get("fencing_epoch") != state.get("epoch") or set(event.get("recovered_ids", [])) != set(state.get("orphan_inventory", [])) or any(record.get(key) != value for key, value in expected.items()) or record.get("cleanup_verified") is not True or not _valid_digest(record.get("absence_proof_digest")) or record.get("stale_writers_absent") is not True or record.get("residue_absent") is not True or record.get("signature_verified") is not True or record.get("not_revoked") is not True or not record.get("verified_by") or record.get("record_digest") != canonical_digest(unsigned): return {"accepted": False, "reason_code": "HOST_ORPHAN_RECOVERY_UNTRUSTED", "state": deepcopy(dict(state))}
        nxt["orphan_inventory"] = []
    nxt["phase"] = target
    return {"accepted": True, "reason_code": "HOST_TRANSITION_ACCEPTED", "state": nxt}
