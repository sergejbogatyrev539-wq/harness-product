#!/usr/bin/env python3
"""Deterministic checks for the specification model (runtime remains absent)."""

from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
from importlib import metadata, util
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

from jsonschema import Draft202012Validator

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
TESTS, SCHEMAS, EXAMPLES = ROOT / "tests", ROOT / "schemas", ROOT / "examples"
CLI = Path("/usr/bin/jsonschema")
EXPECTED_SCHEMAS = {
    "admission-candidate.schema.json", "capability.schema.json", "decision-result.schema.json",
    "effect-manifest.schema.json", "effect-ontology.schema.json", "effect-receipt.schema.json",
    "event-envelope.schema.json", "evidence-plan-and-attestation.schema.json",
    "human-approval-receipt.schema.json", "isolation-profile.schema.json",
    "loop-contract.schema.json", "runtime-policy.schema.json",
}
EXECUTED_TEST_IDS: set[str] = set()
EXECUTED_ASSERTION_INSTANCES: list[str] = []
IPC_FIXTURES: dict[str, dict] = {}
NORMATIVE_REQUIREMENT_SOURCES = (
    ("L0", "10_LEVEL0_PHYSICAL_ISOLATION.md"),
    ("L1", "11_LEVEL1_EFFECT_SYSTEM.md"),
    ("L2", "12_LEVEL2_EFFECT_MANIFEST.md"),
    ("L3", "13_LEVEL3_RUNTIME_POLICY.md"),
    ("L4", "14_LEVEL4_OBSERVABILITY_RESPONSE.md"),
    ("L5", "15_LEVEL5_HUMAN_CONTROL.md"),
)
CANONICAL_STATUS = {
    "specification": "SPECIFIED",
    "runtime": "NOT_IMPLEMENTED",
    "evidence": "SPECIFICATION_MODEL_TESTED",
    "runtime_attestation": "NOT_ATTESTED",
    "overall": "NOT_READY",
    "scope": "FORMAL_SPECIFICATION_AND_PURE_REFERENCE_MODEL_ONLY",
}
STATUS_ARTIFACTS = (
    "03_SYSTEM_THREAT_TRUST_MODEL.md",
    "04_FORMAL_CORE_AND_INVARIANTS.md",
    "10_LEVEL0_PHYSICAL_ISOLATION.md",
    "11_LEVEL1_EFFECT_SYSTEM.md",
    "12_LEVEL2_EFFECT_MANIFEST.md",
    "13_LEVEL3_RUNTIME_POLICY.md",
    "14_LEVEL4_OBSERVABILITY_RESPONSE.md",
    "15_LEVEL5_HUMAN_CONTROL.md",
    "18_IMPLEMENTATION_ROADMAP_AND_ASSURANCE_CASE.md",
)
STATUS_REFERENCE = "invariant-traceability.json#/status"
STATUS_PROJECTION_ARTIFACTS = ("tests/policy-test-vectors.json",)
CANONICAL_INVARIANT_CLAIMS = {
    "INV-001": "STOPPED — единственное fail-closed default. Любое missing/invalid state не даёт execution.",
    "INV-002": "Agent/model не является ambient authority holder или внешним executor; credentials и live sink authority не наследуются.",
    "INV-003": "Каждый side effect проходит через non-bypassable mediation и authoritative event.",
    "INV-004": "Capability exact-bound, single-use, nonreplayable, nontransferable, short-lived и привязан к principal, audience, purpose, operation/request, contract, manifest, policy, nonce, epoch и lineage.",
    "INV-005": "committed ⊆ authorized ⊆ manifested ⊓ physical. Attempted может выйти за ceiling только как заблокированная и зарегистрированная попытка.",
    "INV-006": "Policy lower layers и human approval только сужают authority. Delegation child envelope — attenuated subset; authority join не используется для выдачи прав.",
    "INV-007": "Для delegation tree: spent_parent + Σ(reserved_child + spent_child) ≤ parent_limit; partitions/reservations atomic и linear.",
    "INV-008": "Cumulative counters/budgets монотонны, durable, crash-safe; restart/retry/nested contract/branch не сбрасывает их. D2-PROVISIONAL соблюдается.",
    "INV-009": "Material change prompt/context/model/tool/adapter/manifest/policy/contract/target invalidates связанный receipt/capability.",
    "INV-010": "Незаявленное persistent state не переносится между итерациями; разрешённая память versioned, scoped, labelled, taint-tracked и audited. N→N+1 — явный flow.",
    "INV-011": "Evidence/observability не создают authority. Safety events исходят от authoritative components; missing/corrupt mandatory telemetry/evidence для risk action — failure.",
    "INV-012": "Seal требует quiescence и исключения concurrent writers; postcheck и commit относятся к одному immutable digest.",
    "INV-013": "Confidentiality, integrity, provenance, taint, purpose и retention распространяются по data/control dependencies. Hash/schema/summary не declassify и не endorse. Эти два перехода требуют разных capabilities.",
    "INV-014": "Recovery, rollback и compensation — effectful операции с новыми manifest/policy/budget/capability. UNKNOWN_OUTCOME не auto-retry.",
    "INV-015": "unknown/unclassified/unbounded/missing/stale/mismatched никогда не становится implicit allow; unbounded не approvable.",
}


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def fail(message: str) -> None:
    raise AssertionError(message)


def assertion(test_id: str, condition: bool, message: str = "") -> None:
    EXECUTED_TEST_IDS.add(test_id)
    EXECUTED_ASSERTION_INSTANCES.append(f"{test_id}#{len(EXECUTED_ASSERTION_INSTANCES) + 1}")
    if not condition:
        fail(f"{test_id}: {message or 'assertion failed'}")


def object_boundaries_are_strict(node, path: str = "$") -> list[str]:
    missing: list[str] = []
    if isinstance(node, dict):
        is_match_fragment = any(segment in path for segment in ("/if", "/then", "/contains"))
        if node.get("type") == "object" and node.get("additionalProperties") is not False and not is_match_fragment:
            missing.append(path)
        for key, value in node.items():
            missing.extend(object_boundaries_are_strict(value, f"{path}/{key}"))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            missing.extend(object_boundaries_are_strict(value, f"{path}/{index}"))
    return missing


def apply_pointer(document, pointer: str, value) -> None:
    parts = [part.replace("~1", "/").replace("~0", "~") for part in pointer[1:].split("/")]
    current = document
    for part in parts[:-1]: current = current[int(part)] if isinstance(current, list) else current[part]
    if isinstance(current, list): current[int(parts[-1])] = value
    else: current[parts[-1]] = value


def schema_validator(name: str) -> Draft202012Validator:
    return Draft202012Validator(load(SCHEMAS / name), format_checker=Draft202012Validator.FORMAT_CHECKER)


def schema_valid(name: str, instance) -> bool:
    return not list(schema_validator(name).iter_errors(instance))


def check_schemas() -> int:
    actual = {path.name for path in SCHEMAS.glob("*.schema.json")}
    assertion("T-SCHEMA-INVENTORY", actual == EXPECTED_SCHEMAS, f"expected={sorted(EXPECTED_SCHEMAS)} actual={sorted(actual)}")
    for name in sorted(actual):
        schema = load(SCHEMAS / name)
        Draft202012Validator.check_schema(schema)
        assertion(f"T-SCHEMA-STRICT-{name}", schema.get("$schema") == "https://json-schema.org/draft/2020-12/schema" and not object_boundaries_are_strict(schema), name)
        refs: list[str] = []
        def collect(node):
            if isinstance(node, dict):
                if isinstance(node.get("$ref"), str): refs.append(node["$ref"])
                for child in node.values(): collect(child)
            elif isinstance(node, list):
                for child in node: collect(child)
        collect(schema)
        assertion(f"T-SCHEMA-LOCALREF-{name}", all(ref.startswith("#/") for ref in refs), str(refs))
    return len(actual)


def check_examples() -> tuple[int, int]:
    index = load(TESTS / "example-expectations.json")
    schema_path, validator = (TESTS / index["schema"]).resolve(), schema_validator("effect-manifest.schema.json")
    valid_count = invalid_count = 0
    for case in index["valid"]:
        instance, path = load((TESTS / case["path"]).resolve()), (TESTS / case["path"]).resolve()
        assertion(case["id"], not list(validator.iter_errors(instance)), "valid manifest rejected")
        result = subprocess.run([str(CLI), "-i", str(path), str(schema_path)], cwd=ROOT, text=True, capture_output=True, check=False)
        assertion(case["id"] + "-CLI", result.returncode == 0, result.stdout + result.stderr)
        valid_count += 1
    for case in index["invalid"]:
        fixture_path = (TESTS / case["fixture"]).resolve(); fixture = load(fixture_path)
        instance = deepcopy(load((fixture_path.parent / fixture["base"]).resolve()))
        apply_pointer(instance, fixture["mutation"]["pointer"], fixture["mutation"]["value"])
        errors = list(validator.iter_errors(instance)); messages = "\n".join(error.message for error in errors)
        assertion(case["id"], bool(errors) and fixture["expected_error_fragment"] in messages, messages)
        with tempfile.NamedTemporaryFile("w", suffix=".json", encoding="utf-8") as handle:
            json.dump(instance, handle); handle.flush()
            result = subprocess.run([str(CLI), "-i", handle.name, str(schema_path)], cwd=ROOT, text=True, capture_output=True, check=False)
            assertion(case["id"] + "-CLI", result.returncode != 0, "CLI accepted invalid fixture")
        invalid_count += 1
    return valid_count, invalid_count


def load_reference():
    spec = util.spec_from_file_location("policy_reference", TESTS / "policy-reference.py")
    module = util.module_from_spec(spec); assert spec and spec.loader; spec.loader.exec_module(module)
    return module


def digest(char: str) -> str:
    return "sha256:" + char * 64


def canonical_digest_for_test(value) -> str:
    return "sha256:" + sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()


def refresh_ipc_digest(ipc: dict) -> None:
    digest_value = canonical_digest_for_test({key: value for key, value in ipc.items() if key not in {"attestation_digest", "signature"}})
    ipc["attestation_digest"] = ipc["signature"]["payload_digest"] = digest_value


def ipc_verifier_record(ipc: dict) -> dict:
    payload = {key: deepcopy(value) for key, value in ipc.items() if key not in {"attestation_digest", "signature"}}
    return {"attestation_digest": ipc["attestation_digest"], "isolation_profile_digest": ipc["isolation_profile_digest"], "broker_ipc_binding_digest": ipc["broker_ipc_binding_digest"], "signed_payload": payload, "signed_payload_digest": canonical_digest_for_test(payload), "trust_root": "trust:root", "key_id": ipc["signature"]["key_id"], "algorithm": ipc["signature"]["algorithm"], "verified_by": ipc["signature"]["verified_by"], "signature_verified": True, "freshness_verified": True, "revocation_checked": True, "not_revoked": True, "current_key": True}


def authority_constraints() -> dict:
    return {
        "direction": "OUT",
        "data_label": {"confidentiality": "INTERNAL", "integrity": "USER_ASSERTED", "provenance": ["urn:request:write-file"], "taints": ["USER_INPUT"], "purposes": ["TASK"], "retention": "CONTRACT"},
        "temporal": {"max_duration_ms": 5000, "not_before": "2026-08-24T00:00:00Z", "not_after": "2026-08-25T00:00:00Z"},
        "quantity": {"unit": "BYTES", "limit": 1024},
        "max_concurrency": 1,
        "flows": [],
        "obligations": ["postcheck.run"],
    }


def make_policy(reference, descriptor_binding_digest: str, physical_target_digest: str) -> dict:
    layers = []
    for name, char in zip(("PHYSICAL", "PLATFORM", "PROJECT", "CONTRACT", "SESSION", "CALL"), "123456"):
        layers.append({"layer": name, "digest": digest(char), "mode": "NARROW_ONLY"})
    policy = {
        "schema_version": "1.0.0", "policy_id": "policy:workspace", "policy_version": "1.0.0", "policy_digest": digest("c"),
        "status": "ACTIVE", "environment": "TEST", "owner": "team:runtime", "enforcement_point": "BROKER_PEP",
        "physical_ceiling": {"isolation_profile_id": "isolation:workspace", "isolation_profile_digest": digest("f"), "agent_effects": ["COMPUTE", "OBSERVE"], "mediated_sink_effects": ["COMPUTE", "OBSERVE", "MUTATE"], "agent_ambient_authority": False},
        "hierarchy": layers,
        "authority_map": [{"operation_id": "write-file", "correlation_id": "alt:write", "effect": "MUTATE", "resource_kind": "FILE", "operations": ["CREATE", "WRITE"], "scope": {"kind": "PATH", "values": ["/workspace/output"], "descriptor_binding_digest": descriptor_binding_digest, "physical_target_digest": physical_target_digest}, "facets": ["EXECUTE_EFFECT"], "authority_constraints_digest": canonical_digest_for_test(authority_constraints()), "flows": [], "budget_names": ["CALLS", "WRITE_BYTES"], "obligations": ["postcheck.run", "seal.quiescent"], "approval_class": "NONE"}],
        "deny_rules": [{"rule_id": "DENY-001", "condition": "UNKNOWN", "outcome": "STOP", "reason_code": "UNKNOWN_FAIL_CLOSED"}], "human_rules": [],
        "budgets": [{"name": "CALLS", "unit": "CALLS", "limit": 1, "scope": "CALL", "reset": "NEVER", "scope_digest": digest("1"), "lineage_root": "lineage:root"}, {"name": "WRITE_BYTES", "unit": "BYTES", "limit": 65536, "scope": "CALL", "reset": "NEVER", "scope_digest": digest("2"), "lineage_root": "lineage:root"}],
        "information_flow": {"propagate_data_dependencies": True, "propagate_control_dependencies": True, "hash_declassifies": False, "schema_validation_endorses": False, "declassification_capability_required": True, "endorsement_capability_required": True, "external_model_is_sink": True},
        "registry_snapshot": {"digest": digest("e"), "generation": 7, "rollback_floor": 7, "dynamic_updates": False, "revocation_epoch": 3},
        "transaction_semantics": {"default_state": "STOPPED", "deny_overrides": True, "unknown_result": "STOP", "durable_atomic_fields": ["CAPABILITY_CONSUMPTION", "BUDGET_RESERVATION", "DISPATCH_INTENT", "MONOTONIC_COUNTER", "FENCING_EPOCH"], "unknown_external_outcome": "QUARANTINED_RECONCILING", "automatic_retry_unknown_external": False, "compensation": "NEW_AUTHORIZED_TRANSACTION", "single_writer_fencing": True, "d2_bound": "NO_CONTROLLER_VISIBLE_N_PLUS_2_BEFORE_JOIN_N_PLUS_1"},
    }
    control_digest = reference._control_content_digest(policy, "policy_digest", "policy_activation")
    policy["policy_digest"] = control_digest
    policy["policy_activation"] = {"content_digest": control_digest, "generation": 7, "rollback_floor": 7, "registry_reference": "registry:policy", "issued_at": "2026-08-24T00:00:00Z", "expires_at": "2026-08-25T00:00:00Z", "signature": digest("c"), "external_verification": True}
    return policy


def make_isolation(reference) -> dict:
    roles = [
        {"principal": "agent:worker", "role": "AGENT_WORKER", "ambient_authority": False, "network_mode": "DISCONNECTED", "credential_mode": "NONE", "effect_ceiling": ["COMPUTE", "OBSERVE"]},
        {"principal": "broker:pep", "role": "BROKER", "ambient_authority": False, "network_mode": "BROKER_MEDIATED", "credential_mode": "REFERENCE_ONLY", "effect_ceiling": ["MUTATE", "COMMUNICATE", "DELEGATE", "REFLECT"]},
        {"principal": "executor:workspace", "role": "EXECUTOR", "ambient_authority": False, "network_mode": "NONE", "credential_mode": "EXECUTOR_SCOPED", "effect_ceiling": ["MUTATE"]},
        {"principal": "gateway:model", "role": "MODEL_GATEWAY", "ambient_authority": False, "network_mode": "EXACT_ENDPOINTS", "credential_mode": "EXECUTOR_SCOPED", "effect_ceiling": ["COMMUNICATE"]},
        {"principal": "observer:runtime", "role": "OBSERVER", "ambient_authority": False, "network_mode": "NONE", "credential_mode": "NONE", "effect_ceiling": ["OBSERVE"]},
    ]
    for index, role in enumerate(roles):
        role["os_subject"] = {"process_id": f"process:{index}", "uid": 1000 + index, "gid": 1000 + index, "mount_namespace": f"mnt:{index}", "pid_namespace": f"pid:{index}", "network_namespace": f"net:{index}", "security_label": f"label:{index}", "credential_namespace": f"cred:{index}", "session_id": f"role-session:{index}", "ipc_endpoint": f"ipc:{index}", "inherited_fd_digest": digest(str(index))}
    ipc = {"worker_principal": roles[0]["principal"], "broker_principal": roles[1]["principal"], "worker_endpoint": roles[0]["os_subject"]["ipc_endpoint"], "broker_endpoint": roles[1]["os_subject"]["ipc_endpoint"], "transport": "UNIX_SEQPACKET", "endpoint_mode": "UNIX_CONNECTED_PAIR", "fd_delivery": "SUPERVISOR_TYPED_ALLOWLIST", "sender_authentication": "SCM_CREDENTIALS_PLUS_ENDPOINT_HOLDER_ATTESTATION", "worker_network_namespace": roles[0]["os_subject"]["network_namespace"], "broker_network_namespace": roles[1]["os_subject"]["network_namespace"], "binding_digest": digest("0")}
    ipc["binding_digest"] = canonical_digest_for_test({key: value for key, value in ipc.items() if key != "binding_digest"})
    unit = {"CPU_TIME": "MILLISECONDS", "CPU_RATE": "MILLICORES", "WALL_TIME": "MILLISECONDS", "MEMORY": "MIB", "SWAP": "MIB", "PIDS": "COUNT", "BLOCK_IO_READ": "IOPS", "BLOCK_IO_WRITE": "IOPS", "FILES": "COUNT", "INODES": "COUNT", "OPEN_FDS": "COUNT", "OUTPUT_BYTES": "BYTES", "GPU_TIME": "MILLISECONDS", "GPU_MEMORY": "MIB"}
    enforcement = {name: ("CGROUP_V2" if name in {"CPU_TIME", "CPU_RATE", "MEMORY", "SWAP", "PIDS"} else "SUPERVISOR") for name in unit}
    enforcement.update({"FILES": "FILESYSTEM_QUOTA", "INODES": "FILESYSTEM_QUOTA", "OPEN_FDS": "RLIMIT", "OUTPUT_BYTES": "FILESYSTEM_QUOTA", "BLOCK_IO_READ": "DEVICE_SCHEDULER", "BLOCK_IO_WRITE": "DEVICE_SCHEDULER", "GPU_TIME": "DEVICE_SCHEDULER", "GPU_MEMORY": "DEVICE_SCHEDULER"})
    target = {"canonical_path": "/workspace/output/report.txt", "descriptor_id": "fd:output", "root_id": "root:output", "root_identity": "root:output", "mount_id": "mount:workspace", "mount_identity": "mount:workspace", "resolution_epoch": 3, "final_object_id": "object:report", "final_object_digest": digest("a"), "composite_binding_digest": digest("0"), "verified_by": "verifier:filesystem", "key_id": "key:filesystem", "trust_root": "trust:root", "algorithm": "ED25519", "signature": "F" * 64, "signature_verified": True, "not_revoked": True}
    target["composite_binding_digest"] = canonical_digest_for_test({key: value for key, value in target.items() if key != "composite_binding_digest"})
    profile = {
        "schema_version": "1.0.0", "profile_id": "isolation:workspace", "profile_version": "1.0.0", "profile_digest": digest("f"), "risk_class": "LOCAL_STAGEABLE", "status": "ACTIVE", "owner": "team:runtime", "principal_envelopes": roles,
        "compiled_envelopes": [{"principal": "broker:pep", "audience": "executor:workspace", "allowed_effects": ["MUTATE"], "allowed_resource_kinds": ["FILE"], "allowed_operations": ["WRITE", "CREATE"], "allowed_scopes": ["/workspace/output/report.txt"], "filesystem_targets": [deepcopy(target)], "effect_resource_operations": [{"effect": "MUTATE", "resource_kind": "FILE", "operation": "WRITE"}, {"effect": "MUTATE", "resource_kind": "FILE", "operation": "CREATE"}]}, {"principal": "executor:workspace", "audience": "executor:workspace", "allowed_effects": ["MUTATE"], "allowed_resource_kinds": ["FILE"], "allowed_operations": ["WRITE", "CREATE"], "allowed_scopes": ["/workspace/output/report.txt"], "filesystem_targets": [deepcopy(target)], "effect_resource_operations": [{"effect": "MUTATE", "resource_kind": "FILE", "operation": "WRITE"}, {"effect": "MUTATE", "resource_kind": "FILE", "operation": "CREATE"}]}],
        "filesystem": {"rootfs_read_only": True, "host_checkout_mounted": False, "git_visible": False, "inputs": "READ_ONLY", "outputs": "WRITE_ONLY_STAGING", "path_resolution": "OPENAT2_BENEATH_NO_MAGICLINKS", "private_mounts": True, "tmpfs_quota_bytes": 1048576, "inode_limit": 1024}, "broker_ipc_binding": ipc,
        "network": {"worker_default": "DISCONNECTED", "loopback": "DISABLED", "ipv4": "DISABLED", "ipv6": "DISABLED", "dns": "DISABLED", "unix_sockets": "BROKER_CONNECTED_PAIR_ONLY", "metadata_service": "BLOCKED", "connected_fd_policy": "EXACT_OPERATION_SCOPED_PAIR_ONLY", "external_sink_fds": "NONE", "inherited_fds_closed": True},
        "process": {"namespaces": ["USER", "MOUNT", "PID", "IPC", "UTS", "NETWORK", "CGROUP"], "rootless_user_mapping": True, "no_new_privileges": True, "linux_capabilities": [], "seccomp": "ALLOWLIST", "lsm": "LANDLOCK", "proc_mode": "PRIVATE_RESTRICTED", "ptrace": "DENIED", "devices": "EXACT_ALLOWLIST", "ebpf": "DENIED", "kill_process_tree": True},
        "resources": [{"resource": name, "unit": unit[name], "limit": 1, "enforcement": enforcement[name]} for name in unit],
        "credentials": {"agent_ambient_credentials": False, "secret_resolution": "NONE", "secret_bytes_visible_to_agent": False},
        "supply_chain": {"image_digest": digest("1"), "runtime_digest": digest("2"), "signed_artifacts": True, "registry_snapshot_digest": digest("e"), "composite_measurement_digest": digest("3"), "trusted_roots_digest": digest("4"), "revocation_epoch": 3, "registry_generation": 7, "rollback_floor": 7, "exact_byte_binding": True},
        "seal_and_cleanup": {"freeze_before_snapshot": True, "writers_revoked_before_seal": True, "immutable_snapshot": True, "cleanup_verified": True, "wildcard_cleanup_is_control": False},
        "attestation": {"placement_required": True, "session_receipt_required": True, "independent_verification_required": True},
        "residual_risks": [{"id": "RR-001", "category": "SHARED_KERNEL", "claim": "Specification cannot prove host kernel separation.", "disposition": "ACCEPTANCE_REQUIRED"}],
        "risk_disposition_evidence": [],
    }
    risk = profile["residual_risks"][0]
    evidence = {"evidence_id": "risk-evidence:rr-001", "risk_id": risk["id"], "disposition": risk["disposition"], "evidence_type": "ACCEPTANCE_RECORD", "disposition_payload": {"acceptance_record_id": "acceptance:rr-001"}, "profile_id": profile["profile_id"], "profile_digest": profile["profile_digest"], "scope_digest": canonical_digest_for_test({"profile_id": profile["profile_id"], "profile_version": profile["profile_version"], "risk_id": risk["id"], "category": risk["category"], "claim": risk["claim"]}), "authorized_risk_owner": "team:runtime", "rationale": "Host kernel separation remains a documented residual risk.", "compensating_controls": ["control:independent-attestation", "control:fail-closed-placement"], "issued_at": "2026-08-24T00:00:00Z", "expires_at": "2026-08-25T00:00:00Z", "review_at": "2026-08-24T12:00:00Z", "signed_payload": {}, "external_verification": {"trusted_reference": "risk-verification:rr-001", "verified_by": "verifier:risk", "signature_verified": True, "not_revoked": True, "verified_at": "2026-08-24T00:00:01Z"}}
    signed_payload = {key: value for key, value in evidence.items() if key not in {"signed_payload", "external_verification"}}
    evidence["signed_payload"] = {"payload_digest": canonical_digest_for_test(signed_payload), "key_id": "key:risk", "algorithm": "ED25519", "signature": "R" * 64}
    profile["risk_disposition_evidence"].append(evidence)
    control_digest = reference._control_content_digest(profile, "profile_digest", "profile_activation")
    profile["profile_digest"] = evidence["profile_digest"] = control_digest
    signed_payload = {key: value for key, value in evidence.items() if key not in {"signed_payload", "external_verification"}}
    evidence["signed_payload"]["payload_digest"] = canonical_digest_for_test(signed_payload)
    profile["profile_activation"] = {"content_digest": control_digest, "generation": 7, "rollback_floor": 7, "registry_reference": "registry:profile", "issued_at": "2026-08-24T00:00:00Z", "expires_at": "2026-08-25T00:00:00Z", "signature": digest("f"), "external_verification": True}
    return profile


def make_candidate(reference, manifest: dict, policy: dict, isolation: dict) -> dict:
    components = [{"component": name, "exact_bytes_digest": digest(str(index % 10)), "provenance_digest": digest(str((index + 1) % 10)), "signature_verified": True, "trust_root_id": "trust:root", "revocation_epoch": 3, "registry_generation": 7, "rollback_floor": 7} for index, name in enumerate(sorted(reference.COMPONENT_CLASSES))]
    trusted_roots_digest = isolation["supply_chain"]["trusted_roots_digest"]
    supply_digest = reference.canonical_digest({"trusted_roots_digest": trusted_roots_digest, "components": components})
    isolation["supply_chain"]["composite_measurement_digest"] = supply_digest
    control_digest = reference._control_content_digest(isolation, "profile_digest", "profile_activation")
    isolation["profile_digest"] = control_digest
    isolation["profile_activation"]["content_digest"] = control_digest
    for evidence in isolation["risk_disposition_evidence"]:
        evidence["profile_digest"] = control_digest
        evidence["signed_payload"]["payload_digest"] = canonical_digest_for_test({key: value for key, value in evidence.items() if key not in {"signed_payload", "external_verification"}})
    placement = {"attestation_digest": digest("7"), "subject_instance_id": "instance:one", "host_id": "host:one", "isolation_profile_digest": isolation["profile_digest"], "measurement_digest": supply_digest, "nonce": "placement_nonce_1234567890", "epoch": 3, "issued_at": "2026-08-24T00:00:00Z", "expires_at": "2026-08-24T00:10:00Z", "signature": {"key_id": "key:placement", "algorithm": "ED25519", "payload_digest": digest("7"), "verified_by": "verifier:placement"}}
    session = {"attestation_digest": digest("8"), "session_id": "session:one", "subject_instance_id": "instance:one", "placement_attestation_digest": digest("7"), "measurement_digest": supply_digest, "contract_digest": digest("d"), "nonce": "session_nonce_123456789012", "epoch": 3, "issued_at": "2026-08-24T00:00:00Z", "expires_at": "2026-08-24T00:10:00Z", "signature": {"key_id": "key:session", "algorithm": "ED25519", "payload_digest": digest("8"), "verified_by": "verifier:session"}}
    worker, broker = isolation["principal_envelopes"][0], isolation["principal_envelopes"][1]
    worker_endpoint = {"device_id": "device:ipc", "inode": 7, "cookie": 701}
    broker_endpoint = {"device_id": "device:ipc", "inode": 8, "cookie": 702}
    socket_identity = {"kind": "UNIX_CONNECTED_PAIR", "worker_endpoint": worker_endpoint, "broker_endpoint": broker_endpoint, "pair_binding_digest": canonical_digest_for_test({"worker_endpoint": worker_endpoint, "broker_endpoint": broker_endpoint})}
    ipc = {"attestation_digest": digest("9"), "isolation_profile_digest": isolation["profile_digest"], "broker_ipc_binding_digest": isolation["broker_ipc_binding"]["binding_digest"], "runtime_session_id": session["session_id"], "worker_principal": worker["principal"], "broker_principal": broker["principal"], "worker_subject": deepcopy(worker["os_subject"]), "broker_subject": deepcopy(broker["os_subject"]), "socket_identity": socket_identity, "worker_fd": 3, "broker_fd": 3, "worker_fd_allowlist_digest": digest("1"), "broker_fd_allowlist_digest": digest("2"), "worker_endpoint_holder": {key: worker["os_subject"][key] for key in ("process_id", "uid", "gid", "session_id")}, "broker_endpoint_holder": {key: broker["os_subject"][key] for key in ("process_id", "uid", "gid", "session_id")}, "broker_observed_sender": {key: worker["os_subject"][key] for key in ("process_id", "uid", "gid", "session_id")}, "sender_authentication": "SCM_CREDENTIALS_PLUS_ENDPOINT_HOLDER_ATTESTATION", "transport": "UNIX_SEQPACKET", "message_schema_digest": digest("3"), "operation_id": "write-file", "nonce": "broker_ipc_nonce_123456789", "session_fencing_epoch": 3, "issued_at": "2026-08-24T00:00:00Z", "expires_at": "2026-08-24T00:10:00Z", "revocation_epoch": 3, "signature": {"key_id": "key:broker-ipc", "algorithm": "ED25519", "payload_digest": digest("4"), "verified_by": "verifier:broker-ipc"}}
    refresh_ipc_digest(ipc)
    target = isolation["compiled_envelopes"][0]["filesystem_targets"][0]
    descriptor_binding_digest = reference.canonical_digest({"descriptor_id": target["descriptor_id"], "root_identity": target["root_identity"], "mount_identity": target["mount_identity"], "epoch": target["resolution_epoch"]})
    selector = {"kind": "PATH_DESCRIPTOR", "descriptor_id": target["descriptor_id"], "canonical_path": target["canonical_path"], "resolution": "DESCRIPTOR_PROVEN_BENEATH_NO_MAGICLINKS", "descriptor_binding_digest": descriptor_binding_digest, "physical_target_digest": target["composite_binding_digest"]}
    candidate = {
        "schema_version": "1.0.0", "request_id": "request:write-report", "request_digest": digest("a"), "evaluated_at": "2026-08-24T00:00:05Z", "principal": "broker:pep", "audience": "executor:workspace", "purpose": "TASK", "operation_id": "write-file",
        "bindings": {"manifest_digest": reference.canonical_digest(manifest), "policy_digest": policy["policy_digest"], "contract_id": "contract:write", "contract_digest": digest("d"), "registry_digest": policy["registry_snapshot"]["digest"], "isolation_profile_digest": isolation["profile_digest"], "placement_attestation_digest": placement["attestation_digest"], "session_attestation_digest": session["attestation_digest"], "broker_ipc_attestation_digest": ipc["attestation_digest"], "broker_ipc_binding_digest": ipc["broker_ipc_binding_digest"], "resource_vector_digest": reference.canonical_digest(isolation["resources"]), "supply_chain_measurement_digest": supply_digest},
        "authority_alternatives": [
            {"alternative_id": "alt:write", "entries": [{"entry_id": "auth:create", "effect": "MUTATE", "resource_kind": "FILE", "operation": "CREATE", "selector": deepcopy(selector), "facets": ["EXECUTE_EFFECT"], "constraints": authority_constraints()}, {"entry_id": "auth:write", "effect": "MUTATE", "resource_kind": "FILE", "operation": "WRITE", "selector": deepcopy(selector), "facets": ["EXECUTE_EFFECT"], "constraints": authority_constraints()}]},
            {"alternative_id": "alt:other", "entries": [{"entry_id": "auth:other-create", "effect": "MUTATE", "resource_kind": "FILE", "operation": "CREATE", "selector": {**deepcopy(selector), "descriptor_id": "fd:output2", "canonical_path": "/workspace/output/other.txt"}, "facets": ["EXECUTE_EFFECT"], "constraints": authority_constraints()}, {"entry_id": "auth:other", "effect": "MUTATE", "resource_kind": "FILE", "operation": "WRITE", "selector": {**deepcopy(selector), "descriptor_id": "fd:output2", "canonical_path": "/workspace/output/other.txt"}, "facets": ["EXECUTE_EFFECT"], "constraints": authority_constraints()}]},
        ],
        "selected_alternative_id": "alt:write", "budget_demands": [{"name": "CALLS", "unit": "CALLS", "amount": 1, "scope_digest": digest("1"), "lineage_root": "lineage:root"}, {"name": "WRITE_BYTES", "unit": "BYTES", "amount": 1024, "scope_digest": digest("2"), "lineage_root": "lineage:root"}], "iteration": 1,
        "d2_frontier": {"definition_status": "PROVISIONAL_OPERATIONAL", "contract_digest": digest("d"), "contract_version": "1.0.0", "authority_domain_id": "authority-domain:workspace", "journal_lineage_id": "journal:contract.write", "root_contract_digest": digest("d"), "parent_contract_digest": None, "journal_sequence": 0, "fencing_epoch": 3, "frontier_record_digest": digest("0"), "joined_iteration": 0, "max_iteration": 4, "durable_state_digest": reference.canonical_digest([{"artifact_id": "artifact:iteration1", "class": "PLAN", "iteration": 1, "controller_visible": True, "persisted": False, "staged": False, "tool_bound": False, "budgeted": False, "reusable": False}]), "inventory": [{"artifact_id": "artifact:iteration1", "class": "PLAN", "iteration": 1, "controller_visible": True, "persisted": False, "staged": False, "tool_bound": False, "budgeted": False, "reusable": False}]},
        "placement_attestation": placement, "session_attestation": session, "broker_ipc_attestation": ipc,
        "supply_chain": {"composite_measurement_digest": supply_digest, "components": components, "trusted_roots_digest": trusted_roots_digest, "required_revocation_epoch": 3, "required_rollback_floor": 7, "verified_at": "2026-08-24T00:00:04Z"}, "approval_receipt": None,
    }
    candidate["bindings"]["descriptor_binding_digest"] = descriptor_binding_digest
    candidate["d2_frontier"]["frontier_record_digest"] = reference.canonical_digest({key: value for key, value in candidate["d2_frontier"].items() if key != "frontier_record_digest"})
    slot = {"slot_id": "slot:write.iteration.1", "slot_key_digest": digest("0"), "authority_domain_id": candidate["d2_frontier"]["authority_domain_id"], "root_contract_digest": candidate["d2_frontier"]["root_contract_digest"], "journal_lineage_id": candidate["d2_frontier"]["journal_lineage_id"], "iteration": candidate["iteration"], "owner_request_digest": candidate["request_digest"], "fencing_epoch": candidate["d2_frontier"]["fencing_epoch"], "state": "CLAIMED", "claimed_at": "2026-08-24T00:00:04Z", "expires_at": "2026-08-24T00:10:00Z", "slot_record_digest": digest("0")}
    slot["slot_key_digest"] = reference.canonical_digest({key: slot[key] for key in ("authority_domain_id", "root_contract_digest", "journal_lineage_id", "iteration")})
    slot["slot_record_digest"] = reference.canonical_digest({key: value for key, value in slot.items() if key != "slot_record_digest"})
    candidate["iteration_slot"] = slot
    return candidate


def make_loop_contract(reference, candidate: dict, manifest: dict, policy: dict, isolation: dict) -> dict:
    selector = candidate["authority_alternatives"][0]["entries"][0]["selector"]
    scope_value = selector.get("canonical_path") or selector.get("canonical_endpoint") or selector.get("canonical_value")
    scope_kind = "ENDPOINT" if selector.get("canonical_endpoint") else "PATH"
    effects = sorted({entry["effect"] for entry in candidate["authority_alternatives"][0]["entries"]})
    contract = {
        "schema_version": "1.0.0", "contract_id": "contract:write", "contract_version": 1, "contract_digest": digest("0"), "status": "ACTIVE", "principal": candidate["principal"], "audience": candidate["audience"],
        "authority_domain": {"domain_id": candidate["d2_frontier"]["authority_domain_id"], "definition_status": "PROVISIONAL", "journal_lineage_id": candidate["d2_frontier"]["journal_lineage_id"]},
        "allowed_effects": effects, "allowed_operations": [{"operation_id": candidate["operation_id"], "manifest_digest": candidate["bindings"]["manifest_digest"], "effects": effects, "scopes": [{"kind": scope_kind, "values": [scope_value]}], "approval_class": "NONE"}],
        "aggregate_budgets": [{"name": item["name"], "unit": item["unit"], "limit": item["amount"], "scope": "CONTRACT", "reset": "NEVER", "scope_digest": item["scope_digest"], "lineage_root": item["lineage_root"]} for item in candidate["budget_demands"]],
        "iteration_bound": {"max_iterations": 4, "counter_source": "CANONICAL_DURABLE_JOURNAL", "monotonic": True, "durable": True, "reset_on_restart": False, "reset_on_retry": False, "reset_on_nested_contract": False},
        "d2": {"definition_status": "PROVISIONAL", "operational_bound": "NO_CONTROLLER_VISIBLE_PERSISTED_STAGED_TOOL_BOUND_BUDGETED_REUSABLE_N_PLUS_2_BEFORE_JOIN_N_PLUS_1", "private_ephemeral_tokens_excluded": True},
        "artifact_bindings": {"policy_digest": candidate["bindings"]["policy_digest"], "registry_digest": candidate["bindings"]["registry_digest"], "isolation_profile_digest": candidate["bindings"]["isolation_profile_digest"], "prompt_digest": digest("1"), "context_digest": digest("2"), "model_digest": digest("3"), "toolset_digest": digest("4")},
        "postcheck": {"required_each_iteration": True, "plan_digest": digest("5"), "independent_observer": True, "failure_result": "STOPPED_NEW_TRANSACTION_REQUIRED"},
        "human_confirmation": {"mode": "NOT_REQUIRED", "receipt_digest": None, "machine_join_each_iteration": True, "may_expand_physical_ceiling": False},
        "lifecycle": {"issued_at": "2026-08-24T00:00:00Z", "not_before": "2026-08-24T00:00:00Z", "expires_at": "2026-08-25T00:00:00Z", "revocation_epoch": 3}, "material_change_invalidates": True,
    }
    contract["contract_digest"] = reference.canonical_digest({key: value for key, value in contract.items() if key != "contract_digest"})
    return contract


def make_fixture(reference):
    manifest, isolation = load(EXAMPLES / "valid/write-file.json"), make_isolation(reference)
    target = isolation["compiled_envelopes"][0]["filesystem_targets"][0]
    descriptor_binding_digest = reference.canonical_digest({"descriptor_id": target["descriptor_id"], "root_identity": target["root_identity"], "mount_identity": target["mount_identity"], "epoch": target["resolution_epoch"]})
    resource_selector = manifest["effect_bounds"][0]["resources"][0]["selector"]
    resource_selector.update(descriptor_binding_digest=descriptor_binding_digest, physical_target_digest=target["composite_binding_digest"])
    policy = make_policy(reference, descriptor_binding_digest, target["composite_binding_digest"])
    candidate = make_candidate(reference, manifest, policy, isolation)
    manifest["runtime_requirements"].update(isolation_profile_id=isolation["profile_id"], isolation_profile_digest=isolation["profile_digest"])
    candidate["bindings"]["manifest_digest"] = reference.canonical_digest(manifest)
    policy["physical_ceiling"].update(isolation_profile_id=isolation["profile_id"], isolation_profile_digest=isolation["profile_digest"])
    policy_digest = reference._control_content_digest(policy, "policy_digest", "policy_activation"); policy["policy_digest"] = policy["policy_activation"]["content_digest"] = policy_digest; candidate["bindings"]["policy_digest"] = policy_digest
    contract = make_loop_contract(reference, candidate, manifest, policy, isolation)
    candidate["bindings"]["contract_id"] = contract["contract_id"]
    candidate["bindings"]["contract_digest"] = contract["contract_digest"]
    candidate["session_attestation"]["contract_digest"] = contract["contract_digest"]
    candidate["d2_frontier"].update(contract_digest=contract["contract_digest"], root_contract_digest=contract["contract_digest"])
    candidate["d2_frontier"]["frontier_record_digest"] = reference.canonical_digest({key: value for key, value in candidate["d2_frontier"].items() if key != "frontier_record_digest"})
    slot = candidate["iteration_slot"]; slot["root_contract_digest"] = contract["contract_digest"]
    slot["slot_key_digest"] = reference.canonical_digest({key: slot[key] for key in ("authority_domain_id", "root_contract_digest", "journal_lineage_id", "iteration")})
    slot["slot_record_digest"] = reference.canonical_digest({key: value for key, value in slot.items() if key != "slot_record_digest"})
    evidence = isolation["risk_disposition_evidence"][0]
    facts = {"remaining_budgets": [{"name": "CALLS", "unit": "CALLS", "amount": 1, "scope_digest": digest("1"), "lineage_root": "lineage:root"}, {"name": "WRITE_BYTES", "unit": "BYTES", "amount": 65536, "scope_digest": digest("2"), "lineage_root": "lineage:root"}], "telemetry_ready": True, "d2_frontier_digest": candidate["d2_frontier"]["frontier_record_digest"], "required_d2_artifacts": [{"artifact_id": "artifact:iteration1", "class": "PLAN"}], "trusted_time": candidate["evaluated_at"], "current_revocation_epoch": 3, "current_fencing_epoch": 3, "expected_capability_issuer": "broker:reference", "verified_capability_claims": {}, "verified_approval_receipts": {}, "approval_challenges": {}, "consumed_approval_receipts": [], "revoked_capability_digests": [], "attested_executor_sessions": {"executor:workspace": candidate["session_attestation"]["session_id"]}, "verified_attestations": {candidate["placement_attestation"]["attestation_digest"]: {"issuer": "host:attester", "key_id": "key:placement", "trust_root": "trust:root", "signature_verified": True, "payload_digest": digest("7"), "subject": "instance:one", "session_id": "host-session:none", "placement_digest": digest("7"), "measurement_digest": candidate["placement_attestation"]["measurement_digest"], "freshness_verified": True, "revocation_checked": True}, candidate["session_attestation"]["attestation_digest"]: {"issuer": "host:attester", "key_id": "key:session", "trust_root": "trust:root", "signature_verified": True, "payload_digest": digest("8"), "subject": "instance:one", "session_id": "session:one", "placement_digest": digest("7"), "measurement_digest": candidate["session_attestation"]["measurement_digest"], "freshness_verified": True, "revocation_checked": True}}, "verified_risk_dispositions": {evidence["evidence_id"]: {"risk_id": evidence["risk_id"], "profile_id": evidence["profile_id"], "profile_digest": evidence["signed_payload"]["payload_digest"], "scope_digest": evidence["scope_digest"], "signed_payload_digest": evidence["signed_payload"]["payload_digest"], "verified_by": evidence["external_verification"]["verified_by"], "not_revoked": True, "revocation_checked": True}}}
    facts["trusted_roots_digest"] = isolation["supply_chain"]["trusted_roots_digest"]
    ipc = candidate["broker_ipc_attestation"]
    refresh_ipc_digest(ipc)
    facts["current_broker_ipc_nonce"] = ipc["nonce"]
    facts["verified_broker_ipc_attestations"] = {ipc["attestation_digest"]: ipc_verifier_record(ipc)}
    IPC_FIXTURES[ipc["attestation_digest"]] = deepcopy(ipc)
    for name, artifact, digest_field, activation_field in (("policy", policy, "policy_digest", "policy_activation"), ("profile", isolation, "profile_digest", "profile_activation")):
        activation = artifact[activation_field]
        facts[f"verified_{name}_activations"] = {artifact[digest_field]: {**activation, "signature_verified": True, "not_revoked": True, "freshness_verified": True, "revocation_checked": True, "verified_by": f"verifier:{name}"}}
    facts["verified_role_subjects"] = {role["principal"]: {**role["os_subject"], "profile_digest": isolation["profile_digest"], "signature_verified": True, "not_revoked": True, "verified_by": "verifier:role"} for role in isolation["principal_envelopes"]}
    facts["verified_risk_dispositions"][evidence["evidence_id"]].update(profile_digest=evidence["profile_digest"], evidence_type=evidence["evidence_type"], disposition_payload=deepcopy(evidence["disposition_payload"]))
    facts["authoritative_d2_frontier"] = {**deepcopy(candidate["d2_frontier"]), "signature_verified": True, "not_revoked": True, "freshness_verified": True, "verified_by": "verifier:d2-frontier"}
    facts["verified_supply_components"] = {item["component"]: {"component": item["component"], "component_digest": reference.canonical_digest(item), "exact_bytes_digest": item["exact_bytes_digest"], "provenance_digest": item["provenance_digest"], "registry_digest": isolation["supply_chain"]["registry_snapshot_digest"], "trusted_roots_digest": isolation["supply_chain"]["trusted_roots_digest"], "loaded_bytes_digest": item["exact_bytes_digest"], "placement_measurement_digest": candidate["supply_chain"]["composite_measurement_digest"], "revocation_epoch": item["revocation_epoch"], "registry_generation": item["registry_generation"], "rollback_floor": item["rollback_floor"], "signature_verified": True, "not_revoked": True} for item in candidate["supply_chain"]["components"]}
    descriptor = candidate["authority_alternatives"][0]["entries"][0]["selector"]
    facts["trusted_descriptors"] = {descriptor["descriptor_id"]: {"descriptor_id": descriptor["descriptor_id"], "canonical_path": descriptor["canonical_path"], "root_id": "root:output", "root_identity": "root:output", "mount_id": "mount:workspace", "mount_identity": "mount:workspace", "epoch": 3, "signature_verified": True, "not_revoked": True}}
    facts["verified_filesystem_targets"] = {target["composite_binding_digest"]: {**deepcopy(target), "physical_target_digest": target["composite_binding_digest"]}}
    facts["trusted_loop_contracts"] = {contract["contract_digest"]: deepcopy(contract)}
    facts["verified_loop_contracts"] = {contract["contract_digest"]: {"contract": deepcopy(contract), "signature_verified": True, "not_revoked": True, "freshness_verified": True, "current_key": True, "current_revocation_epoch": 3}}
    facts["active_iteration_slots"] = {slot["slot_key_digest"]: {"slot": deepcopy(slot), "signature_verified": True, "not_revoked": True, "freshness_verified": True, "current_fence": True, "fencing_epoch": 3, "owner_request_digest": candidate["request_digest"]}}
    facts["verified_risk_dispositions"][evidence["evidence_id"]]["profile_digest"] = evidence["profile_digest"]
    manifest_digest = reference.canonical_digest(manifest)
    signer = manifest["tool"]["signer"]
    runtime = manifest["runtime_requirements"]
    facts["verified_manifests"] = {manifest_digest: {"manifest_digest": manifest_digest, "signed_payload_digest": manifest_digest, "signer": signer["key_id"], "key_id": signer["key_id"], "algorithm": signer["algorithm"], "signature_verified": True, "trusted_time": candidate["evaluated_at"], "expires_at": manifest["lifecycle"]["expires_at"], "not_revoked": True, "rollback_floor": manifest["lifecycle"]["rollback_floor"], "dependency_closure_digest": reference.canonical_digest(manifest["tool"]["dependencies"]), "ambient_closure_digest": reference.canonical_digest({"ambient_dependencies": runtime["ambient_dependencies"], "credentials": runtime["credentials"]}), "dependency_closure_measured": True, "ambient_closure_measured": True}}
    candidate, facts = _signed_attestation_fixture(candidate, facts)
    return candidate, manifest, policy, isolation, facts


def check_canonical_chain(reference) -> tuple[dict, dict, dict, dict, dict, dict, dict]:
    candidate, manifest, policy, isolation, facts = make_fixture(reference)
    for name, instance in (("admission-candidate.schema.json", candidate), ("effect-manifest.schema.json", manifest), ("runtime-policy.schema.json", policy), ("isolation-profile.schema.json", isolation)):
        assertion("T-CANONICAL-INPUT-" + name, schema_valid(name, instance), "canonical positive input rejected")
    decision = reference.decide(candidate, manifest, policy, isolation, facts)
    assertion("T-DECISION-ALLOW-EXACT", decision["decision"] == "ALLOW" and schema_valid("decision-result.schema.json", decision) and reference.decision_digest_valid(decision), str(decision))
    capability = reference.mint_capability(decision, candidate)
    if capability is not None:
        facts["verified_capability_claims"][capability["capability_id"]] = reference.capability_verifier_record(capability)
    assertion("T-CAPABILITY-MINT-BOUND", capability is not None and schema_valid("capability.schema.json", capability) and reference.validate_capability(capability, decision, candidate, facts), str(capability))
    for name, mutate in (("MISSING-SOCKET-FIELD", lambda x: x["broker_ipc_attestation"]["socket_identity"]["worker_endpoint"].pop("cookie")), ("ABSTRACT-NAMESPACE", lambda x: x["broker_ipc_attestation"].update(socket_identity={"kind": "UNIX_ABSTRACT", "network_namespace": "net:forged", "abstract_name": "@broker"})), ("ENDPOINT-SUBSTITUTION", lambda x: x["broker_ipc_attestation"]["socket_identity"]["broker_endpoint"].update(cookie=999)), ("SENDER-SUBSTITUTION", lambda x: x["broker_ipc_attestation"]["broker_observed_sender"].update(uid=9999)), ("OPERATION", lambda x: x["broker_ipc_attestation"].update(operation_id="other-operation"))):
        broken = deepcopy(candidate); mutate(broken)
        assertion("T-Q88-BROKER-IPC-" + name, reference.decide(broken, manifest, policy, isolation, facts)["reason_codes"] == ["BROKER_IPC_ATTESTATION_INVALID"])
    forged_signature = deepcopy(candidate); forged_signature["broker_ipc_attestation"]["signature"]["payload_digest"] = digest("0")
    assertion("T-Q88-BROKER-IPC-FORGED-SIGNATURE-PAYLOAD", reference.decide(forged_signature, manifest, policy, isolation, facts)["reason_codes"] == ["BROKER_IPC_ATTESTATION_INVALID"])
    replaced_candidate, replaced_facts = deepcopy(candidate), deepcopy(facts)
    replaced_ipc = replaced_candidate["broker_ipc_attestation"]; replaced_ipc["socket_identity"]["inode"] = 8; replaced_ipc["signature"]["payload_digest"] = canonical_digest_for_test({key: value for key, value in replaced_ipc.items() if key not in {"attestation_digest", "signature"}})
    replaced_facts["verified_broker_ipc_attestations"][replaced_ipc["attestation_digest"]].update(signed_payload={key: deepcopy(value) for key, value in replaced_ipc.items() if key not in {"attestation_digest", "signature"}}, signed_payload_digest=replaced_ipc["signature"]["payload_digest"])
    assertion("T-Q88-BROKER-IPC-REPLACED-SOCKET-RETAINS-DIGEST-DENY", reference.decide(replaced_candidate, manifest, policy, isolation, replaced_facts)["reason_codes"] == ["BROKER_IPC_ATTESTATION_INVALID"])
    resource_digest = candidate["bindings"]["resource_vector_digest"]
    assertion("T-Q89-RESOURCE-VECTOR-POSITIVE", resource_digest == reference.canonical_digest(isolation["resources"]) == decision["evaluation"]["resource_vector_digest"] == capability["bindings"]["resource_vector_digest"])
    forged_vector = deepcopy(candidate); forged_vector["bindings"]["resource_vector_digest"] = digest("0")
    assertion("T-Q89-RESOURCE-VECTOR-DIGEST-DENY", reference.decide(forged_vector, manifest, policy, isolation, facts)["reason_codes"] == ["RESOURCE_VECTOR_BINDING_INVALID"])
    gpu_mismatch = deepcopy(isolation); next(row for row in gpu_mismatch["resources"] if row["resource"] == "GPU_MEMORY")["limit"] = 0
    assertion("T-Q89-GPU-PAIR-EXACT", not schema_valid("isolation-profile.schema.json", gpu_mismatch) and not reference.validate_isolation_profile(gpu_mismatch, facts))
    contract = facts["trusted_loop_contracts"][candidate["bindings"]["contract_digest"]]
    assertion("T-Q84-ITERATION-SLOT-POSITIVE", schema_valid("admission-candidate.schema.json", candidate) and reference._iteration_slot_valid(candidate, facts) and decision["evaluation"]["iteration_slot_digest"] == candidate["iteration_slot"]["slot_record_digest"] and capability["bindings"]["iteration_slot_digest"] == candidate["iteration_slot"]["slot_record_digest"])
    contender = deepcopy(candidate); contender["request_digest"] = digest("b")
    assertion("T-Q84-ITERATION-SLOT-CONFLICT", reference.decide(contender, manifest, policy, isolation, facts)["reason_codes"] == ["LOOP_CONTRACT_TRUST_INVALID"])
    assertion("T-Q86-FULL-CONTRACT-POSITIVE", schema_valid("loop-contract.schema.json", contract) and reference.validate_loop_contract(contract, facts))
    success_target = deepcopy(contract); success_target["iteration_bound"]["success_target"] = 8; success_target["contract_digest"] = reference.canonical_digest({key: value for key, value in success_target.items() if key != "contract_digest"})
    assertion("T-LOOP-SUCCESS-TARGET-NONAUTHORIZING", not schema_valid("loop-contract.schema.json", success_target) and not reference.validate_loop_contract(success_target, facts))
    retry_reset = deepcopy(contract); retry_reset["iteration_bound"]["reset_on_retry"] = True; retry_reset["contract_digest"] = reference.canonical_digest({key: value for key, value in retry_reset.items() if key != "contract_digest"})
    assertion("T-LOOP-RETRY-COUNTS-AS-ATTEMPT", not schema_valid("loop-contract.schema.json", retry_reset) and not reference.validate_loop_contract(retry_reset, facts))
    raised_attempts = deepcopy(contract); raised_attempts["iteration_bound"]["max_iterations"] += 1; raised_attempts["contract_digest"] = reference.canonical_digest({key: value for key, value in raised_attempts.items() if key != "contract_digest"})
    assertion("T-LOOP-MAX-ATTEMPTS-MATERIAL-CHANGE", schema_valid("loop-contract.schema.json", raised_attempts) and not reference.validate_loop_contract(raised_attempts, facts))
    for name, mutate in (("EXPIRY", lambda c: c["lifecycle"].update(expires_at="2026-08-24T00:00:04Z")), ("HUMAN", lambda c: c["human_confirmation"].update(machine_join_each_iteration=False)), ("POSTCHECK", lambda c: c["postcheck"].update(independent_observer=False)), ("D2", lambda c: c["d2"].update(private_ephemeral_tokens_excluded=False)), ("BUDGET", lambda c: c["aggregate_budgets"][0].update(limit=0))):
        bad = deepcopy(contract); mutate(bad)
        assertion("T-Q86-CONTRACT-" + name + "-REJECT", not reference.validate_loop_contract(bad, facts))
    omitted = deepcopy(contract); omitted.pop("postcheck")
    revoked = deepcopy(facts); revoked["verified_loop_contracts"][contract["contract_digest"]]["not_revoked"] = False
    artifact = deepcopy(contract); artifact["artifact_bindings"]["policy_digest"] = digest("0")
    cross = deepcopy(candidate); cross["bindings"]["contract_digest"] = digest("0")
    assertion("T-Q86-CONTRACT-OMISSION-REJECT", not schema_valid("loop-contract.schema.json", omitted) and not reference.validate_loop_contract(omitted, facts))
    assertion("T-Q86-CONTRACT-REVOCATION-REJECT", not reference.validate_loop_contract(contract, revoked))
    assertion("T-Q86-CONTRACT-ARTIFACT-REJECT", not reference.validate_loop_contract(artifact, facts))
    assertion("T-Q86-CONTRACT-CROSS-BINDING-REJECT", reference.decide(cross, manifest, policy, isolation, facts)["reason_codes"] == ["PLACEMENT_OR_SESSION_ATTESTATION_INVALID"])
    malformed_decision = deepcopy(decision); malformed_decision["authorized_envelope"][0]["constraints"]["data_label"] = {}
    malformed_capability = deepcopy(capability); malformed_capability["effects"][0]["constraints"]["quantity"] = {}
    assertion("T-AUTHORITY-TYPED-DECISION-RESULT", not schema_valid("decision-result.schema.json", malformed_decision))
    assertion("T-AUTHORITY-TYPED-CAPABILITY", not schema_valid("capability.schema.json", malformed_capability))
    return candidate, manifest, policy, isolation, facts, decision, capability


def make_delegated_child(reference, candidate, facts, decision, parent, work_effect="MUTATE"):
    child_decision = deepcopy(decision)
    if work_effect == "COMMUNICATE":
        child_decision["authorized_envelope"][0].update(effect="COMMUNICATE", resource_kind="PRINCIPAL", operation="SEND", selector={"kind": "LOCAL_RESOURCE", "reference": "principal:bounded-child", "canonical_value": "principal:bounded-child", "resolution": "EXACT_REGISTRY_ID"})
        child_decision["authorized_effects"] = ["COMMUNICATE"]
        child_decision["decision_digest"] = reference.canonical_digest({key: value for key, value in child_decision.items() if key != "decision_digest"})
    child = reference.mint_capability(child_decision, candidate)
    child["audience"] = "principal:bounded-child"
    child_effects, child_budgets = deepcopy(child["effects"]), deepcopy(child["budgets"])
    delegate_entry = deepcopy(child_effects[0]); delegate_entry.update(effect="DELEGATE", resource_kind="PRINCIPAL", operation="SPAWN", selector={"kind": "LOCAL_RESOURCE", "reference": "principal:bounded-child", "canonical_value": "principal:bounded-child", "resolution": "EXACT_REGISTRY_ID"})
    parent_effects = [delegate_entry, *deepcopy(child_effects)]
    parent_bound = deepcopy(parent); parent_bound["effects"], parent_bound["budgets"] = deepcopy(parent_effects), deepcopy(child_budgets)
    parent_bound["issuer_verification"]["signed_claims_digest"] = reference.canonical_digest(reference._capability_signed_claims(parent_bound))
    parent_bound["capability_digest"] = reference.canonical_digest({key: value for key, value in parent_bound.items() if key != "capability_digest"})
    parent_digest = parent_bound["capability_digest"]
    child["lineage"]["parent_capability_digest"] = parent_digest
    escrow = [{"name": item["name"], "unit": item["unit"], "scope_digest": item["scope_digest"], "lineage_root": item["lineage_root"], "limit": item["amount"], "spent": 0, "reserved": 0, "remaining": item["amount"]} for item in child_budgets]
    reservations = [{"capability_id": child["capability_id"]}]
    delegation_clause = parent_effects[0]
    child["delegation"] = {"parent_capability_id": parent_bound["capability_id"], "parent_capability_digest": parent_digest, "parent_state": "ISSUED", "target_principal": "principal:bounded-child", "parent_envelope_digest": reference.canonical_digest(parent_effects), "parent_delegation_clause_digest": reference.canonical_digest(delegation_clause), "root_lineage_digest": reference.canonical_digest(parent_bound["lineage"]), "edge_nonce": "delegation_edge_nonce_1234567890", "child_principal": child["principal"], "child_audience": child["audience"], "fencing_epoch": child["lineage"]["fencing_epoch"], "parent_effects_digest": reference.canonical_digest(parent_effects), "parent_budget_digest": reference.canonical_digest(child_budgets), "parent_budget_escrow_digest": reference.canonical_digest(escrow), "sibling_reservations_digest": reference.canonical_digest(reservations), "budget_escrow": escrow, "transfer_fence": 1, "ancestry": [], "depth": 1, "max_depth": 4, "fanout": 1, "max_fanout": 2, "cycle_guard": True, "cascade_revocation_digest": digest("d")}
    signed = reference.canonical_digest(reference._capability_signed_claims(child))
    child["issuer_verification"]["signed_claims_digest"] = signed
    child["capability_digest"] = reference.canonical_digest({key: value for key, value in child.items() if key != "capability_digest"})
    child_facts = deepcopy(facts)
    child_facts["verified_capability_claims"][child["capability_id"]] = reference.capability_verifier_record(child)
    child_facts["live_parent_capabilities"] = {parent_digest: {"state": "ISSUED", "capability_id": parent_bound["capability_id"]}}
    child_facts["parent_envelopes"] = {parent_digest: parent_effects}
    child_facts["parent_budgets"] = {parent_digest: child_budgets}
    child_facts["cascade_revocation_facts"] = {parent_digest: digest("d")}
    child_facts["parent_budget_ledgers"] = {parent_digest: {"transfer_fence": 1, "children": reservations}}
    child_facts["delegation_edges"] = {child["capability_id"]: {key: child["delegation"][key] for key in ("parent_capability_id", "parent_capability_digest", "parent_envelope_digest", "parent_delegation_clause_digest", "root_lineage_digest", "edge_nonce", "child_principal", "child_audience", "fencing_epoch")}}
    return child_decision, child, child_facts


def refresh_capability(reference, capability, facts):
    signed = reference.canonical_digest(reference._capability_signed_claims(capability))
    capability["issuer_verification"]["signed_claims_digest"] = signed
    capability["capability_digest"] = reference.canonical_digest({key: value for key, value in capability.items() if key != "capability_digest"})
    facts["verified_capability_claims"][capability["capability_id"]] = reference.capability_verifier_record(capability)


def check_capability_trust(reference, candidate, facts, decision, capability) -> int:
    count = 0
    mutations = (
        ("ISSUER", lambda x: x.update(issuer="broker:forged")),
        ("PRINCIPAL", lambda x: x.update(principal="agent:other")),
        ("AUDIENCE", lambda x: x.update(audience="executor:other")),
        ("PURPOSE", lambda x: x.update(purpose="OTHER")),
        ("BINDING", lambda x: x["bindings"].update(manifest_digest=digest("0"))),
        ("EFFECT", lambda x: x["effects"][0].update(operation="DELETE")),
        ("BUDGET", lambda x: x["budgets"][0].update(amount=2)),
        ("NONCE", lambda x: x.update(nonce="forged_nonce_123456789012")),
        ("LINEAGE", lambda x: x["lineage"].update(call_id="request:other")),
        ("EXPIRY", lambda x: x.update(expires_at="2026-08-24T00:20:00Z")),
        ("REVOCATION", lambda x: x.update(revocation_epoch=4)),
    )
    for name, mutate in mutations:
        bad = deepcopy(capability); mutate(bad)
        bad["issuer_verification"]["signed_claims_digest"] = reference.canonical_digest(reference._capability_signed_claims(bad))
        bad.pop("capability_digest", None); bad["capability_digest"] = reference.canonical_digest(bad)
        assertion("T-CAPABILITY-MUTATE-REHASH-" + name, not reference.validate_capability(bad, decision, candidate, facts)); count += 1
    expired = deepcopy(facts); expired["trusted_time"] = capability["expires_at"]
    assertion("T-CAPABILITY-TRUSTED-TIME", not reference.validate_capability(capability, decision, candidate, expired)); count += 1
    stale = deepcopy(facts); stale["current_revocation_epoch"] += 1
    assertion("T-CAPABILITY-TRUSTED-REVOCATION-EPOCH", not reference.validate_capability(capability, decision, candidate, stale)); count += 1
    fenced = deepcopy(facts); fenced["current_fencing_epoch"] += 1
    assertion("T-CAPABILITY-TRUSTED-FENCING-EPOCH", not reference.validate_capability(capability, decision, candidate, fenced)); count += 1
    revoked = deepcopy(facts); revoked["revoked_capability_digests"] = [capability["capability_digest"]]
    assertion("T-CAPABILITY-TRUSTED-REVOCATION-SET", not reference.validate_capability(capability, decision, candidate, revoked)); count += 1
    state, _ = advance(reference, "STAGEABLE", decision, capability, ["PROPOSE", "NORMALIZE", "CLASSIFY", "ADMIT", "CALCULATE_RESERVATION"])
    issue = event_for("ISSUE_CAPABILITY", decision, capability); issue.pop("capability_verification_ref")
    assertion("T-CAPABILITY-ISSUE-REQUIRES-TRUSTED-FACT", not reference.reduce_transition(state, issue)["accepted"]); count += 1
    issued, _ = advance(reference, "STAGEABLE", decision, capability, ["PROPOSE", "NORMALIZE", "CLASSIFY", "ADMIT", "CALCULATE_RESERVATION", "ISSUE_CAPABILITY"])
    replaced_socket = deepcopy(issued)
    replaced_record = replaced_socket["trusted_store"]["broker_ipc_attestations"][capability["bindings"]["broker_ipc_attestation_digest"]]
    replaced_ipc = replaced_record["attestation"]; replaced_ipc["socket_identity"]["inode"] = 8; replaced_ipc["signature"]["payload_digest"] = canonical_digest_for_test({key: value for key, value in replaced_ipc.items() if key not in {"attestation_digest", "signature"}})
    replaced_record.update(signed_payload={key: deepcopy(value) for key, value in replaced_ipc.items() if key not in {"attestation_digest", "signature"}}, signed_payload_digest=replaced_ipc["signature"]["payload_digest"])
    assertion("T-Q88-DISPATCH-SOCKET-REPLACEMENT-REQUIRES-READMISSION", not reference.reduce_transition(replaced_socket, event_for("DURABLE_DISPATCH", decision, capability))["accepted"]); count += 1
    for name, mutate in (
        ("TIME", lambda x: x.update(dispatch_verification_ref="dispatch:forged-time")),
        ("REVOCATION", lambda x: x.update(dispatch_verification_ref="dispatch:forged-revocation")),
        ("FENCE", lambda x: x.update(dispatch_verification_ref="dispatch:forged-fence")),
        ("REVOKED", lambda x: x.update(dispatch_verification_ref="dispatch:forged-revoked")),
        ("EFFECT_REHASH", lambda x: x.update(capability_effects_digest=canonical_digest_for_test([{**capability["effects"][0], "operation": "DELETE"}]))),
    ):
        bad = event_for("DURABLE_DISPATCH", decision, capability); mutate(bad)
        assertion("T-CAPABILITY-DISPATCH-TRUSTED-" + name, not reference.reduce_transition(issued, bad)["accepted"]); count += 1
    delegate = deepcopy(capability); delegate["effects"][0].update(effect="DELEGATE", resource_kind="PRINCIPAL", operation="SPAWN", selector={"kind": "LOCAL_RESOURCE", "reference": "principal:bounded-child", "canonical_value": "principal:bounded-child", "resolution": "EXACT_REGISTRY_ID"}); delegate["capability_digest"] = reference.canonical_digest({key: value for key, value in delegate.items() if key != "capability_digest"})
    assertion("T-Q75-ROOT-DELEGATE-AUTHORITY-NEEDS-NO-PARENT", schema_valid("capability.schema.json", delegate)); count += 1
    unproven_child = deepcopy(capability); unproven_child["lineage"]["parent_capability_digest"] = digest("d"); refresh_capability(reference, unproven_child, deepcopy(facts))
    assertion("T-Q75-DESCENDANT-WORK-REQUIRES-PROVENANCE", not schema_valid("capability.schema.json", unproven_child)); count += 1
    child_decision, child, child_facts = make_delegated_child(reference, candidate, facts, decision, capability)
    assertion("T-Q75-DESCENDANT-MUTATE-POSITIVE-BOUND", child["effects"][0]["effect"] == "MUTATE" and schema_valid("capability.schema.json", child) and reference.validate_capability(child, child_decision, candidate, child_facts)); count += 1
    communicate_decision, communicate_child, communicate_facts = make_delegated_child(reference, candidate, facts, decision, capability, "COMMUNICATE")
    assertion("T-Q75-DESCENDANT-COMMUNICATE-POSITIVE-BOUND", schema_valid("capability.schema.json", communicate_child) and reference.validate_capability(communicate_child, communicate_decision, candidate, communicate_facts)); count += 1
    parent_id = child["delegation"]["parent_capability_digest"]
    within, within_facts = deepcopy(child), deepcopy(child_facts)
    within_facts["parent_budget_ledgers"][parent_id]["children"].append({"capability_id": "cap:bounded-sibling", "budget_escrow": [{**child["budgets"][0], "amount": 0}]})
    within["delegation"]["sibling_reservations_digest"] = reference.canonical_digest(within_facts["parent_budget_ledgers"][parent_id]["children"]); refresh_capability(reference, within, within_facts)
    assertion("T-DELEGATE-TWO-CHILDREN-WITHIN-BOUND", reference.validate_capability(within, child_decision, candidate, within_facts)); count += 1
    interleaved, interleaved_facts = deepcopy(child), deepcopy(child_facts)
    interleaved_facts["parent_budget_ledgers"][parent_id]["children"].append({"capability_id": "cap:distinct-overlimit", "budget_escrow": [{**child["budgets"][0], "amount": 1026}]})
    interleaved["delegation"]["sibling_reservations_digest"] = reference.canonical_digest(interleaved_facts["parent_budget_ledgers"][parent_id]["children"]); refresh_capability(reference, interleaved, interleaved_facts)
    assertion("T-DELEGATE-SIBLING-INTERLEAVING-CONSERVATION", not reference.validate_capability(interleaved, child_decision, candidate, interleaved_facts)); count += 1
    crash_ledger = deepcopy(child_facts); crash_ledger.pop("parent_budget_ledgers"); assertion("T-DELEGATE-CRASH-LEDGER-PERSISTENCE", not reference.validate_capability(child, child_decision, candidate, crash_ledger)); count += 1
    for name, mutate in (
        ("FORGED_PARENT", lambda f, c: c["delegation"].update(parent_capability_digest=digest("0"))),
        ("PARENT_ID", lambda f, c: c["delegation"].update(parent_capability_id="cap:forged")),
        ("PARENT_ENVELOPE", lambda f, c: c["delegation"].update(parent_envelope_digest=digest("0"))),
        ("ROOT_LINEAGE", lambda f, c: c["delegation"].update(root_lineage_digest=digest("0"))),
        ("EDGE_NONCE", lambda f, c: c["delegation"].update(edge_nonce="forged_edge_nonce_1234567890")),
        ("CHILD_IDENTITY", lambda f, c: c["delegation"].update(child_audience="principal:other")),
        ("FENCE", lambda f, c: c["delegation"].update(fencing_epoch=2)),
        ("NONLIVE_PARENT", lambda f, c: f["live_parent_capabilities"].update({c["delegation"]["parent_capability_digest"]: {"state": "STOPPED"}})),
        ("REVOKED_PARENT", lambda f, c: f.update(revoked_capability_digests=[c["delegation"]["parent_capability_digest"]])),
        ("EFFECT_AMPLIFICATION", lambda f, c: c["effects"][0].update(operation="BIND")),
        ("BUDGET_EXPANSION", lambda f, c: c["budgets"][0].update(amount=c["budgets"][0]["amount"] + 1)),
        ("DEPTH", lambda f, c: c["delegation"].update(depth=5)),
        ("FANOUT", lambda f, c: c["delegation"].update(fanout=3)),
        ("CYCLE", lambda f, c: c["delegation"].update(ancestry=[c["delegation"]["parent_capability_digest"]])),
        ("CASCADE_MISSING", lambda f, c: c["delegation"].pop("cascade_revocation_digest")),
        ("CASCADE", lambda f, c: f["cascade_revocation_facts"].update({c["delegation"]["parent_capability_digest"]: digest("0")})),
    ):
        bad, bad_facts = deepcopy(child), deepcopy(child_facts); mutate(bad_facts, bad); refresh_capability(reference, bad, bad_facts)
        assertion("T-DELEGATE-" + name, not reference.validate_capability(bad, child_decision, candidate, bad_facts)); count += 1
    return count


def reference_capability_record(capability: dict) -> dict:
    verification = capability.get("issuer_verification", {})
    return {"capability_digest": capability.get("capability_digest"), "signed_claims_digest": verification.get("signed_claims_digest"), "issuer": capability.get("issuer"), "principal": capability.get("principal"), "audience": capability.get("audience"), "purpose": capability.get("purpose"), "contract_digest": capability.get("bindings", {}).get("contract_digest"), "lineage_digest": canonical_digest_for_test(capability.get("lineage")), "delegation_digest": canonical_digest_for_test(capability.get("delegation")) if capability.get("delegation") is not None else None, "bindings_digest": canonical_digest_for_test(capability.get("bindings")), "effects_digest": canonical_digest_for_test(capability.get("effects")), "budgets_digest": canonical_digest_for_test(capability.get("budgets")), "signature_verified": True, "not_revoked": True, "full_claims_verified": True, "verified_by": verification.get("verified_by")}


def object_identity() -> dict:
    return {"descriptor_id": "fd:output", "root_id": "root:output", "mount_id": "mount:workspace", "resolution_epoch": 3, "final_object_id": "object:report", "final_object_digest": digest("a")}


def endpoint_binding(manifest: dict | None = None) -> dict:
    if manifest is not None:
        return deepcopy(manifest["effect_bounds"][0]["resources"][0]["selector"]["endpoint_binding"])
    binding = {"endpoint_id": "endpoint:message", "canonical_endpoint": "https://messages.example.test/v1/send", "connector_id": "connector:reference", "connector_digest": digest("9"), "method": "POST", "idempotency_key_digest": digest("6")}
    binding["endpoint_binding_digest"] = canonical_digest_for_test(binding)
    return binding


def refresh_profile_activation(reference, profile: dict, facts: dict, candidate: dict) -> None:
    """Rebind a deliberately changed active profile to the same trusted fixture."""
    profile_digest = reference._control_content_digest(profile, "profile_digest", "profile_activation")
    profile["profile_digest"] = profile["profile_activation"]["content_digest"] = profile_digest
    for evidence in profile["risk_disposition_evidence"]:
        evidence["profile_digest"] = profile_digest
        evidence["signed_payload"]["payload_digest"] = canonical_digest_for_test({key: value for key, value in evidence.items() if key not in {"signed_payload", "external_verification"}})
        facts["verified_risk_dispositions"][evidence["evidence_id"]].update(profile_digest=profile_digest, signed_payload_digest=evidence["signed_payload"]["payload_digest"])
    facts["verified_profile_activations"] = {profile_digest: {**profile["profile_activation"], "signature_verified": True, "not_revoked": True, "freshness_verified": True, "revocation_checked": True, "verified_by": "verifier:profile"}}
    for principal, subject in facts["verified_role_subjects"].items():
        subject["profile_digest"] = profile_digest
    candidate["bindings"]["isolation_profile_digest"] = profile_digest
    candidate["placement_attestation"]["isolation_profile_digest"] = profile_digest
    placement = candidate["placement_attestation"]
    placement_unsigned = {key: value for key, value in placement.items() if key != "signature"}
    placement["signature"]["payload_digest"] = canonical_digest_for_test(placement_unsigned)
    trusted_placement = facts["verified_attestations"][placement["attestation_digest"]]
    trusted_placement.update(isolation_profile_digest=profile_digest, payload_digest=placement["signature"]["payload_digest"], signed_payload_digest=placement["signature"]["payload_digest"], signed_fields=deepcopy(placement_unsigned))
    ipc = candidate.get("broker_ipc_attestation")
    if isinstance(ipc, dict):
        ipc["isolation_profile_digest"] = profile_digest
        refresh_ipc_digest(ipc)
        candidate["bindings"].update(broker_ipc_attestation_digest=ipc["attestation_digest"], broker_ipc_binding_digest=ipc["broker_ipc_binding_digest"], resource_vector_digest=canonical_digest_for_test(profile["resources"]))
        facts["current_broker_ipc_nonce"] = ipc["nonce"]
        facts["verified_broker_ipc_attestations"] = {ipc["attestation_digest"]: ipc_verifier_record(ipc)}
        IPC_FIXTURES[ipc["attestation_digest"]] = deepcopy(ipc)
    rebind_loop_contract(reference, candidate, facts)


def refresh_policy_activation(reference, policy: dict, facts: dict, candidate: dict) -> None:
    policy_digest = reference._control_content_digest(policy, "policy_digest", "policy_activation")
    policy["policy_digest"] = policy["policy_activation"]["content_digest"] = policy_digest
    facts["verified_policy_activations"] = {policy_digest: {**policy["policy_activation"], "signature_verified": True, "not_revoked": True, "freshness_verified": True, "revocation_checked": True, "verified_by": "verifier:policy"}}
    candidate["bindings"]["policy_digest"] = policy_digest
    rebind_loop_contract(reference, candidate, facts)


def refresh_profile_consumers(reference, manifest: dict, policy: dict, profile: dict, facts: dict, candidate: dict) -> None:
    manifest["runtime_requirements"].update(isolation_profile_id=profile["profile_id"], isolation_profile_digest=profile["profile_digest"])
    _rebind_manifest(reference, candidate, manifest, facts)
    runtime = manifest["runtime_requirements"]
    trusted = facts["verified_manifests"][candidate["bindings"]["manifest_digest"]]
    trusted.update(expires_at=manifest["lifecycle"]["expires_at"], rollback_floor=manifest["lifecycle"]["rollback_floor"], dependency_closure_digest=canonical_digest_for_test(manifest["tool"]["dependencies"]), ambient_closure_digest=canonical_digest_for_test({"ambient_dependencies": runtime["ambient_dependencies"], "credentials": runtime["credentials"]}))
    policy["physical_ceiling"].update(isolation_profile_id=profile["profile_id"], isolation_profile_digest=profile["profile_digest"])
    refresh_policy_activation(reference, policy, facts, candidate)


def refresh_broker_ipc_attestation(reference, candidate: dict, profile: dict, facts: dict) -> None:
    ipc = candidate["broker_ipc_attestation"]
    ipc.update(isolation_profile_digest=profile["profile_digest"], broker_ipc_binding_digest=profile["broker_ipc_binding"]["binding_digest"], operation_id=candidate["operation_id"])
    refresh_ipc_digest(ipc)
    candidate["bindings"].update(broker_ipc_attestation_digest=ipc["attestation_digest"], broker_ipc_binding_digest=ipc["broker_ipc_binding_digest"], resource_vector_digest=canonical_digest_for_test(profile["resources"]))
    facts["current_broker_ipc_nonce"] = ipc["nonce"]
    facts["verified_broker_ipc_attestations"] = {ipc["attestation_digest"]: ipc_verifier_record(ipc)}
    IPC_FIXTURES[ipc["attestation_digest"]] = deepcopy(ipc)


def event_for(kind: str, decision: dict, capability: dict, **extra) -> dict:
    event = {"type": kind}
    if kind == "PROPOSE":
        event["transaction_id"] = extra.get("transaction_id", "tx:one")
        pep = {"verified_by": "pep:external", "signature_verified": True, "decision_digest": decision["decision_digest"], "request_digest": decision["evaluation"]["request_digest"], "authorized_envelope_digest": canonical_digest_for_test(decision["authorized_envelope"]), "reservation_vector_digest": canonical_digest_for_test(decision["reservations"]), "manifest_digest": decision["evaluation"]["manifest_digest"], "policy_digest": decision["evaluation"]["policy_digest"]}
        pep["receipt_digest"] = canonical_digest_for_test(pep); event["trusted_pep_receipts"] = {pep["receipt_digest"]: pep}
    elif kind == "ADMIT":
        chosen = extra.get("decision", decision)
        pep = {"verified_by": "pep:external", "signature_verified": True, "decision_digest": chosen["decision_digest"], "request_digest": chosen["evaluation"]["request_digest"], "authorized_envelope_digest": canonical_digest_for_test(chosen["authorized_envelope"]), "reservation_vector_digest": canonical_digest_for_test(chosen["reservations"]), "manifest_digest": chosen["evaluation"]["manifest_digest"], "policy_digest": chosen["evaluation"]["policy_digest"]}
        pep["receipt_digest"] = canonical_digest_for_test(pep); event.update({"decision": chosen, "trusted_pep_verification": pep}); event.update(extra)
    elif kind == "CALCULATE_RESERVATION":
        vector = deepcopy(extra.get("reservation_vector", decision["reservations"])); event.update({"reservation_vector": vector, "reservation_vector_digest": canonical_digest_for_test(vector)}); event.update(extra)
    elif kind == "ISSUE_CAPABILITY": event.update({"capability": deepcopy(extra.get("capability", capability)), "capability_verification_ref": capability["capability_id"]}); event.update(extra)
    elif kind == "DURABLE_DISPATCH":
        event.update({"capability_digest": capability["capability_digest"], "decision_digest": decision["decision_digest"], "iteration_slot_digest": capability["bindings"]["iteration_slot_digest"], "d2_frontier_digest": capability["bindings"]["d2_frontier_digest"], "authorized_envelope_digest": capability["bindings"]["authorized_envelope_digest"], "approval_mode": capability["bindings"]["approval_mode"], "approval_receipt_digest": capability["bindings"]["approval_receipt_digest"], "broker_ipc_attestation_digest": capability["bindings"]["broker_ipc_attestation_digest"], "broker_ipc_binding_digest": capability["bindings"]["broker_ipc_binding_digest"], "resource_vector_digest": capability["bindings"]["resource_vector_digest"], "supply_chain_measurement_digest": capability["bindings"]["supply_chain_measurement_digest"], "execution_binding": capability["execution_binding"], "reservation_vector": decision["reservations"], "reservation_vector_digest": canonical_digest_for_test(decision["reservations"]), "capability_effects_digest": canonical_digest_for_test(capability["effects"]), "capability_budgets_digest": canonical_digest_for_test(capability["budgets"]), "dispatch_verification_ref": capability["capability_digest"], "dispatch_intent_digest": digest("2")})
        if capability["bindings"].get("endpoint_binding_digest"):
            binding = deepcopy(capability["effects"][0]["selector"]["endpoint_binding"])
            event.update(object_identity=binding, idempotency_key_digest=binding["idempotency_key_digest"], connector_id=binding["connector_id"], source_chain_digest=digest("7"))
        else:
            event["object_identity"] = object_identity()
        event.update(extra)
    elif kind == "RECONCILE_SUCCESS": event.update(reconciliation_evidence_ref="reconcile:success"); event.update(extra)
    elif kind in {"RECONCILE_FAILURE", "RECORD_FAILURE"}: event.update(reconciliation_evidence_ref="reconcile:failure"); event.update(extra)
    elif kind == "QUIESCE": event.update(quiescence_attestation_digest=digest("3"), quiesce_evidence_ref="stage:quiesce")
    elif kind == "SEAL": event.update(seal_digest=digest("4"), seal_evidence_ref="stage:seal")
    elif kind == "POSTCHECK_PASS": event.update(postcheck_attestation_digest=digest("5"), postcheck_evidence_ref="stage:postcheck")
    elif kind == "COMMIT":
        event.update({"transaction_id": extra.get("transaction_id", "tx:one"), "object_id": extra.get("object_id", "object:report"), "object_digest": extra.get("object_digest", digest("a")), "receipt_chain_digest": extra.get("receipt_chain_digest", digest("b"))})
        event["commit_evidence_ref"] = "commit:one"
    elif kind == "JOIN":
        identity = deepcopy(extra.get("object_identity", object_identity()))
        event.update({"decision_digest": decision["decision_digest"], "iteration_slot_digest": capability["bindings"]["iteration_slot_digest"], "d2_frontier_digest": capability["bindings"]["d2_frontier_digest"], "broker_ipc_attestation_digest": capability["bindings"]["broker_ipc_attestation_digest"], "broker_ipc_binding_digest": capability["bindings"]["broker_ipc_binding_digest"], "resource_vector_digest": capability["bindings"]["resource_vector_digest"], "object_identity": identity, "join_evidence": {**{key: True for key in ("committed_subset_authorized", "quiescence", "seal", "postcheck", "trusted_attestation", "digest_chain", "anti_rollback")}, "transaction_id": extra.get("transaction_id", "tx:one"), "object_id": extra.get("object_id", "object:report"), "object_digest": extra.get("object_digest", digest("a")), "object_identity": identity, "chain_digest": extra.get("receipt_chain_digest", digest("b")), "iteration_slot_digest": capability["bindings"]["iteration_slot_digest"], "d2_frontier_digest": capability["bindings"]["d2_frontier_digest"], "broker_ipc_attestation_digest": capability["bindings"]["broker_ipc_attestation_digest"], "broker_ipc_binding_digest": capability["bindings"]["broker_ipc_binding_digest"], "resource_vector_digest": capability["bindings"]["resource_vector_digest"], "quiesce_evidence_ref": extra.get("quiesce_evidence_ref", "stage:quiesce"), "seal_evidence_ref": extra.get("seal_evidence_ref", "stage:seal"), "postcheck_evidence_ref": extra.get("postcheck_evidence_ref", "stage:postcheck"), "quiescence_attestation_digest": extra.get("quiescence_attestation_digest", digest("3")), "seal_digest": extra.get("seal_digest", digest("4")), "postcheck_attestation_digest": extra.get("postcheck_attestation_digest", digest("5"))}})
        event["join_evidence_ref"] = "join:one"
        event.update(extra)
    return event


def runtime_d2_verifications(capability: dict, decision: dict, transaction_id: str = "tx:one") -> dict:
    frontier, contract = capability["bindings"]["d2_frontier_digest"], capability["bindings"]["contract_digest"]
    record = deepcopy(decision["evaluation"]["d2_frontier_record"])
    records = {}
    for fence, sequence in ((1, 0), (2, 1), (3, 0), (4, 1), (5, 1)):
        item = {"d2_frontier_digest": frontier, "d2_frontier_record": deepcopy(record), "contract_digest": contract, "transaction_id": transaction_id, "fencing_epoch": fence, "runtime_journal_sequence": sequence, "verified_at": capability["issued_at"], "expires_at": capability["expires_at"], "signature_verified": True, "not_revoked": True, "verified_by": "verifier:d2-frontier", "verifier_key_id": "key:d2-frontier", "verifier_trust_root": "trust:root", "verifier_algorithm": "ED25519", "verifier_signature": "D" * 64}
        item["verification_digest"] = canonical_digest_for_test(item)
        records[f"{frontier}:{fence}"] = item
    return records


def runtime_iteration_slot_verifications(capability: dict, decision: dict) -> dict:
    frontier = decision["evaluation"]["d2_frontier_record"]
    slot = {"slot_id": f"slot:write.iteration.{capability['lineage']['iteration']}", "slot_key_digest": digest("0"), "authority_domain_id": frontier["authority_domain_id"], "root_contract_digest": frontier["root_contract_digest"], "journal_lineage_id": frontier["journal_lineage_id"], "iteration": capability["lineage"]["iteration"], "owner_request_digest": capability["bindings"]["request_digest"], "fencing_epoch": frontier["fencing_epoch"], "state": "CLAIMED", "claimed_at": "2026-08-24T00:00:04Z", "expires_at": capability["expires_at"], "slot_record_digest": digest("0")}
    slot["slot_key_digest"] = canonical_digest_for_test({key: slot[key] for key in ("authority_domain_id", "root_contract_digest", "journal_lineage_id", "iteration")})
    slot["slot_record_digest"] = canonical_digest_for_test({key: value for key, value in slot.items() if key != "slot_record_digest"})
    if slot["slot_record_digest"] != capability["bindings"]["iteration_slot_digest"]:
        raise AssertionError("fixture capability does not bind the admitted iteration slot")
    return {f"{slot['slot_record_digest']}:{fence}": {"slot": deepcopy(slot), "slot_record_digest": slot["slot_record_digest"], "owner_request_digest": slot["owner_request_digest"], "slot_fencing_epoch": slot["fencing_epoch"], "fencing_epoch": fence, "current_fencing_epoch": fence, "signature_verified": True, "not_revoked": True, "freshness_verified": True, "current_fence": True} for fence in (1, 2, 3, 4, 5)}


def scoped_effect_for_failure(effect: dict) -> dict:
    selector = effect["selector"]
    scope_kind = {"FILE": "PATH", "DIRECTORY": "PATH", "ENDPOINT": "ENDPOINT", "PRINCIPAL": "PRINCIPAL", "MEMORY": "MEMORY", "PROMPT": "PROMPT", "POLICY": "POLICY", "PROCESS": "PROCESS", "REGISTRY": "LOCAL_RESOURCE", "COMPUTE_RESOURCE": "LOCAL_RESOURCE"}[effect["resource_kind"]]
    value = selector.get("canonical_value", selector.get("canonical_path", selector.get("canonical_endpoint", selector.get("resource_id"))))
    return {"effect": effect["effect"], "resource_kind": effect["resource_kind"], "operations": [effect["operation"]], "scope": {"kind": scope_kind, "values": [value]}}


def residual_failure_disposition(capability: dict, decision: dict) -> dict:
    effects = [{"component_id": f"component:{index}", "effect": scoped_effect_for_failure(effect), "disposition": "PARTIAL_EFFECT" if index == 0 else "RESIDUAL_EFFECT"} for index, effect in enumerate(capability["effects"])]
    budgets = [{**row, "disposition": "SPENT" if index == 0 else "QUARANTINED_ESCROW"} for index, row in enumerate(decision["reservations"])]
    authorization = {"transaction_id": "tx:compensation", "decision_digest": digest("c"), "capability_digest": digest("d"), "authorized_envelope_digest": digest("e"), "state": "ADMITTED"}
    return {"effect_dispositions": effects, "budget_dispositions": budgets, "automatic_retry_allowed": False, "next_state": "COMPENSATION_PENDING", "compensation_authorization": authorization}


def advance(reference, branch: str, decision: dict, capability: dict, events: list[str], budget_vector=None):
    is_endpoint = capability["bindings"].get("endpoint_binding_digest") is not None
    frontier_record = decision["evaluation"]["d2_frontier_record"]
    post_dispatch_fence = frontier_record["fencing_epoch"] + 1
    identity = deepcopy(capability["effects"][0]["selector"]["endpoint_binding"]) if is_endpoint else object_identity()
    commit = {"evidence_type": "COMMIT", "transaction_id": "tx:one", "decision_digest": decision["decision_digest"], "capability_digest": capability["capability_digest"], "envelope_digest": capability["bindings"]["authorized_envelope_digest"], "object_id": "object:report", "object_digest": digest("a"), "chain_digest": digest("b"), "signature_verified": True, "verified_by": "observer:runtime"}
    commit["evidence_digest"] = canonical_digest_for_test(commit)
    join = {"evidence_type": "JOIN", "transaction_id": "tx:one", "decision_digest": decision["decision_digest"], "iteration_slot_digest": capability["bindings"]["iteration_slot_digest"], "d2_frontier_digest": capability["bindings"]["d2_frontier_digest"], "capability_digest": capability["capability_digest"], "envelope_digest": capability["bindings"]["authorized_envelope_digest"], "object_id": "object:report", "object_digest": digest("a"), "object_identity": identity, "chain_digest": digest("b"), "quiesce_evidence_ref": "stage:quiesce", "seal_evidence_ref": "stage:seal", "postcheck_evidence_ref": "stage:postcheck", "quiescence_attestation_digest": digest("3"), "seal_digest": digest("4"), "postcheck_attestation_digest": digest("5"), "signature_verified": True, "verified_by": "observer:runtime"}
    join["evidence_digest"] = canonical_digest_for_test(join)
    capability_record = reference_capability_record(capability); capability_record.update({"trusted_time": capability["issued_at"], "current_revocation_epoch": capability["revocation_epoch"], "current_fencing_epoch": capability["execution_binding"]["session_epoch"]})
    dispatch_record = deepcopy(capability_record); dispatch_record["object_identity"] = identity
    verified_filesystem_targets, verified_endpoint_bindings = {}, {}
    if is_endpoint:
        verified_endpoint_bindings[identity["endpoint_binding_digest"]] = {**deepcopy(identity), "signature_verified": True, "not_revoked": True, "current_key": True, "verified_by": "verifier:endpoint", "key_id": "key:connector", "trust_root": "trust:connector", "algorithm": "ED25519", "verified_at": capability["issued_at"], "expires_at": capability["expires_at"]}
    else:
        physical_target = {"canonical_path": "/workspace/output/report.txt", "descriptor_id": identity["descriptor_id"], "root_id": identity["root_id"], "root_identity": "root:output", "mount_id": identity["mount_id"], "mount_identity": "mount:workspace", "resolution_epoch": identity["resolution_epoch"], "final_object_id": identity["final_object_id"], "final_object_digest": identity["final_object_digest"], "composite_binding_digest": digest("0"), "verified_by": "verifier:filesystem", "key_id": "key:filesystem", "trust_root": "trust:root", "algorithm": "ED25519", "signature": "F" * 64, "signature_verified": True, "not_revoked": True}
        physical_target["composite_binding_digest"] = canonical_digest_for_test({key: value for key, value in physical_target.items() if key != "composite_binding_digest"})
        capability_target_digests = {effect["selector"].get("physical_target_digest") for effect in capability["effects"] if effect.get("resource_kind") in {"FILE", "DIRECTORY"}}
        if capability_target_digests != {physical_target["composite_binding_digest"]}:
            raise AssertionError("fixture capability does not bind the compiled filesystem target")
        dispatch_record["physical_target"] = physical_target
        verified_filesystem_targets[physical_target["composite_binding_digest"]] = {**deepcopy(physical_target), "physical_target_digest": physical_target["composite_binding_digest"]}
    stage_evidence = {}
    for reference_name, evidence_type, evidence_digest in (("stage:quiesce", "QUIESCE", digest("3")), ("stage:seal", "SEAL", digest("4")), ("stage:postcheck", "POSTCHECK", digest("5"))):
        stage_evidence[reference_name] = {"evidence_type": evidence_type, "evidence_digest": evidence_digest, "transaction_id": "tx:one", "capability_digest": capability["capability_digest"], "session_id": capability["execution_binding"]["session_id"], "object_identity": identity, "fencing_epoch": post_dispatch_fence, "observer": "observer:runtime", "signature_verified": True, "not_revoked": True, "verified_by": "observer:runtime"}
    reconciliation = {}
    reconciliation_cases = [("reconcile:success", "SUCCESS"), ("reconcile:failure", "FAILURE_NO_EFFECT")]
    if is_endpoint:
        reconciliation_cases.append(("reconcile:residual", "FAILURE_WITH_RESIDUAL_EFFECT"))
    failure_disposition = residual_failure_disposition(capability, decision) if is_endpoint else None
    for reference_name, outcome in reconciliation_cases:
        receipt = {"evidence_type": "EXTERNAL_RECONCILIATION", "outcome": outcome, "transaction_id": "tx:one", "decision_digest": decision["decision_digest"], "capability_digest": capability["capability_digest"], "envelope_digest": capability["bindings"]["authorized_envelope_digest"], "contract_digest": capability["bindings"]["contract_digest"], "lineage_digest": canonical_digest_for_test(capability["lineage"]), "dispatch_intent_digest": digest("2"), "idempotency_key_digest": identity.get("idempotency_key_digest", digest("6")), "object_identity": identity, "fencing_epoch": post_dispatch_fence, "connector_id": identity.get("connector_id", "connector:reference"), "connector_evidence_digest": digest("8"), "chain_digest": digest("7"), "verified_at": capability["issued_at"], "expires_at": capability["expires_at"], "signature_verified": True, "not_revoked": True, "verified_by": "verifier:connector", "verifier_key_id": "key:connector", "verifier_trust_root": "trust:connector", "verifier_algorithm": "ED25519", "verifier_signature": "C" * 64}
        if outcome == "FAILURE_WITH_RESIDUAL_EFFECT":
            receipt["failure_disposition"] = deepcopy(failure_disposition)
        receipt["evidence_digest"] = canonical_digest_for_test(receipt)
        reconciliation[reference_name] = receipt
    compensation_authorizations = {}
    compensation_authorization_verifiers = {"verifier:compensation": {"verified_by": "verifier:compensation", "verifier_key_id": "key:compensation", "verifier_trust_root": "trust:compensation", "verifier_algorithm": "ED25519", "signature_verified": True, "not_revoked": True, "current_key": True}}
    if failure_disposition is not None:
        authorization = failure_disposition["compensation_authorization"]
        authorization_digest = canonical_digest_for_test(authorization)
        authorization_record = {**deepcopy(authorization), "authorization_digest": authorization_digest, "source_transaction_id": "tx:one", "failure_disposition_digest": canonical_digest_for_test(failure_disposition), "admitted_at": capability["issued_at"], "expires_at": capability["expires_at"], "signature_verified": True, "not_revoked": True, "verified_by": "verifier:compensation", "verifier_key_id": "key:compensation", "verifier_trust_root": "trust:compensation", "verifier_algorithm": "ED25519", "verifier_signature": "A" * 64}
        authorization_record["record_digest"] = canonical_digest_for_test(authorization_record)
        compensation_authorizations[authorization_digest] = authorization_record
    delegation_records = {}
    parent_capabilities = {}
    parent_statuses = {}
    parent_status_verifiers = {"verifier:parent-status": {"verified_by": "verifier:parent-status", "verifier_key_id": "key:parent-status", "verifier_trust_root": "trust:root", "verifier_algorithm": "ED25519", "signature_verified": True, "not_revoked": True, "current_key": True}}
    current_parent_fencing_epochs, current_parent_revocation_epochs = {}, {}
    if capability.get("delegation") is not None:
        item = capability["delegation"]
        delegation_records[capability["capability_digest"]] = {**{key: item[key] for key in ("parent_capability_id", "parent_capability_digest", "parent_envelope_digest", "parent_delegation_clause_digest", "root_lineage_digest", "edge_nonce", "child_principal", "child_audience", "fencing_epoch")}, "delegation_digest": canonical_digest_for_test(item), "parent_state": "ISSUED", "ancestor_revoked": False, "not_revoked": True, "verified_by": "verifier:delegation"}
        parent_capabilities[item["parent_capability_digest"]] = {"capability_id": item["parent_capability_id"], "capability_digest": item["parent_capability_digest"], "state": "ISSUED", "not_revoked": True, "signature_verified": True, "verified_by": "verifier:parent-capability"}
        parent_status = {"parent_capability_id": item["parent_capability_id"], "parent_capability_digest": item["parent_capability_digest"], "delegation_digest": canonical_digest_for_test(item), "parent_envelope_digest": item["parent_envelope_digest"], "parent_delegation_clause_digest": item["parent_delegation_clause_digest"], "root_lineage_digest": item["root_lineage_digest"], "fencing_epoch": item["fencing_epoch"], "parent_fencing_epoch": item["fencing_epoch"], "current_revocation_epoch": capability["revocation_epoch"], "parent_state": "ISSUED", "ancestor_revoked": False, "verified_at": capability["issued_at"], "expires_at": capability["expires_at"], "signature_verified": True, "not_revoked": True, "verified_by": "verifier:parent-status", "verifier_key_id": "key:parent-status", "verifier_trust_root": "trust:root", "verifier_algorithm": "ED25519", "verifier_signature": "P" * 64}
        parent_status["status_digest"] = canonical_digest_for_test(parent_status)
        parent_statuses[item["parent_capability_digest"]] = parent_status
        current_parent_fencing_epochs[item["parent_capability_digest"]] = item["fencing_epoch"]
        current_parent_revocation_epochs[item["parent_capability_digest"]] = capability["revocation_epoch"]
    reconciliation_verifiers = {"verifier:connector": {"verified_by": "verifier:connector", "verifier_key_id": "key:connector", "verifier_trust_root": "trust:connector", "verifier_algorithm": "ED25519", "signature_verified": True, "not_revoked": True, "current_key": True}}
    broker_ipc = deepcopy(IPC_FIXTURES[capability["bindings"]["broker_ipc_attestation_digest"]])
    broker_ipc_record = {"attestation": broker_ipc, "current_fencing_epoch": broker_ipc["session_fencing_epoch"], "current_revocation_epoch": broker_ipc["revocation_epoch"], **ipc_verifier_record(broker_ipc)}
    store = {"trusted_time": capability["issued_at"], "capabilities": {capability["capability_id"]: deepcopy(capability_record)}, "dispatch": {capability["capability_digest"]: dispatch_record}, "broker_ipc_attestations": {broker_ipc["attestation_digest"]: broker_ipc_record}, "verified_filesystem_targets": verified_filesystem_targets, "verified_endpoint_bindings": verified_endpoint_bindings, "delegations": delegation_records, "parent_capabilities": parent_capabilities, "parent_statuses": parent_statuses, "parent_status_verifiers": parent_status_verifiers, "current_parent_fencing_epochs": current_parent_fencing_epochs, "current_parent_revocation_epochs": current_parent_revocation_epochs, "iteration_slot_verifications": runtime_iteration_slot_verifications(capability, decision), "d2_frontier_verifications": runtime_d2_verifications(capability, decision), "d2_frontier_verifiers": {"verifier:d2-frontier": {"verified_by": "verifier:d2-frontier", "verifier_key_id": "key:d2-frontier", "verifier_trust_root": "trust:root", "verifier_algorithm": "ED25519", "signature_verified": True, "not_revoked": True, "current_key": True}}, "reconciliation": reconciliation, "reconciliation_verifiers": reconciliation_verifiers, "compensation_authorizations": compensation_authorizations, "compensation_authorization_verifiers": compensation_authorization_verifiers, "stage_evidence": stage_evidence, "commit": {"commit:one": commit}, "join": {"join:one": join}}
    state = reference.initial_state(branch, trusted_store=store, budget_vector=budget_vector or decision["reservations"])
    state.update(journal_sequence=frontier_record["journal_sequence"], fencing_epoch=frontier_record["fencing_epoch"], joined_iteration=frontier_record["joined_iteration"])
    records = []
    for kind in events:
        result = reference.reduce_transition(state, event_for(kind, decision, capability))
        assertion("T-LTS-STEP-" + kind, result["accepted"], result["reason_code"])
        if result["durable_record"] and result["durable_record"].get("dispatch_intent"): records.append(result["durable_record"])
        state = result["state"]
        assertion("T-BUDGET-CONSERVATION-" + kind, reference._conserved(state))
    return state, records


def make_external_endpoint_chain(reference, candidate: dict, decision: dict) -> tuple[dict, dict, dict, dict]:
    manifest = load(EXAMPLES / "valid/external-message.json")
    binding = endpoint_binding(manifest)
    candidate_endpoint = deepcopy(candidate)
    entries = []
    for clause in manifest["effect_bounds"]:
        resource = clause["resources"][0]
        entries.append({"entry_id": "auth:" + clause["clause_id"], "effect": clause["effect"], "resource_kind": resource["resource_kind"], "operation": resource["operations"][0], "selector": {"kind": "ENDPOINT_DESCRIPTOR", **deepcopy(binding), "resolution": "PINNED_EXACT_ENDPOINT"}, "facets": ["EXECUTE_EFFECT"], "constraints": {"direction": resource["direction"], "data_label": deepcopy(resource["data_label"]), "temporal": deepcopy(resource["temporal"]), "quantity": deepcopy(resource["quantity"]), "max_concurrency": resource["max_concurrency"], "flows": deepcopy(manifest["flow_rules"]), "obligations": deepcopy(manifest["assurance"]["obligations"])}})
    candidate_endpoint["operation_id"] = manifest["operation_id"]
    candidate_endpoint["authority_alternatives"] = [{"alternative_id": "alt:external", "entries": deepcopy(entries)}]
    candidate_endpoint["selected_alternative_id"] = "alt:external"
    candidate_endpoint["bindings"].pop("descriptor_binding_digest", None)
    candidate_endpoint["bindings"]["endpoint_binding_digest"] = binding["endpoint_binding_digest"]
    candidate_endpoint["bindings"]["manifest_digest"] = canonical_digest_for_test(manifest)
    reservations = [{"name": row["name"], "unit": row["unit"], "amount": row["limit"], "scope_digest": row["scope_digest"], "lineage_root": row["lineage_root"]} for row in manifest["resource_envelope"]]
    candidate_endpoint["budget_demands"] = deepcopy(reservations)
    endpoint_decision = deepcopy(decision)
    endpoint_decision["authorized_envelope"] = [reference._decision_entry(entry) for entry in entries]
    endpoint_decision["authorized_effects"] = sorted({entry["effect"] for entry in entries})
    endpoint_decision["reservations"] = deepcopy(reservations)
    endpoint_decision["evaluation"]["manifest_digest"] = candidate_endpoint["bindings"]["manifest_digest"]
    endpoint_decision["evaluation"].pop("descriptor_binding_digest", None)
    endpoint_decision["evaluation"]["endpoint_binding_digest"] = binding["endpoint_binding_digest"]
    endpoint_decision["decision_digest"] = reference.canonical_digest({key: value for key, value in endpoint_decision.items() if key != "decision_digest"})
    capability = reference.mint_capability(endpoint_decision, candidate_endpoint)
    if capability is None:
        raise AssertionError("endpoint capability mint failed")
    return manifest, candidate_endpoint, endpoint_decision, capability


def check_budget_and_lifecycle(reference, candidate, manifest, policy, isolation, facts, decision, capability) -> tuple[int, int]:
    duplicate_demand = deepcopy(candidate); duplicate_demand["budget_demands"] = [{"name": "CALLS", "unit": "CALLS", "amount": 1}, {"name": "CALLS", "unit": "CALLS", "amount": 1}]
    denied = reference.decide(duplicate_demand, manifest, policy, isolation, facts)
    assertion("T-BUDGET-DUPLICATE-DEMAND-AGGREGATED", denied["decision"] == "DENY" and denied["reason_codes"] == ["BUDGET_EXCEEDED_OR_DUPLICATE_BOUND"])
    duplicate_bound = deepcopy(policy); duplicate_bound["budgets"].append({"name": "CALLS", "unit": "CALLS", "limit": 100, "scope": "SESSION", "reset": "NEVER"})
    denied = reference.decide(candidate, manifest, duplicate_bound, isolation, facts)
    assertion("T-BUDGET-DUPLICATE-BOUND-REJECTED", denied["decision"] == "DENY")
    state = reference.initial_state("STAGEABLE", trusted_store={"iteration_slot_verifications": runtime_iteration_slot_verifications(capability, decision), "d2_frontier_verifications": runtime_d2_verifications(capability, decision), "d2_frontier_verifiers": {"verifier:d2-frontier": {"verified_by": "verifier:d2-frontier", "verifier_key_id": "key:d2-frontier", "verifier_trust_root": "trust:root", "verifier_algorithm": "ED25519", "signature_verified": True, "not_revoked": True, "current_key": True}}, "trusted_time": capability["issued_at"]}, budget_vector=decision["reservations"])
    state.update(journal_sequence=decision["evaluation"]["d2_frontier_record"]["journal_sequence"], fencing_epoch=decision["evaluation"]["d2_frontier_record"]["fencing_epoch"], joined_iteration=decision["evaluation"]["d2_frontier_record"]["joined_iteration"])
    for kind in ("PROPOSE", "NORMALIZE", "CLASSIFY"):
        state = reference.reduce_transition(state, event_for(kind, decision, capability))["state"]
    assertion("T-ADMIT-NULL-DECISION", not reference.reduce_transition(state, {"type": "ADMIT", "decision": None})["accepted"])
    bad_decision = deepcopy(decision); bad_decision["authorized_envelope"][0]["operation"] = "DELETE"
    assertion("T-ADMIT-TAMPERED-DECISION", not reference.reduce_transition(state, {"type": "ADMIT", "decision": bad_decision})["accepted"])
    forged_pep = event_for("ADMIT", decision, capability); forged_pep["trusted_pep_verification"]["decision_digest"] = digest("0"); forged_pep["trusted_pep_verification"]["receipt_digest"] = canonical_digest_for_test({key: value for key, value in forged_pep["trusted_pep_verification"].items() if key != "receipt_digest"})
    assertion("T-ADMIT-EXTERNAL-PEP-FORGED-SELF-HASH", not reference.reduce_transition(state, forged_pep)["accepted"])
    full_events = ["PROPOSE", "NORMALIZE", "CLASSIFY", "ADMIT", "CALCULATE_RESERVATION", "ISSUE_CAPABILITY", "DURABLE_DISPATCH", "QUIESCE", "SEAL", "POSTCHECK_PASS", "COMMIT", "JOIN", "STOP"]
    lifecycle_limits = [{**deepcopy(item), "amount": item["amount"] * 2} for item in decision["reservations"]]
    stopped, records = advance(reference, "STAGEABLE", decision, capability, full_events, budget_vector=lifecycle_limits)
    assertion("T-CAPABILITY-DURABLE-CONSUME", capability["capability_digest"] in stopped["consumed_capability_digests"] and len(records) == 1)
    conflicted_admission = deepcopy(state); slot_key = f"{capability['bindings']['iteration_slot_digest']}:{state['fencing_epoch']}"; conflicted_admission["trusted_store"]["iteration_slot_verifications"][slot_key]["owner_request_digest"] = digest("b")
    assertion("T-Q84-ADMIT-CONFLICTING-SLOT-OWNER", not reference.reduce_transition(conflicted_admission, event_for("ADMIT", decision, capability))["accepted"])
    issued, _ = advance(reference, "STAGEABLE", decision, capability, ["PROPOSE", "NORMALIZE", "CLASSIFY", "ADMIT", "CALCULATE_RESERVATION", "ISSUE_CAPABILITY"])
    dispatch_slot_key = f"{capability['bindings']['iteration_slot_digest']}:{issued['fencing_epoch']}"
    stale_dispatch = deepcopy(issued); stale_dispatch["trusted_store"]["iteration_slot_verifications"][dispatch_slot_key]["current_fencing_epoch"] = 0
    assertion("T-Q84-DISPATCH-STALE-SLOT-FENCE", not reference.reduce_transition(stale_dispatch, event_for("DURABLE_DISPATCH", decision, capability))["accepted"])
    conflicting_dispatch = deepcopy(issued); conflicting_dispatch["trusted_store"]["iteration_slot_verifications"][dispatch_slot_key]["owner_request_digest"] = digest("b")
    assertion("T-Q84-DISPATCH-CONFLICTING-SLOT-OWNER", not reference.reduce_transition(conflicting_dispatch, event_for("DURABLE_DISPATCH", decision, capability))["accepted"])
    executing, _ = advance(reference, "STAGEABLE", decision, capability, ["PROPOSE", "NORMALIZE", "CLASSIFY", "ADMIT", "CALCULATE_RESERVATION", "ISSUE_CAPABILITY", "DURABLE_DISPATCH"])
    crashed = reference.reduce_transition(executing, {"type": "CRASH"})["state"]; crashed["trusted_store"]["iteration_slot_verifications"][f"{capability['bindings']['iteration_slot_digest']}:{crashed['fencing_epoch']}"]["fencing_epoch"] = 1
    assertion("T-Q84-RECOVERY-STALE-SLOT-FENCE", not reference.reduce_transition(crashed, {"type": "RECOVER_ORPHAN", "observed_fencing_epoch": crashed["fencing_epoch"]})["accepted"])
    committed, _ = advance(reference, "STAGEABLE", decision, capability, ["PROPOSE", "NORMALIZE", "CLASSIFY", "ADMIT", "CALCULATE_RESERVATION", "ISSUE_CAPABILITY", "DURABLE_DISPATCH", "QUIESCE", "SEAL", "POSTCHECK_PASS", "COMMIT"])
    stale_join = deepcopy(committed); stale_join["trusted_store"]["iteration_slot_verifications"][f"{capability['bindings']['iteration_slot_digest']}:{stale_join['fencing_epoch']}"]["freshness_verified"] = False
    assertion("T-Q84-JOIN-STALE-SLOT", not reference.reduce_transition(stale_join, event_for("JOIN", decision, capability))["accepted"])
    expired_join = deepcopy(committed); expired_join["trusted_store"]["trusted_time"] = capability["expires_at"]
    assertion("T-Q84-JOIN-EXPIRED-SLOT", not reference.reduce_transition(expired_join, event_for("JOIN", decision, capability))["accepted"])
    replay = stopped
    replay["trusted_store"]["d2_frontier_verifications"].update(runtime_d2_verifications(capability, decision, "tx:replay"))
    for kind in ("PROPOSE", "NORMALIZE", "CLASSIFY"):
        result = reference.reduce_transition(replay, event_for(kind, decision, capability, transaction_id="tx:replay")); replay = result["state"]
    result = reference.reduce_transition(replay, event_for("ADMIT", decision, capability, transaction_id="tx:replay"))
    assertion("T-Q92-REQUEST-ALIAS-CANNOT-REACH-SECOND-DISPATCH", not result["accepted"] and result["reason_code"] == "ADMIT_D2_FRONTIER_REDUCER_STATE_MISMATCH")
    assertion("T-CAPABILITY-REPLAY-AFTER-STOP", not result["accepted"])
    mismatch_state, _ = advance(reference, "STAGEABLE", decision, capability, ["PROPOSE", "NORMALIZE", "CLASSIFY", "ADMIT", "CALCULATE_RESERVATION", "ISSUE_CAPABILITY"])
    bad_dispatch = event_for("DURABLE_DISPATCH", decision, capability); bad_dispatch["execution_binding"] = deepcopy(bad_dispatch["execution_binding"]); bad_dispatch["execution_binding"]["session_epoch"] += 1
    assertion("T-DISPATCH-PLACEMENT-SESSION-MISMATCH", not reference.reduce_transition(mismatch_state, bad_dispatch)["accepted"])
    admitted_for_reservation = reference.reduce_transition(state, event_for("ADMIT", decision, capability))["state"]
    for name, mutate in (("DIMENSION_SWAP", lambda x: x["reservation_vector"].__setitem__(0, {**x["reservation_vector"][0], "unit": "BYTES"})), ("DUPLICATE", lambda x: x["reservation_vector"].append(deepcopy(x["reservation_vector"][0]))), ("SCOPE", lambda x: x["reservation_vector"].__setitem__(0, {**x["reservation_vector"][0], "scope_digest": digest("0")}))):
        bad = event_for("CALCULATE_RESERVATION", decision, capability); mutate(bad)
        assertion("T-RESERVATION-EXACT-" + name, not reference.reduce_transition(admitted_for_reservation, bad)["accepted"])
    bad_issue = event_for("ISSUE_CAPABILITY", decision, capability); bad_issue["capability"]["effects"] = deepcopy(bad_issue["capability"]["effects"]); bad_issue["capability"]["effects"][0]["operation"] = "DELETE"; bad_issue["capability"]["capability_digest"] = canonical_digest_for_test(bad_issue["capability"]); bad_issue["capability"]["issuer_verification"]["signed_claims_digest"] = canonical_digest_for_test(reference._capability_signed_claims(bad_issue["capability"]))
    assertion("T-CAPABILITY-EFFECTS-EXACT-ADMISSION", not reference.reduce_transition(mismatch_state, bad_issue)["accepted"])

    # Q-78: one exhausted key cannot borrow capacity from another key.
    calls_decision = deepcopy(decision)
    calls_decision["reservations"] = [deepcopy(decision["reservations"][0])]
    calls_decision["decision_digest"] = reference.canonical_digest({key: value for key, value in calls_decision.items() if key != "decision_digest"})
    calls_capability = reference.mint_capability(calls_decision, candidate)
    authoritative_limits = [deepcopy(calls_decision["reservations"][0]), {**deepcopy(decision["reservations"][1]), "amount": 100}]
    exhausted, keyed_records = advance(reference, "STAGEABLE", calls_decision, calls_capability, full_events, budget_vector=authoritative_limits)
    calls_key = next(iter(reference._budget_map(calls_decision["reservations"], "amount")))
    bytes_key = next(key for key in exhausted["budget_remaining_by_key"] if key[0] == "WRITE_BYTES")
    assertion("T-Q78-COMPONENT-WISE-EXHAUSTION-PRESERVED", exhausted["budget_remaining_by_key"][calls_key] == 0 and exhausted["budget_spent_by_key"][calls_key] == 1 and exhausted["budget_remaining_by_key"][bytes_key] == 100 and reference._conserved(exhausted))
    keyed_dispatch = keyed_records[0]["budget_reservation_by_key"] if len(keyed_records) == 1 else []
    assertion("T-Q78-DURABLE-DISPATCH-KEYED-VECTOR", [row for row in keyed_dispatch if row["amount"] > 0] == calls_decision["reservations"] and any(row["name"] == "WRITE_BYTES" and row["amount"] == 0 for row in keyed_dispatch))
    second = exhausted
    second["trusted_store"]["d2_frontier_verifications"].update(runtime_d2_verifications(calls_capability, calls_decision, "tx:second"))
    for kind in ("PROPOSE", "NORMALIZE", "CLASSIFY"):
        second = reference.reduce_transition(second, event_for(kind, calls_decision, calls_capability, transaction_id="tx:second"))["state"]
    second_attempt = reference.reduce_transition(second, event_for("ADMIT", calls_decision, calls_capability, transaction_id="tx:second"))
    assertion("T-Q78-NO-CROSS-KEY-SUBSTITUTION", not second_attempt["accepted"] and second_attempt["reason_code"] == "ADMIT_D2_FRONTIER_REDUCER_STATE_MISMATCH" and second_attempt["state"]["budget_remaining_by_key"][bytes_key] == 100)
    swapped_scope = event_for("CALCULATE_RESERVATION", calls_decision, calls_capability); swapped_scope["reservation_vector"][0]["scope_digest"] = digest("0"); swapped_scope["reservation_vector_digest"] = canonical_digest_for_test(swapped_scope["reservation_vector"])
    assertion("T-Q78-SCOPE-LINEAGE-KEY-SWAP-REJECTED", not reference.reduce_transition(second, swapped_scope)["accepted"])
    return len(full_events), len(records)


def check_authority_d2_path(reference, candidate, manifest, policy, isolation, facts) -> int:
    count = 0
    for name, effect, kind, operation in (("MUTATE_READ", "MUTATE", "FILE", "READ"), ("COMPUTE_WRITE", "COMPUTE", "PROCESS", "WRITE"), ("REFLECT_READ", "REFLECT", "FILE", "READ"), ("DELEGATE_DELETE", "DELEGATE", "PRINCIPAL", "DELETE")):
        bad = deepcopy(candidate); entry = bad["authority_alternatives"][0]["entries"][0]; entry.update(effect=effect, resource_kind=kind, operation=operation)
        assertion("T-Q27-CLOSED-RELATION-" + name, not schema_valid("admission-candidate.schema.json", bad) and not reference.validate_authority_entry(entry)); count += 1
    legal = deepcopy(candidate)["authority_alternatives"][0]["entries"][1]
    assertion("T-Q27-LEGAL-MUTATE-FILE-WRITE", schema_valid("admission-candidate.schema.json", candidate) and reference.validate_authority_entry(legal)); count += 1
    unbound_derived = deepcopy(manifest); unbound_derived["effect_bounds"][0]["derived_effects"] = ["clause:missing"]
    assertion("T-Q79-UNBOUND-DERIVED-EFFECT-DENY", reference._manifest_derived_closure(unbound_derived, candidate["authority_alternatives"][0]["entries"]) is None)
    cyclic_derived = deepcopy(manifest); cyclic_derived["effect_bounds"][0]["derived_effects"] = ["clause:write-file-mutate"]
    assertion("T-Q79-CYCLIC-DERIVED-EFFECT-DENY", reference._manifest_derived_closure(cyclic_derived, candidate["authority_alternatives"][0]["entries"]) is None)
    unrelated_manifest = deepcopy(manifest)
    unrelated_resource = deepcopy(unrelated_manifest["effect_bounds"][0]["resources"][0])
    unrelated_resource["selector"]["value"] = "/workspace/output/unrelated.txt"
    unrelated_manifest["effect_bounds"][0]["derived_effects"] = ["clause:unrelated-mutate"]
    unrelated_manifest["effect_bounds"].append({"clause_id": "clause:unrelated-mutate", "effect": "MUTATE", "resources": [unrelated_resource], "derived_effects": [], "uncertainty": "BOUNDED"})
    unrelated_candidate, unrelated_facts = deepcopy(candidate), deepcopy(facts)
    _rebind_manifest(reference, unrelated_candidate, unrelated_manifest, unrelated_facts)
    assertion("T-Q79-UNRELATED-TYPED-MUTATE-DENY", schema_valid("effect-manifest.schema.json", unrelated_manifest) and reference.decide(unrelated_candidate, unrelated_manifest, policy, isolation, unrelated_facts)["reason_codes"] == ["DERIVED_CLAUSE_UNAUTHORIZED"])
    dependent = deepcopy(manifest); notify_resource = deepcopy(dependent["effect_bounds"][0]["resources"][0]); notify_binding = endpoint_binding(); notify_binding.update(endpoint_id="endpoint:notify", canonical_endpoint="https://example.invalid/notify"); notify_binding["endpoint_binding_digest"] = canonical_digest_for_test({key: value for key, value in notify_binding.items() if key != "endpoint_binding_digest"}); notify_resource.update(resource_kind="ENDPOINT", operations=["SEND"], selector={"kind": "ENDPOINT_EXACT", "value": notify_binding["canonical_endpoint"], "endpoint_binding": notify_binding}); dependent["effect_bounds"][0]["derived_effects"] = ["clause:notify"]; dependent["effect_bounds"].append({"clause_id": "clause:notify", "effect": "COMMUNICATE", "resources": [notify_resource], "derived_effects": [], "uncertainty": "BOUNDED"})
    dependent_candidate, dependent_facts = deepcopy(candidate), deepcopy(facts); dependent_manifest_digest = reference.canonical_digest(dependent); dependent_candidate["bindings"]["manifest_digest"] = dependent_manifest_digest; dependent_manifest_record = deepcopy(dependent_facts["verified_manifests"].pop(candidate["bindings"]["manifest_digest"])); dependent_manifest_record.update(manifest_digest=dependent_manifest_digest, signed_payload_digest=dependent_manifest_digest); dependent_facts["verified_manifests"][dependent_manifest_digest] = dependent_manifest_record
    assertion("T-Q79-MISSING-REACHABLE-CLAUSE-DENY", schema_valid("effect-manifest.schema.json", dependent) and reference.decide(dependent_candidate, dependent, policy, isolation, dependent_facts)["reason_codes"] == ["DERIVED_CLAUSE_UNAUTHORIZED"])
    external_manifest = load(EXAMPLES / "valid/external-message.json")
    external_binding = endpoint_binding(external_manifest)
    external_entries = []
    for clause in external_manifest["effect_bounds"]:
        resource = clause["resources"][0]
        external_entries.append({"entry_id": "auth:" + clause["clause_id"], "effect": clause["effect"], "resource_kind": resource["resource_kind"], "operation": resource["operations"][0], "selector": {"kind": "ENDPOINT_DESCRIPTOR", **deepcopy(external_binding), "resolution": "PINNED_EXACT_ENDPOINT"}, "facets": ["EXECUTE_EFFECT"], "constraints": {"direction": resource["direction"], "data_label": deepcopy(resource["data_label"]), "temporal": deepcopy(resource["temporal"]), "quantity": deepcopy(resource["quantity"]), "max_concurrency": resource["max_concurrency"], "flows": deepcopy(external_manifest["flow_rules"]), "obligations": ["event.emit"]}})
    positive = deepcopy(candidate); positive["authority_alternatives"] = [{"alternative_id": "alt:external", "entries": external_entries}]; positive["selected_alternative_id"] = "alt:external"; positive["bindings"].pop("descriptor_binding_digest"); positive["bindings"]["endpoint_binding_digest"] = external_binding["endpoint_binding_digest"]
    positive_closure = reference._manifest_derived_closure(external_manifest, external_entries)
    assertion("T-Q79-EXACT-COMMUNICATE-MUTATE-CLOSURE", schema_valid("admission-candidate.schema.json", positive) and positive_closure is not None and len(positive_closure) == 2 and all(reference._manifest_clause_atoms_covered(external_manifest, clause, external_entries) for clause in positive_closure))
    mismatched_manifest = deepcopy(external_manifest); mismatched_selector = mismatched_manifest["effect_bounds"][0]["resources"][0]["selector"]; mismatched_selector["endpoint_binding"]["canonical_endpoint"] = "https://messages.example.test/v1/other"; mismatched_selector["endpoint_binding"]["endpoint_binding_digest"] = canonical_digest_for_test({key: value for key, value in mismatched_selector["endpoint_binding"].items() if key != "endpoint_binding_digest"})
    assertion("T-Q82-MANIFEST-ENDPOINT-VALUE-BINDING-MISMATCH", schema_valid("effect-manifest.schema.json", mismatched_manifest) and not reference._manifest_covers(mismatched_manifest, external_entries[0]))
    endpoint_candidate, endpoint_policy, endpoint_isolation, endpoint_facts = deepcopy(positive), deepcopy(policy), deepcopy(isolation), deepcopy(facts)
    endpoint_candidate["operation_id"] = external_manifest["operation_id"]
    endpoint_candidate["budget_demands"] = [{"name": row["name"], "unit": row["unit"], "amount": row["limit"], "scope_digest": row["scope_digest"], "lineage_root": row["lineage_root"]} for row in external_manifest["resource_envelope"]]
    for role in endpoint_isolation["principal_envelopes"]:
        if role["principal"] == endpoint_candidate["audience"]:
            role["effect_ceiling"] = sorted(set(role["effect_ceiling"]) | {"COMMUNICATE"})
    for route in endpoint_isolation["compiled_envelopes"]:
        route.update(allowed_effects=["COMMUNICATE", "MUTATE"], allowed_resource_kinds=["ENDPOINT"], allowed_operations=["SEND", "UPDATE"], endpoint_bindings=[deepcopy(external_binding)], effect_resource_operations=[{"effect": "COMMUNICATE", "resource_kind": "ENDPOINT", "operation": "SEND"}, {"effect": "MUTATE", "resource_kind": "ENDPOINT", "operation": "UPDATE"}])
        route.pop("allowed_scopes", None); route.pop("filesystem_targets", None)
    endpoint_isolation["risk_class"] = "MEDIATED_EXTERNAL"
    refresh_profile_activation(reference, endpoint_isolation, endpoint_facts, endpoint_candidate)
    endpoint_manifest = deepcopy(external_manifest)
    endpoint_policy["physical_ceiling"]["mediated_sink_effects"] = sorted(set(endpoint_policy["physical_ceiling"]["mediated_sink_effects"]) | {"COMMUNICATE"})
    budget_names = [row["name"] for row in endpoint_candidate["budget_demands"]]
    endpoint_policy["authority_map"] = [{"operation_id": endpoint_candidate["operation_id"], "correlation_id": "alt:external", "effect": entry["effect"], "resource_kind": "ENDPOINT", "operations": [entry["operation"]], "scope": {"kind": "ENDPOINT", "values": [external_binding["canonical_endpoint"]], "endpoint_binding": deepcopy(external_binding)}, "facets": deepcopy(entry["facets"]), "authority_constraints_digest": canonical_digest_for_test(entry["constraints"]), "flows": [], "budget_names": budget_names, "obligations": deepcopy(external_manifest["assurance"]["obligations"]), "approval_class": "NONE"} for entry in external_entries]
    endpoint_policy["budgets"] = [{"name": row["name"], "unit": row["unit"], "limit": row["amount"], "scope": "CALL", "reset": "NEVER", "scope_digest": row["scope_digest"], "lineage_root": row["lineage_root"]} for row in endpoint_candidate["budget_demands"]]
    refresh_profile_consumers(reference, endpoint_manifest, endpoint_policy, endpoint_isolation, endpoint_facts, endpoint_candidate)
    refresh_broker_ipc_attestation(reference, endpoint_candidate, endpoint_isolation, endpoint_facts)
    endpoint_facts["remaining_budgets"] = deepcopy(endpoint_candidate["budget_demands"])
    endpoint_facts["verified_endpoint_bindings"] = {external_binding["endpoint_binding_digest"]: {**deepcopy(external_binding), "signature_verified": True, "not_revoked": True, "current_key": True, "verified_by": "verifier:endpoint", "key_id": "key:connector", "trust_root": "trust:connector", "algorithm": "ED25519", "verified_at": endpoint_candidate["evaluated_at"], "expires_at": endpoint_manifest["lifecycle"]["expires_at"]}}
    endpoint_contract = make_loop_contract(reference, endpoint_candidate, endpoint_manifest, endpoint_policy, endpoint_isolation)
    endpoint_candidate["bindings"].update(contract_id=endpoint_contract["contract_id"], contract_digest=endpoint_contract["contract_digest"])
    endpoint_candidate["session_attestation"]["contract_digest"] = endpoint_contract["contract_digest"]
    endpoint_candidate["d2_frontier"].update(contract_digest=endpoint_contract["contract_digest"], root_contract_digest=endpoint_contract["contract_digest"])
    endpoint_candidate["d2_frontier"]["frontier_record_digest"] = canonical_digest_for_test({key: value for key, value in endpoint_candidate["d2_frontier"].items() if key != "frontier_record_digest"})
    endpoint_candidate["iteration_slot"]["root_contract_digest"] = endpoint_contract["contract_digest"]
    endpoint_candidate["iteration_slot"]["slot_key_digest"] = canonical_digest_for_test({key: endpoint_candidate["iteration_slot"][key] for key in ("authority_domain_id", "root_contract_digest", "journal_lineage_id", "iteration")})
    endpoint_candidate["iteration_slot"]["slot_record_digest"] = canonical_digest_for_test({key: value for key, value in endpoint_candidate["iteration_slot"].items() if key != "slot_record_digest"})
    endpoint_facts["d2_frontier_digest"] = endpoint_candidate["d2_frontier"]["frontier_record_digest"]
    endpoint_facts["authoritative_d2_frontier"] = {**deepcopy(endpoint_candidate["d2_frontier"]), "signature_verified": True, "not_revoked": True, "freshness_verified": True, "verified_by": "verifier:d2-frontier"}
    endpoint_facts["trusted_loop_contracts"] = {endpoint_contract["contract_digest"]: deepcopy(endpoint_contract)}
    endpoint_facts["verified_loop_contracts"] = {endpoint_contract["contract_digest"]: {"contract": deepcopy(endpoint_contract), "signature_verified": True, "not_revoked": True, "freshness_verified": True, "current_key": True, "current_revocation_epoch": 3}}
    endpoint_facts["active_iteration_slots"] = {endpoint_candidate["iteration_slot"]["slot_key_digest"]: {"slot": deepcopy(endpoint_candidate["iteration_slot"]), "signature_verified": True, "not_revoked": True, "freshness_verified": True, "current_fence": True, "fencing_epoch": 3, "owner_request_digest": endpoint_candidate["request_digest"]}}
    endpoint_candidate, endpoint_facts = _signed_attestation_fixture(endpoint_candidate, endpoint_facts)
    endpoint_result = reference.decide(endpoint_candidate, endpoint_manifest, endpoint_policy, endpoint_isolation, endpoint_facts)
    endpoint_capability = reference.mint_capability(endpoint_result, endpoint_candidate)
    if endpoint_capability is not None:
        endpoint_facts["verified_capability_claims"][endpoint_capability["capability_id"]] = reference.capability_verifier_record(endpoint_capability)
    assertion("T-Q82-ENDPOINT-ADMISSION-MINT-EXACT", all((schema_valid("effect-manifest.schema.json", endpoint_manifest), schema_valid("admission-candidate.schema.json", endpoint_candidate), schema_valid("runtime-policy.schema.json", endpoint_policy), schema_valid("isolation-profile.schema.json", endpoint_isolation), endpoint_result["decision"] == "ALLOW", schema_valid("decision-result.schema.json", endpoint_result), endpoint_capability is not None, schema_valid("capability.schema.json", endpoint_capability), reference.validate_capability(endpoint_capability, endpoint_result, endpoint_candidate, endpoint_facts))))
    file_first_endpoint_selected = deepcopy(endpoint_candidate); file_first_endpoint_selected["authority_alternatives"].insert(0, deepcopy(candidate["authority_alternatives"][0])); file_first_endpoint_selected["bindings"].pop("endpoint_binding_digest"); file_first_endpoint_selected["bindings"]["descriptor_binding_digest"] = candidate["bindings"]["descriptor_binding_digest"]
    assertion("T-Q82-SELECTED-ENDPOINT-CANNOT-USE-FIRST-FILE-BINDING", schema_valid("admission-candidate.schema.json", file_first_endpoint_selected) and reference.decide(file_first_endpoint_selected, endpoint_manifest, endpoint_policy, endpoint_isolation, endpoint_facts)["reason_codes"] == ["TARGET_BINDING_MISMATCH"])
    endpoint_first_file_selected = deepcopy(endpoint_candidate); endpoint_first_file_selected["authority_alternatives"].append(deepcopy(candidate["authority_alternatives"][0])); endpoint_first_file_selected["selected_alternative_id"] = candidate["selected_alternative_id"]
    assertion("T-Q82-SELECTED-FILE-CANNOT-USE-FIRST-ENDPOINT-BINDING", schema_valid("admission-candidate.schema.json", endpoint_first_file_selected) and reference.decide(endpoint_first_file_selected, endpoint_manifest, endpoint_policy, endpoint_isolation, endpoint_facts)["reason_codes"] == ["TARGET_BINDING_MISMATCH"])
    profile_mismatch_manifest, profile_mismatch_candidate, profile_mismatch_facts = deepcopy(endpoint_manifest), deepcopy(endpoint_candidate), deepcopy(endpoint_facts); profile_mismatch_manifest["runtime_requirements"]["isolation_profile_id"] = "isolation:other"; _rebind_manifest(reference, profile_mismatch_candidate, profile_mismatch_manifest, profile_mismatch_facts)
    assertion("T-Q82-MANIFEST-ISOLATION-PROFILE-MISMATCH", reference.decide(profile_mismatch_candidate, profile_mismatch_manifest, endpoint_policy, endpoint_isolation, profile_mismatch_facts)["reason_codes"] == ["PROFILE_MISMATCH"])
    policy_profile_mismatch, policy_profile_facts, policy_profile_candidate = deepcopy(endpoint_policy), deepcopy(endpoint_facts), deepcopy(endpoint_candidate); policy_profile_mismatch["physical_ceiling"]["isolation_profile_id"] = "isolation:other"; refresh_policy_activation(reference, policy_profile_mismatch, policy_profile_facts, policy_profile_candidate)
    assertion("T-Q82-POLICY-ISOLATION-PROFILE-MISMATCH", reference.decide(policy_profile_candidate, endpoint_manifest, policy_profile_mismatch, endpoint_isolation, policy_profile_facts)["reason_codes"] == ["PROFILE_MISMATCH"])
    missing_endpoint_route = deepcopy(endpoint_isolation); missing_endpoint_route["compiled_envelopes"][0].pop("endpoint_bindings")
    assertion("T-Q82-ENDPOINT-COMPILED-BINDING-REQUIRED", not schema_valid("isolation-profile.schema.json", missing_endpoint_route))
    substituted_policy, substituted_facts, substituted_candidate = deepcopy(endpoint_policy), deepcopy(endpoint_facts), deepcopy(endpoint_candidate); substituted_binding = substituted_policy["authority_map"][0]["scope"]["endpoint_binding"]; substituted_binding["connector_id"] = "connector:other"; substituted_binding["endpoint_binding_digest"] = canonical_digest_for_test({key: value for key, value in substituted_binding.items() if key != "endpoint_binding_digest"}); refresh_policy_activation(reference, substituted_policy, substituted_facts, substituted_candidate)
    assertion("T-Q82-POLICY-ENDPOINT-BINDING-SUBSTITUTION", reference.decide(substituted_candidate, endpoint_manifest, substituted_policy, endpoint_isolation, substituted_facts)["reason_codes"] == ["SCOPE_EXCEEDS_CORRELATED_POLICY"])
    principal_mismatch = deepcopy(candidate); principal_mismatch["principal"] = "agent:other"
    assertion("T-ISOLATION-COMPILED-PRINCIPAL-AUDIENCE", reference.decide(principal_mismatch, manifest, policy, isolation, facts)["reason_codes"] == ["ISOLATION_PRINCIPAL_AUDIENCE_MISMATCH"])
    executor_mismatch, mismatch_manifest, mismatch_policy, mismatch_facts, mismatch_candidate = deepcopy(isolation), deepcopy(manifest), deepcopy(policy), deepcopy(facts), deepcopy(candidate); executor_mismatch["compiled_envelopes"][0]["allowed_scopes"] = ["/workspace/output/other.txt"]; target = executor_mismatch["compiled_envelopes"][0]["filesystem_targets"][0]; target["canonical_path"] = "/workspace/output/other.txt"; target["composite_binding_digest"] = canonical_digest_for_test({key: value for key, value in target.items() if key != "composite_binding_digest"})
    refresh_profile_activation(reference, executor_mismatch, mismatch_facts, mismatch_candidate)
    refresh_profile_consumers(reference, mismatch_manifest, mismatch_policy, executor_mismatch, mismatch_facts, mismatch_candidate)
    assertion("T-ISOLATION-COMPILED-EXECUTOR-ENVELOPE", reference.decide(mismatch_candidate, mismatch_manifest, mismatch_policy, executor_mismatch, mismatch_facts)["reason_codes"] == ["ISOLATION_ENVELOPE_MISMATCH"])
    missing_target = deepcopy(isolation); missing_target["compiled_envelopes"][0].pop("filesystem_targets")
    assertion("T-Q80-FILESYSTEM-TARGET-SCHEMA-REQUIRED", not schema_valid("isolation-profile.schema.json", missing_target))
    for name, field, value in (("ROOT", "root_id", "root:other"), ("MOUNT", "mount_id", "mount:other"), ("EPOCH", "resolution_epoch", 4)):
        alternate, alternate_manifest, alternate_policy, alternate_facts, alternate_candidate = deepcopy(isolation), deepcopy(manifest), deepcopy(policy), deepcopy(facts), deepcopy(candidate)
        target = alternate["compiled_envelopes"][0]["filesystem_targets"][0]; target[field] = value; target["composite_binding_digest"] = canonical_digest_for_test({key: value for key, value in target.items() if key != "composite_binding_digest"})
        refresh_profile_activation(reference, alternate, alternate_facts, alternate_candidate)
        refresh_profile_consumers(reference, alternate_manifest, alternate_policy, alternate, alternate_facts, alternate_candidate)
        assertion("T-Q80-SAME-PATH-" + name + "-STOP", reference.decide(alternate_candidate, alternate_manifest, alternate_policy, alternate, alternate_facts)["reason_codes"] == ["COMPILED_FILESYSTEM_TARGET_MISMATCH"])
    coherent_manifest, coherent_policy, coherent_isolation, coherent_candidate, coherent_facts = deepcopy(manifest), deepcopy(policy), deepcopy(isolation), deepcopy(candidate), deepcopy(facts)
    coherent_target = coherent_isolation["compiled_envelopes"][0]["filesystem_targets"][0]
    for route in coherent_isolation["compiled_envelopes"]:
        target = route["filesystem_targets"][0]; target.update(root_id="root:other", root_identity="root:other"); target["composite_binding_digest"] = canonical_digest_for_test({key: value for key, value in target.items() if key != "composite_binding_digest"})
    coherent_target = coherent_isolation["compiled_envelopes"][0]["filesystem_targets"][0]
    coherent_descriptor_digest = reference.canonical_digest({"descriptor_id": coherent_target["descriptor_id"], "root_identity": coherent_target["root_identity"], "mount_identity": coherent_target["mount_identity"], "epoch": coherent_target["resolution_epoch"]})
    for entry in coherent_candidate["authority_alternatives"][0]["entries"]:
        entry["selector"].update(descriptor_binding_digest=coherent_descriptor_digest, physical_target_digest=coherent_target["composite_binding_digest"])
    coherent_candidate["bindings"]["descriptor_binding_digest"] = coherent_descriptor_digest
    coherent_manifest["effect_bounds"][0]["resources"][0]["selector"].update(descriptor_binding_digest=coherent_descriptor_digest, physical_target_digest=coherent_target["composite_binding_digest"])
    coherent_policy["authority_map"][0]["scope"].update(descriptor_binding_digest=coherent_descriptor_digest, physical_target_digest=coherent_target["composite_binding_digest"])
    refresh_profile_activation(reference, coherent_isolation, coherent_facts, coherent_candidate); refresh_profile_consumers(reference, coherent_manifest, coherent_policy, coherent_isolation, coherent_facts, coherent_candidate)
    coherent_facts["trusted_descriptors"]["fd:output"].update(root_id="root:other", root_identity="root:other")
    coherent_facts["trusted_loop_contracts"][coherent_candidate["bindings"]["contract_digest"]]["authority_digest"] = reference.canonical_digest(coherent_candidate["authority_alternatives"][0]["entries"])
    assertion("T-Q80-COHERENT-HIGHER-REBIND-STOP", reference.decide(coherent_candidate, coherent_manifest, coherent_policy, coherent_isolation, coherent_facts)["reason_codes"] == ["COMPILED_FILESYSTEM_TARGET_MISMATCH"])
    decision = reference.decide(candidate, manifest, policy, isolation, facts)
    capability = reference.mint_capability(decision, candidate)
    issued_target, _ = advance(reference, "STAGEABLE", decision, capability, ["PROPOSE", "NORMALIZE", "CLASSIFY", "ADMIT", "CALCULATE_RESERVATION", "ISSUE_CAPABILITY"])
    dispatch_identity = {**object_identity(), "root_id": "root:other", "final_object_id": "object:other", "final_object_digest": digest("b")}; dispatch_target = issued_target["trusted_store"]["dispatch"][issued_target["capability_digest"]]["physical_target"]; dispatch_target.update(root_id="root:other", root_identity="root:other", final_object_id="object:other", final_object_digest=digest("b")); dispatch_target["composite_binding_digest"] = canonical_digest_for_test({key: value for key, value in dispatch_target.items() if key != "composite_binding_digest"}); issued_target["trusted_store"]["verified_filesystem_targets"] = {dispatch_target["composite_binding_digest"]: {**deepcopy(dispatch_target), "physical_target_digest": dispatch_target["composite_binding_digest"]}}; issued_target["trusted_store"]["dispatch"][issued_target["capability_digest"]]["object_identity"] = dispatch_identity
    dispatch_result = reference.reduce_transition(issued_target, event_for("DURABLE_DISPATCH", decision, capability, object_identity=dispatch_identity))
    assertion("T-Q80-DISPATCH-IMMUTABLE-CAPABILITY-TARGET", not dispatch_result["accepted"] and dispatch_result["reason_code"] == "DISPATCH_PHYSICAL_TARGET_MISMATCH")
    for flag in reference.D2_FLAGS:
        mutated = deepcopy(candidate); artifact = deepcopy(mutated["d2_frontier"]["inventory"][0]); artifact.update(iteration=2, **{name: False for name in reference.D2_FLAGS}); artifact[flag] = True; mutated["d2_frontier"]["inventory"].append(artifact)
        result = reference.decide(mutated, manifest, policy, isolation, facts)
        assertion("T-D2-CLASS-" + flag.upper(), result["reason_codes"] == ["D2_TYPED_FRONTIER_VIOLATION"]); count += 1
    for artifact_class in sorted(reference.D2_CLASSES):
        mutated = deepcopy(candidate); artifact = deepcopy(mutated["d2_frontier"]["inventory"][0]); artifact.update({name: False for name in reference.D2_FLAGS}); artifact.update(iteration=2, **{"class": artifact_class, "controller_visible": True}); mutated["d2_frontier"]["inventory"].append(artifact)
        result = reference.decide(mutated, manifest, policy, isolation, facts)
        assertion("T-D2-ARTIFACT-" + artifact_class, result["reason_codes"] == ["D2_TYPED_FRONTIER_VIOLATION"]); count += 1
    mutated = deepcopy(candidate); artifact = deepcopy(mutated["d2_frontier"]["inventory"][0]); artifact.update({name: False for name in reference.D2_FLAGS}); artifact.update(iteration=2, artifact_id="artifact:future"); mutated["d2_frontier"]["inventory"].append(artifact)
    assertion("T-D2-CLASS-BASED-ALL-FLAGS-FALSE", reference.decide(mutated, manifest, policy, isolation, facts)["reason_codes"] == ["D2_TYPED_FRONTIER_VIOLATION"]); count += 1
    mutated = deepcopy(candidate); mutated["iteration"] = 5; mutated["d2_frontier"]["joined_iteration"] = 4
    assertion("T-D2-MAX-ITERATION", reference.decide(mutated, manifest, policy, isolation, facts)["reason_codes"] == ["D2_TYPED_FRONTIER_VIOLATION"]); count += 1
    mutated = deepcopy(candidate); mutated["d2_frontier"]["durable_state_digest"] = digest("0")
    assertion("T-D2-DURABLE-SNAPSHOT-BINDING", reference.decide(mutated, manifest, policy, isolation, facts)["reason_codes"] == ["D2_TYPED_FRONTIER_VIOLATION"]); count += 1
    ill_typed = deepcopy(candidate); entry = ill_typed["authority_alternatives"][0]["entries"][0]; entry.update(effect="OBSERVE", operation="SEND", resource_kind="FILE", selector={"kind": "ENDPOINT_DESCRIPTOR", "endpoint_id": "endpoint:bad", "canonical_endpoint": "https://example.test/send", "resolution": "PINNED_EXACT_ENDPOINT"})
    assertion("T-AUTHORITY-ILL-TYPED-SCHEMA", not schema_valid("admission-candidate.schema.json", ill_typed) and not reference.validate_authority_entry(entry))
    cross = deepcopy(candidate); cross["selected_alternative_id"] = "alt:other"
    result = reference.decide(cross, manifest, policy, isolation, facts)
    assertion("T-AUTHORITY-CORRELATED-NO-CROSS-PAIR", result["reason_codes"] == ["ISOLATION_ENVELOPE_MISMATCH"])
    for path_index, suffix in enumerate(("/../../etc/passwd", "/%2e%2e/etc/passwd", "\\..\\etc\\passwd"), start=6):
        path = "/workspace/output" + suffix
        mutated = deepcopy(candidate); mutated["authority_alternatives"][0]["entries"][0]["selector"]["canonical_path"] = path
        assertion("T-PATH-DESCRIPTOR-REJECT-" + str(path_index), not reference.validate_authority_entry(mutated["authority_alternatives"][0]["entries"][0]), path); count += 1
    for name, path in (("OUTSIDE", "/workspace/input/report.txt"), ("SIBLING", "/workspace/output/report.txt.bak"), ("ENCODED", "/workspace/output/%2e%2e/report.txt")):
        mutated = deepcopy(candidate); mutated["authority_alternatives"][0]["entries"][0]["selector"]["canonical_path"] = path
        result = reference.decide(mutated, manifest, policy, isolation, facts)
        expected_reason = {"OUTSIDE": "DERIVED_CLAUSE_UNAUTHORIZED", "SIBLING": "ISOLATION_ENVELOPE_MISMATCH", "ENCODED": "AUTHORITY_ALTERNATIVE_MALFORMED"}[name]
        assertion("T-Q32-TYPED-CONTAINMENT-" + name, result["reason_codes"] == [expected_reason]); count += 1
    missing_manifest_facts = deepcopy(facts); missing_manifest_facts.pop("verified_manifests")
    assertion("T-Q34-MANIFEST-EXTERNAL-FACT-REQUIRED", reference.decide(candidate, manifest, policy, isolation, missing_manifest_facts)["reason_codes"] == ["MANIFEST_TRUST_INVALID"]); count += 1
    forged_manifest = deepcopy(manifest); forged_manifest["effect_bounds"][0]["uncertainty"] = "UNKNOWN"; forged_candidate = deepcopy(candidate); forged_candidate["bindings"]["manifest_digest"] = reference.canonical_digest(forged_manifest); forged_facts = deepcopy(facts); old = forged_facts["verified_manifests"].pop(candidate["bindings"]["manifest_digest"]); old.update(manifest_digest=forged_candidate["bindings"]["manifest_digest"], signed_payload_digest=forged_candidate["bindings"]["manifest_digest"]); forged_facts["verified_manifests"][forged_candidate["bindings"]["manifest_digest"]] = old
    assertion("T-Q34-MANIFEST-REHASHED-FORGERY-DENY", reference.decide(forged_candidate, forged_manifest, policy, isolation, forged_facts)["reason_codes"] == ["MANIFEST_DERIVED_CLOSURE_INVALID"]); count += 1
    allowed = reference.decide(candidate, manifest, policy, isolation, facts)
    assertion("T-AUTHORITY-CLOSED-CLAUSE-PRESERVED", allowed["authorized_envelope"][0]["constraints"] == candidate["authority_alternatives"][0]["entries"][0]["constraints"]); count += 1
    for name, mutate in (
        ("FACET", lambda x: x["facets"].append("AUTHORIZE_EFFECT")),
        ("DIRECTION", lambda x: x["constraints"].update(direction="INTERNAL")),
        ("LABEL", lambda x: x["constraints"]["data_label"].update(confidentiality="RESTRICTED")),
        ("TIME", lambda x: x["constraints"]["temporal"].update(max_duration_ms=6000)),
        ("QUANTITY", lambda x: x["constraints"]["quantity"].update(limit=65537)),
        ("CONCURRENCY", lambda x: x["constraints"].update(max_concurrency=2)),
        ("FLOW", lambda x: x["constraints"]["flows"].append({"source": "request", "sink": "output", "direction": "OUT", "maximum_label": deepcopy(x["constraints"]["data_label"]), "purpose": "TASK", "declassification_required": False})),
        ("OBLIGATION", lambda x: x["constraints"]["obligations"].append("seal.quiescent")),
    ):
        mutated = deepcopy(candidate); mutate(mutated["authority_alternatives"][0]["entries"][0])
        assertion("T-AUTHORITY-FULL-CLAUSE-" + name, reference.decide(mutated, manifest, policy, isolation, facts)["reason_codes"] == ["DERIVED_CLAUSE_UNAUTHORIZED"]); count += 1
    zero_manifest = deepcopy(manifest); zero_manifest["effect_bounds"][0]["resources"][0]["quantity"]["limit"] = 0
    rebound = deepcopy(candidate); rebound["bindings"]["manifest_digest"] = reference.canonical_digest(zero_manifest)
    zero_facts = deepcopy(facts); zero_digest = rebound["bindings"]["manifest_digest"]; trusted_zero = deepcopy(zero_facts["verified_manifests"][candidate["bindings"]["manifest_digest"]]); trusted_zero.update(manifest_digest=zero_digest, signed_payload_digest=zero_digest); zero_facts["verified_manifests"] = {zero_digest: trusted_zero}
    assertion("T-AUTHORITY-MANIFEST-ZERO-QUANTITY", reference.decide(rebound, zero_manifest, policy, isolation, zero_facts)["reason_codes"] == ["MANIFEST_DERIVED_CLOSURE_INVALID"]); count += 1
    bad_policy, policy_facts, policy_candidate = deepcopy(policy), deepcopy(facts), deepcopy(candidate); bad_policy["authority_map"][0]["authority_constraints_digest"] = digest("0")
    refresh_policy_activation(reference, bad_policy, policy_facts, policy_candidate)
    assertion("T-AUTHORITY-POLICY-CONSTRAINT-DIGEST", reference.decide(policy_candidate, manifest, bad_policy, isolation, policy_facts)["reason_codes"] == ["SCOPE_EXCEEDS_CORRELATED_POLICY"]); count += 1
    deny_policy, deny_facts, deny_candidate = deepcopy(policy), deepcopy(facts), deepcopy(candidate); deny_policy["authority_map"][0]["approval_class"] = "DENY"
    refresh_policy_activation(reference, deny_policy, deny_facts, deny_candidate)
    assertion("T-POLICY-EXPLICIT-DENY-OVERRIDES", reference.decide(deny_candidate, manifest, deny_policy, isolation, deny_facts)["reason_codes"] == ["EXPLICIT_POLICY_DENY"]); count += 1
    missing_budget = deepcopy(candidate); missing_budget["budget_demands"] = [item for item in missing_budget["budget_demands"] if item["name"] != "WRITE_BYTES"]
    assertion("T-BUDGET-REQUIRED-VECTOR-COMPLETE", reference.decide(missing_budget, manifest, policy, isolation, facts)["reason_codes"] == ["BUDGET_VECTOR_BINDING_MISMATCH"]); count += 1
    return count


def make_effect_evidence(decision, capability):
    effect = {"effect": "MUTATE", "resource_kind": "FILE", "operations": ["WRITE"], "scope": {"kind": "PATH", "values": ["/workspace/output/report.txt"]}}
    identity = object_identity()
    event_effect = {**effect, "object_id": "object:report", "object_digest": digest("a"), "object_identity": identity, "envelope_digest": digest("b")}
    bindings = {key: capability["bindings"][key] for key in ("request_digest", "manifest_digest", "policy_digest", "contract_digest", "iteration_slot_digest", "decision_digest", "approval_mode", "approval_receipt_digest", "registry_digest", "placement_attestation_digest", "session_attestation_digest", "broker_ipc_attestation_digest", "broker_ipc_binding_digest", "resource_vector_digest", "supply_chain_measurement_digest")}
    bindings["capability_digest"] = capability["capability_digest"]
    event_effect["envelope_digest"] = capability["bindings"]["authorized_envelope_digest"]
    def stage(record_type: str) -> dict:
        record = {"record_type": record_type, "transaction_id": "tx:one", "capability_digest": capability["capability_digest"], "session_id": "session:one", "object_identity": identity, "epoch": 4, "observer_id": "observer:runtime", "signature_verified": True}
        record["record_digest"] = canonical_digest_for_test(record)
        return record
    stages = {name: {"status": "KNOWN", "entries": [effect]} for name in ("authorized", "attempted", "actual", "committed", "observed", "verified")}
    stages["blocked"] = {"status": "NOT_APPLICABLE", "entries": []}
    receipt = {"schema_version": "1.0.0", "receipt_id": "receipt:one", "transaction_id": "tx:one", "call_id": "call:one", "principal": "executor:workspace", "object_id": "object:report", "object_digest": digest("a"), "object_identity": identity, "bindings": {**{key: value for key, value in bindings.items() if key != "authorized_envelope_digest"}, "approval_mode": "NOT_REQUIRED", "approval_receipt_digest": None, "session_id": "session:one"}, **stages, "outcome": "KNOWN_SUCCESS", "dispatch": {"intent_digest": digest("2"), "capability_consumed": True, "budget_reserved": True, "journal_sequence": 1, "fencing_epoch": 4, "object_identity": identity}, "quiesce_evidence": stage("QUIESCE"), "seal_evidence": stage("SEAL"), "postcheck_evidence": stage("POSTCHECK"), "seal": {"required": True, "writers_quiesced": True, "snapshot_digest": digest("4")}, "postcheck": {"state": "PASSED", "plan_digest": digest("5"), "attestation_digest": digest("6"), "automatic_retry_allowed": False}, "executor_attestation": {"issuer": "executor:workspace", "component_digest": digest("1"), "payload_digest": digest("2"), "key_id": "key:executor", "algorithm": "ED25519", "signature": "A" * 64, "verified_by": "observer:runtime"}, "authoritative_verifier": {"issuer": "observer:runtime", "key_id": "key:observer", "trust_root": "trust:root", "signature_verified": True, "payload_digest": digest("2"), "subject": "executor:workspace", "session_id": "session:one", "placement_digest": digest("7"), "measurement_digest": capability["bindings"]["supply_chain_measurement_digest"], "freshness_verified": True, "revocation_checked": True}, "privacy": {"arg_digest": digest("a"), "output_digest": digest("b"), "confidentiality": "INTERNAL", "integrity": "SERVICE_ATTESTED", "provenance": ["urn:request:write-report"], "taints": ["USER_INPUT"], "purpose": "TASK", "retention": "CONTRACT", "access_policy": "policy:workspace", "redaction_profile": "redaction:default", "raw_sensitive_values_in_metrics": False}, "issued_at": "2026-08-24T00:00:06Z", "chain": {"source_id": "source:receipt", "epoch": 1, "sequence": 0, "genesis": True, "predecessor_digest": None, "previous_receipt_digest": None, "receipt_digest": digest("3"), "witness_digest": digest("4"), "anti_rollback_proven": True}}
    receipt["bindings"].update(approval_mode=capability["bindings"]["approval_mode"], approval_receipt_digest=capability["bindings"]["approval_receipt_digest"])
    receipt["authoritative_verifier"]["payload_digest"] = canonical_digest_for_test({key: value for key, value in receipt.items() if key != "authoritative_verifier"})
    stages = {name: {"status": "KNOWN" if name in {"desired", "requested", "manifested", "authorized", "attempted", "actual", "committed", "observed", "verified"} else "NOT_APPLICABLE", "entries": [event_effect] if name in {"desired", "requested", "manifested", "authorized", "attempted", "actual", "committed", "observed", "verified"} else []} for name in ("desired", "requested", "manifested", "derived", "authorized", "attempted", "blocked", "actual", "committed", "observed", "verified")}
    event = {"schema_version": "1.0.0", "event_id": "event:join", "event_type": "JOIN", "trace_id": "trace:one", "run_id": "run:one", "contract_id": "contract:one", "transaction_id": "tx:one", "object_id": "object:report", "object_digest": digest("a"), "object_identity": identity, "session_id": "session:one", "iteration": 1, "call_id": "call:one", "parent_call_id": None, "delegation_lineage": [], "principal": "executor:workspace", "emitter": {"principal": "observer:runtime", "component": "OBSERVER", "authority_attestation_digest": digest("9"), "trusted_identity_verified": True}, "tool": {"tool_id": "tool:filesystem", "operation_id": "write-file", "version": "1.0.0", "implementation_digest": digest("1")}, "bindings": {**{key: value for key, value in bindings.items() if key != "request_digest"}, "approval_mode": "NOT_REQUIRED", "approval_receipt_digest": None}, "effect_stages": stages, "decision": "ALLOW", "reason_codes": ["AUTHORIZED_EXACT_BOUND"], "obligations": ["postcheck.run"], "budget": {"before": [{"name": "CALLS", "unit": "CALLS", "value": 1}], "delta": [{"name": "CALLS", "unit": "CALLS", "value": 1}], "after": [{"name": "CALLS", "unit": "CALLS", "value": 0}]}, "time": {"occurred_at": "2026-08-24T00:00:06Z", "recorded_at": "2026-08-24T00:00:06Z", "clock_source": "MONOTONIC_AND_WALL", "monotonic_sequence": 1}, "outcome": "VERIFIED", "evidence_digests": [digest("3")], "privacy": {"arg_digest": digest("a"), "output_digest": digest("b"), "confidentiality": "INTERNAL", "integrity": "SERVICE_ATTESTED", "provenance": ["urn:request:write-report"], "taints": ["USER_INPUT"], "purpose": "TASK", "retention": "CONTRACT", "access_policy": "policy:workspace", "redaction_profile": "redaction:default", "raw_sensitive_values_in_metrics": False}, "unsampled": True, "chain": {"source_id": "source:event", "epoch": 1, "sequence": 1, "genesis": False, "predecessor_digest": digest("4"), "previous_event_digest": digest("4"), "event_digest": digest("5"), "witness_digest": digest("6"), "anti_rollback_proven": True}}
    event["bindings"].update(request_digest=digest("a"), authorized_envelope_digest=capability["bindings"]["authorized_envelope_digest"], approval_mode=capability["bindings"]["approval_mode"], approval_receipt_digest=capability["bindings"]["approval_receipt_digest"])
    event_preimage = deepcopy(event); event_preimage["chain"] = {key: value for key, value in event["chain"].items() if key != "event_digest"}
    event["chain"]["event_digest"] = canonical_digest_for_test(event_preimage)
    return effect, receipt, event


def event_trust_facts(event):
    """Externally anchored emitter, physical ceiling and exact stage projection."""
    event_digest = event["chain"]["event_digest"]
    stages = event["effect_stages"]
    physical = deepcopy(stages["derived"]["entries"] if stages["derived"]["status"] == "KNOWN" else stages["manifested"]["entries"])
    record = {
        **deepcopy(event["bindings"]),
        "event_digest": event_digest,
        "manifested_effects_digest": canonical_digest_for_test(stages["manifested"]["entries"]),
        "physical_effects_digest": canonical_digest_for_test(physical),
        "authorized_effects_digest": canonical_digest_for_test(stages["authorized"]["entries"]),
        "committed_effects_digest": canonical_digest_for_test(stages["committed"]["entries"]),
    }
    emitter = event["emitter"]
    return {
        "physical_effects": physical,
        "event_chain_heads": {event["chain"]["source_id"]: {"epoch": event["chain"]["epoch"], "next_sequence": event["chain"]["sequence"], "predecessor_digest": event["chain"]["predecessor_digest"]}},
        "verified_event_emitters": {emitter["authority_attestation_digest"]: {"principal": emitter["principal"], "component": emitter["component"], "authority_attestation_digest": emitter["authority_attestation_digest"], "key_id": "key:observer", "event_digest": event_digest, "signature_verified": True, "freshness_verified": True, "revocation_checked": True}},
        "verified_event_bindings": {event_digest: {**record, "object_identity": deepcopy(event["object_identity"])}},
    }


def receipt_stage_evidence(receipt: dict) -> dict:
    return {field: {"evidence_type": record["record_type"], "evidence_digest": record["record_digest"], "transaction_id": record["transaction_id"], "capability_digest": record["capability_digest"], "session_id": record["session_id"], "object_identity": deepcopy(record["object_identity"]), "fencing_epoch": record["epoch"], "observer": record["observer_id"], "signature_verified": True, "not_revoked": True, "verified_by": "observer:runtime"} for field, record in (("quiesce", receipt["quiesce_evidence"]), ("seal", receipt["seal_evidence"]), ("postcheck", receipt["postcheck_evidence"]))}


def check_evidence_guards(reference, decision, capability) -> int:
    effect, receipt, event = make_effect_evidence(decision, capability)
    trusted_receipt_facts = {"stage_evidence": receipt_stage_evidence(receipt), "receipt_chain_heads": {receipt["chain"]["source_id"]: {"epoch": receipt["chain"]["epoch"], "next_sequence": receipt["chain"]["sequence"], "predecessor_digest": receipt["chain"]["predecessor_digest"]}}, "verified_effect_receipts": {reference.canonical_digest(receipt): {"receipt_digest": reference.canonical_digest(receipt), "payload_digest": reference.canonical_digest({key: value for key, value in receipt.items() if key != "authoritative_verifier"}), "object_id": receipt["object_id"], "object_digest": receipt["object_digest"], "object_identity": deepcopy(receipt["object_identity"]), "session_id": receipt["bindings"]["session_id"], "decision_digest": receipt["bindings"]["decision_digest"], "capability_digest": receipt["bindings"]["capability_digest"], "dispatch_intent_digest": receipt["dispatch"]["intent_digest"], "authoritative_verifier": deepcopy(receipt["authoritative_verifier"])}}}
    assertion("T-RECEIPT-CANONICAL-VALID", schema_valid("effect-receipt.schema.json", receipt) and reference.validate_effect_receipt(receipt, trusted_receipt_facts))
    endpoint_identity = endpoint_binding()
    cross_kind_receipt = deepcopy(receipt); cross_kind_receipt.update(object_id=endpoint_identity["endpoint_id"], object_digest=endpoint_identity["endpoint_binding_digest"], object_identity=deepcopy(endpoint_identity)); cross_kind_receipt["dispatch"]["object_identity"] = deepcopy(endpoint_identity)
    for field in ("quiesce_evidence", "seal_evidence", "postcheck_evidence"):
        cross_kind_receipt[field]["object_identity"] = deepcopy(endpoint_identity)
    assertion("T-Q82-RECEIPT-CROSS-KIND-IDENTITY-REJECTED", not schema_valid("effect-receipt.schema.json", cross_kind_receipt))
    assertion("T-STAGE-EVIDENCE-MISSING-TRUST", not reference.validate_effect_receipt(receipt, {key: value for key, value in trusted_receipt_facts.items() if key != "stage_evidence"}))
    vacuous = deepcopy(receipt); vacuous["actual"] = {"status": "KNOWN", "entries": []}
    assertion("T-RECEIPT-KNOWN-SUCCESS-NONVACUOUS", not schema_valid("effect-receipt.schema.json", vacuous) and not reference.validate_effect_receipt(vacuous, trusted_receipt_facts))
    failure_untagged = deepcopy(receipt); failure_untagged["outcome"] = "KNOWN_FAILURE"; failure_untagged["actual"] = []
    assertion("T-Q85-KNOWN-FAILURE-UNTAGGED-ACTUAL-REJECT", not schema_valid("effect-receipt.schema.json", failure_untagged) and not reference.validate_effect_receipt(failure_untagged, trusted_receipt_facts))
    failure_empty = deepcopy(receipt); failure_empty["outcome"] = "KNOWN_FAILURE"; failure_empty["actual"] = {"status": "KNOWN", "entries": []}
    assertion("T-Q85-KNOWN-FAILURE-EMPTY-ACTUAL-REJECT", not schema_valid("effect-receipt.schema.json", failure_empty) and not reference.validate_effect_receipt(failure_empty, trusted_receipt_facts))
    partial_receipt = deepcopy(receipt); partial_receipt["actual"] = {"status": "PARTIAL", "reason": "incomplete", "entries": []}
    assertion("T-Q85-RECEIPT-PARTIAL-ACTUAL-REJECT", not reference.validate_effect_receipt(partial_receipt, trusted_receipt_facts))
    privacy_missing = deepcopy(receipt); privacy_missing["privacy"].pop("retention")
    assertion("T-RECEIPT-PRIVACY-LIFECYCLE", not schema_valid("effect-receipt.schema.json", privacy_missing) and not reference.validate_effect_receipt(privacy_missing, trusted_receipt_facts))
    event_facts = event_trust_facts(event)
    assertion("T-EVENT-CANONICAL-VALID", schema_valid("event-envelope.schema.json", event) and reference.validate_safety_event(event, event_facts))
    cross_kind_event = deepcopy(event); cross_kind_event.update(object_id=endpoint_identity["endpoint_id"], object_digest=endpoint_identity["endpoint_binding_digest"], object_identity=deepcopy(endpoint_identity))
    for stage in cross_kind_event["effect_stages"].values():
        for entry in stage["entries"]:
            entry.update(object_id=endpoint_identity["endpoint_id"], object_digest=endpoint_identity["endpoint_binding_digest"], object_identity=deepcopy(endpoint_identity))
    assertion("T-Q82-EVENT-CROSS-KIND-IDENTITY-REJECTED", not schema_valid("event-envelope.schema.json", cross_kind_event))
    bad = deepcopy(receipt); bad["committed"] = {"status": "KNOWN", "entries": [{**effect, "operations": ["DELETE"]}]}
    assertion("T-RECEIPT-COMMITTED-SUBSET", not reference.validate_effect_receipt(bad, trusted_receipt_facts))
    for field, value in (("seal", {"required": True, "writers_quiesced": False, "snapshot_digest": None}), ("postcheck", {"state": "PENDING", "plan_digest": None, "attestation_digest": None, "automatic_retry_allowed": False}), ("chain", {"previous_receipt_digest": None, "receipt_digest": digest("3"), "witness_digest": None, "anti_rollback_proven": False})):
        bad = deepcopy(receipt); bad[field] = value
        assertion("T-RECEIPT-GUARD-" + field.upper(), not reference.validate_effect_receipt(bad, trusted_receipt_facts) and not schema_valid("effect-receipt.schema.json", bad))
    fake_internal_verifier = deepcopy(receipt); fake_internal_verifier["authoritative_verifier"]["payload_digest"] = digest("0")
    fake_internal_verifier["chain"]["receipt_digest"] = reference.canonical_digest(fake_internal_verifier)
    assertion("T-RECEIPT-EXTERNAL-VERIFIER-FACTS", not reference.validate_effect_receipt(fake_internal_verifier, trusted_receipt_facts))
    bad_event = deepcopy(event); bad_event["emitter"]["trusted_identity_verified"] = False
    assertion("T-EVENT-TRUSTED-EMITTER", not reference.validate_safety_event(bad_event, event_facts) and not schema_valid("event-envelope.schema.json", bad_event))
    unknown = deepcopy(event); unknown.update(event_type="UNKNOWN_OUTCOME", outcome="UNKNOWN", reconciliation={"reconciliation_id": "reconcile:one", "state": "RECONCILING", "evidence_digests": [digest("7")], "escrow_digest": digest("8"), "automatic_retry_allowed": False})
    for name in ("actual", "committed", "verified"):
        unknown["effect_stages"][name] = {"status": "UNKNOWN", "reason": "external outcome unresolved", "entries": []}
    unknown_preimage = deepcopy(unknown); unknown_preimage["chain"] = {key: value for key, value in unknown["chain"].items() if key != "event_digest"}; unknown["chain"]["event_digest"] = canonical_digest_for_test(unknown_preimage); unknown_facts = event_trust_facts(unknown)
    assertion("T-UNKNOWN-OUTCOME-RECONCILIATION", schema_valid("event-envelope.schema.json", unknown) and reference.validate_safety_event(unknown, unknown_facts))
    missing_reconciliation = deepcopy(unknown); missing_reconciliation.pop("reconciliation")
    assertion("T-UNKNOWN-OUTCOME-REQUIRES-RECONCILIATION", not schema_valid("event-envelope.schema.json", missing_reconciliation) and not reference.validate_safety_event(missing_reconciliation, unknown_facts))
    known_ambiguous = deepcopy(unknown); known_ambiguous["effect_stages"]["committed"] = deepcopy(event["effect_stages"]["committed"])
    assertion("T-UNKNOWN-OUTCOME-KNOWN-COMMIT-AMBIGUITY", not reference.validate_safety_event(known_ambiguous, unknown_facts))
    partial_join = deepcopy(unknown); partial_join.update(event_type="JOIN", outcome="VERIFIED")
    partial_join["effect_stages"]["actual"] = {"status": "PARTIAL", "reason": "external outcome incomplete", "entries": []}
    partial_preimage = deepcopy(partial_join); partial_preimage["chain"].pop("event_digest"); partial_join["chain"]["event_digest"] = canonical_digest_for_test(partial_preimage)
    assertion("T-Q85-RELEASE-JOIN-PARTIAL-ACTUAL-REJECT", not reference.validate_safety_event(partial_join, event_trust_facts(partial_join)))
    empty_known = deepcopy(event); empty_known["effect_stages"]["authorized"] = {"status": "KNOWN", "entries": []}
    assertion("T-EVENT-KNOWN-EMPTY-REJECT", not reference.validate_safety_event(empty_known, event_facts) and not schema_valid("event-envelope.schema.json", empty_known))
    swapped = deepcopy(event); swapped["effect_stages"]["committed"]["entries"][0]["object_id"] = "object:other"
    assertion("T-EVENT-SAME-OBJECT-REJECT", not reference.validate_safety_event(swapped, event_facts))
    for field in ("object_digest", "envelope_digest"):
        bad_chain = deepcopy(event); bad_chain["effect_stages"]["committed"]["entries"][0][field] = digest("0")
        assertion("T-EVENT-SAME-CHAIN-" + field.upper() + "-REJECT", not reference.validate_safety_event(bad_chain, event_facts))
    committed, _ = advance(reference, "STAGEABLE", decision, capability, ["PROPOSE", "NORMALIZE", "CLASSIFY", "ADMIT", "CALCULATE_RESERVATION", "ISSUE_CAPABILITY", "DURABLE_DISPATCH", "QUIESCE", "SEAL", "POSTCHECK_PASS", "COMMIT"])
    assertion("T-JOIN-EVIDENCE-GUARD", not reference.reduce_transition(committed, {"type": "JOIN", "decision_digest": decision["decision_digest"], "join_evidence": {}})["accepted"])
    for field, value in (("descriptor_id", "descriptor:other"), ("root_id", "root:other"), ("mount_id", "mount:other"), ("resolution_epoch", 2), ("final_object_id", "object:other"), ("final_object_digest", digest("c"))):
        identity = deepcopy(committed["object_identity"]); identity[field] = value
        assertion("T-JOIN-OBJECT-IDENTITY-" + field, not reference.reduce_transition(committed, event_for("JOIN", decision, capability, object_identity=identity))["accepted"])
    for field, value in (("quiesce_evidence_ref", "stage:other"), ("seal_evidence_ref", "stage:other"), ("postcheck_evidence_ref", "stage:other"), ("quiescence_attestation_digest", digest("c")), ("seal_digest", digest("c")), ("postcheck_attestation_digest", digest("c"))):
        join_event = event_for("JOIN", decision, capability); join_event["join_evidence"][field] = value
        assertion("T-JOIN-STAGE-BINDING-" + field, not reference.reduce_transition(committed, join_event)["accepted"])
    for name, mutate in (("MISSING", lambda store: store["stage_evidence"].pop("stage:seal")), ("REVOKED", lambda store: store["stage_evidence"]["stage:seal"].update(not_revoked=False)), ("MISMATCHED", lambda store: store["stage_evidence"]["stage:seal"].update(object_identity={**store["stage_evidence"]["stage:seal"]["object_identity"], "mount_id": "mount:other"}))):
        broken = deepcopy(committed); mutate(broken["trusted_store"])
        assertion("T-JOIN-STAGE-TRUST-" + name, not reference.reduce_transition(broken, event_for("JOIN", decision, capability))["accepted"])
    return 7


def check_branch_recovery(reference, candidate, decision, capability) -> int:
    sealed, _ = advance(reference, "STAGEABLE", decision, capability, ["PROPOSE", "NORMALIZE", "CLASSIFY", "ADMIT", "CALCULATE_RESERVATION", "ISSUE_CAPABILITY", "DURABLE_DISPATCH", "QUIESCE", "SEAL"])
    before_spent, before_reserved = sealed["budget_spent"], sealed["budget_reserved"]
    no_effect_fail = {"type": "POSTCHECK_FAIL", "no_effect_proven": True, "no_effect_proof": {"verified_by": "observer:runtime", "signature_verified": True, "payload_digest": digest("a"), "observed_effects": [], "observed_effects_digest": canonical_digest_for_test([])}}
    released = reference.reduce_transition(sealed, no_effect_fail)
    assertion("T-Q38-POSTCHECK-NO-EFFECT-RELEASE", released["accepted"] and released["state"]["phase"] == "DISCARDED" and released["state"]["budget_reserved"] == 0 and released["state"]["budget_spent"] == before_spent and released["state"]["budget_remaining"] == sealed["budget_remaining"] + before_reserved and released["durable_record"]["reservation_release"] == before_reserved)
    assertion("T-Q38-POSTCHECK-UNPROVEN-NOT-RELEASED", not reference.reduce_transition(sealed, {"type": "POSTCHECK_FAIL", "no_effect_proven": True})["accepted"])
    external_manifest, external_candidate, external_decision, external_capability = make_external_endpoint_chain(reference, candidate, decision)
    assertion("T-Q82-ENDPOINT-CHAIN-SCHEMAS", schema_valid("effect-manifest.schema.json", external_manifest) and schema_valid("admission-candidate.schema.json", external_candidate) and schema_valid("decision-result.schema.json", external_decision) and schema_valid("capability.schema.json", external_capability))
    endpoint_with_descriptor = deepcopy(external_candidate); endpoint_with_descriptor["bindings"]["descriptor_binding_digest"] = candidate["bindings"]["descriptor_binding_digest"]
    assertion("T-Q82-CANDIDATE-ENDPOINT-DESCRIPTOR-XOR", not schema_valid("admission-candidate.schema.json", endpoint_with_descriptor))
    mixed_decision = deepcopy(external_decision); mixed_decision["authorized_envelope"].append(deepcopy(decision["authorized_envelope"][0]))
    assertion("T-Q82-DECISION-MIXED-TARGET-KINDS-REJECTED", not schema_valid("decision-result.schema.json", mixed_decision))
    mixed_capability = deepcopy(external_capability); mixed_capability["effects"].append(deepcopy(capability["effects"][0]))
    assertion("T-Q82-CAPABILITY-MIXED-TARGET-KINDS-REJECTED", not schema_valid("capability.schema.json", mixed_capability))
    base = ["PROPOSE", "NORMALIZE", "CLASSIFY", "ADMIT", "CALCULATE_RESERVATION", "ISSUE_CAPABILITY", "PRECHECK_EXTERNAL", "DURABLE_DISPATCH", "OUTCOME_UNKNOWN"]
    issued_endpoint, _ = advance(reference, "EXTERNAL", external_decision, external_capability, base[:-2])
    filesystem_substitution = event_for("DURABLE_DISPATCH", external_decision, external_capability, object_identity=object_identity())
    assertion("T-Q82-ENDPOINT-REJECTS-FILESYSTEM-PROOF", not reference.reduce_transition(issued_endpoint, filesystem_substitution)["accepted"])
    endpoint_substitution = event_for("DURABLE_DISPATCH", external_decision, external_capability)
    endpoint_substitution["object_identity"] = deepcopy(endpoint_substitution["object_identity"]); endpoint_substitution["object_identity"]["canonical_endpoint"] = "https://messages.example.test/v1/other"; endpoint_substitution["object_identity"]["endpoint_binding_digest"] = canonical_digest_for_test({key: value for key, value in endpoint_substitution["object_identity"].items() if key != "endpoint_binding_digest"})
    assertion("T-Q82-ENDPOINT-SUBSTITUTION-REJECTED", not reference.reduce_transition(issued_endpoint, endpoint_substitution)["accepted"])
    missing_endpoint_verifier = deepcopy(issued_endpoint); missing_endpoint_verifier["trusted_store"]["verified_endpoint_bindings"] = {}
    assertion("T-Q82-ENDPOINT-MISSING-VERIFIER-REJECTED", not reference.reduce_transition(missing_endpoint_verifier, event_for("DURABLE_DISPATCH", external_decision, external_capability))["accepted"])
    stale_connector_key = deepcopy(issued_endpoint); stale_connector_key["trusted_store"]["verified_endpoint_bindings"][external_capability["bindings"]["endpoint_binding_digest"]]["current_key"] = False
    assertion("T-Q82-ENDPOINT-STALE-CONNECTOR-KEY-REJECTED", not reference.reduce_transition(stale_connector_key, event_for("DURABLE_DISPATCH", external_decision, external_capability))["accepted"])
    endpoint_on_stageable, _ = advance(reference, "STAGEABLE", external_decision, external_capability, ["PROPOSE", "NORMALIZE", "CLASSIFY", "ADMIT", "CALCULATE_RESERVATION", "ISSUE_CAPABILITY"])
    assertion("T-Q82-ENDPOINT-CANNOT-ENTER-STAGEABLE-BRANCH", not reference.reduce_transition(endpoint_on_stageable, event_for("DURABLE_DISPATCH", external_decision, external_capability))["accepted"])
    filesystem_on_external, _ = advance(reference, "EXTERNAL", decision, capability, ["PROPOSE", "NORMALIZE", "CLASSIFY", "ADMIT", "CALCULATE_RESERVATION", "ISSUE_CAPABILITY", "PRECHECK_EXTERNAL"])
    assertion("T-Q82-FILESYSTEM-CANNOT-ENTER-EXTERNAL-BRANCH", not reference.reduce_transition(filesystem_on_external, event_for("DURABLE_DISPATCH", decision, capability))["accepted"])
    state, _ = advance(reference, "EXTERNAL", external_decision, external_capability, base)
    assertion("T-L3-EXTERNAL-ENDPOINT-LIFECYCLE-EXACT", state["phase"] == "QUARANTINED" and state["target_kind"] == "ENDPOINT" and state["object_identity"] == endpoint_binding(external_manifest))
    assertion("T-EXTERNAL-UNKNOWN-ESCROW", state["phase"] == "QUARANTINED" and state["unknown_escrow"] == state["budget_reserved"] > 0)
    assertion("T-EXTERNAL-UNKNOWN-NO-AUTORETRY", not reference.reduce_transition(state, {"type": "AUTO_RETRY"})["accepted"])
    assertion("T-Q76-EXTERNAL-BARE-RECONCILE-REJECTED", not reference.reduce_transition(state, {"type": "RECONCILE_SUCCESS"})["accepted"])
    result = reference.reduce_transition(state, event_for("RECONCILE_SUCCESS", external_decision, external_capability)); assertion("T-EXTERNAL-RECONCILE-CONSERVES", result["accepted"] and result["state"]["budget_reserved"] == 0 and result["state"]["budget_spent"] == sum(item["amount"] for item in external_decision["reservations"]))
    known, _ = advance(reference, "EXTERNAL", external_decision, external_capability, base[:-1])
    observed = reference.reduce_transition(known, {"type": "OUTCOME_SUCCESS"})
    reconciled = reference.reduce_transition(observed["state"], event_for("RECONCILE_SUCCESS", external_decision, external_capability))
    assertion("T-Q76-KNOWN-SUCCESS-TERMINAL-ONCE", observed["accepted"] and observed["state"]["phase"] == "KNOWN_SUCCESS" and reconciled["accepted"] and not reference.reduce_transition(reconciled["state"], event_for("RECONCILE_SUCCESS", external_decision, external_capability))["accepted"])
    failed_state, _ = advance(reference, "EXTERNAL", external_decision, external_capability, base)
    failed = reference.reduce_transition(failed_state, event_for("RECONCILE_FAILURE", external_decision, external_capability))
    assertion("T-Q76-EXTERNAL-FAILURE-NO-EFFECT-RELEASES", failed["accepted"] and failed["state"]["phase"] == "FAILURE_RECORDED" and failed["state"]["budget_reserved"] == 0 and failed["state"]["budget_spent"] == 0)
    for name, mutate in (
        ("TRANSACTION", lambda record, broken: record.update(transaction_id="tx:other")),
        ("OBJECT", lambda record, broken: record["object_identity"].update(endpoint_id="endpoint:other")),
        ("IDEMPOTENCY", lambda record, broken: record.update(idempotency_key_digest=digest("0"))),
        ("CONNECTOR", lambda record, broken: record.update(connector_id="connector:other")),
        ("CHAIN", lambda record, broken: record.update(chain_digest=digest("0"))),
        ("FENCE", lambda record, broken: record.update(fencing_epoch=1)),
        ("REVOKED", lambda record, broken: record.update(not_revoked=False)),
        ("STALE", lambda record, broken: broken["trusted_store"].update(trusted_time=record["expires_at"])),
        ("FORGED-VERIFIER", lambda record, broken: record.update(verified_by="attacker:forged-verifier")),
    ):
        broken = deepcopy(state); record = broken["trusted_store"]["reconciliation"]["reconcile:success"]; mutate(record, broken)
        record["evidence_digest"] = canonical_digest_for_test({key: value for key, value in record.items() if key != "evidence_digest"})
        assertion("T-Q76-EXTERNAL-RECONCILE-" + name, not reference.reduce_transition(broken, event_for("RECONCILE_SUCCESS", external_decision, external_capability))["accepted"])
    executing, _ = advance(reference, "EXTERNAL", external_decision, external_capability, base[:-1])
    known_failure = reference.reduce_transition(executing, {"type": "OUTCOME_FAILURE"})
    residual_event = event_for("RECORD_FAILURE", external_decision, external_capability, reconciliation_evidence_ref="reconcile:residual")
    residual = reference.reduce_transition(known_failure["state"], residual_event)
    assertion("T-EXTERNAL-KNOWN-FAILURE-PARTIAL-EFFECT-NO-SILENT-RELEASE", residual["accepted"] and residual["state"]["phase"] == "COMPENSATION_PENDING" and residual["state"]["budget_remaining"] == known_failure["state"]["budget_remaining"] and residual["state"]["budget_spent"] > 0 and residual["state"]["unknown_escrow"] == residual["state"]["budget_reserved"] > 0 and residual["durable_record"]["budget_transition"]["kind"] == "RECONCILED_RESIDUAL_EFFECT")
    unrelated_budget = {"name": "WRITE_BYTES", "unit": "BYTES", "amount": 100, "scope_digest": digest("5"), "lineage_root": "lineage:root"}; unrelated_key = (unrelated_budget["name"], unrelated_budget["unit"], unrelated_budget["scope_digest"], unrelated_budget["lineage_root"])
    unrelated_executing, _ = advance(reference, "EXTERNAL", external_decision, external_capability, base[:-1], budget_vector=external_decision["reservations"] + [unrelated_budget]); unrelated_failure = reference.reduce_transition(unrelated_executing, {"type": "OUTCOME_FAILURE"}); unrelated_residual = reference.reduce_transition(unrelated_failure["state"], residual_event)
    assertion("T-Q83-ZERO-RESERVED-KEY-NEEDS-NO-DISPOSITION", unrelated_residual["accepted"] and unrelated_residual["state"]["budget_remaining_by_key"][unrelated_key] == 100 and unrelated_residual["state"]["budget_reserved_by_key"][unrelated_key] == 0 and reference._conserved(unrelated_residual["state"]))
    for forbidden in ({"type": "AUTO_RETRY"}, {"type": "JOIN"}, {"type": "STOP"}):
        blocked_residual = reference.reduce_transition(residual["state"], forbidden)
        assertion("T-Q83-COMPENSATION-PENDING-BLOCKS-" + forbidden["type"], not blocked_residual["accepted"] and blocked_residual["state"]["phase"] == "COMPENSATION_PENDING")
    crashed_residual = reference.reduce_transition(residual["state"], {"type": "CRASH"})
    recovered_residual = reference.reduce_transition(crashed_residual["state"], {"type": "RECOVER_ORPHAN", "observed_fencing_epoch": crashed_residual["state"]["fencing_epoch"]})
    assertion("T-Q83-COMPENSATION-PENDING-SURVIVES-CRASH", crashed_residual["accepted"] and recovered_residual["accepted"] and recovered_residual["state"]["phase"] == "COMPENSATION_PENDING" and recovered_residual["state"]["budget_spent_by_key"] == residual["state"]["budget_spent_by_key"] and recovered_residual["state"]["unknown_escrow_by_key"] == residual["state"]["unknown_escrow_by_key"])
    missing_compensation_authority = deepcopy(known_failure["state"]); missing_compensation_authority["trusted_store"]["compensation_authorizations"] = {}
    assertion("T-Q83-FRESH-COMPENSATION-AUTHORIZATION-REQUIRED", not reference.reduce_transition(missing_compensation_authority, residual_event)["accepted"])
    mismatched_component = deepcopy(known_failure["state"]); residual_record = mismatched_component["trusted_store"]["reconciliation"]["reconcile:residual"]; residual_record["failure_disposition"]["budget_dispositions"][0]["amount"] += 1; residual_record["evidence_digest"] = canonical_digest_for_test({key: value for key, value in residual_record.items() if key != "evidence_digest"})
    assertion("T-Q83-COMPONENT-WISE-BUDGET-DISPOSITION-EXACT", not reference.reduce_transition(mismatched_component, residual_event)["accepted"])
    duplicate_key = deepcopy(known_failure["state"]); budget_key = next(iter(duplicate_key["budget_reserved_by_key"])); duplicate_key["budget_total_by_key"][budget_key] += 1; duplicate_key["budget_reserved_by_key"][budget_key] += 1; duplicate_key["budget_total"] += 1; duplicate_key["budget_reserved"] += 1
    duplicate_record = duplicate_key["trusted_store"]["reconciliation"]["reconcile:residual"]; split_row = deepcopy(duplicate_record["failure_disposition"]["budget_dispositions"][0]); split_row["disposition"] = "QUARANTINED_ESCROW"; duplicate_record["failure_disposition"]["budget_dispositions"].insert(1, split_row)
    authorization = duplicate_record["failure_disposition"]["compensation_authorization"]; authorization_record = duplicate_key["trusted_store"]["compensation_authorizations"][canonical_digest_for_test(authorization)]; authorization_record["failure_disposition_digest"] = canonical_digest_for_test(duplicate_record["failure_disposition"]); authorization_record["record_digest"] = canonical_digest_for_test({key: value for key, value in authorization_record.items() if key != "record_digest"}); duplicate_record["evidence_digest"] = canonical_digest_for_test({key: value for key, value in duplicate_record.items() if key != "evidence_digest"})
    assertion("T-Q83-ONE-DISPOSITION-PER-BUDGET-KEY", reference._conserved(duplicate_key) and not reference.reduce_transition(duplicate_key, residual_event)["accepted"])
    released_partial = deepcopy(known_failure["state"]); released_record = released_partial["trusted_store"]["reconciliation"]["reconcile:residual"]; released_record["failure_disposition"]["budget_dispositions"][0]["disposition"] = "RELEASED"; released_record["evidence_digest"] = canonical_digest_for_test({key: value for key, value in released_record.items() if key != "evidence_digest"})
    assertion("T-Q83-PARTIAL-EFFECT-CANNOT-RELEASE", not reference.reduce_transition(released_partial, residual_event)["accepted"])
    crashed = reference.reduce_transition(executing, {"type": "CRASH"})["state"]
    recovered = reference.reduce_transition(crashed, {"type": "RECOVER_ORPHAN", "observed_fencing_epoch": crashed["fencing_epoch"]})
    assertion("T-CRASH-ORPHAN-RECOVERY", recovered["accepted"] and recovered["state"]["phase"] == "QUARANTINED")
    committed, _ = advance(reference, "STAGEABLE", decision, capability, ["PROPOSE", "NORMALIZE", "CLASSIFY", "ADMIT", "CALCULATE_RESERVATION", "ISSUE_CAPABILITY", "DURABLE_DISPATCH", "QUIESCE", "SEAL", "POSTCHECK_PASS", "COMMIT"])
    committed_crash = reference.reduce_transition(committed, {"type": "CRASH"})
    assertion("T-CRASH-COMMITTED-IMMUTABLE", committed_crash["accepted"] and committed_crash["state"]["phase"] == "COMMITTED_RECOVERY_PENDING")
    pending = reference.reduce_transition(committed_crash["state"], {"type": "RECOVER_ORPHAN", "observed_fencing_epoch": committed_crash["state"]["fencing_epoch"]})
    assertion("T-CRASH-COMMITTED-CHAIN-GATE", not pending["accepted"] and pending["state"]["phase"] == "COMMITTED_RECOVERY_PENDING")
    recovered_commit = reference.reduce_transition(committed_crash["state"], {"type": "RECOVER_ORPHAN", "observed_fencing_epoch": committed_crash["state"]["fencing_epoch"], "same_object_chain_verified": True})
    assertion("T-CRASH-COMMITTED-RECOVERS", recovered_commit["accepted"] and recovered_commit["state"]["phase"] == "COMMITTED")
    recovery = {"fencing_epoch": 1, "orphan_inventory_digest": digest("a"), "recovered_ids_digest": digest("b"), "cleanup_verified": True, "absence_proof_digest": digest("c"), "stale_writers_absent": True, "residue_absent": True, "signature_verified": True, "not_revoked": True, "verified_by": "observer:runtime"}
    recovery["record_digest"] = canonical_digest_for_test(recovery)
    host_crash = reference.reduce_transition(reference.initial_state("STAGEABLE", trusted_store={"verified_host_recoveries": {"recovery:fresh": recovery}}), {"type": "HOST_CRASH"})
    blocked = reference.reduce_transition(host_crash["state"], {"type": "PROPOSE", "transaction_id": "tx:fresh"})
    admitted = reference.reduce_transition(host_crash["state"], {"type": "PROPOSE", "transaction_id": "tx:fresh", "host_recovery_evidence_ref": "recovery:fresh"})
    assertion("T-FRESH-ADMISSION-HOST-CLEANUP-GATE", not blocked["accepted"] and admitted["accepted"])
    compensation = reference.initial_state("COMPENSATION")
    assertion("T-COMPENSATION-FRESH-ADMISSION", not reference.reduce_transition(compensation, event_for("DURABLE_DISPATCH", decision, capability))["accepted"])
    live, _ = advance(reference, "STAGEABLE", decision, capability, ["PROPOSE", "NORMALIZE", "CLASSIFY", "ADMIT", "CALCULATE_RESERVATION", "ISSUE_CAPABILITY"])
    revoked = reference.reduce_transition(live, {"type": "REVOKE"})
    assertion("T-REVOCATION-DURABLE", revoked["accepted"] and capability["capability_digest"] in revoked["state"]["revoked_capability_digests"] and revoked["state"]["budget_reserved"] == 0)
    return 8


def make_approval() -> dict:
    targets = [{"kind": "PATH", "value": "/workspace/output/report.txt"}]
    effects = [{"effect": "MUTATE", "target": targets[0], "operations": ["WRITE"]}]
    budgets = [{"name": "CALLS", "unit": "CALLS", "limit": 1, "scope_digest": digest("1"), "lineage_root": "lineage:root"}]
    terms = {"data_classification": "INTERNAL", "provenance": ["urn:request:write-report"], "irreversibility": "PARTIALLY_REVERSIBLE", "residual_risk": "shared-filesystem-model", "compensation": "AVAILABLE", "retention": "CONTRACT", "data_flows": [{"source": "agent:worker", "recipient": "principal:ops", "channel": "channel:approval", "label": "label:report", "purpose": "purpose:TASK"}], "recipients": [{"recipient_id": "principal:ops", "kind": "PRINCIPAL", "canonical_value": "principal:ops"}], "labels": [{"label_id": "label:report", "data_classification": "INTERNAL", "purpose": "purpose:TASK", "retention": "CONTRACT"}], "aggregate_maxima": [{"name": "CALLS", "unit": "CALLS", "maximum": 1, "scope": "BATCH"}], "actors": [{"principal": "agent:worker", "role": "REQUESTER", "session_id": "session:approval", "auth_assurance": "WEBAUTHN"}, {"principal": "human:alice", "role": "APPROVER", "session_id": "session:human", "auth_assurance": "WEBAUTHN"}, {"principal": "executor:workspace", "role": "EXECUTOR", "session_id": "session:approval", "auth_assurance": "SERVICE_ATTESTED"}, {"principal": "service:approval", "role": "ISSUER", "session_id": "session:approval", "auth_assurance": "SERVICE_ATTESTED"}]}
    view_terms = deepcopy(terms)
    view_preimage = {"intent": "Write the bounded report.", "targets": targets, "effects": effects, "budgets": budgets, "material_terms": view_terms}
    view_digest = canonical_digest_for_test(view_preimage)
    terms["presentation"] = {"renderer_id": "renderer:canonical", "renderer_version": "1.0.0", "locale": "en-US", "anti_confusable_digest": view_digest, "accessibility_digest": digest("6")}
    teach_back = {"target_summary": json.dumps(targets, sort_keys=True, separators=(",", ":"), ensure_ascii=False), "aggregate_maximum": json.dumps(terms["aggregate_maxima"], sort_keys=True, separators=(",", ":"), ensure_ascii=False), "flow_recipients": json.dumps({"data_flows": terms["data_flows"], "recipients": terms["recipients"]}, sort_keys=True, separators=(",", ":"), ensure_ascii=False), "reversibility": terms["irreversibility"]}
    terms["teach_back"] = {**teach_back, "captured_at": "2026-08-24T00:00:01Z"}
    terms["batch"] = {"batch_id": "batch:one", "homogeneity": "HOMOGENEOUS", "item_count": 1, "effect_vector_digest": canonical_digest_for_test(effects), "target_set_digest": canonical_digest_for_test(targets), "aggregate_maxima": deepcopy(terms["aggregate_maxima"])}
    revocation_binding = canonical_digest_for_test({"receipt_id": "approval:one", "approval_nonce": "approval_nonce_1234567890", "revocation_epoch": 3})
    terms["freshness"] = {"not_before": "2026-08-24T00:00:02Z", "activation_not_after": "2026-08-25T00:05:00Z", "grant_expires_at": "2026-08-25T00:05:00Z", "revocation_epoch": 3, "revocation_binding_digest": revocation_binding, "clock_binding_digest": canonical_digest_for_test({"issued_at": "2026-08-24T00:00:02Z", "expires_at": "2026-08-25T00:05:00Z"})}
    terms["obligations"] = {key: [{"obligation_id": "obligation:" + key, "owner": "team:runtime", "plan_digest": digest(str(index))}] for index, key in enumerate(("notification", "monitoring", "postcheck", "reconciliation"))}; terms["obligations"]["retention"] = "CONTRACT"
    final_view_terms = deepcopy(terms); [final_view_terms.pop(key, None) for key in ("presentation", "teach_back", "freshness")]
    view_digest = canonical_digest_for_test({"intent": "Write the bounded report.", "targets": targets, "effects": effects, "budgets": budgets, "material_terms": final_view_terms})
    terms["presentation"]["anti_confusable_digest"] = view_digest
    approved_envelope = {"effects": effects, "targets": targets, "budgets": budgets, "flows": terms["data_flows"]}
    approval = {"schema_version": "1.0.0", "receipt_id": "approval:one", "receipt_type": "ORDINARY", "decision": "APPROVE", "requester": "agent:worker", "approvers": ["human:alice"], "executor": "executor:workspace", "canonical_payload_digest": digest("a"), "approval_nonce": "approval_nonce_1234567890", "quorum": {"required": 1, "present": 1, "met": True}, "separation_of_duties": {"requester_not_approver": True, "executor_not_approver": True, "verified": True}, "bindings": {"request_digest": digest("a"), "manifest_digest": digest("b"), "policy_digest": digest("c"), "contract_digest": digest("d"), "isolation_profile_digest": digest("f"), "authorized_envelope_digest": canonical_digest_for_test(effects), "reservation_vector_digest": canonical_digest_for_test(budgets), "prompt_digest": digest("1"), "context_digest": digest("2"), "model_digest": digest("3")}, "intent": "Write the bounded report.", "targets": targets, "effects": effects, "budgets": budgets, "approved_envelope": approved_envelope, "approved_envelope_digest": canonical_digest_for_test(approved_envelope), "material_terms": terms, "uncertainty": "BOUNDED", "alternatives": [], "automation_stop_reason": "HUMAN_REQUIRED", "human_authentication_evidence": [{"method": "WEBAUTHN", "subject": "human:alice", "approver_id": "human:alice", "role": "APPROVER", "session_id": "session:human", "independence_group": "group:alice", "authenticated_at": "2026-08-24T00:00:00Z", "evidence_digest": digest("4")}], "comprehension_evidence": {"canonical_view_digest": view_digest, "effect_summary_acknowledged": True, "target_summary_acknowledged": True, "budget_summary_acknowledged": True, "irreversibility_acknowledged": True, "captured_at": "2026-08-24T00:00:01Z", "presentation": deepcopy(terms["presentation"]), "teach_back": deepcopy(terms["teach_back"])}, "service_signature": {"service_identity": "service:approval", "key_id": "key:approval", "algorithm": "ED25519", "payload_digest": digest("a"), "canonical_payload_digest": digest("a"), "material_terms_digest": canonical_digest_for_test(terms), "payload_scope": "COMPLETE_CANONICAL_PAYLOAD", "signature": "A" * 64}, "lifecycle": {"phase": "ISSUED", "not_before": "2026-08-24T00:00:02Z", "activation_not_after": "2026-08-25T00:05:00Z", "grant_expires_at": "2026-08-25T00:05:00Z", "revocation_epoch": 3, "revocation_binding_digest": revocation_binding, "activation_consumption": None}, "issued_at": "2026-08-24T00:00:02Z", "expires_at": "2026-08-25T00:05:00Z", "single_use": True, "nonreplayable": True, "material_change_invalidates": True, "state": "ISSUED", "break_glass": None}
    payload = {key: value for key, value in approval.items() if key not in {"receipt_digest", "service_verification", "canonical_payload_digest", "service_signature"}}
    approval["canonical_payload_digest"] = canonical_digest_for_test(payload)
    approval["service_signature"]["payload_digest"] = approval["canonical_payload_digest"]
    approval["service_signature"]["canonical_payload_digest"] = approval["canonical_payload_digest"]
    return approval


def reseal_approval(approval: dict) -> dict:
    terms = approval["material_terms"]
    batch = terms.get("batch")
    if isinstance(batch, dict):
        batch.update(effect_vector_digest=canonical_digest_for_test(approval["effects"]), target_set_digest=canonical_digest_for_test(approval["targets"]), aggregate_maxima=deepcopy(terms["aggregate_maxima"]))
    view_terms = deepcopy(terms)
    for key in ("presentation", "teach_back", "freshness"):
        view_terms.pop(key, None)
    view_digest = canonical_digest_for_test({"intent": approval["intent"], "targets": approval["targets"], "effects": approval["effects"], "budgets": approval["budgets"], "material_terms": view_terms})
    terms["presentation"]["anti_confusable_digest"] = view_digest
    terms["teach_back"] = {
        "target_summary": json.dumps(approval["targets"], sort_keys=True, separators=(",", ":"), ensure_ascii=False),
        "aggregate_maximum": json.dumps(terms["aggregate_maxima"], sort_keys=True, separators=(",", ":"), ensure_ascii=False),
        "flow_recipients": json.dumps({"data_flows": terms["data_flows"], "recipients": terms["recipients"]}, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
        "reversibility": terms["irreversibility"],
        "captured_at": approval["comprehension_evidence"]["captured_at"],
    }
    approval["comprehension_evidence"].update(canonical_view_digest=view_digest, presentation=deepcopy(terms["presentation"]), teach_back=deepcopy(terms["teach_back"]))
    approval["service_signature"]["material_terms_digest"] = canonical_digest_for_test(terms)
    approval["approved_envelope"] = {"effects": deepcopy(approval["effects"]), "targets": deepcopy(approval["targets"]), "budgets": deepcopy(approval["budgets"]), "flows": deepcopy(terms["data_flows"])}
    approval["approved_envelope_digest"] = canonical_digest_for_test(approval["approved_envelope"])
    payload = {key: value for key, value in approval.items() if key not in {"receipt_digest", "service_verification", "canonical_payload_digest", "service_signature"}}
    approval["canonical_payload_digest"] = canonical_digest_for_test(payload)
    approval["service_signature"].update(payload_digest=approval["canonical_payload_digest"], canonical_payload_digest=approval["canonical_payload_digest"])
    return approval


def check_approval_isolation(reference, isolation, facts) -> int:
    approval = make_approval(); approval_digest = reference._approval_receipt_digest(approval); auth = approval["human_authentication_evidence"][0]; approval_facts = {"trusted_time": "2026-08-24T00:00:05Z", "current_revocation_epoch": 3, "required_approval_quorum": 1, "consumed_approval_receipts": [], "verified_approver_authentications": {auth["evidence_digest"]: {**auth, "receipt_id": approval["receipt_id"], "signature_verified": True, "not_revoked": True, "verified_by": "verifier:human"}}, "verified_approval_signatures": {approval_digest: {"receipt_digest": approval_digest, "signature_verified": True, "signed_payload_digest": approval["canonical_payload_digest"], "material_terms_digest": approval["service_signature"]["material_terms_digest"], "service_identity": approval["service_signature"]["service_identity"], "key_id": approval["service_signature"]["key_id"], "algorithm": approval["service_signature"]["algorithm"], "freshness_verified": True, "revocation_checked": True, "revocation_epoch": 3}}}; assertion("T-APPROVAL-LIFECYCLE-VALID", schema_valid("human-approval-receipt.schema.json", approval) and reference.validate_approval_receipt(approval, expected_nonce=approval["approval_nonce"], trusted_facts=approval_facts))
    two = deepcopy(approval); two["approvers"] = ["human:alice", "human:bob"]; two["quorum"] = {"required": 2, "present": 2, "met": True}; two["human_authentication_evidence"].append({"method": "HARDWARE_KEY", "subject": "human:bob", "approver_id": "human:bob", "role": "APPROVER", "session_id": "session:human-bob", "independence_group": "group:bob", "authenticated_at": "2026-08-24T00:00:00Z", "evidence_digest": digest("b")}); two = reseal_approval(two)
    two_digest = reference._approval_receipt_digest(two); two_facts = deepcopy(approval_facts); two_facts["required_approval_quorum"] = 2; two_facts["verified_approver_authentications"] = {row["evidence_digest"]: {**row, "receipt_id": two["receipt_id"], "signature_verified": True, "not_revoked": True, "verified_by": "verifier:human"} for row in two["human_authentication_evidence"]}; two_facts["verified_approval_signatures"] = {two_digest: {**approval_facts["verified_approval_signatures"][approval_digest], "receipt_digest": two_digest, "signed_payload_digest": two["canonical_payload_digest"], "material_terms_digest": two["service_signature"]["material_terms_digest"]}}
    assertion("T-ORDINARY-QUORUM-TWO-POSITIVE", schema_valid("human-approval-receipt.schema.json", two) and reference.validate_approval_receipt(two, expected_nonce=two["approval_nonce"], trusted_facts=two_facts))
    one_auth = deepcopy(two); one_auth["human_authentication_evidence"] = one_auth["human_authentication_evidence"][:1]; one_auth = reseal_approval(one_auth); one_digest = reference._approval_receipt_digest(one_auth); one_facts = deepcopy(two_facts); one_facts["verified_approval_signatures"] = {one_digest: {**next(iter(two_facts["verified_approval_signatures"].values())), "receipt_digest": one_digest, "signed_payload_digest": one_auth["canonical_payload_digest"], "material_terms_digest": one_auth["service_signature"]["material_terms_digest"]}}
    assertion("T-ORDINARY-QUORUM-ONE-AUTH-SCHEMA", schema_valid("human-approval-receipt.schema.json", one_auth))
    assertion("T-ORDINARY-QUORUM-ONE-AUTH-SEMANTIC", not reference.validate_approval_receipt(one_auth, expected_nonce=one_auth["approval_nonce"], trusted_facts=one_facts))
    shared_session = deepcopy(two); shared_session["human_authentication_evidence"][1]["session_id"] = shared_session["human_authentication_evidence"][0]["session_id"]; shared_session = reseal_approval(shared_session); shared_digest = reference._approval_receipt_digest(shared_session); shared_facts = deepcopy(two_facts); shared_facts["verified_approver_authentications"] = {row["evidence_digest"]: {**row, "receipt_id": shared_session["receipt_id"], "signature_verified": True, "not_revoked": True, "verified_by": "verifier:human"} for row in shared_session["human_authentication_evidence"]}; shared_facts["verified_approval_signatures"] = {shared_digest: {**next(iter(two_facts["verified_approval_signatures"].values())), "receipt_digest": shared_digest, "signed_payload_digest": shared_session["canonical_payload_digest"], "material_terms_digest": shared_session["service_signature"]["material_terms_digest"]}}
    assertion("T-ORDINARY-QUORUM-SHARED-SESSION-SCHEMA", schema_valid("human-approval-receipt.schema.json", shared_session))
    assertion("T-ORDINARY-QUORUM-SHARED-SESSION-SEMANTIC", not reference.validate_approval_receipt(shared_session, expected_nonce=shared_session["approval_nonce"], trusted_facts=shared_facts))
    terms_mutation = deepcopy(approval); terms_mutation["material_terms"]["irreversibility"] = "IRREVERSIBLE"
    terms_mutation["service_signature"]["payload_digest"] = terms_mutation["canonical_payload_digest"]
    assertion("T-APPROVAL-SIGNED-MATERIAL-TERMS", not reference.validate_approval_receipt(terms_mutation, expected_nonce=approval["approval_nonce"], trusted_facts=approval_facts))
    for name, expected_schema_valid, mutate in (
        ("NONAPPROVE_ISSUED", False, lambda x: x.update(decision="REJECT")),
        ("SOD", True, lambda x: x["approvers"].append(x["requester"])),
        ("QUORUM", True, lambda x: x["quorum"].update(required=2)),
        ("COMPREHENSION", False, lambda x: x["comprehension_evidence"].update(effect_summary_acknowledged=False)),
        ("NONCE", False, lambda x: x.update(approval_nonce="short")),
        ("SIGNATURE", True, lambda x: x["service_signature"].update(payload_digest=digest("b"))),
    ):
        bad = deepcopy(approval); mutate(bad)
        assertion("T-APPROVAL-" + name + "-SCHEMA", schema_valid("human-approval-receipt.schema.json", bad) is expected_schema_valid)
        assertion("T-APPROVAL-" + name + "-SEMANTIC", not reference.validate_approval_receipt(bad, expected_nonce=approval["approval_nonce"], trusted_facts=approval_facts))
    for name, mutate, fact_mutate in (
        ("EXPIRED", lambda x: x.update(expires_at="2026-08-24T00:00:04Z"), lambda f: None),
        ("TIMED_OUT", lambda x: x.update(decision="TIMED_OUT", state="TIMED_OUT"), lambda f: None),
        ("REVOKED", lambda x: x.update(state="REVOKED"), lambda f: None),
        ("CONSUMED", lambda x: None, lambda f: f["consumed_approval_receipts"].append(approval_digest)),
        ("UNCERTAIN", lambda x: x.update(uncertainty="UNKNOWN"), lambda f: None),
        ("MISSING_MATERIAL", lambda x: x["material_terms"].pop("recipients"), lambda f: None),
        ("BIDI_TARGET", lambda x: x["targets"][0].update(value="/workspace/output/report.\u202etxt"), lambda f: None),
        ("CONFUSABLE_TARGET", lambda x: x["targets"][0].update(value="/workspace/output/repоrt.txt"), lambda f: None),
        ("HIDDEN_TARGET", lambda x: x["targets"][0].update(value="/workspace/output/report\u200b.txt"), lambda f: None),
        ("CHANGED_RENDERER", lambda x: x["material_terms"]["presentation"].update(renderer_version="2.0.0"), lambda f: None),
        ("CHANGED_TEACH_BACK", lambda x: x["material_terms"]["teach_back"].update(target_summary="different"), lambda f: None),
        ("HETEROGENEOUS_BATCH", lambda x: x["material_terms"]["batch"].update(homogeneity="HETEROGENEOUS"), lambda f: None),
        ("MISSING_CLOCK", lambda x: None, lambda f: f.update(trusted_time=None)),
    ):
        bad, bad_facts = deepcopy(approval), deepcopy(approval_facts); mutate(bad); fact_mutate(bad_facts)
        assertion("T-APPROVAL-SEMANTIC-" + name, not reference.validate_approval_receipt(bad, expected_nonce=approval["approval_nonce"], trusted_facts=bad_facts))
    for name, field, value in (("FORGED-SIGNATURE", "signature_verified", False), ("WRONG-KEY", "key_id", "key:other"), ("WRONG-ALGORITHM", "algorithm", "ECDSA_P256_SHA256"), ("WRONG-ISSUER", "service_identity", "service:forged"), ("WRONG-PAYLOAD", "signed_payload_digest", digest("0"))):
        forged = deepcopy(approval_facts); forged["verified_approval_signatures"][approval_digest][field] = value
        assertion("T-APPROVAL-VERIFIER-" + name, not reference.validate_approval_receipt(approval, expected_nonce=approval["approval_nonce"], trusted_facts=forged))
    break_glass = deepcopy(approval); break_glass.update(receipt_type="BREAK_GLASS", approvers=["human:alice", "human:bob"], quorum={"required": 2, "present": 2, "met": True}, human_authentication_evidence=[{"method": "WEBAUTHN", "subject": "human:alice", "approver_id": "human:alice", "role": "INCIDENT_COMMANDER", "session_id": "session:bg-alice", "independence_group": "group:incident", "authenticated_at": "2026-08-24T00:00:00Z", "evidence_digest": digest("8"), "incident_digest": digest("9"), "profile_digest": digest("f"), "target_set_digest": digest("e")}, {"method": "HARDWARE_KEY", "subject": "human:bob", "approver_id": "human:bob", "role": "RESOURCE_AUTHORIZER", "session_id": "session:bg-bob", "independence_group": "group:resource", "authenticated_at": "2026-08-24T00:00:00Z", "evidence_digest": digest("a"), "incident_digest": digest("9"), "profile_digest": digest("f"), "target_set_digest": digest("e")}], break_glass={"emergency_profile_digest": digest("f"), "incident_digest": digest("9"), "target_set_digest": digest("e"), "inside_platform_ceiling": True, "ttl_seconds": 60, "real_time_alert_required": True, "postmortem_required": True, "recovery_plan_digest": digest("b")}, expires_at="2026-08-24T00:00:30Z")
    break_glass["lifecycle"].update(activation_not_after=break_glass["expires_at"], grant_expires_at=break_glass["expires_at"]); break_glass["material_terms"]["freshness"].update(activation_not_after=break_glass["expires_at"], grant_expires_at=break_glass["expires_at"]); break_glass["material_terms"]["freshness"]["clock_binding_digest"] = canonical_digest_for_test({"issued_at": break_glass["issued_at"], "expires_at": break_glass["expires_at"]}); break_glass["service_signature"]["material_terms_digest"] = canonical_digest_for_test(break_glass["material_terms"])
    break_glass["canonical_payload_digest"] = canonical_digest_for_test({key: value for key, value in break_glass.items() if key not in {"receipt_digest", "service_verification", "canonical_payload_digest", "service_signature"}}); break_glass["service_signature"]["payload_digest"] = break_glass["canonical_payload_digest"]; break_glass["service_signature"]["canonical_payload_digest"] = break_glass["canonical_payload_digest"]
    bg_digest = reference._approval_receipt_digest(break_glass); bg_facts = deepcopy(approval_facts); bg_facts["required_approval_quorum"] = 2; bg_facts["verified_approver_authentications"] = {row["evidence_digest"]: {**row, "receipt_id": break_glass["receipt_id"], "signature_verified": True, "not_revoked": True, "verified_by": "verifier:human"} for row in break_glass["human_authentication_evidence"]}; bg_facts["verified_approval_signatures"] = {bg_digest: {**approval_facts["verified_approval_signatures"][approval_digest], "receipt_digest": bg_digest, "signed_payload_digest": break_glass["canonical_payload_digest"], "material_terms_digest": break_glass["service_signature"]["material_terms_digest"]}}; bg_facts.update(break_glass_incident_digest=digest("9"), break_glass_profile_digest=digest("f"), break_glass_target_set_digest=digest("e"), trusted_time="2026-08-24T00:00:05Z")
    assertion("T-BREAK-GLASS-POSITIVE", schema_valid("human-approval-receipt.schema.json", break_glass) and reference.validate_approval_receipt(break_glass, expected_nonce=break_glass["approval_nonce"], trusted_facts=bg_facts))
    for name, mutate in (("SAME-SUBJECT", lambda x: x["human_authentication_evidence"][1].update(subject="human:alice", approver_id="human:alice")), ("SAME-SESSION", lambda x: x["human_authentication_evidence"][1].update(session_id=x["human_authentication_evidence"][0]["session_id"])), ("EMERGENCY-EMERGENCY", lambda x: x["human_authentication_evidence"][1].update(role="SECURITY_AUTHORIZER")), ("RESOURCE-SERVICE", lambda x: x["human_authentication_evidence"][0].update(role="RESOURCE_AUTHORIZER")), ("ROW-INCIDENT", lambda x: x["human_authentication_evidence"][1].update(incident_digest=digest("0"))), ("WRONG-INCIDENT", lambda x: x["break_glass"].update(incident_digest=digest("0")))):
        bad = deepcopy(break_glass); mutate(bad); assertion("T-BREAK-GLASS-" + name, not reference.validate_break_glass(bad, bg_facts))
    assertion("T-ISOLATION-ACTIVE-VALID", schema_valid("isolation-profile.schema.json", isolation) and reference.validate_isolation_profile(isolation, facts))
    assertion("T-Q87-IPC-POSITIVE", reference._broker_ipc_binding_valid(isolation) and isolation["process"]["rootless_user_mapping"] is True)
    for name, mutate in (("ROOTLESS", lambda p: p["process"].update(rootless_user_mapping=False)), ("NETWORK", lambda p: p["network"].update(dns="BROKER_ONLY")), ("IPC-PRINCIPAL", lambda p: p["broker_ipc_binding"].update(broker_principal="broker:other")), ("IPC-ENDPOINT", lambda p: p["broker_ipc_binding"].update(worker_endpoint="ipc:other")), ("IPC-TRANSPORT", lambda p: p["broker_ipc_binding"].update(transport="STREAM")), ("IPC-MODE", lambda p: p["broker_ipc_binding"].update(endpoint_mode="UNIX_PATHNAME")), ("IPC-DELIVERY", lambda p: p["broker_ipc_binding"].update(fd_delivery="SCM_RIGHTS_RUNTIME")), ("IPC-AUTH", lambda p: p["broker_ipc_binding"].update(sender_authentication="SO_PEERCRED_ONLY"))):
        bad = deepcopy(isolation); mutate(bad)
        assertion("T-Q87-" + name + "-REJECT", not reference.validate_isolation_profile(bad, facts))
    root_uid, root_facts = deepcopy(isolation), deepcopy(facts); root_uid["principal_envelopes"][0]["os_subject"]["uid"] = 0; root_facts["verified_role_subjects"][root_uid["principal_envelopes"][0]["principal"]]["uid"] = 0
    profile_digest = reference._control_content_digest(root_uid, "profile_digest", "profile_activation"); root_uid["profile_digest"] = root_uid["profile_activation"]["content_digest"] = profile_digest
    root_facts["verified_profile_activations"] = {profile_digest: {**root_uid["profile_activation"], "signature_verified": True, "not_revoked": True, "freshness_verified": True, "revocation_checked": True, "verified_by": "verifier:profile"}}
    for subject in root_facts["verified_role_subjects"].values(): subject["profile_digest"] = profile_digest
    assertion("T-Q87-UID-REJECT", not schema_valid("isolation-profile.schema.json", root_uid) and not reference.validate_isolation_profile(root_uid, root_facts))
    for field, value in (("worker_default", "DISABLED"), ("loopback", "NONE"), ("ipv4", "BLOCKED"), ("unix_sockets", "BROAD"), ("metadata_service", "NONE"), ("connected_fd_policy", "ANY_INHERITED"), ("external_sink_fds", "ALLOWED")):
        bad = deepcopy(isolation); bad["network"][field] = value
        assertion("T-Q87-NETWORK-EXACT-" + field.upper(), not reference.validate_isolation_profile(bad, facts))
    no_risk_evidence = deepcopy(isolation); no_risk_evidence["risk_disposition_evidence"] = []
    assertion("T-Q33-ACTIVE-ACCEPTANCE-EVIDENCE-REQUIRED", not reference.validate_isolation_profile(no_risk_evidence, facts));
    revoked_risk = deepcopy(facts); revoked_risk["verified_risk_dispositions"][isolation["risk_disposition_evidence"][0]["evidence_id"]]["not_revoked"] = False
    assertion("T-Q33-RISK-EVIDENCE-REVOCATION-FAIL-CLOSED", not reference.validate_isolation_profile(isolation, revoked_risk));
    for name, expected_schema_valid, mutate in (
        ("DUPLICATE_ROLE", False, lambda x: x["principal_envelopes"].__setitem__(1, deepcopy(x["principal_envelopes"][0]))),
        ("WORKER_AMBIENT", False, lambda x: x["principal_envelopes"][0].update(ambient_authority=True)),
        ("RESOURCE_MISSING", False, lambda x: x["resources"].pop()),
        ("ATTESTATION_MISSING", False, lambda x: x["attestation"].update(placement_required=False)),
        ("SUPPLY_ROLLBACK", True, lambda x: x["supply_chain"].update(registry_generation=6)),
    ):
        bad = deepcopy(isolation); mutate(bad)
        assertion("T-ISOLATION-" + name + "-SCHEMA", schema_valid("isolation-profile.schema.json", bad) is expected_schema_valid)
        assertion("T-ISOLATION-" + name + "-SEMANTIC", not reference.validate_isolation_profile(bad))
    return 12


def check_approval_digest_chain(reference, candidate, manifest, policy, isolation, facts, allow_decision) -> int:
    human_policy = deepcopy(policy)
    human_policy["authority_map"][0]["approval_class"] = "HUMAN_SINGLE"
    human_facts, pending_candidate = deepcopy(facts), deepcopy(candidate)
    refresh_policy_activation(reference, human_policy, human_facts, pending_candidate)
    pending_candidate["approval_receipt"] = None
    pending = reference.decide(pending_candidate, manifest, human_policy, isolation, human_facts)
    assertion("T-Q30-HUMAN-PENDING-NULL-DIGEST", pending["decision"] == "REQUIRE_HUMAN" and pending["evaluation"]["approval_mode"] == "REQUIRED" and pending["approval_receipt_digest"] is None and schema_valid("decision-result.schema.json", pending) and reference.decision_digest_valid(pending))
    candidate, facts = pending_candidate, human_facts

    kind_map = {"FILE": "PATH", "DIRECTORY": "PATH", "ENDPOINT": "ENDPOINT", "PRINCIPAL": "PRINCIPAL", "MEMORY": "MEMORY", "PROMPT": "PROMPT", "POLICY": "POLICY", "PROCESS": "PROCESS", "REGISTRY": "LOCAL_RESOURCE", "COMPUTE_RESOURCE": "LOCAL_RESOURCE"}
    targets, effects = [], []
    for entry in allow_decision["authorized_envelope"]:
        target = {"kind": kind_map[entry["resource_kind"]], "value": entry["selector"]["canonical_value"]}
        if target not in targets:
            targets.append(target)
        effects.append({"effect": entry["effect"], "target": target, "operations": [entry["operation"]]})
    approval = make_approval()
    approval["requester"], approval["executor"] = candidate["principal"], candidate["audience"]
    approval["targets"], approval["effects"] = targets, effects
    approval["budgets"] = [{"name": item["name"], "unit": item["unit"], "limit": item["amount"], "scope_digest": item["scope_digest"], "lineage_root": item["lineage_root"]} for item in allow_decision["reservations"]]
    approval["bindings"].update(
        request_digest=candidate["request_digest"],
        manifest_digest=candidate["bindings"]["manifest_digest"],
        policy_digest=candidate["bindings"]["policy_digest"],
        contract_digest=candidate["bindings"]["contract_digest"],
        isolation_profile_digest=candidate["bindings"]["isolation_profile_digest"],
        authorized_envelope_digest=reference.canonical_digest(allow_decision["authorized_envelope"]),
        reservation_vector_digest=reference.canonical_digest(allow_decision["reservations"]),
    )
    terms = approval["material_terms"]
    terms["aggregate_maxima"] = [{"name": item["name"], "unit": item["unit"], "maximum": item["amount"], "scope": "BATCH"} for item in allow_decision["reservations"]]
    terms["data_flows"] = [{"source": candidate["principal"], "recipient": candidate["audience"], "channel": "channel:local-output", "label": "label:report", "purpose": "purpose:TASK"}]
    terms["recipients"] = [{"recipient_id": candidate["audience"], "kind": "PRINCIPAL", "canonical_value": candidate["audience"]}]
    approval = reseal_approval(approval)
    approval_digest = reference._approval_receipt_digest(approval)
    approval_auth = approval["human_authentication_evidence"][0]
    approval_signature_facts = {
        "trusted_time": facts["trusted_time"],
        "current_revocation_epoch": facts["current_revocation_epoch"],
        "required_approval_quorum": approval["quorum"]["required"],
        "consumed_approval_receipts": [],
        "verified_approver_authentications": {approval_auth["evidence_digest"]: {**approval_auth, "receipt_id": approval["receipt_id"], "signature_verified": True, "not_revoked": True, "verified_by": "verifier:human"}},
        "verified_approval_signatures": {approval_digest: {"receipt_digest": approval_digest, "signature_verified": True, "signed_payload_digest": approval["canonical_payload_digest"], "material_terms_digest": approval["service_signature"]["material_terms_digest"], "service_identity": approval["service_signature"]["service_identity"], "key_id": approval["service_signature"]["key_id"], "algorithm": approval["service_signature"]["algorithm"], "freshness_verified": True, "revocation_checked": True, "revocation_epoch": 3}},
    }
    assertion("T-Q30-FULL-APPROVAL-EXACT-VALID", schema_valid("human-approval-receipt.schema.json", approval) and reference.validate_approval_receipt(approval, expected_nonce=approval["approval_nonce"], trusted_facts=approval_signature_facts))

    approval_facts = {
        "receipt_digest": approval_digest,
        "decision": "APPROVE",
        "state": "ISSUED",
        "nonce": approval["approval_nonce"],
        "request_digest": candidate["request_digest"],
        "authorized_envelope_digest": approval["bindings"]["authorized_envelope_digest"],
        "binding_set_digest": reference.canonical_digest(approval["bindings"]),
        "budget_vector_digest": approval["bindings"]["reservation_vector_digest"],
        "approvers": deepcopy(approval["approvers"]),
        "quorum_required": approval["quorum"]["required"],
        "issued_at": approval["issued_at"],
        "expires_at": approval["expires_at"],
        "revocation_epoch": approval["lifecycle"]["revocation_epoch"],
        "fencing_epoch": candidate["session_attestation"]["epoch"],
        "consumed": False,
        "material_change": False,
        "service_verification": {"verified_by": "verifier:approval", "key_id": approval["service_signature"]["key_id"], "algorithm": approval["service_signature"]["algorithm"], "signed_payload_digest": approval["canonical_payload_digest"], "signature_verified": True, "verified_at": facts["trusted_time"]},
    }
    chain_facts = deepcopy(facts)
    chain_facts["approval_challenges"] = {candidate["request_digest"]: approval["approval_nonce"]}
    chain_facts["verified_approval_receipts"] = {approval_digest: {"approval_facts_digest": reference.canonical_digest(approval_facts), "receipt_digest": approval_digest, "full_receipt_digest": approval_digest, "approved_envelope_digest": approval_facts["authorized_envelope_digest"], "binding_set_digest": approval_facts["binding_set_digest"], "candidate_bindings_digest": reference.canonical_digest(candidate["bindings"]), "signed_payload_digest": approval["canonical_payload_digest"], "verified_by": "verifier:approval", "key_id": approval["service_signature"]["key_id"], "algorithm": approval["service_signature"]["algorithm"], "signature_verified": True, "full_receipt_valid": True, "separation_of_duties_verified": True, "comprehension_verified": True, "freshness_verified": True, "revocation_checked": True, "not_revoked": True}}
    approved_candidate = deepcopy(candidate)
    approved_candidate["approval_receipt"] = approval_facts
    approved = reference.decide(approved_candidate, manifest, human_policy, isolation, chain_facts)
    assertion("T-Q30-DECISION-EXACT-DIGEST", schema_valid("admission-candidate.schema.json", approved_candidate) and approved["decision"] == "ALLOW" and approved["approval_receipt_digest"] == approval_digest == approved["evaluation"]["approval_receipt_digest"] and schema_valid("decision-result.schema.json", approved) and reference.decision_digest_valid(approved))
    trusted_envelope_mismatch = deepcopy(chain_facts)
    trusted_envelope_mismatch["verified_approval_receipts"][approval_digest]["approved_envelope_digest"] = digest("0")
    assertion("T-Q93-TRUSTED-APPROVAL-ENVELOPE-EXACT", reference.decide(approved_candidate, manifest, human_policy, isolation, trusted_envelope_mismatch)["decision"] == "REQUIRE_HUMAN")

    capability = reference.mint_capability(approved, approved_candidate)
    if capability is not None:
        chain_facts["verified_capability_claims"][capability["capability_id"]] = reference.capability_verifier_record(capability)
    assertion("T-Q30-CAPABILITY-EXACT-DIGEST", capability is not None and capability["bindings"]["approval_receipt_digest"] == approval_digest and schema_valid("capability.schema.json", capability) and reference.validate_capability(capability, approved, approved_candidate, chain_facts))
    dispatched, _ = advance(reference, "STAGEABLE", approved, capability, ["PROPOSE", "NORMALIZE", "CLASSIFY", "ADMIT", "CALCULATE_RESERVATION", "ISSUE_CAPABILITY", "DURABLE_DISPATCH"])
    assertion("T-Q30-DISPATCH-EXACT-DIGEST", dispatched["phase"] == "EXECUTING" and dispatched["approval_mode"] == "REQUIRED" and dispatched["approval_receipt_digest"] == approval_digest)

    missing = deepcopy(approved)
    missing["approval_receipt_digest"] = missing["evaluation"]["approval_receipt_digest"] = None
    missing["decision_digest"] = reference.canonical_digest({key: value for key, value in missing.items() if key != "decision_digest"})
    assertion("T-Q30-DECISION-NULL-REJECT", not schema_valid("decision-result.schema.json", missing) and reference.mint_capability(missing, approved_candidate) is None)
    substituted = deepcopy(approved)
    substituted["approval_receipt_digest"] = substituted["evaluation"]["approval_receipt_digest"] = digest("0")
    substituted["decision_digest"] = reference.canonical_digest({key: value for key, value in substituted.items() if key != "decision_digest"})
    assertion("T-Q30-DECISION-SUBSTITUTION-REJECT", schema_valid("decision-result.schema.json", substituted) and reference.mint_capability(substituted, approved_candidate) is None)

    bad_capability, bad_capability_facts = deepcopy(capability), deepcopy(chain_facts)
    bad_capability["bindings"]["approval_receipt_digest"] = digest("0")
    refresh_capability(reference, bad_capability, bad_capability_facts)
    assertion("T-Q30-CAPABILITY-SUBSTITUTION-REJECT", not reference.validate_capability(bad_capability, approved, approved_candidate, bad_capability_facts))
    issued, _ = advance(reference, "STAGEABLE", approved, capability, ["PROPOSE", "NORMALIZE", "CLASSIFY", "ADMIT", "CALCULATE_RESERVATION", "ISSUE_CAPABILITY"])
    bad_dispatch = event_for("DURABLE_DISPATCH", approved, capability, approval_receipt_digest=digest("0"))
    assertion("T-Q30-DISPATCH-SUBSTITUTION-REJECT", not reference.reduce_transition(issued, bad_dispatch)["accepted"])

    _, effect_receipt, safety_event = make_effect_evidence(approved, capability)
    receipt_digest = reference.canonical_digest(effect_receipt)
    receipt_payload_digest = reference.canonical_digest({key: value for key, value in effect_receipt.items() if key != "authoritative_verifier"})
    effect_facts = {"approval_mode": "REQUIRED", "approval_receipt_digest": approval_digest, "stage_evidence": receipt_stage_evidence(effect_receipt), "receipt_chain_heads": {effect_receipt["chain"]["source_id"]: {"epoch": effect_receipt["chain"]["epoch"], "next_sequence": effect_receipt["chain"]["sequence"], "predecessor_digest": effect_receipt["chain"]["predecessor_digest"]}}, "verified_effect_receipts": {receipt_digest: {"receipt_digest": receipt_digest, "payload_digest": receipt_payload_digest, "object_id": effect_receipt["object_id"], "object_digest": effect_receipt["object_digest"], "object_identity": deepcopy(effect_receipt["object_identity"]), "session_id": effect_receipt["bindings"]["session_id"], "decision_digest": effect_receipt["bindings"]["decision_digest"], "capability_digest": effect_receipt["bindings"]["capability_digest"], "dispatch_intent_digest": effect_receipt["dispatch"]["intent_digest"], "authoritative_verifier": deepcopy(effect_receipt["authoritative_verifier"])}}}
    effect_facts.update(event_trust_facts(safety_event))
    assertion("T-Q30-EVIDENCE-EXACT-DIGEST", schema_valid("effect-receipt.schema.json", effect_receipt) and reference.validate_effect_receipt(effect_receipt, effect_facts) and schema_valid("event-envelope.schema.json", safety_event) and reference.validate_safety_event(safety_event, effect_facts))
    for name, value in (("NULL", None), ("SUBSTITUTED", digest("0"))):
        bad_receipt = deepcopy(effect_receipt)
        bad_receipt["bindings"]["approval_receipt_digest"] = value
        bad_event = deepcopy(safety_event)
        bad_event["bindings"]["approval_receipt_digest"] = value
        assertion("T-Q30-EVIDENCE-" + name + "-REJECT", not reference.validate_effect_receipt(bad_receipt, effect_facts) and not reference.validate_safety_event(bad_event, effect_facts))
    return 12


def check_attestation_supply(reference, candidate, manifest, policy, isolation, facts) -> int:
    fake_verifier = deepcopy(candidate); fake_facts = deepcopy(facts); fake_facts["verified_attestations"][candidate["placement_attestation"]["attestation_digest"]]["signature_verified"] = False
    assertion("T-ATTESTATION-EXTERNAL-VERIFIER-FACTS", reference.decide(fake_verifier, manifest, policy, isolation, fake_facts)["reason_codes"] == ["PLACEMENT_OR_SESSION_ATTESTATION_INVALID"])
    self_consistent_fake = deepcopy(candidate); self_consistent_fake["placement_attestation"]["signature"].update(key_id="key:caller", payload_digest=digest("0"), verified_by="verifier:caller"); no_anchor = deepcopy(facts); no_anchor["verified_attestations"].pop(candidate["placement_attestation"]["attestation_digest"])
    assertion("T-ATTESTATION-SELF-CONSISTENT-CALLER-DENY", reference.decide(self_consistent_fake, manifest, policy, isolation, no_anchor)["reason_codes"] == ["PLACEMENT_OR_SESSION_ATTESTATION_INVALID"])
    for name, mutate in (
        ("SUBJECT", lambda x: x["session_attestation"].update(subject_instance_id="instance:other")),
        ("PLACEMENT_NONCE", lambda x: x["session_attestation"].update(nonce=x["placement_attestation"]["nonce"])),
        ("EPOCH", lambda x: x["session_attestation"].update(epoch=4)),
        ("BINDING", lambda x: x["bindings"].update(session_attestation_digest=digest("0"))),
        ("FRESHNESS", lambda x: x["session_attestation"].update(expires_at="2026-08-24T00:00:04Z")),
    ):
        bad = deepcopy(candidate); mutate(bad)
        result = reference.decide(bad, manifest, policy, isolation, facts)
        assertion("T-ATTESTATION-" + name, result["reason_codes"] == ["PLACEMENT_OR_SESSION_ATTESTATION_INVALID"])
    for name, mutate in (
        ("SIGNATURE", lambda x: x["supply_chain"]["components"][0].update(signature_verified=False)),
        ("REVOCATION", lambda x: x["supply_chain"]["components"][0].update(revocation_epoch=2)),
        ("ROLLBACK", lambda x: x["supply_chain"]["components"][0].update(registry_generation=6)),
        ("EXACT_BYTES", lambda x: x["supply_chain"]["components"][0].update(exact_bytes_digest=digest("f"))),
        ("COMPOSITE", lambda x: x["supply_chain"].update(composite_measurement_digest=digest("0"))),
    ):
        bad = deepcopy(candidate); mutate(bad)
        result = reference.decide(bad, manifest, policy, isolation, facts)
        assertion("T-SUPPLY-" + name, result["reason_codes"] == ["SUPPLY_CHAIN_MEASUREMENT_INVALID"])
    for name, mutate in (
        ("SESSION_MEASUREMENT", lambda x: x["session_attestation"].update(measurement_digest=digest("0"))),
        ("PLACEMENT_MEASUREMENT", lambda x: x["placement_attestation"].update(measurement_digest=digest("0"))),
    ):
        bad = deepcopy(candidate); mutate(bad)
        assertion("T-SUPPLY-END-TO-END-" + name, reference.decide(bad, manifest, policy, isolation, facts)["reason_codes"] in (["SUPPLY_CHAIN_MEASUREMENT_INVALID"], ["PLACEMENT_OR_SESSION_ATTESTATION_INVALID"]))
    bad_isolation, isolation_manifest, isolation_policy, isolation_facts, isolation_candidate = deepcopy(isolation), deepcopy(manifest), deepcopy(policy), deepcopy(facts), deepcopy(candidate); bad_isolation["supply_chain"]["composite_measurement_digest"] = digest("0")
    refresh_profile_activation(reference, bad_isolation, isolation_facts, isolation_candidate)
    refresh_profile_consumers(reference, isolation_manifest, isolation_policy, bad_isolation, isolation_facts, isolation_candidate)
    assertion("T-SUPPLY-END-TO-END-ISOLATION", reference.decide(isolation_candidate, isolation_manifest, isolation_policy, bad_isolation, isolation_facts)["reason_codes"] == ["SUPPLY_CHAIN_MEASUREMENT_INVALID"])
    substituted = deepcopy(candidate); substituted["supply_chain"]["components"][0]["exact_bytes_digest"] = digest("f"); recomputed = reference.canonical_digest(substituted["supply_chain"]["components"]); substituted["supply_chain"]["composite_measurement_digest"] = recomputed; substituted["bindings"]["supply_chain_measurement_digest"] = recomputed
    assertion("T-SUPPLY-RECOMPUTED-OLD-PLACEMENT-REJECT", reference.decide(substituted, manifest, policy, isolation, facts)["reason_codes"] == ["SUPPLY_CHAIN_MEASUREMENT_INVALID"])
    return 10


def check_host(reference) -> int:
    heartbeat = {"host_id": "host:one", "instance_id": "instance:one", "session_id": "session:one", "epoch": 1, "sequence": 1, "signature_verified": True, "not_revoked": True, "verified_by": "observer:runtime"}; heartbeat["record_digest"] = canonical_digest_for_test(heartbeat)
    recovery = {"host_id": "host:one", "instance_id": "instance:one", "session_id": "session:one", "fencing_epoch": 2, "orphan_inventory_digest": canonical_digest_for_test(["tx:one"]), "recovered_ids_digest": canonical_digest_for_test(["tx:one"]), "cleanup_verified": True, "absence_proof_digest": digest("a"), "stale_writers_absent": True, "residue_absent": True, "signature_verified": True, "not_revoked": True, "verified_by": "observer:runtime"}; recovery["record_digest"] = canonical_digest_for_test(recovery)
    state = reference.initial_host_state({"verified_host_heartbeats": {"heartbeat:one": heartbeat}, "verified_host_recoveries": {"recovery:one": recovery}}); events = [
        {"type": "ALLOCATE", "host_id": "host:one", "instance_id": "instance:one", "nonce": "host_nonce_12345678901234"},
        {"type": "ATTEST_PLACEMENT", "instance_id": "instance:one", "nonce": "host_nonce_12345678901234", "epoch": 1, "placement_digest": digest("7")},
        {"type": "START_SESSION", "session_id": "session:one", "placement_digest": digest("7")},
        {"type": "HEARTBEAT", "sequence": 1, "epoch": 1, "heartbeat_evidence_ref": "heartbeat:one"}, {"type": "CRASH", "orphan_inventory": ["tx:one"]}, {"type": "FENCE"},
        {"type": "RECOVER_ORPHAN", "fencing_epoch": 2, "recovered_ids": ["tx:one"], "recovery_evidence_ref": "recovery:one"}, {"type": "TERMINATE"},
    ]
    for event in events:
        result = reference.reduce_host(state, event); assertion("T-HOST-" + event["type"], result["accepted"], result["reason_code"]); state = result["state"]
    stale = reference.initial_host_state(); stale = reference.reduce_host(stale, events[0])["state"]
    assertion("T-HOST-STALE-PLACEMENT", not reference.reduce_host(stale, {**events[1], "epoch": 0})["accepted"])
    incomplete = deepcopy(state); incomplete["phase"] = "FENCED"; incomplete["orphan_inventory"] = ["tx:one"]
    assertion("T-HOST-ORPHAN-INCOMPLETE", not reference.reduce_host(incomplete, {"type": "RECOVER_ORPHAN", "fencing_epoch": incomplete["epoch"], "recovered_ids": []})["accepted"])
    return len(events) + 2


def normative_requirement_catalog(source_texts: dict[str, str] | None = None) -> tuple[dict[str, list[str]], list[str]]:
    """Parse the six normative tables; docs, not the trace JSON, define their rows."""
    rows, errors = {}, []
    for level, filename in NORMATIVE_REQUIREMENT_SOURCES:
        text = (source_texts or {}).get(filename, (ROOT / filename).read_text(encoding="utf-8"))
        for line_number, line in enumerate(text.splitlines(), 1):
            if not line.lstrip().startswith("|") or not re.search(rf"`{level}-REQ-[0-9]+[a-z]?`", line):
                continue
            if not line.rstrip().endswith("|"):
                errors.append(f"catalog:{filename}:{line_number}:row-terminator")
                continue
            cells = [cell.strip() for cell in line.strip()[1:-1].split("|")]
            requirement_id = cells[0].strip("`") if cells else ""
            if len(cells) != 5 or not all(cells) or not re.fullmatch(rf"{level}-REQ-[0-9]+[a-z]?", requirement_id):
                errors.append(f"catalog:{filename}:{line_number}:row")
                continue
            if requirement_id in rows:
                errors.append(f"catalog:{filename}:{line_number}:duplicate:{requirement_id}")
                continue
            rows[requirement_id] = [filename, *cells]
    if "L5-REQ-001" not in rows or not rows.get("L5-REQ-001", ["", ""])[2]:
        errors.append("catalog:L5-REQ-001:definition")
    return rows, errors


def canonical_status_marker() -> str:
    return "Q94-STATUS-VECTOR: " + "; ".join(f"{field}={value}" for field, value in CANONICAL_STATUS.items())


def status_coherence_errors(
    trace: dict,
    source_texts: dict[str, str] | None = None,
    projection_objects: dict[str, dict] | None = None,
) -> list[str]:
    """Consistency verification: status drift is a fail-closed regression."""
    errors = []
    if trace.get("status") != CANONICAL_STATUS:
        errors.append("status:honesty")
    artifacts = trace.get("status_artifacts")
    if artifacts != list(STATUS_ARTIFACTS):
        errors.append("status:artifacts")
    if isinstance(artifacts, list):
        marker = canonical_status_marker()
        for filename in artifacts:
            if filename not in STATUS_ARTIFACTS:
                continue
            text = source_texts[filename] if source_texts and filename in source_texts else (ROOT / filename).read_text(encoding="utf-8")
            if text.count(marker) != 1:
                errors.append("status:marker-drift:" + filename)
    projections = trace.get("status_projection_artifacts")
    if projections != list(STATUS_PROJECTION_ARTIFACTS):
        errors.append("status:projection-artifacts")
    if isinstance(projections, list):
        for filename in projections:
            if filename not in STATUS_PROJECTION_ARTIFACTS:
                continue
            projection = projection_objects[filename] if projection_objects and filename in projection_objects else load(ROOT / filename)
            if projection.get("status_reference") != STATUS_REFERENCE or "status" in projection:
                errors.append("status:projection-drift:" + filename)
    return errors


def traceability_errors(trace: dict, executed: set[str], status_source_texts: dict[str, str] | None = None) -> list[str]:
    errors = []
    registries = trace.get("registries", {})
    for field in ("requirements", "schema_fields", "enforcement_points", "tests", "evidence"):
        if not isinstance(registries.get(field), list) or len(registries[field]) != len(set(registries[field])): errors.append("registry:" + field)
    catalog, catalog_errors = normative_requirement_catalog()
    errors.extend(catalog_errors)
    catalog_metadata = trace.get("normative_requirement_catalog")
    expected_catalog_digest = canonical_digest_for_test(catalog)
    event_alert_by_level = catalog_metadata.get("event_alert_by_level") if isinstance(catalog_metadata, dict) else None
    if not isinstance(catalog_metadata, dict) or catalog_metadata.get("sources") != [filename for _, filename in NORMATIVE_REQUIREMENT_SOURCES] or catalog_metadata.get("row_count") != len(catalog) or catalog_metadata.get("digest") != expected_catalog_digest or not isinstance(event_alert_by_level, dict) or set(event_alert_by_level) != {level for level, _ in NORMATIVE_REQUIREMENT_SOURCES} or any(not isinstance(event_alert_by_level[level], str) or not event_alert_by_level[level].strip() for level in event_alert_by_level):
        errors.append("catalog:metadata-or-digest")
    preimage_input = trace.get("evidence_preimages", {}).get("input", {})
    if not isinstance(preimage_input, dict) or preimage_input.get("normative_requirement_catalog_digest") != expected_catalog_digest:
        errors.append("catalog:evidence-preimage-binding")
    if registries.get("requirements") != list(catalog):
        errors.append("registry:requirements:catalog-equality")
    non_normative = trace.get("non_normative_registry_nodes", {})
    if isinstance(non_normative, dict) and non_normative.get("requirements"):
        errors.append("registry:requirements:non-normative")
    reverse = trace.get("reverse_edges")
    if not isinstance(reverse, dict):
        errors.append("reverse_edges:missing")
    else:
        for field in ("requirements", "schema_fields", "enforcement_points", "tests", "evidence"):
            forward = {}
            for invariant in trace.get("invariants", []):
                if not isinstance(invariant, dict):
                    continue
                for value in invariant.get(field, []):
                    forward.setdefault(value, set()).add(invariant.get("id"))
            allowed_non_normative = set(non_normative.get(field, [])) if isinstance(non_normative, dict) else set()
            reverse_field = reverse.get(field)
            if not isinstance(reverse_field, dict):
                errors.append("reverse_edges:" + field)
                continue
            if set(registries.get(field, [])) != (set(forward) | allowed_non_normative):
                errors.append("registry:" + field + ":coverage")
            if set(reverse_field) != (set(forward) | allowed_non_normative):
                errors.append("reverse_edges:" + field + ":coverage")
            for value, invariant_ids in forward.items():
                back = reverse_field.get(value)
                if not isinstance(back, list) or len(back) != len(set(back)) or set(back) != invariant_ids:
                    errors.append("reverse_edges:" + field + ":" + str(value))
            for value in allowed_non_normative:
                if reverse_field.get(value) not in ([], None):
                    errors.append("reverse_edges:" + field + ":non-normative:" + str(value))
    invariants = trace.get("invariants", [])
    ids = [item.get("id") for item in invariants if isinstance(item, dict)]
    if len(ids) != len(set(ids)): errors.append("invariants:duplicate-id")
    if set(ids) != set(CANONICAL_INVARIANT_CLAIMS): errors.append("invariants:canonical-id-set")
    claim_hashes = trace.get("claim_hashes", {})
    if not isinstance(claim_hashes, dict) or trace.get("assertion_count_source") != "EXECUTED_ASSERTION_INSTANCES": errors.append("claims:immutable-registry")
    elif set(claim_hashes) != set(ids): errors.append("claims:bidirectional-id-map")
    for invariant in invariants:
        expected_source = f"04_FORMAL_CORE_AND_INVARIANTS.md#{invariant.get('id')}"
        if invariant.get("claim_source") != expected_source:
            errors.append(f"{invariant.get('id')}:claim-source")
        if invariant.get("claim") != CANONICAL_INVARIANT_CLAIMS.get(invariant.get("id")):
            errors.append(f"{invariant.get('id')}:canonical-claim")
        expected_claim_hash = claim_hashes.get(invariant.get("id")) if isinstance(claim_hashes, dict) else None
        if expected_claim_hash != canonical_digest_for_test(invariant.get("claim")):
            errors.append(f"{invariant.get('id')}:claim-hash")
        for field in ("requirements", "schema_fields", "enforcement_points", "tests", "evidence"):
            for value in invariant.get(field, []):
                if value not in registries.get(field, []): errors.append(f"{invariant.get('id')}:{field}:{value}")
        for test_id in invariant.get("tests", []):
            if test_id not in executed: errors.append(f"{invariant.get('id')}:not-executed:{test_id}")
    if isinstance(reverse, dict) and isinstance(reverse.get("requirements"), dict):
        by_id = {invariant.get("id"): invariant for invariant in invariants if isinstance(invariant, dict)}
        for requirement_id, invariant_ids in reverse["requirements"].items():
            mapped = [by_id.get(invariant_id) for invariant_id in invariant_ids] if isinstance(invariant_ids, list) else []
            if not mapped or any(not isinstance(invariant, dict) or any(not invariant.get(field) for field in ("schema_fields", "enforcement_points", "tests", "evidence")) for invariant in mapped):
                errors.append("requirements:invariant-evidence:" + str(requirement_id))
    errors.extend(status_coherence_errors(trace, status_source_texts))
    for anchor_field in ("round5_regression_anchors", "round7a_regression_anchors", "round8a_regression_anchors"):
        anchors = trace.get(anchor_field)
        if not isinstance(anchors, dict):
            errors.append("regression-anchors:missing:" + anchor_field); continue
        for issue_id, test_ids in anchors.items():
            if not isinstance(issue_id, str) or not isinstance(test_ids, list) or not test_ids or len(test_ids) != len(set(test_ids)):
                errors.append("regression-anchors:malformed:" + anchor_field); continue
            for test_id in test_ids:
                if test_id not in executed: errors.append("regression-anchors:not-executed:" + str(test_id))
    attack = trace.get("attack_registry")
    if not isinstance(attack, dict) or not isinstance(attack.get("entries"), list):
        errors.append("attack_registry:missing")
    else:
        catalog_ids, matrix_ids = [], []
        for entry in attack["entries"]:
            if not isinstance(entry, dict) or not isinstance(entry.get("catalog_id"), str) or not entry.get("owner"):
                errors.append("attack_registry:malformed")
                continue
            mids = entry.get("matrix_ids", entry.get("matrix_id"))
            if isinstance(mids, str): mids = [mids]
            if not isinstance(mids, list) or not mids or any(not isinstance(mid, str) for mid in mids):
                errors.append("attack_registry:matrix_ids")
                continue
            catalog_ids.append(entry["catalog_id"]); matrix_ids.extend(mids)
        extensions = attack.get("matrix_only_extensions", [])
        for extension in extensions if isinstance(extensions, list) else []:
            if not isinstance(extension, dict) or not isinstance(extension.get("matrix_id"), str) or not extension.get("owner"):
                errors.append("attack_registry:extension")
            else:
                matrix_ids.append(extension["matrix_id"])
        if len(catalog_ids) != len(set(catalog_ids)) or len(matrix_ids) != len(set(matrix_ids)):
            errors.append("attack_registry:duplicate-id")
        if set(catalog_ids) != {f"CAT-ATK-{index:03d}" for index in range(1, 31)}:
            errors.append("attack_registry:catalog-coverage")
        if set(matrix_ids) != {f"ATK-{index:03d}" for index in range(1, 36)}:
            errors.append("attack_registry:matrix-coverage")
        attack_map = trace.get("attack_map")
        if not isinstance(attack_map, dict):
            errors.append("attack_map:missing")
        else:
            declared_catalog = {entry.get("catalog_id") for entry in attack["entries"] if isinstance(entry, dict)}
            declared_matrix = set(matrix_ids)
            mapped_catalog, mapped_matrix = set(), set()
            for key, value in attack_map.items():
                targets = value if isinstance(value, list) else [value]
                if key not in declared_catalog or not targets or any(target not in declared_matrix for target in targets):
                    errors.append("attack_map:unresolved")
                if key in mapped_catalog or any(target in mapped_matrix for target in targets):
                    errors.append("attack_map:ambiguous")
                mapped_catalog.add(key); mapped_matrix.update(targets)
            if mapped_catalog != declared_catalog or mapped_matrix != declared_matrix:
                errors.append("attack_map:coverage")
            for entry in attack["entries"]:
                if isinstance(entry, dict):
                    mids = entry.get("matrix_ids", entry.get("matrix_id")); mids = [mids] if isinstance(mids, str) else mids
                    if attack_map.get(entry.get("catalog_id")) != mids:
                        errors.append("attack_map:entry-mismatch")
    preimages = trace.get("evidence_preimages")
    records = trace.get("evidence_records")
    if not isinstance(preimages, dict) or not isinstance(records, dict):
        errors.append("evidence:preimages-or-records-missing")
    else:
        expected_environment_digest = canonical_digest_for_test(preimages.get("environment"))
        expected_input_digest = canonical_digest_for_test(preimages.get("input"))
        if preimages.get("environment_digest") != expected_environment_digest or preimages.get("input_digest") != expected_input_digest:
            errors.append("evidence:preimage-digest")
        for evidence_id in registries.get("evidence", []):
            record = records.get(evidence_id); preimage = preimages
            if not isinstance(record, dict):
                errors.append("evidence:missing:" + str(evidence_id)); continue
            for field in ("command", "environment_digest", "input_digest", "result", "status"):
                if field not in record: errors.append("evidence:field:" + str(evidence_id) + ":" + field)
            if record.get("command") != preimage.get("command") or record.get("environment_digest") != expected_environment_digest or record.get("input_digest") != expected_input_digest:
                errors.append("evidence:preimage:" + str(evidence_id))
            if evidence_id == "EV-TRACEABILITY-EXECUTION" and record.get("input_digest") != expected_input_digest:
                errors.append("evidence:catalog-preimage:" + str(evidence_id))
            if record.get("status") not in {"SPECIFICATION_MODEL_TESTED", "NOT_IMPLEMENTED", "NOT_ATTESTED"} or "runtime" in str(record.get("result", "")).lower() and record.get("status") == "RUNTIME_VERIFIED":
                errors.append("evidence:status:" + str(evidence_id))
    return errors


def check_traceability() -> int:
    trace = load(TESTS / "invariant-traceability.json")
    q81_anchor_ids = set(trace["round8a_regression_anchors"]["Q-81"])
    unresolved = deepcopy(trace); unresolved["invariants"][0]["tests"].append("T-NOT-REGISTERED")
    assertion("T-TRACEABILITY-UNRESOLVED-FAILS", bool(traceability_errors(unresolved, EXECUTED_TEST_IDS)))
    removed = set(EXECUTED_TEST_IDS); removed.discard(trace["invariants"][0]["tests"][0])
    assertion("T-TRACEABILITY-REMOVED-ASSERTION-FAILS", bool(traceability_errors(trace, removed)))
    changed_claim = deepcopy(trace); changed_claim["invariants"][0]["claim"] += " changed"
    assertion("T-TRACEABILITY-CLAIM-HASH-FAILS", bool(traceability_errors(changed_claim, EXECUTED_TEST_IDS)))
    duplicate_id = deepcopy(trace); duplicate_id["invariants"][1]["id"] = duplicate_id["invariants"][0]["id"]
    assertion("T-TRACEABILITY-DUPLICATE-ID-FAILS", bool(traceability_errors(duplicate_id, EXECUTED_TEST_IDS)))
    changed_id = deepcopy(trace); changed_id["invariants"][0]["id"] = "INV-999"
    assertion("T-TRACEABILITY-SEMANTIC-ID-FAILS", bool(traceability_errors(changed_id, EXECUTED_TEST_IDS)))
    changed_source = deepcopy(trace); changed_source["invariants"][0]["claim_source"] = "private-alias:INV-001"
    assertion("T-TRACEABILITY-CLAIM-SOURCE-FAILS", bool(traceability_errors(changed_source, EXECUTED_TEST_IDS)))
    orphan = deepcopy(trace); orphan["registries"]["tests"].append("T-ORPHAN-REGISTRY")
    assertion("T-TRACEABILITY-ORPHAN-REGISTRY-FAILS", bool(traceability_errors(orphan, EXECUTED_TEST_IDS)))
    omitted_requirement = deepcopy(trace); omitted_requirement["registries"]["requirements"].pop()
    assertion("T-Q81-CATALOG-OMISSION-FAILS", "registry:requirements:catalog-equality" in traceability_errors(omitted_requirement, EXECUTED_TEST_IDS | q81_anchor_ids))
    dangling_requirement = deepcopy(trace); dangling_requirement["registries"]["requirements"].append("L0-REQ-999")
    assertion("T-Q81-CATALOG-DANGLING-FAILS", "registry:requirements:catalog-equality" in traceability_errors(dangling_requirement, EXECUTED_TEST_IDS | q81_anchor_ids))
    missing_requirement_reverse = deepcopy(trace); missing_requirement_reverse["reverse_edges"]["requirements"].pop("L5-REQ-001")
    assertion("T-Q81-CATALOG-REVERSE-EDGE-FAILS", "reverse_edges:requirements:coverage" in traceability_errors(missing_requirement_reverse, EXECUTED_TEST_IDS | q81_anchor_ids))
    changed_catalog_digest = deepcopy(trace); changed_catalog_digest["normative_requirement_catalog"]["digest"] = digest("f")
    assertion("T-Q81-CATALOG-DIGEST-FAILS", "catalog:metadata-or-digest" in traceability_errors(changed_catalog_digest, EXECUTED_TEST_IDS | q81_anchor_ids))
    changed_catalog_preimage = deepcopy(trace); changed_catalog_preimage["evidence_preimages"]["input"]["normative_requirement_catalog_digest"] = digest("e")
    assertion("T-Q81-CATALOG-EVIDENCE-PREIMAGE-FAILS", "catalog:evidence-preimage-binding" in traceability_errors(changed_catalog_preimage, EXECUTED_TEST_IDS | q81_anchor_ids))
    source_texts = {"15_LEVEL5_HUMAN_CONTROL.md": (ROOT / "15_LEVEL5_HUMAN_CONTROL.md").read_text(encoding="utf-8").replace("| `L5-REQ-001`", "| `L5-REQ-001`", 1).replace(" | Flow PEP + capability issuer + approval service |", " |", 1)}
    _, malformed_errors = normative_requirement_catalog(source_texts)
    assertion("T-Q81-CATALOG-MALFORMED-ROW-FAILS", bool(malformed_errors))
    l5_removed = {"15_LEVEL5_HUMAN_CONTROL.md": "\n".join(line for line in (ROOT / "15_LEVEL5_HUMAN_CONTROL.md").read_text(encoding="utf-8").splitlines() if "`L5-REQ-001`" not in line)}
    _, l5_removed_errors = normative_requirement_catalog(l5_removed)
    assertion("T-Q81-L5-REQ-001-MUTATION-FAILS", "catalog:L5-REQ-001:definition" in l5_removed_errors)
    catalog_resolves_errors = traceability_errors(trace, EXECUTED_TEST_IDS | {"T-Q81-CATALOG-RESOLVES"})
    assertion("T-Q81-CATALOG-RESOLVES", not catalog_resolves_errors, str(catalog_resolves_errors))
    assertion("T-TRACEABILITY-RESOLVES", not traceability_errors(trace, EXECUTED_TEST_IDS), str(traceability_errors(trace, EXECUTED_TEST_IDS)))
    if isinstance(trace.get("reverse_edges"), dict):
        missing_reverse = deepcopy(trace); missing_reverse["reverse_edges"]["tests"].pop(trace["invariants"][0]["tests"][0], None)
        assertion("T-TRACEABILITY-MISSING-REVERSE-EDGE-FAILS", bool(traceability_errors(missing_reverse, EXECUTED_TEST_IDS)))
    if isinstance(trace.get("attack_map"), dict):
        attack_collision = deepcopy(trace); attack_keys = list(attack_collision["attack_map"]); attack_collision["attack_map"][attack_keys[1]] = deepcopy(attack_collision["attack_map"][attack_keys[0]])
        assertion("T-TRACEABILITY-ATTACK-MAP-COLLISION-FAILS", bool(traceability_errors(attack_collision, EXECUTED_TEST_IDS)))
        attack_missing = deepcopy(trace); removed_attack = attack_missing["attack_registry"]["entries"].pop(); attack_missing["attack_map"].pop(removed_attack["catalog_id"])
        assertion("T-TRACEABILITY-ATTACK-MAP-MISSING-FAILS", bool(traceability_errors(attack_missing, EXECUTED_TEST_IDS)))
    if isinstance(trace.get("evidence_records"), dict):
        changed_evidence = deepcopy(trace); changed_evidence["evidence_records"][next(iter(changed_evidence["evidence_records"]))]["command"] = "python3 -c forged"
        assertion("T-TRACEABILITY-EVIDENCE-PREIMAGE-FAILS", bool(traceability_errors(changed_evidence, EXECUTED_TEST_IDS)))
        changed_environment = deepcopy(trace); changed_environment["evidence_preimages"]["environment"]["runtime"] = "IMPLEMENTED"
        assertion("T-TRACEABILITY-EVIDENCE-ENVIRONMENT-FAILS", bool(traceability_errors(changed_environment, EXECUTED_TEST_IDS)))
        changed_input = deepcopy(trace); changed_input["evidence_preimages"]["input"]["scope"] = "runtime"
        assertion("T-TRACEABILITY-EVIDENCE-INPUT-FAILS", bool(traceability_errors(changed_input, EXECUTED_TEST_IDS)))
        changed_status = deepcopy(trace); changed_status["evidence_records"][next(iter(changed_status["evidence_records"]))]["status"] = "RUNTIME_VERIFIED"
        assertion("T-TRACEABILITY-EVIDENCE-STATUS-FAILS", bool(traceability_errors(changed_status, EXECUTED_TEST_IDS)))
        missing_field = deepcopy(trace); missing_field["evidence_records"][next(iter(missing_field["evidence_records"]))].pop("result")
        assertion("T-TRACEABILITY-EVIDENCE-FIELD-FAILS", bool(traceability_errors(missing_field, EXECUTED_TEST_IDS)))
    marker_drift_sources = {filename: (ROOT / filename).read_text(encoding="utf-8") for filename in STATUS_ARTIFACTS}
    marker_drift_sources[STATUS_ARTIFACTS[0]] = marker_drift_sources[STATUS_ARTIFACTS[0]].replace(canonical_status_marker(), "Q94-STATUS-VECTOR: drift", 1)
    assertion("T-Q94-STATUS-MARKER-DRIFT-FAILS", f"status:marker-drift:{STATUS_ARTIFACTS[0]}" in traceability_errors(trace, EXECUTED_TEST_IDS, marker_drift_sources))
    projection_file = STATUS_PROJECTION_ARTIFACTS[0]
    duplicate_projection = load(ROOT / projection_file)
    duplicate_projection["status"] = {"runtime": "IMPLEMENTED"}
    assertion("T-Q94-DUPLICATE-STATUS-PROJECTION-FAILS", f"status:projection-drift:{projection_file}" in status_coherence_errors(trace, projection_objects={projection_file: duplicate_projection}))
    assertion("T-TRACEABILITY-ASSERTION-INSTANCES-UNIQUE", len(EXECUTED_ASSERTION_INSTANCES) == len(set(EXECUTED_ASSERTION_INSTANCES)))
    return len(trace["invariants"])


def check_round4_closure(reference, candidate, manifest, policy, isolation, facts, decision, capability) -> int:
    """Executable counterexamples for accepted Round-4 trust-boundary issues."""
    count = 0
    forged = deepcopy(candidate)
    forged_isolation, forged_manifest, forged_policy, forged_facts = deepcopy(isolation), deepcopy(manifest), deepcopy(policy), deepcopy(facts)
    forged["supply_chain"]["components"][0]["exact_bytes_digest"] = digest("f")
    forged_measurement = reference.canonical_digest(forged["supply_chain"]["components"])
    forged["supply_chain"]["composite_measurement_digest"] = forged_measurement
    forged["bindings"]["supply_chain_measurement_digest"] = forged_measurement
    forged["placement_attestation"]["measurement_digest"] = forged_measurement
    forged["session_attestation"]["measurement_digest"] = forged_measurement
    forged_isolation["supply_chain"]["composite_measurement_digest"] = forged_measurement
    for attestation in forged_facts["verified_attestations"].values():
        attestation["measurement_digest"] = forged_measurement
    forged, forged_facts = _signed_attestation_fixture(forged, forged_facts)
    refresh_profile_activation(reference, forged_isolation, forged_facts, forged)
    refresh_profile_consumers(reference, forged_manifest, forged_policy, forged_isolation, forged_facts, forged)
    assertion("T-Q39-SUPPLY-EXTERNAL-BUNDLE-SUBSTITUTION", reference.decide(forged, forged_manifest, forged_policy, forged_isolation, forged_facts)["reason_codes"] == ["SUPPLY_CHAIN_MEASUREMENT_INVALID"]); count += 1

    empty_facts = deepcopy(facts)
    empty_facts["authoritative_d2_frontier"]["inventory"] = []
    empty_facts["authoritative_d2_frontier"]["durable_state_digest"] = reference.canonical_digest([])
    assertion("T-Q40-D2-EMPTY", reference.decide(candidate, manifest, policy, isolation, empty_facts)["reason_codes"] == ["D2_TYPED_FRONTIER_VIOLATION"]); count += 1
    stale_facts = deepcopy(facts)
    stale_facts["authoritative_d2_frontier"]["durable_state_digest"] = digest("0")
    assertion("T-Q40-D2-STALE", reference.decide(candidate, manifest, policy, isolation, stale_facts)["reason_codes"] == ["D2_TYPED_FRONTIER_VIOLATION"]); count += 1
    hidden = deepcopy(candidate)
    hidden["d2_frontier"]["inventory"].append({**hidden["d2_frontier"]["inventory"][0], "artifact_id": "artifact:hidden", "iteration": 2})
    hidden["d2_frontier"]["durable_state_digest"] = reference.canonical_digest(hidden["d2_frontier"]["inventory"])
    hidden_facts = deepcopy(facts)
    hidden_facts["d2_frontier_digest"] = hidden["d2_frontier"]["durable_state_digest"]
    hidden_facts["authoritative_d2_frontier"] = deepcopy(hidden["d2_frontier"])
    assertion("T-Q40-D2-HIDDEN_N_PLUS_2", reference.decide(hidden, manifest, policy, isolation, hidden_facts)["reason_codes"] == ["D2_TYPED_FRONTIER_VIOLATION"]); count += 1
    missing_required = deepcopy(facts)
    missing_required["required_d2_artifacts"].append({"artifact_id": "artifact:required", "class": "PLAN"})
    assertion("T-Q40-D2-REQUIRED-ARTIFACT-MISSING", reference.decide(candidate, manifest, policy, isolation, missing_required)["reason_codes"] == ["D2_TYPED_FRONTIER_VIOLATION"]); count += 1

    event = make_effect_evidence(decision, capability)[2]
    emitter_facts = event_trust_facts(event)
    bad_event = deepcopy(event)
    bad_event["emitter"]["principal"] = "agent:worker"
    event_preimage = deepcopy(bad_event); event_preimage["chain"].pop("event_digest")
    bad_event["chain"]["event_digest"] = reference.canonical_digest(event_preimage)
    bad_emitter_facts = deepcopy(emitter_facts)
    bad_emitter_facts["verified_event_emitters"][bad_event["emitter"]["authority_attestation_digest"]]["event_digest"] = bad_event["chain"]["event_digest"]
    assertion("T-Q41-EVENT-EMITTER-ROLE-FORGE", not reference.validate_safety_event(bad_event, bad_emitter_facts)); count += 1
    bad_event = deepcopy(event); bad_event["chain"]["event_digest"] = digest("0")
    assertion("T-Q42-EVENT-DIGEST-SUBSTITUTION", not reference.validate_safety_event(bad_event, emitter_facts)); count += 1

    bad = deepcopy(candidate); bad["authority_alternatives"][0]["entries"][0]["selector"]["descriptor_id"] = "fd:host-root"
    assertion("T-Q43-DESCRIPTOR-ROOT-SUBSTITUTION", reference.decide(bad, manifest, policy, isolation, facts)["reason_codes"] == ["DESCRIPTOR_IDENTITY_INVALID"]); count += 1
    bad = deepcopy(candidate)
    bad["bindings"].update(contract_id="contract:forged", contract_digest=digest("0"))
    bad["session_attestation"]["contract_digest"] = digest("0")
    bad["d2_frontier"].update(contract_digest=digest("0"), root_contract_digest=digest("0"))
    bad["d2_frontier"]["frontier_record_digest"] = reference.canonical_digest({key: value for key, value in bad["d2_frontier"].items() if key != "frontier_record_digest"})
    bad, bad_facts = _signed_attestation_fixture(bad, facts)
    bad_facts["d2_frontier_digest"] = bad["d2_frontier"]["frontier_record_digest"]
    bad_facts["authoritative_d2_frontier"] = {**deepcopy(bad["d2_frontier"]), "signature_verified": True, "not_revoked": True, "freshness_verified": True, "verified_by": "verifier:d2-frontier"}
    assertion("T-Q44-CONTRACT-SUBSTITUTION", reference.decide(bad, manifest, policy, isolation, bad_facts)["reason_codes"] == ["LOOP_CONTRACT_TRUST_INVALID"]); count += 1

    state, _ = advance(reference, "STAGEABLE", decision, capability, ["PROPOSE", "NORMALIZE", "CLASSIFY", "ADMIT", "CALCULATE_RESERVATION", "ISSUE_CAPABILITY", "DURABLE_DISPATCH"])
    crashed_state = reference.reduce_transition(state, {"type": "CRASH"})["state"]
    crashed = reference.reduce_transition(crashed_state, {"type": "RECOVER_ORPHAN", "observed_fencing_epoch": crashed_state["fencing_epoch"]})
    assertion("T-Q45-STAGEABLE-CRASH-QUARANTINES", crashed["accepted"] and crashed["state"]["phase"] == "QUARANTINED" and crashed["state"]["unknown_escrow"] > 0); count += 1

    worker = deepcopy(candidate); worker["principal"] = "agent:worker"
    worker_iso = deepcopy(isolation); worker_iso["compiled_envelopes"][0]["principal"] = "agent:worker"; worker_iso["compiled_envelopes"][0]["allowed_effects"] = ["MUTATE"]
    worker_manifest, worker_policy, worker_facts = deepcopy(manifest), deepcopy(policy), deepcopy(facts); refresh_profile_activation(reference, worker_iso, worker_facts, worker); refresh_profile_consumers(reference, worker_manifest, worker_policy, worker_iso, worker_facts, worker)
    assertion("T-Q46-DIRECT-WORKER-MUTATE-DENY", reference.decide(worker, worker_manifest, worker_policy, worker_iso, worker_facts)["reason_codes"] == ["COMPILED_EFFECT_EXCEEDS_PRINCIPAL_CEILING"]); count += 1
    worker_audience = deepcopy(candidate); worker_audience["audience"] = "agent:worker"
    worker_audience_iso = deepcopy(isolation); worker_audience_iso["compiled_envelopes"][1]["audience"] = "agent:worker"
    audience_manifest, audience_policy, audience_facts = deepcopy(manifest), deepcopy(policy), deepcopy(facts); refresh_profile_activation(reference, worker_audience_iso, audience_facts, worker_audience); refresh_profile_consumers(reference, audience_manifest, audience_policy, worker_audience_iso, audience_facts, worker_audience)
    assertion("T-Q47-MUTATION-SELF-AUDIENCE-DENY", reference.decide(worker_audience, audience_manifest, audience_policy, worker_audience_iso, audience_facts)["reason_codes"] == ["MUTATION_AUDIENCE_INVALID"]); count += 1
    bad_policy, policy_facts, policy_candidate = deepcopy(policy), deepcopy(facts), deepcopy(candidate); bad_policy["authority_map"][0]["scope"]["kind"] = "ENDPOINT"
    refresh_policy_activation(reference, bad_policy, policy_facts, policy_candidate)
    assertion("T-Q48-POLICY-SCOPE-KIND-CROSS-MATRIX", reference.decide(policy_candidate, manifest, bad_policy, isolation, policy_facts)["reason_codes"] == ["SCOPE_EXCEEDS_CORRELATED_POLICY"]); count += 1

    postchecked, _ = advance(reference, "STAGEABLE", decision, capability, ["PROPOSE", "NORMALIZE", "CLASSIFY", "ADMIT", "CALCULATE_RESERVATION", "ISSUE_CAPABILITY", "DURABLE_DISPATCH", "QUIESCE", "SEAL", "POSTCHECK_PASS"])
    commit = event_for("COMMIT", decision, capability); commit["commit_evidence_ref"] = "commit:forged"; commit["commit_evidence"] = deepcopy(postchecked["trusted_store"]["commit"]["commit:one"])
    assertion("T-Q49-COMMIT-TYPED-EVIDENCE-FORGE", not reference.reduce_transition(postchecked, commit)["accepted"]); count += 1
    committed = reference.reduce_transition(postchecked, event_for("COMMIT", decision, capability))["state"]
    join = event_for("JOIN", decision, capability); join["join_evidence_ref"] = "join:forged"
    assertion("T-Q49-JOIN-TYPED-EVIDENCE-FORGE", not reference.reduce_transition(committed, join)["accepted"]); count += 1

    budget = deepcopy(candidate); budget["budget_demands"][0]["scope_digest"] = digest("a")
    assertion("T-Q50-BUDGET-SCOPE-IDENTITY-SUBSTITUTION", reference.decide(budget, manifest, policy, isolation, facts)["decision"] != "ALLOW"); count += 1
    budget = deepcopy(candidate); budget["budget_demands"][0]["lineage_root"] = "lineage:forged"
    assertion("T-Q50-BUDGET-LINEAGE-IDENTITY-SUBSTITUTION", reference.decide(budget, manifest, policy, isolation, facts)["decision"] != "ALLOW"); count += 1
    composite_demands = [
        {"name": "CALLS", "unit": "CALLS", "amount": 1, "scope_digest": digest("1"), "lineage_root": "lineage:one"},
        {"name": "CALLS", "unit": "CALLS", "amount": 1, "scope_digest": digest("2"), "lineage_root": "lineage:one"},
        {"name": "CALLS", "unit": "CALLS", "amount": 1, "scope_digest": digest("1"), "lineage_root": "lineage:two"},
    ]
    composite_bounds = [{**item, "limit": item["amount"]} for item in composite_demands]
    reservations = reference.budget_reservations(composite_demands, (composite_bounds, "limit"))
    assertion("T-Q50-BUDGET-FOUR-PART-KEY-PRESERVED", reservations is not None and len(reservations) == 3); count += 1

    issue_state, _ = advance(reference, "STAGEABLE", decision, capability, ["PROPOSE", "NORMALIZE", "CLASSIFY", "ADMIT", "CALCULATE_RESERVATION"])
    issue = event_for("ISSUE_CAPABILITY", decision, capability)
    issue["capability"]["principal"] = "agent:forged"
    issue["capability"]["issuer_verification"]["signed_claims_digest"] = reference.canonical_digest(reference._capability_signed_claims(issue["capability"]))
    issue["capability"].pop("capability_digest")
    issue["capability"]["capability_digest"] = reference.canonical_digest(issue["capability"])
    assertion("T-Q51-ISSUE-EXTERNAL-FULL-RECORD", not reference.reduce_transition(issue_state, issue)["accepted"]); count += 1
    issued, _ = advance(reference, "STAGEABLE", decision, capability, ["PROPOSE", "NORMALIZE", "CLASSIFY", "ADMIT", "CALCULATE_RESERVATION", "ISSUE_CAPABILITY"])
    forged_dispatch_state = deepcopy(issued)
    forged_dispatch_state["trusted_store"]["dispatch"][capability["capability_digest"]]["principal"] = "agent:forged"
    assertion("T-Q51-DISPATCH-EXTERNAL-FULL-RECORD", not reference.reduce_transition(forged_dispatch_state, event_for("DURABLE_DISPATCH", decision, capability))["accepted"]); count += 1
    return count


def _rebind_manifest(reference, candidate, manifest, facts):
    """Rebind the candidate and external manifest record after a test mutation."""
    manifest_digest = reference.canonical_digest(manifest)
    candidate["bindings"]["manifest_digest"] = manifest_digest
    trusted = deepcopy(facts["verified_manifests"].pop(next(iter(facts["verified_manifests"]))))
    trusted.update(manifest_digest=manifest_digest, signed_payload_digest=manifest_digest)
    facts["verified_manifests"] = {manifest_digest: trusted}
    rebind_loop_contract(reference, candidate, facts)


def rebind_loop_contract(reference, candidate, facts):
    """Fixture-only issuance of a new full contract after an explicit control rebind."""
    old = facts.get("trusted_loop_contracts", {}).get(candidate["bindings"]["contract_digest"])
    if not isinstance(old, dict):
        return
    contract = deepcopy(old)
    contract["artifact_bindings"].update({key: candidate["bindings"][key] for key in ("policy_digest", "registry_digest", "isolation_profile_digest")})
    for operation in contract["allowed_operations"]:
        if operation["operation_id"] == candidate["operation_id"]:
            operation["manifest_digest"] = candidate["bindings"]["manifest_digest"]
    contract["contract_digest"] = reference.canonical_digest({key: value for key, value in contract.items() if key != "contract_digest"})
    candidate["bindings"].update(contract_id=contract["contract_id"], contract_digest=contract["contract_digest"])
    candidate["session_attestation"]["contract_digest"] = contract["contract_digest"]
    candidate["d2_frontier"].update(contract_digest=contract["contract_digest"], root_contract_digest=contract["contract_digest"])
    candidate["d2_frontier"]["frontier_record_digest"] = canonical_digest_for_test({key: value for key, value in candidate["d2_frontier"].items() if key != "frontier_record_digest"})
    slot = candidate["iteration_slot"]; slot["root_contract_digest"] = contract["contract_digest"]
    slot["slot_key_digest"] = canonical_digest_for_test({key: slot[key] for key in ("authority_domain_id", "root_contract_digest", "journal_lineage_id", "iteration")})
    slot["slot_record_digest"] = canonical_digest_for_test({key: value for key, value in slot.items() if key != "slot_record_digest"})
    facts["d2_frontier_digest"] = candidate["d2_frontier"]["frontier_record_digest"]
    facts["authoritative_d2_frontier"] = {**deepcopy(candidate["d2_frontier"]), "signature_verified": True, "not_revoked": True, "freshness_verified": True, "verified_by": "verifier:d2-frontier"}
    facts["trusted_loop_contracts"] = {contract["contract_digest"]: deepcopy(contract)}
    facts["verified_loop_contracts"] = {contract["contract_digest"]: {"contract": deepcopy(contract), "signature_verified": True, "not_revoked": True, "freshness_verified": True, "current_key": True, "current_revocation_epoch": facts["current_revocation_epoch"]}}
    facts["active_iteration_slots"] = {slot["slot_key_digest"]: {"slot": deepcopy(slot), "signature_verified": True, "not_revoked": True, "freshness_verified": True, "current_fence": True, "fencing_epoch": facts["current_fencing_epoch"], "owner_request_digest": candidate["request_digest"]}}
    session = candidate["session_attestation"]
    unsigned = {key: deepcopy(value) for key, value in session.items() if key != "signature"}
    session["signature"]["payload_digest"] = canonical_digest_for_test(unsigned)
    facts["verified_attestations"][session["attestation_digest"]].update(contract_digest=session["contract_digest"], payload_digest=session["signature"]["payload_digest"], signed_payload_digest=session["signature"]["payload_digest"], signed_fields=unsigned)


def _signed_attestation_fixture(candidate, facts):
    candidate, facts = deepcopy(candidate), deepcopy(facts)
    for name in ("placement_attestation", "session_attestation"):
        item = candidate[name]
        unsigned = {key: deepcopy(value) for key, value in item.items() if key != "signature"}
        item["signature"]["payload_digest"] = canonical_digest_for_test(unsigned)
        record = facts["verified_attestations"][item["attestation_digest"]]
        record.update({
            "attestation_digest": item["attestation_digest"],
            "subject_instance_id": item["subject_instance_id"],
            "host_id": item.get("host_id"), "nonce": item["nonce"], "epoch": item["epoch"],
            "issued_at": item["issued_at"], "expires_at": item["expires_at"],
            "isolation_profile_digest": item.get("isolation_profile_digest"),
            "measurement_digest": item["measurement_digest"],
            "session_id": item.get("session_id"),
            "placement_attestation_digest": item.get("placement_attestation_digest"),
            "contract_digest": item.get("contract_digest"),
            "verified_by": item["signature"]["verified_by"],
            "algorithm": item["signature"]["algorithm"],
            "signed_payload_digest": item["signature"]["payload_digest"],
            "signed_fields": unsigned,
        })
        record["key_id"] = item["signature"]["key_id"]
        record["payload_digest"] = item["signature"]["payload_digest"]
    return candidate, facts


def check_round5_attestation(reference, candidate, manifest, policy, isolation, facts, decision, capability) -> int:
    """Q-53: every signed placement/session field remains externally bound."""
    signed_candidate, signed_facts = _signed_attestation_fixture(candidate, facts)
    signed_decision = reference.decide(signed_candidate, manifest, policy, isolation, signed_facts)
    signed_capability = reference.mint_capability(signed_decision, signed_candidate)
    assertion("T-ATTESTATION-SIGNED-FIELDS-POSITIVE", signed_decision["decision"] == "ALLOW" and signed_capability is not None)
    count = 1
    mutations = (
        ("EXPIRY", lambda item: item.update(expires_at="2026-08-24T00:20:00Z")),
        ("HOST", lambda item: item.update(host_id="host:forged")),
        ("NONCE", lambda item: item.update(nonce="forged_attestation_nonce_123456")),
        ("SIGNER", lambda item: item["signature"].update(verified_by="verifier:forged")),
        ("ISSUED", lambda item: item.update(issued_at="2026-08-24T00:00:01Z")),
        ("EPOCH", lambda item: item.update(epoch=4)),
        ("PROFILE", lambda item: item.update(isolation_profile_digest=digest("0"))),
    )
    for name, mutate in mutations:
        bad = deepcopy(signed_candidate); bad_facts = deepcopy(signed_facts)
        mutate(bad["placement_attestation"])
        if name in {"EXPIRY", "ISSUED", "EPOCH", "SIGNER"}:
            mutate(bad["session_attestation"])
        result = reference.decide(bad, manifest, policy, isolation, bad_facts)
        bad_capability = reference.mint_capability(result, bad)
        assertion("T-ATTESTATION-SIGNED-FIELD-MUTATION-" + name, result["decision"] != "ALLOW" and bad_capability is None)
        count += 1
        if signed_capability is not None:
            assertion("T-ATTESTATION-DISPATCH-GATE-" + name, not reference.validate_capability(signed_capability, signed_decision, bad, bad_facts))
            count += 1
    return count


def check_round5_manifest_and_descriptor(reference, candidate, manifest, policy, isolation, facts) -> int:
    """Q-54/Q-55: typed manifest scope and exact descriptor identity matrix."""
    count = 0
    relation = {
        "FILE": {"PATH_EXACT", "PATH_PREFIX"}, "DIRECTORY": {"PATH_EXACT", "PATH_PREFIX"},
        "PROCESS": set(), "ENDPOINT": set(),
        "PRINCIPAL": set(), "MEMORY": set(),
        "PROMPT": set(), "POLICY": set(),
        "REGISTRY": set(), "SECRET": set(),
        "COMPUTE_RESOURCE": set(),
    }
    selector_kinds = sorted({kind for kinds in relation.values() for kind in kinds} | {"PRINCIPAL_EXACT"})
    for resource_kind in sorted(relation):
        for selector_kind in selector_kinds:
            bad_manifest = deepcopy(manifest); resource = bad_manifest["effect_bounds"][0]["resources"][0]
            resource["resource_kind"], resource["selector"]["kind"] = resource_kind, selector_kind
            selector_value = {
                "PATH_EXACT": "/workspace/output/report.txt", "PATH_PREFIX": "/workspace/output",
                "ENDPOINT_EXACT": "https://example.test/api", "PROCESS_EXECUTABLE": "/usr/bin/tool",
            }.get(selector_kind, "principal:bounded-child")
            resource["selector"]["value"] = selector_value
            expected = selector_kind in relation[resource_kind]
            assertion("T-Q48-MANIFEST-SCOPE-KIND-CROSS-MATRIX-" + resource_kind + "-" + selector_kind, schema_valid("effect-manifest.schema.json", bad_manifest) == expected)
            count += 1

    incompatible = deepcopy(manifest)
    incompatible["effect_bounds"][0]["resources"][0]["selector"].update(kind="PRINCIPAL_EXACT", value="/workspace/output/report.txt")
    bad_candidate, bad_facts = deepcopy(candidate), deepcopy(facts)
    _rebind_manifest(reference, bad_candidate, incompatible, bad_facts)
    result = reference.decide(bad_candidate, incompatible, policy, isolation, bad_facts)
    assertion("T-Q48-MANIFEST-FILE-PRINCIPAL-EXACT-DENY", result["decision"] != "ALLOW" and result["reason_codes"] == ["MANIFEST_DERIVED_CLOSURE_INVALID"])
    count += 1
    positive = reference.decide(candidate, manifest, policy, isolation, facts)
    assertion("T-Q48-MANIFEST-FILE-PATH-PREFIX-POSITIVE", positive["decision"] == "ALLOW")
    count += 1
    exact_manifest = deepcopy(manifest)
    exact_manifest["effect_bounds"][0]["resources"][0]["selector"].update(kind="PATH_EXACT", value="/workspace/output/report.txt")
    exact_candidate, exact_facts = deepcopy(candidate), deepcopy(facts)
    _rebind_manifest(reference, exact_candidate, exact_manifest, exact_facts)
    exact_result = reference.decide(exact_candidate, exact_manifest, policy, isolation, exact_facts)
    assertion("T-Q48-MANIFEST-FILE-PATH-EXACT-POSITIVE", exact_result["decision"] == "ALLOW")
    count += 1

    descriptor_digest = exact_candidate["authority_alternatives"][0]["entries"][0]["selector"]["descriptor_binding_digest"]
    for name, descriptor in (
        ("DIGEST", digest("0")),
        ("ROOT", reference.canonical_digest({"descriptor_id": "fd:output", "root_identity": "root:forged", "mount_identity": "mount:workspace", "epoch": 3})),
        ("MOUNT", reference.canonical_digest({"descriptor_id": "fd:output", "root_identity": "root:output", "mount_identity": "mount:forged", "epoch": 3})),
        ("EPOCH", reference.canonical_digest({"descriptor_id": "fd:output", "root_identity": "root:output", "mount_identity": "mount:workspace", "epoch": 4})),
    ):
        bad_manifest = deepcopy(exact_manifest)
        bad_manifest["effect_bounds"][0]["resources"][0]["selector"]["descriptor_binding_digest"] = descriptor
        bad_candidate, bad_facts = deepcopy(exact_candidate), deepcopy(exact_facts)
        _rebind_manifest(reference, bad_candidate, bad_manifest, bad_facts)
        result = reference.decide(bad_candidate, bad_manifest, policy, isolation, bad_facts)
        assertion("T-Q43-PATH-EXACT-DESCRIPTOR-" + name + "-DENY", result["reason_codes"] == ["MANIFEST_DERIVED_CLOSURE_INVALID"])
        count += 1
    assertion("T-Q43-PATH-EXACT-DESCRIPTOR-POSITIVE", descriptor_digest == exact_manifest["effect_bounds"][0]["resources"][0]["selector"]["descriptor_binding_digest"] and exact_result["decision"] == "ALLOW")
    return count + 1


def check_round5_isolation_and_supply(reference, candidate, manifest, policy, isolation, facts) -> int:
    """Q-56/Q-57: closed resource metering and trusted-root identity."""
    count = 0
    expected = {"CPU_TIME": ("MILLISECONDS", "CGROUP_V2"), "CPU_RATE": ("MILLICORES", "CGROUP_V2"), "WALL_TIME": ("MILLISECONDS", "SUPERVISOR"), "MEMORY": ("MIB", "CGROUP_V2"), "SWAP": ("MIB", "CGROUP_V2"), "PIDS": ("COUNT", "CGROUP_V2"), "BLOCK_IO_READ": ("IOPS", "DEVICE_SCHEDULER"), "BLOCK_IO_WRITE": ("IOPS", "DEVICE_SCHEDULER"), "FILES": ("COUNT", "FILESYSTEM_QUOTA"), "INODES": ("COUNT", "FILESYSTEM_QUOTA"), "OPEN_FDS": ("COUNT", "RLIMIT"), "OUTPUT_BYTES": ("BYTES", "FILESYSTEM_QUOTA"), "GPU_TIME": ("MILLISECONDS", "DEVICE_SCHEDULER"), "GPU_MEMORY": ("MIB", "DEVICE_SCHEDULER")}
    assertion("T-Q56-ISOLATION-RESOURCE-POSITIVE-CONTROLS", reference.validate_isolation_profile(isolation, facts) and all((row["unit"], row["enforcement"]) == expected[row["resource"]] for row in isolation["resources"]))
    count += 1
    units = ("MILLISECONDS", "MILLICORES", "MIB", "COUNT", "BYTES", "IOPS")
    enforcers = ("CGROUP_V2", "SUPERVISOR", "FILESYSTEM_QUOTA", "RLIMIT", "DEVICE_SCHEDULER")
    for resource_name in sorted(expected):
        for unit in units:
            for enforcer in enforcers:
                profile = deepcopy(isolation)
                target = next(row for row in profile["resources"] if row["resource"] == resource_name)
                target.update(unit=unit, enforcement=enforcer)
                compatible = (unit, enforcer) == expected[resource_name]
                schema_ok = schema_valid("isolation-profile.schema.json", profile)
                semantic_ok = reference.validate_isolation_profile(profile, facts)
                decision_ok = reference.decide(candidate, manifest, policy, profile, facts)["decision"] == "ALLOW"
                assertion("T-ISOLATION-RESOURCE-CROSS-MATRIX-" + resource_name + "-" + unit + "-" + enforcer, schema_ok == compatible and semantic_ok == compatible and decision_ok == compatible)
                count += 1
    assertion("T-ISOLATION-RESOURCE-CROSS-MATRIX-CPU-MIB-CGROUP_V2", not reference.validate_isolation_profile({**deepcopy(isolation), "resources": [{**row, "unit": "MIB"} if row["resource"] == "CPU_TIME" else row for row in isolation["resources"]]}, facts))
    assertion("T-ISOLATION-RESOURCE-CROSS-MATRIX-CPU-MILLISECONDS-SUPERVISOR", not reference.validate_isolation_profile({**deepcopy(isolation), "resources": [{**row, "enforcement": "SUPERVISOR"} if row["resource"] == "CPU_TIME" else row for row in isolation["resources"]]}, facts))
    root = isolation["supply_chain"]["trusted_roots_digest"]
    good_facts = deepcopy(facts); good_facts["trusted_roots_digest"] = root
    assertion("T-Q57-SUPPLY-TRUSTED-ROOT-POSITIVE", reference.validate_supply_chain(candidate, isolation, good_facts) and reference.decide(candidate, manifest, policy, isolation, good_facts)["decision"] == "ALLOW")
    count += 1
    bad_candidate = deepcopy(candidate); bad_candidate["supply_chain"]["trusted_roots_digest"] = digest("0")
    result = reference.decide(bad_candidate, manifest, policy, isolation, good_facts)
    assertion("T-SUPPLY-TRUSTED-ROOT-MISMATCH", not reference.validate_supply_chain(bad_candidate, isolation, good_facts) and result["reason_codes"] == ["SUPPLY_CHAIN_MEASUREMENT_INVALID"] and reference.mint_capability(result, bad_candidate) is None)
    count += 1
    bad_facts = deepcopy(good_facts); bad_facts["trusted_roots_digest"] = digest("0")
    result = reference.decide(candidate, manifest, policy, isolation, bad_facts)
    assertion("T-SUPPLY-TRUSTED-ROOT-EXTERNAL-MISMATCH", not reference.validate_supply_chain(candidate, isolation, bad_facts) and result["reason_codes"] == ["SUPPLY_CHAIN_MEASUREMENT_INVALID"])
    return count + 1


def check_round5_reservation_and_event(reference, candidate, manifest, policy, isolation, facts, decision, capability) -> int:
    """Q-58/Q-59: close reservations on malformed issuance and enforce event containment."""
    count = 0
    reserved, _ = advance(reference, "STAGEABLE", decision, capability, ["PROPOSE", "NORMALIZE", "CLASSIFY", "ADMIT", "CALCULATE_RESERVATION"])
    reserved_amount = reserved["budget_reserved"]
    malformed = event_for("ISSUE_CAPABILITY", decision, capability)
    malformed["capability"]["principal"] = "agent:forged"
    malformed["capability"]["issuer_verification"]["signed_claims_digest"] = reference.canonical_digest(reference._capability_signed_claims(malformed["capability"]))
    malformed["capability"].pop("capability_digest")
    malformed["capability"]["capability_digest"] = reference.canonical_digest(malformed["capability"])
    rejected = reference.reduce_transition(reserved, malformed)
    record = rejected.get("durable_record") or {}
    disposition = record.get("reservation_disposition")
    assertion("T-ISSUE_CAPABILITY-MALFORMED-ONE-DISPOSITION", not rejected["accepted"] and disposition in {"RELEASED", "QUARANTINED_ESCROW"} and record.get("reservation_release", record.get("reservation_escrow")) == reserved_amount and (rejected["state"]["budget_reserved"] == 0 or rejected["state"]["unknown_escrow"] == reserved_amount))
    count += 1
    duplicate = reference.reduce_transition(rejected["state"], malformed)
    assertion("T-ISSUE_CAPABILITY-NO-DUPLICATE-DISPOSITION", not duplicate["accepted"] and duplicate.get("durable_record") is None)
    count += 1
    fresh = reference.reduce_transition(rejected["state"], event_for("PROPOSE", decision, capability, transaction_id="tx:fresh"))
    assertion("T-ISSUE_CAPABILITY-FRESH-BOUNDED-PROPOSAL", fresh["accepted"] and fresh["state"]["budget_reserved"] == 0 and fresh["state"]["budget_remaining"] + fresh["state"]["budget_reserved"] + fresh["state"]["budget_spent"] == fresh["state"]["budget_total"])
    count += 1
    for branch, events, test_id in (
        ("STAGEABLE", ["PROPOSE", "NORMALIZE", "CLASSIFY", "ADMIT", "CALCULATE_RESERVATION", "ISSUE_CAPABILITY"], "T-ISSUE_CAPABILITY-PREDISPATCH-ISSUED-QUARANTINE"),
        ("EXTERNAL", ["PROPOSE", "NORMALIZE", "CLASSIFY", "ADMIT", "CALCULATE_RESERVATION", "ISSUE_CAPABILITY", "PRECHECK_EXTERNAL"], "T-ISSUE_CAPABILITY-PREDISPATCH-PRECHECKED-QUARANTINE"),
    ):
        pending, _ = advance(reference, branch, decision, capability, events)
        invalid_dispatch = event_for("DURABLE_DISPATCH", decision, capability, capability_digest=digest("0"))
        disposed = reference.reduce_transition(pending, invalid_dispatch)
        disposed_record = disposed.get("durable_record") or {}
        assertion(test_id, not disposed["accepted"] and disposed["state"]["phase"] == "QUARANTINED" and disposed["state"]["unknown_escrow"] == pending["budget_reserved"] and disposed_record.get("reservation_disposition") == "QUARANTINED_ESCROW")
        count += 1

    effect, receipt, event = make_effect_evidence(decision, capability)
    emitter_facts = event_trust_facts(event)
    assertion("T-Q59-EVENT-AUTHORIZED-SUBSET-MANIFESTED-POSITIVE", reference.validate_safety_event(event, emitter_facts))
    count += 1
    excess = {**effect, "operations": ["DELETE"]}
    bad = deepcopy(event); bad["effect_stages"]["authorized"]["entries"] = [excess]; bad["effect_stages"]["committed"]["entries"] = [excess]
    preimage = deepcopy(bad); preimage["chain"].pop("event_digest"); bad["chain"]["event_digest"] = canonical_digest_for_test(preimage); bad_facts = event_trust_facts(bad)
    assertion("T-Q59-EVENT-AUTHORIZED-SUBSET-MANIFESTED-DENY", not reference.validate_safety_event(bad, bad_facts))
    count += 1
    attempted = deepcopy(event); attempted_row = {**event["effect_stages"]["attempted"]["entries"][0], "operations": ["DELETE"]}; attempted["effect_stages"]["attempted"]["entries"] = [event["effect_stages"]["attempted"]["entries"][0], attempted_row]; attempted["effect_stages"]["blocked"] = {"status": "KNOWN", "entries": [attempted_row]}
    preimage = deepcopy(attempted); preimage["chain"].pop("event_digest"); attempted["chain"]["event_digest"] = canonical_digest_for_test(preimage); attempted_facts = event_trust_facts(attempted)
    assertion("T-Q59-EVENT-ATTEMPTED-EXCESS-BLOCKED", reference.validate_safety_event(attempted, attempted_facts))
    count += 1
    unblocked = deepcopy(attempted); unblocked["effect_stages"]["blocked"] = {"status": "NOT_APPLICABLE", "entries": []}
    preimage = deepcopy(unblocked); preimage["chain"].pop("event_digest"); unblocked["chain"]["event_digest"] = canonical_digest_for_test(preimage); unblocked_facts = event_trust_facts(unblocked)
    assertion("T-Q59-EVENT-ATTEMPTED-EXCESS-REQUIRES-BLOCKED", not reference.validate_safety_event(unblocked, unblocked_facts))
    count += 1
    trusted_binding = deepcopy(event); trusted_binding["bindings"]["authorized_envelope_digest"] = digest("0")
    for stage in trusted_binding["effect_stages"].values():
        for row in stage.get("entries", []):
            row["envelope_digest"] = digest("0")
    preimage = deepcopy(trusted_binding); preimage["chain"].pop("event_digest"); trusted_binding["chain"]["event_digest"] = canonical_digest_for_test(preimage)
    trusted_binding_facts = event_trust_facts(event); original_record = next(iter(trusted_binding_facts["verified_event_bindings"].values())); original_record["event_digest"] = trusted_binding["chain"]["event_digest"]; trusted_binding_facts["verified_event_bindings"] = {trusted_binding["chain"]["event_digest"]: original_record}; trusted_binding_facts["verified_event_emitters"][event["emitter"]["authority_attestation_digest"]]["event_digest"] = trusted_binding["chain"]["event_digest"]
    assertion("T-Q59-EVENT-TRUSTED-BINDING-NEGATIVE", not reference.validate_safety_event(trusted_binding, trusted_binding_facts))
    return count + 1


def check_round7a_remediation(reference, candidate, manifest, policy, isolation, facts, decision, capability) -> None:
    """Focused Q-75–Q-78 counterexamples from the blind Round 7A arbitration."""
    child_decision, child, child_facts = make_delegated_child(reference, candidate, facts, decision, capability)
    assertion("T-Q91-DELEGATION-CLAUSE-EXACT-POSITIVE", schema_valid("capability.schema.json", child) and reference.validate_capability(child, child_decision, candidate, child_facts))
    def reseal_child_with_parent(parent_rows):
        broken, broken_facts = deepcopy(child), deepcopy(child_facts)
        clause = parent_rows[0]
        parent_digest = broken["delegation"]["parent_capability_digest"]
        broken_facts["parent_envelopes"][parent_digest] = parent_rows
        broken["delegation"].update(parent_envelope_digest=reference.canonical_digest(parent_rows), parent_effects_digest=reference.canonical_digest(parent_rows), parent_delegation_clause_digest=reference.canonical_digest(clause))
        broken_facts["delegation_edges"][broken["capability_id"]] = {key: broken["delegation"][key] for key in ("parent_capability_id", "parent_capability_digest", "parent_envelope_digest", "parent_delegation_clause_digest", "root_lineage_digest", "edge_nonce", "child_principal", "child_audience", "fencing_epoch")}
        refresh_capability(reference, broken, broken_facts)
        return broken, broken_facts
    for name, mutate in (
        ("TARGET", lambda row: row["selector"].update(reference="principal:retargeted", canonical_value="principal:retargeted")),
        ("OPERATION", lambda row: row.update(operation="SEND")),
        ("FACET", lambda row: row.update(facets=["AUTHORIZE_EFFECT"])),
        ("TIME", lambda row: row["constraints"]["temporal"].update(not_after="2026-08-24T00:00:05Z")),
        ("QUANTITY", lambda row: row["constraints"]["quantity"].update(limit=0)),
        ("CONCURRENCY", lambda row: row["constraints"].update(max_concurrency=0)),
    ):
        rows = deepcopy(child_facts["parent_envelopes"][child["delegation"]["parent_capability_digest"]]); mutate(rows[0])
        broken, broken_facts = reseal_child_with_parent(rows)
        assertion("T-Q91-DELEGATION-CLAUSE-" + name, not reference.validate_capability(broken, child_decision, candidate, broken_facts))
    for name, mutate in (("SCOPE", lambda row: row["selector"].update(canonical_path="/workspace/other.txt")), ("DEPTH", lambda delegation: delegation.update(depth=5)), ("FANOUT", lambda delegation: delegation.update(fanout=3))):
        broken, broken_facts = deepcopy(child), deepcopy(child_facts)
        if name == "SCOPE":
            rows = deepcopy(broken_facts["parent_envelopes"][broken["delegation"]["parent_capability_digest"]]); mutate(rows[1]); broken, broken_facts = reseal_child_with_parent(rows)
        else:
            mutate(broken["delegation"]); refresh_capability(reference, broken, broken_facts)
        assertion("T-Q91-DELEGATION-" + name, not reference.validate_capability(broken, child_decision, candidate, broken_facts))
    issued_child, _ = advance(reference, "STAGEABLE", child_decision, child, ["PROPOSE", "NORMALIZE", "CLASSIFY", "ADMIT", "CALCULATE_RESERVATION", "ISSUE_CAPABILITY"])
    assertion("T-Q75-DESCENDANT-ISSUE-TRUSTED-PROVENANCE", issued_child["phase"] == "CAPABILITY_ISSUED")
    pending_child, _ = advance(reference, "STAGEABLE", child_decision, child, ["PROPOSE", "NORMALIZE", "CLASSIFY", "ADMIT", "CALCULATE_RESERVATION"])
    pending_child["revoked_capability_digests"].append(child["delegation"]["parent_capability_digest"])
    assertion("T-Q75-DESCENDANT-ISSUE-DURABLE-PARENT-REVOCATION", not reference.reduce_transition(pending_child, event_for("ISSUE_CAPABILITY", child_decision, child))["accepted"])
    stale_parent_epoch, _ = advance(reference, "STAGEABLE", child_decision, child, ["PROPOSE", "NORMALIZE", "CLASSIFY", "ADMIT", "CALCULATE_RESERVATION"])
    parent_digest = child["delegation"]["parent_capability_digest"]
    stale_parent_epoch["trusted_store"]["current_parent_revocation_epochs"][parent_digest] += 1
    assertion("T-Q75-DESCENDANT-ISSUE-CURRENT-PARENT-REVOCATION-EPOCH", not reference.reduce_transition(stale_parent_epoch, event_for("ISSUE_CAPABILITY", child_decision, child))["accepted"])
    stale_parent = deepcopy(issued_child)
    stale_parent["trusted_store"]["delegations"][child["capability_digest"]]["parent_state"] = "REVOKED"
    assertion("T-Q75-DESCENDANT-DISPATCH-RECHECKS-PARENT", not reference.reduce_transition(stale_parent, event_for("DURABLE_DISPATCH", child_decision, child))["accepted"])
    revoked_parent = deepcopy(issued_child)
    revoked_parent["revoked_capability_digests"].append(child["delegation"]["parent_capability_digest"])
    assertion("T-Q75-DESCENDANT-DISPATCH-DURABLE-PARENT-REVOCATION", not reference.reduce_transition(revoked_parent, event_for("DURABLE_DISPATCH", child_decision, child))["accepted"])
    stale_parent_fence = deepcopy(issued_child)
    stale_parent_fence["trusted_store"]["current_parent_fencing_epochs"][parent_digest] += 1
    assertion("T-Q75-DESCENDANT-DISPATCH-CURRENT-PARENT-FENCE", not reference.reduce_transition(stale_parent_fence, event_for("DURABLE_DISPATCH", child_decision, child))["accepted"])
    forged_parent_signer = deepcopy(issued_child)
    parent_status = forged_parent_signer["trusted_store"]["parent_statuses"][parent_digest]
    parent_status["verified_by"] = "attacker:forged-parent-status"
    parent_status["status_digest"] = canonical_digest_for_test({key: value for key, value in parent_status.items() if key != "status_digest"})
    assertion("T-Q75-DESCENDANT-DISPATCH-PARENT-SIGNER", not reference.reduce_transition(forged_parent_signer, event_for("DURABLE_DISPATCH", child_decision, child))["accepted"])
    forged_clause = deepcopy(issued_child)
    forged_clause["trusted_store"]["delegations"][child["capability_digest"]]["parent_delegation_clause_digest"] = digest("0")
    assertion("T-Q91-DISPATCH-RECHECKS-CLAUSE-DIGEST", not reference.reduce_transition(forged_clause, event_for("DURABLE_DISPATCH", child_decision, child))["accepted"])

    pre_admit, _ = advance(reference, "STAGEABLE", decision, capability, ["PROPOSE", "NORMALIZE", "CLASSIFY"])
    stale_decision = deepcopy(decision); stale_frontier = stale_decision["evaluation"]["d2_frontier_record"]; stale_frontier["joined_iteration"] = 1; stale_frontier["frontier_record_digest"] = canonical_digest_for_test({key: value for key, value in stale_frontier.items() if key != "frontier_record_digest"}); stale_decision["evaluation"]["d2_frontier_digest"] = stale_frontier["frontier_record_digest"]; stale_decision["decision_digest"] = canonical_digest_for_test({key: value for key, value in stale_decision.items() if key != "decision_digest"})
    stale_event = event_for("ADMIT", decision, capability); stale_event["decision"] = stale_decision; stale_event["trusted_pep_verification"]["decision_digest"] = stale_decision["decision_digest"]; stale_event["trusted_pep_verification"]["receipt_digest"] = canonical_digest_for_test({key: value for key, value in stale_event["trusted_pep_verification"].items() if key != "receipt_digest"}); stale_state = deepcopy(pre_admit); stale_state["trusted_pep_receipts"] = {stale_event["trusted_pep_verification"]["receipt_digest"]: stale_event["trusted_pep_verification"]}
    assertion("T-Q92-ADMIT-STALE-JOINED-FRONTIER-REJECT", reference.reduce_transition(stale_state, stale_event)["reason_code"] == "ADMIT_D2_FRONTIER_REDUCER_STATE_MISMATCH")
    fence_decision = deepcopy(decision); fence_frontier = fence_decision["evaluation"]["d2_frontier_record"]; fence_frontier["fencing_epoch"] = 4; fence_frontier["frontier_record_digest"] = canonical_digest_for_test({key: value for key, value in fence_frontier.items() if key != "frontier_record_digest"}); fence_decision["evaluation"]["d2_frontier_digest"] = fence_frontier["frontier_record_digest"]; fence_decision["decision_digest"] = canonical_digest_for_test({key: value for key, value in fence_decision.items() if key != "decision_digest"})
    fence_event = event_for("ADMIT", decision, capability); fence_event["decision"] = fence_decision; fence_event["trusted_pep_verification"]["decision_digest"] = fence_decision["decision_digest"]; fence_event["trusted_pep_verification"]["receipt_digest"] = canonical_digest_for_test({key: value for key, value in fence_event["trusted_pep_verification"].items() if key != "receipt_digest"}); fence_state = deepcopy(pre_admit); fence_state["trusted_pep_receipts"] = {fence_event["trusted_pep_verification"]["receipt_digest"]: fence_event["trusted_pep_verification"]}
    assertion("T-Q92-ADMIT-EMBEDDED-FENCE-REJECT", reference.reduce_transition(fence_state, fence_event)["reason_code"] == "ADMIT_D2_FRONTIER_REDUCER_STATE_MISMATCH")

    for name, mutate in (
        ("AUTHORITY-DOMAIN", lambda f: f["authoritative_d2_frontier"].update(authority_domain_id="authority-domain:other")),
        ("JOURNAL-LINEAGE", lambda f: f["authoritative_d2_frontier"].update(journal_lineage_id="journal:other")),
        ("PARENT-LINEAGE", lambda f: f["authoritative_d2_frontier"].update(parent_contract_digest=digest("e"))),
        ("JOURNAL-SEQUENCE", lambda f: f["authoritative_d2_frontier"].update(journal_sequence=1)),
        ("FENCING-EPOCH", lambda f: f.update(current_fencing_epoch=4)),
    ):
        broken = deepcopy(facts); mutate(broken)
        assertion("T-Q77-D2-" + name + "-TRANSPLANT", reference.decide(candidate, manifest, policy, isolation, broken)["reason_codes"][0] in {"D2_TYPED_FRONTIER_VIOLATION", "BROKER_IPC_ATTESTATION_INVALID"})
    forged_capability, forged_facts = deepcopy(capability), deepcopy(facts)
    forged_capability["bindings"]["d2_frontier_digest"] = digest("0")
    refresh_capability(reference, forged_capability, forged_facts)
    assertion("T-Q77-CAPABILITY-D2-BINDING", not reference.validate_capability(forged_capability, decision, candidate, forged_facts))
    issued, _ = advance(reference, "STAGEABLE", decision, capability, ["PROPOSE", "NORMALIZE", "CLASSIFY", "ADMIT", "CALCULATE_RESERVATION", "ISSUE_CAPABILITY"])
    def mutate_runtime_d2(state, mutate):
        record = state["trusted_store"]["d2_frontier_verifications"][f"{capability['bindings']['d2_frontier_digest']}:{state['fencing_epoch']}"]
        mutate(record)
        record["verification_digest"] = canonical_digest_for_test({key: value for key, value in record.items() if key != "verification_digest"})
    for name, mutate in (
        ("AUTHORITY-DOMAIN", lambda record: record["d2_frontier_record"].update(authority_domain_id="authority-domain:other")),
        ("JOURNAL-LINEAGE", lambda record: record["d2_frontier_record"].update(journal_lineage_id="journal:other")),
        ("ROOT-PARENT", lambda record: record["d2_frontier_record"].update(root_contract_digest=digest("e"), parent_contract_digest=digest("f"))),
        ("FRONTIER-SEQUENCE", lambda record: record["d2_frontier_record"].update(journal_sequence=1)),
        ("FRONTIER-CONTENT", lambda record: record["d2_frontier_record"]["inventory"][0].update(artifact_id="artifact:other")),
        ("RUNTIME-SEQUENCE", lambda record: record.update(runtime_journal_sequence=99)),
        ("SIGNER", lambda record: record.update(verified_by="attacker:forged-d2")),
        ("KEY", lambda record: record.update(verifier_key_id="key:other")),
        ("EXPIRY", lambda record: record.update(expires_at=record["verified_at"])),
    ):
        broken = deepcopy(issued); mutate_runtime_d2(broken, mutate)
        assertion("T-Q77-DISPATCH-D2-" + name, not reference.reduce_transition(broken, event_for("DURABLE_DISPATCH", decision, capability))["accepted"])
    bad_dispatch = event_for("DURABLE_DISPATCH", decision, capability); bad_dispatch["d2_frontier_digest"] = digest("0")
    assertion("T-Q77-DISPATCH-D2-BINDING", not reference.reduce_transition(issued, bad_dispatch)["accepted"])
    missing_dispatch = deepcopy(issued); missing_dispatch["trusted_store"].pop("d2_frontier_verifications")
    assertion("T-Q77-DISPATCH-TRUSTED-FRONTIER-REQUIRED", not reference.reduce_transition(missing_dispatch, event_for("DURABLE_DISPATCH", decision, capability))["accepted"])
    stale_dispatch = deepcopy(issued); stale_dispatch["trusted_store"]["d2_frontier_verifications"][f"{capability['bindings']['d2_frontier_digest']}:{stale_dispatch['fencing_epoch']}"]["fencing_epoch"] = 0
    assertion("T-Q77-DISPATCH-CURRENT-FRONTIER-FENCE-REQUIRED", not reference.reduce_transition(stale_dispatch, event_for("DURABLE_DISPATCH", decision, capability))["accepted"])
    committed, _ = advance(reference, "STAGEABLE", decision, capability, ["PROPOSE", "NORMALIZE", "CLASSIFY", "ADMIT", "CALCULATE_RESERVATION", "ISSUE_CAPABILITY", "DURABLE_DISPATCH", "QUIESCE", "SEAL", "POSTCHECK_PASS", "COMMIT"])
    bad_join = event_for("JOIN", decision, capability); bad_join["d2_frontier_digest"] = bad_join["join_evidence"]["d2_frontier_digest"] = digest("0")
    assertion("T-Q77-JOIN-D2-BINDING", not reference.reduce_transition(committed, bad_join)["accepted"])
    crashed = reference.reduce_transition(committed, {"type": "CRASH"})["state"]
    missing_recovery = deepcopy(crashed); missing_recovery["trusted_store"]["d2_frontier_verifications"].pop(f"{capability['bindings']['d2_frontier_digest']}:{missing_recovery['fencing_epoch']}")
    assertion("T-Q77-RECOVERY-TRUSTED-FRONTIER-REQUIRED", not reference.reduce_transition(missing_recovery, {"type": "RECOVER_ORPHAN", "observed_fencing_epoch": missing_recovery["fencing_epoch"], "same_object_chain_verified": True})["accepted"])
    stale_recovery = deepcopy(crashed); stale_recovery["trusted_store"]["d2_frontier_verifications"][f"{capability['bindings']['d2_frontier_digest']}:{stale_recovery['fencing_epoch']}"]["fencing_epoch"] = 2
    assertion("T-Q77-RECOVERY-CURRENT-FRONTIER-FENCE-REQUIRED", not reference.reduce_transition(stale_recovery, {"type": "RECOVER_ORPHAN", "observed_fencing_epoch": stale_recovery["fencing_epoch"], "same_object_chain_verified": True})["accepted"])
    recovery_domain = deepcopy(crashed); mutate_runtime_d2(recovery_domain, lambda record: record["d2_frontier_record"].update(authority_domain_id="authority-domain:other"))
    assertion("T-Q77-RECOVERY-D2-EXACT-IDENTITY-REQUIRED", not reference.reduce_transition(recovery_domain, {"type": "RECOVER_ORPHAN", "observed_fencing_epoch": recovery_domain["fencing_epoch"], "same_object_chain_verified": True})["accepted"])

    corrupt_ledger = reference.initial_state("STAGEABLE", budget_vector=decision["reservations"])
    calls_key = next(key for key in corrupt_ledger["budget_remaining_by_key"] if key[0] == "CALLS")
    bytes_key = next(key for key in corrupt_ledger["budget_remaining_by_key"] if key[0] == "WRITE_BYTES")
    corrupt_ledger["budget_remaining_by_key"][calls_key] -= 1
    corrupt_ledger["budget_remaining_by_key"][bytes_key] += 1
    assertion("T-Q78-SCALAR-CONSERVATION-CANNOT-HIDE-KEY-SWAP", not reference._conserved(corrupt_ledger))


def check_control_binding_regressions(reference, candidate, manifest, policy, isolation, facts, decision, capability) -> None:
    """Focused schema/semantic regressions for control-binding contracts."""
    _, receipt, event = make_effect_evidence(decision, capability)
    receipt_digest = reference.canonical_digest(receipt)
    receipt_facts = {"stage_evidence": receipt_stage_evidence(receipt), "receipt_chain_heads": {receipt["chain"]["source_id"]: {"epoch": receipt["chain"]["epoch"], "next_sequence": receipt["chain"]["sequence"], "predecessor_digest": receipt["chain"]["predecessor_digest"]}}, "verified_effect_receipts": {receipt_digest: {"receipt_digest": receipt_digest, "payload_digest": reference.canonical_digest({key: value for key, value in receipt.items() if key != "authoritative_verifier"}), "object_id": receipt["object_id"], "object_digest": receipt["object_digest"], "object_identity": deepcopy(receipt["object_identity"]), "session_id": receipt["bindings"]["session_id"], "decision_digest": receipt["bindings"]["decision_digest"], "capability_digest": receipt["bindings"]["capability_digest"], "dispatch_intent_digest": receipt["dispatch"]["intent_digest"], "authoritative_verifier": deepcopy(receipt["authoritative_verifier"])}}}
    bad_identity = deepcopy(receipt); bad_identity["object_identity"]["final_object_id"] = "object:other"
    inactive_policy = deepcopy(policy); inactive_policy["policy_activation"]["content_digest"] = digest("0")
    assertion("T-ACTIVATION-SCHEMA", schema_valid("runtime-policy.schema.json", inactive_policy))
    assertion("T-ACTIVATION-SEMANTIC", reference.decide(candidate, manifest, inactive_policy, isolation, facts)["reason_codes"] == ["POLICY_ACTIVATION_INVALID"])
    assertion("T-OBJECT-IDENTITY-SCHEMA", schema_valid("effect-receipt.schema.json", bad_identity))
    assertion("T-OBJECT-IDENTITY-SEMANTIC", not reference.validate_effect_receipt(bad_identity, receipt_facts))
    bad_risk = deepcopy(isolation); bad_risk["risk_disposition_evidence"][0]["evidence_type"] = "MONITORING_RECORD"
    assertion("T-RISK-EVIDENCE-SCHEMA", not schema_valid("isolation-profile.schema.json", bad_risk))
    assertion("T-RISK-EVIDENCE-SEMANTIC", not reference.validate_isolation_profile(bad_risk, facts))
    bad_subject = deepcopy(isolation); bad_subject["principal_envelopes"][0]["os_subject"].pop("ipc_endpoint")
    assertion("T-OS-SUBJECT-SCHEMA", not schema_valid("isolation-profile.schema.json", bad_subject))
    assertion("T-OS-SUBJECT-SEMANTIC", not reference.validate_isolation_profile(bad_subject, facts))
    bad_stage = deepcopy(receipt); bad_stage["seal_evidence"]["object_identity"]["mount_id"] = "mount:other"
    assertion("T-STAGE-EVIDENCE-SCHEMA", schema_valid("effect-receipt.schema.json", bad_stage))
    assertion("T-STAGE-EVIDENCE-SEMANTIC", not reference.validate_effect_receipt(bad_stage, receipt_facts))
    bad_approval = make_approval(); bad_approval.pop("approved_envelope")
    assertion("T-APPROVED-ENVELOPE-SCHEMA", not schema_valid("human-approval-receipt.schema.json", bad_approval))
    event_facts = event_trust_facts(event); bad_chain = deepcopy(event); bad_chain["chain"]["sequence"] += 1
    preimage = deepcopy(bad_chain); preimage["chain"].pop("event_digest"); bad_chain["chain"]["event_digest"] = canonical_digest_for_test(preimage)
    assertion("T-CHAIN-TOPOLOGY-SCHEMA", schema_valid("event-envelope.schema.json", bad_chain))
    assertion("T-CHAIN-TOPOLOGY-SEMANTIC", not reference.validate_safety_event(bad_chain, event_facts))
    receipt_chain = deepcopy(receipt); receipt_chain["chain"]["sequence"] = 1
    assertion("T-ORACLE-CHAIN-SCHEMA", schema_valid("effect-receipt.schema.json", receipt_chain))
    assertion("T-ORACLE-CHAIN-SEMANTIC", not reference.validate_effect_receipt(receipt_chain, receipt_facts))
    for field, value in (("descriptor_id", "descriptor:other"), ("root_id", "root:other"), ("mount_id", "mount:other"), ("resolution_epoch", 2), ("final_object_id", "object:other"), ("final_object_digest", digest("b"))):
        bad = deepcopy(receipt); bad["object_identity"][field] = value
        assertion("T-OBJECT-IDENTITY-" + field, not reference.validate_effect_receipt(bad, receipt_facts))
    for evidence_type in ("STRONGER_PROFILE_RECORD", "MONITORING_RECORD", "OUT_OF_SCOPE_PROOF", "UNKNOWN"):
        bad = deepcopy(isolation); bad["risk_disposition_evidence"][0]["evidence_type"] = evidence_type
        assertion("T-RISK-EVIDENCE-" + evidence_type, not reference.validate_isolation_profile(bad, facts))
    for field in ("process_id", "mount_namespace", "credential_namespace", "session_id", "ipc_endpoint"):
        bad = deepcopy(isolation); bad["principal_envelopes"][0]["os_subject"].pop(field)
        assertion("T-OS-SUBJECT-" + field, not reference.validate_isolation_profile(bad, facts))
    for field, value in (("record_type", "POSTCHECK"), ("epoch", 5), ("observer_id", "observer:other")):
        bad = deepcopy(receipt); bad["quiesce_evidence"][field] = value
        assertion("T-STAGE-EVIDENCE-" + field, not reference.validate_effect_receipt(bad, receipt_facts))
    for field in ("approved_envelope_digest", "human_authentication_evidence", "quorum"):
        bad = make_approval(); bad.pop(field)
        assertion("T-APPROVAL-PROJECTION-" + field, not schema_valid("human-approval-receipt.schema.json", bad))
    for index, path in enumerate(("/workspace/output/report\x00.txt", "/workspace/output/report\x1f.txt", "//workspace/output/report.txt", "/workspace/output/report\u2215.txt"), start=1):
        bad = deepcopy(candidate); bad["authority_alternatives"][0]["entries"][0]["selector"]["canonical_path"] = path
        assertion("T-BYTE-SAFE-PATH-" + str(index) + "-SCHEMA", not schema_valid("admission-candidate.schema.json", bad))
        assertion("T-BYTE-SAFE-PATH-" + str(index) + "-SEMANTIC", not reference.validate_authority_entry(bad["authority_alternatives"][0]["entries"][0]))
        receipt_path = deepcopy(receipt)
        for field in ("authorized", "attempted", "actual", "committed", "observed", "verified"):
            receipt_path[field]["entries"][0]["scope"]["values"] = [path]
        receipt_path["authoritative_verifier"]["payload_digest"] = reference.canonical_digest({key: value for key, value in receipt_path.items() if key != "authoritative_verifier"})
        path_facts = deepcopy(receipt_facts); path_digest = reference.canonical_digest(receipt_path); path_facts["verified_effect_receipts"] = {path_digest: {**next(iter(path_facts["verified_effect_receipts"].values())), "receipt_digest": path_digest, "payload_digest": receipt_path["authoritative_verifier"]["payload_digest"], "authoritative_verifier": deepcopy(receipt_path["authoritative_verifier"])}}
        assertion("T-BYTE-SAFE-RECEIPT-" + str(index) + "-SCHEMA", not schema_valid("effect-receipt.schema.json", receipt_path))
        assertion("T-BYTE-SAFE-RECEIPT-" + str(index) + "-SEMANTIC", not reference.validate_effect_receipt(receipt_path, path_facts))
    for field, value in (("source_id", "source:other"), ("epoch", 2), ("predecessor_digest", digest("b")), ("previous_event_digest", digest("b"))):
        bad = deepcopy(event); bad["chain"][field] = value; preimage = deepcopy(bad); preimage["chain"].pop("event_digest"); bad["chain"]["event_digest"] = canonical_digest_for_test(preimage)
        assertion("T-CHAIN-TOPOLOGY-" + field, not reference.validate_safety_event(bad, event_facts))
    for field, value in (("source_id", "source:other"), ("epoch", 2), ("sequence", 1), ("receipt_digest", digest("b"))):
        bad = deepcopy(receipt); bad["chain"][field] = value
        assertion("T-ORACLE-ROOT-" + field + "-SCHEMA", schema_valid("effect-receipt.schema.json", bad))
        assertion("T-ORACLE-ROOT-" + field + "-SEMANTIC", not reference.validate_effect_receipt(bad, receipt_facts))
    bad_relation = deepcopy(manifest); bad_relation["effect_bounds"][0]["resources"][0]["resource_kind"] = "ENDPOINT"
    assertion("T-CLOSED-EFFECT-RESOURCE-OPERATION", not schema_valid("effect-manifest.schema.json", bad_relation))
    d2_facts = deepcopy(facts); d2_facts["authoritative_d2_frontier"]["inventory"] = []
    assertion("T-AUTHORITATIVE-INVENTORY-COUNTEREVIDENCE", reference.decide(candidate, manifest, policy, isolation, d2_facts)["reason_codes"] == ["D2_TYPED_FRONTIER_VIOLATION"])
    reserved, _ = advance(reference, "STAGEABLE", decision, capability, ["PROPOSE", "NORMALIZE", "CLASSIFY", "ADMIT", "CALCULATE_RESERVATION"])
    missing_issue = event_for("ISSUE_CAPABILITY", decision, capability); missing_issue.pop("capability_verification_ref")
    assertion("T-TRUSTED-CAPABILITY-ISSUE-COUNTEREVIDENCE", not reference.reduce_transition(reserved, missing_issue)["accepted"])
    issued, _ = advance(reference, "STAGEABLE", decision, capability, ["PROPOSE", "NORMALIZE", "CLASSIFY", "ADMIT", "CALCULATE_RESERVATION", "ISSUE_CAPABILITY"])
    bad_dispatch = event_for("DURABLE_DISPATCH", decision, capability); bad_dispatch["dispatch_verification_ref"] = "dispatch:untrusted"
    assertion("T-TRUSTED-CAPABILITY-DISPATCH-COUNTEREVIDENCE", not reference.reduce_transition(issued, bad_dispatch)["accepted"])
    child_decision, child, child_facts = make_delegated_child(reference, candidate, facts, decision, capability)
    child_facts["parent_budget_ledgers"][child["delegation"]["parent_capability_digest"]]["children"].append({"capability_id": "cap:over", "budget_escrow": [{**child["budgets"][0], "amount": 1026}]})
    child["delegation"]["sibling_reservations_digest"] = reference.canonical_digest(child_facts["parent_budget_ledgers"][child["delegation"]["parent_capability_digest"]]["children"]); refresh_capability(reference, child, child_facts)
    assertion("T-KEYED-ESCROW-COUNTEREVIDENCE", not reference.validate_capability(child, child_decision, candidate, child_facts))
    assertion("T-AUTHORITATIVE-INVENTORY-POSITIVE", reference.decide(candidate, manifest, policy, isolation, facts)["decision"] == "ALLOW")
    hidden_facts = deepcopy(facts); hidden_facts["authoritative_d2_frontier"]["inventory"].append({**hidden_facts["authoritative_d2_frontier"]["inventory"][0], "artifact_id": "artifact:hidden", "iteration": 2})
    assertion("T-AUTHORITATIVE-INVENTORY-HIDDEN-NEGATIVE", reference.decide(candidate, manifest, policy, isolation, hidden_facts)["reason_codes"] == ["D2_TYPED_FRONTIER_VIOLATION"])
    host = reference.initial_host_state(); allocated = reference.reduce_host(host, {"type": "ALLOCATE", "host_id": "host:one", "instance_id": "instance:one", "nonce": "host_nonce_12345678901234"})["state"]; placed = reference.reduce_host(allocated, {"type": "ATTEST_PLACEMENT", "instance_id": "instance:one", "nonce": "host_nonce_12345678901234", "epoch": 1, "placement_digest": digest("7")})["state"]; running = reference.reduce_host(placed, {"type": "START_SESSION", "session_id": "session:one", "placement_digest": digest("7")})["state"]
    assertion("T-HOST-HEARTBEAT-COUNTEREVIDENCE", not reference.reduce_host(running, {"type": "HEARTBEAT", "sequence": 1, "epoch": 1, "heartbeat_evidence_ref": "missing"})["accepted"])
    orphaned = reference.reduce_host(running, {"type": "CRASH", "orphan_inventory": ["tx:one"]})["state"]; fenced = reference.reduce_host(orphaned, {"type": "FENCE"})["state"]
    assertion("T-HOST-RECOVERY-COUNTEREVIDENCE", not reference.reduce_host(fenced, {"type": "RECOVER_ORPHAN", "fencing_epoch": 2, "recovered_ids": [], "recovery_evidence_ref": "missing"})["accepted"])
    approval = make_approval(); approval_digest = reference._approval_receipt_digest(approval); auth = approval["human_authentication_evidence"][0]; approval_facts = {"trusted_time": "2026-08-24T00:00:05Z", "current_revocation_epoch": 3, "required_approval_quorum": 1, "consumed_approval_receipts": [], "verified_approver_authentications": {auth["evidence_digest"]: {**auth, "receipt_id": approval["receipt_id"], "signature_verified": True, "not_revoked": True, "verified_by": "verifier:human"}}, "verified_approval_signatures": {approval_digest: {"receipt_digest": approval_digest, "signature_verified": True, "signed_payload_digest": approval["canonical_payload_digest"], "material_terms_digest": approval["service_signature"]["material_terms_digest"], "service_identity": approval["service_signature"]["service_identity"], "key_id": approval["service_signature"]["key_id"], "algorithm": approval["service_signature"]["algorithm"], "freshness_verified": True, "revocation_checked": True, "revocation_epoch": 3}}}
    for field, mutate in (("effects", lambda x: x["effects"][0].update(effect="COMPUTE")), ("targets", lambda x: x["targets"][0].update(value="/workspace/output/other.txt")), ("budgets", lambda x: x["budgets"][0].update(limit=2)), ("flows", lambda x: x["material_terms"]["data_flows"][0].update(channel="channel:other"))):
        bad = deepcopy(approval); mutate(bad)
        assertion("T-APPROVAL-PROJECTION-" + field + "-SCHEMA", schema_valid("human-approval-receipt.schema.json", bad) is (field != "effects"))
        assertion("T-APPROVAL-PROJECTION-" + field + "-SEMANTIC", not reference.validate_approval_receipt(bad, expected_nonce=approval["approval_nonce"], trusted_facts=approval_facts))
    bad_quorum = deepcopy(approval); bad_quorum["quorum"]["required"] = 2
    assertion("T-APPROVER-QUORUM-SCHEMA", schema_valid("human-approval-receipt.schema.json", bad_quorum))
    assertion("T-APPROVER-QUORUM-SEMANTIC", not reference.validate_approval_receipt(bad_quorum, expected_nonce=approval["approval_nonce"], trusted_facts=approval_facts))
    return None


def check_remediation_report_continuation(reference) -> None:
    """Reports inform readiness only; a separate exact external grant authorizes continuation."""
    def seal_report(report: dict) -> dict:
        report["report_digest"] = reference.canonical_digest({key: report[key] for key in reference.REMEDIATION_REPORT_FIELDS if key != "report_digest"})
        return report

    def make_report() -> dict:
        return seal_report({
            "report_id": "report:continuation-gate",
            "packet_digest": digest("a"),
            "reported_at": "2026-08-24T00:00:00Z",
            "finding_ids": ["finding:continuation-gate"],
            "readiness_impact": "BLOCKS_CLAIM",
            "affected_status_claims": ["READY"],
            "recommended_patch": "Apply the scoped correction only after a separate explicit authorization.",
            "consequence_if_unresolved": "READY remains unavailable for this packet.",
            "report_authority": "NONE",
            "permitted_effects_from_report": [],
            "controller_state_after_report": "STOPPED_AWAITING_EXPLICIT_USER_INSTRUCTION",
            "report_digest": "",
        })

    def make_grant(report: dict, transition_class: str) -> tuple[dict, dict, dict]:
        grant = {
            "grant_id": "grant:continuation:" + transition_class.lower(),
            "transition_class": transition_class,
            "report_id": report["report_id"],
            "report_digest": report["report_digest"],
            "packet_digest": report["packet_digest"],
            "finding_ids": list(report["finding_ids"]),
            "scope_digest": digest("b"),
            "budget_digest": digest("c"),
            "max_attempts": 1,
            "nonce": "continuation_nonce_" + transition_class.lower() + "_1234567890",
            "issued_at": "2026-08-24T00:00:01Z",
            "expires_at": "2026-08-24T00:10:00Z",
            "signature": "signature:continuation:" + transition_class.lower(),
            "grant_digest": "",
        }
        grant["grant_digest"] = reference.canonical_digest({key: grant[key] for key in reference.CONTINUATION_GRANT_FIELDS if key != "grant_digest"})
        record = {
            "grant": deepcopy(grant), "grant_digest": grant["grant_digest"], "signed_payload_digest": grant["grant_digest"],
            "signature": grant["signature"], "signature_verified": True, "freshness_verified": True,
            "revocation_checked": True, "not_revoked": True, "current_key": True, "verified_by": "verifier:continuation",
            "authorization_source": "EXPLICIT_USER_INSTRUCTION", "authorized_subject": "user:a1",
            "authority_role": "USER", "explicit_user_instruction_verified": True,
        }
        request = {key: grant[key] for key in reference.CONTINUATION_REQUEST_FIELDS if key != "attempt"}
        request["attempt"] = 1
        facts = {
            "trusted_time": "2026-08-24T00:00:05Z",
            "current_packet_digest": report["packet_digest"],
            "current_scope_digest": grant["scope_digest"],
            "current_budget_digest": grant["budget_digest"],
            "current_attempt": 1,
            "trusted_continuation_verifiers": ["verifier:continuation"],
            "verified_continuation_grants": {grant["grant_id"]: record},
            "consumed_continuation_grant_ids": [],
            "consumed_continuation_nonces": [],
        }
        return request, facts, grant

    report = make_report()
    report_only = reference.decide_review_continuation(report, None, {})
    assertion("T-REPORT-NONAUTHORIZING", report_only == {"decision": "STOP", "reason_code": "RC_REPORT_NONAUTHORIZING", "detail": "EXPLICIT_CONTINUATION_REQUEST_REQUIRED", "state": "STOPPED_AWAITING_EXPLICIT_USER_INSTRUCTION", "authorized_transition": None, "next_trusted_facts": None})

    imperative = deepcopy(report); imperative["recommended_patch"] = "MUST_FIX: apply the patch and start another review."
    seal_report(imperative)
    imperative_result = reference.decide_review_continuation(imperative, None, {})
    assertion("T-REPORT-IMPERATIVE-TEXT-NONAUTHORIZING", imperative_result["decision"] == "STOP" and imperative_result["state"] == "STOPPED_AWAITING_EXPLICIT_USER_INSTRUCTION" and imperative_result["authorized_transition"] is None)

    patch_request, patch_facts, patch_grant = make_grant(report, "PATCH")
    facts_before = deepcopy(patch_facts)
    patch_result = reference.decide_review_continuation(report, patch_request, patch_facts)
    assertion("T-CONTINUATION-EXACT-PATCH", patch_result["decision"] == "AUTHORIZE_CONTINUATION" and patch_result["authorized_transition"] == {"transition_class": "PATCH", "grant_id": patch_grant["grant_id"], "grant_digest": patch_grant["grant_digest"], "report_digest": report["report_digest"], "packet_digest": report["packet_digest"]} and patch_facts == facts_before and patch_result["next_trusted_facts"]["consumed_continuation_grant_ids"] == [patch_grant["grant_id"]] and patch_result["next_trusted_facts"]["consumed_continuation_nonces"] == [patch_grant["nonce"]])

    cross_kind = deepcopy(patch_request); cross_kind["transition_class"] = "REVIEW"
    cross_kind_result = reference.decide_review_continuation(report, cross_kind, patch_facts)
    assertion("T-CONTINUATION-KIND-SEPARATION", cross_kind_result["decision"] == "STOP")

    packet_mismatch = deepcopy(patch_request); packet_mismatch["packet_digest"] = digest("d")
    packet_mismatch_result = reference.decide_review_continuation(report, packet_mismatch, patch_facts)
    assertion("T-CONTINUATION-PACKET-DIGEST-MISMATCH", packet_mismatch_result["decision"] == "STOP")

    current_packet_drift = deepcopy(patch_facts); current_packet_drift["current_packet_digest"] = digest("d")
    current_packet_drift_result = reference.decide_review_continuation(report, patch_request, current_packet_drift)
    assertion("T-CONTINUATION-CURRENT-PACKET-DRIFT", current_packet_drift_result["decision"] == "STOP")

    current_scope_drift = deepcopy(patch_facts); current_scope_drift["current_scope_digest"] = digest("d")
    current_scope_drift_result = reference.decide_review_continuation(report, patch_request, current_scope_drift)
    assertion("T-CONTINUATION-CURRENT-SCOPE-DRIFT", current_scope_drift_result["decision"] == "STOP")

    current_budget_drift = deepcopy(patch_facts); current_budget_drift["current_budget_digest"] = digest("d")
    current_budget_drift_result = reference.decide_review_continuation(report, patch_request, current_budget_drift)
    assertion("T-CONTINUATION-CURRENT-BUDGET-DRIFT", current_budget_drift_result["decision"] == "STOP")

    current_attempt_drift = deepcopy(patch_facts); current_attempt_drift["current_attempt"] = 2
    current_attempt_drift_result = reference.decide_review_continuation(report, patch_request, current_attempt_drift)
    assertion("T-CONTINUATION-CURRENT-ATTEMPT-DRIFT", current_attempt_drift_result["decision"] == "STOP")

    replay_facts = deepcopy(patch_result["next_trusted_facts"])
    replay_result = reference.decide_review_continuation(report, patch_request, replay_facts)
    assertion("T-CONTINUATION-GRANT-REPLAY", replay_result["decision"] == "STOP")

    expired_facts = deepcopy(patch_facts); expired_facts["trusted_time"] = "2026-08-24T00:10:00Z"
    expired_result = reference.decide_review_continuation(report, patch_request, expired_facts)
    assertion("T-CONTINUATION-GRANT-EXPIRED", expired_result["decision"] == "STOP")

    predated_request, predated_facts, _ = make_grant(report, "PATCH")
    predated_grant = predated_facts["verified_continuation_grants"][predated_request["grant_id"]]["grant"]
    predated_grant["issued_at"] = "2026-08-23T23:59:59Z"
    predated_grant["grant_digest"] = reference.canonical_digest({key: predated_grant[key] for key in reference.CONTINUATION_GRANT_FIELDS if key != "grant_digest"})
    predated_record = predated_facts["verified_continuation_grants"][predated_request["grant_id"]]
    predated_record.update(grant_digest=predated_grant["grant_digest"], signed_payload_digest=predated_grant["grant_digest"])
    predated_request["grant_digest"] = predated_grant["grant_digest"]
    predated_result = reference.decide_review_continuation(report, predated_request, predated_facts)
    assertion("T-CONTINUATION-GRANT-PREDATES-REPORT", predated_result["decision"] == "STOP" and predated_result["detail"] == "CONTINUATION_GRANT_PREDATES_REPORT")

    untrusted_verifier_facts = deepcopy(patch_facts)
    untrusted_verifier_facts["verified_continuation_grants"][patch_grant["grant_id"]]["verified_by"] = "agent:untrusted"
    untrusted_verifier_result = reference.decide_review_continuation(report, patch_request, untrusted_verifier_facts)
    assertion("T-CONTINUATION-UNTRUSTED-VERIFIER", untrusted_verifier_result["decision"] == "STOP")

    agent_auth_facts = deepcopy(patch_facts)
    agent_auth_facts["verified_continuation_grants"][patch_grant["grant_id"]]["authorization_source"] = "AGENT_RECOMMENDATION"
    agent_auth_result = reference.decide_review_continuation(report, patch_request, agent_auth_facts)
    assertion("T-CONTINUATION-AGENT-RECOMMENDATION-NONAUTHORIZING", agent_auth_result["decision"] == "STOP")

    multi_attempt_facts = deepcopy(patch_facts)
    multi_attempt_grant = multi_attempt_facts["verified_continuation_grants"][patch_grant["grant_id"]]["grant"]
    multi_attempt_grant["max_attempts"] = 2
    multi_attempt_grant["grant_digest"] = reference.canonical_digest({key: multi_attempt_grant[key] for key in reference.CONTINUATION_GRANT_FIELDS if key != "grant_digest"})
    multi_attempt_record = multi_attempt_facts["verified_continuation_grants"][patch_grant["grant_id"]]
    multi_attempt_record.update(grant_digest=multi_attempt_grant["grant_digest"], signed_payload_digest=multi_attempt_grant["grant_digest"])
    multi_attempt_request = deepcopy(patch_request); multi_attempt_request["grant_digest"] = multi_attempt_grant["grant_digest"]
    multi_attempt_result = reference.decide_review_continuation(report, multi_attempt_request, multi_attempt_facts)
    assertion("T-CONTINUATION-SINGLE-ATTEMPT-ONLY", multi_attempt_result["decision"] == "STOP")

    freeze_request, freeze_facts, freeze_grant = make_grant(report, "FREEZE")
    freeze_result = reference.decide_review_continuation(report, freeze_request, freeze_facts)
    assertion("T-CONTINUATION-EXACT-FREEZE", freeze_result["decision"] == "AUTHORIZE_CONTINUATION" and freeze_result["authorized_transition"]["transition_class"] == "FREEZE" and freeze_result["authorized_transition"]["grant_digest"] == freeze_grant["grant_digest"])

    review_request, review_facts, review_grant = make_grant(report, "REVIEW")
    review_result = reference.decide_review_continuation(report, review_request, review_facts)
    assertion("T-CONTINUATION-EXACT-REVIEW", review_result["decision"] == "AUTHORIZE_CONTINUATION" and review_result["authorized_transition"]["transition_class"] == "REVIEW" and review_result["authorized_transition"]["grant_digest"] == review_grant["grant_digest"])

    assertion("T-REPORT-CORE-001", report_only["reason_code"] == imperative_result["reason_code"] == "RC_REPORT_NONAUTHORIZING" and report_only["authorized_transition"] is imperative_result["authorized_transition"] is None)
    assertion("T-REPORT-CORE-002", all(result["decision"] == "STOP" and result["reason_code"] == "RC_CONTINUATION_GRANT_INVALID" for result in (cross_kind_result, packet_mismatch_result, current_packet_drift_result, current_scope_drift_result, current_budget_drift_result, current_attempt_drift_result, replay_result, expired_result, predated_result, untrusted_verifier_result, agent_auth_result, multi_attempt_result)) and all(result["decision"] == "AUTHORIZE_CONTINUATION" for result in (patch_result, freeze_result, review_result)))


def main() -> int:
    schemas = check_schemas(); valid, invalid = check_examples(); reference = load_reference()
    candidate, manifest, policy, isolation, facts, decision, capability = check_canonical_chain(reference)
    capability_trust = check_capability_trust(reference, candidate, facts, decision, capability)
    lts_steps, records = check_budget_and_lifecycle(reference, candidate, manifest, policy, isolation, facts, decision, capability)
    negatives = check_authority_d2_path(reference, candidate, manifest, policy, isolation, facts)
    evidence = check_evidence_guards(reference, decision, capability)
    branches = check_branch_recovery(reference, candidate, decision, capability)
    controls = check_approval_isolation(reference, isolation, facts)
    approval_chain = check_approval_digest_chain(reference, candidate, manifest, policy, isolation, facts, decision)
    attestations = check_attestation_supply(reference, candidate, manifest, policy, isolation, facts)
    hosts = check_host(reference)
    round4 = check_round4_closure(reference, candidate, manifest, policy, isolation, facts, decision, capability)
    round5_attestation = check_round5_attestation(reference, candidate, manifest, policy, isolation, facts, decision, capability)
    round5_manifest = check_round5_manifest_and_descriptor(reference, candidate, manifest, policy, isolation, facts)
    round5_isolation_supply = check_round5_isolation_and_supply(reference, candidate, manifest, policy, isolation, facts)
    round5_reservation_event = check_round5_reservation_and_event(reference, candidate, manifest, policy, isolation, facts, decision, capability)
    check_round7a_remediation(reference, candidate, manifest, policy, isolation, facts, decision, capability)
    check_control_binding_regressions(reference, candidate, manifest, policy, isolation, facts, decision, capability)
    check_remediation_report_continuation(reference)
    invariants = check_traceability()
    print(f"jsonschema={metadata.version('jsonschema')}")
    print(f"schemas: PASS ({schemas} Draft 2020-12; strict local boundaries)")
    print(f"examples: PASS ({valid} valid; {invalid} invalid; Python + CLI)")
    print(f"canonical admission/capability: PASS (schema-valid inputs, decision, exact capability)")
    print(f"lifecycle: PASS ({lts_steps} stageable steps; {records} atomic dispatch; replay survives STOP)")
    print(f"negative/property mutations: PASS ({len(EXECUTED_ASSERTION_INSTANCES)} assertion instances)")
    print(f"traceability: PASS ({invariants} invariants; registries resolved; assertions executed)")
    print("status: SPECIFICATION_MODEL_TESTED; runtime=NOT_IMPLEMENTED; runtime_attestation=NOT_ATTESTED")
    print("skipped: real signatures, descriptor syscalls, kernel/isolation enforcement, durable storage, live broker/executor/observer, external reconciliation")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
