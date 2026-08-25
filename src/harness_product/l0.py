"""Exact, fail-closed L0-LX-A profile compiler and host preflight.

This module is milestone M3's Linux boundary.  Compilation is deterministic and
non-effectful.  Host preflight performs read-only measurement only; it never
creates a namespace, cgroup, socket, process tree, worker, or filesystem effect.
The only selected runtime backend is the exact bubblewrap binary pinned below.
"""

from __future__ import annotations

import ctypes
import errno
import fcntl
import json
import os
import platform
import re
import resource
import socket
import stat
import struct
import subprocess
import time
import unicodedata
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from hashlib import sha256
from pathlib import Path, PurePosixPath

from .durable import DispatchClaim, DurableOutcome, DurableStore, VerificationResult, VerificationStatus

PROFILE_ID = "L0-LX-A"
WORKLOAD_CLASS = "DISCONNECTED_STAGEABLE_WORKER"
ENVIRONMENT = "DEV_STAGEABLE_LOCAL"
RUNTIME_PATH = "/usr/bin/bwrap"
RUNTIME_VERSION = "bubblewrap 0.9.0"
RUNTIME_DIGEST = "sha256:52231e1caf55bcbc667b269f49c63599a6f7db4767ae6a039580d0ff853db712"

_MAX_INTEGER = (1 << 63) - 1
_MAX_MESSAGE_BYTES = 1 << 20
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_UTC_TIME = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")

_ROLES = (
    "AGENT_WORKER",
    "BROKER",
    "EXECUTOR",
    "MODEL_GATEWAY",
    "OBSERVER",
)
_ACTIVE_ROLES = frozenset({"AGENT_WORKER", "BROKER", "EXECUTOR"})
_DISABLED_ROLES = frozenset({"MODEL_GATEWAY", "OBSERVER"})
_ROLE_EFFECTS = {
    "AGENT_WORKER": frozenset({"COMPUTE", "OBSERVE"}),
    "BROKER": frozenset({"COMMUNICATE"}),
    "EXECUTOR": frozenset({"MUTATE"}),
    "MODEL_GATEWAY": frozenset(),
    "OBSERVER": frozenset(),
}
_ROLE_NETWORK = {
    "AGENT_WORKER": "DISCONNECTED",
    "BROKER": "BROKER_MEDIATED",
    "EXECUTOR": "NONE",
    "MODEL_GATEWAY": "NONE",
    "OBSERVER": "NONE",
}
_ROLE_FDS = {
    "AGENT_WORKER": frozenset({"BROKER_IPC_WORKER_END"}),
    "BROKER": frozenset({"BROKER_IPC_BROKER_END"}),
    "EXECUTOR": frozenset(),
    "MODEL_GATEWAY": frozenset(),
    "OBSERVER": frozenset(),
}

_RESOURCE_SPEC = {
    "CPU_TIME": ("MILLISECONDS", "CGROUP_V2"),
    "CPU_RATE": ("MILLICORES", "CGROUP_V2"),
    "WALL_TIME": ("MILLISECONDS", "SUPERVISOR"),
    "MEMORY": ("MIB", "CGROUP_V2"),
    "SWAP": ("MIB", "CGROUP_V2"),
    "PIDS": ("COUNT", "CGROUP_V2"),
    "BLOCK_IO_READ": ("IOPS", "DEVICE_SCHEDULER"),
    "BLOCK_IO_WRITE": ("IOPS", "DEVICE_SCHEDULER"),
    "FILES": ("COUNT", "FILESYSTEM_QUOTA"),
    "INODES": ("COUNT", "FILESYSTEM_QUOTA"),
    "OPEN_FDS": ("COUNT", "RLIMIT"),
    "OUTPUT_BYTES": ("BYTES", "FILESYSTEM_QUOTA"),
    "GPU_TIME": ("MILLISECONDS", "DEVICE_SCHEDULER"),
    "GPU_MEMORY": ("MIB", "DEVICE_SCHEDULER"),
}
_RESOURCE_ORDER = tuple(_RESOURCE_SPEC)
_NAMESPACES = frozenset({"USER", "MOUNT", "PID", "IPC", "UTS", "NETWORK", "CGROUP"})
_OPENAT2_FLAGS = frozenset(
    {"RESOLVE_BENEATH", "RESOLVE_NO_MAGICLINKS", "RESOLVE_NO_SYMLINKS", "RESOLVE_NO_XDEV"}
)
_KERNEL_FEATURES = frozenset(
    {
        "CONFIG_CGROUPS=y",
        "CONFIG_SECCOMP=y",
        "CONFIG_SECCOMP_FILTER=y",
        "CONFIG_SECURITY_APPARMOR=y",
        "CONFIG_USER_NS=y",
    }
)
_DENIED_SURFACES = frozenset(
    {
        "ADMIN",
        "BROAD_UNIX_SOCKET",
        "CHECKOUT",
        "CREDENTIALS",
        "DEVICES",
        "DNS",
        "DOT_GIT",
        "DURABLE_DB",
        "EBPF",
        "HOST_HOME",
        "INHERITED_CONNECTED_FD",
        "IPV4",
        "IPV6",
        "LOOPBACK",
        "METADATA_ROUTE",
        "MODULES",
        "PACKET_SOCKET",
        "PTRACE",
        "RAW_SOCKET",
        "RUNTIME_SOCKET",
        "SECRETS",
        "SHARED_MEMORY",
        "WORKER_DIRECT_MUTATE",
    }
)

_TOP_KEYS = frozenset(
    {
        "profile_id",
        "profile_version",
        "status",
        "workload_class",
        "environment",
        "risk_class",
        "data_class",
        "backend",
        "principals",
        "worker_controls",
        "network",
        "broker_ipc",
        "resources",
        "measurement_bindings",
        "denied_surfaces",
    }
)
_BACKEND_KEYS = frozenset({"path", "version", "digest"})
_ACTIVE_PRINCIPAL_KEYS = frozenset(
    {
        "role",
        "principal_id",
        "enabled",
        "uid",
        "gid",
        "user_namespace",
        "mount_namespace",
        "pid_namespace",
        "ipc_namespace",
        "uts_namespace",
        "network_namespace",
        "cgroup_namespace",
        "security_label",
        "credential_namespace",
        "session_id",
        "network_mode",
        "credential_mode",
        "ambient_authority",
        "effect_ceiling",
        "fd_allowlist",
    }
)
_DISABLED_PRINCIPAL_KEYS = frozenset(
    {
        "role",
        "principal_id",
        "enabled",
        "network_mode",
        "credential_mode",
        "ambient_authority",
        "effect_ceiling",
        "fd_allowlist",
    }
)
_WORKER_KEYS = frozenset(
    {
        "namespaces",
        "non_host_uid_gid",
        "no_new_privileges",
        "capabilities",
        "seccomp",
        "lsm",
        "mount_propagation",
        "rootfs",
        "inputs",
        "outputs",
        "staging_output_count",
        "checkout_visible",
        "git_visible",
        "host_home_visible",
        "runtime_socket_visible",
        "durable_db_visible",
        "close_fds",
        "proc_mode",
        "ptrace",
        "devices",
        "ebpf",
        "modules",
        "admin",
        "shared_memory",
        "wall_time_supervisor",
        "path_resolution",
    }
)
_NETWORK_KEYS = frozenset(
    {
        "ipv4",
        "ipv6",
        "loopback",
        "routes",
        "dns",
        "metadata_route",
        "raw_socket",
        "packet_socket",
        "broad_unix_socket",
        "inherited_connected_fds",
        "credentials",
        "secret_bytes",
        "broker_ipc_only",
    }
)
_BROKER_KEYS = frozenset(
    {
        "worker_principal",
        "broker_principal",
        "worker_endpoint",
        "broker_endpoint",
        "transport",
        "peer_credentials",
        "operation_scoped",
        "max_message_bytes",
        "message_schema_digest",
    }
)
_RESOURCE_KEYS = frozenset({"resource", "unit", "limit", "enforcement"})
_MEASUREMENT_KEYS = frozenset(
    {
        "rootfs_manifest_digest",
        "seccomp_profile_digest",
        "lsm_policy_name",
        "lsm_policy_digest",
        "broker_message_schema_digest",
    }
)
_PATH_REQUEST_KEYS = frozenset({"canonical_path", "descriptor_id", "root_id", "resolution_epoch"})
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
_BROKER_MESSAGE_KEYS = frozenset(
    {
        "message_version",
        "operation_id",
        "worker_principal",
        "worker_session",
        "nonce",
        "fencing_epoch",
        "binding_digest",
        "proposal",
        "proposal_digest",
    }
)
_STAGE_REQUEST_KEYS = frozenset(
    {"transaction_id", "claim_digest", "operation", "content", "content_digest", "target_binding"}
)
_BROKER_EXPECTED_KEYS = frozenset(
    {"operation_id", "worker_principal", "worker_session", "nonce", "fencing_epoch", "binding_digest", "peer"}
)
_PEER_KEYS = frozenset({"pid", "uid", "gid", "process_session"})
_M1_REQUEST_KEYS = frozenset(
    {"evaluation_time", "proposal", "manifest", "policy", "physical_ceiling", "trusted_facts"}
)
_M1_PROPOSAL_KEYS = frozenset(
    {"operation_id", "principal_id", "material_digest", "authority"}
)
_DURABLE_CLAIM_KEYS = frozenset(
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
_VERIFICATION_KEYS = frozenset(
    {"verification_version", "verifier_id", "issuer_id", "key_id", "payload_digest", "bindings", "proof"}
)
_SUPPLY_KEYS = frozenset(
    {
        "supply_version",
        "observed_at",
        "profile_digest",
        "measurement_digest",
        "runtime",
        "image",
        "registry",
        "signer",
        "placement",
        "artifacts",
        "verification",
    }
)
_SUPPLY_RUNTIME_KEYS = frozenset({"path", "version", "digest"})
_SUPPLY_IMAGE_KEYS = frozenset({"image_id", "rootfs_manifest_digest", "platform", "architecture"})
_SUPPLY_REGISTRY_KEYS = frozenset(
    {"snapshot_digest", "reference", "generation", "rollback_floor", "issued_at", "expires_at"}
)
_SUPPLY_SIGNER_KEYS = frozenset(
    {"trust_root_id", "signer_id", "key_id", "algorithm", "revocation_epoch", "rollback_floor"}
)
_SUPPLY_PLACEMENT_KEYS = frozenset(
    {
        "placement_id",
        "host_id",
        "subject_instance_id",
        "process_tree_id",
        "session_id",
        "nonce",
        "fencing_epoch",
        "revocation_epoch",
        "rootfs_binding_digest",
        "staging_binding_digest",
        "cgroup_binding_digest",
        "broker_binding_digest",
        "fd_inventory_digest",
        "namespace_plan_digest",
        "issued_at",
        "expires_at",
    }
)
_SUPPLY_ARTIFACT_KEYS = frozenset(
    {"role", "artifact_id", "descriptor", "expected_bytes_digest", "provenance_digest"}
)
_SUPPLY_VERIFICATION_SOURCE_KEYS = frozenset({"verifier_id", "issuer_id", "key_id", "proof"})
_SUPPLY_PAYLOAD_KEYS = frozenset(
    {
        "supply_version",
        "observed_at",
        "profile_digest",
        "measurement_digest",
        "runtime",
        "image",
        "registry",
        "signer",
        "placement",
        "placement_digest",
        "artifacts",
    }
)
_SUPPLY_PLACEMENT_PAYLOAD_KEYS = _SUPPLY_PLACEMENT_KEYS | frozenset(
    {"profile_digest", "measurement_digest", "runtime_digest"}
)
_SUPPLY_ARTIFACT_BINDING_KEYS = frozenset(
    {
        "role",
        "artifact_id",
        "expected_bytes_digest",
        "actual_bytes_digest",
        "provenance_digest",
        "device",
        "inode",
        "size",
        "mode",
        "binding_digest",
    }
)
_SUPPLY_ROLES = (
    "ROOTFS_MANIFEST",
    "LOADER",
    "DEPENDENCY_CLOSURE",
    "TOOL",
    "SBOM",
    "REGISTRY_SNAPSHOT",
    "SECCOMP_PROFILE",
    "LSM_POLICY",
)
_MAX_SUPPLY_ARTIFACT_BYTES = 64 << 20

_SESSION_KEYS = frozenset(
    {
        "session_version",
        "session_record_id",
        "session_id",
        "transaction_id",
        "claim_digest",
        "lineage_root",
        "fencing_epoch",
        "revocation_epoch",
        "worker_principal",
        "executor_principal",
        "subject_instance_id",
        "process_tree_id",
        "namespace_ids",
        "rootfs",
        "inputs",
        "broker_ipc",
        "seccomp",
        "tool",
        "cgroup",
        "staging",
        "supervisor_fds",
        "cleanup",
    }
)
_SESSION_NAMESPACE_KEYS = frozenset({"user", "mount", "pid", "ipc", "uts", "network", "cgroup"})
_SESSION_ROOTFS_KEYS = frozenset({"descriptor", "descriptor_id"})
_SESSION_INPUT_KEYS = frozenset({"descriptor", "descriptor_id", "mount_path", "expected_bytes_digest"})
_SESSION_BROKER_KEYS = frozenset(
    {
        "descriptor",
        "descriptor_id",
        "socket_name",
        "worker_endpoint",
        "broker_endpoint",
        "transport",
    }
)
_SESSION_SECCOMP_KEYS = frozenset({"descriptor", "descriptor_id", "expected_bytes_digest"})
_SESSION_TOOL_KEYS = frozenset({"descriptor", "descriptor_id", "path", "argv", "expected_bytes_digest"})
_SESSION_CGROUP_KEYS = frozenset(
    {"path", "controllers", "device_major", "device_minor", "delegated", "identity_digest"}
)
_SESSION_STAGING_KEYS = frozenset(
    {
        "root_id",
        "root_identity",
        "mount_id",
        "mount_identity",
        "files",
        "inodes",
        "bytes",
    }
)
_SESSION_SUPERVISOR_FD_KEYS = frozenset({"gate_read", "gate_write", "status_read", "status_write"})
_SESSION_CLEANUP_KEYS = frozenset(
    {"cleanup_id", "staging_root_id", "reuse_forbidden", "require_cgroup_empty", "quarantine_on_failure"}
)
_ROOTFS_TOP_LEVEL = frozenset({"inputs", "proc", "run", "usr", "workspace"})
_WORKER_TOOL_PATH = "/usr/lib/harness/worker-tool"
_BROKER_MOUNT = "/run/harness"

_RESOLVE_NO_XDEV = 0x01
_RESOLVE_NO_MAGICLINKS = 0x02
_RESOLVE_NO_SYMLINKS = 0x04
_RESOLVE_BENEATH = 0x08
_OPENAT2_RESOLVE = _RESOLVE_NO_XDEV | _RESOLVE_NO_MAGICLINKS | _RESOLVE_NO_SYMLINKS | _RESOLVE_BENEATH


class L0Outcome(str, Enum):
    COMPILED_DRAFT = "COMPILED_DRAFT"
    READY = "READY"
    RESOLVED = "RESOLVED"
    ACCEPTED = "ACCEPTED"
    STAGED = "STAGED"
    QUARANTINED = "QUARANTINED"
    VERIFIED = "VERIFIED"
    PREPARED = "PREPARED"
    STOPPED = "STOPPED"
    STOP = "STOP"
    ABSENT = "ABSENT"


class L0Reason(str, Enum):
    PROFILE_COMPILED = "PROFILE_COMPILED"
    HOST_VERIFIED = "HOST_VERIFIED"
    MISSING_INPUT = "MISSING_INPUT"
    UNKNOWN_INPUT = "UNKNOWN_INPUT"
    MALFORMED_INPUT = "MALFORMED_INPUT"
    UNBOUNDED_INPUT = "UNBOUNDED_INPUT"
    MISMATCHED_PROFILE = "MISMATCHED_PROFILE"
    UNSUPPORTED_CONTROL = "UNSUPPORTED_CONTROL"
    RUNTIME_ABSENT = "RUNTIME_ABSENT"
    RUNTIME_MISMATCH = "RUNTIME_MISMATCH"
    HOST_UNSUPPORTED = "HOST_UNSUPPORTED"
    USER_NAMESPACE_ABSENT = "USER_NAMESPACE_ABSENT"
    CGROUP_V2_ABSENT = "CGROUP_V2_ABSENT"
    CGROUP_DELEGATION_ABSENT = "CGROUP_DELEGATION_ABSENT"
    LSM_ABSENT = "LSM_ABSENT"
    LSM_POLICY_ABSENT = "LSM_POLICY_ABSENT"
    OPENAT2_ABSENT = "OPENAT2_ABSENT"
    PATH_RESOLVED = "PATH_RESOLVED"
    PATH_DENIED = "PATH_DENIED"
    ROOT_MISMATCH = "ROOT_MISMATCH"
    MOUNT_MISMATCH = "MOUNT_MISMATCH"
    EPOCH_MISMATCH = "EPOCH_MISMATCH"
    OBJECT_MISMATCH = "OBJECT_MISMATCH"
    HARDLINK_DENIED = "HARDLINK_DENIED"
    BROKER_MESSAGE_ACCEPTED = "BROKER_MESSAGE_ACCEPTED"
    BROKER_BINDING_MISMATCH = "BROKER_BINDING_MISMATCH"
    PEER_MISMATCH = "PEER_MISMATCH"
    MESSAGE_TOO_LARGE = "MESSAGE_TOO_LARGE"
    CLAIM_REQUIRED = "CLAIM_REQUIRED"
    CLAIM_MISMATCH = "CLAIM_MISMATCH"
    MATERIAL_MISMATCH = "MATERIAL_MISMATCH"
    STAGE_LIMIT_EXCEEDED = "STAGE_LIMIT_EXCEEDED"
    STAGED = "STAGED"
    STAGE_OUTCOME_UNKNOWN = "STAGE_OUTCOME_UNKNOWN"
    SUPPLY_VERIFIED = "SUPPLY_VERIFIED"
    SUPPLY_VERIFIER_ABSENT = "SUPPLY_VERIFIER_ABSENT"
    SUPPLY_MISMATCH = "SUPPLY_MISMATCH"
    SUPPLY_STALE = "SUPPLY_STALE"
    SUPPLY_ROLLBACK = "SUPPLY_ROLLBACK"
    ARTIFACT_MISMATCH = "ARTIFACT_MISMATCH"
    PLACEMENT_MISMATCH = "PLACEMENT_MISMATCH"
    PLACEMENT_MEASURED = "PLACEMENT_MEASURED"
    SESSION_PREPARED = "SESSION_PREPARED"
    SESSION_MISMATCH = "SESSION_MISMATCH"
    SESSION_STOPPED = "SESSION_STOPPED"
    SESSION_TIMED_OUT = "SESSION_TIMED_OUT"
    DURABLE_PREPARE_FAILED = "DURABLE_PREPARE_FAILED"
    RUNTIME_FAILED = "RUNTIME_FAILED"
    CLEANUP_FAILED = "CLEANUP_FAILED"
    CONFORMANCE_ABSENT = "CONFORMANCE_ABSENT"
    HOST_FAILURE = "HOST_FAILURE"


@dataclass(frozen=True, slots=True)
class PrincipalPlan:
    role: str
    principal_id: str
    enabled: bool
    uid: int | None
    gid: int | None
    user_namespace: str | None
    mount_namespace: str | None
    pid_namespace: str | None
    ipc_namespace: str | None
    uts_namespace: str | None
    network_namespace: str | None
    cgroup_namespace: str | None
    security_label: str | None
    credential_namespace: str | None
    session_id: str | None
    network_mode: str
    credential_mode: str
    ambient_authority: bool
    effect_ceiling: tuple[str, ...]
    fd_allowlist: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ResourceLimit:
    resource: str
    unit: str
    limit: int
    enforcement: str


@dataclass(frozen=True, slots=True)
class CompiledL0Profile:
    profile_id: str
    profile_version: str
    workload_class: str
    environment: str
    backend_path: str
    backend_version: str
    backend_digest: str
    principals: tuple[PrincipalPlan, ...]
    resources: tuple[ResourceLimit, ...]
    broker_binding_digest: str
    resource_vector_digest: str
    canonical_profile_json: str
    profile_digest: str


@dataclass(frozen=True, slots=True)
class HostMeasurement:
    backend_path: str
    backend_version: str
    backend_digest: str
    architecture: str
    kernel_release: str
    kernel_features: tuple[str, ...]
    cgroup_path: str
    cgroup_controllers: tuple[str, ...]
    lsm_stack: tuple[str, ...]
    lsm_policy_name: str
    openat2: bool
    user_namespaces: bool
    measurement_digest: str


@dataclass(frozen=True, slots=True)
class L0Result:
    outcome: L0Outcome
    reason: L0Reason
    profile: CompiledL0Profile | None = None
    measurement: HostMeasurement | None = None

    @property
    def successful(self) -> bool:
        return self.outcome in {L0Outcome.COMPILED_DRAFT, L0Outcome.READY}


@dataclass(frozen=True, slots=True)
class PathBinding:
    canonical_path: str
    descriptor_id: str
    root_id: str
    root_identity: str
    mount_id: str
    mount_identity: str
    resolution_epoch: int
    final_device: int
    final_inode: int
    final_type: str
    final_digest: str
    composite_binding_digest: str

    def data(self) -> dict[str, object]:
        return {
            "canonical_path": self.canonical_path,
            "descriptor_id": self.descriptor_id,
            "root_id": self.root_id,
            "root_identity": self.root_identity,
            "mount_id": self.mount_id,
            "mount_identity": self.mount_identity,
            "resolution_epoch": self.resolution_epoch,
            "final_device": self.final_device,
            "final_inode": self.final_inode,
            "final_type": self.final_type,
            "final_digest": self.final_digest,
            "composite_binding_digest": self.composite_binding_digest,
        }


@dataclass(frozen=True, slots=True)
class PathResult:
    outcome: L0Outcome
    reason: L0Reason
    binding: PathBinding | None = None


@dataclass(frozen=True, slots=True)
class BrokerPeer:
    pid: int
    uid: int
    gid: int
    process_session: int


@dataclass(frozen=True, slots=True)
class BrokerMessage:
    operation_id: str
    worker_principal: str
    worker_session: str
    nonce: str
    fencing_epoch: int
    binding_digest: str
    proposal_json: str
    proposal_digest: str


@dataclass(frozen=True, slots=True)
class BrokerResult:
    outcome: L0Outcome
    reason: L0Reason
    peer: BrokerPeer | None = None
    message: BrokerMessage | None = None


@dataclass(frozen=True, slots=True)
class StageRecord:
    transaction_id: str
    claim_digest: str
    binding_digest: str
    before_digest: str
    after_digest: str
    bytes_written: int
    record_digest: str


@dataclass(frozen=True, slots=True)
class StageResult:
    outcome: L0Outcome
    reason: L0Reason
    record: StageRecord | None = None


@dataclass(frozen=True, slots=True)
class SupplyArtifactBinding:
    role: str
    artifact_id: str
    expected_bytes_digest: str
    actual_bytes_digest: str
    provenance_digest: str
    device: int
    inode: int
    size: int
    mode: int
    binding_digest: str

    def data(self) -> dict[str, object]:
        return {
            "role": self.role,
            "artifact_id": self.artifact_id,
            "expected_bytes_digest": self.expected_bytes_digest,
            "actual_bytes_digest": self.actual_bytes_digest,
            "provenance_digest": self.provenance_digest,
            "device": self.device,
            "inode": self.inode,
            "size": self.size,
            "mode": self.mode,
            "binding_digest": self.binding_digest,
        }


@dataclass(frozen=True, slots=True)
class SupplyVerification:
    supply_digest: str
    placement_digest: str
    profile_digest: str
    measurement_digest: str
    runtime_digest: str
    session_id: str
    subject_instance_id: str
    process_tree_id: str
    fencing_epoch: int
    revocation_epoch: int
    observed_at: str
    expires_at: str
    verifier_id: str
    artifacts: tuple[SupplyArtifactBinding, ...]
    payload_json: str
    verification_json: str


@dataclass(frozen=True, slots=True)
class SupplyResult:
    outcome: L0Outcome
    reason: L0Reason
    verification: SupplyVerification | None = None


@dataclass(frozen=True, slots=True)
class PlacementMeasurement:
    rootfs_binding_digest: str
    staging_binding_digest: str
    cgroup_binding_digest: str
    broker_binding_digest: str
    fd_inventory_digest: str
    namespace_plan_digest: str
    runtime_bindings_json: str
    runtime_bindings_digest: str


@dataclass(frozen=True, slots=True)
class PlacementResult:
    outcome: L0Outcome
    reason: L0Reason
    measurement: PlacementMeasurement | None = None


@dataclass(frozen=True, slots=True)
class SessionPlan:
    profile_digest: str
    measurement_digest: str
    supply_digest: str
    placement_digest: str
    session_record_id: str
    session_id: str
    transaction_id: str
    claim_digest: str
    lineage_root: str
    fencing_epoch: int
    revocation_epoch: int
    worker_principal: str
    executor_principal: str
    subject_instance_id: str
    namespace_ids: tuple[tuple[str, str], ...]
    read_only_mounts: tuple[tuple[int, str], ...]
    broker_root_mount: tuple[int, str]
    broker_socket_path: str
    seccomp_fd: int
    tool_fd: int
    gate_read_fd: int
    gate_write_fd: int
    status_read_fd: int
    status_write_fd: int
    pass_fds: tuple[int, ...]
    bwrap_argv: tuple[str, ...]
    environment: tuple[tuple[str, str], ...]
    cgroup_path: str
    cgroup_limits: tuple[tuple[str, str], ...]
    cpu_time_ms: int
    wall_time_ms: int
    rlimit_nofile: int
    quota: tuple[tuple[str, int | str], ...]
    cleanup_record_json: str
    runtime_bindings_json: str
    runtime_bindings_digest: str
    launch_digest: str


@dataclass(frozen=True, slots=True)
class SessionResult:
    outcome: L0Outcome
    reason: L0Reason
    plan: SessionPlan | None = None


@dataclass(frozen=True, slots=True)
class ConformanceResult:
    outcome: L0Outcome
    reason: L0Reason
    session: SessionPlan | None = None


@dataclass(frozen=True, slots=True)
class RuntimeSessionRecord:
    session_record_id: str
    transaction_id: str
    process_tree_id: str
    process_id: int | None
    state: str
    cgroup_path: str
    launch_digest: str
    status_digest: str | None
    cleanup_digest: str


@dataclass(frozen=True, slots=True)
class SupervisorResult:
    outcome: L0Outcome
    reason: L0Reason
    session: RuntimeSessionRecord | None = None


@dataclass(frozen=True, slots=True)
class _HostObservation:
    backend_path: str
    backend_version: str
    backend_digest: str
    backend_uid: int
    backend_gid: int
    backend_mode: int
    backend_options: tuple[str, ...]
    linux: bool
    architecture: str
    kernel_release: str
    kernel_features: tuple[str, ...]
    user_namespaces: bool
    cgroup_v2: bool
    cgroup_path: str
    host_cgroup_controllers: tuple[str, ...]
    cgroup_controllers: tuple[str, ...]
    cgroup_delegated: bool
    cgroup_isolated: bool
    lsm_stack: tuple[str, ...]
    apparmor_enabled: bool
    loaded_apparmor_profiles: tuple[str, ...]
    openat2: bool


class _Stop(Exception):
    def __init__(self, reason: L0Reason) -> None:
        super().__init__(reason.value)
        self.reason = reason


def _canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _hash_text(value: str) -> str:
    return "sha256:" + sha256(value.encode("utf-8")).hexdigest()


def _closed_dict(value: object, keys: frozenset[str]) -> dict[str, object]:
    if type(value) is not dict or any(type(key) is not str for key in value):
        raise _Stop(L0Reason.MALFORMED_INPUT)
    actual = frozenset(value)
    if keys - actual:
        raise _Stop(L0Reason.MISSING_INPUT)
    if actual - keys:
        raise _Stop(L0Reason.UNKNOWN_INPUT)
    return value


def _list(value: object, *, minimum: int = 0, maximum: int = 256) -> list[object]:
    if type(value) is not list:
        raise _Stop(L0Reason.MALFORMED_INPUT)
    if len(value) < minimum or len(value) > maximum:
        raise _Stop(L0Reason.UNBOUNDED_INPUT)
    return value


def _identifier(value: object) -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise _Stop(L0Reason.MALFORMED_INPUT)
    if any(unicodedata.category(character) in {"Cc", "Cf"} for character in value):
        raise _Stop(L0Reason.MALFORMED_INPUT)
    return value


def _digest(value: object) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise _Stop(L0Reason.MALFORMED_INPUT)
    return value


def _integer(value: object, *, minimum: int = 0, maximum: int = _MAX_INTEGER) -> int:
    if type(value) is not int:
        raise _Stop(L0Reason.MALFORMED_INPUT)
    if value < minimum or value > maximum:
        raise _Stop(L0Reason.UNBOUNDED_INPUT)
    return value


def _boolean(value: object) -> bool:
    if type(value) is not bool:
        raise _Stop(L0Reason.MALFORMED_INPUT)
    return value


def _time(value: object) -> datetime:
    if type(value) is not str or _UTC_TIME.fullmatch(value) is None:
        raise _Stop(L0Reason.MALFORMED_INPUT)
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as error:
        raise _Stop(L0Reason.MALFORMED_INPUT) from error


def _exact(value: object, expected: object) -> None:
    if type(value) is not type(expected):
        raise _Stop(L0Reason.MALFORMED_INPUT)
    if value != expected:
        raise _Stop(L0Reason.MISMATCHED_PROFILE)


def _enum(value: object, allowed: frozenset[str] | set[str]) -> str:
    if type(value) is not str:
        raise _Stop(L0Reason.MALFORMED_INPUT)
    if value not in allowed:
        raise _Stop(L0Reason.UNKNOWN_INPUT)
    return value


def _exact_string_set(value: object, expected: frozenset[str], *, allow_empty: bool = False) -> tuple[str, ...]:
    raw = _list(value, minimum=0 if allow_empty else 1, maximum=max(1, len(expected)))
    if any(type(item) is not str for item in raw):
        raise _Stop(L0Reason.MALFORMED_INPUT)
    if len(set(raw)) != len(raw):
        raise _Stop(L0Reason.MALFORMED_INPUT)
    if frozenset(raw) != expected:
        raise _Stop(L0Reason.MISMATCHED_PROFILE)
    return tuple(sorted(raw))


def _parse_principal(raw: object) -> PrincipalPlan:
    if type(raw) is not dict or type(raw.get("role")) is not str:
        raise _Stop(L0Reason.MALFORMED_INPUT)
    role = _enum(raw["role"], set(_ROLES))
    keys = _ACTIVE_PRINCIPAL_KEYS if role in _ACTIVE_ROLES else _DISABLED_PRINCIPAL_KEYS
    value = _closed_dict(raw, keys)
    principal_id = _identifier(value["principal_id"])
    enabled = _boolean(value["enabled"])
    _exact(value["ambient_authority"], False)
    _exact(value["network_mode"], _ROLE_NETWORK[role])
    _exact(value["credential_mode"], "NONE")
    effects = _exact_string_set(value["effect_ceiling"], _ROLE_EFFECTS[role], allow_empty=True)
    fds = _exact_string_set(value["fd_allowlist"], _ROLE_FDS[role], allow_empty=True)
    if role in _DISABLED_ROLES:
        _exact(enabled, False)
        return PrincipalPlan(
            role=role,
            principal_id=principal_id,
            enabled=False,
            uid=None,
            gid=None,
            user_namespace=None,
            mount_namespace=None,
            pid_namespace=None,
            ipc_namespace=None,
            uts_namespace=None,
            network_namespace=None,
            cgroup_namespace=None,
            security_label=None,
            credential_namespace=None,
            session_id=None,
            network_mode=_ROLE_NETWORK[role],
            credential_mode="NONE",
            ambient_authority=False,
            effect_ceiling=effects,
            fd_allowlist=fds,
        )
    _exact(enabled, True)
    return PrincipalPlan(
        role=role,
        principal_id=principal_id,
        enabled=True,
        uid=_integer(value["uid"], minimum=1),
        gid=_integer(value["gid"], minimum=1),
        user_namespace=_identifier(value["user_namespace"]),
        mount_namespace=_identifier(value["mount_namespace"]),
        pid_namespace=_identifier(value["pid_namespace"]),
        ipc_namespace=_identifier(value["ipc_namespace"]),
        uts_namespace=_identifier(value["uts_namespace"]),
        network_namespace=_identifier(value["network_namespace"]),
        cgroup_namespace=_identifier(value["cgroup_namespace"]),
        security_label=_identifier(value["security_label"]),
        credential_namespace=_identifier(value["credential_namespace"]),
        session_id=_identifier(value["session_id"]),
        network_mode=_ROLE_NETWORK[role],
        credential_mode="NONE",
        ambient_authority=False,
        effect_ceiling=effects,
        fd_allowlist=fds,
    )


def _principal_data(value: PrincipalPlan) -> dict[str, object]:
    data: dict[str, object] = {
        "role": value.role,
        "principal_id": value.principal_id,
        "enabled": value.enabled,
        "network_mode": value.network_mode,
        "credential_mode": value.credential_mode,
        "ambient_authority": value.ambient_authority,
        "effect_ceiling": list(value.effect_ceiling),
        "fd_allowlist": list(value.fd_allowlist),
    }
    if value.enabled:
        data.update(
            uid=value.uid,
            gid=value.gid,
            user_namespace=value.user_namespace,
            mount_namespace=value.mount_namespace,
            pid_namespace=value.pid_namespace,
            ipc_namespace=value.ipc_namespace,
            uts_namespace=value.uts_namespace,
            network_namespace=value.network_namespace,
            cgroup_namespace=value.cgroup_namespace,
            security_label=value.security_label,
            credential_namespace=value.credential_namespace,
            session_id=value.session_id,
        )
    return data


def _parse_principals(raw: object) -> tuple[PrincipalPlan, ...]:
    records = _list(raw, minimum=5, maximum=5)
    parsed = [_parse_principal(item) for item in records]
    by_role = {item.role: item for item in parsed}
    if len(by_role) != 5 or frozenset(by_role) != frozenset(_ROLES):
        raise _Stop(L0Reason.MISMATCHED_PROFILE)
    ordered = tuple(by_role[role] for role in _ROLES)
    if len({item.principal_id for item in ordered}) != 5:
        raise _Stop(L0Reason.MISMATCHED_PROFILE)
    active = tuple(item for item in ordered if item.enabled)
    for field in (
        "uid",
        "gid",
        "user_namespace",
        "mount_namespace",
        "pid_namespace",
        "ipc_namespace",
        "uts_namespace",
        "network_namespace",
        "cgroup_namespace",
        "security_label",
        "credential_namespace",
        "session_id",
    ):
        if len({getattr(item, field) for item in active}) != len(active):
            raise _Stop(L0Reason.MISMATCHED_PROFILE)
    return ordered


def _parse_worker_controls(raw: object) -> dict[str, object]:
    value = _closed_dict(raw, _WORKER_KEYS)
    namespaces = _exact_string_set(value["namespaces"], _NAMESPACES)
    path_resolution = _exact_string_set(value["path_resolution"], _OPENAT2_FLAGS)
    for key in (
        "non_host_uid_gid",
        "no_new_privileges",
        "close_fds",
        "wall_time_supervisor",
    ):
        _exact(_boolean(value[key]), True)
    for key in (
        "checkout_visible",
        "git_visible",
        "host_home_visible",
        "runtime_socket_visible",
        "durable_db_visible",
        "ptrace",
        "ebpf",
        "modules",
        "admin",
    ):
        _exact(_boolean(value[key]), False)
    _exact_string_set(value["capabilities"], frozenset(), allow_empty=True)
    _exact_string_set(value["devices"], frozenset(), allow_empty=True)
    _exact(value["seccomp"], "DENY_DEFAULT_ALLOWLIST")
    _exact(value["lsm"], "APPARMOR")
    _exact(value["mount_propagation"], "PRIVATE_NON_PROPAGATING")
    _exact(value["rootfs"], "MINIMAL_READ_ONLY")
    _exact(value["inputs"], "DECLARED_READ_ONLY")
    _exact(value["outputs"], "NO_WORKER_OUTPUT")
    _exact(_integer(value["staging_output_count"], minimum=1), 1)
    _exact(value["proc_mode"], "PRIVATE_RESTRICTED")
    _exact(value["shared_memory"], "PRIVATE_EMPTY")
    return {
        **value,
        "namespaces": list(namespaces),
        "path_resolution": list(path_resolution),
        "capabilities": [],
        "devices": [],
    }


def _parse_network(raw: object) -> dict[str, object]:
    value = _closed_dict(raw, _NETWORK_KEYS)
    for key in _NETWORK_KEYS - {"broker_ipc_only"}:
        _exact(_boolean(value[key]), False)
    _exact(_boolean(value["broker_ipc_only"]), True)
    return dict(value)


def _parse_broker(raw: object, principals: tuple[PrincipalPlan, ...]) -> tuple[dict[str, object], str]:
    value = _closed_dict(raw, _BROKER_KEYS)
    by_role = {item.role: item for item in principals}
    _exact(value["worker_principal"], by_role["AGENT_WORKER"].principal_id)
    _exact(value["broker_principal"], by_role["BROKER"].principal_id)
    if value["worker_principal"] == value["broker_principal"]:
        raise _Stop(L0Reason.MISMATCHED_PROFILE)
    worker_endpoint = _identifier(value["worker_endpoint"])
    broker_endpoint = _identifier(value["broker_endpoint"])
    if worker_endpoint == broker_endpoint:
        raise _Stop(L0Reason.MISMATCHED_PROFILE)
    _exact(value["transport"], "UNIX_SEQPACKET")
    _exact(value["peer_credentials"], "SO_PEERCRED_REQUIRED")
    _exact(_boolean(value["operation_scoped"]), True)
    _integer(value["max_message_bytes"], minimum=1, maximum=_MAX_MESSAGE_BYTES)
    _digest(value["message_schema_digest"])
    canonical = dict(value)
    canonical.update(
        worker_network_namespace=by_role["AGENT_WORKER"].network_namespace,
        broker_network_namespace=by_role["BROKER"].network_namespace,
    )
    return canonical, _hash_text(_canonical(canonical))


def _parse_resources(raw: object) -> tuple[tuple[ResourceLimit, ...], str]:
    rows = _list(raw, minimum=14, maximum=14)
    parsed: dict[str, ResourceLimit] = {}
    for item in rows:
        row = _closed_dict(item, _RESOURCE_KEYS)
        resource = _enum(row["resource"], set(_RESOURCE_SPEC))
        if resource in parsed:
            raise _Stop(L0Reason.MALFORMED_INPUT)
        unit, enforcement = _RESOURCE_SPEC[resource]
        _exact(row["unit"], unit)
        _exact(row["enforcement"], enforcement)
        minimum = 0 if resource in {"SWAP", "GPU_TIME", "GPU_MEMORY"} else 1
        limit = _integer(row["limit"], minimum=minimum)
        parsed[resource] = ResourceLimit(resource, unit, limit, enforcement)
    if frozenset(parsed) != frozenset(_RESOURCE_SPEC):
        raise _Stop(L0Reason.MISSING_INPUT)
    gpu_time = parsed["GPU_TIME"].limit
    gpu_memory = parsed["GPU_MEMORY"].limit
    if (gpu_time == 0) != (gpu_memory == 0):
        raise _Stop(L0Reason.MISMATCHED_PROFILE)
    if parsed["INODES"].limit < parsed["FILES"].limit:
        raise _Stop(L0Reason.MISMATCHED_PROFILE)
    if parsed["OPEN_FDS"].limit < 4 or parsed["PIDS"].limit < 2:
        raise _Stop(L0Reason.UNBOUNDED_INPUT)
    ordered = tuple(parsed[name] for name in _RESOURCE_ORDER)
    data = [
        {
            "resource": item.resource,
            "unit": item.unit,
            "limit": item.limit,
            "enforcement": item.enforcement,
        }
        for item in ordered
    ]
    return ordered, _hash_text(_canonical(data))


def _parse_measurements(raw: object, broker: dict[str, object]) -> dict[str, object]:
    value = _closed_dict(raw, _MEASUREMENT_KEYS)
    for key in _MEASUREMENT_KEYS - {"lsm_policy_name"}:
        _digest(value[key])
    policy_name = _identifier(value["lsm_policy_name"])
    if policy_name != "harness-l0-lx-a":
        raise _Stop(L0Reason.MISMATCHED_PROFILE)
    if value["broker_message_schema_digest"] != broker["message_schema_digest"]:
        raise _Stop(L0Reason.MISMATCHED_PROFILE)
    return dict(value)


def _compile(raw: object) -> CompiledL0Profile:
    value = _closed_dict(raw, _TOP_KEYS)
    _exact(value["profile_id"], PROFILE_ID)
    _exact(value["profile_version"], "1.0.0")
    _exact(value["status"], "DRAFT")
    _exact(value["workload_class"], WORKLOAD_CLASS)
    _exact(value["environment"], ENVIRONMENT)
    _exact(value["risk_class"], "LOCAL_STAGEABLE")
    _exact(value["data_class"], "SYNTHETIC")

    backend = _closed_dict(value["backend"], _BACKEND_KEYS)
    _exact(backend["path"], RUNTIME_PATH)
    _exact(backend["version"], RUNTIME_VERSION)
    _exact(backend["digest"], RUNTIME_DIGEST)

    principals = _parse_principals(value["principals"])
    worker_controls = _parse_worker_controls(value["worker_controls"])
    network = _parse_network(value["network"])
    broker, broker_digest = _parse_broker(value["broker_ipc"], principals)
    resources, resource_digest = _parse_resources(value["resources"])
    measurements = _parse_measurements(value["measurement_bindings"], broker)
    denied = _exact_string_set(value["denied_surfaces"], _DENIED_SURFACES)

    canonical_data = {
        "profile_id": PROFILE_ID,
        "profile_version": value["profile_version"],
        "status": "DRAFT",
        "workload_class": WORKLOAD_CLASS,
        "environment": ENVIRONMENT,
        "risk_class": "LOCAL_STAGEABLE",
        "data_class": "SYNTHETIC",
        "backend": dict(backend),
        "principals": [_principal_data(item) for item in principals],
        "worker_controls": worker_controls,
        "network": network,
        "broker_ipc": {**broker, "binding_digest": broker_digest},
        "resources": [
            {
                "resource": item.resource,
                "unit": item.unit,
                "limit": item.limit,
                "enforcement": item.enforcement,
            }
            for item in resources
        ],
        "resource_vector_digest": resource_digest,
        "measurement_bindings": measurements,
        "denied_surfaces": list(denied),
        "claim": "DRAFT_MEASUREMENT_PLAN_ONLY",
    }
    canonical_json = _canonical(canonical_data)
    return CompiledL0Profile(
        PROFILE_ID,
        value["profile_version"],
        WORKLOAD_CLASS,
        ENVIRONMENT,
        RUNTIME_PATH,
        RUNTIME_VERSION,
        RUNTIME_DIGEST,
        principals,
        resources,
        broker_digest,
        resource_digest,
        canonical_json,
        _hash_text(canonical_json),
    )


def compile_profile(raw: object) -> L0Result:
    """Compile one exact draft profile without performing external effects."""

    try:
        profile = _compile(raw)
        return L0Result(L0Outcome.COMPILED_DRAFT, L0Reason.PROFILE_COMPILED, profile=profile)
    except _Stop as stop:
        return L0Result(L0Outcome.STOP, stop.reason)
    except Exception:  # noqa: BLE001 - the public trust boundary is total
        return L0Result(L0Outcome.STOP, L0Reason.MALFORMED_INPUT)


def _profile_is_valid(profile: object) -> bool:
    if type(profile) is not CompiledL0Profile:
        return False
    if (
        profile.profile_id != PROFILE_ID
        or profile.profile_version != "1.0.0"
        or profile.workload_class != WORKLOAD_CLASS
        or profile.environment != ENVIRONMENT
        or profile.backend_path != RUNTIME_PATH
        or profile.backend_version != RUNTIME_VERSION
        or profile.backend_digest != RUNTIME_DIGEST
        or _hash_text(profile.canonical_profile_json) != profile.profile_digest
    ):
        return False
    if tuple(item.resource for item in profile.resources) != _RESOURCE_ORDER:
        return False
    vector = [
        {
            "resource": item.resource,
            "unit": item.unit,
            "limit": item.limit,
            "enforcement": item.enforcement,
        }
        for item in profile.resources
    ]
    return _hash_text(_canonical(vector)) == profile.resource_vector_digest


def _resource_limit(profile: CompiledL0Profile, name: str) -> int:
    for item in profile.resources:
        if item.resource == name:
            return item.limit
    raise _Stop(L0Reason.MISMATCHED_PROFILE)


def _canonical_stage_path(value: object) -> tuple[str, str]:
    if (
        type(value) is not str
        or unicodedata.normalize("NFC", value) != value
        or not value.startswith("/staging/")
        or len(value) > 2048
    ):
        raise _Stop(L0Reason.PATH_DENIED)
    if "//" in value or "\\" in value or "%" in value:
        raise _Stop(L0Reason.PATH_DENIED)
    if any(
        unicodedata.category(character) in {"Cc", "Cf"}
        or character in {"\u2044", "\u2215", "\uff0f", "\uff3c"}
        for character in value
    ):
        raise _Stop(L0Reason.PATH_DENIED)
    components = value.split("/")[2:]
    if (
        not components
        or any(component in {"", ".", "..", ".git"} for component in components)
        or components[0] == "proc"
        or any(_IDENTIFIER.fullmatch(component) is None for component in components)
    ):
        raise _Stop(L0Reason.PATH_DENIED)
    return value, "/".join(components)


def _mount_id(descriptor: int) -> int:
    text = _read_text(f"/proc/self/fdinfo/{descriptor}", 8192)
    matches = [line.split(":", 1)[1].strip() for line in text.splitlines() if line.startswith("mnt_id:")]
    if len(matches) != 1 or not matches[0].isdigit():
        raise _Stop(L0Reason.MOUNT_MISMATCH)
    return _integer(int(matches[0]), minimum=1)


def _openat2(descriptor: int, relative: str, flags: int) -> int:
    class OpenHow(ctypes.Structure):
        _fields_ = [("flags", ctypes.c_uint64), ("mode", ctypes.c_uint64), ("resolve", ctypes.c_uint64)]

    libc = ctypes.CDLL(None, use_errno=True)
    syscall = libc.syscall
    syscall.restype = ctypes.c_long
    how = OpenHow(flags, 0, _OPENAT2_RESOLVE)
    result = syscall(
        437,
        descriptor,
        ctypes.c_char_p(relative.encode("utf-8")),
        ctypes.byref(how),
        ctypes.sizeof(how),
    )
    if result < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), relative)
    return int(result)


def _hash_descriptor(descriptor: int, maximum: int) -> str:
    info = os.fstat(descriptor)
    if info.st_size < 0 or info.st_size > maximum:
        raise _Stop(L0Reason.STAGE_LIMIT_EXCEEDED)
    digest = sha256()
    offset = 0
    while offset < info.st_size:
        chunk = os.pread(descriptor, min(65536, info.st_size - offset), offset)
        if not chunk:
            raise _Stop(L0Reason.OBJECT_MISMATCH)
        digest.update(chunk)
        offset += len(chunk)
    return "sha256:" + digest.hexdigest()


def _root_identity(descriptor: int) -> tuple[os.stat_result, int, str, str]:
    info = os.fstat(descriptor)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise _Stop(L0Reason.ROOT_MISMATCH)
    mount = _mount_id(descriptor)
    data = {
        "device": info.st_dev,
        "inode": info.st_ino,
        "mode": stat.S_IFMT(info.st_mode),
        "mount_id": mount,
        "uid": info.st_uid,
        "gid": info.st_gid,
    }
    identity = _hash_text(_canonical(data))
    mount_identity = _hash_text(_canonical({"mount_id": mount, "device": info.st_dev}))
    return info, mount, identity, mount_identity


def _binding_for_open_target(
    profile: CompiledL0Profile,
    root_descriptor: int,
    target_descriptor: int,
    canonical_path: str,
    descriptor_id: str,
    root_id: str,
    resolution_epoch: int,
) -> PathBinding:
    root_info, root_mount, root_identity, mount_identity = _root_identity(root_descriptor)
    target_info = os.fstat(target_descriptor)
    target_mount = _mount_id(target_descriptor)
    if target_mount != root_mount or target_info.st_dev != root_info.st_dev:
        raise _Stop(L0Reason.MOUNT_MISMATCH)
    if not stat.S_ISREG(target_info.st_mode):
        raise _Stop(L0Reason.OBJECT_MISMATCH)
    if target_info.st_nlink != 1:
        raise _Stop(L0Reason.HARDLINK_DENIED)
    digest = _hash_descriptor(target_descriptor, _resource_limit(profile, "OUTPUT_BYTES"))
    data = {
        "canonical_path": canonical_path,
        "descriptor_id": descriptor_id,
        "root_id": root_id,
        "root_identity": root_identity,
        "mount_id": f"mnt:{root_mount}",
        "mount_identity": mount_identity,
        "resolution_epoch": resolution_epoch,
        "final_device": target_info.st_dev,
        "final_inode": target_info.st_ino,
        "final_type": "REGULAR_FILE",
        "final_digest": digest,
    }
    return PathBinding(**data, composite_binding_digest=_hash_text(_canonical(data)))


def _parse_path_request(raw: object) -> tuple[str, str, str, int, str]:
    value = _closed_dict(raw, _PATH_REQUEST_KEYS)
    canonical_path, relative = _canonical_stage_path(value["canonical_path"])
    return (
        canonical_path,
        _identifier(value["descriptor_id"]),
        _identifier(value["root_id"]),
        _integer(value["resolution_epoch"], minimum=1),
        relative,
    )


def resolve_target(profile: object, root_descriptor: object, raw: object) -> PathResult:
    """Resolve and bind one existing staging file through an open trusted root."""

    duplicate = -1
    target = -1
    try:
        if not _profile_is_valid(profile):
            raise _Stop(L0Reason.MISMATCHED_PROFILE)
        if type(root_descriptor) is not int or root_descriptor < 0:
            raise _Stop(L0Reason.MALFORMED_INPUT)
        canonical_path, descriptor_id, root_id, epoch, relative = _parse_path_request(raw)
        duplicate = fcntl.fcntl(root_descriptor, fcntl.F_DUPFD_CLOEXEC, 3)
        _root_identity(duplicate)
        target = _openat2(duplicate, relative, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        binding = _binding_for_open_target(
            profile,
            duplicate,
            target,
            canonical_path,
            descriptor_id,
            root_id,
            epoch,
        )
        return PathResult(L0Outcome.RESOLVED, L0Reason.PATH_RESOLVED, binding)
    except _Stop as stop:
        return PathResult(L0Outcome.STOP, stop.reason)
    except OSError:
        return PathResult(L0Outcome.STOP, L0Reason.PATH_DENIED)
    except Exception:  # noqa: BLE001 - descriptor boundary is total
        return PathResult(L0Outcome.STOP, L0Reason.HOST_FAILURE)
    finally:
        if target >= 0:
            os.close(target)
        if duplicate >= 0:
            os.close(duplicate)


def _parse_path_binding(raw: object) -> PathBinding:
    value = _closed_dict(raw, _PATH_BINDING_KEYS)
    canonical_path, _ = _canonical_stage_path(value["canonical_path"])
    binding = PathBinding(
        canonical_path=canonical_path,
        descriptor_id=_identifier(value["descriptor_id"]),
        root_id=_identifier(value["root_id"]),
        root_identity=_digest(value["root_identity"]),
        mount_id=_identifier(value["mount_id"]),
        mount_identity=_digest(value["mount_identity"]),
        resolution_epoch=_integer(value["resolution_epoch"], minimum=1),
        final_device=_integer(value["final_device"]),
        final_inode=_integer(value["final_inode"], minimum=1),
        final_type=_enum(value["final_type"], {"REGULAR_FILE"}),
        final_digest=_digest(value["final_digest"]),
        composite_binding_digest=_digest(value["composite_binding_digest"]),
    )
    data = binding.data()
    supplied = data.pop("composite_binding_digest")
    if _hash_text(_canonical(data)) != supplied:
        raise _Stop(L0Reason.OBJECT_MISMATCH)
    return binding


def _active_principal(profile: CompiledL0Profile, role: str) -> PrincipalPlan:
    for principal in profile.principals:
        if principal.role == role and principal.enabled:
            return principal
    raise _Stop(L0Reason.MISMATCHED_PROFILE)


def _parse_peer(raw: object) -> BrokerPeer:
    value = _closed_dict(raw, _PEER_KEYS)
    return BrokerPeer(
        pid=_integer(value["pid"], minimum=1),
        uid=_integer(value["uid"]),
        gid=_integer(value["gid"]),
        process_session=_integer(value["process_session"], minimum=1),
    )


def _parse_broker_expected(
    profile: CompiledL0Profile, raw: object
) -> tuple[str, str, str, str, int, str, BrokerPeer]:
    value = _closed_dict(raw, _BROKER_EXPECTED_KEYS)
    worker = _active_principal(profile, "AGENT_WORKER")
    operation_id = _identifier(value["operation_id"])
    worker_principal = _identifier(value["worker_principal"])
    worker_session = _identifier(value["worker_session"])
    nonce = _identifier(value["nonce"])
    fencing_epoch = _integer(value["fencing_epoch"], minimum=1)
    binding_digest = _digest(value["binding_digest"])
    if (
        worker_principal != worker.principal_id
        or worker_session != worker.session_id
        or binding_digest != profile.broker_binding_digest
    ):
        raise _Stop(L0Reason.BROKER_BINDING_MISMATCH)
    return operation_id, worker_principal, worker_session, nonce, fencing_epoch, binding_digest, _parse_peer(
        value["peer"]
    )


def _decode_broker_message(
    profile: CompiledL0Profile,
    packet: bytes,
    expected: tuple[str, str, str, str, int, str, BrokerPeer],
) -> BrokerMessage:
    try:
        raw = json.loads(packet)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise _Stop(L0Reason.MALFORMED_INPUT) from error
    value = _closed_dict(raw, _BROKER_MESSAGE_KEYS)
    _exact(value["message_version"], "1")
    operation_id = _identifier(value["operation_id"])
    worker_principal = _identifier(value["worker_principal"])
    worker_session = _identifier(value["worker_session"])
    nonce = _identifier(value["nonce"])
    fencing_epoch = _integer(value["fencing_epoch"], minimum=1)
    binding_digest = _digest(value["binding_digest"])
    proposal_digest = _digest(value["proposal_digest"])
    expected_operation, expected_principal, expected_session, expected_nonce, expected_fence, expected_binding, _ = (
        expected
    )
    if (
        operation_id != expected_operation
        or worker_principal != expected_principal
        or worker_session != expected_session
        or nonce != expected_nonce
        or fencing_epoch != expected_fence
        or binding_digest != expected_binding
        or binding_digest != profile.broker_binding_digest
    ):
        raise _Stop(L0Reason.BROKER_BINDING_MISMATCH)
    proposal = _closed_dict(value["proposal"], _M1_REQUEST_KEYS)
    proposal_header = _closed_dict(proposal["proposal"], _M1_PROPOSAL_KEYS)
    if proposal_header["operation_id"] != operation_id or proposal_header["principal_id"] != worker_principal:
        raise _Stop(L0Reason.BROKER_BINDING_MISMATCH)
    proposal_json = _canonical(proposal)
    if _hash_text(proposal_json) != proposal_digest:
        raise _Stop(L0Reason.BROKER_BINDING_MISMATCH)
    return BrokerMessage(
        operation_id,
        worker_principal,
        worker_session,
        nonce,
        fencing_epoch,
        binding_digest,
        proposal_json,
        proposal_digest,
    )


def receive_broker_message(
    profile: object,
    connection_descriptor: object,
    raw_expected: object,
) -> BrokerResult:
    """Receive one bounded exact UNIX_SEQPACKET message and verify its peer."""

    duplicate = -1
    connection: socket.socket | None = None
    try:
        if not _profile_is_valid(profile):
            raise _Stop(L0Reason.MISMATCHED_PROFILE)
        if type(connection_descriptor) is not int or connection_descriptor < 0:
            raise _Stop(L0Reason.MALFORMED_INPUT)
        expected = _parse_broker_expected(profile, raw_expected)
        duplicate = fcntl.fcntl(connection_descriptor, fcntl.F_DUPFD_CLOEXEC, 3)
        connection = socket.socket(fileno=duplicate)
        duplicate = -1
        if connection.family != socket.AF_UNIX or connection.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_SEQPACKET:
            raise _Stop(L0Reason.BROKER_BINDING_MISMATCH)
        credentials = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        pid, uid, gid = struct.unpack("3i", credentials)
        observed_peer = BrokerPeer(pid, uid, gid, os.getsid(pid))
        if observed_peer != expected[-1]:
            raise _Stop(L0Reason.PEER_MISMATCH)
        maximum = _integer(json.loads(profile.canonical_profile_json)["broker_ipc"]["max_message_bytes"], minimum=1)
        packet, ancillary, flags, _ = connection.recvmsg(maximum + 1, 1)
        if ancillary or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or len(packet) > maximum:
            raise _Stop(L0Reason.MESSAGE_TOO_LARGE)
        message = _decode_broker_message(profile, packet, expected)
        return BrokerResult(L0Outcome.ACCEPTED, L0Reason.BROKER_MESSAGE_ACCEPTED, observed_peer, message)
    except _Stop as stop:
        return BrokerResult(L0Outcome.STOP, stop.reason)
    except (OSError, ValueError, TypeError):
        return BrokerResult(L0Outcome.STOP, L0Reason.BROKER_BINDING_MISMATCH)
    except Exception:  # noqa: BLE001 - IPC boundary is total
        return BrokerResult(L0Outcome.STOP, L0Reason.HOST_FAILURE)
    finally:
        if connection is not None:
            connection.close()
        elif duplicate >= 0:
            os.close(duplicate)


def _measurement_is_valid(profile: CompiledL0Profile, measurement: object) -> bool:
    if type(measurement) is not HostMeasurement:
        return False
    data = {
        "backend_path": measurement.backend_path,
        "backend_version": measurement.backend_version,
        "backend_digest": measurement.backend_digest,
        "architecture": measurement.architecture,
        "kernel_release": measurement.kernel_release,
        "kernel_features": list(measurement.kernel_features),
        "cgroup_path": measurement.cgroup_path,
        "cgroup_controllers": list(measurement.cgroup_controllers),
        "lsm_stack": list(measurement.lsm_stack),
        "lsm_policy_name": measurement.lsm_policy_name,
        "openat2": measurement.openat2,
        "user_namespaces": measurement.user_namespaces,
        "profile_digest": profile.profile_digest,
    }
    return (
        measurement.backend_path == profile.backend_path
        and measurement.backend_version == profile.backend_version
        and measurement.backend_digest == profile.backend_digest
        and measurement.architecture == "x86_64"
        and frozenset(measurement.kernel_features) == _KERNEL_FEATURES
        and measurement.openat2 is True
        and measurement.user_namespaces is True
        and _hash_text(_canonical(data)) == measurement.measurement_digest
    )


def _measure_supply_artifact(raw: object) -> SupplyArtifactBinding:
    value = _closed_dict(raw, _SUPPLY_ARTIFACT_KEYS)
    role = _enum(value["role"], set(_SUPPLY_ROLES))
    artifact_id = _identifier(value["artifact_id"])
    descriptor = value["descriptor"]
    expected = _digest(value["expected_bytes_digest"])
    provenance = _digest(value["provenance_digest"])
    if type(descriptor) is not int or descriptor < 0:
        raise _Stop(L0Reason.MALFORMED_INPUT)
    try:
        if not fcntl.fcntl(descriptor, fcntl.F_GETFD) & fcntl.FD_CLOEXEC:
            raise _Stop(L0Reason.ARTIFACT_MISMATCH)
        duplicate = fcntl.fcntl(descriptor, fcntl.F_DUPFD_CLOEXEC, 3)
    except OSError as error:
        raise _Stop(L0Reason.ARTIFACT_MISMATCH) from error
    try:
        info = os.fstat(duplicate)
        mode = stat.S_IMODE(info.st_mode)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or mode & 0o022
            or info.st_size < 0
            or info.st_size > _MAX_SUPPLY_ARTIFACT_BYTES
        ):
            raise _Stop(L0Reason.ARTIFACT_MISMATCH)
        actual = _hash_descriptor(duplicate, _MAX_SUPPLY_ARTIFACT_BYTES)
        if actual != expected:
            raise _Stop(L0Reason.ARTIFACT_MISMATCH)
        data = {
            "role": role,
            "artifact_id": artifact_id,
            "expected_bytes_digest": expected,
            "actual_bytes_digest": actual,
            "provenance_digest": provenance,
            "device": info.st_dev,
            "inode": info.st_ino,
            "size": info.st_size,
            "mode": mode,
        }
        return SupplyArtifactBinding(**data, binding_digest=_hash_text(_canonical(data)))
    finally:
        os.close(duplicate)


def _supply_verifier_accepts(
    verifier: object,
    payload_text: str,
    verification_text: str,
    source: dict[str, object],
    payload_digest: str,
    verification_digest: str,
    observed_at: str,
) -> bool:
    try:
        result = verifier.verify(
            payload_text.encode("utf-8"),
            verification_text.encode("utf-8"),
            observed_at,
        )
        return (
            type(result) is VerificationResult
            and result.status is VerificationStatus.VERIFIED
            and result.verifier_id == source["verifier_id"]
            and result.payload_digest == payload_digest
            and result.record_digest == verification_digest
        )
    except Exception:
        return False


def verify_supply(
    profile: object,
    measurement: object,
    raw: object,
    *,
    verifier: object | None = None,
) -> SupplyResult:
    """Measure exact opened supply bytes and verify their placement externally."""

    try:
        if not _profile_is_valid(profile) or not _measurement_is_valid(profile, measurement):
            raise _Stop(L0Reason.PLACEMENT_MISMATCH)
        value = _closed_dict(raw, _SUPPLY_KEYS)
        _exact(value["supply_version"], "1.0.0")
        observed_at = _time(value["observed_at"])
        if _digest(value["profile_digest"]) != profile.profile_digest:
            raise _Stop(L0Reason.PLACEMENT_MISMATCH)
        if _digest(value["measurement_digest"]) != measurement.measurement_digest:
            raise _Stop(L0Reason.PLACEMENT_MISMATCH)
        runtime = _closed_dict(value["runtime"], _SUPPLY_RUNTIME_KEYS)
        _exact(runtime["path"], profile.backend_path)
        _exact(runtime["version"], profile.backend_version)
        if (
            _digest(runtime["digest"]) != profile.backend_digest
            or _binary_digest(profile.backend_path) != profile.backend_digest
            or _runtime_output("--version") != profile.backend_version
        ):
            raise _Stop(L0Reason.SUPPLY_MISMATCH)
        image = _closed_dict(value["image"], _SUPPLY_IMAGE_KEYS)
        _identifier(image["image_id"])
        _digest(image["rootfs_manifest_digest"])
        _exact(image["platform"], "linux")
        _exact(image["architecture"], measurement.architecture)
        registry = _closed_dict(value["registry"], _SUPPLY_REGISTRY_KEYS)
        _digest(registry["snapshot_digest"])
        _identifier(registry["reference"])
        generation = _integer(registry["generation"])
        rollback_floor = _integer(registry["rollback_floor"])
        registry_issued = _time(registry["issued_at"])
        registry_expires = _time(registry["expires_at"])
        signer = _closed_dict(value["signer"], _SUPPLY_SIGNER_KEYS)
        for field in ("trust_root_id", "signer_id", "key_id"):
            _identifier(signer[field])
        _exact(signer["algorithm"], "ED25519")
        signer_revocation = _integer(signer["revocation_epoch"])
        signer_floor = _integer(signer["rollback_floor"])
        if generation < rollback_floor or rollback_floor < signer_floor:
            raise _Stop(L0Reason.SUPPLY_ROLLBACK)
        placement = _closed_dict(value["placement"], _SUPPLY_PLACEMENT_KEYS)
        for field in ("placement_id", "host_id", "subject_instance_id", "process_tree_id", "session_id", "nonce"):
            _identifier(placement[field])
        for field in (
            "rootfs_binding_digest",
            "staging_binding_digest",
            "cgroup_binding_digest",
            "broker_binding_digest",
            "fd_inventory_digest",
            "namespace_plan_digest",
        ):
            _digest(placement[field])
        fencing_epoch = _integer(placement["fencing_epoch"], minimum=1)
        revocation_epoch = _integer(placement["revocation_epoch"])
        placement_issued = _time(placement["issued_at"])
        placement_expires = _time(placement["expires_at"])
        worker = _active_principal(profile, "AGENT_WORKER")
        if placement["session_id"] != worker.session_id or revocation_epoch != signer_revocation:
            raise _Stop(L0Reason.PLACEMENT_MISMATCH)
        if not (
            registry_issued <= observed_at < registry_expires
            and placement_issued <= observed_at < placement_expires
        ):
            raise _Stop(L0Reason.SUPPLY_STALE)
        artifact_rows = _list(value["artifacts"], minimum=len(_SUPPLY_ROLES), maximum=len(_SUPPLY_ROLES))
        artifacts = tuple(sorted((_measure_supply_artifact(row) for row in artifact_rows), key=lambda item: item.role))
        if tuple(item.role for item in artifacts) != tuple(sorted(_SUPPLY_ROLES)):
            raise _Stop(L0Reason.SUPPLY_MISMATCH)
        if len({item.artifact_id for item in artifacts}) != len(artifacts):
            raise _Stop(L0Reason.SUPPLY_MISMATCH)
        if len({(item.device, item.inode) for item in artifacts}) != len(artifacts):
            raise _Stop(L0Reason.ARTIFACT_MISMATCH)
        by_role = {item.role: item for item in artifacts}
        profile_source = json.loads(profile.canonical_profile_json)
        bindings = profile_source["measurement_bindings"]
        if (
            image["rootfs_manifest_digest"] != by_role["ROOTFS_MANIFEST"].actual_bytes_digest
            or bindings["rootfs_manifest_digest"] != by_role["ROOTFS_MANIFEST"].actual_bytes_digest
            or registry["snapshot_digest"] != by_role["REGISTRY_SNAPSHOT"].actual_bytes_digest
            or bindings["seccomp_profile_digest"] != by_role["SECCOMP_PROFILE"].actual_bytes_digest
            or bindings["lsm_policy_digest"] != by_role["LSM_POLICY"].actual_bytes_digest
        ):
            raise _Stop(L0Reason.SUPPLY_MISMATCH)
        verification_source = _closed_dict(value["verification"], _SUPPLY_VERIFICATION_SOURCE_KEYS)
        for field in ("verifier_id", "issuer_id", "key_id"):
            _identifier(verification_source[field])
        proof = verification_source["proof"]
        if (
            type(proof) is not str
            or not proof
            or len(proof) > 8192
            or any(unicodedata.category(character) in {"Cc", "Cf"} for character in proof)
        ):
            raise _Stop(L0Reason.MALFORMED_INPUT)
        if verifier is None:
            raise _Stop(L0Reason.SUPPLY_VERIFIER_ABSENT)
        runtime_data = {key: runtime[key] for key in sorted(runtime)}
        image_data = {key: image[key] for key in sorted(image)}
        registry_data = {key: registry[key] for key in sorted(registry)}
        signer_data = {key: signer[key] for key in sorted(signer)}
        placement_data = {
            **{key: placement[key] for key in sorted(placement)},
            "profile_digest": profile.profile_digest,
            "measurement_digest": measurement.measurement_digest,
            "runtime_digest": profile.backend_digest,
        }
        placement_digest = _hash_text(_canonical(placement_data))
        payload = {
            "supply_version": "1.0.0",
            "observed_at": value["observed_at"],
            "profile_digest": profile.profile_digest,
            "measurement_digest": measurement.measurement_digest,
            "runtime": runtime_data,
            "image": image_data,
            "registry": registry_data,
            "signer": signer_data,
            "placement": placement_data,
            "placement_digest": placement_digest,
            "artifacts": [item.data() for item in artifacts],
        }
        payload_text = _canonical(payload)
        supply_digest = _hash_text(payload_text)
        verification = {
            "verification_version": 1,
            "verifier_id": verification_source["verifier_id"],
            "issuer_id": verification_source["issuer_id"],
            "key_id": verification_source["key_id"],
            "payload_digest": supply_digest,
            "bindings": payload,
            "proof": proof,
        }
        verification_text = _canonical(verification)
        verification_digest = _hash_text(verification_text)
        if not _supply_verifier_accepts(
            verifier,
            payload_text,
            verification_text,
            verification_source,
            supply_digest,
            verification_digest,
            value["observed_at"],
        ):
            raise _Stop(L0Reason.SUPPLY_MISMATCH)
        verified = SupplyVerification(
            supply_digest=supply_digest,
            placement_digest=placement_digest,
            profile_digest=profile.profile_digest,
            measurement_digest=measurement.measurement_digest,
            runtime_digest=profile.backend_digest,
            session_id=placement["session_id"],
            subject_instance_id=placement["subject_instance_id"],
            process_tree_id=placement["process_tree_id"],
            fencing_epoch=fencing_epoch,
            revocation_epoch=revocation_epoch,
            observed_at=value["observed_at"],
            expires_at=placement["expires_at"],
            verifier_id=verification_source["verifier_id"],
            artifacts=artifacts,
            payload_json=payload_text,
            verification_json=verification_text,
        )
        return SupplyResult(L0Outcome.VERIFIED, L0Reason.SUPPLY_VERIFIED, verified)
    except _Stop as stop:
        return SupplyResult(L0Outcome.STOP, stop.reason)
    except (OSError, ValueError, TypeError):
        return SupplyResult(L0Outcome.STOP, L0Reason.SUPPLY_MISMATCH)
    except Exception:  # noqa: BLE001 - external verifier and hostile values are total
        return SupplyResult(L0Outcome.STOP, L0Reason.HOST_FAILURE)


def _verified_supply(
    profile: CompiledL0Profile,
    measurement: HostMeasurement | None,
    supply: object,
    verifier: object,
    observed_at: str,
) -> SupplyVerification:
    """Recheck a frozen supply record; the dataclass itself conveys no trust."""

    if type(supply) is not SupplyVerification:
        raise _Stop(L0Reason.SUPPLY_MISMATCH)
    try:
        payload = _closed_dict(json.loads(supply.payload_json), _SUPPLY_PAYLOAD_KEYS)
        verification = _closed_dict(json.loads(supply.verification_json), _VERIFICATION_KEYS)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise _Stop(L0Reason.SUPPLY_MISMATCH) from error
    if _canonical(payload) != supply.payload_json or _canonical(verification) != supply.verification_json:
        raise _Stop(L0Reason.SUPPLY_MISMATCH)
    _exact(payload["supply_version"], "1.0.0")
    payload_observed = _time(payload["observed_at"])
    requested_observed = _time(observed_at)
    runtime = _closed_dict(payload["runtime"], _SUPPLY_RUNTIME_KEYS)
    _closed_dict(payload["image"], _SUPPLY_IMAGE_KEYS)
    _closed_dict(payload["registry"], _SUPPLY_REGISTRY_KEYS)
    _closed_dict(payload["signer"], _SUPPLY_SIGNER_KEYS)
    placement = _closed_dict(payload["placement"], _SUPPLY_PLACEMENT_PAYLOAD_KEYS)
    artifacts_raw = _list(payload["artifacts"], minimum=len(_SUPPLY_ROLES), maximum=len(_SUPPLY_ROLES))
    artifacts: list[dict[str, object]] = []
    for raw_artifact in artifacts_raw:
        artifact = _closed_dict(raw_artifact, _SUPPLY_ARTIFACT_BINDING_KEYS)
        _enum(artifact["role"], set(_SUPPLY_ROLES))
        _identifier(artifact["artifact_id"])
        for field in (
            "expected_bytes_digest",
            "actual_bytes_digest",
            "provenance_digest",
            "binding_digest",
        ):
            _digest(artifact[field])
        for field in ("device", "inode", "size", "mode"):
            _integer(artifact[field])
        binding_data = {key: artifact[key] for key in artifact if key != "binding_digest"}
        if (
            artifact["expected_bytes_digest"] != artifact["actual_bytes_digest"]
            or _hash_text(_canonical(binding_data)) != artifact["binding_digest"]
        ):
            raise _Stop(L0Reason.ARTIFACT_MISMATCH)
        artifacts.append(artifact)
    if tuple(item["role"] for item in artifacts) != tuple(sorted(_SUPPLY_ROLES)):
        raise _Stop(L0Reason.SUPPLY_MISMATCH)
    if any(type(item) is not SupplyArtifactBinding for item in supply.artifacts):
        raise _Stop(L0Reason.SUPPLY_MISMATCH)
    if tuple(item.data() for item in supply.artifacts) != tuple(artifacts):
        raise _Stop(L0Reason.SUPPLY_MISMATCH)
    supply_digest = _hash_text(supply.payload_json)
    placement_digest = _hash_text(_canonical(placement))
    expires_at = _time(placement["expires_at"])
    if (
        supply.supply_digest != supply_digest
        or supply.placement_digest != placement_digest
        or payload["placement_digest"] != placement_digest
        or supply.profile_digest != profile.profile_digest
        or payload["profile_digest"] != profile.profile_digest
        or placement["profile_digest"] != profile.profile_digest
        or supply.measurement_digest != payload["measurement_digest"]
        or placement["measurement_digest"] != supply.measurement_digest
        or supply.runtime_digest != profile.backend_digest
        or placement["runtime_digest"] != profile.backend_digest
        or runtime["path"] != profile.backend_path
        or runtime["version"] != profile.backend_version
        or runtime["digest"] != profile.backend_digest
        or supply.session_id != placement["session_id"]
        or supply.subject_instance_id != placement["subject_instance_id"]
        or supply.process_tree_id != placement["process_tree_id"]
        or supply.fencing_epoch != placement["fencing_epoch"]
        or supply.revocation_epoch != placement["revocation_epoch"]
        or supply.observed_at != payload["observed_at"]
        or supply.expires_at != placement["expires_at"]
        or supply.verifier_id != verification["verifier_id"]
        or not payload_observed <= requested_observed < expires_at
    ):
        raise _Stop(L0Reason.PLACEMENT_MISMATCH)
    if measurement is not None and (
        not _measurement_is_valid(profile, measurement)
        or supply.measurement_digest != measurement.measurement_digest
    ):
        raise _Stop(L0Reason.PLACEMENT_MISMATCH)
    if (
        _binary_digest(profile.backend_path) != profile.backend_digest
        or _runtime_output("--version") != profile.backend_version
    ):
        raise _Stop(L0Reason.SUPPLY_MISMATCH)
    source = {
        "verifier_id": verification["verifier_id"],
        "issuer_id": verification["issuer_id"],
        "key_id": verification["key_id"],
    }
    for value in source.values():
        _identifier(value)
    proof = verification["proof"]
    if type(proof) is not str or not proof or len(proof) > 8192:
        raise _Stop(L0Reason.SUPPLY_MISMATCH)
    verification_digest = _hash_text(supply.verification_json)
    if (
        verification["verification_version"] != 1
        or verification["payload_digest"] != supply_digest
        or verification["bindings"] != payload
        or not _supply_verifier_accepts(
            verifier,
            supply.payload_json,
            supply.verification_json,
            source,
            supply_digest,
            verification_digest,
            supply.observed_at,
        )
    ):
        raise _Stop(L0Reason.SUPPLY_MISMATCH)
    return supply


def _verified_claim(
    profile: CompiledL0Profile,
    claim: object,
    verifier: object,
) -> DispatchClaim:
    if type(claim) is not DispatchClaim:
        raise _Stop(L0Reason.CLAIM_REQUIRED)
    try:
        claim_value = json.loads(claim.claim_json)
        verification = json.loads(claim.executor_verification_json)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise _Stop(L0Reason.CLAIM_MISMATCH) from error
    claim_value = _closed_dict(claim_value, _DURABLE_CLAIM_KEYS)
    verification = _closed_dict(verification, _VERIFICATION_KEYS)
    if _canonical(claim_value) != claim.claim_json or _canonical(verification) != claim.executor_verification_json:
        raise _Stop(L0Reason.CLAIM_MISMATCH)
    scalar_bindings = {
        "transaction_id": claim.transaction_id,
        "capability_id": claim.capability_id,
        "intent_digest": claim.intent_digest,
        "idempotency_key_digest": claim.idempotency_key_digest,
        "principal_id": claim.principal_id,
        "audience_id": claim.audience_id,
        "purpose": claim.purpose,
        "profile_digest": claim.profile_digest,
        "placement_digest": claim.placement_digest,
        "session_id": claim.session_id,
        "lineage_root": claim.lineage_root,
        "nonce": claim.nonce,
        "revocation_epoch": claim.revocation_epoch,
        "fencing_epoch": claim.fencing_epoch,
        "observed_at": claim.observed_at,
        "target_scope_digest": claim.target_scope_digest,
        "material_digest": claim.material_digest,
    }
    try:
        nested_bindings = {
            "request": json.loads(claim.request_json),
            "decision": json.loads(claim.decision_json),
            "authorized_envelope": json.loads(claim.authorized_envelope_json),
            "capability_payload": json.loads(claim.capability_payload_json),
            "capability_verification": json.loads(claim.capability_verification_json),
            "intent": json.loads(claim.intent_json),
        }
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise _Stop(L0Reason.CLAIM_MISMATCH) from error
    if (
        claim_value.get("claim_version") != 1
        or claim.profile_digest != profile.profile_digest
        or any(claim_value.get(name) != value for name, value in scalar_bindings.items())
        or any(claim_value.get(name) != value for name, value in nested_bindings.items())
        or _hash_text(claim.claim_json) != claim.claim_digest
        or verification.get("verification_version") != 1
        or verification.get("payload_digest") != claim.claim_digest
        or verification.get("bindings") != claim_value
        or claim.principal_id == claim.audience_id
    ):
        raise _Stop(L0Reason.CLAIM_MISMATCH)
    worker = _active_principal(profile, "AGENT_WORKER")
    executor = _active_principal(profile, "EXECUTOR")
    if (
        claim.principal_id != worker.principal_id
        or claim.session_id != worker.session_id
        or claim.audience_id != executor.principal_id
    ):
        raise _Stop(L0Reason.CLAIM_MISMATCH)
    for field in ("verifier_id", "issuer_id", "key_id"):
        _identifier(verification[field])
    proof = verification["proof"]
    if (
        type(proof) is not str
        or not proof
        or len(proof) > 8192
        or any(unicodedata.category(character) in {"Cc", "Cf"} for character in proof)
    ):
        raise _Stop(L0Reason.CLAIM_MISMATCH)
    try:
        result = verifier.verify(
            claim.claim_json.encode("utf-8"),
            claim.executor_verification_json.encode("utf-8"),
            claim.observed_at,
        )
    except Exception as error:
        raise _Stop(L0Reason.CLAIM_MISMATCH) from error
    verification_digest = _hash_text(claim.executor_verification_json)
    if (
        type(result) is not VerificationResult
        or result.status is not VerificationStatus.VERIFIED
        or result.verifier_id != verification["verifier_id"]
        or result.payload_digest != claim.claim_digest
        or result.record_digest != verification_digest
    ):
        raise _Stop(L0Reason.CLAIM_MISMATCH)
    return claim


def _session_descriptor(value: object, *, write_only: bool = False) -> int:
    if type(value) is not int or value < 0:
        raise _Stop(L0Reason.MALFORMED_INPUT)
    try:
        flags = fcntl.fcntl(value, fcntl.F_GETFD)
        status_flags = fcntl.fcntl(value, fcntl.F_GETFL)
    except OSError as error:
        raise _Stop(L0Reason.PLACEMENT_MISMATCH) from error
    expected_access = os.O_WRONLY if write_only else os.O_RDONLY
    if not flags & fcntl.FD_CLOEXEC or status_flags & os.O_ACCMODE != expected_access:
        raise _Stop(L0Reason.PLACEMENT_MISMATCH)
    return value


def _directory_observation(descriptor: int, descriptor_id: str, kind: str) -> dict[str, object]:
    duplicate = fcntl.fcntl(descriptor, fcntl.F_DUPFD_CLOEXEC, 3)
    try:
        info = os.fstat(duplicate)
        mode = stat.S_IMODE(info.st_mode)
        if not stat.S_ISDIR(info.st_mode) or mode & 0o022:
            raise _Stop(L0Reason.PLACEMENT_MISMATCH)
        return {
            "kind": kind,
            "descriptor": descriptor,
            "descriptor_id": descriptor_id,
            "device": info.st_dev,
            "inode": info.st_ino,
            "mount_id": _mount_id(duplicate),
            "mode": mode,
            "type": "DIRECTORY",
        }
    finally:
        os.close(duplicate)


def _regular_observation(
    descriptor: int,
    descriptor_id: str,
    kind: str,
    expected_digest: str,
    maximum: int,
) -> dict[str, object]:
    duplicate = fcntl.fcntl(descriptor, fcntl.F_DUPFD_CLOEXEC, 3)
    try:
        info = os.fstat(duplicate)
        mode = stat.S_IMODE(info.st_mode)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or mode & 0o022
            or info.st_size < 0
            or info.st_size > maximum
        ):
            raise _Stop(L0Reason.PLACEMENT_MISMATCH)
        actual = _hash_descriptor(duplicate, maximum)
        if actual != expected_digest:
            raise _Stop(L0Reason.ARTIFACT_MISMATCH)
        return {
            "kind": kind,
            "descriptor": descriptor,
            "descriptor_id": descriptor_id,
            "device": info.st_dev,
            "inode": info.st_ino,
            "mount_id": _mount_id(duplicate),
            "size": info.st_size,
            "mode": mode,
            "type": "REGULAR",
            "bytes_digest": actual,
        }
    finally:
        os.close(duplicate)


def _require_minimal_rootfs(descriptor: int) -> None:
    duplicate = fcntl.fcntl(descriptor, fcntl.F_DUPFD_CLOEXEC, 3)
    try:
        if frozenset(os.listdir(duplicate)) != _ROOTFS_TOP_LEVEL:
            raise _Stop(L0Reason.PLACEMENT_MISMATCH)
        for relative in (
            "inputs",
            "proc",
            "run",
            "run/harness",
            "usr",
            "usr/lib",
            "usr/lib/harness",
            "workspace",
        ):
            info = os.stat(relative, dir_fd=duplicate, follow_symlinks=False)
            if not stat.S_ISDIR(info.st_mode):
                raise _Stop(L0Reason.PLACEMENT_MISMATCH)
        placeholder = os.stat("usr/lib/harness/worker-tool", dir_fd=duplicate, follow_symlinks=False)
        if not stat.S_ISREG(placeholder.st_mode) or placeholder.st_nlink != 1:
            raise _Stop(L0Reason.PLACEMENT_MISMATCH)
    except (FileNotFoundError, NotADirectoryError) as error:
        raise _Stop(L0Reason.PLACEMENT_MISMATCH) from error
    finally:
        os.close(duplicate)


def _artifact_for(supply: SupplyVerification, role: str) -> SupplyArtifactBinding:
    for artifact in supply.artifacts:
        if artifact.role == role:
            return artifact
    raise _Stop(L0Reason.SUPPLY_MISMATCH)


def _artifact_observation_matches(observed: dict[str, object], artifact: SupplyArtifactBinding) -> bool:
    return (
        observed["device"] == artifact.device
        and observed["inode"] == artifact.inode
        and observed["size"] == artifact.size
        and observed["mode"] == artifact.mode
        and observed["bytes_digest"] == artifact.actual_bytes_digest
    )


def _session_observations(
    profile: CompiledL0Profile,
    measurement: HostMeasurement,
    raw: object,
) -> tuple[PlacementMeasurement, dict[str, object]]:
    if not _profile_is_valid(profile) or not _measurement_is_valid(profile, measurement):
        raise _Stop(L0Reason.PLACEMENT_MISMATCH)
    value = _closed_dict(raw, _SESSION_KEYS)
    _exact(value["session_version"], "1.0.0")
    session_record_id = _identifier(value["session_record_id"])
    session_id = _identifier(value["session_id"])
    transaction_id = _identifier(value["transaction_id"])
    claim_digest = _digest(value["claim_digest"])
    lineage_root = _digest(value["lineage_root"])
    fencing_epoch = _integer(value["fencing_epoch"], minimum=1)
    revocation_epoch = _integer(value["revocation_epoch"])
    worker_principal = _identifier(value["worker_principal"])
    executor_principal = _identifier(value["executor_principal"])
    subject_instance_id = _identifier(value["subject_instance_id"])
    process_tree_id = _identifier(value["process_tree_id"])
    worker = _active_principal(profile, "AGENT_WORKER")
    executor = _active_principal(profile, "EXECUTOR")
    if (
        session_id != worker.session_id
        or worker_principal != worker.principal_id
        or executor_principal != executor.principal_id
        or worker_principal == executor_principal
    ):
        raise _Stop(L0Reason.SESSION_MISMATCH)

    namespace_value = _closed_dict(value["namespace_ids"], _SESSION_NAMESPACE_KEYS)
    expected_namespaces = {
        "user": worker.user_namespace,
        "mount": worker.mount_namespace,
        "pid": worker.pid_namespace,
        "ipc": worker.ipc_namespace,
        "uts": worker.uts_namespace,
        "network": worker.network_namespace,
        "cgroup": worker.cgroup_namespace,
    }
    namespace_ids = {key: _identifier(namespace_value[key]) for key in sorted(namespace_value)}
    if namespace_ids != expected_namespaces or len(set(namespace_ids.values())) != len(namespace_ids):
        raise _Stop(L0Reason.SESSION_MISMATCH)
    namespace_data = {
        "worker_principal": worker_principal,
        "worker_session": session_id,
        "uid": worker.uid,
        "gid": worker.gid,
        "security_label": worker.security_label,
        "credential_namespace": worker.credential_namespace,
        "namespace_ids": namespace_ids,
    }
    namespace_digest = _hash_text(_canonical(namespace_data))

    root_value = _closed_dict(value["rootfs"], _SESSION_ROOTFS_KEYS)
    root_fd = _session_descriptor(root_value["descriptor"])
    root_data = _directory_observation(root_fd, _identifier(root_value["descriptor_id"]), "ROOTFS")
    _require_minimal_rootfs(root_fd)
    rootfs_digest = _hash_text(_canonical(root_data))

    input_rows = _list(value["inputs"], maximum=16)
    input_data: list[dict[str, object]] = []
    input_mounts: list[tuple[int, str]] = []
    for raw_input in input_rows:
        input_value = _closed_dict(raw_input, _SESSION_INPUT_KEYS)
        descriptor_id = _identifier(input_value["descriptor_id"])
        mount_path = input_value["mount_path"]
        if type(mount_path) is not str or mount_path != f"/inputs/{descriptor_id}":
            raise _Stop(L0Reason.PLACEMENT_MISMATCH)
        descriptor = _session_descriptor(input_value["descriptor"])
        observed = _regular_observation(
            descriptor,
            descriptor_id,
            "READ_ONLY_INPUT",
            _digest(input_value["expected_bytes_digest"]),
            _MAX_SUPPLY_ARTIFACT_BYTES,
        )
        observed["mount_path"] = mount_path
        input_data.append(observed)
        input_mounts.append((descriptor, mount_path))
    if len({item["descriptor_id"] for item in input_data}) != len(input_data):
        raise _Stop(L0Reason.MALFORMED_INPUT)

    broker_value = _closed_dict(value["broker_ipc"], _SESSION_BROKER_KEYS)
    broker_fd = _session_descriptor(broker_value["descriptor"])
    broker_id = _identifier(broker_value["descriptor_id"])
    socket_name = _identifier(broker_value["socket_name"])
    profile_source = json.loads(profile.canonical_profile_json)
    broker_profile = profile_source["broker_ipc"]
    if (
        broker_value["worker_endpoint"] != broker_profile["worker_endpoint"]
        or broker_value["broker_endpoint"] != broker_profile["broker_endpoint"]
        or broker_value["transport"] != "UNIX_SEQPACKET"
    ):
        raise _Stop(L0Reason.PLACEMENT_MISMATCH)
    broker_root = _directory_observation(broker_fd, broker_id, "BROKER_IPC_ROOT")
    duplicate = fcntl.fcntl(broker_fd, fcntl.F_DUPFD_CLOEXEC, 3)
    try:
        if os.listdir(duplicate) != [socket_name]:
            raise _Stop(L0Reason.PLACEMENT_MISMATCH)
        socket_info = os.stat(socket_name, dir_fd=duplicate, follow_symlinks=False)
        if not stat.S_ISSOCK(socket_info.st_mode):
            raise _Stop(L0Reason.PLACEMENT_MISMATCH)
    finally:
        os.close(duplicate)
    broker_data = {
        **broker_root,
        "socket_name": socket_name,
        "socket_device": socket_info.st_dev,
        "socket_inode": socket_info.st_ino,
        "worker_endpoint": broker_value["worker_endpoint"],
        "broker_endpoint": broker_value["broker_endpoint"],
        "transport": "UNIX_SEQPACKET",
        "message_binding_digest": profile.broker_binding_digest,
    }
    broker_digest = _hash_text(_canonical(broker_data))

    seccomp_value = _closed_dict(value["seccomp"], _SESSION_SECCOMP_KEYS)
    seccomp_fd = _session_descriptor(seccomp_value["descriptor"])
    seccomp_data = _regular_observation(
        seccomp_fd,
        _identifier(seccomp_value["descriptor_id"]),
        "SECCOMP_PROFILE",
        _digest(seccomp_value["expected_bytes_digest"]),
        _MAX_SUPPLY_ARTIFACT_BYTES,
    )
    tool_value = _closed_dict(value["tool"], _SESSION_TOOL_KEYS)
    tool_fd = _session_descriptor(tool_value["descriptor"])
    tool_data = _regular_observation(
        tool_fd,
        _identifier(tool_value["descriptor_id"]),
        "WORKER_TOOL",
        _digest(tool_value["expected_bytes_digest"]),
        _MAX_SUPPLY_ARTIFACT_BYTES,
    )
    _exact(tool_value["path"], _WORKER_TOOL_PATH)
    tool_argv_raw = _list(tool_value["argv"], minimum=5, maximum=5)
    if any(type(item) is not str for item in tool_argv_raw):
        raise _Stop(L0Reason.MALFORMED_INPUT)
    expected_argv = (
        _WORKER_TOOL_PATH,
        "--broker-socket",
        f"{_BROKER_MOUNT}/{socket_name}",
        "--session",
        session_id,
    )
    if tuple(tool_argv_raw) != expected_argv:
        raise _Stop(L0Reason.PLACEMENT_MISMATCH)

    cgroup_value = _closed_dict(value["cgroup"], _SESSION_CGROUP_KEYS)
    cgroup_path = cgroup_value["path"]
    if (
        type(cgroup_path) is not str
        or not cgroup_path.startswith(measurement.cgroup_path.rstrip("/") + "/")
        or "/../" in cgroup_path
        or "//" in cgroup_path
        or len(PurePosixPath(cgroup_path).parts) != len(PurePosixPath(measurement.cgroup_path).parts) + 1
    ):
        raise _Stop(L0Reason.PLACEMENT_MISMATCH)
    controllers = _exact_string_set(cgroup_value["controllers"], frozenset({"cpu", "io", "memory", "pids"}))
    if not _boolean(cgroup_value["delegated"]):
        raise _Stop(L0Reason.PLACEMENT_MISMATCH)
    cgroup_data = {
        "path": cgroup_path,
        "controllers": list(controllers),
        "device_major": _integer(cgroup_value["device_major"]),
        "device_minor": _integer(cgroup_value["device_minor"]),
        "delegated": True,
        "identity_digest": _digest(cgroup_value["identity_digest"]),
    }
    cgroup_digest = _hash_text(_canonical(cgroup_data))

    staging_value = _closed_dict(value["staging"], _SESSION_STAGING_KEYS)
    staging_data = {
        "root_id": _identifier(staging_value["root_id"]),
        "root_identity": _digest(staging_value["root_identity"]),
        "mount_id": _identifier(staging_value["mount_id"]),
        "mount_identity": _digest(staging_value["mount_identity"]),
        "files": _integer(staging_value["files"], minimum=1),
        "inodes": _integer(staging_value["inodes"], minimum=1),
        "bytes": _integer(staging_value["bytes"], minimum=1),
    }
    if (
        staging_data["files"] != _resource_limit(profile, "FILES")
        or staging_data["inodes"] != _resource_limit(profile, "INODES")
        or staging_data["bytes"] != _resource_limit(profile, "OUTPUT_BYTES")
    ):
        raise _Stop(L0Reason.PLACEMENT_MISMATCH)
    staging_digest = _hash_text(_canonical(staging_data))

    supervisor_value = _closed_dict(value["supervisor_fds"], _SESSION_SUPERVISOR_FD_KEYS)
    gate_fd = _session_descriptor(supervisor_value["gate_read"])
    gate_release_fd = _session_descriptor(supervisor_value["gate_write"], write_only=True)
    status_source_fd = _session_descriptor(supervisor_value["status_read"])
    status_fd = _session_descriptor(supervisor_value["status_write"], write_only=True)
    pipe_fds = (gate_fd, gate_release_fd, status_source_fd, status_fd)
    for descriptor in pipe_fds:
        if not stat.S_ISFIFO(os.fstat(descriptor).st_mode):
            raise _Stop(L0Reason.PLACEMENT_MISMATCH)
    if (
        os.fstat(gate_fd).st_ino != os.fstat(gate_release_fd).st_ino
        or os.fstat(status_source_fd).st_ino != os.fstat(status_fd).st_ino
        or os.fstat(gate_fd).st_ino == os.fstat(status_fd).st_ino
    ):
        raise _Stop(L0Reason.PLACEMENT_MISMATCH)

    cleanup_value = _closed_dict(value["cleanup"], _SESSION_CLEANUP_KEYS)
    cleanup_data = {
        "cleanup_id": _identifier(cleanup_value["cleanup_id"]),
        "staging_root_id": _identifier(cleanup_value["staging_root_id"]),
        "reuse_forbidden": _boolean(cleanup_value["reuse_forbidden"]),
        "require_cgroup_empty": _boolean(cleanup_value["require_cgroup_empty"]),
        "quarantine_on_failure": _boolean(cleanup_value["quarantine_on_failure"]),
    }
    if (
        cleanup_data["staging_root_id"] != staging_data["root_id"]
        or cleanup_data["reuse_forbidden"] is not True
        or cleanup_data["require_cgroup_empty"] is not True
        or cleanup_data["quarantine_on_failure"] is not True
    ):
        raise _Stop(L0Reason.PLACEMENT_MISMATCH)

    pass_descriptors = [root_fd, *(item[0] for item in input_mounts), broker_fd, seccomp_fd, tool_fd, gate_fd, status_fd]
    descriptors = [*pass_descriptors, gate_release_fd, status_source_fd]
    if len(set(descriptors)) != len(descriptors):
        raise _Stop(L0Reason.PLACEMENT_MISMATCH)
    fd_inventory = [
        root_data,
        *input_data,
        broker_root,
        seccomp_data,
        tool_data,
        {
            "kind": "START_GATE",
            "descriptor": gate_fd,
            "device": os.fstat(gate_fd).st_dev,
            "inode": os.fstat(gate_fd).st_ino,
            "type": "PIPE",
        },
        {
            "kind": "STATUS_SINK",
            "descriptor": status_fd,
            "device": os.fstat(status_fd).st_dev,
            "inode": os.fstat(status_fd).st_ino,
            "type": "PIPE",
        },
        {
            "kind": "START_GATE_RELEASE",
            "descriptor": gate_release_fd,
            "device": os.fstat(gate_release_fd).st_dev,
            "inode": os.fstat(gate_release_fd).st_ino,
            "type": "PIPE",
        },
        {
            "kind": "STATUS_SOURCE",
            "descriptor": status_source_fd,
            "device": os.fstat(status_source_fd).st_dev,
            "inode": os.fstat(status_source_fd).st_ino,
            "type": "PIPE",
        },
    ]
    fd_inventory_digest = _hash_text(_canonical(fd_inventory))
    runtime_data = {
        "binding_version": 1,
        "process": {
            "session_record_id": session_record_id,
            "process_tree_id": process_tree_id,
            "transaction_id": transaction_id,
            "claim_digest": claim_digest,
            "lineage_root": lineage_root,
            "session_id": session_id,
            "subject_instance_id": subject_instance_id,
            "worker_principal": worker_principal,
            "executor_principal": executor_principal,
            "fencing_epoch": fencing_epoch,
            "revocation_epoch": revocation_epoch,
        },
        "namespaces": namespace_data,
        "cgroup": cgroup_data,
        "mounts": {
            "rootfs": root_data,
            "read_only_inputs": input_data,
            "worker_writable_mounts": [],
            "staging_visible_to_worker": False,
        },
        "writable_scope": staging_data,
        "broker_ipc": broker_data,
        "fd_allowlist": fd_inventory,
        "cleanup": cleanup_data,
    }
    runtime_json = _canonical(runtime_data)
    placement = PlacementMeasurement(
        rootfs_digest,
        staging_digest,
        cgroup_digest,
        broker_digest,
        fd_inventory_digest,
        namespace_digest,
        runtime_json,
        _hash_text(runtime_json),
    )
    parsed: dict[str, object] = {
        "session_id": session_id,
        "session_record_id": session_record_id,
        "transaction_id": transaction_id,
        "claim_digest": claim_digest,
        "lineage_root": lineage_root,
        "fencing_epoch": fencing_epoch,
        "revocation_epoch": revocation_epoch,
        "worker_principal": worker_principal,
        "executor_principal": executor_principal,
        "subject_instance_id": subject_instance_id,
        "process_tree_id": process_tree_id,
        "namespace_ids": namespace_ids,
        "root_fd": root_fd,
        "input_mounts": tuple(input_mounts),
        "broker_fd": broker_fd,
        "socket_name": socket_name,
        "seccomp_fd": seccomp_fd,
        "seccomp_data": seccomp_data,
        "tool_fd": tool_fd,
        "tool_data": tool_data,
        "tool_argv": expected_argv,
        "cgroup_path": cgroup_path,
        "cgroup_data": cgroup_data,
        "staging_data": staging_data,
        "gate_fd": gate_fd,
        "gate_release_fd": gate_release_fd,
        "status_source_fd": status_source_fd,
        "status_fd": status_fd,
        "cleanup_data": cleanup_data,
        "descriptors": tuple(descriptors),
        "pass_descriptors": tuple(pass_descriptors),
    }
    return placement, parsed


def measure_placement(profile: object, measurement: object, raw: object) -> PlacementResult:
    """Read and bind all prospective runtime objects without creating or launching any."""

    try:
        if type(profile) is not CompiledL0Profile or type(measurement) is not HostMeasurement:
            raise _Stop(L0Reason.PLACEMENT_MISMATCH)
        observed, _ = _session_observations(profile, measurement, raw)
        return PlacementResult(L0Outcome.RESOLVED, L0Reason.PLACEMENT_MEASURED, observed)
    except _Stop as stop:
        return PlacementResult(L0Outcome.STOP, stop.reason)
    except (OSError, ValueError, TypeError):
        return PlacementResult(L0Outcome.STOP, L0Reason.PLACEMENT_MISMATCH)
    except Exception:  # noqa: BLE001 - hostile values and host races are total
        return PlacementResult(L0Outcome.STOP, L0Reason.HOST_FAILURE)


def _session_cgroup_limits(profile: CompiledL0Profile, cgroup: dict[str, object]) -> tuple[tuple[str, str], ...]:
    cpu_rate = _resource_limit(profile, "CPU_RATE")
    memory = _resource_limit(profile, "MEMORY") * 1024 * 1024
    swap = _resource_limit(profile, "SWAP") * 1024 * 1024
    pids = _resource_limit(profile, "PIDS")
    device = f"{cgroup['device_major']}:{cgroup['device_minor']}"
    read_iops = _resource_limit(profile, "BLOCK_IO_READ")
    write_iops = _resource_limit(profile, "BLOCK_IO_WRITE")
    return (
        ("cpu.max", f"{cpu_rate * 100} 100000"),
        ("io.max", f"{device} riops={read_iops} wiops={write_iops}"),
        ("memory.max", str(memory)),
        ("memory.swap.max", str(swap)),
        ("pids.max", str(pids)),
    )


def prepare_session(
    profile: object,
    measurement: object,
    supply: object,
    claim: object,
    raw: object,
    *,
    supply_verifier: object | None = None,
    executor_claim_verifier: object | None = None,
) -> SessionResult:
    """Compile the exact launch record; it never starts a process or creates runtime state."""

    try:
        if type(profile) is not CompiledL0Profile or type(measurement) is not HostMeasurement:
            raise _Stop(L0Reason.PLACEMENT_MISMATCH)
        if supply_verifier is None:
            raise _Stop(L0Reason.SUPPLY_VERIFIER_ABSENT)
        if executor_claim_verifier is None:
            raise _Stop(L0Reason.CLAIM_REQUIRED)
        durable_claim = _verified_claim(profile, claim, executor_claim_verifier)
        verified_supply = _verified_supply(
            profile,
            measurement,
            supply,
            supply_verifier,
            durable_claim.observed_at,
        )
        placement, parsed = _session_observations(profile, measurement, raw)
        supply_payload = json.loads(verified_supply.payload_json)
        supplied_placement = supply_payload["placement"]
        placement_pairs = {
            "rootfs_binding_digest": placement.rootfs_binding_digest,
            "staging_binding_digest": placement.staging_binding_digest,
            "cgroup_binding_digest": placement.cgroup_binding_digest,
            "broker_binding_digest": placement.broker_binding_digest,
            "fd_inventory_digest": placement.fd_inventory_digest,
            "namespace_plan_digest": placement.namespace_plan_digest,
        }
        if (
            any(supplied_placement[key] != digest for key, digest in placement_pairs.items())
            or durable_claim.transaction_id != parsed["transaction_id"]
            or durable_claim.claim_digest != parsed["claim_digest"]
            or durable_claim.lineage_root != parsed["lineage_root"]
            or durable_claim.fencing_epoch != parsed["fencing_epoch"]
            or durable_claim.revocation_epoch != parsed["revocation_epoch"]
            or durable_claim.principal_id != parsed["worker_principal"]
            or durable_claim.audience_id != parsed["executor_principal"]
            or durable_claim.session_id != parsed["session_id"]
            or durable_claim.placement_digest != verified_supply.placement_digest
            or verified_supply.session_id != parsed["session_id"]
            or verified_supply.subject_instance_id != parsed["subject_instance_id"]
            or verified_supply.process_tree_id != parsed["process_tree_id"]
            or verified_supply.fencing_epoch != parsed["fencing_epoch"]
            or verified_supply.revocation_epoch != parsed["revocation_epoch"]
        ):
            raise _Stop(L0Reason.SESSION_MISMATCH)
        if not _artifact_observation_matches(parsed["seccomp_data"], _artifact_for(verified_supply, "SECCOMP_PROFILE")):
            raise _Stop(L0Reason.ARTIFACT_MISMATCH)
        if not _artifact_observation_matches(parsed["tool_data"], _artifact_for(verified_supply, "TOOL")):
            raise _Stop(L0Reason.ARTIFACT_MISMATCH)

        worker = _active_principal(profile, "AGENT_WORKER")
        argv: list[str] = [
            RUNTIME_PATH,
            "--block-fd",
            str(parsed["gate_fd"]),
            "--json-status-fd",
            str(parsed["status_fd"]),
            "--unshare-user",
            "--uid",
            str(worker.uid),
            "--gid",
            str(worker.gid),
            "--unshare-ipc",
            "--unshare-pid",
            "--unshare-net",
            "--unshare-uts",
            "--unshare-cgroup",
            "--disable-userns",
            "--assert-userns-disabled",
            "--hostname",
            "harness-worker",
            "--new-session",
            "--die-with-parent",
            "--clearenv",
            "--cap-drop",
            "ALL",
            "--exec-label",
            str(worker.security_label),
            "--ro-bind-fd",
            str(parsed["root_fd"]),
            "/",
        ]
        read_only_mounts = [(parsed["root_fd"], "/"), *parsed["input_mounts"]]
        for descriptor, destination in parsed["input_mounts"]:
            argv.extend(("--ro-bind-fd", str(descriptor), destination))
        argv.extend(
            (
                "--ro-bind-fd",
                str(parsed["broker_fd"]),
                _BROKER_MOUNT,
                "--ro-bind-fd",
                str(parsed["tool_fd"]),
                _WORKER_TOOL_PATH,
                "--proc",
                "/proc",
                "--remount-ro",
                "/proc",
                "--seccomp",
                str(parsed["seccomp_fd"]),
                "--chdir",
                "/workspace",
                "--",
                *parsed["tool_argv"],
            )
        )
        cgroup_limits = _session_cgroup_limits(profile, parsed["cgroup_data"])
        quota = tuple(sorted(parsed["staging_data"].items()))
        runtime_bindings = json.loads(placement.runtime_bindings_json)
        runtime_process = runtime_bindings["process"]
        broker = _active_principal(profile, "BROKER")
        executor = _active_principal(profile, "EXECUTOR")
        runtime_process.update(
            {
                "profile_digest": profile.profile_digest,
                "measurement_digest": measurement.measurement_digest,
                "supply_digest": verified_supply.supply_digest,
                "placement_digest": verified_supply.placement_digest,
                "runtime_digest": profile.backend_digest,
                "broker_principal": broker.principal_id,
                "broker_session": broker.session_id,
                "executor_session": executor.session_id,
            }
        )
        runtime_bindings_json = _canonical(runtime_bindings)
        runtime_bindings_digest = _hash_text(runtime_bindings_json)
        launch_data = {
            "launch_version": 1,
            "profile_digest": profile.profile_digest,
            "measurement_digest": measurement.measurement_digest,
            "supply_digest": verified_supply.supply_digest,
            "placement_digest": verified_supply.placement_digest,
            "claim_digest": durable_claim.claim_digest,
            "runtime_bindings_digest": runtime_bindings_digest,
            "runtime_path": RUNTIME_PATH,
            "runtime_digest": RUNTIME_DIGEST,
            "argv": argv,
            "environment": [],
            "pass_fds": list(parsed["pass_descriptors"]),
            "cgroup_limits": dict(cgroup_limits),
            "cpu_time_ms": _resource_limit(profile, "CPU_TIME"),
            "wall_time_ms": _resource_limit(profile, "WALL_TIME"),
            "rlimit_nofile": _resource_limit(profile, "OPEN_FDS"),
            "quota": dict(quota),
        }
        launch_json = _canonical(launch_data)
        plan = SessionPlan(
            profile.profile_digest,
            measurement.measurement_digest,
            verified_supply.supply_digest,
            verified_supply.placement_digest,
            str(parsed["session_record_id"]),
            str(parsed["session_id"]),
            str(parsed["transaction_id"]),
            str(parsed["claim_digest"]),
            str(parsed["lineage_root"]),
            int(parsed["fencing_epoch"]),
            int(parsed["revocation_epoch"]),
            str(parsed["worker_principal"]),
            str(parsed["executor_principal"]),
            str(parsed["subject_instance_id"]),
            tuple(parsed["namespace_ids"].items()),
            tuple(read_only_mounts),
            (int(parsed["broker_fd"]), _BROKER_MOUNT),
            f"{_BROKER_MOUNT}/{parsed['socket_name']}",
            int(parsed["seccomp_fd"]),
            int(parsed["tool_fd"]),
            int(parsed["gate_fd"]),
            int(parsed["gate_release_fd"]),
            int(parsed["status_source_fd"]),
            int(parsed["status_fd"]),
            tuple(parsed["pass_descriptors"]),
            tuple(argv),
            (),
            str(parsed["cgroup_path"]),
            cgroup_limits,
            _resource_limit(profile, "CPU_TIME"),
            _resource_limit(profile, "WALL_TIME"),
            _resource_limit(profile, "OPEN_FDS"),
            quota,
            _canonical(parsed["cleanup_data"]),
            runtime_bindings_json,
            runtime_bindings_digest,
            _hash_text(launch_json),
        )
        return SessionResult(L0Outcome.PREPARED, L0Reason.SESSION_PREPARED, plan)
    except _Stop as stop:
        return SessionResult(L0Outcome.STOP, stop.reason)
    except (OSError, ValueError, TypeError):
        return SessionResult(L0Outcome.STOP, L0Reason.SESSION_MISMATCH)
    except Exception:  # noqa: BLE001 - public session boundary is total
        return SessionResult(L0Outcome.STOP, L0Reason.HOST_FAILURE)


def _write_cgroup_control(directory: int, name: str, value: str) -> None:
    if name not in {"cpu.max", "io.max", "memory.max", "memory.swap.max", "pids.max", "cgroup.procs", "cgroup.kill"}:
        raise _Stop(L0Reason.RUNTIME_FAILED)
    descriptor = os.open(name, os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory)
    try:
        encoded = value.encode("ascii")
        offset = 0
        while offset < len(encoded):
            written = os.write(descriptor, encoded[offset:])
            if written <= 0:
                raise OSError(errno.EIO, "short cgroup write")
            offset += written
    finally:
        os.close(descriptor)


def _read_cgroup_control(directory: int, name: str, maximum: int = 65536) -> str:
    if name not in {"cpu.max", "cpu.stat", "io.max", "memory.max", "memory.swap.max", "pids.max", "cgroup.events"}:
        raise _Stop(L0Reason.RUNTIME_FAILED)
    descriptor = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory)
    try:
        value = os.read(descriptor, maximum + 1)
        if len(value) > maximum:
            raise _Stop(L0Reason.RUNTIME_FAILED)
        return value.decode("ascii")
    finally:
        os.close(descriptor)


def _cpu_usage_microseconds(directory: int) -> int:
    rows = _read_cgroup_control(directory, "cpu.stat").splitlines()
    usage = [row.split() for row in rows if row.startswith("usage_usec ")]
    if len(usage) != 1 or len(usage[0]) != 2 or not usage[0][1].isdigit():
        raise _Stop(L0Reason.RUNTIME_FAILED)
    return _integer(int(usage[0][1]))


def _close_standard_descriptors() -> None:
    for descriptor in (0, 1, 2):
        try:
            os.close(descriptor)
        except OSError:
            pass


def _bounded_status_digest(descriptor: int) -> str:
    duplicate = fcntl.fcntl(descriptor, fcntl.F_DUPFD_CLOEXEC, 3)
    try:
        flags = fcntl.fcntl(duplicate, fcntl.F_GETFL)
        fcntl.fcntl(duplicate, fcntl.F_SETFL, flags | os.O_NONBLOCK)
        chunks: list[bytes] = []
        total = 0
        while True:
            try:
                chunk = os.read(duplicate, 65536)
            except BlockingIOError:
                break
            if not chunk:
                break
            total += len(chunk)
            if total > 1 << 20:
                raise _Stop(L0Reason.RUNTIME_FAILED)
            chunks.append(chunk)
        raw = b"".join(chunks)
        if not raw:
            raise _Stop(L0Reason.RUNTIME_FAILED)
        for line in raw.splitlines():
            if not line:
                continue
            value = json.loads(line)
            if type(value) is not dict or any(type(key) is not str for key in value):
                raise _Stop(L0Reason.RUNTIME_FAILED)
        return "sha256:" + sha256(raw).hexdigest()
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise _Stop(L0Reason.RUNTIME_FAILED) from error
    finally:
        os.close(duplicate)


def _runtime_failure_digest(plan: SessionPlan, reason: str, process_id: int | None) -> str:
    return _hash_text(
        _canonical(
            {
                "session_record_id": plan.session_record_id,
                "transaction_id": plan.transaction_id,
                "process_tree_id": json.loads(plan.runtime_bindings_json)["process"]["process_tree_id"],
                "launch_digest": plan.launch_digest,
                "reason": reason,
                "process_id": process_id,
            }
        )
    )


def supervise_session(
    profile: object,
    measurement: object,
    supply: object,
    claim: object,
    raw: object,
    store: object,
    *,
    supply_verifier: object | None = None,
    executor_claim_verifier: object | None = None,
    runtime_verification: object | None = None,
    terminal_observed_at: object = None,
    cleanup_evidence: object | None = None,
    _fault: object | None = None,
) -> SupervisorResult:
    """Run exactly one gated bwrap process after the durable PREPARED commit.

    This path has no fallback and never retries.  Ordinary repository tests do
    not invoke it; exact-profile conformance must run it in an authorized outer
    containment environment.
    """

    plan: SessionPlan | None = None
    parent_fd = -1
    cgroup_fd = -1
    cgroup_created = False
    process: subprocess.Popen[bytes] | None = None
    process_id: int | None = None
    status_digest: str | None = None
    terminal_reason = L0Reason.RUNTIME_FAILED
    durable_prepared = False
    try:
        if type(store) is not DurableStore:
            raise _Stop(L0Reason.DURABLE_PREPARE_FAILED)
        _time(terminal_observed_at)
        if type(profile) is not CompiledL0Profile or type(measurement) is not HostMeasurement:
            raise _Stop(L0Reason.PLACEMENT_MISMATCH)
        observed = _verify_host(profile, _observe_host())
        if observed != measurement:
            raise _Stop(L0Reason.PLACEMENT_MISMATCH)
        planned = prepare_session(
            profile,
            measurement,
            supply,
            claim,
            raw,
            supply_verifier=supply_verifier,
            executor_claim_verifier=executor_claim_verifier,
        )
        if planned.outcome is not L0Outcome.PREPARED or planned.plan is None:
            raise _Stop(planned.reason)
        plan = planned.plan
        if type(runtime_verification) is not dict:
            raise _Stop(L0Reason.DURABLE_PREPARE_FAILED)
        durable = store.prepare_runtime_session(
            {
                "session_record_id": plan.session_record_id,
                "transaction_id": plan.transaction_id,
                "observed_at": claim.observed_at,
                "executor_id": plan.executor_principal,
                "profile_digest": plan.profile_digest,
                "placement_digest": plan.placement_digest,
                "session_id": plan.session_id,
                "fencing_epoch": plan.fencing_epoch,
                "runtime_bindings": json.loads(plan.runtime_bindings_json),
                "runtime_verification": runtime_verification,
            }
        )
        if durable.outcome is not DurableOutcome.COMMITTED or durable.runtime_session is None:
            raise _Stop(L0Reason.DURABLE_PREPARE_FAILED)
        durable_prepared = True
        if _fault is not None:
            _fault("supervisor_after_durable_prepare")  # type: ignore[operator]

        parent_logical = PurePosixPath(measurement.cgroup_path)
        child_logical = PurePosixPath(plan.cgroup_path)
        if child_logical.parent != parent_logical or child_logical.name in {"", ".", ".."}:
            raise _Stop(L0Reason.PLACEMENT_MISMATCH)
        parent_path = Path("/sys/fs/cgroup", measurement.cgroup_path.lstrip("/"))
        parent_fd = os.open(parent_path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        os.mkdir(child_logical.name, mode=0o700, dir_fd=parent_fd)
        cgroup_created = True
        cgroup_fd = os.open(
            child_logical.name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent_fd,
        )
        for name, value in plan.cgroup_limits:
            _write_cgroup_control(cgroup_fd, name, value)
        for name, expected in plan.cgroup_limits:
            observed_value = _read_cgroup_control(cgroup_fd, name).strip()
            if observed_value != expected:
                raise _Stop(L0Reason.RUNTIME_FAILED)
        if _fault is not None:
            _fault("supervisor_before_popen")  # type: ignore[operator]

        process = subprocess.Popen(
            list(plan.bwrap_argv),
            shell=False,
            close_fds=True,
            pass_fds=plan.pass_fds,
            env=dict(plan.environment),
            cwd="/",
            preexec_fn=_close_standard_descriptors,
        )
        process_id = process.pid
        _write_cgroup_control(cgroup_fd, "cgroup.procs", str(process.pid))
        resource.prlimit(process.pid, resource.RLIMIT_NOFILE, (plan.rlimit_nofile, plan.rlimit_nofile))
        cpu_start = _cpu_usage_microseconds(cgroup_fd)
        if os.write(plan.gate_write_fd, b"1") != 1:
            raise _Stop(L0Reason.RUNTIME_FAILED)
        if _fault is not None:
            _fault("supervisor_after_gate_release")  # type: ignore[operator]

        deadline = time.monotonic() + (plan.wall_time_ms / 1000)
        timed_out = False
        while process.poll() is None:
            if time.monotonic() >= deadline or _cpu_usage_microseconds(cgroup_fd) - cpu_start > plan.cpu_time_ms * 1000:
                timed_out = True
                terminal_reason = L0Reason.SESSION_TIMED_OUT
                _write_cgroup_control(cgroup_fd, "cgroup.kill", "1")
                break
            time.sleep(0.001)
        try:
            return_code = process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            _write_cgroup_control(cgroup_fd, "cgroup.kill", "1")
            return_code = process.wait(timeout=1)
            timed_out = True
            terminal_reason = L0Reason.SESSION_TIMED_OUT
        status_digest = _bounded_status_digest(plan.status_read_fd)
        if return_code != 0 and not timed_out:
            raise _Stop(L0Reason.RUNTIME_FAILED)

        # Revoke the only worker IPC route and prove the cgroup is empty before reuse.
        runtime_value = json.loads(plan.runtime_bindings_json)
        broker_record = runtime_value["broker_ipc"]
        broker_fd = plan.broker_root_mount[0]
        socket_name = PurePosixPath(plan.broker_socket_path).name
        socket_info = os.stat(socket_name, dir_fd=broker_fd, follow_symlinks=False)
        if socket_info.st_dev != broker_record["socket_device"] or socket_info.st_ino != broker_record["socket_inode"]:
            raise _Stop(L0Reason.CLEANUP_FAILED)
        os.unlink(socket_name, dir_fd=broker_fd)
        _write_cgroup_control(cgroup_fd, "cgroup.kill", "1")
        events = dict(row.split() for row in _read_cgroup_control(cgroup_fd, "cgroup.events").splitlines())
        if events.get("populated") != "0":
            raise _Stop(L0Reason.CLEANUP_FAILED)
        os.close(cgroup_fd)
        cgroup_fd = -1
        os.rmdir(child_logical.name, dir_fd=parent_fd)
        cgroup_created = False
        cleanup_digest = _runtime_failure_digest(plan, "CLEAN", process_id)

        if timed_out:
            terminal = store.finalize_runtime_session(
                {
                    "session_record_id": plan.session_record_id,
                    "observed_at": terminal_observed_at,
                    "state": "TIMED_OUT",
                    "evidence": {"evidence_digest": cleanup_digest},
                }
            )
        elif type(cleanup_evidence) is dict:
            terminal = store.finalize_runtime_session(
                {
                    "session_record_id": plan.session_record_id,
                    "observed_at": terminal_observed_at,
                    "state": "STOPPED",
                    "evidence": cleanup_evidence,
                }
            )
        else:
            terminal = store.finalize_runtime_session(
                {
                    "session_record_id": plan.session_record_id,
                    "observed_at": terminal_observed_at,
                    "state": "QUARANTINED",
                    "evidence": {"evidence_digest": cleanup_digest},
                }
            )
        released = terminal.outcome is DurableOutcome.COMMITTED and terminal.reason.value == "RELEASED"
        state = "STOPPED" if released else ("TIMED_OUT" if timed_out else "QUARANTINED")
        record = RuntimeSessionRecord(
            plan.session_record_id,
            plan.transaction_id,
            runtime_value["process"]["process_tree_id"],
            process_id,
            state,
            plan.cgroup_path,
            plan.launch_digest,
            status_digest,
            cleanup_digest,
        )
        if released:
            return SupervisorResult(L0Outcome.STOPPED, L0Reason.SESSION_STOPPED, record)
        return SupervisorResult(L0Outcome.QUARANTINED, terminal_reason, record)
    except _Stop as stop:
        terminal_reason = stop.reason
    except Exception:  # noqa: BLE001 - runtime boundary is fail-closed and total
        terminal_reason = L0Reason.RUNTIME_FAILED
    finally:
        if process is not None and process.poll() is None and cgroup_fd >= 0:
            try:
                _write_cgroup_control(cgroup_fd, "cgroup.kill", "1")
                process.wait(timeout=1)
            except Exception:
                pass
        if cgroup_fd >= 0:
            os.close(cgroup_fd)
        if cgroup_created and parent_fd >= 0 and plan is not None:
            try:
                os.rmdir(PurePosixPath(plan.cgroup_path).name, dir_fd=parent_fd)
            except OSError:
                terminal_reason = L0Reason.CLEANUP_FAILED
        if parent_fd >= 0:
            os.close(parent_fd)

    if plan is None or not durable_prepared:
        return SupervisorResult(L0Outcome.STOP, terminal_reason)
    cleanup_digest = _runtime_failure_digest(plan, terminal_reason.value, process_id)
    terminal = store.finalize_runtime_session(
        {
            "session_record_id": plan.session_record_id,
            "observed_at": terminal_observed_at,
            "state": "QUARANTINED",
            "evidence": {"evidence_digest": cleanup_digest},
        }
    )
    runtime_value = json.loads(plan.runtime_bindings_json)
    record = RuntimeSessionRecord(
        plan.session_record_id,
        plan.transaction_id,
        runtime_value["process"]["process_tree_id"],
        process_id,
        "QUARANTINED",
        plan.cgroup_path,
        plan.launch_digest,
        status_digest,
        cleanup_digest,
    )
    if terminal.outcome is not DurableOutcome.COMMITTED:
        return SupervisorResult(L0Outcome.QUARANTINED, L0Reason.CLEANUP_FAILED, record)
    return SupervisorResult(L0Outcome.QUARANTINED, terminal_reason, record)


def stage_committed_intent(
    profile: object,
    claim: object,
    supply: object,
    root_descriptor: object,
    raw: object,
    *,
    executor_claim_verifier: object | None = None,
    supply_verifier: object | None = None,
    _fault: object | None = None,
) -> StageResult:
    """Perform the sole M3 effect: one exact replace inside a trusted staging root."""

    root = -1
    target = -1
    effect_started = False
    try:
        if not _profile_is_valid(profile):
            raise _Stop(L0Reason.MISMATCHED_PROFILE)
        if executor_claim_verifier is None:
            raise _Stop(L0Reason.CLAIM_REQUIRED)
        if supply_verifier is None:
            raise _Stop(L0Reason.SUPPLY_VERIFIER_ABSENT)
        durable_claim = _verified_claim(profile, claim, executor_claim_verifier)
        verified_supply = _verified_supply(
            profile,
            None,
            supply,
            supply_verifier,
            durable_claim.observed_at,
        )
        if (
            durable_claim.placement_digest != verified_supply.placement_digest
            or durable_claim.session_id != verified_supply.session_id
            or durable_claim.fencing_epoch != verified_supply.fencing_epoch
            or durable_claim.revocation_epoch != verified_supply.revocation_epoch
        ):
            raise _Stop(L0Reason.PLACEMENT_MISMATCH)
        if type(root_descriptor) is not int or root_descriptor < 0:
            raise _Stop(L0Reason.MALFORMED_INPUT)
        value = _closed_dict(raw, _STAGE_REQUEST_KEYS)
        transaction_id = _identifier(value["transaction_id"])
        claim_digest = _digest(value["claim_digest"])
        _exact(value["operation"], "WRITE_FILE_REPLACE")
        content = value["content"]
        content_digest = _digest(value["content_digest"])
        if (
            type(content) is not str
            or unicodedata.normalize("NFC", content) != content
            or "\x00" in content
        ):
            raise _Stop(L0Reason.MALFORMED_INPUT)
        content_bytes = content.encode("utf-8")
        if not content_bytes or len(content_bytes) > _resource_limit(profile, "OUTPUT_BYTES"):
            raise _Stop(L0Reason.STAGE_LIMIT_EXCEEDED)
        if (
            _hash_text(content) != content_digest
            or transaction_id != durable_claim.transaction_id
            or claim_digest != durable_claim.claim_digest
            or content_digest != durable_claim.material_digest
        ):
            raise _Stop(L0Reason.MATERIAL_MISMATCH)
        binding = _parse_path_binding(value["target_binding"])
        expected_scope = _hash_text(_canonical({"kind": "PATH_EXACT", "value": binding.canonical_path}))
        if durable_claim.target_scope_digest != expected_scope or binding.final_digest == content_digest:
            raise _Stop(L0Reason.MATERIAL_MISMATCH)
        _, relative = _canonical_stage_path(binding.canonical_path)
        root = fcntl.fcntl(root_descriptor, fcntl.F_DUPFD_CLOEXEC, 3)
        _root_identity(root)
        target = _openat2(root, relative, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            fcntl.flock(target, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            raise _Stop(L0Reason.OBJECT_MISMATCH) from error
        current = _binding_for_open_target(
            profile,
            root,
            target,
            binding.canonical_path,
            binding.descriptor_id,
            binding.root_id,
            binding.resolution_epoch,
        )
        if current != binding:
            raise _Stop(L0Reason.OBJECT_MISMATCH)
        if _fault is not None:
            _fault("stage_before_effect")  # type: ignore[operator]
        effect_started = True
        offset = 0
        while offset < len(content_bytes):
            written = os.pwrite(target, content_bytes[offset:], offset)
            if written <= 0:
                raise OSError(errno.EIO, "short staging write")
            offset += written
        os.ftruncate(target, len(content_bytes))
        if _fault is not None:
            _fault("stage_after_write")  # type: ignore[operator]
        os.fsync(target)
        if _fault is not None:
            _fault("stage_after_fsync")  # type: ignore[operator]
        after_info = os.fstat(target)
        if (
            after_info.st_dev != binding.final_device
            or after_info.st_ino != binding.final_inode
            or not stat.S_ISREG(after_info.st_mode)
            or after_info.st_nlink != 1
            or _mount_id(target) != int(binding.mount_id.removeprefix("mnt:"))
        ):
            raise OSError(errno.ESTALE, "staging object changed")
        after_digest = _hash_descriptor(target, _resource_limit(profile, "OUTPUT_BYTES"))
        if after_digest != content_digest or after_info.st_size != len(content_bytes):
            raise OSError(errno.EIO, "staging verification failed")
        os.fsync(root)
        if _fault is not None:
            _fault("stage_after_verify")  # type: ignore[operator]
        record_data = {
            "transaction_id": durable_claim.transaction_id,
            "claim_digest": durable_claim.claim_digest,
            "binding_digest": binding.composite_binding_digest,
            "before_digest": binding.final_digest,
            "after_digest": after_digest,
            "bytes_written": len(content_bytes),
        }
        record = StageRecord(**record_data, record_digest=_hash_text(_canonical(record_data)))
        return StageResult(L0Outcome.STAGED, L0Reason.STAGED, record)
    except _Stop as stop:
        outcome = L0Outcome.QUARANTINED if effect_started else L0Outcome.STOP
        reason = L0Reason.STAGE_OUTCOME_UNKNOWN if effect_started else stop.reason
        return StageResult(outcome, reason)
    except Exception:  # noqa: BLE001 - post-effect faults must remain uncertain
        if effect_started:
            return StageResult(L0Outcome.QUARANTINED, L0Reason.STAGE_OUTCOME_UNKNOWN)
        return StageResult(L0Outcome.STOP, L0Reason.HOST_FAILURE)
    finally:
        if target >= 0:
            os.close(target)
        if root >= 0:
            os.close(root)


def _read_text(path: str, maximum: int = 1 << 20) -> str:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(65536, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                raise _Stop(L0Reason.HOST_FAILURE)
        return b"".join(chunks).decode("utf-8")
    finally:
        os.close(descriptor)


def _binary_digest(path: str) -> str:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    digest = sha256()
    try:
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            digest.update(chunk)
    finally:
        os.close(descriptor)
    return "sha256:" + digest.hexdigest()


def _runtime_output(argument: str) -> str:
    completed = subprocess.run(
        [RUNTIME_PATH, argument],
        shell=False,
        check=False,
        capture_output=True,
        text=False,
        timeout=5,
        close_fds=True,
        env={"LC_ALL": "C"},
    )
    if completed.returncode != 0 or completed.stderr not in {b"", None}:
        raise _Stop(L0Reason.RUNTIME_MISMATCH)
    return completed.stdout.decode("utf-8").strip()


def _openat2_available() -> bool:
    class OpenHow(ctypes.Structure):
        _fields_ = [("flags", ctypes.c_uint64), ("mode", ctypes.c_uint64), ("resolve", ctypes.c_uint64)]

    libc = ctypes.CDLL(None, use_errno=True)
    syscall = libc.syscall
    syscall.restype = ctypes.c_long
    how = OpenHow(0, 0, 0)
    result = syscall(437, -1, ctypes.c_char_p(b"."), ctypes.byref(how), ctypes.sizeof(how))
    if result >= 0:
        os.close(result)
        return True
    return ctypes.get_errno() != errno.ENOSYS


def _current_cgroup() -> tuple[str, Path]:
    records = _read_text("/proc/self/cgroup", 8192).splitlines()
    if len(records) != 1 or not records[0].startswith("0::/"):
        raise _Stop(L0Reason.CGROUP_V2_ABSENT)
    relative = records[0][4:]
    pure = PurePosixPath(relative)
    if pure.is_absolute() or not pure.parts or ".." in pure.parts:
        raise _Stop(L0Reason.HOST_FAILURE)
    return "/" + pure.as_posix(), Path("/sys/fs/cgroup", pure.as_posix())


def _loaded_apparmor_profiles() -> tuple[str, ...]:
    directory = Path("/sys/kernel/security/apparmor/policy/profiles")
    names: set[str] = set()
    for item in directory.iterdir():
        name = item.name.rsplit(".", 1)[0]
        if _IDENTIFIER.fullmatch(name):
            names.add(name)
    return tuple(sorted(names))


def _observe_host() -> _HostObservation:
    try:
        info = os.stat(RUNTIME_PATH, follow_symlinks=False)
    except FileNotFoundError as error:
        raise _Stop(L0Reason.RUNTIME_ABSENT) from error
    if not stat.S_ISREG(info.st_mode):
        raise _Stop(L0Reason.RUNTIME_MISMATCH)
    version = _runtime_output("--version")
    help_text = _runtime_output("--help")
    options = tuple(sorted(set(re.findall(r"(?m)^\s+(--[a-z0-9-]+)", help_text))))
    uname = os.uname()
    kernel = uname.release
    config_text = _read_text(f"/boot/config-{kernel}")
    kernel_features = tuple(
        sorted(
            name
            for name in _KERNEL_FEATURES
            if name in config_text
        )
    )
    user_namespaces = _read_text("/proc/sys/kernel/unprivileged_userns_clone", 16).strip() == "1"
    cgroup_path, cgroup_directory = _current_cgroup()
    mountinfo = _read_text("/proc/self/mountinfo")
    cgroup_v2 = any(" - cgroup2 " in line and " /sys/fs/cgroup " in line for line in mountinfo.splitlines())
    host_controllers = tuple(sorted(_read_text("/sys/fs/cgroup/cgroup.controllers", 4096).split()))
    controllers = tuple(sorted(_read_text(str(cgroup_directory / "cgroup.controllers"), 4096).split()))
    cgroup_delegated = os.access(cgroup_directory / "cgroup.subtree_control", os.W_OK)
    cgroup_processes = tuple(_read_text(str(cgroup_directory / "cgroup.procs"), 1 << 16).split())
    cgroup_isolated = cgroup_processes == (str(os.getpid()),)
    lsm_stack = tuple(item for item in _read_text("/sys/kernel/security/lsm", 4096).strip().split(",") if item)
    apparmor_enabled = _read_text("/sys/module/apparmor/parameters/enabled", 16).strip() == "Y"
    return _HostObservation(
        RUNTIME_PATH,
        version,
        _binary_digest(RUNTIME_PATH),
        info.st_uid,
        info.st_gid,
        stat.S_IMODE(info.st_mode),
        options,
        platform.system() == "Linux",
        uname.machine,
        kernel,
        kernel_features,
        user_namespaces,
        cgroup_v2,
        cgroup_path,
        host_controllers,
        controllers,
        cgroup_delegated,
        cgroup_isolated,
        lsm_stack,
        apparmor_enabled,
        _loaded_apparmor_profiles(),
        _openat2_available(),
    )


def _verify_host(profile: CompiledL0Profile, observed: _HostObservation) -> HostMeasurement:
    if type(profile) is not CompiledL0Profile or type(observed) is not _HostObservation:
        raise _Stop(L0Reason.MALFORMED_INPUT)
    if (
        observed.backend_path != profile.backend_path
        or observed.backend_version != profile.backend_version
        or observed.backend_digest != profile.backend_digest
        or observed.backend_uid != 0
        or observed.backend_gid != 0
        or observed.backend_mode != 0o755
    ):
        raise _Stop(L0Reason.RUNTIME_MISMATCH)
    required_options = {
        "--assert-userns-disabled",
        "--bind-fd",
        "--cap-drop",
        "--clearenv",
        "--die-with-parent",
        "--disable-userns",
        "--gid",
        "--new-session",
        "--proc",
        "--ro-bind-fd",
        "--seccomp",
        "--tmpfs",
        "--uid",
        "--unshare-all",
        "--unshare-cgroup",
        "--unshare-ipc",
        "--unshare-net",
        "--unshare-pid",
        "--unshare-user",
        "--unshare-uts",
    }
    if not required_options.issubset(observed.backend_options):
        raise _Stop(L0Reason.UNSUPPORTED_CONTROL)
    if (
        not observed.linux
        or observed.architecture != "x86_64"
        or frozenset(observed.kernel_features) != _KERNEL_FEATURES
    ):
        raise _Stop(L0Reason.HOST_UNSUPPORTED)
    if not observed.user_namespaces:
        raise _Stop(L0Reason.USER_NAMESPACE_ABSENT)
    required_controllers = {"cpu", "io", "memory", "pids"}
    if not observed.cgroup_v2 or not required_controllers.issubset(observed.host_cgroup_controllers):
        raise _Stop(L0Reason.CGROUP_V2_ABSENT)
    if (
        not required_controllers.issubset(observed.cgroup_controllers)
        or not observed.cgroup_delegated
        or not observed.cgroup_isolated
    ):
        raise _Stop(L0Reason.CGROUP_DELEGATION_ABSENT)
    if "apparmor" not in observed.lsm_stack or not observed.apparmor_enabled:
        raise _Stop(L0Reason.LSM_ABSENT)
    source = json.loads(profile.canonical_profile_json)
    policy_name = source["measurement_bindings"]["lsm_policy_name"]
    if policy_name not in observed.loaded_apparmor_profiles:
        raise _Stop(L0Reason.LSM_POLICY_ABSENT)
    if not observed.openat2:
        raise _Stop(L0Reason.OPENAT2_ABSENT)
    data = {
        "backend_path": observed.backend_path,
        "backend_version": observed.backend_version,
        "backend_digest": observed.backend_digest,
        "architecture": observed.architecture,
        "kernel_release": observed.kernel_release,
        "kernel_features": list(observed.kernel_features),
        "cgroup_path": observed.cgroup_path,
        "cgroup_controllers": list(observed.cgroup_controllers),
        "lsm_stack": list(observed.lsm_stack),
        "lsm_policy_name": policy_name,
        "openat2": observed.openat2,
        "user_namespaces": observed.user_namespaces,
        "profile_digest": profile.profile_digest,
    }
    return HostMeasurement(
        observed.backend_path,
        observed.backend_version,
        observed.backend_digest,
        observed.architecture,
        observed.kernel_release,
        observed.kernel_features,
        observed.cgroup_path,
        observed.cgroup_controllers,
        observed.lsm_stack,
        policy_name,
        observed.openat2,
        observed.user_namespaces,
        _hash_text(_canonical(data)),
    )


def host_preflight(raw: object) -> L0Result:
    """Compile and read-only verify this host; never launch a worker or effect."""

    compiled = compile_profile(raw)
    if compiled.outcome is not L0Outcome.COMPILED_DRAFT or compiled.profile is None:
        return L0Result(L0Outcome.STOP, compiled.reason)
    try:
        measurement = _verify_host(compiled.profile, _observe_host())
        return L0Result(L0Outcome.READY, L0Reason.HOST_VERIFIED, compiled.profile, measurement)
    except _Stop as stop:
        return L0Result(L0Outcome.STOP, stop.reason)
    except Exception:  # noqa: BLE001 - host/runtime failures must become STOP
        return L0Result(L0Outcome.STOP, L0Reason.HOST_FAILURE)


def runtime_conformance(raw_profile: object) -> ConformanceResult:
    """Report exact-profile conformance availability; never skip or weaken a blocker."""

    try:
        preflight = host_preflight(raw_profile)
        if preflight.outcome is not L0Outcome.READY:
            return ConformanceResult(L0Outcome.ABSENT, preflight.reason)
        # A ready host is necessary but cannot self-attest its supply, placement,
        # cleanup, and attack-test evidence.  The command remains ABSENT until an
        # external trust root and privileged conformance runner are supplied.
        return ConformanceResult(L0Outcome.ABSENT, L0Reason.CONFORMANCE_ABSENT)
    except Exception:  # noqa: BLE001 - exact gate is total and non-skipping
        return ConformanceResult(L0Outcome.ABSENT, L0Reason.HOST_FAILURE)


__all__ = [
    "ENVIRONMENT",
    "PROFILE_ID",
    "RUNTIME_DIGEST",
    "RUNTIME_PATH",
    "RUNTIME_VERSION",
    "WORKLOAD_CLASS",
    "BrokerMessage",
    "BrokerPeer",
    "BrokerResult",
    "CompiledL0Profile",
    "HostMeasurement",
    "L0Outcome",
    "L0Reason",
    "L0Result",
    "PathBinding",
    "PathResult",
    "PlacementMeasurement",
    "PlacementResult",
    "PrincipalPlan",
    "ResourceLimit",
    "RuntimeSessionRecord",
    "SessionPlan",
    "SessionResult",
    "StageRecord",
    "StageResult",
    "SupplyArtifactBinding",
    "SupplyResult",
    "SupplyVerification",
    "SupervisorResult",
    "ConformanceResult",
    "compile_profile",
    "host_preflight",
    "measure_placement",
    "prepare_session",
    "receive_broker_message",
    "resolve_target",
    "runtime_conformance",
    "stage_committed_intent",
    "supervise_session",
    "verify_supply",
]
