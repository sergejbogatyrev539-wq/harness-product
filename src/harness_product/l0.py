"""Exact, fail-closed L0-LX-A profile compiler and host preflight.

This module is milestone M3's Linux boundary.  Compilation is deterministic and
non-effectful.  Host preflight performs read-only measurement only; it never
creates a namespace, cgroup, socket, process tree, worker, or filesystem effect.
The only selected runtime backend is the exact bubblewrap binary pinned below.
"""

from __future__ import annotations

import ctypes
import errno
import json
import os
import platform
import re
import stat
import subprocess
import unicodedata
from dataclasses import dataclass
from enum import Enum
from hashlib import sha256
from pathlib import Path, PurePosixPath

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


class L0Outcome(str, Enum):
    COMPILED_DRAFT = "COMPILED_DRAFT"
    READY = "READY"
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


__all__ = [
    "ENVIRONMENT",
    "PROFILE_ID",
    "RUNTIME_DIGEST",
    "RUNTIME_PATH",
    "RUNTIME_VERSION",
    "WORKLOAD_CLASS",
    "CompiledL0Profile",
    "HostMeasurement",
    "L0Outcome",
    "L0Reason",
    "L0Result",
    "PrincipalPlan",
    "ResourceLimit",
    "compile_profile",
    "host_preflight",
]
