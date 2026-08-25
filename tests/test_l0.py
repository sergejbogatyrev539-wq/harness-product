from __future__ import annotations

import os
import random
import socket
import subprocess
import time
import unittest
from copy import deepcopy
from dataclasses import is_dataclass, replace
from unittest.mock import patch

import harness_product
import harness_product.l0 as l0  # noqa: PLR0402 - exercise the direct submodule boundary


def digest(character: str) -> str:
    return "sha256:" + character * 64


def active_principal(role: str, number: int) -> dict[str, object]:
    return {
        "role": role,
        "principal_id": f"{role.lower()}-{number}",
        "enabled": True,
        "uid": 1000 + number,
        "gid": 2000 + number,
        "user_namespace": f"user-ns-{number}",
        "mount_namespace": f"mount-ns-{number}",
        "pid_namespace": f"pid-ns-{number}",
        "ipc_namespace": f"ipc-ns-{number}",
        "uts_namespace": f"uts-ns-{number}",
        "network_namespace": f"network-ns-{number}",
        "cgroup_namespace": f"cgroup-ns-{number}",
        "security_label": f"label-{number}",
        "credential_namespace": f"credentials-{number}",
        "session_id": f"session-{number}",
        "network_mode": l0._ROLE_NETWORK[role],
        "credential_mode": "NONE",
        "ambient_authority": False,
        "effect_ceiling": sorted(l0._ROLE_EFFECTS[role]),
        "fd_allowlist": sorted(l0._ROLE_FDS[role]),
    }


def disabled_principal(role: str, number: int) -> dict[str, object]:
    return {
        "role": role,
        "principal_id": f"{role.lower()}-{number}",
        "enabled": False,
        "network_mode": "NONE",
        "credential_mode": "NONE",
        "ambient_authority": False,
        "effect_ceiling": [],
        "fd_allowlist": [],
    }


def resources() -> list[dict[str, object]]:
    limits = {
        "CPU_TIME": 10,
        "CPU_RATE": 10,
        "WALL_TIME": 10,
        "MEMORY": 10,
        "SWAP": 0,
        "PIDS": 2,
        "BLOCK_IO_READ": 10,
        "BLOCK_IO_WRITE": 10,
        "FILES": 8,
        "INODES": 8,
        "OPEN_FDS": 4,
        "OUTPUT_BYTES": 10,
        "GPU_TIME": 0,
        "GPU_MEMORY": 0,
    }
    return [
        {
            "resource": name,
            "unit": l0._RESOURCE_SPEC[name][0],
            "limit": limits[name],
            "enforcement": l0._RESOURCE_SPEC[name][1],
        }
        for name in l0._RESOURCE_ORDER
    ]


def valid_raw() -> dict[str, object]:
    principals = [
        active_principal("AGENT_WORKER", 1),
        active_principal("BROKER", 2),
        active_principal("EXECUTOR", 3),
        disabled_principal("MODEL_GATEWAY", 4),
        disabled_principal("OBSERVER", 5),
    ]
    message_digest = digest("a")
    return {
        "profile_id": l0.PROFILE_ID,
        "profile_version": "1.0.0",
        "status": "DRAFT",
        "workload_class": l0.WORKLOAD_CLASS,
        "environment": l0.ENVIRONMENT,
        "risk_class": "LOCAL_STAGEABLE",
        "data_class": "SYNTHETIC",
        "backend": {"path": l0.RUNTIME_PATH, "version": l0.RUNTIME_VERSION, "digest": l0.RUNTIME_DIGEST},
        "principals": principals,
        "worker_controls": {
            "namespaces": sorted(l0._NAMESPACES),
            "non_host_uid_gid": True,
            "no_new_privileges": True,
            "capabilities": [],
            "seccomp": "DENY_DEFAULT_ALLOWLIST",
            "lsm": "APPARMOR",
            "mount_propagation": "PRIVATE_NON_PROPAGATING",
            "rootfs": "MINIMAL_READ_ONLY",
            "inputs": "DECLARED_READ_ONLY",
            "outputs": "NO_WORKER_OUTPUT",
            "staging_output_count": 1,
            "checkout_visible": False,
            "git_visible": False,
            "host_home_visible": False,
            "runtime_socket_visible": False,
            "durable_db_visible": False,
            "close_fds": True,
            "proc_mode": "PRIVATE_RESTRICTED",
            "ptrace": False,
            "devices": [],
            "ebpf": False,
            "modules": False,
            "admin": False,
            "shared_memory": "PRIVATE_EMPTY",
            "wall_time_supervisor": True,
            "path_resolution": sorted(l0._OPENAT2_FLAGS),
        },
        "network": {key: key == "broker_ipc_only" for key in l0._NETWORK_KEYS},
        "broker_ipc": {
            "worker_principal": principals[0]["principal_id"],
            "broker_principal": principals[1]["principal_id"],
            "worker_endpoint": "worker-ipc-endpoint",
            "broker_endpoint": "broker-ipc-endpoint",
            "transport": "UNIX_SEQPACKET",
            "peer_credentials": "SO_PEERCRED_REQUIRED",
            "operation_scoped": True,
            "max_message_bytes": 1024,
            "message_schema_digest": message_digest,
        },
        "resources": resources(),
        "measurement_bindings": {
            "rootfs_manifest_digest": digest("b"),
            "seccomp_profile_digest": digest("c"),
            "lsm_policy_name": "harness-l0-lx-a",
            "lsm_policy_digest": digest("d"),
            "broker_message_schema_digest": message_digest,
        },
        "denied_surfaces": sorted(l0._DENIED_SURFACES),
    }


class L0CompilerTests(unittest.TestCase):
    def assert_stop(self, result: object) -> None:
        self.assertTrue(is_dataclass(result), type(result))
        self.assertTrue(type(result).__dataclass_params__.frozen)
        self.assertEqual(result.outcome, l0.L0Outcome.STOP)
        self.assertIsInstance(result.reason, l0.L0Reason)
        self.assertIsNone(result.profile)
        self.assertIsNone(result.measurement)

    def compiled(self, raw: object | None = None) -> l0.CompiledL0Profile:
        result = l0.compile_profile(valid_raw() if raw is None else raw)
        self.assertEqual((result.outcome, result.reason), (l0.L0Outcome.COMPILED_DRAFT, l0.L0Reason.PROFILE_COMPILED))
        self.assertIs(type(result.profile), l0.CompiledL0Profile)
        self.assertIsNone(result.measurement)
        return result.profile

    def test_compile_is_deterministic_and_normalizes_field_and_resource_order(self) -> None:
        raw = valid_raw()
        first = self.compiled(raw)
        reordered = dict(reversed(list(raw.items())))
        reordered["principals"] = list(reversed(raw["principals"]))
        reordered["resources"] = list(reversed(raw["resources"]))
        reordered["denied_surfaces"] = list(reversed(raw["denied_surfaces"]))
        for row in reordered["resources"]:
            row_copy = dict(reversed(list(row.items())))
            row.clear()
            row.update(row_copy)
        second = self.compiled(reordered)
        self.assertEqual(first, second)
        self.assertEqual(tuple(item.resource for item in first.resources), l0._RESOURCE_ORDER)
        self.assertRegex(first.profile_digest, r"^sha256:[0-9a-f]{64}$")
        self.assertRegex(first.resource_vector_digest, r"^sha256:[0-9a-f]{64}$")

    def test_closed_hostile_and_unbounded_inputs_stop_without_exception(self) -> None:
        class ExplodingDict(dict):
            def keys(self):
                raise AssertionError("subclasses must not be traversed")

        cases: list[object] = []
        missing = valid_raw()
        del missing["network"]
        cases.append(missing)
        extra = valid_raw()
        extra["future_backend"] = "ambient"
        cases.append(extra)
        unknown = valid_raw()
        unknown["resources"][0]["resource"] = "TOKEN_BUCKET"
        cases.append(unknown)
        malformed = valid_raw()
        malformed["profile_version"] = 1
        cases.append(malformed)
        overflow = valid_raw()
        overflow["resources"][0]["limit"] = 1 << 63
        cases.append(overflow)
        boolean = valid_raw()
        boolean["resources"][0]["limit"] = True
        cases.append(boolean)
        cyclic = valid_raw()
        cyclic["worker_controls"] = cyclic
        cases.append(cyclic)
        cases.append(ExplodingDict(valid_raw()))

        for raw in cases:
            with self.subTest(raw=raw):
                self.assert_stop(l0.compile_profile(raw))

    def test_exact_five_roles_active_subject_uniqueness_and_disabled_shapes(self) -> None:
        duplicate_role = valid_raw()
        duplicate_role["principals"][4] = disabled_principal("MODEL_GATEWAY", 5)
        shared_subject = valid_raw()
        shared_subject["principals"][2]["credential_namespace"] = shared_subject["principals"][1]["credential_namespace"]
        disabled_subject = valid_raw()
        disabled_subject["principals"][3]["uid"] = 99
        observer_subject = valid_raw()
        observer_subject["principals"][4]["session_id"] = "forbidden-observer-session"
        disabled_enabled = valid_raw()
        disabled_enabled["principals"][4]["enabled"] = True
        missing_role = valid_raw()
        missing_role["principals"].pop()
        for raw in (
            duplicate_role,
            shared_subject,
            disabled_subject,
            observer_subject,
            disabled_enabled,
            missing_role,
        ):
            with self.subTest(raw=raw):
                self.assert_stop(l0.compile_profile(raw))

    def test_worker_network_fd_effect_and_direct_mutation_invariants_are_exact(self) -> None:
        cases: list[dict[str, object]] = []
        worker_network = valid_raw()
        worker_network["principals"][0]["network_mode"] = "BROKER_MEDIATED"
        cases.append(worker_network)
        worker_effect = valid_raw()
        worker_effect["principals"][0]["effect_ceiling"] = ["COMPUTE", "MUTATE", "OBSERVE"]
        cases.append(worker_effect)
        worker_fd = valid_raw()
        worker_fd["principals"][0]["fd_allowlist"].append("INHERITED_SOCKET")
        cases.append(worker_fd)
        direct_mutate = valid_raw()
        direct_mutate["worker_controls"]["outputs"] = "WRITE_STAGING"
        cases.append(direct_mutate)
        ipv6 = valid_raw()
        ipv6["network"]["ipv6"] = True
        cases.append(ipv6)
        missing_deny = valid_raw()
        missing_deny["denied_surfaces"].remove("WORKER_DIRECT_MUTATE")
        cases.append(missing_deny)
        for raw in cases:
            with self.subTest(raw=raw):
                self.assert_stop(l0.compile_profile(raw))

    def test_broker_ipc_is_exact_seqpacket_and_bound_to_distinct_worker_and_broker(self) -> None:
        cases: list[dict[str, object]] = []
        transport = valid_raw()
        transport["broker_ipc"]["transport"] = "UNIX_STREAM"
        cases.append(transport)
        endpoint = valid_raw()
        endpoint["broker_ipc"]["broker_endpoint"] = endpoint["broker_ipc"]["worker_endpoint"]
        cases.append(endpoint)
        principal = valid_raw()
        principal["broker_ipc"]["broker_principal"] = principal["broker_ipc"]["worker_principal"]
        cases.append(principal)
        operation = valid_raw()
        operation["broker_ipc"]["operation_scoped"] = False
        cases.append(operation)
        oversized = valid_raw()
        oversized["broker_ipc"]["max_message_bytes"] = (1 << 20) + 1
        cases.append(oversized)
        for raw in cases:
            with self.subTest(raw=raw):
                self.assert_stop(l0.compile_profile(raw))

    def test_q56_vector_is_exact_closed_and_gpu_paired(self) -> None:
        cases: list[dict[str, object]] = []
        missing = valid_raw()
        missing["resources"].pop()
        cases.append(missing)
        duplicate = valid_raw()
        duplicate["resources"][-1] = deepcopy(duplicate["resources"][0])
        cases.append(duplicate)
        wrong_unit = valid_raw()
        wrong_unit["resources"][0]["unit"] = "BYTES"
        cases.append(wrong_unit)
        wrong_enforcer = valid_raw()
        wrong_enforcer["resources"][0]["enforcement"] = "SUPERVISOR"
        cases.append(wrong_enforcer)
        gpu_half = valid_raw()
        gpu_half["resources"][-1]["limit"] = 1
        cases.append(gpu_half)
        inodes = valid_raw()
        inodes["resources"][9]["limit"] = 7
        cases.append(inodes)
        for raw in cases:
            with self.subTest(raw=raw):
                self.assert_stop(l0.compile_profile(raw))

    def test_measurement_bindings_are_closed_and_match_broker_schema_digest(self) -> None:
        mismatch = valid_raw()
        mismatch["measurement_bindings"]["broker_message_schema_digest"] = digest("e")
        unknown = valid_raw()
        unknown["measurement_bindings"]["host_measurement"] = digest("f")
        wrong_policy = valid_raw()
        wrong_policy["measurement_bindings"]["lsm_policy_name"] = "other-policy"
        for raw in (mismatch, unknown, wrong_policy):
            with self.subTest(raw=raw):
                self.assert_stop(l0.compile_profile(raw))

    def test_compile_profile_has_no_runtime_effect_surface(self) -> None:
        forbidden = AssertionError("pure compiler attempted a host or external effect")
        with (
            patch("builtins.open", side_effect=forbidden),
            patch.object(os, "open", side_effect=forbidden),
            patch.object(os, "read", side_effect=forbidden),
            patch.object(os, "getenv", side_effect=forbidden),
            patch.object(subprocess, "run", side_effect=forbidden),
            patch.object(socket, "socket", side_effect=forbidden),
            patch.object(random, "random", side_effect=forbidden),
            patch.object(time, "time", side_effect=forbidden),
        ):
            self.compiled()

    def observation(self) -> l0._HostObservation:
        return l0._HostObservation(
            l0.RUNTIME_PATH,
            l0.RUNTIME_VERSION,
            l0.RUNTIME_DIGEST,
            0,
            0,
            0o755,
            (
                "--assert-userns-disabled", "--bind-fd", "--cap-drop", "--clearenv", "--die-with-parent",
                "--disable-userns", "--gid", "--new-session", "--proc", "--ro-bind-fd", "--seccomp",
                "--tmpfs", "--uid", "--unshare-all", "--unshare-cgroup", "--unshare-ipc", "--unshare-net",
                "--unshare-pid", "--unshare-user", "--unshare-uts",
            ),
            True,
            "x86_64",
            "test-kernel",
            (
                "CONFIG_CGROUPS=y", "CONFIG_SECCOMP=y", "CONFIG_SECCOMP_FILTER=y",
                "CONFIG_SECURITY_APPARMOR=y", "CONFIG_USER_NS=y",
            ),
            True,
            True,
            "/test.slice",
            ("cpu", "io", "memory", "pids"),
            ("cpu", "io", "memory", "pids"),
            True,
            True,
            ("capability", "apparmor"),
            True,
            ("harness-l0-lx-a",),
            True,
        )

    def test_patched_ready_preflight_returns_exact_measurement(self) -> None:
        with patch.object(l0, "_observe_host", return_value=self.observation()):
            result = l0.host_preflight(valid_raw())
        self.assertEqual((result.outcome, result.reason), (l0.L0Outcome.READY, l0.L0Reason.HOST_VERIFIED))
        self.assertIs(type(result.profile), l0.CompiledL0Profile)
        self.assertIs(type(result.measurement), l0.HostMeasurement)
        self.assertEqual(result.measurement.backend_digest, l0.RUNTIME_DIGEST)

    def test_host_preflight_fail_closes_each_runtime_blocker_and_exception(self) -> None:
        changes: tuple[tuple[l0.L0Reason, dict[str, object]], ...] = (
            (l0.L0Reason.RUNTIME_MISMATCH, {"backend_digest": digest("f")} ),
            (l0.L0Reason.UNSUPPORTED_CONTROL, {"backend_options": ()}),
            (l0.L0Reason.HOST_UNSUPPORTED, {"linux": False}),
            (l0.L0Reason.USER_NAMESPACE_ABSENT, {"user_namespaces": False}),
            (l0.L0Reason.CGROUP_V2_ABSENT, {"cgroup_v2": False}),
            (l0.L0Reason.CGROUP_DELEGATION_ABSENT, {"cgroup_delegated": False}),
            (l0.L0Reason.LSM_ABSENT, {"lsm_stack": ()}),
            (l0.L0Reason.LSM_POLICY_ABSENT, {"loaded_apparmor_profiles": ()}),
            (l0.L0Reason.OPENAT2_ABSENT, {"openat2": False}),
        )
        for reason, changeset in changes:
            with self.subTest(reason=reason):
                observed = replace(self.observation(), **changeset)
                with patch.object(l0, "_observe_host", return_value=observed):
                    result = l0.host_preflight(valid_raw())
                self.assert_stop(result)
                self.assertEqual(result.reason, reason)

        for side_effect, reason in (
            (l0._Stop(l0.L0Reason.RUNTIME_ABSENT), l0.L0Reason.RUNTIME_ABSENT),
            (RuntimeError("host probe failed"), l0.L0Reason.HOST_FAILURE),
        ):
            with self.subTest(reason=reason):
                with patch.object(l0, "_observe_host", side_effect=side_effect):
                    result = l0.host_preflight(valid_raw())
                self.assert_stop(result)
                self.assertEqual(result.reason, reason)

    def test_live_host_preflight_is_only_a_structured_ready_or_stop_observation(self) -> None:
        result = l0.host_preflight(valid_raw())
        self.assertIn(result.outcome, {l0.L0Outcome.READY, l0.L0Outcome.STOP})
        if result.outcome is l0.L0Outcome.READY:
            self.assertIs(type(result.profile), l0.CompiledL0Profile)
            self.assertIs(type(result.measurement), l0.HostMeasurement)
        else:
            self.assert_stop(result)

    def test_root_package_remains_m1_only_and_has_no_executor_or_l0_compiler_exports(self) -> None:
        for name in ("Broker", "Capability", "Executor", "DispatchReceipt", "compile_profile", "host_preflight"):
            self.assertFalse(hasattr(harness_product, name), name)


if __name__ == "__main__":
    unittest.main()
