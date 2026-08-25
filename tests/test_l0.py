from __future__ import annotations

import os
import random
import socket
import subprocess
import tempfile
import time
import unittest
from copy import deepcopy
from dataclasses import FrozenInstanceError, is_dataclass, replace
from hashlib import sha256
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
        for name in (
            "Broker",
            "Capability",
            "Executor",
            "DispatchReceipt",
            "compile_profile",
            "host_preflight",
            "resolve_target",
            "receive_broker_message",
        ):
            self.assertFalse(hasattr(harness_product, name), name)


class L0PathBindingTests(unittest.TestCase):
    def profile(self) -> l0.CompiledL0Profile:
        result = l0.compile_profile(valid_raw())
        self.assertEqual(result.outcome, l0.L0Outcome.COMPILED_DRAFT)
        self.assertIsNotNone(result.profile)
        return result.profile

    @staticmethod
    def request(path: str = "/staging/artifact.txt") -> dict[str, object]:
        return {"canonical_path": path, "descriptor_id": "descriptor-1", "root_id": "root-1", "resolution_epoch": 1}

    def assert_path_stop(self, result: object, reason: l0.L0Reason | None = None) -> None:
        self.assertIs(type(result), l0.PathResult)
        self.assertEqual(result.outcome, l0.L0Outcome.STOP)
        if reason is not None:
            self.assertEqual(result.reason, reason)
        self.assertIsNone(result.binding)

    @staticmethod
    def open_root(base: str) -> tuple[str, int]:
        root = os.path.join(base, "root")
        os.mkdir(root, 0o700)
        os.chmod(root, 0o700)
        return root, os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)

    def test_resolve_target_returns_immutable_full_descriptor_root_mount_and_object_binding(self) -> None:
        profile = self.profile()
        with tempfile.TemporaryDirectory(prefix="harness-l0-path-") as base:
            root, descriptor = self.open_root(base)
            try:
                target_path = os.path.join(root, "artifact.txt")
                with open(target_path, "wb") as target:
                    target.write(b"payload")
                result = l0.resolve_target(profile, descriptor, self.request())
                self.assertEqual((result.outcome, result.reason), (l0.L0Outcome.RESOLVED, l0.L0Reason.PATH_RESOLVED))
                self.assertIs(type(result.binding), l0.PathBinding)
                binding = result.binding
                self.assertIsNotNone(binding)
                info = os.stat(target_path)
                self.assertEqual((binding.descriptor_id, binding.root_id, binding.resolution_epoch), ("descriptor-1", "root-1", 1))
                self.assertRegex(binding.root_identity, r"^sha256:[0-9a-f]{64}$")
                self.assertRegex(binding.mount_id, r"^mnt:[0-9]+$")
                self.assertRegex(binding.mount_identity, r"^sha256:[0-9a-f]{64}$")
                self.assertEqual((binding.final_device, binding.final_inode, binding.final_type), (info.st_dev, info.st_ino, "REGULAR_FILE"))
                self.assertEqual(binding.final_digest, "sha256:" + sha256(b"payload").hexdigest())
                self.assertRegex(binding.composite_binding_digest, r"^sha256:[0-9a-f]{64}$")
                self.assertTrue(type(binding).__dataclass_params__.frozen)
                with self.assertRaises((AttributeError, FrozenInstanceError)):
                    binding.root_id = "other-root"  # type: ignore[misc]
            finally:
                os.close(descriptor)

    def test_path_traversal_separator_confusables_and_forbidden_surfaces_stop_before_open(self) -> None:
        profile = self.profile()
        paths = (
            "/staging/../artifact.txt", "/staging/dir\\artifact.txt", "/staging/%2e%2e/artifact.txt",
            "/staging/dir\u2044artifact.txt", "/staging/dir\u2215artifact.txt", "/staging/dir\uff0fartifact.txt",
            "/staging/.git/config", "/staging/proc/self", "/staging//artifact.txt",
        )
        with tempfile.TemporaryDirectory(prefix="harness-l0-path-") as base:
            root, descriptor = self.open_root(base)
            try:
                with open(os.path.join(root, "artifact.txt"), "wb") as target:
                    target.write(b"payload")
                for path in paths:
                    with self.subTest(path=path):
                        self.assert_path_stop(l0.resolve_target(profile, descriptor, self.request(path)), l0.L0Reason.PATH_DENIED)
            finally:
                os.close(descriptor)

    def test_symlink_hardlink_missing_root_substitution_and_root_permissions_fail_closed(self) -> None:
        profile = self.profile()
        with tempfile.TemporaryDirectory(prefix="harness-l0-path-") as base:
            root, descriptor = self.open_root(base)
            try:
                target_path = os.path.join(root, "artifact.txt")
                with open(target_path, "wb") as target:
                    target.write(b"payload")
                os.symlink("artifact.txt", os.path.join(root, "linked.txt"))
                os.link(target_path, os.path.join(root, "hardlinked.txt"))
                for path, reason in (
                    ("/staging/linked.txt", l0.L0Reason.PATH_DENIED),
                    ("/staging/hardlinked.txt", l0.L0Reason.HARDLINK_DENIED),
                    ("/staging/missing.txt", l0.L0Reason.PATH_DENIED),
                ):
                    with self.subTest(path=path):
                        self.assert_path_stop(l0.resolve_target(profile, descriptor, self.request(path)), reason)
                file_descriptor = os.open(target_path, os.O_RDONLY | os.O_CLOEXEC)
                try:
                    self.assert_path_stop(l0.resolve_target(profile, file_descriptor, self.request()), l0.L0Reason.ROOT_MISMATCH)
                finally:
                    os.close(file_descriptor)
                os.chmod(root, 0o755)
                self.assert_path_stop(l0.resolve_target(profile, descriptor, self.request()), l0.L0Reason.ROOT_MISMATCH)
            finally:
                os.close(descriptor)

    def test_path_record_mutations_and_openat2_failure_are_rejected_without_binding(self) -> None:
        profile = self.profile()
        with tempfile.TemporaryDirectory(prefix="harness-l0-path-") as base:
            root, descriptor = self.open_root(base)
            try:
                with open(os.path.join(root, "artifact.txt"), "wb") as target:
                    target.write(b"payload")
                resolved = l0.resolve_target(profile, descriptor, self.request())
                self.assertIsNotNone(resolved.binding)
                record = resolved.binding.data()
                mutations: tuple[tuple[str, object], ...] = (
                    ("descriptor_id", "other-descriptor"), ("root_id", "other-root"), ("root_identity", digest("e")),
                    ("mount_id", "mnt:999999"), ("mount_identity", digest("f")),
                    ("resolution_epoch", 2), ("final_device", int(record["final_device"]) + 1),
                    ("final_inode", int(record["final_inode"]) + 1), ("final_type", "DIRECTORY"),
                    ("final_digest", digest("0")),
                )
                for field, value in mutations:
                    with self.subTest(field=field):
                        mutated = dict(record)
                        mutated[field] = value
                        with self.assertRaises(l0._Stop):
                            l0._parse_path_binding(mutated)
                with patch.object(l0, "_openat2", side_effect=OSError("blocked")):
                    self.assert_path_stop(l0.resolve_target(profile, descriptor, self.request()), l0.L0Reason.PATH_DENIED)
                self.assert_path_stop(l0.resolve_target(profile, True, self.request()), l0.L0Reason.MALFORMED_INPUT)
                self.assert_path_stop(l0.resolve_target(profile, descriptor, {"canonical_path": "/staging/artifact.txt"}))
            finally:
                os.close(descriptor)


class L0BrokerReceiveTests(unittest.TestCase):
    def profile(self) -> l0.CompiledL0Profile:
        result = l0.compile_profile(valid_raw())
        self.assertIsNotNone(result.profile)
        return result.profile

    @staticmethod
    def local_peer() -> dict[str, int]:
        return {"pid": os.getpid(), "uid": os.geteuid(), "gid": os.getegid(), "process_session": os.getsid(os.getpid())}

    def expected(self, profile: l0.CompiledL0Profile) -> dict[str, object]:
        worker = next(principal for principal in profile.principals if principal.role == "AGENT_WORKER")
        return {
            "operation_id": "write-report-v1", "worker_principal": worker.principal_id, "worker_session": worker.session_id,
            "nonce": "nonce-1", "fencing_epoch": 1, "binding_digest": profile.broker_binding_digest, "peer": self.local_peer(),
        }

    def packet(self, profile: l0.CompiledL0Profile, expected: dict[str, object]) -> dict[str, object]:
        proposal = {
            "evaluation_time": "2026-08-25T12:00:00Z",
            "proposal": {"operation_id": expected["operation_id"], "principal_id": expected["worker_principal"], "material_digest": digest("a"), "authority": {}},
            "manifest": {}, "policy": {}, "physical_ceiling": {}, "trusted_facts": {},
        }
        return {
            "message_version": "1", "operation_id": expected["operation_id"], "worker_principal": expected["worker_principal"],
            "worker_session": expected["worker_session"], "nonce": expected["nonce"], "fencing_epoch": expected["fencing_epoch"],
            "binding_digest": profile.broker_binding_digest, "proposal": proposal, "proposal_digest": l0._hash_text(l0._canonical(proposal)),
        }

    def receive(self, profile: l0.CompiledL0Profile, expected: dict[str, object], payload: bytes, *, socket_type: int = socket.SOCK_SEQPACKET, ancillary: list[tuple[int, int, bytes]] | None = None) -> l0.BrokerResult:
        sender, receiver = socket.socketpair(socket.AF_UNIX, socket_type)
        try:
            if ancillary is None:
                sender.send(payload)
            else:
                sender.sendmsg([payload], ancillary)
            return l0.receive_broker_message(profile, receiver.fileno(), expected)
        finally:
            sender.close()
            receiver.close()

    def assert_broker_stop(self, result: object, reason: l0.L0Reason | None = None) -> None:
        self.assertIs(type(result), l0.BrokerResult)
        self.assertEqual(result.outcome, l0.L0Outcome.STOP)
        if reason is not None:
            self.assertEqual(result.reason, reason)
        self.assertIsNone(result.peer)
        self.assertIsNone(result.message)

    def test_exact_bounded_canonical_packet_accepts_real_seqpacket_peer_credentials_and_session(self) -> None:
        profile = self.profile()
        expected = self.expected(profile)
        raw = self.packet(profile, expected)
        encoded = l0._canonical(raw).encode("utf-8")
        self.assertLessEqual(len(encoded), 1024)
        result = self.receive(profile, expected, encoded)
        self.assertEqual((result.outcome, result.reason), (l0.L0Outcome.ACCEPTED, l0.L0Reason.BROKER_MESSAGE_ACCEPTED))
        self.assertEqual(result.peer, l0.BrokerPeer(**self.local_peer()))
        self.assertIs(type(result.message), l0.BrokerMessage)
        self.assertEqual(result.message.proposal_json, l0._canonical(raw["proposal"]))
        self.assertEqual(result.message.proposal_digest, raw["proposal_digest"])

    def test_broker_rejects_stream_oversize_truncation_and_ancillary_file_descriptors(self) -> None:
        profile = self.profile()
        expected = self.expected(profile)
        good = l0._canonical(self.packet(profile, expected)).encode("utf-8")
        self.assert_broker_stop(self.receive(profile, expected, good, socket_type=socket.SOCK_STREAM), l0.L0Reason.BROKER_BINDING_MISMATCH)
        self.assert_broker_stop(self.receive(profile, expected, b"x" * 1026), l0.L0Reason.MESSAGE_TOO_LARGE)
        descriptor = os.open(os.devnull, os.O_RDONLY | os.O_CLOEXEC)
        try:
            ancillary = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, descriptor.to_bytes(4, "little", signed=True))]
            self.assert_broker_stop(self.receive(profile, expected, good, ancillary=ancillary), l0.L0Reason.MESSAGE_TOO_LARGE)
        finally:
            os.close(descriptor)

    def test_broker_rejects_peer_expected_and_all_exact_message_binding_substitutions(self) -> None:
        profile = self.profile()
        expected = self.expected(profile)
        raw = self.packet(profile, expected)
        wrong_peer = deepcopy(expected)
        wrong_peer["peer"]["pid"] = int(wrong_peer["peer"]["pid"]) + 1
        self.assert_broker_stop(self.receive(profile, wrong_peer, l0._canonical(raw).encode("utf-8")), l0.L0Reason.PEER_MISMATCH)
        mutations: list[dict[str, object]] = []
        for field, value in (
            ("operation_id", "other-operation"), ("worker_principal", "other-principal"), ("worker_session", "other-session"),
            ("nonce", "other-nonce"), ("fencing_epoch", 2), ("binding_digest", digest("b")), ("proposal_digest", digest("c")),
        ):
            changed = deepcopy(raw)
            changed[field] = value
            mutations.append(changed)
        changed_proposal = deepcopy(raw)
        changed_proposal["proposal"]["proposal"]["principal_id"] = "other-principal"
        changed_proposal["proposal_digest"] = l0._hash_text(l0._canonical(changed_proposal["proposal"]))
        mutations.append(changed_proposal)
        for changed in mutations:
            with self.subTest(changed=changed):
                self.assert_broker_stop(
                    self.receive(profile, expected, l0._canonical(changed).encode("utf-8")), l0.L0Reason.BROKER_BINDING_MISMATCH
                )
        unknown = deepcopy(raw)
        unknown["ambient_authority"] = True
        self.assert_broker_stop(
            self.receive(profile, expected, l0._canonical(unknown).encode("utf-8")), l0.L0Reason.UNKNOWN_INPUT
        )


if __name__ == "__main__":
    unittest.main()
