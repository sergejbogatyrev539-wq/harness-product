"""Contract tests for the closed L0 worker-session planning boundary.

The fixture contains only disposable files below a temporary directory.  Tests
compile and measure a prospective launch record; they never invoke bubblewrap,
connect the broker, create a cgroup, or start a worker.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from hashlib import sha256
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import harness_product.l0 as l0
from harness_product.durable import DispatchClaim, DurableStore, VerificationResult, VerificationStatus
from tests import test_l0 as l0_tests


def _digest_bytes(value: bytes) -> str:
    return "sha256:" + sha256(value).hexdigest()


def _digest_text(value: str) -> str:
    return _digest_bytes(value.encode("utf-8"))


def _canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


class ExactExternalVerifier:
    """A test-only external boundary pinned to one canonical payload family."""

    source = {
        "verifier_id": "external-verifier-1",
        "issuer_id": "external-issuer-1",
        "key_id": "external-key-1",
        "proof": "external-proof-1",
    }

    def __init__(self, expected: dict[str, object]) -> None:
        self.expected = expected
        self.calls: list[tuple[bytes, bytes, str]] = []

    def verify(self, payload: bytes, record: bytes, observed_at: str) -> VerificationResult:
        self.calls.append((payload, record, observed_at))
        payload_digest = _digest_bytes(payload)
        record_digest = _digest_bytes(record)
        try:
            payload_value = json.loads(payload)
            record_value = json.loads(record)
        except (UnicodeDecodeError, json.JSONDecodeError):
            payload_value = record_value = None
        valid = (
            type(payload_value) is dict
            and type(record_value) is dict
            and frozenset(record_value)
            == {"verification_version", "verifier_id", "issuer_id", "key_id", "payload_digest", "bindings", "proof"}
            and record_value.get("verification_version") == 1
            and record_value.get("bindings") == payload_value
            and record_value.get("payload_digest") == payload_digest
            and all(record_value.get(key) == value for key, value in self.source.items())
            and payload_value == self.expected
            and payload_value.get("signer", {}).get("signer_id") != record_value.get("issuer_id")
        )
        return VerificationResult(
            VerificationStatus.VERIFIED if valid else VerificationStatus.REJECTED,
            self.source["verifier_id"],
            payload_digest,
            record_digest,
        )


def _claim(
    profile: l0.CompiledL0Profile,
    placement_digest: str,
    *,
    transaction_id: str = "transaction-1",
) -> DispatchClaim:
    worker = next(item for item in profile.principals if item.role == "AGENT_WORKER")
    executor = next(item for item in profile.principals if item.role == "EXECUTOR")
    request = {
        "proposal": {
            "operation_id": "write-report-v1",
            "principal_id": worker.principal_id,
            "material_digest": _digest_text("material-1"),
            "authority": {},
        }
    }
    capability_payload = {
        "issued_at": "2026-08-25T12:00:00Z",
        "expires_at": "2026-08-25T12:10:00Z",
    }
    bindings = {
        "claim_version": 1,
        "transaction_id": transaction_id,
        "capability_id": "capability-1",
        "intent_digest": _digest_text("intent-1"),
        "idempotency_key_digest": _digest_text("idempotency-1"),
        "principal_id": worker.principal_id,
        "audience_id": executor.principal_id,
        "purpose": "stageable-write",
        "profile_digest": profile.profile_digest,
        "placement_digest": placement_digest,
        "session_id": worker.session_id,
        "lineage_root": _digest_text("lineage-1"),
        "nonce": "nonce-1",
        "revocation_epoch": 7,
        "fencing_epoch": 11,
        "observed_at": "2026-08-25T12:02:00Z",
        "target_scope_digest": _digest_text("target-1"),
        "material_digest": _digest_text("material-1"),
        "request": request,
        "decision": {},
        "authorized_envelope": {},
        "capability_payload": capability_payload,
        "capability_verification": {},
        "intent": {},
    }
    claim_json = _canonical(bindings)
    claim_digest = _digest_text(claim_json)
    verification_json = _canonical(
        {
            "verification_version": 1,
            **ExactExternalVerifier.source,
            "payload_digest": claim_digest,
            "bindings": bindings,
        }
    )
    return DispatchClaim(
        transaction_id,
        claim_digest,
        bindings["intent_digest"],
        bindings["capability_id"],
        bindings["idempotency_key_digest"],
        worker.principal_id,
        executor.principal_id,
        bindings["purpose"],
        profile.profile_digest,
        placement_digest,
        worker.session_id,
        bindings["lineage_root"],
        bindings["nonce"],
        7,
        11,
        bindings["observed_at"],
        bindings["target_scope_digest"],
        bindings["material_digest"],
        _canonical(request),
        _canonical({}),
        _canonical({}),
        _canonical(capability_payload),
        _canonical({}),
        _canonical({}),
        claim_json,
        verification_json,
    )


class WorkerSessionPlanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="harness-l0-session-")
        self.descriptors: list[int] = []
        self.sockets: list[socket.socket] = []

    def tearDown(self) -> None:
        for current in self.sockets:
            current.close()
        for descriptor in self.descriptors:
            try:
                os.close(descriptor)
            except OSError:
                pass
        self.temporary.cleanup()

    def _open_readonly_file(self, path: Path, content: bytes) -> int:
        path.write_bytes(content)
        os.chmod(path, 0o444)
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        self.descriptors.append(descriptor)
        return descriptor

    def _readonly_directory(self, path: Path) -> int:
        os.chmod(path, 0o555)
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        self.descriptors.append(descriptor)
        return descriptor

    def _measurement(self, profile: l0.CompiledL0Profile) -> l0.HostMeasurement:
        return l0._verify_host(profile, l0_tests.L0CompilerTests().observation())

    def fixture(
        self,
    ) -> tuple[l0.CompiledL0Profile, l0.HostMeasurement, l0.SupplyVerification, DispatchClaim, dict[str, object]]:
        root = Path(self.temporary.name)
        contents = {
            "ROOTFS_MANIFEST": b"rootfs-manifest-v1\n",
            "LOADER": b"loader-v1\n",
            "DEPENDENCY_CLOSURE": b"dependency-closure-v1\n",
            "TOOL": b"worker-tool-v1\n",
            "SBOM": b"sbom-v1\n",
            "REGISTRY_SNAPSHOT": b"registry-snapshot-v7\n",
            "SECCOMP_PROFILE": b"seccomp-v1\n",
            "LSM_POLICY": b"lsm-v1\n",
        }
        artifacts: list[dict[str, object]] = []
        by_role: dict[str, int] = {}
        artifact_root = root / "artifacts"
        artifact_root.mkdir(mode=0o700)
        for role, content in contents.items():
            descriptor = self._open_readonly_file(artifact_root / role.lower(), content)
            by_role[role] = descriptor
            artifacts.append(
                {
                    "role": role,
                    "artifact_id": role.lower(),
                    "descriptor": descriptor,
                    "expected_bytes_digest": _digest_bytes(content),
                    "provenance_digest": _digest_text("provenance:" + role),
                }
            )

        profile_raw = l0_tests.valid_raw()
        profile_raw["measurement_bindings"].update(
            rootfs_manifest_digest=_digest_bytes(contents["ROOTFS_MANIFEST"]),
            seccomp_profile_digest=_digest_bytes(contents["SECCOMP_PROFILE"]),
            lsm_policy_digest=_digest_bytes(contents["LSM_POLICY"]),
        )
        compiled = l0.compile_profile(profile_raw)
        self.assertIsNotNone(compiled.profile)
        profile = compiled.profile
        measurement = self._measurement(profile)
        worker = next(item for item in profile.principals if item.role == "AGENT_WORKER")
        executor = next(item for item in profile.principals if item.role == "EXECUTOR")
        user_namespace_fd = os.open("/proc/self/ns/user", os.O_RDONLY | os.O_CLOEXEC)
        self.descriptors.append(user_namespace_fd)
        user_namespace_identity = os.readlink(f"/proc/self/fd/{user_namespace_fd}")

        rootfs = root / "rootfs"
        for relative in (
            "inputs", "lib", "lib64", "proc", "run", "usr/lib/harness", "workspace",
        ):
            (rootfs / relative).mkdir(parents=True, exist_ok=True, mode=0o755)
        tool_placeholder = rootfs / "usr/lib/harness/worker-tool"
        tool_placeholder.write_bytes(contents["TOOL"])
        os.chmod(tool_placeholder, 0o444)
        for directory in (rootfs, *[item for item in rootfs.rglob("*") if item.is_dir()]):
            os.chmod(directory, 0o555)
        root_fd = self._readonly_directory(rootfs)
        input_fd = self._open_readonly_file(root / "input-1", b"synthetic-input-v1\n")

        worker_socket, broker_socket = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        broker_socket.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        self.sockets.extend((worker_socket, broker_socket))

        staging = root / "staging"
        staging.mkdir(mode=0o700)
        staging_fd = os.open(staging, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        _, staging_mount, staging_identity, staging_mount_identity = l0._root_identity(staging_fd)
        os.close(staging_fd)

        gate_read, gate_write = os.pipe2(os.O_CLOEXEC)
        worker_start_read, worker_start_write = os.pipe2(os.O_CLOEXEC)
        status_read, status_write = os.pipe2(os.O_CLOEXEC)
        self.descriptors.extend(
            (gate_read, gate_write, worker_start_read, worker_start_write, status_read, status_write)
        )

        placeholder_claim = _claim(profile, _digest_text("placement-placeholder"))
        raw = {
            "session_version": "1.1.0",
            "session_record_id": "session-record-1",
            "session_id": worker.session_id,
            "transaction_id": placeholder_claim.transaction_id,
            "claim_digest": placeholder_claim.claim_digest,
            "lineage_root": placeholder_claim.lineage_root,
            "fencing_epoch": placeholder_claim.fencing_epoch,
            "revocation_epoch": placeholder_claim.revocation_epoch,
            "worker_principal": worker.principal_id,
            "executor_principal": executor.principal_id,
            "subject_instance_id": "worker-instance-1",
            "process_tree_id": "worker-tree-1",
            "namespace_ids": {
                "user": worker.user_namespace,
                "mount": worker.mount_namespace,
                "pid": worker.pid_namespace,
                "ipc": worker.ipc_namespace,
                "uts": worker.uts_namespace,
                "network": worker.network_namespace,
                "cgroup": worker.cgroup_namespace,
            },
            "user_namespace": {
                "descriptor": user_namespace_fd,
                "descriptor_id": "worker-userns-1",
                "identity": user_namespace_identity,
                "uid_map": f"0 100000 1\n{worker.uid} 3001 1\n",
                "gid_map": f"0 200000 1\n{worker.gid} 4001 1\n",
                "setgroups": "deny",
                "max_user_namespaces": 0,
            },
            "rootfs": {"descriptor": root_fd, "descriptor_id": "rootfs-1"},
            "inputs": [{"descriptor": input_fd, "descriptor_id": "input-1", "mount_path": "/inputs/input-1", "expected_bytes_digest": _digest_bytes(b"synthetic-input-v1\n")}],
            "broker_ipc": {
                "worker_descriptor": worker_socket.fileno(),
                "worker_descriptor_id": "worker-pair-end-1",
                "broker_descriptor": broker_socket.fileno(),
                "broker_descriptor_id": "broker-pair-end-1",
                "worker_endpoint": "worker-ipc-endpoint",
                "broker_endpoint": "broker-ipc-endpoint",
                "transport": "UNIX_SEQPACKET",
                "endpoint_mode": "UNIX_CONNECTED_PAIR",
                "operation_id": "write-report-v1",
                "nonce": "nonce-1",
                "fencing_epoch": 11,
                "revocation_epoch": 7,
                "issued_at": "2026-08-25T12:00:00Z",
                "expires_at": "2026-08-25T12:10:00Z",
            },
            "seccomp": {"descriptor": by_role["SECCOMP_PROFILE"], "descriptor_id": "seccomp-1", "expected_bytes_digest": _digest_bytes(contents["SECCOMP_PROFILE"])},
            "tool": {"descriptor": by_role["TOOL"], "descriptor_id": "tool-1", "path": "/usr/lib/harness/worker-tool", "argv": ["/usr/lib/harness/worker-tool", "--broker-fd", "1", "--session", worker.session_id], "expected_bytes_digest": _digest_bytes(contents["TOOL"])},
            "cgroup": {"path": measurement.cgroup_path.rstrip("/") + "/session-1", "controllers": ["cpu", "io", "memory", "pids"], "device_major": 259, "device_minor": 2, "delegated": True, "identity_digest": _digest_text("cgroup-session-1")},
            "staging": {"root_id": "staging-root-1", "root_identity": staging_identity, "mount_id": f"mnt:{staging_mount}", "mount_identity": staging_mount_identity, "files": 16, "inodes": 32, "bytes": 4096},
            "supervisor_fds": {
                "gate_read": gate_read,
                "gate_write": gate_write,
                "worker_start_read": worker_start_read,
                "worker_start_write": worker_start_write,
                "status_read": status_read,
                "status_write": status_write,
            },
            "cleanup": {"cleanup_id": "cleanup-1", "staging_root_id": "staging-root-1", "reuse_forbidden": True, "require_cgroup_empty": True, "quarantine_on_failure": True},
        }
        initial = l0.measure_placement(profile, measurement, raw)
        self.assertEqual((initial.outcome, initial.reason), (l0.L0Outcome.RESOLVED, l0.L0Reason.PLACEMENT_MEASURED), initial)
        self.assertIsNotNone(initial.measurement)
        observed = initial.measurement
        placement = {
            "placement_id": "placement-l0-lx-a-1", "host_id": "host-l0-1", "subject_instance_id": raw["subject_instance_id"], "process_tree_id": raw["process_tree_id"], "session_id": worker.session_id, "nonce": "supply-nonce-1", "fencing_epoch": 11, "revocation_epoch": 7,
            "rootfs_binding_digest": observed.rootfs_binding_digest, "staging_binding_digest": observed.staging_binding_digest, "cgroup_binding_digest": observed.cgroup_binding_digest, "broker_binding_digest": observed.broker_binding_digest, "fd_inventory_digest": observed.fd_inventory_digest, "namespace_plan_digest": observed.namespace_plan_digest,
            "issued_at": "2026-08-25T11:00:00Z", "expires_at": "2026-08-25T13:00:00Z",
        }
        supply_raw = {
            "supply_version": "1.0.0", "observed_at": "2026-08-25T12:00:00Z", "profile_digest": profile.profile_digest, "measurement_digest": measurement.measurement_digest,
            "runtime": {"path": l0.RUNTIME_PATH, "version": l0.RUNTIME_VERSION, "digest": l0.RUNTIME_DIGEST},
            "image": {"image_id": "image-l0-lx-a-v1", "rootfs_manifest_digest": _digest_bytes(contents["ROOTFS_MANIFEST"]), "platform": "linux", "architecture": "x86_64"},
            "registry": {"snapshot_digest": _digest_bytes(contents["REGISTRY_SNAPSHOT"]), "reference": "registry-snapshot-v7", "generation": 7, "rollback_floor": 7, "issued_at": "2026-08-25T11:00:00Z", "expires_at": "2026-08-25T13:00:00Z"},
            "signer": {
                "trust_root_id": "supply-root-1", "signer_id": "supply-signer-1",
                "key_id": "external-key-1", "algorithm": "ED25519",
                "revocation_epoch": 7, "rollback_floor": 7,
                "verifier_code_digest": profile_raw["measurement_bindings"]["verifier_code_digest"],
                "verifier_public_key_digest": profile_raw["measurement_bindings"]["verifier_public_key_digest"],
                "verifier_libcrypto_digest": profile_raw["measurement_bindings"]["verifier_libcrypto_digest"],
            },
            "placement": placement, "artifacts": artifacts, "verification": dict(ExactExternalVerifier.source),
        }
        # Derive the expected canonical payload without granting it authority, then
        # verify it through an independently pinned test boundary.
        class Probe(ExactExternalVerifier):
            def __init__(self) -> None:
                super().__init__({})

            def verify(self, payload: bytes, record: bytes, observed_at: str) -> VerificationResult:
                self.expected = json.loads(payload)
                return super().verify(payload, record, observed_at)

        probe = Probe()
        with patch.object(l0, "_runtime_output", return_value=l0.RUNTIME_VERSION):
            supplied = l0.verify_supply(profile, measurement, supply_raw, verifier=probe)
        self.assertEqual((supplied.outcome, supplied.reason), (l0.L0Outcome.VERIFIED, l0.L0Reason.SUPPLY_VERIFIED), supplied)
        self.assertIsNotNone(supplied.verification)
        supply = supplied.verification
        claim = _claim(profile, supply.placement_digest)
        raw["claim_digest"] = claim.claim_digest
        raw["lineage_root"] = claim.lineage_root
        return profile, measurement, supply, claim, raw

    def prepared(self) -> tuple[l0.CompiledL0Profile, l0.HostMeasurement, l0.SupplyVerification, DispatchClaim, dict[str, object], l0.SessionPlan]:
        profile, measurement, supply, claim, raw = self.fixture()
        with patch.object(l0, "_runtime_output", return_value=l0.RUNTIME_VERSION):
            result = l0.prepare_session(profile, measurement, supply, claim, raw, supply_verifier=ExactExternalVerifier(json.loads(supply.payload_json)), executor_claim_verifier=ExactExternalVerifier(json.loads(claim.claim_json)))
        self.assertEqual((result.outcome, result.reason), (l0.L0Outcome.PREPARED, l0.L0Reason.SESSION_PREPARED), result)
        self.assertIsNotNone(result.plan)
        return profile, measurement, supply, claim, raw, result.plan

    def assert_stop(self, result: object) -> None:
        self.assertIs(type(result), l0.SessionResult)
        self.assertEqual(result.outcome, l0.L0Outcome.STOP)
        self.assertIsInstance(result.reason, l0.L0Reason)
        self.assertIsNone(result.plan)

    def test_plan_has_only_typed_bwrap_controls_no_environment_and_no_staging_visibility(self) -> None:
        profile, _, _, _, _, plan = self.prepared()
        argv = tuple(plan.bwrap_argv)
        worker = next(item for item in profile.principals if item.role == "AGENT_WORKER")
        self.assertEqual(argv[0], l0.RUNTIME_PATH)
        self.assertNotIn("--unshare-all", argv)
        self.assertNotIn("--share-net", argv)
        self.assertFalse(any(item.endswith("-try") for item in argv))
        for option in ("--userns", "--unshare-ipc", "--unshare-pid", "--unshare-net", "--unshare-uts", "--unshare-cgroup", "--assert-userns-disabled", "--new-session", "--die-with-parent", "--clearenv", "--cap-drop", "--seccomp", "--block-fd", "--json-status-fd", "--chdir"):
            self.assertIn(option, argv)
        self.assertNotIn("--disable-userns", argv)
        self.assertNotIn("--unshare-user", argv)
        self.assertEqual(argv[argv.index("--userns") + 1], str(plan.user_namespace_fd))
        self.assertNotIn("--sync-fd", argv)
        self.assertNotIn("--exec-label", argv)
        self.assertNotIn("--remount-ro", argv)
        separator = argv.index("--")
        self.assertEqual(
            argv[separator + 1 : separator + 9],
            (
                l0.AA_EXEC_PATH, "--profile", worker.security_label, "--", "/usr/bin/python3.12",
                "-I", "-S", "/usr/lib/harness/worker-tool",
            ),
        )
        self.assertNotIn("--uid", argv)
        self.assertNotIn("--gid", argv)
        self.assertEqual(argv[argv.index("--cap-drop") + 1], "ALL")
        self.assertEqual(argv[argv.index("--chdir") + 1], "/workspace")
        self.assertEqual(tuple(plan.environment), ())
        self.assertNotIn(plan.worker_start_read_fd, plan.pass_fds)
        runtime = json.loads(plan.runtime_bindings_json)
        self.assertEqual(
            {
                row["kind"]
                for row in runtime["fd_allowlist"]
                if row["kind"].startswith("WORKER_START_")
            },
            {"WORKER_START_GATE", "WORKER_START_RELEASE"},
        )
        self.assertFalse(any(item in {"sh", "bash", "-c"} for item in argv))
        self.assertFalse(any(destination == "/staging" for _, destination in plan.read_only_mounts))
        self.assertNotIn("/staging", argv)
        self.assertNotIn("/run/harness", argv)
        self.assertNotIn("--broker-socket", argv)
        self.assertNotIn(plan.broker_peer_fd, plan.pass_fds)
        self.assertNotIn(plan.worker_broker_fd, plan.pass_fds)

    def test_plan_exactly_binds_resources_descriptors_and_lifecycle_record(self) -> None:
        profile, measurement, supply, claim, raw, plan = self.prepared()
        self.assertEqual(plan.profile_digest, profile.profile_digest)
        self.assertEqual(plan.measurement_digest, measurement.measurement_digest)
        self.assertEqual(plan.supply_digest, supply.supply_digest)
        self.assertEqual(plan.placement_digest, supply.placement_digest)
        self.assertEqual(plan.transaction_id, claim.transaction_id)
        self.assertEqual(plan.claim_digest, claim.claim_digest)
        self.assertEqual(plan.session_id, raw["session_id"])
        self.assertEqual((plan.fencing_epoch, plan.revocation_epoch), (11, 7))
        self.assertEqual((len(plan.pass_fds), len(set(plan.pass_fds))), (7, 7))
        self.assertEqual(plan.user_namespace_fd, raw["user_namespace"]["descriptor"])
        self.assertEqual(len(plan.read_only_mounts), 2)
        self.assertEqual(plan.worker_broker_fd, raw["broker_ipc"]["worker_descriptor"])
        self.assertEqual(plan.broker_peer_fd, raw["broker_ipc"]["broker_descriptor"])
        self.assertRegex(plan.broker_pair_binding_digest, r"^sha256:[0-9a-f]{64}$")
        self.assertEqual(dict(plan.cgroup_limits)["pids.max"], "8")
        self.assertEqual(dict(plan.cgroup_limits)["memory.max"], str(128 * 1024 * 1024))
        self.assertEqual(dict(plan.cgroup_limits)["memory.swap.max"], "0")
        self.assertEqual(dict(plan.cgroup_limits)["io.max"], "259:2 rbps=409600 wbps=409600 riops=100 wiops=100")
        self.assertEqual((plan.cpu_time_ms, plan.wall_time_ms, plan.rlimit_nofile), (2000, 3000, 32))
        self.assertEqual(dict(plan.quota)["root_id"], "staging-root-1")
        self.assertEqual(dict(plan.namespace_ids), raw["namespace_ids"])
        self.assertIn('"reuse_forbidden":true', plan.cleanup_record_json)
        self.assertRegex(plan.runtime_bindings_digest, r"^sha256:[0-9a-f]{64}$")
        self.assertRegex(plan.launch_digest, r"^sha256:[0-9a-f]{64}$")

    def test_closed_mutations_stop_without_partial_plan(self) -> None:
        profile, measurement, supply, claim, raw = self.fixture()
        supply_verifier = ExactExternalVerifier(json.loads(supply.payload_json))
        claim_verifier = ExactExternalVerifier(json.loads(claim.claim_json))
        cases: list[tuple[str, object, object, object, object | None, object | None]] = []
        missing = deepcopy(raw); del missing["seccomp"]
        cases.append(("missing-seccomp", supply, claim, missing, supply_verifier, claim_verifier))
        extra = deepcopy(raw); extra["ambient"] = True
        cases.append(("extra-session", supply, claim, extra, supply_verifier, claim_verifier))
        duplicate_fd = deepcopy(raw); duplicate_fd["inputs"][0]["descriptor"] = raw["rootfs"]["descriptor"]
        cases.append(("duplicate-fd", supply, claim, duplicate_fd, supply_verifier, claim_verifier))
        wrong_mount = deepcopy(raw); wrong_mount["inputs"][0]["mount_path"] = "/workspace"
        cases.append(("input-mount", supply, claim, wrong_mount, supply_verifier, claim_verifier))
        wrong_ipc = deepcopy(raw); wrong_ipc["broker_ipc"]["transport"] = "UNIX_STREAM"
        cases.append(("ipc", supply, claim, wrong_ipc, supply_verifier, claim_verifier))
        legacy_ipc = deepcopy(raw); legacy_ipc["broker_ipc"]["socket_name"] = "broker.sock"
        cases.append(("legacy-ipc", supply, claim, legacy_ipc, supply_verifier, claim_verifier))
        pair_mode = deepcopy(raw); pair_mode["broker_ipc"]["endpoint_mode"] = "PATHNAME"
        cases.append(("pair-mode", supply, claim, pair_mode, supply_verifier, claim_verifier))
        pair_nonce = deepcopy(raw); pair_nonce["broker_ipc"]["nonce"] = "other-nonce"
        cases.append(("pair-nonce", supply, claim, pair_nonce, supply_verifier, claim_verifier))
        pair_fence = deepcopy(raw); pair_fence["broker_ipc"]["fencing_epoch"] = 12
        cases.append(("pair-fence", supply, claim, pair_fence, supply_verifier, claim_verifier))
        pair_expiry = deepcopy(raw); pair_expiry["broker_ipc"]["expires_at"] = "2026-08-25T12:11:00Z"
        cases.append(("pair-expiry", supply, claim, pair_expiry, supply_verifier, claim_verifier))
        pair_swap = deepcopy(raw)
        pair_swap["broker_ipc"]["worker_descriptor"], pair_swap["broker_ipc"]["broker_descriptor"] = (
            pair_swap["broker_ipc"]["broker_descriptor"], pair_swap["broker_ipc"]["worker_descriptor"]
        )
        cases.append(("pair-swap", supply, claim, pair_swap, supply_verifier, claim_verifier))
        no_device = deepcopy(raw); del no_device["cgroup"]["device_major"]
        cases.append(("io-device", supply, claim, no_device, supply_verifier, claim_verifier))
        not_delegated = deepcopy(raw); not_delegated["cgroup"]["delegated"] = False
        cases.append(("cgroup", supply, claim, not_delegated, supply_verifier, claim_verifier))
        stale_fence = deepcopy(raw); stale_fence["fencing_epoch"] = 12
        cases.append(("stale-fence", supply, claim, stale_fence, supply_verifier, claim_verifier))
        namespace = deepcopy(raw); namespace["namespace_ids"]["network"] = "shared-net"
        cases.append(("namespace", supply, claim, namespace, supply_verifier, claim_verifier))
        userns_limit = deepcopy(raw); userns_limit["user_namespace"]["max_user_namespaces"] = 1
        cases.append(("userns-limit", supply, claim, userns_limit, supply_verifier, claim_verifier))
        userns_map = deepcopy(raw); userns_map["user_namespace"]["uid_map"] = "0 0 1\n"
        cases.append(("userns-map", supply, claim, userns_map, supply_verifier, claim_verifier))
        userns_fd = deepcopy(raw); userns_fd["user_namespace"]["descriptor"] = raw["rootfs"]["descriptor"]
        cases.append(("userns-fd", supply, claim, userns_fd, supply_verifier, claim_verifier))
        missing_start = deepcopy(raw); del missing_start["supervisor_fds"]["worker_start_read"]
        cases.append(("missing-worker-start", supply, claim, missing_start, supply_verifier, claim_verifier))
        shared_start = deepcopy(raw); shared_start["supervisor_fds"]["worker_start_read"] = raw["supervisor_fds"]["gate_read"]
        cases.append(("shared-worker-start", supply, claim, shared_start, supply_verifier, claim_verifier))
        wrong_start_direction = deepcopy(raw); wrong_start_direction["supervisor_fds"]["worker_start_read"] = raw["supervisor_fds"]["worker_start_write"]
        cases.append(("worker-start-direction", supply, claim, wrong_start_direction, supply_verifier, claim_verifier))
        process_tree = deepcopy(raw); process_tree["process_tree_id"] = "other-tree"
        cases.append(("process-tree", supply, claim, process_tree, supply_verifier, claim_verifier))
        cleanup = deepcopy(raw); cleanup["cleanup"]["reuse_forbidden"] = False
        cases.append(("cleanup", supply, claim, cleanup, supply_verifier, claim_verifier))
        shell = deepcopy(raw); shell["tool"]["argv"] = ["/bin/sh", "-c", "id", "--session", "session-1"]
        cases.append(("shell", supply, claim, shell, supply_verifier, claim_verifier))
        cases.append(("supply-missing-verifier", supply, claim, raw, None, claim_verifier))
        cases.append(("claim-missing-verifier", supply, claim, raw, supply_verifier, None))
        cases.append(("claim-placement", supply, replace(claim, placement_digest=_digest_text("wrong")), raw, supply_verifier, claim_verifier))
        cases.append(("supply-placement", replace(supply, placement_digest=_digest_text("wrong")), claim, raw, supply_verifier, claim_verifier))
        for name, tested_supply, tested_claim, tested_raw, tested_supply_verifier, tested_claim_verifier in cases:
            with self.subTest(name=name):
                with patch.object(l0, "_runtime_output", return_value=l0.RUNTIME_VERSION):
                    result = l0.prepare_session(profile, measurement, tested_supply, tested_claim, tested_raw, supply_verifier=tested_supply_verifier, executor_claim_verifier=tested_claim_verifier)
                self.assert_stop(result)

    def test_supervisor_host_failure_stops_before_durable_prepare_or_process(self) -> None:
        profile, measurement, supply, claim, raw = self.fixture()
        store = DurableStore(str(Path(self.temporary.name) / "supervisor.sqlite3"), ExactExternalVerifier({}))
        forbidden = AssertionError("supervisor crossed the failed host boundary")
        with (
            patch.object(l0, "_observe_host", side_effect=RuntimeError("host measurement failed")),
            patch.object(store, "prepare_runtime_session", side_effect=forbidden) as prepare,
            patch.object(subprocess, "Popen", side_effect=forbidden) as popen,
            patch.object(os, "mkdir", side_effect=forbidden) as mkdir,
        ):
            result = l0.supervise_session(
                profile,
                measurement,
                supply,
                claim,
                raw,
                store,
                terminal_observed_at="2026-08-25T12:04:00Z",
            )
        self.assertEqual((result.outcome, result.reason), (l0.L0Outcome.STOP, l0.L0Reason.RUNTIME_FAILED))
        self.assertIsNone(result.session)
        prepare.assert_not_called()
        popen.assert_not_called()
        mkdir.assert_not_called()


class RuntimeConformanceOrderingTests(unittest.TestCase):
    def test_cgroup_preflight_stop_precedes_every_runtime_mutation_surface(self) -> None:
        profile_raw = l0_tests.valid_raw()
        stopped = l0.L0Result(l0.L0Outcome.STOP, l0.L0Reason.CGROUP_DELEGATION_ABSENT)
        forbidden = AssertionError("runtime conformance mutated host after failed preflight")
        with (patch.object(l0, "host_preflight", return_value=stopped) as preflight, patch.object(subprocess, "Popen", side_effect=forbidden), patch.object(socket, "socket", side_effect=forbidden), patch.object(os, "mkdir", side_effect=forbidden), patch.object(os, "makedirs", side_effect=forbidden), patch.object(os, "write", side_effect=forbidden), patch.object(os, "unlink", side_effect=forbidden)):
            result = l0.runtime_conformance(profile_raw)
        preflight.assert_called_once_with(profile_raw)
        self.assertEqual((result.outcome, result.reason), (l0.L0Outcome.ABSENT, l0.L0Reason.CGROUP_DELEGATION_ABSENT))
        self.assertIsNone(result.session)


if __name__ == "__main__":
    unittest.main()
