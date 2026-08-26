"""Non-skipping M3 exact-profile gate regressions.

The gate is intentionally unavailable on an unattested developer host.  These
tests verify that absence is a nonzero, structured result rather than a skip or
a weakened runtime launch.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import harness_product.l0 as l0
from harness_product.l0 import L0Outcome, compile_profile


ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "profiles" / "l0-lx-a.json"
GATE = ROOT / "scripts" / "check_m3_l0.py"

_SPEC = importlib.util.spec_from_file_location("harness_m3_gate", GATE)
assert _SPEC is not None and _SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(CHECKER)


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest(value: str) -> str:
    return "sha256:" + sha256(value.encode("utf-8")).hexdigest()


class L0ConformanceGateTests(unittest.TestCase):
    def test_exact_profile_artifact_compiles(self) -> None:
        raw = json.loads(PROFILE.read_bytes())
        result = compile_profile(raw)
        self.assertEqual(result.outcome, L0Outcome.COMPILED_DRAFT)
        self.assertIsNotNone(result.profile)
        bindings = raw["measurement_bindings"]
        for key, name in (
            ("rootfs_manifest_digest", "l0-lx-a-rootfs-manifest.json"),
            ("lsm_policy_digest", "l0-lx-a.apparmor"),
            ("broker_message_schema_digest", "l0-lx-a-broker-message.json"),
        ):
            self.assertEqual(
                bindings[key],
                "sha256:" + sha256((ROOT / "profiles" / name).read_bytes()).hexdigest(),
            )
        seccomp_raw = json.loads((ROOT / "profiles/l0-lx-a-seccomp.json").read_bytes())
        self.assertEqual(
            bindings["seccomp_profile_digest"],
            "sha256:" + sha256(l0._compile_seccomp_bpf(seccomp_raw)).hexdigest(),
        )

    def test_unattested_gate_is_nonzero_absent_and_digest_bound(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(GATE)],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(completed.stderr, "")
        record = json.loads(completed.stdout)
        self.assertEqual(record["outcome"], "ABSENT")
        self.assertEqual(record["status"], "NOT_ATTESTED")
        self.assertNotIn("skip", completed.stdout.lower())
        evidence_digest = record.pop("evidence_digest")
        self.assertEqual(evidence_digest, "sha256:" + sha256(_canonical(record)).hexdigest())

    def test_unknown_attested_argument_is_nonzero_structured_absent(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(GATE), "--verified=true"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(completed.stderr, "")
        record = json.loads(completed.stdout)
        self.assertEqual((record["outcome"], record["reason"]), ("ABSENT", "UNKNOWN_OR_MISSING_ARGUMENT"))


class L0SignedEvidenceBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temporary.name) / "repository"
        profiles = cls.root / "profiles"
        profiles.mkdir(parents=True, mode=0o700)
        cls.profile_path = profiles / "l0-lx-a.json"
        cls.apparmor_path = profiles / "l0-lx-a.apparmor"
        cls.apparmor_path.write_bytes(b"test apparmor policy\n")
        cls.seccomp_path = profiles / "l0-lx-a-seccomp.json"
        cls.seccomp_path.write_bytes(b'{"policy":"test"}\n')
        verifier_directory = cls.root / "src" / "harness_product"
        verifier_directory.mkdir(parents=True, mode=0o700)
        cls.verifier_path = verifier_directory / "verification.py"
        cls.verifier_path.write_bytes(
            (ROOT / "src" / "harness_product" / "verification.py").read_bytes()
        )
        scripts = cls.root / "scripts"
        scripts.mkdir(mode=0o700)
        cls.runner_path = scripts / "run_m3_vm_conformance.py"
        cls.runner_path.write_bytes(
            (ROOT / "scripts" / "run_m3_vm_conformance.py").read_bytes()
        )
        os.chmod(cls.runner_path, 0o444)
        cls.private_key = Path(cls.temporary.name) / "private.pem"
        cls.public_key = Path(cls.temporary.name) / "public.pem"
        subprocess.run(
            ["/usr/bin/openssl", "genpkey", "-algorithm", "ED25519", "-out", str(cls.private_key)],
            check=True,
            capture_output=True,
            timeout=10,
        )
        subprocess.run(
            ["/usr/bin/openssl", "pkey", "-in", str(cls.private_key), "-pubout", "-out", str(cls.public_key)],
            check=True,
            capture_output=True,
            timeout=10,
        )
        os.chmod(cls.private_key, 0o600)
        os.chmod(cls.public_key, 0o644)
        public_bytes = cls.public_key.read_bytes()
        der = subprocess.run(
            ["/usr/bin/openssl", "pkey", "-pubin", "-in", str(cls.public_key), "-outform", "DER"],
            check=True,
            capture_output=True,
            timeout=10,
        ).stdout
        openssl_version = subprocess.run(
            ["/usr/bin/openssl", "version"], check=True, capture_output=True, text=True, timeout=10
        ).stdout.strip()
        openssl_identity = {
            "digest": "sha256:" + sha256(Path("/usr/bin/openssl").read_bytes()).hexdigest(),
            "path": "/usr/bin/openssl",
            "version": openssl_version,
        }
        cls.trust = {
            "algorithm": "ED25519",
            "key_id": "fixture-key-1",
            "openssl": openssl_identity.copy(),
            "public_key_fingerprint": "sha256:" + sha256(der).hexdigest(),
            "public_key_pem_digest": "sha256:" + sha256(public_bytes).hexdigest(),
            "revocation_state_digest": _digest("fixture-revocation-state"),
            "rollback_floor": 1,
            "scope": {
                "data_class": "SYNTHETIC",
                "environment": "DEV_STAGEABLE_LOCAL",
                "profile_id": "L0-LX-A",
                "workload_class": "DISCONNECTED_STAGEABLE_WORKER",
            },
            "signer_id": "harness-m3-attestor",
            "trust_root_id": "fixture-test-root",
            "trust_version": "1.0.0",
            "verifier_openssl": openssl_identity.copy(),
        }
        cls.trust_path = Path(cls.temporary.name) / "trust.json"
        cls.trust_path.write_bytes(_canonical(cls.trust))
        profile_raw = json.loads(PROFILE.read_bytes())
        bindings = profile_raw["measurement_bindings"]
        bindings["lsm_policy_digest"] = (
            "sha256:" + sha256(cls.apparmor_path.read_bytes()).hexdigest()
        )
        bindings["verifier_code_digest"] = (
            "sha256:" + sha256(cls.verifier_path.read_bytes()).hexdigest()
        )
        bindings["verifier_public_key_digest"] = cls.trust["public_key_pem_digest"]
        cls.profile_path.write_bytes(_canonical(profile_raw))
        source_files = {
            path: "sha256:" + sha256((cls.root / path).read_bytes()).hexdigest()
            for path in (
                "profiles/l0-lx-a.json",
                "profiles/l0-lx-a.apparmor",
                "profiles/l0-lx-a-seccomp.json",
                "scripts/run_m3_vm_conformance.py",
                "src/harness_product/verification.py",
            )
        }
        cls.source = {
            "commit": "1" * 40,
            "tree": "2" * 40,
            "files": source_files,
        }
        cls.source["files_digest"] = "sha256:" + sha256(_canonical(cls.source["files"])).hexdigest()
        cls.now = datetime(2026, 8, 26, 12, 0, 0, tzinfo=UTC)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def _signature(self, payload: bytes) -> bytes:
        payload_path = Path(self.temporary.name) / "record-payload.json"
        payload_path.write_bytes(payload)
        return subprocess.run(
            [
                "/usr/bin/openssl", "pkeyutl", "-sign", "-inkey",
                str(self.private_key), "-rawin", "-in", str(payload_path),
            ],
            check=True,
            capture_output=True,
            timeout=10,
        ).stdout

    def _signed_record(self, payload: dict[str, object]) -> dict[str, object]:
        payload_bytes = _canonical(payload)
        return {
            "verification_version": 1,
            "verifier_id": "harness-m3-external-verifier/v1",
            "issuer_id": self.trust["signer_id"],
            "key_id": self.trust["key_id"],
            "payload_digest": "sha256:" + sha256(payload_bytes).hexdigest(),
            "bindings": payload,
            "proof": "ed25519:" + self._signature(payload_bytes).hex(),
        }

    def _evidence(self) -> dict[str, object]:
        profile_raw = json.loads(self.profile_path.read_bytes())
        compiled = compile_profile(profile_raw)
        self.assertIsNotNone(compiled.profile)
        profile_digest = compiled.profile.profile_digest
        bindings = profile_raw["measurement_bindings"]
        labels = {
            row["role"]: row["security_label"]
            for row in profile_raw["principals"]
            if row["enabled"]
        }

        def network(connected: bool) -> dict[str, bool]:
            return {
                "ipv4": False,
                "ipv6": False,
                "loopback": False,
                "routes": False,
                "dns": False,
                "raw": False,
                "packet": False,
                "broad_unix": False,
                "connected_fds": connected,
            }

        principal_specs = (
            ("ATTESTOR", 0, 4004, 0, 4004, 0, 4004, "attestor-session-500", 500, "harness-l0-lx-a.attestor", [0, 1, 2, 3, 4], False),
            ("CONTROLLER", 3000, 4000, 3000, 4000, 3000, 4000, "controller-session-501", 501, "harness-l0-lx-a.controller", [0, 1, 2, 3], False),
            ("AGENT_WORKER", 3001, 4001, 3001, 4001, 1001, 2001, "session-1", 502, labels["AGENT_WORKER"], [0, 1], True),
            ("BROKER", 3002, 4002, 3002, 4002, 1002, 2002, "session-2", 503, labels["BROKER"], [0, 1, 2], True),
            ("EXECUTOR", 3003, 4003, 3003, 4003, 1003, 2003, "session-3", 504, labels["EXECUTOR"], [0, 1], False),
        )
        active = []
        for number, spec in enumerate(principal_specs):
            (
                role, launcher_uid, launcher_gid, host_uid, host_gid,
                namespace_uid, namespace_gid, session_id, process_id,
                security_label, fds, connected,
            ) = spec
            active.append(
                {
                    "role": role,
                    "launcher_uid": launcher_uid,
                    "launcher_gid": launcher_gid,
                    "host_uid": host_uid,
                    "host_gid": host_gid,
                    "namespace_uid": namespace_uid,
                    "namespace_gid": namespace_gid,
                    "session_id": session_id,
                    "process_id": process_id,
                    "cgroup": f"/harness/{role.lower()}-{process_id}",
                    "security_label": security_label,
                    "credential_namespace": f"credential-{role.lower()}-{process_id}",
                    "namespace_ids": {
                        key: f"{key}:[{1000 + number}]"
                        for key in ("user", "mount", "pid", "ipc", "uts", "network", "cgroup")
                    },
                    "fd_inventory": fds,
                    "network": network(connected),
                }
            )
        principals = {row["role"]: row for row in active}
        event_types = sorted(CHECKER._EVENT_TYPES)
        tests = []
        events = []
        for number, (test_id, matrix) in enumerate(CHECKER._TEST_MATRIX.items()):
            event_id = f"event-{number}"
            tests.append(
                {
                    "id": test_id,
                    "matrix_ids": list(matrix),
                    "command": ["/opt/harness-m3/runner.py", test_id],
                    "exit_code": 0,
                    "oracle": f"fixture oracle {number}",
                    "result": "PASS",
                    "event_ids": [event_id],
                }
            )
            events.append(
                {
                    "event_id": event_id,
                    "type": event_types[number % len(event_types)],
                    "test_id": test_id,
                    "subject": f"subject-{number}",
                    "observed_digest": _digest(f"observed-{number}"),
                    "oracle_digest": _digest(f"oracle-{number}"),
                    "result": "PASS",
                }
            )
        resources = {row["resource"]: row["limit"] for row in profile_raw["resources"]}
        tool = lambda path, version, digest, package, package_version: {  # noqa: E731
            "path": path,
            "version": version,
            "digest": digest,
            "package": package,
            "package_version": package_version,
        }
        libcrypto_digest = bindings["verifier_libcrypto_digest"]
        aa_exec_digest = _digest("aa-exec")
        python_digest = _digest("python")
        loader_digest = _digest("loader")
        tool_digest = _digest("tool")
        dependency_digest = _digest("dependencies")
        sbom_digest = _digest("sbom")
        registry_digest = _digest("registry")
        runtime = {
            "backend": tool("/usr/bin/bwrap", "bubblewrap 0.9.0", CHECKER.l0.RUNTIME_DIGEST, "bubblewrap", "0.9.0-1ubuntu0.1"),
            "aa_exec": tool("/usr/bin/aa-exec", "aa-exec 4.0.1", aa_exec_digest, "apparmor", "4.0.1"),
            "openssl": tool("/usr/bin/openssl", self.trust["openssl"]["version"], self.trust["openssl"]["digest"], "openssl", "3.0.13"),
            "python": tool("/usr/bin/python3.12", "Python 3.12.3", python_digest, "python3.12", "3.12.3"),
            "apparmor_parser": tool("/usr/sbin/apparmor_parser", "AppArmor parser 4.0.1", _digest("parser"), "apparmor", "4.0.1"),
            "dependencies": [
                {"path": "/usr/lib/x86_64-linux-gnu/libcrypto.so.3", "digest": libcrypto_digest, "package": "libssl3t64", "version": "3.0.13"},
                {"path": "/lib/dependency-1.so", "digest": _digest("dependency-1"), "package": "package-1", "version": "1.0"},
                {"path": "/lib/dependency-2.so", "digest": _digest("dependency-2"), "package": "package-2", "version": "1.0"},
                {"path": "/lib/dependency-3.so", "digest": _digest("dependency-3"), "package": "package-3", "version": "1.0"},
            ],
            "apparmor_policy_digest": "sha256:" + sha256(self.apparmor_path.read_bytes()).hexdigest(),
            "seccomp_policy_digest": "sha256:" + sha256(self.seccomp_path.read_bytes()).hexdigest(),
            "seccomp_bpf_digest": bindings["seccomp_profile_digest"],
            "sbom_digest": sbom_digest,
            "registry_snapshot_digest": registry_digest,
            "profile_digest": profile_digest,
            "code_digest": self.source["files_digest"],
            "package_index_digest": _digest("package-index"),
            "verifier": {
                "backend": "OPENSSL_LIBCRYPTO_SHARED",
                "code_digest": bindings["verifier_code_digest"],
                "public_key_digest": bindings["verifier_public_key_digest"],
                "libcrypto_digest": libcrypto_digest,
                "controller_principal": "CONTROLLER",
                "executor_principal": "EXECUTOR",
                "independent_implementations": False,
            },
        }
        artifact_digests = {
            "ROOTFS_MANIFEST": bindings["rootfs_manifest_digest"],
            "BWRAP": runtime["backend"]["digest"],
            "AA_EXEC": aa_exec_digest,
            "PYTHON": python_digest,
            "LOADER": loader_digest,
            "TOOL": tool_digest,
            "SECCOMP_BPF": bindings["seccomp_profile_digest"],
            "APPARMOR_POLICY": bindings["lsm_policy_digest"],
            "SBOM": sbom_digest,
            "REGISTRY_SNAPSHOT": registry_digest,
        }
        opened_artifacts = [
            {
                "role": role,
                "path": f"/artifact/{role.lower()}",
                "device": 1,
                "inode": 100 + number,
                "bytes": 1000 + number,
                "digest": artifact_digests[role],
            }
            for number, role in enumerate(sorted(artifact_digests))
        ]
        supply_role_digests = {
            "ROOTFS_MANIFEST": bindings["rootfs_manifest_digest"],
            "LOADER": loader_digest,
            "DEPENDENCY_CLOSURE": dependency_digest,
            "TOOL": tool_digest,
            "SBOM": sbom_digest,
            "REGISTRY_SNAPSHOT": registry_digest,
            "SECCOMP_PROFILE": bindings["seccomp_profile_digest"],
            "LSM_POLICY": bindings["lsm_policy_digest"],
        }
        supply_artifacts = []
        for number, role in enumerate(sorted(supply_role_digests)):
            row = {
                "role": role,
                "artifact_id": f"fixture-{role.lower().replace('_', '-')}",
                "expected_bytes_digest": supply_role_digests[role],
                "actual_bytes_digest": supply_role_digests[role],
                "provenance_digest": _digest(f"provenance-{role}"),
                "device": 2,
                "inode": 200 + number,
                "size": 2000 + number,
                "mode": 0o444,
            }
            row["binding_digest"] = "sha256:" + sha256(_canonical(row)).hexdigest()
            supply_artifacts.append(row)
        measurement_digest = _digest("measurement")
        placement = {
            "placement_id": "fixture-placement-1",
            "host_id": "fixture-host-1",
            "subject_instance_id": "worker-instance-1",
            "process_tree_id": "worker-tree-1",
            "session_id": "session-1",
            "nonce": "nonce-m3-runtime-1",
            "fencing_epoch": 1,
            "revocation_epoch": 0,
            "rootfs_binding_digest": _digest("rootfs-binding"),
            "staging_binding_digest": _digest("staging-binding"),
            "cgroup_binding_digest": _digest("cgroup-binding"),
            "broker_binding_digest": _digest("broker-placement-binding"),
            "fd_inventory_digest": _digest("fd-inventory"),
            "namespace_plan_digest": _digest("namespace-plan"),
            "issued_at": "2026-08-26T11:00:00Z",
            "expires_at": "2026-08-26T13:00:00Z",
            "profile_digest": profile_digest,
            "measurement_digest": measurement_digest,
            "runtime_digest": CHECKER.l0.RUNTIME_DIGEST,
        }
        placement_digest = "sha256:" + sha256(_canonical(placement)).hexdigest()
        supply_payload = {
            "supply_version": "1.0.0",
            "observed_at": "2026-08-26T12:00:00Z",
            "profile_digest": profile_digest,
            "measurement_digest": measurement_digest,
            "runtime": {
                "path": CHECKER.l0.RUNTIME_PATH,
                "version": CHECKER.l0.RUNTIME_VERSION,
                "digest": CHECKER.l0.RUNTIME_DIGEST,
            },
            "image": {
                "image_id": "ubuntu-noble-20260814-amd64",
                "rootfs_manifest_digest": bindings["rootfs_manifest_digest"],
                "platform": "linux",
                "architecture": "x86_64",
            },
            "registry": {
                "snapshot_digest": registry_digest,
                "reference": "ubuntu-noble-20260814-installed-snapshot",
                "generation": 1,
                "rollback_floor": 1,
                "issued_at": "2026-08-26T11:00:00Z",
                "expires_at": "2026-08-26T13:00:00Z",
            },
            "signer": {
                "trust_root_id": self.trust["trust_root_id"],
                "signer_id": self.trust["signer_id"],
                "key_id": self.trust["key_id"],
                "algorithm": "ED25519",
                "revocation_epoch": 0,
                "rollback_floor": 1,
                "verifier_code_digest": bindings["verifier_code_digest"],
                "verifier_public_key_digest": bindings["verifier_public_key_digest"],
                "verifier_libcrypto_digest": libcrypto_digest,
            },
            "placement": placement,
            "placement_digest": placement_digest,
            "artifacts": supply_artifacts,
        }
        supply_record = self._signed_record(supply_payload)

        worker_socket = {
            "kind": "BROKER_IPC_WORKER_END",
            "descriptor": 10,
            "descriptor_id": "fixture-worker-end",
            "device": 3,
            "inode": 701,
            "cookie": 801,
            "type": "SOCKET",
            "family": "AF_UNIX",
            "socket_type": "SOCK_SEQPACKET",
            "address_mode": "ANONYMOUS_CONNECTED",
            "pass_credentials": False,
            "creation_peer": {"pid": 1, "uid": 0, "gid": 0},
        }
        broker_socket = {
            **worker_socket,
            "kind": "BROKER_IPC_BROKER_END",
            "descriptor": 11,
            "descriptor_id": "fixture-broker-end",
            "inode": 702,
            "cookie": 802,
            "pass_credentials": True,
        }
        broker_runtime = {
            "kind": "UNIX_CONNECTED_PAIR",
            "endpoint_mode": profile_raw["broker_ipc"]["endpoint_mode"],
            "transport": profile_raw["broker_ipc"]["transport"],
            "worker_endpoint": profile_raw["broker_ipc"]["worker_endpoint"],
            "broker_endpoint": profile_raw["broker_ipc"]["broker_endpoint"],
            "worker_principal": profile_raw["broker_ipc"]["worker_principal"],
            "broker_principal": profile_raw["broker_ipc"]["broker_principal"],
            "worker_session": "session-1",
            "broker_session": "session-2",
            "worker_security_label": labels["AGENT_WORKER"],
            "broker_security_label": labels["BROKER"],
            "worker_socket_identity": worker_socket,
            "broker_socket_identity": broker_socket,
            "operation_id": "stage-write-v1",
            "nonce": "nonce-m3-runtime-1",
            "fencing_epoch": 1,
            "revocation_epoch": 0,
            "issued_at": "2026-08-26T11:00:00Z",
            "expires_at": "2026-08-26T13:00:00Z",
            "sender_authentication": profile_raw["broker_ipc"]["sender_authentication"],
            "message_binding_digest": compiled.profile.broker_binding_digest,
        }
        broker_runtime["pair_binding_digest"] = (
            "sha256:" + sha256(_canonical(broker_runtime)).hexdigest()
        )

        def holder(role: str, socket_identity: dict[str, object]) -> dict[str, object]:
            principal = principals[role]
            side = "worker" if role == "AGENT_WORKER" else "broker"
            return {
                "principal": broker_runtime[f"{side}_principal"],
                "session": principal["session_id"],
                "security_label": principal["security_label"],
                "host_uid": principal["host_uid"],
                "host_gid": principal["host_gid"],
                "process_id": principal["process_id"],
                "cgroup": principal["cgroup"],
                "namespace_ids": principal["namespace_ids"],
                "fd_inventory": principal["fd_inventory"],
                "socket_identity": socket_identity,
                "socket_target": f"socket:[{socket_identity['inode']}]",
            }

        holder_payload = {
            "attestation_version": "1.0.0",
            "observed_at": "2026-08-26T12:00:00Z",
            "profile_digest": profile_digest,
            "runtime_session_id": "m3-session-record-1",
            "operation_id": broker_runtime["operation_id"],
            "nonce": broker_runtime["nonce"],
            "fencing_epoch": 1,
            "revocation_epoch": 0,
            "pair_binding_digest": broker_runtime["pair_binding_digest"],
            "message_binding_digest": broker_runtime["message_binding_digest"],
            "worker_holder": holder("AGENT_WORKER", worker_socket),
            "broker_holder": holder("BROKER", broker_socket),
            "message_credentials_in_broker_namespace": {"pid": 0, "uid": 65534, "gid": 65534},
            "gates": {"broker": "CLOSED", "worker": "CLOSED"},
        }
        holder_bytes = _canonical(holder_payload)
        holder_signature = self._signature(holder_bytes)
        broker_report = {
            "creator_credentials": [0, 65534, 65534],
            "message_credentials": [0, 65534, 65534],
            "packet_digest": _digest("broker-packet"),
        }

        verifier_summary = {
            key: runtime["verifier"][key]
            for key in ("backend", "code_digest", "public_key_digest", "libcrypto_digest")
        }
        controller_operations = [
            "EVALUATE", "BOOTSTRAP", "ISSUE", "CONSUME", "CLAIM", "CLAIM",
            "PREPARE", "PREPARE", "VERIFY_CLAIM", "FINALIZE", "FINALIZE",
            "CLAIM", "RECOVER", "STOP",
        ]
        operation_rows = [
            {
                "operation": operation,
                "request_digest": _digest(f"request-{number}"),
                "response_digest": _digest(f"response-{number}"),
            }
            for number, operation in enumerate(controller_operations)
        ]
        controller_principal = principals["CONTROLLER"]
        controller_argv = [
            "/usr/bin/aa-exec", "--profile", "harness-l0-lx-a.controller", "--",
            "/usr/bin/python3.12", "-I", "-S",
            "/opt/harness-m3-source/scripts/run_m3_vm_conformance.py",
            "--controller-session",
        ]
        controller = {
            **{
                key: controller_principal[key]
                for key in (
                    "launcher_uid", "launcher_gid", "host_uid", "host_gid",
                    "namespace_uid", "namespace_gid", "session_id", "process_id",
                    "cgroup", "security_label", "credential_namespace", "namespace_ids",
                    "fd_inventory", "network",
                )
            },
            "process_session": 501,
            "argv": controller_argv,
            "argv_digest": "sha256:" + sha256(_canonical(controller_argv)).hexdigest(),
            "status": {
                "CapInh": "0000000000000000",
                "CapPrm": "0000000000000000",
                "CapEff": "0000000000000000",
                "NoNewPrivs": "1",
            },
            "envelope_digest": _digest("controller-envelope"),
            "code_descriptor": {
                "path": "/opt/harness-m3-source/scripts/run_m3_vm_conformance.py",
                "descriptor": 3,
                "device": 4,
                "inode": 901,
                "bytes": len(self.runner_path.read_bytes()),
                "digest": self.source["files"]["scripts/run_m3_vm_conformance.py"],
                "flags": os.O_RDONLY | os.O_CLOEXEC,
                "uid": 0,
                "gid": 0,
                "mode": 0o444,
            },
            "verifier": verifier_summary,
            "durable_database": "/var/lib/harness-m3-controller/durable.sqlite3",
            "control_proof": {
                "closed": True,
                "cgroup_populated_after_close": 0,
                "operations": operation_rows,
                "operations_digest": "sha256:" + sha256(_canonical(operation_rows)).hexdigest(),
            },
        }

        quota_mount = (
            f"size={resources['OUTPUT_BYTES']},nr_inodes={resources['INODES']},"
            "mode=0700,uid=3003,gid=4003,nosuid,nodev,noexec"
        )
        resource_oracles = {
            "cpu": {
                "cpu_max": "50000 100000",
                "rate_delta": {"usage_usec": 500000, "nr_periods": 10, "nr_throttled": 5, "throttled_usec": 250000},
                "time_limit_usec": resources["CPU_TIME"] * 1000,
                "time_trigger_usec": resources["CPU_TIME"] * 1000 + 50000,
                "time_overshoot_usec": 50000,
                "time_return_code": -9,
                "cgroup_populated_after_kill": 0,
            },
            "memory": {
                "memory_max": str(resources["MEMORY"] * 1024 * 1024),
                "swap_max": "0",
                "max_events": 1,
                "oom_kill_events": 1,
                "swap_before": 0,
                "swap_after": 0,
                "return_code": -9,
                "memory_current": 0,
            },
            "pids": {
                "pids_max": str(resources["PIDS"]),
                "max_events": 1,
                "peak": resources["PIDS"],
                "launched": resources["PIDS"] - 1,
                "launch_rejection": "EAGAIN",
                "return_codes": [-9],
            },
            "io": {
                "io_max": "253:0 rbps=409600 wbps=409600 riops=100 wiops=100",
                "device": {
                    "backing_device": "vda1",
                    "controller_device": "253:0",
                    "partition": True,
                    "binding_digest": _digest("io-device"),
                },
                "control_elapsed_ns": 100000000,
                "limited_elapsed_ns": 1800000000,
                "control_delta": {"dbytes": 0, "dios": 0, "rbytes": 393216, "rios": 96, "wbytes": 393216, "wios": 96},
                "limited_delta": {"dbytes": 0, "dios": 0, "rbytes": 393216, "rios": 96, "wbytes": 393216, "wios": 96},
                "read_bytes": 393216,
                "write_bytes": 393216,
                "control_events": ["populated 0", "frozen 0"],
                "limited_events": ["populated 0", "frozen 0"],
                "minimum_slowdown_factor": 3,
            },
            "quota": {
                "mount_options": quota_mount,
                "files": resources["FILES"],
                "inodes": resources["INODES"],
                "logical_bytes": resources["OUTPUT_BYTES"],
                "allocated_bytes": resources["OUTPUT_BYTES"],
                "create_errno": 28,
                "append_errno": 28,
                "entries": ["artifact.txt"] + [f"quota-{number:02d}" for number in range(15)],
                "owners_match": True,
                "modes_match": True,
                "links_match": True,
                "statvfs_files": resources["INODES"],
                "statvfs_free": 0,
                "cgroup_populated_after_cleanup": 0,
            },
            "rlimit_nofile": {
                "limit": [resources["OPEN_FDS"], resources["OPEN_FDS"]],
                "return_code": 0,
                "cgroup_events": ["populated 0", "frozen 0"],
            },
            "wall_time": {
                "limit_ms": resources["WALL_TIME"],
                "elapsed_ms": resources["WALL_TIME"] + 1,
                "return_code": -9,
                "process_tree_size": 2,
                "cgroup_events": ["populated 0", "frozen 0"],
            },
        }
        qemu_version = subprocess.run(
            ["/usr/bin/qemu-system-x86_64", "--version"],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.splitlines()[0]
        return {
            "evidence_version": "1.0.0",
            "image": {
                "source_url": CHECKER._IMAGE_URL,
                "resolved_url": CHECKER._IMAGE_URL,
                "release_id": "20260814",
                "filename": "ubuntu-24.04-server-cloudimg-amd64.img",
                "bytes": 624447488,
                "sha256": CHECKER._IMAGE_DIGEST,
                "sums_sha256": CHECKER._SUMS_DIGEST,
                "sums_signature_sha256": CHECKER._SUMS_SIGNATURE_DIGEST,
                "signer_fingerprint": CHECKER._UBUNTU_SIGNER,
            },
            "vm": {
                "qemu_path": CHECKER._QEMU_PATH,
                "qemu_version": qemu_version,
                "qemu_digest": CHECKER._QEMU_DIGEST,
                "machine": "q35",
                "kvm_api": 12,
                "vcpus": 2,
                "memory_bytes": 2 * 1024 * 1024 * 1024,
                "overlay_virtual_bytes": 3758096384,
                "seed_digest": _digest("seed"),
                "management_address": "127.0.0.1:22227",
                "shared_host_mounts": 0,
                "qemu_argv_digest": "sha256:" + sha256(
                    _canonical(CHECKER._qemu_argv(CHECKER.LAB))
                ).hexdigest(),
            },
            "guest": {
                "os_release_digest": _digest("os-release"),
                "kernel_release": "6.8.0-fixture-generic",
                "kernel_digest": _digest("kernel"),
                "architecture": "x86_64",
                "cgroup_v2": True,
                "apparmor_enabled": True,
                "user_namespaces": True,
                "openat2": True,
                "offline_egress": True,
                "rootfs_digest": _digest("rootfs"),
            },
            "runtime": runtime,
            "supply": {
                "image_digest": CHECKER._IMAGE_DIGEST,
                "rootfs_digest": _digest("rootfs"),
                "runtime_digest": CHECKER.l0.RUNTIME_DIGEST,
                "loader_digest": loader_digest,
                "dependency_closure_digest": dependency_digest,
                "tool_digest": tool_digest,
                "sbom_digest": runtime["sbom_digest"],
                "registry_snapshot_digest": runtime["registry_snapshot_digest"],
                "key_id": self.trust["key_id"],
                "issued_at": "2026-08-26T11:00:00Z",
                "expires_at": "2026-08-26T13:00:00Z",
                "revocation_epoch": 0,
                "rollback_floor": 1,
                "revocation_state_digest": self.trust["revocation_state_digest"],
                "profile_digest": profile_digest,
                "placement_digest": placement_digest,
                "actual_opened_bytes_digest": "sha256:" + sha256(_canonical(opened_artifacts)).hexdigest(),
                "verification_payload_digest": "sha256:" + sha256(_canonical(supply_payload)).hexdigest(),
                "verification_payload": supply_payload,
                "verification_record": supply_record,
                "verifier_backend": "OPENSSL_LIBCRYPTO_SHARED",
                "verifier_code_digest": bindings["verifier_code_digest"],
                "verifier_public_key_digest": bindings["verifier_public_key_digest"],
                "verifier_libcrypto_digest": libcrypto_digest,
            },
            "principals": {
                "active": active,
                "disabled": [
                    {"role": role, "enabled": False, "process": False, "route": False, "fd": False, "credential": False}
                    for role in ("MODEL_GATEWAY", "OBSERVER")
                ],
            },
            "measurements": {
                "resource_vector": profile_raw["resources"],
                "cgroup": {
                    "path": "/harness/session",
                    "controllers": ["cpu", "io", "memory", "pids"],
                    "limits": {
                        "cpu.max": "50000 100000",
                        "io.max": "253:0 rbps=409600 wbps=409600 riops=100 wiops=100",
                        "memory.max": str(resources["MEMORY"] * 1024 * 1024),
                        "memory.swap.max": "0",
                        "pids.max": "8",
                    },
                    "delegated": True,
                    "isolated": True,
                    "cgroup_kill": True,
                    "populated_after_cleanup": 0,
                },
                "quota": {
                    "bytes": resources["OUTPUT_BYTES"],
                    "files": resources["FILES"],
                    "inodes": resources["INODES"],
                    "mount_options": quota_mount,
                    "outside_writes": 0,
                },
                "mounts": {
                    "rootfs_read_only": True,
                    "inputs_read_only": True,
                    "staging_worker_visible": False,
                    "checkout_visible": False,
                    "git_visible": False,
                    "home_visible": False,
                    "durable_db_visible": False,
                    "private_proc": True,
                    "private_non_propagating": True,
                },
                "opened_artifacts": opened_artifacts,
                "broker_ipc": {
                    "profile": profile_raw["broker_ipc"],
                    "runtime": broker_runtime,
                    "holder_payload": holder_payload,
                    "holder_payload_digest": "sha256:" + sha256(holder_bytes).hexdigest(),
                    "holder_signature": "ed25519:" + holder_signature.hex(),
                    "holder_signature_digest": "sha256:" + sha256(holder_signature).hexdigest(),
                    "broker_report": broker_report,
                    "broker_report_digest": "sha256:" + sha256(_canonical(broker_report)).hexdigest(),
                },
                "controller": controller,
                "resource_oracles": resource_oracles,
            },
            "tests": tests,
            "events": events,
            "lifecycle": {
                "prepared_event_id": "event-0",
                "terminal_event_id": "event-1",
                "terminal_state": "STOPPED",
                "restart_event_id": "event-2",
                "cleanup_event_id": "event-3",
                "old_session_resumed": False,
                "retry_created": False,
                "uncertainty_disposition": "QUARANTINED_ESCROW",
                "cgroup_populated_after_cleanup": 0,
                "orphan_processes_after_cleanup": 0,
            },
            "canaries": {
                "staging_before": _digest("staging-before"),
                "staging_after": _digest("staging-after"),
                "checkout_before": _digest("checkout"),
                "checkout_after": _digest("checkout"),
                "home_before": _digest("home"),
                "home_after": _digest("home"),
                "secret_before": _digest("secret"),
                "secret_after": _digest("secret"),
                "durable_db_before": _digest("db"),
                "durable_db_after": _digest("db"),
                "outside_before": _digest("outside"),
                "outside_after": _digest("outside"),
            },
            "residual_risk": CHECKER._RESIDUAL_RISK,
        }

    def _bundle(self, mutate_evidence: object | None = None, mutate_manifest: object | None = None) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        bundle = Path(temporary.name) / "bundle"
        bundle.mkdir(mode=0o700)
        evidence = self._evidence()
        if mutate_evidence is not None:
            mutate_evidence(evidence)
        evidence_bytes = _canonical(evidence)
        (bundle / "evidence.json").write_bytes(evidence_bytes)
        profile_bytes = self.profile_path.read_bytes()
        compiled = compile_profile(json.loads(profile_bytes))
        self.assertIsNotNone(compiled.profile)
        manifest = {
            "bundle_version": "1.0.0",
            "claim": "M3_TEST_PROFILE_RUNTIME_CONFORMANCE",
            "outcome": "VERIFIED",
            "scope": self.trust["scope"],
            "source": deepcopy(self.source),
            "profile": {
                "path": "profiles/l0-lx-a.json",
                "profile_artifact_digest": "sha256:" + sha256(profile_bytes).hexdigest(),
                "compiled_profile_digest": compiled.profile.profile_digest,
                "runtime_path": CHECKER.l0.RUNTIME_PATH,
                "runtime_version": CHECKER.l0.RUNTIME_VERSION,
                "runtime_digest": CHECKER.l0.RUNTIME_DIGEST,
            },
            "attestation": {
                "trust_root_id": self.trust["trust_root_id"],
                "signer_id": self.trust["signer_id"],
                "key_id": self.trust["key_id"],
                "algorithm": self.trust["algorithm"],
                "public_key_fingerprint": self.trust["public_key_fingerprint"],
                "openssl": self.trust["openssl"],
                "issued_at": "2026-08-26T11:00:00Z",
                "expires_at": "2026-08-26T13:00:00Z",
                "revocation_epoch": 0,
                "fencing_epoch": 1,
                "rollback_floor": 1,
                "revocation_state_digest": self.trust["revocation_state_digest"],
                "nonce": "fixture-nonce-1",
            },
            "evidence": {
                "path": "evidence.json",
                "bytes": len(evidence_bytes),
                "digest": "sha256:" + sha256(evidence_bytes).hexdigest(),
            },
        }
        if mutate_manifest is not None:
            mutate_manifest(manifest)
        manifest_bytes = _canonical(manifest)
        (bundle / "manifest.json").write_bytes(manifest_bytes)
        subprocess.run(
            [
                "/usr/bin/openssl", "pkeyutl", "-sign", "-inkey", str(self.private_key),
                "-rawin", "-in", str(bundle / "manifest.json"), "-out", str(bundle / "manifest.sig"),
            ],
            check=True,
            capture_output=True,
            timeout=10,
        )
        return bundle

    def _verify(self, bundle: Path) -> dict[str, object]:
        return CHECKER._verify_bundle(
            bundle,
            root=self.root,
            trust_config=self.trust_path,
            public_key=self.public_key,
            source_state=self.source,
            now=self.now,
            host_lab=None,
        )

    def test_exact_signed_bundle_is_verified_without_changing_product_status(self) -> None:
        result = self._verify(self._bundle())
        self.assertEqual(result["outcome"], "VERIFIED")
        self.assertEqual(result["claim_status"], "M3_TEST_PROFILE_RUNTIME_CONFORMANCE_VERIFIED")
        self.assertEqual(result["product_status"], "NOT_ATTESTED")
        self.assertEqual(
            result["host_verifier_openssl_digest"],
            self.trust["verifier_openssl"]["digest"],
        )

    def test_host_verifier_openssl_is_exact_and_live_overlay_probe_is_force_shared(self) -> None:
        checker_source = Path(CHECKER.__file__).read_text(encoding="utf-8")
        self.assertIn(
            '"/usr/bin/qemu-img", "info", "--force-share", "--output=json"',
            checker_source,
        )
        bundle = self._bundle()
        mutations = {
            "missing": lambda value: value.pop("verifier_openssl"),
            "digest": lambda value: value["verifier_openssl"].update(
                digest=_digest("other-host-openssl")
            ),
            "version": lambda value: value["verifier_openssl"].update(
                version="OpenSSL substituted"
            ),
        }
        for name, mutation in mutations.items():
            altered = deepcopy(self.trust)
            mutation(altered)
            trust_path = Path(self.temporary.name) / f"trust-{name}.json"
            trust_path.write_bytes(_canonical(altered))
            with self.subTest(name=name), self.assertRaises(CHECKER._InvalidEvidence):
                CHECKER._verify_bundle(
                    bundle,
                    root=self.root,
                    trust_config=trust_path,
                    public_key=self.public_key,
                    source_state=self.source,
                    now=self.now,
                    host_lab=None,
                )

    def test_bundle_file_set_signature_and_key_substitution_fail_closed(self) -> None:
        missing = self._bundle()
        (missing / "manifest.sig").unlink()
        with self.assertRaises(CHECKER._InvalidEvidence):
            self._verify(missing)
        extra = self._bundle()
        (extra / "extra").write_bytes(b"x")
        with self.assertRaises(CHECKER._InvalidEvidence):
            self._verify(extra)
        signature = self._bundle()
        (signature / "manifest.sig").write_bytes(b"\x00" * 64)
        with self.assertRaises(CHECKER._InvalidEvidence):
            self._verify(signature)

    def test_duplicate_and_noncanonical_json_are_rejected_before_authority(self) -> None:
        for raw in (b'{"a":1,"a":2}', b'{ "a":1}', b'{"a":NaN}'):
            with self.subTest(raw=raw), self.assertRaises(CHECKER._InvalidEvidence):
                CHECKER._strict_json(raw)

    def test_evidence_completeness_lifecycle_canary_and_supply_mutations_fail_closed(self) -> None:
        mutations = {
            "missing-test": lambda value: value["tests"].pop(),
            "duplicate-test": lambda value: value["tests"].append(deepcopy(value["tests"][0])),
            "unresolved-event": lambda value: value["tests"][0].update(event_ids=["missing-event"]),
            "retry": lambda value: value["lifecycle"].update(retry_created=True),
            "outside-canary": lambda value: value["canaries"].update(outside_after=_digest("changed")),
            "key-substitution": lambda value: value["supply"].update(key_id="other-key"),
            "policy-substitution": lambda value: value["runtime"].update(apparmor_policy_digest=_digest("other-policy")),
        }
        for name, mutation in mutations.items():
            with self.subTest(name=name), self.assertRaises(CHECKER._InvalidEvidence):
                self._verify(self._bundle(mutate_evidence=mutation))

    def test_verifier_pair_controller_resource_and_artifact_bindings_fail_closed(self) -> None:
        mutations = {
            "verifier-code": lambda value: value["runtime"]["verifier"].update(
                code_digest=_digest("other-verifier-code")
            ),
            "verifier-public-key": lambda value: value["runtime"]["verifier"].update(
                public_key_digest=_digest("other-public-key")
            ),
            "verifier-libcrypto": lambda value: value["runtime"]["verifier"].update(
                libcrypto_digest=_digest("other-libcrypto")
            ),
            "false-independent-implementation-claim": lambda value: value["runtime"]["verifier"].update(
                independent_implementations=True
            ),
            "supply-signature": lambda value: value["supply"]["verification_record"].update(
                proof="ed25519:" + "00" * 64
            ),
            "broker-message-binding": lambda value: value["measurements"]["broker_ipc"]["runtime"].update(
                message_binding_digest=_digest("other-message-binding")
            ),
            "broker-holder-signature": lambda value: value["measurements"]["broker_ipc"].update(
                holder_signature="ed25519:" + "00" * 64
            ),
            "broker-creator-namespace": lambda value: value["measurements"]["broker_ipc"][
                "broker_report"
            ].update(creator_credentials=[1, 0, 0]),
            "controller-code": lambda value: value["measurements"]["controller"]["code_descriptor"].update(
                digest=_digest("other-controller-code")
            ),
            "controller-mode": lambda value: value["measurements"]["controller"][
                "code_descriptor"
            ].update(mode=0o755),
            "controller-proof": lambda value: value["measurements"]["controller"]["control_proof"].update(
                closed=False
            ),
            "memory-swap": lambda value: value["measurements"]["resource_oracles"]["memory"].update(
                swap_max="1"
            ),
            "quota-files": lambda value: value["measurements"]["resource_oracles"]["quota"].update(
                files=15
            ),
            "opened-artifact": lambda value: value["measurements"]["opened_artifacts"][0].update(
                digest=_digest("other-opened-bytes")
            ),
        }
        for name, mutation in mutations.items():
            with self.subTest(name=name), self.assertRaises(CHECKER._InvalidEvidence):
                self._verify(self._bundle(mutate_evidence=mutation))

    def test_stale_attestation_and_source_substitution_fail_with_valid_signature(self) -> None:
        stale = lambda value: value["attestation"].update(issued_at="2026-08-20T11:00:00Z", expires_at="2026-08-20T13:00:00Z")
        source = lambda value: value["source"].update(commit="3" * 40)
        for name, mutation in (("stale", stale), ("source", source)):
            with self.subTest(name=name), self.assertRaises(CHECKER._InvalidEvidence):
                self._verify(self._bundle(mutate_manifest=mutation))


if __name__ == "__main__":
    unittest.main()
