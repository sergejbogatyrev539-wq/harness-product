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
        result = compile_profile(json.loads(PROFILE.read_bytes()))
        self.assertEqual(result.outcome, L0Outcome.COMPILED_DRAFT)
        self.assertIsNotNone(result.profile)

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
        cls.profile_path.write_bytes(PROFILE.read_bytes())
        cls.apparmor_path = profiles / "l0-lx-a.apparmor"
        cls.apparmor_path.write_bytes(b"test apparmor policy\n")
        cls.seccomp_path = profiles / "l0-lx-a-seccomp.json"
        cls.seccomp_path.write_bytes(b'{"policy":"test"}\n')
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
        cls.trust = {
            "algorithm": "ED25519",
            "key_id": "fixture-key-1",
            "openssl": {
                "digest": "sha256:" + sha256(Path("/usr/bin/openssl").read_bytes()).hexdigest(),
                "path": "/usr/bin/openssl",
                "version": openssl_version,
            },
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
        }
        cls.trust_path = Path(cls.temporary.name) / "trust.json"
        cls.trust_path.write_text(json.dumps(cls.trust, sort_keys=True), encoding="utf-8")
        cls.source = {
            "commit": "1" * 40,
            "tree": "2" * 40,
            "files": {"fixture": _digest("fixture-source")},
        }
        cls.source["files_digest"] = "sha256:" + sha256(_canonical(cls.source["files"])).hexdigest()
        cls.now = datetime(2026, 8, 26, 12, 0, 0, tzinfo=UTC)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def _evidence(self) -> dict[str, object]:
        profile_raw = json.loads(self.profile_path.read_bytes())
        compiled = compile_profile(profile_raw)
        self.assertIsNotNone(compiled.profile)
        profile_digest = compiled.profile.profile_digest
        labels = {
            row["role"]: row["security_label"]
            for row in profile_raw["principals"]
            if row["enabled"]
        }
        network = {
            "ipv4": False,
            "ipv6": False,
            "loopback": False,
            "routes": False,
            "dns": False,
            "raw": False,
            "packet": False,
            "broad_unix": False,
            "connected_fds": False,
        }
        roles = ("ATTESTOR", "CONTROLLER", "AGENT_WORKER", "BROKER", "EXECUTOR")
        active = []
        for number, role in enumerate(roles):
            active.append(
                {
                    "role": role,
                    "launcher_uid": 3000 + number,
                    "launcher_gid": 4000 + number,
                    "host_uid": 100000 + number,
                    "host_gid": 200000 + number,
                    "namespace_uid": 1000 + number,
                    "namespace_gid": 2000 + number,
                    "session_id": f"session-{number}",
                    "process_id": 500 + number,
                    "cgroup": f"/harness/session-{number}",
                    "security_label": (
                        f"harness-l0-lx-a.{role.lower()}"
                        if role in {"ATTESTOR", "CONTROLLER"}
                        else labels[role]
                    ),
                    "credential_namespace": f"credential-{number}",
                    "namespace_ids": {
                        key: f"{key}-{number}"
                        for key in ("user", "mount", "pid", "ipc", "uts", "network", "cgroup")
                    },
                    "fd_inventory": [3] if role == "AGENT_WORKER" else [],
                    "network": dict(network),
                }
            )
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
        artifact_roles = (
            "ROOTFS", "BWRAP", "AA_EXEC", "PYTHON", "SECCOMP_BPF", "APPARMOR_POLICY", "SBOM", "REGISTRY_SNAPSHOT"
        )
        opened_artifacts = [
            {
                "role": role,
                "path": f"/artifact/{role.lower()}",
                "device": 1,
                "inode": 100 + number,
                "bytes": 10 + number,
                "digest": _digest(f"artifact-{role}"),
            }
            for number, role in enumerate(artifact_roles)
        ]
        tool = lambda path, version, digest, package, package_version: {  # noqa: E731
            "path": path,
            "version": version,
            "digest": digest,
            "package": package,
            "package_version": package_version,
        }
        runtime = {
            "backend": tool("/usr/bin/bwrap", "bubblewrap 0.9.0", CHECKER.l0.RUNTIME_DIGEST, "bubblewrap", "0.9.0-1ubuntu0.1"),
            "aa_exec": tool("/usr/bin/aa-exec", "aa-exec 4.0.1", _digest("aa-exec"), "apparmor", "4.0.1"),
            "openssl": tool("/usr/bin/openssl", self.trust["openssl"]["version"], self.trust["openssl"]["digest"], "openssl", "3.0.13"),
            "python": tool("/usr/bin/python3.12", "Python 3.12.3", _digest("python"), "python3.12", "3.12.3"),
            "apparmor_parser": tool("/usr/sbin/apparmor_parser", "AppArmor parser 4.0.1", _digest("parser"), "apparmor", "4.0.1"),
            "dependencies": [
                {"path": f"/lib/dependency-{number}.so", "digest": _digest(f"dependency-{number}"), "package": f"package-{number}", "version": "1.0"}
                for number in range(4)
            ],
            "apparmor_policy_digest": "sha256:" + sha256(self.apparmor_path.read_bytes()).hexdigest(),
            "seccomp_policy_digest": "sha256:" + sha256(self.seccomp_path.read_bytes()).hexdigest(),
            "seccomp_bpf_digest": _digest("seccomp-bpf"),
            "sbom_digest": _digest("sbom"),
            "registry_snapshot_digest": _digest("registry"),
            "profile_digest": profile_digest,
            "code_digest": _digest("code"),
            "package_index_digest": _digest("package-index"),
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
                "loader_digest": _digest("loader"),
                "dependency_closure_digest": _digest("dependencies"),
                "tool_digest": _digest("tool"),
                "sbom_digest": runtime["sbom_digest"],
                "registry_snapshot_digest": runtime["registry_snapshot_digest"],
                "key_id": self.trust["key_id"],
                "issued_at": "2026-08-26T11:00:00Z",
                "expires_at": "2026-08-26T13:00:00Z",
                "revocation_epoch": 0,
                "rollback_floor": 1,
                "revocation_state_digest": self.trust["revocation_state_digest"],
                "profile_digest": profile_digest,
                "placement_digest": _digest("placement"),
                "actual_opened_bytes_digest": _digest("opened-bytes"),
                "verification_payload_digest": _digest("verification-payload"),
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
                        "memory.max": "67108864",
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
                    "mount_options": f"size={resources['OUTPUT_BYTES']},nr_inodes={resources['INODES']}",
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
        )

    def test_exact_signed_bundle_is_verified_without_changing_product_status(self) -> None:
        result = self._verify(self._bundle())
        self.assertEqual(result["outcome"], "VERIFIED")
        self.assertEqual(result["claim_status"], "M3_TEST_PROFILE_RUNTIME_CONFORMANCE_VERIFIED")
        self.assertEqual(result["product_status"], "NOT_ATTESTED")

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

    def test_stale_attestation_and_source_substitution_fail_with_valid_signature(self) -> None:
        stale = lambda value: value["attestation"].update(issued_at="2026-08-20T11:00:00Z", expires_at="2026-08-20T13:00:00Z")
        source = lambda value: value["source"].update(commit="3" * 40)
        for name, mutation in (("stale", stale), ("source", source)):
            with self.subTest(name=name), self.assertRaises(CHECKER._InvalidEvidence):
                self._verify(self._bundle(mutate_manifest=mutation))


if __name__ == "__main__":
    unittest.main()
