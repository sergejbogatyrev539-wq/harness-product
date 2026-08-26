from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest

import harness_product.l0 as l0
from harness_product.durable import VerificationResult, VerificationStatus
from tests import test_l0 as l0_tests


def digest_bytes(value: bytes) -> str:
    return "sha256:" + sha256(value).hexdigest()


class ExactSupplyVerifier:
    """Test-only external verifier; no inline boolean or self-attestation is accepted."""

    source = {"verifier_id": "supply-verifier-1", "issuer_id": "supply-attestor-1", "key_id": "supply-key-1", "proof": "proof-1"}

    @staticmethod
    def externally_pinned(payload: dict[str, object]) -> bool:
        signer = payload.get("signer")
        placement = payload.get("placement")
        bindings = l0_tests.valid_raw()["measurement_bindings"]
        return (
            signer
            == {
                "algorithm": "ED25519",
                "key_id": "supply-key-1",
                "revocation_epoch": 7,
                "rollback_floor": 7,
                "verifier_code_digest": bindings["verifier_code_digest"],
                "verifier_public_key_digest": bindings["verifier_public_key_digest"],
                "verifier_libcrypto_digest": bindings["verifier_libcrypto_digest"],
                "signer_id": "supply-signer-1",
                "trust_root_id": "supply-root-1",
            }
            and type(placement) is dict
            and all(
                placement.get(key) == value
                for key, value in {
                    "placement_id": "placement-l0-lx-a-1",
                    "host_id": "host-l0-1",
                    "subject_instance_id": "worker-instance-1",
                    "process_tree_id": "worker-tree-1",
                    "session_id": "session-1",
                    "nonce": "supply-nonce-1",
                    "fencing_epoch": 11,
                    "revocation_epoch": 7,
                    "rootfs_binding_digest": digest_bytes(b"rootfs-binding"),
                    "staging_binding_digest": digest_bytes(b"staging-binding"),
                    "cgroup_binding_digest": digest_bytes(b"cgroup-binding"),
                    "fd_inventory_digest": digest_bytes(b"fd-inventory"),
                    "namespace_plan_digest": digest_bytes(b"namespace-plan"),
                    "broker_binding_digest": l0.compile_profile(l0_tests.valid_raw()).profile.broker_binding_digest,
                }.items()
            )
        )

    def __init__(self, *, status: VerificationStatus = VerificationStatus.VERIFIED) -> None:
        self.status = status
        self.calls: list[tuple[bytes, bytes, str]] = []

    def verify(self, payload: bytes, record: bytes, observed_at: str) -> VerificationResult:
        self.calls.append((payload, record, observed_at))
        try:
            payload_value = json.loads(payload)
            record_value = json.loads(record)
        except (UnicodeDecodeError, json.JSONDecodeError):
            payload_value = record_value = None
        payload_digest = digest_bytes(payload)
        record_digest = digest_bytes(record)
        valid = (
            type(payload_value) is dict
            and type(record_value) is dict
            and frozenset(record_value) == {"verification_version", "verifier_id", "issuer_id", "key_id", "payload_digest", "bindings", "proof"}
            and record_value["bindings"] == payload_value
            and record_value["payload_digest"] == payload_digest
            and all(record_value[name] == value for name, value in self.source.items())
            and payload_value.get("signer", {}).get("signer_id") != record_value["issuer_id"]
            and self.externally_pinned(payload_value)
        )
        return VerificationResult(
            status=self.status if valid else VerificationStatus.REJECTED,
            verifier_id=self.source["verifier_id"],
            payload_digest=payload_digest,
            record_digest=record_digest,
        )


class L0SupplyBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="harness-l0-supply-")
        self.serial = 0

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def fixture(self) -> tuple[l0.CompiledL0Profile, l0.HostMeasurement, dict[str, object], list[int], dict[str, Path]]:
        self.serial += 1
        root = Path(self.temporary.name) / str(self.serial)
        root.mkdir(mode=0o700)
        values = {
            "ROOTFS_MANIFEST": b"rootfs-manifest-v1\n",
            "LOADER": b"loader-v1\n",
            "DEPENDENCY_CLOSURE": b"dependency-closure-v1\n",
            "TOOL": b"tool-v1\n",
            "SBOM": b"sbom-v1\n",
            "REGISTRY_SNAPSHOT": b"registry-snapshot-v7\n",
            "SECCOMP_PROFILE": b"seccomp-v1\n",
            "LSM_POLICY": b"lsm-v1\n",
        }
        descriptors: list[int] = []
        paths: dict[str, Path] = {}
        artifacts: list[dict[str, object]] = []
        for role, content in values.items():
            path = root / role.lower()
            path.write_bytes(content)
            os.chmod(path, 0o444)
            descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            descriptors.append(descriptor)
            paths[role] = path
            artifacts.append(
                {
                    "role": role,
                    "artifact_id": role.lower(),
                    "descriptor": descriptor,
                    "expected_bytes_digest": digest_bytes(content),
                    "provenance_digest": digest_bytes(b"provenance:" + role.encode("ascii")),
                }
            )
        raw_profile = l0_tests.valid_raw()
        raw_profile["measurement_bindings"].update(
            rootfs_manifest_digest=digest_bytes(values["ROOTFS_MANIFEST"]),
            seccomp_profile_digest=digest_bytes(values["SECCOMP_PROFILE"]),
            lsm_policy_digest=digest_bytes(values["LSM_POLICY"]),
        )
        compiled = l0.compile_profile(raw_profile)
        self.assertIsNotNone(compiled.profile)
        profile = compiled.profile
        observation = l0_tests.L0CompilerTests().observation()
        measurement = l0._verify_host(profile, observation)
        raw = {
            "supply_version": "1.0.0",
            "observed_at": "2026-08-25T12:00:00Z",
            "profile_digest": profile.profile_digest,
            "measurement_digest": measurement.measurement_digest,
            "runtime": {"path": l0.RUNTIME_PATH, "version": l0.RUNTIME_VERSION, "digest": l0.RUNTIME_DIGEST},
            "image": {
                "image_id": "image-l0-lx-a-v1",
                "rootfs_manifest_digest": digest_bytes(values["ROOTFS_MANIFEST"]),
                "platform": "linux",
                "architecture": "x86_64",
            },
            "registry": {
                "snapshot_digest": digest_bytes(values["REGISTRY_SNAPSHOT"]),
                "reference": "registry-snapshot-v7",
                "generation": 7,
                "rollback_floor": 7,
                "issued_at": "2026-08-25T11:00:00Z",
                "expires_at": "2026-08-25T13:00:00Z",
            },
            "signer": {
                "trust_root_id": "supply-root-1",
                "signer_id": "supply-signer-1",
                "key_id": "supply-key-1",
                "algorithm": "ED25519",
                "revocation_epoch": 7,
                "rollback_floor": 7,
                "verifier_code_digest": raw_profile["measurement_bindings"]["verifier_code_digest"],
                "verifier_public_key_digest": raw_profile["measurement_bindings"]["verifier_public_key_digest"],
                "verifier_libcrypto_digest": raw_profile["measurement_bindings"]["verifier_libcrypto_digest"],
            },
            "placement": {
                "placement_id": "placement-l0-lx-a-1",
                "host_id": "host-l0-1",
                "subject_instance_id": "worker-instance-1",
                "process_tree_id": "worker-tree-1",
                "session_id": "session-1",
                "nonce": "supply-nonce-1",
                "fencing_epoch": 11,
                "revocation_epoch": 7,
                "issued_at": "2026-08-25T11:00:00Z",
                "expires_at": "2026-08-25T13:00:00Z",
                "rootfs_binding_digest": digest_bytes(b"rootfs-binding"),
                "staging_binding_digest": digest_bytes(b"staging-binding"),
                "cgroup_binding_digest": digest_bytes(b"cgroup-binding"),
                "broker_binding_digest": profile.broker_binding_digest,
                "fd_inventory_digest": digest_bytes(b"fd-inventory"),
                "namespace_plan_digest": digest_bytes(b"namespace-plan"),
            },
            "artifacts": artifacts,
            "verification": dict(ExactSupplyVerifier.source),
        }
        return profile, measurement, raw, descriptors, paths

    @staticmethod
    def close(descriptors: list[int]) -> None:
        for descriptor in descriptors:
            os.close(descriptor)

    def assert_stop(self, result: object) -> None:
        self.assertIs(type(result), l0.SupplyResult)
        self.assertEqual(result.outcome, l0.L0Outcome.STOP)
        self.assertIsNone(result.verification)

    def test_exact_external_supply_verification_is_frozen_canonical_and_effect_free(self) -> None:
        profile, measurement, raw, descriptors, _ = self.fixture()
        verifier = ExactSupplyVerifier()
        forbidden = AssertionError("supply verifier attempted network or runtime execution")
        try:
            from unittest.mock import patch

            with (
                patch.object(l0, "_runtime_output", return_value=l0.RUNTIME_VERSION),
                patch.object(socket, "socket", side_effect=forbidden),
                patch.object(subprocess, "run", side_effect=forbidden),
                patch.object(subprocess, "Popen", side_effect=forbidden),
            ):
                result = l0.verify_supply(profile, measurement, raw, verifier=verifier)
            self.assertNotEqual(result.outcome, l0.L0Outcome.STOP, result)
            self.assertIs(type(result.verification), l0.SupplyVerification)
            self.assertTrue(type(result).__dataclass_params__.frozen)
            self.assertTrue(type(result.verification).__dataclass_params__.frozen)
            self.assertRegex(result.verification.supply_digest, r"^sha256:[0-9a-f]{64}$")
            self.assertEqual(len(verifier.calls), 1)
            payload, record, observed_at = verifier.calls[0]
            self.assertEqual(payload, json.dumps(json.loads(payload), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode())
            self.assertEqual(record, json.dumps(json.loads(record), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode())
            self.assertEqual(observed_at, raw["observed_at"])
        finally:
            self.close(descriptors)

    def test_default_self_signed_and_verified_boolean_never_establish_supply_authority(self) -> None:
        profile, measurement, raw, descriptors, _ = self.fixture()
        try:
            self.assert_stop(l0.verify_supply(profile, measurement, raw))
            self_signed = deepcopy(raw)
            self_signed["signer"]["signer_id"] = ExactSupplyVerifier.source["issuer_id"]
            self.assert_stop(l0.verify_supply(profile, measurement, self_signed, verifier=ExactSupplyVerifier()))
            inline = deepcopy(raw)
            inline["verified"] = True
            self.assert_stop(l0.verify_supply(profile, measurement, inline, verifier=ExactSupplyVerifier()))
        finally:
            self.close(descriptors)

    def test_closed_hostile_stale_rollback_and_every_supply_binding_substitution_stops(self) -> None:
        cases: list[tuple[str, callable]] = []
        cases.extend(
            [
                ("missing", lambda raw, paths: raw.pop("image")),
                ("unknown", lambda raw, paths: raw.__setitem__("ambient_supply", True)),
                ("boolean", lambda raw, paths: raw["registry"].__setitem__("generation", True)),
                ("stale", lambda raw, paths: raw.__setitem__("observed_at", "2026-08-25T13:00:00Z")),
                ("rollback", lambda raw, paths: raw["registry"].__setitem__("generation", 6)),
                ("runtime-path", lambda raw, paths: raw["runtime"].__setitem__("path", "/tmp/bwrap")),
                ("runtime-digest", lambda raw, paths: raw["runtime"].__setitem__("digest", "sha256:" + "0" * 64)),
                ("rootfs", lambda raw, paths: raw["image"].__setitem__("rootfs_manifest_digest", "sha256:" + "1" * 64)),
                ("loader", lambda raw, paths: raw["artifacts"][1].__setitem__("expected_bytes_digest", "sha256:" + "2" * 64)),
                ("dependency", lambda raw, paths: raw["artifacts"][2].__setitem__("expected_bytes_digest", "sha256:" + "3" * 64)),
                ("tool", lambda raw, paths: raw["artifacts"][3].__setitem__("expected_bytes_digest", "sha256:" + "4" * 64)),
                ("sbom", lambda raw, paths: raw["artifacts"][4].__setitem__("expected_bytes_digest", "sha256:" + "5" * 64)),
                ("registry", lambda raw, paths: raw["registry"].__setitem__("snapshot_digest", "sha256:" + "6" * 64)),
                ("signer", lambda raw, paths: raw["signer"].__setitem__("signer_id", "other-signer")),
                ("key", lambda raw, paths: raw["signer"].__setitem__("key_id", "other-key")),
                ("trust-root", lambda raw, paths: raw["signer"].__setitem__("trust_root_id", "other-root")),
                ("profile", lambda raw, paths: raw.__setitem__("profile_digest", "sha256:" + "8" * 64)),
                ("measurement", lambda raw, paths: raw.__setitem__("measurement_digest", "sha256:" + "9" * 64)),
                ("placement", lambda raw, paths: raw["placement"].__setitem__("placement_id", "other-placement")),
                ("placement-rootfs", lambda raw, paths: raw["placement"].__setitem__("rootfs_binding_digest", "sha256:" + "c" * 64)),
                ("placement-staging", lambda raw, paths: raw["placement"].__setitem__("staging_binding_digest", "sha256:" + "d" * 64)),
                ("placement-cgroup", lambda raw, paths: raw["placement"].__setitem__("cgroup_binding_digest", "sha256:" + "e" * 64)),
                ("placement-broker", lambda raw, paths: raw["placement"].__setitem__("broker_binding_digest", "sha256:" + "f" * 64)),
                ("placement-fds", lambda raw, paths: raw["placement"].__setitem__("fd_inventory_digest", "sha256:" + "0" * 64)),
                ("placement-namespaces", lambda raw, paths: raw["placement"].__setitem__("namespace_plan_digest", "sha256:" + "1" * 64)),
                ("artifact-digest", lambda raw, paths: raw["artifacts"][0].__setitem__("expected_bytes_digest", "sha256:" + "b" * 64)),
            ]
        )
        for name, mutate in cases:
            with self.subTest(name=name):
                profile, measurement, raw, descriptors, _ = self.fixture()
                try:
                    mutate(raw, {})
                    self.assert_stop(l0.verify_supply(profile, measurement, raw, verifier=ExactSupplyVerifier()))
                finally:
                    self.close(descriptors)
        profile, measurement, raw, descriptors, paths = self.fixture()
        try:
            os.chmod(paths["ROOTFS_MANIFEST"], 0o644)
            paths["ROOTFS_MANIFEST"].write_bytes(b"substituted-opened-bytes")
            os.chmod(paths["ROOTFS_MANIFEST"], 0o444)
            self.assert_stop(l0.verify_supply(profile, measurement, raw, verifier=ExactSupplyVerifier()))
        finally:
            self.close(descriptors)
        cyclic_profile, cyclic_measurement, cyclic, descriptors, _ = self.fixture()
        try:
            cyclic["artifacts"] = cyclic
            self.assert_stop(l0.verify_supply(cyclic_profile, cyclic_measurement, cyclic, verifier=ExactSupplyVerifier()))
        finally:
            self.close(descriptors)


if __name__ == "__main__":
    unittest.main()
