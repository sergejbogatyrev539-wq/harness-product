from __future__ import annotations

from contextlib import ExitStack
import importlib.util
import inspect
from enum import Enum
from io import BytesIO, StringIO
import json
from copy import deepcopy
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "profiles/m4-lx-a.json"
POLICY = ROOT / "profiles/m4-lx-a.apparmor"
RUNNER = ROOT / "scripts/run_m4_vm_conformance.py"
SERVICE = ROOT / "profiles/harness-m4-controller@.service"
L0_PROFILE = ROOT / "profiles/l0-lx-a.json"
L0_SECCOMP = ROOT / "profiles/l0-lx-a-seccomp.json"
L0_BROKER_SECCOMP = ROOT / "profiles/l0-lx-a-broker-seccomp.json"
L0_EXECUTOR_SECCOMP = ROOT / "profiles/l0-lx-a-executor-seccomp.json"
M3_RUNNER = ROOT / "scripts/run_m3_vm_conformance.py"
HOST_LAUNCHER = ROOT / "scripts/run_m4_host_qualification.py"


def _module():
    specification = importlib.util.spec_from_file_location("harness_m4_vm_runner", RUNNER)
    if specification is None or specification.loader is None:
        raise AssertionError("runner module unavailable")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _host_module():
    specification = importlib.util.spec_from_file_location(
        "harness_m4_host_launcher_reason_boundary", HOST_LAUNCHER
    )
    if specification is None or specification.loader is None:
        raise AssertionError("host launcher module unavailable")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


class M4VMRunnerContractTests(unittest.TestCase):
    @staticmethod
    def _qualification_contract(
        module,
        *,
        candidate: str = "b" * 40,
        tree: str = "c" * 40,
        source_files_digest: str = "sha256:" + "d" * 64,
        seed_digest: str = "sha256:" + "e" * 64,
        host_provenance_digest: str = "sha256:" + "f" * 64,
    ):
        core = {
            "contract_version": "2.0.0",
            "contract_kind": "M4_EXACT_DISPOSABLE_TEST_PROFILE_QUALIFICATION_V2",
            "user_scope_reference": (
                "/home/a1/.codex/attachments/"
                "4adf762e-32a5-45e2-bf75-3c79125ace23/pasted-text.txt"
            ),
            "user_goal_digest": (
                "sha256:431777706d5b37c95c2dfebac910b1ce6a57908fe8650353058c58a83feff20b"
            ),
            "candidate": candidate,
            "tree": tree,
            "attempt": 1,
            "source_files_digest": source_files_digest,
            "canonical_profile_digest": (
                "sha256:50947b4b4ae139effbaddd749c7175a15755675f824e0ae1ed734a85694b4682"
            ),
            "raw_profile_artifact_digest": (
                "sha256:50947b4b4ae139effbaddd749c7175a15755675f824e0ae1ed734a85694b4682"
            ),
            "base_image_digest": (
                "sha256:6e40c07ae715f744f84af0bec76415cc1987dd115b4b8de437818561f01a3733"
            ),
            "predecessor_qualification_ledger_digest": (
                "sha256:719505206caf364c6c0d40983687416bcca5644f879a46254714621cb070d5f9"
            ),
            "predecessor_diagnostic_ledger_digest": (
                "sha256:6d5d1d00dc2fc303a061c1fc6f3456fb1e6c9fb1c1baae3f667a6521f8382d78"
            ),
            "predecessor_diagnostic_bundle_digest": (
                "sha256:91abc47ad6070c8b9c8cad89369780b698a696c3e90aed5e2c84cb45f0b1418d"
            ),
            "max_attempts": 2,
            "success_target": 1,
            "success_target_authorizing": False,
        }
        core_digest = module._digest_bytes(module._canonical(core))
        environment_preimage = {
            "contract_core_digest": core_digest,
            "source_archive_digest": "sha256:" + "2" * 64,
            "seed_digest": seed_digest,
            "package_runtime_plan_digest": "sha256:" + "3" * 64,
            "host_provenance_digest": host_provenance_digest,
        }
        contract = {
            "contract_core": core,
            "contract_core_digest": core_digest,
            "environment_preimage": environment_preimage,
            "environment_digest": module._digest_bytes(
                module._canonical(environment_preimage)
            ),
        }
        return contract, module._digest_bytes(module._canonical(contract))

    @staticmethod
    def _qualification_request(module, **changes):
        contract, contract_digest = M4VMRunnerContractTests._qualification_contract(
            module, **changes
        )
        return {
            "request_version": "2.0.0",
            "qualification_contract": contract,
            "qualification_contract_digest": contract_digest,
        }

    @staticmethod
    def _one_use_scope_projection(
        *,
        candidate: str = "b" * 40,
        tree: str = "c" * 40,
        user_scope_reference: str = (
            "thread:/goal/m4-one-use-qualification-contract/2026-08-28"
        ),
    ):
        return {
            "record_version": "1.0.0",
            "record_kind": "M4_ONE_USE_QUALIFICATION_SCOPE_PROJECTION",
            "authority": "NONE",
            "user_scope_reference": user_scope_reference,
            "candidate": candidate,
            "tree": tree,
            "max_attempts": 1,
            "success_target": 1,
            "success_target_authorizing": False,
            "predecessor_qualification_ledger_digest": (
                "sha256:c80f4eb33b811b59a4f80aee5fdf781964b441d20e1620ca4b1f2b63f30c479a"
            ),
            "predecessor_diagnostic_ledger_digest": (
                "sha256:f6a93ebc7f06447ed2be71f1e43c2c65d488bd9a5cb9a26cc3f03b7252f77cc3"
            ),
            "predecessor_diagnostic_bundle_digest": (
                "sha256:e42fbd54170edcabe49814366ccf8fa7452eb6b167d50c2c799d2d611d95b623"
            ),
        }

    @staticmethod
    def _one_use_qualification_contract(
        module,
        *,
        candidate: str = "b" * 40,
        tree: str = "c" * 40,
        source_files_digest: str = "sha256:" + "d" * 64,
        seed_digest: str = "sha256:" + "e" * 64,
        host_provenance_digest: str = "sha256:" + "f" * 64,
    ):
        projection = M4VMRunnerContractTests._one_use_scope_projection(
            candidate=candidate, tree=tree
        )
        core = {
            "contract_version": "3.0.0",
            "contract_kind": "M4_REQUEST_BOUND_ONE_USE_QUALIFICATION",
            "scope_projection": projection,
            "user_scope_reference": projection["user_scope_reference"],
            "user_goal_digest": module._digest_bytes(module._canonical(projection)),
            "candidate": candidate,
            "tree": tree,
            "attempt": 1,
            "source_files_digest": source_files_digest,
            "canonical_profile_digest": module.CANONICAL_PROFILE_DIGEST,
            "raw_profile_artifact_digest": module.CANONICAL_PROFILE_DIGEST,
            "base_image_digest": module.BASE_IMAGE_DIGEST,
            "predecessor_qualification_ledger_digest": projection[
                "predecessor_qualification_ledger_digest"
            ],
            "predecessor_diagnostic_ledger_digest": projection[
                "predecessor_diagnostic_ledger_digest"
            ],
            "predecessor_diagnostic_bundle_digest": projection[
                "predecessor_diagnostic_bundle_digest"
            ],
            "max_attempts": 1,
            "success_target": 1,
            "success_target_authorizing": False,
        }
        core_digest = module._digest_bytes(module._canonical(core))
        environment_preimage = {
            "contract_core_digest": core_digest,
            "source_archive_digest": "sha256:" + "2" * 64,
            "seed_digest": seed_digest,
            "package_runtime_plan_digest": "sha256:" + "3" * 64,
            "host_provenance_digest": host_provenance_digest,
        }
        contract = {
            "contract_core": core,
            "contract_core_digest": core_digest,
            "environment_preimage": environment_preimage,
            "environment_digest": module._digest_bytes(
                module._canonical(environment_preimage)
            ),
        }
        return contract, module._digest_bytes(module._canonical(contract))

    @staticmethod
    def _one_use_qualification_request(module, **changes):
        contract, contract_digest = (
            M4VMRunnerContractTests._one_use_qualification_contract(
                module, **changes
            )
        )
        return {
            "request_version": "3.0.0",
            "qualification_contract": contract,
            "qualification_contract_digest": contract_digest,
        }

    @staticmethod
    def _post_v2_diagnostic_request(
        module,
        *,
        candidate: str = "b" * 40,
        tree: str = "c" * 40,
        source_files_digest: str = "sha256:" + "d" * 64,
        seed_digest: str = "sha256:" + "e" * 64,
        host_provenance_digest: str = "sha256:" + "f" * 64,
    ):
        failed_ledger_digest = (
            "sha256:c80f4eb33b811b59a4f80aee5fdf781964b441d20e1620ca4b1f2b63f30c479a"
        )
        goal_record = {
            "goal_version": "1.0.0",
            "goal_kind": "M4_POST_V2_PRE_ADMISSION_DIAGNOSTIC",
            "user_scope_reference": (
                "thread:/goal/m4-post-v2-pre-admission-diagnostic/2026-08-28"
            ),
            "predecessor_qualification_ledger_digest": failed_ledger_digest,
            "max_attempts": 1,
            "allowed_phases": ["provision", "run"],
            "allowed_outcome": "SANITIZED_DIAGNOSTIC_ONLY",
            "forbidden_operations": [
                "AUTOMATIC_RETRY",
                "KEY_ADMISSION_ARTIFACT",
                "QUALIFICATION_EVIDENCE_EXPORT",
                "QUALIFICATION_V2_LEDGER_WRITE",
                "REBOOT_OR_RECOVERY",
                "RUNTIME_VERIFIED_CLAIM",
                "WORKER_OR_EFFECT_EXECUTION",
            ],
        }
        core = {
            "contract_version": "1.0.0",
            "contract_kind": "M4_POST_V2_PRE_ADMISSION_DIAGNOSTIC",
            "goal_record": goal_record,
            "goal_record_digest": module._digest_bytes(module._canonical(goal_record)),
            "failed_v2_candidate": (
                "a2336eb987364cc6bff0fdcdc7d7bfb8b21b3db8"
            ),
            "failed_v2_tree": "106facb47f1b203ed121917adfa7c885374d9fdc",
            "failed_qualification_v2_ledger_digest": failed_ledger_digest,
            "candidate": candidate,
            "tree": tree,
            "attempt": 1,
            "source_files_digest": source_files_digest,
            "canonical_profile_digest": module.CANONICAL_PROFILE_DIGEST,
            "raw_profile_artifact_digest": module.CANONICAL_PROFILE_DIGEST,
            "base_image_digest": module.BASE_IMAGE_DIGEST,
            "max_attempts": 1,
            "allowed_phases": ["provision", "run"],
            "non_authorizing": True,
        }
        core_digest = module._digest_bytes(module._canonical(core))
        environment = {
            "contract_core_digest": core_digest,
            "source_archive_digest": "sha256:" + "2" * 64,
            "seed_digest": seed_digest,
            "package_runtime_plan_digest": "sha256:" + "3" * 64,
            "host_provenance_digest": host_provenance_digest,
        }
        contract = {
            "contract_core": core,
            "contract_core_digest": core_digest,
            "environment_preimage": environment,
            "environment_digest": module._digest_bytes(module._canonical(environment)),
        }
        return {
            "request_version": "2.1.0",
            "mode": "POST_V2_PRE_ADMISSION_DIAGNOSTIC",
            "diagnostic_contract": contract,
            "diagnostic_contract_digest": module._digest_bytes(
                module._canonical(contract)
            ),
        }

    @staticmethod
    def _run_state(module, *, one_use: bool = False):
        digest = "sha256:" + "a" * 64
        candidate = "b" * 40
        tree = "c" * 40
        source = {
            "commit": candidate,
            "tree": tree,
            "files": {},
            "files_digest": "sha256:" + "d" * 64,
        }
        host_provenance = {
            "image": {
                "sha256": (
                    "sha256:6e40c07ae715f744f84af0bec76415cc1987dd115b4b8de437818561f01a3733"
                )
            },
            "vm": {"seed_digest": "sha256:" + "e" * 64},
        }
        contract_builder = (
            M4VMRunnerContractTests._one_use_qualification_contract
            if one_use
            else M4VMRunnerContractTests._qualification_contract
        )
        contract, contract_digest = contract_builder(
            module,
            candidate=candidate,
            tree=tree,
            source_files_digest=source["files_digest"],
            seed_digest=host_provenance["vm"]["seed_digest"],
            host_provenance_digest=module._digest_bytes(
                module._canonical(host_provenance)
            ),
        )
        package_runtime_plan = {
            "plan_version": "1.0.0",
            "packages": dict(module.PACKAGE_VERSIONS),
            "provisioning_script_digest": digest,
            "package_sources": {
                path: (
                    module.PACKAGE_SOURCE_UBUNTU_DIGEST
                    if path == module.PACKAGE_SOURCE_UBUNTU_PATH
                    else digest
                )
                for path in module.PACKAGE_SOURCE_PATHS
            },
            "runtime_configs": {
                path: digest for path in module.RUNTIME_CONFIG_PATHS
            },
            "runtime_tools": {
                path: digest for path in module.RUNTIME_TOOL_PATHS
            },
        }
        contract["environment_preimage"]["package_runtime_plan_digest"] = (
            module._digest_bytes(module._canonical(package_runtime_plan))
        )
        contract["environment_digest"] = module._digest_bytes(
            module._canonical(contract["environment_preimage"])
        )
        contract_digest = module._digest_bytes(module._canonical(contract))
        receipt_keys = {
            "M4_AUTHORITY": digest,
            "OBSERVER": digest,
            "PUBLISHER": digest,
        }
        admission = {
            "admission_version": "3.0.0" if one_use else "2.0.0",
            "mode": module.KEY_ADMISSION_MODE,
            "qualification_contract": contract,
            "qualification_contract_digest": contract_digest,
            "contract_core_digest": contract["contract_core_digest"],
            "ledger_entry_digest": digest,
            "receipt_public_key_digests": receipt_keys,
            "supply_public_key_digest": digest,
            "runtime_trust_digest": digest,
        }
        binding = {"composite_binding_digest": digest, "final_digest": digest}
        return {
            "record_version": "1.0.0",
            "phase": "PRE_RESTART_PASS",
            "identity": {
                "candidate": candidate,
                "environment": contract["environment_digest"],
                "attempt": 1,
                "qualification_contract": contract,
                "qualification_contract_digest": contract_digest,
                "boot_id": "12345678-1234-1234-1234-123456789abc",
                "guest": {},
                "source": source,
                "host_provenance": host_provenance,
                "package_runtime_plan": package_runtime_plan,
            },
            "trust": {
                "profile_digest": contract["contract_core"]["canonical_profile_digest"],
                "m4_apparmor_digest": digest,
                "m3_apparmor_digest": digest,
                "runtime_trust_digest": digest,
                "key_admission": admission,
                "receipt_public_key_digests": receipt_keys,
                "supply_public_key_digest": digest,
                "verifier": {
                    "backend": "OPENSSL_LIBCRYPTO_SHARED",
                    "code_digest": digest,
                    "libcrypto_path": "/usr/lib/x86_64-linux-gnu/libcrypto.so.3",
                    "libcrypto_digest": digest,
                    "independent_cryptographic_implementations": False,
                },
                "revocation_epoch": 0,
                "fencing_epoch": 1,
            },
            "durable": {
                "m4_recovery": {
                    "transaction_id": "transaction-1",
                    "state": "JOINED",
                    "contract_digest": digest,
                    "d2_frontier_digest": digest,
                    "fencing_epoch": 1,
                    "record_digest": digest,
                    "frontier_record_digest": digest,
                    "iteration": 1,
                    "frontier_attempt_cursor": 0,
                    "frontier_joined_iteration": 0,
                    "attempt_cursor": 1,
                    "joined_iteration": 1,
                    "journal_sequence": 20,
                    "intent_state": "SPENT",
                    "revocation_epoch": 0,
                    "resume_allowed": False,
                    "retry_allowed": False,
                },
                "m3_runtime_session": {
                    "session_record_id": "session-record-1",
                    "transaction_id": "transaction-1",
                    "claim_digest": digest,
                    "state": "STOPPED",
                    "fencing_epoch": 1,
                },
            },
            "publication": {
                "root": str(module.PUBLICATION_ROOT),
                "topology_digest": digest,
                "root_anchor": {"anchor_digest": digest},
                "target_binding": binding,
                "published_binding": binding,
                "artifact_digest": digest,
                "snapshot_digest": digest,
                "transport": module.SEALED_FD_ONLY,
            },
            "execution": {
                "controller_facts": {},
                "publisher_facts": {},
                "executor_facts": [{}],
                "observer_facts": [{}],
                "runtime_events": [],
                "denial_events": [{}, {}],
                "role_seccomp_digests": {},
                "m3_role_seccomp": {},
                "cleanup": {},
            },
        }

    def test_exact_profile_closes_roles_fds_keys_and_publication_topology(self) -> None:
        raw = json.loads(PROFILE.read_text(encoding="utf-8"))
        self.assertEqual(
            frozenset(raw),
            {
                "profile_version", "profile_id", "assurance_scope", "backend",
                "publication", "roles", "receipt_keys", "supply_trust", "limits",
            },
        )
        self.assertEqual((raw["profile_version"], raw["profile_id"]), ("1.0.0", "M4-LX-A"))
        self.assertEqual(raw["assurance_scope"], "DEPLOYMENT_ATTESTED")
        self.assertEqual(raw["backend"], {"path": "/usr/bin/bwrap", "version": "bubblewrap 0.9.0"})
        roles = raw["roles"]
        self.assertEqual(
            frozenset(roles),
            {"WORKER", "CONTROLLER", "EXECUTOR", "OBSERVER", "PUBLISHER"},
        )
        identities = [
            (
                role["uid"], role["gid"], role["session_id"], role["security_label"],
                role["cgroup"], role["credential_namespace"], role["namespace_id"],
            )
            for role in roles.values()
        ]
        for index in range(7):
            self.assertEqual(len({identity[index] for identity in identities}), 5)
        self.assertEqual(roles["OBSERVER"]["fd_allowlist"], [0, 1, 2])
        self.assertEqual(roles["PUBLISHER"]["fd_allowlist"], [0, 1, 2])
        self.assertEqual(roles["EXECUTOR"]["fd_allowlist"], [0, 1, 2])
        self.assertEqual(roles["WORKER"]["fd_allowlist"], [0, 1])
        self.assertEqual(roles["CONTROLLER"]["fd_allowlist"], [0, 1, 2, 3])
        publication = raw["publication"]
        self.assertEqual(
            publication,
            {
                "root": "/var/lib/harness-m4-publication/anchor/publication",
                "sandbox_root": "/var/lib/harness-m4-publication/anchor/publication",
                "target": "/staging/artifact.txt",
                "parent_owner": "ROOT_SUPERVISOR",
                "root_owner": "PUBLISHER",
                "parent_writable_roles": [],
                "root_writable_roles": ["PUBLISHER"],
                "git_authority": "DENY",
                "transport": "SEALED_FD_ONLY",
            },
        )
        self.assertEqual(frozenset(raw["receipt_keys"]), {"M4_AUTHORITY", "OBSERVER", "PUBLISHER"})
        self.assertEqual(
            {entry["private_owner"] for entry in raw["receipt_keys"].values()},
            {"CONTROLLER", "OBSERVER", "PUBLISHER"},
        )
        self.assertEqual(
            raw["supply_trust"],
            {
                "trust_root_id": "harness-m4-disposable-supply-root-1",
                "signer_id": "harness-m4-supply-attestor",
                "key_id": "harness-m4-supply-ed25519-1",
                "private_owner": "ROOT_SUPERVISOR",
                "algorithm": "ED25519",
                "admission": "HOST_ATTEMPT_LEDGER_PIN_BEFORE_WORKER_GATE",
            },
        )

    def test_repository_profile_is_exact_canonical_bytes(self) -> None:
        module = _module()
        raw = PROFILE.read_bytes()
        value = json.loads(raw)
        self.assertEqual(raw, module._canonical(value))
        self.assertEqual(len(raw), 2698)
        self.assertEqual(
            module._digest_bytes(raw),
            "sha256:50947b4b4ae139effbaddd749c7175a15755675f824e0ae1ed734a85694b4682",
        )
        self.assertFalse(raw.endswith(b"\n"))

    def test_guest_profile_accepts_only_exact_repository_bytes(self) -> None:
        module = _module()
        canonical = module._canonical(json.loads(PROFILE.read_bytes()))
        with tempfile.TemporaryDirectory(prefix="harness-m4-profile-") as directory:
            path = Path(directory) / "m4-lx-a.json"
            path.write_bytes(canonical)
            with mock.patch.object(module, "PROFILE_PATH", path):
                self.assertEqual(module._profile()["profile_id"], "M4-LX-A")
            for suffix in (b"\n", b" "):
                path.write_bytes(canonical + suffix)
                with self.subTest(suffix=suffix), mock.patch.object(
                    module, "PROFILE_PATH", path
                ), self.assertRaisesRegex(
                    module.QualificationStop, "NONCANONICAL_JSON"
                ):
                    module._profile()

    def test_inherited_l0_json_inputs_are_exact_canonical_and_digest_bound(
        self,
    ) -> None:
        module = _module()
        expected = {
            L0_PROFILE: (
                6210,
                "sha256:72ebbc0899870d304b29f0dfe24c6001f55fa1cf2efa84f1a08c41f47f9afcb5",
            ),
            L0_SECCOMP: (
                411,
                "sha256:e83c1507c68922fcc1686ec008560b92c4b53bb57867e8b5845b788c640ffb6a",
            ),
        }
        for path, (size, digest) in expected.items():
            raw = path.read_bytes()
            with self.subTest(path=path.name):
                self.assertEqual(raw, module._canonical(json.loads(raw)))
                self.assertFalse(raw.endswith(b"\n"))
                self.assertEqual(len(raw), size)
                self.assertEqual(module._digest_bytes(raw), digest)

        specification = importlib.util.spec_from_file_location(
            "harness_m3_vm_runner_digest_binding", M3_RUNNER
        )
        self.assertIsNotNone(specification)
        self.assertIsNotNone(specification.loader)
        m3 = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(m3)
        base_digest = module._digest_bytes(L0_SECCOMP.read_bytes())
        self.assertEqual(m3.BASE_SECCOMP_POLICY_DIGEST, base_digest)
        for path in (L0_BROKER_SECCOMP, L0_EXECUTOR_SECCOMP):
            with self.subTest(role=path.name):
                self.assertEqual(
                    json.loads(path.read_bytes())["base_profile_digest"],
                    base_digest,
                )

        draft = object()
        ready = object()
        compile_seccomp = mock.Mock(return_value=b"unreached")
        l0 = SimpleNamespace(
            L0Outcome=SimpleNamespace(COMPILED_DRAFT=draft, READY=ready),
            compile_profile=lambda value: SimpleNamespace(
                outcome=draft, profile=value
            ),
            host_preflight=lambda value: SimpleNamespace(
                outcome=ready, measurement=value
            ),
            _compile_seccomp_bpf=compile_seccomp,
        )
        supply = {
            "directory": "/tmp/attestor",
            "private_key": "/tmp/private.pem",
            "public_key": "/tmp/public.pem",
            "state": "/tmp/state.json",
            "public_key_digest": "sha256:" + "1" * 64,
            "trust_root_id": "test-root",
            "signer_id": "test-signer",
            "key_id": "test-key",
        }
        profile_raw = L0_PROFILE.read_bytes()
        seccomp_raw = L0_SECCOMP.read_bytes()
        with tempfile.TemporaryDirectory(prefix="harness-m4-l0-canonical-") as directory:
            root = Path(directory)
            profile_path = root / "l0-lx-a.json"
            profiles = root / "profiles"
            profiles.mkdir()
            seccomp_path = profiles / "l0-lx-a-seccomp.json"
            libcrypto = root / "libcrypto.so.3"
            libcrypto.write_bytes(b"test-only")
            for target in ("profile", "seccomp"):
                for suffix in (b"\n", b" "):
                    profile_path.write_bytes(
                        profile_raw + suffix if target == "profile" else profile_raw
                    )
                    seccomp_path.write_bytes(
                        seccomp_raw + suffix if target == "seccomp" else seccomp_raw
                    )
                    with (
                        self.subTest(target=target, suffix=suffix),
                        mock.patch.object(module, "L0_PROFILE", profile_path),
                        mock.patch.object(module, "SOURCE", root),
                        mock.patch.object(module, "LIBCRYPTO", str(libcrypto)),
                        mock.patch.object(
                            module,
                            "_load_project",
                            return_value=(None, l0, None, None, None),
                        ),
                        mock.patch.object(
                            module,
                            "_digest_file",
                            return_value="sha256:" + "2" * 64,
                        ),
                        self.assertRaisesRegex(
                            module.QualificationStop, "NONCANONICAL_JSON"
                        ),
                    ):
                        module._configure_m3_supply_trust(
                            SimpleNamespace(), supply
                        )
                    compile_seccomp.assert_not_called()
                    compile_seccomp.reset_mock()

    def test_apparmor_has_exact_observer_and_publisher_domains(self) -> None:
        policy = POLICY.read_text(encoding="utf-8")
        self.assertIn("profile harness-m4-lx-a.observer", policy)
        self.assertIn("profile harness-m4-lx-a.publisher", policy)
        publication = "/var/lib/harness-m4-publication/anchor/publication"
        self.assertIn(publication + "/** rwk,", policy)
        self.assertIn("audit deny " + publication + "/.git/** rwkl,", policy)
        observer = policy.split("profile harness-m4-lx-a.observer", 1)[1].split(
            "profile harness-m4-lx-a.publisher", 1
        )[0]
        self.assertNotIn(publication + "/** rwk,", observer)
        self.assertNotIn("\n  /** mr,", policy)
        for forbidden in ("ux,", "pux", "PUx", "attach_disconnected", "/run/harness/broker.sock"):
            self.assertNotIn(forbidden, policy)
        for required in (
            "/inputs/m4-role.json r,",
            "/etc/harness-m4/runtime-trust.json r,",
            "/opt/harness-m3-source/src/ r,",
            "/opt/harness-m3-source/src/harness_product/ r,",
            "/opt/harness-m3-source/src/harness_product/** r,",
            "/var/lib/harness-m4-keys/public/** r,",
            "audit deny mount,",
            "audit deny capability,",
            "audit deny change_profile,",
        ):
            self.assertGreaterEqual(policy.count(required), 2)
        publisher = policy.split("profile harness-m4-lx-a.publisher", 1)[1]
        for ancestor in (
            "/var/ r,",
            "/var/lib/ r,",
            "/var/lib/harness-m4-publication/ r,",
            "/var/lib/harness-m4-publication/anchor/ r,",
        ):
            self.assertIn(ancestor, publisher)
        self.assertIn("unix (getopt) type=seqpacket addr=none,", publisher)
        self.assertIn(
            "unix (receive) type=seqpacket addr=none peer=(addr=none,label=unconfined),",
            publisher,
        )
        for forbidden in (
            "unix (create", "unix (bind", "unix (listen", "unix (accept",
            "unix (connect", "network unix",
        ):
            self.assertNotIn(forbidden, publisher)
        for family in ("inet", "inet6", "netlink", "packet"):
            self.assertIn("audit deny network " + family + ",", publisher)

    def test_guest_runner_is_one_closed_runtime_boundary_without_pathname_broker_fallback(self) -> None:
        module = _module()
        self.assertEqual(module.M4_PROFILE, PROFILE)
        boundary = module.M4GuestRuntime
        for name in ("preflight", "stage", "observe", "publish", "continuity"):
            self.assertTrue(callable(getattr(boundary, name, None)))
        source = RUNNER.read_text(encoding="utf-8")
        for forbidden in (
            "/run/harness/broker.sock", "--broker-socket", "socket.bind(",
            "socket.listen(", "CODE_MODEL_FIXTURE", "verified=true", "shell=True",
        ):
            self.assertNotIn(forbidden, source)
        for required in (
            "StageExecutionGrant", "OpenSSLEd25519Verifier", "close_range",
            "SEALED_FD_ONLY", "F_GET_SEALS", "DEPLOYMENT_ATTESTED",
            "publisher_before_replace", "PRE_COMMIT", "PRE_JOIN",
            "key-admission.json", "KEY_ADMISSION_REQUIRED",
            "HOST_ATTEMPT_LEDGER_PIN_BEFORE_WORKER_GATE",
            "SOCK_SEQPACKET", "SCM_RIGHTS", "publisher_after_pre_replace_checks",
        ):
            self.assertIn(required, source)
        for name in ("_executor_role", "_observer_role", "_publisher_role"):
            self.assertTrue(callable(getattr(module, name, None)))
        self.assertNotIn("INTERNAL_ROLE_NOT_LAUNCHED", source)
        boundary_source = source.split("class M4GuestRuntime", 1)[1].split(
            "def _prepare_publication_root", 1
        )[0]
        self.assertIn("publisher_session", boundary_source)
        self.assertIn("controller.sign", boundary_source)
        self.assertIn("self.publisher_session.publish", boundary_source)
        self.assertIn("self.publisher_session.continuity", boundary_source)
        self.assertNotIn("publisher_key", boundary_source)
        self.assertNotIn("os.open(PUBLICATION_ROOT", boundary_source)

    def test_all_effect_roles_use_the_exact_bwrap_userns_and_seccomp_launcher(self) -> None:
        module = _module()
        self.assertTrue(callable(getattr(module, "_launch_m4_role", None)))
        self.assertTrue(callable(getattr(module, "_materialize_m4_role_rootfs", None)))
        self.assertEqual(
            module.M4_ROLE_SECCOMP_ADDITIONS,
            {
                "EXECUTOR": (18, 73, 77, 437),
                "OBSERVER": (18, 77),
                "PUBLISHER": (18, 47, 55, 263, 264, 437),
            },
        )
        source = RUNNER.read_text(encoding="utf-8")
        for required in (
            "--assert-userns-disabled", "--unshare-pid", "--unshare-ipc",
            "--unshare-uts", "--unshare-net", "--unshare-cgroup",
            "--block-fd", "--json-status-fd", "--seccomp",
            "_create_user_namespace", "_find_confined_process",
        ):
            self.assertIn(required, source)
        for forbidden in ("--disable-userns", "--unshare-user", "--ro-bind / /"):
            self.assertNotIn(forbidden, source)

    def test_nested_m4_role_entrypoints_require_namespace_identity(self) -> None:
        module = _module()

        class NextBoundary(BaseException):
            pass

        cases = (
            ("EXECUTOR", module._executor_role),
            ("OBSERVER", module._observer_role),
            ("PUBLISHER", module._publisher_role),
        )
        for role, entrypoint in cases:
            outer_uid, outer_gid, namespace_uid, namespace_gid = (
                module.M4_NAMESPACE_ROLE_IDS[role]
            )
            expected_label = module.ROLE_LABELS[role] + " (enforce)"
            self.assertEqual((outer_uid, outer_gid), module.ROLE_IDS[role])
            self.assertNotEqual((namespace_uid, namespace_gid), module.ROLE_IDS[role])

            with (
                self.subTest(role=role, identity="namespace"),
                mock.patch.object(module.os, "geteuid", return_value=namespace_uid),
                mock.patch.object(module.os, "getegid", return_value=namespace_gid),
                mock.patch.object(
                    module.Path,
                    "read_text",
                    return_value=expected_label,
                ),
                mock.patch.object(
                    module,
                    "_close_except",
                    side_effect=NextBoundary,
                ) as next_boundary,
                self.assertRaises(NextBoundary),
            ):
                entrypoint()
            next_boundary.assert_called_once_with(frozenset({0, 1, 2}))

            for uid, gid, label in (
                (outer_uid, outer_gid, expected_label),
                (namespace_uid, namespace_gid, module.ROLE_LABELS[role]),
            ):
                with (
                    self.subTest(role=role, uid=uid, gid=gid, label=label),
                    mock.patch.object(module.os, "geteuid", return_value=uid),
                    mock.patch.object(module.os, "getegid", return_value=gid),
                    mock.patch.object(module.Path, "read_text", return_value=label),
                    mock.patch.object(module, "_close_except") as next_boundary,
                    self.assertRaisesRegex(
                        module.QualificationStop,
                        rf"^{role}_PRINCIPAL_MISMATCH$",
                    ),
                ):
                    entrypoint()
                next_boundary.assert_not_called()

    def test_publisher_adopts_inherited_seqpacket_socket_with_explicit_type(
        self,
    ) -> None:
        module = _module()
        _, _, namespace_uid, namespace_gid = module.M4_NAMESPACE_ROLE_IDS[
            "PUBLISHER"
        ]
        expected_label = module.ROLE_LABELS["PUBLISHER"] + " (enforce)"

        class NextBoundary(BaseException):
            pass

        connection = object()
        with (
            mock.patch.object(module.os, "geteuid", return_value=namespace_uid),
            mock.patch.object(module.os, "getegid", return_value=namespace_gid),
            mock.patch.object(module.Path, "read_text", return_value=expected_label),
            mock.patch.object(module, "_close_except") as close_except,
            mock.patch.object(
                module.socket,
                "socket",
                return_value=connection,
            ) as adopt_socket,
            mock.patch.object(
                module,
                "_strict_file",
                side_effect=NextBoundary,
            ) as next_boundary,
            self.assertRaises(NextBoundary),
        ):
            module._publisher_role()

        close_except.assert_called_once_with(frozenset({0, 1, 2}))
        adopt_socket.assert_called_once_with(
            module.socket.AF_UNIX,
            module.socket.SOCK_SEQPACKET,
            0,
            fileno=0,
        )
        next_boundary.assert_called_once_with(
            module.ROLE_INPUT,
            frozenset({"input_version", "l0_profile", "m4_profile", "target"}),
        )

    def test_publisher_bootstrap_transfers_root_fd_after_valid_python_stdio(
        self,
    ) -> None:
        module = _module()
        parent, child = module._publisher_control_pair()
        root_descriptor = received_descriptor = -1

        class ReplyBoundary(Exception):
            pass

        try:
            with tempfile.TemporaryDirectory() as directory:
                root_descriptor = module.os.open(
                    directory,
                    module.os.O_RDONLY | module.os.O_DIRECTORY,
                )
                root_info = module.os.fstat(root_descriptor)
                probe = [
                    module.sys.executable,
                    "-I",
                    "-S",
                    "-B",
                    "-c",
                    "import os; os.write(1, b'ENTERED')",
                ]
                directory_stderr = module.subprocess.run(
                    probe,
                    stdout=module.subprocess.PIPE,
                    stderr=root_descriptor,
                    check=False,
                )
                self.assertNotEqual(directory_stderr.returncode, 0)
                self.assertEqual(directory_stderr.stdout, b"")
                stream_stderr = module.subprocess.run(
                    probe,
                    stdout=module.subprocess.PIPE,
                    stderr=module.subprocess.DEVNULL,
                    check=False,
                )
                self.assertEqual(stream_stderr.returncode, 0)
                self.assertEqual(stream_stderr.stdout, b"ENTERED")

                session = module.PublisherSession.__new__(module.PublisherSession)
                session.closed = False
                session.process = SimpleNamespace(poll=lambda: None)
                session.request_id = 0
                session.connection = parent
                with (
                    mock.patch.object(
                        session,
                        "_reply",
                        side_effect=ReplyBoundary,
                    ),
                    self.assertRaises(ReplyBoundary),
                ):
                    session.bootstrap(root_descriptor)
                request, descriptors = module._recv_control(child, 1)
                received_descriptor = descriptors[0]
                self.assertEqual(
                    request,
                    {
                        "protocol_version": 1,
                        "request_id": 1,
                        "operation": "BOOTSTRAP",
                        "payload": {},
                    },
                )
                received_info = module.os.fstat(received_descriptor)
                self.assertEqual(
                    (received_info.st_dev, received_info.st_ino),
                    (root_info.st_dev, root_info.st_ino),
                )
        finally:
            for descriptor in (root_descriptor, received_descriptor):
                if descriptor >= 0:
                    module.os.close(descriptor)
            parent.close()
            child.close()

        start_source = inspect.getsource(module._start_publisher_session)
        self.assertIn("stderr_descriptor=subprocess.DEVNULL", start_source)
        bootstrap_offset = start_source.index(
            "session.bootstrap(namespace_publication_descriptor)"
        )
        self.assertLess(
            start_source.index("_open_publication_root_in_namespace("),
            bootstrap_offset,
        )
        self.assertGreater(
            start_source.index(
                "os.close(publication_root_descriptor)",
                bootstrap_offset,
            ),
            bootstrap_offset,
        )
        publisher_source = inspect.getsource(module._publisher_role)
        self.assertIn(
            "publication_root_descriptor = _validate_publication_root_descriptor(",
            publisher_source,
        )
        self.assertIn("descriptors[0]", publisher_source)
        self.assertRegex(
            publisher_source,
            r"(?s)l0\.resolve_target\(\s*profile,\s*publication_root_descriptor,",
        )
        self.assertNotIn("l0.resolve_target(profile, 2", publisher_source)

    def test_publisher_ready_precedes_confined_fd_inventory_check(self) -> None:
        module = _module()
        read_descriptor, write_descriptor = module.os.pipe()
        try:
            module.os.write(
                write_descriptor,
                module._canonical(
                    {
                        "kind": "ROLE_READY",
                        "protocol_version": 1,
                        "role": "PUBLISHER",
                    }
                )
                + b"\n",
            )
            module._await_m4_role_ready(read_descriptor, "PUBLISHER")
        finally:
            module.os.close(read_descriptor)
            module.os.close(write_descriptor)

        read_descriptor, write_descriptor = module.os.pipe()
        try:
            module.os.write(
                write_descriptor,
                module._canonical(
                    {
                        "outcome": "STOP",
                        "reason": "PUBLISHER_PRINCIPAL_MISMATCH",
                        "status": "NOT_ATTESTED",
                    }
                )
                + b"\n",
            )
            with self.assertRaisesRegex(
                module.QualificationStop,
                r"^PUBLISHER_PRINCIPAL_MISMATCH$",
            ):
                module._await_m4_role_ready(read_descriptor, "PUBLISHER")
        finally:
            module.os.close(read_descriptor)
            module.os.close(write_descriptor)

        launcher_source = inspect.getsource(module._launch_m4_role)
        self.assertLess(
            launcher_source.index("_await_m4_role_ready"),
            launcher_source.index("m3._find_confined_process"),
        )
        self.assertIn(
            "startup_ready=True",
            inspect.getsource(module._start_publisher_session),
        )
        publisher_source = inspect.getsource(module._publisher_role)
        self.assertLess(
            publisher_source.index('"kind": "ROLE_READY"'),
            publisher_source.index("while True:"),
        )

    def test_publisher_startup_exception_reason_is_stage_closed_and_secret_free(
        self,
    ) -> None:
        module = _module()

        class PrivateFailure(Exception):
            pass

        cases = (
            (
                "CONTROL_ADOPTION",
                PermissionError(1, "/private/control.sock"),
                "PUBLISHER_STARTUP_CONTROL_ADOPTION_OSERROR",
            ),
            (
                "VERIFIER_LOAD",
                PrivateFailure("/private/verifier/key"),
                "PUBLISHER_STARTUP_VERIFIER_LOAD_EXCEPTION",
            ),
        )
        for stage, error, expected in cases:
            with self.subTest(stage=stage):
                reason = module._publisher_startup_exception_reason(stage, error)
                self.assertEqual(reason, expected)
                self.assertRegex(reason, module._STOP_REASON)
                self.assertNotIn("private", reason.lower())
        self.assertEqual(
            module._publisher_startup_exception_reason(
                "UNKNOWN",
                PrivateFailure("secret"),
            ),
            "M4_RUNTIME_FAILURE",
        )

    def test_publisher_bootstrap_exception_reason_is_stage_closed(self) -> None:
        module = _module()
        reason = module._publisher_bootstrap_exception_reason(
            "ROOT_MEASUREMENT",
            PermissionError(1, "/private/mount"),
        )
        self.assertEqual(reason, "PUBLISHER_BOOTSTRAP_ROOT_MEASUREMENT_OSERROR")
        self.assertRegex(reason, module._STOP_REASON)
        self.assertNotIn("private", reason.lower())
        self.assertEqual(
            module._publisher_bootstrap_exception_reason(
                "UNKNOWN",
                RuntimeError("secret"),
            ),
            "M4_RUNTIME_FAILURE",
        )

    def test_publisher_socket_adoption_requires_explicit_type_under_exact_seccomp(
        self,
    ) -> None:
        module = _module()
        module.M3_RUNNER = M3_RUNNER
        m3 = module._load_m3()
        raw = module._strict_bytes(L0_SECCOMP.read_bytes())
        self.assertIs(type(raw), dict)
        rows = tuple(
            sorted(
                (
                    *raw["syscalls"],
                    *module.M4_ROLE_SECCOMP_ADDITIONS["PUBLISHER"],
                )
            )
        )
        self.assertNotIn(51, rows)
        program = m3._compile_seccomp_rows(rows)

        child_code = f"""
import ctypes
import errno
import os
import socket
import sys

class SockFilter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_ushort),
        ("jt", ctypes.c_ubyte),
        ("jf", ctypes.c_ubyte),
        ("value", ctypes.c_uint),
    ]

class SockFprog(ctypes.Structure):
    _fields_ = [
        ("length", ctypes.c_ushort),
        ("filters", ctypes.POINTER(SockFilter)),
    ]

raw = bytes.fromhex({program.hex()!r})
filters = (SockFilter * (len(raw) // ctypes.sizeof(SockFilter))).from_buffer_copy(raw)
filter_program = SockFprog(len(filters), filters)
libc = ctypes.CDLL(None, use_errno=True)
libc.prctl.argtypes = [
    ctypes.c_int,
    ctypes.c_ulong,
    ctypes.c_void_p,
    ctypes.c_ulong,
    ctypes.c_ulong,
]
libc.prctl.restype = ctypes.c_int
if libc.prctl(38, 1, None, 0, 0) != 0:
    raise OSError(ctypes.get_errno(), "PR_SET_NO_NEW_PRIVS")
if libc.prctl(22, 2, ctypes.byref(filter_program), 0, 0) != 0:
    raise OSError(ctypes.get_errno(), "PR_SET_SECCOMP")

before = os.fstat(0)
if sys.argv[1] == "generic":
    try:
        socket.socket(fileno=0)
    except PermissionError as error:
        if error.errno == errno.EPERM:
            os.write(1, b"GENERIC_EPERM")
            os._exit(0)
    os._exit(10)

adopted = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET, 0, fileno=0)
after = os.fstat(adopted.fileno())
if (
    adopted.fileno() != 0
    or (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino)
    or adopted.family != socket.AF_UNIX
    or adopted.type != socket.SOCK_SEQPACKET
    or adopted.proto != 0
    or adopted.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
    != socket.SOCK_SEQPACKET
):
    os._exit(11)
os.write(1, ("EXPLICIT_OK:%d:%d" % (after.st_dev, after.st_ino)).encode("ascii"))
os._exit(0)
"""

        for mode in ("generic", "explicit"):
            peer, endpoint = module.socket.socketpair(
                module.socket.AF_UNIX,
                module.socket.SOCK_SEQPACKET,
            )
            with peer, endpoint, self.subTest(mode=mode):
                info = module.os.fstat(endpoint.fileno())
                completed = module.subprocess.run(
                    [
                        module.sys.executable,
                        "-I",
                        "-S",
                        "-B",
                        "-c",
                        child_code,
                        mode,
                    ],
                    stdin=endpoint,
                    stdout=module.subprocess.PIPE,
                    stderr=module.subprocess.PIPE,
                    check=False,
                    close_fds=True,
                    timeout=10,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(completed.stderr, b"")
                if mode == "generic":
                    self.assertEqual(completed.stdout, b"GENERIC_EPERM")
                else:
                    self.assertEqual(
                        completed.stdout,
                        (
                            "EXPLICIT_OK:%d:%d" % (info.st_dev, info.st_ino)
                        ).encode("ascii"),
                    )

    def test_nested_role_reports_keep_namespace_and_host_identity_coordinates_distinct(
        self,
    ) -> None:
        module = _module()
        durable, l0, m4, _, _ = module._load_project()
        digest = "sha256:" + "1" * 64
        host_pid = 91_001
        host_session = 91_002
        host_uid = 91_003
        host_gid = 91_004
        namespace_uid = 11_003
        namespace_gid = 12_003
        facts = {
            "process_session": host_session,
            "launcher_uid": host_uid,
            "launcher_gid": host_gid,
            "namespace_uid": namespace_uid,
            "namespace_gid": namespace_gid,
        }

        def launched_role() -> tuple[dict[str, object], mock.Mock]:
            process = mock.Mock(spec=module.subprocess.Popen)
            process.stdout = mock.Mock()
            process.stdout.fileno.return_value = 70
            return (
                {
                    "process": process,
                    "process_id": host_pid,
                    "facts": dict(facts),
                },
                process,
            )

        record_body = {
            "transaction_id": "transaction-1",
            "claim_digest": digest,
            "binding_digest": "sha256:" + "2" * 64,
            "before_digest": "sha256:" + "3" * 64,
            "after_digest": "sha256:" + "4" * 64,
            "bytes_written": 1,
        }
        record = {
            **record_body,
            "record_digest": l0._hash_text(l0._canonical(record_body)),
        }
        claim = object.__new__(durable.DispatchClaim)
        object.__setattr__(claim, "transaction_id", record["transaction_id"])
        object.__setattr__(claim, "claim_digest", record["claim_digest"])
        supply = object.__new__(l0.SupplyVerification)
        grant = object.__new__(durable.StageExecutionGrant)

        def invoke_executor(report: dict[str, object]) -> object:
            launched, _ = launched_role()
            with (
                mock.patch.object(module.os, "pipe2", return_value=(40, 41)),
                mock.patch.object(module.os, "write", return_value=len(module.START_PACKET)),
                mock.patch.object(module.os, "close"),
                mock.patch.object(module, "asdict", return_value={}),
                mock.patch.object(module, "_launch_m4_role", return_value=launched),
                mock.patch.object(module, "_read_line", return_value=b"report"),
                mock.patch.object(module, "_strict_bytes", return_value=report),
                mock.patch.object(module, "_finish_m4_role"),
                mock.patch.object(module, "_abort_m4_role"),
            ):
                return module._executor_launcher(
                    object(),
                    claim,
                    supply,
                    9,
                    {},
                    grant,
                    lambda: None,
                    lambda: None,
                    lambda: None,
                    m3=object(),
                    manager=object(),
                    raw_l0_profile={},
                    seccomp_program=b"seccomp",
                )

        executor_report = {
            "outcome": "STAGED",
            "reason": "STAGED",
            "record": record,
            "verifier_instances": 3,
            "independent_cryptographic_implementations": False,
        }
        execution = invoke_executor(executor_report)
        self.assertIs(type(execution), m4.RuntimeStageExecution)
        self.assertEqual((execution.process_id, execution.process_session), (host_pid, host_session))
        for field, value in (("pid", host_pid), ("session", host_session)):
            with (
                self.subTest(role="EXECUTOR", field=field),
                self.assertRaisesRegex(
                    module.QualificationStop,
                    r"^EXECUTOR_REPORT_MALFORMED$",
                ),
            ):
                invoke_executor({**executor_report, field: value})
        executor_source = inspect.getsource(module._executor_role)
        self.assertNotIn('"pid": os.getpid()', executor_source)
        self.assertNotIn('"session": os.getsid(0)', executor_source)

        seals = (
            module.fcntl.F_SEAL_GROW
            | module.fcntl.F_SEAL_SHRINK
            | module.fcntl.F_SEAL_WRITE
            | module.fcntl.F_SEAL_SEAL
        )
        snapshot = m4.M4Snapshot(
            "snapshot-1",
            21,
            22,
            23,
            "sha256:" + "5" * 64,
            (),
            True,
            True,
        )
        measurement = {
            "uid": namespace_uid,
            "gid": namespace_gid,
            "device": snapshot.device,
            "inode": snapshot.inode,
            "size": snapshot.size,
            "digest": snapshot.digest,
            "seals": seals,
            "read_only": True,
            "write_denied": True,
            "truncate_denied": True,
        }
        receipt = {"observed_at": "2026-09-02T00:00:00Z"}
        verification_source = {
            "verifier_id": "observer-verifier/v1",
            "issuer_id": "observer",
            "key_id": "observer-key",
            "proof": "proof",
        }

        def invoke_observer(observed: dict[str, object]) -> object:
            launched, _ = launched_role()
            report = {
                "kind": "OBSERVER_RECEIPT",
                "receipt": receipt,
                "verification_source": verification_source,
                "measurement": observed,
            }
            stat = SimpleNamespace(st_dev=21, st_ino=22, st_size=23)

            def fcntl_call(_descriptor: int, command: int, *_args: object) -> int:
                if command == module.fcntl.F_DUPFD_CLOEXEC:
                    return 42
                if command == module.fcntl.F_GET_SEALS:
                    return seals
                if command == module.fcntl.F_GETFL:
                    return module.os.O_RDONLY
                raise AssertionError(f"unexpected fcntl command: {command}")

            verified = SimpleNamespace(status=durable.VerificationStatus.VERIFIED)
            router = mock.Mock()
            router.verify.return_value = verified
            with (
                mock.patch.object(module.os, "pipe2", return_value=(40, 41)),
                mock.patch.object(module.os, "open", return_value=43),
                mock.patch.object(module.os, "fstat", return_value=stat),
                mock.patch.object(module.os, "write", return_value=len(module.START_PACKET)),
                mock.patch.object(module.os, "close"),
                mock.patch.object(module.fcntl, "fcntl", side_effect=fcntl_call),
                mock.patch.object(module, "asdict", return_value={}),
                mock.patch.object(module, "_launch_m4_role", return_value=launched),
                mock.patch.object(module, "_read_line", return_value=b"report"),
                mock.patch.object(module, "_strict_bytes", return_value=report),
                mock.patch.object(module, "ConfiguredVerifierRouter", return_value=router),
                mock.patch.object(module, "_finish_m4_role"),
                mock.patch.object(module, "_abort_m4_role"),
            ):
                return module._observer_launcher(
                    object(),
                    8,
                    snapshot,
                    {},
                    m3=object(),
                    manager=object(),
                    raw_l0_profile={},
                    m4_profile={},
                    seccomp_program=b"seccomp",
                )

        observation = invoke_observer(measurement)
        self.assertIs(type(observation), m4.RuntimeObserverReceipt)
        self.assertEqual(
            (
                observation.process_id,
                observation.process_session,
                observation.uid,
                observation.gid,
            ),
            (host_pid, host_session, host_uid, host_gid),
        )
        for field, value in (
            ("uid", host_uid),
            ("gid", host_gid),
            ("uid", float(namespace_uid)),
            ("gid", float(namespace_gid)),
        ):
            with (
                self.subTest(field=field, value=value),
                self.assertRaisesRegex(
                    module.QualificationStop,
                    r"^OBSERVER_REPORT_MISMATCH$",
                ),
            ):
                invoke_observer({**measurement, field: value})
        for field, value in (("pid", host_pid), ("session", host_session)):
            with (
                self.subTest(role="OBSERVER", field=field),
                self.assertRaisesRegex(
                    module.QualificationStop,
                    r"^OBSERVER_REPORT_MALFORMED$",
                ),
            ):
                invoke_observer({**measurement, field: value})
        observer_source = inspect.getsource(module._observer_role)
        self.assertNotIn('"pid": os.getpid()', observer_source)
        self.assertNotIn('"session": os.getsid(0)', observer_source)
        self.assertIn('"uid": os.geteuid()', observer_source)
        self.assertIn('"gid": os.getegid()', observer_source)

        publisher_source = inspect.getsource(module._start_publisher_session)
        self.assertIn('facts=launched["facts"]', publisher_source)
        self.assertNotIn('"measurement"', publisher_source)

    def test_role_launcher_rejects_unowned_stdio_channels_before_allocation(self) -> None:
        module = _module()
        cases = (
            {"stdin_descriptor": module.subprocess.PIPE, "stdout_descriptor": 1, "stderr_descriptor": 2},
            {"stdin_descriptor": 0, "stdout_descriptor": module.subprocess.DEVNULL, "stderr_descriptor": 2},
            {"stdin_descriptor": 0, "stdout_descriptor": 1, "stderr_descriptor": module.subprocess.PIPE},
        )
        for descriptors in cases:
            with self.subTest(descriptors=descriptors), self.assertRaises(module.QualificationStop):
                module._launch_m4_role(
                    m3=object(), manager=object(), role="EXECUTOR",
                    role_input={}, instance="stdio-negative",
                    seccomp_program=b"x", **descriptors,
                )

    def test_role_wrappers_preserve_grant_sealed_fd_and_publisher_session_boundaries(self) -> None:
        module = _module()
        executor = getattr(module, "_executor_launcher", None)
        observer = getattr(module, "_observer_launcher", None)
        publisher = getattr(module, "_start_publisher_session", None)
        for boundary in (executor, observer, publisher):
            self.assertTrue(callable(boundary))

        executor_source = inspect.getsource(executor)
        self.assertIn("stage_execution_grant", executor_source)
        self.assertIn("durable_store", inspect.getsource(module._executor_role))
        self.assertIn("durable_store=None", inspect.getsource(module._executor_role))
        self.assertNotIn("M4_DATABASE", executor_source)
        self.assertIn("START_PACKET", executor_source)

        observer_source = inspect.getsource(observer)
        self.assertIn("snapshot_descriptor", observer_source)
        self.assertIn("F_DUPFD_CLOEXEC", observer_source)
        self.assertIn("RuntimeObserverReceipt", observer_source)
        self.assertIn('measurement["seals"]', observer_source)
        self.assertNotIn("M4_DATABASE", observer_source)

        publisher_source = inspect.getsource(publisher)
        self.assertIn("_publisher_control_pair", publisher_source)
        self.assertIn("PublisherSession", publisher_source)
        self.assertIn("PUBLICATION_ROOT", publisher_source)
        self.assertIn("_publication_descriptor_identity", publisher_source)
        self.assertNotIn("TrustedPublisher", publisher_source)

        materializer_source = inspect.getsource(module._materialize_m4_role_rootfs)
        self.assertGreater(
            materializer_source.rfind("os.chmod(key_root, 0o500)"),
            materializer_source.find("for path in sorted(root.rglob"),
        )
        self.assertIn("finally:", inspect.getsource(module._finish_m4_role))

    def test_stage_record_reconstruction_rejects_bool_and_wrong_digest(self) -> None:
        module = _module()
        valid = {
            "transaction_id": "transaction-1",
            "claim_digest": "sha256:" + "1" * 64,
            "binding_digest": "sha256:" + "2" * 64,
            "before_digest": "sha256:" + "3" * 64,
            "after_digest": "sha256:" + "4" * 64,
            "bytes_written": 4,
        }
        l0 = module._load_project()[1]
        record = {
            **valid,
            "record_digest": l0._hash_text(l0._canonical(valid)),
        }
        self.assertEqual(module._stage_record_from_data(record).bytes_written, 4)
        for mutation in (
            {**record, "bytes_written": True},
            {**record, "after_digest": "sha256:" + "5" * 64},
        ):
            with self.assertRaises(module.QualificationStop):
                module._stage_record_from_data(mutation)

    def test_controller_recovery_decoder_rejects_json_type_aliases(self) -> None:
        module = _module()
        durable = module._load_project()[0]
        digest = "sha256:" + "a" * 64
        row = durable.M4Recovery(
            transaction_id="transaction-1",
            state="JOINED",
            contract_digest=digest,
            d2_frontier_digest=digest,
            fencing_epoch=1,
            record_digest=digest,
            frontier_record_digest=digest,
            iteration=1,
            frontier_attempt_cursor=0,
            frontier_joined_iteration=0,
            attempt_cursor=1,
            joined_iteration=1,
            journal_sequence=20,
            intent_state="SPENT",
            revocation_epoch=0,
            resume_allowed=False,
            retry_allowed=False,
        )
        encoded = module._durable_result_data(
            durable.DurableResult(
                durable.DurableOutcome.OK,
                durable.DurableReason.RECOVERED,
                m4_recovery=(row,),
            )
        )
        encoded = module._strict_bytes(module._canonical(encoded))
        self.assertEqual(module._durable_result_from_data(encoded).m4_recovery, (row,))
        for field, replacement in (
            ("fencing_epoch", True),
            ("iteration", 1.0),
            ("resume_allowed", 0),
            ("record_digest", False),
        ):
            mutation = deepcopy(encoded)
            mutation["m4_recovery"][0][field] = replacement
            with self.subTest(field=field), self.assertRaises(module.QualificationStop):
                module._durable_result_from_data(mutation)

    def test_final_evidence_is_materialized_only_after_private_key_cleanup(self) -> None:
        module = _module()
        bundle = {
            "evidence.json": b"{}",
            "manifest.json": b"{}",
            "manifest.sig": b"x" * 64,
        }
        order = []
        with mock.patch.object(
            module,
            "_remove_test_private_keys",
            side_effect=lambda: order.append("keys") or ["private.pem"],
        ), mock.patch.object(
            module,
            "_materialize_m4_evidence",
            side_effect=lambda value: order.append(("bundle", value)),
        ):
            self.assertEqual(module._finalize_m4_evidence(bundle), ["private.pem"])
        self.assertEqual(order, ["keys", ("bundle", bundle)])

        with mock.patch.object(
            module,
            "_remove_test_private_keys",
            side_effect=module.QualificationStop("cleanup failed"),
        ), mock.patch.object(module, "_materialize_m4_evidence") as materialize:
            with self.assertRaises(module.QualificationStop):
                module._finalize_m4_evidence(bundle)
            materialize.assert_not_called()
        with mock.patch.object(module.os, "lstat", side_effect=OSError("denied")):
            with self.assertRaises(module.QualificationStop):
                module._remove_test_private_keys()

    def test_publication_descriptor_identity_rejects_substitution(self) -> None:
        module = _module()
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory) / "anchor"
            root = parent / "publication"
            substitute = parent / "substitute"
            root.mkdir(parents=True)
            substitute.mkdir()
            original_parent = module.PUBLICATION_PARENT
            original_root = module.PUBLICATION_ROOT
            module.PUBLICATION_PARENT = parent
            module.PUBLICATION_ROOT = root
            parent_fd = root_fd = substitute_fd = -1
            try:
                parent_fd = module.os.open(parent, module.os.O_RDONLY | module.os.O_DIRECTORY)
                root_fd = module.os.open(root, module.os.O_RDONLY | module.os.O_DIRECTORY)
                substitute_fd = module.os.open(
                    substitute, module.os.O_RDONLY | module.os.O_DIRECTORY
                )
                measured = module._publication_descriptor_identity(parent_fd, root_fd)
                self.assertEqual(measured["basename"], "publication")
                with self.assertRaises(module.QualificationStop):
                    module._publication_descriptor_identity(parent_fd, substitute_fd)
            finally:
                for descriptor in (parent_fd, root_fd, substitute_fd):
                    if descriptor >= 0:
                        module.os.close(descriptor)
                module.PUBLICATION_PARENT = original_parent
                module.PUBLICATION_ROOT = original_root

    def test_controller_owns_the_complete_m3_to_m4_durable_sequence(self) -> None:
        module = _module()
        controller = module.ControllerSession
        for operation in (
            "bootstrap", "issue", "consume", "claim_dispatch",
            "prepare_runtime_session", "verify_dispatch_claim",
            "activate_m4_contract", "bind_current_m4_frontier",
            "begin_m4_transaction", "consume_m4_stage_authorization",
            "advance_m4", "recover",
        ):
            self.assertTrue(callable(getattr(controller, operation, None)), operation)
        child_source = inspect.getsource(module._controller_role)
        self.assertIn('"PREPARE": store.prepare_runtime_session', child_source)
        self.assertIn('"BIND_CURRENT_FRONTIER"', child_source)

    def test_remapped_code_fd_survives_exec_with_closed_inventory(self) -> None:
        module = _module()
        with tempfile.TemporaryDirectory(prefix="m4-code-fd-exec-") as directory:
            root = Path(directory)
            payload = root / "payload.py"
            payload.write_text(
                "import os\n"
                "open_fds = []\n"
                "for descriptor in range(32):\n"
                "    try:\n"
                "        os.fstat(descriptor)\n"
                "    except OSError:\n"
                "        continue\n"
                "    open_fds.append(descriptor)\n"
                "print(','.join(str(item) for item in open_fds), flush=True)\n",
                encoding="utf-8",
            )
            probe = root / "probe.py"
            probe.write_text(
                "import os\n"
                "import subprocess\n"
                "import sys\n"
                "target = os.open(os.devnull, os.O_RDONLY | os.O_CLOEXEC)\n"
                "if target != 3:\n"
                "    os.dup2(target, 3, inheritable=True)\n"
                "    os.close(target)\n"
                "else:\n"
                "    os.set_inheritable(3, True)\n"
                "source = os.open(sys.argv[2], os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)\n"
                "if source <= 3:\n"
                "    raise RuntimeError('source fd was not greater than target fd')\n"
                "def remap():\n"
                "    os.dup2(source, 3, inheritable=True)\n"
                "    os.close(source)\n"
                "pass_fds = (source,) if sys.argv[1] == 'old' else tuple(sorted({source, 3}))\n"
                "try:\n"
                "    completed = subprocess.run(\n"
                "        [sys.executable, '-I', '-S', '/proc/self/fd/3'],\n"
                "        close_fds=True,\n"
                "        pass_fds=pass_fds,\n"
                "        preexec_fn=remap,\n"
                "        check=False,\n"
                "    )\n"
                "finally:\n"
                "    os.close(source)\n"
                "    os.close(3)\n"
                "raise SystemExit(completed.returncode)\n",
                encoding="utf-8",
            )

            old = module.subprocess.run(
                [module.PYTHON, "-I", "-S", probe, "old", payload],
                stdout=module.subprocess.PIPE,
                stderr=module.subprocess.PIPE,
                check=False,
                timeout=10,
            )
            self.assertNotEqual(old.returncode, 0)
            self.assertEqual(old.stdout, b"")
            self.assertIn(b"/proc/self/fd/3", old.stderr)

            fixed = module.subprocess.run(
                [module.PYTHON, "-I", "-S", probe, "fixed", payload],
                stdout=module.subprocess.PIPE,
                stderr=module.subprocess.PIPE,
                check=False,
                timeout=10,
            )
            self.assertEqual(fixed.returncode, 0, fixed.stderr.decode("utf-8", "replace"))
            self.assertEqual(fixed.stdout, b"0,1,2,3\n")
            self.assertEqual(fixed.stderr, b"")

        self.assertEqual(tuple(sorted({3, 3})), (3,))
        for call_site in (
            inspect.getsource(module.ControllerSession.__init__),
            inspect.getsource(module._publication_denial_probe),
        ):
            self.assertIn("pass_fds=tuple(sorted({code, 3})),", call_site)
            self.assertNotIn("pass_fds=(code,),", call_site)
            self.assertIn("((code, 3),)", call_site)

    def test_publisher_reply_preserves_closed_child_stop(self) -> None:
        module = _module()
        read_descriptor, write_descriptor = module.os.pipe()
        try:
            raw = module._canonical(
                {
                    "outcome": "STOP",
                    "reason": "PUBLISHER_TARGET_UNRESOLVED",
                    "status": "NOT_ATTESTED",
                }
            )
            module.os.write(write_descriptor, raw + b"\n")
            session = module.PublisherSession.__new__(module.PublisherSession)
            session.process = SimpleNamespace(
                stdout=SimpleNamespace(fileno=lambda: read_descriptor)
            )
            with self.assertRaisesRegex(
                module.QualificationStop,
                "^PUBLISHER_TARGET_UNRESOLVED$",
            ):
                session._reply(1, "BOOTSTRAP")
        finally:
            module.os.close(read_descriptor)
            module.os.close(write_descriptor)

    def test_publisher_accepts_namespace_bound_root_without_path_reopen(self) -> None:
        module = _module()
        with tempfile.TemporaryDirectory(prefix="m4-publisher-root-adopt-") as directory:
            root = Path(directory) / "publication"
            substitute = Path(directory) / "substitute"
            root.mkdir()
            substitute.mkdir()
            original_root = module.PUBLICATION_ROOT
            authority_descriptor = -1
            local_descriptor = -1
            substitute_descriptor = -1
            try:
                module.PUBLICATION_ROOT = root
                authority_descriptor = module.os.open(
                    root,
                    module.os.O_RDONLY | module.os.O_DIRECTORY | module.os.O_CLOEXEC,
                )
                authority_info = module.os.fstat(authority_descriptor)
                with mock.patch.object(
                    module.os,
                    "open",
                    side_effect=AssertionError("confined publisher reopened a path"),
                ):
                    self.assertEqual(
                        module._validate_publication_root_descriptor(
                            authority_descriptor
                        ),
                        authority_descriptor,
                    )
                local_descriptor = module._open_publication_root_in_namespace(
                    module.os.getpid(),
                    authority_descriptor,
                )
                local_info = module.os.fstat(local_descriptor)
                self.assertEqual(
                    (local_info.st_dev, local_info.st_ino),
                    (authority_info.st_dev, authority_info.st_ino),
                )
                module.fcntl.fcntl(authority_descriptor, module.fcntl.F_GETFD)

                substitute_descriptor = module.os.open(
                    substitute,
                    module.os.O_RDONLY | module.os.O_DIRECTORY | module.os.O_CLOEXEC,
                )
                with self.assertRaisesRegex(
                    module.QualificationStop,
                    "^PUBLICATION_DESCRIPTOR_MISMATCH$",
                ):
                    module._open_publication_root_in_namespace(
                        module.os.getpid(),
                        substitute_descriptor,
                    )
            finally:
                module.PUBLICATION_ROOT = original_root
                for descriptor in (
                    authority_descriptor,
                    local_descriptor,
                    substitute_descriptor,
                ):
                    if descriptor >= 0:
                        module.os.close(descriptor)

    def test_run_phase_enters_one_actual_m3_to_m4_join_chain(self) -> None:
        module = _module()
        source = inspect.getsource(module._run_phase)
        self.assertNotIn("M4_RUNTIME_CHAIN_NOT_ENTERED", source)
        for required in (
            "ControllerSession(", "_start_publisher_session(",
            "_authority_chain(", "bind_current_m4_frontier(",
            "M4GuestRuntime(", "M4Coordinator(", ".execute(",
            "publisher_session.install(",
        ):
            self.assertIn(required, source)

    def test_service_exposes_only_exact_run_and_recover_phases(self) -> None:
        unit = SERVICE.read_text(encoding="utf-8")
        self.assertIn("ConditionVirtualization=vm", unit)
        self.assertIn("Delegate=yes", unit)
        self.assertIn("run_m4_vm_conformance.py --phase %i", unit)
        self.assertIn("User=root", unit)
        self.assertNotIn("Restart=always", unit)
        module = _module()
        self.assertEqual(module.ALLOWED_PHASES, ("run", "recover"))

    def test_pre_key_diagnostic_markers_are_closed_ordered_and_non_authorizing(self) -> None:
        module = _module()
        expected = (
            "SERVICE_ENTERED",
            "REQUEST_VALIDATED",
            "PRE_KEY_CHECKS_COMPLETE",
            "KEY_GENERATION_STARTED",
            "KEY_GENERATION_COMPLETE",
            "RUNTIME_TRUST_READY",
            "KEY_READY_WRITTEN",
        )
        self.assertEqual(module.PRE_KEY_STAGES, expected)
        with mock.patch.object(module.os, "write", side_effect=lambda _fd, raw: len(raw)) as write:
            module._diagnostic_stage("KEY_GENERATION_STARTED")
        raw = write.call_args.args[1]
        self.assertEqual(
            json.loads(raw),
            {
                "non_authorizing": True,
                "record_type": "M4_PRE_KEY_STAGE",
                "stage": "KEY_GENERATION_STARTED",
            },
        )
        with self.assertRaises(module.QualificationStop):
            module._diagnostic_stage("KEY_ADMITTED")

        source = inspect.getsource(module._run_phase) + inspect.getsource(module._await_key_admission)
        positions = [source.index(f'_diagnostic_stage("{stage}")') for stage in expected]
        self.assertEqual(positions, sorted(positions))
        self.assertNotIn('_diagnostic_stage("KEY_ADMITTED")', source)

    def test_ubuntu_source_boundaries_distinguish_before_and_during_apt(
        self,
    ) -> None:
        module = _module()
        expected = (
            "sha256:eafe8bd9490d039ddaa42d1ca6e2682b0a4e68fe13845aa47d8c195292574d55"
        )
        different = "sha256:" + "0" * 64
        generic = "sha256:" + "a" * 64
        before = "BEFORE_APT_GET_UPDATE"
        after = "AFTER_EXACT_PACKAGE_INSTALL_AND_CLEAN"
        self.assertEqual(module.PACKAGE_SOURCE_UBUNTU_DIGEST, expected)
        self.assertEqual(
            module.PACKAGE_SOURCE_BOUNDARIES,
            (before, after),
        )
        self.assertEqual(
            module.PACKAGE_SOURCE_BOUNDARY_OUTCOMES,
            frozenset({"MATCH", "MISMATCH", "READ_ERROR"}),
        )

        def observation(
            boundary: str,
            outcome: str,
            observed: str | None,
            *,
            binding_id: str = "PACKAGE_SOURCE_UBUNTU",
            expected_sha256: str = expected,
        ) -> dict[str, object]:
            return {
                "binding_id": binding_id,
                "boundary": boundary,
                "expected_sha256": expected_sha256,
                "non_authorizing": True,
                "observed_sha256": observed,
                "outcome": outcome,
                "record_type": "M4_PACKAGE_SOURCE_BOUNDARY_OBSERVATION",
            }

        exact_rows = (
            observation(before, "MATCH", expected),
            observation(after, "MATCH", expected),
        )
        plan = {
            "plan_version": "1.0.0",
            "packages": dict(module.PACKAGE_VERSIONS),
            "provisioning_script_digest": generic,
            "package_sources": {
                path: (
                    expected
                    if path == module.PACKAGE_SOURCE_UBUNTU_PATH
                    else generic
                )
                for path in module.PACKAGE_SOURCE_PATHS
            },
            "runtime_configs": {
                path: generic for path in module.RUNTIME_CONFIG_PATHS
            },
            "runtime_tools": {
                path: generic for path in module.RUNTIME_TOOL_PATHS
            },
        }

        with tempfile.TemporaryDirectory(
            prefix="m4-ubuntu-source-boundaries-"
        ) as directory:
            boundary_path = Path(directory) / "package-source-boundaries.jsonl"

            def invoke(
                raw: bytes,
                *,
                diagnostic_observation: bool = True,
                final_source_digest: str = expected,
            ) -> tuple[
                dict[str, object] | None,
                str | None,
                list[dict[str, object]],
                mock.Mock,
            ]:
                boundary_path.write_bytes(raw)
                writes: list[dict[str, object]] = []
                dpkg = mock.Mock(
                    side_effect=lambda argv, **_kwargs: (
                        module.subprocess.CompletedProcess(
                            argv,
                            0,
                            stdout=module.PACKAGE_VERSIONS[argv[-1]].encode(
                                "ascii"
                            ),
                            stderr=b"",
                        )
                    )
                )

                def digest_file(path, _maximum=64 << 20):
                    if path == module.PROVISIONING_SCRIPT:
                        return generic
                    if str(path) == module.PACKAGE_SOURCE_UBUNTU_PATH:
                        return final_source_digest
                    return generic

                def capture(_descriptor, raw_record):
                    writes.append(
                        module._strict_bytes(raw_record.removesuffix(b"\n"), 1024)
                    )
                    return len(raw_record)

                result = None
                reason = None
                with (
                    mock.patch.object(
                        module,
                        "PACKAGE_SOURCE_BOUNDARY_OBSERVATIONS",
                        boundary_path,
                    ),
                    mock.patch.object(module, "_strict_file", return_value=plan),
                    mock.patch.object(
                        module, "_digest_file", side_effect=digest_file
                    ),
                    mock.patch.object(module.subprocess, "run", dpkg),
                    mock.patch.object(
                        module.Path,
                        "resolve",
                        new=lambda path, strict=False: path,
                    ),
                    mock.patch.object(module.os, "write", side_effect=capture),
                ):
                    try:
                        result = module._package_runtime_plan(
                            diagnostic_observation=diagnostic_observation
                        )
                    except module.QualificationStop as error:
                        reason = str(error)
                return result, reason, writes, dpkg

            def jsonl(*rows: dict[str, object]) -> bytes:
                return b"".join(module._canonical(row) + b"\n" for row in rows)

            result, reason, writes, dpkg = invoke(
                jsonl(observation(before, "MISMATCH", different))
            )
            self.assertIsNone(result)
            self.assertEqual(reason, "PACKAGE_RUNTIME_PLAN_BINDING_MISMATCH")
            self.assertEqual(
                writes, [observation(before, "MISMATCH", different)]
            )
            dpkg.assert_not_called()

            result, reason, writes, dpkg = invoke(
                jsonl(
                    observation(before, "MATCH", expected),
                    observation(after, "MISMATCH", different),
                )
            )
            self.assertIsNone(result)
            self.assertEqual(reason, "PACKAGE_RUNTIME_PLAN_BINDING_MISMATCH")
            self.assertEqual(
                writes,
                [
                    observation(before, "MATCH", expected),
                    observation(after, "MISMATCH", different),
                ],
            )
            dpkg.assert_not_called()

            result, reason, writes, dpkg = invoke(jsonl(*exact_rows))
            self.assertEqual(result, plan)
            self.assertIsNone(reason)
            self.assertEqual(writes, list(exact_rows))
            self.assertEqual(dpkg.call_count, len(module.PACKAGE_VERSIONS))

            malformed = {**exact_rows[0], "unknown": True}
            for name, raw in (
                ("malformed", jsonl(malformed)),
                ("duplicate", jsonl(exact_rows[0], exact_rows[0])),
                (
                    "unknown-binding",
                    jsonl(
                        observation(
                            before,
                            "MATCH",
                            expected,
                            binding_id="PACKAGE_SOURCE_UNKNOWN",
                        )
                    ),
                ),
                (
                    "unknown-boundary",
                    jsonl(observation("DURING_APT", "MATCH", expected)),
                ),
                (
                    "nonstring-boundary",
                    jsonl({**exact_rows[0], "boundary": []}),
                ),
                (
                    "unknown-outcome",
                    jsonl(observation(before, "UNKNOWN", expected)),
                ),
                (
                    "nonstring-outcome",
                    jsonl({**exact_rows[0], "outcome": []}),
                ),
                (
                    "wrong-expected",
                    jsonl(
                        observation(
                            before,
                            "MATCH",
                            different,
                            expected_sha256=different,
                        )
                    ),
                ),
                (
                    "match-observed-mismatch",
                    jsonl(observation(before, "MATCH", different)),
                ),
                (
                    "mismatch-observed-match",
                    jsonl(observation(before, "MISMATCH", expected)),
                ),
                (
                    "read-error-observed-digest",
                    jsonl(observation(before, "READ_ERROR", different)),
                ),
            ):
                with self.subTest(name=name):
                    result, reason, writes, dpkg = invoke(raw)
                    self.assertIsNone(result)
                    self.assertEqual(
                        reason,
                        "PACKAGE_SOURCE_BOUNDARY_OBSERVATION_MALFORMED",
                    )
                    self.assertEqual(writes, [])
                    dpkg.assert_not_called()

            for name, rows in (
                (
                    "wrong-before",
                    (observation(before, "MISMATCH", different),),
                ),
                (
                    "changed-during-apt",
                    (
                        observation(before, "MATCH", expected),
                        observation(after, "MISMATCH", different),
                    ),
                ),
            ):
                with self.subTest(ordinary_non_authorizing=name):
                    result, reason, writes, dpkg = invoke(
                        jsonl(*rows), diagnostic_observation=False
                    )
                    self.assertIsNone(result)
                    self.assertEqual(
                        reason, "PACKAGE_RUNTIME_PLAN_BINDING_MISMATCH"
                    )
                    self.assertEqual(writes, [])
                    dpkg.assert_not_called()

            result, reason, writes, dpkg = invoke(
                jsonl(*exact_rows),
                diagnostic_observation=False,
                final_source_digest=different,
            )
            self.assertIsNone(result)
            self.assertEqual(reason, "PACKAGE_RUNTIME_PLAN_BINDING_MISMATCH")
            self.assertEqual(writes, [])
            self.assertEqual(dpkg.call_count, len(module.PACKAGE_VERSIONS))

    def test_post_v2_package_runtime_plan_observation_discriminates_all_bindings(
        self,
    ) -> None:
        module = _module()
        package_ids = {
            "apparmor": "PACKAGE_VERSION_APPARMOR",
            "apparmor-utils": "PACKAGE_VERSION_APPARMOR_UTILS",
            "bubblewrap": "PACKAGE_VERSION_BUBBLEWRAP",
            "libssl3t64": "PACKAGE_VERSION_LIBSSL3T64",
            "openssl": "PACKAGE_VERSION_OPENSSL",
            "python3.12": "PACKAGE_VERSION_PYTHON3_12",
        }
        file_ids = {
            "/etc/apt/apt.conf.d/99-harness-m4": (
                "PACKAGE_SOURCE_APT_HARNESS_M4"
            ),
            "/etc/apt/sources.list.d/ubuntu.sources": "PACKAGE_SOURCE_UBUNTU",
            "/etc/hosts": "RUNTIME_CONFIG_HOSTS",
            "/etc/harness-m4/nftables-offline.conf": (
                "RUNTIME_CONFIG_NFTABLES_OFFLINE"
            ),
            "/etc/harness-m4/nftables-provisioning.conf": (
                "RUNTIME_CONFIG_NFTABLES_PROVISIONING"
            ),
            "/usr/bin/aa-exec": "RUNTIME_TOOL_AA_EXEC",
            "/usr/bin/bwrap": "RUNTIME_TOOL_BWRAP",
            "/usr/bin/openssl": "RUNTIME_TOOL_OPENSSL",
            "/usr/bin/python3.12": "RUNTIME_TOOL_PYTHON3_12",
            "/usr/lib/x86_64-linux-gnu/libcrypto.so.3": (
                "RUNTIME_TOOL_LIBCRYPTO"
            ),
            "/usr/sbin/apparmor_parser": "RUNTIME_TOOL_APPARMOR_PARSER",
        }
        expected_ids = (
            "PROVISIONING_SCRIPT",
            *package_ids.values(),
            *file_ids.values(),
        )
        self.assertEqual(module.PACKAGE_RUNTIME_PLAN_BINDING_IDS, expected_ids)
        self.assertEqual(len(expected_ids), 18)
        self.assertEqual(len(frozenset(expected_ids)), 18)
        self.assertEqual(
            module.PACKAGE_RUNTIME_PLAN_OUTCOMES,
            frozenset(
                {
                    "MISMATCH",
                    "QUERY_ERROR",
                    "DECODE_ERROR",
                    "READ_ERROR",
                    "RESOLVE_ERROR",
                }
            ),
        )

        digest = "sha256:" + "a" * 64
        other_digest = "sha256:" + "b" * 64
        plan = {
            "plan_version": "1.0.0",
            "packages": dict(module.PACKAGE_VERSIONS),
            "provisioning_script_digest": digest,
            "package_sources": {
                path: (
                    module.PACKAGE_SOURCE_UBUNTU_DIGEST
                    if path == module.PACKAGE_SOURCE_UBUNTU_PATH
                    else digest
                )
                for path in module.PACKAGE_SOURCE_PATHS
            },
            "runtime_configs": {
                path: digest for path in module.RUNTIME_CONFIG_PATHS
            },
            "runtime_tools": {
                path: digest for path in module.RUNTIME_TOOL_PATHS
            },
        }
        package_by_id = {binding_id: name for name, binding_id in package_ids.items()}
        path_by_id = {binding_id: name for name, binding_id in file_ids.items()}

        def invoke(
            binding_id: str,
            failure: str,
            *,
            diagnostic_observation: bool = True,
        ) -> list[tuple[bytes, dict[str, object]]]:
            writes: list[bytes] = []

            def dpkg(argv, **_kwargs):
                name = argv[-1]
                current = package_ids[name]
                if current == binding_id and failure == "query":
                    raise module.subprocess.TimeoutExpired(argv, 5)
                if current == binding_id and failure == "nonzero":
                    return module.subprocess.CompletedProcess(
                        argv, 1, stdout=b"", stderr=b"not retained"
                    )
                if current == binding_id and failure == "decode":
                    return module.subprocess.CompletedProcess(
                        argv, 0, stdout=b"\xff", stderr=b""
                    )
                installed = (
                    "0" if current == binding_id and failure == "mismatch"
                    else module.PACKAGE_VERSIONS[name]
                )
                return module.subprocess.CompletedProcess(
                    argv, 0, stdout=installed.encode("ascii"), stderr=b""
                )

            def digest_file(path, _maximum=64 << 20):
                text = str(path)
                current = (
                    "PROVISIONING_SCRIPT"
                    if path == module.PROVISIONING_SCRIPT
                    else file_ids[text]
                )
                if current == binding_id and failure == "read":
                    raise OSError("synthetic read error")
                if current == binding_id and failure == "mismatch":
                    return other_digest
                if path == module.PROVISIONING_SCRIPT:
                    return plan["provisioning_script_digest"]
                return {
                    **plan["package_sources"],
                    **plan["runtime_configs"],
                    **plan["runtime_tools"],
                }[text]

            def resolve(path, strict=False):
                del strict
                if (
                    file_ids.get(str(path)) == binding_id
                    and failure == "resolve"
                ):
                    raise OSError("synthetic resolve error")
                return path

            with (
                mock.patch.object(module, "_strict_file", return_value=plan),
                mock.patch.object(
                    module, "_package_source_boundary_observations"
                ),
                mock.patch.object(module, "_digest_file", side_effect=digest_file),
                mock.patch.object(module.subprocess, "run", side_effect=dpkg),
                mock.patch.object(module.Path, "resolve", new=resolve),
                mock.patch.object(
                    module.os,
                    "write",
                    side_effect=lambda _fd, raw: writes.append(raw) or len(raw),
                ),
                self.assertRaisesRegex(
                    module.QualificationStop,
                    "^PACKAGE_RUNTIME_PLAN_BINDING_MISMATCH$",
                ),
            ):
                module._package_runtime_plan(
                    diagnostic_observation=diagnostic_observation
                )
            return [
                (
                    raw,
                    module._strict_bytes(raw.removesuffix(b"\n"), 1024),
                )
                for raw in writes
            ]

        for binding_id in expected_ids:
            with self.subTest(binding_id=binding_id):
                observed = invoke(binding_id, "mismatch")
                self.assertEqual(len(observed), 1)
                raw, record = observed[0]
                self.assertEqual(
                    record,
                    {
                        "binding_id": binding_id,
                        "non_authorizing": True,
                        "outcome": "MISMATCH",
                        "record_type": "M4_PACKAGE_RUNTIME_PLAN_OBSERVATION",
                    },
                )
                self.assertEqual(raw, module._canonical(record) + b"\n")

        for binding_id, failure, outcome in (
            (package_ids["apparmor"], "query", "QUERY_ERROR"),
            (package_ids["apparmor"], "nonzero", "QUERY_ERROR"),
            (package_ids["apparmor"], "decode", "DECODE_ERROR"),
            (file_ids["/etc/hosts"], "read", "READ_ERROR"),
            (file_ids[module.LIBCRYPTO], "resolve", "RESOLVE_ERROR"),
        ):
            with self.subTest(outcome=outcome):
                observed = invoke(binding_id, failure)
                self.assertEqual(len(observed), 1)
                self.assertEqual(observed[0][1]["binding_id"], binding_id)
                self.assertEqual(observed[0][1]["outcome"], outcome)

        self.assertEqual(
            invoke(
                "PROVISIONING_SCRIPT",
                "mismatch",
                diagnostic_observation=False,
            ),
            [],
        )
        for binding_id, outcome in (
            ("UNKNOWN_BINDING", "MISMATCH"),
            ("PROVISIONING_SCRIPT", "UNKNOWN_OUTCOME"),
        ):
            with (
                self.subTest(binding_id=binding_id, outcome=outcome),
                mock.patch.object(module.os, "write") as write,
                self.assertRaises(module.QualificationStop),
            ):
                module._emit_package_runtime_plan_observation(binding_id, outcome)
            write.assert_not_called()

        def successful_dpkg(argv, **_kwargs):
            return module.subprocess.CompletedProcess(
                argv,
                0,
                stdout=module.PACKAGE_VERSIONS[argv[-1]].encode("ascii"),
                stderr=b"",
            )

        with (
            mock.patch.object(module, "_strict_file", return_value=plan),
            mock.patch.object(module, "_package_source_boundary_observations"),
            mock.patch.object(
                module,
                "_digest_file",
                side_effect=OSError("ordinary read failure"),
            ),
            mock.patch.object(module.subprocess, "run", side_effect=successful_dpkg),
            mock.patch.object(module.os, "write") as write,
            self.assertRaisesRegex(OSError, "ordinary read failure"),
        ):
            module._package_runtime_plan(diagnostic_observation=False)
        write.assert_not_called()

        def resolve_failure(_path, strict=False):
            del strict
            raise OSError("ordinary resolve failure")

        def exact_digest_file(path, _maximum=64 << 20):
            if path == module.PROVISIONING_SCRIPT:
                return plan["provisioning_script_digest"]
            return {
                **plan["package_sources"],
                **plan["runtime_configs"],
                **plan["runtime_tools"],
            }[str(path)]

        with (
            mock.patch.object(module, "_strict_file", return_value=plan),
            mock.patch.object(module, "_package_source_boundary_observations"),
            mock.patch.object(
                module, "_digest_file", side_effect=exact_digest_file
            ),
            mock.patch.object(module.subprocess, "run", side_effect=successful_dpkg),
            mock.patch.object(module.Path, "resolve", new=resolve_failure),
            mock.patch.object(module.os, "write") as write,
            self.assertRaisesRegex(OSError, "ordinary resolve failure"),
        ):
            module._package_runtime_plan(diagnostic_observation=False)
        write.assert_not_called()

        for name, effect in (
            ("short-write", 0),
            ("write-error", OSError("synthetic write error")),
        ):
            patcher = (
                mock.patch.object(module.os, "write", return_value=effect)
                if type(effect) is int
                else mock.patch.object(module.os, "write", side_effect=effect)
            )
            with (
                self.subTest(name=name),
                patcher,
                self.assertRaisesRegex(
                    module.QualificationStop,
                    "^M4_PACKAGE_RUNTIME_PLAN_OBSERVATION_WRITE_FAILED$",
                ),
            ):
                module._emit_package_runtime_plan_observation(
                    "PROVISIONING_SCRIPT", "READ_ERROR"
                )

        self.assertIn(
            "diagnostic_observation=True",
            inspect.getsource(module._verify_post_v2_diagnostic_environment),
        )
        self.assertNotIn(
            "diagnostic_observation=True",
            inspect.getsource(module._verify_qualification_environment),
        )

    def test_launch_request_accepts_only_closed_single_attempt_diagnostic_shape(self) -> None:
        module = _module()
        digest = "sha256:" + "a" * 64
        request = {
            "request_version": "1.1.0",
            "mode": "KEY_READY_DIAGNOSTIC",
            "candidate": "b" * 40,
            "tree": "c" * 40,
            "environment": digest,
            "attempt": 1,
            "user_goal_digest": digest,
            "predecessor_qualification_ledger_digest": digest,
        }
        self.assertEqual(module._validate_launch_request(request), "KEY_READY_DIAGNOSTIC")
        for mutation in (
            {**request, "attempt": 2},
            {**request, "mode": "QUALIFICATION"},
            {**request, "unknown": True},
            {**request, "user_goal_digest": "sha256:" + "d" * 63},
        ):
            with self.subTest(mutation=mutation), self.assertRaises(module.QualificationStop):
                module._validate_launch_request(mutation)

    def test_post_v2_diagnostic_request_is_closed_failed_ledger_bound_and_single_use(
        self,
    ) -> None:
        module = _module()
        request = self._post_v2_diagnostic_request(module)
        self.assertEqual(
            module._validate_launch_request(request),
            "POST_V2_PRE_ADMISSION_DIAGNOSTIC",
        )
        contract = request["diagnostic_contract"]
        core = contract["contract_core"]
        goal = core["goal_record"]
        self.assertEqual(core["max_attempts"], 1)
        self.assertIs(core["non_authorizing"], True)
        self.assertEqual(
            core["failed_qualification_v2_ledger_digest"],
            "sha256:c80f4eb33b811b59a4f80aee5fdf781964b441d20e1620ca4b1f2b63f30c479a",
        )
        self.assertEqual(goal["allowed_outcome"], "SANITIZED_DIAGNOSTIC_ONLY")
        self.assertEqual(len(module._canonical(goal)), 582)
        self.assertEqual(
            module._digest_bytes(module._canonical(goal)),
            "sha256:7e171d5a592859fc7a49e91ec1dca61d11ec326bbe1083ee5511f70163b9bc70",
        )
        self.assertEqual(
            goal["forbidden_operations"],
            [
                "AUTOMATIC_RETRY",
                "KEY_ADMISSION_ARTIFACT",
                "QUALIFICATION_EVIDENCE_EXPORT",
                "QUALIFICATION_V2_LEDGER_WRITE",
                "REBOOT_OR_RECOVERY",
                "RUNTIME_VERIFIED_CLAIM",
                "WORKER_OR_EFFECT_EXECUTION",
            ],
        )

        def reseal(value):
            diagnostic = value["diagnostic_contract"]
            diagnostic_core = diagnostic["contract_core"]
            diagnostic["contract_core_digest"] = module._digest_bytes(
                module._canonical(diagnostic_core)
            )
            diagnostic["environment_preimage"]["contract_core_digest"] = (
                diagnostic["contract_core_digest"]
            )
            diagnostic["environment_digest"] = module._digest_bytes(
                module._canonical(diagnostic["environment_preimage"])
            )
            value["diagnostic_contract_digest"] = module._digest_bytes(
                module._canonical(diagnostic)
            )
            return value

        mutations = [
            ("missing-request", {key: value for key, value in request.items() if key != "mode"}),
            ("extra-request", {**request, "unknown": True}),
            ("request-version", {**request, "request_version": "2.0.0"}),
            ("request-mode", {**request, "mode": "KEY_READY_DIAGNOSTIC"}),
            (
                "request-digest",
                {**request, "diagnostic_contract_digest": "sha256:" + "0" * 64},
            ),
        ]
        for field in contract:
            value = deepcopy(request)
            value["diagnostic_contract"].pop(field)
            value["diagnostic_contract_digest"] = module._digest_bytes(
                module._canonical(value["diagnostic_contract"])
            )
            mutations.append(("missing-contract-" + field, value))
        value = deepcopy(request)
        value["diagnostic_contract"]["unknown"] = True
        value["diagnostic_contract_digest"] = module._digest_bytes(
            module._canonical(value["diagnostic_contract"])
        )
        mutations.append(("extra-contract", value))
        for field in core:
            value = deepcopy(request)
            value["diagnostic_contract"]["contract_core"].pop(field)
            mutations.append(("missing-core-" + field, reseal(value)))
        value = deepcopy(request)
        value["diagnostic_contract"]["contract_core"]["unknown"] = True
        mutations.append(("extra-core", reseal(value)))
        for field in goal:
            value = deepcopy(request)
            diagnostic_core = value["diagnostic_contract"]["contract_core"]
            diagnostic_core["goal_record"].pop(field)
            diagnostic_core["goal_record_digest"] = module._digest_bytes(
                module._canonical(diagnostic_core["goal_record"])
            )
            mutations.append(("missing-goal-" + field, reseal(value)))
        value = deepcopy(request)
        diagnostic_core = value["diagnostic_contract"]["contract_core"]
        diagnostic_core["goal_record"]["unknown"] = True
        diagnostic_core["goal_record_digest"] = module._digest_bytes(
            module._canonical(diagnostic_core["goal_record"])
        )
        mutations.append(("extra-goal", reseal(value)))
        for field in contract["environment_preimage"]:
            value = deepcopy(request)
            diagnostic = value["diagnostic_contract"]
            diagnostic["environment_preimage"].pop(field)
            diagnostic["environment_digest"] = module._digest_bytes(
                module._canonical(diagnostic["environment_preimage"])
            )
            value["diagnostic_contract_digest"] = module._digest_bytes(
                module._canonical(diagnostic)
            )
            mutations.append(("missing-environment-" + field, value))
        value = deepcopy(request)
        diagnostic = value["diagnostic_contract"]
        diagnostic["environment_preimage"]["unknown"] = "sha256:" + "8" * 64
        diagnostic["environment_digest"] = module._digest_bytes(
            module._canonical(diagnostic["environment_preimage"])
        )
        value["diagnostic_contract_digest"] = module._digest_bytes(
            module._canonical(diagnostic)
        )
        mutations.append(("extra-environment", value))
        for field, replacement in (
            ("candidate", "a2336eb987364cc6bff0fdcdc7d7bfb8b21b3db8"),
            ("tree", "106facb47f1b203ed121917adfa7c885374d9fdc"),
            ("failed_v2_candidate", "0" * 40),
            ("failed_v2_tree", "0" * 40),
            ("failed_qualification_v2_ledger_digest", "sha256:" + "0" * 64),
            ("attempt", 2),
            ("attempt", True),
            ("max_attempts", 2),
            ("max_attempts", True),
            ("allowed_phases", ["provision", "run", "recover"]),
            ("non_authorizing", False),
            ("canonical_profile_digest", "sha256:" + "0" * 64),
            ("raw_profile_artifact_digest", "sha256:" + "0" * 64),
            ("base_image_digest", "sha256:" + "0" * 64),
        ):
            value = deepcopy(request)
            value["diagnostic_contract"]["contract_core"][field] = replacement
            mutations.append(("core-" + field, reseal(value)))
        for field, replacement in (
            ("user_scope_reference", "thread:/different-goal"),
            ("predecessor_qualification_ledger_digest", "sha256:" + "0" * 64),
            ("max_attempts", 2),
            ("max_attempts", True),
            ("allowed_phases", ["provision", "run", "recover"]),
            ("allowed_outcome", "KEY_READY_REACHED"),
            ("forbidden_operations", []),
        ):
            value = deepcopy(request)
            diagnostic_core = value["diagnostic_contract"]["contract_core"]
            diagnostic_core["goal_record"][field] = replacement
            diagnostic_core["goal_record_digest"] = module._digest_bytes(
                module._canonical(diagnostic_core["goal_record"])
            )
            mutations.append(("goal-" + field, reseal(value)))
        for field in contract["environment_preimage"]:
            value = deepcopy(request)
            value["diagnostic_contract"]["environment_preimage"][field] = (
                "sha256:" + "9" * 64
            )
            mutations.append(("environment-" + field, value))
        for name, mutation in mutations:
            with self.subTest(name=name), self.assertRaises(module.QualificationStop):
                module._validate_launch_request(mutation)

    def test_post_v2_diagnostic_writes_bound_ready_then_stops_before_admission(
        self,
    ) -> None:
        module = _module()
        request = self._post_v2_diagnostic_request(module)
        digest = "sha256:" + "a" * 64
        keys = {
            name: type("Key", (), {"public_key_digest": digest})()
            for name in ("M4_AUTHORITY", "OBSERVER", "PUBLISHER")
        }
        with tempfile.TemporaryDirectory(prefix="m4-post-v2-ready-") as directory:
            runtime = Path(directory)
            with (
                mock.patch.object(module, "RUNTIME", runtime),
                mock.patch.object(module, "KEY_ADMISSION", runtime / "must-not-read.json"),
                mock.patch.object(module, "_key_admission", side_effect=AssertionError),
                mock.patch.object(module.time, "sleep", side_effect=AssertionError),
                mock.patch.object(module.os, "fchown"),
                mock.patch.object(module.os, "fchmod"),
                mock.patch.object(module.os, "fsync"),
                mock.patch.object(module, "_diagnostic_stage") as stage,
                self.assertRaisesRegex(
                    module.QualificationStop,
                    "^M4_POST_V2_DIAGNOSTIC_COMPLETE$",
                ),
            ):
                module._complete_post_v2_diagnostic(
                    request,
                    keys,
                    {"public_key_digest": digest},
                    {"trust_version": "1.0.0"},
                )
            ready = json.loads((runtime / "key-ready.json").read_bytes())
            self.assertEqual(
                frozenset(ready),
                {
                    "ready_version",
                    "mode",
                    "non_authorizing",
                    "diagnostic_contract",
                    "diagnostic_contract_digest",
                    "contract_core_digest",
                    "receipt_public_key_digests",
                    "supply_public_key_digest",
                    "runtime_trust_digest",
                },
            )
            self.assertEqual(ready["ready_version"], "2.1.0")
            self.assertEqual(ready["mode"], "POST_V2_PRE_ADMISSION_DIAGNOSTIC")
            self.assertIs(ready["non_authorizing"], True)
            self.assertEqual(ready["diagnostic_contract"], request["diagnostic_contract"])
            self.assertEqual(
                ready["diagnostic_contract_digest"],
                request["diagnostic_contract_digest"],
            )
            stage.assert_called_once_with("KEY_READY_WRITTEN")

        with tempfile.TemporaryDirectory(prefix="m4-post-v2-admission-") as directory:
            runtime = Path(directory)
            admission = runtime / "key-admission.json"
            admission.write_bytes(b"{}")
            with (
                mock.patch.object(module, "RUNTIME", runtime),
                mock.patch.object(module, "KEY_ADMISSION", admission),
                mock.patch.object(module, "_key_admission", side_effect=AssertionError),
                mock.patch.object(module, "_diagnostic_stage") as stage,
                self.assertRaisesRegex(
                    module.QualificationStop,
                    "^M4_POST_V2_DIAGNOSTIC_ADMISSION_FORBIDDEN$",
                ),
            ):
                module._complete_post_v2_diagnostic(
                    request,
                    keys,
                    {"public_key_digest": digest},
                    {"trust_version": "1.0.0"},
                )
            self.assertFalse((runtime / "key-ready.json").exists())
            stage.assert_not_called()

        run_source = inspect.getsource(module._run_phase)
        completion_source = inspect.getsource(module._complete_post_v2_diagnostic)
        for forbidden in (
            "_await_key_admission",
            "_key_admission(",
            "RUN_STATE",
            "_export_m4_evidence",
            "VERIFIED",
        ):
            self.assertNotIn(forbidden, completion_source)
        self.assertLess(
            run_source.index("_verify_post_v2_diagnostic_environment("),
            run_source.index("_prepare_keys("),
        )
        self.assertLess(
            run_source.index("_complete_post_v2_diagnostic("),
            run_source.index("_configure_m3_supply_trust("),
        )
        recover_source = inspect.getsource(module._recover_phase)
        self.assertLess(
            recover_source.index("_validate_launch_request(request)"),
            recover_source.index("_validate_run_state("),
        )

    def test_launch_request_requires_closed_qualification_v2_contract(self) -> None:
        module = _module()
        request = self._qualification_request(module)
        self.assertEqual(module._validate_launch_request(request), "QUALIFICATION")
        with self.assertRaises(module.QualificationStop):
            module._validate_launch_request(
                {
                    "request_version": "1.0.0",
                    "candidate": "b" * 40,
                    "environment": "sha256:" + "a" * 64,
                    "attempt": 1,
                }
            )

        mutations = []
        for field in request:
            value = deepcopy(request)
            value.pop(field)
            mutations.append(("missing-request-" + field, value))
        mutations.append(("extra-request", {**request, "unknown": True}))
        mutations.append(
            (
                "request-version",
                {**request, "request_version": "1.0.0"},
            )
        )
        mutations.append(
            (
                "contract-digest",
                {**request, "qualification_contract_digest": "sha256:" + "0" * 64},
            )
        )
        for field in request["qualification_contract"]:
            value = deepcopy(request)
            value["qualification_contract"].pop(field)
            value["qualification_contract_digest"] = module._digest_bytes(
                module._canonical(value["qualification_contract"])
            )
            mutations.append(("missing-contract-" + field, value))
        value = deepcopy(request)
        value["qualification_contract"]["unknown"] = True
        value["qualification_contract_digest"] = module._digest_bytes(
            module._canonical(value["qualification_contract"])
        )
        mutations.append(("extra-contract", value))
        for field, replacement in (
            ("attempt", True),
            ("max_attempts", 2.0),
            ("success_target", 1.0),
        ):
            value = deepcopy(request)
            value["qualification_contract"]["contract_core"][field] = replacement
            mutations.append(("type-alias-" + field, value))
        for field in request["qualification_contract"]["contract_core"]:
            value = deepcopy(request)
            core = value["qualification_contract"]["contract_core"]
            original = core[field]
            if type(original) is bool:
                core[field] = not original
            elif type(original) is int:
                core[field] = original + 1
            else:
                core[field] = str(original) + "-mutated"
            mutations.append(("core-" + field, value))
        for field in request["qualification_contract"]["environment_preimage"]:
            value = deepcopy(request)
            value["qualification_contract"]["environment_preimage"][field] = (
                "sha256:" + "9" * 64
            )
            mutations.append(("environment-" + field, value))
        for name, mutation in mutations:
            with self.subTest(name=name), self.assertRaises(module.QualificationStop):
                module._validate_launch_request(mutation)

    def test_one_use_qualification_contract_is_closed_single_attempt_and_cross_mode_safe(
        self,
    ) -> None:
        module = _module()
        request = self._one_use_qualification_request(module)
        contract = request["qualification_contract"]
        core = contract["contract_core"]
        projection = core["scope_projection"]
        validated, digest = module._one_use_qualification_request_contract(request)
        self.assertIs(validated, contract)
        self.assertEqual(digest, request["qualification_contract_digest"])
        self.assertEqual(
            module._validate_launch_request(request),
            "M4_REQUEST_BOUND_ONE_USE_QUALIFICATION",
        )
        self.assertEqual(
            frozenset(projection),
            {
                "record_version",
                "record_kind",
                "authority",
                "user_scope_reference",
                "candidate",
                "tree",
                "max_attempts",
                "success_target",
                "success_target_authorizing",
                "predecessor_qualification_ledger_digest",
                "predecessor_diagnostic_ledger_digest",
                "predecessor_diagnostic_bundle_digest",
            },
        )
        self.assertEqual(
            (projection["record_version"], projection["record_kind"]),
            ("1.0.0", "M4_ONE_USE_QUALIFICATION_SCOPE_PROJECTION"),
        )
        self.assertEqual(projection["authority"], "NONE")
        self.assertEqual(core["user_goal_digest"], module._digest_bytes(
            module._canonical(projection)
        ))
        self.assertEqual(
            (core["attempt"], core["max_attempts"], core["success_target"]),
            (1, 1, 1),
        )
        self.assertIs(core["success_target_authorizing"], False)
        for field in (
            "user_scope_reference",
            "candidate",
            "tree",
            "max_attempts",
            "success_target",
            "success_target_authorizing",
            "predecessor_qualification_ledger_digest",
            "predecessor_diagnostic_ledger_digest",
            "predecessor_diagnostic_bundle_digest",
        ):
            self.assertEqual(core[field], projection[field])

        def reseal(
            value,
            *,
            bind_projection: bool = True,
            sync_environment_core: bool = True,
        ):
            changed_contract = value["qualification_contract"]
            changed_core = changed_contract["contract_core"]
            changed_projection = changed_core.get("scope_projection")
            if bind_projection and type(changed_projection) is dict:
                changed_core["user_goal_digest"] = module._digest_bytes(
                    module._canonical(changed_projection)
                )
            changed_contract["contract_core_digest"] = module._digest_bytes(
                module._canonical(changed_core)
            )
            environment = changed_contract["environment_preimage"]
            if sync_environment_core:
                environment["contract_core_digest"] = changed_contract[
                    "contract_core_digest"
                ]
            changed_contract["environment_digest"] = module._digest_bytes(
                module._canonical(environment)
            )
            value["qualification_contract_digest"] = module._digest_bytes(
                module._canonical(changed_contract)
            )
            return value

        mutations = []
        for field in request:
            value = deepcopy(request)
            value.pop(field)
            mutations.append(("missing-request-" + field, value))
        mutations.extend(
            [
                ("extra-request", {**request, "unknown": True}),
                ("request-version-v2", {**request, "request_version": "2.0.0"}),
                (
                    "request-digest",
                    {
                        **request,
                        "qualification_contract_digest": "sha256:" + "0" * 64,
                    },
                ),
            ]
        )
        v2_request = self._qualification_request(module)
        mutations.extend(
            [
                (
                    "v3-request-v2-contract",
                    {
                        "request_version": "3.0.0",
                        "qualification_contract": v2_request[
                            "qualification_contract"
                        ],
                        "qualification_contract_digest": v2_request[
                            "qualification_contract_digest"
                        ],
                    },
                ),
                (
                    "v2-request-v3-contract",
                    {**request, "request_version": "2.0.0"},
                ),
            ]
        )
        for field in contract:
            value = deepcopy(request)
            value["qualification_contract"].pop(field)
            value["qualification_contract_digest"] = module._digest_bytes(
                module._canonical(value["qualification_contract"])
            )
            mutations.append(("missing-contract-" + field, value))
        value = deepcopy(request)
        value["qualification_contract"]["unknown"] = True
        value["qualification_contract_digest"] = module._digest_bytes(
            module._canonical(value["qualification_contract"])
        )
        mutations.append(("extra-contract", value))

        core_replacements = {
            "contract_version": "2.0.0",
            "contract_kind": "M4_EXACT_DISPOSABLE_TEST_PROFILE_QUALIFICATION_V2",
            "scope_projection": {},
            "user_scope_reference": "thread:/different-goal",
            "user_goal_digest": module.QUALIFICATION_GOAL_DIGEST,
            "candidate": "0" * 40,
            "tree": "1" * 40,
            "attempt": 2,
            "source_files_digest": "sha256:" + "0" * 64,
            "canonical_profile_digest": "sha256:" + "0" * 64,
            "raw_profile_artifact_digest": "sha256:" + "0" * 64,
            "base_image_digest": "sha256:" + "0" * 64,
            "predecessor_qualification_ledger_digest": (
                module.PREDECESSOR_QUALIFICATION_LEDGER_DIGEST
            ),
            "predecessor_diagnostic_ledger_digest": (
                module.PREDECESSOR_DIAGNOSTIC_LEDGER_DIGEST
            ),
            "predecessor_diagnostic_bundle_digest": (
                module.PREDECESSOR_DIAGNOSTIC_BUNDLE_DIGEST
            ),
            "max_attempts": 2,
            "success_target": 2,
            "success_target_authorizing": True,
        }
        for field in core:
            value = deepcopy(request)
            value["qualification_contract"]["contract_core"].pop(field)
            mutations.append(
                (
                    "missing-core-" + field,
                    reseal(
                        value,
                        bind_projection=field
                        not in {"scope_projection", "user_goal_digest"},
                    ),
                )
            )
            if field != "source_files_digest":
                value = deepcopy(request)
                value["qualification_contract"]["contract_core"][field] = (
                    core_replacements[field]
                )
                mutations.append(
                    (
                        "core-" + field,
                        reseal(value, bind_projection=field != "user_goal_digest"),
                    )
                )
            else:
                value = deepcopy(request)
                value["qualification_contract"]["contract_core"][field] = (
                    "sha256:" + "0" * 64
                )
                mutations.append(("core-" + field, value))
        value = deepcopy(request)
        value["qualification_contract"]["contract_core"]["unknown"] = True
        mutations.append(("extra-core", reseal(value)))

        projection_replacements = {
            "record_version": "2.0.0",
            "record_kind": "M4_DIFFERENT_SCOPE_PROJECTION",
            "authority": "QUALIFICATION",
            "user_scope_reference": "",
            "candidate": "0" * 40,
            "tree": "1" * 40,
            "max_attempts": 2,
            "success_target": 2,
            "success_target_authorizing": True,
            "predecessor_qualification_ledger_digest": (
                module.PREDECESSOR_QUALIFICATION_LEDGER_DIGEST
            ),
            "predecessor_diagnostic_ledger_digest": (
                module.PREDECESSOR_DIAGNOSTIC_LEDGER_DIGEST
            ),
            "predecessor_diagnostic_bundle_digest": (
                module.PREDECESSOR_DIAGNOSTIC_BUNDLE_DIGEST
            ),
        }
        for field in projection:
            value = deepcopy(request)
            value["qualification_contract"]["contract_core"][
                "scope_projection"
            ].pop(field)
            mutations.append(("missing-projection-" + field, reseal(value)))
            value = deepcopy(request)
            value["qualification_contract"]["contract_core"][
                "scope_projection"
            ][field] = projection_replacements[field]
            mutations.append(("projection-" + field, reseal(value)))
        value = deepcopy(request)
        value["qualification_contract"]["contract_core"]["scope_projection"][
            "unknown"
        ] = True
        mutations.append(("extra-projection", reseal(value)))
        value = deepcopy(request)
        value["qualification_contract"]["contract_core"]["scope_projection"][
            "user_scope_reference"
        ] = "\ud800"
        mutations.append(("projection-user-scope-invalid-utf8", value))
        value = deepcopy(request)
        value["qualification_contract"]["contract_core"]["scope_projection"][
            "user_scope_reference"
        ] = "x" * 513
        mutations.append(("projection-user-scope-unbounded", reseal(value)))

        for field in contract["environment_preimage"]:
            value = deepcopy(request)
            value["qualification_contract"]["environment_preimage"].pop(field)
            changed_contract = value["qualification_contract"]
            changed_contract["environment_digest"] = module._digest_bytes(
                module._canonical(changed_contract["environment_preimage"])
            )
            value["qualification_contract_digest"] = module._digest_bytes(
                module._canonical(changed_contract)
            )
            mutations.append(("missing-environment-" + field, value))
            if field == "contract_core_digest":
                value = deepcopy(request)
                value["qualification_contract"]["environment_preimage"][field] = (
                    "sha256:" + "9" * 64
                )
                mutations.append(
                    (
                        "environment-" + field,
                        reseal(value, sync_environment_core=False),
                    )
                )
            else:
                value = deepcopy(request)
                value["qualification_contract"]["environment_preimage"][field] = (
                    "sha256:" + "9" * 64
                )
                mutations.append(("environment-" + field, value))
        value = deepcopy(request)
        value["qualification_contract"]["environment_preimage"]["unknown"] = (
            "sha256:" + "8" * 64
        )
        mutations.append(("extra-environment", reseal(value)))
        for field, replacement in (
            ("attempt", True),
            ("max_attempts", True),
            ("success_target", True),
        ):
            value = deepcopy(request)
            value["qualification_contract"]["contract_core"][field] = replacement
            mutations.append(
                ("bool-as-int-core-" + field, reseal(value))
            )
        for field in ("max_attempts", "success_target"):
            value = deepcopy(request)
            value["qualification_contract"]["contract_core"][
                "scope_projection"
            ][field] = True
            mutations.append(("bool-as-int-projection-" + field, reseal(value)))

        for name, mutation in mutations:
            with self.subTest(name=name), self.assertRaises(
                module.QualificationStop
            ):
                module._one_use_qualification_request_contract(mutation)
            with self.subTest(dispatch=name), self.assertRaises(
                module.QualificationStop
            ):
                module._validate_launch_request(mutation)

        profile = module._strict_bytes(PROFILE.read_bytes())
        source = {
            "commit": core["candidate"],
            "tree": core["tree"],
            "files_digest": core["source_files_digest"],
        }
        host_provenance = {
            "image": {"sha256": module.BASE_IMAGE_DIGEST},
            "vm": {"seed_digest": contract["environment_preimage"]["seed_digest"]},
        }
        live_request = self._one_use_qualification_request(
            module,
            host_provenance_digest=module._digest_bytes(
                module._canonical(host_provenance)
            ),
        )
        live_contract = live_request["qualification_contract"]
        observed_digests = {
            module.PROFILE_PATH: module.CANONICAL_PROFILE_DIGEST,
            module.SOURCE_ARCHIVE: live_contract["environment_preimage"][
                "source_archive_digest"
            ],
            module.PACKAGE_RUNTIME_PLAN: live_contract["environment_preimage"][
                "package_runtime_plan_digest"
            ],
        }

        live_mutations = []
        value = deepcopy(live_request)
        value["qualification_contract"]["contract_core"][
            "source_files_digest"
        ] = "sha256:" + "9" * 64
        live_mutations.append(("live-core-source_files_digest", reseal(value)))
        for field in (
            "source_archive_digest",
            "seed_digest",
            "package_runtime_plan_digest",
            "host_provenance_digest",
        ):
            value = deepcopy(live_request)
            value["qualification_contract"]["environment_preimage"][field] = (
                "sha256:" + "9" * 64
            )
            live_mutations.append(("live-environment-" + field, reseal(value)))
        with (
            mock.patch.object(module, "_package_runtime_plan", return_value={}),
            mock.patch.object(
                module,
                "_digest_file",
                side_effect=lambda path, _maximum: observed_digests[path],
            ),
        ):
            for name, mutation in live_mutations:
                with self.subTest(name=name), self.assertRaises(
                    module.QualificationStop
                ):
                    module._verify_qualification_environment(
                        mutation,
                        source,
                        host_provenance,
                        profile,
                    )

        digest_value = "sha256:" + "a" * 64
        keys = {
            name: type("Key", (), {"public_key_digest": digest_value})()
            for name in ("M4_AUTHORITY", "OBSERVER", "PUBLISHER")
        }
        supply = {"public_key_digest": digest_value}
        runtime_trust = {"trust_version": "1.0.0"}
        admission = {
            "admission_version": "3.0.0",
            "mode": module.KEY_ADMISSION_MODE,
            "qualification_contract": contract,
            "qualification_contract_digest": request[
                "qualification_contract_digest"
            ],
            "contract_core_digest": contract["contract_core_digest"],
            "ledger_entry_digest": digest_value,
            "receipt_public_key_digests": {
                name: key.public_key_digest for name, key in keys.items()
            },
            "supply_public_key_digest": digest_value,
            "runtime_trust_digest": module._digest_bytes(
                module._canonical(runtime_trust)
            ),
        }
        with tempfile.TemporaryDirectory(prefix="m4-one-use-admission-") as directory:
            root = Path(directory)
            admission_path = root / "key-admission.json"
            admission_path.write_bytes(module._canonical(admission))
            ready_payloads = []
            with (
                mock.patch.object(module, "RUNTIME", root),
                mock.patch.object(module, "KEY_ADMISSION", admission_path),
                mock.patch.object(
                    module,
                    "_write_exact",
                    side_effect=lambda _path, raw, _mode: ready_payloads.append(raw),
                ),
                mock.patch.object(module, "_diagnostic_stage"),
            ):
                self.assertEqual(
                    module._await_key_admission(
                        request, keys, supply, runtime_trust
                    ),
                    admission,
                )
            self.assertEqual(len(ready_payloads), 1)
            ready = module._strict_bytes(ready_payloads[0])
            self.assertEqual(ready["ready_version"], "3.0.0")
            self.assertEqual((ready["attempt"], core["max_attempts"]), (1, 1))
            admission_path.write_bytes(
                module._canonical({**admission, "admission_version": "2.0.0"})
            )
            with mock.patch.object(module, "KEY_ADMISSION", admission_path), self.assertRaises(
                module.QualificationStop
            ):
                module._key_admission(
                    request,
                    keys,
                    digest_value,
                    admission["runtime_trust_digest"],
                )

        write = mock.Mock()
        with (
            mock.patch.object(module, "_write_exact", write),
            self.assertRaises(module.QualificationStop),
        ):
            module._await_key_admission(projection, keys, supply, runtime_trust)
        write.assert_not_called()
        for forbidden in (
            "_write_exact",
            "_key_admission",
            "_prepare_keys",
            "_configure_m3_supply_trust",
            "_export_m4_evidence",
        ):
            self.assertNotIn(
                forbidden,
                inspect.getsource(module._one_use_qualification_request_contract),
            )

        state = self._run_state(module, one_use=True)
        self.assertIs(module._validate_run_state(state), state)
        evidence_projection = module._qualification_evidence_projection(state)
        evidence_core = evidence_projection["qualification_contract"][
            "contract_core"
        ]
        self.assertEqual(
            (state["identity"]["attempt"], evidence_core["max_attempts"]),
            (1, 1),
        )
        self.assertEqual(
            state["trust"]["key_admission"]["admission_version"], "3.0.0"
        )
        self.assertIn(
            '"max_attempts": contract["contract_core"]["max_attempts"]',
            inspect.getsource(module._export_m4_evidence),
        )

    def test_key_ready_and_admission_bind_the_full_exact_contract(self) -> None:
        module = _module()
        request = self._qualification_request(module)
        contract = request["qualification_contract"]
        contract_digest = request["qualification_contract_digest"]
        digest = "sha256:" + "a" * 64
        keys = {
            name: type("Key", (), {"public_key_digest": digest})()
            for name in ("M4_AUTHORITY", "OBSERVER", "PUBLISHER")
        }
        admission = {
            "admission_version": "2.0.0",
            "mode": module.KEY_ADMISSION_MODE,
            "qualification_contract": contract,
            "qualification_contract_digest": contract_digest,
            "contract_core_digest": contract["contract_core_digest"],
            "ledger_entry_digest": digest,
            "receipt_public_key_digests": {
                name: key.public_key_digest for name, key in keys.items()
            },
            "supply_public_key_digest": digest,
            "runtime_trust_digest": digest,
        }
        with tempfile.TemporaryDirectory(prefix="m4-v2-admission-") as directory:
            path = Path(directory) / "key-admission.json"
            path.write_bytes(module._canonical(admission))
            with mock.patch.object(module, "KEY_ADMISSION", path):
                self.assertEqual(
                    module._key_admission(request, keys, digest, digest),
                    admission,
                )
            for name, mutation in (
                ("contract", {**admission, "qualification_contract": {}}),
                ("contract-digest", {**admission, "qualification_contract_digest": digest}),
                ("core-digest", {**admission, "contract_core_digest": digest}),
                ("extra", {**admission, "unknown": True}),
            ):
                path.write_bytes(module._canonical(mutation))
                with self.subTest(name=name), mock.patch.object(
                    module, "KEY_ADMISSION", path
                ), self.assertRaises(module.QualificationStop):
                    module._key_admission(request, keys, digest, digest)

        ready_source = inspect.getsource(module._await_key_admission)
        for field in (
            "qualification_contract",
            "qualification_contract_digest",
            "contract_core_digest",
        ):
            self.assertIn(field, ready_source)

    def test_guest_remeasures_all_locally_observable_environment_inputs(self) -> None:
        module = _module()
        with tempfile.TemporaryDirectory(prefix="m4-v2-environment-") as directory:
            root = Path(directory)
            source_archive = root / "source.tgz"
            package_plan_path = root / "package-runtime-plan.json"
            provisioning_script = root / "provision.sh"
            package_source = root / "ubuntu.sources"
            runtime_config = root / "offline.conf"
            runtime_tool = root / "tool"
            for path, raw in (
                (source_archive, b"source-archive"),
                (provisioning_script, b"#!/bin/sh\nexit 0\n"),
                (package_source, b"deb-source"),
                (runtime_config, b"offline"),
                (runtime_tool, b"tool"),
            ):
                path.write_bytes(raw)
            packages = {"exact-package": "1.2.3-1"}
            plan = {
                "plan_version": "1.0.0",
                "packages": packages,
                "provisioning_script_digest": module._digest_file(
                    provisioning_script
                ),
                "package_sources": {
                    str(package_source): module._digest_file(package_source)
                },
                "runtime_configs": {
                    str(runtime_config): module._digest_file(runtime_config)
                },
                "runtime_tools": {
                    str(runtime_tool): module._digest_file(runtime_tool)
                },
            }
            package_plan_path.write_bytes(module._canonical(plan))
            source = {
                "commit": "b" * 40,
                "tree": "c" * 40,
                "files": {},
                "files_digest": "sha256:" + "d" * 64,
            }
            host_provenance = {
                "image": {"sha256": module.BASE_IMAGE_DIGEST},
                "vm": {"seed_digest": "sha256:" + "e" * 64},
            }
            contract, _ = self._qualification_contract(
                module,
                source_files_digest=source["files_digest"],
                seed_digest=host_provenance["vm"]["seed_digest"],
                host_provenance_digest=module._digest_bytes(
                    module._canonical(host_provenance)
                ),
            )
            environment = contract["environment_preimage"]
            environment["source_archive_digest"] = module._digest_file(source_archive)
            environment["package_runtime_plan_digest"] = module._digest_file(
                package_plan_path
            )
            contract["environment_digest"] = module._digest_bytes(
                module._canonical(environment)
            )
            request = {
                "request_version": "2.0.0",
                "qualification_contract": contract,
                "qualification_contract_digest": module._digest_bytes(
                    module._canonical(contract)
                ),
            }
            diagnostic_request = self._post_v2_diagnostic_request(
                module,
                source_files_digest=source["files_digest"],
                seed_digest=host_provenance["vm"]["seed_digest"],
                host_provenance_digest=module._digest_bytes(
                    module._canonical(host_provenance)
                ),
            )
            diagnostic_contract = diagnostic_request["diagnostic_contract"]
            diagnostic_environment = diagnostic_contract["environment_preimage"]
            diagnostic_environment["source_archive_digest"] = module._digest_file(
                source_archive
            )
            diagnostic_environment["package_runtime_plan_digest"] = (
                module._digest_file(package_plan_path)
            )
            diagnostic_contract["environment_digest"] = module._digest_bytes(
                module._canonical(diagnostic_environment)
            )
            diagnostic_request["diagnostic_contract_digest"] = module._digest_bytes(
                module._canonical(diagnostic_contract)
            )

            def dpkg(argv, **_kwargs):
                return module.subprocess.CompletedProcess(
                    argv, 0, stdout=packages[argv[-1]].encode("ascii"), stderr=b""
                )

            patches = (
                mock.patch.object(module, "SOURCE_ARCHIVE", source_archive),
                mock.patch.object(module, "PACKAGE_RUNTIME_PLAN", package_plan_path),
                mock.patch.object(module, "PROVISIONING_SCRIPT", provisioning_script),
                mock.patch.object(module, "PROFILE_PATH", PROFILE),
                mock.patch.object(module, "PACKAGE_VERSIONS", packages),
                mock.patch.object(module, "PACKAGE_SOURCE_PATHS", frozenset({str(package_source)})),
                mock.patch.object(module, "PACKAGE_SOURCE_UBUNTU_PATH", str(package_source)),
                mock.patch.object(
                    module,
                    "PACKAGE_SOURCE_UBUNTU_DIGEST",
                    module._digest_file(package_source),
                ),
                mock.patch.object(module, "RUNTIME_CONFIG_PATHS", frozenset({str(runtime_config)})),
                mock.patch.object(module, "RUNTIME_TOOL_PATHS", frozenset({str(runtime_tool)})),
                mock.patch.object(module, "_package_source_boundary_observations"),
                mock.patch.object(module.subprocess, "run", side_effect=dpkg),
            )
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7], patches[8], patches[9], patches[10], patches[11]:
                profile = json.loads(PROFILE.read_bytes())
                self.assertEqual(
                    module._verify_qualification_environment(
                        request, source, host_provenance, profile
                    ),
                    plan,
                )
                self.assertEqual(
                    module._verify_post_v2_diagnostic_environment(
                        diagnostic_request, source, host_provenance, profile
                    ),
                    plan,
                )
                for field, replacement in (
                    ("candidate", "0" * 40),
                    ("tree", "0" * 40),
                    ("source_files_digest", "sha256:" + "0" * 64),
                ):
                    mutated_diagnostic = deepcopy(diagnostic_request)
                    mutated_contract = mutated_diagnostic["diagnostic_contract"]
                    mutated_core = mutated_contract["contract_core"]
                    mutated_core[field] = replacement
                    mutated_contract["contract_core_digest"] = module._digest_bytes(
                        module._canonical(mutated_core)
                    )
                    mutated_environment = mutated_contract["environment_preimage"]
                    mutated_environment["contract_core_digest"] = mutated_contract[
                        "contract_core_digest"
                    ]
                    mutated_contract["environment_digest"] = module._digest_bytes(
                        module._canonical(mutated_environment)
                    )
                    mutated_diagnostic["diagnostic_contract_digest"] = (
                        module._digest_bytes(module._canonical(mutated_contract))
                    )
                    with self.subTest(
                        diagnostic_core_binding=field
                    ), self.assertRaises(module.QualificationStop):
                        module._verify_post_v2_diagnostic_environment(
                            mutated_diagnostic, source, host_provenance, profile
                        )
                source_archive.write_bytes(b"substituted")
                with self.assertRaises(module.QualificationStop):
                    module._verify_qualification_environment(
                        request, source, host_provenance, profile
                    )
                with self.assertRaises(module.QualificationStop):
                    module._verify_post_v2_diagnostic_environment(
                        diagnostic_request, source, host_provenance, profile
                    )
                source_archive.write_bytes(b"source-archive")
                package_plan_path.write_bytes(
                    module._canonical({**plan, "unknown": True})
                )
                with self.assertRaises(module.QualificationStop):
                    module._verify_qualification_environment(
                        request, source, host_provenance, profile
                    )
                package_plan_path.write_bytes(module._canonical(plan))
                for field, replacement in (
                    ("commit", "0" * 40),
                    ("tree", "0" * 40),
                    ("files_digest", "sha256:" + "0" * 64),
                ):
                    mutated_source = {**source, field: replacement}
                    with self.subTest(source_field=field), self.assertRaises(
                        module.QualificationStop
                    ):
                        module._verify_qualification_environment(
                            request, mutated_source, host_provenance, profile
                        )
                for field in ("base-image", "seed", "host-provenance"):
                    mutated_provenance = deepcopy(host_provenance)
                    if field == "base-image":
                        mutated_provenance["image"]["sha256"] = (
                            "sha256:" + "0" * 64
                        )
                    elif field == "seed":
                        mutated_provenance["vm"]["seed_digest"] = (
                            "sha256:" + "0" * 64
                        )
                    else:
                        mutated_provenance["unknown"] = True
                    with self.subTest(provenance_field=field), self.assertRaises(
                        module.QualificationStop
                    ):
                        module._verify_qualification_environment(
                            request, source, mutated_provenance, profile
                        )
                mutated_request = deepcopy(request)
                mutated_environment = mutated_request["qualification_contract"][
                    "environment_preimage"
                ]
                mutated_environment["seed_digest"] = "sha256:" + "0" * 64
                mutated_request["qualification_contract"]["environment_digest"] = (
                    module._digest_bytes(module._canonical(mutated_environment))
                )
                mutated_request["qualification_contract_digest"] = module._digest_bytes(
                    module._canonical(mutated_request["qualification_contract"])
                )
                with self.assertRaises(module.QualificationStop):
                    module._verify_qualification_environment(
                        mutated_request, source, host_provenance, profile
                    )
                for field in (
                    "source_archive_digest",
                    "seed_digest",
                    "package_runtime_plan_digest",
                    "host_provenance_digest",
                ):
                    mutated_diagnostic = deepcopy(diagnostic_request)
                    mutated_contract = mutated_diagnostic["diagnostic_contract"]
                    mutated_environment = mutated_contract["environment_preimage"]
                    mutated_environment[field] = "sha256:" + "0" * 64
                    mutated_contract["environment_digest"] = module._digest_bytes(
                        module._canonical(mutated_environment)
                    )
                    mutated_diagnostic["diagnostic_contract_digest"] = (
                        module._digest_bytes(module._canonical(mutated_contract))
                    )
                    with self.subTest(
                        diagnostic_environment_binding=field
                    ), self.assertRaises(module.QualificationStop):
                        module._verify_post_v2_diagnostic_environment(
                            mutated_diagnostic, source, host_provenance, profile
                        )

    def test_run_state_rejects_contract_or_plan_projection_substitution(self) -> None:
        module = _module()
        valid = self._run_state(module)
        self.assertIs(module._validate_run_state(valid), valid)
        for name, mutate in (
            (
                "contract",
                lambda value: value["identity"]["qualification_contract"]
                ["contract_core"].update({"attempt": 2}),
            ),
            (
                "contract-digest",
                lambda value: value["identity"].update(
                    {"qualification_contract_digest": "sha256:" + "0" * 64}
                ),
            ),
            (
                "admission-contract",
                lambda value: value["trust"]["key_admission"].update(
                    {"qualification_contract": {}}
                ),
            ),
            (
                "package-plan",
                lambda value: value["identity"]["package_runtime_plan"].update(
                    {"unknown": True}
                ),
            ),
        ):
            value = deepcopy(valid)
            mutate(value)
            with self.subTest(name=name), self.assertRaises(module.QualificationStop):
                module._validate_run_state(value)

    def test_manifest_and_evidence_export_exact_v2_contract_and_admission(self) -> None:
        module = _module()
        state = self._run_state(module)
        projection = module._qualification_evidence_projection(state)
        self.assertEqual(
            frozenset(projection),
            {
                "qualification_contract",
                "qualification_contract_digest",
                "admission_digest",
                "package_runtime_plan",
            },
        )
        self.assertEqual(
            projection["qualification_contract"],
            state["identity"]["qualification_contract"],
        )
        self.assertEqual(
            projection["qualification_contract_digest"],
            state["identity"]["qualification_contract_digest"],
        )
        self.assertEqual(
            projection["admission_digest"],
            state["trust"]["key_admission"]["ledger_entry_digest"],
        )
        source = inspect.getsource(module._export_m4_evidence)
        self.assertIn('"bundle_version": "2.0.0"', source)
        self.assertEqual(source.count("**contract_projection"), 2)
        run_source = inspect.getsource(module._run_phase)
        self.assertLess(
            run_source.index("_verify_qualification_environment("),
            run_source.index("_prepare_keys("),
        )
        recover_source = inspect.getsource(module._recover_phase)
        self.assertLess(
            recover_source.index("_verify_qualification_environment("),
            recover_source.index("_export_m4_evidence("),
        )
        self.assertIn('"qualification_contract": contract', recover_source)
        self.assertIn('"qualification_contract_digest": contract_digest', recover_source)

    def test_run_state_writer_and_recovery_share_one_closed_schema(self) -> None:
        module = _module()
        valid = self._run_state(module)
        self.assertIs(module._validate_run_state(valid), valid)
        for mutation in ("missing", "extra", "prepared", "cursor", "retry", "crypto-claim"):
            value = deepcopy(valid)
            if mutation == "missing":
                value.pop("publication")
            elif mutation == "extra":
                value["unknown"] = True
            elif mutation == "prepared":
                value["durable"]["m3_runtime_session"]["state"] = "PREPARED"
            elif mutation == "cursor":
                value["durable"]["m4_recovery"]["attempt_cursor"] = 0
            elif mutation == "retry":
                value["durable"]["m4_recovery"]["retry_allowed"] = True
            else:
                value["trust"]["verifier"]["independent_cryptographic_implementations"] = True
            with self.subTest(mutation=mutation), self.assertRaises(module.QualificationStop):
                module._validate_run_state(value)

    def test_prepared_publication_root_fd_resolves_exact_canonical_target(self) -> None:
        module = _module()
        l0 = module._load_project()[1]
        compiled = l0.compile_profile(module._strict_bytes(L0_PROFILE.read_bytes()))
        self.assertEqual(
            (compiled.outcome, compiled.reason),
            (l0.L0Outcome.COMPILED_DRAFT, l0.L0Reason.PROFILE_COMPILED),
        )
        self.assertIsNotNone(compiled.profile)

        with tempfile.TemporaryDirectory(prefix="harness-m4-publication-root-") as directory:
            base = Path(directory)
            parent = base / "anchor"
            root = parent / "publication"
            denied = base / "synthetic-repository"
            root_descriptor = -1
            try:
                with ExitStack() as stack:
                    stack.enter_context(mock.patch.object(module, "PUBLICATION_PARENT", parent))
                    stack.enter_context(mock.patch.object(module, "PUBLICATION_ROOT", root))
                    stack.enter_context(mock.patch.object(module, "DENIED_REPOSITORY", denied))
                    stack.enter_context(mock.patch.object(module.os, "chown"))
                    stack.enter_context(mock.patch.object(module.os, "fchown"))
                    root_descriptor = module._prepare_publication_root()

                    result = l0.resolve_target(
                        compiled.profile,
                        root_descriptor,
                        {
                            "canonical_path": "/staging/artifact.txt",
                            "descriptor_id": "m4-publication-target-1",
                            "root_id": "m4-publication-root-1",
                            "resolution_epoch": 1,
                        },
                    )
                    self.assertEqual(
                        (result.outcome, result.reason),
                        (l0.L0Outcome.RESOLVED, l0.L0Reason.PATH_RESOLVED),
                    )
                    self.assertIsNotNone(result.binding)
                    target = root / "artifact.txt"
                    info = target.stat()
                    self.assertEqual(result.binding.canonical_path, "/staging/artifact.txt")
                    self.assertEqual(
                        (result.binding.final_device, result.binding.final_inode),
                        (info.st_dev, info.st_ino),
                    )
                    self.assertEqual(result.binding.final_digest, module._digest_bytes(b"old\n"))
                    self.assertFalse((root / "staging").exists())
            finally:
                if root_descriptor >= 0:
                    module.os.close(root_descriptor)
                for path in (parent, denied, denied / ".git"):
                    if path.exists():
                        module.os.chmod(path, 0o700)

    def test_restart_publication_rejects_oversized_artifact_before_hashing(self) -> None:
        module = _module()
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory) / "anchor"
            root = parent / "publication"
            artifact = root / "artifact.txt"
            denied = Path(directory) / "synthetic-repository"
            artifact.parent.mkdir(parents=True)
            denied.mkdir()
            artifact.write_bytes(b"x" * ((1 << 20) + 1))
            root_info = root.stat()
            artifact_info = artifact.stat()
            digest = "sha256:" + "a" * 64
            state = {
                "publication": {
                    "root_anchor": {
                        "ancestry": [
                            {"device": root_info.st_dev, "inode": root_info.st_ino}
                        ]
                    },
                    "published_binding": {
                        "final_device": artifact_info.st_dev,
                        "final_inode": artifact_info.st_ino,
                        "final_digest": digest,
                    },
                    "artifact_digest": digest,
                }
            }
            old_parent = module.PUBLICATION_PARENT
            old_root = module.PUBLICATION_ROOT
            old_denied = module.DENIED_REPOSITORY
            module.PUBLICATION_PARENT = parent
            module.PUBLICATION_ROOT = root
            module.DENIED_REPOSITORY = denied
            try:
                with mock.patch.object(
                    module,
                    "_digest_bytes",
                    side_effect=AssertionError("oversized bytes reached the hasher"),
                ), self.assertRaisesRegex(
                    module.QualificationStop,
                    "^M4_PUBLICATION_RESTART_BYTES_MISMATCH$",
                ):
                    module._recover_publication(state)
            finally:
                module.PUBLICATION_PARENT = old_parent
                module.PUBLICATION_ROOT = old_root
                module.DENIED_REPOSITORY = old_denied

    def test_package_plan_discriminator_contract_is_closed_and_stops_before_keys(
        self,
    ) -> None:
        module = _module()
        goal = {
            "goal_version": "1.0.0",
            "goal_kind": "M4_PACKAGE_RUNTIME_PLAN_DISCRIMINATOR",
            "user_scope_reference": (
                "thread:/goal/m4-package-runtime-plan-discriminator/2026-08-28"
            ),
            "predecessor_qualification_ledger_digest": (
                "sha256:c80f4eb33b811b59a4f80aee5fdf781964b441d20e1620ca4b1f2b63f30c479a"
            ),
            "predecessor_post_v2_diagnostic_ledger_digest": (
                "sha256:e8cfa1b9117268bf2298ba1936a99a79114e8f83aea2188e998fce6becdf97dc"
            ),
            "predecessor_post_v2_diagnostic_bundle_digest": (
                "sha256:51b84c6477a17a66e92290ed7cb6f787fb9df8f5445d112d76e3e38c055f6d2f"
            ),
            "max_attempts": 1,
            "success_target": 1,
            "success_target_authorizing": False,
            "allowed_phases": ["provision", "run"],
            "allowed_outcome": "SANITIZED_PACKAGE_RUNTIME_PLAN_OBSERVATION_ONLY",
            "forbidden_operations": [
                "AUTOMATIC_RETRY",
                "KEY_ADMISSION_ARTIFACT",
                "PACKAGE_PLAN_REMEDIATION",
                "POST_V2_DIAGNOSTIC_BUNDLE_MUTATION",
                "POST_V2_DIAGNOSTIC_LEDGER_WRITE",
                "QUALIFICATION_EVIDENCE_EXPORT",
                "QUALIFICATION_V2_LEDGER_WRITE",
                "REBOOT_OR_RECOVERY",
                "RUNTIME_VERIFIED_CLAIM",
                "WORKER_OR_EFFECT_EXECUTION",
            ],
        }
        core = {
            "contract_version": "1.0.0",
            "contract_kind": "M4_PACKAGE_RUNTIME_PLAN_DISCRIMINATOR",
            "goal_record": goal,
            "goal_record_digest": module._digest_bytes(module._canonical(goal)),
            "failed_v2_candidate": module.FAILED_V2_CANDIDATE,
            "failed_v2_tree": module.FAILED_V2_TREE,
            "failed_qualification_v2_ledger_digest": (
                module.FAILED_QUALIFICATION_V2_LEDGER_DIGEST
            ),
            "predecessor_post_v2_diagnostic_ledger_digest": (
                module.POST_V2_DIAGNOSTIC_LEDGER_DIGEST
            ),
            "predecessor_post_v2_diagnostic_bundle_digest": (
                module.POST_V2_DIAGNOSTIC_BUNDLE_DIGEST
            ),
            "candidate": "e" * 40,
            "tree": "f" * 40,
            "attempt": 1,
            "source_files_digest": "sha256:" + "1" * 64,
            "canonical_profile_digest": module.CANONICAL_PROFILE_DIGEST,
            "raw_profile_artifact_digest": module.CANONICAL_PROFILE_DIGEST,
            "base_image_digest": module.BASE_IMAGE_DIGEST,
            "max_attempts": 1,
            "allowed_phases": ["provision", "run"],
            "non_authorizing": True,
        }
        core_digest = module._digest_bytes(module._canonical(core))
        environment = {
            "contract_core_digest": core_digest,
            "source_archive_digest": "sha256:" + "2" * 64,
            "seed_digest": "sha256:" + "3" * 64,
            "package_runtime_plan_digest": "sha256:" + "4" * 64,
            "host_provenance_digest": "sha256:" + "5" * 64,
        }
        contract = {
            "contract_core": core,
            "contract_core_digest": core_digest,
            "environment_preimage": environment,
            "environment_digest": module._digest_bytes(module._canonical(environment)),
        }
        request = {
            "request_version": "2.2.0",
            "mode": "M4_PACKAGE_RUNTIME_PLAN_DISCRIMINATOR",
            "diagnostic_contract": contract,
            "diagnostic_contract_digest": module._digest_bytes(
                module._canonical(contract)
            ),
        }
        self.assertEqual(
            module._validate_launch_request(request),
            "M4_PACKAGE_RUNTIME_PLAN_DISCRIMINATOR",
        )
        for name in (
            "predecessor_post_v2_diagnostic_ledger_digest",
            "predecessor_post_v2_diagnostic_bundle_digest",
        ):
            changed = deepcopy(request)
            changed_core = changed["diagnostic_contract"]["contract_core"]
            changed_core[name] = "sha256:" + "0" * 64
            changed["diagnostic_contract"]["contract_core_digest"] = (
                module._digest_bytes(module._canonical(changed_core))
            )
            changed["diagnostic_contract"]["environment_preimage"][
                "contract_core_digest"
            ] = changed["diagnostic_contract"]["contract_core_digest"]
            changed["diagnostic_contract"]["environment_digest"] = (
                module._digest_bytes(
                    module._canonical(
                        changed["diagnostic_contract"]["environment_preimage"]
                    )
                )
            )
            changed["diagnostic_contract_digest"] = module._digest_bytes(
                module._canonical(changed["diagnostic_contract"])
            )
            with self.subTest(name=name), self.assertRaises(module.QualificationStop):
                module._validate_launch_request(changed)

        with (
            mock.patch.object(
                module, "_verify_bound_environment", return_value={"plan": True}
            ) as verify,
            self.assertRaisesRegex(
                module.QualificationStop,
                "^PACKAGE_RUNTIME_PLAN_DISCRIMINATOR_NO_FAILURE$",
            ),
        ):
            module._verify_package_plan_discriminator_environment(
                request, {}, {}, {}
            )
        self.assertIs(verify.call_args.kwargs["diagnostic_observation"], True)
        run_source = inspect.getsource(module._run_phase)
        self.assertLess(
            run_source.index("_verify_package_plan_discriminator_environment("),
            run_source.index('_diagnostic_stage("REQUEST_VALIDATED")'),
        )
        for forbidden in (
            "_complete_post_v2_diagnostic(", "_await_key_admission(",
            "_export_m4_evidence(",
        ):
            self.assertNotIn(
                forbidden,
                inspect.getsource(module._verify_package_plan_discriminator_environment),
            )

        fake_m3 = type(
            "M3",
            (),
            {
                "_require_guest": staticmethod(lambda: {}),
                "_source_identity": staticmethod(lambda: {}),
                "_host_provenance": staticmethod(lambda: {}),
            },
        )()
        with (
            mock.patch.object(module, "_diagnostic_stage"),
            mock.patch.object(module.os, "geteuid", return_value=0),
            mock.patch.object(module, "_profile", return_value={}),
            mock.patch.object(module, "_load_m3", return_value=fake_m3),
            mock.patch.object(
                module.Path,
                "read_text",
                return_value="00000000-0000-0000-0000-000000000001",
            ),
            mock.patch.object(
                module, "_read_regular", return_value=module._canonical(request)
            ),
            mock.patch.object(
                module,
                "_verify_package_plan_discriminator_environment",
                side_effect=module.QualificationStop("DISCRIMINATOR_STOP"),
            ) as discriminator,
            mock.patch.object(module, "_prepare_keys") as prepare_keys,
            mock.patch.object(module, "_await_key_admission") as admission,
            mock.patch.object(module, "_configure_m3_supply_trust") as effects,
            mock.patch.object(module, "_export_m4_evidence") as evidence,
            self.assertRaisesRegex(
                module.QualificationStop, "^DISCRIMINATOR_STOP$"
            ),
        ):
            module._run_phase()
        discriminator.assert_called_once()
        prepare_keys.assert_not_called()
        admission.assert_not_called()
        effects.assert_not_called()
        evidence.assert_not_called()

    def test_post_key_exception_reason_is_closed_fixed_and_secret_free(
        self,
    ) -> None:
        module = _module()
        host = _host_module()

        class PrivateRuntimeError(Exception):
            pass

        cases = (
            (
                json.JSONDecodeError(
                    "private token", "/private/customer/path", 0
                ),
                "JSONDECODEERROR",
            ),
            (module.sqlite3.IntegrityError("private token"), "SQLITEERROR"),
            (
                module.subprocess.CalledProcessError(
                    7, ["/private/customer/path"]
                ),
                "SUBPROCESSERROR",
            ),
            (FileNotFoundError("/private/customer/path"), "OSERROR"),
            (ValueError("private token"), "VALUEERROR"),
            (TypeError("private token"), "TYPEERROR"),
            (KeyError("private token"), "KEYERROR"),
            (AttributeError("private token"), "ATTRIBUTEERROR"),
            (PrivateRuntimeError("private token"), "EXCEPTION"),
        )
        expected_stages = (
            "ADMISSION_CONSUMPTION",
            "SUPPLY_AND_CONTROLLER_SETUP",
            "PUBLISHER_AUTHORITY_FRONTIER_SETUP",
            "RUNTIME_CONSTRUCTION",
            "COORDINATOR_EXECUTION",
            "PRE_RESTART_FINALIZATION",
        )
        self.assertEqual(module._POST_KEY_EXCEPTION_STAGES, expected_stages)
        for error, code in cases:
            with self.subTest(error=type(error).__name__):
                reason = module._post_key_exception_reason(
                    "RUNTIME_CONSTRUCTION", error
                )
                self.assertEqual(
                    reason,
                    "M4_POST_KEY_RUNTIME_CONSTRUCTION_" + code,
                )
                self.assertTrue(host._is_post_key_run_failure_reason(reason))
                self.assertNotIn("PRIVATE", reason)
                self.assertNotIn("CUSTOMER", reason)
                if isinstance(error, PrivateRuntimeError):
                    self.assertNotIn("PRIVATERUNTIMEERROR", reason)
        self.assertEqual(
            module._post_key_exception_reason(
                "UNKNOWN_STAGE", OSError("private token")
            ),
            "M4_RUNTIME_FAILURE",
        )

        staged_reason = module._post_key_exception_reason(
            "RUNTIME_CONSTRUCTION",
            OSError("private path/token"),
        )
        arguments = mock.Mock(internal_role=None, phase="run")
        stdout = mock.Mock(buffer=BytesIO())
        stderr = StringIO()
        with (
            mock.patch.object(module, "_parse_args", return_value=arguments),
            mock.patch.object(
                module,
                "_run_phase",
                side_effect=module.QualificationStop(staged_reason),
            ),
            mock.patch.object(module.sys, "stdout", stdout),
            mock.patch.object(module.sys, "stderr", stderr),
        ):
            result = module.main([])
        self.assertEqual(result, 2)
        self.assertEqual(
            stdout.buffer.getvalue(),
            module._canonical(
                {
                    "outcome": "STOP",
                    "reason": "M4_POST_KEY_RUNTIME_CONSTRUCTION_OSERROR",
                    "status": "NOT_ATTESTED",
                }
            )
            + b"\n",
        )
        self.assertEqual(stderr.getvalue(), "")
        self.assertNotIn(b"private", stdout.buffer.getvalue())
        self.assertNotIn(b"OSError", stdout.buffer.getvalue())
        self.assertNotIn(b"Traceback", stdout.buffer.getvalue())

    def test_dynamically_loaded_m3_stop_crosses_post_key_boundary_with_sanitized_reason(
        self,
    ) -> None:
        module = _module()
        with mock.patch.object(module, "M3_RUNNER", M3_RUNNER):
            real_m3 = module._load_m3()
        self.assertIsNot(real_m3.QualificationStop, module.QualificationStop)
        stages = (
            "ADMISSION_CONSUMPTION",
            "SUPPLY_AND_CONTROLLER_SETUP",
            "PUBLISHER_AUTHORITY_FRONTIER_SETUP",
            "RUNTIME_CONSTRUCTION",
            "COORDINATOR_EXECUTION",
            "PRE_RESTART_FINALIZATION",
        )

        def invoke(
            target: str, error: BaseException
        ) -> tuple[
            BaseException,
            list[str],
            mock.Mock,
            mock.Mock,
            mock.Mock,
        ]:
            calls: list[str] = []
            manager = mock.Mock()
            controller = mock.Mock()
            publisher_session = mock.Mock()
            runtime = mock.Mock(events=[])
            coordinator = mock.Mock()
            committed = object()
            frontier_bound = object()
            joined = object()
            joined_reason = object()

            def boundary(stage: str, value: object = None) -> object:
                calls.append(stage)
                if target == stage:
                    raise error
                return value

            class FinalizationResult:
                @property
                def outcome(self) -> object:
                    return boundary("PRE_RESTART_FINALIZATION")

            with tempfile.TemporaryDirectory(
                prefix="m4-post-key-stage-"
            ) as directory:
                root = Path(directory)
                runtime_root = root / "runtime"
                controller_root = root / "controller"
                evidence_root = root / "evidence"
                m3_runtime = root / "m3-runtime"
                m3_controller = root / "m3-controller"
                publication_parent = root / "publication-parent"
                publication_root = publication_parent / "publication"
                publication_root.mkdir(parents=True)
                raw_l0 = object()
                compiled_l0 = object()
                measurement = object()
                seccomp_program = b"seccomp"
                topology = object()
                bound = SimpleNamespace(
                    outcome=committed,
                    reason=frontier_bound,
                    d2_frontier_digest="sha256:" + "1" * 64,
                    frontier_record_digest="sha256:" + "2" * 64,
                    m4_iteration=1,
                    contract_digest="sha256:" + "3" * 64,
                )
                controller.bind_current_m4_frontier.return_value = bound
                durable = SimpleNamespace(
                    DurableOutcome=SimpleNamespace(COMMITTED=committed),
                    DurableReason=SimpleNamespace(D2_FRONTIER_BOUND=frontier_bound),
                )
                fake_m4 = SimpleNamespace(
                    M4Outcome=SimpleNamespace(JOINED=joined),
                    M4Reason=SimpleNamespace(JOINED=joined_reason),
                    M4Principals=mock.Mock(return_value=object()),
                    M4Coordinator=mock.Mock(return_value=coordinator),
                )
                chain = {
                    "m4_authority": {
                        "context": {
                            "topology": topology,
                            "topology_verification": {},
                        }
                    },
                    "times": {
                        "issued_at": "2026-08-28T00:00:00Z",
                        "prepare_at": "2026-08-28T00:00:00Z",
                    },
                    "claim": SimpleNamespace(
                        transaction_id="transaction",
                        claim_digest="sha256:" + "4" * 64,
                        material_digest="sha256:" + "5" * 64,
                    ),
                    "supply": SimpleNamespace(
                        expires_at="2026-08-28T01:00:00Z",
                    ),
                    "staging": {
                        "descriptor": 7,
                        "path": str(root / "staging"),
                    },
                    "content": b"content",
                }

                def start_publisher(**_kwargs: object) -> tuple[object, object]:
                    return boundary(
                        "PUBLISHER_AUTHORITY_FRONTIER_SETUP",
                        (publisher_session, object()),
                    )

                def runtime_factory(**_kwargs: object) -> object:
                    return boundary("RUNTIME_CONSTRUCTION", runtime)

                def execute(*_args: object, **_kwargs: object) -> object:
                    return boundary(
                        "COORDINATOR_EXECUTION", FinalizationResult()
                    )

                coordinator.execute.side_effect = execute
                fake_m3 = SimpleNamespace(
                    QualificationStop=real_m3.QualificationStop,
                    RUNTIME=m3_runtime,
                    CONTROLLER=m3_controller,
                    Ed25519PayloadVerifier=object,
                    _require_guest=mock.Mock(return_value={}),
                    _source_identity=mock.Mock(return_value={}),
                    _host_provenance=mock.Mock(return_value={}),
                    _load_apparmor=mock.Mock(return_value={}),
                    _verify_tools=mock.Mock(return_value={}),
                    _role_seccomp_programs=mock.Mock(
                        return_value=({"BROKER": b"broker"}, {})
                    ),
                    CgroupManager=mock.Mock(return_value=manager),
                    _authority_chain=mock.Mock(return_value=chain),
                    _transition_time=mock.Mock(
                        return_value="2026-08-28T00:00:01Z"
                    ),
                )
                request = {}
                profile = {
                    "roles": {
                        "CONTROLLER": {
                            "principal_id": "controller-principal",
                            "session_id": "controller-session",
                        },
                        "OBSERVER": {
                            "principal_id": "observer-principal",
                            "session_id": "observer-session",
                        },
                    }
                }
                contract = {"contract_core": {}}
                contract_digest = "sha256:" + "6" * 64
                captured: BaseException | None = None
                patches = (
                    mock.patch.multiple(
                        module,
                        RUNTIME=runtime_root,
                        CONTROLLER=controller_root,
                        EVIDENCE=evidence_root,
                        PUBLICATION_PARENT=publication_parent,
                        PUBLICATION_ROOT=publication_root,
                    ),
                    mock.patch.object(module.os, "geteuid", return_value=0),
                    mock.patch.object(module.os, "chown"),
                    mock.patch.object(module.os, "chmod"),
                    mock.patch.object(
                        module.Path,
                        "read_text",
                        return_value="00000000-0000-0000-0000-000000000001",
                    ),
                    mock.patch.object(module, "_diagnostic_stage"),
                    mock.patch.object(module, "_profile", return_value=profile),
                    mock.patch.object(module, "_load_m3", return_value=fake_m3),
                    mock.patch.object(module, "_read_regular", return_value=b"{}"),
                    mock.patch.object(module, "_strict_bytes", return_value=request),
                    mock.patch.object(
                        module,
                        "_validate_launch_request",
                        return_value="QUALIFICATION",
                    ),
                    mock.patch.object(
                        module,
                        "_qualification_request_contract",
                        return_value=(contract, contract_digest),
                    ),
                    mock.patch.object(
                        module,
                        "_verify_qualification_environment",
                        return_value={},
                    ),
                    mock.patch.object(module, "_load_apparmor"),
                    mock.patch.object(
                        module,
                        "_prepare_publication_root",
                        side_effect=lambda: module.os.open(
                            publication_root,
                            module.os.O_RDONLY | module.os.O_DIRECTORY,
                        ),
                    ),
                    mock.patch.object(module, "_prepare_keys", return_value={}),
                    mock.patch.object(module, "_prepare_supply_key", return_value={}),
                    mock.patch.object(module, "_write_runtime_trust", return_value={}),
                    mock.patch.object(
                        module,
                        "_await_key_admission",
                        side_effect=lambda *_args: boundary(
                            "ADMISSION_CONSUMPTION", {}
                        ),
                    ),
                    mock.patch.object(
                        module,
                        "_configure_m3_supply_trust",
                        side_effect=lambda *_args: boundary(
                            "SUPPLY_AND_CONTROLLER_SETUP",
                            (
                                raw_l0,
                                compiled_l0,
                                measurement,
                                seccomp_program,
                            ),
                        ),
                    ),
                    mock.patch.object(
                        module,
                        "_m4_role_seccomp_programs",
                        return_value={
                            "PUBLISHER": b"publisher",
                            "EXECUTOR": b"executor",
                            "OBSERVER": b"observer",
                        },
                    ),
                    mock.patch.object(
                        module, "ControllerSession", return_value=controller
                    ),
                    mock.patch.object(
                        module,
                        "_start_publisher_session",
                        side_effect=start_publisher,
                    ),
                    mock.patch.object(
                        module, "_m4_authority_builder", return_value=object()
                    ),
                    mock.patch.object(
                        module,
                        "_load_project",
                        return_value=(durable, None, fake_m4, None, None),
                    ),
                    mock.patch.object(
                        module, "M4GuestRuntime", side_effect=runtime_factory
                    ),
                    mock.patch.object(
                        module, "ConfiguredVerifierRouter", return_value=object()
                    ),
                )
                with ExitStack() as stack:
                    for patcher in patches:
                        stack.enter_context(patcher)
                    try:
                        module._run_phase()
                    except BaseException as caught:
                        captured = caught
                if captured is None:
                    self.fail("post-key boundary did not stop")
                return captured, calls, manager, controller, publisher_session

        for index, stage in enumerate(stages):
            private_error = OSError("private path/token")
            error, calls, manager, controller, publisher = invoke(
                stage, private_error
            )
            with self.subTest(stage=stage):
                self.assertIsInstance(error, module.QualificationStop)
                self.assertEqual(
                    str(error), "M4_POST_KEY_" + stage + "_OSERROR"
                )
                self.assertEqual(calls, list(stages[: index + 1]))
                if index >= 2:
                    manager.cleanup.assert_called_once_with()
                    controller.close.assert_called_once_with()
                if index >= 3:
                    publisher.close.assert_called_once_with()

        generic_error, _, manager, controller, publisher = invoke(
            "RUNTIME_CONSTRUCTION", RuntimeError("/private/generic")
        )
        self.assertEqual(
            str(generic_error),
            "M4_POST_KEY_RUNTIME_CONSTRUCTION_EXCEPTION",
        )
        self.assertNotIn("/private/generic", str(generic_error))
        manager.cleanup.assert_called_once_with()
        controller.close.assert_called_once_with()
        publisher.close.assert_called_once_with()

        typed = module.QualificationStop("M4_RUNTIME_JOIN_FAILED")
        error, _, manager, controller, publisher = invoke(
            "RUNTIME_CONSTRUCTION", typed
        )
        self.assertIs(error, typed)
        manager.cleanup.assert_called_once_with()
        controller.close.assert_called_once_with()
        publisher.close.assert_called_once_with()
        for base_error in (SystemExit(7), KeyboardInterrupt()):
            error, _, manager, controller, publisher = invoke(
                "RUNTIME_CONSTRUCTION", base_error
            )
            with self.subTest(base_error=type(base_error).__name__):
                self.assertIs(error, base_error)
                manager.cleanup.assert_called_once_with()
                controller.close.assert_called_once_with()
                publisher.close.assert_called_once_with()

        arguments = mock.Mock(internal_role=None, phase="run")
        m3_cases = (
            (
                real_m3.QualificationStop("GUEST_MARKER_MISMATCH"),
                "RUNTIME_CONSTRUCTION",
                "GUEST_MARKER_MISMATCH",
                (),
            ),
            (
                real_m3.QualificationStop("COMMAND_FAILED:bwrap"),
                "SUPPLY_AND_CONTROLLER_SETUP",
                "M4_POST_KEY_SUPPLY_AND_CONTROLLER_SETUP_EXCEPTION",
                (b"COMMAND_FAILED", b"bwrap"),
            ),
            (
                real_m3.QualificationStop(
                    "FD_INVENTORY_MISMATCH:0,1,2,3:/private/payload"
                ),
                "PUBLISHER_AUTHORITY_FRONTIER_SETUP",
                "M4_POST_KEY_PUBLISHER_AUTHORITY_FRONTIER_SETUP_EXCEPTION",
                (b"FD_INVENTORY_MISMATCH", b"/private/payload"),
            ),
            (
                real_m3.QualificationStop(),
                "ADMISSION_CONSUMPTION",
                "M4_POST_KEY_ADMISSION_CONSUMPTION_EXCEPTION",
                (),
            ),
            (
                real_m3.QualificationStop("GUEST_MARKER_MISMATCH", "extra"),
                "COORDINATOR_EXECUTION",
                "M4_POST_KEY_COORDINATOR_EXECUTION_EXCEPTION",
                (b"GUEST_MARKER_MISMATCH", b"extra"),
            ),
        )
        for m3_error, stage, expected_reason, forbidden in m3_cases:
            error, _, manager, controller, publisher = invoke(
                stage, m3_error
            )
            with self.subTest(stage=stage, m3_reason=m3_error.args):
                self.assertIsInstance(error, module.QualificationStop)
                self.assertEqual(str(error), expected_reason)
                stage_index = stages.index(stage)
                if stage_index >= 2:
                    manager.cleanup.assert_called_once_with()
                    controller.close.assert_called_once_with()
                if stage_index >= 3:
                    publisher.close.assert_called_once_with()

                stdout = mock.Mock(buffer=BytesIO())
                stderr = StringIO()
                with (
                    mock.patch.object(
                        module, "_parse_args", return_value=arguments
                    ),
                    mock.patch.object(module, "_run_phase", side_effect=error),
                    mock.patch.object(module.sys, "stdout", stdout),
                    mock.patch.object(module.sys, "stderr", stderr),
                ):
                    self.assertEqual(module.main([]), 2)
                self.assertEqual(
                    stdout.buffer.getvalue(),
                    module._canonical(
                        {
                            "outcome": "STOP",
                            "reason": expected_reason,
                            "status": "NOT_ATTESTED",
                        }
                    )
                    + b"\n",
                )
                self.assertEqual(stderr.getvalue(), "")
                for raw_fragment in forbidden:
                    self.assertNotIn(raw_fragment, stdout.buffer.getvalue())
                self.assertNotIn(b"Traceback", stdout.buffer.getvalue())

    def test_guest_stop_reason_boundary_is_total_closed_and_host_parseable(
        self,
    ) -> None:
        module = _module()
        host = _host_module()
        arguments = mock.Mock(internal_role=None, phase="run")

        def invoke(error: BaseException) -> tuple[int, bytes, str]:
            stdout = mock.Mock(buffer=BytesIO())
            stderr = StringIO()
            with (
                mock.patch.object(module, "_parse_args", return_value=arguments),
                mock.patch.object(module, "_run_phase", side_effect=error),
                mock.patch.object(module.sys, "stdout", stdout),
                mock.patch.object(module.sys, "stderr", stderr),
            ):
                result = module.main([])
            return result, stdout.buffer.getvalue(), stderr.getvalue()

        result, raw, stderr = invoke(
            TypeError("private-value:/outside/guest/root")
        )
        self.assertEqual(result, 2)
        self.assertEqual(
            raw,
            module._canonical(
                {
                    "outcome": "STOP",
                    "reason": "M4_UNHANDLED_EXCEPTION",
                    "status": "NOT_ATTESTED",
                }
            )
            + b"\n",
        )
        self.assertEqual(stderr, "")
        self.assertNotIn(b"private-value", raw)
        self.assertNotIn(b"Traceback", raw)

        for reason in (
            "PUBLISHER_TOPOLOGY_MISMATCH",
            "ROLE_ENVELOPE_MISMATCH_PUBLISHER",
        ):
            result, raw, stderr = invoke(module.QualificationStop(reason))
            with self.subTest(valid_reason=reason):
                self.assertEqual(result, 2)
                self.assertEqual(
                    raw,
                    module._canonical(
                        {
                            "outcome": "STOP",
                            "reason": reason,
                            "status": "NOT_ATTESTED",
                        }
                    )
                    + b"\n",
                )
                self.assertEqual(stderr, "")
                self.assertEqual(module._sanitize_stop_reason(reason), reason)
                self.assertTrue(host._is_post_key_run_failure_reason(reason))

        invalid_reasons = (
            None,
            7,
            "",
            "lowercase",
            "ROLE_ENVELOPE_MISMATCH:PUBLISHER",
            "/private/path",
            "CONTROL\nVALUE",
            "UNICODE_Я",
            "A" * 129,
        )
        for reason in invalid_reasons:
            with (
                self.subTest(invalid_reason=repr(reason)),
                self.assertRaisesRegex(
                    module.QualificationStop, "^M4_RUNTIME_FAILURE$"
                ),
            ):
                module._stop(reason)
            result, raw, stderr = invoke(module.QualificationStop(reason))
            self.assertEqual(result, 2)
            self.assertEqual(
                raw,
                module._canonical(
                    {
                        "outcome": "STOP",
                        "reason": "M4_RUNTIME_FAILURE",
                        "status": "NOT_ATTESTED",
                    }
                )
                + b"\n",
            )
            self.assertEqual(stderr, "")
            if type(reason) is str and reason:
                self.assertNotIn(reason.encode("utf-8"), raw)

        for error in (SystemExit(7), KeyboardInterrupt()):
            stdout = mock.Mock(buffer=BytesIO())
            with (
                self.subTest(error=type(error).__name__),
                mock.patch.object(module, "_parse_args", return_value=arguments),
                mock.patch.object(module, "_run_phase", side_effect=error),
                mock.patch.object(module.sys, "stdout", stdout),
                self.assertRaises(type(error)),
            ):
                module.main([])
            self.assertEqual(stdout.buffer.getvalue(), b"")

    def test_dynamic_role_and_l0_stop_reasons_are_host_parseable(self) -> None:
        module = _module()
        host = _host_module()

        with (
            mock.patch.object(module.time, "monotonic", side_effect=(0.0, 4.0)),
            self.assertRaises(module.QualificationStop) as role_stop,
        ):
            module._observe_role(1234, "PUBLISHER", Path("/unused"), [])
        self.assertEqual(
            str(role_stop.exception), "ROLE_ENVELOPE_MISMATCH_PUBLISHER"
        )
        self.assertTrue(
            host._is_post_key_run_failure_reason(str(role_stop.exception))
        )

        class FakeL0Reason(str, Enum):
            HOST_FAILURE = "HOST_FAILURE"

        compiled_outcome = object()
        ready_outcome = object()
        failed_outcome = object()
        preflight_reason: object = FakeL0Reason.HOST_FAILURE
        l0 = SimpleNamespace(
            L0Outcome=SimpleNamespace(
                COMPILED_DRAFT=compiled_outcome, READY=ready_outcome
            ),
            L0Reason=FakeL0Reason,
            compile_profile=lambda value: SimpleNamespace(
                outcome=compiled_outcome, profile=value
            ),
            host_preflight=lambda _value: SimpleNamespace(
                outcome=failed_outcome,
                measurement=None,
                reason=preflight_reason,
            ),
        )
        supply = {
            "directory": "/tmp/attestor",
            "private_key": "/tmp/private.pem",
            "public_key": "/tmp/public.pem",
            "state": "/tmp/state.json",
            "public_key_digest": "sha256:" + "1" * 64,
            "trust_root_id": "test-root",
            "signer_id": "test-signer",
            "key_id": "test-key",
        }
        profile = {
            "measurement_bindings": {
                "verifier_public_key_digest": "sha256:" + "0" * 64
            }
        }

        def configure() -> None:
            with (
                mock.patch.object(module, "_read_regular", return_value=b"{}"),
                mock.patch.object(module, "_strict_bytes", return_value=profile),
                mock.patch.object(
                    module, "_digest_file", return_value="sha256:" + "2" * 64
                ),
                mock.patch.object(
                    module,
                    "_load_project",
                    return_value=(None, l0, None, None, None),
                ),
            ):
                module._configure_m3_supply_trust(SimpleNamespace(), supply)

        with self.assertRaises(module.QualificationStop) as l0_stop:
            configure()
        self.assertEqual(
            str(l0_stop.exception),
            "L0_DYNAMIC_HOST_PREFLIGHT_FAILED_HOST_FAILURE",
        )
        self.assertTrue(
            host._is_post_key_run_failure_reason(str(l0_stop.exception))
        )

        preflight_reason = SimpleNamespace(value="ARBITRARY_BUT_GRAMMAR_SAFE")
        with self.assertRaises(module.QualificationStop) as untrusted_stop:
            configure()
        self.assertEqual(
            str(untrusted_stop.exception), "M4_RUNTIME_FAILURE"
        )


if __name__ == "__main__":
    unittest.main()
