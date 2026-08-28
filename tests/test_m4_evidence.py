from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "scripts/check_m4_runtime_evidence.py"
PROFILE = ROOT / "profiles/m4-lx-a.json"


def _module():
    specification = importlib.util.spec_from_file_location(
        "harness_m4_runtime_evidence", CHECKER
    )
    if specification is None or specification.loader is None:
        raise AssertionError("M4 evidence verifier unavailable")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _digest_bytes(value: bytes) -> str:
    return "sha256:" + sha256(value).hexdigest()


class M4RuntimeEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="harness-m4-evidence-test-")
        self.root = Path(self.temporary.name)
        self.module = _module()
        self.module.IMAGE_LAB = self.root / "host-assets"
        self.module.IMAGE_LAB.mkdir(mode=0o700)
        for name in set(self.module._PACKAGE_SOURCE_ASSETS.values()) | set(
            self.module._RUNTIME_CONFIG_ASSETS.values()
        ):
            (self.module.IMAGE_LAB / name).write_bytes((name + "\n").encode("utf-8"))
        self.now = datetime(2026, 8, 27, 12, 0, 0, tzinfo=UTC)
        self.observed_at = "2026-08-27T11:59:00Z"
        self.expires_at = "2026-08-27T12:30:00Z"
        self.fixture_index = 0
        self.keys = {
            role: self._key(role.lower().replace("_", "-"))
            for role in ("M4_AUTHORITY", "OBSERVER", "PUBLISHER", "SUPPLY")
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_checker_requires_v2_embedded_ledger_bundle_surface(self) -> None:
        self.assertEqual(
            self.module._BUNDLE_FILES,
            frozenset({
                "manifest.json",
                "manifest.sig",
                "evidence.json",
                "attempt-ledger.jsonl",
            }),
        )
        self.assertEqual(
            self.module.M4_LAB,
            Path("/home/a1/Загрузки/harness/harness-m4-qualification-v2"),
        )

    def test_one_use_bundle_requires_external_scope_and_single_attempt_ledger(self) -> None:
        def load(name: str, path: Path):
            specification = importlib.util.spec_from_file_location(name, path)
            self.assertIsNotNone(specification)
            self.assertIsNotNone(specification.loader)
            value = importlib.util.module_from_spec(specification)
            specification.loader.exec_module(value)
            return value

        host = load(
            "harness_m4_one_use_host",
            ROOT / "scripts/run_m4_host_qualification.py",
        )
        guest = load(
            "harness_m4_one_use_guest",
            ROOT / "scripts/run_m4_vm_conformance.py",
        )
        source = self._source()
        projection = {
            "record_version": "1.0.0",
            "record_kind": "M4_ONE_USE_QUALIFICATION_SCOPE_PROJECTION",
            "authority": "NONE",
            "user_scope_reference": (
                "thread:/goal/m4-one-use-qualification-contract/2026-08-28"
            ),
            "candidate": source["commit"],
            "tree": source["tree"],
            "max_attempts": 1,
            "success_target": 1,
            "success_target_authorizing": False,
            "predecessor_qualification_ledger_digest": (
                self.module._ONE_USE_PREDECESSOR_QUALIFICATION_LEDGER_DIGEST
            ),
            "predecessor_diagnostic_ledger_digest": (
                self.module._ONE_USE_PREDECESSOR_DIAGNOSTIC_LEDGER_DIGEST
            ),
            "predecessor_diagnostic_bundle_digest": (
                self.module._ONE_USE_PREDECESSOR_DIAGNOSTIC_BUNDLE_DIGEST
            ),
        }
        scope_path = self.root / "one-use-scope.json"
        scope_path.write_bytes(_canonical(projection))
        os.chmod(scope_path, 0o444)
        checked_scope, scope_digest = self.module._read_one_use_scope_projection(
            scope_path
        )
        self.assertEqual(checked_scope, projection)
        self.module.ONE_USE_QUALIFICATION_ROOT = self.root / "one-use-labs"
        self.module.ONE_USE_EVIDENCE_ROOT = self.root / "one-use-evidence"
        lab, evidence_root = self.module._one_use_paths(scope_digest)
        self.module.M4_LAB = lab

        bundle, _ledger, fixture_source, _goal_reference, _goal_digest = (
            self._fixture()
        )
        manifest = json.loads(
            (bundle / "manifest.json").read_text(encoding="utf-8")
        )
        old_contract = manifest["qualification_contract"]
        old_environment = old_contract["environment_preimage"]
        contract = host._one_use_qualification_contract(
            projection=projection,
            projection_digest=scope_digest,
            source_files_digest=fixture_source["files_digest"],
            source_archive_digest=old_environment["source_archive_digest"],
            seed_digest=old_environment["seed_digest"],
            package_runtime_plan_digest=old_environment[
                "package_runtime_plan_digest"
            ],
            host_provenance_digest=old_environment["host_provenance_digest"],
        )
        request = {
            "request_version": "3.0.0",
            "qualification_contract": contract,
            "qualification_contract_digest": _digest_bytes(_canonical(contract)),
        }
        self.assertEqual(
            guest._one_use_qualification_request_contract(request),
            (contract, request["qualification_contract_digest"]),
        )

        def install_one_use(core, environment, _source, _plan):
            core.clear()
            core.update(deepcopy(contract["contract_core"]))
            environment.clear()
            environment.update(deepcopy(contract["environment_preimage"]))

        self._rewrite_contract_bundle(
            bundle,
            install_one_use,
            ledger_version="3.0.0",
            admission_version="3.0.0",
        )
        expected_bundle = evidence_root / "attempt-1" / "bundle"
        expected_bundle.parent.mkdir(parents=True, mode=0o700)
        bundle.rename(expected_bundle)
        result = self.module._verify_bundle(
            expected_bundle,
            source_state=fixture_source,
            now=self.now,
            mode=self.module._ONE_USE_MODE,
            one_use_scope=scope_path,
        )
        self.assertEqual((result["outcome"], result["attempt"]), ("VERIFIED", 1))

        wrong_bundle = self.root / "wrong-bundle"
        expected_bundle.rename(wrong_bundle)
        with self.assertRaises(self.module._InvalidEvidence):
            self.module._verify_bundle(
                wrong_bundle,
                source_state=fixture_source,
                now=self.now,
                mode=self.module._ONE_USE_MODE,
                one_use_scope=scope_path,
            )
        wrong_bundle.rename(expected_bundle)

        with self.assertRaises(self.module._InvalidEvidence):
            self.module._verify_bundle(
                expected_bundle,
                source_state=fixture_source,
                now=self.now,
            )
        changed_scope = self.root / "changed-scope.json"
        changed = {**projection, "user_scope_reference": "thread:/different"}
        changed_scope.write_bytes(_canonical(changed))
        os.chmod(changed_scope, 0o444)
        with self.assertRaises(self.module._InvalidEvidence):
            self.module._verify_bundle(
                expected_bundle,
                source_state=fixture_source,
                now=self.now,
                mode=self.module._ONE_USE_MODE,
                one_use_scope=changed_scope,
            )
        ledger = expected_bundle / "attempt-ledger.jsonl"
        original_ledger = ledger.read_bytes()
        rows = original_ledger.splitlines()
        mutations = {
            "extension": original_ledger + b"{}\n",
            "truncation": b"\n".join(rows[:-1]) + b"\n",
            "replacement": rows[0] + b"\n{}\n" + rows[2] + b"\n",
        }
        changed_terminal = json.loads(rows[-1])
        changed_terminal["qemu_phase_outcomes"]["run"]["argv_digest"] = (
            "sha256:" + "0" * 64
        )
        mutations["qemu-argv"] = (
            b"\n".join(rows[:-1]) + b"\n" + _canonical(changed_terminal) + b"\n"
        )
        for name, raw in mutations.items():
            os.chmod(ledger, 0o600)
            ledger.write_bytes(raw)
            os.chmod(ledger, 0o444)
            with self.subTest(name=name), self.assertRaises(
                self.module._InvalidEvidence
            ):
                self.module._verify_bundle(
                    expected_bundle,
                    source_state=fixture_source,
                    now=self.now,
                    mode=self.module._ONE_USE_MODE,
                    one_use_scope=scope_path,
                )
        os.chmod(ledger, 0o600)
        ledger.write_bytes(original_ledger)
        os.chmod(ledger, 0o444)

        v2_bundle, _v2_ledger, v2_source, _, _ = self._fixture()
        second_scope = self.root / "second-scope.json"
        second_projection = {
            **projection,
            "user_scope_reference": "thread:/goal/second-one-use-scope",
        }
        second_scope.write_bytes(_canonical(second_projection))
        os.chmod(second_scope, 0o444)
        _, second_digest = self.module._read_one_use_scope_projection(second_scope)
        _, second_evidence = self.module._one_use_paths(second_digest)
        second_expected = second_evidence / "attempt-1" / "bundle"
        second_expected.parent.mkdir(parents=True, mode=0o700)
        v2_bundle.rename(second_expected)
        with self.assertRaises(self.module._InvalidEvidence):
            self.module._verify_bundle(
                second_expected,
                source_state=v2_source,
                now=self.now,
                mode=self.module._ONE_USE_MODE,
                one_use_scope=second_scope,
            )

    def test_post_key_run_failure_record_is_closed_ordered_and_bound(self) -> None:
        _bundle, ledger, _source, goal_reference, goal_digest = self._fixture()
        started, admitted, terminal = [
            json.loads(line) for line in ledger.read_bytes().splitlines()
        ]
        start_digest = _digest_bytes(_canonical(started))
        admission_digest = _digest_bytes(_canonical(admitted))
        common = {
            name: admitted[name]
            for name in self.module._LEDGER_COMMON
        }

        def rows(
            *,
            reason: str = "M4_RUNTIME_JOIN_FAILED",
            stage: str = "POST_KEY_RUN_SERVICE_FAILED",
            attempt_start_digest: str = start_digest,
            key_admission_digest: str = admission_digest,
            terminal_reason: str = "RUN_FAILED",
            extra: dict[str, object] | None = None,
        ) -> list[dict[str, object]]:
            failure = {
                **common,
                "sequence": 3,
                "previous_entry_digest": admission_digest,
                "entry_type": "POST_KEY_RUN_FAILURE",
                "attempt_start_digest": attempt_start_digest,
                "key_admission_digest": key_admission_digest,
                "failure_stage": stage,
                "reason": reason,
                **({} if extra is None else extra),
            }
            failed_terminal = {
                **terminal,
                "sequence": 4,
                "previous_entry_digest": _digest_bytes(_canonical(failure)),
                "result": "QUARANTINED",
                "terminal_reason": terminal_reason,
                "manifest_digest": None,
                "signed_payload_bundle_digest": None,
                "qemu_phase_outcomes": None,
            }
            return [deepcopy(started), deepcopy(admitted), failure, failed_terminal]

        def parse(value: list[dict[str, object]]) -> list[tuple[dict[str, object], str]]:
            return self.module._ledger_entries(
                b"".join(_canonical(row) + b"\n" for row in value),
                now=self.now,
                goal_reference=goal_reference,
                goal_digest=goal_digest,
            )

        accepted = parse(rows())
        self.assertEqual(
            [row["entry_type"] for row, _digest in accepted],
            [
                "ATTEMPT_STARTED",
                "KEY_ADMITTED",
                "POST_KEY_RUN_FAILURE",
                "ATTEMPT_TERMINAL",
            ],
        )
        self.assertEqual(accepted[2][0]["reason"], "M4_RUNTIME_JOIN_FAILED")
        self.assertEqual(parse(rows(reason="UNAVAILABLE"))[2][0]["reason"], "UNAVAILABLE")
        self.assertEqual(
            parse(rows(terminal_reason="CLEANUP_FAILED"))[-1][0]["terminal_reason"],
            "CLEANUP_FAILED",
        )

        projection = {
            "record_version": "1.0.0",
            "record_kind": "M4_ONE_USE_QUALIFICATION_SCOPE_PROJECTION",
            "authority": "NONE",
            "user_scope_reference": "thread:/goal/post-key-run-failure",
            "candidate": started["candidate"],
            "tree": started["tree"],
            "max_attempts": 1,
            "success_target": 1,
            "success_target_authorizing": False,
            "predecessor_qualification_ledger_digest": (
                self.module._ONE_USE_PREDECESSOR_QUALIFICATION_LEDGER_DIGEST
            ),
            "predecessor_diagnostic_ledger_digest": (
                self.module._ONE_USE_PREDECESSOR_DIAGNOSTIC_LEDGER_DIGEST
            ),
            "predecessor_diagnostic_bundle_digest": (
                self.module._ONE_USE_PREDECESSOR_DIAGNOSTIC_BUNDLE_DIGEST
            ),
        }
        one_use = rows()
        contract = deepcopy(started["qualification_contract"])
        core = contract["contract_core"]
        core.update(
            contract_version="3.0.0",
            contract_kind=self.module._ONE_USE_QUALIFICATION_CONTRACT_KIND,
            scope_projection=projection,
            user_scope_reference=projection["user_scope_reference"],
            user_goal_digest=_digest_bytes(_canonical(projection)),
            max_attempts=1,
            predecessor_qualification_ledger_digest=(
                projection["predecessor_qualification_ledger_digest"]
            ),
            predecessor_diagnostic_ledger_digest=(
                projection["predecessor_diagnostic_ledger_digest"]
            ),
            predecessor_diagnostic_bundle_digest=(
                projection["predecessor_diagnostic_bundle_digest"]
            ),
        )
        core_digest = _digest_bytes(_canonical(core))
        contract["contract_core_digest"] = core_digest
        contract["environment_preimage"]["contract_core_digest"] = core_digest
        environment = _digest_bytes(_canonical(contract["environment_preimage"]))
        contract["environment_digest"] = environment
        contract_digest = _digest_bytes(_canonical(contract))
        for row in one_use:
            row.update(
                ledger_version="3.0.0",
                environment=environment,
                user_scope_reference=projection["user_scope_reference"],
                user_goal_digest=core["user_goal_digest"],
                max_attempts=1,
                contract_core_digest=core_digest,
                qualification_contract_digest=contract_digest,
            )
        one_use[0]["qualification_contract"] = contract
        one_use_start_digest = _digest_bytes(_canonical(one_use[0]))
        one_use[1].update(
            previous_entry_digest=one_use_start_digest,
            attempt_start_digest=one_use_start_digest,
            admitted_qualification_contract_digest=contract_digest,
        )
        one_use_key_digest = _digest_bytes(_canonical(one_use[1]))
        one_use[2].update(
            previous_entry_digest=one_use_key_digest,
            attempt_start_digest=one_use_start_digest,
            key_admission_digest=one_use_key_digest,
        )
        one_use[3].update(
            previous_entry_digest=_digest_bytes(_canonical(one_use[2])),
            attempt_start_digest=one_use_start_digest,
            key_admission_digest=one_use_key_digest,
        )
        checked_one_use = self.module._ledger_entries(
            b"".join(_canonical(row) + b"\n" for row in one_use),
            now=self.now,
            goal_reference=str(projection["user_scope_reference"]),
            goal_digest=str(core["user_goal_digest"]),
            mode=self.module._ONE_USE_MODE,
            one_use_scope=projection,
            lab=self.root / "one-use-lab",
        )
        self.assertEqual(len(checked_one_use), 4)

        mutations = {
            "extra-field": rows(extra={"journal": "forbidden"}),
            "attempt-start-digest": rows(
                attempt_start_digest="sha256:" + "0" * 64
            ),
            "key-admission-digest": rows(
                key_admission_digest="sha256:" + "0" * 64
            ),
            "environment-binding": rows(
                extra={"environment": "sha256:" + "0" * 64}
            ),
            "wrong-stage": rows(stage="PRE_KEY_RUN_SERVICE_FAILED"),
            "malformed-stage": rows(stage=["POST_KEY_RUN_SERVICE_FAILED"]),
            "forged-reason": rows(reason="FORGED_REASON"),
            "malformed-reason": rows(reason={"reason": "M4_RUNTIME_JOIN_FAILED"}),
            "wrong-terminal-reason": rows(
                terminal_reason="EVIDENCE_EXPORT_FAILED"
            ),
        }
        wrong_order = rows()
        wrong_order[2], wrong_order[3] = wrong_order[3], wrong_order[2]
        for sequence, row in enumerate(wrong_order, 1):
            row["sequence"] = sequence
            row["previous_entry_digest"] = (
                None
                if sequence == 1
                else _digest_bytes(_canonical(wrong_order[sequence - 2]))
            )
        mutations["wrong-order"] = wrong_order
        for name, value in mutations.items():
            with self.subTest(name=name), self.assertRaises(
                self.module._InvalidEvidence
            ):
                parse(value)

    def _key(self, name: str) -> dict[str, object]:
        directory = self.root / name
        directory.mkdir(mode=0o700)
        private = directory / "private.pem"
        public = directory / "public.pem"
        for argv in (
            ["/usr/bin/openssl", "genpkey", "-algorithm", "ED25519", "-out", str(private)],
            ["/usr/bin/openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)],
        ):
            result = subprocess.run(
                argv,
                shell=False,
                close_fds=True,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={"LC_ALL": "C"},
                timeout=10,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", "replace"))
        os.chmod(private, 0o600)
        os.chmod(public, 0o600)
        raw = public.read_bytes()
        return {
            "private": private,
            "public": public,
            "pem": raw.decode("ascii"),
            "digest": _digest_bytes(raw),
        }

    def _signature(self, role: str, value: dict[str, object]) -> bytes:
        payload = self.root / (role.lower() + "-payload.json")
        signature = self.root / (role.lower() + "-signature.bin")
        payload.write_bytes(_canonical(value))
        result = subprocess.run(
            [
                "/usr/bin/openssl", "pkeyutl", "-sign", "-inkey",
                str(self.keys[role]["private"]), "-rawin", "-in", str(payload),
                "-out", str(signature),
            ],
            shell=False,
            close_fds=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"LC_ALL": "C"},
            timeout=10,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", "replace"))
        return signature.read_bytes()

    def _source(self) -> dict[str, object]:
        files = {
            "profiles/m4-lx-a.json": _digest_bytes(PROFILE.read_bytes()),
        }
        return {
            "commit": "b" * 40,
            "tree": "c" * 40,
            "files": files,
            "files_digest": _digest_bytes(_canonical(files)),
        }

    def _host_provenance(
        self,
        digest: str,
        attempt: int,
        *,
        lab: Path | None = None,
        max_attempts: int = 2,
    ) -> dict[str, object]:
        return {
            "image": {
                "source_url": self.module._IMAGE_URL,
                "resolved_url": self.module._IMAGE_URL,
                "release_id": "20260814",
                "filename": "ubuntu-24.04-server-cloudimg-amd64.img",
                "bytes": 624447488,
                "sha256": self.module._IMAGE_DIGEST,
                "sums_sha256": self.module._SUMS_DIGEST,
                "sums_signature_sha256": self.module._SUMS_SIGNATURE_DIGEST,
                "signer_fingerprint": self.module._UBUNTU_SIGNER,
            },
            "vm": {
                "qemu_path": "/usr/bin/qemu-system-x86_64",
                "qemu_version": "QEMU emulator version 8.2.2 (fixture)",
                "qemu_digest": self.module._QEMU_DIGEST,
                "machine": "q35",
                "kvm_api": 12,
                "vcpus": 2,
                "memory_bytes": 2147483648,
                "overlay_virtual_bytes": 3758096384,
                "seed_digest": digest,
                "management_address": "127.0.0.1:22227",
                "shared_host_mounts": 0,
                "qemu_argv_digest": _digest_bytes(
                    _canonical(
                        self.module._qemu_lifecycle(
                            attempt,
                            lab=self.module.M4_LAB if lab is None else lab,
                            max_attempts=max_attempts,
                        )
                    )
                ),
            },
        }

    def _package_runtime_plan(self) -> dict[str, object]:
        return self.module._expected_package_runtime_plan()

    def _role_facts(self, profile: dict[str, object], role: str) -> dict[str, object]:
        expected = profile["roles"][role]
        if role == "CONTROLLER":
            return {
                "role": role,
                "uid": expected["uid"],
                "gid": expected["gid"],
                "label": expected["security_label"],
                "fd_inventory": expected["fd_allowlist"],
                "cgroup": "/harness/" + expected["cgroup"],
            }
        return {
            "role": role,
            "launcher_uid": expected["uid"],
            "launcher_gid": expected["gid"],
            "label": expected["security_label"],
            "fd_inventory": expected["fd_allowlist"],
            "cgroup": "/harness/" + expected["cgroup"],
        }

    def _verification_source(
        self, profile: dict[str, object], role: str, payload: dict[str, object]
    ) -> dict[str, object]:
        route = profile["receipt_keys"][role]
        return {
            "verifier_id": "harness-m4-openssl-libcrypto/v1",
            "issuer_id": route["issuer_id"],
            "key_id": route["key_id"],
            "proof": "ed25519:" + self._signature(role, payload).hex(),
        }

    def _verification_record(
        self, profile: dict[str, object], role: str, payload: dict[str, object]
    ) -> dict[str, object]:
        source = self._verification_source(profile, role, payload)
        return {
            "verification_version": 1,
            "verifier_id": source["verifier_id"],
            "issuer_id": source["issuer_id"],
            "key_id": source["key_id"],
            "payload_digest": _digest_bytes(_canonical(payload)),
            "bindings": payload,
            "proof": source["proof"],
        }

    def _ledger_row(
        self,
        *,
        sequence: int,
        previous: str | None,
        entry_type: str,
        candidate: str,
        tree: str,
        environment: str,
        attempt: int,
        goal_reference: str,
        goal_digest: str,
        contract_core_digest: str,
        qualification_contract_digest: str,
        extra: dict[str, object] | None = None,
        ledger_version: str = "2.0.0",
        max_attempts: int = 2,
    ) -> dict[str, object]:
        return {
            "ledger_version": ledger_version,
            "sequence": sequence,
            "previous_entry_digest": previous,
            "entry_type": entry_type,
            "recorded_at": self.observed_at,
            "candidate": candidate,
            "tree": tree,
            "environment": environment,
            "user_scope_reference": goal_reference,
            "user_goal_digest": goal_digest,
            "max_attempts": max_attempts,
            "success_target": 1,
            "success_target_authorizing": False,
            "attempt": attempt,
            "contract_core_digest": contract_core_digest,
            "qualification_contract_digest": qualification_contract_digest,
            **({} if extra is None else extra),
        }

    def _fixture(
        self,
        *,
        attempt: int = 1,
        prior_result: str | None = None,
        repeat_candidate_environment: bool = False,
    ) -> tuple[Path, Path, dict[str, object], str, str]:
        if attempt not in {1, 2} or (attempt == 1) != (prior_result is None):
            raise AssertionError("invalid synthetic attempt history")
        self.fixture_index += 1
        workspace = self.root / f"case-{self.fixture_index}"
        workspace.mkdir(mode=0o700)
        profile = json.loads(PROFILE.read_text(encoding="utf-8"))
        digest = "sha256:" + "a" * 64
        source = self._source()
        goal_reference = "/tmp/authorized-m4-goal.md"
        goal_digest = _digest_bytes(b"authorized M4 test goal\n")
        host_provenance = self._host_provenance(digest, attempt)
        package_runtime_plan = self._package_runtime_plan()
        profile_digest = _digest_bytes(PROFILE.read_bytes())
        contract_core = {
            "contract_version": "2.0.0",
            "contract_kind": "M4_EXACT_DISPOSABLE_TEST_PROFILE_QUALIFICATION_V2",
            "user_scope_reference": goal_reference,
            "user_goal_digest": goal_digest,
            "candidate": source["commit"],
            "tree": source["tree"],
            "attempt": attempt,
            "source_files_digest": source["files_digest"],
            "canonical_profile_digest": profile_digest,
            "raw_profile_artifact_digest": profile_digest,
            "base_image_digest": self.module._IMAGE_DIGEST,
            "predecessor_qualification_ledger_digest": (
                self.module._PREDECESSOR_QUALIFICATION_LEDGER_DIGEST
            ),
            "predecessor_diagnostic_ledger_digest": (
                self.module._PREDECESSOR_DIAGNOSTIC_LEDGER_DIGEST
            ),
            "predecessor_diagnostic_bundle_digest": (
                self.module._PREDECESSOR_DIAGNOSTIC_BUNDLE_DIGEST
            ),
            "max_attempts": 2,
            "success_target": 1,
            "success_target_authorizing": False,
        }
        contract_core_digest = _digest_bytes(_canonical(contract_core))
        environment_preimage = {
            "contract_core_digest": contract_core_digest,
            "source_archive_digest": self.module._source_archive_digest(),
            "seed_digest": host_provenance["vm"]["seed_digest"],
            "package_runtime_plan_digest": _digest_bytes(
                _canonical(package_runtime_plan)
            ),
            "host_provenance_digest": _digest_bytes(_canonical(host_provenance)),
        }
        environment = _digest_bytes(_canonical(environment_preimage))
        qualification_contract = {
            "contract_core": contract_core,
            "contract_core_digest": contract_core_digest,
            "environment_preimage": environment_preimage,
            "environment_digest": environment,
        }
        qualification_contract_digest = _digest_bytes(
            _canonical(qualification_contract)
        )
        receipt_digests = {
            role: self.keys[role]["digest"]
            for role in ("M4_AUTHORITY", "OBSERVER", "PUBLISHER")
        }
        runtime_trust_digest = _digest_bytes(
            _canonical({
                "profile_digest": profile_digest,
                "receipt_public_key_digests": receipt_digests,
                "supply_public_key_digest": self.keys["SUPPLY"]["digest"],
            })
        )
        ledger_prefix = b""
        sequence = 1
        previous: str | None = None
        if prior_result is not None:
            prior_candidate = source["commit"] if repeat_candidate_environment else "a" * 40
            prior_tree = source["tree"] if repeat_candidate_environment else "d" * 40
            prior_core = deepcopy(contract_core)
            prior_core.update(
                candidate=prior_candidate,
                tree=prior_tree,
                attempt=1,
            )
            prior_core_digest = _digest_bytes(_canonical(prior_core))
            prior_preimage = deepcopy(environment_preimage)
            prior_preimage["contract_core_digest"] = prior_core_digest
            prior_environment = _digest_bytes(_canonical(prior_preimage))
            prior_contract = {
                "contract_core": prior_core,
                "contract_core_digest": prior_core_digest,
                "environment_preimage": prior_preimage,
                "environment_digest": prior_environment,
            }
            prior_contract_digest = _digest_bytes(_canonical(prior_contract))
            if repeat_candidate_environment:
                prior_environment = environment
            prior_start = self._ledger_row(
                sequence=1,
                previous=None,
                entry_type="ATTEMPT_STARTED",
                candidate=prior_candidate,
                tree=prior_tree,
                environment=prior_environment,
                attempt=1,
                goal_reference=goal_reference,
                goal_digest=goal_digest,
                contract_core_digest=prior_core_digest,
                qualification_contract_digest=prior_contract_digest,
                extra={"qualification_contract": prior_contract},
            )
            prior_start_line = _canonical(prior_start)
            prior_start_digest = _digest_bytes(prior_start_line)
            prior_terminal = self._ledger_row(
                sequence=2,
                previous=prior_start_digest,
                entry_type="ATTEMPT_TERMINAL",
                candidate=prior_candidate,
                tree=prior_tree,
                environment=prior_environment,
                attempt=1,
                goal_reference=goal_reference,
                goal_digest=goal_digest,
                contract_core_digest=prior_core_digest,
                qualification_contract_digest=prior_contract_digest,
                extra={
                    "attempt_start_digest": prior_start_digest,
                    "key_admission_digest": None,
                    "result": prior_result,
                    "terminal_reason": {
                        "FAILED": "RUN_FAILED",
                        "BLOCKED": "HOST_PREFLIGHT_FAILED",
                        "QUARANTINED": "RUN_FAILED",
                    }[prior_result],
                    "manifest_digest": None,
                    "signed_payload_bundle_digest": None,
                    "qemu_phase_outcomes": None,
                },
            )
            prior_terminal_line = _canonical(prior_terminal)
            previous = _digest_bytes(prior_terminal_line)
            ledger_prefix = prior_start_line + b"\n" + prior_terminal_line + b"\n"
            sequence = 3
        start = self._ledger_row(
            sequence=sequence,
            previous=previous,
            entry_type="ATTEMPT_STARTED",
            candidate=source["commit"],
            tree=source["tree"],
            environment=environment,
            attempt=attempt,
            goal_reference=goal_reference,
            goal_digest=goal_digest,
            contract_core_digest=contract_core_digest,
            qualification_contract_digest=qualification_contract_digest,
            extra={"qualification_contract": qualification_contract},
        )
        start_line = _canonical(start)
        start_digest = _digest_bytes(start_line)
        key_row = self._ledger_row(
            sequence=sequence + 1,
            previous=start_digest,
            entry_type="KEY_ADMITTED",
            candidate=source["commit"],
            tree=source["tree"],
            environment=environment,
            attempt=attempt,
            goal_reference=goal_reference,
            goal_digest=goal_digest,
            contract_core_digest=contract_core_digest,
            qualification_contract_digest=qualification_contract_digest,
            extra={
                "attempt_start_digest": start_digest,
                "admitted_qualification_contract_digest": (
                    qualification_contract_digest
                ),
                "receipt_public_key_digests": receipt_digests,
                "supply_public_key_digest": self.keys["SUPPLY"]["digest"],
                "runtime_trust_digest": runtime_trust_digest,
            },
        )
        key_line = _canonical(key_row)
        key_digest = _digest_bytes(key_line)
        binding_body = {
            "canonical_path": "/staging/artifact.txt",
            "descriptor_id": "publication-target-1",
            "root_id": "publication-root-1",
            "root_identity": digest,
            "mount_id": "mnt:1",
            "mount_identity": digest,
            "resolution_epoch": 1,
            "final_device": 1,
            "final_inode": 3,
            "final_type": "REGULAR_FILE",
            "final_digest": digest,
        }
        binding = {
            **binding_body,
            "composite_binding_digest": _digest_bytes(_canonical(binding_body)),
        }
        root_anchor_body = {
            "anchor_version": 1,
            "mount_namespace_id": "mntns:1:1",
            "mount_id": "mnt:1",
            "mountpoint": "/",
            "root_path": "/var/lib/harness-m4-publication/anchor/publication",
            "basename": "publication",
            "root_identity": digest,
            "ancestry": [
                {
                    "component": "publication",
                    "device": 1,
                    "inode": 2,
                    "mode": 0o040000,
                    "mount_id": "mnt:1",
                }
            ],
        }
        root_anchor = {
            **root_anchor_body,
            "anchor_digest": _digest_bytes(_canonical(root_anchor_body)),
        }
        durable = {
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
        }
        common = {
            "transaction_id": durable["transaction_id"],
            "contract_digest": durable["contract_digest"],
            "d2_frontier_digest": durable["d2_frontier_digest"],
            "attempt_cursor": 1,
            "iteration": 1,
            "publication_target_binding_digest": binding["composite_binding_digest"],
            "publication_root_anchor_digest": root_anchor["anchor_digest"],
            "snapshot_digest": digest,
            "revocation_epoch": 0,
            "fencing_epoch": 1,
            "issued_at": self.observed_at,
            "observed_at": self.observed_at,
            "expires_at": self.expires_at,
        }
        preflight = {
            "runtime_version": "1.0.0",
            "outcome": "READY",
            "transaction_id": durable["transaction_id"],
            "claim_digest": digest,
            "profile_digest": profile_digest,
            "placement_digest": digest,
            "session_id": "session-1",
            "revocation_epoch": 0,
            "fencing_epoch": 1,
            "executor_principal": profile["roles"]["EXECUTOR"]["principal_id"],
            "executor_session": profile["roles"]["EXECUTOR"]["session_id"],
            "staging_binding_digest": digest,
            "observed_at": self.observed_at,
            "expires_at": self.expires_at,
        }
        observer_body = {
            **common,
            "receipt_version": 1,
            "outcome": "PASS",
            "proposal_digest": digest,
        }
        observer = {
            **observer_body,
            "receipt_digest": _digest_bytes(_canonical(observer_body)),
        }
        publication_body = {
            **common,
            "receipt_version": 1,
            "outcome": "PUBLISHED",
            "published_binding": binding,
        }
        publication_receipt = {
            **publication_body,
            "receipt_digest": _digest_bytes(_canonical(publication_body)),
        }
        pre_commit = {**common, "purpose": "PRE_COMMIT", "outcome": "CONTINUOUS"}
        pre_join = {**common, "purpose": "PRE_JOIN", "outcome": "CONTINUOUS"}
        authorization_body = {
            "authorization_version": 1,
            "transaction_id": durable["transaction_id"],
            "claim_digest": digest,
            "intent_digest": digest,
            "capability_id": digest,
            "contract_digest": durable["contract_digest"],
            "d2_frontier_digest": durable["d2_frontier_digest"],
            "iteration": durable["iteration"],
            "target_authority_digest": digest,
            "target_binding": binding,
            "publication_target_binding_digest": binding["composite_binding_digest"],
            "publication_root_anchor_digest": root_anchor["anchor_digest"],
            "profile_digest": profile_digest,
            "placement_digest": digest,
            "session_id": "session-1",
            "revocation_epoch": durable["revocation_epoch"],
            "fencing_epoch": durable["fencing_epoch"],
            "issued_at": self.observed_at,
            "expires_at": self.expires_at,
        }
        authorization = {
            **authorization_body,
            "authorization_digest": _digest_bytes(_canonical(authorization_body)),
        }
        authorization_payload = {
            "record_type": "M4_STAGE_AUTHORIZATION",
            "authorization": authorization,
        }
        authorization_verification = self._verification_record(
            profile, "M4_AUTHORITY", authorization_payload
        )
        consumption = {
            "consumption_version": 1,
            "transaction_id": durable["transaction_id"],
            "stage_authorization_digest": authorization["authorization_digest"],
            "claim_digest": authorization["claim_digest"],
            "intent_digest": authorization["intent_digest"],
            "capability_id": authorization["capability_id"],
            "contract_digest": authorization["contract_digest"],
            "d2_frontier_digest": authorization["d2_frontier_digest"],
            "iteration": authorization["iteration"],
            "target_authority_digest": authorization["target_authority_digest"],
            "target_binding": authorization["target_binding"],
            "profile_digest": authorization["profile_digest"],
            "placement_digest": authorization["placement_digest"],
            "session_id": authorization["session_id"],
            "revocation_epoch": authorization["revocation_epoch"],
            "fencing_epoch": authorization["fencing_epoch"],
            "consumed_at": self.observed_at,
            "expires_at": authorization["expires_at"],
        }
        grant_payload = {
            "record_type": "M4_STAGE_EXECUTION_GRANT",
            "authorization": authorization,
            "authorization_verification": authorization_verification,
            "consumption": consumption,
        }
        grant_verification = self._verification_record(
            profile, "M4_AUTHORITY", grant_payload
        )
        events = [
            {
                "type": "M4_RUNTIME_PREFLIGHT",
                "payload": preflight,
                "verification_source": self._verification_source(profile, "M4_AUTHORITY", preflight),
            },
            {
                "type": "TCB_STAGE",
                "pid": 3101,
                "session": 3101,
                "stage_authorization_digest": authorization["authorization_digest"],
                "target_binding": binding,
                "grant_payload": grant_payload,
                "grant_verification": grant_verification,
                "grant_payload_digest": _digest_bytes(_canonical(grant_payload)),
                "grant_verification_digest": _digest_bytes(_canonical(grant_verification)),
            },
            {
                "type": "TCB_POSTCHECK",
                "pid": 3102,
                "session": 3102,
                "receipt": observer,
                "verification_source": self._verification_source(profile, "OBSERVER", observer),
            },
            {
                "type": "TCB_PUBLICATION",
                "receipt": publication_receipt,
                "verification_source": self._verification_source(
                    profile, "PUBLISHER", publication_receipt
                ),
            },
            {
                "type": "PRE_COMMIT",
                "payload": pre_commit,
                "verification_source": self._verification_source(profile, "PUBLISHER", pre_commit),
            },
            {
                "type": "PRE_JOIN",
                "payload": pre_join,
                "verification_source": self._verification_source(profile, "PUBLISHER", pre_join),
            },
        ]
        state = {
            "record_version": "1.0.0",
            "phase": "PRE_RESTART_PASS",
            "identity": {
                "candidate": source["commit"],
                "environment": environment,
                "attempt": attempt,
                "boot_id": "12345678-1234-1234-1234-123456789abc",
                "guest": {},
                "source": source,
                "host_provenance": host_provenance,
                "qualification_contract": qualification_contract,
                "qualification_contract_digest": qualification_contract_digest,
                "package_runtime_plan": package_runtime_plan,
            },
            "trust": {
                "profile_digest": profile_digest,
                "m4_apparmor_digest": self.module._digest_file(
                    ROOT / "profiles/m4-lx-a.apparmor", 1 << 20
                ),
                "m3_apparmor_digest": self.module._digest_file(
                    ROOT / "profiles/l0-lx-a.apparmor", 1 << 20
                ),
                "runtime_trust_digest": runtime_trust_digest,
                "key_admission": {
                    "admission_version": "2.0.0",
                    "mode": "HOST_ATTEMPT_LEDGER_PIN_BEFORE_WORKER_GATE",
                    "ledger_entry_digest": key_digest,
                    "receipt_public_key_digests": receipt_digests,
                    "supply_public_key_digest": self.keys["SUPPLY"]["digest"],
                    "runtime_trust_digest": runtime_trust_digest,
                    "qualification_contract": qualification_contract,
                    "qualification_contract_digest": qualification_contract_digest,
                    "contract_core_digest": contract_core_digest,
                },
                "receipt_public_key_digests": receipt_digests,
                "supply_public_key_digest": self.keys["SUPPLY"]["digest"],
                "verifier": {
                    "backend": "OPENSSL_LIBCRYPTO_SHARED",
                    "code_digest": self.module._digest_file(
                        ROOT / "src/harness_product/verification.py", 1 << 20
                    ),
                    "libcrypto_path": str(self.module.LIBCRYPTO),
                    "libcrypto_digest": self.module._digest_file(
                        self.module.LIBCRYPTO.resolve(strict=True), 16 << 20
                    ),
                    "independent_cryptographic_implementations": False,
                },
                "revocation_epoch": 0,
                "fencing_epoch": 1,
            },
            "durable": {
                "m4_recovery": durable,
                "m3_runtime_session": {
                    "session_record_id": "session-record-1",
                    "transaction_id": durable["transaction_id"],
                    "claim_digest": digest,
                    "state": "STOPPED",
                    "fencing_epoch": 1,
                },
            },
            "publication": {
                "root": profile["publication"]["root"],
                "topology_digest": digest,
                "root_anchor": root_anchor,
                "target_binding": binding,
                "published_binding": binding,
                "artifact_digest": digest,
                "snapshot_digest": digest,
                "transport": "SEALED_FD_ONLY",
            },
            "execution": {
                "controller_facts": self._role_facts(profile, "CONTROLLER"),
                "publisher_facts": self._role_facts(profile, "PUBLISHER"),
                "executor_facts": [self._role_facts(profile, "EXECUTOR")],
                "observer_facts": [self._role_facts(profile, "OBSERVER")],
                "runtime_events": events,
                "denial_events": [
                    {
                        "point": "AFTER_PRE_REPLACE_CHECKS",
                        "errno": 13,
                        "principal": {
                            "role": "CONTROLLER",
                            "pid": 3201,
                            "uid": profile["roles"]["CONTROLLER"]["uid"],
                            "gid": profile["roles"]["CONTROLLER"]["gid"],
                            "session": 3201,
                            "label": profile["roles"]["CONTROLLER"]["security_label"],
                            "cgroup": "/harness/m4-relocation-replace",
                            "fd_inventory": [0, 1, 2],
                            "namespaces": {
                                name: name + ":[1]"
                                for name in ("user", "mnt", "pid", "ipc", "uts", "net", "cgroup")
                            },
                            "capabilities": {
                                name: "0000000000000000"
                                for name in ("CapInh", "CapPrm", "CapEff")
                            },
                            "no_new_privs": 1,
                        },
                        "root_device": 1,
                        "root_inode": 2,
                        "git_destination_absent": True,
                        "pause": {
                            "anchor_digest": root_anchor["anchor_digest"],
                            "binding_digest": binding["composite_binding_digest"],
                        },
                    },
                    {
                        "point": "AFTER_PRE_JOIN",
                        "errno": 13,
                        "principal": {
                            "role": "CONTROLLER",
                            "pid": 3202,
                            "uid": profile["roles"]["CONTROLLER"]["uid"],
                            "gid": profile["roles"]["CONTROLLER"]["gid"],
                            "session": 3202,
                            "label": profile["roles"]["CONTROLLER"]["security_label"],
                            "cgroup": "/harness/m4-relocation-join",
                            "fd_inventory": [0, 1, 2],
                            "namespaces": {
                                name: name + ":[2]"
                                for name in ("user", "mnt", "pid", "ipc", "uts", "net", "cgroup")
                            },
                            "capabilities": {
                                name: "0000000000000000"
                                for name in ("CapInh", "CapPrm", "CapEff")
                            },
                            "no_new_privs": 1,
                        },
                        "root_device": 1,
                        "root_inode": 2,
                        "git_destination_absent": True,
                        "pause": {},
                    },
                ],
                "role_seccomp_digests": {},
                "m3_role_seccomp": {},
                "cleanup": {},
            },
        }
        recovery = {
            "recovery_version": "1.0.0",
            "qualification_contract": qualification_contract,
            "qualification_contract_digest": qualification_contract_digest,
            "previous_boot_id": state["identity"]["boot_id"],
            "current_boot_id": "87654321-4321-4321-4321-cba987654321",
            "durable": {
                "m4_recovery": durable,
                "m3_runtime_session": state["durable"]["m3_runtime_session"],
                "old_session_resumed": False,
                "retry_created": False,
            },
            "survival": {
                "recorded_process_ids": [3101, 3102, 3201, 3202],
                "live_process_ids": [],
                "recorded_cgroups": sorted({
                    state["execution"]["controller_facts"]["cgroup"],
                    state["execution"]["publisher_facts"]["cgroup"],
                    state["execution"]["executor_facts"][0]["cgroup"],
                    state["execution"]["observer_facts"][0]["cgroup"],
                    "/harness/m4-relocation-replace",
                    "/harness/m4-relocation-join",
                }),
                "surviving_cgroups": [],
            },
            "publication": {
                "descriptor_identity": {"root_device": 1, "root_inode": 2},
                "artifact_device": 1,
                "artifact_inode": 3,
                "artifact_size": 16,
                "artifact_digest": digest,
                "git_destination_absent": True,
            },
            "controller_facts": self._role_facts(profile, "CONTROLLER"),
            "source_reverified": True,
            "host_provenance_reverified": True,
            "trust_reverified": True,
        }
        evidence = {
            "bundle_version": "2.0.0",
            "evidence_version": "2.0.0",
            "claim": "M4_EXACT_DISPOSABLE_TEST_PROFILE_RUNTIME_CONFORMANCE",
            "qualification_contract": qualification_contract,
            "qualification_contract_digest": qualification_contract_digest,
            "admission_digest": key_digest,
            "package_runtime_plan": package_runtime_plan,
            "scope": {
                "profile_id": "M4-LX-A",
                "assurance_scope": "DEPLOYMENT_ATTESTED",
                "environment": "DISPOSABLE_UBUNTU_24_04_QEMU_KVM",
                "data_class": "SYNTHETIC",
            },
            "run_state": state,
            "run_state_digest": _digest_bytes(_canonical(state)),
            "recovery": recovery,
            "public_keys": {
                "receipts": {
                    role: {"digest": self.keys[role]["digest"], "pem": self.keys[role]["pem"]}
                    for role in ("M4_AUTHORITY", "OBSERVER", "PUBLISHER")
                },
                "supply_attestor": {
                    "digest": self.keys["SUPPLY"]["digest"],
                    "pem": self.keys["SUPPLY"]["pem"],
                },
            },
            "residual_risk": self.module._RESIDUAL_RISK,
        }
        evidence_bytes = _canonical(evidence)
        manifest = {
            "bundle_version": "2.0.0",
            "claim": evidence["claim"],
            "outcome": "VERIFIED",
            "status": "NOT_ATTESTED",
            "candidate": source["commit"],
            "environment": environment,
            "attempt": attempt,
            "qualification_contract": qualification_contract,
            "qualification_contract_digest": qualification_contract_digest,
            "admission_digest": key_digest,
            "package_runtime_plan": package_runtime_plan,
            "source": source,
            "host_provenance": host_provenance,
            "profile": {
                "path": "profiles/m4-lx-a.json",
                "digest": profile_digest,
                "apparmor_digest": state["trust"]["m4_apparmor_digest"],
                "runtime_trust_digest": runtime_trust_digest,
                "verifier": state["trust"]["verifier"],
            },
            "attempt_ledger": {
                "ledger_entry_digest": key_digest,
                "max_attempts": 2,
                "success_target": 1,
                "success_target_authorizing": False,
                "contract_core_digest": contract_core_digest,
                "qualification_contract_digest": qualification_contract_digest,
            },
            "durable": durable,
            "attestation": {
                "trust_root_id": profile["supply_trust"]["trust_root_id"],
                "signer_id": profile["supply_trust"]["signer_id"],
                "key_id": profile["supply_trust"]["key_id"],
                "algorithm": "ED25519",
                "public_key_digest": self.keys["SUPPLY"]["digest"],
                "issued_at": self.observed_at,
                "expires_at": self.expires_at,
                "revocation_epoch": 0,
                "fencing_epoch": 1,
                "rollback_floor": 1,
                "nonce": "m4-evidence-" + recovery["current_boot_id"].replace("-", ""),
            },
            "evidence": {
                "path": "evidence.json",
                "bytes": len(evidence_bytes),
                "digest": _digest_bytes(evidence_bytes),
            },
        }
        manifest_bytes = _canonical(manifest)
        manifest_signature = self._signature("SUPPLY", manifest)
        signed_payload_bundle_digest = _digest_bytes(
            _canonical({
                "evidence.json": _digest_bytes(evidence_bytes),
                "manifest.json": _digest_bytes(manifest_bytes),
                "manifest.sig": _digest_bytes(manifest_signature),
            })
        )
        terminal = self._ledger_row(
            sequence=sequence + 2,
            previous=key_digest,
            entry_type="ATTEMPT_TERMINAL",
            candidate=source["commit"],
            tree=source["tree"],
            environment=environment,
            attempt=attempt,
            goal_reference=goal_reference,
            goal_digest=goal_digest,
            contract_core_digest=contract_core_digest,
            qualification_contract_digest=qualification_contract_digest,
            extra={
                "attempt_start_digest": start_digest,
                "key_admission_digest": key_digest,
                "result": "BUNDLE_EXPORTED",
                "terminal_reason": "SIGNED_PAYLOAD_EXPORTED",
                "manifest_digest": _digest_bytes(manifest_bytes),
                "signed_payload_bundle_digest": signed_payload_bundle_digest,
                "qemu_phase_outcomes": {
                    phase: {
                        "argv_digest": _digest_bytes(
                            _canonical(self.module._qemu_argv(attempt, phase))
                        ),
                        "return_code": 0,
                    }
                    for phase in ("provision", "run", "recover")
                },
            },
        )
        ledger_bytes = (
            ledger_prefix
            + start_line
            + b"\n"
            + key_line
            + b"\n"
            + _canonical(terminal)
            + b"\n"
        )
        bundle = workspace / "bundle"
        bundle.mkdir(mode=0o700)
        for name, raw in (
            ("manifest.json", manifest_bytes),
            ("manifest.sig", manifest_signature),
            ("evidence.json", evidence_bytes),
            ("attempt-ledger.jsonl", ledger_bytes),
        ):
            path = bundle / name
            path.write_bytes(raw)
            os.chmod(path, 0o444)
        ledger = bundle / "attempt-ledger.jsonl"
        return bundle, ledger, source, goal_reference, goal_digest

    def _rewrite_bundle(
        self,
        bundle: Path,
        ledger: Path,
        change: object,
    ) -> None:
        manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
        evidence = json.loads((bundle / "evidence.json").read_text(encoding="utf-8"))
        lines = [json.loads(line) for line in ledger.read_bytes().splitlines()]
        change(manifest, evidence)
        evidence["run_state_digest"] = _digest_bytes(_canonical(evidence["run_state"]))
        evidence_bytes = _canonical(evidence)
        manifest["evidence"] = {
            "path": "evidence.json",
            "bytes": len(evidence_bytes),
            "digest": _digest_bytes(evidence_bytes),
        }
        manifest_bytes = _canonical(manifest)
        signature = self._signature("SUPPLY", manifest)
        lines[-1]["manifest_digest"] = _digest_bytes(manifest_bytes)
        lines[-1]["signed_payload_bundle_digest"] = _digest_bytes(
            _canonical({
                "evidence.json": _digest_bytes(evidence_bytes),
                "manifest.json": _digest_bytes(manifest_bytes),
                "manifest.sig": _digest_bytes(signature),
            })
        )
        ledger_bytes = b"".join(_canonical(row) + b"\n" for row in lines)
        for path in bundle.iterdir():
            os.chmod(path, 0o600)
        (bundle / "evidence.json").write_bytes(evidence_bytes)
        (bundle / "manifest.json").write_bytes(manifest_bytes)
        (bundle / "manifest.sig").write_bytes(signature)
        ledger.write_bytes(ledger_bytes)
        for path in bundle.iterdir():
            os.chmod(path, 0o444)

    def _rewrite_contract_bundle(
        self,
        bundle: Path,
        change: object,
        *,
        ledger_version: str = "2.0.0",
        admission_version: str = "2.0.0",
    ) -> None:
        manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
        evidence = json.loads((bundle / "evidence.json").read_text(encoding="utf-8"))
        ledger = bundle / "attempt-ledger.jsonl"
        rows = [json.loads(line) for line in ledger.read_bytes().splitlines()]
        for row in rows[-3:]:
            row["ledger_version"] = ledger_version
        contract = deepcopy(manifest["qualification_contract"])
        source = deepcopy(manifest["source"])
        plan = deepcopy(manifest["package_runtime_plan"])
        change(contract["contract_core"], contract["environment_preimage"], source, plan)
        core = contract["contract_core"]
        core_digest = _digest_bytes(_canonical(core))
        contract["contract_core_digest"] = core_digest
        contract["environment_preimage"]["contract_core_digest"] = core_digest
        contract["environment_preimage"]["package_runtime_plan_digest"] = (
            _digest_bytes(_canonical(plan))
        )
        environment = _digest_bytes(_canonical(contract["environment_preimage"]))
        contract["environment_digest"] = environment
        contract_digest = _digest_bytes(_canonical(contract))

        state = evidence["run_state"]
        identity = state["identity"]
        admission = state["trust"]["key_admission"]
        for projection in (manifest, evidence):
            projection["qualification_contract"] = contract
            projection["qualification_contract_digest"] = contract_digest
            projection["package_runtime_plan"] = plan
        identity.update(
            candidate=core["candidate"],
            environment=environment,
            attempt=core["attempt"],
            source=source,
            qualification_contract=contract,
            qualification_contract_digest=contract_digest,
            package_runtime_plan=plan,
        )
        evidence["recovery"]["qualification_contract"] = contract
        evidence["recovery"]["qualification_contract_digest"] = contract_digest
        admission.update(
            admission_version=admission_version,
            qualification_contract=contract,
            qualification_contract_digest=contract_digest,
            contract_core_digest=core_digest,
        )
        manifest.update(
            candidate=core["candidate"],
            environment=environment,
            attempt=core["attempt"],
            source=source,
        )

        start, key_row, terminal = rows[-3:]
        common = {
            "candidate": core["candidate"],
            "tree": core["tree"],
            "environment": environment,
            "attempt": core["attempt"],
            "user_scope_reference": core["user_scope_reference"],
            "user_goal_digest": core["user_goal_digest"],
            "max_attempts": core["max_attempts"],
            "success_target": core["success_target"],
            "success_target_authorizing": core["success_target_authorizing"],
            "contract_core_digest": core_digest,
            "qualification_contract_digest": contract_digest,
        }
        start.update(common)
        start["qualification_contract"] = contract
        start_line = _canonical(start)
        start_digest = _digest_bytes(start_line)
        key_row.update(common)
        key_row["previous_entry_digest"] = start_digest
        key_row["attempt_start_digest"] = start_digest
        key_row["admitted_qualification_contract_digest"] = contract_digest
        key_line = _canonical(key_row)
        key_digest = _digest_bytes(key_line)
        admission["ledger_entry_digest"] = key_digest
        manifest["admission_digest"] = key_digest
        evidence["admission_digest"] = key_digest
        manifest["attempt_ledger"] = {
            "ledger_entry_digest": key_digest,
            "max_attempts": core["max_attempts"],
            "success_target": core["success_target"],
            "success_target_authorizing": core["success_target_authorizing"],
            "contract_core_digest": core_digest,
            "qualification_contract_digest": contract_digest,
        }
        terminal.update(common)
        terminal["previous_entry_digest"] = key_digest
        terminal["attempt_start_digest"] = start_digest
        terminal["key_admission_digest"] = key_digest

        evidence["run_state_digest"] = _digest_bytes(_canonical(state))
        evidence_bytes = _canonical(evidence)
        manifest["evidence"] = {
            "path": "evidence.json",
            "bytes": len(evidence_bytes),
            "digest": _digest_bytes(evidence_bytes),
        }
        manifest_bytes = _canonical(manifest)
        signature = self._signature("SUPPLY", manifest)
        terminal["manifest_digest"] = _digest_bytes(manifest_bytes)
        terminal["signed_payload_bundle_digest"] = _digest_bytes(
            _canonical({
                "evidence.json": _digest_bytes(evidence_bytes),
                "manifest.json": _digest_bytes(manifest_bytes),
                "manifest.sig": _digest_bytes(signature),
            })
        )
        ledger_bytes = b"".join(
            _canonical(row) + b"\n" for row in rows[:-3]
        ) + start_line + b"\n" + key_line + b"\n" + _canonical(terminal) + b"\n"
        for path in bundle.iterdir():
            os.chmod(path, 0o600)
        (bundle / "manifest.json").write_bytes(manifest_bytes)
        (bundle / "manifest.sig").write_bytes(signature)
        (bundle / "evidence.json").write_bytes(evidence_bytes)
        ledger.write_bytes(ledger_bytes)
        for path in bundle.iterdir():
            os.chmod(path, 0o444)

    def test_exact_signed_bundle_and_authoritative_attempt_ledger_verify(self) -> None:
        bundle, ledger, source, goal_reference, goal_digest = self._fixture()
        result = self.module._verify_bundle(
            bundle,
            source_state=source,
            now=self.now,
            goal_reference=goal_reference,
            goal_digest=goal_digest,
        )
        self.assertEqual(result["outcome"], "VERIFIED")
        self.assertEqual(result["product_status"], "NOT_ATTESTED")
        self.assertEqual(result["attempt"], 1)
        self.assertEqual(result["gate_version"], 2)
        self.assertEqual(
            result["aggregate_bundle_digest"],
            self.module._closed_file_digest(
                result["bundle_file_digests"], self.module._BUNDLE_FILES
            ),
        )
        self.assertNotIn("aggregate_bundle_digest", ledger.read_text(encoding="utf-8"))

    def test_v1_bundle_is_rejected_even_when_resigned_and_relinked(self) -> None:
        bundle, ledger, source, goal_reference, goal_digest = self._fixture()
        self._rewrite_bundle(
            bundle,
            ledger,
            lambda manifest, evidence: (
                manifest.__setitem__("bundle_version", "1.0.0"),
                evidence.__setitem__("bundle_version", "1.0.0"),
                evidence.__setitem__("evidence_version", "1.0.0"),
            ),
        )
        with self.assertRaises(self.module._InvalidEvidence):
            self.module._verify_bundle(
                bundle,
                source_state=source,
                now=self.now,
                goal_reference=goal_reference,
                goal_digest=goal_digest,
            )

    def test_raw_profile_is_exact_canonical_and_alternate_bytes_are_rejected(self) -> None:
        raw = PROFILE.read_bytes()
        self.assertEqual(len(raw), 2698)
        self.assertEqual(_digest_bytes(raw), self.module._PROFILE_DIGEST)
        self.assertEqual(self.module._canonical(self.module._strict_json(raw, 1 << 20)), raw)
        for changed in (raw + b"\n", b" " + raw):
            with self.subTest(changed=changed[:1]), self.assertRaises(
                self.module._InvalidEvidence
            ):
                self.module._strict_json(changed, 1 << 20)

    def test_contract_binding_substitution_matrix_fails_closed(self) -> None:
        replacement = "sha256:" + "0" * 64

        def source_files(core: dict[str, object], _environment: dict[str, object],
                         source: dict[str, object], _plan: dict[str, object]) -> None:
            core["source_files_digest"] = replacement
            source["files_digest"] = replacement

        mutations = {
            "candidate": lambda core, _env, source, _plan: (
                core.__setitem__("candidate", "d" * 40),
                source.__setitem__("commit", "d" * 40),
            ),
            "tree": lambda core, _env, source, _plan: (
                core.__setitem__("tree", "e" * 40),
                source.__setitem__("tree", "e" * 40),
            ),
            "source-files": source_files,
            "canonical-profile": lambda core, *_: core.__setitem__(
                "canonical_profile_digest", replacement
            ),
            "raw-profile": lambda core, *_: core.__setitem__(
                "raw_profile_artifact_digest", replacement
            ),
            "environment-source-archive": lambda _core, environment, *_: (
                environment.__setitem__("source_archive_digest", replacement)
            ),
            "predecessor-qualification": lambda core, *_: core.__setitem__(
                "predecessor_qualification_ledger_digest", replacement
            ),
            "predecessor-diagnostic-ledger": lambda core, *_: core.__setitem__(
                "predecessor_diagnostic_ledger_digest", replacement
            ),
            "predecessor-diagnostic-bundle": lambda core, *_: core.__setitem__(
                "predecessor_diagnostic_bundle_digest", replacement
            ),
        }
        for name, mutation in mutations.items():
            with self.subTest(name=name):
                bundle, _ledger, source, goal_reference, goal_digest = self._fixture()
                self._rewrite_contract_bundle(bundle, mutation)
                with self.assertRaises(self.module._InvalidEvidence):
                    self.module._verify_bundle(
                        bundle,
                        source_state=source,
                        now=self.now,
                        goal_reference=goal_reference,
                        goal_digest=goal_digest,
                    )

    def test_package_runtime_plan_inputs_are_independently_pinned(self) -> None:
        replacement = "sha256:" + "0" * 64

        def replace_in(section: str, path: str):
            def mutate(_core, _environment, _source, plan) -> None:
                plan[section][path] = replacement

            return mutate

        mutations = {
            "provisioning-script": lambda _core, _environment, _source, plan: (
                plan.__setitem__("provisioning_script_digest", replacement)
            ),
            "package-source": replace_in(
                "package_sources", sorted(self.module._PACKAGE_SOURCE_PATHS)[0]
            ),
            "runtime-config": replace_in(
                "runtime_configs", sorted(self.module._RUNTIME_CONFIG_PATHS)[0]
            ),
            "runtime-tool": replace_in(
                "runtime_tools", sorted(self.module._RUNTIME_TOOL_PATHS)[0]
            ),
        }
        for name, mutation in mutations.items():
            with self.subTest(name=name):
                bundle, _ledger, source, goal_reference, goal_digest = self._fixture()
                self._rewrite_contract_bundle(bundle, mutation)
                with self.assertRaises(self.module._InvalidEvidence):
                    self.module._verify_bundle(
                        bundle,
                        source_state=source,
                        now=self.now,
                        goal_reference=goal_reference,
                        goal_digest=goal_digest,
                    )

    def test_embedded_ledger_removal_replacement_truncation_and_extension_fail(self) -> None:
        for name in ("removal", "replacement", "truncation", "extension"):
            with self.subTest(name=name):
                bundle, ledger, source, goal_reference, goal_digest = self._fixture()
                if name == "removal":
                    ledger.unlink()
                elif name == "replacement":
                    _other_bundle, other, *_ = self._fixture(
                        attempt=2, prior_result="BLOCKED"
                    )
                    os.chmod(ledger, 0o600)
                    ledger.write_bytes(other.read_bytes())
                    os.chmod(ledger, 0o444)
                elif name == "truncation":
                    os.chmod(ledger, 0o600)
                    ledger.write_bytes(b"\n".join(ledger.read_bytes().splitlines()[:-1]) + b"\n")
                    os.chmod(ledger, 0o444)
                else:
                    rows = [json.loads(line) for line in ledger.read_bytes().splitlines()]
                    appended = deepcopy(rows[-1])
                    appended["sequence"] += 1
                    appended["previous_entry_digest"] = _digest_bytes(
                        _canonical(rows[-1])
                    )
                    os.chmod(ledger, 0o600)
                    ledger.write_bytes(
                        ledger.read_bytes() + _canonical(appended) + b"\n"
                    )
                    os.chmod(ledger, 0o444)
                with self.assertRaises(self.module._InvalidEvidence):
                    self.module._verify_bundle(
                        bundle,
                        source_state=source,
                        now=self.now,
                        goal_reference=goal_reference,
                        goal_digest=goal_digest,
                    )

    def test_extra_bundle_file_and_terminal_linkage_mutations_fail_closed(self) -> None:
        bundle, _ledger, source, goal_reference, goal_digest = self._fixture()
        extra = bundle / "unexpected"
        extra.write_bytes(b"x")
        os.chmod(extra, 0o444)
        with self.assertRaises(self.module._InvalidEvidence):
            self.module._verify_bundle(
                bundle,
                source_state=source,
                now=self.now,
                goal_reference=goal_reference,
                goal_digest=goal_digest,
            )
        for field in ("manifest_digest", "signed_payload_bundle_digest"):
            with self.subTest(field=field):
                bundle, ledger, source, goal_reference, goal_digest = self._fixture()
                rows = [json.loads(line) for line in ledger.read_bytes().splitlines()]
                rows[-1][field] = "sha256:" + "0" * 64
                os.chmod(ledger, 0o600)
                ledger.write_bytes(b"".join(_canonical(row) + b"\n" for row in rows))
                os.chmod(ledger, 0o444)
                with self.assertRaises(self.module._InvalidEvidence):
                    self.module._verify_bundle(
                        bundle,
                        source_state=source,
                        now=self.now,
                        goal_reference=goal_reference,
                        goal_digest=goal_digest,
                    )

    def test_aggregate_digest_is_sensitive_to_each_exact_bundle_file(self) -> None:
        baseline = {
            name: _digest_bytes(name.encode("utf-8"))
            for name in self.module._BUNDLE_FILES
        }
        expected = self.module._closed_file_digest(
            baseline, self.module._BUNDLE_FILES
        )
        for name in sorted(self.module._BUNDLE_FILES):
            changed = dict(baseline)
            changed[name] = _digest_bytes((name + "-changed").encode("utf-8"))
            with self.subTest(name=name):
                self.assertNotEqual(
                    self.module._closed_file_digest(
                        changed, self.module._BUNDLE_FILES
                    ),
                    expected,
                )

    def test_failed_first_attempt_consumes_slot_and_second_attempt_verifies(self) -> None:
        bundle, ledger, source, goal_reference, goal_digest = self._fixture(
            attempt=2, prior_result="BLOCKED"
        )
        result = self.module._verify_bundle(
            bundle,
            source_state=source,
            now=self.now,
            goal_reference=goal_reference,
            goal_digest=goal_digest,
        )
        self.assertEqual(result["outcome"], "VERIFIED")
        self.assertEqual(result["attempt"], 2)

    def test_second_attempt_cannot_repeat_candidate_and_environment(self) -> None:
        bundle, ledger, source, goal_reference, goal_digest = self._fixture(
            attempt=2,
            prior_result="BLOCKED",
            repeat_candidate_environment=True,
        )
        with self.assertRaises(self.module._InvalidEvidence):
            self.module._verify_bundle(
                bundle,
                source_state=source,
                now=self.now,
                goal_reference=goal_reference,
                goal_digest=goal_digest,
            )

    def test_missing_terminal_attempt_record_fails_closed(self) -> None:
        bundle, ledger, source, goal_reference, goal_digest = self._fixture()
        lines = ledger.read_bytes().splitlines()
        os.chmod(ledger, 0o600)
        ledger.write_bytes(b"\n".join(lines[:2]) + b"\n")
        os.chmod(ledger, 0o444)
        with self.assertRaises(self.module._InvalidEvidence):
            self.module._verify_bundle(
                bundle,
                source_state=source,
                now=self.now,
                goal_reference=goal_reference,
                goal_digest=goal_digest,
            )

    def test_malformed_runtime_event_and_attestation_time_fail_closed(self) -> None:
        for name, change in (
            (
                "runtime-event",
                lambda _manifest, evidence: evidence["run_state"]["execution"][
                    "runtime_events"
                ].append(None),
            ),
            (
                "attestation-time",
                lambda manifest, _evidence: manifest["attestation"].__setitem__(
                    "expires_at", None
                ),
            ),
        ):
            with self.subTest(name=name):
                bundle, ledger, source, goal_reference, goal_digest = self._fixture()
                self._rewrite_bundle(bundle, ledger, change)
                with self.assertRaises(self.module._InvalidEvidence):
                    self.module._verify_bundle(
                        bundle,
                        source_state=source,
                        now=self.now,
                        goal_reference=goal_reference,
                        goal_digest=goal_digest,
                    )

    def test_host_provenance_constants_fail_closed(self) -> None:
        bundle, ledger, source, goal_reference, goal_digest = self._fixture()

        def mutate(manifest: dict[str, object], evidence: dict[str, object]) -> None:
            manifest["host_provenance"]["vm"]["qemu_version"] = "QEMU emulator version 9.9.9"
            evidence["run_state"]["identity"]["host_provenance"]["vm"][
                "qemu_version"
            ] = "QEMU emulator version 9.9.9"

        self._rewrite_bundle(bundle, ledger, mutate)
        with self.assertRaises(self.module._InvalidEvidence):
            self.module._verify_bundle(
                bundle,
                source_state=source,
                now=self.now,
                goal_reference=goal_reference,
                goal_digest=goal_digest,
            )

    def test_qemu_phase_outcomes_fail_closed(self) -> None:
        for name, mutate in (
            (
                "nonzero-return",
                lambda terminal: terminal["qemu_phase_outcomes"]["run"].__setitem__(
                    "return_code", 1
                ),
            ),
            (
                "wrong-argv",
                lambda terminal: terminal["qemu_phase_outcomes"]["recover"].__setitem__(
                    "argv_digest", "sha256:" + "0" * 64
                ),
            ),
            (
                "missing-phase",
                lambda terminal: terminal["qemu_phase_outcomes"].pop("provision"),
            ),
        ):
            with self.subTest(name=name):
                bundle, ledger, source, goal_reference, goal_digest = self._fixture()
                rows = [json.loads(line) for line in ledger.read_bytes().splitlines()]
                mutate(rows[-1])
                os.chmod(ledger, 0o600)
                ledger.write_bytes(b"".join(_canonical(row) + b"\n" for row in rows))
                os.chmod(ledger, 0o444)
                with self.assertRaises(self.module._InvalidEvidence):
                    self.module._verify_bundle(
                        bundle,
                        source_state=source,
                        now=self.now,
                        goal_reference=goal_reference,
                        goal_digest=goal_digest,
                    )

    def test_duplicate_physical_denial_event_fails_closed(self) -> None:
        bundle, ledger, source, goal_reference, goal_digest = self._fixture()

        def duplicate(_manifest: dict[str, object], evidence: dict[str, object]) -> None:
            denials = evidence["run_state"]["execution"]["denial_events"]
            denials.append(dict(denials[0]))

        self._rewrite_bundle(bundle, ledger, duplicate)
        with self.assertRaises(self.module._InvalidEvidence):
            self.module._verify_bundle(
                bundle,
                source_state=source,
                now=self.now,
                goal_reference=goal_reference,
                goal_digest=goal_digest,
            )

    def test_durable_integer_alias_and_session_fence_mutations_fail_closed(self) -> None:
        for name, change in (
            (
                "boolean-attempt-cursor",
                lambda _manifest, evidence: evidence["run_state"]["durable"][
                    "m4_recovery"
                ].__setitem__("attempt_cursor", True),
            ),
            (
                "zero-journal-sequence",
                lambda _manifest, evidence: evidence["run_state"]["durable"][
                    "m4_recovery"
                ].__setitem__("journal_sequence", 0),
            ),
            (
                "session-fence",
                lambda _manifest, evidence: evidence["run_state"]["durable"][
                    "m3_runtime_session"
                ].__setitem__("fencing_epoch", 2),
            ),
        ):
            with self.subTest(name=name):
                bundle, ledger, source, goal_reference, goal_digest = self._fixture()
                self._rewrite_bundle(bundle, ledger, change)
                with self.assertRaises(self.module._InvalidEvidence):
                    self.module._verify_bundle(
                        bundle,
                        source_state=source,
                        now=self.now,
                        goal_reference=goal_reference,
                        goal_digest=goal_digest,
                    )

    def test_embedded_public_key_digest_mutations_fail_closed(self) -> None:
        for name, change in (
            (
                "receipt",
                lambda _manifest, evidence: evidence["public_keys"]["receipts"][
                    "OBSERVER"
                ].__setitem__("digest", "sha256:" + "0" * 64),
            ),
            (
                "supply",
                lambda _manifest, evidence: evidence["public_keys"][
                    "supply_attestor"
                ].__setitem__("digest", "sha256:" + "0" * 64),
            ),
        ):
            with self.subTest(name=name):
                bundle, ledger, source, goal_reference, goal_digest = self._fixture()
                self._rewrite_bundle(bundle, ledger, change)
                with self.assertRaises(self.module._InvalidEvidence):
                    self.module._verify_bundle(
                        bundle,
                        source_state=source,
                        now=self.now,
                        goal_reference=goal_reference,
                        goal_digest=goal_digest,
                    )

    def test_m3_apparmor_digest_mutation_fails_closed(self) -> None:
        bundle, ledger, source, goal_reference, goal_digest = self._fixture()
        self._rewrite_bundle(
            bundle,
            ledger,
            lambda _manifest, evidence: evidence["run_state"]["trust"].__setitem__(
                "m3_apparmor_digest", "sha256:" + "0" * 64
            ),
        )
        with self.assertRaises(self.module._InvalidEvidence):
            self.module._verify_bundle(
                bundle,
                source_state=source,
                now=self.now,
                goal_reference=goal_reference,
                goal_digest=goal_digest,
            )

    def test_recovery_type_and_principal_mutations_fail_closed(self) -> None:
        for name, change in (
            (
                "boolean-recorded-pid",
                lambda _manifest, evidence: evidence["recovery"]["survival"].__setitem__(
                    "recorded_process_ids", [True]
                ),
            ),
            (
                "boolean-artifact-size",
                lambda _manifest, evidence: evidence["recovery"]["publication"].__setitem__(
                    "artifact_size", True
                ),
            ),
            (
                "controller-label",
                lambda _manifest, evidence: evidence["recovery"]["controller_facts"].__setitem__(
                    "label", "unconfined"
                ),
            ),
        ):
            with self.subTest(name=name):
                bundle, ledger, source, goal_reference, goal_digest = self._fixture()
                self._rewrite_bundle(bundle, ledger, change)
                with self.assertRaises(self.module._InvalidEvidence):
                    self.module._verify_bundle(
                        bundle,
                        source_state=source,
                        now=self.now,
                        goal_reference=goal_reference,
                        goal_digest=goal_digest,
                    )

    def test_stage_execution_grant_mutations_fail_closed(self) -> None:
        def stage(evidence: dict[str, object]) -> dict[str, object]:
            return evidence["run_state"]["execution"]["runtime_events"][1]

        def mutate_nested(_manifest: dict[str, object], evidence: dict[str, object]) -> None:
            event = stage(evidence)
            event["grant_payload"]["consumption"]["session_id"] = "substituted-session"
            event["grant_payload_digest"] = _digest_bytes(_canonical(event["grant_payload"]))

        for name, change in (
            (
                "target-binding",
                lambda _manifest, evidence: stage(evidence).__setitem__(
                    "target_binding", {"substituted": True}
                ),
            ),
            (
                "authorization-digest",
                lambda _manifest, evidence: stage(evidence).__setitem__(
                    "stage_authorization_digest", "sha256:" + "0" * 64
                ),
            ),
            (
                "grant-verification-digest",
                lambda _manifest, evidence: stage(evidence).__setitem__(
                    "grant_verification_digest", "sha256:" + "0" * 64
                ),
            ),
            ("nested-grant-binding", mutate_nested),
        ):
            with self.subTest(name=name):
                bundle, ledger, source, goal_reference, goal_digest = self._fixture()
                self._rewrite_bundle(bundle, ledger, change)
                with self.assertRaises(self.module._InvalidEvidence):
                    self.module._verify_bundle(
                        bundle,
                        source_state=source,
                        now=self.now,
                        goal_reference=goal_reference,
                        goal_digest=goal_digest,
                    )

    def test_bundle_and_ledger_permissions_are_exact(self) -> None:
        for name, mutate in (
            ("bundle-directory", lambda bundle, _ledger: os.chmod(bundle, 0o755)),
            (
                "bundle-file",
                lambda bundle, _ledger: os.chmod(bundle / "manifest.json", 0o644),
            ),
            ("ledger-parent", lambda _bundle, ledger: os.chmod(ledger.parent, 0o755)),
        ):
            with self.subTest(name=name):
                bundle, ledger, source, goal_reference, goal_digest = self._fixture()
                mutate(bundle, ledger)
                with self.assertRaises(self.module._InvalidEvidence):
                    self.module._verify_bundle(
                        bundle,
                        source_state=source,
                        now=self.now,
                        goal_reference=goal_reference,
                        goal_digest=goal_digest,
                    )


if __name__ == "__main__":
    unittest.main()
