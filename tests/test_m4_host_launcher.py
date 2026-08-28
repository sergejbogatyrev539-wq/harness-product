from __future__ import annotations

import base64
from datetime import UTC, datetime
import importlib.util
import inspect
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def _module(name: str, path: Path) -> object:
    specification = importlib.util.spec_from_file_location(name, path)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


class M4HostLauncherTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.launcher = _module(
            "harness_m4_host_launcher", ROOT / "scripts/run_m4_host_qualification.py"
        )
        cls.checker = _module(
            "harness_m4_evidence_checker", ROOT / "scripts/check_m4_runtime_evidence.py"
        )

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="harness-m4-host-test-")
        self.root = Path(self.temporary.name)
        self.goal = self.root / "goal.md"
        self.goal.write_text("authorized synthetic M4 goal\n", encoding="utf-8")
        os.chmod(self.goal, 0o444)
        self.launcher.EVIDENCE_ROOT = self.root / "evidence"
        self.now = datetime(2026, 8, 27, 12, 0, 0, tzinfo=UTC)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _phase_outcomes(self, attempt: int) -> dict[str, object]:
        return {
            phase: {
                "argv_digest": self.launcher._digest_bytes(
                    self.launcher._canonical(self.launcher._qemu_argv(attempt, phase))
                ),
                "return_code": 0,
            }
            for phase in ("provision", "run", "recover")
        }

    def _contract(self, attempt: int = 1, **changes: object) -> dict[str, object]:
        values: dict[str, object] = {
            "goal_reference": str(self.goal),
            "goal_digest": self.launcher._digest_file(self.goal, 1 << 20),
            "candidate": "a" * 40,
            "tree": "b" * 40,
            "attempt": attempt,
            "source_files_digest": "sha256:" + "1" * 64,
            "source_archive_digest": "sha256:" + "2" * 64,
            "seed_digest": "sha256:" + "3" * 64,
            "package_runtime_plan_digest": "sha256:" + "4" * 64,
            "host_provenance_digest": "sha256:" + "5" * 64,
        }
        values.update(changes)
        return self.launcher._qualification_contract(**values)

    def _ready(self, contract: dict[str, object]) -> dict[str, object]:
        return {
            "ready_version": "2.0.0",
            "candidate": contract["contract_core"]["candidate"],
            "environment": contract["environment_digest"],
            "attempt": contract["contract_core"]["attempt"],
            "qualification_contract": contract,
            "qualification_contract_digest": (
                self.launcher._qualification_contract_digest(contract)
            ),
            "contract_core_digest": contract["contract_core_digest"],
            "receipt_public_key_digests": {
                role: "sha256:" + character * 64
                for role, character in (
                    ("M4_AUTHORITY", "1"),
                    ("OBSERVER", "2"),
                    ("PUBLISHER", "3"),
                )
            },
            "supply_public_key_digest": "sha256:" + "4" * 64,
            "runtime_trust_digest": "sha256:" + "5" * 64,
        }

    def test_qemu_lifecycle_matches_independent_checker_contract(self) -> None:
        for attempt in (1, 2):
            actual = self.launcher._qemu_lifecycle(attempt)
            self.assertEqual(actual, self.checker._qemu_lifecycle(attempt))
            self.assertIn("restrict=off", " ".join(actual["provision"]))
            for phase in ("run", "recover"):
                joined = " ".join(actual[phase])
                self.assertIn("restrict=on", joined)
                self.assertNotIn("seed.iso", joined)
                self.assertNotIn("-virtfs", actual[phase])
                self.assertNotIn("-fsdev", actual[phase])

    def test_provisioning_pins_exact_runtime_before_offline_transition(self) -> None:
        script = self.launcher._provision_script().decode("ascii")
        self.assertIn("test -x /usr/sbin/nft", script)
        self.assertLess(
            script.index("nftables-provisioning.conf"),
            script.index("/usr/bin/apt-get update"),
        )
        for package, version in (
            ("bubblewrap", "0.9.0-1ubuntu0.1"),
            ("apparmor", "4.0.1really4.0.1-0ubuntu0.24.04.7"),
            ("apparmor-utils", "4.0.1really4.0.1-0ubuntu0.24.04.7"),
            ("openssl", "3.0.13-0ubuntu3.12"),
            ("libssl3t64", "3.0.13-0ubuntu3.12"),
            ("python3.12", "3.12.3-1ubuntu0.15"),
        ):
            self.assertIn(package + "=" + version, script)
            self.assertIn("dpkg-query -W -f='${Version}' " + package, script)
        for digest in (
            "52231e1caf55bcbc667b269f49c63599a6f7db4767ae6a039580d0ff853db712",
            "f28cbce3c8664cab5154492fdbc55ecb937a3e7ce1a9478c881a5f5965d7ce3e",
            "1451aceec262c3338052fa77542eb971d4ba311c6bf12d9aa70d0b56aca942f9",
        ):
            self.assertIn(digest, script)
        self.assertLess(
            script.index("sha256sum -c -"),
            script.index("nftables-offline.conf"),
        )

    def test_cloud_init_seed_uses_schema_valid_host_key_generation(self) -> None:
        raw = self.launcher._cloud_config(
            "ssh-ed25519 AAAATEST harness-m4-client-attempt-2", []
        ).decode("utf-8")
        self.assertIn("ssh_deletekeys: false\n", raw)
        self.assertIn("ssh_genkeytypes: [ed25519]\n", raw)
        self.assertNotIn("ssh_genkeytypes: []", raw)
        self.assertIn(
            '      - "ssh-ed25519 AAAATEST harness-m4-client-attempt-2"\n', raw
        )

    def test_host_profile_preflight_requires_exact_canonical_bytes(self) -> None:
        canonical = self.launcher._canonical(
            json.loads((ROOT / "profiles/m4-lx-a.json").read_bytes())
        )
        profile_root = self.root / "source"
        profile = profile_root / "profiles/m4-lx-a.json"
        profile.parent.mkdir(parents=True)
        profile.write_bytes(canonical)
        with mock.patch.object(self.launcher, "ROOT", profile_root):
            value, digest = self.launcher._profile()
            self.assertEqual(value["profile_id"], "M4-LX-A")
            self.assertEqual(len(canonical), 2698)
            self.assertEqual(
                digest,
                "sha256:50947b4b4ae139effbaddd749c7175a15755675f824e0ae1ed734a85694b4682",
            )
            for suffix in (b"\n", b" "):
                profile.write_bytes(canonical + suffix)
                with self.subTest(suffix=suffix), self.assertRaisesRegex(
                    self.launcher.QualificationStop, "NONCANONICAL_JSON"
                ):
                    self.launcher._profile()
            for raw, reason in (
                (b'{"a":1,"a":2}', "DUPLICATE_JSON_KEY"),
                (b'{"a":NaN}', "NONFINITE_JSON"),
                (
                    self.launcher._canonical(
                        {**json.loads(canonical), "unknown_profile_field": True}
                    ),
                    "PROFILE_MALFORMED",
                ),
            ):
                profile.write_bytes(raw)
                with self.subTest(reason=reason), self.assertRaisesRegex(
                    self.launcher.QualificationStop, reason
                ):
                    self.launcher._profile()

    def test_noncanonical_profile_stops_before_qualification_side_effects(self) -> None:
        lab = self.root / "qualification-v2"
        source = {
            "commit": "a" * 40,
            "tree": "b" * 40,
            "files": {},
            "files_digest": "sha256:" + "c" * 64,
        }
        with mock.patch.object(self.launcher, "USER_GOAL", self.goal), mock.patch.object(
            self.launcher, "LAB", lab
        ), mock.patch.object(
            self.launcher, "_source_state", return_value=source
        ), mock.patch.object(
            self.launcher,
            "_profile",
            side_effect=self.launcher.QualificationStop("NONCANONICAL_JSON"),
        ), mock.patch.object(
            self.launcher, "AttemptLedger"
        ) as ledger, mock.patch.object(
            self.launcher, "_create_seed"
        ) as seed, mock.patch.object(
            self.launcher, "_create_overlay"
        ) as overlay, mock.patch.object(
            self.launcher, "_provision_vm"
        ) as vm:
            with self.assertRaisesRegex(
                self.launcher.QualificationStop, "NONCANONICAL_JSON"
            ):
                self.launcher._qualification()
        ledger.assert_not_called()
        seed.assert_not_called()
        overlay.assert_not_called()
        vm.assert_not_called()
        self.assertFalse(lab.exists())

    def test_raw_profile_bytes_are_part_of_the_source_file_map_binding(self) -> None:
        current = "sha256:50947b4b4ae139effbaddd749c7175a15755675f824e0ae1ed734a85694b4682"
        previous = "sha256:5832e7261a2bf881877ef833056eaa6c0247309db468b9952a9203b503cd88f3"

        def run(argv, **_kwargs):
            if argv[-1] == "HEAD":
                stdout = b"a" * 40 + b"\n"
            elif argv[-1] == "HEAD^{tree}":
                stdout = b"b" * 40 + b"\n"
            elif "status" in argv:
                stdout = b""
            elif "ls-files" in argv:
                stdout = b""
            else:
                raise AssertionError(argv)
            return subprocess.CompletedProcess(argv, 0, stdout=stdout, stderr=b"")

        def source(profile_digest):
            def digest(path, _maximum):
                if path.name == "m4-lx-a.json":
                    return profile_digest
                return self.launcher._digest_bytes(str(path).encode("utf-8"))

            with mock.patch.object(self.launcher, "_run", side_effect=run), mock.patch.object(
                self.launcher, "_digest_file", side_effect=digest
            ):
                return self.launcher._source_state()

        current_source = source(current)
        previous_source = source(previous)
        self.assertEqual(
            current_source["files"]["profiles/m4-lx-a.json"], current
        )
        self.assertEqual(
            previous_source["files"]["profiles/m4-lx-a.json"], previous
        )
        self.assertNotEqual(
            current_source["files_digest"], previous_source["files_digest"]
        )

    def test_qualification_contract_v2_is_closed_digest_bound_and_mutation_sensitive(self) -> None:
        contract = self._contract()
        self.assertEqual(
            frozenset(contract),
            {
                "contract_core", "contract_core_digest", "environment_preimage",
                "environment_digest",
            },
        )
        core = contract["contract_core"]
        self.assertEqual(core["contract_version"], "2.0.0")
        self.assertEqual(core["attempt"], 1)
        self.assertFalse(core["success_target_authorizing"])
        self.assertEqual(
            contract["contract_core_digest"],
            self.launcher._digest_bytes(self.launcher._canonical(core)),
        )
        self.assertEqual(
            contract["environment_preimage"]["contract_core_digest"],
            contract["contract_core_digest"],
        )
        self.assertEqual(
            contract["environment_digest"],
            self.launcher._digest_bytes(
                self.launcher._canonical(contract["environment_preimage"])
            ),
        )
        contract_digest = self.launcher._qualification_contract_digest(contract)
        self.assertEqual(
            contract_digest,
            self.launcher._digest_bytes(self.launcher._canonical(contract)),
        )
        self.assertEqual(self.launcher._validate_qualification_contract(contract), contract)

        for field in (
            "source_archive_digest", "seed_digest", "package_runtime_plan_digest",
            "host_provenance_digest",
        ):
            changed = self._contract(**{field: "sha256:" + "9" * 64})
            with self.subTest(field=field):
                self.assertNotEqual(changed["environment_digest"], contract["environment_digest"])
                self.assertNotEqual(
                    self.launcher._qualification_contract_digest(changed), contract_digest
                )

        for mutation in (
            {key: value for key, value in contract.items() if key != "environment_digest"},
            {**contract, "extra": False},
            {**contract, "contract_core_digest": "sha256:" + "8" * 64},
        ):
            with self.subTest(keys=sorted(mutation)), self.assertRaises(
                self.launcher.QualificationStop
            ):
                self.launcher._validate_qualification_contract(mutation)

    def test_package_runtime_plan_is_closed_and_binds_provisioning_inputs(self) -> None:
        plan = self.launcher._package_runtime_plan()
        self.assertEqual(
            frozenset(plan),
            {
                "plan_version", "packages", "provisioning_script_digest",
                "package_sources", "runtime_configs", "runtime_tools",
            },
        )
        self.assertEqual(plan["plan_version"], "1.0.0")
        self.assertEqual(plan["packages"]["bubblewrap"], "0.9.0-1ubuntu0.1")
        self.assertEqual(
            plan["provisioning_script_digest"],
            self.launcher._digest_bytes(self.launcher._provision_script()),
        )
        self.assertIn("/etc/apt/sources.list.d/ubuntu.sources", plan["package_sources"])
        self.assertIn("/etc/harness-m4/nftables-offline.conf", plan["runtime_configs"])
        self.assertIn("/usr/lib/x86_64-linux-gnu/libcrypto.so.3", plan["runtime_tools"])
        self.assertIn(
            "/etc/harness-m4/source-archive.tgz",
            self.launcher._provision_script().decode("ascii"),
        )

    def test_ubuntu_source_seed_plan_is_byte_exact_and_boundary_bound(self) -> None:
        final_path = "/etc/apt/sources.list.d/ubuntu.sources"
        seed_path = "/etc/harness-m4/apt-ubuntu.sources"
        expected = (
            "sha256:eafe8bd9490d039ddaa42d1ca6e2682b0a4e68fe13845aa47d8c195292574d55"
        )
        plan = self.launcher._package_runtime_plan()
        self.assertEqual(plan["package_sources"][final_path], expected)
        path, raw, mode = self.launcher._ubuntu_source_seed_entry(plan)
        self.assertEqual((path, len(raw), mode), (seed_path, 321, 0o444))
        self.assertEqual(self.launcher._digest_bytes(raw), expected)
        cloud_entry = self.launcher._cloud_file(path, raw, mode)
        self.assertEqual(
            base64.b64decode(cloud_entry[-1].removeprefix("    content: "), validate=True),
            raw,
        )
        self.assertEqual(
            self.launcher._digest_bytes(self.launcher._provision_script()),
            "sha256:e3e66da8b31e841910d491f3fdbf94735badce3ee36eceb9241c72003366fd2c",
        )
        entry = self.launcher._provision_entry_script().decode("ascii")
        self.assertIn(seed_path, entry)
        self.assertIn(final_path, entry)
        self.assertIn("source /root/harness-m4-provision.sh", entry)
        self.assertIn('[[ "$command" == "/usr/bin/apt-get clean" ]]', entry)
        self.assertIn("AFTER_EXACT_PACKAGE_INSTALL_AND_CLEAN", entry)
        cloud = self.launcher._cloud_config("ssh-ed25519 AAAATEST", []).decode(
            "utf-8"
        )
        self.assertIn(
            "  - [ /bin/bash, /root/harness-m4-provision-entry.sh ]", cloud
        )
        self.assertNotIn(
            "  - [ /bin/bash, /root/harness-m4-provision.sh ]", cloud
        )

        for case_name, wrong_before, changed_during, expected_outcomes in (
            ("exact", False, False, ["MATCH", "MATCH"]),
            ("wrong-before-apt", True, False, ["MISMATCH"]),
            ("changed-during-apt", False, True, ["MATCH", "MISMATCH"]),
        ):
            with self.subTest(boundary_case=case_name):
                case_root = self.root / case_name
                case_root.mkdir()
                canonical = case_root / "apt-ubuntu.sources"
                final = case_root / "installed-ubuntu.sources"
                records = case_root / "package-source-boundaries.jsonl"
                wrong_source = case_root / "wrong.sources"
                canonical.write_bytes(raw)
                wrong_source.write_bytes((case_name + "\n").encode("ascii"))

                def executable(name: str, body: str) -> Path:
                    path = case_root / name
                    path.write_text("#!/bin/bash\nset -euo pipefail\n" + body)
                    os.chmod(path, 0o700)
                    return path

                mutate = executable(
                    "mutate-before",
                    f'/usr/bin/cp -- "{wrong_source}" "{final}"\n',
                )
                update_body = "/usr/bin/printf 'APT_UPDATE\\n'\n"
                if changed_during:
                    update_body += f'/usr/bin/cp -- "{wrong_source}" "{final}"\n'
                update = executable("apt-update", update_body)
                clean = executable("apt-clean", "/usr/bin/printf 'APT_CLEAN\\n'\n")
                after = executable("after-base", "/usr/bin/printf 'AFTER_BASE\\n'\n")
                main = case_root / "provision.sh"
                commands = ([str(mutate)] if wrong_before else []) + [
                    str(update), str(clean), str(after)
                ]
                main.write_text("#!/bin/bash\nset -euo pipefail\n" + "\n".join(commands) + "\n")

                local_entry = entry
                replacements = (
                    (
                        f"boundary_canonical='{seed_path}'",
                        f"boundary_canonical='{canonical}'",
                    ),
                    (
                        f"boundary_final='{final_path}'",
                        f"boundary_final='{final}'",
                    ),
                    (
                        "boundary_records='/var/lib/harness-m4-provisioning/"
                        "package-source-boundaries.jsonl'",
                        f"boundary_records='{records}'",
                    ),
                    (
                        "/usr/bin/install -d -o root -g root -m 0700 "
                        "/var/lib/harness-m4-provisioning",
                        f'/usr/bin/install -d -m 0700 "{case_root}"',
                    ),
                    (
                        "/usr/bin/install -o root -g root -m 0644",
                        "/usr/bin/install -m 0644",
                    ),
                    (
                        '[[ "$command" == "/usr/bin/apt-get update" ]]',
                        f'[[ "$command" == "{update}" ]]',
                    ),
                    (
                        '[[ "$command" == "/usr/bin/apt-get clean" ]]',
                        f'[[ "$command" == "{clean}" ]]',
                    ),
                    (
                        "source /root/harness-m4-provision.sh",
                        f'source "{main}"',
                    ),
                )
                for original, replacement in replacements:
                    self.assertIn(original, local_entry)
                    local_entry = local_entry.replace(original, replacement, 1)
                wrapper = case_root / "entry.sh"
                wrapper.write_text(local_entry)
                result = subprocess.run(
                    ["/bin/bash", str(wrapper)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                    timeout=5,
                    text=True,
                )
                observations = (
                    self.launcher._extract_package_source_boundary_observations(
                        records.read_bytes()
                    )
                )
                self.assertEqual(
                    [observation["outcome"] for observation in observations],
                    expected_outcomes,
                )
                observation_lines = [
                    self.launcher._canonical(observation).decode("ascii")
                    for observation in observations
                ]
                stdout_lines = result.stdout.splitlines()
                if case_name == "exact":
                    self.assertEqual(result.returncode, 0)
                    self.launcher._require_exact_package_source_boundaries(
                        records.read_bytes()
                    )
                    self.assertEqual(
                        stdout_lines,
                        [
                            observation_lines[0], "APT_UPDATE", "APT_CLEAN",
                            observation_lines[1], "AFTER_BASE",
                        ],
                    )
                elif case_name == "wrong-before-apt":
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(stdout_lines, observation_lines)
                else:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(
                        stdout_lines,
                        [
                            observation_lines[0], "APT_UPDATE", "APT_CLEAN",
                            observation_lines[1],
                        ],
                    )
                self.assertEqual(result.stderr, "")

        changed = json.loads(self.launcher._canonical(plan))
        changed["package_sources"][final_path] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(
            self.launcher.QualificationStop, "PACKAGE_RUNTIME_PLAN_SEED_MISMATCH"
        ):
            self.launcher._ubuntu_source_seed_entry(changed)

        image_lab = self.root / "wrong-image-lab"
        image_lab.mkdir()
        wrong = image_lab / "apt-ubuntu.sources"
        wrong.write_bytes(b"x" * 321)
        os.chmod(wrong, 0o444)
        attempt_root = self.root / "wrong-seed"
        attempt_root.mkdir()
        source = {"commit": "a" * 40, "tree": "b" * 40}
        with (
            mock.patch.object(self.launcher, "IMAGE_LAB", image_lab),
            mock.patch.object(self.launcher, "_generate_key") as generate_key,
            mock.patch.object(self.launcher, "_run") as run,
            self.assertRaisesRegex(
                self.launcher.QualificationStop,
                "PACKAGE_RUNTIME_PLAN_SEED_MISMATCH",
            ),
        ):
            self.launcher._create_seed(
                attempt_root,
                attempt=1,
                source=source,
                package_runtime_plan=plan,
            )
        generate_key.assert_not_called()
        run.assert_not_called()

    def test_package_source_boundary_observation_parser_is_closed(self) -> None:
        expected = (
            "sha256:eafe8bd9490d039ddaa42d1ca6e2682b0a4e68fe13845aa47d8c195292574d55"
        )

        def record(boundary: str, outcome: str = "MATCH") -> dict[str, object]:
            return {
                "binding_id": "PACKAGE_SOURCE_UBUNTU",
                "boundary": boundary,
                "expected_sha256": expected,
                "non_authorizing": True,
                "observed_sha256": expected,
                "outcome": outcome,
                "record_type": "M4_PACKAGE_SOURCE_BOUNDARY_OBSERVATION",
            }

        before = record("BEFORE_APT_GET_UPDATE")
        after = record("AFTER_EXACT_PACKAGE_INSTALL_AND_CLEAN")
        exact_raw = b"\n".join(
            (self.launcher._canonical(before), self.launcher._canonical(after), b"")
        )
        self.assertEqual(
            self.launcher._extract_package_source_boundary_observations(exact_raw),
            [before, after],
        )
        before_prefix = self.launcher._canonical(before) + b"\n"
        self.assertEqual(
            self.launcher._extract_package_source_boundary_observations(
                before_prefix
            ),
            [before],
        )
        self.assertEqual(
            self.launcher._require_exact_package_source_boundaries(exact_raw),
            [before, after],
        )
        self.assertEqual(
            self.launcher._extract_package_source_boundary_observations(
                b"historical log without the token\n"
            ),
            [],
        )
        mismatch = {
            **before,
            "observed_sha256": "sha256:" + "0" * 64,
            "outcome": "MISMATCH",
        }
        read_error = {
            **after,
            "observed_sha256": None,
            "outcome": "READ_ERROR",
        }
        self.assertEqual(
            self.launcher._extract_package_source_boundary_observations(
                self.launcher._canonical(mismatch) + b"\n"
            ),
            [mismatch],
        )
        self.assertEqual(
            self.launcher._extract_package_source_boundary_observations(
                self.launcher._canonical(before)
                + b"\n"
                + self.launcher._canonical(read_error)
                + b"\n"
            ),
            [before, read_error],
        )

        malformed_cases = (
            json.dumps(before, sort_keys=True).encode("utf-8") + b"\n",
            self.launcher._canonical(before)
            + b"\n"
            + self.launcher._canonical(before)
            + b"\n",
            self.launcher._canonical({**before, "binding_id": "UNALLOWLISTED"})
            + b"\n",
            self.launcher._canonical({**before, "boundary": "UNALLOWLISTED"})
            + b"\n",
            self.launcher._canonical({**before, "boundary": []}) + b"\n",
            self.launcher._canonical({**before, "outcome": "UNALLOWLISTED"})
            + b"\n",
            self.launcher._canonical({**before, "outcome": []}) + b"\n",
            self.launcher._canonical({**before, "extra": "secret"}) + b"\n",
            before_prefix,
        )
        for raw in malformed_cases:
            with self.subTest(raw=raw[:80]), self.assertRaisesRegex(
                self.launcher.QualificationStop,
                "PACKAGE_SOURCE_BOUNDARY_OBSERVATION_MALFORMED",
            ):
                if raw == malformed_cases[-1]:
                    self.launcher._require_exact_package_source_boundaries(raw)
                else:
                    self.launcher._extract_package_source_boundary_observations(raw)

        prefix_root = self.root / "boundary-prefix-capture"
        prefix_root.mkdir()
        prefix_log = prefix_root / "provision.serial.log"
        prefix_log.write_bytes(before_prefix + b"provisioning failed\n")
        os.chmod(prefix_log, 0o600)
        prefix_capture = self.launcher._capture_post_v2_qemu_logs(prefix_root)
        self.assertEqual(
            prefix_capture["provision.serial.log"]["lines"][0],
            self.launcher._canonical(before).decode("utf-8"),
        )

        attempt_root = self.root / "boundary-log-capture"
        attempt_root.mkdir()
        ordinary = [f"ordinary-{index}" for index in range(140)]
        serial = (
            self.launcher._canonical(before)
            + b"\n"
            + "\n".join(ordinary).encode("ascii")
            + b"\n"
            + self.launcher._canonical(after)
            + b"\n"
        )
        serial_path = attempt_root / "provision.serial.log"
        serial_path.write_bytes(serial)
        os.chmod(serial_path, 0o600)
        captured = self.launcher._capture_post_v2_qemu_logs(attempt_root)
        retained = captured["provision.serial.log"]["lines"]
        self.assertEqual(
            retained[:2],
            [
                self.launcher._canonical(before).decode("utf-8"),
                self.launcher._canonical(after).decode("utf-8"),
            ],
        )
        self.assertLessEqual(len(retained), 128)

        provision_source = inspect.getsource(self.launcher._provision_vm)
        self.assertLess(
            provision_source.index("_require_exact_package_source_boundaries"),
            provision_source.index("_install_guest_file"),
        )
        for authority_path in (
            self.launcher._key_admission,
            self.launcher.AttemptLedger.admit,
        ):
            self.assertNotIn(
                "package_source_boundary", inspect.getsource(authority_path).casefold()
            )

    def test_v2_lab_qemu_and_ledger_never_continue_old_contracts(self) -> None:
        self.assertEqual(
            self.launcher.LAB,
            Path("/home/a1/Загрузки/harness/harness-m4-qualification-v2"),
        )
        self.assertEqual(
            self.launcher.USER_GOAL,
            Path(
                "/home/a1/.codex/attachments/4adf762e-32a5-45e2-bf75-3c79125ace23/"
                "pasted-text.txt"
            ),
        )
        self.assertNotEqual(self.launcher.OLD_LEDGER.parent, self.launcher.LAB)
        lifecycle = self.launcher._qemu_lifecycle(1)
        self.assertTrue(
            all("harness-m4-qualification-v2" in " ".join(argv) for argv in lifecycle.values())
        )

    def test_predecessor_artifacts_are_digest_checked_without_mutation(self) -> None:
        paths = [self.root / name for name in ("old-ledger", "diagnostic-ledger", "diagnostic")]
        for index, path in enumerate(paths):
            path.write_bytes(f"immutable-{index}\n".encode("ascii"))
            os.chmod(path, 0o444)
        digests = [self.launcher._digest_file(path, 1 << 20) for path in paths]
        before = [(path.read_bytes(), path.stat().st_mode) for path in paths]
        with (
            mock.patch.object(self.launcher, "OLD_LEDGER", paths[0]),
            mock.patch.object(self.launcher, "OLD_LEDGER_DIGEST", digests[0]),
            mock.patch.object(self.launcher, "PREDECESSOR_DIAGNOSTIC_LEDGER", paths[1]),
            mock.patch.object(
                self.launcher, "PREDECESSOR_DIAGNOSTIC_LEDGER_DIGEST", digests[1]
            ),
            mock.patch.object(self.launcher, "PREDECESSOR_DIAGNOSTIC_BUNDLE", paths[2]),
            mock.patch.object(
                self.launcher, "PREDECESSOR_DIAGNOSTIC_BUNDLE_DIGEST", digests[2]
            ),
        ):
            self.assertEqual(
                self.launcher._verify_qualification_predecessors(),
                {
                    "predecessor_qualification_ledger_digest": digests[0],
                    "predecessor_diagnostic_ledger_digest": digests[1],
                    "predecessor_diagnostic_bundle_digest": digests[2],
                },
            )
        self.assertEqual(before, [(path.read_bytes(), path.stat().st_mode) for path in paths])

        with (
            mock.patch.object(self.launcher, "OLD_LEDGER", paths[0]),
            mock.patch.object(
                self.launcher, "OLD_LEDGER_DIGEST", "sha256:" + "0" * 64
            ),
        ):
            with self.assertRaisesRegex(
                self.launcher.QualificationStop,
                "QUALIFICATION_PREDECESSOR_DIGEST_MISMATCH",
            ):
                self.launcher._verify_qualification_predecessors()

    def test_ledger_consumes_failed_slot_and_rejects_third_attempt(self) -> None:
        lab = self.root / "lab"
        goal_digest = self.launcher._digest_file(self.goal, 1 << 20)
        with self.launcher.AttemptLedger(
            lab,
            goal_reference=str(self.goal),
            goal_digest=goal_digest,
            clock=lambda: self.now,
        ) as ledger:
            first = ledger.begin(self._contract())
            ledger.terminalize(
                first, None, "FAILED", terminal_reason="PROVISION_FAILED"
            )
        with self.launcher.AttemptLedger(
            lab,
            goal_reference=str(self.goal),
            goal_digest=goal_digest,
            clock=lambda: self.now,
        ) as ledger:
            second = ledger.begin(
                self._contract(
                    2,
                    candidate="d" * 40,
                    tree="e" * 40,
                    source_archive_digest="sha256:" + "f" * 64,
                )
            )
            self.assertEqual(second.attempt, 2)
            ledger.terminalize(
                second, None, "FAILED", terminal_reason="RUN_FAILED"
            )
        with self.launcher.AttemptLedger(
            lab,
            goal_reference=str(self.goal),
            goal_digest=goal_digest,
            clock=lambda: self.now,
        ) as ledger:
            with self.assertRaisesRegex(
                self.launcher.QualificationStop, "ATTEMPT_LIMIT_REACHED"
            ):
                ledger.begin(
                    self._contract(
                        2,
                        candidate="1" * 40,
                        tree="2" * 40,
                        source_archive_digest="sha256:" + "3" * 64,
                    )
                )
        rows = [json.loads(line) for line in (lab / "m4-attempt-ledger.jsonl").read_bytes().splitlines()]
        self.assertEqual(
            [row["entry_type"] for row in rows],
            ["ATTEMPT_STARTED", "ATTEMPT_TERMINAL"] * 2,
        )
        self.assertTrue(all(row["ledger_version"] == "2.0.0" for row in rows))
        self.assertTrue(all(row["success_target_authorizing"] is False for row in rows))
        self.assertTrue(all("contract_core_digest" in row for row in rows))
        self.assertTrue(all("qualification_contract_digest" in row for row in rows))

    def test_admission_is_bound_before_success_terminal(self) -> None:
        lab = self.root / "lab"
        goal_digest = self.launcher._digest_file(self.goal, 1 << 20)
        with self.launcher.AttemptLedger(
            lab,
            goal_reference=str(self.goal),
            goal_digest=goal_digest,
            clock=lambda: self.now,
        ) as ledger:
            contract = self._contract()
            start = ledger.begin(contract)
            ready = self._ready(contract)
            admission = ledger.admit(start, ready)
            ledger.terminalize(
                start,
                admission,
                "BUNDLE_EXPORTED",
                terminal_reason="SIGNED_PAYLOAD_EXPORTED",
                manifest_digest="sha256:" + "6" * 64,
                signed_payload_bundle_digest="sha256:" + "7" * 64,
                qemu_phase_outcomes=self._phase_outcomes(start.attempt),
            )
        rows = [json.loads(line) for line in (lab / "m4-attempt-ledger.jsonl").read_bytes().splitlines()]
        self.assertEqual(rows[1]["attempt_start_digest"], start.digest)
        self.assertEqual(
            rows[1]["admitted_qualification_contract_digest"],
            start.qualification_contract_digest,
        )
        self.assertEqual(rows[2]["key_admission_digest"], admission)
        self.assertEqual(rows[2]["terminal_reason"], "SIGNED_PAYLOAD_EXPORTED")
        self.assertNotIn("aggregate_bundle_digest", rows[2])
        self.assertEqual(rows[2]["qemu_phase_outcomes"], self._phase_outcomes(1))

    def test_key_admission_rejects_v1_extra_and_substituted_exact_contract(self) -> None:
        lab = self.root / "lab"
        goal_digest = self.launcher._digest_file(self.goal, 1 << 20)
        with self.launcher.AttemptLedger(
            lab,
            goal_reference=str(self.goal),
            goal_digest=goal_digest,
            clock=lambda: self.now,
        ) as ledger:
            contract = self._contract()
            start = ledger.begin(contract)
            valid = self._ready(contract)
            substituted_contract = self._contract(candidate="d" * 40)
            mutations = (
                {**valid, "ready_version": "1.0.0"},
                {**valid, "extra": False},
                {key: value for key, value in valid.items() if key != "contract_core_digest"},
                {
                    **valid,
                    "qualification_contract": substituted_contract,
                    "qualification_contract_digest": (
                        self.launcher._qualification_contract_digest(substituted_contract)
                    ),
                    "contract_core_digest": substituted_contract["contract_core_digest"],
                },
            )
            for mutation in mutations:
                with self.subTest(keys=sorted(mutation)), self.assertRaises(
                    self.launcher.QualificationStop
                ):
                    ledger.admit(start, mutation)
            admission = ledger.admit(start, valid)
            ledger.terminalize(
                start,
                admission,
                "QUARANTINED",
                terminal_reason="RUN_FAILED",
            )
        rows = (lab / "m4-attempt-ledger.jsonl").read_bytes().splitlines()
        self.assertEqual(len(rows), 3)

    def test_host_generated_admission_has_minimal_nine_key_shape(self) -> None:
        lab = self.root / "lab"
        goal_digest = self.launcher._digest_file(self.goal, 1 << 20)
        with self.launcher.AttemptLedger(
            lab,
            goal_reference=str(self.goal),
            goal_digest=goal_digest,
            clock=lambda: self.now,
        ) as ledger:
            contract = self._contract()
            start = ledger.begin(contract)
            ready = self._ready(contract)
            digest = ledger.admit(start, ready)
            admission = self.launcher._key_admission(start, ready, digest)
            self.assertEqual(
                frozenset(admission),
                {
                    "admission_version", "mode", "qualification_contract",
                    "qualification_contract_digest", "contract_core_digest",
                    "ledger_entry_digest", "receipt_public_key_digests",
                    "supply_public_key_digest", "runtime_trust_digest",
                },
            )
            self.assertNotIn("candidate", admission)
            self.assertNotIn("environment", admission)
            self.assertNotIn("attempt", admission)
            ledger.terminalize(
                start,
                digest,
                "QUARANTINED",
                terminal_reason="RUN_FAILED",
            )

    def test_admitted_failure_uses_durable_active_admission(self) -> None:
        lab = self.root / "lab"
        goal_digest = self.launcher._digest_file(self.goal, 1 << 20)
        with self.launcher.AttemptLedger(
            lab,
            goal_reference=str(self.goal),
            goal_digest=goal_digest,
            clock=lambda: self.now,
        ) as ledger:
            contract = self._contract()
            start = ledger.begin(contract)
            admission = ledger.admit(start, self._ready(contract))
            self.assertEqual(ledger.active_admission, admission)
            ledger.terminalize(
                start,
                ledger.active_admission,
                "QUARANTINED",
                terminal_reason="RUN_FAILED",
            )
        rows = [
            json.loads(line)
            for line in (lab / "m4-attempt-ledger.jsonl").read_bytes().splitlines()
        ]
        self.assertEqual(
            [row["entry_type"] for row in rows],
            ["ATTEMPT_STARTED", "KEY_ADMITTED", "ATTEMPT_TERMINAL"],
        )
        self.assertEqual(rows[-1]["key_admission_digest"], admission)
        self.assertEqual(rows[-1]["terminal_reason"], "RUN_FAILED")
        self.assertIsNone(rows[-1]["qemu_phase_outcomes"])

    def test_ledger_rejects_unresolved_or_repeated_pair_and_wrong_metadata(self) -> None:
        lab = self.root / "lab"
        goal_digest = self.launcher._digest_file(self.goal, 1 << 20)
        with self.launcher.AttemptLedger(
            lab,
            goal_reference=str(self.goal),
            goal_digest=goal_digest,
            clock=lambda: self.now,
        ) as ledger:
            ledger.begin(self._contract())
        with self.assertRaisesRegex(
            self.launcher.QualificationStop, "PRIOR_ATTEMPT_UNRESOLVED"
        ):
            with self.launcher.AttemptLedger(
                lab,
                goal_reference=str(self.goal),
                goal_digest=goal_digest,
                clock=lambda: self.now,
            ):
                pass

        completed_lab = self.root / "completed-lab"
        with self.launcher.AttemptLedger(
            completed_lab,
            goal_reference=str(self.goal),
            goal_digest=goal_digest,
            clock=lambda: self.now,
        ) as ledger:
            completed = ledger.begin(self._contract())
            ledger.terminalize(
                completed, None, "FAILED", terminal_reason="PROVISION_FAILED"
            )
        with self.launcher.AttemptLedger(
            completed_lab,
            goal_reference=str(self.goal),
            goal_digest=goal_digest,
            clock=lambda: self.now,
        ) as ledger:
            with self.assertRaisesRegex(
                self.launcher.QualificationStop, "ATTEMPT_BINDING_MISMATCH"
            ):
                ledger.begin(
                    self._contract(
                        2,
                        goal_digest="sha256:" + "c" * 64,
                        source_archive_digest="sha256:" + "d" * 64,
                    )
                )
        os.chmod(lab / "m4-attempt-ledger.jsonl", 0o644)
        with self.assertRaisesRegex(self.launcher.QualificationStop, "LEDGER_UNTRUSTED"):
            with self.launcher.AttemptLedger(
                lab,
                goal_reference=str(self.goal),
                goal_digest=goal_digest,
                clock=lambda: self.now,
            ):
                pass

    def test_v2_ledger_rejects_v1_coherent_mutation_and_nonempty_new_lab(self) -> None:
        goal_digest = self.launcher._digest_file(self.goal, 1 << 20)

        occupied = self.root / "occupied"
        occupied.mkdir(mode=0o700)
        (occupied / "unexpected").write_bytes(b"not a v2 ledger")
        with self.assertRaisesRegex(
            self.launcher.QualificationStop, "QUALIFICATION_LAB_REUSE_FORBIDDEN"
        ):
            with self.launcher.AttemptLedger(
                occupied,
                goal_reference=str(self.goal),
                goal_digest=goal_digest,
                clock=lambda: self.now,
            ):
                pass
        self.assertFalse((occupied / "m4-attempt-ledger.jsonl").exists())

        v1 = self.root / "v1"
        v1.mkdir(mode=0o700)
        old = v1 / "m4-attempt-ledger.jsonl"
        old.write_bytes(
            self.launcher._canonical(
                {
                    "ledger_version": "1.0.0",
                    "sequence": 1,
                    "previous_entry_digest": None,
                    "entry_type": "ATTEMPT_STARTED",
                }
            )
            + b"\n"
        )
        os.chmod(old, 0o600)
        with self.assertRaises(self.launcher.QualificationStop):
            with self.launcher.AttemptLedger(
                v1,
                goal_reference=str(self.goal),
                goal_digest=goal_digest,
                clock=lambda: self.now,
            ):
                pass

        for field, replacement in (
            ("candidate", "9" * 40),
            ("tree", "8" * 40),
            ("environment", "sha256:" + "7" * 64),
            ("contract_core_digest", "sha256:" + "6" * 64),
            ("qualification_contract_digest", "sha256:" + "5" * 64),
            ("max_attempts", 3),
            ("success_target", 2),
            ("success_target_authorizing", True),
        ):
            lab = self.root / ("mutated-" + field)
            with self.launcher.AttemptLedger(
                lab,
                goal_reference=str(self.goal),
                goal_digest=goal_digest,
                clock=lambda: self.now,
            ) as ledger:
                start = ledger.begin(self._contract())
                ledger.terminalize(
                    start, None, "FAILED", terminal_reason="PROVISION_FAILED"
                )
            path = lab / "m4-attempt-ledger.jsonl"
            rows = [json.loads(line) for line in path.read_bytes().splitlines()]
            rows[0][field] = replacement
            first_raw = self.launcher._canonical(rows[0])
            rows[1]["previous_entry_digest"] = self.launcher._digest_bytes(first_raw)
            rows[1]["attempt_start_digest"] = self.launcher._digest_bytes(first_raw)
            path.write_bytes(first_raw + b"\n" + self.launcher._canonical(rows[1]) + b"\n")
            os.chmod(path, 0o600)
            with self.subTest(field=field), self.assertRaises(
                self.launcher.QualificationStop
            ):
                with self.launcher.AttemptLedger(
                    lab,
                    goal_reference=str(self.goal),
                    goal_digest=goal_digest,
                    clock=lambda: self.now,
                ):
                    pass

    def test_four_file_bundle_is_assembled_only_after_terminalization_without_cycle(self) -> None:
        lab = self.root / "lab"
        bundle = self.root / "bundle"
        bundle.mkdir(mode=0o700)
        goal_digest = self.launcher._digest_file(self.goal, 1 << 20)
        with self.launcher.AttemptLedger(
            lab,
            goal_reference=str(self.goal),
            goal_digest=goal_digest,
            clock=lambda: self.now,
        ) as ledger:
            contract = self._contract()
            start = ledger.begin(contract)
            admission = ledger.admit(start, self._ready(contract))
            projection = self.launcher._canonical(
                {
                    "bundle_version": "2.0.0",
                    "qualification_contract": contract,
                    "qualification_contract_digest": (
                        self.launcher._qualification_contract_digest(contract)
                    ),
                    "admission_digest": admission,
                }
            )
            for name, raw in (
                ("manifest.json", projection),
                ("manifest.sig", b"s" * 64),
                ("evidence.json", projection),
            ):
                path = bundle / name
                path.write_bytes(raw)
                os.chmod(path, 0o444)
            with self.assertRaisesRegex(
                self.launcher.QualificationStop, "LEDGER_NOT_TERMINAL"
            ):
                self.launcher._assemble_terminal_bundle(
                    bundle, lab / "m4-attempt-ledger.jsonl"
                )
            manifest_digest, signed_digest = self.launcher._signed_payload_digests(bundle)
            ledger.terminalize(
                start,
                admission,
                "BUNDLE_EXPORTED",
                terminal_reason="SIGNED_PAYLOAD_EXPORTED",
                manifest_digest=manifest_digest,
                signed_payload_bundle_digest=signed_digest,
                qemu_phase_outcomes=self._phase_outcomes(1),
            )
            embedded = self.launcher._assemble_terminal_bundle(
                bundle, lab / "m4-attempt-ledger.jsonl"
            )
        self.assertEqual(embedded, bundle / "attempt-ledger.jsonl")
        self.assertEqual(
            {item.name for item in bundle.iterdir()},
            {"manifest.json", "manifest.sig", "evidence.json", "attempt-ledger.jsonl"},
        )
        self.assertTrue(
            all(stat.S_IMODE(item.stat().st_mode) == 0o444 for item in bundle.iterdir())
        )
        terminal = json.loads(embedded.read_bytes().splitlines()[-1])
        self.assertEqual(terminal["terminal_reason"], "SIGNED_PAYLOAD_EXPORTED")
        self.assertEqual(terminal["signed_payload_bundle_digest"], signed_digest)
        self.assertNotIn("aggregate_bundle_digest", terminal)

    def test_export_is_not_independent_verification_and_does_not_reset_ceiling(self) -> None:
        lab = self.root / "lab"
        goal_digest = self.launcher._digest_file(self.goal, 1 << 20)
        with self.launcher.AttemptLedger(
            lab,
            goal_reference=str(self.goal),
            goal_digest=goal_digest,
            clock=lambda: self.now,
        ) as ledger:
            first_contract = self._contract()
            first = ledger.begin(first_contract)
            admission = ledger.admit(first, self._ready(first_contract))
            ledger.terminalize(
                first,
                admission,
                "BUNDLE_EXPORTED",
                terminal_reason="SIGNED_PAYLOAD_EXPORTED",
                manifest_digest="sha256:" + "6" * 64,
                signed_payload_bundle_digest="sha256:" + "7" * 64,
                qemu_phase_outcomes=self._phase_outcomes(1),
            )
        with self.launcher.AttemptLedger(
            lab,
            goal_reference=str(self.goal),
            goal_digest=goal_digest,
            clock=lambda: self.now,
        ) as ledger:
            second = ledger.begin(
                self._contract(
                    2,
                    candidate="d" * 40,
                    tree="e" * 40,
                    source_archive_digest="sha256:" + "f" * 64,
                )
            )
            self.assertEqual(second.attempt, 2)
            ledger.terminalize(
                second,
                None,
                "FAILED",
                terminal_reason="EVIDENCE_VERIFICATION_FAILED",
            )
        rows = self.checker._ledger_entries(
            (lab / "m4-attempt-ledger.jsonl").read_bytes(),
            now=self.now,
            goal_reference=str(self.goal),
            goal_digest=goal_digest,
        )
        self.assertEqual(
            [row["entry_type"] for row, _digest in rows],
            [
                "ATTEMPT_STARTED",
                "KEY_ADMITTED",
                "ATTEMPT_TERMINAL",
                "ATTEMPT_STARTED",
                "ATTEMPT_TERMINAL",
            ],
        )
        with self.launcher.AttemptLedger(
            lab,
            goal_reference=str(self.goal),
            goal_digest=goal_digest,
            clock=lambda: self.now,
        ) as ledger:
            with self.assertRaisesRegex(
                self.launcher.QualificationStop, "ATTEMPT_LIMIT_REACHED"
            ):
                ledger.begin(
                    self._contract(
                        2,
                        candidate="1" * 40,
                        tree="2" * 40,
                        source_archive_digest="sha256:" + "3" * 64,
                    )
                )

    def test_independent_verification_record_prevents_second_attempt_after_reopen(self) -> None:
        lab = self.root / "lab"
        goal_digest = self.launcher._digest_file(self.goal, 1 << 20)
        payload = {
            "evidence.json": b"evidence",
            "manifest.json": b"manifest",
            "manifest.sig": b"s" * 64,
        }
        signed_files = {
            name: self.launcher._digest_bytes(raw) for name, raw in payload.items()
        }
        signed_payload = self.launcher._digest_bytes(
            self.launcher._canonical(signed_files)
        )
        with self.launcher.AttemptLedger(
            lab,
            goal_reference=str(self.goal),
            goal_digest=goal_digest,
            clock=lambda: self.now,
        ) as ledger:
            contract = self._contract()
            start = ledger.begin(contract)
            admission = ledger.admit(start, self._ready(contract))
            ledger.terminalize(
                start,
                admission,
                "BUNDLE_EXPORTED",
                terminal_reason="SIGNED_PAYLOAD_EXPORTED",
                manifest_digest=signed_files["manifest.json"],
                signed_payload_bundle_digest=signed_payload,
                qemu_phase_outcomes=self._phase_outcomes(1),
            )
            payload["attempt-ledger.jsonl"] = (lab / "m4-attempt-ledger.jsonl").read_bytes()
            files = {
                name: self.launcher._digest_bytes(raw) for name, raw in payload.items()
            }
            bundle = self.launcher.EVIDENCE_ROOT / "attempt-1" / "bundle"
            bundle.mkdir(mode=0o700, parents=True)
            for name, raw in payload.items():
                path = bundle / name
                path.write_bytes(raw)
                os.chmod(path, 0o444)
            self.launcher._record_independent_verification(
                ledger,
                {
                    "outcome": "VERIFIED",
                    "claim_status": (
                        "M4_EXACT_DISPOSABLE_TEST_PROFILE_RUNTIME_CONFORMANCE_VERIFIED"
                    ),
                    "commit": start.candidate,
                    "tree": start.tree,
                    "attempt": start.attempt,
                    "environment": start.environment,
                    "qualification_contract_digest": (
                        start.qualification_contract_digest
                    ),
                    "admission_digest": admission,
                    "manifest_digest": signed_files["manifest.json"],
                    "signed_payload_bundle_digest": signed_payload,
                    "aggregate_bundle_digest": self.launcher._digest_bytes(
                        self.launcher._canonical(files)
                    ),
                    "bundle_file_digests": files,
                },
            )
        with self.launcher.AttemptLedger(
            lab,
            goal_reference=str(self.goal),
            goal_digest=goal_digest,
            clock=lambda: self.now,
        ) as ledger:
            with self.assertRaisesRegex(
                self.launcher.QualificationStop, "QUALIFICATION_ALREADY_VERIFIED"
            ):
                ledger.begin(
                    self._contract(
                        2,
                        candidate="d" * 40,
                        tree="e" * 40,
                        source_archive_digest="sha256:" + "f" * 64,
                    )
                )

    def test_success_finalization_orders_terminal_embed_verify_then_cleanup(self) -> None:
        events: list[str] = []
        contract = self._contract()
        start = self.launcher.AttemptStart(
            1,
            "a" * 40,
            "b" * 40,
            contract["environment_digest"],
            contract["contract_core_digest"],
            self.launcher._qualification_contract_digest(contract),
            contract,
            "sha256:" + "1" * 64,
        )
        ledger = mock.Mock()
        ledger.terminalize.side_effect = lambda *args, **kwargs: events.append("terminal")
        ledger.lab = self.root / "lab"
        bundle = self.root / "bundle"
        attempt_root = self.root / "attempt-1"

        with mock.patch.object(
            self.launcher,
            "_signed_payload_digests",
            side_effect=lambda *args, **kwargs: (
                events.append("signed") or "sha256:" + "2" * 64,
                "sha256:" + "3" * 64,
            ),
        ), mock.patch.object(
            self.launcher,
            "_assemble_terminal_bundle",
            side_effect=lambda *args, **kwargs: events.append("embedded"),
        ), mock.patch.object(
            self.launcher,
            "_verify_bundle",
            side_effect=lambda *args, **kwargs: (
                events.append("verified") or {"outcome": "VERIFIED"}
            ),
        ), mock.patch.object(
            self.launcher,
            "_cleanup_attempt",
            side_effect=lambda *args, **kwargs: events.append("cleanup") or ["seed.iso"],
        ), mock.patch.object(
            self.launcher,
            "_record_independent_verification",
            side_effect=lambda *args, **kwargs: events.append("recorded"),
        ):
            verified, removed = self.launcher._finalize_exported_attempt(
                ledger=ledger,
                start=start,
                admission_digest="sha256:" + "4" * 64,
                bundle=bundle,
                phase_outcomes=self._phase_outcomes(1),
                attempt_root=attempt_root,
            )
        self.assertEqual(
            events,
            ["signed", "terminal", "embedded", "verified", "cleanup", "recorded"],
        )
        self.assertEqual(verified, {"outcome": "VERIFIED"})
        self.assertEqual(removed, ["seed.iso"])

    def test_diagnostic_ledger_is_separate_single_use_and_binds_terminal_reason(self) -> None:
        predecessor = self.root / "old-ledger.jsonl"
        old_rows = []
        previous = None
        sequence = 0
        for attempt in (1, 2):
            sequence += 1
            start = {
                "ledger_version": "1.0.0",
                "sequence": sequence,
                "previous_entry_digest": previous,
                "entry_type": "ATTEMPT_STARTED",
                "max_attempts": 2,
                "attempt": attempt,
            }
            raw = self.launcher._canonical(start)
            previous = self.launcher._digest_bytes(raw)
            old_rows.append(raw)
            sequence += 1
            terminal = {
                "ledger_version": "1.0.0",
                "sequence": sequence,
                "previous_entry_digest": previous,
                "entry_type": "ATTEMPT_TERMINAL",
                "max_attempts": 2,
                "attempt": attempt,
                "result": "QUARANTINED",
            }
            raw = self.launcher._canonical(terminal)
            previous = self.launcher._digest_bytes(raw)
            old_rows.append(raw)
        old_raw = b"\n".join(old_rows) + b"\n"
        predecessor.write_bytes(old_raw)
        os.chmod(predecessor, 0o600)
        old_digest = self.launcher._digest_bytes(old_raw)
        self.assertEqual(
            self.launcher._verify_diagnostic_predecessor(predecessor, old_digest),
            old_digest,
        )

        lab = self.root / "diagnostic-lab"
        goal_digest = self.launcher._digest_file(self.goal, 1 << 20)
        with self.launcher.DiagnosticLedger(
            lab,
            goal_reference=str(self.goal),
            goal_digest=goal_digest,
            predecessor_digest=old_digest,
            clock=lambda: self.now,
        ) as ledger:
            started = ledger.begin("a" * 40, "b" * 40, "sha256:" + "c" * 64)
            terminal_digest = ledger.terminalize(
                started,
                "SERVICE_FAILED_PRE_KEY_READY",
                diagnostic_bundle_digest="sha256:" + "d" * 64,
                key_ready_digest=None,
                systemd_properties_digest="sha256:" + "e" * 64,
                cleanup_digest="sha256:" + "f" * 64,
                qemu_phase_outcomes={
                    phase: {
                        "argv_digest": self.launcher._digest_bytes(
                            self.launcher._canonical(
                                self.launcher._qemu_argv(
                                    1, phase, lab=self.launcher.DIAGNOSTIC_LAB
                                )
                            )
                        ),
                        "return_code": 0 if phase == "provision" else 1,
                    }
                    for phase in ("provision", "run")
                },
            )
        rows = [
            json.loads(line)
            for line in (lab / "m4-key-ready-diagnostic-ledger.jsonl").read_bytes().splitlines()
        ]
        self.assertEqual([row["entry_type"] for row in rows], ["DIAGNOSTIC_STARTED", "DIAGNOSTIC_TERMINAL"])
        self.assertEqual(rows[-1]["terminal_reason"], "SERVICE_FAILED_PRE_KEY_READY")
        self.assertEqual(rows[-1]["previous_entry_digest"], started.digest)
        self.assertEqual(terminal_digest, self.launcher._digest_bytes(self.launcher._canonical(rows[-1])))
        self.assertEqual(predecessor.read_bytes(), old_raw)

        with self.launcher.DiagnosticLedger(
            lab,
            goal_reference=str(self.goal),
            goal_digest=goal_digest,
            predecessor_digest=old_digest,
            clock=lambda: self.now,
        ) as ledger:
            with self.assertRaisesRegex(
                self.launcher.QualificationStop, "DIAGNOSTIC_ATTEMPT_LIMIT_REACHED"
            ):
                ledger.begin("d" * 40, "e" * 40, "sha256:" + "f" * 64)

    def test_diagnostic_wait_distinguishes_service_timeout_qemu_and_ready_without_sleep(self) -> None:
        active = {
            "ActiveState": "activating",
            "SubState": "start",
            "Result": "success",
            "ExecMainCode": "0",
            "ExecMainStatus": "0",
        }
        failed = {
            "ActiveState": "failed",
            "SubState": "failed",
            "Result": "exit-code",
            "ExecMainCode": "1",
            "ExecMainStatus": "2",
        }
        ready = {
            "ready_version": "1.0.0",
            "candidate": "a" * 40,
            "environment": "sha256:" + "b" * 64,
            "attempt": 1,
            "receipt_public_key_digests": {
                role: "sha256:" + character * 64
                for role, character in (("M4_AUTHORITY", "1"), ("OBSERVER", "2"), ("PUBLISHER", "3"))
            },
            "supply_public_key_digest": "sha256:" + "4" * 64,
            "runtime_trust_digest": "sha256:" + "5" * 64,
        }

        class FakeQemu:
            def __init__(self, error: Exception | None = None) -> None:
                self.error = error
                self.process = mock.Mock(returncode=17)

            def require_alive(self) -> None:
                if self.error is not None:
                    raise self.error

        with (
            mock.patch.object(self.launcher, "_service_properties", return_value=failed),
            mock.patch.object(
                self.launcher,
                "_ssh_try",
                return_value=subprocess.CompletedProcess([], 1, b"", b"absent"),
            ),
            mock.patch.object(self.launcher.time, "sleep") as sleep,
        ):
            observed = self.launcher._wait_key_ready_diagnostic(
                FakeQemu(), Path("client"), Path("known"), "unit",
                timeout=90, clock=lambda: 0.0,
            )
        self.assertEqual(observed["terminal_reason"], "SERVICE_FAILED_PRE_KEY_READY")
        self.assertEqual(observed["systemd_properties"], failed)
        sleep.assert_not_called()

        clock_values = iter((0.0, 0.0, 91.0))
        with (
            mock.patch.object(self.launcher, "_service_properties", return_value=active),
            mock.patch.object(
                self.launcher,
                "_ssh_try",
                return_value=subprocess.CompletedProcess([], 1, b"", b"absent"),
            ),
            mock.patch.object(self.launcher.time, "sleep") as sleep,
        ):
            observed = self.launcher._wait_key_ready_diagnostic(
                FakeQemu(), Path("client"), Path("known"), "unit",
                timeout=90, clock=lambda: next(clock_values),
            )
        self.assertEqual(observed["terminal_reason"], "KEY_READY_TIMEOUT")
        self.assertEqual(observed["systemd_properties"], active)
        sleep.assert_called_once_with(0.5)

        with mock.patch.object(self.launcher, "_service_properties") as properties:
            observed = self.launcher._wait_key_ready_diagnostic(
                FakeQemu(self.launcher.QualificationStop("QEMU_EXITED_EARLY")),
                Path("client"), Path("known"), "unit", timeout=90, clock=lambda: 0.0,
            )
        self.assertEqual(observed["terminal_reason"], "QEMU_EXITED")
        self.assertEqual(observed["qemu_return_code"], 17)
        properties.assert_not_called()

        with (
            mock.patch.object(self.launcher, "_service_properties", return_value=active),
            mock.patch.object(
                self.launcher,
                "_ssh_try",
                return_value=subprocess.CompletedProcess([], 0, self.launcher._canonical(ready), b""),
            ),
            mock.patch.object(self.launcher.time, "sleep") as sleep,
        ):
            observed = self.launcher._wait_key_ready_diagnostic(
                FakeQemu(), Path("client"), Path("known"), "unit",
                timeout=90, clock=lambda: 0.0,
            )
        self.assertEqual(observed["terminal_reason"], "KEY_READY_REACHED")
        self.assertEqual(observed["key_ready"], ready)
        sleep.assert_not_called()

    def test_systemd_properties_are_fetched_in_one_closed_query(self) -> None:
        raw = b"\n".join(
            f"{name}=value-{index}".encode("ascii")
            for index, name in enumerate(self.launcher._SERVICE_PROPERTIES)
        ) + b"\n"
        with mock.patch.object(self.launcher, "_ssh", return_value=raw) as ssh:
            value = self.launcher._service_properties(Path("client"), Path("known"), "unit")
        self.assertEqual(frozenset(value), frozenset(self.launcher._SERVICE_PROPERTIES))
        command = ssh.call_args.args[2]
        self.assertEqual(command.count("--property"), 5)
        self.assertEqual(ssh.call_count, 1)
        with mock.patch.object(self.launcher, "_ssh", return_value=b"ActiveState=failed\n"):
            with self.assertRaisesRegex(
                self.launcher.QualificationStop, "SYSTEMD_PROPERTIES_MALFORMED"
            ):
                self.launcher._service_properties(Path("client"), Path("known"), "unit")

    def test_diagnostic_bundle_is_closed_bounded_and_secret_free(self) -> None:
        digest = "sha256:" + "a" * 64
        record = {
            "diagnostic_version": "1.0.0",
            "claim": "M4_KEY_READY_PRE_ADMISSION_DIAGNOSTIC_ONLY",
            "status": "NOT_ATTESTED",
            "candidate": "b" * 40,
            "tree": "c" * 40,
            "environment": digest,
            "user_scope_reference": str(self.goal),
            "user_goal_digest": digest,
            "predecessor_qualification_ledger_digest": digest,
            "diagnostic_start_digest": digest,
            "attempt": 1,
            "boot_id": "12345678-1234-1234-1234-123456789abc",
            "terminal_reason": "SERVICE_FAILED_PRE_KEY_READY",
            "systemd_properties": {
                "ActiveState": "failed", "SubState": "failed", "Result": "exit-code",
                "ExecMainCode": "1", "ExecMainStatus": "2",
            },
            "unit_journal": ["normal line", "-----BEGIN PRIVATE KEY----- secret"],
            "kernel_events": ["apparmor=DENIED profile=harness-m4-lx-a.publisher"],
            "stage_markers": [
                {"record_type": "M4_PRE_KEY_STAGE", "stage": "SERVICE_ENTERED", "non_authorizing": True}
            ],
            "artifact_digests": {"runner": digest, "service": digest, "profile": digest},
            "qemu_phase_outcomes": {
                phase: {
                    "argv_digest": self.launcher._digest_bytes(
                        self.launcher._canonical(
                            self.launcher._qemu_argv(
                                1, phase, lab=self.launcher.DIAGNOSTIC_LAB
                            )
                        )
                    ),
                    "return_code": 0 if phase == "provision" else 1,
                }
                for phase in ("provision", "run")
            },
        }
        sanitized = self.launcher._sanitize_diagnostic_record(record)
        bundle = self.launcher._materialize_diagnostic_bundle(self.root / "diagnostic", sanitized)
        raw = bundle.read_bytes()
        self.assertNotIn(b"PRIVATE KEY", raw)
        self.assertNotIn(b"secret", raw.lower())
        self.assertEqual(self.launcher._read_diagnostic_bundle(bundle), sanitized)
        self.assertEqual(oct(os.stat(bundle).st_mode & 0o777), "0o444")

        malformed = self.root / "malformed.json"
        malformed.write_bytes(b"{")
        os.chmod(malformed, 0o444)
        with self.assertRaises(self.launcher.QualificationStop):
            self.launcher._read_diagnostic_bundle(malformed)
        oversized = self.root / "oversized.json"
        oversized.write_bytes(b"x" * ((1 << 20) + 1))
        os.chmod(oversized, 0o444)
        with self.assertRaises(self.launcher.QualificationStop):
            self.launcher._read_diagnostic_bundle(oversized)
        linked = self.root / "linked.json"
        linked.symlink_to(bundle)
        with self.assertRaises(self.launcher.QualificationStop):
            self.launcher._read_diagnostic_bundle(linked)

    def test_diagnostic_cleanup_removes_all_disposable_inputs_but_preserves_bundle(self) -> None:
        lab = self.root / "diagnostic-lab"
        runs = lab / "runs"
        runs.mkdir(parents=True)
        attempt_root = runs / "attempt-1"
        attempt_root.mkdir(mode=0o700)
        for name in self.launcher._DIAGNOSTIC_DISPOSABLE_NAMES:
            (attempt_root / name).write_bytes(b"disposable")
        preserved = lab / "diagnostics" / "attempt-1" / "diagnostic.json"
        preserved.parent.mkdir(parents=True)
        preserved.write_bytes(b"preserved")
        removed = self.launcher._cleanup_diagnostic_attempt(attempt_root, lab=lab)
        self.assertEqual(set(removed), set(self.launcher._DIAGNOSTIC_DISPOSABLE_NAMES))
        self.assertFalse(attempt_root.exists())
        self.assertEqual(preserved.read_bytes(), b"preserved")

        outside = self.root / "outside"
        outside.write_bytes(b"keep")
        attempt_root.mkdir(mode=0o700)
        (attempt_root / self.launcher._DIAGNOSTIC_DISPOSABLE_NAMES[0]).symlink_to(outside)
        with self.assertRaisesRegex(self.launcher.QualificationStop, "CLEANUP_TARGET_MISMATCH"):
            self.launcher._cleanup_diagnostic_attempt(attempt_root, lab=lab)
        self.assertEqual(outside.read_bytes(), b"keep")

    def test_diagnostic_collection_is_unit_scoped_bounded_and_extracts_only_stage_markers(self) -> None:
        unit = "harness-m4-controller@run.service"

        class FakeQemu:
            def require_alive(self) -> None:
                return None

        service = b"\n".join(
            (
                self.launcher._canonical(
                    {
                        "record_type": "M4_PRE_KEY_STAGE",
                        "stage": "SERVICE_ENTERED",
                        "non_authorizing": True,
                    }
                ),
                b"Traceback: apparmor_parser failed",
            )
        )
        kernel = b"ordinary kernel line\napparmor=DENIED profile=harness\nOOM killed process\n"
        with mock.patch.object(
            self.launcher, "_ssh", side_effect=(service, kernel)
        ) as ssh:
            (
                unit_lines,
                kernel_lines,
                markers,
                package_observation,
            ) = self.launcher._collect_pre_key_diagnostics(
                FakeQemu(), Path("client"), Path("known"), unit
            )
        self.assertEqual(len(ssh.call_args_list), 2)
        self.assertIn("--unit", ssh.call_args_list[0].args[2])
        self.assertIn(unit, ssh.call_args_list[0].args[2])
        self.assertIn("--lines=512", ssh.call_args_list[0].args[2])
        self.assertEqual(ssh.call_args_list[0].kwargs["maximum"], 1 << 20)
        self.assertIn("Traceback: apparmor_parser failed", unit_lines)
        self.assertEqual(kernel_lines, ["apparmor=DENIED profile=harness", "OOM killed process"])
        self.assertEqual([item["stage"] for item in markers], ["SERVICE_ENTERED"])
        self.assertIsNone(package_observation)

    def test_post_v2_package_runtime_plan_observation_parser_is_closed_and_ordered(
        self,
    ) -> None:
        expected_ids = (
            "PROVISIONING_SCRIPT",
            "PACKAGE_VERSION_APPARMOR",
            "PACKAGE_VERSION_APPARMOR_UTILS",
            "PACKAGE_VERSION_BUBBLEWRAP",
            "PACKAGE_VERSION_LIBSSL3T64",
            "PACKAGE_VERSION_OPENSSL",
            "PACKAGE_VERSION_PYTHON3_12",
            "PACKAGE_SOURCE_APT_HARNESS_M4",
            "PACKAGE_SOURCE_UBUNTU",
            "RUNTIME_CONFIG_HOSTS",
            "RUNTIME_CONFIG_NFTABLES_OFFLINE",
            "RUNTIME_CONFIG_NFTABLES_PROVISIONING",
            "RUNTIME_TOOL_AA_EXEC",
            "RUNTIME_TOOL_BWRAP",
            "RUNTIME_TOOL_OPENSSL",
            "RUNTIME_TOOL_PYTHON3_12",
            "RUNTIME_TOOL_LIBCRYPTO",
            "RUNTIME_TOOL_APPARMOR_PARSER",
        )
        expected_outcomes = frozenset(
            {
                "MISMATCH",
                "QUERY_ERROR",
                "DECODE_ERROR",
                "READ_ERROR",
                "RESOLVE_ERROR",
            }
        )
        self.assertEqual(
            self.launcher.PACKAGE_RUNTIME_PLAN_BINDING_IDS, expected_ids
        )
        self.assertEqual(
            self.launcher.PACKAGE_RUNTIME_PLAN_OUTCOMES, expected_outcomes
        )
        self.assertEqual(len(frozenset(expected_ids)), 18)
        observation = {
            "binding_id": "RUNTIME_TOOL_LIBCRYPTO",
            "non_authorizing": True,
            "outcome": "RESOLVE_ERROR",
            "record_type": "M4_PACKAGE_RUNTIME_PLAN_OBSERVATION",
        }
        terminal = {
            "outcome": "STOP",
            "reason": "PACKAGE_RUNTIME_PLAN_BINDING_MISMATCH",
            "status": "NOT_ATTESTED",
        }
        stage = {
            "record_type": "M4_PRE_KEY_STAGE",
            "stage": "SERVICE_ENTERED",
            "non_authorizing": True,
        }

        def journal(*rows: object) -> bytes:
            return b"\n".join(self.launcher._canonical(row) for row in rows) + b"\n"

        self.assertEqual(
            self.launcher._extract_package_runtime_plan_observation(
                journal(stage, observation, terminal)
            ),
            observation,
        )

        class FakeQemu:
            def require_alive(self) -> None:
                return None

        with mock.patch.object(
            self.launcher,
            "_ssh",
            side_effect=(
                journal(stage, observation, terminal),
                self.launcher.QualificationStop("KERNEL_JOURNAL_UNAVAILABLE"),
            ),
        ):
            (
                unit_lines,
                kernel_lines,
                markers,
                collected_observation,
            ) = self.launcher._collect_pre_key_diagnostics(
                FakeQemu(),
                Path("client"),
                Path("known"),
                "harness-m4-controller@run.service",
                require_package_runtime_plan_observation=True,
            )
        self.assertEqual(collected_observation, observation)
        self.assertIn(
            self.launcher._canonical(observation).decode("utf-8"), unit_lines
        )
        self.assertEqual(
            kernel_lines, ["UNAVAILABLE:SSH_DIAGNOSTIC_COLLECTION_FAILED"]
        )
        self.assertEqual([item["stage"] for item in markers], ["SERVICE_ENTERED"])
        for binding_id in expected_ids:
            with self.subTest(binding_id=binding_id):
                self.assertEqual(
                    self.launcher._extract_package_runtime_plan_observation(
                        journal(
                            {**observation, "binding_id": binding_id}, terminal
                        )
                    )["binding_id"],
                    binding_id,
                )
        for outcome in expected_outcomes:
            with self.subTest(outcome=outcome):
                self.assertEqual(
                    self.launcher._extract_package_runtime_plan_observation(
                        journal({**observation, "outcome": outcome}, terminal)
                    )["outcome"],
                    outcome,
                )
        noncanonical_observation = json.dumps(
            observation, sort_keys=True
        ).encode("utf-8")
        duplicate_key_observation = (
            b'{"binding_id":"RUNTIME_TOOL_LIBCRYPTO",'
            b'"binding_id":"RUNTIME_TOOL_LIBCRYPTO",'
            b'"non_authorizing":true,"outcome":"RESOLVE_ERROR",'
            b'"record_type":"M4_PACKAGE_RUNTIME_PLAN_OBSERVATION"}'
        )
        for name, raw, reason in (
            (
                "missing",
                journal(stage, terminal),
                "POST_V2_PACKAGE_RUNTIME_PLAN_OBSERVATION_MISSING",
            ),
            (
                "duplicate",
                journal(observation, observation, terminal),
                "POST_V2_PACKAGE_RUNTIME_PLAN_OBSERVATION_DUPLICATE",
            ),
            (
                "noncanonical-full-record",
                noncanonical_observation
                + b"\n"
                + self.launcher._canonical(terminal)
                + b"\n",
                "POST_V2_PACKAGE_RUNTIME_PLAN_OBSERVATION_MALFORMED",
            ),
            (
                "duplicate-key",
                duplicate_key_observation
                + b"\n"
                + self.launcher._canonical(terminal)
                + b"\n",
                "POST_V2_PACKAGE_RUNTIME_PLAN_OBSERVATION_MALFORMED",
            ),
            (
                "invalid-utf8",
                self.launcher._canonical(observation)[:-1]
                + b',"x":"\xff"}\n'
                + self.launcher._canonical(terminal)
                + b"\n",
                "POST_V2_PACKAGE_RUNTIME_PLAN_OBSERVATION_MALFORMED",
            ),
            (
                "unknown-field",
                journal({**observation, "extra": True}, terminal),
                "POST_V2_PACKAGE_RUNTIME_PLAN_OBSERVATION_MALFORMED",
            ),
            (
                "unknown-binding",
                journal({**observation, "binding_id": "UNKNOWN"}, terminal),
                "POST_V2_PACKAGE_RUNTIME_PLAN_OBSERVATION_UNKNOWN",
            ),
            (
                "unknown-outcome",
                journal({**observation, "outcome": "UNKNOWN"}, terminal),
                "POST_V2_PACKAGE_RUNTIME_PLAN_OBSERVATION_UNKNOWN",
            ),
            (
                "wrong-order",
                journal(terminal, observation),
                "POST_V2_PACKAGE_RUNTIME_PLAN_OBSERVATION_ORDER_MISMATCH",
            ),
            (
                "missing-terminal",
                journal(observation),
                "POST_V2_PACKAGE_RUNTIME_PLAN_OBSERVATION_ORDER_MISMATCH",
            ),
            (
                "duplicate-terminal",
                journal(observation, terminal, terminal),
                "POST_V2_PACKAGE_RUNTIME_PLAN_OBSERVATION_ORDER_MISMATCH",
            ),
            (
                "noncanonical-terminal",
                self.launcher._canonical(observation)
                + b"\n"
                + json.dumps(terminal, sort_keys=True).encode("utf-8")
                + b"\n",
                "POST_V2_PACKAGE_RUNTIME_PLAN_OBSERVATION_ORDER_MISMATCH",
            ),
            (
                "oversized",
                (
                    b'{"record_type":"M4_PACKAGE_RUNTIME_PLAN_OBSERVATION","x":"'
                    + b"x" * 1025
                    + b'"}\n'
                    + self.launcher._canonical(terminal)
                    + b"\n"
                ),
                "POST_V2_PACKAGE_RUNTIME_PLAN_OBSERVATION_MALFORMED",
            ),
        ):
            with self.subTest(name=name), self.assertRaisesRegex(
                self.launcher.QualificationStop, reason
            ):
                self.launcher._extract_package_runtime_plan_observation(raw)

        post_v2_source = inspect.getsource(
            self.launcher._run_post_v2_diagnostic_vm_phase
        )
        self.assertIn("require_package_runtime_plan_observation=True", post_v2_source)
        for ordinary in (
            self.launcher._run_vm_phase,
            self.launcher._run_diagnostic_vm_phase,
            self.launcher._key_ready_diagnostic,
        ):
            self.assertNotIn(
                "package_runtime_plan_observation",
                inspect.getsource(ordinary),
            )

    def test_diagnostic_mode_has_only_provision_run_and_never_admits_or_recovers(self) -> None:
        lifecycle = self.launcher._qemu_lifecycle(
            1,
            lab=self.root / "diagnostic-lab",
            phases=("provision", "run"),
        )
        self.assertEqual(frozenset(lifecycle), {"provision", "run"})
        self.assertIn("restrict=off", " ".join(lifecycle["provision"]))
        self.assertIn("restrict=on", " ".join(lifecycle["run"]))
        source = inspect.getsource(self.launcher._key_ready_diagnostic)
        self.assertIn("_provision_vm", source)
        self.assertIn("_run_diagnostic_vm_phase", source)
        self.assertNotIn(".admit(", source)
        self.assertNotIn("key-admission.json", source)
        self.assertNotIn('"recover"', source)

    def test_post_v2_diagnostic_is_exact_single_use_and_captures_before_cleanup(self) -> None:
        failed_candidate = "a2336eb987364cc6bff0fdcdc7d7bfb8b21b3db8"
        failed_tree = "106facb47f1b203ed121917adfa7c885374d9fdc"
        failed_lab = self.root / "failed-v2"
        failed_goal_digest = self.launcher._digest_file(self.goal, 1 << 20)
        failed_contract = self.launcher._qualification_contract(
            goal_reference=str(self.goal),
            goal_digest=failed_goal_digest,
            candidate=failed_candidate,
            tree=failed_tree,
            attempt=1,
            source_files_digest="sha256:" + "a" * 64,
            source_archive_digest="sha256:" + "b" * 64,
            seed_digest="sha256:" + "c" * 64,
            package_runtime_plan_digest="sha256:" + "d" * 64,
            host_provenance_digest="sha256:" + "e" * 64,
        )
        with self.launcher.AttemptLedger(
            failed_lab,
            goal_reference=str(self.goal),
            goal_digest=failed_goal_digest,
            clock=lambda: self.now,
        ) as ledger:
            failed_start = ledger.begin(failed_contract)
            ledger.terminalize(
                failed_start, None, "FAILED", terminal_reason="KEY_READY_TIMEOUT"
            )
        failed_ledger = failed_lab / self.launcher.LEDGER_NAME
        failed_raw = failed_ledger.read_bytes()
        failed_digest = self.launcher._digest_bytes(failed_raw)
        self.assertEqual(
            self.launcher._verify_failed_v2_qualification_ledger(
                failed_ledger, failed_digest
            ),
            failed_digest,
        )
        failed_rows = [json.loads(line) for line in failed_raw.splitlines()]
        self.assertEqual(
            [row["entry_type"] for row in failed_rows],
            ["ATTEMPT_STARTED", "ATTEMPT_TERMINAL"],
        )
        self.assertEqual(failed_rows[-1]["terminal_reason"], "KEY_READY_TIMEOUT")
        self.assertIsNone(failed_rows[-1]["key_admission_digest"])
        mutated_predecessor = self.root / "mutated-v2-ledger.jsonl"
        failed_rows[-1]["terminal_reason"] = "RUN_FAILED"
        mutated_raw = b"\n".join(
            self.launcher._canonical(row) for row in failed_rows
        ) + b"\n"
        mutated_predecessor.write_bytes(mutated_raw)
        os.chmod(mutated_predecessor, 0o600)
        with self.assertRaisesRegex(
            self.launcher.QualificationStop,
            "POST_V2_PREDECESSOR_NOT_EXACT_FAILED_ATTEMPT",
        ):
            self.launcher._verify_failed_v2_qualification_ledger(
                mutated_predecessor,
                self.launcher._digest_bytes(mutated_raw),
            )

        goal = self.launcher._post_v2_diagnostic_goal_record()
        self.assertEqual(
            goal,
            {
                "goal_version": "1.0.0",
                "goal_kind": "M4_POST_V2_PRE_ADMISSION_DIAGNOSTIC",
                "user_scope_reference": (
                    "thread:/goal/m4-post-v2-pre-admission-diagnostic/2026-08-28"
                ),
                "predecessor_qualification_ledger_digest": (
                    "sha256:c80f4eb33b811b59a4f80aee5fdf781964b441d20e1620ca4b1f2b63f30c479a"
                ),
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
            },
        )
        goal_digest = self.launcher._digest_bytes(self.launcher._canonical(goal))
        self.assertEqual(len(self.launcher._canonical(goal)), 582)
        self.assertEqual(
            goal_digest,
            "sha256:7e171d5a592859fc7a49e91ec1dca61d11ec326bbe1083ee5511f70163b9bc70",
        )
        contract = self.launcher._post_v2_diagnostic_contract(
            goal_record=goal,
            candidate="c" * 40,
            tree="d" * 40,
            source_files_digest="sha256:" + "1" * 64,
            source_archive_digest="sha256:" + "2" * 64,
            seed_digest="sha256:" + "3" * 64,
            package_runtime_plan_digest="sha256:" + "4" * 64,
            host_provenance_digest="sha256:" + "5" * 64,
        )
        self.assertEqual(
            frozenset(contract),
            {
                "contract_core", "contract_core_digest",
                "environment_preimage", "environment_digest",
            },
        )
        core = contract["contract_core"]
        self.assertEqual(core["goal_record_digest"], goal_digest)
        self.assertEqual(core["failed_v2_candidate"], failed_candidate)
        self.assertEqual(core["failed_v2_tree"], failed_tree)
        self.assertEqual(core["max_attempts"], 1)
        self.assertIs(core["non_authorizing"], True)
        request = self.launcher._post_v2_diagnostic_request(contract)
        self.assertEqual(
            frozenset(request),
            {
                "request_version", "mode", "diagnostic_contract",
                "diagnostic_contract_digest",
            },
        )
        self.assertEqual(request["request_version"], "2.1.0")
        self.assertEqual(request["mode"], "POST_V2_PRE_ADMISSION_DIAGNOSTIC")
        ready = {
            "ready_version": "2.1.0",
            "mode": "POST_V2_PRE_ADMISSION_DIAGNOSTIC",
            "non_authorizing": True,
            "diagnostic_contract": contract,
            "diagnostic_contract_digest": (
                self.launcher._post_v2_diagnostic_contract_digest(contract)
            ),
            "contract_core_digest": contract["contract_core_digest"],
            "receipt_public_key_digests": {
                role: "sha256:" + character * 64
                for role, character in (
                    ("M4_AUTHORITY", "6"),
                    ("OBSERVER", "7"),
                    ("PUBLISHER", "8"),
                )
            },
            "supply_public_key_digest": "sha256:" + "9" * 64,
            "runtime_trust_digest": "sha256:" + "a" * 64,
        }
        self.assertEqual(
            self.launcher._validate_post_v2_key_ready(ready, contract), ready
        )
        with self.assertRaisesRegex(
            self.launcher.QualificationStop, "POST_V2_KEY_READY_MALFORMED"
        ):
            self.launcher._validate_post_v2_key_ready(
                {**ready, "non_authorizing": False}, contract
            )

        def rebound_core(**changes: object) -> dict[str, object]:
            changed = json.loads(self.launcher._canonical(contract))
            changed["contract_core"].update(changes)
            changed["contract_core_digest"] = self.launcher._digest_bytes(
                self.launcher._canonical(changed["contract_core"])
            )
            changed["environment_preimage"]["contract_core_digest"] = changed[
                "contract_core_digest"
            ]
            changed["environment_digest"] = self.launcher._digest_bytes(
                self.launcher._canonical(changed["environment_preimage"])
            )
            return changed

        for mutation in (
            {"attempt": True},
            {"max_attempts": True},
            {"candidate": failed_candidate},
            {"tree": failed_tree},
        ):
            with self.subTest(contract_mutation=mutation), self.assertRaises(
                self.launcher.QualificationStop
            ):
                self.launcher._validate_post_v2_diagnostic_contract(
                    rebound_core(**mutation)
                )

        lab = self.root / "post-v2-diagnostic"
        with self.launcher.PostV2DiagnosticLedger(
            lab,
            goal_record=goal,
            clock=lambda: self.now,
        ) as ledger:
            started = ledger.begin(contract)
            outcomes = {
                phase: {
                    "argv_digest": self.launcher._digest_bytes(
                        self.launcher._canonical(
                            self.launcher._qemu_argv(1, phase, lab=lab)
                        )
                    ),
                    "return_code": 0 if phase == "provision" else 1,
                }
                for phase in ("provision", "run")
            }
            attempt_root = lab / "runs" / "attempt-1"
            attempt_root.mkdir(parents=True, mode=0o700)
            for phase in ("provision", "run"):
                for suffix in ("qemu.log", "serial.log"):
                    path = attempt_root / f"{phase}.{suffix}"
                    path.write_text(
                        "ordinary line\n-----BEGIN PRIVATE KEY----- forbidden\n",
                        encoding="utf-8",
                    )
                    os.chmod(path, 0o600)
            self.assertFalse((attempt_root / "key-admission.json").exists())
            captured = self.launcher._capture_post_v2_qemu_logs(attempt_root)
            captured_raw = self.launcher._canonical(captured)
            self.assertNotIn(b"PRIVATE KEY", captured_raw)
            self.assertNotIn(b"forbidden", captured_raw)
            self.assertEqual(
                frozenset(captured),
                {
                    "provision.qemu.log", "provision.serial.log",
                    "run.qemu.log", "run.serial.log",
                },
            )
            unavailable = {
                name: "UNAVAILABLE" for name in self.launcher._SERVICE_PROPERTIES
            }
            artifact_digests = {
                name: "sha256:" + character * 64
                for name, character in (
                    ("host_launcher", "6"), ("runner", "7"),
                    ("service", "8"), ("profile", "9"),
                )
            }
            package_observation = {
                "binding_id": "RUNTIME_TOOL_LIBCRYPTO",
                "non_authorizing": True,
                "outcome": "MISMATCH",
                "record_type": "M4_PACKAGE_RUNTIME_PLAN_OBSERVATION",
            }
            aggregate_stop = {
                "outcome": "STOP",
                "reason": "PACKAGE_RUNTIME_PLAN_BINDING_MISMATCH",
                "status": "NOT_ATTESTED",
            }
            record = self.launcher._sanitize_post_v2_diagnostic_record(
                {
                    "diagnostic_version": "2.1.0",
                    "claim": "M4_POST_V2_PRE_ADMISSION_DIAGNOSTIC_ONLY",
                    "status": "NOT_ATTESTED",
                    "goal_record": goal,
                    "goal_record_digest": goal_digest,
                    "diagnostic_contract": contract,
                    "diagnostic_contract_digest": (
                        self.launcher._post_v2_diagnostic_contract_digest(contract)
                    ),
                    "contract_core_digest": contract["contract_core_digest"],
                    "diagnostic_start_digest": started.digest,
                    "boot_id": "UNAVAILABLE",
                    "observed_terminal_reason": "SERVICE_FAILED_PRE_KEY_READY",
                    "systemd_properties": unavailable,
                    "unit_journal": [
                        self.launcher._canonical(package_observation).decode("utf-8"),
                        self.launcher._canonical(aggregate_stop).decode("utf-8"),
                    ],
                    "kernel_events": ["apparmor=DENIED"],
                    "stage_markers": [],
                    "package_runtime_plan_observation": package_observation,
                    "artifact_digests": artifact_digests,
                    "qemu_phase_outcomes": outcomes,
                    "qemu_log_captures": captured,
                    "key_ready_digest": None,
                },
                lab=lab,
            )
            bundle = self.launcher._materialize_post_v2_diagnostic_bundle(
                lab, record
            )
            removed = self.launcher._cleanup_diagnostic_attempt(
                attempt_root, lab=lab
            )
            self.assertFalse(attempt_root.exists())
            retained = self.launcher._read_post_v2_diagnostic_bundle(
                bundle, lab=lab
            )
            self.assertEqual(retained["qemu_log_captures"], captured)
            self.assertEqual(
                retained["observed_terminal_reason"],
                "SERVICE_FAILED_PRE_KEY_READY",
            )
            self.assertNotIn("terminal_reason", retained)
            self.assertNotIn(b"key-admission.json", bundle.read_bytes())
            historical = dict(record)
            historical["diagnostic_version"] = "2.0.0"
            historical.pop("package_runtime_plan_observation")
            historical["unit_journal"] = ["historical unit failure"]
            self.assertIs(
                self.launcher._validate_post_v2_diagnostic_record(
                    historical, lab=lab
                ),
                historical,
            )
            historical_with_projection = dict(historical)
            historical_with_projection[
                "package_runtime_plan_observation"
            ] = package_observation
            with self.assertRaisesRegex(
                self.launcher.QualificationStop,
                "POST_V2_DIAGNOSTIC_RECORD_MALFORMED",
            ):
                self.launcher._validate_post_v2_diagnostic_record(
                    historical_with_projection, lab=lab
                )
            missing = dict(record)
            missing.pop("package_runtime_plan_observation")
            with self.assertRaisesRegex(
                self.launcher.QualificationStop,
                "POST_V2_DIAGNOSTIC_RECORD_MALFORMED",
            ):
                self.launcher._validate_post_v2_diagnostic_record(
                    missing, lab=lab
                )
            observation_line = self.launcher._canonical(
                package_observation
            ).decode("utf-8")
            aggregate_line = self.launcher._canonical(
                aggregate_stop
            ).decode("utf-8")
            for name, mutation in (
                (
                    "typed-projection-mismatch",
                    {
                        "package_runtime_plan_observation": {
                            **package_observation,
                            "binding_id": "PROVISIONING_SCRIPT",
                        }
                    },
                ),
                ("journal-observation-missing", {"unit_journal": [aggregate_line]}),
                (
                    "journal-observation-duplicate",
                    {
                        "unit_journal": [
                            observation_line,
                            observation_line,
                            aggregate_line,
                        ]
                    },
                ),
                (
                    "journal-observation-noncanonical-extra",
                    {
                        "unit_journal": [
                            observation_line,
                            json.dumps(package_observation, sort_keys=True),
                            aggregate_line,
                        ]
                    },
                ),
                (
                    "journal-order-reversed",
                    {"unit_journal": [aggregate_line, observation_line]},
                ),
                (
                    "journal-aggregate-missing",
                    {"unit_journal": [observation_line]},
                ),
                (
                    "journal-aggregate-duplicate",
                    {
                        "unit_journal": [
                            observation_line,
                            aggregate_line,
                            aggregate_line,
                        ]
                    },
                ),
                (
                    "journal-aggregate-noncanonical-extra",
                    {
                        "unit_journal": [
                            observation_line,
                            aggregate_line,
                            json.dumps(aggregate_stop, sort_keys=True),
                        ]
                    },
                ),
                (
                    "journal-aggregate-noncanonical",
                    {
                        "unit_journal": [
                            observation_line,
                            json.dumps(aggregate_stop, sort_keys=True),
                        ]
                    },
                ),
            ):
                changed = dict(record)
                changed.update(mutation)
                with self.subTest(name=name), self.assertRaisesRegex(
                    self.launcher.QualificationStop,
                    "POST_V2_DIAGNOSTIC_RECORD_MALFORMED",
                ):
                    self.launcher._validate_post_v2_diagnostic_record(
                        changed, lab=lab
                    )
            ledger.terminalize(
                started,
                "SERVICE_FAILED_PRE_KEY_READY",
                diagnostic_bundle_digest=self.launcher._digest_file(
                    bundle, 2 << 20
                ),
                key_ready_digest=None,
                systemd_properties_digest=self.launcher._digest_bytes(
                    self.launcher._canonical(unavailable)
                ),
                cleanup_digest=self.launcher._digest_bytes(
                    self.launcher._canonical(
                        {"complete": True, "removed": sorted(removed)}
                    )
                ),
                qemu_phase_outcomes=outcomes,
            )
        ledger_path = lab / "m4-post-v2-diagnostic-ledger.jsonl"
        rows = [json.loads(line) for line in ledger_path.read_bytes().splitlines()]
        self.assertEqual(
            [row["entry_type"] for row in rows],
            ["DIAGNOSTIC_STARTED", "DIAGNOSTIC_TERMINAL"],
        )
        self.assertNotIn("KEY_ADMITTED", {row["entry_type"] for row in rows})
        self.assertEqual(rows[0]["diagnostic_contract"], contract)
        self.assertEqual(rows[1]["diagnostic_start_digest"], started.digest)
        self.assertEqual(rows[1]["previous_entry_digest"], started.digest)
        self.assertEqual(
            rows[1]["terminal_reason"], "SERVICE_FAILED_PRE_KEY_READY"
        )
        self.assertNotIn("observed_terminal_reason", rows[1])
        self.assertTrue(all(row["max_attempts"] == 1 for row in rows))
        self.assertTrue(
            all(
                row["failed_qualification_v2_ledger_digest"]
                == goal["predecessor_qualification_ledger_digest"]
                for row in rows
            )
        )
        for field in ("sequence", "max_attempts", "attempt"):
            mutation_lab = self.root / f"ledger-{field}-float"
            mutation_lab.mkdir(mode=0o700)
            changed_rows = json.loads(json.dumps(rows))
            targets = changed_rows[:1] if field == "sequence" else changed_rows
            for row in targets:
                row[field] = 1.0
            first_raw = self.launcher._canonical(changed_rows[0])
            changed_rows[1]["previous_entry_digest"] = (
                self.launcher._digest_bytes(first_raw)
            )
            changed_rows[1]["diagnostic_start_digest"] = (
                self.launcher._digest_bytes(first_raw)
            )
            mutation_raw = first_raw + b"\n" + self.launcher._canonical(
                changed_rows[1]
            ) + b"\n"
            mutation_path = (
                mutation_lab / self.launcher.POST_V2_DIAGNOSTIC_LEDGER_NAME
            )
            mutation_path.write_bytes(mutation_raw)
            os.chmod(mutation_path, 0o600)
            with self.subTest(ledger_float_field=field), self.assertRaises(
                self.launcher.QualificationStop
            ):
                with self.launcher.PostV2DiagnosticLedger(
                    mutation_lab,
                    goal_record=goal,
                    clock=lambda: self.now,
                ):
                    pass
        with self.launcher.PostV2DiagnosticLedger(
            lab,
            goal_record=goal,
            clock=lambda: self.now,
        ) as ledger:
            with self.assertRaisesRegex(
                self.launcher.QualificationStop,
                "POST_V2_DIAGNOSTIC_ATTEMPT_LIMIT_REACHED",
            ):
                ledger.begin(contract)
        self.assertEqual(
            set(removed),
            {
                "provision.qemu.log", "provision.serial.log",
                "run.qemu.log", "run.serial.log",
            },
        )

        source = inspect.getsource(self.launcher._post_v2_pre_admission_diagnostic)
        self.assertLess(
            source.index("_capture_post_v2_qemu_logs"),
            source.index("_cleanup_diagnostic_attempt"),
        )
        for forbidden in (
            ".admit(", "_key_admission(", "key-admission.json",
            '"recover"', "_export_bundle(", "_verify_bundle(",
        ):
            self.assertNotIn(forbidden, source)

        immutable_paths = [
            self.root / "old-qualification-ledger.jsonl",
            self.root / "old-diagnostic-ledger.jsonl",
            self.root / "old-diagnostic-bundle.json",
        ]
        for index, path in enumerate(immutable_paths):
            path.write_bytes(f"immutable-{index}\n".encode("ascii"))
            os.chmod(path, 0o444)
        immutable_snapshot = [
            (path.read_bytes(), path.stat().st_mode) for path in immutable_paths
        ]
        crash_lab = self.root / "post-v2-after-start-failure"
        created_names = {
            "seed.iso", "ssh-client", "ssh-client.pub", "ssh-host",
            "ssh-host.pub", "user-data", "meta-data", "source.tgz",
        }

        def fake_seed(
            attempt_root: Path, **_kwargs: object
        ) -> tuple[Path, Path, Path]:
            for name in created_names:
                (attempt_root / name).write_bytes(b"disposable")
                os.chmod(attempt_root / name, 0o600)
            return (
                attempt_root / "seed.iso",
                attempt_root / "ssh-client",
                attempt_root / "ssh-host",
            )

        def fake_known_hosts(_public: Path, output: Path) -> None:
            output.write_bytes(b"known host\n")
            os.chmod(output, 0o600)

        def fake_overlay(attempt_root: Path) -> Path:
            overlay = attempt_root / "overlay.qcow2"
            overlay.write_bytes(b"overlay")
            os.chmod(overlay, 0o600)
            return overlay

        def phase_outcome(phase: str) -> dict[str, object]:
            return {
                "argv_digest": self.launcher._digest_bytes(
                    self.launcher._canonical(
                        self.launcher._qemu_argv(
                            1,
                            phase,
                            lab=self.launcher.POST_V2_DIAGNOSTIC_LAB,
                        )
                    )
                ),
                "return_code": 0,
            }

        def fake_provision(
            attempt_root: Path, *_args: object, **_kwargs: object
        ) -> tuple[list[Path], dict[str, object]]:
            for name in ("host-provenance.json", "qualification.json"):
                (attempt_root / name).write_bytes(b"disposable")
                os.chmod(attempt_root / name, 0o600)
            return [], phase_outcome("provision")

        def fake_run(*_args: object, **_kwargs: object) -> tuple[object, ...]:
            properties = {
                "ActiveState": "failed",
                "SubState": "failed",
                "Result": "exit-code",
                "ExecMainCode": "1",
                "ExecMainStatus": "1",
            }
            package_observation = {
                "binding_id": "RUNTIME_TOOL_LIBCRYPTO",
                "non_authorizing": True,
                "outcome": "RESOLVE_ERROR",
                "record_type": "M4_PACKAGE_RUNTIME_PLAN_OBSERVATION",
            }
            aggregate_stop = {
                "outcome": "STOP",
                "reason": "PACKAGE_RUNTIME_PLAN_BINDING_MISMATCH",
                "status": "NOT_ATTESTED",
            }
            return (
                {
                    "terminal_reason": "SERVICE_FAILED_PRE_KEY_READY",
                    "key_ready": None,
                    "systemd_properties": properties,
                    "qemu_return_code": None,
                },
                "12345678-1234-1234-1234-123456789abc",
                [
                    self.launcher._canonical(package_observation).decode("utf-8"),
                    self.launcher._canonical(aggregate_stop).decode("utf-8"),
                ],
                ["apparmor=DENIED"],
                [],
                package_observation,
                phase_outcome("run"),
            )

        with (
            mock.patch.object(
                self.launcher, "POST_V2_DIAGNOSTIC_LAB", crash_lab
            ),
            mock.patch.object(
                self.launcher,
                "_verify_failed_v2_qualification_ledger",
                return_value=goal["predecessor_qualification_ledger_digest"],
            ),
            mock.patch.object(
                self.launcher,
                "_source_state",
                return_value={
                    "commit": "e" * 40,
                    "tree": "f" * 40,
                    "files": {},
                    "files_digest": "sha256:" + "b" * 64,
                },
            ),
            mock.patch.object(
                self.launcher,
                "_profile",
                return_value=({}, self.launcher._M4_PROFILE_DIGEST),
            ),
            mock.patch.object(
                self.launcher,
                "_verify_host_assets",
                return_value=({"sha256": self.launcher._IMAGE_DIGEST}, "QEMU test"),
            ),
            mock.patch.object(self.launcher, "_verify_host_tools", return_value={}),
            mock.patch.object(self.launcher, "_verify_kvm"),
            mock.patch.object(self.launcher, "_verify_management_port_free"),
            mock.patch.object(self.launcher, "_verify_disk_budget", return_value=1),
            mock.patch.object(self.launcher, "_create_seed", side_effect=fake_seed),
            mock.patch.object(
                self.launcher, "_known_hosts", side_effect=fake_known_hosts
            ),
            mock.patch.object(
                self.launcher,
                "_host_provenance",
                return_value={"image": {}, "vm": {}},
            ),
            mock.patch.object(
                self.launcher, "_create_overlay", side_effect=fake_overlay
            ),
            mock.patch.object(
                self.launcher, "_provision_vm", side_effect=fake_provision
            ),
            mock.patch.object(
                self.launcher,
                "_run_post_v2_diagnostic_vm_phase",
                side_effect=fake_run,
            ),
            mock.patch.object(
                self.launcher,
                "_materialize_post_v2_diagnostic_bundle",
                side_effect=self.launcher.QualificationStop("CAPTURE_STORE_FAILED"),
            ) as materialize,
            mock.patch.object(self.launcher, "OLD_LEDGER", immutable_paths[0]),
            mock.patch.object(
                self.launcher, "PREDECESSOR_DIAGNOSTIC_LEDGER", immutable_paths[1]
            ),
            mock.patch.object(
                self.launcher, "PREDECESSOR_DIAGNOSTIC_BUNDLE", immutable_paths[2]
            ),
        ):
            with self.assertRaisesRegex(
                self.launcher.QualificationStop, "CAPTURE_STORE_FAILED"
            ):
                self.launcher._post_v2_pre_admission_diagnostic()
            self.assertFalse((crash_lab / "runs" / "attempt-1").exists())
            unproven_lab = self.root / "post-v2-vm-cleanup-unproven"
            self.launcher.POST_V2_DIAGNOSTIC_LAB = unproven_lab
            materialize.side_effect = self.launcher.VMCleanupUnproven(
                "VM_CLEANUP_UNPROVEN"
            )
            with self.assertRaisesRegex(
                self.launcher.VMCleanupUnproven, "VM_CLEANUP_UNPROVEN"
            ):
                self.launcher._post_v2_pre_admission_diagnostic()
        self.assertFalse((crash_lab / "runs" / "attempt-1").exists())
        self.assertTrue((unproven_lab / "runs" / "attempt-1").is_dir())
        self.assertEqual(
            immutable_snapshot,
            [(path.read_bytes(), path.stat().st_mode) for path in immutable_paths],
        )
        self.assertEqual(failed_ledger.read_bytes(), failed_raw)

        output = tempfile.TemporaryFile(mode="w+b")
        stdout = mock.Mock(buffer=output)
        with (
            mock.patch.object(self.launcher.sys, "stdout", stdout),
            mock.patch.object(
                self.launcher,
                "_post_v2_pre_admission_diagnostic",
                side_effect=self.launcher.QualificationStop("EXPECTED_FAILURE"),
            ),
        ):
            self.assertEqual(
                self.launcher.main(["--post-v2-pre-admission-diagnostic"]), 1
            )
        output.seek(0)
        failure = json.loads(output.read())
        output.close()
        self.assertEqual(
            failure["claim"], "M4_POST_V2_PRE_ADMISSION_DIAGNOSTIC_ONLY"
        )
        self.assertNotIn("M4_EXACT_DISPOSABLE", failure["claim"])

    def test_package_plan_discriminator_is_exact_bound_one_use_and_non_authorizing(
        self,
    ) -> None:
        goal = self.launcher._package_plan_discriminator_goal_record()
        self.assertEqual(goal["goal_kind"], "M4_PACKAGE_RUNTIME_PLAN_DISCRIMINATOR")
        self.assertEqual(goal["max_attempts"], 1)
        self.assertEqual(goal["success_target"], 1)
        self.assertIs(goal["success_target_authorizing"], False)
        self.assertEqual(
            goal["predecessor_qualification_ledger_digest"],
            self.launcher.FAILED_QUALIFICATION_V2_LEDGER_DIGEST,
        )
        self.assertEqual(
            goal["predecessor_post_v2_diagnostic_ledger_digest"],
            "sha256:e8cfa1b9117268bf2298ba1936a99a79114e8f83aea2188e998fce6becdf97dc",
        )
        self.assertEqual(
            goal["predecessor_post_v2_diagnostic_bundle_digest"],
            "sha256:51b84c6477a17a66e92290ed7cb6f787fb9df8f5445d112d76e3e38c055f6d2f",
        )
        self.assertEqual(
            self.launcher._digest_bytes(self.launcher._canonical(goal)),
            "sha256:44ff546b459a3e433b0b9ed1d009eb92c82b9fd1f3afc5f331a1ba0fe51115aa",
        )
        contract = self.launcher._post_v2_diagnostic_contract(
            goal_record=goal,
            candidate="e" * 40,
            tree="f" * 40,
            source_files_digest="sha256:" + "1" * 64,
            source_archive_digest="sha256:" + "2" * 64,
            seed_digest="sha256:" + "3" * 64,
            package_runtime_plan_digest="sha256:" + "4" * 64,
            host_provenance_digest="sha256:" + "5" * 64,
        )
        core = contract["contract_core"]
        self.assertEqual(core["contract_kind"], goal["goal_kind"])
        self.assertEqual(core["contract_version"], "1.0.0")
        for name in (
            "predecessor_post_v2_diagnostic_ledger_digest",
            "predecessor_post_v2_diagnostic_bundle_digest",
        ):
            self.assertEqual(core[name], goal[name])
        request = self.launcher._post_v2_diagnostic_request(contract)
        self.assertEqual(request["request_version"], "2.2.0")
        self.assertEqual(request["mode"], "M4_PACKAGE_RUNTIME_PLAN_DISCRIMINATOR")

        unavailable = {
            name: "UNAVAILABLE" for name in self.launcher._SERVICE_PROPERTIES
        }
        package_observation = {
            "binding_id": "RUNTIME_TOOL_LIBCRYPTO",
            "non_authorizing": True,
            "outcome": "MISMATCH",
            "record_type": "M4_PACKAGE_RUNTIME_PLAN_OBSERVATION",
        }
        class FakeQemu:
            process = type("Process", (), {"returncode": 0})()

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return None

            @staticmethod
            def alive() -> bool:
                return True

        for name, ready, collection, expected_error in (
            (
                "missing",
                None,
                [
                    self.launcher.QualificationStop(
                        "POST_V2_PACKAGE_RUNTIME_PLAN_OBSERVATION_MISSING"
                    ),
                    (["missing observation"], [], [], None),
                ],
                "MISSING",
            ),
            (
                "key-ready",
                {"unexpected": True},
                [(["observation", "stop"], [], [], package_observation)],
                "KEY_READY_FORBIDDEN",
            ),
            (
                "malformed-unbounded-recollection",
                None,
                [
                    self.launcher.QualificationStop(
                        "POST_V2_PACKAGE_RUNTIME_PLAN_OBSERVATION_MALFORMED"
                    ),
                    self.launcher.QualificationStop(
                        "DIAGNOSTIC_JOURNAL_UNBOUNDED"
                    ),
                ],
                "MALFORMED",
            ),
            (
                "malformed-oversized-line",
                None,
                [
                    self.launcher.QualificationStop(
                        "POST_V2_PACKAGE_RUNTIME_PLAN_OBSERVATION_MALFORMED"
                    ),
                    (["x" * 1025], [], [], None),
                ],
                "MALFORMED",
            ),
        ):
            with (
                self.subTest(name=name),
                mock.patch.object(self.launcher, "QemuProcess", return_value=FakeQemu()),
                mock.patch.object(self.launcher, "_wait_for_ssh"),
                mock.patch.object(
                    self.launcher,
                    "_guest_boot_id",
                    return_value="00000000-0000-0000-0000-000000000001",
                ),
                mock.patch.object(self.launcher, "_ssh"),
                mock.patch.object(
                    self.launcher,
                    "_wait_key_ready_diagnostic",
                    return_value={
                        "terminal_reason": (
                            "KEY_READY_REACHED"
                            if ready is not None
                            else "SERVICE_FAILED_PRE_KEY_READY"
                        ),
                        "key_ready": ready,
                        "systemd_properties": unavailable,
                        "qemu_return_code": None,
                    },
                ),
                mock.patch.object(
                    self.launcher,
                    "_collect_pre_key_diagnostics",
                    side_effect=collection,
                ),
                mock.patch.object(self.launcher, "_poweroff"),
                mock.patch.object(self.launcher, "_verify_management_port_free"),
                mock.patch.object(
                    self.launcher,
                    "_diagnostic_qemu_outcome",
                    return_value={
                        "argv_digest": "sha256:" + "a" * 64,
                        "return_code": 0,
                    },
                ),
            ):
                phase = self.launcher._run_post_v2_diagnostic_vm_phase(
                    self.root / "attempt-1",
                    self.root / "ssh-client",
                    self.root / "known-hosts",
                    contract,
                    lab=self.root / "phase-lab",
                )
            self.assertEqual(
                phase[5], {"package_runtime_plan_observation_error": expected_error}
            )
            self.assertEqual(
                phase[0]["terminal_reason"],
                "PACKAGE_RUNTIME_PLAN_OBSERVATION_REJECTED",
            )
            self.assertLessEqual(len(phase[2]), 512)
            self.assertTrue(all(len(line) <= 1024 for line in phase[2]))

        lab = self.root / "package-plan-discriminator"
        with self.launcher.PostV2DiagnosticLedger(
            lab, goal_record=goal, clock=lambda: self.now
        ) as ledger:
            start = ledger.begin(contract)
            outcomes = {
                phase: {
                    "argv_digest": self.launcher._digest_bytes(
                        self.launcher._canonical(
                            self.launcher._qemu_argv(1, phase, lab=lab)
                        )
                    ),
                    "return_code": 0,
                }
                for phase in ("provision", "run")
            }
            error_record = {
                "diagnostic_version": "2.3.0",
                "claim": "M4_PACKAGE_RUNTIME_PLAN_DISCRIMINATOR_ONLY",
                "status": "NOT_ATTESTED",
                "goal_record": goal,
                "goal_record_digest": self.launcher.PACKAGE_PLAN_DISCRIMINATOR_GOAL_DIGEST,
                "diagnostic_contract": contract,
                "diagnostic_contract_digest": (
                    self.launcher._post_v2_diagnostic_contract_digest(contract)
                ),
                "contract_core_digest": contract["contract_core_digest"],
                "diagnostic_start_digest": start.digest,
                "boot_id": "UNAVAILABLE",
                "observed_terminal_reason": (
                    "PACKAGE_RUNTIME_PLAN_OBSERVATION_REJECTED"
                ),
                "systemd_properties": unavailable,
                "unit_journal": ["missing observation"],
                "kernel_events": [],
                "stage_markers": [
                    {
                        "record_type": "M4_PRE_KEY_STAGE",
                        "stage": "SERVICE_ENTERED",
                        "non_authorizing": True,
                    }
                ],
                "package_runtime_plan_observation_error": "MISSING",
                "artifact_digests": {
                    name: "sha256:" + character * 64
                    for name, character in (
                        ("host_launcher", "1"), ("runner", "2"),
                        ("service", "3"), ("profile", "4"),
                    )
                },
                "qemu_phase_outcomes": outcomes,
                "qemu_log_captures": {
                    name: {"bytes": 0, "digest": None, "lines": []}
                    for name in (
                        "provision.qemu.log", "provision.serial.log",
                        "run.qemu.log", "run.serial.log",
                    )
                },
                "key_ready_digest": None,
            }
            bundle = self.launcher._materialize_post_v2_diagnostic_bundle(
                lab, error_record
            )
            bundle_digest = self.launcher._digest_file(bundle, 2 << 20)
            ledger.terminalize(
                start,
                "PACKAGE_RUNTIME_PLAN_OBSERVATION_REJECTED",
                diagnostic_bundle_digest=bundle_digest,
                key_ready_digest=None,
                systemd_properties_digest="sha256:" + "7" * 64,
                cleanup_digest="sha256:" + "8" * 64,
                qemu_phase_outcomes=outcomes,
            )
        ledger_path = lab / self.launcher.PACKAGE_PLAN_DISCRIMINATOR_LEDGER_NAME
        self.assertTrue(ledger_path.is_file())
        rows = [json.loads(line) for line in ledger_path.read_bytes().splitlines()]
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["max_attempts"], 1)
        self.assertEqual(rows[0]["success_target"], 1)
        self.assertIs(rows[0]["success_target_authorizing"], False)
        self.assertEqual(rows[1]["previous_entry_digest"], start.digest)
        self.assertEqual(rows[1]["diagnostic_bundle_digest"], bundle_digest)
        self.assertEqual(
            self.launcher._read_post_v2_diagnostic_bundle(bundle, lab=lab),
            error_record,
        )
        late_success = dict(error_record)
        late_success["diagnostic_version"] = "2.2.0"
        late_success.pop("package_runtime_plan_observation_error")
        late_success["package_runtime_plan_observation"] = package_observation
        late_success["observed_terminal_reason"] = "SERVICE_FAILED_PRE_KEY_READY"
        late_success["unit_journal"] = [
            self.launcher._canonical(package_observation).decode("utf-8"),
            self.launcher._canonical(
                {
                    "outcome": "STOP",
                    "reason": "PACKAGE_RUNTIME_PLAN_BINDING_MISMATCH",
                    "status": "NOT_ATTESTED",
                }
            ).decode("utf-8"),
        ]
        late_success["stage_markers"] = [
            *error_record["stage_markers"],
            {
                "record_type": "M4_PRE_KEY_STAGE",
                "stage": "REQUEST_VALIDATED",
                "non_authorizing": True,
            },
        ]
        with self.assertRaisesRegex(
            self.launcher.QualificationStop,
            "POST_V2_DIAGNOSTIC_RECORD_MALFORMED",
        ):
            self.launcher._validate_post_v2_diagnostic_record(
                late_success, lab=lab
            )
        with self.assertRaisesRegex(
            self.launcher.QualificationStop,
            "POST_V2_DIAGNOSTIC_ATTEMPT_LIMIT_REACHED",
        ):
            with self.launcher.PostV2DiagnosticLedger(
                lab, goal_record=goal, clock=lambda: self.now
            ) as ledger:
                ledger.ensure_available()

        self.assertEqual(
            self.launcher.PACKAGE_PLAN_DISCRIMINATOR_LAB,
            Path(
                "/home/a1/Загрузки/harness/"
                "harness-m4-package-plan-discriminator"
            ),
        )
        source = inspect.getsource(self.launcher._package_plan_discriminator)
        for forbidden in (
            ".admit(", "_key_admission(", '"recover"', "_export_bundle(",
            "_verify_bundle(", "_qualification(",
        ):
            self.assertNotIn(forbidden, source)
        pipeline = inspect.getsource(self.launcher._post_v2_pre_admission_diagnostic)
        self.assertLess(
            pipeline.index("_materialize_post_v2_diagnostic_bundle"),
            pipeline.index("_cleanup_diagnostic_attempt"),
        )
        self.assertLess(
            pipeline.index("_cleanup_diagnostic_attempt"),
            pipeline.index("ledger.terminalize"),
        )
        output = tempfile.TemporaryFile(mode="w+b")
        stdout = mock.Mock(buffer=output)
        with (
            mock.patch.object(self.launcher.sys, "stdout", stdout),
            mock.patch.object(
                self.launcher,
                "_package_plan_discriminator",
                side_effect=self.launcher.QualificationStop("EXPECTED_STOP"),
            ),
        ):
            self.assertEqual(
                self.launcher.main(["--package-runtime-plan-discriminator"]), 1
            )
        output.seek(0)
        failure = json.loads(output.read())
        output.close()
        self.assertEqual(
            failure["claim"], "M4_PACKAGE_RUNTIME_PLAN_DISCRIMINATOR_ONLY"
        )

    def test_one_use_scope_projection_is_closed_and_derives_unique_contract(
        self,
    ) -> None:
        launcher = self.launcher
        projection = {
            "record_version": "1.0.0",
            "record_kind": "M4_ONE_USE_QUALIFICATION_SCOPE_PROJECTION",
            "authority": "NONE",
            "user_scope_reference": (
                "thread:/goal/m4-one-use-qualification-contract/2026-08-28"
            ),
            "candidate": "a" * 40,
            "tree": "b" * 40,
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
        path = self.root / "scope.json"
        path.write_bytes(launcher._canonical(projection))
        os.chmod(path, 0o444)
        value, digest = launcher._read_one_use_scope_projection(path)
        self.assertEqual(value, projection)
        self.assertEqual(digest, launcher._digest_bytes(launcher._canonical(projection)))
        self.assertEqual(
            launcher._one_use_run_id(digest),
            "scope-" + digest.removeprefix("sha256:"),
        )
        changed_identity = {
            **projection,
            "candidate": "c" * 40,
            "tree": "d" * 40,
        }
        changed_digest = launcher._one_use_scope_projection_digest(
            changed_identity
        )
        self.assertNotEqual(changed_digest, digest)
        self.assertNotEqual(
            launcher._one_use_paths(changed_digest),
            launcher._one_use_paths(digest),
        )

        contract = launcher._one_use_qualification_contract(
            projection=projection,
            projection_digest=digest,
            source_files_digest="sha256:" + "1" * 64,
            source_archive_digest="sha256:" + "2" * 64,
            seed_digest="sha256:" + "3" * 64,
            package_runtime_plan_digest="sha256:" + "4" * 64,
            host_provenance_digest="sha256:" + "5" * 64,
        )
        core = contract["contract_core"]
        self.assertEqual(
            (core["contract_version"], core["contract_kind"], core["attempt"]),
            ("3.0.0", "M4_REQUEST_BOUND_ONE_USE_QUALIFICATION", 1),
        )
        self.assertEqual(core["scope_projection"], projection)
        self.assertEqual(core["user_goal_digest"], digest)
        self.assertEqual((core["max_attempts"], core["success_target"]), (1, 1))
        self.assertIs(core["success_target_authorizing"], False)
        self.assertEqual(launcher._validate_qualification_contract(contract), contract)

        bound_projection = json.loads(json.dumps(projection))
        projection["user_scope_reference"] = "thread:/mutated-after-binding"
        self.assertEqual(
            contract["contract_core"]["scope_projection"], bound_projection
        )
        with self.assertRaises(launcher.QualificationStop):
            launcher._one_use_qualification_contract(
                projection=projection,
                projection_digest=digest,
                source_files_digest="sha256:" + "1" * 64,
                source_archive_digest="sha256:" + "2" * 64,
                seed_digest="sha256:" + "3" * 64,
                package_runtime_plan_digest="sha256:" + "4" * 64,
                host_provenance_digest="sha256:" + "5" * 64,
            )
        projection = bound_projection

        malformed = [
            ("extra", {**projection, "unknown": True}),
            ("bool-max", {**projection, "max_attempts": True}),
            ("authority", {**projection, "authority": "QUALIFICATION"}),
            ("candidate", {**projection, "candidate": "A" * 40}),
            ("tree", {**projection, "tree": "not-a-tree"}),
            ("surrogate", {**projection, "user_scope_reference": "\ud800"}),
            (
                "old-predecessor",
                {
                    **projection,
                    "predecessor_diagnostic_ledger_digest": (
                        launcher.PREDECESSOR_DIAGNOSTIC_LEDGER_DIGEST
                    ),
                },
            ),
        ]
        for field in projection:
            value = dict(projection)
            value.pop(field)
            malformed.append(("missing-" + field, value))
        for name, mutation in malformed:
            with self.subTest(name=name), self.assertRaises(
                launcher.QualificationStop
            ):
                launcher._validate_one_use_scope_projection(mutation)
        os.chmod(path, 0o600)
        path.write_bytes(launcher._canonical(projection) + b"\n")
        os.chmod(path, 0o444)
        with self.assertRaises(launcher.QualificationStop):
            launcher._read_one_use_scope_projection(path)

        symlink = self.root / "scope-link.json"
        symlink.symlink_to(path)
        with self.assertRaises(launcher.QualificationStop):
            launcher._read_one_use_scope_projection(symlink)

        source_mismatch = {"commit": "0" * 40, "tree": "1" * 40}
        with (
            mock.patch.object(
                launcher,
                "_read_one_use_scope_projection",
                return_value=(projection, digest),
            ),
            mock.patch.object(launcher, "_verify_one_use_predecessors"),
            mock.patch.object(launcher, "_source_state", return_value=source_mismatch),
            mock.patch.object(launcher, "_profile") as profile,
            mock.patch.object(launcher, "QemuProcess") as qemu,
            self.assertRaisesRegex(
                launcher.QualificationStop, "ONE_USE_SOURCE_IDENTITY_MISMATCH"
            ),
        ):
            launcher._one_use_qualification(path)
        profile.assert_not_called()
        qemu.assert_not_called()

        with (
            mock.patch.object(launcher.Path, "cwd", return_value=self.root),
            mock.patch.object(
                launcher,
                "_read_one_use_scope_projection",
                return_value=(projection, digest),
            ) as read_scope,
            mock.patch.object(launcher, "_verify_one_use_predecessors"),
            mock.patch.object(launcher, "_source_state", return_value=source_mismatch),
            self.assertRaisesRegex(
                launcher.QualificationStop, "ONE_USE_SOURCE_IDENTITY_MISMATCH"
            ),
        ):
            launcher._one_use_qualification(Path("scope.json"))
        read_scope.assert_called_once_with(self.root / "scope.json")

        qualification_root = self.root / "qualification-root"
        evidence_root = self.root / "evidence-root"
        occupied_paths = launcher._one_use_paths(
            digest,
            qualification_root=qualification_root,
            evidence_root=evidence_root,
        )
        qualification_root.mkdir(mode=0o700)
        evidence_root.mkdir(mode=0o700)
        os.chmod(evidence_root, 0o755)
        with self.assertRaisesRegex(
            launcher.QualificationStop, "UNTRUSTED_DIRECTORY"
        ):
            launcher._prepare_one_use_paths(
                digest,
                qualification_root=qualification_root,
                evidence_root=evidence_root,
            )
        os.chmod(evidence_root, 0o700)
        occupied_paths.lab.mkdir(mode=0o700)
        with self.assertRaisesRegex(
            launcher.QualificationStop, "ONE_USE_RUN_ID_COLLISION"
        ):
            launcher._prepare_one_use_paths(
                digest,
                qualification_root=qualification_root,
                evidence_root=evidence_root,
            )

        fresh_collision = evidence_root / "fresh-collision"
        fresh_collision.mkdir(mode=0o700)
        with self.assertRaisesRegex(
            launcher.QualificationStop,
            "EVIDENCE_DESTINATION_REUSE_FORBIDDEN",
        ):
            launcher._mkdir_fresh_exact(
                fresh_collision,
                0o700,
                "EVIDENCE_DESTINATION_REUSE_FORBIDDEN",
            )
        second_digest = "sha256:" + "6" * 64
        second_paths = launcher._one_use_paths(
            second_digest,
            qualification_root=qualification_root,
            evidence_root=evidence_root,
        )
        second_paths.evidence.symlink_to(self.root / "outside")
        with self.assertRaisesRegex(
            launcher.QualificationStop, "ONE_USE_RUN_ID_COLLISION"
        ):
            launcher._prepare_one_use_paths(
                second_digest,
                qualification_root=qualification_root,
                evidence_root=evidence_root,
            )

        with tempfile.TemporaryDirectory(prefix="m4-one-use-ledger-") as directory:
            lab = Path(directory) / "lab"
            with launcher.AttemptLedger(
                lab,
                goal_reference=projection["user_scope_reference"],
                goal_digest=digest,
                one_use=True,
            ) as ledger:
                start = ledger.begin(contract)
                ledger.terminalize(
                    start,
                    None,
                    "FAILED",
                    terminal_reason="PROVISION_FAILED",
                )
            with launcher.AttemptLedger(
                lab,
                goal_reference=projection["user_scope_reference"],
                goal_digest=digest,
                one_use=True,
            ) as ledger:
                with self.assertRaisesRegex(
                    launcher.QualificationStop, "ATTEMPT_LIMIT_REACHED"
                ):
                    ledger.next_attempt()

            v2_contract = self._contract()
            with launcher.AttemptLedger(
                Path(directory) / "cross-v3",
                goal_reference=projection["user_scope_reference"],
                goal_digest=digest,
                one_use=True,
            ) as ledger:
                with self.assertRaises(launcher.QualificationStop):
                    ledger.begin(v2_contract)
            with launcher.AttemptLedger(
                Path(directory) / "cross-v2",
                goal_reference=str(self.goal),
                goal_digest=launcher._digest_file(self.goal, 1 << 20),
            ) as ledger:
                with self.assertRaises(launcher.QualificationStop):
                    ledger.begin(contract)

            success_lab = Path(directory) / "success-v3"
            ready = self._ready(contract)
            ready["ready_version"] = "3.0.0"
            outcomes = {
                phase: {
                    "argv_digest": launcher._digest_bytes(
                        launcher._canonical(
                            launcher._qemu_argv(1, phase, lab=success_lab)
                        )
                    ),
                    "return_code": 0,
                }
                for phase in ("provision", "run", "recover")
            }
            with launcher.AttemptLedger(
                success_lab,
                goal_reference=projection["user_scope_reference"],
                goal_digest=digest,
                one_use=True,
            ) as ledger:
                start = ledger.begin(contract)
                admission_digest = ledger.admit(start, ready)
                admission = launcher._key_admission(
                    start, ready, admission_digest
                )
                self.assertEqual(admission["admission_version"], "3.0.0")
                ledger.terminalize(
                    start,
                    admission_digest,
                    "BUNDLE_EXPORTED",
                    terminal_reason="SIGNED_PAYLOAD_EXPORTED",
                    manifest_digest="sha256:" + "7" * 64,
                    signed_payload_bundle_digest="sha256:" + "8" * 64,
                    qemu_phase_outcomes=outcomes,
                )
            with launcher.AttemptLedger(
                success_lab,
                goal_reference=projection["user_scope_reference"],
                goal_digest=digest,
                one_use=True,
            ) as ledger:
                with self.assertRaisesRegex(
                    launcher.QualificationStop, "ATTEMPT_LIMIT_REACHED"
                ):
                    ledger.next_attempt()

        changed_contract = json.loads(json.dumps(contract))
        changed_contract["contract_core"]["attempt"] = 2
        changed_contract["contract_core_digest"] = launcher._digest_bytes(
            launcher._canonical(changed_contract["contract_core"])
        )
        changed_contract["environment_preimage"]["contract_core_digest"] = (
            changed_contract["contract_core_digest"]
        )
        changed_contract["environment_digest"] = launcher._digest_bytes(
            launcher._canonical(changed_contract["environment_preimage"])
        )
        with self.assertRaises(launcher.QualificationStop):
            launcher._validate_one_use_qualification_contract(changed_contract)

        output = tempfile.TemporaryFile(mode="w+b")
        stdout = mock.Mock(buffer=output)
        with (
            mock.patch.object(launcher.sys, "stdout", stdout),
            mock.patch.object(
                launcher,
                "_one_use_qualification",
                side_effect=launcher.QualificationStop("EXPECTED_STOP"),
            ) as run,
        ):
            self.assertEqual(launcher.main(["--one-use-scope", str(path)]), 1)
        run.assert_called_once_with(path)
        output.close()


if __name__ == "__main__":
    unittest.main()
