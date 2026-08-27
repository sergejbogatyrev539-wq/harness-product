from __future__ import annotations

from datetime import UTC, datetime
import importlib.util
import inspect
import json
import os
from pathlib import Path
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

    def test_ledger_consumes_failed_slot_and_rejects_third_attempt(self) -> None:
        lab = self.root / "lab"
        goal_digest = self.launcher._digest_file(self.goal, 1 << 20)
        with self.launcher.AttemptLedger(
            lab,
            goal_reference=str(self.goal),
            goal_digest=goal_digest,
            clock=lambda: self.now,
        ) as ledger:
            first = ledger.begin("a" * 40, "b" * 40, "sha256:" + "c" * 64)
            ledger.terminalize(first, None, "BLOCKED")
        with self.launcher.AttemptLedger(
            lab,
            goal_reference=str(self.goal),
            goal_digest=goal_digest,
            clock=lambda: self.now,
        ) as ledger:
            second = ledger.begin("d" * 40, "e" * 40, "sha256:" + "f" * 64)
            self.assertEqual(second.attempt, 2)
            ledger.terminalize(second, None, "FAILED")
        with self.launcher.AttemptLedger(
            lab,
            goal_reference=str(self.goal),
            goal_digest=goal_digest,
            clock=lambda: self.now,
        ) as ledger:
            with self.assertRaisesRegex(
                self.launcher.QualificationStop, "ATTEMPT_LIMIT_REACHED"
            ):
                ledger.begin("1" * 40, "2" * 40, "sha256:" + "3" * 64)
        rows = [json.loads(line) for line in (lab / "m4-attempt-ledger.jsonl").read_bytes().splitlines()]
        self.assertEqual(
            [row["entry_type"] for row in rows],
            ["ATTEMPT_STARTED", "ATTEMPT_TERMINAL"] * 2,
        )

    def test_admission_is_bound_before_success_terminal(self) -> None:
        lab = self.root / "lab"
        goal_digest = self.launcher._digest_file(self.goal, 1 << 20)
        with self.launcher.AttemptLedger(
            lab,
            goal_reference=str(self.goal),
            goal_digest=goal_digest,
            clock=lambda: self.now,
        ) as ledger:
            start = ledger.begin("a" * 40, "b" * 40, "sha256:" + "c" * 64)
            ready = {
                "ready_version": "1.0.0",
                "candidate": start.candidate,
                "environment": start.environment,
                "attempt": start.attempt,
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
            admission = ledger.admit(start, ready)
            ledger.terminalize(
                start,
                admission,
                "BUNDLE_EXPORTED",
                manifest_digest="sha256:" + "6" * 64,
                bundle_digest="sha256:" + "7" * 64,
                qemu_phase_outcomes=self._phase_outcomes(start.attempt),
            )
        rows = [json.loads(line) for line in (lab / "m4-attempt-ledger.jsonl").read_bytes().splitlines()]
        self.assertEqual(rows[1]["attempt_start_digest"], start.digest)
        self.assertEqual(rows[2]["key_admission_digest"], admission)
        self.assertEqual(rows[2]["qemu_phase_outcomes"], self._phase_outcomes(1))

    def test_admitted_failure_uses_durable_active_admission(self) -> None:
        lab = self.root / "lab"
        goal_digest = self.launcher._digest_file(self.goal, 1 << 20)
        with self.launcher.AttemptLedger(
            lab,
            goal_reference=str(self.goal),
            goal_digest=goal_digest,
            clock=lambda: self.now,
        ) as ledger:
            start = ledger.begin("a" * 40, "b" * 40, "sha256:" + "c" * 64)
            admission = ledger.admit(
                start,
                {
                    "ready_version": "1.0.0",
                    "candidate": start.candidate,
                    "environment": start.environment,
                    "attempt": start.attempt,
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
                },
            )
            self.assertEqual(ledger.active_admission, admission)
            ledger.terminalize(start, ledger.active_admission, "QUARANTINED")
        rows = [
            json.loads(line)
            for line in (lab / "m4-attempt-ledger.jsonl").read_bytes().splitlines()
        ]
        self.assertEqual(
            [row["entry_type"] for row in rows],
            ["ATTEMPT_STARTED", "KEY_ADMITTED", "ATTEMPT_TERMINAL"],
        )
        self.assertEqual(rows[-1]["key_admission_digest"], admission)
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
            ledger.begin("a" * 40, "b" * 40, "sha256:" + "c" * 64)
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
            completed = ledger.begin("a" * 40, "b" * 40, "sha256:" + "c" * 64)
            ledger.terminalize(completed, None, "BLOCKED")
        with self.launcher.AttemptLedger(
            completed_lab,
            goal_reference=str(self.goal),
            goal_digest=goal_digest,
            clock=lambda: self.now,
        ) as ledger:
            with self.assertRaisesRegex(
                self.launcher.QualificationStop, "ATTEMPT_BINDING_MISMATCH"
            ):
                ledger.begin("a" * 40, "d" * 40, "sha256:" + "c" * 64)
        os.chmod(lab / "m4-attempt-ledger.jsonl", 0o644)
        with self.assertRaisesRegex(self.launcher.QualificationStop, "LEDGER_UNTRUSTED"):
            with self.launcher.AttemptLedger(
                lab,
                goal_reference=str(self.goal),
                goal_digest=goal_digest,
                clock=lambda: self.now,
            ):
                pass

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
            unit_lines, kernel_lines, markers = self.launcher._collect_pre_key_diagnostics(
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


if __name__ == "__main__":
    unittest.main()
