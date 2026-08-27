from __future__ import annotations

from datetime import UTC, datetime
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest


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


if __name__ == "__main__":
    unittest.main()
