"""Non-skipping M3 exact-profile gate regressions.

The gate is intentionally unavailable on an unattested developer host.  These
tests verify that absence is a nonzero, structured result rather than a skip or
a weakened runtime launch.
"""

from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
import unittest

from harness_product.l0 import L0Outcome, compile_profile


ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "profiles" / "l0-lx-a.json"
GATE = ROOT / "scripts" / "check_m3_l0.py"


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


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


if __name__ == "__main__":
    unittest.main()
