from __future__ import annotations

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "spec"


class RepositoryContractTests(unittest.TestCase):
    def test_required_spec_groups_are_present(self) -> None:
        documents = {
            "03_SYSTEM_THREAT_TRUST_MODEL.md",
            "04_FORMAL_CORE_AND_INVARIANTS.md",
            "10_LEVEL0_PHYSICAL_ISOLATION.md",
            "11_LEVEL1_EFFECT_SYSTEM.md",
            "12_LEVEL2_EFFECT_MANIFEST.md",
            "13_LEVEL3_RUNTIME_POLICY.md",
            "14_LEVEL4_OBSERVABILITY_RESPONSE.md",
            "15_LEVEL5_HUMAN_CONTROL.md",
            "16_CROSS_CUTTING_PLANES.md",
            "17_ATTACK_TEST_AND_EVIDENCE_MATRIX.md",
            "18_IMPLEMENTATION_ROADMAP_AND_ASSURANCE_CASE.md",
        }
        self.assertTrue(all((SPEC / name).is_file() for name in documents))
        self.assertEqual(len(list((SPEC / "schemas").glob("*.schema.json"))), 12)
        self.assertEqual(len(list((SPEC / "examples" / "valid").glob("*.json"))), 8)
        self.assertEqual(len(list((SPEC / "examples" / "invalid").glob("*.json"))), 8)

    def test_status_cannot_advance_without_evidence(self) -> None:
        status = json.loads((ROOT / "STATUS.json").read_text(encoding="utf-8"))
        required = {"specification", "implementation", "evidence", "runtime_attestation", "overall", "scope"}
        self.assertEqual(set(status), required)
        if status["implementation"] != "NOT_IMPLEMENTED":
            self.assertTrue((ROOT / "evidence" / "runtime-conformance.json").is_file())
        if status["runtime_attestation"] != "NOT_ATTESTED":
            self.assertTrue((ROOT / "evidence" / "runtime-attestation.json").is_file())
        if status["overall"] == "READY":
            self.assertEqual(status["implementation"], "ENFORCED")
            self.assertEqual(status["runtime_attestation"], "ATTESTED")


if __name__ == "__main__":
    unittest.main()
