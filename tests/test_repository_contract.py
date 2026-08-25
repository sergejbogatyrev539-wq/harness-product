from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from scripts import check as repository_check


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

    def test_status_advancement_stops_until_a_verifier_exists(self) -> None:
        repository_check.verify_status(ROOT)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            advanced = dict(repository_check.UNIMPLEMENTED_STATUS)
            advanced.update(implementation="ENFORCED", runtime_attestation="ATTESTED", overall="READY")
            (root / "STATUS.json").write_text(json.dumps(advanced), encoding="utf-8")
            evidence = root / "evidence"
            evidence.mkdir()
            (evidence / "runtime-conformance.json").write_text("arbitrary", encoding="utf-8")
            (evidence / "runtime-attestation.json").write_text("arbitrary", encoding="utf-8")
            with self.assertRaisesRegex(SystemExit, "status advancement verifier is not implemented"):
                repository_check.verify_status(root)

    def test_spec_manifest_rejects_cache_named_extra_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            spec = Path(directory) / "spec"
            shutil.copytree(SPEC, spec)
            extra = spec / "__pycache__" / "extra.pyc"
            extra.parent.mkdir()
            extra.write_bytes(b"not transferred")
            with self.assertRaisesRegex(SystemExit, "spec inventory mismatch"):
                repository_check.verify_spec_manifest(spec, spec / "MANIFEST.sha256")

    def test_jsonschema_version_contract_is_closed(self) -> None:
        for version in ("4.10.3", "4.18.1", "5.0.0", "unknown"):
            with patch.object(repository_check.metadata, "version", return_value=version):
                with self.assertRaises(SystemExit, msg=version):
                    repository_check.jsonschema_cli()

    def test_jsonschema_cli_must_belong_to_the_running_interpreter(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ambient = root / "ambient"
            local = root / "local"
            ambient.mkdir()
            local.mkdir()
            ambient_cli = ambient / "jsonschema"
            ambient_cli.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            ambient_cli.chmod(0o755)
            interpreter = local / "python"
            with (
                patch.object(repository_check.metadata, "version", return_value="4.18.0"),
                patch.object(repository_check.sys, "executable", str(interpreter)),
                patch.dict(os.environ, {"PATH": str(ambient)}),
            ):
                with self.assertRaisesRegex(SystemExit, "interpreter-local jsonschema CLI"):
                    repository_check.jsonschema_cli()

            local_cli = local / "jsonschema"
            local_cli.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            local_cli.chmod(0o755)
            with (
                patch.object(repository_check.metadata, "version", return_value="4.18.0"),
                patch.object(repository_check.sys, "executable", str(interpreter)),
            ):
                self.assertEqual(repository_check.jsonschema_cli(), local_cli)


if __name__ == "__main__":
    unittest.main()
