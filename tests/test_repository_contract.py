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
    def _assert_work_context(self, context: object) -> None:
        self.assertIs(type(context), dict)
        self.assertEqual(
            set(context),
            {"meta", "task", "invariant", "oracle", "progress", "qualification", "continuation", "notes"},
        )
        meta = context["meta"]
        self.assertEqual(
            meta,
            {
                "format_version": "1.0.0",
                "record_kind": "NON_AUTHORIZING_WORK_CONTEXT",
                "authority": "NONE",
                "owner": "ROOT_CONTROLLER",
            },
        )
        task = context["task"]
        self.assertEqual(
            set(task),
            {"task_id", "status", "user_scope_reference", "active_milestone", "last_product_commit"},
        )
        self.assertRegex(task["last_product_commit"], r"^[0-9a-f]{40}$")
        self.assertIn(task["status"], {"IDLE", "ACTIVE", "BLOCKED", "READY_FOR_GATE"})

        oracle = context["oracle"]
        progress = context["progress"]
        qualification = context["qualification"]
        continuation = context["continuation"]
        self.assertEqual(set(oracle), {"command", "expected"})
        self.assertEqual(set(progress), {"working_set", "last_check", "cause", "diagnostic_attempts"})
        self.assertEqual(set(qualification), {"candidate_environment_pair", "attempt_ledger", "vm_start"})
        self.assertEqual(set(continuation), {"next_step_hint", "automatic_continuation"})
        self.assertEqual(continuation["automatic_continuation"], "FORBIDDEN")
        self.assertIn(
            continuation["next_step_hint"],
            {
                "STOP_AWAIT_EXPLICIT_USER_GOAL",
                "REVALIDATE_USER_SCOPE_BEFORE_NEXT_STEP",
                "REPORT_BLOCKER_TO_USER",
                "AWAIT_FROZEN_REVIEW_PACKET",
            },
        )

        self.assertIs(type(progress["diagnostic_attempts"]), int)
        self.assertGreaterEqual(progress["diagnostic_attempts"], 0)
        self.assertLessEqual(progress["diagnostic_attempts"], 3)
        if progress["diagnostic_attempts"] == 3:
            self.assertEqual(task["status"], "BLOCKED")
        self.assertIsInstance(progress["working_set"], list)
        self.assertEqual(len(progress["working_set"]), len(set(progress["working_set"])))
        for relative in progress["working_set"]:
            self.assertIsInstance(relative, str)
            self.assertFalse(Path(relative).is_absolute())
            self.assertNotIn("..", Path(relative).parts)
        if progress["last_check"] is not None:
            self.assertEqual(set(progress["last_check"]), {"scope", "command", "result"})
            self.assertIn(progress["last_check"]["scope"], {"FOCUSED", "MODULE", "REPOSITORY", "HOST", "VM"})
            self.assertIn(progress["last_check"]["result"], {"PASS", "EXPECTED_NONZERO", "FAIL"})
            self.assertIsInstance(progress["last_check"]["command"], str)
            self.assertTrue(progress["last_check"]["command"])

        pair = qualification["candidate_environment_pair"]
        self.assertIn(qualification["attempt_ledger"], {"ABSENT", "PRESENT"})
        if qualification["attempt_ledger"] == "ABSENT":
            self.assertIsNone(pair)
            self.assertEqual(qualification["vm_start"], "FORBIDDEN_WITHOUT_REVIEWED_HOST_ENTRYPOINT")
        else:
            self.assertEqual(set(pair), {"candidate_digest", "environment_digest"})
            self.assertRegex(pair["candidate_digest"], r"^sha256:[0-9a-f]{64}$")
            self.assertRegex(pair["environment_digest"], r"^sha256:[0-9a-f]{64}$")
            self.assertIn(qualification["vm_start"], {"NOT_CONSUMED", "CONSUMED"})

        self.assertIsInstance(context["notes"], list)
        self.assertTrue(all(isinstance(note, str) and note for note in context["notes"]))
        if task["status"] == "IDLE":
            self.assertIsNone(task["task_id"])
            self.assertIsNone(task["user_scope_reference"])
            self.assertIsNone(task["active_milestone"])
            self.assertIsNone(context["invariant"])
            self.assertEqual(oracle, {"command": None, "expected": None})
            self.assertEqual(continuation["next_step_hint"], "STOP_AWAIT_EXPLICIT_USER_GOAL")
        else:
            self.assertRegex(task["task_id"], r"^[a-z0-9][a-z0-9._-]{0,63}$")
            self.assertIsInstance(task["user_scope_reference"], str)
            self.assertTrue(task["user_scope_reference"])
            self.assertIsInstance(task["active_milestone"], str)
            self.assertTrue(task["active_milestone"])
            self.assertIsInstance(context["invariant"], str)
            self.assertTrue(context["invariant"])
            self.assertIsInstance(oracle["command"], str)
            self.assertTrue(oracle["command"])
            self.assertIsInstance(oracle["expected"], str)
            self.assertTrue(oracle["expected"])
            self.assertTrue(progress["working_set"])

    def test_agent_workflow_is_closed_non_authorizing_and_compaction_safe(self) -> None:
        agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        normalized_agents = " ".join(agents.split())
        template_path = ROOT / "WORKING_CONTEXT.template.json"
        template = json.loads(template_path.read_text(encoding="utf-8"))

        required_rules = (
            "Read this entire file from first line to last.",
            "Repeat all four steps immediately after context compaction",
            "automatic_continuation` is always `FORBIDDEN`",
            "Do not run it after every small edit.",
            "Do not rerun an unchanged failed command without a new hypothesis.",
            "There is no reviewed host VM launcher or append-only attempt ledger",
            "A future reviewed host entrypoint must atomically consume one append-only attempt record",
            "A success target never enlarges an attempt ceiling.",
            "Do not start the next milestone or a new review cycle.",
            "a formally process-blind reviewer reads only its frozen review packet",
            "`scripts/check.py` is the sole repository-level development conformance harness.",
            "Every milestone implementation regression must be discoverable",
            "it is not host, VM, runtime, production, or attestation evidence.",
        )
        for rule in required_rules:
            self.assertIn(rule, normalized_agents)

        self.assertEqual(len(template_path.read_text(encoding="utf-8").splitlines()), 10)
        self._assert_work_context(template)
        self.assertIn(".agent/", (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines())
        live_path = ROOT / ".agent" / "WORKING_CONTEXT.json"
        if live_path.exists():
            self._assert_work_context(json.loads(live_path.read_text(encoding="utf-8")))

        for hint in ("COMPLETE_AUTHORIZED_COMMIT", "RUN_FULL_VM", "START_M4", "PATCH", "FREEZE", "REVIEW"):
            mutated = json.loads(json.dumps(template))
            mutated["continuation"]["next_step_hint"] = hint
            with self.subTest(hint=hint), self.assertRaises(AssertionError):
                self._assert_work_context(mutated)

        self.assertLessEqual(len(agents.splitlines()), 180)

    def test_scripts_check_is_the_single_discovering_development_harness(self) -> None:
        self.assertEqual(
            repository_check.__doc__,
            "The sole fail-closed repository development and specification conformance gate.",
        )
        with patch.object(repository_check.subprocess, "run") as run:
            repository_check.run_product_tests()
        run.assert_called_once()
        command = run.call_args.args[0]
        self.assertEqual(
            command,
            [
                repository_check.sys.executable,
                "-m",
                "unittest",
                "discover",
                "-s",
                "tests",
                "-p",
                "test_*.py",
                "-v",
            ],
        )
        self.assertEqual(run.call_args.kwargs["cwd"], ROOT)
        self.assertTrue(run.call_args.kwargs["check"])
        self.assertEqual(run.call_args.kwargs["env"]["PYTHONDONTWRITEBYTECODE"], "1")
        self.assertEqual(run.call_args.kwargs["env"]["PYTHONPATH"], str(ROOT / "src"))

        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertEqual(workflow.count("- run: python scripts/check.py"), 1)
        self.assertNotRegex(workflow, r"- run: python scripts/check_m[0-9]")

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

    def test_spec_manifest_rejects_control_character_names(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            spec = Path(directory) / "spec"
            shutil.copytree(SPEC, spec)
            manifest = spec / "MANIFEST.sha256"
            records = manifest.read_text(encoding="utf-8").splitlines()
            digest, relative = records[0].split("  ", 1)
            unsafe_relative = relative + "\t"
            (spec / relative).rename(spec / unsafe_relative)
            records[0] = f"{digest}  {unsafe_relative}"
            manifest.write_text("\n".join(records) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(SystemExit, "unsafe or duplicate spec path"):
                repository_check.verify_spec_manifest(spec, manifest)

    def test_spec_manifest_rejects_symlinked_entries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            spec = root / "spec"
            shutil.copytree(SPEC, spec)
            manifest = spec / "MANIFEST.sha256"
            _, relative = manifest.read_text(encoding="utf-8").splitlines()[0].split("  ", 1)
            listed = spec / relative
            external = root / "external-copy"
            external.write_bytes(listed.read_bytes())
            listed.unlink()
            listed.symlink_to(external)
            with self.assertRaisesRegex(SystemExit, "not a regular file"):
                repository_check.verify_spec_manifest(spec, manifest)

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
