#!/usr/bin/env python3
"""Non-skipping exact-profile M3 conformance availability gate."""

from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import sys


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from harness_product import l0  # noqa: E402


PROFILE = ROOT / "profiles" / "l0-lx-a.json"


def _digest_bytes(value: bytes) -> str:
    return "sha256:" + sha256(value).hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def main() -> int:
    try:
        profile_bytes = PROFILE.read_bytes()
        raw = json.loads(profile_bytes)
        compiled = l0.compile_profile(raw)
        result = l0.runtime_conformance(raw)
        runtime_actual = l0._binary_digest(l0.RUNTIME_PATH)
        code_artifacts = {
            path.relative_to(ROOT).as_posix(): _digest_bytes(path.read_bytes())
            for path in sorted((SRC / "harness_product").glob("*.py"))
        }
        kernel = {
            "architecture": platform.machine(),
            "kernel_release": platform.release(),
        }
        environment = {
            "gid": os.getgid(),
            "python": platform.python_version(),
            "uid": os.getuid(),
        }
        record = {
            "gate_version": 1,
            "claim": "M3_RUNTIME_CONFORMANCE",
            "outcome": result.outcome.value,
            "reason": result.reason.value,
            "command": [str(Path(sys.executable).resolve()), str(Path(__file__).resolve())],
            "code_artifacts": code_artifacts,
            "code_digest": _digest_bytes(_canonical(code_artifacts)),
            "gate_digest": _digest_bytes(Path(__file__).read_bytes()),
            "profile_artifact_digest": _digest_bytes(profile_bytes),
            "compiled_profile_digest": compiled.profile.profile_digest if compiled.profile is not None else "ABSENT",
            "runtime": {
                "path": l0.RUNTIME_PATH,
                "version": l0.RUNTIME_VERSION,
                "expected_digest": l0.RUNTIME_DIGEST,
                "actual_digest": runtime_actual,
            },
            "kernel_digest": _digest_bytes(_canonical(kernel)),
            "environment_digest": _digest_bytes(_canonical(environment)),
            "image_digest": "ABSENT",
            "registry_snapshot_digest": "ABSENT",
            "sbom_digest": "ABSENT",
            "external_supply_verifier": "ABSENT",
            "privileged_runtime_attestor": "ABSENT",
            "authoritative_tcb_event": "ABSENT",
            "negative_test": "tests.test_l0_conformance.L0ConformanceGateTests.test_unattested_gate_is_nonzero_absent_and_digest_bound",
            "status": "NOT_ATTESTED",
        }
    except Exception as error:  # noqa: BLE001 - a broken gate is ABSENT, never skipped
        record = {
            "gate_version": 1,
            "claim": "M3_RUNTIME_CONFORMANCE",
            "outcome": l0.L0Outcome.ABSENT.value,
            "reason": l0.L0Reason.HOST_FAILURE.value,
            "error_type": type(error).__name__,
            "status": "NOT_ATTESTED",
        }
    record["evidence_digest"] = _digest_bytes(_canonical(record))
    print(_canonical(record).decode("utf-8"))
    return 0 if record["outcome"] == "VERIFIED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
