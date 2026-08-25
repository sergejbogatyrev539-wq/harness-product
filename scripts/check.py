#!/usr/bin/env python3
"""One fail-closed repository and specification conformance gate."""

from __future__ import annotations

from hashlib import sha256
from importlib import metadata, util
import json
from pathlib import Path, PurePosixPath
import os
import re
import subprocess
import sys


sys.dont_write_bytecode = True


ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "spec"
MANIFEST = SPEC / "MANIFEST.sha256"
LINE = re.compile(r"^([0-9a-f]{64})  (.+)$")
UNIMPLEMENTED_STATUS = {
    "specification": "SPECIFIED",
    "implementation": "NOT_IMPLEMENTED",
    "evidence": "SPECIFICATION_MODEL_TESTED",
    "runtime_attestation": "NOT_ATTESTED",
    "overall": "NOT_READY",
    "scope": "IMPORTED_SPECIFICATION_AND_NON_EFFECTFUL_KERNEL_SCAFFOLD",
}


def stop(message: str) -> "NoReturn":
    raise SystemExit(f"STOP: {message}")


def verify_status(root: Path = ROOT) -> None:
    try:
        status = json.loads((root / "STATUS.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        stop(f"invalid status artifact: {error}")
    if status != UNIMPLEMENTED_STATUS:
        stop("runtime status advancement verifier is not implemented")


def verify_spec_manifest(spec: Path = SPEC, manifest: Path = MANIFEST) -> None:
    entries: dict[str, str] = {}
    for number, raw in enumerate(manifest.read_text(encoding="utf-8").splitlines(), 1):
        match = LINE.fullmatch(raw)
        if not match:
            stop(f"invalid spec manifest line {number}")
        digest, relative = match.groups()
        path = PurePosixPath(relative)
        if path.is_absolute() or ".." in path.parts or relative in entries:
            stop(f"unsafe or duplicate spec path: {relative}")
        entries[relative] = digest

    actual = {
        path.relative_to(spec).as_posix()
        for path in spec.rglob("*")
        if path.is_file() and path != manifest
    }
    if set(entries) != actual:
        stop(f"spec inventory mismatch missing={sorted(set(entries) - actual)} extra={sorted(actual - set(entries))}")
    for relative, expected in entries.items():
        observed = sha256((spec / relative).read_bytes()).hexdigest()
        if observed != expected:
            stop(f"spec digest mismatch: {relative}")
    if len(entries) != 48:
        stop(f"expected 48 transferred spec files, got {len(entries)}")


def compile_python() -> None:
    for base in (ROOT / "src", ROOT / "tests", ROOT / "scripts"):
        for path in base.rglob("*.py"):
            compile(path.read_bytes(), str(path), "exec")


def run_product_tests() -> None:
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONPATH"] = str(ROOT / "src")
    subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py", "-v"],
        cwd=ROOT,
        env=env,
        check=True,
    )


def jsonschema_cli() -> Path:
    try:
        installed = metadata.version("jsonschema")
    except metadata.PackageNotFoundError:
        stop("jsonschema distribution is required")
    if installed != "4.18.0":
        stop(f"jsonschema==4.18.0 is required, got {installed}")
    cli = Path(sys.executable).absolute().with_name("jsonschema")
    if not cli.is_file() or not os.access(cli, os.X_OK):
        stop(f"interpreter-local jsonschema CLI is required: {cli}")
    return cli


def run_specification_model() -> None:
    cli = jsonschema_cli()
    path = SPEC / "tests" / "run_checks.py"
    module_spec = util.spec_from_file_location("transferred_spec_checks", path)
    if module_spec is None or module_spec.loader is None:
        stop("cannot load transferred specification checks")
    module = util.module_from_spec(module_spec)
    module_spec.loader.exec_module(module)
    module.CLI = Path(cli)
    if module.main() != 0:
        stop("transferred specification checks failed")


def main() -> int:
    verify_status()
    verify_spec_manifest()
    compile_python()
    run_product_tests()
    run_specification_model()
    print("repository conformance: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
