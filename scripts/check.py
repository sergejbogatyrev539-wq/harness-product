#!/usr/bin/env python3
"""One fail-closed repository and specification conformance gate."""

from __future__ import annotations

from hashlib import sha256
from importlib import util
from pathlib import Path, PurePosixPath
import os
import re
import shutil
import subprocess
import sys


sys.dont_write_bytecode = True


ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "spec"
MANIFEST = SPEC / "MANIFEST.sha256"
LINE = re.compile(r"^([0-9a-f]{64})  (.+)$")


def stop(message: str) -> "NoReturn":
    raise SystemExit(f"STOP: {message}")


def verify_spec_manifest() -> None:
    entries: dict[str, str] = {}
    for number, raw in enumerate(MANIFEST.read_text(encoding="utf-8").splitlines(), 1):
        match = LINE.fullmatch(raw)
        if not match:
            stop(f"invalid spec manifest line {number}")
        digest, relative = match.groups()
        path = PurePosixPath(relative)
        if path.is_absolute() or ".." in path.parts or relative in entries:
            stop(f"unsafe or duplicate spec path: {relative}")
        entries[relative] = digest

    actual = {
        path.relative_to(SPEC).as_posix()
        for path in SPEC.rglob("*")
        if path.is_file() and path != MANIFEST and "__pycache__" not in path.parts and path.suffix != ".pyc"
    }
    if set(entries) != actual:
        stop(f"spec inventory mismatch missing={sorted(set(entries) - actual)} extra={sorted(actual - set(entries))}")
    for relative, expected in entries.items():
        observed = sha256((SPEC / relative).read_bytes()).hexdigest()
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


def run_specification_model() -> None:
    cli = shutil.which("jsonschema")
    if cli is None:
        stop("jsonschema CLI is required")
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
    verify_spec_manifest()
    compile_python()
    run_product_tests()
    run_specification_model()
    print("repository conformance: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
