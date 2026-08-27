#!/usr/bin/python3.12
"""Run the one disposable Ubuntu L0-LX-A qualification profile.

This command is guest-only.  It has no weaker backend and no developer-host
fallback.  ``run`` records an exact pre-restart result; ``recover`` verifies
that no prior process, cgroup, mount or writable layer survived and creates the
signed three-file bundle consumed by ``check_m3_l0.py``.
"""

from __future__ import annotations

import ctypes
from dataclasses import asdict, replace
from datetime import UTC, datetime, timedelta
import errno
import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path, PurePosixPath
import re
import resource
import select
import shutil
import signal
import socket
import sqlite3
import stat
import struct
import subprocess
import sys
import time
from typing import NoReturn


SOURCE = Path("/opt/harness-m3-source")
RUNTIME = Path("/var/lib/harness-m3-runtime")
CONTROLLER = Path("/var/lib/harness-m3-controller")
ATTESTOR = Path("/var/lib/harness-m3-attestor")
GUEST_EVIDENCE = Path("/var/lib/harness-m3-evidence")
GUEST_MARKER = Path("/etc/harness-m3/guest.json")
SOURCE_IDENTITY = Path("/etc/harness-m3/source-identity.json")
HOST_PROVENANCE = Path("/etc/harness-m3/host-provenance.json")
PROFILE = SOURCE / "profiles/l0-lx-a.json"
APPARMOR_POLICY = SOURCE / "profiles/l0-lx-a.apparmor"
SECCOMP_POLICY = SOURCE / "profiles/l0-lx-a-seccomp.json"
BROKER_SECCOMP_POLICY = SOURCE / "profiles/l0-lx-a-broker-seccomp.json"
EXECUTOR_SECCOMP_POLICY = SOURCE / "profiles/l0-lx-a-executor-seccomp.json"
ROOTFS_MANIFEST = SOURCE / "profiles/l0-lx-a-rootfs-manifest.json"
BROKER_SCHEMA = SOURCE / "profiles/l0-lx-a-broker-message.json"
TRUST_CONFIG = SOURCE / "profiles/l0-lx-a-test-attestor.json"
PRIVATE_KEY = ATTESTOR / "attestor-private.pem"
PUBLIC_KEY = Path("/etc/harness-m3/attestor-public.pem")
ATTESTOR_STATE = ATTESTOR / "state.json"
RUN_STATE = CONTROLLER / "run-state.json"

SOURCE_FIXED = (
    "AGENTS.md",
    "README.md",
    "ROADMAP.md",
    "SECURITY.md",
    "STATUS.json",
    "docs/ARCHITECTURE.md",
    "profiles/harness-m3-controller@.service",
    "spec/MANIFEST.sha256",
)

PYTHON = "/usr/bin/python3.12"
BWRAP = "/usr/bin/bwrap"
AA_EXEC = "/usr/bin/aa-exec"
OPENSSL = "/usr/bin/openssl"
LIBCRYPTO = "/usr/lib/x86_64-linux-gnu/libcrypto.so.3"
VERIFIER_CODE = SOURCE / "src/harness_product/verification.py"
APPARMOR_PARSER = "/usr/sbin/apparmor_parser"
MOUNT = "/usr/bin/mount"
UMOUNT = "/usr/bin/umount"
NSENTER = "/usr/bin/nsenter"

IMAGE_DIGEST = "sha256:6e40c07ae715f744f84af0bec76415cc1987dd115b4b8de437818561f01a3733"
BWRAP_DIGEST = "sha256:52231e1caf55bcbc667b269f49c63599a6f7db4767ae6a039580d0ff853db712"
AA_EXEC_DIGEST = "sha256:f28cbce3c8664cab5154492fdbc55ecb937a3e7ce1a9478c881a5f5965d7ce3e"
PYTHON_DIGEST = "sha256:1643dacd9feaedc58f3cc581e4d22577dfe25c09b10282936186ccf0f2e61118"
APPARMOR_PARSER_DIGEST = "sha256:6bc852b37807961c14976be9a227ae96bd817f73b5189cb0e0ff5eca4448c01c"
OPENSSL_DIGEST = "sha256:b86b739329008369aebe1f7cff6c2adb18965609d68a19456fca55232f2908f5"
BASE_SECCOMP_POLICY_DIGEST = "sha256:9cb79c8d1e8326a12f027bfdc05fae396be20c4cc84ca6dd62b84a569867e1ed"
PUBLIC_KEY_DIGEST = "sha256:dc1655a93a74ba69604cda200d6c103342e4dd764762765038566d1b7889b557"
LIBCRYPTO_DIGEST = "sha256:1451aceec262c3338052fa77542eb971d4ba311c6bf12d9aa70d0b56aca942f9"
VERIFIER_CODE_DIGEST = "sha256:b15162329e8cb2feb74e89cb2587d0e2f59c672702d402eac7c8dead141dcbeb"
KEY_ID = "harness-m3-test-ed25519-666ea1916c97e9c7"
TRUST_ROOT_ID = "harness-m3-disposable-test-root-20260826"
SIGNER_ID = "harness-m3-attestor"
PROFILE_LABELS = {
    "ATTESTOR": "harness-l0-lx-a.attestor",
    "CONTROLLER": "harness-l0-lx-a.controller",
    "AGENT_WORKER": "harness-l0-lx-a.worker",
    "BROKER": "harness-l0-lx-a.broker",
    "EXECUTOR": "harness-l0-lx-a.executor",
}
ROLE_IDS = {
    "CONTROLLER": (3000, 4000, 1000, 2000),
    "AGENT_WORKER": (3001, 4001, 1001, 2001),
    "BROKER": (3002, 4002, 1002, 2002),
    "EXECUTOR": (3003, 4003, 1003, 2003),
    "ATTESTOR": (0, 4004, 0, 4004),
}
SUBORDINATE_IDS = {
    "AGENT_WORKER": (100000, 200000),
    "BROKER": (100001, 200001),
    "EXECUTOR": (100002, 200002),
}
CONTROLLERS = ("cpu", "io", "memory", "pids")
ROLE_SECCOMP_ADDITIONS = {
    "BROKER": (47, 55),
    "EXECUTOR": (18, 73, 77, 437),
}
MAX_JSON = 8 << 20
CLONE_NEWUSER = 0x10000000
CLONE_NEWNS = 0x00020000
CLONE_NEWPID = 0x20000000
NS_GET_PARENT = 0xB702
MS_NOSUID = 2
MS_NODEV = 4
MS_NOEXEC = 8
MS_REC = 16384
MS_PRIVATE = 1 << 18
PR_SET_KEEPCAPS = 8
PR_SET_NO_NEW_PRIVS = 38
PR_CAP_AMBIENT = 47
PR_CAP_AMBIENT_RAISE = 2
CAP_SETGID = 6
CAP_SETUID = 7
CAP_SYS_ADMIN = 21
START_PACKET = b"START"
BROKER_START = b"BROKER_START"
_USER_NAMESPACE_KEYS = frozenset(
    {
        "role",
        "descriptor",
        "device",
        "inode",
        "identity",
        "uid_map",
        "gid_map",
        "setgroups",
        "max_user_namespaces",
    }
)
RESIDUAL_RISK = (
    "Disposable Ubuntu 24.04 test-profile evidence only; no production trust root, "
    "production isolation, zero-covert-channel, physical durability, M4 seal/postcheck, "
    "COMMIT, JOIN, or readiness claim."
)

TEST_MATRIX = {
    "T-DECISION-ALLOW-EXACT": (),
    "T-M3-ACTUAL-BWRAP-LAUNCH": ("ATK-001",),
    "T-M3-LIFECYCLE-PREPARED-TERMINAL": ("ATK-019",),
    "T-M3-BROKER-MEDIATED-STAGE": ("ATK-003",),
    "T-Q46-DIRECT-WORKER-MUTATE-DENY": ("ATK-003", "T-Q46-DIRECT-WORKER-MUTATE-DENY"),
    "T-M3-CONFUSED-DEPUTY-DENY": ("ATK-010",),
    "T-Q47-MUTATION-SELF-AUDIENCE-DENY": ("ATK-010", "T-Q47-MUTATION-SELF-AUDIENCE-DENY"),
    "T-Q43-DESCRIPTOR-ROOT-SUBSTITUTION": ("ATK-007", "T-Q43-DESCRIPTOR-ROOT-SUBSTITUTION"),
    "T-M3-KERNEL-SURFACES-DENY": ("ATK-011", "ATK-012"),
    "T-M3-NETWORK-DENY": ("ATK-001", "ATK-002"),
    "T-M3-CANARY-INVISIBILITY": ("ATK-026",),
    "T-M3-CGROUP-CPU-LIMIT": ("ATK-019",),
    "T-M3-CGROUP-MEMORY-SWAP-LIMIT": ("ATK-020",),
    "T-M3-CGROUP-PID-LIMIT": ("ATK-021",),
    "T-M3-CGROUP-IO-LIMIT": ("ATK-022",),
    "T-M3-RLIMIT-NOFILE": ("ATK-026",),
    "T-M3-WALL-TIME-TREE-KILL": ("ATK-028",),
    "T-Q39-SUPPLY-EXTERNAL-BUNDLE-SUBSTITUTION": (
        "ATK-034", "T-Q39-SUPPLY-EXTERNAL-BUNDLE-SUBSTITUTION",
    ),
    "T-M3-STALE-FENCE-REVOCATION-DENY": ("ATK-010",),
    "T-M3-RESTART-CLEANUP-NO-RESUME": ("ATK-028",),
    "T-M3-UNCERTAINTY-QUARANTINE-NO-RETRY": ("ATK-034",),
}


class QualificationStop(Exception):
    pass


def _stop(reason: str) -> NoReturn:
    raise QualificationStop(reason)


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as error:
        raise QualificationStop("MALFORMED_VALUE") from error


def _digest_bytes(value: bytes) -> str:
    return "sha256:" + sha256(value).hexdigest()


def _is_digest(value: object) -> bool:
    return type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None


def _digest_file(path: Path, maximum: int = 64 << 20) -> str:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    digest = sha256()
    total = 0
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            _stop("UNTRUSTED_FILE")
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                _stop("UNBOUNDED_FILE")
            digest.update(chunk)
    finally:
        os.close(descriptor)
    return "sha256:" + digest.hexdigest()


def _strict_json(path: Path, keys: frozenset[str], maximum: int = MAX_JSON) -> dict[str, object]:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > maximum:
            _stop("UNTRUSTED_JSON")
        raw = os.read(descriptor, maximum + 1)
        if len(raw) != info.st_size:
            _stop("JSON_RACE")
    finally:
        os.close(descriptor)

    def pairs(rows: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in rows:
            if type(key) is not str or key in result:
                _stop("DUPLICATE_KEY")
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=lambda _: _stop("NONFINITE"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise QualificationStop("MALFORMED_JSON") from error
    if type(value) is not dict or frozenset(value) != keys:
        _stop("UNKNOWN_OR_MISSING_FIELD")
    return value


def _write_all(descriptor: int, data: bytes, reason: str = "SHORT_WRITE") -> None:
    remaining = memoryview(data)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            _stop(reason)
        remaining = remaining[written:]


def _write_exact(path: Path, data: bytes, mode: int) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = os.open(path, flags, mode)
    try:
        _write_all(descriptor, data)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _replace_exact(path: Path, data: bytes, mode: int) -> None:
    temporary = path.with_name(path.name + ".new")
    try:
        temporary.unlink(missing_ok=True)
        _write_exact(temporary, data, mode)
        os.replace(temporary, path)
        os.chmod(path, mode, follow_symlinks=False)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def _run(
    argv: list[str],
    *,
    input_bytes: bytes | None = None,
    timeout: float = 15,
    check: bool = True,
    pass_fds: tuple[int, ...] = (),
) -> subprocess.CompletedProcess[bytes]:
    if not argv or any(type(item) is not str or not item for item in argv):
        _stop("MALFORMED_ARGV")
    completed = subprocess.run(
        argv,
        input=input_bytes,
        shell=False,
        check=False,
        capture_output=True,
        timeout=timeout,
        close_fds=True,
        pass_fds=pass_fds,
        env={"LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
    )
    if check and completed.returncode != 0:
        _stop("COMMAND_FAILED:" + Path(argv[0]).name)
    return completed


def _strict_bytes(raw: object, maximum: int = MAX_JSON) -> object:
    if type(raw) is not bytes or not raw or len(raw) > maximum:
        _stop("MALFORMED_CANONICAL_BYTES")

    def pairs(rows: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in rows:
            if type(key) is not str or key in value:
                _stop("DUPLICATE_JSON_KEY")
            value[key] = item
        return value

    try:
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("non-finite number")),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as error:
        raise QualificationStop("MALFORMED_CANONICAL_BYTES") from error
    if _canonical(value) != raw:
        _stop("NONCANONICAL_BYTES")
    return value


def _root_marker(path: Path, keys: frozenset[str], maximum: int = MAX_JSON) -> dict[str, object]:
    info = os.lstat(path)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or (info.st_uid, info.st_gid) != (0, 0)
        or stat.S_IMODE(info.st_mode) != 0o444
        or info.st_size < 2
        or info.st_size > maximum
    ):
        _stop("ROOT_MARKER_METADATA_MISMATCH")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        raw = os.read(descriptor, maximum + 1)
        opened = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        len(raw) != info.st_size
        or (opened.st_dev, opened.st_ino, opened.st_size)
        != (info.st_dev, info.st_ino, info.st_size)
    ):
        _stop("ROOT_MARKER_RACE")
    value = _strict_bytes(raw, maximum)
    if type(value) is not dict or frozenset(value) != keys:
        _stop("ROOT_MARKER_FIELD_MISMATCH")
    return value


def _source_paths(root: Path) -> tuple[str, ...]:
    paths = {
        str(path.relative_to(root))
        for pattern in (
            "src/harness_product/*.py",
            "scripts/*.py",
            "tests/*.py",
            "profiles/l0-lx-a*",
        )
        for path in root.glob(pattern)
        if path.is_file() and not path.is_symlink()
    }
    paths.update(SOURCE_FIXED)
    if not paths or any(not (root / path).is_file() or (root / path).is_symlink() for path in paths):
        _stop("SOURCE_FILE_SET_MISMATCH")
    return tuple(sorted(paths))


def _source_identity() -> dict[str, object]:
    marker = _root_marker(
        SOURCE_IDENTITY,
        frozenset({"marker_version", "snapshot_root", "source"}),
        4 << 20,
    )
    if marker["marker_version"] != "1.0.0" or marker["snapshot_root"] != str(SOURCE):
        _stop("SOURCE_MARKER_MISMATCH")
    source = marker["source"]
    if type(source) is not dict or frozenset(source) != {"commit", "tree", "files", "files_digest"}:
        _stop("SOURCE_MARKER_MISMATCH")
    if (
        type(source["commit"]) is not str
        or re.fullmatch(r"[0-9a-f]{40}", source["commit"]) is None
        or type(source["tree"]) is not str
        or re.fullmatch(r"[0-9a-f]{40}", source["tree"]) is None
        or type(source["files"]) is not dict
    ):
        _stop("SOURCE_MARKER_MISMATCH")
    expected_paths = _source_paths(SOURCE)
    if tuple(sorted(source["files"])) != expected_paths:
        _stop("SOURCE_FILE_SET_MISMATCH")
    measured: dict[str, str] = {}
    for relative in expected_paths:
        path = SOURCE / relative
        info = os.lstat(path)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) & 0o022
        ):
            _stop("SOURCE_FILE_METADATA_MISMATCH")
        measured[relative] = _digest_file(path, 16 << 20)
    if source["files"] != measured or source["files_digest"] != _digest_bytes(_canonical(measured)):
        _stop("SOURCE_BYTES_MISMATCH")
    return source


def _host_provenance() -> dict[str, object]:
    marker = _root_marker(
        HOST_PROVENANCE,
        frozenset({"marker_version", "image", "vm"}),
        1 << 20,
    )
    if marker["marker_version"] != "1.0.0":
        _stop("HOST_PROVENANCE_MISMATCH")
    image = marker["image"]
    vm = marker["vm"]
    if (
        type(image) is not dict
        or frozenset(image)
        != {
            "source_url", "resolved_url", "release_id", "filename", "bytes", "sha256",
            "sums_sha256", "sums_signature_sha256", "signer_fingerprint",
        }
        or type(vm) is not dict
        or frozenset(vm)
        != {
            "qemu_path", "qemu_version", "qemu_digest", "machine", "kvm_api", "vcpus",
            "memory_bytes", "overlay_virtual_bytes", "seed_digest", "management_address",
            "shared_host_mounts", "qemu_argv_digest",
        }
        or image["sha256"] != IMAGE_DIGEST
        or image["release_id"] != "20260814"
        or vm["qemu_path"] != "/usr/bin/qemu-system-x86_64"
        or vm["machine"] != "q35"
        or vm["shared_host_mounts"] != 0
        or not all(_is_digest(value) for value in (image["sha256"], image["sums_sha256"], image["sums_signature_sha256"], vm["qemu_digest"], vm["seed_digest"], vm["qemu_argv_digest"]))
    ):
        _stop("HOST_PROVENANCE_MISMATCH")
    return {"image": image, "vm": vm}


def _verification_source(proof: str = "ed25519:" + "0" * 128) -> dict[str, str]:
    return {
        "verifier_id": "harness-m3-external-verifier/v1",
        "issuer_id": SIGNER_ID,
        "key_id": KEY_ID,
        "proof": proof,
    }


def _utc_text(value: datetime) -> str:
    if value.tzinfo is None:
        _stop("TIMEZONE_REQUIRED")
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _qualification_times(now: datetime | None = None) -> dict[str, str]:
    current = datetime.now(UTC) if now is None else now
    if type(current) is not datetime or current.tzinfo is None:
        _stop("TIME_MALFORMED")
    current = current.astimezone(UTC).replace(microsecond=0)
    return {
        "not_before": _utc_text(current - timedelta(minutes=1)),
        "observed_at": _utc_text(current - timedelta(seconds=30)),
        "issued_at": _utc_text(current),
        "consume_at": _utc_text(current),
        "claim_at": _utc_text(current),
        "prepare_at": _utc_text(current),
        "terminal_at": _utc_text(current),
        "facts_expires_at": _utc_text(current + timedelta(minutes=30)),
        "expires_at": _utc_text(current + timedelta(minutes=20)),
        "not_after": _utc_text(current + timedelta(hours=1)),
    }


def _transition_time(previous: str, now: datetime | None = None) -> str:
    if type(previous) is not str:
        _stop("TIME_MALFORMED")
    try:
        lower_bound = datetime.strptime(previous, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as error:
        raise QualificationStop("TIME_MALFORMED") from error
    current = datetime.now(UTC) if now is None else now
    if type(current) is not datetime or current.tzinfo is None:
        _stop("TIME_MALFORMED")
    current = current.astimezone(UTC).replace(microsecond=0)
    if current < lower_bound:
        _stop("CLOCK_ROLLBACK")
    return _utc_text(current)


def _m1_request(times: dict[str, str], content: str) -> dict[str, object]:
    if frozenset(times) != {
        "not_before", "observed_at", "issued_at", "consume_at", "claim_at", "prepare_at",
        "terminal_at", "facts_expires_at", "expires_at", "not_after",
    } or type(content) is not str or not content or len(content.encode("utf-8")) > 4096:
        _stop("M1_INPUT_MALFORMED")
    material = _digest_bytes(content.encode("utf-8"))
    exact = {
        "effect": "MUTATE",
        "resource": "FILE",
        "operation": "WRITE",
        "selector": {"kind": "PATH_EXACT", "value": "/staging/artifact.txt"},
        "facets": ["EXECUTE_EFFECT"],
        "not_before": times["not_before"],
        "not_after": times["not_after"],
        "max_duration_ms": 3000,
        "quantity_unit": "FILES",
        "max_quantity": 1,
        "max_concurrency": 1,
    }
    ceiling = {**exact, "selector": {"kind": "PATH_PREFIX", "value": "/staging"}}
    source = {"operation_id": "stage-write-v1", "authority": [ceiling]}
    return {
        "evaluation_time": times["issued_at"],
        "proposal": {
            "operation_id": "stage-write-v1",
            "principal_id": "agent_worker-1",
            "material_digest": material,
            "authority": exact,
        },
        "manifest": json.loads(json.dumps(source)),
        "policy": json.loads(json.dumps(source)),
        "physical_ceiling": json.loads(json.dumps(source)),
        "trusted_facts": {
            "operation_id": "stage-write-v1",
            "material_digest": material,
            "observed_at": times["observed_at"],
            "expires_at": times["facts_expires_at"],
            "authority": [ceiling],
        },
    }


class CaptureVerifier:
    """Powerless first pass used only to obtain the kernel/store canonical payload."""

    def __init__(self) -> None:
        self.payload: bytes | None = None
        self.record: bytes | None = None
        self.observed_at: str | None = None

    def verify(self, payload: bytes, record: bytes, observed_at: str) -> object:
        _, durable, _ = _load_project()
        self.payload = bytes(payload)
        self.record = bytes(record)
        self.observed_at = observed_at
        return durable.VerificationResult(
            durable.VerificationStatus.REJECTED,
            "harness-m3-external-verifier/v1",
            _digest_bytes(payload),
            _digest_bytes(record),
        )


class Ed25519PayloadVerifier:
    """Controller-side instance of the shared, pinned libcrypto verifier."""

    def __init__(
        self,
        *,
        expected_revocation_epoch: int | None = 0,
        expected_fencing_epoch: int | None = 1,
        clock: object | None = None,
    ) -> None:
        _load_project()
        from harness_product.verification import OpenSSLEd25519Verifier  # noqa: PLC0415

        self._delegate = OpenSSLEd25519Verifier(
            verifier_id="harness-m3-external-verifier/v1",
            issuer_id=SIGNER_ID,
            key_id=KEY_ID,
            public_key_path=str(PUBLIC_KEY),
            public_key_digest=PUBLIC_KEY_DIGEST,
            libcrypto_path=LIBCRYPTO,
            libcrypto_digest=LIBCRYPTO_DIGEST,
            verifier_code_path=str(VERIFIER_CODE),
            verifier_code_digest=VERIFIER_CODE_DIGEST,
            expected_revocation_epoch=expected_revocation_epoch,
            expected_fencing_epoch=expected_fencing_epoch,
            clock=clock,
        )

    def verify(self, payload: bytes, record: bytes, observed_at: str) -> object:
        return self._delegate.verify(payload, record, observed_at)


def _trusted_preexec(cgroup: Path, uid: int, gid: int) -> object:
    def child() -> None:
        try:
            diagnostic = os.open(
                RUNTIME / "preexec-failure.txt",
                os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600,
            )
        except OSError:
            diagnostic = -1
        stage = "TRUSTED_CGROUP_ATTACH"
        try:
            cgroup.joinpath("cgroup.procs").write_text(str(os.getpid()), encoding="ascii")
            if str(os.getpid()) not in cgroup.joinpath("cgroup.procs").read_text(encoding="ascii").split():
                raise OSError(errno.EPERM, "cgroup attach read-back failed")
            stage = "TRUSTED_SESSION"
            os.setsid()
            stage = "TRUSTED_GROUPS"
            os.setgroups([])
            stage = "TRUSTED_GID"
            os.setgid(gid)
            stage = "TRUSTED_UID"
            os.setuid(uid)
            stage = "TRUSTED_NO_NEW_PRIVS"
            libc = ctypes.CDLL(None, use_errno=True)
            if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
                code = ctypes.get_errno()
                raise OSError(code, os.strerror(code))
        except BaseException as error:
            if diagnostic >= 0:
                _record_preexec_failure(stage, error, descriptor=diagnostic)
            raise
        finally:
            if diagnostic >= 0:
                os.close(diagnostic)

    return child


def _record_preexec_failure(
    stage: str, error: BaseException, *, descriptor: int | None = None
) -> None:
    message = f"{stage}:{type(error).__name__}:{getattr(error, 'errno', 0) or 0}".encode("ascii", "replace")[:256]
    owned = descriptor is None
    if descriptor is None:
        descriptor = os.open(
            RUNTIME / "preexec-failure.txt",
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
    try:
        os.write(descriptor, message)
    finally:
        if owned:
            os.close(descriptor)


def _consume_empty_preexec_diagnostic() -> None:
    path = RUNTIME / "preexec-failure.txt"
    try:
        info = os.lstat(path)
    except OSError as error:
        raise QualificationStop("PREEXEC_DIAGNOSTIC_MISMATCH") from error
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or (info.st_uid, info.st_gid) != (os.geteuid(), os.getegid())
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_size != 0
    ):
        _stop("PREEXEC_DIAGNOSTIC_MISMATCH")
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        opened = os.fstat(descriptor)
        current = os.lstat(path)
        if (
            (opened.st_dev, opened.st_ino, opened.st_size)
            != (info.st_dev, info.st_ino, info.st_size)
            or (current.st_dev, current.st_ino)
            != (info.st_dev, info.st_ino)
            or os.read(descriptor, 1)
        ):
            _stop("PREEXEC_DIAGNOSTIC_MISMATCH")
    except OSError as error:
        raise QualificationStop("PREEXEC_DIAGNOSTIC_MISMATCH") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    try:
        path.unlink()
    except OSError as error:
        raise QualificationStop("PREEXEC_DIAGNOSTIC_MISMATCH") from error


def _cleanup_signing_runtime(manager: object | None, signing_complete: bool) -> None:
    if manager is not None:
        manager.cleanup()
    diagnostic = RUNTIME / "preexec-failure.txt"
    if signing_complete or diagnostic.exists() or diagnostic.is_symlink():
        _consume_empty_preexec_diagnostic()
    if RUNTIME.exists():
        leftovers = list(RUNTIME.iterdir())
        if leftovers:
            _stop("RECOVERY_SIGNING_CLEANUP_FAILED")
        RUNTIME.rmdir()


def _trusted_domain_observation(
    process: subprocess.Popen[bytes],
    role: str,
    cgroup: Path,
    uid: int,
    gid: int,
) -> dict[str, object] | None:
    expected = PROFILE_LABELS[role] + " (enforce)"
    label = Path(f"/proc/{process.pid}/attr/current").read_text(encoding="ascii").strip()
    status_value = _status_fields(process.pid)
    attached = str(process.pid) in cgroup.joinpath("cgroup.procs").read_text(encoding="ascii").split()
    observed_uid = int(status_value["Uid"].split()[0])
    observed_gid = int(status_value["Gid"].split()[0])
    if label != expected or not attached or (observed_uid, observed_gid) != (uid, gid):
        return None
    session_id = os.getsid(process.pid)
    entries = list(Path(f"/proc/{process.pid}/fd").iterdir())
    inventory = sorted(int(item.name) for item in entries)
    targets = [os.readlink(item) for item in entries]
    if inventory != sorted(int(item.name) for item in Path(f"/proc/{process.pid}/fd").iterdir()):
        raise FileNotFoundError("trusted descriptor inventory changed")
    return {
        "launcher_uid": uid,
        "launcher_gid": gid,
        "host_uid": observed_uid,
        "host_gid": observed_gid,
        "namespace_uid": observed_uid,
        "namespace_gid": observed_gid,
        "process_id": process.pid,
        "process_session": session_id,
        "cgroup": str(cgroup).removeprefix("/sys/fs/cgroup"),
        "security_label": label.removesuffix(" (enforce)"),
        "credential_namespace": f"cred-{role.lower()}-{process.pid}-{session_id}",
        "namespace_ids": _namespace_ids(process.pid),
        "fd_inventory": inventory,
        "network": {
            "ipv4": False,
            "ipv6": False,
            "loopback": False,
            "routes": False,
            "dns": False,
            "raw": False,
            "packet": False,
            "broad_unix": False,
            "connected_fds": any(target.startswith("socket:[") for target in targets),
        },
    }


def _wait_trusted_domain(
    process: subprocess.Popen[bytes],
    role: str,
    cgroup: Path,
    *,
    uid: int,
    gid: int,
    timeout: float = 3,
) -> dict[str, object]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and process.poll() is None:
        try:
            observation = _trusted_domain_observation(process, role, cgroup, uid, gid)
        except (OSError, KeyError, ValueError):
            observation = None
        if observation is not None:
            return observation
        time.sleep(0.01)
    _stop("TRUSTED_DOMAIN_TRANSITION_ABSENT")


def _attestor_sign(payload: bytes, cgroup: Path) -> tuple[str, dict[str, object]]:
    _strict_bytes(payload)
    state = _strict_json(
        ATTESTOR_STATE,
        frozenset({"key_id", "revocation_epoch", "revoked", "rollback_floor"}),
        4096,
    )
    key = os.lstat(PRIVATE_KEY)
    directory = os.lstat(ATTESTOR)
    if (
        state != {"key_id": KEY_ID, "revocation_epoch": 0, "revoked": False, "rollback_floor": 1}
        or not stat.S_ISDIR(directory.st_mode)
        or directory.st_uid != 0
        or stat.S_IMODE(directory.st_mode) != 0o700
        or not stat.S_ISREG(key.st_mode)
        or key.st_uid != 0
        or stat.S_IMODE(key.st_mode) != 0o600
        or _digest_file(PUBLIC_KEY, 4096) != PUBLIC_KEY_DIGEST
    ):
        _stop("ATTESTOR_TRUST_ROOT_MISMATCH")
    gate_read, gate_write = os.pipe2(os.O_CLOEXEC)
    payload_fd = os.memfd_create("harness-m3-attestor-payload", os.MFD_CLOEXEC)
    if os.write(payload_fd, payload) != len(payload):
        _stop("ATTESTOR_PAYLOAD_SHORT_WRITE")
    os.lseek(payload_fd, 0, os.SEEK_SET)
    program = (
        "import os,sys\n"
        "gate,payload=map(int,sys.argv[1:3])\n"
        "if os.read(gate,1)!=b'S': raise SystemExit(91)\n"
        f"os.execve({OPENSSL!r},[{OPENSSL!r},'pkeyutl','-sign','-inkey',{str(PRIVATE_KEY)!r},"
        "'-rawin','-in',f'/proc/self/fd/{payload}'],"
        "{'LC_ALL':'C','PATH':'/usr/sbin:/usr/bin:/sbin:/bin'})\n"
    )
    process: subprocess.Popen[bytes] | None = None
    try:
        process = subprocess.Popen(
            [
                AA_EXEC, "--profile", PROFILE_LABELS["ATTESTOR"], "--", PYTHON,
                "-I", "-S", "-c", program, str(gate_read), str(payload_fd),
            ],
            shell=False,
            close_fds=True,
            pass_fds=(gate_read, payload_fd),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env={},
            cwd="/",
            preexec_fn=_trusted_preexec(cgroup, 0, ROLE_IDS["ATTESTOR"][1]),
        )
        facts = _wait_trusted_domain(
            process, "ATTESTOR", cgroup, uid=0, gid=ROLE_IDS["ATTESTOR"][1]
        )
        if os.write(gate_write, b"S") != 1:
            _stop("ATTESTOR_SIGNATURE_FAILED")
        signature, _ = process.communicate(timeout=5)
        if process.returncode != 0:
            _stop("ATTESTOR_SIGNATURE_FAILED")
        if len(signature) != 64:
            _stop("ATTESTOR_SIGNATURE_MALFORMED")
        return "ed25519:" + signature.hex(), facts
    except subprocess.TimeoutExpired as error:
        if process is not None:
            process.kill()
        raise QualificationStop("ATTESTOR_TIMEOUT") from error
    finally:
        for descriptor in (gate_read, gate_write, payload_fd):
            try:
                os.close(descriptor)
            except OSError:
                pass


def _require_guest() -> dict[str, object]:
    if os.geteuid() != 0:
        _stop("ROOT_SUPERVISOR_REQUIRED")
    marker = _strict_json(
        GUEST_MARKER,
        frozenset({"marker_version", "image_digest", "release_id", "qemu_machine", "offline_egress"}),
        4096,
    )
    if marker != {
        "marker_version": "1.0.0",
        "image_digest": IMAGE_DIGEST,
        "release_id": "20260814",
        "qemu_machine": "q35",
        "offline_egress": True,
    }:
        _stop("GUEST_MARKER_MISMATCH")
    detected = _run(["/usr/bin/systemd-detect-virt", "--vm"], timeout=5).stdout.strip()
    if detected not in {b"kvm", b"qemu"}:
        _stop("DISPOSABLE_VM_REQUIRED")
    return marker


def _load_project() -> tuple[object, object, object]:
    source = str(SOURCE / "src")
    if source not in sys.path:
        sys.path.insert(0, source)
    import harness_product.kernel as kernel  # noqa: PLC0415
    import harness_product.durable as durable  # noqa: PLC0415
    import harness_product.l0 as l0  # noqa: PLC0415

    return kernel, durable, l0


_DURABLE_RESULT_KEYS = frozenset(
    {
        "outcome", "reason", "capability_id", "transaction_id", "journal_sequence",
        "recovery_intents", "dispatch_claim", "runtime_session", "recovery_sessions",
    }
)


def _durable_result_data(result: object) -> dict[str, object]:
    if (
        result.contract_digest is not None
        or result.d2_frontier_digest is not None
        or result.record_digest is not None
        or result.m4_state is not None
        or result.m4_iteration is not None
        or result.frontier_record_digest is not None
        or result.m4_recovery
    ):
        _stop("CONTROLLER_RESULT_MALFORMED")
    data = asdict(result)
    for key in (
        "contract_digest", "d2_frontier_digest", "record_digest", "m4_state",
        "m4_iteration", "frontier_record_digest", "m4_recovery",
    ):
        del data[key]
    data["outcome"] = result.outcome.value
    data["reason"] = result.reason.value
    data["recovery_intents"] = [asdict(item) for item in result.recovery_intents]
    data["dispatch_claim"] = (
        None if result.dispatch_claim is None else asdict(result.dispatch_claim)
    )
    data["runtime_session"] = (
        None if result.runtime_session is None else asdict(result.runtime_session)
    )
    data["recovery_sessions"] = [asdict(item) for item in result.recovery_sessions]
    if frozenset(data) != _DURABLE_RESULT_KEYS:
        _stop("CONTROLLER_RESULT_MALFORMED")
    return data


def _durable_result_from_data(durable: object, data: object) -> object:
    if type(data) is not dict or frozenset(data) != _DURABLE_RESULT_KEYS:
        _stop("CONTROLLER_RESULT_MALFORMED")
    try:
        dispatch_claim = (
            None
            if data["dispatch_claim"] is None
            else durable.DispatchClaim(**data["dispatch_claim"])
        )
        runtime_session = (
            None
            if data["runtime_session"] is None
            else durable.RuntimeSession(**data["runtime_session"])
        )
        return durable.DurableResult(
            outcome=durable.DurableOutcome(data["outcome"]),
            reason=durable.DurableReason(data["reason"]),
            capability_id=data["capability_id"],
            transaction_id=data["transaction_id"],
            journal_sequence=data["journal_sequence"],
            recovery_intents=tuple(
                durable.RecoveryIntent(**item) for item in data["recovery_intents"]
            ),
            dispatch_claim=dispatch_claim,
            runtime_session=runtime_session,
            recovery_sessions=tuple(
                durable.RecoverySession(**item) for item in data["recovery_sessions"]
            ),
        )
    except (KeyError, TypeError, ValueError) as error:
        raise QualificationStop("CONTROLLER_RESULT_MALFORMED") from error


def _controller_evaluation_data(result: object) -> dict[str, object]:
    return {
        "outcome": result.decision.outcome.value,
        "reason": result.decision.reason.value,
        "stage": result.decision.stage.value,
        "transition_accepted": result.transition.accepted,
        "proposal_authorities": [item.authority.value for item in result.transition.proposals],
    }


def _controller_session_phase() -> None:
    expected_label = PROFILE_LABELS["CONTROLLER"] + " (enforce)"
    if (
        os.geteuid() != ROLE_IDS["CONTROLLER"][0]
        or os.getegid() != ROLE_IDS["CONTROLLER"][1]
        or Path("/proc/self/attr/current").read_text(encoding="ascii").strip() != expected_label
    ):
        _stop("CONTROLLER_PRINCIPAL_MISMATCH")
    kernel, durable, _ = _load_project()
    verifier = Ed25519PayloadVerifier()
    store = durable.DurableStore(
        str(CONTROLLER / "durable.sqlite3"),
        verifier,
        executor_claim_verifier=verifier,
        runtime_session_verifier=verifier,
    )
    operations = {
        "BOOTSTRAP": store.bootstrap,
        "ISSUE": store.issue,
        "CONSUME": store.consume,
        "CLAIM": store.claim_dispatch,
        "PREPARE": store.prepare_runtime_session,
        "VERIFY_CLAIM": store.verify_dispatch_claim,
        "FINALIZE": store.finalize_runtime_session,
    }
    while True:
        raw = sys.stdin.buffer.readline(MAX_JSON + 2)
        if not raw or len(raw) > MAX_JSON + 1 or not raw.endswith(b"\n"):
            _stop("CONTROLLER_PROTOCOL_MALFORMED")
        request = _strict_bytes(raw[:-1])
        if (
            type(request) is not dict
            or frozenset(request) != {"operation", "raw"}
            or type(request["operation"]) is not str
            or type(request["raw"]) is not dict
        ):
            _stop("CONTROLLER_PROTOCOL_MALFORMED")
        operation = request["operation"]
        if operation == "STOP":
            response = {"kind": "STOPPED", "status": "OK", "value": {"closed": True}}
            _write_all(1, _canonical(response) + b"\n", "CONTROLLER_RESPONSE_SHORT_WRITE")
            return
        if operation == "EVALUATE":
            result = kernel.evaluate(request["raw"])
            response = {
                "kind": "EVALUATION", "status": "OK",
                "value": _controller_evaluation_data(result),
            }
        elif operation == "RECOVER":
            if request["raw"]:
                _stop("CONTROLLER_PROTOCOL_MALFORMED")
            response = {
                "kind": "DURABLE", "status": "OK",
                "value": _durable_result_data(store.recover()),
            }
        elif operation in operations:
            response = {
                "kind": "DURABLE", "status": "OK",
                "value": _durable_result_data(operations[operation](request["raw"])),
            }
        else:
            _stop("CONTROLLER_OPERATION_UNKNOWN")
        _write_all(1, _canonical(response) + b"\n", "CONTROLLER_RESPONSE_SHORT_WRITE")


class ControllerSession:
    """One measured controller-domain process that owns every live M1/M2 mutation."""

    def __init__(self, manager: "CgroupManager") -> None:
        self.manager = manager
        self.cgroup = manager.create("controller-session")
        self.operations: list[dict[str, str]] = []
        self.closed = False
        argv = [
            AA_EXEC, "--profile", PROFILE_LABELS["CONTROLLER"], "--", PYTHON,
            "-I", "-S", str(Path(__file__).resolve()), "--controller-session",
        ]
        self.argv = argv
        self.process = subprocess.Popen(
            argv,
            shell=False,
            close_fds=True,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env={},
            cwd="/",
            preexec_fn=_trusted_preexec(
                self.cgroup, ROLE_IDS["CONTROLLER"][0], ROLE_IDS["CONTROLLER"][1]
            ),
        )
        facts = _wait_trusted_domain(
            self.process,
            "CONTROLLER",
            self.cgroup,
            uid=ROLE_IDS["CONTROLLER"][0],
            gid=ROLE_IDS["CONTROLLER"][1],
        )
        status_value = _status_fields(self.process.pid)
        command = Path(f"/proc/{self.process.pid}/cmdline").read_bytes().split(b"\0")[:-1]
        expected_command = [item.encode("utf-8") for item in argv[4:]]
        executable = Path(f"/proc/{self.process.pid}/exe").resolve(strict=True)
        code_path = Path(__file__).resolve(strict=True)
        code_target = Path(f"/proc/{self.process.pid}/fd/3")
        code_info = os.stat(code_target, follow_symlinks=True)
        source_info = os.stat(code_path, follow_symlinks=False)
        fdinfo = Path(f"/proc/{self.process.pid}/fdinfo/3").read_text(encoding="ascii")
        flags_row = next(
            (row for row in fdinfo.splitlines() if row.startswith("flags:\t")),
            "",
        )
        try:
            code_flags = int(flags_row.removeprefix("flags:\t"), 8)
        except ValueError:
            code_flags = -1
        code_descriptor = {
            "descriptor": 3,
            "path": str(code_path),
            "device": code_info.st_dev,
            "inode": code_info.st_ino,
            "bytes": code_info.st_size,
            "mode": stat.S_IMODE(code_info.st_mode),
            "uid": code_info.st_uid,
            "gid": code_info.st_gid,
            "flags": code_flags,
            "digest": _digest_file(code_path),
        }
        verifier_binding = {
            "backend": "OPENSSL_LIBCRYPTO_SHARED",
            "code_digest": _digest_file(VERIFIER_CODE),
            "public_key_digest": _digest_file(PUBLIC_KEY, 4096),
            "libcrypto_digest": _digest_file(Path(LIBCRYPTO).resolve(strict=True), 16 << 20),
        }
        envelope = {
            "capabilities": {
                key: status_value.get(key)
                for key in ("CapInh", "CapPrm", "CapEff")
            },
            "no_new_privs": status_value.get("NoNewPrivs"),
            "fd_inventory": facts["fd_inventory"],
            "fd_targets": {
                str(descriptor): os.readlink(f"/proc/{self.process.pid}/fd/{descriptor}")
                for descriptor in facts["fd_inventory"]
            },
            "code_descriptor": code_descriptor,
            "command": [item.decode("utf-8", "replace") for item in command],
            "expected_command": [item.decode("utf-8") for item in expected_command],
            "executable": str(executable),
            "expected_executable": str(Path(PYTHON).resolve(strict=True)),
            "verifier": verifier_binding,
        }
        if (
            any(
                status_value.get(key) != "0000000000000000"
                for key in ("CapInh", "CapPrm", "CapEff")
            )
            or status_value.get("NoNewPrivs") != "1"
            or facts["fd_inventory"] != [0, 1, 2, 3]
            or os.readlink(code_target) != str(code_path)
            or not stat.S_ISREG(code_info.st_mode)
            or code_info.st_nlink != 1
            or (code_info.st_dev, code_info.st_ino)
            != (source_info.st_dev, source_info.st_ino)
            or code_info.st_uid != 0
            or code_info.st_gid != 0
            or stat.S_IMODE(code_info.st_mode) & 0o022
            or code_flags < 0
            or code_flags & os.O_ACCMODE != os.O_RDONLY
            or code_flags & os.O_CLOEXEC != os.O_CLOEXEC
            or command != expected_command
            or executable != Path(PYTHON).resolve(strict=True)
            or verifier_binding
            != {
                "backend": "OPENSSL_LIBCRYPTO_SHARED",
                "code_digest": VERIFIER_CODE_DIGEST,
                "public_key_digest": PUBLIC_KEY_DIGEST,
                "libcrypto_digest": LIBCRYPTO_DIGEST,
            }
        ):
            _replace_exact(
                CONTROLLER / "controller-envelope-failure.json",
                _canonical(envelope),
                0o600,
            )
            self.abort()
            _stop("CONTROLLER_ENVELOPE_MISMATCH")
        facts.update(
            {
                "session_id": f"controller-session-{facts['process_session']}",
                "argv": argv,
                "argv_digest": _digest_bytes(_canonical(argv)),
                "status": {
                    key: status_value[key]
                    for key in ("CapInh", "CapPrm", "CapEff", "NoNewPrivs")
                },
                "envelope_digest": _digest_bytes(_canonical(envelope)),
                "code_descriptor": code_descriptor,
                "durable_database": str(CONTROLLER / "durable.sqlite3"),
                "verifier": verifier_binding,
            }
        )
        self.facts = facts

    def _request(self, operation: str, raw: dict[str, object]) -> tuple[str, object]:
        if self.closed or self.process.poll() is not None:
            _stop("CONTROLLER_SESSION_CLOSED")
        request = {"operation": operation, "raw": raw}
        request_bytes = _canonical(request)
        if len(request_bytes) > MAX_JSON:
            _stop("CONTROLLER_PROTOCOL_UNBOUNDED")
        if self.process.stdin is None or self.process.stdout is None:
            _stop("CONTROLLER_PROTOCOL_CLOSED")
        _write_all(
            self.process.stdin.fileno(), request_bytes + b"\n",
            "CONTROLLER_REQUEST_SHORT_WRITE",
        )
        response_raw = _read_pipe_line(
            self.process.stdout.fileno(), maximum=MAX_JSON, timeout=20
        )
        response = _strict_bytes(response_raw)
        if (
            type(response) is not dict
            or frozenset(response) != {"kind", "status", "value"}
            or response["status"] != "OK"
            or type(response["kind"]) is not str
        ):
            _stop("CONTROLLER_RESPONSE_MALFORMED")
        self.operations.append(
            {
                "operation": operation,
                "request_digest": _digest_bytes(request_bytes),
                "response_digest": _digest_bytes(response_raw),
            }
        )
        return response["kind"], response["value"]

    def evaluate(self, raw: dict[str, object]) -> dict[str, object]:
        kind, value = self._request("EVALUATE", raw)
        if kind != "EVALUATION" or type(value) is not dict:
            _stop("CONTROLLER_RESPONSE_MALFORMED")
        return value

    def _durable(self, operation: str, raw: dict[str, object]) -> object:
        _, durable, _ = _load_project()
        kind, value = self._request(operation, raw)
        if kind != "DURABLE":
            _stop("CONTROLLER_RESPONSE_MALFORMED")
        return _durable_result_from_data(durable, value)

    def bootstrap(self, raw: dict[str, object]) -> object:
        return self._durable("BOOTSTRAP", raw)

    def issue(self, raw: dict[str, object]) -> object:
        return self._durable("ISSUE", raw)

    def consume(self, raw: dict[str, object]) -> object:
        return self._durable("CONSUME", raw)

    def claim_dispatch(self, raw: dict[str, object]) -> object:
        return self._durable("CLAIM", raw)

    def prepare_runtime_session(self, raw: dict[str, object]) -> object:
        return self._durable("PREPARE", raw)

    def verify_dispatch_claim(self, raw: dict[str, object]) -> object:
        return self._durable("VERIFY_CLAIM", raw)

    def finalize_runtime_session(self, raw: dict[str, object]) -> object:
        return self._durable("FINALIZE", raw)

    def recover(self) -> object:
        return self._durable("RECOVER", {})

    def close(self) -> dict[str, object]:
        if self.closed:
            return self.facts
        kind, value = self._request("STOP", {})
        if kind != "STOPPED" or value != {"closed": True}:
            _stop("CONTROLLER_STOP_MISMATCH")
        self.closed = True
        if self.process.stdin is not None:
            self.process.stdin.close()
        if self.process.stdout is not None:
            self.process.stdout.close()
        if self.process.wait(timeout=5) != 0:
            _stop("CONTROLLER_STOP_FAILED")
        self.manager.kill(self.cgroup)
        self.facts["control_proof"] = {
            "operations": [dict(item) for item in self.operations],
            "operations_digest": _digest_bytes(_canonical(self.operations)),
            "closed": True,
            "cgroup_populated_after_close": 0,
        }
        return self.facts

    def abort(self) -> None:
        self.closed = True
        try:
            self.manager.kill(self.cgroup)
        except Exception:
            pass
        try:
            self.process.kill()
        except Exception:
            pass


def _profile() -> tuple[dict[str, object], object, object]:
    raw = _strict_json(
        PROFILE,
        frozenset(
            {
                "profile_id", "profile_version", "status", "workload_class", "environment",
                "risk_class", "data_class", "backend", "principals", "worker_controls", "network",
                "broker_ipc", "resources", "measurement_bindings", "denied_surfaces",
            }
        ),
    )
    _, _, l0 = _load_project()
    compiled = l0.compile_profile(raw)
    if compiled.outcome is not l0.L0Outcome.COMPILED_DRAFT or compiled.profile is None:
        _stop("PROFILE_COMPILE_FAILED")
    bindings = raw["measurement_bindings"]
    if (
        bindings["lsm_policy_digest"] != _digest_file(APPARMOR_POLICY)
        or bindings["rootfs_manifest_digest"] != _digest_file(ROOTFS_MANIFEST)
        or bindings["broker_message_schema_digest"] != _digest_file(BROKER_SCHEMA)
        or bindings["verifier_code_digest"] != _digest_file(VERIFIER_CODE)
        or bindings["verifier_public_key_digest"] != _digest_file(PUBLIC_KEY, 4096)
        or bindings["verifier_libcrypto_digest"]
        != _digest_file(Path(LIBCRYPTO).resolve(strict=True), 16 << 20)
    ):
        _stop("PROFILE_ARTIFACT_MISMATCH")
    seccomp = _strict_json(
        SECCOMP_POLICY,
        frozenset({"architecture", "default_action", "format_version", "syscalls"}),
    )
    bpf = l0._compile_seccomp_bpf(seccomp)
    if bindings["seccomp_profile_digest"] != _digest_bytes(bpf):
        _stop("SECCOMP_BINDING_MISMATCH")
    return raw, compiled.profile, bpf


def _compile_seccomp_rows(rows: tuple[int, ...]) -> bytes:
    if (
        not rows
        or len(rows) > 256
        or tuple(sorted(rows)) != rows
        or len(set(rows)) != len(rows)
        or any(type(item) is not int or item < 0 or item > (1 << 31) - 1 for item in rows)
    ):
        _stop("SECCOMP_POLICY_MALFORMED")
    instructions: list[tuple[int, int, int, int]] = [
        (0x20, 0, 0, 4),
        (0x15, 1, 0, 0xC000003E),
        (0x06, 0, 0, 0x80000000),
        (0x20, 0, 0, 0),
    ]
    for syscall_number in rows:
        instructions.extend(
            ((0x15, 0, 1, syscall_number), (0x06, 0, 0, 0x7FFF0000))
        )
    instructions.append((0x06, 0, 0, 0x00050000 | errno.EPERM))
    return b"".join(struct.pack("=HBBI", *item) for item in instructions)


def _compile_role_seccomp(raw: object, base: object, role: str) -> bytes:
    expected = ROLE_SECCOMP_ADDITIONS.get(role)
    if (
        expected is None
        or type(raw) is not dict
        or frozenset(raw)
        != {"additional_syscalls", "base_profile_digest", "format_version", "role"}
        or raw.get("format_version") != "1.0.0"
        or raw.get("role") != role
        or raw.get("base_profile_digest") != BASE_SECCOMP_POLICY_DIGEST
        or type(raw.get("additional_syscalls")) is not list
        or tuple(raw["additional_syscalls"]) != expected
        or type(base) is not dict
        or frozenset(base) != {"architecture", "default_action", "format_version", "syscalls"}
        or base.get("architecture") != "AUDIT_ARCH_X86_64"
        or base.get("default_action") != "ERRNO_EPERM"
        or base.get("format_version") != "1.0.0"
        or type(base.get("syscalls")) is not list
    ):
        _stop("SECCOMP_POLICY_MALFORMED")
    base_rows = tuple(base["syscalls"])
    if any(item in base_rows for item in expected):
        _stop("SECCOMP_POLICY_MALFORMED")
    return _compile_seccomp_rows(tuple(sorted((*base_rows, *expected))))


def _role_seccomp_programs() -> tuple[dict[str, bytes], dict[str, dict[str, str]]]:
    if _digest_file(SECCOMP_POLICY) != BASE_SECCOMP_POLICY_DIGEST:
        _stop("SECCOMP_BASE_DIGEST_MISMATCH")
    base = _strict_json(
        SECCOMP_POLICY,
        frozenset({"architecture", "default_action", "format_version", "syscalls"}),
    )
    paths = {"BROKER": BROKER_SECCOMP_POLICY, "EXECUTOR": EXECUTOR_SECCOMP_POLICY}
    programs: dict[str, bytes] = {}
    records: dict[str, dict[str, str]] = {}
    for role, path in paths.items():
        raw = _strict_json(
            path,
            frozenset({"additional_syscalls", "base_profile_digest", "format_version", "role"}),
        )
        program = _compile_role_seccomp(raw, base, role)
        programs[role] = program
        records[role] = {
            "policy_digest": _digest_file(path),
            "bpf_digest": _digest_bytes(program),
            "base_policy_digest": BASE_SECCOMP_POLICY_DIGEST,
        }
    return programs, records


def _verify_tools() -> dict[str, dict[str, str]]:
    expected = {
        BWRAP: BWRAP_DIGEST,
        AA_EXEC: AA_EXEC_DIGEST,
        PYTHON: PYTHON_DIGEST,
        APPARMOR_PARSER: APPARMOR_PARSER_DIGEST,
        OPENSSL: OPENSSL_DIGEST,
    }
    for name, digest in expected.items():
        path = Path(name)
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o755:
            _stop("TOOL_METADATA_MISMATCH")
        if _digest_file(path) != digest:
            _stop("TOOL_DIGEST_MISMATCH")
    versions = {
        BWRAP: _run([BWRAP, "--version"]).stdout.decode().strip(),
        AA_EXEC: "aa-exec 4.0.1really4.0.1-0ubuntu0.24.04.7",
        PYTHON: _run([PYTHON, "--version"]).stdout.decode().strip(),
        APPARMOR_PARSER: _run([APPARMOR_PARSER, "--version"]).stdout.decode().splitlines()[0].strip(),
        OPENSSL: _run([OPENSSL, "version"]).stdout.decode().strip(),
    }
    if "--profile" not in _run([AA_EXEC, "--help"]).stdout.decode():
        _stop("AA_EXEC_PROFILE_OPTION_ABSENT")
    packages = {
        BWRAP: ("bubblewrap", "0.9.0-1ubuntu0.1"),
        AA_EXEC: ("apparmor", "4.0.1really4.0.1-0ubuntu0.24.04.7"),
        PYTHON: ("python3.12", "3.12.3-1ubuntu0.15"),
        APPARMOR_PARSER: ("apparmor", "4.0.1really4.0.1-0ubuntu0.24.04.7"),
        OPENSSL: ("openssl", "3.0.13-0ubuntu3.12"),
    }
    return {
        name: {
            "path": name,
            "version": versions[name],
            "digest": expected[name],
            "package": packages[name][0],
            "package_version": packages[name][1],
        }
        for name in expected
    }


def _package_metadata(path: Path) -> tuple[str, str]:
    resolved = path.resolve(strict=True)
    packages: set[str] = set()
    result = _run(
        ["/usr/bin/dpkg-query", "--search", str(resolved)],
        timeout=5,
        check=False,
    )
    if result.returncode == 0:
        for raw in result.stdout.decode("utf-8").splitlines():
            fields = raw.split(": ", 1)
            if len(fields) == 2 and fields[0] and fields[1]:
                packages.add(fields[0])
    if len(packages) != 1:
        _stop("DEPENDENCY_PACKAGE_MISMATCH")
    package = next(iter(packages))
    shown = _run(
        [
            "/usr/bin/dpkg-query",
            "--show",
            "--showformat=${binary:Package}\t${Version}",
            package,
        ],
        timeout=5,
    ).stdout.decode("utf-8")
    fields = shown.split("\t")
    if len(fields) != 2 or not fields[0] or not fields[1] or "\n" in shown:
        _stop("DEPENDENCY_PACKAGE_MISMATCH")
    return fields[0], fields[1]


def _opened_artifact(role: str, path: Path) -> dict[str, object]:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size < 1:
            _stop("EVIDENCE_ARTIFACT_MISMATCH")
        digest = sha256()
        total = 0
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > 64 << 20:
                _stop("EVIDENCE_ARTIFACT_UNBOUNDED")
            digest.update(chunk)
        if total != info.st_size:
            _stop("EVIDENCE_ARTIFACT_RACE")
        return {
            "role": role,
            "path": str(path),
            "device": info.st_dev,
            "inode": info.st_ino,
            "bytes": info.st_size,
            "digest": "sha256:" + digest.hexdigest(),
        }
    finally:
        os.close(descriptor)


def _supply_artifacts(
    seccomp_program: bytes,
    tools: dict[str, dict[str, str]],
    worker_tool: Path,
) -> tuple[list[dict[str, object]], list[int], dict[str, object]]:
    directory = CONTROLLER / "supply"
    directory.mkdir(mode=0o700)
    dependencies = []
    for path in _dynamic_dependencies([Path(BWRAP), Path(AA_EXEC), Path(PYTHON), Path(OPENSSL)]):
        package, version = _package_metadata(path)
        dependencies.append(
            {
                "path": str(path),
                "digest": _digest_file(path.resolve(strict=True)),
                "package": package,
                "version": version,
            }
        )
    dependency_bytes = _canonical(
        {"format_version": "1.0.0", "image_digest": IMAGE_DIGEST, "files": dependencies}
    )
    sbom_bytes = _canonical(
        {
            "format_version": "1.0.0",
            "image_digest": IMAGE_DIGEST,
            "tools": [tools[path] for path in sorted(tools)],
            "dependency_closure_digest": _digest_bytes(dependency_bytes),
        }
    )
    registry_bytes = _canonical(
        {
            "format_version": "1.0.0",
            "release_id": "20260814",
            "repository": "Ubuntu noble signed package snapshot installed in disposable VM",
            "packages": [
                {"package": row["package"], "version": row["package_version"], "digest": row["digest"]}
                for row in sorted(tools.values(), key=lambda item: item["package"] + item["path"])
            ],
        }
    )
    generated = {
        "DEPENDENCY_CLOSURE": (directory / "dependency-closure.json", dependency_bytes),
        "SBOM": (directory / "sbom.json", sbom_bytes),
        "REGISTRY_SNAPSHOT": (directory / "registry-snapshot.json", registry_bytes),
        "SECCOMP_PROFILE": (directory / "seccomp.bpf", seccomp_program),
    }
    for path, content in generated.values():
        _write_exact(path, content, 0o444)
    paths = {
        "ROOTFS_MANIFEST": ROOTFS_MANIFEST,
        "LOADER": Path("/lib64/ld-linux-x86-64.so.2").resolve(strict=True),
        "TOOL": worker_tool,
        "LSM_POLICY": APPARMOR_POLICY,
        **{role: path for role, (path, _) in generated.items()},
    }
    rows: list[dict[str, object]] = []
    descriptors: list[int] = []
    opened: list[dict[str, object]] = []
    try:
        for role in sorted(paths):
            path = paths[role]
            descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            info = os.fstat(descriptor)
            digest = _digest_file(path)
            descriptors.append(descriptor)
            rows.append(
                {
                    "role": role,
                    "artifact_id": "m3-" + role.lower().replace("_", "-"),
                    "descriptor": descriptor,
                    "expected_bytes_digest": digest,
                    "provenance_digest": _digest_bytes(
                        _canonical(
                            {
                                "role": role,
                                "path": str(path),
                                "image_digest": IMAGE_DIGEST,
                                "release_id": "20260814",
                            }
                        )
                    ),
                }
            )
            opened.append(
                {
                    "role": role,
                    "path": str(path),
                    "device": info.st_dev,
                    "inode": info.st_ino,
                    "bytes": info.st_size,
                    "digest": digest,
                }
            )
    except Exception:
        for descriptor in descriptors:
            os.close(descriptor)
        raise
    evidence_paths = {
        "ROOTFS_MANIFEST": ROOTFS_MANIFEST,
        "BWRAP": Path(BWRAP),
        "AA_EXEC": Path(AA_EXEC),
        "PYTHON": Path(PYTHON),
        "LOADER": paths["LOADER"],
        "TOOL": worker_tool,
        "SECCOMP_BPF": generated["SECCOMP_PROFILE"][0],
        "APPARMOR_POLICY": APPARMOR_POLICY,
        "SBOM": generated["SBOM"][0],
        "REGISTRY_SNAPSHOT": generated["REGISTRY_SNAPSHOT"][0],
    }
    evidence_opened = [
        _opened_artifact(role, path) for role, path in sorted(evidence_paths.items())
    ]
    return rows, descriptors, {
        "dependencies": dependencies,
        "dependency_closure_digest": _digest_bytes(dependency_bytes),
        "sbom_digest": _digest_bytes(sbom_bytes),
        "registry_snapshot_digest": _digest_bytes(registry_bytes),
        "opened": opened,
        "loader_digest": _digest_file(paths["LOADER"]),
        "tool_digest": _digest_file(paths["TOOL"]),
        "evidence_opened": evidence_opened,
        "actual_opened_bytes_digest": _digest_bytes(_canonical(evidence_opened)),
        "package_index_digest": _digest_file(Path("/var/lib/dpkg/status"), 16 << 20),
        "seccomp_policy_digest": _digest_file(SECCOMP_POLICY),
    }


def _supply_raw(
    profile: object,
    measurement: object,
    artifacts: list[dict[str, object]],
    material: dict[str, object],
    placement: dict[str, str],
    times: dict[str, str],
) -> dict[str, object]:
    required_placement = frozenset(
        {
            "rootfs_binding_digest", "staging_binding_digest", "cgroup_binding_digest",
            "broker_binding_digest", "fd_inventory_digest", "namespace_plan_digest",
        }
    )
    if frozenset(placement) != required_placement:
        _stop("SUPPLY_PLACEMENT_MALFORMED")
    return {
        "supply_version": "1.0.0",
        "observed_at": times["issued_at"],
        "profile_digest": profile.profile_digest,
        "measurement_digest": measurement.measurement_digest,
        "runtime": {"path": BWRAP, "version": "bubblewrap 0.9.0", "digest": BWRAP_DIGEST},
        "image": {
            "image_id": "ubuntu-noble-20260814-amd64",
            "rootfs_manifest_digest": _digest_file(ROOTFS_MANIFEST),
            "platform": "linux",
            "architecture": "x86_64",
        },
        "registry": {
            "snapshot_digest": material["registry_snapshot_digest"],
            "reference": "ubuntu-noble-20260814-installed-snapshot",
            "generation": 1,
            "rollback_floor": 1,
            "issued_at": times["not_before"],
            "expires_at": times["not_after"],
        },
        "signer": {
            "trust_root_id": TRUST_ROOT_ID,
            "signer_id": SIGNER_ID,
            "key_id": KEY_ID,
            "algorithm": "ED25519",
            "revocation_epoch": 0,
            "rollback_floor": 1,
            "verifier_code_digest": VERIFIER_CODE_DIGEST,
            "verifier_public_key_digest": PUBLIC_KEY_DIGEST,
            "verifier_libcrypto_digest": LIBCRYPTO_DIGEST,
        },
        "placement": {
            "placement_id": "placement-l0-lx-a-vm-1",
            "host_id": "harness-m3-vm-1",
            "subject_instance_id": "worker-instance-1",
            "process_tree_id": "worker-tree-1",
            "session_id": "session-1",
            "nonce": "supply-nonce-1",
            "fencing_epoch": 1,
            "revocation_epoch": 0,
            "issued_at": times["not_before"],
            "expires_at": times["not_after"],
            **placement,
        },
        "artifacts": artifacts,
        "verification": _verification_source(),
    }


def _sign_capture(
    capture: CaptureVerifier,
    manager: "CgroupManager",
    name: str,
) -> tuple[str, dict[str, object]]:
    if (
        capture.payload is None
        or capture.record is None
        or capture.observed_at is None
        or not name.replace("-", "").isalnum()
    ):
        _stop("CANONICAL_CAPTURE_ABSENT")
    _strict_bytes(capture.payload)
    _strict_bytes(capture.record)
    cgroup = manager.create("attestor-" + name)
    proof, facts = _attestor_sign(capture.payload, cgroup)
    manager.kill(cgroup)
    return proof, facts


def _attest_runtime_record(
    record: dict[str, object], manager: "CgroupManager", name: str
) -> dict[str, object]:
    if type(record) is not dict or not name.replace("-", "").isalnum():
        _stop("RUNTIME_ATTESTATION_MALFORMED")
    payload = _canonical(record)
    cgroup = manager.create("attestor-" + name)
    proof, facts = _attestor_sign(payload, cgroup)
    manager.kill(cgroup)
    signature = bytes.fromhex(proof.removeprefix("ed25519:"))
    payload_fd = os.memfd_create("harness-m3-runtime-attestation", os.MFD_CLOEXEC)
    signature_fd = os.memfd_create("harness-m3-runtime-signature", os.MFD_CLOEXEC)
    key_fd = os.open(PUBLIC_KEY, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        if os.write(payload_fd, payload) != len(payload) or os.write(signature_fd, signature) != 64:
            _stop("RUNTIME_ATTESTATION_SHORT_WRITE")
        os.lseek(payload_fd, 0, os.SEEK_SET)
        os.lseek(signature_fd, 0, os.SEEK_SET)
        verified = _run(
            [
                OPENSSL, "pkeyutl", "-verify", "-pubin", "-inkey", f"/proc/self/fd/{key_fd}",
                "-rawin", "-in", f"/proc/self/fd/{payload_fd}",
                "-sigfile", f"/proc/self/fd/{signature_fd}",
            ],
            pass_fds=(key_fd, payload_fd, signature_fd),
            timeout=5,
            check=False,
        )
        if verified.returncode != 0:
            _stop("RUNTIME_ATTESTATION_SIGNATURE_INVALID")
    finally:
        os.close(key_fd)
        os.close(payload_fd)
        os.close(signature_fd)
    return {
        "payload": record,
        "payload_digest": _digest_bytes(payload),
        "signature": proof,
        "signature_digest": _digest_bytes(signature),
        "attestor": facts,
    }


def _verified_supply(
    profile: object,
    measurement: object,
    raw: dict[str, object],
    manager: "CgroupManager",
) -> tuple[object, dict[str, object]]:
    _, _, l0 = _load_project()
    capture = CaptureVerifier()
    rejected = l0.verify_supply(profile, measurement, raw, verifier=capture)
    if rejected.outcome is not l0.L0Outcome.STOP or capture.payload is None:
        _stop("SUPPLY_CAPTURE_DID_NOT_FAIL_CLOSED")
    proof, attestor_facts = _sign_capture(capture, manager, "supply")
    raw["verification"] = _verification_source(proof)
    verified = l0.verify_supply(profile, measurement, raw, verifier=Ed25519PayloadVerifier())
    if (
        verified.outcome is not l0.L0Outcome.VERIFIED
        or verified.reason is not l0.L0Reason.SUPPLY_VERIFIED
        or verified.verification is None
    ):
        _stop("SUPPLY_VERIFICATION_FAILED")
    return verified.verification, attestor_facts


def _m2_chain(
    profile: object,
    supply: object,
    times: dict[str, str],
    content: str,
    manager: "CgroupManager",
    registry_digest: str,
    controller: ControllerSession,
) -> dict[str, object]:
    kernel, durable, _ = _load_project()
    request = _m1_request(times, content)
    evaluated = kernel.evaluate(request)
    if (
        evaluated.decision.outcome is not kernel.Outcome.ALLOW
        or not evaluated.transition.accepted
        or len(evaluated.transition.proposals) != 1
        or evaluated.transition.proposals[0].authority is not kernel.ProposalAuthority.NONE
    ):
        _stop("M1_EXACT_ALLOW_ABSENT")
    controller_evaluation = controller.evaluate(request)
    if controller_evaluation != _controller_evaluation_data(evaluated):
        _stop("CONTROLLER_M1_EVALUATION_MISMATCH")
    database = CONTROLLER / "durable.sqlite3"
    verifier = Ed25519PayloadVerifier()
    lineage = _digest_bytes(
        _canonical(
            {
                "image_digest": IMAGE_DIGEST,
                "profile_digest": profile.profile_digest,
                "placement_digest": supply.placement_digest,
                "session_id": supply.session_id,
            }
        )
    )
    scope = durable.canonical_digest({"kind": "PATH_EXACT", "value": "/staging/artifact.txt"})
    bootstrap = {
        "lineage_root": lineage,
        "revocation_epoch": 0,
        "fencing_epoch": 1,
        "budgets": [
            {
                "name": "writes", "unit": "FILES", "scope_digest": scope,
                "lineage_root": lineage, "limit": 1,
            }
        ],
    }
    store = controller
    bootstrapped = controller.bootstrap(bootstrap)
    if bootstrapped.outcome is not durable.DurableOutcome.COMMITTED:
        _stop("DURABLE_BOOTSTRAP_FAILED")
    issue = {
        "request": request,
        "audience_id": "executor-3",
        "purpose": "stageable-local-write",
        "target_authority_digest": scope,
        "contract_digest": _digest_bytes(_canonical({"contract": "l0-stage-write-v1"})),
        "registry_digest": registry_digest,
        "profile_digest": profile.profile_digest,
        "placement_digest": supply.placement_digest,
        "session_id": "session-1",
        "lineage_root": lineage,
        "nonce": "nonce-m3-runtime-1",
        "issued_at": times["issued_at"],
        "not_before": times["not_before"],
        "expires_at": times["expires_at"],
        "revocation_epoch": 0,
        "fencing_epoch": 1,
        "idempotency_key_digest": _digest_bytes(_canonical({"attempt": "m3-runtime-1"})),
        "budget": [
            {
                "name": "writes", "unit": "FILES", "scope_digest": scope,
                "lineage_root": lineage, "amount": 1,
            }
        ],
        "verification": _verification_source(),
    }
    issue_capture = CaptureVerifier()
    capture_store = durable.DurableStore(
        str(database), issue_capture,
        executor_claim_verifier=verifier,
        runtime_session_verifier=verifier,
    )
    rejected = capture_store.issue(issue)
    if (
        rejected.outcome is not durable.DurableOutcome.DENY
        or rejected.reason is not durable.DurableReason.CAPABILITY_INVALID
    ):
        _stop("CAPABILITY_CAPTURE_DID_NOT_ROLL_BACK")
    issue_proof, _ = _sign_capture(issue_capture, manager, "capability")
    issue["verification"] = _verification_source(issue_proof)
    issued = controller.issue(issue)
    if (
        issued.outcome is not durable.DurableOutcome.COMMITTED
        or issued.reason is not durable.DurableReason.CAPABILITY_ISSUED
        or issued.capability_id is None
    ):
        _stop("CAPABILITY_ISSUE_FAILED")
    with sqlite3.connect(database) as connection:
        row = connection.execute(
            "SELECT payload_json FROM capabilities WHERE capability_id=?", (issued.capability_id,)
        ).fetchone()
    if row is None or type(row[0]) is not str:
        _stop("CAPABILITY_PAYLOAD_ABSENT")
    payload = _strict_bytes(row[0].encode("utf-8"))
    if type(payload) is not dict:
        _stop("CAPABILITY_PAYLOAD_MALFORMED")
    times["consume_at"] = _transition_time(times["issued_at"])
    consumed = controller.consume(
        {
            "capability_id": issued.capability_id,
            "transaction_id": "transaction-m3-1",
            **{
                key: payload[key]
                for key in (
                    "nonce", "principal_id", "audience_id", "purpose", "decision_digest",
                    "request_digest", "authorized_envelope_digest", "manifest_digest", "policy_digest",
                    "physical_ceiling_digest", "trusted_facts_digest", "contract_digest", "registry_digest",
                    "profile_digest", "placement_digest", "session_id", "lineage_root", "revocation_epoch",
                    "fencing_epoch", "idempotency_key_digest", "target_authority_digest",
                )
            },
            "observed_at": times["consume_at"],
            "budget": payload["budget_vector"],
        }
    )
    if (
        consumed.outcome is not durable.DurableOutcome.COMMITTED
        or consumed.reason is not durable.DurableReason.INTENT_COMMITTED
    ):
        _stop("ATOMIC_CONSUME_FAILED")
    times["claim_at"] = _transition_time(times["consume_at"])
    claim_raw = {
        "transaction_id": "transaction-m3-1",
        "observed_at": times["claim_at"],
        "executor_verification": _verification_source(),
    }
    claim_capture = CaptureVerifier()
    capture_store = durable.DurableStore(
        str(database), verifier,
        executor_claim_verifier=claim_capture,
        runtime_session_verifier=verifier,
    )
    rejected = capture_store.claim_dispatch(claim_raw)
    if (
        rejected.outcome is not durable.DurableOutcome.DENY
        or rejected.reason is not durable.DurableReason.CAPABILITY_INVALID
    ):
        _stop("CLAIM_CAPTURE_DID_NOT_ROLL_BACK")
    claim_proof, _ = _sign_capture(claim_capture, manager, "claim")
    claim_raw["executor_verification"] = _verification_source(claim_proof)
    claimed = controller.claim_dispatch(claim_raw)
    if (
        claimed.outcome is not durable.DurableOutcome.COMMITTED
        or claimed.reason is not durable.DurableReason.DISPATCH_ATTEMPT_CLAIMED
        or claimed.dispatch_claim is None
    ):
        _stop("DISPATCH_CLAIM_FAILED")
    replay = controller.claim_dispatch(claim_raw)
    if replay.outcome is not durable.DurableOutcome.DENY or replay.reason is not durable.DurableReason.REPLAY:
        _stop("DISPATCH_REPLAY_NOT_DENIED")
    return {
        "store": store,
        "database": database,
        "request": request,
        "evaluated": evaluated,
        "controller_evaluation": controller_evaluation,
        "lineage": lineage,
        "scope": scope,
        "issue": issue,
        "claim_raw": claim_raw,
        "claim": claimed.dispatch_claim,
    }


def _load_apparmor() -> dict[str, object]:
    _run([APPARMOR_PARSER, "-r", "-W", str(APPARMOR_POLICY)], timeout=20)
    directory = Path("/sys/kernel/security/apparmor/policy/profiles")
    names = {item.name.rsplit(".", 1)[0] for item in directory.iterdir()}
    missing = sorted(set(PROFILE_LABELS.values()) - names)
    if missing:
        _stop("APPARMOR_PROFILE_ABSENT")
    modes = _run(["/usr/sbin/aa-status", "--json"], timeout=10).stdout
    if any(label.encode() not in modes for label in PROFILE_LABELS.values()):
        _stop("APPARMOR_STATUS_MISMATCH")
    return {"digest": _digest_file(APPARMOR_POLICY), "profiles": sorted(PROFILE_LABELS.values())}


def _reload_recovery_apparmor(expected: object) -> dict[str, object]:
    exact = {
        "digest": _digest_file(APPARMOR_POLICY),
        "profiles": sorted(PROFILE_LABELS.values()),
    }
    if type(expected) is not dict or expected != exact:
        _stop("RECOVERY_POLICY_MISMATCH")
    observed = _load_apparmor()
    if observed != exact:
        _stop("RECOVERY_POLICY_MISMATCH")
    return observed


def _seccomp_memfd(program: bytes) -> int:
    descriptor = os.memfd_create("harness-m3-seccomp", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    if os.write(descriptor, program) != len(program):
        os.close(descriptor)
        _stop("SECCOMP_SHORT_WRITE")
    fcntl.fcntl(
        descriptor,
        fcntl.F_ADD_SEALS,
        fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE,
    )
    os.lseek(descriptor, 0, os.SEEK_SET)
    return descriptor


def _tree_digest(root: Path) -> str:
    rows: list[dict[str, object]] = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        info = os.lstat(path)
        if stat.S_ISLNK(info.st_mode):
            _stop("ROOTFS_SYMLINK")
        if stat.S_ISDIR(info.st_mode):
            rows.append({"path": relative, "type": "DIRECTORY", "mode": stat.S_IMODE(info.st_mode)})
        elif stat.S_ISREG(info.st_mode):
            rows.append(
                {
                    "path": relative,
                    "type": "REGULAR",
                    "mode": stat.S_IMODE(info.st_mode),
                    "bytes": info.st_size,
                    "digest": _digest_file(path, 128 << 20),
                }
            )
        else:
            _stop("ROOTFS_SPECIAL_FILE")
    return _digest_bytes(_canonical(rows))


def _copy_regular(source: Path, target: Path, mode: int) -> dict[str, object]:
    source_info = os.stat(source, follow_symlinks=True)
    if not stat.S_ISREG(source_info.st_mode):
        _stop("ROOTFS_SOURCE_NOT_REGULAR")
    target.parent.mkdir(parents=True, mode=0o755, exist_ok=True)
    descriptor = os.open(source, os.O_RDONLY | os.O_CLOEXEC)
    output = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, mode)
    digest = sha256()
    size = 0
    try:
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            _write_all(output, chunk, "ROOTFS_SHORT_WRITE")
            digest.update(chunk)
            size += len(chunk)
        os.fsync(output)
    finally:
        os.close(output)
        os.close(descriptor)
    os.chmod(target, mode, follow_symlinks=False)
    return {"path": target.as_posix(), "bytes": size, "digest": "sha256:" + digest.hexdigest()}


def _dynamic_dependencies(paths: list[Path]) -> list[Path]:
    discovered: set[Path] = set()
    for path in paths:
        completed = _run(["/usr/bin/ldd", str(path)], timeout=10)
        for line in completed.stdout.decode().splitlines():
            tokens = line.strip().split()
            candidates = [token for token in tokens if token.startswith("/")]
            for candidate in candidates:
                if len(candidate) > 4096 or ".." in PurePosixPath(candidate).parts:
                    _stop("DEPENDENCY_PATH_MALFORMED")
                try:
                    resolved = Path(candidate).resolve(strict=True)
                except OSError as error:
                    raise QualificationStop("DEPENDENCY_RESOLUTION_FAILED") from error
                if not resolved.is_file():
                    _stop("DEPENDENCY_NOT_REGULAR")
                # Preserve the absolute loader/SONAME alias emitted by ldd, but
                # copy its resolved bytes as a regular file into the rootfs.
                discovered.add(Path(candidate))
    return sorted(discovered)


def _materialize_rootfs(
    role: str,
    tool: bytes,
    instance: str,
    *,
    executor_input: bytes | None = None,
    io_probe: bool = False,
) -> tuple[Path, dict[str, object]]:
    if role not in {"AGENT_WORKER", "BROKER", "EXECUTOR"}:
        _stop("UNKNOWN_ROLE")
    if not instance.replace("-", "").isalnum() or len(instance) > 64:
        _stop("ROOTFS_INSTANCE_INVALID")
    root = RUNTIME / "rootfs" / (role.lower() + "-" + instance)
    if root.exists():
        _stop("ROOTFS_REUSE_FORBIDDEN")
    root.mkdir(parents=True, mode=0o700)
    if (role == "EXECUTOR") is not (executor_input is not None) or (io_probe and role != "EXECUTOR"):
        _stop("EXECUTOR_INPUT_MISMATCH")
    directories = [
        "proc", "workspace", "inputs", "run", "usr/lib/harness", "usr/lib/python3.12",
    ]
    if role == "EXECUTOR":
        directories.extend(
            (
                "staging",
                "etc/harness-m3",
                "usr/lib/harness/harness_product",
                "usr/lib/x86_64-linux-gnu",
            )
        )
    for relative in directories:
        (root / relative).mkdir(parents=True, mode=0o755, exist_ok=True)

    manifest = _strict_json(
        ROOTFS_MANIFEST,
        frozenset({"architecture", "files", "format_version", "rootfs", "source_release"}),
    )
    if manifest["architecture"] != "x86_64" or manifest["format_version"] != "1.0.0":
        _stop("ROOTFS_MANIFEST_MISMATCH")
    opened: list[dict[str, object]] = []
    for row in manifest["files"]:
        if type(row) is not dict or frozenset(row) != {"path", "digest", "mode"}:
            _stop("ROOTFS_MANIFEST_MALFORMED")
        pure = PurePosixPath(row["path"])
        if not pure.is_absolute() or ".." in pure.parts or type(row["mode"]) is not int:
            _stop("ROOTFS_MANIFEST_MALFORMED")
        source = Path(row["path"])
        if _digest_file(source.resolve(strict=True), 128 << 20) != row["digest"]:
            _stop("ROOTFS_SOURCE_DIGEST_MISMATCH")
        opened.append(_copy_regular(source, root / pure.relative_to("/"), row["mode"]))

    # Python's standard library is the only role runtime dependency.  It is a
    # read-only measured closure; worker receives no project/controller code.
    stdlib_source = Path("/usr/lib/python3.12")
    stdlib_target = root / "usr/lib/python3.12"
    shutil.rmtree(stdlib_target)
    shutil.copytree(stdlib_source, stdlib_target, symlinks=False)
    extension_paths = sorted((stdlib_target / "lib-dynload").glob("*.so"))
    dependency_roots = [Path(PYTHON), Path(AA_EXEC), *extension_paths]
    if role == "EXECUTOR":
        dependency_roots.append(Path(LIBCRYPTO))
    dependency_sources = _dynamic_dependencies(dependency_roots)
    for source in dependency_sources:
        relative = source.relative_to("/")
        target = root / relative
        if target.exists():
            continue
        opened.append(_copy_regular(source, target, stat.S_IMODE(os.stat(source).st_mode)))

    if role == "EXECUTOR":
        opened.append(_copy_regular(Path(BWRAP), root / "usr/bin/bwrap", 0o555))
        libcrypto_source = Path(LIBCRYPTO).resolve(strict=True)
        opened.append(
            _copy_regular(
                libcrypto_source,
                root / PurePosixPath(LIBCRYPTO).relative_to("/"),
                stat.S_IMODE(os.stat(libcrypto_source).st_mode),
            )
        )
        opened.append(
            _copy_regular(PUBLIC_KEY, root / "etc/harness-m3/attestor-public.pem", 0o444)
        )
        for source in sorted((SOURCE / "src/harness_product").glob("*.py")):
            opened.append(
                _copy_regular(
                    source,
                    root / "usr/lib/harness/harness_product" / source.name,
                    0o444,
                )
            )
        assert executor_input is not None
        _write_exact(root / "inputs/stage.json", executor_input, 0o444)
        if io_probe:
            _write_exact(root / "staging/io-scratch", b"", 0o600)

    tool_path = root / "usr/lib/harness/worker-tool"
    _write_exact(tool_path, tool, 0o555)
    for path in sorted(root.rglob("*"), reverse=True):
        if path.is_dir():
            os.chmod(path, 0o555)
        elif path != tool_path:
            os.chmod(path, stat.S_IMODE(os.stat(path).st_mode) & ~0o222)
    os.chmod(root, 0o555)
    record = {
        "manifest_digest": _digest_file(ROOTFS_MANIFEST),
        "tree_digest": _tree_digest(root),
        "tool_digest": _digest_bytes(tool),
        "opened": opened,
    }
    if role == "EXECUTOR":
        assert executor_input is not None
        record.update(
            {
                "input_digest": _digest_bytes(executor_input),
                "libcrypto_digest": _digest_file(Path(LIBCRYPTO).resolve(strict=True)),
                "public_key_digest": _digest_file(PUBLIC_KEY, 4096),
            }
        )
    return root, record


def _mount_staging(profile: object, instance: str = "session-1") -> dict[str, object]:
    _, _, l0 = _load_project()
    identities = {
        "session-1": ("stage-root-1", "harness-m3-stage"),
        "quota-probe": ("quota-root-1", "harness-m3-quota"),
    }
    if instance not in identities:
        _stop("STAGING_INSTANCE_MISMATCH")
    root_id, mount_source = identities[instance]
    resources = {item.resource: item.limit for item in profile.resources}
    root = RUNTIME / "staging" / instance
    root.mkdir(parents=True, mode=0o700)
    options = (
        f"size={resources['OUTPUT_BYTES']},nr_inodes={resources['INODES']},mode=0700,"
        f"uid={ROLE_IDS['EXECUTOR'][0]},gid={ROLE_IDS['EXECUTOR'][1]},"
        "nosuid,nodev,noexec"
    )
    _run([MOUNT, "-t", "tmpfs", "-o", options, mount_source, str(root)], timeout=10)
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(info.st_mode)
            or (info.st_uid, info.st_gid)
            != (ROLE_IDS["EXECUTOR"][0], ROLE_IDS["EXECUTOR"][1])
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            _stop("STAGING_ROOT_IDENTITY_MISMATCH")
        mount_id = l0._mount_id(descriptor)
        root_identity = _digest_bytes(
            _canonical(
                {
                    "device": info.st_dev, "inode": info.st_ino, "mode": stat.S_IFMT(info.st_mode),
                    "mount_id": mount_id, "uid": info.st_uid, "gid": info.st_gid,
                }
            )
        )
        mount_identity = _digest_bytes(_canonical({"mount_id": mount_id, "device": info.st_dev}))
        parent = os.open(root.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            if l0._mount_id(parent) == mount_id:
                _stop("STAGING_MOUNT_ABSENT")
        finally:
            os.close(parent)
        target = os.open(
            "artifact.txt",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=descriptor,
        )
        try:
            initial = b"old\n"
            if os.write(target, initial) != len(initial):
                _stop("STAGING_CANARY_SHORT_WRITE")
            os.fchown(target, ROLE_IDS["EXECUTOR"][0], ROLE_IDS["EXECUTOR"][1])
            os.fsync(target)
        finally:
            os.close(target)
        os.fsync(descriptor)
        mount_line = next(
            (
                line for line in Path("/proc/self/mountinfo").read_text(encoding="ascii").splitlines()
                if f" {root} " in line and " - tmpfs " in line
            ),
            None,
        )
        if mount_line is None:
            _stop("STAGING_MOUNT_ABSENT")
        return {
            "path": root,
            "descriptor": descriptor,
            "root_id": root_id,
            "root_identity": root_identity,
            "mount_id": f"mnt:{mount_id}",
            "mount_identity": mount_identity,
            "files": resources["FILES"],
            "inodes": resources["INODES"],
            "bytes": resources["OUTPUT_BYTES"],
            "mount_options": options,
            "mount_source": mount_source,
            "mountinfo_digest": _digest_bytes(mount_line.encode("utf-8")),
            "initial_digest": _digest_bytes(initial),
            "device": info.st_dev,
            "inode": info.st_ino,
        }
    except Exception:
        os.close(descriptor)
        _run([UMOUNT, str(root)], timeout=10, check=False)
        raise


def _current_cgroup() -> Path:
    rows = Path("/proc/self/cgroup").read_text(encoding="ascii").splitlines()
    if len(rows) != 1 or not rows[0].startswith("0::/"):
        _stop("CGROUP_V2_ABSENT")
    relative = PurePosixPath(rows[0][4:])
    if relative.is_absolute() or ".." in relative.parts:
        _stop("CGROUP_PATH_INVALID")
    return Path("/sys/fs/cgroup", relative.as_posix())


def _io_controller_device(
    path: Path,
    sys_root: Path = Path("/sys"),
    *,
    device_number: int | None = None,
) -> dict[str, object]:
    if device_number is None:
        device_number = os.stat(path, follow_symlinks=False).st_dev
    if type(device_number) is not int or device_number < 0:
        _stop("IO_DEVICE_BINDING_MISMATCH")
    backing = f"{os.major(device_number)}:{os.minor(device_number)}"
    link = sys_root / "dev/block" / backing
    if not link.is_symlink():
        _stop("IO_DEVICE_BINDING_MISMATCH")
    try:
        resolved = link.resolve(strict=True)
        partition = resolved / "partition"
        controller = resolved.parent if partition.is_file() else resolved
        controller_device = (controller / "dev").read_text(encoding="ascii").strip()
    except OSError as error:
        raise QualificationStop("IO_DEVICE_BINDING_MISMATCH") from error
    fields = controller_device.split(":")
    if (
        len(fields) != 2
        or any(not field.isascii() or not field.isdecimal() for field in fields)
        or not (sys_root / "dev/block" / controller_device).exists()
    ):
        _stop("IO_DEVICE_BINDING_MISMATCH")
    return {
        "backing_device": backing,
        "controller_device": controller_device,
        "partition": partition.is_file(),
        "binding_digest": _digest_bytes(
            _canonical(
                {
                    "backing_device": backing,
                    "controller_device": controller_device,
                    "resolved_sysfs": str(resolved),
                }
            )
        ),
    }


class CgroupManager:
    def __init__(self, profile: dict[str, object]) -> None:
        self.root = _current_cgroup()
        available = set((self.root / "cgroup.controllers").read_text(encoding="ascii").split())
        if not set(CONTROLLERS).issubset(available):
            _stop("CGROUP_CONTROLLERS_ABSENT")
        self.manager = self.root / "manager"
        self.manager.mkdir(mode=0o700)
        (self.manager / "cgroup.procs").write_text(str(os.getpid()), encoding="ascii")
        (self.root / "cgroup.subtree_control").write_text(
            "+cpu +io +memory +pids", encoding="ascii"
        )
        enabled = set((self.root / "cgroup.subtree_control").read_text(encoding="ascii").split())
        if not set(CONTROLLERS).issubset(enabled):
            _stop("CGROUP_DELEGATION_ABSENT")
        resources = {row["resource"]: row["limit"] for row in profile["resources"]}
        self.io_device = _io_controller_device(RUNTIME.parent)
        major_text, minor_text = str(self.io_device["controller_device"]).split(":")
        self.device_major = int(major_text)
        self.device_minor = int(minor_text)
        device = str(self.io_device["controller_device"])
        self.limits = {
            "cpu.max": f"{resources['CPU_RATE'] * 100} 100000",
            "io.max": (
                f"{device} rbps={resources['BLOCK_IO_READ'] * 4096} "
                f"wbps={resources['BLOCK_IO_WRITE'] * 4096} "
                f"riops={resources['BLOCK_IO_READ']} wiops={resources['BLOCK_IO_WRITE']}"
            ),
            "memory.max": str(resources["MEMORY"] * 1024 * 1024),
            "memory.swap.max": str(resources["SWAP"] * 1024 * 1024),
            "pids.max": str(resources["PIDS"]),
        }
        self.children: list[Path] = []

    def create(self, name: str) -> Path:
        if not name.replace("-", "").isalnum() or len(name) > 64:
            _stop("CGROUP_NAME_INVALID")
        path = self.root / name
        path.mkdir(mode=0o700)
        for control, value in self.limits.items():
            (path / control).write_text(value, encoding="ascii")
        readback = {
            control: (path / control).read_text(encoding="ascii").strip()
            for control in self.limits
        }
        if readback != self.limits:
            _stop("CGROUP_LIMIT_READBACK_MISMATCH")
        self.children.append(path)
        return path

    def attach(self, path: Path, pid: int) -> None:
        (path / "cgroup.procs").write_text(str(pid), encoding="ascii")
        if str(pid) not in (path / "cgroup.procs").read_text(encoding="ascii").split():
            _stop("CGROUP_ATTACH_FAILED")

    def kill(self, path: Path) -> None:
        (path / "cgroup.kill").write_text("1", encoding="ascii")
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            events = dict(
                line.split() for line in (path / "cgroup.events").read_text(encoding="ascii").splitlines()
            )
            if events.get("populated") == "0":
                return
            time.sleep(0.02)
        _stop("CGROUP_NOT_EMPTY")

    def cleanup(self) -> None:
        for path in reversed(self.children):
            if path.exists():
                self.kill(path)
                path.rmdir()
        self.children.clear()


def _delegated_measurement(profile: object, measurement: object, manager: CgroupManager) -> object:
    """Bind the empty delegated parent while the trusted supervisor occupies its manager child."""

    _, _, l0 = _load_project()
    parent_path = str(manager.root).removeprefix("/sys/fs/cgroup")
    supervisor_path = str(manager.manager).removeprefix("/sys/fs/cgroup")
    controllers = tuple(sorted((manager.root / "cgroup.controllers").read_text(encoding="ascii").split()))
    enabled = set((manager.root / "cgroup.subtree_control").read_text(encoding="ascii").split())
    parent_processes = (manager.root / "cgroup.procs").read_text(encoding="ascii").split()
    supervisor_processes = (manager.manager / "cgroup.procs").read_text(encoding="ascii").split()
    if (
        type(measurement) is not l0.HostMeasurement
        or measurement.cgroup_path != parent_path
        or manager.manager.parent != manager.root
        or not set(CONTROLLERS).issubset(controllers)
        or not set(CONTROLLERS).issubset(enabled)
        or parent_processes
        or supervisor_processes != [str(os.getpid())]
    ):
        _stop("CGROUP_DELEGATION_BINDING_MISMATCH")
    data = {
        "backend_path": measurement.backend_path,
        "backend_version": measurement.backend_version,
        "backend_digest": measurement.backend_digest,
        "aa_exec_path": measurement.aa_exec_path,
        "aa_exec_digest": measurement.aa_exec_digest,
        "architecture": measurement.architecture,
        "kernel_release": measurement.kernel_release,
        "kernel_features": list(measurement.kernel_features),
        "cgroup_path": parent_path,
        "cgroup_controllers": list(controllers),
        "lsm_stack": list(measurement.lsm_stack),
        "lsm_policy_name": measurement.lsm_policy_name,
        "apparmor_profiles": list(measurement.apparmor_profiles),
        "openat2": measurement.openat2,
        "user_namespaces": measurement.user_namespaces,
        "profile_digest": profile.profile_digest,
    }
    bound = replace(
        measurement,
        cgroup_path=parent_path,
        cgroup_controllers=controllers,
        measurement_digest=l0._hash_text(l0._canonical(data)),
    )
    if not l0._measurement_is_valid(profile, bound):
        _stop("CGROUP_DELEGATION_BINDING_MISMATCH")
    return bound


def _namespace_maps(role: str) -> tuple[str, str]:
    if role not in SUBORDINATE_IDS:
        _stop("UNKNOWN_ROLE")
    launcher_uid, launcher_gid, namespace_uid, namespace_gid = ROLE_IDS[role]
    subordinate_uid, subordinate_gid = SUBORDINATE_IDS[role]
    return (
        f"0 {subordinate_uid} 1\n{namespace_uid} {launcher_uid} 1\n",
        f"0 {subordinate_gid} 1\n{namespace_gid} {launcher_gid} 1\n",
    )


def _bootstrap_namespace_maps(role: str) -> tuple[str, str]:
    if role not in SUBORDINATE_IDS:
        _stop("UNKNOWN_ROLE")
    launcher_uid, launcher_gid, namespace_uid, namespace_gid = ROLE_IDS[role]
    subordinate_uid, subordinate_gid = SUBORDINATE_IDS[role]
    return (
        f"0 0 1\n{namespace_uid} {launcher_uid} 1\n{subordinate_uid} {subordinate_uid} 1\n",
        f"0 0 1\n{namespace_gid} {launcher_gid} 1\n{subordinate_gid} {subordinate_gid} 1\n",
    )


def _canonical_id_map(value: object) -> str:
    if type(value) is not str or len(value) > 256:
        _stop("USER_NAMESPACE_BINDING_MISMATCH")
    rows = [line.split() for line in value.splitlines()]
    if (
        len(rows) != 2
        or any(len(row) != 3 for row in rows)
        or any(not field.isascii() or not field.isdecimal() for row in rows for field in row)
    ):
        _stop("USER_NAMESPACE_BINDING_MISMATCH")
    return "".join(" ".join(str(int(field)) for field in row) + "\n" for row in rows)


def _validate_user_namespace_record(role: str, value: object) -> dict[str, object]:
    if role not in SUBORDINATE_IDS or type(value) is not dict or frozenset(value) != _USER_NAMESPACE_KEYS:
        _stop("USER_NAMESPACE_BINDING_MISMATCH")
    uid_map, gid_map = _namespace_maps(role)
    if (
        value["role"] != role
        or type(value["descriptor"]) is not int
        or value["descriptor"] < 0
        or any(type(value[field]) is not int or value[field] < 1 for field in ("device", "inode"))
        or type(value["identity"]) is not str
        or value["identity"] != f"user:[{value['inode']}]"
        or _canonical_id_map(value["uid_map"]) != uid_map
        or _canonical_id_map(value["gid_map"]) != gid_map
        or value["setgroups"] != "deny"
        or value["max_user_namespaces"] != 0
    ):
        _stop("USER_NAMESPACE_BINDING_MISMATCH")
    result = dict(value)
    result["uid_map"] = uid_map
    result["gid_map"] = gid_map
    return result


def _verify_user_namespace_fd(
    descriptor: int, record: object, *, require_nested: bool = False
) -> dict[str, object]:
    role = record.get("role") if type(record) is dict else None
    if type(role) is not str:
        _stop("USER_NAMESPACE_BINDING_MISMATCH")
    value = _validate_user_namespace_record(role, record)
    try:
        info = os.fstat(descriptor)
        identity = os.readlink(f"/proc/self/fd/{descriptor}")
    except OSError as error:
        raise QualificationStop("USER_NAMESPACE_FD_MISMATCH") from error
    if (
        descriptor != value["descriptor"]
        or info.st_dev != value["device"]
        or info.st_ino != value["inode"]
        or identity != value["identity"]
    ):
        _stop("USER_NAMESPACE_FD_MISMATCH")
    if require_nested:
        parent_fd = -1
        try:
            parent_fd = fcntl.ioctl(descriptor, NS_GET_PARENT)
            parent_info = os.fstat(parent_fd)
            host_info = os.stat("/proc/self/ns/user")
        except OSError as error:
            raise QualificationStop("USER_NAMESPACE_PARENT_MISMATCH") from error
        finally:
            if parent_fd >= 0:
                os.close(parent_fd)
        if (
            parent_info.st_ino in {info.st_ino, host_info.st_ino}
            or parent_info.st_dev != info.st_dev
        ):
            _stop("USER_NAMESPACE_PARENT_MISMATCH")
    return value


def _namespace_limit_probe(descriptor: int, value: int | None) -> int:
    if (
        type(descriptor) is not int
        or descriptor < 0
        or (value is not None and (type(value) is not int or value != 0))
    ):
        _stop("USER_NAMESPACE_LIMIT_MISMATCH")
    parent, child_socket = socket.socketpair(
        socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC
    )
    child = os.fork()
    if child == 0:
        stage = "SETNS"
        proc_root: Path | None = None
        proc_bytes: bytes | None = None
        proc_mounted = False
        try:
            parent.close()
            signal.alarm(3)
            libc = ctypes.CDLL(None, use_errno=True)
            if libc.setns(descriptor, CLONE_NEWUSER) != 0:
                code = ctypes.get_errno()
                raise OSError(code, os.strerror(code))
            stage = "MOUNT_PID_NAMESPACE"
            if libc.unshare(CLONE_NEWNS | CLONE_NEWPID) != 0:
                code = ctypes.get_errno()
                raise OSError(code, os.strerror(code))
            probe = os.fork()
            if probe != 0:
                child_socket.close()
                _, probe_status = os.waitpid(probe, 0)
                os._exit(os.waitstatus_to_exitcode(probe_status))
            stage = "PRIVATE_MOUNTS"
            if libc.mount(None, b"/", None, MS_REC | MS_PRIVATE, None) != 0:
                code = ctypes.get_errno()
                raise OSError(code, os.strerror(code))
            proc_root = Path(f"/tmp/harness-m3-userns-proc-{os.getpid()}")
            proc_root.mkdir(mode=0o700)
            proc_bytes = os.fsencode(proc_root)
            stage = "PROC_MOUNT"
            if libc.mount(
                b"proc", proc_bytes, b"proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, None
            ) != 0:
                code = ctypes.get_errno()
                raise OSError(code, os.strerror(code))
            proc_mounted = True
            maximum = proc_root / "sys/user/max_user_namespaces"
            if value is not None:
                stage = "SYSCTL_WRITE"
                maximum.write_text(str(value), encoding="ascii")
            stage = "SYSCTL_READ"
            observed = maximum.read_text(encoding="ascii").strip()
            stage = "PROC_UNMOUNT"
            if libc.umount2(proc_bytes, 0) != 0:
                code = ctypes.get_errno()
                raise OSError(code, os.strerror(code))
            proc_mounted = False
            proc_root.rmdir()
            if child_socket.send(observed.encode("ascii")) != len(observed):
                os._exit(110)
            os._exit(0)
        except BaseException as error:
            try:
                if proc_mounted and proc_bytes is not None:
                    ctypes.CDLL(None, use_errno=True).umount2(proc_bytes, 0)
                if proc_root is not None:
                    proc_root.rmdir()
            except BaseException:
                pass
            try:
                code = error.errno if isinstance(error, OSError) and error.errno else 0
                child_socket.send(f"ERROR:{stage}:{code}".encode("ascii"))
            except BaseException:
                pass
            os._exit(111)
    child_socket.close()
    parent.settimeout(4)
    try:
        response = parent.recv(32)
    except socket.timeout:
        os.kill(child, signal.SIGKILL)
        response = b""
    finally:
        parent.close()
    _, status_value = os.waitpid(child, 0)
    if status_value != 0 or response != b"0":
        if response.startswith(b"ERROR:SETNS:"):
            _stop("USER_NAMESPACE_LIMIT_SETNS_DENIED")
        if response.startswith(b"ERROR:MOUNT_PID_NAMESPACE:"):
            _stop("USER_NAMESPACE_LIMIT_MOUNT_PID_NAMESPACE_DENIED")
        if response.startswith(b"ERROR:PRIVATE_MOUNTS:"):
            _stop("USER_NAMESPACE_LIMIT_PRIVATE_MOUNTS_DENIED")
        if response.startswith(b"ERROR:PROC_MOUNT:"):
            _stop("USER_NAMESPACE_LIMIT_PROC_MOUNT_DENIED")
        if response.startswith(b"ERROR:SYSCTL_WRITE:"):
            _stop("USER_NAMESPACE_LIMIT_WRITE_DENIED")
        if response.startswith(b"ERROR:SYSCTL_READ:"):
            _stop("USER_NAMESPACE_LIMIT_READ_DENIED")
        _stop("USER_NAMESPACE_LIMIT_MISMATCH")
    return 0


def _create_user_namespace(role: str) -> tuple[int, dict[str, object]]:
    if role not in SUBORDINATE_IDS:
        _stop("UNKNOWN_ROLE")
    uid_map, gid_map = _namespace_maps(role)
    bootstrap_uid_map, bootstrap_gid_map = _bootstrap_namespace_maps(role)
    parent, bootstrap_socket = socket.socketpair(
        socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC
    )
    child = os.fork()
    if child == 0:
        bootstrap_stage = "UNSHARE"
        try:
            parent.close()
            os.setgroups([])
            libc = ctypes.CDLL(None, use_errno=True)
            if libc.unshare(CLONE_NEWUSER) != 0:
                os._exit(90)
            bootstrap_socket.send(b"BOOTSTRAP_READY")
            if bootstrap_socket.recv(32) != b"BOOTSTRAP_MAPPED":
                os._exit(91)
            bootstrap_stage = "TARGET_FORK"
            target_parent, target_child = socket.socketpair(
                socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC
            )
            namespace_uid = ROLE_IDS[role][2]
            namespace_gid = ROLE_IDS[role][3]
            subordinate_uid, subordinate_gid = SUBORDINATE_IDS[role]
            target = os.fork()
            if target == 0:
                stage = "UNSHARE"
                try:
                    bootstrap_socket.close()
                    target_parent.close()
                    os.setgid(namespace_gid)
                    os.setuid(namespace_uid)
                    if libc.unshare(CLONE_NEWUSER) != 0:
                        code = ctypes.get_errno()
                        raise OSError(code, os.strerror(code))
                    target_child.send(b"TARGET_READY")
                    if target_child.recv(32) != b"TARGET_MAPPED":
                        os._exit(93)
                    stage = "IDENTITY"
                    if os.getuid() != namespace_uid or os.getgid() != namespace_gid:
                        raise OSError(errno.EPERM, "target namespace owner mapping mismatch")
                    target_child.send(b"TARGET_MAPPED")
                    if target_child.recv(32) != b"TARGET_REVERIFY":
                        os._exit(95)
                    if os.getuid() != namespace_uid or os.getgid() != namespace_gid:
                        os._exit(96)
                    target_child.send(b"TARGET_REVERIFIED")
                    if target_child.recv(32) != b"TARGET_RELEASE":
                        os._exit(97)
                    os._exit(0)
                except BaseException as error:
                    try:
                        code = error.errno if isinstance(error, OSError) and error.errno else 0
                        target_child.send(f"TARGET_ERROR:{stage}:{code}".encode("ascii"))
                    except BaseException:
                        pass
                    os._exit(98)
            target_child.close()
            bootstrap_stage = "TARGET_READY"
            target_status = target_parent.recv(32)
            if target_status != b"TARGET_READY":
                bootstrap_socket.send(b"ERROR:" + target_status[:48])
                os._exit(92)
            bootstrap_socket.send(f"TARGET_READY:{target}".encode("ascii"))
            if bootstrap_socket.recv(32) != b"MAP_TARGET":
                os._exit(98)
            bootstrap_stage = "TARGET_SETGROUPS"
            Path(f"/proc/{target}/setgroups").write_text("deny", encoding="ascii")
            bootstrap_stage = "TARGET_UID_MAP"
            Path(f"/proc/{target}/uid_map").write_text(
                f"0 {subordinate_uid} 1\n{namespace_uid} {namespace_uid} 1\n",
                encoding="ascii",
            )
            bootstrap_stage = "TARGET_GID_MAP"
            Path(f"/proc/{target}/gid_map").write_text(
                f"0 {subordinate_gid} 1\n{namespace_gid} {namespace_gid} 1\n",
                encoding="ascii",
            )
            bootstrap_stage = "TARGET_VERIFY"
            target_parent.send(b"TARGET_MAPPED")
            target_status = target_parent.recv(32)
            if target_status != b"TARGET_MAPPED":
                bootstrap_socket.send(b"ERROR:" + target_status[:48])
                os._exit(99)
            bootstrap_socket.send(f"TARGET_MAPPED:{target}".encode("ascii"))
            if bootstrap_socket.recv(32) != b"VERIFY":
                os._exit(100)
            target_parent.send(b"TARGET_REVERIFY")
            if target_parent.recv(32) != b"TARGET_REVERIFIED":
                os._exit(101)
            bootstrap_socket.send(b"VERIFIED:0")
            if bootstrap_socket.recv(32) != b"RELEASE":
                os._exit(102)
            target_parent.send(b"TARGET_RELEASE")
            _, target_status = os.waitpid(target, 0)
            if target_status != 0:
                os._exit(103)
            os._exit(0)
        except BaseException as error:
            try:
                code = error.errno if isinstance(error, OSError) and error.errno else 0
                bootstrap_socket.send(
                    f"ERROR:BOOTSTRAP:{bootstrap_stage}:{code}".encode("ascii")
                )
            except BaseException:
                pass
            os._exit(104)
    bootstrap_socket.close()
    parent.settimeout(3)
    if parent.recv(32) != b"BOOTSTRAP_READY":
        _stop("USER_NAMESPACE_CREATE_FAILED")
    Path(f"/proc/{child}/setgroups").write_text("deny", encoding="ascii")
    Path(f"/proc/{child}/uid_map").write_text(bootstrap_uid_map, encoding="ascii")
    Path(f"/proc/{child}/gid_map").write_text(bootstrap_gid_map, encoding="ascii")
    parent.send(b"BOOTSTRAP_MAPPED")
    target_message = parent.recv(64)
    if not target_message.startswith(b"TARGET_READY:") or not target_message[13:].isdigit():
        if target_message.startswith(b"ERROR:BOOTSTRAP:"):
            _stop("USER_NAMESPACE_BOOTSTRAP_DENIED")
        if target_message.startswith(b"ERROR:TARGET_ERROR:UNSHARE:"):
            _stop("USER_NAMESPACE_TARGET_UNSHARE_DENIED")
        if target_message.startswith(b"ERROR:TARGET_ERROR:IDENTITY:"):
            _stop("USER_NAMESPACE_TARGET_IDENTITY_DENIED")
        if target_message.startswith(b"ERROR:TARGET_ERROR:SYSCTL:"):
            code = target_message.removeprefix(b"ERROR:TARGET_ERROR:SYSCTL:")
            if code == str(errno.EACCES).encode("ascii") or code == str(errno.EPERM).encode("ascii"):
                _stop("USER_NAMESPACE_SYSCTL_DENIED")
            _stop("USER_NAMESPACE_SYSCTL_FAILED")
        if target_message == b"":
            _stop("USER_NAMESPACE_HELPER_EXITED")
        _stop("USER_NAMESPACE_CREATE_FAILED")
    target = int(target_message[13:])
    parent.send(b"MAP_TARGET")
    target_message = parent.recv(64)
    if target_message != f"TARGET_MAPPED:{target}".encode("ascii"):
        _stop("USER_NAMESPACE_CREATE_FAILED")
    namespace_fd = os.open(f"/proc/{target}/ns/user", os.O_RDONLY | os.O_CLOEXEC)
    try:
        _namespace_limit_probe(namespace_fd, 0)
        _namespace_limit_probe(namespace_fd, None)
        parent.send(b"VERIFY")
        if parent.recv(32) != b"VERIFIED:0":
            _stop("USER_NAMESPACE_LIMIT_MISMATCH")
        info = os.fstat(namespace_fd)
        record = _validate_user_namespace_record(
            role,
            {
                "role": role,
                "descriptor": namespace_fd,
                "device": info.st_dev,
                "inode": info.st_ino,
                "identity": os.readlink(f"/proc/{target}/ns/user"),
                "uid_map": Path(f"/proc/{target}/uid_map").read_text(encoding="ascii"),
                "gid_map": Path(f"/proc/{target}/gid_map").read_text(encoding="ascii"),
                "setgroups": Path(f"/proc/{target}/setgroups").read_text(encoding="ascii").strip(),
                "max_user_namespaces": 0,
            },
        )
        _verify_user_namespace_fd(namespace_fd, record, require_nested=True)
        parent.send(b"RELEASE")
    finally:
        parent.close()
    _, status_value = os.waitpid(child, 0)
    if status_value != 0:
        _stop("USER_NAMESPACE_HELPER_FAILED")
    return namespace_fd, record


def _validate_runtime_argv(
    argv: object, namespace_fd: int, *, prepared: bool = False
) -> tuple[str, ...]:
    if type(argv) not in {list, tuple} or any(type(item) is not str or not item for item in argv):
        _stop("RUNTIME_ARGV_MISMATCH")
    value = tuple(argv)
    if (
        not value
        or value[0] != BWRAP
        or "--disable-userns" in value
        or "--unshare-user" in value
        or "--uid" in value
        or "--gid" in value
        or value.count("--userns") != 1
        or value[value.index("--userns") + 1] != str(namespace_fd)
        or value.count("--assert-userns-disabled") != 1
        or value.count("--block-fd") != 1
        or value.count("--json-status-fd") != 1
    ):
        _stop("RUNTIME_ARGV_MISMATCH")
    if prepared:
        if "--sync-fd" in value:
            _stop("RUNTIME_ARGV_MISMATCH")
    elif (
        value.count("--sync-fd") != 1
        or not value[value.index("--sync-fd") + 1].isdecimal()
        or int(value[value.index("--sync-fd") + 1]) < 20
    ):
        _stop("RUNTIME_ARGV_MISMATCH")
    return value


def _namespace_ids(pid: int) -> dict[str, str]:
    result: dict[str, str] = {}
    for name in ("user", "mnt", "pid", "ipc", "uts", "net", "cgroup"):
        target = os.readlink(f"/proc/{pid}/ns/{name}")
        key = {"mnt": "mount", "net": "network"}.get(name, name)
        result[key] = target
    if len(set(result.values())) != 7:
        _stop("NAMESPACE_NOT_DISTINCT")
    return result


def _status_fields(pid: int) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in Path(f"/proc/{pid}/status").read_text(encoding="ascii").splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            values[key] = value.strip()
    return values


def _fd_inventory(pid: int) -> list[int]:
    try:
        result = sorted(int(item.name) for item in Path(f"/proc/{pid}/fd").iterdir())
    except (FileNotFoundError, ProcessLookupError, ValueError) as error:
        raise QualificationStop("FD_INVENTORY_UNAVAILABLE") from error
    return result


def _find_confined_process(
    cgroup: Path,
    expected_label: str,
    namespace_record: dict[str, object],
    expected_inventory: tuple[int, ...],
    expected_tool_arguments: tuple[bytes, ...],
    expected_tool: bytes = b"/usr/lib/harness/worker-tool",
    timeout: float = 3,
) -> tuple[int, dict[str, object]]:
    deadline = time.monotonic() + timeout
    saw_expected_label = False
    last_inventory: list[int] = []
    last_targets: dict[int, str] = {}
    while time.monotonic() < deadline:
        for raw_pid in (cgroup / "cgroup.procs").read_text(encoding="ascii").split():
            pid = int(raw_pid)
            try:
                label = Path(f"/proc/{pid}/attr/current").read_text(encoding="ascii").strip()
            except (FileNotFoundError, ProcessLookupError):
                continue
            if label == expected_label + " (enforce)":
                saw_expected_label = True
                try:
                    executable = os.readlink(f"/proc/{pid}/exe")
                    command = Path(f"/proc/{pid}/cmdline").read_bytes()
                except (FileNotFoundError, ProcessLookupError, OSError):
                    continue
                arguments = command.rstrip(b"\0").split(b"\0")
                if (
                    not executable.endswith("/python3.12")
                    or len(arguments) != 4 + len(expected_tool_arguments)
                    or arguments[:4]
                    != [
                        PYTHON.encode("ascii"), b"-I", b"-S",
                        expected_tool,
                    ]
                    or tuple(arguments[4:]) != expected_tool_arguments
                ):
                    time.sleep(0.005)
                    continue
                status_value = _status_fields(pid)
                if any(status_value.get(key) != "0000000000000000" for key in ("CapInh", "CapPrm", "CapEff")):
                    _stop("CAPABILITY_SET_NONEMPTY")
                if status_value.get("NoNewPrivs") != "1" or status_value.get("Seccomp") != "2":
                    _stop("NNP_OR_SECCOMP_ABSENT")
                namespaces = _namespace_ids(pid)
                if (
                    namespaces["user"] != namespace_record["identity"]
                    or _canonical_id_map(Path(f"/proc/{pid}/uid_map").read_text(encoding="ascii")) != namespace_record["uid_map"]
                    or _canonical_id_map(Path(f"/proc/{pid}/gid_map").read_text(encoding="ascii")) != namespace_record["gid_map"]
                    or Path(f"/proc/{pid}/setgroups").read_text(encoding="ascii").strip() != "deny"
                ):
                    _stop("USER_NAMESPACE_RUNTIME_MISMATCH")
                inventory = _fd_inventory(pid)
                last_inventory = inventory
                last_targets = {}
                for descriptor in inventory:
                    try:
                        last_targets[descriptor] = os.readlink(f"/proc/{pid}/fd/{descriptor}")[:160]
                    except OSError:
                        last_targets[descriptor] = "UNAVAILABLE"
                if inventory != list(expected_inventory):
                    time.sleep(0.01)
                    continue
                return pid, {
                    "label": label.removesuffix(" (enforce)"),
                    "executable": executable,
                    "command_digest": _digest_bytes(command),
                    "namespaces": namespaces,
                    "status": {key: status_value[key] for key in ("CapInh", "CapPrm", "CapEff", "NoNewPrivs", "Seccomp")},
                    "fd_inventory": inventory,
                }
        time.sleep(0.01)
    _stop(
        "FD_INVENTORY_MISMATCH:"
        + ",".join(str(item) for item in last_inventory)
        + ":"
        + _canonical(last_targets).decode("utf-8")[:512]
        if saw_expected_label
        else "APPARMOR_TRANSITION_ABSENT"
    )


def _preexec(
    role: str,
    preserved: tuple[tuple[int, int], ...],
    nofile: int,
    cgroup: Path,
    *,
    user_namespace_fd: int | None = None,
) -> object:
    if role not in SUBORDINATE_IDS or type(nofile) is not int or nofile < 4:
        _stop("PREEXEC_BINDING_MISMATCH")

    def child() -> None:
        try:
            diagnostic = os.open(
                RUNTIME / "preexec-failure.txt",
                os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600,
            )
        except OSError:
            diagnostic = -1
        stage = role + "_CGROUP_ATTACH"
        try:
            cgroup.joinpath("cgroup.procs").write_text(str(os.getpid()), encoding="ascii")
            if str(os.getpid()) not in cgroup.joinpath("cgroup.procs").read_text(encoding="ascii").split():
                raise OSError(errno.EPERM, "cgroup attach read-back failed")
            stage = role + "_SESSION"
            os.setsid()
            stage = role + "_FD_MAP"
            for source, target in preserved:
                if source != target:
                    os.dup2(source, target, inheritable=True)
            launcher_uid, launcher_gid, _, _ = ROLE_IDS[role]
            stage = role + "_GROUPS"
            os.setgroups([])
            if user_namespace_fd is None:
                stage = role + "_GID"
                os.setgid(launcher_gid)
                stage = role + "_UID"
                os.setuid(launcher_uid)
            else:
                parent_fd = -1
                libc = ctypes.CDLL(None, use_errno=True)
                try:
                    stage = role + "_USERNS_PARENT"
                    target_info = os.fstat(user_namespace_fd)
                    host_info = os.stat("/proc/self/ns/user")
                    parent_fd = fcntl.ioctl(user_namespace_fd, NS_GET_PARENT)
                    parent_info = os.fstat(parent_fd)
                    if (
                        parent_info.st_dev != target_info.st_dev
                        or parent_info.st_ino in {target_info.st_ino, host_info.st_ino}
                    ):
                        raise OSError(errno.EPERM, "user namespace parent mismatch")
                    stage = role + "_USERNS_SETNS"
                    if libc.setns(parent_fd, CLONE_NEWUSER) != 0:
                        code = ctypes.get_errno()
                        raise OSError(code, os.strerror(code))
                finally:
                    if parent_fd >= 0:
                        os.close(parent_fd)
                _, _, namespace_uid, namespace_gid = ROLE_IDS[role]
                stage = role + "_NAMESPACE_GID"
                os.setgid(namespace_gid)
                stage = role + "_NAMESPACE_UID"
                os.setuid(namespace_uid)
                if os.getuid() != namespace_uid or os.getgid() != namespace_gid:
                    raise OSError(errno.EPERM, "user namespace identity transition failed")
            stage = role + "_RLIMIT"
            resource.setrlimit(resource.RLIMIT_NOFILE, (nofile, nofile))
        except BaseException as error:
            if diagnostic >= 0:
                _record_preexec_failure(stage, error, descriptor=diagnostic)
            raise
        finally:
            if diagnostic >= 0:
                os.close(diagnostic)

    return child


def _duplicate_high(descriptor: int) -> int:
    return fcntl.fcntl(descriptor, fcntl.F_DUPFD_CLOEXEC, 20)


def _worker_start_binding(runtime_bindings_json: str, release_fd: int) -> dict[str, object]:
    value = _strict_bytes(runtime_bindings_json.encode("utf-8"))
    if type(value) is not dict or type(value.get("fd_allowlist")) is not list:
        _stop("WORKER_START_GATE_BINDING_MISMATCH")
    rows = {
        row.get("kind"): row
        for row in value["fd_allowlist"]
        if type(row) is dict and row.get("kind") in {"WORKER_START_GATE", "WORKER_START_RELEASE"}
    }
    if set(rows) != {"WORKER_START_GATE", "WORKER_START_RELEASE"}:
        _stop("WORKER_START_GATE_BINDING_MISMATCH")
    gate = rows["WORKER_START_GATE"]
    release = rows["WORKER_START_RELEASE"]
    try:
        info = os.fstat(release_fd)
        flags = fcntl.fcntl(release_fd, fcntl.F_GETFL)
    except OSError as error:
        raise QualificationStop("WORKER_START_GATE_BINDING_MISMATCH") from error
    if (
        frozenset(gate) != {"kind", "descriptor", "device", "inode", "type"}
        or frozenset(release) != {"kind", "descriptor", "device", "inode", "type"}
        or gate["inode"] != release["inode"]
        or release["descriptor"] != release_fd
        or release["device"] != info.st_dev
        or release["inode"] != info.st_ino
        or release["type"] != gate["type"]
        or release["type"] != "PIPE"
        or not stat.S_ISFIFO(info.st_mode)
        or flags & os.O_ACCMODE != os.O_WRONLY
    ):
        _stop("WORKER_START_GATE_BINDING_MISMATCH")
    return {
        "read_descriptor": gate["descriptor"],
        "write_descriptor": release_fd,
        "device": info.st_dev,
        "inode": info.st_ino,
        "binding_digest": _digest_bytes(_canonical({"gate": gate, "release": release})),
    }


def _prepared_process_facts(
    cgroup: Path,
    role: str,
    namespace_record: dict[str, object],
) -> tuple[int, dict[str, object]]:
    if role == "AGENT_WORKER":
        expected_inventory = (0, 1)
        expected_arguments = (b"--broker-fd", b"1", b"--session", b"session-1")
        start_descriptor = 0
        operation_descriptor = 1
    elif role == "BROKER":
        expected_inventory = (0, 1, 2)
        expected_arguments = (b"--broker-fd", b"0", b"--session", b"session-2")
        start_descriptor = 2
        operation_descriptor = 0
    else:
        expected_inventory = (0, 1)
        expected_arguments = (b"--stage", b"--session", b"session-3")
        start_descriptor = 0
        operation_descriptor = 1
    process_id, facts = _find_confined_process(
        cgroup,
        PROFILE_LABELS[role],
        namespace_record,
        expected_inventory=expected_inventory,
        expected_tool_arguments=expected_arguments,
    )
    status_value = _status_fields(process_id)
    expected_uid, expected_gid, _, _ = ROLE_IDS[role]
    uid_values = status_value.get("Uid", "").split()
    gid_values = status_value.get("Gid", "").split()
    host_namespaces = _namespace_ids(os.getpid())
    target_namespaces = facts["namespaces"]
    try:
        start_target = os.readlink(f"/proc/{process_id}/fd/{start_descriptor}")
        operation_target = (
            os.readlink(f"/proc/{process_id}/fd/{operation_descriptor}")
            if operation_descriptor >= 0
            else "ABSENT"
        )
    except OSError as error:
        raise QualificationStop("PREPARED_PROCESS_OBSERVATION_FAILED") from error
    failures: list[str] = []
    if uid_values != [str(expected_uid)] * 4:
        failures.append("UID")
    if gid_values != [str(expected_gid)] * 4:
        failures.append("GID")
    if status_value.get("CapAmb") != "0000000000000000":
        failures.append("AMBIENT_CAPABILITY")
    if not start_target.startswith("pipe:["):
        failures.append("START_FD")
    if role in {"AGENT_WORKER", "BROKER"}:
        if not operation_target.startswith("socket:["):
            failures.append("OPERATION_FD")
    elif not operation_target.startswith("pipe:["):
        failures.append("RESULT_FD")
    if any(
        target_namespaces[name] == host_namespaces[name]
        for name in ("mount", "pid", "ipc", "uts", "network", "cgroup")
    ):
        failures.append("NAMESPACE")
    if failures:
        _stop(
            "PREPARED_PROCESS_OBSERVATION_FAILED:"
            + ",".join(failures)
            + ":UID="
            + ".".join(uid_values)[:96]
            + ":GID="
            + ".".join(gid_values)[:96]
        )
    facts.update(
        {
            "host_uid": expected_uid,
            "host_gid": expected_gid,
            "process_session": os.getsid(process_id),
            "credential_namespace": f"cred-{role.lower()}-{process_id}-{os.getsid(process_id)}",
            "start_fd_target": start_target,
            "operation_fd_target": operation_target,
            "host_namespace_ids": host_namespaces,
            "network": {
                "ipv4": False,
                "ipv6": False,
                "loopback": False,
                "routes": False,
                "dns": False,
                "raw": False,
                "packet": False,
                "broad_unix": False,
                "connected_fds": role in {"AGENT_WORKER", "BROKER"},
            },
        }
    )
    return process_id, facts


def _launch_prepared_worker(
    chain: dict[str, object],
    apparmor_digest: str,
    seccomp_program: bytes,
    *,
    release: bool = True,
) -> tuple[subprocess.Popen[bytes], int, dict[str, object]]:
    _, durable, l0 = _load_project()
    plan = chain.get("session_plan")
    runtime_session = chain.get("runtime_session")
    cgroup = chain.get("worker_cgroup")
    namespace_binding = chain.get("namespaces", {}).get("AGENT_WORKER")
    if (
        type(plan) is not l0.SessionPlan
        or type(runtime_session) is not durable.RuntimeSession
        or not isinstance(cgroup, Path)
        or type(namespace_binding) is not tuple
        or runtime_session.state != "PREPARED"
        or runtime_session.session_record_id != plan.session_record_id
        or runtime_session.transaction_id != plan.transaction_id
        or runtime_session.claim_digest != plan.claim_digest
        or runtime_session.runtime_bindings_json != plan.runtime_bindings_json
    ):
        _stop("DURABLE_PREPARED_BINDING_MISMATCH")
    namespace_fd, namespace_record = namespace_binding
    _verify_user_namespace_fd(namespace_fd, namespace_record, require_nested=True)
    _worker_start_binding(plan.runtime_bindings_json, plan.worker_start_write_fd)
    argv = list(_validate_runtime_argv(list(plan.bwrap_argv), namespace_fd, prepared=True))
    process = subprocess.Popen(
        argv,
        shell=False,
        close_fds=True,
        pass_fds=plan.pass_fds,
        stdin=plan.worker_start_read_fd,
        stdout=plan.worker_broker_fd,
        stderr=subprocess.PIPE,
        env=dict(plan.environment),
        cwd="/",
        preexec_fn=_preexec(
            "AGENT_WORKER", (), plan.rlimit_nofile, cgroup,
            user_namespace_fd=plan.user_namespace_fd,
        ),
    )
    os.close(plan.worker_broker_fd)
    chain["worker_broker_fd"] = -1
    for descriptor in (plan.gate_read_fd, plan.worker_start_read_fd, plan.status_write_fd):
        os.close(descriptor)
    attached = str(process.pid) in cgroup.joinpath("cgroup.procs").read_text(encoding="ascii").split()
    limit_readback = {
        name: cgroup.joinpath(name).read_text(encoding="ascii").strip()
        for name, _ in plan.cgroup_limits
    }
    if not attached or limit_readback != dict(plan.cgroup_limits):
        _stop("CGROUP_ATTACH_FAILED")
    try:
        if os.write(plan.gate_write_fd, b"1") != 1:
            _stop("OUTER_GATE_RELEASE_FAILED")
    finally:
        os.close(plan.gate_write_fd)
    try:
        confined_pid, observed = _prepared_process_facts(cgroup, "AGENT_WORKER", namespace_record)
    except QualificationStop as error:
        try:
            os.close(plan.worker_start_write_fd)
        except OSError:
            pass
        if process.poll() is None:
            cgroup.joinpath("cgroup.kill").write_text("1", encoding="ascii")
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=1)
        diagnostic = b"" if process.stderr is None else process.stderr.read(4097)
        if len(diagnostic) > 4096:
            diagnostic = diagnostic[:4096]
        _stop(
            "PREPARED_WORKER_FAILED:"
            + str(process.returncode)
            + ":"
            + diagnostic.decode("utf-8", "replace").replace("\n", " ")[:512]
            + ":"
            + str(error)
        )
    _verify_user_namespace_fd(namespace_fd, namespace_record, require_nested=True)
    _namespace_limit_probe(namespace_fd, None)
    observed["max_user_namespaces"] = 0
    runtime_value = json.loads(plan.runtime_bindings_json)
    expected_endpoint = runtime_value["broker_ipc"]["worker_socket_identity"]
    held = os.stat(f"/proc/{confined_pid}/fd/1")
    if (
        held.st_dev != expected_endpoint["device"]
        or held.st_ino != expected_endpoint["inode"]
        or observed["operation_fd_target"] != f"socket:[{expected_endpoint['inode']}]"
    ):
        _stop("WORKER_ENDPOINT_HOLDER_MISMATCH")
    facts = {
        **observed,
        "launcher_uid": ROLE_IDS["AGENT_WORKER"][0],
        "launcher_gid": ROLE_IDS["AGENT_WORKER"][1],
        "namespace_uid": ROLE_IDS["AGENT_WORKER"][2],
        "namespace_gid": ROLE_IDS["AGENT_WORKER"][3],
        "process_id": confined_pid,
        "cgroup": {
            "path": str(cgroup).removeprefix("/sys/fs/cgroup"),
            "process_id": confined_pid,
            "attached": str(confined_pid) in cgroup.joinpath("cgroup.procs").read_text(encoding="ascii").split(),
            "readback_verified": limit_readback == dict(plan.cgroup_limits),
            "limits": limit_readback,
        },
        "argv": argv,
        "argv_digest": _digest_bytes(_canonical(argv)),
        "program_digest": chain["worker_root_record"]["tool_digest"],
        "user_namespace": namespace_record,
        "policy": {
            "apparmor_digest": apparmor_digest,
            "seccomp_digest": _digest_bytes(seccomp_program),
        },
        "runtime_session_digest": _digest_bytes(runtime_session.runtime_bindings_json.encode("utf-8")),
        "broker_pair_binding_digest": plan.broker_pair_binding_digest,
    }
    if facts["label"] != PROFILE_LABELS["AGENT_WORKER"] or facts["fd_inventory"] != [0, 1]:
        _stop("EARLY_START_GATE_DENIED")
    facts["gate"] = {
        "state": "CLOSED_AFTER_DURABLE_AND_RUNTIME_VERIFICATION",
        "packet_digest": _digest_bytes(START_PACKET),
        "binding_digest": _worker_start_binding(
            plan.runtime_bindings_json, plan.worker_start_write_fd
        )["binding_digest"],
    }
    if release:
        facts = _release_prepared_worker(chain, facts)
    return process, plan.status_read_fd, facts


def _release_prepared_worker(
    chain: dict[str, object], facts: object
) -> dict[str, object]:
    _, durable, l0 = _load_project()
    plan = chain.get("session_plan")
    runtime_session = chain.get("runtime_session")
    cgroup = chain.get("worker_cgroup")
    if (
        type(plan) is not l0.SessionPlan
        or type(runtime_session) is not durable.RuntimeSession
        or not isinstance(cgroup, Path)
        or runtime_session.state != "PREPARED"
        or type(facts) is not dict
        or type(facts.get("gate")) is not dict
        or facts["gate"].get("state") != "CLOSED_AFTER_DURABLE_AND_RUNTIME_VERIFICATION"
        or facts.get("label") != PROFILE_LABELS["AGENT_WORKER"]
        or facts.get("fd_inventory") != [0, 1]
        or str(facts.get("process_id"))
        not in cgroup.joinpath("cgroup.procs").read_text(encoding="ascii").split()
    ):
        _stop("EARLY_START_GATE_DENIED")
    gate = _worker_start_binding(plan.runtime_bindings_json, plan.worker_start_write_fd)
    try:
        if os.write(plan.worker_start_write_fd, START_PACKET) != len(START_PACKET):
            _stop("START_GATE_SHORT_WRITE")
    except OSError as error:
        raise QualificationStop("EARLY_START_GATE_DENIED") from error
    finally:
        try:
            os.close(plan.worker_start_write_fd)
        except OSError:
            pass
    result = dict(facts)
    result["gate"] = {
        "state": "OPENED_AFTER_DURABLE_AND_RUNTIME_VERIFICATION",
        "packet_digest": _digest_bytes(START_PACKET),
        "binding_digest": gate["binding_digest"],
    }
    return result


def _launch_prepared_broker(
    chain: dict[str, object],
    apparmor_digest: str,
    seccomp_program: bytes,
) -> tuple[subprocess.Popen[bytes], int, int, dict[str, object]]:
    _, durable, l0 = _load_project()
    plan = chain.get("session_plan")
    runtime_session = chain.get("runtime_session")
    cgroup = chain.get("broker_cgroup")
    namespace_binding = chain.get("namespaces", {}).get("BROKER")
    rootfs = chain.get("broker_runtime_root")
    program = chain.get("broker_program")
    if (
        type(plan) is not l0.SessionPlan
        or type(runtime_session) is not durable.RuntimeSession
        or runtime_session.state != "PREPARED"
        or runtime_session.runtime_bindings_json != plan.runtime_bindings_json
        or not isinstance(cgroup, Path)
        or type(namespace_binding) is not tuple
        or not isinstance(rootfs, Path)
        or type(program) is not bytes
    ):
        _stop("DURABLE_PREPARED_BINDING_MISMATCH")
    namespace_fd, namespace_record = namespace_binding
    _verify_user_namespace_fd(namespace_fd, namespace_record, require_nested=True)
    command_read, command_write = os.pipe2(os.O_CLOEXEC)
    report_read, report_write = os.pipe2(os.O_CLOEXEC)
    outer_read, outer_write = os.pipe2(os.O_CLOEXEC)
    status_read, status_write = os.pipe2(os.O_CLOEXEC)
    seccomp_fd = _seccomp_memfd(seccomp_program)
    root_fd = os.open(rootfs, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    outer_high = _duplicate_high(outer_read)
    descriptors = (
        namespace_fd,
        seccomp_fd,
        root_fd,
        outer_high,
        status_write,
    )
    argv = list(
        _validate_runtime_argv(
            [
                BWRAP,
                "--userns", str(namespace_fd),
                "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-net", "--unshare-cgroup",
                "--assert-userns-disabled", "--hostname", "harness-broker",
                "--new-session", "--die-with-parent", "--clearenv", "--cap-drop", "ALL",
                "--block-fd", str(outer_high), "--json-status-fd", str(status_write),
                "--ro-bind-fd", str(root_fd), "/", "--proc", "/proc",
                "--seccomp", str(seccomp_fd), "--chdir", "/workspace", "--",
                AA_EXEC, "--profile", PROFILE_LABELS["BROKER"], "--", PYTHON,
                "-I", "-S", "/usr/lib/harness/worker-tool",
                "--broker-fd", "0", "--session", "session-2",
            ],
            namespace_fd,
            prepared=True,
        )
    )
    process: subprocess.Popen[bytes] | None = None
    try:
        process = subprocess.Popen(
            argv,
            shell=False,
            close_fds=True,
            pass_fds=descriptors,
            stdin=plan.broker_peer_fd,
            stdout=report_write,
            stderr=command_read,
            env={},
            cwd="/",
            preexec_fn=_preexec(
                "BROKER", (), plan.rlimit_nofile, cgroup,
                user_namespace_fd=namespace_fd,
            ),
        )
    finally:
        for descriptor in (
            command_read, report_write, outer_read, outer_high, status_write, seccomp_fd, root_fd,
        ):
            try:
                os.close(descriptor)
            except OSError:
                pass
    if process is None:
        _stop("BROKER_LAUNCH_FAILED")
    os.close(plan.broker_peer_fd)
    chain["broker_peer_fd"] = -1
    limits = {name: cgroup.joinpath(name).read_text(encoding="ascii").strip() for name in dict(plan.cgroup_limits)}
    if (
        str(process.pid) not in cgroup.joinpath("cgroup.procs").read_text(encoding="ascii").split()
        or limits != dict(plan.cgroup_limits)
    ):
        _stop("CGROUP_ATTACH_FAILED")
    try:
        if os.write(outer_write, b"1") != 1:
            _stop("OUTER_GATE_RELEASE_FAILED")
    finally:
        os.close(outer_write)
    try:
        confined_pid, observed = _prepared_process_facts(cgroup, "BROKER", namespace_record)
    except QualificationStop as error:
        try:
            os.close(command_write)
        except OSError:
            pass
        cgroup.joinpath("cgroup.kill").write_text("1", encoding="ascii")
        process.wait(timeout=3)
        diagnostic = b"" if process.stderr is None else process.stderr.read(4096)
        _stop("PREPARED_BROKER_FAILED:" + str(error) + ":" + diagnostic.decode("utf-8", "replace")[:512])
    runtime = json.loads(plan.runtime_bindings_json)
    expected_endpoint = runtime["broker_ipc"]["broker_socket_identity"]
    held = os.stat(f"/proc/{confined_pid}/fd/0")
    if (
        held.st_dev != expected_endpoint["device"]
        or held.st_ino != expected_endpoint["inode"]
        or observed["operation_fd_target"] != f"socket:[{expected_endpoint['inode']}]"
    ):
        _stop("BROKER_ENDPOINT_HOLDER_MISMATCH")
    facts = {
        **observed,
        "launcher_uid": ROLE_IDS["BROKER"][0],
        "launcher_gid": ROLE_IDS["BROKER"][1],
        "namespace_uid": ROLE_IDS["BROKER"][2],
        "namespace_gid": ROLE_IDS["BROKER"][3],
        "process_id": confined_pid,
        "cgroup": {
            "path": str(cgroup).removeprefix("/sys/fs/cgroup"),
            "process_id": confined_pid,
            "attached": True,
            "readback_verified": True,
            "limits": limits,
        },
        "argv": argv,
        "argv_digest": _digest_bytes(_canonical(argv)),
        "program_digest": _digest_bytes(program),
        "user_namespace": namespace_record,
        "policy": {"apparmor_digest": apparmor_digest, "seccomp_digest": _digest_bytes(seccomp_program)},
        "runtime_session_digest": _digest_bytes(runtime_session.runtime_bindings_json.encode("utf-8")),
        "broker_pair_binding_digest": plan.broker_pair_binding_digest,
        "operation_gate": {
            "state": "CLOSED_AFTER_DURABLE_AND_RUNTIME_VERIFICATION",
            "pipe_inode": os.fstat(command_write).st_ino,
        },
    }
    chain.update(
        {
            "broker_process": process,
            "broker_status_fd": status_read,
            "broker_command_fd": command_write,
            "broker_report_fd": report_read,
            "broker_facts": facts,
        }
    )
    return process, status_read, report_read, facts


def _release_prepared_broker(chain: dict[str, object]) -> dict[str, object]:
    _, durable, l0 = _load_project()
    runtime_session = chain.get("runtime_session")
    plan = chain.get("session_plan")
    process = chain.get("broker_process")
    command_fd = chain.get("broker_command_fd")
    cgroup = chain.get("broker_cgroup")
    facts = chain.get("broker_facts")
    if (
        type(runtime_session) is not durable.RuntimeSession
        or type(plan) is not l0.SessionPlan
        or runtime_session.state != "PREPARED"
        or type(process) is not subprocess.Popen
        or process.poll() is not None
        or type(command_fd) is not int
        or command_fd < 0
        or not isinstance(cgroup, Path)
        or type(facts) is not dict
        or facts.get("label") != PROFILE_LABELS["BROKER"]
        or facts.get("fd_inventory") != [0, 1, 2]
        or facts.get("broker_pair_binding_digest") != plan.broker_pair_binding_digest
        or type(facts.get("operation_gate")) is not dict
        or facts["operation_gate"].get("state") != "CLOSED_AFTER_DURABLE_AND_RUNTIME_VERIFICATION"
        or str(facts.get("process_id")) not in cgroup.joinpath("cgroup.procs").read_text(encoding="ascii").split()
    ):
        _stop("EARLY_BROKER_GATE_DENIED")
    try:
        if os.write(command_fd, BROKER_START) != len(BROKER_START):
            _stop("BROKER_GATE_SHORT_WRITE")
    finally:
        os.close(command_fd)
        chain["broker_command_fd"] = -1
    result = dict(facts)
    result["operation_gate"] = {
        "state": "OPENED_AFTER_DURABLE_PREPARED",
        "packet_digest": _digest_bytes(BROKER_START),
        "pair_binding_digest": plan.broker_pair_binding_digest,
        "runtime_session_id": runtime_session.session_record_id,
    }
    chain["broker_facts"] = result
    return result


def _read_pipe_line(descriptor: int, *, maximum: int = 2048, timeout: float = 3) -> bytes:
    if type(descriptor) is not int or descriptor < 0 or type(maximum) is not int or maximum < 1:
        _stop("MEDIATOR_REPORT_MALFORMED")
    deadline = time.monotonic() + timeout
    result = bytearray()
    while len(result) <= maximum:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([descriptor], [], [], remaining)[0]:
            _stop("MEDIATOR_REPORT_TIMEOUT")
        chunk = os.read(descriptor, 1)
        if not chunk:
            _stop("MEDIATOR_REPORT_EOF")
        if chunk == b"\n":
            return bytes(result)
        result.extend(chunk)
    _stop("MEDIATOR_REPORT_UNBOUNDED")


def _complete_role(
    process: subprocess.Popen[bytes],
    status: int,
    cgroup: Path,
    *,
    timeout: float,
) -> tuple[int, str]:
    deadline = time.monotonic() + timeout
    while process.poll() is None and time.monotonic() < deadline:
        time.sleep(0.01)
    if process.poll() is None:
        (cgroup / "cgroup.kill").write_text("1", encoding="ascii")
    try:
        return_code = process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        _stop("PROCESS_TREE_KILL_FAILED")
    raw = b""
    try:
        while len(raw) <= 65536:
            chunk = os.read(status, 65536)
            if not chunk:
                break
            raw += chunk
    finally:
        os.close(status)
    return return_code, _digest_bytes(raw)


def _worker_program(packet: bytes) -> bytes:
    if len(packet) > 1024:
        _stop("BROKER_PACKET_TOO_LARGE")
    return (
        _role_gate_prefix("AGENT_WORKER", "session-1")
        + b"packet=" + repr(packet).encode("ascii") + b"\n"
        b"if os.write(1,packet)!=len(packet): raise SystemExit(93)\n"
        b"os.close(1)\n"
    )


def _broker_program(packet: bytes) -> bytes:
    if not packet or len(packet) > 1024:
        _stop("BROKER_PACKET_TOO_LARGE")
    overflow_uid = Path("/proc/sys/kernel/overflowuid").read_text(encoding="ascii").strip()
    overflow_gid = Path("/proc/sys/kernel/overflowgid").read_text(encoding="ascii").strip()
    if not overflow_uid.isdecimal() or not overflow_gid.isdecimal():
        _stop("BROKER_CREDENTIAL_MAPPING_MALFORMED")
    return (
        _role_gate_prefix("BROKER", "session-2", report_fd=True)
        + b"expected=" + repr(packet).encode("ascii") + b"\n"
        + b"expected_credentials=(0," + overflow_uid.encode("ascii") + b"," + overflow_gid.encode("ascii") + b")\n"
        b"import hashlib,json,socket,struct\n"
        b"stage='IMPORT'\n"
        b"def failure(kind,error,trace):\n"
        b" report=json.dumps({'stage':stage,'error_type':kind.__name__[:64],'error':str(error)[:256]},sort_keys=True,separators=(',',':')).encode('utf-8')\n"
        b" os.write(1,b'ERROR:'+report+b'\\n')\n"
        b"sys.excepthook=failure\n"
        b"stage='SOCKET_WRAP'\n"
        b"connection=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET,0,fileno=0)\n"
        b"stage='SOCKET_TYPE'\n"
        b"if connection.family!=socket.AF_UNIX or connection.getsockopt(socket.SOL_SOCKET,socket.SO_TYPE)!=socket.SOCK_SEQPACKET: raise SystemExit(120)\n"
        b"stage='PASSCRED'\n"
        b"if connection.getsockopt(socket.SOL_SOCKET,socket.SO_PASSCRED)!=1: raise SystemExit(121)\n"
        b"stage='PEERCRED'\n"
        b"creator=struct.unpack('3i',connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))\n"
        b"stage='RECVMSG'\n"
        b"received,ancillary,flags,address=connection.recvmsg(1025,socket.CMSG_SPACE(12))\n"
        b"if flags&(socket.MSG_TRUNC|socket.MSG_CTRUNC) or address not in (None,'',b''): raise SystemExit(122)\n"
        b"if len(ancillary)!=1 or ancillary[0][0:2]!=(socket.SOL_SOCKET,socket.SCM_CREDENTIALS): raise SystemExit(123)\n"
        b"credentials=struct.unpack('3i',ancillary[0][2][:12])\n"
        b"if credentials!=expected_credentials or received!=expected: raise SystemExit(124)\n"
        b"report=json.dumps({'creator_credentials':list(creator),'message_credentials':list(credentials),'packet_digest':'sha256:'+hashlib.sha256(received).hexdigest()},sort_keys=True,separators=(',',':')).encode('utf-8')\n"
        b"if len(report)>1024 or os.write(1,report+b'\\n')!=len(report)+1: raise SystemExit(125)\n"
        b"connection.close()\n"
    )


def _executor_input(chain: dict[str, object]) -> bytes:
    _, durable, l0 = _load_project()
    claim = chain.get("claim")
    supply = chain.get("supply")
    profile = chain.get("raw_profile")
    staging = chain.get("staging")
    content = chain.get("content")
    if (
        type(claim) is not durable.DispatchClaim
        or type(supply) is not l0.SupplyVerification
        or type(profile) is not dict
        or type(staging) is not dict
        or type(content) is not str
    ):
        _stop("EXECUTOR_INPUT_MISMATCH")
    value = {
        "claim": asdict(claim),
        "content": content,
        "profile": profile,
        "supply": asdict(supply),
        "target": {
            "canonical_path": "/staging/artifact.txt",
            "descriptor_id": "executor-stage-target-1",
            "root_id": staging["root_id"],
            "resolution_epoch": 1,
        },
    }
    return _canonical(value)


def _executor_program(libcrypto_digest: str) -> bytes:
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", libcrypto_digest):
        _stop("EXECUTOR_CRYPTO_BINDING_MALFORMED")
    source = f'''import fcntl,hashlib,json,os,sys
from dataclasses import asdict
sys.path.insert(0,"/usr/lib/harness")
from harness_product import durable,l0
from harness_product.verification import OpenSSLEd25519Verifier

EXPECTED_ARGS=["--stage","--session","session-3"]
PUBLIC_KEY="/etc/harness-m3/attestor-public.pem"
PUBLIC_KEY_DIGEST={PUBLIC_KEY_DIGEST!r}
LIBCRYPTO={LIBCRYPTO!r}
LIBCRYPTO_DIGEST={libcrypto_digest!r}
SIGNER_ID={SIGNER_ID!r}
KEY_ID={KEY_ID!r}
VERIFIER_ID="harness-m3-external-verifier/v1"
VERIFIER_CODE="/usr/lib/harness/harness_product/verification.py"
VERIFIER_CODE_DIGEST={VERIFIER_CODE_DIGEST!r}

def fail(code):
 raise RuntimeError(code)

def canonical(value):
 return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(",",":"),allow_nan=False).encode("utf-8")

def report_failure(kind,error,trace):
 report=canonical({{"error_type":kind.__name__[:64],"message":str(error)[:256]}})
 try: os.write(1,b"ERROR:"+report+b"\\n")
 except OSError: pass

sys.excepthook=report_failure

def pairs(rows):
 result={{}}
 for key,value in rows:
  if type(key) is not str or key in result: fail("DUPLICATE_OR_NONSTRING_KEY")
  result[key]=value
 return result

def bad_constant(value):
 fail("NONFINITE_JSON")

def strict(raw):
 if type(raw) is not bytes or not raw or len(raw)>(8<<20): fail("INPUT_BOUNDS")
 value=json.loads(raw.decode("utf-8"),object_pairs_hook=pairs,parse_constant=bad_constant)
 if canonical(value)!=raw: fail("NONCANONICAL_JSON")
 return value

def digest_bytes(value):
 return "sha256:"+hashlib.sha256(value).hexdigest()

def Verifier():
 return OpenSSLEd25519Verifier(
  verifier_id=VERIFIER_ID,issuer_id=SIGNER_ID,key_id=KEY_ID,
  public_key_path=PUBLIC_KEY,public_key_digest=PUBLIC_KEY_DIGEST,
  libcrypto_path=LIBCRYPTO,libcrypto_digest=LIBCRYPTO_DIGEST,
  verifier_code_path=VERIFIER_CODE,verifier_code_digest=VERIFIER_CODE_DIGEST,
  expected_revocation_epoch=0,expected_fencing_epoch=1)

if sys.argv[1:]!=EXPECTED_ARGS: raise SystemExit(90)
sys.stdin=None;sys.stdout=None;sys.stderr=None
for descriptor in tuple(int(item) for item in os.listdir("/proc/self/fd")):
 if descriptor not in (0,1):
  try: os.close(descriptor)
  except OSError: pass
if os.read(0,5)!=b"START": raise SystemExit(92)
os.close(0)
input_descriptor=os.open("/inputs/stage.json",os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
try:
 raw=b""
 while True:
  chunk=os.read(input_descriptor,65536)
  if not chunk: break
  raw+=chunk
  if len(raw)>(8<<20): fail("INPUT_BOUNDS")
finally:
 os.close(input_descriptor)
value=strict(raw)
if type(value) is not dict or set(value)!={{"claim","content","profile","supply","target"}}: fail("INPUT_KEYS")
target=value["target"]
if type(target) is not dict or set(target)!={{"canonical_path","descriptor_id","root_id","resolution_epoch"}}: fail("TARGET_KEYS")
if target!={{"canonical_path":"/staging/artifact.txt","descriptor_id":"executor-stage-target-1","root_id":"stage-root-1","resolution_epoch":1}}: fail("TARGET_BINDING")
compiled=l0.compile_profile(value["profile"])
if compiled.outcome.value!="COMPILED_DRAFT" or compiled.profile is None: fail("PROFILE_REJECTED")
if type(value["claim"]) is not dict or set(value["claim"])!=set(durable.DispatchClaim.__dataclass_fields__): fail("CLAIM_KEYS")
claim=durable.DispatchClaim(**value["claim"])
supply_value=value["supply"]
if type(supply_value) is not dict or set(supply_value)!=set(l0.SupplyVerification.__dataclass_fields__): fail("SUPPLY_KEYS")
artifact_values=supply_value["artifacts"]
if type(artifact_values) is not list: fail("ARTIFACT_LIST")
artifacts=[]
for item in artifact_values:
 if type(item) is not dict or set(item)!=set(l0.SupplyArtifactBinding.__dataclass_fields__): fail("ARTIFACT_KEYS")
 artifacts.append(l0.SupplyArtifactBinding(**item))
supply_value=dict(supply_value)
supply_value["artifacts"]=tuple(artifacts)
supply=l0.SupplyVerification(**supply_value)
root=os.open("/staging",os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW)
try:
 resolved=l0.resolve_target(compiled.profile,root,target)
 if resolved.outcome.value!="RESOLVED" or resolved.binding is None: fail("TARGET_REJECTED")
 parsed_binding=l0._parse_path_binding(resolved.binding.data())
 relative=l0._canonical_stage_path(target["canonical_path"])[1]
 duplicate=fcntl.fcntl(root,fcntl.F_DUPFD_CLOEXEC,3)
 probe=-1
 try:
  probe=l0._openat2(duplicate,relative,os.O_RDWR|os.O_CLOEXEC|os.O_NOFOLLOW)
  current=l0._binding_for_open_target(compiled.profile,duplicate,probe,target["canonical_path"],target["descriptor_id"],target["root_id"],target["resolution_epoch"])
 finally:
  if probe>=0: os.close(probe)
  os.close(duplicate)
 if parsed_binding!=resolved.binding or current!=resolved.binding: fail("PRE_STAGE_OBJECT_MISMATCH")
 content=value["content"]
 stage={{"transaction_id":claim.transaction_id,"claim_digest":claim.claim_digest,"operation":"WRITE_FILE_REPLACE","content":content,"content_digest":"sha256:"+hashlib.sha256(content.encode("utf-8")).hexdigest(),"target_binding":resolved.binding.data()}}
 result=l0.stage_committed_intent(compiled.profile,claim,supply,root,stage,executor_claim_verifier=Verifier(),supply_verifier=Verifier())
 output={{"input_digest":digest_bytes(raw),"outcome":result.outcome.value,"reason":result.reason.value,"record":None if result.record is None else asdict(result.record)}}
finally:
 os.close(root)
encoded=canonical(output)+b"\\n"
if len(encoded)>4096: raise SystemExit(94)
offset=0
while offset<len(encoded):
 written=os.write(1,encoded[offset:])
 if written<=0: raise SystemExit(95)
 offset+=written
os.close(1)
'''
    return source.encode("utf-8")


def _worker_packet(profile: object, request: dict[str, object]) -> bytes:
    worker_input = {
        "evaluation_time": "CONTROLLER_REQUIRED",
        "proposal": request["proposal"],
        "manifest": {},
        "policy": {},
        "physical_ceiling": {},
        "trusted_facts": {},
    }
    packet = _canonical(
        {
            "message_version": "1",
            "operation_id": "stage-write-v1",
            "worker_principal": "agent_worker-1",
            "worker_session": "session-1",
            "nonce": "nonce-m3-runtime-1",
            "fencing_epoch": 1,
            "binding_digest": profile.broker_binding_digest,
            "proposal": worker_input,
            "proposal_digest": _digest_bytes(_canonical(worker_input)),
        }
    )
    if len(packet) > 1024:
        _stop("BROKER_PACKET_TOO_LARGE")
    return packet


def _session_input(
    raw_profile: dict[str, object],
    profile: object,
    measurement: object,
    *,
    claim_digest: str,
    lineage_root: str,
    namespace_binding: tuple[int, dict[str, object]],
    rootfs: Path,
    worker_broker_fd: int,
    broker_peer_fd: int,
    times: dict[str, str],
    seccomp_fd: int,
    seccomp_digest: str,
    tool_fd: int,
    tool_digest: str,
    cgroup: Path,
    manager: CgroupManager,
    staging: dict[str, object],
) -> tuple[dict[str, object], tuple[int, ...]]:
    worker = next(item for item in profile.principals if item.role == "AGENT_WORKER")
    executor = next(item for item in profile.principals if item.role == "EXECUTOR")
    namespace_fd, namespace_record = namespace_binding
    _verify_user_namespace_fd(namespace_fd, namespace_record, require_nested=True)
    root_fd = os.open(rootfs, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    gate_read, gate_write = os.pipe2(os.O_CLOEXEC)
    worker_start_read, worker_start_write = os.pipe2(os.O_CLOEXEC)
    status_read, status_write = os.pipe2(os.O_CLOEXEC)
    owned = (
        root_fd, gate_read, gate_write, worker_start_read, worker_start_write,
        status_read, status_write,
    )
    try:
        raw = {
            "session_version": "1.1.0",
            "session_record_id": "m3-session-record-1",
            "session_id": worker.session_id,
            "transaction_id": "transaction-m3-1",
            "claim_digest": claim_digest,
            "lineage_root": lineage_root,
            "fencing_epoch": 1,
            "revocation_epoch": 0,
            "worker_principal": worker.principal_id,
            "executor_principal": executor.principal_id,
            "subject_instance_id": "worker-instance-1",
            "process_tree_id": "worker-tree-1",
            "namespace_ids": {
                "user": worker.user_namespace,
                "mount": worker.mount_namespace,
                "pid": worker.pid_namespace,
                "ipc": worker.ipc_namespace,
                "uts": worker.uts_namespace,
                "network": worker.network_namespace,
                "cgroup": worker.cgroup_namespace,
            },
            "user_namespace": {
                "descriptor": namespace_fd,
                "descriptor_id": "worker-userns-1",
                "identity": namespace_record["identity"],
                "uid_map": namespace_record["uid_map"],
                "gid_map": namespace_record["gid_map"],
                "setgroups": namespace_record["setgroups"],
                "max_user_namespaces": namespace_record["max_user_namespaces"],
            },
            "rootfs": {"descriptor": root_fd, "descriptor_id": "rootfs-1"},
            "inputs": [],
            "broker_ipc": {
                "worker_descriptor": worker_broker_fd,
                "worker_descriptor_id": "worker-pair-end-1",
                "broker_descriptor": broker_peer_fd,
                "broker_descriptor_id": "broker-pair-end-1",
                "worker_endpoint": raw_profile["broker_ipc"]["worker_endpoint"],
                "broker_endpoint": raw_profile["broker_ipc"]["broker_endpoint"],
                "transport": "UNIX_SEQPACKET",
                "endpoint_mode": "UNIX_CONNECTED_PAIR",
                "operation_id": "stage-write-v1",
                "nonce": "nonce-m3-runtime-1",
                "fencing_epoch": 1,
                "revocation_epoch": 0,
                "issued_at": times["issued_at"],
                "expires_at": times["expires_at"],
            },
            "seccomp": {
                "descriptor": seccomp_fd,
                "descriptor_id": "seccomp-1",
                "expected_bytes_digest": seccomp_digest,
            },
            "tool": {
                "descriptor": tool_fd,
                "descriptor_id": "tool-1",
                "path": "/usr/lib/harness/worker-tool",
                "argv": [
                    "/usr/lib/harness/worker-tool", "--broker-fd", "1",
                    "--session", worker.session_id,
                ],
                "expected_bytes_digest": tool_digest,
            },
            "cgroup": {
                "path": str(cgroup).removeprefix("/sys/fs/cgroup"),
                "controllers": list(CONTROLLERS),
                "device_major": manager.device_major,
                "device_minor": manager.device_minor,
                "delegated": True,
                "identity_digest": _digest_bytes(
                    _canonical(
                        {
                            "path": str(cgroup).removeprefix("/sys/fs/cgroup"),
                            "limits": manager.limits,
                            "io_device": manager.io_device,
                        }
                    )
                ),
            },
            "staging": {
                key: staging[key]
                for key in (
                    "root_id", "root_identity", "mount_id", "mount_identity", "files", "inodes", "bytes",
                )
            },
            "supervisor_fds": {
                "gate_read": gate_read,
                "gate_write": gate_write,
                "worker_start_read": worker_start_read,
                "worker_start_write": worker_start_write,
                "status_read": status_read,
                "status_write": status_write,
            },
            "cleanup": {
                "cleanup_id": "cleanup-1",
                "staging_root_id": staging["root_id"],
                "reuse_forbidden": True,
                "require_cgroup_empty": True,
                "quarantine_on_failure": True,
            },
        }
        if not str(raw["cgroup"]["path"]).startswith(measurement.cgroup_path.rstrip("/") + "/"):
            _stop("SESSION_CGROUP_MISMATCH")
        return raw, owned
    except Exception:
        for descriptor in owned:
            os.close(descriptor)
        raise


def _authority_chain(
    raw_profile: dict[str, object],
    profile: object,
    measurement: object,
    seccomp_program: bytes,
    broker_seccomp_program: bytes,
    tools: dict[str, dict[str, str]],
    manager: CgroupManager,
    controller: ControllerSession,
) -> dict[str, object]:
    measurement = _delegated_measurement(profile, measurement, manager)
    times = _qualification_times()
    content = "qualified-stage\n"
    namespaces = {
        role: _create_user_namespace(role) for role in ("AGENT_WORKER", "BROKER", "EXECUTOR")
    }
    request = _m1_request(times, content)
    packet = _worker_packet(profile, request)
    worker_root, worker_root_record = _materialize_rootfs(
        "AGENT_WORKER", _worker_program(packet), "session-1"
    )
    staging = _mount_staging(profile)
    broker_program = _broker_program(packet)
    broker_runtime_root, broker_runtime_record = _materialize_rootfs(
        "BROKER", broker_program, "session-2"
    )
    worker_connection, broker_connection = socket.socketpair(
        socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC
    )
    worker_connection.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 0)
    broker_connection.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    worker_broker_fd = worker_connection.detach()
    broker_peer_fd = broker_connection.detach()
    artifacts, descriptors, supply_material = _supply_artifacts(
        seccomp_program, tools, worker_root / "usr/lib/harness/worker-tool"
    )
    artifact_by_role = {row["role"]: row for row in artifacts}
    if len(artifact_by_role) != 8:
        _stop("SUPPLY_ARTIFACT_DUPLICATE")
    worker_cgroup = manager.create("worker-session-1")
    broker_cgroup = manager.create("broker-session-2")
    session_raw, session_descriptors = _session_input(
        raw_profile,
        profile,
        measurement,
        claim_digest=_digest_bytes(b"prospective-claim"),
        lineage_root=_digest_bytes(b"prospective-lineage"),
        namespace_binding=namespaces["AGENT_WORKER"],
        rootfs=worker_root,
        worker_broker_fd=worker_broker_fd,
        broker_peer_fd=broker_peer_fd,
        times=times,
        seccomp_fd=artifact_by_role["SECCOMP_PROFILE"]["descriptor"],
        seccomp_digest=artifact_by_role["SECCOMP_PROFILE"]["expected_bytes_digest"],
        tool_fd=artifact_by_role["TOOL"]["descriptor"],
        tool_digest=artifact_by_role["TOOL"]["expected_bytes_digest"],
        cgroup=worker_cgroup,
        manager=manager,
        staging=staging,
    )
    _, durable, l0 = _load_project()
    prospective = l0.measure_placement(profile, measurement, session_raw)
    if (
        prospective.outcome is not l0.L0Outcome.RESOLVED
        or prospective.reason is not l0.L0Reason.PLACEMENT_MEASURED
        or prospective.measurement is None
    ):
        _stop("PROSPECTIVE_PLACEMENT_FAILED:" + prospective.reason.value)
    placement_measurement = prospective.measurement
    placement = {
        "rootfs_binding_digest": placement_measurement.rootfs_binding_digest,
        "staging_binding_digest": placement_measurement.staging_binding_digest,
        "cgroup_binding_digest": placement_measurement.cgroup_binding_digest,
        "broker_binding_digest": placement_measurement.broker_binding_digest,
        "fd_inventory_digest": placement_measurement.fd_inventory_digest,
        "namespace_plan_digest": placement_measurement.namespace_plan_digest,
    }
    supply_raw = _supply_raw(profile, measurement, artifacts, supply_material, placement, times)
    supply, attestor_facts = _verified_supply(profile, measurement, supply_raw, manager)
    chain = _m2_chain(
        profile,
        supply,
        times,
        content,
        manager,
        str(supply_material["registry_snapshot_digest"]),
        controller,
    )
    if chain["request"] != request:
        _stop("WORKER_CONTROLLER_REQUEST_MISMATCH")
    session_raw["claim_digest"] = chain["claim"].claim_digest
    session_raw["lineage_root"] = chain["lineage"]
    planned = l0.prepare_session(
        profile,
        measurement,
        supply,
        chain["claim"],
        session_raw,
        supply_verifier=Ed25519PayloadVerifier(),
        executor_claim_verifier=Ed25519PayloadVerifier(),
    )
    if (
        planned.outcome is not l0.L0Outcome.PREPARED
        or planned.reason is not l0.L0Reason.SESSION_PREPARED
        or planned.plan is None
    ):
        _stop("SESSION_PLAN_FAILED:" + planned.reason.value)
    plan = planned.plan
    times["prepare_at"] = _transition_time(times["claim_at"])
    prepare_raw = {
        "session_record_id": plan.session_record_id,
        "transaction_id": plan.transaction_id,
        "observed_at": times["prepare_at"],
        "executor_id": plan.executor_principal,
        "profile_digest": plan.profile_digest,
        "placement_digest": plan.placement_digest,
        "session_id": plan.session_id,
        "fencing_epoch": plan.fencing_epoch,
        "runtime_bindings": json.loads(plan.runtime_bindings_json),
        "runtime_verification": _verification_source(),
    }
    capture = CaptureVerifier()
    verifier = Ed25519PayloadVerifier()
    capture_store = durable.DurableStore(
        str(chain["database"]),
        verifier,
        executor_claim_verifier=verifier,
        runtime_session_verifier=capture,
    )
    rejected = capture_store.prepare_runtime_session(prepare_raw)
    if (
        rejected.outcome is not durable.DurableOutcome.DENY
        or rejected.reason is not durable.DurableReason.CAPABILITY_INVALID
    ):
        _stop("RUNTIME_CAPTURE_DID_NOT_ROLL_BACK")
    prepare_proof, runtime_attestor_facts = _sign_capture(capture, manager, "runtime-session")
    prepare_raw["runtime_verification"] = _verification_source(prepare_proof)
    prepared = controller.prepare_runtime_session(prepare_raw)
    if (
        prepared.outcome is not durable.DurableOutcome.COMMITTED
        or prepared.reason is not durable.DurableReason.RUNTIME_SESSION_PREPARED
        or prepared.runtime_session is None
    ):
        _stop("RUNTIME_SESSION_PREPARE_FAILED")
    replay = controller.prepare_runtime_session(prepare_raw)
    if replay.outcome is not durable.DurableOutcome.DENY or replay.reason is not durable.DurableReason.REPLAY:
        _stop("RUNTIME_SESSION_REPLAY_NOT_DENIED")
    return {
        "raw_profile": raw_profile,
        "profile": profile,
        "measurement": measurement,
        "times": times,
        "content": content,
        "namespaces": namespaces,
        "worker_root": worker_root,
        "worker_root_record": worker_root_record,
        "staging": staging,
        "worker_broker_fd": worker_broker_fd,
        "broker_peer_fd": broker_peer_fd,
        "broker_runtime_root": broker_runtime_root,
        "broker_runtime_record": broker_runtime_record,
        "broker_program": broker_program,
        "broker_cgroup": broker_cgroup,
        "broker_seccomp_digest": _digest_bytes(broker_seccomp_program),
        "placement_bindings": placement,
        "supply_raw": supply_raw,
        "supply": supply,
        "supply_material": supply_material,
        "attestor_facts": attestor_facts,
        "runtime_attestor_facts": runtime_attestor_facts,
        "supply_descriptors": tuple(descriptors),
        "session_descriptors": session_descriptors,
        "session_raw": session_raw,
        "session_plan": plan,
        "prepare_raw": prepare_raw,
        "runtime_session": prepared.runtime_session,
        "worker_cgroup": worker_cgroup,
        **chain,
    }


def _role_gate_prefix(
    role: str = "AGENT_WORKER",
    session: str = "session-1",
    *,
    report_fd: bool = False,
) -> bytes:
    if role not in {"AGENT_WORKER", "BROKER"} or session not in {"session-1", "session-2"}:
        _stop("ROLE_GATE_BINDING_MISMATCH")
    broker_fd = "0" if role == "BROKER" else "1"
    expected = ["--broker-fd", broker_fd, "--session", session]
    retained = "(0,1,2)" if report_fd else "(0,1)"
    gate = "BROKER_START" if role == "BROKER" else "START"
    gate_fd = 2 if role == "BROKER" else 0
    return (
        b"import os,sys\n"
        + f"if sys.argv[1:]!={expected!r}: raise SystemExit(90)\n".encode("ascii")
        + b"sys.stdin=None;sys.stdout=None;sys.stderr=None\n"
        + b"for descriptor in tuple(int(item) for item in os.listdir('/proc/self/fd')):\n"
        + f" if descriptor not in {retained}:\n".encode("ascii")
        + b"  try: os.close(descriptor)\n"
        + b"  except OSError: pass\n"
        + f"if os.read({gate_fd},{len(gate)})!={gate.encode()!r}: raise SystemExit(92)\n".encode("ascii")
        + f"os.close({gate_fd})\n".encode("ascii")
    )


def _probe_program(kind: str) -> bytes:
    probes = {
        "direct-write": (
            "import os\n"
            "targets=('/staging/forbidden','/opt/harness-m3-source/README.md','/opt/harness-m3-source/.git/config','/home/lab-admin/.profile','/var/lib/harness-m3-controller/synthetic-secret-canary.bin','/var/lib/harness-m3-controller/durable-canary.sqlite3','/etc/machine-id')\n"
            "for path in targets:\n"
            " for flags in (os.O_RDONLY,os.O_WRONLY|os.O_CREAT):\n"
            "  try:\n   descriptor=os.open(path,flags|os.O_CLOEXEC,0o600)\n"
            "  except OSError:\n   continue\n"
            "  else:\n   os.close(descriptor);raise SystemExit(91)\n"
            "raise SystemExit(0)\n"
        ),
        "network": (
            "import socket\n"
            "for family,kind in ((socket.AF_INET,socket.SOCK_STREAM),(socket.AF_INET6,socket.SOCK_STREAM),(socket.AF_UNIX,socket.SOCK_STREAM),(socket.AF_PACKET,socket.SOCK_RAW)):\n"
            " try:\n  socket.socket(family,kind)\n  raise SystemExit(91)\n except PermissionError:\n  pass\n"
            "raise SystemExit(0)\n"
        ),
        "kernel": (
            "try:\n import ctypes,errno\n libc=ctypes.CDLL(None,use_errno=True)\n"
            " for index,(nr,args) in enumerate(((56,(0,0,0,0,0)),(272,(0,)),(308,(-1,0)),(101,(0,0,0,0)),(321,(0,0,0)),(175,(0,0,0)))):\n"
            "  result=libc.syscall(nr,*args)\n  error=ctypes.get_errno()\n"
            "  if result!=-1 or error!=1:\n   raise SystemExit(100+index)\n"
            " try:\n  open('/proc/sys/user/max_user_namespaces','w').write('1')\n except OSError:\n  pass\n else:\n  raise SystemExit(110)\n"
            "except Exception:\n raise SystemExit(111)\n"
            "raise SystemExit(0)\n"
        ),
        "fd-limit": (
            "import os\n"
            "fds=[]\n"
            "try:\n"
            " while True: fds.append(os.open('/proc/self/status',os.O_RDONLY))\n"
            "except OSError as e:\n raise SystemExit(0 if e.errno==24 else 91)\n"
        ),
        "cpu-rate": (
            "import time\n"
            "deadline=time.monotonic()+1.2\n"
            "value=0\n"
            "while time.monotonic()<deadline: value=(value+1)&0x7fffffff\n"
        ),
        "cpu-time": (
            "import time\n"
            "deadline=time.monotonic()+8\n"
            "value=0\n"
            "while time.monotonic()<deadline: value=(value+1)&0x7fffffff\n"
            "raise SystemExit(93)\n"
        ),
        "memory": (
            "data=bytearray(256*1024*1024)\n"
            "for offset in range(0,len(data),4096): data[offset]=1\n"
        ),
        "pids-hold": (
            "import time\n"
            "time.sleep(30)\n"
        ),
        "timeout": (
            "import time\n"
            "time.sleep(30)\n"
        ),
    }
    if kind not in probes:
        _stop("UNKNOWN_PROBE")
    branches: list[str] = []
    for index, (name, source) in enumerate(probes.items()):
        keyword = "if" if index == 0 else "elif"
        body = "".join(" " + line + "\n" for line in source.splitlines())
        branches.append(f"{keyword} kind=={name!r}:\n{body}")
    allowed = tuple(probes)
    return (
        b"import os,sys\n"
        + f"allowed={allowed!r}\n".encode("ascii")
        + b"if len(sys.argv)!=5 or sys.argv[1]!='--probe' or sys.argv[2] not in allowed or sys.argv[3]!='--session': raise SystemExit(90)\n"
        + b"kind=sys.argv[2]\n"
        + b"session=sys.argv[4]\n"
        + b"pids_sessions=tuple('probe-pids-hold-'+str(index) for index in range(8))\n"
        + b"if session!='probe-'+kind and not (kind=='pids-hold' and session in pids_sessions): raise SystemExit(90)\n"
        + b"sys.stdin=None;sys.stdout=None;sys.stderr=None\n"
        + b"for descriptor in tuple(int(item) for item in os.listdir('/proc/self/fd')):\n"
        + b" if descriptor!=0:\n"
        + b"  try: os.close(descriptor)\n"
        + b"  except OSError: pass\n"
        + b"if os.read(0,5)!=b'START': raise SystemExit(92)\n"
        + b"os.close(0)\n"
        + "".join(branches).encode("utf-8")
        + b"raise SystemExit(0)\n"
    )


def _io_probe_program() -> bytes:
    return b'''import os,sys
if sys.argv[1:] != ["--io-probe", "--session", "io-probe"]: raise SystemExit(90)
sys.stdin=None;sys.stdout=None;sys.stderr=None
for descriptor in tuple(int(item) for item in os.listdir('/proc/self/fd')):
 if descriptor not in (0,1):
  try: os.close(descriptor)
  except OSError: pass
if os.read(0,5)!=b"START": raise SystemExit(91)
os.close(0)
try:
 import ctypes,json,mmap,time
 flags=os.O_RDWR|os.O_CLOEXEC|os.O_DIRECT|os.O_SYNC
 descriptor=os.open('/staging/io-scratch',flags)
 buffer=mmap.mmap(-1,4096,flags=mmap.MAP_SHARED,prot=mmap.PROT_READ|mmap.PROT_WRITE)
 buffer[:]=b'Q'*4096
 address=ctypes.addressof(ctypes.c_char.from_buffer(buffer))
 libc=ctypes.CDLL(None,use_errno=True)
 libc.pread.argtypes=(ctypes.c_int,ctypes.c_void_p,ctypes.c_size_t,ctypes.c_longlong)
 libc.pread.restype=ctypes.c_ssize_t
 libc.pwrite.argtypes=(ctypes.c_int,ctypes.c_void_p,ctypes.c_size_t,ctypes.c_longlong)
 libc.pwrite.restype=ctypes.c_ssize_t
 started=time.monotonic_ns()
 for index in range(96):
  if libc.pread(descriptor,address,4096,index*8192)!=4096: raise RuntimeError('PREAD:'+str(ctypes.get_errno()))
 for index in range(96):
  if libc.pwrite(descriptor,address,4096,index*8192+4096)!=4096: raise RuntimeError('PWRITE:'+str(ctypes.get_errno()))
 os.fsync(descriptor)
 elapsed=time.monotonic_ns()-started
 os.close(descriptor);buffer.close()
 record={'elapsed_ns':elapsed,'read_bytes':96*4096,'write_bytes':96*4096,'operations':192}
except BaseException as error:
 encoded=('ERROR:'+type(error).__name__+':'+str(error)[:256]+'\\n').encode('ascii','backslashreplace')
 os.write(1,encoded);os.close(1);raise SystemExit(95)
encoded=json.dumps(record,sort_keys=True,separators=(',',':')).encode('ascii')+b'\\n'
if os.write(1,encoded)!=len(encoded): raise SystemExit(94)
os.close(1)
'''


def _quota_probe_program() -> bytes:
    return b'''import errno,json,os,stat,sys
if sys.argv[1:] != ["--quota-probe", "--session", "quota-probe"]: raise SystemExit(90)
sys.stdin=None;sys.stdout=None;sys.stderr=None
for descriptor in tuple(int(item) for item in os.listdir('/proc/self/fd')):
 if descriptor not in (0,1):
  try: os.close(descriptor)
  except OSError: pass
if os.read(0,5)!=b"START": raise SystemExit(91)
os.close(0)
try:
 for index in range(15):
  descriptor=os.open('/staging/quota-%02d'%index,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC|os.O_NOFOLLOW,0o600)
  os.close(descriptor)
 try:
  descriptor=os.open('/staging/quota-15',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC|os.O_NOFOLLOW,0o600)
 except OSError as error:
  create_errno=error.errno
 else:
  os.close(descriptor);raise RuntimeError('INODE_LIMIT_NOT_ENFORCED')
 descriptor=os.open('/staging/artifact.txt',os.O_WRONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
 os.ftruncate(descriptor,0)
 payload=b'Q'*4096
 offset=0
 while offset<len(payload):
  written=os.write(descriptor,payload[offset:])
  if written<1: raise RuntimeError('SHORT_WRITE')
  offset+=written
 os.fsync(descriptor)
 try:
  written=os.pwrite(descriptor,b'X',4096)
 except OSError as error:
  append_errno=error.errno
 else:
  raise RuntimeError('BYTE_LIMIT_NOT_ENFORCED:'+str(written))
 os.close(descriptor)
 entries=sorted(os.listdir('/staging'))
 rows=[os.stat('/staging/'+name,follow_symlinks=False) for name in entries]
 root=os.stat('/staging',follow_symlinks=False)
 if any(not stat.S_ISREG(row.st_mode) or row.st_nlink!=1 for row in rows): raise RuntimeError('OBJECT_MISMATCH')
 record={'files':len(entries),'inodes':len({root.st_ino}|{row.st_ino for row in rows}),'logical_bytes':sum(row.st_size for row in rows),'allocated_bytes':sum(row.st_blocks*512 for row in rows),'create_errno':create_errno,'append_errno':append_errno}
except BaseException as error:
 encoded=('ERROR:'+type(error).__name__+':'+str(error)[:256]+'\\n').encode('ascii','backslashreplace')
 os.write(1,encoded);os.close(1);raise SystemExit(95)
encoded=json.dumps(record,sort_keys=True,separators=(',',':')).encode('ascii')+b'\\n'
if os.write(1,encoded)!=len(encoded): raise SystemExit(94)
os.close(1)
'''


def _quota_oracle_valid(
    result: object,
    host: object,
    *,
    files: object,
    inodes: object,
    output_bytes: object,
) -> bool:
    result_keys = frozenset(
        {"files", "inodes", "logical_bytes", "allocated_bytes", "create_errno", "append_errno"}
    )
    host_keys = result_keys | frozenset(
        {"entries", "owners_match", "modes_match", "links_match", "statvfs_files", "statvfs_free"}
    )
    if (
        type(result) is not dict
        or type(host) is not dict
        or frozenset(result) != result_keys
        or frozenset(host) != host_keys
        or type(files) is not int
        or type(inodes) is not int
        or type(output_bytes) is not int
        or files < 1
        or inodes != files + 1
        or output_bytes < 1
    ):
        return False
    numeric = result_keys
    if any(type(result[key]) is not int for key in numeric) or any(
        type(host[key]) is not int for key in numeric | {"statvfs_files", "statvfs_free"}
    ):
        return False
    expected_entries = ["artifact.txt", *(f"quota-{index:02d}" for index in range(files - 1))]
    expected = {
        "files": files,
        "inodes": inodes,
        "logical_bytes": output_bytes,
        "allocated_bytes": output_bytes,
    }
    errors = {errno.ENOSPC, errno.EDQUOT}
    return (
        all(result[key] == value and host[key] == value for key, value in expected.items())
        and result["create_errno"] in errors
        and result["append_errno"] in errors
        and host["create_errno"] in errors
        and host["append_errno"] in errors
        and host["entries"] == expected_entries
        and host["owners_match"] is True
        and host["modes_match"] is True
        and host["links_match"] is True
        and host["statvfs_files"] == inodes
        and host["statvfs_free"] == 0
    )


def _launch_resource_probe(
    kind: str,
    rootfs: Path,
    cgroup: Path,
    program: bytes,
    *,
    seccomp_program: bytes,
    apparmor_digest: str,
    profile: dict[str, object],
    expected_limits: dict[str, str],
    instance: int | None = None,
) -> tuple[subprocess.Popen[bytes], int, dict[str, object]]:
    """Launch one bounded worker probe with only an attested start pipe."""

    resources = {row["resource"]: row["limit"] for row in profile["resources"]}
    namespace_fd, namespace_record = _create_user_namespace("AGENT_WORKER")
    start_read, start_write = os.pipe2(os.O_CLOEXEC)
    outer_read, outer_write = os.pipe2(os.O_CLOEXEC)
    status_read, status_write = os.pipe2(os.O_CLOEXEC)
    seccomp_fd = _seccomp_memfd(seccomp_program)
    root_fd = os.open(rootfs, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    outer_high = _duplicate_high(outer_read)
    descriptors = (namespace_fd, seccomp_fd, root_fd, outer_high, status_write)
    if instance is not None and (
        kind != "pids-hold" or type(instance) is not int or instance < 0 or instance > 7
    ):
        _stop("PROBE_INSTANCE_MISMATCH")
    session = "probe-" + kind + ("" if instance is None else "-" + str(instance))
    argv = list(
        _validate_runtime_argv(
            [
                BWRAP,
                "--userns", str(namespace_fd),
                "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-net", "--unshare-cgroup",
                "--assert-userns-disabled", "--hostname", "harness-worker-probe",
                "--new-session", "--die-with-parent", "--clearenv", "--cap-drop", "ALL",
                "--block-fd", str(outer_high), "--json-status-fd", str(status_write),
                "--ro-bind-fd", str(root_fd), "/", "--proc", "/proc",
                "--seccomp", str(seccomp_fd), "--chdir", "/workspace", "--",
                AA_EXEC, "--profile", PROFILE_LABELS["AGENT_WORKER"], "--", PYTHON,
                "-I", "-S", "/usr/lib/harness/worker-tool",
                "--probe", kind, "--session", session,
            ],
            namespace_fd,
            prepared=True,
        )
    )
    process: subprocess.Popen[bytes] | None = None
    try:
        try:
            process = subprocess.Popen(
                argv,
                shell=False,
                close_fds=True,
                pass_fds=descriptors,
                stdin=start_read,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env={},
                cwd="/",
                preexec_fn=_preexec(
                    "AGENT_WORKER", (), resources["OPEN_FDS"], cgroup,
                    user_namespace_fd=namespace_fd,
                ),
            )
        except (OSError, subprocess.SubprocessError) as error:
            for descriptor in (start_write, outer_write, namespace_fd):
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            raise QualificationStop("PROBE_LAUNCH_REJECTED") from error
    finally:
        for descriptor in (start_read, outer_read, outer_high, status_write, seccomp_fd, root_fd):
            try:
                os.close(descriptor)
            except OSError:
                pass
    if process is None:
        _stop("PROBE_LAUNCH_FAILED")
    try:
        limit_readback = {
            name: cgroup.joinpath(name).read_text(encoding="ascii").strip()
            for name in expected_limits
        }
        if (
            str(process.pid) not in cgroup.joinpath("cgroup.procs").read_text(encoding="ascii").split()
            or limit_readback != expected_limits
        ):
            _stop("CGROUP_LIMIT_READBACK_MISMATCH")
        if os.write(outer_write, b"1") != 1:
            _stop("OUTER_GATE_RELEASE_FAILED")
        confined_pid, observed = _find_confined_process(
            cgroup,
            PROFILE_LABELS["AGENT_WORKER"],
            namespace_record,
            expected_inventory=(0,),
            expected_tool_arguments=(
                b"--probe", kind.encode("ascii"), b"--session", session.encode("ascii"),
            ),
        )
        status_value = _status_fields(confined_pid)
        uid_values = status_value.get("Uid", "").split()
        gid_values = status_value.get("Gid", "").split()
        if (
            uid_values != [str(ROLE_IDS["AGENT_WORKER"][0])] * 4
            or gid_values != [str(ROLE_IDS["AGENT_WORKER"][1])] * 4
            or status_value.get("CapAmb") != "0000000000000000"
            or resource.prlimit(confined_pid, resource.RLIMIT_NOFILE)
            != (resources["OPEN_FDS"], resources["OPEN_FDS"])
        ):
            _stop("PROBE_PROCESS_OBSERVATION_FAILED")
        _verify_user_namespace_fd(namespace_fd, namespace_record, require_nested=True)
        _namespace_limit_probe(namespace_fd, None)
        facts = {
            **observed,
            "process_id": confined_pid,
            "launcher_uid": ROLE_IDS["AGENT_WORKER"][0],
            "launcher_gid": ROLE_IDS["AGENT_WORKER"][1],
            "namespace_uid": ROLE_IDS["AGENT_WORKER"][2],
            "namespace_gid": ROLE_IDS["AGENT_WORKER"][3],
            "cgroup": {
                "path": str(cgroup).removeprefix("/sys/fs/cgroup"),
                "limits": limit_readback,
                "processes_before_release": cgroup.joinpath("cgroup.procs").read_text(encoding="ascii").split(),
            },
            "argv": argv,
            "argv_digest": _digest_bytes(_canonical(argv)),
            "program_digest": _digest_bytes(program),
            "user_namespace": namespace_record,
            "policy": {
                "apparmor_digest": apparmor_digest,
                "seccomp_digest": _digest_bytes(seccomp_program),
            },
            "rlimit_nofile": list(resource.prlimit(confined_pid, resource.RLIMIT_NOFILE)),
        }
        if os.write(start_write, START_PACKET) != len(START_PACKET):
            _stop("PROBE_START_GATE_SHORT_WRITE")
        return process, status_read, facts
    finally:
        for descriptor in (start_write, outer_write, namespace_fd):
            try:
                os.close(descriptor)
            except OSError:
                pass


def _cgroup_values(path: Path, name: str) -> dict[str, int]:
    if not name.replace(".", "").replace("_", "").isalnum():
        _stop("CGROUP_COUNTER_NAME_INVALID")
    try:
        lines = path.joinpath(name).read_text(encoding="ascii").splitlines()
    except OSError as error:
        raise QualificationStop("CGROUP_COUNTER_UNAVAILABLE") from error
    result: dict[str, int] = {}
    for line in lines:
        fields = line.split()
        if (
            len(fields) != 2
            or not fields[0].replace("_", "").replace(".", "").isalnum()
            or not fields[1].isdecimal()
        ):
            _stop("CGROUP_COUNTER_MALFORMED")
        if fields[0] in result:
            _stop("CGROUP_COUNTER_DUPLICATE")
        result[fields[0]] = int(fields[1])
    if not result:
        _stop("CGROUP_COUNTER_MALFORMED")
    return result


def _cpu_time_oracle_valid(
    trigger_usage: object,
    limit: object,
    return_code: object,
    remaining_processes: object,
) -> bool:
    return (
        type(trigger_usage) is int
        and type(limit) is int
        and type(return_code) is int
        and type(remaining_processes) is list
        and limit > 0
        and limit <= trigger_usage <= limit + 250_000
        and return_code < 0
        and not remaining_processes
    )


def _io_stat_device(cgroup: Path, device: str) -> dict[str, int]:
    if not re.fullmatch(r"[0-9]+:[0-9]+", device):
        _stop("IO_STAT_DEVICE_MALFORMED")
    allowed = frozenset({"rbytes", "wbytes", "rios", "wios", "dbytes", "dios"})
    required = frozenset({"rbytes", "wbytes", "rios", "wios"})
    match: dict[str, int] | None = None
    for line in cgroup.joinpath("io.stat").read_text(encoding="ascii").splitlines():
        fields = line.split()
        if not fields or fields[0] != device:
            continue
        if match is not None:
            _stop("IO_STAT_DEVICE_DUPLICATE")
        if len(fields) == 1:
            match = {key: 0 for key in allowed}
            continue
        values: dict[str, int] = {}
        for field in fields[1:]:
            parts = field.split("=", 1)
            if (
                len(parts) != 2
                or parts[0] not in allowed
                or parts[0] in values
                or not parts[1].isascii()
                or not parts[1].isdecimal()
            ):
                _stop("IO_STAT_MALFORMED")
            values[parts[0]] = int(parts[1])
        if not required.issubset(values):
            _stop("IO_STAT_MALFORMED")
        match = values
    return {key: 0 for key in allowed} if match is None else match


def _io_limit_is_unbounded(raw: str, device: str) -> bool:
    if type(raw) is not str or not re.fullmatch(r"[0-9]+:[0-9]+", device):
        return False
    rows = [line.split() for line in raw.splitlines() if line.strip()]
    matches = [row for row in rows if row and row[0] == device]
    if not matches:
        return True
    if len(matches) != 1:
        return False
    values = {}
    for field in matches[0][1:]:
        parts = field.split("=", 1)
        if len(parts) != 2 or parts[0] in values:
            return False
        values[parts[0]] = parts[1]
    return values == {"rbps": "max", "wbps": "max", "riops": "max", "wiops": "max"}


def _create_io_scratch(path: Path, manager: CgroupManager) -> dict[str, object]:
    expected_uid, expected_gid = ROLE_IDS["EXECUTOR"][:2]
    descriptor = os.open(
        path,
        os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        os.fchown(descriptor, expected_uid, expected_gid)
        os.fchmod(descriptor, 0o600)
        os.posix_fallocate(descriptor, 0, 1 << 20)
        block = b"R" * 4096
        for index in range(96):
            if os.pwrite(descriptor, block, index * 8192) != len(block):
                _stop("IO_SCRATCH_INITIALIZATION_FAILED")
        os.fsync(descriptor)
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or (info.st_uid, info.st_gid) != (expected_uid, expected_gid)
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size != 1 << 20
        ):
            _stop("IO_SCRATCH_IDENTITY_MISMATCH")
    finally:
        os.close(descriptor)
    binding = _io_controller_device(path)
    if binding["controller_device"] != manager.io_device["controller_device"]:
        _stop("IO_SCRATCH_DEVICE_SUBSTITUTION")
    return {
        "path": str(path),
        "device": info.st_dev,
        "inode": info.st_ino,
        "bytes": info.st_size,
        "initialized_read_bytes": 96 * 4096,
        "uid": info.st_uid,
        "gid": info.st_gid,
        "mode": stat.S_IMODE(info.st_mode),
        "backing_device": binding["backing_device"],
        "controller_device": binding["controller_device"],
        "binding_digest": binding["binding_digest"],
    }


def _run_io_workload(
    raw_profile: dict[str, object],
    rootfs: Path,
    program: bytes,
    scratch: Path,
    cgroup: Path,
    seccomp_program: bytes,
    apparmor_digest: str,
    expected_io_max: str,
    manager: CgroupManager,
) -> dict[str, object]:
    resources = {row["resource"]: row["limit"] for row in raw_profile["resources"]}
    namespace_fd, namespace_record = _create_user_namespace("EXECUTOR")
    start_read, start_write = os.pipe2(os.O_CLOEXEC)
    result_read, result_write = os.pipe2(os.O_CLOEXEC)
    outer_read, outer_write = os.pipe2(os.O_CLOEXEC)
    status_read, status_write = os.pipe2(os.O_CLOEXEC)
    seccomp_fd = _seccomp_memfd(seccomp_program)
    root_fd = os.open(rootfs, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    scratch_fd = os.open(scratch, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
    outer_high = _duplicate_high(outer_read)
    descriptors = (namespace_fd, seccomp_fd, root_fd, scratch_fd, outer_high, status_write)
    argv = list(
        _validate_runtime_argv(
            [
                BWRAP,
                "--userns", str(namespace_fd),
                "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-net", "--unshare-cgroup",
                "--assert-userns-disabled", "--hostname", "harness-io-probe",
                "--new-session", "--die-with-parent", "--clearenv", "--cap-drop", "ALL",
                "--block-fd", str(outer_high), "--json-status-fd", str(status_write),
                "--ro-bind-fd", str(root_fd), "/",
                "--bind-fd", str(scratch_fd), "/staging/io-scratch",
                "--proc", "/proc", "--seccomp", str(seccomp_fd), "--chdir", "/workspace", "--",
                AA_EXEC, "--profile", PROFILE_LABELS["EXECUTOR"], "--", PYTHON,
                "-I", "-S", "/usr/lib/harness/worker-tool",
                "--io-probe", "--session", "io-probe",
            ],
            namespace_fd,
            prepared=True,
        )
    )
    process: subprocess.Popen[bytes] | None = None
    raw_result = b""
    external_elapsed_ns = 0
    device = expected_io_max.split()[0] if expected_io_max else ""
    try:
        process = subprocess.Popen(
            argv,
            shell=False,
            close_fds=True,
            pass_fds=descriptors,
            stdin=start_read,
            stdout=result_write,
            stderr=subprocess.DEVNULL,
            env={},
            cwd="/",
            preexec_fn=_preexec(
                "EXECUTOR", (), resources["OPEN_FDS"], cgroup,
                user_namespace_fd=namespace_fd,
            ),
        )
        for descriptor in (start_read, result_write, outer_read, outer_high, status_write, seccomp_fd, root_fd, scratch_fd):
            os.close(descriptor)
        if str(process.pid) not in cgroup.joinpath("cgroup.procs").read_text(encoding="ascii").split():
            _stop("IO_PROBE_CGROUP_ATTACH_FAILED")
        if os.write(outer_write, b"1") != 1:
            _stop("IO_PROBE_OUTER_GATE_FAILED")
        os.close(outer_write)
        outer_write = -1
        confined_pid, facts = _find_confined_process(
            cgroup,
            PROFILE_LABELS["EXECUTOR"],
            namespace_record,
            expected_inventory=(0, 1),
            expected_tool_arguments=(b"--io-probe", b"--session", b"io-probe"),
        )
        status_value = _status_fields(confined_pid)
        if (
            status_value.get("Uid", "").split() != [str(ROLE_IDS["EXECUTOR"][0])] * 4
            or status_value.get("Gid", "").split() != [str(ROLE_IDS["EXECUTOR"][1])] * 4
            or status_value.get("CapAmb") != "0000000000000000"
            or resource.prlimit(confined_pid, resource.RLIMIT_NOFILE)
            != (resources["OPEN_FDS"], resources["OPEN_FDS"])
        ):
            _stop("IO_PROBE_PROCESS_MISMATCH")
        before = _io_stat_device(cgroup, device)
        started = time.monotonic_ns()
        if os.write(start_write, START_PACKET) != len(START_PACKET):
            _stop("IO_PROBE_START_GATE_FAILED")
        os.close(start_write)
        start_write = -1
        try:
            raw_result = _read_pipe_line(
                result_read,
                maximum=1024,
                timeout=resources["WALL_TIME"] / 1000.0,
            )
        except QualificationStop as error:
            return_code = process.wait(timeout=3)
            _stop("IO_PROBE_REPORT_FAILED:" + str(error) + ":" + str(return_code))
        external_elapsed_ns = time.monotonic_ns() - started
        os.close(result_read)
        result_read = -1
        return_code, status_digest = _complete_role(process, status_read, cgroup, timeout=0.5)
        status_read = -1
        if return_code != 0:
            _stop(
                "IO_PROBE_PROCESS_FAILED:"
                + str(return_code)
                + ":"
                + raw_result.decode("ascii", "backslashreplace")[:384]
            )
        after = _io_stat_device(cgroup, device)
        manager_values = {
            "io.max": cgroup.joinpath("io.max").read_text(encoding="ascii").strip(),
            "cgroup.events": cgroup.joinpath("cgroup.events").read_text(encoding="ascii").splitlines(),
        }
        result = _strict_bytes(raw_result)
        if (
            type(result) is not dict
            or frozenset(result) != {"elapsed_ns", "read_bytes", "write_bytes", "operations"}
            or result["read_bytes"] != 96 * 4096
            or result["write_bytes"] != 96 * 4096
            or result["operations"] != 192
            or type(result["elapsed_ns"]) is not int
            or result["elapsed_ns"] < 1
        ):
            _stop("IO_PROBE_RESULT_MALFORMED")
        delta = {key: after.get(key, 0) - before.get(key, 0) for key in before}
        if delta["rbytes"] < result["read_bytes"] or delta["wbytes"] < result["write_bytes"]:
            _stop(
                "IO_STAT_ACCOUNTING_MISMATCH:"
                + _canonical(
                    {
                        "device": device,
                        "before": before,
                        "after": after,
                        "delta": delta,
                        "result": result,
                    }
                ).decode("ascii")
            )
        return {
            "result": result,
            "external_elapsed_ns": external_elapsed_ns,
            "before": before,
            "after": after,
            "delta": delta,
            "runtime": {
                **facts,
                "process_id": confined_pid,
                "argv_digest": _digest_bytes(_canonical(argv)),
                "program_digest": _digest_bytes(program),
                "seccomp_digest": _digest_bytes(seccomp_program),
                "apparmor_digest": apparmor_digest,
                "user_namespace": namespace_record,
            },
            "controls": manager_values,
            "status_digest": status_digest,
        }
    finally:
        for descriptor in (
            start_read, start_write, result_read, result_write, outer_read, outer_write,
            status_read, status_write, seccomp_fd, root_fd, scratch_fd, outer_high, namespace_fd,
        ):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        if process is not None and process.poll() is None:
            try:
                cgroup.joinpath("cgroup.kill").write_text("1", encoding="ascii")
                process.wait(timeout=3)
            except (OSError, subprocess.TimeoutExpired):
                process.kill()
                process.wait(timeout=1)
        if process is not None:
            try:
                manager.kill(cgroup)
            except OSError as error:
                raise QualificationStop("IO_PROBE_CLEANUP_FAILED") from error


def _run_io_oracle(
    raw_profile: dict[str, object],
    seccomp_program: bytes,
    apparmor_digest: str,
    manager: CgroupManager,
) -> dict[str, object]:
    program = _io_probe_program()
    rootfs, root_record = _materialize_rootfs(
        "EXECUTOR", program, "io-probe", executor_input=b"{}", io_probe=True
    )
    device = str(manager.io_device["controller_device"])
    control_cgroup = manager.create("probe-io-control")
    limited_cgroup = manager.create("probe-io-limited")
    unbounded = f"{device} rbps=max wbps=max riops=max wiops=max"
    control_cgroup.joinpath("io.max").write_text(unbounded, encoding="ascii")
    control_readback = control_cgroup.joinpath("io.max").read_text(encoding="ascii").strip()
    if not _io_limit_is_unbounded(control_readback, device):
        _stop("IO_CONTROL_NOT_UNBOUNDED")
    control_path = RUNTIME / "io-control.bin"
    limited_path = RUNTIME / "io-limited.bin"
    control_binding = _create_io_scratch(control_path, manager)
    limited_binding = _create_io_scratch(limited_path, manager)
    try:
        control = _run_io_workload(
            raw_profile, rootfs, program, control_path, control_cgroup,
            seccomp_program, apparmor_digest, unbounded, manager,
        )
        limited = _run_io_workload(
            raw_profile, rootfs, program, limited_path, limited_cgroup,
            seccomp_program, apparmor_digest, manager.limits["io.max"], manager,
        )
    finally:
        control_path.unlink(missing_ok=True)
        limited_path.unlink(missing_ok=True)
    control_ns = control["external_elapsed_ns"]
    limited_ns = limited["external_elapsed_ns"]
    if (
        control_ns > 500_000_000
        or limited_ns < 1_300_000_000
        or limited_ns > 3_000_000_000
        or limited_ns < control_ns * 3
        or limited["controls"]["io.max"] != manager.limits["io.max"]
    ):
        _stop("IO_LIMIT_ENFORCEMENT_ORACLE_FAILED")
    return {
        "device": manager.io_device,
        "rootfs": root_record,
        "control_scratch": control_binding,
        "limited_scratch": limited_binding,
        "control": control,
        "limited": limited,
        "oracle": {
            "control_maximum_ns": 500_000_000,
            "limited_minimum_ns": 1_300_000_000,
            "limited_maximum_ns": 3_000_000_000,
            "minimum_slowdown_factor": 3,
        },
    }


def _quota_host_observation(
    staging: dict[str, object],
    *,
    files: int,
    inodes: int,
    output_bytes: int,
) -> dict[str, object]:
    descriptor = staging.get("descriptor")
    if (
        type(descriptor) is not int
        or descriptor < 0
        or type(files) is not int
        or type(inodes) is not int
        or type(output_bytes) is not int
    ):
        _stop("QUOTA_BINDING_MISMATCH")
    entries = sorted(os.listdir(descriptor))
    rows = []
    for name in entries:
        if type(name) is not str or not name.isascii() or "/" in name or name in {".", ".."}:
            _stop("QUOTA_ENTRY_MALFORMED")
        rows.append(os.stat(name, dir_fd=descriptor, follow_symlinks=False))
    root = os.fstat(descriptor)
    owner = ROLE_IDS["EXECUTOR"][:2]
    file_system = os.fstatvfs(descriptor)

    try:
        created = os.open(
            "quota-15",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=descriptor,
        )
    except OSError as error:
        create_errno = error.errno
    else:
        os.close(created)
        _stop("HOST_INODE_LIMIT_NOT_ENFORCED")

    artifact = os.open(
        "artifact.txt",
        os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        dir_fd=descriptor,
    )
    try:
        try:
            written = os.pwrite(artifact, b"X", output_bytes)
        except OSError as error:
            append_errno = error.errno
        else:
            _stop("HOST_BYTE_LIMIT_NOT_ENFORCED:" + str(written))
    finally:
        os.close(artifact)

    return {
        "entries": entries,
        "files": len(rows),
        "inodes": len({root.st_ino, *(row.st_ino for row in rows)}),
        "logical_bytes": sum(row.st_size for row in rows),
        "allocated_bytes": sum(row.st_blocks * 512 for row in rows),
        "create_errno": create_errno,
        "append_errno": append_errno,
        "owners_match": all((row.st_uid, row.st_gid) == owner for row in rows),
        "modes_match": all(stat.S_ISREG(row.st_mode) and stat.S_IMODE(row.st_mode) == 0o600 for row in rows),
        "links_match": all(row.st_nlink == 1 and row.st_dev == root.st_dev for row in rows),
        "statvfs_files": file_system.f_files,
        "statvfs_free": file_system.f_ffree,
    }


def _run_quota_oracle(
    raw_profile: dict[str, object],
    profile: object,
    seccomp_program: bytes,
    apparmor_digest: str,
    manager: CgroupManager,
) -> dict[str, object]:
    resources = {row["resource"]: row["limit"] for row in raw_profile["resources"]}
    files = resources["FILES"]
    inodes = resources["INODES"]
    output_bytes = resources["OUTPUT_BYTES"]
    program = _quota_probe_program()
    rootfs, root_record = _materialize_rootfs(
        "EXECUTOR", program, "quota-probe", executor_input=b"{}"
    )
    staging = _mount_staging(profile, "quota-probe")
    cgroup = manager.create("probe-quota")
    namespace_fd, namespace_record = _create_user_namespace("EXECUTOR")
    start_read, start_write = os.pipe2(os.O_CLOEXEC)
    result_read, result_write = os.pipe2(os.O_CLOEXEC)
    outer_read, outer_write = os.pipe2(os.O_CLOEXEC)
    status_read, status_write = os.pipe2(os.O_CLOEXEC)
    seccomp_fd = _seccomp_memfd(seccomp_program)
    root_fd = os.open(rootfs, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    stage_fd = os.open(
        staging["path"], os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    )
    outer_high = _duplicate_high(outer_read)
    descriptors = (namespace_fd, seccomp_fd, root_fd, stage_fd, outer_high, status_write)
    argv = list(
        _validate_runtime_argv(
            [
                BWRAP,
                "--userns", str(namespace_fd),
                "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-net", "--unshare-cgroup",
                "--assert-userns-disabled", "--hostname", "harness-quota-probe",
                "--new-session", "--die-with-parent", "--clearenv", "--cap-drop", "ALL",
                "--block-fd", str(outer_high), "--json-status-fd", str(status_write),
                "--ro-bind-fd", str(root_fd), "/",
                "--bind-fd", str(stage_fd), "/staging",
                "--proc", "/proc", "--seccomp", str(seccomp_fd), "--chdir", "/workspace", "--",
                AA_EXEC, "--profile", PROFILE_LABELS["EXECUTOR"], "--", PYTHON,
                "-I", "-S", "/usr/lib/harness/worker-tool",
                "--quota-probe", "--session", "quota-probe",
            ],
            namespace_fd,
            prepared=True,
        )
    )
    process: subprocess.Popen[bytes] | None = None
    raw_result = b""
    try:
        process = subprocess.Popen(
            argv,
            shell=False,
            close_fds=True,
            pass_fds=descriptors,
            stdin=start_read,
            stdout=result_write,
            stderr=subprocess.DEVNULL,
            env={},
            cwd="/",
            preexec_fn=_preexec(
                "EXECUTOR", (), resources["OPEN_FDS"], cgroup,
                user_namespace_fd=namespace_fd,
            ),
        )
        for descriptor in (
            start_read, result_write, outer_read, outer_high, status_write,
            seccomp_fd, root_fd, stage_fd,
        ):
            os.close(descriptor)
        if str(process.pid) not in cgroup.joinpath("cgroup.procs").read_text(encoding="ascii").split():
            _stop("QUOTA_PROBE_CGROUP_ATTACH_FAILED")
        if os.write(outer_write, b"1") != 1:
            _stop("QUOTA_PROBE_OUTER_GATE_FAILED")
        os.close(outer_write)
        outer_write = -1
        confined_pid, facts = _find_confined_process(
            cgroup,
            PROFILE_LABELS["EXECUTOR"],
            namespace_record,
            expected_inventory=(0, 1),
            expected_tool_arguments=(b"--quota-probe", b"--session", b"quota-probe"),
        )
        status_value = _status_fields(confined_pid)
        if (
            status_value.get("Uid", "").split() != [str(ROLE_IDS["EXECUTOR"][0])] * 4
            or status_value.get("Gid", "").split() != [str(ROLE_IDS["EXECUTOR"][1])] * 4
            or status_value.get("CapAmb") != "0000000000000000"
            or resource.prlimit(confined_pid, resource.RLIMIT_NOFILE)
            != (resources["OPEN_FDS"], resources["OPEN_FDS"])
        ):
            _stop("QUOTA_PROBE_PROCESS_MISMATCH")
        staging_oracle = _executor_staging_oracle(confined_pid, staging)
        if os.write(start_write, START_PACKET) != len(START_PACKET):
            _stop("QUOTA_PROBE_START_GATE_FAILED")
        os.close(start_write)
        start_write = -1
        raw_result = _read_pipe_line(
            result_read,
            maximum=1024,
            timeout=resources["WALL_TIME"] / 1000.0,
        )
        os.close(result_read)
        result_read = -1
        return_code, status_digest = _complete_role(process, status_read, cgroup, timeout=0.5)
        status_read = -1
        manager.kill(cgroup)
        if return_code != 0 or raw_result.startswith(b"ERROR:"):
            _stop(
                "QUOTA_PROBE_PROCESS_FAILED:"
                + str(return_code)
                + ":"
                + raw_result.decode("ascii", "backslashreplace")[:384]
            )
        result = _strict_bytes(raw_result)
        host = _quota_host_observation(
            staging,
            files=files,
            inodes=inodes,
            output_bytes=output_bytes,
        )
        if not _quota_oracle_valid(
            result,
            host,
            files=files,
            inodes=inodes,
            output_bytes=output_bytes,
        ):
            _stop(
                "QUOTA_ENFORCEMENT_ORACLE_FAILED:"
                + _canonical({"result": result, "host": host}).decode("ascii")[:1024]
            )
        return {
            "result": result,
            "host": host,
            "staging": {
                key: staging[key]
                for key in (
                    "root_id", "root_identity", "mount_id", "mount_identity", "device", "inode",
                    "files", "inodes", "bytes", "mount_options", "mount_source", "mountinfo_digest",
                )
            },
            "runtime": {
                **facts,
                "process_id": confined_pid,
                "argv_digest": _digest_bytes(_canonical(argv)),
                "program_digest": _digest_bytes(program),
                "seccomp_digest": _digest_bytes(seccomp_program),
                "apparmor_digest": apparmor_digest,
                "user_namespace": namespace_record,
                "staging_oracle": staging_oracle,
            },
            "rootfs": root_record,
            "status_digest": status_digest,
            "cgroup_populated_after_cleanup": 0,
        }
    finally:
        for descriptor in (
            start_read, start_write, result_read, result_write, outer_read, outer_write,
            status_read, status_write, seccomp_fd, root_fd, stage_fd, outer_high, namespace_fd,
        ):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        if process is not None and process.poll() is None:
            try:
                cgroup.joinpath("cgroup.kill").write_text("1", encoding="ascii")
                process.wait(timeout=3)
            except (OSError, subprocess.TimeoutExpired):
                process.kill()
                process.wait(timeout=1)
        try:
            manager.kill(cgroup)
        except OSError as error:
            raise QualificationStop("QUOTA_PROBE_CLEANUP_FAILED") from error
        try:
            os.close(staging["descriptor"])
        except OSError:
            pass
        _run([UMOUNT, str(staging["path"])], timeout=10)
        shutil.rmtree(staging["path"])


def _event(test_id: str, kind: str, subject: str, observed: object, oracle: object) -> dict[str, object]:
    return {
        "event_id": "event-" + test_id.lower().replace("_", "-").replace("/", "-")[:120],
        "type": kind,
        "test_id": test_id,
        "subject": subject,
        "observed_digest": _digest_bytes(_canonical(observed)),
        "oracle_digest": _digest_bytes(_canonical(oracle)),
        "result": "PASS",
    }


def _test_row(
    test_id: str,
    oracle: str,
    event_id: str,
    *,
    phase: str = "run",
) -> dict[str, object]:
    if test_id not in TEST_MATRIX or phase not in {"run", "recover"}:
        _stop("TEST_BINDING_MISMATCH")
    return {
        "id": test_id,
        "matrix_ids": list(TEST_MATRIX[test_id]),
        "command": [PYTHON, str(SOURCE / "scripts/run_m3_vm_conformance.py"), "--phase", phase],
        "exit_code": 0,
        "oracle": oracle,
        "result": "PASS",
        "event_ids": [event_id],
    }


def _record_pass(
    tests: list[dict[str, object]],
    events: list[dict[str, object]],
    test_id: str,
    kind: str,
    subject: str,
    observed: object,
    oracle: object,
    text: str,
    *,
    phase: str = "run",
) -> None:
    event = _event(test_id, kind, subject, observed, oracle)
    if event["event_id"] in {row["event_id"] for row in events}:
        _stop("DUPLICATE_EVENT")
    events.append(event)
    tests.append(_test_row(test_id, text, str(event["event_id"]), phase=phase))


def _validate_test_event_set(
    tests: object,
    events: object,
    expected_ids: frozenset[str],
) -> None:
    test_keys = frozenset(
        {"id", "matrix_ids", "command", "exit_code", "oracle", "result", "event_ids"}
    )
    event_keys = frozenset(
        {"event_id", "type", "test_id", "subject", "observed_digest", "oracle_digest", "result"}
    )
    if (
        type(tests) is not list
        or type(events) is not list
        or type(expected_ids) is not frozenset
        or len(tests) != len(expected_ids)
        or len(events) != len(expected_ids)
    ):
        _stop("TEST_EVENT_SET_MISMATCH")
    by_test: dict[str, dict[str, object]] = {}
    for row in tests:
        if type(row) is not dict or frozenset(row) != test_keys:
            _stop("TEST_RECORD_MALFORMED")
        test_id = row["id"]
        phase = "recover" if test_id == "T-M3-RESTART-CLEANUP-NO-RESUME" else "run"
        if (
            type(test_id) is not str
            or test_id not in expected_ids
            or test_id in by_test
            or row["matrix_ids"] != list(TEST_MATRIX[test_id])
            or row["command"]
            != [PYTHON, str(SOURCE / "scripts/run_m3_vm_conformance.py"), "--phase", phase]
            or row["exit_code"] != 0
            or type(row["exit_code"]) is not int
            or type(row["oracle"]) is not str
            or not row["oracle"]
            or row["result"] != "PASS"
            or type(row["event_ids"]) is not list
            or len(row["event_ids"]) != 1
            or type(row["event_ids"][0]) is not str
        ):
            _stop("TEST_RECORD_MALFORMED")
        by_test[test_id] = row
    by_event: dict[str, dict[str, object]] = {}
    for row in events:
        if type(row) is not dict or frozenset(row) != event_keys:
            _stop("EVENT_RECORD_MALFORMED")
        event_id = row["event_id"]
        test_id = row["test_id"]
        if (
            type(event_id) is not str
            or not event_id
            or event_id in by_event
            or type(test_id) is not str
            or test_id not in by_test
            or by_test[test_id]["event_ids"] != [event_id]
            or row["type"]
            not in {"TCB_LAUNCH", "TCB_DENY", "TCB_RESOURCE", "TCB_KILL", "TCB_CLEANUP", "TCB_STAGE", "TCB_RECOVERY"}
            or type(row["subject"]) is not str
            or not row["subject"]
            or not _is_digest(row["observed_digest"])
            or not _is_digest(row["oracle_digest"])
            or row["result"] != "PASS"
        ):
            _stop("EVENT_RECORD_MALFORMED")
        by_event[event_id] = row
    if frozenset(by_test) != expected_ids or len(by_event) != len(events):
        _stop("TEST_EVENT_SET_MISMATCH")


def _runtime_mount_targets() -> list[str]:
    prefix = str(RUNTIME).rstrip("/") + "/"
    targets: list[str] = []
    for line in Path("/proc/self/mountinfo").read_text(encoding="ascii").splitlines():
        fields = line.split()
        if len(fields) < 10:
            _stop("MOUNTINFO_MALFORMED")
        target = fields[4]
        if target == str(RUNTIME) or target.startswith(prefix):
            targets.append(target)
    if len(targets) != len(set(targets)):
        _stop("RUNTIME_MOUNT_DUPLICATE")
    return sorted(targets, reverse=True)


def _close_non_stdio_descriptors() -> dict[str, object]:
    def live() -> list[int]:
        result: list[int] = []
        for item in os.listdir("/proc/self/fd"):
            if not item.isdecimal() or int(item) <= 2:
                continue
            descriptor = int(item)
            try:
                os.fstat(descriptor)
            except OSError as error:
                if error.errno != errno.EBADF:
                    raise
            else:
                result.append(descriptor)
        return sorted(result)

    descriptors = live()
    targets = []
    for descriptor in descriptors:
        try:
            targets.append(os.readlink(f"/proc/self/fd/{descriptor}"))
        except OSError:
            targets.append("CLOSED_DURING_OBSERVATION")
        try:
            os.close(descriptor)
        except OSError:
            pass
    remaining = live()
    if remaining:
        _stop("DESCRIPTOR_CLEANUP_FAILED")
    return {
        "closed_count": len(descriptors),
        "closed_targets_digest": _digest_bytes(_canonical(targets)),
        "remaining_non_stdio": remaining,
    }


def _cleanup_disposable_runtime(manager: CgroupManager, staging_path: Path) -> dict[str, object]:
    if staging_path != RUNTIME / "staging" / "session-1":
        _stop("CLEANUP_TARGET_MISMATCH")
    manager.cleanup()
    descriptors = _close_non_stdio_descriptors()
    mounts = _runtime_mount_targets()
    if mounts != [str(staging_path)]:
        _stop("RUNTIME_MOUNT_SET_MISMATCH")
    _run([UMOUNT, str(staging_path)], timeout=10)
    if _runtime_mount_targets():
        _stop("RUNTIME_MOUNT_CLEANUP_FAILED")
    info = os.lstat(RUNTIME)
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != 0
        or info.st_gid != 0
        or stat.S_IMODE(info.st_mode) != 0o711
    ):
        _stop("RUNTIME_ROOT_IDENTITY_MISMATCH")
    shutil.rmtree(RUNTIME)
    if RUNTIME.exists():
        _stop("RUNTIME_STORAGE_CLEANUP_FAILED")
    return {
        "descriptors": descriptors,
        "removed_mounts": mounts,
        "remaining_mounts": [],
        "runtime_root_absent": True,
        "cgroup_children_empty": not manager.children,
    }


def _run_cgroup_resource_oracles(
    raw_profile: dict[str, object],
    probe_root: Path,
    probe_program: bytes,
    seccomp_program: bytes,
    apparmor_digest: str,
    manager: CgroupManager,
    tests: list[dict[str, object]],
    events: list[dict[str, object]],
) -> dict[str, object]:
    """Exercise the exact cgroup limits with fixed, disposable workloads."""

    results: dict[str, object] = {}

    cpu_cgroup = manager.create("probe-cpu-rate")
    cpu_before = _cgroup_values(cpu_cgroup, "cpu.stat")
    cpu_process, cpu_status, cpu_facts = _launch_resource_probe(
        "cpu-rate", probe_root, cpu_cgroup, probe_program,
        seccomp_program=seccomp_program,
        apparmor_digest=apparmor_digest,
        profile=raw_profile,
        expected_limits=manager.limits,
    )
    cpu_return, cpu_status_digest = _complete_role(
        cpu_process, cpu_status, cpu_cgroup, timeout=3
    )
    cpu_after = _cgroup_values(cpu_cgroup, "cpu.stat")
    manager.kill(cpu_cgroup)
    cpu_delta = {
        key: cpu_after.get(key, 0) - cpu_before.get(key, 0)
        for key in ("usage_usec", "nr_periods", "nr_throttled", "throttled_usec")
    }
    if (
        cpu_return != 0
        or cpu_cgroup.joinpath("cpu.max").read_text(encoding="ascii").strip()
        != manager.limits["cpu.max"]
        or any(cpu_delta[key] <= 0 for key in cpu_delta)
    ):
        _stop("CPU_LIMIT_ORACLE_FAILED")
    results["cpu"] = {
        "before": cpu_before,
        "after": cpu_after,
        "delta": cpu_delta,
        "facts": cpu_facts,
        "status": cpu_status_digest,
    }

    cpu_time_cgroup = manager.create("probe-cpu-time")
    cpu_time_before = _cgroup_values(cpu_time_cgroup, "cpu.stat")
    cpu_time_process, cpu_time_status, cpu_time_facts = _launch_resource_probe(
        "cpu-time", probe_root, cpu_time_cgroup, probe_program,
        seccomp_program=seccomp_program,
        apparmor_digest=apparmor_digest,
        profile=raw_profile,
        expected_limits=manager.limits,
    )
    cpu_time_limit = {
        row["resource"]: row["limit"] for row in raw_profile["resources"]
    }["CPU_TIME"] * 1000
    deadline = time.monotonic() + 6
    trigger_usage = 0
    while time.monotonic() < deadline and cpu_time_process.poll() is None:
        current = _cgroup_values(cpu_time_cgroup, "cpu.stat").get("usage_usec", 0)
        delta = current - cpu_time_before.get("usage_usec", 0)
        if delta >= cpu_time_limit:
            trigger_usage = delta
            cpu_time_cgroup.joinpath("cgroup.kill").write_text("1", encoding="ascii")
            break
        time.sleep(0.01)
    cpu_time_return, cpu_time_status_digest = _complete_role(
        cpu_time_process, cpu_time_status, cpu_time_cgroup, timeout=0.5
    )
    manager.kill(cpu_time_cgroup)
    cpu_time_after = _cgroup_values(cpu_time_cgroup, "cpu.stat")
    if not _cpu_time_oracle_valid(
        trigger_usage,
        cpu_time_limit,
        cpu_time_return,
        cpu_time_cgroup.joinpath("cgroup.procs").read_text(encoding="ascii").split(),
    ):
        _stop("CPU_TIME_LIMIT_ORACLE_FAILED")
    results["cpu"]["time_budget"] = {
        "limit_usec": cpu_time_limit,
        "trigger_usage_usec": trigger_usage,
        "overshoot_usec": trigger_usage - cpu_time_limit,
        "before": cpu_time_before,
        "after": cpu_time_after,
        "return_code": cpu_time_return,
        "facts": cpu_time_facts,
        "status": cpu_time_status_digest,
        "cgroup_populated_after_kill": 0,
    }
    _record_pass(
        tests, events, "T-M3-CGROUP-CPU-LIMIT", "TCB_RESOURCE", "cpu.max",
        results["cpu"],
        {
            "cpu.max": manager.limits["cpu.max"],
            "throttled": True,
            "cpu_time_limit_usec": cpu_time_limit,
            "tree_killed": True,
        },
        "Exact cpu.max throttling and the cgroup cpu.stat CPU-time threshold were enforced by a bounded external whole-tree kill.",
    )

    memory_cgroup = manager.create("probe-memory")
    memory_before = _cgroup_values(memory_cgroup, "memory.events")
    swap_before = int(memory_cgroup.joinpath("memory.swap.current").read_text(encoding="ascii").strip())
    memory_process, memory_status, memory_facts = _launch_resource_probe(
        "memory", probe_root, memory_cgroup, probe_program,
        seccomp_program=seccomp_program,
        apparmor_digest=apparmor_digest,
        profile=raw_profile,
        expected_limits=manager.limits,
    )
    memory_return, memory_status_digest = _complete_role(
        memory_process, memory_status, memory_cgroup, timeout=3
    )
    memory_after = _cgroup_values(memory_cgroup, "memory.events")
    swap_after = int(memory_cgroup.joinpath("memory.swap.current").read_text(encoding="ascii").strip())
    memory_current = int(memory_cgroup.joinpath("memory.current").read_text(encoding="ascii").strip())
    manager.kill(memory_cgroup)
    if (
        memory_return == 0
        or memory_cgroup.joinpath("memory.max").read_text(encoding="ascii").strip()
        != manager.limits["memory.max"]
        or memory_cgroup.joinpath("memory.swap.max").read_text(encoding="ascii").strip() != "0"
        or memory_after.get("max", 0) <= memory_before.get("max", 0)
        or memory_after.get("oom_kill", 0) <= memory_before.get("oom_kill", 0)
        or swap_before != 0
        or swap_after != 0
        or memory_current > int(manager.limits["memory.max"])
    ):
        _stop("MEMORY_SWAP_LIMIT_ORACLE_FAILED")
    results["memory"] = {
        "before": memory_before,
        "after": memory_after,
        "swap_before": swap_before,
        "swap_after": swap_after,
        "memory_current": memory_current,
        "return_code": memory_return,
        "facts": memory_facts,
        "status": memory_status_digest,
    }
    _record_pass(
        tests, events, "T-M3-CGROUP-MEMORY-SWAP-LIMIT", "TCB_RESOURCE", "memory.max",
        results["memory"],
        {"memory.max": manager.limits["memory.max"], "memory.swap.max": "0", "oom_kill": True},
        "A fixed 256 MiB allocation crossed the 128 MiB cgroup limit, produced oom_kill, and consumed no swap.",
    )

    pids_cgroup = manager.create("probe-pids")
    pids_before = _cgroup_values(pids_cgroup, "pids.events")
    pids_processes: list[tuple[subprocess.Popen[bytes], int]] = []
    pids_facts: list[dict[str, object]] = []
    launch_rejection = ""
    peak = 0
    for index in range(8):
        current = int(pids_cgroup.joinpath("pids.current").read_text(encoding="ascii").strip())
        peak = max(peak, current)
        try:
            process, status_fd, facts = _launch_resource_probe(
                "pids-hold", probe_root, pids_cgroup, probe_program,
                seccomp_program=seccomp_program,
                apparmor_digest=apparmor_digest,
                profile=raw_profile,
                expected_limits=manager.limits,
                instance=index,
            )
        except QualificationStop as error:
            launch_rejection = str(error)
            break
        pids_processes.append((process, status_fd))
        pids_facts.append(facts)
    peak = max(
        peak,
        int(pids_cgroup.joinpath("pids.current").read_text(encoding="ascii").strip()),
    )
    pids_after = _cgroup_values(pids_cgroup, "pids.events")
    manager.kill(pids_cgroup)
    pids_returns = [
        _complete_role(process, status_fd, pids_cgroup, timeout=0.1)[0]
        for process, status_fd in pids_processes
    ]
    pids_readback = pids_cgroup.joinpath("pids.max").read_text(encoding="ascii").strip()
    if (
        not launch_rejection
        or pids_readback != manager.limits["pids.max"]
        or pids_after.get("max", 0) <= pids_before.get("max", 0)
        or peak > int(manager.limits["pids.max"])
        or len(pids_processes) < 2
        or any(code >= 0 for code in pids_returns)
    ):
        _stop(
            "PIDS_LIMIT_ORACLE_FAILED:"
            + _canonical(
                {
                    "before": pids_before,
                    "after": pids_after,
                    "peak": peak,
                    "readback": pids_readback,
                    "launched": len(pids_processes),
                    "rejection": launch_rejection,
                    "returns": pids_returns,
                }
            ).decode("ascii")[:1024]
        )
    results["pids"] = {
        "before": pids_before,
        "after": pids_after,
        "peak": peak,
        "launch_rejection": launch_rejection,
        "launched": len(pids_processes),
        "return_codes": pids_returns,
        "facts": pids_facts,
    }
    _record_pass(
        tests, events, "T-M3-CGROUP-PID-LIMIT", "TCB_RESOURCE", "pids.max",
        results["pids"], {"pids.max": manager.limits["pids.max"], "pids.events.max": "increased"},
        "A bounded set of sleeping sandboxes reached pids.max; the next creation was rejected and the cgroup emptied.",
    )
    return results


def _read_stage_file(staging_descriptor: int, maximum: int) -> dict[str, object]:
    if type(staging_descriptor) is not int or staging_descriptor < 0 or type(maximum) is not int or maximum < 1:
        _stop("STAGING_READ_BINDING_MISMATCH")
    descriptor = os.open(
        "artifact.txt",
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        dir_fd=staging_descriptor,
    )
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > maximum:
            _stop("STAGING_OBJECT_MISMATCH")
        value = b""
        while True:
            chunk = os.read(descriptor, min(65536, maximum + 1 - len(value)))
            if not chunk:
                break
            value += chunk
            if len(value) > maximum:
                _stop("STAGING_OBJECT_UNBOUNDED")
        if len(value) != info.st_size:
            _stop("STAGING_OBJECT_SHORT_READ")
        return {
            "bytes": len(value),
            "digest": _digest_bytes(value),
            "device": info.st_dev,
            "inode": info.st_ino,
            "links": info.st_nlink,
        }
    finally:
        os.close(descriptor)


def _staging_root_observation(
    descriptor: int,
    maximum: int,
    *,
    process_id: int | None = None,
) -> dict[str, object]:
    _, _, l0 = _load_project()
    duplicate = fcntl.fcntl(descriptor, fcntl.F_DUPFD_CLOEXEC, 3)
    try:
        info = os.fstat(duplicate)
        if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700:
            _stop("EXECUTOR_STAGING_ROOT_MISMATCH")
        mount_id = l0._mount_id(duplicate)
        root = {
            "device": info.st_dev,
            "inode": info.st_ino,
            "mode": stat.S_IMODE(info.st_mode),
            "uid": info.st_uid,
            "gid": info.st_gid,
            "mount_id": f"mnt:{mount_id}",
        }
        result: dict[str, object] = {
            "root": root,
            "target": _read_stage_file(duplicate, maximum),
        }
        if process_id is not None:
            rows = Path(f"/proc/{process_id}/mountinfo").read_text(encoding="ascii").splitlines()
            matches = []
            for row in rows:
                fields = row.split()
                if len(fields) < 10 or "-" not in fields or fields[4] != "/staging":
                    continue
                separator = fields.index("-")
                if separator + 2 >= len(fields):
                    _stop("EXECUTOR_STAGING_MOUNT_MALFORMED")
                matches.append(
                    {
                        "mount_point": fields[4],
                        "filesystem": fields[separator + 1],
                        "source": fields[separator + 2],
                        "digest": _digest_bytes(row.encode("utf-8")),
                    }
                )
            if len(matches) != 1 or matches[0]["filesystem"] != "tmpfs":
                _stop("EXECUTOR_STAGING_MOUNT_MISMATCH")
            result["mount"] = matches[0]
        return result
    finally:
        os.close(duplicate)


def _require_same_staging_view(expected: object, observed: object) -> None:
    if type(expected) is not dict or type(observed) is not dict:
        _stop("EXECUTOR_STAGING_ROOT_MISMATCH")
    required = frozenset({"root", "target"})
    if not required.issubset(expected) or not required.issubset(observed):
        _stop("EXECUTOR_STAGING_ROOT_MISMATCH")
    expected_root = expected["root"]
    observed_root = observed["root"]
    if type(expected_root) is not dict or type(observed_root) is not dict:
        _stop("EXECUTOR_STAGING_ROOT_MISMATCH")
    root_fields = ("device", "inode", "mode", "uid", "gid")
    if any(expected_root.get(field) != observed_root.get(field) for field in root_fields):
        _stop("EXECUTOR_STAGING_ROOT_MISMATCH")
    expected_target = expected["target"]
    observed_target = observed["target"]
    if type(expected_target) is not dict or type(observed_target) is not dict:
        _stop("EXECUTOR_STAGING_TARGET_MISMATCH")
    target_fields = ("device", "inode", "links", "bytes", "digest")
    if any(expected_target.get(field) != observed_target.get(field) for field in target_fields):
        _stop("EXECUTOR_STAGING_TARGET_MISMATCH")


def _executor_staging_oracle(
    process_id: int,
    staging: dict[str, object],
) -> dict[str, object]:
    host = _staging_root_observation(staging["descriptor"], staging["bytes"])
    expected_root = host["root"]
    if (
        expected_root["device"] != staging["device"]
        or expected_root["inode"] != staging["inode"]
        or expected_root["mount_id"] != staging["mount_id"]
    ):
        _stop("STORED_STAGING_ROOT_MISMATCH")
    expected_root_identity = _digest_bytes(
        _canonical(
            {
                "device": expected_root["device"],
                "inode": expected_root["inode"],
                "mode": stat.S_IFDIR,
                "mount_id": int(str(expected_root["mount_id"]).removeprefix("mnt:")),
                "uid": expected_root["uid"],
                "gid": expected_root["gid"],
            }
        )
    )
    expected_mount_identity = _digest_bytes(
        _canonical(
            {
                "mount_id": int(str(expected_root["mount_id"]).removeprefix("mnt:")),
                "device": expected_root["device"],
            }
        )
    )
    if (
        expected_root_identity != staging["root_identity"]
        or expected_mount_identity != staging["mount_identity"]
        or host["target"]["digest"] != staging["initial_digest"]
    ):
        _stop("STORED_STAGING_BINDING_MISMATCH")

    child_descriptor = os.open(
        f"/proc/{process_id}/root/staging",
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        child = _staging_root_observation(
            child_descriptor,
            staging["bytes"],
            process_id=process_id,
        )
    finally:
        os.close(child_descriptor)
    _require_same_staging_view(host, child)

    substitute = RUNTIME / "descriptor-substitute"
    if substitute.exists():
        _stop("DESCRIPTOR_SUBSTITUTE_REUSE_FORBIDDEN")
    substitute.mkdir(mode=0o700)
    os.chown(substitute, expected_root["uid"], expected_root["gid"])
    substitute_descriptor = os.open(
        substitute,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        target = os.open(
            "artifact.txt",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=substitute_descriptor,
        )
        try:
            _write_all(target, b"old\n")
            os.fchown(target, expected_root["uid"], expected_root["gid"])
            os.fsync(target)
        finally:
            os.close(target)
        substitute_observation = _staging_root_observation(
            substitute_descriptor,
            staging["bytes"],
        )
        try:
            _require_same_staging_view(host, substitute_observation)
        except QualificationStop as error:
            if str(error) != "EXECUTOR_STAGING_ROOT_MISMATCH":
                raise
            substitution_reason = str(error)
        else:
            _stop("DESCRIPTOR_ROOT_SUBSTITUTION_ACCEPTED")
    finally:
        os.close(substitute_descriptor)
        os.unlink(substitute / "artifact.txt")
        os.rmdir(substitute)
    after = _staging_root_observation(staging["descriptor"], staging["bytes"])
    _require_same_staging_view(host, after)
    return {
        "host": host,
        "executor": child,
        "substitute": substitute_observation,
        "substitution_reason": substitution_reason,
        "unchanged_after_negative": after == host,
    }


def _prepare_external_canaries() -> dict[str, Path]:
    secret = CONTROLLER / "synthetic-secret-canary.bin"
    durable_canary = CONTROLLER / "durable-canary.sqlite3"
    _write_exact(secret, b"synthetic-m3-secret-canary-v1\n", 0o600)
    if durable_canary.exists():
        _stop("DURABLE_CANARY_REUSE_FORBIDDEN")
    connection = sqlite3.connect(durable_canary)
    try:
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("CREATE TABLE canary (id INTEGER PRIMARY KEY CHECK(id=1), value TEXT NOT NULL)")
        connection.execute("INSERT INTO canary(id,value) VALUES(1,'synthetic-m3-durable-canary-v1')")
        connection.commit()
    finally:
        connection.close()
    os.chmod(durable_canary, 0o600, follow_symlinks=False)
    descriptor = os.open(durable_canary, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return {
        "checkout": SOURCE,
        "home": Path("/home/lab-admin/.profile"),
        "secret": secret,
        "durable_db": durable_canary,
        "outside": Path("/etc/machine-id"),
    }


def _external_canary_snapshot(paths: object) -> dict[str, str]:
    if type(paths) is not dict or frozenset(paths) != {
        "checkout", "home", "secret", "durable_db", "outside",
    }:
        _stop("CANARY_SET_MISMATCH")
    result: dict[str, str] = {}
    for name, path in paths.items():
        if not isinstance(path, Path) or not path.is_absolute():
            _stop("CANARY_PATH_MISMATCH")
        result[name] = _tree_digest(path) if name == "checkout" else _digest_file(path, 16 << 20)
    return result


def _claim_recheck_raw(claim: object, observed_at: str) -> dict[str, object]:
    return {
        "transaction_id": claim.transaction_id,
        "claim_digest": claim.claim_digest,
        "audience_id": claim.audience_id,
        "placement_digest": claim.placement_digest,
        "session_id": claim.session_id,
        "revocation_epoch": claim.revocation_epoch,
        "fencing_epoch": claim.fencing_epoch,
        "observed_at": observed_at,
    }


def _backup_store(source: Path, target: Path) -> None:
    if target.exists() or source == target:
        _stop("NEGATIVE_STORE_REUSE_FORBIDDEN")
    source_connection = sqlite3.connect(source)
    target_connection = sqlite3.connect(target)
    try:
        source_connection.backup(target_connection)
    finally:
        target_connection.close()
        source_connection.close()


def _pre_stage_negative_oracles(
    chain: dict[str, object],
    manager: CgroupManager,
) -> dict[str, object]:
    _, durable, l0 = _load_project()
    claim = chain.get("claim")
    supply = chain.get("supply")
    staging = chain.get("staging")
    if (
        type(claim) is not durable.DispatchClaim
        or type(supply) is not l0.SupplyVerification
        or type(staging) is not dict
    ):
        _stop("NEGATIVE_ORACLE_BINDING_MISMATCH")
    before = _read_stage_file(staging["descriptor"], staging["bytes"])
    verifier = Ed25519PayloadVerifier()
    results: dict[str, object] = {}

    self_audience = l0.stage_committed_intent(
        chain["profile"],
        replace(claim, audience_id=claim.principal_id),
        supply,
        staging["descriptor"],
        {},
        executor_claim_verifier=verifier,
        supply_verifier=verifier,
    )
    if self_audience.outcome is not l0.L0Outcome.STOP or self_audience.reason is not l0.L0Reason.CLAIM_MISMATCH:
        _stop("SELF_AUDIENCE_NOT_DENIED")
    results["self_audience"] = {"outcome": self_audience.outcome.value, "reason": self_audience.reason.value}

    confused_claim = l0.stage_committed_intent(
        chain["profile"],
        replace(claim, material_digest=_digest_bytes(b"confused-material")),
        supply,
        staging["descriptor"],
        {},
        executor_claim_verifier=verifier,
        supply_verifier=verifier,
    )
    material = "substituted-stage\n"
    confused_argument = l0.stage_committed_intent(
        chain["profile"],
        claim,
        supply,
        staging["descriptor"],
        {
            "transaction_id": claim.transaction_id,
            "claim_digest": claim.claim_digest,
            "operation": "WRITE_FILE_REPLACE",
            "content": material,
            "content_digest": _digest_bytes(material.encode("utf-8")),
            "target_binding": {},
        },
        executor_claim_verifier=verifier,
        supply_verifier=verifier,
    )
    if (
        confused_claim.outcome is not l0.L0Outcome.STOP
        or confused_claim.reason is not l0.L0Reason.CLAIM_MISMATCH
        or confused_argument.outcome is not l0.L0Outcome.STOP
        or confused_argument.reason is not l0.L0Reason.MATERIAL_MISMATCH
    ):
        _stop("CONFUSED_DEPUTY_NOT_DENIED")
    results["confused_deputy"] = {
        "claim": confused_claim.reason.value,
        "argument": confused_argument.reason.value,
    }

    substituted_verification = _strict_bytes(supply.verification_json.encode("utf-8"))
    if type(substituted_verification) is not dict:
        _stop("SUPPLY_VERIFICATION_RECORD_MALFORMED")
    substituted_verification["proof"] = "ed25519:" + ("0" * 128)
    supply_substitution = l0.stage_committed_intent(
        chain["profile"],
        claim,
        replace(supply, verification_json=_canonical(substituted_verification).decode("utf-8")),
        staging["descriptor"],
        {},
        executor_claim_verifier=verifier,
        supply_verifier=verifier,
    )
    if supply_substitution.outcome is not l0.L0Outcome.STOP or supply_substitution.reason is not l0.L0Reason.SUPPLY_MISMATCH:
        _stop("SUPPLY_SUBSTITUTION_NOT_DENIED")
    results["supply_substitution"] = {
        "outcome": supply_substitution.outcome.value,
        "reason": supply_substitution.reason.value,
    }

    recheck = _claim_recheck_raw(claim, chain["times"]["prepare_at"])
    fence_database = CONTROLLER / "negative-stale-fence.sqlite3"
    revocation_database = CONTROLLER / "negative-stale-revocation.sqlite3"
    for path in (fence_database, revocation_database):
        _backup_store(chain["database"], path)
    try:
        fence_store = durable.DurableStore(
            str(fence_database), verifier,
            executor_claim_verifier=verifier,
            runtime_session_verifier=verifier,
        )
        advanced = fence_store.advance_fence(
            {
                "expected_fencing_epoch": claim.fencing_epoch,
                "new_fencing_epoch": claim.fencing_epoch + 1,
                "reason_digest": _digest_bytes(b"negative-fence"),
            }
        )
        stale_fence = fence_store.verify_dispatch_claim(recheck)
        if (
            advanced.outcome is not durable.DurableOutcome.COMMITTED
            or stale_fence.outcome is not durable.DurableOutcome.DENY
            or stale_fence.reason is not durable.DurableReason.STALE_FENCE
        ):
            _stop("STALE_FENCE_NOT_DENIED")

        revocation_store = durable.DurableStore(
            str(revocation_database), verifier,
            executor_claim_verifier=verifier,
            runtime_session_verifier=verifier,
        )
        sibling_raw = dict(chain["issue"])
        sibling_raw["nonce"] = "nonce-m3-revocation-probe"
        sibling_raw["idempotency_key_digest"] = _digest_bytes(b"revocation-probe")
        sibling_raw["verification"] = _verification_source()
        capture = CaptureVerifier()
        capture_store = durable.DurableStore(
            str(revocation_database), capture,
            executor_claim_verifier=verifier,
            runtime_session_verifier=verifier,
        )
        rejected = capture_store.issue(sibling_raw)
        if rejected.outcome is not durable.DurableOutcome.DENY or capture.payload is None:
            _stop("REVOCATION_PROBE_CAPTURE_FAILED")
        proof, _ = _sign_capture(capture, manager, "revocation-probe")
        sibling_raw["verification"] = _verification_source(proof)
        sibling = revocation_store.issue(sibling_raw)
        if sibling.outcome is not durable.DurableOutcome.COMMITTED or sibling.capability_id is None:
            _stop("REVOCATION_PROBE_ISSUE_FAILED")
        revoked = revocation_store.revoke(
            {
                "capability_id": sibling.capability_id,
                "expected_revocation_epoch": claim.revocation_epoch,
                "new_revocation_epoch": claim.revocation_epoch + 1,
                "fencing_epoch": claim.fencing_epoch,
                "reason_digest": _digest_bytes(b"negative-revocation"),
            }
        )
        stale_revocation = revocation_store.verify_dispatch_claim(recheck)
        if (
            revoked.outcome is not durable.DurableOutcome.COMMITTED
            or stale_revocation.outcome is not durable.DurableOutcome.DENY
            or stale_revocation.reason is not durable.DurableReason.STALE_REVOCATION
        ):
            _stop("STALE_REVOCATION_NOT_DENIED")
        results["epochs"] = {
            "stale_fence": stale_fence.reason.value,
            "stale_revocation": stale_revocation.reason.value,
        }
    finally:
        for path in (fence_database, revocation_database):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
    after = _read_stage_file(staging["descriptor"], staging["bytes"])
    if after != before:
        _stop("NEGATIVE_ORACLE_CHANGED_STAGING")
    results["canary"] = {"before": before, "after": after}
    return results


def _execute_executor_stage(
    chain: dict[str, object],
    apparmor_digest: str,
    seccomp_program: bytes,
    manager: CgroupManager,
) -> dict[str, object]:
    _, durable, l0 = _load_project()
    plan = chain.get("session_plan")
    runtime_session = chain.get("runtime_session")
    staging = chain.get("staging")
    namespace_binding = chain.get("namespaces", {}).get("EXECUTOR")
    if (
        type(plan) is not l0.SessionPlan
        or type(runtime_session) is not durable.RuntimeSession
        or runtime_session.state != "PREPARED"
        or type(staging) is not dict
        or type(namespace_binding) is not tuple
    ):
        _stop("EXECUTOR_PREPARED_BINDING_MISMATCH")
    claim = chain.get("claim")
    if type(claim) is not durable.DispatchClaim:
        _stop("EXECUTOR_CLAIM_MISMATCH")
    claim_recheck_raw = _claim_recheck_raw(claim, chain["times"]["prepare_at"])
    claim_recheck = chain["store"].verify_dispatch_claim(claim_recheck_raw)
    if (
        claim_recheck.outcome is not durable.DurableOutcome.OK
        or claim_recheck.reason is not durable.DurableReason.DISPATCH_CLAIM_VERIFIED
        or claim_recheck.dispatch_claim != claim
    ):
        _stop("EXECUTOR_CLAIM_RECHECK_FAILED:" + claim_recheck.reason.value)
    namespace_fd, namespace_record = namespace_binding
    _verify_user_namespace_fd(namespace_fd, namespace_record, require_nested=True)
    libcrypto_digest = _digest_file(Path(LIBCRYPTO).resolve(strict=True), 16 << 20)
    executor_input = _executor_input(chain)
    executor_program = _executor_program(libcrypto_digest)
    executor_root, executor_root_record = _materialize_rootfs(
        "EXECUTOR",
        executor_program,
        "session-3",
        executor_input=executor_input,
    )
    executor_cgroup = manager.create("executor-session-3")
    start_read, start_write = os.pipe2(os.O_CLOEXEC)
    result_read, result_write = os.pipe2(os.O_CLOEXEC)
    outer_read, outer_write = os.pipe2(os.O_CLOEXEC)
    status_read, status_write = os.pipe2(os.O_CLOEXEC)
    seccomp_fd = _seccomp_memfd(seccomp_program)
    root_fd = os.open(executor_root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    stage_fd = fcntl.fcntl(staging["descriptor"], fcntl.F_DUPFD_CLOEXEC, 20)
    outer_high = _duplicate_high(outer_read)
    descriptors = (namespace_fd, seccomp_fd, root_fd, stage_fd, outer_high, status_write)
    argv = list(
        _validate_runtime_argv(
            [
                BWRAP,
                "--userns", str(namespace_fd),
                "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-net", "--unshare-cgroup",
                "--assert-userns-disabled", "--hostname", "harness-executor",
                "--new-session", "--die-with-parent", "--clearenv", "--cap-drop", "ALL",
                "--block-fd", str(outer_high), "--json-status-fd", str(status_write),
                "--ro-bind-fd", str(root_fd), "/",
                "--bind-fd", str(stage_fd), "/staging",
                "--proc", "/proc", "--seccomp", str(seccomp_fd), "--chdir", "/workspace", "--",
                AA_EXEC, "--profile", PROFILE_LABELS["EXECUTOR"], "--", PYTHON,
                "-I", "-S", "/usr/lib/harness/worker-tool",
                "--stage", "--session", "session-3",
            ],
            namespace_fd,
            prepared=True,
        )
    )
    process: subprocess.Popen[bytes] | None = None
    try:
        process = subprocess.Popen(
            argv,
            shell=False,
            close_fds=True,
            pass_fds=descriptors,
            stdin=start_read,
            stdout=result_write,
            stderr=subprocess.DEVNULL,
            env={},
            cwd="/",
            preexec_fn=_preexec(
                "EXECUTOR", (), plan.rlimit_nofile, executor_cgroup,
                user_namespace_fd=namespace_fd,
            ),
        )
    finally:
        for descriptor in (
            start_read, result_write, outer_read, outer_high, status_write,
            seccomp_fd, root_fd, stage_fd,
        ):
            try:
                os.close(descriptor)
            except OSError:
                pass
    if process is None:
        _stop("EXECUTOR_LAUNCH_FAILED")
    limits = {
        name: executor_cgroup.joinpath(name).read_text(encoding="ascii").strip()
        for name in dict(plan.cgroup_limits)
    }
    if (
        str(process.pid) not in executor_cgroup.joinpath("cgroup.procs").read_text(encoding="ascii").split()
        or limits != dict(plan.cgroup_limits)
    ):
        _stop("EXECUTOR_CGROUP_ATTACH_FAILED")
    try:
        if os.write(outer_write, b"1") != 1:
            _stop("EXECUTOR_OUTER_GATE_RELEASE_FAILED")
    finally:
        os.close(outer_write)
    confined_pid, observed = _prepared_process_facts(
        executor_cgroup,
        "EXECUTOR",
        namespace_record,
    )
    before = _read_stage_file(staging["descriptor"], staging["bytes"])
    if before["digest"] != staging["initial_digest"]:
        _stop("EARLY_EXECUTOR_EFFECT")
    staging_oracle = _executor_staging_oracle(confined_pid, staging)
    executor_facts = {
        **observed,
        "launcher_uid": ROLE_IDS["EXECUTOR"][0],
        "launcher_gid": ROLE_IDS["EXECUTOR"][1],
        "namespace_uid": ROLE_IDS["EXECUTOR"][2],
        "namespace_gid": ROLE_IDS["EXECUTOR"][3],
        "process_id": confined_pid,
        "cgroup": {
            "path": str(executor_cgroup).removeprefix("/sys/fs/cgroup"),
            "limits": limits,
            "processes_before_release": executor_cgroup.joinpath("cgroup.procs").read_text(encoding="ascii").split(),
        },
        "argv": argv,
        "argv_digest": _digest_bytes(_canonical(argv)),
        "program_digest": _digest_bytes(executor_program),
        "input_digest": _digest_bytes(executor_input),
        "rootfs_digest": executor_root_record["tree_digest"],
        "user_namespace": namespace_record,
        "policy": {
            "apparmor_digest": apparmor_digest,
            "seccomp_digest": _digest_bytes(seccomp_program),
            "libcrypto_digest": libcrypto_digest,
            "verifier_backend": "OPENSSL_LIBCRYPTO_SHARED",
            "verifier_code_digest": _digest_file(VERIFIER_CODE),
            "verifier_public_key_digest": _digest_file(PUBLIC_KEY, 4096),
        },
        "claim_recheck": {
            "outcome": claim_recheck.outcome.value,
            "reason": claim_recheck.reason.value,
            "claim_digest": claim.claim_digest,
            "observed_at": claim_recheck_raw["observed_at"],
        },
        "staging": {
            key: staging[key]
            for key in ("root_id", "root_identity", "mount_id", "mount_identity", "device", "inode")
        },
        "before": before,
        "staging_oracle": staging_oracle,
    }
    executor_attestation = _attest_runtime_record(executor_facts, manager, "executor-placement")
    try:
        if os.write(start_write, START_PACKET) != len(START_PACKET):
            _stop("EXECUTOR_START_GATE_SHORT_WRITE")
    finally:
        os.close(start_write)
    raw_result = _read_pipe_line(result_read, maximum=4096, timeout=5)
    os.close(result_read)
    return_code, status_digest = _complete_role(
        process,
        status_read,
        executor_cgroup,
        timeout=5,
    )
    manager.kill(executor_cgroup)
    if return_code != 0:
        _stop(
            "EXECUTOR_STAGE_FAILED:"
            + str(return_code)
            + ":"
            + raw_result.decode("utf-8", "replace")[:512]
        )
    if raw_result.startswith(b"ERROR:"):
        _stop("EXECUTOR_PROGRAM_ERROR:" + raw_result[6:].decode("utf-8", "replace")[:512])
    result = _strict_bytes(raw_result)
    if (
        type(result) is not dict
        or frozenset(result) != {"input_digest", "outcome", "reason", "record"}
        or result["input_digest"] != _digest_bytes(executor_input)
        or result["outcome"] != "STAGED"
        or result["reason"] != "STAGED"
        or type(result["record"]) is not dict
    ):
        _stop(
            "EXECUTOR_RESULT_MISMATCH:"
            + raw_result.decode("utf-8", "replace")[:768]
        )
    after = _read_stage_file(staging["descriptor"], staging["bytes"])
    if (
        after["digest"] != chain["claim"].material_digest
        or after["bytes"] != len(chain["content"].encode("utf-8"))
        or result["record"].get("before_digest") != before["digest"]
        or result["record"].get("after_digest") != after["digest"]
        or result["record"].get("claim_digest") != chain["claim"].claim_digest
    ):
        _stop("STAGING_POSTCONDITION_MISMATCH")
    terminal_evidence = {
        "executor_attestation_digest": executor_attestation["payload_digest"],
        "result_digest": _digest_bytes(raw_result),
        "before": before,
        "after": after,
        "cgroup_empty": True,
    }
    chain["times"]["terminal_at"] = _transition_time(chain["times"]["prepare_at"])
    terminal = chain["store"].finalize_runtime_session(
        {
            "session_record_id": plan.session_record_id,
            "observed_at": chain["times"]["terminal_at"],
            "state": "QUARANTINED",
            "evidence": {"evidence_digest": _digest_bytes(_canonical(terminal_evidence))},
        }
    )
    if (
        terminal.outcome is not durable.DurableOutcome.COMMITTED
        or terminal.reason is not durable.DurableReason.QUARANTINED_ESCROW
    ):
        _stop("RUNTIME_TERMINAL_QUARANTINE_FAILED")
    duplicate_terminal = chain["store"].finalize_runtime_session(
        {
            "session_record_id": plan.session_record_id,
            "observed_at": chain["times"]["terminal_at"],
            "state": "QUARANTINED",
            "evidence": {"evidence_digest": _digest_bytes(_canonical(terminal_evidence))},
        }
    )
    if (
        duplicate_terminal.outcome is not durable.DurableOutcome.DENY
        or duplicate_terminal.reason is not durable.DurableReason.ILLEGAL_TRANSITION
    ):
        _stop("DUPLICATE_TERMINAL_NOT_DENIED")
    replay = chain["store"].claim_dispatch(chain["claim_raw"])
    if replay.outcome is not durable.DurableOutcome.DENY or replay.reason is not durable.DurableReason.REPLAY:
        _stop("POST_STAGE_RETRY_NOT_DENIED")
    recovered = chain["store"].recover()
    if (
        recovered.outcome is not durable.DurableOutcome.OK
        or len(recovered.recovery_intents) != 1
        or recovered.recovery_intents[0].state != "QUARANTINED_ESCROW"
        or len(recovered.recovery_sessions) != 1
        or recovered.recovery_sessions[0].state != "QUARANTINED"
    ):
        _stop("POST_STAGE_RECOVERY_MISMATCH")
    return {
        "executor_facts": executor_facts,
        "executor_attestation": executor_attestation,
        "executor_root_record": executor_root_record,
        "stage_result": result,
        "stage_result_digest": _digest_bytes(raw_result),
        "stage_before": before,
        "stage_after": after,
        "terminal": {
            "outcome": terminal.outcome.value,
            "reason": terminal.reason.value,
            "transaction_id": terminal.transaction_id,
            "journal_sequence": terminal.journal_sequence,
        },
        "recovery": {
            "intents": [asdict(item) for item in recovered.recovery_intents],
            "sessions": [asdict(item) for item in recovered.recovery_sessions],
            "retry_created": False,
        },
        "terminal_evidence": terminal_evidence,
        "executor_cgroup": executor_cgroup,
    }


def _execute_prepared_proposal(
    raw_profile: dict[str, object],
    profile: object,
    measurement: object,
    seccomp_program: bytes,
    role_seccomp: dict[str, bytes],
    tools: dict[str, dict[str, str]],
    policy: dict[str, object],
    manager: CgroupManager,
    controller: ControllerSession,
) -> dict[str, object]:
    chain = _authority_chain(
        raw_profile,
        profile,
        measurement,
        seccomp_program,
        role_seccomp["BROKER"],
        tools,
        manager,
        controller,
    )
    broker_process, broker_status, broker_report, broker_facts = _launch_prepared_broker(
        chain, str(policy["digest"]), role_seccomp["BROKER"]
    )
    worker_process, worker_status, worker_facts = _launch_prepared_worker(
        chain, str(policy["digest"]), seccomp_program, release=False
    )
    plan = chain["session_plan"]
    runtime = json.loads(plan.runtime_bindings_json)
    pair = runtime["broker_ipc"]
    expected_message_credentials = {
        "pid": 0,
        "uid": int(Path("/proc/sys/kernel/overflowuid").read_text(encoding="ascii").strip()),
        "gid": int(Path("/proc/sys/kernel/overflowgid").read_text(encoding="ascii").strip()),
    }
    holder_record = {
        "attestation_version": "1.0.0",
        "observed_at": chain["times"]["prepare_at"],
        "profile_digest": profile.profile_digest,
        "runtime_session_id": plan.session_record_id,
        "operation_id": pair["operation_id"],
        "nonce": pair["nonce"],
        "fencing_epoch": pair["fencing_epoch"],
        "revocation_epoch": pair["revocation_epoch"],
        "pair_binding_digest": pair["pair_binding_digest"],
        "message_binding_digest": pair["message_binding_digest"],
        "worker_holder": {
            "principal": pair["worker_principal"],
            "session": pair["worker_session"],
            "security_label": worker_facts["label"],
            "host_uid": worker_facts["host_uid"],
            "host_gid": worker_facts["host_gid"],
            "process_id": worker_facts["process_id"],
            "cgroup": worker_facts["cgroup"]["path"],
            "namespace_ids": worker_facts["namespaces"],
            "fd_inventory": worker_facts["fd_inventory"],
            "socket_identity": pair["worker_socket_identity"],
            "socket_target": worker_facts["operation_fd_target"],
        },
        "broker_holder": {
            "principal": pair["broker_principal"],
            "session": pair["broker_session"],
            "security_label": broker_facts["label"],
            "host_uid": broker_facts["host_uid"],
            "host_gid": broker_facts["host_gid"],
            "process_id": broker_facts["process_id"],
            "cgroup": broker_facts["cgroup"]["path"],
            "namespace_ids": broker_facts["namespaces"],
            "fd_inventory": broker_facts["fd_inventory"],
            "socket_identity": pair["broker_socket_identity"],
            "socket_target": broker_facts["operation_fd_target"],
        },
        "message_credentials_in_broker_namespace": expected_message_credentials,
        "gates": {"broker": "CLOSED", "worker": "CLOSED"},
    }
    holder_attestation = _attest_runtime_record(holder_record, manager, "pair-holders")
    chain["pair_holder_attestation"] = holder_attestation
    chain["broker_facts"] = _release_prepared_broker(chain)
    chain["worker_facts"] = _release_prepared_worker(chain, worker_facts)
    try:
        report_raw = _read_pipe_line(broker_report)
    except QualificationStop as error:
        worker_return, worker_status_digest = _complete_role(
            worker_process, worker_status, chain["worker_cgroup"], timeout=3
        )
        broker_return, broker_status_digest = _complete_role(
            broker_process, broker_status, chain["broker_cgroup"], timeout=3
        )
        _stop(
            "BROKER_REPORT_FAILED:"
            + str(error)
            + ":WORKER="
            + str(worker_return)
            + ":BROKER="
            + str(broker_return)
            + ":STATUS="
            + worker_status_digest
            + ":"
            + broker_status_digest
        )
    if report_raw.startswith(b"ERROR:"):
        _stop("BROKER_PROGRAM_ERROR:" + report_raw[6:].decode("utf-8", "replace")[:512])
    report = _strict_bytes(report_raw)
    if (
        type(report) is not dict
        or frozenset(report) != {"creator_credentials", "message_credentials", "packet_digest"}
        or report["message_credentials"]
        != [
            expected_message_credentials["pid"],
            expected_message_credentials["uid"],
            expected_message_credentials["gid"],
        ]
        or report["packet_digest"] != _digest_bytes(_worker_packet(profile, chain["request"]))
    ):
        _stop("BROKER_PACKET_MISMATCH")
    worker_return, worker_status_digest = _complete_role(
        worker_process, worker_status, chain["worker_cgroup"], timeout=3
    )
    broker_return, broker_status_digest = _complete_role(
        broker_process, broker_status, chain["broker_cgroup"], timeout=3
    )
    if worker_return != 0 or broker_return != 0:
        diagnostic = b"" if broker_process.stderr is None else broker_process.stderr.read(4096)
        _stop(
            "PREPARED_PAIR_EXECUTION_FAILED:"
            + str(worker_return)
            + ":"
            + str(broker_return)
            + ":"
            + diagnostic.decode("utf-8", "replace")[:512]
        )
    manager.kill(chain["worker_cgroup"])
    manager.kill(chain["broker_cgroup"])
    chain.update(
        {
            "broker_report": report,
            "broker_report_digest": _digest_bytes(report_raw),
            "worker_return": worker_return,
            "broker_return": broker_return,
            "worker_status_digest": worker_status_digest,
            "broker_status_digest": broker_status_digest,
        }
    )
    return chain


def _guest_measurement(
    measurement: object,
    marker: dict[str, object],
    rootfs_digest: str,
) -> dict[str, object]:
    release = os.uname().release
    kernel = Path("/boot") / ("vmlinuz-" + release)
    apparmor = Path("/sys/module/apparmor/parameters/enabled").read_text(encoding="ascii").strip()
    user_namespaces = int(
        Path("/proc/sys/user/max_user_namespaces").read_text(encoding="ascii").strip()
    )
    if (
        marker.get("offline_egress") is not True
        or not _is_digest(rootfs_digest)
        or getattr(measurement, "openat2", False) is not True
        or getattr(measurement, "user_namespaces", False) is not True
        or not Path("/sys/fs/cgroup/cgroup.controllers").is_file()
        or apparmor != "Y"
        or user_namespaces < 1
    ):
        _stop("GUEST_MEASUREMENT_MISMATCH")
    return {
        "os_release_digest": _digest_file(Path("/usr/lib/os-release"), 1 << 20),
        "kernel_release": release,
        "kernel_digest": _digest_file(kernel, 64 << 20),
        "architecture": os.uname().machine,
        "cgroup_v2": True,
        "apparmor_enabled": True,
        "user_namespaces": True,
        "openat2": True,
        "offline_egress": True,
        "rootfs_digest": rootfs_digest,
    }


def _principal_row(role: str, facts: dict[str, object], session_id: str) -> dict[str, object]:
    trusted = role in {"ATTESTOR", "CONTROLLER"}
    label_key = "security_label" if trusted else "label"
    namespaces_key = "namespace_ids" if trusted else "namespaces"
    cgroup = facts["cgroup"]
    if type(cgroup) is dict:
        cgroup = cgroup.get("path")
    process_session = facts.get("process_session")
    if type(process_session) is not int:
        _stop("PRINCIPAL_SESSION_MISSING")
    credential = facts.get("credential_namespace")
    if type(credential) is not str:
        credential = f"cred-{role.lower()}-{facts['process_id']}-{process_session}"
    network = facts.get("network")
    if type(network) is not dict:
        network = {
            "ipv4": False,
            "ipv6": False,
            "loopback": False,
            "routes": False,
            "dns": False,
            "raw": False,
            "packet": False,
            "broad_unix": False,
            "connected_fds": role in {"AGENT_WORKER", "BROKER"},
        }
    return {
        "role": role,
        "launcher_uid": facts["launcher_uid"],
        "launcher_gid": facts["launcher_gid"],
        "host_uid": facts["host_uid"],
        "host_gid": facts["host_gid"],
        "namespace_uid": facts["namespace_uid"],
        "namespace_gid": facts["namespace_gid"],
        "session_id": session_id,
        "process_id": facts["process_id"],
        "cgroup": cgroup,
        "security_label": facts[label_key],
        "credential_namespace": credential,
        "namespace_ids": facts[namespaces_key],
        "fd_inventory": facts["fd_inventory"],
        "network": network,
    }


def _resource_evidence(state: dict[str, object]) -> dict[str, object]:
    resources = state["resource_results"]
    probes = state["probe_results"]
    cpu = resources["cpu"]
    time_budget = cpu["time_budget"]
    memory = resources["memory"]
    pids = resources["pids"]
    io_result = resources["io"]
    quota = resources["quota"]
    host_quota = quota["host"]
    limits = state["cgroup"]["limits"]
    return {
        "cpu": {
            "cpu_max": limits["cpu.max"],
            "rate_delta": cpu["delta"],
            "time_limit_usec": time_budget["limit_usec"],
            "time_trigger_usec": time_budget["trigger_usage_usec"],
            "time_overshoot_usec": time_budget["overshoot_usec"],
            "time_return_code": time_budget["return_code"],
            "cgroup_populated_after_kill": time_budget["cgroup_populated_after_kill"],
        },
        "memory": {
            "memory_max": limits["memory.max"],
            "swap_max": limits["memory.swap.max"],
            "max_events": memory["after"].get("max", 0) - memory["before"].get("max", 0),
            "oom_kill_events": memory["after"].get("oom_kill", 0) - memory["before"].get("oom_kill", 0),
            "swap_before": memory["swap_before"],
            "swap_after": memory["swap_after"],
            "return_code": memory["return_code"],
            "memory_current": memory["memory_current"],
        },
        "pids": {
            "pids_max": limits["pids.max"],
            "max_events": pids["after"].get("max", 0) - pids["before"].get("max", 0),
            "peak": pids["peak"],
            "launched": pids["launched"],
            "launch_rejection": pids["launch_rejection"],
            "return_codes": pids["return_codes"],
        },
        "io": {
            "io_max": limits["io.max"],
            "device": io_result["device"],
            "control_elapsed_ns": io_result["control"]["external_elapsed_ns"],
            "limited_elapsed_ns": io_result["limited"]["external_elapsed_ns"],
            "control_delta": io_result["control"]["delta"],
            "limited_delta": io_result["limited"]["delta"],
            "read_bytes": io_result["limited"]["result"]["read_bytes"],
            "write_bytes": io_result["limited"]["result"]["write_bytes"],
            "control_events": io_result["control"]["controls"]["cgroup.events"],
            "limited_events": io_result["limited"]["controls"]["cgroup.events"],
            "minimum_slowdown_factor": io_result["oracle"]["minimum_slowdown_factor"],
        },
        "quota": {
            "mount_options": quota["staging"]["mount_options"],
            "files": host_quota["files"],
            "inodes": host_quota["inodes"],
            "logical_bytes": host_quota["logical_bytes"],
            "allocated_bytes": host_quota["allocated_bytes"],
            "create_errno": host_quota["create_errno"],
            "append_errno": host_quota["append_errno"],
            "entries": host_quota["entries"],
            "owners_match": host_quota["owners_match"],
            "modes_match": host_quota["modes_match"],
            "links_match": host_quota["links_match"],
            "statvfs_files": host_quota["statvfs_files"],
            "statvfs_free": host_quota["statvfs_free"],
            "cgroup_populated_after_cleanup": quota["cgroup_populated_after_cleanup"],
        },
        "rlimit_nofile": {
            "limit": probes["fd-limit"]["facts"]["rlimit_nofile"],
            "return_code": probes["fd-limit"]["return_code"],
            "cgroup_events": probes["fd-limit"]["cgroup_events"],
        },
        "wall_time": {
            "limit_ms": state["resources"]["WALL_TIME"],
            "elapsed_ms": probes["timeout"]["elapsed_ms"],
            "return_code": probes["timeout"]["return_code"],
            "process_tree_size": len(probes["timeout"]["process_tree_before"]),
            "cgroup_events": probes["timeout"]["cgroup_events"],
        },
    }


def _build_evidence(
    state: dict[str, object],
    raw_profile: dict[str, object],
    tests: list[dict[str, object]],
    events: list[dict[str, object]],
    recovery: dict[str, object],
) -> dict[str, object]:
    trust = _strict_json(
        TRUST_CONFIG,
        frozenset(
            {
                "trust_version", "trust_root_id", "signer_id", "key_id", "algorithm",
                "public_key_pem_digest", "public_key_fingerprint", "openssl",
                "verifier_openssl", "rollback_floor", "revocation_state_digest", "scope",
            }
        ),
        65536,
    )
    supply = state["supply"]
    supply_payload = _strict_bytes(supply["payload_json"].encode("utf-8"))
    supply_record = _strict_bytes(supply["verification_json"].encode("utf-8"))
    material = state["supply_material"]
    registry = supply_payload["registry"]
    signer = supply_payload["signer"]
    tools = state["tools"]
    pair_attestation = state["pair_holder_attestation"]
    runtime_pair = state["broker_ipc"]
    active = [
        _principal_row(
            "ATTESTOR",
            pair_attestation["attestor"],
            f"attestor-session-{pair_attestation['attestor']['process_session']}",
        ),
        _principal_row("CONTROLLER", state["controller_facts"], state["controller_facts"]["session_id"]),
        _principal_row("AGENT_WORKER", state["worker_facts"], runtime_pair["worker_session"]),
        _principal_row("BROKER", state["broker_facts"], runtime_pair["broker_session"]),
        _principal_row("EXECUTOR", state["executor_facts"], "session-3"),
    ]
    resources = state["resources"]
    quota = state["resource_results"]["quota"]
    lifecycle_event = next(
        row["event_id"] for row in events if row["test_id"] == "T-M3-LIFECYCLE-PREPARED-TERMINAL"
    )
    restart_event = next(
        row["event_id"] for row in events if row["test_id"] == "T-M3-RESTART-CLEANUP-NO-RESUME"
    )
    return {
        "evidence_version": "1.0.0",
        "image": state["host_provenance"]["image"],
        "vm": state["host_provenance"]["vm"],
        "guest": state["guest_measurement"],
        "runtime": {
            "backend": tools[BWRAP],
            "aa_exec": tools[AA_EXEC],
            "openssl": tools[OPENSSL],
            "python": tools[PYTHON],
            "apparmor_parser": tools[APPARMOR_PARSER],
            "dependencies": material["dependencies"],
            "apparmor_policy_digest": state["policy"]["digest"],
            "seccomp_policy_digest": material["seccomp_policy_digest"],
            "seccomp_bpf_digest": state["seccomp_bpf_digest"],
            "sbom_digest": material["sbom_digest"],
            "registry_snapshot_digest": material["registry_snapshot_digest"],
            "profile_digest": state["profile_digest"],
            "code_digest": state["source"]["files_digest"],
            "package_index_digest": material["package_index_digest"],
            "verifier": {
                "backend": "OPENSSL_LIBCRYPTO_SHARED",
                "code_digest": signer["verifier_code_digest"],
                "public_key_digest": signer["verifier_public_key_digest"],
                "libcrypto_digest": signer["verifier_libcrypto_digest"],
                "controller_principal": "CONTROLLER",
                "executor_principal": "EXECUTOR",
                "independent_implementations": False,
            },
        },
        "supply": {
            "image_digest": IMAGE_DIGEST,
            "rootfs_digest": state["guest_measurement"]["rootfs_digest"],
            "runtime_digest": supply["runtime_digest"],
            "loader_digest": material["loader_digest"],
            "dependency_closure_digest": material["dependency_closure_digest"],
            "tool_digest": material["tool_digest"],
            "sbom_digest": material["sbom_digest"],
            "registry_snapshot_digest": material["registry_snapshot_digest"],
            "key_id": signer["key_id"],
            "issued_at": registry["issued_at"],
            "expires_at": registry["expires_at"],
            "revocation_epoch": signer["revocation_epoch"],
            "rollback_floor": signer["rollback_floor"],
            "revocation_state_digest": trust["revocation_state_digest"],
            "profile_digest": supply["profile_digest"],
            "placement_digest": supply["placement_digest"],
            "actual_opened_bytes_digest": material["actual_opened_bytes_digest"],
            "verification_payload_digest": _digest_bytes(supply["payload_json"].encode("utf-8")),
            "verification_payload": supply_payload,
            "verification_record": supply_record,
            "verifier_backend": "OPENSSL_LIBCRYPTO_SHARED",
            "verifier_code_digest": signer["verifier_code_digest"],
            "verifier_public_key_digest": signer["verifier_public_key_digest"],
            "verifier_libcrypto_digest": signer["verifier_libcrypto_digest"],
        },
        "principals": {
            "active": active,
            "disabled": [
                {
                    "role": role,
                    "enabled": False,
                    "process": False,
                    "route": False,
                    "fd": False,
                    "credential": False,
                }
                for role in ("MODEL_GATEWAY", "OBSERVER")
            ],
        },
        "measurements": {
            "resource_vector": raw_profile["resources"],
            "cgroup": {
                **state["cgroup"],
                "delegated": True,
                "isolated": True,
                "cgroup_kill": True,
            },
            "quota": {
                "bytes": resources["OUTPUT_BYTES"],
                "files": resources["FILES"],
                "inodes": resources["INODES"],
                "mount_options": quota["staging"]["mount_options"],
                "outside_writes": 0,
            },
            "mounts": {
                "rootfs_read_only": True,
                "inputs_read_only": True,
                "staging_worker_visible": False,
                "checkout_visible": False,
                "git_visible": False,
                "home_visible": False,
                "durable_db_visible": False,
                "private_proc": True,
                "private_non_propagating": True,
            },
            "opened_artifacts": material["evidence_opened"],
            "broker_ipc": {
                "profile": raw_profile["broker_ipc"],
                "runtime": runtime_pair,
                "holder_payload": pair_attestation["payload"],
                "holder_payload_digest": pair_attestation["payload_digest"],
                "holder_signature": pair_attestation["signature"],
                "holder_signature_digest": pair_attestation["signature_digest"],
                "broker_report": state["broker_report"],
                "broker_report_digest": state["broker_report_digest"],
            },
            "controller": state["controller_facts"],
            "resource_oracles": _resource_evidence(state),
        },
        "tests": tests,
        "events": events,
        "lifecycle": {
            "prepared_event_id": lifecycle_event,
            "terminal_event_id": lifecycle_event,
            "terminal_state": "QUARANTINED",
            "restart_event_id": restart_event,
            "cleanup_event_id": restart_event,
            "old_session_resumed": recovery["old_session_resumed"],
            "retry_created": recovery["retry_created"],
            "uncertainty_disposition": "QUARANTINED_ESCROW",
            "cgroup_populated_after_cleanup": 0,
            "orphan_processes_after_cleanup": 0,
        },
        "canaries": state["canaries"],
        "residual_risk": RESIDUAL_RISK,
    }


def _export_evidence(
    state: dict[str, object],
    raw_profile: dict[str, object],
    tests: list[dict[str, object]],
    events: list[dict[str, object]],
    recovery: dict[str, object],
    current_boot: str,
) -> tuple[str, dict[str, object]]:
    if state["source"] != _source_identity() or state["host_provenance"] != _host_provenance():
        _stop("RECOVERY_PROVENANCE_MISMATCH")
    guest = state["guest_measurement"]
    if (
        guest["kernel_release"] != os.uname().release
        or guest["kernel_digest"]
        != _digest_file(Path("/boot") / ("vmlinuz-" + os.uname().release), 64 << 20)
        or guest["os_release_digest"] != _digest_file(Path("/usr/lib/os-release"), 1 << 20)
    ):
        _stop("RECOVERY_GUEST_MISMATCH")
    if any(GUEST_EVIDENCE.iterdir()):
        _stop("EVIDENCE_OUTPUT_REUSE_FORBIDDEN")
    evidence = _build_evidence(state, raw_profile, tests, events, recovery)
    evidence_bytes = _canonical(evidence)
    if len(evidence_bytes) > MAX_JSON:
        _stop("EVIDENCE_UNBOUNDED")
    trust = _strict_json(
        TRUST_CONFIG,
        frozenset(
            {
                "trust_version", "trust_root_id", "signer_id", "key_id", "algorithm",
                "public_key_pem_digest", "public_key_fingerprint", "openssl",
                "verifier_openssl", "rollback_floor", "revocation_state_digest", "scope",
            }
        ),
        65536,
    )
    issued = datetime.now(UTC).replace(microsecond=0)
    manifest = {
        "bundle_version": "1.0.0",
        "claim": "M3_TEST_PROFILE_RUNTIME_CONFORMANCE",
        "outcome": "VERIFIED",
        "scope": trust["scope"],
        "source": state["source"],
        "profile": {
            "path": "profiles/l0-lx-a.json",
            "profile_artifact_digest": state["profile_artifact_digest"],
            "compiled_profile_digest": state["profile_digest"],
            "runtime_path": BWRAP,
            "runtime_version": state["tools"][BWRAP]["version"],
            "runtime_digest": state["tools"][BWRAP]["digest"],
        },
        "attestation": {
            "trust_root_id": trust["trust_root_id"],
            "signer_id": trust["signer_id"],
            "key_id": trust["key_id"],
            "algorithm": trust["algorithm"],
            "public_key_fingerprint": trust["public_key_fingerprint"],
            "openssl": trust["openssl"],
            "issued_at": _utc_text(issued),
            "expires_at": _utc_text(issued + timedelta(days=1)),
            "revocation_epoch": 0,
            "fencing_epoch": 1,
            "rollback_floor": trust["rollback_floor"],
            "revocation_state_digest": trust["revocation_state_digest"],
            "nonce": "evidence-" + current_boot.replace("-", ""),
        },
        "evidence": {
            "path": "evidence.json",
            "bytes": len(evidence_bytes),
            "digest": _digest_bytes(evidence_bytes),
        },
    }
    manifest_bytes = _canonical(manifest)
    RUNTIME.mkdir(mode=0o711)
    manager: CgroupManager | None = None
    signing_complete = False
    try:
        manager = CgroupManager(raw_profile)
        signing_cgroup = manager.create("attestor-evidence")
        proof, signer_facts = _attestor_sign(manifest_bytes, signing_cgroup)
        signing_complete = True
        manager.kill(signing_cgroup)
        signature = bytes.fromhex(proof.removeprefix("ed25519:"))
        _, durable, _ = _load_project()
        record = {
            "verification_version": 1,
            "verifier_id": "harness-m3-external-verifier/v1",
            "issuer_id": SIGNER_ID,
            "key_id": KEY_ID,
            "payload_digest": _digest_bytes(manifest_bytes),
            "bindings": manifest,
            "proof": proof,
        }
        verified = Ed25519PayloadVerifier().verify(
            manifest_bytes,
            _canonical(record),
            manifest["attestation"]["issued_at"],
        )
        if verified.status is not durable.VerificationStatus.VERIFIED or len(signature) != 64:
            _stop("FINAL_EVIDENCE_SIGNATURE_INVALID")
    finally:
        _cleanup_signing_runtime(manager, signing_complete)
    _write_exact(GUEST_EVIDENCE / "evidence.json", evidence_bytes, 0o444)
    _write_exact(GUEST_EVIDENCE / "manifest.json", manifest_bytes, 0o444)
    _write_exact(GUEST_EVIDENCE / "manifest.sig", signature, 0o444)
    directory = os.open(
        GUEST_EVIDENCE,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    if {path.name for path in GUEST_EVIDENCE.iterdir()} != {
        "evidence.json", "manifest.json", "manifest.sig"
    }:
        _stop("EVIDENCE_FILE_SET_MISMATCH")
    return _digest_bytes(manifest_bytes), signer_facts


def _run_phase() -> None:
    guest_marker = _require_guest()
    source = _source_identity()
    host_provenance = _host_provenance()
    raw_profile, compiled_profile, seccomp_program = _profile()
    tools = _verify_tools()
    policy = _load_apparmor()
    role_seccomp, role_seccomp_records = _role_seccomp_programs()
    _, _, l0 = _load_project()
    preflight = l0.host_preflight(raw_profile)
    if (
        preflight.outcome is not l0.L0Outcome.READY
        or preflight.reason is not l0.L0Reason.HOST_VERIFIED
        or preflight.measurement is None
    ):
        _stop("HOST_PREFLIGHT_FAILED:" + preflight.reason.value)
    measurement = preflight.measurement
    if RUNTIME.exists() and any(RUNTIME.iterdir()):
        _stop("UNCLEAN_PRIOR_RUNTIME")
    RUNTIME.mkdir(mode=0o711, exist_ok=True)
    if stat.S_IMODE(os.stat(RUNTIME, follow_symlinks=False).st_mode) != 0o711:
        _stop("RUNTIME_ROOT_MODE_MISMATCH")
    CONTROLLER.mkdir(mode=0o700, exist_ok=True)
    if (CONTROLLER / "durable.sqlite3").exists() or RUN_STATE.exists():
        _stop("CONTROLLER_STATE_REUSE_FORBIDDEN")
    os.chown(CONTROLLER, ROLE_IDS["CONTROLLER"][0], ROLE_IDS["CONTROLLER"][1])
    os.chmod(CONTROLLER, 0o700)
    controller_info = os.stat(CONTROLLER, follow_symlinks=False)
    if (
        not stat.S_ISDIR(controller_info.st_mode)
        or (controller_info.st_uid, controller_info.st_gid)
        != ROLE_IDS["CONTROLLER"][:2]
        or stat.S_IMODE(controller_info.st_mode) != 0o700
    ):
        _stop("CONTROLLER_STORAGE_MISMATCH")
    GUEST_EVIDENCE.mkdir(mode=0o700, exist_ok=True)
    evidence_info = os.lstat(GUEST_EVIDENCE)
    if (
        not stat.S_ISDIR(evidence_info.st_mode)
        or (evidence_info.st_uid, evidence_info.st_gid) != (0, 0)
        or stat.S_IMODE(evidence_info.st_mode) != 0o700
        or any(GUEST_EVIDENCE.iterdir())
    ):
        _stop("EVIDENCE_OUTPUT_REUSE_FORBIDDEN")
    canary_paths = _prepare_external_canaries()
    canary_before = _external_canary_snapshot(canary_paths)
    tests: list[dict[str, object]] = []
    events: list[dict[str, object]] = []
    manager = CgroupManager(raw_profile)
    controller = ControllerSession(manager)
    profile_resources = {row["resource"]: row["limit"] for row in raw_profile["resources"]}

    chain = _execute_prepared_proposal(
        raw_profile,
        compiled_profile,
        measurement,
        seccomp_program,
        role_seccomp,
        tools,
        policy,
        manager,
        controller,
    )
    negative_results = _pre_stage_negative_oracles(chain, manager)
    stage_execution = _execute_executor_stage(
        chain,
        str(policy["digest"]),
        role_seccomp["EXECUTOR"],
        manager,
    )
    worker_facts = chain["worker_facts"]
    broker_facts = chain["broker_facts"]
    worker_root_record = chain["worker_root_record"]
    broker_root_record = chain["broker_runtime_record"]
    executor_root_record = stage_execution["executor_root_record"]
    probe_program = _probe_program("direct-write")
    probe_root, probe_root_record = _materialize_rootfs(
        "AGENT_WORKER", probe_program, "bounded-probes"
    )
    packet = _worker_packet(compiled_profile, chain["request"])
    _record_pass(
        tests, events, "T-M3-ACTUAL-BWRAP-LAUNCH", "TCB_LAUNCH", "agent_worker-1",
        {
            "worker": worker_facts,
            "broker": broker_facts,
            "packet_digest": _digest_bytes(packet),
            "worker_status_digest": chain["worker_status_digest"],
            "broker_status_digest": chain["broker_status_digest"],
            "pair_holder_attestation_digest": chain["pair_holder_attestation"]["payload_digest"],
        },
        {"worker_label": PROFILE_LABELS["AGENT_WORKER"], "broker_label": PROFILE_LABELS["BROKER"]},
        "Actual pinned bwrap launched distinct broker and worker only after durable PREPARED and signed endpoint-holder verification.",
    )
    evaluated = chain["evaluated"]
    decision_observation = {
        "outcome": evaluated.decision.outcome.value,
        "reason": evaluated.decision.reason.value,
        "stage": evaluated.decision.stage.value,
        "transition_accepted": evaluated.transition.accepted,
        "proposal_authorities": [item.authority.value for item in evaluated.transition.proposals],
    }
    _record_pass(
        tests, events, "T-DECISION-ALLOW-EXACT", "TCB_LAUNCH", "m1-kernel",
        decision_observation,
        {
            "outcome": "ALLOW",
            "transition_accepted": True,
            "proposal_authority": "NONE",
        },
        "The exact M1 request produced ALLOW while its only proposal remained powerless.",
    )
    _record_pass(
        tests, events, "T-M3-LIFECYCLE-PREPARED-TERMINAL", "TCB_CLEANUP", "m3-session-record-1",
        {
            "prepared": {
                "session_record_id": chain["runtime_session"].session_record_id,
                "state": chain["runtime_session"].state,
                "runtime_bindings_digest": _digest_bytes(
                    chain["runtime_session"].runtime_bindings_json.encode("utf-8")
                ),
            },
            "terminal": stage_execution["terminal"],
            "recovery": stage_execution["recovery"],
        },
        {
            "prepared": "PREPARED",
            "terminal": "QUARANTINED_ESCROW",
            "retry_created": False,
        },
        "The durable session moved from PREPARED to one terminal quarantined escrow state with no retry.",
    )
    _record_pass(
        tests, events, "T-M3-BROKER-MEDIATED-STAGE", "TCB_STAGE", "executor-3",
        {
            "broker_report_digest": chain["broker_report_digest"],
            "claim_digest": chain["claim"].claim_digest,
            "executor": stage_execution["executor_facts"],
            "stage": stage_execution["stage_result"],
            "before": stage_execution["stage_before"],
            "after": stage_execution["stage_after"],
        },
        {
            "audience": "executor-3",
            "outcome": "STAGED",
            "outside_effects": 0,
        },
        "One committed claim traversed the exact broker pair and one distinct executor changed only the disposable staging canary.",
    )
    _record_pass(
        tests, events, "T-M3-UNCERTAINTY-QUARANTINE-NO-RETRY", "TCB_RECOVERY", "transaction-m3-1",
        {
            "terminal": stage_execution["terminal"],
            "recovery": stage_execution["recovery"],
        },
        {"disposition": "QUARANTINED_ESCROW", "retry_created": False},
        "Without M4 acknowledgement the completed staging attempt remains quarantined escrow and cannot be claimed again.",
    )
    _record_pass(
        tests, events, "T-Q43-DESCRIPTOR-ROOT-SUBSTITUTION", "TCB_DENY", "executor-3",
        stage_execution["executor_facts"]["staging_oracle"],
        {
            "actual_root_bound": True,
            "substitution_reason": "EXECUTOR_STAGING_ROOT_MISMATCH",
            "unchanged_before_gate": True,
        },
        "The external observer bound the actual executor staging mount and rejected a same-bytes substitute root before opening the inner gate.",
    )
    _record_pass(
        tests, events, "T-Q47-MUTATION-SELF-AUDIENCE-DENY", "TCB_DENY", "transaction-m3-1",
        negative_results["self_audience"],
        {"outcome": "STOP", "reason": "CLAIM_MISMATCH", "staging_unchanged": True},
        "A worker-self audience substitution was rejected before the executor effect boundary.",
    )
    _record_pass(
        tests, events, "T-M3-CONFUSED-DEPUTY-DENY", "TCB_DENY", "transaction-m3-1",
        negative_results["confused_deputy"],
        {"claim": "CLAIM_MISMATCH", "argument": "MATERIAL_MISMATCH", "staging_unchanged": True},
        "Claim-material and request-argument substitutions were rejected before staging.",
    )
    _record_pass(
        tests, events, "T-Q39-SUPPLY-EXTERNAL-BUNDLE-SUBSTITUTION", "TCB_DENY", "transaction-m3-1",
        negative_results["supply_substitution"],
        {"outcome": "STOP", "reason": "SUPPLY_MISMATCH", "staging_unchanged": True},
        "A signed-supply runtime-byte substitution was rejected before executor launch.",
    )
    _record_pass(
        tests, events, "T-M3-STALE-FENCE-REVOCATION-DENY", "TCB_DENY", "transaction-m3-1",
        negative_results["epochs"],
        {"stale_fence": "STALE_FENCE", "stale_revocation": "STALE_REVOCATION"},
        "Independent durable-store copies rejected the committed claim after fence and revocation advances.",
    )

    # Remaining fixed probes each get a fresh rootfs/session/cgroup and no
    # staging or controller state.  They are bounded and never target egress.
    probe_results: dict[str, object] = {}
    for probe_name, test_id, event_type, timeout_value in (
        ("direct-write", "T-Q46-DIRECT-WORKER-MUTATE-DENY", "TCB_DENY", 2.0),
        ("network", "T-M3-NETWORK-DENY", "TCB_DENY", 2.0),
        ("kernel", "T-M3-KERNEL-SURFACES-DENY", "TCB_DENY", 2.0),
        ("fd-limit", "T-M3-RLIMIT-NOFILE", "TCB_RESOURCE", 2.0),
        (
            "timeout", "T-M3-WALL-TIME-TREE-KILL", "TCB_KILL",
            profile_resources["WALL_TIME"] / 1000.0,
        ),
    ):
        probe_cgroup = manager.create("probe-" + probe_name)
        probe, probe_status, facts = _launch_resource_probe(
            probe_name, probe_root, probe_cgroup, probe_program,
            seccomp_program=seccomp_program,
            apparmor_digest=str(policy["digest"]), profile=raw_profile,
            expected_limits=manager.limits,
        )
        tree_before = probe_cgroup.joinpath("cgroup.procs").read_text(encoding="ascii").split()
        started = time.monotonic()
        return_code, probe_status_digest = _complete_role(
            probe, probe_status, probe_cgroup, timeout=timeout_value
        )
        elapsed = time.monotonic() - started
        manager.kill(probe_cgroup)
        expected = return_code == 0 if probe_name != "timeout" else return_code < 0
        if (
            not expected
            or (
                probe_name == "timeout"
                and (
                    len(tree_before) < 2
                    or elapsed < timeout_value
                    or elapsed > timeout_value + 0.75
                    or probe_cgroup.joinpath("cgroup.procs").read_text(encoding="ascii").split()
                )
            )
        ):
            _stop(f"PROBE_FAILED:{probe_name}:{return_code}")
        probe_results[probe_name] = {
            "return_code": return_code,
            "facts": facts,
            "status": probe_status_digest,
            "elapsed_ms": int(elapsed * 1000),
            "process_tree_before": tree_before,
            "cgroup_events": probe_cgroup.joinpath("cgroup.events").read_text(encoding="ascii").splitlines(),
        }
        _record_pass(
            tests, events, test_id, event_type, "agent_worker-1", probe_results[probe_name],
            {"bounded": True, "denied_or_killed": True},
            "Bounded in-guest kernel oracle observed the required deny or whole-tree kill.",
        )

    resource_results = _run_cgroup_resource_oracles(
        raw_profile,
        probe_root,
        probe_program,
        seccomp_program,
        str(policy["digest"]),
        manager,
        tests,
        events,
    )
    resource_results["io"] = _run_io_oracle(
        raw_profile,
        role_seccomp["EXECUTOR"],
        str(policy["digest"]),
        manager,
    )
    _record_pass(
        tests, events, "T-M3-CGROUP-IO-LIMIT", "TCB_RESOURCE", "executor-io-probe",
        resource_results["io"],
        {
            "exact_io_max": manager.limits["io.max"],
            "direct_read_and_write_accounted": True,
            "control_vs_limited_slowdown": ">=3",
        },
        "A fixed O_DIRECT executor workload was accounted to the exact block device and measurably throttled by the profile io.max relative to an unbounded control.",
    )
    resource_results["quota"] = _run_quota_oracle(
        raw_profile,
        compiled_profile,
        role_seccomp["EXECUTOR"],
        str(policy["digest"]),
        manager,
    )
    canary_after = _external_canary_snapshot(canary_paths)
    canaries = {
        "staging_before": stage_execution["stage_before"]["digest"],
        "staging_after": stage_execution["stage_after"]["digest"],
        **{
            name + "_before": canary_before[name]
            for name in ("checkout", "home", "secret", "durable_db", "outside")
        },
        **{
            name + "_after": canary_after[name]
            for name in ("checkout", "home", "secret", "durable_db", "outside")
        },
    }
    if (
        canaries["staging_before"] == canaries["staging_after"]
        or any(
            canaries[name + "_before"] != canaries[name + "_after"]
            for name in ("checkout", "home", "secret", "durable_db", "outside")
        )
    ):
        _stop("CANARY_BOUNDARY_MISMATCH")
    _record_pass(
        tests, events, "T-M3-CANARY-INVISIBILITY", "TCB_DENY", "agent_worker-1",
        {
            "canaries": canaries,
            "direct_probe": probe_results["direct-write"],
            "quota": resource_results["quota"],
        },
        {
            "only_disposable_staging_changed": True,
            "ambient_paths_opened": 0,
            "files": profile_resources["FILES"],
            "inodes": profile_resources["INODES"],
            "output_bytes": profile_resources["OUTPUT_BYTES"],
            "overflow_denied": True,
        },
        "The direct worker probe could open none of the ambient canaries; only disposable staging changed, while a distinct executor tmpfs enforced the exact files, inode, and output-byte bounds.",
    )

    controller_facts = controller.close()
    old_process_ids = {
        controller_facts["process_id"],
        worker_facts["process_id"],
        broker_facts["process_id"],
        stage_execution["executor_facts"]["process_id"],
        *(row["facts"]["process_id"] for row in probe_results.values()),
        resource_results["cpu"]["facts"]["process_id"],
        resource_results["memory"]["facts"]["process_id"],
        *(row["process_id"] for row in resource_results["pids"]["facts"]),
        resource_results["io"]["control"]["runtime"]["process_id"],
        resource_results["io"]["limited"]["runtime"]["process_id"],
        resource_results["quota"]["runtime"]["process_id"],
    }

    state = {
        "state_version": "1.0.0",
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip(),
        "profile_digest": compiled_profile.profile_digest,
        "profile_artifact_digest": _digest_file(PROFILE),
        "source": source,
        "host_provenance": host_provenance,
        "guest_measurement": _guest_measurement(
            measurement,
            guest_marker,
            worker_root_record["tree_digest"],
        ),
        "seccomp_bpf_digest": _digest_bytes(seccomp_program),
        "tools": tools,
        "policy": policy,
        "rootfs": {
            "worker": worker_root_record,
            "broker": broker_root_record,
            "executor": executor_root_record,
            "probes": probe_root_record,
        },
        "resources": profile_resources,
        "cgroup": {
            "path": str(manager.root).removeprefix("/sys/fs/cgroup"),
            "controllers": list(CONTROLLERS),
            "limits": manager.limits,
            "populated_after_cleanup": 0,
        },
        "worker_facts": worker_facts,
        "broker_facts": broker_facts,
        "executor_facts": stage_execution["executor_facts"],
        "controller_facts": controller_facts,
        "broker_ipc": json.loads(chain["session_plan"].runtime_bindings_json)["broker_ipc"],
        "pair_holder_attestation": chain["pair_holder_attestation"],
        "broker_report": chain["broker_report"],
        "broker_report_digest": chain["broker_report_digest"],
        "supply_material": chain["supply_material"],
        "attestor_facts": chain["attestor_facts"],
        "runtime_attestor_facts": chain["runtime_attestor_facts"],
        "role_seccomp": role_seccomp_records,
        "decision": decision_observation,
        "supply": asdict(chain["supply"]),
        "runtime_session": asdict(chain["runtime_session"]),
        "stage": {
            "result": stage_execution["stage_result"],
            "result_digest": stage_execution["stage_result_digest"],
            "before": stage_execution["stage_before"],
            "after": stage_execution["stage_after"],
            "terminal": stage_execution["terminal"],
            "recovery": stage_execution["recovery"],
            "terminal_evidence": stage_execution["terminal_evidence"],
            "executor_attestation": stage_execution["executor_attestation"],
        },
        "negative_results": negative_results,
        "canaries": canaries,
        "tests": tests,
        "events": events,
        "probe_results": probe_results,
        "resource_results": resource_results,
        "fencing_epoch": 1,
        "revocation_epoch": 0,
        "old_process_ids": sorted(old_process_ids),
        "runtime_root": str(RUNTIME),
        "residual_risk": RESIDUAL_RISK,
    }
    _validate_test_event_set(
        tests,
        events,
        frozenset(TEST_MATRIX) - {"T-M3-RESTART-CLEANUP-NO-RESUME"},
    )
    state["cleanup"] = _cleanup_disposable_runtime(
        manager,
        Path(chain["staging"]["path"]),
    )
    _replace_exact(RUN_STATE, _canonical(state), 0o600)
    print(_canonical({"outcome": "PRE_RESTART_PASS", "run_state_digest": _digest_file(RUN_STATE)}).decode())


def _recover_phase() -> None:
    _require_guest()
    source = _source_identity()
    host_provenance = _host_provenance()
    raw_profile, _, _ = _profile()
    state = _strict_json(
        RUN_STATE,
        frozenset(
            {
                "state_version", "boot_id", "profile_digest", "profile_artifact_digest",
                "source", "host_provenance", "guest_measurement", "seccomp_bpf_digest",
                "tools", "policy", "rootfs", "resources", "cgroup",
                "controller_facts", "worker_facts", "broker_facts", "executor_facts", "broker_ipc",
                "pair_holder_attestation", "broker_report", "broker_report_digest", "decision", "supply",
                "supply_material", "attestor_facts", "runtime_attestor_facts", "role_seccomp",
                "runtime_session", "stage", "negative_results", "canaries", "tests", "events",
                "probe_results", "resource_results", "fencing_epoch", "revocation_epoch",
                "old_process_ids", "runtime_root", "residual_risk", "cleanup",
            }
        ),
    )
    if state["state_version"] != "1.0.0" or state["runtime_root"] != str(RUNTIME):
        _stop("RUN_STATE_BINDING_MISMATCH")
    if state["source"] != source or state["host_provenance"] != host_provenance:
        _stop("RECOVERY_PROVENANCE_MISMATCH")
    _reload_recovery_apparmor(state["policy"])
    _validate_test_event_set(
        state["tests"],
        state["events"],
        frozenset(TEST_MATRIX) - {"T-M3-RESTART-CLEANUP-NO-RESUME"},
    )
    current_boot = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    if current_boot == state["boot_id"]:
        _stop("RESTART_REQUIRED")
    if any(Path(f"/proc/{pid}").exists() for pid in state["old_process_ids"]):
        _stop("OLD_PROCESS_SURVIVED")
    old_cgroup = Path("/sys/fs/cgroup", str(state["cgroup"]["path"]).lstrip("/"))
    if old_cgroup.exists():
        _stop("OLD_CGROUP_SURVIVED")
    if _runtime_mount_targets():
        _stop("OLD_MOUNT_SURVIVED")
    if RUNTIME.exists():
        _stop("OLD_RUNTIME_STORAGE_SURVIVED")
    cleanup = state["cleanup"]
    if (
        type(cleanup) is not dict
        or frozenset(cleanup)
        != {
            "descriptors", "removed_mounts", "remaining_mounts",
            "runtime_root_absent", "cgroup_children_empty",
        }
        or cleanup["removed_mounts"] != [str(RUNTIME / "staging" / "session-1")]
        or cleanup["remaining_mounts"] != []
        or cleanup["runtime_root_absent"] is not True
        or cleanup["cgroup_children_empty"] is not True
    ):
        _stop("RUN_CLEANUP_RECORD_MISMATCH")
    _, durable, _ = _load_project()
    verifier = Ed25519PayloadVerifier()
    store = durable.DurableStore(
        str(CONTROLLER / "durable.sqlite3"),
        verifier,
        executor_claim_verifier=verifier,
        runtime_session_verifier=verifier,
    )
    recovered = store.recover()
    if (
        recovered.outcome is not durable.DurableOutcome.OK
        or len(recovered.recovery_intents) != 1
        or recovered.recovery_intents[0].state != "QUARANTINED_ESCROW"
        or len(recovered.recovery_sessions) != 1
        or recovered.recovery_sessions[0].state != "QUARANTINED"
    ):
        _stop("RESTART_DURABLE_RECOVERY_MISMATCH")
    recovery = {
        "old_boot_id": state["boot_id"],
        "current_boot_id": current_boot,
        "old_processes_absent": True,
        "old_cgroup_absent": True,
        "old_mounts_absent": True,
        "old_runtime_storage_absent": True,
        "recovery_intents": [asdict(item) for item in recovered.recovery_intents],
        "recovery_sessions": [asdict(item) for item in recovered.recovery_sessions],
        "old_session_resumed": False,
        "retry_created": False,
    }
    tests = list(state["tests"])
    events = list(state["events"])
    _record_pass(
        tests,
        events,
        "T-M3-RESTART-CLEANUP-NO-RESUME",
        "TCB_RECOVERY",
        "m3-session-record-1",
        recovery,
        {
            "new_boot": True,
            "old_processes": 0,
            "old_cgroups": 0,
            "old_mounts": 0,
            "old_storage": 0,
            "durable_disposition": "QUARANTINED_ESCROW",
            "old_session_resumed": False,
            "retry_created": False,
        },
        "After a real VM reboot, no old process, cgroup, mount, or writable runtime layer survived; durable quarantine remained and no retry or session resume was created.",
        phase="recover",
    )
    _validate_test_event_set(tests, events, frozenset(TEST_MATRIX))
    bundle_digest, signer_facts = _export_evidence(
        state,
        raw_profile,
        tests,
        events,
        recovery,
        current_boot,
    )
    print(
        _canonical(
            {
                "outcome": "RECOVERY_PASS",
                "tests": len(tests),
                "events": len(events),
                "old_session_resumed": False,
                "retry_created": False,
                "recovery_digest": _digest_bytes(_canonical(recovery)),
                "bundle_digest": bundle_digest,
                "signer_subject_digest": _digest_bytes(_canonical(signer_facts)),
            }
        ).decode()
    )


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    try:
        if arguments == ["--phase", "run"]:
            _run_phase()
        elif arguments == ["--phase", "recover"]:
            _recover_phase()
        elif arguments == ["--controller-session"]:
            _controller_session_phase()
        else:
            _stop("UNKNOWN_OR_MISSING_ARGUMENT")
        return 0
    except QualificationStop as error:
        print(_canonical({"outcome": "STOP", "reason": str(error)}).decode())
        return 1
    except Exception as error:
        try:
            CONTROLLER.mkdir(mode=0o700, parents=True, exist_ok=True)
            detail = {
                "diagnostic_version": "1.0.0",
                "error_type": type(error).__name__[:128],
                "message": str(error)[:512],
            }
            _replace_exact(CONTROLLER / "last-failure.json", _canonical(detail), 0o600)
        except Exception:
            pass
        print(_canonical({"outcome": "STOP", "reason": "INTERNAL_FAILURE"}).decode())
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
