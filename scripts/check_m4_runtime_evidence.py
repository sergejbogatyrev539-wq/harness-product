#!/usr/bin/env python3
"""Independent exact-candidate verifier for the disposable M4 VM bundle."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
from typing import NoReturn


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from harness_product.durable import VerificationStatus  # noqa: E402
from harness_product.verification import OpenSSLEd25519Verifier  # noqa: E402


PROFILE = ROOT / "profiles/m4-lx-a.json"
APPARMOR = ROOT / "profiles/m4-lx-a.apparmor"
M3_APPARMOR = ROOT / "profiles/l0-lx-a.apparmor"
VERIFIER_CODE = SRC / "harness_product/verification.py"
LIBCRYPTO = Path("/usr/lib/x86_64-linux-gnu/libcrypto.so.3")
M4_LAB = Path("/home/a1/Загрузки/harness/harness-m4-qualification-v2")
IMAGE_LAB = Path("/home/a1/Загрузки/harness/harness-m3-lab")
USER_GOAL = Path(
    "/home/a1/.codex/attachments/4adf762e-32a5-45e2-bf75-3c79125ace23/pasted-text.txt"
)
_BUNDLE_FILES = frozenset({
    "manifest.json", "manifest.sig", "evidence.json", "attempt-ledger.jsonl",
})
_SIGNED_PAYLOAD_FILES = frozenset({"manifest.json", "manifest.sig", "evidence.json"})
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_TIME = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
_IMAGE_URL = (
    "https://cloud-images.ubuntu.com/releases/noble/release-20260814/"
    "ubuntu-24.04-server-cloudimg-amd64.img"
)
_IMAGE_DIGEST = "sha256:6e40c07ae715f744f84af0bec76415cc1987dd115b4b8de437818561f01a3733"
_PROFILE_DIGEST = "sha256:50947b4b4ae139effbaddd749c7175a15755675f824e0ae1ed734a85694b4682"
_PREDECESSOR_QUALIFICATION_LEDGER_DIGEST = (
    "sha256:719505206caf364c6c0d40983687416bcca5644f879a46254714621cb070d5f9"
)
_PREDECESSOR_DIAGNOSTIC_LEDGER_DIGEST = (
    "sha256:6d5d1d00dc2fc303a061c1fc6f3456fb1e6c9fb1c1baae3f667a6521f8382d78"
)
_PREDECESSOR_DIAGNOSTIC_BUNDLE_DIGEST = (
    "sha256:91abc47ad6070c8b9c8cad89369780b698a696c3e90aed5e2c84cb45f0b1418d"
)
_SUMS_DIGEST = "sha256:0f92d5610dfc5797f9574a5a8a000021d845c70c70f6b187b2b78eb1584618cf"
_SUMS_SIGNATURE_DIGEST = "sha256:a4466d91a9481850908ce0e8c518ebb1cf3ca414add6ba378e783c7d553618a7"
_UBUNTU_SIGNER = "D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81"
_QEMU_PATH = "/usr/bin/qemu-system-x86_64"
_QEMU_DIGEST = "sha256:8a35ccba41582fc6c38b9df85fc9e35fa1d42f414d2d7d8090ee9b2f5e7c0854"
_OVERLAY_VIRTUAL_BYTES = 3758096384
_SOURCE_FIXED = (
    "AGENTS.md", "README.md", "ROADMAP.md", "SECURITY.md", "STATUS.json",
    "docs/ARCHITECTURE.md", "profiles/harness-m3-controller@.service",
    "profiles/harness-m4-controller@.service", "profiles/m4-lx-a.apparmor",
    "profiles/m4-lx-a.json", "spec/MANIFEST.sha256",
)
_RESIDUAL_RISK = (
    "Exact disposable Ubuntu 24.04 M4 test profile only; no production trust "
    "root, production deployment, universal-project non-bypassability, M5, or "
    "product readiness claim. Observer and publisher use distinct keys but all "
    "Ed25519 verification instances use the same pinned OpenSSL libcrypto."
)


class _InvalidEvidence(Exception):
    pass


def _invalid(reason: str) -> NoReturn:
    raise _InvalidEvidence(reason)


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as error:
        raise _InvalidEvidence("NONCANONICAL_JSON") from error


def _strict_json(raw: bytes, maximum: int, *, canonical: bool = True) -> object:
    if type(raw) is not bytes or not raw or len(raw) > maximum:
        _invalid("MALFORMED_JSON")

    def pairs(rows: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in rows:
            if type(key) is not str or key in result:
                _invalid("DUPLICATE_JSON_KEY")
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=pairs,
            parse_constant=lambda _: _invalid("NONFINITE_JSON"),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise _InvalidEvidence("MALFORMED_JSON") from error
    if canonical and _canonical(value) != raw:
        _invalid("NONCANONICAL_JSON")
    return value


def _read_regular(path: Path, maximum: int) -> bytes:
    try:
        before = os.lstat(path)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) & 0o022
            or before.st_size < 1
            or before.st_size > maximum
        ):
            _invalid("UNTRUSTED_FILE")
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as error:
        raise _InvalidEvidence("UNTRUSTED_FILE") from error
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (
            before.st_dev, before.st_ino, before.st_size
        ):
            _invalid("FILE_IDENTITY_CHANGED")
        remaining = opened.st_size
        chunks: list[bytes] = []
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                _invalid("SHORT_READ")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            _invalid("UNBOUNDED_READ")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _read_regular_at(
    directory_descriptor: int,
    name: str,
    maximum: int,
    *,
    mode: int,
    owner: int,
) -> bytes:
    if (
        type(directory_descriptor) is not int
        or directory_descriptor < 0
        or type(name) is not str
        or not name
        or "/" in name
        or name in {".", ".."}
    ):
        _invalid("UNTRUSTED_FILE")
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=directory_descriptor,
        )
    except OSError as error:
        raise _InvalidEvidence("UNTRUSTED_FILE") from error
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_uid != owner
            or stat.S_IMODE(opened.st_mode) != mode
            or opened.st_size < 1
            or opened.st_size > maximum
        ):
            _invalid("UNTRUSTED_FILE")
        remaining = opened.st_size
        chunks: list[bytes] = []
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                _invalid("SHORT_READ")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            _invalid("UNBOUNDED_READ")
        after = os.fstat(descriptor)
        linked = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
        identity = (
            opened.st_dev, opened.st_ino, opened.st_size, opened.st_nlink,
            opened.st_uid, stat.S_IMODE(opened.st_mode),
        )
        if identity != (
            after.st_dev, after.st_ino, after.st_size, after.st_nlink,
            after.st_uid, stat.S_IMODE(after.st_mode),
        ) or identity != (
            linked.st_dev, linked.st_ino, linked.st_size, linked.st_nlink,
            linked.st_uid, stat.S_IMODE(linked.st_mode),
        ):
            _invalid("FILE_IDENTITY_CHANGED")
        return b"".join(chunks)
    except OSError as error:
        raise _InvalidEvidence("UNTRUSTED_FILE") from error
    finally:
        os.close(descriptor)


def _digest_bytes(value: bytes) -> str:
    return "sha256:" + sha256(value).hexdigest()


def _digest_file(path: Path, maximum: int) -> str:
    return _digest_bytes(_read_regular(path, maximum))


def _closed(value: object, keys: frozenset[str]) -> dict[str, object]:
    if type(value) is not dict or frozenset(value) != keys:
        _invalid("UNKNOWN_OR_MISSING_FIELD")
    return value


def _digest(value: object) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        _invalid("DIGEST_MALFORMED")
    return value


def _closed_file_digest(file_digests: object, names: frozenset[str]) -> str:
    rows = _closed(file_digests, names)
    for digest in rows.values():
        _digest(digest)
    return _digest_bytes(_canonical({name: rows[name] for name in sorted(names)}))


def _integer(value: object, minimum: int = 0) -> int:
    if type(value) is not int or isinstance(value, bool) or value < minimum:
        _invalid("INTEGER_MALFORMED")
    return value


def _parse_timestamp(value: object) -> datetime:
    if type(value) is not str or _TIME.fullmatch(value) is None:
        _invalid("TIME_MALFORMED")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as error:
        raise _InvalidEvidence("TIME_MALFORMED") from error


def _timestamp(value: object, now: datetime) -> datetime:
    parsed = _parse_timestamp(value)
    if parsed > now:
        _invalid("TIME_FUTURE")
    return parsed


def _run(argv: list[str]) -> bytes:
    try:
        result = subprocess.run(
            argv, shell=False, close_fds=True, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={"LC_ALL": "C"},
            cwd="/", timeout=10, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise _InvalidEvidence("SOURCE_UNAVAILABLE") from error
    if result.returncode != 0:
        _invalid("SOURCE_UNAVAILABLE")
    return result.stdout


def _qemu_argv(attempt: int, phase: str) -> list[str]:
    if type(attempt) is not int or isinstance(attempt, bool) or attempt not in {1, 2}:
        _invalid("ATTEMPT_MISMATCH")
    if phase not in {"provision", "run", "recover"}:
        _invalid("VM_PHASE_MISMATCH")
    attempt_root = M4_LAB / "runs" / f"attempt-{attempt}"
    argv = [
        _QEMU_PATH,
        "-name", f"harness-m4-disposable-attempt-{attempt}-{phase}",
        "-machine", "q35,accel=kvm",
        "-cpu", "host",
        "-smp", "2",
        "-m", "2048",
        "-drive", "if=virtio,format=qcow2,file=" + str(attempt_root / "overlay.qcow2"),
    ]
    if phase == "provision":
        argv.extend([
            "-drive",
            "if=virtio,format=raw,readonly=on,media=cdrom,file="
            + str(attempt_root / "seed.iso"),
        ])
    argv.extend([
        "-netdev",
        "user,id=net0,restrict=" + ("off" if phase == "provision" else "on")
        + ",hostfwd=tcp:127.0.0.1:22227-:22",
        "-device", "virtio-net-pci,netdev=net0",
        "-display", "none",
        "-serial", "file:" + str(attempt_root / f"{phase}.serial.log"),
        "-monitor", "none",
        "-no-reboot",
    ])
    return argv


def _qemu_lifecycle(attempt: int) -> dict[str, list[str]]:
    return {phase: _qemu_argv(attempt, phase) for phase in ("provision", "run", "recover")}


def _validate_qemu_phase_outcomes(value: object, attempt: int) -> dict[str, object]:
    rows = _closed(value, frozenset({"provision", "run", "recover"}))
    for phase in ("provision", "run", "recover"):
        row = _closed(rows[phase], frozenset({"argv_digest", "return_code"}))
        if (
            row["argv_digest"] != _digest_bytes(_canonical(_qemu_argv(attempt, phase)))
            or _integer(row["return_code"], 0) != 0
        ):
            _invalid("QEMU_PHASE_OUTCOME_MISMATCH")
    return rows


def _validate_host_provenance(raw: object, attempt: int) -> dict[str, object]:
    value = _closed(raw, frozenset({"image", "vm"}))
    image = _closed(
        value["image"],
        frozenset({
            "source_url", "resolved_url", "release_id", "filename", "bytes",
            "sha256", "sums_sha256", "sums_signature_sha256", "signer_fingerprint",
        }),
    )
    vm = _closed(
        value["vm"],
        frozenset({
            "qemu_path", "qemu_version", "qemu_digest", "machine", "kvm_api",
            "vcpus", "memory_bytes", "overlay_virtual_bytes", "seed_digest",
            "management_address", "shared_host_mounts", "qemu_argv_digest",
        }),
    )
    for key, minimum in (
        ("bytes", 1),
        ("kvm_api", 1),
        ("vcpus", 1),
        ("memory_bytes", 1),
        ("overlay_virtual_bytes", 1),
        ("shared_host_mounts", 0),
    ):
        _integer(image[key] if key == "bytes" else vm[key], minimum)
    for digest in (
        image["sha256"], image["sums_sha256"], image["sums_signature_sha256"],
        vm["qemu_digest"], vm["seed_digest"], vm["qemu_argv_digest"],
    ):
        _digest(digest)
    if (
        image != {
            "source_url": _IMAGE_URL,
            "resolved_url": _IMAGE_URL,
            "release_id": "20260814",
            "filename": "ubuntu-24.04-server-cloudimg-amd64.img",
            "bytes": 624447488,
            "sha256": _IMAGE_DIGEST,
            "sums_sha256": _SUMS_DIGEST,
            "sums_signature_sha256": _SUMS_SIGNATURE_DIGEST,
            "signer_fingerprint": _UBUNTU_SIGNER,
        }
        or vm["qemu_path"] != _QEMU_PATH
        or vm["qemu_digest"] != _QEMU_DIGEST
        or type(vm["qemu_version"]) is not str
        or not vm["qemu_version"].startswith("QEMU emulator version 8.2.2 ")
        or vm["machine"] != "q35"
        or vm["kvm_api"] != 12
        or vm["vcpus"] != 2
        or vm["memory_bytes"] != 2 * 1024 * 1024 * 1024
        or vm["overlay_virtual_bytes"] != _OVERLAY_VIRTUAL_BYTES
        or vm["management_address"] != "127.0.0.1:22227"
        or vm["shared_host_mounts"] != 0
        or vm["qemu_argv_digest"] != _digest_bytes(_canonical(_qemu_lifecycle(attempt)))
    ):
        _invalid("HOST_PROVENANCE_MISMATCH")
    return value


def _verify_retained_host_assets(lab: Path) -> None:
    image = lab / "ubuntu-24.04-server-cloudimg-amd64.img"
    sums = lab / "SHA256SUMS"
    signature = lab / "SHA256SUMS.gpg"
    if (
        _digest_file(image, 1 << 30) != _IMAGE_DIGEST
        or _digest_file(sums, 1 << 20) != _SUMS_DIGEST
        or _digest_file(signature, 1 << 20) != _SUMS_SIGNATURE_DIGEST
        or _digest_file(Path(_QEMU_PATH), 64 << 20) != _QEMU_DIGEST
    ):
        _invalid("HOST_ASSET_DIGEST_MISMATCH")
    expected = _IMAGE_DIGEST.removeprefix("sha256:") + " *ubuntu-24.04-server-cloudimg-amd64.img"
    if expected not in _read_regular(sums, 1 << 20).decode("utf-8").splitlines():
        _invalid("IMAGE_SUMS_BINDING_MISMATCH")
    try:
        verified = subprocess.run(
            [
                "/usr/bin/gpgv", "--status-fd", "1", "--keyring",
                "/usr/share/keyrings/ubuntu-cloudimage-keyring.gpg",
                str(signature), str(sums),
            ],
            shell=False,
            close_fds=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"LC_ALL": "C"},
            cwd="/",
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise _InvalidEvidence("IMAGE_SIGNATURE_MISMATCH") from error
    if verified.returncode != 0 or not any(
        line.startswith("[GNUPG:] VALIDSIG " + _UBUNTU_SIGNER + " ")
        for line in verified.stdout.decode("utf-8", "replace").splitlines()
    ):
        _invalid("IMAGE_SIGNATURE_MISMATCH")
    qemu_version = _run([_QEMU_PATH, "--version"]).decode("utf-8", "replace").splitlines()[0]
    if not qemu_version.startswith("QEMU emulator version 8.2.2 "):
        _invalid("QEMU_VERSION_MISMATCH")


def _source_state(root: Path = ROOT, *, require_clean: bool = True) -> dict[str, object]:
    commit = _run(["/usr/bin/git", "-C", str(root), "rev-parse", "HEAD"]).decode().strip()
    tree = _run(["/usr/bin/git", "-C", str(root), "rev-parse", "HEAD^{tree}"]).decode().strip()
    if _COMMIT.fullmatch(commit) is None or _COMMIT.fullmatch(tree) is None:
        _invalid("SOURCE_IDENTITY_INVALID")
    if require_clean and _run(
        ["/usr/bin/git", "-C", str(root), "status", "--porcelain=v1", "--untracked-files=no"]
    ):
        _invalid("SOURCE_DIRTY")
    tracked = _run(
        ["/usr/bin/git", "-C", str(root), "ls-files", "-z", "--",
         "src/harness_product", "scripts", "profiles", "tests"]
    ).split(b"\0")
    paths = [
        raw.decode("utf-8") for raw in tracked if raw and (
            raw.startswith(b"src/harness_product/") and raw.endswith(b".py")
            or raw.startswith(b"scripts/") and raw.endswith(b".py")
            or raw.startswith(b"tests/") and raw.endswith(b".py")
            or raw.startswith(b"profiles/l0-lx-a")
        )
    ]
    paths.extend(_SOURCE_FIXED)
    if len(paths) != len(set(paths)) or not paths:
        _invalid("SOURCE_FILE_SET_INVALID")
    files = {
        name: _digest_file(root / name, 16 << 20)
        for name in sorted(paths)
    }
    return {
        "commit": commit,
        "tree": tree,
        "files": files,
        "files_digest": _digest_bytes(_canonical(files)),
    }


def _source_archive_digest(root: Path = ROOT) -> str:
    raw = _run([
        "/usr/bin/git", "-C", str(root), "archive", "--format=tar.gz", "HEAD",
    ])
    if not raw or len(raw) > 64 << 20:
        _invalid("SOURCE_ARCHIVE_MISMATCH")
    return _digest_bytes(raw)


def _validate_source_projection(value: object) -> dict[str, object]:
    source = _closed(
        value, frozenset({"commit", "tree", "files", "files_digest"})
    )
    files = source["files"]
    if (
        type(source["commit"]) is not str
        or _COMMIT.fullmatch(source["commit"]) is None
        or type(source["tree"]) is not str
        or _COMMIT.fullmatch(source["tree"]) is None
        or type(files) is not dict
        or not files
        or any(type(path) is not str or not path for path in files)
        or any(_digest(digest) != digest for digest in files.values())
        or source["files_digest"] != _digest_bytes(_canonical(files))
    ):
        _invalid("SOURCE_PROJECTION_MISMATCH")
    return source


_CONTRACT_CORE_FIELDS = frozenset({
    "contract_version", "contract_kind", "user_scope_reference",
    "user_goal_digest", "candidate", "tree", "attempt",
    "source_files_digest", "canonical_profile_digest",
    "raw_profile_artifact_digest", "base_image_digest",
    "predecessor_qualification_ledger_digest",
    "predecessor_diagnostic_ledger_digest",
    "predecessor_diagnostic_bundle_digest", "max_attempts",
    "success_target", "success_target_authorizing",
})
_ENVIRONMENT_PREIMAGE_FIELDS = frozenset({
    "contract_core_digest", "source_archive_digest", "seed_digest",
    "package_runtime_plan_digest", "host_provenance_digest",
})
_QUALIFICATION_CONTRACT_FIELDS = frozenset({
    "contract_core", "contract_core_digest", "environment_preimage",
    "environment_digest",
})
_PACKAGE_VERSIONS = {
    "apparmor": "4.0.1really4.0.1-0ubuntu0.24.04.7",
    "apparmor-utils": "4.0.1really4.0.1-0ubuntu0.24.04.7",
    "bubblewrap": "0.9.0-1ubuntu0.1",
    "libssl3t64": "3.0.13-0ubuntu3.12",
    "openssl": "3.0.13-0ubuntu3.12",
    "python3.12": "3.12.3-1ubuntu0.15",
}
_PACKAGE_NAMES = frozenset(_PACKAGE_VERSIONS)
_PROVISIONING_SCRIPT_DIGEST = (
    "sha256:e3e66da8b31e841910d491f3fdbf94735badce3ee36eceb9241c72003366fd2c"
)
_PACKAGE_SOURCE_ASSETS = {
    "/etc/apt/apt.conf.d/99-harness-m4": "apt-harness-m3.conf",
    "/etc/apt/sources.list.d/ubuntu.sources": "apt-ubuntu.sources",
}
_RUNTIME_CONFIG_ASSETS = {
    "/etc/hosts": "guest-hosts",
    "/etc/harness-m4/nftables-offline.conf": "nftables-offline.conf",
    "/etc/harness-m4/nftables-provisioning.conf": "nftables-provisioning.conf",
}
_RUNTIME_TOOL_DIGESTS = {
    "/usr/bin/aa-exec": "sha256:f28cbce3c8664cab5154492fdbc55ecb937a3e7ce1a9478c881a5f5965d7ce3e",
    "/usr/bin/bwrap": "sha256:52231e1caf55bcbc667b269f49c63599a6f7db4767ae6a039580d0ff853db712",
    "/usr/bin/openssl": "sha256:b86b739329008369aebe1f7cff6c2adb18965609d68a19456fca55232f2908f5",
    "/usr/bin/python3.12": "sha256:1643dacd9feaedc58f3cc581e4d22577dfe25c09b10282936186ccf0f2e61118",
    "/usr/lib/x86_64-linux-gnu/libcrypto.so.3": "sha256:1451aceec262c3338052fa77542eb971d4ba311c6bf12d9aa70d0b56aca942f9",
    "/usr/sbin/apparmor_parser": "sha256:6bc852b37807961c14976be9a227ae96bd817f73b5189cb0e0ff5eca4448c01c",
}
_PACKAGE_SOURCE_PATHS = frozenset(_PACKAGE_SOURCE_ASSETS)
_RUNTIME_CONFIG_PATHS = frozenset(_RUNTIME_CONFIG_ASSETS)
_RUNTIME_TOOL_PATHS = frozenset(_RUNTIME_TOOL_DIGESTS)


def _expected_package_runtime_plan() -> dict[str, object]:
    return {
        "plan_version": "1.0.0",
        "packages": dict(_PACKAGE_VERSIONS),
        "provisioning_script_digest": _PROVISIONING_SCRIPT_DIGEST,
        "package_sources": {
            path: _digest_file(IMAGE_LAB / asset, 1 << 20)
            for path, asset in _PACKAGE_SOURCE_ASSETS.items()
        },
        "runtime_configs": {
            path: _digest_file(IMAGE_LAB / asset, 1 << 20)
            for path, asset in _RUNTIME_CONFIG_ASSETS.items()
        },
        "runtime_tools": dict(_RUNTIME_TOOL_DIGESTS),
    }


def _validate_package_runtime_plan(value: object) -> dict[str, object]:
    plan = _closed(
        value,
        frozenset({
            "plan_version", "packages", "provisioning_script_digest",
            "package_sources", "runtime_configs", "runtime_tools",
        }),
    )
    packages = _closed(plan["packages"], _PACKAGE_NAMES)
    package_sources = _closed(plan["package_sources"], _PACKAGE_SOURCE_PATHS)
    runtime_configs = _closed(plan["runtime_configs"], _RUNTIME_CONFIG_PATHS)
    runtime_tools = _closed(plan["runtime_tools"], _RUNTIME_TOOL_PATHS)
    if (
        plan["plan_version"] != "1.0.0"
        or packages != _PACKAGE_VERSIONS
        or plan != _expected_package_runtime_plan()
    ):
        _invalid("PACKAGE_RUNTIME_PLAN_MISMATCH")
    _digest(plan["provisioning_script_digest"])
    for rows in (package_sources, runtime_configs, runtime_tools):
        for digest in rows.values():
            _digest(digest)
    return plan


def _validate_qualification_contract(
    value: object,
    qualification_contract_digest: object,
    *,
    source: dict[str, object],
    profile_digest: str,
    host_provenance: dict[str, object],
    package_runtime_plan: dict[str, object],
    goal_reference: str,
    goal_digest: str,
) -> tuple[dict[str, object], str, str]:
    contract = _closed(value, _QUALIFICATION_CONTRACT_FIELDS)
    core = _closed(contract["contract_core"], _CONTRACT_CORE_FIELDS)
    preimage = _closed(
        contract["environment_preimage"], _ENVIRONMENT_PREIMAGE_FIELDS
    )
    computed_core_digest = _digest_bytes(_canonical(core))
    computed_environment_digest = _digest_bytes(_canonical(preimage))
    computed_contract_digest = _digest_bytes(_canonical(contract))
    for digest in (
        core["user_goal_digest"], core["source_files_digest"],
        core["canonical_profile_digest"], core["raw_profile_artifact_digest"],
        core["base_image_digest"],
        core["predecessor_qualification_ledger_digest"],
        core["predecessor_diagnostic_ledger_digest"],
        core["predecessor_diagnostic_bundle_digest"],
        contract["contract_core_digest"], preimage["contract_core_digest"],
        preimage["source_archive_digest"], preimage["seed_digest"],
        preimage["package_runtime_plan_digest"],
        preimage["host_provenance_digest"], contract["environment_digest"],
        qualification_contract_digest,
    ):
        _digest(digest)
    files = source.get("files")
    if (
        core["contract_version"] != "2.0.0"
        or core["contract_kind"]
        != "M4_EXACT_DISPOSABLE_TEST_PROFILE_QUALIFICATION_V2"
        or core["user_scope_reference"] != goal_reference
        or core["user_goal_digest"] != goal_digest
        or type(core["candidate"]) is not str
        or _COMMIT.fullmatch(core["candidate"]) is None
        or type(core["tree"]) is not str
        or _COMMIT.fullmatch(core["tree"]) is None
        or _integer(core["attempt"], 1) not in {1, 2}
        or core["candidate"] != source.get("commit")
        or core["tree"] != source.get("tree")
        or core["source_files_digest"] != source.get("files_digest")
        or type(files) is not dict
        or files.get("profiles/m4-lx-a.json") != _PROFILE_DIGEST
        or core["canonical_profile_digest"] != profile_digest
        or core["raw_profile_artifact_digest"] != profile_digest
        or profile_digest != _PROFILE_DIGEST
        or core["base_image_digest"] != _IMAGE_DIGEST
        or core["predecessor_qualification_ledger_digest"]
        != _PREDECESSOR_QUALIFICATION_LEDGER_DIGEST
        or core["predecessor_diagnostic_ledger_digest"]
        != _PREDECESSOR_DIAGNOSTIC_LEDGER_DIGEST
        or core["predecessor_diagnostic_bundle_digest"]
        != _PREDECESSOR_DIAGNOSTIC_BUNDLE_DIGEST
        or core["max_attempts"] != 2
        or core["success_target"] != 1
        or core["success_target_authorizing"] is not False
        or contract["contract_core_digest"] != computed_core_digest
        or preimage["contract_core_digest"] != computed_core_digest
        or preimage["seed_digest"] != host_provenance["vm"]["seed_digest"]
        or preimage["source_archive_digest"] != _source_archive_digest()
        or preimage["package_runtime_plan_digest"]
        != _digest_bytes(_canonical(package_runtime_plan))
        or preimage["host_provenance_digest"]
        != _digest_bytes(_canonical(host_provenance))
        or contract["environment_digest"] != computed_environment_digest
        or qualification_contract_digest != computed_contract_digest
    ):
        _invalid("QUALIFICATION_CONTRACT_MISMATCH")
    return contract, computed_core_digest, computed_contract_digest


_LEDGER_COMMON = frozenset(
    {
        "ledger_version", "sequence", "previous_entry_digest", "entry_type",
        "recorded_at", "candidate", "tree", "environment",
        "user_scope_reference", "user_goal_digest", "max_attempts",
        "success_target", "success_target_authorizing", "attempt",
        "contract_core_digest", "qualification_contract_digest",
    }
)
_LEDGER_EXTRA = {
    "ATTEMPT_STARTED": frozenset({"qualification_contract"}),
    "KEY_ADMITTED": frozenset(
        {
            "attempt_start_digest", "admitted_qualification_contract_digest",
            "receipt_public_key_digests", "supply_public_key_digest",
            "runtime_trust_digest",
        }
    ),
    "ATTEMPT_TERMINAL": frozenset(
        {
            "attempt_start_digest", "key_admission_digest", "result",
            "terminal_reason", "manifest_digest",
            "signed_payload_bundle_digest", "qemu_phase_outcomes",
        }
    ),
}
_TERMINAL_REASON_BY_RESULT = {
    "BUNDLE_EXPORTED": frozenset({"SIGNED_PAYLOAD_EXPORTED"}),
    "FAILED": frozenset({
        "PROVISION_FAILED", "QEMU_EXITED", "SERVICE_FAILED_PRE_KEY_READY",
        "KEY_READY_TIMEOUT", "KEY_ADMISSION_FAILED", "RUN_FAILED",
        "RECOVERY_FAILED", "EVIDENCE_EXPORT_FAILED",
        "EVIDENCE_VERIFICATION_FAILED", "CLEANUP_FAILED",
    }),
    "BLOCKED": frozenset({"HOST_PREFLIGHT_FAILED", "ATTEMPT_LIMIT_REACHED"}),
    "QUARANTINED": frozenset({
        "PROVISION_FAILED", "QEMU_EXITED", "SERVICE_FAILED_PRE_KEY_READY",
        "KEY_READY_TIMEOUT", "KEY_ADMISSION_FAILED", "RUN_FAILED",
        "RECOVERY_FAILED", "EVIDENCE_EXPORT_FAILED",
        "EVIDENCE_VERIFICATION_FAILED", "CLEANUP_FAILED",
    }),
}


def _ledger_entries(
    raw: bytes,
    *,
    now: datetime,
    goal_reference: str,
    goal_digest: str,
) -> list[tuple[dict[str, object], str]]:
    if (
        type(raw) is not bytes
        or not raw
        or len(raw) > 4 << 20
        or not raw.endswith(b"\n")
        or b"\n\n" in raw
    ):
        _invalid("LEDGER_MALFORMED")
    result: list[tuple[dict[str, object], str]] = []
    previous: str | None = None
    for sequence, line in enumerate(raw[:-1].split(b"\n"), 1):
        value = _strict_json(line, 1 << 20)
        if type(value) is not dict or value.get("entry_type") not in _LEDGER_EXTRA:
            _invalid("LEDGER_MALFORMED")
        expected = _LEDGER_COMMON | _LEDGER_EXTRA[str(value["entry_type"])]
        row = _closed(value, expected)
        if (
            row["ledger_version"] != "2.0.0"
            or _integer(row["sequence"], 1) != sequence
            or row["previous_entry_digest"] != previous
            or type(row["candidate"]) is not str
            or _COMMIT.fullmatch(row["candidate"]) is None
            or type(row["tree"]) is not str
            or _COMMIT.fullmatch(row["tree"]) is None
            or _digest(row["environment"]) != row["environment"]
            or row["user_scope_reference"] != goal_reference
            or row["user_goal_digest"] != goal_digest
            or row["max_attempts"] != 2
            or row["success_target"] != 1
            or row["success_target_authorizing"] is not False
            or _integer(row["attempt"], 1) not in {1, 2}
            or _digest(row["contract_core_digest"])
            != row["contract_core_digest"]
            or _digest(row["qualification_contract_digest"])
            != row["qualification_contract_digest"]
        ):
            _invalid("LEDGER_BINDING_MISMATCH")
        _timestamp(row["recorded_at"], now)
        if row["entry_type"] == "ATTEMPT_STARTED":
            contract = _closed(
                row["qualification_contract"], _QUALIFICATION_CONTRACT_FIELDS
            )
            core = _closed(contract["contract_core"], _CONTRACT_CORE_FIELDS)
            preimage = _closed(
                contract["environment_preimage"], _ENVIRONMENT_PREIMAGE_FIELDS
            )
            computed_core_digest = _digest_bytes(_canonical(core))
            computed_contract_digest = _digest_bytes(_canonical(contract))
            if (
                contract["contract_core_digest"] != computed_core_digest
                or preimage["contract_core_digest"] != computed_core_digest
                or contract["environment_digest"]
                != _digest_bytes(_canonical(preimage))
                or row["contract_core_digest"] != computed_core_digest
                or row["qualification_contract_digest"]
                != computed_contract_digest
                or core["candidate"] != row["candidate"]
                or core["tree"] != row["tree"]
                or core["attempt"] != row["attempt"]
                or contract["environment_digest"] != row["environment"]
                or core["user_scope_reference"] != row["user_scope_reference"]
                or core["user_goal_digest"] != row["user_goal_digest"]
                or core["max_attempts"] != row["max_attempts"]
                or core["success_target"] != row["success_target"]
                or core["success_target_authorizing"]
                is not row["success_target_authorizing"]
                or core["contract_version"] != "2.0.0"
                or core["contract_kind"]
                != "M4_EXACT_DISPOSABLE_TEST_PROFILE_QUALIFICATION_V2"
                or core["canonical_profile_digest"] != _PROFILE_DIGEST
                or core["raw_profile_artifact_digest"] != _PROFILE_DIGEST
                or core["base_image_digest"] != _IMAGE_DIGEST
                or core["predecessor_qualification_ledger_digest"]
                != _PREDECESSOR_QUALIFICATION_LEDGER_DIGEST
                or core["predecessor_diagnostic_ledger_digest"]
                != _PREDECESSOR_DIAGNOSTIC_LEDGER_DIGEST
                or core["predecessor_diagnostic_bundle_digest"]
                != _PREDECESSOR_DIAGNOSTIC_BUNDLE_DIGEST
            ):
                _invalid("LEDGER_CONTRACT_MISMATCH")
            for name in (
                "source_files_digest", "canonical_profile_digest",
                "raw_profile_artifact_digest", "base_image_digest",
                "predecessor_qualification_ledger_digest",
                "predecessor_diagnostic_ledger_digest",
                "predecessor_diagnostic_bundle_digest",
            ):
                _digest(core[name])
            for value in preimage.values():
                _digest(value)
        elif row["entry_type"] == "KEY_ADMITTED":
            keys = _closed(
                row["receipt_public_key_digests"],
                frozenset({"M4_AUTHORITY", "OBSERVER", "PUBLISHER"}),
            )
            _digest(row["attempt_start_digest"])
            if (
                row["admitted_qualification_contract_digest"]
                != row["qualification_contract_digest"]
            ):
                _invalid("LEDGER_BINDING_MISMATCH")
            _digest(row["supply_public_key_digest"])
            _digest(row["runtime_trust_digest"])
            for value in keys.values():
                _digest(value)
        elif row["entry_type"] == "ATTEMPT_TERMINAL":
            if row["result"] not in _TERMINAL_REASON_BY_RESULT:
                _invalid("LEDGER_TERMINAL_MISMATCH")
            _digest(row["attempt_start_digest"])
            if row["result"] == "BUNDLE_EXPORTED":
                if row["terminal_reason"] != "SIGNED_PAYLOAD_EXPORTED":
                    _invalid("LEDGER_TERMINAL_MISMATCH")
                for key in (
                    "key_admission_digest", "manifest_digest",
                    "signed_payload_bundle_digest",
                ):
                    _digest(row[key])
                _validate_qemu_phase_outcomes(row["qemu_phase_outcomes"], row["attempt"])
            else:
                if row["terminal_reason"] not in _TERMINAL_REASON_BY_RESULT[row["result"]]:
                    _invalid("LEDGER_TERMINAL_MISMATCH")
                if row["key_admission_digest"] is not None:
                    _digest(row["key_admission_digest"])
                if (
                    row["manifest_digest"] is not None
                    or row["signed_payload_bundle_digest"] is not None
                    or row["qemu_phase_outcomes"] is not None
                ):
                    _invalid("LEDGER_TERMINAL_MISMATCH")
        digest = _digest_bytes(line)
        result.append((row, digest))
        previous = digest
    if not result:
        _invalid("LEDGER_EMPTY")
    qualification_keys = (
        "user_scope_reference", "user_goal_digest", "max_attempts", "success_target",
        "success_target_authorizing",
    )
    qualification = tuple(result[0][0][name] for name in qualification_keys)
    if any(
        tuple(row[name] for name in qualification_keys) != qualification
        for row, _ in result
    ):
        _invalid("LEDGER_LIFECYCLE_MISMATCH")
    cursor = 0
    expected_attempt = 1
    candidate_environment_pairs: set[tuple[object, object]] = set()
    while cursor < len(result):
        start, start_digest = result[cursor]
        pair = (start["candidate"], start["environment"])
        if (
            start["entry_type"] != "ATTEMPT_STARTED"
            or start["attempt"] != expected_attempt
            or expected_attempt > 2
            or pair in candidate_environment_pairs
        ):
            _invalid("ATTEMPT_CEILING_MISMATCH")
        candidate_environment_pairs.add(pair)
        cursor += 1
        key_row: dict[str, object] | None = None
        key_digest: str | None = None
        if cursor < len(result) and result[cursor][0]["entry_type"] == "KEY_ADMITTED":
            key_row, key_digest = result[cursor]
            cursor += 1
        if cursor >= len(result) or result[cursor][0]["entry_type"] != "ATTEMPT_TERMINAL":
            _invalid("LEDGER_LIFECYCLE_MISMATCH")
        terminal, _ = result[cursor]
        cursor += 1
        for row in (() if key_row is None else (key_row,)) + (terminal,):
            for name in (
                "candidate", "tree", "environment", "attempt",
                "contract_core_digest", "qualification_contract_digest",
            ):
                if row[name] != start[name]:
                    _invalid("LEDGER_LIFECYCLE_MISMATCH")
        if (
            terminal["attempt_start_digest"] != start_digest
            or (
                key_row is None
                and terminal["key_admission_digest"] is not None
            )
            or (
                key_row is not None
                and (
                    key_row["attempt_start_digest"] != start_digest
                    or terminal["key_admission_digest"] != key_digest
                )
            )
            or (terminal["result"] == "BUNDLE_EXPORTED" and key_row is None)
        ):
            _invalid("LEDGER_LIFECYCLE_MISMATCH")
        expected_attempt += 1
    return result


def _write_public_key(directory: Path, name: str, pem: str, digest: str) -> Path:
    raw = pem.encode("ascii")
    if _digest_bytes(raw) != digest:
        _invalid("PUBLIC_KEY_DIGEST_MISMATCH")
    path = directory / (name + ".pem")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    try:
        if os.write(descriptor, raw) != len(raw):
            _invalid("PUBLIC_KEY_WRITE_FAILED")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return path


def _verify_signature(
    payload: dict[str, object],
    source: dict[str, object],
    *,
    public_key: Path,
    public_key_digest: str,
    issuer_id: str,
    key_id: str,
    observed_at: str,
    revocation_epoch: int,
    fencing_epoch: int,
    now: datetime,
) -> None:
    source = _closed(source, frozenset({"verifier_id", "issuer_id", "key_id", "proof"}))
    record = {
        "verification_version": 1,
        "verifier_id": source["verifier_id"],
        "issuer_id": source["issuer_id"],
        "key_id": source["key_id"],
        "payload_digest": _digest_bytes(_canonical(payload)),
        "bindings": payload,
        "proof": source["proof"],
    }
    library = LIBCRYPTO.resolve(strict=True)
    verifier = OpenSSLEd25519Verifier(
        verifier_id="harness-m4-openssl-libcrypto/v1",
        issuer_id=issuer_id,
        key_id=key_id,
        public_key_path=str(public_key),
        public_key_digest=public_key_digest,
        libcrypto_path=str(library),
        libcrypto_digest=_digest_file(library, 16 << 20),
        verifier_code_path=str(VERIFIER_CODE),
        verifier_code_digest=_digest_file(VERIFIER_CODE, 1 << 20),
        expected_revocation_epoch=revocation_epoch,
        expected_fencing_epoch=fencing_epoch,
        clock=lambda: now,
    )
    if verifier.verify(_canonical(payload), _canonical(record), observed_at).status is not VerificationStatus.VERIFIED:
        _invalid("SIGNATURE_REJECTED")


def _verification_source_from_record(
    value: object, payload: dict[str, object]
) -> dict[str, object]:
    record = _closed(
        value,
        frozenset({
            "verification_version", "verifier_id", "issuer_id", "key_id",
            "payload_digest", "bindings", "proof",
        }),
    )
    if (
        record["verification_version"] != 1
        or record["bindings"] != payload
        or record["payload_digest"] != _digest_bytes(_canonical(payload))
    ):
        _invalid("VERIFICATION_RECORD_MISMATCH")
    return {
        "verifier_id": record["verifier_id"],
        "issuer_id": record["issuer_id"],
        "key_id": record["key_id"],
        "proof": record["proof"],
    }


def _validate_role_facts(state: dict[str, object], profile: dict[str, object]) -> None:
    execution = state["execution"]
    rows = {
        "CONTROLLER": execution["controller_facts"],
        "PUBLISHER": execution["publisher_facts"],
        "EXECUTOR": execution["executor_facts"][0],
        "OBSERVER": execution["observer_facts"][0],
    }
    for role, facts in rows.items():
        expected = profile["roles"][role]
        if type(facts) is not dict or facts.get("role") != role:
            _invalid("PRINCIPAL_FACTS_MISMATCH")
        uid = facts.get("uid") if role == "CONTROLLER" else facts.get("launcher_uid")
        gid = facts.get("gid") if role == "CONTROLLER" else facts.get("launcher_gid")
        if (
            uid != expected["uid"]
            or gid != expected["gid"]
            or facts.get("label") != expected["security_label"]
            or facts.get("fd_inventory") != expected["fd_allowlist"]
            or type(facts.get("cgroup")) is not str
            or not facts["cgroup"]
        ):
            _invalid("PRINCIPAL_FACTS_MISMATCH")


def _validate_events(
    state: dict[str, object],
    profile: dict[str, object],
    public_paths: dict[str, Path],
    now: datetime,
) -> None:
    events = state["execution"]["runtime_events"]
    expected_types = (
        "M4_RUNTIME_PREFLIGHT", "TCB_STAGE", "TCB_POSTCHECK",
        "TCB_PUBLICATION", "PRE_COMMIT", "PRE_JOIN",
    )
    event_keys = {
        "M4_RUNTIME_PREFLIGHT": frozenset({"type", "payload", "verification_source"}),
        "TCB_STAGE": frozenset({
            "type", "pid", "session", "stage_authorization_digest",
            "target_binding", "grant_payload", "grant_verification",
            "grant_payload_digest", "grant_verification_digest",
        }),
        "TCB_POSTCHECK": frozenset({
            "type", "pid", "session", "receipt", "verification_source",
        }),
        "TCB_PUBLICATION": frozenset({"type", "receipt", "verification_source"}),
        "PRE_COMMIT": frozenset({"type", "payload", "verification_source"}),
        "PRE_JOIN": frozenset({"type", "payload", "verification_source"}),
    }
    if (
        type(events) is not list
        or len(events) != len(expected_types)
        or any(type(row) is not dict for row in events)
        or tuple(row.get("type") for row in events) != expected_types
    ):
        _invalid("RUNTIME_EVENT_SET_MISMATCH")
    durable = state["durable"]["m4_recovery"]
    publication = state["publication"]
    routes = {
        "M4_RUNTIME_PREFLIGHT": "M4_AUTHORITY",
        "TCB_POSTCHECK": "OBSERVER",
        "TCB_PUBLICATION": "PUBLISHER",
        "PRE_COMMIT": "PUBLISHER",
        "PRE_JOIN": "PUBLISHER",
    }
    for untrusted_event in events:
        event_type = untrusted_event["type"]
        event = _closed(untrusted_event, event_keys[event_type])
        if event_type == "TCB_STAGE":
            grant = _closed(
                event["grant_payload"],
                frozenset({
                    "record_type", "authorization", "authorization_verification",
                    "consumption",
                }),
            )
            authorization = _closed(
                grant["authorization"],
                frozenset({
                    "authorization_version", "transaction_id", "claim_digest",
                    "intent_digest", "capability_id", "contract_digest",
                    "d2_frontier_digest", "iteration", "target_authority_digest",
                    "target_binding", "publication_target_binding_digest",
                    "publication_root_anchor_digest", "profile_digest",
                    "placement_digest", "session_id", "revocation_epoch",
                    "fencing_epoch", "issued_at", "expires_at",
                    "authorization_digest",
                }),
            )
            consumption = _closed(
                grant["consumption"],
                frozenset({
                    "consumption_version", "transaction_id",
                    "stage_authorization_digest", "claim_digest", "intent_digest",
                    "capability_id", "contract_digest", "d2_frontier_digest",
                    "iteration", "target_authority_digest", "target_binding",
                    "profile_digest", "placement_digest", "session_id",
                    "revocation_epoch", "fencing_epoch", "consumed_at", "expires_at",
                }),
            )
            authorization_body = {
                key: value
                for key, value in authorization.items()
                if key != "authorization_digest"
            }
            authorization_payload = {
                "record_type": "M4_STAGE_AUTHORIZATION",
                "authorization": authorization,
            }
            authorization_source = _verification_source_from_record(
                grant["authorization_verification"], authorization_payload
            )
            grant_source = _verification_source_from_record(
                event["grant_verification"], grant
            )
            issued_at = _parse_timestamp(authorization["issued_at"])
            consumed_at = _parse_timestamp(consumption["consumed_at"])
            expires_at = _parse_timestamp(authorization["expires_at"])
            preflight = events[0]["payload"]
            if (
                type(preflight) is not dict
                or grant["record_type"] != "M4_STAGE_EXECUTION_GRANT"
                or authorization["authorization_version"] != 1
                or consumption["consumption_version"] != 1
                or authorization["authorization_digest"]
                != _digest_bytes(_canonical(authorization_body))
                or event["stage_authorization_digest"]
                != authorization["authorization_digest"]
                or consumption["stage_authorization_digest"]
                != authorization["authorization_digest"]
                or event["target_binding"] != authorization["target_binding"]
                or consumption["target_binding"] != authorization["target_binding"]
                or event["grant_payload_digest"] != _digest_bytes(_canonical(grant))
                or event["grant_verification_digest"]
                != _digest_bytes(_canonical(event["grant_verification"]))
                or type(event["pid"]) is not int
                or event["pid"] < 2
                or type(event["session"]) is not int
                or event["session"] < 1
                or authorization["transaction_id"] != durable["transaction_id"]
                or authorization["contract_digest"] != durable["contract_digest"]
                or authorization["d2_frontier_digest"] != durable["d2_frontier_digest"]
                or authorization["iteration"] != durable["iteration"]
                or authorization["revocation_epoch"] != durable["revocation_epoch"]
                or authorization["fencing_epoch"] != durable["fencing_epoch"]
                or authorization["claim_digest"]
                != state["durable"]["m3_runtime_session"]["claim_digest"]
                or authorization["target_authority_digest"] != publication["topology_digest"]
                or authorization["publication_target_binding_digest"]
                != publication["target_binding"]["composite_binding_digest"]
                or authorization["publication_root_anchor_digest"]
                != publication["root_anchor"]["anchor_digest"]
                or authorization["profile_digest"] != state["trust"]["profile_digest"]
                or authorization["placement_digest"] != preflight.get("placement_digest")
                or authorization["session_id"] != preflight.get("session_id")
                or consumption["expires_at"] != authorization["expires_at"]
                or any(
                    consumption[name] != authorization[name]
                    for name in (
                        "transaction_id", "claim_digest", "intent_digest",
                        "capability_id", "contract_digest", "d2_frontier_digest",
                        "iteration", "target_authority_digest", "profile_digest",
                        "placement_digest", "session_id", "revocation_epoch",
                        "fencing_epoch",
                    )
                )
                or not issued_at <= consumed_at < expires_at
            ):
                _invalid("STAGE_EVENT_MISMATCH")
            authority_key = profile["receipt_keys"]["M4_AUTHORITY"]
            for payload, source in (
                (authorization_payload, authorization_source),
                (grant, grant_source),
            ):
                _verify_signature(
                    payload,
                    source,
                    public_key=public_paths["M4_AUTHORITY"],
                    public_key_digest=state["trust"]["receipt_public_key_digests"][
                        "M4_AUTHORITY"
                    ],
                    issuer_id=authority_key["issuer_id"],
                    key_id=authority_key["key_id"],
                    observed_at=consumption["consumed_at"],
                    revocation_epoch=durable["revocation_epoch"],
                    fencing_epoch=durable["fencing_epoch"],
                    now=now,
                )
            continue
        payload_name = "receipt" if event_type in {"TCB_POSTCHECK", "TCB_PUBLICATION"} else "payload"
        payload = event.get(payload_name)
        source = event.get("verification_source")
        if type(payload) is not dict or type(source) is not dict:
            _invalid("SIGNED_EVENT_MALFORMED")
        for key, expected in (
            ("transaction_id", durable["transaction_id"]),
            ("revocation_epoch", durable["revocation_epoch"]),
            ("fencing_epoch", durable["fencing_epoch"]),
        ):
            if payload.get(key) != expected:
                _invalid("SIGNED_EVENT_BINDING_MISMATCH")
        for key, expected in (
            ("contract_digest", durable["contract_digest"]),
            ("d2_frontier_digest", durable["d2_frontier_digest"]),
            ("attempt_cursor", durable["iteration"]),
            ("iteration", durable["iteration"]),
            ("publication_target_binding_digest", publication["target_binding"]["composite_binding_digest"]),
            ("publication_root_anchor_digest", publication["root_anchor"]["anchor_digest"]),
            ("snapshot_digest", publication["snapshot_digest"]),
        ):
            if key in payload and payload[key] != expected:
                _invalid("SIGNED_EVENT_BINDING_MISMATCH")
        body = {key: value for key, value in payload.items() if key != "receipt_digest"}
        if "receipt_digest" in payload and payload["receipt_digest"] != _digest_bytes(_canonical(body)):
            _invalid("RECEIPT_DIGEST_MISMATCH")
        role = routes[event_type]
        key_row = profile["receipt_keys"][role]
        observed_at = payload.get("observed_at")
        if type(observed_at) is not str:
            _invalid("SIGNED_EVENT_TIME_MISSING")
        _verify_signature(
            payload, source, public_key=public_paths[role],
            public_key_digest=state["trust"]["receipt_public_key_digests"][role],
            issuer_id=key_row["issuer_id"], key_id=key_row["key_id"],
            observed_at=observed_at,
            revocation_epoch=durable["revocation_epoch"],
            fencing_epoch=durable["fencing_epoch"], now=now,
        )
    denials = state["execution"]["denial_events"]
    denial_keys = frozenset({
        "point", "errno", "principal", "root_device", "root_inode",
        "git_destination_absent", "pause",
    })
    if (
        type(denials) is not list
        or len(denials) != 2
        or any(type(row) is not dict for row in denials)
        or [row.get("point") for row in denials]
        != ["AFTER_PRE_REPLACE_CHECKS", "AFTER_PRE_JOIN"]
    ):
        _invalid("PHYSICAL_DENIAL_EVIDENCE_MISMATCH")
    ancestry = publication["root_anchor"].get("ancestry")
    if type(ancestry) is not list or not ancestry or type(ancestry[-1]) is not dict:
        _invalid("PHYSICAL_DENIAL_EVIDENCE_MISMATCH")
    root_device = ancestry[-1].get("device")
    root_inode = ancestry[-1].get("inode")
    controller = profile["roles"]["CONTROLLER"]
    for untrusted_row in denials:
        row = _closed(untrusted_row, denial_keys)
        principal = _closed(
            row["principal"],
            frozenset({
                "role", "pid", "uid", "gid", "session", "label", "cgroup",
                "fd_inventory", "namespaces", "capabilities", "no_new_privs",
            }),
        )
        namespaces = _closed(
            principal["namespaces"],
            frozenset({"user", "mnt", "pid", "ipc", "uts", "net", "cgroup"}),
        )
        capabilities = _closed(
            principal["capabilities"], frozenset({"CapInh", "CapPrm", "CapEff"})
        )
        expected_pause = (
            {
                "anchor_digest": publication["root_anchor"]["anchor_digest"],
                "binding_digest": publication["target_binding"]["composite_binding_digest"],
            }
            if row["point"] == "AFTER_PRE_REPLACE_CHECKS"
            else {}
        )
        if (
            row["errno"] not in {1, 13}
            or row["git_destination_absent"] is not True
            or type(root_device) is not int
            or type(root_inode) is not int
            or root_device < 1
            or root_inode < 1
            or row["root_device"] != root_device
            or row["root_inode"] != root_inode
            or row["pause"] != expected_pause
            or principal["role"] != "CONTROLLER"
            or principal["uid"] != controller["uid"]
            or principal["gid"] != controller["gid"]
            or principal["label"] != controller["security_label"]
            or principal["fd_inventory"] != [0, 1, 2]
            or type(principal["pid"]) is not int
            or principal["pid"] < 1
            or type(principal["session"]) is not int
            or principal["session"] < 1
            or type(principal["cgroup"]) is not str
            or not principal["cgroup"]
            or principal["no_new_privs"] != 1
            or any(type(value) is not str or not value for value in namespaces.values())
            or any(value != "0000000000000000" for value in capabilities.values())
        ):
            _invalid("PHYSICAL_DENIAL_EVIDENCE_MISMATCH")


def _validate_state(state: object, profile: dict[str, object]) -> dict[str, object]:
    state = _closed(
        state,
        frozenset({"record_version", "phase", "identity", "trust", "durable", "publication", "execution"}),
    )
    identity = _closed(
        state["identity"],
        frozenset({
            "candidate", "environment", "attempt", "boot_id", "guest", "source",
            "host_provenance", "qualification_contract",
            "qualification_contract_digest", "package_runtime_plan",
        }),
    )
    trust = _closed(
        state["trust"],
        frozenset({
            "profile_digest", "m4_apparmor_digest", "m3_apparmor_digest",
            "runtime_trust_digest", "key_admission", "receipt_public_key_digests",
            "supply_public_key_digest", "verifier", "revocation_epoch", "fencing_epoch",
        }),
    )
    durable = _closed(state["durable"], frozenset({"m4_recovery", "m3_runtime_session"}))
    recovery = _closed(
        durable["m4_recovery"],
        frozenset({
            "transaction_id", "state", "contract_digest", "d2_frontier_digest",
            "fencing_epoch", "record_digest", "frontier_record_digest", "iteration",
            "frontier_attempt_cursor", "frontier_joined_iteration", "attempt_cursor",
            "joined_iteration", "journal_sequence", "intent_state", "revocation_epoch",
            "resume_allowed", "retry_allowed",
        }),
    )
    session = _closed(
        durable["m3_runtime_session"],
        frozenset({"session_record_id", "transaction_id", "claim_digest", "state", "fencing_epoch"}),
    )
    publication = _closed(
        state["publication"],
        frozenset({
            "root", "topology_digest", "root_anchor", "target_binding",
            "published_binding", "artifact_digest", "snapshot_digest", "transport",
        }),
    )
    execution = _closed(
        state["execution"],
        frozenset({
            "controller_facts", "publisher_facts", "executor_facts", "observer_facts",
            "runtime_events", "denial_events", "role_seccomp_digests",
            "m3_role_seccomp", "cleanup",
        }),
    )
    verifier = _closed(
        trust["verifier"],
        frozenset({
            "backend", "code_digest", "libcrypto_path", "libcrypto_digest",
            "independent_cryptographic_implementations",
        }),
    )
    for name, minimum in (
        ("fencing_epoch", 0),
        ("iteration", 1),
        ("frontier_attempt_cursor", 0),
        ("frontier_joined_iteration", 0),
        ("attempt_cursor", 1),
        ("joined_iteration", 0),
        ("journal_sequence", 1),
        ("revocation_epoch", 0),
    ):
        _integer(recovery[name], minimum)
    _integer(session["fencing_epoch"], 0)
    if (
        state["record_version"] != "1.0.0"
        or state["phase"] != "PRE_RESTART_PASS"
        or type(identity["candidate"]) is not str
        or _COMMIT.fullmatch(identity["candidate"]) is None
        or _digest(identity["environment"]) != identity["environment"]
        or _integer(identity["attempt"], 1) not in {1, 2}
        or type(identity["boot_id"]) is not str
        or _UUID.fullmatch(identity["boot_id"]) is None
        or type(identity["source"]) is not dict
        or identity["source"].get("commit") != identity["candidate"]
        or type(identity["qualification_contract"]) is not dict
        or _digest(identity["qualification_contract_digest"])
        != identity["qualification_contract_digest"]
        or type(identity["package_runtime_plan"]) is not dict
        or _digest(trust["profile_digest"]) != trust["profile_digest"]
        or _digest(trust["m4_apparmor_digest"]) != trust["m4_apparmor_digest"]
        or trust["m3_apparmor_digest"] != _digest_file(M3_APPARMOR, 1 << 20)
        or _digest(trust["runtime_trust_digest"]) != trust["runtime_trust_digest"]
        or trust["revocation_epoch"] != 0
        or trust["fencing_epoch"] != 1
        or verifier["backend"] != "OPENSSL_LIBCRYPTO_SHARED"
        or verifier["code_digest"] != _digest_file(VERIFIER_CODE, 1 << 20)
        or verifier["libcrypto_path"] != str(LIBCRYPTO)
        or verifier["libcrypto_digest"] != _digest_file(LIBCRYPTO.resolve(strict=True), 16 << 20)
        or verifier["independent_cryptographic_implementations"] is not False
        or recovery["state"] != "JOINED"
        or recovery["intent_state"] != "SPENT"
        or recovery["fencing_epoch"] != trust["fencing_epoch"]
        or recovery["revocation_epoch"] != trust["revocation_epoch"]
        or recovery["resume_allowed"] is not False
        or recovery["retry_allowed"] is not False
        or _integer(recovery["iteration"], 1) != recovery["attempt_cursor"]
        or recovery["joined_iteration"] != recovery["iteration"]
        or recovery["frontier_attempt_cursor"] != recovery["iteration"] - 1
        or recovery["frontier_joined_iteration"] > recovery["frontier_attempt_cursor"]
        or session["transaction_id"] != recovery["transaction_id"]
        or session["fencing_epoch"] != recovery["fencing_epoch"]
        or session["state"] != "STOPPED"
        or publication["transport"] != "SEALED_FD_ONLY"
        or publication["artifact_digest"] != publication["snapshot_digest"]
        or publication["published_binding"].get("final_digest") != publication["artifact_digest"]
        or type(execution["executor_facts"]) is not list
        or len(execution["executor_facts"]) != 1
        or type(execution["observer_facts"]) is not list
        or len(execution["observer_facts"]) != 1
    ):
        _invalid("RUN_STATE_MISMATCH")
    for name in (
        "contract_digest", "d2_frontier_digest", "record_digest", "frontier_record_digest"
    ):
        _digest(recovery[name])
    _digest(session["claim_digest"])
    for name in ("topology_digest", "artifact_digest", "snapshot_digest"):
        _digest(publication[name])
    for name in ("root_anchor", "target_binding", "published_binding"):
        if type(publication[name]) is not dict:
            _invalid("PUBLICATION_BINDING_MISMATCH")
    _digest(publication["root_anchor"].get("anchor_digest"))
    _digest(publication["target_binding"].get("composite_binding_digest"))
    _digest(publication["published_binding"].get("composite_binding_digest"))
    _validate_role_facts(state, profile)
    return state


def _validate_recovery(
    value: object, state: dict[str, object], profile: dict[str, object]
) -> None:
    recovery = _closed(
        value,
        frozenset({
            "recovery_version", "previous_boot_id", "current_boot_id", "durable",
            "survival", "publication", "controller_facts", "source_reverified",
            "host_provenance_reverified", "trust_reverified",
            "qualification_contract", "qualification_contract_digest",
        }),
    )
    durable = _closed(
        recovery["durable"],
        frozenset({"m4_recovery", "m3_runtime_session", "old_session_resumed", "retry_created"}),
    )
    survival = _closed(
        recovery["survival"],
        frozenset({"recorded_process_ids", "live_process_ids", "recorded_cgroups", "surviving_cgroups"}),
    )
    publication = _closed(
        recovery["publication"],
        frozenset({
            "descriptor_identity", "artifact_device", "artifact_inode", "artifact_size",
            "artifact_digest", "git_destination_absent",
        }),
    )
    descriptor_identity = _closed(
        publication["descriptor_identity"], frozenset({"root_device", "root_inode"})
    )
    observed_process_ids: set[int] = set()
    observed_cgroups: set[str] = set()

    def visit_runtime(item: object) -> None:
        if type(item) is dict:
            for key, nested in item.items():
                if key in {"pid", "process_id"} and type(nested) is int and nested > 1:
                    observed_process_ids.add(nested)
                elif key == "cgroup" and type(nested) is str and nested.startswith("/"):
                    observed_cgroups.add(nested)
                visit_runtime(nested)
        elif type(item) is list:
            for nested in item:
                visit_runtime(nested)

    visit_runtime(state["execution"])
    recorded_process_ids = survival["recorded_process_ids"]
    recorded_cgroups = survival["recorded_cgroups"]
    controller_facts = recovery["controller_facts"]
    expected_controller = profile["roles"]["CONTROLLER"]
    if type(controller_facts) is not dict:
        _invalid("RECOVERY_MISMATCH")
    root_ancestry = state["publication"]["root_anchor"].get("ancestry")
    published = state["publication"]["published_binding"]
    if (
        recovery["recovery_version"] != "1.0.0"
        or recovery["qualification_contract"]
        != state["identity"]["qualification_contract"]
        or recovery["qualification_contract_digest"]
        != state["identity"]["qualification_contract_digest"]
        or recovery["previous_boot_id"] != state["identity"]["boot_id"]
        or type(recovery["current_boot_id"]) is not str
        or _UUID.fullmatch(recovery["current_boot_id"]) is None
        or recovery["current_boot_id"] == recovery["previous_boot_id"]
        or durable["m4_recovery"] != state["durable"]["m4_recovery"]
        or durable["m3_runtime_session"] != state["durable"]["m3_runtime_session"]
        or durable["old_session_resumed"] is not False
        or durable["retry_created"] is not False
        or type(recorded_process_ids) is not list
        or any(type(pid) is not int or pid < 2 for pid in recorded_process_ids)
        or recorded_process_ids != sorted(observed_process_ids)
        or type(recorded_cgroups) is not list
        or any(type(path) is not str or not path.startswith("/") for path in recorded_cgroups)
        or recorded_cgroups != sorted(observed_cgroups)
        or survival["live_process_ids"] != []
        or survival["surviving_cgroups"] != []
        or type(root_ancestry) is not list
        or not root_ancestry
        or type(root_ancestry[-1]) is not dict
        or _integer(descriptor_identity["root_device"], 1) != root_ancestry[-1].get("device")
        or _integer(descriptor_identity["root_inode"], 1) != root_ancestry[-1].get("inode")
        or _integer(publication["artifact_device"], 1) != published.get("final_device")
        or _integer(publication["artifact_inode"], 1) != published.get("final_inode")
        or _integer(publication["artifact_size"], 1) > 1 << 20
        or publication["artifact_digest"] != state["publication"]["artifact_digest"]
        or publication["git_destination_absent"] is not True
        or controller_facts.get("role") != "CONTROLLER"
        or controller_facts.get("uid") != expected_controller["uid"]
        or controller_facts.get("gid") != expected_controller["gid"]
        or controller_facts.get("label") != expected_controller["security_label"]
        or controller_facts.get("fd_inventory") != expected_controller["fd_allowlist"]
        or type(controller_facts.get("cgroup")) is not str
        or not controller_facts["cgroup"]
        or recovery["source_reverified"] is not True
        or recovery["host_provenance_reverified"] is not True
        or recovery["trust_reverified"] is not True
    ):
        _invalid("RECOVERY_MISMATCH")


def _verify_bundle(
    bundle: Path,
    *,
    source_state: dict[str, object] | None = None,
    now: datetime | None = None,
    goal_reference: str = str(USER_GOAL),
    goal_digest: str | None = None,
    host_assets: Path | None = None,
) -> dict[str, object]:
    verification_time = (datetime.now(UTC) if now is None else now).astimezone(UTC).replace(microsecond=0)
    try:
        bundle_descriptor = os.open(
            bundle,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
    except OSError as error:
        raise _InvalidEvidence("BUNDLE_UNAVAILABLE") from error
    try:
        directory = os.fstat(bundle_descriptor)
        if (
            not stat.S_ISDIR(directory.st_mode)
            or stat.S_IMODE(directory.st_mode) != 0o700
            or directory.st_uid != os.getuid()
        ):
            _invalid("UNTRUSTED_BUNDLE_DIRECTORY")
        if frozenset(os.listdir(bundle_descriptor)) != _BUNDLE_FILES:
            _invalid("BUNDLE_FILE_SET_MISMATCH")
        manifest_bytes = _read_regular_at(
            bundle_descriptor, "manifest.json", 1 << 20,
            mode=0o444, owner=os.getuid(),
        )
        signature = _read_regular_at(
            bundle_descriptor, "manifest.sig", 128,
            mode=0o444, owner=os.getuid(),
        )
        evidence_bytes = _read_regular_at(
            bundle_descriptor, "evidence.json", 8 << 20,
            mode=0o444, owner=os.getuid(),
        )
        ledger_bytes = _read_regular_at(
            bundle_descriptor, "attempt-ledger.jsonl", 4 << 20,
            mode=0o444, owner=os.getuid(),
        )
        after_directory = os.fstat(bundle_descriptor)
        if (
            frozenset(os.listdir(bundle_descriptor)) != _BUNDLE_FILES
            or (after_directory.st_dev, after_directory.st_ino, after_directory.st_mode)
            != (directory.st_dev, directory.st_ino, directory.st_mode)
        ):
            _invalid("BUNDLE_FILE_SET_MISMATCH")
    finally:
        os.close(bundle_descriptor)
    if len(signature) != 64:
        _invalid("SIGNATURE_LENGTH_MISMATCH")
    manifest = _closed(
        _strict_json(manifest_bytes, 1 << 20),
        frozenset({
            "bundle_version", "claim", "outcome", "status", "candidate",
            "environment", "attempt", "source", "host_provenance", "profile",
            "attempt_ledger", "durable", "attestation", "evidence",
            "qualification_contract", "qualification_contract_digest",
            "admission_digest", "package_runtime_plan",
        }),
    )
    evidence = _closed(
        _strict_json(evidence_bytes, 8 << 20),
        frozenset({
            "bundle_version", "evidence_version", "claim", "scope", "run_state",
            "run_state_digest", "recovery", "public_keys", "residual_risk",
            "qualification_contract", "qualification_contract_digest",
            "admission_digest", "package_runtime_plan",
        }),
    )
    profile_bytes = _read_regular(PROFILE, 1 << 20)
    profile = _strict_json(profile_bytes, 1 << 20)
    profile_digest = _digest_bytes(profile_bytes)
    if (
        type(profile) is not dict
        or len(profile_bytes) != 2698
        or profile_digest != _PROFILE_DIGEST
    ):
        _invalid("PROFILE_MALFORMED")
    state = _validate_state(evidence["run_state"], profile)
    host_provenance = _validate_host_provenance(
        state["identity"]["host_provenance"], state["identity"]["attempt"]
    )
    package_runtime_plan = _validate_package_runtime_plan(
        state["identity"]["package_runtime_plan"]
    )
    if (
        manifest["qualification_contract"]
        != evidence["qualification_contract"]
        or manifest["qualification_contract"]
        != state["identity"]["qualification_contract"]
        or manifest["qualification_contract_digest"]
        != evidence["qualification_contract_digest"]
        or manifest["qualification_contract_digest"]
        != state["identity"]["qualification_contract_digest"]
        or manifest["package_runtime_plan"] != package_runtime_plan
        or evidence["package_runtime_plan"] != package_runtime_plan
    ):
        _invalid("QUALIFICATION_CONTRACT_PROJECTION_MISMATCH")
    source = _validate_source_projection(
        _source_state() if source_state is None else source_state
    )
    expected_goal_digest = (
        goal_digest
        if goal_digest is not None
        else _digest_file(USER_GOAL, 1 << 20)
    )
    qualification_contract, contract_core_digest, qualification_contract_digest = (
        _validate_qualification_contract(
            manifest["qualification_contract"],
            manifest["qualification_contract_digest"],
            source=source,
            profile_digest=profile_digest,
            host_provenance=host_provenance,
            package_runtime_plan=package_runtime_plan,
            goal_reference=goal_reference,
            goal_digest=expected_goal_digest,
        )
    )
    core = qualification_contract["contract_core"]
    if (
        state["identity"]["environment"]
        != qualification_contract["environment_digest"]
        or state["identity"]["candidate"] != core["candidate"]
        or state["identity"]["attempt"] != core["attempt"]
    ):
        _invalid("ENVIRONMENT_MISMATCH")
    if host_assets is not None:
        _verify_retained_host_assets(host_assets)
    admission = _closed(
        state["trust"]["key_admission"],
        frozenset({
            "admission_version", "mode", "ledger_entry_digest",
            "receipt_public_key_digests",
            "supply_public_key_digest", "runtime_trust_digest",
            "qualification_contract", "qualification_contract_digest",
            "contract_core_digest",
        }),
    )
    rows = _ledger_entries(
        ledger_bytes, now=verification_time, goal_reference=goal_reference,
        goal_digest=expected_goal_digest,
    )
    row_by_digest = {digest: row for row, digest in rows}
    selected = row_by_digest.get(admission["ledger_entry_digest"])
    if type(selected) is not dict or selected.get("entry_type") != "KEY_ADMITTED":
        _invalid("LEDGER_ADMISSION_ABSENT")
    start = row_by_digest.get(selected["attempt_start_digest"])
    if type(start) is not dict or start.get("entry_type") != "ATTEMPT_STARTED":
        _invalid("LEDGER_ATTEMPT_ABSENT")
    for key, expected in (
        ("candidate", core["candidate"]),
        ("tree", core["tree"]),
        ("environment", qualification_contract["environment_digest"]),
        ("attempt", core["attempt"]),
        ("contract_core_digest", contract_core_digest),
        ("qualification_contract_digest", qualification_contract_digest),
    ):
        if selected[key] != expected or start[key] != expected:
            _invalid("LEDGER_ADMISSION_MISMATCH")
    if (
        admission["admission_version"] != "2.0.0"
        or admission["mode"] != "HOST_ATTEMPT_LEDGER_PIN_BEFORE_WORKER_GATE"
        or admission["qualification_contract"] != qualification_contract
        or admission["qualification_contract_digest"]
        != qualification_contract_digest
        or admission["contract_core_digest"] != contract_core_digest
        or start["qualification_contract"] != qualification_contract
        or start["tree"] != state["identity"]["source"].get("tree")
        or selected["admitted_qualification_contract_digest"]
        != qualification_contract_digest
        or selected["receipt_public_key_digests"] != admission["receipt_public_key_digests"]
        or selected["supply_public_key_digest"] != admission["supply_public_key_digest"]
        or selected["runtime_trust_digest"] != admission["runtime_trust_digest"]
        or admission["receipt_public_key_digests"]
        != state["trust"]["receipt_public_key_digests"]
        or admission["supply_public_key_digest"]
        != state["trust"]["supply_public_key_digest"]
        or admission["runtime_trust_digest"] != state["trust"]["runtime_trust_digest"]
    ):
        _invalid("LEDGER_ADMISSION_MISMATCH")
    terminals = [
        row for row, _ in rows
        if row["entry_type"] == "ATTEMPT_TERMINAL"
        and row["key_admission_digest"] == admission["ledger_entry_digest"]
    ]
    file_digests = {
        "attempt-ledger.jsonl": _digest_bytes(ledger_bytes),
        "evidence.json": _digest_bytes(evidence_bytes),
        "manifest.json": _digest_bytes(manifest_bytes),
        "manifest.sig": _digest_bytes(signature),
    }
    signed_payload_bundle_digest = _closed_file_digest(
        {name: file_digests[name] for name in _SIGNED_PAYLOAD_FILES},
        _SIGNED_PAYLOAD_FILES,
    )
    aggregate_bundle_digest = _closed_file_digest(file_digests, _BUNDLE_FILES)
    if (
        len(terminals) != 1
        or terminals[0] is not rows[-1][0]
        or terminals[0]["result"] != "BUNDLE_EXPORTED"
        or terminals[0]["terminal_reason"] != "SIGNED_PAYLOAD_EXPORTED"
        or terminals[0]["manifest_digest"] != file_digests["manifest.json"]
        or terminals[0]["signed_payload_bundle_digest"]
        != signed_payload_bundle_digest
        or terminals[0]["contract_core_digest"] != contract_core_digest
        or terminals[0]["qualification_contract_digest"]
        != qualification_contract_digest
    ):
        _invalid("LEDGER_TERMINAL_MISMATCH")
    supply_key = _closed(
        _closed(evidence["public_keys"], frozenset({"receipts", "supply_attestor"}))["supply_attestor"],
        frozenset({"digest", "pem"}),
    )
    receipts = _closed(
        evidence["public_keys"]["receipts"],
        frozenset({"M4_AUTHORITY", "OBSERVER", "PUBLISHER"}),
    )
    receipt_rows = {
        role: _closed(row, frozenset({"digest", "pem"}))
        for role, row in receipts.items()
    }
    if (
        type(supply_key["pem"]) is not str
        or supply_key["digest"] != admission["supply_public_key_digest"]
        or any(
            type(row["pem"]) is not str
            or row["digest"] != state["trust"]["receipt_public_key_digests"][role]
            for role, row in receipt_rows.items()
        )
    ):
        _invalid("PUBLIC_KEY_DIGEST_MISMATCH")
    with tempfile.TemporaryDirectory(prefix="harness-m4-verifier-") as directory_name:
        directory_path = Path(directory_name)
        supply_path = _write_public_key(
            directory_path, "supply", supply_key["pem"],
            admission["supply_public_key_digest"],
        )
        public_paths = {
            role: _write_public_key(
                directory_path, role.lower(), row["pem"],
                state["trust"]["receipt_public_key_digests"][role],
            )
            for role, row in receipt_rows.items()
        }
        attestation = _closed(
            manifest["attestation"],
            frozenset({
                "trust_root_id", "signer_id", "key_id", "algorithm",
                "public_key_digest", "issued_at", "expires_at", "revocation_epoch",
                "fencing_epoch", "rollback_floor", "nonce",
            }),
        )
        issued = _timestamp(attestation["issued_at"], verification_time)
        expires = _parse_timestamp(attestation["expires_at"])
        supply_profile = profile["supply_trust"]
        if (
            attestation["trust_root_id"] != supply_profile["trust_root_id"]
            or attestation["signer_id"] != supply_profile["signer_id"]
            or attestation["key_id"] != supply_profile["key_id"]
            or attestation["algorithm"] != "ED25519"
            or attestation["public_key_digest"] != admission["supply_public_key_digest"]
            or attestation["revocation_epoch"] != 0
            or attestation["fencing_epoch"] != 1
            or attestation["rollback_floor"] != 1
            or not issued < expires
            or not verification_time < expires
            or expires - issued > timedelta(days=1)
            or attestation["nonce"]
            != "m4-evidence-" + str(evidence["recovery"]["current_boot_id"]).replace("-", "")
        ):
            _invalid("ATTESTATION_MISMATCH")
        final_source = {
            "verifier_id": "harness-m3-external-verifier/v1",
            "issuer_id": attestation["signer_id"],
            "key_id": attestation["key_id"],
            "proof": "ed25519:" + signature.hex(),
        }
        # Final attestation uses the M3 route ID but the same pinned libcrypto verifier.
        record = {
            "verification_version": 1,
            "verifier_id": final_source["verifier_id"],
            "issuer_id": final_source["issuer_id"],
            "key_id": final_source["key_id"],
            "payload_digest": _digest_bytes(manifest_bytes),
            "bindings": manifest,
            "proof": final_source["proof"],
        }
        library = LIBCRYPTO.resolve(strict=True)
        final_verifier = OpenSSLEd25519Verifier(
            verifier_id=final_source["verifier_id"],
            issuer_id=final_source["issuer_id"], key_id=final_source["key_id"],
            public_key_path=str(supply_path),
            public_key_digest=attestation["public_key_digest"],
            libcrypto_path=str(library),
            libcrypto_digest=_digest_file(library, 16 << 20),
            verifier_code_path=str(VERIFIER_CODE),
            verifier_code_digest=_digest_file(VERIFIER_CODE, 1 << 20),
            expected_revocation_epoch=0, expected_fencing_epoch=1,
            clock=lambda: verification_time,
        )
        if final_verifier.verify(manifest_bytes, _canonical(record), attestation["issued_at"]).status is not VerificationStatus.VERIFIED:
            _invalid("MANIFEST_SIGNATURE_REJECTED")
        _validate_events(state, profile, public_paths, verification_time)
    profile_row = _closed(
        manifest["profile"],
        frozenset({"path", "digest", "apparmor_digest", "runtime_trust_digest", "verifier"}),
    )
    ledger_row = _closed(
        manifest["attempt_ledger"],
        frozenset({
            "ledger_entry_digest", "max_attempts", "success_target",
            "success_target_authorizing", "contract_core_digest",
            "qualification_contract_digest",
        }),
    )
    evidence_row = _closed(manifest["evidence"], frozenset({"path", "bytes", "digest"}))
    scope = _closed(evidence["scope"], frozenset({"profile_id", "assurance_scope", "environment", "data_class"}))
    if (
        manifest["bundle_version"] != "2.0.0"
        or manifest["claim"] != "M4_EXACT_DISPOSABLE_TEST_PROFILE_RUNTIME_CONFORMANCE"
        or manifest["outcome"] != "VERIFIED"
        or manifest["status"] != "NOT_ATTESTED"
        or evidence["bundle_version"] != "2.0.0"
        or evidence["evidence_version"] != "2.0.0"
        or evidence["claim"] != manifest["claim"]
        or evidence["residual_risk"] != _RESIDUAL_RISK
        or scope != {
            "profile_id": "M4-LX-A", "assurance_scope": "DEPLOYMENT_ATTESTED",
            "environment": "DISPOSABLE_UBUNTU_24_04_QEMU_KVM", "data_class": "SYNTHETIC",
        }
        or evidence["run_state_digest"] != _digest_bytes(_canonical(state))
        or manifest["qualification_contract"] != qualification_contract
        or evidence["qualification_contract"] != qualification_contract
        or manifest["qualification_contract_digest"]
        != qualification_contract_digest
        or evidence["qualification_contract_digest"]
        != qualification_contract_digest
        or manifest["admission_digest"] != admission["ledger_entry_digest"]
        or evidence["admission_digest"] != admission["ledger_entry_digest"]
        or manifest["candidate"] != state["identity"]["candidate"]
        or manifest["environment"] != state["identity"]["environment"]
        or manifest["attempt"] != state["identity"]["attempt"]
        or manifest["source"] != state["identity"]["source"]
        or manifest["source"] != source
        or manifest["host_provenance"] != state["identity"]["host_provenance"]
        or profile_row["path"] != "profiles/m4-lx-a.json"
        or profile_row["digest"] != profile_digest
        or profile_row["digest"] != state["trust"]["profile_digest"]
        or profile_row["apparmor_digest"] != _digest_file(APPARMOR, 1 << 20)
        or profile_row["apparmor_digest"] != state["trust"]["m4_apparmor_digest"]
        or profile_row["runtime_trust_digest"] != state["trust"]["runtime_trust_digest"]
        or profile_row["verifier"] != state["trust"]["verifier"]
        or ledger_row != {
            "ledger_entry_digest": admission["ledger_entry_digest"],
            "max_attempts": 2,
            "success_target": 1,
            "success_target_authorizing": False,
            "contract_core_digest": contract_core_digest,
            "qualification_contract_digest": qualification_contract_digest,
        }
        or manifest["durable"] != state["durable"]["m4_recovery"]
        or evidence_row["path"] != "evidence.json"
        or evidence_row["bytes"] != len(evidence_bytes)
        or evidence_row["digest"] != _digest_bytes(evidence_bytes)
    ):
        _invalid("CROSS_BINDING_MISMATCH")
    _validate_recovery(evidence["recovery"], state, profile)
    return {
        "gate_version": 2,
        "claim": "M4_EXACT_DISPOSABLE_TEST_PROFILE_RUNTIME_CONFORMANCE",
        "claim_status": "M4_EXACT_DISPOSABLE_TEST_PROFILE_RUNTIME_CONFORMANCE_VERIFIED",
        "outcome": "VERIFIED",
        "reason": "CONFORMANCE_VERIFIED",
        "product_status": "NOT_ATTESTED",
        "commit": manifest["candidate"],
        "tree": manifest["source"]["tree"],
        "attempt": manifest["attempt"],
        "environment": manifest["environment"],
        "qualification_contract_digest": qualification_contract_digest,
        "admission_digest": admission["ledger_entry_digest"],
        "manifest_digest": file_digests["manifest.json"],
        "signed_payload_bundle_digest": signed_payload_bundle_digest,
        "aggregate_bundle_digest": aggregate_bundle_digest,
        "bundle_file_digests": file_digests,
        "residual_risk": _RESIDUAL_RISK,
    }


def _absent(reason: str) -> dict[str, object]:
    return {
        "gate_version": 2,
        "claim": "M4_EXACT_DISPOSABLE_TEST_PROFILE_RUNTIME_CONFORMANCE",
        "outcome": "ABSENT",
        "reason": reason,
        "product_status": "NOT_ATTESTED",
    }


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[0] != "--evidence":
        sys.stdout.buffer.write(_canonical(_absent("EVIDENCE_ARGUMENT_REQUIRED")) + b"\n")
        return 1
    try:
        result = _verify_bundle(Path(argv[1]), host_assets=IMAGE_LAB)
    except (OSError, ValueError, _InvalidEvidence) as error:
        reason = str(error) if str(error) else "EVIDENCE_REJECTED"
        sys.stdout.buffer.write(_canonical(_absent(reason)) + b"\n")
        return 1
    sys.stdout.buffer.write(_canonical(result) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
