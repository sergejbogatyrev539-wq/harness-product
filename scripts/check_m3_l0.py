#!/usr/bin/env python3
"""Non-skipping exact-profile M3 availability and signed-evidence gate.

With no arguments this command only measures the current developer host and is
expected to return ABSENT. ``--evidence`` verifies a fixed three-file bundle
against a repository-pinned public test root. It never launches a worker and
never accepts a caller supplied boolean, digest, key, or image tag as proof.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import sys
from typing import NoReturn


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from harness_product import l0  # noqa: E402


PROFILE = ROOT / "profiles" / "l0-lx-a.json"
TRUST_CONFIG = ROOT / "profiles" / "l0-lx-a-test-attestor.json"
TRUST_PUBLIC_KEY = ROOT / "profiles" / "l0-lx-a-test-attestor.pub"
APPARMOR_POLICY = Path("profiles/l0-lx-a.apparmor")
SECCOMP_POLICY = Path("profiles/l0-lx-a-seccomp.json")
VERIFIER_CODE = Path("src/harness_product/verification.py")
LIBCRYPTO_PATH = "/usr/lib/x86_64-linux-gnu/libcrypto.so.3"
LAB = Path("/home/a1/Загрузки/harness/harness-m3-lab")

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,191}$")
_UTC = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_BUNDLE_FILES = frozenset({"manifest.json", "manifest.sig", "evidence.json"})
_IMAGE_URL = (
    "https://cloud-images.ubuntu.com/releases/noble/release-20260814/"
    "ubuntu-24.04-server-cloudimg-amd64.img"
)
_IMAGE_DIGEST = "sha256:6e40c07ae715f744f84af0bec76415cc1987dd115b4b8de437818561f01a3733"
_SUMS_DIGEST = "sha256:0f92d5610dfc5797f9574a5a8a000021d845c70c70f6b187b2b78eb1584618cf"
_SUMS_SIGNATURE_DIGEST = "sha256:a4466d91a9481850908ce0e8c518ebb1cf3ca414add6ba378e783c7d553618a7"
_UBUNTU_SIGNER = "D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81"
_QEMU_PATH = "/usr/bin/qemu-system-x86_64"
_QEMU_DIGEST = "sha256:8a35ccba41582fc6c38b9df85fc9e35fa1d42f414d2d7d8090ee9b2f5e7c0854"
_SOURCE_FIXED = (
    "AGENTS.md", "README.md", "ROADMAP.md", "SECURITY.md", "STATUS.json",
    "docs/ARCHITECTURE.md", "profiles/harness-m3-controller@.service",
    "spec/MANIFEST.sha256",
)
_RESIDUAL_RISK = (
    "Disposable Ubuntu 24.04 test-profile evidence only; no production trust root, "
    "production isolation, zero-covert-channel, physical durability, M4 seal/postcheck, "
    "COMMIT, JOIN, or readiness claim."
)

_TEST_MATRIX = {
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
        "ATK-034",
        "T-Q39-SUPPLY-EXTERNAL-BUNDLE-SUBSTITUTION",
    ),
    "T-M3-STALE-FENCE-REVOCATION-DENY": ("ATK-010",),
    "T-M3-RESTART-CLEANUP-NO-RESUME": ("ATK-028",),
    "T-M3-UNCERTAINTY-QUARANTINE-NO-RETRY": ("ATK-034",),
}
_REQUIRED_MATRIX = frozenset(
    {
        "ATK-001", "ATK-002", "ATK-003", "ATK-007", "ATK-010", "ATK-011",
        "ATK-012", "ATK-019", "ATK-020", "ATK-021", "ATK-022", "ATK-026",
        "ATK-028", "ATK-034", "T-Q39-SUPPLY-EXTERNAL-BUNDLE-SUBSTITUTION",
        "T-Q43-DESCRIPTOR-ROOT-SUBSTITUTION", "T-Q46-DIRECT-WORKER-MUTATE-DENY",
        "T-Q47-MUTATION-SELF-AUDIENCE-DENY",
    }
)
_EVENT_TYPES = frozenset(
    {"TCB_LAUNCH", "TCB_DENY", "TCB_RESOURCE", "TCB_KILL", "TCB_CLEANUP", "TCB_STAGE", "TCB_RECOVERY"}
)


class _InvalidEvidence(Exception):
    pass


def _invalid(reason: str) -> NoReturn:
    raise _InvalidEvidence(reason)


def _digest_bytes(value: bytes) -> str:
    return "sha256:" + sha256(value).hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _strict_json(raw: bytes) -> object:
    def pairs(rows: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in rows:
            if type(key) is not str or key in result:
                _invalid("DUPLICATE_OR_NONSTRING_KEY")
            result[key] = value
        return result

    def constant(_: str) -> NoReturn:
        _invalid("NONFINITE_NUMBER")

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise _InvalidEvidence("MALFORMED_JSON") from error
    if _canonical(value) != raw:
        _invalid("NONCANONICAL_JSON")
    return value


def _closed(value: object, keys: frozenset[str]) -> dict[str, object]:
    if type(value) is not dict or frozenset(value) != keys:
        _invalid("UNKNOWN_OR_MISSING_FIELD")
    return value


def _string(value: object, *, identifier: bool = False, maximum: int = 4096) -> str:
    if type(value) is not str or not value or len(value.encode("utf-8")) > maximum:
        _invalid("MALFORMED_STRING")
    if identifier and not _IDENTIFIER.fullmatch(value):
        _invalid("MALFORMED_IDENTIFIER")
    return value


def _integer(value: object, *, minimum: int = 0, maximum: int = (1 << 63) - 1) -> int:
    if type(value) is not int or value < minimum or value > maximum:
        _invalid("MALFORMED_INTEGER")
    return value


def _boolean(value: object) -> bool:
    if type(value) is not bool:
        _invalid("MALFORMED_BOOLEAN")
    return value


def _digest(value: object) -> str:
    text = _string(value, maximum=71)
    if not _DIGEST.fullmatch(text):
        _invalid("MALFORMED_DIGEST")
    return text


def _timestamp(value: object) -> datetime:
    text = _string(value, maximum=20)
    if not _UTC.fullmatch(text):
        _invalid("MALFORMED_TIME")
    try:
        return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as error:
        raise _InvalidEvidence("MALFORMED_TIME") from error


def _string_list(value: object, *, minimum: int = 0, maximum: int = 256, unique: bool = True) -> list[str]:
    if type(value) is not list or len(value) < minimum or len(value) > maximum:
        _invalid("MALFORMED_LIST")
    result = [_string(item) for item in value]
    if unique and len(set(result)) != len(result):
        _invalid("DUPLICATE_LIST_VALUE")
    return result


def _read_regular(path: Path, maximum: int) -> bytes:
    info = os.lstat(path)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) & 0o022
        or info.st_size < 0
        or info.st_size > maximum
    ):
        _invalid("UNTRUSTED_FILE")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (info.st_dev, info.st_ino, info.st_size):
            _invalid("FILE_RACE")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(65536, maximum + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                _invalid("UNBOUNDED_FILE")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _run(argv: list[str], *, input_bytes: bytes | None = None, pass_fds: tuple[int, ...] = ()) -> bytes:
    completed = subprocess.run(
        argv,
        input=input_bytes,
        shell=False,
        check=False,
        capture_output=True,
        timeout=15,
        close_fds=True,
        pass_fds=pass_fds,
        env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
    )
    if completed.returncode != 0:
        _invalid("VERIFIER_COMMAND_FAILED")
    return completed.stdout


def _source_state(root: Path, *, require_clean: bool = True) -> dict[str, object]:
    git = "/usr/bin/git"
    commit = _run([git, "-C", str(root), "rev-parse", "HEAD"]).decode("ascii").strip()
    tree = _run([git, "-C", str(root), "rev-parse", "HEAD^{tree}"]).decode("ascii").strip()
    if not re.fullmatch(r"[0-9a-f]{40}", commit) or not re.fullmatch(r"[0-9a-f]{40}", tree):
        _invalid("SOURCE_IDENTITY_INVALID")
    if require_clean and _run(
        [git, "-C", str(root), "status", "--porcelain=v1", "--untracked-files=no"]
    ):
        _invalid("SOURCE_DIRTY")
    tracked = _run(
        [git, "-C", str(root), "ls-files", "-z", "--", "src/harness_product", "scripts", "profiles", "tests"]
    ).split(b"\0")
    paths: list[str] = []
    for raw in tracked:
        if not raw:
            continue
        path = raw.decode("utf-8")
        if (
            path.startswith("src/harness_product/") and path.endswith(".py")
            or path.startswith("scripts/") and path.endswith(".py")
            or path.startswith("tests/") and path.endswith(".py")
            or path.startswith("profiles/l0-lx-a")
        ):
            paths.append(path)
    for fixed in _SOURCE_FIXED:
        if not (root / fixed).is_file():
            _invalid("SOURCE_FILE_SET_INVALID")
        paths.append(fixed)
    if len(paths) != len(set(paths)) or not paths:
        _invalid("SOURCE_FILE_SET_INVALID")
    files = {path: _digest_bytes(_read_regular(root / path, 16 << 20)) for path in sorted(paths)}
    return {"commit": commit, "tree": tree, "files": files, "files_digest": _digest_bytes(_canonical(files))}


def _qemu_argv(lab: Path) -> list[str]:
    return [
        _QEMU_PATH,
        "-name", "harness-m3-disposable",
        "-machine", "q35,accel=kvm",
        "-cpu", "host",
        "-smp", "2",
        "-m", "2048",
        "-drive", "if=virtio,format=qcow2,file=" + str(lab / "harness-m3-overlay.qcow2"),
        "-drive", "if=virtio,format=raw,readonly=on,media=cdrom,file=" + str(lab / "harness-m3-seed.iso"),
        "-netdev", "user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:22227-:22",
        "-device", "virtio-net-pci,netdev=net0",
        "-display", "none",
        "-serial", "mon:stdio",
        "-no-reboot",
    ]


def _verify_host_lab(image: dict[str, object], vm: dict[str, object], lab: Path) -> None:
    expected_paths = {
        "image": lab / "ubuntu-24.04-server-cloudimg-amd64.img",
        "sums": lab / "SHA256SUMS",
        "signature": lab / "SHA256SUMS.gpg",
        "seed": lab / "harness-m3-seed.iso",
        "overlay": lab / "harness-m3-overlay.qcow2",
    }
    if not lab.is_dir() or lab.is_symlink():
        _invalid("LAB_PROVENANCE_ABSENT")
    if _digest_bytes(_read_regular(expected_paths["image"], 1 << 30)) != image["sha256"]:
        _invalid("IMAGE_MISMATCH")
    sums = _read_regular(expected_paths["sums"], 1 << 20)
    signature = _read_regular(expected_paths["signature"], 1 << 20)
    if _digest_bytes(sums) != image["sums_sha256"] or _digest_bytes(signature) != image["sums_signature_sha256"]:
        _invalid("IMAGE_MISMATCH")
    expected_line = str(image["sha256"]).removeprefix("sha256:") + " *" + str(image["filename"])
    if expected_line not in sums.decode("utf-8").splitlines():
        _invalid("IMAGE_MISMATCH")
    _run(
        [
            "/usr/bin/gpgv", "--keyring", "/usr/share/keyrings/ubuntu-cloudimage-keyring.gpg",
            str(expected_paths["signature"]), str(expected_paths["sums"]),
        ]
    )
    if _digest_bytes(_read_regular(expected_paths["seed"], 16 << 20)) != vm["seed_digest"]:
        _invalid("VM_MISMATCH")
    overlay = os.lstat(expected_paths["overlay"])
    if (
        not stat.S_ISREG(overlay.st_mode)
        or overlay.st_nlink != 1
        or stat.S_IMODE(overlay.st_mode) & 0o077
        or overlay.st_size > int(vm["overlay_virtual_bytes"])
    ):
        _invalid("VM_MISMATCH")
    try:
        info = json.loads(
            _run(
                [
                    "/usr/bin/qemu-img", "info", "--force-share", "--output=json",
                    str(expected_paths["overlay"]),
                ]
            ).decode("utf-8")
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise _InvalidEvidence("VM_MISMATCH") from error
    if info.get("format") != "qcow2" or info.get("virtual-size") != vm["overlay_virtual_bytes"]:
        _invalid("VM_MISMATCH")
    expected_argv = _qemu_argv(lab)
    matches: list[int] = []
    for item in Path("/proc").iterdir():
        if not item.name.isdecimal():
            continue
        try:
            argv = item.joinpath("cmdline").read_bytes().rstrip(b"\0").split(b"\0")
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        if argv == [value.encode("utf-8") for value in expected_argv]:
            matches.append(int(item.name))
    if len(matches) != 1 or vm["qemu_argv_digest"] != _digest_bytes(_canonical(expected_argv)):
        _invalid("VM_LAUNCH_MISMATCH")
    descriptor = os.open("/dev/kvm", os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        api = fcntl.ioctl(descriptor, 0xAE00, 0)
    finally:
        os.close(descriptor)
    if api != vm["kvm_api"]:
        _invalid("VM_MISMATCH")


def _load_trust(config_path: Path, public_key_path: Path) -> tuple[dict[str, object], bytes]:
    raw = _read_regular(config_path, 65536)
    try:
        trust = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise _InvalidEvidence("TRUST_CONFIG_INVALID") from error
    trust = _closed(
        trust,
        frozenset(
            {
                "trust_version", "trust_root_id", "signer_id", "key_id", "algorithm",
                "public_key_pem_digest", "public_key_fingerprint", "openssl",
                "verifier_openssl", "rollback_floor", "revocation_state_digest", "scope",
            }
        ),
    )
    if trust["trust_version"] != "1.0.0" or trust["algorithm"] != "ED25519":
        _invalid("TRUST_CONFIG_INVALID")
    for key in ("trust_root_id", "signer_id", "key_id"):
        _string(trust[key], identifier=True)
    _digest(trust["public_key_pem_digest"])
    _digest(trust["public_key_fingerprint"])
    _digest(trust["revocation_state_digest"])
    _integer(trust["rollback_floor"], minimum=1)
    scope = _closed(trust["scope"], frozenset({"profile_id", "workload_class", "environment", "data_class"}))
    expected_scope = {
        "profile_id": l0.PROFILE_ID,
        "workload_class": l0.WORKLOAD_CLASS,
        "environment": l0.ENVIRONMENT,
        "data_class": "SYNTHETIC",
    }
    if scope != expected_scope:
        _invalid("TRUST_SCOPE_MISMATCH")
    signer_openssl = _closed(
        trust["openssl"], frozenset({"path", "version", "digest"})
    )
    verifier_openssl = _closed(
        trust["verifier_openssl"], frozenset({"path", "version", "digest"})
    )
    if (
        signer_openssl["path"] != "/usr/bin/openssl"
        or verifier_openssl["path"] != "/usr/bin/openssl"
    ):
        _invalid("OPENSSL_MISMATCH")
    _digest(signer_openssl["digest"])
    _string(signer_openssl["version"], maximum=256)
    expected_verifier = _digest(verifier_openssl["digest"])
    if (
        _digest_bytes(
            _read_regular(Path(str(verifier_openssl["path"])), 8 << 20)
        )
        != expected_verifier
    ):
        _invalid("OPENSSL_MISMATCH")
    version = _run([str(verifier_openssl["path"]), "version"]).decode("utf-8").strip()
    if version != verifier_openssl["version"]:
        _invalid("OPENSSL_MISMATCH")
    public_key = _read_regular(public_key_path, 65536)
    if _digest_bytes(public_key) != trust["public_key_pem_digest"]:
        _invalid("PUBLIC_KEY_MISMATCH")
    der = _run(
        [str(verifier_openssl["path"]), "pkey", "-pubin", "-outform", "DER"],
        input_bytes=public_key,
    )
    if _digest_bytes(der) != trust["public_key_fingerprint"]:
        _invalid("PUBLIC_KEY_MISMATCH")
    return trust, public_key


def _verify_signature(openssl_path: str, public_key: bytes, manifest: bytes, signature: bytes) -> None:
    if len(signature) != 64:
        _invalid("SIGNATURE_INVALID")
    key_fd = os.memfd_create("m3-public-key", os.MFD_CLOEXEC)
    manifest_fd = os.memfd_create("m3-manifest", os.MFD_CLOEXEC)
    signature_fd = os.memfd_create("m3-signature", os.MFD_CLOEXEC)
    try:
        os.write(key_fd, public_key)
        os.write(manifest_fd, manifest)
        os.write(signature_fd, signature)
        os.lseek(key_fd, 0, os.SEEK_SET)
        os.lseek(manifest_fd, 0, os.SEEK_SET)
        os.lseek(signature_fd, 0, os.SEEK_SET)
        _run(
            [
                openssl_path, "pkeyutl", "-verify", "-pubin", "-inkey", f"/proc/self/fd/{key_fd}",
                "-rawin", "-in", f"/proc/self/fd/{manifest_fd}", "-sigfile", f"/proc/self/fd/{signature_fd}",
            ],
            pass_fds=(key_fd, manifest_fd, signature_fd),
        )
    finally:
        os.close(key_fd)
        os.close(manifest_fd)
        os.close(signature_fd)


def _signed_record(
    payload: object,
    record: object,
    observed_at: object,
    trust: dict[str, object],
    public_key: bytes,
    now: datetime,
    *,
    expected_revocation_epoch: int,
    expected_fencing_epoch: int,
) -> None:
    payload_bytes = _canonical(payload)
    value = _closed(
        record,
        frozenset(
            {
                "verification_version", "verifier_id", "issuer_id", "key_id",
                "payload_digest", "bindings", "proof",
            }
        ),
    )
    if (
        value["verification_version"] not in {1, 3}
        or value["verifier_id"] != "harness-m3-external-verifier/v1"
        or value["issuer_id"] != trust["signer_id"]
        or value["key_id"] != trust["key_id"]
        or value["payload_digest"] != _digest_bytes(payload_bytes)
        or value["bindings"] != payload
    ):
        _invalid("VERIFICATION_RECORD_MISMATCH")
    proof = _string(value["proof"], maximum=136)
    if len(proof) != 136 or not proof.startswith("ed25519:"):
        _invalid("SIGNATURE_INVALID")
    try:
        signature = bytes.fromhex(proof[8:])
    except ValueError as error:
        raise _InvalidEvidence("SIGNATURE_INVALID") from error
    _verify_signature(
        str(trust["verifier_openssl"]["path"]),
        public_key,
        payload_bytes,
        signature,
    )
    observed = _timestamp(observed_at)
    if observed > now:
        _invalid("VERIFICATION_STALE")
    pending = [payload]
    revocations: list[int] = []
    fences: list[int] = []
    intervals = 0
    visited = 0
    while pending:
        current = pending.pop()
        visited += 1
        if visited > 65536:
            _invalid("VERIFICATION_UNBOUNDED")
        if type(current) is list:
            pending.extend(current)
            continue
        if type(current) is not dict:
            continue
        pending.extend(current.values())
        if "revocation_epoch" in current:
            revocations.append(_integer(current["revocation_epoch"]))
        if "fencing_epoch" in current:
            fences.append(_integer(current["fencing_epoch"], minimum=1))
        starts = [
            _timestamp(current[key])
            for key in ("not_before", "issued_at")
            if key in current
        ]
        if any(start > now for start in starts):
            _invalid("VERIFICATION_STALE")
        if "observed_at" in current and _timestamp(current["observed_at"]) > now:
            _invalid("VERIFICATION_STALE")
        if "expires_at" in current:
            expires = _timestamp(current["expires_at"])
            intervals += 1
            if now >= expires or any(start >= expires for start in starts):
                _invalid("VERIFICATION_STALE")
    if (
        intervals == 0
        or not revocations
        or any(value != expected_revocation_epoch for value in revocations)
        or not fences
        or any(value != expected_fencing_epoch for value in fences)
    ):
        _invalid("VERIFICATION_EPOCH_MISMATCH")


def _validate_manifest(
    manifest: object,
    trust: dict[str, object],
    source: dict[str, object],
    root: Path,
    now: datetime,
) -> tuple[dict[str, object], dict[str, object]]:
    value = _closed(
        manifest,
        frozenset({"bundle_version", "claim", "outcome", "scope", "source", "profile", "attestation", "evidence"}),
    )
    if value["bundle_version"] != "1.0.0" or value["claim"] != "M3_TEST_PROFILE_RUNTIME_CONFORMANCE" or value["outcome"] != "VERIFIED":
        _invalid("CLAIM_MISMATCH")
    if value["scope"] != trust["scope"]:
        _invalid("TRUST_SCOPE_MISMATCH")
    signed_source = _closed(value["source"], frozenset({"commit", "tree", "files", "files_digest"}))
    if signed_source != source:
        _invalid("SOURCE_MISMATCH")

    profile = _closed(
        value["profile"],
        frozenset({"path", "profile_artifact_digest", "compiled_profile_digest", "runtime_path", "runtime_version", "runtime_digest"}),
    )
    if profile["path"] != "profiles/l0-lx-a.json":
        _invalid("PROFILE_MISMATCH")
    profile_bytes = _read_regular(root / str(profile["path"]), 1 << 20)
    if _digest_bytes(profile_bytes) != profile["profile_artifact_digest"]:
        _invalid("PROFILE_MISMATCH")
    try:
        raw_profile = json.loads(profile_bytes)
    except json.JSONDecodeError as error:
        raise _InvalidEvidence("PROFILE_MISMATCH") from error
    compiled = l0.compile_profile(raw_profile)
    if compiled.profile is None or compiled.profile.profile_digest != profile["compiled_profile_digest"]:
        _invalid("PROFILE_MISMATCH")
    if (
        profile["runtime_path"] != l0.RUNTIME_PATH
        or profile["runtime_version"] != l0.RUNTIME_VERSION
        or profile["runtime_digest"] != l0.RUNTIME_DIGEST
    ):
        _invalid("RUNTIME_MISMATCH")

    attestation = _closed(
        value["attestation"],
        frozenset(
            {
                "trust_root_id", "signer_id", "key_id", "algorithm", "public_key_fingerprint",
                "openssl", "issued_at", "expires_at", "revocation_epoch", "rollback_floor",
                "revocation_state_digest", "nonce", "fencing_epoch",
            }
        ),
    )
    for key in ("trust_root_id", "signer_id", "key_id", "algorithm", "public_key_fingerprint", "openssl", "revocation_state_digest"):
        expected = trust["openssl"] if key == "openssl" else trust[key]
        if attestation[key] != expected:
            _invalid("ATTESTOR_MISMATCH")
    issued = _timestamp(attestation["issued_at"])
    expires = _timestamp(attestation["expires_at"])
    if issued > now or now > expires or expires <= issued or expires - issued > timedelta(days=7):
        _invalid("ATTESTATION_STALE")
    if _integer(attestation["revocation_epoch"]) != 0:
        _invalid("ATTESTATION_REVOKED")
    if _integer(attestation["fencing_epoch"], minimum=1) != 1:
        _invalid("ATTESTATION_FENCE_MISMATCH")
    if _integer(attestation["rollback_floor"], minimum=1) < int(trust["rollback_floor"]):
        _invalid("ATTESTATION_ROLLBACK")
    _string(attestation["nonce"], identifier=True)
    evidence = _closed(value["evidence"], frozenset({"path", "bytes", "digest"}))
    if evidence["path"] != "evidence.json":
        _invalid("EVIDENCE_PATH_MISMATCH")
    _integer(evidence["bytes"], minimum=2, maximum=8 << 20)
    _digest(evidence["digest"])
    return raw_profile, evidence


def _validate_verifier_binding(
    value: object,
    raw_profile: dict[str, object],
    manifest: dict[str, object],
    trust: dict[str, object],
    root: Path,
    dependencies: list[dict[str, object]],
) -> dict[str, object]:
    verifier = _closed(
        value,
        frozenset(
            {
                "backend", "code_digest", "public_key_digest", "libcrypto_digest",
                "controller_principal", "executor_principal", "independent_implementations",
            }
        ),
    )
    bindings = _closed(
        raw_profile["measurement_bindings"],
        frozenset(
            {
                "rootfs_manifest_digest", "seccomp_profile_digest", "lsm_policy_name",
                "lsm_policy_digest", "broker_message_schema_digest", "verifier_code_digest",
                "verifier_public_key_digest", "verifier_libcrypto_digest",
            }
        ),
    )
    expected_code = _digest_bytes(_read_regular(root / VERIFIER_CODE, 1 << 20))
    expected_public = trust["public_key_pem_digest"]
    expected_libcrypto = _digest(bindings["verifier_libcrypto_digest"])
    if (
        verifier["backend"] != "OPENSSL_LIBCRYPTO_SHARED"
        or verifier["code_digest"] != expected_code
        or verifier["code_digest"] != bindings["verifier_code_digest"]
        or verifier["code_digest"] != manifest["source"]["files"].get(str(VERIFIER_CODE))
        or verifier["public_key_digest"] != expected_public
        or verifier["public_key_digest"] != bindings["verifier_public_key_digest"]
        or verifier["libcrypto_digest"] != expected_libcrypto
        or verifier["controller_principal"] != "CONTROLLER"
        or verifier["executor_principal"] != "EXECUTOR"
        or _boolean(verifier["independent_implementations"])
    ):
        _invalid("VERIFIER_BINDING_MISMATCH")
    crypto_rows = [
        row for row in dependencies
        if str(row["path"]).endswith("/libcrypto.so.3")
    ]
    if len(crypto_rows) != 1 or crypto_rows[0]["digest"] != expected_libcrypto:
        _invalid("VERIFIER_BINDING_MISMATCH")
    return verifier


def _validate_principals(
    value: object,
    raw_profile: dict[str, object],
) -> dict[str, dict[str, object]]:
    principal_value = _closed(value, frozenset({"active", "disabled"}))
    active = principal_value["active"]
    if type(active) is not list or len(active) != 5:
        _invalid("PRINCIPAL_MISMATCH")
    profile_principals = {row["role"]: row for row in raw_profile["principals"] if row["enabled"]}
    expected = {
        "ATTESTOR": (0, 4004, 0, 4004, 0, 4004, "harness-l0-lx-a.attestor"),
        "CONTROLLER": (3000, 4000, 3000, 4000, 3000, 4000, "harness-l0-lx-a.controller"),
        "AGENT_WORKER": (3001, 4001, 3001, 4001, 1001, 2001, profile_principals["AGENT_WORKER"]["security_label"]),
        "BROKER": (3002, 4002, 3002, 4002, 1002, 2002, profile_principals["BROKER"]["security_label"]),
        "EXECUTOR": (3003, 4003, 3003, 4003, 1003, 2003, profile_principals["EXECUTOR"]["security_label"]),
    }
    expected_fds: dict[str, object] = {
        "ATTESTOR": None,
        "CONTROLLER": [0, 1, 2, 3],
        "AGENT_WORKER": [0, 1],
        "BROKER": [0, 1, 2],
        "EXECUTOR": [0, 1],
    }
    result: dict[str, dict[str, object]] = {}
    identities: set[tuple[int, int]] = set()
    sessions: set[str] = set()
    credentials: set[str] = set()
    isolated_namespaces: set[tuple[str, ...]] = set()
    for row in active:
        item = _closed(
            row,
            frozenset(
                {
                    "role", "launcher_uid", "launcher_gid", "host_uid", "host_gid",
                    "namespace_uid", "namespace_gid", "session_id", "process_id", "cgroup",
                    "security_label", "credential_namespace", "namespace_ids", "fd_inventory",
                    "network",
                }
            ),
        )
        role = _string(item["role"], identifier=True)
        if role not in expected or role in result:
            _invalid("PRINCIPAL_MISMATCH")
        actual_identity = tuple(
            _integer(item[key])
            for key in (
                "launcher_uid", "launcher_gid", "host_uid", "host_gid",
                "namespace_uid", "namespace_gid",
            )
        )
        if actual_identity != expected[role][0:6] or item["security_label"] != expected[role][6]:
            _invalid("PRINCIPAL_MISMATCH")
        host_identity = (int(item["host_uid"]), int(item["host_gid"]))
        if host_identity in identities:
            _invalid("PRINCIPAL_MISMATCH")
        identities.add(host_identity)
        session = _string(item["session_id"], identifier=True)
        credential = _string(item["credential_namespace"], identifier=True)
        if session in sessions or credential in credentials:
            _invalid("PRINCIPAL_MISMATCH")
        sessions.add(session)
        credentials.add(credential)
        _integer(item["process_id"], minimum=1)
        _string(item["cgroup"])
        namespaces = _closed(
            item["namespace_ids"],
            frozenset({"user", "mount", "pid", "ipc", "uts", "network", "cgroup"}),
        )
        namespace_tuple = tuple(_string(namespaces[key], maximum=256) for key in sorted(namespaces))
        if role in {"AGENT_WORKER", "BROKER", "EXECUTOR"}:
            if namespace_tuple in isolated_namespaces:
                _invalid("PRINCIPAL_MISMATCH")
            isolated_namespaces.add(namespace_tuple)
        fds = item["fd_inventory"]
        if (
            type(fds) is not list
            or any(type(fd) is not int or fd < 0 for fd in fds)
            or fds != sorted(set(fds))
        ):
            _invalid("FD_INVENTORY_MISMATCH")
        if role == "ATTESTOR":
            if len(fds) != 5 or fds[:3] != [0, 1, 2] or any(fd <= 2 for fd in fds[3:]):
                _invalid("FD_INVENTORY_MISMATCH")
        elif fds != expected_fds[role]:
            _invalid("FD_INVENTORY_MISMATCH")
        network = _closed(
            item["network"],
            frozenset(
                {"ipv4", "ipv6", "loopback", "routes", "dns", "raw", "packet", "broad_unix", "connected_fds"}
            ),
        )
        connected = role in {"AGENT_WORKER", "BROKER"}
        if (
            any(_boolean(network[key]) for key in network if key != "connected_fds")
            or _boolean(network["connected_fds"]) is not connected
        ):
            _invalid("PRINCIPAL_NETWORK_MISMATCH")
        result[role] = item
    if set(result) != set(expected) or len(isolated_namespaces) != 3:
        _invalid("PRINCIPAL_MISMATCH")
    disabled = principal_value["disabled"]
    if type(disabled) is not list or len(disabled) != 2:
        _invalid("DISABLED_ROLE_MISMATCH")
    disabled_roles: set[str] = set()
    for row in disabled:
        item = _closed(row, frozenset({"role", "enabled", "process", "route", "fd", "credential"}))
        role = _string(item["role"], identifier=True)
        if role in disabled_roles or any(_boolean(item[key]) for key in ("enabled", "process", "route", "fd", "credential")):
            _invalid("DISABLED_ROLE_MISMATCH")
        disabled_roles.add(role)
    if disabled_roles != {"MODEL_GATEWAY", "OBSERVER"}:
        _invalid("DISABLED_ROLE_MISMATCH")
    return result


def _validate_controller(
    value: object,
    principal: dict[str, object],
    verifier: dict[str, object],
    manifest: dict[str, object],
) -> None:
    controller = _closed(
        value,
        frozenset(
            {
                "argv", "argv_digest", "cgroup", "code_descriptor", "control_proof",
                "credential_namespace", "durable_database", "envelope_digest", "fd_inventory",
                "host_gid", "host_uid", "launcher_gid", "launcher_uid", "namespace_gid",
                "namespace_ids", "namespace_uid", "network", "process_id", "process_session",
                "security_label", "session_id", "status", "verifier",
            }
        ),
    )
    for key in (
        "cgroup", "credential_namespace", "fd_inventory", "host_gid", "host_uid",
        "launcher_gid", "launcher_uid", "namespace_gid", "namespace_ids", "namespace_uid",
        "network", "process_id", "security_label", "session_id",
    ):
        if controller[key] != principal[key]:
            _invalid("CONTROLLER_MISMATCH")
    _integer(controller["process_session"], minimum=1)
    expected_argv = [
        "/usr/bin/aa-exec", "--profile", "harness-l0-lx-a.controller", "--",
        "/usr/bin/python3.12", "-I", "-S",
        "/opt/harness-m3-source/scripts/run_m3_vm_conformance.py", "--controller-session",
    ]
    if controller["argv"] != expected_argv or controller["argv_digest"] != _digest_bytes(_canonical(expected_argv)):
        _invalid("CONTROLLER_MISMATCH")
    if controller["durable_database"] != "/var/lib/harness-m3-controller/durable.sqlite3":
        _invalid("CONTROLLER_MISMATCH")
    _digest(controller["envelope_digest"])
    status_value = _closed(controller["status"], frozenset({"CapInh", "CapPrm", "CapEff", "NoNewPrivs"}))
    if any(status_value[key] != "0000000000000000" for key in ("CapInh", "CapPrm", "CapEff")) or status_value["NoNewPrivs"] != "1":
        _invalid("CONTROLLER_MISMATCH")
    descriptor = _closed(
        controller["code_descriptor"],
        frozenset({"path", "descriptor", "device", "inode", "bytes", "digest", "flags", "uid", "gid", "mode"}),
    )
    if (
        descriptor["path"] != "/opt/harness-m3-source/scripts/run_m3_vm_conformance.py"
        or descriptor["descriptor"] != 3
        or _integer(descriptor["device"]) < 0
        or _integer(descriptor["inode"], minimum=1) < 1
        or _integer(descriptor["bytes"], minimum=1) < 1
        or descriptor["digest"] != manifest["source"]["files"].get("scripts/run_m3_vm_conformance.py")
        or descriptor["uid"] != 0
        or descriptor["gid"] != 0
        or descriptor["mode"] != 0o444
        or type(descriptor["flags"]) is not int
        or descriptor["flags"] & os.O_ACCMODE != os.O_RDONLY
        or descriptor["flags"] & os.O_CLOEXEC != os.O_CLOEXEC
    ):
        _invalid("CONTROLLER_CODE_MISMATCH")
    binding = _closed(controller["verifier"], frozenset({"backend", "code_digest", "public_key_digest", "libcrypto_digest"}))
    if any(binding[key] != verifier[key] for key in binding):
        _invalid("VERIFIER_BINDING_MISMATCH")
    proof = _closed(
        controller["control_proof"],
        frozenset({"closed", "cgroup_populated_after_close", "operations", "operations_digest"}),
    )
    operations = proof["operations"]
    expected_operations = [
        "EVALUATE", "BOOTSTRAP", "ISSUE", "CONSUME", "CLAIM", "CLAIM", "PREPARE",
        "PREPARE", "VERIFY_CLAIM", "FINALIZE", "FINALIZE", "CLAIM", "RECOVER", "STOP",
    ]
    if type(operations) is not list or len(operations) != len(expected_operations):
        _invalid("CONTROLLER_PROOF_MISMATCH")
    observed: list[str] = []
    for row in operations:
        item = _closed(row, frozenset({"operation", "request_digest", "response_digest"}))
        observed.append(_string(item["operation"], identifier=True))
        _digest(item["request_digest"])
        _digest(item["response_digest"])
    if (
        observed != expected_operations
        or proof["operations_digest"] != _digest_bytes(_canonical(operations))
        or _boolean(proof["closed"]) is not True
        or proof["cgroup_populated_after_close"] != 0
    ):
        _invalid("CONTROLLER_PROOF_MISMATCH")


def _direct_signature(
    proof: object,
    payload: dict[str, object],
    trust: dict[str, object],
    public_key: bytes,
) -> bytes:
    text = _string(proof, maximum=136)
    if len(text) != 136 or not text.startswith("ed25519:"):
        _invalid("SIGNATURE_INVALID")
    try:
        signature = bytes.fromhex(text[8:])
    except ValueError as error:
        raise _InvalidEvidence("SIGNATURE_INVALID") from error
    _verify_signature(
        str(trust["verifier_openssl"]["path"]),
        public_key,
        _canonical(payload),
        signature,
    )
    return signature


def _validate_broker_ipc(
    value: object,
    raw_profile: dict[str, object],
    principals: dict[str, dict[str, object]],
    trust: dict[str, object],
    public_key: bytes,
    now: datetime,
) -> None:
    binding = _closed(
        value,
        frozenset(
            {
                "profile", "runtime", "holder_payload", "holder_payload_digest",
                "holder_signature", "holder_signature_digest", "broker_report",
                "broker_report_digest",
            }
        ),
    )
    if binding["profile"] != raw_profile["broker_ipc"]:
        _invalid("BROKER_IPC_MISMATCH")
    runtime = _closed(
        binding["runtime"],
        frozenset(
            {
                "kind", "endpoint_mode", "transport", "worker_endpoint", "broker_endpoint",
                "worker_principal", "broker_principal", "worker_session", "broker_session",
                "worker_security_label", "broker_security_label", "worker_socket_identity",
                "broker_socket_identity", "operation_id", "nonce", "fencing_epoch",
                "revocation_epoch", "issued_at", "expires_at", "sender_authentication",
                "message_binding_digest", "pair_binding_digest",
            }
        ),
    )
    compiled = l0.compile_profile(raw_profile).profile
    profile_ipc = raw_profile["broker_ipc"]
    if (
        compiled is None
        or runtime["kind"] != "UNIX_CONNECTED_PAIR"
        or runtime["endpoint_mode"] != profile_ipc["endpoint_mode"]
        or runtime["transport"] != profile_ipc["transport"]
        or runtime["sender_authentication"] != profile_ipc["sender_authentication"]
        or runtime["worker_endpoint"] != profile_ipc["worker_endpoint"]
        or runtime["broker_endpoint"] != profile_ipc["broker_endpoint"]
        or runtime["worker_principal"] != profile_ipc["worker_principal"]
        or runtime["broker_principal"] != profile_ipc["broker_principal"]
        or runtime["worker_security_label"] != principals["AGENT_WORKER"]["security_label"]
        or runtime["broker_security_label"] != principals["BROKER"]["security_label"]
        or runtime["worker_session"] != principals["AGENT_WORKER"]["session_id"]
        or runtime["broker_session"] != principals["BROKER"]["session_id"]
        or runtime["message_binding_digest"] != compiled.broker_binding_digest
        or runtime["fencing_epoch"] != 1
        or runtime["revocation_epoch"] != 0
    ):
        _invalid("BROKER_IPC_MISMATCH")
    _string(runtime["operation_id"], identifier=True)
    _string(runtime["nonce"], identifier=True)
    issued = _timestamp(runtime["issued_at"])
    expires = _timestamp(runtime["expires_at"])
    if issued > now or now >= expires or issued >= expires:
        _invalid("BROKER_IPC_STALE")
    socket_keys = frozenset(
        {
            "kind", "descriptor", "descriptor_id", "device", "inode", "cookie", "type",
            "family", "socket_type", "address_mode", "pass_credentials", "creation_peer",
        }
    )
    sockets: dict[str, dict[str, object]] = {}
    for side, kind, pass_credentials in (
        ("worker", "BROKER_IPC_WORKER_END", False),
        ("broker", "BROKER_IPC_BROKER_END", True),
    ):
        item = _closed(runtime[f"{side}_socket_identity"], socket_keys)
        peer = _closed(item["creation_peer"], frozenset({"pid", "uid", "gid"}))
        if (
            item["kind"] != kind
            or item["type"] != "SOCKET"
            or item["family"] != "AF_UNIX"
            or item["socket_type"] != "SOCK_SEQPACKET"
            or item["address_mode"] != "ANONYMOUS_CONNECTED"
            or _boolean(item["pass_credentials"]) is not pass_credentials
            or _integer(item["descriptor"]) < 0
            or _integer(item["device"]) < 0
            or _integer(item["inode"], minimum=1) < 1
            or _integer(item["cookie"], minimum=1) < 1
            or _integer(peer["pid"], minimum=1) < 1
            or peer["uid"] != 0
            or peer["gid"] != 0
        ):
            _invalid("BROKER_IPC_ENDPOINT_MISMATCH")
        _string(item["descriptor_id"], identifier=True)
        sockets[side] = item
    if (
        sockets["worker"]["descriptor"] == sockets["broker"]["descriptor"]
        or sockets["worker"]["inode"] == sockets["broker"]["inode"]
        or sockets["worker"]["cookie"] == sockets["broker"]["cookie"]
        or sockets["worker"]["creation_peer"] != sockets["broker"]["creation_peer"]
    ):
        _invalid("BROKER_IPC_ENDPOINT_MISMATCH")
    pair_preimage = {key: runtime[key] for key in sorted(runtime) if key != "pair_binding_digest"}
    if runtime["pair_binding_digest"] != _digest_bytes(_canonical(pair_preimage)):
        _invalid("BROKER_IPC_BINDING_MISMATCH")
    payload = _closed(
        binding["holder_payload"],
        frozenset(
            {
                "attestation_version", "observed_at", "profile_digest", "runtime_session_id",
                "operation_id", "nonce", "fencing_epoch", "revocation_epoch",
                "pair_binding_digest", "message_binding_digest", "worker_holder",
                "broker_holder", "message_credentials_in_broker_namespace", "gates",
            }
        ),
    )
    if (
        payload["attestation_version"] != "1.0.0"
        or payload["profile_digest"] != compiled.profile_digest
        or payload["runtime_session_id"] != "m3-session-record-1"
        or any(payload[key] != runtime[key] for key in ("operation_id", "nonce", "fencing_epoch", "revocation_epoch", "pair_binding_digest", "message_binding_digest"))
        or payload["gates"] != {"broker": "CLOSED", "worker": "CLOSED"}
    ):
        _invalid("BROKER_HOLDER_MISMATCH")
    observed = _timestamp(payload["observed_at"])
    if not issued <= observed <= now < expires:
        _invalid("BROKER_IPC_STALE")
    holder_keys = frozenset(
        {
            "principal", "session", "security_label", "host_uid", "host_gid", "process_id",
            "cgroup", "namespace_ids", "fd_inventory", "socket_identity", "socket_target",
        }
    )
    for side, role in (("worker", "AGENT_WORKER"), ("broker", "BROKER")):
        holder = _closed(payload[f"{side}_holder"], holder_keys)
        principal = principals[role]
        if (
            holder["principal"] != runtime[f"{side}_principal"]
            or holder["session"] != principal["session_id"]
            or holder["security_label"] != principal["security_label"]
            or holder["host_uid"] != principal["host_uid"]
            or holder["host_gid"] != principal["host_gid"]
            or holder["process_id"] != principal["process_id"]
            or holder["cgroup"] != principal["cgroup"]
            or holder["namespace_ids"] != principal["namespace_ids"]
            or holder["fd_inventory"] != principal["fd_inventory"]
            or holder["socket_identity"] != sockets[side]
            or holder["socket_target"] != f"socket:[{sockets[side]['inode']}]"
        ):
            _invalid("BROKER_HOLDER_MISMATCH")
    message_credentials = _closed(
        payload["message_credentials_in_broker_namespace"],
        frozenset({"pid", "uid", "gid"}),
    )
    if message_credentials != {"pid": 0, "uid": 65534, "gid": 65534}:
        _invalid("BROKER_CREDENTIAL_MISMATCH")
    payload_bytes = _canonical(payload)
    if binding["holder_payload_digest"] != _digest_bytes(payload_bytes):
        _invalid("BROKER_HOLDER_MISMATCH")
    signature = _direct_signature(binding["holder_signature"], payload, trust, public_key)
    if binding["holder_signature_digest"] != _digest_bytes(signature):
        _invalid("BROKER_HOLDER_MISMATCH")
    report = _closed(
        binding["broker_report"],
        frozenset({"creator_credentials", "message_credentials", "packet_digest"}),
    )
    creator = report["creator_credentials"]
    message = report["message_credentials"]
    if (
        creator != [message_credentials[key] for key in ("pid", "uid", "gid")]
        or message != [message_credentials[key] for key in ("pid", "uid", "gid")]
        or not isinstance(report["packet_digest"], str)
    ):
        _invalid("BROKER_REPORT_MISMATCH")
    _digest(report["packet_digest"])
    if binding["broker_report_digest"] != _digest_bytes(_canonical(report)):
        _invalid("BROKER_REPORT_MISMATCH")


def _validate_resource_oracles(
    value: object,
    resources: dict[str, int],
    cgroup: dict[str, object],
) -> None:
    oracles = _closed(
        value,
        frozenset({"cpu", "memory", "pids", "io", "quota", "rlimit_nofile", "wall_time"}),
    )
    limits = cgroup["limits"]
    cpu = _closed(
        oracles["cpu"],
        frozenset(
            {
                "cpu_max", "rate_delta", "time_limit_usec", "time_trigger_usec",
                "time_overshoot_usec", "time_return_code", "cgroup_populated_after_kill",
            }
        ),
    )
    rate = _closed(cpu["rate_delta"], frozenset({"usage_usec", "nr_periods", "nr_throttled", "throttled_usec"}))
    limit_usec = resources["CPU_TIME"] * 1000
    overshoot = _integer(cpu["time_overshoot_usec"], maximum=250000)
    if (
        cpu["cpu_max"] != limits["cpu.max"]
        or any(_integer(rate[key], minimum=1) < 1 for key in rate)
        or cpu["time_limit_usec"] != limit_usec
        or cpu["time_trigger_usec"] != limit_usec + overshoot
        or type(cpu["time_return_code"]) is not int
        or cpu["time_return_code"] >= 0
        or cpu["cgroup_populated_after_kill"] != 0
    ):
        _invalid("CPU_ORACLE_MISMATCH")
    memory = _closed(
        oracles["memory"],
        frozenset(
            {
                "memory_max", "swap_max", "max_events", "oom_kill_events", "swap_before",
                "swap_after", "return_code", "memory_current",
            }
        ),
    )
    if (
        memory["memory_max"] != limits["memory.max"]
        or memory["swap_max"] != limits["memory.swap.max"]
        or _integer(memory["max_events"], minimum=1) < 1
        or _integer(memory["oom_kill_events"], minimum=1) < 1
        or memory["swap_before"] != 0
        or memory["swap_after"] != 0
        or type(memory["return_code"]) is not int
        or memory["return_code"] == 0
        or _integer(memory["memory_current"]) > int(limits["memory.max"])
    ):
        _invalid("MEMORY_ORACLE_MISMATCH")
    pids = _closed(
        oracles["pids"],
        frozenset({"pids_max", "max_events", "peak", "launched", "launch_rejection", "return_codes"}),
    )
    returns = pids["return_codes"]
    if (
        pids["pids_max"] != limits["pids.max"]
        or _integer(pids["max_events"], minimum=1) < 1
        or not 1 <= _integer(pids["peak"]) <= int(limits["pids.max"])
        or not 1 <= _integer(pids["launched"]) <= int(limits["pids.max"])
        or not _string(pids["launch_rejection"])
        or type(returns) is not list
        or not returns
        or any(type(code) is not int or code >= 0 for code in returns)
    ):
        _invalid("PIDS_ORACLE_MISMATCH")
    io = _closed(
        oracles["io"],
        frozenset(
            {
                "io_max", "device", "control_elapsed_ns", "limited_elapsed_ns",
                "control_delta", "limited_delta", "read_bytes", "write_bytes",
                "control_events", "limited_events", "minimum_slowdown_factor",
            }
        ),
    )
    device = _closed(io["device"], frozenset({"backing_device", "controller_device", "partition", "binding_digest"}))
    _string(device["backing_device"], identifier=True)
    controller_device = _string(device["controller_device"], identifier=True)
    _digest(device["binding_digest"])
    if _boolean(device["partition"]) is not True or not str(limits["io.max"]).startswith(controller_device + " "):
        _invalid("IO_ORACLE_MISMATCH")
    deltas = []
    for name in ("control_delta", "limited_delta"):
        delta = _closed(io[name], frozenset({"dbytes", "dios", "rbytes", "rios", "wbytes", "wios"}))
        for key in delta:
            _integer(delta[key])
        if delta["rbytes"] < 393216 or delta["wbytes"] < 393216 or delta["rios"] < 96 or delta["wios"] < 96:
            _invalid("IO_ORACLE_MISMATCH")
        deltas.append(delta)
    control_elapsed = _integer(io["control_elapsed_ns"], minimum=1, maximum=500000000)
    limited_elapsed = _integer(io["limited_elapsed_ns"], minimum=1300000000, maximum=3000000000)
    factor = _integer(io["minimum_slowdown_factor"], minimum=3, maximum=16)
    if (
        io["io_max"] != limits["io.max"]
        or io["read_bytes"] != 393216
        or io["write_bytes"] != 393216
        or limited_elapsed < control_elapsed * factor
        or io["control_events"] != ["populated 0", "frozen 0"]
        or io["limited_events"] != ["populated 0", "frozen 0"]
    ):
        _invalid("IO_ORACLE_MISMATCH")
    quota = _closed(
        oracles["quota"],
        frozenset(
            {
                "mount_options", "files", "inodes", "logical_bytes", "allocated_bytes",
                "create_errno", "append_errno", "entries", "owners_match", "modes_match",
                "links_match", "statvfs_files", "statvfs_free", "cgroup_populated_after_cleanup",
            }
        ),
    )
    expected_entries = ["artifact.txt"] + [f"quota-{number:02d}" for number in range(15)]
    if (
        quota["mount_options"] != f"size={resources['OUTPUT_BYTES']},nr_inodes={resources['INODES']},mode=0700,uid=3003,gid=4003,nosuid,nodev,noexec"
        or quota["files"] != resources["FILES"]
        or quota["inodes"] != resources["INODES"]
        or quota["logical_bytes"] != resources["OUTPUT_BYTES"]
        or quota["allocated_bytes"] != resources["OUTPUT_BYTES"]
        or quota["create_errno"] not in {28, 122}
        or quota["append_errno"] not in {28, 122}
        or quota["entries"] != expected_entries
        or any(_boolean(quota[key]) is not True for key in ("owners_match", "modes_match", "links_match"))
        or quota["statvfs_files"] != resources["INODES"]
        or quota["statvfs_free"] != 0
        or quota["cgroup_populated_after_cleanup"] != 0
    ):
        _invalid("QUOTA_ORACLE_MISMATCH")
    nofile = _closed(oracles["rlimit_nofile"], frozenset({"limit", "return_code", "cgroup_events"}))
    if nofile["limit"] != [resources["OPEN_FDS"], resources["OPEN_FDS"]] or nofile["return_code"] != 0 or nofile["cgroup_events"] != ["populated 0", "frozen 0"]:
        _invalid("RLIMIT_ORACLE_MISMATCH")
    wall = _closed(oracles["wall_time"], frozenset({"limit_ms", "elapsed_ms", "return_code", "process_tree_size", "cgroup_events"}))
    if (
        wall["limit_ms"] != resources["WALL_TIME"]
        or not resources["WALL_TIME"] <= _integer(wall["elapsed_ms"]) <= resources["WALL_TIME"] + 1000
        or type(wall["return_code"]) is not int
        or wall["return_code"] >= 0
        or _integer(wall["process_tree_size"], minimum=2) < 2
        or wall["cgroup_events"] != ["populated 0", "frozen 0"]
    ):
        _invalid("WALL_TIME_ORACLE_MISMATCH")


def _validate_evidence(
    raw: object,
    raw_profile: dict[str, object],
    manifest: dict[str, object],
    trust: dict[str, object],
    public_key: bytes,
    root: Path,
    now: datetime,
    host_lab: Path | None,
) -> None:
    value = _closed(
        raw,
        frozenset(
            {
                "evidence_version", "image", "vm", "guest", "runtime", "supply", "principals",
                "measurements", "tests", "events", "lifecycle", "canaries", "residual_risk",
            }
        ),
    )
    if value["evidence_version"] != "1.0.0" or value["residual_risk"] != _RESIDUAL_RISK:
        _invalid("EVIDENCE_VERSION_MISMATCH")
    image = _closed(
        value["image"],
        frozenset({"source_url", "resolved_url", "release_id", "filename", "bytes", "sha256", "sums_sha256", "sums_signature_sha256", "signer_fingerprint"}),
    )
    if (
        image["source_url"] != _IMAGE_URL
        or image["resolved_url"] != _IMAGE_URL
        or image["release_id"] != "20260814"
        or image["filename"] != "ubuntu-24.04-server-cloudimg-amd64.img"
        or image["bytes"] != 624447488
        or image["sha256"] != _IMAGE_DIGEST
        or image["sums_sha256"] != _SUMS_DIGEST
        or image["sums_signature_sha256"] != _SUMS_SIGNATURE_DIGEST
        or image["signer_fingerprint"] != _UBUNTU_SIGNER
    ):
        _invalid("IMAGE_MISMATCH")

    vm = _closed(
        value["vm"],
        frozenset({"qemu_path", "qemu_version", "qemu_digest", "machine", "kvm_api", "vcpus", "memory_bytes", "overlay_virtual_bytes", "seed_digest", "management_address", "shared_host_mounts", "qemu_argv_digest"}),
    )
    if (
        vm["qemu_path"] != _QEMU_PATH
        or vm["qemu_digest"] != _QEMU_DIGEST
        or _digest_bytes(_read_regular(Path(_QEMU_PATH), 64 << 20)) != _QEMU_DIGEST
        or not _string(vm["qemu_version"]).startswith("QEMU emulator version 8.2.2 ")
        or vm["machine"] != "q35"
        or vm["kvm_api"] != 12
        or vm["vcpus"] != 2
        or vm["memory_bytes"] != 2 * 1024 * 1024 * 1024
        or vm["overlay_virtual_bytes"] != 3758096384
        or vm["management_address"] != "127.0.0.1:22227"
        or vm["shared_host_mounts"] != 0
        or vm["qemu_argv_digest"] != _digest_bytes(_canonical(_qemu_argv(LAB)))
    ):
        _invalid("VM_MISMATCH")
    _digest(vm["seed_digest"])
    if host_lab is not None:
        _verify_host_lab(image, vm, host_lab)

    guest = _closed(
        value["guest"],
        frozenset({"os_release_digest", "kernel_release", "kernel_digest", "architecture", "cgroup_v2", "apparmor_enabled", "user_namespaces", "openat2", "offline_egress", "rootfs_digest"}),
    )
    for key in ("os_release_digest", "kernel_digest", "rootfs_digest"):
        _digest(guest[key])
    if guest["architecture"] != "x86_64" or not _string(guest["kernel_release"]).startswith("6.8.0-"):
        _invalid("GUEST_MISMATCH")
    if any(_boolean(guest[key]) is not True for key in ("cgroup_v2", "apparmor_enabled", "user_namespaces", "openat2", "offline_egress")):
        _invalid("GUEST_CONTROL_ABSENT")

    runtime = _closed(
        value["runtime"],
        frozenset({"backend", "aa_exec", "openssl", "python", "apparmor_parser", "dependencies", "apparmor_policy_digest", "seccomp_policy_digest", "seccomp_bpf_digest", "sbom_digest", "registry_snapshot_digest", "profile_digest", "code_digest", "package_index_digest", "verifier"}),
    )
    tool_keys = frozenset({"path", "version", "digest", "package", "package_version"})
    backend = _closed(runtime["backend"], tool_keys)
    if (
        backend["path"] != l0.RUNTIME_PATH
        or backend["version"] != l0.RUNTIME_VERSION
        or backend["digest"] != l0.RUNTIME_DIGEST
        or backend["package"] != "bubblewrap"
        or backend["package_version"] != "0.9.0-1ubuntu0.1"
    ):
        _invalid("RUNTIME_MISMATCH")
    for name in ("aa_exec", "openssl", "python", "apparmor_parser"):
        tool = _closed(runtime[name], tool_keys)
        _string(tool["path"])
        _string(tool["version"])
        _digest(tool["digest"])
        _string(tool["package"], identifier=True)
        _string(tool["package_version"])
    dependencies = runtime["dependencies"]
    if type(dependencies) is not list or not 4 <= len(dependencies) <= 32:
        _invalid("DEPENDENCY_CLOSURE_MISMATCH")
    dependency_paths: set[str] = set()
    for row in dependencies:
        item = _closed(row, frozenset({"path", "digest", "package", "version"}))
        path = _string(item["path"])
        if path in dependency_paths:
            _invalid("DEPENDENCY_CLOSURE_MISMATCH")
        dependency_paths.add(path)
        _digest(item["digest"])
        _string(item["package"], identifier=True)
        _string(item["version"])
    compiled = l0.compile_profile(raw_profile).profile
    if compiled is None or runtime["profile_digest"] != compiled.profile_digest:
        _invalid("PROFILE_MISMATCH")
    for key in ("apparmor_policy_digest", "seccomp_policy_digest", "seccomp_bpf_digest", "sbom_digest", "registry_snapshot_digest", "code_digest", "package_index_digest"):
        _digest(runtime[key])
    if _digest_bytes(_read_regular(root / APPARMOR_POLICY, 1 << 20)) != runtime["apparmor_policy_digest"]:
        _invalid("APPARMOR_POLICY_MISMATCH")
    if _digest_bytes(_read_regular(root / SECCOMP_POLICY, 1 << 20)) != runtime["seccomp_policy_digest"]:
        _invalid("SECCOMP_POLICY_MISMATCH")
    bindings = raw_profile["measurement_bindings"]
    if (
        runtime["apparmor_policy_digest"] != bindings["lsm_policy_digest"]
        or runtime["seccomp_bpf_digest"] != bindings["seccomp_profile_digest"]
        or runtime["code_digest"] != manifest["source"]["files_digest"]
    ):
        _invalid("RUNTIME_BINDING_MISMATCH")
    verifier_binding = _validate_verifier_binding(
        runtime["verifier"], raw_profile, manifest, trust, root, dependencies
    )

    supply = _closed(
        value["supply"],
        frozenset({"image_digest", "rootfs_digest", "runtime_digest", "loader_digest", "dependency_closure_digest", "tool_digest", "sbom_digest", "registry_snapshot_digest", "key_id", "issued_at", "expires_at", "revocation_epoch", "rollback_floor", "revocation_state_digest", "profile_digest", "placement_digest", "actual_opened_bytes_digest", "verification_payload_digest", "verification_payload", "verification_record", "verifier_backend", "verifier_code_digest", "verifier_public_key_digest", "verifier_libcrypto_digest"}),
    )
    for key in (
        "image_digest", "rootfs_digest", "runtime_digest", "loader_digest", "dependency_closure_digest",
        "tool_digest", "sbom_digest", "registry_snapshot_digest", "revocation_state_digest", "profile_digest",
        "placement_digest", "actual_opened_bytes_digest", "verification_payload_digest",
        "verifier_code_digest", "verifier_public_key_digest", "verifier_libcrypto_digest",
    ):
        _digest(supply[key])
    if (
        supply["image_digest"] != _IMAGE_DIGEST
        or supply["runtime_digest"] != l0.RUNTIME_DIGEST
        or supply["sbom_digest"] != runtime["sbom_digest"]
        or supply["registry_snapshot_digest"] != runtime["registry_snapshot_digest"]
        or supply["key_id"] != trust["key_id"]
        or supply["revocation_state_digest"] != trust["revocation_state_digest"]
        or supply["profile_digest"] != runtime["profile_digest"]
        or supply["revocation_epoch"] != 0
        or supply["rollback_floor"] < trust["rollback_floor"]
        or supply["rootfs_digest"] != guest["rootfs_digest"]
        or supply["verifier_backend"] != verifier_binding["backend"]
        or supply["verifier_code_digest"] != verifier_binding["code_digest"]
        or supply["verifier_public_key_digest"] != verifier_binding["public_key_digest"]
        or supply["verifier_libcrypto_digest"] != verifier_binding["libcrypto_digest"]
    ):
        _invalid("SUPPLY_MISMATCH")
    supply_payload = _closed(
        supply["verification_payload"],
        frozenset(
            {
                "supply_version", "observed_at", "profile_digest", "measurement_digest",
                "runtime", "image", "registry", "signer", "placement", "placement_digest",
                "artifacts",
            }
        ),
    )
    if (
        supply_payload["supply_version"] != "1.0.0"
        or supply_payload["profile_digest"] != compiled.profile_digest
        or supply["verification_payload_digest"] != _digest_bytes(_canonical(supply_payload))
    ):
        _invalid("SUPPLY_PAYLOAD_MISMATCH")
    _digest(supply_payload["measurement_digest"])
    payload_runtime = _closed(supply_payload["runtime"], frozenset({"path", "version", "digest"}))
    if payload_runtime != {
        "path": l0.RUNTIME_PATH,
        "version": l0.RUNTIME_VERSION,
        "digest": l0.RUNTIME_DIGEST,
    }:
        _invalid("SUPPLY_PAYLOAD_MISMATCH")
    payload_image = _closed(
        supply_payload["image"],
        frozenset({"image_id", "rootfs_manifest_digest", "platform", "architecture"}),
    )
    if (
        payload_image["image_id"] != "ubuntu-noble-20260814-amd64"
        or payload_image["platform"] != "linux"
        or payload_image["architecture"] != "x86_64"
    ):
        _invalid("SUPPLY_PAYLOAD_MISMATCH")
    _digest(payload_image["rootfs_manifest_digest"])
    registry = _closed(
        supply_payload["registry"],
        frozenset({"snapshot_digest", "reference", "generation", "rollback_floor", "issued_at", "expires_at"}),
    )
    if (
        registry["snapshot_digest"] != runtime["registry_snapshot_digest"]
        or registry["generation"] != 1
        or registry["rollback_floor"] < trust["rollback_floor"]
        or supply["issued_at"] != registry["issued_at"]
        or supply["expires_at"] != registry["expires_at"]
    ):
        _invalid("SUPPLY_PAYLOAD_MISMATCH")
    _string(registry["reference"], identifier=True)
    registry_issued = _timestamp(registry["issued_at"])
    registry_expires = _timestamp(registry["expires_at"])
    signer = _closed(
        supply_payload["signer"],
        frozenset(
            {
                "trust_root_id", "signer_id", "key_id", "algorithm", "revocation_epoch",
                "rollback_floor", "verifier_code_digest", "verifier_public_key_digest",
                "verifier_libcrypto_digest",
            }
        ),
    )
    if (
        signer["trust_root_id"] != trust["trust_root_id"]
        or signer["signer_id"] != trust["signer_id"]
        or signer["key_id"] != trust["key_id"]
        or signer["algorithm"] != "ED25519"
        or signer["revocation_epoch"] != 0
        or signer["rollback_floor"] < trust["rollback_floor"]
        or signer["verifier_code_digest"] != verifier_binding["code_digest"]
        or signer["verifier_public_key_digest"] != verifier_binding["public_key_digest"]
        or signer["verifier_libcrypto_digest"] != verifier_binding["libcrypto_digest"]
    ):
        _invalid("SUPPLY_SIGNER_MISMATCH")
    placement = _closed(
        supply_payload["placement"],
        frozenset(
            {
                "placement_id", "host_id", "subject_instance_id", "process_tree_id",
                "session_id", "nonce", "fencing_epoch", "revocation_epoch",
                "rootfs_binding_digest", "staging_binding_digest", "cgroup_binding_digest",
                "broker_binding_digest", "fd_inventory_digest", "namespace_plan_digest",
                "issued_at", "expires_at", "profile_digest", "measurement_digest",
                "runtime_digest",
            }
        ),
    )
    for key in (
        "rootfs_binding_digest", "staging_binding_digest", "cgroup_binding_digest",
        "broker_binding_digest", "fd_inventory_digest", "namespace_plan_digest",
    ):
        _digest(placement[key])
    placement_issued = _timestamp(placement["issued_at"])
    placement_expires = _timestamp(placement["expires_at"])
    placement_preimage = {key: placement[key] for key in sorted(placement)}
    if (
        placement["profile_digest"] != compiled.profile_digest
        or placement["measurement_digest"] != supply_payload["measurement_digest"]
        or placement["runtime_digest"] != l0.RUNTIME_DIGEST
        or placement["fencing_epoch"] != 1
        or placement["revocation_epoch"] != 0
        or supply_payload["placement_digest"] != _digest_bytes(_canonical(placement_preimage))
        or supply["placement_digest"] != supply_payload["placement_digest"]
        or not registry_issued <= _timestamp(supply_payload["observed_at"]) < registry_expires
        or not placement_issued <= _timestamp(supply_payload["observed_at"]) < placement_expires
    ):
        _invalid("SUPPLY_PLACEMENT_MISMATCH")
    supply_artifacts = supply_payload["artifacts"]
    required_supply_roles = {
        "ROOTFS_MANIFEST", "LOADER", "DEPENDENCY_CLOSURE", "TOOL", "SBOM",
        "REGISTRY_SNAPSHOT", "SECCOMP_PROFILE", "LSM_POLICY",
    }
    if type(supply_artifacts) is not list or len(supply_artifacts) != len(required_supply_roles):
        _invalid("SUPPLY_ARTIFACT_MISMATCH")
    supply_artifact_by_role: dict[str, dict[str, object]] = {}
    supply_artifact_keys = frozenset(
        {
            "role", "artifact_id", "expected_bytes_digest", "actual_bytes_digest",
            "provenance_digest", "device", "inode", "size", "mode", "binding_digest",
        }
    )
    for row in supply_artifacts:
        item = _closed(row, supply_artifact_keys)
        role = _string(item["role"], identifier=True)
        preimage = {key: item[key] for key in sorted(item) if key != "binding_digest"}
        if (
            role not in required_supply_roles
            or role in supply_artifact_by_role
            or item["expected_bytes_digest"] != item["actual_bytes_digest"]
            or item["binding_digest"] != _digest_bytes(_canonical(preimage))
        ):
            _invalid("SUPPLY_ARTIFACT_MISMATCH")
        _string(item["artifact_id"], identifier=True)
        for key in ("expected_bytes_digest", "actual_bytes_digest", "provenance_digest", "binding_digest"):
            _digest(item[key])
        _integer(item["device"])
        _integer(item["inode"], minimum=1)
        _integer(item["size"], minimum=1)
        _integer(item["mode"], minimum=0, maximum=0o7777)
        supply_artifact_by_role[role] = item
    if set(supply_artifact_by_role) != required_supply_roles:
        _invalid("SUPPLY_ARTIFACT_MISMATCH")
    _signed_record(
        supply_payload,
        supply["verification_record"],
        supply_payload["observed_at"],
        trust,
        public_key,
        now,
        expected_revocation_epoch=0,
        expected_fencing_epoch=1,
    )

    principals = _validate_principals(value["principals"], raw_profile)
    if placement["session_id"] != principals["AGENT_WORKER"]["session_id"]:
        _invalid("SUPPLY_PLACEMENT_MISMATCH")

    measurements = _closed(
        value["measurements"],
        frozenset(
            {
                "resource_vector", "cgroup", "quota", "mounts", "opened_artifacts",
                "broker_ipc", "controller", "resource_oracles",
            }
        ),
    )
    if measurements["resource_vector"] != raw_profile["resources"]:
        _invalid("RESOURCE_VECTOR_MISMATCH")
    cgroup = _closed(measurements["cgroup"], frozenset({"path", "controllers", "limits", "delegated", "isolated", "cgroup_kill", "populated_after_cleanup"}))
    if set(_string_list(cgroup["controllers"], minimum=4)) != {"cpu", "io", "memory", "pids"}:
        _invalid("CGROUP_MISMATCH")
    limits = _closed(cgroup["limits"], frozenset({"cpu.max", "io.max", "memory.max", "memory.swap.max", "pids.max"}))
    for key, item in limits.items():
        text = _string(item, maximum=256)
        if text == "max" or (key == "io.max" and "max" in text):
            _invalid("UNBOUNDED_RESOURCE")
    if not all(_boolean(cgroup[key]) for key in ("delegated", "isolated", "cgroup_kill")) or cgroup["populated_after_cleanup"] != 0:
        _invalid("CGROUP_MISMATCH")
    _string(cgroup["path"])
    quota = _closed(measurements["quota"], frozenset({"bytes", "files", "inodes", "mount_options", "outside_writes"}))
    resources = {row["resource"]: row["limit"] for row in raw_profile["resources"]}
    if (
        quota["bytes"] != resources["OUTPUT_BYTES"]
        or quota["files"] != resources["FILES"]
        or quota["inodes"] != resources["INODES"]
        or quota["outside_writes"] != 0
        or "size=" not in _string(quota["mount_options"])
        or "nr_inodes=" not in str(quota["mount_options"])
    ):
        _invalid("QUOTA_MISMATCH")
    mounts = _closed(measurements["mounts"], frozenset({"rootfs_read_only", "inputs_read_only", "staging_worker_visible", "checkout_visible", "git_visible", "home_visible", "durable_db_visible", "private_proc", "private_non_propagating"}))
    if (
        not _boolean(mounts["rootfs_read_only"])
        or not _boolean(mounts["inputs_read_only"])
        or any(_boolean(mounts[key]) for key in ("staging_worker_visible", "checkout_visible", "git_visible", "home_visible", "durable_db_visible"))
        or not _boolean(mounts["private_proc"])
        or not _boolean(mounts["private_non_propagating"])
    ):
        _invalid("MOUNT_MISMATCH")
    artifacts = measurements["opened_artifacts"]
    required_artifacts = {
        "ROOTFS_MANIFEST", "BWRAP", "AA_EXEC", "PYTHON", "LOADER", "TOOL",
        "SECCOMP_BPF", "APPARMOR_POLICY", "SBOM", "REGISTRY_SNAPSHOT",
    }
    if type(artifacts) is not list or len(artifacts) != len(required_artifacts):
        _invalid("ARTIFACT_MISMATCH")
    artifact_rows: dict[str, dict[str, object]] = {}
    for row in artifacts:
        item = _closed(row, frozenset({"role", "path", "device", "inode", "bytes", "digest"}))
        role = _string(item["role"], identifier=True)
        if role in artifact_rows:
            _invalid("ARTIFACT_MISMATCH")
        _string(item["path"])
        _integer(item["device"])
        _integer(item["inode"], minimum=1)
        _integer(item["bytes"], minimum=1)
        _digest(item["digest"])
        artifact_rows[role] = item
    if set(artifact_rows) != required_artifacts:
        _invalid("ARTIFACT_MISMATCH")
    if supply["actual_opened_bytes_digest"] != _digest_bytes(_canonical(artifacts)):
        _invalid("ARTIFACT_MISMATCH")
    evidence_to_supply = {
        "ROOTFS_MANIFEST": "ROOTFS_MANIFEST",
        "LOADER": "LOADER",
        "TOOL": "TOOL",
        "SECCOMP_BPF": "SECCOMP_PROFILE",
        "APPARMOR_POLICY": "LSM_POLICY",
        "SBOM": "SBOM",
        "REGISTRY_SNAPSHOT": "REGISTRY_SNAPSHOT",
    }
    for evidence_role, supply_role in evidence_to_supply.items():
        if artifact_rows[evidence_role]["digest"] != supply_artifact_by_role[supply_role]["actual_bytes_digest"]:
            _invalid("ARTIFACT_MISMATCH")
    if (
        artifact_rows["BWRAP"]["digest"] != backend["digest"]
        or artifact_rows["AA_EXEC"]["digest"] != runtime["aa_exec"]["digest"]
        or artifact_rows["PYTHON"]["digest"] != runtime["python"]["digest"]
        or artifact_rows["ROOTFS_MANIFEST"]["digest"] != payload_image["rootfs_manifest_digest"]
        or artifact_rows["ROOTFS_MANIFEST"]["digest"] != bindings["rootfs_manifest_digest"]
        or artifact_rows["LOADER"]["digest"] != supply["loader_digest"]
        or artifact_rows["TOOL"]["digest"] != supply["tool_digest"]
        or artifact_rows["SECCOMP_BPF"]["digest"] != runtime["seccomp_bpf_digest"]
        or artifact_rows["APPARMOR_POLICY"]["digest"] != runtime["apparmor_policy_digest"]
        or artifact_rows["SBOM"]["digest"] != runtime["sbom_digest"]
        or artifact_rows["REGISTRY_SNAPSHOT"]["digest"] != runtime["registry_snapshot_digest"]
        or supply["dependency_closure_digest"]
        != supply_artifact_by_role["DEPENDENCY_CLOSURE"]["actual_bytes_digest"]
    ):
        _invalid("ARTIFACT_BINDING_MISMATCH")
    _validate_broker_ipc(
        measurements["broker_ipc"], raw_profile, principals, trust, public_key, now
    )
    _validate_controller(
        measurements["controller"], principals["CONTROLLER"], verifier_binding, manifest
    )
    _validate_resource_oracles(measurements["resource_oracles"], resources, cgroup)

    tests = value["tests"]
    if type(tests) is not list or len(tests) != len(_TEST_MATRIX):
        _invalid("TEST_SET_MISMATCH")
    test_rows: dict[str, dict[str, object]] = {}
    observed_matrix: set[str] = set()
    for row in tests:
        item = _closed(row, frozenset({"id", "matrix_ids", "command", "exit_code", "oracle", "result", "event_ids"}))
        test_id = _string(item["id"], identifier=True)
        if test_id not in _TEST_MATRIX or test_id in test_rows:
            _invalid("TEST_SET_MISMATCH")
        matrix = _string_list(item["matrix_ids"], maximum=16)
        if tuple(matrix) != _TEST_MATRIX[test_id]:
            _invalid("TEST_MATRIX_MISMATCH")
        observed_matrix.update(matrix)
        command = _string_list(item["command"], minimum=1, maximum=64, unique=False)
        if any("--skip" in part.lower() or part in {"sh", "bash", "-c"} for part in command):
            _invalid("TEST_COMMAND_MISMATCH")
        if item["exit_code"] != 0 or item["result"] != "PASS":
            _invalid("TEST_FAILED")
        _string(item["oracle"], maximum=4096)
        _string_list(item["event_ids"], minimum=1, maximum=16)
        test_rows[test_id] = item
    if set(test_rows) != set(_TEST_MATRIX) or not _REQUIRED_MATRIX.issubset(observed_matrix):
        _invalid("TEST_SET_MISMATCH")

    events = value["events"]
    if type(events) is not list or not len(_TEST_MATRIX) <= len(events) <= 256:
        _invalid("EVENT_SET_MISMATCH")
    event_rows: dict[str, dict[str, object]] = {}
    event_types: set[str] = set()
    for row in events:
        item = _closed(row, frozenset({"event_id", "type", "test_id", "subject", "observed_digest", "oracle_digest", "result"}))
        event_id = _string(item["event_id"], identifier=True)
        event_type = _string(item["type"], identifier=True)
        test_id = _string(item["test_id"], identifier=True)
        if event_id in event_rows or event_type not in _EVENT_TYPES or test_id not in test_rows or item["result"] != "PASS":
            _invalid("EVENT_SET_MISMATCH")
        _string(item["subject"], identifier=True)
        _digest(item["observed_digest"])
        _digest(item["oracle_digest"])
        event_rows[event_id] = item
        event_types.add(event_type)
    for test_id, row in test_rows.items():
        for event_id in row["event_ids"]:
            if event_id not in event_rows or event_rows[event_id]["test_id"] != test_id:
                _invalid("EVENT_SET_MISMATCH")
    if not _EVENT_TYPES.issubset(event_types):
        _invalid("EVENT_SET_MISMATCH")

    lifecycle = _closed(
        value["lifecycle"],
        frozenset({"prepared_event_id", "terminal_event_id", "terminal_state", "restart_event_id", "cleanup_event_id", "old_session_resumed", "retry_created", "uncertainty_disposition", "cgroup_populated_after_cleanup", "orphan_processes_after_cleanup"}),
    )
    for key in ("prepared_event_id", "terminal_event_id", "restart_event_id", "cleanup_event_id"):
        if lifecycle[key] not in event_rows:
            _invalid("LIFECYCLE_MISMATCH")
    if (
        lifecycle["terminal_state"] not in {"STOPPED", "QUARANTINED"}
        or _boolean(lifecycle["old_session_resumed"])
        or _boolean(lifecycle["retry_created"])
        or lifecycle["uncertainty_disposition"] != "QUARANTINED_ESCROW"
        or lifecycle["cgroup_populated_after_cleanup"] != 0
        or lifecycle["orphan_processes_after_cleanup"] != 0
    ):
        _invalid("LIFECYCLE_MISMATCH")

    canaries = _closed(value["canaries"], frozenset({"staging_before", "staging_after", "checkout_before", "checkout_after", "home_before", "home_after", "secret_before", "secret_after", "durable_db_before", "durable_db_after", "outside_before", "outside_after"}))
    for item in canaries.values():
        _digest(item)
    if canaries["staging_before"] == canaries["staging_after"]:
        _invalid("STAGING_CANARY_UNCHANGED")
    for name in ("checkout", "home", "secret", "durable_db", "outside"):
        if canaries[f"{name}_before"] != canaries[f"{name}_after"]:
            _invalid("OUTSIDE_CANARY_CHANGED")
    if supply["profile_digest"] != manifest["profile"]["compiled_profile_digest"]:
        _invalid("CROSS_BINDING_MISMATCH")


def _verify_bundle(
    bundle: Path,
    *,
    root: Path = ROOT,
    trust_config: Path = TRUST_CONFIG,
    public_key: Path = TRUST_PUBLIC_KEY,
    source_state: dict[str, object] | None = None,
    now: datetime | None = None,
    host_lab: Path | None = LAB,
) -> dict[str, object]:
    directory = os.lstat(bundle)
    if not stat.S_ISDIR(directory.st_mode) or stat.S_IMODE(directory.st_mode) & 0o022:
        _invalid("UNTRUSTED_BUNDLE_DIRECTORY")
    if frozenset(os.listdir(bundle)) != _BUNDLE_FILES:
        _invalid("BUNDLE_FILE_SET_MISMATCH")
    manifest_bytes = _read_regular(bundle / "manifest.json", 1 << 20)
    signature = _read_regular(bundle / "manifest.sig", 128)
    evidence_bytes = _read_regular(bundle / "evidence.json", 8 << 20)
    manifest = _strict_json(manifest_bytes)
    trust, key_bytes = _load_trust(trust_config, public_key)
    _verify_signature(
        str(trust["verifier_openssl"]["path"]),
        key_bytes,
        manifest_bytes,
        signature,
    )
    source = source_state if source_state is not None else _source_state(root)
    verification_time = datetime.now(UTC) if now is None else now
    raw_profile, evidence_binding = _validate_manifest(
        manifest,
        trust,
        source,
        root,
        verification_time,
    )
    if evidence_binding["bytes"] != len(evidence_bytes) or evidence_binding["digest"] != _digest_bytes(evidence_bytes):
        _invalid("EVIDENCE_DIGEST_MISMATCH")
    evidence = _strict_json(evidence_bytes)
    _validate_evidence(
        evidence, raw_profile, manifest, trust, key_bytes, root, verification_time, host_lab
    )
    return {
        "gate_version": 2,
        "claim": "M3_TEST_PROFILE_RUNTIME_CONFORMANCE",
        "claim_status": "M3_TEST_PROFILE_RUNTIME_CONFORMANCE_VERIFIED",
        "outcome": "VERIFIED",
        "reason": "CONFORMANCE_VERIFIED",
        "product_status": "NOT_ATTESTED",
        "commit": source["commit"],
        "tree": source["tree"],
        "manifest_digest": _digest_bytes(manifest_bytes),
        "evidence_bundle_digest": _digest_bytes(_canonical({"manifest": _digest_bytes(manifest_bytes), "signature": _digest_bytes(signature), "evidence": _digest_bytes(evidence_bytes)})),
        "profile_digest": manifest["profile"]["compiled_profile_digest"],
        "image_digest": evidence["image"]["sha256"],
        "kernel_digest": evidence["guest"]["kernel_digest"],
        "runtime_digest": evidence["runtime"]["backend"]["digest"],
        "host_verifier_openssl_digest": trust["verifier_openssl"]["digest"],
        "residual_risk": _RESIDUAL_RISK,
    }


def _unattested_record() -> dict[str, object]:
    profile_bytes = PROFILE.read_bytes()
    raw = json.loads(profile_bytes)
    compiled = l0.compile_profile(raw)
    result = l0.runtime_conformance(raw)
    runtime_actual = l0._binary_digest(l0.RUNTIME_PATH)
    code_artifacts = {
        path.relative_to(ROOT).as_posix(): _digest_bytes(path.read_bytes())
        for path in sorted((SRC / "harness_product").glob("*.py"))
    }
    kernel = {"architecture": platform.machine(), "kernel_release": platform.release()}
    environment = {"gid": os.getgid(), "python": platform.python_version(), "uid": os.getuid()}
    return {
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
        "runtime": {"path": l0.RUNTIME_PATH, "version": l0.RUNTIME_VERSION, "expected_digest": l0.RUNTIME_DIGEST, "actual_digest": runtime_actual},
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


def _failure_record(reason: str) -> dict[str, object]:
    return {
        "gate_version": 2,
        "claim": "M3_TEST_PROFILE_RUNTIME_CONFORMANCE",
        "outcome": "ABSENT",
        "reason": reason,
        "status": "NOT_ATTESTED",
    }


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    try:
        if not arguments:
            record = _unattested_record()
        elif len(arguments) == 2 and arguments[0] == "--evidence":
            record = _verify_bundle(Path(arguments[1]))
        else:
            record = _failure_record("UNKNOWN_OR_MISSING_ARGUMENT")
    except _InvalidEvidence as error:
        record = _failure_record(str(error))
    except Exception:  # noqa: BLE001 - the public gate is total and fail-closed
        record = _failure_record("HOST_FAILURE")
    record["evidence_digest"] = _digest_bytes(_canonical(record))
    print(_canonical(record).decode("utf-8"))
    return 0 if record["outcome"] == "VERIFIED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
