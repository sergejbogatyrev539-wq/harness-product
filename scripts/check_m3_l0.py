#!/usr/bin/env python3
"""Non-skipping exact-profile M3 availability and signed-evidence gate.

With no arguments this command only measures the current developer host and is
expected to return ABSENT. ``--evidence`` verifies a fixed three-file bundle
against a repository-pinned public test root. It never launches a worker and
never accepts a caller supplied boolean, digest, key, or image tag as proof.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
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
    for fixed in ("AGENTS.md", "ROADMAP.md", "STATUS.json", "README.md", "SECURITY.md", "docs/ARCHITECTURE.md", "spec/MANIFEST.sha256"):
        if (root / fixed).is_file():
            paths.append(fixed)
    if len(paths) != len(set(paths)) or not paths:
        _invalid("SOURCE_FILE_SET_INVALID")
    files = {path: _digest_bytes(_read_regular(root / path, 16 << 20)) for path in sorted(paths)}
    return {"commit": commit, "tree": tree, "files": files, "files_digest": _digest_bytes(_canonical(files))}


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
                "public_key_pem_digest", "public_key_fingerprint", "openssl", "rollback_floor",
                "revocation_state_digest", "scope",
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
    openssl = _closed(trust["openssl"], frozenset({"path", "version", "digest"}))
    if openssl["path"] != "/usr/bin/openssl":
        _invalid("OPENSSL_MISMATCH")
    expected_openssl = _digest(openssl["digest"])
    if _digest_bytes(_read_regular(Path(str(openssl["path"])), 8 << 20)) != expected_openssl:
        _invalid("OPENSSL_MISMATCH")
    version = _run([str(openssl["path"]), "version"]).decode("utf-8").strip()
    if version != openssl["version"]:
        _invalid("OPENSSL_MISMATCH")
    public_key = _read_regular(public_key_path, 65536)
    if _digest_bytes(public_key) != trust["public_key_pem_digest"]:
        _invalid("PUBLIC_KEY_MISMATCH")
    der = _run([str(openssl["path"]), "pkey", "-pubin", "-outform", "DER"], input_bytes=public_key)
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
                "revocation_state_digest", "nonce",
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
    if _integer(attestation["rollback_floor"], minimum=1) < int(trust["rollback_floor"]):
        _invalid("ATTESTATION_ROLLBACK")
    _string(attestation["nonce"], identifier=True)
    evidence = _closed(value["evidence"], frozenset({"path", "bytes", "digest"}))
    if evidence["path"] != "evidence.json":
        _invalid("EVIDENCE_PATH_MISMATCH")
    _integer(evidence["bytes"], minimum=2, maximum=8 << 20)
    _digest(evidence["digest"])
    return raw_profile, evidence


def _validate_evidence(
    raw: object,
    raw_profile: dict[str, object],
    manifest: dict[str, object],
    trust: dict[str, object],
    root: Path,
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
        frozenset({"qemu_path", "qemu_version", "qemu_digest", "machine", "kvm_api", "vcpus", "memory_bytes", "overlay_virtual_bytes", "seed_digest", "management_address", "shared_host_mounts"}),
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
    ):
        _invalid("VM_MISMATCH")
    _digest(vm["seed_digest"])

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
        frozenset({"backend", "aa_exec", "openssl", "python", "apparmor_parser", "dependencies", "apparmor_policy_digest", "seccomp_policy_digest", "seccomp_bpf_digest", "sbom_digest", "registry_snapshot_digest", "profile_digest", "code_digest", "package_index_digest"}),
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

    supply = _closed(
        value["supply"],
        frozenset({"image_digest", "rootfs_digest", "runtime_digest", "loader_digest", "dependency_closure_digest", "tool_digest", "sbom_digest", "registry_snapshot_digest", "key_id", "issued_at", "expires_at", "revocation_epoch", "rollback_floor", "revocation_state_digest", "profile_digest", "placement_digest", "actual_opened_bytes_digest", "verification_payload_digest"}),
    )
    for key in (
        "image_digest", "rootfs_digest", "runtime_digest", "loader_digest", "dependency_closure_digest",
        "tool_digest", "sbom_digest", "registry_snapshot_digest", "revocation_state_digest", "profile_digest",
        "placement_digest", "actual_opened_bytes_digest", "verification_payload_digest",
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
    ):
        _invalid("SUPPLY_MISMATCH")
    _timestamp(supply["issued_at"])
    _timestamp(supply["expires_at"])

    principal_value = _closed(value["principals"], frozenset({"active", "disabled"}))
    active = principal_value["active"]
    if type(active) is not list or len(active) != 5:
        _invalid("PRINCIPAL_MISMATCH")
    profile_principals = {row["role"]: row for row in raw_profile["principals"] if row["enabled"]}
    expected_labels = {
        "ATTESTOR": "harness-l0-lx-a.attestor",
        "CONTROLLER": "harness-l0-lx-a.controller",
        "AGENT_WORKER": profile_principals["AGENT_WORKER"]["security_label"],
        "BROKER": profile_principals["BROKER"]["security_label"],
        "EXECUTOR": profile_principals["EXECUTOR"]["security_label"],
    }
    seen_roles: set[str] = set()
    host_ids: set[tuple[int, int]] = set()
    sessions: set[str] = set()
    credentials: set[str] = set()
    active_namespace_sets: list[tuple[str, ...]] = []
    for row in active:
        item = _closed(
            row,
            frozenset({"role", "launcher_uid", "launcher_gid", "host_uid", "host_gid", "namespace_uid", "namespace_gid", "session_id", "process_id", "cgroup", "security_label", "credential_namespace", "namespace_ids", "fd_inventory", "network"}),
        )
        role = _string(item["role"], identifier=True)
        if role not in expected_labels or role in seen_roles or item["security_label"] != expected_labels[role]:
            _invalid("PRINCIPAL_MISMATCH")
        seen_roles.add(role)
        identity = (_integer(item["host_uid"]), _integer(item["host_gid"]))
        if identity in host_ids:
            _invalid("PRINCIPAL_MISMATCH")
        host_ids.add(identity)
        for key in ("launcher_uid", "launcher_gid", "namespace_uid", "namespace_gid", "process_id"):
            _integer(item[key])
        session = _string(item["session_id"], identifier=True)
        credential = _string(item["credential_namespace"], identifier=True)
        if session in sessions or credential in credentials:
            _invalid("PRINCIPAL_MISMATCH")
        sessions.add(session)
        credentials.add(credential)
        _string(item["cgroup"])
        namespaces = _closed(item["namespace_ids"], frozenset({"user", "mount", "pid", "ipc", "uts", "network", "cgroup"}))
        namespace_tuple = tuple(_string(namespaces[key], identifier=True) for key in sorted(namespaces))
        if role in {"AGENT_WORKER", "BROKER", "EXECUTOR"}:
            active_namespace_sets.append(namespace_tuple)
        fds = item["fd_inventory"]
        if type(fds) is not list or any(type(fd) is not int or fd < 0 for fd in fds) or len(fds) != len(set(fds)):
            _invalid("FD_INVENTORY_MISMATCH")
        network = _closed(item["network"], frozenset({"ipv4", "ipv6", "loopback", "routes", "dns", "raw", "packet", "broad_unix", "connected_fds"}))
        if role == "AGENT_WORKER" and (any(_boolean(network[key]) for key in network) or fds != [3]):
            _invalid("WORKER_NETWORK_OR_FD_MISMATCH")
    if seen_roles != set(expected_labels) or len(set(active_namespace_sets)) != 3:
        _invalid("PRINCIPAL_MISMATCH")
    disabled = principal_value["disabled"]
    if type(disabled) is not list or len(disabled) != 2:
        _invalid("DISABLED_ROLE_MISMATCH")
    disabled_roles: set[str] = set()
    for row in disabled:
        item = _closed(row, frozenset({"role", "enabled", "process", "route", "fd", "credential"}))
        disabled_roles.add(_string(item["role"], identifier=True))
        if any(_boolean(item[key]) for key in ("enabled", "process", "route", "fd", "credential")):
            _invalid("DISABLED_ROLE_MISMATCH")
    if disabled_roles != {"MODEL_GATEWAY", "OBSERVER"}:
        _invalid("DISABLED_ROLE_MISMATCH")

    measurements = _closed(value["measurements"], frozenset({"resource_vector", "cgroup", "quota", "mounts", "opened_artifacts"}))
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
    required_artifacts = {"ROOTFS", "BWRAP", "AA_EXEC", "PYTHON", "SECCOMP_BPF", "APPARMOR_POLICY", "SBOM", "REGISTRY_SNAPSHOT"}
    if type(artifacts) is not list or len(artifacts) != len(required_artifacts):
        _invalid("ARTIFACT_MISMATCH")
    roles: set[str] = set()
    for row in artifacts:
        item = _closed(row, frozenset({"role", "path", "device", "inode", "bytes", "digest"}))
        roles.add(_string(item["role"], identifier=True))
        _string(item["path"])
        _integer(item["device"])
        _integer(item["inode"], minimum=1)
        _integer(item["bytes"], minimum=1)
        _digest(item["digest"])
    if roles != required_artifacts:
        _invalid("ARTIFACT_MISMATCH")

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
    _verify_signature(str(trust["openssl"]["path"]), key_bytes, manifest_bytes, signature)
    source = source_state if source_state is not None else _source_state(root)
    raw_profile, evidence_binding = _validate_manifest(
        manifest,
        trust,
        source,
        root,
        datetime.now(UTC) if now is None else now,
    )
    if evidence_binding["bytes"] != len(evidence_bytes) or evidence_binding["digest"] != _digest_bytes(evidence_bytes):
        _invalid("EVIDENCE_DIGEST_MISMATCH")
    evidence = _strict_json(evidence_bytes)
    _validate_evidence(evidence, raw_profile, manifest, trust, root)
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
