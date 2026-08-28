#!/usr/bin/env python3
"""Single-host entrypoint for the exact disposable M4 qualification VM."""

from __future__ import annotations

import base64
from io import BytesIO
from datetime import UTC, datetime
import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import tarfile
import time
from typing import BinaryIO, Callable, NamedTuple, NoReturn


ROOT = Path(__file__).resolve().parents[1]
LAB = Path("/home/a1/Загрузки/harness/harness-m4-qualification-v2")
OLD_QUALIFICATION_LAB = Path("/home/a1/Загрузки/harness/harness-m4-lab")
DIAGNOSTIC_LAB = Path("/home/a1/Загрузки/harness/harness-m4-diagnostic-lab")
POST_V2_DIAGNOSTIC_LAB = Path(
    "/home/a1/Загрузки/harness/harness-m4-post-v2-diagnostic"
)
PACKAGE_PLAN_DISCRIMINATOR_LAB = Path(
    "/home/a1/Загрузки/harness/harness-m4-package-plan-discriminator"
)
IMAGE_LAB = Path("/home/a1/Загрузки/harness/harness-m3-lab")
EVIDENCE_ROOT = Path("/home/a1/Загрузки/harness/harness-m4-evidence-v2")
ONE_USE_QUALIFICATION_ROOT = Path(
    "/home/a1/Загрузки/harness/harness-m4-one-use-qualification"
)
ONE_USE_EVIDENCE_ROOT = Path(
    "/home/a1/Загрузки/harness/harness-m4-one-use-evidence"
)
USER_GOAL = Path(
    "/home/a1/.codex/attachments/4adf762e-32a5-45e2-bf75-3c79125ace23/"
    "pasted-text.txt"
)
LEDGER_NAME = "m4-attempt-ledger.jsonl"
INDEPENDENT_VERIFICATION_NAME = "independent-verification.json"
DIAGNOSTIC_LEDGER_NAME = "m4-key-ready-diagnostic-ledger.jsonl"
POST_V2_DIAGNOSTIC_LEDGER_NAME = "m4-post-v2-diagnostic-ledger.jsonl"
PACKAGE_PLAN_DISCRIMINATOR_LEDGER_NAME = (
    "m4-package-plan-discriminator-ledger.jsonl"
)
PACKAGE_PLAN_DISCRIMINATOR_LEDGER = (
    PACKAGE_PLAN_DISCRIMINATOR_LAB / PACKAGE_PLAN_DISCRIMINATOR_LEDGER_NAME
)
PACKAGE_PLAN_DISCRIMINATOR_LEDGER_DIGEST = (
    "sha256:f6a93ebc7f06447ed2be71f1e43c2c65d488bd9a5cb9a26cc3f03b7252f77cc3"
)
PACKAGE_PLAN_DISCRIMINATOR_BUNDLE = (
    PACKAGE_PLAN_DISCRIMINATOR_LAB / "diagnostics/attempt-1/diagnostic.json"
)
PACKAGE_PLAN_DISCRIMINATOR_BUNDLE_DIGEST = (
    "sha256:e42fbd54170edcabe49814366ccf8fa7452eb6b167d50c2c799d2d611d95b623"
)
OLD_LEDGER = OLD_QUALIFICATION_LAB / LEDGER_NAME
OLD_LEDGER_DIGEST = "sha256:719505206caf364c6c0d40983687416bcca5644f879a46254714621cb070d5f9"
PREDECESSOR_DIAGNOSTIC_LEDGER = DIAGNOSTIC_LAB / DIAGNOSTIC_LEDGER_NAME
PREDECESSOR_DIAGNOSTIC_LEDGER_DIGEST = (
    "sha256:6d5d1d00dc2fc303a061c1fc6f3456fb1e6c9fb1c1baae3f667a6521f8382d78"
)
PREDECESSOR_DIAGNOSTIC_BUNDLE = (
    DIAGNOSTIC_LAB / "diagnostics/attempt-1/diagnostic.json"
)
PREDECESSOR_DIAGNOSTIC_BUNDLE_DIGEST = (
    "sha256:91abc47ad6070c8b9c8cad89369780b698a696c3e90aed5e2c84cb45f0b1418d"
)
FAILED_QUALIFICATION_V2_LEDGER = LAB / LEDGER_NAME
FAILED_QUALIFICATION_V2_LEDGER_DIGEST = (
    "sha256:c80f4eb33b811b59a4f80aee5fdf781964b441d20e1620ca4b1f2b63f30c479a"
)
FAILED_QUALIFICATION_V2_CANDIDATE = "a2336eb987364cc6bff0fdcdc7d7bfb8b21b3db8"
FAILED_QUALIFICATION_V2_TREE = "106facb47f1b203ed121917adfa7c885374d9fdc"
POST_V2_DIAGNOSTIC_GOAL_REFERENCE = (
    "thread:/goal/m4-post-v2-pre-admission-diagnostic/2026-08-28"
)
POST_V2_DIAGNOSTIC_GOAL_DIGEST = (
    "sha256:7e171d5a592859fc7a49e91ec1dca61d11ec326bbe1083ee5511f70163b9bc70"
)
POST_V2_DIAGNOSTIC_LEDGER = (
    POST_V2_DIAGNOSTIC_LAB / POST_V2_DIAGNOSTIC_LEDGER_NAME
)
POST_V2_DIAGNOSTIC_LEDGER_DIGEST = (
    "sha256:e8cfa1b9117268bf2298ba1936a99a79114e8f83aea2188e998fce6becdf97dc"
)
POST_V2_DIAGNOSTIC_BUNDLE = (
    POST_V2_DIAGNOSTIC_LAB / "diagnostics/attempt-1/diagnostic.json"
)
POST_V2_DIAGNOSTIC_BUNDLE_DIGEST = (
    "sha256:51b84c6477a17a66e92290ed7cb6f787fb9df8f5445d112d76e3e38c055f6d2f"
)
PACKAGE_PLAN_DISCRIMINATOR_GOAL_REFERENCE = (
    "thread:/goal/m4-package-runtime-plan-discriminator/2026-08-28"
)
PACKAGE_PLAN_DISCRIMINATOR_GOAL_DIGEST = (
    "sha256:44ff546b459a3e433b0b9ed1d009eb92c82b9fd1f3afc5f331a1ba0fe51115aa"
)
_QEMU_PATH = "/usr/bin/qemu-system-x86_64"
_QEMU_DIGEST = "sha256:8a35ccba41582fc6c38b9df85fc9e35fa1d42f414d2d7d8090ee9b2f5e7c0854"
_OVERLAY_VIRTUAL_BYTES = 3758096384
_IMAGE_URL = (
    "https://cloud-images.ubuntu.com/releases/noble/release-20260814/"
    "ubuntu-24.04-server-cloudimg-amd64.img"
)
_IMAGE_DIGEST = "sha256:6e40c07ae715f744f84af0bec76415cc1987dd115b4b8de437818561f01a3733"
_M4_PROFILE_DIGEST = "sha256:50947b4b4ae139effbaddd749c7175a15755675f824e0ae1ed734a85694b4682"
_UBUNTU_SOURCE_BYTES = 321
_UBUNTU_SOURCE_DIGEST = (
    "sha256:eafe8bd9490d039ddaa42d1ca6e2682b0a4e68fe13845aa47d8c195292574d55"
)
_UBUNTU_SOURCE_FINAL_PATH = "/etc/apt/sources.list.d/ubuntu.sources"
_UBUNTU_SOURCE_SEED_PATH = "/etc/harness-m4/apt-ubuntu.sources"
_PACKAGE_SOURCE_BOUNDARY_PATH = (
    "/var/lib/harness-m4-provisioning/package-source-boundaries.jsonl"
)
_SUMS_DIGEST = "sha256:0f92d5610dfc5797f9574a5a8a000021d845c70c70f6b187b2b78eb1584618cf"
_SUMS_SIGNATURE_DIGEST = "sha256:a4466d91a9481850908ce0e8c518ebb1cf3ca414add6ba378e783c7d553618a7"
_UBUNTU_SIGNER = "D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81"
_IMAGE_NAME = "ubuntu-24.04-server-cloudimg-amd64.img"
_MANAGEMENT_PORT = 22227
_MAX_SEED_BYTES = 16 << 20
_MAX_PHASE_LOG_BYTES = 64 << 20
_MAX_BUNDLE_BYTES = 10 << 20
_HOST_RESERVE_BYTES = 4 << 30
_SOURCE_FIXED = (
    "AGENTS.md", "README.md", "ROADMAP.md", "SECURITY.md", "STATUS.json",
    "docs/ARCHITECTURE.md", "profiles/harness-m3-controller@.service",
    "profiles/harness-m4-controller@.service", "profiles/m4-lx-a.apparmor",
    "profiles/m4-lx-a.json", "spec/MANIFEST.sha256",
)
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_TIME = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
ONE_USE_SCOPE_PROJECTION_KIND = "M4_ONE_USE_QUALIFICATION_SCOPE_PROJECTION"
ONE_USE_QUALIFICATION_CONTRACT_KIND = (
    "M4_REQUEST_BOUND_ONE_USE_QUALIFICATION"
)
_ONE_USE_SCOPE_PROJECTION_KEYS = frozenset(
    {
        "record_version", "record_kind", "authority",
        "user_scope_reference", "candidate", "tree", "max_attempts",
        "success_target", "success_target_authorizing",
        "predecessor_qualification_ledger_digest",
        "predecessor_diagnostic_ledger_digest",
        "predecessor_diagnostic_bundle_digest",
    }
)
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
            "attempt_start_digest", "receipt_public_key_digests",
            "supply_public_key_digest", "runtime_trust_digest",
            "admitted_qualification_contract_digest",
        }
    ),
    "POST_KEY_RUN_FAILURE": frozenset(
        {
            "attempt_start_digest", "key_admission_digest",
            "failure_stage", "reason",
        }
    ),
    "ATTEMPT_TERMINAL": frozenset(
        {
            "attempt_start_digest", "key_admission_digest", "result",
            "terminal_reason", "manifest_digest", "signed_payload_bundle_digest",
            "qemu_phase_outcomes",
        }
    ),
}
POST_KEY_RUN_FAILURE_REASONS = frozenset(
    {
        "UNAVAILABLE",
        "KEY_ADMISSION_REQUIRED",
        "L0_PROFILE_MALFORMED",
        "L0_PROFILE_TEMPLATE_MUTATION",
        "L0_DYNAMIC_PROFILE_COMPILE_FAILED",
        "L0_SECCOMP_PROFILE_MALFORMED",
        "L0_SECCOMP_BINDING_MISMATCH",
        "M4_ROLE_ROOTFS_INPUT_MALFORMED",
        "M4_SECCOMP_PROFILE_MALFORMED",
        "M4_ROLE_LAUNCH_MALFORMED",
        "M4_ROLE_CGROUP_ATTACH_FAILED",
        "M4_ROLE_OUTER_GATE_RELEASE_FAILED",
        "M4_ROLE_IDENTITY_MISMATCH",
        "M4_ROLE_RESULT_MALFORMED",
        "M4_ROLE_FAILED",
        "M4_ROLE_CLEANUP_FAILED",
        "M4_AUTHORITY_CONTEXT_ABSENT",
        "M4_TOPOLOGY_ABSENT",
        "M4_FRONTIER_BIND_FAILED",
        "M4_RUNTIME_JOIN_FAILED",
        "M4_PRE_RESTART_DURABLE_MISMATCH",
        "M4_RUNTIME_STORAGE_CLEANUP_MISMATCH",
        "M4_RUNTIME_STORAGE_CLEANUP_FAILED",
        "M4_PUBLICATION_EVIDENCE_ABSENT",
    }
)
_POST_KEY_RUN_FAILURE_STAGE = "POST_KEY_RUN_SERVICE_FAILED"
_TERMINAL_RESULTS = frozenset({"BUNDLE_EXPORTED", "FAILED", "BLOCKED", "QUARANTINED"})
_TERMINAL_REASON_BY_RESULT = {
    "BUNDLE_EXPORTED": frozenset({"SIGNED_PAYLOAD_EXPORTED"}),
    "FAILED": frozenset(
        {
            "PROVISION_FAILED", "QEMU_EXITED", "SERVICE_FAILED_PRE_KEY_READY",
            "KEY_READY_TIMEOUT", "KEY_ADMISSION_FAILED", "RUN_FAILED",
            "RECOVERY_FAILED", "EVIDENCE_EXPORT_FAILED",
            "EVIDENCE_VERIFICATION_FAILED", "CLEANUP_FAILED",
        }
    ),
    "BLOCKED": frozenset({"HOST_PREFLIGHT_FAILED", "ATTEMPT_LIMIT_REACHED"}),
    "QUARANTINED": frozenset(
        {
            "PROVISION_FAILED", "QEMU_EXITED", "SERVICE_FAILED_PRE_KEY_READY",
            "KEY_READY_TIMEOUT", "KEY_ADMISSION_FAILED", "RUN_FAILED",
            "RECOVERY_FAILED", "EVIDENCE_EXPORT_FAILED",
            "EVIDENCE_VERIFICATION_FAILED", "CLEANUP_FAILED",
        }
    ),
}
_DIAGNOSTIC_REASONS = frozenset(
    {
        "PROVISION_FAILED", "QEMU_EXITED", "SERVICE_FAILED_PRE_KEY_READY",
        "KEY_READY_TIMEOUT", "KEY_READY_REACHED", "CLEANUP_FAILED",
    }
)
PACKAGE_RUNTIME_PLAN_BINDING_IDS = (
    "PROVISIONING_SCRIPT",
    "PACKAGE_VERSION_APPARMOR",
    "PACKAGE_VERSION_APPARMOR_UTILS",
    "PACKAGE_VERSION_BUBBLEWRAP",
    "PACKAGE_VERSION_LIBSSL3T64",
    "PACKAGE_VERSION_OPENSSL",
    "PACKAGE_VERSION_PYTHON3_12",
    "PACKAGE_SOURCE_APT_HARNESS_M4",
    "PACKAGE_SOURCE_UBUNTU",
    "RUNTIME_CONFIG_HOSTS",
    "RUNTIME_CONFIG_NFTABLES_OFFLINE",
    "RUNTIME_CONFIG_NFTABLES_PROVISIONING",
    "RUNTIME_TOOL_AA_EXEC",
    "RUNTIME_TOOL_BWRAP",
    "RUNTIME_TOOL_OPENSSL",
    "RUNTIME_TOOL_PYTHON3_12",
    "RUNTIME_TOOL_LIBCRYPTO",
    "RUNTIME_TOOL_APPARMOR_PARSER",
)
PACKAGE_RUNTIME_PLAN_OUTCOMES = frozenset(
    {"MISMATCH", "QUERY_ERROR", "DECODE_ERROR", "READ_ERROR", "RESOLVE_ERROR"}
)
PACKAGE_RUNTIME_PLAN_OBSERVATION_ERRORS = frozenset(
    {
        "DUPLICATE", "KEY_READY_FORBIDDEN", "MALFORMED", "MISSING",
        "ORDER_MISMATCH", "UNKNOWN",
    }
)
_PACKAGE_RUNTIME_PLAN_PARSER_ERRORS = {
    "POST_V2_PACKAGE_RUNTIME_PLAN_OBSERVATION_DUPLICATE": "DUPLICATE",
    "POST_V2_PACKAGE_RUNTIME_PLAN_OBSERVATION_MALFORMED": "MALFORMED",
    "POST_V2_PACKAGE_RUNTIME_PLAN_OBSERVATION_MISSING": "MISSING",
    "POST_V2_PACKAGE_RUNTIME_PLAN_OBSERVATION_ORDER_MISMATCH": (
        "ORDER_MISMATCH"
    ),
    "POST_V2_PACKAGE_RUNTIME_PLAN_OBSERVATION_UNKNOWN": "UNKNOWN",
}
_PACKAGE_RUNTIME_PLAN_REJECTED = (
    "PACKAGE_RUNTIME_PLAN_OBSERVATION_REJECTED"
)
_PACKAGE_RUNTIME_PLAN_OBSERVATION_KEYS = frozenset(
    {"record_type", "non_authorizing", "binding_id", "outcome"}
)
_PACKAGE_SOURCE_BOUNDARY_KEYS = frozenset(
    {
        "record_type", "non_authorizing", "binding_id", "boundary", "outcome",
        "expected_sha256", "observed_sha256",
    }
)
_PACKAGE_SOURCE_BOUNDARIES = (
    "BEFORE_APT_GET_UPDATE",
    "AFTER_EXACT_PACKAGE_INSTALL_AND_CLEAN",
)
_PACKAGE_SOURCE_BOUNDARY_OUTCOMES = frozenset(
    {"MATCH", "MISMATCH", "READ_ERROR"}
)
_PACKAGE_SOURCE_BOUNDARY_TOKEN = b'"M4_PACKAGE_SOURCE_BOUNDARY_OBSERVATION"'
_SERVICE_PROPERTIES = (
    "ActiveState", "SubState", "Result", "ExecMainCode", "ExecMainStatus",
)
_DIAGNOSTIC_DISPOSABLE_NAMES = (
    "overlay.qcow2", "seed.iso", "ssh-client", "ssh-client.pub", "ssh-host",
    "ssh-host.pub", "known_hosts", "user-data", "meta-data", "source.tgz",
    "host-provenance.json", "qualification.json", "provision.qemu.log",
    "provision.serial.log", "run.qemu.log", "run.serial.log",
)


class QualificationStop(Exception):
    pass


class VMCleanupUnproven(QualificationStop):
    pass


def _stop(reason: str) -> NoReturn:
    raise QualificationStop(reason)


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as error:
        raise QualificationStop("NONCANONICAL_JSON") from error


def _strict_json(raw: bytes, maximum: int) -> object:
    if type(raw) is not bytes or not raw or len(raw) > maximum:
        _stop("MALFORMED_JSON")

    def pairs(rows: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in rows:
            if type(key) is not str or key in value:
                _stop("DUPLICATE_JSON_KEY")
            value[key] = item
        return value

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=pairs,
            parse_constant=lambda _: _stop("NONFINITE_JSON"),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise QualificationStop("MALFORMED_JSON") from error
    if _canonical(value) != raw:
        _stop("NONCANONICAL_JSON")
    return value


def _digest_bytes(raw: bytes) -> str:
    return "sha256:" + sha256(raw).hexdigest()


class OneUsePaths(NamedTuple):
    lab: Path
    evidence: Path


def _validate_one_use_scope_projection(value: object) -> dict[str, object]:
    if type(value) is not dict or frozenset(value) != _ONE_USE_SCOPE_PROJECTION_KEYS:
        _stop("ONE_USE_SCOPE_PROJECTION_MALFORMED")
    reference = value["user_scope_reference"]
    if type(reference) is not str or not reference:
        _stop("ONE_USE_SCOPE_PROJECTION_BINDING_MISMATCH")
    try:
        reference_bytes = reference.encode("utf-8")
    except UnicodeEncodeError:
        _stop("ONE_USE_SCOPE_PROJECTION_BINDING_MISMATCH")
    if (
        value["record_version"] != "1.0.0"
        or value["record_kind"] != ONE_USE_SCOPE_PROJECTION_KIND
        or value["authority"] != "NONE"
        or len(reference_bytes) > 512
        or type(value["candidate"]) is not str
        or _COMMIT.fullmatch(value["candidate"]) is None
        or type(value["tree"]) is not str
        or _COMMIT.fullmatch(value["tree"]) is None
        or type(value["max_attempts"]) is not int
        or isinstance(value["max_attempts"], bool)
        or value["max_attempts"] != 1
        or type(value["success_target"]) is not int
        or isinstance(value["success_target"], bool)
        or value["success_target"] != 1
        or value["success_target_authorizing"] is not False
        or value["predecessor_qualification_ledger_digest"]
        != FAILED_QUALIFICATION_V2_LEDGER_DIGEST
        or value["predecessor_diagnostic_ledger_digest"]
        != PACKAGE_PLAN_DISCRIMINATOR_LEDGER_DIGEST
        or value["predecessor_diagnostic_bundle_digest"]
        != PACKAGE_PLAN_DISCRIMINATOR_BUNDLE_DIGEST
    ):
        _stop("ONE_USE_SCOPE_PROJECTION_BINDING_MISMATCH")
    return value


def _one_use_scope_projection_digest(value: object) -> str:
    projection = _validate_one_use_scope_projection(value)
    try:
        return _digest_bytes(_canonical(projection))
    except UnicodeEncodeError:
        _stop("ONE_USE_SCOPE_PROJECTION_BINDING_MISMATCH")


def _read_one_use_scope_projection(path: Path) -> tuple[dict[str, object], str]:
    try:
        value = _strict_json(_read_regular(path, 4096), 4096)
    except UnicodeEncodeError:
        _stop("ONE_USE_SCOPE_PROJECTION_MALFORMED")
    projection = _validate_one_use_scope_projection(value)
    return projection, _one_use_scope_projection_digest(projection)


def _one_use_run_id(projection_digest: str) -> str:
    if type(projection_digest) is not str or _DIGEST.fullmatch(projection_digest) is None:
        _stop("ONE_USE_SCOPE_PROJECTION_DIGEST_MISMATCH")
    return "scope-" + projection_digest.removeprefix("sha256:")


def _one_use_paths(
    projection_digest: str,
    *,
    qualification_root: Path | None = None,
    evidence_root: Path | None = None,
) -> OneUsePaths:
    run_id = _one_use_run_id(projection_digest)
    qualification_base = (
        ONE_USE_QUALIFICATION_ROOT
        if qualification_root is None
        else qualification_root
    )
    evidence_base = ONE_USE_EVIDENCE_ROOT if evidence_root is None else evidence_root
    return OneUsePaths(qualification_base / run_id, evidence_base / run_id)


def _read_regular(path: Path, maximum: int) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as error:
        raise QualificationStop("UNTRUSTED_FILE") from error
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_size < 1
            or info.st_size > maximum
            or stat.S_IMODE(info.st_mode) & 0o022
        ):
            _stop("UNTRUSTED_FILE")
        remaining = info.st_size
        chunks: list[bytes] = []
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                _stop("SHORT_READ")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            _stop("UNBOUNDED_READ")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _digest_file(path: Path, maximum: int) -> str:
    return _digest_bytes(_read_regular(path, maximum))


def _qualification_contract(
    *,
    goal_reference: str,
    goal_digest: str,
    candidate: str,
    tree: str,
    attempt: int,
    source_files_digest: str,
    source_archive_digest: str,
    seed_digest: str,
    package_runtime_plan_digest: str,
    host_provenance_digest: str,
) -> dict[str, object]:
    core = {
        "contract_version": "2.0.0",
        "contract_kind": "M4_EXACT_DISPOSABLE_TEST_PROFILE_QUALIFICATION_V2",
        "user_scope_reference": goal_reference,
        "user_goal_digest": goal_digest,
        "candidate": candidate,
        "tree": tree,
        "attempt": attempt,
        "source_files_digest": source_files_digest,
        "canonical_profile_digest": _M4_PROFILE_DIGEST,
        "raw_profile_artifact_digest": _M4_PROFILE_DIGEST,
        "base_image_digest": _IMAGE_DIGEST,
        "predecessor_qualification_ledger_digest": OLD_LEDGER_DIGEST,
        "predecessor_diagnostic_ledger_digest": PREDECESSOR_DIAGNOSTIC_LEDGER_DIGEST,
        "predecessor_diagnostic_bundle_digest": PREDECESSOR_DIAGNOSTIC_BUNDLE_DIGEST,
        "max_attempts": 2,
        "success_target": 1,
        "success_target_authorizing": False,
    }
    core_digest = _digest_bytes(_canonical(core))
    environment_preimage = {
        "contract_core_digest": core_digest,
        "source_archive_digest": source_archive_digest,
        "seed_digest": seed_digest,
        "package_runtime_plan_digest": package_runtime_plan_digest,
        "host_provenance_digest": host_provenance_digest,
    }
    contract = {
        "contract_core": core,
        "contract_core_digest": core_digest,
        "environment_preimage": environment_preimage,
        "environment_digest": _digest_bytes(_canonical(environment_preimage)),
    }
    return _validate_v2_qualification_contract(contract)


def _validate_v2_qualification_contract(value: object) -> dict[str, object]:
    if type(value) is not dict or frozenset(value) != {
        "contract_core", "contract_core_digest", "environment_preimage",
        "environment_digest",
    }:
        _stop("QUALIFICATION_CONTRACT_MALFORMED")
    core = value["contract_core"]
    core_keys = {
        "contract_version", "contract_kind", "user_scope_reference",
        "user_goal_digest", "candidate", "tree", "attempt",
        "source_files_digest", "canonical_profile_digest",
        "raw_profile_artifact_digest", "base_image_digest",
        "predecessor_qualification_ledger_digest",
        "predecessor_diagnostic_ledger_digest",
        "predecessor_diagnostic_bundle_digest", "max_attempts",
        "success_target", "success_target_authorizing",
    }
    if type(core) is not dict or frozenset(core) != core_keys:
        _stop("QUALIFICATION_CONTRACT_MALFORMED")
    digests = (
        core["user_goal_digest"], core["source_files_digest"],
        core["canonical_profile_digest"], core["raw_profile_artifact_digest"],
        core["base_image_digest"], core["predecessor_qualification_ledger_digest"],
        core["predecessor_diagnostic_ledger_digest"],
        core["predecessor_diagnostic_bundle_digest"],
    )
    if (
        core["contract_version"] != "2.0.0"
        or core["contract_kind"]
        != "M4_EXACT_DISPOSABLE_TEST_PROFILE_QUALIFICATION_V2"
        or type(core["user_scope_reference"]) is not str
        or not core["user_scope_reference"]
        or type(core["candidate"]) is not str
        or _COMMIT.fullmatch(core["candidate"]) is None
        or type(core["tree"]) is not str
        or _COMMIT.fullmatch(core["tree"]) is None
        or type(core["attempt"]) is not int
        or isinstance(core["attempt"], bool)
        or core["attempt"] not in {1, 2}
        or any(type(item) is not str or _DIGEST.fullmatch(item) is None for item in digests)
        or core["canonical_profile_digest"] != _M4_PROFILE_DIGEST
        or core["raw_profile_artifact_digest"] != _M4_PROFILE_DIGEST
        or core["base_image_digest"] != _IMAGE_DIGEST
        or core["predecessor_qualification_ledger_digest"] != OLD_LEDGER_DIGEST
        or core["predecessor_diagnostic_ledger_digest"]
        != PREDECESSOR_DIAGNOSTIC_LEDGER_DIGEST
        or core["predecessor_diagnostic_bundle_digest"]
        != PREDECESSOR_DIAGNOSTIC_BUNDLE_DIGEST
        or core["max_attempts"] != 2
        or core["success_target"] != 1
        or core["success_target_authorizing"] is not False
    ):
        _stop("QUALIFICATION_CONTRACT_BINDING_MISMATCH")
    core_digest = _digest_bytes(_canonical(core))
    environment = value["environment_preimage"]
    if (
        value["contract_core_digest"] != core_digest
        or type(environment) is not dict
        or frozenset(environment)
        != {
            "contract_core_digest", "source_archive_digest", "seed_digest",
            "package_runtime_plan_digest", "host_provenance_digest",
        }
        or environment["contract_core_digest"] != core_digest
        or any(
            type(environment[name]) is not str
            or _DIGEST.fullmatch(environment[name]) is None
            for name in (
                "source_archive_digest", "seed_digest",
                "package_runtime_plan_digest", "host_provenance_digest",
            )
        )
        or value["environment_digest"] != _digest_bytes(_canonical(environment))
    ):
        _stop("QUALIFICATION_CONTRACT_DIGEST_MISMATCH")
    return value


def _one_use_qualification_contract(
    *,
    projection: object,
    projection_digest: str,
    source_files_digest: str,
    source_archive_digest: str,
    seed_digest: str,
    package_runtime_plan_digest: str,
    host_provenance_digest: str,
) -> dict[str, object]:
    scope = _strict_json(
        _canonical(_validate_one_use_scope_projection(projection)), 4096
    )
    if projection_digest != _one_use_scope_projection_digest(scope):
        _stop("ONE_USE_SCOPE_PROJECTION_DIGEST_MISMATCH")
    core = {
        "contract_version": "3.0.0",
        "contract_kind": ONE_USE_QUALIFICATION_CONTRACT_KIND,
        "scope_projection": scope,
        "user_scope_reference": scope["user_scope_reference"],
        "user_goal_digest": projection_digest,
        "candidate": scope["candidate"],
        "tree": scope["tree"],
        "attempt": 1,
        "source_files_digest": source_files_digest,
        "canonical_profile_digest": _M4_PROFILE_DIGEST,
        "raw_profile_artifact_digest": _M4_PROFILE_DIGEST,
        "base_image_digest": _IMAGE_DIGEST,
        "predecessor_qualification_ledger_digest": scope[
            "predecessor_qualification_ledger_digest"
        ],
        "predecessor_diagnostic_ledger_digest": scope[
            "predecessor_diagnostic_ledger_digest"
        ],
        "predecessor_diagnostic_bundle_digest": scope[
            "predecessor_diagnostic_bundle_digest"
        ],
        "max_attempts": 1,
        "success_target": 1,
        "success_target_authorizing": False,
    }
    core_digest = _digest_bytes(_canonical(core))
    environment = {
        "contract_core_digest": core_digest,
        "source_archive_digest": source_archive_digest,
        "seed_digest": seed_digest,
        "package_runtime_plan_digest": package_runtime_plan_digest,
        "host_provenance_digest": host_provenance_digest,
    }
    return _validate_one_use_qualification_contract(
        {
            "contract_core": core,
            "contract_core_digest": core_digest,
            "environment_preimage": environment,
            "environment_digest": _digest_bytes(_canonical(environment)),
        }
    )


def _validate_one_use_qualification_contract(
    value: object,
) -> dict[str, object]:
    if type(value) is not dict or frozenset(value) != {
        "contract_core", "contract_core_digest", "environment_preimage",
        "environment_digest",
    }:
        _stop("ONE_USE_QUALIFICATION_CONTRACT_MALFORMED")
    core = value["contract_core"]
    environment = value["environment_preimage"]
    core_keys = {
        "contract_version", "contract_kind", "scope_projection",
        "user_scope_reference", "user_goal_digest", "candidate", "tree",
        "attempt", "source_files_digest", "canonical_profile_digest",
        "raw_profile_artifact_digest", "base_image_digest",
        "predecessor_qualification_ledger_digest",
        "predecessor_diagnostic_ledger_digest",
        "predecessor_diagnostic_bundle_digest", "max_attempts",
        "success_target", "success_target_authorizing",
    }
    if (
        type(core) is not dict
        or frozenset(core) != core_keys
        or type(environment) is not dict
        or frozenset(environment) != {
            "contract_core_digest", "source_archive_digest", "seed_digest",
            "package_runtime_plan_digest", "host_provenance_digest",
        }
    ):
        _stop("ONE_USE_QUALIFICATION_CONTRACT_MALFORMED")
    scope = _validate_one_use_scope_projection(core["scope_projection"])
    scope_digest = _one_use_scope_projection_digest(scope)
    if (
        core["contract_version"] != "3.0.0"
        or core["contract_kind"] != ONE_USE_QUALIFICATION_CONTRACT_KIND
        or core["user_scope_reference"] != scope["user_scope_reference"]
        or core["user_goal_digest"] != scope_digest
        or core["candidate"] != scope["candidate"]
        or core["tree"] != scope["tree"]
        or type(core["attempt"]) is not int
        or isinstance(core["attempt"], bool)
        or core["attempt"] != 1
        or type(core["source_files_digest"]) is not str
        or _DIGEST.fullmatch(core["source_files_digest"]) is None
        or core["canonical_profile_digest"] != _M4_PROFILE_DIGEST
        or core["raw_profile_artifact_digest"] != _M4_PROFILE_DIGEST
        or core["base_image_digest"] != _IMAGE_DIGEST
        or core["predecessor_qualification_ledger_digest"]
        != scope["predecessor_qualification_ledger_digest"]
        or core["predecessor_diagnostic_ledger_digest"]
        != scope["predecessor_diagnostic_ledger_digest"]
        or core["predecessor_diagnostic_bundle_digest"]
        != scope["predecessor_diagnostic_bundle_digest"]
        or type(core["max_attempts"]) is not int
        or isinstance(core["max_attempts"], bool)
        or core["max_attempts"] != 1
        or type(core["success_target"]) is not int
        or isinstance(core["success_target"], bool)
        or core["success_target"] != 1
        or core["success_target_authorizing"] is not False
        or any(
            type(environment[name]) is not str
            or _DIGEST.fullmatch(environment[name]) is None
            for name in (
                "contract_core_digest", "source_archive_digest", "seed_digest",
                "package_runtime_plan_digest", "host_provenance_digest",
            )
        )
    ):
        _stop("ONE_USE_QUALIFICATION_CONTRACT_BINDING_MISMATCH")
    core_digest = _digest_bytes(_canonical(core))
    if (
        value["contract_core_digest"] != core_digest
        or environment["contract_core_digest"] != core_digest
        or value["environment_digest"] != _digest_bytes(_canonical(environment))
    ):
        _stop("ONE_USE_QUALIFICATION_CONTRACT_DIGEST_MISMATCH")
    return value


def _validate_qualification_contract(value: object) -> dict[str, object]:
    core = value.get("contract_core") if type(value) is dict else None
    selector = (
        (core.get("contract_version"), core.get("contract_kind"))
        if type(core) is dict
        else (None, None)
    )
    if selector == (
        "2.0.0", "M4_EXACT_DISPOSABLE_TEST_PROFILE_QUALIFICATION_V2"
    ):
        return _validate_v2_qualification_contract(value)
    if selector == ("3.0.0", ONE_USE_QUALIFICATION_CONTRACT_KIND):
        return _validate_one_use_qualification_contract(value)
    _stop("QUALIFICATION_CONTRACT_BINDING_MISMATCH")


def _qualification_contract_digest(contract: object) -> str:
    return _digest_bytes(_canonical(_validate_qualification_contract(contract)))


def _post_v2_diagnostic_goal_record() -> dict[str, object]:
    return {
        "goal_version": "1.0.0",
        "goal_kind": "M4_POST_V2_PRE_ADMISSION_DIAGNOSTIC",
        "user_scope_reference": POST_V2_DIAGNOSTIC_GOAL_REFERENCE,
        "predecessor_qualification_ledger_digest": (
            FAILED_QUALIFICATION_V2_LEDGER_DIGEST
        ),
        "max_attempts": 1,
        "allowed_phases": ["provision", "run"],
        "allowed_outcome": "SANITIZED_DIAGNOSTIC_ONLY",
        "forbidden_operations": [
            "AUTOMATIC_RETRY",
            "KEY_ADMISSION_ARTIFACT",
            "QUALIFICATION_EVIDENCE_EXPORT",
            "QUALIFICATION_V2_LEDGER_WRITE",
            "REBOOT_OR_RECOVERY",
            "RUNTIME_VERIFIED_CLAIM",
            "WORKER_OR_EFFECT_EXECUTION",
        ],
    }


def _package_plan_discriminator_goal_record() -> dict[str, object]:
    return {
        "goal_version": "1.0.0",
        "goal_kind": "M4_PACKAGE_RUNTIME_PLAN_DISCRIMINATOR",
        "user_scope_reference": PACKAGE_PLAN_DISCRIMINATOR_GOAL_REFERENCE,
        "predecessor_qualification_ledger_digest": (
            FAILED_QUALIFICATION_V2_LEDGER_DIGEST
        ),
        "predecessor_post_v2_diagnostic_ledger_digest": (
            POST_V2_DIAGNOSTIC_LEDGER_DIGEST
        ),
        "predecessor_post_v2_diagnostic_bundle_digest": (
            POST_V2_DIAGNOSTIC_BUNDLE_DIGEST
        ),
        "max_attempts": 1,
        "success_target": 1,
        "success_target_authorizing": False,
        "allowed_phases": ["provision", "run"],
        "allowed_outcome": (
            "SANITIZED_PACKAGE_RUNTIME_PLAN_OBSERVATION_ONLY"
        ),
        "forbidden_operations": [
            "AUTOMATIC_RETRY",
            "KEY_ADMISSION_ARTIFACT",
            "PACKAGE_PLAN_REMEDIATION",
            "POST_V2_DIAGNOSTIC_BUNDLE_MUTATION",
            "POST_V2_DIAGNOSTIC_LEDGER_WRITE",
            "QUALIFICATION_EVIDENCE_EXPORT",
            "QUALIFICATION_V2_LEDGER_WRITE",
            "REBOOT_OR_RECOVERY",
            "RUNTIME_VERIFIED_CLAIM",
            "WORKER_OR_EFFECT_EXECUTION",
        ],
    }


def _validate_post_v2_diagnostic_goal_record(value: object) -> dict[str, object]:
    if type(value) is not dict:
        _stop("POST_V2_DIAGNOSTIC_GOAL_MISMATCH")
    raw = _canonical(value)
    for expected, size, digest in (
        (
            _post_v2_diagnostic_goal_record(),
            582,
            POST_V2_DIAGNOSTIC_GOAL_DIGEST,
        ),
        (
            _package_plan_discriminator_goal_record(),
            1002,
            PACKAGE_PLAN_DISCRIMINATOR_GOAL_DIGEST,
        ),
    ):
        if (
            raw == _canonical(expected)
            and len(raw) == size
            and _digest_bytes(raw) == digest
        ):
            return value
    _stop("POST_V2_DIAGNOSTIC_GOAL_MISMATCH")


def _post_v2_diagnostic_contract(
    *,
    goal_record: object,
    candidate: str,
    tree: str,
    source_files_digest: str,
    source_archive_digest: str,
    seed_digest: str,
    package_runtime_plan_digest: str,
    host_provenance_digest: str,
) -> dict[str, object]:
    goal = _validate_post_v2_diagnostic_goal_record(goal_record)
    core = {
        "contract_version": "1.0.0",
        "contract_kind": goal["goal_kind"],
        "goal_record": goal,
        "goal_record_digest": _digest_bytes(_canonical(goal)),
        "failed_v2_candidate": FAILED_QUALIFICATION_V2_CANDIDATE,
        "failed_v2_tree": FAILED_QUALIFICATION_V2_TREE,
        "failed_qualification_v2_ledger_digest": (
            FAILED_QUALIFICATION_V2_LEDGER_DIGEST
        ),
        "candidate": candidate,
        "tree": tree,
        "attempt": 1,
        "source_files_digest": source_files_digest,
        "canonical_profile_digest": _M4_PROFILE_DIGEST,
        "raw_profile_artifact_digest": _M4_PROFILE_DIGEST,
        "base_image_digest": _IMAGE_DIGEST,
        "max_attempts": 1,
        "allowed_phases": ["provision", "run"],
        "non_authorizing": True,
    }
    if goal["goal_kind"] == "M4_PACKAGE_RUNTIME_PLAN_DISCRIMINATOR":
        core.update(
            {
                "predecessor_post_v2_diagnostic_ledger_digest": (
                    POST_V2_DIAGNOSTIC_LEDGER_DIGEST
                ),
                "predecessor_post_v2_diagnostic_bundle_digest": (
                    POST_V2_DIAGNOSTIC_BUNDLE_DIGEST
                ),
            }
        )
    core_digest = _digest_bytes(_canonical(core))
    environment_preimage = {
        "contract_core_digest": core_digest,
        "source_archive_digest": source_archive_digest,
        "seed_digest": seed_digest,
        "package_runtime_plan_digest": package_runtime_plan_digest,
        "host_provenance_digest": host_provenance_digest,
    }
    return _validate_post_v2_diagnostic_contract(
        {
            "contract_core": core,
            "contract_core_digest": core_digest,
            "environment_preimage": environment_preimage,
            "environment_digest": _digest_bytes(_canonical(environment_preimage)),
        }
    )


def _validate_post_v2_diagnostic_contract(value: object) -> dict[str, object]:
    if type(value) is not dict or frozenset(value) != {
        "contract_core", "contract_core_digest", "environment_preimage",
        "environment_digest",
    }:
        _stop("POST_V2_DIAGNOSTIC_CONTRACT_MALFORMED")
    core = value["contract_core"]
    core_keys = {
        "contract_version", "contract_kind", "goal_record",
        "goal_record_digest", "failed_v2_candidate", "failed_v2_tree",
        "failed_qualification_v2_ledger_digest", "candidate", "tree",
        "attempt", "source_files_digest", "canonical_profile_digest",
        "raw_profile_artifact_digest", "base_image_digest", "max_attempts",
        "allowed_phases", "non_authorizing",
    }
    if (
        type(core) is dict
        and core.get("contract_kind")
        == "M4_PACKAGE_RUNTIME_PLAN_DISCRIMINATOR"
    ):
        core_keys |= {
            "predecessor_post_v2_diagnostic_ledger_digest",
            "predecessor_post_v2_diagnostic_bundle_digest",
        }
    if type(core) is not dict or frozenset(core) != core_keys:
        _stop("POST_V2_DIAGNOSTIC_CONTRACT_MALFORMED")
    goal = _validate_post_v2_diagnostic_goal_record(core["goal_record"])
    discriminator = (
        goal["goal_kind"] == "M4_PACKAGE_RUNTIME_PLAN_DISCRIMINATOR"
    )
    digests = (
        core["goal_record_digest"], core["failed_qualification_v2_ledger_digest"],
        core["source_files_digest"], core["canonical_profile_digest"],
        core["raw_profile_artifact_digest"], core["base_image_digest"],
    )
    if (
        core["contract_version"] != "1.0.0"
        or core["contract_kind"] != goal["goal_kind"]
        or core["goal_record_digest"] != _digest_bytes(_canonical(goal))
        or core["failed_v2_candidate"] != FAILED_QUALIFICATION_V2_CANDIDATE
        or core["failed_v2_tree"] != FAILED_QUALIFICATION_V2_TREE
        or core["failed_qualification_v2_ledger_digest"]
        != FAILED_QUALIFICATION_V2_LEDGER_DIGEST
        or type(core["candidate"]) is not str
        or _COMMIT.fullmatch(core["candidate"]) is None
        or core["candidate"] == FAILED_QUALIFICATION_V2_CANDIDATE
        or type(core["tree"]) is not str
        or _COMMIT.fullmatch(core["tree"]) is None
        or core["tree"] == FAILED_QUALIFICATION_V2_TREE
        or type(core["attempt"]) is not int
        or core["attempt"] != 1
        or any(type(item) is not str or _DIGEST.fullmatch(item) is None for item in digests)
        or core["canonical_profile_digest"] != _M4_PROFILE_DIGEST
        or core["raw_profile_artifact_digest"] != _M4_PROFILE_DIGEST
        or core["base_image_digest"] != _IMAGE_DIGEST
        or type(core["max_attempts"]) is not int
        or core["max_attempts"] != 1
        or core["allowed_phases"] != ["provision", "run"]
        or core["non_authorizing"] is not True
        or (
            discriminator
            and (
                core["predecessor_post_v2_diagnostic_ledger_digest"]
                != POST_V2_DIAGNOSTIC_LEDGER_DIGEST
                or core["predecessor_post_v2_diagnostic_bundle_digest"]
                != POST_V2_DIAGNOSTIC_BUNDLE_DIGEST
                or core["predecessor_post_v2_diagnostic_ledger_digest"]
                != goal["predecessor_post_v2_diagnostic_ledger_digest"]
                or core["predecessor_post_v2_diagnostic_bundle_digest"]
                != goal["predecessor_post_v2_diagnostic_bundle_digest"]
            )
        )
    ):
        _stop("POST_V2_DIAGNOSTIC_CONTRACT_BINDING_MISMATCH")
    core_digest = _digest_bytes(_canonical(core))
    environment = value["environment_preimage"]
    if (
        value["contract_core_digest"] != core_digest
        or type(environment) is not dict
        or frozenset(environment) != {
            "contract_core_digest", "source_archive_digest", "seed_digest",
            "package_runtime_plan_digest", "host_provenance_digest",
        }
        or environment["contract_core_digest"] != core_digest
        or any(
            type(environment[name]) is not str
            or _DIGEST.fullmatch(environment[name]) is None
            for name in (
                "source_archive_digest", "seed_digest",
                "package_runtime_plan_digest", "host_provenance_digest",
            )
        )
        or value["environment_digest"] != _digest_bytes(_canonical(environment))
    ):
        _stop("POST_V2_DIAGNOSTIC_CONTRACT_DIGEST_MISMATCH")
    return value


def _post_v2_diagnostic_contract_digest(contract: object) -> str:
    return _digest_bytes(
        _canonical(_validate_post_v2_diagnostic_contract(contract))
    )


def _post_v2_diagnostic_request(contract: object) -> dict[str, object]:
    value = _strict_json(
        _canonical(_validate_post_v2_diagnostic_contract(contract)), 1 << 20
    )
    discriminator = (
        value["contract_core"]["contract_kind"]
        == "M4_PACKAGE_RUNTIME_PLAN_DISCRIMINATOR"
    )
    return {
        "request_version": "2.2.0" if discriminator else "2.1.0",
        "mode": (
            "M4_PACKAGE_RUNTIME_PLAN_DISCRIMINATOR"
            if discriminator
            else "POST_V2_PRE_ADMISSION_DIAGNOSTIC"
        ),
        "diagnostic_contract": value,
        "diagnostic_contract_digest": _post_v2_diagnostic_contract_digest(value),
    }


def _validate_post_v2_key_ready(
    value: object, contract: object
) -> dict[str, object]:
    expected_contract = _validate_post_v2_diagnostic_contract(contract)
    expected_digest = _post_v2_diagnostic_contract_digest(expected_contract)
    if type(value) is not dict or frozenset(value) != {
        "ready_version", "mode", "non_authorizing", "diagnostic_contract",
        "diagnostic_contract_digest", "contract_core_digest",
        "receipt_public_key_digests", "supply_public_key_digest",
        "runtime_trust_digest",
    }:
        _stop("POST_V2_KEY_READY_MALFORMED")
    ready_contract = _validate_post_v2_diagnostic_contract(
        value["diagnostic_contract"]
    )
    keys = value["receipt_public_key_digests"]
    if (
        value["ready_version"] != "2.1.0"
        or value["mode"] != "POST_V2_PRE_ADMISSION_DIAGNOSTIC"
        or value["non_authorizing"] is not True
        or _canonical(ready_contract) != _canonical(expected_contract)
        or value["diagnostic_contract_digest"] != expected_digest
        or value["contract_core_digest"]
        != expected_contract["contract_core_digest"]
        or type(keys) is not dict
        or frozenset(keys) != {"M4_AUTHORITY", "OBSERVER", "PUBLISHER"}
        or any(
            type(item) is not str or _DIGEST.fullmatch(item) is None
            for item in keys.values()
        )
        or type(value["supply_public_key_digest"]) is not str
        or _DIGEST.fullmatch(value["supply_public_key_digest"]) is None
        or type(value["runtime_trust_digest"]) is not str
        or _DIGEST.fullmatch(value["runtime_trust_digest"]) is None
    ):
        _stop("POST_V2_KEY_READY_MALFORMED")
    return value


def _package_runtime_plan() -> dict[str, object]:
    return {
        "plan_version": "1.0.0",
        "packages": {
            "apparmor": "4.0.1really4.0.1-0ubuntu0.24.04.7",
            "apparmor-utils": "4.0.1really4.0.1-0ubuntu0.24.04.7",
            "bubblewrap": "0.9.0-1ubuntu0.1",
            "libssl3t64": "3.0.13-0ubuntu3.12",
            "openssl": "3.0.13-0ubuntu3.12",
            "python3.12": "3.12.3-1ubuntu0.15",
        },
        "provisioning_script_digest": _digest_bytes(_provision_script()),
        "package_sources": {
            "/etc/apt/apt.conf.d/99-harness-m4": _digest_file(
                IMAGE_LAB / "apt-harness-m3.conf", 1 << 20
            ),
            _UBUNTU_SOURCE_FINAL_PATH: _UBUNTU_SOURCE_DIGEST,
        },
        "runtime_configs": {
            "/etc/harness-m4/nftables-offline.conf": _digest_file(
                IMAGE_LAB / "nftables-offline.conf", 1 << 20
            ),
            "/etc/harness-m4/nftables-provisioning.conf": _digest_file(
                IMAGE_LAB / "nftables-provisioning.conf", 1 << 20
            ),
            "/etc/hosts": _digest_file(IMAGE_LAB / "guest-hosts", 1 << 20),
        },
        "runtime_tools": {
            "/usr/bin/aa-exec": "sha256:f28cbce3c8664cab5154492fdbc55ecb937a3e7ce1a9478c881a5f5965d7ce3e",
            "/usr/bin/bwrap": "sha256:52231e1caf55bcbc667b269f49c63599a6f7db4767ae6a039580d0ff853db712",
            "/usr/bin/openssl": "sha256:b86b739329008369aebe1f7cff6c2adb18965609d68a19456fca55232f2908f5",
            "/usr/bin/python3.12": "sha256:1643dacd9feaedc58f3cc581e4d22577dfe25c09b10282936186ccf0f2e61118",
            "/usr/lib/x86_64-linux-gnu/libcrypto.so.3": "sha256:1451aceec262c3338052fa77542eb971d4ba311c6bf12d9aa70d0b56aca942f9",
            "/usr/sbin/apparmor_parser": "sha256:6bc852b37807961c14976be9a227ae96bd817f73b5189cb0e0ff5eca4448c01c",
        },
    }


def _ubuntu_source_seed_entry(
    package_runtime_plan: dict[str, object],
) -> tuple[str, bytes, int]:
    sources = package_runtime_plan.get("package_sources")
    try:
        raw = _read_regular(IMAGE_LAB / "apt-ubuntu.sources", _UBUNTU_SOURCE_BYTES)
    except QualificationStop as error:
        raise QualificationStop("PACKAGE_RUNTIME_PLAN_SEED_MISMATCH") from error
    if (
        type(sources) is not dict
        or sources.get(_UBUNTU_SOURCE_FINAL_PATH) != _UBUNTU_SOURCE_DIGEST
        or len(raw) != _UBUNTU_SOURCE_BYTES
        or _digest_bytes(raw) != _UBUNTU_SOURCE_DIGEST
    ):
        _stop("PACKAGE_RUNTIME_PLAN_SEED_MISMATCH")
    return _UBUNTU_SOURCE_SEED_PATH, raw, 0o444


def _qemu_argv(attempt: int, phase: str, *, lab: Path = LAB) -> list[str]:
    if type(attempt) is not int or isinstance(attempt, bool) or attempt not in {1, 2}:
        _stop("ATTEMPT_MISMATCH")
    if phase not in {"provision", "run", "recover"}:
        _stop("VM_PHASE_MISMATCH")
    attempt_root = lab / "runs" / f"attempt-{attempt}"
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


def _qemu_lifecycle(
    attempt: int,
    *,
    lab: Path = LAB,
    phases: tuple[str, ...] = ("provision", "run", "recover"),
) -> dict[str, list[str]]:
    return {phase: _qemu_argv(attempt, phase, lab=lab) for phase in phases}


def _validate_qemu_phase_outcomes(
    value: object, attempt: int, *, lab: Path = LAB
) -> dict[str, object]:
    if type(value) is not dict or frozenset(value) != {"provision", "run", "recover"}:
        _stop("QEMU_PHASE_OUTCOME_MISMATCH")
    for phase in ("provision", "run", "recover"):
        row = value[phase]
        if (
            type(row) is not dict
            or frozenset(row) != {"argv_digest", "return_code"}
            or row["argv_digest"]
            != _digest_bytes(_canonical(_qemu_argv(attempt, phase, lab=lab)))
            or type(row["return_code"]) is not int
            or isinstance(row["return_code"], bool)
            or row["return_code"] != 0
        ):
            _stop("QEMU_PHASE_OUTCOME_MISMATCH")
    return value


class AttemptStart(NamedTuple):
    attempt: int
    candidate: str
    tree: str
    environment: str
    contract_core_digest: str
    qualification_contract_digest: str
    qualification_contract: dict[str, object]
    digest: str


class AttemptLedger:
    """Append-only, exclusively locked qualification-attempt ledger."""

    def __init__(
        self,
        lab: Path,
        *,
        goal_reference: str,
        goal_digest: str,
        one_use: bool = False,
        require_fresh: bool = False,
        evidence_root: Path | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.lab = lab
        self.goal_reference = goal_reference
        self.goal_digest = goal_digest
        self.one_use = one_use
        self.require_fresh = require_fresh
        self.ledger_version = "3.0.0" if one_use else "2.0.0"
        self.max_attempts = 1 if one_use else 2
        self.ready_version = "3.0.0" if one_use else "2.0.0"
        self.evidence_root = EVIDENCE_ROOT if evidence_root is None else evidence_root
        self.clock = (lambda: datetime.now(UTC)) if clock is None else clock
        self._directory_descriptor = -1
        self._descriptor = -1
        self._rows: list[tuple[dict[str, object], str]] = []
        self._active_start: AttemptStart | None = None
        self._active_admission: str | None = None
        self._active_post_key_failure: str | None = None

    def __enter__(self) -> AttemptLedger:
        lab_created = False
        try:
            os.mkdir(self.lab, 0o700)
            lab_created = True
        except FileExistsError:
            pass
        except OSError as error:
            raise QualificationStop("LEDGER_UNTRUSTED") from error
        try:
            if self.require_fresh and not lab_created:
                _stop("QUALIFICATION_LAB_REUSE_FORBIDDEN")
            self._directory_descriptor = os.open(
                self.lab,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            directory = os.fstat(self._directory_descriptor)
            if (
                not stat.S_ISDIR(directory.st_mode)
                or directory.st_uid != os.geteuid()
                or stat.S_IMODE(directory.st_mode) != 0o700
            ):
                _stop("LEDGER_UNTRUSTED")
            if lab_created:
                _fsync_directory(self.lab.parent)
            names = set(os.listdir(self.lab))
            if (
                LEDGER_NAME not in names
                and names
                or LEDGER_NAME in names
                and not names <= {
                    LEDGER_NAME, INDEPENDENT_VERIFICATION_NAME, "runs"
                }
            ):
                _stop("QUALIFICATION_LAB_REUSE_FORBIDDEN")
            ledger_created = False
            try:
                self._descriptor = os.open(
                    LEDGER_NAME,
                    os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_EXCL
                    | os.O_CLOEXEC | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=self._directory_descriptor,
                )
                ledger_created = True
            except FileExistsError:
                self._descriptor = os.open(
                    LEDGER_NAME,
                    os.O_RDWR | os.O_APPEND | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=self._directory_descriptor,
                )
            fcntl.flock(self._descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            opened = os.fstat(self._descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or opened.st_uid != os.geteuid()
                or stat.S_IMODE(opened.st_mode) != 0o600
                or opened.st_size > 4 << 20
            ):
                _stop("LEDGER_UNTRUSTED")
            if ledger_created:
                os.fsync(self._descriptor)
                os.fsync(self._directory_descriptor)
            self._rows = self._read_and_validate()
            return self
        except (OSError, BlockingIOError) as error:
            self.__exit__(None, None, None)
            raise QualificationStop("LEDGER_UNTRUSTED") from error
        except Exception:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, _kind: object, _value: object, _traceback: object) -> None:
        if self._descriptor >= 0:
            try:
                fcntl.flock(self._descriptor, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(self._descriptor)
            self._descriptor = -1
        if self._directory_descriptor >= 0:
            os.close(self._directory_descriptor)
            self._directory_descriptor = -1

    def _read_and_validate(self) -> list[tuple[dict[str, object], str]]:
        size = os.fstat(self._descriptor).st_size
        os.lseek(self._descriptor, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        remaining = size
        while remaining:
            chunk = os.read(self._descriptor, min(65536, remaining))
            if not chunk:
                _stop("LEDGER_MALFORMED")
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if not raw:
            return []
        if not raw.endswith(b"\n") or b"\n\n" in raw:
            _stop("LEDGER_MALFORMED")
        now = self.clock().astimezone(UTC).replace(microsecond=0)
        result: list[tuple[dict[str, object], str]] = []
        previous: str | None = None
        for sequence, line in enumerate(raw[:-1].split(b"\n"), 1):
            row = _strict_json(line, 1 << 20)
            if type(row) is not dict or row.get("entry_type") not in _LEDGER_EXTRA:
                _stop("LEDGER_MALFORMED")
            if frozenset(row) != _LEDGER_COMMON | _LEDGER_EXTRA[str(row["entry_type"])]:
                _stop("LEDGER_MALFORMED")
            if (
                row["ledger_version"] != self.ledger_version
                or type(row["sequence"]) is not int
                or isinstance(row["sequence"], bool)
                or row["sequence"] != sequence
                or row["previous_entry_digest"] != previous
                or type(row["candidate"]) is not str
                or _COMMIT.fullmatch(row["candidate"]) is None
                or type(row["tree"]) is not str
                or _COMMIT.fullmatch(row["tree"]) is None
                or type(row["environment"]) is not str
                or _DIGEST.fullmatch(row["environment"]) is None
                or row["user_scope_reference"] != self.goal_reference
                or row["user_goal_digest"] != self.goal_digest
                or type(row["max_attempts"]) is not int
                or isinstance(row["max_attempts"], bool)
                or row["max_attempts"] != self.max_attempts
                or type(row["success_target"]) is not int
                or isinstance(row["success_target"], bool)
                or row["success_target"] != 1
                or row["success_target_authorizing"] is not False
                or type(row["attempt"]) is not int
                or isinstance(row["attempt"], bool)
                or row["attempt"] not in set(range(1, self.max_attempts + 1))
                or type(row["contract_core_digest"]) is not str
                or _DIGEST.fullmatch(row["contract_core_digest"]) is None
                or type(row["qualification_contract_digest"]) is not str
                or _DIGEST.fullmatch(row["qualification_contract_digest"]) is None
                or type(row["recorded_at"]) is not str
                or _TIME.fullmatch(row["recorded_at"]) is None
            ):
                _stop("LEDGER_BINDING_MISMATCH")
            recorded = datetime.strptime(row["recorded_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
            if recorded > now:
                _stop("LEDGER_BINDING_MISMATCH")
            self._validate_row(
                row,
                one_use=self.one_use,
                lab=self.lab if self.one_use else LAB,
            )
            digest = _digest_bytes(line)
            result.append((row, digest))
            previous = digest
        self._validate_lifecycle(result, max_attempts=self.max_attempts)
        return result

    @staticmethod
    def _validate_row(
        row: dict[str, object], *, one_use: bool = False, lab: Path = LAB
    ) -> None:
        if row["entry_type"] == "ATTEMPT_STARTED":
            contract = _validate_qualification_contract(row["qualification_contract"])
            core = contract["contract_core"]
            if (
                type(core) is not dict
                or (
                    core.get("contract_kind")
                    == ONE_USE_QUALIFICATION_CONTRACT_KIND
                ) is not one_use
                or row["candidate"] != core["candidate"]
                or row["tree"] != core["tree"]
                or row["environment"] != contract["environment_digest"]
                or row["attempt"] != core["attempt"]
                or row["user_scope_reference"] != core["user_scope_reference"]
                or row["user_goal_digest"] != core["user_goal_digest"]
                or row["max_attempts"] != core["max_attempts"]
                or row["success_target"] != core["success_target"]
                or row["success_target_authorizing"]
                is not core["success_target_authorizing"]
                or row["contract_core_digest"] != contract["contract_core_digest"]
                or row["qualification_contract_digest"]
                != _qualification_contract_digest(contract)
            ):
                _stop("LEDGER_BINDING_MISMATCH")
        elif row["entry_type"] == "KEY_ADMITTED":
            keys = row["receipt_public_key_digests"]
            if type(keys) is not dict or frozenset(keys) != {
                "M4_AUTHORITY", "OBSERVER", "PUBLISHER"
            }:
                _stop("LEDGER_BINDING_MISMATCH")
            values = [
                row["attempt_start_digest"], row["supply_public_key_digest"],
                row["runtime_trust_digest"],
                row["admitted_qualification_contract_digest"], *keys.values(),
            ]
            if any(type(value) is not str or _DIGEST.fullmatch(value) is None for value in values):
                _stop("LEDGER_BINDING_MISMATCH")
            if (
                row["admitted_qualification_contract_digest"]
                != row["qualification_contract_digest"]
            ):
                _stop("LEDGER_BINDING_MISMATCH")
        elif row["entry_type"] == "POST_KEY_RUN_FAILURE":
            if (
                type(row["attempt_start_digest"]) is not str
                or _DIGEST.fullmatch(row["attempt_start_digest"]) is None
                or type(row["key_admission_digest"]) is not str
                or _DIGEST.fullmatch(row["key_admission_digest"]) is None
                or type(row["failure_stage"]) is not str
                or row["failure_stage"] != _POST_KEY_RUN_FAILURE_STAGE
                or type(row["reason"]) is not str
                or row["reason"] not in POST_KEY_RUN_FAILURE_REASONS
            ):
                _stop("LEDGER_BINDING_MISMATCH")
        elif row["entry_type"] == "ATTEMPT_TERMINAL":
            if (
                row["result"] not in _TERMINAL_RESULTS
                or row["terminal_reason"]
                not in _TERMINAL_REASON_BY_RESULT[row["result"]]
                or type(row["attempt_start_digest"]) is not str
                or _DIGEST.fullmatch(row["attempt_start_digest"]) is None
            ):
                _stop("LEDGER_BINDING_MISMATCH")
            if row["result"] == "BUNDLE_EXPORTED":
                values = [
                    row["key_admission_digest"], row["manifest_digest"],
                    row["signed_payload_bundle_digest"],
                ]
                if any(type(value) is not str or _DIGEST.fullmatch(value) is None for value in values):
                    _stop("LEDGER_BINDING_MISMATCH")
                _validate_qemu_phase_outcomes(
                    row["qemu_phase_outcomes"], row["attempt"], lab=lab
                )
            elif (
                row["manifest_digest"] is not None
                or row["signed_payload_bundle_digest"] is not None
                or row["qemu_phase_outcomes"] is not None
                or (
                    row["key_admission_digest"] is not None
                    and (
                        type(row["key_admission_digest"]) is not str
                        or _DIGEST.fullmatch(row["key_admission_digest"]) is None
                    )
                )
            ):
                _stop("LEDGER_BINDING_MISMATCH")

    @staticmethod
    def _validate_lifecycle(
        rows: list[tuple[dict[str, object], str]], *, max_attempts: int = 2
    ) -> None:
        cursor = 0
        attempt = 1
        pairs: set[tuple[object, object]] = set()
        while cursor < len(rows):
            start, start_digest = rows[cursor]
            pair = (start["candidate"], start["environment"])
            if (
                start["entry_type"] != "ATTEMPT_STARTED"
                or start["attempt"] != attempt
                or pair in pairs
            ):
                _stop("LEDGER_LIFECYCLE_MISMATCH")
            pairs.add(pair)
            cursor += 1
            admission: tuple[dict[str, object], str] | None = None
            if cursor < len(rows) and rows[cursor][0]["entry_type"] == "KEY_ADMITTED":
                admission = rows[cursor]
                cursor += 1
            post_key_failure: tuple[dict[str, object], str] | None = None
            if (
                cursor < len(rows)
                and rows[cursor][0]["entry_type"] == "POST_KEY_RUN_FAILURE"
            ):
                post_key_failure = rows[cursor]
                cursor += 1
            if cursor >= len(rows) or rows[cursor][0]["entry_type"] != "ATTEMPT_TERMINAL":
                _stop("PRIOR_ATTEMPT_UNRESOLVED")
            terminal, _ = rows[cursor]
            cursor += 1
            group = (
                ([] if admission is None else [admission[0]])
                + ([] if post_key_failure is None else [post_key_failure[0]])
                + [terminal]
            )
            if any(
                any(
                    row[key] != start[key]
                    for key in (
                        "candidate", "tree", "environment", "attempt",
                        "contract_core_digest", "qualification_contract_digest",
                    )
                )
                for row in group
            ):
                _stop("LEDGER_LIFECYCLE_MISMATCH")
            if terminal["attempt_start_digest"] != start_digest:
                _stop("LEDGER_LIFECYCLE_MISMATCH")
            if admission is None:
                if terminal["key_admission_digest"] is not None:
                    _stop("LEDGER_LIFECYCLE_MISMATCH")
            elif (
                admission[0]["attempt_start_digest"] != start_digest
                or terminal["key_admission_digest"] != admission[1]
            ):
                _stop("LEDGER_LIFECYCLE_MISMATCH")
            if post_key_failure is not None and (
                admission is None
                or post_key_failure[0]["attempt_start_digest"] != start_digest
                or post_key_failure[0]["key_admission_digest"] != admission[1]
                or terminal["result"] != "QUARANTINED"
                or terminal["terminal_reason"] not in {"RUN_FAILED", "CLEANUP_FAILED"}
            ):
                _stop("LEDGER_LIFECYCLE_MISMATCH")
            if terminal["result"] == "BUNDLE_EXPORTED" and admission is None:
                _stop("LEDGER_LIFECYCLE_MISMATCH")
            attempt += 1
        if attempt - 1 > max_attempts:
            _stop("LEDGER_LIFECYCLE_MISMATCH")

    def _recorded_at(self) -> str:
        return self.clock().astimezone(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")

    def _append(self, entry_type: str, start: AttemptStart, extra: dict[str, object]) -> str:
        previous = None if not self._rows else self._rows[-1][1]
        row = {
            "ledger_version": self.ledger_version,
            "sequence": len(self._rows) + 1,
            "previous_entry_digest": previous,
            "entry_type": entry_type,
            "recorded_at": self._recorded_at(),
            "candidate": start.candidate,
            "tree": start.tree,
            "environment": start.environment,
            "user_scope_reference": self.goal_reference,
            "user_goal_digest": self.goal_digest,
            "max_attempts": self.max_attempts,
            "success_target": 1,
            "success_target_authorizing": False,
            "attempt": start.attempt,
            "contract_core_digest": start.contract_core_digest,
            "qualification_contract_digest": start.qualification_contract_digest,
            **extra,
        }
        raw = _canonical(row)
        digest = _digest_bytes(raw)
        line = raw + b"\n"
        try:
            if os.write(self._descriptor, line) != len(line):
                _stop("LEDGER_APPEND_FAILED")
            os.fsync(self._descriptor)
        except OSError as error:
            raise QualificationStop("LEDGER_APPEND_FAILED") from error
        self._rows.append((row, digest))
        return digest

    def begin(self, qualification_contract: object) -> AttemptStart:
        if self._active_start is not None:
            _stop("ATTEMPT_ALREADY_STARTED")
        contract = _strict_json(
            _canonical(_validate_qualification_contract(qualification_contract)),
            1 << 20,
        )
        if type(contract) is not dict:
            _stop("QUALIFICATION_CONTRACT_MALFORMED")
        core = contract["contract_core"]
        if type(core) is not dict:
            _stop("QUALIFICATION_CONTRACT_MALFORMED")
        if (
            core.get("contract_kind") == ONE_USE_QUALIFICATION_CONTRACT_KIND
        ) is not self.one_use:
            _stop("ATTEMPT_BINDING_MISMATCH")
        attempt = self.next_attempt()
        starts = [row for row, _ in self._rows if row["entry_type"] == "ATTEMPT_STARTED"]
        if (
            core["user_scope_reference"] != self.goal_reference
            or core["user_goal_digest"] != self.goal_digest
            or core["attempt"] != attempt
            or any(
                row["candidate"] == core["candidate"]
                and row["environment"] == contract["environment_digest"]
                for row in starts
            )
        ):
            _stop("ATTEMPT_BINDING_MISMATCH")
        contract_digest = _qualification_contract_digest(contract)
        provisional = AttemptStart(
            attempt,
            str(core["candidate"]),
            str(core["tree"]),
            str(contract["environment_digest"]),
            str(contract["contract_core_digest"]),
            contract_digest,
            contract,
            "",
        )
        digest = self._append(
            "ATTEMPT_STARTED",
            provisional,
            {"qualification_contract": contract},
        )
        self._active_start = AttemptStart(*provisional[:-1], digest)
        return self._active_start

    def next_attempt(self) -> int:
        marker = self.lab / INDEPENDENT_VERIFICATION_NAME
        if marker.exists() or marker.is_symlink():
            _validate_independent_verification(
                self, _strict_json(_read_regular(marker, 1 << 20), 1 << 20)
            )
            _stop("QUALIFICATION_ALREADY_VERIFIED")
        starts = [row for row, _ in self._rows if row["entry_type"] == "ATTEMPT_STARTED"]
        if len(starts) >= self.max_attempts:
            _stop("ATTEMPT_LIMIT_REACHED")
        return len(starts) + 1

    def admit(self, start: AttemptStart, ready: object) -> str:
        if start != self._active_start or self._active_admission is not None:
            _stop("KEY_ADMISSION_ORDER_MISMATCH")
        if type(ready) is not dict or frozenset(ready) != {
            "ready_version", "candidate", "environment", "attempt",
            "qualification_contract",
            "qualification_contract_digest", "contract_core_digest",
            "receipt_public_key_digests", "supply_public_key_digest",
            "runtime_trust_digest",
        }:
            _stop("KEY_READY_MALFORMED")
        ready_contract = _validate_qualification_contract(
            ready["qualification_contract"]
        )
        keys = ready["receipt_public_key_digests"]
        if (
            ready["ready_version"] != self.ready_version
            or ready["candidate"] != start.candidate
            or ready["environment"] != start.environment
            or ready["attempt"] != start.attempt
            or _canonical(ready_contract) != _canonical(start.qualification_contract)
            or ready["qualification_contract_digest"]
            != start.qualification_contract_digest
            or ready["qualification_contract_digest"]
            != _qualification_contract_digest(ready_contract)
            or ready["contract_core_digest"] != start.contract_core_digest
            or type(keys) is not dict
            or frozenset(keys) != {"M4_AUTHORITY", "OBSERVER", "PUBLISHER"}
            or any(type(value) is not str or _DIGEST.fullmatch(value) is None for value in keys.values())
            or type(ready["supply_public_key_digest"]) is not str
            or _DIGEST.fullmatch(ready["supply_public_key_digest"]) is None
            or type(ready["runtime_trust_digest"]) is not str
            or _DIGEST.fullmatch(ready["runtime_trust_digest"]) is None
        ):
            _stop("KEY_READY_MALFORMED")
        self._active_admission = self._append(
            "KEY_ADMITTED",
            start,
            {
                "attempt_start_digest": start.digest,
                "admitted_qualification_contract_digest": (
                    start.qualification_contract_digest
                ),
                "receipt_public_key_digests": keys,
                "supply_public_key_digest": ready["supply_public_key_digest"],
                "runtime_trust_digest": ready["runtime_trust_digest"],
            },
        )
        return self._active_admission

    @property
    def active_start(self) -> AttemptStart | None:
        return self._active_start

    @property
    def active_admission(self) -> str | None:
        return self._active_admission

    def post_key_run_failure(
        self,
        start: AttemptStart,
        admission_digest: str,
        reason: str,
    ) -> str:
        if (
            start != self._active_start
            or admission_digest != self._active_admission
            or self._active_admission is None
            or self._active_post_key_failure is not None
            or type(reason) is not str
            or reason not in POST_KEY_RUN_FAILURE_REASONS
        ):
            _stop("POST_KEY_RUN_FAILURE_ORDER_MISMATCH")
        self._active_post_key_failure = self._append(
            "POST_KEY_RUN_FAILURE",
            start,
            {
                "attempt_start_digest": start.digest,
                "key_admission_digest": admission_digest,
                "failure_stage": _POST_KEY_RUN_FAILURE_STAGE,
                "reason": reason,
            },
        )
        return self._active_post_key_failure

    def terminalize(
        self,
        start: AttemptStart,
        admission_digest: str | None,
        result: str,
        *,
        terminal_reason: str,
        manifest_digest: str | None = None,
        signed_payload_bundle_digest: str | None = None,
        qemu_phase_outcomes: dict[str, object] | None = None,
    ) -> str:
        if (
            start != self._active_start
            or admission_digest != self._active_admission
            or result not in _TERMINAL_RESULTS
            or terminal_reason not in _TERMINAL_REASON_BY_RESULT[result]
        ):
            _stop("ATTEMPT_TERMINAL_ORDER_MISMATCH")
        if self._active_post_key_failure is not None and (
            result != "QUARANTINED"
            or terminal_reason not in {"RUN_FAILED", "CLEANUP_FAILED"}
        ):
            _stop("ATTEMPT_TERMINAL_ORDER_MISMATCH")
        if result == "BUNDLE_EXPORTED":
            if (
                admission_digest is None
                or type(manifest_digest) is not str
                or _DIGEST.fullmatch(manifest_digest) is None
                or type(signed_payload_bundle_digest) is not str
                or _DIGEST.fullmatch(signed_payload_bundle_digest) is None
            ):
                _stop("ATTEMPT_TERMINAL_MALFORMED")
            _validate_qemu_phase_outcomes(
                qemu_phase_outcomes,
                start.attempt,
                lab=self.lab if self.one_use else LAB,
            )
        elif (
            manifest_digest is not None
            or signed_payload_bundle_digest is not None
            or qemu_phase_outcomes is not None
        ):
            _stop("ATTEMPT_TERMINAL_MALFORMED")
        digest = self._append(
            "ATTEMPT_TERMINAL",
            start,
            {
                "attempt_start_digest": start.digest,
                "key_admission_digest": admission_digest,
                "result": result,
                "terminal_reason": terminal_reason,
                "manifest_digest": manifest_digest,
                "signed_payload_bundle_digest": signed_payload_bundle_digest,
                "qemu_phase_outcomes": qemu_phase_outcomes,
            },
        )
        self._active_start = None
        self._active_admission = None
        self._active_post_key_failure = None
        return digest


def _verify_failed_v2_qualification_ledger(
    path: Path = FAILED_QUALIFICATION_V2_LEDGER,
    expected_digest: str = FAILED_QUALIFICATION_V2_LEDGER_DIGEST,
) -> str:
    raw = _read_regular(path, 4 << 20)
    if (
        type(expected_digest) is not str
        or _DIGEST.fullmatch(expected_digest) is None
        or _digest_bytes(raw) != expected_digest
    ):
        _stop("POST_V2_PREDECESSOR_DIGEST_MISMATCH")
    if not raw.endswith(b"\n") or b"\n\n" in raw:
        _stop("POST_V2_PREDECESSOR_MALFORMED")
    lines = raw[:-1].split(b"\n")
    if len(lines) != 2:
        _stop("POST_V2_PREDECESSOR_NOT_EXACT_FAILED_ATTEMPT")
    rows: list[tuple[dict[str, object], str]] = []
    previous: str | None = None
    for sequence, line in enumerate(lines, 1):
        row = _strict_json(line, 1 << 20)
        if (
            type(row) is not dict
            or row.get("entry_type")
            != ("ATTEMPT_STARTED" if sequence == 1 else "ATTEMPT_TERMINAL")
            or frozenset(row)
            != _LEDGER_COMMON | _LEDGER_EXTRA[str(row.get("entry_type"))]
            or row.get("ledger_version") != "2.0.0"
            or row.get("sequence") != sequence
            or row.get("previous_entry_digest") != previous
        ):
            _stop("POST_V2_PREDECESSOR_MALFORMED")
        AttemptLedger._validate_row(row)
        digest = _digest_bytes(line)
        rows.append((row, digest))
        previous = digest
    AttemptLedger._validate_lifecycle(rows)
    started = rows[0][0]
    terminal = rows[1][0]
    contract = started["qualification_contract"]
    core = contract["contract_core"] if type(contract) is dict else None
    if (
        type(core) is not dict
        or started["candidate"] != FAILED_QUALIFICATION_V2_CANDIDATE
        or started["tree"] != FAILED_QUALIFICATION_V2_TREE
        or core["candidate"] != FAILED_QUALIFICATION_V2_CANDIDATE
        or core["tree"] != FAILED_QUALIFICATION_V2_TREE
        or started["max_attempts"] != 2
        or terminal["max_attempts"] != 2
        or terminal["result"] != "FAILED"
        or terminal["terminal_reason"] != "KEY_READY_TIMEOUT"
        or terminal["key_admission_digest"] is not None
        or terminal["manifest_digest"] is not None
        or terminal["signed_payload_bundle_digest"] is not None
        or terminal["qemu_phase_outcomes"] is not None
    ):
        _stop("POST_V2_PREDECESSOR_NOT_EXACT_FAILED_ATTEMPT")
    return expected_digest


def _verify_package_plan_discriminator_predecessors() -> dict[str, str]:
    failed = _verify_failed_v2_qualification_ledger()
    raw = _read_regular(POST_V2_DIAGNOSTIC_LEDGER, 4 << 20)
    if _digest_bytes(raw) != POST_V2_DIAGNOSTIC_LEDGER_DIGEST:
        _stop("PACKAGE_PLAN_DISCRIMINATOR_PREDECESSOR_DIGEST_MISMATCH")
    if not raw.endswith(b"\n") or b"\n\n" in raw:
        _stop("PACKAGE_PLAN_DISCRIMINATOR_PREDECESSOR_MALFORMED")
    lines = raw[:-1].split(b"\n")
    if len(lines) != 2:
        _stop("PACKAGE_PLAN_DISCRIMINATOR_PREDECESSOR_MALFORMED")
    validator = PostV2DiagnosticLedger(
        POST_V2_DIAGNOSTIC_LAB,
        goal_record=_post_v2_diagnostic_goal_record(),
    )
    rows: list[tuple[dict[str, object], str]] = []
    previous: str | None = None
    for sequence, line in enumerate(lines, 1):
        row = _strict_json(line, 1 << 20)
        validator._validate_row(row, sequence, previous)
        digest = _digest_bytes(line)
        rows.append((row, digest))
        previous = digest
    started, terminal = rows[0], rows[1]
    if (
        terminal[0]["previous_entry_digest"] != started[1]
        or terminal[0]["diagnostic_start_digest"] != started[1]
        or terminal[0]["diagnostic_bundle_digest"]
        != POST_V2_DIAGNOSTIC_BUNDLE_DIGEST
    ):
        _stop("PACKAGE_PLAN_DISCRIMINATOR_PREDECESSOR_MALFORMED")
    for name in validator._common_keys() - {
        "post_v2_diagnostic_ledger_version", "sequence",
        "previous_entry_digest", "entry_type", "recorded_at",
    }:
        if terminal[0][name] != started[0][name]:
            _stop("PACKAGE_PLAN_DISCRIMINATOR_PREDECESSOR_MALFORMED")
    bundle_raw = _read_regular(POST_V2_DIAGNOSTIC_BUNDLE, 2 << 20)
    if _digest_bytes(bundle_raw) != POST_V2_DIAGNOSTIC_BUNDLE_DIGEST:
        _stop("PACKAGE_PLAN_DISCRIMINATOR_PREDECESSOR_DIGEST_MISMATCH")
    bundle = _validate_post_v2_diagnostic_record(
        _strict_json(bundle_raw, 2 << 20), lab=POST_V2_DIAGNOSTIC_LAB
    )
    if (
        bundle["diagnostic_start_digest"] != started[1]
        or bundle["diagnostic_contract"] != started[0]["diagnostic_contract"]
        or bundle["diagnostic_contract_digest"]
        != started[0]["diagnostic_contract_digest"]
        or bundle["contract_core_digest"]
        != started[0]["contract_core_digest"]
    ):
        _stop("PACKAGE_PLAN_DISCRIMINATOR_PREDECESSOR_MALFORMED")
    return {
        "failed_qualification_v2_ledger_digest": failed,
        "post_v2_diagnostic_ledger_digest": POST_V2_DIAGNOSTIC_LEDGER_DIGEST,
        "post_v2_diagnostic_bundle_digest": POST_V2_DIAGNOSTIC_BUNDLE_DIGEST,
    }


def _verify_one_use_predecessors(
    projection: object,
) -> dict[str, str]:
    scope = _validate_one_use_scope_projection(projection)
    lineage = _verify_package_plan_discriminator_predecessors()
    ledger_raw = _read_regular(PACKAGE_PLAN_DISCRIMINATOR_LEDGER, 4 << 20)
    if _digest_bytes(ledger_raw) != PACKAGE_PLAN_DISCRIMINATOR_LEDGER_DIGEST:
        _stop("ONE_USE_PREDECESSOR_DIGEST_MISMATCH")
    if not ledger_raw.endswith(b"\n") or b"\n\n" in ledger_raw:
        _stop("ONE_USE_PREDECESSOR_MALFORMED")
    lines = ledger_raw[:-1].split(b"\n")
    if len(lines) != 2:
        _stop("ONE_USE_PREDECESSOR_MALFORMED")
    validator = PostV2DiagnosticLedger(
        PACKAGE_PLAN_DISCRIMINATOR_LAB,
        goal_record=_package_plan_discriminator_goal_record(),
    )
    rows: list[tuple[dict[str, object], str]] = []
    previous: str | None = None
    for sequence, line in enumerate(lines, 1):
        row = _strict_json(line, 1 << 20)
        validator._validate_row(row, sequence, previous)
        digest = _digest_bytes(line)
        rows.append((row, digest))
        previous = digest
    start, terminal = rows
    if (
        terminal[0]["previous_entry_digest"] != start[1]
        or terminal[0]["diagnostic_start_digest"] != start[1]
        or terminal[0]["diagnostic_bundle_digest"]
        != PACKAGE_PLAN_DISCRIMINATOR_BUNDLE_DIGEST
    ):
        _stop("ONE_USE_PREDECESSOR_MALFORMED")
    bundle_raw = _read_regular(PACKAGE_PLAN_DISCRIMINATOR_BUNDLE, 2 << 20)
    if _digest_bytes(bundle_raw) != PACKAGE_PLAN_DISCRIMINATOR_BUNDLE_DIGEST:
        _stop("ONE_USE_PREDECESSOR_DIGEST_MISMATCH")
    bundle = _validate_post_v2_diagnostic_record(
        _strict_json(bundle_raw, 2 << 20), lab=PACKAGE_PLAN_DISCRIMINATOR_LAB
    )
    if (
        bundle["diagnostic_start_digest"] != start[1]
        or bundle["diagnostic_contract"] != start[0]["diagnostic_contract"]
        or bundle["diagnostic_contract_digest"]
        != start[0]["diagnostic_contract_digest"]
        or bundle["contract_core_digest"] != start[0]["contract_core_digest"]
        or scope["predecessor_qualification_ledger_digest"]
        != FAILED_QUALIFICATION_V2_LEDGER_DIGEST
        or scope["predecessor_diagnostic_ledger_digest"]
        != PACKAGE_PLAN_DISCRIMINATOR_LEDGER_DIGEST
        or scope["predecessor_diagnostic_bundle_digest"]
        != PACKAGE_PLAN_DISCRIMINATOR_BUNDLE_DIGEST
    ):
        _stop("ONE_USE_PREDECESSOR_MALFORMED")
    return {
        **lineage,
        "predecessor_qualification_ledger_digest": (
            FAILED_QUALIFICATION_V2_LEDGER_DIGEST
        ),
        "predecessor_diagnostic_ledger_digest": (
            PACKAGE_PLAN_DISCRIMINATOR_LEDGER_DIGEST
        ),
        "predecessor_diagnostic_bundle_digest": (
            PACKAGE_PLAN_DISCRIMINATOR_BUNDLE_DIGEST
        ),
    }


class DiagnosticStart(NamedTuple):
    candidate: str
    tree: str
    environment: str
    digest: str


def _verify_diagnostic_predecessor(path: Path, expected_digest: str) -> str:
    raw = _read_regular(path, 4 << 20)
    if _DIGEST.fullmatch(expected_digest) is None or _digest_bytes(raw) != expected_digest:
        _stop("DIAGNOSTIC_PREDECESSOR_DIGEST_MISMATCH")
    if not raw.endswith(b"\n") or b"\n\n" in raw:
        _stop("DIAGNOSTIC_PREDECESSOR_MALFORMED")
    rows = [_strict_json(line, 1 << 20) for line in raw[:-1].split(b"\n")]
    if len(rows) != 4:
        _stop("DIAGNOSTIC_PREDECESSOR_NOT_EXHAUSTED")
    previous: str | None = None
    for sequence, row in enumerate(rows, 1):
        if (
            type(row) is not dict
            or row.get("ledger_version") != "1.0.0"
            or row.get("sequence") != sequence
            or row.get("previous_entry_digest") != previous
            or row.get("max_attempts") != 2
            or row.get("attempt") != (sequence + 1) // 2
            or row.get("entry_type")
            != ("ATTEMPT_STARTED" if sequence % 2 else "ATTEMPT_TERMINAL")
            or (sequence % 2 == 0 and row.get("result") != "QUARANTINED")
        ):
            _stop("DIAGNOSTIC_PREDECESSOR_NOT_EXHAUSTED")
        previous = _digest_bytes(_canonical(row))
    return expected_digest


class DiagnosticLedger:
    """One-use append-only ledger for the non-authorizing pre-key diagnostic."""

    def __init__(
        self,
        lab: Path,
        *,
        goal_reference: str,
        goal_digest: str,
        predecessor_digest: str,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.lab = lab
        self.goal_reference = goal_reference
        self.goal_digest = goal_digest
        self.predecessor_digest = predecessor_digest
        self.clock = (lambda: datetime.now(UTC)) if clock is None else clock
        self._directory_descriptor = -1
        self._descriptor = -1
        self._rows: list[tuple[dict[str, object], str]] = []
        self._active: DiagnosticStart | None = None

    def __enter__(self) -> DiagnosticLedger:
        _mkdir_exact(self.lab, 0o700)
        _fsync_directory(self.lab.parent)
        try:
            self._directory_descriptor = os.open(
                self.lab,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            try:
                self._descriptor = os.open(
                    DIAGNOSTIC_LEDGER_NAME,
                    os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_EXCL
                    | os.O_CLOEXEC | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=self._directory_descriptor,
                )
                os.fsync(self._descriptor)
                os.fsync(self._directory_descriptor)
            except FileExistsError:
                self._descriptor = os.open(
                    DIAGNOSTIC_LEDGER_NAME,
                    os.O_RDWR | os.O_APPEND | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=self._directory_descriptor,
                )
            fcntl.flock(self._descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            info = os.fstat(self._descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_size > 2 << 20
            ):
                _stop("DIAGNOSTIC_LEDGER_UNTRUSTED")
            self._rows = self._read_rows()
            return self
        except (OSError, BlockingIOError) as error:
            self.__exit__(None, None, None)
            raise QualificationStop("DIAGNOSTIC_LEDGER_UNTRUSTED") from error
        except Exception:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, _kind: object, _value: object, _traceback: object) -> None:
        if self._descriptor >= 0:
            try:
                fcntl.flock(self._descriptor, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(self._descriptor)
            self._descriptor = -1
        if self._directory_descriptor >= 0:
            os.close(self._directory_descriptor)
            self._directory_descriptor = -1

    def _read_rows(self) -> list[tuple[dict[str, object], str]]:
        size = os.fstat(self._descriptor).st_size
        os.lseek(self._descriptor, 0, os.SEEK_SET)
        raw = b""
        while len(raw) < size:
            chunk = os.read(self._descriptor, min(65536, size - len(raw)))
            if not chunk:
                _stop("DIAGNOSTIC_LEDGER_MALFORMED")
            raw += chunk
        if not raw:
            return []
        if not raw.endswith(b"\n") or b"\n\n" in raw:
            _stop("DIAGNOSTIC_LEDGER_MALFORMED")
        if len(raw[:-1].split(b"\n")) not in {1, 2}:
            _stop("DIAGNOSTIC_LEDGER_MALFORMED")
        rows: list[tuple[dict[str, object], str]] = []
        previous: str | None = None
        for sequence, line in enumerate(raw[:-1].split(b"\n"), 1):
            row = _strict_json(line, 1 << 20)
            self._validate_row(row, sequence, previous)
            digest = _digest_bytes(line)
            rows.append((row, digest))
            previous = digest
        if len(rows) == 1:
            _stop("DIAGNOSTIC_PRIOR_ATTEMPT_UNRESOLVED")
        if rows[1][0]["diagnostic_start_digest"] != rows[0][1]:
            _stop("DIAGNOSTIC_LEDGER_BINDING_MISMATCH")
        if any(
            rows[1][0][name] != rows[0][0][name]
            for name in (
                "candidate", "tree", "environment", "user_scope_reference",
                "user_goal_digest", "predecessor_qualification_ledger_digest",
                "attempt",
            )
        ):
            _stop("DIAGNOSTIC_LEDGER_BINDING_MISMATCH")
        return rows

    def _validate_row(self, row: object, sequence: int, previous: str | None) -> None:
        common = {
            "diagnostic_ledger_version", "sequence", "previous_entry_digest",
            "entry_type", "recorded_at", "diagnostic_kind", "candidate", "tree",
            "environment", "user_scope_reference", "user_goal_digest",
            "predecessor_qualification_ledger_digest", "max_attempts",
            "success_target", "attempt",
        }
        terminal = {
            "diagnostic_start_digest", "terminal_reason",
            "diagnostic_bundle_digest", "key_ready_digest",
            "systemd_properties_digest", "cleanup_digest", "qemu_phase_outcomes",
        }
        if type(row) is not dict or row.get("entry_type") not in {
            "DIAGNOSTIC_STARTED", "DIAGNOSTIC_TERMINAL"
        }:
            _stop("DIAGNOSTIC_LEDGER_MALFORMED")
        expected = common | (terminal if row["entry_type"] == "DIAGNOSTIC_TERMINAL" else set())
        if frozenset(row) != expected:
            _stop("DIAGNOSTIC_LEDGER_MALFORMED")
        if (
            row["diagnostic_ledger_version"] != "1.0.0"
            or type(row["sequence"]) is not int
            or isinstance(row["sequence"], bool)
            or row["sequence"] != sequence
            or row["previous_entry_digest"] != previous
            or row["entry_type"]
            != ("DIAGNOSTIC_STARTED" if sequence == 1 else "DIAGNOSTIC_TERMINAL")
            or row["diagnostic_kind"] != "M4_KEY_READY_PRE_ADMISSION"
            or type(row["candidate"]) is not str
            or _COMMIT.fullmatch(row["candidate"]) is None
            or type(row["tree"]) is not str
            or _COMMIT.fullmatch(row["tree"]) is None
            or type(row["environment"]) is not str
            or _DIGEST.fullmatch(row["environment"]) is None
            or row["user_scope_reference"] != self.goal_reference
            or row["user_goal_digest"] != self.goal_digest
            or row["predecessor_qualification_ledger_digest"] != self.predecessor_digest
            or row["max_attempts"] != 1
            or row["success_target"] != 1
            or type(row["attempt"]) is not int
            or isinstance(row["attempt"], bool)
            or row["attempt"] != 1
            or type(row["recorded_at"]) is not str
            or _TIME.fullmatch(row["recorded_at"]) is None
        ):
            _stop("DIAGNOSTIC_LEDGER_BINDING_MISMATCH")
        recorded = datetime.strptime(row["recorded_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
        if recorded > self.clock().astimezone(UTC).replace(microsecond=0):
            _stop("DIAGNOSTIC_LEDGER_BINDING_MISMATCH")
        if row["entry_type"] == "DIAGNOSTIC_TERMINAL":
            values = (
                row["diagnostic_start_digest"], row["diagnostic_bundle_digest"],
                row["systemd_properties_digest"], row["cleanup_digest"],
            )
            if (
                row["terminal_reason"] not in _DIAGNOSTIC_REASONS
                or any(type(value) is not str or _DIGEST.fullmatch(value) is None for value in values)
                or (
                    row["key_ready_digest"] is not None
                    and (
                        type(row["key_ready_digest"]) is not str
                        or _DIGEST.fullmatch(row["key_ready_digest"]) is None
                    )
                )
            ):
                _stop("DIAGNOSTIC_LEDGER_BINDING_MISMATCH")
            _validate_diagnostic_phase_outcomes(row["qemu_phase_outcomes"])

    def _append(self, entry_type: str, start: DiagnosticStart, extra: dict[str, object]) -> str:
        row = {
            "diagnostic_ledger_version": "1.0.0",
            "sequence": len(self._rows) + 1,
            "previous_entry_digest": None if not self._rows else self._rows[-1][1],
            "entry_type": entry_type,
            "recorded_at": self.clock().astimezone(UTC).replace(microsecond=0).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "diagnostic_kind": "M4_KEY_READY_PRE_ADMISSION",
            "candidate": start.candidate,
            "tree": start.tree,
            "environment": start.environment,
            "user_scope_reference": self.goal_reference,
            "user_goal_digest": self.goal_digest,
            "predecessor_qualification_ledger_digest": self.predecessor_digest,
            "max_attempts": 1,
            "success_target": 1,
            "attempt": 1,
            **extra,
        }
        raw = _canonical(row)
        digest = _digest_bytes(raw)
        try:
            if os.write(self._descriptor, raw + b"\n") != len(raw) + 1:
                _stop("DIAGNOSTIC_LEDGER_APPEND_FAILED")
            os.fsync(self._descriptor)
        except OSError as error:
            raise QualificationStop("DIAGNOSTIC_LEDGER_APPEND_FAILED") from error
        self._rows.append((row, digest))
        return digest

    def begin(self, candidate: str, tree: str, environment: str) -> DiagnosticStart:
        self.ensure_available()
        if (
            type(candidate) is not str
            or _COMMIT.fullmatch(candidate) is None
            or type(tree) is not str
            or _COMMIT.fullmatch(tree) is None
            or type(environment) is not str
            or _DIGEST.fullmatch(environment) is None
        ):
            _stop("DIAGNOSTIC_ATTEMPT_BINDING_MISMATCH")
        provisional = DiagnosticStart(candidate, tree, environment, "")
        digest = self._append("DIAGNOSTIC_STARTED", provisional, {})
        self._active = DiagnosticStart(candidate, tree, environment, digest)
        return self._active

    def ensure_available(self) -> None:
        if self._rows or self._active is not None:
            _stop("DIAGNOSTIC_ATTEMPT_LIMIT_REACHED")

    def terminalize(
        self,
        start: DiagnosticStart,
        terminal_reason: str,
        *,
        diagnostic_bundle_digest: str,
        key_ready_digest: str | None,
        systemd_properties_digest: str,
        cleanup_digest: str,
        qemu_phase_outcomes: dict[str, object],
    ) -> str:
        values = (
            diagnostic_bundle_digest, systemd_properties_digest, cleanup_digest,
        )
        if (
            start != self._active
            or terminal_reason not in _DIAGNOSTIC_REASONS
            or any(type(value) is not str or _DIGEST.fullmatch(value) is None for value in values)
            or (
                key_ready_digest is not None
                and (
                    type(key_ready_digest) is not str
                    or _DIGEST.fullmatch(key_ready_digest) is None
                )
            )
        ):
            _stop("DIAGNOSTIC_TERMINAL_ORDER_MISMATCH")
        _validate_diagnostic_phase_outcomes(qemu_phase_outcomes)
        digest = self._append(
            "DIAGNOSTIC_TERMINAL",
            start,
            {
                "diagnostic_start_digest": start.digest,
                "terminal_reason": terminal_reason,
                "diagnostic_bundle_digest": diagnostic_bundle_digest,
                "key_ready_digest": key_ready_digest,
                "systemd_properties_digest": systemd_properties_digest,
                "cleanup_digest": cleanup_digest,
                "qemu_phase_outcomes": qemu_phase_outcomes,
            },
        )
        self._active = None
        return digest


def _validate_diagnostic_phase_outcomes(value: object) -> dict[str, object]:
    if type(value) is not dict or frozenset(value) != {"provision", "run"}:
        _stop("DIAGNOSTIC_QEMU_OUTCOME_MISMATCH")
    for phase, row in value.items():
        if row is None:
            continue
        if (
            type(row) is not dict
            or frozenset(row) != {"argv_digest", "return_code"}
            or type(row["argv_digest"]) is not str
            or _DIGEST.fullmatch(row["argv_digest"]) is None
            or row["argv_digest"]
            != _digest_bytes(
                _canonical(_qemu_argv(1, phase, lab=DIAGNOSTIC_LAB))
            )
            or type(row["return_code"]) is not int
            or isinstance(row["return_code"], bool)
            or not -255 <= row["return_code"] <= 255
        ):
            _stop("DIAGNOSTIC_QEMU_OUTCOME_MISMATCH")
    return value


class PostV2DiagnosticStart(NamedTuple):
    candidate: str
    tree: str
    environment: str
    goal_record_digest: str
    source_files_digest: str
    canonical_profile_digest: str
    raw_profile_artifact_digest: str
    base_image_digest: str
    contract_core_digest: str
    diagnostic_contract_digest: str
    diagnostic_contract: dict[str, object]
    digest: str


def _validate_post_v2_diagnostic_phase_outcomes(
    value: object, lab: Path
) -> dict[str, object]:
    if type(value) is not dict or frozenset(value) != {"provision", "run"}:
        _stop("POST_V2_DIAGNOSTIC_QEMU_OUTCOME_MISMATCH")
    for phase, row in value.items():
        if row is None:
            continue
        if (
            type(row) is not dict
            or frozenset(row) != {"argv_digest", "return_code"}
            or row["argv_digest"]
            != _digest_bytes(_canonical(_qemu_argv(1, phase, lab=lab)))
            or type(row["return_code"]) is not int
            or isinstance(row["return_code"], bool)
            or not -255 <= row["return_code"] <= 255
        ):
            _stop("POST_V2_DIAGNOSTIC_QEMU_OUTCOME_MISMATCH")
    return value


class PostV2DiagnosticLedger:
    """Exact one-slot ledger for the post-v2 pre-admission diagnostic."""

    def __init__(
        self,
        lab: Path,
        *,
        goal_record: object,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.lab = lab
        self.goal_record = _strict_json(
            _canonical(_validate_post_v2_diagnostic_goal_record(goal_record)),
            1 << 20,
        )
        self.discriminator = (
            self.goal_record["goal_kind"]
            == "M4_PACKAGE_RUNTIME_PLAN_DISCRIMINATOR"
        )
        self.ledger_name = (
            PACKAGE_PLAN_DISCRIMINATOR_LEDGER_NAME
            if self.discriminator
            else POST_V2_DIAGNOSTIC_LEDGER_NAME
        )
        self.ledger_version = "2.1.0" if self.discriminator else "2.0.0"
        self.diagnostic_kind = (
            "M4_PACKAGE_RUNTIME_PLAN_DISCRIMINATOR"
            if self.discriminator
            else "M4_POST_V2_PRE_ADMISSION"
        )
        self.goal_record_digest = _digest_bytes(_canonical(self.goal_record))
        self.clock = (lambda: datetime.now(UTC)) if clock is None else clock
        self._directory_descriptor = -1
        self._descriptor = -1
        self._rows: list[tuple[dict[str, object], str]] = []
        self._active: PostV2DiagnosticStart | None = None

    def __enter__(self) -> PostV2DiagnosticLedger:
        created = False
        try:
            os.mkdir(self.lab, 0o700)
            created = True
        except FileExistsError:
            pass
        except OSError as error:
            raise QualificationStop("POST_V2_DIAGNOSTIC_LEDGER_UNTRUSTED") from error
        try:
            self._directory_descriptor = os.open(
                self.lab,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            directory = os.fstat(self._directory_descriptor)
            if (
                not stat.S_ISDIR(directory.st_mode)
                or directory.st_uid != os.geteuid()
                or stat.S_IMODE(directory.st_mode) != 0o700
            ):
                _stop("POST_V2_DIAGNOSTIC_LEDGER_UNTRUSTED")
            if created:
                _fsync_directory(self.lab.parent)
            names = set(os.listdir(self.lab))
            if self.discriminator and not created and self.ledger_name not in names:
                _stop("POST_V2_DIAGNOSTIC_LAB_REUSE_FORBIDDEN")
            if (
                self.ledger_name not in names
                and names
                or self.ledger_name in names
                and not names <= {
                    self.ledger_name, "runs", "diagnostics"
                }
            ):
                _stop("POST_V2_DIAGNOSTIC_LAB_REUSE_FORBIDDEN")
            ledger_created = False
            try:
                self._descriptor = os.open(
                    self.ledger_name,
                    os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_EXCL
                    | os.O_CLOEXEC | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=self._directory_descriptor,
                )
                ledger_created = True
            except FileExistsError:
                self._descriptor = os.open(
                    self.ledger_name,
                    os.O_RDWR | os.O_APPEND | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=self._directory_descriptor,
                )
            fcntl.flock(self._descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            info = os.fstat(self._descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_size > 4 << 20
            ):
                _stop("POST_V2_DIAGNOSTIC_LEDGER_UNTRUSTED")
            if ledger_created:
                os.fsync(self._descriptor)
                os.fsync(self._directory_descriptor)
            self._rows = self._read_rows()
            return self
        except (OSError, BlockingIOError) as error:
            self.__exit__(None, None, None)
            raise QualificationStop("POST_V2_DIAGNOSTIC_LEDGER_UNTRUSTED") from error
        except Exception:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, _kind: object, _value: object, _traceback: object) -> None:
        if self._descriptor >= 0:
            try:
                fcntl.flock(self._descriptor, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(self._descriptor)
            self._descriptor = -1
        if self._directory_descriptor >= 0:
            os.close(self._directory_descriptor)
            self._directory_descriptor = -1

    def _read_rows(self) -> list[tuple[dict[str, object], str]]:
        size = os.fstat(self._descriptor).st_size
        os.lseek(self._descriptor, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        remaining = size
        while remaining:
            chunk = os.read(self._descriptor, min(65536, remaining))
            if not chunk:
                _stop("POST_V2_DIAGNOSTIC_LEDGER_MALFORMED")
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if not raw:
            return []
        if not raw.endswith(b"\n") or b"\n\n" in raw:
            _stop("POST_V2_DIAGNOSTIC_LEDGER_MALFORMED")
        lines = raw[:-1].split(b"\n")
        if len(lines) not in {1, 2}:
            _stop("POST_V2_DIAGNOSTIC_LEDGER_MALFORMED")
        rows: list[tuple[dict[str, object], str]] = []
        previous: str | None = None
        for sequence, line in enumerate(lines, 1):
            row = _strict_json(line, 1 << 20)
            self._validate_row(row, sequence, previous)
            digest = _digest_bytes(line)
            rows.append((row, digest))
            previous = digest
        if len(rows) == 1:
            _stop("POST_V2_DIAGNOSTIC_PRIOR_ATTEMPT_UNRESOLVED")
        if rows[1][0]["diagnostic_start_digest"] != rows[0][1]:
            _stop("POST_V2_DIAGNOSTIC_LEDGER_BINDING_MISMATCH")
        for name in self._common_keys() - {
            "post_v2_diagnostic_ledger_version", "sequence",
            "previous_entry_digest", "entry_type", "recorded_at",
        }:
            if rows[1][0][name] != rows[0][0][name]:
                _stop("POST_V2_DIAGNOSTIC_LEDGER_BINDING_MISMATCH")
        return rows

    def _common_keys(self) -> set[str]:
        keys = {
            "post_v2_diagnostic_ledger_version", "sequence",
            "previous_entry_digest", "entry_type", "recorded_at",
            "diagnostic_kind", "candidate", "tree", "environment",
            "goal_record_digest", "failed_qualification_v2_ledger_digest",
            "source_files_digest", "canonical_profile_digest",
            "raw_profile_artifact_digest", "base_image_digest",
            "contract_core_digest", "diagnostic_contract_digest",
            "max_attempts", "attempt",
        }
        if self.discriminator:
            keys |= {
                "predecessor_post_v2_diagnostic_ledger_digest",
                "predecessor_post_v2_diagnostic_bundle_digest",
                "success_target", "success_target_authorizing",
            }
        return keys

    def _terminal_reasons(self) -> frozenset[str]:
        if self.discriminator:
            return _DIAGNOSTIC_REASONS | {_PACKAGE_RUNTIME_PLAN_REJECTED}
        return _DIAGNOSTIC_REASONS

    def _validate_row(
        self, row: object, sequence: int, previous: str | None
    ) -> None:
        started = {"diagnostic_contract"}
        terminal = {
            "diagnostic_start_digest", "terminal_reason",
            "diagnostic_bundle_digest", "key_ready_digest",
            "systemd_properties_digest", "cleanup_digest",
            "qemu_phase_outcomes",
        }
        if type(row) is not dict or row.get("entry_type") not in {
            "DIAGNOSTIC_STARTED", "DIAGNOSTIC_TERMINAL"
        }:
            _stop("POST_V2_DIAGNOSTIC_LEDGER_MALFORMED")
        extra = started if row["entry_type"] == "DIAGNOSTIC_STARTED" else terminal
        if frozenset(row) != self._common_keys() | extra:
            _stop("POST_V2_DIAGNOSTIC_LEDGER_MALFORMED")
        digest_names = (
            "environment", "goal_record_digest",
            "failed_qualification_v2_ledger_digest", "source_files_digest",
            "canonical_profile_digest", "raw_profile_artifact_digest",
            "base_image_digest", "contract_core_digest",
            "diagnostic_contract_digest",
        )
        if self.discriminator:
            digest_names += (
                "predecessor_post_v2_diagnostic_ledger_digest",
                "predecessor_post_v2_diagnostic_bundle_digest",
            )
        if (
            row["post_v2_diagnostic_ledger_version"] != self.ledger_version
            or type(row["sequence"]) is not int
            or row["sequence"] != sequence
            or row["previous_entry_digest"] != previous
            or row["entry_type"]
            != ("DIAGNOSTIC_STARTED" if sequence == 1 else "DIAGNOSTIC_TERMINAL")
            or row["diagnostic_kind"] != self.diagnostic_kind
            or type(row["candidate"]) is not str
            or _COMMIT.fullmatch(row["candidate"]) is None
            or type(row["tree"]) is not str
            or _COMMIT.fullmatch(row["tree"]) is None
            or any(
                type(row[name]) is not str or _DIGEST.fullmatch(row[name]) is None
                for name in digest_names
            )
            or row["goal_record_digest"] != self.goal_record_digest
            or row["failed_qualification_v2_ledger_digest"]
            != FAILED_QUALIFICATION_V2_LEDGER_DIGEST
            or row["canonical_profile_digest"] != _M4_PROFILE_DIGEST
            or row["raw_profile_artifact_digest"] != _M4_PROFILE_DIGEST
            or row["base_image_digest"] != _IMAGE_DIGEST
            or type(row["max_attempts"]) is not int
            or row["max_attempts"] != 1
            or type(row["attempt"]) is not int
            or row["attempt"] != 1
            or type(row["recorded_at"]) is not str
            or _TIME.fullmatch(row["recorded_at"]) is None
            or (
                self.discriminator
                and (
                    row["predecessor_post_v2_diagnostic_ledger_digest"]
                    != POST_V2_DIAGNOSTIC_LEDGER_DIGEST
                    or row["predecessor_post_v2_diagnostic_bundle_digest"]
                    != POST_V2_DIAGNOSTIC_BUNDLE_DIGEST
                    or type(row["success_target"]) is not int
                    or row["success_target"] != 1
                    or row["success_target_authorizing"] is not False
                )
            )
        ):
            _stop("POST_V2_DIAGNOSTIC_LEDGER_BINDING_MISMATCH")
        recorded = datetime.strptime(
            row["recorded_at"], "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=UTC)
        if recorded > self.clock().astimezone(UTC).replace(microsecond=0):
            _stop("POST_V2_DIAGNOSTIC_LEDGER_BINDING_MISMATCH")
        if row["entry_type"] == "DIAGNOSTIC_STARTED":
            contract = _validate_post_v2_diagnostic_contract(
                row["diagnostic_contract"]
            )
            core = contract["contract_core"]
            if (
                core["goal_record"] != self.goal_record
                or row["candidate"] != core["candidate"]
                or row["tree"] != core["tree"]
                or row["environment"] != contract["environment_digest"]
                or row["source_files_digest"] != core["source_files_digest"]
                or row["canonical_profile_digest"]
                != core["canonical_profile_digest"]
                or row["raw_profile_artifact_digest"]
                != core["raw_profile_artifact_digest"]
                or row["base_image_digest"] != core["base_image_digest"]
                or row["contract_core_digest"] != contract["contract_core_digest"]
                or row["diagnostic_contract_digest"]
                != _post_v2_diagnostic_contract_digest(contract)
                or (
                    self.discriminator
                    and (
                        row["predecessor_post_v2_diagnostic_ledger_digest"]
                        != core[
                            "predecessor_post_v2_diagnostic_ledger_digest"
                        ]
                        or row[
                            "predecessor_post_v2_diagnostic_bundle_digest"
                        ]
                        != core[
                            "predecessor_post_v2_diagnostic_bundle_digest"
                        ]
                    )
                )
            ):
                _stop("POST_V2_DIAGNOSTIC_LEDGER_BINDING_MISMATCH")
        else:
            values = (
                row["diagnostic_start_digest"], row["diagnostic_bundle_digest"],
                row["systemd_properties_digest"], row["cleanup_digest"],
            )
            if (
                row["terminal_reason"] not in self._terminal_reasons()
                or any(
                    type(item) is not str or _DIGEST.fullmatch(item) is None
                    for item in values
                )
                or (
                    row["key_ready_digest"] is not None
                    and (
                        type(row["key_ready_digest"]) is not str
                        or _DIGEST.fullmatch(row["key_ready_digest"]) is None
                    )
                )
            ):
                _stop("POST_V2_DIAGNOSTIC_LEDGER_BINDING_MISMATCH")
            _validate_post_v2_diagnostic_phase_outcomes(
                row["qemu_phase_outcomes"], self.lab
            )

    def _append(
        self,
        entry_type: str,
        start: PostV2DiagnosticStart,
        extra: dict[str, object],
    ) -> str:
        row = {
            "post_v2_diagnostic_ledger_version": self.ledger_version,
            "sequence": len(self._rows) + 1,
            "previous_entry_digest": None if not self._rows else self._rows[-1][1],
            "entry_type": entry_type,
            "recorded_at": self.clock().astimezone(UTC).replace(
                microsecond=0
            ).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "diagnostic_kind": self.diagnostic_kind,
            "candidate": start.candidate,
            "tree": start.tree,
            "environment": start.environment,
            "goal_record_digest": start.goal_record_digest,
            "failed_qualification_v2_ledger_digest": (
                FAILED_QUALIFICATION_V2_LEDGER_DIGEST
            ),
            "source_files_digest": start.source_files_digest,
            "canonical_profile_digest": start.canonical_profile_digest,
            "raw_profile_artifact_digest": start.raw_profile_artifact_digest,
            "base_image_digest": start.base_image_digest,
            "contract_core_digest": start.contract_core_digest,
            "diagnostic_contract_digest": start.diagnostic_contract_digest,
            "max_attempts": 1,
            "attempt": 1,
            **extra,
        }
        if self.discriminator:
            row.update(
                {
                    "predecessor_post_v2_diagnostic_ledger_digest": (
                        POST_V2_DIAGNOSTIC_LEDGER_DIGEST
                    ),
                    "predecessor_post_v2_diagnostic_bundle_digest": (
                        POST_V2_DIAGNOSTIC_BUNDLE_DIGEST
                    ),
                    "success_target": 1,
                    "success_target_authorizing": False,
                }
            )
        raw = _canonical(row)
        digest = _digest_bytes(raw)
        line = raw + b"\n"
        try:
            if os.write(self._descriptor, line) != len(line):
                _stop("POST_V2_DIAGNOSTIC_LEDGER_APPEND_FAILED")
            os.fsync(self._descriptor)
        except OSError as error:
            raise QualificationStop(
                "POST_V2_DIAGNOSTIC_LEDGER_APPEND_FAILED"
            ) from error
        self._rows.append((row, digest))
        return digest

    def ensure_available(self) -> None:
        if self._rows or self._active is not None:
            _stop("POST_V2_DIAGNOSTIC_ATTEMPT_LIMIT_REACHED")

    def begin(self, diagnostic_contract: object) -> PostV2DiagnosticStart:
        self.ensure_available()
        contract = _strict_json(
            _canonical(_validate_post_v2_diagnostic_contract(diagnostic_contract)),
            1 << 20,
        )
        core = contract["contract_core"]
        if type(core) is not dict or core["goal_record"] != self.goal_record:
            _stop("POST_V2_DIAGNOSTIC_ATTEMPT_BINDING_MISMATCH")
        provisional = PostV2DiagnosticStart(
            str(core["candidate"]),
            str(core["tree"]),
            str(contract["environment_digest"]),
            str(core["goal_record_digest"]),
            str(core["source_files_digest"]),
            str(core["canonical_profile_digest"]),
            str(core["raw_profile_artifact_digest"]),
            str(core["base_image_digest"]),
            str(contract["contract_core_digest"]),
            _post_v2_diagnostic_contract_digest(contract),
            contract,
            "",
        )
        digest = self._append(
            "DIAGNOSTIC_STARTED", provisional, {"diagnostic_contract": contract}
        )
        self._active = PostV2DiagnosticStart(*provisional[:-1], digest)
        return self._active

    def terminalize(
        self,
        start: PostV2DiagnosticStart,
        terminal_reason: str,
        *,
        diagnostic_bundle_digest: str,
        key_ready_digest: str | None,
        systemd_properties_digest: str,
        cleanup_digest: str,
        qemu_phase_outcomes: dict[str, object],
    ) -> str:
        values = (
            diagnostic_bundle_digest, systemd_properties_digest, cleanup_digest,
        )
        if (
            start != self._active
            or terminal_reason not in self._terminal_reasons()
            or any(
                type(item) is not str or _DIGEST.fullmatch(item) is None
                for item in values
            )
            or (
                key_ready_digest is not None
                and (
                    type(key_ready_digest) is not str
                    or _DIGEST.fullmatch(key_ready_digest) is None
                )
            )
        ):
            _stop("POST_V2_DIAGNOSTIC_TERMINAL_ORDER_MISMATCH")
        _validate_post_v2_diagnostic_phase_outcomes(qemu_phase_outcomes, self.lab)
        digest = self._append(
            "DIAGNOSTIC_TERMINAL",
            start,
            {
                "diagnostic_start_digest": start.digest,
                "terminal_reason": terminal_reason,
                "diagnostic_bundle_digest": diagnostic_bundle_digest,
                "key_ready_digest": key_ready_digest,
                "systemd_properties_digest": systemd_properties_digest,
                "cleanup_digest": cleanup_digest,
                "qemu_phase_outcomes": qemu_phase_outcomes,
            },
        )
        self._active = None
        return digest


def _run(
    argv: list[str],
    *,
    timeout: float = 30,
    cwd: Path = Path("/"),
    stdout: int | BinaryIO = subprocess.PIPE,
) -> subprocess.CompletedProcess[bytes]:
    try:
        result = subprocess.run(
            argv,
            shell=False,
            close_fds=True,
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=subprocess.PIPE,
            env={"LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
            cwd=str(cwd),
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise QualificationStop("HOST_COMMAND_FAILED") from error
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace")[:512]
        raise QualificationStop("HOST_COMMAND_FAILED:" + detail)
    return result


def _source_state() -> dict[str, object]:
    commit = _run(["/usr/bin/git", "-C", str(ROOT), "rev-parse", "HEAD"]).stdout.decode().strip()
    tree = _run(["/usr/bin/git", "-C", str(ROOT), "rev-parse", "HEAD^{tree}"]).stdout.decode().strip()
    if _COMMIT.fullmatch(commit) is None or _COMMIT.fullmatch(tree) is None:
        _stop("SOURCE_IDENTITY_INVALID")
    if _run(
        [
            "/usr/bin/git", "-C", str(ROOT), "status", "--porcelain=v1",
            "--untracked-files=all",
        ]
    ).stdout:
        _stop("SOURCE_DIRTY")
    tracked = _run(
        [
            "/usr/bin/git", "-C", str(ROOT), "ls-files", "-z", "--",
            "src/harness_product", "scripts", "profiles", "tests",
        ]
    ).stdout.split(b"\0")
    paths = [
        raw.decode("utf-8")
        for raw in tracked
        if raw
        and (
            raw.startswith(b"src/harness_product/") and raw.endswith(b".py")
            or raw.startswith(b"scripts/") and raw.endswith(b".py")
            or raw.startswith(b"tests/") and raw.endswith(b".py")
            or raw.startswith(b"profiles/l0-lx-a")
        )
    ]
    paths.extend(_SOURCE_FIXED)
    if len(paths) != len(set(paths)) or not paths:
        _stop("SOURCE_FILE_SET_INVALID")
    files = {name: _digest_file(ROOT / name, 16 << 20) for name in sorted(paths)}
    return {
        "commit": commit,
        "tree": tree,
        "files": files,
        "files_digest": _digest_bytes(_canonical(files)),
    }


def _profile() -> tuple[dict[str, object], str]:
    raw = _read_regular(ROOT / "profiles/m4-lx-a.json", 1 << 20)
    value = _strict_json(raw, 1 << 20)
    if type(value) is not dict or _digest_bytes(raw) != _M4_PROFILE_DIGEST:
        _stop("PROFILE_MALFORMED")
    return value, _M4_PROFILE_DIGEST


def _verify_qualification_predecessors() -> dict[str, str]:
    artifacts = {
        "predecessor_qualification_ledger_digest": (
            OLD_LEDGER, OLD_LEDGER_DIGEST, 4 << 20
        ),
        "predecessor_diagnostic_ledger_digest": (
            PREDECESSOR_DIAGNOSTIC_LEDGER,
            PREDECESSOR_DIAGNOSTIC_LEDGER_DIGEST,
            4 << 20,
        ),
        "predecessor_diagnostic_bundle_digest": (
            PREDECESSOR_DIAGNOSTIC_BUNDLE,
            PREDECESSOR_DIAGNOSTIC_BUNDLE_DIGEST,
            1 << 20,
        ),
    }
    verified: dict[str, str] = {}
    for name, (path, expected, maximum) in artifacts.items():
        if _digest_file(path, maximum) != expected:
            _stop("QUALIFICATION_PREDECESSOR_DIGEST_MISMATCH")
        verified[name] = expected
    return verified


def _verify_host_assets() -> tuple[dict[str, object], str]:
    image = IMAGE_LAB / _IMAGE_NAME
    sums = IMAGE_LAB / "SHA256SUMS"
    signature = IMAGE_LAB / "SHA256SUMS.gpg"
    if (
        _digest_file(image, 1 << 30) != _IMAGE_DIGEST
        or _digest_file(sums, 1 << 20) != _SUMS_DIGEST
        or _digest_file(signature, 1 << 20) != _SUMS_SIGNATURE_DIGEST
        or _digest_file(Path(_QEMU_PATH), 64 << 20) != _QEMU_DIGEST
    ):
        _stop("HOST_ASSET_DIGEST_MISMATCH")
    sums_text = _read_regular(sums, 1 << 20).decode("utf-8")
    if _IMAGE_DIGEST.removeprefix("sha256:") + " *" + _IMAGE_NAME not in sums_text.splitlines():
        _stop("IMAGE_SUMS_BINDING_MISMATCH")
    verified = _run(
        [
            "/usr/bin/gpgv", "--status-fd", "1", "--keyring",
            "/usr/share/keyrings/ubuntu-cloudimage-keyring.gpg",
            str(signature), str(sums),
        ]
    ).stdout.decode("utf-8", "replace")
    if not any(
        line.startswith("[GNUPG:] VALIDSIG " + _UBUNTU_SIGNER + " ")
        for line in verified.splitlines()
    ):
        _stop("IMAGE_SIGNATURE_MISMATCH")
    qemu_version = _run([_QEMU_PATH, "--version"]).stdout.decode("utf-8", "replace").splitlines()[0]
    if not qemu_version.startswith("QEMU emulator version 8.2.2 "):
        _stop("QEMU_VERSION_MISMATCH")
    image_info = os.stat(image, follow_symlinks=False)
    if image_info.st_size != 624447488:
        _stop("IMAGE_SIZE_MISMATCH")
    return (
        {
            "source_url": _IMAGE_URL,
            "resolved_url": _IMAGE_URL,
            "release_id": "20260814",
            "filename": _IMAGE_NAME,
            "bytes": image_info.st_size,
            "sha256": _IMAGE_DIGEST,
            "sums_sha256": _SUMS_DIGEST,
            "sums_signature_sha256": _SUMS_SIGNATURE_DIGEST,
            "signer_fingerprint": _UBUNTU_SIGNER,
        },
        qemu_version,
    )


def _verify_kvm() -> None:
    try:
        descriptor = os.open("/dev/kvm", os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as error:
        raise QualificationStop("KVM_UNAVAILABLE") from error
    try:
        if fcntl.ioctl(descriptor, 0xAE00, 0) != 12:
            _stop("KVM_API_MISMATCH")
    finally:
        os.close(descriptor)


def _verify_management_port_free() -> None:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
    try:
        probe.bind(("127.0.0.1", _MANAGEMENT_PORT))
    except OSError as error:
        raise QualificationStop("MANAGEMENT_PORT_BUSY") from error
    finally:
        probe.close()


def _verify_disk_budget(path: Path) -> int:
    available = os.statvfs(path).f_bavail * os.statvfs(path).f_frsize
    required = (
        _OVERLAY_VIRTUAL_BYTES
        + _MAX_SEED_BYTES
        + 3 * _MAX_PHASE_LOG_BYTES
        + _MAX_BUNDLE_BYTES
        + _HOST_RESERVE_BYTES
    )
    if available < required:
        raise QualificationStop(
            f"HOST_DISK_BUDGET_INSUFFICIENT:available={available}:required={required}"
        )
    return available - required


def _mkdir_exact(path: Path, mode: int) -> None:
    try:
        path.mkdir(mode=mode)
    except FileExistsError:
        pass
    except OSError as error:
        raise QualificationStop("UNTRUSTED_DIRECTORY") from error
    info = os.lstat(path)
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != mode
    ):
        _stop("UNTRUSTED_DIRECTORY")


def _mkdir_fresh_exact(path: Path, mode: int, collision_reason: str) -> None:
    try:
        path.mkdir(mode=mode)
    except FileExistsError:
        _stop(collision_reason)
    except OSError as error:
        raise QualificationStop("UNTRUSTED_DIRECTORY") from error
    info = os.lstat(path)
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != mode
    ):
        _stop("UNTRUSTED_DIRECTORY")
    _fsync_directory(path.parent)


def _prepare_one_use_paths(
    projection_digest: str,
    *,
    qualification_root: Path | None = None,
    evidence_root: Path | None = None,
) -> OneUsePaths:
    qualification_base = (
        ONE_USE_QUALIFICATION_ROOT
        if qualification_root is None
        else qualification_root
    )
    evidence_base = ONE_USE_EVIDENCE_ROOT if evidence_root is None else evidence_root
    paths = _one_use_paths(
        projection_digest,
        qualification_root=qualification_base,
        evidence_root=evidence_base,
    )
    _mkdir_exact(qualification_base, 0o700)
    _mkdir_exact(evidence_base, 0o700)
    _fsync_directory(qualification_base.parent)
    _fsync_directory(evidence_base.parent)
    for path in paths:
        if path.exists() or path.is_symlink():
            _stop("ONE_USE_RUN_ID_COLLISION")
    _fsync_directory(qualification_base)
    _fsync_directory(evidence_base)
    return paths


def _write_exact(path: Path, raw: bytes, mode: int) -> None:
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            mode,
        )
    except OSError as error:
        raise QualificationStop("HOST_FILE_CREATE_FAILED") from error
    try:
        if os.write(descriptor, raw) != len(raw):
            _stop("HOST_FILE_WRITE_FAILED")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _independent_bundle_file_digests(
    attempt: int, *, evidence_root: Path | None = None
) -> dict[str, str]:
    root = EVIDENCE_ROOT if evidence_root is None else evidence_root
    bundle = root / f"attempt-{attempt}" / "bundle"
    expected = {
        "attempt-ledger.jsonl", "evidence.json", "manifest.json", "manifest.sig"
    }
    try:
        directory = os.lstat(bundle)
        names = {entry.name for entry in os.scandir(bundle)}
    except OSError as error:
        raise QualificationStop("INDEPENDENT_VERIFICATION_MISMATCH") from error
    if (
        not stat.S_ISDIR(directory.st_mode)
        or directory.st_uid != os.geteuid()
        or stat.S_IMODE(directory.st_mode) != 0o700
        or names != expected
    ):
        _stop("INDEPENDENT_VERIFICATION_MISMATCH")
    result: dict[str, str] = {}
    for name in sorted(expected):
        path = bundle / name
        info = os.lstat(path)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o444
        ):
            _stop("INDEPENDENT_VERIFICATION_MISMATCH")
        result[name] = _digest_file(
            path, 128 if name == "manifest.sig" else 8 << 20
        )
    return result


def _validate_independent_verification(
    ledger: AttemptLedger, value: object
) -> dict[str, object]:
    keys = frozenset({
        "record_version", "verifier_digest", "attempt", "candidate", "tree",
        "environment", "contract_core_digest", "qualification_contract_digest",
        "admission_digest", "manifest_digest", "signed_payload_bundle_digest",
        "aggregate_bundle_digest", "bundle_file_digests",
    })
    if type(value) is not dict or frozenset(value) != keys:
        _stop("INDEPENDENT_VERIFICATION_MISMATCH")
    files = value["bundle_file_digests"]
    if (
        value["record_version"] != "1.0.0"
        or value["verifier_digest"]
        != _digest_file(ROOT / "scripts/check_m4_runtime_evidence.py", 16 << 20)
        or type(value["attempt"]) is not int
        or isinstance(value["attempt"], bool)
        or value["attempt"]
        not in set(range(1, ledger.max_attempts + 1))
        or type(value["candidate"]) is not str
        or _COMMIT.fullmatch(value["candidate"]) is None
        or type(value["tree"]) is not str
        or _COMMIT.fullmatch(value["tree"]) is None
        or any(
            type(value[name]) is not str or _DIGEST.fullmatch(value[name]) is None
            for name in (
                "environment", "contract_core_digest",
                "qualification_contract_digest", "admission_digest",
                "manifest_digest", "signed_payload_bundle_digest",
                "aggregate_bundle_digest",
            )
        )
        or type(files) is not dict
        or frozenset(files) != {
            "attempt-ledger.jsonl", "evidence.json", "manifest.json", "manifest.sig"
        }
        or any(type(item) is not str or _DIGEST.fullmatch(item) is None for item in files.values())
        or value["manifest_digest"] != files["manifest.json"]
        or value["signed_payload_bundle_digest"]
        != _digest_bytes(_canonical({
            name: digest for name, digest in files.items()
            if name != "attempt-ledger.jsonl"
        }))
        or value["aggregate_bundle_digest"] != _digest_bytes(_canonical(files))
        or files
        != _independent_bundle_file_digests(
            value["attempt"], evidence_root=ledger.evidence_root
        )
        or files["attempt-ledger.jsonl"]
        != _digest_file(ledger.lab / LEDGER_NAME, 4 << 20)
    ):
        _stop("INDEPENDENT_VERIFICATION_MISMATCH")
    starts = [
        (row, digest) for row, digest in ledger._rows
        if row["entry_type"] == "ATTEMPT_STARTED" and row["attempt"] == value["attempt"]
    ]
    admissions = [
        (row, digest) for row, digest in ledger._rows
        if row["entry_type"] == "KEY_ADMITTED" and row["attempt"] == value["attempt"]
    ]
    terminals = [
        row for row, _digest in ledger._rows
        if row["entry_type"] == "ATTEMPT_TERMINAL" and row["attempt"] == value["attempt"]
    ]
    if len(starts) != 1 or len(admissions) != 1 or len(terminals) != 1:
        _stop("INDEPENDENT_VERIFICATION_MISMATCH")
    start, _start_digest = starts[0]
    _admission, admission_digest = admissions[0]
    terminal = terminals[0]
    if (
        terminal is not ledger._rows[-1][0]
        or terminal["result"] != "BUNDLE_EXPORTED"
        or terminal["terminal_reason"] != "SIGNED_PAYLOAD_EXPORTED"
        or value["candidate"] != start["candidate"]
        or value["tree"] != start["tree"]
        or value["environment"] != start["environment"]
        or value["contract_core_digest"] != start["contract_core_digest"]
        or value["qualification_contract_digest"]
        != start["qualification_contract_digest"]
        or value["admission_digest"] != admission_digest
        or terminal["key_admission_digest"] != admission_digest
        or value["manifest_digest"] != terminal["manifest_digest"]
        or value["signed_payload_bundle_digest"]
        != terminal["signed_payload_bundle_digest"]
    ):
        _stop("INDEPENDENT_VERIFICATION_MISMATCH")
    return value


def _record_independent_verification(
    ledger: AttemptLedger, verified: object
) -> None:
    if (
        type(verified) is not dict
        or verified.get("outcome") != "VERIFIED"
        or verified.get("claim_status")
        != "M4_EXACT_DISPOSABLE_TEST_PROFILE_RUNTIME_CONFORMANCE_VERIFIED"
    ):
        _stop("INDEPENDENT_VERIFICATION_MISMATCH")
    record = {
        "record_version": "1.0.0",
        "verifier_digest": _digest_file(
            ROOT / "scripts/check_m4_runtime_evidence.py", 16 << 20
        ),
        "attempt": verified.get("attempt"),
        "candidate": verified.get("commit"),
        "tree": verified.get("tree"),
        "environment": verified.get("environment"),
        "contract_core_digest": ledger._rows[-1][0]["contract_core_digest"],
        "qualification_contract_digest": verified.get(
            "qualification_contract_digest"
        ),
        "admission_digest": verified.get("admission_digest"),
        "manifest_digest": verified.get("manifest_digest"),
        "signed_payload_bundle_digest": verified.get(
            "signed_payload_bundle_digest"
        ),
        "aggregate_bundle_digest": verified.get("aggregate_bundle_digest"),
        "bundle_file_digests": verified.get("bundle_file_digests"),
    }
    _validate_independent_verification(ledger, record)
    _write_exact(
        ledger.lab / INDEPENDENT_VERIFICATION_NAME, _canonical(record), 0o444
    )
    _fsync_directory(ledger.lab)


def _generate_key(path: Path, comment: str) -> None:
    _run(
        [
            "/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C",
            comment, "-f", str(path),
        ]
    )
    private = os.lstat(path)
    public = os.lstat(path.with_suffix(path.suffix + ".pub"))
    if (
        not stat.S_ISREG(private.st_mode)
        or private.st_nlink != 1
        or stat.S_IMODE(private.st_mode) != 0o600
        or not stat.S_ISREG(public.st_mode)
        or public.st_nlink != 1
        or stat.S_IMODE(public.st_mode) & 0o022
    ):
        _stop("SSH_KEY_METADATA_MISMATCH")


def _cloud_file(path: str, raw: bytes, mode: int) -> list[str]:
    return [
        "  - path: " + path,
        "    owner: root:root",
        f"    permissions: '{mode:04o}'",
        "    encoding: b64",
        "    content: " + base64.b64encode(raw).decode("ascii"),
    ]


def _provision_script() -> bytes:
    return b"""#!/bin/bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
test -x /usr/sbin/nft
test -x /usr/sbin/sshd
/usr/sbin/nft -f /etc/harness-m4/nftables-provisioning.conf
/usr/bin/apt-get update
/usr/bin/apt-get install -y --allow-downgrades \
  bubblewrap=0.9.0-1ubuntu0.1 \
  apparmor=4.0.1really4.0.1-0ubuntu0.24.04.7 \
  apparmor-utils=4.0.1really4.0.1-0ubuntu0.24.04.7 \
  openssl=3.0.13-0ubuntu3.12 \
  libssl3t64=3.0.13-0ubuntu3.12 \
  python3.12=3.12.3-1ubuntu0.15
test "$(/usr/bin/dpkg-query -W -f='${Version}' bubblewrap)" = 0.9.0-1ubuntu0.1
test "$(/usr/bin/dpkg-query -W -f='${Version}' apparmor)" = 4.0.1really4.0.1-0ubuntu0.24.04.7
test "$(/usr/bin/dpkg-query -W -f='${Version}' apparmor-utils)" = 4.0.1really4.0.1-0ubuntu0.24.04.7
test "$(/usr/bin/dpkg-query -W -f='${Version}' openssl)" = 3.0.13-0ubuntu3.12
test "$(/usr/bin/dpkg-query -W -f='${Version}' libssl3t64)" = 3.0.13-0ubuntu3.12
test "$(/usr/bin/dpkg-query -W -f='${Version}' python3.12)" = 3.12.3-1ubuntu0.15
printf '%s  %s\n' \
  52231e1caf55bcbc667b269f49c63599a6f7db4767ae6a039580d0ff853db712 /usr/bin/bwrap \
  f28cbce3c8664cab5154492fdbc55ecb937a3e7ce1a9478c881a5f5965d7ce3e /usr/bin/aa-exec \
  1643dacd9feaedc58f3cc581e4d22577dfe25c09b10282936186ccf0f2e61118 /usr/bin/python3.12 \
  6bc852b37807961c14976be9a227ae96bd817f73b5189cb0e0ff5eca4448c01c /usr/sbin/apparmor_parser \
  b86b739329008369aebe1f7cff6c2adb18965609d68a19456fca55232f2908f5 /usr/bin/openssl \
  1451aceec262c3338052fa77542eb971d4ba311c6bf12d9aa70d0b56aca942f9 /usr/lib/x86_64-linux-gnu/libcrypto.so.3 \
  | /usr/bin/sha256sum -c -
/usr/bin/install -d -o root -g root -m 0755 /opt/harness-m3-source
/usr/bin/install -o root -g root -m 0444 \
  /var/tmp/harness-source.tgz /etc/harness-m4/source-archive.tgz
/usr/bin/tar -xzf /var/tmp/harness-source.tgz -C /opt/harness-m3-source
/usr/bin/chown -R root:root /opt/harness-m3-source
/usr/bin/chmod -R go-w /opt/harness-m3-source
/usr/bin/install -o root -g root -m 0444 /etc/harness-m4/nftables-offline.conf /etc/nftables.conf
/usr/sbin/nft -f /etc/nftables.conf
/usr/bin/systemctl enable nftables.service
/usr/bin/systemctl daemon-reload
/usr/bin/apt-get clean
/usr/bin/rm -f /var/tmp/harness-source.tgz
/usr/bin/install -d -o root -g root -m 0700 /var/lib/harness-m4-provisioning
/usr/bin/touch /var/lib/harness-m4-provisioning/complete
"""


def _provision_entry_script() -> bytes:
    return f"""#!/bin/bash
set -euo pipefail
boundary_expected='{_UBUNTU_SOURCE_DIGEST}'
boundary_canonical='{_UBUNTU_SOURCE_SEED_PATH}'
boundary_final='{_UBUNTU_SOURCE_FINAL_PATH}'
boundary_records='{_PACKAGE_SOURCE_BOUNDARY_PATH}'
/usr/bin/install -d -o root -g root -m 0700 /var/lib/harness-m4-provisioning
if [[ -e "$boundary_records" || -L "$boundary_records" ]]; then
  exit 1
fi
(umask 077; : > "$boundary_records")

_harness_m4_observe_ubuntu_source() {{
  local boundary="$1"
  local result hex observed observed_json outcome
  if result=$(/usr/bin/sha256sum -- "$boundary_final" 2>/dev/null); then
    hex="${{result%% *}}"
    if [[ "$hex" =~ ^[0-9a-f]{{64}}$ ]]; then
      observed="sha256:$hex"
      observed_json="\\\"$observed\\\""
      if [[ "$observed" == "$boundary_expected" ]]; then
        outcome='MATCH'
      else
        outcome='MISMATCH'
      fi
    else
      observed_json='null'
      outcome='READ_ERROR'
    fi
  else
    observed_json='null'
    outcome='READ_ERROR'
  fi
  if ! /usr/bin/printf '{{"binding_id":"PACKAGE_SOURCE_UBUNTU","boundary":"%s","expected_sha256":"%s","non_authorizing":true,"observed_sha256":%s,"outcome":"%s","record_type":"M4_PACKAGE_SOURCE_BOUNDARY_OBSERVATION"}}\\n' \
    "$boundary" "$boundary_expected" "$observed_json" "$outcome" \
    | /usr/bin/tee -a "$boundary_records"; then
    return 1
  fi
  [[ "$outcome" == 'MATCH' ]]
}}

/usr/bin/install -o root -g root -m 0644 "$boundary_canonical" "$boundary_final"
_harness_m4_seen_update=0
_harness_m4_clean_state=0
_harness_m4_debug() {{
  local command="$BASH_COMMAND"
  trap - DEBUG
  if [[ "$_harness_m4_clean_state" == 1 ]]; then
    _harness_m4_clean_state=2
    if ! _harness_m4_observe_ubuntu_source \
      'AFTER_EXACT_PACKAGE_INSTALL_AND_CLEAN'; then
      exit 1
    fi
  fi
  if [[ "$command" == "/usr/bin/apt-get update" ]]; then
    if [[ "$_harness_m4_seen_update" != 0 ]]; then
      exit 1
    fi
    if ! _harness_m4_observe_ubuntu_source 'BEFORE_APT_GET_UPDATE'; then
      exit 1
    fi
    _harness_m4_seen_update=1
  elif [[ "$command" == "/usr/bin/apt-get clean" ]]; then
    if [[ "$_harness_m4_seen_update" != 1 || "$_harness_m4_clean_state" != 0 ]]; then
      exit 1
    fi
    _harness_m4_clean_state=1
  fi
  trap _harness_m4_debug DEBUG
}}
set -T
trap _harness_m4_debug DEBUG
source /root/harness-m4-provision.sh
trap - DEBUG
if [[ "$_harness_m4_seen_update" != 1 || "$_harness_m4_clean_state" != 2 ]]; then
  exit 1
fi
""".encode("ascii")


def _cloud_config(client_public: str, writes: list[str]) -> bytes:
    lines = (
        [
            "#cloud-config",
            "hostname: harness-m4-disposable",
            "manage_etc_hosts: false",
            "ssh_pwauth: false",
            "disable_root: true",
            "ssh_deletekeys: false",
            "ssh_genkeytypes: [ed25519]",
            "users:",
            "  - name: lab-admin",
            "    groups: [adm, sudo]",
            "    shell: /bin/bash",
            "    sudo: ALL=(ALL) NOPASSWD:ALL",
            "    lock_passwd: true",
            "    ssh_authorized_keys:",
            "      - " + json.dumps(client_public),
            "write_files:",
        ]
        + writes
        + [
            "runcmd:",
            "  - [ /bin/bash, /root/harness-m4-provision-entry.sh ]",
            "",
        ]
    )
    return "\n".join(lines).encode("utf-8")


def _create_seed(
    attempt_root: Path,
    *,
    attempt: int,
    source: dict[str, object],
    package_runtime_plan: dict[str, object] | None = None,
) -> tuple[Path, Path, Path]:
    runtime_plan = (
        _package_runtime_plan()
        if package_runtime_plan is None
        else package_runtime_plan
    )
    if (
        type(runtime_plan) is not dict
        or _strict_json(_canonical(runtime_plan), 1 << 20) != runtime_plan
    ):
        _stop("PACKAGE_RUNTIME_PLAN_MALFORMED")
    ubuntu_source_entry = _ubuntu_source_seed_entry(runtime_plan)
    client_key = attempt_root / "ssh-client"
    host_key = attempt_root / "ssh-host"
    _generate_key(client_key, f"harness-m4-client-attempt-{attempt}")
    _generate_key(host_key, f"harness-m4-host-attempt-{attempt}")
    source_archive = attempt_root / "source.tgz"
    _run(
        [
            "/usr/bin/git", "-C", str(ROOT), "archive", "--format=tar.gz",
            "--output=" + str(source_archive), "HEAD",
        ],
        timeout=60,
    )
    os.chmod(source_archive, 0o600)
    source_marker = {
        "marker_version": "1.0.0",
        "snapshot_root": "/opt/harness-m3-source",
        "source": source,
    }
    guest_marker = {
        "marker_version": "1.0.0",
        "image_digest": _IMAGE_DIGEST,
        "release_id": "20260814",
        "qemu_machine": "q35",
        "offline_egress": True,
    }
    writes: list[str] = []
    for path, raw, mode in (
        ("/var/tmp/harness-source.tgz", _read_regular(source_archive, 16 << 20), 0o600),
        ("/etc/harness-m3/guest.json", _canonical(guest_marker), 0o444),
        ("/etc/harness-m3/source-identity.json", _canonical(source_marker), 0o444),
        (
            "/etc/systemd/system/harness-m4-controller@.service",
            _read_regular(ROOT / "profiles/harness-m4-controller@.service", 1 << 20),
            0o444,
        ),
        ubuntu_source_entry,
        (
            "/etc/apt/apt.conf.d/99-harness-m4",
            _read_regular(IMAGE_LAB / "apt-harness-m3.conf", 1 << 20),
            0o644,
        ),
        ("/etc/hosts", _read_regular(IMAGE_LAB / "guest-hosts", 1 << 20), 0o644),
        (
            "/etc/harness-m4/nftables-provisioning.conf",
            _read_regular(IMAGE_LAB / "nftables-provisioning.conf", 1 << 20),
            0o444,
        ),
        (
            "/etc/harness-m4/nftables-offline.conf",
            _read_regular(IMAGE_LAB / "nftables-offline.conf", 1 << 20),
            0o444,
        ),
        (
            "/etc/harness-m4/package-runtime-plan.json",
            _canonical(runtime_plan),
            0o444,
        ),
        ("/etc/ssh/ssh_host_ed25519_key", _read_regular(host_key, 4096), 0o600),
        (
            "/etc/ssh/ssh_host_ed25519_key.pub",
            _read_regular(host_key.with_suffix(".pub"), 4096),
            0o644,
        ),
        ("/root/harness-m4-provision.sh", _provision_script(), 0o700),
        (
            "/root/harness-m4-provision-entry.sh",
            _provision_entry_script(),
            0o700,
        ),
    ):
        writes.extend(_cloud_file(path, raw, mode))
    client_public = _read_regular(client_key.with_suffix(".pub"), 4096).decode("ascii").strip()
    user_data_path = attempt_root / "user-data"
    meta_data_path = attempt_root / "meta-data"
    _write_exact(user_data_path, _cloud_config(client_public, writes), 0o600)
    _write_exact(
        meta_data_path,
        (
            f"instance-id: harness-m4-{source['commit'][:12]}-attempt-{attempt}\n"
            "local-hostname: harness-m4-disposable\n"
        ).encode("ascii"),
        0o600,
    )
    seed = attempt_root / "seed.iso"
    _run(
        [
            "/usr/bin/xorriso", "-as", "mkisofs", "-quiet", "-volid", "cidata",
            "-joliet", "-rock", "-output", str(seed), str(user_data_path),
            str(meta_data_path),
        ],
        timeout=60,
    )
    os.chmod(seed, 0o600)
    seed_info = os.lstat(seed)
    if (
        not stat.S_ISREG(seed_info.st_mode)
        or seed_info.st_nlink != 1
        or seed_info.st_size < 1
        or seed_info.st_size > _MAX_SEED_BYTES
        or stat.S_IMODE(seed_info.st_mode) != 0o600
    ):
        _stop("SEED_BOUND_MISMATCH")
    return seed, client_key, host_key


def _host_provenance(
    image: dict[str, object],
    *,
    qemu_version: str,
    seed_digest: str,
    attempt: int,
    lab: Path = LAB,
    phases: tuple[str, ...] = ("provision", "run", "recover"),
) -> dict[str, object]:
    return {
        "image": image,
        "vm": {
            "qemu_path": _QEMU_PATH,
            "qemu_version": qemu_version,
            "qemu_digest": _QEMU_DIGEST,
            "machine": "q35",
            "kvm_api": 12,
            "vcpus": 2,
            "memory_bytes": 2 * 1024 * 1024 * 1024,
            "overlay_virtual_bytes": _OVERLAY_VIRTUAL_BYTES,
            "seed_digest": seed_digest,
            "management_address": "127.0.0.1:22227",
            "shared_host_mounts": 0,
            "qemu_argv_digest": _digest_bytes(
                _canonical(_qemu_lifecycle(attempt, lab=lab, phases=phases))
            ),
        },
    }


def _known_hosts(host_public_key: Path, output: Path) -> None:
    fields = _read_regular(host_public_key, 4096).decode("ascii").strip().split()
    if len(fields) < 2 or fields[0] != "ssh-ed25519":
        _stop("SSH_HOST_KEY_MALFORMED")
    _write_exact(
        output,
        f"[127.0.0.1]:{_MANAGEMENT_PORT} {fields[0]} {fields[1]}\n".encode("ascii"),
        0o600,
    )


def _ssh_base(client_key: Path, known_hosts: Path) -> list[str]:
    return [
        "/usr/bin/ssh",
        "-p", str(_MANAGEMENT_PORT),
        "-i", str(client_key),
        "-o", "BatchMode=yes",
        "-o", "IdentitiesOnly=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", "UserKnownHostsFile=" + str(known_hosts),
        "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=5",
        "-o", "ServerAliveInterval=5",
        "-o", "ServerAliveCountMax=2",
        "lab-admin@127.0.0.1",
    ]


def _ssh_try(
    client_key: Path,
    known_hosts: Path,
    command: list[str],
    *,
    timeout: float = 15,
) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            _ssh_base(client_key, known_hosts) + command,
            shell=False,
            close_fds=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"LC_ALL": "C"},
            cwd="/",
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise QualificationStop("SSH_COMMAND_FAILED") from error


def _ssh(
    client_key: Path,
    known_hosts: Path,
    command: list[str],
    *,
    timeout: float = 30,
    maximum: int = 1 << 20,
) -> bytes:
    result = _ssh_try(client_key, known_hosts, command, timeout=timeout)
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace")[:512]
        raise QualificationStop("SSH_COMMAND_FAILED:" + detail)
    if len(result.stdout) > maximum:
        _stop("SSH_OUTPUT_UNBOUNDED")
    return result.stdout


def _service_properties(
    client_key: Path, known_hosts: Path, unit: str
) -> dict[str, str]:
    command = ["sudo", "/usr/bin/systemctl", "show", unit, "--no-pager"]
    for name in _SERVICE_PROPERTIES:
        command.extend(("--property", name))
    raw = _ssh(client_key, known_hosts, command, maximum=4096)
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise QualificationStop("SYSTEMD_PROPERTIES_MALFORMED") from error
    result: dict[str, str] = {}
    for line in lines:
        if "=" not in line:
            _stop("SYSTEMD_PROPERTIES_MALFORMED")
        name, value = line.split("=", 1)
        if name not in _SERVICE_PROPERTIES or name in result or len(value) > 128:
            _stop("SYSTEMD_PROPERTIES_MALFORMED")
        result[name] = value
    if frozenset(result) != frozenset(_SERVICE_PROPERTIES):
        _stop("SYSTEMD_PROPERTIES_MALFORMED")
    return result


def _service_finished_before_key_ready(properties: dict[str, str]) -> bool:
    return (
        properties["ActiveState"] == "failed"
        or properties["Result"] not in {"", "success"}
        or (
            properties["ActiveState"] in {"inactive", "active"}
            and properties["SubState"] in {"dead", "failed", "exited"}
            and properties["ExecMainCode"] != "0"
        )
    )


def _wait_key_ready_diagnostic(
    qemu: QemuProcess,
    client_key: Path,
    known_hosts: Path,
    unit: str,
    *,
    timeout: float = 90,
    clock: Callable[[], float] = time.monotonic,
) -> dict[str, object]:
    deadline = clock() + timeout
    last_properties = {name: "UNAVAILABLE" for name in _SERVICE_PROPERTIES}
    while clock() < deadline:
        try:
            qemu.require_alive()
        except QualificationStop:
            process = getattr(qemu, "process", None)
            return {
                "terminal_reason": "QEMU_EXITED",
                "key_ready": None,
                "systemd_properties": last_properties,
                "qemu_return_code": getattr(process, "returncode", None),
            }
        last_properties = _service_properties(client_key, known_hosts, unit)
        marker = _ssh_try(
            client_key,
            known_hosts,
            ["sudo", "/usr/bin/cat", "/var/lib/harness-m4-runtime/key-ready.json"],
            timeout=10,
        )
        if marker.returncode == 0:
            ready = _strict_json(marker.stdout, 1 << 20)
            if type(ready) is not dict:
                _stop("KEY_READY_MALFORMED")
            return {
                "terminal_reason": "KEY_READY_REACHED",
                "key_ready": ready,
                "systemd_properties": last_properties,
                "qemu_return_code": None,
            }
        if _service_finished_before_key_ready(last_properties):
            return {
                "terminal_reason": "SERVICE_FAILED_PRE_KEY_READY",
                "key_ready": None,
                "systemd_properties": last_properties,
                "qemu_return_code": None,
            }
        time.sleep(0.5)
    return {
        "terminal_reason": "KEY_READY_TIMEOUT",
        "key_ready": None,
        "systemd_properties": last_properties,
        "qemu_return_code": None,
    }


def _guest_boot_id(client_key: Path, known_hosts: Path) -> str:
    try:
        value = _ssh(
            client_key,
            known_hosts,
            ["/usr/bin/cat", "/proc/sys/kernel/random/boot_id"],
            maximum=128,
        ).decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise QualificationStop("GUEST_BOOT_ID_MALFORMED") from error
    if re.fullmatch(r"[0-9a-f-]{36}", value) is None:
        _stop("GUEST_BOOT_ID_MALFORMED")
    return value


def _journal_lines(raw: bytes) -> list[str]:
    try:
        lines = raw.decode("utf-8", "replace").splitlines()
    except (AttributeError, UnicodeError) as error:
        raise QualificationStop("DIAGNOSTIC_JOURNAL_MALFORMED") from error
    if len(lines) > 512:
        _stop("DIAGNOSTIC_JOURNAL_UNBOUNDED")
    return lines


def _post_key_run_failure_reason(raw: bytes) -> str:
    if type(raw) is not bytes or len(raw) > 1 << 20:
        return "UNAVAILABLE"
    lines = raw.split(b"\n")
    if lines and not lines[-1]:
        lines.pop()
    if len(lines) > 512:
        return "UNAVAILABLE"
    records: list[dict[str, object]] = []
    for line in lines:
        if not line:
            continue
        structured = line.lstrip().startswith(b"{")
        if len(line) > 1024:
            if structured:
                return "UNAVAILABLE"
            continue
        try:
            decoded = line.decode("utf-8")
        except UnicodeDecodeError:
            if structured:
                return "UNAVAILABLE"
            continue
        try:
            pairs = json.loads(decoded, object_pairs_hook=lambda rows: rows)
        except (json.JSONDecodeError, RecursionError):
            if structured:
                return "UNAVAILABLE"
            continue
        if type(pairs) is not list:
            continue
        if not any(
            type(pair) is tuple
            and len(pair) == 2
            and pair[0] == "outcome"
            and pair[1] == "STOP"
            for pair in pairs
        ):
            continue
        if not structured:
            return "UNAVAILABLE"
        try:
            value = _strict_json(line, 1024)
        except QualificationStop:
            return "UNAVAILABLE"
        if (
            type(value) is not dict
            or frozenset(value) != {"outcome", "reason", "status"}
            or type(value.get("outcome")) is not str
            or value.get("outcome") != "STOP"
            or type(value.get("status")) is not str
            or value.get("status") != "NOT_ATTESTED"
            or type(value.get("reason")) is not str
            or value.get("reason") not in POST_KEY_RUN_FAILURE_REASONS - {"UNAVAILABLE"}
        ):
            return "UNAVAILABLE"
        records.append(value)
    if len(records) != 1:
        return "UNAVAILABLE"
    return str(records[0]["reason"])


def _capture_post_key_run_failure_reason(
    client_key: Path, known_hosts: Path, unit: str
) -> str:
    try:
        raw = _ssh(
            client_key,
            known_hosts,
            [
                "sudo", "/usr/bin/journalctl", "--boot=0", "--unit", unit,
                "--no-pager", "--output=cat", "--lines=512",
            ],
            timeout=20,
            maximum=1 << 20,
        )
    except QualificationStop:
        return "UNAVAILABLE"
    return _post_key_run_failure_reason(raw)


def _stage_markers(lines: list[str]) -> list[dict[str, object]]:
    order = (
        "SERVICE_ENTERED", "REQUEST_VALIDATED", "PRE_KEY_CHECKS_COMPLETE",
        "KEY_GENERATION_STARTED", "KEY_GENERATION_COMPLETE",
        "RUNTIME_TRUST_READY", "KEY_READY_WRITTEN",
    )
    result: list[dict[str, object]] = []
    for line in lines:
        try:
            value = json.loads(line)
        except (json.JSONDecodeError, TypeError):
            continue
        if (
            type(value) is dict
            and frozenset(value) == {"record_type", "stage", "non_authorizing"}
            and value["record_type"] == "M4_PRE_KEY_STAGE"
            and value["stage"] in order
            and value["non_authorizing"] is True
            and value["stage"] not in {item["stage"] for item in result}
        ):
            result.append(value)
    if [item["stage"] for item in result] != sorted(
        [item["stage"] for item in result], key=order.index
    ):
        _stop("DIAGNOSTIC_STAGE_ORDER_MISMATCH")
    return result


def _validate_package_runtime_plan_observation(
    value: object,
) -> dict[str, object]:
    if (
        type(value) is not dict
        or frozenset(value) != _PACKAGE_RUNTIME_PLAN_OBSERVATION_KEYS
        or value.get("record_type") != "M4_PACKAGE_RUNTIME_PLAN_OBSERVATION"
        or value.get("non_authorizing") is not True
        or type(value.get("binding_id")) is not str
        or type(value.get("outcome")) is not str
    ):
        _stop("POST_V2_PACKAGE_RUNTIME_PLAN_OBSERVATION_MALFORMED")
    if (
        value["binding_id"] not in PACKAGE_RUNTIME_PLAN_BINDING_IDS
        or value["outcome"] not in PACKAGE_RUNTIME_PLAN_OUTCOMES
    ):
        _stop("POST_V2_PACKAGE_RUNTIME_PLAN_OBSERVATION_UNKNOWN")
    return value


def _package_runtime_plan_observation_error(
    reason: str,
) -> dict[str, str]:
    error = _PACKAGE_RUNTIME_PLAN_PARSER_ERRORS.get(reason, reason)
    if error not in PACKAGE_RUNTIME_PLAN_OBSERVATION_ERRORS:
        _stop("POST_V2_PACKAGE_RUNTIME_PLAN_OBSERVATION_ERROR_UNKNOWN")
    return {"package_runtime_plan_observation_error": error}


def _validate_package_runtime_plan_observation_error(
    value: object,
) -> str:
    if (
        type(value) is not str
        or value not in PACKAGE_RUNTIME_PLAN_OBSERVATION_ERRORS
    ):
        _stop("POST_V2_PACKAGE_RUNTIME_PLAN_OBSERVATION_ERROR_UNKNOWN")
    return value


def _extract_package_runtime_plan_observation(
    unit_raw: bytes,
) -> dict[str, object]:
    if type(unit_raw) is not bytes or len(unit_raw) > 1 << 20:
        _stop("POST_V2_PACKAGE_RUNTIME_PLAN_OBSERVATION_MALFORMED")
    lines = unit_raw.splitlines()
    if len(lines) > 512:
        _stop("POST_V2_PACKAGE_RUNTIME_PLAN_OBSERVATION_MALFORMED")
    observation_token = b'"M4_PACKAGE_RUNTIME_PLAN_OBSERVATION"'
    terminal_token = b'"PACKAGE_RUNTIME_PLAN_BINDING_MISMATCH"'
    observation_rows = [
        (index, line)
        for index, line in enumerate(lines)
        if observation_token in line
    ]
    if not observation_rows:
        _stop("POST_V2_PACKAGE_RUNTIME_PLAN_OBSERVATION_MISSING")
    if len(observation_rows) != 1:
        _stop("POST_V2_PACKAGE_RUNTIME_PLAN_OBSERVATION_DUPLICATE")
    observation_index, observation_raw = observation_rows[0]
    if not observation_raw or len(observation_raw) > 1024:
        _stop("POST_V2_PACKAGE_RUNTIME_PLAN_OBSERVATION_MALFORMED")
    try:
        observation = _validate_package_runtime_plan_observation(
            _strict_json(observation_raw, 1024)
        )
    except QualificationStop as error:
        if str(error) == "POST_V2_PACKAGE_RUNTIME_PLAN_OBSERVATION_UNKNOWN":
            raise
        raise QualificationStop(
            "POST_V2_PACKAGE_RUNTIME_PLAN_OBSERVATION_MALFORMED"
        ) from error

    terminal_rows = [
        (index, line)
        for index, line in enumerate(lines)
        if terminal_token in line
    ]
    if len(terminal_rows) != 1:
        _stop("POST_V2_PACKAGE_RUNTIME_PLAN_OBSERVATION_ORDER_MISMATCH")
    terminal_index, terminal_raw = terminal_rows[0]
    expected_terminal = {
        "outcome": "STOP",
        "reason": "PACKAGE_RUNTIME_PLAN_BINDING_MISMATCH",
        "status": "NOT_ATTESTED",
    }
    try:
        terminal = _strict_json(terminal_raw, 1024)
    except QualificationStop as error:
        raise QualificationStop(
            "POST_V2_PACKAGE_RUNTIME_PLAN_OBSERVATION_ORDER_MISMATCH"
        ) from error
    if terminal != expected_terminal or observation_index >= terminal_index:
        _stop("POST_V2_PACKAGE_RUNTIME_PLAN_OBSERVATION_ORDER_MISMATCH")
    return observation


def _validate_package_source_boundary_observation(
    value: object,
) -> dict[str, object]:
    if (
        type(value) is not dict
        or frozenset(value) != _PACKAGE_SOURCE_BOUNDARY_KEYS
        or value.get("record_type")
        != "M4_PACKAGE_SOURCE_BOUNDARY_OBSERVATION"
        or value.get("non_authorizing") is not True
        or value.get("binding_id") != "PACKAGE_SOURCE_UBUNTU"
        or type(value.get("boundary")) is not str
        or value.get("boundary") not in _PACKAGE_SOURCE_BOUNDARIES
        or type(value.get("outcome")) is not str
        or value.get("outcome") not in _PACKAGE_SOURCE_BOUNDARY_OUTCOMES
        or value.get("expected_sha256") != _UBUNTU_SOURCE_DIGEST
    ):
        _stop("PACKAGE_SOURCE_BOUNDARY_OBSERVATION_MALFORMED")
    observed = value["observed_sha256"]
    outcome = value["outcome"]
    if (
        (outcome == "MATCH" and observed != _UBUNTU_SOURCE_DIGEST)
        or (
            outcome == "MISMATCH"
            and (
                type(observed) is not str
                or _DIGEST.fullmatch(observed) is None
                or observed == _UBUNTU_SOURCE_DIGEST
            )
        )
        or (outcome == "READ_ERROR" and observed is not None)
    ):
        _stop("PACKAGE_SOURCE_BOUNDARY_OBSERVATION_MALFORMED")
    return value


def _extract_package_source_boundary_observations(
    raw: bytes,
) -> list[dict[str, object]]:
    if type(raw) is not bytes or len(raw) > _MAX_PHASE_LOG_BYTES:
        _stop("PACKAGE_SOURCE_BOUNDARY_OBSERVATION_MALFORMED")
    token_rows = [
        line for line in raw.splitlines() if _PACKAGE_SOURCE_BOUNDARY_TOKEN in line
    ]
    if not token_rows:
        return []
    if len(token_rows) not in {1, 2}:
        _stop("PACKAGE_SOURCE_BOUNDARY_OBSERVATION_MALFORMED")
    observations: list[dict[str, object]] = []
    for line in token_rows:
        if not line or len(line) > 1024:
            _stop("PACKAGE_SOURCE_BOUNDARY_OBSERVATION_MALFORMED")
        try:
            observation = _validate_package_source_boundary_observation(
                _strict_json(line, 1024)
            )
        except QualificationStop as error:
            raise QualificationStop(
                "PACKAGE_SOURCE_BOUNDARY_OBSERVATION_MALFORMED"
            ) from error
        observations.append(observation)
    if (
        observations[0]["boundary"] != _PACKAGE_SOURCE_BOUNDARIES[0]
        or (
            len(observations) == 2
            and (
                observations[0]["outcome"] != "MATCH"
                or observations[1]["boundary"] != _PACKAGE_SOURCE_BOUNDARIES[1]
            )
        )
    ):
        _stop("PACKAGE_SOURCE_BOUNDARY_OBSERVATION_MALFORMED")
    return observations


def _require_exact_package_source_boundaries(
    raw: bytes,
) -> list[dict[str, object]]:
    observations = _extract_package_source_boundary_observations(raw)
    expected_raw = b"".join(_canonical(row) + b"\n" for row in observations)
    if (
        len(observations) != 2
        or any(row["outcome"] != "MATCH" for row in observations)
        or raw != expected_raw
    ):
        _stop("PACKAGE_SOURCE_BOUNDARY_OBSERVATION_MALFORMED")
    return observations


def _collect_pre_key_diagnostics(
    qemu: QemuProcess,
    client_key: Path,
    known_hosts: Path,
    unit: str,
    *,
    require_package_runtime_plan_observation: bool = False,
) -> tuple[
    list[str], list[str], list[dict[str, object]], dict[str, object] | None
]:
    if type(require_package_runtime_plan_observation) is not bool:
        _stop("POST_V2_PACKAGE_RUNTIME_PLAN_OBSERVATION_MALFORMED")
    try:
        qemu.require_alive()
    except QualificationStop:
        if require_package_runtime_plan_observation:
            _stop("POST_V2_PACKAGE_RUNTIME_PLAN_OBSERVATION_MISSING")
        unavailable = ["UNAVAILABLE:QEMU_EXITED"]
        return unavailable, unavailable, [], None
    try:
        unit_raw = _ssh(
            client_key,
            known_hosts,
            [
                "sudo", "/usr/bin/journalctl", "--boot=0", "--unit", unit,
                "--no-pager", "--output=cat", "--lines=512",
            ],
            timeout=20,
            maximum=1 << 20,
        )
    except QualificationStop:
        if require_package_runtime_plan_observation:
            _stop("POST_V2_PACKAGE_RUNTIME_PLAN_OBSERVATION_MISSING")
        unavailable = ["UNAVAILABLE:SSH_DIAGNOSTIC_COLLECTION_FAILED"]
        return unavailable, unavailable, [], None
    package_observation = (
        _extract_package_runtime_plan_observation(unit_raw)
        if require_package_runtime_plan_observation
        else None
    )
    try:
        kernel_raw = _ssh(
            client_key,
            known_hosts,
            [
                "sudo", "/usr/bin/journalctl", "--boot=0", "--dmesg",
                "--no-pager", "--output=cat", "--lines=512",
            ],
            timeout=20,
            maximum=1 << 20,
        )
    except QualificationStop:
        if require_package_runtime_plan_observation:
            unit_lines = _journal_lines(unit_raw)
            return (
                unit_lines,
                ["UNAVAILABLE:SSH_DIAGNOSTIC_COLLECTION_FAILED"],
                _stage_markers(unit_lines),
                package_observation,
            )
        unavailable = ["UNAVAILABLE:SSH_DIAGNOSTIC_COLLECTION_FAILED"]
        return unavailable, unavailable, [], None
    unit_lines = _journal_lines(unit_raw)
    kernel_lines = [
        line
        for line in _journal_lines(kernel_raw)
        if any(
            token in line.casefold()
            for token in ("apparmor", "oom", "out of memory", "killed process")
        )
    ]
    return unit_lines, kernel_lines, _stage_markers(unit_lines), package_observation


def _scp_to_guest(
    client_key: Path,
    known_hosts: Path,
    local: Path,
    remote: str,
) -> None:
    result = _run(
        [
            "/usr/bin/scp",
            "-P", str(_MANAGEMENT_PORT),
            "-i", str(client_key),
            "-o", "BatchMode=yes",
            "-o", "IdentitiesOnly=yes",
            "-o", "StrictHostKeyChecking=yes",
            "-o", "UserKnownHostsFile=" + str(known_hosts),
            "-o", "GlobalKnownHostsFile=/dev/null",
            str(local),
            "lab-admin@127.0.0.1:" + remote,
        ],
        timeout=30,
    )
    if result.stdout:
        _stop("SCP_UNEXPECTED_OUTPUT")


def _install_guest_file(
    attempt_root: Path,
    client_key: Path,
    known_hosts: Path,
    *,
    name: str,
    target: str,
    raw: bytes,
    mode: int,
) -> Path:
    local = attempt_root / name
    _write_exact(local, raw, 0o600)
    remote = "/tmp/" + name
    _scp_to_guest(client_key, known_hosts, local, remote)
    _ssh(
        client_key,
        known_hosts,
        [
            "sudo", "/usr/bin/install", "-o", "root", "-g", "root", "-m",
            f"{mode:04o}", remote, target,
        ],
    )
    _ssh(client_key, known_hosts, ["/usr/bin/rm", "-f", remote])
    return local


class QemuProcess:
    def __init__(
        self, attempt_root: Path, attempt: int, phase: str, *, lab: Path = LAB
    ) -> None:
        self.attempt_root = attempt_root
        self.attempt = attempt
        self.phase = phase
        self.lab = lab
        self.process: subprocess.Popen[bytes] | None = None
        self._log: BinaryIO | None = None

    def __enter__(self) -> QemuProcess:
        log_path = self.attempt_root / f"{self.phase}.qemu.log"
        descriptor = os.open(
            log_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
        self._log = os.fdopen(descriptor, "wb", closefd=True)
        try:
            self.process = subprocess.Popen(
                _qemu_argv(self.attempt, self.phase, lab=self.lab),
                shell=False,
                close_fds=True,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=self._log,
                env={"LC_ALL": "C"},
                cwd="/",
            )
        except OSError as error:
            self._log.close()
            self._log = None
            raise QualificationStop("QEMU_LAUNCH_FAILED") from error
        return self

    def __exit__(self, _kind: object, _value: object, _traceback: object) -> None:
        try:
            self.ensure_stopped()
        finally:
            if self._log is not None:
                self._log.flush()
                os.fsync(self._log.fileno())
                self._log.close()
                self._log = None

    def _bounded_logs(self) -> None:
        for suffix in ("qemu.log", "serial.log"):
            path = self.attempt_root / f"{self.phase}.{suffix}"
            try:
                size = os.lstat(path).st_size
            except FileNotFoundError:
                size = 0
            if size > _MAX_PHASE_LOG_BYTES:
                _stop("VM_LOG_LIMIT_EXCEEDED")

    def alive(self) -> bool:
        return self.process is not None and self.process.poll() is None

    def require_alive(self) -> None:
        self._bounded_logs()
        if not self.alive():
            _stop("QEMU_EXITED_EARLY")

    def wait_for_poweroff(self, timeout: float = 90) -> None:
        if self.process is None:
            _stop("QEMU_PROCESS_ABSENT")
        deadline = time.monotonic() + timeout
        while self.process.poll() is None and time.monotonic() < deadline:
            self._bounded_logs()
            time.sleep(0.25)
        if self.process.poll() is None:
            _stop("QEMU_POWEROFF_TIMEOUT")
        self._bounded_logs()
        if self.process.returncode != 0:
            _stop("QEMU_EXIT_FAILURE")

    def ensure_stopped(self) -> None:
        if self.process is None or self.process.poll() is not None:
            return
        self.process.terminate()
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired as error:
                raise VMCleanupUnproven("VM_CLEANUP_UNPROVEN") from error
        if self.process.poll() is None:
            raise VMCleanupUnproven("VM_CLEANUP_UNPROVEN")

    def successful_outcome(self) -> dict[str, object]:
        expected = _qemu_argv(self.attempt, self.phase, lab=self.lab)
        if (
            self.process is None
            or self.process.poll() is None
            or self.process.returncode != 0
            or self.process.args != expected
        ):
            _stop("QEMU_PHASE_OUTCOME_MISMATCH")
        return {
            "argv_digest": _digest_bytes(_canonical(expected)),
            "return_code": 0,
        }


def _wait_for_ssh(
    qemu: QemuProcess,
    client_key: Path,
    known_hosts: Path,
    *,
    timeout: float = 300,
) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        qemu.require_alive()
        result = _ssh_try(client_key, known_hosts, ["/usr/bin/true"], timeout=8)
        if result.returncode == 0:
            return
        time.sleep(1)
    _stop("SSH_READY_TIMEOUT")


def _poweroff(
    qemu: QemuProcess,
    client_key: Path,
    known_hosts: Path,
) -> None:
    _ssh_try(
        client_key,
        known_hosts,
        ["sudo", "/usr/bin/systemctl", "poweroff", "--no-wall"],
        timeout=10,
    )
    qemu.wait_for_poweroff()


def _wait_for_service(
    qemu: QemuProcess,
    client_key: Path,
    known_hosts: Path,
    unit: str,
    *,
    timeout: float = 210,
) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        qemu.require_alive()
        state = _ssh(
            client_key,
            known_hosts,
            ["sudo", "/usr/bin/systemctl", "show", unit, "-p", "ActiveState", "--value"],
        ).decode("ascii", "replace").strip()
        result = _ssh(
            client_key,
            known_hosts,
            ["sudo", "/usr/bin/systemctl", "show", unit, "-p", "Result", "--value"],
        ).decode("ascii", "replace").strip()
        status = _ssh(
            client_key,
            known_hosts,
            ["sudo", "/usr/bin/systemctl", "show", unit, "-p", "ExecMainStatus", "--value"],
        ).decode("ascii", "replace").strip()
        if state == "inactive" and result == "success" and status == "0":
            return
        if state == "failed" or result not in {"success", ""}:
            raise QualificationStop(f"GUEST_SERVICE_FAILED:{unit}:{result}:{status}")
        time.sleep(0.5)
    _stop("GUEST_SERVICE_TIMEOUT")


def _service_result(
    client_key: Path,
    known_hosts: Path,
    unit: str,
    expected: str,
) -> dict[str, object]:
    raw = _ssh(
        client_key,
        known_hosts,
        [
            "sudo", "/usr/bin/journalctl", "-u", unit, "--no-pager", "-o", "cat",
        ],
        maximum=4 << 20,
    )
    for line in reversed(raw.splitlines()):
        try:
            value = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if type(value) is dict and value.get("outcome") == expected:
            return value
    _stop("GUEST_RESULT_ABSENT")


def _wait_key_ready(
    qemu: QemuProcess,
    client_key: Path,
    known_hosts: Path,
    *,
    timeout: float = 90,
) -> dict[str, object]:
    deadline = time.monotonic() + timeout
    path = "/var/lib/harness-m4-runtime/key-ready.json"
    while time.monotonic() < deadline:
        qemu.require_alive()
        result = _ssh_try(
            client_key,
            known_hosts,
            ["sudo", "/usr/bin/cat", path],
            timeout=10,
        )
        if result.returncode == 0:
            value = _strict_json(result.stdout, 1 << 20)
            if type(value) is not dict:
                _stop("KEY_READY_MALFORMED")
            return value
        time.sleep(0.5)
    _stop("KEY_READY_TIMEOUT")


def _create_overlay(attempt_root: Path) -> Path:
    overlay = attempt_root / "overlay.qcow2"
    _run(
        [
            "/usr/bin/qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2",
            "-b", str(IMAGE_LAB / _IMAGE_NAME), str(overlay),
            str(_OVERLAY_VIRTUAL_BYTES),
        ],
        timeout=60,
    )
    os.chmod(overlay, 0o600)
    info = json.loads(
        _run(
            ["/usr/bin/qemu-img", "info", "--output=json", str(overlay)], timeout=30
        ).stdout.decode("utf-8")
    )
    if info.get("format") != "qcow2" or info.get("virtual-size") != _OVERLAY_VIRTUAL_BYTES:
        _stop("OVERLAY_BOUND_MISMATCH")
    return overlay


def _provision_vm(
    attempt_root: Path,
    attempt: int,
    client_key: Path,
    known_hosts: Path,
    *,
    host_provenance: dict[str, object],
    request: dict[str, object],
    lab: Path = LAB,
) -> tuple[list[Path], dict[str, object]]:
    created: list[Path] = []
    with QemuProcess(attempt_root, attempt, "provision", lab=lab) as qemu:
        _wait_for_ssh(qemu, client_key, known_hosts)
        _ssh(
            client_key,
            known_hosts,
            ["sudo", "/usr/bin/cloud-init", "status", "--wait"],
            timeout=900,
        )
        _ssh(
            client_key,
            known_hosts,
            ["sudo", "/usr/bin/test", "-f", "/var/lib/harness-m4-provisioning/complete"],
        )
        _require_exact_package_source_boundaries(
            _ssh(
                client_key,
                known_hosts,
                ["sudo", "/usr/bin/cat", _PACKAGE_SOURCE_BOUNDARY_PATH],
                maximum=4096,
            )
        )
        created.append(
            _install_guest_file(
                attempt_root,
                client_key,
                known_hosts,
                name="host-provenance.json",
                target="/etc/harness-m3/host-provenance.json",
                raw=_canonical({"marker_version": "1.0.0", **host_provenance}),
                mode=0o444,
            )
        )
        created.append(
            _install_guest_file(
                attempt_root,
                client_key,
                known_hosts,
                name="qualification.json",
                target="/etc/harness-m4/qualification.json",
                raw=_canonical(request),
                mode=0o444,
            )
        )
        _poweroff(qemu, client_key, known_hosts)
    outcome = qemu.successful_outcome()
    _verify_management_port_free()
    return created, outcome


def _key_admission(
    start: AttemptStart,
    ready: dict[str, object],
    ledger_entry_digest: str,
) -> dict[str, object]:
    if (
        type(start) is not AttemptStart
        or type(ready) is not dict
        or ready.get("candidate") != start.candidate
        or ready.get("environment") != start.environment
        or ready.get("attempt") != start.attempt
        or ready.get("qualification_contract") != start.qualification_contract
        or ready.get("qualification_contract_digest")
        != start.qualification_contract_digest
        or ready.get("contract_core_digest") != start.contract_core_digest
        or type(ledger_entry_digest) is not str
        or _DIGEST.fullmatch(ledger_entry_digest) is None
    ):
        _stop("KEY_ADMISSION_BINDING_MISMATCH")
    return {
        "admission_version": start.qualification_contract["contract_core"][
            "contract_version"
        ],
        "mode": "HOST_ATTEMPT_LEDGER_PIN_BEFORE_WORKER_GATE",
        "qualification_contract": start.qualification_contract,
        "qualification_contract_digest": start.qualification_contract_digest,
        "contract_core_digest": start.contract_core_digest,
        "ledger_entry_digest": ledger_entry_digest,
        "receipt_public_key_digests": ready["receipt_public_key_digests"],
        "supply_public_key_digest": ready["supply_public_key_digest"],
        "runtime_trust_digest": ready["runtime_trust_digest"],
    }


def _run_vm_phase(
    attempt_root: Path,
    attempt: int,
    phase: str,
    client_key: Path,
    known_hosts: Path,
    *,
    ledger: AttemptLedger,
    start: AttemptStart,
    lab: Path = LAB,
    evidence_root: Path | None = None,
) -> tuple[dict[str, object], str | None, list[Path], dict[str, object]]:
    unit = f"harness-m4-controller@{phase}.service"
    created: list[Path] = []
    admission_digest: str | None = None
    with QemuProcess(attempt_root, attempt, phase, lab=lab) as qemu:
        _wait_for_ssh(qemu, client_key, known_hosts)
        _ssh(
            client_key,
            known_hosts,
            ["sudo", "/usr/bin/systemctl", "start", "--no-block", unit],
        )
        if phase == "run":
            ready = _wait_key_ready(qemu, client_key, known_hosts)
            admission_digest = ledger.admit(start, ready)
            admission = _key_admission(start, ready, admission_digest)
            created.append(
                _install_guest_file(
                    attempt_root,
                    client_key,
                    known_hosts,
                    name="key-admission.json",
                    target="/etc/harness-m4/key-admission.json",
                    raw=_canonical(admission),
                    mode=0o444,
                )
            )
        try:
            _wait_for_service(qemu, client_key, known_hosts, unit)
        except QualificationStop as error:
            if (
                phase == "run"
                and admission_digest is not None
                and str(error).startswith("GUEST_SERVICE_FAILED:" + unit + ":")
            ):
                ledger.post_key_run_failure(
                    start,
                    admission_digest,
                    _capture_post_key_run_failure_reason(
                        client_key, known_hosts, unit
                    ),
                )
            raise
        expected = "PRE_RESTART_PASS" if phase == "run" else "RECOVERY_PASS"
        result = _service_result(client_key, known_hosts, unit, expected)
        if phase == "recover":
            _ssh(
                client_key,
                known_hosts,
                [
                    "sudo", "/usr/bin/test", "!", "-e",
                    "/var/lib/harness-m4-keys/m4-authority/private.pem",
                ],
            )
        if phase == "recover":
            bundle = _export_bundle(
                attempt_root,
                attempt,
                client_key,
                known_hosts,
                evidence_root=evidence_root,
                require_fresh_root=ledger.one_use,
            )
            result = {**result, "bundle": str(bundle)}
        _poweroff(qemu, client_key, known_hosts)
    outcome = qemu.successful_outcome()
    _verify_management_port_free()
    return result, admission_digest, created, outcome


def _diagnostic_qemu_outcome(
    qemu: QemuProcess, phase: str, *, lab: Path = DIAGNOSTIC_LAB
) -> dict[str, object] | None:
    process = qemu.process
    if process is None or process.returncode is None:
        return None
    return {
        "argv_digest": _digest_bytes(
            _canonical(_qemu_argv(1, phase, lab=lab))
        ),
        "return_code": process.returncode,
    }


def _run_diagnostic_vm_phase(
    attempt_root: Path,
    client_key: Path,
    known_hosts: Path,
) -> tuple[
    dict[str, object], str, list[str], list[str], list[dict[str, object]],
    dict[str, object] | None,
]:
    unit = "harness-m4-controller@run.service"
    with QemuProcess(
        attempt_root, 1, "run", lab=DIAGNOSTIC_LAB
    ) as qemu:
        _wait_for_ssh(qemu, client_key, known_hosts)
        boot_id = _guest_boot_id(client_key, known_hosts)
        _ssh(
            client_key,
            known_hosts,
            ["sudo", "/usr/bin/systemctl", "start", "--no-block", unit],
        )
        observation = _wait_key_ready_diagnostic(
            qemu, client_key, known_hosts, unit
        )
        unit_lines, kernel_lines, markers, _ = _collect_pre_key_diagnostics(
            qemu, client_key, known_hosts, unit
        )
        if qemu.alive():
            try:
                _poweroff(qemu, client_key, known_hosts)
            except QualificationStop:
                observation = {
                    **observation,
                    "terminal_reason": "QEMU_EXITED",
                    "qemu_return_code": getattr(qemu.process, "returncode", None),
                }
    _verify_management_port_free()
    return (
        observation, boot_id, unit_lines, kernel_lines, markers,
        _diagnostic_qemu_outcome(qemu, "run"),
    )


def _run_post_v2_diagnostic_vm_phase(
    attempt_root: Path,
    client_key: Path,
    known_hosts: Path,
    contract: dict[str, object],
    *,
    lab: Path = POST_V2_DIAGNOSTIC_LAB,
) -> tuple[
    dict[str, object], str, list[str], list[str], list[dict[str, object]],
    dict[str, object], dict[str, object] | None,
]:
    discriminator = (
        contract["contract_core"]["contract_kind"]
        == "M4_PACKAGE_RUNTIME_PLAN_DISCRIMINATOR"
    )
    unit = "harness-m4-controller@run.service"
    with QemuProcess(attempt_root, 1, "run", lab=lab) as qemu:
        _wait_for_ssh(qemu, client_key, known_hosts)
        boot_id = _guest_boot_id(client_key, known_hosts)
        _ssh(
            client_key,
            known_hosts,
            ["sudo", "/usr/bin/systemctl", "start", "--no-block", unit],
        )
        observation = _wait_key_ready_diagnostic(
            qemu, client_key, known_hosts, unit
        )
        try:
            (
                unit_lines,
                kernel_lines,
                markers,
                package_runtime_plan_result,
            ) = _collect_pre_key_diagnostics(
                qemu,
                client_key,
                known_hosts,
                unit,
                require_package_runtime_plan_observation=True,
            )
            if package_runtime_plan_result is None:
                _stop("POST_V2_PACKAGE_RUNTIME_PLAN_OBSERVATION_MISSING")
        except QualificationStop as error:
            if (
                not discriminator
                or str(error) not in _PACKAGE_RUNTIME_PLAN_PARSER_ERRORS
            ):
                raise
            package_runtime_plan_result = (
                _package_runtime_plan_observation_error(str(error))
            )
            error_name = package_runtime_plan_result[
                "package_runtime_plan_observation_error"
            ]
            unavailable = [
                "UNAVAILABLE:PACKAGE_RUNTIME_PLAN_OBSERVATION_" + error_name
            ]
            try:
                (
                    unit_lines,
                    kernel_lines,
                    markers,
                    _,
                ) = _collect_pre_key_diagnostics(
                    qemu,
                    client_key,
                    known_hosts,
                    unit,
                    require_package_runtime_plan_observation=False,
                )
            except QualificationStop:
                unit_lines, kernel_lines, markers = unavailable, unavailable, []
            if len(unit_lines) > 512 or any(
                type(line) is not str or len(line) > 1024
                for line in unit_lines
            ):
                unit_lines, markers = unavailable, []
            if len(kernel_lines) > 512 or any(
                type(line) is not str or len(line) > 1024
                for line in kernel_lines
            ):
                kernel_lines = unavailable
            observation = {
                **observation,
                "terminal_reason": _PACKAGE_RUNTIME_PLAN_REJECTED,
            }
        ready = observation["key_ready"]
        if ready is not None:
            if discriminator:
                package_runtime_plan_result = (
                    _package_runtime_plan_observation_error(
                        "KEY_READY_FORBIDDEN"
                    )
                )
                observation = {
                    **observation,
                    "terminal_reason": _PACKAGE_RUNTIME_PLAN_REJECTED,
                }
            else:
                try:
                    _validate_post_v2_key_ready(ready, contract)
                except QualificationStop:
                    observation = {
                        **observation,
                        "terminal_reason": "SERVICE_FAILED_PRE_KEY_READY",
                        "key_ready": None,
                    }
                    unit_lines = (
                        unit_lines + ["HOST:POST_V2_KEY_READY_MALFORMED"]
                    )[-512:]
        if qemu.alive():
            try:
                _poweroff(qemu, client_key, known_hosts)
            except QualificationStop:
                if not (
                    discriminator
                    and frozenset(package_runtime_plan_result)
                    == {"package_runtime_plan_observation_error"}
                ):
                    observation = {
                        **observation,
                        "terminal_reason": "QEMU_EXITED",
                        "qemu_return_code": getattr(
                            qemu.process, "returncode", None
                        ),
                    }
    _verify_management_port_free()
    return (
        observation, boot_id, unit_lines, kernel_lines, markers,
        package_runtime_plan_result,
        _diagnostic_qemu_outcome(qemu, "run", lab=lab),
    )


def _export_bundle(
    attempt_root: Path,
    attempt: int,
    client_key: Path,
    known_hosts: Path,
    *,
    evidence_root: Path | None = None,
    require_fresh_root: bool = False,
) -> Path:
    raw = _ssh(
        client_key,
        known_hosts,
        [
            "sudo", "/usr/bin/tar", "-C", "/var/lib/harness-m4-evidence", "-cf", "-",
            "manifest.json", "manifest.sig", "evidence.json",
        ],
        timeout=30,
        maximum=_MAX_BUNDLE_BYTES,
    )
    try:
        archive = tarfile.open(fileobj=BytesIO(raw), mode="r:")
        members = archive.getmembers()
    except (tarfile.TarError, OSError) as error:
        raise QualificationStop("EVIDENCE_EXPORT_MALFORMED") from error
    expected = {"manifest.json", "manifest.sig", "evidence.json"}
    if {member.name for member in members} != expected or any(
        not member.isfile()
        or member.mode != 0o444
        or member.size < 1
        or member.size > (128 if member.name == "manifest.sig" else 8 << 20)
        for member in members
    ):
        _stop("EVIDENCE_EXPORT_MALFORMED")
    root = EVIDENCE_ROOT if evidence_root is None else evidence_root
    if require_fresh_root:
        _mkdir_fresh_exact(
            root, 0o700, "EVIDENCE_DESTINATION_REUSE_FORBIDDEN"
        )
    else:
        _mkdir_exact(root, 0o700)
    attempt_evidence = root / f"attempt-{attempt}"
    if attempt_evidence.exists() or attempt_evidence.is_symlink():
        _stop("EVIDENCE_DESTINATION_REUSE_FORBIDDEN")
    attempt_evidence.mkdir(mode=0o700)
    bundle = attempt_evidence / "bundle"
    bundle.mkdir(mode=0o700)
    for member in members:
        extracted = archive.extractfile(member)
        if extracted is None:
            _stop("EVIDENCE_EXPORT_MALFORMED")
        content = extracted.read(member.size + 1)
        if len(content) != member.size:
            _stop("EVIDENCE_EXPORT_MALFORMED")
        _write_exact(bundle / member.name, content, 0o444)
    archive.close()
    _fsync_directory(bundle)
    _fsync_directory(attempt_evidence)
    _fsync_directory(root)
    return bundle


def _signed_payload_digests(
    bundle: Path,
    *,
    qualification_contract: dict[str, object] | None = None,
    qualification_contract_digest: str | None = None,
    admission_digest: str | None = None,
) -> tuple[str, str]:
    try:
        directory = os.lstat(bundle)
        names = {entry.name for entry in os.scandir(bundle)}
    except OSError as error:
        raise QualificationStop("EVIDENCE_BUNDLE_MALFORMED") from error
    expected = {"manifest.json", "manifest.sig", "evidence.json"}
    if not stat.S_ISDIR(directory.st_mode) or names != expected:
        _stop("EVIDENCE_BUNDLE_MALFORMED")
    raw: dict[str, bytes] = {}
    for name, maximum in (
        ("manifest.json", 1 << 20),
        ("manifest.sig", 128),
        ("evidence.json", 8 << 20),
    ):
        path = bundle / name
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o444:
            _stop("EVIDENCE_BUNDLE_MALFORMED")
        raw[name] = _read_regular(path, maximum)
    if len(raw["manifest.sig"]) != 64:
        _stop("EVIDENCE_SIGNATURE_LENGTH_MISMATCH")
    manifest = _strict_json(raw["manifest.json"], 1 << 20)
    evidence = _strict_json(raw["evidence.json"], 8 << 20)
    if (
        type(manifest) is not dict
        or type(evidence) is not dict
        or manifest.get("bundle_version") != "2.0.0"
        or evidence.get("bundle_version") != "2.0.0"
    ):
        _stop("EVIDENCE_V2_REQUIRED")
    if qualification_contract is not None:
        expected_contract = _validate_qualification_contract(qualification_contract)
        if (
            type(qualification_contract_digest) is not str
            or type(admission_digest) is not str
            or manifest.get("qualification_contract") != expected_contract
            or evidence.get("qualification_contract") != expected_contract
            or manifest.get("qualification_contract_digest")
            != qualification_contract_digest
            or evidence.get("qualification_contract_digest")
            != qualification_contract_digest
            or manifest.get("admission_digest") != admission_digest
            or evidence.get("admission_digest") != admission_digest
        ):
            _stop("SIGNED_PAYLOAD_CONTRACT_MISMATCH")
    digests = {name: _digest_bytes(content) for name, content in raw.items()}
    return digests["manifest.json"], _digest_bytes(_canonical(digests))


def _assemble_terminal_bundle(
    bundle: Path,
    ledger_path: Path,
    *,
    one_use: bool = False,
    lab: Path = LAB,
) -> Path:
    ledger_raw = _read_regular(ledger_path, 4 << 20)
    if not ledger_raw.endswith(b"\n") or b"\n\n" in ledger_raw:
        _stop("LEDGER_MALFORMED")
    lines = ledger_raw[:-1].split(b"\n")
    rows: list[tuple[dict[str, object], str]] = []
    previous: str | None = None
    for sequence, line in enumerate(lines, 1):
        row = _strict_json(line, 1 << 20)
        if (
            type(row) is not dict
            or row.get("entry_type") not in _LEDGER_EXTRA
            or frozenset(row)
            != _LEDGER_COMMON | _LEDGER_EXTRA[str(row["entry_type"])]
            or row.get("ledger_version") != ("3.0.0" if one_use else "2.0.0")
            or row.get("sequence") != sequence
            or row.get("previous_entry_digest") != previous
        ):
            _stop("LEDGER_MALFORMED")
        AttemptLedger._validate_row(row, one_use=one_use, lab=lab)
        digest = _digest_bytes(line)
        rows.append((row, digest))
        previous = digest
    if not rows or rows[-1][0]["entry_type"] != "ATTEMPT_TERMINAL":
        _stop("LEDGER_NOT_TERMINAL")
    AttemptLedger._validate_lifecycle(rows, max_attempts=1 if one_use else 2)
    terminal = rows[-1][0]
    starts = [row for row, _ in rows if row["entry_type"] == "ATTEMPT_STARTED"]
    start = starts[-1]
    contract = start["qualification_contract"]
    if type(contract) is not dict:
        _stop("LEDGER_BINDING_MISMATCH")
    manifest_digest, signed_payload_digest = _signed_payload_digests(
        bundle,
        qualification_contract=contract,
        qualification_contract_digest=str(start["qualification_contract_digest"]),
        admission_digest=str(terminal["key_admission_digest"]),
    )
    if (
        terminal["result"] != "BUNDLE_EXPORTED"
        or terminal["terminal_reason"] != "SIGNED_PAYLOAD_EXPORTED"
        or terminal["manifest_digest"] != manifest_digest
        or terminal["signed_payload_bundle_digest"] != signed_payload_digest
    ):
        _stop("TERMINAL_BUNDLE_LINKAGE_MISMATCH")
    embedded = bundle / "attempt-ledger.jsonl"
    _write_exact(embedded, ledger_raw, 0o444)
    if {entry.name for entry in os.scandir(bundle)} != {
        "manifest.json", "manifest.sig", "evidence.json", "attempt-ledger.jsonl"
    }:
        _stop("EVIDENCE_BUNDLE_MALFORMED")
    for path in bundle.iterdir():
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o444:
            _stop("EVIDENCE_BUNDLE_MALFORMED")
    _fsync_directory(bundle)
    return embedded


def _verify_host_tools() -> dict[str, str]:
    result: dict[str, str] = {}
    for path in (
        "/usr/bin/git", "/usr/bin/gpgv", "/usr/bin/qemu-img", _QEMU_PATH,
        "/usr/bin/scp", "/usr/bin/ssh", "/usr/bin/ssh-keygen", "/usr/bin/xorriso",
    ):
        info = os.stat(path, follow_symlinks=False)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) & 0o022
        ):
            _stop("HOST_TOOL_UNTRUSTED")
        result[path] = _digest_file(Path(path), 64 << 20)
    return result


def _sanitize_diagnostic_line(line: object) -> str:
    if type(line) is not str:
        _stop("DIAGNOSTIC_RECORD_MALFORMED")
    value = "".join(character for character in line[:1024] if character in "\t" or ord(character) >= 32)
    lowered = value.casefold()
    if any(
        token in lowered
        for token in (
            "private key", "-----begin", "ssh-ed25519 ", "password",
            "credential", "authorized_keys", "key-admission", "authorization",
            "signature", "proof", "secret",
        )
    ):
        return "[REDACTED]"
    return value


def _read_post_v2_phase_log(path: Path) -> bytes | None:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise QualificationStop("POST_V2_DIAGNOSTIC_LOG_UNTRUSTED") from error
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o022
            or info.st_size > _MAX_PHASE_LOG_BYTES
        ):
            _stop("POST_V2_DIAGNOSTIC_LOG_UNTRUSTED")
        chunks: list[bytes] = []
        remaining = info.st_size
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                _stop("POST_V2_DIAGNOSTIC_LOG_SHORT_READ")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            _stop("POST_V2_DIAGNOSTIC_LOG_UNBOUNDED")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _capture_post_v2_qemu_logs(attempt_root: Path) -> dict[str, object]:
    result: dict[str, object] = {}
    for phase in ("provision", "run"):
        for suffix in ("qemu.log", "serial.log"):
            name = f"{phase}.{suffix}"
            raw = _read_post_v2_phase_log(attempt_root / name)
            if raw is None:
                result[name] = {
                    "bytes": 0,
                    "digest": None,
                    "lines": ["UNAVAILABLE:LOG_ABSENT"],
                }
                continue
            boundary_lines = (
                [
                    _canonical(row).decode("utf-8")
                    for row in _extract_package_source_boundary_observations(raw)
                ]
                if name == "provision.serial.log"
                else []
            )
            lines = [
                _sanitize_diagnostic_line(line)
                for line in raw.decode("utf-8", "replace").splitlines()[-128:]
            ]
            if boundary_lines:
                lines = [line for line in lines if line not in boundary_lines]
                lines = boundary_lines + lines[-(128 - len(boundary_lines)):]
            result[name] = {
                "bytes": len(raw),
                "digest": _digest_bytes(raw),
                "lines": lines,
            }
    return _validate_post_v2_qemu_log_capture(result)


def _validate_post_v2_qemu_log_capture(value: object) -> dict[str, object]:
    expected = {
        f"{phase}.{suffix}"
        for phase in ("provision", "run")
        for suffix in ("qemu.log", "serial.log")
    }
    if type(value) is not dict or frozenset(value) != expected:
        _stop("POST_V2_DIAGNOSTIC_LOG_CAPTURE_MALFORMED")
    for row in value.values():
        if (
            type(row) is not dict
            or frozenset(row) != {"bytes", "digest", "lines"}
            or type(row["bytes"]) is not int
            or not 0 <= row["bytes"] <= _MAX_PHASE_LOG_BYTES
            or (
                row["digest"] is not None
                and (
                    type(row["digest"]) is not str
                    or _DIGEST.fullmatch(row["digest"]) is None
                )
            )
            or (row["digest"] is None and row["bytes"] != 0)
            or type(row["lines"]) is not list
            or len(row["lines"]) > 128
            or any(
                type(line) is not str or len(line) > 1024
                for line in row["lines"]
            )
        ):
            _stop("POST_V2_DIAGNOSTIC_LOG_CAPTURE_MALFORMED")
    return value


def _sanitize_post_v2_diagnostic_record(
    record: object, *, lab: Path = POST_V2_DIAGNOSTIC_LAB
) -> dict[str, object]:
    if type(record) is not dict:
        _stop("POST_V2_DIAGNOSTIC_RECORD_MALFORMED")
    value = dict(record)
    if value.get("diagnostic_version") in {"2.1.0", "2.2.0"}:
        _validate_package_runtime_plan_observation_lines(
            value.get("unit_journal"),
            value.get("package_runtime_plan_observation"),
        )
    for name in ("unit_journal", "kernel_events"):
        rows = value.get(name)
        if type(rows) is not list or len(rows) > 512:
            _stop("POST_V2_DIAGNOSTIC_RECORD_MALFORMED")
        value[name] = [_sanitize_diagnostic_line(line) for line in rows]
    captures = value.get("qemu_log_captures")
    if type(captures) is not dict:
        _stop("POST_V2_DIAGNOSTIC_RECORD_MALFORMED")
    value["qemu_log_captures"] = {
        name: {
            **row,
            "lines": [_sanitize_diagnostic_line(line) for line in row["lines"]],
        }
        for name, row in captures.items()
        if type(row) is dict and type(row.get("lines")) is list
    }
    return _validate_post_v2_diagnostic_record(value, lab=lab)


def _validate_package_runtime_plan_observation_lines(
    lines: object, observation: object
) -> dict[str, object]:
    package_observation = _validate_package_runtime_plan_observation(
        observation
    )
    if type(lines) is not list or any(type(line) is not str for line in lines):
        _stop("POST_V2_DIAGNOSTIC_RECORD_MALFORMED")
    observation_line = _canonical(package_observation).decode("utf-8")
    aggregate_line = _canonical(
        {
            "outcome": "STOP",
            "reason": "PACKAGE_RUNTIME_PLAN_BINDING_MISMATCH",
            "status": "NOT_ATTESTED",
        }
    ).decode("utf-8")
    observation_token = '"M4_PACKAGE_RUNTIME_PLAN_OBSERVATION"'
    aggregate_token = '"PACKAGE_RUNTIME_PLAN_BINDING_MISMATCH"'
    observation_rows = [
        (index, line)
        for index, line in enumerate(lines)
        if observation_token in line
    ]
    aggregate_rows = [
        (index, line)
        for index, line in enumerate(lines)
        if aggregate_token in line
    ]
    if (
        len(observation_rows) != 1
        or observation_rows[0][1] != observation_line
        or len(aggregate_rows) != 1
        or aggregate_rows[0][1] != aggregate_line
        or observation_rows[0][0] >= aggregate_rows[0][0]
    ):
        _stop("POST_V2_DIAGNOSTIC_RECORD_MALFORMED")
    return package_observation


def _validate_post_v2_diagnostic_record(
    value: object, *, lab: Path = POST_V2_DIAGNOSTIC_LAB
) -> dict[str, object]:
    historical_expected = {
        "diagnostic_version", "claim", "status", "goal_record",
        "goal_record_digest", "diagnostic_contract",
        "diagnostic_contract_digest", "contract_core_digest",
        "diagnostic_start_digest", "boot_id", "observed_terminal_reason",
        "systemd_properties", "unit_journal", "kernel_events",
        "stage_markers", "artifact_digests", "qemu_phase_outcomes",
        "qemu_log_captures", "key_ready_digest",
    }
    if type(value) is not dict or type(value.get("diagnostic_version")) is not str:
        _stop("POST_V2_DIAGNOSTIC_RECORD_MALFORMED")
    if value["diagnostic_version"] == "2.0.0":
        expected = historical_expected
    elif value["diagnostic_version"] in {"2.1.0", "2.2.0"}:
        expected = historical_expected | {"package_runtime_plan_observation"}
    elif value["diagnostic_version"] == "2.3.0":
        expected = historical_expected | {
            "package_runtime_plan_observation_error"
        }
    else:
        _stop("POST_V2_DIAGNOSTIC_RECORD_MALFORMED")
    if frozenset(value) != expected:
        _stop("POST_V2_DIAGNOSTIC_RECORD_MALFORMED")
    goal = _validate_post_v2_diagnostic_goal_record(value["goal_record"])
    contract = _validate_post_v2_diagnostic_contract(
        value["diagnostic_contract"]
    )
    core = contract["contract_core"]
    discriminator = (
        core["contract_kind"] == "M4_PACKAGE_RUNTIME_PLAN_DISCRIMINATOR"
    )
    expected_claim = (
        "M4_PACKAGE_RUNTIME_PLAN_DISCRIMINATOR_ONLY"
        if discriminator
        else "M4_POST_V2_PRE_ADMISSION_DIAGNOSTIC_ONLY"
    )
    observation_error = (
        _validate_package_runtime_plan_observation_error(
            value["package_runtime_plan_observation_error"]
        )
        if value["diagnostic_version"] == "2.3.0"
        else None
    )
    properties = value["systemd_properties"]
    artifacts = value["artifact_digests"]
    markers = value["stage_markers"]
    digests = (
        value["goal_record_digest"], value["diagnostic_contract_digest"],
        value["contract_core_digest"], value["diagnostic_start_digest"],
    )
    if (
        value["claim"] != expected_claim
        or (
            discriminator
            and value["diagnostic_version"] not in {"2.2.0", "2.3.0"}
        )
        or (
            not discriminator
            and value["diagnostic_version"] not in {"2.0.0", "2.1.0"}
        )
        or value["status"] != "NOT_ATTESTED"
        or core["goal_record"] != goal
        or value["goal_record_digest"] != _digest_bytes(_canonical(goal))
        or value["diagnostic_contract_digest"]
        != _post_v2_diagnostic_contract_digest(contract)
        or value["contract_core_digest"] != contract["contract_core_digest"]
        or any(
            type(item) is not str or _DIGEST.fullmatch(item) is None
            for item in digests
        )
        or type(value["boot_id"]) is not str
        or (
            value["boot_id"] != "UNAVAILABLE"
            and re.fullmatch(r"[0-9a-f-]{36}", value["boot_id"]) is None
        )
        or (
            value["diagnostic_version"] == "2.3.0"
            and value["observed_terminal_reason"]
            != _PACKAGE_RUNTIME_PLAN_REJECTED
        )
        or (
            value["diagnostic_version"] != "2.3.0"
            and value["observed_terminal_reason"] not in _DIAGNOSTIC_REASONS
        )
        or type(properties) is not dict
        or frozenset(properties) != frozenset(_SERVICE_PROPERTIES)
        or any(
            type(item) is not str or len(item) > 128
            for item in properties.values()
        )
        or type(artifacts) is not dict
        or frozenset(artifacts) != {"host_launcher", "runner", "service", "profile"}
        or any(
            type(item) is not str or _DIGEST.fullmatch(item) is None
            for item in artifacts.values()
        )
        or type(value["unit_journal"]) is not list
        or type(value["kernel_events"]) is not list
        or len(value["unit_journal"]) > 512
        or len(value["kernel_events"]) > 512
        or any(
            type(line) is not str or len(line) > 1024
            for line in [*value["unit_journal"], *value["kernel_events"]]
        )
        or type(markers) is not list
        or len(markers) > 7
        or (
            value["key_ready_digest"] is not None
            and (
                type(value["key_ready_digest"]) is not str
                or _DIGEST.fullmatch(value["key_ready_digest"]) is None
            )
        )
        or (
            discriminator
            and value["diagnostic_version"] == "2.2.0"
            and value["key_ready_digest"] is not None
        )
        or (
            value["diagnostic_version"] == "2.3.0"
            and (
                observation_error == "KEY_READY_FORBIDDEN"
                and value["key_ready_digest"] is None
                or observation_error != "KEY_READY_FORBIDDEN"
                and value["key_ready_digest"] is not None
            )
        )
    ):
        _stop("POST_V2_DIAGNOSTIC_RECORD_MALFORMED")
    order = (
        "SERVICE_ENTERED", "REQUEST_VALIDATED", "PRE_KEY_CHECKS_COMPLETE",
        "KEY_GENERATION_STARTED", "KEY_GENERATION_COMPLETE",
        "RUNTIME_TRUST_READY", "KEY_READY_WRITTEN",
    )
    seen: list[str] = []
    for marker in markers:
        if (
            type(marker) is not dict
            or frozenset(marker) != {"record_type", "stage", "non_authorizing"}
            or marker["record_type"] != "M4_PRE_KEY_STAGE"
            or marker["stage"] not in order
            or marker["non_authorizing"] is not True
            or marker["stage"] in seen
        ):
            _stop("POST_V2_DIAGNOSTIC_RECORD_MALFORMED")
        seen.append(marker["stage"])
    if seen != sorted(seen, key=order.index):
        _stop("POST_V2_DIAGNOSTIC_RECORD_MALFORMED")
    if (
        discriminator
        and value["diagnostic_version"] == "2.2.0"
        and seen != ["SERVICE_ENTERED"]
    ):
        _stop("POST_V2_DIAGNOSTIC_RECORD_MALFORMED")
    if (
        discriminator
        and value["diagnostic_version"] == "2.3.0"
        and observation_error != "KEY_READY_FORBIDDEN"
        and seen not in ([], ["SERVICE_ENTERED"])
    ):
        _stop("POST_V2_DIAGNOSTIC_RECORD_MALFORMED")
    if value["diagnostic_version"] in {"2.1.0", "2.2.0"}:
        _validate_package_runtime_plan_observation_lines(
            value["unit_journal"],
            value["package_runtime_plan_observation"],
        )
    _validate_post_v2_diagnostic_phase_outcomes(
        value["qemu_phase_outcomes"], lab
    )
    _validate_post_v2_qemu_log_capture(value["qemu_log_captures"])
    raw = _canonical(value)
    if len(raw) > 2 << 20 or any(
        token in raw.lower()
        for token in (
            b"private key", b"-----begin", b"ssh-ed25519 ", b"password",
            b"credential", b"authorized_keys", b"key-admission.json",
            b"authorization", b"signature", b"proof", b"secret",
        )
    ):
        _stop("POST_V2_DIAGNOSTIC_SECRET_PRESENT")
    return value


def _read_post_v2_diagnostic_bundle(
    path: Path, *, lab: Path = POST_V2_DIAGNOSTIC_LAB
) -> dict[str, object]:
    value = _strict_json(_read_regular(path, 2 << 20), 2 << 20)
    return _validate_post_v2_diagnostic_record(value, lab=lab)


def _materialize_post_v2_diagnostic_bundle(
    lab: Path, record: dict[str, object]
) -> Path:
    value = _validate_post_v2_diagnostic_record(record, lab=lab)
    _mkdir_exact(lab, 0o700)
    diagnostics = lab / "diagnostics"
    _mkdir_exact(diagnostics, 0o700)
    attempt = diagnostics / "attempt-1"
    if attempt.exists() or attempt.is_symlink():
        _stop("POST_V2_DIAGNOSTIC_DESTINATION_REUSE_FORBIDDEN")
    attempt.mkdir(mode=0o700)
    path = attempt / "diagnostic.json"
    _write_exact(path, _canonical(value), 0o444)
    _fsync_directory(attempt)
    _fsync_directory(diagnostics)
    _fsync_directory(lab)
    if _read_post_v2_diagnostic_bundle(path, lab=lab) != value:
        _stop("POST_V2_DIAGNOSTIC_RECORD_MISMATCH")
    return path


def _sanitize_diagnostic_record(record: object) -> dict[str, object]:
    if type(record) is not dict:
        _stop("DIAGNOSTIC_RECORD_MALFORMED")
    value = dict(record)
    for name in ("unit_journal", "kernel_events"):
        rows = value.get(name)
        if type(rows) is not list or len(rows) > 512:
            _stop("DIAGNOSTIC_RECORD_MALFORMED")
        value[name] = [_sanitize_diagnostic_line(line) for line in rows]
    return _validate_diagnostic_record(value)


def _validate_diagnostic_record(value: object) -> dict[str, object]:
    expected = {
        "diagnostic_version", "claim", "status", "candidate", "tree",
        "environment", "user_scope_reference", "user_goal_digest",
        "predecessor_qualification_ledger_digest", "diagnostic_start_digest",
        "attempt", "boot_id", "terminal_reason", "systemd_properties",
        "unit_journal", "kernel_events", "stage_markers", "artifact_digests",
        "qemu_phase_outcomes",
    }
    if type(value) is not dict or frozenset(value) != expected:
        _stop("DIAGNOSTIC_RECORD_MALFORMED")
    digests = (
        value["environment"], value["user_goal_digest"],
        value["predecessor_qualification_ledger_digest"],
        value["diagnostic_start_digest"],
    )
    properties = value["systemd_properties"]
    artifacts = value["artifact_digests"]
    markers = value["stage_markers"]
    if (
        value["diagnostic_version"] != "1.0.0"
        or value["claim"] != "M4_KEY_READY_PRE_ADMISSION_DIAGNOSTIC_ONLY"
        or value["status"] != "NOT_ATTESTED"
        or type(value["candidate"]) is not str
        or _COMMIT.fullmatch(value["candidate"]) is None
        or type(value["tree"]) is not str
        or _COMMIT.fullmatch(value["tree"]) is None
        or any(type(item) is not str or _DIGEST.fullmatch(item) is None for item in digests)
        or type(value["user_scope_reference"]) is not str
        or not value["user_scope_reference"].startswith("/")
        or len(value["user_scope_reference"]) > 4096
        or value["attempt"] != 1
        or type(value["boot_id"]) is not str
        or (
            value["boot_id"] != "UNAVAILABLE"
            and re.fullmatch(r"[0-9a-f-]{36}", value["boot_id"]) is None
        )
        or value["terminal_reason"] not in _DIAGNOSTIC_REASONS
        or type(properties) is not dict
        or frozenset(properties) != frozenset(_SERVICE_PROPERTIES)
        or any(type(item) is not str or len(item) > 128 for item in properties.values())
        or type(artifacts) is not dict
        or frozenset(artifacts) != {"runner", "service", "profile"}
        or any(type(item) is not str or _DIGEST.fullmatch(item) is None for item in artifacts.values())
        or type(value["unit_journal"]) is not list
        or type(value["kernel_events"]) is not list
        or len(value["unit_journal"]) > 512
        or len(value["kernel_events"]) > 512
        or any(
            type(line) is not str or len(line) > 1024
            for line in [*value["unit_journal"], *value["kernel_events"]]
        )
        or type(markers) is not list
        or len(markers) > 7
    ):
        _stop("DIAGNOSTIC_RECORD_MALFORMED")
    order = (
        "SERVICE_ENTERED", "REQUEST_VALIDATED", "PRE_KEY_CHECKS_COMPLETE",
        "KEY_GENERATION_STARTED", "KEY_GENERATION_COMPLETE",
        "RUNTIME_TRUST_READY", "KEY_READY_WRITTEN",
    )
    seen: list[str] = []
    for marker in markers:
        if (
            type(marker) is not dict
            or frozenset(marker) != {"record_type", "stage", "non_authorizing"}
            or marker["record_type"] != "M4_PRE_KEY_STAGE"
            or marker["stage"] not in order
            or marker["non_authorizing"] is not True
            or marker["stage"] in seen
        ):
            _stop("DIAGNOSTIC_RECORD_MALFORMED")
        seen.append(marker["stage"])
    if seen != sorted(seen, key=order.index):
        _stop("DIAGNOSTIC_RECORD_MALFORMED")
    _validate_diagnostic_phase_outcomes(value["qemu_phase_outcomes"])
    raw = _canonical(value)
    if len(raw) > 1 << 20 or any(
        token in raw.lower()
        for token in (
            b"private key", b"-----begin", b"ssh-ed25519 ", b"password",
            b"credential", b"authorized_keys", b"key-admission",
            b"authorization", b"signature", b"proof", b"secret",
        )
    ):
        _stop("DIAGNOSTIC_SECRET_PRESENT")
    return value


def _read_diagnostic_bundle(path: Path) -> dict[str, object]:
    value = _strict_json(_read_regular(path, 1 << 20), 1 << 20)
    return _validate_diagnostic_record(value)


def _materialize_diagnostic_bundle(lab: Path, record: dict[str, object]) -> Path:
    value = _validate_diagnostic_record(record)
    _mkdir_exact(lab, 0o700)
    diagnostics = lab / "diagnostics"
    _mkdir_exact(diagnostics, 0o700)
    attempt = diagnostics / "attempt-1"
    if attempt.exists() or attempt.is_symlink():
        _stop("DIAGNOSTIC_DESTINATION_REUSE_FORBIDDEN")
    attempt.mkdir(mode=0o700)
    path = attempt / "diagnostic.json"
    _write_exact(path, _canonical(value), 0o444)
    _fsync_directory(attempt)
    _fsync_directory(diagnostics)
    _fsync_directory(lab)
    if _read_diagnostic_bundle(path) != value:
        _stop("DIAGNOSTIC_RECORD_MISMATCH")
    return path


def _cleanup_diagnostic_attempt(attempt_root: Path, *, lab: Path = DIAGNOSTIC_LAB) -> list[str]:
    if attempt_root.parent != lab / "runs" or attempt_root.name != "attempt-1":
        _stop("CLEANUP_TARGET_MISMATCH")
    try:
        root_info = os.lstat(attempt_root)
        if (
            not stat.S_ISDIR(root_info.st_mode)
            or root_info.st_uid != os.geteuid()
            or stat.S_IMODE(root_info.st_mode) != 0o700
        ):
            _stop("CLEANUP_TARGET_MISMATCH")
        present = {path.name for path in attempt_root.iterdir()}
    except OSError as error:
        raise QualificationStop("ATTEMPT_CLEANUP_FAILED") from error
    if not present.issubset(_DIAGNOSTIC_DISPOSABLE_NAMES):
        _stop("CLEANUP_TARGET_MISMATCH")
    removed: list[str] = []
    try:
        for name in _DIAGNOSTIC_DISPOSABLE_NAMES:
            path = attempt_root / name
            try:
                info = os.lstat(path)
            except FileNotFoundError:
                continue
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                _stop("CLEANUP_TARGET_MISMATCH")
            os.unlink(path)
            removed.append(name)
        _fsync_directory(attempt_root)
        os.rmdir(attempt_root)
        _fsync_directory(attempt_root.parent)
    except OSError as error:
        raise QualificationStop("ATTEMPT_CLEANUP_FAILED") from error
    return removed


def _cleanup_attempt(
    attempt_root: Path,
    *,
    require_complete: bool,
    lab: Path = LAB,
    max_attempts: int = 2,
) -> list[str]:
    allowed = {f"attempt-{attempt}" for attempt in range(1, max_attempts + 1)}
    if attempt_root.parent != lab / "runs" or attempt_root.name not in allowed:
        _stop("CLEANUP_TARGET_MISMATCH")
    names = (
        "overlay.qcow2", "seed.iso", "ssh-client", "ssh-client.pub", "ssh-host",
        "ssh-host.pub", "known_hosts", "user-data", "meta-data", "source.tgz",
        "host-provenance.json", "qualification.json", "key-admission.json",
    )
    if require_complete and any(
        not (attempt_root / name).is_file()
        for name in ("overlay.qcow2", "seed.iso", "ssh-client", "ssh-host", "user-data")
    ):
        _stop("CLEANUP_INPUT_MISSING")
    removed: list[str] = []
    try:
        for name in names:
            path = attempt_root / name
            try:
                info = os.lstat(path)
            except FileNotFoundError:
                continue
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                _stop("CLEANUP_TARGET_MISMATCH")
            os.unlink(path)
            removed.append(name)
        _fsync_directory(attempt_root)
    except OSError as error:
        raise QualificationStop("ATTEMPT_CLEANUP_FAILED") from error
    if any((attempt_root / name).exists() or (attempt_root / name).is_symlink() for name in names):
        _stop("ATTEMPT_CLEANUP_FAILED")
    return removed


def _verify_bundle(
    bundle: Path, *, one_use_scope: Path | None = None
) -> dict[str, object]:
    arguments = [
        sys.executable,
        str(ROOT / "scripts/check_m4_runtime_evidence.py"),
    ]
    if one_use_scope is not None:
        arguments.extend(["--one-use-scope", str(one_use_scope)])
    arguments.extend(["--evidence", str(bundle)])
    result = _run(
        arguments,
        timeout=60,
    )
    value = _strict_json(result.stdout.rstrip(b"\n"), 1 << 20)
    if type(value) is not dict or value.get("outcome") != "VERIFIED":
        _stop("FINAL_EVIDENCE_VERIFICATION_FAILED")
    return value


def _finalize_exported_attempt(
    *,
    ledger: AttemptLedger,
    start: AttemptStart,
    admission_digest: str,
    bundle: Path,
    phase_outcomes: dict[str, object],
    attempt_root: Path,
    one_use_scope: Path | None = None,
) -> tuple[dict[str, object], list[str]]:
    """Finish the non-cyclic export before deleting disposable inputs."""

    try:
        manifest_digest, signed_payload_digest = _signed_payload_digests(
            bundle,
            qualification_contract=start.qualification_contract,
            qualification_contract_digest=start.qualification_contract_digest,
            admission_digest=admission_digest,
        )
        ledger.terminalize(
            start,
            admission_digest,
            "BUNDLE_EXPORTED",
            terminal_reason="SIGNED_PAYLOAD_EXPORTED",
            manifest_digest=manifest_digest,
            signed_payload_bundle_digest=signed_payload_digest,
            qemu_phase_outcomes=phase_outcomes,
        )
        _assemble_terminal_bundle(
            bundle,
            ledger.lab / LEDGER_NAME,
            one_use=ledger.one_use,
            lab=ledger.lab,
        )
    except (OSError, ValueError, QualificationStop) as error:
        raise QualificationStop("EVIDENCE_EXPORT_FAILED:" + str(error)) from error
    try:
        verified = _verify_bundle(bundle, one_use_scope=one_use_scope)
    except (OSError, ValueError, QualificationStop) as error:
        raise QualificationStop("EVIDENCE_VERIFICATION_FAILED:" + str(error)) from error
    try:
        removed = _cleanup_attempt(
            attempt_root,
            require_complete=True,
            lab=ledger.lab,
            max_attempts=ledger.max_attempts,
        )
    except (OSError, ValueError, QualificationStop) as error:
        raise QualificationStop("CLEANUP_FAILED:" + str(error)) from error
    try:
        _record_independent_verification(ledger, verified)
    except (OSError, ValueError, QualificationStop) as error:
        raise QualificationStop("VERIFICATION_RECORD_FAILED:" + str(error)) from error
    return verified, removed


def _key_ready_diagnostic(goal: Path) -> dict[str, object]:
    goal_digest = _digest_file(goal, 1 << 20)
    predecessor_digest = _verify_diagnostic_predecessor(
        OLD_LEDGER, OLD_LEDGER_DIGEST
    )
    source = _source_state()
    _, profile_digest = _profile()
    image, qemu_version = _verify_host_assets()
    tools = _verify_host_tools()
    _verify_kvm()
    _verify_management_port_free()
    remaining = _verify_disk_budget(IMAGE_LAB.parent)
    artifact_digests = {
        "runner": _digest_file(
            ROOT / "scripts/run_m4_vm_conformance.py", 16 << 20
        ),
        "service": _digest_file(
            ROOT / "profiles/harness-m4-controller@.service", 1 << 20
        ),
        "profile": _digest_file(ROOT / "profiles/m4-lx-a.json", 1 << 20),
    }
    start: DiagnosticStart | None = None
    phase_outcomes: dict[str, object] = {"provision": None, "run": None}
    observation: dict[str, object] = {
        "terminal_reason": "PROVISION_FAILED",
        "key_ready": None,
        "systemd_properties": {
            name: "UNAVAILABLE" for name in _SERVICE_PROPERTIES
        },
        "qemu_return_code": None,
    }
    boot_id = "UNAVAILABLE"
    unit_lines = ["UNAVAILABLE:PROVISION_FAILED"]
    kernel_lines = ["UNAVAILABLE:PROVISION_FAILED"]
    markers: list[dict[str, object]] = []
    cleanup_complete = False
    removed: list[str] = []
    bundle: Path | None = None
    cleanup_error: QualificationStop | None = None
    with DiagnosticLedger(
        DIAGNOSTIC_LAB,
        goal_reference=str(goal),
        goal_digest=goal_digest,
        predecessor_digest=predecessor_digest,
    ) as ledger:
        ledger.ensure_available()
        runs = DIAGNOSTIC_LAB / "runs"
        _mkdir_exact(runs, 0o700)
        if (DIAGNOSTIC_LAB / "diagnostics").exists() or (
            DIAGNOSTIC_LAB / "diagnostics"
        ).is_symlink():
            _stop("DIAGNOSTIC_DESTINATION_REUSE_FORBIDDEN")
        attempt_root = runs / "attempt-1"
        if attempt_root.exists() or attempt_root.is_symlink():
            _stop("DIAGNOSTIC_ATTEMPT_ROOT_REUSE_FORBIDDEN")
        attempt_root.mkdir(mode=0o700)
        try:
            seed, client_key, host_key = _create_seed(
                attempt_root, attempt=1, source=source
            )
            known_hosts = attempt_root / "known_hosts"
            _known_hosts(host_key.with_suffix(".pub"), known_hosts)
            provenance = _host_provenance(
                image,
                qemu_version=qemu_version,
                seed_digest=_digest_file(seed, _MAX_SEED_BYTES),
                attempt=1,
                lab=DIAGNOSTIC_LAB,
                phases=("provision", "run"),
            )
            environment = _digest_bytes(
                _canonical(
                    {
                        "host_provenance": provenance,
                        "profile_digest": profile_digest,
                        "diagnostic_contract": {
                            "kind": "M4_KEY_READY_PRE_ADMISSION",
                            "user_goal_digest": goal_digest,
                            "predecessor_qualification_ledger_digest": predecessor_digest,
                            "max_attempts": 1,
                            "success_target": 1,
                            "success_target_authorizing": False,
                            "phases": ["provision", "run"],
                        },
                    }
                )
            )
            request = {
                "request_version": "1.1.0",
                "mode": "KEY_READY_DIAGNOSTIC",
                "candidate": source["commit"],
                "tree": source["tree"],
                "environment": environment,
                "attempt": 1,
                "user_goal_digest": goal_digest,
                "predecessor_qualification_ledger_digest": predecessor_digest,
            }
            start = ledger.begin(
                str(source["commit"]), str(source["tree"]), environment
            )
            try:
                _create_overlay(attempt_root)
                _, phase_outcomes["provision"] = _provision_vm(
                    attempt_root,
                    1,
                    client_key,
                    known_hosts,
                    host_provenance=provenance,
                    request=request,
                    lab=DIAGNOSTIC_LAB,
                )
            except QualificationStop:
                observation["terminal_reason"] = "PROVISION_FAILED"
            else:
                try:
                    (
                        observation,
                        boot_id,
                        unit_lines,
                        kernel_lines,
                        markers,
                        phase_outcomes["run"],
                    ) = _run_diagnostic_vm_phase(
                        attempt_root, client_key, known_hosts
                    )
                except QualificationStop as error:
                    reason = "QEMU_EXITED" if "QEMU" in str(error) else "SERVICE_FAILED_PRE_KEY_READY"
                    observation = {
                        **observation,
                        "terminal_reason": reason,
                    }
                    unit_lines = ["UNAVAILABLE:" + reason]
                    kernel_lines = ["UNAVAILABLE:" + reason]
            terminal_reason = str(observation["terminal_reason"])
            record = _sanitize_diagnostic_record(
                {
                    "diagnostic_version": "1.0.0",
                    "claim": "M4_KEY_READY_PRE_ADMISSION_DIAGNOSTIC_ONLY",
                    "status": "NOT_ATTESTED",
                    "candidate": source["commit"],
                    "tree": source["tree"],
                    "environment": environment,
                    "user_scope_reference": str(goal),
                    "user_goal_digest": goal_digest,
                    "predecessor_qualification_ledger_digest": predecessor_digest,
                    "diagnostic_start_digest": start.digest,
                    "attempt": 1,
                    "boot_id": boot_id,
                    "terminal_reason": terminal_reason,
                    "systemd_properties": observation["systemd_properties"],
                    "unit_journal": unit_lines,
                    "kernel_events": kernel_lines,
                    "stage_markers": markers,
                    "artifact_digests": artifact_digests,
                    "qemu_phase_outcomes": phase_outcomes,
                }
            )
            bundle = _materialize_diagnostic_bundle(DIAGNOSTIC_LAB, record)
            bundle_digest = _digest_file(bundle, 1 << 20)
            try:
                removed = _cleanup_diagnostic_attempt(
                    attempt_root, lab=DIAGNOSTIC_LAB
                )
                cleanup_complete = True
                try:
                    os.rmdir(runs)
                except OSError:
                    pass
                _fsync_directory(DIAGNOSTIC_LAB)
            except QualificationStop as error:
                cleanup_error = error
                terminal_reason = "CLEANUP_FAILED"
            cleanup_digest = _digest_bytes(
                _canonical(
                    {
                        "complete": cleanup_complete,
                        "removed": sorted(removed),
                    }
                )
            )
            key_ready = observation["key_ready"]
            key_ready_digest = (
                _digest_bytes(_canonical(key_ready)) if key_ready is not None else None
            )
            ledger.terminalize(
                start,
                terminal_reason,
                diagnostic_bundle_digest=bundle_digest,
                key_ready_digest=key_ready_digest,
                systemd_properties_digest=_digest_bytes(
                    _canonical(observation["systemd_properties"])
                ),
                cleanup_digest=cleanup_digest,
                qemu_phase_outcomes=phase_outcomes,
            )
            if cleanup_error is not None:
                raise cleanup_error
            ledger_path = DIAGNOSTIC_LAB / DIAGNOSTIC_LEDGER_NAME
            return {
                "outcome": "DIAGNOSTIC_COMPLETE",
                "claim": "M4_KEY_READY_PRE_ADMISSION_DIAGNOSTIC_ONLY",
                "status": "NOT_ATTESTED",
                "terminal_reason": terminal_reason,
                "last_stage": markers[-1]["stage"] if markers else "NONE",
                "systemd_properties": observation["systemd_properties"],
                "qemu_return_code": observation["qemu_return_code"],
                "candidate": source["commit"],
                "tree": source["tree"],
                "environment": environment,
                "diagnostic_ledger": str(ledger_path),
                "diagnostic_ledger_digest": _digest_file(ledger_path, 2 << 20),
                "diagnostic_bundle": str(bundle),
                "diagnostic_bundle_digest": bundle_digest,
                "preserved_base_image": str(IMAGE_LAB / _IMAGE_NAME),
                "preserved_base_image_digest": _IMAGE_DIGEST,
                "removed_disposable_files": sorted(removed),
                "host_tool_digests": tools,
                "disk_bytes_remaining_after_worst_case": remaining,
            }
        except BaseException:
            if start is None:
                try:
                    _cleanup_diagnostic_attempt(attempt_root, lab=DIAGNOSTIC_LAB)
                except QualificationStop:
                    pass
            raise


def _post_v2_pre_admission_diagnostic(
    *, goal_record: object | None = None
) -> dict[str, object]:
    if goal_record is None:
        goal_record = _post_v2_diagnostic_goal_record()
    goal_record = _validate_post_v2_diagnostic_goal_record(goal_record)
    discriminator = (
        goal_record["goal_kind"]
        == "M4_PACKAGE_RUNTIME_PLAN_DISCRIMINATOR"
    )
    lab = (
        PACKAGE_PLAN_DISCRIMINATOR_LAB
        if discriminator
        else POST_V2_DIAGNOSTIC_LAB
    )
    claim = (
        "M4_PACKAGE_RUNTIME_PLAN_DISCRIMINATOR_ONLY"
        if discriminator
        else "M4_POST_V2_PRE_ADMISSION_DIAGNOSTIC_ONLY"
    )
    goal_digest = (
        PACKAGE_PLAN_DISCRIMINATOR_GOAL_DIGEST
        if discriminator
        else POST_V2_DIAGNOSTIC_GOAL_DIGEST
    )
    predecessors = (
        _verify_package_plan_discriminator_predecessors()
        if discriminator
        else {
            "failed_qualification_v2_ledger_digest": (
                _verify_failed_v2_qualification_ledger()
            )
        }
    )
    predecessor_digest = predecessors[
        "failed_qualification_v2_ledger_digest"
    ]
    source = _source_state()
    _, profile_digest = _profile()
    image, qemu_version = _verify_host_assets()
    tools = _verify_host_tools()
    package_runtime_plan = _package_runtime_plan()
    package_runtime_plan_digest = _digest_bytes(
        _canonical(package_runtime_plan)
    )
    _verify_kvm()
    _verify_management_port_free()
    remaining = _verify_disk_budget(IMAGE_LAB.parent)
    artifact_digests = {
        "host_launcher": _digest_file(Path(__file__).resolve(), 16 << 20),
        "runner": _digest_file(
            ROOT / "scripts/run_m4_vm_conformance.py", 16 << 20
        ),
        "service": _digest_file(
            ROOT / "profiles/harness-m4-controller@.service", 1 << 20
        ),
        "profile": _digest_file(ROOT / "profiles/m4-lx-a.json", 1 << 20),
    }
    start: PostV2DiagnosticStart | None = None
    phase_outcomes: dict[str, object] = {"provision": None, "run": None}
    observation: dict[str, object] = {
        "terminal_reason": "PROVISION_FAILED",
        "key_ready": None,
        "systemd_properties": {
            name: "UNAVAILABLE" for name in _SERVICE_PROPERTIES
        },
        "qemu_return_code": None,
    }
    boot_id = "UNAVAILABLE"
    unit_lines = ["UNAVAILABLE:PROVISION_FAILED"]
    kernel_lines = ["UNAVAILABLE:PROVISION_FAILED"]
    markers: list[dict[str, object]] = []
    package_runtime_plan_observation: dict[str, object] | None = None
    package_runtime_plan_observation_error: str | None = None
    cleanup_complete = False
    removed: list[str] = []
    bundle: Path | None = None
    cleanup_error: QualificationStop | None = None
    with PostV2DiagnosticLedger(lab, goal_record=goal_record) as ledger:
        ledger.ensure_available()
        runs = lab / "runs"
        _mkdir_exact(runs, 0o700)
        if (lab / "diagnostics").exists() or (lab / "diagnostics").is_symlink():
            _stop("POST_V2_DIAGNOSTIC_DESTINATION_REUSE_FORBIDDEN")
        attempt_root = runs / "attempt-1"
        if attempt_root.exists() or attempt_root.is_symlink():
            _stop("POST_V2_DIAGNOSTIC_ATTEMPT_ROOT_REUSE_FORBIDDEN")
        attempt_root.mkdir(mode=0o700)
        try:
            seed, client_key, host_key = _create_seed(
                attempt_root,
                attempt=1,
                source=source,
                package_runtime_plan=package_runtime_plan,
            )
            known_hosts = attempt_root / "known_hosts"
            _known_hosts(host_key.with_suffix(".pub"), known_hosts)
            seed_digest = _digest_file(seed, _MAX_SEED_BYTES)
            provenance = _host_provenance(
                image,
                qemu_version=qemu_version,
                seed_digest=seed_digest,
                attempt=1,
                lab=lab,
                phases=("provision", "run"),
            )
            contract = _post_v2_diagnostic_contract(
                goal_record=goal_record,
                candidate=str(source["commit"]),
                tree=str(source["tree"]),
                source_files_digest=str(source["files_digest"]),
                source_archive_digest=_digest_file(
                    attempt_root / "source.tgz", 16 << 20
                ),
                seed_digest=seed_digest,
                package_runtime_plan_digest=package_runtime_plan_digest,
                host_provenance_digest=_digest_bytes(_canonical(provenance)),
            )
            request = _post_v2_diagnostic_request(contract)
            start = ledger.begin(contract)
            try:
                _create_overlay(attempt_root)
                _, phase_outcomes["provision"] = _provision_vm(
                    attempt_root,
                    1,
                    client_key,
                    known_hosts,
                    host_provenance=provenance,
                    request=request,
                    lab=lab,
                )
            except VMCleanupUnproven:
                raise
            except QualificationStop:
                observation["terminal_reason"] = "PROVISION_FAILED"
            else:
                try:
                    (
                        observation,
                        boot_id,
                        unit_lines,
                        kernel_lines,
                        markers,
                        package_runtime_plan_result,
                        phase_outcomes["run"],
                    ) = _run_post_v2_diagnostic_vm_phase(
                        attempt_root,
                        client_key,
                        known_hosts,
                        contract,
                        lab=lab,
                    )
                    if (
                        discriminator
                        and type(package_runtime_plan_result) is dict
                        and frozenset(package_runtime_plan_result)
                        == {"package_runtime_plan_observation_error"}
                    ):
                        package_runtime_plan_observation_error = (
                            _validate_package_runtime_plan_observation_error(
                                package_runtime_plan_result[
                                    "package_runtime_plan_observation_error"
                                ]
                            )
                        )
                    else:
                        package_runtime_plan_observation = (
                            _validate_package_runtime_plan_observation(
                                package_runtime_plan_result
                            )
                        )
                except VMCleanupUnproven:
                    raise
                except QualificationStop as error:
                    reason = (
                        "QEMU_EXITED"
                        if "QEMU" in str(error)
                        else "SERVICE_FAILED_PRE_KEY_READY"
                    )
                    observation = {
                        **observation,
                        "terminal_reason": reason,
                    }
                    unit_lines = ["UNAVAILABLE:" + reason]
                    kernel_lines = ["UNAVAILABLE:" + reason]
            terminal_reason = str(observation["terminal_reason"])
            key_ready = observation["key_ready"]
            key_ready_digest = (
                _digest_bytes(_canonical(key_ready))
                if key_ready is not None
                else None
            )
            qemu_log_captures = _capture_post_v2_qemu_logs(attempt_root)
            if (
                package_runtime_plan_observation is None
                and package_runtime_plan_observation_error is None
            ):
                _stop("POST_V2_PACKAGE_RUNTIME_PLAN_OBSERVATION_MISSING")
            if package_runtime_plan_observation_error is not None:
                terminal_reason = _PACKAGE_RUNTIME_PLAN_REJECTED
            record = _sanitize_post_v2_diagnostic_record(
                {
                    "diagnostic_version": (
                        "2.3.0"
                        if package_runtime_plan_observation_error is not None
                        else ("2.2.0" if discriminator else "2.1.0")
                    ),
                    "claim": claim,
                    "status": "NOT_ATTESTED",
                    "goal_record": goal_record,
                    "goal_record_digest": goal_digest,
                    "diagnostic_contract": contract,
                    "diagnostic_contract_digest": (
                        _post_v2_diagnostic_contract_digest(contract)
                    ),
                    "contract_core_digest": contract["contract_core_digest"],
                    "diagnostic_start_digest": start.digest,
                    "boot_id": boot_id,
                    "observed_terminal_reason": terminal_reason,
                    "systemd_properties": observation["systemd_properties"],
                    "unit_journal": unit_lines,
                    "kernel_events": kernel_lines,
                    "stage_markers": markers,
                    **(
                        {
                            "package_runtime_plan_observation_error": (
                                package_runtime_plan_observation_error
                            )
                        }
                        if package_runtime_plan_observation_error is not None
                        else {
                            "package_runtime_plan_observation": (
                                package_runtime_plan_observation
                            )
                        }
                    ),
                    "artifact_digests": artifact_digests,
                    "qemu_phase_outcomes": phase_outcomes,
                    "qemu_log_captures": qemu_log_captures,
                    "key_ready_digest": key_ready_digest,
                },
                lab=lab,
            )
            bundle = _materialize_post_v2_diagnostic_bundle(lab, record)
            bundle_digest = _digest_file(bundle, 2 << 20)
            try:
                removed = _cleanup_diagnostic_attempt(
                    attempt_root, lab=lab
                )
                cleanup_complete = True
                try:
                    os.rmdir(runs)
                except OSError:
                    pass
                _fsync_directory(lab)
            except QualificationStop as error:
                cleanup_error = error
                terminal_reason = "CLEANUP_FAILED"
            cleanup_digest = _digest_bytes(
                _canonical(
                    {"complete": cleanup_complete, "removed": sorted(removed)}
                )
            )
            ledger.terminalize(
                start,
                terminal_reason,
                diagnostic_bundle_digest=bundle_digest,
                key_ready_digest=key_ready_digest,
                systemd_properties_digest=_digest_bytes(
                    _canonical(observation["systemd_properties"])
                ),
                cleanup_digest=cleanup_digest,
                qemu_phase_outcomes=phase_outcomes,
            )
            if cleanup_error is not None:
                raise cleanup_error
            ledger_path = lab / ledger.ledger_name
            return {
                "outcome": "DIAGNOSTIC_COMPLETE",
                "claim": claim,
                "status": "NOT_ATTESTED",
                "terminal_reason": terminal_reason,
                "last_stage": markers[-1]["stage"] if markers else "NONE",
                "systemd_properties": observation["systemd_properties"],
                "qemu_return_code": observation["qemu_return_code"],
                "candidate": source["commit"],
                "tree": source["tree"],
                "environment": start.environment,
                "diagnostic_contract_digest": start.diagnostic_contract_digest,
                "diagnostic_ledger": str(ledger_path),
                "diagnostic_ledger_digest": _digest_file(ledger_path, 4 << 20),
                "diagnostic_bundle": str(bundle),
                "diagnostic_bundle_digest": bundle_digest,
                "preserved_base_image": str(IMAGE_LAB / _IMAGE_NAME),
                "preserved_base_image_digest": _IMAGE_DIGEST,
                "removed_disposable_files": sorted(removed),
                "host_tool_digests": tools,
                "disk_bytes_remaining_after_worst_case": remaining,
                "predecessor_qualification_ledger_digest": predecessor_digest,
                **(
                    {
                        "predecessor_post_v2_diagnostic_ledger_digest": (
                            predecessors[
                                "post_v2_diagnostic_ledger_digest"
                            ]
                        ),
                        "predecessor_post_v2_diagnostic_bundle_digest": (
                            predecessors[
                                "post_v2_diagnostic_bundle_digest"
                            ]
                        ),
                    }
                    if discriminator
                    else {}
                ),
            }
        except VMCleanupUnproven:
            raise
        except BaseException as primary_error:
            if attempt_root.exists() or attempt_root.is_symlink():
                try:
                    _cleanup_diagnostic_attempt(
                        attempt_root, lab=lab
                    )
                except QualificationStop as cleanup_failure:
                    raise QualificationStop(
                        "CLEANUP_FAILED:" + str(cleanup_failure)
                    ) from primary_error
            raise


def _package_plan_discriminator() -> dict[str, object]:
    return _post_v2_pre_admission_diagnostic(
        goal_record=_package_plan_discriminator_goal_record()
    )


def _qualification_terminal_reason(error: BaseException, fallback: str) -> str:
    detail = str(error)
    for reason in (
        "PROVISION_FAILED", "SERVICE_FAILED_PRE_KEY_READY", "KEY_READY_TIMEOUT",
        "KEY_ADMISSION_FAILED", "RUN_FAILED", "RECOVERY_FAILED",
        "EVIDENCE_EXPORT_FAILED", "EVIDENCE_VERIFICATION_FAILED",
        "CLEANUP_FAILED",
    ):
        if reason in detail:
            return reason
    if "QEMU" in detail:
        return "QEMU_EXITED"
    return fallback


def _qualification_lifecycle(
    one_use_scope: Path | None = None,
) -> dict[str, object]:
    one_use = one_use_scope is not None
    projection: dict[str, object] | None = None
    if one_use:
        if not one_use_scope.is_absolute():
            one_use_scope = Path.cwd() / one_use_scope
        projection, goal_digest = _read_one_use_scope_projection(one_use_scope)
        goal_reference = str(projection["user_scope_reference"])
        _verify_one_use_predecessors(projection)
    else:
        goal_digest = _digest_file(USER_GOAL, 1 << 20)
        goal_reference = str(USER_GOAL)
        _verify_qualification_predecessors()
    source = _source_state()
    if one_use and (
        source["commit"] != projection["candidate"]
        or source["tree"] != projection["tree"]
    ):
        _stop("ONE_USE_SOURCE_IDENTITY_MISMATCH")
    _profile()
    image, qemu_version = _verify_host_assets()
    tools = _verify_host_tools()
    package_runtime_plan = _package_runtime_plan()
    package_runtime_plan_digest = _digest_bytes(_canonical(package_runtime_plan))
    _verify_kvm()
    _verify_management_port_free()
    remaining = _verify_disk_budget(IMAGE_LAB.parent)
    paths = (
        _prepare_one_use_paths(goal_digest)
        if one_use
        else OneUsePaths(LAB, EVIDENCE_ROOT)
    )
    lab = paths.lab
    evidence_root = paths.evidence
    start: AttemptStart | None = None
    admission_digest: str | None = None
    bundle: Path | None = None
    phase_outcomes: dict[str, object] = {}
    failure_reason = "PROVISION_FAILED"
    with AttemptLedger(
        lab,
        goal_reference=goal_reference,
        goal_digest=goal_digest,
        one_use=one_use,
        require_fresh=one_use,
        evidence_root=evidence_root,
    ) as ledger:
        attempt = ledger.next_attempt()
        _mkdir_exact(lab / "runs", 0o700)
        attempt_root = lab / "runs" / f"attempt-{attempt}"
        if attempt_root.exists() or attempt_root.is_symlink():
            _stop("ATTEMPT_ROOT_REUSE_FORBIDDEN")
        attempt_root.mkdir(mode=0o700)
        try:
            seed, client_key, host_key = _create_seed(
                attempt_root,
                attempt=attempt,
                source=source,
                package_runtime_plan=package_runtime_plan,
            )
            known_hosts = attempt_root / "known_hosts"
            _known_hosts(host_key.with_suffix(".pub"), known_hosts)
            seed_digest = _digest_file(seed, _MAX_SEED_BYTES)
            provenance = _host_provenance(
                image,
                qemu_version=qemu_version,
                seed_digest=seed_digest,
                attempt=attempt,
                lab=lab,
            )
            common_contract = {
                "source_files_digest": str(source["files_digest"]),
                "source_archive_digest": _digest_file(
                    attempt_root / "source.tgz", 16 << 20
                ),
                "seed_digest": seed_digest,
                "package_runtime_plan_digest": package_runtime_plan_digest,
                "host_provenance_digest": _digest_bytes(_canonical(provenance)),
            }
            contract = (
                _one_use_qualification_contract(
                    projection=projection,
                    projection_digest=goal_digest,
                    **common_contract,
                )
                if one_use
                else _qualification_contract(
                    goal_reference=goal_reference,
                    goal_digest=goal_digest,
                    candidate=str(source["commit"]),
                    tree=str(source["tree"]),
                    attempt=attempt,
                    **common_contract,
                )
            )
            request = {
                "request_version": "3.0.0" if one_use else "2.0.0",
                "qualification_contract": contract,
                "qualification_contract_digest": _qualification_contract_digest(
                    contract
                ),
            }
            start = ledger.begin(contract)
            _create_overlay(attempt_root)
            _, phase_outcomes["provision"] = _provision_vm(
                attempt_root,
                attempt,
                client_key,
                known_hosts,
                host_provenance=provenance,
                request=request,
                lab=lab,
            )
            failure_reason = "RUN_FAILED"
            run_result, admission_digest, _, phase_outcomes["run"] = _run_vm_phase(
                attempt_root,
                attempt,
                "run",
                client_key,
                known_hosts,
                ledger=ledger,
                start=start,
                lab=lab,
                evidence_root=evidence_root,
            )
            if admission_digest is None:
                _stop("KEY_ADMISSION_ABSENT")
            failure_reason = "RECOVERY_FAILED"
            recover_result, _, _, phase_outcomes["recover"] = _run_vm_phase(
                attempt_root,
                attempt,
                "recover",
                client_key,
                known_hosts,
                ledger=ledger,
                start=start,
                lab=lab,
                evidence_root=evidence_root,
            )
            bundle_value = recover_result.get("bundle")
            if type(bundle_value) is not str:
                _stop("EVIDENCE_EXPORT_ABSENT")
            bundle = Path(bundle_value)
            failure_reason = "EVIDENCE_EXPORT_FAILED"
            verified, removed = _finalize_exported_attempt(
                ledger=ledger,
                start=start,
                admission_digest=admission_digest,
                bundle=bundle,
                phase_outcomes=phase_outcomes,
                attempt_root=attempt_root,
                one_use_scope=one_use_scope,
            )
            return {
                "outcome": "VERIFIED",
                "claim": verified["claim_status"],
                "status": "NOT_ATTESTED",
                "candidate": source["commit"],
                "tree": source["tree"],
                "environment": start.environment,
                "qualification_contract_digest": start.qualification_contract_digest,
                "attempt": attempt,
                "bundle": str(bundle),
                "aggregate_bundle_digest": verified["aggregate_bundle_digest"],
                "host_tool_digests": tools,
                "disk_bytes_remaining_after_worst_case": remaining,
                "run_result_digest": _digest_bytes(_canonical(run_result)),
                "recovery_result_digest": _digest_bytes(_canonical(recover_result)),
                "removed_disposable_files": sorted(removed),
                "preserved_base_image": str(IMAGE_LAB / _IMAGE_NAME),
                "preserved_base_image_digest": _IMAGE_DIGEST,
            }
        except BaseException as error:
            terminal_reason = _qualification_terminal_reason(error, failure_reason)
            try:
                _cleanup_attempt(
                    attempt_root,
                    require_complete=False,
                    lab=lab,
                    max_attempts=ledger.max_attempts,
                )
            except QualificationStop:
                terminal_reason = "CLEANUP_FAILED"
            if start is not None and ledger.active_start is not None:
                ledger.terminalize(
                    start,
                    ledger.active_admission,
                    "QUARANTINED" if ledger.active_admission is not None else "FAILED",
                    terminal_reason=terminal_reason,
                )
            raise


def _qualification() -> dict[str, object]:
    return _qualification_lifecycle()


def _one_use_qualification(scope_path: Path) -> dict[str, object]:
    return _qualification_lifecycle(scope_path)


def _absent(reason: str) -> dict[str, object]:
    return {
        "outcome": "ABSENT",
        "claim": "M4_EXACT_DISPOSABLE_TEST_PROFILE_RUNTIME_CONFORMANCE",
        "reason": reason,
        "status": "NOT_ATTESTED",
    }


def _post_v2_diagnostic_absent(reason: str) -> dict[str, object]:
    return {
        "outcome": "ABSENT",
        "claim": "M4_POST_V2_PRE_ADMISSION_DIAGNOSTIC_ONLY",
        "reason": reason,
        "status": "NOT_ATTESTED",
    }


def _package_plan_discriminator_absent(reason: str) -> dict[str, object]:
    return {
        "outcome": "ABSENT",
        "claim": "M4_PACKAGE_RUNTIME_PLAN_DISCRIMINATOR_ONLY",
        "reason": reason,
        "status": "NOT_ATTESTED",
    }


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    post_v2_diagnostic = arguments == ["--post-v2-pre-admission-diagnostic"]
    package_plan_discriminator = arguments == [
        "--package-runtime-plan-discriminator"
    ]
    try:
        if not arguments:
            result = _qualification()
        elif len(arguments) == 2 and arguments[0] == "--one-use-scope":
            result = _one_use_qualification(Path(arguments[1]))
        elif len(arguments) == 2 and arguments[0] == "--key-ready-diagnostic":
            result = _key_ready_diagnostic(Path(arguments[1]))
        elif arguments == ["--post-v2-pre-admission-diagnostic"]:
            result = _post_v2_pre_admission_diagnostic()
        elif package_plan_discriminator:
            result = _package_plan_discriminator()
        else:
            _stop("M4_HOST_ARGUMENTS_FORBIDDEN")
    except (OSError, ValueError, QualificationStop) as error:
        reason = str(error) if str(error) else (
            "M4_PACKAGE_PLAN_DISCRIMINATOR_FAILED"
            if package_plan_discriminator
            else (
                "M4_POST_V2_DIAGNOSTIC_FAILED"
                if post_v2_diagnostic
                else "M4_HOST_QUALIFICATION_FAILED"
            )
        )
        failure = (
            _package_plan_discriminator_absent(reason)
            if package_plan_discriminator
            else (
                _post_v2_diagnostic_absent(reason)
                if post_v2_diagnostic
                else _absent(reason)
            )
        )
        sys.stdout.buffer.write(_canonical(failure) + b"\n")
        return 1
    sys.stdout.buffer.write(_canonical(result) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
