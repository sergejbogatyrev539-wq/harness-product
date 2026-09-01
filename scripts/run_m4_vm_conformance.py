#!/usr/bin/python3.12
"""Qualify the single disposable M4-LX-A guest runtime.

This file is deliberately a guest boundary, not a development test runner and
not a VM launcher.  It has two externally callable phases: ``run`` writes one
pre-restart record, and ``recover`` proves that the old attempt cannot resume
before exporting evidence.  Every other entry point is an internal role that
is reached only by a typed ``subprocess`` argv from the root supervisor.

The physical route is intentionally small:

    powerless worker -> controller/PEP -> one-use StageExecutionGrant
    -> executor -> sealed memfd -> observer -> publisher -> exact root

The observer and publisher create their receipts after the authoritative
event and sign with different VM-only keys.  Verification at the controller
and executor uses separate ``OpenSSLEd25519Verifier`` instances backed by the
same pinned OpenSSL libcrypto implementation; this is not claimed to be two
independent cryptographic implementations.
"""

from __future__ import annotations

from dataclasses import asdict
from datetime import UTC, datetime, timedelta
import argparse
import ctypes
import errno
import fcntl
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
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
RUNTIME = Path("/var/lib/harness-m4-runtime")
CONTROLLER = Path("/var/lib/harness-m4-controller")
M4_DATABASE = Path("/var/lib/harness-m3-controller/durable.sqlite3")
KEY_ROOT = Path("/var/lib/harness-m4-keys")
SUPPLY_KEY_ROOT = Path("/var/lib/harness-m3-attestor")
EVIDENCE = Path("/var/lib/harness-m4-evidence")
PUBLICATION_PARENT = Path("/var/lib/harness-m4-publication/anchor")
PUBLICATION_ROOT = PUBLICATION_PARENT / "publication"
DENIED_REPOSITORY = PUBLICATION_PARENT.parent / "synthetic-repository"
RUN_STATE = CONTROLLER / "run-state.json"
KEY_ADMISSION = Path("/etc/harness-m4/key-admission.json")
RUNTIME_TRUST = Path("/etc/harness-m4/runtime-trust.json")
QUALIFICATION_REQUEST = Path("/etc/harness-m4/qualification.json")
SOURCE_ARCHIVE = Path("/etc/harness-m4/source-archive.tgz")
PACKAGE_RUNTIME_PLAN = Path("/etc/harness-m4/package-runtime-plan.json")
PROVISIONING_SCRIPT = Path("/root/harness-m4-provision.sh")
PACKAGE_SOURCE_BOUNDARY_OBSERVATIONS = Path(
    "/var/lib/harness-m4-provisioning/package-source-boundaries.jsonl"
)
PROFILE_PATH = SOURCE / "profiles/m4-lx-a.json"
M4_PROFILE = Path(__file__).resolve().parents[1] / "profiles/m4-lx-a.json"
APPARMOR_POLICY = SOURCE / "profiles/m4-lx-a.apparmor"
L0_PROFILE = SOURCE / "profiles/l0-lx-a.json"
M3_RUNNER = SOURCE / "scripts/run_m3_vm_conformance.py"
VERIFIER_CODE = SOURCE / "src/harness_product/verification.py"

PYTHON = "/usr/bin/python3.12"
BWRAP = "/usr/bin/bwrap"
AA_EXEC = "/usr/bin/aa-exec"
OPENSSL = "/usr/bin/openssl"
LIBCRYPTO = "/usr/lib/x86_64-linux-gnu/libcrypto.so.3"
APPARMOR_PARSER = "/usr/sbin/apparmor_parser"
ALLOWED_PHASES = ("run", "recover")
INTERNAL_ROLES = ("controller", "executor", "observer", "publisher", "relocator")
PRE_KEY_STAGES = (
    "SERVICE_ENTERED",
    "REQUEST_VALIDATED",
    "PRE_KEY_CHECKS_COMPLETE",
    "KEY_GENERATION_STARTED",
    "KEY_GENERATION_COMPLETE",
    "RUNTIME_TRUST_READY",
    "KEY_READY_WRITTEN",
)
MAX_JSON = 8 << 20
MAX_REPORT = 1 << 20
PR_SET_NO_NEW_PRIVS = 38
F_GET_SEALS = fcntl.F_GET_SEALS
SEALED_FD_ONLY = "SEALED_FD_ONLY"
PUBLISHER_BEFORE_REPLACE = "publisher_before_replace"
EXPECTED_SCOPE = "DEPLOYMENT_ATTESTED"
KEY_ADMISSION_MODE = "HOST_ATTEMPT_LEDGER_PIN_BEFORE_WORKER_GATE"
QUALIFICATION_CONTRACT_KIND = "M4_EXACT_DISPOSABLE_TEST_PROFILE_QUALIFICATION_V2"
ONE_USE_QUALIFICATION_CONTRACT_KIND = (
    "M4_REQUEST_BOUND_ONE_USE_QUALIFICATION"
)
ONE_USE_SCOPE_PROJECTION_KIND = (
    "M4_ONE_USE_QUALIFICATION_SCOPE_PROJECTION"
)
QUALIFICATION_GOAL_REFERENCE = (
    "/home/a1/.codex/attachments/"
    "4adf762e-32a5-45e2-bf75-3c79125ace23/pasted-text.txt"
)
QUALIFICATION_GOAL_DIGEST = (
    "sha256:431777706d5b37c95c2dfebac910b1ce6a57908fe8650353058c58a83feff20b"
)
CANONICAL_PROFILE_DIGEST = (
    "sha256:50947b4b4ae139effbaddd749c7175a15755675f824e0ae1ed734a85694b4682"
)
BASE_IMAGE_DIGEST = (
    "sha256:6e40c07ae715f744f84af0bec76415cc1987dd115b4b8de437818561f01a3733"
)
PREDECESSOR_QUALIFICATION_LEDGER_DIGEST = (
    "sha256:719505206caf364c6c0d40983687416bcca5644f879a46254714621cb070d5f9"
)
PREDECESSOR_DIAGNOSTIC_LEDGER_DIGEST = (
    "sha256:6d5d1d00dc2fc303a061c1fc6f3456fb1e6c9fb1c1baae3f667a6521f8382d78"
)
PREDECESSOR_DIAGNOSTIC_BUNDLE_DIGEST = (
    "sha256:91abc47ad6070c8b9c8cad89369780b698a696c3e90aed5e2c84cb45f0b1418d"
)
ONE_USE_PREDECESSOR_QUALIFICATION_LEDGER_DIGEST = (
    "sha256:c80f4eb33b811b59a4f80aee5fdf781964b441d20e1620ca4b1f2b63f30c479a"
)
ONE_USE_PREDECESSOR_DIAGNOSTIC_LEDGER_DIGEST = (
    "sha256:f6a93ebc7f06447ed2be71f1e43c2c65d488bd9a5cb9a26cc3f03b7252f77cc3"
)
ONE_USE_PREDECESSOR_DIAGNOSTIC_BUNDLE_DIGEST = (
    "sha256:e42fbd54170edcabe49814366ccf8fa7452eb6b167d50c2c799d2d611d95b623"
)
FAILED_QUALIFICATION_V2_LEDGER_DIGEST = (
    "sha256:c80f4eb33b811b59a4f80aee5fdf781964b441d20e1620ca4b1f2b63f30c479a"
)
FAILED_V2_CANDIDATE = "a2336eb987364cc6bff0fdcdc7d7bfb8b21b3db8"
FAILED_V2_TREE = "106facb47f1b203ed121917adfa7c885374d9fdc"
POST_V2_DIAGNOSTIC_LEDGER_DIGEST = (
    "sha256:e8cfa1b9117268bf2298ba1936a99a79114e8f83aea2188e998fce6becdf97dc"
)
POST_V2_DIAGNOSTIC_BUNDLE_DIGEST = (
    "sha256:51b84c6477a17a66e92290ed7cb6f787fb9df8f5445d112d76e3e38c055f6d2f"
)
POST_V2_DIAGNOSTIC_MODE = "POST_V2_PRE_ADMISSION_DIAGNOSTIC"
POST_V2_DIAGNOSTIC_GOAL_REFERENCE = (
    "thread:/goal/m4-post-v2-pre-admission-diagnostic/2026-08-28"
)
POST_V2_DIAGNOSTIC_FORBIDDEN_OPERATIONS = [
    "AUTOMATIC_RETRY",
    "KEY_ADMISSION_ARTIFACT",
    "QUALIFICATION_EVIDENCE_EXPORT",
    "QUALIFICATION_V2_LEDGER_WRITE",
    "REBOOT_OR_RECOVERY",
    "RUNTIME_VERIFIED_CLAIM",
    "WORKER_OR_EFFECT_EXECUTION",
]
PACKAGE_PLAN_DISCRIMINATOR_MODE = "M4_PACKAGE_RUNTIME_PLAN_DISCRIMINATOR"
PACKAGE_PLAN_DISCRIMINATOR_GOAL_REFERENCE = (
    "thread:/goal/m4-package-runtime-plan-discriminator/2026-08-28"
)
PACKAGE_PLAN_DISCRIMINATOR_GOAL_DIGEST = (
    "sha256:44ff546b459a3e433b0b9ed1d009eb92c82b9fd1f3afc5f331a1ba0fe51115aa"
)
PACKAGE_PLAN_DISCRIMINATOR_FORBIDDEN_OPERATIONS = [
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
]
PACKAGE_VERSIONS = {
    "apparmor": "4.0.1really4.0.1-0ubuntu0.24.04.7",
    "apparmor-utils": "4.0.1really4.0.1-0ubuntu0.24.04.7",
    "bubblewrap": "0.9.0-1ubuntu0.1",
    "libssl3t64": "3.0.13-0ubuntu3.12",
    "openssl": "3.0.13-0ubuntu3.12",
    "python3.12": "3.12.3-1ubuntu0.15",
}
PACKAGE_SOURCE_UBUNTU_PATH = "/etc/apt/sources.list.d/ubuntu.sources"
PACKAGE_SOURCE_UBUNTU_DIGEST = (
    "sha256:eafe8bd9490d039ddaa42d1ca6e2682b0a4e68fe13845aa47d8c195292574d55"
)
PACKAGE_SOURCE_BOUNDARIES = (
    "BEFORE_APT_GET_UPDATE",
    "AFTER_EXACT_PACKAGE_INSTALL_AND_CLEAN",
)
PACKAGE_SOURCE_BOUNDARY_OUTCOMES = frozenset(
    {"MATCH", "MISMATCH", "READ_ERROR"}
)
PACKAGE_SOURCE_PATHS = frozenset(
    {
        "/etc/apt/apt.conf.d/99-harness-m4",
        PACKAGE_SOURCE_UBUNTU_PATH,
    }
)
RUNTIME_CONFIG_PATHS = frozenset(
    {
        "/etc/hosts",
        "/etc/harness-m4/nftables-offline.conf",
        "/etc/harness-m4/nftables-provisioning.conf",
    }
)
RUNTIME_TOOL_PATHS = frozenset(
    {
        AA_EXEC,
        BWRAP,
        OPENSSL,
        PYTHON,
        LIBCRYPTO,
        APPARMOR_PARSER,
    }
)
_PACKAGE_VERSION_BINDING_IDS = {
    "apparmor": "PACKAGE_VERSION_APPARMOR",
    "apparmor-utils": "PACKAGE_VERSION_APPARMOR_UTILS",
    "bubblewrap": "PACKAGE_VERSION_BUBBLEWRAP",
    "libssl3t64": "PACKAGE_VERSION_LIBSSL3T64",
    "openssl": "PACKAGE_VERSION_OPENSSL",
    "python3.12": "PACKAGE_VERSION_PYTHON3_12",
}
_PACKAGE_FILE_BINDING_IDS = {
    "/etc/apt/apt.conf.d/99-harness-m4": "PACKAGE_SOURCE_APT_HARNESS_M4",
    "/etc/apt/sources.list.d/ubuntu.sources": "PACKAGE_SOURCE_UBUNTU",
    "/etc/hosts": "RUNTIME_CONFIG_HOSTS",
    "/etc/harness-m4/nftables-offline.conf": (
        "RUNTIME_CONFIG_NFTABLES_OFFLINE"
    ),
    "/etc/harness-m4/nftables-provisioning.conf": (
        "RUNTIME_CONFIG_NFTABLES_PROVISIONING"
    ),
    AA_EXEC: "RUNTIME_TOOL_AA_EXEC",
    BWRAP: "RUNTIME_TOOL_BWRAP",
    OPENSSL: "RUNTIME_TOOL_OPENSSL",
    PYTHON: "RUNTIME_TOOL_PYTHON3_12",
    LIBCRYPTO: "RUNTIME_TOOL_LIBCRYPTO",
    APPARMOR_PARSER: "RUNTIME_TOOL_APPARMOR_PARSER",
}
PACKAGE_RUNTIME_PLAN_BINDING_IDS = (
    "PROVISIONING_SCRIPT",
    *_PACKAGE_VERSION_BINDING_IDS.values(),
    *_PACKAGE_FILE_BINDING_IDS.values(),
)
PACKAGE_RUNTIME_PLAN_OUTCOMES = frozenset(
    {"MISMATCH", "QUERY_ERROR", "DECODE_ERROR", "READ_ERROR", "RESOLVE_ERROR"}
)
ROLE_LABELS = {
    "CONTROLLER": "harness-l0-lx-a.controller",
    "EXECUTOR": "harness-l0-lx-a.executor",
    "OBSERVER": "harness-m4-lx-a.observer",
    "PUBLISHER": "harness-m4-lx-a.publisher",
}
ROLE_IDS = {
    "CONTROLLER": (3000, 4000),
    "EXECUTOR": (3003, 4003),
    "OBSERVER": (3004, 4004),
    "PUBLISHER": (3005, 4005),
}
M4_NAMESPACE_ROLE_IDS = {
    "EXECUTOR": (3003, 4003, 1003, 2003),
    "OBSERVER": (3004, 4004, 1004, 2004),
    "PUBLISHER": (3005, 4005, 1005, 2005),
}
M4_SUBORDINATE_IDS = {
    "EXECUTOR": (100002, 200002),
    "OBSERVER": (100003, 200003),
    "PUBLISHER": (100004, 200004),
}
M4_ROLE_SECCOMP_ADDITIONS = {
    "EXECUTOR": (18, 73, 77, 437),
    "OBSERVER": (18, 77),
    "PUBLISHER": (18, 47, 55, 263, 264, 437),
}
PURPOSE_ROUTES = {
    "ACTIVE_CONTRACT": "M4_AUTHORITY",
    "D2_FRONTIER": "M4_AUTHORITY",
    "M4_STAGE_AUTHORIZATION": "M4_AUTHORITY",
    "M4_STAGE_EXECUTION_GRANT": "M4_AUTHORITY",
    "M4_PUBLICATION_AUTHORIZATION": "M4_AUTHORITY",
    "M4_TOPOLOGY": "M4_AUTHORITY",
    "M4_RUNTIME_PREFLIGHT": "M4_AUTHORITY",
    "M4_OBSERVER_RECEIPT": "OBSERVER",
    "M4_PUBLICATION_RECEIPT": "PUBLISHER",
    "PRE_COMMIT": "PUBLISHER",
    "PRE_JOIN": "PUBLISHER",
}
START_PACKET = b"START"
ROLE_INPUT = Path("/inputs/m4-role.json")
_CONTROL_KEYS = frozenset({"protocol_version", "request_id", "operation", "payload"})
_CONTROL_OPERATIONS = frozenset({"BOOTSTRAP", "INSTALL", "PUBLISH", "CONTINUITY", "CONTINUE", "STOP"})
RUN_STATE_KEYS = frozenset(
    {"record_version", "phase", "identity", "trust", "durable", "publication", "execution"}
)
_RUN_IDENTITY_KEYS = frozenset(
    {
        "candidate", "environment", "attempt", "qualification_contract",
        "qualification_contract_digest", "boot_id", "guest", "source",
        "host_provenance", "package_runtime_plan",
    }
)
_RUN_TRUST_KEYS = frozenset(
    {
        "profile_digest", "m4_apparmor_digest", "m3_apparmor_digest",
        "runtime_trust_digest", "key_admission", "receipt_public_key_digests",
        "supply_public_key_digest", "verifier", "revocation_epoch", "fencing_epoch",
    }
)
_M4_RECOVERY_KEYS = frozenset(
    {
        "transaction_id", "state", "contract_digest", "d2_frontier_digest",
        "fencing_epoch", "record_digest", "frontier_record_digest", "iteration",
        "frontier_attempt_cursor", "frontier_joined_iteration", "attempt_cursor",
        "joined_iteration", "journal_sequence", "intent_state", "revocation_epoch",
        "resume_allowed", "retry_allowed",
    }
)
_RECOVERY_SESSION_KEYS = frozenset(
    {"session_record_id", "transaction_id", "claim_digest", "state", "fencing_epoch"}
)
_RUN_DURABLE_KEYS = frozenset({"m4_recovery", "m3_runtime_session"})
_RUN_PUBLICATION_KEYS = frozenset(
    {
        "root", "topology_digest", "root_anchor", "target_binding",
        "published_binding", "artifact_digest", "snapshot_digest", "transport",
    }
)
_RUN_EXECUTION_KEYS = frozenset(
    {
        "controller_facts", "publisher_facts", "executor_facts", "observer_facts",
        "runtime_events", "denial_events", "role_seccomp_digests",
        "m3_role_seccomp", "cleanup",
    }
)
_QUALIFICATION_REQUEST_KEYS = frozenset(
    {"request_version", "qualification_contract", "qualification_contract_digest"}
)
_QUALIFICATION_CONTRACT_KEYS = frozenset(
    {
        "contract_core", "contract_core_digest", "environment_preimage",
        "environment_digest",
    }
)
_QUALIFICATION_CORE_KEYS = frozenset(
    {
        "contract_version", "contract_kind", "user_scope_reference",
        "user_goal_digest", "candidate", "tree", "attempt",
        "source_files_digest", "canonical_profile_digest",
        "raw_profile_artifact_digest", "base_image_digest",
        "predecessor_qualification_ledger_digest",
        "predecessor_diagnostic_ledger_digest",
        "predecessor_diagnostic_bundle_digest", "max_attempts",
        "success_target", "success_target_authorizing",
    }
)
_ONE_USE_QUALIFICATION_CORE_KEYS = _QUALIFICATION_CORE_KEYS | {
    "scope_projection"
}
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
_QUALIFICATION_ENVIRONMENT_KEYS = frozenset(
    {
        "contract_core_digest", "source_archive_digest", "seed_digest",
        "package_runtime_plan_digest", "host_provenance_digest",
    }
)
_POST_V2_DIAGNOSTIC_REQUEST_KEYS = frozenset(
    {"request_version", "mode", "diagnostic_contract", "diagnostic_contract_digest"}
)
_POST_V2_DIAGNOSTIC_CONTRACT_KEYS = frozenset(
    {
        "contract_core", "contract_core_digest", "environment_preimage",
        "environment_digest",
    }
)
_POST_V2_DIAGNOSTIC_CORE_KEYS = frozenset(
    {
        "contract_version", "contract_kind", "goal_record", "goal_record_digest",
        "failed_v2_candidate", "failed_v2_tree",
        "failed_qualification_v2_ledger_digest", "candidate", "tree", "attempt",
        "source_files_digest", "canonical_profile_digest",
        "raw_profile_artifact_digest", "base_image_digest", "max_attempts",
        "allowed_phases", "non_authorizing",
    }
)
_POST_V2_DIAGNOSTIC_GOAL_KEYS = frozenset(
    {
        "goal_version", "goal_kind", "user_scope_reference",
        "predecessor_qualification_ledger_digest", "max_attempts",
        "allowed_phases", "allowed_outcome", "forbidden_operations",
    }
)
_PACKAGE_PLAN_DISCRIMINATOR_CORE_KEYS = frozenset(
    {
        "contract_version", "contract_kind", "goal_record", "goal_record_digest",
        "failed_v2_candidate", "failed_v2_tree",
        "failed_qualification_v2_ledger_digest",
        "predecessor_post_v2_diagnostic_ledger_digest",
        "predecessor_post_v2_diagnostic_bundle_digest", "candidate", "tree",
        "attempt", "source_files_digest", "canonical_profile_digest",
        "raw_profile_artifact_digest", "base_image_digest", "max_attempts",
        "allowed_phases", "non_authorizing",
    }
)
_PACKAGE_PLAN_DISCRIMINATOR_GOAL_KEYS = frozenset(
    {
        "goal_version", "goal_kind", "user_scope_reference",
        "predecessor_qualification_ledger_digest",
        "predecessor_post_v2_diagnostic_ledger_digest",
        "predecessor_post_v2_diagnostic_bundle_digest", "max_attempts",
        "success_target", "success_target_authorizing", "allowed_phases",
        "allowed_outcome", "forbidden_operations",
    }
)
_PACKAGE_RUNTIME_PLAN_KEYS = frozenset(
    {
        "plan_version", "packages", "provisioning_script_digest",
        "package_sources", "runtime_configs", "runtime_tools",
    }
)
_PACKAGE_SOURCE_BOUNDARY_OBSERVATION_KEYS = frozenset(
    {
        "record_type", "non_authorizing", "binding_id", "boundary",
        "outcome", "expected_sha256", "observed_sha256",
    }
)
_KEY_ADMISSION_KEYS = frozenset(
    {
        "admission_version", "mode", "qualification_contract",
        "qualification_contract_digest", "contract_core_digest", "ledger_entry_digest",
        "receipt_public_key_digests", "supply_public_key_digest",
        "runtime_trust_digest",
    }
)


class QualificationStop(Exception):
    """One structured fail-closed qualification outcome."""


_STOP_REASON = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
_POST_KEY_EXCEPTION_STAGES = (
    "ADMISSION_CONSUMPTION",
    "SUPPLY_AND_CONTROLLER_SETUP",
    "PUBLISHER_AUTHORITY_FRONTIER_SETUP",
    "RUNTIME_CONSTRUCTION",
    "COORDINATOR_EXECUTION",
    "PRE_RESTART_FINALIZATION",
)
_POST_KEY_EXCEPTION_CLASSES = (
    (json.JSONDecodeError, "JSONDECODEERROR"),
    (sqlite3.Error, "SQLITEERROR"),
    (subprocess.SubprocessError, "SUBPROCESSERROR"),
    (OSError, "OSERROR"),
    (ValueError, "VALUEERROR"),
    (TypeError, "TYPEERROR"),
    (KeyError, "KEYERROR"),
    (AttributeError, "ATTRIBUTEERROR"),
    (Exception, "EXCEPTION"),
)


def _sanitize_stop_reason(reason: object) -> str:
    if type(reason) is str and _STOP_REASON.fullmatch(reason) is not None:
        return reason
    return "M4_RUNTIME_FAILURE"


def _stop(reason: object) -> NoReturn:
    raise QualificationStop(_sanitize_stop_reason(reason))


def _post_key_exception_reason(stage: object, error: object) -> str:
    if (
        type(stage) is not str
        or stage not in _POST_KEY_EXCEPTION_STAGES
        or not isinstance(error, Exception)
    ):
        return "M4_RUNTIME_FAILURE"
    for exception_type, code in _POST_KEY_EXCEPTION_CLASSES:
        if isinstance(error, exception_type):
            return f"M4_POST_KEY_{stage}_{code}"
    return "M4_RUNTIME_FAILURE"


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
        raise QualificationStop("MALFORMED_VALUE") from error


def _diagnostic_stage(stage: str) -> None:
    if stage not in PRE_KEY_STAGES:
        _stop("M4_DIAGNOSTIC_STAGE_MISMATCH")
    raw = _canonical(
        {
            "record_type": "M4_PRE_KEY_STAGE",
            "stage": stage,
            "non_authorizing": True,
        }
    ) + b"\n"
    try:
        if os.write(1, raw) != len(raw):
            _stop("M4_DIAGNOSTIC_STAGE_WRITE_FAILED")
    except OSError as error:
        raise QualificationStop("M4_DIAGNOSTIC_STAGE_WRITE_FAILED") from error


def _emit_package_runtime_plan_observation(binding_id: str, outcome: str) -> None:
    if (
        type(binding_id) is not str
        or binding_id not in PACKAGE_RUNTIME_PLAN_BINDING_IDS
        or type(outcome) is not str
        or outcome not in PACKAGE_RUNTIME_PLAN_OUTCOMES
    ):
        _stop("M4_PACKAGE_RUNTIME_PLAN_OBSERVATION_MALFORMED")
    raw = _canonical(
        {
            "binding_id": binding_id,
            "non_authorizing": True,
            "outcome": outcome,
            "record_type": "M4_PACKAGE_RUNTIME_PLAN_OBSERVATION",
        }
    ) + b"\n"
    try:
        if os.write(1, raw) != len(raw):
            _stop("M4_PACKAGE_RUNTIME_PLAN_OBSERVATION_WRITE_FAILED")
    except OSError as error:
        raise QualificationStop(
            "M4_PACKAGE_RUNTIME_PLAN_OBSERVATION_WRITE_FAILED"
        ) from error


def _emit_package_source_boundary_observation(
    value: dict[str, object],
) -> None:
    raw = _canonical(value) + b"\n"
    try:
        if os.write(1, raw) != len(raw):
            _stop("M4_PACKAGE_SOURCE_BOUNDARY_OBSERVATION_WRITE_FAILED")
    except OSError as error:
        raise QualificationStop(
            "M4_PACKAGE_SOURCE_BOUNDARY_OBSERVATION_WRITE_FAILED"
        ) from error


def _package_runtime_plan_binding_stop(
    binding_id: str | None,
    outcome: str,
    diagnostic_observation: bool,
    error: BaseException | None = None,
) -> NoReturn:
    if diagnostic_observation:
        if binding_id is None:
            _stop("PACKAGE_RUNTIME_PLAN_MISMATCH")
        _emit_package_runtime_plan_observation(binding_id, outcome)
    if error is None:
        _stop("PACKAGE_RUNTIME_PLAN_BINDING_MISMATCH")
    raise QualificationStop("PACKAGE_RUNTIME_PLAN_BINDING_MISMATCH") from error


def _pairs(rows: list[tuple[object, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in rows:
        if type(key) is not str or key in result:
            _stop("DUPLICATE_OR_NONSTRING_KEY")
        result[key] = value
    return result


def _strict_bytes(raw: bytes, maximum: int = MAX_JSON) -> object:
    if type(raw) is not bytes or not raw or len(raw) > maximum:
        _stop("JSON_BOUNDS")

    def bad_constant(_: str) -> NoReturn:
        _stop("NONFINITE_JSON")

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_pairs,
            parse_constant=bad_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise QualificationStop("MALFORMED_JSON") from error
    if _canonical(value) != raw:
        _stop("NONCANONICAL_JSON")
    return value


def _read_regular(path: Path, maximum: int = MAX_JSON) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
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
        raw = b""
        while len(raw) <= maximum:
            chunk = os.read(descriptor, min(65536, maximum + 1 - len(raw)))
            if not chunk:
                break
            raw += chunk
        if len(raw) != info.st_size:
            _stop("SHORT_OR_UNBOUNDED_READ")
        return raw
    finally:
        os.close(descriptor)


def _strict_file(path: Path, keys: frozenset[str], maximum: int = MAX_JSON) -> dict[str, object]:
    value = _strict_bytes(_read_regular(path, maximum), maximum)
    if type(value) is not dict or frozenset(value) != keys:
        _stop("UNKNOWN_OR_MISSING_FIELD")
    return value


def _digest_bytes(value: bytes) -> str:
    return "sha256:" + sha256(value).hexdigest()


def _digest_file(path: Path, maximum: int = 64 << 20) -> str:
    return _digest_bytes(_read_regular(path, maximum))


def _write_exact(path: Path, payload: bytes, mode: int, uid: int = 0, gid: int = 0) -> None:
    if path.exists() or path.is_symlink():
        _stop("OUTPUT_REUSE_FORBIDDEN")
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        mode,
    )
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                _stop("SHORT_WRITE")
            offset += written
        os.fchown(descriptor, uid, gid)
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _is_digest(value: object) -> bool:
    return type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None


def _validate_v2_qualification_contract(value: object) -> dict[str, object]:
    if type(value) is not dict or frozenset(value) != _QUALIFICATION_CONTRACT_KEYS:
        _stop("M4_QUALIFICATION_CONTRACT_MISMATCH")
    core = value["contract_core"]
    environment = value["environment_preimage"]
    if (
        type(core) is not dict
        or frozenset(core) != _QUALIFICATION_CORE_KEYS
        or type(environment) is not dict
        or frozenset(environment) != _QUALIFICATION_ENVIRONMENT_KEYS
        or core["contract_version"] != "2.0.0"
        or core["contract_kind"] != QUALIFICATION_CONTRACT_KIND
        or core["user_scope_reference"] != QUALIFICATION_GOAL_REFERENCE
        or core["user_goal_digest"] != QUALIFICATION_GOAL_DIGEST
        or type(core["candidate"]) is not str
        or re.fullmatch(r"[0-9a-f]{40}", core["candidate"]) is None
        or type(core["tree"]) is not str
        or re.fullmatch(r"[0-9a-f]{40}", core["tree"]) is None
        or type(core["attempt"]) is not int
        or isinstance(core["attempt"], bool)
        or core["attempt"] not in {1, 2}
        or core["canonical_profile_digest"] != CANONICAL_PROFILE_DIGEST
        or core["raw_profile_artifact_digest"] != CANONICAL_PROFILE_DIGEST
        or core["base_image_digest"] != BASE_IMAGE_DIGEST
        or core["predecessor_qualification_ledger_digest"]
        != PREDECESSOR_QUALIFICATION_LEDGER_DIGEST
        or core["predecessor_diagnostic_ledger_digest"]
        != PREDECESSOR_DIAGNOSTIC_LEDGER_DIGEST
        or core["predecessor_diagnostic_bundle_digest"]
        != PREDECESSOR_DIAGNOSTIC_BUNDLE_DIGEST
        or type(core["max_attempts"]) is not int
        or core["max_attempts"] != 2
        or type(core["success_target"]) is not int
        or core["success_target"] != 1
        or core["success_target_authorizing"] is not False
        or not _is_digest(core["source_files_digest"])
        or not all(_is_digest(item) for item in environment.values())
    ):
        _stop("M4_QUALIFICATION_CONTRACT_MISMATCH")
    core_digest = _digest_bytes(_canonical(core))
    if (
        value["contract_core_digest"] != core_digest
        or environment["contract_core_digest"] != core_digest
        or value["environment_digest"] != _digest_bytes(_canonical(environment))
    ):
        _stop("M4_QUALIFICATION_CONTRACT_DIGEST_MISMATCH")
    return value


def _validate_one_use_scope_projection(value: object) -> dict[str, object]:
    if type(value) is not dict or frozenset(value) != _ONE_USE_SCOPE_PROJECTION_KEYS:
        _stop("M4_ONE_USE_SCOPE_PROJECTION_MISMATCH")
    reference = value["user_scope_reference"]
    if type(reference) is not str or not reference:
        _stop("M4_ONE_USE_SCOPE_PROJECTION_MISMATCH")
    try:
        reference_bytes = reference.encode("utf-8")
    except UnicodeEncodeError:
        _stop("M4_ONE_USE_SCOPE_PROJECTION_MISMATCH")
    if (
        value["record_version"] != "1.0.0"
        or value["record_kind"] != ONE_USE_SCOPE_PROJECTION_KIND
        or value["authority"] != "NONE"
        or len(reference_bytes) > 512
        or type(value["candidate"]) is not str
        or re.fullmatch(r"[0-9a-f]{40}", value["candidate"]) is None
        or type(value["tree"]) is not str
        or re.fullmatch(r"[0-9a-f]{40}", value["tree"]) is None
        or type(value["max_attempts"]) is not int
        or isinstance(value["max_attempts"], bool)
        or value["max_attempts"] != 1
        or type(value["success_target"]) is not int
        or isinstance(value["success_target"], bool)
        or value["success_target"] != 1
        or value["success_target_authorizing"] is not False
        or value["predecessor_qualification_ledger_digest"]
        != ONE_USE_PREDECESSOR_QUALIFICATION_LEDGER_DIGEST
        or value["predecessor_diagnostic_ledger_digest"]
        != ONE_USE_PREDECESSOR_DIAGNOSTIC_LEDGER_DIGEST
        or value["predecessor_diagnostic_bundle_digest"]
        != ONE_USE_PREDECESSOR_DIAGNOSTIC_BUNDLE_DIGEST
    ):
        _stop("M4_ONE_USE_SCOPE_PROJECTION_MISMATCH")
    return value


def _validate_one_use_qualification_contract(
    value: object,
) -> dict[str, object]:
    if type(value) is not dict or frozenset(value) != _QUALIFICATION_CONTRACT_KEYS:
        _stop("M4_ONE_USE_QUALIFICATION_CONTRACT_MISMATCH")
    core = value["contract_core"]
    environment = value["environment_preimage"]
    if (
        type(core) is not dict
        or frozenset(core) != _ONE_USE_QUALIFICATION_CORE_KEYS
        or type(environment) is not dict
        or frozenset(environment) != _QUALIFICATION_ENVIRONMENT_KEYS
    ):
        _stop("M4_ONE_USE_QUALIFICATION_CONTRACT_MISMATCH")
    projection = _validate_one_use_scope_projection(core["scope_projection"])
    projection_digest = _digest_bytes(_canonical(projection))
    if (
        core["contract_version"] != "3.0.0"
        or core["contract_kind"] != ONE_USE_QUALIFICATION_CONTRACT_KIND
        or core["user_scope_reference"] != projection["user_scope_reference"]
        or core["user_goal_digest"] != projection_digest
        or core["candidate"] != projection["candidate"]
        or core["tree"] != projection["tree"]
        or type(core["attempt"]) is not int
        or isinstance(core["attempt"], bool)
        or core["attempt"] != 1
        or core["canonical_profile_digest"] != CANONICAL_PROFILE_DIGEST
        or core["raw_profile_artifact_digest"] != CANONICAL_PROFILE_DIGEST
        or core["base_image_digest"] != BASE_IMAGE_DIGEST
        or core["predecessor_qualification_ledger_digest"]
        != projection["predecessor_qualification_ledger_digest"]
        or core["predecessor_diagnostic_ledger_digest"]
        != projection["predecessor_diagnostic_ledger_digest"]
        or core["predecessor_diagnostic_bundle_digest"]
        != projection["predecessor_diagnostic_bundle_digest"]
        or type(core["max_attempts"]) is not int
        or isinstance(core["max_attempts"], bool)
        or core["max_attempts"] != projection["max_attempts"]
        or type(core["success_target"]) is not int
        or isinstance(core["success_target"], bool)
        or core["success_target"] != projection["success_target"]
        or core["success_target_authorizing"]
        is not projection["success_target_authorizing"]
        or not _is_digest(core["source_files_digest"])
        or not all(_is_digest(item) for item in environment.values())
    ):
        _stop("M4_ONE_USE_QUALIFICATION_CONTRACT_MISMATCH")
    core_digest = _digest_bytes(_canonical(core))
    if (
        value["contract_core_digest"] != core_digest
        or environment["contract_core_digest"] != core_digest
        or value["environment_digest"] != _digest_bytes(_canonical(environment))
    ):
        _stop("M4_ONE_USE_QUALIFICATION_CONTRACT_DIGEST_MISMATCH")
    return value


def _validate_qualification_contract(value: object) -> dict[str, object]:
    core = value.get("contract_core") if type(value) is dict else None
    selector = (
        (core.get("contract_version"), core.get("contract_kind"))
        if type(core) is dict
        else (None, None)
    )
    if selector == ("2.0.0", QUALIFICATION_CONTRACT_KIND):
        return _validate_v2_qualification_contract(value)
    if selector == ("3.0.0", ONE_USE_QUALIFICATION_CONTRACT_KIND):
        return _validate_one_use_qualification_contract(value)
    _stop("M4_QUALIFICATION_CONTRACT_MISMATCH")


def _v2_qualification_request_contract(
    request: dict[str, object],
) -> tuple[dict[str, object], str]:
    if (
        type(request) is not dict
        or frozenset(request) != _QUALIFICATION_REQUEST_KEYS
        or request.get("request_version") != "2.0.0"
    ):
        _stop("M4_QUALIFICATION_REQUEST_MISMATCH")
    contract = _validate_v2_qualification_contract(
        request["qualification_contract"]
    )
    digest = _digest_bytes(_canonical(contract))
    if request["qualification_contract_digest"] != digest:
        _stop("M4_QUALIFICATION_CONTRACT_DIGEST_MISMATCH")
    return contract, digest


def _one_use_qualification_request_contract(
    request: dict[str, object],
) -> tuple[dict[str, object], str]:
    if (
        type(request) is not dict
        or frozenset(request) != _QUALIFICATION_REQUEST_KEYS
        or request.get("request_version") != "3.0.0"
    ):
        _stop("M4_ONE_USE_QUALIFICATION_REQUEST_MISMATCH")
    contract = _validate_one_use_qualification_contract(
        request["qualification_contract"]
    )
    digest = _digest_bytes(_canonical(contract))
    if request["qualification_contract_digest"] != digest:
        _stop("M4_ONE_USE_QUALIFICATION_CONTRACT_DIGEST_MISMATCH")
    return contract, digest


def _qualification_request_contract(
    request: dict[str, object],
) -> tuple[dict[str, object], str]:
    version = request.get("request_version") if type(request) is dict else None
    if version == "2.0.0":
        return _v2_qualification_request_contract(request)
    if version == "3.0.0":
        return _one_use_qualification_request_contract(request)
    _stop("M4_QUALIFICATION_REQUEST_MISMATCH")


def _post_v2_diagnostic_request_contract(
    request: dict[str, object],
) -> tuple[dict[str, object], str]:
    if (
        type(request) is not dict
        or frozenset(request) != _POST_V2_DIAGNOSTIC_REQUEST_KEYS
        or request.get("request_version") != "2.1.0"
        or request.get("mode") != POST_V2_DIAGNOSTIC_MODE
    ):
        _stop("M4_POST_V2_DIAGNOSTIC_REQUEST_MISMATCH")
    contract = request["diagnostic_contract"]
    if type(contract) is not dict or frozenset(contract) != (
        _POST_V2_DIAGNOSTIC_CONTRACT_KEYS
    ):
        _stop("M4_POST_V2_DIAGNOSTIC_CONTRACT_MISMATCH")
    core = contract["contract_core"]
    environment = contract["environment_preimage"]
    if (
        type(core) is not dict
        or frozenset(core) != _POST_V2_DIAGNOSTIC_CORE_KEYS
        or type(environment) is not dict
        or frozenset(environment) != _QUALIFICATION_ENVIRONMENT_KEYS
    ):
        _stop("M4_POST_V2_DIAGNOSTIC_CONTRACT_MISMATCH")
    goal = core["goal_record"]
    expected_goal = {
        "goal_version": "1.0.0",
        "goal_kind": "M4_POST_V2_PRE_ADMISSION_DIAGNOSTIC",
        "user_scope_reference": POST_V2_DIAGNOSTIC_GOAL_REFERENCE,
        "predecessor_qualification_ledger_digest": (
            FAILED_QUALIFICATION_V2_LEDGER_DIGEST
        ),
        "max_attempts": 1,
        "allowed_phases": ["provision", "run"],
        "allowed_outcome": "SANITIZED_DIAGNOSTIC_ONLY",
        "forbidden_operations": POST_V2_DIAGNOSTIC_FORBIDDEN_OPERATIONS,
    }
    if (
        type(goal) is not dict
        or frozenset(goal) != _POST_V2_DIAGNOSTIC_GOAL_KEYS
        or _canonical(goal) != _canonical(expected_goal)
        or core["contract_version"] != "1.0.0"
        or core["contract_kind"] != "M4_POST_V2_PRE_ADMISSION_DIAGNOSTIC"
        or core["goal_record_digest"] != _digest_bytes(_canonical(goal))
        or core["failed_v2_candidate"] != FAILED_V2_CANDIDATE
        or core["failed_v2_tree"] != FAILED_V2_TREE
        or core["failed_qualification_v2_ledger_digest"]
        != FAILED_QUALIFICATION_V2_LEDGER_DIGEST
        or type(core["candidate"]) is not str
        or re.fullmatch(r"[0-9a-f]{40}", core["candidate"]) is None
        or core["candidate"] == FAILED_V2_CANDIDATE
        or type(core["tree"]) is not str
        or re.fullmatch(r"[0-9a-f]{40}", core["tree"]) is None
        or core["tree"] == FAILED_V2_TREE
        or type(core["attempt"]) is not int
        or isinstance(core["attempt"], bool)
        or core["attempt"] != 1
        or not _is_digest(core["source_files_digest"])
        or core["canonical_profile_digest"] != CANONICAL_PROFILE_DIGEST
        or core["raw_profile_artifact_digest"] != CANONICAL_PROFILE_DIGEST
        or core["base_image_digest"] != BASE_IMAGE_DIGEST
        or type(core["max_attempts"]) is not int
        or isinstance(core["max_attempts"], bool)
        or core["max_attempts"] != 1
        or core["allowed_phases"] != ["provision", "run"]
        or core["non_authorizing"] is not True
        or not all(_is_digest(item) for item in environment.values())
    ):
        _stop("M4_POST_V2_DIAGNOSTIC_CONTRACT_MISMATCH")
    core_digest = _digest_bytes(_canonical(core))
    contract_digest = _digest_bytes(_canonical(contract))
    if (
        contract["contract_core_digest"] != core_digest
        or environment["contract_core_digest"] != core_digest
        or contract["environment_digest"]
        != _digest_bytes(_canonical(environment))
        or request["diagnostic_contract_digest"] != contract_digest
    ):
        _stop("M4_POST_V2_DIAGNOSTIC_CONTRACT_DIGEST_MISMATCH")
    return contract, contract_digest


def _package_plan_discriminator_request_contract(
    request: dict[str, object],
) -> tuple[dict[str, object], str]:
    if (
        type(request) is not dict
        or frozenset(request) != _POST_V2_DIAGNOSTIC_REQUEST_KEYS
        or request.get("request_version") != "2.2.0"
        or request.get("mode") != PACKAGE_PLAN_DISCRIMINATOR_MODE
    ):
        _stop("M4_PACKAGE_PLAN_DISCRIMINATOR_REQUEST_MISMATCH")
    contract = request["diagnostic_contract"]
    if type(contract) is not dict or frozenset(contract) != (
        _POST_V2_DIAGNOSTIC_CONTRACT_KEYS
    ):
        _stop("M4_PACKAGE_PLAN_DISCRIMINATOR_CONTRACT_MISMATCH")
    core = contract["contract_core"]
    environment = contract["environment_preimage"]
    if (
        type(core) is not dict
        or frozenset(core) != _PACKAGE_PLAN_DISCRIMINATOR_CORE_KEYS
        or type(environment) is not dict
        or frozenset(environment) != _QUALIFICATION_ENVIRONMENT_KEYS
    ):
        _stop("M4_PACKAGE_PLAN_DISCRIMINATOR_CONTRACT_MISMATCH")
    goal = core["goal_record"]
    expected_goal = {
        "goal_version": "1.0.0",
        "goal_kind": PACKAGE_PLAN_DISCRIMINATOR_MODE,
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
        "forbidden_operations": (
            PACKAGE_PLAN_DISCRIMINATOR_FORBIDDEN_OPERATIONS
        ),
    }
    if (
        type(goal) is not dict
        or frozenset(goal) != _PACKAGE_PLAN_DISCRIMINATOR_GOAL_KEYS
        or _canonical(goal) != _canonical(expected_goal)
        or _digest_bytes(_canonical(goal))
        != PACKAGE_PLAN_DISCRIMINATOR_GOAL_DIGEST
        or core["contract_version"] != "1.0.0"
        or core["contract_kind"] != PACKAGE_PLAN_DISCRIMINATOR_MODE
        or core["goal_record_digest"]
        != PACKAGE_PLAN_DISCRIMINATOR_GOAL_DIGEST
        or core["failed_v2_candidate"] != FAILED_V2_CANDIDATE
        or core["failed_v2_tree"] != FAILED_V2_TREE
        or core["failed_qualification_v2_ledger_digest"]
        != FAILED_QUALIFICATION_V2_LEDGER_DIGEST
        or core["predecessor_post_v2_diagnostic_ledger_digest"]
        != POST_V2_DIAGNOSTIC_LEDGER_DIGEST
        or core["predecessor_post_v2_diagnostic_bundle_digest"]
        != POST_V2_DIAGNOSTIC_BUNDLE_DIGEST
        or type(core["candidate"]) is not str
        or re.fullmatch(r"[0-9a-f]{40}", core["candidate"]) is None
        or core["candidate"] == FAILED_V2_CANDIDATE
        or type(core["tree"]) is not str
        or re.fullmatch(r"[0-9a-f]{40}", core["tree"]) is None
        or core["tree"] == FAILED_V2_TREE
        or type(core["attempt"]) is not int
        or isinstance(core["attempt"], bool)
        or core["attempt"] != 1
        or not _is_digest(core["source_files_digest"])
        or core["canonical_profile_digest"] != CANONICAL_PROFILE_DIGEST
        or core["raw_profile_artifact_digest"] != CANONICAL_PROFILE_DIGEST
        or core["base_image_digest"] != BASE_IMAGE_DIGEST
        or type(core["max_attempts"]) is not int
        or isinstance(core["max_attempts"], bool)
        or core["max_attempts"] != 1
        or core["allowed_phases"] != ["provision", "run"]
        or core["non_authorizing"] is not True
        or not all(_is_digest(item) for item in environment.values())
    ):
        _stop("M4_PACKAGE_PLAN_DISCRIMINATOR_CONTRACT_MISMATCH")
    core_digest = _digest_bytes(_canonical(core))
    contract_digest = _digest_bytes(_canonical(contract))
    if (
        contract["contract_core_digest"] != core_digest
        or environment["contract_core_digest"] != core_digest
        or contract["environment_digest"]
        != _digest_bytes(_canonical(environment))
        or request["diagnostic_contract_digest"] != contract_digest
    ):
        _stop("M4_PACKAGE_PLAN_DISCRIMINATOR_CONTRACT_DIGEST_MISMATCH")
    return contract, contract_digest


def _validate_launch_request(request: object) -> str:
    diagnostic_keys = frozenset(
        {
            "request_version", "mode", "candidate", "tree", "environment",
            "attempt", "user_goal_digest",
            "predecessor_qualification_ledger_digest",
        }
    )
    if type(request) is not dict:
        _stop("M4_QUALIFICATION_REQUEST_MISMATCH")
    if frozenset(request) == _QUALIFICATION_REQUEST_KEYS:
        _qualification_request_contract(request)
        return (
            ONE_USE_QUALIFICATION_CONTRACT_KIND
            if request.get("request_version") == "3.0.0"
            else "QUALIFICATION"
        )
    if frozenset(request) == _POST_V2_DIAGNOSTIC_REQUEST_KEYS:
        selector = (request.get("request_version"), request.get("mode"))
        if selector == ("2.1.0", POST_V2_DIAGNOSTIC_MODE):
            _post_v2_diagnostic_request_contract(request)
            return POST_V2_DIAGNOSTIC_MODE
        if selector == ("2.2.0", PACKAGE_PLAN_DISCRIMINATOR_MODE):
            _package_plan_discriminator_request_contract(request)
            return PACKAGE_PLAN_DISCRIMINATOR_MODE
        _stop("M4_DIAGNOSTIC_REQUEST_MISMATCH")
    if frozenset(request) == diagnostic_keys:
        if (
            request["request_version"] != "1.1.0"
            or request["mode"] != "KEY_READY_DIAGNOSTIC"
            or type(request["candidate"]) is not str
            or re.fullmatch(r"[0-9a-f]{40}", request["candidate"]) is None
            or type(request["tree"]) is not str
            or re.fullmatch(r"[0-9a-f]{40}", request["tree"]) is None
            or not _is_digest(request["environment"])
            or type(request["attempt"]) is not int
            or isinstance(request["attempt"], bool)
            or request["attempt"] != 1
            or not _is_digest(request["user_goal_digest"])
            or not _is_digest(request["predecessor_qualification_ledger_digest"])
        ):
            _stop("M4_DIAGNOSTIC_REQUEST_MISMATCH")
        return "KEY_READY_DIAGNOSTIC"
    _stop("M4_QUALIFICATION_REQUEST_MISMATCH")


def _validate_package_runtime_plan(value: object) -> dict[str, object]:
    if type(value) is not dict or frozenset(value) != _PACKAGE_RUNTIME_PLAN_KEYS:
        _stop("PACKAGE_RUNTIME_PLAN_MISMATCH")
    packages = value["packages"]
    sources = value["package_sources"]
    configs = value["runtime_configs"]
    tools = value["runtime_tools"]
    if (
        value["plan_version"] != "1.0.0"
        or type(packages) is not dict
        or packages != PACKAGE_VERSIONS
        or not _is_digest(value["provisioning_script_digest"])
        or type(sources) is not dict
        or frozenset(sources) != PACKAGE_SOURCE_PATHS
        or sources.get(PACKAGE_SOURCE_UBUNTU_PATH)
        != PACKAGE_SOURCE_UBUNTU_DIGEST
        or type(configs) is not dict
        or frozenset(configs) != RUNTIME_CONFIG_PATHS
        or type(tools) is not dict
        or frozenset(tools) != RUNTIME_TOOL_PATHS
        or not all(
            _is_digest(digest)
            for bindings in (sources, configs, tools)
            for digest in bindings.values()
        )
    ):
        _stop("PACKAGE_RUNTIME_PLAN_MISMATCH")
    return value


def _validate_package_source_boundary_observation(
    value: object,
) -> dict[str, object]:
    if (
        type(value) is not dict
        or frozenset(value) != _PACKAGE_SOURCE_BOUNDARY_OBSERVATION_KEYS
        or value.get("record_type")
        != "M4_PACKAGE_SOURCE_BOUNDARY_OBSERVATION"
        or value.get("non_authorizing") is not True
        or value.get("binding_id") != "PACKAGE_SOURCE_UBUNTU"
        or type(value.get("boundary")) is not str
        or value.get("boundary") not in PACKAGE_SOURCE_BOUNDARIES
        or type(value.get("outcome")) is not str
        or value.get("outcome") not in PACKAGE_SOURCE_BOUNDARY_OUTCOMES
        or value.get("expected_sha256") != PACKAGE_SOURCE_UBUNTU_DIGEST
    ):
        _stop("PACKAGE_SOURCE_BOUNDARY_OBSERVATION_MALFORMED")
    outcome = value["outcome"]
    observed = value["observed_sha256"]
    if (
        outcome == "READ_ERROR"
        and observed is not None
        or outcome != "READ_ERROR"
        and not _is_digest(observed)
        or outcome == "MATCH"
        and observed != PACKAGE_SOURCE_UBUNTU_DIGEST
        or outcome == "MISMATCH"
        and observed == PACKAGE_SOURCE_UBUNTU_DIGEST
    ):
        _stop("PACKAGE_SOURCE_BOUNDARY_OBSERVATION_MALFORMED")
    return value


def _package_source_boundary_observations(
    *, diagnostic_observation: bool,
) -> None:
    if type(diagnostic_observation) is not bool:
        _stop("PACKAGE_SOURCE_BOUNDARY_OBSERVATION_MALFORMED")
    try:
        raw = _read_regular(PACKAGE_SOURCE_BOUNDARY_OBSERVATIONS, 2 << 10)
        if not raw.endswith(b"\n"):
            _stop("PACKAGE_SOURCE_BOUNDARY_OBSERVATION_MALFORMED")
        lines = raw[:-1].split(b"\n")
        if len(lines) not in {1, 2}:
            _stop("PACKAGE_SOURCE_BOUNDARY_OBSERVATION_MALFORMED")
        observations = [
            _validate_package_source_boundary_observation(
                _strict_bytes(line, 1024)
            )
            for line in lines
        ]
        if (
            observations[0]["boundary"] != PACKAGE_SOURCE_BOUNDARIES[0]
            or len(observations) == 1
            and observations[0]["outcome"] == "MATCH"
            or len(observations) == 2
            and (
                observations[0]["outcome"] != "MATCH"
                or observations[1]["boundary"] != PACKAGE_SOURCE_BOUNDARIES[1]
            )
        ):
            _stop("PACKAGE_SOURCE_BOUNDARY_OBSERVATION_MALFORMED")
    except (OSError, QualificationStop, TypeError, ValueError, RecursionError) as error:
        raise QualificationStop(
            "PACKAGE_SOURCE_BOUNDARY_OBSERVATION_MALFORMED"
        ) from error
    if diagnostic_observation:
        for observation in observations:
            _emit_package_source_boundary_observation(observation)
    if any(observation["outcome"] != "MATCH" for observation in observations):
        _stop("PACKAGE_RUNTIME_PLAN_BINDING_MISMATCH")


def _package_runtime_plan(
    *, diagnostic_observation: bool = False
) -> dict[str, object]:
    if type(diagnostic_observation) is not bool:
        _stop("PACKAGE_RUNTIME_PLAN_MISMATCH")
    value = _validate_package_runtime_plan(
        _strict_file(PACKAGE_RUNTIME_PLAN, _PACKAGE_RUNTIME_PLAN_KEYS, 1 << 20)
    )
    try:
        provisioning_digest = _digest_file(PROVISIONING_SCRIPT, 1 << 20)
    except (OSError, QualificationStop) as error:
        if diagnostic_observation:
            _package_runtime_plan_binding_stop(
                "PROVISIONING_SCRIPT", "READ_ERROR", True, error
            )
        raise
    if value["provisioning_script_digest"] != provisioning_digest:
        _package_runtime_plan_binding_stop(
            "PROVISIONING_SCRIPT", "MISMATCH", diagnostic_observation
        )
    _package_source_boundary_observations(
        diagnostic_observation=diagnostic_observation
    )
    for name, expected in PACKAGE_VERSIONS.items():
        binding_id = _PACKAGE_VERSION_BINDING_IDS.get(name)
        try:
            result = subprocess.run(
                ["/usr/bin/dpkg-query", "-W", "-f=${Version}", name],
                shell=False,
                close_fds=True,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={"LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
                cwd="/",
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            _package_runtime_plan_binding_stop(
                binding_id, "QUERY_ERROR", diagnostic_observation, error
            )
        if result.returncode != 0:
            _package_runtime_plan_binding_stop(
                binding_id, "QUERY_ERROR", diagnostic_observation
            )
        try:
            installed = result.stdout.decode("ascii", "strict")
        except UnicodeDecodeError as error:
            _package_runtime_plan_binding_stop(
                binding_id, "DECODE_ERROR", diagnostic_observation, error
            )
        if installed != expected:
            _package_runtime_plan_binding_stop(
                binding_id, "MISMATCH", diagnostic_observation
            )
    for bindings in (
        value["package_sources"], value["runtime_configs"], value["runtime_tools"]
    ):
        for name, expected in bindings.items():
            binding_id = _PACKAGE_FILE_BINDING_IDS.get(name)
            path = Path(name)
            if name == LIBCRYPTO:
                try:
                    path = path.resolve(strict=True)
                except (OSError, RuntimeError) as error:
                    if diagnostic_observation:
                        _package_runtime_plan_binding_stop(
                            binding_id, "RESOLVE_ERROR", True, error
                        )
                    raise
            try:
                actual = _digest_file(path, 16 << 20)
            except (OSError, QualificationStop) as error:
                if diagnostic_observation:
                    _package_runtime_plan_binding_stop(
                        binding_id, "READ_ERROR", True, error
                    )
                raise
            if actual != expected:
                _package_runtime_plan_binding_stop(
                    binding_id, "MISMATCH", diagnostic_observation
                )
    return value


def _verify_bound_environment(
    contract: dict[str, object],
    source: dict[str, object],
    host_provenance: dict[str, object],
    profile: dict[str, object],
    mismatch_reason: str,
    *,
    diagnostic_observation: bool = False,
) -> dict[str, object]:
    core = contract["contract_core"]
    environment = contract["environment_preimage"]
    plan = _package_runtime_plan(
        diagnostic_observation=diagnostic_observation
    )
    image = host_provenance.get("image") if type(host_provenance) is dict else None
    vm = host_provenance.get("vm") if type(host_provenance) is dict else None
    if (
        type(source) is not dict
        or source.get("commit") != core["candidate"]
        or source.get("tree") != core["tree"]
        or source.get("files_digest") != core["source_files_digest"]
        or _digest_bytes(_canonical(profile)) != core["canonical_profile_digest"]
        or _digest_file(PROFILE_PATH, 1 << 20) != core["raw_profile_artifact_digest"]
        or type(image) is not dict
        or image.get("sha256") != core["base_image_digest"]
        or type(vm) is not dict
        or vm.get("seed_digest") != environment["seed_digest"]
        or _digest_file(SOURCE_ARCHIVE, 64 << 20)
        != environment["source_archive_digest"]
        or _digest_file(PACKAGE_RUNTIME_PLAN, 1 << 20)
        != environment["package_runtime_plan_digest"]
        or _digest_bytes(_canonical(host_provenance))
        != environment["host_provenance_digest"]
    ):
        _stop(mismatch_reason)
    return plan


def _verify_qualification_environment(
    request: dict[str, object],
    source: dict[str, object],
    host_provenance: dict[str, object],
    profile: dict[str, object],
) -> dict[str, object]:
    contract, _ = _qualification_request_contract(request)
    return _verify_bound_environment(
        contract,
        source,
        host_provenance,
        profile,
        "M4_QUALIFICATION_ENVIRONMENT_MISMATCH",
    )


def _verify_post_v2_diagnostic_environment(
    request: dict[str, object],
    source: dict[str, object],
    host_provenance: dict[str, object],
    profile: dict[str, object],
) -> dict[str, object]:
    contract, _ = _post_v2_diagnostic_request_contract(request)
    return _verify_bound_environment(
        contract,
        source,
        host_provenance,
        profile,
        "M4_POST_V2_DIAGNOSTIC_ENVIRONMENT_MISMATCH",
        diagnostic_observation=True,
    )


def _verify_package_plan_discriminator_environment(
    request: dict[str, object],
    source: dict[str, object],
    host_provenance: dict[str, object],
    profile: dict[str, object],
) -> None:
    contract, _ = _package_plan_discriminator_request_contract(request)
    _verify_bound_environment(
        contract,
        source,
        host_provenance,
        profile,
        "M4_PACKAGE_PLAN_DISCRIMINATOR_ENVIRONMENT_MISMATCH",
        diagnostic_observation=True,
    )
    _stop("PACKAGE_RUNTIME_PLAN_DISCRIMINATOR_NO_FAILURE")


def _validate_run_state(value: object) -> dict[str, object]:
    if type(value) is not dict or frozenset(value) != RUN_STATE_KEYS:
        _stop("RUN_STATE_SCHEMA_MISMATCH")
    identity = value["identity"]
    trust = value["trust"]
    durable_state = value["durable"]
    publication = value["publication"]
    execution = value["execution"]
    if (
        value["record_version"] != "1.0.0"
        or value["phase"] != "PRE_RESTART_PASS"
        or type(identity) is not dict
        or frozenset(identity) != _RUN_IDENTITY_KEYS
        or type(trust) is not dict
        or frozenset(trust) != _RUN_TRUST_KEYS
        or type(durable_state) is not dict
        or frozenset(durable_state) != _RUN_DURABLE_KEYS
        or type(publication) is not dict
        or frozenset(publication) != _RUN_PUBLICATION_KEYS
        or type(execution) is not dict
        or frozenset(execution) != _RUN_EXECUTION_KEYS
    ):
        _stop("RUN_STATE_SCHEMA_MISMATCH")
    source = identity["source"]
    admission = trust["key_admission"]
    receipt_digests = trust["receipt_public_key_digests"]
    verifier = trust["verifier"]
    recovery = durable_state["m4_recovery"]
    session = durable_state["m3_runtime_session"]
    contract = _validate_qualification_contract(identity["qualification_contract"])
    contract_digest = _digest_bytes(_canonical(contract))
    core = contract["contract_core"]
    expected_admission_version = core["contract_version"]
    package_runtime_plan = _validate_package_runtime_plan(
        identity["package_runtime_plan"]
    )
    host_image = (
        identity["host_provenance"].get("image")
        if type(identity["host_provenance"]) is dict
        else None
    )
    host_vm = (
        identity["host_provenance"].get("vm")
        if type(identity["host_provenance"]) is dict
        else None
    )
    if (
        type(identity["candidate"]) is not str
        or re.fullmatch(r"[0-9a-f]{40}", identity["candidate"]) is None
        or type(identity["environment"]) is not str
        or not _is_digest(identity["environment"])
        or type(identity["attempt"]) is not int
        or isinstance(identity["attempt"], bool)
        or identity["attempt"] not in {1, 2}
        or type(identity["boot_id"]) is not str
        or re.fullmatch(r"[0-9a-f-]{36}", identity["boot_id"]) is None
        or type(source) is not dict
        or source.get("commit") != identity["candidate"]
        or source.get("tree") != core["tree"]
        or source.get("files_digest") != core["source_files_digest"]
        or identity["candidate"] != core["candidate"]
        or identity["environment"] != contract["environment_digest"]
        or identity["attempt"] != core["attempt"]
        or identity["qualification_contract_digest"] != contract_digest
        or _digest_bytes(_canonical(identity["host_provenance"]))
        != contract["environment_preimage"]["host_provenance_digest"]
        or type(host_image) is not dict
        or host_image.get("sha256")
        != core["base_image_digest"]
        or type(host_vm) is not dict
        or host_vm.get("seed_digest")
        != contract["environment_preimage"]["seed_digest"]
        or _digest_bytes(_canonical(package_runtime_plan))
        != contract["environment_preimage"]["package_runtime_plan_digest"]
        or not all(
            type(identity[name]) is dict
            for name in (
                "guest", "source", "host_provenance", "package_runtime_plan"
            )
        )
        or not all(
            _is_digest(trust[name])
            for name in (
                "profile_digest", "m4_apparmor_digest", "m3_apparmor_digest",
                "runtime_trust_digest", "supply_public_key_digest",
            )
        )
        or trust["profile_digest"] != core["canonical_profile_digest"]
        or trust["revocation_epoch"] != 0
        or trust["fencing_epoch"] != 1
        or type(admission) is not dict
        or frozenset(admission) != _KEY_ADMISSION_KEYS
        or admission.get("admission_version") != expected_admission_version
        or admission.get("mode") != KEY_ADMISSION_MODE
        or admission.get("qualification_contract") != contract
        or admission.get("qualification_contract_digest") != contract_digest
        or admission.get("contract_core_digest") != contract["contract_core_digest"]
        or not _is_digest(admission.get("ledger_entry_digest"))
        or admission.get("receipt_public_key_digests") != receipt_digests
        or admission.get("supply_public_key_digest") != trust["supply_public_key_digest"]
        or admission.get("runtime_trust_digest") != trust["runtime_trust_digest"]
        or type(receipt_digests) is not dict
        or frozenset(receipt_digests) != {"M4_AUTHORITY", "OBSERVER", "PUBLISHER"}
        or not all(_is_digest(item) for item in receipt_digests.values())
        or type(verifier) is not dict
        or frozenset(verifier)
        != {
            "backend", "code_digest", "libcrypto_path", "libcrypto_digest",
            "independent_cryptographic_implementations",
        }
        or verifier["backend"] != "OPENSSL_LIBCRYPTO_SHARED"
        or not _is_digest(verifier["code_digest"])
        or verifier["libcrypto_path"] != LIBCRYPTO
        or not _is_digest(verifier["libcrypto_digest"])
        or verifier["independent_cryptographic_implementations"] is not False
        or type(recovery) is not dict
        or frozenset(recovery) != _M4_RECOVERY_KEYS
        or type(session) is not dict
        or frozenset(session) != _RECOVERY_SESSION_KEYS
    ):
        _stop("RUN_STATE_BINDING_MISMATCH")
    if (
        recovery["state"] != "JOINED"
        or recovery["intent_state"] != "SPENT"
        or recovery["resume_allowed"] is not False
        or recovery["retry_allowed"] is not False
        or not all(
            _is_digest(recovery[name])
            for name in (
                "contract_digest", "d2_frontier_digest", "record_digest",
                "frontier_record_digest",
            )
        )
        or type(recovery["iteration"]) is not int
        or isinstance(recovery["iteration"], bool)
        or recovery["iteration"] < 1
        or recovery["frontier_attempt_cursor"] != recovery["iteration"] - 1
        or recovery["frontier_joined_iteration"] > recovery["frontier_attempt_cursor"]
        or recovery["attempt_cursor"] != recovery["iteration"]
        or recovery["joined_iteration"] != recovery["iteration"]
        or type(recovery["journal_sequence"]) is not int
        or isinstance(recovery["journal_sequence"], bool)
        or recovery["journal_sequence"] < 1
        or recovery["fencing_epoch"] != trust["fencing_epoch"]
        or recovery["revocation_epoch"] != trust["revocation_epoch"]
        or session["transaction_id"] != recovery["transaction_id"]
        or session["state"] != "STOPPED"
        or session["fencing_epoch"] != recovery["fencing_epoch"]
        or not _is_digest(session["claim_digest"])
    ):
        _stop("RUN_STATE_DURABLE_MISMATCH")
    if (
        publication["root"] != str(PUBLICATION_ROOT)
        or publication["transport"] != SEALED_FD_ONLY
        or not all(
            _is_digest(publication[name])
            for name in ("topology_digest", "artifact_digest", "snapshot_digest")
        )
        or publication["artifact_digest"] != publication["snapshot_digest"]
        or not all(
            type(publication[name]) is dict
            for name in ("root_anchor", "target_binding", "published_binding")
        )
        or publication["root_anchor"].get("anchor_digest") is None
        or not _is_digest(publication["root_anchor"].get("anchor_digest"))
        or not _is_digest(publication["target_binding"].get("composite_binding_digest"))
        or not _is_digest(publication["published_binding"].get("composite_binding_digest"))
        or publication["published_binding"].get("final_digest") != publication["artifact_digest"]
        or type(execution["controller_facts"]) is not dict
        or type(execution["publisher_facts"]) is not dict
        or any(type(execution[name]) is not list for name in (
            "executor_facts", "observer_facts", "runtime_events", "denial_events"
        ))
        or len(execution["executor_facts"]) != 1
        or len(execution["observer_facts"]) != 1
        or len(execution["denial_events"]) != 2
        or type(execution["role_seccomp_digests"]) is not dict
        or type(execution["m3_role_seccomp"]) is not dict
        or type(execution["cleanup"]) is not dict
    ):
        _stop("RUN_STATE_EVIDENCE_MISMATCH")
    return value


def _load_project() -> tuple[object, object, object, object, object]:
    source = SOURCE / "src"
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))
    from harness_product import durable, l0, m4, publisher  # noqa: PLC0415
    from harness_product.verification import OpenSSLEd25519Verifier  # noqa: PLC0415

    return durable, l0, m4, publisher, OpenSSLEd25519Verifier


def _load_m3() -> object:
    specification = importlib.util.spec_from_file_location("harness_m3_runtime", M3_RUNNER)
    if specification is None or specification.loader is None:
        _stop("M3_RUNTIME_MODULE_ABSENT")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _profile() -> dict[str, object]:
    raw = _strict_file(
        PROFILE_PATH,
        frozenset(
            {
                "profile_version",
                "profile_id",
                "assurance_scope",
                "backend",
                "publication",
                "roles",
                "receipt_keys",
                "supply_trust",
                "limits",
            }
        ),
    )
    if (
        raw["profile_version"] != "1.0.0"
        or raw["profile_id"] != "M4-LX-A"
        or raw["assurance_scope"] != EXPECTED_SCOPE
        or raw["backend"] != {"path": BWRAP, "version": "bubblewrap 0.9.0"}
    ):
        _stop("M4_PROFILE_MISMATCH")
    roles = raw["roles"]
    if type(roles) is not dict or frozenset(roles) != {
        "WORKER", "CONTROLLER", "EXECUTOR", "OBSERVER", "PUBLISHER"
    }:
        _stop("M4_ROLE_SET_MISMATCH")
    identities = []
    for name, row in roles.items():
        if type(row) is not dict or frozenset(row) != {
            "principal_id", "uid", "gid", "session_id", "security_label",
            "cgroup", "credential_namespace", "namespace_id", "fd_allowlist",
        }:
            _stop("M4_ROLE_SHAPE_MISMATCH")
        identities.append(
            tuple(
                row[key]
                for key in (
                    "principal_id", "uid", "gid", "session_id", "security_label",
                    "cgroup", "credential_namespace", "namespace_id",
                )
            )
        )
        if name in ROLE_IDS and (row["uid"], row["gid"]) != ROLE_IDS[name]:
            _stop("M4_ROLE_IDENTITY_MISMATCH")
    if any(len({row[index] for row in identities}) != len(identities) for index in range(8)):
        _stop("M4_ROLE_ALIAS")
    publication = raw["publication"]
    if (
        type(publication) is not dict
        or publication.get("transport") != SEALED_FD_ONLY
        or publication.get("git_authority") != "DENY"
        or publication.get("root") != str(PUBLICATION_ROOT)
        or publication.get("parent_writable_roles") != []
        or publication.get("root_writable_roles") != ["PUBLISHER"]
    ):
        _stop("M4_PUBLICATION_PROFILE_MISMATCH")
    supply_trust = raw["supply_trust"]
    if supply_trust != {
        "trust_root_id": "harness-m4-disposable-supply-root-1",
        "signer_id": "harness-m4-supply-attestor",
        "key_id": "harness-m4-supply-ed25519-1",
        "private_owner": "ROOT_SUPERVISOR",
        "algorithm": "ED25519",
        "admission": KEY_ADMISSION_MODE,
    }:
        _stop("M4_SUPPLY_TRUST_PROFILE_MISMATCH")
    return raw


def _key_admission(
    request: dict[str, object], keys: dict[str, "RoleKey"], supply_public_digest: str,
    runtime_trust_digest: str,
) -> dict[str, object]:
    """Require the host ledger pin before any untrusted start gate opens."""

    contract, contract_digest = _qualification_request_contract(request)
    value = _strict_file(
        KEY_ADMISSION,
        _KEY_ADMISSION_KEYS,
        1 << 20,
    )
    expected_keys = {name: key.public_key_digest for name, key in keys.items()}
    if (
        value["admission_version"]
        != contract["contract_core"]["contract_version"]
        or value["mode"] != KEY_ADMISSION_MODE
        or value["qualification_contract"] != contract
        or value["qualification_contract_digest"] != contract_digest
        or value["contract_core_digest"] != contract["contract_core_digest"]
        or value["receipt_public_key_digests"] != expected_keys
        or value["supply_public_key_digest"] != supply_public_digest
        or value["runtime_trust_digest"] != runtime_trust_digest
        or not _is_digest(value["ledger_entry_digest"])
    ):
        _stop("KEY_ADMISSION_REQUIRED")
    return value


def _verification_record(payload: dict[str, object], source: dict[str, object]) -> dict[str, object]:
    if frozenset(source) != {"verifier_id", "issuer_id", "key_id", "proof"}:
        _stop("VERIFICATION_SOURCE_MALFORMED")
    return {
        "verification_version": 1,
        "verifier_id": source["verifier_id"],
        "issuer_id": source["issuer_id"],
        "key_id": source["key_id"],
        "payload_digest": _digest_bytes(_canonical(payload)),
        "bindings": payload,
        "proof": source["proof"],
    }


def _configured_verifier(config: dict[str, object]) -> object:
    _, _, _, _, verifier_type = _load_project()
    trust = _strict_file(
        RUNTIME_TRUST,
        frozenset(
            {
                "trust_version", "profile_digest", "verifier_code_path",
                "verifier_code_digest", "libcrypto_path", "libcrypto_digest",
                "m4_routes", "supply", "revocation_epoch", "fencing_epoch",
            }
        ),
        1 << 20,
    )
    if (
        type(config) is not dict
        or frozenset(config)
        != {
            "verifier_id", "issuer_id", "key_id", "public_key_path",
            "public_key_digest",
        }
    ):
        _stop("VERIFIER_CONFIG_MALFORMED")
    return verifier_type(
        verifier_id=str(config["verifier_id"]),
        issuer_id=str(config["issuer_id"]),
        key_id=str(config["key_id"]),
        public_key_path=str(config["public_key_path"]),
        public_key_digest=str(config["public_key_digest"]),
        libcrypto_path=str(trust["libcrypto_path"]),
        libcrypto_digest=str(trust["libcrypto_digest"]),
        verifier_code_path=str(trust["verifier_code_path"]),
        verifier_code_digest=str(trust["verifier_code_digest"]),
        expected_revocation_epoch=int(trust["revocation_epoch"]),
        expected_fencing_epoch=int(trust["fencing_epoch"]),
    )


class ConfiguredVerifierRouter:
    """Verifier-only route reconstructed from the root-owned trust record."""

    def __init__(self) -> None:
        trust = _strict_file(
            RUNTIME_TRUST,
            frozenset(
                {
                    "trust_version", "profile_digest", "verifier_code_path",
                    "verifier_code_digest", "libcrypto_path", "libcrypto_digest",
                    "m4_routes", "supply", "revocation_epoch", "fencing_epoch",
                }
            ),
            1 << 20,
        )
        routes = trust["m4_routes"]
        if type(routes) is not dict or frozenset(routes) != {
            "M4_AUTHORITY", "OBSERVER", "PUBLISHER"
        }:
            raise ValueError("incomplete M4 verifier routes")
        self._routes = {name: _configured_verifier(value) for name, value in routes.items()}

    def verify(self, payload: bytes, record: bytes, observed_at: str) -> object:
        durable, _, _, _, _ = _load_project()
        try:
            value = _strict_bytes(payload)
            purpose = _purpose_from_payload(value)
            route = PURPOSE_ROUTES.get(purpose)
            if route is None and purpose.startswith("M4_TRANSITION:"):
                route = "M4_AUTHORITY"
            verifier = self._routes.get(str(route))
            if verifier is None:
                _stop("VERIFIER_ROUTE_ABSENT")
            return verifier.verify(payload, record, observed_at)
        except Exception:
            return durable.VerificationResult(
                durable.VerificationStatus.REJECTED,
                "harness-m4-openssl-libcrypto/v1",
                _digest_bytes(payload if type(payload) is bytes else b""),
                _digest_bytes(record if type(record) is bytes else b""),
            )


def _openssl_sign(
    private_key: Path,
    payload: bytes,
    libcrypto_digest: str,
) -> str:
    """Sign in-process with the same pinned OpenSSL libcrypto as verification."""

    if type(payload) is not bytes or not payload or len(payload) > MAX_JSON:
        _stop("SIGNING_PAYLOAD_MALFORMED")
    key_bytes = _read_regular(private_key, 8192)
    library_descriptor = os.open(
        LIBCRYPTO,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    bio = 0
    key = 0
    context = 0
    try:
        info = os.fstat(library_descriptor)
        library_hash = sha256()
        offset = 0
        while offset <= 16 << 20:
            chunk = os.pread(
                library_descriptor,
                min(65536, (16 << 20) + 1 - offset),
                offset,
            )
            if not chunk:
                break
            library_hash.update(chunk)
            offset += len(chunk)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) & 0o022
            or offset != info.st_size
            or offset > 16 << 20
            or "sha256:" + library_hash.hexdigest() != libcrypto_digest
        ):
            _stop("LIBCRYPTO_BINDING_MISMATCH")
        library = ctypes.CDLL(
            f"/proc/self/fd/{library_descriptor}",
            use_errno=True,
        )
        library.BIO_new_mem_buf.argtypes = [ctypes.c_void_p, ctypes.c_int]
        library.BIO_new_mem_buf.restype = ctypes.c_void_p
        library.BIO_free.argtypes = [ctypes.c_void_p]
        library.PEM_read_bio_PrivateKey.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        library.PEM_read_bio_PrivateKey.restype = ctypes.c_void_p
        library.EVP_PKEY_free.argtypes = [ctypes.c_void_p]
        library.EVP_PKEY_get_base_id.argtypes = [ctypes.c_void_p]
        library.EVP_PKEY_get_base_id.restype = ctypes.c_int
        library.EVP_MD_CTX_new.restype = ctypes.c_void_p
        library.EVP_MD_CTX_free.argtypes = [ctypes.c_void_p]
        library.EVP_DigestSignInit.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        library.EVP_DigestSign.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_size_t),
            ctypes.c_void_p,
            ctypes.c_size_t,
        ]
        key_buffer = ctypes.create_string_buffer(key_bytes, len(key_bytes))
        bio = int(library.BIO_new_mem_buf(key_buffer, len(key_bytes)))
        key = int(library.PEM_read_bio_PrivateKey(bio, None, None, None))
        context = int(library.EVP_MD_CTX_new())
        if (
            not bio
            or not key
            or not context
            or library.EVP_PKEY_get_base_id(key) != 1087
            or library.EVP_DigestSignInit(context, None, None, None, key) != 1
        ):
            _stop("SIGNATURE_FAILED")
        size = ctypes.c_size_t(0)
        payload_buffer = ctypes.create_string_buffer(payload, len(payload))
        if library.EVP_DigestSign(
            context,
            None,
            ctypes.byref(size),
            payload_buffer,
            len(payload),
        ) != 1 or size.value != 64:
            _stop("SIGNATURE_FAILED")
        signature = ctypes.create_string_buffer(size.value)
        if library.EVP_DigestSign(
            context,
            signature,
            ctypes.byref(size),
            payload_buffer,
            len(payload),
        ) != 1 or size.value != 64:
            _stop("SIGNATURE_FAILED")
        return "ed25519:" + bytes(signature.raw[: size.value]).hex()
    finally:
        if context:
            library.EVP_MD_CTX_free(context)
        if key:
            library.EVP_PKEY_free(key)
        if bio:
            library.BIO_free(bio)
        os.close(library_descriptor)


class ControllerVerificationProvider:
    """Authority-key provider that exists only in the controller principal."""

    def __init__(self) -> None:
        trust = _strict_file(
            RUNTIME_TRUST,
            frozenset(
                {
                    "trust_version", "profile_digest", "verifier_code_path",
                    "verifier_code_digest", "libcrypto_path", "libcrypto_digest",
                    "m4_routes", "supply", "revocation_epoch", "fencing_epoch",
                }
            ),
            1 << 20,
        )
        config = trust["m4_routes"]["M4_AUTHORITY"]
        self.verifier_id = str(config["verifier_id"])
        self.issuer_id = str(config["issuer_id"])
        self.key_id = str(config["key_id"])
        self.private_key = KEY_ROOT / "m4-authority/private.pem"
        self.libcrypto_digest = str(trust["libcrypto_digest"])
        self._verifier = _configured_verifier(config)

    def sign(self, payload: bytes, observed_at: str, purpose: str) -> dict[str, object]:
        if (
            type(payload) is not bytes
            or _purpose_from_payload(_strict_bytes(payload)) != purpose
            or (
                PURPOSE_ROUTES.get(purpose) != "M4_AUTHORITY"
                and not purpose.startswith("M4_TRANSITION:")
            )
        ):
            _stop("CONTROLLER_SIGNING_PURPOSE_REJECTED")
        return {
            "verifier_id": self.verifier_id,
            "issuer_id": self.issuer_id,
            "key_id": self.key_id,
            "proof": _openssl_sign(
                self.private_key,
                payload,
                self.libcrypto_digest,
            ),
        }

    def verify(
        self, purpose: str, payload: bytes, record: bytes, observed_at: str
    ) -> object:
        durable, _, _, _, _ = _load_project()
        if (
            PURPOSE_ROUTES.get(purpose) != "M4_AUTHORITY"
            and not purpose.startswith("M4_TRANSITION:")
        ):
            return durable.VerificationResult(
                durable.VerificationStatus.REJECTED,
                self.verifier_id,
                _digest_bytes(payload),
                _digest_bytes(record),
            )
        return self._verifier.verify(payload, record, observed_at)


def _purpose_from_payload(payload: object) -> str:
    if type(payload) is not dict:
        _stop("VERIFICATION_PAYLOAD_MALFORMED")
    record_type = payload.get("record_type")
    if record_type == "ACTIVE_CONTRACT":
        return "ACTIVE_CONTRACT"
    if record_type == "D2_FRONTIER":
        return "D2_FRONTIER"
    if record_type in {"M4_STAGE_AUTHORIZATION", "M4_STAGE_EXECUTION_GRANT"}:
        return str(record_type)
    if record_type == "M4_TRANSITION":
        state = payload.get("state")
        if type(state) is not str:
            _stop("VERIFICATION_PURPOSE_MALFORMED")
        return "M4_TRANSITION:" + state
    if payload.get("topology_version") == 1:
        return "M4_TOPOLOGY"
    if payload.get("runtime_version") == "1.0.0":
        return "M4_RUNTIME_PREFLIGHT"
    if payload.get("receipt_version") == 1 and payload.get("outcome") == "PASS":
        return "M4_OBSERVER_RECEIPT"
    if payload.get("receipt_version") == 1 and payload.get("outcome") == "PUBLISHED":
        return "M4_PUBLICATION_RECEIPT"
    if payload.get("authorization_version") == 1:
        return "M4_PUBLICATION_AUTHORIZATION"
    if payload.get("continuity_version") == 1:
        purpose = payload.get("purpose")
        if purpose in {"PRE_COMMIT", "PRE_JOIN"}:
            return str(purpose)
    _stop("VERIFICATION_PURPOSE_UNKNOWN")


class RoleKey:
    """One exact VM-only Ed25519 route using typed OpenSSL argv."""

    def __init__(self, role: str, row: dict[str, object], directory: Path) -> None:
        if role not in {"M4_AUTHORITY", "OBSERVER", "PUBLISHER"}:
            raise ValueError("unknown M4 key role")
        self.role = role
        self.verifier_id = "harness-m4-openssl-libcrypto/v1"
        self.issuer_id = str(row["issuer_id"])
        self.key_id = str(row["key_id"])
        self.private_key = directory / "private.pem"
        self.public_key = directory / "public.pem"
        self.public_key_digest = _digest_file(self.public_key, 4096)
        self.libcrypto_digest = _digest_file(Path(LIBCRYPTO).resolve(strict=True), 16 << 20)
        self.verifier_code_digest = _digest_file(VERIFIER_CODE, 1 << 20)

    def _expected(self, purpose: str) -> bool:
        route = PURPOSE_ROUTES.get(purpose)
        if route is None and purpose.startswith("M4_TRANSITION:"):
            route = "M4_AUTHORITY"
        return route == self.role

    def sign(self, payload: bytes, observed_at: str, purpose: str) -> dict[str, object]:
        if type(payload) is not bytes or not self._expected(purpose):
            _stop("SIGNING_PURPOSE_REJECTED")
        value = _strict_bytes(payload)
        if _purpose_from_payload(value) != purpose:
            _stop("SIGNING_PAYLOAD_PURPOSE_MISMATCH")
        return {
            "verifier_id": self.verifier_id,
            "issuer_id": self.issuer_id,
            "key_id": self.key_id,
            "proof": _openssl_sign(
                self.private_key,
                payload,
                self.libcrypto_digest,
            ),
        }

    def verifier(self, *, revocation_epoch: int = 0, fencing_epoch: int = 1) -> object:
        _, _, _, _, verifier_type = _load_project()
        return verifier_type(
            verifier_id=self.verifier_id,
            issuer_id=self.issuer_id,
            key_id=self.key_id,
            public_key_path=str(self.public_key),
            public_key_digest=self.public_key_digest,
            libcrypto_path=LIBCRYPTO,
            libcrypto_digest=self.libcrypto_digest,
            verifier_code_path=str(VERIFIER_CODE),
            verifier_code_digest=self.verifier_code_digest,
            expected_revocation_epoch=revocation_epoch,
            expected_fencing_epoch=fencing_epoch,
        )

    def verify(
        self,
        purpose: str,
        payload: bytes,
        record: bytes,
        observed_at: str,
    ) -> object:
        durable, _, _, _, _ = _load_project()
        if not self._expected(purpose):
            return durable.VerificationResult(
                durable.VerificationStatus.REJECTED,
                self.verifier_id,
                _digest_bytes(payload if type(payload) is bytes else b""),
                _digest_bytes(record if type(record) is bytes else b""),
            )
        try:
            value = _strict_bytes(payload)
            if _purpose_from_payload(value) != purpose:
                raise QualificationStop("PURPOSE_MISMATCH")
        except QualificationStop:
            return durable.VerificationResult(
                durable.VerificationStatus.REJECTED,
                self.verifier_id,
                _digest_bytes(payload if type(payload) is bytes else b""),
                _digest_bytes(record if type(record) is bytes else b""),
            )
        return self.verifier().verify(payload, record, observed_at)


class VerificationRouter:
    """Route records by exact purpose; all routes use OpenSSL libcrypto."""

    def __init__(self, keys: dict[str, RoleKey]) -> None:
        if frozenset(keys) != {"M4_AUTHORITY", "OBSERVER", "PUBLISHER"}:
            raise ValueError("incomplete M4 verifier routes")
        self._keys = dict(keys)

    def verify(self, payload: bytes, record: bytes, observed_at: str) -> object:
        durable, _, _, _, _ = _load_project()
        try:
            value = _strict_bytes(payload)
            purpose = _purpose_from_payload(value)
            route = PURPOSE_ROUTES.get(purpose)
            if route is None and purpose.startswith("M4_TRANSITION:"):
                route = "M4_AUTHORITY"
            if route not in self._keys:
                _stop("VERIFIER_ROUTE_ABSENT")
            return self._keys[route].verifier().verify(payload, record, observed_at)
        except Exception:
            return durable.VerificationResult(
                durable.VerificationStatus.REJECTED,
                "harness-m4-openssl-libcrypto/v1",
                _digest_bytes(payload if type(payload) is bytes else b""),
                _digest_bytes(record if type(record) is bytes else b""),
            )


def _close_except(allowed: frozenset[int]) -> None:
    """Close the complete Linux FD range; inability to prove closure is fatal."""

    _, _, m4, _, _ = _load_project()
    # The product helper is the exact close_range implementation shared by the
    # stage and observer child boundaries.  It has no RLIMIT or /proc fallback.
    m4._close_except(allowed)
    for descriptor in allowed:
        try:
            fcntl.fcntl(descriptor, fcntl.F_GETFD)
        except OSError as error:
            raise QualificationStop("ALLOWED_DESCRIPTOR_LOST") from error


def _read_line(descriptor: int, maximum: int = MAX_REPORT, timeout: float = 5.0) -> bytes:
    deadline = time.monotonic() + timeout
    value = bytearray()
    while len(value) <= maximum:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([descriptor], [], [], remaining)[0]:
            _stop("ROLE_REPORT_TIMEOUT")
        chunk = os.read(descriptor, 1)
        if not chunk:
            _stop("ROLE_REPORT_EOF")
        if chunk == b"\n":
            return bytes(value)
        value.extend(chunk)
    _stop("ROLE_REPORT_UNBOUNDED")


def _write_report(value: dict[str, object]) -> None:
    encoded = _canonical(value) + b"\n"
    if len(encoded) > MAX_REPORT:
        _stop("ROLE_REPORT_UNBOUNDED")
    offset = 0
    while offset < len(encoded):
        written = os.write(1, encoded[offset:])
        if written <= 0:
            _stop("ROLE_REPORT_SHORT_WRITE")
        offset += written


def _read_start(descriptor: int) -> None:
    if os.read(descriptor, len(START_PACKET)) != START_PACKET or os.read(descriptor, 1):
        _stop("EARLY_START_GATE_DENIED")


def _control_message(value: object) -> dict[str, object]:
    if (
        type(value) is not dict
        or frozenset(value) != _CONTROL_KEYS
        or value.get("protocol_version") != 1
        or type(value.get("request_id")) is not int
        or int(value["request_id"]) < 1
        or value.get("operation") not in _CONTROL_OPERATIONS
        or type(value.get("payload")) is not dict
    ):
        _stop("PUBLISHER_PROTOCOL_MALFORMED")
    return value


def _recv_control(
    connection: socket.socket, expected_fds: int | None
) -> tuple[dict[str, object], tuple[int, ...]]:
    if expected_fds is not None and (
        type(expected_fds) is not int or expected_fds not in {0, 1}
    ):
        _stop("PUBLISHER_PROTOCOL_MALFORMED")
    raw, ancillary, flags, address = connection.recvmsg(
        MAX_REPORT + 1,
        socket.CMSG_SPACE(struct.calcsize("i") * 2),
    )
    received: list[int] = []
    try:
        if (
            not raw
            or len(raw) > MAX_REPORT
            or address not in {None, "", b""}
            or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
        ):
            _stop("PUBLISHER_PROTOCOL_MALFORMED")
        for level, kind, data in ancillary:
            if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS:
                _stop("PUBLISHER_ANCILLARY_REJECTED")
            width = struct.calcsize("i")
            if not data or len(data) % width:
                _stop("PUBLISHER_ANCILLARY_REJECTED")
            received.extend(
                struct.unpack("=" + "i" * (len(data) // width), data)
            )
        if len(received) > 1 or (
            expected_fds is not None and len(received) != expected_fds
        ):
            _stop("PUBLISHER_ANCILLARY_REJECTED")
        value = _control_message(_strict_bytes(raw, MAX_REPORT))
        return value, tuple(received)
    except Exception:
        for descriptor in received:
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise


def _send_control(
    connection: socket.socket,
    value: dict[str, object],
    descriptor: int | None = None,
) -> None:
    message = _control_message(value)
    payload = _canonical(message)
    ancillary: list[tuple[int, int, bytes]] = []
    if descriptor is not None:
        fcntl.fcntl(descriptor, fcntl.F_GETFD)
        ancillary.append(
            (socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack("=i", descriptor))
        )
    if connection.sendmsg([payload], ancillary) != len(payload):
        _stop("PUBLISHER_PROTOCOL_SHORT_WRITE")


def _claim_from_data(value: object) -> object:
    durable, _, _, _, _ = _load_project()
    if type(value) is not dict or frozenset(value) != frozenset(
        durable.DispatchClaim.__dataclass_fields__
    ):
        _stop("DISPATCH_CLAIM_MALFORMED")
    try:
        return durable.DispatchClaim(**value)
    except (TypeError, ValueError) as error:
        raise QualificationStop("DISPATCH_CLAIM_MALFORMED") from error


def _supply_from_data(value: object) -> object:
    _, l0, _, _, _ = _load_project()
    if type(value) is not dict or frozenset(value) != frozenset(
        l0.SupplyVerification.__dataclass_fields__
    ):
        _stop("SUPPLY_VERIFICATION_MALFORMED")
    artifacts = value.get("artifacts")
    if type(artifacts) is not list:
        _stop("SUPPLY_VERIFICATION_MALFORMED")
    parsed_artifacts = []
    for row in artifacts:
        if type(row) is not dict or frozenset(row) != frozenset(
            l0.SupplyArtifactBinding.__dataclass_fields__
        ):
            _stop("SUPPLY_VERIFICATION_MALFORMED")
        try:
            parsed_artifacts.append(l0.SupplyArtifactBinding(**row))
        except (TypeError, ValueError) as error:
            raise QualificationStop("SUPPLY_VERIFICATION_MALFORMED") from error
    parsed = dict(value)
    parsed["artifacts"] = tuple(parsed_artifacts)
    try:
        return l0.SupplyVerification(**parsed)
    except (TypeError, ValueError) as error:
        raise QualificationStop("SUPPLY_VERIFICATION_MALFORMED") from error


def _grant_from_data(value: object) -> object:
    durable, _, _, _, _ = _load_project()
    if type(value) is not dict or frozenset(value) != frozenset(
        durable.StageExecutionGrant.__dataclass_fields__
    ):
        _stop("STAGE_EXECUTION_GRANT_MALFORMED")
    try:
        return durable.StageExecutionGrant(**value)
    except (TypeError, ValueError) as error:
        raise QualificationStop("STAGE_EXECUTION_GRANT_MALFORMED") from error


def _stage_record_from_data(value: object) -> object:
    _, l0, _, _, _ = _load_project()
    fields = frozenset(l0.StageRecord.__dataclass_fields__)
    digest_fields = {
        "claim_digest", "binding_digest", "before_digest", "after_digest",
        "record_digest",
    }
    if (
        type(value) is not dict
        or frozenset(value) != fields
        or type(value.get("transaction_id")) is not str
        or not value["transaction_id"]
        or len(value["transaction_id"].encode("utf-8")) > 256
        or any(
            type(value.get(field)) is not str
            or re.fullmatch(r"sha256:[0-9a-f]{64}", value[field]) is None
            for field in digest_fields
        )
        or type(value.get("bytes_written")) is not int
        or value["bytes_written"] < 0
    ):
        _stop("EXECUTOR_STAGE_RECORD_MALFORMED")
    body = {key: item for key, item in value.items() if key != "record_digest"}
    if value["record_digest"] != l0._hash_text(l0._canonical(body)):
        _stop("EXECUTOR_STAGE_RECORD_MISMATCH")
    try:
        return l0.StageRecord(**value)
    except (TypeError, ValueError) as error:
        raise QualificationStop("EXECUTOR_STAGE_RECORD_MALFORMED") from error


def _snapshot_from_data(value: object) -> object:
    _, _, m4, _, _ = _load_project()
    if type(value) is not dict or frozenset(value) != frozenset(
        m4.M4Snapshot.__dataclass_fields__
    ):
        _stop("SNAPSHOT_MALFORMED")
    parsed = dict(value)
    if type(parsed.get("kernel_seals")) is not list:
        _stop("SNAPSHOT_MALFORMED")
    parsed["kernel_seals"] = tuple(parsed["kernel_seals"])
    try:
        return m4.M4Snapshot(**parsed)
    except (TypeError, ValueError) as error:
        raise QualificationStop("SNAPSHOT_MALFORMED") from error


def _publication_fact_from_data(value: object) -> object:
    _, l0, _, publisher, _ = _load_project()
    expected = frozenset(publisher.PublicationFact.__dataclass_fields__) | {
        "receipt_version",
        "outcome",
        "publication_method",
    }
    if (
        type(value) is not dict
        or frozenset(value) != expected
        or value.get("receipt_version") != 1
        or value.get("outcome") != "PUBLISHED"
        or value.get("publication_method") != "ATOMIC_REPLACE_FSYNC"
    ):
        _stop("PUBLICATION_FACT_MALFORMED")
    try:
        fields = {
            name: value[name]
            for name in publisher.PublicationFact.__dataclass_fields__
        }
        fields["before_binding"] = l0._parse_path_binding(value["before_binding"])
        fields["published_binding"] = l0._parse_path_binding(
            value["published_binding"]
        )
        fields["publisher_subject"] = publisher._subject(value["publisher_subject"])
        fact = publisher.PublicationFact(**fields)
    except Exception as error:
        raise QualificationStop("PUBLICATION_FACT_MALFORMED") from error
    if fact.data() != value:
        _stop("PUBLICATION_FACT_MALFORMED")
    return fact


def _publisher_control_pair() -> tuple[socket.socket, socket.socket]:
    return socket.socketpair(
        socket.AF_UNIX,
        socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC,
    )


def _role_preexec(role: str, cgroup: Path, mappings: tuple[tuple[int, int], ...]) -> object:
    if role not in ROLE_IDS:
        raise ValueError("unknown role")

    def child() -> None:
        (cgroup / "cgroup.procs").write_text(str(os.getpid()), encoding="ascii")
        if str(os.getpid()) not in (cgroup / "cgroup.procs").read_text(encoding="ascii").split():
            raise OSError(errno.EPERM, "cgroup attach readback failed")
        os.setsid()
        for source, target in mappings:
            if source != target:
                os.dup2(source, target, inheritable=True)
        for source, target in mappings:
            if source != target and source not in {item[1] for item in mappings}:
                os.close(source)
        os.setgroups([])
        os.setgid(ROLE_IDS[role][1])
        os.setuid(ROLE_IDS[role][0])
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            code = ctypes.get_errno()
            raise OSError(code, os.strerror(code))
        resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))

    return child


def _compile_l0_profile(raw: object) -> object:
    _, l0, _, _, _ = _load_project()
    result = l0.compile_profile(raw)
    if result.outcome is not l0.L0Outcome.COMPILED_DRAFT or result.profile is None:
        _stop("L0_DYNAMIC_PROFILE_COMPILE_FAILED")
    return result.profile


def _executor_role() -> None:
    expected = ROLE_LABELS["EXECUTOR"] + " (enforce)"
    if (
        os.geteuid() != M4_NAMESPACE_ROLE_IDS["EXECUTOR"][2]
        or os.getegid() != M4_NAMESPACE_ROLE_IDS["EXECUTOR"][3]
        or Path("/proc/self/attr/current").read_text(encoding="ascii").strip()
        != expected
    ):
        _stop("EXECUTOR_PRINCIPAL_MISMATCH")
    _close_except(frozenset({0, 1, 2}))
    _read_start(0)
    os.close(0)
    value = _strict_file(
        ROLE_INPUT,
        frozenset(
            {
                "input_version",
                "l0_profile",
                "claim",
                "supply",
                "stage_request",
                "stage_execution_grant",
            }
        ),
    )
    if value["input_version"] != "1.0.0" or type(value["stage_request"]) is not dict:
        _stop("EXECUTOR_INPUT_MALFORMED")
    durable, l0, _, _, _ = _load_project()
    profile = _compile_l0_profile(value["l0_profile"])
    claim = _claim_from_data(value["claim"])
    supply = _supply_from_data(value["supply"])
    grant = _grant_from_data(value["stage_execution_grant"])
    trust = _strict_file(
        RUNTIME_TRUST,
        frozenset(
            {
                "trust_version", "profile_digest", "verifier_code_path",
                "verifier_code_digest", "libcrypto_path", "libcrypto_digest",
                "m4_routes", "supply", "revocation_epoch", "fencing_epoch",
            }
        ),
        1 << 20,
    )
    # Separate verifier instances are created at the executor boundary.  They
    # use the same pinned OpenSSL libcrypto implementation but do not consume a
    # controller verdict, boolean, or caller digest.
    claim_verifier = _configured_verifier(trust["supply"])
    supply_verifier = _configured_verifier(trust["supply"])
    m4_verifier = ConfiguredVerifierRouter()
    result = l0.stage_committed_intent(
        profile,
        claim,
        supply,
        2,
        value["stage_request"],
        durable_store=None,
        stage_execution_grant=grant,
        m4_verifier=m4_verifier,
        executor_claim_verifier=claim_verifier,
        supply_verifier=supply_verifier,
    )
    report = {
        "outcome": result.outcome.value,
        "reason": result.reason.value,
        "record": None if result.record is None else asdict(result.record),
        "pid": os.getpid(),
        "session": os.getsid(0),
        "verifier_instances": 3,
        "independent_cryptographic_implementations": False,
    }
    if (
        result.outcome is not l0.L0Outcome.STAGED
        or result.reason is not l0.L0Reason.STAGED
        or result.record is None
    ):
        _stop("EXECUTOR_STAGE_REJECTED")
    _write_report(report)


def _observer_role() -> None:
    expected = ROLE_LABELS["OBSERVER"] + " (enforce)"
    if (
        os.geteuid() != M4_NAMESPACE_ROLE_IDS["OBSERVER"][2]
        or os.getegid() != M4_NAMESPACE_ROLE_IDS["OBSERVER"][3]
        or Path("/proc/self/attr/current").read_text(encoding="ascii").strip()
        != expected
    ):
        _stop("OBSERVER_PRINCIPAL_MISMATCH")
    _close_except(frozenset({0, 1, 2}))
    _read_start(2)
    os.close(2)
    value = _strict_file(
        ROLE_INPUT,
        frozenset(
            {
                "input_version", "l0_profile", "m4_profile", "snapshot",
                "receipt_body",
            }
        ),
    )
    if (
        value["input_version"] != "1.0.0"
        or type(value["receipt_body"]) is not dict
        or type(value["m4_profile"]) is not dict
    ):
        _stop("OBSERVER_INPUT_MALFORMED")
    durable, l0, _, _, _ = _load_project()
    profile = _compile_l0_profile(value["l0_profile"])
    snapshot = _snapshot_from_data(value["snapshot"])
    info = os.fstat(0)
    access = fcntl.fcntl(0, fcntl.F_GETFL) & os.O_ACCMODE
    seals = fcntl.fcntl(0, fcntl.F_GET_SEALS)
    digest = l0._hash_descriptor(0, l0._resource_limit(profile, "OUTPUT_BYTES"))
    write_denied = False
    truncate_denied = False
    try:
        os.pwrite(0, b"x", 0)
    except OSError as error:
        write_denied = error.errno in {errno.EBADF, errno.EINVAL, errno.EPERM}
    try:
        os.ftruncate(0, 0)
    except OSError as error:
        truncate_denied = error.errno in {errno.EBADF, errno.EINVAL, errno.EPERM}
    measurement = {
        "pid": os.getpid(),
        "session": os.getsid(0),
        "uid": os.geteuid(),
        "gid": os.getegid(),
        "device": info.st_dev,
        "inode": info.st_ino,
        "size": info.st_size,
        "digest": digest,
        "seals": seals,
        "read_only": access == os.O_RDONLY,
        "write_denied": write_denied,
        "truncate_denied": truncate_denied,
    }
    expected_measurement = {
        "device": snapshot.device,
        "inode": snapshot.inode,
        "size": snapshot.size,
        "digest": snapshot.digest,
        "seals": fcntl.F_SEAL_GROW
        | fcntl.F_SEAL_SHRINK
        | fcntl.F_SEAL_WRITE
        | fcntl.F_SEAL_SEAL,
        "read_only": True,
        "write_denied": True,
        "truncate_denied": True,
    }
    if any(measurement[key] != item for key, item in expected_measurement.items()):
        _stop("OBSERVER_SNAPSHOT_MISMATCH")
    body = {
        **value["receipt_body"],
        "outcome": "PASS",
        "proposal_digest": _digest_bytes(_canonical(measurement)),
    }
    receipt = {**body, "receipt_digest": durable.canonical_digest(body)}
    row = value["m4_profile"].get("receipt_keys", {}).get("OBSERVER")
    if type(row) is not dict:
        _stop("OBSERVER_KEY_BINDING_MALFORMED")
    key = RoleKey("OBSERVER", row, KEY_ROOT / "observer")
    source = key.sign(
        _canonical(receipt), str(receipt["observed_at"]), "M4_OBSERVER_RECEIPT"
    )
    verification = _verification_record(receipt, source)
    verified = ConfiguredVerifierRouter().verify(
        _canonical(receipt), _canonical(verification), str(receipt["observed_at"])
    )
    if verified.status is not durable.VerificationStatus.VERIFIED:
        _stop("OBSERVER_RECEIPT_SELF_CHECK_FAILED")
    _write_report(
        {
            "kind": "OBSERVER_RECEIPT",
            "receipt": receipt,
            "verification_source": source,
            "measurement": measurement,
        }
    )


def _publisher_response(request_id: int, kind: str, payload: dict[str, object]) -> None:
    _write_report(
        {
            "protocol_version": 1,
            "request_id": request_id,
            "kind": kind,
            "payload": payload,
        }
    )


def _publisher_role() -> None:
    expected = ROLE_LABELS["PUBLISHER"] + " (enforce)"
    if (
        os.geteuid() != M4_NAMESPACE_ROLE_IDS["PUBLISHER"][2]
        or os.getegid() != M4_NAMESPACE_ROLE_IDS["PUBLISHER"][3]
        or Path("/proc/self/attr/current").read_text(encoding="ascii").strip()
        != expected
    ):
        _stop("PUBLISHER_PRINCIPAL_MISMATCH")
    _close_except(frozenset({0, 1, 2}))
    connection = socket.socket(fileno=0)
    value = _strict_file(
        ROLE_INPUT,
        frozenset({"input_version", "l0_profile", "m4_profile", "target"}),
    )
    if (
        value["input_version"] != "1.0.0"
        or type(value["m4_profile"]) is not dict
        or type(value["target"]) is not dict
    ):
        _stop("PUBLISHER_INPUT_MALFORMED")
    durable, l0, _, publisher, _ = _load_project()
    profile = _compile_l0_profile(value["l0_profile"])
    key_row = value["m4_profile"].get("receipt_keys", {}).get("PUBLISHER")
    if type(key_row) is not dict:
        _stop("PUBLISHER_KEY_BINDING_MALFORMED")
    key = RoleKey("PUBLISHER", key_row, KEY_ROOT / "publisher")
    router = ConfiguredVerifierRouter()
    target = None
    anchor = None
    trusted = None
    installed_topology = None
    last_request = 0
    while True:
        request, descriptors = _recv_control(connection, None)
        request_id = int(request["request_id"])
        operation = str(request["operation"])
        payload = request["payload"]
        if request_id != last_request + 1:
            _stop("PUBLISHER_REQUEST_REPLAY")
        last_request = request_id
        if operation == "BOOTSTRAP":
            if descriptors or payload or anchor is not None:
                _stop("PUBLISHER_BOOTSTRAP_REPLAY")
            resolved = l0.resolve_target(profile, 2, value["target"])
            if resolved.outcome is not l0.L0Outcome.RESOLVED or resolved.binding is None:
                _stop("PUBLISHER_TARGET_UNRESOLVED")
            target = resolved.binding
            anchor = publisher._measure_publication_root(2)
            _publisher_response(
                request_id,
                "BOOTSTRAP",
                {"target_binding": target.data(), "root_anchor": anchor.data()},
            )
        elif operation == "INSTALL":
            if (
                descriptors
                or
                trusted is not None
                or target is None
                or anchor is None
                or frozenset(payload)
                != {"topology", "topology_verification", "observed_at"}
                or type(payload["topology"]) is not dict
                or type(payload["topology_verification"]) is not dict
                or type(payload["observed_at"]) is not str
            ):
                _stop("PUBLISHER_INSTALL_MALFORMED")
            compiled = publisher.compile_topology(payload["topology"])
            if (
                compiled.outcome is not publisher.PublisherOutcome.READY
                or compiled.topology is None
                or compiled.topology.publication_target_binding != target
                or compiled.topology.publication_root_anchor != anchor
            ):
                _stop("PUBLISHER_TOPOLOGY_MISMATCH")
            trusted = publisher.TrustedPublisher(
                profile=profile,
                root_descriptor=2,
                topology=compiled.topology,
                topology_verification=payload["topology_verification"],
                verifier_factory=ConfiguredVerifierRouter,
            )
            preflight = trusted.deployment_preflight(payload["observed_at"])
            if preflight.outcome is not publisher.PublisherOutcome.READY:
                _stop("PUBLISHER_DEPLOYMENT_PREFLIGHT_FAILED")
            installed_topology = compiled.topology
            _publisher_response(
                request_id,
                "INSTALLED",
                {
                    "topology_digest": installed_topology.topology_digest,
                    "anchor_digest": anchor.anchor_digest,
                    "binding_digest": target.composite_binding_digest,
                },
            )
        elif operation == "PUBLISH":
            if (
                trusted is None
                or installed_topology is None
                or len(descriptors) != 1
                or frozenset(payload)
                != {"authorization", "authorization_verification", "observed_at"}
                or type(payload["authorization"]) is not dict
                or type(payload["authorization_verification"]) is not dict
                or type(payload["observed_at"]) is not str
            ):
                for descriptor in descriptors:
                    os.close(descriptor)
                _stop("PUBLISHER_REQUEST_MALFORMED")
            snapshot_descriptor = descriptors[0]

            def physical_denial_gate(point: str) -> None:
                if point != "publisher_after_pre_replace_checks":
                    return
                _publisher_response(
                    request_id,
                    "PAUSE_AFTER_PRE_REPLACE_CHECKS",
                    {
                        "anchor_digest": installed_topology.publication_root_anchor.anchor_digest,
                        "binding_digest": installed_topology.publication_target_binding.composite_binding_digest,
                    },
                )
                continuation, extra = _recv_control(connection, 0)
                if (
                    extra
                    or continuation["request_id"] != request_id
                    or continuation["operation"] != "CONTINUE"
                    or continuation["payload"]
                    != {"point": "AFTER_PRE_REPLACE_CHECKS"}
                ):
                    _stop("PUBLISHER_CONTINUATION_REJECTED")

            try:
                result = trusted.publish(
                    snapshot_descriptor,
                    payload["authorization"],
                    payload["authorization_verification"],
                    payload["observed_at"],
                    _fault=physical_denial_gate,
                )
            finally:
                os.close(snapshot_descriptor)
            if (
                result.outcome is not publisher.PublisherOutcome.PUBLISHED
                or result.fact is None
            ):
                _stop("PUBLISHER_PUBLICATION_FAILED")
            fact = result.fact.data()
            source = key.sign(
                _canonical(fact), payload["observed_at"], "M4_PUBLICATION_RECEIPT"
            )
            verification = _verification_record(fact, source)
            if router.verify(
                _canonical(fact), _canonical(verification), payload["observed_at"]
            ).status is not durable.VerificationStatus.VERIFIED:
                _stop("PUBLICATION_RECEIPT_SIGNATURE_REJECTED")
            _publisher_response(
                request_id,
                "PUBLICATION_RECEIPT",
                {"fact": fact, "verification_source": source},
            )
        elif operation == "CONTINUITY":
            if (
                descriptors
                or
                trusted is None
                or installed_topology is None
                or frozenset(payload) != {"purpose", "continuity"}
                or payload["purpose"] not in {"PRE_COMMIT", "PRE_JOIN"}
                or type(payload["continuity"]) is not dict
                or not trusted.continuity()
            ):
                _stop("PUBLICATION_CONTINUITY_LOST")
            continuity = payload["continuity"]
            source = key.sign(
                _canonical(continuity),
                str(continuity.get("observed_at")),
                str(payload["purpose"]),
            )
            verification = _verification_record(continuity, source)
            if router.verify(
                _canonical(continuity),
                _canonical(verification),
                str(continuity.get("observed_at")),
            ).status is not durable.VerificationStatus.VERIFIED:
                _stop("CONTINUITY_SIGNATURE_REJECTED")
            if payload["purpose"] == "PRE_JOIN":
                _publisher_response(request_id, "PAUSE_AFTER_PRE_JOIN", {})
                continuation, extra = _recv_control(connection, 0)
                if (
                    extra
                    or continuation["request_id"] != request_id
                    or continuation["operation"] != "CONTINUE"
                    or continuation["payload"] != {"point": "AFTER_PRE_JOIN"}
                ):
                    _stop("PUBLISHER_CONTINUATION_REJECTED")
            _publisher_response(
                request_id,
                "CONTINUITY",
                {"payload": continuity, "verification_source": source},
            )
        elif operation == "STOP":
            if descriptors or payload:
                _stop("PUBLISHER_STOP_MALFORMED")
            _publisher_response(request_id, "STOPPED", {"closed": True})
            connection.close()
            return
        else:
            _stop("PUBLISHER_OPERATION_REJECTED")


def _relocator_role() -> None:
    expected_label = ROLE_LABELS["CONTROLLER"] + " (enforce)"
    actual_label = Path("/proc/self/attr/current").read_text(
        encoding="ascii"
    ).strip()
    if (
        os.geteuid() != ROLE_IDS["CONTROLLER"][0]
        or os.getegid() != ROLE_IDS["CONTROLLER"][1]
        or actual_label != expected_label
    ):
        _stop("RELOCATOR_PRINCIPAL_MISMATCH")
    _close_except(frozenset({0, 1, 2}))
    raw = sys.stdin.buffer.readline(MAX_JSON + 2)
    if not raw or len(raw) > MAX_JSON + 1 or not raw.endswith(b"\n"):
        _stop("RELOCATOR_REQUEST_MALFORMED")
    request = _strict_bytes(raw[:-1])
    destination = DENIED_REPOSITORY / ".git" / PUBLICATION_ROOT.name
    if request != {
        "request_version": "1.0.0",
        "point": request.get("point") if type(request) is dict else None,
        "source": str(PUBLICATION_ROOT),
        "destination": str(destination),
    } or request["point"] not in {
        "AFTER_PRE_REPLACE_CHECKS",
        "AFTER_PRE_JOIN",
    }:
        _stop("RELOCATOR_REQUEST_MALFORMED")
    error_number = 0
    try:
        os.rename(PUBLICATION_ROOT, destination)
    except OSError as error:
        error_number = int(error.errno or 0)
    report = {
        "point": request["point"],
        "errno": error_number,
        "source_exists": PUBLICATION_ROOT.is_dir(),
        "destination_exists": destination.exists(),
        "pid": os.getpid(),
        "session": os.getsid(0),
        "uid": os.geteuid(),
        "gid": os.getegid(),
        "label": actual_label.removesuffix(" (enforce)"),
    }
    _write_report(report)
    if error_number not in {errno.EACCES, errno.EPERM}:
        _stop("PUBLICATION_RELOCATION_NOT_DENIED")


def _durable_result_data(result: object) -> dict[str, object]:
    value = asdict(result)
    value["outcome"] = result.outcome.value
    value["reason"] = result.reason.value
    return value


def _m4_recovery_from_data(value: object, durable: object) -> object:
    if (
        type(value) is not dict
        or frozenset(value) != frozenset(durable.M4Recovery.__dataclass_fields__)
        or any(
            type(value[name]) is not str or not value[name] or len(value[name]) > 128
            for name in ("transaction_id", "state", "intent_state")
        )
        or any(
            not _is_digest(value[name])
            for name in (
                "contract_digest", "d2_frontier_digest", "frontier_record_digest"
            )
        )
        or (
            value["record_digest"] is not None
            and not _is_digest(value["record_digest"])
        )
        or any(
            type(value[name]) is not int or isinstance(value[name], bool)
            for name in (
                "fencing_epoch", "iteration", "frontier_attempt_cursor",
                "frontier_joined_iteration", "attempt_cursor", "joined_iteration",
                "journal_sequence", "revocation_epoch",
            )
        )
        or value["fencing_epoch"] < 1
        or value["iteration"] < 1
        or any(
            value[name] < 0
            for name in (
                "frontier_attempt_cursor", "frontier_joined_iteration",
                "attempt_cursor", "joined_iteration", "journal_sequence",
                "revocation_epoch",
            )
        )
        or type(value["resume_allowed"]) is not bool
        or type(value["retry_allowed"]) is not bool
    ):
        _stop("CONTROLLER_RESULT_MALFORMED")
    return durable.M4Recovery(**value)


def _durable_result_from_data(value: object) -> object:
    durable, _, _, _, _ = _load_project()
    if type(value) is not dict or frozenset(value) != frozenset(
        durable.DurableResult.__dataclass_fields__
    ):
        _stop("CONTROLLER_RESULT_MALFORMED")
    recovery_rows = value.get("m4_recovery")
    if (
        type(recovery_rows) is not list
        or any(
            type(item) is not dict
            or frozenset(item) != frozenset(durable.M4Recovery.__dataclass_fields__)
            for item in recovery_rows
        )
    ):
        _stop("CONTROLLER_RESULT_MALFORMED")
    try:
        return durable.DurableResult(
            outcome=durable.DurableOutcome(value["outcome"]),
            reason=durable.DurableReason(value["reason"]),
            capability_id=value["capability_id"],
            transaction_id=value["transaction_id"],
            journal_sequence=value["journal_sequence"],
            recovery_intents=tuple(
                durable.RecoveryIntent(**item) for item in value["recovery_intents"]
            ),
            dispatch_claim=(
                None
                if value["dispatch_claim"] is None
                else durable.DispatchClaim(**value["dispatch_claim"])
            ),
            runtime_session=(
                None
                if value["runtime_session"] is None
                else durable.RuntimeSession(**value["runtime_session"])
            ),
            recovery_sessions=tuple(
                durable.RecoverySession(**item) for item in value["recovery_sessions"]
            ),
            contract_digest=value["contract_digest"],
            d2_frontier_digest=value["d2_frontier_digest"],
            record_digest=value["record_digest"],
            m4_state=value["m4_state"],
            m4_iteration=value["m4_iteration"],
            frontier_record_digest=value["frontier_record_digest"],
            m4_recovery=tuple(
                _m4_recovery_from_data(item, durable) for item in recovery_rows
            ),
            stage_execution_grant=(
                None
                if value["stage_execution_grant"] is None
                else durable.StageExecutionGrant(**value["stage_execution_grant"])
            ),
        )
    except (KeyError, TypeError, ValueError) as error:
        raise QualificationStop("CONTROLLER_RESULT_MALFORMED") from error


def _bind_current_frontier(
    store: object,
    provider: ControllerVerificationProvider,
    raw: dict[str, object],
) -> object:
    """Build, sign and bind D2 only from the controller-owned live store."""

    durable, _, _, _, _ = _load_project()
    if (
        frozenset(raw) != {"transaction_id", "observed_at", "issued_at", "expires_at"}
        or any(type(raw[key]) is not str for key in raw)
    ):
        _stop("CONTROLLER_FRONTIER_REQUEST_MALFORMED")
    connection: sqlite3.Connection | None = None
    try:
        connection = store._connect()
        store._audit(connection)
        meta = connection.execute("SELECT * FROM store_meta WHERE id=1").fetchone()
        intent = connection.execute(
            "SELECT * FROM dispatch_intents WHERE transaction_id=?",
            (raw["transaction_id"],),
        ).fetchone()
        claim = connection.execute(
            "SELECT * FROM dispatch_attempt_claims WHERE transaction_id=?",
            (raw["transaction_id"],),
        ).fetchone()
        if meta is None or intent is None or claim is None:
            _stop("CONTROLLER_FRONTIER_SOURCE_ABSENT")
        capability = connection.execute(
            "SELECT * FROM capabilities WHERE capability_id=?",
            (intent["capability_id"],),
        ).fetchone()
        if capability is None:
            _stop("CONTROLLER_FRONTIER_SOURCE_ABSENT")
        contract_row = connection.execute(
            "SELECT * FROM active_contracts WHERE contract_digest=?",
            (capability["contract_digest"],),
        ).fetchone()
        if contract_row is None:
            _stop("CONTROLLER_FRONTIER_SOURCE_ABSENT")
        contract = _strict_bytes(contract_row["contract_json"].encode("utf-8"))
        if type(contract) is not dict:
            _stop("CONTROLLER_FRONTIER_SOURCE_MALFORMED")
        iteration = int(contract_row["attempt_cursor"]) + 1
        frontier_body: dict[str, object] = {
            "frontier_version": "2.0.0",
            "contract_digest": contract["contract_digest"],
            "contract_version": contract["contract_version"],
            "authority_domain_id": contract["authority_domain_id"],
            "journal_lineage_id": contract["journal_lineage_id"],
            "root_contract_digest": contract["root_contract_digest"],
            "parent_contract_digest": contract["parent_contract_digest"],
            "journal_sequence": int(meta["journal_head_sequence"]),
            "attempt_cursor": int(contract_row["attempt_cursor"]),
            "joined_iteration": int(contract_row["joined_iteration"]),
            "iteration": iteration,
            "fencing_epoch": int(meta["fencing_epoch"]),
            "issued_at": raw["issued_at"],
            "expires_at": raw["expires_at"],
            "inventory": store._authoritative_d2_inventory(
                connection, raw["transaction_id"], iteration
            ),
        }
        frontier = {
            **frontier_body,
            "frontier_record_digest": durable.canonical_digest(frontier_body),
        }
        payload = store._d2_payload(connection, raw["transaction_id"], frontier)
        source = provider.sign(
            _canonical(payload), raw["observed_at"], "D2_FRONTIER"
        )
    except QualificationStop:
        raise
    except Exception as error:
        raise QualificationStop("CONTROLLER_FRONTIER_BUILD_FAILED") from error
    finally:
        if connection is not None:
            connection.close()
    return store.bind_m4_frontier(
        {
            "transaction_id": raw["transaction_id"],
            "observed_at": raw["observed_at"],
            "frontier": frontier,
            "frontier_verification": source,
        }
    )


def _controller_role() -> None:
    expected = ROLE_LABELS["CONTROLLER"] + " (enforce)"
    if (
        os.geteuid() != ROLE_IDS["CONTROLLER"][0]
        or os.getegid() != ROLE_IDS["CONTROLLER"][1]
        or Path("/proc/self/attr/current").read_text(encoding="ascii").strip()
        != expected
    ):
        _stop("CONTROLLER_PRINCIPAL_MISMATCH")
    durable, _, _, _, _ = _load_project()
    trust = _strict_file(
        RUNTIME_TRUST,
        frozenset(
            {
                "trust_version", "profile_digest", "verifier_code_path",
                "verifier_code_digest", "libcrypto_path", "libcrypto_digest",
                "m4_routes", "supply", "revocation_epoch", "fencing_epoch",
            }
        ),
        1 << 20,
    )
    supply_verifier = _configured_verifier(trust["supply"])
    router = ConfiguredVerifierRouter()
    provider = ControllerVerificationProvider()
    store = durable.DurableStore(
        str(M4_DATABASE),
        supply_verifier,
        executor_claim_verifier=supply_verifier,
        runtime_session_verifier=supply_verifier,
        m4_verifier=router,
        m4_verification_provider=provider,
    )
    operations = {
        "BOOTSTRAP": store.bootstrap,
        "ISSUE": store.issue,
        "CONSUME": store.consume,
        "CLAIM": store.claim_dispatch,
        "PREPARE": store.prepare_runtime_session,
        "VERIFY_CLAIM": store.verify_dispatch_claim,
        "ACTIVATE_CONTRACT": store.activate_m4_contract,
        "BEGIN_M4": store.begin_m4_transaction,
        "CONSUME_M4": lambda raw: store.consume_m4_stage_authorization(
            raw, require_execution_grant=True
        ),
        "ADVANCE_M4": store.advance_m4,
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
            response = {"kind": "STOPPED", "value": {"closed": True}}
        elif operation == "EVALUATE":
            from harness_product import kernel  # noqa: PLC0415

            evaluated = kernel.evaluate(request["raw"])
            response = {
                "kind": "EVALUATION",
                "value": {
                    "outcome": evaluated.decision.outcome.value,
                    "reason": evaluated.decision.reason.value,
                    "stage": evaluated.decision.stage.value,
                    "transition_accepted": evaluated.transition.accepted,
                    "proposal_authorities": [
                        item.authority.value for item in evaluated.transition.proposals
                    ],
                },
            }
        elif operation == "RECOVER":
            if request["raw"]:
                _stop("CONTROLLER_PROTOCOL_MALFORMED")
            response = {"kind": "DURABLE", "value": _durable_result_data(store.recover())}
        elif operation == "SIGN":
            signing = request["raw"]
            if (
                frozenset(signing) != {"payload", "observed_at", "purpose"}
                or type(signing["payload"]) is not dict
                or type(signing["observed_at"]) is not str
                or type(signing["purpose"]) is not str
            ):
                _stop("CONTROLLER_PROTOCOL_MALFORMED")
            response = {
                "kind": "VERIFICATION_SOURCE",
                "value": provider.sign(
                    _canonical(signing["payload"]),
                    signing["observed_at"],
                    signing["purpose"],
                ),
            }
        elif operation == "BIND_CURRENT_FRONTIER":
            response = {
                "kind": "DURABLE",
                "value": _durable_result_data(
                    _bind_current_frontier(store, provider, request["raw"])
                ),
            }
        elif operation in operations:
            response = {
                "kind": "DURABLE",
                "value": _durable_result_data(operations[operation](request["raw"])),
            }
        else:
            _stop("CONTROLLER_OPERATION_UNKNOWN")
        sys.stdout.buffer.write(_canonical(response) + b"\n")
        sys.stdout.buffer.flush()
        if operation == "STOP":
            return


class ControllerSession:
    """Measured controller/PEP that owns the current M1-M4 durable store."""

    def __init__(self, manager: object) -> None:
        self.manager = manager
        self.cgroup = manager.create("m4-controller")
        self.operations: list[dict[str, object]] = []
        self.closed = False
        code = os.open(Path(__file__).resolve(), os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        argv = [
            AA_EXEC, "--profile", ROLE_LABELS["CONTROLLER"], "--", PYTHON,
            "-I", "-S", "/proc/self/fd/3", "--internal-role", "controller",
        ]
        try:
            self.process = subprocess.Popen(
                argv,
                shell=False,
                close_fds=True,
                pass_fds=tuple(sorted({code, 3})),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env={},
                cwd="/",
                preexec_fn=_role_preexec("CONTROLLER", self.cgroup, ((code, 3),)),
            )
        finally:
            os.close(code)
        self.facts = _observe_role(
            self.process.pid,
            "CONTROLLER",
            self.cgroup,
            list(_profile()["roles"]["CONTROLLER"]["fd_allowlist"]),
        )
        self.facts["argv"] = argv
        self.facts["argv_digest"] = _digest_bytes(_canonical(argv))

    @property
    def dynamic_m4_verification(self) -> bool:
        return True

    def _request(self, operation: str, raw: dict[str, object]) -> tuple[str, object]:
        if self.closed or self.process.poll() is not None:
            _stop("CONTROLLER_SESSION_CLOSED")
        request = {"operation": operation, "raw": raw}
        encoded = _canonical(request)
        if self.process.stdin is None or self.process.stdout is None:
            _stop("CONTROLLER_PROTOCOL_CLOSED")
        self.process.stdin.write(encoded + b"\n")
        self.process.stdin.flush()
        response_raw = _read_line(self.process.stdout.fileno(), MAX_JSON, 20)
        response = _strict_bytes(response_raw)
        if type(response) is not dict or frozenset(response) != {"kind", "value"}:
            _stop("CONTROLLER_RESPONSE_MALFORMED")
        self.operations.append(
            {
                "operation": operation,
                "request_digest": _digest_bytes(encoded),
                "response_digest": _digest_bytes(response_raw),
            }
        )
        return str(response["kind"]), response["value"]

    def evaluate(self, raw: dict[str, object]) -> dict[str, object]:
        kind, value = self._request("EVALUATE", raw)
        if kind != "EVALUATION" or type(value) is not dict:
            _stop("CONTROLLER_RESPONSE_MALFORMED")
        return value

    def _durable(self, operation: str, raw: dict[str, object]) -> object:
        kind, value = self._request(operation, raw)
        if kind != "DURABLE":
            _stop("CONTROLLER_RESPONSE_MALFORMED")
        return _durable_result_from_data(value)

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

    def activate_m4_contract(self, raw: dict[str, object]) -> object:
        return self._durable("ACTIVATE_CONTRACT", raw)

    def bind_current_m4_frontier(self, raw: dict[str, object]) -> object:
        return self._durable("BIND_CURRENT_FRONTIER", raw)

    def begin_m4_transaction(self, raw: dict[str, object]) -> object:
        return self._durable("BEGIN_M4", raw)

    def consume_m4_stage_authorization(
        self, raw: dict[str, object], *, require_execution_grant: bool = False
    ) -> object:
        if not require_execution_grant:
            _stop("DEPLOYMENT_GRANT_REQUIRED")
        return self._durable("CONSUME_M4", raw)

    def advance_m4(self, raw: dict[str, object]) -> object:
        return self._durable("ADVANCE_M4", raw)

    def recover(self) -> object:
        return self._durable("RECOVER", {})

    def sign(
        self, payload: bytes, observed_at: str, purpose: str
    ) -> dict[str, object]:
        parsed = _strict_bytes(payload)
        if type(parsed) is not dict or _canonical(parsed) != payload:
            _stop("CONTROLLER_SIGNING_PAYLOAD_MALFORMED")
        kind, value = self._request(
            "SIGN",
            {
                "payload": parsed,
                "observed_at": observed_at,
                "purpose": purpose,
            },
        )
        if (
            kind != "VERIFICATION_SOURCE"
            or type(value) is not dict
            or frozenset(value) != {"verifier_id", "issuer_id", "key_id", "proof"}
        ):
            _stop("CONTROLLER_RESPONSE_MALFORMED")
        return value

    @staticmethod
    def m4_verifier() -> ConfiguredVerifierRouter:
        return ConfiguredVerifierRouter()

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
            "operations": self.operations,
            "operations_digest": _digest_bytes(_canonical(self.operations)),
            "closed": True,
            "cgroup_populated_after_close": 0,
        }
        return self.facts


class PublisherSession:
    """One persistent publisher principal from topology bootstrap through JOIN."""

    def __init__(
        self,
        *,
        process: subprocess.Popen[bytes],
        connection: socket.socket,
        manager: object,
        m3: object,
        cgroup: Path,
        status_read: int,
        facts: dict[str, object],
        denial_probe: object,
    ) -> None:
        if (
            process.stdout is None
            or type(status_read) is not int
            or status_read < 0
            or not callable(denial_probe)
        ):
            raise ValueError("invalid publisher session")
        self.process = process
        self.connection = connection
        self.manager = manager
        self.m3 = m3
        self.cgroup = cgroup
        self.status_read = status_read
        self.facts = facts
        self.denial_probe = denial_probe
        self.request_id = 0
        self.closed = False
        self.topology_digest: str | None = None

    def _next_request(
        self,
        operation: str,
        payload: dict[str, object],
        descriptor: int | None = None,
    ) -> int:
        if self.closed or self.process.poll() is not None:
            _stop("PUBLISHER_SESSION_CLOSED")
        self.request_id += 1
        _send_control(
            self.connection,
            {
                "protocol_version": 1,
                "request_id": self.request_id,
                "operation": operation,
                "payload": payload,
            },
            descriptor,
        )
        return self.request_id

    def _reply(self, request_id: int, expected_kind: str) -> dict[str, object]:
        if self.process.stdout is None:
            _stop("PUBLISHER_PROTOCOL_CLOSED")
        raw = _read_line(self.process.stdout.fileno(), MAX_REPORT, 20)
        value = _strict_bytes(raw, MAX_REPORT)
        if (
            type(value) is not dict
            or frozenset(value)
            != {"protocol_version", "request_id", "kind", "payload"}
            or value.get("protocol_version") != 1
            or value.get("request_id") != request_id
            or value.get("kind") != expected_kind
            or type(value.get("payload")) is not dict
        ):
            _stop("PUBLISHER_RESPONSE_MALFORMED")
        return value["payload"]

    def bootstrap(self) -> dict[str, object]:
        request_id = self._next_request("BOOTSTRAP", {})
        payload = self._reply(request_id, "BOOTSTRAP")
        if frozenset(payload) != {"target_binding", "root_anchor"}:
            _stop("PUBLISHER_BOOTSTRAP_MALFORMED")
        _, l0, _, publisher, _ = _load_project()
        try:
            target = l0._parse_path_binding(payload["target_binding"])
            anchor = publisher._parse_anchor(payload["root_anchor"])
        except Exception as error:
            raise QualificationStop("PUBLISHER_BOOTSTRAP_MALFORMED") from error
        return {"target_binding": target, "root_anchor": anchor}

    def install(
        self,
        topology: object,
        topology_verification: dict[str, object],
        observed_at: str,
    ) -> None:
        if self.topology_digest is not None or not hasattr(topology, "data"):
            _stop("PUBLISHER_INSTALL_REPLAY")
        request_id = self._next_request(
            "INSTALL",
            {
                "topology": topology.data(),
                "topology_verification": topology_verification,
                "observed_at": observed_at,
            },
        )
        payload = self._reply(request_id, "INSTALLED")
        if payload != {
            "topology_digest": topology.topology_digest,
            "anchor_digest": topology.publication_root_anchor.anchor_digest,
            "binding_digest": (
                topology.publication_target_binding.composite_binding_digest
            ),
        }:
            _stop("PUBLISHER_INSTALL_MISMATCH")
        self.topology_digest = topology.topology_digest

    def publish(
        self,
        snapshot_descriptor: int,
        authorization: dict[str, object],
        authorization_verification: dict[str, object],
        observed_at: str,
    ) -> object:
        if self.topology_digest is None:
            _stop("PUBLISHER_TOPOLOGY_ABSENT")
        request_id = self._next_request(
            "PUBLISH",
            {
                "authorization": authorization,
                "authorization_verification": authorization_verification,
                "observed_at": observed_at,
            },
            snapshot_descriptor,
        )
        pause = self._reply(request_id, "PAUSE_AFTER_PRE_REPLACE_CHECKS")
        if frozenset(pause) != {"anchor_digest", "binding_digest"}:
            _stop("PUBLISHER_DENIAL_GATE_MALFORMED")
        self.denial_probe("AFTER_PRE_REPLACE_CHECKS", pause)
        _send_control(
            self.connection,
            {
                "protocol_version": 1,
                "request_id": request_id,
                "operation": "CONTINUE",
                "payload": {"point": "AFTER_PRE_REPLACE_CHECKS"},
            },
        )
        payload = self._reply(request_id, "PUBLICATION_RECEIPT")
        if frozenset(payload) != {"fact", "verification_source"} or type(
            payload["verification_source"]
        ) is not dict:
            _stop("PUBLICATION_RECEIPT_MALFORMED")
        _, _, m4, _, _ = _load_project()
        return m4.RuntimePublicationReceipt(
            _publication_fact_from_data(payload["fact"]),
            payload["verification_source"],
        )

    def continuity(self, purpose: str, payload: dict[str, object]) -> object:
        if self.topology_digest is None or purpose not in {"PRE_COMMIT", "PRE_JOIN"}:
            _stop("CONTINUITY_PURPOSE_REJECTED")
        request_id = self._next_request(
            "CONTINUITY",
            {"purpose": purpose, "continuity": payload},
        )
        if purpose == "PRE_JOIN":
            pause = self._reply(request_id, "PAUSE_AFTER_PRE_JOIN")
            if pause:
                _stop("PUBLISHER_DENIAL_GATE_MALFORMED")
            self.denial_probe("AFTER_PRE_JOIN", {})
            _send_control(
                self.connection,
                {
                    "protocol_version": 1,
                    "request_id": request_id,
                    "operation": "CONTINUE",
                    "payload": {"point": "AFTER_PRE_JOIN"},
                },
            )
        response = self._reply(request_id, "CONTINUITY")
        if (
            frozenset(response) != {"payload", "verification_source"}
            or response["payload"] != payload
            or type(response["verification_source"]) is not dict
        ):
            _stop("PUBLICATION_CONTINUITY_LOST")
        _, _, m4, _, _ = _load_project()
        return m4.RuntimeContinuity(payload, response["verification_source"])

    def close(self) -> dict[str, object]:
        if self.closed:
            return self.facts
        succeeded = False
        status_digest = ""
        try:
            request_id = self._next_request("STOP", {})
            if self._reply(request_id, "STOPPED") != {"closed": True}:
                _stop("PUBLISHER_STOP_MISMATCH")
            return_code, status_digest = self.m3._complete_role(
                self.process,
                self.status_read,
                self.cgroup,
                timeout=5,
            )
            self.status_read = -1
            if return_code != 0:
                _stop("PUBLISHER_STOP_FAILED")
            succeeded = True
        finally:
            self.closed = True
            try:
                self.connection.close()
            except OSError:
                pass
            if self.process.stdout is not None:
                self.process.stdout.close()
            if not succeeded:
                try:
                    self.manager.kill(self.cgroup)
                except Exception:
                    pass
                try:
                    self.process.wait(timeout=3)
                except Exception:
                    pass
                if self.status_read >= 0:
                    try:
                        os.close(self.status_read)
                    except OSError:
                        pass
                    self.status_read = -1
            self.manager.kill(self.cgroup)
        self.facts["closed"] = True
        self.facts["cgroup_populated_after_close"] = 0
        self.facts["status_digest"] = status_digest
        return self.facts


def _observe_role(pid: int, role: str, cgroup: Path, expected_fds: list[int]) -> dict[str, object]:
    deadline = time.monotonic() + 3
    expected_label = ROLE_LABELS[role] + " (enforce)"
    while time.monotonic() < deadline:
        try:
            label = Path(f"/proc/{pid}/attr/current").read_text(encoding="ascii").strip()
            status_rows = Path(f"/proc/{pid}/status").read_text(encoding="ascii").splitlines()
            status = dict(row.split(":", 1) for row in status_rows if ":" in row)
            inventory = sorted(int(path.name) for path in Path(f"/proc/{pid}/fd").iterdir())
            attached = str(pid) in (cgroup / "cgroup.procs").read_text(encoding="ascii").split()
            if (
                label == expected_label
                and inventory == expected_fds
                and attached
                and all(status.get(key, "").strip() == "0000000000000000" for key in ("CapInh", "CapPrm", "CapEff"))
                and status.get("NoNewPrivs", "").strip() == "1"
            ):
                namespaces = {
                    name: os.readlink(f"/proc/{pid}/ns/{name}")
                    for name in ("user", "mnt", "pid", "ipc", "uts", "net", "cgroup")
                }
                return {
                    "role": role,
                    "pid": pid,
                    "uid": int(status["Uid"].split()[0]),
                    "gid": int(status["Gid"].split()[0]),
                    "session": os.getsid(pid),
                    "label": label.removesuffix(" (enforce)"),
                    "cgroup": str(cgroup).removeprefix("/sys/fs/cgroup"),
                    "fd_inventory": inventory,
                    "namespaces": namespaces,
                    "capabilities": {key: status[key].strip() for key in ("CapInh", "CapPrm", "CapEff")},
                    "no_new_privs": 1,
                }
        except (FileNotFoundError, ProcessLookupError, OSError, KeyError, ValueError):
            pass
        time.sleep(0.01)
    _stop("ROLE_ENVELOPE_MISMATCH_" + role)


class M4GuestRuntime:
    """One concrete M4RuntimeBoundary for the disposable Ubuntu guest."""

    def __init__(
        self,
        *,
        profile: dict[str, object],
        topology: object,
        topology_verification: dict[str, object],
        stage_root_descriptor: int,
        controller: ControllerSession,
        publisher_session: PublisherSession,
        verifier_router: VerificationRouter,
        manager: object,
        executor_launcher: object,
        observer_launcher: object,
    ) -> None:
        if (
            profile.get("assurance_scope") != EXPECTED_SCOPE
            or profile.get("publication", {}).get("transport") != SEALED_FD_ONLY
            or type(controller) is not ControllerSession
            or type(publisher_session) is not PublisherSession
            or not callable(executor_launcher)
            or not callable(observer_launcher)
            or publisher_session.topology_digest != topology.topology_digest
        ):
            raise ValueError("invalid exact M4 guest runtime")
        self.profile = profile
        self.topology = topology
        self.topology_verification = topology_verification
        self.stage_root_descriptor = fcntl.fcntl(stage_root_descriptor, fcntl.F_DUPFD_CLOEXEC, 3)
        self.controller = controller
        self.publisher_session = publisher_session
        self.verifier_router = verifier_router
        self.manager = manager
        self._executor_launcher = executor_launcher
        self._observer_launcher = observer_launcher
        self.events: list[dict[str, object]] = []

    def _controller_signed(
        self,
        payload: dict[str, object],
        observed_at: str,
        purpose: str,
    ) -> object:
        _, _, m4, _, _ = _load_project()
        source = self.controller.sign(_canonical(payload), observed_at, purpose)
        record = _verification_record(payload, source)
        result = self.verifier_router.verify(_canonical(payload), _canonical(record), observed_at)
        durable, _, _, _, _ = _load_project()
        if result.status is not durable.VerificationStatus.VERIFIED:
            _stop("POST_EVENT_SIGNATURE_REJECTED")
        return m4.RuntimeContinuity(payload, source)

    def preflight(
        self,
        profile: object,
        claim: object,
        supply: object,
        staging_binding: object,
        observed_at: str,
    ) -> object:
        if (
            profile.profile_digest != claim.profile_digest
            or supply.placement_digest != claim.placement_digest
            or self.publisher_session.topology_digest != self.topology.topology_digest
        ):
            _stop("M4_RUNTIME_PREFLIGHT_REJECTED")
        payload = {
            "runtime_version": "1.0.0",
            "outcome": "READY",
            "transaction_id": claim.transaction_id,
            "claim_digest": claim.claim_digest,
            "profile_digest": profile.profile_digest,
            "placement_digest": supply.placement_digest,
            "session_id": claim.session_id,
            "revocation_epoch": claim.revocation_epoch,
            "fencing_epoch": claim.fencing_epoch,
            "executor_principal": claim.audience_id,
            "executor_session": self.topology.subject("EXECUTOR").session_id,
            "staging_binding_digest": staging_binding.composite_binding_digest,
            "observed_at": observed_at,
            "expires_at": supply.expires_at,
        }
        result = self._controller_signed(
            payload,
            observed_at,
            "M4_RUNTIME_PREFLIGHT",
        )
        self.events.append(
            {
                "type": "M4_RUNTIME_PREFLIGHT",
                "payload": payload,
                "verification_source": result.verification_source,
            }
        )
        return result

    def stage(
        self,
        profile: object,
        claim: object,
        supply: object,
        root_descriptor: int,
        stage_request: dict[str, object],
        stage_execution_grant: object,
        claim_verifier_factory: object,
        supply_verifier_factory: object,
        m4_verifier_factory: object,
    ) -> object:
        durable, _, m4, _, _ = _load_project()
        if type(stage_execution_grant) is not durable.StageExecutionGrant:
            _stop("STAGE_EXECUTION_GRANT_REQUIRED")
        grant_payload = _strict_bytes(
            stage_execution_grant.payload_json.encode("utf-8")
        )
        grant_verification = _strict_bytes(
            stage_execution_grant.verification_json.encode("utf-8")
        )
        if (
            type(grant_payload) is not dict
            or type(grant_verification) is not dict
            or type(grant_payload.get("consumption")) is not dict
            or type(grant_payload.get("authorization")) is not dict
        ):
            _stop("STAGE_EXECUTION_GRANT_MALFORMED")
        result = self._executor_launcher(
            profile,
            claim,
            supply,
            root_descriptor,
            stage_request,
            stage_execution_grant,
            claim_verifier_factory,
            supply_verifier_factory,
            m4_verifier_factory,
        )
        if type(result) is not m4.RuntimeStageExecution:
            _stop("EXECUTOR_BOUNDARY_FAILED")
        self.events.append(
            {
                "type": "TCB_STAGE",
                "pid": result.process_id,
                "session": result.process_session,
                "stage_authorization_digest": grant_payload["consumption"].get(
                    "stage_authorization_digest"
                ),
                "target_binding": grant_payload["authorization"].get(
                    "target_binding"
                ),
                "grant_payload": grant_payload,
                "grant_verification": grant_verification,
                "grant_payload_digest": _digest_bytes(
                    stage_execution_grant.payload_json.encode("utf-8")
                ),
                "grant_verification_digest": _digest_bytes(
                    stage_execution_grant.verification_json.encode("utf-8")
                ),
            }
        )
        return result

    def observe(
        self,
        profile: object,
        snapshot_descriptor: int,
        snapshot: object,
        receipt_body: dict[str, object],
    ) -> object:
        _, _, m4, _, _ = _load_project()
        result = self._observer_launcher(
            profile,
            snapshot_descriptor,
            snapshot,
            receipt_body,
        )
        if type(result) is not m4.RuntimeObserverReceipt:
            _stop("OBSERVER_BOUNDARY_FAILED")
        self.events.append(
            {
                "type": "TCB_POSTCHECK",
                "pid": result.process_id,
                "session": result.process_session,
                "receipt": result.receipt,
                "verification_source": result.verification_source,
            }
        )
        return result

    def publish(
        self,
        snapshot_descriptor: int,
        authorization: dict[str, object],
        authorization_verification: dict[str, object],
        observed_at: str,
        fault: object | None,
    ) -> object:
        if fault is not None:
            _stop("RUNTIME_FAULT_INJECTION_FORBIDDEN")
        _, _, m4, _, _ = _load_project()
        result = self.publisher_session.publish(
            snapshot_descriptor,
            authorization,
            authorization_verification,
            observed_at,
        )
        if type(result) is not m4.RuntimePublicationReceipt:
            _stop("PUBLISHER_BOUNDARY_FAILED")
        self.events.append(
            {
                "type": "TCB_PUBLICATION",
                "receipt": result.fact.data(),
                "verification_source": result.verification_source,
            }
        )
        return result

    def continuity(self, purpose: str, payload: dict[str, object]) -> object:
        if purpose not in {"PRE_COMMIT", "PRE_JOIN"}:
            _stop("CONTINUITY_PURPOSE_REJECTED")
        result = self.publisher_session.continuity(purpose, payload)
        self.events.append(
            {
                "type": purpose,
                "payload": payload,
                "verification_source": result.verification_source,
            }
        )
        return result


def _prepare_publication_root() -> int:
    publisher_uid, publisher_gid = ROLE_IDS["PUBLISHER"]
    if PUBLICATION_PARENT.exists() or PUBLICATION_PARENT.is_symlink():
        _stop("PUBLICATION_ROOT_REUSE_FORBIDDEN")
    PUBLICATION_ROOT.mkdir(parents=True, mode=0o700)
    os.chown(PUBLICATION_PARENT.parent, 0, 0)
    os.chmod(PUBLICATION_PARENT.parent, 0o755)
    os.chown(PUBLICATION_PARENT, 0, 0)
    os.chmod(PUBLICATION_PARENT, 0o555)
    os.chown(PUBLICATION_ROOT, publisher_uid, publisher_gid)
    os.chmod(PUBLICATION_ROOT, 0o700)
    target = PUBLICATION_ROOT / "artifact.txt"
    _write_exact(target, b"old\n", 0o600, publisher_uid, publisher_gid)
    denied_git = DENIED_REPOSITORY / ".git"
    denied_git.mkdir(parents=True, mode=0o555)
    for path in (DENIED_REPOSITORY, denied_git):
        os.chown(path, 0, 0)
        os.chmod(path, 0o555)
    if (PUBLICATION_ROOT / ".git").exists():
        _stop("PHYSICAL_GIT_BYPASS")
    return os.open(
        PUBLICATION_ROOT,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )


def _publication_denial_probe(
    manager: object,
    point: str,
    pause: dict[str, object],
) -> dict[str, object]:
    if (
        point not in {"AFTER_PRE_REPLACE_CHECKS", "AFTER_PRE_JOIN"}
        or type(pause) is not dict
        or (
            point == "AFTER_PRE_REPLACE_CHECKS"
            and frozenset(pause) != {"anchor_digest", "binding_digest"}
        )
        or (point == "AFTER_PRE_JOIN" and pause)
    ):
        _stop("PUBLICATION_DENIAL_PROBE_MALFORMED")
    before = os.stat(PUBLICATION_ROOT, follow_symlinks=False)
    destination = DENIED_REPOSITORY / ".git" / PUBLICATION_ROOT.name
    if destination.exists() or destination.is_symlink():
        _stop("PHYSICAL_GIT_BYPASS")
    cgroup = manager.create(
        "m4-relocation-" + ("replace" if point == "AFTER_PRE_REPLACE_CHECKS" else "join")
    )
    code = os.open(
        Path(__file__).resolve(),
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    argv = [
        AA_EXEC,
        "--profile",
        ROLE_LABELS["CONTROLLER"],
        "--",
        PYTHON,
        "-I",
        "-S",
        "/proc/self/fd/3",
        "--internal-role",
        "relocator",
    ]
    process: subprocess.Popen[bytes] | None = None
    try:
        process = subprocess.Popen(
            argv,
            shell=False,
            close_fds=True,
            pass_fds=tuple(sorted({code, 3})),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env={},
            cwd="/",
            preexec_fn=_role_preexec("CONTROLLER", cgroup, ((code, 3),)),
        )
    finally:
        os.close(code)
    try:
        facts = _observe_role(process.pid, "CONTROLLER", cgroup, [0, 1, 2])
        request = {
            "request_version": "1.0.0",
            "point": point,
            "source": str(PUBLICATION_ROOT),
            "destination": str(destination),
        }
        if process.stdin is None or process.stdout is None:
            _stop("PUBLICATION_DENIAL_CHANNEL_ABSENT")
        process.stdin.write(_canonical(request) + b"\n")
        process.stdin.flush()
        process.stdin.close()
        report = _strict_bytes(_read_line(process.stdout.fileno(), 4096, 5), 4096)
        process.stdout.close()
        if process.wait(timeout=5) != 0:
            _stop("PUBLICATION_DENIAL_PROBE_FAILED")
        manager.kill(cgroup)
        after = os.stat(PUBLICATION_ROOT, follow_symlinks=False)
        expected = {
            "point", "errno", "source_exists", "destination_exists",
            "pid", "session", "uid", "gid", "label",
        }
        if (
            type(report) is not dict
            or frozenset(report) != expected
            or report["point"] != point
            or report["errno"] not in {errno.EACCES, errno.EPERM}
            or report["source_exists"] is not True
            or report["destination_exists"] is not False
            or report["pid"] != facts["pid"]
            or report["session"] != facts["session"]
            or report["uid"] != ROLE_IDS["CONTROLLER"][0]
            or report["gid"] != ROLE_IDS["CONTROLLER"][1]
            or report["label"] != ROLE_LABELS["CONTROLLER"]
            or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
            or destination.exists()
        ):
            _stop("PUBLICATION_RELOCATION_NOT_DENIED")
        return {
            "point": point,
            "errno": report["errno"],
            "principal": facts,
            "root_device": after.st_dev,
            "root_inode": after.st_ino,
            "git_destination_absent": True,
            "pause": pause,
        }
    except Exception:
        if process.poll() is None:
            try:
                manager.kill(cgroup)
            except Exception:
                process.kill()
            try:
                process.wait(timeout=3)
            except Exception:
                pass
        raise


def _load_apparmor() -> dict[str, object]:
    policy_digest = _digest_file(APPARMOR_POLICY, 1 << 20)
    completed = subprocess.run(
        [APPARMOR_PARSER, "-r", "-W", str(APPARMOR_POLICY)],
        shell=False,
        close_fds=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
        cwd="/",
        timeout=20,
        check=False,
    )
    if completed.returncode != 0:
        _stop("M4_APPARMOR_LOAD_FAILED")
    profiles = Path("/sys/kernel/security/apparmor/policy/profiles")
    names = {path.name.rsplit(".", 1)[0] for path in profiles.iterdir()}
    expected = {ROLE_LABELS["OBSERVER"], ROLE_LABELS["PUBLISHER"]}
    if not expected.issubset(names):
        _stop("M4_APPARMOR_PROFILE_ABSENT")
    return {"digest": policy_digest, "profiles": sorted(expected)}


def _prepare_keys(profile: dict[str, object]) -> dict[str, RoleKey]:
    if KEY_ROOT.exists() or KEY_ROOT.is_symlink():
        _stop("M4_KEY_ROOT_REUSE_FORBIDDEN")
    # Search-only parent: each private directory remains 0700 and is owned by
    # its exact signer.  No peer can list or enter another role directory.
    KEY_ROOT.mkdir(mode=0o711)
    public_directory = KEY_ROOT / "public"
    public_directory.mkdir(mode=0o755)
    rows = profile["receipt_keys"]
    result: dict[str, RoleKey] = {}
    for role in ("M4_AUTHORITY", "OBSERVER", "PUBLISHER"):
        row = rows[role]
        owner = str(row["private_owner"])
        uid, gid = ROLE_IDS[owner]
        directory = KEY_ROOT / role.lower().replace("_", "-")
        directory.mkdir(mode=0o700)
        os.chown(directory, uid, gid)
        private_key = directory / "private.pem"
        public_key = directory / "public.pem"
        generated = subprocess.run(
            [OPENSSL, "genpkey", "-algorithm", "ED25519", "-out", str(private_key)],
            shell=False,
            close_fds=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            env={"LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
            cwd="/",
            timeout=5,
            check=False,
        )
        if generated.returncode != 0:
            _stop("M4_KEY_GENERATION_FAILED")
        os.chown(private_key, uid, gid)
        os.chmod(private_key, 0o600)
        exported = subprocess.run(
            [OPENSSL, "pkey", "-in", str(private_key), "-pubout", "-out", str(public_key)],
            shell=False,
            close_fds=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            env={"LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
            cwd="/",
            timeout=5,
            check=False,
        )
        if exported.returncode != 0:
            _stop("M4_PUBLIC_KEY_EXPORT_FAILED")
        os.chown(public_key, 0, 0)
        os.chmod(public_key, 0o444)
        result[role] = RoleKey(role, row, directory)
        public_copy = public_directory / (role.lower().replace("_", "-") + ".pem")
        _write_exact(public_copy, _read_regular(public_key, 4096), 0o444)
    return result


def _prepare_supply_key(profile: dict[str, object]) -> dict[str, object]:
    row = profile["supply_trust"]
    directory = SUPPLY_KEY_ROOT
    if directory.exists() or directory.is_symlink():
        _stop("M4_SUPPLY_KEY_ROOT_REUSE_FORBIDDEN")
    directory.mkdir(mode=0o700)
    private_key = directory / "private.pem"
    public_key = directory / "public.pem"
    state = directory / "state.json"
    generated = subprocess.run(
        [OPENSSL, "genpkey", "-algorithm", "ED25519", "-out", str(private_key)],
        shell=False,
        close_fds=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        env={"LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
        cwd="/",
        timeout=5,
        check=False,
    )
    if generated.returncode != 0:
        _stop("M4_SUPPLY_KEY_GENERATION_FAILED")
    os.chown(private_key, 0, 0)
    os.chmod(private_key, 0o600)
    exported = subprocess.run(
        [OPENSSL, "pkey", "-in", str(private_key), "-pubout", "-out", str(public_key)],
        shell=False,
        close_fds=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        env={"LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
        cwd="/",
        timeout=5,
        check=False,
    )
    if exported.returncode != 0:
        _stop("M4_SUPPLY_PUBLIC_KEY_EXPORT_FAILED")
    os.chown(public_key, 0, 0)
    os.chmod(public_key, 0o444)
    state_value = {
        "key_id": row["key_id"],
        "revocation_epoch": 0,
        "revoked": False,
        "rollback_floor": 1,
    }
    _write_exact(state, _canonical(state_value), 0o444)
    return {
        "directory": str(directory),
        "private_key": str(private_key),
        "public_key": str(public_key),
        "public_key_digest": _digest_file(public_key, 4096),
        "state": str(state),
        "trust_root_id": row["trust_root_id"],
        "signer_id": row["signer_id"],
        "key_id": row["key_id"],
    }


def _complete_post_v2_diagnostic(
    request: dict[str, object],
    keys: dict[str, RoleKey],
    supply: dict[str, object],
    runtime_trust: dict[str, object],
) -> NoReturn:
    contract, contract_digest = _post_v2_diagnostic_request_contract(request)
    if KEY_ADMISSION.exists() or KEY_ADMISSION.is_symlink():
        _stop("M4_POST_V2_DIAGNOSTIC_ADMISSION_FORBIDDEN")
    ready = {
        "ready_version": "2.1.0",
        "mode": POST_V2_DIAGNOSTIC_MODE,
        "non_authorizing": True,
        "diagnostic_contract": contract,
        "diagnostic_contract_digest": contract_digest,
        "contract_core_digest": contract["contract_core_digest"],
        "receipt_public_key_digests": {
            name: key.public_key_digest for name, key in keys.items()
        },
        "supply_public_key_digest": supply["public_key_digest"],
        "runtime_trust_digest": _digest_bytes(_canonical(runtime_trust)),
    }
    _write_exact(RUNTIME / "key-ready.json", _canonical(ready), 0o444)
    _diagnostic_stage("KEY_READY_WRITTEN")
    _stop("M4_POST_V2_DIAGNOSTIC_COMPLETE")


def _await_key_admission(
    request: dict[str, object], keys: dict[str, RoleKey], supply: dict[str, object],
    runtime_trust: dict[str, object],
) -> dict[str, object]:
    key_digests = {name: key.public_key_digest for name, key in keys.items()}
    runtime_trust_digest = _digest_bytes(_canonical(runtime_trust))
    request_mode = _validate_launch_request(request)
    if request_mode in {"QUALIFICATION", ONE_USE_QUALIFICATION_CONTRACT_KIND}:
        contract, contract_digest = _qualification_request_contract(request)
        core = contract["contract_core"]
        ready = {
            "ready_version": core["contract_version"],
            "candidate": core["candidate"],
            "environment": contract["environment_digest"],
            "attempt": core["attempt"],
            "qualification_contract": contract,
            "qualification_contract_digest": contract_digest,
            "contract_core_digest": contract["contract_core_digest"],
            "receipt_public_key_digests": key_digests,
            "supply_public_key_digest": supply["public_key_digest"],
            "runtime_trust_digest": runtime_trust_digest,
        }
    else:
        ready = {
            "ready_version": "1.0.0",
            "candidate": request["candidate"],
            "environment": request["environment"],
            "attempt": request["attempt"],
            "receipt_public_key_digests": key_digests,
            "supply_public_key_digest": supply["public_key_digest"],
            "runtime_trust_digest": runtime_trust_digest,
        }
    _write_exact(RUNTIME / "key-ready.json", _canonical(ready), 0o444)
    _diagnostic_stage("KEY_READY_WRITTEN")
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        if KEY_ADMISSION.is_file() and not KEY_ADMISSION.is_symlink():
            return _key_admission(
                request,
                keys,
                str(supply["public_key_digest"]),
                runtime_trust_digest,
            )
        time.sleep(0.1)
    _stop("KEY_ADMISSION_REQUIRED")


def _write_runtime_trust(
    profile: dict[str, object], keys: dict[str, RoleKey], supply: dict[str, object]
) -> dict[str, object]:
    public_directory = KEY_ROOT / "public"
    routes = {
        name: {
            "verifier_id": key.verifier_id,
            "issuer_id": key.issuer_id,
            "key_id": key.key_id,
            "public_key_path": str(
                public_directory / (name.lower().replace("_", "-") + ".pem")
            ),
            "public_key_digest": key.public_key_digest,
        }
        for name, key in keys.items()
    }
    value = {
        "trust_version": "1.0.0",
        "profile_digest": _digest_bytes(_canonical(profile)),
        "verifier_code_path": str(VERIFIER_CODE),
        "verifier_code_digest": _digest_file(VERIFIER_CODE, 1 << 20),
        "libcrypto_path": LIBCRYPTO,
        "libcrypto_digest": _digest_file(
            Path(LIBCRYPTO).resolve(strict=True), 16 << 20
        ),
        "m4_routes": routes,
        "supply": {
            "verifier_id": "harness-m3-external-verifier/v1",
            "issuer_id": supply["signer_id"],
            "key_id": supply["key_id"],
            "public_key_path": supply["public_key"],
            "public_key_digest": supply["public_key_digest"],
        },
        "revocation_epoch": 0,
        "fencing_epoch": 1,
    }
    _write_exact(RUNTIME_TRUST, _canonical(value), 0o444)
    return value


def _configure_m3_supply_trust(
    m3: object, supply: dict[str, object]
) -> tuple[dict[str, object], object, object, bytes]:
    """Compile the exact L0 profile after the host has pinned its VM key."""

    raw_value = _strict_bytes(_read_regular(L0_PROFILE, 1 << 20), 1 << 20)
    if type(raw_value) is not dict:
        _stop("L0_PROFILE_MALFORMED")
    raw = json.loads(json.dumps(raw_value))
    bindings = raw.get("measurement_bindings")
    if type(bindings) is not dict:
        _stop("L0_PROFILE_MALFORMED")
    bindings["verifier_public_key_digest"] = supply["public_key_digest"]
    # The runtime-generated profile differs from the committed template only
    # by the public key already pinned in the outer attempt ledger.
    template = json.loads(json.dumps(raw))
    template["measurement_bindings"]["verifier_public_key_digest"] = raw_value[
        "measurement_bindings"
    ]["verifier_public_key_digest"]
    if template != raw_value:
        _stop("L0_PROFILE_TEMPLATE_MUTATION")
    m3.ATTESTOR = Path(str(supply["directory"]))
    m3.PRIVATE_KEY = Path(str(supply["private_key"]))
    m3.PUBLIC_KEY = Path(str(supply["public_key"]))
    m3.ATTESTOR_STATE = Path(str(supply["state"]))
    m3.PUBLIC_KEY_DIGEST = str(supply["public_key_digest"])
    m3.TRUST_ROOT_ID = str(supply["trust_root_id"])
    m3.SIGNER_ID = str(supply["signer_id"])
    m3.KEY_ID = str(supply["key_id"])
    m3.VERIFIER_CODE_DIGEST = _digest_file(VERIFIER_CODE, 1 << 20)
    m3.LIBCRYPTO_DIGEST = _digest_file(
        Path(LIBCRYPTO).resolve(strict=True), 16 << 20
    )
    _, l0, _, _, _ = _load_project()
    compiled = l0.compile_profile(raw)
    if compiled.outcome is not l0.L0Outcome.COMPILED_DRAFT or compiled.profile is None:
        _stop("L0_DYNAMIC_PROFILE_COMPILE_FAILED")
    preflight = l0.host_preflight(raw)
    if preflight.outcome is not l0.L0Outcome.READY or preflight.measurement is None:
        if not isinstance(preflight.reason, l0.L0Reason):
            _stop(None)
        _stop("L0_DYNAMIC_HOST_PREFLIGHT_FAILED_" + preflight.reason.value)
    seccomp_raw = _strict_bytes(_read_regular(SOURCE / "profiles/l0-lx-a-seccomp.json", 1 << 20))
    if type(seccomp_raw) is not dict:
        _stop("L0_SECCOMP_PROFILE_MALFORMED")
    seccomp = l0._compile_seccomp_bpf(seccomp_raw)
    if bindings.get("seccomp_profile_digest") != _digest_bytes(seccomp):
        _stop("L0_SECCOMP_BINDING_MISMATCH")
    return raw, compiled.profile, preflight.measurement, seccomp


def _configure_m3_m4_roles(m3: object) -> None:
    m3.ROLE_IDS.update(M4_NAMESPACE_ROLE_IDS)
    m3.SUBORDINATE_IDS.update(M4_SUBORDINATE_IDS)
    m3.PROFILE_LABELS.update(
        {role: ROLE_LABELS[role] for role in M4_NAMESPACE_ROLE_IDS}
    )


def _copy_into_rootfs(
    m3: object,
    source: Path,
    root: Path,
    target: Path,
    mode: int,
) -> dict[str, object]:
    absolute = root / target.relative_to("/")
    parent = absolute.parent
    while parent != root.parent:
        if parent.exists():
            os.chmod(parent, 0o755)
        parent = parent.parent
    return m3._copy_regular(source, absolute, mode)


def _materialize_m4_role_rootfs(
    m3: object,
    role: str,
    role_input: dict[str, object],
    instance: str,
) -> tuple[Path, dict[str, object]]:
    if role not in M4_NAMESPACE_ROLE_IDS or type(role_input) is not dict:
        _stop("M4_ROLE_ROOTFS_INPUT_MALFORMED")
    encoded = _canonical(role_input)
    root, record = m3._materialize_rootfs(
        "EXECUTOR",
        Path(__file__).resolve().read_bytes(),
        "m4-" + instance,
        executor_input=encoded,
    )
    os.chmod(root, 0o755)
    input_directory = root / "inputs"
    os.chmod(input_directory, 0o755)
    os.rename(input_directory / "stage.json", root / ROLE_INPUT.relative_to("/"))
    opened = list(record["opened"])

    source_target = root / SOURCE.relative_to("/") / "src/harness_product"
    source_target.mkdir(parents=True, mode=0o755, exist_ok=True)
    for source in sorted((SOURCE / "src/harness_product").glob("*.py")):
        opened.append(
            _copy_into_rootfs(
                m3,
                source,
                root,
                SOURCE / "src/harness_product" / source.name,
                0o444,
            )
        )
    opened.append(
        _copy_into_rootfs(m3, RUNTIME_TRUST, root, RUNTIME_TRUST, 0o444)
    )
    for source in sorted((KEY_ROOT / "public").glob("*.pem")):
        opened.append(
            _copy_into_rootfs(
                m3,
                source,
                root,
                KEY_ROOT / "public" / source.name,
                0o444,
            )
        )
    opened.append(
        _copy_into_rootfs(
            m3,
            SUPPLY_KEY_ROOT / "public.pem",
            root,
            SUPPLY_KEY_ROOT / "public.pem",
            0o444,
        )
    )
    key_root: Path | None = None
    if role in {"OBSERVER", "PUBLISHER"}:
        key_directory = KEY_ROOT / role.lower()
        for name, mode in (("private.pem", 0o400), ("public.pem", 0o444)):
            target = KEY_ROOT / role.lower() / name
            opened.append(
                _copy_into_rootfs(
                    m3,
                    key_directory / name,
                    root,
                    target,
                    mode,
                )
            )
        private = root / (KEY_ROOT / role.lower() / "private.pem").relative_to("/")
        os.chown(private, *ROLE_IDS[role])
        key_root = private.parent
        os.chown(key_root, *ROLE_IDS[role])
        os.chmod(key_root, 0o500)
    if role == "PUBLISHER":
        for path in (PUBLICATION_PARENT, PUBLICATION_ROOT):
            target = root / path.relative_to("/")
            target.mkdir(parents=True, mode=0o755, exist_ok=True)
    for path in sorted(root.rglob("*"), reverse=True):
        if path.is_dir():
            os.chmod(path, 0o555)
        elif path.name != "private.pem":
            os.chmod(path, stat.S_IMODE(os.stat(path).st_mode) & ~0o222)
    if key_root is not None:
        os.chmod(key_root, 0o500)
    os.chmod(root, 0o555)
    return root, {
        **record,
        "opened": opened,
        "input_digest": _digest_bytes(encoded),
        "tree_digest": m3._tree_digest(root),
        "role": role,
    }


def _m4_role_seccomp_programs(m3: object) -> dict[str, bytes]:
    raw = _strict_file(
        SOURCE / "profiles/l0-lx-a-seccomp.json",
        frozenset({"architecture", "default_action", "format_version", "syscalls"}),
        1 << 20,
    )
    rows = raw.get("syscalls")
    if (
        raw.get("architecture") != "AUDIT_ARCH_X86_64"
        or raw.get("default_action") != "ERRNO_EPERM"
        or raw.get("format_version") != "1.0.0"
        or type(rows) is not list
        or any(type(item) is not int or item < 0 for item in rows)
    ):
        _stop("M4_SECCOMP_PROFILE_MALFORMED")
    base = tuple(rows)
    programs: dict[str, bytes] = {}
    for role, additions in M4_ROLE_SECCOMP_ADDITIONS.items():
        if any(item in base for item in additions):
            _stop("M4_SECCOMP_PROFILE_MALFORMED")
        programs[role] = m3._compile_seccomp_rows(
            tuple(sorted((*base, *additions)))
        )
    return programs


def _launch_m4_role(
    *,
    m3: object,
    manager: object,
    role: str,
    role_input: dict[str, object],
    instance: str,
    seccomp_program: bytes,
    stdin_descriptor: int,
    stdout_descriptor: int,
    stderr_descriptor: int,
    mounts: tuple[tuple[str, int, str], ...] = (),
) -> dict[str, object]:
    if (
        role not in M4_NAMESPACE_ROLE_IDS
        or type(seccomp_program) is not bytes
        or not seccomp_program
        or type(stdin_descriptor) is not int
        or stdin_descriptor < 0
        or type(stdout_descriptor) is not int
        or stdout_descriptor not in {subprocess.PIPE} and stdout_descriptor < 0
        or type(stderr_descriptor) is not int
        or stderr_descriptor not in {subprocess.DEVNULL} and stderr_descriptor < 0
        or any(
            type(row) is not tuple
            or len(row) != 3
            or row[0] not in {"--bind-fd", "--ro-bind-fd"}
            or type(row[1]) is not int
            or row[1] < 0
            or type(row[2]) is not str
            or not row[2].startswith("/")
            for row in mounts
        )
    ):
        _stop("M4_ROLE_LAUNCH_MALFORMED")
    _configure_m3_m4_roles(m3)
    owned_descriptors: set[int] = set()
    cgroup: Path | None = None
    process: subprocess.Popen[bytes] | None = None

    def own(descriptor: int) -> int:
        owned_descriptors.add(descriptor)
        return descriptor

    def close_owned(descriptor: int) -> None:
        if descriptor in owned_descriptors:
            owned_descriptors.remove(descriptor)
            try:
                os.close(descriptor)
            except OSError:
                pass

    try:
        namespace_fd, namespace_record = m3._create_user_namespace(role)
        own(namespace_fd)
        m3._verify_user_namespace_fd(
            namespace_fd, namespace_record, require_nested=True
        )
        root, root_record = _materialize_m4_role_rootfs(
            m3,
            role,
            role_input,
            instance,
        )
        cgroup = manager.create("m4-" + role.lower() + "-" + instance)
        outer_read, outer_write = os.pipe2(os.O_CLOEXEC)
        own(outer_read)
        own(outer_write)
        status_read, status_write = os.pipe2(os.O_CLOEXEC)
        own(status_read)
        own(status_write)
        seccomp_descriptor = own(m3._seccomp_memfd(seccomp_program))
        root_descriptor = own(
            os.open(
                root,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
        )
        outer_high = own(m3._duplicate_high(outer_read))
        mount_rows: list[tuple[str, int, str]] = []
        mount_descriptors: list[int] = []
        for kind, descriptor, target in mounts:
            duplicate = own(m3._duplicate_high(descriptor))
            mount_descriptors.append(duplicate)
            mount_rows.append((kind, duplicate, target))
        argv = [
            BWRAP,
            "--userns", str(namespace_fd),
            "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-net",
            "--unshare-cgroup", "--assert-userns-disabled",
            "--hostname", "harness-m4-" + role.lower(),
            "--new-session", "--die-with-parent", "--clearenv", "--cap-drop", "ALL",
            "--block-fd", str(outer_high), "--json-status-fd", str(status_write),
            "--ro-bind-fd", str(root_descriptor), "/",
        ]
        for kind, descriptor, target in mount_rows:
            argv.extend((kind, str(descriptor), target))
        argv.extend(
            (
                "--proc", "/proc", "--seccomp", str(seccomp_descriptor),
                "--chdir", "/workspace", "--", AA_EXEC, "--profile",
                ROLE_LABELS[role], "--", PYTHON, "-I", "-S",
                "/usr/lib/harness/worker-tool", "--internal-role", role.lower(),
            )
        )
        argv = list(m3._validate_runtime_argv(argv, namespace_fd, prepared=True))
        pass_fds = (
            namespace_fd,
            seccomp_descriptor,
            root_descriptor,
            outer_high,
            status_write,
            *mount_descriptors,
        )
        process = subprocess.Popen(
            argv,
            shell=False,
            close_fds=True,
            pass_fds=pass_fds,
            stdin=stdin_descriptor,
            stdout=stdout_descriptor,
            stderr=stderr_descriptor,
            env={},
            cwd="/",
            preexec_fn=m3._preexec(
                role,
                (),
                32,
                cgroup,
                user_namespace_fd=namespace_fd,
            ),
        )
        for descriptor in (
            namespace_fd,
            seccomp_descriptor,
            root_descriptor,
            outer_read,
            outer_high,
            status_write,
            *mount_descriptors,
        ):
            close_owned(descriptor)
        limits = {
            name: cgroup.joinpath(name).read_text(encoding="ascii").strip()
            for name in manager.limits
        }
        if (
            str(process.pid)
            not in cgroup.joinpath("cgroup.procs").read_text(encoding="ascii").split()
            or limits != manager.limits
        ):
            _stop("M4_ROLE_CGROUP_ATTACH_FAILED")
        if os.write(outer_write, b"1") != 1:
            _stop("M4_ROLE_OUTER_GATE_RELEASE_FAILED")
        close_owned(outer_write)
        confined_pid, facts = m3._find_confined_process(
            cgroup,
            ROLE_LABELS[role],
            namespace_record,
            expected_inventory=(0, 1, 2),
            expected_tool_arguments=(b"--internal-role", role.lower().encode("ascii")),
        )
        status_value = m3._status_fields(confined_pid)
        if (
            status_value.get("Uid", "").split() != [str(ROLE_IDS[role][0])] * 4
            or status_value.get("Gid", "").split() != [str(ROLE_IDS[role][1])] * 4
            or status_value.get("CapAmb") != "0000000000000000"
        ):
            _stop("M4_ROLE_IDENTITY_MISMATCH")
        result = {
            "process": process,
            "process_id": confined_pid,
            "cgroup": cgroup,
            "status_read": status_read,
            "facts": {
                **facts,
                "role": role,
                "launcher_uid": ROLE_IDS[role][0],
                "launcher_gid": ROLE_IDS[role][1],
                "process_id": confined_pid,
                "process_session": os.getsid(confined_pid),
                "namespace_uid": M4_NAMESPACE_ROLE_IDS[role][2],
                "namespace_gid": M4_NAMESPACE_ROLE_IDS[role][3],
                "user_namespace": namespace_record,
                "cgroup": str(cgroup).removeprefix("/sys/fs/cgroup"),
                "cgroup_limits": limits,
                "argv": argv,
                "argv_digest": _digest_bytes(_canonical(argv)),
                "rootfs": root_record,
                "seccomp_digest": _digest_bytes(seccomp_program),
            },
        }
        owned_descriptors.remove(status_read)
        return result
    except BaseException as original_error:
        for descriptor in tuple(owned_descriptors):
            close_owned(descriptor)
        cleanup_error: BaseException | None = None
        if cgroup is not None:
            try:
                manager.kill(cgroup)
            except BaseException as error:
                cleanup_error = error
        if process is not None:
            try:
                process.wait(timeout=3)
            except BaseException as error:
                if cleanup_error is None:
                    cleanup_error = error
            if process.stdout is not None:
                process.stdout.close()
        if cleanup_error is not None:
            raise QualificationStop("M4_ROLE_CLEANUP_FAILED") from cleanup_error
        del original_error
        raise


def _finish_m4_role(
    m3: object,
    manager: object,
    launched: dict[str, object],
    *,
    timeout: float,
    require_success: bool,
) -> dict[str, object]:
    process = launched.get("process")
    cgroup = launched.get("cgroup")
    status_read = launched.get("status_read")
    if (
        not isinstance(process, subprocess.Popen)
        or not isinstance(cgroup, Path)
        or type(status_read) is not int
        or status_read < 0
    ):
        _stop("M4_ROLE_RESULT_MALFORMED")
    try:
        if not require_success:
            manager.kill(cgroup)
        return_code, status_digest = m3._complete_role(
            process,
            status_read,
            cgroup,
            timeout=timeout,
        )
    finally:
        launched["status_read"] = -1
        manager.kill(cgroup)
    if require_success and return_code != 0:
        _stop("M4_ROLE_FAILED")
    launched["return_code"] = return_code
    launched["status_digest"] = status_digest
    return launched


def _abort_m4_role(m3: object, manager: object, launched: object) -> None:
    if type(launched) is not dict:
        return
    process = launched.get("process")
    cgroup = launched.get("cgroup")
    status_read = launched.get("status_read")
    if not isinstance(process, subprocess.Popen) or not isinstance(cgroup, Path):
        return
    try:
        manager.kill(cgroup)
    except Exception:
        pass
    try:
        if type(status_read) is int and status_read >= 0:
            m3._complete_role(process, status_read, cgroup, timeout=0)
            launched["status_read"] = -1
        else:
            process.wait(timeout=3)
    except Exception:
        pass
    if process.stdout is not None:
        process.stdout.close()


def _executor_launcher(
    profile: object,
    claim: object,
    supply: object,
    root_descriptor: int,
    stage_request: dict[str, object],
    stage_execution_grant: object,
    claim_verifier_factory: object,
    supply_verifier_factory: object,
    m4_verifier_factory: object,
    *,
    m3: object,
    manager: object,
    raw_l0_profile: dict[str, object],
    seccomp_program: bytes,
    facts_sink: list[dict[str, object]] | None = None,
) -> object:
    durable, l0, m4, _, _ = _load_project()
    if (
        type(stage_execution_grant) is not durable.StageExecutionGrant
        or type(claim) is not durable.DispatchClaim
        or type(supply) is not l0.SupplyVerification
        or type(raw_l0_profile) is not dict
        or type(stage_request) is not dict
        or type(root_descriptor) is not int
        or root_descriptor < 0
        or not all(
            callable(factory)
            for factory in (
                claim_verifier_factory,
                supply_verifier_factory,
                m4_verifier_factory,
            )
        )
    ):
        _stop("EXECUTOR_LAUNCH_INPUT_MALFORMED")
    start_read, start_write = os.pipe2(os.O_CLOEXEC)
    launched: dict[str, object] | None = None
    try:
        launched = _launch_m4_role(
            m3=m3,
            manager=manager,
            role="EXECUTOR",
            role_input={
                "input_version": "1.0.0",
                "l0_profile": raw_l0_profile,
                "claim": asdict(claim),
                "supply": asdict(supply),
                "stage_request": stage_request,
                "stage_execution_grant": asdict(stage_execution_grant),
            },
            instance="stage-1",
            seccomp_program=seccomp_program,
            stdin_descriptor=start_read,
            stdout_descriptor=subprocess.PIPE,
            stderr_descriptor=root_descriptor,
            mounts=(("--bind-fd", root_descriptor, "/staging"),),
        )
        os.close(start_read)
        start_read = -1
        if os.write(start_write, START_PACKET) != len(START_PACKET):
            _stop("EXECUTOR_START_GATE_FAILED")
        os.close(start_write)
        start_write = -1
        process = launched["process"]
        if not isinstance(process, subprocess.Popen) or process.stdout is None:
            _stop("EXECUTOR_REPORT_CHANNEL_ABSENT")
        report = _strict_bytes(_read_line(process.stdout.fileno(), MAX_REPORT, 10))
        expected = {
            "outcome", "reason", "record", "pid", "session",
            "verifier_instances", "independent_cryptographic_implementations",
        }
        if (
            type(report) is not dict
            or frozenset(report) != expected
            or report["outcome"] != "STAGED"
            or report["reason"] != "STAGED"
            or report["verifier_instances"] != 3
            or report["independent_cryptographic_implementations"] is not False
            or type(report["record"]) is not dict
            or frozenset(report["record"])
            != frozenset(l0.StageRecord.__dataclass_fields__)
            or report["pid"] != launched["process_id"]
            or report["session"] != launched["facts"]["process_session"]
        ):
            _stop("EXECUTOR_REPORT_MALFORMED")
        record = _stage_record_from_data(report["record"])
        if (
            record.transaction_id != claim.transaction_id
            or record.claim_digest != claim.claim_digest
        ):
            _stop("EXECUTOR_STAGE_RECORD_MISMATCH")
        _finish_m4_role(
            m3,
            manager,
            launched,
            timeout=5,
            require_success=True,
        )
        if facts_sink is not None:
            facts_sink.append(dict(launched["facts"]))
        process.stdout.close()
        return m4.RuntimeStageExecution(
            record,
            launched["process_id"],
            launched["facts"]["process_session"],
        )
    except Exception:
        _abort_m4_role(m3, manager, launched)
        raise
    finally:
        for descriptor in (start_read, start_write):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass


def _observer_launcher(
    profile: object,
    snapshot_descriptor: int,
    snapshot: object,
    receipt_body: dict[str, object],
    *,
    m3: object,
    manager: object,
    raw_l0_profile: dict[str, object],
    m4_profile: dict[str, object],
    seccomp_program: bytes,
    facts_sink: list[dict[str, object]] | None = None,
) -> object:
    durable, _, m4, _, _ = _load_project()
    if (
        type(snapshot) is not m4.M4Snapshot
        or type(receipt_body) is not dict
        or type(raw_l0_profile) is not dict
        or type(m4_profile) is not dict
    ):
        _stop("OBSERVER_LAUNCH_INPUT_MALFORMED")
    trusted_duplicate = -1
    snapshot_read = -1
    start_read, start_write = os.pipe2(os.O_CLOEXEC)
    launched: dict[str, object] | None = None
    try:
        trusted_duplicate = fcntl.fcntl(
            snapshot_descriptor,
            fcntl.F_DUPFD_CLOEXEC,
            3,
        )
        original = os.fstat(trusted_duplicate)
        if (
            original.st_dev != snapshot.device
            or original.st_ino != snapshot.inode
            or original.st_size != snapshot.size
            or fcntl.fcntl(trusted_duplicate, fcntl.F_GET_SEALS)
            != (
                fcntl.F_SEAL_GROW
                | fcntl.F_SEAL_SHRINK
                | fcntl.F_SEAL_WRITE
                | fcntl.F_SEAL_SEAL
            )
        ):
            _stop("OBSERVER_SNAPSHOT_MISMATCH")
        snapshot_read = os.open(
            f"/proc/self/fd/{trusted_duplicate}",
            os.O_RDONLY | os.O_CLOEXEC,
        )
        read_info = os.fstat(snapshot_read)
        if (
            (read_info.st_dev, read_info.st_ino, read_info.st_size)
            != (original.st_dev, original.st_ino, original.st_size)
            or fcntl.fcntl(snapshot_read, fcntl.F_GETFL) & os.O_ACCMODE
            != os.O_RDONLY
        ):
            _stop("OBSERVER_SNAPSHOT_MISMATCH")
        os.close(trusted_duplicate)
        trusted_duplicate = -1
        launched = _launch_m4_role(
            m3=m3,
            manager=manager,
            role="OBSERVER",
            role_input={
                "input_version": "1.0.0",
                "l0_profile": raw_l0_profile,
                "m4_profile": m4_profile,
                "snapshot": asdict(snapshot),
                "receipt_body": receipt_body,
            },
            instance="postcheck-1",
            seccomp_program=seccomp_program,
            stdin_descriptor=snapshot_read,
            stdout_descriptor=subprocess.PIPE,
            stderr_descriptor=start_read,
        )
        os.close(snapshot_read)
        snapshot_read = -1
        os.close(start_read)
        start_read = -1
        if os.write(start_write, START_PACKET) != len(START_PACKET):
            _stop("OBSERVER_START_GATE_FAILED")
        os.close(start_write)
        start_write = -1
        process = launched["process"]
        if not isinstance(process, subprocess.Popen) or process.stdout is None:
            _stop("OBSERVER_REPORT_CHANNEL_ABSENT")
        report = _strict_bytes(_read_line(process.stdout.fileno(), MAX_REPORT, 10))
        measurement_keys = {
            "pid", "session", "uid", "gid", "device", "inode", "size",
            "digest", "seals", "read_only", "write_denied", "truncate_denied",
        }
        if (
            type(report) is not dict
            or frozenset(report)
            != {"kind", "receipt", "verification_source", "measurement"}
            or report["kind"] != "OBSERVER_RECEIPT"
            or type(report["receipt"]) is not dict
            or type(report["verification_source"]) is not dict
            or frozenset(report["verification_source"])
            != {"verifier_id", "issuer_id", "key_id", "proof"}
            or type(report["measurement"]) is not dict
            or frozenset(report["measurement"]) != measurement_keys
        ):
            _stop("OBSERVER_REPORT_MALFORMED")
        measurement = report["measurement"]
        facts = launched["facts"]
        if (
            measurement["pid"] != launched["process_id"]
            or measurement["session"] != facts["process_session"]
            or measurement["uid"] != ROLE_IDS["OBSERVER"][0]
            or measurement["gid"] != ROLE_IDS["OBSERVER"][1]
            or measurement["device"] != snapshot.device
            or measurement["inode"] != snapshot.inode
            or measurement["size"] != snapshot.size
            or measurement["digest"] != snapshot.digest
            or measurement["seals"]
            != (
                fcntl.F_SEAL_GROW
                | fcntl.F_SEAL_SHRINK
                | fcntl.F_SEAL_WRITE
                | fcntl.F_SEAL_SEAL
            )
            or measurement["read_only"] is not True
            or measurement["write_denied"] is not True
            or measurement["truncate_denied"] is not True
        ):
            _stop("OBSERVER_REPORT_MISMATCH")
        verification = _verification_record(
            report["receipt"], report["verification_source"]
        )
        if ConfiguredVerifierRouter().verify(
            _canonical(report["receipt"]),
            _canonical(verification),
            str(report["receipt"].get("observed_at")),
        ).status is not durable.VerificationStatus.VERIFIED:
            _stop("OBSERVER_RECEIPT_SIGNATURE_REJECTED")
        _finish_m4_role(
            m3,
            manager,
            launched,
            timeout=5,
            require_success=True,
        )
        if facts_sink is not None:
            facts_sink.append(dict(facts))
        process.stdout.close()
        return m4.RuntimeObserverReceipt(
            report["receipt"],
            report["verification_source"],
            launched["process_id"],
            facts["process_session"],
            ROLE_IDS["OBSERVER"][0],
            ROLE_IDS["OBSERVER"][1],
        )
    except Exception:
        _abort_m4_role(m3, manager, launched)
        raise
    finally:
        for descriptor in (
            trusted_duplicate,
            snapshot_read,
            start_read,
            start_write,
        ):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass


def _publication_descriptor_identity(
    parent_descriptor: int,
    root_descriptor: int,
) -> dict[str, object]:
    if any(type(value) is not int or value < 0 for value in (parent_descriptor, root_descriptor)):
        _stop("PUBLICATION_DESCRIPTOR_MALFORMED")
    parent = os.fstat(parent_descriptor)
    root = os.fstat(root_descriptor)
    try:
        linked = os.stat(
            PUBLICATION_ROOT.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        parent_path = os.lstat(PUBLICATION_PARENT)
        root_path = os.lstat(PUBLICATION_ROOT)
    except OSError as error:
        raise QualificationStop("PUBLICATION_DESCRIPTOR_MISMATCH") from error
    if (
        not stat.S_ISDIR(parent.st_mode)
        or not stat.S_ISDIR(root.st_mode)
        or not stat.S_ISDIR(linked.st_mode)
        or not stat.S_ISDIR(parent_path.st_mode)
        or not stat.S_ISDIR(root_path.st_mode)
        or (parent.st_dev, parent.st_ino)
        != (parent_path.st_dev, parent_path.st_ino)
        or (root.st_dev, root.st_ino)
        != (root_path.st_dev, root_path.st_ino)
        or (root.st_dev, root.st_ino) != (linked.st_dev, linked.st_ino)
        or PUBLICATION_ROOT.parent != PUBLICATION_PARENT
        or PUBLICATION_ROOT.name != "publication"
    ):
        _stop("PUBLICATION_DESCRIPTOR_MISMATCH")
    return {
        "parent_device": parent.st_dev,
        "parent_inode": parent.st_ino,
        "root_device": root.st_dev,
        "root_inode": root.st_ino,
        "basename": PUBLICATION_ROOT.name,
    }


def _start_publisher_session(
    *,
    m3: object,
    manager: object,
    raw_l0_profile: dict[str, object],
    m4_profile: dict[str, object],
    seccomp_program: bytes,
    publication_parent_descriptor: int,
    publication_root_descriptor: int,
    denial_probe: object,
) -> tuple[PublisherSession, dict[str, object]]:
    if (
        type(raw_l0_profile) is not dict
        or type(m4_profile) is not dict
        or not callable(denial_probe)
    ):
        _stop("PUBLISHER_LAUNCH_INPUT_MALFORMED")
    descriptor_identity = _publication_descriptor_identity(
        publication_parent_descriptor,
        publication_root_descriptor,
    )
    parent, child = _publisher_control_pair()
    launched: dict[str, object] | None = None
    session: PublisherSession | None = None
    try:
        publication = m4_profile.get("publication")
        target_path = publication.get("target") if type(publication) is dict else None
        if type(target_path) is not str:
            _stop("PUBLISHER_TARGET_MALFORMED")
        launched = _launch_m4_role(
            m3=m3,
            manager=manager,
            role="PUBLISHER",
            role_input={
                "input_version": "1.0.0",
                "l0_profile": raw_l0_profile,
                "m4_profile": m4_profile,
                "target": {
                    "canonical_path": target_path,
                    "descriptor_id": "m4-publication-target-1",
                    "root_id": "m4-publication-root-1",
                    "resolution_epoch": 1,
                },
            },
            instance="publisher-1",
            seccomp_program=seccomp_program,
            stdin_descriptor=child.fileno(),
            stdout_descriptor=subprocess.PIPE,
            stderr_descriptor=publication_root_descriptor,
            mounts=(
                (
                    "--ro-bind-fd",
                    publication_parent_descriptor,
                    str(PUBLICATION_PARENT),
                ),
                (
                    "--bind-fd",
                    publication_root_descriptor,
                    str(PUBLICATION_ROOT),
                ),
            ),
        )
        child.close()
        os.close(publication_parent_descriptor)
        publication_parent_descriptor = -1
        os.close(publication_root_descriptor)
        publication_root_descriptor = -1
        session = PublisherSession(
            process=launched["process"],
            connection=parent,
            manager=manager,
            m3=m3,
            cgroup=launched["cgroup"],
            status_read=launched["status_read"],
            facts=launched["facts"],
            denial_probe=denial_probe,
        )
        context = session.bootstrap()
        target_data = context["target_binding"].data()
        anchor_data = context["root_anchor"].data()
        if (
            target_data["canonical_path"] != target_path
            or target_data["descriptor_id"] != "m4-publication-target-1"
            or target_data["root_id"] != "m4-publication-root-1"
            or target_data["resolution_epoch"] != 1
            or anchor_data["root_path"] != str(PUBLICATION_ROOT)
            or anchor_data["basename"] != descriptor_identity["basename"]
            or anchor_data["ancestry"][-1]["device"]
            != descriptor_identity["root_device"]
            or anchor_data["ancestry"][-1]["inode"]
            != descriptor_identity["root_inode"]
        ):
            _stop("PUBLISHER_BOOTSTRAP_MISMATCH")
        return session, {
            **context,
            "executable_digests": {
                role: _digest_bytes(
                    _canonical(
                        {
                            "role": role,
                            "runner_code_digest": _digest_file(
                                Path(__file__).resolve(), 8 << 20
                            ),
                        }
                    )
                )
                for role in (
                    "WORKER", "CONTROLLER", "EXECUTOR", "OBSERVER", "PUBLISHER"
                )
            },
        }
    except Exception:
        if session is not None:
            try:
                session.close()
            except Exception:
                pass
        else:
            _abort_m4_role(m3, manager, launched)
            parent.close()
            child.close()
        raise
    finally:
        for descriptor in (
            publication_parent_descriptor,
            publication_root_descriptor,
        ):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass


def _publication_context(profile: object, root_descriptor: int) -> dict[str, object]:
    """Measure the exact publication target and its trusted physical anchor."""

    _, l0, _, publisher, _ = _load_project()
    resolved = l0.resolve_target(
        profile,
        root_descriptor,
        {
            "canonical_path": "/staging/artifact.txt",
            "descriptor_id": "m4-publication-target-1",
            "root_id": "m4-publication-root-1",
            "resolution_epoch": 1,
        },
    )
    if resolved.outcome is not l0.L0Outcome.RESOLVED or resolved.binding is None:
        _stop("M4_PUBLICATION_TARGET_UNRESOLVED")
    anchor = publisher._measure_publication_root(root_descriptor)
    code_digest = _digest_file(Path(__file__).resolve(), 8 << 20)
    executables = {
        role: _digest_bytes(
            _canonical({"role": role, "runner_code_digest": code_digest})
        )
        for role in ("WORKER", "CONTROLLER", "EXECUTOR", "OBSERVER", "PUBLISHER")
    }
    return {
        "target_binding": resolved.binding,
        "root_anchor": anchor,
        "executable_digests": executables,
    }


def _m4_authority_builder(
    runtime_profile: dict[str, object],
    publication: dict[str, object],
    controller: ControllerSession,
) -> object:
    """Return the one post-supply/pre-issue authority builder used by M3."""

    _, l0, _, publisher, _ = _load_project()
    if (
        frozenset(publication)
        != {"target_binding", "root_anchor", "executable_digests"}
        or type(publication["target_binding"]) is not l0.PathBinding
        or type(publication["root_anchor"]) is not publisher.PublicationRootAnchor
        or type(publication["executable_digests"]) is not dict
    ):
        _stop("M4_PUBLICATION_CONTEXT_MALFORMED")

    def build(
        *,
        profile: object,
        supply: object,
        staging: dict[str, object],
        request: dict[str, object],
        times: dict[str, str],
    ) -> dict[str, object]:
        durable, l0_module, _, publisher_module, _ = _load_project()
        roles = runtime_profile["roles"]
        if (
            type(roles) is not dict
            or type(staging) is not dict
            or type(staging.get("descriptor")) is not int
            or type(staging.get("root_id")) is not str
        ):
            _stop("M4_AUTHORITY_CONTEXT_MALFORMED")
        resolved = l0_module.resolve_target(
            profile,
            staging["descriptor"],
            {
                "canonical_path": "/staging/artifact.txt",
                "descriptor_id": "m4-stage-target-1",
                "root_id": staging["root_id"],
                "resolution_epoch": 1,
            },
        )
        if resolved.outcome is not l0_module.L0Outcome.RESOLVED or resolved.binding is None:
            _stop("M4_STAGING_TARGET_UNRESOLVED")
        subjects: dict[str, dict[str, object]] = {}
        executable_digests = publication["executable_digests"]
        for role in ("WORKER", "CONTROLLER", "EXECUTOR", "OBSERVER", "PUBLISHER"):
            row = roles[role]
            subjects[role] = {
                "principal_id": row["principal_id"],
                "session_id": (
                    supply.session_id if role == "WORKER" else row["session_id"]
                ),
                "uid": row["uid"],
                "gid": row["gid"],
                "security_label": row["security_label"],
                "credential_namespace": row["credential_namespace"],
                "namespace_id": row["namespace_id"],
                "executable_digest": executable_digests[role],
            }
        topology_body = {
            "topology_version": 1,
            "assurance_scope": EXPECTED_SCOPE,
            "topology_id": "m4-lx-a-topology-1",
            "observed_at": times["issued_at"],
            "expires_at": times["expires_at"],
            "profile_digest": profile.profile_digest,
            "placement_digest": supply.placement_digest,
            "session_id": supply.session_id,
            "revocation_epoch": supply.revocation_epoch,
            "fencing_epoch": supply.fencing_epoch,
            "staging_binding": resolved.binding.data(),
            "publication_target_binding": publication["target_binding"].data(),
            "publication_root_anchor": publication["root_anchor"].data(),
            "subjects": subjects,
            "sole_writer_principal": roles["PUBLISHER"]["principal_id"],
            "denied_writer_principals": sorted(
                roles[role]["principal_id"]
                for role in ("WORKER", "CONTROLLER", "EXECUTOR", "OBSERVER")
            ),
            "git_authority": "DENY",
            "transport": SEALED_FD_ONLY,
        }
        topology_raw = {
            **topology_body,
            "topology_digest": durable.canonical_digest(topology_body),
        }
        compiled = publisher_module.compile_topology(topology_raw)
        if (
            compiled.outcome is not publisher_module.PublisherOutcome.READY
            or compiled.topology is None
        ):
            _stop("M4_TOPOLOGY_COMPILE_FAILED")
        topology_source = controller.sign(
            _canonical(compiled.topology.data()), times["issued_at"], "M4_TOPOLOGY"
        )
        lineage = _digest_bytes(
            _canonical(
                {
                    "image_digest": m3_image_digest(),
                    "profile_digest": profile.profile_digest,
                    "placement_digest": supply.placement_digest,
                    "session_id": supply.session_id,
                }
            )
        )
        scope = durable.canonical_digest(
            {"kind": "PATH_EXACT", "value": "/staging/artifact.txt"}
        )
        contract_body: dict[str, object] = {
            "contract_version": "2.0.0",
            "authority_domain_id": "m4-disposable-local",
            "journal_lineage_id": "m4-journal-lineage-1",
            "root_contract_digest": _digest_bytes(
                _canonical({"root": "m4-lx-a", "topology": topology_raw["topology_digest"]})
            ),
            "parent_contract_digest": None,
            "lineage_root": lineage,
            "authority_digest": durable.canonical_digest(
                request["proposal"]["authority"]
            ),
            "target_authority_digest": topology_raw["topology_digest"],
            "profile_digest": profile.profile_digest,
            "operation_kind": "STAGEABLE_FILESYSTEM",
            "external_branch": "DENY",
            "max_iterations": 1,
            "joined_iteration": 0,
            "postcheck_required": True,
            "independent_observer_required": True,
            "budget_vector": [
                {
                    "name": "writes",
                    "unit": "FILES",
                    "scope_digest": scope,
                    "lineage_root": lineage,
                    "limit": 1,
                }
            ],
            "issued_at": times["issued_at"],
            "expires_at": times["expires_at"],
            "revocation_epoch": supply.revocation_epoch,
            "fencing_epoch": supply.fencing_epoch,
        }
        contract = {
            **contract_body,
            "contract_digest": durable.canonical_digest(contract_body),
        }
        return {
            "target_authority_digest": topology_raw["topology_digest"],
            "contract": contract,
            "budget_limit": 1,
            "context": {
                "topology": compiled.topology,
                "topology_verification": topology_source,
                "staging_binding": resolved.binding,
                "publication_target_binding": publication["target_binding"],
                "publication_root_anchor": publication["root_anchor"],
            },
        }

    return build


def m3_image_digest() -> str:
    """Keep the M3 lineage preimage byte-for-byte identical."""

    m3 = _load_m3()
    value = str(m3.IMAGE_DIGEST)
    if re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None:
        _stop("M3_IMAGE_DIGEST_MALFORMED")
    return value


def _existing_supply_key(profile: dict[str, object]) -> dict[str, object]:
    row = profile.get("supply_trust")
    if type(row) is not dict:
        _stop("M4_SUPPLY_TRUST_PROFILE_MISMATCH")
    directory = SUPPLY_KEY_ROOT
    private_key = directory / "private.pem"
    public_key = directory / "public.pem"
    state_path = directory / "state.json"
    try:
        directory_info = os.lstat(directory)
        private_info = os.lstat(private_key)
        public_info = os.lstat(public_key)
    except OSError as error:
        raise QualificationStop("M4_SUPPLY_KEY_ROOT_MISMATCH") from error
    state = _strict_file(
        state_path,
        frozenset({"key_id", "revocation_epoch", "revoked", "rollback_floor"}),
        4096,
    )
    if (
        not stat.S_ISDIR(directory_info.st_mode)
        or directory_info.st_uid != 0
        or directory_info.st_gid != 0
        or stat.S_IMODE(directory_info.st_mode) != 0o700
        or not stat.S_ISREG(private_info.st_mode)
        or private_info.st_uid != 0
        or private_info.st_gid != 0
        or stat.S_IMODE(private_info.st_mode) != 0o600
        or private_info.st_nlink != 1
        or not stat.S_ISREG(public_info.st_mode)
        or public_info.st_uid != 0
        or public_info.st_gid != 0
        or stat.S_IMODE(public_info.st_mode) != 0o444
        or public_info.st_nlink != 1
        or state
        != {
            "key_id": row["key_id"],
            "revocation_epoch": 0,
            "revoked": False,
            "rollback_floor": 1,
        }
    ):
        _stop("M4_SUPPLY_KEY_ROOT_MISMATCH")
    return {
        "directory": str(directory),
        "private_key": str(private_key),
        "public_key": str(public_key),
        "public_key_digest": _digest_file(public_key, 4096),
        "state": str(state_path),
        "trust_root_id": row["trust_root_id"],
        "signer_id": row["signer_id"],
        "key_id": row["key_id"],
    }


def _receipt_public_material() -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for role in ("M4_AUTHORITY", "OBSERVER", "PUBLISHER"):
        path = KEY_ROOT / "public" / (role.lower().replace("_", "-") + ".pem")
        raw = _read_regular(path, 4096)
        try:
            pem = raw.decode("ascii")
        except UnicodeDecodeError as error:
            raise QualificationStop("M4_PUBLIC_KEY_MALFORMED") from error
        result[role] = {"digest": _digest_bytes(raw), "pem": pem}
    return result


def _execution_survival(state: dict[str, object]) -> dict[str, object]:
    process_ids: set[int] = set()
    cgroups: set[str] = set()

    def visit(value: object) -> None:
        if type(value) is dict:
            for key, item in value.items():
                if key in {"pid", "process_id"} and type(item) is int and item > 1:
                    process_ids.add(item)
                elif key == "cgroup" and type(item) is str and item.startswith("/"):
                    cgroups.add(item)
                visit(item)
        elif type(value) is list:
            for item in value:
                visit(item)

    visit(state["execution"])
    live_processes = sorted(pid for pid in process_ids if Path(f"/proc/{pid}").exists())
    surviving_cgroups = sorted(
        cgroup
        for cgroup in cgroups
        if (Path("/sys/fs/cgroup") / cgroup.removeprefix("/")).exists()
    )
    if live_processes or surviving_cgroups:
        _stop("M4_OLD_RUNTIME_SURVIVED_RESTART")
    return {
        "recorded_process_ids": sorted(process_ids),
        "live_process_ids": live_processes,
        "recorded_cgroups": sorted(cgroups),
        "surviving_cgroups": surviving_cgroups,
    }


def _recover_publication(state: dict[str, object]) -> dict[str, object]:
    publication = state["publication"]
    parent_descriptor = root_descriptor = artifact_descriptor = -1
    try:
        parent_descriptor = os.open(
            PUBLICATION_PARENT,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        root_descriptor = os.open(
            PUBLICATION_ROOT,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        descriptor_identity = _publication_descriptor_identity(
            parent_descriptor, root_descriptor
        )
        old_root = publication["root_anchor"]["ancestry"][-1]
        if (
            descriptor_identity["root_device"] != old_root["device"]
            or descriptor_identity["root_inode"] != old_root["inode"]
            or (PUBLICATION_ROOT / ".git").exists()
            or (DENIED_REPOSITORY / ".git" / PUBLICATION_ROOT.name).exists()
        ):
            _stop("M4_PUBLICATION_RESTART_IDENTITY_MISMATCH")
        artifact_descriptor = os.open(
            "artifact.txt",
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=root_descriptor,
        )
        info = os.fstat(artifact_descriptor)
        published = publication["published_binding"]
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_size < 1
            or info.st_size > 1 << 20
            or info.st_dev != published["final_device"]
            or info.st_ino != published["final_inode"]
        ):
            _stop("M4_PUBLICATION_RESTART_BYTES_MISMATCH")
        digest = sha256()
        remaining = info.st_size
        while remaining:
            chunk = os.read(artifact_descriptor, min(65536, remaining))
            if not chunk:
                _stop("M4_PUBLICATION_RESTART_BYTES_MISMATCH")
            digest.update(chunk)
            remaining -= len(chunk)
        after = os.fstat(artifact_descriptor)
        artifact_digest = "sha256:" + digest.hexdigest()
        if (
            os.read(artifact_descriptor, 1)
            or (after.st_dev, after.st_ino, after.st_size, after.st_nlink)
            != (info.st_dev, info.st_ino, info.st_size, info.st_nlink)
            or artifact_digest != publication["artifact_digest"]
            or artifact_digest != published["final_digest"]
        ):
            _stop("M4_PUBLICATION_RESTART_BYTES_MISMATCH")
        return {
            "descriptor_identity": descriptor_identity,
            "artifact_device": info.st_dev,
            "artifact_inode": info.st_ino,
            "artifact_size": info.st_size,
            "artifact_digest": artifact_digest,
            "git_destination_absent": True,
        }
    except QualificationStop:
        raise
    except OSError as error:
        raise QualificationStop("M4_PUBLICATION_RESTART_UNAVAILABLE") from error
    finally:
        for descriptor in (artifact_descriptor, root_descriptor, parent_descriptor):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass


def _utc_text(value: datetime) -> str:
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def _qualification_evidence_projection(
    state: dict[str, object],
) -> dict[str, object]:
    identity = state["identity"]
    contract = _validate_qualification_contract(identity["qualification_contract"])
    contract_digest = _digest_bytes(_canonical(contract))
    admission = state["trust"]["key_admission"]
    admission_digest = admission["ledger_entry_digest"]
    package_runtime_plan = _validate_package_runtime_plan(
        identity["package_runtime_plan"]
    )
    if (
        identity["qualification_contract_digest"] != contract_digest
        or admission["qualification_contract"] != contract
        or admission["qualification_contract_digest"] != contract_digest
        or admission["contract_core_digest"] != contract["contract_core_digest"]
        or not _is_digest(admission_digest)
        or _digest_bytes(_canonical(package_runtime_plan))
        != contract["environment_preimage"]["package_runtime_plan_digest"]
    ):
        _stop("M4_EVIDENCE_CONTRACT_MISMATCH")
    return {
        "qualification_contract": contract,
        "qualification_contract_digest": contract_digest,
        "admission_digest": admission_digest,
        "package_runtime_plan": package_runtime_plan,
    }


def _export_m4_evidence(
    *,
    state: dict[str, object],
    recovery: dict[str, object],
    public_keys: dict[str, dict[str, str]],
    supply: dict[str, object],
    raw_l0: dict[str, object],
    current_boot_id: str,
    m3: object,
) -> tuple[str, dict[str, object], dict[str, bytes]]:
    if any(EVIDENCE.iterdir()):
        _stop("EVIDENCE_OUTPUT_REUSE_FORBIDDEN")
    identity = state["identity"]
    admission = state["trust"]["key_admission"]
    contract_projection = _qualification_evidence_projection(state)
    contract = contract_projection["qualification_contract"]
    contract_digest = contract_projection["qualification_contract_digest"]
    admission_digest = contract_projection["admission_digest"]
    supply_public_raw = _read_regular(Path(str(supply["public_key"])), 4096)
    try:
        supply_public_pem = supply_public_raw.decode("ascii")
    except UnicodeDecodeError as error:
        raise QualificationStop("M4_SUPPLY_PUBLIC_KEY_MALFORMED") from error
    evidence = {
        "evidence_version": "2.0.0",
        "bundle_version": "2.0.0",
        "claim": "M4_EXACT_DISPOSABLE_TEST_PROFILE_RUNTIME_CONFORMANCE",
        **contract_projection,
        "scope": {
            "profile_id": "M4-LX-A",
            "assurance_scope": EXPECTED_SCOPE,
            "environment": "DISPOSABLE_UBUNTU_24_04_QEMU_KVM",
            "data_class": "SYNTHETIC",
        },
        "run_state": state,
        "run_state_digest": _digest_bytes(_canonical(state)),
        "recovery": recovery,
        "public_keys": {
            "receipts": public_keys,
            "supply_attestor": {
                "digest": supply["public_key_digest"],
                "pem": supply_public_pem,
            },
        },
        "residual_risk": (
            "Exact disposable Ubuntu 24.04 M4 test profile only; no production "
            "trust root, production deployment, universal-project non-bypassability, "
            "M5, or product readiness claim. Observer and publisher use distinct keys "
            "but all Ed25519 verification instances use the same pinned OpenSSL libcrypto."
        ),
    }
    evidence_bytes = _canonical(evidence)
    if len(evidence_bytes) > MAX_JSON:
        _stop("M4_EVIDENCE_UNBOUNDED")
    issued = datetime.now(UTC).replace(microsecond=0)
    durable_anchor = state["durable"]["m4_recovery"]
    manifest = {
        "bundle_version": "2.0.0",
        "claim": "M4_EXACT_DISPOSABLE_TEST_PROFILE_RUNTIME_CONFORMANCE",
        "outcome": "VERIFIED",
        "status": "NOT_ATTESTED",
        **contract_projection,
        "candidate": state["identity"]["candidate"],
        "environment": state["identity"]["environment"],
        "attempt": state["identity"]["attempt"],
        "source": state["identity"]["source"],
        "host_provenance": state["identity"]["host_provenance"],
        "profile": {
            "path": "profiles/m4-lx-a.json",
            "digest": state["trust"]["profile_digest"],
            "apparmor_digest": state["trust"]["m4_apparmor_digest"],
            "runtime_trust_digest": state["trust"]["runtime_trust_digest"],
            "verifier": state["trust"]["verifier"],
        },
        "attempt_ledger": {
            "ledger_entry_digest": admission_digest,
            "max_attempts": contract["contract_core"]["max_attempts"],
            "success_target": 1,
            "success_target_authorizing": False,
            "contract_core_digest": contract["contract_core_digest"],
            "qualification_contract_digest": contract_digest,
        },
        "durable": durable_anchor,
        "attestation": {
            "trust_root_id": supply["trust_root_id"],
            "signer_id": supply["signer_id"],
            "key_id": supply["key_id"],
            "algorithm": "ED25519",
            "public_key_digest": supply["public_key_digest"],
            "issued_at": _utc_text(issued),
            "expires_at": _utc_text(issued + timedelta(days=1)),
            "revocation_epoch": state["trust"]["revocation_epoch"],
            "fencing_epoch": state["trust"]["fencing_epoch"],
            "rollback_floor": 1,
            "nonce": "m4-evidence-" + current_boot_id.replace("-", ""),
        },
        "evidence": {
            "path": "evidence.json",
            "bytes": len(evidence_bytes),
            "digest": _digest_bytes(evidence_bytes),
        },
    }
    manifest_bytes = _canonical(manifest)
    m3.RUNTIME.mkdir(mode=0o711)
    signing_manager: object | None = None
    signing_complete = False
    try:
        signing_manager = m3.CgroupManager(raw_l0)
        signing_cgroup = signing_manager.create("m4-evidence-attestor")
        proof, signer_facts = m3._attestor_sign(manifest_bytes, signing_cgroup)
        signing_complete = True
        signing_manager.kill(signing_cgroup)
        signature = bytes.fromhex(proof.removeprefix("ed25519:"))
        record = {
            "verification_version": 1,
            "verifier_id": "harness-m3-external-verifier/v1",
            "issuer_id": supply["signer_id"],
            "key_id": supply["key_id"],
            "payload_digest": _digest_bytes(manifest_bytes),
            "bindings": manifest,
            "proof": proof,
        }
        durable, _, _, _, _ = _load_project()
        verified = m3.Ed25519PayloadVerifier().verify(
            manifest_bytes,
            _canonical(record),
            manifest["attestation"]["issued_at"],
        )
        if (
            verified.status is not durable.VerificationStatus.VERIFIED
            or len(signature) != 64
        ):
            _stop("M4_FINAL_EVIDENCE_SIGNATURE_INVALID")
    finally:
        m3._cleanup_signing_runtime(signing_manager, signing_complete)
    return (
        _digest_bytes(manifest_bytes),
        signer_facts,
        {
            "evidence.json": evidence_bytes,
            "manifest.json": manifest_bytes,
            "manifest.sig": signature,
        },
    )


def _materialize_m4_evidence(bundle: dict[str, bytes]) -> None:
    expected = {"evidence.json", "manifest.json", "manifest.sig"}
    if (
        frozenset(bundle) != expected
        or any(type(value) is not bytes or not value for value in bundle.values())
        or any(EVIDENCE.iterdir())
    ):
        _stop("M4_EVIDENCE_FILE_SET_MISMATCH")
    for name in ("evidence.json", "manifest.json", "manifest.sig"):
        _write_exact(EVIDENCE / name, bundle[name], 0o444)
    _fsync_directory(EVIDENCE)
    if {path.name for path in EVIDENCE.iterdir()} != expected:
        _stop("M4_EVIDENCE_FILE_SET_MISMATCH")


def _remove_test_private_keys() -> list[str]:
    paths = [
        KEY_ROOT / "m4-authority" / "private.pem",
        KEY_ROOT / "observer" / "private.pem",
        KEY_ROOT / "publisher" / "private.pem",
        SUPPLY_KEY_ROOT / "private.pem",
    ]
    removed: list[str] = []
    for path in paths:
        try:
            info = os.lstat(path)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                _stop("M4_PRIVATE_KEY_CLEANUP_MISMATCH")
            path.unlink()
            _fsync_directory(path.parent)
            if path.exists() or path.is_symlink():
                _stop("M4_PRIVATE_KEY_CLEANUP_FAILED")
        except QualificationStop:
            raise
        except OSError as error:
            raise QualificationStop("M4_PRIVATE_KEY_CLEANUP_FAILED") from error
        removed.append(str(path))
    return removed


def _finalize_m4_evidence(bundle: dict[str, bytes]) -> list[str]:
    removed = _remove_test_private_keys()
    _materialize_m4_evidence(bundle)
    return removed


def _run_phase() -> None:
    _diagnostic_stage("SERVICE_ENTERED")
    if os.geteuid() != 0:
        _stop("ROOT_SUPERVISOR_REQUIRED")
    profile = _profile()
    m3 = _load_m3()
    guest = m3._require_guest()
    source = m3._source_identity()
    host_provenance = m3._host_provenance()
    boot_id = Path("/proc/sys/kernel/random/boot_id").read_text(
        encoding="ascii"
    ).strip()
    if re.fullmatch(r"[0-9a-f-]{36}", boot_id) is None:
        _stop("BOOT_ID_MALFORMED")
    request = _strict_bytes(
        _read_regular(QUALIFICATION_REQUEST, 1 << 20),
        1 << 20,
    )
    request_mode = _validate_launch_request(request)
    qualification_contract: dict[str, object] | None = None
    qualification_contract_digest: str | None = None
    package_runtime_plan: dict[str, object] | None = None
    if request_mode in {"QUALIFICATION", ONE_USE_QUALIFICATION_CONTRACT_KIND}:
        qualification_contract, qualification_contract_digest = (
            _qualification_request_contract(request)
        )
        package_runtime_plan = _verify_qualification_environment(
            request, source, host_provenance, profile
        )
    elif request_mode == POST_V2_DIAGNOSTIC_MODE:
        _verify_post_v2_diagnostic_environment(
            request, source, host_provenance, profile
        )
    elif request_mode == PACKAGE_PLAN_DISCRIMINATOR_MODE:
        _verify_package_plan_discriminator_environment(
            request, source, host_provenance, profile
        )
    elif request["candidate"] != source["commit"] or request["tree"] != source["tree"]:
        _stop("M4_DIAGNOSTIC_REQUEST_MISMATCH")
    _diagnostic_stage("REQUEST_VALIDATED")
    if (
        RUNTIME.exists()
        or CONTROLLER.exists()
        or EVIDENCE.exists()
        or m3.RUNTIME.exists()
        or m3.CONTROLLER.exists()
    ):
        _stop("UNCLEAN_PRIOR_M4_RUNTIME")
    RUNTIME.mkdir(mode=0o700)
    CONTROLLER.mkdir(mode=0o700)
    EVIDENCE.mkdir(mode=0o700)
    m3.RUNTIME.mkdir(mode=0o711)
    m3.CONTROLLER.mkdir(mode=0o700)
    os.chown(m3.CONTROLLER, *ROLE_IDS["CONTROLLER"])
    os.chmod(m3.CONTROLLER, 0o700)
    m3_policy = m3._load_apparmor()
    _load_apparmor()
    publication_descriptor = _prepare_publication_root()
    publication_parent_descriptor = os.open(
        PUBLICATION_PARENT,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    _diagnostic_stage("PRE_KEY_CHECKS_COMPLETE")
    _diagnostic_stage("KEY_GENERATION_STARTED")
    keys = _prepare_keys(profile)
    supply_key = _prepare_supply_key(profile)
    _diagnostic_stage("KEY_GENERATION_COMPLETE")
    runtime_trust = _write_runtime_trust(profile, keys, supply_key)
    _diagnostic_stage("RUNTIME_TRUST_READY")
    manager: object | None = None
    controller: ControllerSession | None = None
    publisher_session: PublisherSession | None = None
    chain: dict[str, object] | None = None
    denial_events: list[dict[str, object]] = []
    post_key_stage: str | None = None
    try:
        if request_mode == POST_V2_DIAGNOSTIC_MODE:
            _complete_post_v2_diagnostic(
                request, keys, supply_key, runtime_trust
            )
        post_key_stage = "ADMISSION_CONSUMPTION"
        key_admission = _await_key_admission(
            request, keys, supply_key, runtime_trust
        )
        if (
            qualification_contract is None
            or qualification_contract_digest is None
            or package_runtime_plan is None
        ):
            _stop("M4_DIAGNOSTIC_REQUEST_NONAUTHORIZING")
        post_key_stage = "SUPPLY_AND_CONTROLLER_SETUP"
        raw_l0, compiled_l0, measurement, seccomp_program = (
            _configure_m3_supply_trust(m3, supply_key)
        )
        tools = m3._verify_tools()
        role_seccomp, role_seccomp_records = m3._role_seccomp_programs()
        m4_seccomp = _m4_role_seccomp_programs(m3)
        manager = m3.CgroupManager(raw_l0)
        controller = ControllerSession(manager)

        def denial_probe(point: str, pause: dict[str, object]) -> None:
            denial_events.append(
                _publication_denial_probe(manager, point, pause)
            )

        post_key_stage = "PUBLISHER_AUTHORITY_FRONTIER_SETUP"
        publisher_session, publication = _start_publisher_session(
            m3=m3,
            manager=manager,
            raw_l0_profile=raw_l0,
            m4_profile=profile,
            seccomp_program=m4_seccomp["PUBLISHER"],
            publication_parent_descriptor=publication_parent_descriptor,
            publication_root_descriptor=publication_descriptor,
            denial_probe=denial_probe,
        )
        publication_parent_descriptor = -1
        publication_descriptor = -1
        chain = m3._authority_chain(
            raw_l0,
            compiled_l0,
            measurement,
            seccomp_program,
            role_seccomp["BROKER"],
            tools,
            manager,
            controller,
            m4_authority_builder=_m4_authority_builder(
                profile,
                publication,
                controller,
            ),
        )
        authority = chain.get("m4_authority")
        if (
            type(authority) is not dict
            or type(authority.get("context")) is not dict
        ):
            _stop("M4_AUTHORITY_CONTEXT_ABSENT")
        context = authority["context"]
        topology = context.get("topology")
        topology_verification = context.get("topology_verification")
        if topology is None or type(topology_verification) is not dict:
            _stop("M4_TOPOLOGY_ABSENT")
        publisher_session.install(
            topology,
            topology_verification,
            chain["times"]["issued_at"],
        )
        m4_times: dict[str, str] = {}
        previous = chain["times"]["prepare_at"]
        for state in (
            "BEGIN", "STAGED", "QUIESCED", "SEALED", "POSTCHECKED",
            "COMMITTED", "JOINED", "QUARANTINED", "RECONCILING",
        ):
            previous = m3._transition_time(previous)
            m4_times[state] = previous
        bound = controller.bind_current_m4_frontier(
            {
                "transaction_id": chain["claim"].transaction_id,
                "observed_at": m4_times["BEGIN"],
                "issued_at": m4_times["BEGIN"],
                "expires_at": chain["supply"].expires_at,
            }
        )
        durable, _, m4, _, _ = _load_project()
        if (
            bound.outcome is not durable.DurableOutcome.COMMITTED
            or bound.reason is not durable.DurableReason.D2_FRONTIER_BOUND
            or bound.d2_frontier_digest is None
            or bound.frontier_record_digest is None
            or bound.m4_iteration is None
        ):
            _stop("M4_FRONTIER_BIND_FAILED")

        post_key_stage = "RUNTIME_CONSTRUCTION"
        executor_facts: list[dict[str, object]] = []
        observer_facts: list[dict[str, object]] = []

        def launch_executor(*arguments: object) -> object:
            return _executor_launcher(
                *arguments,
                m3=m3,
                manager=manager,
                raw_l0_profile=raw_l0,
                seccomp_program=m4_seccomp["EXECUTOR"],
                facts_sink=executor_facts,
            )

        def launch_observer(*arguments: object) -> object:
            return _observer_launcher(
                *arguments,
                m3=m3,
                manager=manager,
                raw_l0_profile=raw_l0,
                m4_profile=profile,
                seccomp_program=m4_seccomp["OBSERVER"],
                facts_sink=observer_facts,
            )

        runtime = M4GuestRuntime(
            profile=profile,
            topology=topology,
            topology_verification=topology_verification,
            stage_root_descriptor=chain["staging"]["descriptor"],
            controller=controller,
            publisher_session=publisher_session,
            verifier_router=ConfiguredVerifierRouter(),
            manager=manager,
            executor_launcher=launch_executor,
            observer_launcher=launch_observer,
        )
        coordinator = m4.M4Coordinator(
            store=controller,
            profile=compiled_l0,
            staging_root_descriptor=chain["staging"]["descriptor"],
            topology=topology,
            topology_verification=topology_verification,
            trusted_publisher=None,
            executor_claim_verifier_factory=m3.Ed25519PayloadVerifier,
            supply_verifier_factory=m3.Ed25519PayloadVerifier,
            external_verifier_factory=ConfiguredVerifierRouter,
            principals=m4.M4Principals(
                profile["roles"]["CONTROLLER"]["principal_id"],
                profile["roles"]["CONTROLLER"]["session_id"],
                profile["roles"]["OBSERVER"]["principal_id"],
                profile["roles"]["OBSERVER"]["session_id"],
            ),
            runtime_boundary=runtime,
            m4_verifier_factory=ConfiguredVerifierRouter,
            external_verification_provider=controller,
        )
        post_key_stage = "COORDINATOR_EXECUTION"
        result = coordinator.execute(
            chain["claim"],
            chain["supply"],
            {
                "runtime_version": "1.0.0",
                "transaction_id": chain["claim"].transaction_id,
                "d2_frontier_digest": bound.d2_frontier_digest,
                "stage_request": {
                    "transaction_id": chain["claim"].transaction_id,
                    "claim_digest": chain["claim"].claim_digest,
                    "operation": "WRITE_FILE_REPLACE",
                    "content": chain["content"],
                    "content_digest": chain["claim"].material_digest,
                },
                "observed_at": m4_times,
            },
        )
        post_key_stage = "PRE_RESTART_FINALIZATION"
        if (
            result.outcome is not m4.M4Outcome.JOINED
            or result.reason is not m4.M4Reason.JOINED
            or result.state != "JOINED"
            or result.snapshot is None
            or result.record_digest is None
            or [row["point"] for row in denial_events]
            != ["AFTER_PRE_REPLACE_CHECKS", "AFTER_PRE_JOIN"]
        ):
            _stop("M4_RUNTIME_JOIN_FAILED")
        publisher_facts = publisher_session.close()
        publisher_session = None
        pre_restart_recovery = controller.recover()
        if (
            pre_restart_recovery.outcome is not durable.DurableOutcome.OK
            or pre_restart_recovery.reason is not durable.DurableReason.RECOVERED
            or pre_restart_recovery.recovery_intents
            or len(pre_restart_recovery.recovery_sessions) != 1
            or len(pre_restart_recovery.m4_recovery) != 1
        ):
            _stop("M4_PRE_RESTART_DURABLE_MISMATCH")
        recovery_anchor = pre_restart_recovery.m4_recovery[0]
        runtime_session_anchor = pre_restart_recovery.recovery_sessions[0]
        prepared_session = chain.get("runtime_session")
        if (
            recovery_anchor.transaction_id != result.transaction_id
            or recovery_anchor.state != "JOINED"
            or recovery_anchor.contract_digest != bound.contract_digest
            or recovery_anchor.d2_frontier_digest != bound.d2_frontier_digest
            or recovery_anchor.record_digest != result.record_digest
            or recovery_anchor.frontier_record_digest != bound.frontier_record_digest
            or recovery_anchor.iteration != bound.m4_iteration
            or recovery_anchor.intent_state != "SPENT"
            or recovery_anchor.resume_allowed
            or recovery_anchor.retry_allowed
            or prepared_session is None
            or runtime_session_anchor.session_record_id
            != prepared_session.session_record_id
            or runtime_session_anchor.transaction_id != result.transaction_id
            or runtime_session_anchor.state != "STOPPED"
        ):
            _stop("M4_PRE_RESTART_DURABLE_MISMATCH")
        controller_facts = controller.close()
        controller = None
        cleanup = m3._cleanup_disposable_runtime(
            manager,
            Path(chain["staging"]["path"]),
        )
        manager = None
        if not RUNTIME.is_dir() or RUNTIME.is_symlink():
            _stop("M4_RUNTIME_STORAGE_CLEANUP_MISMATCH")
        shutil.rmtree(RUNTIME)
        if RUNTIME.exists() or RUNTIME.is_symlink():
            _stop("M4_RUNTIME_STORAGE_CLEANUP_FAILED")
        cleanup = {**cleanup, "m4_runtime_root_absent": True}
        publication_events = [
            event for event in runtime.events
            if type(event) is dict and event.get("type") == "TCB_PUBLICATION"
        ]
        if (
            len(publication_events) != 1
            or type(publication_events[0].get("receipt")) is not dict
            or type(publication_events[0]["receipt"].get("published_binding"))
            is not dict
        ):
            _stop("M4_PUBLICATION_EVIDENCE_ABSENT")
        published_binding = publication_events[0]["receipt"]["published_binding"]
        artifact_digest = _digest_file(
            PUBLICATION_ROOT / "artifact.txt",
            1 << 20,
        )
        marker = {
            "record_version": "1.0.0",
            "phase": "PRE_RESTART_PASS",
            "identity": {
                "candidate": qualification_contract["contract_core"]["candidate"],
                "environment": qualification_contract["environment_digest"],
                "attempt": qualification_contract["contract_core"]["attempt"],
                "qualification_contract": qualification_contract,
                "qualification_contract_digest": qualification_contract_digest,
                "boot_id": boot_id,
                "guest": guest,
                "source": source,
                "host_provenance": host_provenance,
                "package_runtime_plan": package_runtime_plan,
            },
            "trust": {
                "profile_digest": _digest_bytes(_canonical(profile)),
                "m4_apparmor_digest": _digest_file(APPARMOR_POLICY, 1 << 20),
                "m3_apparmor_digest": m3_policy["digest"],
                "runtime_trust_digest": _digest_bytes(_canonical(runtime_trust)),
                "key_admission": key_admission,
                "receipt_public_key_digests": {
                    name: key.public_key_digest for name, key in keys.items()
                },
                "supply_public_key_digest": supply_key["public_key_digest"],
                "verifier": {
                    "backend": "OPENSSL_LIBCRYPTO_SHARED",
                    "code_digest": runtime_trust["verifier_code_digest"],
                    "libcrypto_path": runtime_trust["libcrypto_path"],
                    "libcrypto_digest": runtime_trust["libcrypto_digest"],
                    "independent_cryptographic_implementations": False,
                },
                "revocation_epoch": chain["supply"].revocation_epoch,
                "fencing_epoch": chain["supply"].fencing_epoch,
            },
            "durable": {
                "m4_recovery": asdict(recovery_anchor),
                "m3_runtime_session": asdict(runtime_session_anchor),
            },
            "publication": {
                "root": str(PUBLICATION_ROOT),
                "topology_digest": topology.topology_digest,
                "root_anchor": topology.publication_root_anchor.data(),
                "target_binding": topology.publication_target_binding.data(),
                "published_binding": published_binding,
                "artifact_digest": artifact_digest,
                "snapshot_digest": result.snapshot.digest,
                "transport": SEALED_FD_ONLY,
            },
            "execution": {
                "controller_facts": controller_facts,
                "publisher_facts": publisher_facts,
                "executor_facts": executor_facts,
                "observer_facts": observer_facts,
                "runtime_events": runtime.events,
                "denial_events": denial_events,
                "role_seccomp_digests": {
                    role: _digest_bytes(program)
                    for role, program in m4_seccomp.items()
                },
                "m3_role_seccomp": role_seccomp_records,
                "cleanup": cleanup,
            },
        }
        _validate_run_state(marker)
        _write_exact(RUN_STATE, _canonical(marker), 0o600)
        _fsync_directory(CONTROLLER)
        sys.stdout.buffer.write(
            _canonical(
                {
                    "outcome": "PRE_RESTART_PASS",
                    "transaction_id": result.transaction_id,
                    "record_digest": result.record_digest,
                    "snapshot_digest": result.snapshot.digest,
                    "status": "NOT_ATTESTED",
                }
            )
            + b"\n"
        )
    except QualificationStop:
        raise
    except m3.QualificationStop as error:
        _stop(error.args[0] if len(error.args) == 1 else None)
    except Exception as error:
        if post_key_stage is None:
            raise
        _stop(_post_key_exception_reason(post_key_stage, error))
    finally:
        if publisher_session is not None:
            try:
                publisher_session.close()
            except Exception:
                pass
        if controller is not None:
            try:
                controller.close()
            except Exception:
                pass
        if manager is not None:
            try:
                manager.cleanup()
            except Exception:
                pass
        for descriptor in (publication_parent_descriptor, publication_descriptor):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass


def _recover_phase() -> None:
    if os.geteuid() != 0:
        _stop("ROOT_SUPERVISOR_REQUIRED")
    request = _strict_bytes(
        _read_regular(QUALIFICATION_REQUEST, 1 << 20), 1 << 20
    )
    request_mode = _validate_launch_request(request)
    if request_mode not in {"QUALIFICATION", ONE_USE_QUALIFICATION_CONTRACT_KIND}:
        _stop("M4_RECOVERY_QUALIFICATION_CONTRACT_MISMATCH")
    profile = _profile()
    m3 = _load_m3()
    guest = m3._require_guest()
    source = m3._source_identity()
    host_provenance = m3._host_provenance()
    state = _validate_run_state(_strict_file(RUN_STATE, RUN_STATE_KEYS))
    contract, contract_digest = _qualification_request_contract(request)
    package_runtime_plan = _verify_qualification_environment(
        request, source, host_provenance, profile
    )
    current_boot_id = Path("/proc/sys/kernel/random/boot_id").read_text(
        encoding="ascii"
    ).strip()
    identity = state["identity"]
    trust = state["trust"]
    runtime_trust = _strict_file(
        RUNTIME_TRUST,
        frozenset(
            {
                "trust_version", "profile_digest", "verifier_code_path",
                "verifier_code_digest", "libcrypto_path", "libcrypto_digest",
                "m4_routes", "supply", "revocation_epoch", "fencing_epoch",
            }
        ),
        1 << 20,
    )
    if (
        re.fullmatch(r"[0-9a-f-]{36}", current_boot_id) is None
        or current_boot_id == identity["boot_id"]
        or identity["guest"] != guest
        or identity["source"] != source
        or identity["host_provenance"] != host_provenance
        or identity["qualification_contract"] != contract
        or identity["qualification_contract_digest"] != contract_digest
        or identity["package_runtime_plan"] != package_runtime_plan
        or source["commit"] != identity["candidate"]
        or trust["profile_digest"] != _digest_bytes(_canonical(profile))
        or trust["m4_apparmor_digest"] != _digest_file(APPARMOR_POLICY, 1 << 20)
        or trust["m3_apparmor_digest"]
        != _digest_file(Path(str(m3.APPARMOR_POLICY)), 1 << 20)
        or trust["runtime_trust_digest"] != _digest_file(RUNTIME_TRUST, 1 << 20)
        or trust["verifier"]
        != {
            "backend": "OPENSSL_LIBCRYPTO_SHARED",
            "code_digest": runtime_trust["verifier_code_digest"],
            "libcrypto_path": runtime_trust["libcrypto_path"],
            "libcrypto_digest": runtime_trust["libcrypto_digest"],
            "independent_cryptographic_implementations": False,
        }
    ):
        _stop("M4_RECOVERY_PROVENANCE_MISMATCH")
    admission = _strict_file(
        KEY_ADMISSION,
        _KEY_ADMISSION_KEYS,
        1 << 20,
    )
    if admission != trust["key_admission"]:
        _stop("M4_RECOVERY_KEY_ADMISSION_MISMATCH")
    public_keys = _receipt_public_material()
    if (
        {name: value["digest"] for name, value in public_keys.items()}
        != trust["receipt_public_key_digests"]
    ):
        _stop("M4_RECOVERY_PUBLIC_KEY_MISMATCH")
    supply = _existing_supply_key(profile)
    if supply["public_key_digest"] != trust["supply_public_key_digest"]:
        _stop("M4_RECOVERY_PUBLIC_KEY_MISMATCH")
    if RUNTIME.exists() or RUNTIME.is_symlink() or m3.RUNTIME.exists() or m3.RUNTIME.is_symlink():
        _stop("M4_OLD_RUNTIME_STORAGE_SURVIVED")
    evidence_info = os.lstat(EVIDENCE)
    if (
        not stat.S_ISDIR(evidence_info.st_mode)
        or evidence_info.st_uid != 0
        or evidence_info.st_gid != 0
        or stat.S_IMODE(evidence_info.st_mode) != 0o700
        or any(EVIDENCE.iterdir())
    ):
        _stop("M4_EVIDENCE_ROOT_MISMATCH")
    survival = _execution_survival(state)
    publication_recovery = _recover_publication(state)
    m3_policy = m3._load_apparmor()
    m4_policy = _load_apparmor()
    if (
        m3_policy["digest"] != trust["m3_apparmor_digest"]
        or m4_policy["digest"] != trust["m4_apparmor_digest"]
    ):
        _stop("M4_RECOVERY_POLICY_MISMATCH")
    raw_l0, _, _, _ = _configure_m3_supply_trust(m3, supply)
    manager: object | None = None
    controller: ControllerSession | None = None
    try:
        manager = m3.CgroupManager(raw_l0)
        controller = ControllerSession(manager)
        recovered = controller.recover()
        if (
            recovered.outcome is not _load_project()[0].DurableOutcome.OK
            or recovered.reason is not _load_project()[0].DurableReason.RECOVERED
            or recovered.recovery_intents
            or len(recovered.recovery_sessions) != 1
            or len(recovered.m4_recovery) != 1
            or asdict(recovered.m4_recovery[0]) != state["durable"]["m4_recovery"]
            or asdict(recovered.recovery_sessions[0])
            != state["durable"]["m3_runtime_session"]
        ):
            _stop("M4_RECOVERY_DURABLE_MISMATCH")
        controller_facts = controller.close()
        controller = None
        manager.cleanup()
        manager = None
    finally:
        if controller is not None:
            try:
                controller.close()
            except Exception:
                pass
        if manager is not None:
            try:
                manager.cleanup()
            except Exception:
                pass
    recovery = {
        "recovery_version": "1.0.0",
        "qualification_contract": contract,
        "qualification_contract_digest": contract_digest,
        "previous_boot_id": identity["boot_id"],
        "current_boot_id": current_boot_id,
        "durable": {
            "m4_recovery": asdict(recovered.m4_recovery[0]),
            "m3_runtime_session": asdict(recovered.recovery_sessions[0]),
            "old_session_resumed": False,
            "retry_created": False,
        },
        "survival": survival,
        "publication": publication_recovery,
        "controller_facts": controller_facts,
        "source_reverified": True,
        "host_provenance_reverified": True,
        "trust_reverified": True,
    }
    manifest_digest, signer_facts, bundle = _export_m4_evidence(
        state=state,
        recovery=recovery,
        public_keys=public_keys,
        supply=supply,
        raw_l0=raw_l0,
        current_boot_id=current_boot_id,
        m3=m3,
    )
    removed_private_keys = _finalize_m4_evidence(bundle)
    sys.stdout.buffer.write(
        _canonical(
            {
                "outcome": "RECOVERY_PASS",
                "claim": "M4_EXACT_DISPOSABLE_TEST_PROFILE_RUNTIME_CONFORMANCE",
                "manifest_digest": manifest_digest,
                "signer_facts_digest": _digest_bytes(_canonical(signer_facts)),
                "private_keys_removed": removed_private_keys,
                "status": "NOT_ATTESTED",
            }
        )
        + b"\n"
    )


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    parser.add_argument("--phase", choices=ALLOWED_PHASES)
    parser.add_argument("--internal-role", choices=INTERNAL_ROLES)
    value = parser.parse_args(argv)
    if (value.phase is None) == (value.internal_role is None):
        parser.error("exactly one entry point is required")
    return value


def main(argv: list[str] | None = None) -> int:
    try:
        arguments = _parse_args(sys.argv[1:] if argv is None else argv)
        if arguments.internal_role == "controller":
            _controller_role()
        elif arguments.internal_role == "executor":
            _executor_role()
        elif arguments.internal_role == "observer":
            _observer_role()
        elif arguments.internal_role == "publisher":
            _publisher_role()
        elif arguments.internal_role == "relocator":
            _relocator_role()
        elif arguments.phase == "run":
            _run_phase()
        elif arguments.phase == "recover":
            _recover_phase()
        else:
            _stop("UNKNOWN_PHASE")
        return 0
    except QualificationStop as error:
        record = {
            "outcome": "STOP",
            "reason": _sanitize_stop_reason(
                error.args[0] if len(error.args) == 1 else None
            ),
            "status": "NOT_ATTESTED",
        }
        sys.stdout.buffer.write(_canonical(record) + b"\n")
        return 2
    except Exception:
        record = {
            "outcome": "STOP",
            "reason": "M4_UNHANDLED_EXCEPTION",
            "status": "NOT_ATTESTED",
        }
        sys.stdout.buffer.write(_canonical(record) + b"\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
