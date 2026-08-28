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
LAB = Path("/home/a1/Загрузки/harness/harness-m4-lab")
DIAGNOSTIC_LAB = Path("/home/a1/Загрузки/harness/harness-m4-diagnostic-lab")
IMAGE_LAB = Path("/home/a1/Загрузки/harness/harness-m3-lab")
EVIDENCE_ROOT = Path("/home/a1/Загрузки/harness/harness-m4-evidence")
USER_GOAL = Path(
    "/home/a1/.codex/attachments/a1d7db13-d210-4875-b261-a086d01fca5a/goal-objective.md"
)
LEDGER_NAME = "m4-attempt-ledger.jsonl"
DIAGNOSTIC_LEDGER_NAME = "m4-key-ready-diagnostic-ledger.jsonl"
OLD_LEDGER = LAB / LEDGER_NAME
OLD_LEDGER_DIGEST = "sha256:719505206caf364c6c0d40983687416bcca5644f879a46254714621cb070d5f9"
_QEMU_PATH = "/usr/bin/qemu-system-x86_64"
_QEMU_DIGEST = "sha256:8a35ccba41582fc6c38b9df85fc9e35fa1d42f414d2d7d8090ee9b2f5e7c0854"
_OVERLAY_VIRTUAL_BYTES = 3758096384
_IMAGE_URL = (
    "https://cloud-images.ubuntu.com/releases/noble/release-20260814/"
    "ubuntu-24.04-server-cloudimg-amd64.img"
)
_IMAGE_DIGEST = "sha256:6e40c07ae715f744f84af0bec76415cc1987dd115b4b8de437818561f01a3733"
_M4_PROFILE_DIGEST = "sha256:50947b4b4ae139effbaddd749c7175a15755675f824e0ae1ed734a85694b4682"
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
_LEDGER_COMMON = frozenset(
    {
        "ledger_version", "sequence", "previous_entry_digest", "entry_type",
        "recorded_at", "candidate", "tree", "environment",
        "user_scope_reference", "user_goal_digest", "max_attempts",
        "success_target", "attempt",
    }
)
_LEDGER_EXTRA = {
    "ATTEMPT_STARTED": frozenset(),
    "KEY_ADMITTED": frozenset(
        {
            "attempt_start_digest", "receipt_public_key_digests",
            "supply_public_key_digest", "runtime_trust_digest",
        }
    ),
    "ATTEMPT_TERMINAL": frozenset(
        {
            "attempt_start_digest", "key_admission_digest", "result",
            "manifest_digest", "bundle_digest", "qemu_phase_outcomes",
        }
    ),
}
_TERMINAL_RESULTS = frozenset({"BUNDLE_EXPORTED", "FAILED", "BLOCKED", "QUARANTINED"})
_DIAGNOSTIC_REASONS = frozenset(
    {
        "PROVISION_FAILED", "QEMU_EXITED", "SERVICE_FAILED_PRE_KEY_READY",
        "KEY_READY_TIMEOUT", "KEY_READY_REACHED", "CLEANUP_FAILED",
    }
)
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


def _validate_qemu_phase_outcomes(value: object, attempt: int) -> dict[str, object]:
    if type(value) is not dict or frozenset(value) != {"provision", "run", "recover"}:
        _stop("QEMU_PHASE_OUTCOME_MISMATCH")
    for phase in ("provision", "run", "recover"):
        row = value[phase]
        if (
            type(row) is not dict
            or frozenset(row) != {"argv_digest", "return_code"}
            or row["argv_digest"] != _digest_bytes(_canonical(_qemu_argv(attempt, phase)))
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
    digest: str


class AttemptLedger:
    """Append-only, exclusively locked qualification-attempt ledger."""

    def __init__(
        self,
        lab: Path,
        *,
        goal_reference: str,
        goal_digest: str,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.lab = lab
        self.goal_reference = goal_reference
        self.goal_digest = goal_digest
        self.clock = (lambda: datetime.now(UTC)) if clock is None else clock
        self._directory_descriptor = -1
        self._descriptor = -1
        self._rows: list[tuple[dict[str, object], str]] = []
        self._active_start: AttemptStart | None = None
        self._active_admission: str | None = None

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
                row["ledger_version"] != "1.0.0"
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
                or row["max_attempts"] != 2
                or row["success_target"] != 1
                or type(row["attempt"]) is not int
                or isinstance(row["attempt"], bool)
                or row["attempt"] not in {1, 2}
                or type(row["recorded_at"]) is not str
                or _TIME.fullmatch(row["recorded_at"]) is None
            ):
                _stop("LEDGER_BINDING_MISMATCH")
            recorded = datetime.strptime(row["recorded_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
            if recorded > now:
                _stop("LEDGER_BINDING_MISMATCH")
            self._validate_row(row)
            digest = _digest_bytes(line)
            result.append((row, digest))
            previous = digest
        self._validate_lifecycle(result)
        return result

    @staticmethod
    def _validate_row(row: dict[str, object]) -> None:
        if row["entry_type"] == "KEY_ADMITTED":
            keys = row["receipt_public_key_digests"]
            if type(keys) is not dict or frozenset(keys) != {
                "M4_AUTHORITY", "OBSERVER", "PUBLISHER"
            }:
                _stop("LEDGER_BINDING_MISMATCH")
            values = [
                row["attempt_start_digest"], row["supply_public_key_digest"],
                row["runtime_trust_digest"], *keys.values(),
            ]
            if any(type(value) is not str or _DIGEST.fullmatch(value) is None for value in values):
                _stop("LEDGER_BINDING_MISMATCH")
        elif row["entry_type"] == "ATTEMPT_TERMINAL":
            if (
                row["result"] not in _TERMINAL_RESULTS
                or type(row["attempt_start_digest"]) is not str
                or _DIGEST.fullmatch(row["attempt_start_digest"]) is None
            ):
                _stop("LEDGER_BINDING_MISMATCH")
            if row["result"] == "BUNDLE_EXPORTED":
                values = [row["key_admission_digest"], row["manifest_digest"], row["bundle_digest"]]
                if any(type(value) is not str or _DIGEST.fullmatch(value) is None for value in values):
                    _stop("LEDGER_BINDING_MISMATCH")
                _validate_qemu_phase_outcomes(row["qemu_phase_outcomes"], row["attempt"])
            elif (
                row["manifest_digest"] is not None
                or row["bundle_digest"] is not None
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
    def _validate_lifecycle(rows: list[tuple[dict[str, object], str]]) -> None:
        cursor = 0
        attempt = 1
        exported = False
        pairs: set[tuple[object, object]] = set()
        while cursor < len(rows):
            start, start_digest = rows[cursor]
            pair = (start["candidate"], start["environment"])
            if (
                start["entry_type"] != "ATTEMPT_STARTED"
                or start["attempt"] != attempt
                or pair in pairs
                or exported
            ):
                _stop("LEDGER_LIFECYCLE_MISMATCH")
            pairs.add(pair)
            cursor += 1
            admission: tuple[dict[str, object], str] | None = None
            if cursor < len(rows) and rows[cursor][0]["entry_type"] == "KEY_ADMITTED":
                admission = rows[cursor]
                cursor += 1
            if cursor >= len(rows) or rows[cursor][0]["entry_type"] != "ATTEMPT_TERMINAL":
                _stop("PRIOR_ATTEMPT_UNRESOLVED")
            terminal, _ = rows[cursor]
            cursor += 1
            group = ([] if admission is None else [admission[0]]) + [terminal]
            if any(
                any(row[key] != start[key] for key in ("candidate", "tree", "environment", "attempt"))
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
            if terminal["result"] == "BUNDLE_EXPORTED" and admission is None:
                _stop("LEDGER_LIFECYCLE_MISMATCH")
            exported = terminal["result"] == "BUNDLE_EXPORTED"
            attempt += 1

    def _recorded_at(self) -> str:
        return self.clock().astimezone(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")

    def _append(self, entry_type: str, start: AttemptStart, extra: dict[str, object]) -> str:
        previous = None if not self._rows else self._rows[-1][1]
        row = {
            "ledger_version": "1.0.0",
            "sequence": len(self._rows) + 1,
            "previous_entry_digest": previous,
            "entry_type": entry_type,
            "recorded_at": self._recorded_at(),
            "candidate": start.candidate,
            "tree": start.tree,
            "environment": start.environment,
            "user_scope_reference": self.goal_reference,
            "user_goal_digest": self.goal_digest,
            "max_attempts": 2,
            "success_target": 1,
            "attempt": start.attempt,
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

    def begin(self, candidate: str, tree: str, environment: str) -> AttemptStart:
        if self._active_start is not None:
            _stop("ATTEMPT_ALREADY_STARTED")
        attempt = self.next_attempt()
        starts = [row for row, _ in self._rows if row["entry_type"] == "ATTEMPT_STARTED"]
        if (
            type(candidate) is not str
            or _COMMIT.fullmatch(candidate) is None
            or type(tree) is not str
            or _COMMIT.fullmatch(tree) is None
            or type(environment) is not str
            or _DIGEST.fullmatch(environment) is None
            or any(
                row["candidate"] == candidate and row["environment"] == environment
                for row in starts
            )
        ):
            _stop("ATTEMPT_BINDING_MISMATCH")
        provisional = AttemptStart(attempt, candidate, tree, environment, "")
        digest = self._append("ATTEMPT_STARTED", provisional, {})
        self._active_start = AttemptStart(attempt, candidate, tree, environment, digest)
        return self._active_start

    def next_attempt(self) -> int:
        starts = [row for row, _ in self._rows if row["entry_type"] == "ATTEMPT_STARTED"]
        if any(
            row["entry_type"] == "ATTEMPT_TERMINAL" and row["result"] == "BUNDLE_EXPORTED"
            for row, _ in self._rows
        ):
            _stop("QUALIFICATION_ALREADY_EXPORTED")
        if len(starts) >= 2:
            _stop("ATTEMPT_LIMIT_REACHED")
        return len(starts) + 1

    def admit(self, start: AttemptStart, ready: object) -> str:
        if start != self._active_start or self._active_admission is not None:
            _stop("KEY_ADMISSION_ORDER_MISMATCH")
        if type(ready) is not dict or frozenset(ready) != {
            "ready_version", "candidate", "environment", "attempt",
            "receipt_public_key_digests", "supply_public_key_digest",
            "runtime_trust_digest",
        }:
            _stop("KEY_READY_MALFORMED")
        keys = ready["receipt_public_key_digests"]
        if (
            ready["ready_version"] != "1.0.0"
            or ready["candidate"] != start.candidate
            or ready["environment"] != start.environment
            or ready["attempt"] != start.attempt
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

    def terminalize(
        self,
        start: AttemptStart,
        admission_digest: str | None,
        result: str,
        *,
        manifest_digest: str | None = None,
        bundle_digest: str | None = None,
        qemu_phase_outcomes: dict[str, object] | None = None,
    ) -> str:
        if (
            start != self._active_start
            or admission_digest != self._active_admission
            or result not in _TERMINAL_RESULTS
        ):
            _stop("ATTEMPT_TERMINAL_ORDER_MISMATCH")
        if result == "BUNDLE_EXPORTED":
            if (
                admission_digest is None
                or type(manifest_digest) is not str
                or _DIGEST.fullmatch(manifest_digest) is None
                or type(bundle_digest) is not str
                or _DIGEST.fullmatch(bundle_digest) is None
            ):
                _stop("ATTEMPT_TERMINAL_MALFORMED")
            _validate_qemu_phase_outcomes(qemu_phase_outcomes, start.attempt)
        elif (
            manifest_digest is not None
            or bundle_digest is not None
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
                "manifest_digest": manifest_digest,
                "bundle_digest": bundle_digest,
                "qemu_phase_outcomes": qemu_phase_outcomes,
            },
        )
        self._active_start = None
        self._active_admission = None
        return digest


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
        + ["runcmd:", "  - [ /bin/bash, /root/harness-m4-provision.sh ]", ""]
    )
    return "\n".join(lines).encode("utf-8")


def _create_seed(
    attempt_root: Path,
    *,
    attempt: int,
    source: dict[str, object],
) -> tuple[Path, Path, Path]:
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
        (
            "/etc/apt/sources.list.d/ubuntu.sources",
            _read_regular(IMAGE_LAB / "apt-ubuntu.sources", 1 << 20),
            0o644,
        ),
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
        ("/etc/ssh/ssh_host_ed25519_key", _read_regular(host_key, 4096), 0o600),
        (
            "/etc/ssh/ssh_host_ed25519_key.pub",
            _read_regular(host_key.with_suffix(".pub"), 4096),
            0o644,
        ),
        ("/root/harness-m4-provision.sh", _provision_script(), 0o700),
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


def _collect_pre_key_diagnostics(
    qemu: QemuProcess,
    client_key: Path,
    known_hosts: Path,
    unit: str,
) -> tuple[list[str], list[str], list[dict[str, object]]]:
    try:
        qemu.require_alive()
    except QualificationStop:
        unavailable = ["UNAVAILABLE:QEMU_EXITED"]
        return unavailable, unavailable, []
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
        unavailable = ["UNAVAILABLE:SSH_DIAGNOSTIC_COLLECTION_FAILED"]
        return unavailable, unavailable, []
    unit_lines = _journal_lines(unit_raw)
    kernel_lines = [
        line
        for line in _journal_lines(kernel_raw)
        if any(
            token in line.casefold()
            for token in ("apparmor", "oom", "out of memory", "killed process")
        )
    ]
    return unit_lines, kernel_lines, _stage_markers(unit_lines)


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


def _run_vm_phase(
    attempt_root: Path,
    attempt: int,
    phase: str,
    client_key: Path,
    known_hosts: Path,
    *,
    ledger: AttemptLedger,
    start: AttemptStart,
) -> tuple[dict[str, object], str | None, list[Path], dict[str, object]]:
    unit = f"harness-m4-controller@{phase}.service"
    created: list[Path] = []
    admission_digest: str | None = None
    with QemuProcess(attempt_root, attempt, phase) as qemu:
        _wait_for_ssh(qemu, client_key, known_hosts)
        _ssh(
            client_key,
            known_hosts,
            ["sudo", "/usr/bin/systemctl", "start", "--no-block", unit],
        )
        if phase == "run":
            ready = _wait_key_ready(qemu, client_key, known_hosts)
            admission_digest = ledger.admit(start, ready)
            admission = {
                "admission_version": "1.0.0",
                "mode": "HOST_ATTEMPT_LEDGER_PIN_BEFORE_WORKER_GATE",
                "candidate": start.candidate,
                "environment": start.environment,
                "attempt": start.attempt,
                "ledger_entry_digest": admission_digest,
                "receipt_public_key_digests": ready["receipt_public_key_digests"],
                "supply_public_key_digest": ready["supply_public_key_digest"],
                "runtime_trust_digest": ready["runtime_trust_digest"],
            }
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
        _wait_for_service(qemu, client_key, known_hosts, unit)
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
            bundle = _export_bundle(attempt_root, attempt, client_key, known_hosts)
            result = {**result, "bundle": str(bundle)}
        _poweroff(qemu, client_key, known_hosts)
    outcome = qemu.successful_outcome()
    _verify_management_port_free()
    return result, admission_digest, created, outcome


def _diagnostic_qemu_outcome(
    qemu: QemuProcess, phase: str
) -> dict[str, object] | None:
    process = qemu.process
    if process is None or process.returncode is None:
        return None
    return {
        "argv_digest": _digest_bytes(
            _canonical(_qemu_argv(1, phase, lab=DIAGNOSTIC_LAB))
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
        unit_lines, kernel_lines, markers = _collect_pre_key_diagnostics(
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


def _export_bundle(
    attempt_root: Path,
    attempt: int,
    client_key: Path,
    known_hosts: Path,
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
    _mkdir_exact(EVIDENCE_ROOT, 0o700)
    attempt_evidence = EVIDENCE_ROOT / f"attempt-{attempt}"
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
    _fsync_directory(EVIDENCE_ROOT)
    return bundle


def _bundle_digests(bundle: Path, admission_digest: str) -> tuple[str, str]:
    manifest = _read_regular(bundle / "manifest.json", 1 << 20)
    signature = _read_regular(bundle / "manifest.sig", 128)
    evidence = _read_regular(bundle / "evidence.json", 8 << 20)
    if len(signature) != 64:
        _stop("EVIDENCE_SIGNATURE_LENGTH_MISMATCH")
    manifest_digest = _digest_bytes(manifest)
    bundle_digest = _digest_bytes(
        _canonical(
            {
                "manifest": manifest_digest,
                "signature": _digest_bytes(signature),
                "evidence": _digest_bytes(evidence),
                "ledger_entry": admission_digest,
            }
        )
    )
    return manifest_digest, bundle_digest


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


def _cleanup_attempt(attempt_root: Path, *, require_complete: bool) -> list[str]:
    if attempt_root.parent != LAB / "runs" or not re.fullmatch(r"attempt-[12]", attempt_root.name):
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


def _verify_bundle(bundle: Path) -> dict[str, object]:
    result = _run(
        [
            sys.executable,
            str(ROOT / "scripts/check_m4_runtime_evidence.py"),
            "--evidence",
            str(bundle),
        ],
        timeout=60,
    )
    value = _strict_json(result.stdout.rstrip(b"\n"), 1 << 20)
    if type(value) is not dict or value.get("outcome") != "VERIFIED":
        _stop("FINAL_EVIDENCE_VERIFICATION_FAILED")
    return value


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


def _qualification() -> dict[str, object]:
    goal_digest = _digest_file(USER_GOAL, 1 << 20)
    source = _source_state()
    profile, profile_digest = _profile()
    image, qemu_version = _verify_host_assets()
    tools = _verify_host_tools()
    _verify_kvm()
    _verify_management_port_free()
    remaining = _verify_disk_budget(IMAGE_LAB.parent)
    start: AttemptStart | None = None
    admission_digest: str | None = None
    bundle: Path | None = None
    cleanup_complete = False
    phase_outcomes: dict[str, object] = {}
    with AttemptLedger(
        LAB,
        goal_reference=str(USER_GOAL),
        goal_digest=goal_digest,
    ) as ledger:
        attempt = ledger.next_attempt()
        _mkdir_exact(LAB / "runs", 0o700)
        attempt_root = LAB / "runs" / f"attempt-{attempt}"
        if attempt_root.exists() or attempt_root.is_symlink():
            _stop("ATTEMPT_ROOT_REUSE_FORBIDDEN")
        attempt_root.mkdir(mode=0o700)
        try:
            seed, client_key, host_key = _create_seed(
                attempt_root,
                attempt=attempt,
                source=source,
            )
            known_hosts = attempt_root / "known_hosts"
            _known_hosts(host_key.with_suffix(".pub"), known_hosts)
            provenance = _host_provenance(
                image,
                qemu_version=qemu_version,
                seed_digest=_digest_file(seed, _MAX_SEED_BYTES),
                attempt=attempt,
            )
            environment = _digest_bytes(
                _canonical(
                    {
                        "host_provenance": provenance,
                        "profile_digest": profile_digest,
                    }
                )
            )
            request = {
                "request_version": "1.0.0",
                "candidate": source["commit"],
                "environment": environment,
                "attempt": attempt,
            }
            start = ledger.begin(
                str(source["commit"]), str(source["tree"]), environment
            )
            _create_overlay(attempt_root)
            _, phase_outcomes["provision"] = _provision_vm(
                attempt_root,
                attempt,
                client_key,
                known_hosts,
                host_provenance=provenance,
                request=request,
            )
            run_result, admission_digest, _, phase_outcomes["run"] = _run_vm_phase(
                attempt_root,
                attempt,
                "run",
                client_key,
                known_hosts,
                ledger=ledger,
                start=start,
            )
            if admission_digest is None:
                _stop("KEY_ADMISSION_ABSENT")
            recover_result, _, _, phase_outcomes["recover"] = _run_vm_phase(
                attempt_root,
                attempt,
                "recover",
                client_key,
                known_hosts,
                ledger=ledger,
                start=start,
            )
            bundle_value = recover_result.get("bundle")
            if type(bundle_value) is not str:
                _stop("EVIDENCE_EXPORT_ABSENT")
            bundle = Path(bundle_value)
            removed = _cleanup_attempt(attempt_root, require_complete=True)
            cleanup_complete = True
            manifest_digest, bundle_digest = _bundle_digests(bundle, admission_digest)
            ledger.terminalize(
                start,
                admission_digest,
                "BUNDLE_EXPORTED",
                manifest_digest=manifest_digest,
                bundle_digest=bundle_digest,
                qemu_phase_outcomes=phase_outcomes,
            )
            verified = _verify_bundle(bundle)
            return {
                "outcome": "VERIFIED",
                "claim": verified["claim_status"],
                "status": "NOT_ATTESTED",
                "candidate": source["commit"],
                "tree": source["tree"],
                "environment": environment,
                "attempt": attempt,
                "bundle": str(bundle),
                "evidence_bundle_digest": verified["evidence_bundle_digest"],
                "host_tool_digests": tools,
                "disk_bytes_remaining_after_worst_case": remaining,
                "run_result_digest": _digest_bytes(_canonical(run_result)),
                "recovery_result_digest": _digest_bytes(_canonical(recover_result)),
                "removed_disposable_files": sorted(removed),
                "preserved_base_image": str(IMAGE_LAB / _IMAGE_NAME),
            }
        except BaseException as error:
            if isinstance(error, VMCleanupUnproven):
                raise
            try:
                _cleanup_attempt(attempt_root, require_complete=False)
                cleanup_complete = True
            except QualificationStop:
                cleanup_complete = False
            if start is not None and ledger.active_start is not None and cleanup_complete:
                ledger.terminalize(start, ledger.active_admission, "QUARANTINED")
            raise


def _absent(reason: str) -> dict[str, object]:
    return {
        "outcome": "ABSENT",
        "claim": "M4_EXACT_DISPOSABLE_TEST_PROFILE_RUNTIME_CONFORMANCE",
        "reason": reason,
        "status": "NOT_ATTESTED",
    }


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    try:
        if not arguments:
            result = _qualification()
        elif len(arguments) == 2 and arguments[0] == "--key-ready-diagnostic":
            result = _key_ready_diagnostic(Path(arguments[1]))
        else:
            _stop("M4_HOST_ARGUMENTS_FORBIDDEN")
    except (OSError, ValueError, QualificationStop) as error:
        reason = str(error) if str(error) else "M4_HOST_QUALIFICATION_FAILED"
        sys.stdout.buffer.write(_canonical(_absent(reason)) + b"\n")
        return 1
    sys.stdout.buffer.write(_canonical(result) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
