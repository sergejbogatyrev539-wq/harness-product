"""Exact local M4 stage, kernel seal, postcheck, commit and JOIN coordinator.

This module is intentionally limited to the existing disconnected, stageable
filesystem profile.  It has no connector, external-effect or retry path.
"""

from __future__ import annotations

import ctypes
from dataclasses import asdict, dataclass
from enum import Enum
import errno
import fcntl
import json
import os
import re
import select
import signal
import stat
import time
from typing import Callable

from . import kernel, l0, publisher
from .durable import DispatchClaim, DurableOutcome, DurableStore, canonical_digest
from .model import (
    EffectKind,
    KernelResult,
    NormalizedInput,
    Operation,
    Outcome,
    PowerlessProposal,
    ProposalAuthority,
    ResourceKind,
    SelectorKind,
)


_INPUT_KEYS = frozenset(
    {
        "transaction_id",
        "d2_frontier_digest",
        "stage_request",
        "observed_at",
        "verifications",
        "external_verifications",
    }
)
_TIME_KEYS = frozenset(
    {
        "BEGIN",
        "STAGED",
        "QUIESCED",
        "SEALED",
        "POSTCHECKED",
        "COMMITTED",
        "JOINED",
        "QUARANTINED",
        "RECONCILING",
    }
)
_VERIFICATION_KEYS = _TIME_KEYS - {"BEGIN"}
_EXTERNAL_VERIFICATION_KEYS = frozenset(
    {
        "OBSERVER_RECEIPT",
        "PUBLICATION_AUTHORIZATION",
        "PUBLICATION_RECEIPT",
    }
)
_STAGE_KEYS = frozenset(
    {"transaction_id", "claim_digest", "operation", "content", "content_digest"}
)
_STAGE_RECORD_KEYS = frozenset(
    {
        "transaction_id",
        "claim_digest",
        "binding_digest",
        "before_digest",
        "after_digest",
        "bytes_written",
        "record_digest",
    }
)
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_MAX_REPORT = 1 << 20
_CHILD_TIMEOUT_SECONDS = 10.0
_SEAL_NAMES = ("F_SEAL_GROW", "F_SEAL_SEAL", "F_SEAL_SHRINK", "F_SEAL_WRITE")
_SEAL_VALUES = (
    fcntl.F_SEAL_GROW,
    fcntl.F_SEAL_SEAL,
    fcntl.F_SEAL_SHRINK,
    fcntl.F_SEAL_WRITE,
)
_SEAL_MASK = sum(_SEAL_VALUES)


class M4Outcome(str, Enum):
    JOINED = "JOINED"
    QUARANTINED = "QUARANTINED"
    STOPPED = "STOPPED"


class M4Reason(str, Enum):
    JOINED = "JOINED"
    MALFORMED_INPUT = "MALFORMED_INPUT"
    M1_REJECTED = "M1_REJECTED"
    CLAIM_REJECTED = "CLAIM_REJECTED"
    EXTERNAL_BRANCH_DENIED = "EXTERNAL_BRANCH_DENIED"
    STAGE_FAILED = "STAGE_FAILED"
    QUIESCENCE_FAILED = "QUIESCENCE_FAILED"
    SEAL_FAILED = "SEAL_FAILED"
    POSTCHECK_FAILED = "POSTCHECK_FAILED"
    PUBLICATION_FAILED = "PUBLICATION_FAILED"
    DURABLE_TRANSITION_FAILED = "DURABLE_TRANSITION_FAILED"
    RECONCILING = "RECONCILING"
    INTERNAL_ERROR = "INTERNAL_ERROR"


@dataclass(frozen=True, slots=True)
class M4Principals:
    controller_principal: str
    controller_session: str
    observer_principal: str
    observer_session: str


@dataclass(frozen=True, slots=True)
class M4Snapshot:
    snapshot_id: str
    device: int
    inode: int
    size: int
    digest: str
    kernel_seals: tuple[int, ...]
    write_denied: bool
    truncate_denied: bool


@dataclass(frozen=True, slots=True)
class M4Result:
    outcome: M4Outcome
    reason: M4Reason
    state: str
    transaction_id: str | None = None
    snapshot: M4Snapshot | None = None
    executor_pid: int | None = None
    executor_session: int | None = None
    observer_pid: int | None = None
    observer_session: int | None = None
    record_digest: str | None = None


class _M4Stop(Exception):
    def __init__(self, reason: M4Reason) -> None:
        self.reason = reason


@dataclass(slots=True)
class _ReadLease:
    descriptor: int
    device: int
    inode: int
    previous_owner: int
    previous_handler: object
    break_requested: bool = False
    active: bool = False


def _closed(value: object, keys: frozenset[str]) -> dict[str, object]:
    if type(value) is not dict or frozenset(value) != keys:
        raise _M4Stop(M4Reason.MALFORMED_INPUT)
    return value


def _identifier(value: object) -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise _M4Stop(M4Reason.MALFORMED_INPUT)
    return value


def _digest(value: object) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise _M4Stop(M4Reason.MALFORMED_INPUT)
    return value


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise _M4Stop(M4Reason.MALFORMED_INPUT) from error


def _strict_json(text: object) -> object:
    if type(text) is not str or len(text.encode("utf-8")) > _MAX_REPORT:
        raise _M4Stop(M4Reason.MALFORMED_INPUT)

    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    try:
        value = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)),
        )
    except (UnicodeError, ValueError, TypeError, json.JSONDecodeError) as error:
        raise _M4Stop(M4Reason.MALFORMED_INPUT) from error
    if _canonical(value).decode("utf-8") != text:
        raise _M4Stop(M4Reason.MALFORMED_INPUT)
    return value


def _evidence(body: dict[str, object]) -> dict[str, object]:
    value = dict(body)
    value["evidence_digest"] = canonical_digest(body)
    return value


def _linux_close_range(first: int, last: int) -> None:
    try:
        close_range = ctypes.CDLL(None, use_errno=True).close_range
    except (AttributeError, OSError) as error:
        raise OSError(errno.ENOSYS, "close_range unavailable") from error
    close_range.argtypes = (ctypes.c_uint, ctypes.c_uint, ctypes.c_uint)
    close_range.restype = ctypes.c_int
    ctypes.set_errno(0)
    if close_range(first, last, 0) != 0:
        error_number = ctypes.get_errno() or errno.EIO
        raise OSError(error_number, os.strerror(error_number))


def _close_except(keep: set[int]) -> None:
    maximum = (1 << (ctypes.sizeof(ctypes.c_uint) * 8)) - 1
    if any(
        type(descriptor) is not int or descriptor < 0 or descriptor > maximum
        for descriptor in keep
    ):
        raise OSError(errno.EOVERFLOW, "invalid descriptor allowlist")
    for descriptor in keep:
        fcntl.fcntl(descriptor, fcntl.F_GETFD)
    start = 0
    for descriptor in sorted(keep):
        if start < descriptor:
            _linux_close_range(start, descriptor - 1)
        start = descriptor + 1
    if start <= maximum:
        _linux_close_range(start, maximum)
    for descriptor in keep:
        fcntl.fcntl(descriptor, fcntl.F_GETFD)


def _write_all(descriptor: int, value: bytes) -> None:
    if len(value) > _MAX_REPORT:
        os._exit(126)
    offset = 0
    while offset < len(value):
        written = os.write(descriptor, value[offset:])
        if written <= 0:
            os._exit(126)
        offset += written


def _collect_child(pid: int, descriptor: int) -> dict[str, object]:
    chunks: list[bytes] = []
    total = 0
    deadline = time.monotonic() + _CHILD_TIMEOUT_SECONDS
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            readable, _, _ = select.select([descriptor], [], [], remaining)
            if not readable:
                raise TimeoutError
            chunk = os.read(descriptor, min(65536, _MAX_REPORT + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > _MAX_REPORT:
                raise ValueError("child report too large")
        _, status = os.waitpid(pid, 0)
        pid = -1
        if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
            raise ValueError("child failed")
        text = b"".join(chunks).decode("utf-8")
        value = _strict_json(text)
        if type(value) is not dict:
            raise ValueError("child report is not an object")
        return value
    except Exception as error:
        if pid > 0:
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
            try:
                os.waitpid(pid, 0)
            except OSError:
                pass
        raise _M4Stop(M4Reason.INTERNAL_ERROR) from error
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass


def _factory(factory: object) -> object:
    if not callable(factory):
        raise _M4Stop(M4Reason.MALFORMED_INPUT)
    value = factory()
    if value is None:
        raise _M4Stop(M4Reason.MALFORMED_INPUT)
    return value


def _stage_child(
    store: DurableStore,
    profile: l0.CompiledL0Profile,
    claim: DispatchClaim,
    supply: l0.SupplyVerification,
    root_descriptor: int,
    stage_request: dict[str, object],
    claim_verifier_factory: object,
    supply_verifier_factory: object,
) -> tuple[l0.StageRecord, int, int]:
    read_descriptor, write_descriptor = os.pipe2(os.O_CLOEXEC)
    pid = os.fork()
    if pid == 0:
        try:
            os.close(read_descriptor)
            os.setsid()
            _close_except({root_descriptor, write_descriptor})
            result = l0.stage_committed_intent(
                profile,
                claim,
                supply,
                root_descriptor,
                stage_request,
                durable_store=store,
                executor_claim_verifier=_factory(claim_verifier_factory),
                supply_verifier=_factory(supply_verifier_factory),
            )
            report = {
                "outcome": result.outcome.value,
                "reason": result.reason.value,
                "record": None if result.record is None else asdict(result.record),
                "pid": os.getpid(),
                "session": os.getsid(0),
            }
            _write_all(write_descriptor, _canonical(report).strip())
            os._exit(0)
        except BaseException:
            os._exit(125)
    os.close(write_descriptor)
    report = _collect_child(pid, read_descriptor)
    if report.get("outcome") != l0.L0Outcome.STAGED.value or report.get("reason") != l0.L0Reason.STAGED.value:
        raise _M4Stop(M4Reason.STAGE_FAILED)
    record_value = report.get("record")
    if type(record_value) is not dict or frozenset(record_value) != _STAGE_RECORD_KEYS:
        raise _M4Stop(M4Reason.STAGE_FAILED)
    try:
        record = l0.StageRecord(**record_value)
    except TypeError as error:
        raise _M4Stop(M4Reason.STAGE_FAILED) from error
    child_pid = report.get("pid")
    child_session = report.get("session")
    if type(child_pid) is not int or child_pid != pid or type(child_session) is not int or child_session != pid:
        raise _M4Stop(M4Reason.STAGE_FAILED)
    return record, pid, child_session


def _recheck_target(
    profile: l0.CompiledL0Profile,
    descriptor: int,
    binding: l0.PathBinding,
    reason: M4Reason = M4Reason.SEAL_FAILED,
) -> None:
    info = os.fstat(descriptor)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_dev != binding.final_device
        or info.st_ino != binding.final_inode
        or l0._mount_id(descriptor) != int(binding.mount_id.removeprefix("mnt:"))
        or l0._hash_descriptor(descriptor, l0._resource_limit(profile, "OUTPUT_BYTES"))
        != binding.final_digest
    ):
        raise _M4Stop(reason)


def _recheck_bound_path(
    profile: l0.CompiledL0Profile,
    root_descriptor: int,
    binding: l0.PathBinding,
) -> None:
    descriptor = -1
    try:
        _, relative = l0._canonical_stage_path(binding.canonical_path)
        descriptor = l0._openat2(
            root_descriptor,
            relative,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        observed = l0._binding_for_open_target(
            profile,
            root_descriptor,
            descriptor,
            binding.canonical_path,
            binding.descriptor_id,
            binding.root_id,
            binding.resolution_epoch,
        )
        if observed != binding:
            raise _M4Stop(M4Reason.QUIESCENCE_FAILED)
    except _M4Stop:
        raise
    except Exception as error:
        raise _M4Stop(M4Reason.QUIESCENCE_FAILED) from error
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _assert_read_lease(
    profile: l0.CompiledL0Profile,
    lease: _ReadLease,
    binding: l0.PathBinding,
) -> None:
    if not lease.active or lease.break_requested:
        raise _M4Stop(M4Reason.QUIESCENCE_FAILED)
    try:
        info = os.fstat(lease.descriptor)
        if (
            info.st_dev != lease.device
            or info.st_ino != lease.inode
            or fcntl.fcntl(lease.descriptor, fcntl.F_GETLEASE) != fcntl.F_RDLCK
            or fcntl.fcntl(lease.descriptor, fcntl.F_GETOWN) != os.getpid()
        ):
            raise _M4Stop(M4Reason.QUIESCENCE_FAILED)
        _recheck_target(
            profile,
            lease.descriptor,
            binding,
            M4Reason.QUIESCENCE_FAILED,
        )
    except _M4Stop:
        raise
    except Exception as error:
        raise _M4Stop(M4Reason.QUIESCENCE_FAILED) from error
    if lease.break_requested:
        raise _M4Stop(M4Reason.QUIESCENCE_FAILED)


def _release_read_lease(lease: _ReadLease) -> None:
    if lease.active:
        try:
            fcntl.fcntl(lease.descriptor, fcntl.F_SETLEASE, fcntl.F_UNLCK)
        except OSError:
            pass
        lease.active = False
    try:
        fcntl.fcntl(lease.descriptor, fcntl.F_SETOWN, lease.previous_owner)
    except OSError:
        pass
    try:
        signal.signal(signal.SIGIO, lease.previous_handler)
    except (OSError, ValueError):
        pass


def _acquire_read_lease(
    profile: l0.CompiledL0Profile,
    descriptor: int,
    binding: l0.PathBinding,
) -> _ReadLease:
    previous_handler: object | None = None
    previous_owner = 0
    lease: _ReadLease | None = None
    try:
        _recheck_target(profile, descriptor, binding, M4Reason.QUIESCENCE_FAILED)
        if (
            fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE
        ) != os.O_RDONLY or not (
            fcntl.fcntl(descriptor, fcntl.F_GETFD) & fcntl.FD_CLOEXEC
        ):
            raise _M4Stop(M4Reason.QUIESCENCE_FAILED)
        previous_handler = signal.getsignal(signal.SIGIO)
        previous_owner = fcntl.fcntl(descriptor, fcntl.F_GETOWN)
        info = os.fstat(descriptor)
        lease = _ReadLease(
            descriptor,
            info.st_dev,
            info.st_ino,
            previous_owner,
            previous_handler,
        )

        def break_handler(_signal: int, _frame: object) -> None:
            lease.break_requested = True

        signal.signal(signal.SIGIO, break_handler)
        fcntl.fcntl(descriptor, fcntl.F_SETOWN, os.getpid())
        fcntl.fcntl(descriptor, fcntl.F_SETLEASE, fcntl.F_RDLCK)
        lease.active = True
        _assert_read_lease(profile, lease, binding)
        return lease
    except _M4Stop:
        if lease is not None:
            _release_read_lease(lease)
        elif previous_handler is not None:
            try:
                fcntl.fcntl(descriptor, fcntl.F_SETOWN, previous_owner)
            except OSError:
                pass
            try:
                signal.signal(signal.SIGIO, previous_handler)
            except (OSError, ValueError):
                pass
        raise
    except Exception as error:
        if lease is not None:
            _release_read_lease(lease)
        elif previous_handler is not None:
            try:
                fcntl.fcntl(descriptor, fcntl.F_SETOWN, previous_owner)
            except OSError:
                pass
            try:
                signal.signal(signal.SIGIO, previous_handler)
            except (OSError, ValueError):
                pass
        raise _M4Stop(M4Reason.QUIESCENCE_FAILED) from error


def _denied(operation: Callable[[], object]) -> bool:
    try:
        operation()
    except OSError as error:
        # Linux may report EINVAL rather than EBADF for ftruncate on a
        # read-only descriptor.  Both are kernel denials; the parent also
        # proves F_SEAL_WRITE through a writable descriptor.
        return error.errno in {errno.EBADF, errno.EINVAL, errno.EPERM}
    return False


def _seal_snapshot(
    profile: l0.CompiledL0Profile,
    target_descriptor: int,
    binding: l0.PathBinding,
    fault: object | None,
) -> tuple[int, M4Snapshot]:
    maximum = l0._resource_limit(profile, "OUTPUT_BYTES")
    _recheck_target(profile, target_descriptor, binding)
    info = os.fstat(target_descriptor)
    if info.st_size <= 0 or info.st_size > maximum:
        raise _M4Stop(M4Reason.SEAL_FAILED)
    snapshot_descriptor = os.memfd_create(
        "harness-m4-seal",
        os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING,
    )
    try:
        offset = 0
        while offset < info.st_size:
            chunk = os.pread(target_descriptor, min(65536, info.st_size - offset), offset)
            if not chunk:
                raise OSError(errno.EIO, "short staged object")
            written = os.pwrite(snapshot_descriptor, chunk, offset)
            if written != len(chunk):
                raise OSError(errno.EIO, "short snapshot write")
            offset += written
        os.ftruncate(snapshot_descriptor, info.st_size)
        os.fsync(snapshot_descriptor)
        if fault is not None:
            fault("seal_after_copy")
        _recheck_target(profile, target_descriptor, binding)
        if l0._hash_descriptor(snapshot_descriptor, maximum) != binding.final_digest:
            raise _M4Stop(M4Reason.SEAL_FAILED)
        fcntl.fcntl(snapshot_descriptor, fcntl.F_ADD_SEALS, _SEAL_MASK)
        seals = fcntl.fcntl(snapshot_descriptor, fcntl.F_GET_SEALS)
        if seals != _SEAL_MASK:
            raise _M4Stop(M4Reason.SEAL_FAILED)
        snapshot_info = os.fstat(snapshot_descriptor)
        write_denied = _denied(lambda: os.pwrite(snapshot_descriptor, b"x", 0))
        truncate_denied = _denied(lambda: os.ftruncate(snapshot_descriptor, 0))
        if not write_denied or not truncate_denied:
            raise _M4Stop(M4Reason.SEAL_FAILED)
        snapshot = M4Snapshot(
            snapshot_id="sealed-" + binding.final_digest.removeprefix("sha256:")[:24],
            device=snapshot_info.st_dev,
            inode=snapshot_info.st_ino,
            size=snapshot_info.st_size,
            digest=binding.final_digest,
            kernel_seals=_SEAL_VALUES,
            write_denied=True,
            truncate_denied=True,
        )
        return snapshot_descriptor, snapshot
    except Exception:
        os.close(snapshot_descriptor)
        raise


def _postcheck_child(
    profile: l0.CompiledL0Profile,
    snapshot_descriptor: int,
    snapshot: M4Snapshot,
) -> tuple[int, int, int, int, str]:
    observer_descriptor = os.open(
        f"/proc/self/fd/{snapshot_descriptor}",
        os.O_RDONLY | os.O_CLOEXEC,
    )
    read_descriptor, write_descriptor = os.pipe2(os.O_CLOEXEC)
    pid = os.fork()
    if pid == 0:
        try:
            os.close(read_descriptor)
            os.setsid()
            _close_except({observer_descriptor, write_descriptor})
            info = os.fstat(observer_descriptor)
            access = fcntl.fcntl(observer_descriptor, fcntl.F_GETFL) & os.O_ACCMODE
            seals = fcntl.fcntl(observer_descriptor, fcntl.F_GET_SEALS)
            digest = l0._hash_descriptor(
                observer_descriptor,
                l0._resource_limit(profile, "OUTPUT_BYTES"),
            )
            write_denied = _denied(lambda: os.pwrite(observer_descriptor, b"x", 0))
            truncate_denied = _denied(lambda: os.ftruncate(observer_descriptor, 0))
            report = {
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
            _write_all(write_descriptor, _canonical(report).strip())
            os._exit(0)
        except BaseException:
            os._exit(125)
    os.close(write_descriptor)
    os.close(observer_descriptor)
    report = _collect_child(pid, read_descriptor)
    expected = {
        "device": snapshot.device,
        "inode": snapshot.inode,
        "size": snapshot.size,
        "digest": snapshot.digest,
        "seals": _SEAL_MASK,
        "read_only": True,
        "write_denied": True,
        "truncate_denied": True,
    }
    if any(report.get(key) != value for key, value in expected.items()):
        raise _M4Stop(M4Reason.POSTCHECK_FAILED)
    child_pid = report.get("pid")
    child_session = report.get("session")
    uid = report.get("uid")
    gid = report.get("gid")
    if (
        type(child_pid) is not int
        or child_pid != pid
        or type(child_session) is not int
        or child_session != pid
        or type(uid) is not int
        or uid < 1
        or type(gid) is not int
        or gid < 1
    ):
        raise _M4Stop(M4Reason.POSTCHECK_FAILED)
    postcheck_digest = canonical_digest(report)
    return child_pid, child_session, uid, gid, postcheck_digest


class M4Coordinator:
    """One fail-closed Controller/PEP path for the exact local M4 branch."""

    def __init__(
        self,
        *,
        store: DurableStore,
        profile: l0.CompiledL0Profile,
        staging_root_descriptor: int,
        topology: publisher.PublisherTopology,
        topology_verification: object,
        trusted_publisher: publisher.TrustedPublisher,
        executor_claim_verifier_factory: object,
        supply_verifier_factory: object,
        external_verifier_factory: object,
        principals: M4Principals,
    ) -> None:
        if type(staging_root_descriptor) is not int or staging_root_descriptor < 0:
            raise ValueError("invalid trusted staging root")
        if (
            type(profile) is not l0.CompiledL0Profile
            or not l0._profile_is_valid(profile)
            or type(topology) is not publisher.PublisherTopology
            or type(trusted_publisher) is not publisher.TrustedPublisher
            or trusted_publisher.topology != topology
            or type(principals) is not M4Principals
            or not all(
                callable(value)
                for value in (
                    executor_claim_verifier_factory,
                    supply_verifier_factory,
                    external_verifier_factory,
                )
            )
        ):
            raise ValueError("invalid trusted M4 publication boundary")
        self._store = store
        self._profile = profile
        self._staging_root = fcntl.fcntl(staging_root_descriptor, fcntl.F_DUPFD_CLOEXEC, 3)
        self._topology = topology
        self._topology_verification = topology_verification
        self._publisher = trusted_publisher
        self._claim_verifier_factory = executor_claim_verifier_factory
        self._supply_verifier_factory = supply_verifier_factory
        self._external_verifier_factory = external_verifier_factory
        self._principals = principals

    def _advance(
        self,
        transaction_id: str,
        expected_state: str,
        state: str,
        observed_at: dict[str, object],
        verifications: dict[str, object],
        evidence: dict[str, object],
    ) -> str:
        result = self._store.advance_m4(
            {
                "transaction_id": transaction_id,
                "expected_state": expected_state,
                "state": state,
                "observed_at": observed_at[state],
                "evidence": evidence,
                "verification": verifications[state],
            }
        )
        if not result.committed or result.m4_state != state or result.record_digest is None:
            raise _M4Stop(M4Reason.DURABLE_TRANSITION_FAILED)
        return result.record_digest

    def _validate_principals(self, claim: DispatchClaim) -> None:
        values = (
            self._principals.controller_principal,
            self._principals.controller_session,
            self._principals.observer_principal,
            self._principals.observer_session,
        )
        if not all(type(value) is str and _IDENTIFIER.fullmatch(value) for value in values):
            raise _M4Stop(M4Reason.MALFORMED_INPUT)
        if len(set(values)) != len(values):
            raise _M4Stop(M4Reason.MALFORMED_INPUT)
        if self._principals.controller_principal in {claim.principal_id, claim.audience_id}:
            raise _M4Stop(M4Reason.CLAIM_REJECTED)
        if self._principals.observer_principal in {claim.principal_id, claim.audience_id}:
            raise _M4Stop(M4Reason.CLAIM_REJECTED)
        if self._principals.controller_session == claim.session_id or self._principals.observer_session == claim.session_id:
            raise _M4Stop(M4Reason.CLAIM_REJECTED)
        subjects = {name: subject for name, subject in self._topology.subjects}
        if (
            subjects["WORKER"].principal_id != claim.principal_id
            or subjects["WORKER"].session_id != claim.session_id
            or subjects["EXECUTOR"].principal_id != claim.audience_id
            or subjects["CONTROLLER"].principal_id != self._principals.controller_principal
            or subjects["CONTROLLER"].session_id != self._principals.controller_session
            or subjects["OBSERVER"].principal_id != self._principals.observer_principal
            or subjects["OBSERVER"].session_id != self._principals.observer_session
        ):
            raise _M4Stop(M4Reason.CLAIM_REJECTED)

    def _admit(self, claim: DispatchClaim, source: l0.PathBinding) -> None:
        request = _strict_json(claim.request_json)
        result = kernel.evaluate(request)
        normalized = kernel.normalize(request)
        if (
            type(result) is not KernelResult
            or result.decision.outcome is not Outcome.ALLOW
            or not result.transition.accepted
            or len(result.transition.proposals) != 1
            or type(result.transition.proposals[0]) is not PowerlessProposal
            or result.transition.proposals[0].authority is not ProposalAuthority.NONE
            or type(normalized) is not NormalizedInput
        ):
            raise _M4Stop(M4Reason.M1_REJECTED)
        authority = normalized.proposal.authority
        if (
            authority.effect is not EffectKind.MUTATE
            or authority.resource is not ResourceKind.FILE
            or authority.operation is not Operation.WRITE
            or authority.selector.kind is not SelectorKind.PATH_EXACT
            or authority.selector.value != source.canonical_path
        ):
            raise _M4Stop(M4Reason.EXTERNAL_BRANCH_DENIED)

    def execute(
        self,
        claim: object,
        supply: object,
        raw: object,
        *,
        _fault: object | None = None,
    ) -> M4Result:
        root_descriptor = -1
        target_descriptor = -1
        snapshot_descriptor = -1
        read_lease: _ReadLease | None = None
        transaction_id: str | None = None
        state: str | None = None
        current_record_digest: str | None = None
        snapshot: M4Snapshot | None = None
        executor_pid: int | None = None
        executor_session: int | None = None
        observer_pid: int | None = None
        observer_session: int | None = None
        times: dict[str, object] | None = None
        verifications: dict[str, object] | None = None
        try:
            if type(claim) is not DispatchClaim or type(supply) is not l0.SupplyVerification:
                raise _M4Stop(M4Reason.MALFORMED_INPUT)
            value = _closed(raw, _INPUT_KEYS)
            transaction_id = _identifier(value["transaction_id"])
            _digest(value["d2_frontier_digest"])
            if transaction_id != claim.transaction_id:
                raise _M4Stop(M4Reason.CLAIM_REJECTED)
            root_descriptor = fcntl.fcntl(self._staging_root, fcntl.F_DUPFD_CLOEXEC, 3)
            if _fault is not None and not callable(_fault):
                raise _M4Stop(M4Reason.MALFORMED_INPUT)
            times = _closed(value["observed_at"], _TIME_KEYS)
            verifications = _closed(value["verifications"], _VERIFICATION_KEYS)
            external_verifications = _closed(
                value["external_verifications"], _EXTERNAL_VERIFICATION_KEYS
            )
            if not all(type(item) is str for item in times.values()):
                raise _M4Stop(M4Reason.MALFORMED_INPUT)
            if not all(
                type(item) is dict
                for item in (*verifications.values(), *external_verifications.values())
            ):
                raise _M4Stop(M4Reason.MALFORMED_INPUT)
            stage_input = _closed(value["stage_request"], _STAGE_KEYS)
            source = self._topology.staging_binding
            stage_request = {**stage_input, "target_binding": source.data()}
            if (
                stage_request["transaction_id"] != claim.transaction_id
                or stage_request["claim_digest"] != claim.claim_digest
            ):
                raise _M4Stop(M4Reason.CLAIM_REJECTED)
            if not l0._profile_is_valid(self._profile):
                raise _M4Stop(M4Reason.MALFORMED_INPUT)
            self._validate_principals(claim)
            self._admit(claim, source)
            if (
                claim.profile_digest != self._profile.profile_digest
                or supply.profile_digest != self._profile.profile_digest
                or supply.placement_digest != claim.placement_digest
                or supply.session_id != claim.session_id
                or supply.revocation_epoch != claim.revocation_epoch
                or supply.fencing_epoch != claim.fencing_epoch
                or claim.target_authority_digest != self._topology.topology_digest
                or self._topology.profile_digest != claim.profile_digest
                or self._topology.placement_digest != claim.placement_digest
                or self._topology.session_id != claim.session_id
                or self._topology.revocation_epoch != claim.revocation_epoch
                or self._topology.fencing_epoch != claim.fencing_epoch
                or self._publisher.topology != self._topology
            ):
                raise _M4Stop(M4Reason.CLAIM_REJECTED)
            if not publisher.verify_external(
                self._external_verifier_factory,
                self._topology.data(),
                self._topology_verification,
                times["BEGIN"],
            ):
                raise _M4Stop(M4Reason.CLAIM_REJECTED)
            l0._root_identity(root_descriptor)
            _, relative = l0._canonical_stage_path(source.canonical_path)
            target_descriptor = l0._openat2(
                root_descriptor,
                relative,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            if l0._binding_for_open_target(
                self._profile,
                root_descriptor,
                target_descriptor,
                source.canonical_path,
                source.descriptor_id,
                source.root_id,
                source.resolution_epoch,
            ) != source:
                raise _M4Stop(M4Reason.CLAIM_REJECTED)
            verified = self._store.verify_dispatch_claim(
                {
                    "transaction_id": claim.transaction_id,
                    "claim_digest": claim.claim_digest,
                    "audience_id": claim.audience_id,
                    "placement_digest": claim.placement_digest,
                    "session_id": claim.session_id,
                    "revocation_epoch": claim.revocation_epoch,
                    "fencing_epoch": claim.fencing_epoch,
                    "observed_at": times["BEGIN"],
                }
            )
            if verified.outcome is not DurableOutcome.OK or verified.dispatch_claim != claim:
                raise _M4Stop(M4Reason.CLAIM_REJECTED)
            begun = self._store.begin_m4_transaction(
                {
                    "transaction_id": transaction_id,
                    "d2_frontier_digest": value["d2_frontier_digest"],
                    "target_binding": source.data(),
                    "observed_at": times["BEGIN"],
                    "stage_authorization_verification": verifications["STAGED"],
                }
            )
            if (
                not begun.committed
                or begun.m4_state != "DISPATCHED"
                or begun.m4_iteration is None
                or begun.frontier_record_digest is None
                or begun.record_digest is None
            ):
                raise _M4Stop(M4Reason.DURABLE_TRANSITION_FAILED)
            state = "DISPATCHED"
            if _fault is not None:
                _fault("after_dispatch")
            stage_request = {
                **stage_request,
                "stage_authorization_digest": begun.record_digest,
                "observed_at": times["STAGED"],
            }
            stage_record, executor_pid, executor_session = _stage_child(
                self._store,
                self._profile,
                claim,
                supply,
                root_descriptor,
                stage_request,
                self._claim_verifier_factory,
                self._supply_verifier_factory,
            )
            staged = l0._binding_for_open_target(
                self._profile,
                root_descriptor,
                target_descriptor,
                source.canonical_path,
                source.descriptor_id,
                source.root_id,
                source.resolution_epoch,
            )
            if (
                stage_record.transaction_id != transaction_id
                or stage_record.claim_digest != claim.claim_digest
                or stage_record.binding_digest != source.composite_binding_digest
                or stage_record.before_digest != source.final_digest
                or stage_record.after_digest != staged.final_digest
                or staged.final_digest != claim.material_digest
            ):
                raise _M4Stop(M4Reason.STAGE_FAILED)
            current_record_digest = self._advance(
                transaction_id,
                state,
                "STAGED",
                times,
                verifications,
                {
                    "evidence_version": 1,
                    "stage_record": asdict(stage_record),
                    "source_object_binding": source.data(),
                    "staged_object_binding": staged.data(),
                },
            )
            state = "STAGED"
            if _fault is not None:
                _fault("after_stage")
            _recheck_bound_path(self._profile, root_descriptor, staged)
            read_lease = _acquire_read_lease(
                self._profile,
                target_descriptor,
                staged,
            )
            _assert_read_lease(self._profile, read_lease, staged)
            _recheck_bound_path(self._profile, root_descriptor, staged)
            quiesce = _evidence(
                {
                    "evidence_version": 1,
                    "process_tree_id": supply.process_tree_id,
                    "session_id": claim.session_id,
                    "writer_fencing_epoch": claim.fencing_epoch,
                    "revoked_writer_fds": [root_descriptor],
                    "remaining_writer_fds": [],
                    "writer_leases_revoked": True,
                    "process_tree_quiesced": True,
                }
            )
            current_record_digest = self._advance(
                transaction_id, state, "QUIESCED", times, verifications, quiesce
            )
            state = "QUIESCED"
            _assert_read_lease(self._profile, read_lease, staged)
            _recheck_bound_path(self._profile, root_descriptor, staged)
            snapshot_descriptor, snapshot = _seal_snapshot(
                self._profile, target_descriptor, staged, _fault
            )
            _assert_read_lease(self._profile, read_lease, staged)
            _recheck_bound_path(self._profile, root_descriptor, staged)
            seal = _evidence(
                {
                    "evidence_version": 1,
                    "seal_type": "LINUX_MEMFD",
                    "source_object_binding": staged.data(),
                    "snapshot_id": snapshot.snapshot_id,
                    "snapshot_device": snapshot.device,
                    "snapshot_inode": snapshot.inode,
                    "snapshot_size": snapshot.size,
                    "snapshot_digest": snapshot.digest,
                    "kernel_seals": list(_SEAL_NAMES),
                    "sealer_principal": self._principals.controller_principal,
                    "sealer_session": self._principals.controller_session,
                }
            )
            current_record_digest = self._advance(
                transaction_id, state, "SEALED", times, verifications, seal
            )
            seal_record_digest = current_record_digest
            state = "SEALED"
            _assert_read_lease(self._profile, read_lease, staged)
            _recheck_bound_path(self._profile, root_descriptor, staged)
            if _fault is not None:
                _fault("after_seal")
            _assert_read_lease(self._profile, read_lease, staged)
            _recheck_bound_path(self._profile, root_descriptor, staged)
            observer_pid, observer_session, observer_uid, observer_gid, postcheck_digest = _postcheck_child(
                self._profile, snapshot_descriptor, snapshot
            )
            _assert_read_lease(self._profile, read_lease, staged)
            _recheck_bound_path(self._profile, root_descriptor, staged)
            capability_payload = _strict_json(claim.capability_payload_json)
            if type(capability_payload) is not dict:
                raise _M4Stop(M4Reason.CLAIM_REJECTED)
            observer_subject = self._topology.subject("OBSERVER")
            observer_body = {
                "receipt_version": 1,
                "outcome": "PASS",
                "transaction_id": transaction_id,
                "capability_id": claim.capability_id,
                "claim_digest": claim.claim_digest,
                "intent_digest": claim.intent_digest,
                "decision_digest": capability_payload["decision_digest"],
                "authorized_envelope_digest": capability_payload[
                    "authorized_envelope_digest"
                ],
                "target_authority_digest": self._topology.topology_digest,
                "profile_digest": claim.profile_digest,
                "placement_digest": claim.placement_digest,
                "session_id": claim.session_id,
                "seal_record_digest": seal_record_digest,
                "snapshot_id": snapshot.snapshot_id,
                "snapshot_device": snapshot.device,
                "snapshot_inode": snapshot.inode,
                "snapshot_size": snapshot.size,
                "snapshot_digest": snapshot.digest,
                "observer_subject": observer_subject.data(),
                "proposal_digest": postcheck_digest,
                "revocation_epoch": claim.revocation_epoch,
                "fencing_epoch": claim.fencing_epoch,
                "observed_at": times["POSTCHECKED"],
            }
            observer_receipt = {
                **observer_body,
                "receipt_digest": canonical_digest(observer_body),
            }
            if not publisher.verify_external(
                self._external_verifier_factory,
                observer_receipt,
                external_verifications["OBSERVER_RECEIPT"],
                times["POSTCHECKED"],
            ):
                raise _M4Stop(M4Reason.POSTCHECK_FAILED)
            observer_verification = publisher._external_verification_record(
                observer_receipt, external_verifications["OBSERVER_RECEIPT"]
            )
            if observer_verification is None:
                raise _M4Stop(M4Reason.POSTCHECK_FAILED)
            postcheck = _evidence(
                {
                    "evidence_version": 1,
                    "seal_record_digest": seal_record_digest,
                    "snapshot_id": snapshot.snapshot_id,
                    "snapshot_device": snapshot.device,
                    "snapshot_inode": snapshot.inode,
                    "snapshot_size": snapshot.size,
                    "snapshot_digest": snapshot.digest,
                    "observer_receipt": observer_receipt,
                    "observer_verification": observer_verification,
                }
            )
            current_record_digest = self._advance(
                transaction_id, state, "POSTCHECKED", times, verifications, postcheck
            )
            postcheck_record_digest = current_record_digest
            state = "POSTCHECKED"
            _assert_read_lease(self._profile, read_lease, staged)
            if _fault is not None:
                _fault("after_postcheck")
            _assert_read_lease(self._profile, read_lease, staged)
            _recheck_bound_path(self._profile, root_descriptor, staged)
            authorization_body = {
                "authorization_version": 1,
                "transaction_id": transaction_id,
                "decision_digest": capability_payload["decision_digest"],
                "authorized_envelope_digest": capability_payload[
                    "authorized_envelope_digest"
                ],
                "claim_digest": claim.claim_digest,
                "intent_digest": claim.intent_digest,
                "capability_id": claim.capability_id,
                "contract_digest": capability_payload["contract_digest"],
                "d2_frontier_digest": value["d2_frontier_digest"],
                "iteration": begun.m4_iteration,
                "target_authority_digest": self._topology.topology_digest,
                "publication_target_binding_digest": (
                    self._topology.publication_target_binding.composite_binding_digest
                ),
                "snapshot_id": snapshot.snapshot_id,
                "snapshot_digest": snapshot.digest,
                "snapshot_size": snapshot.size,
                "seal_record_digest": seal_record_digest,
                "postcheck_record_digest": postcheck_record_digest,
                "profile_digest": claim.profile_digest,
                "placement_digest": claim.placement_digest,
                "session_id": claim.session_id,
                "revocation_epoch": claim.revocation_epoch,
                "fencing_epoch": claim.fencing_epoch,
                "publisher_principal": self._topology.subject("PUBLISHER").principal_id,
                "publisher_session": self._topology.subject("PUBLISHER").session_id,
                "observed_at": times["COMMITTED"],
                "expires_at": self._topology.expires_at,
            }
            authorization = {
                **authorization_body,
                "authorization_digest": canonical_digest(authorization_body),
            }
            publication_result = self._publisher.publish(
                snapshot_descriptor,
                authorization,
                external_verifications["PUBLICATION_AUTHORIZATION"],
                times["COMMITTED"],
                _fault=_fault,
            )
            if (
                publication_result.outcome is not publisher.PublisherOutcome.PUBLISHED
                or publication_result.fact is None
            ):
                raise _M4Stop(M4Reason.PUBLICATION_FAILED)
            publication_receipt = publication_result.fact.data()
            if not publisher.verify_external(
                self._external_verifier_factory,
                publication_receipt,
                external_verifications["PUBLICATION_RECEIPT"],
                times["COMMITTED"],
            ):
                raise _M4Stop(M4Reason.PUBLICATION_FAILED)
            publication_authorization_verification = publisher._external_verification_record(
                authorization, external_verifications["PUBLICATION_AUTHORIZATION"]
            )
            publication_verification = publisher._external_verification_record(
                publication_receipt, external_verifications["PUBLICATION_RECEIPT"]
            )
            if (
                publication_authorization_verification is None
                or publication_verification is None
            ):
                raise _M4Stop(M4Reason.PUBLICATION_FAILED)
            _assert_read_lease(self._profile, read_lease, staged)
            _recheck_bound_path(self._profile, root_descriptor, staged)
            if _fault is not None:
                _fault("before_commit_record")
            if not self._publisher.continuity():
                raise _M4Stop(M4Reason.PUBLICATION_FAILED)
            _assert_read_lease(self._profile, read_lease, staged)
            _recheck_bound_path(self._profile, root_descriptor, staged)
            commit = _evidence(
                {
                    "evidence_version": 1,
                    "seal_record_digest": seal_record_digest,
                    "postcheck_record_digest": postcheck_record_digest,
                    "snapshot_id": snapshot.snapshot_id,
                    "snapshot_device": snapshot.device,
                    "snapshot_inode": snapshot.inode,
                    "snapshot_size": snapshot.size,
                    "snapshot_digest": snapshot.digest,
                    "publication_authorization": authorization,
                    "publication_authorization_verification": publication_authorization_verification,
                    "publication_receipt": publication_receipt,
                    "publication_verification": publication_verification,
                }
            )
            if not self._publisher.continuity():
                raise _M4Stop(M4Reason.PUBLICATION_FAILED)
            current_record_digest = self._advance(
                transaction_id, state, "COMMITTED", times, verifications, commit
            )
            state = "COMMITTED"
            if _fault is not None:
                _fault("after_commit")
            if not self._publisher.continuity():
                raise _M4Stop(M4Reason.PUBLICATION_FAILED)
            _assert_read_lease(self._profile, read_lease, staged)
            _recheck_bound_path(self._profile, root_descriptor, staged)
            join = _evidence(
                {
                    "evidence_version": 1,
                    "commit_record_digest": current_record_digest,
                    "joined_iteration": begun.m4_iteration,
                    "frontier_record_digest": begun.frontier_record_digest,
                    "controller_principal": self._principals.controller_principal,
                    "controller_session": self._principals.controller_session,
                }
            )
            if not self._publisher.continuity():
                raise _M4Stop(M4Reason.PUBLICATION_FAILED)
            current_record_digest = self._advance(
                transaction_id, state, "JOINED", times, verifications, join
            )
            state = "JOINED"
            return M4Result(
                M4Outcome.JOINED,
                M4Reason.JOINED,
                state,
                transaction_id,
                snapshot,
                executor_pid,
                executor_session,
                observer_pid,
                observer_session,
                current_record_digest,
            )
        except _M4Stop as stop:
            reason = stop.reason
        except Exception:
            reason = M4Reason.INTERNAL_ERROR
        finally:
            if read_lease is not None:
                _release_read_lease(read_lease)
            for descriptor in (snapshot_descriptor, target_descriptor, root_descriptor):
                if descriptor >= 0:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass

        if transaction_id is not None and state is not None and times is not None and verifications is not None:
            try:
                if state == "COMMITTED" and current_record_digest is not None:
                    record_digest = self._advance(
                        transaction_id,
                        state,
                        "RECONCILING",
                        times,
                        verifications,
                        _evidence(
                            {
                                "evidence_version": 1,
                                "quarantine_record_digest": current_record_digest,
                            }
                        ),
                    )
                    return M4Result(
                        M4Outcome.QUARANTINED,
                        M4Reason.RECONCILING,
                        "RECONCILING",
                        transaction_id,
                        snapshot,
                        executor_pid,
                        executor_session,
                        observer_pid,
                        observer_session,
                        record_digest,
                    )
                if state in {"DISPATCHED", "STAGED", "QUIESCED", "SEALED", "POSTCHECKED"}:
                    uncertainty = "M4_" + reason.value
                    record_digest = self._advance(
                        transaction_id,
                        state,
                        "QUARANTINED",
                        times,
                        verifications,
                        _evidence(
                            {
                                "evidence_version": 1,
                                "uncertainty": uncertainty,
                            }
                        ),
                    )
                    return M4Result(
                        M4Outcome.QUARANTINED,
                        reason,
                        "QUARANTINED",
                        transaction_id,
                        snapshot,
                        executor_pid,
                        executor_session,
                        observer_pid,
                        observer_session,
                        record_digest,
                    )
            except Exception:
                pass
        return M4Result(
            M4Outcome.STOPPED,
            reason,
            state or "STOPPED",
            transaction_id,
            snapshot,
            executor_pid,
            executor_session,
            observer_pid,
            observer_session,
            current_record_digest,
        )
