"""Closed Ed25519 verification boundary for the exact M3 test profile.

The module is deliberately not exported from :mod:`harness_product`.  It has
no import-time effects and grants no capability: callers still have to check
the verified, canonical bindings at their own authoritative transition.
"""

from __future__ import annotations

import base64
import binascii
import ctypes
from datetime import UTC, datetime
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
from typing import Callable, NoReturn

from .durable import VerificationResult, VerificationStatus


_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_TIME = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_RECORD_KEYS = frozenset(
    {
        "verification_version",
        "verifier_id",
        "issuer_id",
        "key_id",
        "payload_digest",
        "bindings",
        "proof",
    }
)
_TIME_KEYS = frozenset({"observed_at", "issued_at", "not_before", "expires_at"})
_MAX_INPUT = 8 << 20


class _Reject(Exception):
    pass


def _reject() -> NoReturn:
    raise _Reject


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


def _strict(raw: bytes) -> object:
    if type(raw) is not bytes or not raw or len(raw) > _MAX_INPUT:
        _reject()

    def pairs(rows: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in rows:
            if type(key) is not str or key in result:
                _reject()
            result[key] = value
        return result

    def constant(_: str) -> NoReturn:
        _reject()

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=pairs,
            parse_constant=constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise _Reject from error
    if _canonical(value) != raw:
        _reject()
    return value


def _timestamp(value: object) -> datetime:
    if type(value) is not str or not _TIME.fullmatch(value):
        _reject()
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as error:
        raise _Reject from error


def _open_regular(path: Path, expected_digest: str, maximum: int) -> tuple[int, bytes]:
    if not _DIGEST.fullmatch(expected_digest):
        _reject()
    info = os.lstat(path)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) & 0o022
        or info.st_size < 1
        or info.st_size > maximum
    ):
        _reject()
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (
            info.st_dev,
            info.st_ino,
            info.st_size,
        ):
            _reject()
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(65536, maximum + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                _reject()
            chunks.append(chunk)
        value = b"".join(chunks)
        if _digest_bytes(value) != expected_digest:
            _reject()
        return descriptor, value
    except Exception:
        os.close(descriptor)
        raise


def _read_regular(path: Path, expected_digest: str, maximum: int) -> bytes:
    descriptor, value = _open_regular(path, expected_digest, maximum)
    os.close(descriptor)
    return value


def _walk(value: object, *, maximum: int = 65536) -> list[dict[str, object]]:
    pending = [value]
    dictionaries: list[dict[str, object]] = []
    seen = 0
    while pending:
        current = pending.pop()
        seen += 1
        if seen > maximum:
            _reject()
        if type(current) is dict:
            dictionaries.append(current)
            pending.extend(current.values())
        elif type(current) is list:
            pending.extend(current)
    return dictionaries


def _authority_context(
    payload: dict[str, object],
    observed_at: str,
    now: datetime,
    expected_revocation_epoch: int | None,
    expected_fencing_epoch: int | None,
) -> None:
    requested = _timestamp(observed_at)
    if requested > now:
        _reject()
    revocations: list[int] = []
    fences: list[int] = []
    intervals = 0
    for item in _walk(payload):
        if "revocation_epoch" in item:
            value = item["revocation_epoch"]
            if type(value) is not int or value < 0:
                _reject()
            revocations.append(value)
        if "fencing_epoch" in item:
            value = item["fencing_epoch"]
            if type(value) is not int or value < 1:
                _reject()
            fences.append(value)
        present = _TIME_KEYS.intersection(item)
        if present:
            parsed = {key: _timestamp(item[key]) for key in present}
            if "observed_at" in parsed and parsed["observed_at"] > now:
                _reject()
            starts = [parsed[key] for key in ("not_before", "issued_at") if key in parsed]
            if starts and any(start > now for start in starts):
                _reject()
            if "expires_at" in parsed:
                intervals += 1
                if now >= parsed["expires_at"] or any(
                    start >= parsed["expires_at"] for start in starts
                ):
                    _reject()
    if intervals == 0:
        _reject()
    if expected_revocation_epoch is not None and (
        not revocations or any(value != expected_revocation_epoch for value in revocations)
    ):
        _reject()
    if expected_fencing_epoch is not None and (
        not fences or any(value != expected_fencing_epoch for value in fences)
    ):
        _reject()


def _ed25519_verify(
    library: ctypes.CDLL,
    public_key: bytes,
    payload: bytes,
    signature: bytes,
) -> bool:
    lines = public_key.strip().splitlines()
    if (
        len(lines) < 3
        or lines[0] != b"-----BEGIN PUBLIC KEY-----"
        or lines[-1] != b"-----END PUBLIC KEY-----"
    ):
        return False
    try:
        der = base64.b64decode(b"".join(lines[1:-1]), validate=True)
    except (ValueError, binascii.Error):
        return False
    prefix = bytes.fromhex("302a300506032b6570032100")
    if len(der) != 44 or not der.startswith(prefix):
        return False
    raw_key = der[len(prefix) :]
    library.EVP_PKEY_new_raw_public_key.argtypes = [
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
    ]
    library.EVP_PKEY_new_raw_public_key.restype = ctypes.c_void_p
    library.EVP_PKEY_free.argtypes = [ctypes.c_void_p]
    library.EVP_MD_CTX_new.restype = ctypes.c_void_p
    library.EVP_MD_CTX_free.argtypes = [ctypes.c_void_p]
    library.EVP_DigestVerifyInit.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    library.EVP_DigestVerify.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_size_t,
    ]
    key_buffer = ctypes.create_string_buffer(raw_key, len(raw_key))
    key = library.EVP_PKEY_new_raw_public_key(1087, None, key_buffer, len(raw_key))
    context = library.EVP_MD_CTX_new()
    if not key or not context:
        if key:
            library.EVP_PKEY_free(key)
        if context:
            library.EVP_MD_CTX_free(context)
        return False
    try:
        if library.EVP_DigestVerifyInit(context, None, None, None, key) != 1:
            return False
        signature_buffer = ctypes.create_string_buffer(signature, len(signature))
        payload_buffer = ctypes.create_string_buffer(payload, len(payload))
        return (
            library.EVP_DigestVerify(
                context,
                signature_buffer,
                len(signature),
                payload_buffer,
                len(payload),
            )
            == 1
        )
    finally:
        library.EVP_MD_CTX_free(context)
        library.EVP_PKEY_free(key)


class OpenSSLEd25519Verifier:
    """Verify one exact signed record; all failures become ``REJECTED``."""

    def __init__(
        self,
        *,
        verifier_id: str,
        issuer_id: str,
        key_id: str,
        public_key_path: str,
        public_key_digest: str,
        libcrypto_path: str,
        libcrypto_digest: str,
        verifier_code_path: str,
        verifier_code_digest: str,
        expected_revocation_epoch: int | None,
        expected_fencing_epoch: int | None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._verifier_id = verifier_id
        self._issuer_id = issuer_id
        self._key_id = key_id
        self._public_key_path = Path(public_key_path)
        self._public_key_digest = public_key_digest
        self._libcrypto_path = Path(libcrypto_path)
        self._libcrypto_digest = libcrypto_digest
        self._verifier_code_path = Path(verifier_code_path)
        self._verifier_code_digest = verifier_code_digest
        self._expected_revocation_epoch = expected_revocation_epoch
        self._expected_fencing_epoch = expected_fencing_epoch
        self._clock = clock if clock is not None else lambda: datetime.now(UTC)

    def verify(self, payload: bytes, record: bytes, observed_at: str) -> VerificationResult:
        payload_digest = _digest_bytes(payload) if type(payload) is bytes else _digest_bytes(b"")
        record_digest = _digest_bytes(record) if type(record) is bytes else _digest_bytes(b"")
        status = VerificationStatus.REJECTED
        try:
            payload_value = _strict(payload)
            record_value = _strict(record)
            if type(payload_value) is not dict or type(record_value) is not dict:
                _reject()
            if frozenset(record_value) != _RECORD_KEYS:
                _reject()
            if (
                record_value["verification_version"] not in {1, 3}
                or record_value["verifier_id"] != self._verifier_id
                or record_value["issuer_id"] != self._issuer_id
                or record_value["key_id"] != self._key_id
                or record_value["payload_digest"] != payload_digest
                or record_value["bindings"] != payload_value
            ):
                _reject()
            proof = record_value["proof"]
            if type(proof) is not str or len(proof) != 136 or not proof.startswith("ed25519:"):
                _reject()
            try:
                signature = bytes.fromhex(proof[8:])
            except ValueError as error:
                raise _Reject from error
            if len(signature) != 64:
                _reject()
            public_key = _read_regular(self._public_key_path, self._public_key_digest, 4096)
            _read_regular(self._verifier_code_path, self._verifier_code_digest, 1 << 20)
            reference = self._clock()
            if type(reference) is not datetime or reference.tzinfo is None:
                _reject()
            _authority_context(
                payload_value,
                observed_at,
                reference.astimezone(UTC).replace(microsecond=0),
                self._expected_revocation_epoch,
                self._expected_fencing_epoch,
            )
            libcrypto_descriptor, _ = _open_regular(
                self._libcrypto_path, self._libcrypto_digest, 16 << 20
            )
            try:
                library = ctypes.CDLL(
                    f"/proc/self/fd/{libcrypto_descriptor}", use_errno=True
                )
                if _ed25519_verify(library, public_key, payload, signature):
                    status = VerificationStatus.VERIFIED
            finally:
                os.close(libcrypto_descriptor)
        except Exception:
            status = VerificationStatus.REJECTED
        return VerificationResult(status, self._verifier_id, payload_digest, record_digest)


__all__ = ["OpenSSLEd25519Verifier"]
