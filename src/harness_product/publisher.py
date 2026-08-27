"""Exact M4 publication boundary for one disposable local filesystem target.

The caller never supplies a target descriptor, path, bytes, command, or
environment to :meth:`TrustedPublisher.publish`.  Those values come from one
closed, externally verified topology record and one sealed snapshot.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import fcntl
import json
import os
import re
import stat
from typing import Callable

from . import l0
from .durable import VerificationResult, VerificationStatus, canonical_digest


_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_TIME = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_SUBJECT_KEYS = frozenset(
    {
        "principal_id",
        "session_id",
        "uid",
        "gid",
        "security_label",
        "credential_namespace",
        "namespace_id",
        "executable_digest",
    }
)
_SUBJECT_ROLES = ("WORKER", "CONTROLLER", "EXECUTOR", "OBSERVER", "PUBLISHER")
_TOPOLOGY_KEYS = frozenset(
    {
        "topology_version",
        "assurance_scope",
        "topology_id",
        "observed_at",
        "expires_at",
        "profile_digest",
        "placement_digest",
        "session_id",
        "revocation_epoch",
        "fencing_epoch",
        "staging_binding",
        "publication_target_binding",
        "publication_root_anchor",
        "subjects",
        "sole_writer_principal",
        "denied_writer_principals",
        "git_authority",
        "transport",
        "topology_digest",
    }
)
_ANCHOR_KEYS = frozenset(
    {
        "anchor_version",
        "mount_namespace_id",
        "mount_id",
        "mountpoint",
        "root_path",
        "basename",
        "root_identity",
        "ancestry",
        "anchor_digest",
    }
)
_ANCESTRY_KEYS = frozenset({"component", "device", "inode", "mode", "mount_id"})
_SOURCE_KEYS = frozenset({"verifier_id", "issuer_id", "key_id", "proof"})
_AUTHORIZATION_KEYS = frozenset(
    {
        "authorization_version",
        "transaction_id",
        "decision_digest",
        "authorized_envelope_digest",
        "claim_digest",
        "intent_digest",
        "capability_id",
        "contract_digest",
        "d2_frontier_digest",
        "attempt_cursor",
        "iteration",
        "target_authority_digest",
        "publication_target_binding_digest",
        "publication_root_anchor_digest",
        "snapshot_id",
        "snapshot_digest",
        "snapshot_size",
        "seal_record_digest",
        "postcheck_record_digest",
        "profile_digest",
        "placement_digest",
        "session_id",
        "revocation_epoch",
        "fencing_epoch",
        "publisher_principal",
        "publisher_session",
        "issued_at",
        "observed_at",
        "expires_at",
        "authorization_digest",
    }
)


class PublisherOutcome(str, Enum):
    READY = "READY"
    PUBLISHED = "PUBLISHED"
    ABSENT = "ABSENT"
    STOP = "STOP"
    UNCERTAIN = "UNCERTAIN"


class PublisherReason(str, Enum):
    READY = "READY"
    PUBLISHED = "PUBLISHED"
    MALFORMED_INPUT = "MALFORMED_INPUT"
    TOPOLOGY_UNVERIFIED = "TOPOLOGY_UNVERIFIED"
    DEPLOYMENT_TOPOLOGY_ABSENT = "DEPLOYMENT_TOPOLOGY_ABSENT"
    SUBJECT_MISMATCH = "SUBJECT_MISMATCH"
    TARGET_MISMATCH = "TARGET_MISMATCH"
    SNAPSHOT_MISMATCH = "SNAPSHOT_MISMATCH"
    AUTHORIZATION_REJECTED = "AUTHORIZATION_REJECTED"
    PUBLICATION_FAILED = "PUBLICATION_FAILED"
    PUBLICATION_UNCERTAIN = "PUBLICATION_UNCERTAIN"


class _Stop(Exception):
    def __init__(self, reason: PublisherReason) -> None:
        self.reason = reason


@dataclass(frozen=True, slots=True)
class SecuritySubject:
    principal_id: str
    session_id: str
    uid: int
    gid: int
    security_label: str
    credential_namespace: str
    namespace_id: str
    executable_digest: str

    def data(self) -> dict[str, object]:
        return {
            "principal_id": self.principal_id,
            "session_id": self.session_id,
            "uid": self.uid,
            "gid": self.gid,
            "security_label": self.security_label,
            "credential_namespace": self.credential_namespace,
            "namespace_id": self.namespace_id,
            "executable_digest": self.executable_digest,
        }


@dataclass(frozen=True, slots=True)
class PublicationAncestryEntry:
    component: str
    device: int
    inode: int
    mode: int
    mount_id: str

    def data(self) -> dict[str, object]:
        return {
            "component": self.component,
            "device": self.device,
            "inode": self.inode,
            "mode": self.mode,
            "mount_id": self.mount_id,
        }


@dataclass(frozen=True, slots=True)
class PublicationRootAnchor:
    mount_namespace_id: str
    mount_id: str
    mountpoint: str
    root_path: str
    basename: str
    root_identity: str
    ancestry: tuple[PublicationAncestryEntry, ...]
    anchor_digest: str

    def data(self) -> dict[str, object]:
        return {
            "anchor_version": 1,
            "mount_namespace_id": self.mount_namespace_id,
            "mount_id": self.mount_id,
            "mountpoint": self.mountpoint,
            "root_path": self.root_path,
            "basename": self.basename,
            "root_identity": self.root_identity,
            "ancestry": [entry.data() for entry in self.ancestry],
            "anchor_digest": self.anchor_digest,
        }


@dataclass(frozen=True, slots=True)
class PublisherTopology:
    assurance_scope: str
    topology_id: str
    observed_at: str
    expires_at: str
    profile_digest: str
    placement_digest: str
    session_id: str
    revocation_epoch: int
    fencing_epoch: int
    staging_binding: l0.PathBinding
    publication_target_binding: l0.PathBinding
    publication_root_anchor: PublicationRootAnchor
    subjects: tuple[tuple[str, SecuritySubject], ...]
    sole_writer_principal: str
    denied_writer_principals: tuple[str, ...]
    topology_digest: str

    def subject(self, role: str) -> SecuritySubject:
        for name, value in self.subjects:
            if name == role:
                return value
        raise KeyError(role)

    def data(self) -> dict[str, object]:
        return {
            "topology_version": 1,
            "assurance_scope": self.assurance_scope,
            "topology_id": self.topology_id,
            "observed_at": self.observed_at,
            "expires_at": self.expires_at,
            "profile_digest": self.profile_digest,
            "placement_digest": self.placement_digest,
            "session_id": self.session_id,
            "revocation_epoch": self.revocation_epoch,
            "fencing_epoch": self.fencing_epoch,
            "staging_binding": self.staging_binding.data(),
            "publication_target_binding": self.publication_target_binding.data(),
            "publication_root_anchor": self.publication_root_anchor.data(),
            "subjects": {name: subject.data() for name, subject in self.subjects},
            "sole_writer_principal": self.sole_writer_principal,
            "denied_writer_principals": list(self.denied_writer_principals),
            "git_authority": "DENY",
            "transport": "SEALED_FD_ONLY",
            "topology_digest": self.topology_digest,
        }


@dataclass(frozen=True, slots=True)
class TopologyResult:
    outcome: PublisherOutcome
    reason: PublisherReason
    topology: PublisherTopology | None = None


@dataclass(frozen=True, slots=True)
class PublicationFact:
    transaction_id: str
    decision_digest: str
    authorized_envelope_digest: str
    claim_digest: str
    intent_digest: str
    capability_id: str
    contract_digest: str
    d2_frontier_digest: str
    attempt_cursor: int
    iteration: int
    target_authority_digest: str
    publication_target_binding_digest: str
    publication_root_anchor_digest: str
    snapshot_id: str
    snapshot_digest: str
    snapshot_size: int
    before_binding: l0.PathBinding
    published_binding: l0.PathBinding
    publisher_subject: SecuritySubject
    profile_digest: str
    placement_digest: str
    session_id: str
    revocation_epoch: int
    fencing_epoch: int
    authorization_digest: str
    issued_at: str
    observed_at: str
    expires_at: str
    receipt_digest: str

    def data(self) -> dict[str, object]:
        return {
            "receipt_version": 1,
            "outcome": "PUBLISHED",
            "transaction_id": self.transaction_id,
            "decision_digest": self.decision_digest,
            "authorized_envelope_digest": self.authorized_envelope_digest,
            "claim_digest": self.claim_digest,
            "intent_digest": self.intent_digest,
            "capability_id": self.capability_id,
            "contract_digest": self.contract_digest,
            "d2_frontier_digest": self.d2_frontier_digest,
            "attempt_cursor": self.attempt_cursor,
            "iteration": self.iteration,
            "target_authority_digest": self.target_authority_digest,
            "publication_target_binding_digest": self.publication_target_binding_digest,
            "publication_root_anchor_digest": self.publication_root_anchor_digest,
            "snapshot_id": self.snapshot_id,
            "snapshot_digest": self.snapshot_digest,
            "snapshot_size": self.snapshot_size,
            "before_binding": self.before_binding.data(),
            "published_binding": self.published_binding.data(),
            "publisher_subject": self.publisher_subject.data(),
            "profile_digest": self.profile_digest,
            "placement_digest": self.placement_digest,
            "session_id": self.session_id,
            "revocation_epoch": self.revocation_epoch,
            "fencing_epoch": self.fencing_epoch,
            "authorization_digest": self.authorization_digest,
            "publication_method": "ATOMIC_REPLACE_FSYNC",
            "issued_at": self.issued_at,
            "observed_at": self.observed_at,
            "expires_at": self.expires_at,
            "receipt_digest": self.receipt_digest,
        }


@dataclass(frozen=True, slots=True)
class PublicationResult:
    outcome: PublisherOutcome
    reason: PublisherReason
    fact: PublicationFact | None = None


def _closed(value: object, keys: frozenset[str]) -> dict[str, object]:
    if type(value) is not dict or frozenset(value) != keys:
        raise _Stop(PublisherReason.MALFORMED_INPUT)
    return value


def _identifier(value: object) -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise _Stop(PublisherReason.MALFORMED_INPUT)
    return value


def _digest(value: object) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise _Stop(PublisherReason.MALFORMED_INPUT)
    return value


def _integer(value: object, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum or value > (1 << 63) - 1:
        raise _Stop(PublisherReason.MALFORMED_INPUT)
    return value


def _time(value: object) -> datetime:
    if type(value) is not str or _TIME.fullmatch(value) is None:
        raise _Stop(PublisherReason.MALFORMED_INPUT)
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as error:
        raise _Stop(PublisherReason.MALFORMED_INPUT) from error


def _subject(raw: object) -> SecuritySubject:
    value = _closed(raw, _SUBJECT_KEYS)
    return SecuritySubject(
        _identifier(value["principal_id"]),
        _identifier(value["session_id"]),
        _integer(value["uid"], 1),
        _integer(value["gid"], 1),
        _identifier(value["security_label"]),
        _identifier(value["credential_namespace"]),
        _identifier(value["namespace_id"]),
        _digest(value["executable_digest"]),
    )


def _physical_path(value: object) -> str:
    if (
        type(value) is not str
        or not value.startswith("/")
        or len(value.encode("utf-8")) > 4096
        or "\x00" in value
        or value != os.path.normpath(value)
        or value.endswith(" (deleted)")
        or ".git" in value.split("/")
    ):
        raise _Stop(PublisherReason.TARGET_MISMATCH)
    return value


def _path_component(value: object) -> str:
    if (
        type(value) is not str
        or value in {"", ".", "..", ".git"}
        or "/" in value
        or "\x00" in value
        or len(value.encode("utf-8")) > 255
    ):
        raise _Stop(PublisherReason.TARGET_MISMATCH)
    return value


def _parse_anchor(raw: object) -> PublicationRootAnchor:
    value = _closed(raw, _ANCHOR_KEYS)
    if value["anchor_version"] != 1:
        raise _Stop(PublisherReason.MALFORMED_INPUT)
    root_path = _physical_path(value["root_path"])
    mountpoint = _physical_path(value["mountpoint"])
    basename = _path_component(value["basename"])
    components = tuple(component for component in root_path.split("/") if component)
    if not components or components[-1] != basename:
        raise _Stop(PublisherReason.TARGET_MISMATCH)
    ancestry_raw = value["ancestry"]
    if type(ancestry_raw) is not list or len(ancestry_raw) != len(components):
        raise _Stop(PublisherReason.MALFORMED_INPUT)
    ancestry: list[PublicationAncestryEntry] = []
    for component, raw_entry in zip(components, ancestry_raw, strict=True):
        entry = _closed(raw_entry, _ANCESTRY_KEYS)
        if (
            _path_component(entry["component"]) != component
            or entry["mode"] != stat.S_IFDIR
        ):
            raise _Stop(PublisherReason.TARGET_MISMATCH)
        ancestry.append(
            PublicationAncestryEntry(
                component,
                _integer(entry["device"]),
                _integer(entry["inode"], 1),
                entry["mode"],
                _identifier(entry["mount_id"]),
            )
        )
    body = {key: value[key] for key in value if key != "anchor_digest"}
    anchor_digest = _digest(value["anchor_digest"])
    if canonical_digest(body) != anchor_digest:
        raise _Stop(PublisherReason.TOPOLOGY_UNVERIFIED)
    return PublicationRootAnchor(
        _identifier(value["mount_namespace_id"]),
        _identifier(value["mount_id"]),
        mountpoint,
        root_path,
        basename,
        _digest(value["root_identity"]),
        tuple(ancestry),
        anchor_digest,
    )


def _mountpoint(mount_id: int) -> str:
    def unescape(value: str) -> str:
        def replacement(match: re.Match[str]) -> str:
            return chr(int(match.group(1), 8))

        decoded = re.sub(r"\\([0-7]{3})", replacement, value)
        if "\\" in decoded:
            raise _Stop(PublisherReason.TARGET_MISMATCH)
        return decoded

    matches: list[str] = []
    for line in l0._read_text("/proc/self/mountinfo", 1 << 20).splitlines():
        fields = line.split()
        if len(fields) >= 10 and fields[0] == str(mount_id) and "-" in fields:
            matches.append(unescape(fields[4]))
    if len(matches) != 1:
        raise _Stop(PublisherReason.TARGET_MISMATCH)
    return _physical_path(matches[0])


def _measure_publication_root(root_descriptor: int) -> PublicationRootAnchor:
    if type(root_descriptor) is not int or root_descriptor < 0:
        raise _Stop(PublisherReason.MALFORMED_INPUT)
    root_info, mount_id, root_identity, _ = l0._root_identity(root_descriptor)
    root_path = _physical_path(os.readlink(f"/proc/self/fd/{root_descriptor}"))
    components = tuple(component for component in root_path.split("/") if component)
    if not components:
        raise _Stop(PublisherReason.TARGET_MISMATCH)
    namespace = os.stat("/proc/self/ns/mnt")
    parent = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    ancestry: list[PublicationAncestryEntry] = []
    try:
        for component in components:
            _path_component(component)
            child = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=parent,
            )
            os.close(parent)
            parent = child
            info = os.fstat(child)
            ancestry.append(
                PublicationAncestryEntry(
                    component,
                    info.st_dev,
                    info.st_ino,
                    stat.S_IFMT(info.st_mode),
                    f"mnt:{l0._mount_id(child)}",
                )
            )
        anchored = os.fstat(parent)
        if (
            anchored.st_dev != root_info.st_dev
            or anchored.st_ino != root_info.st_ino
            or stat.S_IFMT(anchored.st_mode) != stat.S_IFDIR
        ):
            raise _Stop(PublisherReason.TARGET_MISMATCH)
    finally:
        os.close(parent)
    body: dict[str, object] = {
        "anchor_version": 1,
        "mount_namespace_id": f"mntns:{namespace.st_dev}:{namespace.st_ino}",
        "mount_id": f"mnt:{mount_id}",
        "mountpoint": _mountpoint(mount_id),
        "root_path": root_path,
        "basename": components[-1],
        "root_identity": root_identity,
        "ancestry": [entry.data() for entry in ancestry],
    }
    return PublicationRootAnchor(
        body["mount_namespace_id"],
        body["mount_id"],
        body["mountpoint"],
        root_path,
        components[-1],
        root_identity,
        tuple(ancestry),
        canonical_digest(body),
    )


def compile_topology(raw: object) -> TopologyResult:
    """Normalize one closed topology record without touching the filesystem."""

    try:
        value = _closed(raw, _TOPOLOGY_KEYS)
        if value["topology_version"] != 1:
            raise _Stop(PublisherReason.MALFORMED_INPUT)
        scope = value["assurance_scope"]
        if scope not in {"CODE_MODEL_FIXTURE", "DEPLOYMENT_ATTESTED"}:
            raise _Stop(PublisherReason.MALFORMED_INPUT)
        observed = _time(value["observed_at"])
        expires = _time(value["expires_at"])
        if observed >= expires:
            raise _Stop(PublisherReason.MALFORMED_INPUT)
        subjects_value = _closed(value["subjects"], frozenset(_SUBJECT_ROLES))
        subjects = tuple((role, _subject(subjects_value[role])) for role in _SUBJECT_ROLES)
        identities = [
            (
                subject.principal_id,
                subject.session_id,
                subject.uid,
                subject.gid,
                subject.security_label,
                subject.credential_namespace,
                subject.namespace_id,
            )
            for _, subject in subjects
        ]
        if (
            len(set(identities)) != len(identities)
            or len({item[0] for item in identities}) != len(identities)
            or len({item[1] for item in identities}) != len(identities)
            or len({item[2] for item in identities}) != len(identities)
            or len({item[3] for item in identities}) != len(identities)
            or len({item[4] for item in identities}) != len(identities)
            or len({item[5] for item in identities}) != len(identities)
            or len({item[6] for item in identities}) != len(identities)
        ):
            raise _Stop(PublisherReason.SUBJECT_MISMATCH)
        staging = l0._parse_path_binding(value["staging_binding"])
        publication = l0._parse_path_binding(value["publication_target_binding"])
        publication_anchor = _parse_anchor(value["publication_root_anchor"])
        if (
            staging.canonical_path != publication.canonical_path
            or ".git" in publication.canonical_path.split("/")
            or staging.root_identity == publication.root_identity
            or staging.root_id == publication.root_id
            or staging.composite_binding_digest == publication.composite_binding_digest
            or publication_anchor.root_identity != publication.root_identity
            or publication_anchor.mount_id != publication.mount_id
        ):
            raise _Stop(PublisherReason.TARGET_MISMATCH)
        publisher_subject = dict(subjects)["PUBLISHER"]
        denied = tuple(value["denied_writer_principals"]) if type(value["denied_writer_principals"]) is list else ()
        expected_denied = tuple(sorted(dict(subjects)[role].principal_id for role in _SUBJECT_ROLES[:-1]))
        if (
            denied != expected_denied
            or value["sole_writer_principal"] != publisher_subject.principal_id
            or value["git_authority"] != "DENY"
            or value["transport"] != "SEALED_FD_ONLY"
        ):
            raise _Stop(PublisherReason.SUBJECT_MISMATCH)
        body = {key: value[key] for key in value if key != "topology_digest"}
        supplied = _digest(value["topology_digest"])
        if canonical_digest(body) != supplied:
            raise _Stop(PublisherReason.TOPOLOGY_UNVERIFIED)
        topology = PublisherTopology(
            scope,
            _identifier(value["topology_id"]),
            value["observed_at"],
            value["expires_at"],
            _digest(value["profile_digest"]),
            _digest(value["placement_digest"]),
            _identifier(value["session_id"]),
            _integer(value["revocation_epoch"]),
            _integer(value["fencing_epoch"], 1),
            staging,
            publication,
            publication_anchor,
            subjects,
            publisher_subject.principal_id,
            denied,
            supplied,
        )
        return TopologyResult(PublisherOutcome.READY, PublisherReason.READY, topology)
    except Exception as error:
        reason = error.reason if isinstance(error, _Stop) else PublisherReason.MALFORMED_INPUT
        return TopologyResult(PublisherOutcome.STOP, reason)


def _external_verification_record(
    payload: dict[str, object], source: object
) -> dict[str, object] | None:
    try:
        source_value = _closed(source, _SOURCE_KEYS)
        for field in ("verifier_id", "issuer_id", "key_id"):
            _identifier(source_value[field])
        proof = source_value["proof"]
        if type(proof) is not str or not proof or len(proof.encode("utf-8")) > 8192:
            return None
        payload_digest = canonical_digest(payload)
        return {
            "verification_version": 1,
            "verifier_id": source_value["verifier_id"],
            "issuer_id": source_value["issuer_id"],
            "key_id": source_value["key_id"],
            "payload_digest": payload_digest,
            "bindings": payload,
            "proof": proof,
        }
    except Exception:
        return None


def verify_external(
    verifier_factory: object,
    payload: dict[str, object],
    source: object,
    observed_at: str,
) -> bool:
    """Independently verify one full canonical payload through a closed boundary."""

    try:
        _time(observed_at)
        record = _external_verification_record(payload, source)
        if record is None:
            return False
        payload_digest = canonical_digest(payload)
        verifier = verifier_factory() if callable(verifier_factory) else verifier_factory
        result = verifier.verify(
            json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8"),
            json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8"),
            observed_at,
        )
        return (
            type(result) is VerificationResult
            and result.status is VerificationStatus.VERIFIED
            and result.verifier_id == record["verifier_id"]
            and result.payload_digest == payload_digest
            and result.record_digest == canonical_digest(record)
        )
    except Exception:
        return False


class TrustedPublisher:
    """Single exact-root publisher; publication requests contain no effect data."""

    def __init__(
        self,
        *,
        profile: l0.CompiledL0Profile,
        root_descriptor: int,
        topology: PublisherTopology,
        topology_verification: object,
        verifier_factory: object,
    ) -> None:
        if type(root_descriptor) is not int or root_descriptor < 0:
            raise ValueError("invalid trusted publication root")
        self._profile = profile
        self._root = fcntl.fcntl(root_descriptor, fcntl.F_DUPFD_CLOEXEC, 3)
        self._topology = topology
        self._topology_verification = topology_verification
        self._verifier_factory = verifier_factory
        try:
            if _measure_publication_root(self._root) != topology.publication_root_anchor:
                raise ValueError("publication root anchor mismatch")
        except Exception as error:
            os.close(self._root)
            raise ValueError("invalid trusted publication root anchor") from error

    @property
    def topology(self) -> PublisherTopology:
        return self._topology

    def continuity(self) -> bool:
        """Re-measure the deployment-owned physical root and full ancestry."""

        try:
            return (
                _measure_publication_root(self._root)
                == self._topology.publication_root_anchor
            )
        except Exception:
            return False

    def _current_target(self) -> tuple[int, l0.PathBinding]:
        binding = self._topology.publication_target_binding
        _, relative = l0._canonical_stage_path(binding.canonical_path)
        descriptor = l0._openat2(
            self._root,
            relative,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        current = l0._binding_for_open_target(
            self._profile,
            self._root,
            descriptor,
            binding.canonical_path,
            binding.descriptor_id,
            binding.root_id,
            binding.resolution_epoch,
        )
        return descriptor, current

    def deployment_preflight(self, observed_at: str) -> PublicationResult:
        """Require physical subject/root facts; normal developer hosts stay ABSENT."""

        try:
            if self._topology.assurance_scope != "DEPLOYMENT_ATTESTED":
                return PublicationResult(
                    PublisherOutcome.ABSENT, PublisherReason.DEPLOYMENT_TOPOLOGY_ABSENT
                )
            publisher = self._topology.subject("PUBLISHER")
            root = os.fstat(self._root)
            if (
                os.geteuid() != publisher.uid
                or os.getegid() != publisher.gid
                or root.st_uid != publisher.uid
                or root.st_gid != publisher.gid
                or stat.S_IMODE(root.st_mode) & 0o022
                or not self.continuity()
            ):
                return PublicationResult(
                    PublisherOutcome.ABSENT, PublisherReason.DEPLOYMENT_TOPOLOGY_ABSENT
                )
            descriptor, current = self._current_target()
            os.close(descriptor)
            if current != self._topology.publication_target_binding:
                return PublicationResult(PublisherOutcome.STOP, PublisherReason.TARGET_MISMATCH)
            if not verify_external(
                self._verifier_factory,
                self._topology.data(),
                self._topology_verification,
                observed_at,
            ):
                return PublicationResult(PublisherOutcome.STOP, PublisherReason.TOPOLOGY_UNVERIFIED)
            return PublicationResult(PublisherOutcome.READY, PublisherReason.READY)
        except Exception:
            return PublicationResult(PublisherOutcome.STOP, PublisherReason.PUBLICATION_FAILED)

    def publish(
        self,
        snapshot_descriptor: object,
        authorization: object,
        authorization_verification: object,
        observed_at: object,
        *,
        _fault: Callable[[str], None] | None = None,
    ) -> PublicationResult:
        target = -1
        parent = -1
        temporary = -1
        temporary_name: str | None = None
        publication_attempted = False
        try:
            if type(snapshot_descriptor) is not int or snapshot_descriptor < 0:
                raise _Stop(PublisherReason.SNAPSHOT_MISMATCH)
            if type(observed_at) is not str:
                raise _Stop(PublisherReason.MALFORMED_INPUT)
            observed = _time(observed_at)
            topology_observed = _time(self._topology.observed_at)
            topology_expires = _time(self._topology.expires_at)
            if not (topology_observed <= observed < topology_expires):
                raise _Stop(PublisherReason.TOPOLOGY_UNVERIFIED)
            if not self.continuity():
                raise _Stop(PublisherReason.TARGET_MISMATCH)
            if self._topology.assurance_scope == "DEPLOYMENT_ATTESTED":
                preflight = self.deployment_preflight(observed_at)
                if preflight.outcome is not PublisherOutcome.READY:
                    return preflight
            if not verify_external(
                self._verifier_factory,
                self._topology.data(),
                self._topology_verification,
                observed_at,
            ):
                raise _Stop(PublisherReason.TOPOLOGY_UNVERIFIED)
            value = _closed(authorization, _AUTHORIZATION_KEYS)
            body = {key: value[key] for key in value if key != "authorization_digest"}
            auth_digest = _digest(value["authorization_digest"])
            if canonical_digest(body) != auth_digest:
                raise _Stop(PublisherReason.AUTHORIZATION_REJECTED)
            expires = _time(value["expires_at"])
            if (
                observed >= expires
                or value["issued_at"] != observed_at
                or value["observed_at"] != observed_at
            ):
                raise _Stop(PublisherReason.AUTHORIZATION_REJECTED)
            publisher = self._topology.subject("PUBLISHER")
            if (
                value["authorization_version"] != 1
                or value["target_authority_digest"] != self._topology.topology_digest
                or value["publication_target_binding_digest"]
                != self._topology.publication_target_binding.composite_binding_digest
                or value["publication_root_anchor_digest"]
                != self._topology.publication_root_anchor.anchor_digest
                or value["attempt_cursor"] != value["iteration"]
                or value["profile_digest"] != self._topology.profile_digest
                or value["placement_digest"] != self._topology.placement_digest
                or value["session_id"] != self._topology.session_id
                or value["revocation_epoch"] != self._topology.revocation_epoch
                or value["fencing_epoch"] != self._topology.fencing_epoch
                or value["publisher_principal"] != publisher.principal_id
                or value["publisher_session"] != publisher.session_id
            ):
                raise _Stop(PublisherReason.AUTHORIZATION_REJECTED)
            for field in (
                "transaction_id", "snapshot_id", "session_id", "publisher_principal", "publisher_session"
            ):
                _identifier(value[field])
            for field in (
                "decision_digest", "authorized_envelope_digest", "claim_digest",
                "intent_digest", "capability_id", "contract_digest", "d2_frontier_digest",
                "target_authority_digest", "publication_target_binding_digest",
                "publication_root_anchor_digest",
                "snapshot_digest", "seal_record_digest", "postcheck_record_digest",
                "profile_digest", "placement_digest",
            ):
                _digest(value[field])
            _integer(value["attempt_cursor"], 1)
            _integer(value["iteration"], 1)
            _integer(value["snapshot_size"])
            _integer(value["revocation_epoch"])
            _integer(value["fencing_epoch"], 1)
            if not verify_external(
                self._verifier_factory, value, authorization_verification, observed_at
            ):
                raise _Stop(PublisherReason.AUTHORIZATION_REJECTED)
            snapshot = os.fstat(snapshot_descriptor)
            if (
                not stat.S_ISREG(snapshot.st_mode)
                or snapshot.st_size != value["snapshot_size"]
                or fcntl.fcntl(snapshot_descriptor, fcntl.F_GET_SEALS) & (
                    fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_WRITE | fcntl.F_SEAL_SEAL
                )
                != (fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_WRITE | fcntl.F_SEAL_SEAL)
                or l0._hash_descriptor(
                    snapshot_descriptor, l0._resource_limit(self._profile, "OUTPUT_BYTES")
                )
                != value["snapshot_digest"]
            ):
                raise _Stop(PublisherReason.SNAPSHOT_MISMATCH)
            target, before = self._current_target()
            if before != self._topology.publication_target_binding:
                raise _Stop(PublisherReason.TARGET_MISMATCH)
            if not self.continuity():
                raise _Stop(PublisherReason.TARGET_MISMATCH)
            os.close(target)
            target = -1
            _, relative = l0._canonical_stage_path(before.canonical_path)
            parts = relative.split("/")
            basename = parts.pop()
            parent = fcntl.fcntl(self._root, fcntl.F_DUPFD_CLOEXEC, 3)
            for component in parts:
                next_parent = l0._openat2(
                    parent,
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                )
                os.close(parent)
                parent = next_parent
            temporary_name = ".harness-m4-" + auth_digest.removeprefix("sha256:")[:24] + ".tmp"
            temporary = os.open(
                temporary_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600,
                dir_fd=parent,
            )
            offset = 0
            size = value["snapshot_size"]
            while offset < size:
                chunk = os.pread(snapshot_descriptor, min(65536, size - offset), offset)
                if not chunk or os.pwrite(temporary, chunk, offset) != len(chunk):
                    raise _Stop(PublisherReason.PUBLICATION_FAILED)
                offset += len(chunk)
            os.fsync(temporary)
            if _fault is not None:
                _fault("publisher_before_replace")
            if not self.continuity():
                raise _Stop(PublisherReason.TARGET_MISMATCH)
            current_descriptor, current = self._current_target()
            os.close(current_descriptor)
            if current != before:
                raise _Stop(PublisherReason.TARGET_MISMATCH)
            if not verify_external(
                self._verifier_factory,
                self._topology.data(),
                self._topology_verification,
                observed_at,
            ):
                raise _Stop(PublisherReason.TOPOLOGY_UNVERIFIED)
            if not self.continuity():
                raise _Stop(PublisherReason.TARGET_MISMATCH)
            if _fault is not None:
                # The deployment conformance runtime pauses here to prove that
                # a denied principal cannot relocate the physical root after
                # the final pre-replace checks.  The hook supplies no authority
                # and the publication still uses the already-bound parent FD.
                _fault("publisher_after_pre_replace_checks")
            publication_attempted = True
            os.replace(temporary_name, basename, src_dir_fd=parent, dst_dir_fd=parent)
            temporary_name = None
            if _fault is not None:
                _fault("publisher_after_replace")
            os.fsync(parent)
            if not self.continuity():
                raise _Stop(PublisherReason.PUBLICATION_UNCERTAIN)
            target, published = self._current_target()
            if (
                published.final_digest != value["snapshot_digest"]
                or published.canonical_path != before.canonical_path
                or published.root_identity != before.root_identity
                or published.mount_identity != before.mount_identity
                or published.resolution_epoch != before.resolution_epoch
                or not self.continuity()
            ):
                raise _Stop(PublisherReason.PUBLICATION_UNCERTAIN)
            receipt_body = {
                "receipt_version": 1,
                "outcome": "PUBLISHED",
                "transaction_id": value["transaction_id"],
                "decision_digest": value["decision_digest"],
                "authorized_envelope_digest": value["authorized_envelope_digest"],
                "claim_digest": value["claim_digest"],
                "intent_digest": value["intent_digest"],
                "capability_id": value["capability_id"],
                "contract_digest": value["contract_digest"],
                "d2_frontier_digest": value["d2_frontier_digest"],
                "attempt_cursor": value["attempt_cursor"],
                "iteration": value["iteration"],
                "target_authority_digest": self._topology.topology_digest,
                "publication_target_binding_digest": value[
                    "publication_target_binding_digest"
                ],
                "publication_root_anchor_digest": value[
                    "publication_root_anchor_digest"
                ],
                "snapshot_id": value["snapshot_id"],
                "snapshot_digest": value["snapshot_digest"],
                "snapshot_size": value["snapshot_size"],
                "before_binding": before.data(),
                "published_binding": published.data(),
                "publisher_subject": publisher.data(),
                "profile_digest": value["profile_digest"],
                "placement_digest": value["placement_digest"],
                "session_id": value["session_id"],
                "revocation_epoch": value["revocation_epoch"],
                "fencing_epoch": value["fencing_epoch"],
                "authorization_digest": auth_digest,
                "publication_method": "ATOMIC_REPLACE_FSYNC",
                "issued_at": observed_at,
                "observed_at": observed_at,
                "expires_at": value["expires_at"],
            }
            fact = PublicationFact(
                value["transaction_id"],
                value["decision_digest"],
                value["authorized_envelope_digest"],
                value["claim_digest"],
                value["intent_digest"],
                value["capability_id"],
                value["contract_digest"],
                value["d2_frontier_digest"],
                value["attempt_cursor"],
                value["iteration"],
                self._topology.topology_digest,
                value["publication_target_binding_digest"],
                value["publication_root_anchor_digest"],
                value["snapshot_id"],
                value["snapshot_digest"],
                value["snapshot_size"],
                before,
                published,
                publisher,
                value["profile_digest"],
                value["placement_digest"],
                value["session_id"],
                value["revocation_epoch"],
                value["fencing_epoch"],
                auth_digest,
                observed_at,
                observed_at,
                value["expires_at"],
                canonical_digest(receipt_body),
            )
            return PublicationResult(PublisherOutcome.PUBLISHED, PublisherReason.PUBLISHED, fact)
        except Exception as error:
            reason = error.reason if isinstance(error, _Stop) else PublisherReason.PUBLICATION_FAILED
            if publication_attempted:
                return PublicationResult(PublisherOutcome.UNCERTAIN, PublisherReason.PUBLICATION_UNCERTAIN)
            return PublicationResult(PublisherOutcome.STOP, reason)
        finally:
            if temporary_name is not None and parent >= 0:
                try:
                    os.unlink(temporary_name, dir_fd=parent)
                    os.fsync(parent)
                except OSError:
                    pass
            for descriptor in (temporary, target, parent):
                if descriptor >= 0:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass


__all__ = [
    "PublicationFact",
    "PublicationResult",
    "PublisherOutcome",
    "PublisherReason",
    "PublisherTopology",
    "SecuritySubject",
    "TopologyResult",
    "TrustedPublisher",
    "compile_topology",
]
