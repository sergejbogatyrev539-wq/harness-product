"""Immutable values for the non-effectful M1 policy kernel.

These values describe proposals and abstract authority only.  They are not
capabilities, attestations, durable records, or enforcement mechanisms.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from hashlib import sha256
import json


class EffectKind(str, Enum):
    COMPUTE = "COMPUTE"
    OBSERVE = "OBSERVE"
    MUTATE = "MUTATE"
    COMMUNICATE = "COMMUNICATE"
    DELEGATE = "DELEGATE"
    REFLECT = "REFLECT"


class ResourceKind(str, Enum):
    FILE = "FILE"
    DIRECTORY = "DIRECTORY"
    PROCESS = "PROCESS"
    ENDPOINT = "ENDPOINT"
    PRINCIPAL = "PRINCIPAL"
    MEMORY = "MEMORY"
    PROMPT = "PROMPT"
    POLICY = "POLICY"
    REGISTRY = "REGISTRY"
    COMPUTE_RESOURCE = "COMPUTE_RESOURCE"


class Operation(str, Enum):
    READ = "READ"
    LIST = "LIST"
    WRITE = "WRITE"
    CREATE = "CREATE"
    DELETE = "DELETE"
    EXECUTE = "EXECUTE"
    SEND = "SEND"
    SPAWN = "SPAWN"
    UPDATE = "UPDATE"
    BIND = "BIND"
    ALLOCATE = "ALLOCATE"


class Facet(str, Enum):
    EXECUTE_EFFECT = "EXECUTE_EFFECT"
    AUTHORIZE_EFFECT = "AUTHORIZE_EFFECT"
    DECLASSIFY_DATA = "DECLASSIFY_DATA"
    ENDORSE_DATA = "ENDORSE_DATA"
    PERSIST_SCHEDULE = "PERSIST_SCHEDULE"
    ALLOCATE_RESOURCE = "ALLOCATE_RESOURCE"


class QuantityUnit(str, Enum):
    CALLS = "CALLS"
    BYTES = "BYTES"
    FILES = "FILES"
    MESSAGES = "MESSAGES"
    AGENTS = "AGENTS"
    TOKENS = "TOKENS"
    MILLISECONDS = "MILLISECONDS"
    CPU_MILLISECONDS = "CPU_MILLISECONDS"
    MIB = "MIB"
    OPERATIONS = "OPERATIONS"


class SelectorKind(str, Enum):
    """Logical selector kinds; resolving them physically is outside M1."""

    PATH_EXACT = "PATH_EXACT"
    PATH_PREFIX = "PATH_PREFIX"
    ENDPOINT_EXACT = "ENDPOINT_EXACT"
    LOCAL_EXACT = "LOCAL_EXACT"


class Stage(str, Enum):
    NORMALIZE = "NORMALIZE"
    CLASSIFY = "CLASSIFY"
    DERIVE = "DERIVE"
    DECIDE = "DECIDE"
    TRANSITION = "TRANSITION"


class Outcome(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    STOP = "STOP"


class Reason(str, Enum):
    MALFORMED_INPUT = "MALFORMED_INPUT"
    UNKNOWN_INPUT = "UNKNOWN_INPUT"
    UNBOUNDED_INPUT = "UNBOUNDED_INPUT"
    STALE_INPUT = "STALE_INPUT"
    BINDING_MISMATCH = "BINDING_MISMATCH"
    TYPED_SCOPE_MISMATCH = "TYPED_SCOPE_MISMATCH"
    AUTHORITY_EXCEEDED = "AUTHORITY_EXCEEDED"
    ILLEGAL_TRANSITION = "ILLEGAL_TRANSITION"
    AUTHORIZED_EXACT_BOUND = "AUTHORIZED_EXACT_BOUND"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class ProposalAuthority(str, Enum):
    NONE = "NONE"


class Phase(str, Enum):
    STOPPED = "STOPPED"
    DECIDED = "DECIDED"


# One closed relation: independently valid enum members cannot be cross-paired.
EFFECT_RESOURCE_OPERATIONS = frozenset(
    {
        (EffectKind.COMPUTE, ResourceKind.PROCESS, Operation.EXECUTE),
        (EffectKind.COMPUTE, ResourceKind.COMPUTE_RESOURCE, Operation.ALLOCATE),
        (EffectKind.OBSERVE, ResourceKind.FILE, Operation.READ),
        (EffectKind.OBSERVE, ResourceKind.FILE, Operation.LIST),
        (EffectKind.OBSERVE, ResourceKind.DIRECTORY, Operation.READ),
        (EffectKind.OBSERVE, ResourceKind.DIRECTORY, Operation.LIST),
        (EffectKind.OBSERVE, ResourceKind.MEMORY, Operation.READ),
        (EffectKind.OBSERVE, ResourceKind.MEMORY, Operation.LIST),
        (EffectKind.OBSERVE, ResourceKind.PROMPT, Operation.READ),
        (EffectKind.OBSERVE, ResourceKind.PROMPT, Operation.LIST),
        (EffectKind.OBSERVE, ResourceKind.POLICY, Operation.READ),
        (EffectKind.OBSERVE, ResourceKind.POLICY, Operation.LIST),
        (EffectKind.OBSERVE, ResourceKind.REGISTRY, Operation.READ),
        (EffectKind.OBSERVE, ResourceKind.REGISTRY, Operation.LIST),
        (EffectKind.MUTATE, ResourceKind.FILE, Operation.WRITE),
        (EffectKind.MUTATE, ResourceKind.FILE, Operation.CREATE),
        (EffectKind.MUTATE, ResourceKind.FILE, Operation.DELETE),
        (EffectKind.MUTATE, ResourceKind.DIRECTORY, Operation.WRITE),
        (EffectKind.MUTATE, ResourceKind.DIRECTORY, Operation.CREATE),
        (EffectKind.MUTATE, ResourceKind.DIRECTORY, Operation.DELETE),
        (EffectKind.MUTATE, ResourceKind.ENDPOINT, Operation.UPDATE),
        (EffectKind.MUTATE, ResourceKind.MEMORY, Operation.UPDATE),
        (EffectKind.MUTATE, ResourceKind.PROMPT, Operation.UPDATE),
        (EffectKind.MUTATE, ResourceKind.POLICY, Operation.UPDATE),
        (EffectKind.MUTATE, ResourceKind.REGISTRY, Operation.UPDATE),
        (EffectKind.COMMUNICATE, ResourceKind.ENDPOINT, Operation.SEND),
        (EffectKind.COMMUNICATE, ResourceKind.PRINCIPAL, Operation.SEND),
        (EffectKind.DELEGATE, ResourceKind.PRINCIPAL, Operation.SPAWN),
        (EffectKind.DELEGATE, ResourceKind.PRINCIPAL, Operation.BIND),
        (EffectKind.REFLECT, ResourceKind.MEMORY, Operation.READ),
        (EffectKind.REFLECT, ResourceKind.MEMORY, Operation.UPDATE),
        (EffectKind.REFLECT, ResourceKind.PROMPT, Operation.READ),
        (EffectKind.REFLECT, ResourceKind.PROMPT, Operation.UPDATE),
        (EffectKind.REFLECT, ResourceKind.POLICY, Operation.READ),
        (EffectKind.REFLECT, ResourceKind.POLICY, Operation.UPDATE),
        (EffectKind.REFLECT, ResourceKind.REGISTRY, Operation.READ),
        (EffectKind.REFLECT, ResourceKind.REGISTRY, Operation.UPDATE),
    }
)


@dataclass(frozen=True, slots=True)
class Selector:
    kind: SelectorKind
    value: str


@dataclass(frozen=True, slots=True)
class AuthorityClause:
    """A correlated and finitely bounded authority clause."""

    effect: EffectKind
    resource: ResourceKind
    operation: Operation
    selector: Selector
    facets: tuple[Facet, ...]
    not_before: datetime
    not_after: datetime
    max_duration_ms: int
    quantity_unit: QuantityUnit
    max_quantity: int
    max_concurrency: int


@dataclass(frozen=True, slots=True)
class Proposal:
    operation_id: str
    principal_id: str
    material_digest: str
    authority: AuthorityClause


@dataclass(frozen=True, slots=True)
class AuthoritySource:
    operation_id: str
    clauses: tuple[AuthorityClause, ...]


@dataclass(frozen=True, slots=True)
class TrustedFacts:
    operation_id: str
    material_digest: str
    observed_at: datetime
    expires_at: datetime
    clauses: tuple[AuthorityClause, ...]


@dataclass(frozen=True, slots=True)
class NormalizedInput:
    evaluation_time: datetime
    proposal: Proposal
    manifest: AuthoritySource
    policy: AuthoritySource
    physical_ceiling: AuthoritySource
    trusted_facts: TrustedFacts


@dataclass(frozen=True, slots=True)
class ClassifiedInput:
    normalized: NormalizedInput


@dataclass(frozen=True, slots=True)
class DerivedAuthority:
    """The exact proposal proven to be inside all four authority sources."""

    classified: ClassifiedInput
    effective: AuthorityClause
    proposal_digest: str
    source_clause_digests: tuple[str, str, str, str]


@dataclass(frozen=True, slots=True)
class PowerlessProposal:
    """A description with no method, token, credential, or dispatch authority."""

    proposal: Proposal
    proposal_digest: str
    authority: ProposalAuthority = ProposalAuthority.NONE


@dataclass(frozen=True, slots=True)
class Decision:
    outcome: Outcome
    reason: Reason
    stage: Stage
    proposal_digest: str | None
    proposals: tuple[PowerlessProposal, ...]
    decision_digest: str

    @property
    def allowed(self) -> bool:
        return self.outcome is Outcome.ALLOW


@dataclass(frozen=True, slots=True)
class KernelState:
    phase: Phase = Phase.STOPPED
    decision_digest: str | None = None


@dataclass(frozen=True, slots=True)
class TransitionResult:
    accepted: bool
    outcome: Outcome
    reason: Reason
    state: KernelState
    proposals: tuple[PowerlessProposal, ...] = ()


@dataclass(frozen=True, slots=True)
class KernelResult:
    decision: Decision
    transition: TransitionResult


def canonical_digest(value: object) -> str:
    """Digest an already-normalized JSON value deterministically."""

    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return "sha256:" + sha256(encoded).hexdigest()


def _time_text(value: datetime) -> str:
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def selector_data(value: Selector) -> dict[str, str]:
    return {"kind": value.kind.value, "value": value.value}


def clause_data(value: AuthorityClause) -> dict[str, object]:
    return {
        "effect": value.effect.value,
        "facets": [facet.value for facet in value.facets],
        "max_concurrency": value.max_concurrency,
        "max_duration_ms": value.max_duration_ms,
        "max_quantity": value.max_quantity,
        "not_after": _time_text(value.not_after),
        "not_before": _time_text(value.not_before),
        "operation": value.operation.value,
        "quantity_unit": value.quantity_unit.value,
        "resource": value.resource.value,
        "selector": selector_data(value.selector),
    }


def clause_digest(value: AuthorityClause) -> str:
    return canonical_digest(clause_data(value))


def proposal_data(value: Proposal) -> dict[str, object]:
    return {
        "authority": clause_data(value.authority),
        "material_digest": value.material_digest,
        "operation_id": value.operation_id,
        "principal_id": value.principal_id,
    }


def proposal_digest(value: Proposal) -> str:
    return canonical_digest(proposal_data(value))


def powerless_proposal_data(value: PowerlessProposal) -> dict[str, object]:
    return {
        "authority": value.authority.value,
        "proposal": proposal_data(value.proposal),
        "proposal_digest": value.proposal_digest,
    }


def decision_data(
    outcome: Outcome,
    reason: Reason,
    stage: Stage,
    proposal_digest_value: str | None,
    proposals: tuple[PowerlessProposal, ...],
) -> dict[str, object]:
    return {
        "outcome": outcome.value,
        "proposal_digest": proposal_digest_value,
        "proposals": [powerless_proposal_data(item) for item in proposals],
        "reason": reason.value,
        "stage": stage.value,
    }
