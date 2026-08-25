"""Closed, side-effect-free types for the reference enforcement kernel.

This module deliberately models a narrow subset of the formalization.  It is
not a production isolation, signing, or durable-storage implementation.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from hashlib import sha256
import json
from typing import FrozenSet


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
    ENDPOINT = "ENDPOINT"
    PRINCIPAL = "PRINCIPAL"
    MEMORY = "MEMORY"
    PROMPT = "PROMPT"
    POLICY = "POLICY"
    REGISTRY = "REGISTRY"
    SECRET = "SECRET"
    COMPUTE_RESOURCE = "COMPUTE_RESOURCE"


class SelectorKind(str, Enum):
    PATH_EXACT = "PATH_EXACT"
    PATH_PREFIX = "PATH_PREFIX"
    PROCESS_EXECUTABLE = "PROCESS_EXECUTABLE"
    ENDPOINT_EXACT = "ENDPOINT_EXACT"
    PRINCIPAL_EXACT = "PRINCIPAL_EXACT"
    MEMORY_NAMESPACE = "MEMORY_NAMESPACE"
    PROMPT_COMPONENT = "PROMPT_COMPONENT"
    POLICY_OBJECT = "POLICY_OBJECT"
    LOCAL_RESOURCE = "LOCAL_RESOURCE"


class PrincipalRole(str, Enum):
    WORKER = "WORKER"
    BROKER = "BROKER"
    EXECUTOR = "EXECUTOR"


class Outcome(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    STOP = "STOP"


class Reason(str, Enum):
    MALFORMED_INPUT = "MALFORMED_INPUT"
    UNKNOWN_OR_UNBOUNDED = "UNKNOWN_OR_UNBOUNDED"
    OPERATION_MISMATCH = "OPERATION_MISMATCH"
    EFFECT_EXCEEDS_CEILING = "EFFECT_EXCEEDS_CEILING"
    TYPED_SCOPE_MISMATCH = "TYPED_SCOPE_MISMATCH"
    CAPABILITY_BINDING_MISMATCH = "CAPABILITY_BINDING_MISMATCH"
    CAPABILITY_UNCONSUMED = "CAPABILITY_UNCONSUMED"
    REPLAY = "REPLAY"
    NO_DIRECT_DISPATCH = "NO_DIRECT_DISPATCH"
    AUTHORIZED_EXACT_BOUND = "AUTHORIZED_EXACT_BOUND"


_SELECTORS_BY_RESOURCE: dict[ResourceKind, FrozenSet[SelectorKind]] = {
    ResourceKind.FILE: frozenset({SelectorKind.PATH_EXACT, SelectorKind.PATH_PREFIX}),
    ResourceKind.DIRECTORY: frozenset({SelectorKind.PATH_EXACT, SelectorKind.PATH_PREFIX}),
    ResourceKind.ENDPOINT: frozenset({SelectorKind.ENDPOINT_EXACT}),
    ResourceKind.PRINCIPAL: frozenset({SelectorKind.PRINCIPAL_EXACT}),
    ResourceKind.MEMORY: frozenset({SelectorKind.MEMORY_NAMESPACE}),
    ResourceKind.PROMPT: frozenset({SelectorKind.PROMPT_COMPONENT}),
    ResourceKind.POLICY: frozenset({SelectorKind.POLICY_OBJECT}),
    ResourceKind.REGISTRY: frozenset({SelectorKind.LOCAL_RESOURCE}),
    ResourceKind.SECRET: frozenset({SelectorKind.LOCAL_RESOURCE}),
    ResourceKind.COMPUTE_RESOURCE: frozenset({SelectorKind.LOCAL_RESOURCE}),
}


@dataclass(frozen=True)
class Principal:
    identifier: str
    role: PrincipalRole


@dataclass(frozen=True)
class Selector:
    kind: SelectorKind
    value: str


@dataclass(frozen=True)
class Request:
    operation_id: str
    principal: Principal
    effect: EffectKind
    resource: ResourceKind
    selector: Selector
    material_digest: str

    def digest(self) -> str:
        """A canonical binding for this exact request, not an attestation."""
        payload = {
            "effect": self.effect.value,
            "material_digest": self.material_digest,
            "operation_id": self.operation_id,
            "principal": {"identifier": self.principal.identifier, "role": self.principal.role.value},
            "resource": self.resource.value,
            "selector": {"kind": self.selector.kind.value, "value": self.selector.value},
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return sha256(encoded).hexdigest()


@dataclass(frozen=True)
class Manifest:
    operation_id: str
    effects: FrozenSet[EffectKind]
    resource: ResourceKind


@dataclass(frozen=True)
class Policy:
    allowed_effects: FrozenSet[EffectKind]


@dataclass(frozen=True)
class Decision:
    outcome: Outcome
    reason: Reason
    request_digest: str | None = None

    @property
    def allowed(self) -> bool:
        return self.outcome is Outcome.ALLOW


@dataclass(frozen=True)
class Capability:
    """A one-use exact binding; journal state determines whether it is live."""

    identifier: str
    request_digest: str
    worker: Principal
    audience: Principal
    issued_sequence: int


def _is_text(value: object) -> bool:
    return isinstance(value, str) and bool(value)


def is_canonical_sha256(value: object) -> bool:
    """Accept only the canonical ``sha256:<64 lowercase hex>`` representation."""
    if not isinstance(value, str) or not value.startswith("sha256:") or len(value) != 71:
        return False
    hexadecimal = value[7:]
    return all(character in "0123456789abcdef" for character in hexadecimal)


def _is_effect_set(value: object) -> bool:
    return type(value) is frozenset and bool(value) and all(type(item) is EffectKind for item in value)


def is_valid_principal(value: object, role: PrincipalRole | None = None) -> bool:
    return (
        type(value) is Principal
        and _is_text(value.identifier)
        and type(value.role) is PrincipalRole
        and (role is None or value.role is role)
    )


def is_valid_request(value: object) -> bool:
    return (
        type(value) is Request
        and _is_text(value.operation_id)
        and is_valid_principal(value.principal, PrincipalRole.WORKER)
        and type(value.effect) is EffectKind
        and type(value.resource) is ResourceKind
        and type(value.selector) is Selector
        and type(value.selector.kind) is SelectorKind
        and _is_text(value.selector.value)
        and is_canonical_sha256(value.material_digest)
    )


def is_valid_manifest(value: object) -> bool:
    return (
        type(value) is Manifest
        and _is_text(value.operation_id)
        and _is_effect_set(value.effects)
        and type(value.resource) is ResourceKind
    )


def is_valid_policy(value: object) -> bool:
    return type(value) is Policy and _is_effect_set(value.allowed_effects)


def is_valid_effect_ceiling(value: object) -> bool:
    return _is_effect_set(value)


def selector_matches_resource(resource: object, selector: object) -> bool:
    if type(resource) is not ResourceKind or type(selector) is not Selector or type(selector.kind) is not SelectorKind:
        return False
    return selector.kind in _SELECTORS_BY_RESOURCE.get(resource, frozenset())


def decide(
    request: object,
    manifest: object,
    policy: object,
    physical_ceiling: object,
) -> Decision:
    """Pure, total and deny-by-default admission decision.

    Trusted facts such as signatures, clocks and runtime attestation are out of
    scope for this in-memory reference model; their absence must not be read as
    successful verification in a production system.
    """
    if not is_valid_request(request) or not is_valid_manifest(manifest) or not is_valid_policy(policy):
        return Decision(Outcome.STOP, Reason.MALFORMED_INPUT)
    if not is_valid_effect_ceiling(physical_ceiling):
        return Decision(Outcome.STOP, Reason.MALFORMED_INPUT)
    if not selector_matches_resource(request.resource, request.selector):
        return Decision(Outcome.DENY, Reason.TYPED_SCOPE_MISMATCH)
    if manifest.operation_id != request.operation_id or manifest.resource is not request.resource:
        return Decision(Outcome.DENY, Reason.OPERATION_MISMATCH)
    if request.effect not in manifest.effects or request.effect not in policy.allowed_effects or request.effect not in physical_ceiling:
        return Decision(Outcome.DENY, Reason.EFFECT_EXCEEDS_CEILING)
    return Decision(Outcome.ALLOW, Reason.AUTHORIZED_EXACT_BOUND, request.digest())
