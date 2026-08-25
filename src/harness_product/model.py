"""Closed, side-effect-free types for the reference enforcement kernel.

This module deliberately models a narrow subset of the formalization.  It is
not a production isolation, signing, or durable-storage implementation.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from hashlib import sha256
import json
import unicodedata
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
class ScopeBound:
    """One correlated effect/resource/selector authority bound.

    This reference type deliberately keeps a selector with the effect and
    resource it constrains.  It is not an independent effects/resources/
    selectors cross-product.
    """

    effect: EffectKind
    resource: ResourceKind
    selector: Selector


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
    bounds: FrozenSet[ScopeBound]


@dataclass(frozen=True)
class Policy:
    bounds: FrozenSet[ScopeBound]


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
    return type(value) is str and bool(value)


def _is_valid_operation_id(value: object) -> bool:
    return (
        type(value) is str
        and 1 <= len(value) <= 128
        and "a" <= value[0] <= "z"
        and all("a" <= character <= "z" or "0" <= character <= "9" or character in "._/-" for character in value[1:])
    )


def is_canonical_sha256(value: object) -> bool:
    """Accept only the canonical ``sha256:<64 lowercase hex>`` representation."""
    if type(value) is not str or not value.startswith("sha256:") or len(value) != 71:
        return False
    hexadecimal = value[7:]
    return all(character in "0123456789abcdef" for character in hexadecimal)


def is_canonical_workspace_path(value: object) -> bool:
    """Accept a lexical canonical path rooted at ``/workspace`` only.

    This pure model cannot establish descriptor, mount, or symlink identity;
    M2/M3 runtime enforcement remains responsible for that physical proof.
    """
    if type(value) is not str:
        return False
    if value == "/workspace":
        return True
    if (
        not value.startswith("/workspace/")
        or "\\" in value
        or "%" in value
        or any(
            unicodedata.category(character) in {"Cc", "Cf"}
            or character in {"\u2044", "\u2215", "\uff0f", "\uff3c"}
            for character in value
        )
    ):
        return False
    return all(component not in {"", ".", ".."} for component in value.split("/")[2:])


def is_valid_principal(value: object, role: PrincipalRole | None = None) -> bool:
    return (
        type(value) is Principal
        and _is_text(value.identifier)
        and type(value.role) is PrincipalRole
        and (role is None or value.role is role)
    )


def _is_valid_selector(value: object) -> bool:
    if type(value) is not Selector or type(value.kind) is not SelectorKind or not _is_text(value.value):
        return False
    if value.kind in {SelectorKind.PATH_EXACT, SelectorKind.PATH_PREFIX}:
        return is_canonical_workspace_path(value.value)
    return True


def is_valid_request(value: object) -> bool:
    return (
        type(value) is Request
        and _is_valid_operation_id(value.operation_id)
        and is_valid_principal(value.principal, PrincipalRole.WORKER)
        and type(value.effect) is EffectKind
        and type(value.resource) is ResourceKind
        and _is_valid_selector(value.selector)
        and is_canonical_sha256(value.material_digest)
    )


def is_valid_scope_bound(value: object) -> bool:
    return (
        type(value) is ScopeBound
        and type(value.effect) is EffectKind
        and type(value.resource) is ResourceKind
        and _is_valid_selector(value.selector)
        and selector_matches_resource(value.resource, value.selector)
    )


def _is_scope_bound_set(value: object) -> bool:
    return type(value) is frozenset and bool(value) and all(is_valid_scope_bound(item) for item in value)


def is_valid_manifest(value: object) -> bool:
    return (
        type(value) is Manifest
        and _is_valid_operation_id(value.operation_id)
        and _is_scope_bound_set(value.bounds)
    )


def is_valid_policy(value: object) -> bool:
    return type(value) is Policy and _is_scope_bound_set(value.bounds)


def is_valid_physical_ceiling(value: object) -> bool:
    return _is_scope_bound_set(value)


def selector_matches_resource(resource: object, selector: object) -> bool:
    if type(resource) is not ResourceKind or type(selector) is not Selector or type(selector.kind) is not SelectorKind:
        return False
    return selector.kind in _SELECTORS_BY_RESOURCE.get(resource, frozenset())


def _path_is_within(path: str, root: str) -> bool:
    path_components = path.split("/")[1:]
    root_components = root.split("/")[1:]
    return path_components[:len(root_components)] == root_components


def scope_bound_contains(bound: object, request: object) -> bool:
    """Return whether one typed bound contains this request's exact scope."""
    if not is_valid_scope_bound(bound) or not is_valid_request(request):
        return False
    if bound.effect is not request.effect or bound.resource is not request.resource:
        return False
    bound_selector = bound.selector
    request_selector = request.selector
    if bound_selector.kind is SelectorKind.PATH_EXACT:
        return request_selector.kind is SelectorKind.PATH_EXACT and bound_selector.value == request_selector.value
    if bound_selector.kind is SelectorKind.PATH_PREFIX:
        return (
            request_selector.kind in {SelectorKind.PATH_EXACT, SelectorKind.PATH_PREFIX}
            and _path_is_within(request_selector.value, bound_selector.value)
        )
    return bound_selector == request_selector


def _has_effect_resource_bound(bounds: FrozenSet[ScopeBound], request: Request) -> bool:
    return any(bound.effect is request.effect and bound.resource is request.resource for bound in bounds)


def _scope_is_covered(bounds: FrozenSet[ScopeBound], request: Request) -> bool:
    return any(scope_bound_contains(bound, request) for bound in bounds)


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
    if not is_valid_physical_ceiling(physical_ceiling):
        return Decision(Outcome.STOP, Reason.MALFORMED_INPUT)
    if not selector_matches_resource(request.resource, request.selector):
        return Decision(Outcome.DENY, Reason.TYPED_SCOPE_MISMATCH)
    if manifest.operation_id != request.operation_id:
        return Decision(Outcome.DENY, Reason.OPERATION_MISMATCH)
    inputs = (manifest.bounds, policy.bounds, physical_ceiling)
    if any(not _has_effect_resource_bound(bounds, request) for bounds in inputs):
        return Decision(Outcome.DENY, Reason.EFFECT_EXCEEDS_CEILING)
    if any(not _scope_is_covered(bounds, request) for bounds in inputs):
        return Decision(Outcome.DENY, Reason.TYPED_SCOPE_MISMATCH)
    return Decision(Outcome.ALLOW, Reason.AUTHORIZED_EXACT_BOUND, request.digest())
