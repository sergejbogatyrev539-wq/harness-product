"""Cooperative in-process reference dispatch kernel.

No method in this module performs shell, network, filesystem, or other real
effects.  ``executed`` means only that the exact call reached this model's
executor after its checks.  The journal is intentionally non-production: it
is process-local, not durable, serialized, signed, or crash-safe.  Python
private names and object identity are not a security boundary; actual
non-bypassable mediation needs M2/M3 process-isolated principals and an
enforced executor profile.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .model import (
    Capability,
    Decision,
    EffectKind,
    Manifest,
    Outcome,
    Policy,
    Principal,
    PrincipalRole,
    Reason,
    Request,
    decide,
    is_valid_physical_ceiling,
    is_valid_principal,
    is_valid_request,
)


class CapabilityState(str, Enum):
    ISSUED = "ISSUED"
    CONSUMED = "CONSUMED"


@dataclass(frozen=True)
class DispatchReceipt:
    executed: bool
    reason: Reason
    sequence: int | None = None


@dataclass(frozen=True)
class _DispatchOrder:
    """Internal simulated dispatch message for cooperative API calls."""

    request: Request
    capability: Capability
    sequence: int
    broker_key: object


class _InMemoryJournal:
    """Monotonic reference journal.  It is explicitly not a durable journal."""

    def __init__(self, authority: object) -> None:
        self._authority = authority
        self._sequence = 0
        self._states: dict[str, CapabilityState] = {}
        self._capabilities: dict[str, Capability] = {}
        self._events: list[tuple[int, str, str]] = []

    @property
    def sequence(self) -> int:
        return self._sequence

    @property
    def events(self) -> tuple[tuple[int, str, str], ...]:
        return tuple(self._events)

    def state_of(self, capability: object) -> CapabilityState | None:
        if not _is_valid_capability(capability):
            return None
        stored = self._capabilities.get(capability.identifier)
        if stored != capability:
            return None
        return self._states.get(capability.identifier)

    def _issue(self, request: Request, audience: Principal, authority: object) -> Capability | None:
        if authority is not self._authority or not is_valid_request(request) or not is_valid_principal(audience, PrincipalRole.EXECUTOR):
            return None
        self._sequence += 1
        identifier = f"cap-{self._sequence}"
        capability = Capability(identifier, request.digest(), request.principal, audience, self._sequence)
        self._capabilities[identifier] = capability
        self._states[identifier] = CapabilityState.ISSUED
        self._events.append((self._sequence, "ISSUED", identifier))
        return capability

    def _consume(self, capability: object, authority: object) -> tuple[bool, Reason, int | None]:
        if authority is not self._authority:
            return False, Reason.NO_DIRECT_DISPATCH, None
        state = self.state_of(capability)
        if state is None:
            return False, Reason.CAPABILITY_BINDING_MISMATCH, None
        if state is CapabilityState.CONSUMED:
            return False, Reason.REPLAY, None
        self._sequence += 1
        self._states[capability.identifier] = CapabilityState.CONSUMED
        self._events.append((self._sequence, "CONSUMED", capability.identifier))
        return True, Reason.AUTHORIZED_EXACT_BOUND, self._sequence


def _is_request_digest(value: object) -> bool:
    return type(value) is str and len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _is_valid_capability(value: object) -> bool:
    return (
        type(value) is Capability
        and type(value.identifier) is str
        and bool(value.identifier)
        and _is_request_digest(value.request_digest)
        and is_valid_principal(value.worker, PrincipalRole.WORKER)
        and is_valid_principal(value.audience, PrincipalRole.EXECUTOR)
        and type(value.issued_sequence) is int
        and value.issued_sequence > 0
    )


class Executor:
    """Cooperative exact-call checker, not an isolation or enforcement boundary."""

    def __init__(self, principal: object, journal: _InMemoryJournal, broker_key: object) -> None:
        self._principal = principal
        self._journal = journal
        self._broker_key = broker_key

    @property
    def principal(self) -> object:
        return self._principal

    def dispatch(self, order: object) -> DispatchReceipt:
        """Reject every object except a consumed, exact, broker-bound order."""
        if type(order) is not _DispatchOrder or order.broker_key is not self._broker_key:
            return DispatchReceipt(False, Reason.NO_DIRECT_DISPATCH)
        if not is_valid_request(order.request) or not _is_valid_capability(order.capability) or type(order.sequence) is not int:
            return DispatchReceipt(False, Reason.MALFORMED_INPUT)
        capability = order.capability
        if self._journal.state_of(capability) is not CapabilityState.CONSUMED:
            return DispatchReceipt(False, Reason.CAPABILITY_UNCONSUMED)
        if capability.audience != self._principal or capability.worker != order.request.principal:
            return DispatchReceipt(False, Reason.CAPABILITY_BINDING_MISMATCH)
        if capability.request_digest != order.request.digest():
            return DispatchReceipt(False, Reason.CAPABILITY_BINDING_MISMATCH)
        return DispatchReceipt(True, Reason.AUTHORIZED_EXACT_BOUND, order.sequence)


class Broker:
    """Coordinates authorization and simulated dispatch in this reference model."""

    def __init__(self, executor_principal: object, physical_ceiling: object) -> None:
        """Build a disabled fail-closed broker rather than raising on bad input."""
        self._broker_key = object()
        self._journal_authority = object()
        self._journal = _InMemoryJournal(self._journal_authority)
        self._executor = Executor(executor_principal, self._journal, self._broker_key)
        self._physical_ceiling = physical_ceiling
        self._configuration_valid = (
            is_valid_principal(executor_principal, PrincipalRole.EXECUTOR)
            and is_valid_physical_ceiling(physical_ceiling)
        )

    @property
    def journal_sequence(self) -> int:
        """Read-only view of the non-production journal's monotonic sequence."""
        return self._journal.sequence

    @property
    def journal_events(self) -> tuple[tuple[int, str, str], ...]:
        """Read-only event snapshot; this is not durable audit evidence."""
        return self._journal.events

    def capability_state(self, capability: object) -> CapabilityState | None:
        """Read-only capability state lookup."""
        return self._journal.state_of(capability)

    def authorize(self, request: object, manifest: object, policy: object) -> tuple[Decision, Capability | None]:
        if not self._configuration_valid:
            return Decision(Outcome.STOP, Reason.MALFORMED_INPUT), None
        decision = decide(request, manifest, policy, self._physical_ceiling)
        if not decision.allowed or not is_valid_request(request):
            return decision, None
        capability = self._journal._issue(request, self._executor.principal, self._journal_authority)
        if capability is None:
            return Decision(Outcome.STOP, Reason.MALFORMED_INPUT), None
        return decision, capability

    def dispatch(self, request: object, capability: object) -> DispatchReceipt:
        """Atomically consume in the reference journal before simulated dispatch."""
        if not is_valid_request(request) or not _is_valid_capability(capability):
            return DispatchReceipt(False, Reason.MALFORMED_INPUT)
        if capability.request_digest != request.digest() or capability.worker != request.principal:
            return DispatchReceipt(False, Reason.CAPABILITY_BINDING_MISMATCH)
        consumed, reason, sequence = self._journal._consume(capability, self._journal_authority)
        if not consumed:
            return DispatchReceipt(False, reason)
        return self._executor.dispatch(_DispatchOrder(request, capability, sequence, self._broker_key))
