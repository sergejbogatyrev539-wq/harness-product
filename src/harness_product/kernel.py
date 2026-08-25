"""Pure M1 normalization, classification, and authority derivation.

The module consumes only in-memory values and never calls filesystem, network,
process, shell, clock, random, or environment APIs.  Time is explicit input.
"""

from __future__ import annotations

from datetime import datetime, timezone
import re
import unicodedata

from .model import (
    EFFECT_RESOURCE_OPERATIONS,
    AuthorityClause,
    AuthoritySource,
    ClassifiedInput,
    Decision,
    DerivedAuthority,
    EffectKind,
    Facet,
    KernelResult,
    KernelState,
    NormalizedInput,
    Operation,
    Outcome,
    Phase,
    PowerlessProposal,
    Proposal,
    ProposalAuthority,
    QuantityUnit,
    Reason,
    ResourceKind,
    Selector,
    SelectorKind,
    Stage,
    TransitionResult,
    TrustedFacts,
    canonical_digest,
    clause_digest,
    decision_data,
    proposal_digest,
)


_OPERATION_ID = re.compile(r"^[a-z][a-z0-9._/-]{0,127}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_UTC_TIME = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_ENDPOINT = re.compile(r"^https://[A-Za-z0-9.-]+(?::[0-9]{1,5})?/[A-Za-z0-9._~!$&'()*+,;=:@/-]*$")
_MAX_AUTHORITY_CLAUSES = 256
_MAX_BOUND = (1 << 63) - 1

_SELECTORS_BY_RESOURCE = {
    ResourceKind.FILE: frozenset({SelectorKind.PATH_EXACT, SelectorKind.PATH_PREFIX}),
    ResourceKind.DIRECTORY: frozenset({SelectorKind.PATH_EXACT, SelectorKind.PATH_PREFIX}),
    ResourceKind.ENDPOINT: frozenset({SelectorKind.ENDPOINT_EXACT}),
    ResourceKind.PROCESS: frozenset({SelectorKind.LOCAL_EXACT}),
    ResourceKind.PRINCIPAL: frozenset({SelectorKind.LOCAL_EXACT}),
    ResourceKind.MEMORY: frozenset({SelectorKind.LOCAL_EXACT}),
    ResourceKind.PROMPT: frozenset({SelectorKind.LOCAL_EXACT}),
    ResourceKind.POLICY: frozenset({SelectorKind.LOCAL_EXACT}),
    ResourceKind.REGISTRY: frozenset({SelectorKind.LOCAL_EXACT}),
    ResourceKind.COMPUTE_RESOURCE: frozenset({SelectorKind.LOCAL_EXACT}),
}


def _decision(
    outcome: Outcome,
    reason: Reason,
    stage: Stage,
    proposal_digest_value: str | None = None,
    proposals: tuple[PowerlessProposal, ...] = (),
) -> Decision:
    payload = decision_data(outcome, reason, stage, proposal_digest_value, proposals)
    return Decision(
        outcome,
        reason,
        stage,
        proposal_digest_value,
        proposals,
        canonical_digest(payload),
    )


def _closed_dict(value: object, keys: frozenset[str]) -> bool:
    return type(value) is dict and all(type(key) is str for key in value) and frozenset(value) == keys


def _enum(enum_type: type, value: object) -> object | None:
    if type(value) is not str:
        return None
    return enum_type._value2member_map_.get(value)


def _bounded_integer(value: object, minimum: int) -> bool:
    return type(value) is int and minimum <= value <= _MAX_BOUND


def _parse_time(value: object) -> datetime | None:
    if type(value) is not str or _UTC_TIME.fullmatch(value) is None:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _canonical_path(value: object) -> bool:
    if type(value) is not str or not 2 <= len(value) <= 2048 or not value.startswith("/"):
        return False
    if "//" in value or "\\" in value or "%" in value:
        return False
    if any(
        unicodedata.category(character) in {"Cc", "Cf"}
        or character in {"\u2044", "\u2215", "\uff0f", "\uff3c"}
        for character in value
    ):
        return False
    return all(component not in {"", ".", ".."} for component in value.split("/")[1:])


def _normalize_selector(raw: object) -> tuple[Selector | None, Reason | None]:
    if not _closed_dict(raw, frozenset({"kind", "value"})):
        return None, Reason.MALFORMED_INPUT
    kind = _enum(SelectorKind, raw["kind"])
    if kind is None:
        return None, Reason.UNKNOWN_INPUT
    value = raw["value"]
    if kind in {SelectorKind.PATH_EXACT, SelectorKind.PATH_PREFIX}:
        valid = _canonical_path(value)
    elif kind is SelectorKind.ENDPOINT_EXACT:
        valid = type(value) is str and len(value) <= 2048 and "%" not in value and _ENDPOINT.fullmatch(value) is not None
    else:
        valid = type(value) is str and _IDENTIFIER.fullmatch(value) is not None
    if not valid:
        return None, Reason.MALFORMED_INPUT
    return Selector(kind, value), None


_CLAUSE_KEYS = frozenset(
    {
        "effect",
        "resource",
        "operation",
        "selector",
        "facets",
        "not_before",
        "not_after",
        "max_duration_ms",
        "quantity_unit",
        "max_quantity",
        "max_concurrency",
    }
)


def _normalize_clause(raw: object) -> tuple[AuthorityClause | None, Reason | None]:
    if not _closed_dict(raw, _CLAUSE_KEYS):
        return None, Reason.MALFORMED_INPUT
    effect = _enum(EffectKind, raw["effect"])
    resource = _enum(ResourceKind, raw["resource"])
    operation = _enum(Operation, raw["operation"])
    unit = _enum(QuantityUnit, raw["quantity_unit"])
    if None in {effect, resource, operation, unit}:
        return None, Reason.UNKNOWN_INPUT
    selector, selector_error = _normalize_selector(raw["selector"])
    if selector_error is not None:
        return None, selector_error
    facets_raw = raw["facets"]
    if type(facets_raw) is not list or not facets_raw or len(facets_raw) > len(Facet):
        return None, Reason.UNBOUNDED_INPUT if facets_raw in (None, []) else Reason.MALFORMED_INPUT
    facets: list[Facet] = []
    for item in facets_raw:
        facet = _enum(Facet, item)
        if facet is None:
            return None, Reason.UNKNOWN_INPUT
        facets.append(facet)
    if len(set(facets)) != len(facets):
        return None, Reason.MALFORMED_INPUT
    not_before = _parse_time(raw["not_before"])
    not_after = _parse_time(raw["not_after"])
    if not_before is None or not_after is None or not_before >= not_after:
        return None, Reason.UNBOUNDED_INPUT if raw["not_before"] is None or raw["not_after"] is None else Reason.MALFORMED_INPUT
    for field, minimum in (("max_duration_ms", 1), ("max_quantity", 0), ("max_concurrency", 1)):
        if raw[field] is None:
            return None, Reason.UNBOUNDED_INPUT
        if not _bounded_integer(raw[field], minimum):
            return None, Reason.MALFORMED_INPUT
    return (
        AuthorityClause(
            effect,
            resource,
            operation,
            selector,
            tuple(sorted(facets, key=lambda item: item.value)),
            not_before,
            not_after,
            raw["max_duration_ms"],
            unit,
            raw["max_quantity"],
            raw["max_concurrency"],
        ),
        None,
    )


def _normalize_clauses(raw: object) -> tuple[tuple[AuthorityClause, ...] | None, Reason | None]:
    if type(raw) is not list or not raw:
        return None, Reason.UNBOUNDED_INPUT if raw in (None, []) else Reason.MALFORMED_INPUT
    if len(raw) > _MAX_AUTHORITY_CLAUSES:
        return None, Reason.UNBOUNDED_INPUT
    clauses: list[AuthorityClause] = []
    for item in raw:
        clause, error = _normalize_clause(item)
        if error is not None:
            return None, error
        clauses.append(clause)
    ordered = tuple(sorted(clauses, key=clause_digest))
    digests = tuple(clause_digest(item) for item in ordered)
    if len(set(digests)) != len(digests):
        return None, Reason.MALFORMED_INPUT
    return ordered, None


def _normalize_source(raw: object) -> tuple[AuthoritySource | None, Reason | None]:
    if not _closed_dict(raw, frozenset({"operation_id", "authority"})):
        return None, Reason.MALFORMED_INPUT
    if type(raw["operation_id"]) is not str or _OPERATION_ID.fullmatch(raw["operation_id"]) is None:
        return None, Reason.MALFORMED_INPUT
    clauses, error = _normalize_clauses(raw["authority"])
    if error is not None:
        return None, error
    return AuthoritySource(raw["operation_id"], clauses), None


def normalize(raw: object) -> NormalizedInput | Decision:
    """Close and type every raw field without repairing or defaulting it."""

    try:
        keys = frozenset({"evaluation_time", "proposal", "manifest", "policy", "physical_ceiling", "trusted_facts"})
        if not _closed_dict(raw, keys):
            return _decision(Outcome.STOP, Reason.MALFORMED_INPUT, Stage.NORMALIZE)
        evaluation_time = _parse_time(raw["evaluation_time"])
        proposal_raw = raw["proposal"]
        if evaluation_time is None or not _closed_dict(
            proposal_raw,
            frozenset({"operation_id", "principal_id", "material_digest", "authority"}),
        ):
            return _decision(Outcome.STOP, Reason.MALFORMED_INPUT, Stage.NORMALIZE)
        if (
            type(proposal_raw["operation_id"]) is not str
            or _OPERATION_ID.fullmatch(proposal_raw["operation_id"]) is None
            or type(proposal_raw["principal_id"]) is not str
            or _IDENTIFIER.fullmatch(proposal_raw["principal_id"]) is None
            or type(proposal_raw["material_digest"]) is not str
            or _DIGEST.fullmatch(proposal_raw["material_digest"]) is None
        ):
            return _decision(Outcome.STOP, Reason.MALFORMED_INPUT, Stage.NORMALIZE)
        proposal_clause, error = _normalize_clause(proposal_raw["authority"])
        if error is not None:
            return _decision(Outcome.STOP, error, Stage.NORMALIZE)
        sources: list[AuthoritySource] = []
        for name in ("manifest", "policy", "physical_ceiling"):
            source, error = _normalize_source(raw[name])
            if error is not None:
                return _decision(Outcome.STOP, error, Stage.NORMALIZE)
            sources.append(source)
        facts_raw = raw["trusted_facts"]
        if not _closed_dict(
            facts_raw,
            frozenset({"operation_id", "material_digest", "observed_at", "expires_at", "authority"}),
        ):
            return _decision(Outcome.STOP, Reason.MALFORMED_INPUT, Stage.NORMALIZE)
        if (
            type(facts_raw["operation_id"]) is not str
            or _OPERATION_ID.fullmatch(facts_raw["operation_id"]) is None
            or type(facts_raw["material_digest"]) is not str
            or _DIGEST.fullmatch(facts_raw["material_digest"]) is None
        ):
            return _decision(Outcome.STOP, Reason.MALFORMED_INPUT, Stage.NORMALIZE)
        observed_at = _parse_time(facts_raw["observed_at"])
        expires_at = _parse_time(facts_raw["expires_at"])
        if observed_at is None or expires_at is None or observed_at >= expires_at:
            reason = Reason.UNBOUNDED_INPUT if facts_raw["expires_at"] is None else Reason.MALFORMED_INPUT
            return _decision(Outcome.STOP, reason, Stage.NORMALIZE)
        fact_clauses, error = _normalize_clauses(facts_raw["authority"])
        if error is not None:
            return _decision(Outcome.STOP, error, Stage.NORMALIZE)
        proposal = Proposal(
            proposal_raw["operation_id"],
            proposal_raw["principal_id"],
            proposal_raw["material_digest"],
            proposal_clause,
        )
        facts = TrustedFacts(
            facts_raw["operation_id"],
            facts_raw["material_digest"],
            observed_at,
            expires_at,
            fact_clauses,
        )
        return NormalizedInput(evaluation_time, proposal, sources[0], sources[1], sources[2], facts)
    except Exception:
        return _decision(Outcome.STOP, Reason.INTERNAL_ERROR, Stage.NORMALIZE)


def _selector_matches_resource(clause: AuthorityClause) -> bool:
    return clause.selector.kind in _SELECTORS_BY_RESOURCE.get(clause.resource, frozenset())


def _clause_is_typed(value: object) -> bool:
    try:
        return (
            type(value) is AuthorityClause
            and type(value.effect) is EffectKind
            and type(value.resource) is ResourceKind
            and type(value.operation) is Operation
            and type(value.selector) is Selector
            and type(value.selector.kind) is SelectorKind
            and type(value.selector.value) is str
            and type(value.facets) is tuple
            and bool(value.facets)
            and all(type(facet) is Facet for facet in value.facets)
            and tuple(sorted(value.facets, key=lambda item: item.value)) == value.facets
            and len(set(value.facets)) == len(value.facets)
            and type(value.not_before) is datetime
            and type(value.not_after) is datetime
            and value.not_before.tzinfo is timezone.utc
            and value.not_after.tzinfo is timezone.utc
            and value.not_before < value.not_after
            and _bounded_integer(value.max_duration_ms, 1)
            and type(value.quantity_unit) is QuantityUnit
            and _bounded_integer(value.max_quantity, 0)
            and _bounded_integer(value.max_concurrency, 1)
        )
    except Exception:
        return False


def _source_is_typed(value: object) -> bool:
    try:
        return (
            type(value) is AuthoritySource
            and type(value.operation_id) is str
            and _OPERATION_ID.fullmatch(value.operation_id) is not None
            and type(value.clauses) is tuple
            and 1 <= len(value.clauses) <= _MAX_AUTHORITY_CLAUSES
            and all(_clause_is_typed(item) for item in value.clauses)
            and tuple(sorted(value.clauses, key=clause_digest)) == value.clauses
            and len({clause_digest(item) for item in value.clauses}) == len(value.clauses)
        )
    except Exception:
        return False


def _proposal_is_typed(value: object) -> bool:
    try:
        return (
            type(value) is Proposal
            and type(value.operation_id) is str
            and _OPERATION_ID.fullmatch(value.operation_id) is not None
            and type(value.principal_id) is str
            and _IDENTIFIER.fullmatch(value.principal_id) is not None
            and type(value.material_digest) is str
            and _DIGEST.fullmatch(value.material_digest) is not None
            and _clause_is_typed(value.authority)
        )
    except Exception:
        return False


def _normalized_is_typed(value: object) -> bool:
    try:
        proposal = value.proposal
        facts = value.trusted_facts
        return (
            type(value) is NormalizedInput
            and type(value.evaluation_time) is datetime
            and value.evaluation_time.tzinfo is timezone.utc
            and _proposal_is_typed(proposal)
            and _source_is_typed(value.manifest)
            and _source_is_typed(value.policy)
            and _source_is_typed(value.physical_ceiling)
            and type(facts) is TrustedFacts
            and type(facts.operation_id) is str
            and _OPERATION_ID.fullmatch(facts.operation_id) is not None
            and type(facts.material_digest) is str
            and _DIGEST.fullmatch(facts.material_digest) is not None
            and type(facts.observed_at) is datetime
            and type(facts.expires_at) is datetime
            and facts.observed_at.tzinfo is timezone.utc
            and facts.expires_at.tzinfo is timezone.utc
            and facts.observed_at < facts.expires_at
            and type(facts.clauses) is tuple
            and 1 <= len(facts.clauses) <= _MAX_AUTHORITY_CLAUSES
            and all(_clause_is_typed(item) for item in facts.clauses)
            and tuple(sorted(facts.clauses, key=clause_digest)) == facts.clauses
            and len({clause_digest(item) for item in facts.clauses}) == len(facts.clauses)
        )
    except Exception:
        return False


def classify(value: object) -> ClassifiedInput | Decision:
    """Validate closed relations, typed selectors, bindings, and freshness."""

    try:
        if not _normalized_is_typed(value):
            return _decision(Outcome.STOP, Reason.MALFORMED_INPUT, Stage.CLASSIFY)
        clauses = (
            value.proposal.authority,
            *value.manifest.clauses,
            *value.policy.clauses,
            *value.physical_ceiling.clauses,
            *value.trusted_facts.clauses,
        )
        if any((item.effect, item.resource, item.operation) not in EFFECT_RESOURCE_OPERATIONS for item in clauses):
            return _decision(Outcome.STOP, Reason.UNKNOWN_INPUT, Stage.CLASSIFY)
        if any(not _selector_matches_resource(item) for item in clauses):
            return _decision(Outcome.DENY, Reason.TYPED_SCOPE_MISMATCH, Stage.CLASSIFY)
        operation_id = value.proposal.operation_id
        if any(
            source.operation_id != operation_id
            for source in (value.manifest, value.policy, value.physical_ceiling, value.trusted_facts)
        ):
            return _decision(Outcome.STOP, Reason.BINDING_MISMATCH, Stage.CLASSIFY)
        if value.trusted_facts.material_digest != value.proposal.material_digest:
            return _decision(Outcome.STOP, Reason.BINDING_MISMATCH, Stage.CLASSIFY)
        now = value.evaluation_time
        if not (value.trusted_facts.observed_at <= now < value.trusted_facts.expires_at):
            return _decision(Outcome.STOP, Reason.STALE_INPUT, Stage.CLASSIFY)
        proposed = value.proposal.authority
        if not (proposed.not_before <= now < proposed.not_after):
            return _decision(Outcome.STOP, Reason.STALE_INPUT, Stage.CLASSIFY)
        return ClassifiedInput(value)
    except Exception:
        return _decision(Outcome.STOP, Reason.INTERNAL_ERROR, Stage.CLASSIFY)


def _path_within(path: str, root: str) -> bool:
    path_parts = path.split("/")[1:]
    root_parts = root.split("/")[1:]
    return path_parts[: len(root_parts)] == root_parts


def _selector_contains(bound: Selector, requested: Selector) -> bool:
    if bound.kind is SelectorKind.PATH_EXACT:
        return requested.kind is SelectorKind.PATH_EXACT and bound.value == requested.value
    if bound.kind is SelectorKind.PATH_PREFIX:
        return requested.kind in {SelectorKind.PATH_EXACT, SelectorKind.PATH_PREFIX} and _path_within(
            requested.value,
            bound.value,
        )
    return bound == requested


def _contains(bound: AuthorityClause, requested: AuthorityClause) -> bool:
    return (
        bound.effect is requested.effect
        and bound.resource is requested.resource
        and bound.operation is requested.operation
        and _selector_contains(bound.selector, requested.selector)
        and set(requested.facets) <= set(bound.facets)
        and bound.not_before <= requested.not_before
        and requested.not_after <= bound.not_after
        and requested.max_duration_ms <= bound.max_duration_ms
        and requested.quantity_unit is bound.quantity_unit
        and requested.max_quantity <= bound.max_quantity
        and requested.max_concurrency <= bound.max_concurrency
    )


def derive(value: object) -> DerivedAuthority | Decision:
    """Meet manifest, policy, physical ceiling, and trusted fact authority."""

    try:
        if type(value) is not ClassifiedInput:
            return _decision(Outcome.STOP, Reason.MALFORMED_INPUT, Stage.DERIVE)
        checked = classify(value.normalized)
        if type(checked) is Decision:
            return _decision(checked.outcome, checked.reason, Stage.DERIVE)
        if checked != value:
            return _decision(Outcome.STOP, Reason.MALFORMED_INPUT, Stage.DERIVE)
        requested = value.normalized.proposal.authority
        sources = (
            value.normalized.manifest.clauses,
            value.normalized.policy.clauses,
            value.normalized.physical_ceiling.clauses,
            value.normalized.trusted_facts.clauses,
        )
        selected: list[str] = []
        for clauses in sources:
            correlated = tuple(
                item
                for item in clauses
                if item.effect is requested.effect
                and item.resource is requested.resource
                and item.operation is requested.operation
            )
            if not correlated:
                return _decision(Outcome.DENY, Reason.AUTHORITY_EXCEEDED, Stage.DERIVE)
            selector_matches = tuple(item for item in correlated if _selector_contains(item.selector, requested.selector))
            if not selector_matches:
                return _decision(Outcome.DENY, Reason.TYPED_SCOPE_MISMATCH, Stage.DERIVE)
            covering = tuple(item for item in selector_matches if _contains(item, requested))
            if not covering:
                return _decision(Outcome.DENY, Reason.AUTHORITY_EXCEEDED, Stage.DERIVE)
            selected.append(min(clause_digest(item) for item in covering))
        return DerivedAuthority(
            value,
            requested,
            proposal_digest(value.normalized.proposal),
            (selected[0], selected[1], selected[2], selected[3]),
        )
    except Exception:
        return _decision(Outcome.STOP, Reason.INTERNAL_ERROR, Stage.DERIVE)


def decide(value: object) -> Decision:
    """Return a total decision whose ALLOW contains only a powerless proposal."""

    try:
        if type(value) is not DerivedAuthority:
            return _decision(Outcome.STOP, Reason.MALFORMED_INPUT, Stage.DECIDE)
        checked = derive(value.classified)
        if type(checked) is Decision:
            return _decision(checked.outcome, checked.reason, Stage.DECIDE)
        if checked != value:
            return _decision(Outcome.STOP, Reason.BINDING_MISMATCH, Stage.DECIDE)
        proposal = value.classified.normalized.proposal
        powerless = PowerlessProposal(proposal, value.proposal_digest)
        return _decision(
            Outcome.ALLOW,
            Reason.AUTHORIZED_EXACT_BOUND,
            Stage.DECIDE,
            value.proposal_digest,
            (powerless,),
        )
    except Exception:
        return _decision(Outcome.STOP, Reason.INTERNAL_ERROR, Stage.DECIDE)


def _decision_is_valid(value: object) -> bool:
    try:
        if (
            type(value) is not Decision
            or type(value.outcome) is not Outcome
            or type(value.reason) is not Reason
            or type(value.stage) is not Stage
            or type(value.proposals) is not tuple
            or type(value.decision_digest) is not str
            or _DIGEST.fullmatch(value.decision_digest) is None
        ):
            return False
        if value.outcome is Outcome.ALLOW:
            if (
                value.stage is not Stage.DECIDE
                or value.reason is not Reason.AUTHORIZED_EXACT_BOUND
                or type(value.proposal_digest) is not str
                or _DIGEST.fullmatch(value.proposal_digest) is None
                or len(value.proposals) != 1
            ):
                return False
            proposal = value.proposals[0]
            if (
                type(proposal) is not PowerlessProposal
                or proposal.authority is not ProposalAuthority.NONE
                or proposal.proposal_digest != value.proposal_digest
                or not _proposal_is_typed(proposal.proposal)
                or proposal_digest(proposal.proposal) != value.proposal_digest
            ):
                return False
        elif (
            value.outcome not in {Outcome.DENY, Outcome.STOP}
            or value.reason is Reason.AUTHORIZED_EXACT_BOUND
            or value.proposal_digest is not None
            or value.proposals
        ):
            return False
        expected = canonical_digest(
            decision_data(
                value.outcome,
                value.reason,
                value.stage,
                value.proposal_digest,
                value.proposals,
            )
        )
        return value.decision_digest == expected
    except Exception:
        return False


def _state_is_valid(value: object) -> bool:
    return type(value) is KernelState and (
        (value.phase is Phase.STOPPED and value.decision_digest is None)
        or (
            value.phase is Phase.DECIDED
            and type(value.decision_digest) is str
            and _DIGEST.fullmatch(value.decision_digest) is not None
        )
    )


def transition(state: object, decision: object) -> TransitionResult:
    """Purely project a decision into immutable model state; perform no action."""

    try:
        if not _state_is_valid(state):
            return TransitionResult(
                False,
                Outcome.STOP,
                Reason.MALFORMED_INPUT,
                KernelState(),
            )
        if type(decision) is not Decision:
            return TransitionResult(False, Outcome.STOP, Reason.MALFORMED_INPUT, state)
        if not _decision_is_valid(decision):
            return TransitionResult(False, Outcome.STOP, Reason.BINDING_MISMATCH, state)
        if decision.outcome is not Outcome.ALLOW:
            return TransitionResult(False, decision.outcome, decision.reason, state)
        if state.phase is not Phase.STOPPED:
            return TransitionResult(False, Outcome.STOP, Reason.ILLEGAL_TRANSITION, state)
        return TransitionResult(
            True,
            Outcome.ALLOW,
            Reason.AUTHORIZED_EXACT_BOUND,
            KernelState(Phase.DECIDED, decision.decision_digest),
            decision.proposals,
        )
    except Exception:
        safe_state = state if _state_is_valid(state) else KernelState()
        return TransitionResult(False, Outcome.STOP, Reason.INTERNAL_ERROR, safe_state)


def evaluate(raw: object, state: object = KernelState()) -> KernelResult:
    """Run normalize → classify → derive → decide → transition as one pure API."""

    try:
        if not _state_is_valid(state):
            failure = _decision(Outcome.STOP, Reason.MALFORMED_INPUT, Stage.TRANSITION)
            return KernelResult(failure, transition(state, failure))
        if state.phase is not Phase.STOPPED:
            failure = _decision(Outcome.STOP, Reason.ILLEGAL_TRANSITION, Stage.TRANSITION)
            return KernelResult(failure, transition(state, failure))
        normalized = normalize(raw)
        if type(normalized) is Decision:
            return KernelResult(normalized, transition(state, normalized))
        classified = classify(normalized)
        if type(classified) is Decision:
            return KernelResult(classified, transition(state, classified))
        derived = derive(classified)
        if type(derived) is Decision:
            return KernelResult(derived, transition(state, derived))
        decision = decide(derived)
        return KernelResult(decision, transition(state, decision))
    except Exception:
        failure = _decision(Outcome.STOP, Reason.INTERNAL_ERROR, Stage.TRANSITION)
        safe_state = state if _state_is_valid(state) else KernelState()
        return KernelResult(failure, TransitionResult(False, Outcome.STOP, Reason.INTERNAL_ERROR, safe_state))
