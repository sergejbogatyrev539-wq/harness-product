# Target architecture

This document describes the intended implementation boundary. It does not attest
that a runtime exists.

## Implemented M1 and M2 boundary

The current implementation is one pure in-memory pipeline:

```text
closed raw data → NORMALIZED → CLASSIFIED → DERIVED → DECIDED
                                                        │
                                                        v
                                      immutable DECIDED model state
                                      + powerless proposal (authority=NONE)
```

Normalization rejects missing and extra fields and creates immutable typed
values. Classification validates the closed effect/resource/operation relation,
typed selector relation, exact operation/material bindings, and caller-supplied
freshness time. Derivation admits only the exact proposal covered independently
by manifest, policy, physical ceiling, and trusted facts. Decision and transition
revalidate their inputs and return structured `DENY`/`STOP` on failure without
mutating the supplied data or state.

There is no ambient clock or randomness and no filesystem, network, process, or
shell adapter in M1. Trusted facts are model inputs; M1 does not attest their
provenance. Decision digests are deterministic bindings, not signatures.

M2 is one direct `harness_product.durable` stdlib SQLite module, deliberately
outside the package-root API. Schema v1 uses `STRICT` tables and foreign keys;
each competing mutation uses `BEGIN IMMEDIATE`, rollback-journal (`DELETE`) mode,
and `synchronous=FULL`. Capability issue reruns M1 and stores its full canonical
inputs, exact bindings, canonical decision digest, and full verifier record.
Consume rechecks that record and bindings, then atomically consumes the
capability, reserves the complete component-wise budget vector, advances durable
counters/journal, records exact dispatch intent/idempotency bindings, and writes
a mandatory local outbox event. A reservation terminally becomes `SPENT`,
`RELEASED`, or `QUARANTINED_ESCROW`; release is allowed only after an independently
verified no-effect record. Recovery never performs dispatch or creates retry.
Rollback `DELETE` mode is chosen for the serialized single-writer profile so
recovery does not also depend on WAL checkpoint state; SQLite still creates a
transient rollback-journal file for a transaction.

The following executor topology remains future M3+ work, not an implemented path.

```text
untrusted worker ── powerless proposal ──> Controller / PEP
                                              │ pure total decision
                                              v
                                  durable broker + journal + capability store
                                              │ exact-bound, one-use dispatch
                                              v
                         executor / model gateway / other declared sink
                                              │ authoritative receipt
                                              v
                               independent observer / postcheck → evidence
```

## Core

One deep control module may package the admission kernel, broker/PEP, durable
transaction coordinator, supervisor, and canonical event outbox. Packaging does
not collapse principals: when active, worker, broker, executor, gateway, and
observer remain separately attested security principals with distinct physical
ceilings.

The admission kernel canonicalizes a request, derives its transitive effects, and
purely decides its bounded envelope. The durable transaction atomically reserves
budget, consumes the one-use capability, records intent/counters, and fences
dispatch. No direct worker-to-executor or worker-to-sink route may exist.

## Target fail-closed lifecycle

`STOPPED → NORMALIZED → CLASSIFIED → DECIDED → durable consume/reserve/intent → DISPATCHED`.
Invalid state stops before dispatch. Stageable work seals an immutable snapshot
before independent postcheck; failed checks discard it. External outcomes that
cannot be proved are quarantined rather than retried. Recovery preserves durable
lineage, fences stale processes, and requires fresh admission where specified.

M1 remains pure and returns only powerless proposals. M2 persists a durable
intent, not an effect: it supplies no executor, connector, gateway, effect
adapter, external cryptography/trust root/attestation, OS enforcement, or
non-bypassable path. The local hash chain cannot detect a coherent whole-database
rollback without an independent external anchor. `synchronous=FULL` depends on
filesystem/device flush and ordering behavior and is not proof of power-loss
durability. Therefore the product remains `NOT_IMPLEMENTED`, `NOT_ATTESTED`, and
`NOT_READY`; enforcement, external evidence, and all M3+ work remain future.

## Evidence and profiles

The product binds policy, manifest, code/image, tool registry, prompt/context,
contract, target, profile, decisions, capabilities, receipts, and events by
canonical digests. Evidence is valid only for the exact measured profile; material
changes invalidate future bindings and require new evidence.

The first profile should deny external/non-stageable effects, raw secrets,
delegation, persistent reflection, and break-glass. Broader profiles require the
additional controls and evidence defined by the normative `spec/` corpus.
