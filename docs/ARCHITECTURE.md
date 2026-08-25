# Target architecture

This document describes the intended implementation boundary. It does not attest
that a runtime exists.

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

## Fail-closed lifecycle

`STOPPED → NORMALIZED → CLASSIFIED → DECIDED → durable consume/reserve/intent → DISPATCHED`.
Invalid state stops before dispatch. Stageable work seals an immutable snapshot
before independent postcheck; failed checks discard it. External outcomes that
cannot be proved are quarantined rather than retried. Recovery preserves durable
lineage, fences stale processes, and requires fresh admission where specified.

## Evidence and profiles

The product binds policy, manifest, code/image, tool registry, prompt/context,
contract, target, profile, decisions, capabilities, receipts, and events by
canonical digests. Evidence is valid only for the exact measured profile; material
changes invalidate future bindings and require new evidence.

The first profile should deny external/non-stageable effects, raw secrets,
delegation, persistent reflection, and break-glass. Broader profiles require the
additional controls and evidence defined by the normative `spec/` corpus.
