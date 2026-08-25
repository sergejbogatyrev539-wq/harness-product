# Target architecture

This document describes the intended implementation boundary. It does not attest
that a runtime exists.

## Implemented M1/M2 and M3 draft-preflight boundary

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
outside the package-root API. Schema v2 (with exact audited v1 migration) uses
`STRICT` tables and foreign keys;
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

M3 adds one atomic `claim_dispatch` transition to that store. It derives the
claim exclusively from a committed intent and its stored capability, repeats
the complete capability/verifier/expiry/revocation/fence checks, verifies a
second canonical executor record, and persists the one-attempt claim plus its
journal/outbox event before returning a frozen envelope. Recovery returns only
`ATTEMPT_CLAIMED`; it never recreates the envelope or retries.

M3 adds one direct `harness_product.l0` module without exporting it from the
package root. Its first slice is a pure closed compiler for the exact draft
`L0-LX-A / DISCONNECTED_STAGEABLE_WORKER` profile and a read-only host
preflight. The compiler produces canonical immutable role, resource, broker-IPC,
and measurement-plan bindings; it never treats `verified=true`, a digest, or a
draft profile as physical proof. The only selected backend is the pinned
root-owned `/usr/bin/bwrap` binary (bubblewrap 0.9.0, exact SHA-256 bound in
code). Preflight verifies the binary and required platform capabilities with
typed absolute argv and no shell. It creates no runtime object or effect.

The next slice remains in the same deep module. `receive_broker_message`
accepts one bounded canonical message from an exact `AF_UNIX/SOCK_SEQPACKET`
descriptor only after `SO_PEERCRED`, process-session, worker/session/nonce/fence,
and broker-binding checks. `resolve_target` opens one existing file relative to
a trusted root descriptor with `openat2(BENEATH|NO_MAGICLINKS|NO_SYMLINKS|NO_XDEV)`
and binds path, descriptor/root/mount/epoch, final device/inode/type/content, and
one composite digest. `stage_committed_intent` is the sole effect surface: after
revalidating an exact M2 claim and external claim-verifier record, it can replace
that file inside a 0700 disposable staging root. It has no project-root path,
durable DB handle, network, shell, commit, seal, JOIN, or retry surface. A fault
after the first write becomes `QUARANTINED/STAGE_OUTCOME_UNKNOWN`.

The current host result is a structured `STOP/CGROUP_DELEGATION_ABSENT`: the
application cgroup is shared and lacks delegated CPU/IO controllers. The
preflight consequently returns no partial compiled/measurement authority and
does not fall back to Docker or a weaker profile.

The boundaries above implement the powerless proposal/claim/staging edges, but
the following physical principal topology remains unfinished and unattested M3
work.

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

M1 remains pure and returns only powerless proposals. The durable store persists
intent and one-attempt claims, not effects: it supplies no executor, connector, gateway, effect
adapter, external cryptography/trust root/attestation, OS enforcement, or
non-bypassable path. The local hash chain cannot detect a coherent whole-database
rollback without an independent external anchor. `synchronous=FULL` depends on
filesystem/device flush and ordering behavior and is not proof of power-loss
durability. The M3 compiler/preflight and local staging tests prove closed
planning, descriptor mediation, and the one disposable-root operation only;
they have not launched or attested an isolated worker.
Therefore the product remains `NOT_IMPLEMENTED`, `NOT_ATTESTED`, and
`NOT_READY`; runtime enforcement and external evidence remain absent.

## Evidence and profiles

The product binds policy, manifest, code/image, tool registry, prompt/context,
contract, target, profile, decisions, capabilities, receipts, and events by
canonical digests. Evidence is valid only for the exact measured profile; material
changes invalidate future bindings and require new evidence.

The first profile should deny external/non-stageable effects, raw secrets,
delegation, persistent reflection, and break-glass. Broader profiles require the
additional controls and evidence defined by the normative `spec/` corpus.
