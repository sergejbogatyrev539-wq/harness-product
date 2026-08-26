# Target architecture

This document describes the intended implementation boundary. It does not attest
that a runtime exists.

## Implemented M1/M2 and M3 exact-profile code boundary

The M1 portion of the current implementation is one pure in-memory pipeline:

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
outside the package-root API. Format version 1/schema version 3 (with exact
audited v1-to-v2-to-v3 migrations) uses `STRICT` tables and foreign keys;
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

The same store durably records an exact pre-exec session only after the complete
claim/capability/verification/expiry/revocation/fence checks and an external
runtime-verifier check. One transaction appends `PREPARED` plus its mandatory
journal/outbox event. Terminal state is exactly `STOPPED`, `TIMED_OUT`, or
`QUARANTINED`; only independently verified no-effect cleanup releases budget.
Recovery exposes frozen summaries and never resumes or retries them.

M3 adds one direct `harness_product.l0` module without exporting it from the
package root. Its first slice is a pure closed compiler for the exact draft
`L0-LX-A / DISCONNECTED_STAGEABLE_WORKER` profile and a read-only host
preflight. The compiler produces canonical immutable role, resource, broker-IPC,
and measurement-plan bindings; it never treats `verified=true`, a digest, or a
draft profile as physical proof. The only selected backend is the pinned
root-owned `/usr/bin/bwrap` binary (bubblewrap 0.9.0, exact SHA-256 bound in
code). Preflight verifies the binary and required platform capabilities with
typed absolute argv and no shell. It creates no runtime object or effect.

The supply boundary hashes actual bytes from pre-opened immutable descriptors
and binds the rootfs manifest, runtime and loader, dependency closure, tools,
SBOM, registry snapshot/generation, signer/key/algorithm/lifecycle/rollback,
profile and placement. It requires a separate verifier over the full canonical
payload and verification record; it has no default trust root and never accepts
a caller boolean, bare hash, image tag, or self-signed fixture as proof.

The next slice remains in the same deep module. `receive_broker_message`
accepts one bounded canonical message from an exact `AF_UNIX/SOCK_SEQPACKET`
descriptor only after `SO_PEERCRED`, process-session, worker/session/nonce/fence,
and broker-binding checks. `resolve_target` opens one existing file relative to
a trusted root descriptor with `openat2(BENEATH|NO_MAGICLINKS|NO_SYMLINKS|NO_XDEV)`
and binds path, descriptor/root/mount/epoch, final device/inode/type/content, and
one composite digest. `stage_committed_intent` is the sole effect surface: after
revalidating exact M2 claim and supply-verifier records, it can replace that file
inside a 0700 disposable staging root. It has no project-root path,
durable DB handle, network, shell, commit, seal, JOIN, or retry surface. A fault
after the first write becomes `QUARANTINED/STAGE_OUTCOME_UNKNOWN`.

`prepare_session` remeasures the complete prospective runtime inventory and
binds namespace identities, non-host UID/GID, rootfs and read-only inputs,
broker socket, seccomp/tool bytes, cgroup, all inherited FDs, process-tree,
quota and cleanup records. Staging is deliberately absent from worker mounts and
FDs. `supervise_session` has one bwrap backend and no fallback: it remeasures the
host, commits the durable `PREPARED` record before launch, writes and verifies
the cgroup-v2 limits, uses exact typed argv with `shell=False`, starts behind an
early gate, applies RLIMIT and external wall/CPU termination, kills the complete
cgroup and terminally releases or quarantines the reservation. The implementation
does not retry after any uncertain outcome.

A host without a dedicated cgroup-v2 subtree and delegated CPU/IO controllers
returns structured `STOP/CGROUP_DELEGATION_ABSENT`. Preflight returns no partial
compiled/measurement authority and does not fall back to Docker or a weaker
profile.

The exact disposable test-VM candidate at product commit
`437ee01ca331cd7e4632fb8ad55eaa894254daa9` completed its physical qualification
and produced a retained signed bundle. This is exact historical test-profile
evidence, not a reusable claim about later commits and not production
attestation.

The boundaries above implement the powerless proposal/claim/session/staging
edges. The following physical principal topology remains unattested on this
host; a compiled role record is not proof that the processes were separated.

The safe regression mapping is explicit; `UNIT` below proves the closed code
boundary only, while `ABSENT` means the physical exact-profile oracle still
requires the non-skipping conformance environment.

| Normative rows | Regression boundary | Claim |
|---|---|---|
| `ATK-001`, `ATK-019`, `T-Q43-DESCRIPTOR-ROOT-SUBSTITUTION` | `test_l0.py` descriptor/path/link/mount/epoch/object cases and unchanged external canaries | UNIT; runtime TCB evidence ABSENT |
| `ATK-003`, `T-Q46-DIRECT-WORKER-MUTATE-DENY`, `T-Q47-MUTATION-SELF-AUDIENCE-DENY`, `T-DECISION-ALLOW-EXACT` | `test_l0.py`, `test_l0_stage.py`, and retained M1 decision tests | UNIT; distinct-principal attestation ABSENT |
| `ATK-028`, `T-Q39-SUPPLY-EXTERNAL-BUNDLE-SUBSTITUTION` | `test_l0_supply.py` exact opened-byte and every-component substitution matrix | UNIT; production trust root ABSENT |
| `ATK-002`, `ATK-020`, `ATK-021`, `ATK-034` | `test_l0.py` and `test_l0_lifecycle.py` closed network/FD/secret/IPC/process plans | UNIT; syscall/TCB attack evidence ABSENT |
| `ATK-007`, `ATK-010`, `ATK-022` | exact Q-56 compiler rows, lifecycle cgroup/RLIMIT/watchdog plan, durable budget conservation | UNIT; physical limit receipts ABSENT |
| `ATK-011`, `ATK-012`, `ATK-026` | no checkout/`.git`/home/staging visibility, disposable-root stage tests, durable cleanup/quarantine state | UNIT; cross-session cleanup proof ABSENT |

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
durability. The M3 compiler/preflight, supply, lifecycle and local staging tests
prove closed planning, durable ordering, descriptor mediation, fail-closed error
handling and the one disposable-root operation only. `scripts/check_m3_l0.py`
is a separate non-skipping exact-profile gate. Its host preflight exits nonzero
with `ABSENT/CGROUP_DELEGATION_ABSENT` when exact cgroup delegation is absent. A worker was qualified
only in the exact disposable test VM bound to the historical commit named
above. No production external trust root, production privileged runtime
attestor, or current production evidence exists. Therefore the product remains
`NOT_IMPLEMENTED`, `NOT_ATTESTED`, and `NOT_READY`.

## Development control loop

The implementation process is fail-closed. One micro-iteration changes one
cohesive invariant and proves it with the smallest focused oracle. A module
suite follows a coherent cluster; repository conformance follows a checkpoint;
physical qualification follows only a stable candidate whose cheaper gates are
green. Host-side evidence parsing is tested against retained or synthetic
bundles before a VM is started.

`.agent/WORKING_CONTEXT.json`, initialized from the tracked closed template, is
ignored non-authorizing handoff state. After compaction, restart, or handoff,
the root/controller agent rereads the complete `AGENTS.md` and that record before
acting; process-blind reviewers do not. The live record is not part of a runtime
candidate. No report, passing test, or roadmap transition starts another attempt
or milestone without fresh user authority.

No reviewed host VM entrypoint or append-only attempt ledger exists yet, so a
new full VM cycle is forbidden. A future launcher must consume the exact
candidate/environment/ceiling/user-scope tuple once before launch and reject
replay across restart or handoff.

## Evidence and profiles

The product binds policy, manifest, code/image, tool registry, prompt/context,
contract, target, profile, decisions, capabilities, receipts, and events by
canonical digests. Evidence is valid only for the exact measured profile; material
changes invalidate future bindings and require new evidence.

The first profile should deny external/non-stageable effects, raw secrets,
delegation, persistent reflection, and break-glass. Broader profiles require the
additional controls and evidence defined by the normative `spec/` corpus.
