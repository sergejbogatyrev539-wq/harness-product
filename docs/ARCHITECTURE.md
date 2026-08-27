# Target architecture

This document describes the intended implementation boundary. It does not attest
that a runtime exists.

## Implemented M1-M4 exact-profile code boundary

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
outside the package-root API. Format version 1/schema version 5 uses `STRICT`
tables and foreign keys. Exact v1-v3 schemas migrate atomically; v4 migrates
only with an empty M4 surface and otherwise fails closed without mutation;
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
revalidating exact M2 claim and supply-verifier records, it must atomically
consume a current one-use M4 stage authorization bound to the exact
contract/frontier attempt, target authority and root/object identity before it
can replace that file inside a 0700 disposable staging root. A claim, boolean or
caller digest alone cannot stage. It has no project-root path, network, shell,
commit, seal, JOIN, or retry surface. A fault
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

M4 keeps the same deep-module shape. `harness_product.m4` is one direct
Controller/PEP coordinator and `harness_product.publisher` is one exact trusted
publication boundary. The coordinator reruns M1 admission and uses only an
existing M2 dispatch claim plus trusted active-contract/D2 state. One immutable
topology binds the disposable staging object, separate publication target,
worker/controller/executor/observer/publisher subjects, sole publisher writer,
and denied `.git` authority. Neither root descriptor is accepted from the M4
request. Schema v5 stores fenced, verified records for `STAGED`, `QUIESCED`,
`SEALED`, `POSTCHECKED`, `COMMITTED`, `JOINED`, `DISCARDED`, `QUARANTINED`, and
`RECONCILING`. Every record preserves the exact four-part budget key; only a
COMMITTED record containing verified publication authorization and receipt
spends escrow, while uncertainty and recovery never resume or retry.
The append-only D2 frontier sequence is the attempt ledger: every committed
frontier consumes the next slot, terminal discard and restart do not reset it,
and `joined_iteration` remains the last successful JOIN rather than an attempt
cursor.

Stage and observer children close the complete Linux descriptor space with
`close_range` and fail closed if exact allowlist closure cannot be proved. The
controller retains the trusted staging resolver and rechecks the exact inode
by descriptor and canonical path at every boundary. A Linux read lease has no
fallback; its break flag, state, owner, device/inode, mount and content remain
checked through JOIN. The controller copies that inode into a memfd and applies
all four immutable seals. A separate observer child sees only a read-only
snapshot and emits a powerless proposal; a full external observer receipt is
mandatory. A separately verified publication authorization then permits the
trusted publisher to consume only the sealed descriptor, atomically replace its
fixed descriptor-rooted target, fsync, and return a mandatory verified receipt.
The publication root is separately anchored to its mount namespace, mountpoint,
absolute path, basename, root identity and complete physical ancestry; those
facts are checked around atomic replacement and again before COMMIT/JOIN. The
controller performs one final lease/path check before JOIN. Existing or new
writers, lease loss, unsupported filesystems, path/inode/target substitution,
publication-root relocation (including movement under `.git`), crashes,
publication uncertainty, or record mutations prohibit JOIN and
preserve quarantine/no-retry semantics. A reconciling lineage also fences fresh
issue, consume, claim, frontier and begin transitions. The external branch
remains explicitly disabled.

The boundaries above implement the powerless proposal/claim/session/staging and
trusted-publication code edges. The physical M4 principal topology remains
unattested on this host; a compiled role record and local child process are not
proof of deployment separation. `DEPLOYMENT_ATTESTED` therefore remains
`ABSENT`, and product status remains `NOT_IMPLEMENTED`, `NOT_ATTESTED`, and
`NOT_READY`.

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
| `T-Q40-*`, `T-Q44-*`, `T-Q49-*`, `T-Q50-*` | `test_m4_durable.py` complete D2, contract/lineage, typed evidence and four-part budget mutation matrices | UNIT; production external anchor ABSENT |
| `T-Q45-STAGEABLE-CRASH-QUARANTINES`, `T-Q48-POLICY-SCOPE-KIND-CROSS-MATRIX` | `test_m4.py` process/fault recovery, no-retry escrow, endpoint deny, exact inode lease races and atomic publication uncertainty | UNIT; current physical M4 qualification ABSENT |
| `M4-SEC-001`–`M4-SEC-005`, `INT-001`–`INT-003`, `FORMAL-ATTEMPT-001` | `test_m4.py` and `test_m4_durable.py` trusted-root, ancestry, observer, full-FD closure, durable stage-authorization, lineage-fence, publisher and attempt-ceiling matrices | UNIT; `DEPLOYMENT_ATTESTED` topology ABSENT on this host |

```text
untrusted worker ── powerless proposal ──> Controller / PEP
                                              │ pure total decision
                                              v
                                  durable broker + journal + capability store
                                              │ exact-bound, one-use dispatch
                                              v
                              exact staging executor
                                              │ sealed read-only snapshot
                                              v
                       observer proposal → verified observer receipt
                                              │ verified publish authorization
                                              v
                  trusted publisher → verified receipt → COMMIT → JOIN
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
intent, one-attempt claims, and M4 lifecycle records; it supplies no connector,
gateway, external cryptography/trust root/attestation, production executor, or
non-bypassable deployment. The local hash chain cannot detect a coherent whole-database
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

No reviewed host VM entrypoint or append-only *qualification-attempt* ledger
exists yet, so a new full VM cycle is forbidden. This is distinct from the M4
contract-attempt ledger above. A future launcher must consume the exact
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
