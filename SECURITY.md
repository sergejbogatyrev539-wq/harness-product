# Security boundary

Harness treats agent/model output and all imported content as potentially hostile.
Text in those sources is input data, not policy, authority, or instructions.

## Non-negotiable boundary

These are runtime requirements, not current implementation claims. M1 only
models their admission inputs and powerless output; M2/M3 must provide durable
mediation and an enforced profile before any boundary can be claimed.

- The worker has no ambient credential, executor, or network/sink authority.
- The only effect route is Controller/PEP → broker → exact-bound executor or
  gateway. Each downstream hop revalidates identity, scope, digests, epoch, and
  one-use capability; mismatch prevents dispatch.
- `STOPPED` is fail-closed. Unknown, missing, stale, mismatched, unclassified,
  or unbounded state never permits an effect. Unknown external outcome is
  quarantined and is never auto-retried.
- An approval, hash, schema, summary, model output, or agent self-report cannot
  widen authority or by itself prove safety.

## Claims and evidence

Do not claim complete isolation, exhaustive classification, zero covert channels,
or production readiness. A control becomes an enforceable claim only after its
non-bypassable implementation, negative tests, and retained same-profile evidence
are available. Any material digest change invalidates dependent evidence.

This includes development and review inputs that are part of the measured
candidate. A retained bundle remains valid evidence about its exact historical
candidate; it must never be relabelled as evidence for a later commit. A failed
qualification is not permission to retry or patch: the user authorizes the
action, and `AGENTS.md` controls the bounded diagnostic cadence.

The detailed threat model and residual-risk requirements are normative in
`spec/03_SYSTEM_THREAT_TRUST_MODEL.md`.

## Implemented M2 durable-intent boundary

`harness_product.durable` is a direct stdlib SQLite store, not an executor or
effect route. Format version 1/schema version 3, including exact audited
v1-to-v2-to-v3 migrations, uses `STRICT` tables, foreign keys, `BEGIN IMMEDIATE`,
rollback-journal (`DELETE`) mode, and `synchronous=FULL`. At issue and consume
it reruns/rechecks the exact M1 result, full canonical bindings, and full
verifier record. Its one durable consume transaction records capability use,
component-wise reservation, exact dispatch intent, monotonic journal/counters,
and a mandatory local outbox event. Recovery only exposes that state; it never
dispatches or creates a retry. A reservation has one terminal disposition:
`SPENT`, `RELEASED`, or `QUARANTINED_ESCROW`; `RELEASED` requires an independently
verified no-effect record.

An M3 claim transition can expose an executor envelope only once and only for a
committed pending intent. It rechecks the full capability and verifier record,
nonce-bound consumed state, expiry, current revocation/fencing epochs, and a
second external verifier record, then atomically appends the claim and mandatory
journal/outbox event. Crash recovery reports `ATTEMPT_CLAIMED` without returning
an envelope or creating a retry. This remains durable mediation, not execution.

Before prospective untrusted exec, a further atomic transition stores the full
closed runtime object inventory, external runtime-verifier record, claim,
profile, placement, session and fence bindings as `PREPARED`, with its mandatory
journal/outbox event. Terminal records are exactly `STOPPED`, `TIMED_OUT`, or
`QUARANTINED`; only independently verified no-effect cleanup may release budget.
Recovery enumerates stale records but never resumes a process or dispatches a
retry.

This is not external cryptography, a trust root, runtime attestation, OS
enforcement, non-bypassable mediation, or readiness. The local hash chain can
detect inconsistent local chain state, but cannot detect a coherent rollback of
the whole database without an independent external anchor. `synchronous=FULL`
also relies on the filesystem/device honoring flush and ordering guarantees; it
does not prove power-loss durability.

## M3 exact-profile implementation boundary

`harness_product.l0` compiles only the closed draft
`L0-LX-A / DISCONNECTED_STAGEABLE_WORKER` profile and performs read-only host
preflight for one exact pinned `/usr/bin/bwrap` backend. A successful compile is
not activation, session attestation, or enforcement. Missing, extra, hostile,
unbounded, duplicate, shared-identity, or
mismatched profile/control input returns a structured `STOP` without a partial
profile. Host/runtime exceptions also become `STOP`.

Preflight creates no namespaces, cgroups, sockets, worker, executor, or staging
write. A host without a dedicated cgroup-v2 subtree with delegated CPU and IO
controllers stops before launch. No fallback runtime is attempted.

The same module has two separately callable, closed boundaries: exact
`UNIX_SEQPACKET` ingress with peer-credential and canonical binding checks, and
descriptor-rooted target resolution using all four required `openat2` resolve
restrictions. Its only effect replaces one existing canary under a pre-opened
0700 disposable staging root after an exact M2 claim and repeated external
claim verification. It rejects traversal, links, cross-mount and descriptor/
root/mount/epoch/object substitution; any post-write uncertainty is returned as
`QUARANTINED` and the original binding cannot be retried.

Supply admission has no production default: it hashes actual bytes from exact
pre-opened descriptors and requires an external verifier over the complete
canonical rootfs/runtime/loader/dependency/tool/SBOM/registry/signer/profile/
placement payload and record. Caller-provided digests, tags, booleans and
self-signed test fixtures cannot pass. The session planner then remeasures and
binds the exact namespace, cgroup, mount, IPC, descriptor, process-tree, quota
and cleanup inventory. Its staging scope is explicitly absent from the worker
mount and FD plan.

The supervisor implementation repeats host measurement, requires the durable
`PREPARED` commit before launch, uses one exact typed bwrap argv with
`shell=False`, releases an early start gate only after cgroup controls and PID
placement, enforces external wall/CPU termination, kills the complete cgroup,
and fails terminal uncertainty to quarantine without retry. These are code and
unit-test properties in the current tree. The exact disposable test-VM candidate
at product commit `437ee01ca331cd7e4632fb8ad55eaa894254daa9` also produced
retained physical test evidence. That evidence is historical after any later
commit and is not a production trust root, deployment attestation, or readiness
claim.

`scripts/check_m3_l0.py` is a separate non-skipping gate. Its no-argument host
preflight exits nonzero with `ABSENT/CGROUP_DELEGATION_ABSENT` whenever the exact
delegated CPU/IO cgroup boundary is unavailable. Production external trust
roots, a production privileged runtime attestor, and production deployment
evidence remain absent.
Consequently the disposable-VM qualification does not establish production
isolation, production non-bypassability, production supply attestation, or
readiness.
