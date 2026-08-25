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

The detailed threat model and residual-risk requirements are normative in
`spec/03_SYSTEM_THREAT_TRUST_MODEL.md`.

## Implemented M2 durable-intent boundary

`harness_product.durable` is a direct stdlib SQLite store, not an executor or
effect route. Schema v1 uses `STRICT` tables, foreign keys, `BEGIN IMMEDIATE`,
rollback-journal (`DELETE`) mode, and `synchronous=FULL`. At issue and consume
it reruns/rechecks the exact M1 result, full canonical bindings, and full
verifier record. Its one durable consume transaction records capability use,
component-wise reservation, exact dispatch intent, monotonic journal/counters,
and a mandatory local outbox event. Recovery only exposes that state; it never
dispatches or creates a retry. A reservation has one terminal disposition:
`SPENT`, `RELEASED`, or `QUARANTINED_ESCROW`; `RELEASED` requires an independently
verified no-effect record.

This is not external cryptography, a trust root, runtime attestation, OS
enforcement, non-bypassable mediation, or readiness. The local hash chain can
detect inconsistent local chain state, but cannot detect a coherent rollback of
the whole database without an independent external anchor. `synchronous=FULL`
also relies on the filesystem/device honoring flush and ordering guarantees; it
does not prove power-loss durability.

## M3 draft compiler and preflight boundary

`harness_product.l0` currently compiles only the closed draft
`L0-LX-A / DISCONNECTED_STAGEABLE_WORKER` profile and performs read-only host
preflight for one exact pinned `/usr/bin/bwrap` backend. A successful compile is
not activation, supply verification, placement proof, session attestation, or
enforcement. Missing, extra, hostile, unbounded, duplicate, shared-identity, or
mismatched profile/control input returns a structured `STOP` without a partial
profile. Host/runtime exceptions also become `STOP`.

Preflight creates no namespaces, cgroups, sockets, worker, executor, or staging
write. On the current host it stops before launch because the session lacks a
dedicated cgroup-v2 subtree with delegated CPU and IO controllers. No fallback
runtime is attempted. Exact worker/broker/executor execution, descriptor-rooted
staging, external supply/placement verification, lifecycle cleanup evidence,
and runtime conformance are not yet implemented or claimed.
