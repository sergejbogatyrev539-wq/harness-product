# Harness product

Universal, policy-enforced mediation for agent-initiated work. The product is to
turn the normative Harness specification into a runtime in which untrusted
workers can propose bounded work but cannot bypass the control path.

## Current status

`specification=SPECIFIED; runtime=NOT_IMPLEMENTED; runtime_attestation=NOT_ATTESTED; overall=NOT_READY`.
The copied `spec/` corpus is normative; it is not a runnable security product.

## Start here

```bash
python -m venv .venv
.venv/bin/pip install -e .
.venv/bin/python scripts/check.py
```

The single check verifies all 48 transferred specification files against
`spec/MANIFEST.sha256`, runs the product unit tests, and executes the original
specification-model runner. Any missing dependency or check is a failure, not a
skip.

## Intended minimum

1. A pure, total admission kernel derives and narrows an exact authority envelope.
2. A Controller/PEP and broker durably authorize one use of a capability.
3. A separately attested executor or gateway performs the exact call; a worker
   only sends powerless proposals.
4. The runtime blocks unknown or mismatched state, records authoritative events,
   and retains same-profile evidence.

See [architecture](docs/ARCHITECTURE.md), [roadmap](ROADMAP.md), and
[security boundary](SECURITY.md). Implementations must follow [AGENTS.md](AGENTS.md).

`src/harness_product/` keeps the M1 in-memory model pure. Its public
`evaluate` API runs the deterministic
`normalize → classify → derive → decide → transition` chain over closed input
data and explicit time. Effective authority is the exact proposal contained by
the manifest, policy, physical ceiling, and trusted-fact inputs. An `ALLOW`
contains only an immutable proposal marked `authority=NONE`; it cannot dispatch
or perform an effect. The returned digest is a deterministic binding, not a
signature or attestation.

M2 adds one direct, non-root-exported `harness_product.durable` stdlib SQLite
store. Its schema v1 uses `STRICT` tables, foreign keys, `BEGIN IMMEDIATE`,
rollback-journal (`DELETE`) mode, and `synchronous=FULL`. Issue reruns the exact
M1 decision and stores the complete canonical M1 inputs/bindings and complete
verifier record; consume checks them again. A single commit consumes the
capability, reserves every budget component, records the exact durable dispatch
intent, counters/journal, and a mandatory local outbox event. Reservations end
exactly once as `SPENT`, `RELEASED`, or `QUARANTINED_ESCROW`; release requires an
independently verified no-effect record. Recovery never dispatches or retries.

`DELETE` is intentional for this single-writer profile: `BEGIN IMMEDIATE`
serializes mutations, while rollback journaling avoids a separate WAL checkpoint
lifecycle. It still uses a transient rollback-journal file during a transaction.

This is durable intent only: it has no executor, connector, effect adapter,
external crypto/trust root/attestation, OS enforcement, non-bypassability, or
readiness claim. A local hash chain cannot detect a coherent whole-database
rollback without an independent external anchor. `synchronous=FULL` depends on
the filesystem and device honoring flush/order guarantees and does not prove
power-loss durability. M3+ enforcement and evidence remain future work.
