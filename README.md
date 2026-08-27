# Harness product

Universal, policy-enforced mediation for agent-initiated work. The product is to
turn the normative Harness specification into a runtime in which untrusted
workers can propose bounded work but cannot bypass the control path.

## Current status

`specification=SPECIFIED; implementation=NOT_IMPLEMENTED; runtime_attestation=NOT_ATTESTED; overall=NOT_READY`.
The copied `spec/` corpus is normative; it is not a runnable security product.
Here `NOT_IMPLEMENTED` means that no complete current non-bypassable deployment
implements the full specification; it does not mean that M1-M4 source modules
are absent.

## Start here

Agents must first read all of [AGENTS.md](AGENTS.md) and the ignored live record
`.agent/WORKING_CONTEXT.json`, initialized from the closed
[working-context template](WORKING_CONTEXT.template.json). The record preserves
the current invariant, exact oracle, and progress across compaction or handoff,
but is non-authorizing and cannot start work.

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
store. Its format version remains 1 and its M4-extended schema is v5. Exact v1
through v3 stores migrate atomically; exact v4 stores migrate only while their
M4 surface is empty, and otherwise remain unchanged and fail closed. It uses
`STRICT` tables, foreign keys, `BEGIN IMMEDIATE`,
rollback-journal (`DELETE`) mode, and `synchronous=FULL`. Issue reruns the exact
M1 decision and stores the complete canonical M1 inputs/bindings and complete
verifier record; consume checks them again. A single commit consumes the
capability, reserves every budget component, records the exact durable dispatch
intent, counters/journal, and a mandatory local outbox event. Reservations end
exactly once as `SPENT`, `RELEASED`, or `QUARANTINED_ESCROW`; release requires an
independently verified no-effect record. Recovery never dispatches or retries.
The M3 extension can atomically claim one already committed intent after
rechecking its complete stored capability/verifier bindings, expiry, revocation
epoch, and fence through a second external-verifier boundary. The claim and its
mandatory event/outbox record persist before an executor can receive an
envelope; reopen exposes only `ATTEMPT_CLAIMED`, never an automatic retry. An M3
transition can then durably record the exact prospective runtime object
inventory as `PREPARED` before untrusted exec and terminally record `STOPPED`,
`TIMED_OUT`, or `QUARANTINED`. Only independently verified no-effect cleanup can
release the reservation; every uncertain terminal result remains quarantined.

`DELETE` is intentional for this single-writer profile: `BEGIN IMMEDIATE`
serializes mutations, while rollback journaling avoids a separate WAL checkpoint
lifecycle. It still uses a transient rollback-journal file during a transaction.

The durable module still has no executor, connector, or effect adapter,
external crypto/trust root/attestation, OS enforcement, non-bypassability, or
readiness claim. A local hash chain cannot detect a coherent whole-database
rollback without an independent external anchor. `synchronous=FULL` depends on
the filesystem and device honoring flush/order guarantees and does not prove
power-loss durability.

M3 adds the direct, non-root-exported `harness_product.l0` module: a closed
compiler, read-only host preflight, external supply/placement-verifier boundary,
exact session planner and supervisor, descriptor/IPC boundaries, and one
minimal local staging operation for the one
profile `L0-LX-A / DISCONNECTED_STAGEABLE_WORKER`. It pins the single backend
to root-owned `/usr/bin/bwrap`, `bubblewrap 0.9.0`, SHA-256
`52231e1caf55bcbc667b269f49c63599a6f7db4767ae6a039580d0ff853db712`.
Compilation closes and canonicalizes five role plans, the exact fourteen-row
Q-56 resource vector, disconnected worker controls, exact `UNIX_SEQPACKET`
broker IPC, and measurement requirements. It emits a draft measurement plan,
not activation or attestation. Preflight only reads host controls and invokes
`bwrap --version/--help` with absolute typed argv, `shell=False`; it never
creates a worker, namespace, cgroup, socket, or staging effect.

Supply admission hashes actual bytes from pre-opened, immutable descriptors and
binds the rootfs manifest, loader, dependency closure, tool, SBOM, registry
snapshot, seccomp and LSM policy to exact runtime, signer lifecycle, profile,
placement, session, fence, and rollback fields. It requires an explicit external
verifier over the complete canonical payload and record. No default verifier,
caller hash, `verified=true`, tag, or self-signed fixture is trusted.

The session planner remeasures all descriptors and binds namespace, cgroup,
mount, IPC, FD, process-tree, quota and cleanup inventories. The supervisor path
has no fallback or retry: it repeats host measurement, durably commits
`PREPARED`, creates and verifies one cgroup, launches only typed bwrap argv with
`shell=False`, releases an early start gate, applies external wall/CPU limits,
kills the cgroup process tree on failure, and terminally releases or quarantines
the durable reservation. These properties were qualified for the exact
disposable test-VM candidate at product commit
`437ee01ca331cd7e4632fb8ad55eaa894254daa9`. That retained bundle is historical,
test-profile evidence: it is not production attestation and cannot attest any
later commit. Separately,
`resolve_target` uses Linux `openat2` with `BENEATH`, `NO_MAGICLINKS`,
`NO_SYMLINKS`, and `NO_XDEV`; broker ingress accepts only bounded
`UNIX_SEQPACKET` messages with exact `SO_PEERCRED` and binding checks. The sole
effect API can replace one already-existing file beneath a pre-opened 0700
disposable staging root only after an exact M2 claim, external claim-verifier
recheck, M1 selector/material match, immutable descriptor/root/mount/epoch/
object match, and atomic consumption of the current one-use M4 stage
authorization from `DurableStore`. A claim or caller binding alone is
powerless. Unknown post-write outcome is quarantined and never retried.

M4 adds one direct, non-root-exported `harness_product.m4` coordinator and one
non-root-exported `harness_product.publisher` boundary for that same local
stageable-file profile. M1 admission, the M2 claim/frontier and the exact
publication topology bind both the disposable staging inode and the separately
configured publication target; caller input supplies neither root descriptor.
External and non-stageable requests are deny-only. The v5 durable schema stores
the active contract, complete D2 frontier, target-authority digest, and fenced
canonical records for `STAGED → QUIESCED → SEALED → POSTCHECKED → publication
authorization/receipt → COMMITTED → JOINED`, plus discard, quarantine and
reconciliation. Budget escrow becomes `SPENT` only after a verified publication
receipt, and recovery never resumes or retries an incomplete M4 transaction.
Each committed D2 frontier is also one irreversible attempt slot; its append-only
iteration sequence survives discard and reopen, while `joined_iteration`
continues to mean only the last successful JOIN. The hard `max_iterations`
ceiling is checked before another capability is issued.

Before sealing, the coordinator re-resolves the canonical path through its
trusted root and acquires a Linux `F_RDLCK` lease on the exact read-only staged
inode. It retains that resolver capability and rechecks both the lease and the
canonical binding through JOIN. There is no weaker fallback: existing writers,
a break request, lease loss, unsupported filesystems, rename/substitution, or
identity mismatch quarantine the transaction. The immutable snapshot is a real
sealed memfd with `F_SEAL_GROW|F_SEAL_SEAL|F_SEAL_SHRINK|F_SEAL_WRITE`.

A separate observer child first closes the complete Linux descriptor range with
`close_range`, preserving only its exact allowlist; inability to prove closure
stops the boundary. It then produces a powerless proposal from a read-only
snapshot; a full externally verified observer receipt is mandatory before a
separately verified publication authorization can reach the trusted publisher.
The publisher accepts only that authorization and the sealed descriptor, uses
its configured descriptor-rooted target, performs one atomic replace plus
fsync, and returns a mandatory verified publication receipt. Unknown outcome is
quarantined without retry. The closed topology also requires pairwise-distinct
worker/controller/executor/observer/publisher subjects, a sole publisher writer,
and no `.git` authority. The publication root is additionally bound to its
physical mount namespace, mountpoint, absolute root path, basename and complete
parent ancestry, with continuity checks around atomic replacement and before
COMMIT/JOIN. Relocation or ancestry drift, including movement under `.git`,
quarantines rather than publishes. These are code-model and local regression
properties.
`DEPLOYMENT_ATTESTED` preflight remains `ABSENT` on a shared developer host; no
new physical-runtime qualification or production attestation is claimed. The
actual checkout and `.git` retain their existing host permissions and are not
protected by this disposable code-model boundary.

Run the non-skipping exact-profile availability gate separately:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src .venv/bin/python scripts/check_m3_l0.py
```

With no argument this is a read-only developer-host preflight. The following
mode verifies only a same-candidate bundle while its exact live lab, checkout,
and freshness window are still available; it is not an offline verifier for a
historical retained bundle and never launches a VM:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src .venv/bin/python scripts/check_m3_l0.py --evidence <bundle-directory>
```

Each mode exits nonzero unless its exact requirement is satisfied.
On a host without the exact dedicated cgroup-v2 CPU/IO delegation it reports
`ABSENT/CGROUP_DELEGATION_ABSENT`; no weaker fallback is selected. The
historical disposable-VM qualification does not provide a production trust
root, production privileged attestor, or production deployment evidence.
Status therefore stays
`NOT_IMPLEMENTED`, `NOT_ATTESTED`, and `NOT_READY`.
