# 18 — Implementation roadmap and assurance case

## 1. Результат и текущая нижняя граница

Этот roadmap dependency/gate-based. Исторические оценки «3–5 дней», «10 дней», numerical limits и benchmark/alert thresholds не имеют evidence basis и не являются обязательствами. Они могут стать profile values только после calibration and owner approval.

Current scoped status:

```text
specification = SPECIFIED
runtime = NOT_IMPLEMENTED
evidence = SPECIFICATION_MODEL_TESTED
runtime_attestation = NOT_ATTESTED
overall = NOT_READY
scope = FORMAL_SPECIFICATION_AND_PURE_REFERENCE_MODEL_ONLY
```

Canonical status marker: `Q94-STATUS-VECTOR: specification=SPECIFIED; runtime=NOT_IMPLEMENTED; evidence=SPECIFICATION_MODEL_TESTED; runtime_attestation=NOT_ATTESTED; overall=NOT_READY; scope=FORMAL_SPECIFICATION_AND_PURE_REFERENCE_MODEL_ONLY`.

Status одного artifact не повышает остальные controls. Specification-model evidence не повышает runtime implementation, runtime attestation или overall readiness.

The strengthened clauses in the specification are obligations only. Until authenticated capability/approval verification, durable scoped vectors/frontier/recovery, compiled pairwise-distinct isolation, same-object evidence, delegation escrow and end-to-end supply measurement exist and pass runtime conformance, their status remains `NOT_IMPLEMENTED` / `NOT_ATTESTED` and `overall=NOT_READY`.

## 2. Ponytail architecture: минимальная глубокая система

Не требуется сеть из 16–19 сервисов. Первый coherent implementation SHOULD иметь:

1. `harnessd`: один deep control module с pure normalize/classify/derive/decide/transition kernel, broker/PEP, capability+budget transaction coordinator, supervisor, canonical event outbox и approval renderer. Internal modules have explicit interfaces; they need not be network services.
2. Один serializable transactional store for pilot (например, SQLite in single-host profile after durability/failure qualification): contracts, material bindings, capabilities, reservations/spend, dispatch/outcome, monotonic lineage, fencing epochs and outbox in one durability domain. Local hash chain is only tamper-evident until an independent anchor exists.
3. One immutable signed/content-addressed registry snapshot bundled/pinned to exact broker/image digest. No dynamic discovery/update in pilot.
4. One disposable worker sandbox per iteration: network disconnected; no credentials; read-only typed inputs; independent writable output FS; no host checkout/`.git`; exact stageable workspace operations only.
5. A separate postcheck principal/process observing the sealed immutable snapshot, not the live writable workspace.
6. One content-addressed evidence/artifact store with access/retention policy.
7. `harnessctl` as a thin command surface of the same implementation for approve/run/reconcile/verify; not a duplicate policy engine.
8. Structured canonical JSON events and deterministic local detectors first. Prometheus/tracing exporters are later projections if operationally needed.
9. Offline benchmark reuses exact harness binary/profile in `bench` mode and has no production credentials/sinks.

Pilot profile explicitly denies external/non-stageable effects, raw secrets, delegation/fan-out, persistent reflection and break-glass. Model/provider communication, if needed, is a distinct broker-owned sink with explicit flow policy. This narrowing preserves safety controls rather than implementing speculative breadth.

“One deep module” is a code-packaging choice, not principal collapse: worker, broker, executor, gateway and observer entrypoints MUST run as pairwise-distinct attested OS/security principals whenever those roles are active.

## 3. Dependency graph

```text
M0 terms/claims/profile decision
 ├─> M1 schema + pure kernel + exhaustive abstract tests
 ├─> M2 durable ledger/capability/budget/outbox/fencing
 │    └─> M4 stage/seal/postcheck/commit/JOIN
 └─> M3 L0 sandbox/TCB/registry/placement attestation
      └─> M4
M4 ─> M5 authoritative events/detectors/IR
M1+M3+M4 ─> M6 approval service/SoD/revocation
M1..M6 ─> M7 conformance, attack, fault, game-day, benchmark assurance
M7 + human governance decisions ─> any activation decision
```

No phase may be “parallelized” across an unsatisfied trust-boundary dependency. Documentation, UI, monitoring or human approval cannot compensate for missing M2/M3/M4 enforcement.

## 4. Milestones and hard gates

### M0 — Scope, authority and governance baseline

Deliverables: authoritative or explicitly provisional project glossary; exact pilot threat/environment/profile; actual tool/skill/plugin/MCP inventory; principals/owners/data classes/purposes/retention; disabled effect list; approval/risk authority.

Gate: every normative claim has owner, enforcement point, failure, test and evidence type. Any `UNKNOWN` needed for an allowed action keeps STOP.

### M1 — Executable specification kernel

Deliverables: strict schemas/examples; single pure total decision/reducer; canonicalization; finite decision/LTS partitions; bounded explorer; traceability requirement→field→decision→test.

Gate: all expected-valid/invalid examples behave exactly; finite partitions exhaustively covered; property/mutation tests for envelope restriction, effect algebra, monotonicity, D2 and unknown fail-closed pass. This gate proves abstract artifacts only.

### M2 — Durable authority and state

Deliverables: serializable capability/budget/dispatch/outbox store; unique nonce; root lineage; epochs/fencing; revocation/freshness; crash recovery; protected backup/anchor decision; durable external full-field capability verifier at issue and dispatch; exact `(name,unit,scope_digest,lineage_root)` budget keys.

Gate: crash before/after every durability boundary and concurrent consume/reserve/revoke schedule produces no double dispatch, counter reset, reclaimed-live escrow, lost mandatory event or unsafe retry; stageable post-dispatch uncertainty remains quarantined with escrow absent independent no-effect proof. Actual fsync/durability assumptions documented and fault-tested.

### M3 — L0 runtime and supply boundary

Deliverables: exact worker/broker/gateway/observer profiles; namespace/mount/seccomp/LSM/cgroup/path/FD/network/credential controls; signed image/runtime/SBOM/registry; externally anchored exact-byte supply verification; descriptor/root/mount/epoch binding; placement and cleanup attestation; compiled worker-effect subset and distinct executor audience.

Gate: profile conformance and ATK-001–003/007/010–012/019–022/026/028/034 plus `T-Q39-SUPPLY-EXTERNAL-BUNDLE-SUBSTITUTION`, `T-Q43-DESCRIPTOR-ROOT-SUBSTITUTION`, `T-Q46-DIRECT-WORKER-MUTATE-DENY`, `T-Q47-MUTATION-SELF-AUDIENCE-DENY` and the positive `T-DECISION-ALLOW-EXACT` pass on the exact deployment kernel/runtime. Shared-kernel/covert residual claims scoped. `actual_skill_set_verified=true` must be backed by inventory evidence, not a flag.

### M4 — Stage, seal, postcheck and external branch

Deliverables: quiescence/freeze, immutable snapshot, independent externally verified observer, typed same-object evidence through stageable commit/JOIN; explicit connector precheck/outcome/reconcile and compensation transaction semantics (external branch may remain disabled); trusted active-contract lookup and complete D2 inventory.

Gate: all writer/seal/postcheck/crash races pass; no JOIN without full typed same-object evidence; the executed `T-Q40-*`, `T-Q44-*`, `T-Q45-*`, `T-Q48-*`, `T-Q49-*`, `T-Q50-*` assertions named in `17_ATTACK_TEST_AND_EVIDENCE_MATRIX.md` pass; unknown external outcome never auto-retries. If independent observer/receipt remains absent, production claim is blocked.

### M5 — Observability, detection and response

Deliverables: canonical source events/outbox/spool/storage/access/retention; externally verified emitter identity and canonical signed source chain; bounded projections; detector/runbook catalog; scoped containment/reconciliation/closure.

Gate: lifecycle completeness, spoof/tamper/gap/cardinality/privacy/pipeline fault tests and each detector positive+negative fixture pass, including `T-Q41-EVENT-EMITTER-ROLE-FORGE` and `T-Q42-EVENT-DIGEST-SUBSTITUTION`; game days generate complete closure bundles. Witness absence limits anti-rollback claim.

### M6 — Human/governance control (`L5-REQ-002`…`L5-REQ-011`)

Deliverables: canonical accessible UI, identity/role/SoD, service-signed exact receipt, comprehension obligation, revocation/material invalidation and disabled-or-enforced break-glass.

Gate: binding/replay/expiry/revocation/disagreement/SoD/confusable/batching/fatigue tests pass. Production break-glass requires dual-control game day and postmortem; otherwise it remains disabled.

### M7 — Integrated assurance and quality

Deliverables: total source→requirement→invariant→field→PEP→event→test→evidence trace; attack/fault/concurrency/mutation suite; exact-profile implementation attestation; calibrated paired benchmark; operational owner signoffs; independent review/closure evidence.

Gate: no open Critical/High; Medium fixed or has valid authorized risk-owner receipt; no unsupported claims; exact final artifact/profile digests frozen. Passing documentation review alone cannot activate runtime.

## 5. Profile progression

| Profile | Allowed scope | Required additional evidence |
|---|---|---|
| `SPEC_ONLY` | schema/reference pure tests only; no effect executor | package hashes and validation report |
| `DEV_STAGEABLE_LOCAL` | bounded local stageable workspace mutation, disconnected worker, synthetic data | M1–M4 tests on dev profile; one-human governance permitted only with machine SoD |
| `TEST_ADVERSARIAL` | disposable attack/fault tests; fake connectors; no production credentials | dedicated host/VM approval, blast/stop/recovery plan, full ATK evidence |
| `PROD_STAGEABLE` | only proven stageable operations and data classes | all M0–M7 gates, production SoD, monitoring, IR/game-day and risk decisions |
| `PROD_EXTERNAL` | named non-stageable connector operations only | connector idempotency/reconciliation/compensation evidence, privacy/legal approval, dual/high-risk governance |
| `MULTI_AGENT/REFLECTION` | named graph/flow/control-plane operations | tree model/conservation/taint/material-change conformance; new material profile approval |

No profile inherits a broader lower-assurance profile automatically. Effective authority always intersects all active ceilings.

## 6. Status transition criteria

### `DECLARED → IMPLEMENTED`

Requires actual code/config/deployment for every claimed enforcement point, exact environment/profile and owner, deployed durable state, L0 attestation, registry/tool inventory, observer/seal path, event pipeline and approval/revocation where claimed. Boolean configuration is not evidence.

### `IMPLEMENTED → ENFORCED`

Requires demonstrated non-bypassability in scope: negative tests from untrusted worker, downstream fencing, connector boundaries, crash/concurrency/fault evidence, no ambient alternative path, and deployment admission that refuses missing/mismatched attestation.

### Evidence maturity

- `UNTESTED`: prose/schema only.
- `TESTED`: reproducible artifact or implementation tests with exact digests/environment.
- `ATTESTED`: trusted TCB reports actual configuration/state and verifier checks it.
- `MONITORED`: authoritative continuous telemetry plus tested response.
- `VERIFIED`: named machine-checked property **and** implementation conformance in exact scope; it does not cover LLM semantics/human comprehension/covert channels unless explicitly proven.

## 7. Assurance cases by level

| Claim | Argument | Required evidence | Current maturity/residual |
|---|---|---|---|
| `C-L0`: worker actual effects cannot exceed exact physical profile | Separate principals, kernel/runtime controls and mediated exact executor deny alternative paths | signed image/runtime/placement/isolation/secret/cleanup receipts + ATK L0 negatives | `UNTESTED`; no deployed profile; shared-kernel/covert risk |
| `C-L1`: known request receives conservative compound effect upper bound | Operational ontology + fixed-point closure; unknown dynamic behavior maps TOP/deny | classifier fixtures/properties/mutations bound to exact operations | reference artifacts may be `TESTED`; arbitrary semantics undecidable |
| `C-L2`: manifest is an exact implementation-bound static upper bound | signed digest/provenance + transitive closure + canonical argument narrowing + registry atomicity | schema validation, registry resolution/conformance/substitution evidence | canonical schema/examples `TESTED`; actual signatures/registry/tool inventory absent |
| `C-L3`: only an authorized/budgeted single-use call dispatches and failures do not amplify | pure meet/decision plus serializable reserve/consume/dispatch/counters, LTS and fencing | crash/concurrency/explorer + durable store/executor receipts | pure model chain and negative mutations `TESTED`; runtime/durability/fencing absent |
| `C-L4`: risky call has complete authoritative causal evidence and bounded response | per-transition emitters/outbox/spool/reconciliation and tested detectors/runbooks | completeness/tamper/privacy/cardinality/game-day/closure evidence | `UNTESTED`; witness/backend/owners open |
| `C-L5`: human decision is exact, bounded, revocable and cannot expand L0 | `L5-REQ-002`…`L5-REQ-011`: canonical presentation, SoD/quorum, trusted receipt, freshness and hard-ceiling meet | UX/identity/signature/replay/race/accessibility/break-glass evidence | `UNTESTED`; human fallibility remains |

## 8. Assurance cases for global invariants

The canonical invariant text is in `04_FORMAL_CORE_AND_INVARIANTS.md`. This table preserves one assurance row per shared ID; if review renumbers an invariant, total mapping MUST be updated rather than silently dropped.

| Invariant | Claim/argument | Required evidence | Current status |
|---|---|---|---|
| `INV-001` | STOPPED/default unknown is fail-closed through total decision table | exhaustive decision partitions and deny reason events | canonical negative model checks pass; runtime absent |
| `INV-002` | agent has no ambient external authority; broker/executor envelopes are separate | credential/FD/network/identity attestation + confused-deputy negatives | untested runtime |
| `INV-003` | every side effect is mediated non-bypassably | L0 route inventory, syscall/path/network/tool negative tests | untested runtime |
| `INV-004` | capability exact-bound, short-lived, nontransferable and single-use | semantic binding/replay/time/race tests + durable consume ledger | schema-valid issuance/consume/replay model passes; durable runtime absent |
| `INV-005` | committed ⊆ authorized ⊆ manifested∩physical; attempts outside are blocked | reducer properties + TCB/actual-effect reconciliation | semantic receipt/event/JOIN mutations pass; TCB runtime absent |
| `INV-006` | delegation cannot amplify authority or quantitative resources | bounded graph/property/concurrency/crash tests + escrow ledger | specified; delegation disabled |
| `INV-007` | cumulative counters monotonic across restart/retry/nesting/branch | durable fault/concurrency tests and lineage state | abstract explorer only |
| `INV-008` | provisional D2 has at most one controller-visible next frontier | bounded explorer + persistent-state inspection per JOIN | all declared frontier flags/artifact classes negative-tested; definition/runtime remain provisional/absent |
| `INV-009` | material config change invalidates future bindings | dependency impact and race tests + revoke/activation receipts | specified; runtime absent |
| `INV-010` | only declared scoped taint-tracked state/flow crosses iteration/principal | context/provenance/flow laundering tests | specified; runtime absent |
| `INV-011` | observability/evidence creates no authority; missing risky evidence fails | spoof/missing-edge tests + PEP state proof | specified; runtime absent |
| `INV-012` | seal is immutable with no writer until JOIN | writer fencing/quiescence/snapshot/postcheck crash races | untested runtime |
| `INV-013` | information labels include C/I/provenance/purpose/retention and propagate; declass ≠ endorse | data/control-flow properties and exact-capability tests | specified; runtime absent |
| `INV-014` | recovery/rollback/compensation are fresh governed effects | unknown/retry/compensation fault traces and receipts | abstract unknown escrow/fresh-compensation/revocation traces pass; runtime absent |
| `INV-015` | unknown/unclassified/unbounded/missing/stale/mismatched never implicitly allows | exhaustive enum/partition/mutation tests | abstract material negative mutations pass; runtime absent |

## 9. Traceability and evidence bundle gate

Each normative row MUST resolve bidirectionally:

```text
source claim/gap ↔ REQ-ID ↔ INV-ID ↔ schema/policy field
↔ enforcement point ↔ event/alert ↔ TEST-ID ↔ EV-ID ↔ status/profile
```

Deployment evidence bundle includes exact source/spec/schema/code/image/kernel/runtime/model/prompt/context/tool/registry/policy/contract/profile digests; validation/explorer/test commands and results; attestation/signature/key status; residual risks/owner; review/approval/risk receipts; and retention/access metadata. Re-running against any changed material digest creates a new bundle; old evidence remains historical, not silently reused.

### 9.1. Required root-side traceability validator and mutation checks

The existing `tests/run_checks.py` remains backwards-compatible; the root-side validator must additionally: (a) assert `attack_registry.entries` has unique `catalog_id`, unique matrix-row ownership across `matrix_ids`, complete `ATK-001..035` coverage, IDs that resolve to the declared catalog/matrix rows, non-empty owner, and no namespace collision; numeric equality is never used as a semantic mapping; (b) assert every node in every legacy registry has a reverse edge and every reverse edge points back to a forward invariant edge; (c) resolve every test/evidence ID and require each evidence record's command, preimage-backed `environment_digest`, preimage-backed `input_digest`, result and specification-only status; and (d) reject runtime/attested status while runtime is absent. Mutation tests must duplicate or swap catalog/matrix IDs, remove an attack entry, create an ambiguous two-target mapping, remove each reverse edge, add an unknown test/evidence ID, delete each evidence field, alter either digest preimage, and set status to `RUNTIME_VERIFIED`; each mutation must fail deterministically.

## 10. Rollout, rollback and incident readiness

Rollout proceeds deny-by-default in synthetic/dev, then adversarial test, canary and only named production operations. Each step has explicit enable flag in signed profile, exact capability ceiling and rollback/disable path. Rollback of control plane revokes future materials and deploys a separately attested prior version; it never erases already committed effects/evidence. In-flight unknown effect is quarantined/reconciled.

Before production: named on-call/incident/governance/privacy/resource owners, detection/runbooks, evidence preservation, revocation/kill/freeze, backup/restore, RTO/RPO, retention/legal hold and game day MUST exist. No arbitrary numeric SLA is supplied by this corpus.

## 11. Exact current blockers / next actions

1. Obtain authoritative project-term definitions or approve the explicitly provisional local ones.
2. Select and attest exact Linux/runtime/isolation/host threat profile.
3. Inventory exact tools/skills/plugins/MCP adapters/models and freeze implementation/registry digests.
4. Implement and fault-test serializable capability/budget/dispatch/outbox/fencing state.
5. Implement quiescence/seal/independent postcheck/cleanup and prove race behavior.
6. Deploy authoritative event sources/storage/detectors/runbooks/privacy-retention controls; decide witness/anchor.
7. Implement identity/SoD/approval/revocation UI/service; keep break-glass disabled until tested.
8. Run all ATK, crash, concurrency, mutation and implementation-conformance suites in authorized disposable environments.
9. Calibrate profile limits, alert SLO and quality benchmark with data and named owners.
10. Complete independent review closure; obtain human receipts for any remaining Medium proposal. Critical/High cannot be risk-accepted here.

Until then `overall=NOT_READY`, regardless of specification quality.

## 12. Unsupported claims and sources

The assurance case does not assert full isolation, exhaustive effect classification, zero covert channel, detection of all anomalies, guaranteed human comprehension, anti-rollback without witness, or production readiness. Primary general references (RFC 8174, JSON Schema 2020-12, Linux Landlock/cgroup v2, OCI Linux runtime config and OpenTelemetry semantics) inform terminology only; they are not evidence that this harness implements those controls.

## 13. Closure prerequisites

No runtime status changes follow from these specifications. Before any activation, the implementation must demonstrate the `04` content/identity/stage/escrow/chain bindings, the `10` OS-subject/path controls, the `14` authenticated host/event records, and the `15` full-receipt approval/quorum verifier in one exact deployment profile. The separate schema and semantic oracle matrix in `17` must pass for the same frozen artifacts. Until then: `NOT_IMPLEMENTED`, `NOT_ATTESTED`, `NOT_READY`.
