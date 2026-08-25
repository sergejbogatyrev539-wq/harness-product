# 02 — Матрица «существует / отсутствует»

## Как читать матрицу

`Existing` означает только наличие идеи или декларации в frozen corpus. `Added` — нормативная формализация в этом пакете. `Missing runtime` — фактический enforcement/evidence, которого пакет документов сам создать не может. Любая строка без owner, failure semantics, test и evidence остаётся неполной; здесь эти элементы заданы как требования, а не как утверждение о внедрении.

| ID | Plane/level | Existing in corpus | Added normative requirement | Enforcement owner/point | Failure semantics | Test → expected evidence | Current status |
|---|---|---|---|---|---|---|---|
| MAP-001 | Core | CB5/JOIN/D2/law-of-cut names and formulas | Explicit provisional glossary; replacement is material change | Project authority + policy kernel | Unknown term → STOP | `T-LTS-D2-*` → explorer trace | `SPECIFIED_PROVISIONAL`; runtime missing |
| MAP-002 | Core | Intersections of allowed effects | Dependent typed envelope, deny-overrides, `UNKNOWN/TOP` | Pure decision kernel/PEP | Non-comparable/unknown → DENY | `T-POL-MEET-*` → decision vectors | Spec tested only |
| MAP-003 | Core | Sequential loop sketch | Common admission + stageable/external/compensation LTS | Broker + durable ledger + executor | Illegal/crash/unknown transition → STOP or quarantine | `T-LTS-*` → exhaustive transition report | Runtime missing |
| MAP-004 | Core | Capability UUID/TTL concepts | Exact-bound, single-use, durable consumption atomic with dispatch intent | Capability store/transaction coordinator | Replay/mismatch/stale → DENY; post-dispatch unknown → quarantine | `T-POL-CAP-*`, crash matrix → ledger receipts | Runtime missing |
| MAP-005 | Core | Qualitative budgets | Typed vector, atomic reservation, monotonic lineage counters, linear child escrow | Budget ledger/PEP | Exhaustion/divergence → STOP/freeze | `T-POL-BUD-*`, race tests → before/reserve/spend/after receipt | Runtime missing |
| MAP-006 | L0 | Container/chroot/network/resource proposals | Risk-based profiles and claim boundaries; separate agent/broker/gateway/observer envelopes | Platform TCB/runtime supervisor | Attestation missing/mismatch → no dispatch | `T-ATTACK-L0-*` → signed placement/isolation/cleanup receipts | `DECLARED`; not attested |
| MAP-007 | L0 | Workspace-only/read-only ideas | Descriptor-based paths, no host checkout/`.git`, symlink/hardlink/magic-link/race handling | Executor VFS boundary | Escape attempt blocked/logged; uncertainty kills worker | Path adversarial suite → TCB block events/snapshot | Runtime missing |
| MAP-008 | L0 | CPU/memory/PID limits examples | cgroups v2 + FS/inode/FD/IO/GPU and broker budget split; profile-calibrated values | Runtime supervisor + broker ledger | Limit hit → kill/STOP; cleanup verified | Exhaustion/fork-bomb suite → cgroup/ledger/cleanup evidence | Runtime missing |
| MAP-009 | L0 | `network_egress=false` | Worker disconnected across IPv4/IPv6/DNS/UNIX/loopback/metadata; broker gateway explicit | Network namespace/LSM/broker | Any undeclared flow blocked; inherited channel → no dispatch | Egress matrix → TCB deny receipts | Runtime missing |
| MAP-010 | L0 | Some image/version fields | Signed/pinned image/runtime/SBOM/registry snapshot and actual placement attestation | Supply-chain verifier + runtime | Digest/provenance mismatch → STOP | Substitution/downgrade tests → verification receipts | Runtime missing |
| MAP-011 | L1 | Three allowed effects and informal taxonomy | Six compound effects with operational boundaries; orthogonal externality/persistence/sensitivity/uncertainty | Classifier + PEP | Ambiguous/dynamic closure → `UNKNOWN/TOP` → DENY | Boundary/property fixtures → classification report | Spec tested only |
| MAP-012 | L1 | Evidence transfer allowed | Information-flow composition and control-dependency taint; model provider explicit sink | Context assembler/flow PEP | Missing label/provenance/purpose → DENY | Laundering tests → flow decision/evidence manifest | Runtime missing |
| MAP-013 | L2 | Tool profiles/manifests in prose | Signed content-addressed per-operation upper bound bound to exact implementation and transitive closure | Immutable registry resolver + PEP | Missing/revoked/mismatched/dynamic unknown → DENY | Schema examples/substitution tests → resolver receipt | Schemas tested; registry absent |
| MAP-014 | L2 | Partial fields | Strict Draft 2020-12 schemas for ontology, manifest, isolation, policy, decision, contract, capability, events, receipts/evidence/approval | Schema validator + semantic validator | Invalid/unknown field/version → reject before admission | `tests/run_checks.py` → validation report | Spec artifact tested |
| MAP-015 | L2 | Runtime args notion | Canonical args bind scope; args may narrow but never widen manifest; shell conservative | Trusted binder/classifier | Noncanonical/overbroad/unbounded → DENY | Valid/invalid operation examples → expected pass/fail | Spec artifact tested |
| MAP-016 | L3 | Policy hierarchy and booleans | Physical→platform→project→contract→session→call intersection; explicit deny reasons | Pure policy kernel/PEP | Any conflict chooses narrower/deny | Exhaustive partitions → decision report | Spec tested only |
| MAP-017 | L3 | JSONL journal/single writer claims | Serializable durable state transition, epochs/fencing and outbox; protected witness needed for rollback claim | Ledger owner + executor fence | CAS/fence/fsync failure → STOP/quarantine | Crash/concurrency tests → transaction/fencing receipts | Runtime missing |
| MAP-018 | L3 | Retry/rollback mentions | Per-state retry eligibility; compensation as new authorized effect; unknown external outcome no auto-retry | Broker/reconciler | Unknown → quarantine/reconcile | Fault matrix → reconciliation/compensation receipts | Runtime missing |
| MAP-019 | L3 | Prompt/tool pinning concepts | Exact material bindings for model/prompt/context/memory/tool/registry/policy; stale receipts revoked | Control plane/PEP | Drift/revocation/feed failure → STOP | Material-change races → revocation/invalidation events | Runtime missing |
| MAP-020 | L3 | Sequential D2 formula | No controller-visible N+2 frontier before JOIN(N+1); unique lineage/sequence; attempts separate | Controller/ledger | Second frontier/counter reset → STOP | Bounded explorer → D2 counterexample absence | Spec tested only |
| MAP-021 | L4 | One iteration event, a few metrics/alerts | Authoritative per-transition unsampled safety event stream with causal links/outbox | PEP, ledger, executor, observer; collector is not authority | Missing/corrupt mandatory receipt → risky action STOP | Lifecycle completeness/crash tests → signed event chain | Runtime missing |
| MAP-022 | L4 | Prometheus/Jaeger sketches | Bounded label allowlist; restricted exact IDs/digests; privacy classification/access/retention | Telemetry governance + SRE | Cardinality/privacy violation → quarantine export/incident | Fuzz/canary tests → series/privacy reports | Runtime missing/profile open |
| MAP-023 | L4 | Loop/token/postcheck alerts | Detection→response catalog for all mandated surfaces, deterministic vs statistical split | SRE/security/connector/service owners | Deterministic invariant violation auto-contained; statistical signal never grants authority | Detector/runbook tests → incident closure bundle | Runtime missing |
| MAP-024 | L4 | Hash-chained ledger | Local tamper evidence plus sequence/gap/signature/reconciliation; no anti-rollback claim without anchor | Evidence store + independent witness if selected | Gap/fork/anchor loss → freeze/quarantine | Tamper/fork/truncation tests → anchor/reconciliation evidence | Witness open |
| MAP-025 | L5 | Aggregate approval and signature alternatives | Trusted canonical presentation; service-signed exact-bound receipt; separate auth/comprehension evidence | Approval service + PEP | Reject/modify/timeout/cancel/revoke/stale → no capability | Binding/replay/UX fixtures → presentation/receipt/decision chain | Runtime missing |
| MAP-026 | L5 | Dev/prod owner counts | SoD among requester/approver/issuer/executor/observer/risk owner; quorum by distinct principals | Identity/policy service | Role collision/disagreement/timeout → STOP | SoD/disagreement tests → identity/quorum evidence | Profile identities open |
| MAP-027 | L5 | Break-glass deferred/off | Predeclared emergency profile within L0 ceiling, dual control, TTL, alarm, immutable audit, recovery/postmortem | Incident commander + two authorizers + PEP | Protocol incomplete/outside ceiling → STOP | Break-glass matrix/game day → activation/revoke/postmortem receipts | Disabled; runtime missing |
| MAP-028 | Context | Sliding window/summary/hash notions | Ordered exact context bundle, segment provenance/labels, summary derivation, memory snapshot and retention | Trusted context assembler | Missing/stale/tainted unauthorized segment → reject | Injection/order/summary tests → assembly manifest | Runtime missing |
| MAP-029 | Delegation | Attenuation statement | Acyclic task-instance graph; fan-out/depth/nodes/concurrency bounds; linear lineage escrow; no ambient child defaults | Delegation broker/ledger | Amplification/cycle/orphan/unknown child → deny/freeze/quarantine | Tree property/crash tests → delegation/budget receipts | Disabled in pilot |
| MAP-030 | Reflection | Material-change invalidation prose | `MUTATE+REFLECT`, impact closure, atomic activation and future-facing receipt/capability revocation | Control plane/governance | Unknown materiality/drift → STOP | Prompt/model/tool/config mutation tests → change/invalidation receipts | Disabled in pilot |
| MAP-031 | Verification | Golden benchmark idea | Deterministic invariant tests separated from calibrated semantic quality and live telemetry | Assurance/quality owner | Missing exact bindings/calibration → inconclusive/no deploy | Paired holdout runs → signed benchmark report | Benchmark data/profile absent |
| MAP-032 | Recovery | Retry/rollback fragments | Detect→contain→preserve→reconcile→recover/compensate→close→postmortem→regression | Incident/recovery owner | Unknown effect never silently retried; closure requires bundle | Game days → closure and new regression IDs | Runtime missing |
| MAP-033 | Supply chain | Registry/adapters/signatures fragments | Immutable V0 registry snapshot, exact digests/SBOM, signed updates/revocation/rollback prevention | Registry/supply-chain owner | Mismatch/downgrade/stale key → STOP | Poison/substitution tests → resolution/provenance receipt | Runtime missing |
| MAP-034 | Human risk | Historical residual-risk language | Separate risk-acceptance receipt; only authorized human may accept Medium with expiry/review | Named risk owner | No valid receipt → issue remains OPEN | Receipt schema/semantic checks → signed risk record | No receipts in package |
| MAP-035 | Assurance | Prose “formal/pass/ready” claims | Per-claim `Claim→Argument→Evidence→Profile→Maturity→Residual risk` and status vector | Assurance owner + independent reviewers | Evidence missing → maturity cannot advance | Traceability audit → coverage report | Specification review in progress |

## Пять различий, которые сохраняются во всех уровнях

1. Live observability **не равно** offline quality benchmark.
2. Static manifest **не равно** actual-effect receipt.
3. Human approval **не равно** formal verification или controller JOIN.
4. Content hash/signature **не равно** semantic safety.
5. Fresh container **не равно** отсутствию объявленного cross-iteration information flow.

## Текущая нижняя граница

- Корпус: полностью прочитан и хеширован.
- Новая спецификация: Draft V0 в сборке и далее проходит независимые review rounds.
- JSON Schema/reference policy: проверяют форму и абстрактную semantics, но не runtime.
- Harness runtime: отсутствует.
- Runtime evidence/monitoring/attestation: отсутствуют.
- Поэтому никакая строка этой матрицы не повышает общий runtime status выше `NOT_IMPLEMENTED`.
