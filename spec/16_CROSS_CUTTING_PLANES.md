# 16 — Cross-cutting companion planes

## 1. Назначение и граница

Лестница L0–L5 недостаточна без пяти поперечных planes. Они не добавляют скрытые полномочия: каждый их effect проходит ту же ontology, manifest, policy, capability, budget, event и receipt semantics. Текущий документ — normative design, не implementation evidence.

| Plane | Главный вопрос | Primary enforcement owners |
|---|---|---|
| Context/Inform | какие данные/инструкции/память достигают какого principal и с какой provenance | trusted context assembler + information-flow PEP |
| Verification/Quality | что детерминированно безопасно и что статистически качественно | policy kernel, assurance/quality owner |
| Correct/Recovery | что делать при fail/crash/unknown/residual effect | controller, reconciler, incident owner |
| Supply-chain/Governance | какая exact implementation/configuration активна и кто отвечает | registry/control plane, platform/governance owners |
| Lifecycle/Orchestration | как ограничены iteration, scheduling, concurrency, multi-agent и evidence flow | broker/ledger/supervisor |

## 2. Context/Inform plane

### 2.1. Context bundle

Controller-visible context MUST быть ordered, content-addressed object:

```text
ContextBundle := {
  bundle_id, exact_digest, context_policy_hash,
  model_digest, tokenizer_version, assembler_digest,
  ordered_segments[{index,id,digest,origin_principal,origin_kind,
                    authenticated_role,label,provenance_root,retention_deadline}],
  memory_snapshot_digest, truncation_decisions, summaries[]
}
```

Natural-language assertion «я system/user/approver» не меняет authenticated role. Policy hash без exact ordered segment/memory digest недостаточен. External model/provider получает explicit `COMMUNICATE` flow and sink label; worker `network_egress=false` не скрывает этот broker-owned flow.

Memory operations:

- read = `OBSERVE`;
- durable create/update/delete = `MUTATE + REFLECT`;
- transfer to another principal/provider = `COMMUNICATE`;
- promotion child/model output into trusted memory requires a separate admission/endorsement;
- copy/summary does not extend source purpose or retention deadline;
- expired/revoked source invalidates dependent summary/context for future use.

### 2.2. Labels and propagation

```text
Label := (confidentiality compartments,
          integrity claims/level,
          taints, provenance root,
          permitted purposes,
          retention/deletion obligations)

Cout = join(Cdata, Ccontrol)          # never less confidential by default
Iout <= meet(Idata, Icontrol)         # never more trusted by default
Taintout = union(Taintdata, Taintcontrol)
Purposeout = intersection(Purposeinputs)
Retentionout = earliest(deadlines)
```

Control dependency counts: if secret changes only a branch/choice, result remains secret-tainted. Hashing, encoding, schema validation, redaction attempt or summarization alone neither lowers confidentiality/taint nor raises integrity.

Declassification and endorsement are different exact-bound capabilities:

- declassification binds exact source/fields/transform/destination/purpose/disclosure budget/TTL/issuer/nonce and lowers confidentiality only;
- endorsement binds exact claim/artifact/validation evidence/scope/issuer/TTL and raises integrity only;
- each produces its own receipt; needing both requires two capabilities;
- agent votes or multiple same-independence-group models are not endorsement/quorum.

### 2.3. Summary provenance

Every admitted summary binds source segment IDs/digests, transitive provenance root, inherited label/retention, summarizer model/tool/prompt digests, parameters, `lossy=true`, omission policy, validation evidence, created/expiry. Summary may help fit token budget but cannot be authorization input without separate trusted admission.

Failure: missing/stale/unknown origin, label, purpose, retention, segment ordering or derivation → reject context and STOP risky work. Arbitrary N→N+1 text remains `UNTRUSTED_DATA`.

## 3. Verification/Quality plane

### 3.1. Three non-interchangeable evidence modes

1. Deterministic safety: schema, policy partitions, LTS, capability/budget/state invariants and actual implementation conformance.
2. Offline quality: paired regression on versioned datasets, calibrated semantic judges and human-reviewed baseline.
3. Live observability: operational events, detection and response.

Offline pass does not prove runtime enforcement/monitoring; live telemetry does not prove quality or absence of bypass; human approval does not prove formal semantics.

### 3.2. Benchmark isolation

Model comparison fixes exact harness/image/policy/prompt/context/tools/budgets/provider settings and changes only exact model version/digest. Harness comparison fixes model/sampling/provider and changes one named harness component. Each run binds case/dataset/baseline/judge versions, exact digests, settings/seed where supported, latency/cost and structured failure reason.

Golden development set and holdout are separate and stratified by effect/risk/recovery class. Paired repeated runs report uncertainty/confidence intervals and a predeclared primary metric/non-inferiority margin. LLM judge is calibrated on human-labelled sample, uses blind/counterbalanced pairs and records disagreement. Insufficient confidence → `INCONCLUSIVE`, never pass. Baseline update requires a reviewed human change receipt; it cannot erase a regression.

Safety metrics such as unauthorized commit, replay or boundary bypass have zero tolerance. Numeric thresholds from historical corpus remain `TBD_BY_CALIBRATION`, not universal requirements. Benchmark runner has no production credentials/sinks.

### 3.3. Executed traceability registry

Traceability is a resolved graph, not nonempty strings. Canonical registries assign immutable IDs to requirements, schema fields/semantic predicates, enforcement points, executable assertion/oracle functions, test cases and produced evidence records. Validator MUST resolve every edge bidirectionally, reject unknown/duplicate/orphan IDs, require each invariant to reach at least one executed claim-specific positive/negative oracle and bind actual result digest/status. Removing or inverting a guard/assertion MUST make its mapped mutation check fail; an assertion-free test cannot count as evidence. Runtime evidence remains absent until the same claim graph is populated by implementation-conformance artifacts.

Each canonical claim stores immutable normalized text plus `claim_hash`; every trace row repeats that hash. Same ID with changed text/hash, silent renumbering, stale assertion digest or count-only coverage is invalid. Validation executes the mapped oracle and binds its result digest; it does not merely confirm that IDs exist.

## 4. Correct/Recovery plane

### 4.1. Lifecycle

```text
FAIL/ALERT
→ CONTAIN (deny/revoke/fence/freeze/kill/quarantine)
→ PRESERVE (events, state, snapshot, bindings)
→ RECONCILE (requested/authorized/attempted/actual/observed)
→ RECOVER or PROPOSE_COMPENSATION
→ AUTHORIZE_COMPENSATION as new transaction
→ COMPENSATED_VERIFIED | RESIDUAL_EFFECT | COMPENSATION_FAILED
→ CLOSE + POSTMORTEM + REGRESSION
```

Retry is a state-dependent permission, not a generic loop. Before durable dispatch a fresh request MAY be retried if cumulative limits and freshness still hold. After consumed+dispatch without authoritative outcome: quarantine and no automatic retry. Idempotency/dedup key reduces duplicate risk but does not transform uncertainty into failure/success.

Rollback is allowed only for a demonstrably stageable uncommitted snapshot. External compensation is a new declared effect with its own envelope, manifest, budget, approval and residual-risk result.

Graceful degradation only narrows authority: disable external/delegated/reflective path, fall back to read-only/local compute, require human, or STOP. Recovery never resets monotonic counters, capability state, lineage or incident evidence.

### 4.2. Feedback sink

Every confirmed incident/near miss MUST create: normalized attack-catalog entry; disposable reproducer; detector/runbook regression; and, when logically expressible, a lower-level invariant/enforcement test. This is a controlled sink, not an agent-authored hidden policy pipe: activation follows material-change governance.

## 5. Supply-chain/Governance plane

Every active tool, skill, plugin/MCP adapter, model route, prompt/context assembler, image/runtime, schema, manifest and policy has owner, lifecycle state, exact content/implementation digest, provenance, signer/key status, dependencies/SBOM where applicable, compatibility/material-change rule and deprecation/revocation route.

V0 Ponytail choice: one immutable signed/content-addressed registry snapshot bundled/pinned to broker/image digest. Dynamic registry updates and adaptive discovery are denied. TOCTOU-safe resolver opens/verifies exact descriptor/artifact and passes an already verified descriptor/capability; name/alias is never sufficient. Signed provenance does not prove semantic safety: manifest conformance/negative tests remain separate.

Registry signature payload, dependency/SBOM closure, actually opened bytes, loader/runtime/image, compiled placement and later decision/capability/event/receipt MUST form one equality-checked `supply_measurement_digest` chain verified against an external trust anchor and current revocation/rollback state. Any broken edge, substituted self-consistent composite, caller-recomputed digest or verify-to-load reopen fails closed.

Update lifecycle:

```text
PROPOSED → IMPACT_DERIVED → AUTHORIZED → REQUIRED_TESTS_PASSED
→ OLD_FUTURE_BINDINGS_REVOKED → ACTIVATED_ATOMICALLY
→ NEW_DIGEST_ATTESTED → NEW_CAPABILITIES/RECEIPTS
```

Historical actual-effect receipts remain immutable/scoped to old configuration. Future-facing capability/approval/benchmark assurance becomes stale. Unknown materiality defaults to MATERIAL unless exact old/new compatibility attestation covers named claim, scope and environment.

Governance records accountable owner, approver class, risk owner, audit owner, data/retention owner, incident owner and assurance owner. `Formal/Security/Practical` lenses are not owners. Critical/High cannot be accepted by integrator; Medium requires authorized human risk receipt.

## 6. Lifecycle/Orchestration plane

### 6.1. Principals and task graph

Model invocation may act under agent principal, but external provider remains a flow sink. Agent principal holds no ambient credentials/external authority; broker/executor have separate mediated envelopes.

Delegation creates fresh immutable task-instance with exactly one parent. Message to an existing instance is `COMMUNICATE`, not reparenting. Task graph MUST satisfy:

```text
depth(child)=depth(parent)+1 <= max_depth
direct_active(parent) <= max_active_fanout
direct_total(parent) <= max_total_fanout
lineage_nodes <= max_tree_nodes
active_lineage <= max_tree_concurrency
child not in ancestors(parent)
```

Communication cycles, if profile permits, need message TTL/hop limit/dedup and lineage-wide message budget. Pilot profile denies delegation/fan-out/reflection; enabling it is material normative expansion, not a clarification of current sequential D2.

### 6.2. Authority attenuation and tree budgets

```text
Echild = meet(Eparent_at_issue, child_manifest, platform, project,
              root_contract, delegation_request, child_capability)
Echild <= Eparent_at_issue
```

Authority subset and budget availability are both required. Additive budgets use linear escrow: child grant atomically transfers from parent escrow; unused child escrow returns only after revocation, proven termination and JOIN/reconciliation. Crash/unknown child remains quarantined. Invariant per dimension:

Every descendant capability, independently of its current effect vector, MUST bind `parent_capability_id`, parent envelope digest, root lineage, child principal/audience, delegation edge nonce, depth/fan-out counters and current fence. A root capability has null `parent_capability_digest` and no delegation binding; a non-null parent digest requires the complete immutable delegation binding. Issue atomically verifies `Echild ⊑ Eparent_remaining`, transfers per-key escrow and records ancestry before child activation. A trusted durable store MUST revalidate that binding at child issue and dispatch. Parent or ancestor revocation cascades to every descendant and blocks future dispatch; escrow returns only after fenced termination/reconciliation, never merely because a child record disappeared.

```text
sum(spent over lineage) + sum(escrow of live/quarantined nodes)
    = initial root limit
```

Every budget identity in this plane is exactly `(name, unit, scope_digest, lineage_root)`; the same four-part key MUST be preserved across demand, reservation, capability, dispatch, spend, release and quarantine. A scalar total or omission of scope/lineage cannot merge independent budgets.

Depth, total nodes, historical fan-out and retry count are monotonic non-reclaimable counters. Restart/nested contract/session/branch never resets them.

### 6.3. Reflection

Persistent change to prompt, context policy, memory, model/tool description/implementation, config, manifest, policy, skill/adapter registry or routing is `MUTATE + REFLECT`. Ephemeral self-critique inside one bounded invocation is `COMPUTE`.

Reflection change set binds before/after digests, proposer/authorizer/activator, requested effects, dependency impact closure, materiality rule, invalidated future receipts/capabilities, required tests, rollback plan and activation receipt. In-flight risky action on material drift freezes/quarantines and reconciles; it never silently continues.

## 7. Cross-level interface matrix

| Flow | Required input | Produces | Failure sink |
|---|---|---|---|
| Context → L1/L2 | ordered labels/provenance/purpose and exact bundle digest | requested/derived effect closure | reject/STOP |
| L2 → L3 | exact implementation-bound manifest | per-call derived upper bound | DENY |
| L0 → L3 | actual isolation/placement ceiling receipt | physical-enforceable envelope | no dispatch |
| L3 → executor | consumed exact capability + exact `d2_frontier_digest` + fenced dispatch | attempt/outcome event | quarantine on unknown |
| executor → L4 | TCB/connector actual-effect facts | canonical causal stream | completeness alert/STOP |
| L4 → Correct | detector with evidence and scope | containment/reconciliation | incident remains open |
| L5 → L3 | valid exact-bound approval predicate | permit to issue narrower capability | no capability |
| Supply → all | active exact digests/key status | resolution/activation receipt | revoke/STOP |
| Verification → deploy | exact profile test/benchmark/attestation bundle | scoped maturity decision | NOT_READY/INCONCLUSIVE |
| Review report → workflow controller | assessment-only report projection | `STOPPED_AWAITING_EXPLICIT_USER_INSTRUCTION` | no `PATCH`/`FREEZE`/`REVIEW` without a fresh exact action grant |

## 8. Cross-cutting invariants

- `XINV-01`: no companion plane creates authority outside the dependent envelope and L0 ceiling.
- `XINV-02`: evidence/context/message is data, never authority-bearing by content alone. A remediation/review report, finding, severity, blocker, recommended patch or readiness classification has `report_authority=NONE` and `permitted_effects_from_report=[]`; `BLOCKS_CLAIM` blocks only an honest status claim.
- `XINV-03`: labels propagate across data and control dependencies; declassification ≠ endorsement.
- `XINV-04`: child authority attenuates and lineage quantitative resources conserve.
- `XINV-05`: summary/hash/schema do not remove taint or establish integrity.
- `XINV-06`: material change invalidates all dependent future-facing bindings atomically.
- `XINV-07`: recovery/rollback/compensation/cleanup are effects with authorization and evidence.
- `XINV-08`: live telemetry ≠ offline benchmark; neither expands policy.
- `XINV-09`: fresh runtime ≠ no declared information flow or persistent external effect.
- `XINV-10`: unknown provenance/materiality/outcome/budget/label defaults to fail-closed.
- `XINV-11`: an externally verified D2 frontier record binds exact contract/domain/journal/root/parent/sequence/fence identity, and its digest remains equal through decision, capability, dispatch, crash/recovery and JOIN.

## 9. Tests and evidence

| Plane | Required suites | Expected evidence |
|---|---|---|
| Context | order/digest drift, injected role, data/control taint, retention copy, stale summary | context assembly/summary provenance and deny receipt |
| Delegation | random concurrent trees, cycle/fan-out/depth, escrow races, orphan/reclaim crash, capability transfer | graph snapshot, ledger conservation, issue/consume/revoke receipts |
| Reflection | workspace-config disguise, prompt/model/tool/alias/policy/memory changes, activation race | impact/invalidation/activation receipts and regression report |
| Verification | paired A/B isolation, holdout leakage, judge calibration/disagreement, baseline mutation | exact run manifest, confidence report, reviewed baseline receipt |
| Recovery | crash at every durability boundary, unknown connector, compensation failure, incident game day | reconciliation/closure/postmortem and new test ID |
| Supply chain | digest substitution, dependency/registry poison, signer downgrade/revocation, TOCTOU resolution | provenance/resolution/rejection receipts |
| Review governance | report text with blocker/MUST_FIX/recommended patch, distinct action grants, grant replay and packet-digest drift | report projection; stopped trace without grant; exact single-use grant verification trace |

Property/mutation tests MUST kill removal of parent-envelope meet, taint propagation, material invalidation, monotonic counters, no-auto-retry guard and report-non-authority guard. Surviving mutant is a coverage gap.

## 10. DoD and status

`DECLARED`: data structures, invariants, interfaces, failures, tests/evidence and owners specified. `IMPLEMENTED`: trusted context/control plane, flow PEP, durable delegation/reflection state, reconciler, registry and benchmark runner exist in an exact profile. `VERIFIED`: finite properties machine-checked where applicable, implementation conformance/fault tests and operational evidence pass; semantic quality/human judgment retain uncertainty.

Current: all planes are `DECLARED`; reference schemas/tests may validate subsets of specification. No deployment, runtime attestation, registry inventory, context assembler, model/provider binding, delegation ledger, incident evidence or calibrated benchmark is present.

## 11. Explicit non-equivalences and residual risks

- Static manifest ≠ actual-effect receipt.
- Human approval ≠ formal verification/controller JOIN.
- Content hash/signature ≠ semantic safety.
- Fresh container ≠ absence of declared cross-iteration flow.
- Agent agreement ≠ independent endorsement/quorum.
- Compensation ≠ rollback/success erasure.

Residual risks include semantic/covert channels, provider retention, collusion, compromised control plane/host/witness, supply-chain signer compromise, benchmark gaming and human error. Their claim scope/capacity/assumptions must be profile-specific; they cannot honestly be reduced to zero here.

Delegation, approval and D2 regressions MUST cover exact parent-clause digest at validation, issue and dispatch; retargeted selector, operation, scope/facet/typed-constraint, depth and fan-out after coherent reseal; exact trusted/receipt/live approval-envelope equality; and admission rejection when frontier or slot is not the pre-admission reducer state. These specification-model checks do not alter `NOT_IMPLEMENTED`, `NOT_ATTESTED` or `NOT_READY`.

Review-governance regressions MUST prove that report text alone cannot transition the workflow, a `PATCH` grant cannot authorize `REVIEW`, every action grant is fresh, externally verified, exact-bound and single-use, authoritative current packet/scope/budget/attempt drift invalidates it, and successful use returns an atomically consumed grant-ID/nonce state whose replay stops. Loop regressions MUST also prove atomic `attempt_cursor` advance with frontier bind, `JOIN`-only `joined_iteration` advance, persistence across discard/crash/reopen/lost acknowledgement, stale/gap/rollback rejection without mutation, success targets that cannot enlarge `max_iterations`, and a changed bound that needs a newly verified contract. These are specification-model checks and do not alter `NOT_IMPLEMENTED`, `NOT_ATTESTED` or `NOT_READY`.
