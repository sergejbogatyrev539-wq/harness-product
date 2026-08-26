# Level 3 — Runtime policy and transaction semantics

## Status and claim boundary

Status vector for this artifact:

- `specification = SPECIFIED`
- `runtime = NOT_IMPLEMENTED`
- `evidence = SPECIFICATION_MODEL_TESTED`
- `runtime_attestation = NOT_ATTESTED`
- `overall = NOT_READY`
- `scope = FORMAL_SPECIFICATION_AND_PURE_REFERENCE_MODEL_ONLY`
- Canonical status marker: `Q94-STATUS-VECTOR: specification=SPECIFIED; runtime=NOT_IMPLEMENTED; evidence=SPECIFICATION_MODEL_TESTED; runtime_attestation=NOT_ATTESTED; overall=NOT_READY; scope=FORMAL_SPECIFICATION_AND_PURE_REFERENCE_MODEL_ONLY`

The executable artifact `tests/policy-reference.py` is a pure reference model. It performs no signature verification, I/O, journaling, locking, dispatch, isolation, telemetry emission or external effect. Its “durable record” is a JSON value describing what an implementation must commit atomically; it is not a durable store. Passing these tests is not runtime conformance evidence.

`MUST`, `MUST NOT`, `SHOULD`, and `MAY` are normative terms in this package. Their Russian equivalents have the same force.

## 1. Purpose and non-goals

Level 3 decides whether one normalized request may proceed, issues an exact capability, and constrains a transaction from admission through JOIN or safe terminal failure.

Its purposes are to:

1. intersect every authority ceiling without accidental permission synthesis;
2. fail closed on unknown, missing, stale, mismatched or unbounded input;
3. reserve cumulative budgets and consume capability at the durable dispatch boundary;
4. preserve separate stageable and non-stageable external branches;
5. define crash, retry, recovery, revocation, reconciliation and compensation semantics;
6. make the provisional D2 operational bound testable.

Non-goals are runtime isolation, implementation of a durable journal, proof of external provider behavior, proof of human comprehension, and prediction of all effects of arbitrary code.

## 2. Assets, adversaries and trust assumptions

Protected assets include authority boundaries, capability uniqueness, contract and policy integrity, monotonic counters, resource budgets, external-effect deduplication, staged snapshots, information labels, receipts and evidence lineage.

Adversaries and failures include malicious model output, prompt/tool/registry poisoning, replayed capabilities, confused-deputy calls, policy mismatch, scope expansion, budget fragmentation, delegation amplification, concurrent writers, stale clocks/revocation, crash between consume and dispatch, ledger rollback/fork, unknown external outcome, forged telemetry and approval confusion.

Trust assumptions:

- normalized inputs and trusted facts are provided by components outside the agent;
- Level 0 supplies separate envelopes for worker, broker/executor, model gateway and observer;
- the broker/PEP, durable store, signer/verifier, clock/revocation service and executor fencing mechanism are trusted only for their stated roles;
- no agent is an ambient authority holder or external effect executor;
- an external model/provider is an explicit `COMMUNICATE` sink, even while the worker network remains disconnected;
- project-specific `CB5`, `JOIN`, law-of-cut, `D2`, `JR5`, `LRP1_D`, `S5`, `RJ*`, `B3`, placement `P2`, `R0–R6` and authority domain remain `PROVISIONAL` absent authoritative definitions.

## 3. Inputs, outputs and authoritative sources

The pure decision consumes:

- normalized request and typed requested authority entries;
- Level 2 bound manifest and registry snapshot;
- physical, platform, project, contract, session and call policy layers;
- exact loop contract and trusted approval facts where required;
- capability candidate, revocation/freshness state and consumed-nonce set;
- remaining budget vector, joined/candidate sequence and telemetry readiness.

The result conforms to `schemas/decision-result.schema.json`:

```text
DecisionResult =
  decision ∈ {ALLOW, DENY, REQUIRE_HUMAN, STOP}
  + reason_codes
  + authorized_effects
  + obligations
  + budget reservations
  + next_state
  + material digests
```

Only `ALLOW` may request capability issuance, and it contains at least one authorized effect. `DENY`, `STOP`, and `REQUIRE_HUMAN` contain no authorized effects and issue no capability.

Authoritative runtime state would come from a durable serializable journal and trusted state services. RAM sets and JSONL files do not satisfy that obligation.

A remediation/review report is not a `DecisionResult`, request, capability or approval. Its closed content-addressed projection binds report/packet identity, report time, finding IDs, readiness impact, affected status claims, recommended patch and unresolved consequence, while fixing `report_authority=NONE`, `permitted_effects_from_report=[]`, and `controller_state_after_report=STOPPED_AWAITING_EXPLICIT_USER_INSTRUCTION`. `readiness_impact` is closed to `BLOCKS_CLAIM | HUMAN_RISK_DECISION_REQUIRED | NONBLOCKING | NONE`; `affected_status_claims` is a subset of `SPECIFIED | IMPLEMENTED | VERIFIED | READY`. `BLOCKS_CLAIM` blocks only the named honest status claim, never a subsequent action.

## 4. Policy hierarchy and effective authority

Precedence is fixed:

```text
physical hard ceiling
  → platform/org
  → project
  → contract
  → session
  → iteration/call
```

Every lower layer may only narrow. Deny overrides allow at every layer. A conflict produces a specific reason code; it does not select the more permissive value.

An explicit deny is evaluated as a terminal match over the same complete correlated clause and MUST run before any allow construction. No empty allow list, later rule, approval, capability, schema validity or narrower-looking request can mask a matching deny.

For typed operation `o`, effect `e`, resource kind `r`, requested scope/bounds `q`:

```text
Effective(o,e,r) = meet(
  Physical(o,e,r),
  Manifest(o,e,r),
  Platform(o,e,r),
  Project(o,e,r),
  Contract(o,e,r),
  Session(o,e,r),
  CallPolicy(o,e,r),
  Capability(o,e,r)
)

ALLOW only if every requested dependent entry q is covered by Effective(o,e,r)
         and demand_vector ≤ remaining_vector
         and all admission predicates and obligations hold.
```

There is no independent recombination of an allowed effect from one entry, an allowed target from another and a budget from a third. An undefined typed meet is `UNKNOWN` and fails closed.

Human approval is an exact-bound predicate/evidence input. It is neither a lattice join nor controller `JOIN`, and it cannot expand the physical/platform ceiling.

## 5. Pure/total decision function

The reference signature is:

```python
decide(request, manifest, policy, capability, state) -> DecisionResult
```

It is pure because it reads no clock, filesystem, network, registry or mutable global state; `now_tick` and verification outcomes are explicit trusted facts. It is total over JSON-like partitions: malformed inputs return `STOP`, not an exception or implicit allow. For filesystem mutation, admission verifies the selector's physical-target digest against an independent trusted target record and carries it in the capability; dispatch requires its trusted physical target to equal that immutable capability digest as well as canonical path, descriptor ID, root/mount IDs and identities, resolution epoch, and final object ID/digest. Same-path root, mount or epoch substitution is `STOP`.

### 5.1 Ordered decision table

| Priority | Predicate | Result / reason |
|---|---|---|
| 1 | malformed input or invalid controller state | `STOP / MALFORMED_INPUT` or `INVALID_CONTROLLER_STATE` |
| 2 | unclassified, unbounded or illegible | `STOP / UNKNOWN_OR_UNBOUNDED` |
| 3 | unknown effect/deny/approval set | `STOP / UNKNOWN_*` |
| 4 | inactive policy/manifest or operation mismatch | `DENY / INACTIVE_*` or `OPERATION_MISMATCH` |
| 5 | effect exceeds manifest, physical, policy or capability ceiling | `DENY / EFFECT_EXCEEDS_*` |
| 6 | explicit deny matches | `DENY / EXPLICIT_DENY` |
| 7 | typed scope/operation is not covered | `DENY / SCOPE_EXCEEDS_*` |
| 8 | material digest/request binding missing or mismatched | `STOP` if missing; otherwise `DENY / *_MISMATCH` |
| 9 | capability is replayed, stale, revoked, transferred or wrong-purpose | `DENY / CAPABILITY_*` |
| 10 | D2 or iteration bound fails | `DENY / D2_VIOLATION` or `ITERATION_BUDGET_EXCEEDED` |
| 11 | demand is malformed or exceeds any bound | `DENY / BUDGET_EXCEEDED_OR_MALFORMED` |
| 12 | required authoritative telemetry unavailable | `STOP / TELEMETRY_MISSING` |
| 13 | exact human approval is required but absent/stale/mismatched | `REQUIRE_HUMAN / EXACT_APPROVAL_REQUIRED` |
| 14 | all predicates hold | `ALLOW / AUTHORIZED_EXACT_BOUND` |

`REQUIRE_HUMAN` is reachable only after boundedness, legibility, physical, manifest, policy, capability, scope, freshness, D2, budget and telemetry checks. Unknown or uncontainable work is not approvable.

## 6. Normative requirements

| ID | Normative requirement | Owner / enforcement point | Failure result | Test / evidence |
|---|---|---|---|---|
| `L3-REQ-001` | Controller default and every unknown pre-dispatch terminal result MUST be `STOPPED`. | Controller owner / broker PEP | `STOP` | `T-POL-002`, `T-LTS-ILLEGAL` |
| `L3-REQ-002` | Unknown, missing, unclassified, unbounded, stale or mismatched data MUST NOT become allow. | Policy owner / broker PEP | `DENY/STOP` | 192 exhaustive partitions; 25 malformed partitions |
| `L3-REQ-003` | Agents MUST have no ambient external authority; broker, executor, model gateway and observer MUST have separate envelopes. | Platform owner / Level 0 + broker PEP | `STOP: PROFILE_MISMATCH` | schema/profile conformance obligation |
| `L3-REQ-004` | Every side effect MUST pass admission and non-bypassable mediated dispatch. Tool proposals remain powerless. | Runtime owner / broker + executor PEP | `DENY/STOP` | stageable/external traces |
| `L3-REQ-005` | Requested authority MUST be covered by the dependent meet of physical, manifest, every policy layer, contract and capability. | Policy owner / broker PEP | `DENY: EFFECT/SCOPE_EXCEEDS_*` | `T-POL-004`, exhaustive partitions |
| `L3-REQ-006` | Capability MUST bind principal, audience, purpose, contract, manifest, policy, request, registry, profile, nonce and lineage; every descendant additionally carries immutable delegation provenance independently of its current effect vector. It MUST be short-lived, single-use, nonreplayable and nontransferable. | Capability owner / broker + durable store | `DENY: CAPABILITY_*` | `T-POL-006/007/015/016` |
| `L3-REQ-007` | Demand MUST be reserved before dispatch against call, iteration, session, contract, lineage and delegation-tree budgets. Counters MUST NOT reset on retry, restart, branching or nested contracts. | Budget owner / broker + durable store | `DENY: BUDGET_*` | `T-POL-009`, durable trace assertions |
| `L3-REQ-008` | Stageable mutation MUST quiesce/revoke writers, seal an immutable snapshot, run independent postcheck, then commit. | Runtime owner / supervisor + observer + committer | discard/quarantine | `T-LTS-001/002`, bounded explorer |
| `L3-REQ-009` | Capability consume, budget reservation, dispatch intent, monotonic counter and fencing epoch MUST commit in one durable serializable transition before/downstream with dispatch. | Journal owner / single writer + executor fence | `STOP/QUARANTINE`; no dispatch without record | atomic record assertions |
| `L3-REQ-010` | Before `JOIN(N+1)`, no controller-visible, persisted, staged, tool-bound, budgeted or reusable N+2 candidate or authority artifact may exist. | Controller owner / controller + journal | `DENY: D2_VIOLATION` | `T-POL-010`, trace ordering |
| `L3-REQ-011` | Non-stageable external effects MUST precheck, use a dedup key where supported, durably consume at dispatch, reconcile outcome through an externally verified typed terminal receipt, and never auto-retry `UNKNOWN_OUTCOME`. Compensation is a fresh authorized transaction. | External-effect owner / broker + executor + recovery | quarantine/reconcile | `T-LTS-003`, no-auto-retry assertion |
| `L3-REQ-012` | Required safety events MUST be emitted unsampled by authoritative components. Missing/corrupt required telemetry for risky action MUST fail closed. | Observability owner / broker/PEP/TCB | `STOP/QUARANTINE` | `T-POL-011` |
| `L3-REQ-013` | Material prompt/context/tool/model/adapter/manifest/policy/contract/registry change MUST invalidate approval and capability bindings. | Policy owner / broker PEP | `DENY: MATERIAL_BINDING_MISMATCH` | `T-POL-008/013` |
| `L3-REQ-014` | N→N+1 evidence MUST be schema-bound, label/taint-propagated and explicitly admitted; arbitrary output is not trusted context or authority. | Context owner / context assembler + broker PEP | `DENY/STOP` | context/taint implementation obligation |
| `L3-REQ-015` | Declassification and integrity endorsement MUST require separate exact capabilities; hash/schema/summary MUST NOT perform either automatically. | Data owner / flow PEP | `DENY: FLOW_NOT_ALLOWED` | schema field checks; flow conformance obligation |
| `L3-REQ-016` | Delegation MUST attenuate authority and atomically conserve parent/child budgets across the complete tree. | Orchestration owner / orchestrator + broker PEP | `DENY: DELEGATION_AMPLIFICATION` | spawn manifest; delegation runtime obligation |
| `L3-REQ-017` | A single writer MUST use monotonic fencing epochs; downstream executors MUST reject stale epochs. | Journal owner / durable store + executor | `STOP/QUARANTINE` | atomic dispatch record; stale-fence implementation test |
| `L3-REQ-018` | Development/test/production profiles MUST be separate and all numeric bounds MUST be calibrated/profile-owned, not inherited as universal corpus constants. | Risk owner / policy registry | `STOP: PROFILE_UNCALIBRATED` | profile review evidence |
| `L3-REQ-019` | D2 admission MUST consume a complete externally verified controller-derived frontier record with exact contract/domain/journal/root/parent/sequence/fence bindings and canonical digest. Omitted, empty, stale or hidden N+2 classes MUST fail closed; caller-provided inventory is non-authoritative. | Controller + journal | `DENY: D2_INVENTORY_INVALID` | `T-Q40-D2-EMPTY`, `T-Q40-D2-STALE`, `T-Q40-D2-HIDDEN_N_PLUS_2`, `T-Q40-D2-REQUIRED-ARTIFACT-MISSING` |
| `L3-REQ-020` | Active contract admission MUST resolve the trusted current contract and bind canonical contract digest, authority, budgets, iteration/D2, postcheck and real lineage through decision, capability, dispatch and JOIN. | Contract resolver + controller | `STOP: CONTRACT_BINDING_MISMATCH` | `T-Q44-CONTRACT-SUBSTITUTION` |
| `L3-REQ-021` | A stageable crash after durable dispatch with unknown effect MUST enter `QUARANTINED/RECONCILING` and retain escrow; it may release only with independently verified no-effect evidence. | Recovery owner + journal/reconciler | `QUARANTINE` | `T-Q45-STAGEABLE-CRASH-QUARANTINES` |
| `L3-REQ-022` | Mutation capability audience MUST resolve to an externally verified, pairwise-distinct `EXECUTOR` principal/session; worker/self audience is forbidden. | Capability issuer + executor | `DENY: AUDIENCE_ROLE_MISMATCH` | `T-Q47-MUTATION-SELF-AUDIENCE-DENY`, `T-DECISION-ALLOW-EXACT` |
| `L3-REQ-023` | Selector/resource scope MUST use a closed typed relation before comparing values; incompatible kinds (for example endpoint versus file) MUST not authorize one another. | Policy PEP | `DENY: TYPED_SCOPE_MISMATCH` | `T-Q48-POLICY-SCOPE-KIND-CROSS-MATRIX` |
| `L3-REQ-024` | `COMMIT` and `JOIN` MUST require externally verified typed same-object evidence bound to transaction, decision, capability, envelope, seal/postcheck or external receipt. Forged, swapped, missing or self-asserted evidence fails closed. | Observer/commit authority + controller | `QUARANTINE` | `T-Q49-COMMIT-TYPED-EVIDENCE-FORGE`, `T-Q49-JOIN-TYPED-EVIDENCE-FORGE` |
| `L3-REQ-025` | Every budget key MUST be exactly `(name, unit, scope_digest, lineage_root)` and the identical key set MUST survive demand, reservation, capability and dispatch. | Budget ledger + PEP | `DENY: BUDGET_IDENTITY_MISMATCH` | `T-Q50-BUDGET-SCOPE-IDENTITY-SUBSTITUTION`, `T-Q50-BUDGET-LINEAGE-IDENTITY-SUBSTITUTION`, `T-Q50-BUDGET-FOUR-PART-KEY-PRESERVED` |
| `L3-REQ-026` | Capability issue and dispatch MUST each consult a durable external verifier record covering every signed field; inline facts or a recomputed plain digest never authenticate a mutated capability. | Capability verifier/store + executor | `DENY: CAPABILITY_NOT_VERIFIED` | `T-Q51-ISSUE-EXTERNAL-FULL-RECORD`, `T-Q51-DISPATCH-EXTERNAL-FULL-RECORD` |

## 7. State machine and branches

### 7.1 Common admission

```text
STOPPED → PROPOSED → NORMALIZED → CLASSIFIED → ADMITTED
        → BUDGET_RESERVED → CAPABILITY_ISSUED
```

`BUDGET_RESERVED` means the amount has been computed and checked; no effect has been dispatched. At `DURABLE_DISPATCH`, the implementation must atomically record capability consumption, reservation, dispatch intent, counter increment and fencing epoch. Splitting these across crashable writes is non-conformant.

Required budget keys are exactly `(name,unit,scope_digest,lineage_root)` from the authorized envelope. Demand, decision, capability and durable dispatch vectors MUST have identical key sets and dispatch vector MUST equal the decision reservation component-wise; scalar totals, omitted dimensions and cross-scope or lineage substitution are invalid. The key is part of budget identity, not display metadata.

The durable ledger MUST retain `remaining`, `reserved`, `spent` and unknown-outcome escrow for every exact four-part key and atomically record each transition's before/delta/after vectors. Scalar totals are derived views only and MUST NOT authorize, conserve or release budget.

Нормативный порядок: verified ceilings/evidence дают `ALLOW(authorized_envelope, reservation_vector, obligations, decision_digest)`; затем durable `ADMITTED(decision_digest)`; только после этого trusted issuer создаёт exact-bound capability, и executor выполняет atomic consume+reserve+dispatch. Decision input MUST NOT требовать уже live `ISSUED` capability, создание которой разрешает это же решение: до `ALLOW` существует только non-authoritative ceiling candidate. `ADMIT` без verified decision, null/malformed capability digest, envelope/decision/session mismatch и replay (включая после `STOP`/restart) MUST NOT dispatch. Consumed nonce/digest и cumulative counters не очищаются.

Before `ALLOW`, the contract resolver MUST load the trusted active loop contract and verify its canonical digest, exact authority/budget/iteration/D2/postcheck bindings and real root/child lineage. A caller-supplied contract ID/digest or placeholder lineage is not an active contract fact; substitution or stale resolution yields `STOP: CONTRACT_BINDING_MISMATCH`.

Capability is authoritative only after an externally anchored durable verifier record verifies the issuer signature over its complete canonical payload and exact current principal/audience/purpose/envelope/request/decision/contract/manifest/policy/registry/placement/session/lineage/nonce/time/revocation/fence bindings. Rehashing a mutated payload never authenticates it; PEP and executor independently consult the verifier and recheck trusted time, revocation and fence immediately before dispatch. Mutation capability audience MUST be an externally verified, pairwise-distinct `EXECUTOR` principal/session and MUST NOT be the worker.

**Q-59 normative anchor (effect containment).** The authoritative event and
receipt chain MUST enforce `committed ⊆ authorized ⊆ manifested ∩ physical`.
Every attempted entry outside the authorized envelope MUST be represented in
`blocked`; attempted excess MUST NOT be committed, observed as success or
silently omitted. Any containment or binding inconsistency forces
`QUARANTINED` and forbids `COMMIT/JOIN`.

Path scope принимает только canonical descriptor-root identity и normalized components. Raw lexical prefix не является containment proof. `..`, NUL, ambiguous/percent-encoded traversal, symlink/magic-link/hardlink/mount crossing или identity drift дают `DENY`; executor использует descriptor-relative beneath/no-magic-link resolution (`openat2` или эквивалент) и сверяет final object identity при effect.

**Q-55 normative anchor (`PATH_EXACT`).** `PATH_EXACT` MUST bind the exact
descriptor digest, `descriptor_id`, root identity, mount identity, epoch and
normalized components. The same composite identity MUST survive manifest,
policy, capability, dispatch and receipt; digest-only or descriptor-only
substitution is `DENY/STOP`, even when the lexical path is unchanged.

Placement/session verifier facts — не boolean: exact attestation digest, instance/session IDs, composite measurement, nonce, issue/expiry, revocation epoch и fence проходят через decision/capability/durable dispatch и повторно проверяются непосредственно перед dispatch.

Broker IPC verifier facts are likewise not boolean: admission requires one externally verified signed complete-payload record for the exact worker↔broker `AF_UNIX/SOCK_SEQPACKET` `UNIX_CONNECTED_PAIR` session, including profile and IPC-binding digests, subjects, both endpoint device/inode/socket-cookie identities, exact FD allowlists and observed holders, broker-observed per-message credentials, message schema, operation, nonce, fence, lifetime and revocation. Creation-time `SO_PEERCRED` alone does not authenticate the final holders. The canonical signed payload excludes only `attestation_digest` and `signature`; `attestation_digest` and `signature.payload_digest` both equal its canonical digest. Its attestation and IPC-binding digests continue unchanged through decision, capability, durable dispatch, receipt/event and `JOIN`; durable dispatch and `JOIN` recheck the record. Endpoint/holder/credential substitution, any additional connected or external-sink FD, reconnect, replay or pair replacement is material change requiring fresh admission or `STOP`, not a transition or service.

`resource_vector_digest` is the digest of the canonical active isolation-profile `resources` array. It remains unchanged through admission, decision, capability, dispatch, receipt and event, while operation-specific reservations remain a separate exact vector; neither vector may be inferred from, substituted for or translated into the other.

**Q-56/Q-57 cross-level anchors.** The Level 3 admission MUST preserve the
closed Level 0 `(resource, unit, enforcer)` tuple without translation or
substitution. It MUST also require exact equality of the trusted-root digest
across candidate, profile, external verifier facts and composite measurement
preimage; mismatch is `STOP`.

**Q-53 normative anchor (complete signed attestation projection).** Level 3
MUST consume an externally verified signed attestation projection whose record
covers every signed field (subject/host, profile and measurement digests,
nonce, epoch/fence, issue/expiry, signer/key, revocation and
placement/session binding). A caller-computed digest or partial projection is
not trusted evidence; any field mismatch yields `STOP` and cannot issue or
dispatch a capability. Runtime attestation remains `ABSENT`.

### 7.2 Stageable/reversible branch

```text
CAPABILITY_ISSUED
 → DURABLE_DISPATCH → EXECUTING → QUIESCED → SEALED
 → POSTCHECKED → COMMITTED → JOINED → STOPPED / next transaction

SEALED → POSTCHECK_FAILED → DISCARDED → STOPPED
commit uncertainty → QUARANTINED / RECONCILING
```

The reference reducer uses `POSTCHECK_FAIL → DISCARDED`. A runtime must also prove that all writers were quiesced before seal and cannot mutate the sealed object before JOIN.

If a crash occurs after durable stageable dispatch and the effect is not independently proven absent, recovery MUST enter `QUARANTINED/RECONCILING`, retain the reservation as `QUARANTINED_ESCROW`, and forbid `DISCARDED`/`RELEASED` or retry. Release is permitted only after an independent authoritative no-effect verifier record bound to the same transaction, dispatch intent, target object and epoch.

### 7.3 Non-stageable external branch

```text
CAPABILITY_ISSUED → PRECHECKED → DURABLE_DISPATCH → EXECUTING
 → KNOWN_SUCCESS | KNOWN_FAILURE | UNKNOWN_OUTCOME

KNOWN_SUCCESS → RECONCILED → JOINED
KNOWN_FAILURE → FAILURE_RECORDED → STOPPED / COMPENSATION_PENDING
UNKNOWN_OUTCOME → QUARANTINED / RECONCILING
```

`UNKNOWN_OUTCOME` is not failure and is not success. The original capability is consumed, automatic retry is prohibited, and reconciliation continues under quarantine. A duplicate external call is permitted only after the outcome is known and a fresh transaction is independently admitted under provider-specific idempotency semantics. `RECONCILED_SUCCESS` and `RECONCILED_FAILURE` require a closed typed terminal reconciliation receipt with `EXTERNAL_RECONCILIATION` evidence type, `SUCCESS` or `FAILURE_NO_EFFECT` outcome, and exact transaction, decision, capability, envelope, contract, lineage, dispatch intent, idempotency key, object identity, fencing epoch, connector evidence and chain bindings.

`COMMIT`/`JOIN` consume only typed evidence records verified by an external observer/verifier: transaction, decision, capability, envelope, object identity, seal/postcheck (or external receipt), source/event chain and epoch MUST all match. Terminal reconciliation receipts MUST be resolved and verified from a trusted external store; caller-supplied or self-hashed receipt fields are not authority. Digest-shaped records, swapped objects, self-asserted passed booleans or missing stages are not evidence and MUST leave the transaction quarantined.

### 7.4 Compensation branch

```text
fresh PROPOSED transaction
 → full common admission
 → COMPENSATED_VERIFIED | RESIDUAL_EFFECT | COMPENSATION_FAILED
 → STOPPED
```

Compensation has its own effects, manifest, contract/policy bounds, budget, capability, event and receipt. It does not erase the original committed effect from history and is not equivalent to rollback success.

### 7.5 Illegal and crash transitions

An illegal pre-dispatch transition fails to `STOPPED`. If a capability was consumed and the effect is not known committed/joined/stopped, an illegal or malformed transition enters `QUARANTINED`, preserving uncertainty. The reducer never invents a successful terminal state.

## 8. Durable state, concurrency and fencing

The minimum serializable record at dispatch contains:

```text
transaction_id
capability_consumption
budget_reservation
dispatch_intent
monotonic_counter
journal_sequence
fencing_epoch
```

Required properties:

- one authoritative writer per lineage;
- compare-and-advance or equivalent serialization;
- capability nonce uniqueness and durable consumed state;
- budget reservation linearity; no double-spend across child branches;
- counter/journal/epoch monotonicity across crash/restart;
- executor rejection of stale fencing epochs;
- an anti-rollback witness/anchor for any claim stronger than tamper evidence.

The reference reducer checks the atomic-field set and ordering only. It does not implement serialization, disk durability, consensus, signatures, witnesses, trusted-store reconciliation verification or fencing at an executor; runtime status remains `NOT_IMPLEMENTED` and attestation `NOT_ATTESTED`.

Каждая reservation имеет ровно один durable terminal disposition: `SPENT`, `RELEASED` или `QUARANTINED_ESCROW`. Stageable commit и reconciled external success переводят escrow в spent; proven no-effect failure/discard — в released; unknown outcome сохраняет quarantined escrow. `JOIN` и completed `STOP` с unresolved reservation/lease запрещены. Reducer моделирует typed crash/restart/recovery/revocation/cancel/commit-unknown transitions; recovery не восстанавливает `ISSUED` capability из intent и не повторяет dispatch. Compensation начинается только новой fully admitted transaction.

For an endpoint-only external operation, trusted identity is the closed
`endpoint_binding` tuple: `endpoint_id`, `canonical_endpoint`, `connector_id`,
`connector_digest`, `method`, `idempotency_key_digest` and
`endpoint_binding_digest`. It binds admission, manifest, policy, capability,
Level 0's compiled endpoint envelope, durable dispatch and reconciliation
exactly. That compiled route carries endpoint bindings and no path scope or
filesystem target; a route mixing `ENDPOINT` with `FILE`/`DIRECTORY` is
invalid. Endpoint receipt/event identity is
that tuple alone; descriptor/root/mount/final-object filesystem proof is
rejected, as endpoint evidence is rejected for a filesystem effect. This is a
specified contract only: runtime connector trust/dispatch/reconciliation remain
`NOT_IMPLEMENTED` / `NOT_ATTESTED`.

A trusted `KNOWN_FAILURE` receipt/event MUST carry a closed component-wise
disposition: each effect component is `NO_EFFECT`, `PARTIAL_EFFECT` or
`RESIDUAL_EFFECT`; each exact positive-amount budget key is `SPENT`, `RELEASED`
or `QUARANTINED_ESCROW`. Signed external residual reconciliation uses terminal
`FAILURE_WITH_RESIDUAL_EFFECT`, never `FAILURE_NO_EFFECT`. Partial/residual effect forbids `RELEASED`, automatic retry
and `JOIN`; it is contained/quarantined until a fresh independently admitted
compensation transaction exists. `COMPENSATION_PENDING` therefore carries that
new transaction's `ADMITTED` decision/envelope/capability binding; it cannot
reuse the failed transaction's capability or authorization.

**Q-58 normative anchor (pre-dispatch rejection closure).** Every rejection
before dispatch, including malformed capability issuance, MUST atomically write
exactly one durable terminal disposition for each reservation: `RELEASED` or
`QUARANTINED_ESCROW` (and never both or neither). The disposition MUST carry
the complete reservation vector/digest and equal the reserved amount; a
duplicate rejection emits no second disposition, and a fresh proposal starts
only after the prior reservation is closed. Runtime durable-store evidence is
`ABSENT`.

## 9. D2 provisional operational rule

Because no authoritative project definition was found, D2 remains `PROVISIONAL`. V0 preserves the corpus inequality and applies the following operational bound:

> Before controller `JOIN(N+1)`, there MUST NOT exist a controller-visible, persisted, staged, tool-bound, budgeted or reusable N+2 proposal/branch, nor an N+2 capability, reservation, lock, target binding, dispatch or external authorization.

Controller MUST хранить closed typed `frontier_inventory` всех этих classes as an authoritative, durable snapshot with an externally verified frontier record: exact `contract_digest`, `contract_version=1.0.0`, `authority_domain_id`, `journal_lineage_id`, `root_contract_digest`, nullable `parent_contract_digest`, `journal_sequence`, `fencing_epoch` and `frontier_record_digest`. Its canonical `d2_frontier_digest` MUST be bound unchanged through decision, capability, dispatch, crash/recovery and JOIN. Each create/persist/stage/tool-bind/reserve/lock/capability/target-bind/dispatch/external-authorize transition atomically updates the inventory and до `JOIN(N+1)` отвергает class для N+2 без state mutation. Caller-provided empty/omitted, stale, or hidden-N+2 inventories are invalid; scalar comparison номера итерации без complete inventory не удовлетворяет этому требованию.

Inventory is durable and class-derived, not caller-labelled: `PLAN`, `PROMPT`, `CONTEXT`, `CANDIDATE`, `REUSABLE_BRANCH`, `TOOL_BINDING`, `CAPABILITY`, `BUDGET_RESERVATION`, `LOCK`, `TARGET_BINDING`, `DISPATCH_INTENT`, `EXTERNAL_AUTHORIZATION`, `STAGED_OUTPUT`, `PERSISTED_STATE`, `CONTROLLER_TOKEN`. Empty/false fields do not remove intrinsic class membership. Creation also fails when `iteration > contract.max_iterations`.

Here `contract.max_iterations` is a maximum attempt count. Failed, blocked, retried, restarted and nested attempts advance the same durable counter; a desired success count never enlarges or resets it. A changed contract or frozen-packet digest requires a new exact contract and fresh explicit user continuation grant.

Private ephemeral model tokens that are never persisted, transferred, exposed to the controller or made context/evidence are outside this transaction bound. If they become reusable or observable, they enter the bound. Per-contract human confirmation does not replace per-iteration machine JOIN.

## 10. Human approval semantics

Approval is evaluated only after the request is bounded and legible. Trusted approval verifier result must bind request, manifest, policy, contract and canonical payload digests, exact approved envelope, nonce, TTL/freshness/revocation, quorum/SoD and comprehension evidence; it must be service-signed, live, single-use, nonreplayable and unchanged materially. Agent-supplied booleans are untrusted input. Only decision `APPROVE` can create an authorization state `ISSUED/CONSUMED`; `REJECT`, `MODIFY`, `REQUEST_MORE_EVIDENCE` and `CANCEL` cannot. Human authentication and comprehension evidence are separate from the service signature.

Approval can activate only the already-allowed exact subset. It cannot:

- expand Level 0 or platform policy;
- classify unknown behavior as safe;
- supply missing budgets or telemetry;
- act as controller JOIN;
- authorize a stale/mismatched capability.

This runtime approval is distinct from a workflow continuation grant. A continuation grant can authorize only its one exact `PATCH`, `FREEZE` or `REVIEW` workflow transition after a report; it never authorizes a runtime effect, and report wording never substitutes for it. The controller compares the grant with its authoritative current packet/scope/budget/attempt state and MUST atomically persist grant-ID/nonce consumption with that one transition.

Break glass is outside the ordinary decision path and remains inside an immutable platform ceiling with dual control, TTL, real-time alert, recovery plan and postmortem.

## 11. Information, secrets and N→N+1 evidence

Labels contain confidentiality, integrity, provenance, taint, purpose and retention. They propagate over both data and control dependencies. A broker-owned model gateway is an explicit external `COMMUNICATE` sink. The worker remains network-disconnected and receives no ambient credentials.

Secret references MAY be resolved just-in-time by the broker/executor for an exact call. Secret bytes MUST NOT be exposed to the agent unless a separate exact authority entry and policy explicitly permit it.

Output N→N+1 is a declared information/control channel. Before admission as next context, it must be canonicalized, schema-validated, size/depth bounded, label/taint propagated and bound by new material digests. Those operations do not declassify, endorse or turn evidence into authority.

## 12. Failure, timeout, retry, recovery and revocation

| Condition | Normative response |
|---|---|
| Decision timeout, missing fact or evaluator error | `STOP`; no capability |
| Capability expiry/revocation/replay | `DENY`; durable replay event |
| Budget exhaustion/fragmentation | `DENY`; no partial reservation |
| Crash before atomic durable dispatch | recover `STOPPED`; fresh decision/capability; counters unchanged |
| Crash after atomic durable dispatch but before known outcome | recover from journal; stageable reconcile or external quarantine; no capability reuse |
| Executor sees stale fencing epoch | reject and emit authoritative stale-writer event |
| Stageable postcheck failure | discard sealed staging object; `STOPPED`; new transaction for retry |
| External known failure | authoritative component-wise disposition; partial/residual → contain/quarantine, no release/retry/JOIN; compensation only with fresh admitted authorization |
| External unknown outcome | quarantine/reconcile; automatic retry forbidden |
| Material artifact/policy change | invalidate receipt and capability; re-admit |
| Missing/corrupt safety telemetry | `STOP/QUARANTINE` according to dispatch state |
| Recovery/rollback/compensation | treat as a new manifested and budgeted effect transaction |

Backoff, circuit breakers and graceful degradation MAY reduce load but MUST NOT extend authority, reset counters or turn unknown outcome into safe retry.

Recovery is phase-sensitive: durable `COMMITTED` cannot become `DISCARDED`; it resumes as commit-pending-JOIN or quarantine/reconciliation. A fresh transaction clears all prior request/capability/approval/reservation/dispatch/stage/receipt fields and inherits only explicitly scoped cumulative lineage, budget and revocation facts. After supervisor/host failure no new admission occurs until old epochs are fenced and actual processes, writers, leases and storage are reconciled by the host recovery gate.

## 13. Telemetry and evidence

Every authoritative transition must emit an unsampled event that binds:

- trace/run/contract/session/iteration/call and delegation lineage IDs;
- principal, tool, implementation, manifest, policy, contract, capability and registry digests;
- requested, manifested, derived, authorized, attempted, blocked, actual, committed, observed and verified effects/scopes;
- decision/reason/obligations;
- budget before/delta/after;
- journal sequence and fencing epoch;
- outcome, seal, postcheck, reconciliation and receipt digests;
- clock source and privacy-safe canonical argument/output digests.

The agent cannot be the authoritative emitter. Unbounded identifiers, hashes and arguments belong in logs/traces/evidence, not unbounded metric labels.

Specification evidence currently available:

- schema checks and CLI example validation;
- 16 named decision vectors;
- exhaustive finite product of 192 decision-table partitions;
- 25 malformed top-level totality partitions;
- three end-to-end abstract transition traces;
- 2,300 bounded reducer event applications;
- invariant traceability for `INV-001` through `INV-015`.

None is evidence that a production broker, journal, executor, observer or isolation boundary exists.

## 14. Test obligations

Positive tests:

- exact stageable workspace write through commit/JOIN;
- bounded exact human approval;
- known-success external effect with reconciliation;
- attenuated delegation with conserved budget;
- fresh material digest after a permitted reflective update.

Negative/adversarial tests:

- unknown effect, scope expansion, explicit deny, stale/replayed/revoked capability, binding mismatch, budget exceed, D2 violation, missing telemetry, unbounded request;
- capability/approval replay and homoglyph/hidden-term contract changes;
- tainted-data egress, policy/registry rollback and manifest/binary mismatch;
- delegation fan-out/depth/cycle and cross-agent budget laundering.

Concurrency tests:

- two dispatchers consume one nonce;
- two children reserve the same parent budget;
- stale executor races a newer fencing epoch;
- writer races quiescence/seal/postcheck;
- registry or revocation changes between decision and dispatch.

Fault tests:

- crash before, during and after atomic durable dispatch;
- partial/forked journal, lost acknowledgement and rollback attempt;
- external success with lost response (`UNKNOWN_OUTCOME`);
- missing heartbeat/event, observer crash and corrupt receipt;
- compensation known failure/residual effect.

The reference suite covers a schema-valid admission→issuance→consume chain, 13 modeled stageable transitions and 485 executed assertion instances across negative/property checks, including typed D2 classes. It does **not** claim exhaustive coverage of every combined policy/state partition. Unbounded paths, payloads, concurrency schedules and external systems require boundary/property/fuzz/mutation and implementation fault tests.

## 15. Residual risks and unsupported claims

- The reference evaluator assumes normalized trusted facts and does not verify signatures or clocks.
- Python purity and test coverage do not prove non-bypassability or durable crash consistency.
- The exact authoritative semantics of project-specific identifiers remain provisional.
- An immutable local hash chain without witness cannot prove anti-rollback.
- Container/shared-kernel and covert-channel risks remain outside Level 3 proof.
- Human comprehension is fallible even with a valid receipt.
- External systems can produce unknown or irreversible outcomes.
- All numeric limits are profile calibration inputs, not universal constants.
- Runtime isolation, actual skill set, trusted runtime receipts, independent witness/observer and technical implementation evidence are absent.

## 16. Definition of Done

`DECLARED` / `SPECIFIED` requires:

- hierarchy/precedence and dependent authority meet defined;
- pure total decision and reason codes;
- common, stageable, external and compensation transitions;
- failure/retry/recovery/revocation semantics;
- schemas, declared finite partitions/mutations, bounded exploration and resolved traceability passing, with any unexercised partition explicitly listed rather than implied complete.

`IMPLEMENTED` requires, in addition:

- non-bypassable broker/executor PEPs and separate principal envelopes;
- cryptographic verifier, exact capability store and durable serializable journal;
- downstream fencing, monotonic budgets/counters and anti-rollback mechanism;
- quiescent seal/independent postcheck and external reconciliation;
- authoritative unsampled event/receipt pipeline;
- conformance and crash/concurrency tests in an exact named environment.

`VERIFIED` requires, in addition:

- independent evidence for every claimed control and environment;
- runtime attack/fault tests and receipt/event reconciliation;
- demonstrated physical/manifest/policy/capability subset invariants;
- proof evidence appropriate to durability/fencing/anti-rollback claims;
- explicit authorized residual-risk disposition.

Current status remains `SPECIFIED / NOT_IMPLEMENTED / SPECIFICATION_MODEL_TESTED / NOT_ATTESTED / NOT_READY` within `FORMAL_SPECIFICATION_AND_PURE_REFERENCE_MODEL_ONLY`.

## 17. Source-versus-new traceability

| Topic | Corpus basis | V0 resolution/addition |
|---|---|---|
| Policy precedence and decision scope | `metaprompt-harness-levels-0-5-ru.md:262-281` | Ordered pure/total decision table and finite partitions |
| Single-use bounded capability | `HARNESS_ACTIVATION_DIFF.md:130-152`, `HARNESS_ACTIVATION_DIFF.md:213-222` | Exact digest/principal/audience/purpose/lineage bindings and replay/freshness rules |
| Execution components not implemented | `HARNESS_ACTIVATION_DIFF.md:183-210`, `HARNESS_ACTIVATION_DIFF.md:226-268` | Explicit model/runtime separation and implementation blockers |
| Journal/counters | `HARNESS_ACTIVATION_DIFF.md:293-340`, `security.md:75-91` | One atomic dispatch record; RAM/JSONL rejected as durable evidence; fencing epochs |
| Postcheck and observer | `HARNESS_ACTIVATION_DIFF.md:345-391`, `security.md:39-46` | Quiesce → immutable seal → independent postcheck → commit |
| Per-contract approval vs machine JOIN | `HARNESS_ACTIVATION_DIFF.md:396-428` | Approval as exact predicate; JOIN remains per iteration |
| Retry and D2 | `HARNESS_ACTIVATION_DIFF.md:438-469` | Provisional controller-visible N+2 operational bound |
| External unknown outcome and compensation | `metaprompt-harness-levels-0-5-ru.md:268-281` | Quarantine/no auto-retry; compensation as fresh transaction |
| Persistence/evidence channel risks | `security.md:101-152` | Explicit N→N+1 information/control admission and registry pinning |
| Согласованная V0 semantics | Новое требование V0; source authority не заявляется | Minimal profile, immutable registry snapshot, honest evidence status |

The exact local state names, reason-code taxonomy, typed scope comparison and JSON reference record are new V0 constructs. They operationalize corpus requirements without claiming to be the authoritative definitions of the provisional project terms.

## Activation gate

Policy activation MUST use the complete-content, externally verified activation rule in `04_FORMAL_CORE_AND_INVARIANTS.md`: signed/fresh/non-revoked registry or compiler provenance, generation and rollback floor are part of the gate. An advertised policy digest cannot stand in for content or provenance, and a material approval-class, physical-ceiling or risk-control change requires a new activation.

## Iteration claim and contract resolution

Before evaluation, the durable controller MUST claim the unique iteration slot by CAS on `(authority_domain_id, root_contract_digest, journal_lineage_id, iteration)`. Its digest is an immutable binding in the decision, capability, dispatch, receipt/event, recovery and `JOIN` records; recovery reuses neither an expired nor a differently owned slot. The evaluator consumes one resolver-verified, full schema-valid loop-contract object—not a caller projection—and recomputes its complete-content digest excluding `contract_digest`. Lifecycle/revocation, audience and human confirmation, artifact bindings, D2, aggregate budget vector and selected manifest postcheck/independent-observer requirements must all match exactly before `ALLOW`.

A delegated capability MUST carry immutable `parent_delegation_clause_digest`: the canonical digest of one exact parent `DELEGATE(PRINCIPAL, SPAWN|BIND)` row. The trusted parent envelope resolves that row by digest and requires exact target principal, selector reference/canonical value, typed facet/constraint coverage, child-effect attenuation and depth/fan-out limits. Issue and dispatch recheck that digest through the existing signed delegation and parent-status records; a coherent rehash of a retargeted row remains rejected.
