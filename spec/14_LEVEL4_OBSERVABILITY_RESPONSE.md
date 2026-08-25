# 14 — Level 4: наблюдаемость, обнаружение и реагирование

## 1. Цель, claim boundary и статус

Level 4 обеспечивает причинно связанное evidence о решениях и эффектах, детерминированное обнаружение известных нарушений, статистические сигналы отклонений и проверяемое реагирование. Он **не** выдаёт полномочия, не заменяет L0–L3 и не обещает обнаружить все неизвестные аномалии или covert channels.

Статус-вектор этого artifact: `specification=SPECIFIED`, `runtime=NOT_IMPLEMENTED`, `evidence=SPECIFICATION_MODEL_TESTED`, `runtime_attestation=NOT_ATTESTED`, `overall=NOT_READY`, `scope=FORMAL_SPECIFICATION_AND_PURE_REFERENCE_MODEL_ONLY`.
Canonical status marker: `Q94-STATUS-VECTOR: specification=SPECIFIED; runtime=NOT_IMPLEMENTED; evidence=SPECIFICATION_MODEL_TESTED; runtime_attestation=NOT_ATTESTED; overall=NOT_READY; scope=FORMAL_SPECIFICATION_AND_PURE_REFERENCE_MODEL_ONLY`.
Схема и reference tests проверяют только specification model; production event sources, storage, alerts, runbooks, SLO и incident evidence остаются runtime-absent и не являются runtime conformance evidence.

Normative words `MUST`, `SHOULD`, `MAY` понимаются по RFC 8174. Русское «обязан» эквивалентно `MUST`.

## 2. Assets, adversaries, assumptions и trust boundaries

Защищаются: causal history решения; exact bindings; capability/budget state; actual-effect evidence; confidentiality telemetry; возможность containment/reconciliation; audit accountability.

Adversaries включают malicious/compromised agent output, forged self-report, compromised connector, telemetry suppression/flooding, insider, registry/policy substitution, clock faults, partial writes и collector/storage outage. Hash-chain writer или collector не считается независимым witness самому себе.

Trust boundaries:

- agent/model events — только `UNTRUSTED_DIAGNOSTIC`;
- broker/PEP авторитетен для normalized request, derived/authorized envelope, decision и obligations;
- durable ledger/capability store — для reservation/spend/consume/revoke/fence;
- executor/TCB supervisor — для dispatch, process/resource/blocked-attempt facts;
- mediated connector — для acknowledged external outcome в пределах connector protocol;
- independent observer/postcheck — для snapshot/observed/verified facts, но не authorization;
- approval service — для issue/use/revoke approval receipt;
- signed control plane/registry — для activated material configuration;
- collector/metrics/tracing backend — transport/projection, не source of truth.

## 3. Нормативный event model

### 3.1. Event-per-transition

Каждый safety-relevant LTS transition `MUST` создать canonical event через transactional outbox в той же durability boundary, что authoritative state transition. Один summary после итерации недостаточен. Mandatory safety events не сэмплируются.

Минимальные семейства:

| Family | Authoritative emitter | Terminal/completeness rule |
|---|---|---|
| normalize/classify/decide | PEP | каждый admitted or denied request имеет decision |
| budget reserve/release/spend | ledger | reserve имеет spend/release/quarantine |
| capability issue/consume/revoke/expire | capability store | issued capability имеет ровно один terminal state |
| dispatch/attempt/block | executor/TCB | consume+dispatch связан с outcome или `UNKNOWN_OUTCOME` |
| execute/quiesce/seal/postcheck/commit/JOIN | executor, snapshotter, observer, controller | stageable commit невозможен без seal+postcheck chain |
| external acknowledge/reconcile | connector/reconciler | unknown удерживает quarantine и запрещает auto-retry |
| approval/material change | approval/control plane | future-facing bindings invalidated atomically |
| contain/recover/compensate/close | IR/reconciler | closure требует evidence bundle и regression ID |

### 3.2. Canonical envelope

`event-envelope.schema.json` задаёт форму. Semantic validator обязан проверять cross-object invariants. Envelope содержит:

- identity/causality: schema/event/source IDs, per-emitter monotonic sequence, trace/run/contract/session/iteration/call, parent event/call/delegation lineage и LTS before/after;
- provenance: emitter principal/role/component/version/digest/trust domain/isolation profile/instance attestation и конечный `authoritative_for` enum;
- exact bindings: request, tool, manifest, policy, contract, capability, approval, model/prompt/context/registry digests; никогда raw capability/credential;
- distinct stage vectors: requested, manifested, derived, authorized, attempted, blocked, actual/committed, observed, verified; absent stage обозначается явно, не пустым implicit success;
- decision/obligations: `ALLOW|DENY|REQUIRE_HUMAN|STOP`, bounded reason codes и obligation terminal states;
- budgets: typed before/reserved/spent/released/after with lineage scope;
- time/outcome: wall and monotonic time, clock source/uncertainty, `KNOWN_SUCCESS|KNOWN_FAILURE|UNKNOWN_OUTCOME|NOT_APPLICABLE`, retry eligibility;
- evidence: snapshot/seal/postcheck/effect/approval/containment/reconciliation/durable-store receipt digests;
- information governance: confidentiality, integrity, provenance/taint, purpose, retention class/expiry/legal hold, redaction/access-policy ID;
- integrity/completeness: canonical payload digest, previous-event hash, service signature/key ID, source sequence, durable ack, sampling=`NONE` for safety, export state.

Timestamps не определяют causal order. Для этого используются source sequence, parent links, ledger transaction/epoch и reconciliation edges.

### 3.3. Completeness invariants

- `L4-INV-01`: каждый dispatch имеет один terminal known outcome либо `UNKNOWN_OUTCOME` с open reconciliation.
- `L4-INV-02`: каждый issued capability заканчивается consumed, revoked или expired; consumed не возвращается в fresh.
- `L4-INV-03`: каждый stageable commit связан с quiescence, immutable seal, independent postcheck и controller JOIN.
- `L4-INV-04`: agent self-report не продвигает authoritative state.
- `L4-INV-05`: `committed ⊆ authorized`; uncertain committed effect вызывает containment/quarantine.
- `L4-INV-06`: missing/corrupt mandatory receipt для risky action блокирует dispatch/JOIN.
- `L4-INV-07`: logs, metrics и traces — projections одного canonical stream, не независимые truths.

### 3.1. Semantic validation and authoritative chain

Schema-valid shape не делает event authoritative. Trusted semantic validator MUST проверить externally anchored emitter identity/role/component/key, canonical signed payload, signature/key/revocation/freshness, monotonic chain/epoch и event-type obligations. The signed payload digest MUST be computed over the canonical event bytes, and the signature MUST cover the event digest, source sequence and previous-event link; caller-supplied event/previous/witness/authority digests or a worker self-asserting `OBSERVER`/`PEP` role are invalid. Effect stages кодируются как `KNOWN(entries) | UNKNOWN(reason) | NOT_APPLICABLE | ABSENT(reason)`, а не неоднозначные пустые arrays.

`COMMIT/JOIN` допускаются только если `committed ⊆ authorized`, attempted excess находится только в `blocked`, и decision/authorized-envelope/capability/dispatch/seal/postcheck/receipt digests совпадают. Stageable success требует `writers_quiesced=true`, immutable snapshot digest и independently attested passed postcheck. `anti_rollback_proven=true` допустимо только с verified external anchor/witness claim; локальная self-assertion запрещена. External `UNKNOWN_OUTCOME` требует reconciliation state, mandatory evidence и no automatic retry. A terminal reconciliation outcome requires a trusted-store externally verified `EXTERNAL_RECONCILIATION` receipt bound to transaction, decision, capability, envelope, contract/lineage, dispatch/idempotency, exact object identity, epoch, connector evidence and chain; a caller-supplied digest or boolean is not evidence. Любая inconsistency ведёт в `QUARANTINE`, и reducer не принимает JOIN. These are specification obligations only: runtime remains `NOT_IMPLEMENTED` and `NOT_ATTESTED`.

**Q-59 normative anchor (manifested/physical containment).** For every safety
event, the validator MUST establish `committed ⊆ authorized ⊆ manifested ∩
physical`; an attempted excess is admissible only when it is explicitly
present in `blocked`. Excess that is unblocked, committed, or omitted is a
containment failure and MUST force `QUARANTINE`/no `JOIN`.

Every stage entry is a tagged record with `object_id`, `object_digest` and authority-envelope digest. Semantic validation reconstructs one same-object chain from dispatch through attempted/actual, seal or external receipt, postcheck/reconciliation, commit and JOIN. Empty arrays, self-asserted equality booleans, unrelated receipt digests or an object substitution at any edge are not evidence and MUST prevent JOIN.

The emitter verifier record is an external source of truth for principal, role, component, key, freshness and revocation; `trusted_identity_verified=true` without that record is only an untrusted claim. `COMMIT`/`JOIN` MUST reject any canonical digest or source-chain substitution and retain the transaction in `QUARANTINED/RECONCILING`.

### 3.2. Stable normative requirement catalog

| ID | Normative obligation | Enforcement point / owner | Failure semantics | Test / evidence |
|---|---|---|---|---|
| `L4-REQ-001` | Every authoritative safety event MUST resolve an externally verified emitter identity, role, component and current non-revoked key record. | Authoritative emitter verifier + observer | Reject event; risky transition remains stopped or quarantined. | `T-Q41-EVENT-EMITTER-ROLE-FORGE`; `EV-R4-Q41-001` |
| `L4-REQ-002` | Canonical signed event bytes MUST bind event digest, source epoch/sequence and predecessor link; substitution, fork, gap, rollback or stale key MUST fail. | Event-chain verifier + durable evidence store | Reject chain advance; emit integrity incident; no JOIN. | `T-Q42-EVENT-DIGEST-SUBSTITUTION`; `EV-R4-Q42-001` |
| `L4-REQ-003` | `COMMIT` and `JOIN` MUST resolve typed same-object dispatch, seal/external receipt and postcheck/reconciliation evidence with exact authority bindings. | Observer + commit/JOIN authority | Keep transaction quarantined; no commit/JOIN. | `T-Q49-COMMIT-TYPED-EVIDENCE-FORGE`, `T-Q49-JOIN-TYPED-EVIDENCE-FORGE`; `EV-R4-Q49-001` |

These are executed specification-model regressions only. Runtime evidence remains `ABSENT/UNTESTED`.

## 4. Storage, integrity, sampling и clocks

Safety source использует локальный bounded durable spool и export acknowledgements. При downstream outage работа может продолжаться только в профиле, где spool сохраняет полный mandatory stream и запас доказан; exhaustion до risky dispatch означает STOP. Gap, duplicate, reorder, bad signature, clock uncertainty, fork и cross-source divergence детектируются.

Canonical records имеют stable canonicalization version, per-source sequence, previous hash and service signature. Внешний witness/anchor нужен для anti-truncation/anti-rollback claim. Без него пакет заявляет только обнаружение модификации внутри доступной цепочки; compromised writer может удалить/откатить хвост.

Safety events `sampling=NONE`. Diagnostic spans MAY sample по versioned policy. Retention/legal basis/durations задаёт deployment profile; отсутствующие значения — blocker, не guessed default.

## 5. Privacy и cardinality

Raw prompts, args, outputs, secrets и PII не попадают в metrics и default logs. Exact binding digest хранится в restricted ledger/evidence. Plain SHA low-entropy value не является anonymization: для analytics применяется purpose/tenant-scoped keyed token. Sensitive payload отделяется как encrypted access-controlled object; immutable non-sensitive audit skeleton может пережить crypto-shred payload key по retention policy.

Metric labels MUST быть finite versioned allowlists: `environment`, `component`, bounded `event_type`, `decision`, bounded `reason_code`, `effect_class`, `outcome_class`, `severity`, `isolation_profile`, coarse `data_class`; logical tool operation допустим только при finite registry. IDs, hashes, nonces, signatures, paths, endpoints, principals, tenant/user values, args/outputs и arbitrary loop signatures — только restricted logs/traces/evidence. Trace ID MAY быть exemplar, не label.

## 6. Logs, metrics, traces и evidence

| Projection | Назначение | Запрет |
|---|---|---|
| Canonical signed events | audit, state reconstruction, reconciliation | sampling mandatory lifecycle |
| Restricted logs | human investigation of bounded/redacted fields | raw secret/default payload dump |
| Metrics | bounded aggregate health/response/quality/cost | high-cardinality identity/binding fields |
| Traces | causal navigation; safety events linked unsampled | считать span источником authorization/actual truth |
| Evidence objects | sealed snapshots/receipts/reports by digest | интерпретировать arbitrary agent prose как authority |

## 7. Detection → response catalog

`threshold` ниже — rule type, не выдуманное число. Каждый deployment profile обязан задать owner, query implementation, calibration where statistical, runbook version и paging SLA. `0 tolerated` — hard invariant, а не SLO error budget.

| ID | Signal / query pseudocode | Threshold/baseline; severity; FP | Owner; automatic action | Escalation/runbook; closure evidence |
|---|---|---|---|---|
| SAFE-001 | `actual_or_committed !<= authorized` | 0; Critical; no benign FP after canonicalization | Security + PEP; freeze, kill, revoke lineage, snapshot | Incident commander; reconcile every effect, sealed timeline, regression |
| SAFE-002 | attempted effect/scope outside capability | per event deny; burst profile-statistical; High | PEP/TCB; block; repeated → freeze | Security; denied request + TCB receipt |
| CAP-001 | replay/expired/wrong subject/audience/purpose/digest/nonce | 0 accepted; Critical if accepted, High attempt | Capability store; deny/revoke | Security/control plane; consume/revoke ledger and test |
| BUD-001 | underflow, nonconservation, CAS divergence | 0; Critical/High | Ledger; stop lineage, fence writer | Runtime/SRE; reconciled before/reserve/spend/after |
| BUD-002 | fragmented reservations/slope anomaly | profile-calibrated; Medium/High; workload FP possible | Ledger/SRE; throttle or freeze, never allow | Service owner; workload comparison and released escrows |
| JRN-001 | sequence gap/fork/replay/rollback/fence mismatch | 0 accepted; High/Critical by exposure | Ledger/evidence owner; quarantine/fence | Security/SRE; preserved branches, anchor/reconcile receipt |
| TEL-001 | mandatory event missing/corrupt/bad signature | 0 for risky chain; High | SRE/PEP; block dispatch/JOIN when completeness unprovable | SRE/security; gap root cause, spool/repair and regression |
| TEL-002 | spool/collector/export exhaustion or heartbeat loss | bounded spool threshold from profile; High before loss | SRE; stop risky work at safety margin | Capacity/runbook owner; durable ack and recovery evidence |
| TCB-001 | forbidden file/syscall/process/device/proc/ptrace/FD | exact profile allowlist; High/Critical | Runtime supervisor; block/kill/freeze | Platform security; TCB event + snapshot + negative test |
| NET-001 | IPv4/IPv6/DNS/UNIX/loopback/metadata undeclared flow | 0; High/Critical | Network TCB; block/kill | Platform/network security; packet/socket evidence and profile repair |
| DATA-001 | tainted data to unauthorized sink; missing declass/endorse | 0; Critical/High | Flow PEP; deny/quarantine payload | Privacy/security; lineage, access review, deletion/containment receipt |
| SUP-001 | new/mismatched tool/image/model/prompt/context/registry/policy digest | exact-binding mismatch; High | Resolver/PEP; deny/revoke/rollback activation | Supply-chain owner; provenance and invalidation chain |
| VER-001 | concurrent writer, seal mismatch, postcheck failure/TOCTOU | 0 stageable commits; High | Controller; discard/quarantine, prohibit JOIN | Runtime/assurance; writer revocation + seal/postcheck evidence |
| DEL-001 | fan-out/depth/node/concurrency/cycle/escrow violation | hard profile bounds; High | Delegation broker; deny child/freeze subtree | Control-plane security; graph/budget snapshot |
| REF-001 | persistent/control-plane change without activated change set | 0; High | Control plane; freeze/revoke dependent material | Governance/security; before/after + invalidation receipts |
| LOOP-001 | exact canonical call/sequence fingerprint repeats | contract-defined hard repetition bound; Medium/High | Controller; circuit-break/STOP | Service owner/human; trace, reason, revised test/contract |
| COST-001 | token/spend/call/latency slope drift | calibrated statistical baseline; FP from workload shift | SRE/service; warn/throttle/freeze; never grants | Service/finance; calibration and disposition report |
| DENY-001 | denied-call/diagnostic flood | calibrated rate + exact source limits; Medium/High | PEP/SRE; rate-limit untrusted diagnostics, isolate principal | Security; preserve authoritative safety events |
| OUT-001 | `UNKNOWN_OUTCOME` or reconciliation deadline breach | immediate quarantine; profile deadline for page; High | Connector/reconciler; no retry, lock idempotency key | Connector/resource owner; authoritative reconciliation receipt |
| LIFE-001 | cleanup/persistence/fresh-session receipt absent | 0 next risky iteration; High | Supervisor; block next iteration/quarantine residual | Platform owner; lifecycle and absence/presence scan evidence |
| PRIV-001 | secret/PII canary, unauthorized telemetry access, retention/delete fail | 0 disclosure; High/Critical | Privacy/SRE; quarantine export/revoke access | Privacy incident; access log, deletion/crypto-shred proof |
| TIME-001 | clock rollback/unsynced; expiry unknowable | exact uncertainty ceiling per risk profile; High | PEP; use sequence, stop expiry-sensitive action | Platform/SRE; clock repair and revalidation |
| BG-001 | break-glass request/activation/expiry/over-scope | every activation pages; outside ceiling 0; Critical | PEP/security; deny or auto-expire/revoke | Incident/governance; dual receipts + mandatory postmortem |
| QUAL-001 | calibrated live quality/drift signal | statistical confidence/profile; no safety authority | Quality owner; investigate/canary rollback | Offline benchmark owner; paired report and reviewed baseline decision |

False positives may delay work but MUST NOT be “fixed” by implicit allow. Statistical detector MAY freeze/escalate; it MUST NOT convert `DENY/UNKNOWN` into `ALLOW`.

## 8. SLI/SLO boundary

No error budget applies to: unauthorized committed effect; accepted replay; authority/delegation amplification; risky dispatch/JOIN without mandatory evidence; unauthorized secret disclosure; break-glass outside ceiling; accepted ledger rollback. Один случай — incident и readiness invalidation.

Profile-defined SLI/SLO MAY cover central export/query completeness and latency, gap-detection latency, alert availability, containment/reconciliation latency, trace joinability, operational availability, redaction/deletion timeliness, cost and calibrated quality. Mandatory source evidence completeness remains per-call invariant; only replication/query latency has availability budget.

## 9. Incident and recovery lifecycle

`DETECT → AUTO-CONTAIN → PRESERVE → RECONCILE → RECOVER or AUTHORIZE COMPENSATION → CLOSE → POSTMORTEM → REGRESSION TEST`.

Containment scope is minimal but sufficient: principal, capability, contract, session, delegation subtree, connector or registry version. Available actions: deny, revoke, stop new dispatch, fence/freeze writer, kill process tree, disable route, snapshot/quarantine, preserve evidence. Compensation is a fresh manifested, budgeted and authorized effect.

Closure is not “alert cleared”. Bundle includes triggering events, containment receipts, revoked bindings, immutable snapshot digest, causal timeline, actual-effect reconciliation, security/privacy impact, recovery authorization, residual effect, postmortem and new regression/test-to-invariant link.

## 10. Failure, crash, retry and revocation semantics

- Crash before durable transition: no dispatch authority exists; reservation is safely releasable by serializable recovery.
- Crash after durable consume/dispatch with no authoritative outcome: `UNKNOWN_OUTCOME`, escrow/capability quarantined, no automatic retry.
- Collector outage with durable local coverage: profile MAY continue until precomputed safety margin; otherwise STOP.
- Missing observer/postcheck evidence: no commit/JOIN.
- Revocation after dispatch: future calls blocked; in-flight effect killed where safe, otherwise reconciled; historical receipt remains immutable.
- Clock uncertainty: sequence remains causal; expiry-sensitive risky action stops.

## 11. Tests и expected evidence

| Test IDs | Test | Oracle/evidence |
|---|---|---|
| `T-L4-SCHEMA-*` | valid/invalid envelope, unknown field, event-type payload partitions | validator report; rejected fixtures |
| `T-L4-LIFE-*` | every legal LTS path and every missing/duplicate lifecycle edge | transition report; completeness graph |
| `T-L4-CRASH-*` | crash around reserve/consume/dispatch/outcome/seal/postcheck/commit/JOIN | no replay/silent effect; reconciliation state |
| `T-L4-SPOOF-*` | agent forges allow/actual/postcheck | event remains diagnostic and cannot advance state |
| `T-L4-INTEGRITY-*` | mutate/truncate/reorder/duplicate/fork/key rotation | deterministic alert; limited claim without witness |
| `T-L4-PIPE-*` | backpressure, disk full, spool exhaustion, clock skew, partition | bounded fail-closed transition and recovery receipt |
| `T-L4-CARD-*` | fuzz IDs/hashes/paths/args/signatures | finite series budget; no forbidden label |
| `T-L4-PRIV-*` | PII/secret canaries, cross-tenant access, expiry/hold/delete | raw bytes absent; access/delete evidence |
| `T-L4-ALERT-*` | positive and negative fixture for every detector/runbook | expected severity/action; idempotent scoped containment |
| `T-L4-GAMEDAY-*` | registry poisoning, egress, TOCTOU, telemetry suppression, unknown connector | closure bundle and incident→test link |

## 12. DoD, traceability и residual risks

`DECLARED`: envelope, emitter authority, completeness rules, detector catalog, failures/tests/evidence are versioned. `IMPLEMENTED`: authoritative sources/outbox/storage/projections/alerts/runbooks/retention/access control are deployed in an exact profile and all conformance/fault tests pass. `VERIFIED`: applicable finite lifecycle properties machine-checked, deployed implementation conformance attested, response game days passed and continuous completeness/alert evidence exists. Schema/prose review alone never reaches `VERIFIED`.

Source coverage: historical event/metric/alert sketches are preserved but narrowed; per-transition stream, emitter ownership, privacy/cardinality, completeness, SLO boundary and closure bundles are new normative requirements derived from `metaprompt…md:283–302` and gaps in `HARNESS_ACTIVATION_DIFF.md:293–325`/DOCX `#p0641–p0648`.

Residual risks: compromised host/writer without independent anchor; unobservable external/covert effects; semantic leakage; telemetry backend compromise; detector false negatives; human/IR error. Concrete topology, backend, retention, jurisdiction, RTO/RPO, owners and numerical SLO remain `OPEN_PROFILE`.

## Authenticated host and causal records

A heartbeat is accepted only when an external record authenticates host, instance, session, epoch and exact next sequence. Recovery requires a signed, fresh/non-revoked record for the fenced host/session, complete orphan inventory and recovered set digests, cleanup and absence of residue/stale writers; a caller string or boolean never clears the gate. Event and receipt emission advances the durable source/epoch/sequence/predecessor chain rule in `04_FORMAL_CORE_AND_INVARIANTS.md`; gap, fork, replay, reorder, reset and truncation quarantine rather than infer success.
