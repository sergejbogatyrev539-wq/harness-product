# 15 — Level 5: human control и governance

## 1. Цель, граница claim и статус

Level 5 обеспечивает понятное человеку, exact-bound и проверяемое governance-решение для уже физически ограниченного действия. Человек не oracle, не catch-all и не заменяет L0–L4, formal verification или postcheck.

Human approval:

- является аутентифицированным evidence выполнения admission obligation;
- не является lattice join `⊔` и не объединяет полномочия;
- не является controller `JOIN`, завершающим транзакцию после effect/postcheck;
- не может расширять immutable physical/platform ceiling;
- не делает `UNKNOWN/TOP` понятным или разрешённым.

Статус-вектор этого artifact: `specification=SPECIFIED`, `runtime=NOT_IMPLEMENTED`, `evidence=SPECIFICATION_MODEL_TESTED`, `runtime_attestation=NOT_ATTESTED`, `overall=NOT_READY`, `scope=FORMAL_SPECIFICATION_AND_PURE_REFERENCE_MODEL_ONLY`.
Canonical status marker: `Q94-STATUS-VECTOR: specification=SPECIFIED; runtime=NOT_IMPLEMENTED; evidence=SPECIFICATION_MODEL_TESTED; runtime_attestation=NOT_ATTESTED; overall=NOT_READY; scope=FORMAL_SPECIFICATION_AND_PURE_REFERENCE_MODEL_ONLY`.
Approval service/UI/PKI/role directory/revocation/break-glass остаются не реализованными; specification-model tests не являются runtime conformance evidence.

## 1.1. Stable normative requirement IDs

These IDs are the stable anchors for the controls below; later prose references the ID instead of restating its rule.

| ID | Normative obligation | Enforcement point / owner | Failure semantics | Test / evidence |
|---|---|---|---|---|
| `L5-REQ-001` | Confidentiality, integrity, provenance, taint, purpose and retention MUST propagate through data/control dependencies; declassification and endorsement require distinct exact-bound capabilities. | Flow PEP + capability issuer + approval service | Deny label/sink transition; quarantine inconsistent evidence. | `T-RECEIPT-PRIVACY-LIFECYCLE`, `T-AUTHORITY-TYPED-DECISION-RESULT`; `EV-SCHEMA-CONFORMANCE` |
| `L5-REQ-002` | Bind approval to the exact normalized request, derived effect closure, envelope and non-human ceiling. | Approval service + broker PEP | Reject receipt; no capability or dispatch. | `T-AUTHORITY-CORRELATED-NO-CROSS-PAIR`; `EV-NEGATIVE-MUTATIONS` |
| `L5-REQ-003` | Enforce the discriminated approval lifecycle, one-time activation and approval clearing on modification. | Approval service + durable journal | Reject stale/replayed transition; clear approval. | `T-APPROVAL-LIFECYCLE-VALID`; `EV-CAPABILITY-LIFECYCLE` |
| `L5-REQ-004` | Require a trusted service signature and verifier result bound to the complete canonical receipt. | Receipt verifier + broker PEP | Reject forged/unverified receipt. | `T-APPROVER-SIGNATURE`; `EV-NEGATIVE-MUTATIONS` |
| `L5-REQ-005` | Treat material payload/binding changes as invalidating future approval and capability. | Digest resolver + broker/executor PEP | Re-admit; revoke stale approval/capability. | `T-ATTESTATION-BINDING`; `EV-NEGATIVE-MUTATIONS` |
| `L5-REQ-006` | Render the complete material payload through an accessible, canonical, anti-confusable trusted presentation. | Trusted approval UI owner | Approval unavailable; request remains stopped. | `T-HUM-L5-PRESENTATION-001`; runtime evidence `ABSENT` |
| `L5-REQ-007` | Require comprehension evidence and homogeneous, fatigue-controlled batching without implying infallibility. | Approval workflow owner | Reject incomplete comprehension/batch receipt. | `T-HUM-L5-COMPREHENSION-001`; runtime evidence `ABSENT` |
| `L5-REQ-008` | Enforce distinct authenticated SoD/quorum and break-glass dual control inside the immutable ceiling. | Approval service + role directory | Reject shared identity/session/group or insufficient quorum. | `T-ORDINARY-QUORUM-TWO-POSITIVE`, `T-ORDINARY-QUORUM-ONE-AUTH-SEMANTIC`, `T-ORDINARY-QUORUM-SHARED-SESSION-SEMANTIC`; `EV-NEGATIVE-MUTATIONS` |
| `L5-REQ-009` | Keep operational approval distinct from residual-risk acceptance with named authority, scope and expiry. | Governance registry + named risk owner | Risk remains open; no agent acceptance. | `T-HUM-L5-RISK-001`; authorized receipt evidence required |
| `L5-REQ-010` | Check freshness, TTL, revocation, epoch and material digests before issue, activation and dispatch. | Broker/executor PEP + revocation service | Reject/revoke stale receipt or capability. | `T-APPROVAL-LIFECYCLE-VALID`, `T-CAPABILITY-REPLAY-AFTER-STOP`; `EV-CAPABILITY-LIFECYCLE` |
| `L5-REQ-011` | Emit immutable lifecycle/evidence records with exact binding, owner, status and retention/access controls. | Approval service + observer | Missing evidence blocks risky transition; incident/quarantine. | `T-EVENT-TRUSTED-EMITTER`, `T-EVENT-KNOWN-EMPTY-REJECT`; `EV-TRACEABILITY-EXECUTION` |

## 2. Assets, adversaries, assumptions и principals

Защищаются: informed decision; exact request binding; separation of duties; revocation; accountable risk ownership; emergency limits; confidentiality approval data.

Adversaries/failures: malicious agent prose, homoglyph/bidi/hidden terms, unit confusion, stale base state, fatigue/urgency, coercion/conformity, compromised approver/issuer, credential replay, collusion, UI truncation, clock/revocation outage и honest human error.

Distinct principals/roles: requester/proposer, human approver, named residual-risk owner, receipt-issuer service, broker/PEP, executor service, observer/postcheck, incident commander, audit/closure. Role labels без distinct authenticated principals не создают SoD.

## 3. Formal approval semantics (`L5-REQ-002`)

Пусть `q` — trusted-normalized immutable request, `D(q)` — derived transitive effect closure, `C` — non-human ceiling `physical ∩ manifest ∩ platform ∩ project ∩ contract`, `Aρ` — envelope, показанный человеку, `ρ` — receipt.

```text
ValidApproval(ρ,q,now,state) :=
    service_signature_valid(ρ)
 ∧ ρ.decision = APPROVE
 ∧ exact_request_and_presentation_hashes_match(ρ,q)
 ∧ all_material_runtime_digests_match(ρ)
 ∧ eligible_distinct_quorum(ρ)
 ∧ separation_of_duties(ρ)
 ∧ now in [not_before, grant_expires_at)
 ∧ revocation_epoch_fresh(ρ)
 ∧ activation_not_consumed(ρ)
 ∧ comprehension_obligations_met(ρ)
 ∧ D(q) ⊆ Aρ ⊆ C
 ∧ no UNKNOWN/UNBOUNDED/MISSING/STALE/MISMATCHED field

Kcall := narrow(C ∩ Aρ ∩ derived_call_scope ∩ remaining_budget)
ALLOW only if ValidApproval ∧ D(call) ⊆ Kcall ∧ no higher-precedence DENY
```

Один service-signed receipt MAY one-time activate immutable aggregate loop contract. Каждая итерация всё равно получает новую single-use call capability и machine controller JOIN. Новый human decision обязателен при material change, expiry/revocation, новом contract или выходе за envelope.

## 4. Approval receipt и lifecycle (`L5-REQ-003`, `L5-REQ-004`)

`human-approval-receipt.schema.json` определяет shape; semantic validator проверяет identities, quorum, exact digests, time/revocation and subset relations.

Receipt MUST содержать:

- receipt/schema ID, issuer service/key/signature и signature algorithm;
- approve/reject decision, bounded reason code, rationale/alternatives;
- request, presentation, contract, manifest, policy, tool/image, model, prompt/context/memory/registry/isolation hashes;
- effect vector, scopes, targets/principals/resources, flows/recipients, data labels;
- aggregate quantities, calls/iterations/time/spend/concurrency/delegation limits;
- before/after base, irreversibility, residual effects, compensation/recovery plan and uncertainty;
- requester, approver(s), risk owner where applicable, issuer, intended executor/observer, tenant and auth assurance;
- presentation renderer/version/locale, anti-confusable transform and comprehension-evidence digest;
- issued/not-before/activation-not-after/grant-expiry, nonce, single-use state, revocation epoch;
- notification, monitoring, postcheck, reconciliation, retention/purpose obligations.

Lifecycle:

```text
DRAFT → NORMALIZED → PRESENTED
→ REJECTED | REQUEST_MORE_EVIDENCE | CANCELLED | TIMED_OUT
→ MODIFIED(new request/presentation; prior approvals cleared)
→ APPROVED_PENDING_ISSUE → ISSUED → ACTIVATION_CONSUMED → ACTIVE_GRANT
→ COMPLETED | EXPIRED | REVOKED
```

Timeout/urgency is never consent. Appeal is a new review transaction and never edits historical receipt.

### 4.1. Authorizing versus non-authorizing records (`L5-REQ-003`, `L5-REQ-004`)

Receipt state machine is discriminated by decision. Только `APPROVE`, после successful trusted verification, может пройти `APPROVED_PENDING_ISSUE → ISSUED → ACTIVATION_CONSUMED → ACTIVE_GRANT → COMPLETED|EXPIRED|REVOKED`. `REJECT`, `MODIFY`, `REQUEST_MORE_EVIDENCE`, `CANCEL` и `TIMED_OUT` являются terminal/non-authorizing records и schema/semantic validator запрещает им `ISSUED`, `CONSUMED` или active grant. `MODIFY` создаёт новый request/presentation digest и очищает все предыдущие approvals.

Policy получает signed verifier result, а не human/agent booleans. Verifier проверяет service signature over complete canonical receipt, eligible distinct principals/sessions, requester/approver/executor separation, required quorum, authentication and comprehension evidence, exact envelope/bindings, nonce, time interval, revocation epoch/feed, unused activation и отсутствие material change. Повторная activation или любая stale/mismatched составляющая даёт `DENY/STOP`; ordinary approval не расширяет hard ceiling.

Authoritative verifier result MUST itself be signed and exact-bound to receipt digest, request/presentation/authorized-envelope/decision/contract/session/placement digests, approver identities and quorum, nonce, verifier identity, verification time, expiry and revocation epoch. PEP compares every field to current trusted state and atomically consumes the activation nonce with capability issuance; an agent-provided boolean or a valid receipt rebound to another request/session is non-authorizing.

## 5. Decision classes

| Condition | Required decision |
|---|---|
| Fully bounded, internal, reversible and policy-preauthorized low risk | machine allow + audit; profile MAY notify |
| Bounded stageable workspace mutation inside immutable approved loop contract | one pre-contract approval; per-iteration capability + machine JOIN |
| Known bounded external communication/mutation, sensitive data, credential use, persistent REFLECT/DELEGATE | pre-action approval; dual control for production/high sensitivity/blast radius/irreversibility |
| Injection/poisoning signal, stale receipt, digest mismatch, missing telemetry/postcheck | deny/freeze/revoke + security escalation |
| Unknown/unclassified/unbounded action, unmediated sink, hard-ceiling expansion | unconditional `DENY/STOP`; not human-overridable |
| Declared emergency inside pre-signed emergency profile | separate break-glass protocol |

Exact mapping to source R0–R6/S5 remains `PROVISIONAL/OPEN_PROFILE` because authoritative definitions were not found.

## 6. Trusted presentation and comprehension evidence (`L5-REQ-006`, `L5-REQ-007`)

Trusted control plane renders canonical payload; agent prose appears only as quoted untrusted context. Material terms cannot be collapsed or pre-checked. Screen MUST show:

- exact verb/action and immutable target ID plus human-readable name;
- per-step and aggregate worst-case bounds with canonical adjacent units;
- trusted before/after semantic diff and base digest;
- external recipients/channels and data sensitivity/purpose;
- irreversibility, residual effects and limits of compensation;
- delegation/reflection/control-plane changes;
- tool/model/manifest/policy/contract provenance/digests;
- uncertainty, why automation stopped, exact consequence of approval and safer alternatives.

Bidi controls/security identifiers are rejected or escaped with codepoints. Domains/principals show canonical form and stable ID. Color is not the only signal; keyboard and screen-reader path is required; locale-sensitive numbers/time are paired with canonical representation.

Material approval requires risk-class-specific teach-back about target, aggregate maximum, external/sensitive flow and reversibility. A checkbox alone is acknowledgement, not comprehension. Comprehension evidence records that the check occurred; it never proves infallible understanding.

Heterogeneous effects/targets MUST NOT be batch-approved. A homogeneous batch shows count, aggregate worst case and permits removing an item. Fatigue controls deduplicate/queue/escalate/STOP; they never auto-approve.

## 7. Separation of duties and disagreement (`L5-REQ-008`, `L5-REQ-009`)

- Agent/model MAY propose but MUST NOT approve, issue receipt, accept residual risk or execute external effect ambiently.
- High-risk requester does not count in approver quorum.
- Approver and executor are distinct; receipt issuer binds recorded decision but does not make it.
- Observer does not issue authority.
- Dual approval requires distinct eligible human principals, credentials and auth sessions; repeated click by one principal counts once.
- Break-glass requires incident/security authorizer and independent resource/service authorizer.
- Operational approval and residual-risk acceptance are different receipt types.
- Critical cannot be deferred; High cannot be accepted by agent/integrator; Medium needs named authorized human risk-owner receipt with identity, scope, rationale, compensating controls, TTL/expiry and review date.

`APPROVE + REJECT/TIMEOUT/REQUEST_MORE_EVIDENCE` fails quorum and yields STOP/pending. Second approver SHOULD submit independently without seeing first verdict. Conflict of interest causes recusal/substitution, not smaller quorum. Appeal uses higher-authority new transaction.

## 8. Material change, freshness and revocation (`L5-REQ-005`, `L5-REQ-010`)

Material fields include action/effects, scope/target/principal/tenant, data class/flow/recipient, budget/unit/time/concurrency/delegation, reversibility/compensation, tool/image/model/prompt/context/memory/adapter/manifest/policy/contract/registry/isolation digest, before-state base, approval class/quorum and presentation semantics. Only schema-designated telemetry-only fields MAY be non-material; agent does not decide equivalence.

Call narrowing inside approved envelope is allowed. Envelope modification creates a new request/hash and clears approvals, even when apparently narrower, so presentation remains exact.

Freshness/revocation is checked before receipt issue, contract activation, each capability issue and immediately before dispatch. TTL expiry, role/key/policy revocation, base-state drift, digest mismatch, uncertain clock or missing revocation feed causes STOP. Revocation after dispatch blocks future calls and triggers kill/freeze where safe; completed/unknown effect is reconciled and historical receipt remains immutable.

## 9. Break-glass (`L5-REQ-008`, `L5-REQ-011`)

```text
DISABLED → REQUESTED(exact incident/profile/scope)
→ FIRST_AUTHORIZED → SECOND_INDEPENDENT_AUTHORIZED
→ ACTIVATED → COMPLETED | EXPIRED | REVOKED
→ RECOVERY/RECONCILIATION → POSTMORTEM_CLOSED
```

Break-glass MUST:

- activate only a pre-signed minimal emergency profile inside immutable L0/platform ceiling;
- retain mediation, isolation, budgets, single-use capabilities, evidence and audit;
- bind incident, emergency-profile and target-set digests exactly; every break-glass authentication-evidence record MUST bind the same incident/profile/target-set tuple, and the verifier MUST reject any mismatch;
- require cross-domain quorum: at least one `INCIDENT_COMMANDER` or `SECURITY_AUTHORIZER` and at least one independent `RESOURCE_AUTHORIZER` or `SERVICE_AUTHORIZER`;
- bind operations, quantities, activation deadline and hard TTL;
- have no auto-renewal; each extension is a new dual decision;
- alert security/service/risk owners in real time;
- check revocation before dispatch; unknown in-flight outcome quarantines and never auto-retries;
- produce immutable audit, recovery/reconciliation and mandatory postmortem.

Changing the hard ceiling is a separate administrative deployment operation outside current agent contract; that contract terminates. Until enforcement/tests exist, `break_glass=DISABLED` and emergencies STOP.

## 10. Failure/crash/retry semantics and telemetry

Receipt-issuer crash before durable issue yields no receipt. After issue, unique nonce/activation state recovers durably. Concurrent activation permits at most one consumption. Missing role/revocation/time/signature/presentation evidence is fail-closed. Modification never inherits old approvals. Revocation race is resolved by serializable epoch checked at dispatch. Already external effect is not undone by deleting receipt; recovery/compensation is new authorized work.

Authoritative events: requested/presented/decision/issued/activation-consumed/rejected/modified/timed-out/revoked/expired/completed, SoD/quorum failure, stale/material change, comprehension obligation, break-glass lifecycle. Human rationale is privacy-controlled; metrics use bounded decision/reason/risk classes, never principal IDs or payload hashes as labels.

## 11. Tests and expected evidence (`L5-REQ-011`)

| ID family | Test/oracle | Expected evidence |
|---|---|---|
| `T-HUM-BIND-*` | mutate target/unit/budget/recipient/digest after presentation → no capability | presentation/request hashes + PEP reason |
| `T-HUM-PRESENT-*` | hidden field, truncation, bidi/homoglyph/unit fixture rejected/escaped; accessibility tree complete | canonical semantic render snapshot |
| `T-HUM-REPLAY-*` | first activation consumes, concurrent/second activation denied | durable consume/replay events |
| `T-HUM-TIME-*` | boundary at expiry; uncertain clock/feed for high risk stops | clock/revocation evidence |
| `T-HUM-REVOKE-*` | revoke before issue, issue/dispatch race, during execution, after commit | future dispatch blocked; in-flight reconcile trace |
| `T-HUM-SOD-*` | requester=approver, duplicate principal/session, ineligible role denied; distinct quorum accepted | auth/role/quorum record |
| `T-HUM-DISAGREE-*` | approve+reject/timeout/request-evidence creates no receipt | independent decision events |
| `T-HUM-MOD-*` | modify creates new hash and clears approvals | invalidation event |
| `T-HUM-CEILING-*` | valid signature outside L0/manifest still denied; UNKNOWN signed approval denied | hard-ceiling reason |
| `T-HUM-LOOP-*` | one contract activation, fresh call caps/JOINs; material N+1 expansion invalidates | contract/capability/JOIN chain |
| `T-HUM-BATCH-*` | heterogeneous batch rejected; fatigue does not alter default deny | presentation/queue events |
| `T-HUM-COMP-*` | required teach-back absent/failed → request evidence | comprehension obligation record |
| `T-HUM-RISK-*` | Critical/High acceptance invalid; incomplete/expired Medium receipt invalid | risk-owner validation report |
| `T-HUM-BG-*` | same principal twice, outside ceiling, expired TTL, missing alert/audit denied | dual authorization and postmortem evidence |

End-to-end expected chain: canonical request → trusted presentation → human auth decision → service-signed receipt → activation/capability → executor effect receipt → independent postcheck → machine JOIN → notification/revocation/closure.

## 12. DoD, ownership, traceability and residual risks (`L5-REQ-009`, `L5-REQ-011`)

Accountable functions: governance policy owner, resource/business owner, named risk owner, control-plane/approval-service owner, platform security, executor service owner, independent assurance/observer, privacy owner and audit/closure function. Concrete identities remain deployment input.

`DECLARED`: receipt semantics, presentation, SoD, lifecycle, failure and tests/evidence specified. `IMPLEMENTED`: trusted UI/service/identity/PKI/revocation/PEP bindings and accessibility are deployed; race/adversarial tests pass. `VERIFIED`: machine-checkable bindings/concurrency conform in exact environment and recurring governance/game-day evidence exists. Human comprehension itself is never “formally verified”.

Source coverage: aggregate approval, signatures and human gate ideas are preserved; distinctions among receipt/auth/signature/JOIN, material freshness, SoD/disagreement, trustworthy presentation, fatigue and break-glass are added from gaps at `HARNESS_ACTIVATION_DIFF.md:410–434,545–557`, `security.md:158–171` and `metaprompt…md:304–320`.

Residual risks: approver collusion/coercion/error; compromised identity/issuer/UI; semantic ambiguity despite canonicalization; accessibility/localization failures; alert overload. Open profile decisions include approval-class mapping, eligible roles, PKI, clock/revocation guarantees, TTL/quorum/fatigue/SLA, jurisdiction/retention and emergency profiles.

## Full-receipt approval binding

The signed full receipt MUST canonically project its effects, targets, budgets and flows into `approved_envelope`; its verifier recomputes that projection and binds it exactly to the live admission envelope. Compact admission facts are only a projection of that separately verified full receipt. Listed approvers and authenticated evidence have exact one-to-one set equality; each evidence record binds approver, subject, role, session and independence group, and the externally verified policy quorum is met. Count-only quorum, one evidence for two names, or shared session/group is rejection.

Human activation of a loop MUST bind the resolver-verified complete schema-valid loop-contract digest, not a summary or independently reconstructed subset. The trusted presentation and verifier compare the selected contract's audience, lifecycle/revocation, human-confirmation receipt, artifact bindings, D2 bound and aggregate budget vector exactly, and also require the selected manifest to require postcheck and an independent observer. Any mismatch, expiration or revocation invalidates approval and requires fresh admission.

For admission, `trusted.approved_envelope_digest == receipt.authorized_envelope_digest == canonical_digest(live_envelope)` MUST hold exactly. A schema-valid receipt or trusted record with a different digest is non-authorizing and requires fresh approval; a digest-shaped value is not an equivalence proof.
