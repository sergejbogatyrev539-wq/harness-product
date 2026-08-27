# 04. Формальное ядро и глобальные инварианты

## 0. Паспорт и граница утверждений

| Поле | Значение |
|---|---|
| Версия | V0 |
| `specification` | `SPECIFIED` |
| `runtime` | `NOT_IMPLEMENTED` |
| `evidence` | `SPECIFICATION_MODEL_TESTED` |
| `runtime_attestation` | `NOT_ATTESTED` |
| `overall` | `NOT_READY` |
| Scope | `FORMAL_SPECIFICATION_AND_PURE_REFERENCE_MODEL_ONLY` |
| Canonical status marker | `Q94-STATUS-VECTOR: specification=SPECIFIED; runtime=NOT_IMPLEMENTED; evidence=SPECIFICATION_MODEL_TESTED; runtime_attestation=NOT_ATTESTED; overall=NOT_READY; scope=FORMAL_SPECIFICATION_AND_PURE_REFERENCE_MODEL_ONLY` |
| Источник snapshot | `CORPUS_PACKET`, aggregate source SHA-256 `08a296ee00349eac64d13292e4d4c714d1de0cd412adca1c695ef5e5f92838e0` |

Этот документ задаёт одно общее ядро. Он не является доказательством безопасности реализации. Схемы могут доказать форму данных; чистая reference-модель и тестовые векторы могут проверить конечные разделы семантики; только conformance-испытания конкретного runtime могут дать implementation evidence.

Слова **MUST / MUST NOT / SHOULD / SHOULD NOT / MAY** понимаются в смысле RFC 8174: обязательное требование, обязательный запрет, рекомендуемое требование, рекомендуемый запрет и разрешённая опция соответственно. Русские «ДОЛЖЕН», «НЕ ДОЛЖЕН», «СЛЕДУЕТ», «НЕ СЛЕДУЕТ», «МОЖЕТ» эквивалентны им.

## 1. Термины и статусы определений

### 1.1. Принципалы и компоненты

| Термин | Нормативное значение |
|---|---|
| `agent` | Ненадёжный принципал, формирующий предложения и локальные вычисления. Агент не имеет ambient authority и не исполняет внешние эффекты от собственного имени. |
| `model` | Вероятностный вычислительный компонент агента. Его вывод считается недоверенным вводом. |
| `controller` | Владелец state machine: нормализует ход транзакции, вызывает policy decision, управляет состояниями и фиксирует `JOIN`. |
| `PEP` | Policy Enforcement Point, не обходная точка допуска конкретного effect call. Может быть частью controller/broker, но логическая роль отдельна. |
| `broker` | Принципал, разрешающий exact-bound вызов и посредничающий доступ к executor/gateway/секретам. |
| `executor` | Принципал, который выполняет допущенную операцию в собственном envelope. Его authority не наследуется агентом. |
| `model_gateway` | Broker-owned коммуникационный sink для обращения к внешнему поставщику модели. Это отдельный `COMMUNICATE`, а не сеть worker-а. |
| `observer/postcheck` | Принципал, независимо наблюдающий sealed state и выпускающий evidence. Наблюдение не даёт ему права расширять authority. |
| `human approver` | Аутентифицированный человек, способный выдать только exact-bound approval внутри неизменяемого platform/L0 ceiling. Не oracle и не controller `JOIN`. |
| `journal writer` | Единственный логический writer канонической lineage, защищённый epoch/fencing. |
| `registry` | Digest-pinned источник manifest/tool/skill/adapter records. В минимальном профиле это неизменяемый snapshot; dynamic updates отключены. |

### 1.2. Сущности

`operation` — типизированная операция конкретного tool/adapter. `resource` — типизированная цель: файл, descriptor-root, endpoint, principal, tenant, queue, memory slot, policy object и т. п. `effect` — класс изменения или потока, определённый в Level 1. `scope` — допустимое множество целей/операций для конкретной пары effect/resource, а не универсальная строка.

`policy` — версия набора ограничений. `contract` — подписанный/зафиксированный набор агрегированных границ работы. `permission` — решение о допустимости попытки. `capability` — защищённый exact-bound bearer/reference, необходимый для одной попытки. `credential` — секрет или идентификатор, принимаемый внешним ресурсом; capability не обязана раскрывать credential. `authority` — множество допустимых trace-фрагментов, которое принципал способен фактически совершить через доступные enforcement paths.

`budget` — целочисленный вектор лимитов с единицами и областью учёта. `obligation` — проверяемое условие допуска/исполнения/постпроверки. `journal` — канонический crash-safe источник lineage и монотонных фактов. `receipt` — подписанное утверждение конкретного issuer-а о конкретном payload/digest; receipt не доказывает больше, чем утверждает issuer. `evidence` — данные, пригодные для проверки claim. `postcheck` — проверка sealed snapshot или reconciled external outcome. `compensation` — новая, отдельно разрешённая effect transaction; это не синоним rollback.

`tool`, `skill`, `plugin/MCP adapter` — разные packaging/resolution формы операций. Их имена не дают authority: допуск привязан к operation identity, implementation digest, manifest digest и runtime attestation.

### 1.3. Статусы effect-фактов

Эти множества нельзя сливать:

| Множество | Значение | Авторитетный источник |
|---|---|---|
| `desired` | Намерение пользователя/плана; не полномочие | intent/plan |
| `requested` | Канонизированный запрос конкретной операции | controller |
| `manifested` | Подписанная статическая верхняя граница реализации | registry/manifest |
| `derived` | Консервативное замыкание manifest с canonical args, доверенными facts и transitive sinks | classifier/PEP |
| `authorized` | Итоговый dependent envelope после всех ограничений и решения | PEP/controller |
| `attempted` | То, что процесс фактически попытался сделать | TCB/executor instrumentation |
| `blocked` | Подмножество попыток, остановленное enforcement | TCB/PEP |
| `actual` | Эффекты, которые, по имеющимся данным, произошли | executor/reconciliation |
| `committed` | Эффекты, принятые в каноническое состояние либо необратимо отправленные во внешний sink | commit/reconciliation authority |
| `observed` | Эффекты, увиденные observer-ом | observer |
| `verified` | Эффекты/постусловия, подтверждённые валидным evidence plan | verifier |

`actual` при неизвестном внешнем исходе может быть `UNKNOWN`; это не превращается ни в `KNOWN_SUCCESS`, ни в право повторить вызов.

### 1.4. Проектные термины с неустановленным авторитетным определением

Следующие определения локальны и помечены **PROVISIONAL**. Они обеспечивают проверяемую V0-семантику, но не заявляют восстановление исходной authority:

| Термин | Локальное PROVISIONAL-значение |
|---|---|
| `CB5` | Полный bounded transaction frame от предложения до controller `JOIN`/остановки с неизменными digest bindings. Число «5» не интерпретируется. |
| controller `JOIN` | Машинный переход, которым controller принимает согласованные commit/evidence/lineage facts и закрывает итерацию. Это не lattice join и не human approval. |
| `law-of-cut` | Требование, что effect/authority не пересекает trust boundary вне типизированного, журналируемого и exact-bound mediated transition. Полноценная исходная теорема не найдена. |
| `D2` | Исходная формула `proposed_sequence <= verified_sequence + 1` с operational bound из §6. |
| `JR5` | Каноническая durable journal lineage; суффикс не получает дополнительной семантики. |
| `LRP1_D` | Именованный, но не определённый профиль resource budget. До калибровки это обязательный параметр, а не число. |
| `S5` | Именованный conditional control для credentials/external mutation/unknown/significant blast radius. Его механизм и authority остаются открытыми. |
| `RJ*` | Семейство route/decision identifiers из исходного проекта; конкретные уровни не определены. |
| `B3` | Именованный bundle-режим; adaptive/static semantics не авторитетны. В V0 bundle expansion запрещён. |
| `R0–R6` | Именованные risk bands без восстановленных границ. Локальные isolation profiles не доказывают соответствие этим bands. |
| `PLACEMENT-P2` | Физическое размещение `P2` из diff; переименовано, чтобы не путать с roadmap `PHASE-P2`. Защитное свойство не следует из имени. |
| `authority domain` | Область, внутри которой едины platform ceiling, policy lineage, contract lineage, journal/fencing regime и risk owner. Междоменный перенос требует новой транзакции. |

До появления authoritative definitions потребитель MUST NOT выводить из этих терминов дополнительные разрешения.

## 2. Effect-ядро и ортогональные аспекты

Базовый effect vector — конечное множество из:

`{COMPUTE, OBSERVE, MUTATE, COMMUNICATE, DELEGATE, REFLECT}`.

Операция может иметь несколько effects одновременно. Следующие понятия **не** добавляются как равноправные primitives:

- `AUTHORIZE/GRANT` — authority transition;
- `DECLASSIFY` — information-flow capability, снижающая confidentiality restriction;
- `ENDORSE` — отдельная integrity capability, повышающая доверие к данным;
- `PERSIST/SCHEDULE` — temporal/lifecycle facet для состояния или будущего действия;
- `ALLOCATE` — resource/budget facet;
- `EXECUTE` — lifecycle relation между допущенной операцией и attempted/actual effect.

Каждый из этих facets MUST быть типизирован и exact-bound. Отсутствие facet означает запрет, а не наследование из effect name.

## 3. Dependent authority envelope

### 3.1. Тип

Пусть:

- `Op` — множество versioned operation identities;
- `Eff` — шесть effect primitives;
- `Res` — сумма типизированных видов ресурсов;
- `K = {(o,e,r) | ValidTriple(o,e,r)}` — только допустимые тройки.

Для каждого `k=(o,e,r)` определён собственный тип границы:

```text
Bound(k) = {
  scope: ScopeType(r,e),
  flows: FlowConstraints(r,e),
  time: TimeWindow,
  budgets: BudgetVector(k),
  obligations: PredicateSet(k),
  facets: FacetBounds(k)
}

Envelope = dependent finite map  k ↦ Bound(k)
```

Например, filesystem scope задаётся descriptor-root, разрешёнными относительными компонентами и операциями; network scope — protocol/address/port/SNI/direction; delegation scope — target principal, depth/fan-out и attenuated child envelope. Они не образуют небезопасный независимый cross product.

Денотация `⟦E⟧` — множество конечных типизированных trace-фрагментов, удовлетворяющих каждой границе и obligation. Отсутствующий ключ означает `DENY` для этого effect/resource. `UNKNOWN` является аналитическим верхом, но никогда не grant.

### 3.2. Порядок и операции

```text
E1 ⊑ E2  iff  ⟦E1⟧ ⊆ ⟦E2⟧
⊥         = envelope без разрешённых effect-traces
⊤/UNKNOWN = неконкретизированная верхняя граница; admission результата = DENY/STOP
E1 ⊓ E2   = greatest lower bound, денотация intersection
E1 ⊔ E2   = least upper bound, денотация union
```

`⊔` разрешён для анализа compound manifest и консервативной классификации; он MUST NOT использоваться как операция выдачи authority. Effective authority образуется только ограничением (`⊓`). Human approval и controller `JOIN` не являются `⊔`.

Законы для конечных, хорошо типизированных envelopes:

- `⊓` и `⊔` ассоциативны, коммутативны и идемпотентны;
- absorption: `E ⊓ (E ⊔ F) = E`, `E ⊔ (E ⊓ F) = E`;
- restriction monotonicity: `E ⊓ P ⊑ E`;
- unknown safety: `decide(⊤)=DENY/STOP`, а не `ALLOW`.

### 3.3. Последовательность, параллельность и замыкание

`E ; F` — relational composition trace-фрагментов через промежуточное состояние. Она ассоциативна при совместимых state schemas и transaction boundaries, но в общем не коммутативна. Budgets складываются/резервируются по размерности; labels и taint переходят по data- и control-dependencies; последующий scope может зависеть только от разрешённого/верифицированного результата предыдущего шага.

`E || F` — множество допустимых interleavings. Симметрия допустима только как денотация interleavings при независимых resource partitions, locks/fencing и атомарных budget reservations. При общем mutable resource композиция interference-aware и MAY быть inadmissible; перестановка действий не считается законом.

`Cl(X)` — наименьшая фиксированная точка, содержащая прямые effects `X`, transitive subtools/sinks, data/control flows, persistence, delegation и reflection consequences:

```text
Cl(X) = μY. (X ∪ DirectDependencies(Y) ∪ FlowConsequences(Y))
```

Для известного конечного dependency graph `Cl` монотонно, экстенсивно и идемпотентно. Dynamic dispatch, неразрешённый sink или недоказанный dependency даёт `UNKNOWN`, следовательно `DENY/STOP`.

### 3.4. Effective authority по маршруту

Физические ceilings различаются для worker, broker, executor, gateway и observer. Их нельзя перемножить в единый ambient envelope. Для каждого hop `i` маршрута:

```text
Effective_i(q) = Physical(principal_i)
               ⊓ Manifest(operation_i, digest_i)
               ⊓ PlatformPolicy
               ⊓ ProjectPolicy
               ⊓ Contract
               ⊓ CallCapability_i
```

```text
ALLOW(q) iff
  для каждого hop_i: Cl(Derived_i(q)) ⊑ Effective_i(q)
  and DemandVector_i(q) ≤ RemainingBudgetVector_i
  and все cross-principal flows явно присутствуют в FlowConstraints
  and все obligations выполнимы и привязаны к тем же digest/version facts.
```

Worker с `network_egress=false` может передать типизированный model request broker-у только через объявленный IPC edge; broker-owned model gateway совершает отдельный `COMMUNICATE` в собственном envelope. Ни credential, ни socket/FD gateway не MUST наследоваться worker-ом.

## 4. Чистая функция решения

```text
decide(
  request, principal, manifested, derived,
  capability_metadata, policy_versions,
  contract, durable_state_snapshot, remaining_budgets, evidence
) -> Decision

Decision = {
  outcome: ALLOW | DENY | REQUIRE_HUMAN | STOP,
  authorized_envelope?: Envelope,
  obligations: [Obligation],
  reason_codes: [ReasonCode],
  decision_digest: sha256
}
```

`decide` MUST быть pure и total для валидного входного schema-domain. Она не резервирует бюджет, не потребляет capability и не dispatch-ит. Неизвестный enum, stale/missing/mismatched digest, неограниченный scope, несогласованный journal snapshot или невозможная obligation дают `STOP` либо `DENY` по policy table. `REQUIRE_HUMAN` допустим только для уже bounded и legible envelope; approval не может исправить `UNKNOWN/TOP`.

Минимальные reason codes: `RC_UNKNOWN`, `RC_SCHEMA_INVALID`, `RC_DIGEST_MISMATCH`, `RC_MANIFEST_EXCEEDED`, `RC_PHYSICAL_CEILING`, `RC_POLICY_DENY`, `RC_SCOPE_EXCEEDED`, `RC_FLOW_DENIED`, `RC_BUDGET_EXHAUSTED`, `RC_CAPABILITY_INVALID`, `RC_REPLAY`, `RC_STALE`, `RC_HUMAN_REQUIRED`, `RC_OBLIGATION_UNSATISFIABLE`, `RC_JOURNAL_CONFLICT`, `RC_D2_VIOLATION`, `RC_UNKNOWN_OUTCOME`, `RC_TELEMETRY_MISSING`, `RC_REPORT_INVALID`, `RC_REPORT_NONAUTHORIZING`, `RC_CONTINUATION_GRANT_INVALID`, `RC_CONTINUATION_EXACT_BOUND`.

### 4.1. Отчёт review не является authority

Finding, severity, blocker, recommended patch, readiness classification и remediation/review report — это evidence/assessment, а не request, capability, approval или authority. Их canonical projection имеет только следующие поля и значения:

```text
report_id; report_digest = H(all other projection fields)
packet_digest; reported_at; finding_ids
readiness_impact ∈ {BLOCKS_CLAIM, HUMAN_RISK_DECISION_REQUIRED, NONBLOCKING, NONE}
affected_status_claims ⊆ {SPECIFIED, IMPLEMENTED, VERIFIED, READY}
recommended_patch; consequence_if_unresolved
report_authority = NONE
permitted_effects_from_report = []
controller_state_after_report = STOPPED_AWAITING_EXPLICIT_USER_INSTRUCTION
```

`BLOCKS_CLAIM` запрещает лишь нечестно заявлять затронутый status; он не разрешает remediation. После report чистая total-функция `decide_review_continuation(report_projection, continuation_request, trusted_facts)` возвращает `STOPPED_AWAITING_EXPLICIT_USER_INSTRUCTION` с `RC_REPORT_NONAUTHORIZING`, если нет fresh externally verified single-use user/human continuation grant, exact-bound к одному `transition_class ∈ {PATCH, FREEZE, REVIEW}`, report/finding/current-packet digests, scope, budget, attempt ceiling, nonce and post-report TTL. Идентичность пользователя и verifier должны быть внешне подтверждены; current packet/scope/budget/attempt берутся из authoritative controller state, а не из report или request. `PATCH`, `FREEZE` и `REVIEW` — разные grants: grant одного action никогда не authorizes другой. Любое изменение packet digest, уже использованный или неполный grant даёт `RC_CONTINUATION_GRANT_INVALID`; текст report не является input, способным изменить это решение. При успехе pure function возвращает post-consumption state; controller MUST атомарно зафиксировать consumption grant ID и nonce вместе с ровно одним transition, а повторное применение старого pre-state недопустимо. Эта pure-model rule не создаёт runtime implementation или attestation.

## 5. LTS: общий admission и ветви исполнения

### 5.1. Состояние транзакции

```text
Tx = (
  phase, principal, request_digest, manifest_digest, policy_digest,
  contract_digest, capability_id/state, lineage, epoch,
  budget_before/reserved/spent, dispatch_intent,
  desired/requested/manifested/derived/authorized,
  attempted/blocked/actual/committed/observed/verified,
  obligations, outcome
)
```

Начальное и fail-closed состояние — `STOPPED`. `STOPPED` не означает успех и не выдаёт capability.

### 5.2. Общая ветвь

```text
STOPPED
  → PROPOSED
  → NORMALIZED
  → CLASSIFIED
  → DECIDED
  → ADMITTED
  → CAPABILITY_ISSUED_PROTECTED
  → DURABLE_CONSUME_RESERVE_INTENT_COUNTER
```

`PROPOSED→NORMALIZED` канонизирует args и identity. `NORMALIZED→CLASSIFIED` вычисляет `Cl(derived)`. `CLASSIFIED→DECIDED` вызывает pure `decide`. `DENY` возвращает `STOPPED`; `STOP` оставляет/создаёт incident state; `REQUIRE_HUMAN` переходит в `WAITING_HUMAN`, после exact-bound receipt решение вычисляется заново.

Переход `DURABLE_CONSUME_RESERVE_INTENT_COUNTER` MUST быть одной serializable durable транзакцией. Он одновременно:

1. проверяет epoch/fence и неиспользованный capability;
2. помечает capability consumed;
3. резервирует budget vector;
4. фиксирует dispatch intent и idempotency/dedup facts;
5. двигает монотонные iteration/call/lineage counters.

`BUDGET_RESERVED` и `CAPABILITY_DURABLY_CONSUMED_AND_DISPATCHED` — логические проекции результата этого единого commit, а не crash-visible промежуточные записи. Downstream executor MUST проверять epoch/fencing token; «single writer» без fencing недостаточен.

### 5.3. Stageable/reversible branch

```text
DURABLE_CONSUME_RESERVE_INTENT_COUNTER
  → EXECUTING
  → QUIESCED
  → SNAPSHOTTED_SEALED
  → POSTCHECKED
  → COMMITTED
  → JOINED
  → STOPPED | NEXT_TRANSACTION

POSTCHECK_FAILED → DISCARDED → STOPPED
SEAL_OR_COMMIT_UNKNOWN → QUARANTINED → RECONCILING
```

До `SNAPSHOTTED_SEALED` supervisor MUST прекратить/заморозить process tree, отозвать writer FDs/leases и доказать отсутствие concurrent writer в заявленном scope. Postcheck читает immutable snapshot. Failed postcheck не commit-ит staged delta. Unknown commit не трактуется как failure, пригодный для retry.

### 5.4. Non-stageable external branch

```text
ADMITTED → PRECHECKED → CAPABILITY_ISSUED_PROTECTED
  → DURABLE_CONSUME_RESERVE_INTENT_COUNTER
  → KNOWN_SUCCESS | KNOWN_FAILURE | UNKNOWN_OUTCOME

KNOWN_SUCCESS → RECONCILED → JOINED → STOPPED | NEXT_TRANSACTION
KNOWN_FAILURE → FAILURE_RECORDED → STOPPED | COMPENSATION_PENDING
UNKNOWN_OUTCOME → QUARANTINED → RECONCILING
```

При `UNKNOWN_OUTCOME` automatic retry MUST NOT выполняться. Idempotency key, если sink его поддерживает, уменьшает риск дубликата, но не превращает unknown в known. Отмена после отправки не доказывает отсутствие эффекта.

**Q-82 normative anchor (endpoint-only external evidence).** An external capability
MUST bind exactly one trusted `endpoint_binding`: `endpoint_id`, canonical HTTPS
endpoint, `connector_id`, pinned `connector_digest`, HTTP `method`,
`idempotency_key_digest` and `endpoint_binding_digest`. This is the dispatch and
reconciliation target identity; it is not a filesystem descriptor. Endpoint
identity and filesystem identity are disjoint closed types: an endpoint dispatch
or external reconciliation MUST NOT require, accept or infer descriptor/root/
mount/final-object evidence, and a filesystem effect MUST NOT accept endpoint
binding evidence. The same endpoint binding is equality-checked from admission,
manifest and policy through capability, durable intent, event and authoritative
reconciliation receipt. Missing, mixed or cross-kind identity is `DENY/STOP`.

**Q-83 normative anchor (known failure disposition).** `KNOWN_FAILURE` is a
trusted typed fact, never a shorthand for no effect. Its receipt records every
effect component as `NO_EFFECT`, `PARTIAL_EFFECT` or `RESIDUAL_EFFECT`, and every
exact four-part budget key `(name, unit, scope_digest, lineage_root)` with its
positive exact `amount` as `SPENT`, `RELEASED` or `QUARANTINED_ESCROW`.
`FAILURE_WITH_RESIDUAL_EFFECT` is a signed terminal reconciliation outcome, not
`FAILURE_NO_EFFECT`. A partial/residual component forbids
release of that failure's budget vector, retry and `JOIN`; it remains contained
or quarantined pending a new effect. `COMPENSATION_PENDING` is allowed only with
a different, fully admitted compensation transaction binding its own decision,
envelope and capability. It is not a release, retry or controller `JOIN`.

### 5.5. Compensation branch

```text
COMPENSATION_PENDING
  → NEW_PROPOSED_TRANSACTION
  → ... common admission ...
  → COMPENSATED_VERIFIED | RESIDUAL_EFFECT | COMPENSATION_FAILED
```

Compensation имеет собственные manifest, envelope, capability, budget, evidence и committed effects. `COMPENSATION_PENDING` требует уже свежего `ADMITTED` compensation authorization (новые transaction/decision/envelope/capability digests); без него original transaction остаётся `STOPPED` или quarantined. `COMPENSATED_VERIFIED` не стирает исторический original effect.

### 5.6. Crash, retry, recovery, revocation

| Событие | Обязательный переход |
|---|---|
| Crash до durable consume/dispatch commit | Capability MAY быть отозван; повтор допускается только после нового решения и подтверждения отсутствия dispatch intent. |
| Crash после durable commit, до подтверждённого dispatch | Recovery сверяет intent с executor по idempotency/epoch; не выдаёт новый capability автоматически. |
| Crash во время external dispatch | `UNKNOWN_OUTCOME → QUARANTINED/RECONCILING`; automatic retry запрещён. |
| Timeout stageable execution | Kill process tree, revoke leases, discard unsealed delta, record actual/blocked effects, `STOPPED`. |
| Timeout postcheck/reconciliation | `QUARANTINED`; отсутствие evidence не равно success. |
| Revocation до dispatch commit | Переход в `STOPPED`, capability revoked. |
| Revocation после dispatch commit | Supervisor пытается cancel/freeze/contain; уже committed external effect остаётся фактом и требует reconciliation/compensation. |
| Restart/retry/nested contract | Не сбрасывает lineage counters/budgets и не возрождает consumed capability. Новый contract требует самостоятельной human-bound admission и anti-rollback evidence. |

Recovery MUST быть phase-sensitive. Durable `COMMITTED` никогда не переходит в `DISCARDED`: после crash он остаётся `COMMITTED_RECOVERY_PENDING` до проверки same-object receipts и затем только `JOINED` либо `QUARANTINED/RECONCILING`. Новый `transaction_id` начинается из чистого transaction frame и не наследует request/capability/approval/reservation/dispatch/stage/receipt fields предыдущей транзакции; переносимы только явно scoped cumulative lineage/budget/revocation facts. После host/supervisor crash fresh admission запрещён до authoritative host recovery gate: старый epoch fenced, process/writer/lease inventory reconciled, cleanup или quarantine зафиксированы.

## 6. Controller JOIN, human approval и D2

Human approval — exact-bound predicate/evidence при admission. Controller `JOIN` — машинное закрытие каждой итерации после допустимого commit/reconciliation и evidence. Per-contract human confirmation не означает human approval каждого `JOIN`; каждый шаг всё равно проходит machine admission и отдельный `JOIN`.

### D2-PROVISIONAL operational bound

Сохраняется исходная формула:

```text
proposed_sequence <= verified_sequence + 1
```

Durable `attempt_cursor` обозначает число уже начатых попыток, а `joined_iteration` — номер последней успешно присоединённой попытки; всегда `0 <= joined_iteration <= attempt_cursor <= max_iterations`. До atomic frontier bind следующей попытки MUST NOT существовать относящийся к `attempt_cursor+1` объект, который является хотя бы одним из следующего:

- controller-visible;
- persisted или staged;
- передан tool/executor/другому principal;
- budgeted/reserved/locked;
- candidate/proposal/bundle branch, пригодный к повторному использованию;
- capability, target binding, dispatch intent или external authorization.

Atomic frontier bind для iteration `attempt_cursor+1` необратимо двигает только `attempt_cursor`; `JOIN` двигает только `joined_iteration`. Поэтому terminal `DISCARDED` попытки N разрешает admission N+1 без ложного `JOIN(N)`, но failed, blocked, discarded, restarted и nested attempts не возвращают slot. До terminal `JOINED` или `DISCARDED` текущей попытки следующий frontier не допускается. Private ephemeral model tokens MAY существовать вне этого bound только если они никогда не сохраняются, не передаются, не становятся context/evidence/control input и не связываются с tool/budget/target. Нарушение переводит controller в `STOPPED`, а при возможном внешнем эффекте — в `QUARANTINED`.

## 7. Глобальные инварианты

| ID | Нормативное утверждение | Enforcement owner / failure |
|---|---|---|
| `INV-001` | `STOPPED` — единственное fail-closed default. Любое missing/invalid state не даёт execution. | Controller/PEP; `STOP`. |
| `INV-002` | Agent/model не является ambient authority holder или внешним executor; credentials и live sink authority не наследуются. | L0 + broker; kill/revoke/incident. |
| `INV-003` | Каждый side effect проходит через non-bypassable mediation и authoritative event. | PEP/TCB; block + `STOPPED/QUARANTINED`. |
| `INV-004` | Capability exact-bound, single-use, nonreplayable, nontransferable, short-lived и привязан к principal, pairwise-distinct audience/EXECUTOR session, purpose, operation/request, contract, manifest, policy, nonce, epoch и lineage; every field is checked against a durable external verifier at issue and dispatch. | Capability issuer/store; `DENY/RC_CAPABILITY_INVALID` или `DENY/RC_REPLAY`. |
| `INV-005` | `committed ⊆ authorized ⊆ manifested ⊓ physical`; compiled worker effects are a subset of the worker physical ceiling and worker `COMMUNICATE` is proposal-only through a distinct sink hop. Attempted может выйти за ceiling только как заблокированная и зарегистрированная попытка. | L0/PEP/commit authority; containment при нарушении/uncertainty. |
| `INV-006` | Policy lower layers и human approval только сужают authority. Delegation child envelope — attenuated subset; authority join не используется для выдачи прав. | PEP/delegation broker; deny/revoke subtree. |
| `INV-007` | Для всего delegation tree: `spent_parent + Σ(reserved_child + spent_child) ≤ parent_limit`; partitions/reservations atomic и linear. | Budget ledger; stop subtree on conflict. |
| `INV-008` | Cumulative counters/budgets монотонны, durable, crash-safe; restart/retry/nested contract/branch не сбрасывает их. D2-PROVISIONAL соблюдается. | Journal writer + fenced executors; `STOP/QUARANTINE`. |
| `INV-009` | Material change prompt/context/model/tool/adapter/manifest/policy/contract/target invalidates связанный receipt/capability. | Digest resolver/PEP; re-admission. |
| `INV-010` | Незаявленное persistent state не переносится между итерациями; разрешённая память versioned, scoped, labelled, taint-tracked и audited. N→N+1 — явный flow. | Context plane/L0/controller; reject input + incident. |
| `INV-011` | Evidence/observability не создают authority. Safety events исходят от externally verified role-bound emitters and canonical signed source chains; missing/corrupt mandatory telemetry/evidence для risk action — failure. | Broker/observer; freeze/quarantine. |
| `INV-012` | Seal требует quiescence и исключения concurrent writers; descriptor/root/mount/epoch and postcheck/commit относятся к одному immutable same-object digest chain. | Supervisor/snapshotter/commit authority; discard/quarantine. |
| `INV-013` | Confidentiality, integrity, provenance, taint, purpose и retention распространяются по data/control dependencies. Hash/schema/summary не declassify и не endorse. Эти два перехода требуют разных capabilities. | Flow PEP; block sink + incident. |
| `INV-014` | Recovery, rollback и compensation — effectful операции с новыми manifest/policy/budget/capability. `UNKNOWN_OUTCOME` не auto-retry. | Controller/recovery owner; quarantine. |
| `INV-015` | `unknown/unclassified/unbounded/missing/stale/mismatched` никогда не становится implicit allow; unbounded не approvable. | Все decision/enforcement points; `DENY/STOP`. |

## 8. Preconditions и postconditions

Общие preconditions `ADMIT`:

1. canonical request и все identity/digest bindings валидны;
2. operation implementation совпадает с immutable registry snapshot;
3. `Cl(derived)` конечен и не `UNKNOWN`;
4. dependent scope/flows/time/budgets/obligations типизированы;
5. journal snapshot fresh, epoch/fence current, capability unused;
6. demand не превышает remaining budgets;
7. обязательные human/evidence predicates присутствуют и exact-bound;
8. D2 и material-change checks проходят.

Общие postconditions завершённой итерации:

- ровно один terminal disposition: `JOINED`, `DISCARDED`, `FAILURE_RECORDED`, `QUARANTINED` либо `STOPPED_BEFORE_DISPATCH`;
- capability `consumed|revoked`, но никогда вновь `issued` с тем же ID;
- budget reservation reconciled в `spent|released|quarantined`, без потери lineage;
- attempted/blocked/actual/committed/observed/verified записаны раздельно;
- все authoritative events связаны одним trace/transaction digest;
- при `JOINED` postconditions и evidence относятся к тому же sealed/externally reconciled outcome.

## 9. Проверки и evidence obligations

| Test ID | Обязательство | Oracle | Expected evidence | Сейчас |
|---|---|---|---|---|
| `T-SCHEMA-CORE-001` | Все object schemas закрыты, enums конечны, unknown поля rejected. | Draft 2020-12 validator. | `EV-SPEC-SCHEMA-CORE-001` validation report. | `SPECIFICATION_TESTED`: 12 schemas + examples |
| `T-POL-CORE-001` | Pure `decide` total/deterministic на canonical admission inputs. | Повтор даёт byte-identical decision; material negative mutations не `ALLOW`. | `EV-SPEC-POL-CORE-001`. | `SPECIFICATION_TESTED`; runtime absent |
| `T-POL-CORE-002` | Policy monotonicity и deny-overrides. | Добавление restriction не расширяет denotation. | Property report. | `PLANNED/ABSENT` |
| `T-POL-CORE-003` | Algebra laws для `⊓/⊔/Cl`; sequence non-commutativity fixtures. | Указанные законы проходят; контрпример `E;F != F;E` сохраняется. | `EV-SPEC-ALG-001`. | `PARTIAL`: correlated-alternative negative tested; full laws absent |
| `T-LTS-CORE-001` | Finite transition matrix for modeled reference branches. | Нелегальные transitions fail closed; terminal conservation guards hold. | `EV-SPEC-LTS-001`. | `PARTIAL_SPECIFICATION_TESTED`; not runtime-exhaustive |
| `T-LTS-CORE-002` | Crash/replay at modeled durable dispatch boundaries. | Нет replay after STOP; reservation/capability state conserved. | `EV-SPEC-LTS-CRASH-001`. | `PARTIAL_SPECIFICATION_TESTED`; durable store absent |
| `T-LTS-CORE-003` | Unknown external outcome. | Нет automatic retry; только quarantine/reconcile with escrow. | Trace bundle. | `SPECIFICATION_TESTED`; live connector absent |
| `T-LTS-CORE-004` | D2 typed frontier exploration. | За `attempt_cursor+1` rejected all declared artifact classes/flags; stale/gap cursor и rollback не меняют state. | `EV-SPEC-D2-001`. | `SPECIFICATION_TESTED`; D2 definition provisional |
| `T-LTS-CORE-005` | Concurrency/fencing двух writers/executors. | Только current epoch может dispatch/commit; loser stops. | Schedule traces. | `PLANNED/ABSENT` |
| `T-ATTACK-CORE-001` | Replay/transfer/stale/material-change attempts. | Все denied; authoritative block events emitted. | Attack trace bundle. | `PLANNED/ABSENT` |
| `T-ATTACK-CORE-002` | Delegation amplification/budget fragmentation. | Child subset и conservation equation сохраняются при interleavings/crash. | Property/fault report. | `PLANNED/ABSENT` |
| `T-REPORT-CORE-001` | Report-authority boundary. | `BLOCKS_CLAIM`, any finding text including “MUST_FIX”, severity or recommended patch without a valid grant leaves controller `STOPPED_AWAITING_EXPLICIT_USER_INSTRUCTION`; no `PATCH`, `FREEZE` or `REVIEW`. | Pure-model trace with `RC_REPORT_NONAUTHORIZING`. | `SPECIFICATION_TESTED` |
| `T-REPORT-CORE-002` | Continuation grant separation, freshness and use. | `PATCH` grant cannot start `FREEZE`/`REVIEW`; each action is exact-bound, single-use, post-report and digest-bound; packet change, replay, predated or incomplete grant gives `RC_CONTINUATION_GRANT_INVALID`; only a fresh exact grant admits its one named transition. | Pure-model traces. | `SPECIFICATION_TESTED` |

Эти тесты проверят specification/reference semantics. Даже успешный результат не меняет `implementation=NOT_IMPLEMENTED`.

## 10. Definition of Done и assurance status

| Стадия | Необходимые условия |
|---|---|
| `DECLARED` / `SPECIFIED` | Glossary и PROVISIONAL terms явны; LTS total по конечным событиям; все `INV-001..015` имеют enforcement/failure/test/evidence mapping; schemas и reference vectors проходят. |
| `IMPLEMENTED` | Конкретные PEP/broker/journal/executor/observer реализованы; atomicity, fencing, L0 ceilings и authoritative events доказаны conformance-тестами в точно названной среде. |
| `VERIFIED` | Независимые adversarial/concurrency/fault испытания на pinned digests подтверждают каждый claim; scope/environment/expiry evidence указаны; нет open Critical/High. |

Evidence maturity ведётся отдельно per claim: `UNTESTED → TESTED → ATTESTED → MONITORED → VERIFIED`. Более высокий общий статус не повышает автоматически status отдельного invariant/control.

Текущий честный итог: semantics, 12 schemas и pure reference model существуют и проходят abstract checks; runtime implementation, real cryptography/kernel/durable-store enforcement и runtime safety evidence отсутствуют.

### Canonical binding obligations

The normalized active policy and isolation profile MUST be content-addressed over their complete normalized control content (including compiled envelopes and risk controls) and accepted only through a fresh, non-revoked external activation record bound to registry/compiler provenance, generation and rollback floor. A digest, a local recomputation, or an inline boolean is not an activation. The exact descriptor/root/mount/resolution-epoch binding MUST continue to the final opened-object identity in dispatch, receipt, event, `COMMIT` and `JOIN`; lexical paths are never identity.

Admission MUST require one externally verified, signed complete-payload broker IPC runtime attestation for the exact worker↔broker `AF_UNIX/SOCK_SEQPACKET` `UNIX_CONNECTED_PAIR` session: profile and broker-IPC-binding digests, both full OS subjects, both immutable endpoint identities (device, inode and socket cookie), both FDs and allowlists, externally observed endpoint holders, broker-observed per-message credentials, message schema, operation, nonce, session fence, lifetime and revocation epoch. The pair is the sole typed exception to the worker's closed connected-FD set and carries only a powerless proposal; it is not an external sink or executor FD. Creation-time `SO_PEERCRED`, a caller boolean or a digest is not proof of the post-exec holders. To avoid self-reference, the canonical signed payload excludes only `attestation_digest` and `signature`; both `attestation_digest` and `signature.payload_digest` MUST equal its canonical digest. Its attestation and broker-IPC-binding digests are immutable bindings through decision, capability, durable dispatch, receipt/event and `JOIN`; durable dispatch and `JOIN` MUST recheck the same external record. Endpoint replacement, additional connected FD, reconnect, replay or holder/credential substitution is a material change requiring fresh admission or `STOP`, not a new transition or service.

`resource_vector_digest` is the digest of the canonical active isolation-profile `resources` array. It preserves that exact closed profile vector unchanged through decision, capability, dispatch, receipt and event without copying the vector into those artifacts. Operation-specific reservations remain separate exact vectors and do not substitute for, translate or extend the profile resource vector.

For every residual risk there is exactly one current, signed, externally verified record whose evidence type and typed payload match the disposition, including monitor telemetry/escalation and an out-of-scope proof. For stageable commit, `QUIESCE`, `SEAL` and `POSTCHECK` each require a typed, independently verified record bound to transaction, capability, session, same object identity, epoch and observer. A parent delegation ledger is keyed by `(name, unit, scope_digest, lineage_root)` with `remaining = limit − spent − reserved`; sibling transfers are atomic and fenced, and scalar cross-key totals are invalid. Event and receipt chains are accepted only against durable per-source `(epoch, next_sequence, predecessor_digest)` state with explicit genesis.

These are pure-model obligations, not an assertion that a runtime, signature verifier, filesystem resolver or durable store exists: `implementation=NOT_IMPLEMENTED`, `runtime_attestation=NOT_ATTESTED`, `overall=NOT_READY`.

## 10.1. Канонический машинный контракт

### Correlated authority clauses

`AuthorityEnvelope` MUST быть конечным множеством **коррелированных** `AuthorityClause`, а не декартовым произведением независимо расширяемых полей:

```text
AuthorityClause =
  (effect, resource_kind, operations, selector,
   temporal_bound, quantity_bound, data_flow,
   exact_authority_facets, principal, audience, purpose)
```

Допустимые `(effect, resource_kind, operation, selector)` задаются закрытыми discriminated variants. Например, `OBSERVE+FILE` допускает `READ|LIST` с path-selector, а `COMMUNICATE+ENDPOINT` — `SEND` с endpoint-selector; комбинация `OBSERVE+FILE+SEND+ENDPOINT` ill-typed и MUST быть rejected до policy evaluation. `declassify`, `endorse`, `authorize`, `persist_schedule`, `allocate` и `execute` — не boolean-флаги: каждая ненулевая facet содержит точные source/sink/label/purpose/time/quantity bounds.

Одна и та же canonical serialization `AuthorityClause` MUST без потерь использоваться в normalized request, manifest, каждой policy layer, decision, capability и dispatch intent. Clause coverage проверяется целиком: effect/resource/operations/selector, direction/flows, confidentiality+integrity+provenance+purpose+retention labels, time, quantity, concurrency, obligations и authority facets. Отсутствующее поле означает deny; `quantity=0` разрешает нулевой demand, а не произвольную операцию; request MUST NOT добавлять facet, flow, label transition или operation, отсутствующие в manifest/policy. Любая lossy projection, independent field union или несовместимый clause type даёт `STOP/RC_SCHEMA_INVALID`.

The canonical binding also carries trusted identity facts, not merely their digests. A `SupplyVerification` record MUST be externally anchored and bind registry snapshot, revocation/rollback state, dependency closure, exact loaded bytes, loader/runtime and placement to one composite measurement; a caller recomputing all fields is not a verifier. A `ContractVerification` record MUST resolve the active contract and bind its canonical digest, authority, budget, iteration, D2 and postcheck rules to the real lineage. A `CapabilityVerification` record MUST be durable and externally verifiable at both issue and dispatch, and MUST cover every signed field (principal, audience, purpose, envelope, request, decision, contract, manifest, policy, registry, placement, session, lineage, nonce, time, revocation and fence). Missing, stale, substituted or inline-only facts give `STOP/RC_CAPABILITY_INVALID`.

For every stageable or committed trace, `descriptor_id`, trusted descriptor-root identity, mount identity and epoch are one exact binding carried end-to-end. `COMMIT` and `JOIN` require typed externally verified records for the same transaction/object, with equal transaction, decision, capability, envelope, seal/postcheck and effect identities; digest-shaped values, self-asserted booleans or swapped objects are not evidence. Worker compiled effects MUST satisfy `compiled_worker_effects ⊆ Physical(worker)`; worker `COMMUNICATE` is proposal-only and a permitted external communication uses a separate broker/gateway sink hop. A mutation capability's audience MUST resolve to a pairwise-distinct attested `EXECUTOR` principal/session. Scope comparison is defined only for the declared `(selector_kind, resource_kind)` relation; raw value equality across incompatible kinds is `UNKNOWN`.

Денотация envelope — union денотаций clauses. `A ⊔ B` сохраняет clauses как alternatives; pointwise union полей запрещён, потому что он мог бы синтезировать неразрешённые пары `(scope_A,time_B)`. `A ⊓ B` строит только непустые pairwise intersections совместимых clauses. Parallel composition разрешена лишь для доказанно независимых resources или под общим serializable fence; иначе `DENY/RC_PARALLEL_INTERFERENCE`.

### Canonical budgets

Budget key равен `(name, unit, scope_digest, lineage_root)`. В каждом входном bound ключ уникален; duplicate bound — malformed `STOP`. Demand сначала агрегируется checked-addition по ключу, затем единожды сравнивается с каждым ceiling и создаёт одну reservation. Переполнение, неизвестная unit или неоднозначный scope дают `STOP`, не saturation. Для каждой транзакции:

```text
initial = remaining + reserved + spent
terminal_completed => reserved = 0
unknown_outcome => reserved = quarantined_escrow
```

Required budget keys задаются effective envelope. Demand, decision `reservation_vector`, capability и durable dispatch record MUST иметь ровно эти keys и одинаковые `(unit,scope_digest,lineage_root)`; ключ нельзя опустить, заменить scalar total или погасить нулём другой размерности. Dispatch допускается только при exact equality `dispatch.reservation_vector = decision.reservation_vector` и component-wise coverage всеми ceilings.

### Admission, issuance and consumption

До `ALLOW` существует только неавторитетный `CapabilityCeilingCandidate`. Pure decision возвращает полный `authorized_envelope`, canonical `reservation_vector`, obligations и `decision_digest`. Только trusted issuer после durable `ADMITTED(decision_digest)` mint'ит live capability, связанную с issuer/principal/audience/purpose, exact envelope, request/decision/contract/manifest/policy/registry/placement/session digests, lineage root, nonce, issue/not-before/expiry, revocation epoch и executor fence. Issuer подписывает canonical complete payload; capability ID или self-hash без проверенной подписи не является authentication.

PEP и executor независимо проверяют signature/trust root/key status, canonical payload, exact field equality с admitted decision/current session, trusted current time, current revocation epoch/feed и current fence immediately before dispatch. Любая field mutation с пересчитанным digest, stale/missing verifier fact или issuer mismatch даёт `DENY/RC_CAPABILITY_INVALID`. Durable consume+reservation+dispatch intent атомарно переводит capability `ISSUED→CONSUMED`; использованные ID/digest/nonce остаются в monotonic replay set после `STOP`, restart и recovery. Null capability, pre-existing live capability как prerequisite для issuance, несоответствие envelope/digest или повторный consume MUST NOT dispatch.

### D2 frontier state

Controller durable-хранит closed inventory `frontier[iteration]` для classes `PLAN`, `PROMPT`, `CONTEXT`, `CANDIDATE`, `REUSABLE_BRANCH`, `TOOL_BINDING`, `CAPABILITY`, `BUDGET_RESERVATION`, `LOCK`, `TARGET_BINDING`, `DISPATCH_INTENT`, `EXTERNAL_AUTHORIZATION`, `STAGED_OUTPUT`, `PERSISTED_STATE`, `CONTROLLER_TOKEN`. An externally verified frontier record MUST bind exact `contract_digest`, `contract_version=2.0.0`, `authority_domain_id`, `journal_lineage_id`, `root_contract_digest`, nullable `parent_contract_digest`, `journal_sequence`, `fencing_epoch`, `attempt_cursor`, `joined_iteration`, `iteration` and `frontier_record_digest`. Its canonical `d2_frontier_digest` remains exact through decision, capability, dispatch, crash/recovery and JOIN. Даже artifact с false/empty flags остаётся членом своего intrinsic class. Bind допускается только когда record cursor равен current durable cursor, `iteration = attempt_cursor + 1`, `joined_iteration` равен отдельному current join progress, previous attempt terminal, и `iteration <= contract.max_iterations`; event append, frontier write и cursor CAS образуют один atomic commit. Любой stale/gap/rollback или старый frontier/contract record отклоняется без изменения state. Scalar check номера итерации, caller-supplied visibility flags или RAM-only inventory не удовлетворяют D2-PROVISIONAL.

### Effect stages and JOIN

Каждая stage имеет tagged форму `KNOWN(entries) | UNKNOWN(reason) | NOT_APPLICABLE | ABSENT(reason)`; пустой array, boolean или отсутствующее поле не кодируют known success. Каждый entry несёт canonical `object_id`, `object_digest` и envelope digest. `COMMIT/JOIN` требуют semantic validation: trusted emitter/signature, `committed ⊆ authorized`, и один непрерывный same-object chain `dispatch → attempted/actual → seal-or-external-receipt → postcheck/reconciliation → commit → JOIN`; все звенья совпадают по transaction, decision, capability, object identity, authorized envelope и relevant snapshot/effect digest. Self-asserted equality booleans и произвольные receipt digests запрещены. Stageable branch дополнительно требует quiesced writers, immutable snapshot и independent passed postcheck; external branch — authoritative reconciliation. `UNKNOWN` всегда ведёт в `QUARANTINED/RECONCILING`.

## 11. Source-vs-new traceability

| Тема | Корпус | V0 disposition |
|---|---|---|
| Separate CB5 transaction, STOPPED, one-use permission, D2 | `HARNESS_ACTIVATION_DIFF.md:5-10,130-180,438-470,533-558`; `formal.md:16-109` | Сохранено, но project terms помечены PROVISIONAL; булевы claims заменены LTS obligations. |
| Общий admission и три execution branches | `metaprompt-harness-levels-0-5-ru.md:105-145` | Сохранено и уточнено atomic durable dispatch transition. |
| Dependent authority envelope и effective intersection | `metaprompt-harness-levels-0-5-ru.md:147-167` | Новый dependent map исключает ложный cross product и разделяет ceilings принципалов; это новое нормативное требование, а не evidence существующей реализации. |
| Глобальные invariants | `metaprompt-harness-levels-0-5-ru.md:169-185`; `HARNESS_ACTIVATION_DIFF.md:533-558` | Нормализованы как `INV-001..015`, добавлены owners/failure/tests. |
| Unknown outcome и compensation | `metaprompt-harness-levels-0-5-ru.md:120-145` | Сохранено; auto-retry запрещён, compensation — новая транзакция. |
| Journal replay/fencing/crash | `security.md:75-99`; `comparison.md:200-206` | Усилено: RAM capability store и JSONL сами по себе не являются crash-safe; требуется serializable durability и downstream fencing. |
| Information flow/evidence N→N+1 | `security.md:120-153`; `comparison.md:113-118,165-171`; `metaprompt...:179-184` | Канал объявлен; labels включают confidentiality/integrity/provenance/taint/purpose/retention; hash/schema не снимают taint. |
| Six effects vs facets | DOCX `word/document.xml#p0845-p0878`; `metaprompt...:208-239` | Шесть effects сохранены как set/vector; authority/flow/lifecycle facets отделены. |
| Numeric limits | `HARNESS_ACTIVATION_DIFF.md:42-75,103-127,328-342`; `synthesis.md:29-114` | Все числа считаются profile examples/TBD до калибровки, не универсальными bounds и не readiness claims. |

## Iteration slot and canonical loop contract

Admission MUST atomically claim one durable `iteration_slot` by CAS uniqueness on `(authority_domain_id, root_contract_digest, journal_lineage_id, iteration)`. The closed `CLAIMED` slot record binds its key, owner request, fencing epoch, claim/expiry times and `slot_record_digest`; the same `iteration_slot_digest` MUST remain exact through decision evaluation, capability bindings, durable dispatch, effect receipts/events, crash recovery and `JOIN`. A conflicting, expired, stale-fenced or differently bound claim is `DENY/STOP` without another admission mutation.

Each receipt stage is the closed tagged object `{status, entries, reason?}`: `KNOWN` has nonempty entries and no reason; `UNKNOWN` or `ABSENT` has an empty entries array and a reason; `NOT_APPLICABLE` has an empty entries array and no reason. Endpoint stages contain only endpoint entries; non-endpoint stages contain no endpoint entries. Outcome and commit predicates operate on `status`, never on array truthiness.

The only consumed loop contract is one complete schema-valid `loop-contract` object. Its `contract_digest` is computed over its canonical complete content excluding that field itself, and an externally verified resolver record MUST bind that digest to the resolved object. Admission, capability, dispatch, recovery and `JOIN` require exact equality for the selected contract's lifecycle/revocation, audience/human confirmation, artifact bindings, D2 definition/bound, aggregate budget keys and values, and the selected manifest's `postcheck_required=true` and `independent_observer_required=true`; a projection, partial reconstruction or digest-only assertion is non-authorizing.

`iteration_bound.max_iterations` is the hard `max_attempts` ceiling, not a success quota. Every started attempt atomically and irreversibly consumes the next durable `attempt_cursor` slot when its D2 frontier commits, including failed, blocked, discarded, retried, restarted and nested attempts. `JOIN` advances only `joined_iteration`; success never returns a cursor slot. `success_target`, if used for assessment, is non-authorizing metadata and MUST NOT raise or reset that ceiling. Changing `max_iterations` or the frozen packet digest terminates the current exact-bound contract; further work requires a new contract plus a fresh explicit user continuation grant.

At `ADMIT`, the embedded verified frontier's `journal_sequence`, `fencing_epoch`, `attempt_cursor` and `joined_iteration` MUST equal the pre-admission durable reducer state, and the claimed slot's `iteration` MUST equal `attempt_cursor + 1`. Admission atomically advances `attempt_cursor` together with the frontier record; `JOIN` later advances only `joined_iteration`. This is an admission-time state coupling, not a generic dispatch predicate: durable dispatch advances sequence and fence.
