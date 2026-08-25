# 11. Level 1 — система эффектов

## 0. Паспорт

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
| Level claim | Типизированная консервативная классификация effects; не предсказание поведения произвольного кода |
| Corpus snapshot | aggregate source SHA-256 `08a296ee00349eac64d13292e4d4c714d1de0cd412adca1c695ef5e5f92838e0` |

Слова **MUST / MUST NOT / SHOULD / MAY** нормативны в смысле RFC 8174.

## 1. Purpose, claim boundary и non-goals

Level 1 задаёт минимальное общее effect vocabulary и композицию, необходимые для manifest, runtime policy, observability и human control. Операция классифицируется как **set/vector**, а не один mutually exclusive enum.

Базовый набор:

```text
EffectKind = COMPUTE | OBSERVE | MUTATE | COMMUNICATE | DELEGATE | REFLECT
```

V0 не утверждает, что шесть слов семантически исчерпывают все будущие действия или что произвольный код всегда decidably классифицируем. Для конечного configured tool/operation set должен существовать конечный syntactic inventory; неизвестные transitive/dynamic последствия получают `UNKNOWN/TOP` и fail closed.

System MUST различать effect class, authority, information-flow, lifecycle и resource facets. `AUTHORIZE`, `DECLASSIFY`, `ENDORSE`, `PERSIST/SCHEDULE`, `ALLOCATE`, `EXECUTE` не добавляются молча в `EffectKind`.

## 2. Assets, adversaries и trust assumptions

### 2.1. Assets

- sound conservative upper bounds операций;
- точность per-effect scope, target/resource identity и information-flow labels;
- manifest/operation/classifier/environment digests;
- policy decision и distinction `requested/manifested/derived/authorized/attempted/blocked/actual/committed/observed/verified`;
- authority attenuation, budget conservation и material-change binding;
- event/evidence records, позволяющие обнаружить classifier/implementation drift.

### 2.2. Adversaries/failures

- tool или model занижает effects, переименовывает destructive operation в benign action;
- shell/terminal/dynamic dispatch скрывает transitive sink;
- schema-valid/polyglot args меняют interpretation;
- GET/read создаёт access log, `atime`, lock или внешний signal;
- output→input, hashing/summary и control dependencies стирают taint только на словах;
- delegation размывает authority/budgets через proxy/child/collusion;
- persistent reflection меняет будущие policy/context/tool/model facts;
- concurrent registry/environment change создаёт TOCTOU между classification и dispatch.

### 2.3. Trust assumptions

1. Manifest и classifier сами не authority: trusted PEP сравнивает derived closure с physical/policy envelope.
2. Classifier version/digest, manifest digest, implementation digest и trusted environment facts pinned на весь call.
3. Dependency resolver возвращает immutable snapshot либо `UNKNOWN`; agent-supplied dependency claims не authoritative.
4. Runtime TCB/executor сообщает attempted/blocked/actual effects независимо от agent self-report для conformance detection.
5. Никакой human approval не превращает `UNKNOWN/TOP` в bounded effect vector.

## 3. Inputs, outputs и authoritative sources

### 3.1. Input

```text
ClassifyInput = {
  operation_id/version,
  implementation_digest,
  manifest_digest,
  canonical_args,
  input_labels,
  trusted_environment_facts,
  dependency_snapshot_digest,
  classifier_version/digest,
  principal_and_route,
  policy/contract/capability digests
}
```

`canonical_args` MUST быть получены type-specific canonicalizer-ом. Raw shell string, ambiguous URI/path/principal, unknown encoding или неполный dependency snapshot не являются bounded input.

### 3.2. Output

```text
EffectClassification = {
  direct_atoms: [EffectAtom],
  derived_closure: [EffectAtom] | UNKNOWN,
  information_flows: [FlowEdge],
  authority_facets: [AuthorityFacet],
  lifecycle_facets: [LifecycleFacet],
  resource_demand: BudgetVector,
  obligations: [Obligation],
  uncertainty/reason_codes,
  all_input_digests,
  classification_digest
}
```

`EffectAtom` — типизированная запись `(operation, effect_kind, resource_kind, scope_bound, temporal_extent, persistence, externality, reversibility, uncertainty)`. `scope_bound` зависит от `(operation,effect_kind,resource_kind)`; нельзя независимо комбинировать path scope одной операции с network scope другой.

### 3.3. Authoritative sources

- immutable manifest/registry/dependency snapshot;
- trusted canonicalizer и environment resolver;
- Level 0 physical profile;
- platform/project/contract/capability records;
- TCB/executor/observer actual-effect events.

Tool description, name, LLM reasoning и agent self-classification MAY быть hints, но не authoritative input допуска.

## 4. Денотационные и operational definitions

### 4.1. `COMPUTE`

`COMPUTE` преобразует уже объявленные inputs и потребляет локальные resource budgets, но само по себе не получает нового environment observation, не меняет persistent/external state и не пересекает principal/trust boundary.

Operational oracle: при одинаковых pinned inputs/environment и без других application effects меняются только ephemeral worker state и resource accounting. Harness-internal budget ledger transition классифицируется отдельно как controller operation; он не заставляет каждый worker `COMPUTE` автоматически получать application `MUTATE`. Если resource/timing pattern переносит signal другому principal, derived closure включает `COMMUNICATE`. Allocating CPU/memory — `ALLOCATE` facet/budget, а не новый primitive.

### 4.2. `OBSERVE`

`OBSERVE` читает environment state и создаёт information/taint effect независимо от изменения bytes источника. Scope MUST называть resource, operation/read projection, labels, purpose и retention.

Если чтение также обновляет `atime`, access/audit log, cursor, rate counter или lock, operation имеет и `MUTATE`. Network GET обычно также имеет `COMMUNICATE` из-за boundary crossing.

### 4.3. `MUTATE`

`MUTATE` создаёт, обновляет, удаляет, блокирует, резервирует, планирует или иным образом делает состояние persistent/observable для последующей операции или другого principal. External object change is `MUTATE(ENDPOINT,UPDATE)`. Scope MUST включать resource identity, allowed operation и state/delta bounds.

Создание lock, queue item, scheduled job, filesystem metadata, audit/access record и явная операция reservation shared capacity — mutation, даже если business payload «не изменён». Обязательное harness accounting исполняется как отдельная controller `MUTATE`; worker operation сохраняет собственный effect vector. Stageable/rollback/compensation — orthogonal properties, не отсутствие `MUTATE`.

### 4.4. `COMMUNICATE`

`COMMUNICATE` переносит информацию или signal через principal/trust boundary: user-visible output, child/broker message, external API/email, telemetry в иной trust domain и известные relevant covert/storage/timing channels.

Scope MUST назвать source, sink principal/resource, direction, protocol/medium, data labels, purpose/retention и quantitative bounds. Worker→broker IPC и broker gateway→provider — два отдельных flow edges.

### 4.5. `DELEGATE`

`DELEGATE` заставляет другой principal/agent действовать: spawn, queue, proxy, subagent request либо передача/attenuation authority. Обычно он одновременно `COMMUNICATE`; closure MUST включать conservative child effect upper bound и entire delegation-tree budgets.

Child authority MUST быть subset parent transferable envelope. Delegation без известного child manifest/envelope/lineage даёт `UNKNOWN`.

### 4.6. `REFLECT`

`REFLECT` меняет control-plane input, влияющий на будущие decisions/behavior: persistent memory, prompt/context assembly, plan/bundle, model/tool/adapter/config, policy, manifest, skill/registry selection.

Ephemeral self-critique/replanning только внутри текущего bounded context, никогда не persisted/transferred/tool-bound, — `COMPUTE`. Запись этой критики в memory или изменение будущего context — `MUTATE + REFLECT`; material digest/contract MUST измениться и прежние receipts/capabilities invalidated.

## 5. Orthogonal facets

| Facet | Значение | Нормативное правило |
|---|---|---|
| `AUTHORIZE/GRANT` | Authority transition | Требует отдельного issuer/receipt/capability; effect classification не выдаёт authority. |
| `DECLASSIFY` | Снижение confidentiality restriction для exact data/flow/sink/purpose/time | Отдельная capability; hash/schema/summary не являются declassification. |
| `ENDORSE` | Повышение integrity/trust label | Отдельная capability и evidence; не совмещается автоматически с declassification. |
| `PERSIST/SCHEDULE` | Temporal persistence или будущая activation | Отмечается вместе с `MUTATE` и conservative future effect closure. |
| `ALLOCATE` | Reservation/consumption resource budget | Требует atomic accounting; сам по себе не отменяет C/O/M/C/D/R effects. |
| `EXECUTE` | Lifecycle: authorized operation attempted/actual/committed | Статусы хранятся раздельно; название `EXECUTE` не заменяет effect vector. |

## 6. Effect algebra и dependent composition

### 6.1. Effect-set lattice

Для известных direct kinds:

```text
S ⊆ EffectKind
⊥e = ∅
S ⊔e T = S ∪ T
S ⊓e T = S ∩ T
⊤e = EffectKind, но UNKNOWN scope/dependency остаётся отдельным fail-closed marker
```

Union/intersection ассоциативны, коммутативны и идемпотентны. Однако effect set сам не является authority: без dependent scopes/flows/time/budgets/obligations он непригоден для `ALLOW`.

### 6.2. Dependent atoms/envelope

Для каждого `(operation,effect,resource)` существует свой `Bound`. Полная классификация — finite dependent map, как в formal core:

```text
operation/effect/resource ↦ {
  scope, flows, time, budgets, obligations, facets
}
```

Effective authorization получается pointwise restriction/denotational intersection, а не независимым cross product. Args MAY только сужать manifest upper bound. Если bind расширяет bound, call denied как manifest violation.

### 6.3. Sequence, parallel и closure

- `A ; B` — ordering-sensitive relational composition. В общем `A;B != B;A`.
- `A || B` — все разрешённые interleavings с shared-resource interference, atomic reservations и fencing. Симметричная абстракция допустима только для доказанно независимых partitions.
- `Cl(X)` добавляет transitive subtools/sinks, information/control dependencies, delegation descendants, scheduled future effects и persistent reflection. Для конечного pinned graph `Cl` монотонно, экстенсивно, идемпотентно.
- Restriction monotonicity: если `P' ⊑ P`, то `Cl(X) ⊓ P' ⊑ Cl(X) ⊓ P`.
- Неизвестный dynamic target/dependency/interpreter → `Cl(X)=UNKNOWN`, outcome `DENY/STOP`.

### 6.4. Information-flow composition

```text
OBSERVE(label=L, source=S)
  ; COMPUTE
  ; COMMUNICATE(sink=K)
```

создаёт flow `S→K` с label не ниже propagated confidentiality/taint и не выше доказанной integrity. Data и control dependencies учитываются. Hashing, summarization, validation и model transformation не снимают taint. Declassification и endorsement требуют разных exact-bound facets/capabilities.

### 6.5. Authority-flow composition

`DELEGATE(child)` добавляет child route, но:

```text
Envelope(child) ⊑ TransferableEnvelope(parent)
spent_parent + Σ(reserved_child + spent_child) ≤ parent_limit
```

`REFLECT` не может менять этот порядок внутри текущего contract. Любая material reflection создаёт новый digest и требует re-admission.

Каждый effect сохраняется как полный correlated authority clause. Классификатор MUST NOT отдельно объединять effect, selector, flow, label, time, quantity, concurrency, obligation или authority facet из разных clauses; request, manifest, policy, decision, capability и receipt используют одну каноническую clause serialization. Потеря корреляции даёт `TOP/UNKNOWN → STOP`.

### 6.1. Представимость и interference

Concrete representation MUST хранить finite disjunction of correlated clauses. Она не может отдельно объединять selectors, time windows, tenants, labels и purposes: union `{(/a,M),(/b,E)}` не разрешает `(/a,E)` или `(/b,M)`. Meet выполняет совместимую pairwise intersection с удалением empty clauses; join — set union с subsumption normalization. Если precise clause budget превышен, результат `TOP/UNKNOWN` и admission `STOP`, а не fieldwise over-approximation с `ALLOW`.

Для `A || B` classifier строит conflict keys из descriptor/resource identity, flow sink, authority facet, budget key и control-plane target. Общий mutable key требует serializable executor/fence или rejection. Количественные effects складываются checked arithmetic; duplicate `SEND`, spawn или write не исчезает из-за set-deduplication. Property suite MUST проверять lattice laws на representable clauses, correlation counterexamples, sequence non-commutativity, shared-write schedules и quantity preservation.

## 7. Boundary и ambiguous examples

| Operation | Direct/derived classification | Почему / required bound |
|---|---|---|
| Сложить два числа из уже переданного immutable input | `COMPUTE` | Только ephemeral state + bounded resources. |
| Прочитать файл по descriptor-root | `OBSERVE` | File identity/path projection и labels обязательны. |
| Прочитать файл на FS с `atime` или audit write | `OBSERVE + MUTATE` | Наблюдение вызывает persistent metadata/log mutation. |
| HTTP GET с ответом | `COMMUNICATE + OBSERVE`; часто `+ MUTATE` | Request/response пересекают boundary; server access log/rate state — mutation, если причинно входит в model. |
| HTTP POST, создающий внешний объект | `COMMUNICATE + MUTATE` и `OBSERVE`, если читается response | External non-stageable sink, idempotency/reconciliation required. |
| Записать/удалить/rename файл workspace | `MUTATE` | Stageability, path scope, delta/size и seal obligations отдельно. |
| Показать ответ человеку | `COMMUNICATE` | User-visible output пересекает principal boundary даже без network syscall worker-а. |
| Worker посылает model request broker-у; gateway — provider-у | Два `COMMUNICATE` edges; response даёт `OBSERVE` | Отдельные principals/envelopes, worker direct network всё ещё deny. |
| Spawn/queue subagent с context/capability | `DELEGATE + COMMUNICATE` + closure child effects | Child envelope attenuated, tree budgets/lineage mandatory. |
| Ephemeral self-critique в текущем context | `COMPUTE` | Не persisted/transferred/tool-bound и не меняет material digest. |
| Запись self-critique в persistent memory | `MUTATE + REFLECT` | Меняет future control input; labels/digest/contract invalidation. |
| Изменить prompt, model, tool config, manifest или policy | `MUTATE + REFLECT`; возможно `COMMUNICATE/DELEGATE` | Control-plane material change; отдельная governance transaction. |
| Создать scheduled email/job | `MUTATE` + `PERSIST/SCHEDULE`, closure будущего `COMMUNICATE`/other effects | Schedule state и future sink должны быть authorized сейчас или split transaction per policy. |
| Хешировать/суммировать tainted data | `COMPUTE`, labels сохраняются | Не `DECLASSIFY` и не `ENDORSE`. |
| Declassify и отправить данные | `COMMUNICATE` + exact `DECLASSIFY` facet/capability | Sink/data/purpose/time exact-bound; integrity отдельно. |
| Dynamic shell/terminal с произвольной строкой | `UNKNOWN/TOP` по умолчанию | Только finite command/arg grammar + transitive manifest + L0 confinement MAY дать bounded vector. |
| `git hash-object -w` или похожий «compute» tool | `MUTATE` persistent store; возможно `OBSERVE` | Имя/намерение не скрывает actual storage effect. |
| CPU load, наблюдаемый соседним tenant | `COMPUTE + COMMUNICATE` в соответствующей threat model | Известный timing channel включается; residual unknown channels документируются. |
| Lock/reservation без изменения business payload | `MUTATE` + `ALLOCATE` facet | Изменяет availability/state и budget ledger. |

## 8. Admission/classification rules и требования

| ID | Нормативное требование | Owner / enforcement point | Failure semantics | Test / evidence |
|---|---|---|---|---|
| `L1-REQ-001` | Каждая operation MUST иметь effect **set/vector**; one-hot enum MUST NOT использоваться как полная семантика compound call. | Manifest author + classifier | Schema/classification reject | `T-SCHEMA-L1-001`, `EV-SPEC-L1-SCHEMA-001` |
| `L1-REQ-002` | `COMPUTE` MUST исключать new observation, persistence и boundary flow; resource use учитывается отдельным budget/facet. | Classifier/PEP | Reclassify/deny unknown | `T-POL-L1-COMPUTE-001` |
| `L1-REQ-003` | Любое чтение environment state MUST включать `OBSERVE` и labels; read-induced metadata/log/cursor/lock changes MUST добавлять `MUTATE`. | Classifier + dependency resolver | Conservative expansion или deny | `T-POL-L1-OBSERVE-001` |
| `L1-REQ-004` | Create/update/delete/block/lock/явная reservation/schedule/persist state MUST включать `MUTATE`, независимо от reversibility/idempotency. Mandatory harness accounting MUST моделироваться отдельной controller operation и не скрываться. | Classifier | Deny underclassification | `T-POL-L1-MUTATE-001` |
| `L1-REQ-005` | Любой data/signal crossing principal/trust boundary MUST включать `COMMUNICATE` с exact flow labels/source/sink/direction/purpose/retention. | Flow classifier/PEP | Block flow; incident if attempted | `T-POL-L1-COMM-001` |
| `L1-REQ-006` | Spawn/queue/proxy/authority transfer MUST включать `DELEGATE`, child closure и attenuated envelope/tree budgets. | Delegation broker | Deny/revoke subtree | `T-POL-L1-DELEGATE-001` |
| `L1-REQ-007` | Persistent/authority-relevant future control change MUST включать `MUTATE+REFLECT` и material digest invalidation. | Context/governance PEP | Stop current receipt/capability; new admission | `T-POL-L1-REFLECT-001` |
| `L1-REQ-008` | Ephemeral self-critique MAY быть `COMPUTE` только если не persisted, не transferred, не превращена в reusable candidate/branch, не tool/target/dispatch-bound и не меняет future control input. Обычный учёт compute/token resources не делает её `REFLECT`. | Controller/context assembler | Если условие не доказано — `REFLECT`/unknown | `T-POL-L1-REFLECT-002` |
| `L1-REQ-009` | `AUTHORIZE`, `DECLASSIFY`, `ENDORSE`, `PERSIST/SCHEDULE`, `ALLOCATE`, `EXECUTE` MUST храниться как typed orthogonal facets/relations, не implicit permissions. | Schema/policy owner | Missing required facet → deny | `T-SCHEMA-L1-FACET-001` |
| `L1-REQ-010` | Classifier MUST вычислять `derived = Cl(bind(manifest, canonical_args, trusted_environment_facts))`, включая subtools/sinks/data/control/delegation/reflection dependencies. | Trusted classifier/PEP | Unknown/missing closure → `DENY/STOP` | `T-POL-L1-CLOSURE-001` |
| `L1-REQ-011` | Runtime args MUST только сужать manifest bounds. Derived atom вне manifest upper bound MUST быть rejected до dispatch. | PEP | `DENY/RC_MANIFEST_EXCEEDED` | `T-POL-L1-BIND-001` |
| `L1-REQ-012` | Scope MUST быть dependent typed bound per `(operation,effect,resource)`; независимый cross product эффектов/scopes/flows запрещён. | Schema/compiler/PEP | Invalid envelope → stop | `T-POL-L1-DEPENDENT-001` |
| `L1-REQ-013` | Dynamic shell/terminal/eval/interpreter MUST быть `UNKNOWN/TOP`, если finite grammar, transitive closure и physical confinement не доказаны. | Classifier/PEP | `DENY/STOP`; human не override | `T-ATTACK-L1-SHELL-001` |
| `L1-REQ-014` | Confidentiality, integrity, provenance, taint, purpose и retention MUST распространяться по data/control dependencies. | Flow engine | Flow deny/quarantine | `T-POL-L1-FLOW-001` |
| `L1-REQ-015` | Declassification и endorsement MUST требовать разные exact-bound capabilities; hash/schema/summary/model output MUST NOT выполнять их автоматически. | Flow PEP/capability issuer | Deny sink/label change | `T-ATTACK-L1-TAINT-001` |
| `L1-REQ-016` | Sequential composition MUST сохранять order/state dependency; parallel composition MUST моделировать interference, atomic budgets и fencing. | Planner/controller | Inadmissible schedule → stop | `T-POL-L1-COMPOSE-001`, `T-LTS-L1-CONC-001` |
| `L1-REQ-017` | Unknown/unclassified/unbounded/missing/stale/mismatched effect fact MUST NOT стать implicit allow или approvable request. | PEP | `DENY/STOP/INV-015` | `T-POL-L1-UNKNOWN-001` |
| `L1-REQ-018` | Material change operation/tool/model/prompt/context/manifest/policy/contract/target MUST invalidate classification/decision/receipt/capability. | Digest resolver/PEP | Reclassify/re-admit | `T-POL-L1-MATERIAL-001` |
| `L1-REQ-019` | Desired, requested, manifested, derived, authorized, attempted, blocked, actual, committed, observed и verified vectors MUST логироваться раздельно. | Controller/TCB/observer | Missing safety vector → stop/quarantine by risk profile | `T-SCHEMA-L1-STATUS-001` |
| `L1-REQ-020` | Каждый principal hop MUST классифицироваться отдельно; broker-owned `COMMUNICATE` MUST NOT расширять worker physical envelope. | Route compiler/PEP | Deny route/kill bypass | `T-POL-L1-ROUTE-001` |
| `L1-REQ-021` | Authoritative attempted/blocked/actual events MUST исходить от PEP/TCB/executor/observer; agent self-report только diagnostic. | Telemetry issuer | Evidence insufficient; stop/quarantine | `T-ATTACK-L1-SELFREPORT-001` |
| `L1-REQ-022` | Compiled effects for a worker MUST be a subset of its attested physical ceiling. Worker `COMMUNICATE` is a proposal-only edge to broker IPC; external communication is a separate broker/model-gateway sink hop, and worker `MUTATE` requires a distinct mediated executor route. | Trusted classifier + L0/L3 PEP | `DENY/RC_PHYSICAL_CEILING` | `T-Q46-DIRECT-WORKER-MUTATE-DENY`, `T-Q47-MUTATION-SELF-AUDIENCE-DENY`, `T-DECISION-ALLOW-EXACT` |

## 9. Invariants, preconditions и postconditions

### 9.1. Level invariants

- `L1-I1`: `direct_effects ⊆ derived_closure`; closure не теряет effect.

- `L1-I1a`: every derived edge resolves to a complete typed manifest authority clause; unresolved, cyclic or unbounded edges produce `UNKNOWN/STOP`, and authorization consumes every reachable clause.
- `L1-I2`: `authorized ⊆ manifested ⊓ physical`; underclassified committed effect нарушает `INV-005`.
- `L1-I2a`: `compiled_worker_effects ⊆ Physical(worker)`; worker `COMMUNICATE` can only propose the broker hop and worker `MUTATE` is never an executable audience/route.
- `L1-I3`: labels не ослабляются через compute/hash/schema/summary без exact declassification/endorsement transitions.
- `L1-I4`: child closure/envelope ≤ transferable parent envelope, budgets conserved.
- `L1-I5`: material reflection делает прежние classification/receipts stale.
- `L1-I6`: `UNKNOWN/TOP` никогда не приводит к `ALLOW`.

Они конкретизируют `INV-003/005/006/007/009/010/013/015`.

### 9.2. Preconditions `CLASSIFIED→DECIDED`

1. Operation/implementation/manifest/classifier/dependency/environment digests pinned and matching.
2. Args canonical and type-valid.
3. Every direct/transitive atom has typed resource/scope/flow/time/budget/obligations.
4. Closure finite and not `UNKNOWN`.
5. Input labels complete; any declassification/endorsement capability exact and fresh.
6. Principal route and each boundary edge explicit.

Failure → `DENY/STOP`; classification не dispatch-ит.

### 9.3. Postconditions

- classification digest deterministically binds all inputs and output atoms;
- `derived_closure` is conservative and fits manifest upper bound, иначе denial record;
- reason codes and uncertainty explicit;
- downstream decision/capability/event/receipt reference same classification digest;
- later attempted/actual events can be compared atom-by-atom to authorized classification.

## 10. Failure, timeout, crash, retry, recovery и revocation

| Event | Required semantics |
|---|---|
| Invalid/noncanonical args | `DENY/RC_SCHEMA_INVALID`; no capability/dispatch. |
| Missing dependency/environment fact | `STOP/RC_UNKNOWN`; no human approval path while unbounded. |
| Manifest/implementation/classifier digest mismatch | Invalidate classification/decision/receipt; resolve pinned version anew. |
| Classifier crash/timeout | Pure evaluation leaves no authority/state change; retry MAY recompute from same immutable snapshot, bounded by controller policy. |
| Registry changes concurrently | Current immutable snapshot remains bound or call stops; no mid-call upgrade. New version requires new classification. |
| Runtime attempted effect outside derived/authorized | L0/PEP blocks and emits event; possible committed effect → containment/quarantine/incident. Manifest must be corrected only through governance. |
| Unknown external outcome | Actual remains `UNKNOWN`; no effect reclassification to failure/success and no auto-retry. |
| Revoked tool/manifest/policy/capability | All cached classifications referencing it become stale; pending calls denied/cancelled; in-flight effect reconciled by L3. |
| Recovery/replay | Classification MAY be recomputed, but capability/counters/lineage remain durable; same classification does not authorize replay. |

## 11. Telemetry и evidence

Для каждого call authoritative event chain MUST включать:

- operation/tool/version/implementation/manifest/classifier/dependency/environment digests;
- canonical args hash и input label summary (privacy-safe, full data access-controlled);
- direct atoms, derived closure, unknown/reason codes;
- per-atom scope/flow/time/budget/obligation/facets;
- desired/requested/manifested/derived/authorized/attempted/blocked/actual/committed/observed/verified vectors separately;
- principal route and delegation lineage;
- material-change invalidation/reclassification event;
- conformance mismatch/containment outcome.

Safety events MUST быть unsampled. Arbitrary args, paths, endpoints, hashes и IDs не должны становиться unbounded metric labels. Evidence MUST быть tied to exact classifier/manifest/runtime digests and environment scope.

## 12. Test matrix

| Test ID | Type | Fixture | Oracle | Expected evidence | Status |
|---|---|---|---|---|---|
| `T-SCHEMA-L1-001` | Positive/negative | Compound vector; one-hot-only, unknown effect, untyped scope/flow/facet | Compound accepted; invalid variants rejected | `EV-SPEC-L1-SCHEMA-001` | `PLANNED/ABSENT` |
| `T-POL-L1-COMPUTE-001` | Boundary | Pure input transform; transform with new read/persist/flow | First is `COMPUTE`-only; second cannot remain `COMPUTE`-only | Classifier vectors/reasons | `PLANNED/ABSENT` |
| `T-POL-L1-OBSERVE-001` | Boundary | File read vs atime/audit/cursor side effect | `OBSERVE` vs `OBSERVE+MUTATE` exactly | Classifier vectors/reasons | `PLANNED/ABSENT` |
| `T-POL-L1-MUTATE-001` | Positive/negative | create/update/delete/lock/reserve/schedule; benign label | State-changing fixtures include `MUTATE`; benign label cannot suppress | Classification report | `PLANNED/ABSENT` |
| `T-POL-L1-COMM-001` | Boundary | user output, worker→broker, gateway→provider, HTTP GET/POST | Every trust crossing has explicit C edge and labels | Flow graph evidence | `PLANNED/ABSENT` |
| `T-POL-L1-DELEGATE-001` | Positive/adversarial | Valid attenuated child; broader child/fanout/cycle/proxy laundering | Valid accepted; amplification denied | Delegation tree/decision trace | `PLANNED/ABSENT` |
| `T-POL-L1-REFLECT-001` | Boundary | Ephemeral critique vs persistent memory/prompt/tool/policy update | C-only vs M+R and material invalidation | Before/after digest trace | `PLANNED/ABSENT` |
| `T-POL-L1-REFLECT-002` | D2/boundary | Private ephemeral critique with ordinary resource accounting vs persisted/reusable/tool/target-bound N+2 branch | Первый случай остаётся `COMPUTE`; второй — `MUTATE+REFLECT` и/или D2 denial | Context/branch/digest trace | `PLANNED/ABSENT` |
| `T-SCHEMA-L1-FACET-001` | Negative | Declassify/endorse/schedule/allocate/execute encoded as effect or implicit flag | Rejected; distinct typed facet required | Schema report | `PLANNED/ABSENT` |
| `T-POL-L1-CLOSURE-001` | Property | Finite dependency graphs, nested tools/sinks | Closure extensive/monotone/idempotent; no dependency lost | `EV-SPEC-L1-ALG-001` | `PLANNED/ABSENT` |
| `T-POL-L1-BIND-001` | Property/adversarial | Args narrow/equal/widen manifest scope | Narrow/equal accepted for policy step; widen denied | Bind decision vectors | `PLANNED/ABSENT` |
| `T-POL-L1-DEPENDENT-001` | Negative/property | Swap path/network/principal scopes across operations | Unsafe cross-product impossible/rejected; meet monotone | Type/property report | `PLANNED/ABSENT` |
| `T-ATTACK-L1-SHELL-001` | Adversarial | Shell/eval/polyglot/dynamic subcommand/transitive binary | UNKNOWN/DENY unless finite grammar+closure+L0 proof | Attack/classifier trace | `PLANNED/ABSENT` |
| `T-POL-L1-FLOW-001` | Property | `OBSERVE→COMPUTE→COMMUNICATE` with data/control dependencies | Labels/source/sink/purpose/retention preserved | Flow property report | `PLANNED/ABSENT` |
| `T-ATTACK-L1-TAINT-001` | Adversarial | Hash/summary/schema/model paraphrase + unauthorized sink; endorse/declass confusion | Taint persists; sink denied; distinct capabilities required | Taint/decision trace | `PLANNED/ABSENT` |
| `T-POL-L1-COMPOSE-001` | Algebra | `⊔/⊓` laws; sequence order counterexamples; independent parallel fixtures | Lattice laws pass; noncommutativity retained; unsafe interference denied | `EV-SPEC-L1-ALG-002` | `PLANNED/ABSENT` |
| `T-LTS-L1-CONC-001` | Concurrency | Parallel operations share target/budget; registry update race | Atomic reservation/fencing; immutable snapshot or stop | Schedule/fault traces | `PLANNED/ABSENT` |
| `T-POL-L1-UNKNOWN-001` | Exhaustive finite partitions | Unknown enum/scope/dependency/label/stale digest | Никогда `ALLOW/REQUIRE_HUMAN`; only deny/stop | Decision vector report | `PLANNED/ABSENT` |
| `T-POL-L1-MATERIAL-001` | Fault | Change each material digest between classify/admit/dispatch | Stale decision/capability rejected | Transition trace | `PLANNED/ABSENT` |
| `T-SCHEMA-L1-STATUS-001` | Positive/negative | All effect-status vectors vs conflated/missing records | Separate vectors required; missing risk event fails | Event schema report | `PLANNED/ABSENT` |
| `T-POL-L1-ROUTE-001` | Positive/negative | Worker disconnected + broker gateway communicate; worker inherits gateway FD | Valid two-hop route accepted; inheritance/direct flow denied | Route/L0/decision trace | `PLANNED/ABSENT` |
| `T-ATTACK-L1-SELFREPORT-001` | Fault/adversarial | Agent claims C-only/success while TCB sees M/C or block | Authoritative vector wins; mismatch incident | TCB/agent comparison evidence | `PLANNED/ABSENT` |

Finite enums, algebra laws и transition partitions MAY быть exhaustive. Unbounded paths/URIs/args/programs требуют equivalence/boundary/property/fuzz/mutation tests; V0 не обещает exhaustive semantic prediction. Ни один тест здесь не выполнен.

## 13. Residual risks и unsupported claims

- Консервативный classifier может over-classify и снизить availability; это предпочтительнее implicit allow, но требует reason codes и decomposition path.
- Semantic effects внешнего service могут измениться без локального binary digest; environment/provider facts и conformance monitoring обязательны.
- Covert channels могут быть неизвестны; известные channels включаются в closure, остальные остаются residual risk Level 0/threat profile.
- `COMMUNICATE` охватывает declared principal flows, но не доказывает confidentiality без encryption/access/retention controls.
- `REFLECT` boundary зависит от materiality rule; все неочевидные persistent/control changes должны считаться material до governance resolution.
- Signature/digest доказывают identity/integrity binding, но не semantic soundness manifest/classifier.
- Шесть primitives — минимальная V0 taxonomy. Их достаточность должна проверяться corpus/implementation counterexamples; расширение требует migration impact и обновления schemas/tests.
- Утверждения DOCX о теоремах/невозможности являются unverified external narrative; V0 не опирается на них. Fail-closed `UNKNOWN` и finite configured inventory достаточны для этой спецификации.

## 14. Definition of Done

| Stage | Level 1 DoD |
|---|---|
| `DECLARED/SPECIFIED` | Definitions/boundaries/facets/algebra однозначны; `L1-REQ-001..021` имеют owner/failure/test/evidence; schemas закрыты; finite decision/algebra vectors проходят. |
| `IMPLEMENTED` | Trusted canonicalizer/classifier/dependency resolver/flow engine/PEP работают на pinned digests; route-specific derived closure связан с capability/events; TCB actual-effect collection существует. |
| `VERIFIED` | Independent positive/negative/adversarial/concurrency/fault and conformance tests поддерживают заявленный conservative upper-bound claim для pinned finite operation set в точном environment и подтверждают fail-closed unknown behavior; scope/expiry evidence и residual limitations указаны. |

Текущий честный статус: Level 1 semantics сформулирована; classifier, schema validation, property tests, runtime conformance и evidence отсутствуют. `actual_skill_set_verified=false` и dynamic registry disabled остаются явными ограничениями; V0 использует только immutable digest-pinned registry snapshot semantics.

## 15. Source-vs-new traceability

| Тема | Corpus source | V0 disposition |
|---|---|---|
| Шесть effects | DOCX `word/document.xml#p0845-p0878, p0913-p0918`; `metaprompt-harness-levels-0-5-ru.md:208-239` | Сохранены как non-exclusive set/vector; external completeness claims не повторены. |
| Diff разрешает только C/O/M и workspace constraints | `HARNESS_ACTIVATION_DIFF.md:42-75,473-506` | Это exact minimal profile, не вся ontology; C/D/R известны и explicit deny в LX-A. |
| Effect algebra/dependent authority | `metaprompt...:147-167,222-239` | Уточнено dependent map, laws, sequence/parallel/closure и separation facets как новое нормативное требование. |
| Tool proposal/shell/polyglot | `security.md:48-62`; `comparison.md:179-192` | Dynamic shell default UNKNOWN; args narrow only; transitive sinks mandatory. |
| Evidence/steganography/N→N+1 | `security.md:120-153`; `comparison.md:113-118,165-171` | Явные flow labels/control deps; hash/schema/summary не declassify/endorse. |
| Adapter/skill registry poisoning | `security.md:128-153`; `comparison.md:193-199` | Immutable digest-pinned snapshot; dynamic registry disabled; material change invalidates. |
| Boundary examples GET/atime/POST/self-reflection | `metaprompt...:208-239` | Нормативно классифицированы в §7 и покрыты tests. |
| Narrative constrain/inform/verify/correct | `harness_connected_text.md:9-19,41-43` | Использовано как proposal/context; unverifiable external product/research claims исключены. |

## Closed authority atom

`(effect, resource_kind, operation)` is one shared closed relation, not three independent allowlists. Every authority, compiled envelope, manifest bound, approval projection, event and effect receipt MUST reject a tuple outside that relation before containment or digest comparison. The complete cross-product schema-and-semantic negative oracle is owned by `17_ATTACK_TEST_AND_EVIDENCE_MATRIX.md`.
