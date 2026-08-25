# 01 — Реестр противоречий и пробелов

## Статус и правила диспозиции

Этот реестр относится к frozen corpus с aggregate SHA-256 `08a296ee00349eac64d13292e4d4c714d1de0cd412adca1c695ef5e5f92838e0`. Он не переписывает исторические документы: ниже зафиксирована нормативная диспозиция для нового пакета.

Метки:

- `RESOLVED_SPEC` — конфликт разрешён в новой спецификации; runtime ещё не доказан.
- `OPEN_IMPLEMENTATION` — требование определено, но реализации/evidence нет.
- `OPEN_PROFILE` — требуется решение владельца конкретной среды или калибровка.
- `PROVISIONAL` — локальная семантика введена явно из-за отсутствия авторитетного определения.
- `UNVERIFIED_EXTERNAL_CLAIM` — утверждение нельзя использовать как evidence этого пакета.
- `REJECTED_CLAIM` — формулировка логически или эмпирически сильнее имеющихся оснований.

`RESOLVED_SPEC` не означает `IMPLEMENTED`, `ENFORCED`, `MONITORED` или `VERIFIED`.

## Нормализованный конфликтный реестр

| ID | Источники/локаторы | Конфликт или пробел | Нормативная диспозиция | Статус |
|---|---|---|---|---|
| CFG-001 | `security.md:9–171`, `security.md:177–190`, `synthesis.md:15–23` | Названо 14 gaps, но механически есть 18 numbered subsections; summary содержит 12 строк. | Сохранить все 18 как source findings; summary rows и C1–C10 связать total mapping, не выдавая merge за исчезновение. | `RESOLVED_SPEC` |
| CFG-002 | `synthesis.md:15,20,111,121–125` | Заявлены 4 Critical, но перечислены пять: R1–R5. | Canonical count исторического реестра: 15 risks, 5 Critical. | `RESOLVED_SPEC` |
| CFG-003 | `synthesis.md:38,57,75,90,232` | «10 → 13», но перечислены четыре additions; арифметика/dedup отсутствуют. | Не переносить count как факт; roadmap строить по dependencies/gates. | `RESOLVED_SPEC` |
| CFG-004 | `formal.md:10–12,72–88`; `metaprompt…md:115,178` | «Law-of-cut/D2 preserved» утверждается без авторитетных определений и executable semantics. | Ввести явно `PROVISIONAL` локальные определения; не заявлять доказательство source theorem. | `PROVISIONAL` |
| CFG-005 | весь corpus | `CB5`, controller `JOIN`, law-of-cut, `D2`, `JR5`, `LRP1_D`, `S5`, `RJ*`, `B3`, `authority domain`, `P2`, `R0–R6` не имеют найденных authoritative definitions. | Словарь перечисляет каждый термин и границу локального определения. Замена требует material-change review. | `PROVISIONAL` |
| CFG-006 | `formal.md:36–66`; `metaprompt…md:147–161` | Независимое `Effects × Scopes` может синтезировать ложные пары полномочий. | Envelope — зависимая конечная map `(effect, operation, resource) → scope bound` плюс flows/time/budgets/obligations; meet по допустимым действиям. | `RESOLVED_SPEC` |
| CFG-007 | `HARNESS_ACTIVATION_DIFF.md:48–68`; `metaprompt…md:208–237` | Diff знает только COMPUTE/OBSERVE/MUTATE, хотя transfer, delegation и reflection реально возможны. | Ontology знает шесть compound effects. Минимальный pilot явно DENY `COMMUNICATE/DELEGATE/REFLECT`, кроме отдельно описанного broker model channel. | `RESOLVED_SPEC` |
| CFG-008 | `HARNESS_ACTIVATION_DIFF.md:171–177`; `practical.md:32`; `synthesis.md:74,175–178` | `SKILL_REGISTRY_ACTIVE` одновременно required, deferred и предлагается удалить без revised diff. | Первый профиль использует immutable signed/content-addressed registry snapshot, bound к image/broker digest; dynamic updates запрещены. | `RESOLVED_SPEC`; `OPEN_IMPLEMENTATION` |
| CFG-009 | `HARNESS_ACTIVATION_DIFF.md:65,241–267` | `network_egress=false` сосуществует с model/app/protocol/terminal gateways. | Запрет относится к worker. Broker-owned model/provider gateway — отдельный principal и declared `COMMUNICATE` sink; worker не наследует его sockets/FDs/credentials. | `RESOLVED_SPEC`; `OPEN_IMPLEMENTATION` |
| CFG-010 | `practical.md:19–20,61–62`; `metaprompt…md:143–145` | UUID/TTL в RAM и JSONL ledger не дают atomic consume/reserve/dispatch и переживание crash. | Pure decision отделён от serializable durable transition; capability consumption, reservation, dispatch intent, counters и outbox commit атомарны. | `RESOLVED_SPEC`; `OPEN_IMPLEMENTATION` |
| CFG-011 | `security.md:39–46`; `synthesis.md:89,96` | Read-only sidecar/mount ошибочно сближается с immutable snapshot; concurrent writer остаётся. | `freeze/revoke writers → quiescence receipt → immutable snapshot/seal → independent postcheck → commit/JOIN`; mismatch → quarantine. | `RESOLVED_SPEC`; `OPEN_IMPLEMENTATION` |
| CFG-012 | `practical.md:15,63`; `security.md:112–118`; `metaprompt…md:191–206` | PATH filtering, chroot, iptables, `docker --rm` и wildcard cleanup названы/использованы как будто sufficient controls. | Это defense-in-depth, не boundary. L0 требует profile-specific TCB enforcement и attestation; wildcard cleanup не security oracle. | `REJECTED_CLAIM`; `OPEN_IMPLEMENTATION` |
| CFG-013 | `HARNESS_ACTIVATION_DIFF.md:276–288,455–465`; `security.md:120–144` | Output→input/evidence transfer объявлен не-authority, но является communication/control channel и несёт injection/taint. | Каждый transfer — `COMMUNICATE`; agent output остаётся untrusted data. Typed admission, provenance, taint и purpose обязательны; hash/schema/summary не снимают taint. | `RESOLVED_SPEC`; `OPEN_IMPLEMENTATION` |
| CFG-014 | `security.md:101–134`; `metaprompt…md:332` | Fresh container/session смешан с отсутствием межитерационного information flow. | Это разные claims. Разрешённая memory/evidence flow объявляется, versioned, scoped, taint-tracked и audited. | `RESOLVED_SPEC` |
| CFG-015 | `HARNESS_ACTIVATION_DIFF.md:410–428`; `formal.md:98–99`; DOCX `word/document.xml#p0559` | Per-contract human confirmation, per-iteration controller JOIN и lattice join смешиваются. | Approval receipt один раз активирует immutable contract; каждая итерация имеет fresh capability и machine JOIN. Approval — predicate/evidence, не `⊔` и не controller JOIN. | `RESOLVED_SPEC` |
| CFG-016 | `practical.md:18,40,55–58`; `synthesis.md:49–57`; `metaprompt…md:74,316–318` | HMAC, Ed25519 human signature, click-through и service receipt представлены как взаимозаменяемые. | Human auth decision, optional human key signature и service-signed canonical receipt — разные evidence. Signature не доказывает comprehension. | `RESOLVED_SPEC`; `OPEN_IMPLEMENTATION` |
| CFG-017 | `HARNESS_ACTIVATION_DIFF.md:61–63`; `metaprompt…md:185,281` | `unknown` выглядит approvable. | `UNKNOWN/TOP`, unbounded, mismatched или stale → `DENY/STOP`; human может запросить evidence, но не расширить hard ceiling. | `RESOLVED_SPEC` |
| CFG-018 | `HARNESS_ACTIVATION_DIFF.md:318,365`; `practical.md:43`; `synthesis.md:192–195` | Freshness/revocation одновременно marked available и deferred. | Проверка обязательна при receipt issue/activation, capability issue и перед dispatch; отсутствие feed/uncertain time для risky action → STOP. | `RESOLVED_SPEC`; `OPEN_IMPLEMENTATION` |
| CFG-019 | `HARNESS_ACTIVATION_DIFF.md:432–434`; `practical.md:34`; `metaprompt…md:316` | Quorum выражен числом owners, не независимыми principals; SoD не определена. | Requester/approver/issuer/executor/observer/risk owner — distinct roles; quorum считает eligible distinct principals and credentials. | `RESOLVED_SPEC`; `OPEN_PROFILE` |
| CFG-020 | `HARNESS_ACTIVATION_DIFF.md:545–557`; `practical.md:35,128`; `synthesis.md:166–169,192–195` | Break-glass выключен, но roadmap допускает production до полного protocol/evidence. | Пока protocol не enforced/tested — emergency request STOP. Break-glass никогда не пересекает immutable L0/platform ceiling. | `RESOLVED_SPEC`; `OPEN_IMPLEMENTATION` |
| CFG-021 | `harness_connected_text.md:19`; `metaprompt…md:306,332,336` | «Человек разрулит всё» конфликтует с human fallibility/threat model. | Human control — fallible governance layer; unbounded/uncontainable action остаётся deny. | `REJECTED_CLAIM` |
| CFG-022 | `synthesis.md:150–154`; `metaprompt…md:480–504` | Residual risk acceptance не имеет authority/receipt semantics. | Critical не defer; High не accept агентом; Medium требует authorized human risk-owner receipt с scope, rationale, controls, TTL, expiry/review date. | `RESOLVED_SPEC`; текущих receipts нет |
| CFG-023 | `synthesis.md:32–38,52–57,87–91,119–135` | `Formal/Security/Practical` названы owners, хотя это lenses. | Назначены accountable functions: platform, policy, runtime, service/resource, SRE/IR, privacy, governance/risk, assurance. Конкретные identities остаются profile input. | `RESOLVED_SPEC`; `OPEN_PROFILE` |
| CFG-024 | `HARNESS_ACTIVATION_DIFF.md:293–325`; `metaprompt…md:287–302` | Один event/iteration и hash-chain ledger недостаточны для crash reconstruction; witness отсутствует. | Canonical per-transition events + transactional outbox + emitter sequences/signatures. Без independent anchor claim только tamper-evident, не rollback-proof. | `RESOLVED_SPEC`; `OPEN_IMPLEMENTATION` |
| CFG-025 | DOCX `word/document.xml#p0646–p0648`; `metaprompt…md:296` | Unbounded `contract_hash`/loop signature labels создают cardinality/privacy risk; thresholds не обоснованы. | Metrics labels — finite allowlists; IDs/digests/args остаются restricted logs/traces/evidence. Thresholds profile-calibrated. | `RESOLVED_SPEC`; `OPEN_PROFILE` |
| CFG-026 | DOCX `word/document.xml#p0647–p0648,p0737,p0740`; `metaprompt…md:300–302` | Три alerts и vanity count «≥10 metrics» не покрывают safety lifecycle; optional trace конфликтует с reconstructability. | Detection-response catalog привязан к invariant, owner, action, runbook and closure evidence; zero-tolerance cases не имеют error budget. | `RESOLVED_SPEC`; `OPEN_IMPLEMENTATION` |
| CFG-027 | `HARNESS_ACTIVATION_DIFF.md:256–261,312–313,367`; `formal.md:20–27`; `practical.md:24–43` | `actual_skill_set_verified`, runtime isolation, trusted receipt, witness, observer и technical evidence отсутствуют, но prose местами звучит как pass. | Каждое отсутствие — explicit implementation blocker. Boolean declarations никогда не evidence. | `REJECTED_CLAIM`; `OPEN_IMPLEMENTATION` |
| CFG-028 | `formal.md:82–88`; narrative analogies | Rice/halting/Gödel language используется шире доказанного. | Корректная граница: невозможно sound+complete решить произвольную semantic behavior property для всех программ; finite abstraction/known operations проверяемы. Gödel не нужен для runtime claim. | `RESOLVED_SPEC` |
| CFG-029 | `HARNESS_ACTIVATION_DIFF.md:30,123–124,495–502`; `practical.md:49–70,127`; `synthesis.md:17,38,60,75,90,112`; DOCX `#p0671–p0703,#p0744–p0758` | Числа limits, thresholds и сроки представлены без calibration/evidence. | Все числа — non-normative profile examples или `TBD_BY_CALIBRATION`; roadmap без duration promises. | `RESOLVED_SPEC`; `OPEN_PROFILE` |
| CFG-030 | `harness_connected_text.md:3,15,39` и связанные narrative claims | Внешние расходы, эксперименты, исследования и масштабы не подтверждены corpus evidence. | Не используются для requirements/readiness; retained as narrative-only unverified assertions. | `UNVERIFIED_EXTERNAL_CLAIM` |
| CFG-031 | `HARNESS_ACTIVATION_DIFF.md:285–287`; `metaprompt…md:117–145` | Одна transaction story применяется к stageable и irreversible external effects. | Common admission разделён на stageable branch, non-stageable branch и new compensation transaction. `UNKNOWN_OUTCOME` запрещает auto-retry. | `RESOLVED_SPEC` |
| CFG-032 | `metaprompt…md:176`; corpus delegation prose | Формула tree budget допускает неоднозначный двойной счёт reserved/spent. | Linear escrow transfer: `Σspent + Σescrow(live/quarantined)=initial`; depth/nodes/retries — monotonic non-reclaimable counters. | `RESOLVED_SPEC`; `OPEN_IMPLEMENTATION` |
| CFG-033 | `synthesis.md:124–125,215,217` | Некоторые risk→counterexample mappings неверны или many-to-one без merge record. | Новый attack catalog хранит source locator и total mapping; no unmapped source row. | `RESOLVED_SPEC` |
| CFG-034 | corpus placement/roadmap | `P2` перегружен как placement/risk label и roadmap phase. | Локально использовать `PLACEMENT-P2-PROVISIONAL` и `MILESTONE-M2`. | `RESOLVED_SPEC` |
| CFG-035 | весь corpus | Static manifest, actual-effect receipt, human approval, formal verification, hash и fresh container периодически сближаются. | Спецификация поддерживает пять явных non-equivalences и отдельные evidence maturity fields. | `RESOLVED_SPEC` |

## Открытые решения, которые нельзя безопасно выдумать

| Gap | Требуемый human/environment input | До решения |
|---|---|---|
| Точный kernel/container/microVM/host profile и hostile-host assumption | Platform security owner | Только specification; никакого L0 attestation claim |
| Реальный tool/skill/plugin/MCP inventory и implementation digests | Tool registry owner | `actual_skill_set_verified=false`; undeclared operation denied |
| Principals, tenants, data classes, purposes, retention/legal-hold regimes | Governance/privacy owners | External/sensitive flows disabled or `DENY` |
| Model/provider topology и permitted data egress | Platform/data owner | Worker disconnected; gateway channel limited to declared test profile |
| Policy limits, SLO/alert thresholds, benchmark margins | Service owner with calibration evidence | `TBD_BY_CALIBRATION`; hard invariants retain zero tolerance |
| Approval classes, eligible roles, quorum, TTL and emergency profiles | Governance/security owners | Production activation and break-glass disabled |
| Anti-rollback witness/anchor and key infrastructure | Security/platform owners | Ledger claim limited to local tamper evidence |
| External effect idempotency/reconciliation/compensation | Connector/resource owner | Non-stageable effects disabled |
| Authoritative project-term definitions | Project authority | Local definitions remain `PROVISIONAL`; material change on replacement |

## Логическая граница overclaim

Пакет не утверждает: полную изоляцию; исчерпывающую классификацию произвольного кода; нулевые covert channels; обнаружение всех аномалий; безошибочное человеческое понимание; anti-rollback без witness; production readiness; или работоспособную реализацию. Нормативное уточнение конфликта не является evidence исполнения.
