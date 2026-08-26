# 03. Системная модель угроз и доверия

## 0. Паспорт и утверждаемая граница

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
| Corpus snapshot | aggregate source SHA-256 `08a296ee00349eac64d13292e4d4c714d1de0cd412adca1c695ef5e5f92838e0` |

Слова **MUST / MUST NOT / SHOULD / MAY** нормативны в смысле RFC 8174.

Модель считает вывод agent/model потенциально злонамеренным или скомпрометированным. Она не заявляет полную изоляцию, отсутствие всех side/covert channels, корректность kernel/hypervisor, безошибочность человека, semantic soundness manifest или наличие работающего runtime. Все attack statuses ниже — `OPEN/UNTESTED`, пока нет evidence от pinned implementation/environment.

## 1. Цель, claims и non-goals

### 1.1. Цель

Модель ДОЛЖНА позволять для каждой операции ответить:

1. какой principal инициировал request и какой principal фактически совершает effect;
2. какие assets и trust boundaries затрагиваются;
3. какой dependent authority envelope и information-flow edge требуются;
4. где prevention, detection, containment/recovery и evidence;
5. какой минимальный counterexample опровергает claim при отсутствии контроля.

### 1.2. Допустимые claims V0

- Default decision — fail-closed `STOPPED`.
- Агент не является ambient authority holder или внешним executor.
- Worker и broker-owned model gateway имеют разные physical/authority envelopes.
- Неизвестное, неограниченное, stale или mismatched не approvable.
- N→N+1 является объявленным communication/control channel, а не доказательством отсутствия hidden authority.
- Любой committed unauthorized effect — нарушение `INV-003/005`, требующее containment и расследования, а не допустимый SLO error budget.

### 1.3. Явно не поддерживаемые claims

- «Container/chroot/PATH/iptables/`--rm` дают полную изоляцию».
- «Hash, подпись, schema, summary или entropy check доказывают semantic safety».
- «Observability обнаруживает все атаки» или «tamper-evident hash chain без witness защищает от rollback».
- «Человек поймёт и исправит всё».
- «Шесть effect classes перечисляют все будущие действия»; они задают консервативную классификацию effects, а `UNKNOWN/TOP` остаётся fail-closed.

## 2. Assets

| ID | Asset | Требуемое свойство |
|---|---|---|
| `AS-01` | Platform/L0 hard ceiling и TCB configuration | Целостность, non-bypassability, provenance |
| `AS-02` | User/project data и workspace state | Confidentiality, integrity, declared persistence |
| `AS-03` | External target state и сообщения | Exact target/effect, dedup/reconciliation |
| `AS-04` | Credentials, secret bytes и broker references | Не попадают в ambient agent context; least disclosure |
| `AS-05` | Policy, contract, manifest, prompt/context, model/tool/adapter digests | Целостность, freshness, material-change invalidation |
| `AS-06` | Capability/approval receipts | Single-use, nonreplayable, exact-bound, authenticated |
| `AS-07` | Budgets: CPU, memory, PIDs, IO, disk/inodes, FDs, GPU, tokens, spend, calls, messages, concurrency | Atomic reservation, conservation, monotonicity |
| `AS-08` | Canonical journal, counters, epochs/fencing, anti-rollback state | Durability, serialization, lineage continuity |
| `AS-09` | Sealed snapshot, postcheck rules и evidence | Same-object binding, independence, immutability |
| `AS-10` | Event/log/metric/trace/evidence records | Completeness for safety events, integrity, privacy |
| `AS-11` | Availability of host, broker, executor, gateways and observers | Bounded consumption, containment, recovery |
| `AS-12` | Registry/SBOM/image/runtime/tool/skill/plugin/MCP provenance | Digest pinning, signed governance, rollback control |
| `AS-13` | Human identity, attention and risk decisions | Authentication, legibility, separation of duties |
| `AS-14` | Confidentiality/integrity/provenance/taint/purpose/retention labels | Propagation through data and control dependencies |

## 3. Adversaries и отказные модели

| ID | Adversary/failure | Возможности, которые MUST предполагаться |
|---|---|---|
| `ADV-01` | Скомпрометированный agent/model | Произвольный output, prompt injection following, obfuscation, replay attempts, resource abuse, collusion proposals |
| `ADV-02` | Злонамеренный corpus/tool output/data source | Instructions-as-data, polyglots, schema-valid semantic payloads, taint laundering |
| `ADV-03` | Confused deputy | Broker/executor с более широким ambient authority неверно связывает args/target/caller |
| `ADV-04` | Malicious/compromised tool, skill, plugin/MCP, adapter, image или registry | Digest substitution, dynamic dispatch, dependency/signer downgrade |
| `ADV-05` | Конкурирующий процесс/агент | TOCTOU, writer race, budget fragmentation, delegation laundering, lock/fence abuse |
| `ADV-06` | Host/runtime/kernel compromise or bug | Namespace/seccomp/LSM escape, stale FD/device/proc paths; не полностью устраняется container profile |
| `ADV-07` | Insider/operator/risk owner error | Misconfiguration, stale approval, dangerous exception, audit suppression |
| `ADV-08` | Human approver manipulation/fatigue | Homoglyph/hidden terms, heterogeneous batching, replay, coercion, misunderstanding |
| `ADV-09` | Crash/partition/clock/storage failure | Half-state, unknown dispatch outcome, rollback/forked journal, stale revocation |
| `ADV-10` | External service | Timeout after commit, non-idempotency, ambiguous response, provider logging/retention outside local boundary |

Наличие trusted role не исключает её failure mode. Trust здесь означает узкий claim, проверяемый evidence, а не абсолютную добросовестность.

## 4. Принципалы и минимальные trust assumptions

| Principal | Доверяем только для | Не доверяем для / обязательное разделение |
|---|---|---|
| Human requester | Формулировать intent | Не даёт authority одной формулировкой |
| Human approver | Аутентифицированно выбрать exact-bound bounded option | Не доказывает comprehension; не расширяет L0; requester/approver/executor разделяются по profile |
| Policy/manifest owner | Выпускать versioned artifact под governance | Подпись не доказывает semantic soundness; reviewer/risk owner отдельны |
| Controller/PEP | Pure/total decision, transition ownership, fail-closed | Не исполняет произвольный agent payload; state проверяется по journal snapshot |
| Capability issuer/store | Exact binding и one-use lifecycle | Не хранит crash-critical consume state только в RAM |
| Broker | Mediation, canonical args, JIT secret resolution, authoritative events | Не передаёт ambient credential/FD/socket worker-у; scope проверяется заново |
| Executor | Исполнять одну exact-bound call capability | Проверяет epoch/fence; не принимает agent self-asserted scope |
| Agent/model worker | Только proposal/declared local compute | Полностью недоверенный относительно policy, evidence, effects и telemetry |
| Model gateway | Совершать объявленный external `COMMUNICATE` | Отдельный principal/sink; provider retention и payload labels учитываются |
| Observer/postcheck | Наблюдать immutable snapshot/externally reconciled facts | Не расширяет authority и не разделяет writable context с worker |
| Journal writer | Канонические durable facts и counters | Требует serializability, anti-rollback regime, epoch/fencing; JSONL сам по себе недостаточен |
| Registry resolver | Возвращать immutable digest-pinned snapshot | Dynamic registry в минимальном профиле disabled; update требует governance transaction |
| Host kernel/hypervisor | Enforcement, заявленное конкретным profile | Shared-kernel risks остаются; stronger profile требуется по риску |

## 5. Trust boundaries

| ID | Граница | Разрешённый переход | Non-bypassable enforcement / failure |
|---|---|---|---|
| `TB-01` | Human/UI → controller | Canonical intent/approval payload | Schema + anti-confusion UI + service-signed exact receipt; unknown/unbounded → deny |
| `TB-02` | Corpus/context/tool output → agent/model | Labelled input bytes | Context assembler, provenance/taint, size/depth limits; instructions внутри данных не меняют policy |
| `TB-03` | Agent/model → controller/PEP | Powerless proposal | Canonicalization, manifest bind/closure, pure decision; direct executor path отсутствует |
| `TB-04` | Controller → broker/capability store | Exact authorized envelope | Durable serializable consume/reserve/intent/counter transition |
| `TB-05` | Broker → executor | One-call capability + canonical args + epoch | Executor validates audience/digests/fence; mismatch → no dispatch |
| `TB-06` | Worker sandbox → host | Только L0-profile syscalls/resources | Namespaces + capabilities/no_new_privs + seccomp + LSM + cgroups + supervisor; violation → block/kill |
| `TB-07` | Worker → filesystem inputs/outputs | Descriptor-rooted declared flow | Read-only inputs, bounded outputs, safe path resolution, seal; escape → block/incident |
| `TB-08` | Worker → broker IPC | Typed, bounded request/evidence channel | Единственная exact operation-scoped `UNIX_CONNECTED_PAIR` proposal-FD pair; endpoint-holder attestation + per-message credentials + schema/identity/flow policy; любой другой inherited/broad/connected FD запрещён |
| `TB-09` | Broker/model gateway → provider/network | Declared `COMMUNICATE` sink | Allowlist, labels, minimization, budget, authoritative receipt; worker network remains disconnected |
| `TB-10` | Executor → external target | Exact operation/target/idempotency binding | Precheck, durable intent, reconciliation; unknown → quarantine/no auto-retry |
| `TB-11` | Worker/executor → observer/postcheck | Immutable snapshot или independently observed outcome | Quiescence, seal digest, read-only independent plane; mismatch → discard/quarantine |
| `TB-12` | Components → journal/telemetry/evidence store | Canonical safety events/facts | Authenticated writers, append/tamper evidence, anti-rollback/witness per claim; missing → failure |
| `TB-13` | Registry/supply chain → resolver/runtime | Signed, digest-pinned implementation set | Provenance, revocation, rollback control, TOCTOU-safe resolution |
| `TB-14` | Parent → child agent/principal | Attenuated envelope, partitioned budget, labelled data | Atomic reservation, depth/fan-out/cycle limits; amplification → deny/revoke subtree |
| `TB-15` | Iteration N → N+1 | Declared, validated evidence/context flow | D2, material digest, taint/provenance, fresh transaction; arbitrary output не trusted автоматически |

### 5.1. Network semantics

`network_egress=false` относится к agent worker. Worker MUST NOT иметь usable IPv4/IPv6/loopback/DNS/metadata route, broad UNIX socket, connected external sink FD или undeclared inherited connected FD. Единственное исключение — заранее созданная trusted supervisor-ом exact operation-scoped `AF_UNIX/SOCK_SEQPACKET` connected pair для powerless proposal `worker → broker`; worker получает только свой typed endpoint, не может создавать/reconnect-ить сокеты, а external attestor до start gate связывает оба endpoint-FD с точными worker/broker OS subjects. Broker проверяет bounded canonical message и фактические per-message credentials; creation-time `SO_PEERCRED`, caller boolean или digest сами по себе не доказывают будущих держателей pair. Model request к внешнему provider — отдельный flow `worker → broker IPC → model_gateway → provider`, классифицируемый как `COMMUNICATE`; каждый hop имеет собственный envelope. Universal terminal/protocol gateway не являются исключением из этой модели.

## 6. Attack surfaces

Поверхности включают: canonicalization и parser boundaries; shell/terminal; filesystem/path/mount/proc/device/IPC; worker networking и broker IPC; capability/approval lifecycle; budget/journal/fencing; snapshot/postcheck; output→input context; registries/supply chain; delegation/reflection; external non-stageable sinks; telemetry/alerting; human UI; recovery/break-glass.

Исходный `TH-15 agent_harness_workspace_escape_cumulative_exhaustion` (`HARNESS_ACTIVATION_DIFF.md:508-530`) сохраняется только как **PROVISIONAL threat family**. Нормализованный каталог ниже шире и не зависит от неверного подсчёта «14 gaps».

## 7. Нормативные правила threat handling

1. Каждый attack class MUST иметь prevention layer, detection layer, response, oracle, expected evidence и residual risk.
2. Prevention MUST находиться на границе, не контролируемой атакующим principal.
3. Agent self-report MAY использоваться диагностически, но MUST NOT быть единственным safety event/evidence.
4. Detection не заменяет prevention для committed unauthorized effects.
5. Failure mandatory telemetry/postcheck/journal consistency MUST переводить risk action в `STOPPED` или `QUARANTINED`.
6. Любой unknown external outcome MUST быть quarantined и MUST NOT auto-retry.
7. Incident→test→нижний invariant/control feedback MAY изменять policy только через новую versioned governance transaction; agent не переписывает policy сам.
8. Numeric thresholds MUST быть profile-calibrated и иметь units/rationale; corpus numbers — только examples/TBD.

Across `TB-01/04/05/06/12/13/14`, names, hashes and booleans are not trust evidence. Admission MUST consume verifier-authenticated, fresh, exact-bound records: pairwise-distinct principal/session identities; complete capability or approval signed payload; current time/revocation/fence; compiled isolation placement; and the measured supply object actually loaded. A mismatch at any hop is `STOP` before dispatch or `QUARANTINED` after possible effect.

Round-4 closure rules are normative and remain implementation obligations: (Q-39) supply facts MUST be externally signed and anchored to the immutable registry, revocation/rollback state, exact loaded bytes and placement; recomputing caller-controlled measurements is not verification. (Q-40) the D2 `frontier_inventory` MUST be a complete controller-derived snapshot/digest, not caller input; omitted, empty, stale or hidden N+2 classes fail closed. (Q-41) every authoritative event MUST identify an externally verified principal, role, component and key with fresh revocation state. (Q-42) the event signature MUST cover the canonical event payload and source sequence/previous link; independently supplied digests do not establish a chain. (Q-43) descriptor identity, root, mount and epoch MUST remain equal from manifest through policy, capability, dispatch and receipt. (Q-44) contract binding MUST resolve the trusted active contract and carry its canonical digest and real lineage, not a placeholder. (Q-45) uncertainty after stageable dispatch MUST enter quarantine with escrow retained unless an independent verifier proves no effect. (Q-46) compiled effects MUST be a subset of the worker's physical ceiling; a worker may propose `COMMUNICATE`, but only a distinct broker/gateway sink may perform it, and worker mutation requires a separate mediated hop. (Q-47) mutation capability audience MUST be an externally verified, pairwise-distinct `EXECUTOR` principal/session, never the worker. (Q-48) scope selectors and resource kinds MUST be a closed typed relation; raw value equality across kinds is invalid. (Q-49) `COMMIT`/`JOIN` MUST consume externally verified typed same-object evidence bound to transaction, decision, capability and envelope. (Q-50) every budget identity MUST be exactly `(name, unit, scope_digest, lineage_root)` across demand, reservation, capability and dispatch. (Q-51) issue and dispatch MUST consult a durable external verifier record for every capability field; inline facts and recomputed plain digests are insufficient. These controls are `NOT_IMPLEMENTED`/`NOT_ATTESTED` until their exact runtime evidence exists.

## 8. Нормализованный attack catalog и полное source mapping

`security.md` содержит 18 детализированных subsections (`1.1–6.2`), но 12 строк summary; утверждение «14 gap’ов» не согласуется ни с одним числом. V0 сохраняет все 18 как `CAT-ATK-001..018`. `comparison.md` C1–C10 отображены без изменения смысла; дополнительные обязательные классы из метапромпта получают `CAT-ATK-019..030`.

`CAT-ATK-*` — единственные IDs threat catalog в этом документе; matrix `ATK-*` в `17_ATTACK_TEST_AND_EVIDENCE_MATRIX.md` — отдельные stable row IDs. Numeric equality не означает semantic equality: `CAT-ATK-023` и `ATK-023`, например, являются разными объектами. Catalog owns attack semantics/source/owner; matrix owns executable oracle/evidence rows. Каждый matrix row отображается ровно в один catalog class, а один class может требовать несколько matrix rows. Lossless semantic map находится в `tests/invariant-traceability.json#attack_map`; collision, unmapped row и ambiguous mapping являются ошибками.

| ID | Attack / trace | Assets / boundaries / invariant | Prevention; detection; response | Test / expected evidence | Source mapping | Status |
|---|---|---|---|---|---|---|
| `CAT-ATK-001` | Hardlink/symlink/path escape из workspace | `AS-01/02`, `TB-06/07`, `INV-003/005` | Descriptor-rooted resolution, separate FS/mount domain, identity recheck; denied path event; kill/incident | `T-ATTACK-L0-PATH-001`; syscall/path trace + unchanged outside inode | Security `1.1`; summary row 1; Comparison `C1` | `OPEN/UNTESTED` |
| `CAT-ATK-002` | DNS/timing/shared-runtime covert egress | `AS-02/10`, `TB-06/08/09`, `INV-003/013` | Network disconnect + IPC allowlist + resource partition; egress/syscall anomaly; kill/revoke | `T-ATTACK-L0-NET-001`; packet/syscall/IPC evidence | Security `1.2`; summary row 2; Comparison `C2` | `OPEN/UNTESTED`, covert residual |
| `CAT-ATK-003` | Adapter env/config/proc leak | `AS-04/05`, `TB-06/13`, `INV-002/009` | Separate principal/PID/proc, RO pinned config, zero secrets in worker; proc/open denial; revoke | `T-ATTACK-L0-PROC-001`; mount/proc/secret canary evidence | Security `1.3`; Synthesis `R15` | `OPEN/UNTESTED` |
| `CAT-ATK-004` | Postcheck binary/shared-volume TOCTOU, mutation after check before seal | `AS-02/09`, `TB-11`, `INV-011/012` | Quiesce then immutable seal; independent observer; digest compare; discard/quarantine | `T-ATTACK-SEAL-001`; writer-fence trace + same digest receipt | Security `2.1`; summary row 3; Comparison `C3` | `OPEN/UNTESTED` |
| `CAT-ATK-005` | Tool proposal triggers eval/shell/transitive side effect | `AS-01/03`, `TB-03/05`, `INV-003/005` | Static upper bound, canonical args, no ambient dispatch, exact physical ceiling; block event; stop | `T-ATTACK-TOOL-001`; decision + syscall/sink trace | Security `2.2`; summary row 4; Comparison `C7` | `OPEN/UNTESTED` |
| `CAT-ATK-006` | Content-addressed polyglot/quine/type confusion | `AS-02/05`, `TB-02/03`, `INV-009/015` | Canonical typed decoding, no eval, format/size/depth bounds; mismatch alert; reject | `T-ATTACK-INPUT-001`; canonical bytes/hash/parser evidence | Security `2.3`; summary row 5; Comparison `C8` | `OPEN/UNTESTED` |
| `CAT-ATK-007` | Fork/memory/disk/IO exhaustion при undefined `LRP1_D` | `AS-07/11`, `TB-06`, `INV-007/015` | cgroups/quotas/rlimits/watchdog with calibrated units; resource event; kill tree | `T-ATTACK-L0-RESOURCE-001`; cgroup/usage/kill evidence | Security `3.1`; summary row 6; Synthesis `R4` | `OPEN/UNTESTED` |
| `CAT-ATK-008` | Ledger write/replay/counter bypass | `AS-06/08`, `TB-04/12`, `INV-004/008` | Serializable durable ledger, nonce/dedup, anti-rollback evidence, fenced writer; divergence alert; stop | `T-ATTACK-LEDGER-001`; recovery/fork trace | Security `3.2`; summary row 7; Comparison `C10` | `OPEN/UNTESTED` |
| `CAT-ATK-009` | Crash/recovery создаёт nested contract и сбрасывает limits | `AS-07/08/13`, `TB-01/12/15`, `INV-008/009` | New contract requires new exact approval + lineage anti-rollback; reset attempt alert; stop | `T-ATTACK-CONTRACT-001`; pre/post lineage evidence | Security `3.3`; Comparison `C6` | `OPEN/UNTESTED` |
| `CAT-ATK-010` | Sleep/spin/CPU starvation внутри wall deadline | `AS-07/11`, `TB-06`, `INV-007` | CPU quota + wall watchdog + fair scheduler; saturation detection; kill | `T-ATTACK-L0-CPU-001`; cpu.stat/supervisor trace | Security `3.4`; Synthesis `R14` | `OPEN/UNTESTED` |
| `CAT-ATK-011` | Overlay/volume/tmp/shm persistence across fresh sessions | `AS-02/14`, `TB-06/07/15`, `INV-010` | Per-session private storage, no reused writable layers, verified cleanup; residue scan; quarantine | `T-ATTACK-L0-PERSIST-001`; before/after mount/inode inventory | Security `4.1`; summary row 8; Synthesis `R5` | `OPEN/UNTESTED` |
| `CAT-ATK-012` | Git binary/object store/hooks как undeclared persistence | `AS-02/05`, `TB-07`, `INV-010` | Host checkout/`.git` inaccessible; binary absence only defense-in-depth; write denial; stop | `T-ATTACK-L0-GIT-001`; mount/path/process trace | Security `4.2`; summary row 9; Comparison `C4` | `OPEN/UNTESTED` |
| `CAT-ATK-013` | Encoded state через legal output→input channel | `AS-05/14`, `TB-15`, `INV-010/013` | Declared schema/labels/provenance/purpose/size; prompt-injection boundary; reject/quarantine | `T-ATTACK-FLOW-001`; N/N+1 context diff and taint trace | Security `4.3`; related to Comparison `C5` | `OPEN/UNTESTED` |
| `CAT-ATK-014` | Mutable adapter registry poisoning | `AS-05/12`, `TB-13`, `INV-009/015` | Immutable digest-pinned snapshot; dynamic registry disabled in minimal profile; mismatch alert/revoke | `T-ATTACK-SUPPLY-001`; registry resolution/attestation evidence | Security `4.4`; summary row 11; Comparison `C9` | `OPEN/UNTESTED` |
| `CAT-ATK-015` | Steganographic instructions/capability in evidence | `AS-09/14`, `TB-11/15`, `INV-010/011/013` | Strict typed evidence, taint/control-flow tracking; semantic sanitization is not assumed; reject/quarantine | `T-ATTACK-FLOW-002`; labelled evidence/context trace | Security `5.1`; summary row 10; Comparison `C5` | `OPEN/UNTESTED` |
| `CAT-ATK-016` | Skill confusion/registry authority amplification | `AS-05/12`, `TB-03/13`, `INV-005/006/009` | Per-operation manifest/digest, child envelope ≤ caller, immutable registry; deny/revoke | `T-ATTACK-SUPPLY-002`; resolver/decision trace | Security `5.2`; Synthesis `R13` | `OPEN/UNTESTED` |
| `CAT-ATK-017` | Homoglyph/hidden terms/deep JSON в loop approval UI | `AS-06/13`, `TB-01`, `INV-009/015` | Canonical rendering, diff, bounded fields, separate comprehension evidence; stale/confusion alert; cancel | `T-HUM-ATTACK-001`; rendered payload + receipt + UX study | Security `6.1`; summary row 12; Synthesis `R11` | `OPEN/UNTESTED` |
| `CAT-ATK-018` | Ambiguous contract позволяет adaptive branch/bundle expansion | `AS-05/07`, `TB-01/03/15`, `INV-008/009/015` | Typed whitelist, no adaptive bundle expansion, material re-admission; D2 alert; stop | `T-ATTACK-CONTRACT-002`; decision/LTS trace | Security `6.2`; related Synthesis `R11` | `OPEN/UNTESTED` |
| `CAT-ATK-019` | Magic-link, mount, proc-fd path and rename races | `AS-01/02`, `TB-06/07`, `INV-003/012` | Descriptor-based path policy, mount isolation, race-safe seal; syscall/path identity event; kill | `T-ATTACK-L0-PATH-002`; adversarial race trace | Metaprompt `334-350` | `OPEN/UNTESTED` |
| `CAT-ATK-020` | `/proc`, ptrace, devices, shared memory, inherited FDs, broad UNIX sockets | `AS-01/04`, `TB-06/08`, `INV-002/003` | PID/IPC/device controls, FD allowlist/closure, LSM/seccomp; violation alert; kill/revoke | `T-ATTACK-L0-IPC-001`; FD/proc/syscall inventory | Metaprompt `191-206,341` | `OPEN/UNTESTED` |
| `CAT-ATK-021` | IPv6/loopback/metadata-service/network-rule bypass | `AS-02/04`, `TB-06/09`, `INV-003/013` | Default-disconnected namespace, no routes/interfaces/resolver, broker-only egress; packet alerts; kill | `T-ATTACK-L0-NET-002`; IPv4/IPv6/DNS/route capture | Metaprompt `191-206,341` | `OPEN/UNTESTED` |
| `CAT-ATK-022` | FD/inode/log/token/spend/GPU/concurrency exhaustion и budget fragmentation | `AS-07/11`, `TB-04/06/14`, `INV-007/008` | Multidimensional atomic budgets; host+broker accounting; slope/fragment alerts; cancel subtree | `T-ATTACK-RESOURCE-002`; ledger + kernel/scheduler metrics | Metaprompt `198-202,342` | `OPEN/UNTESTED` |
| `CAT-ATK-023` | Prompt/data/tool-description poisoning, taint laundering, confused deputy | `AS-03/05/14`, `TB-02/03/05/15`, `INV-003/009/013/015` | Provenance/taint/control deps, target binding, canonical args; drift/flow alert; deny/quarantine | `T-ATTACK-TAINT-001`; context/decision/sink trace | Metaprompt `334-350` | `OPEN/UNTESTED` |
| `CAT-ATK-024` | Manifest/binary/image/dependency substitution, signature downgrade | `AS-01/12`, `TB-13`, `INV-005/009/015` | Digest pinning, provenance/SBOM, trusted resolver, rollback/revocation; mismatch alert; stop | `T-ATTACK-SUPPLY-003`; attestation/resolution bundle | Metaprompt `344-348`; DOCX `p0845-p0878` caveat | `OPEN/UNTESTED` |
| `CAT-ATK-025` | Delegation amplification, fan-out/depth/cycle, collusion/cross-agent laundering | `AS-06/07/14`, `TB-14`, `INV-006/007/010` | Attenuation + atomic partitions + ancestry/cycle check; lineage alerts; revoke subtree | `T-ATTACK-DELEGATE-001`; complete delegation tree ledger | Metaprompt `334-350` | `OPEN/UNTESTED` |
| `CAT-ATK-026` | Persistent/authority-relevant reflection меняет prompt/memory/model/tool/policy | `AS-05/12/14`, `TB-03/13/15`, `INV-009/010` | `MUTATE+REFLECT`, new material digest/contract, governance path; drift alert; rollback to pinned set | `T-ATTACK-REFLECT-001`; before/after digest + admission trace | Metaprompt `208-239,348` | `OPEN/UNTESTED` |
| `CAT-ATK-027` | Concurrent writer, stale epoch, seal/snapshot mismatch, split-brain | `AS-02/08/09`, `TB-04/05/11/12`, `INV-008/012` | Serializable state + downstream fencing + quiescence; divergence alert; quarantine | `T-ATTACK-CONCURRENCY-001`; exhaustive schedules/fault trace | Metaprompt `262-281,343` | `OPEN/UNTESTED` |
| `CAT-ATK-028` | Crash/rollback/journal fork/stale revocation/unknown external outcome | `AS-03/06/08`, `TB-04/10/12`, `INV-004/008/014` | Durable intent/consume/reserve, anti-rollback, reconcile; unknown alert; no retry/quarantine | `T-ATTACK-RECOVERY-001`; crash-point matrix | Metaprompt `120-145,262-281,345` | `OPEN/UNTESTED` |
| `CAT-ATK-029` | Telemetry suppression/tampering, sampling loss, alert flooding | `AS-10/11`, `TB-12`, `INV-003/011` | Authoritative unsampled safety events, bounded labels, authenticated store; completeness alert; freeze/preserve evidence | `T-ATTACK-TELEM-001`; gap/tamper/flood evidence | Metaprompt `283-302,349` | `OPEN/UNTESTED` |
| `CAT-ATK-030` | Approval replay/fatigue/confusion, insider misuse, break-glass abuse | `AS-06/13`, `TB-01/12`, `INV-004/009/015` | Exact single-use receipt, separation/dual control, TTL, immutable ceiling, alerts/postmortem; revoke | `T-HUM-ATTACK-002`; receipt/replay/dual-control evidence | Metaprompt `304-320,349` | `OPEN/UNTESTED` |

### 8.1. C1–C10 total mapping

| Corpus counterexample | Canonical attack |
|---|---|
| `C1` FS Hardlink Escape | `CAT-ATK-001` (+ `CAT-ATK-019` для расширенных path races) |
| `C2` DNS Side-Channel | `CAT-ATK-002` (+ `CAT-ATK-021`) |
| `C3` Postcheck TOCTOU | `CAT-ATK-004` (+ `CAT-ATK-027`) |
| `C4` Git Binary Abuse | `CAT-ATK-012` |
| `C5` Evidence Steganography | `CAT-ATK-015` (storage-channel variant `CAT-ATK-013`) |
| `C6` Contract Nesting | `CAT-ATK-009` (UI ambiguity отдельно `CAT-ATK-017/018`) |
| `C7` Tool Proposal Side-Effect | `CAT-ATK-005` |
| `C8` Polyglot Input | `CAT-ATK-006` |
| `C9` Adapter Registry Poisoning | `CAT-ATK-014` |
| `C10` Ledger Replay | `CAT-ATK-008` |

### 8.2. Accountable control owners

Имена ниже — роли, не утверждение о назначенных людях или существующих компонентах. Concrete deployment MUST сопоставить каждой роли accountable human owner и operating team.

| Attacks | Primary owner | Independent detection/response owner |
|---|---|---|
| `CAT-ATK-001,011,012,019` | L0 filesystem/runtime owner | Security + incident response |
| `CAT-ATK-002,020,021` | L0 network/IPC owner | Network security + incident response |
| `CAT-ATK-003,014,016,024` | Supply-chain/runtime registry owner | Security governance |
| `CAT-ATK-004,027` | Supervisor/snapshot/commit owner | Independent observer + recovery owner |
| `CAT-ATK-005,006,023` | Tool/input classifier and PEP owner | Security detection owner |
| `CAT-ATK-007,010,022` | Resource scheduler/budget ledger owner | SRE/availability owner |
| `CAT-ATK-008,009,028` | Journal/recovery owner | Independent reconciliation/incident owner |
| `CAT-ATK-013,015,026` | Context/information-flow/governance owner | Security/privacy owner |
| `CAT-ATK-017,018,030` | Human-control/governance owner | Risk owner + audit/incident response |
| `CAT-ATK-025` | Delegation/orchestration owner | Budget/journal + security owner |
| `CAT-ATK-029` | Telemetry/SRE owner | Independent security monitoring owner |

## 9. Prevention, detection, response и recovery policy

| Condition | Mandatory response | Authority после response |
|---|---|---|
| Заблокированная attempted effect вне envelope | Emit authoritative block event; stop call; оценить compromise | Не расширяется; capability consumed/revoked по dispatch state |
| Возможный committed unauthorized effect | Freeze/kill affected route, revoke descendants, preserve evidence, `QUARANTINED`, incident | Новые effects запрещены кроме отдельно разрешённого containment/recovery |
| Missing/corrupt safety telemetry или postcheck | `STOPPED` до dispatch; `QUARANTINED` после возможного effect | Unknown не success |
| Journal/epoch/fence conflict | Stop all losing writers/executors, reconcile authoritative epoch, anti-rollback check | Никакого automatic failover с прежним capability |
| External timeout/ambiguous response | `UNKNOWN_OUTCOME`, quarantine, reconcile by independent query/receipt | Automatic retry запрещён |
| Resource threshold reached | Deny new reservation, cancel/kill bounded subtree, record actual usage | Restart не сбрасывает cumulative limits |
| Stale/materially changed approval/manifest/policy/context | Invalidate receipt/capability, recompute decision | Human approval не переносится |
| Registry/supply-chain mismatch | Stop resolution/load, revoke affected digest, inventory exposure | Fallback только на заранее pinned compatible digest с policy authorization |
| Incident correction | New governed change + regression test + new digest | Agent не меняет control plane напрямую |

## 10. Test и evidence matrix

| Класс | Минимальные positive/negative/adversarial/concurrency/fault tests | Oracle | Evidence ID / status |
|---|---|---|---|
| Filesystem/process L0 | Разрешённый descriptor-root read/write; deny traversal, symlink/hardlink/magic-link, mount, proc, ptrace, device, shm, inherited FD; race rename/seal | Только declared inode/resource меняется; outside immutable; violation blocked | `EV-ATTACK-L0-FS-001` / `ABSENT` |
| Network/IPC L0 | Exact connected-pair broker IPC positive; IPv4/IPv6/loopback/DNS/metadata/pathname/abstract/socketpair/external-sink negatives; endpoint/holder/credential/FD substitution and inheritance faults | Worker передаёт только один bounded proposal exact broker endpoint-у; не создаёт undeclared flow; gateway event принадлежит broker principal | `EV-ATTACK-L0-NET-001` / `ABSENT` |
| Resources | Bounds below/at/above each unit; fork/tree, memory/swap, IO/disk/inode/log/FD/GPU/token/spend; concurrent children; crash | Atomic conservation, deterministic denial/kill, monotonic ledger | `EV-ATTACK-RESOURCE-001` / `ABSENT` |
| Tool/input/supply | Valid pinned tool; shell injection, polyglot, dynamic dispatch, manifest/binary/dependency mismatch, registry rollback | Derived closure never exceeds upper bound; unknown denied | `EV-ATTACK-SUPPLY-001` / `ABSENT` |
| Capability/journal/recovery | Valid one-use; replay/transfer/stale; crash at every durable boundary; stale writer/split-brain | Не существует half-state/duplicate committed dispatch; loser fenced | `EV-ATTACK-STATE-001` / `ABSENT` |
| Seal/postcheck | Valid seal; concurrent writer, checker replacement, digest mismatch, timeout | Postcheck и commit refer to same immutable snapshot; else discard/quarantine | `EV-ATTACK-SEAL-001` / `ABSENT` |
| Information flow N→N+1 | Valid typed evidence; prompt injection, steganography, taint laundering, hash/summary/schema laundering | Labels/control deps preserved; no unauthorized sink or endorsement | `EV-ATTACK-FLOW-001` / `ABSENT` |
| Delegation/reflection | Valid attenuated child; fan-out/depth/cycle/amplification/collusion; persistent policy/memory changes | Child subset and budget conservation; reflection requires new digest/admission | `EV-ATTACK-ORC-001` / `ABSENT` |
| Telemetry/response | Normal events; drop/tamper/reorder/flood; alert owner unavailable | Safety events unsampled; missing is detected; auto-containment bounded | `EV-ATTACK-TELEM-001` / `ABSENT` |
| Human | Exact approval; homoglyph/hidden term/heterogeneous batch/replay/fatigue/break-glass abuse | Only canonical exact payload accepted; comprehension evidence separate; hard ceiling unchanged | `EV-HUM-ATTACK-001` / `ABSENT` |

Ни один destructive payload не должен запускаться на host. Attack fixtures выполняются только в явно disposable test environment с собственной outer containment boundary.

## 11. Assumptions, residual risks и out-of-scope

### 11.1. Assumptions, требующие evidence

- Конкретный kernel/runtime/hypervisor и isolation profile pinned и attestable.
- Broker/PEP/journal writer/observer binaries не writable worker-ом.
- Capability consume, budget reservation, dispatch intent и counters входят в одну durable serializable transition.
- Executor проверяет epoch/fencing downstream.
- Registry snapshot immutable и digest-pinned; dynamic registry disabled в минимальном профиле.
- Clock/freshness semantics и anti-rollback anchor определены конкретным deployment profile.

До evidence это assumptions, не facts.

### 11.2. Residual risks

- Shared-kernel exploit и hardware/microarchitectural leakage остаются для container profile.
- Covert timing/resource channels нельзя честно свести к нулю; profile MUST заявить допускаемую модель соседства/capacity и sensitivity.
- External provider может сохранять/обрабатывать переданные данные по собственной boundary.
- Semantic deception может пройти schemas/hashes и потребовать domain verification/human review.
- Insider/human error полностью не устраняется подписью или dual control.
- Tamper-evident local chain без независимого witness/anchor не доказывает отсутствие rollback/fork.

### 11.3. Out-of-scope V0

- Доказательство корректности Linux kernel, hypervisor, CPU и внешних providers.
- Универсальное предсказание поведения произвольного кода.
- Калиброванные численные budgets/SLO/alert thresholds.
- Реальное исполнение exploit/fork-bomb/escape fixtures.
- Risk acceptance от имени пользователя.

## 12. Definition of Done и текущий status

| Stage | Threat-model DoD |
|---|---|
| `DECLARED/SPECIFIED` | Все assets/principals/boundaries/attacks имеют owner, prevention, detection, response, oracle, evidence ID и residual risk; `CAT-ATK-001..030` source mapping complete. |
| `IMPLEMENTED` | Enforcement points существуют на pinned runtime; authoritative events/evidence emit; recovery/containment paths работают; exact configuration recorded. |
| `VERIFIED` | Positive/negative/adversarial/concurrency/fault matrix выполнена независимо; no open Critical/High; residual Medium имеет authorized time-bounded receipt; evidence scope/expiry известны. |

Текущий status: каталог и нормативные обязанности сформулированы; implementation и runtime evidence отсутствуют; каждый `CAT-ATK-*` остаётся `OPEN/UNTESTED`.

## 13. Source-vs-new traceability

| Corpus material | Покрытие V0 |
|---|---|
| `security.md:7-174` — 18 detailed findings; `:175-200` — 12 summary rows | Каждый detailed finding получил отдельный `CAT-ATK-001..018`; числовой конфликт сохранён явно. |
| `comparison.md:133-206` — C1–C10 | Полное отображение в §8.1 без неверной дедуп-арифметики. |
| `synthesis.md:117-135` — 15 risks, фактически 5 Critical | Severity labels не приняты как доказанный runtime risk rating; все records source-mapped, статусы open. |
| `HARNESS_ACTIVATION_DIFF.md:508-530` — TH-15 | Сохранён как PROVISIONAL family, разложен на конкретные attacks/boundaries. |
| `metaprompt-harness-levels-0-5-ru.md:334-350` — обязательные threat/test classes | Добавлены `CAT-ATK-019..030` и test/evidence families. |
| DOCX `word/document.xml#p0831-p0918` — невозможность полного action list/negative-space proposal | Теоретические внешние claims не повторены как facts; принят конечный syntactic configuration + conservative effects/UNKNOWN + residual open-world risk. |
| Новые требования V0 без утверждения об исходной реализации | Зафиксированы D2 boundary, separate principals, labels, exact approval, Linux risks, authoritative events и honest evidence status. |
