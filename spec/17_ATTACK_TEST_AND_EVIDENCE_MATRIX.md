# 17 — Attack, test and evidence matrix

## 1. Scope, safety and status

Это нормализованный **план** атак и evidence, не отчёт о проведённом pentest. Никакие внешние, destructive, privilege-escalation, network-exfiltration или resource-exhaustion payloads в рамках подготовки документа не запускались. Runtime implementation отсутствует; поэтому oracle/evidence ниже — обязательные будущие artifacts, а не существующие результаты.

Adversary model: agent/model output потенциально malicious/compromised; также рассматриваются poisoned tools/data/registry, confused deputy, ambient authority, concurrent actors, crash/recovery, colluding agents, compromised connector/observer/telemetry, insider и fallible approver. Host/kernel compromise, hardware/firmware compromise и zero covert-channel guarantee — out of scope unless a stronger profile explicitly brings them into TCB claims.

## 2. Total mapping исходного Security-прохода и C1–C10

Механический source count: **18** numbered subsections (`1.1–6.2`), а не заявленные 14. Все 18 сохранены:

| Canonical | Security source subsection | Counterexample mapping | Normalized class |
|---|---|---|---|
| ATK-001 | `security.md:9–17` 1.1 undefined workspace | C1 | workspace/path boundary |
| ATK-002 | `security.md:18–26` 1.2 shared-runtime side-channel | C2 | network/shared channel |
| ATK-003 | `security.md:27–35` 1.3 runtime adapter escape | C9 partial | mediated-executor/supply boundary |
| ATK-004 | `security.md:39–46` 2.1 compromisable postcheck | C3 | observer TOCTOU/trust |
| ATK-005 | `security.md:48–54` 2.2 tool proposal escape | C7 | proposal has side effect |
| ATK-006 | `security.md:56–62` 2.3 content-address validation bypass | C8 | canonicalization/polyglot |
| ATK-007 | `security.md:66–73` 3.1 per-iteration exhaustion | none | resource amplification |
| ATK-008 | `security.md:75–83` 3.2 ledger replay | C10 | replay/rollback |
| ATK-009 | `security.md:85–91` 3.3 nested contract | C6 | counter/budget reset |
| ATK-010 | `security.md:93–99` 3.4 sleep/spin | none | CPU/wall/process lifecycle |
| ATK-011 | `security.md:103–110` 4.1 workspace persistence | none | declared/undeclared state |
| ATK-012 | `security.md:112–118` 4.2 git persistence | C4 | control metadata persistence |
| ATK-013 | `security.md:120–126` 4.3 output→input state | C5 partial | declared communication/control flow |
| ATK-014 | `security.md:128–136` 4.4 adapter registry poisoning | C9 | supply-chain/material drift |
| ATK-015 | `security.md:140–144` 5.1 steganographic evidence | C5 | taint/integrity laundering |
| ATK-016 | `security.md:146–154` 5.2 skill registry amplification | none | hidden ambient tool authority |
| ATK-017 | `security.md:158–165` 6.1 approval UI confusion | none | human decision confusion |
| ATK-018 | `security.md:167–171` 6.2 adaptive interpretation | none | reflection/D2 branch expansion |

Thus C1–C10 are all mapped, including many-to-one mapping where source itself overlaps. No merge erases the distinct ATK row. Historical incorrect mappings in `synthesis.md:124–125,215,217` are not carried forward.

The matrix `ATK-*` namespace is distinct from the threat-catalog `CAT-ATK-*` namespace in `03_SYSTEM_THREAT_TRUST_MODEL.md`; the lossless one-to-one map and accountable owner are in `tests/invariant-traceability.json#attack_registry`.

## 3. Core attack matrix ATK-001–018

Abbreviations: `P` prevention; `D` detection; `R` response; evidence is expected future evidence.

| ID | Preconditions and minimal action trace | Violated invariant | P / D / R | Test oracle → expected evidence | Residual risk |
|---|---|---|---|---|---|
| ATK-001 | Same-UID attacker prepares external hardlink/symlink or traversal target; worker opens path by string and writes outside logical output. Exact `/etc/passwd` hardlink may be infeasible and is not the oracle. | `INV-003`, L0 output-only mutation | P: private mounts, descriptor-rooted `openat2`-equivalent, no host checkout, inode/mount policy; D: TCB path event + post-seal delta; R: block/kill/quarantine. | `T-ATTACK-PATH-001`: any resolved inode outside allowed root must fail before write → deny event, unchanged external canary, isolation receipt. | kernel/VFS bug; shared-UID/FS semantics profile-dependent |
| ATK-002 | Worker sends signal/data via inherited socket, DNS, loopback/shared service or timing/shared runtime despite declared no egress. | `INV-002/003`, flow envelope | P: separate worker net namespace, closed FDs, broker gateway only; D: socket/syscall/network TCB events; R: block/kill/freeze. | `T-ATTACK-NET-001`: matrix of IPv4/IPv6/DNS/UNIX/loopback/metadata/inherited FD all denied → per-channel block receipt. | shared-kernel timing/cache covert capacity cannot be zeroed |
| ATK-003 | Agent invokes overpowered adapter/terminal or causes broker to execute undeclared subtool/host operation. | non-bypassable mediation; derived closure ≤ manifest/physical | P: exact operation manifest, transitive closure, separate broker principal, per-call cap; D: tool/implementation/dispatch mismatch; R: deny/revoke/quarantine. | `T-ATTACK-ADAPTER-001`: alias/subtool/dynamic dispatch not in bound closure cannot dispatch → resolver/PEP receipt. | adapter/kernel implementation defect |
| ATK-004 | Worker or concurrent writer modifies target after postcheck reads it, or postcheck shares compromisable context. | `INV-012`, L4 seal chain | P: revoke/fence writers, quiescence, immutable snapshot, independent observer; D: epoch/seal mismatch; R: discard/quarantine. | `T-ATTACK-TOCTOU-001`: race writer against freeze/seal; no commit/JOIN → writer-revoke, seal, observer and quarantine events. | compromised host/observer; snapshot implementation bugs |
| ATK-005 | Supposedly inert tool proposal itself downloads/writes/executes or pre-reserves authority. | proposal has no execution authority; D2 frontier | P: proposal is pure data, no executor/capability/reservation; D: TCB side-effect attempt; R: deny/kill. | `T-ATTACK-PROPOSAL-001`: proposal phase syscall/write/flow blocked; N+2 artifacts absent → TCB and D2 explorer evidence. | model may encode harmful plan text; remains tainted data |
| ATK-006 | Polyglot, duplicate keys, Unicode/path ambiguity, encoded content has one hash but validator/executor interpret differently. | canonical request/manifest binding | P: single canonical parser, duplicate rejection, encoding/depth/size constraints, semantic binder; D: canonical digest/interpretation mismatch; R: reject. | `T-ATTACK-CANON-001`: parser differential corpus has exactly one interpretation or reject → fixture report and no dispatch. | downstream parser discrepancy if separate parser exists |
| ATK-007 | One iteration forks processes, writes files/logs, consumes memory/IO/tokens/spend/GPU below incomplete per-field limits. | typed budget and physical ceiling | P: cgroups/quotas/FDs/watchdog plus broker budgets; D: ledger/TCB usage; R: throttle/kill/STOP, cleanup verify. | `T-ATTACK-RESOURCE-001`: each dimension reaches exact bound and cannot exceed → limit event, killed tree, monotonic spend and cleanup receipt. | unmetered kernel/provider resources; calibration |
| ATK-008 | Replay capability/event, roll ledger back/fork it, duplicate delivery, or use stale writer epoch. | `INV-005/006`, single-use and monotonicity | P: serializable unique nonce, protected epochs/fencing, signature/anchor; D: duplicate/gap/fork/fence mismatch; R: quarantine lineage. | `T-ATTACK-LEDGER-001`: mutate/reorder/truncate/fork/concurrent consume; at most one dispatch and deterministic alert → ledger branches/anchor result. | without independent anchor, compromised writer can hide truncation |
| ATK-009 | Child/nested contract/restart opens fresh counters while retaining same lineage authority. | cumulative monotonic limits; tree conservation | P: immutable root lineage and ancestor ceilings; D: lineage/counter mismatch; R: deny/freeze subtree. | `T-ATTACK-NEST-001`: restart/retry/nesting/branch never lowers spent/attempt counts → ledger invariant report. | incorrect lineage resolution/cross-system reconciliation |
| ATK-010 | Sleep/spin/fork escapes CPU-only or wall-only bound; orphan survives timeout. | execution deadline/process-tree termination | P: CPU cgroup + monotonic wall watchdog + PID tree/cgroup kill; D: supervisor heartbeat/usage; R: kill/fence/cleanup. | `T-ATTACK-TIME-001`: sleep, spin, fork+detach all terminate at profile bounds → supervisor/cgroup/cleanup receipts. | host scheduler/kernel DoS |
| ATK-011 | Worker leaves config/cache/lock/hidden file in workspace/volume/tmp to influence next iteration. | no undeclared persistent state | P: disposable FS, allowlisted memory objects, verified cleanup; D: before/after inventory/seal; R: quarantine/remove whole disposable instance. | `T-ATTACK-PERSIST-001`: files across output/tmp/shm/volume/overlay checked; only declared sealed output transfers → lifecycle receipt. | external provider/storage state; storage remanence |
| ATK-012 | Git binary/lib/direct `.git` write or hooks/config persist control state despite PATH filter. | no hidden control-plane mutation | P: `.git` absent/unmounted, FS denies control metadata, no host checkout; D: unexpected file/process; R: block/quarantine. | `T-ATTACK-GIT-001`: absolute binary/libgit/direct write/hook fixtures cannot observe or mutate repo metadata → TCB deny and unchanged digest. | other VCS/control files need same policy |
| ATK-013 | N output carries commands/state into N+1; schema-valid free text becomes control input. | `INV-010`, taint/provenance | P: declared field allowlist, untrusted label, trusted context assembler; D: unauthorized control dependency/flow; R: reject field/context. | `T-ATTACK-FLOW-001`: injection in every transferable field cannot change policy/tool/role; typed facts retain taint → assembly manifest/deny. | semantic influence in allowed natural-language task data |
| ATK-014 | Registry name/alias or adapter digest changes between approval and dispatch; signature downgrade accepted. | material bindings exact/fresh | P: immutable signed snapshot, exact artifact FD/digest, atomic activation/revocation; D: mismatch/key rollback; R: revoke/STOP/rollback activation. | `T-ATTACK-REGISTRY-001`: substitution at resolution/dispatch cannot execute → resolver, stale-receipt and supply alert evidence. | trusted signer compromise; dependency transparency gap |
| ATK-015 | Evidence hides capability/prompt/steganographic instruction; summary/hash/schema is treated as trusted. | evidence does not create authority; label monotonicity | P: evidence typed as data, field/purpose allowlist, separate endorsement/declass; D: taint/entropy as signal only; R: reject/quarantine. | `T-ATTACK-EVIDENCE-001`: encoded/schema-valid/high/low-entropy variants cannot activate authority → context/PEP trace. | semantic/steganographic channels cannot be exhaustively detected |
| ATK-016 | Agent names or triggers undeclared skill/plugin/default-rich child; registry resolution grants ambient authority. | actual tool set/manifest upper bound; no child amplification | P: pinned verified registry, default deny, exact operation cap; D: unknown operation/digest; R: deny/revoke. | `T-ATTACK-SKILL-001`: undeclared/mismatched skill/plugin/MCP operation fails before load → registry/PEP receipt. | current actual skill inventory is not verified |
| ATK-017 | Homoglyph/bidi/hidden field/unit change/batching makes human approve different effect or aggregate. (`L5-REQ-006`, `L5-REQ-007`) | exact informed approval | P: trusted canonical semantic UI, anti-confusable, no hidden terms, teach-back, homogeneous batching; D: presentation/hash/comprehension failure; R: no receipt/STOP. | `T-HUM-PRESENT-*`: fixtures render canonical or reject; altered payload invalidates receipt → semantic render and decision evidence. | comprehension/fallibility never eliminated |
| ATK-018 | Agent reinterprets contract, writes config/memory, creates N+2 branch/capability before JOIN or expands targets. | D2, material-change invalidation, `REFLECT` policy | P: single frontier, control-plane writes classified `MUTATE+REFLECT`, immutable contract; D: frontier/config drift; R: deny/freeze/revoke. | `T-ATTACK-REFLECT-001`: config/prompt/model/tool/memory mutation and N+2 artifact are denied/invalidate → explorer and change receipts. | private ephemeral model tokens outside boundary; semantic planning ambiguity |

## 4. Additional mandatory attack classes

These rows extend, rather than replace, ATK-001–018. `ATK-*` names matrix rows and never aliases the `CAT-ATK-*` threat-class namespace; the explicit semantic map is `tests/invariant-traceability.json#attack_map`.

| ID | Preconditions/action trace | Invariant | P / D / R | Oracle → expected evidence | Residual |
|---|---|---|---|---|---|
| ATK-019 | symlink/magic-link/path traversal/mount move swaps resolution | output scope and immutable root | descriptor-root + mount namespace; path/mount event; block/kill | `T-ATTACK-PATH-002`: swap/race corpus never reaches external canary → resolution receipt | VFS/kernel bug |
| ATK-020 | read `/proc`, ptrace sibling, device/shm/eBPF/inherited FD exposes secret/authority | zero ambient credential/host observation | private proc/PID/IPC, no devices, drop caps/no_new_privs/seccomp/LSM/closed FDs; TCB detect; kill | `T-ATTACK-KERNELSURF-001` all forbidden surfaces denied → profile attestation/events | shared kernel residual |
| ATK-021 | alternate network stack/path bypasses primary OUTPUT policy | declared flow only | namespaces+LSM+socket policy across IPv4/6/DNS/UNIX/loopback/metadata; detect; kill | full channel matrix → zero successful external canary and TCB receipts | covert timing/shared service |
| ATK-022 | disk/inode/log/token/spend/message/agent-count/concurrency/GPU exhausted | complete typed budgets | physical+broker ledger bounds; slope/usage alerts; kill/STOP | per-dimension boundary/fault suite → before/delta/after evidence | provider-side metering lag |
| ATK-023 | writer revocation/observer crash/snapshot mismatch around commit | seal/JOIN chain | epochs, quiescence, immutable seal, independent observer; mismatch; quarantine | crash at each seal boundary → no JOIN without full chain | compromised witness |
| ATK-024 | shell argument/env/newline/NUL/polyglot causes extra command or dynamic effect closure | manifest upper bound and canonical args | avoid shell; typed argv/env; conservative shell `UNKNOWN/TOP`; detect; deny | injection corpus → no extra process/file/flow; classifier reason | interpreter/compiler bugs |
| ATK-025 | recovery restores old counter/receipt, nested session or duplicate queue delivery reuses authority | crash-safe monotonic state | serializable store, uniqueness, epochs, root lineage; divergence alert; quarantine | crash/restart/duplicate matrix → single dispatch and monotonic counter | split-brain without consensus |
| ATK-026 | state persists through overlay layer, tmp, shared registry/cache/volume | no undeclared persistence | disposable layers/private tmp/shm/no shared mutable cache; inventory; destroy/quarantine | cross-session canary scan → verified cleanup/absence | media remanence/external cache |
| ATK-027 | secret A→summary/hash/schema→agent B→external sink; branch-only dependency omitted | label propagation and flow policy | transitive data/control taint, purpose/retention; flow alert; deny | laundering graph variants blocked → provenance/flow receipt | approximate semantic dependency tracking |
| ATK-028 | image/tool/dependency/signer/key is downgraded or SBOM omission hides subtool | exact supply provenance | signed pinned digest, key lifecycle, dependency closure; mismatch; STOP | substitute each layer/key status → resolver rejects | trusted build/signing compromise |
| ATK-029 | many attenuated children aggregate attempts/disclosure/spend; child delegates to ancestor; same-group agents fake quorum | no amplification, acyclic graph, independence | linear escrow/topology/flow shards/independence groups; graph alert; deny/freeze subtree | random concurrent trees/sharded secret/quorum fixtures → conservation/flow/SoD evidence | collusion/covert reconstruction |
| ATK-030 | workspace config, prompt, memory, tool description/binary, model alias or policy changes behavior | material change invalidates future bindings | impact closure + atomic activation; drift alert; freeze/revoke | mutate each dependency/race activation → stale cap/receipt and historical receipt preserved | incomplete dependency graph |
| ATK-031 | suppress/tamper/flood events, exhaust spool, spoof authoritative source | mandatory evidence completeness | signed sequences/outbox/spool/allowlist; gap/signature/cardinality alerts; STOP/freeze | truncate/reorder/spoof/backpressure/disk-full → deterministic failure/closure | compromised writer without witness |
| ATK-032 | approval replay, stale role/key, fatigue, heterogeneous batch, hidden diff, colluding approvers (`L5-REQ-002/003/005/006/007/008/010`) | valid exact-bound SoD approval | single-use/TTL/revocation/canonical UI/quorum; stale/fatigue alerts; no receipt/revoke | `T-HUM-*` race/UX/disagreement suite → receipt chain | coercion/human fallibility |
| ATK-033 | external connector times out after committing; controller retries and duplicates effect | no auto-retry unknown; capability single-use | precheck/idempotency key/durable consume/reconcile; OUT-001; quarantine | fault before/after remote commit/ack → no auto-retry, later authoritative reconciliation | external system lacks query/idempotency |
| ATK-034 | credentials/env/metadata/token exposed to worker/log/context; confused deputy uses broader broker identity | zero ambient credentials, exact purpose/audience | secret references/JIT broker, no raw secret unless declared, scoped identity; canary/access alerts; revoke | secret/metadata/env/log canaries → no unauthorized bytes/use | side channels/provider access |
| ATK-035 | break-glass same person twice, outside ceiling, auto-renew, silent activation or evidence disabled (`L5-REQ-008/009/010/011`) | emergency inside immutable ceiling | pre-signed profile/dual distinct auth/TTL/alarms/audit; BG-001; deny/expire | break-glass state matrix → dual receipts, alarm, revoke, postmortem | insider collusion/emergency pressure |

## 4.1. Round-4 closure anchors Q-39–Q-51

These stable rows are normative future obligations, not completed runtime evidence. Each row has one requirement anchor, one regression test ID and one evidence ID; `ABSENT` means the artifact has not yet been produced.

| Issue | Requirement anchor | Required regression / oracle | Required evidence artifact | Current status |
|---|---|---|---|---|
| Q-39 | `L0-REQ-016`, `L2-REQ-014a` | `T-Q39-SUPPLY-EXTERNAL-BUNDLE-SUBSTITUTION`: synchronized component-byte substitution → reject | `EV-R4-Q39-001`: external verifier, registry/revocation, exact-loaded-bytes and placement chain | `SPECIFICATION_MODEL_TESTED; RUNTIME ABSENT/UNTESTED` |
| Q-40 | `L3-REQ-019` | `T-Q40-D2-EMPTY`, `T-Q40-D2-STALE`, `T-Q40-D2-HIDDEN_N_PLUS_2`, `T-Q40-D2-REQUIRED-ARTIFACT-MISSING` → reject | `EV-R4-Q40-001`: authoritative complete inventory snapshot/digest and denial trace | `SPECIFICATION_MODEL_TESTED; RUNTIME ABSENT/UNTESTED` |
| Q-41 | `L4-REQ-001` (event model) | `T-Q41-EVENT-EMITTER-ROLE-FORGE`: rehashed worker/forged emitter identity → reject | `EV-R4-Q41-001`: external emitter principal-role-component-key freshness/revocation record | `SPECIFICATION_MODEL_TESTED; RUNTIME ABSENT/UNTESTED` |
| Q-42 | `L4-REQ-002` (canonical chain) | `T-Q42-EVENT-DIGEST-SUBSTITUTION`: mutate canonical event digest → reject | `EV-R4-Q42-001`: signed canonical event and externally verified source chain | `SPECIFICATION_MODEL_TESTED; RUNTIME ABSENT/UNTESTED` |
| Q-43 | `L0-REQ-006`, `L2-REQ-014b` | `T-Q43-DESCRIPTOR-ROOT-SUBSTITUTION`: descriptor/root identity substitution → reject | `EV-R4-Q43-001`: end-to-end descriptor binding and final receipt identity trace | `SPECIFICATION_MODEL_TESTED; RUNTIME ABSENT/UNTESTED` |
| Q-44 | `L3-REQ-020` | `T-Q44-CONTRACT-SUBSTITUTION`: synchronized active contract digest/lineage substitution → reject | `EV-R4-Q44-001`: trusted active-contract lookup and real lineage receipt | `SPECIFICATION_MODEL_TESTED; RUNTIME ABSENT/UNTESTED` |
| Q-45 | `L3-REQ-021` | `T-Q45-STAGEABLE-CRASH-QUARANTINES`: crash after durable dispatch without no-effect proof → quarantine, escrow retained | `EV-R4-Q45-001`: recovery/quarantine/reconciliation and no-effect verifier record | `SPECIFICATION_MODEL_TESTED; RUNTIME ABSENT/UNTESTED` |
| Q-46 | `L0-REQ-020`, `L1-REQ-022` | `T-Q46-DIRECT-WORKER-MUTATE-DENY` rejects worker mutation; `T-DECISION-ALLOW-EXACT` accepts broker→executor control | `EV-R4-Q46-001`: compiled subset, worker denial and distinct sink trace | `SPECIFICATION_MODEL_TESTED; RUNTIME ABSENT/UNTESTED` |
| Q-47 | `L3-REQ-022` | `T-Q47-MUTATION-SELF-AUDIENCE-DENY` rejects worker audience; `T-DECISION-ALLOW-EXACT` accepts executor audience | `EV-R4-Q47-001`: verified executor role/principal/session mapping | `SPECIFICATION_MODEL_TESTED; RUNTIME ABSENT/UNTESTED` |
| Q-48 | `L2-REQ-014c`, `L3-REQ-023` | `T-Q48-POLICY-SCOPE-KIND-CROSS-MATRIX`: endpoint/file cross-kind authorization → reject | `EV-R4-Q48-001`: typed scope/resource relation and negative matrix | `SPECIFICATION_MODEL_TESTED; RUNTIME ABSENT/UNTESTED` |
| Q-49 | `L3-REQ-024`, `L4-REQ-003` | `T-Q49-COMMIT-TYPED-EVIDENCE-FORGE`, `T-Q49-JOIN-TYPED-EVIDENCE-FORGE` → reject | `EV-R4-Q49-001`: externally verified typed chain through JOIN | `SPECIFICATION_MODEL_TESTED; RUNTIME ABSENT/UNTESTED` |
| Q-50 | `L3-REQ-025` | `T-Q50-BUDGET-SCOPE-IDENTITY-SUBSTITUTION`, `T-Q50-BUDGET-LINEAGE-IDENTITY-SUBSTITUTION`, `T-Q50-BUDGET-FOUR-PART-KEY-PRESERVED` | `EV-R4-Q50-001`: four-part budget key equality/conservation trace | `SPECIFICATION_MODEL_TESTED; RUNTIME ABSENT/UNTESTED` |
| Q-51 | `L3-REQ-026` | `T-Q51-ISSUE-EXTERNAL-FULL-RECORD`, `T-Q51-DISPATCH-EXTERNAL-FULL-RECORD`: rehashed forged field → reject | `EV-R4-Q51-001`: durable external full-field verifier records at both gates | `SPECIFICATION_MODEL_TESTED; RUNTIME ABSENT/UNTESTED` |

## 4.2. Round-5 closure anchors Q-53–Q-59 (post-round remediation)

These anchors record the patched model obligations after the historical Round-5
packet. They do not change the Round-5 disposition and do not constitute
runtime verification. Test IDs are existing entries in
`tests/policy-test-vectors.json` and/or `tests/invariant-traceability.json`.

| Issue | Normative closure anchor | Existing model tests | Runtime |
|---|---|---|---|
| Q-53 | `10 §7.2 Q-53`; `13 §7.1 Q-53` — complete externally verified signed attestation projection | `T-ATTESTATION-SIGNED-FIELDS-POSITIVE`; `T-ATTESTATION-SIGNED-FIELD-MUTATION-EXPIRY`; `T-ATTESTATION-SIGNED-FIELD-MUTATION-HOST`; `T-ATTESTATION-SIGNED-FIELD-MUTATION-NONCE`; `T-ATTESTATION-SIGNED-FIELD-MUTATION-SIGNER` | `ABSENT` |
| Q-54 | `12 §4.1 Q-54`; `L2-REQ-014c` — closed `resource_kind↔selector.kind` matrix | `T-Q48-MANIFEST-FILE-PRINCIPAL-EXACT-DENY`; `T-Q48-MANIFEST-FILE-PATH-PREFIX-POSITIVE`; `T-Q48-MANIFEST-FILE-PATH-EXACT-POSITIVE` | `ABSENT` |
| Q-55 | `10 §6.2 Q-55`; `12 §4.1 Q-55`; `L2-REQ-014b` — `PATH_EXACT` descriptor digest/identity | `T-Q43-PATH-EXACT-DESCRIPTOR-DIGEST-DENY`; `T-Q43-PATH-EXACT-DESCRIPTOR-ROOT-DENY`; `T-Q43-PATH-EXACT-DESCRIPTOR-MOUNT-DENY`; `T-Q43-PATH-EXACT-DESCRIPTOR-EPOCH-DENY`; `T-Q43-PATH-EXACT-DESCRIPTOR-POSITIVE` | `ABSENT` |
| Q-56 | `10 §7.1 Q-56`; `L0-REQ-012` — exact closed resource-unit-enforcer mapping | `T-Q56-ISOLATION-RESOURCE-POSITIVE-CONTROLS`; complete `T-ISOLATION-RESOURCE-CROSS-MATRIX-*` | `ABSENT` |
| Q-57 | `10 §7.4 Q-57`; `12 §4 Q-57`; `L2-REQ-014a` — trusted-root equality and measurement-preimage inclusion | `T-Q57-SUPPLY-TRUSTED-ROOT-POSITIVE`; `T-SUPPLY-TRUSTED-ROOT-MISMATCH`; `T-SUPPLY-TRUSTED-ROOT-EXTERNAL-MISMATCH` | `ABSENT` |
| Q-58 | `13 §8 Q-58`; `L3-REQ-009` — exactly one durable terminal reservation disposition on every pre-dispatch rejection | `T-ISSUE_CAPABILITY-MALFORMED-ONE-DISPOSITION`; `T-ISSUE_CAPABILITY-NO-DUPLICATE-DISPOSITION`; `T-ISSUE_CAPABILITY-FRESH-BOUNDED-PROPOSAL`; `T-ISSUE_CAPABILITY-PREDISPATCH-ISSUED-QUARANTINE`; `T-ISSUE_CAPABILITY-PREDISPATCH-PRECHECKED-QUARANTINE` | `ABSENT` |
| Q-59 | `13 §7.1 Q-59`; `14 §3.3 Q-59`; `L3-REQ-024` — manifested/physical/authorized/committed containment; attempted excess blocked | `T-Q59-EVENT-AUTHORIZED-SUBSET-MANIFESTED-POSITIVE`; `T-Q59-EVENT-AUTHORIZED-SUBSET-MANIFESTED-DENY`; `T-Q59-EVENT-ATTEMPTED-EXCESS-BLOCKED`; `T-Q59-EVENT-ATTEMPTED-EXCESS-REQUIRES-BLOCKED`; `T-Q59-EVENT-TRUSTED-BINDING-NEGATIVE` | `ABSENT` |

## 5. Crash, concurrency and mutation matrix

Every durability boundary is fault-injected immediately before and after: normalize/classify/decide; reserve; capability issue; durable consume+dispatch intent; executor receipt; external outcome; quiesce; seal; postcheck; commit; JOIN; release/reclaim; material activation. Required invariant: crash/retry never widens authority, reuses capability, resets cumulative counters, silently commits, or retries `UNKNOWN_OUTCOME`.

Concurrency schedules include two consumes of one capability, two controllers per lineage, budget reserve race, revoke/cancel versus dispatch/commit, writer versus seal/postcheck, registry/policy update versus resolution, duplicate/reordered events and concurrent child escrow/reclaim.

Mutation suite removes or inverts every safety predicate: envelope meet, deny precedence, required schema field/bound, taint propagation, material invalidation, single-use, monotonic counter, legal-transition edge, unknown-retry prohibition, writer freeze and mandatory event. Every mutant MUST be killed by a named test; surviving mutant is an open coverage finding, never an acceptable coverage percentage.

### 5.1. Mandatory pure-regression counterexamples

The specification runner MUST preserve named, non-destructive fixtures for: duplicate budget amplification; admission-before-issuance and replay-after-STOP; every D2 N+2 frontier class; ill-typed authority atom and correlated scope/time cross-pair; unauthorized/unevidenced JOIN and contradictory effect receipt; branch terminal budget conservation and unknown escrow; non-APPROVE authorization state; unsafe/duplicate-role active isolation profile; lexical and encoded traversal; unresolved traceability ID/assertion removal; stale/wrong placement session/nonce/epoch; supervisor-crash orphan fencing; and revoked/rollback/substituted supply bundle. Each fixture has a reason-code oracle and an executed assertion ID. These abstract checks create `SPECIFICATION_TESTED` evidence only; Linux, signature, durable-store and sink conformance remain separate `ABSENT` runtime evidence.

The mandatory mutation set also changes every capability signed field while recomputing its plain digest; fabricates/rebinds approval verifier output; omits each required scoped budget key; uses an intrinsic D2 class with all flags false or exceeds `max_iterations`; swaps object identity between seal/postcheck/commit/JOIN; crashes from every phase including `COMMITTED`; reuses prior transaction fields; amplifies/revokes a delegation subtree; and substitutes one signed supply-chain edge. Every case MUST fail with its named oracle.

## 6. Test execution classes

| Class | Safe execution environment | Success oracle |
|---|---|---|
| Pure schema/policy/LTS | local disposable process; no external effects | expected valid/invalid and decision/state results exactly match vectors |
| Linux negative/conformance | disposable isolated test host/VM dedicated by platform owner | forbidden attempt blocked; canaries unchanged; attestation matches profile |
| Resource/fault/concurrency | bounded dedicated disposable environment with watchdog and host protection | hard ceiling holds; recovery state/evidence exact |
| External connector | fake/stub service first; production-like sandbox only with explicit authorization | duplicate/unknown/reconcile semantics match; no real user effect |
| Human UX | synthetic fixtures and authorized usability study | canonical presentation properties; no implied comprehension guarantee |
| Incident/game day | non-production profile unless separate change approval | scoped containment and complete closure bundle |

External payload execution requires a separate authorized test plan with target, blast radius, stop conditions, owner and recovery. This package itself grants no authority to run it.

## 7. Evidence maturity and coverage gate

For every attack row, readiness requires:

1. exact test case and environment/profile digest;
2. precondition and controlled canary/target;
3. enforcement/decision/TCB event from authoritative source;
4. actual-effect or absence evidence appropriate to the claim;
5. cleanup/reconciliation receipt;
6. immutable test report digest and trace to invariant/requirement;
7. residual-risk statement and owner.

Current evidence: source mapping and abstract schema/policy tests only. No Linux attack, external effect, human study, telemetry suppression, game day or runtime conformance result exists. Accordingly the matrix is `DECLARED_TEST_PLAN`, not `VERIFIED_ATTACK_RESISTANCE`.

## 8. Covert-channel statement

The design reduces and accounts for named channels but does not claim zero capacity. Each deployment profile must state shared resources, assumed adversary strength, acceptable residual capacity and whether stronger container/microVM/VM/dedicated-host placement is required. Detection or rate limits are not proof of absence.

## 9. Oracle discipline

Each listed control mutation has two declared outcomes: schema validity and semantic validity. The runner MUST assert both independently; `schema_reject OR semantic_reject` is not an oracle. Required mutations cover activation/provenance/rollback, descriptor-to-final-object races, heartbeat/recovery identity, every risk-disposition type/payload mismatch, stage evidence, OS-subject collisions, receipt effect/target/budget/flow and approver evidence, same-key sibling escrow, the full invalid effect/resource/operation cross-product, byte-level path forms, and chain gap/fork/replay/reorder/reset/truncation. This requirement produces specification-test evidence only, not runtime attestation.
