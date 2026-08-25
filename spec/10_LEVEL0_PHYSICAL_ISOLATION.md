# 10. Level 0 — физическая изоляция

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
| Level claim | Риск-профили и обязательства Linux/runtime boundary; не attestation существующей среды |
| Corpus snapshot | aggregate source SHA-256 `08a296ee00349eac64d13292e4d4c714d1de0cd412adca1c695ef5e5f92838e0` |

Слова **MUST / MUST NOT / SHOULD / MAY** нормативны в смысле RFC 8174.

## 1. Purpose, protection claim и non-goals

Level 0 задаёт физический ceiling: что конкретный principal может сделать даже при произвольном malicious output. Он ДОЛЖЕН ограничивать filesystem, process/IPC, network, devices, credentials, resources и lifecycle независимо от prompt, manifest, runtime policy и human approval.

Level 0 не классифицирует semantic intent и не доказывает, что разрешённая операция полезна или безопасна по смыслу. Он также не устраняет все kernel/hardware/covert-channel risks.

### 1.1. Точный V0 claim для минимального профиля

`L0-LX-A / DISCONNECTED_STAGEABLE_WORKER` задаёт целевую, но пока не реализованную границу:

- application effects worker-а physically intended: локальные `COMPUTE`, чтение объявленных read-only inputs (`OBSERVE`) и stageable mutation только объявленного ephemeral workspace (`MUTATE`); единственный дополнительный flow — system-owned, типизированный `COMMUNICATE` edge к exact broker control/model IPC;
- worker-directed external/user-visible `COMMUNICATE`, `DELEGATE`, authority-relevant/persistent `REFLECT`, external mutation, credentials/secrets и host checkout — explicit `DENY`;
- model/control message MAY пересечь границу только по типизированному broker IPC; внешний model call выполняет отдельный broker-owned gateway principal и классифицируется `COMMUNICATE`;
- никакой staged delta не становится committed до quiescence, immutable seal и independent postcheck;
- все количественные limits MUST быть concrete integers with units в активированном profile. В V0 значения `TBD(profile)`, поэтому профиль нельзя считать deployable.

Это «current minimal implementable profile» как specification target, а не утверждение об implementation.

### 1.2. Non-goals и запрещённые overclaims

Нельзя называть полной изоляцией отдельно или в простой сумме:

- `chroot`/`pivot_root`;
- отсутствие `git` в `PATH`;
- `iptables -P OUTPUT DROP`;
- read-only mount/sidecar;
- rootless container;
- default seccomp;
- `docker run --rm`/аналог;
- очистку wildcard-командой.

Каждый механизм имеет предпосылки, дополняющие controls и residual risk.

## 2. Assets, adversaries и trust assumptions

### 2.1. Assets

- host kernel, runtime daemon/hypervisor и TCB configuration;
- host/project data, checkout, `.git`, sockets, devices, process memory;
- declared read-only inputs, writable staging workspace и sealed outputs;
- broker/executor/model-gateway/observer credentials и FDs;
- CPU, memory/swap, PIDs, block IO, disk bytes/inodes, FDs, GPU, wall time;
- isolation/image/runtime/config digests и placement/session/seal/cleanup receipts.

### 2.2. Adversaries

Level 0 предполагает malicious worker code, shell payload, fork/resource abuse, filesystem races, proc/ptrace/device/IPC discovery, inherited-FD abuse, IPv4/IPv6/DNS/loopback/metadata egress, persistence в writable layers и попытки помешать seal/cleanup. Также учитываются runtime misconfiguration, stale image/config, competing writers и crash.

### 2.3. Trust assumptions

1. Kernel/runtime/hypervisor и outer host controls trusted только в scope заявленного профиля и pinned versions.
2. Broker, executor, gateway и observer запускаются как отдельные principals/envelopes; worker не может писать их binaries/config/state.
3. Host cgroup/LSM/network/mount enforcement не управляется worker-ом.
4. Session supervisor способен идентифицировать и terminate/freeze весь process tree и отозвать writer handles.
5. Attestation issuer и evidence store аутентифицированы; self-report worker-а не является authoritative.

Если assumption не подтверждён evidence, соответствующий protection claim остаётся `UNTESTED`, а risk action MUST NOT активироваться.

## 3. Inputs, outputs и authoritative sources

### 3.1. Inputs

```text
IsolationProfile = {
  profile_id/version/digest,
  principal_id,
  kernel/runtime/image digests,
  namespace_plan,
  uid_gid_map,
  mount_plan,
  path_policy,
  fd_ipc_plan,
  network_plan,
  capability_seccomp_lsm_plan,
  proc_device_gpu_plan,
  resource_budget_vector,
  secret_reference_policy,
  lifecycle/seal/cleanup_plan,
  required_attestations,
  residual_risk_statement
}
```

`resource_budget_vector` MUST как минимум иметь целочисленные поля с единицами для `cpu_time`, `cpu_rate`, `wall_time`, `memory`, `swap`, `pids`, `block_io_read/write`, `filesystem_bytes`, `filesystem_inodes`, `output_bytes`, `open_fds`, `gpu_time/memory`, а broker ledger отдельно — `tokens`, `spend_minor_units`, `tool_calls`, `messages`, `concurrency`, `agent_count`, `delegation_depth/fanout`.

Значение `null`, «unlimited», неразобранная строка либо отсутствующая обязательная размерность даёт `STOP/RC_BUDGET_EXHAUSTED|RC_UNKNOWN`; human approval не исправляет unbounded profile.

### 3.2. Authoritative sources

- digest-pinned profile, image/runtime artifacts и policy/contract;
- фактические kernel/runtime/cgroup/mount/network/LSM state из host-side attestor;
- supervisor, broker и observer events;
- sealed filesystem/object digest и resource accounting from enforcement plane.

Worker environment, `PATH`, текстовая команда и agent self-report не являются authoritative source границы.

### 3.3. Outputs/evidence artifacts

- `EV-L0-PLACEMENT-*`: placement/profile attestation;
- `EV-L0-SESSION-*`: namespace/mount/FD/network/resource session receipt;
- `EV-L0-BLOCK-*`: authoritative denied syscall/path/flow/resource events;
- `EV-L0-SEAL-*`: quiescence + immutable snapshot digest receipt;
- `EV-L0-CLEANUP-*`: verified teardown/no-reuse evidence;
- `EV-L0-CONFORMANCE-*`: test report tied to exact kernel/runtime/image/profile digests.

## 4. Risk-based isolation profiles

| Profile | Intended workload | Required boundary | Exact non-claim / escalation trigger |
|---|---|---|---|
| `L0-LX-A DISCONNECTED_STAGEABLE_WORKER` | Pinned tools/code; stageable ephemeral workspace mutation; no credentials/external effects/delegation/reflection | Hardened shared-kernel sandbox, worker network disconnected, broker IPC only, full controls `L0-REQ-001..022` | Не подходит, если arbitrary native code, sensitive secrets, hostile multi-tenancy или kernel escape impact неприемлемы |
| `L0-LX-B MEDIATED_SINK_WORKER` | То же, но request может вызвать broker/executor external sink | Worker остаётся как LX-A; broker/executor/gateway имеют отдельные principals, exact call capabilities, JIT secrets и own profiles | Не означает network/credentials у worker; non-stageable effects требуют L3 reconciliation, не только L0 |
| `L0-VM-C STRONG_KERNEL_BOUNDARY` | Untrusted native code, более чувствительные данные, hostile tenants или высокий impact shared-kernel compromise | MicroVM/VM или эквивалентная separate-kernel boundary, device/IOMMU/network/storage controls, attested image | Не устраняет hypervisor/hardware/covert channels; exact technology/profile требует отдельной threat assessment |
| `L0-DEDICATED-D` | Высокая чувствительность или недопустимое соседство/covert capacity | Dedicated host/VM placement, constrained ingress/egress, physical/operational controls | Не является автоматическим соответствием provisional `R0–R6`; risk owner и evidence обязательны |

### 4.1. Profile selection rule

Выбор MUST учитывать минимум: доверие к code/toolchain, sensitivity/taint, наличие secrets, stageability/reversibility, external sinks, multi-tenant adjacency, blast radius, kernel attack surface, required covert-channel bound и recovery needs. Неизвестная ось выбирает более сильный profile или `DENY/STOP`.

`PLACEMENT-P2` из корпуса — PROVISIONAL label. V0 не отождествляет его автоматически ни с `L0-LX-A`, ни с roadmap `PHASE-P2`.

## 5. Нормативные требования и enforcement ownership

| ID | Нормативное требование | Owner / enforcement point | Failure semantics | Test / evidence |
|---|---|---|---|---|
| `L0-REQ-001` | Каждая session MUST назвать exact profile/version/digest, principal, kernel/runtime/image digests и все concrete limits. Profile без bounds MUST NOT стартовать. | Placement controller + host attestor | `STOP` до process creation | `T-SCHEMA-L0-001`, `EV-L0-PLACEMENT-001` |
| `L0-REQ-002` | Worker, broker, executor, model gateway и observer/postcheck MUST быть pairwise-distinct OS/security principals и иметь разные envelopes/sessions. Agent MUST NOT наследовать sink authority. | Deployment/runtime supervisor | Refuse placement; revoke/kill при обнаружении shared authority | `T-ATTACK-L0-PRINCIPAL-001`, session attestation |
| `L0-REQ-003` | Shared-kernel Linux profile MUST изолировать user, mount, PID, IPC, UTS, network и cgroup views; enforcement budgets MUST применяться host cgroup v2/equivalent, а не только cgroup namespace. | Host runtime | Session start fails closed | `T-ATTACK-L0-NS-001`, namespace/cgroup inventory |
| `L0-REQ-004` | Worker MUST запускаться с non-host UID/GID mapping, без privileged mode, с dropped Linux capabilities и `no_new_privs`; setuid/setgid/file capabilities MUST быть недоступны. | Runtime + kernel | Exec denied/kill | `T-ATTACK-L0-PRIV-001`, capability/uid trace |
| `L0-REQ-005` | Rootfs MUST быть minimal и read-only; mounts private/non-propagating; inputs read-only; staging outputs отделены; writable paths исчерпывающе перечислены и quota-bound. | Mount namespace builder | Start refusal или block + incident | `T-ATTACK-L0-MOUNT-001`, mountinfo attestation |
| `L0-REQ-006` | Filesystem access MUST разрешаться относительно pre-opened trusted directory descriptors с platform `openat2`-equivalent constraints, проверкой identity/type и TOCTOU-safe operations. Symlink, hardlink, magic-link, traversal, rename и mount-crossing MUST учитываться. | Filesystem broker/LSM/runtime | Path denied; attempted effect event; stop on ambiguity | `T-ATTACK-L0-PATH-001/002`, path/inode trace |
| `L0-REQ-007` | Worker MUST NOT видеть host checkout, `.git`, VCS object store/hooks/socket/config. Удаление `git` из `PATH` MAY быть defense-in-depth, но не control boundary. | Mount builder + path PEP | Start refusal или denied access | `T-ATTACK-L0-GIT-001`, mount/path inventory |
| `L0-REQ-008` | Перед exec supervisor MUST закрыть все FDs кроме explicit typed allowlist (`close_range`/equivalent), запретить broad inherited sockets/pipes, shared memory и host IPC. Каждый broker IPC endpoint MUST быть peer-authenticated и operation-scoped. | Supervisor + IPC broker | Start refusal; kill/revoke on unexpected FD | `T-ATTACK-L0-IPC-001`, FD inventory |
| `L0-REQ-009` | `L0-LX-A/B` worker MUST быть network-default-disconnected: IPv4, IPv6, loopback, routes, DNS resolver, metadata endpoints, raw/packet sockets и direct UNIX-socket egress недоступны, кроме exact broker IPC из `L0-REQ-008`. | Host network/runtime/seccomp | Socket/connect blocked; authoritative event; kill on bypass | `T-ATTACK-L0-NET-001/002`, packet/syscall/route evidence |
| `L0-REQ-010` | Любой разрешённый внешний flow MUST выполняться отдельным broker/executor/gateway principal с own L0 profile и exact-bound capability. Worker MUST NOT получать connected FD или credential в обход broker. | Broker + executor | `DENY`; revoke route | `T-ATTACK-L0-BROKER-001`, cross-principal trace |
| `L0-REQ-011` | Profile MUST применить syscall allowlist seccomp/equivalent, LSM policy (SELinux/AppArmor/Landlock where applicable), proc/ptrace restrictions, device allowlist, no eBPF/module/admin interfaces. Ни один из controls не считается достаточным отдельно. | Kernel/runtime/LSM | Syscall denied; repeated/probing attempts → kill | `T-ATTACK-L0-SYSCALL-001`, seccomp/LSM evidence |
| `L0-REQ-012` | CPU, memory/swap, PIDs и block IO MUST иметь hard host-enforced bounds; filesystem bytes/inodes/output и `RLIMIT_NOFILE`/equivalent MUST быть bounded. | cgroup/quota/runtime | New allocation denied; process tree killed if policy says hard termination | `T-ATTACK-L0-RESOURCE-001`, resource receipt |
| `L0-REQ-013` | Wall deadline MUST контролироваться external supervisor; cancel/timeout MUST terminate/freeze the entire process tree and revoke leases/FDs, not only PID 1. | Supervisor | `STOPPED`; staged delta discarded unless safely sealed | `T-LTS-L0-TIMEOUT-001`, supervisor/process-tree trace |
| `L0-REQ-014` | GPU resources and non-kernel budgets (tokens, spend, calls, messages, concurrency, agent count/depth) MUST контролироваться dedicated scheduler/broker ledger; cgroups alone insufficient. | GPU scheduler + broker | Deny reservation/cancel subtree; counters persist | `T-ATTACK-L0-RESOURCE-002`, combined ledger evidence |
| `L0-REQ-015` | Worker MUST иметь zero ambient credentials. Secret references MAY разрешаться broker-ом just-in-time в exact sink operation; secret bytes MUST NOT попадать worker-у без отдельного explicit envelope. | Secret broker + executor | Deny; rotate/revoke on exposure | `T-ATTACK-L0-SECRET-001`, canary/no-secret scan |
| `L0-REQ-016` | Image, runtime, kernel profile, tool binaries и policies MUST быть version/digest pinned, provenance-checked и tied to placement receipt. A trusted external supply verifier MUST bind signed component/dependency facts, registry snapshot, revocation/rollback state, exact loaded bytes and placement; caller-controlled measurements or recomputed plain digests are not verification. Mismatch or stale revocation MUST fail closed. | Supply-chain resolver + attestor | `STOP/RC_DIGEST_MISMATCH` | `T-ATTACK-SUPPLY-003`, `T-Q39-SUPPLY-EXTERNAL-BUNDLE-SUBSTITUTION`; provenance/attestation bundle |
| `L0-REQ-017` | Каждая iteration MUST получать fresh session и private writable storage. Writable layer/volume/tmp/shm/registry reuse MUST быть запрещён, если persistence не declared and labelled. Cleanup MUST быть target-specific и verified; wildcard deletion не security proof. | Session lifecycle manager | Refuse reuse; quarantine residue | `T-ATTACK-L0-PERSIST-001`, cleanup receipt |
| `L0-REQ-018` | Перед snapshot supervisor MUST добиться quiescence, закрыть/revoke all writer paths, создать immutable/content-addressed seal и не допускать writer до `JOIN`. | Supervisor + snapshotter | Discard или quarantine on uncertainty | `T-ATTACK-SEAL-001`, `EV-L0-SEAL-001` |
| `L0-REQ-019` | Observer/postcheck MUST исполняться вне worker write/trust domain и читать тот же sealed digest, который может быть committed. Read-only mount сам по себе не доказывает independence. | Observer owner + commit authority | Postcheck invalid; discard/quarantine | `T-ATTACK-SEAL-002`, observer/commit digest match |
| `L0-REQ-020` | Известные, но disabled effects/sinks MUST быть explicit `DENY`, а не absent ambiguity. Compiled worker effects MUST be a subset of `Physical(worker)`; worker `COMMUNICATE` is proposal-only, and any permitted external/user-visible communication MUST use a separate broker/model-gateway sink hop. Worker MUST NOT receive a direct mutation capability or direct mutation route; mutation requires a distinct mediated executor. Для LX-A application effects: worker-directed external/user-visible `COMMUNICATE`, `DELEGATE`, persistent/authority `REFLECT`, credentials/external effects запрещены; exact system-owned broker IPC из `L0-REQ-008/010` — единственное разрешённое communication edge. | Profile compiler + PEP | `DENY/RC_PHYSICAL_CEILING` | `T-POL-L0-001`, `T-Q46-DIRECT-WORKER-MUTATE-DENY`, `T-Q47-MUTATION-SELF-AUDIENCE-DENY`, `T-DECISION-ALLOW-EXACT`; compiled ceiling artifact |
| `L0-REQ-021` | Block/kill/resource/seal/cleanup events MUST исходить из TCB/supervisor/broker и быть unsampled safety events. Unbounded IDs/paths/args MUST NOT быть metric labels. | TCB telemetry issuer | Missing required event → `STOP/QUARANTINE` | `T-ATTACK-TELEM-001`, event completeness evidence |
| `L0-REQ-022` | Profile MUST задокументировать shared-kernel/hypervisor/hardware/covert-channel residual risks и objective escalation criteria. Неприемлемый или unknown residual MUST выбрать stronger profile либо deny workload. | Security owner + risk owner | Placement denied; агент не принимает risk | `T-HUM-L0-PROFILE-001`, signed risk disposition |

## 6. Invariants, preconditions и postconditions

### 6.1. Level invariants

- `L0-I1`: `Physical(worker) ⊑ declared L0 profile`; обнаруженный более широкий path/flow/privilege — нарушение.
- `L0-I2`: `Physical(worker)` не содержит direct external network/credential/delegation/reflection authority в `L0-LX-A/B`.
- `L0-I3`: broker/executor/gateway authority не наследуется через environment, FD, filesystem, IPC или process relation.
- `L0-I4`: writable objects до seal принадлежат ровно одной current epoch/session; после seal writer отсутствует.
- `L0-I5`: resource use + reserved use не превышает concrete profile vector; unbounded dimension запрещает start.
- `L0-I6`: cleanup/restart не сбрасывает durable lineage/budget и не делает старый session/capability reusable.

Они реализуют `INV-002/003/005/007/008/010/012/013/015` из formal core.

### 6.2. Session preconditions

До process creation ДОЛЖНЫ быть true:

1. exact profile и все mandatory bounds concrete;
2. image/runtime/tool/config digests match immutable resolution;
3. namespaces/mounts/UID/capabilities/seccomp/LSM/cgroups/network/FD plans скомпилированы без unknown;
4. broker IPC endpoint exact-scoped и peer-authenticated либо отсутствует;
5. no ambient secrets/host checkout/shared writable registry;
6. current epoch/fencing/session ID связан с contract/capability lineage;
7. attestor успешно проверил фактическое состояние.

Descriptor-root identity, mount identity, descriptor ID and epoch MUST be one trusted composite binding and MUST remain unchanged through manifest, policy, capability, dispatch and effect/receipt records; descriptor-only substitution or host-root substitution is `STOP`.

Every compiled filesystem target is an independently signed/attested typed record binding canonical path, descriptor/root/mount identities, resolution epoch and final object identity/digest in one composite digest. Admission verifies that digest against an independent target record, carries it in the capability authority entry, and dispatch requires the same immutable digest; an alternate root, mount or epoch for the same path is `STOP`.

An endpoint-only compiled envelope MUST carry one or more exact `endpoint_binding`
tuples (`endpoint_id`, `canonical_endpoint`, `connector_id`, `connector_digest`,
`method`, `idempotency_key_digest`, `endpoint_binding_digest`) and MUST NOT
carry path scopes or filesystem targets. A compiled envelope MUST NOT mix
`ENDPOINT` with `FILE` or `DIRECTORY`; the compiler rejects that mixed route
rather than combining independent target proofs.

**Q-55 normative anchor (`PATH_EXACT`).** An exact path selector MUST carry the
descriptor binding digest plus the trusted `descriptor_id`, root identity, mount
identity and epoch; the canonical descriptor identity and normalized path MUST
remain equal through manifest, policy, capability, dispatch and receipt. Any
digest, descriptor, root, mount or epoch substitution is `STOP`, even when the
lexical path is unchanged.

Failure любой precondition → `STOPPED`; human approval не override-ит L0.

### 6.3. Session postconditions

Успешный stageable session завершается только если:

- process tree quiesced/terminated, FDs/leases revoked;
- immutable seal digest создан и совпадает с observer input/commit candidate;
- resource usage reconciled в durable ledger;
- attempted/blocked events recorded by authoritative components;
- private writable layers/tmp/shm уничтожены и отсутствие reuse проверено;
- session/capability/epoch не могут быть возобновлены.

## 7. Failure, timeout, crash, retry, recovery и revocation

| Событие | Нормативная semantics |
|---|---|
| Profile compilation/attestation mismatch | Process не создаётся; `STOPPED`; event с reason code. |
| Denied syscall/path/network/IPC | Kernel/PEP блокирует; событие authoritative. Повтор/probing MAY вызвать kill/incident, но не расширение rule. |
| Hard resource exhaustion | Allocation/creation блокируется; supervisor завершает bounded tree согласно policy; actual usage journaled. |
| Wall timeout/cancel | Kill/freeze entire tree; revoke handles; unsealed state discarded; uncertain seal → quarantine. |
| Runtime/host crash before seal | Никакой workspace state не считается committed; recovery проверяет durable dispatch/session facts; новый session требует fresh admission. |
| Crash после seal до commit/JOIN | Sealed object хранится quarantined; recovery проверяет digest/epoch/evidence; старый worker не возобновляется. |
| Cleanup failure/residue | Session lineage quarantined; storage не переиспользуется; новая iteration не стартует на том же writable state. |
| Revocation | Запрет новых calls, cancel/freeze/kill route, revoke broker/executor capabilities; уже возможный external effect обрабатывает L3 reconciliation. |
| Retry | Только новая transaction/capability/session; cumulative counters не сбрасываются; unknown external outcome не auto-retry. |

## 7.1. Active-profile semantic gate

JSON shape validation недостаточна. Перед process creation trusted profile compiler MUST проверить и подписать compiled profile:

- ровно по одному pairwise-distinct OS/security principal и session identity для `AGENT_WORKER`, `BROKER`, `EXECUTOR`, `MODEL_GATEWAY`, `OBSERVER_POSTCHECK`; один principal/session/credential namespace не может занимать несколько ролей;
- worker: `ambient_authority=false`, credentials `NONE`, direct network `DISCONNECTED`, отсутствие inherited ambient FDs, rootless mapping, private mounts и read-only minimal rootfs; writable поверхности — только перечисленные quota-bound staging objects;
- profile-specific полный, без duplicate keys, resource vector: `CPU_TIME`, `CPU_RATE`, `WALL_TIME`, memory+swap, PIDs, read+write block IO, bytes, inodes/files, FDs и explicit `GPU_TIME`/`GPU_MEMORY`; broker дополнительно обеспечивает calls/tokens/spend/messages/concurrency/agent depth/fan-out;
- `ACTIVE` требует verified compiler, placement, cleanup, supply-chain и session evidence predicates; self-asserted booleans не являются attestation.

Отсутствующая role/dimension, unsafe mount, worker credential/network, duplicate role/key, несовместимые unit/enforcer или false mandatory predicate дают `STOP/RC_ISOLATION_PROFILE_INVALID` до exec.

**Q-56 normative anchor (closed resource mapping).** The active profile MUST
use this closed `(resource, unit, enforcer)` relation exactly; no unit or
enforcer may be supplied independently, aliased, duplicated or left implicit:

| Resource | Unit | Enforcer |
|---|---|---|
| `CPU_TIME` | `MILLISECONDS` | `CGROUP_V2` |
| `CPU_RATE` | `MILLICORES` | `CGROUP_V2` |
| `WALL_TIME` | `MILLISECONDS` | `SUPERVISOR` |
| `MEMORY`, `SWAP` | `MIB` | `CGROUP_V2` |
| `PIDS` | `COUNT` | `CGROUP_V2` |
| `BLOCK_IO_READ`, `BLOCK_IO_WRITE` | `IOPS` | `DEVICE_SCHEDULER` |
| `FILES`, `INODES` | `COUNT` | `FILESYSTEM_QUOTA` |
| `OPEN_FDS` | `COUNT` | `RLIMIT` |
| `OUTPUT_BYTES` | `BYTES` | `FILESYSTEM_QUOTA` |
| `GPU_TIME` | `MILLISECONDS` | `DEVICE_SCHEDULER` |
| `GPU_MEMORY` | `MIB` | `DEVICE_SCHEDULER` |

An active profile contains exactly one of every listed row. GPU unavailable is
explicitly `GPU_TIME=0` and `GPU_MEMORY=0`; GPU enabled requires both limits
to be greater than zero. Its canonical `resource_vector_digest` MUST remain
unchanged through admission, decision, capability, dispatch and receipt.
Operation-specific reservations are a separate exact vector; mismatch is
`STOP/RC_ISOLATION_PROFILE_INVALID`.

## 7.2. Placement/session binding and TOCTOU

Static `isolation_profile_digest` не доказывает actual placement. Host attestor создаёт fresh `PlacementAttestation` над composite measurement: compiled-profile digest, image/runtime/kernel/security-config measurements, exact instance/host/session IDs, namespaces/mount/FD/network/cgroup identities, nonce, monotonic epoch/fence, issue/expiry и revocation state. Verifier result и digest проходят неизменными через request → decision → capability → durable dispatch → event/effect receipt. PEP повторно проверяет freshness, instance и epoch непосредственно перед atomic dispatch; executor сверяет ту же instance binding. Wrong/stale/revoked/missing attestation или race изменения state ведёт в `STOP`, а после consume — `QUARANTINED`.

**Q-53 normative anchor (complete signed attestation projection).** A
`PlacementAttestation`/`SessionAttestation` projection is admissible only when
an external verifier record verifies the complete canonical signed payload and
projects every signed field (subject/host, profile and measurement digests,
nonce, epoch/fence, issue/expiry, signer/key, revocation and placement/session
binding). The projection digest and field values MUST remain identical through
decision, capability, dispatch and receipt; caller recomputation or a partial
verifier record is not evidence and yields `STOP`. Runtime attestation remains
`ABSENT`.

## 7.3. Host lifecycle ledger and orphan recovery

Privileged supervisor MUST durable-record `session_id`, epoch и каждый cgroup/netns/mount/overlay/volume/IPC/shm/socket/lease/process-tree identifier **до** untrusted exec; objects получают independently enumerable labels. На restart supervisor сначала fences all older epochs, enumerates actual resources and performs idempotent reconciliation. Fresh admission для затронутого resource/lineage запрещён, пока каждый old process/writer/lease не доказан absent и storage не cleaned, либо node не переведён в `DRAINED/QUARANTINED`. Невозможность kill/unmount, включая D-state, не может быть записана как successful cleanup; допускается node reset/reboot по отдельному operational protocol.

## 7.4. Supply-chain resolution

`signed_artifacts=true` запрещён как доказательство. Required resolution bundle связывает exact image manifest/config/layers, runtime/loader/dependency closure, architecture/platform, kernel/security configuration, toolset/SBOM и signed registry snapshot/root. Для каждого signed statement проверяются canonical payload, signer/trust policy, algorithm, issue/expiry, key revocation и rollback floor. Loader/host attestor измеряет реально открытые bytes/FDs; mutable tag или совпадающее имя не заменяют digest. Substitution, revoked/untrusted key, rollback/equivocation, platform mismatch или verify-to-load race дают `STOP` до exec.

Один `supply_measurement_digest` MUST быть равен digest verified registry statement, resolved manifest/dependency closure, actually opened image/runtime/tool bytes и placement attestation; тот же digest без пересчёта проходит через decision, capability, dispatch event и effect receipt. Проверенная подпись над одним object при загрузке другого, даже с тем же name/tag, является substitution и блокирует session.

**Q-57 normative anchor (trusted-root measurement).** The trusted-root digest
MUST be exactly equal across candidate supply data, active isolation profile,
external trusted verifier facts and every component record. The root digest
MUST be an explicit member of the canonical measurement preimage (not merely a
parallel field), and the resulting composite measurement MUST equal the
placement/session measurements and the bound `supply_measurement_digest`.
Any root mismatch or preimage omission is `STOP/RC_DIGEST_MISMATCH`.

## 8. Telemetry и evidence

Каждая session MUST emit от authoritative components:

- profile/principal/kernel/runtime/image/policy/contract/capability digests;
- namespace IDs, UID/GID map, mount/network/FD plan digest, cgroup path/limits, seccomp/LSM policy digest;
- session start/exec/deny/resource/cancel/kill/quiesce/seal/postcheck handoff/cleanup events;
- resource before/delta/after и reason codes;
- sealed digest, writer epoch/fence, observer receipt digest;
- cleanup result и residual risk/profile escalation decision.

Safety events MUST быть unsampled. Paths/args/contract hashes MAY находиться в access-controlled logs/traces/evidence, но не как unbounded metric labels. Agent self-report MAY дополнять диагностику, но не удовлетворяет `EV-L0-*`.

Tamper-evident chain без independent witness/anchor доказывает только обнаружимость части изменений при сохранённом anchor; она не является anti-rollback proof.

## 9. Test matrix

| Test ID | Type | Fixture/action | Oracle | Expected evidence | Status |
|---|---|---|---|---|---|
| `T-SCHEMA-L0-001` | Positive/negative | Complete profile; duplicate roles/unsafe worker/missing resources or attestation | Complete accepted; остальные rejected | Schema/semantic report | `SPECIFICATION_TESTED`; runtime absent |
| `T-POL-L0-001` | Positive/negative | Compile LX-A allowed/disabled effect set | Только local C/O/M application scopes и exact system-owned broker IPC present; all worker-directed external sinks и known disabled effects explicit deny | Compiled ceiling digest | `PLANNED/ABSENT` |
| `T-ATTACK-L0-PRINCIPAL-001` | Adversarial | Attempt env/FD/proc/config access to broker/gateway/observer | No secret/authority/config write; attempts blocked | Principal/FD/proc trace | `PLANNED/ABSENT` |
| `T-ATTACK-L0-NS-001` | Adversarial | Escape each namespace / inspect host IDs/mounts/IPC | No undeclared host object reachable | Attested namespace/mount diff | `PLANNED/ABSENT` |
| `T-ATTACK-L0-PRIV-001` | Adversarial | Privileged mode, UID/GID escape, setuid/file-capability/no_new_privs bypass | No host identity/capability gained; exec/syscall denied | UID/capability/kernel trace | `PLANNED/ABSENT` |
| `T-ATTACK-L0-MOUNT-001` | Positive/adversarial | Declared RO/RW mounts; propagation, remount and undeclared writable path attempts | Only enumerated quota-bound staging paths writable; mounts private | mountinfo + write probes | `PLANNED/ABSENT` |
| `T-ATTACK-L0-PATH-001` | Adversarial | Traversal, symlink, hardlink, magic-link, proc-fd, mount-crossing | Outside object unchanged; path denied | Inode/path/syscall evidence | `PLANNED/ABSENT` |
| `T-ATTACK-L0-PATH-002` | Concurrency | Rename/link writer races during access/seal | Descriptor identity holds; no TOCTOU commit | Interleaving trace | `PLANNED/ABSENT` |
| `T-ATTACK-L0-GIT-001` | Adversarial | Discover/write `.git`, object store, hooks, VCS socket/config; invoke hidden git binary | No checkout/VCS state reachable or changed | mount/path/process inventory | `PLANNED/ABSENT` |
| `T-ATTACK-L0-IPC-001` | Adversarial | Unexpected inherited FD/socket/shm/ptrace | Exact FD allowlist only; peer auth enforced | FD/proc/IPC inventory | `PLANNED/ABSENT` |
| `T-ATTACK-L0-PROC-001` | Adversarial | Read broker/adapter env or memory via `/proc`, ptrace, proc-fd and pid reuse | No cross-principal data/handle exposure | proc/ptrace/secret-canary trace | `PLANNED/ABSENT` |
| `T-ATTACK-L0-NET-001` | Adversarial | DNS/IPv4/IPv6/loopback/metadata/raw sockets | All worker direct flows fail; authoritative blocks emitted | Packet/syscall/route evidence | `PLANNED/ABSENT` |
| `T-ATTACK-L0-NET-002` | Fault/adversarial | Stale route/interface/resolver, IPv6 fallback, connected FD and broad UNIX-socket bypass | Attestation/start fails or every undeclared flow blocked | Before/after route/FD/packet evidence | `PLANNED/ABSENT` |
| `T-ATTACK-L0-BROKER-001` | Positive/negative | Typed broker model request; arbitrary socket/target | Declared broker flow works; direct/broader request denied | Cross-principal trace | `PLANNED/ABSENT` |
| `T-ATTACK-L0-SYSCALL-001` | Adversarial | proc/ptrace/device/eBPF/module/admin syscall probes | Denied without privilege/host change | seccomp/LSM/kernel events | `PLANNED/ABSENT` |
| `T-ATTACK-L0-RESOURCE-001` | Boundary/fault | Below/at/above CPU/memory/PID/IO/disk/inode/FD limits | Exact deterministic bound; complete tree containment | cgroup/quota/supervisor report | `PLANNED/ABSENT` |
| `T-ATTACK-L0-CPU-001` | Fault/adversarial | Sleep/spin/starvation near wall and CPU thresholds | CPU and wall bounds independently enforced; whole tree contained | cpu.stat + supervisor timeline | `PLANNED/ABSENT` |
| `T-ATTACK-L0-RESOURCE-002` | Concurrency | Parallel children fragment broker/GPU/token/spend budgets | Conservation holds under all interleavings/crash | Combined ledger traces | `PLANNED/ABSENT` |
| `T-LTS-L0-TIMEOUT-001` | Fault | Supervisor crash/orphan/fence/recovery abstract lifecycle; runtime timeout/cancel remain | No fresh admission before exact reconciliation | Model trace / runtime fault timeline | `PARTIAL_SPECIFICATION_TESTED`; runtime absent |
| `T-ATTACK-L0-PERSIST-001` | Fault/adversarial | Write layer/tmp/shm/registry, crash, start next session | No undeclared bytes/objects visible next session | Before/after storage inventory | `PLANNED/ABSENT` |
| `T-ATTACK-SEAL-001` | Concurrency/fault | Writer after postcheck, checker replacement, seal timeout | Same immutable digest or discard/quarantine | Seal/observer/commit receipts | `PLANNED/ABSENT` |
| `T-ATTACK-SEAL-002` | Negative/fault | Observer shares writer identity/config or receives different snapshot digest | Independence/digest check fails; no commit | Principal attestation + digest chain | `PLANNED/ABSENT` |
| `T-ATTACK-L0-SECRET-001` | Adversarial | Scan env/proc/files/FDs; secret canary request | No secret bytes in worker; exact broker sink only | Canary and broker logs | `PLANNED/ABSENT` |
| `T-ATTACK-SUPPLY-003` | Negative/fault | Composite digest, exact-byte, rollback/revocation/signature model mutations | Admission denied; no fallback to unpinned artifact | Model resolution report | `SPECIFICATION_TESTED`; real signature/loader absent |
| `T-ATTACK-TELEM-001` | Fault/adversarial | Drop/sample/tamper block, kill, resource, seal or cleanup safety event | Missing/tampered event detected; session stops/quarantines | Completeness/tamper report | `PLANNED/ABSENT` |
| `T-HUM-L0-PROFILE-001` | Human/risk | Unknown or unacceptable residual risk; attempted weaker profile selection | Workload denied or escalated; only authorized owner can accept bounded residual | Profile decision/risk receipt | `PLANNED/ABSENT` |

Attack tests MUST выполняться только внутри disposable outer-contained lab, никогда непосредственно на рабочем host. Ни один тест здесь не выполнен в рамках Draft V0.

## 10. Residual risks и unsupported claims

- Shared-kernel profiles остаются уязвимы к kernel/runtime bugs и части microarchitectural/covert channels.
- CPU pinning/cgroups уменьшают resource/timing capacity, но не доказывают нулевой covert channel.
- `openat2`-equivalent защищает только при корректном descriptor-root/mount/file-identity design; он не чинит shared writable mount или malicious filesystem semantics сам по себе.
- Namespace без host-side enforcement может быть неверно configured; firewall inside worker не является доверенной boundary.
- Rootless снижает impact, но user namespaces/runtime daemon/kernel остаются attack surface.
- VM/microVM переносит trust в hypervisor/device model/hardware, не устраняя его.
- Cleanup не может заменить absence of reuse и immutable sealing; `--rm` не доказывает удаление external volumes/logs/caches.
- External provider и broker-owned sink лежат вне worker ceiling и требуют своих claims/evidence.

## 11. Definition of Done

| Stage | Level 0 DoD |
|---|---|
| `DECLARED/SPECIFIED` | Все `L0-REQ-001..022` имеют exact field/owner/failure/test/evidence; profile selection и residual risks явны; concrete deployment profile не содержит `TBD/unbounded`. |
| `IMPLEMENTED` | Pinned runtime создаёт separate principals, компилирует/attest-ит actual namespace/mount/FD/network/seccomp/LSM/cgroup/resource state; quiescence/seal/cleanup и authoritative events реализованы. |
| `VERIFIED` | Все positive/negative/adversarial/concurrency/fault tests проходят на exact kernel/runtime/image/profile digest; independent test подтверждает outside-state invariants и cleanup; residual risk scope/expiry принят уполномоченным owner-ом. |

Текущий честный статус: Level 0 requirements сформулированы; concrete limits, runtime, placement attestation и test evidence отсутствуют. `runtime_isolation_verified=false` остаётся blocker для implementation claim.

## 12. Source-vs-new traceability

| Требование/решение | Corpus source | V0 disposition |
|---|---|---|
| `PLACEMENT-P2`, workspace-only, no network/git, finite session | `HARNESS_ACTIVATION_DIFF.md:77-127`; `:473-506` | Сохранено как PROVISIONAL placement/target, но не как protection proof; numbers не приняты универсально. |
| FS/DNS/runtime/postcheck/resource/persistence attacks | `security.md:7-137`; `comparison.md:137-206` | Разложены по descriptor paths, IPC/network, resources, seal and cleanup; chroot/PATH/iptables/RO sidecar недостаточны отдельно. |
| Практический container recipe | `practical.md:7-24,47-73,110-128`; `synthesis.md:29-114` | Трактуется как proposal, не implementation evidence; RAM/JSONL/wildcard cleanup и readiness estimates не приняты. |
| Полная Level 0 глубина | `metaprompt-harness-levels-0-5-ru.md:191-206,334-350` | Нормализована в `L0-REQ-001..022`, profiles и test matrix. |
| Worker vs broker model channel conflict | `metaprompt...:73` | Разрешён separate-principal/hop model: worker disconnected, gateway is explicit broker `COMMUNICATE`; это новое нормативное уточнение. |
| Physical isolation narrative | `harness_connected_text.md:13-19,41-43`; DOCX `word/document.xml#p0880-p0918` | Narrative principle «physical, not prompt» сохранён; external/absolute claims не повторены. |
| Minimal implementable profile | Новое требование V0; исходного implementation evidence нет | LX-A точно запрещает credentials/external effects/delegation/reflection и позволяет только bounded local stageable C/O/M. |

## Identity and path binding

The active profile MUST bind each symbolic role to an externally verified OS subject: process, UID/GID, mount/PID/network namespaces, security and credential namespaces, session, IPC endpoint and inherited-FD digest. These identities are pairwise distinct where the role separation requires it; distinct role strings alone do not establish separation. Canonical path processing rejects NUL/control characters, separator confusables, ambiguous repeated leading slashes and every path outside the declared `/workspace` root before descriptor binding. Final object identity is owned by the formal binding rule in `04_FORMAL_CORE_AND_INVARIANTS.md`.

## Broker IPC binding

The worker MUST have rootless user mapping, a non-root externally verified UID/GID, and disabled loopback, IPv4, IPv6 and DNS; it has no worker network path or generic Unix-socket allowance. Its only broker interaction is a separately attested closed `broker_ipc_binding`: exact worker/broker principals and endpoints, their distinct named network namespaces, `UNIX_SEQPACKET` transport, verified peer credentials and a binding digest. Static `peer_credentials_verified` is declared intent, not runtime evidence: external broker IPC attestation and launch, dispatch and `JOIN` rechecks are required, and reconnect is a material change. This broker channel is IPC between separately identified principals, not an exception to worker network isolation; missing, substituted or unverified binding prevents start.
