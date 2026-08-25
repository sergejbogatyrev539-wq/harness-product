# Level 2 — Static effect manifest

## Status and claim boundary

Status vector for this artifact:

- `specification = SPECIFIED`
- `runtime = NOT_IMPLEMENTED`
- `evidence = SPECIFICATION_MODEL_TESTED`
- `runtime_attestation = NOT_ATTESTED`
- `overall = NOT_READY`
- `scope = FORMAL_SPECIFICATION_AND_PURE_REFERENCE_MODEL_ONLY`
- Canonical status marker: `Q94-STATUS-VECTOR: specification=SPECIFIED; runtime=NOT_IMPLEMENTED; evidence=SPECIFICATION_MODEL_TESTED; runtime_attestation=NOT_ATTESTED; overall=NOT_READY; scope=FORMAL_SPECIFICATION_AND_PURE_REFERENCE_MODEL_ONLY`

This document specifies a signed/content-addressed upper bound for one exact tool operation. It does **not** prove that the implementation obeys the manifest, that a signature is valid, that an isolation profile exists, or that any runtime enforcement is deployed. A digest establishes byte identity; a signature establishes a key-bound statement; neither establishes semantic soundness.

`MUST`, `MUST NOT`, `SHOULD`, and `MAY` are normative terms in this package. The Russian equivalents «ОБЯЗАН», «НЕ ДОЛЖЕН», «СЛЕДУЕТ», and «МОЖЕТ» have the same force.

The current minimal implementable profile is narrower than the schema vocabulary: stageable mutation under `/workspace`, a network-disconnected worker, no credentials, and explicit denial of `COMMUNICATE`, `DELEGATE`, and `REFLECT`. A schema-valid external-message, delegation, or reflection manifest is therefore a shape example, not permission to activate that operation.

## 1. Purpose and non-goals

Level 2 has four purposes:

1. bind an operation to exact implementation/provenance bytes;
2. declare a conservative typed effect/resource/scope upper bound;
3. provide sufficient constraints to compile a narrower per-call ceiling;
4. make unknown, dynamic, transitive, and ambient behavior explicit and fail-closed.

Non-goals:

- prediction of every semantic consequence of arbitrary code;
- replacement of Level 0 isolation, Level 3 admission, receipts, or postcheck;
- proof that an operation had only the declared effects;
- approval of a tool merely because its manifest validates.

## 2. Assets, adversaries and trust assumptions

Protected assets are policy integrity, registry integrity, implementation identity, target scope, confidential data, budgets, evidence, and future control-plane inputs.

Relevant adversaries include a malicious or compromised model, poisoned tool description, substituted binary/image/dependency, confused deputy, malicious arguments, path/endpoint ambiguity, registry rollback, dynamic-dispatch expansion, and concurrent registry replacement.

Trust assumptions are deliberately narrow:

- canonicalization and schema validation run outside the agent principal;
- the trusted PEP receives authenticated registry and environment facts;
- Level 0 can enforce the compiled ceiling claimed by its selected profile;
- signer trust, signature verification, descriptor-safe resolution, and durable rollback floors are implementation obligations, not facts proven here;
- agent self-description and tool self-report are untrusted inputs.

## 3. Inputs, outputs and authoritative sources

Inputs are the immutable manifest bytes, exact implementation/dependency digests, canonical call arguments, trusted environment facts, an immutable registry snapshot, revocation state, and the selected Level 0 profile.

The authoritative Level 2 output is:

```text
BoundManifest = (
  operation,
  implementation identity,
  derived typed authority entries,
  flow rules,
  budgets,
  obligations,
  assurance requirements,
  material digests
)
```

The output is an upper bound supplied to Level 3. It is never a capability and never an execution instruction.

## 4. Formal entities and machine-readable representation

The canonical schema is `schemas/effect-manifest.schema.json`. The related schemas are:

- `effect-ontology.schema.json` — six effects plus orthogonal authority/lifecycle/information-flow facets;
- `isolation-profile.schema.json` — the required physical profile and separate principal envelopes;
- `evidence-plan-and-attestation.schema.json` — evidence obligations and any later scoped attestation.

Every schema uses Draft 2020-12, local `$defs`, finite enums, integer budget units, the SHA-256 form `sha256:<64 lowercase hex>`, and `additionalProperties: false` at every declared object boundary. Shape validation is distinct from cross-object semantic checks.

### 4.1 Effect and authority representation

The primitive effect set is:

```text
E = {COMPUTE, OBSERVE, MUTATE, COMMUNICATE, DELEGATE, REFLECT}
```

`AUTHORIZE`, `DECLASSIFY`, `ENDORSE`, `PERSIST_SCHEDULE`, `ALLOCATE`, and `EXECUTE` are orthogonal facets. They are not silently inserted into `E`.

Authority is a dependent collection, not an independent Cartesian product:

```text
AuthorityEntry(operation, effect, resource_kind) =
  (operations, selector, direction, information_label,
   temporal_bound, quantity_bound, concurrency_bound,
   flows, obligations)
```

Scope inclusion is defined only for compatible typed entries. An endpoint scope cannot be compared with a filesystem scope; `WRITE` authority cannot be inferred from `READ`; a path prefix has no meaning for a principal selector. An undefined comparison returns `UNKNOWN`, which is fail-closed.

### 4.2 Bind and closure

For every call, the trusted PEP computes:

```text
canonical_args = canonicalize_and_validate(raw_args, input_contract)
bound           = bind(manifest, canonical_args, trusted_environment_facts)
derived         = least_fixed_point(effect_and_sink_closure, bound)
```

The following conditions are mandatory:

```text
derived ⊆ manifest_upper_bound
compiled_effects ⊆ Physical(principal)
compiled_physical_ceiling ⊆ derived ∩ Physical(principal)
requested ⊆ compiled_physical_ceiling
requested ⊆ call_capability ⊆ derived
```

Runtime arguments may only narrow selector values, operations, flows, time, quantity, and concurrency. They cannot add a resource kind, effect, sink, dependency, credential, or authority facet.

If closure encounters an unpinned dependency, undeclared sink, ambient dependency, unbounded interpreter, unsupported selector, or unresolved dynamic dispatch, the result is `UNKNOWN/TOP`; the operation is inadmissible. `TOP` is a diagnostic upper bound, never an implicit permission.

Each effect-bound clause has a unique `clause_id`; each `derived_effects` edge references that exact clause, never a bare effect name. It MUST resolve through the finite manifest graph to a non-unknown complete typed effect/resource/operation clause. Cycles, missing/duplicate targets and unbounded derived edges fail closed; every reachable atom must be present in the admitted authority vector.

### 4.3 Dynamic shell and terminal operations

A general shell is not benign `COMPUTE`. It MUST either:

- be decomposed into an exact operation with pinned executable/argv and conservative compound effects;
- declare the full conservative upper bound and run inside an independently justified ceiling; or
- be denied.

The valid `shell.json` example is bound to one implementation, `/usr/bin/python3 -m compileall`, workspace read/write scopes, CPU/files budgets, and compound `COMPUTE + OBSERVE + MUTATE`. It is not a general-purpose shell grant.

### 4.1. Единый dependent schema vocabulary

Manifest MUST использовать тот же canonical `AuthorityClause`/`BudgetKey`, что normalized request, runtime policy, decision result и capability. Независимые локальные representations, которые требуют lossy translation, запрещены. Schema discriminators исключают неподдерживаемые effect/resource/operation/selector combinations; semantic compiler проверяет subset/correlation, canonical ordering, duplicate keys, fixed-point derived closure и exact authority facets. Decision/capability переносят тот же canonical envelope либо его verified canonical digest без потери scope.

Manifest signer подтверждает canonical manifest payload, но не actual bytes. Registry resolution отдельно MUST связать manifest с exact implementation/dependency bytes и verified supply-chain bundle; `true`/hash без verifier result, trust root, freshness, revocation и rollback evidence не удовлетворяет admission.

The verified supply record MUST bind one canonical payload containing registry snapshot, manifest, SBOM/dependency closure, image/runtime/loader, platform and exact content digests. Resolver measurement of the already-open execution object, placement attestation, decision, capability and effect receipt MUST all carry the same `supply_measurement_digest`; recomputing an internally consistent digest over substituted bytes does not preserve the signed identity.

**Q-57 normative anchor.** The trusted-root digest MUST be exactly equal in the
candidate supply record, active isolation profile, external verifier facts and every
verified component record. It MUST be included in the canonical measurement
preimage; the resulting composite measurement MUST equal the placement/session
measurements and the bound `supply_measurement_digest`. Root mismatch or
preimage omission is `STOP`.

Descriptor-rooted effects MUST carry the trusted `descriptor_id`, root identity, mount identity and epoch through manifest, policy, capability, dispatch and receipt; a descriptor or host-root substitution is not a narrowing. Selector/resource scope is a closed typed relation: an `ENDPOINT` selector cannot authorize a `FILE` resource (or another incompatible kind) by raw value equality; undefined relation is `UNKNOWN/STOP`.

**Q-54 normative anchor (closed selector matrix).** The manifest compiler MUST
use this closed `resource_kind ↔ selector.kind` relation before comparing
values: `FILE|DIRECTORY ↔ PATH_EXACT|PATH_PREFIX`, `PROCESS ↔
PROCESS_EXECUTABLE`, `ENDPOINT ↔ ENDPOINT_EXACT`, `PRINCIPAL ↔
PRINCIPAL_EXACT`, `MEMORY ↔ MEMORY_NAMESPACE`, `PROMPT ↔ PROMPT_COMPONENT`,
`POLICY ↔ POLICY_OBJECT`, and `REGISTRY|SECRET|COMPUTE_RESOURCE ↔
LOCAL_RESOURCE`. Every other pair is `UNKNOWN/STOP`, including raw-value
equality across kinds.

**Q-55 normative anchor (`PATH_EXACT`).** An exact path selector MUST preserve
the descriptor binding digest and the trusted descriptor/root/mount/epoch
identity end-to-end; a changed digest or identity is not a narrowing and MUST
be denied.

## 5. Normative requirements

| ID | Normative requirement | Owner / enforcement point | Failure result | Test / evidence |
|---|---|---|---|---|
| `L2-REQ-001` | A manifest MUST describe exactly one `operation_id` of one exact `tool_id` and implementation digest. | Registry owner / registry resolver | `DENY: OPERATION_MISMATCH` | `T-SCHEMA-VALID-MANIFESTS`, `T-POL-003`; `EV-SCHEMA-EXAMPLES` |
| `L2-REQ-002` | Owner, provenance URI, signer, SBOM digest, issue/expiry, revocation ID, generation and rollback floor MUST be present. | Supply-chain owner / registry verifier | `STOP: MISSING_BINDING` | schema meta-validation; `EV-SCHEMA-META` |
| `L2-REQ-003` | All dependencies, subtools and adapters MUST be digest-pinned; agent-visible ambient dependencies MUST be empty. | Tool owner / loader PEP | `DENY/STOP` | invalid prompt ambient-dependency fixture |
| `L2-REQ-004` | Input/output contracts MUST bind schema digest, canonicalization, byte/depth, encoding and content-type limits before interpretation. | Tool owner / argument PEP | `DENY: INVALID_CANONICAL_INPUT` | all valid examples; polyglot/canonicalization test obligation |
| `L2-REQ-005` | Each effect MUST carry typed resource, operations, selector, direction, label, time, quantity and concurrency bounds. | Tool owner / manifest compiler | `STOP: UNCLASSIFIED_OR_UNBOUNDED` | strict schema and eight valid examples |
| `L2-REQ-006` | `bind` and transitive closure MUST only narrow the manifest; compiled Level 0 and capability ceilings MUST be no wider than `derived`. | Policy owner / broker PEP | `DENY: SCOPE_EXCEEDS_MANIFEST` | `T-POL-004`, `T-POL-EXHAUSTIVE` |
| `L2-REQ-007` | Unknown effects, selectors, dependencies, sinks, dynamic dispatch or behavior MUST resolve to `DENY/STOP`, never allow. | Policy owner / broker PEP | `STOP: UNKNOWN_EFFECT` | `T-POL-002`, invalid shell fixture |
| `L2-REQ-008` | Manifests MUST declare required mediation, isolation profile, credentials mode, FD closure and relevant delegation/reflection controls. | Runtime owner / loader + executor PEP | `STOP: PROFILE_MISMATCH` | schema validation; isolation binding test obligation |
| `L2-REQ-009` | Labels MUST include confidentiality, integrity, provenance, taint, purpose and retention; data and control dependencies MUST propagate them. Hashing, summarization and schema validation MUST NOT declassify or endorse. | Data owner / flow PEP | `DENY: FLOW_NOT_ALLOWED` | message/memory examples; `INV-013` trace |
| `L2-REQ-010` | Preconditions, postconditions, invariants, obligations, evidence plan, postcheck and observer-independence requirements MUST be declared. | Tool owner / broker + observer | `STOP/QUARANTINE` | write/shell examples; stageable traces |
| `L2-REQ-011` | `DELEGATE` MUST bind the target principal and require authority attenuation, atomic budget partition and bounded depth/fan-out. | Orchestration owner / orchestrator PEP | `DENY: DELEGATION_AMPLIFICATION` | spawn example and invalid unknown-effect fixture |
| `L2-REQ-012` | Persistent or authority-relevant memory, prompt, context, model, tool, manifest, registry or policy change MUST be `MUTATE + REFLECT` with a new material digest. | Control owner / control-plane PEP | `DENY: REFLECTION_UNDECLARED` | memory/prompt/policy examples |
| `L2-REQ-013` | Determinism, idempotency, reversibility, persistence, expected residual effects and compensation semantics MUST be explicit. Compensation MUST be a separate authorized transaction. | Tool owner / broker PEP | `STOP/COMPENSATION_PENDING` | external-message example; `T-LTS-003` |
| `L2-REQ-014` | Registry resolution MUST use an immutable digest-pinned snapshot, signed entries, a monotonic generation/rollback floor, revocation and TOCTOU-safe exact-byte loading. Dynamic updates are disabled in V0. | Registry owner / registry resolver | `STOP: REGISTRY_ROLLBACK_OR_RACE` | invalid dynamic-registry fixture |
| `L2-REQ-014a` | Supply admission MUST consume an externally anchored verifier record binding signed component/dependency facts, registry/revocation state, exact opened bytes, loader/runtime and placement; synchronized substitution with recomputed caller digests MUST fail. | Registry verifier + loader/attestor | `STOP: SUPPLY_NOT_VERIFIED` | `T-Q39-SUPPLY-EXTERNAL-BUNDLE-SUBSTITUTION` |
| `L2-REQ-014b` | Descriptor identity, descriptor-root/mount identity, digest and epoch MUST be exact-bound end-to-end; descriptor-only or host-root substitution MUST fail. | Manifest compiler + L0/L3 PEP | `DENY: DESCRIPTOR_BINDING_MISMATCH` | `T-Q43-DESCRIPTOR-ROOT-SUBSTITUTION` |
| `L2-REQ-014c` | Scope comparison MUST use the closed `resource_kind ↔ selector.kind` matrix before value comparison; cross-kind raw equality MUST be rejected. | Manifest compiler / policy PEP | `DENY: TYPED_SCOPE_MISMATCH` | `T-Q48-POLICY-SCOPE-KIND-CROSS-MATRIX` |
| `L2-REQ-015` | Tool, dependency, entrypoint, schema, effect, flow, profile, budget, behavior, owner or signer changes MUST create a new manifest and invalidate bound capabilities/contracts/receipts. | Registry + policy owners / broker PEP | `DENY: MATERIAL_BINDING_MISMATCH` | `T-POL-008`, approval vector |
| `L2-REQ-016` | Schema-valid but policy-disabled effects MUST remain explicit `DENY`; schema validity MUST NOT be interpreted as admission. | Policy owner / broker PEP | `DENY: EFFECT_DENIED_BY_POLICY` | minimal-profile decision partitions |

## 6. Admission, decision and enforcement rules

Level 2 resolution is accepted only when all of the following hold:

1. registry snapshot digest/generation is pinned by the contract and policy;
2. registry generation is not below the durable rollback floor;
3. the manifest is active, unexpired and not revoked;
4. signature, manifest digest, implementation digest, dependencies and SBOM bindings verify;
5. canonical input validates before use;
6. `bind + closure` is known and bounded;
7. the selected isolation profile can enforce a ceiling no wider than `derived`;
8. Level 3 independently admits the request.

Deny overrides allow. A manifest resolver cannot issue authority. A tool proposal remains powerless until Level 3 has issued and durably consumed an exact capability.

TOCTOU-safe resolution requires the implementation bytes actually opened for execution to be the bytes whose digest was verified. Checking a path and later reopening the same path is insufficient. The implementation must retain an exact immutable handle or equivalent content-addressed object across verify-to-dispatch.

## 7. Invariants and pre/postconditions

Level 2 directly supports `INV-002`, `INV-003`, `INV-005`, `INV-006`, `INV-009`, `INV-010`, `INV-012`, `INV-013`, `INV-014`, and `INV-015` in `tests/invariant-traceability.json`.

Preconditions:

- exact immutable registry snapshot and rollback floor are available;
- manifest and implementation identities verify;
- input has a canonical representation and bounded shape;
- trusted environment facts are fresh and scoped;
- no unknown closure edge remains.

Postconditions:

- every derived authority entry is covered by the manifest;
- every bound used by Level 3 carries the manifest and registry digests;
- required obligations and evidence plan survive binding;
- resolution emits an authoritative unsampled safety event;
- no capability or execution has occurred merely from resolution.

## 8. Failure, timeout, crash, retry, recovery and revocation

| Condition | Required semantics |
|---|---|
| Missing/malformed/stale manifest or environment fact | `STOP`; no capability |
| Digest/signature/operation/dependency mismatch | `DENY`; emit mismatch event |
| Unknown transitive sink or dynamic dispatch | `STOP` or explicit manifest widening to `UNKNOWN/TOP`, which remains inadmissible |
| Canonicalization/schema/size/depth failure | `DENY` before parsing/execution |
| Resolver timeout | `STOP`; no reuse of a partial result |
| Crash before Level 3 durable dispatch | recovery starts from `STOPPED`; re-resolve against the same or newer permitted snapshot |
| Registry revocation after decision but before dispatch | capability becomes stale; re-decision required |
| Registry change during resolution | abort; pin a fresh immutable snapshot; never mix generations |
| Retry | fresh resolution and fresh capability; cumulative budgets do not reset |
| Compensation/rollback tool | its own manifest, policy, budgets, capability and evidence plan |

## 9. Telemetry and evidence

Authoritative components MUST emit at least:

- manifest resolution requested/accepted/denied;
- registry snapshot digest, generation and rollback-floor comparison;
- exact tool/operation/version/implementation/dependency digests;
- requested, manifested and derived effect/scope vectors;
- canonical argument digest and classification, never raw sensitive values in metrics;
- obligations and evidence-plan ID;
- failure reason and revocation state.

The event must bind manifest hash to contract, capability, event and later effect receipt. Agent self-report is diagnostic only. A hash chain without an independent witness does not prove anti-rollback.

Required specification evidence is produced by `tests/run_checks.py`: Draft 2020-12 meta-validation, strict-object scan, direct `/usr/bin/jsonschema` validation of positive cases, materialized negative mutation validation, policy subset checks and traceability coverage.

## 10. Test obligations

Positive tests:

- read file inside `/workspace/input`;
- staged write inside `/workspace/output`;
- bounded compound shell operation;
- exact external message sink;
- exact attenuated child principal;
- scoped memory, prompt and policy updates.

Negative/adversarial tests:

- outside-workspace read/write, insecure endpoint, unknown effect, undeclared dynamic dispatch, ambient dependency, dynamic registry update;
- symlink/hardlink/magic-link/path-race tests against the eventual Level 0/loader implementation;
- manifest/binary/dependency/SBOM mismatch and registry rollback;
- shell injection/polyglot/canonicalization/dynamic-subtool expansion;
- taint laundering and unapproved declassification/endorsement.

Concurrency/fault tests:

- registry entry replacement between resolution and open;
- revocation between decision and dispatch;
- loader crash after verification but before durable dispatch;
- concurrent calls attempting to share one capability or budget reservation.

The current suite validates schema and reference semantics only. Runtime attack/fault tests remain implementation blockers.

## 11. Residual risks and unsupported claims

- Conservative manifests can be semantically incomplete even when signed and schema-valid.
- Arbitrary code behavior and covert channels cannot be exhaustively predicted.
- A descriptor-safe loader, registry signature verifier, rollback witness and Level 0 enforcement are not implemented here.
- The valid external/delegation/reflection examples are disabled by the minimal profile.
- Numeric example limits are not calibrated production values.
- This document does not claim complete isolation, complete effect enumeration, non-bypassability, or runtime verification.

## 12. Definition of Done

`DECLARED` / `SPECIFIED` requires:

- strict self-contained schema;
- dependent typed authority representation;
- all requirements, failure semantics, owners, tests and evidence mapped;
- valid/invalid examples and reference subset checks passing.

`IMPLEMENTED` requires, in addition:

- trusted registry/signature/revocation resolver;
- exact-byte TOCTOU-safe loader;
- closure compiler and Level 0 ceiling integration;
- authoritative events and receipt binding;
- runtime conformance and fault tests in a named environment.

`VERIFIED` requires, in addition:

- independent scoped evidence for semantic-conformance claims;
- registry rollback/revocation and concurrency tests;
- attack tests for transitive sinks, path races and dynamic dispatch;
- explicit residual-risk acceptance by an authorized owner.

The current artifact is `SPECIFIED / NOT_IMPLEMENTED / SPECIFICATION_MODEL_TESTED / NOT_ATTESTED / NOT_READY` within `FORMAL_SPECIFICATION_AND_PURE_REFERENCE_MODEL_ONLY`; it is not runtime `IMPLEMENTED` or `VERIFIED`.

## 13. Source-versus-new traceability

| Topic | Corpus basis | V0 resolution/addition |
|---|---|---|
| Manifest as exact signed upper bound | `metaprompt-harness-levels-0-5-ru.md:241-245` | Dependent typed authority entries and explicit fail-closed closure |
| Required manifest fields | `metaprompt-harness-levels-0-5-ru.md:247-258` | Strict Draft 2020-12 schema with local `$defs` |
| Required operation examples and hash bindings | `metaprompt-harness-levels-0-5-ru.md:260` | Eight positive and eight single-mutation negative cases |
| Powerless proposal and static manifest mediation | `HARNESS_ACTIVATION_DIFF.md:63-73`, `security.md:48-54` | Separate resolution from admission/capability/dispatch |
| Workspace-path escape | `security.md:9-16` | Typed path selectors plus Level 0/loader runtime test obligation; no claim that schema alone enforces paths |
| Polyglot/content-addressing gap | `security.md:56-60` | Canonical input contract; content hash does not imply safe interpretation |
| Registry poisoning | `security.md:128-134` | Immutable digest-pinned snapshot; dynamic updates disabled; rollback floor and revocation |
| Reflection and persistent control state | `metaprompt-harness-levels-0-5-ru.md:218-223` | Separate memory/prompt/policy `MUTATE + REFLECT` manifests |
| Согласованная V0 semantics | Новое требование V0; source authority не заявляется | One schema/reference core, explicit status and disabled minimal profile |

Requirements not stated authoritatively in the corpus—exact local definitions of scope comparison, registry snapshot procedure, and V0 reason codes—are new V0 requirements. They do not redefine the project-specific `CB5`, `JOIN`, law-of-cut, `D2`, `JR5`, `LRP1_D`, `S5`, `RJ*`, `B3`, `P2`, `R0–R6`, or authority-domain terms, which remain `PROVISIONAL` where used.
