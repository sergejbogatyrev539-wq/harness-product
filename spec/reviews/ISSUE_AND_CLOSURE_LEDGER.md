# Issue and closure ledger

## Status boundary

This ledger records specification defects and their abstract regression evidence. It does not claim runtime implementation, enforcement, attestation or production readiness. `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` may be used only after root confirms the integrated live model and its green runner; an in-progress working tree is `REMEDIATION_IN_PROGRESS`. `CLOSED` additionally requires an allowed arbiter disposition and independent verification on an immutable packet.

## Process audit attempt

- Candidate: `ROUND_1_PACKET`, SHA-256 `e8b0200e9051a8547e5b020c00efe8ffecedeca2efd0749b69a8196fc7ca3e08`.
- Raw manifest: `RAW_FINDINGS_MANIFEST_ROUND_1_ATTEMPT_CONTAMINATED.json`, 21 raw findings (`3 Critical / 17 High / 1 Medium`) recorded before deduplication.
- Total raw→canonical mapping: `CANONICAL_MAPPING_ROUND_1_ATTEMPT_CONTAMINATED.json`, 21/21 raw IDs mapped to 13 issues.
- Fresh arbiter preserved strongest severity and set all 13 to `OPEN` because they were not yet patched/verified.
- This attempt is not an official round: six candidate references exposed author rationale. The packet and evidence are preserved; a sanitized clean round is required.

## Official Round 1 arbitration

- Candidate: `ROUND_1_CLEAN_PACKET`, SHA-256 `10499bcb8eeb11a46656a5620f59cf351b9909f6419c5dedb6184bccf6decd4d` (44 immutable files).
- Raw manifest: `RAW_FINDINGS_MANIFEST_ROUND_1_OFFICIAL.json`, 26 raw findings (`4 Critical / 21 High / 1 Medium`) captured before deduplication.
- Total mapping: `CANONICAL_MAPPING_ROUND_1_OFFICIAL.json`, 26/26 raw IDs mapped exactly once to 13 canonical clusters.
- Fresh independent arbiter kept four Critical and eight High clusters `OPEN`. The contested Medium `Q-07` was `REJECTED_WITH_COUNTEREVIDENCE`; its semantic-envelope top and epistemic `UNKNOWN` are already distinct, with an editorial rename still useful.
- Therefore the official Round 1 packet is `NOT_READY`. Live-file remediation after this immutable packet does not close an issue until a later fresh reviewer verifies it.

| Official cluster | Severity | Round-1 disposition | Live remediation state |
|---|---:|---|---|
| `Q-08` full correlated authority clause | Critical | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-02` authenticated exact capability | Critical | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-11` authoritative exact-bound approval | Critical | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-04` distinct principals / compiled isolation | Critical | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-12` explicit deny override | High | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-05` scoped budget vector | High | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-01` durable class-based D2 / iteration bound | High | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-10` lifted evidence stages / same-object chain | High | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-06` phase-sensitive recovery / cleanup gate | High | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-13` immutable claim-hash traceability | High | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-03` parent-bound delegation attenuation | High | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-09` end-to-end supply measurement | High | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-07` lattice top vs epistemic unknown | Medium | `REJECTED_WITH_COUNTEREVIDENCE` | `NO_SAFETY_PATCH_REQUIRED` |

## Official Round 2 arbitration

- Candidate: `ROUND_2_PACKET`, SHA-256 `0d3804c7071d851fa18ec58b78ae9e5400ec5b14a6c703dbfa0a2d83b6834d81` (44 manifest-listed files, independently reverified).
- Raw manifest: `RAW_FINDINGS_MANIFEST_ROUND_2_OFFICIAL.json`, 12 raw findings (`9 High / 3 Medium`) captured before deduplication.
- Total mapping: `CANONICAL_MAPPING_ROUND_2_OFFICIAL.json`, 12/12 raw IDs mapped exactly once.
- Fresh independent arbiter kept all 12 clusters `OPEN`; no human risk-owner receipt exists for the Medium findings.

| Official cluster | Severity | Round-2 disposition | Live remediation state |
|---|---:|---|---|
| `Q-14` unknown-outcome event guard | High | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-15` typed authority handoff | High | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-16` privacy lifecycle evidence | Medium | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-17` complete material approval payload | High | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-18` canonical semantic traceability | High | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-19` aggregate delegation tree escrow | Medium | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-20` trusted PEP decision admission | High | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-21` exact reservation vector | High | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-22` issue/dispatch capability equality | High | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-23` external attestation verification | High | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-24` non-vacuous authoritative effect receipt | High | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-25` isolation principal-role intersection | Medium | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |

## Official Round 3 arbitration

- Candidate: `ROUND_3_PACKET`, SHA-256 `e6bbbd968edc695f7475f5d479ec034f2962b88884a20357905201c68912589c` (44 immutable files, independently reverified before and after review).
- Raw manifest: `RAW_FINDINGS_MANIFEST_ROUND_3_OFFICIAL.json`, 18 raw findings (`13 High / 5 Medium`) captured before deduplication.
- Total mapping: `CANONICAL_MAPPING_ROUND_3_OFFICIAL.json`, 18/18 raw IDs mapped exactly once.
- Fresh Luna-high arbiter kept ten High and three Medium canonical model gaps `OPEN`, merged one traceability duplicate, and rejected four runtime-assurance clusters with counterevidence because those mechanisms are already explicitly absent and not claimed as implemented.

| Official cluster | Severity | Round-3 disposition | Live remediation state |
|---|---:|---|---|
| `Q-26` bidirectional L5 traceability / executable evidence | High | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-27` closed effect-resource-operation relation | High | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-28` trusted approval lifecycle state | Medium | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-29` unique canonical attack identifiers | High | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-30` end-to-end exact approval binding | High | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-31` externally trusted approval signature verification | High | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-32` compiled selector scope containment | High | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-33` enforced residual-risk disposition receipt | High | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-34` trusted manifest lifecycle / dependency verification | High | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-35` approval presentation / comprehension / batching | Medium | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-36` identity-bound break-glass dual control | High | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-37` complete closed human approval payload | High | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-38` postcheck failure reservation release | Medium | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |

Rejected raw clusters: `R3-ASR-004`, `R3-ASR-007`, `R3-ASR-008`, `R3-ASR-009` are `REJECTED_WITH_COUNTEREVIDENCE`; they remain explicit future runtime assurance gates, not verified controls.

## Official Round 4 full-scope arbitration

- Candidate: `FINAL_PACKET`, SHA-256 `7696bc35f0c2f343e056bf2cd3ef6d0327ab527120269078ae9431c070e40f59` (44 immutable files).
- Raw manifest: `RAW_FINDINGS_MANIFEST_ROUND_4_OFFICIAL.json`, 14 raw findings (`2 Critical / 11 High / 1 Low`) captured before deduplication.
- Total mapping: `CANONICAL_MAPPING_ROUND_4_OFFICIAL.json`, 14/14 raw IDs mapped exactly once to 14 canonical issues.
- Fresh Luna-high arbiter independently reproduced every counterexample and left all 14 issues `OPEN`. Two proposed merge clusters were split to preserve independent obligations.
- Round 4 is not clean. Any patch resets the full-scope convergence series; under the five-round cap the package remains overall `NOT_READY` even if Round 5 verifies the patched model.

| Official cluster | Severity | Round-4 disposition | Live remediation state |
|---|---:|---|---|
| `Q-39` externally anchored supply-chain verification | High | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-40` authoritative complete D2 inventory | High | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-41` externally verified authoritative event emitter | High | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-42` canonical signed event and source chain | High | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-43` trusted descriptor-root identity binding | High | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-44` trusted active loop-contract binding | High | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-45` stageable crash uncertainty quarantine | High | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-46` worker compiled-effect ceiling | Critical | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-47` mutation audience bound to distinct executor | Critical | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-48` typed policy scope and resource correlation | High | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-49` trusted typed COMMIT and JOIN evidence | High | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-50` scope-and-lineage-complete budget identity | High | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-51` externally anchored full capability verification | Critical | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-52` reproducible packet aggregate algorithm | Low | `OPEN` | `PATCHED_PACKET_REPRODUCED_AWAITING_INDEPENDENT_VERIFICATION` |

Live post-patch verification target: immutable `ROUND_5_PACKET`, 44 files, aggregate SHA-256 `e7a91a83c6c581f74730b518cbebb9762702fff83c9014487fb4645187dcf090`. Its manifest defines UTF-8 records sorted ascending by `relative_path`, and an independent `jq | sha256sum` reproduction matches exactly. Packet-local model checks pass with 561 assertion instances; this is specification-model evidence only.

## Official Round 5 full-scope arbitration

- Candidate: `ROUND_5_PACKET`, SHA-256 `e7a91a83c6c581f74730b518cbebb9762702fff83c9014487fb4645187dcf090` (44 immutable files, independently reverified by all reviewers).
- Raw manifest: `RAW_FINDINGS_MANIFEST_ROUND_5_OFFICIAL.json`, 7 raw findings (`7 High`) captured before deduplication. The formal reviewer returned `NO_FINDING`; runtime and assurance reviewers returned three and four High findings respectively.
- Total mapping: `CANONICAL_MAPPING_ROUND_5_OFFICIAL.json`, 7/7 raw IDs mapped exactly once to seven distinct canonical obligations `Q-53` through `Q-59`.
- The first fresh arbiter reproduced all seven counterexamples, but its `REJECTED_WITH_COUNTEREVIDENCE` labels contradicted those successful reproductions. A second fresh independent disposition adjudicator invalidated that ruling and set all seven to the protocol-required `OPEN/NOT_READY`; the integrator did not change severity or disposition unilaterally.
- Round 5 is not clean. The maximum of five rounds is exhausted, no patch follows this round, and the two-clean-round precondition was not met. Closure auditor and novelty verifier therefore were not run.

| Official cluster | Severity | Round-5 disposition | Current closure state |
|---|---:|---|---|
| `Q-53` exact signed-field attestation binding | High | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-54` manifest selector-resource typed relation | High | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-55` PATH_EXACT descriptor identity binding | High | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-56` isolation resource-unit-enforcer correlation | High | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-57` trusted supply-root digest binding | High | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-58` pre-dispatch reservation terminal disposition | High | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-59` safety-event manifested containment | High | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |

Historical next action recorded at Round 5 (superseded by the remediation note below): minimally patch `Q-53`–`Q-59`, add their named regressions, freeze a new immutable packet, and restart the required two-clean-full-scope-round series. Runtime implementation and runtime attestation remain separate future work.

## Subsequent remediation note (after historical Round 5)

The then-live documents contained the Q-53–Q-59 normative anchors and named pure
model regressions. The full suite then recorded **1008 assertion instances**
for that remediation state. Immutable `ROUND_6_PACKET` freezes the same 44
artifact paths at aggregate SHA-256
`321b0efc2c8202f142b1e6b28dca93c5cecb5804cc62d8bf555ba78d65d84f8d`;
all 44 hashes, the aggregate and the packet-local suite were reproduced.
Independent verification and the required two clean full-scope rounds are
still pending. This is not `CLOSED` or `READY`.

Runtime status remains `NOT_IMPLEMENTED`; runtime attestation remains
`NOT_ATTESTED` and runtime evidence is absent.

## Official Round 6A full-scope arbitration

- Candidate: `ROUND_6_PACKET`, aggregate SHA-256 `321b0efc2c8202f142b1e6b28dca93c5cecb5804cc62d8bf555ba78d65d84f8d` (44 read-only files). The frozen packet-local baseline recorded 1008 assertion instances.
- Raw manifest: `RAW_FINDINGS_MANIFEST_ROUND_6A_OFFICIAL.json`, 17 raw findings; response-set SHA-256 `04511699b92e99938ffc2535aceb602dafc9b966e9633ba03cae993819f52ffc`; finding-set SHA-256 `29da24988a8c94e6800ee1f15fba465d629b042c61985612ef245ed03b7dc566`.
- Total mapping: `CANONICAL_MAPPING_ROUND_6A_OFFICIAL.json`, 17/17 raw IDs mapped exactly once to 15 canonical issues. Luna/high reviewers produced the immutable raw evidence; Terra/high reproduction and fresh disposition ruling settled 13 `OPEN` and two `REJECTED_WITH_COUNTEREVIDENCE`.
- `Q-60`–`Q-65` and `Q-68`–`Q-74` remain `OPEN`; `Q-66` (capability exact binding) and `Q-67` (D2 class-completeness overclaim) are rejected with counterevidence. No Critical issue was sustained: the packet expressly remains `NOT_IMPLEMENTED` and `NOT_ATTESTED`.

| Canonical clusters | Round-6A disposition | Current live state |
|---|---|---|
| `Q-60` policy/profile activation; `Q-61` descriptor/object continuity; `Q-62` recovery/heartbeat; `Q-63` residual-risk evidence; `Q-64` stage evidence; `Q-65` OS/session role separation | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-66` ISSUE/DISPATCH capability predicate; `Q-67` D2 snapshot claim | `REJECTED_WITH_COUNTEREVIDENCE` | retain existing counterevidence regressions; no safety-patch expansion asserted |
| `Q-68` approval-envelope derivation; `Q-69` delegation escrow; `Q-70` closed effect relation; `Q-71` byte-safe paths; `Q-72` authenticated quorum; `Q-73` causal topology; `Q-74` layer-specific oracles | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |

Root confirmed the integrated live Terra remediation: 12 schemas, 8 valid/8 invalid examples, lifecycle with 1 atomic dispatch, 15 traceability invariants, and 1079 assertion instances pass. This is live pre-freeze specification-model evidence only; no new immutable packet or independent verification exists. The supplemental clean series is `0`; runtime remains `NOT_IMPLEMENTED`/`NOT_ATTESTED` and overall status `NOT_READY`.

## Official Round 7A full-scope arbitration

- Candidate: `ROUND_7_PACKET`, aggregate SHA-256 `ad9a3f9249919b29e5eae0eeeae22bfd905bf43c113df2c989a1781e31d6c923` (44 read-only files); packet-local specification-model baseline: 1079 assertion instances.
- Raw manifest: `RAW_FINDINGS_MANIFEST_ROUND_7A_OFFICIAL.json`, four High findings captured before deduplication. The assurance reviewer found no additional candidate-local model defect but accepted only `DRAFT / SPECIFICATION_MODEL_TESTED` and expressly rejected any runtime-enforcement inference.
- Total mapping: `CANONICAL_MAPPING_ROUND_7A_OFFICIAL.json`, 4/4 raw IDs mapped without merging to `Q-75`–`Q-78`.
- A fresh blind Terra/high arbiter independently reproduced all four counterexamples and left all four `OPEN` at High severity. The integrator changed neither severity nor disposition.

| Canonical issue | Severity | Round-7A disposition | Current live state |
|---|---:|---|---|
| `Q-75` orthogonal delegation provenance on descendant work capabilities | High | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-76` externally verified typed reconciliation receipt | High | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-77` D2 authority-domain and durable journal-lineage binding | High | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-78` component-wise four-part-key lifecycle budget conservation | High | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |

Root confirmed the integrated live Q-75–Q-78 remediation: 12 schemas, 8 valid/8 invalid examples, lifecycle with 1 atomic dispatch, 15 traceability invariants and 1259 assertion instances pass. The same gate includes reproduced stale/signer-mismatched parent status, forged reconciliation verifier and full-identity/stale/signer-mismatched runtime-D2 counterexamples found by the pre-freeze audits. This is live pre-freeze specification-model evidence only; it does not close any issue.

Round 7A is not clean and the supplemental clean series remains `0`. The remediation invalidates `ROUND_7_PACKET` as a convergence target; a new immutable packet must receive two fresh clean full-scope rounds on the same digest. Runtime remains `NOT_IMPLEMENTED`, runtime attestation remains `NOT_ATTESTED`, and overall status remains `NOT_READY`.

## Round 8 immutable convergence candidate

- Candidate: `ROUND_8_PACKET`, aggregate SHA-256 `8b59334f79205ae5e297a9b58ac313e2643a1057e9f26606ec2a70530d0e07d5` (44 read-only files).
- Every manifest-listed SHA-256 and the relative-path-ordered aggregate were independently reproduced; the packet-local suite passes 1259 assertion instances and 15 traceability invariants.
- This freeze is not a review disposition. `Q-75`–`Q-78` remain `OPEN`, the supplemental clean series remains `0`, and both Round 8A and 8B must be clean on this exact digest before closure audit begins.
- Runtime remains `NOT_IMPLEMENTED`, runtime attestation remains `NOT_ATTESTED`, and overall status remains `NOT_READY`.

## Official Round 8A full-scope arbitration

- Candidate: `ROUND_8_PACKET`, aggregate SHA-256 `8b59334f79205ae5e297a9b58ac313e2643a1057e9f26606ec2a70530d0e07d5` (44 read-only files); packet-local baseline: 1259 assertion instances and 15 traceability invariants.
- Raw manifest: `RAW_FINDINGS_MANIFEST_ROUND_8A_OFFICIAL.json`, three valid High findings and one preserved contaminated no-verdict attempt. Phase-2 response-set SHA-256: `0067810d95fd03a85967d77497ca3d39b7dfe161fb14053d2547f71d22240c1b`; finding-set SHA-256: `0c75334b53bb99630e25f9a10f10d17fa71c430ed05c9ebf04e55324970c396b`.
- Total mapping: `CANONICAL_MAPPING_ROUND_8A_OFFICIAL.json`, 3/3 raw IDs mapped once to `Q-79`–`Q-81`; no drops, merges or severity downgrades.
- A fresh blind Terra/high arbiter independently reproduced all three counterexamples and retained all three as `OPEN` High findings.

| Canonical issue | Severity | Round-8A disposition | Current live state |
|---|---:|---|---|
| `Q-79` derived-effect edges not exact-bound to typed reachable clauses | High | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-80` lexical filesystem ceiling lacks independent immutable physical-target binding | High | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-81` incomplete normative requirement catalog and reverse traceability | High | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |

Root confirmed the integrated live Q-79–Q-81 remediation: 12 schemas, 8 valid/8 invalid examples, lifecycle with 1 atomic dispatch, 15 traceability invariants, an exact 103-row L0–L5 requirement catalog and 1290 assertion instances pass. A separate read-only Terra/high pre-freeze audit reproduced the original counterexample classes and found the controls effective; its only residual was this package's stale Round-5 synthesis, which was updated before freeze. This is live pre-freeze specification-model evidence only and does not close any issue.

Round 8A is not clean and the supplemental clean series is `0`. The live remediation invalidates `ROUND_8_PACKET` as the convergence target. A new immutable packet must be frozen and receive two entirely fresh clean full-scope Terra/high rounds on the same digest before closure audit and novelty verification. Runtime remains `NOT_IMPLEMENTED`, runtime attestation remains `NOT_ATTESTED`, and overall status remains `NOT_READY`.

## Round 9 immutable convergence candidate

- Candidate: `ROUND_9_PACKET`, aggregate SHA-256 `bf52dbcc325aeee48edbcfb7c75720b6d22bb4ecacaed561d86c6fb9a68ff726` (44 read-only files).
- Every manifest-listed SHA-256 and the relative-path-ordered aggregate were independently reproduced; all files are mode `0444`, all directories mode `0555`, and the packet-local suite passes 1290 assertion instances and 15 traceability invariants.
- This freeze is not a review disposition. `Q-79`–`Q-81` remain `OPEN`, the supplemental clean series remains `0`, and both Round 9A and 9B must be clean on this exact digest before closure audit begins.
- Runtime remains `NOT_IMPLEMENTED`, runtime attestation remains `NOT_ATTESTED`, and overall status remains `NOT_READY`.

## Official Round 9A full-scope arbitration

- Candidate: `ROUND_9_PACKET`, aggregate SHA-256 `bf52dbcc325aeee48edbcfb7c75720b6d22bb4ecacaed561d86c6fb9a68ff726` (44 read-only files). Neutral corpus aggregate SHA-256: `0971fbac41b38c1a491118f3768d48bfe4c2c27f0b33394107930f90eb544e46`. Anonymized arbitration input SHA-256: `4b6cbf2528763f7a20d338c320568cea40004d46f1fe98fc195f3dbfe5a1807d`.
- Fresh Terra/high blind arbitration retained both findings `OPEN`: `A-6D4E2B91` maps one-to-one to `Q-82` (High, endpoint-only dispatch), and `A-B7C19F04` maps one-to-one to `Q-83` (Medium, partial/residual known failure).
- Round 9A failed. The supplemental clean series is `0`; Round 9B must not run on this failed packet. Runtime remains `NOT_IMPLEMENTED`, runtime attestation remains `NOT_ATTESTED`, and overall status remains `NOT_READY`.

| Canonical issue | Severity | Round-9A disposition | Current live state |
|---|---:|---|---|
| `Q-82` typed dispatch target verification for endpoint-only external effects | High | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-83` known failure with partial or residual external effect | Medium | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |

Root confirmed the integrated live Q-82/Q-83 remediation: 12 schemas, 8 valid/8 invalid examples, lifecycle with 1 atomic dispatch, 15 traceability invariants and 1377 assertion instances pass. The focused regressions cover exact endpoint identity from selected authority through dispatch, cross-alternative and cross-kind substitution, verifier freshness/revocation, signed residual-effect disposition, component-wise budget conservation and durable compensation-pending recovery. A separate read-only Terra/high pre-freeze audit repeated the original, reciprocal and endpoint-to-endpoint selected-alternative attacks plus the Q-83 residual paths on the stable live snapshot and found no remaining concrete Q-82/Q-83 blocker. This is live pre-freeze specification-model evidence only and does not close either issue.

Round 9A remains failed and the supplemental clean series remains `0`. The live remediation invalidates `ROUND_9_PACKET` as the convergence target. A new immutable packet must be frozen and receive two entirely fresh clean full-scope Terra/high rounds on the same digest before closure audit and novelty verification. Runtime remains `NOT_IMPLEMENTED`, runtime attestation remains `NOT_ATTESTED`, and overall status remains `NOT_READY`.

## Round 10 immutable convergence candidate

- Candidate: `ROUND_10_PACKET`, aggregate SHA-256 `1e6168e475df0c6ea73cd1dc19e17fc1ad4c492d15b3fdbb2bae08f8bcc4e008` (44 read-only files).
- Every manifest-listed SHA-256 and the relative-path-ordered aggregate were independently reproduced; all files are mode `0444`, all directories mode `0555`, and the packet-local suite passes 1377 assertion instances and 15 traceability invariants.
- This freeze is not a review disposition. `Q-82`–`Q-83` remain `OPEN`, the supplemental clean series remains `0`, and both Round 10A and 10B must be clean on this exact digest before closure audit begins.
- Runtime remains `NOT_IMPLEMENTED`, runtime attestation remains `NOT_ATTESTED`, and overall status remains `NOT_READY`.

## Official Round 10A full-scope arbitration

- Candidate: `ROUND_10_PACKET`, aggregate SHA-256 `1e6168e475df0c6ea73cd1dc19e17fc1ad4c492d15b3fdbb2bae08f8bcc4e008` (44 read-only files). Neutral corpus aggregate SHA-256: `0971fbac41b38c1a491118f3768d48bfe4c2c27f0b33394107930f90eb544e46`. Anonymized arbitration input SHA-256: `fb65a01bdea907c3fbdc8e9e0e2070272f17cb13d369deda16d4a94b7c036c50`.
- Raw capture contains 5 findings (`1 Critical / 3 High / 1 Medium`); total mapping is 5/5 raw to 4 canonical issues, with one evidence-preserving merge, no drops and no severity downgrade.
- Fresh Terra/high blind arbitration reproduced all four canonical counterexamples and retained all four `OPEN`.
- Round 10A failed. The supplemental clean series is `0`; Round 10B must not run on this failed packet. Runtime remains `NOT_IMPLEMENTED`, runtime attestation remains `NOT_ATTESTED`, and overall status remains `NOT_READY`.

| Canonical issue | Severity | Round-10A disposition | Current live state |
|---|---:|---|---|
| `Q-84` unique durable iteration-slot claim | High | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-85` tagged effect-receipt stage semantics | Medium | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-86` canonical loop-contract and independent-postcheck admission bridge | High | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-87` closed L0 rootless and disconnected-worker profile | Critical | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |

Root confirmed the integrated live Q-84–Q-87 remediation: 12 Draft 2020-12 schemas, 8 valid/8 invalid examples, lifecycle with 13 stageable steps and 1 atomic dispatch, 15 traceability invariants and 1460 assertion instances pass. A read-only Terra/high pre-freeze auditor initially found a coherent UID=0 gap at 1400 assertions; after minimal UID/network/slot completion, it reran at 1460 and found no concrete Q-84–Q-87 blocker. This is live pre-freeze specification-model evidence only and does not close any issue.

Round 10A remains failed, the clean series is `0`, and Round 10B must not run on its failed packet. A new immutable packet and two fresh clean full-scope rounds on the same digest are required. Runtime remains `NOT_IMPLEMENTED`, runtime attestation remains `NOT_ATTESTED`, and overall status remains `NOT_READY`.

## Round 11 immutable convergence candidate

- Candidate: `ROUND_11_PACKET`, aggregate SHA-256 `1a2533951c99f206709ad45b8334aba9f8bc278a5db5f5868bb647eb501b5b4f` (44 read-only files).
- All 44/44 manifest-listed hashes and sizes were reproduced; files are `0444`, directories `0555`, the adjacent manifest is `0444`, and the packet-local suite passes 1460 assertion instances and 15 traceability invariants.
- This freeze is not a review disposition. `Q-84`–`Q-87` remain `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION`, the clean series remains `0`, and Round 11A then Round 11B must be fresh full-scope rounds on this exact digest.
- Runtime remains `NOT_IMPLEMENTED`, runtime attestation remains `NOT_ATTESTED`, and overall status remains `NOT_READY`.

## Official Round 11A full-scope arbitration

- Candidate: `ROUND_11_PACKET`, aggregate SHA-256 `1a2533951c99f206709ad45b8334aba9f8bc278a5db5f5868bb647eb501b5b4f` (44 read-only files). Fresh blind Terra/high arbitration verified neutral corpus aggregate `0971fbac41b38c1a491118f3768d48bfe4c2c27f0b33394107930f90eb544e46`, the candidate packet, and anonymized input SHA-256 `e4a20cc3d7b8b2a3359aa99a97e3c8df88090f96cce10edb28f6e74645139455`.
- Raw capture contains three High findings. `CANONICAL_MAPPING_ROUND_11A_OFFICIAL.json` maps all three 1:1 to three canonical issues: no merge, drop, or severity downgrade.
- The fresh blind `gpt-5.6-terra`/high arbiter independently reproduced the counterexamples and retained `Q-88`, `Q-89`, and `Q-90` as `OPEN` at High severity.
- Round 11A failed; the clean series is `0`, and Round 11B is prohibited on this failed packet. Remediate the open issues, freeze a new immutable packet, and complete two fresh clean full-scope rounds on that same new digest before closure audit and novelty verification. Runtime remains `NOT_IMPLEMENTED`, runtime attestation remains `NOT_ATTESTED`, and overall status remains `NOT_READY`.

| Canonical issue | Severity | Round-11A disposition | Current live state |
|---|---:|---|---|
| `Q-88` externally verified runtime broker IPC binding | High | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-89` complete closed resource-dimension vector | High | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-90` cross-domain break-glass quorum | High | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |

Root confirmed the integrated live Q-88–Q-90 remediation: 12 Draft 2020-12 schemas, 8 valid/8 invalid examples, lifecycle with 13 stageable steps and 1 atomic dispatch, 15 traceability invariants and 1618 assertion instances pass. A fresh read-only Terra/high pre-freeze audit first reproduced old-digest socket replacement; the minimal content-addressed patch raised the live suite from 1616 to 1618 assertions, after which exact probes denied and the auditor found no concrete Q-88–Q-90 blocker. This is live pre-freeze specification-model evidence only and does not close any issue.

Round 11A remains failed, the clean series remains `0`, and Round 11B must not run on its failed packet. A new immutable packet and two fresh clean full-scope rounds on the same new digest are required. Runtime remains `NOT_IMPLEMENTED`, runtime attestation remains `NOT_ATTESTED`, and overall status remains `NOT_READY`.

## Round 12 immutable convergence candidate

- Candidate: `ROUND_12_PACKET`, aggregate SHA-256 `aff34c2ef8d8fd2237faacc63c20f4cbeeb0a36da5087838de7b6f5cf4c57493` (44 read-only files).
- All 44/44 manifest-listed hashes, sizes and live copies match; files are `0444`, directories `0555`, and the adjacent manifest is `0444`. The packet-local suite passes 12 Draft 2020-12 schemas, 8 valid/8 invalid examples, lifecycle with 13 stageable steps and 1 atomic dispatch, 1618 assertion instances and 15 traceability invariants.
- This freeze is not a review disposition or closure. `Q-88`–`Q-90` and all prior patched issues remain `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION`; the clean series remains `0`. Round 12A then, only if Round 12A is clean, Round 12B must be fresh full-scope Terra/high process-blind reviews on this exact digest.
- Round 11B remains prohibited on its failed packet. Runtime remains `NOT_IMPLEMENTED`, runtime attestation remains `NOT_ATTESTED`, and overall status remains `NOT_READY`.

## Official Round 12A full-scope arbitration

- Candidate: `ROUND_12_PACKET`, aggregate SHA-256 `aff34c2ef8d8fd2237faacc63c20f4cbeeb0a36da5087838de7b6f5cf4c57493` (44 immutable files; 1618 assertion instances and 15 traceability invariants). Fresh blind `gpt-5.6-terra`/high arbitration verified neutral corpus aggregate `0971fbac41b38c1a491118f3768d48bfe4c2c27f0b33394107930f90eb544e46`, the candidate packet, and anonymized input SHA-256 `26df79052bde2931d8991967aaf83bedab1e877ca15442798f4a1e22d0b9f23f`.
- Raw capture contains four findings (`1 Critical / 2 High / 1 Medium`); the runtime reviewer returned `CLEAN_NO_MATERIAL_FINDING`. `CANONICAL_MAPPING_ROUND_12A_OFFICIAL.json` maps all four 1:1 to four canonical issues: no merge, drop, or severity downgrade.
- The fresh blind arbiter retained `Q-91` (delegation target authority containment, Critical), `Q-93` (exact trusted approval-envelope projection, High), and `Q-94` (canonical scoped package-status coherence, Medium) `OPEN`; it dispositioned `Q-92` (durable D2 frontier and iteration-slot currentness, High) `REJECTED_WITH_COUNTEREVIDENCE`.
- Round 12A failed; the clean series is `0`, and Round 12B is prohibited on this failed packet. Remediate the open issues, freeze a new immutable packet, and complete two fresh clean full-scope rounds on that same new digest before closure audit and novelty verification. Runtime remains `NOT_IMPLEMENTED`, runtime attestation remains `NOT_ATTESTED`, and overall status remains `NOT_READY`.

| Canonical issue | Severity | Round-12A disposition | Current closure state |
|---|---:|---|---|
| `Q-91` delegation target authority containment | Critical | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-92` durable D2 frontier and iteration-slot currentness | High | `REJECTED_WITH_COUNTEREVIDENCE` | `REJECTED_WITH_COUNTEREVIDENCE` |
| `Q-93` exact trusted approval-envelope projection | High | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `Q-94` canonical scoped package-status coherence | Medium | `OPEN` | `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |

Root verified the live post-Round-12A remediation at 12 Draft 2020-12 schemas, 8 valid/8 invalid examples, 13 stageable lifecycle steps, 1 atomic dispatch, 1641 assertion instances and 15 traceability invariants. A fresh read-only Terra/high pre-freeze audit found one duplicate status projection, which was removed in favor of `tests/invariant-traceability.json#/status`; the added negative regression rejects reintroduction of a local conflicting status. Its final rerun was `CLEAN`: Q91's exact `SPAWN|BIND` clause selection matched the written norm, Q92 preserved fresh-iteration liveness while stale state failed closed, and Q93/Q94 exact bindings held. This advisory audit is not an official clean full-scope round and closes nothing. Round 12A remains failed, the clean series remains `0`, and Round 12B remains prohibited.

## Round 13 immutable convergence candidate

- Candidate: `ROUND_13_PACKET`, aggregate SHA-256 `79bb6b9e3cff81df48abf7fdecec07e258f8f477756b4cd16ac099b065b0b5f8` (44 read-only files).
- All 44/44 manifest-listed hashes, sizes and live copies independently match; files are `0444`, directories `0555`, and the adjacent manifest is `0444`. The packet-local suite passes 12 Draft 2020-12 schemas, 8 valid/8 invalid examples, lifecycle with 13 steps and 1 atomic dispatch, 1641 assertion instances and 15 traceability invariants.
- This freeze is not a review disposition or closure. The clean series remains `0`; `Q-91`, `Q-93`, `Q-94` and all prior accepted findings remain `PATCHED_MODEL_TESTED_AWAITING_INDEPENDENT_VERIFICATION`, while `Q-92` remains `REJECTED_WITH_COUNTEREVIDENCE` with the existing regression-tested defense-in-depth hardening.
- No Round 13 review has run. The next eligible action is a fresh process-blind Terra/high Round 13A; Round 13B is eligible only if Round 13A is clean and must use this exact digest. Runtime remains `NOT_IMPLEMENTED`, runtime attestation remains `NOT_ATTESTED`, and overall status remains `NOT_READY`.

## Canonical issues

| Canonical issue | Severity | Raw IDs | Patch/evidence in current package | Current closure state |
|---|---:|---|---|---|
| `C-R1A-01` duplicate budget amplification | Critical | `R1A-002`, `R1B-002` | Canonical aggregate/reject logic; duplicate demand/bound and conservation assertions | `PATCHED_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `C-R1A-02` cyclic/replayable capability lifecycle | Critical | `R1A-001`, `R1B-001`, `R1B-003`, `R1B-008` | Schema-valid admission→decision digest→mint→atomic consume; null/tamper/mismatch/replay-after-STOP assertions | `PATCHED_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `C-R1A-03` scalar-only D2 | High | `R1A-003` | Typed frontier flags and all declared artifact classes, including capability/reservation/lock/target/dispatch/external authorization | `PATCHED_TESTED_AWAITING_INDEPENDENT_VERIFICATION`; D2 remains provisional |
| `C-R1A-04` ill-typed/correlation/parallel algebra | High | `R1A-004`, `R1A-007` | Ill-typed atom and correlated cross-pair assertions; clauses specified as correlated alternatives | `OPEN_PARTIAL`: executable full lattice laws and parallel-interference model remain absent |
| `C-R1A-05` unauthorized/unevidenced JOIN | High | `R1A-005`, `R1B-006`, `R1C-003` | Receipt/event semantic validators; committed-subset, seal/postcheck/chain/emitter/JOIN mutations | `PATCHED_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `C-R1A-06` external reservation/crash/compensation gaps | High | `R1A-006` | Unknown escrow/no-retry/reconcile conservation, crash/orphan, durable revocation and fresh-compensation assertions | `PATCHED_TESTED_AWAITING_INDEPENDENT_VERIFICATION`; exhaustive runtime fault matrix absent |
| `C-R1A-07` untrusted/inconsistent approval | High | `R1B-004` | Discriminated non-authorizing lifecycle; SoD/quorum/comprehension/nonce/signature mutations | `PATCHED_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `C-R1A-08` unsafe active isolation profile | High | `R1B-005`, `R1C-001` | Role uniqueness, worker ceiling, full resources, attestation and supply rollback semantic mutations | `PATCHED_TESTED_AWAITING_INDEPENDENT_VERIFICATION`; kernel conformance absent |
| `C-R1A-09` lexical path escape | High | `R1B-007` | Descriptor-proven canonical selector plus raw/encoded/backslash traversal assertions; runtime `openat2` obligation | `PATCHED_TESTED_AWAITING_INDEPENDENT_VERIFICATION`; syscall conformance absent |
| `C-R1A-10` false traceability PASS | High | `R1A-008` | Resolved registries, executed assertion set, unknown-ID and removed-assertion mutations | `PATCHED_TESTED_AWAITING_INDEPENDENT_VERIFICATION` |
| `C-R1A-11` placement/session TOCTOU | High | `R1C-002` | Exact placement/session/composite binding plus subject/nonce/epoch/freshness mutations | `PATCHED_TESTED_AWAITING_INDEPENDENT_VERIFICATION`; real attestor absent |
| `C-R1A-12` host orphan lifecycle | High | `R1C-004` | Abstract host ledger/fence/orphan-reconciliation state machine and stale/incomplete recovery negatives | `PATCHED_TESTED_AWAITING_INDEPENDENT_VERIFICATION`; host fault injection absent |
| `C-R1A-13` self-asserted supply provenance | High | `R1C-005` | Typed composite component measurements; signature/revocation/rollback/exact-byte/composite mutations | `PATCHED_TESTED_AWAITING_INDEPENDENT_VERIFICATION`; real crypto/loader absent |

## Historical Round-5 immutable verification target

- Candidate: `ROUND_5_PACKET`; aggregate SHA-256 `e7a91a83c6c581f74730b518cbebb9762702fff83c9014487fb4645187dcf090`; 44 files.
- Passing baseline evidence: 12 schemas; 8 valid/8 invalid examples; schema-valid admission/capability chain; 13 stageable steps; one atomic dispatch; replay survives STOP; 561 negative/property assertion instances; 15 resolved/executed invariant mappings.
- Independent result: seven reproducible High counterexamples remain open. Passing baseline checks do not cover them and do not imply convergence.
- Skipped/runtime-absent: real signatures, descriptor syscalls, kernel/isolation enforcement, durable storage, live broker/executor/observer, external reconciliation and runtime attestation.
- Overall: `NOT_READY`. No finding is closed by author assertion or test count alone.

## Round-6 candidate (historical post-Round-5 remediation)

- Candidate: `ROUND_6_PACKET`; aggregate SHA-256 `321b0efc2c8202f142b1e6b28dca93c5cecb5804cc62d8bf555ba78d65d84f8d`; 44 read-only files.
- Passing packet-local evidence: 12 schemas; 8 valid/8 invalid examples; schema-valid admission/capability chain; 13 stageable steps; one atomic dispatch; replay survives STOP; 1008 negative/property assertion instances; 15 resolved/executed invariant mappings.
- Independent status: Round 6A was not clean; its 13 open canonical issues are under live Terra remediation. A new candidate has not yet been frozen or independently verified.
- Runtime remains `NOT_IMPLEMENTED`; runtime attestation and real enforcement evidence remain `NOT_ATTESTED/ABSENT`.
- Overall remains `NOT_READY` pending independent convergence and final closure/novelty checks.
