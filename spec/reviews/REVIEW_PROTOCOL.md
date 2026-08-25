# Review protocol

## Assurance boundary

Review is **process-blind**, not technically or cryptographically blind. All agents share a filesystem; no ACL/sandbox evidence proves that an agent could not access forbidden files. Each role receives an explicit least-context path contract and attests what it actually read. Attestation is procedural evidence only.

The primary integrator authors/integrates but is never the sole reviewer, arbiter, closure auditor or risk owner. Reviewer count and consensus do not establish truth.

## Frozen inputs

- Neutral source packet: `CORPUS_PACKET`; aggregate SHA-256 `0971fbac41b38c1a491118f3768d48bfe4c2c27f0b33394107930f90eb544e46`.
- Each candidate packet is copied rather than linked, hashed per file with a checked manifest, independently aggregate-reproduced, and chmod read-only. The procedure is mechanical; no dedicated packet-builder dependency is required.
- Candidate packets contain only normative files `03`, `04`, `10–18`, schemas, examples and tests.
- They exclude source/coverage/conflict/issue/closure ledgers, reviews, discovery/author rationale, changelog and intended final answer.

## Discovery gate

Eight fresh agents ran before Draft V0 in waves `3 + 3 + 2`, packet-only, without writes, web or nested delegation:

1. corpus/traceability;
2. formal methods/effect algebra/capabilities;
3. Linux isolation/runtime/supply chain;
4. policy/distributed state/concurrency;
5. multi-agent delegation/reflection/information flow;
6. SRE/observability/IR/privacy;
7. human factors/governance/approval UX;
8. verification/testing/benchmark/assurance/Ponytail implementability.

All eight memo completions preceded `work/AUTHOR_BRIEF.md` and Draft V0.

## Reviewer two-phase contract

For each lens and round, a fresh agent with `fork_turns="none"` receives only:

1. Phase 1: neutral corpus packet path/digest and the lens. It returns a frozen checklist/proof obligations/attack hypotheses/attempted falsifications, a digest of its exact precommit, and an access attestation.
2. Phase 2: exactly one `followup_task` containing only the candidate packet path/digest. No further context is sent. It returns findings in the required structured format or `NO_FINDING` with coverage and failed falsification attempts.

Reviewer instruction: ignore intended answer, author authority and votes; first seek a minimal counterexample or failed proof obligation. No quota findings. No draft edits, sibling communication, web or nested spawning.

## Rounds

| Round | Review lenses |
|---|---|
| 1 | formal/effect/D2; capability authority red team; Linux/TOCTOU/crash |
| 2 | delegation/information/reflection; policy/ledger/recovery/supply chain; SRE/privacy/correction |
| 3 | human/break-glass; schemas/tests/traceability/assurance; Ponytail/DX/minimal coherent implementation |
| 4 | three independent full-scope L0–L5 + cross-cutting convergence passes |
| 5 | three new independent full-scope L0–L5 + cross-cutting convergence passes |
| 6A (supplemental, authorized after the historical cap) | three fresh full-scope convergence passes of `ROUND_6_PACKET`; failed and was fully arbitrated |
| 7A (supplemental) | three fresh Terra/high full-scope convergence passes of `ROUND_7_PACKET`; four High findings, fully arbitrated, clean series reset to zero |
| 8A (supplemental) | three fresh Terra/high full-scope passes of `ROUND_8_PACKET`; three High findings, fully arbitrated, clean series reset/remains zero |
| 9A/9B (supplemental) | Round 9A on `ROUND_9_PACKET` digest `bf52dbcc…ff726` failed with one High and one Medium finding, both `OPEN`; clean series reset to zero and Round 9B must not run on this failed packet |
| 10A/10B (supplemental) | Round 10A on `ROUND_10_PACKET` digest `1e6168e4…c4e008` failed with one Critical, three High and one Medium raw findings mapped to four `OPEN` issues; clean series reset to zero and Round 10B must not run on this failed packet |
| 11A/11B (supplemental) | Round 11A on `ROUND_11_PACKET` digest `1a253395…1b5b4f` failed with three raw High findings mapped 3→3, with no merge, drop, or severity downgrade; fresh blind Terra/high arbitration retained `Q-88`–`Q-90` `OPEN`, clean series `0`, and Round 11B must not run on this failed packet. Remediation, a new immutable packet, and two fresh clean full-scope rounds on that new digest are required. |
| 12A/12B (supplemental) | Round 12A on `ROUND_12_PACKET` digest `aff34c2e…57493` (44 immutable files; 1618 assertions/15 invariants) failed with four raw findings (`1 Critical / 2 High / 1 Medium`); the runtime reviewer was clean. Mapping preserved 4→4 with no merge, drop, or severity downgrade. Fresh blind `gpt-5.6-terra`/high arbitration verified neutral `0971fb…544e46`, the candidate and anonymized input `26df79…b9f23f`; it retained `Q-91` Critical, `Q-93` High and `Q-94` Medium `OPEN`, and set `Q-92` High `REJECTED_WITH_COUNTEREVIDENCE`. Clean series is `0`; Round 12B must not run on this failed packet. Remediation, a new immutable packet, and two fresh clean full-scope rounds on that new digest are required. |
| 13A/13B (supplemental) | `ROUND_13_PACKET` digest `79bb6b9e…0b5f8` is frozen and mechanically verified (44/44 hashes, sizes and live copies independently matched; files `0444`; directories `0555`; adjacent manifest `0444`; 12 schemas; 8 valid/8 invalid; 13 lifecycle steps; 1 atomic dispatch; 1641 assertions; 15 invariants). This freeze is not a review, arbitration or closure; no Round 13 review has run. The clean series remains `0`. The only eligible next review is fresh process-blind Terra/high Round 13A; Round 13B may run only if Round 13A is clean and only on the exact same digest. |

Live post-Round-12A remediation passes 1641 assertions and 15 invariants. A separate read-only Terra/high pre-freeze audit is advisory only: its final result was clean after the package-status projection was reduced to one machine-readable source. It does not increment the clean series. The frozen Round 13 candidate does not increment it either. The next eligible official sequence is fresh process-blind Terra/high Round 13A and, only if 13A is clean, Round 13B on the exact same digest.

The fixed five-round cap governed historical Rounds 1–5: a needed patch after Round 4 or 5 meant `NOT_READY`, never hidden as convergence. After Round 6A, the user expressly authorized a supplemental series. Any patch resets that series to zero; it does not revise the historical cap or establish readiness. At a max-round stop, the report is terminal and the controller is `STOPPED_AWAITING_EXPLICIT_USER_INSTRUCTION`; neither it nor a finding can start a patch, freeze or further review.

A desired count of clean results is a `success_target`, never an attempt allowance. Every started review or remediation pass consumes one durable attempt; failure, retry, restart or packet change does not refund it. The configured maximum attempt count cannot be raised by the success target. A frozen-packet digest change ends the current exact-bound continuation contract, and any further `PATCH`, `FREEZE` or `REVIEW` needs a new explicit user grant.

Supplemental closure requires a newly frozen immutable candidate, two entirely fresh clean full-scope Terra/high rounds on that same digest, then a fresh closure auditor and a separate novelty verifier. No issue or package is closed before all four checks; runtime status remains a separate claim. Historical wording such as “remediation”, “required” or “two fresh rounds” states a readiness condition only; it is never authorization to continue.

## Finding and severity contract

Every finding records: ID; lens; severity; confidence; packet digest; affected artifacts/levels; normative claim; locator; concrete failure trace; failed control; minimal safe patch; regression test; expected evidence; residual risk; blindness attestation.

Every resulting remediation/review report also records this closed assessment projection:

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

`BLOCKS_CLAIM` means only that the affected status cannot honestly be claimed. A report, finding, severity, blocker, recommended patch and readiness classification are evidence/assessment only: their text cannot cause a workflow transition. After every report, `PATCH`, `FREEZE` and `REVIEW` each require a fresh externally verified single-use user/human continuation grant exact-bound to that action, report/finding/current-packet digests, scope, budget, attempt ceiling, nonce and post-report TTL. User identity and verifier trust are externally established; current packet/scope/budget/attempt come from authoritative controller state rather than the report or request. The grants are distinct; one action never authorizes another, and packet-digest change invalidates any old grant. `decide_review_continuation` is the pure controller check for this rule; without the matching grant it returns `STOPPED_AWAITING_EXPLICIT_USER_INSTRUCTION` with `RC_REPORT_NONAUTHORIZING` or `RC_CONTINUATION_GRANT_INVALID`. On success it returns the post-consumption facts, which the controller MUST commit atomically with exactly one transition; stale pre-state is not reusable.

- `Critical`: committed unauthorized effect, authority amplification/hard-boundary bypass, unrecoverable integrity/confidentiality/safety loss, or absent non-bypassable enforcement.
- `High`: plausible route to Critical, untestable normative control, missing fail-closed/recovery semantics, or material evidence loss.
- `Medium`: bounded ambiguity/coverage/operability gap with an effective compensating control.
- `Low`: clarity/DX/maintainability issue without a direct safety-claim change.

## Raw capture, deduplication and arbitration

Immediately after each three-reviewer batch and before deduplication, the integrator records a `RAW_FINDINGS_MANIFEST` with candidate digest, an exact captured-response digest/count and severity counts. Then it constructs a total raw→canonical mapping; no merge may lose the strongest severity, counterexample or test obligation.

Before arbitration, reviewer identity, lens and cycle position are removed, findings get random anonymous IDs and are shuffled. A fresh arbiter receives neutral corpus, frozen candidate, test evidence and anonymized raw/canonical Critical/High plus contested Medium. Allowed dispositions only: `ACCEPTED_FIXED`, `REJECTED_WITH_COUNTEREVIDENCE`, `PROPOSED_FOR_HUMAN_RISK_ACCEPTANCE`, `OPEN`.

The integrator cannot lower severity or override disposition. Critical is never deferred. High remains open until independently verified. Medium without a signed authorized human risk-owner receipt remains an open proposal.

## Final assurance roles

Only after convergence attempts:

- a fresh closure auditor sees anonymized issue/closure ledger, final packet and evidence and checks every raw→canonical mapping, disposition, patch and test;
- a different fresh novelty verifier sees neutral corpus + final packet only and seeks new contradictions/counterexamples/overclaims.

Both attest access. Their pass/fail changes assurance status, not runtime implementation status.

## Model disclosure

Round 6A reviewers were `gpt-5.6-luna` with `high` reasoning, under the prior instruction; those immutable reports remain Luna evidence. After the user's override, Round 6A reproduction/arbitration/remediation and every Round 7A role use `gpt-5.6-terra` with `high` reasoning. Every newly created continuation role remains Terra/high. Earlier roles use the models recorded by their orchestration metadata. The primary integrator runtime identifies itself only as GPT-5 in the governing system context; no local API exposed a trustworthy model-build or reasoning-effort attestation for the root. The package therefore does not claim end-to-end model homogeneity or imitate an unavailable identity.
