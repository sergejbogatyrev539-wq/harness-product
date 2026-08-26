# Roadmap

This is a gate-based implementation plan, not execution authority or a readiness
claim. No milestone changes the status of another control. Passing a gate does
not authorize review, status advancement, repeat qualification, or the next
gate.

| Gate | Deliverable | Exit evidence |
|---|---|---|
| M0 | Requirement/invariant trace and named enforcement ownership | Every claimed control maps to enforcement, failure mode, test, event, and evidence. |
| M1 | Pure normalize/classify/derive/decide/transition kernel | Exhaustive and mutation tests show unknown, stale, unbounded, and mismatched inputs stop. |
| M2 | Durable capability, budget, journal, fencing, and recovery state | Crash, race, replay, revocation, and counter-conservation tests pass. |
| M3 | Exact L0 worker/broker/executor/gateway profile and pinned supply | Direct worker effect and confused-deputy attempts are blocked in the measured profile. |
| M4 | Stage/seal/postcheck plus external outcome reconciliation | Same-object evidence, writer races, and unknown-outcome quarantine tests pass. |
| M5 | Authoritative events, detection, response, and evidence retention | Missing/spoofed telemetry fails closed; incident controls have exercised evidence. |
| M6 | Human identity, exact approval, revocation, and separation of duties | Approval cannot expand authority; replay/race/accessibility checks pass. |
| M7 | Integrated profile assurance | Complete traceability, adversarial/fault/concurrency suites, independent review, and an exact evidence bundle pass. |

Until an exact deployment profile completes its applicable gates, it remains
`NOT_IMPLEMENTED`/`NOT_ATTESTED`/`NOT_READY`. If explicitly authorized, the
initial pilot should deny external effects, raw secrets, delegation, persistent
reflection, and break-glass.

## Milestone admission

A roadmap row is not execution authority. Start only the milestone named in a
fresh explicit user instruction. A finding or successful gate does not authorize
its remediation, a repeat qualification, an independent review, or the next
milestone. Completing the authorized milestone returns the workflow to
`STOP_AWAIT_EXPLICIT_USER_GOAL`.

Development follows the short-iteration and expensive-gate protocols in
`AGENTS.md`. Focused checks follow each small change, repository conformance
follows a cohesive checkpoint, and a full physical qualification runs once per
exact candidate/environment pair after all cheaper gates pass.
