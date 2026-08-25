# Roadmap

This is a gate-based implementation plan, not a readiness claim. No milestone
changes the status of another control.

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
`NOT_IMPLEMENTED`/`NOT_ATTESTED`/`NOT_READY`. Start with a pilot that denies
external effects, raw secrets, delegation, persistent reflection, and break-glass.
