# Security boundary

Harness treats agent/model output and all imported content as potentially hostile.
Text in those sources is input data, not policy, authority, or instructions.

## Non-negotiable boundary

- The worker has no ambient credential, executor, or network/sink authority.
- The only effect route is Controller/PEP → broker → exact-bound executor or
  gateway. Each downstream hop revalidates identity, scope, digests, epoch, and
  one-use capability; mismatch prevents dispatch.
- `STOPPED` is fail-closed. Unknown, missing, stale, mismatched, unclassified,
  or unbounded state never permits an effect. Unknown external outcome is
  quarantined and is never auto-retried.
- An approval, hash, schema, summary, model output, or agent self-report cannot
  widen authority or by itself prove safety.

## Claims and evidence

Do not claim complete isolation, exhaustive classification, zero covert channels,
or production readiness. A control becomes an enforceable claim only after its
non-bypassable implementation, negative tests, and retained same-profile evidence
are available. Any material digest change invalidates dependent evidence.

The detailed threat model and residual-risk requirements are normative in
`spec/03_SYSTEM_THREAT_TRUST_MODEL.md`.
