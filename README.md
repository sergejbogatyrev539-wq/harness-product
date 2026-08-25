# Harness product

Universal, policy-enforced mediation for agent-initiated work. The product is to
turn the normative Harness specification into a runtime in which untrusted
workers can propose bounded work but cannot bypass the control path.

## Current status

`specification=SPECIFIED; runtime=NOT_IMPLEMENTED; runtime_attestation=NOT_ATTESTED; overall=NOT_READY`.
The copied `spec/` corpus is normative; it is not a runnable security product.

## Start here

```bash
python -m venv .venv
.venv/bin/pip install -e .
.venv/bin/python scripts/check.py
```

The single check verifies all 48 transferred specification files against
`spec/MANIFEST.sha256`, runs the product unit tests, and executes the original
specification-model runner. Any missing dependency or check is a failure, not a
skip.

## Intended minimum

1. A pure, total admission kernel derives and narrows an exact authority envelope.
2. A Controller/PEP and broker durably authorize one use of a capability.
3. A separately attested executor or gateway performs the exact call; a worker
   only sends powerless proposals.
4. The runtime blocks unknown or mismatched state, records authoritative events,
   and retains same-profile evidence.

See [architecture](docs/ARCHITECTURE.md), [roadmap](ROADMAP.md), and
[security boundary](SECURITY.md). Implementations must follow [AGENTS.md](AGENTS.md).

`src/harness_product/` is only a non-effectful reference scaffold. It demonstrates
pure scoped admission and cooperative one-use API behavior. Same-interpreter
Python internals are not a security boundary; non-bypassable dispatch begins only
after M2/M3 supplies separately enforced broker/executor principals. This scaffold
does not provide durable storage, OS isolation, real signatures, an effect
executor, runtime evidence, or attestation.
