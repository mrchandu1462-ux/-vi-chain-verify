# vi-chain-verify

An independent, from-scratch verifier for **Verifiable Intent (VI)** — the
Mastercard-aligned three-layer signed credential chain (L1 → L2 → L3) used
by the [XRPL x402 Facilitator](https://xrpl-x402.t54.ai/docs/verifiable-intent)
to authorize AI-agent payments. Built with a design-verification mindset:
independent reference model, constrained + property-based negative testing,
and a decision log for every check.

## What this is (and isn't)

**This is:** a clean-room implementation of the VI chain-of-trust logic
(hash binding between layers, scope narrowing from L1→L2, single-use
enforcement on L3, ES256 signature verification per layer), stress-tested
against its own constructions with 17 passing tests, including two
property-based fuzz tests that mutate signatures and payload fields across
hundreds of generated cases.

**This is not (yet):** a validation of T54's actual production code. Every
chain in this repo's test suite is built by `chain.py` in this same repo —
so "the verifier rejects every mutation we tried" is a true and useful
result, but it says something about *this reference implementation*, not
about T54's SDK or hosted facilitator. That's Phase B (below), not done here.

Concretely:

| Claim | Status |
|---|---|
| Independent L1→L2→L3 hash-binding + signature model | ✅ Built |
| Scope-escalation checks (L2 can't grant more than L1) | ✅ Built |
| Single-use / replay enforcement on L3 | ✅ Built |
| Mutation tests against **our own** mock chains | ✅ 17/17 passing |
| Verified against **T54's actual SDK / facilitator** | ❌ Not done — Phase B |
| Any product-level finding on T54's implementation | ❌ None claimed |

## Why this exists

The docs describe VI as a chain where each layer narrows the last:
Trustline issues L1 (owner identity + ceiling), the owner signs L2
(delegates to an agent under tighter limits, hash-bound to L1), the agent
signs L3 (commits to one exact payment, hash-bound to L2, single-use). A
verifier's entire job is to refuse anything that breaks that chain — a
forged signature, a severed hash binding, a delegation that grants more
than it was given, a replayed single-use token, an expired credential, or
a payment that doesn't match what L3 actually committed to.

That's structurally the same job as a hardware verification testbench:
define the legal state space, then throw everything at the boundary of it.
`verify.py` is written as a sequence of independent assertions for exactly
that reason — each check fails closed, and a single failing assertion is
enough to deny.

## Structure

```
src/vi_verify/
  crypto.py         ES256 (P-256/SHA-256) sign+verify, canonical JSON hashing
  models.py         Credential / Chain / PaymentRequirements / VerificationResult
  chain.py          builds L1 -> L2 -> L3 (the "happy path" issuance flow)
  verify.py         the assertion engine: every check the verifier runs
  replay_store.py   single-use jti tracking
  cli.py            `vi-verify demo [--tamper l2hash|l3hash|replay]`
tests/
  test_adversarial.py   targeted negative tests: hash tampering, signature
                        substitution, scope escalation, expiry, replay,
                        payment/invoice mismatch
  test_fuzz.py          hypothesis property tests: random signature byte
                        flips and payload field tampering must never verify
```

## Running it

```bash
pip install -e ".[dev]"
pytest -v
python -m vi_verify.cli demo                  # valid chain -> allow
python -m vi_verify.cli demo --tamper l2hash  # broken L1<-L2 binding -> deny
python -m vi_verify.cli demo --tamper l3hash  # broken L2<-L3 binding -> deny
python -m vi_verify.cli demo --tamper replay  # reused L3 jti -> deny
```

Current result: **17 passed** (`test_adversarial.py` + `test_fuzz.py`,
the latter running 200 and 100 generated examples respectively per property).

## Decision model

`verify_chain()` returns one of:

- **allow** — every structural, cryptographic, and business-rule check passed.
- **deny** — at least one check failed: bad signature, broken hash binding,
  replay, expired credential, scope escalation, or a payment that doesn't
  match what L3 actually committed to.
- **review** — structurally and cryptographically valid, but the payment
  amount is ≥90% of the L1 spend ceiling — a soft risk signal, not a hard
  rule. A real facilitator's risk decision folds in far more signal than
  this; it's a deliberately conservative stand-in so "review" isn't unused.

## Phase B (not started here)

The next milestone, once this reference implementation is frozen, is
differential testing against T54's actual code: generate genuine artifacts
with their SDK, run the *same* mutation matrix used here against their
implementation instead of this repo's mock chains, and compare decisions.
A divergence — T54 accepts what this verifier rejects, or vice versa — is
the only thing that would turn this from an independent reference
implementation into an actual finding about their product. Until that
comparison happens, no claim is made about T54's code either way.

## Background reading

- [XRPL x402 Facilitator — Verifiable Intent docs](https://xrpl-x402.t54.ai/docs/verifiable-intent)
- [Mastercard Verifiable Intent standard](https://verifiableintent.dev/)

## License

MIT
