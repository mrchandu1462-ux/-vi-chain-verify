# Phase B — Evidence Report

## Scope

Phase B evaluates an independent Verifiable Intent (VI) reference verifier
against a planned external verifier interface.

The external adapter is implemented for the Trustline
`verifiable-intent/verify-chain` endpoint used by the x402-secure facilitator,
but no genuine Trustline endpoint or credential was available in the current
environment.

## Reference implementation

Source:

`phase_a_independent_reference`

The reference implementation is the Phase-A clean-room verifier in
`src/vi_verify/`.

It independently checks:

- L1 signature and expiry
- L2 signature and L1 hash binding
- L2 scope narrowing
- L2 spend ceiling
- L3 signature and L2 hash binding
- L3 expiry
- payment/invoice/requirements binding
- payment scope
- L3 replay protection
- review threshold

## Phase-B corpus

The differential corpus contains 16 controlled vectors:

1. valid
2. l2_hash_tampered
3. l3_hash_tampered
4. l2_signature_tampered
5. l3_signature_tampered
6. scope_asset_escalation
7. scope_chain_escalation
8. per_tx_limit_escalation
9. payment_amount_exceeded
10. payment_chain_mismatch
11. payment_asset_mismatch
12. payment_invoice_mismatch
13. payment_requirements_mismatch
14. expired_l1
15. expired_l2
16. expired_l3

## Execution result

Reference verifier:

- 16/16 vectors executed
- Expected reference decisions matched

External verifier:

- 0 genuine Trustline executions
- 16 vectors classified `UNAVAILABLE`
- 0 `AGREE`
- 0 `DISAGREE`
- 0 `INVALID_EVIDENCE`

Full project regression suite:

`23 passed`

## Why the Trustline side is unavailable

The x402-secure source confirms that the facilitator forwards the VI chain to:

`verifiable-intent/verify-chain`

The Trustline endpoint and authentication are supplied through deployment
environment configuration.

The current environment contains no configured Trustline endpoint or
credential, and no local Trustline verification service is running.

The repository's Docker/test configuration uses local or mock services and
does not constitute genuine Trustline verification evidence.

## Evidence classification

The 16 `UNAVAILABLE` results must not be interpreted as agreement or
disagreement with Trustline.

No product-level finding is claimed from these Phase-B executions.

## Current conclusion

Phase B infrastructure is complete:

- independent reference adapter
- Trustline adapter
- differential comparator
- unavailable-state handling
- 16-vector differential corpus
- executable runner
- evidence classification

However, genuine Trustline behavioral validation remains pending access to an
authorized, reachable Trustline verification service.

Therefore:

**Trustline equivalence: NOT ESTABLISHED**

**Trustline vulnerability/finding: NOT CLAIMED**
