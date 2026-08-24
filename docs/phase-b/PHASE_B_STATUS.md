# Phase B — Differential Verification

## Objective

Determine whether an independently implemented Verifiable Intent chain verifier
agrees with the genuine Trustline verifier on the same inputs.

## Evidence boundary

Phase B must distinguish between:

1. Genuine Trustline verification
2. Independent reference verification
3. Mock/test responses

A mock response must never be presented as evidence of Trustline behavior.

The independent verifier from Phase A is not Trustline and must remain clearly
identified as an independent reference implementation.

## Current status

- Phase A independent verifier: COMPLETE
- Phase B adapter interface: NOT STARTED
- Real Trustline verifier access: NOT CONFIRMED
- Differential test corpus: NOT STARTED
- Trustline-vs-reference results: NOT AVAILABLE

## Intended comparison

For each test vector:

    same input chain + payment + policy
                |
        +-------+-------+
        |               |
        v               v
 Independent        Trustline
 reference          verifier
 verifier
        |               |
        +-------+-------+
                |
                v
        normalized results
                |
                v
          differential
            comparison

## Result categories

AGREE
    Both implementations produce equivalent security decisions.

DISAGREE
    The implementations produce materially different decisions or verification
    states.

UNAVAILABLE
    Genuine Trustline verification could not be executed.

INVALID_EVIDENCE
    A result cannot be attributed to genuine Trustline verification.

## Important limitation

Until a genuine Trustline verifier endpoint, SDK, executable, or other
independently attributable verification interface is available, this project
cannot claim to have validated Trustline's implementation.

Tests using mocks or the independent AgenticRiskStandard reference
implementation are integration-shape tests only. They are not Trustline
behavioral evidence.
