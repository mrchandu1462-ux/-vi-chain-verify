"""
Unavailable external verifier adapter.

This adapter deliberately performs NO verification.

It represents the current state where a genuine external/Trustline
verification interface has not been provided.

Its output must never be interpreted as Trustline behavior.
"""

from __future__ import annotations

from .interface import (
    NormalizedVerificationResult,
    VerificationInput,
    VerifierAdapter,
)


class UnavailableVerifierAdapter(VerifierAdapter):
    source_name = "genuine_external_verifier_unavailable"
    is_mock = False

    def verify(
        self,
        request: VerificationInput,
    ) -> NormalizedVerificationResult:
        return NormalizedVerificationResult(
            source=self.source_name,
            is_mock=False,
            decision="unavailable",
            verified=None,
            chain_verified=None,
            constraint_satisfied=None,
            payment_bound=None,
            reasons=[
                "No genuine external verifier interface is configured"
            ],
            error_code="EXTERNAL_VERIFIER_UNAVAILABLE",
            raw_result={
                "status": "UNAVAILABLE",
                "evidence_valid": False,
            },
        )
