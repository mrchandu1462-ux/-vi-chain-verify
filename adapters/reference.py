"""
Phase-B adapter for the independent Phase-A reference verifier.

This adapter is NOT Trustline.

It exists only to expose the Phase-A verifier through the common
Phase-B adapter interface so differential comparisons have a stable
reference side.
"""

from __future__ import annotations

from vi_verify.models import PaymentRequirements
from vi_verify.verify import VerifyContext, verify_chain

from .interface import (
    NormalizedVerificationResult,
    VerificationInput,
    VerifierAdapter,
)


class ReferenceVerifierAdapter(VerifierAdapter):
    """
    Adapter around the independent Phase-A verifier.

    This implementation is genuine executable verification, but it is
    independent of Trustline and must never be described as Trustline.
    """

    source_name = "phase_a_independent_reference"
    is_mock = False

    def __init__(self, context: VerifyContext) -> None:
        self.context = context

    def verify(
        self,
        request: VerificationInput,
    ) -> NormalizedVerificationResult:
        result = verify_chain(
            request.chain,
            request.payment,
            self.context,
        )

        verified = result.decision == "allow"

        return NormalizedVerificationResult(
            source=self.source_name,
            is_mock=self.is_mock,
            decision=result.decision,
            verified=verified,
            chain_verified=verified,
            constraint_satisfied=verified,
            payment_bound=verified,
            reasons=list(result.reasons),
            raw_result=result.to_dict(),
        )
