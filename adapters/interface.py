"""
Adapter boundary for Phase B differential verification.

This module defines the interface between the Phase-A independent reference
verifier and any external verifier implementation.

IMPORTANT:
- This file contains no Trustline verification logic.
- A mock adapter is not evidence of Trustline behavior.
- An independent reference implementation must be labeled as such.
- A future real Trustline adapter must only use a genuine Trustline interface.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional

from vi_verify.models import Chain, PaymentRequirements


@dataclass
class VerificationInput:
    """Common input supplied to every verifier adapter."""

    chain: Chain
    payment: PaymentRequirements
    policy: dict[str, Any] = field(default_factory=dict)


@dataclass
class NormalizedVerificationResult:
    """
    Common result representation used for differential comparison.

    `source` identifies the actual verifier implementation.
    `is_mock` prevents mock output from being mistaken for external evidence.
    `raw_result` preserves the original adapter result.
    """

    source: str
    is_mock: bool

    decision: str
    verified: Optional[bool] = None
    chain_verified: Optional[bool] = None
    constraint_satisfied: Optional[bool] = None
    payment_bound: Optional[bool] = None

    reasons: list[str] = field(default_factory=list)
    error_code: Optional[str] = None

    raw_result: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "is_mock": self.is_mock,
            "decision": self.decision,
            "verified": self.verified,
            "chain_verified": self.chain_verified,
            "constraint_satisfied": self.constraint_satisfied,
            "payment_bound": self.payment_bound,
            "reasons": self.reasons,
            "error_code": self.error_code,
            "raw_result": self.raw_result,
        }


class VerifierAdapter(ABC):
    """
    Common interface for Phase-B differential verification.

    Implementations may represent:
      - the Phase-A independent reference verifier,
      - a test/mock verifier,
      - a genuine external verifier.

    `source_name` must identify the implementation honestly.
    """

    source_name: str = "unspecified"
    is_mock: bool = True

    @abstractmethod
    def verify(
        self,
        request: VerificationInput,
    ) -> NormalizedVerificationResult:
        """Verify one chain/payment input."""
        raise NotImplementedError
