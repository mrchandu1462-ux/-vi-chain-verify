"""
Differential comparison for Phase B verifier results.

The comparator compares normalized results from two independently identified
verifier adapters.

External verifier availability is handled explicitly:
- UNAVAILABLE means genuine external verification was not executed.
- INVALID_EVIDENCE means the external result cannot be attributed to a
  genuine verifier.
- DISAGREE means both sides executed and produced materially different
  verification results.
- AGREE means both sides executed and their normalized results agree.
"""

from __future__ import annotations

from dataclasses import dataclass

from .interface import NormalizedVerificationResult


@dataclass
class DifferentialResult:
    """Result of comparing two verifier outputs."""

    status: str
    reference_source: str
    external_source: str
    differences: list[str]

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "reference_source": self.reference_source,
            "external_source": self.external_source,
            "differences": self.differences,
        }


def compare_results(
    reference: NormalizedVerificationResult,
    external: NormalizedVerificationResult,
) -> DifferentialResult:
    """
    Compare two normalized verification results.

    The reference side is the independent Phase-A verifier.

    The external side must actually execute a verifier before its result can
    produce AGREE or DISAGREE.

    An unavailable external verifier therefore produces UNAVAILABLE rather
    than DISAGREE.
    """

    differences: list[str] = []

    # No genuine external verification was executed.
    if external.decision == "unavailable":
        return DifferentialResult(
            status="UNAVAILABLE",
            reference_source=reference.source,
            external_source=external.source,
            differences=[
                "Genuine external verifier was not available"
            ],
        )

    # Mock output can never be treated as external verification evidence.
    if external.is_mock:
        return DifferentialResult(
            status="INVALID_EVIDENCE",
            reference_source=reference.source,
            external_source=external.source,
            differences=[
                "External result is marked as mock/test output"
            ],
        )

    # A verifier result without provenance is not attributable evidence.
    if not external.source:
        return DifferentialResult(
            status="INVALID_EVIDENCE",
            reference_source=reference.source,
            external_source=external.source,
            differences=[
                "External result has no source identifier"
            ],
        )

    if reference.decision != external.decision:
        differences.append(
            f"decision differs: reference={reference.decision!r}, "
            f"external={external.decision!r}"
        )

    fields = (
        "verified",
        "chain_verified",
        "constraint_satisfied",
        "payment_bound",
    )

    for field in fields:
        reference_value = getattr(reference, field)
        external_value = getattr(external, field)

        if (
            reference_value is not None
            and external_value is not None
            and reference_value != external_value
        ):
            differences.append(
                f"{field} differs: reference={reference_value!r}, "
                f"external={external_value!r}"
            )

    status = "DISAGREE" if differences else "AGREE"

    return DifferentialResult(
        status=status,
        reference_source=reference.source,
        external_source=external.source,
        differences=differences,
    )
