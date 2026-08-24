"""
Phase-B differential runner.

Runs the same test vector through:
1. the Phase-A independent reference verifier
2. the configured external verifier adapter

No external result is treated as Trustline evidence unless the adapter
actually represents a genuine Trustline interface.
"""

from __future__ import annotations

from dataclasses import dataclass

from adapters.differential import DifferentialResult, compare_results
from adapters.interface import VerificationInput, VerifierAdapter
from adapters.reference import ReferenceVerifierAdapter
from vi_verify import crypto
from vi_verify.replay_store import ReplayStore
from vi_verify.verify import VerifyContext

from tests_phase_b_corpus import get_vectors


@dataclass
class VectorRun:
    name: str
    expected_reference_decision: str
    reference_decision: str
    external_decision: str
    differential: DifferentialResult

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "expected_reference_decision": self.expected_reference_decision,
            "reference_decision": self.reference_decision,
            "external_decision": self.external_decision,
            "differential": self.differential.to_dict(),
        }


def run_vector(vector, external_adapter: VerifierAdapter) -> VectorRun:
    chain, payment, trustline_public_key = vector.build()

    reference_context = VerifyContext(
        trustline_public_key=trustline_public_key,
        replay_store=ReplayStore(),
    )

    reference_adapter = ReferenceVerifierAdapter(reference_context)

    request = VerificationInput(
        chain=chain,
        payment=payment,
    )

    reference_result = reference_adapter.verify(request)
    external_result = external_adapter.verify(request)

    differential = compare_results(
        reference_result,
        external_result,
    )

    return VectorRun(
        name=vector.name,
        expected_reference_decision=vector.expected_reference_decision,
        reference_decision=reference_result.decision,
        external_decision=external_result.decision,
        differential=differential,
    )


def run_corpus(external_adapter: VerifierAdapter) -> list[VectorRun]:
    return [
        run_vector(vector, external_adapter)
        for vector in get_vectors()
    ]
