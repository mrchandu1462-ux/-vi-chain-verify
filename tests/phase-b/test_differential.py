from adapters.differential import compare_results
from adapters.interface import NormalizedVerificationResult


def result(
    *,
    source: str = "test",
    is_mock: bool = False,
    decision: str = "allow",
    verified: bool | None = True,
    chain_verified: bool | None = True,
    constraint_satisfied: bool | None = True,
    payment_bound: bool | None = True,
):
    return NormalizedVerificationResult(
        source=source,
        is_mock=is_mock,
        decision=decision,
        verified=verified,
        chain_verified=chain_verified,
        constraint_satisfied=constraint_satisfied,
        payment_bound=payment_bound,
    )


def test_identical_real_results_agree():
    comparison = compare_results(
        result(source="phase_a_independent_reference"),
        result(source="external_verifier"),
    )

    assert comparison.status == "AGREE"
    assert comparison.differences == []


def test_decision_difference_is_disagreement():
    comparison = compare_results(
        result(source="phase_a_independent_reference", decision="deny", verified=False),
        result(source="external_verifier", decision="allow", verified=True),
    )

    assert comparison.status == "DISAGREE"
    assert any("decision differs" in item for item in comparison.differences)


def test_security_field_difference_is_disagreement():
    comparison = compare_results(
        result(source="phase_a_independent_reference"),
        result(
            source="external_verifier",
            constraint_satisfied=False,
        ),
    )

    assert comparison.status == "DISAGREE"
    assert any(
        "constraint_satisfied differs" in item
        for item in comparison.differences
    )


def test_mock_external_result_is_not_evidence():
    comparison = compare_results(
        result(source="phase_a_independent_reference"),
        result(source="mock", is_mock=True),
    )

    assert comparison.status == "INVALID_EVIDENCE"


def test_empty_external_source_is_invalid_evidence():
    comparison = compare_results(
        result(source="phase_a_independent_reference"),
        result(source=""),
    )

    assert comparison.status == "INVALID_EVIDENCE"
