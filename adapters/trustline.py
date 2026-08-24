"""
Phase-B adapter for the genuine Trustline VI-chain verifier.

This adapter talks to the Trustline verification interface used by the
x402-secure facilitator:

    POST /api/v1/validation/verifiable-intent/verify-chain

The endpoint/base URL and authentication are configurable through environment
variables.

IMPORTANT:
This adapter is only considered genuine Trustline evidence when it actually
connects to the configured Trustline service. A connection failure is reported
as UNAVAILABLE rather than being converted into a verification decision.
"""

from __future__ import annotations

import os
from typing import Any

import httpx

from .interface import (
    NormalizedVerificationResult,
    VerificationInput,
    VerifierAdapter,
)


DEFAULT_VALIDATION_PREFIX = "/api/v1/validation"
DEFAULT_VERIFY_CHAIN_PATH = "verifiable-intent/verify-chain"


def _base_url() -> str:
    return (
        os.getenv("TRUSTLINE_API_URL")
        or os.getenv("TRUSTLINE_BASE_URL")
        or os.getenv("RISK_ENGINE_URL")
        or ""
    ).rstrip("/")


def _validation_prefix() -> str:
    return os.getenv(
        "TRUSTLINE_VALIDATION_PREFIX",
        DEFAULT_VALIDATION_PREFIX,
    ).strip("/")


def _verify_chain_path() -> str:
    return (
        os.getenv(
            "TRUSTLINE_FACILITATOR_VERIFY_CHAIN_PATH",
        )
        or os.getenv("TRUSTLINE_VERIFY_CHAIN_PATH")
        or DEFAULT_VERIFY_CHAIN_PATH
    ).strip("/")


def _token() -> str | None:
    return (
        os.getenv("TRUSTLINE_INTERNAL_TOKEN")
        or os.getenv("RISK_INTERNAL_TOKEN")
        or os.getenv("TRUSTLINE_API_KEY")
        or os.getenv("X402_SECURE_TRUSTLINE_TOKEN")
    )


def build_url() -> str:
    base = _base_url()

    if not base:
        raise RuntimeError(
            "No Trustline base URL configured. "
            "Set TRUSTLINE_API_URL, TRUSTLINE_BASE_URL, "
            "or RISK_ENGINE_URL."
        )

    if base.endswith("/validation"):
        return f"{base}/{_verify_chain_path()}"

    return f"{base}/{_validation_prefix()}/{_verify_chain_path()}"


def build_payload(request: VerificationInput) -> dict[str, Any]:
    """
    Build the same logical payload shape used by x402-secure.

    The Chain model is converted to the protocol's verifiableIntentChain
    representation without modifying the credential contents.
    """

    chain_dict = request.chain.to_dict()

    return {
        "verifiableIntentChain": chain_dict["verifiableIntentChain"],
        "paymentRequirements": request.payment.to_dict(),
        "policy": request.policy,
    }


def _normalize_response(
    response: dict[str, Any],
) -> NormalizedVerificationResult:
    """
    Normalize the Trustline VI-chain response.

    Trustline/x402-secure accepts either a top-level `vi` object or a
    top-level `chain` object.
    """

    vi = response.get("vi")

    if not isinstance(vi, dict):
        chain = response.get("chain")

        if isinstance(chain, dict):
            chain_verified = bool(chain.get("verified"))
            constraint_satisfied = chain.get("constraint_satisfied")
            error_code = chain.get("error_code")

            verified = (
                chain_verified
                and constraint_satisfied is not False
                and not error_code
            )

            vi = {
                "verified": verified,
                "chain_verified": chain_verified,
                "constraint_satisfied": constraint_satisfied,
                "error_code": error_code,
                "violations": chain.get("violations") or [],
            }
        else:
            vi = {}

    decision = str(
        response.get("decision", "review")
    ).strip().lower()

    if decision == "approve":
        decision = "allow"
    elif decision == "decline":
        decision = "deny"

    verified = vi.get("verified")
    chain_verified = vi.get("chain_verified")
    constraint_satisfied = vi.get("constraint_satisfied")

    reasons = list(response.get("reasons") or [])

    error_code = vi.get("error_code")

    if error_code and error_code not in reasons:
        reasons.append(str(error_code))

    for violation in vi.get("violations") or []:
        text = (
            violation
            if isinstance(violation, str)
            else str(violation)
        )
        if text not in reasons:
            reasons.append(text)

    return NormalizedVerificationResult(
        source="genuine_trustline_verifier",
        is_mock=False,
        decision=decision,
        verified=verified,
        chain_verified=chain_verified,
        constraint_satisfied=constraint_satisfied,
        payment_bound=(
            verified
            if verified is not None
            else None
        ),
        reasons=reasons,
        error_code=(
            str(error_code)
            if error_code is not None
            else None
        ),
        raw_result=response,
    )


class TrustlineVerifierAdapter(VerifierAdapter):
    """
    Adapter for the genuine Trustline verifier endpoint.

    It does not fall back to the Phase-A implementation.
    """

    source_name = "genuine_trustline_verifier"
    is_mock = False

    def __init__(self, timeout: float | None = None) -> None:
        self.timeout = timeout or float(
            os.getenv("TRUSTLINE_TIMEOUT_S", "15")
        )

    def verify(
        self,
        request: VerificationInput,
    ) -> NormalizedVerificationResult:

        try:
            url = build_url()
        except Exception as exc:
            return NormalizedVerificationResult(
                source=self.source_name,
                is_mock=False,
                decision="unavailable",
                reasons=[str(exc)],
                error_code="TRUSTLINE_CONFIGURATION_UNAVAILABLE",
                raw_result={
                    "status": "UNAVAILABLE",
                    "evidence_valid": False,
                },
            )

        payload = build_payload(request)

        token = _token()

        headers: dict[str, str] = {}

        if token:
            headers["Authorization"] = f"Bearer {token}"

        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.post(
                    url,
                    json=payload,
                    headers=headers,
                )

        except httpx.HTTPError as exc:
            return NormalizedVerificationResult(
                source=self.source_name,
                is_mock=False,
                decision="unavailable",
                reasons=[
                    f"Trustline verifier request failed: {exc}"
                ],
                error_code="TRUSTLINE_HTTP_UNAVAILABLE",
                raw_result={
                    "status": "UNAVAILABLE",
                    "url": url,
                    "evidence_valid": False,
                },
            )

        if response.status_code >= 400:
            return NormalizedVerificationResult(
                source=self.source_name,
                is_mock=False,
                decision="unavailable",
                reasons=[
                    f"Trustline verifier returned HTTP "
                    f"{response.status_code}"
                ],
                error_code="TRUSTLINE_HTTP_ERROR",
                raw_result={
                    "status": "UNAVAILABLE",
                    "http_status": response.status_code,
                    "url": url,
                    "body": response.text[:1000],
                    "evidence_valid": False,
                },
            )

        try:
            data = response.json()
        except ValueError as exc:
            return NormalizedVerificationResult(
                source=self.source_name,
                is_mock=False,
                decision="unavailable",
                reasons=[
                    f"Trustline returned invalid JSON: {exc}"
                ],
                error_code="TRUSTLINE_INVALID_RESPONSE",
                raw_result={
                    "status": "UNAVAILABLE",
                    "http_status": response.status_code,
                    "url": url,
                    "evidence_valid": False,
                },
            )

        if not isinstance(data, dict):
            return NormalizedVerificationResult(
                source=self.source_name,
                is_mock=False,
                decision="unavailable",
                reasons=[
                    "Trustline response is not a JSON object"
                ],
                error_code="TRUSTLINE_INVALID_RESPONSE",
                raw_result={
                    "status": "UNAVAILABLE",
                    "http_status": response.status_code,
                    "url": url,
                    "evidence_valid": False,
                },
            )

        return _normalize_response(data)
