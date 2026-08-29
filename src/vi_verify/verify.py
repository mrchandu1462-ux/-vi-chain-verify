"""
Verifies a Verifiable Intent L1 -> L2 -> L3 chain against a payment.

This is the part of the system that has to be paranoid. Every check below is
written as an independent assertion -- like an SVA property in a hardware
testbench -- and a single failing assertion is enough to DENY. Nothing here
trusts anything it hasn't independently checked: not the hash bindings, not
the constraint narrowing between layers, not the expiry, not the reuse of a
single-use token.

Decision model (mirrors the docs' "allow / deny / review"):
  - allow:  every structural, cryptographic, and business-rule check passes.
  - deny:   at least one check fails outright (bad signature, broken hash
            chain, replay, expired, scope escalation, mismatched payment).
  - review: chain is structurally and cryptographically valid, but crosses a
            soft threshold worth a human/second-system look (e.g. spend
            within 90-100% of the L1 ceiling). Real Trustline risk decisions
            fold in far more signal than this; this is a deliberately
            conservative stand-in so "review" isn't just unused.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation

from . import crypto
from .models import Chain, PaymentRequirements, VerificationResult
from .replay_store import ReplayStore


REVIEW_THRESHOLD_FRACTION = Decimal("0.9")  # spend >= 90% of L1 ceiling -> review


@dataclass
class VerifyContext:
    trustline_public_key: "crypto.ec.EllipticCurvePublicKey"
    replay_store: ReplayStore = field(default_factory=ReplayStore)
    clock: int | None = None  # override "now" for deterministic tests

    def now(self) -> int:
        import time

        return self.clock if self.clock is not None else int(time.time())


def _decimal(value: str) -> Decimal | None:
    try:
        result = Decimal(value)
    except (InvalidOperation, TypeError, ValueError):
        return None

    if not result.is_finite():
        return None

    return result


def verify_chain(chain: Chain, payment: PaymentRequirements, ctx: VerifyContext) -> VerificationResult:
    reasons: list[str] = []

    # --- L1: issuer credential, signed by Trustline ---
    if chain.l1.payload.get("type") != "vi-l1":
        reasons.append("L1: wrong credential type")
    if not crypto.verify_es256(ctx.trustline_public_key, chain.l1.payload, chain.l1.signature):
        reasons.append("L1: signature does not verify against Trustline issuer key")
    l1_iat = chain.l1.payload.get("iat")
    l1_exp = chain.l1.payload.get("exp")

    if not isinstance(l1_iat, int):
        reasons.append("L1: iat must be an integer")
    if not isinstance(l1_exp, int) or l1_exp <= ctx.now():
        reasons.append("L1: expired")
    if isinstance(l1_iat, int) and isinstance(l1_exp, int) and l1_iat > l1_exp:
        reasons.append("L1: iat must not be after exp")

    if reasons:
        return VerificationResult(decision="deny", reasons=reasons)

    owner_pubkey_pem = chain.l1.payload.get("ownerPubKey", "")
    try:
        owner_pubkey = crypto.public_key_from_pem(owner_pubkey_pem)
    except Exception:
        return VerificationResult(decision="deny", reasons=["L1: unparseable ownerPubKey"])

    if chain.l1.payload.get("sub") != crypto.public_key_thumbprint(owner_pubkey):
        return VerificationResult(
            decision="deny",
            reasons=["L1: sub does not match the owner public key thumbprint"],
        )

    # --- L2: owner delegation, must be signed by the *L1-bound* owner key ---
    if chain.l2.payload.get("type") != "vi-l2":
        reasons.append("L2: wrong credential type")
    if chain.l2.payload.get("iss") != chain.l1.payload.get("sub"):
        reasons.append("L2: iss does not match L1 sub")
    if not crypto.verify_es256(owner_pubkey, chain.l2.payload, chain.l2.signature):
        reasons.append("L2: signature does not verify against the owner key bound in L1")
    if chain.l2.payload.get("l1Hash") != crypto.hash_payload(chain.l1.payload):
        reasons.append("L2: l1Hash does not match the actual L1 credential (hash-binding broken)")
    l2_iat = chain.l2.payload.get("iat")
    l2_exp = chain.l2.payload.get("exp")

    if not isinstance(l2_iat, int):
        reasons.append("L2: iat must be an integer")
    if not isinstance(l2_exp, int) or l2_exp <= ctx.now():
        reasons.append("L2: expired")
    if isinstance(l2_iat, int) and isinstance(l2_exp, int) and l2_iat > l2_exp:
        reasons.append("L2: iat must not be after exp")
    if isinstance(l1_iat, int) and isinstance(l2_iat, int) and l2_iat < l1_iat:
        reasons.append("L2: iat cannot be before L1 iat")

    if reasons:
        return VerificationResult(decision="deny", reasons=reasons)

    # --- L2 scope must not exceed what L1 actually granted (no privilege escalation) ---
    l1_allowed_chains = chain.l1.payload.get("allowedChains")
    l1_allowed_assets = chain.l1.payload.get("allowedAssets")
    l2_allowed_chains = chain.l2.payload.get("allowedChains")
    l2_allowed_assets = chain.l2.payload.get("allowedAssets")

    if not isinstance(l1_allowed_chains, list):
        reasons.append("L1: allowedChains must be a list")
    if not isinstance(l1_allowed_assets, list):
        reasons.append("L1: allowedAssets must be a list")
    if not isinstance(l2_allowed_chains, list):
        reasons.append("L2: allowedChains must be a list")
    if not isinstance(l2_allowed_assets, list):
        reasons.append("L2: allowedAssets must be a list")

    if reasons:
        return VerificationResult(decision="deny", reasons=reasons)

    for name, values in (
        ("L1: allowedChains", l1_allowed_chains),
        ("L1: allowedAssets", l1_allowed_assets),
        ("L2: allowedChains", l2_allowed_chains),
        ("L2: allowedAssets", l2_allowed_assets),
    ):
        if any(not isinstance(value, str) or not value for value in values):
            reasons.append(f"{name} must contain only non-empty strings")

    if reasons:
        return VerificationResult(decision="deny", reasons=reasons)

    l1_chains = set(l1_allowed_chains)
    l1_assets = set(l1_allowed_assets)
    l2_chains = set(l2_allowed_chains)
    l2_assets = set(l2_allowed_assets)
    if not l2_chains.issubset(l1_chains):
        reasons.append("L2: allowedChains is not a subset of L1's allowedChains (scope escalation)")
    if not l2_assets.issubset(l1_assets):
        reasons.append("L2: allowedAssets is not a subset of L1's allowedAssets (scope escalation)")

    l1_ceiling = _decimal(chain.l1.payload.get("spendCeiling", ""))
    per_tx_max = _decimal(chain.l2.payload.get("perTxMax", ""))
    if l1_ceiling is None:
        reasons.append("L1: spendCeiling is not a valid decimal")
    if per_tx_max is None:
        reasons.append("L2: perTxMax is not a valid decimal")
    if l1_ceiling is not None and per_tx_max is not None and per_tx_max > l1_ceiling:
        reasons.append("L2: perTxMax exceeds L1 spendCeiling (scope escalation)")

    if reasons:
        return VerificationResult(decision="deny", reasons=reasons)

    agent_pubkey_pem = chain.l2.payload.get("agentPubKey", "")
    try:
        agent_pubkey = crypto.public_key_from_pem(agent_pubkey_pem)
    except Exception:
        return VerificationResult(decision="deny", reasons=["L2: unparseable agentPubKey"])

    # --- L3: final action, must be signed by the *L2-bound* agent key ---
    if chain.l3.payload.get("type") != "vi-l3":
        reasons.append("L3: wrong credential type")
    if not crypto.verify_es256(agent_pubkey, chain.l3.payload, chain.l3.signature):
        reasons.append("L3: signature does not verify against the agent key bound in L2")
    if chain.l3.payload.get("l2Hash") != crypto.hash_payload(chain.l2.payload):
        reasons.append("L3: l2Hash does not match the actual L2 credential (hash-binding broken)")
    l3_iat = chain.l3.payload.get("iat")
    l3_exp = chain.l3.payload.get("exp")

    if not isinstance(l3_iat, int):
        reasons.append("L3: iat must be an integer")
    if not isinstance(l3_exp, int) or l3_exp <= ctx.now():
        reasons.append("L3: expired")
    if isinstance(l3_iat, int) and isinstance(l3_exp, int) and l3_iat > l3_exp:
        reasons.append("L3: iat must not be after exp")
    if isinstance(l2_iat, int) and isinstance(l3_iat, int) and l3_iat < l2_iat:
        reasons.append("L3: iat cannot be before L2 iat")

    if reasons:
        return VerificationResult(decision="deny", reasons=reasons)

    # --- L3 must commit to exactly this payment ---
    if chain.l3.payload.get("invoiceId") != payment.invoice_id:
        reasons.append("L3: invoiceId does not match the payment being settled")
    if chain.l3.payload.get("requirementsHash") != crypto.hash_payload(payment.to_dict()):
        reasons.append("L3: requirementsHash does not match the actual payment requirements")

    # --- payment must fall within the L2 (and transitively L1) grant ---
    if payment.chain_id not in l2_chains:
        reasons.append("Payment: chainId not covered by L2 delegation")
    if payment.asset not in l2_assets:
        reasons.append("Payment: asset not covered by L2 delegation")
    amount = _decimal(payment.amount)
    if amount is None:
        reasons.append("Payment: amount is not a valid finite decimal")
    elif amount < 0:
        reasons.append("Payment: amount cannot be negative")
    elif per_tx_max is not None and amount > per_tx_max:
        reasons.append("Payment: amount exceeds L2 perTxMax")

    if reasons:
        return VerificationResult(decision="deny", reasons=reasons)

    # --- single-use enforcement: an L3 jti must never be seen twice ---
    jti = chain.l3.payload.get("jti")
    if not isinstance(jti, str) or not jti:
        return VerificationResult(
            decision="deny",
            reasons=["L3: jti must be a non-empty string"],
        )

    if not ctx.replay_store.claim(jti):
        return VerificationResult(
            decision="deny",
            reasons=["L3: jti already used (replay)"],
        )

    # --- soft risk signal: spend close to the L1 ceiling gets a second look ---
    if amount is not None and l1_ceiling is not None and l1_ceiling > 0:
        if amount >= l1_ceiling * REVIEW_THRESHOLD_FRACTION:
            return VerificationResult(
                decision="review",
                reasons=[f"Payment amount is >= {REVIEW_THRESHOLD_FRACTION:.0%} of the L1 spend ceiling"],
            )

    return VerificationResult(decision="allow", reasons=[])
