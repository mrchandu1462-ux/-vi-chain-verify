"""
Builds a Verifiable Intent L1 -> L2 -> L3 chain.

This mirrors docs section "Who holds which key":
  - Trustline (issuer) signs L1 over the owner's pubkey + limits.
  - The owner signs L2, delegating to an agent key under narrower constraints,
    binding L1 by hash.
  - The agent signs L3, committing to one exact payment, binding L2 by hash.

Each build_* function is deliberately "dumb" -- it does not re-check business
rules (that's verify.py's job). This keeps the adversarial test suite honest:
we can build intentionally-invalid chains here to prove the verifier catches
them, the same way a UVM sequence can drive illegal transactions to prove an
assertion fires.
"""
from __future__ import annotations

from dataclasses import dataclass

from . import crypto
from .crypto import KeyPair
from .models import Credential, Chain, PaymentRequirements, new_jti, now


@dataclass
class L1Terms:
    allowed_chains: list[str]
    allowed_assets: list[str]
    spend_ceiling: str  # max cumulative / per-credential ceiling, decimal string
    ttl_seconds: int = 3600


@dataclass
class L2Terms:
    allowed_chains: list[str]
    allowed_assets: list[str]
    per_tx_max: str
    ttl_seconds: int = 900


def build_l1(trustline_key: KeyPair, owner_key: KeyPair, terms: L1Terms) -> Credential:
    payload = {
        "type": "vi-l1",
        "iss": "trustline",
        "sub": owner_key.public_jwk_thumbprint(),
        "ownerPubKey": crypto.public_key_to_pem(owner_key.public_key),
        "allowedChains": terms.allowed_chains,
        "allowedAssets": terms.allowed_assets,
        "spendCeiling": terms.spend_ceiling,
        "iat": now(),
        "exp": now() + terms.ttl_seconds,
        "jti": new_jti(),
    }
    signature = crypto.sign_es256(trustline_key.private_key, payload)
    return Credential(payload=payload, signature=signature)


def build_l2(owner_key: KeyPair, agent_key: KeyPair, l1: Credential, terms: L2Terms) -> Credential:
    payload = {
        "type": "vi-l2",
        "iss": l1.payload["sub"],  # owner, identified by their L1-bound key thumbprint
        "agentPubKey": crypto.public_key_to_pem(agent_key.public_key),
        "l1Hash": crypto.hash_payload(l1.payload),
        "allowedChains": terms.allowed_chains,
        "allowedAssets": terms.allowed_assets,
        "perTxMax": terms.per_tx_max,
        "iat": now(),
        "exp": now() + terms.ttl_seconds,
        "jti": new_jti(),
    }
    signature = crypto.sign_es256(owner_key.private_key, payload)
    return Credential(payload=payload, signature=signature)


def build_l3(
    agent_key: KeyPair,
    l2: Credential,
    payment: PaymentRequirements,
    ttl_seconds: int = 120,
) -> Credential:
    payload = {
        "type": "vi-l3",
        "l2Hash": crypto.hash_payload(l2.payload),
        "invoiceId": payment.invoice_id,
        "requirementsHash": crypto.hash_payload(payment.to_dict()),
        "iat": now(),
        "exp": now() + ttl_seconds,
        "jti": new_jti(),  # single-use token for this exact payment
    }
    signature = crypto.sign_es256(agent_key.private_key, payload)
    return Credential(payload=payload, signature=signature)


def build_valid_chain(
    trustline_key: KeyPair,
    owner_key: KeyPair,
    agent_key: KeyPair,
    payment: PaymentRequirements,
    *,
    spend_ceiling: str = "1000.0",
    per_tx_max: str = "50.0",
) -> Chain:
    """Convenience: builds a fully-valid, internally-consistent chain for `payment`."""
    l1_terms = L1Terms(
        allowed_chains=[payment.chain_id],
        allowed_assets=[payment.asset],
        spend_ceiling=spend_ceiling,
    )
    l1 = build_l1(trustline_key, owner_key, l1_terms)

    l2_terms = L2Terms(
        allowed_chains=[payment.chain_id],
        allowed_assets=[payment.asset],
        per_tx_max=per_tx_max,
    )
    l2 = build_l2(owner_key, agent_key, l1, l2_terms)

    l3 = build_l3(agent_key, l2, payment)

    return Chain(l1=l1, l2=l2, l3=l3)
