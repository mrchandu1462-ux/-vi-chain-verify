"""
Payload shapes for the Verifiable Intent L1 -> L2 -> L3 chain, modeled after
the public docs at https://xrpl-x402.t54.ai/docs/verifiable-intent and the
Mastercard Verifiable Intent standard (https://verifiableintent.dev/).

L1  Issuer credential   -- signed by Trustline
L2  Owner delegation    -- signed by the owner, binds L1 by hash
L3  Final action        -- signed by the agent, binds L2 by hash, single-use

A "Credential" here is: {"payload": {...}, "signature": "<b64url ES256 sig>"}.
That's the minimum shape a chain-of-trust verifier has to check correctly;
it intentionally does not implement full SD-JWT selective disclosure.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any


def now() -> int:
    return int(time.time())


def new_jti() -> str:
    return uuid.uuid4().hex


@dataclass
class PaymentRequirements:
    """The x402 payment being authorized -- what L3 must exactly match."""

    invoice_id: str
    chain_id: str
    asset: str
    amount: str  # decimal string, e.g. drops or RLUSD units
    payee: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "invoiceId": self.invoice_id,
            "chainId": self.chain_id,
            "asset": self.asset,
            "amount": self.amount,
            "payee": self.payee,
        }


@dataclass
class Credential:
    """A signed layer: payload + ES256 signature over the canonical payload."""

    payload: dict[str, Any]
    signature: str

    def to_dict(self) -> dict[str, Any]:
        return {"payload": self.payload, "signature": self.signature}

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "Credential":
        return Credential(payload=data["payload"], signature=data["signature"])


@dataclass
class Chain:
    """The assembled L1 -> L2 -> L3 chain, as it would ride in PAYMENT-SIGNATURE."""

    l1: Credential
    l2: Credential
    l3: Credential

    def to_dict(self) -> dict[str, Any]:
        return {
            "verifiableIntentChain": {
                "l1Credential": self.l1.to_dict(),
                "l2Delegation": self.l2.to_dict(),
                "l3FinalAction": self.l3.to_dict(),
            }
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "Chain":
        chain = data.get("verifiableIntentChain", data)
        return Chain(
            l1=Credential.from_dict(chain["l1Credential"]),
            l2=Credential.from_dict(chain["l2Delegation"]),
            l3=Credential.from_dict(chain["l3FinalAction"]),
        )


@dataclass
class VerificationResult:
    decision: str  # "allow" | "deny" | "review"
    reasons: list[str] = field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return self.decision == "allow"

    def to_dict(self) -> dict[str, Any]:
        return {"decision": self.decision, "reasons": self.reasons}
