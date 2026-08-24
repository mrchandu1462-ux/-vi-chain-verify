"""
Phase-B differential test corpus.

Every vector returns:
    (chain, payment, trustline_public_key)

The corpus is independent of Trustline. It only defines deterministic
security-relevant inputs for differential execution.
"""

from __future__ import annotations

import copy
import time
from dataclasses import dataclass
from typing import Callable

from vi_verify import crypto
from vi_verify.chain import (
    L1Terms,
    L2Terms,
    build_l1,
    build_l2,
    build_l3,
    build_valid_chain,
)
from vi_verify.crypto import KeyPair, generate_keypair
from vi_verify.models import Chain, Credential, PaymentRequirements


@dataclass
class TestVector:
    name: str
    description: str
    expected_reference_decision: str
    build: Callable[
        [],
        tuple[Chain, PaymentRequirements, object],
    ]


def _keys() -> dict[str, KeyPair]:
    return {
        "trustline": generate_keypair(),
        "owner": generate_keypair(),
        "agent": generate_keypair(),
        "foreign": generate_keypair(),
    }


def _payment() -> PaymentRequirements:
    return PaymentRequirements(
        invoice_id="inv-phase-b-001",
        chain_id="xrpl:mainnet",
        asset="RLUSD",
        amount="25.00",
        payee="rTrustline...merchant",
    )


def _valid(
    keys: dict[str, KeyPair],
    payment: PaymentRequirements,
) -> Chain:
    return build_valid_chain(
        keys["trustline"],
        keys["owner"],
        keys["agent"],
        payment,
        spend_ceiling="1000.0",
        per_tx_max="50.0",
    )


def _result(
    chain: Chain,
    payment: PaymentRequirements,
    keys: dict[str, KeyPair],
):
    return chain, payment, keys["trustline"].public_key


def _resign(key: KeyPair, payload: dict) -> str:
    return crypto.sign_es256(key.private_key, payload)


def valid_vector():
    keys = _keys()
    payment = _payment()
    return _result(_valid(keys, payment), payment, keys)


def l2_hash_tampered():
    keys = _keys()
    payment = _payment()
    chain = _valid(keys, payment)

    payload = copy.deepcopy(chain.l2.payload)
    payload["l1Hash"] = "0" * 64

    l2 = Credential(
        payload=payload,
        signature=_resign(keys["owner"], payload),
    )

    return _result(
        Chain(chain.l1, l2, chain.l3),
        payment,
        keys,
    )


def l3_hash_tampered():
    keys = _keys()
    payment = _payment()
    chain = _valid(keys, payment)

    payload = copy.deepcopy(chain.l3.payload)
    payload["l2Hash"] = "f" * 64

    l3 = Credential(
        payload=payload,
        signature=_resign(keys["agent"], payload),
    )

    return _result(
        Chain(chain.l1, chain.l2, l3),
        payment,
        keys,
    )


def l2_signature_tampered():
    keys = _keys()
    payment = _payment()
    chain = _valid(keys, payment)

    payload = copy.deepcopy(chain.l2.payload)

    l2 = Credential(
        payload=payload,
        signature=_resign(keys["foreign"], payload),
    )

    return _result(
        Chain(chain.l1, l2, chain.l3),
        payment,
        keys,
    )


def l3_signature_tampered():
    keys = _keys()
    payment = _payment()
    chain = _valid(keys, payment)

    payload = copy.deepcopy(chain.l3.payload)

    l3 = Credential(
        payload=payload,
        signature=_resign(keys["foreign"], payload),
    )

    return _result(
        Chain(chain.l1, chain.l2, l3),
        payment,
        keys,
    )


def scope_asset_escalation():
    keys = _keys()
    payment = _payment()

    l1 = build_l1(
        keys["trustline"],
        keys["owner"],
        L1Terms(
            allowed_chains=["xrpl:mainnet"],
            allowed_assets=["RLUSD"],
            spend_ceiling="1000.0",
        ),
    )

    l2 = build_l2(
        keys["owner"],
        keys["agent"],
        l1,
        L2Terms(
            allowed_chains=["xrpl:mainnet"],
            allowed_assets=["RLUSD", "XRP"],
            per_tx_max="50.0",
        ),
    )

    l3 = build_l3(keys["agent"], l2, payment)

    return _result(Chain(l1, l2, l3), payment, keys)


def scope_chain_escalation():
    keys = _keys()
    payment = _payment()

    l1 = build_l1(
        keys["trustline"],
        keys["owner"],
        L1Terms(
            allowed_chains=["xrpl:mainnet"],
            allowed_assets=["RLUSD"],
            spend_ceiling="1000.0",
        ),
    )

    l2 = build_l2(
        keys["owner"],
        keys["agent"],
        l1,
        L2Terms(
            allowed_chains=["xrpl:mainnet", "xrpl:testnet"],
            allowed_assets=["RLUSD"],
            per_tx_max="50.0",
        ),
    )

    l3 = build_l3(keys["agent"], l2, payment)

    return _result(Chain(l1, l2, l3), payment, keys)


def per_tx_limit_escalation():
    keys = _keys()
    payment = _payment()

    l1 = build_l1(
        keys["trustline"],
        keys["owner"],
        L1Terms(
            allowed_chains=["xrpl:mainnet"],
            allowed_assets=["RLUSD"],
            spend_ceiling="100.0",
        ),
    )

    l2 = build_l2(
        keys["owner"],
        keys["agent"],
        l1,
        L2Terms(
            allowed_chains=["xrpl:mainnet"],
            allowed_assets=["RLUSD"],
            per_tx_max="500.0",
        ),
    )

    l3 = build_l3(keys["agent"], l2, payment)

    return _result(Chain(l1, l2, l3), payment, keys)


def payment_amount_exceeded():
    keys = _keys()

    payment = PaymentRequirements(
        "inv-phase-b-big",
        "xrpl:mainnet",
        "RLUSD",
        "999.00",
        "rTrustline...merchant",
    )

    chain = build_valid_chain(
        keys["trustline"],
        keys["owner"],
        keys["agent"],
        payment,
        spend_ceiling="1000.0",
        per_tx_max="50.0",
    )

    return _result(chain, payment, keys)


def payment_chain_mismatch():
    keys = _keys()
    payment = _payment()
    chain = _valid(keys, payment)

    other = PaymentRequirements(
        payment.invoice_id,
        "xrpl:testnet",
        payment.asset,
        payment.amount,
        payment.payee,
    )

    return _result(chain, other, keys)


def payment_asset_mismatch():
    keys = _keys()
    payment = _payment()
    chain = _valid(keys, payment)

    other = PaymentRequirements(
        payment.invoice_id,
        payment.chain_id,
        "XRP",
        payment.amount,
        payment.payee,
    )

    return _result(chain, other, keys)


def payment_invoice_mismatch():
    keys = _keys()
    payment = _payment()
    chain = _valid(keys, payment)

    other = PaymentRequirements(
        "inv-phase-b-different",
        payment.chain_id,
        payment.asset,
        payment.amount,
        payment.payee,
    )

    return _result(chain, other, keys)


def payment_requirements_mismatch():
    keys = _keys()
    payment = _payment()
    chain = _valid(keys, payment)

    other = PaymentRequirements(
        payment.invoice_id,
        payment.chain_id,
        payment.asset,
        "1.00",
        payment.payee,
    )

    return _result(chain, other, keys)


def expired_l1():
    keys = _keys()
    payment = _payment()
    chain = _valid(keys, payment)

    payload = copy.deepcopy(chain.l1.payload)
    payload["exp"] = int(time.time()) - 10

    l1 = Credential(
        payload=payload,
        signature=_resign(keys["trustline"], payload),
    )

    return _result(Chain(l1, chain.l2, chain.l3), payment, keys)


def expired_l2():
    keys = _keys()
    payment = _payment()
    chain = _valid(keys, payment)

    payload = copy.deepcopy(chain.l2.payload)
    payload["exp"] = int(time.time()) - 10

    l2 = Credential(
        payload=payload,
        signature=_resign(keys["owner"], payload),
    )

    return _result(Chain(chain.l1, l2, chain.l3), payment, keys)


def expired_l3():
    keys = _keys()
    payment = _payment()
    chain = _valid(keys, payment)

    payload = copy.deepcopy(chain.l3.payload)
    payload["exp"] = int(time.time()) - 10

    l3 = Credential(
        payload=payload,
        signature=_resign(keys["agent"], payload),
    )

    return _result(Chain(chain.l1, chain.l2, l3), payment, keys)


VECTORS = [
    TestVector("valid", "Valid L1 -> L2 -> L3 chain", "allow", valid_vector),
    TestVector("l2_hash_tampered", "L2 l1Hash binding broken", "deny", l2_hash_tampered),
    TestVector("l3_hash_tampered", "L3 l2Hash binding broken", "deny", l3_hash_tampered),
    TestVector("l2_signature_tampered", "L2 signed by unrelated key", "deny", l2_signature_tampered),
    TestVector("l3_signature_tampered", "L3 signed by unrelated key", "deny", l3_signature_tampered),
    TestVector("scope_asset_escalation", "L2 grants asset outside L1", "deny", scope_asset_escalation),
    TestVector("scope_chain_escalation", "L2 grants chain outside L1", "deny", scope_chain_escalation),
    TestVector("per_tx_limit_escalation", "L2 perTxMax exceeds L1 ceiling", "deny", per_tx_limit_escalation),
    TestVector("payment_amount_exceeded", "Payment exceeds L2 perTxMax", "deny", payment_amount_exceeded),
    TestVector("payment_chain_mismatch", "Payment chain mismatch", "deny", payment_chain_mismatch),
    TestVector("payment_asset_mismatch", "Payment asset mismatch", "deny", payment_asset_mismatch),
    TestVector("payment_invoice_mismatch", "Payment invoice mismatch", "deny", payment_invoice_mismatch),
    TestVector("payment_requirements_mismatch", "Payment requirements changed", "deny", payment_requirements_mismatch),
    TestVector("expired_l1", "L1 expired", "deny", expired_l1),
    TestVector("expired_l2", "L2 expired", "deny", expired_l2),
    TestVector("expired_l3", "L3 expired", "deny", expired_l3),
]


def get_vectors() -> list[TestVector]:
    return list(VECTORS)
