"""
Adversarial test suite for the Verifiable Intent verifier.

Every negative test here follows the same shape as an SVA negative-testing
sequence: take a chain we know is otherwise valid, mutate exactly one thing,
and assert the verifier's decision is never "allow". A single test that
accidentally lets a broken chain through is worse than a missing test, so
each mutation targets one specific check in verify.py.
"""
from __future__ import annotations

import copy
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from vi_verify import crypto
from vi_verify.chain import build_l1, build_l2, build_l3, build_valid_chain, L1Terms, L2Terms
from vi_verify.crypto import generate_keypair
from vi_verify.models import Chain, Credential, PaymentRequirements
from vi_verify.replay_store import ReplayStore
from vi_verify.verify import VerifyContext, verify_chain


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def keys():
    return {
        "trustline": generate_keypair(),
        "owner": generate_keypair(),
        "agent": generate_keypair(),
        "foreign": generate_keypair(),  # an unrelated key, for substitution attacks
    }


@pytest.fixture()
def payment():
    return PaymentRequirements(
        invoice_id="inv-0001",
        chain_id="xrpl:mainnet",
        asset="RLUSD",
        amount="25.00",
        payee="rTrustline...merchant",
    )


@pytest.fixture()
def ctx(keys):
    return VerifyContext(trustline_public_key=keys["trustline"].public_key, replay_store=ReplayStore())


def _valid_chain(keys, payment):
    return build_valid_chain(
        keys["trustline"], keys["owner"], keys["agent"], payment,
        spend_ceiling="1000.0", per_tx_max="50.0",
    )


def _resign(private_key, payload):
    """Re-sign a (possibly mutated) payload so we're only testing ONE failure mode at a time."""
    return crypto.sign_es256(private_key, payload)


# ---------------------------------------------------------------------------
# Baseline: a correctly-built chain must be allowed (or reviewed if near ceiling)
# ---------------------------------------------------------------------------

def test_valid_chain_is_allowed(keys, payment, ctx):
    chain = _valid_chain(keys, payment)
    result = verify_chain(chain, payment, ctx)
    assert result.decision == "allow", result.reasons


def test_valid_chain_near_ceiling_is_reviewed(keys, ctx):
    payment = PaymentRequirements("inv-review", "xrpl:mainnet", "RLUSD", "95.00", "rMerchant")
    chain = build_valid_chain(
        keys["trustline"], keys["owner"], keys["agent"], payment,
        spend_ceiling="100.0", per_tx_max="100.0",
    )
    result = verify_chain(chain, payment, ctx)
    assert result.decision == "review", result.reasons


# ---------------------------------------------------------------------------
# Hash-binding tampering (L2 <- L1, L3 <- L2)
# ---------------------------------------------------------------------------

def test_tampered_l2_l1_hash_is_denied(keys, payment, ctx):
    chain = _valid_chain(keys, payment)
    l2_payload = copy.deepcopy(chain.l2.payload)
    l2_payload["l1Hash"] = "0" * 64  # break the hash binding to L1
    tampered_l2 = Credential(payload=l2_payload, signature=_resign(keys["owner"].private_key, l2_payload))
    chain = Chain(l1=chain.l1, l2=tampered_l2, l3=chain.l3)
    # l3 still binds to the ORIGINAL l2 hash, so this also breaks the l2->l3 link;
    # either failure is acceptable, we just must never allow.
    result = verify_chain(chain, payment, ctx)
    assert result.decision == "deny", result.reasons


def test_tampered_l3_l2_hash_is_denied(keys, payment, ctx):
    chain = _valid_chain(keys, payment)
    l3_payload = copy.deepcopy(chain.l3.payload)
    l3_payload["l2Hash"] = "f" * 64
    tampered_l3 = Credential(payload=l3_payload, signature=_resign(keys["agent"].private_key, l3_payload))
    chain = Chain(l1=chain.l1, l2=chain.l2, l3=tampered_l3)
    result = verify_chain(chain, payment, ctx)
    assert result.decision == "deny", result.reasons
    assert any("l2Hash" in r for r in result.reasons)


# ---------------------------------------------------------------------------
# Signature substitution -- someone else's valid signature on a real payload
# ---------------------------------------------------------------------------

def test_l2_signed_by_wrong_key_is_denied(keys, payment, ctx):
    chain = _valid_chain(keys, payment)
    l2_payload = copy.deepcopy(chain.l2.payload)
    forged_l2 = Credential(payload=l2_payload, signature=_resign(keys["foreign"].private_key, l2_payload))
    chain = Chain(l1=chain.l1, l2=forged_l2, l3=chain.l3)
    result = verify_chain(chain, payment, ctx)
    assert result.decision == "deny", result.reasons
    assert any("owner key" in r for r in result.reasons)


def test_l3_signed_by_wrong_key_is_denied(keys, payment, ctx):
    chain = _valid_chain(keys, payment)
    l3_payload = copy.deepcopy(chain.l3.payload)
    forged_l3 = Credential(payload=l3_payload, signature=_resign(keys["foreign"].private_key, l3_payload))
    chain = Chain(l1=chain.l1, l2=chain.l2, l3=forged_l3)
    result = verify_chain(chain, payment, ctx)
    assert result.decision == "deny", result.reasons
    assert any("agent key" in r for r in result.reasons)


# ---------------------------------------------------------------------------
# Scope escalation -- L2 must never grant more than L1 allowed
# ---------------------------------------------------------------------------

def test_l2_asset_escalation_is_denied(keys, payment, ctx):
    l1_terms = L1Terms(allowed_chains=["xrpl:mainnet"], allowed_assets=["RLUSD"], spend_ceiling="1000.0")
    l1 = build_l1(keys["trustline"], keys["owner"], l1_terms)
    l2_terms = L2Terms(allowed_chains=["xrpl:mainnet"], allowed_assets=["RLUSD", "XRP"], per_tx_max="50.0")
    l2 = build_l2(keys["owner"], keys["agent"], l1, l2_terms)  # smuggles in XRP, which L1 never granted
    l3 = build_l3(keys["agent"], l2, payment)
    chain = Chain(l1=l1, l2=l2, l3=l3)
    result = verify_chain(chain, payment, ctx)
    assert result.decision == "deny", result.reasons
    assert any("escalation" in r for r in result.reasons)


def test_l2_spend_escalation_is_denied(keys, payment, ctx):
    l1_terms = L1Terms(allowed_chains=["xrpl:mainnet"], allowed_assets=["RLUSD"], spend_ceiling="100.0")
    l1 = build_l1(keys["trustline"], keys["owner"], l1_terms)
    l2_terms = L2Terms(allowed_chains=["xrpl:mainnet"], allowed_assets=["RLUSD"], per_tx_max="500.0")
    l2 = build_l2(keys["owner"], keys["agent"], l1, l2_terms)  # per-tx max exceeds L1's ceiling
    l3 = build_l3(keys["agent"], l2, payment)
    chain = Chain(l1=l1, l2=l2, l3=l3)
    result = verify_chain(chain, payment, ctx)
    assert result.decision == "deny", result.reasons
    assert any("spendCeiling" in r for r in result.reasons)


def test_payment_amount_over_per_tx_max_is_denied(keys, ctx):
    payment = PaymentRequirements("inv-big", "xrpl:mainnet", "RLUSD", "999.00", "rMerchant")
    chain = build_valid_chain(
        keys["trustline"], keys["owner"], keys["agent"], payment,
        spend_ceiling="1000.0", per_tx_max="50.0",
    )
    # payment amount (999) exceeds L2 per_tx_max (50) even though it's under the L1 ceiling
    result = verify_chain(chain, payment, ctx)
    assert result.decision == "deny", result.reasons
    assert any("perTxMax" in r for r in result.reasons)


# ---------------------------------------------------------------------------
# Payment mismatch -- L3 must commit to exactly the payment being settled
# ---------------------------------------------------------------------------

def test_wrong_invoice_id_is_denied(keys, payment, ctx):
    chain = _valid_chain(keys, payment)
    other_payment = PaymentRequirements("inv-DIFFERENT", payment.chain_id, payment.asset, payment.amount, payment.payee)
    result = verify_chain(chain, other_payment, ctx)
    assert result.decision == "deny", result.reasons


def test_altered_payment_amount_after_signing_is_denied(keys, payment, ctx):
    chain = _valid_chain(keys, payment)
    tampered_payment = PaymentRequirements(
        payment.invoice_id, payment.chain_id, payment.asset, "1.00", payment.payee
    )  # amount changed after L3 was signed -> requirementsHash mismatch
    result = verify_chain(chain, tampered_payment, ctx)
    assert result.decision == "deny", result.reasons
    assert any("requirementsHash" in r for r in result.reasons)


# ---------------------------------------------------------------------------
# Expiry
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("layer", ["l1", "l2", "l3"])
def test_expired_layer_is_denied(keys, payment, ctx, layer):
    chain = _valid_chain(keys, payment)
    cred = getattr(chain, layer)
    payload = copy.deepcopy(cred.payload)
    payload["exp"] = int(time.time()) - 10  # already expired
    signer = {"l1": keys["trustline"], "l2": keys["owner"], "l3": keys["agent"]}[layer]
    expired_cred = Credential(payload=payload, signature=_resign(signer.private_key, payload))
    kwargs = {"l1": chain.l1, "l2": chain.l2, "l3": chain.l3}
    kwargs[layer] = expired_cred
    chain = Chain(**kwargs)
    result = verify_chain(chain, payment, ctx)
    assert result.decision == "deny", result.reasons


# ---------------------------------------------------------------------------
# Single-use / replay enforcement
# ---------------------------------------------------------------------------

def test_replayed_l3_jti_is_denied_on_second_use(keys, payment, ctx):
    chain = _valid_chain(keys, payment)
    first = verify_chain(chain, payment, ctx)
    assert first.decision in ("allow", "review"), first.reasons

    second = verify_chain(chain, payment, ctx)  # exact same chain, same jti, replayed
    assert second.decision == "deny", second.reasons
    assert any("replay" in r for r in second.reasons)

# ---------------------------------------------------------------------------
# Boundary and malformed authorization values
# ---------------------------------------------------------------------------

def test_expiry_exactly_at_current_time_is_denied(keys, payment):
    chain = _valid_chain(keys, payment)
    now = int(time.time())

    l3_payload = copy.deepcopy(chain.l3.payload)
    l3_payload["exp"] = now
    l3 = Credential(
        payload=l3_payload,
        signature=_resign(keys["agent"].private_key, l3_payload),
    )

    chain = Chain(l1=chain.l1, l2=chain.l2, l3=l3)
    ctx = VerifyContext(
        trustline_public_key=keys["trustline"].public_key,
        replay_store=ReplayStore(),
        clock=now,
    )

    result = verify_chain(chain, payment, ctx)

    assert result.decision == "deny", result.reasons
    assert any("expired" in r.lower() for r in result.reasons)


def test_negative_payment_amount_is_denied(keys, ctx):
    payment = PaymentRequirements(
        "inv-negative",
        "xrpl:mainnet",
        "RLUSD",
        "-1.00",
        "rMerchant",
    )

    chain = build_valid_chain(
        keys["trustline"],
        keys["owner"],
        keys["agent"],
        payment,
        spend_ceiling="1000.0",
        per_tx_max="50.0",
    )

    result = verify_chain(chain, payment, ctx)

    assert result.decision == "deny", result.reasons


@pytest.mark.parametrize("amount", ["NaN", "Infinity", "-Infinity"])
def test_non_finite_payment_amount_is_denied(keys, ctx, amount):
    payment = PaymentRequirements(
        "inv-nonfinite",
        "xrpl:mainnet",
        "RLUSD",
        amount,
        "rMerchant",
    )

    chain = build_valid_chain(
        keys["trustline"],
        keys["owner"],
        keys["agent"],
        payment,
        spend_ceiling="1000.0",
        per_tx_max="50.0",
    )

    result = verify_chain(chain, payment, ctx)

    assert result.decision == "deny", result.reasons


def test_negative_per_tx_max_is_denied(keys, payment, ctx):
    chain = _valid_chain(keys, payment)

    l2_payload = copy.deepcopy(chain.l2.payload)
    l2_payload["perTxMax"] = "-1.00"

    l2 = Credential(
        payload=l2_payload,
        signature=_resign(keys["owner"].private_key, l2_payload),
    )

    # L3 must bind to the mutated L2 so this test isolates perTxMax.
    l3_payload = copy.deepcopy(chain.l3.payload)
    l3_payload["l2Hash"] = crypto.hash_payload(l2_payload)
    l3 = Credential(
        payload=l3_payload,
        signature=_resign(keys["agent"].private_key, l3_payload),
    )

    chain = Chain(l1=chain.l1, l2=l2, l3=l3)

    result = verify_chain(chain, payment, ctx)

    assert result.decision == "deny", result.reasons


@pytest.mark.parametrize("jti", ["", None])
def test_missing_or_empty_l3_jti_is_denied(keys, payment, ctx, jti):
    chain = _valid_chain(keys, payment)

    l3_payload = copy.deepcopy(chain.l3.payload)
    l3_payload["jti"] = jti

    l3 = Credential(
        payload=l3_payload,
        signature=_resign(keys["agent"].private_key, l3_payload),
    )

    chain = Chain(l1=chain.l1, l2=chain.l2, l3=l3)

    result = verify_chain(chain, payment, ctx)

    assert result.decision == "deny", result.reasons

# ---------------------------------------------------------------------------
# Schema/type confusion
# ---------------------------------------------------------------------------

def test_allowed_chains_string_is_denied_not_iterated_as_characters(keys, payment, ctx):
    chain = _valid_chain(keys, payment)

    l2_payload = copy.deepcopy(chain.l2.payload)
    l2_payload["allowedChains"] = "xrpl:mainnet"

    l2 = Credential(
        payload=l2_payload,
        signature=_resign(keys["owner"].private_key, l2_payload),
    )

    l3_payload = copy.deepcopy(chain.l3.payload)
    l3_payload["l2Hash"] = crypto.hash_payload(l2_payload)
    l3 = Credential(
        payload=l3_payload,
        signature=_resign(keys["agent"].private_key, l3_payload),
    )

    mutated = Chain(l1=chain.l1, l2=l2, l3=l3)

    result = verify_chain(mutated, payment, ctx)

    assert result.decision == "deny", result.reasons


def test_allowed_assets_string_is_denied_not_iterated_as_characters(keys, payment, ctx):
    chain = _valid_chain(keys, payment)

    l2_payload = copy.deepcopy(chain.l2.payload)
    l2_payload["allowedAssets"] = "RLUSD"

    l2 = Credential(
        payload=l2_payload,
        signature=_resign(keys["owner"].private_key, l2_payload),
    )

    l3_payload = copy.deepcopy(chain.l3.payload)
    l3_payload["l2Hash"] = crypto.hash_payload(l2_payload)
    l3 = Credential(
        payload=l3_payload,
        signature=_resign(keys["agent"].private_key, l3_payload),
    )

    mutated = Chain(l1=chain.l1, l2=l2, l3=l3)

    result = verify_chain(mutated, payment, ctx)

    assert result.decision == "deny", result.reasons


@pytest.mark.parametrize("field", ["allowedChains", "allowedAssets"])
def test_none_scope_field_is_denied(keys, payment, ctx, field):
    chain = _valid_chain(keys, payment)

    l2_payload = copy.deepcopy(chain.l2.payload)
    l2_payload[field] = None

    l2 = Credential(
        payload=l2_payload,
        signature=_resign(keys["owner"].private_key, l2_payload),
    )

    l3_payload = copy.deepcopy(chain.l3.payload)
    l3_payload["l2Hash"] = crypto.hash_payload(l2_payload)
    l3 = Credential(
        payload=l3_payload,
        signature=_resign(keys["agent"].private_key, l3_payload),
    )

    mutated = Chain(l1=chain.l1, l2=l2, l3=l3)

    result = verify_chain(mutated, payment, ctx)

    assert result.decision == "deny", result.reasons


@pytest.mark.parametrize("field", ["spendCeiling", "perTxMax"])
@pytest.mark.parametrize("value", ["NaN", "Infinity", "-Infinity"])
def test_non_finite_authorization_limit_is_denied(keys, payment, ctx, field, value):
    chain = _valid_chain(keys, payment)

    l2_payload = copy.deepcopy(chain.l2.payload)
    if field == "perTxMax":
        l2_payload[field] = value
    else:
        l1_payload = copy.deepcopy(chain.l1.payload)
        l1_payload[field] = value
        l1 = Credential(
            payload=l1_payload,
            signature=_resign(keys["trustline"].private_key, l1_payload),
        )
    if field == "perTxMax":
        l1 = chain.l1

    l2 = Credential(
        payload=l2_payload,
        signature=_resign(keys["owner"].private_key, l2_payload),
    )

    l3_payload = copy.deepcopy(chain.l3.payload)
    l3_payload["l2Hash"] = crypto.hash_payload(l2_payload)
    l3 = Credential(
        payload=l3_payload,
        signature=_resign(keys["agent"].private_key, l3_payload),
    )

    mutated = Chain(l1=l1, l2=l2, l3=l3)

    result = verify_chain(mutated, payment, ctx)

    assert result.decision == "deny", result.reasons

# ---------------------------------------------------------------------------
# Semantic authorization boundaries
# ---------------------------------------------------------------------------

def test_empty_l2_allowed_chains_is_denied(keys, payment, ctx):
    chain = _valid_chain(keys, payment)

    l2_payload = copy.deepcopy(chain.l2.payload)
    l2_payload["allowedChains"] = []

    l2 = Credential(
        payload=l2_payload,
        signature=_resign(keys["owner"].private_key, l2_payload),
    )

    l3_payload = copy.deepcopy(chain.l3.payload)
    l3_payload["l2Hash"] = crypto.hash_payload(l2_payload)
    l3 = Credential(
        payload=l3_payload,
        signature=_resign(keys["agent"].private_key, l3_payload),
    )

    result = verify_chain(
        Chain(l1=chain.l1, l2=l2, l3=l3),
        payment,
        ctx,
    )

    assert result.decision == "deny", result.reasons


def test_empty_l2_allowed_assets_is_denied(keys, payment, ctx):
    chain = _valid_chain(keys, payment)

    l2_payload = copy.deepcopy(chain.l2.payload)
    l2_payload["allowedAssets"] = []

    l2 = Credential(
        payload=l2_payload,
        signature=_resign(keys["owner"].private_key, l2_payload),
    )

    l3_payload = copy.deepcopy(chain.l3.payload)
    l3_payload["l2Hash"] = crypto.hash_payload(l2_payload)
    l3 = Credential(
        payload=l3_payload,
        signature=_resign(keys["agent"].private_key, l3_payload),
    )

    result = verify_chain(
        Chain(l1=chain.l1, l2=l2, l3=l3),
        payment,
        ctx,
    )

    assert result.decision == "deny", result.reasons


def test_negative_l1_spend_ceiling_is_denied(keys, payment, ctx):
    chain = _valid_chain(keys, payment)

    l1_payload = copy.deepcopy(chain.l1.payload)
    l1_payload["spendCeiling"] = "-100.0"

    l1 = Credential(
        payload=l1_payload,
        signature=_resign(keys["trustline"].private_key, l1_payload),
    )

    l2_payload = copy.deepcopy(chain.l2.payload)
    l2_payload["l1Hash"] = crypto.hash_payload(l1_payload)

    l2 = Credential(
        payload=l2_payload,
        signature=_resign(keys["owner"].private_key, l2_payload),
    )

    l3_payload = copy.deepcopy(chain.l3.payload)
    l3_payload["l2Hash"] = crypto.hash_payload(l2_payload)

    l3 = Credential(
        payload=l3_payload,
        signature=_resign(keys["agent"].private_key, l3_payload),
    )

    result = verify_chain(
        Chain(l1=l1, l2=l2, l3=l3),
        payment,
        ctx,
    )

    assert result.decision == "deny", result.reasons


def test_zero_l1_spend_ceiling_is_denied(keys, payment, ctx):
    chain = _valid_chain(keys, payment)

    l1_payload = copy.deepcopy(chain.l1.payload)
    l1_payload["spendCeiling"] = "0"

    l1 = Credential(
        payload=l1_payload,
        signature=_resign(keys["trustline"].private_key, l1_payload),
    )

    l2_payload = copy.deepcopy(chain.l2.payload)
    l2_payload["l1Hash"] = crypto.hash_payload(l1_payload)

    l2 = Credential(
        payload=l2_payload,
        signature=_resign(keys["owner"].private_key, l2_payload),
    )

    l3_payload = copy.deepcopy(chain.l3.payload)
    l3_payload["l2Hash"] = crypto.hash_payload(l2_payload)

    l3 = Credential(
        payload=l3_payload,
        signature=_resign(keys["agent"].private_key, l3_payload),
    )

    result = verify_chain(
        Chain(l1=l1, l2=l2, l3=l3),
        payment,
        ctx,
    )

    assert result.decision == "deny", result.reasons


def test_zero_l2_per_tx_max_is_denied(keys, payment, ctx):
    chain = _valid_chain(keys, payment)

    l2_payload = copy.deepcopy(chain.l2.payload)
    l2_payload["perTxMax"] = "0"

    l2 = Credential(
        payload=l2_payload,
        signature=_resign(keys["owner"].private_key, l2_payload),
    )

    l3_payload = copy.deepcopy(chain.l3.payload)
    l3_payload["l2Hash"] = crypto.hash_payload(l2_payload)

    l3 = Credential(
        payload=l3_payload,
        signature=_resign(keys["agent"].private_key, l3_payload),
    )

    result = verify_chain(
        Chain(l1=chain.l1, l2=l2, l3=l3),
        payment,
        ctx,
    )

    assert result.decision == "deny", result.reasons

# ---------------------------------------------------------------------------
# Credential field type confusion
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("jti", [123, [], {}, False])
def test_non_string_l3_jti_is_denied(keys, payment, ctx, jti):
    chain = _valid_chain(keys, payment)

    l3_payload = copy.deepcopy(chain.l3.payload)
    l3_payload["jti"] = jti

    l3 = Credential(
        payload=l3_payload,
        signature=_resign(keys["agent"].private_key, l3_payload),
    )

    chain = Chain(l1=chain.l1, l2=chain.l2, l3=l3)

    result = verify_chain(chain, payment, ctx)

    assert result.decision == "deny", result.reasons


@pytest.mark.parametrize("field", ["l1Hash", "l2Hash"])
def test_non_string_hash_binding_is_denied(keys, payment, ctx, field):
    chain = _valid_chain(keys, payment)

    if field == "l1Hash":
        l2_payload = copy.deepcopy(chain.l2.payload)
        l2_payload[field] = None

        l2 = Credential(
            payload=l2_payload,
            signature=_resign(keys["owner"].private_key, l2_payload),
        )

        chain = Chain(l1=chain.l1, l2=l2, l3=chain.l3)

    else:
        l3_payload = copy.deepcopy(chain.l3.payload)
        l3_payload[field] = None

        l3 = Credential(
            payload=l3_payload,
            signature=_resign(keys["agent"].private_key, l3_payload),
        )

        chain = Chain(l1=chain.l1, l2=chain.l2, l3=l3)

    result = verify_chain(chain, payment, ctx)

    assert result.decision == "deny", result.reasons


def test_empty_owner_public_key_is_denied(keys, payment, ctx):
    chain = _valid_chain(keys, payment)

    l1_payload = copy.deepcopy(chain.l1.payload)
    l1_payload["ownerPubKey"] = ""

    l1 = Credential(
        payload=l1_payload,
        signature=_resign(keys["trustline"].private_key, l1_payload),
    )

    chain = Chain(l1=l1, l2=chain.l2, l3=chain.l3)

    result = verify_chain(chain, payment, ctx)

    assert result.decision == "deny", result.reasons


def test_empty_agent_public_key_is_denied(keys, payment, ctx):
    chain = _valid_chain(keys, payment)

    l2_payload = copy.deepcopy(chain.l2.payload)
    l2_payload["agentPubKey"] = ""

    l2 = Credential(
        payload=l2_payload,
        signature=_resign(keys["owner"].private_key, l2_payload),
    )

    chain = Chain(l1=chain.l1, l2=l2, l3=chain.l3)

    result = verify_chain(chain, payment, ctx)

    assert result.decision == "deny", result.reasons

# ---------------------------------------------------------------------------
# Hash-binding type and format confusion
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("bad_hash", [None, 123, [], {}, False, ""])
def test_malformed_l1_hash_binding_is_denied(keys, payment, ctx, bad_hash):
    chain = _valid_chain(keys, payment)

    l2_payload = copy.deepcopy(chain.l2.payload)
    l2_payload["l1Hash"] = bad_hash

    l2 = Credential(
        payload=l2_payload,
        signature=_resign(keys["owner"].private_key, l2_payload),
    )

    result = verify_chain(
        Chain(l1=chain.l1, l2=l2, l3=chain.l3),
        payment,
        ctx,
    )

    assert result.decision == "deny", result.reasons


@pytest.mark.parametrize("bad_hash", [None, 123, [], {}, False, ""])
def test_malformed_l2_hash_binding_is_denied(keys, payment, ctx, bad_hash):
    chain = _valid_chain(keys, payment)

    l3_payload = copy.deepcopy(chain.l3.payload)
    l3_payload["l2Hash"] = bad_hash

    l3 = Credential(
        payload=l3_payload,
        signature=_resign(keys["agent"].private_key, l3_payload),
    )

    result = verify_chain(
        Chain(l1=chain.l1, l2=chain.l2, l3=l3),
        payment,
        ctx,
    )

    assert result.decision == "deny", result.reasons


@pytest.mark.parametrize(
    "bad_hash",
    [
        "0" * 63,
        "0" * 65,
        "g" * 64,
        "A" * 64,
        "sha256:" + "0" * 64,
    ],
)
def test_malformed_l1_hash_format_is_denied(keys, payment, ctx, bad_hash):
    chain = _valid_chain(keys, payment)

    l2_payload = copy.deepcopy(chain.l2.payload)
    l2_payload["l1Hash"] = bad_hash

    l2 = Credential(
        payload=l2_payload,
        signature=_resign(keys["owner"].private_key, l2_payload),
    )

    result = verify_chain(
        Chain(l1=chain.l1, l2=l2, l3=chain.l3),
        payment,
        ctx,
    )

    assert result.decision == "deny", result.reasons


@pytest.mark.parametrize(
    "bad_hash",
    [
        "0" * 63,
        "0" * 65,
        "g" * 64,
        "A" * 64,
        "sha256:" + "0" * 64,
    ],
)
def test_malformed_l2_hash_format_is_denied(keys, payment, ctx, bad_hash):
    chain = _valid_chain(keys, payment)

    l3_payload = copy.deepcopy(chain.l3.payload)
    l3_payload["l2Hash"] = bad_hash

    l3 = Credential(
        payload=l3_payload,
        signature=_resign(keys["agent"].private_key, l3_payload),
    )

    result = verify_chain(
        Chain(l1=chain.l1, l2=chain.l2, l3=l3),
        payment,
        ctx,
    )

    assert result.decision == "deny", result.reasons

# ---------------------------------------------------------------------------
# Malformed external chain structure
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "bad_chain",
    [
        {},
        {"verifiableIntentChain": {}},
        {"verifiableIntentChain": None},
        {"verifiableIntentChain": []},
        {"verifiableIntentChain": {"l1Credential": {}}},
        {"verifiableIntentChain": {"l1Credential": None}},
        {"verifiableIntentChain": {"l1Credential": []}},
    ],
)
def test_malformed_chain_structure_does_not_verify(bad_chain):
    with pytest.raises((KeyError, TypeError, AttributeError)):
        Chain.from_dict(bad_chain)


@pytest.mark.parametrize(
    "bad_credential",
    [
        {},
        None,
        [],
        {"payload": {}},
        {"signature": "abc"},
        {"payload": [], "signature": "abc"},
        {"payload": {}, "signature": None},
    ],
)
def test_malformed_credential_structure_rejected(bad_credential):
    with pytest.raises((KeyError, TypeError, AttributeError)):
        Credential.from_dict(bad_credential)

# ---------------------------------------------------------------------------
# Malformed whole-chain structure
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "bad_chain",
    [
        None,
        [],
        "chain",
        {"verifiableIntentChain": None},
        {"verifiableIntentChain": []},
        {"verifiableIntentChain": "chain"},
        {"verifiableIntentChain": {}},
    ],
)
def test_malformed_chain_container_is_rejected(bad_chain):
    with pytest.raises((TypeError, KeyError)):
        Chain.from_dict(bad_chain)


@pytest.mark.parametrize("field", ["l1Credential", "l2Delegation", "l3FinalAction"])
def test_missing_chain_credential_is_rejected(field):
    valid = {
        "l1Credential": {
            "payload": {},
            "signature": "abc",
        },
        "l2Delegation": {
            "payload": {},
            "signature": "abc",
        },
        "l3FinalAction": {
            "payload": {},
            "signature": "abc",
        },
    }

    del valid[field]

    with pytest.raises(KeyError):
        Chain.from_dict({"verifiableIntentChain": valid})


@pytest.mark.parametrize("field", ["l1Credential", "l2Delegation", "l3FinalAction"])
def test_malformed_chain_credential_is_rejected(field):
    valid = {
        "l1Credential": {
            "payload": {},
            "signature": "abc",
        },
        "l2Delegation": {
            "payload": {},
            "signature": "abc",
        },
        "l3FinalAction": {
            "payload": {},
            "signature": "abc",
        },
    }

    valid[field] = None

    with pytest.raises(TypeError):
        Chain.from_dict({"verifiableIntentChain": valid})


def test_valid_chain_round_trips_through_dict(keys, payment):
    original = _valid_chain(keys, payment)

    restored = Chain.from_dict(original.to_dict())

    assert restored.to_dict() == original.to_dict()

# ---------------------------------------------------------------------------
# Signature decoding / representation boundary
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "bad_signature",
    [
        None,
        123,
        [],
        {},
        False,
        "",
        "not-base64!!!",
        "%%%%",
        "abc",
    ],
)
def test_malformed_l1_signature_is_denied_without_crashing(keys, payment, ctx, bad_signature):
    chain = _valid_chain(keys, payment)

    l1 = Credential(
        payload=chain.l1.payload,
        signature=bad_signature,
    )

    result = verify_chain(
        Chain(l1=l1, l2=chain.l2, l3=chain.l3),
        payment,
        ctx,
    )

    assert result.decision == "deny", result.reasons


@pytest.mark.parametrize(
    "bad_signature",
    [
        "A" * 10,
        "A" * 100,
        "0" * 86,
        "!" * 86,
    ],
)
def test_malformed_signature_lengths_are_denied(keys, payment, ctx, bad_signature):
    chain = _valid_chain(keys, payment)

    l1 = Credential(
        payload=chain.l1.payload,
        signature=bad_signature,
    )

    result = verify_chain(
        Chain(l1=l1, l2=chain.l2, l3=chain.l3),
        payment,
        ctx,
    )

    assert result.decision == "deny", result.reasons


def test_valid_signature_still_verifies_after_boundary_tests(keys, payment, ctx):
    chain = _valid_chain(keys, payment)

    assert crypto.verify_es256(
        keys["trustline"].public_key,
        chain.l1.payload,
        chain.l1.signature,
    )
# ---------------------------------------------------------------------------
# Temporal consistency / issuance-order attacks
# ---------------------------------------------------------------------------

def test_l1_iat_after_exp_is_denied(keys, payment, ctx):
    chain = _valid_chain(keys, payment)

    l1_payload = copy.deepcopy(chain.l1.payload)
    l1_payload["iat"] = l1_payload["exp"] + 1

    l1 = Credential(
        payload=l1_payload,
        signature=_resign(keys["trustline"].private_key, l1_payload),
    )

    result = verify_chain(
        Chain(l1=l1, l2=chain.l2, l3=chain.l3),
        payment,
        ctx,
    )

    assert result.decision == "deny", result.reasons


def test_l2_iat_after_exp_is_denied(keys, payment, ctx):
    chain = _valid_chain(keys, payment)

    l2_payload = copy.deepcopy(chain.l2.payload)
    l2_payload["iat"] = l2_payload["exp"] + 1

    l2 = Credential(
        payload=l2_payload,
        signature=_resign(keys["owner"].private_key, l2_payload),
    )

    result = verify_chain(
        Chain(l1=chain.l1, l2=l2, l3=chain.l3),
        payment,
        ctx,
    )

    assert result.decision == "deny", result.reasons


def test_l3_iat_after_exp_is_denied(keys, payment, ctx):
    chain = _valid_chain(keys, payment)

    l3_payload = copy.deepcopy(chain.l3.payload)
    l3_payload["iat"] = l3_payload["exp"] + 1

    l3 = Credential(
        payload=l3_payload,
        signature=_resign(keys["agent"].private_key, l3_payload),
    )

    result = verify_chain(
        Chain(l1=chain.l1, l2=chain.l2, l3=l3),
        payment,
        ctx,
    )

    assert result.decision == "deny", result.reasons


def test_non_integer_iat_is_denied(keys, payment, ctx):
    chain = _valid_chain(keys, payment)

    l3_payload = copy.deepcopy(chain.l3.payload)
    l3_payload["iat"] = "not-a-timestamp"

    l3 = Credential(
        payload=l3_payload,
        signature=_resign(keys["agent"].private_key, l3_payload),
    )

    result = verify_chain(
        Chain(l1=chain.l1, l2=chain.l2, l3=l3),
        payment,
        ctx,
    )

    assert result.decision == "deny", result.reasons


def test_l2_cannot_be_issued_before_l1(keys, payment, ctx):
    chain = _valid_chain(keys, payment)

    l2_payload = copy.deepcopy(chain.l2.payload)
    l2_payload["iat"] = chain.l1.payload["iat"] - 1

    l2 = Credential(
        payload=l2_payload,
        signature=_resign(keys["owner"].private_key, l2_payload),
    )

    l3_payload = copy.deepcopy(chain.l3.payload)
    l3_payload["l2Hash"] = crypto.hash_payload(l2_payload)

    l3 = Credential(
        payload=l3_payload,
        signature=_resign(keys["agent"].private_key, l3_payload),
    )

    result = verify_chain(
        Chain(l1=chain.l1, l2=l2, l3=l3),
        payment,
        ctx,
    )

    assert result.decision == "deny", result.reasons


def test_l3_cannot_be_issued_before_l2(keys, payment, ctx):
    chain = _valid_chain(keys, payment)

    l3_payload = copy.deepcopy(chain.l3.payload)
    l3_payload["iat"] = chain.l2.payload["iat"] - 1

    l3 = Credential(
        payload=l3_payload,
        signature=_resign(keys["agent"].private_key, l3_payload),
    )

    result = verify_chain(
        Chain(l1=chain.l1, l2=chain.l2, l3=l3),
        payment,
        ctx,
    )

    assert result.decision == "deny", result.reasons

# ---------------------------------------------------------------------------
# Required scalar field schema
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("field", ["sub", "ownerPubKey"])
def test_l1_required_identity_fields_must_be_non_empty_strings(keys, payment, ctx, field):
    chain = _valid_chain(keys, payment)

    l1_payload = copy.deepcopy(chain.l1.payload)
    l1_payload[field] = None

    l1 = Credential(
        payload=l1_payload,
        signature=_resign(keys["trustline"].private_key, l1_payload),
    )

    result = verify_chain(
        Chain(l1=l1, l2=chain.l2, l3=chain.l3),
        payment,
        ctx,
    )

    assert result.decision == "deny", result.reasons


@pytest.mark.parametrize("field", ["sub", "ownerPubKey"])
def test_l1_required_identity_fields_wrong_type_are_denied(keys, payment, ctx, field):
    chain = _valid_chain(keys, payment)

    l1_payload = copy.deepcopy(chain.l1.payload)
    l1_payload[field] = 123

    l1 = Credential(
        payload=l1_payload,
        signature=_resign(keys["trustline"].private_key, l1_payload),
    )

    result = verify_chain(
        Chain(l1=l1, l2=chain.l2, l3=chain.l3),
        payment,
        ctx,
    )

    assert result.decision == "deny", result.reasons


@pytest.mark.parametrize("field", ["iss", "agentPubKey"])
def test_l2_required_identity_fields_must_be_non_empty_strings(keys, payment, ctx, field):
    chain = _valid_chain(keys, payment)

    l2_payload = copy.deepcopy(chain.l2.payload)
    l2_payload[field] = None

    l2 = Credential(
        payload=l2_payload,
        signature=_resign(keys["owner"].private_key, l2_payload),
    )

    result = verify_chain(
        Chain(l1=chain.l1, l2=l2, l3=chain.l3),
        payment,
        ctx,
    )

    assert result.decision == "deny", result.reasons


@pytest.mark.parametrize("field", ["iss", "agentPubKey"])
def test_l2_required_identity_fields_wrong_type_are_denied(keys, payment, ctx, field):
    chain = _valid_chain(keys, payment)

    l2_payload = copy.deepcopy(chain.l2.payload)
    l2_payload[field] = []

    l2 = Credential(
        payload=l2_payload,
        signature=_resign(keys["owner"].private_key, l2_payload),
    )

    result = verify_chain(
        Chain(l1=chain.l1, l2=l2, l3=chain.l3),
        payment,
        ctx,
    )

    assert result.decision == "deny", result.reasons


@pytest.mark.parametrize("field", ["invoiceId", "requirementsHash"])
def test_l3_required_payment_fields_must_be_non_empty_strings(keys, payment, ctx, field):
    chain = _valid_chain(keys, payment)

    l3_payload = copy.deepcopy(chain.l3.payload)
    l3_payload[field] = None

    l3 = Credential(
        payload=l3_payload,
        signature=_resign(keys["agent"].private_key, l3_payload),
    )

    result = verify_chain(
        Chain(l1=chain.l1, l2=chain.l2, l3=l3),
        payment,
        ctx,
    )

    assert result.decision == "deny", result.reasons


@pytest.mark.parametrize("field", ["invoiceId", "requirementsHash"])
def test_l3_required_payment_fields_wrong_type_are_denied(keys, payment, ctx, field):
    chain = _valid_chain(keys, payment)

    l3_payload = copy.deepcopy(chain.l3.payload)
    l3_payload[field] = {}

    l3 = Credential(
        payload=l3_payload,
        signature=_resign(keys["agent"].private_key, l3_payload),
    )

    result = verify_chain(
        Chain(l1=chain.l1, l2=chain.l2, l3=l3),
        payment,
        ctx,
    )

    assert result.decision == "deny", result.reasons

# ---------------------------------------------------------------------------
# Identity binding
# ---------------------------------------------------------------------------

def test_l2_issuer_must_match_l1_subject(keys, payment, ctx):
    chain = _valid_chain(keys, payment)

    l2_payload = copy.deepcopy(chain.l2.payload)
    l2_payload["iss"] = "different-owner"

    l2 = Credential(
        payload=l2_payload,
        signature=_resign(keys["owner"].private_key, l2_payload),
    )

    l3_payload = copy.deepcopy(chain.l3.payload)
    l3_payload["l2Hash"] = crypto.hash_payload(l2_payload)

    l3 = Credential(
        payload=l3_payload,
        signature=_resign(keys["agent"].private_key, l3_payload),
    )

    result = verify_chain(
        Chain(l1=chain.l1, l2=l2, l3=l3),
        payment,
        ctx,
    )

    assert result.decision == "deny", result.reasons
    assert any("iss" in r.lower() for r in result.reasons)


def test_l1_subject_must_match_owner_public_key(keys, payment, ctx):
    chain = _valid_chain(keys, payment)

    l1_payload = copy.deepcopy(chain.l1.payload)
    l1_payload["sub"] = "not-the-owner-thumbprint"

    l1 = Credential(
        payload=l1_payload,
        signature=_resign(keys["trustline"].private_key, l1_payload),
    )

    result = verify_chain(
        Chain(l1=l1, l2=chain.l2, l3=chain.l3),
        payment,
        ctx,
    )

    assert result.decision == "deny", result.reasons
    assert any("sub" in r.lower() for r in result.reasons)


def test_l1_subject_cannot_be_bound_to_different_owner_key(keys, payment, ctx):
    chain = _valid_chain(keys, payment)

    l1_payload = copy.deepcopy(chain.l1.payload)
    l1_payload["ownerPubKey"] = crypto.public_key_to_pem(keys["foreign"].public_key)

    l1 = Credential(
        payload=l1_payload,
        signature=_resign(keys["trustline"].private_key, l1_payload),
    )

    result = verify_chain(
        Chain(l1=l1, l2=chain.l2, l3=chain.l3),
        payment,
        ctx,
    )

    assert result.decision == "deny", result.reasons
# ---------------------------------------------------------------------------
# Authorization limit semantic boundaries
# ---------------------------------------------------------------------------

def test_negative_spend_ceiling_is_denied(keys, payment, ctx):
    chain = _valid_chain(keys, payment)

    l1_payload = copy.deepcopy(chain.l1.payload)
    l1_payload["spendCeiling"] = "-1.00"

    l1 = Credential(
        payload=l1_payload,
        signature=_resign(keys["trustline"].private_key, l1_payload),
    )

    # Rebind L2 to the modified L1 so this test isolates spendCeiling.
    l2_payload = copy.deepcopy(chain.l2.payload)
    l2_payload["l1Hash"] = crypto.hash_payload(l1_payload)

    l2 = Credential(
        payload=l2_payload,
        signature=_resign(keys["owner"].private_key, l2_payload),
    )

    # Rebind L3 to the modified L2.
    l3_payload = copy.deepcopy(chain.l3.payload)
    l3_payload["l2Hash"] = crypto.hash_payload(l2_payload)

    l3 = Credential(
        payload=l3_payload,
        signature=_resign(keys["agent"].private_key, l3_payload),
    )

    result = verify_chain(
        Chain(l1=l1, l2=l2, l3=l3),
        payment,
        ctx,
    )

    assert result.decision == "deny", result.reasons


def test_zero_spend_ceiling_is_denied_for_positive_payment(keys, payment, ctx):
    chain = _valid_chain(keys, payment)

    l1_payload = copy.deepcopy(chain.l1.payload)
    l1_payload["spendCeiling"] = "0"

    l1 = Credential(
        payload=l1_payload,
        signature=_resign(keys["trustline"].private_key, l1_payload),
    )

    l2_payload = copy.deepcopy(chain.l2.payload)
    l2_payload["l1Hash"] = crypto.hash_payload(l1_payload)

    l2 = Credential(
        payload=l2_payload,
        signature=_resign(keys["owner"].private_key, l2_payload),
    )

    l3_payload = copy.deepcopy(chain.l3.payload)
    l3_payload["l2Hash"] = crypto.hash_payload(l2_payload)

    l3 = Credential(
        payload=l3_payload,
        signature=_resign(keys["agent"].private_key, l3_payload),
    )

    result = verify_chain(
        Chain(l1=l1, l2=l2, l3=l3),
        payment,
        ctx,
    )

    assert result.decision == "deny", result.reasons


def test_per_tx_max_equal_to_spend_ceiling_is_allowed(keys, payment, ctx):
    chain = build_valid_chain(
        keys["trustline"],
        keys["owner"],
        keys["agent"],
        payment,
        spend_ceiling="25.00",
        per_tx_max="25.00",
    )

    result = verify_chain(chain, payment, ctx)

    assert result.decision in ("allow", "review"), result.reasons


@pytest.mark.parametrize("field", ["spendCeiling", "perTxMax"])
@pytest.mark.parametrize("value", ["NaN", "Infinity", "-Infinity"])
def test_non_finite_authorization_limit_is_denied(keys, payment, ctx, field, value):
    chain = _valid_chain(keys, payment)

    if field == "spendCeiling":
        l1_payload = copy.deepcopy(chain.l1.payload)
        l1_payload[field] = value

        l1 = Credential(
            payload=l1_payload,
            signature=_resign(keys["trustline"].private_key, l1_payload),
        )

        l2_payload = copy.deepcopy(chain.l2.payload)
        l2_payload["l1Hash"] = crypto.hash_payload(l1_payload)

        l2 = Credential(
            payload=l2_payload,
            signature=_resign(keys["owner"].private_key, l2_payload),
        )

        l3_payload = copy.deepcopy(chain.l3.payload)
        l3_payload["l2Hash"] = crypto.hash_payload(l2_payload)

        l3 = Credential(
            payload=l3_payload,
            signature=_resign(keys["agent"].private_key, l3_payload),
        )

        chain = Chain(l1=l1, l2=l2, l3=l3)

    else:
        l2_payload = copy.deepcopy(chain.l2.payload)
        l2_payload[field] = value

        l2 = Credential(
            payload=l2_payload,
            signature=_resign(keys["owner"].private_key, l2_payload),
        )

        l3_payload = copy.deepcopy(chain.l3.payload)
        l3_payload["l2Hash"] = crypto.hash_payload(l2_payload)

        l3 = Credential(
            payload=l3_payload,
            signature=_resign(keys["agent"].private_key, l3_payload),
        )

        chain = Chain(l1=chain.l1, l2=l2, l3=l3)

    result = verify_chain(chain, payment, ctx)

    assert result.decision == "deny", result.reasons
