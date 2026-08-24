"""
Property-based fuzz test: take a valid chain, flip a random field or byte
in one of the signatures, and assert the verifier NEVER allows it.

This is the constrained-random-with-a-checker half of the suite -- the
targeted tests in test_adversarial.py prove specific checks work; this one
throws noise at the whole chain and checks the invariant that actually
matters: a mutated chain must never be accepted as authentic.
"""
from __future__ import annotations

import copy
import sys
from pathlib import Path

from hypothesis import given, settings, strategies as st

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from vi_verify.chain import build_valid_chain
from vi_verify.crypto import generate_keypair, b64url, b64url_decode
from vi_verify.models import Chain, Credential, PaymentRequirements
from vi_verify.replay_store import ReplayStore
from vi_verify.verify import VerifyContext, verify_chain


TRUSTLINE = generate_keypair()
OWNER = generate_keypair()
AGENT = generate_keypair()
PAYMENT = PaymentRequirements("inv-fuzz", "xrpl:mainnet", "RLUSD", "10.00", "rMerchant")


def _fresh_valid_chain() -> Chain:
    return build_valid_chain(TRUSTLINE, OWNER, AGENT, PAYMENT, spend_ceiling="1000.0", per_tx_max="50.0")


LAYER_NAMES = ("l1", "l2", "l3")


@given(
    layer=st.sampled_from(LAYER_NAMES),
    byte_index=st.integers(min_value=0, max_value=63),
    flip_mask=st.integers(min_value=1, max_value=255),
)
@settings(max_examples=200, deadline=None)
def test_random_signature_byte_flip_is_never_allowed(layer, byte_index, flip_mask):
    chain = _fresh_valid_chain()
    cred: Credential = getattr(chain, layer)

    raw_sig = bytearray(b64url_decode(cred.signature))
    raw_sig[byte_index % len(raw_sig)] ^= flip_mask
    mutated_sig = b64url(bytes(raw_sig))

    mutated_cred = Credential(payload=cred.payload, signature=mutated_sig)
    kwargs = {"l1": chain.l1, "l2": chain.l2, "l3": chain.l3}
    kwargs[layer] = mutated_cred
    mutated_chain = Chain(**kwargs)

    ctx = VerifyContext(trustline_public_key=TRUSTLINE.public_key, replay_store=ReplayStore())
    result = verify_chain(mutated_chain, PAYMENT, ctx)

    # A single flipped signature byte must never still verify as authentic.
    assert result.decision == "deny", (layer, byte_index, flip_mask, result.reasons)


@given(
    layer=st.sampled_from(LAYER_NAMES),
    field_name=st.sampled_from(["exp", "iat", "jti"]),
    delta=st.integers(min_value=-10_000, max_value=10_000).filter(lambda x: x != 0),
)
@settings(max_examples=100, deadline=None)
def test_random_numeric_field_tamper_without_resign_is_never_allowed(layer, field_name, delta):
    """Mutate a payload field but keep the OLD signature (attacker doesn't have the key)."""
    chain = _fresh_valid_chain()
    cred: Credential = getattr(chain, layer)

    if field_name not in cred.payload or not isinstance(cred.payload[field_name], int):
        return  # e.g. jti is a string; skip incompatible combinations

    tampered_payload = copy.deepcopy(cred.payload)
    tampered_payload[field_name] = tampered_payload[field_name] + delta
    # keep the original signature -- it no longer matches the payload
    tampered_cred = Credential(payload=tampered_payload, signature=cred.signature)

    kwargs = {"l1": chain.l1, "l2": chain.l2, "l3": chain.l3}
    kwargs[layer] = tampered_cred
    mutated_chain = Chain(**kwargs)

    ctx = VerifyContext(trustline_public_key=TRUSTLINE.public_key, replay_store=ReplayStore())
    result = verify_chain(mutated_chain, PAYMENT, ctx)

    assert result.decision == "deny", (layer, field_name, delta, result.reasons)
