"""
Minimal ES256 (P-256 / ECDSA-SHA256) signing + canonical hashing helpers.

Verifiable Intent credentials (L1/L2/L3) are SD-JWT-family objects in the
real spec (https://verifiableintent.dev/). This module does not implement
full SD-JWT (selective disclosure, key-binding JWT framing, etc.) -- it
implements the *cryptographic shape* that matters for chain-of-trust
verification: each layer is a canonical JSON payload, signed with ES256,
and the next layer binds the previous one by hash. That's the part a
verifier actually has to get right, and the part this project stress-tests.
"""
from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.exceptions import InvalidSignature


def _is_p256_public_key(key: object) -> bool:
    return isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, ec.SECP256R1)


def public_key_thumbprint(public_key: ec.EllipticCurvePublicKey) -> str:
    """Return a short, stable identifier for a public key."""
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    return hashlib.sha256(raw).hexdigest()[:16]


@dataclass(frozen=True)
class KeyPair:
    private_key: ec.EllipticCurvePrivateKey
    public_key: ec.EllipticCurvePublicKey

    def public_jwk_thumbprint(self) -> str:
        """A short, stable identifier for the public key."""
        return public_key_thumbprint(self.public_key)


def generate_keypair() -> KeyPair:
    priv = ec.generate_private_key(ec.SECP256R1())
    return KeyPair(private_key=priv, public_key=priv.public_key())


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(data: str) -> bytes:
    if not isinstance(data, str):
        raise TypeError("base64url input must be a string")

    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def canonical_json(obj: dict) -> bytes:
    """Deterministic JSON serialization so both signer and verifier hash the same bytes."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_payload(payload: dict) -> str:
    return sha256_hex(canonical_json(payload))


def sign_es256(private_key: ec.EllipticCurvePrivateKey, payload: dict) -> str:
    """Sign a JSON payload, return a base64url ES256 signature (r||s, JOSE-style)."""
    message = canonical_json(payload)
    der_sig = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_sig)
    raw_sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return b64url(raw_sig)


def verify_es256(public_key: ec.EllipticCurvePublicKey, payload: dict, signature_b64url: str) -> bool:
    """Verify an ES256 signature over a JSON payload. Never raises on bad input -- returns False."""
    try:
        if not _is_p256_public_key(public_key):
            return False
        raw_sig = b64url_decode(signature_b64url)
        if len(raw_sig) != 64:
            return False
        r = int.from_bytes(raw_sig[:32], "big")
        s = int.from_bytes(raw_sig[32:], "big")
        der_sig = encode_dss_signature(r, s)
        message = canonical_json(payload)
        public_key.verify(der_sig, message, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, TypeError, ValueError):
        return False


def public_key_to_pem(public_key: ec.EllipticCurvePublicKey) -> str:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def public_key_from_pem(pem: str) -> ec.EllipticCurvePublicKey:
    key = serialization.load_pem_public_key(pem.encode("ascii"))
    if not _is_p256_public_key(key):
        raise ValueError("ES256 public key must use P-256 (secp256r1)")
    return key
