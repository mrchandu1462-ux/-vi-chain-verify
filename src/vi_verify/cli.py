"""
Minimal CLI so the verifier is demo-able, not just testable.

    vi-verify demo                 build a valid chain + payment, verify it, print the decision
    vi-verify demo --tamper l3hash  build a chain, break one binding, print the (denied) decision
"""
from __future__ import annotations

import argparse
import json
import sys

from .chain import build_valid_chain
from .crypto import generate_keypair
from .models import Chain, Credential, PaymentRequirements
from .replay_store import ReplayStore
from .verify import VerifyContext, verify_chain


TAMPER_CHOICES = ["none", "l2hash", "l3hash", "replay"]


def _build_demo_chain(payment: PaymentRequirements):
    trustline = generate_keypair()
    owner = generate_keypair()
    agent = generate_keypair()
    chain = build_valid_chain(trustline, owner, agent, payment, spend_ceiling="1000.0", per_tx_max="50.0")
    return trustline, chain


def _apply_tamper(chain: Chain, mode: str) -> Chain:
    if mode == "l2hash":
        payload = dict(chain.l2.payload)
        payload["l1Hash"] = "0" * 64
        return Chain(l1=chain.l1, l2=Credential(payload=payload, signature=chain.l2.signature), l3=chain.l3)
    if mode == "l3hash":
        payload = dict(chain.l3.payload)
        payload["l2Hash"] = "f" * 64
        return Chain(l1=chain.l1, l2=chain.l2, l3=Credential(payload=payload, signature=chain.l3.signature))
    return chain


def cmd_demo(args: argparse.Namespace) -> int:
    payment = PaymentRequirements(
        invoice_id="inv-demo-0001",
        chain_id="xrpl:mainnet",
        asset="RLUSD",
        amount="25.00",
        payee="rDemoMerchant",
    )
    trustline, chain = _build_demo_chain(payment)
    chain = _apply_tamper(chain, args.tamper)

    ctx = VerifyContext(trustline_public_key=trustline.public_key, replay_store=ReplayStore())
    result = verify_chain(chain, payment, ctx)

    if args.tamper == "replay":
        verify_chain(chain, payment, ctx)  # consume the jti once
        result = verify_chain(chain, payment, ctx)  # replay it

    print(json.dumps({"tamper": args.tamper, **result.to_dict()}, indent=2))
    return 0 if result.decision != "allow" or args.tamper == "none" else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="vi-verify")
    sub = parser.add_subparsers(dest="command", required=True)

    demo = sub.add_parser("demo", help="build a demo chain and verify it")
    demo.add_argument("--tamper", choices=TAMPER_CHOICES, default="none")
    demo.set_defaults(func=cmd_demo)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
