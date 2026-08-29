"""Focused regression tests for atomic JTI consumption."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from vi_verify.replay_store import ReplayStore


def test_first_claim_succeeds():
    assert ReplayStore().claim("jti-1")


def test_second_claim_fails():
    store = ReplayStore()

    assert store.claim("jti-1")
    assert not store.claim("jti-1")


def test_concurrent_claims_have_exactly_one_winner():
    store = ReplayStore()

    with ThreadPoolExecutor(max_workers=16) as executor:
        claims = list(executor.map(store.claim, ["jti-1"] * 64))

    assert sum(claims) == 1
