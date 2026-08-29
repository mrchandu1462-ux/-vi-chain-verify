"""
Tracks L3 `jti` values and cumulative spend per L1 credential.

An in-memory set is enough for this project's purposes (a single verifier
process / a single test run). A production facilitator would back this with
a database or distributed cache keyed by jti and L1 credential hash, with
TTLs past the respective credential expiries.
"""
from __future__ import annotations

from decimal import Decimal
from enum import Enum, auto
from threading import Lock


class ClaimResult(Enum):
    CLAIMED = auto()
    REPLAYED = auto()
    SPEND_CEILING_EXCEEDED = auto()


class ReplayStore:
    def __init__(self) -> None:
        self._seen: set[str] = set()
        self._spent: dict[str, Decimal] = {}
        self._lock = Lock()

    def claim(self, jti: str) -> bool:
        """Atomically consume `jti`, returning True only for its first claim.

        Production backends should implement the same operation with an atomic
        conditional insert (for example, Redis SET NX or a unique DB key).
        """
        with self._lock:
            if jti in self._seen:
                return False
            self._seen.add(jti)
            return True

    def claim_and_reserve(
        self,
        jti: str,
        authorization_id: str,
        amount: Decimal,
        spend_ceiling: Decimal,
    ) -> ClaimResult:
        """Atomically consume a JTI and reserve spend under one L1 credential.

        `authorization_id` is the canonical hash of the signed L1 payload.
        Production backends must implement this as one transaction (for
        example, a Redis Lua script or database transaction) so neither a JTI
        claim nor a budget reservation survives a failed companion check.
        """
        with self._lock:
            if jti in self._seen:
                return ClaimResult.REPLAYED

            current_spend = self._spent.get(authorization_id, Decimal("0"))
            if current_spend + amount > spend_ceiling:
                return ClaimResult.SPEND_CEILING_EXCEEDED

            self._seen.add(jti)
            self._spent[authorization_id] = current_spend + amount
            return ClaimResult.CLAIMED

    def reset(self) -> None:
        with self._lock:
            self._seen.clear()
            self._spent.clear()
