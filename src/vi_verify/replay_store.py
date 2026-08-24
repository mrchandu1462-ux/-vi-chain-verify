"""
Tracks L3 `jti` values that have already been settled, so a captured L3
credential can never be replayed against the facilitator a second time.

An in-memory set is enough for this project's purposes (a single verifier
process / a single test run). A production facilitator would back this with
a database or distributed cache keyed by jti with a TTL past L3's `exp`.
"""
from __future__ import annotations


class ReplayStore:
    def __init__(self) -> None:
        self._seen: set[str] = set()

    def seen(self, jti: str) -> bool:
        return jti in self._seen

    def record(self, jti: str) -> None:
        self._seen.add(jti)

    def reset(self) -> None:
        self._seen.clear()
