"""
Tracks L3 `jti` values that have already been settled, so a captured L3
credential can never be replayed against the facilitator a second time.

An in-memory set is enough for this project's purposes (a single verifier
process / a single test run). A production facilitator would back this with
a database or distributed cache keyed by jti with a TTL past L3's `exp`.
"""
from __future__ import annotations

from threading import Lock


class ReplayStore:
    def __init__(self) -> None:
        self._seen: set[str] = set()
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

    def reset(self) -> None:
        with self._lock:
            self._seen.clear()
