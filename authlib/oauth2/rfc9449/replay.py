"""authlib.oauth2.rfc9449.replay.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Replay protection for DPoP proof JWTs per :rfc:`9449#section-4.2`.

The ``jti`` of a DPoP proof is only accepted once within its acceptable time
window. Storage must be atomic: concurrent requests presenting the same valid
proof can only pass once, and a proof that failed validation must never
reserve its identifier.
"""

import threading
import time
from typing import Protocol
from typing import runtime_checkable

__all__ = ["ReplayStore", "InMemoryReplayStore"]


@runtime_checkable
class ReplayStore(Protocol):
    """Storage for DPoP proof identifiers that guarantees atomic check-and-store.

    Implementations must make :meth:`check_and_store` atomic: when two threads
    or processes present the same ``jti`` at the same time, exactly one call
    returns ``True``. The method is only called for proofs that already passed
    every other validation, so rejected proofs never reserve an identifier.
    """

    def check_and_store(self, jti: str, expires_at: float) -> bool:
        """Atomically store ``jti`` if it has not been seen before.

        :param jti: The unique ``jti`` claim of a valid DPoP proof.
        :param expires_at: A UNIX timestamp after which the entry may be
            removed, typically the proof ``iat`` plus the accepted window.
        :return: ``True`` if the identifier was unknown and is now stored,
            ``False`` if the same proof was already accepted.
        """
        ...


class InMemoryReplayStore:
    """Thread-safe in-memory implementation of :class:`ReplayStore`.

    A single lock makes check-and-store atomic, so concurrent requests with
    the same valid ``jti`` can only be accepted once. Expired entries are
    purged opportunistically, so a still-valid proof is never removed before
    its window elapses.

    :param max_entries: Maximum number of identifiers kept in memory. When the
        limit is reached, expired entries are purged before inserting a new
        one. If none can be purged, a :class:`RuntimeError` is raised instead
        of evicting entries that still protect against replays.
    :param clock: A callable returning the current UNIX time, used to decide
        which entries are expired. Defaults to :func:`time.time`.
    """

    def __init__(self, max_entries: int = 100_000, clock=time.time):
        self._entries: dict[str, float] = {}
        self._lock = threading.Lock()
        self._max_entries = max_entries
        self._clock = clock
        self._operations_since_purge = 0

    def check_and_store(self, jti: str, expires_at: float) -> bool:
        with self._lock:
            if jti in self._entries:
                return False

            if len(self._entries) >= self._max_entries:
                self._purge(self._clock())
                if len(self._entries) >= self._max_entries:
                    raise RuntimeError("DPoP replay store is full")

            self._entries[jti] = expires_at
            self._schedule_purge()
            return True

    def _schedule_purge(self) -> None:
        # Purge expired entries periodically instead of on every call, so the
        # hot path stays O(1) while memory cannot grow beyond the live window
        # plus one purge interval.
        self._operations_since_purge += 1
        if self._operations_since_purge >= self._max_entries:
            self._purge(self._clock())
            self._operations_since_purge = 0

    def _purge(self, now: float) -> None:
        expired = [
            stored_jti
            for stored_jti, expires_at in self._entries.items()
            if expires_at <= now
        ]
        for stored_jti in expired:
            del self._entries[stored_jti]
