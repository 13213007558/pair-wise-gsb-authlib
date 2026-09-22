"""authlib.oauth2.rfc9449.store.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Storage interface for DPoP proof replay detection, per RFC 9449
Section 11.1. The ``jti`` claim of each accepted DPoP proof MUST be
recorded so that a replayed proof can be rejected within its
validity window.
"""

import threading
import time

__all__ = [
    "DPoPReplayStore",
    "InMemoryDPoPReplayStore",
]


class DPoPReplayStore:
    """Interface of the storage used to detect DPoP proof replays.

    Implementations MUST record a proof identifier atomically: two
    concurrent calls with the same ``jti`` MUST result in exactly one
    of them returning ``True``.
    """

    def record(self, jti: str, expires_at: float) -> bool:
        """Record ``jti`` as seen until ``expires_at`` (a POSIX timestamp).

        :param jti: the ``jti`` claim of an accepted DPoP proof.
        :param expires_at: timestamp after which the record may be discarded.
        :return: ``True`` if the identifier was recorded, ``False`` if it
            was already present (i.e. the proof is a replay).
        """
        raise NotImplementedError()

    def cleanup(self):
        """Discard expired records. Implementations MAY also cleanup
        lazily inside :meth:`record`.
        """


class InMemoryDPoPReplayStore(DPoPReplayStore):
    """Process-local replay store, suitable for development, tests and
    single-process deployments. Multi-process deployments SHOULD provide
    a shared implementation (e.g. backed by Redis or a database) with the
    same atomic semantics.
    """

    def __init__(self):
        self._items = {}
        self._lock = threading.Lock()

    def record(self, jti: str, expires_at: float) -> bool:
        with self._lock:
            self._cleanup_locked()
            if jti in self._items:
                return False
            self._items[jti] = expires_at
            return True

    def cleanup(self):
        with self._lock:
            self._cleanup_locked()

    def _cleanup_locked(self):
        now = time.time()
        expired = [jti for jti, exp in self._items.items() if exp <= now]
        for jti in expired:
            del self._items[jti]
