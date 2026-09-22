"""authlib.oauth2.rfc9449.store.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Storage interface for DPoP proof replay detection.

https://www.rfc-editor.org/rfc/rfc9449.html#section-11.1
"""

import threading
import time

__all__ = ["DPoPReplayStore", "InMemoryDPoPReplayStore"]


class DPoPReplayStore:
    """Interface of the storage used to detect replayed DPoP proofs.
    Developers MUST re-implement this class with a storage backend that
    is shared by all server instances, e.g. Redis or a database::

        class RedisDPoPReplayStore(DPoPReplayStore):
            def __init__(self, redis):
                self.redis = redis

            def record(self, jti, expires_at):
                # SET jti expires_at NX PX ...
                ...
    """

    def record(self, jti, expires_at):
        """Atomically record a proof ``jti``. This method MUST return
        ``True`` only if the ``jti`` was not recorded before, and ``False``
        if it was already seen (and has not expired yet). Implementations
        MUST be atomic so that concurrent proofs with the same ``jti`` can
        not both succeed.

        :param jti: the ``jti`` claim of a validated DPoP proof
        :param expires_at: unix timestamp after which the record MAY be
            discarded
        :return: True if the ``jti`` is new, False on replay
        """
        raise NotImplementedError()

    def purge(self, now=None):
        """Remove expired records. Implementations MAY re-implement this
        method if the backend does not expire records by itself.
        """


class InMemoryDPoPReplayStore(DPoPReplayStore):
    """A process local, thread safe replay store. Suitable for development
    and single process deployments only.
    """

    def __init__(self):
        self._records = {}
        self._lock = threading.Lock()

    def record(self, jti, expires_at):
        with self._lock:
            self._purge_locked(time.time())
            if jti in self._records:
                return False
            self._records[jti] = expires_at
            return True

    def purge(self, now=None):
        with self._lock:
            self._purge_locked(now if now is not None else time.time())

    def _purge_locked(self, now):
        expired = [jti for jti, exp in self._records.items() if exp <= now]
        for jti in expired:
            del self._records[jti]
