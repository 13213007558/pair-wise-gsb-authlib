import threading
import time

__all__ = ["LogoutTokenStore", "InMemoryLogoutStore"]


def _match_session(record, iss, sid, sub):
    if record["iss"] != iss:
        # a "sid" (or "sub") identity is always scoped to its issuer; an
        # identical "sid" value from another issuer MUST NOT be affected
        return False
    if sid is not None and sub is not None:
        # when both are present, the session must belong to both of them
        return record["sid"] == sid and record["sub"] == sub
    if sid is not None:
        return record["sid"] == sid
    return record["sub"] == sub


class LogoutTokenStore:
    """Interface of the persistence adapter for back-channel logout.

    The store keeps an index of the local login sessions (keyed by issuer,
    session id and subject) together with the replay records of the logout
    tokens that have already been processed.

    Implementations of :meth:`apply_logout` MUST provide an atomic boundary
    between recording the logout token's ``jti`` and invalidating the
    matched sessions: either both effects are persisted, or none of them.
    A database backed adapter would typically wrap them in a transaction.
    """

    def add_session(self, session_id, iss, sid=None, sub=None):
        """Register a local login session so that it can be found and
        invalidated by a back-channel logout notification.

        :param session_id: the local session identifier.
        :param iss: issuer of the OpenID provider that authenticated the user.
        :param sid: the ``sid`` of the upstream session, if any.
        :param sub: the ``sub`` of the authenticated user, if any.
        """
        raise NotImplementedError()

    def remove_session(self, session_id):
        """Remove a local session from the index, e.g. when the user logs
        out in the browser."""
        raise NotImplementedError()

    def apply_logout(self, claims, on_logout=None):
        """Atomically record the logout token's ``jti`` and invalidate
        every session matching the token's ``iss``/``sid``/``sub``.

        :param claims: a validated :class:`LogoutToken` claims instance.
        :param on_logout: optional callback invoked as
            ``on_logout(session_ids, claims)`` with the invalidated
            session ids, so the application can drop the real sessions.
        :return: the list of invalidated session ids, or ``None`` when the
            ``jti`` was already recorded (idempotent replay).
        """
        raise NotImplementedError()


class InMemoryLogoutStore(LogoutTokenStore):
    """Default in-process :class:`LogoutTokenStore`.

    Suitable for development and single-process deployments. Production
    applications running several processes should provide their own
    :class:`LogoutTokenStore` backed by shared persistent storage.

    :param expires_in: seconds a ``jti`` replay record is kept.
    """

    def __init__(self, expires_in=86400):
        self.expires_in = expires_in
        self._lock = threading.Lock()
        self._sessions = {}
        self._jti_records = {}

    def add_session(self, session_id, iss, sid=None, sub=None):
        with self._lock:
            self._sessions[session_id] = {"iss": iss, "sid": sid, "sub": sub}

    def remove_session(self, session_id):
        with self._lock:
            self._sessions.pop(session_id, None)

    def apply_logout(self, claims, on_logout=None):
        iss = claims["iss"]
        jti = claims["jti"]
        sid = claims.get("sid")
        sub = claims.get("sub")

        with self._lock:
            self._purge_expired()
            if (iss, jti) in self._jti_records:
                return None
            matched = [
                session_id
                for session_id, record in self._sessions.items()
                if _match_session(record, iss, sid, sub)
            ]
            # the atomic boundary: the replay record and the session
            # invalidations become visible together
            self._jti_records[(iss, jti)] = time.time() + self.expires_in
            for session_id in matched:
                self._sessions.pop(session_id, None)

        if on_logout and matched:
            on_logout(matched, claims)
        return matched

    def _purge_expired(self):
        now = time.time()
        expired = [key for key, exp in self._jti_records.items() if exp < now]
        for key in expired:
            del self._jti_records[key]
