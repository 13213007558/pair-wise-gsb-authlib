"""Session adapter contract for OpenID Back-Channel Logout.

The application provides a :class:`BackChannelLogoutStore` implementation
that maps OP session identifiers (`sid`) and subjects (`sub`) to its own
server-side sessions, scoped by `(issuer, client_id)` so that sessions
from different tenants or issuers are never mixed.

https://openid.net/specs/openid-connect-backchannel-1_0.html#BCActions
"""

from __future__ import annotations

import threading
from typing import Any

__all__ = ["BackChannelLogoutStore", "InMemoryBackChannelLogoutStore"]


class BackChannelLogoutStore:
    """Application-provided session adapter for back-channel logout.

    All methods MUST be idempotent: invalidating a session that no longer
    exists (e.g. a replayed `logout_token`) is a success, not an error.

    If the underlying storage fails, implementations MUST raise an
    exception instead of silently succeeding, so that the caller knows the
    logout was not fully processed and can signal the failure to the OP
    (e.g. with an HTTP 500 response).
    """

    def get_session_sub(self, issuer: str, client_id: str, sid: str) -> str | None:
        """Return the `sub` bound to the given session, or `None` when
        the session is unknown or already invalidated.

        :param issuer: The `iss` claim of the logout token.
        :param client_id: The OAuth 2.0 client identifier (`aud`).
        :param sid: The `sid` claim of the logout token.
        """
        raise NotImplementedError()

    def delete_sessions_by_sid(self, issuer: str, client_id: str, sid: str) -> int:
        """Invalidate the single session identified by `sid` under the
        given `issuer` and `client_id`. Returns the number of sessions
        invalidated. MUST NOT raise when the session does not exist.
        """
        raise NotImplementedError()

    def delete_sessions_by_sub(self, issuer: str, client_id: str, sub: str) -> int:
        """Invalidate **all** sessions of the subject `sub` under the
        given `issuer` and `client_id`. Sessions of the same `sub`
        under a different issuer or client MUST NOT be touched. Returns the
        number of sessions invalidated.
        """
        raise NotImplementedError()


class InMemoryBackChannelLogoutStore(BackChannelLogoutStore):
    """A thread-safe in-memory session adapter.

    Suitable for development, demos and tests. Sessions are registered with
    :meth:`add_session` and looked up by `(issuer, client_id, sid)`.
    """

    def __init__(self):
        self._sessions: dict[tuple[str, str, str], dict[str, Any]] = {}
        self._lock = threading.Lock()

    def add_session(
        self,
        issuer: str,
        client_id: str,
        sid: str,
        sub: str,
        data: dict[str, Any] | None = None,
    ) -> None:
        """Register an active session bound to `(issuer, client_id, sid)`."""
        with self._lock:
            self._sessions[(issuer, client_id, sid)] = {"sub": sub, "data": data or {}}

    def get_session(
        self, issuer: str, client_id: str, sid: str
    ) -> dict[str, Any] | None:
        """Return the stored session record, or `None` if not active."""
        with self._lock:
            return self._sessions.get((issuer, client_id, sid))

    def get_session_sub(self, issuer: str, client_id: str, sid: str) -> str | None:
        with self._lock:
            record = self._sessions.get((issuer, client_id, sid))
        if record is None:
            return None
        return record["sub"]

    def delete_sessions_by_sid(self, issuer: str, client_id: str, sid: str) -> int:
        with self._lock:
            if self._sessions.pop((issuer, client_id, sid), None) is not None:
                return 1
        return 0

    def delete_sessions_by_sub(self, issuer: str, client_id: str, sub: str) -> int:
        with self._lock:
            keys = [
                key
                for key, record in self._sessions.items()
                if key[0] == issuer and key[1] == client_id and record["sub"] == sub
            ]
            for key in keys:
                del self._sessions[key]
        return len(keys)
