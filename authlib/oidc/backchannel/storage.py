from __future__ import annotations

from .errors import SessionIdentityMismatchError


class BackChannelLogoutStore:
    """Storage contract for server-side OIDC sessions and logout replay state.

    All methods operate in one issuer/client scope. Revocation methods should
    be atomic: either all matching sessions are revoked, or the method raises.
    """

    def is_logout_processed(self, issuer, client_id, jti):
        raise NotImplementedError()

    def mark_logout_processed(self, issuer, client_id, jti):
        raise NotImplementedError()

    def revoke_session(self, issuer, client_id, sid, sub=None):
        """Revoke one active session in one issuer/client scope.

        Revoking an unknown or already revoked session must succeed. When
        ``sub`` is supplied, implementations must not revoke a session whose
        subject differs and must raise an error instead.
        """
        raise NotImplementedError()

    def revoke_subject_sessions(self, issuer, client_id, sub):
        """Revoke every active subject session in one issuer/client scope.

        An issuer may have no active session for the subject during a retry;
        that is an idempotent success.
        """
        raise NotImplementedError()


class InMemoryBackChannelLogoutStore(BackChannelLogoutStore):
    """Process-local store for examples and tests; use durable storage in production."""

    def __init__(self):
        self.sessions = []
        self.processed_logouts = set()

    def add_session(
        self, session_id, issuer, client_id, sub, sid=None, active=True
    ):
        session = {
            "session_id": session_id,
            "issuer": issuer,
            "client_id": client_id,
            "sub": sub,
            "sid": sid,
            "active": active,
        }
        self.sessions.append(session)
        return session

    def is_active(self, session_id):
        for session in self.sessions:
            if session["session_id"] == session_id:
                return session["active"]
        return False

    def is_logout_processed(self, issuer, client_id, jti):
        return (issuer, client_id, jti) in self.processed_logouts

    def mark_logout_processed(self, issuer, client_id, jti):
        self.processed_logouts.add((issuer, client_id, jti))

    def revoke_session(self, issuer, client_id, sid, sub=None):
        for session in self.sessions:
            if (
                session["issuer"] == issuer
                and session["client_id"] == client_id
                and session["sid"] == sid
            ):
                if sub is not None and session["sub"] != sub:
                    raise SessionIdentityMismatchError()
                session["active"] = False

    def revoke_subject_sessions(self, issuer, client_id, sub):
        for session in self.sessions:
            if (
                session["active"]
                and session["issuer"] == issuer
                and session["client_id"] == client_id
                and session["sub"] == sub
            ):
                session["active"] = False
