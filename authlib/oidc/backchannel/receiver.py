"""OpenID Connect Back-Channel Logout 1.0 receiver (RP side).

Validates incoming Logout Tokens and invalidates the corresponding
application sessions through a :class:`BackChannelLogoutStore`.

https://openid.net/specs/openid-connect-backchannel-1_0.html#BCActions
"""

from __future__ import annotations

from joserfc import jwt
from joserfc.errors import InvalidClaimError
from joserfc.jwk import KeySet
from joserfc.jws import JWSRegistry

from .claims import LogoutToken
from .store import BackChannelLogoutStore

__all__ = ["BackChannelLogoutReceiver"]


class BackChannelLogoutReceiver:
    """Validate Logout Tokens and revoke the matching sessions.

    :param store: The application-provided session adapter.
    :param issuer: The expected `iss` value of the OP.
    :param client_id: The OAuth 2.0 client identifier; the `aud` claim of
        the Logout Token MUST contain this value.
    :param jwks: The OP's JSON Web Key Set (dict or
        :class:`joserfc.jwk.KeySet`) used to verify the signature.
    :param algorithms: Allowed JWS algorithms. When omitted, every
        algorithm compatible with the given keys is accepted.
    :param leeway: Allowed clock skew in seconds for time claims.
    """

    def __init__(
        self,
        store: BackChannelLogoutStore,
        issuer: str,
        client_id: str,
        jwks: dict | KeySet,
        algorithms: list[str] | None = None,
        leeway: int = 120,
    ):
        self.store = store
        self.issuer = issuer
        self.client_id = client_id
        self.jwks = jwks
        self.algorithms = algorithms
        self.leeway = leeway

    def validate_logout_token(self, logout_token: str) -> LogoutToken:
        """Decode and validate a Logout Token.

        Verifies the signature (restricted to :attr:`algorithms` when
        given), the `iss` and `aud` claims, the time claims, the
        back-channel logout `events` claim, and the presence of `sid`
        or `sub`. Tokens carrying a `nonce` claim are rejected.

        :param logout_token: The compact JWT received from the OP.
        :returns: The validated :class:`LogoutToken` claims.
        :raises joserfc.errors.JoseError: If the token is invalid.
        """
        jwks = self.jwks
        if isinstance(jwks, dict):
            jwks = KeySet.import_key_set(jwks)

        registry = None
        if self.algorithms:
            registry = JWSRegistry(
                algorithms=self.algorithms, strict_check_header=False
            )

        token = jwt.decode(logout_token, jwks, registry=registry)
        claims = LogoutToken(
            token.claims,
            token.header,
            options={
                "iss": {"values": [self.issuer]},
                "aud": {"values": [self.client_id]},
            },
            params={"client_id": self.client_id},
        )
        claims.validate(leeway=self.leeway)
        return claims

    def revoke_sessions(self, claims: LogoutToken) -> int:
        """Invalidate the sessions identified by validated claims.

        The lookup is always scoped to `(issuer, client_id)`, so sessions
        of the same subject under another issuer or client are never
        touched:

        - `sid` present: only that one session is invalidated. When `sub`
          is also present, it MUST match the identity of that session.
        - only `sub`: every session of this subject under this issuer and
          client is invalidated.

        The operation is idempotent: unknown or already invalidated
        sessions are treated as success. Storage exceptions raised by the
        session adapter are propagated unchanged so the caller knows the
        logout was not fully processed.

        :param claims: A validated :class:`LogoutToken`.
        :returns: The number of sessions invalidated.
        :raises joserfc.errors.InvalidClaimError: If `sid` and `sub` do
            not identify the same session.
        """
        sid = claims.get("sid")
        sub = claims.get("sub")

        if sid:
            if sub is not None:
                session_sub = self.store.get_session_sub(
                    self.issuer, self.client_id, sid
                )
                # backchannel 2.8: "the RP MUST verify that the Logout Token
                # contains a sid Claim ... that identifies the session" and
                # when both are present they identify the same session. An
                # unknown session (None) means it is already invalidated,
                # which the idempotent replay contract treats as success.
                if session_sub is not None and session_sub != sub:
                    raise InvalidClaimError("sid")
            return self.store.delete_sessions_by_sid(self.issuer, self.client_id, sid)
        return self.store.delete_sessions_by_sub(self.issuer, self.client_id, sub)

    def process_logout(self, logout_token: str) -> LogoutToken:
        """Validate a Logout Token and invalidate the matching sessions.

        :param logout_token: The compact JWT received from the OP.
        :returns: The validated :class:`LogoutToken` claims.
        """
        claims = self.validate_logout_token(logout_token)
        self.revoke_sessions(claims)
        return claims
