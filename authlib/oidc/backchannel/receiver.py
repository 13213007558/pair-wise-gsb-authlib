"""Logout token validation and reception for OIDC Back-Channel Logout 1.0.

This module implements the Relying Party (RP) side of the specification:
validating incoming logout tokens and terminating the matching local
sessions.

https://openid.net/specs/openid-connect-backchannel-1_0.html
"""

import dataclasses
import json

from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jwk import KeySet
from joserfc.jwk import import_key
from joserfc.jws import extract_compact
from joserfc.jwt import JWTClaimsRegistry

from .logout_token import BACKCHANNEL_LOGOUT_EVENT


class InvalidLogoutTokenError(ValueError):
    """The logout token is missing, malformed, or fails validation.

    The endpoint should answer ``400 Bad Request`` when it catches this
    error. The OP should not send the same token again.
    """


@dataclasses.dataclass(frozen=True)
class LogoutResult:
    """The outcome of a processed logout token.

    :param claims: The validated claims of the logout token.
    :param sessions: The local sessions that the notification targets.
    :param already_processed: ``True`` when the ``jti`` of the token was
        already recorded. The notification is a duplicate: the sessions were
        invalidated by the first delivery, and this result is the idempotent
        answer to a retry.
    """

    claims: dict
    sessions: list
    already_processed: bool


class LogoutTokenStore:
    """Persistence of the logout notifications, for replay protection.

    Implementations must commit the ``jti`` record and the session
    invalidations in a single atomic operation, such as one database
    transaction.
    """

    def record_logout(self, *, jti: str, sessions: list, expires_at: int) -> bool:
        """Record the ``jti`` and invalidate the ``sessions``, atomically.

        :param jti: The unique ID of the logout token.
        :param sessions: The local sessions to invalidate, as returned by
            :meth:`BackchannelLogoutReceiver.get_logout_sessions`.
        :param expires_at: The ``exp`` of the logout token. The store may
            drop the ``jti`` record after this time, to keep the table small.
        :return: ``True`` if the ``jti`` is new and the commit succeeded,
            ``False`` if the ``jti`` was already recorded. A ``False`` return
            means the notification is a duplicate: do not change anything,
            the first delivery already invalidated the sessions.
        :raises Exception: Any persistence failure must raise, before any
            success is reported. The caller answers with an error, and the OP
            may send the notification again. A retry is safe because the
            ``jti`` record is idempotent.
        """
        raise NotImplementedError()


def validate_logout_token(
    token: str,
    key,
    *,
    issuer: str,
    audience: str,
    algorithms: list | None = None,
    leeway: int = 0,
) -> dict:
    """Validate a logout token, and return its claims.

    The validation follows the `Logout Token Validation`_ section of the
    specification: signature, ``iss``, ``aud``, ``iat``, ``exp``, ``jti``,
    the ``events`` claim, and the ``sub``/``sid`` requirements. A token with
    a ``nonce`` claim is rejected, and so is a token without the
    back-channel logout event — a plain ID token of the same issuer is not
    a logout notification.

    :param token: The encoded logout token.
    :param key: The public key of the issuer: a joserfc ``Key``, ``KeySet``,
        JWK dict or JWKS dict.
    :param issuer: The expected ``iss`` value.
    :param audience: The ``client_id`` of this RP at this issuer.
    :param algorithms: Allowed signing algorithms. Defaults to the joserfc
        recommended set. The ``none`` algorithm is never allowed.
    :param leeway: Clock skew tolerance in seconds, for ``exp`` and ``iat``.
    :raises InvalidLogoutTokenError: If the token fails any validation step.
    :return: The validated claims of the logout token.

    .. _Logout Token Validation:
        https://openid.net/specs/openid-connect-backchannel-1_0.html#Validation
    """
    if isinstance(key, dict):
        if "keys" in key:
            key = KeySet.import_key_set(key)
        else:
            key = import_key(key)

    try:
        decoded = jwt.decode(token, key, algorithms=algorithms)
    except JoseError as error:
        raise InvalidLogoutTokenError(f"Invalid logout token: {error}") from error

    header = decoded.header
    claims = decoded.claims

    # backchannel §2.6: "Additionally, an alg with the value none MUST NOT be
    # used for Logout Tokens."
    if header.get("alg") == "none":
        raise InvalidLogoutTokenError("Logout tokens must not use the 'none' algorithm")

    # backchannel §2.4: "nonce - PROHIBITED. A nonce Claim MUST NOT be
    # present." This also keeps ID tokens with a nonce out.
    if "nonce" in claims:
        raise InvalidLogoutTokenError("A logout token must not contain a 'nonce' claim")

    # backchannel §2.4: "events - REQUIRED. Claim whose value is a JSON
    # object containing the member name
    # http://schemas.openid.net/event/backchannel-logout." A plain ID token
    # has no such claim, and is rejected here.
    events = claims.get("events")
    if not isinstance(events, dict) or BACKCHANNEL_LOGOUT_EVENT not in events:
        raise InvalidLogoutTokenError(
            "A logout token must contain the backchannel-logout event"
        )
    if not isinstance(events[BACKCHANNEL_LOGOUT_EVENT], dict):
        raise InvalidLogoutTokenError(
            "The backchannel-logout event value must be a JSON object"
        )

    # backchannel §2.4: "A Logout Token MUST contain either a sub or a sid
    # Claim, and MAY contain both."
    if claims.get("sub") is None and claims.get("sid") is None:
        raise InvalidLogoutTokenError(
            "A logout token must contain a 'sub' or a 'sid' claim"
        )

    registry = JWTClaimsRegistry(
        leeway=leeway,
        iss={"essential": True, "value": issuer},
        aud={"essential": True, "values": [audience]},
        exp={"essential": True},
        iat={"essential": True},
        jti={"essential": True},
    )
    try:
        registry.validate(claims)
    except JoseError as error:
        raise InvalidLogoutTokenError(f"Invalid logout token: {error}") from error

    return claims


class BackchannelLogoutReceiver:
    """Receive back-channel logout notifications, as a Relying Party.

    Subclass it, create one instance, and call it from the
    ``backchannel_logout_uri`` endpoint::

        class MyLogoutTokenStore(LogoutTokenStore):
            def record_logout(self, *, jti, sessions, expires_at):
                if db.jti_exists(jti):
                    return False
                db.record_jti(jti, expires_at)
                db.delete_sessions(sessions)
                db.commit()  # one transaction for the jti and the sessions
                return True


        class MyBackchannelLogoutReceiver(BackchannelLogoutReceiver):
            def get_issuer_keys(self, issuer):
                return load_op_jwks(issuer)  # None for an untrusted issuer

            def get_client_id(self, issuer):
                return "my-client-id"

            def get_logout_sessions(self, issuer, client_id, sub, sid):
                return db.query_sessions(
                    issuer=issuer, client_id=client_id, sub=sub, sid=sid
                )

            def get_store(self):
                return MyLogoutTokenStore()


        backchannel_logout = MyBackchannelLogoutReceiver()

    The endpoint answers ``400 Bad Request`` when
    :meth:`handle_logout_token` raises :class:`InvalidLogoutTokenError`,
    and ``200 OK`` (or ``204 No Content``) when it returns. An exception
    from the store means the logout was not committed: answer with an
    error, so that the OP may send the notification again.
    """

    #: Clock skew tolerance in seconds, for the ``exp`` and ``iat`` claims.
    LEEWAY = 0

    def handle_logout_token(self, token: str) -> LogoutResult:
        """Validate a logout token and terminate the matching sessions.

        The validation is read-only. The only write is the
        :meth:`LogoutTokenStore.record_logout` call, which commits the
        ``jti`` record and the session invalidations together. The endpoint
        reports success only after this commit. A duplicate notification
        returns a :class:`LogoutResult` with ``already_processed`` set, and
        changes nothing.

        :param token: The ``logout_token`` parameter of the POST request.
        :raises InvalidLogoutTokenError: If the token fails validation.
        :return: The result of the logout.
        """
        issuer = self._token_issuer(token)
        key = self.get_issuer_keys(issuer)
        if key is None:
            raise InvalidLogoutTokenError(f"Untrusted issuer: {issuer!r}")

        client_id = self.get_client_id(issuer)
        claims = validate_logout_token(
            token,
            key,
            issuer=issuer,
            audience=client_id,
            algorithms=self.get_issuer_algorithms(issuer),
            leeway=self.LEEWAY,
        )

        sessions = list(
            self.get_logout_sessions(
                issuer, client_id, claims.get("sub"), claims.get("sid")
            )
        )
        recorded = self.get_store().record_logout(
            jti=claims["jti"], sessions=sessions, expires_at=claims["exp"]
        )
        return LogoutResult(
            claims=claims, sessions=sessions, already_processed=not recorded
        )

    def get_issuer_keys(self, issuer: str):
        """Return the public keys of the issuer, to verify the signature.

        The return value can be a joserfc ``Key``, a ``KeySet``, a JWK dict
        or a JWKS dict. Return ``None`` for an issuer this RP does not trust:
        the token is rejected. Fetch the keys from the ``jwks_uri`` of the
        issuer, and cache them.
        """
        raise NotImplementedError()

    def get_client_id(self, issuer: str) -> str:
        """Return the ``client_id`` of this RP at this issuer.

        The ``aud`` claim of the logout token must contain this value. An RP
        registered at several OPs may have a different ``client_id`` at each
        of them.
        """
        raise NotImplementedError()

    def get_issuer_algorithms(self, issuer: str) -> list | None:
        """Return the allowed signing algorithms of the issuer.

        Defaults to ``None``, the joserfc recommended set. The ``none``
        algorithm is never allowed for logout tokens.
        """
        return None

    def get_logout_sessions(
        self,
        issuer: str,
        client_id: str,
        sub: str | None,
        sid: str | None,
    ) -> list:
        """Return the local sessions that the logout token targets.

        The lookup must always be scoped by ``issuer`` and ``client_id``: a
        ``sid`` or ``sub`` value may exist at another issuer, or for another
        client, and the notification must not terminate those sessions.

        - With a ``sid``, return the sessions of this ``(issuer, client_id,
          sid)``. If a ``sub`` is also present, the sessions must match it
          too.
        - With only a ``sub``, return all the sessions of this user at this
          ``(issuer, client_id)``. This is the legitimate scope of a
          sub-only notification: every session of this user with this OP
          account, for this client, and nothing else.
        """
        raise NotImplementedError()

    def get_store(self) -> LogoutTokenStore:
        """Return the store that records the logout notifications."""
        raise NotImplementedError()

    @staticmethod
    def _token_issuer(token: str) -> str:
        """Read the ``iss`` claim without verifying the signature.

        The issuer selects the keys that verify the signature, so it must be
        read first. The claim is validated against the expected value by
        :func:`validate_logout_token` after the signature check.
        """
        try:
            raw = token.encode() if isinstance(token, str) else token
            claims = json.loads(extract_compact(raw).payload)
        except (JoseError, ValueError, TypeError, UnicodeDecodeError) as error:
            raise InvalidLogoutTokenError("Malformed logout token") from error

        issuer = claims.get("iss") if isinstance(claims, dict) else None
        if not isinstance(issuer, str) or not issuer:
            raise InvalidLogoutTokenError("A logout token must contain an 'iss' claim")
        return issuer
