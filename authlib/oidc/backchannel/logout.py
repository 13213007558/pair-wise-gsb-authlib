from __future__ import annotations

from dataclasses import dataclass

from joserfc import jwt
from joserfc.errors import InvalidKeyIdError
from joserfc.errors import JoseError
from joserfc.jwk import KeySet
from joserfc.jws import JWSRegistry

from .claims import LogoutTokenClaims
from .errors import InvalidLogoutTokenError


@dataclass(frozen=True)
class BackChannelLogoutResult:
    replayed: bool
    claims: dict


def process_logout_token(client, logout_token, store=None, leeway=120):
    """Validate an OIDC logout token and revoke the identified RP sessions.

    Storage errors are intentionally not caught: a failed revocation or replay
    update means the request must not be reported as successfully processed.
    """
    store = store or getattr(client, "backchannel_logout_store", None)
    if store is None:
        raise RuntimeError("A back-channel logout store is required.")

    metadata = client.load_server_metadata()
    issuer = metadata.get("issuer")
    client_id = client.client_id
    if not issuer or not client_id:
        raise InvalidLogoutTokenError()

    claims = _decode_claims(
        client, logout_token, metadata, issuer, client_id, leeway
    )
    jti = claims["jti"]

    if store.is_logout_processed(issuer, client_id, jti):
        return BackChannelLogoutResult(replayed=True, claims=dict(claims))

    sid = claims.get("sid")
    sub = claims.get("sub")
    if sid is not None:
        store.revoke_session(issuer, client_id, sid, sub)
    else:
        store.revoke_subject_sessions(issuer, client_id, sub)

    store.mark_logout_processed(issuer, client_id, jti)
    return BackChannelLogoutResult(replayed=False, claims=dict(claims))


def _decode_claims(client, logout_token, metadata, issuer, client_id, leeway):
    alg_values = metadata.get("id_token_signing_alg_values_supported")
    if alg_values is not None:
        alg_values = [alg for alg in alg_values if alg != "none"]
        if not alg_values:
            raise InvalidLogoutTokenError()

    key_set = KeySet.import_key_set(client.fetch_jwk_set())
    try:
        token = _decode(logout_token, key_set, alg_values)
    except InvalidKeyIdError:
        try:
            refreshed_key_set = KeySet.import_key_set(
                client.fetch_jwk_set(force=True)
            )
        except RuntimeError:
            refreshed_key_set = key_set
        try:
            token = _decode(logout_token, refreshed_key_set, alg_values)
        except JoseError as exc:
            raise InvalidLogoutTokenError(description=str(exc)) from exc
    except JoseError as exc:
        raise InvalidLogoutTokenError(description=str(exc)) from exc

    if token.header.get("alg") == "none":
        raise InvalidLogoutTokenError()
    typ = token.header.get("typ")
    if typ is not None and typ != "logout+jwt":
        raise InvalidLogoutTokenError()

    def validate_audience(claims, audience):
        if audience == client_id:
            return True
        return (
            isinstance(audience, list)
            and len(audience) == 1
            and audience[0] == client_id
        )

    def is_string(claims, value):
        return isinstance(value, str) and bool(value)

    claims_options = {
        "iss": {"essential": True, "value": issuer},
        "aud": {"essential": True, "validate": validate_audience},
        "exp": {"essential": True},
        "iat": {"essential": True},
        "jti": {"essential": True, "validate": is_string},
        "events": {"essential": True},
        "sub": {"essential": False, "validate": is_string},
        "sid": {"essential": False, "validate": is_string},
    }
    claims = LogoutTokenClaims(
        token.claims, token.header, claims_options, {"client_id": client_id}
    )
    try:
        claims.validate(leeway=leeway)
    except JoseError as exc:
        raise InvalidLogoutTokenError(description=str(exc)) from exc
    return claims


def _decode(logout_token, key_set, alg_values):
    return jwt.decode(
        logout_token,
        key=key_set,
        registry=JWSRegistry(
            algorithms=alg_values,
            strict_check_header=False,
        ),
    )
