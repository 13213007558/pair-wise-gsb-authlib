"""Client side validation of JWT Secured Authorization Responses (JARM)."""

from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jwt import JWTClaimsRegistry

from ..rfc6749.errors import OAuth2Error

__all__ = ["InvalidJARMResponseError", "validate_jarm_response"]


class InvalidJARMResponseError(OAuth2Error):
    """The JWT secured authorization response is invalid: the signature,
    the signing algorithm, or one of the required claims (``iss``,
    ``aud``, ``exp``) failed validation.
    """

    error = "invalid_jarm_response"
    description = "Invalid JWT Secured Authorization Response."


def validate_jarm_response(response, key, issuer, audience, algorithms=None, leeway=60):
    """Decode and validate a JARM ``response`` JWT.

    The signature and the signing algorithm are verified first, then the
    ``iss``, ``aud`` and ``exp`` claims are validated. Only after these
    checks succeed may the caller trust claims such as ``state`` and
    ``code``.

    :param response: the value of the ``response`` parameter.
    :param key: a key or key set accepted by ``joserfc`` to verify the
        signature.
    :param issuer: expected ``iss`` value of the authorization server.
    :param audience: expected ``aud`` value, usually the client_id.
    :param algorithms: allowed ``alg`` values, defaults to ``["RS256"]``.
    :param leeway: leeway in seconds for the ``exp`` validation.
    :return: the validated claims dict.
    :raises InvalidJARMResponseError: if any validation fails.
    """
    if algorithms is None:
        # JARM: "authorization_signed_response_alg" defaults to RS256
        algorithms = ["RS256"]

    try:
        token = jwt.decode(response, key, algorithms=algorithms)
    except JoseError as exc:
        raise InvalidJARMResponseError() from exc

    registry = JWTClaimsRegistry(
        leeway=leeway,
        iss={"essential": True, "value": issuer},
        aud={"essential": True, "value": audience},
        exp={"essential": True},
    )
    try:
        registry.validate(token.claims)
    except JoseError as exc:
        raise InvalidJARMResponseError() from exc
    return token.claims
