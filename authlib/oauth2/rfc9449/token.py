"""authlib.oauth2.rfc9449.token.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

DPoP-bound JWT access token generator, per RFC 9449 Section 5.1.

The issued token is a JWT access token (RFC 9068) carrying the JWK
thumbprint of the client DPoP key in the ``cnf.jkt`` claim, and is
returned with ``token_type`` ``DPoP``.
"""

from contextlib import contextmanager
from contextvars import ContextVar

from ..rfc9068 import JWTBearerTokenGenerator

__all__ = [
    "DPoPTokenGenerator",
    "bound_dpop_jkt",
]

#: JWK thumbprint of the DPoP key the token being issued is bound to.
#: Set by the token endpoint while generating a token.
_current_jkt: ContextVar = ContextVar("authlib.oauth2.rfc9449.jkt", default=None)


@contextmanager
def bound_dpop_jkt(jkt):
    """Context manager binding the token being issued to a DPoP key
    thumbprint. Used by token endpoints around token generation.
    """
    token = _current_jkt.set(jkt)
    try:
        yield
    finally:
        _current_jkt.reset(token)


class DPoPTokenGenerator(JWTBearerTokenGenerator):
    r"""A DPoP-bound JWT access token generator.

    :param issuer: The issuer identifier. Will appear in the JWT ``iss`` claim.
    :param alg: The JWS algorithm used to sign access tokens, default is
        ``ES256``.
    :param \*\*kwargs: Other parameters are inherited from
        :class:`~authlib.oauth2.rfc9068.JWTBearerTokenGenerator`.

    Developers MUST re-implement ``get_jwks`` like for
    :class:`~authlib.oauth2.rfc9068.JWTBearerTokenGenerator`::

        class MyDPoPTokenGenerator(DPoPTokenGenerator):
            def get_jwks(self):
                return load_jwks("jwks.json")


        authorization_server.register_token_generator(
            "default",
            MyDPoPTokenGenerator(issuer="https://as.example.org"),
        )
    """

    def __init__(
        self,
        issuer,
        alg="ES256",
        refresh_token_generator=None,
        expires_generator=None,
    ):
        super().__init__(
            issuer,
            alg=alg,
            refresh_token_generator=refresh_token_generator,
            expires_generator=expires_generator,
        )

    def generate(
        self,
        grant_type,
        client,
        user=None,
        scope=None,
        expires_in=None,
        include_refresh_token=True,
    ):
        token = super().generate(
            grant_type,
            client,
            user=user,
            scope=scope,
            expires_in=expires_in,
            include_refresh_token=include_refresh_token,
        )
        # RFC 9449, Section 5.1: the token_type in the response MUST be DPoP.
        token["token_type"] = "DPoP"
        return token

    def get_extra_claims(self, client, grant_type, user, scope):
        claims = dict(super().get_extra_claims(client, grant_type, user, scope))
        jkt = _current_jkt.get()
        if jkt:
            # RFC 9449, Section 6.1: the access token is bound to the
            # client DPoP key through the ``cnf.jkt`` claim (RFC 7800).
            claims["cnf"] = {"jkt": jkt}
        return claims
