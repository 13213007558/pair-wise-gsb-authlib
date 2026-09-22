"""authlib.oauth2.rfc9449.token.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

DPoP-bound JWT access token generator.

https://www.rfc-editor.org/rfc/rfc9449.html#section-5
"""

import contextvars

from ..rfc9068 import JWTBearerTokenGenerator
from .errors import InvalidDPoPProofError
from .validator import pop_current_jkt

__all__ = ["DPoPTokenGenerator"]

#: handoff of the proof thumbprint from ``generate`` to ``get_extra_claims``
#: within the current request context
_pending_jkt = contextvars.ContextVar("authlib.oauth2.rfc9449.pending_jkt")


class DPoPTokenGenerator(JWTBearerTokenGenerator):
    r"""A JWT access token generator that binds the issued token to the
    public key of the DPoP proof validated for the current token request.
    The JWK SHA-256 thumbprint is embedded in the ``cnf.jkt`` claim and the
    token response uses ``token_type=DPoP``.

    It requires a :class:`DPoPGrantExtension` to be registered on the grant,
    which validates the proof and publishes its thumbprint::

        class MyDPoPTokenGenerator(DPoPTokenGenerator):
            def get_jwks(self): ...


        server.register_grant(ClientCredentialsGrant, [DPoPGrantExtension()])
        server.register_token_generator(
            "client_credentials",
            MyDPoPTokenGenerator(issuer="https://as.example.org"),
        )
    """

    def __init__(self, issuer, alg="ES256", **kwargs):
        super().__init__(issuer, alg=alg, **kwargs)

    def generate(
        self,
        grant_type,
        client,
        user=None,
        scope=None,
        expires_in=None,
        include_refresh_token=True,
    ):
        jkt = pop_current_jkt()
        if jkt is None:
            raise InvalidDPoPProofError(
                "Missing DPoP proof to bind the access token to."
            )
        reset = _pending_jkt.set(jkt)
        try:
            token = super().generate(
                grant_type,
                client,
                user=user,
                scope=scope,
                expires_in=expires_in,
                include_refresh_token=include_refresh_token,
            )
        finally:
            _pending_jkt.reset(reset)
        token["token_type"] = "DPoP" if jkt else "Bearer"
        return token

    def get_extra_claims(self, client, grant_type, user, scope):
        claims = dict(super().get_extra_claims(client, grant_type, user, scope))
        jkt = _pending_jkt.get()
        if jkt:
            claims["cnf"] = {"jkt": jkt}
        return claims
