"""authlib.oauth2.rfc8693.validator.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Resource server side validation for tokens issued via OAuth 2.0 Token
Exchange. The validator checks that the subject, actor chain, audience
and scope of the token correspond to the protected resource.

https://tools.ietf.org/html/rfc8693
"""

from ..rfc6750 import BearerTokenValidator
from ..rfc6750.errors import InvalidTokenError
from .claims import ActorChainError
from .claims import ensure_acyclic_actor_chain
from .claims import parse_actor_chain

__all__ = ["TokenExchangeBearerTokenValidator"]


class TokenExchangeBearerTokenValidator(BearerTokenValidator):
    """A bearer token validator for resource servers consuming tokens
    issued by :class:`TokenExchangeGrant`. Besides the usual bearer token
    checks, it verifies:

    * the token carries a ``sub`` (subject) value
    * the ``act`` (actor) claim is a well formed, ordered and acyclic
      delegation chain
    * the ``aud`` (audience) of the token covers this resource server

    It works with JWT claims dicts as well as token objects (e.g. ORM
    instances for opaque tokens) exposing ``sub``, ``act``, ``aud`` and
    ``scope`` attributes::

        class MyValidator(TokenExchangeBearerTokenValidator):
            def authenticate_token(self, token_string):
                return Token.query.filter_by(access_token=token_string).first()


        require_oauth.register_token_validator(
            MyValidator(resource_server="https://reports.example.com")
        )
    """

    TOKEN_TYPE = "bearer"

    def __init__(self, resource_server=None, realm=None, **extra_attributes):
        super().__init__(realm, **extra_attributes)
        #: identifier (absolute URI) of this resource server
        self.resource_server = resource_server

    def get_token_claims(self, token):
        """Extract the token exchange claims from the authenticated token.
        ``token`` may be a claims dict (e.g. decoded JWT) or an object
        exposing the claims as attributes.
        """
        if isinstance(token, dict):
            return token
        claims = {}
        for name in ("sub", "act", "aud", "scope"):
            value = getattr(token, name, None)
            if value is not None:
                claims[name] = value
        return claims

    def validate_token(self, token, scopes, request):
        super().validate_token(token, scopes, request)
        claims = self.get_token_claims(token)

        if not claims.get("sub"):
            raise InvalidTokenError(
                realm=self.realm,
                extra_attributes=self.extra_attributes,
            )

        act = claims.get("act")
        if act is not None:
            try:
                chain = parse_actor_chain(act)
                ensure_acyclic_actor_chain(chain)
            except ActorChainError:
                raise InvalidTokenError(
                    realm=self.realm,
                    extra_attributes=self.extra_attributes,
                ) from None

        if self.resource_server is not None:
            audiences = claims.get("aud")
            if audiences is None:
                audiences = []
            elif not isinstance(audiences, list | tuple):
                audiences = [audiences]
            if self.resource_server not in audiences:
                raise InvalidTokenError(
                    realm=self.realm,
                    extra_attributes=self.extra_attributes,
                )
