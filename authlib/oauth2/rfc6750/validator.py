"""authlib.oauth2.rfc6750.validator.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Validate Bearer Token for in request, scope and token.
"""

from ..rfc6749 import TokenValidator
from .errors import InsufficientScopeError
from .errors import InvalidTokenError


class BearerTokenValidator(TokenValidator):
    TOKEN_TYPE = "bearer"

    def __init__(self, realm=None, resource_server=None, **extra_attributes):
        super().__init__(realm, **extra_attributes)
        #: An identifier for the current resource server. When set, tokens
        #: whose RFC 8707 resources do not contain this identifier are
        #: rejected, even if their scope is sufficient.
        self.resource_server = resource_server

    def authenticate_token(self, token_string):
        """A method to query token from database with the given token string.
        Developers MUST re-implement this method. For instance::

            def authenticate_token(self, token_string):
                return get_token_from_database(token_string)

        :param token_string: A string to represent the access_token.
        :return: token
        """
        raise NotImplementedError()

    def validate_token(self, token, scopes, request):
        """Check if token is active and matches the requested scopes."""
        if not token:
            raise InvalidTokenError(
                realm=self.realm, extra_attributes=self.extra_attributes
            )
        if token.is_expired():
            raise InvalidTokenError(
                realm=self.realm, extra_attributes=self.extra_attributes
            )
        if token.is_revoked():
            raise InvalidTokenError(
                realm=self.realm, extra_attributes=self.extra_attributes
            )
        if self.scope_insufficient(token.get_scope(), scopes):
            raise InsufficientScopeError()
        self.validate_resources(token)

    def validate_resources(self, token):
        """Check if the token targets this resource server. When the
        validator is configured with a ``resource_server`` identifier, the
        token MUST carry that identifier in its RFC 8707 resources.

        :param token: the token instance returned by ``authenticate_token``.
        :raise InvalidTokenError: if the token audience does not match.
        """
        if self.resource_server is None:
            return
        resources = token.get_resources() or []
        if self.resource_server not in resources:
            raise InvalidTokenError(
                realm=self.realm, extra_attributes=self.extra_attributes
            )
