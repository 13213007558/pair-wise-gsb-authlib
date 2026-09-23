"""authlib.oauth2.rfc8707.grants.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Implementation of Resource Indicators for OAuth 2.0, per RFC 8707.

https://www.rfc-editor.org/rfc/rfc8707.html
"""

import logging

from ..rfc6749.errors import InvalidGrantError
from ..rfc6749.errors import OAuth2Error
from ..rfc6749.grants import AuthorizationCodeGrant as _AuthorizationCodeGrant
from ..rfc6749.grants import RefreshTokenGrant as _RefreshTokenGrant
from ..rfc6749.hooks import hooked
from .errors import InvalidTargetError
from .util import extract_resource_parameter
from .util import validate_resource_parameter

log = logging.getLogger(__name__)


class ResourceIndicatorMixin:
    """Shared logic to validate the resource parameter defined by RFC 8707.

    The validated resource selection is passed to the token generator as
    the "resources" argument, it is never folded into the "scope" value.
    """

    def get_allowed_resources(self, client, resources):
        """Get the resources the client is allowed to be authorized for.
        The application decides which resources may be requested, and which
        resources may be authorized together. Developers MAY re-implement
        this method, e.g.::

            def get_allowed_resources(self, client, resources):
                allowed = {"https://api1.example.com", "https://api2.example.com"}
                if not set(resources).issubset(allowed):
                    raise InvalidTargetError()
                if len(resources) > 1:
                    raise InvalidTargetError("Resources cannot be combined.")
                return resources

        :param client: the client making the request
        :param resources: the requested resource indicators
        :return: the allowed resource indicators
        """
        return resources

    def validate_requested_resources(self, resources):
        """Validate the requested resource indicators: values MUST be
        absolute URIs without a fragment component, and the application
        policy decides which resources can be authorized together.

        :param resources: the requested resource indicators
        :return: the allowed resource indicators
        """
        validate_resource_parameter(resources)
        return self.get_allowed_resources(self.request.client, resources)


class AuthorizationCodeGrant(ResourceIndicatorMixin, _AuthorizationCodeGrant):
    """Authorization code grant with support for the resource parameter
    defined by RFC 8707. Register it instead of the RFC 6749 grant::

        from authlib.oauth2.rfc8707 import AuthorizationCodeGrant


        class MyAuthorizationCodeGrant(AuthorizationCodeGrant):
            def save_authorization_code(self, code, request):
                # save request.resources alongside the code
                ...


        authorization_server.register_grant(MyAuthorizationCodeGrant)

    The authorization code model MUST implement
    :class:`authlib.oauth2.rfc8707.AuthorizationCodeMixin` so the
    consented resources are available at the token endpoint.
    """

    def validate_authorization_request(self):
        """Validate the resource parameter of the authorization request.
        The parameter MAY appear multiple times, every value MUST be an
        absolute URI without a fragment component. The validated resources
        are stored on request.resources so that save_authorization_code
        can persist the consented set.
        """
        redirect_uri = super().validate_authorization_request()
        try:
            resources = extract_resource_parameter(self.request.payload)
            self.request.resources = self.validate_requested_resources(resources)
        except OAuth2Error as error:
            error.redirect_uri = redirect_uri
            raise
        return redirect_uri

    def validate_token_request(self):
        super().validate_token_request()
        self.request.resources = self.validate_requested_token_resources()

    def validate_requested_token_resources(self):
        """Resolve the resource indicators for the token request. The
        client MAY request a subset of the resources consented during the
        authorization request. When the resource parameter is omitted, the
        server default selection policy applies, see
        :meth:`get_default_resources`.
        """
        client = self.request.client
        authorization_code = self.request.authorization_code
        requested = extract_resource_parameter(self.request.payload)
        consented = authorization_code.get_resources() or []
        if requested:
            if consented and not set(requested).issubset(set(consented)):
                raise InvalidTargetError(
                    "The requested 'resource' is not part of the resources "
                    "granted with the authorization code."
                )
            resources = self.validate_requested_resources(requested)
        else:
            resources = self.get_default_resources(client, authorization_code)
        return resources or None

    def get_default_resources(self, client, authorization_code):
        """The default resource selection policy used when the token
        request does not contain a resource parameter. By default, all the
        resources consented during the authorization request are selected.
        Developers MAY re-implement this method to explicitly configure
        another policy, e.g. issuing tokens for a single default resource::

            def get_default_resources(self, client, authorization_code):
                return ["https://api.example.com"]

        :param client: the client making the request
        :param authorization_code: the authorization code being exchanged
        :return: a list of resource indicator strings
        """
        return authorization_code.get_resources()

    @hooked
    def create_token_response(self):
        client = self.request.client
        authorization_code = self.request.authorization_code

        user = self.authenticate_user(authorization_code)
        if not user:
            raise InvalidGrantError("There is no 'user' for this code.")
        self.request.user = user

        scope = authorization_code.get_scope()
        token = self.generate_token(
            user=user,
            scope=scope,
            resources=self.request.resources,
            include_refresh_token=client.check_grant_type("refresh_token"),
        )
        log.debug("Issue token %r to %r", token, client)

        self.save_token(token)
        self.delete_authorization_code(authorization_code)
        return 200, token, self.TOKEN_RESPONSE_HEADER


class RefreshTokenGrant(ResourceIndicatorMixin, _RefreshTokenGrant):
    """Refresh token grant with support for the resource parameter defined
    by RFC 8707. A refresh request MAY select a subset of the resources the
    original token was issued for, it can never widen that set. The token
    model MUST implement :class:`authlib.oauth2.rfc8707.TokenMixin`::

        from authlib.oauth2.rfc8707 import RefreshTokenGrant


        class MyRefreshTokenGrant(RefreshTokenGrant):
            ...


        authorization_server.register_grant(MyRefreshTokenGrant)
    """

    def validate_token_request(self):
        super().validate_token_request()
        self.request.resources = self.validate_requested_token_resources()

    def validate_requested_token_resources(self):
        """Resolve the resource indicators for the refresh request. The
        requested resources MUST NOT exceed the resources the original
        token was issued for. When the resource parameter is omitted, the
        original resources are kept.
        """
        refresh_token = self.request.refresh_token
        requested = extract_resource_parameter(self.request.payload)
        validate_resource_parameter(requested)
        original = refresh_token.get_resources() or []
        if requested:
            if not set(requested).issubset(set(original)):
                raise InvalidTargetError(
                    "The requested 'resource' exceeds the resources "
                    "originally granted to the refresh token."
                )
            resources = requested
        else:
            resources = original
        return resources or None

    def issue_token(self, user, refresh_token):
        scope = self.request.payload.scope
        if not scope:
            scope = refresh_token.get_scope()
        return self.generate_token(
            user=user,
            scope=scope,
            resources=self.request.resources,
            include_refresh_token=self.INCLUDE_NEW_REFRESH_TOKEN,
        )
