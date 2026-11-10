"""Grant extensions for the ``resource`` parameter of :rfc:`8707`.

The resource indicators requested at the authorization endpoint are stored
with the authorization code. At the token endpoint, the client can only
select a subset of them, and a refresh request can never add a resource that
was not previously authorized.
"""

from ..rfc6749 import BaseGrant
from .errors import InvalidTargetError
from .parameter import get_resource_indicators
from .parameter import validate_resource_indicator

__all__ = ["ResourceIndicators"]


class ResourceIndicators:
    """Authorization server extension for :rfc:`8707` resource indicators.

    Register it on the grants that must honor the ``resource`` parameter::

        server.register_grant(AuthorizationCodeGrant, [ResourceIndicators()])
        server.register_grant(RefreshTokenGrant, [ResourceIndicators()])

    The extension validates every ``resource`` value as an absolute URI
    without a fragment, keeps all the repeated values, and exposes the final
    authorized set to the token generator through its ``resource`` keyword.

    :param allow_without_resource: how to behave when a request contains no
        ``resource`` parameter. When ``False`` (the default), such a request
        is rejected with ``invalid_target``. When ``True``, the request keeps
        the legacy behavior and gets no resource indicator. The choice is
        always explicit, per :rfc:`RFC 8707 §5 <8707#section-5>`.
    """

    def __init__(self, allow_without_resource=False):
        self.allow_without_resource = allow_without_resource

    def __call__(self, grant):
        if grant.GRANT_TYPE == "authorization_code":
            grant.register_authorization_parameters(
                {"resource": str}, repeated=("resource",)
            )
        grant.register_hook(
            self.pass_resources_to_token_generator,
            replace=BaseGrant.generate_token,
        )

        if grant.GRANT_TYPE == "authorization_code":
            grant.register_hook(
                self.validate_authorization_resources,
                after=grant.validate_authorization_request_payload,
            )
            grant.register_hook(
                self.validate_token_resources,
                after=grant.validate_token_request,
            )
        elif grant.GRANT_TYPE == "refresh_token":
            grant.register_hook(
                self.validate_refresh_resources,
                after=grant.validate_token_request,
            )

    # -- authorization endpoint -- #

    def validate_authorization_resources(self, grant, redirect_uri):
        """Validate the resource indicators of an authorization request and
        remember them on the request, so ``save_authorization_code`` can store
        them with the code.

        :raises InvalidTargetError: if a resource indicator is invalid, if the
            client is not allowed to use one, or if no resource was requested
            while :attr:`allow_without_resource` is ``False``.
        """
        request = grant.request
        resources = get_resource_indicators(request.payload)
        state = request.payload.state

        if not resources:
            if self.allow_without_resource:
                request.resources = None
                return
            raise InvalidTargetError(
                "Missing 'resource' parameter.",
                redirect_uri=redirect_uri,
                state=state,
            )

        self._validate_resources(
            grant, resources, redirect_uri=redirect_uri, state=state
        )
        request.resources = list(resources)

    # -- token endpoint, authorization code -- #

    def validate_token_resources(self, grant, result):
        """Check that the resources requested when exchanging a code were
        authorized for that code, and compute the audience of the new token.

        Per :rfc:`RFC 8707 §2.1 <8707#section-2.1>`, every requested resource
        MUST be one of the indicators bound to the authorization code. Without
        a ``resource`` parameter, the whole set of the code is used.
        """
        request = grant.request
        requested = get_resource_indicators(request.payload)
        authorized = self.get_authorization_code_resources(request.authorization_code)

        request.resources = self._select_resources(grant, requested, authorized)

    # -- token endpoint, refresh -- #

    def validate_refresh_resources(self, grant, result):
        """Check that a refresh request stays within the resources of the
        refresh token.

        Per :rfc:`RFC 8707 §2.2.1 <8707#section-2.2.1>`, a refresh request
        cannot obtain a resource indicator that was not in the original
        request. Without a ``resource`` parameter, the new token keeps the
        resources of the previous one.
        """
        request = grant.request
        requested = get_resource_indicators(request.payload)
        authorized = self.get_token_resources(request.refresh_token)

        request.resources = self._select_resources(grant, requested, authorized)

    # -- storage helpers, to override in a subclass -- #

    def get_authorization_code_resources(self, authorization_code):
        """Return the resource indicators stored with an authorization code.

        Developers MAY re-implement it to match their storage::

            def get_authorization_code_resources(self, authorization_code):
                return authorization_code.get_resources()

        :param authorization_code: the authorization code of the request
        :return: a list of resource indicator URIs, or ``None``
        """
        return authorization_code.get_resources()

    def get_token_resources(self, token):
        """Return the resource indicators stored with a refresh token.

        Developers MAY re-implement it to match their storage::

            def get_token_resources(self, token):
                return token.get_resources()

        :param token: the token of the refresh request
        :return: a list of resource indicator URIs, or ``None``
        """
        return token.get_resources()

    # -- policy hook -- #

    def validate_client_resource(self, client, resource):
        """Tell if a client may request a resource indicator.

        Override it to restrict some resources to some clients. The default
        implementation allows every syntactically valid indicator, as allowed
        by :rfc:`RFC 8707 §4 <8707#section-4>`.

        :param client: the client of the request
        :param resource: an absolute URI without fragment
        :return: ``True`` if the client may use the resource indicator
        """
        return True

    # -- token generation -- #

    def pass_resources_to_token_generator(self, grant, original, **kwargs):
        """Pass the authorized resource set to the token generator.

        The authorization server forwards it only to generators that accept a
        ``resource`` keyword, such as a JWT generator that builds its ``aud``
        claim. Generators with the legacy signature are called unchanged, so
        existing applications keep working.
        """
        resources = getattr(grant.request, "resources", None)
        if resources is not None:
            kwargs["resource"] = list(resources)
        return original(**kwargs)

    # -- internals -- #

    def _validate_resources(self, grant, resources, *, redirect_uri, state):
        for resource in resources:
            validate_resource_indicator(
                resource, redirect_uri=redirect_uri, state=state
            )
            if not self.validate_client_resource(grant.client, resource):
                raise InvalidTargetError(
                    f"The client is not authorized to request '{resource}'.",
                    redirect_uri=redirect_uri,
                    state=state,
                )

    def _select_resources(self, grant, requested, authorized):
        if not requested:
            if authorized:
                return list(authorized)
            if self.allow_without_resource:
                return None
            raise InvalidTargetError("Missing 'resource' parameter.")

        for resource in requested:
            validate_resource_indicator(resource)

        if not authorized:
            raise InvalidTargetError(
                "The authorization grant has no resource indicator."
            )

        authorized_set = set(authorized)
        for resource in requested:
            if resource not in authorized_set:
                raise InvalidTargetError(
                    f"The resource '{resource}' was not authorized."
                )

        client = grant.client
        for resource in requested:
            if not self.validate_client_resource(client, resource):
                raise InvalidTargetError(
                    f"The client is not authorized to request '{resource}'."
                )

        return list(requested)
