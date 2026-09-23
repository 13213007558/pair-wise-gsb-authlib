"""authlib.oauth2.rfc8707.grant
~~~~~~~~~~~~~~~~~~~~~~~~~~

Resource Indicators for OAuth 2.0 grant extension.

https://www.rfc-editor.org/rfc/rfc8707
"""

from authlib.common.urls import urlparse

from .errors import InvalidTargetError


def is_valid_resource(value):
    """A "resource" parameter value MUST be an absolute URI and MUST NOT
    include a fragment component.

    https://www.rfc-editor.org/rfc/rfc8707#section-2
    """
    if not value:
        return False
    try:
        parsed = urlparse.urlparse(value)
    except ValueError:
        return False
    return bool(parsed.scheme) and not parsed.fragment


def parse_request_resources(request):
    """Extract the "resource" parameters from the request. The parameter can
    be repeated, so the multi-value semantics are preserved and duplicated
    values are removed. Returns a list of resources, or None if the request
    does not contain any "resource" parameter.
    """
    values = request.payload.datalist.get("resource") or []
    resources = []
    for value in values:
        if value not in resources:
            resources.append(value)
    return resources or None


class ResourceIndicator:
    """Resource Indicators for OAuth 2.0 extension, per RFC 8707. It allows
    clients to signal to the authorization server which protected resources
    they intend to access, so the issued tokens can be restricted to those
    resources (for instance with the "aud" claim of RFC 9068 JWT access
    tokens).

    Register it on the grants that should understand the "resource"
    parameter::

        server.register_grant(AuthorizationCodeGrant, [ResourceIndicator()])
        server.register_grant(RefreshTokenGrant, [ResourceIndicator()])

    At the authorization endpoint, the validated resources are stored on
    "request.resources", so developers MUST persist them with the
    authorization code in "save_authorization_code", and the authorization
    code model MUST expose them with a "get_resources" method. At the token
    endpoint, the client can select a subset of the granted resources; the
    selected resources are stored on "request.resources" and passed to the
    token generator. Refreshing a token can only narrow the resources
    attached to the refresh token, never expand them.

    :param validate_resources: an optional callable with the signature
        "validate_resources(grant, resources)", letting the application
        decide if the requested resources can be authorized together. It
        must return a truthy value to accept the request. An
        "invalid_target" error is raised otherwise.
    :param default_resources: the policy used to select resources when a
        token request does not contain any "resource" parameter. It can be
        a list of resource URIs, or a callable with the signature
        "default_resources(grant, resources)". The selection is always
        narrowed to the granted resources. By default, all the granted
        resources are selected.
    """

    def __init__(self, validate_resources=None, default_resources=None):
        self.validate_resources = validate_resources
        self.default_resources = default_resources

    def __call__(self, grant):
        grant.register_hook(
            "after_validate_authorization_request_payload",
            self.validate_authorization_request_resources,
        )
        grant.register_hook(
            "after_validate_token_request",
            self.validate_token_request_resources,
        )

    def validate_authorization_request_resources(self, grant, _):
        """Validate the "resource" parameters of the authorization request.
        The consented resources are stored on "request.resources" so that
        "save_authorization_code" can persist them with the authorization
        code.
        """
        request = grant.request
        resources = parse_request_resources(request)
        if resources is None:
            return
        self._validate_resource_values(resources)
        self._validate_resources_policy(grant, resources)
        request.resources = resources

    def validate_token_request_resources(self, grant, _):
        """Validate the "resource" parameters of the token request. The
        requested resources can only be a subset of the resources granted
        by the authorization code or the refresh token. When the request
        does not contain any "resource" parameter, the configured default
        selection policy applies.
        """
        request = grant.request
        requested = parse_request_resources(request)
        granted = self.get_granted_resources(grant)

        if requested:
            self._validate_resource_values(requested)
            self._validate_resources_policy(grant, requested)
            if granted is not None and not set(requested).issubset(set(granted)):
                raise InvalidTargetError(
                    "The requested 'resource' is not part of the granted resources."
                )
            request.resources = requested
        elif granted:
            request.resources = self.get_default_resources(grant, granted)

    def get_granted_resources(self, grant):
        """Return the resources granted by the authorization code or the
        refresh token of the current request. Returns None when the grant
        has no credential to check the resources against (e.g. the client
        credentials grant).
        """
        request = grant.request
        credential = request.authorization_code or request.refresh_token
        if credential is None:
            return None
        get_resources = getattr(credential, "get_resources", None)
        if get_resources is None:
            return []
        return get_resources() or []

    def get_default_resources(self, grant, resources):
        """Select the resources to use when a token request does not contain
        any "resource" parameter. The selection is narrowed to the granted
        resources, so the default policy can never expand them.
        """
        if callable(self.default_resources):
            selected = self.default_resources(grant, resources)
        elif self.default_resources is not None:
            selected = self.default_resources
        else:
            selected = resources
        if isinstance(selected, str):
            selected = [selected]
        return [resource for resource in selected if resource in resources]

    def _validate_resource_values(self, resources):
        for resource in resources:
            if not is_valid_resource(resource):
                raise InvalidTargetError(
                    "The 'resource' parameter value must be an absolute URI "
                    "without a fragment component."
                )

    def _validate_resources_policy(self, grant, resources):
        if self.validate_resources is None:
            return
        if not self.validate_resources(grant, resources):
            raise InvalidTargetError(
                "The requested resources cannot be authorized together."
            )
