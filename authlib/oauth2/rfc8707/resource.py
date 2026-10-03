"""Resource indicators helpers and authorization policy per RFC 8707.

https://www.rfc-editor.org/rfc/rfc8707.html
"""

from urllib.parse import urlsplit

from .errors import InvalidTargetError

__all__ = [
    "ResourcePolicy",
    "get_resource_indicators",
    "is_absolute_uri",
    "unique_resource_indicators",
    "validate_resource_indicators",
]


def is_absolute_uri(value):
    """Check whether ``value`` is an absolute URI usable as a resource indicator.

    Per RFC 8707 Section 2, every ``resource`` parameter MUST be an absolute
    URI (as defined by Section 4.3 of RFC 3986) that MUST NOT contain a
    fragment component.
    """
    if not isinstance(value, str) or not value:
        return False
    if any(char.isspace() for char in value):
        return False
    try:
        parts = urlsplit(value)
    except ValueError:
        return False
    if not parts.scheme or not parts.netloc or parts.fragment:
        return False
    if not parts.scheme[0].isalpha():
        return False
    return True


def get_resource_indicators(payload):
    """Return every ``resource`` parameter value of the request, in order.

    The ``resource`` parameter can be repeated, so this MUST be read from the
    multi-valued ``datalist`` (never from the single-valued ``data`` mapping,
    which would silently drop values).
    """
    return list(payload.datalist.get("resource", []))


def validate_resource_indicators(resources):
    """Validate that every resource indicator is an absolute URI without a
    fragment (RFC 8707 Section 2).

    :raises InvalidTargetError: if one of the values is not a valid URI.
    """
    for resource in resources:
        if not is_absolute_uri(resource):
            raise InvalidTargetError(
                "The resource indicator MUST be an absolute URI without a fragment."
            )


def unique_resource_indicators(resources):
    """Remove duplicate resource indicators while preserving their order."""
    return list(dict.fromkeys(resources))


class ResourcePolicy:
    """Strategy deciding which resource indicators can be authorized for a
    client, and which resources a token targets when the client does not ask
    explicitly.

    Configure one on the authorization server with::

        authorization_server.register_resource_policy(MyResourcePolicy())

    Subclasses MUST implement :meth:`get_allowed_resources`. Implementing
    :meth:`get_default_resources` is optional; by default tokens issued without
    an explicit ``resource`` parameter are not bound to *any* resource. This is
    deliberate: RFC 8707 forbids silently defaulting to all authorized
    resources.
    """

    def get_allowed_resources(self, client, resources, request):
        """Return the subset of requested ``resources`` that can be authorized
        for ``client``, in order.

        :param client: the OAuth 2 client making the request.
        :param resources: list of resource indicators requested by the client.
        :param request: the current OAuth2Request instance.
        :return: list of authorized resource indicators.
        :raises InvalidTargetError: if any requested resource cannot be
            authorized.
        """
        raise NotImplementedError()

    def get_default_resources(self, client, request, authorized_resources=None):
        """Resolve the resources of a token when the request does not include a
        ``resource`` parameter.

        :param client: the OAuth 2 client making the request.
        :param request: the current OAuth2Request instance.
        :param authorized_resources: resources consented at the authorization
            endpoint (authorization code grant) or bound to the credential
            being refreshed, when applicable.
        :return: list of resource indicators for the new token. Defaults to an
            empty list, which MUST NOT be interpreted as "all resources".
        """
        return []
