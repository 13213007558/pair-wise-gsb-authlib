"""Validation of the ``resource`` parameter of :rfc:`8707`.

A resource indicator is an absolute URI with no fragment component. It only
identifies a resource; the authorization server never accesses the address.
The same ``resource`` parameter may be sent several times, so all its values
must be preserved.
"""

from urllib.parse import urlparse

from .errors import InvalidTargetError

__all__ = ["get_resource_indicators", "validate_resource_indicator"]


def get_resource_indicators(payload):
    """Return all the values of the ``resource`` parameter, in order.

    Unlike :attr:`OAuth2Payload.data`, it keeps the repeated values that the
    client sent. Per :rfc:`RFC 8707 §2 <8707#section-2>`, a request can contain
    several resource indicators.

    :param payload: the ``request.payload`` of an OAuth 2 request
    :return: the list of resource indicator URIs, possibly empty
    """
    return list(payload.datalist.get("resource", []))


def validate_resource_indicator(resource, *, redirect_uri=None, state=None):
    """Validate one resource indicator.

    Per :rfc:`RFC 8707 §1.1 <8707#section-1.1>`, a resource indicator MUST be
    an absolute URI and MUST NOT include a fragment component. The identifier
    is only an identifier: the server does not fetch it, so its reachability
    is never checked.

    :param resource: the value of a ``resource`` parameter
    :param redirect_uri: the redirect URI of an authorization request, so the
        error is redirected instead of returned in the body
    :param state: the ``state`` of the authorization request
    :raises InvalidTargetError: if the resource indicator is not an absolute
        URI without fragment
    """
    if not isinstance(resource, str) or not resource:
        raise InvalidTargetError(
            "The 'resource' parameter MUST be an absolute URI.",
            redirect_uri=redirect_uri,
            state=state,
        )

    try:
        parsed = urlparse(resource)
    except ValueError:
        parsed = None

    if (
        parsed is None
        or not parsed.scheme
        or not (parsed.netloc or parsed.path)
        or "#" in resource
        or resource.strip() != resource
    ):
        raise InvalidTargetError(
            "The 'resource' parameter MUST be an absolute URI "
            "without a fragment component.",
            redirect_uri=redirect_uri,
            state=state,
        )
