"""authlib.oauth2.rfc8707.util.
~~~~~~~~~~~~~~~~~~~~~~~~~~

Utilities to extract and validate the resource request parameter
defined by RFC 8707.
"""

from authlib.common.urls import urlparse

from .errors import InvalidTargetError

__all__ = ["extract_resource_parameter", "validate_resource_parameter"]


def extract_resource_parameter(payload) -> list[str]:
    """Extract the resource parameter values from a request payload.

    The resource parameter MAY be included multiple times in a request,
    each occurrence carrying a single resource indicator value. Multi-value
    semantics are preserved: every occurrence is collected, in order, and
    duplicated values are removed.

    :param payload: an OAuth2Payload instance
    :return: a list of resource indicator strings
    """
    resources = []
    for value in payload.datalist.get("resource", []):
        if isinstance(value, (list, tuple)):
            values = value
        else:
            values = [value]
        for resource in values:
            if resource and resource not in resources:
                resources.append(resource)
    return resources


def validate_resource_parameter(resources) -> None:
    """Validate resource indicator values.

    Per RFC 8707, Section 2, a resource indicator value MUST be an
    absolute URI and MUST NOT include a fragment component.

    https://www.rfc-editor.org/rfc/rfc8707.html#section-2

    :param resources: a list of resource indicator strings
    :raise InvalidTargetError: if a value is not an absolute URI or
        contains a fragment component
    """
    for resource in resources:
        try:
            parsed = urlparse.urlparse(resource)
        except ValueError:
            parsed = None
        if parsed is None or not parsed.scheme:
            raise InvalidTargetError(
                f"Invalid 'resource' value: {resource!r} is not an absolute URI."
            )
        if parsed.fragment:
            raise InvalidTargetError(
                f"Invalid 'resource' value: {resource!r} contains a fragment component."
            )
