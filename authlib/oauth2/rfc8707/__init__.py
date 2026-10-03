"""authlib.oauth2.rfc8707.
~~~~~~~~~~~~~~~~~~~~~~~

Implementation of Resource Indicators for OAuth 2.0 per RFC 8707.

This module provides:

* :class:`InvalidTargetError`: the ``invalid_target`` protocol error.
* :func:`validate_resource_indicator`: syntax validation of a single
  ``resource`` parameter value.
* :func:`parse_resource_indicators`: extraction of every ``resource``
  parameter value from a request payload, without losing repeated
  values.

https://www.rfc-editor.org/rfc/rfc8707.html
"""

from authlib.common.urls import urlparse
from authlib.oauth2.base import OAuth2Error

__all__ = [
    "InvalidTargetError",
    "validate_resource_indicator",
    "parse_resource_indicators",
]


class InvalidTargetError(OAuth2Error):
    """The requested resource is invalid, unknown, malformed, or exceeds
    the set of resources the client is allowed to request. Defined in
    `Section 2.4.1`_ of RFC 8707.

    .. _`Section 2.4.1`: https://www.rfc-editor.org/rfc/rfc8707.html#section-2.4.1
    """

    error = "invalid_target"
    description = "The requested resource is invalid, missing, unknown, or malformed."


def validate_resource_indicator(value):
    """Validate the syntax of a single ``resource`` parameter value.

    Per RFC 8707 `Section 2`_, the value MUST be an absolute URI and
    MUST NOT include a fragment component.

    :param value: the ``resource`` parameter value.
    :return: the validated value.
    :raise InvalidTargetError: if the value is not a valid resource indicator.

    .. _`Section 2`: https://www.rfc-editor.org/rfc/rfc8707.html#section-2
    """
    if not value or not isinstance(value, str):
        raise InvalidTargetError(
            description="The 'resource' parameter value MUST be a non-empty string."
        )

    parts = urlparse.urlparse(value)
    if not parts.scheme:
        raise InvalidTargetError(
            description=f"The 'resource' value {value!r} is not an absolute URI."
        )
    if parts.fragment:
        raise InvalidTargetError(
            description=f"The 'resource' value {value!r} MUST NOT contain a fragment."
        )
    return value


def parse_resource_indicators(datalist):
    """Extract and validate every ``resource`` parameter value from a
    request payload ``datalist``.

    The ``resource`` parameter MAY be repeated in authorization and token
    requests, so values MUST be read from the multi-value ``datalist``
    mapping instead of a single-value dictionary.

    :param datalist: a mapping of parameter names to lists of values.
    :return: a list of unique resource indicators, preserving the
        original order. An empty list means the request did not contain
        any ``resource`` parameter.
    :raise InvalidTargetError: if any value is malformed.
    """
    resources = []
    for value in datalist.get("resource") or []:
        validate_resource_indicator(value)
        if value not in resources:
            resources.append(value)
    return resources
