"""authlib.oauth2.rfc8707.errors
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Error response defined by RFC 8707.

https://www.rfc-editor.org/rfc/rfc8707
"""

from ..rfc6749.errors import OAuth2Error


class InvalidTargetError(OAuth2Error):
    """The requested resource is invalid, missing, unknown, or malformed.

    The authorization server can use this error code at the authorization
    endpoint and at the token endpoint when a "resource" parameter does
    not satisfy the requirements of RFC 8707, or when the requested
    resource is not part of the resources granted to the client.

    https://www.rfc-editor.org/rfc/rfc8707#section-2.2
    """

    error = "invalid_target"
