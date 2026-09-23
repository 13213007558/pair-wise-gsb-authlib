"""authlib.oauth2.rfc8707.errors.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Implementation of the error response defined by RFC 8707,
Section 2.1.

https://www.rfc-editor.org/rfc/rfc8707.html#section-2.1
"""

from ..rfc6749.errors import OAuth2Error

__all__ = ["InvalidTargetError"]


class InvalidTargetError(OAuth2Error):
    """The requested resource is invalid, missing, unknown, or malformed.

    https://www.rfc-editor.org/rfc/rfc8707.html#section-2.1
    """

    error = "invalid_target"
