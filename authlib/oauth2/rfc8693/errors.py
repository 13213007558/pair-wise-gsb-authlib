"""authlib.oauth2.rfc8693.errors.
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Error responses defined by OAuth 2.0 Token Exchange.

https://tools.ietf.org/html/rfc8693#section-2.2.2
"""

from ..rfc6749.errors import OAuth2Error

__all__ = ["InvalidTargetError"]


class InvalidTargetError(OAuth2Error):
    """The specified resource or audience is invalid, malformed, or not
    allowed by the authorization server policy.

    https://tools.ietf.org/html/rfc8693#section-2.2.2
    """

    error = "invalid_target"
