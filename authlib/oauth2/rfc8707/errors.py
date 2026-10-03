"""Errors defined by RFC 8707 (Resource Indicators for OAuth 2.0).

The ``invalid_target`` error code is used both at the authorization
endpoint (delivered via redirect) and at the token endpoint.

https://www.rfc-editor.org/rfc/rfc8707.html#section-4
"""

from ..rfc6749.errors import OAuth2Error

__all__ = ["InvalidTargetError"]


class InvalidTargetError(OAuth2Error):
    """The requested resource indicator is invalid or not accepted by the
    authorization server.

    * At the authorization endpoint, the error is returned to the client via
      the redirection URI, per RFC 8707 Section 2.1.
    * At the token endpoint, the error is returned in the JSON response body
      with an HTTP 400 status code, per RFC 8707 Sections 2.2 and 3.
    """

    error = "invalid_target"
    description = "The requested resource indicator is invalid or unauthorized."
    status_code = 400
