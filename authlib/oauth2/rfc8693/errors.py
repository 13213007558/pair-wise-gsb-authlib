"""Errors specific to OAuth 2.0 Token Exchange.

:rfc:`8693#section-2.2.2` only adds one error code to the OAuth 2.0 error
registry. Every other failure reuses the standard errors from
:mod:`authlib.oauth2.rfc6749.errors`, so clients keep receiving the usual
OAuth error shape.
"""

from ..rfc6749.errors import OAuth2Error

__all__ = ["InvalidTargetError"]


class InvalidTargetError(OAuth2Error):
    """The requested target, audience or resource is not accepted by the
    authorization server.

    :rfc:`8693#section-2.2.2`
    """

    error = "invalid_target"
    description = "The requested audience or resource is not valid for this exchange."
