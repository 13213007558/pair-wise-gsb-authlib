from ..rfc6749 import OAuth2Error

__all__ = ["InvalidTargetError"]


class InvalidTargetError(OAuth2Error):
    """The requested resource indicator is invalid, or the client is not
    authorized to request it.

    Per :rfc:`RFC 8707 §2.2 <8707#section-2.2>`, the authorization server
    rejects an authorization request with an invalid ``resource`` parameter
    by redirecting the error to the client. At the token endpoint it answers
    with an HTTP 400 response.
    """

    error = "invalid_target"
