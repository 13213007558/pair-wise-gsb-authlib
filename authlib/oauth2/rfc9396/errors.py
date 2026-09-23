from authlib.oauth2.base import OAuth2Error

__all__ = ["InvalidAuthorizationDetailsError"]


class InvalidAuthorizationDetailsError(OAuth2Error):
    """The ``authorization_details`` request parameter contains an unknown
    or unsupported ``type``, an invalid entry for its ``type``, or asks
    for more than what has been granted. Per `RFC 9396`_.

    .. _`RFC 9396`: https://www.rfc-editor.org/rfc/rfc9396
    """

    error = "invalid_authorization_details"
