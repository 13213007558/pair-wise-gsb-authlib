from ..rfc6749.errors import OAuth2Error

__all__ = ["InvalidAuthorizationDetailsError"]


class InvalidAuthorizationDetailsError(OAuth2Error):
    """The `authorization_details` parameter is malformed: it is not a
    valid JSON array of objects, an object is missing its `type` field,
    the `type` is not registered on the server, or the registered type
    handler rejected the object.

    Note that requesting *more* than what was granted is NOT reported with
    this error; such widening attempts are rejected with `invalid_scope`,
    so that syntax errors and privilege escalation stay distinguishable.

    https://www.rfc-editor.org/rfc/rfc9396#section-5.1
    """

    error = "invalid_authorization_details"
