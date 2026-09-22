from authlib.common.errors import AuthlibBaseError


class BackChannelLogoutError(AuthlibBaseError):
    error = "backchannel_logout_error"


class InvalidLogoutTokenError(BackChannelLogoutError):
    error = "invalid_logout_token"
    description = "The logout token is not valid."


class SessionIdentityMismatchError(BackChannelLogoutError):
    error = "session_identity_mismatch"
    description = "The 'sid' and 'sub' claims do not identify the same session."
