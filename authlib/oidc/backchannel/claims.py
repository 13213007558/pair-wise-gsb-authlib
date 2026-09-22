"""OpenID Connect Back-Channel Logout 1.0 Logout Token claims.

https://openid.net/specs/openid-connect-backchannel-1_0.html#LogoutToken
"""

from joserfc.errors import InvalidClaimError
from joserfc.errors import JoseError
from joserfc.errors import MissingClaimError

from authlib.oauth2.claims import JWTClaims

__all__ = ["BACKCHANNEL_LOGOUT_EVENT", "LogoutToken", "MissingSessionIdentifierError"]

#: The event URI that MUST be present in the "events" claim of a Logout Token.
BACKCHANNEL_LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout"


class MissingSessionIdentifierError(JoseError):
    """A Logout Token MUST contain either a "sub" or a "sid" claim."""

    error = "missing_claim"
    description = 'Missing claim: "sub" or "sid" is required'


class LogoutToken(JWTClaims):
    """Claims of an OpenID Back-Channel Logout Token.

    Per Section 2.4 of the specification, a Logout Token is a JWT with
    "iss", "aud", "iat", "exp", "jti" and "events" claims, and either a
    "sub" or a "sid" claim (or both). A "nonce" claim MUST NOT be present.

    https://openid.net/specs/openid-connect-backchannel-1_0.html#LogoutToken
    """

    ESSENTIAL_CLAIMS = ["iss", "aud", "iat", "exp", "jti", "events"]

    def validate(self, now=None, leeway=0):
        for k in self.ESSENTIAL_CLAIMS:
            if k not in self:
                raise MissingClaimError(k)

        super().validate(now, leeway)
        self.validate_events()
        self.validate_nonce()
        self.validate_sub_and_sid()

    def validate_events(self):
        """The "events" claim MUST be a JSON object containing the member
        "http://schemas.openid.net/event/backchannel-logout" with a JSON
        object value.
        """
        events = self.get("events")
        if not isinstance(events, dict) or BACKCHANNEL_LOGOUT_EVENT not in events:
            raise InvalidClaimError("events")
        if not isinstance(events[BACKCHANNEL_LOGOUT_EVENT], dict):
            raise InvalidClaimError("events")

    def validate_nonce(self):
        """A "nonce" claim is PROHIBITED in a Logout Token."""
        if "nonce" in self:
            raise InvalidClaimError("nonce")

    def validate_sub_and_sid(self):
        """A Logout Token MUST contain either a "sub" or a "sid" claim,
        and MAY contain both.
        """
        if "sub" not in self and "sid" not in self:
            raise MissingSessionIdentifierError()
