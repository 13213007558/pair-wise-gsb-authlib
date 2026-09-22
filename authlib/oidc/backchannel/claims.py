from __future__ import annotations

from joserfc.errors import InvalidClaimError
from joserfc.errors import MissingClaimError

from authlib.oauth2.claims import JWTClaims

LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout"


class LogoutTokenClaims(JWTClaims):
    REGISTERED_CLAIMS = [
        "iss",
        "sub",
        "aud",
        "exp",
        "nbf",
        "iat",
        "jti",
        "events",
        "sid",
    ]

    def validate(self, now=None, leeway=0):
        super().validate(now=now, leeway=leeway)
        self.validate_nonce_absent()
        self.validate_logout_event()
        self.validate_session_claims()

    def validate_nonce_absent(self):
        if "nonce" in self:
            raise InvalidClaimError("nonce")

    def validate_logout_event(self):
        events = self.get("events")
        if not isinstance(events, dict):
            raise InvalidClaimError("events")
        if set(events) != {LOGOUT_EVENT}:
            raise InvalidClaimError("events")
        if events[LOGOUT_EVENT] != {}:
            raise InvalidClaimError("events")

    def validate_session_claims(self):
        sid = self.get("sid")
        sub = self.get("sub")

        if sid is None and sub is None:
            raise MissingClaimError("sid")
        if sid is not None and not isinstance(sid, str):
            raise InvalidClaimError("sid")
        if sub is not None and not isinstance(sub, str):
            raise InvalidClaimError("sub")
        if sid is not None and not sid:
            raise InvalidClaimError("sid")
        if sub is not None and not sub:
            raise InvalidClaimError("sub")
