"""authlib.oauth2.rfc9449.errors.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

DPoP error responses per RFC 9449. The token endpoint responds with
HTTP 400 and a JSON body, the resource server responds with HTTP 401
and a "WWW-Authenticate: DPoP" header. A "DPoP-Nonce" header is added
whenever the server challenges the client with a nonce.

https://www.rfc-editor.org/rfc/rfc9449#section-7.1
"""

from ..rfc6749.errors import OAuth2Error

__all__ = ["InvalidDPoPProofError", "UseDPoPNonceError", "InvalidDPoPTokenError"]


class DPoPError(OAuth2Error):
    """Base error for DPoP related failures."""

    status_code = 400

    def __init__(
        self,
        description=None,
        nonce=None,
        status_code=None,
        realm=None,
        extra_attributes=None,
    ):
        super().__init__(description, status_code=status_code)
        self.nonce = nonce
        self.realm = realm
        self.extra_attributes = extra_attributes or {}

    def get_headers(self):
        headers = super().get_headers()
        if self.status_code == 401:
            extras = []
            if self.realm:
                extras.append(f'realm="{self.realm}"')
            extras.extend(
                [f'{k}="{self.extra_attributes[k]}"' for k in self.extra_attributes]
            )
            extras.append(f'error="{self.error}"')
            error_description = self.get_error_description()
            extras.append(f'error_description="{error_description}"')
            headers.append(("WWW-Authenticate", "DPoP " + ", ".join(extras)))
        if self.nonce:
            headers.append(("DPoP-Nonce", self.nonce))
        return headers


class InvalidDPoPProofError(DPoPError):
    """The DPoP proof is invalid, e.g. it is malformed, has an invalid
    signature, is reused, or does not match the HTTP request.

    https://www.rfc-editor.org/rfc/rfc9449#section-7.1
    """

    error = "invalid_dpop_proof"
    description = "The DPoP proof is invalid."


class UseDPoPNonceError(DPoPError):
    """The authorization or resource server requires a nonce in the DPoP
    proof. The expected nonce value is returned in the "DPoP-Nonce"
    header, the client MUST retry with a new proof.

    https://www.rfc-editor.org/rfc/rfc9449#section-8
    """

    error = "use_dpop_nonce"
    description = "The server requires a nonce in the DPoP proof."


class InvalidDPoPTokenError(DPoPError):
    """The access token provided is expired, revoked, malformed, not
    DPoP bound, or invalid for other reasons.

    https://www.rfc-editor.org/rfc/rfc9449#section-7.1
    """

    error = "invalid_token"
    description = (
        "The access token provided is expired, revoked, malformed, "
        "or invalid for other reasons."
    )
    status_code = 401
