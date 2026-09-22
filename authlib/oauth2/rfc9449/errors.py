"""authlib.oauth2.rfc9449.errors.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Error definitions for OAuth 2.0 Demonstrating Proof of Possession (DPoP),
per RFC 9449 Sections 5.1 and 7.1.

https://www.rfc-editor.org/rfc/rfc9449.html
"""

from ..base import OAuth2Error

__all__ = [
    "InvalidDPoPProofError",
    "InvalidDPoPTokenError",
    "UseDPoPNonceError",
]


class DPoPError(OAuth2Error):
    """Base error for DPoP related failures. It can carry a fresh server
    nonce in the ``DPoP-Nonce`` response header, per RFC 9449 Section 8.
    """

    def __init__(self, description=None, nonce=None, **kwargs):
        super().__init__(description=description, **kwargs)
        self.nonce = nonce

    def get_headers(self):
        headers = super().get_headers()
        if self.nonce:
            headers.append(("DPoP-Nonce", self.nonce))
        return headers


class InvalidDPoPProofError(DPoPError):
    """The DPoP proof JWT is invalid. Used by the token endpoint, which
    responds with HTTP 400 and the ``invalid_dpop_proof`` error code,
    per RFC 9449 Section 5.1.
    """

    error = "invalid_dpop_proof"
    status_code = 400
    description = "The DPoP proof is invalid."


class UseDPoPNonceError(DPoPError):
    """The authorization or resource server requires a fresh server nonce
    in the DPoP proof, per RFC 9449 Section 8. The new nonce value is
    transported in the ``DPoP-Nonce`` response header.
    """

    error = "use_dpop_nonce"
    status_code = 400
    description = "The server requires a nonce in the DPoP proof."


class InvalidDPoPTokenError(DPoPError):
    """The DPoP-bound access token or the DPoP proof is invalid on a
    protected resource request. The resource server responds with HTTP 401
    and a ``WWW-Authenticate: DPoP`` challenge, per RFC 9449 Section 7.1.
    """

    error = "invalid_token"
    status_code = 401
    description = (
        "The access token provided is expired, revoked, malformed, "
        "or invalid for other reasons."
    )

    def __init__(self, description=None, nonce=None, realm=None, **kwargs):
        super().__init__(description=description, nonce=nonce, **kwargs)
        self.realm = realm

    def get_headers(self):
        headers = super().get_headers()
        extras = []
        if self.realm:
            extras.append(f'realm="{self.realm}"')
        extras.append(f'error="{self.error}"')
        error_description = self.get_error_description()
        extras.append(f'error_description="{error_description}"')
        headers.append(("WWW-Authenticate", "DPoP " + ", ".join(extras)))
        return headers
