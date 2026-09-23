"""authlib.oauth2.rfc9449.errors.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Error responses for DPoP per RFC 9449 Section 5.2 (token endpoint)
and Section 7.1 (resource server).
"""

from ..base import OAuth2Error
from ..rfc6750.errors import InvalidTokenError


class InvalidDPoPProofError(OAuth2Error):
    """The DPoP proof presented at the token endpoint is invalid.
    Defined by RFC 9449 Section 5.2, responded with HTTP 400.
    """

    error = "invalid_dpop_proof"
    description = "The DPoP proof is invalid."
    status_code = 400


class UseDPoPNonceError(OAuth2Error):
    """The authorization server requires a fresh nonce in the DPoP
    proof. The new nonce value is delivered in the 'DPoP-Nonce'
    response header. Defined by RFC 9449 Section 5.2.
    """

    error = "use_dpop_nonce"
    description = "The authorization server requires a nonce in the DPoP proof."
    status_code = 400

    def __init__(self, nonce, description=None, **kwargs):
        super().__init__(description=description, **kwargs)
        self.nonce = nonce

    def get_headers(self):
        headers = super().get_headers()
        headers.append(("DPoP-Nonce", self.nonce))
        return headers


class DPoPInvalidTokenError(InvalidTokenError):
    """Invalid token error for the resource server, using the 'DPoP'
    authentication scheme in the 'WWW-Authenticate' response header
    per RFC 9449 Section 7.1.
    """

    def get_headers(self):
        headers = OAuth2Error.get_headers(self)
        extras = []
        if self.realm:
            extras.append(f'realm="{self.realm}"')
        if self.extra_attributes:
            extras.extend(
                [f'{k}="{self.extra_attributes[k]}"' for k in self.extra_attributes]
            )
        extras.append(f'error="{self.error}"')
        error_description = self.get_error_description()
        extras.append(f'error_description="{error_description}"')
        headers.append(("WWW-Authenticate", "DPoP " + ", ".join(extras)))
        return headers


class DPoPUseNonceError(DPoPInvalidTokenError):
    """The resource server requires a fresh nonce in the DPoP proof.
    Responded with HTTP 401, a 'WWW-Authenticate: DPoP' challenge with
    'error="use_dpop_nonce"' and the new nonce in the 'DPoP-Nonce'
    response header. Defined by RFC 9449 Section 7.1.
    """

    error = "use_dpop_nonce"
    description = "The resource server requires a nonce in the DPoP proof."
    status_code = 401

    def __init__(self, nonce, description=None, **kwargs):
        super().__init__(description=description, **kwargs)
        self.nonce = nonce

    def get_headers(self):
        headers = super().get_headers()
        headers.append(("DPoP-Nonce", self.nonce))
        return headers
