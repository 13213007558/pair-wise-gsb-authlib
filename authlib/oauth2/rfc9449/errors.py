"""authlib.oauth2.rfc9449.errors.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Error responses defined by OAuth 2.0 Demonstrating Proof of
Possession (DPoP).

https://www.rfc-editor.org/rfc/rfc9449.html#section-11.2
"""

from ..rfc6749.errors import OAuth2Error
from ..rfc6750.errors import InvalidTokenError

__all__ = ["InvalidDPoPProofError", "UseDPoPNonceError", "DPoPInvalidTokenError"]


class InvalidDPoPProofError(OAuth2Error):
    """The DPoP proof is invalid, e.g. the signature does not verify, the
    ``htm`` or ``htu`` claims do not match the request, the ``iat`` claim is
    out of the acceptable time window, or the ``jti`` was already seen.

    https://www.rfc-editor.org/rfc/rfc9449.html#section-11.2
    """

    error = "invalid_dpop_proof"
    description = "The DPoP proof is invalid."
    status_code = 400


class UseDPoPNonceError(OAuth2Error):
    """The authorization server requires a DPoP nonce in the proof. The
    current nonce value is transported in the ``DPoP-Nonce`` response
    header.

    https://www.rfc-editor.org/rfc/rfc9449.html#section-8
    """

    error = "use_dpop_nonce"
    description = "The authorization server requires a DPoP nonce."
    status_code = 400

    def __init__(self, nonce, description=None, **kwargs):
        super().__init__(description, **kwargs)
        self.nonce = nonce

    def get_headers(self):
        headers = super().get_headers()
        if self.nonce:
            headers.append(("DPoP-Nonce", self.nonce))
        return headers


class DPoPInvalidTokenError(InvalidTokenError):
    """Resource server side error for DPoP protected resources. It responds
    with a ``WWW-Authenticate: DPoP`` challenge instead of ``Bearer``, and
    can carry a server nonce in the ``DPoP-Nonce`` response header.

    https://www.rfc-editor.org/rfc/rfc9449.html#section-7.1
    """

    AUTH_SCHEME = "DPoP"

    def __init__(self, description=None, nonce=None, error=None, **kwargs):
        super().__init__(description, **kwargs)
        if error:
            self.error = error
        self.nonce = nonce

    def get_headers(self):
        headers = super().get_headers()
        if self.nonce:
            headers.append(("DPoP-Nonce", self.nonce))
        return headers
