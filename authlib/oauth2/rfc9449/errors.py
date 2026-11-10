"""authlib.oauth2.rfc9449.errors.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Errors returned when validating DPoP proofs on a resource server.

Per :rfc:`9449#section-7.2`, DPoP errors use the HTTP 401 status code and a
``WWW-Authenticate`` header with the ``DPoP`` scheme. When the server requires
a nonce, the error additionally carries a ``DPoP-Nonce`` header and uses the
``use_dpop_nonce`` error code.
"""

from ..base import OAuth2Error

__all__ = [
    "DPoPError",
    "InvalidDPoPProofError",
    "UseDPoPNonceError",
]


class DPoPError(OAuth2Error):
    """Base class for DPoP errors.

    Every DPoP error is an HTTP 401 response. In addition to the standard
    OAuth 2.0 JSON body, it contains a ``WWW-Authenticate`` header using the
    ``DPoP`` scheme, per :rfc:`9449#section-7.2`.
    """

    status_code = 401
    #: When set, a ``DPoP-Nonce`` header is added to the response.
    nonce = None
    #: Extra parameters added to the ``WWW-Authenticate`` header.
    extra_attributes = None

    def __init__(
        self,
        description=None,
        uri=None,
        status_code=None,
        state=None,
        nonce=None,
        realm=None,
        extra_attributes=None,
    ):
        super().__init__(description, uri, status_code, state)
        self.nonce = nonce
        self.realm = realm
        self.extra_attributes = extra_attributes or {}

    def get_headers(self):
        headers = super().get_headers()

        extras = []
        if self.realm:
            extras.append(f'realm="{self.realm}"')
        if self.nonce is not None:
            extras.append(f'nonce="{self.nonce}"')
        for key, value in self.extra_attributes.items():
            extras.append(f'{key}="{value}"')
        extras.append(f'error="{self.error}"')
        error_description = self.get_error_description()
        extras.append(f'error_description="{error_description}"')
        headers.append(("WWW-Authenticate", "DPoP " + ", ".join(extras)))

        if self.nonce is not None:
            headers.append(("DPoP-Nonce", self.nonce))
        return headers


class InvalidDPoPProofError(DPoPError):
    """The DPoP proof is missing, malformed, invalid, or does not match the
    request or the access token.

    :rfc:`9449#section-7.2`
    """

    error = "invalid_dpop_proof"
    description = "The DPoP proof is invalid."


class UseDPoPNonceError(DPoPError):
    """The resource server requires a nonce in the DPoP proof.

    The response carries a fresh ``DPoP-Nonce`` header, and the client retries
    the request with that nonce.

    :rfc:`9449#section-7.2`
    """

    error = "use_dpop_nonce"
    description = "The DPoP proof requires a nonce."
