"""authlib.oauth2.rfc9449.protector.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

ResourceProtector extension enforcing DPoP sender-constrained access tokens
per :rfc:`9449`.

The extension plugs into
:class:`~authlib.oauth2.rfc6749.ResourceProtector` with hooks. It does not
replace the registered token validator: the validator still authenticates the
access token and returns its metadata, including the ``cnf.jkt`` thumbprint.
The extension then verifies that the DPoP proof on the request is bound to the
same key and to this exact request.
"""

from ..rfc6749 import ResourceProtector
from .errors import InvalidDPoPProofError
from .errors import UseDPoPNonceError
from .proof import DPoPProofValidator

__all__ = ["DPoPProtector"]


def get_token_confirmation_jkt(token):
    """Return the ``cnf.jkt`` thumbprint bound to a token, or ``None``.

    The token returned by a token validator may be a mapping, an object with a
    ``get`` method (such as the JWT claims objects of :rfc:`9068`), or any
    object exposing a ``cnf`` attribute or item.
    """
    cnf = None
    if hasattr(token, "get"):
        cnf = token.get("cnf")
    elif hasattr(token, "cnf"):
        cnf = token.cnf

    if cnf is None:
        return None
    if hasattr(cnf, "get"):
        return cnf.get("jkt")
    return getattr(cnf, "jkt", None)


class DPoPProtector:
    """ResourceProtector extension for DPoP-bound access tokens.

    Usage::

        from authlib.oauth2.rfc9449 import DPoPProtector

        require_oauth.register_token_validator(MyBearerTokenValidator())
        require_oauth.register_extension(
            DPoPProtector(nonce_generator=lambda: server_nonce)
        )

    Requests using the ``DPoP`` scheme are authenticated with the registered
    bearer token validator, and the DPoP proof is then checked against the
    request and the token ``cnf.jkt``. A failed DPoP check always rejects the
    request: it is never downgraded to an unbound bearer acceptance.

    :param proof_validator: A :class:`DPoPProofValidator`. A default one is
        created when omitted.
    :param nonce_generator: An optional zero-argument callable that issues a
        fresh server nonce. Forwarded to the default proof validator.
    :param expected_nonce: An optional callable taking the request and
        returning the nonce the server currently requires. When it returns a
        value, proofs must carry it in their ``nonce`` claim.
    """

    def __init__(
        self,
        proof_validator=None,
        nonce_generator=None,
        expected_nonce=None,
    ):
        self.proof_validator = proof_validator or DPoPProofValidator(
            nonce_generator=nonce_generator
        )
        self.nonce_generator = nonce_generator
        self.expected_nonce = expected_nonce

    def __call__(self, protector):
        protector.register_hook(
            self._parse_request_authorization,
            replace=ResourceProtector.parse_request_authorization,
        )
        protector.register_hook(
            self._validate_request,
            replace=ResourceProtector.validate_request,
        )

    # -- hooks -----------------------------------------------------------

    def _parse_request_authorization(self, protector, original, request):
        auth = request.headers.get("Authorization")
        scheme = self._get_scheme(auth)
        if scheme != "dpop":
            # Bearer requests never bypass the binding check: a token that
            # carries a cnf.jkt must be presented with a DPoP proof.
            validator, token_string = original(request)
            request._dpop_scheme = False
            request._dpop_token_string = token_string
            return validator, token_string

        parts = auth.split(None, 1)
        if len(parts) != 2:
            raise InvalidDPoPProofError(
                "Missing access token in the Authorization header."
            )
        token_string = parts[1].strip()
        if not token_string:
            raise InvalidDPoPProofError(
                "Missing access token in the Authorization header."
            )

        # The DPoP scheme reuses the bearer token validator, which returns the
        # token metadata including the cnf claim.
        validator = protector.get_token_validator("bearer")
        request._dpop_scheme = True
        request._dpop_token_string = token_string
        return validator, token_string

    def _validate_request(self, protector, original, scopes, request, **kwargs):
        token = original(scopes, request, **kwargs)

        proof_string = self._get_dpop_header(request)
        if not getattr(request, "_dpop_scheme", False):
            # RFC 9449 §4.3: a sender-constrained token presented as a plain
            # bearer token must be rejected, whether or not a DPoP header is
            # present. A DPoP failure must never downgrade to bearer access.
            if get_token_confirmation_jkt(token):
                raise InvalidDPoPProofError(
                    "This access token must be sent with the DPoP scheme."
                )
            return token

        if proof_string is None:
            raise self._missing_proof_error(request)

        proof = self.proof_validator.validate(
            proof_string,
            http_method=request.method,
            url=self.get_request_url(request),
            access_token=request._dpop_token_string,
            expected_nonce=self._get_expected_nonce(request),
        )

        expected_jkt = get_token_confirmation_jkt(token)
        if not expected_jkt:
            raise InvalidDPoPProofError("The access token is not bound to a DPoP key.")
        if expected_jkt != proof.jkt:
            raise InvalidDPoPProofError(
                "The DPoP key does not match the access token binding."
            )
        return token

    # -- helpers ---------------------------------------------------------

    def get_request_url(self, request):
        """Return the trusted request URL used to check the ``htu`` claim.

        The default implementation uses ``request.uri``, which the framework
        builds from the request line and its own server configuration. It does
        not read ``X-Forwarded-*`` or other forwarding headers directly: those
        are only trustworthy after the deployment explicitly configures the
        framework (for example Werkzeug ``ProxyFix``) to process them. Override
        this method to supply a canonical URL another way.
        """
        return request.uri

    def _get_expected_nonce(self, request):
        if self.expected_nonce is None:
            return None
        return self.expected_nonce(request)

    def _missing_proof_error(self, request):
        if self.nonce_generator is None:
            return InvalidDPoPProofError("Missing DPoP proof header.")
        return UseDPoPNonceError(nonce=self.nonce_generator())

    @staticmethod
    def _get_scheme(authorization):
        if not authorization:
            return None
        parts = authorization.split(None, 1)
        return parts[0].lower() if parts else None

    @staticmethod
    def _get_dpop_header(request):
        """Return the single DPoP header value, or ``None``.

        Multiple DPoP headers are ambiguous and rejected. Both plain mappings
        and multi-value header containers (such as Werkzeug's) are supported.
        """
        headers = request.headers
        getlist = getattr(headers, "getlist", None)
        if getlist is not None:
            values = getlist("DPoP")
        else:
            value = headers.get("DPoP")
            values = [value] if value is not None else []

        if not values:
            return None
        if len(values) > 1:
            raise InvalidDPoPProofError("Multiple DPoP headers are not allowed.")
        return values[0]
