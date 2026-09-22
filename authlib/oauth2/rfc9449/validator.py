"""authlib.oauth2.rfc9449.validator.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Resource server side validation of DPoP-bound access tokens, per
RFC 9449 Sections 6 and 7.
"""

from joserfc import jwt
from joserfc.errors import JoseError

from authlib._joserfc_helpers import import_any_key
from authlib.oauth2.claims import ClaimsOption
from authlib.oauth2.rfc6749 import TokenValidator
from authlib.oauth2.rfc6750.errors import InsufficientScopeError
from authlib.oauth2.rfc9068.claims import JWTAccessTokenClaims

from .errors import DPoPError
from .errors import InvalidDPoPTokenError
from .errors import UseDPoPNonceError
from .proof import DPoPProofValidator

__all__ = [
    "DPoPTokenValidator",
]


class DPoPTokenValidator(TokenValidator):
    """Validate DPoP-bound JWT access tokens on protected resources.

    :param issuer: The issuer from which tokens are accepted. If set, the
        ``iss`` claim of access tokens is checked against it.
    :param resource_server: An identifier for the current resource server,
        which must appear in the ``aud`` claim. Optional.
    :param proof_validator: The :class:`DPoPProofValidator` used to validate
        the ``DPoP`` proof header. A default one is created if omitted.

    Developers MUST implement ``get_jwks`` to provide the authorization
    server signing keys::

        class MyDPoPTokenValidator(DPoPTokenValidator):
            def get_jwks(self):
                return load_jwks("jwks.json")


        require_oauth = ResourceProtector()
        require_oauth.register_token_validator(
            MyDPoPTokenValidator(issuer="https://as.example.org")
        )
    """

    TOKEN_TYPE = "dpop"

    def __init__(
        self,
        issuer=None,
        resource_server=None,
        proof_validator=None,
        *args,
        **kwargs,
    ):
        self.issuer = issuer
        self.resource_server = resource_server
        if proof_validator is None:
            proof_validator = DPoPProofValidator()
        self.proof_validator = proof_validator
        super().__init__(*args, **kwargs)

    def get_jwks(self):
        """Return the JWKs used to verify the access token signature.
        Developers MUST re-implement this method.
        """
        raise NotImplementedError()

    def validate_iss(self, claims, iss: str) -> bool:
        return iss == self.issuer

    def authenticate_token(self, token_string):
        claims_options: dict[str, ClaimsOption] = {
            "exp": {"essential": True},
            "iat": {"essential": True},
            "jti": {"essential": True},
            "sub": {"essential": True},
            "client_id": {"essential": True},
            "scope": {"essential": False},
        }
        if self.issuer:
            claims_options["iss"] = {
                "essential": True,
                "validate": self.validate_iss,
            }
        if self.resource_server:
            claims_options["aud"] = {
                "essential": True,
                "value": self.resource_server,
            }

        key = import_any_key(self.get_jwks())
        try:
            token = jwt.decode(token_string, key=key)
            return JWTAccessTokenClaims(token.claims, token.header, claims_options)
        except JoseError as exc:
            raise InvalidDPoPTokenError(realm=self.realm) from exc

    def validate_request(self, request):
        # RFC 9449, Section 7.1: a DPoP-bound access token MUST be
        # accompanied by a DPoP proof.
        if not request.headers.get("DPoP"):
            raise InvalidDPoPTokenError(
                description="Missing 'DPoP' proof header.",
                realm=self.realm,
            )

    def validate_token(self, token, scopes, request):
        try:
            token.validate()
        except JoseError as exc:
            raise InvalidDPoPTokenError(realm=self.realm) from exc

        # RFC 9449, Section 6.1: the access token MUST be bound to a
        # public key through the ``cnf.jkt`` claim.
        cnf = token.get("cnf")
        jkt = cnf.get("jkt") if isinstance(cnf, dict) else None
        if not jkt:
            raise InvalidDPoPTokenError(
                description="The access token is not DPoP-bound.",
                realm=self.realm,
            )

        proof = self._validate_proof(request, token_string=self._token_string(request))

        # The proof MUST be signed with the key the token is bound to:
        # a proof signed with another key is rejected.
        if proof.jkt != jkt:
            raise InvalidDPoPTokenError(
                description="The DPoP proof key does not match the token.",
                realm=self.realm,
            )

        if self.scope_insufficient(token.get("scope"), scopes):
            raise InsufficientScopeError()

    def _validate_proof(self, request, token_string):
        try:
            return self.proof_validator.validate(
                request.headers.get("DPoP"),
                method=request.method,
                url=request.uri,
                access_token=token_string,
            )
        except UseDPoPNonceError as exc:
            raise InvalidDPoPTokenError(
                description=exc.get_error_description(),
                nonce=exc.nonce,
                realm=self.realm,
                error="use_dpop_nonce",
            ) from exc
        except DPoPError as exc:
            raise InvalidDPoPTokenError(
                description=exc.get_error_description(),
                nonce=exc.nonce,
                realm=self.realm,
            ) from exc

    @staticmethod
    def _token_string(request):
        auth = request.headers.get("Authorization") or ""
        parts = auth.split(None, 1)
        if len(parts) == 2:
            return parts[1]
        return ""
