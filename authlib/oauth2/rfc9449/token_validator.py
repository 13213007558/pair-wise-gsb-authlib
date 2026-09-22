"""authlib.oauth2.rfc9449.token_validator.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Validating DPoP-bound access tokens on the resource server.

https://www.rfc-editor.org/rfc/rfc9449.html#section-7
"""

from ..rfc9068 import JWTBearerTokenValidator
from .errors import DPoPInvalidTokenError
from .errors import InvalidDPoPProofError
from .errors import UseDPoPNonceError
from .grant_extension import get_header_values
from .validator import DPoPProofValidator

__all__ = ["DPoPTokenValidator"]


class DPoPTokenValidator(JWTBearerTokenValidator):
    """Validate DPoP-bound JWT access tokens together with their DPoP
    proof. Register it on the resource protector::

        class MyDPoPTokenValidator(DPoPTokenValidator):
            def get_jwks(self): ...


        require_oauth.register_token_validator(
            MyDPoPTokenValidator(issuer=issuer, resource_server=resource_id)
        )

    Requests MUST use the ``DPoP`` authorization scheme and carry exactly
    one ``DPoP`` proof header. The proof key thumbprint MUST match the
    ``cnf.jkt`` claim of the access token, and the proof ``ath`` claim MUST
    match the presented access token.

    :param proof_validator: a :class:`DPoPProofValidator` instance, used to
        configure the replay store, the proof time window and the nonce
        policy.
    """

    TOKEN_TYPE = "dpop"

    def __init__(self, issuer, resource_server, proof_validator=None, **kwargs):
        super().__init__(issuer, resource_server, **kwargs)
        self.proof_validator = proof_validator or DPoPProofValidator()

    def validate_request(self, request):
        values = get_header_values(request.headers, "DPoP")
        if len(values) != 1:
            raise DPoPInvalidTokenError(
                "Exactly one 'DPoP' header is required.",
                realm=self.realm,
                extra_attributes=self.extra_attributes,
            )

    def validate_token(self, token, scopes, request, **kwargs):
        super().validate_token(token, scopes, request, **kwargs)

        cnf = token.get("cnf")
        jkt = cnf.get("jkt") if isinstance(cnf, dict) else None
        if not jkt:
            raise DPoPInvalidTokenError(
                "The access token is not DPoP-bound.",
                realm=self.realm,
                extra_attributes=self.extra_attributes,
            )

        access_token = self._parse_access_token(request)
        proof_value = get_header_values(request.headers, "DPoP")[0]

        try:
            proof = self.proof_validator.validate(
                proof_value,
                request.method,
                request.uri,
                access_token=access_token,
            )
        except UseDPoPNonceError as exc:
            raise DPoPInvalidTokenError(
                exc.get_error_description(),
                nonce=exc.nonce,
                error="use_dpop_nonce",
                realm=self.realm,
                extra_attributes=self.extra_attributes,
            ) from exc
        except InvalidDPoPProofError as exc:
            raise DPoPInvalidTokenError(
                exc.get_error_description(),
                realm=self.realm,
                extra_attributes=self.extra_attributes,
            ) from exc

        if proof.jkt != jkt:
            raise DPoPInvalidTokenError(
                "The DPoP proof key does not match the access token.",
                realm=self.realm,
                extra_attributes=self.extra_attributes,
            )

    @staticmethod
    def _parse_access_token(request):
        auth = request.headers.get("Authorization") or ""
        parts = auth.split(None, 1)
        return parts[1] if len(parts) == 2 else ""
