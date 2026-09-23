"""authlib.oauth2.rfc9449.validator.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

DPoP token validator for resource servers, per RFC 9449 Section 7.

https://www.rfc-editor.org/rfc/rfc9449#section-7
"""

from ..rfc6749 import TokenValidator
from ..rfc6750 import InsufficientScopeError
from .errors import InvalidDPoPProofError
from .errors import InvalidDPoPTokenError
from .proof import DEFAULT_IAT_LEEWAY
from .proof import DPoPProofValidator
from .proof import compute_ath

__all__ = ["DPoPTokenValidator"]


class DPoPTokenValidator(TokenValidator):
    """Validate DPoP bound access tokens on protected resources.
    Register it into the resource protector::

        class MyDPoPTokenValidator(DPoPTokenValidator):
            def authenticate_token(self, token_string):
                return Token.query.filter_by(access_token=token_string).first()


        require_oauth.register_token_validator(MyDPoPTokenValidator(store=store))

    Clients access the resource with the "DPoP" authorization scheme
    and a "DPoP" proof header. The proof MUST be signed with the
    private key matching the "cnf.jkt" binding of the access token,
    and its "ath" claim MUST match the presented access token.

    :param store: a DPoPStateStore instance for nonce handling and
        replay detection, provided by the application.
    :param clock: a callable returning the current UNIX timestamp.
    :param realm: realm for the "WWW-Authenticate" header.
    :param iat_leeway: acceptable "iat" window in seconds.
    """

    TOKEN_TYPE = "dpop"

    def __init__(
        self, store=None, clock=None, realm=None, iat_leeway=None, **extra_attributes
    ):
        super().__init__(realm, **extra_attributes)
        self.proof_validator = DPoPProofValidator(
            store=store,
            clock=clock,
            iat_leeway=iat_leeway or DEFAULT_IAT_LEEWAY,
            status_code=401,
            realm=realm,
        )

    def validate_request(self, request):
        """Validate the DPoP proof of the resource request: signature,
        "typ", asymmetric "alg", "htm", "htu", "iat", "jti" and nonce.
        """
        if "DPoP" not in request.headers:
            raise InvalidDPoPProofError(
                "Missing 'DPoP' proof in headers.",
                status_code=401,
                realm=self.realm,
            )
        request.dpop_proof = self.proof_validator.validate(request)

    def authenticate_token(self, token_string):
        """A method to query token from database with the given token
        string. Developers MUST re-implement this method. For instance::

            def authenticate_token(self, token_string):
                return get_token_from_database(token_string)

        :param token_string: A string to represent the access_token.
        :return: token
        """
        raise NotImplementedError()

    def validate_token(self, token, scopes, request):
        """Check that the token is active, matches the requested
        scopes, is DPoP bound, and that the proof matches the binding
        ("cnf.jkt") and the presented access token ("ath").
        """
        if not token:
            raise InvalidDPoPTokenError(
                realm=self.realm, extra_attributes=self.extra_attributes
            )
        if token.is_expired():
            raise InvalidDPoPTokenError(
                realm=self.realm, extra_attributes=self.extra_attributes
            )
        if token.is_revoked():
            raise InvalidDPoPTokenError(
                realm=self.realm, extra_attributes=self.extra_attributes
            )
        if self.scope_insufficient(token.get_scope(), scopes):
            raise InsufficientScopeError()

        proof = getattr(request, "dpop_proof", None)
        if proof is None:
            raise InvalidDPoPProofError(
                "Missing 'DPoP' proof in headers.",
                status_code=401,
                realm=self.realm,
            )

        access_token = self.get_access_token_string(token)
        ath = proof.claims.get("ath")
        if not ath or ath != compute_ath(access_token):
            raise InvalidDPoPProofError(
                "Invalid 'ath' in DPoP proof.",
                status_code=401,
                realm=self.realm,
            )

        jkt = self.get_token_jkt(token)
        if not jkt:
            raise InvalidDPoPTokenError(
                "The access token is not bound to a DPoP key.",
                realm=self.realm,
                extra_attributes=self.extra_attributes,
            )
        if jkt != proof.jkt:
            raise InvalidDPoPProofError(
                "DPoP proof does not match the access token binding.",
                status_code=401,
                realm=self.realm,
            )

    def get_access_token_string(self, token):
        """Get the access token string of the token model, used to
        verify the "ath" claim of the proof.

        :param token: the token model instance
        :return: access token string
        """
        return token.access_token

    def get_token_jkt(self, token):
        """Get the "cnf.jkt" value bound to the access token at
        issuance. Developers MAY re-implement this method if the
        binding is stored elsewhere.

        :param token: the token model instance
        :return: JWK thumbprint string or None
        """
        return getattr(token, "dpop_jkt", None)
