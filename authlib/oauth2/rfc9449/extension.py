"""authlib.oauth2.rfc9449.extension.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

DPoP extension for the token endpoint, per RFC 9449 Section 5. It
binds issued access tokens and refresh tokens to the public key of
the presented DPoP proof.

https://www.rfc-editor.org/rfc/rfc9449#section-5
"""

from ..rfc6749.errors import InvalidGrantError
from .errors import InvalidDPoPProofError
from .proof import DEFAULT_IAT_LEEWAY
from .proof import DPoPProofValidator

__all__ = ["DPoPExtension"]


class DPoPExtension:
    """DPoP extension for token endpoint grants. Register it on the
    "authorization_code" and "refresh_token" grants::

        store = MyDPoPStateStore()
        server.register_grant(AuthorizationCodeGrant, [DPoPExtension(store)])
        server.register_grant(RefreshTokenGrant, [DPoPExtension(store)])

    When a valid "DPoP" proof is presented with the token request, the
    JWK thumbprint of the proof public key is bound to the issued
    tokens: the token dict gets a "dpop_jkt" member (the "cnf.jkt"
    confirmation value) and its "token_type" becomes "DPoP". The
    application SHOULD persist "dpop_jkt" together with the token.

    A refresh token issued for a DPoP bound token stays bound to the
    same key: a refresh request presenting a proof of another key is
    rejected.

    :param store: a DPoPStateStore instance for nonce handling and
        replay detection, provided by the application.
    :param clock: a callable returning the current UNIX timestamp.
    :param required: if True, token requests without a "DPoP" proof
        are rejected.
    :param iat_leeway: acceptable "iat" window in seconds.
    """

    def __init__(self, store=None, clock=None, required=False, iat_leeway=None):
        self.required = required
        self.proof_validator = DPoPProofValidator(
            store=store,
            clock=clock,
            iat_leeway=iat_leeway or DEFAULT_IAT_LEEWAY,
            status_code=400,
        )

    def __call__(self, grant):
        grant.register_hook("before_create_token_response", self.validate_dpop_proof)
        original_generate_token = grant.generate_token

        def generate_token(*args, **kwargs):
            token = original_generate_token(*args, **kwargs)
            jkt = getattr(grant.request, "dpop_jkt", None)
            if jkt:
                token["token_type"] = "DPoP"
                token["dpop_jkt"] = jkt
            return token

        grant.generate_token = generate_token

    def validate_dpop_proof(self, grant):
        request = grant.request
        credential = getattr(request, "refresh_token", None)
        bound_jkt = credential and self.get_refresh_token_jkt(credential)

        if "DPoP" not in request.headers:
            # a DPoP bound refresh token always requires a proof
            if self.required or bound_jkt:
                raise InvalidDPoPProofError("Missing 'DPoP' proof in headers.")
            return

        proof = self.proof_validator.validate(request)

        if bound_jkt and bound_jkt != proof.jkt:
            raise InvalidGrantError(
                "DPoP proof does not match the refresh token binding."
            )

        request.dpop_jkt = proof.jkt

    def get_refresh_token_jkt(self, credential):
        """Get the JWK thumbprint bound to the refresh token. Developers
        MAY re-implement this method if the binding is stored elsewhere::

            def get_refresh_token_jkt(self, credential):
                return credential.dpop_jkt

        :param credential: the refresh token model instance
        :return: JWK thumbprint string or None
        """
        return getattr(credential, "dpop_jkt", None)
