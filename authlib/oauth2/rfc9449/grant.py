"""authlib.oauth2.rfc9449.grant.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

DPoP-aware token endpoint grants, per RFC 9449 Section 5.
"""

from ..rfc6749.grants import ClientCredentialsGrant
from .errors import InvalidDPoPProofError
from .proof import DPoPProofValidator
from .token import bound_dpop_jkt

__all__ = [
    "DPoPClientCredentialsGrant",
]


class DPoPClientCredentialsGrant(ClientCredentialsGrant):
    """The client credentials grant with DPoP proof validation, per
    RFC 9449 Section 5.1.

    The grant requires a valid DPoP proof in the ``DPoP`` header of the
    token request, and binds the issued access token to the proof public
    key (``cnf.jkt``). The proof validator is read from the authorization
    server ``dpop_proof_validator`` attribute, so the time window, the
    replay store and the nonce policy are configurable::

        server.dpop_proof_validator = DPoPProofValidator(
            max_age=120,
            replay_store=MyReplayStore(),
            nonce_provider=DPoPNonceProvider(),
        )
        server.register_grant(DPoPClientCredentialsGrant)
    """

    def get_dpop_proof_validator(self) -> DPoPProofValidator:
        """Return the proof validator configured on the authorization
        server, creating a default one if none was set.
        """
        validator = getattr(self.server, "dpop_proof_validator", None)
        if validator is None:
            validator = DPoPProofValidator()
            self.server.dpop_proof_validator = validator
        return validator

    def validate_token_request(self):
        super().validate_token_request()

        # RFC 9449, Section 5.1: the client MUST present a DPoP proof
        # for the token endpoint itself.
        proof_jwt = self.request.headers.get("DPoP")
        if not proof_jwt:
            raise InvalidDPoPProofError("Missing 'DPoP' proof header.")

        validator = self.get_dpop_proof_validator()
        proof = validator.validate(
            proof_jwt,
            method=self.request.method,
            url=self.request.uri,
        )
        self.request.dpop_jkt = proof.jkt

    def create_token_response(self):
        with bound_dpop_jkt(self.request.dpop_jkt):
            return super().create_token_response()
