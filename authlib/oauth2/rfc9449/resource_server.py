"""authlib.oauth2.rfc9449.resource_server.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

DPoP token validator for resource servers per RFC 9449 Section 7.
Requests must use the 'DPoP' authentication scheme and carry a valid
DPoP proof bound to the access token via the 'ath' claim; the proof
key must match the 'cnf.jkt' the token was issued with.
"""

import time

from ..rfc6750.errors import InsufficientScopeError
from ..rfc6750.validator import BearerTokenValidator
from .errors import DPoPInvalidTokenError
from .errors import DPoPUseNonceError
from .proof import DEFAULT_MAX_AGE
from .proof import DPoPProofError
from .proof import get_cnf_jkt
from .proof import validate_dpop_proof


class DPoPTokenValidator(BearerTokenValidator):
    """Validate DPoP bound access tokens on protected resources.

    :param store: a 'DPoPStateStore' instance for replay protection and
        nonce handling; when None, replay protection is disabled
    :param nonce_required: whether proofs must contain the server nonce
    :param max_age: maximum acceptable age of a proof, in seconds
    :param now: callable returning the current timestamp; injectable
        for testing
    """

    TOKEN_TYPE = "dpop"

    def __init__(
        self,
        store=None,
        nonce_required=False,
        max_age=DEFAULT_MAX_AGE,
        now=None,
        realm=None,
        **extra_attributes,
    ):
        super().__init__(realm, **extra_attributes)
        self.store = store
        self.nonce_required = nonce_required
        self.max_age = max_age
        self._now = now or time.time

    def _invalid_token(self, description):
        return DPoPInvalidTokenError(
            description=description,
            realm=self.realm,
            extra_attributes=self.extra_attributes,
        )

    def validate_request(self, request):
        """Validate the DPoP proof attached to the resource request."""
        proof_jwt = request.headers.get("DPoP")
        if not proof_jwt:
            raise self._invalid_token("Missing 'DPoP' in headers.")

        access_token = self._get_access_token(request)
        now = self._now()
        try:
            proof = validate_dpop_proof(
                proof_jwt,
                htm=request.method,
                htu=request.uri,
                access_token=access_token,
                now=now,
                max_age=self.max_age,
            )
        except DPoPProofError as exc:
            raise self._invalid_token(str(exc)) from exc

        self._validate_nonce(proof)

        if self.store is not None:
            expires_at = proof.iat + self.max_age
            if not self.store.register_jti(proof.jkt, proof.jti, expires_at):
                raise self._invalid_token("The DPoP proof 'jti' has already been used.")

        request.dpop_jkt = proof.jkt

    def validate_token(self, token, scopes, request):
        """Check the token is active, covers the requested scopes, and
        is bound to the key of the validated DPoP proof."""
        if not token:
            raise self._invalid_token(
                "The access token provided is expired, revoked, malformed, "
                "or invalid for other reasons."
            )
        if token.is_expired():
            raise self._invalid_token("The access token is expired.")
        if token.is_revoked():
            raise self._invalid_token("The access token has been revoked.")

        bound_jkt = self.get_token_jkt(token)
        if not bound_jkt:
            raise self._invalid_token("The access token is not DPoP bound.")
        if bound_jkt != getattr(request, "dpop_jkt", None):
            raise self._invalid_token(
                "The DPoP proof key does not match the key bound to the "
                "access token."
            )

        if self.scope_insufficient(token.get_scope(), scopes):
            raise InsufficientScopeError()

    def _validate_nonce(self, proof):
        if not self.nonce_required:
            return
        if self.store is None:
            raise RuntimeError("A 'DPoPStateStore' is required for nonce handling.")
        expected = self.store.get_nonce()
        if expected is None or proof.claims.get("nonce") != expected:
            raise DPoPUseNonceError(
                self.store.create_nonce(),
                realm=self.realm,
                extra_attributes=self.extra_attributes,
            )

    def _get_access_token(self, request):
        auth = request.headers.get("Authorization")
        if not auth:
            raise self._invalid_token("Missing 'Authorization' in headers.")
        parts = auth.split(None, 1)
        if len(parts) != 2 or parts[0].lower() != self.TOKEN_TYPE:
            raise self._invalid_token(
                "The access token must use the 'DPoP' authentication scheme."
            )
        return parts[1]

    def get_token_jkt(self, token):
        """Get the JWK thumbprint bound to the access token. Developers
        MAY re-implement this method in a subclass. The default logic
        reads the 'cnf' attribute of the token.
        """
        return get_cnf_jkt(getattr(token, "cnf", None))
