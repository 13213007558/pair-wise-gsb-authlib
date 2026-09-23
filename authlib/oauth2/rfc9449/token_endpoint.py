"""authlib.oauth2.rfc9449.token_endpoint.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

DPoP extension for the token endpoint. When registered on a grant,
the grant requires a valid DPoP proof on token requests, binds the
issued access token to the proof key via 'cnf.jkt', and binds the
refresh token to the same key.

Usage::

    server.register_grant(AuthorizationCodeGrant, [DPoPTokenExtension(store)])
    server.register_grant(RefreshTokenGrant, [DPoPTokenExtension(store)])
"""

import functools
import time

from ..rfc6749.errors import InvalidGrantError
from .errors import InvalidDPoPProofError
from .errors import UseDPoPNonceError
from .proof import DEFAULT_MAX_AGE
from .proof import DPoPProofError
from .proof import get_cnf_jkt
from .proof import validate_dpop_proof


class DPoPTokenExtension:
    """Grant extension implementing the authorization-server side of
    DPoP per RFC 9449 Section 5.

    :param store: a 'DPoPStateStore' instance for replay protection and
        nonce handling; when None, replay protection is disabled
    :param required: whether a DPoP proof is mandatory on token requests
    :param nonce_required: whether proofs must contain the server nonce
    :param max_age: maximum acceptable age of a proof, in seconds
    :param now: callable returning the current timestamp; injectable
        for testing
    """

    def __init__(
        self,
        store=None,
        required=True,
        nonce_required=False,
        max_age=DEFAULT_MAX_AGE,
        now=None,
    ):
        self.store = store
        self.required = required
        self.nonce_required = nonce_required
        self.max_age = max_age
        self._now = now or time.time

    def __call__(self, grant):
        grant.register_hook("before_create_token_response", self.validate_dpop)
        self._wrap_generate_token(grant)

    def _wrap_generate_token(self, grant):
        original_generate_token = grant.generate_token

        @functools.wraps(original_generate_token)
        def generate_token(
            user=None,
            scope=None,
            grant_type=None,
            expires_in=None,
            include_refresh_token=True,
        ):
            token = original_generate_token(
                user=user,
                scope=scope,
                grant_type=grant_type,
                expires_in=expires_in,
                include_refresh_token=include_refresh_token,
            )
            jkt = getattr(grant.request, "dpop_jkt", None)
            if jkt:
                # RFC 9449 Section 5.1: the token_type of a DPoP bound
                # token is "DPoP"; the confirmation claim carries the
                # JWK thumbprint of the key the token is bound to
                token["token_type"] = "DPoP"
                token["cnf"] = {"jkt": jkt}
            return token

        grant.generate_token = generate_token

    def validate_dpop(self, grant):
        """Hook executed before the token response is created. At this
        point the grant has validated the client and the authorization
        code or refresh token."""
        request = grant.request
        proof_jwt = request.headers.get("DPoP")
        if not proof_jwt:
            if self.required:
                raise InvalidDPoPProofError("Missing 'DPoP' in headers.")
            return

        now = self._now()
        try:
            proof = validate_dpop_proof(
                proof_jwt,
                htm=request.method,
                htu=request.uri,
                now=now,
                max_age=self.max_age,
            )
        except DPoPProofError as exc:
            raise InvalidDPoPProofError(str(exc)) from exc

        self._validate_nonce(proof)
        self._validate_refresh_token_binding(request, proof.jkt)
        self._register_replay(proof, now)
        request.dpop_jkt = proof.jkt

    def _validate_nonce(self, proof):
        if not self.nonce_required:
            return
        if self.store is None:
            raise RuntimeError("A 'DPoPStateStore' is required for nonce handling.")
        expected = self.store.get_nonce()
        if expected is None or proof.claims.get("nonce") != expected:
            raise UseDPoPNonceError(self.store.create_nonce())

    def _validate_refresh_token_binding(self, request, jkt):
        # 'request.refresh_token' is set by RefreshTokenGrant; when the
        # presented refresh token is DPoP bound, the proof must be signed
        # with the same key (RFC 9449 Section 5.1)
        credential = getattr(request, "refresh_token", None)
        if credential is None:
            return
        bound_jkt = self.get_credential_jkt(credential)
        if bound_jkt and bound_jkt != jkt:
            raise InvalidGrantError(
                "The DPoP proof key does not match the key bound to the "
                "refresh token."
            )

    def _register_replay(self, proof, now):
        if self.store is None:
            return
        expires_at = proof.iat + self.max_age
        if not self.store.register_jti(proof.jkt, proof.jti, expires_at):
            raise InvalidDPoPProofError("The DPoP proof 'jti' has already been used.")

    def get_credential_jkt(self, credential):
        """Get the JWK thumbprint bound to a stored credential (the
        token record holding the refresh token). Developers MAY
        re-implement this method in a subclass. The default logic reads
        the 'cnf' attribute of the credential.
        """
        return get_cnf_jkt(getattr(credential, "cnf", None))
