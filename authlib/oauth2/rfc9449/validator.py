"""authlib.oauth2.rfc9449.validator.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Validation of DPoP proofs against the current HTTP request.

https://www.rfc-editor.org/rfc/rfc9449.html#section-4.3
"""

import contextvars
import time

from .errors import InvalidDPoPProofError
from .errors import UseDPoPNonceError
from .proof import compute_ath
from .proof import normalize_htu
from .proof import parse_proof
from .store import InMemoryDPoPReplayStore

#: the JWK thumbprint of the DPoP proof validated for the current request,
#: consumed by DPoPTokenGenerator to bind the issued access token
_current_jkt = contextvars.ContextVar("authlib.oauth2.rfc9449.jkt", default=None)


def set_current_jkt(jkt):
    _current_jkt.set(jkt)


def pop_current_jkt():
    jkt = _current_jkt.get()
    _current_jkt.set(None)
    return jkt


class DPoPProofValidator:
    """Validate DPoP proofs for authorization and resource servers.

    :param store: a :class:`DPoPReplayStore` instance used to detect
        replayed proofs. Defaults to an in-memory store.
    :param max_age: maximum age in seconds of a proof, checked against the
        ``iat`` claim. Recorded ``jti`` values are kept for this duration.
    :param leeway: leeway in seconds to allow for clock skew when checking
        that ``iat`` is not in the future.
    :param algs: accepted proof signature algorithms. Only asymmetric
        algorithms are allowed; defaults to ES256.
    :param nonce_getter: optional callable returning the current server
        issued nonce. When configured, proofs MUST contain a matching
        ``nonce`` claim, otherwise a ``use_dpop_nonce`` error is raised.
        A nonce is never consumed: the same nonce can be used by many
        different proofs, replay detection relies on ``jti`` only.
    """

    DEFAULT_MAX_AGE = 300
    DEFAULT_LEEWAY = 30
    DEFAULT_ALGS = ("ES256",)

    def __init__(
        self,
        store=None,
        max_age=None,
        leeway=None,
        algs=None,
        nonce_getter=None,
    ):
        self.store = store if store is not None else InMemoryDPoPReplayStore()
        self.max_age = max_age if max_age is not None else self.DEFAULT_MAX_AGE
        self.leeway = leeway if leeway is not None else self.DEFAULT_LEEWAY
        self.algs = tuple(algs) if algs else self.DEFAULT_ALGS
        self.nonce_getter = nonce_getter

    def validate(self, value, method, uri, access_token=None):
        """Validate a DPoP proof for the given HTTP request.

        :param value: the proof JWT from the ``DPoP`` header
        :param method: the HTTP method of the request
        :param uri: the full HTTP URI of the request
        :param access_token: when validating a proof for a protected
            resource, the access token presented with the proof
        :return: DPoPProof
        :raise: InvalidDPoPProofError
        :raise: UseDPoPNonceError
        """
        proof = parse_proof(value, self.algs)
        claims = proof.claims

        # the htm claim MUST match the HTTP method of the request,
        # compared case-sensitively
        htm = claims.get("htm")
        if not isinstance(htm, str) or htm != method:
            raise InvalidDPoPProofError(
                "The 'htm' claim does not match the request method."
            )

        # the htu claim MUST match the HTTP URI of the request,
        # ignoring the query and fragment components
        htu = claims.get("htu")
        if not isinstance(htu, str) or normalize_htu(htu) != normalize_htu(uri):
            raise InvalidDPoPProofError(
                "The 'htu' claim does not match the request URI."
            )

        now = time.time()

        # the iat claim MUST be present and within the acceptable window
        iat = claims.get("iat")
        if isinstance(iat, bool) or not isinstance(iat, (int, float)):
            raise InvalidDPoPProofError("Missing 'iat' in DPoP proof.")
        if iat > now + self.leeway or iat < now - self.max_age:
            raise InvalidDPoPProofError("The 'iat' of the DPoP proof is stale.")

        # the jti claim MUST be present
        jti = claims.get("jti")
        if not isinstance(jti, str) or not jti:
            raise InvalidDPoPProofError("Missing 'jti' in DPoP proof.")

        if self.nonce_getter is not None:
            nonce = self.nonce_getter()
            if nonce is not None and claims.get("nonce") != nonce:
                raise UseDPoPNonceError(nonce)

        # the ath claim is REQUIRED when the proof is presented together
        # with an access token
        if access_token is not None:
            ath = claims.get("ath")
            if not isinstance(ath, str) or ath != compute_ath(access_token):
                raise InvalidDPoPProofError(
                    "The 'ath' claim does not match the access token."
                )

        # the jti is recorded only after every other check passed, so that
        # an invalid proof can not burn the jti of a legitimate one
        if not self.store.record(jti, now + self.max_age):
            raise InvalidDPoPProofError("The DPoP proof was already used.")

        return proof
