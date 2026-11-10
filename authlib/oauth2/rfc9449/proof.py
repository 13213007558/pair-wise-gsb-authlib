"""authlib.oauth2.rfc9449.proof.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Validation of DPoP proof JWTs on a resource server per :rfc:`9449#section-4.3`.

The validator is independent of any web framework. It receives the request
data already extracted by the integration and returns the parsed proof, or
raises one of the errors defined in :mod:`authlib.oauth2.rfc9449.errors`.
"""

import base64
import hashlib
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jwk import ECKey
from joserfc.jwk import OKPKey
from joserfc.jwk import RSAKey
from joserfc.jwk import import_key
from joserfc.jws import JWSRegistry
from joserfc.jws import extract_compact

from authlib.common.encoding import json_loads

from .errors import InvalidDPoPProofError
from .errors import UseDPoPNonceError
from .replay import InMemoryReplayStore

__all__ = ["DPoPProof", "DPoPProofValidator", "compute_ath"]

#: Asymmetric JWS algorithms accepted for DPoP proofs. Symmetric algorithms
#: such as HS256 cannot be used, because the proof is signed with a key the
#: client controls and the resource server only knows its public JWK.
DEFAULT_ALGORITHMS = ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "EdDSA")

_ASYMMETRIC_KEY_TYPES = (RSAKey, ECKey, OKPKey)

#: DPoP proofs carry a public 'jwk' member, which is not part of the default
#: strict JWS header registry, and RSA JWKs can exceed the default header size
#: limit. A dedicated registry relaxes both while keeping the algorithm
#: allow-list enforced.
_MAX_HEADER_LENGTH = 10_000


def build_registry(algorithms):
    """Build a JWS registry accepting the given DPoP algorithms."""
    registry = JWSRegistry(algorithms=algorithms, strict_check_header=False)
    registry.max_header_length = _MAX_HEADER_LENGTH
    return registry


@dataclass(frozen=True)
class DPoPProof:
    """A DPoP proof that passed every validation except replay storage."""

    #: The parsed JWT header.
    header: dict
    #: The validated JWT claims.
    claims: dict
    #: The public JWK from the ``jwk`` header, as a joserfc key.
    public_key: object
    #: The base64url-encoded SHA-256 JWK thumbprint of the public key.
    jkt: str
    #: The unique proof identifier.
    jti: str


@dataclass
class _ParsedProof:
    """The unverified header and claims extracted from a compact JWT."""

    header: dict
    claims: dict


def compute_ath(access_token: str) -> str:
    """Compute the ``ath`` claim for an access token.

    It is the base64url encoding without padding of the SHA-256 hash of the
    access token, per :rfc:`9449#section-4.2`.
    """
    digest = hashlib.sha256(access_token.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def normalize_url(url: str) -> str:
    """Return ``url`` without its query and fragment components.

    The ``htu`` claim is compared against the request target URI after
    stripping the query and fragment, per :rfc:`9449#section-4.3`.
    """
    parts = urlsplit(url)
    return parts._replace(query="", fragment="").geturl()


class DPoPProofValidator:
    """Validate DPoP proof JWTs for resource server requests.

    :param leeway: Number of seconds of clock skew accepted when checking the
        ``iat`` claim.
    :param max_age: Maximum age of a proof, in seconds, measured from ``iat``.
    :param algorithms: Accepted asymmetric JWS algorithms.
    :param replay_store: A :class:`~authlib.oauth2.rfc9449.replay.ReplayStore`
        used to reject replayed proofs. Defaults to a process-local
        :class:`InMemoryReplayStore`.
    :param clock: A callable returning the current UNIX time. It defaults to
        :func:`time.time` and can be fixed in tests.
    :param nonce_generator: An optional zero-argument callable returning a
        fresh server nonce. When set, every proof must carry the current
        nonce in its ``nonce`` claim; a missing or stale nonce raises a
        :class:`UseDPoPNonceError` carrying a fresh nonce.
    """

    def __init__(
        self,
        leeway: int = 60,
        max_age: int = 300,
        algorithms=DEFAULT_ALGORITHMS,
        replay_store=None,
        clock=time.time,
        nonce_generator=None,
    ):
        self.leeway = leeway
        self.max_age = max_age
        self.algorithms = tuple(algorithms)
        self.registry = build_registry(self.algorithms)
        self.replay_store = replay_store or InMemoryReplayStore()
        self.clock = clock
        self.nonce_generator = nonce_generator

    def validate(
        self,
        proof_string: str,
        *,
        http_method: str,
        url: str,
        access_token: str,
        expected_nonce: str | None = None,
    ) -> DPoPProof:
        """Validate a DPoP proof for one resource request.

        :param proof_string: The compact JWT sent in the ``DPoP`` header.
        :param http_method: The HTTP method of the request, uppercased.
        :param url: The request URL as seen by the server, with its query and
            fragment still present; they are removed before the comparison.
        :param access_token: The raw access token string from the
            ``Authorization`` header, used to check the ``ath`` claim.
        :param expected_nonce: The nonce the server currently requires, if
            any. When provided, the proof ``nonce`` claim must match it.
        :raises InvalidDPoPProofError: if any proof check fails.
        :raises UseDPoPNonceError: if the server requires a nonce and the
            proof does not carry the expected one.
        """
        token = self._parse(proof_string)
        header = token.header
        claims = token.claims

        self._validate_header(header)
        public_key = self._validate_jwk(header)
        self._verify_signature(claims, public_key, proof_string)
        self._validate_claims(claims, http_method, url)
        self._validate_ath(claims, access_token)
        self._validate_nonce(claims, expected_nonce)

        proof = DPoPProof(
            header=header,
            claims=claims,
            public_key=public_key,
            jkt=public_key.thumbprint(),
            jti=claims["jti"],
        )

        now = self.clock()
        # Replay storage is the last step and the only side effect. A proof
        # that failed any check above never reserves its jti.
        if not self.replay_store.check_and_store(proof.jti, now + self.max_age):
            raise InvalidDPoPProofError("The DPoP proof has already been used.")
        return proof

    def _parse(self, proof_string):
        if not isinstance(proof_string, str) or not proof_string:
            raise InvalidDPoPProofError("Missing DPoP proof.")
        try:
            # Parse without verifying: the signature is checked below with the
            # public JWK embedded in the header, once that JWK is validated.
            compact = extract_compact(
                proof_string.encode("ascii"), registry=self.registry
            )
            header = compact.protected
            claims = json_loads(compact.payload)
        except (JoseError, ValueError, UnicodeError) as exc:
            raise InvalidDPoPProofError("The DPoP proof is not a valid JWT.") from exc

        if not isinstance(header, dict) or not isinstance(claims, dict):
            raise InvalidDPoPProofError("The DPoP proof is not a valid JWT.")
        return _ParsedProof(header, claims)

    def _validate_header(self, header):
        # RFC 9449 §4.2: the 'typ' header MUST be "dpop+jwt".
        typ = header.get("typ")
        if typ != "dpop+jwt":
            raise InvalidDPoPProofError(
                "The DPoP proof 'typ' header must be 'dpop+jwt'."
            )

        alg = header.get("alg")
        if alg not in self.algorithms:
            raise InvalidDPoPProofError(
                f"Algorithm '{alg}' is not accepted for DPoP proofs."
            )

        # RFC 9449 §4.2: a 'jwk' header is REQUIRED. The JWK itself is checked
        # separately to make sure it is a public asymmetric key.
        if "jwk" not in header:
            raise InvalidDPoPProofError("The DPoP proof must contain a 'jwk' header.")

    def _validate_jwk(self, header):
        jwk = header["jwk"]
        if not isinstance(jwk, dict):
            raise InvalidDPoPProofError("The DPoP 'jwk' header must be a JWK object.")

        try:
            key = import_key(jwk)
        except JoseError as exc:
            raise InvalidDPoPProofError(
                "The DPoP 'jwk' header is not a valid JWK."
            ) from exc

        if not isinstance(key, _ASYMMETRIC_KEY_TYPES):
            raise InvalidDPoPProofError("The DPoP key must be asymmetric.")

        # A proof is signed with the client's private key, so the embedded JWK
        # MUST be public. Rejecting private members prevents a client from
        # binding a token to a key it does not exclusively control.
        if key.is_private:
            raise InvalidDPoPProofError("The DPoP 'jwk' header must be a public key.")
        return key

    def _verify_signature(self, claims, public_key, proof_string):
        try:
            verified = jwt.decode(
                proof_string,
                key=public_key,
                registry=self.registry,
            )
        except JoseError as exc:
            raise InvalidDPoPProofError(
                "The DPoP proof signature cannot be verified with its 'jwk'."
            ) from exc
        # Decoding again after verification guards against any discrepancy
        # between the unverified parse and the verified contents.
        claims.update(verified.claims)

    def _validate_claims(self, claims, http_method, url):
        for name in ("jti", "htm", "htu", "iat"):
            if name not in claims:
                raise InvalidDPoPProofError(
                    f"The DPoP proof must contain a '{name}' claim."
                )

        jti = claims["jti"]
        if not isinstance(jti, str) or not jti:
            raise InvalidDPoPProofError("The DPoP 'jti' claim must be a string.")

        # RFC 9449 §4.3: htm MUST be the HTTP method of the request.
        if claims["htm"] != http_method.upper():
            raise InvalidDPoPProofError(
                "The DPoP 'htm' claim does not match the method."
            )

        # RFC 9449 §4.3: htu MUST be the request target URI without query or
        # fragment. Comparison is on the normalized values only.
        if claims["htu"] != normalize_url(url):
            raise InvalidDPoPProofError("The DPoP 'htu' claim does not match the URL.")

        iat = claims["iat"]
        if isinstance(iat, bool) or not isinstance(iat, int | float):
            raise InvalidDPoPProofError("The DPoP 'iat' claim must be a numeric date.")

        now = self.clock()
        if iat > now + self.leeway:
            raise InvalidDPoPProofError("The DPoP proof 'iat' claim is in the future.")
        if now - iat > self.max_age + self.leeway:
            raise InvalidDPoPProofError("The DPoP proof has expired.")

    def _validate_ath(self, claims, access_token):
        # RFC 9449 §4.3: when the proof is presented with an access token, the
        # 'ath' claim MUST be the hash of that exact token.
        ath = claims.get("ath")
        expected = compute_ath(access_token)
        if ath != expected:
            raise InvalidDPoPProofError(
                "The DPoP 'ath' claim does not match the access token."
            )

    def _validate_nonce(self, claims, expected_nonce):
        if expected_nonce is None:
            return
        if claims.get("nonce") != expected_nonce:
            if self.nonce_generator is None:
                raise InvalidDPoPProofError("The DPoP proof nonce is invalid.")
            raise UseDPoPNonceError(nonce=self.nonce_generator())
