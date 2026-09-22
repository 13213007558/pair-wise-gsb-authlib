"""authlib.oauth2.rfc9449.proof.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Validation of DPoP proof JWTs, per RFC 9449 Section 4.
"""

import hashlib
import hmac
import time
from urllib.parse import urlsplit
from urllib.parse import urlunsplit

from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jwk import import_key

from authlib.common.encoding import json_loads
from authlib.common.encoding import to_bytes
from authlib.common.encoding import to_unicode
from authlib.common.encoding import urlsafe_b64decode
from authlib.common.encoding import urlsafe_b64encode

from .errors import InvalidDPoPProofError
from .errors import UseDPoPNonceError
from .store import InMemoryDPoPReplayStore

__all__ = [
    "DPoPProof",
    "DPoPProofValidator",
    "compute_ath",
]

#: JWK members that carry private or symmetric key material. A DPoP proof
#: MUST only contain a public key (RFC 9449, Section 4.2).
_FORBIDDEN_JWK_MEMBERS = frozenset(["d", "p", "q", "dp", "dq", "qi", "oth", "k"])

#: JOSE header parameters that reference key material located elsewhere.
#: A DPoP proof MUST be self-contained; remote key URLs MUST NOT be
#: fetched or trusted (RFC 9449, Section 4.2).
_FORBIDDEN_HEADER_PARAMS = frozenset(["jku", "x5u", "x5c", "x5t", "x5t#S256"])

_DEFAULT_PORTS = {
    "http": 80,
    "https": 443,
}


def compute_ath(access_token: str) -> str:
    """Compute the ``ath`` value for an access token: the base64url
    encoded SHA-256 hash of the ASCII token string (RFC 9449, Section 4.2).
    """
    digest = hashlib.sha256(to_bytes(access_token)).digest()
    return to_unicode(urlsafe_b64encode(digest))


def normalize_htu(url: str) -> str:
    """Normalize an HTTP URI for ``htu`` comparison: the query and fragment
    components are removed, and the scheme and host are lowercased, per
    RFC 9449 Section 4.3.
    """
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    hostname = (parts.hostname or "").lower()
    try:
        port = parts.port
    except ValueError:
        port = None
    if port is not None and port != _DEFAULT_PORTS.get(scheme):
        netloc = f"{hostname}:{port}"
    else:
        netloc = hostname
    path = parts.path or "/"
    return urlunsplit((scheme, netloc, path, "", ""))


class DPoPProof:
    """A validated DPoP proof.

    :param header: the verified JOSE header of the proof JWT.
    :param claims: the verified claims of the proof JWT.
    :param jkt: the JWK SHA-256 thumbprint (RFC 7638) of the proof public key.
    """

    def __init__(self, header, claims, jkt):
        self.header = header
        self.claims = claims
        self.jkt = jkt


class DPoPProofValidator:
    """Validate DPoP proof JWTs.

    :param allowed_algs: allowed (asymmetric) JWS algorithms for proofs,
        default is ``("ES256",)``. ``none`` and symmetric algorithms SHOULD
        NOT be listed here.
    :param max_age: maximum age of a proof in seconds, used to validate the
        ``iat`` claim and as the lifetime of replay records. Default is 300.
    :param leeway: clock skew tolerance in seconds when validating ``iat``.
        Default is 30.
    :param replay_store: a :class:`DPoPReplayStore` used to detect proof
        replays. Defaults to a process-local in-memory store.
    :param nonce_provider: an optional :class:`DPoPNonceProvider`. When set,
        proofs MUST contain a valid ``nonce`` claim.
    """

    def __init__(
        self,
        allowed_algs=("ES256",),
        max_age=300,
        leeway=30,
        replay_store=None,
        nonce_provider=None,
    ):
        self.allowed_algs = tuple(allowed_algs)
        self.max_age = max_age
        self.leeway = leeway
        if replay_store is None:
            replay_store = InMemoryDPoPReplayStore()
        self.replay_store = replay_store
        self.nonce_provider = nonce_provider

    def validate(self, proof_jwt, method, url, access_token=None) -> DPoPProof:
        """Validate a DPoP proof and return a :class:`DPoPProof`.

        :param proof_jwt: the compact serialization of the proof JWT.
        :param method: the HTTP method of the request carrying the proof.
        :param url: the absolute HTTP URI of the request carrying the proof.
        :param access_token: when validating a proof on a protected resource
            request, the access token it must be bound to via ``ath``.
        :raise InvalidDPoPProofError: if the proof is invalid.
        :raise UseDPoPNonceError: if a server nonce is required or stale.
        """
        header = self._decode_header(proof_jwt)
        self._validate_header(header)
        jwk = self._import_jwk(header)
        claims = self._verify_signature(proof_jwt, jwk)
        self._validate_claims(claims, method, url, access_token)
        # The proof identifier is recorded only after every other check
        # (including the signature) passed, so that a forged proof cannot
        # burn the ``jti`` of a legitimate one.
        self._record_jti(claims)
        return DPoPProof(header, claims, jwk.thumbprint())

    @staticmethod
    def _decode_header(proof_jwt):
        if not proof_jwt or not isinstance(proof_jwt, str):
            raise InvalidDPoPProofError("Missing DPoP proof.")
        parts = proof_jwt.split(".")
        if len(parts) != 3:
            raise InvalidDPoPProofError("The DPoP proof is not a compact JWS.")
        try:
            header = json_loads(urlsafe_b64decode(to_bytes(parts[0])))
        except (ValueError, TypeError):
            raise InvalidDPoPProofError(
                "The DPoP proof header is not valid JSON."
            ) from None
        if not isinstance(header, dict):
            raise InvalidDPoPProofError("The DPoP proof header is not a JSON object.")
        return header

    def _validate_header(self, header):
        # RFC 9449, Section 4.2: the JOSE header MUST contain ``typ``,
        # ``alg`` and ``jwk``.
        typ = header.get("typ")
        if typ != "dpop+jwt":
            raise InvalidDPoPProofError(
                "The DPoP proof header 'typ' must be 'dpop+jwt'."
            )

        alg = header.get("alg")
        if not alg or alg == "none" or alg not in self.allowed_algs:
            raise InvalidDPoPProofError(
                f"The DPoP proof algorithm '{alg}' is not allowed."
            )

        untrusted = _FORBIDDEN_HEADER_PARAMS.intersection(header)
        if untrusted:
            raise InvalidDPoPProofError(
                "The DPoP proof header must not contain: "
                + ", ".join(sorted(untrusted))
            )

        jwk = header.get("jwk")
        if not isinstance(jwk, dict) or not jwk.get("kty"):
            raise InvalidDPoPProofError(
                "The DPoP proof header must contain a public 'jwk'."
            )
        leaked = _FORBIDDEN_JWK_MEMBERS.intersection(jwk)
        if leaked:
            raise InvalidDPoPProofError(
                "The DPoP proof 'jwk' must not contain private or "
                "symmetric key material."
            )

    @staticmethod
    def _import_jwk(header):
        try:
            return import_key(header["jwk"])
        except (ValueError, KeyError, TypeError) as exc:
            raise InvalidDPoPProofError(
                "The DPoP proof 'jwk' is not a valid public key."
            ) from exc

    @staticmethod
    def _verify_signature(proof_jwt, jwk):
        try:
            token = jwt.decode(proof_jwt, jwk)
        except JoseError as exc:
            raise InvalidDPoPProofError("The DPoP proof signature is invalid.") from exc
        return token.claims

    def _validate_claims(self, claims, method, url, access_token):
        # RFC 9449, Section 4.2: the payload MUST contain ``jti``, ``htm``,
        # ``htu`` and ``iat``.
        jti = claims.get("jti")
        if not jti or not isinstance(jti, str):
            raise InvalidDPoPProofError("The DPoP proof is missing 'jti'.")

        htm = claims.get("htm")
        # HTTP methods are case-sensitive (RFC 9110, Section 9.1); the
        # comparison MUST be exact.
        if not htm or htm != method:
            raise InvalidDPoPProofError(
                "The DPoP proof 'htm' does not match the request method."
            )

        htu = claims.get("htu")
        if not htu or not isinstance(htu, str):
            raise InvalidDPoPProofError("The DPoP proof is missing 'htu'.")
        # The query and fragment components are ignored in the comparison,
        # per RFC 9449 Section 4.3.
        if normalize_htu(htu) != normalize_htu(url):
            raise InvalidDPoPProofError(
                "The DPoP proof 'htu' does not match the request URI."
            )

        iat = claims.get("iat")
        if not isinstance(iat, (int, float)) or isinstance(iat, bool):
            raise InvalidDPoPProofError("The DPoP proof 'iat' is missing or invalid.")
        now = time.time()
        if iat > now + self.leeway or iat < now - self.max_age:
            raise InvalidDPoPProofError(
                "The DPoP proof 'iat' is outside the acceptable window."
            )

        if access_token is not None:
            # RFC 9449, Section 6.1: proofs presented to a resource server
            # MUST contain an ``ath`` claim bound to the access token.
            ath = claims.get("ath")
            if not ath or not hmac.compare_digest(str(ath), compute_ath(access_token)):
                raise InvalidDPoPProofError(
                    "The DPoP proof 'ath' does not match the access token."
                )

        if self.nonce_provider is not None:
            nonce = claims.get("nonce")
            if not self.nonce_provider.validate_nonce(nonce):
                raise UseDPoPNonceError(
                    nonce=self.nonce_provider.generate_nonce(),
                )

    def _record_jti(self, claims):
        expires_at = time.time() + self.max_age
        if not self.replay_store.record(claims["jti"], expires_at):
            raise InvalidDPoPProofError("The DPoP proof 'jti' has already been used.")
