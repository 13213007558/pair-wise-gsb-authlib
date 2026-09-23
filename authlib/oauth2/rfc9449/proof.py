"""authlib.oauth2.rfc9449.proof.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

DPoP proof JWT parsing and validation per RFC 9449 Section 4.

https://www.rfc-editor.org/rfc/rfc9449#section-4
"""

import hashlib
import json
import time
from urllib.parse import urlsplit

from joserfc import jwk
from joserfc import jwt
from joserfc.errors import JoseError

from authlib.common.encoding import to_bytes
from authlib.common.encoding import to_unicode
from authlib.common.encoding import urlsafe_b64decode
from authlib.common.encoding import urlsafe_b64encode

from .errors import InvalidDPoPProofError
from .errors import UseDPoPNonceError

__all__ = [
    "DPoPProof",
    "DPoPProofValidator",
    "compute_ath",
    "compute_jkt",
    "normalize_uri",
]

PROOF_TYPE = "dpop+jwt"

#: per RFC 9449 Section 4.2, "none" and symmetric (MAC) algorithms
#: MUST NOT be used for DPoP proofs
ASYMMETRIC_ALGORITHMS = frozenset(
    [
        "RS256",
        "RS384",
        "RS512",
        "PS256",
        "PS384",
        "PS512",
        "ES256",
        "ES384",
        "ES512",
        "EdDSA",
    ]
)

ASYMMETRIC_KEY_TYPES = frozenset(["RSA", "EC", "OKP"])

#: JWK members that carry private key material
PRIVATE_JWK_MEMBERS = frozenset(["d", "p", "q", "dp", "dq", "qi", "oth", "k"])

#: default acceptable window (in seconds) for the "iat" claim
DEFAULT_IAT_LEEWAY = 300


def compute_jkt(jwk_dict):
    """Compute the JWK SHA-256 thumbprint (RFC 7638) of a public JWK
    dict. This is the value of the "cnf.jkt" confirmation claim.

    :param jwk_dict: a public JWK dict
    :return: base64url encoded thumbprint
    """
    key = jwk.import_key(jwk_dict)
    return key.thumbprint()


def compute_ath(access_token):
    """Compute the "ath" value of an access token, which is the
    base64url encoded SHA-256 hash of the ASCII token string.

    :param access_token: the access token string
    :return: base64url encoded hash, without padding
    """
    digest = hashlib.sha256(to_bytes(access_token, "ascii")).digest()
    return to_unicode(urlsafe_b64encode(digest)).rstrip("=")


def normalize_uri(uri):
    """Normalize an HTTP URI for "htu" comparison per RFC 9449 Section
    4.3. The query and fragment components are removed, the scheme and
    host are lowercased, and default ports are dropped. The path is
    kept intact, since rewriting it could change the identity of the
    resource.

    :param uri: the URI to normalize
    :return: normalized URI string
    """
    parts = urlsplit(uri)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    try:
        port = parts.port
    except ValueError:
        port = None
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        port = None
    authority = host if port is None else f"{host}:{port}"
    path = parts.path or "/"
    return f"{scheme}://{authority}{path}"


class DPoPProof:
    """A parsed and verified DPoP proof JWT."""

    def __init__(self, header, claims, jwk_dict, jkt):
        #: the protected header of the proof JWT
        self.header = header
        #: the claims of the proof JWT
        self.claims = claims
        #: the public JWK dict of the "jwk" header member
        self.jwk = jwk_dict
        #: the JWK SHA-256 thumbprint of the public key
        self.jkt = jkt


class DPoPProofValidator:
    """Validate DPoP proof JWTs on HTTP requests, per RFC 9449 Section
    4.3. This logic is shared by the token endpoint and the resource
    server.

    :param store: a DPoPStateStore instance for nonce handling and
        replay detection, provided by the application.
    :param clock: a callable returning the current UNIX timestamp, so
        that applications can control time (e.g. in tests).
    :param iat_leeway: acceptable "iat" window in seconds.
    :param status_code: HTTP status code of raised errors, 400 for the
        token endpoint, 401 for the resource server.
    :param realm: realm for the "WWW-Authenticate" header of 401 errors.
    """

    def __init__(
        self,
        store=None,
        clock=None,
        iat_leeway=DEFAULT_IAT_LEEWAY,
        status_code=400,
        realm=None,
    ):
        self.store = store
        self.clock = clock or time.time
        self.iat_leeway = iat_leeway
        self.status_code = status_code
        self.realm = realm

    def error(self, description):
        return InvalidDPoPProofError(
            description, status_code=self.status_code, realm=self.realm
        )

    def validate(self, request, access_token=None):
        """Validate the DPoP proof of an HTTP request.

        :param request: a request object with "method", "uri" and "headers".
        :param access_token: when given (resource server side), the "ath"
            claim of the proof MUST match this access token.
        :return: DPoPProof
        :raise: InvalidDPoPProofError
        :raise: UseDPoPNonceError
        """
        value = request.headers.get("DPoP")
        if not value:
            raise self.error("Missing 'DPoP' proof in headers.")

        proof = self.parse(value)
        claims = proof.claims

        htm = claims.get("htm")
        if not isinstance(htm, str) or htm.upper() != request.method.upper():
            raise self.error("Invalid 'htm' in DPoP proof.")

        self.validate_htu(claims.get("htu"), request.uri)
        self.validate_iat(claims.get("iat"))

        jti = claims.get("jti")
        if not jti or not isinstance(jti, str):
            raise self.error("Missing 'jti' in DPoP proof.")

        self.validate_nonce(claims)

        if access_token is not None:
            ath = claims.get("ath")
            if not ath or ath != compute_ath(access_token):
                raise self.error("Invalid 'ath' in DPoP proof.")

        # replay detection is the last step, so that a proof rejected
        # for other reasons does not burn its "jti"
        self.register_jti(proof, jti)
        return proof

    def parse(self, value):
        """Parse and verify the signature of a DPoP proof JWT.

        :param value: the proof JWT string of the "DPoP" header
        :return: DPoPProof
        :raise: InvalidDPoPProofError
        """
        try:
            header_segment = value.split(".")[0]
            header = json.loads(urlsafe_b64decode(to_bytes(header_segment)))
        except (ValueError, UnicodeDecodeError):
            raise self.error("Malformed DPoP proof.")

        if not isinstance(header, dict):
            raise self.error("Malformed DPoP proof.")

        if header.get("typ") != PROOF_TYPE:
            raise self.error("Invalid 'typ' in DPoP proof header.")

        alg = header.get("alg")
        if alg not in ASYMMETRIC_ALGORITHMS:
            raise self.error("Invalid 'alg' in DPoP proof header.")

        jwk_dict = header.get("jwk")
        if not isinstance(jwk_dict, dict):
            raise self.error("Missing 'jwk' in DPoP proof header.")

        if jwk_dict.get("kty") not in ASYMMETRIC_KEY_TYPES:
            raise self.error("Invalid 'kty' of 'jwk' in DPoP proof header.")

        if PRIVATE_JWK_MEMBERS.intersection(jwk_dict):
            raise self.error(
                "The 'jwk' in DPoP proof header MUST NOT contain "
                "private key material."
            )

        try:
            key = jwk.import_key(jwk_dict)
            token = jwt.decode(value, key)
        except (JoseError, ValueError):
            raise self.error("Invalid signature of DPoP proof.")

        return DPoPProof(
            header=token.header,
            claims=token.claims,
            jwk_dict=jwk_dict,
            jkt=key.thumbprint(),
        )

    def validate_htu(self, htu, uri):
        """The "htu" claim MUST match the HTTP URI of the request,
        ignoring the query and fragment components.

        :param htu: the "htu" claim of the proof
        :param uri: the URI of the HTTP request
        :raise: InvalidDPoPProofError
        """
        if not htu or not isinstance(htu, str):
            raise self.error("Missing 'htu' in DPoP proof.")

        parts = urlsplit(htu)
        if parts.query or parts.fragment:
            raise self.error(
                "The 'htu' in DPoP proof MUST NOT contain query or fragment."
            )

        if normalize_uri(htu) != normalize_uri(uri):
            raise self.error("Invalid 'htu' in DPoP proof.")

    def validate_iat(self, iat):
        """The "iat" claim MUST be present and within the acceptable
        window around the current time.

        :param iat: the "iat" claim of the proof
        :raise: InvalidDPoPProofError
        """
        now = int(self.clock())
        if (
            not isinstance(iat, int)
            or isinstance(iat, bool)
            or abs(now - iat) > self.iat_leeway
        ):
            raise self.error("Invalid 'iat' in DPoP proof.")

    def validate_nonce(self, claims):
        """If the application provided store requires a nonce, the
        "nonce" claim of the proof MUST match it, otherwise a
        "use_dpop_nonce" challenge is issued.

        :param claims: the claims of the proof
        :raise: UseDPoPNonceError
        """
        if self.store is None:
            return
        nonce = self.store.get_nonce()
        if nonce is not None and claims.get("nonce") != nonce:
            raise UseDPoPNonceError(
                nonce=nonce, status_code=self.status_code, realm=self.realm
            )

    def register_jti(self, proof, jti):
        """Atomically register the "jti" of the proof for replay
        detection. The application provided store decides if the
        (jkt, jti) pair was seen before.

        :param proof: the validated DPoPProof
        :param jti: the "jti" claim of the proof
        :raise: InvalidDPoPProofError
        """
        if self.store is None:
            return
        expires_at = int(self.clock()) + self.iat_leeway
        if not self.store.register_jti(proof.jkt, jti, expires_at):
            raise self.error("Replayed 'jti' in DPoP proof.")
