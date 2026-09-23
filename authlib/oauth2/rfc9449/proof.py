"""authlib.oauth2.rfc9449.proof.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Stateless validation of DPoP proof JWTs per RFC 9449 Section 4.2 and
4.3. This module performs no I/O; replay protection and nonce storage
are delegated to 'DPoPStateStore' implementations provided by
the application.
"""

import hashlib
import json
import time
from urllib.parse import urlsplit

from joserfc import jws
from joserfc.errors import JoseError
from joserfc.jwk import KeySet

from authlib.common.encoding import to_bytes
from authlib.common.encoding import to_unicode
from authlib.common.encoding import urlsafe_b64encode

#: "typ" header value required for DPoP proof JWTs
DPOP_TYPE = "dpop+jwt"

#: algorithms that MUST NOT be used for DPoP proofs (symmetric or none)
SYMMETRIC_ALGORITHMS = frozenset(["none", "HS256", "HS384", "HS512"])

#: JWK members that indicate private or symmetric key material
PRIVATE_JWK_MEMBERS = frozenset(["d", "p", "q", "dp", "dq", "qi", "oth", "k"])

#: default acceptable age of a proof, in seconds
DEFAULT_MAX_AGE = 300


class DPoPProofError(ValueError):
    """Raised when a DPoP proof is invalid. Carries a human readable
    reason that callers can embed into an OAuth2 error response."""


class DPoPProof:
    """A successfully validated DPoP proof.

    :ivar jwk: the public JWK dict embedded in the proof header
    :ivar jkt: the JWK SHA-256 thumbprint of the public key
    :ivar claims: the payload claims of the proof JWT
    """

    def __init__(self, jwk, jkt, claims):
        self.jwk = jwk
        self.jkt = jkt
        self.claims = claims

    @property
    def jti(self):
        return self.claims.get("jti")

    @property
    def iat(self):
        return self.claims.get("iat")


def compute_jkt(public_jwk):
    """Compute the JWK SHA-256 thumbprint (RFC 7638) of a public JWK
    dict, base64url encoded without padding. This is the value placed
    into the 'cnf.jkt' confirmation claim."""
    key = KeySet.import_key_set({"keys": [public_jwk]}).keys[0]
    return key.thumbprint()


def compute_ath(access_token):
    """Compute the 'ath' value for an access token:
    base64url(SHA-256(ASCII(access_token))) without padding."""
    digest = hashlib.sha256(to_bytes(access_token, "ascii")).digest()
    return to_unicode(urlsafe_b64encode(digest))


def _authority(parts):
    scheme = parts.scheme.lower()
    host = parts.hostname
    if not scheme or not host:
        raise DPoPProofError("The 'htu' claim is not an absolute HTTP URI.")
    host = host.lower()
    try:
        port = parts.port
    except ValueError as exc:
        raise DPoPProofError("The 'htu' claim contains an invalid port.") from exc
    if port is None:
        if scheme == "https":
            port = 443
        elif scheme == "http":
            port = 80
    return scheme, host, port


def htu_matches(proof_htu, request_uri):
    """Compare the 'htu' claim with the URI of the HTTP request.

    Per RFC 9449 Section 4.3, the query and fragment components are
    ignored. The path is compared exactly: no normalization (dot-segment
    removal, case folding, trailing-slash rewriting) is applied, since
    such rewriting could change the identity of the target resource.
    """
    if not isinstance(proof_htu, str) or not isinstance(request_uri, str):
        return False
    try:
        proof_parts = urlsplit(proof_htu)
        request_parts = urlsplit(request_uri)
    except ValueError:
        return False
    try:
        if _authority(proof_parts) != _authority(request_parts):
            return False
    except DPoPProofError:
        return False
    # an empty path is equivalent to "/" for HTTP URIs (RFC 7230);
    # anything else is compared byte for byte
    proof_path = proof_parts.path or "/"
    request_path = request_parts.path or "/"
    return proof_path == request_path


def _validate_header(header):
    typ = header.get("typ")
    if not isinstance(typ, str) or typ.lower() != DPOP_TYPE:
        raise DPoPProofError("The proof 'typ' header must be 'dpop+jwt'.")

    alg = header.get("alg")
    if not isinstance(alg, str) or alg in SYMMETRIC_ALGORITHMS:
        raise DPoPProofError("The proof 'alg' header must be an asymmetric algorithm.")

    jwk = header.get("jwk")
    if not isinstance(jwk, dict):
        raise DPoPProofError("The proof header must embed a public 'jwk'.")

    kty = jwk.get("kty")
    if not kty or kty == "oct":
        raise DPoPProofError("The proof 'jwk' must be an asymmetric public key.")

    if PRIVATE_JWK_MEMBERS.intersection(jwk):
        raise DPoPProofError("The proof 'jwk' must not contain private key material.")

    return alg, jwk


def validate_dpop_proof(
    proof,
    *,
    htm,
    htu,
    access_token=None,
    now=None,
    max_age=DEFAULT_MAX_AGE,
):
    """Validate a DPoP proof JWT and return a 'DPoPProof'.

    :param proof: the compact JWS from the 'DPoP' HTTP header
    :param htm: the HTTP method of the request the proof is attached to
    :param htu: the HTTP URI of the request (query/fragment are ignored)
    :param access_token: when verifying a resource request, the access
        token sent alongside the proof; the 'ath' claim is then required
    :param now: current timestamp in seconds; injectable for testing
    :param max_age: maximum acceptable age of the proof in seconds
    :raise DPoPProofError: if the proof is invalid
    """
    if now is None:
        now = time.time()

    if not isinstance(proof, str) or proof.count(".") != 2:
        raise DPoPProofError("The DPoP proof is not a compact JWS.")

    try:
        extracted = jws.extract_compact(to_bytes(proof, "utf-8"))
        header = extracted.headers()
    except (JoseError, ValueError) as exc:
        raise DPoPProofError("The DPoP proof is malformed.") from exc

    alg, public_jwk = _validate_header(header)

    try:
        key_set = KeySet.import_key_set({"keys": [public_jwk]})
    except (JoseError, ValueError) as exc:
        raise DPoPProofError("The proof 'jwk' is not a valid public key.") from exc

    try:
        # restrict verification to the algorithm declared in the header,
        # which also enforces key/algorithm compatibility
        obj = jws.deserialize_compact(
            to_bytes(proof, "utf-8"), key_set, algorithms=[alg]
        )
    except JoseError as exc:
        raise DPoPProofError("The DPoP proof signature is invalid.") from exc

    try:
        claims = json.loads(obj.payload)
    except (TypeError, ValueError) as exc:
        raise DPoPProofError("The DPoP proof payload is not a JSON object.") from exc
    if not isinstance(claims, dict):
        raise DPoPProofError("The DPoP proof payload is not a JSON object.")

    proof_htm = claims.get("htm")
    if not isinstance(proof_htm, str) or proof_htm.upper() != htm.upper():
        raise DPoPProofError("The 'htm' claim does not match the request method.")

    if not htu_matches(claims.get("htu"), htu):
        raise DPoPProofError("The 'htu' claim does not match the request URI.")

    iat = claims.get("iat")
    if isinstance(iat, bool) or not isinstance(iat, int | float):
        raise DPoPProofError("The 'iat' claim must be a number.")
    if abs(now - iat) > max_age:
        raise DPoPProofError("The 'iat' claim is outside the acceptable window.")

    jti = claims.get("jti")
    if not isinstance(jti, str) or not jti or len(jti) > 1024:
        raise DPoPProofError("The 'jti' claim must be a non-empty string.")

    if access_token is not None:
        ath = claims.get("ath")
        if not isinstance(ath, str) or ath != compute_ath(access_token):
            raise DPoPProofError(
                "The 'ath' claim does not match the presented access token."
            )

    jkt = compute_jkt(public_jwk)
    return DPoPProof(jwk=public_jwk, jkt=jkt, claims=claims)


def get_cnf_jkt(cnf):
    """Extract the 'jkt' value from a 'cnf' structure, which may be
    a dict or a JSON encoded string. Returns None when absent."""
    if isinstance(cnf, str):
        try:
            cnf = json.loads(cnf)
        except ValueError:
            return None
    if isinstance(cnf, dict):
        return cnf.get("jkt")
    return None
