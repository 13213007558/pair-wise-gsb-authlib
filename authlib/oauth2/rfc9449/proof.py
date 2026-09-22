"""authlib.oauth2.rfc9449.proof.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Parsing and validation of DPoP proof JWTs.

https://www.rfc-editor.org/rfc/rfc9449.html#section-4.2
"""

import hashlib
import urllib.parse as urlparse

from joserfc import jwt as _jwt
from joserfc.errors import JoseError
from joserfc.jwk import import_key

from authlib.common.encoding import json_loads
from authlib.common.encoding import to_bytes
from authlib.common.encoding import to_unicode
from authlib.common.encoding import urlsafe_b64decode
from authlib.common.encoding import urlsafe_b64encode

from .errors import InvalidDPoPProofError

#: JWK members that only appear in private keys. A DPoP proof MUST NOT
#: contain a private key.
PRIVATE_JWK_MEMBERS = frozenset(["d", "p", "q", "dp", "dq", "qi", "oth", "k"])

#: mapping of ``alg`` to the required ``kty`` (and ``crv`` for EC keys)
ALG_KEY_TYPES = {
    "ES256": ("EC", "P-256"),
    "ES384": ("EC", "P-384"),
    "ES512": ("EC", "P-521"),
    "RS256": ("RSA", None),
    "RS384": ("RSA", None),
    "RS512": ("RSA", None),
    "PS256": ("RSA", None),
    "PS384": ("RSA", None),
    "PS512": ("RSA", None),
    "EdDSA": ("OKP", None),
}


class DPoPProof:
    """A parsed and signature-verified DPoP proof.

    :param header: the JWS header of the proof JWT
    :param claims: the claims set of the proof JWT
    :param public_jwk: the public JWK contained in the proof header
    :param jkt: the JWK SHA-256 thumbprint of ``public_jwk`` (RFC 7638)
    """

    def __init__(self, header, claims, public_jwk, jkt):
        self.header = header
        self.claims = claims
        self.public_jwk = public_jwk
        self.jkt = jkt

    def __getitem__(self, item):
        return self.claims[item]

    def get(self, item, default=None):
        return self.claims.get(item, default)


def compute_ath(access_token):
    """Compute the ``ath`` value for an access token, which is the
    base64url encoded SHA-256 hash of the ASCII encoding of the token.

    https://www.rfc-editor.org/rfc/rfc9449.html#section-4.2
    """
    digest = hashlib.sha256(to_bytes(access_token, "ascii")).digest()
    return to_unicode(urlsafe_b64encode(digest))


def normalize_htu(uri):
    """Normalize an HTTP URI for ``htu`` comparison. The query and fragment
    components are removed, the scheme and host are lowercased, and default
    ports are made explicit.

    https://www.rfc-editor.org/rfc/rfc9449.html#section-4.3
    """
    parts = urlparse.urlsplit(to_unicode(uri))
    scheme = parts.scheme.lower()
    host = parts.hostname.lower() if parts.hostname else ""
    try:
        port = parts.port
    except ValueError:
        raise InvalidDPoPProofError("Invalid port in URI.") from None
    if port is None:
        if scheme == "http":
            port = 80
        elif scheme == "https":
            port = 443
    netloc = f"{host}:{port}" if port is not None else host
    path = parts.path or "/"
    return urlparse.urlunsplit((scheme, netloc, path, "", ""))


def check_public_jwk(public_jwk, alg):
    """Validate the ``jwk`` header parameter of a DPoP proof. Only inline
    public keys are accepted; remote key references (``jku``, ``x5u``) are
    never dereferenced. The key MUST NOT contain private key material and
    MUST match the proof ``alg``.
    """
    if not isinstance(public_jwk, dict):
        raise InvalidDPoPProofError("The 'jwk' header parameter must be a JWK.")

    if PRIVATE_JWK_MEMBERS.intersection(public_jwk):
        raise InvalidDPoPProofError(
            "The 'jwk' header parameter MUST NOT contain a private key."
        )

    kty = public_jwk.get("kty")
    expected = ALG_KEY_TYPES.get(alg)
    if expected is None:
        raise InvalidDPoPProofError(f"Unsupported DPoP alg {alg!r}.")

    expected_kty, expected_crv = expected
    if kty != expected_kty:
        raise InvalidDPoPProofError(
            f"The 'jwk' key type {kty!r} does not match alg {alg!r}."
        )
    if expected_crv is not None and public_jwk.get("crv") != expected_crv:
        raise InvalidDPoPProofError(f"The 'jwk' curve does not match alg {alg!r}.")


def parse_proof(value, algs):
    """Parse a DPoP proof JWT and verify its signature with the public key
    embedded in its ``jwk`` header parameter.

    :param value: the compact serialization of the proof JWT
    :param algs: a collection of allowed ``alg`` values
    :return: DPoPProof
    :raise: InvalidDPoPProofError
    """
    try:
        segments = to_unicode(value).split(".")
    except (TypeError, ValueError):
        raise InvalidDPoPProofError("Malformed DPoP proof.") from None

    if len(segments) != 3:
        raise InvalidDPoPProofError("Malformed DPoP proof.")

    try:
        header = json_loads(urlsafe_b64decode(to_bytes(segments[0])))
    except (TypeError, ValueError):
        raise InvalidDPoPProofError("Malformed DPoP proof header.") from None

    if not isinstance(header, dict):
        raise InvalidDPoPProofError("Malformed DPoP proof header.")

    # https://www.rfc-editor.org/rfc/rfc9449.html#section-4.2
    # the typ of a DPoP proof MUST be "dpop+jwt"
    if header.get("typ") != "dpop+jwt":
        raise InvalidDPoPProofError("Invalid 'typ' in DPoP proof header.")

    # the alg MUST be an asymmetric signature algorithm, and MUST be one
    # of the algorithms accepted by the server
    alg = header.get("alg")
    if not alg or alg not in algs or alg not in ALG_KEY_TYPES:
        raise InvalidDPoPProofError("Invalid 'alg' in DPoP proof header.")

    public_jwk = header.get("jwk")
    if public_jwk is None:
        raise InvalidDPoPProofError("Missing 'jwk' in DPoP proof header.")
    check_public_jwk(public_jwk, alg)

    try:
        key = import_key(public_jwk)
    except (ValueError, JoseError):
        raise InvalidDPoPProofError("Invalid 'jwk' in DPoP proof header.") from None

    try:
        token = _jwt.decode(value, key, algorithms=[alg])
    except JoseError:
        raise InvalidDPoPProofError("The DPoP proof signature is invalid.") from None

    claims = token.claims
    jkt = key.thumbprint()
    return DPoPProof(header, claims, public_jwk, jkt)
