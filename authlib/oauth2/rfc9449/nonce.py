"""authlib.oauth2.rfc9449.nonce.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Optional server-provided nonce for DPoP proofs, per RFC 9449 Section 8.

A nonce is NOT single-use: the same nonce can be presented by concurrent
proofs. Replay protection is always ensured by the ``jti`` claim, the
nonce only limits the lifetime of a proof to a server-chosen window.
"""

import hashlib
import hmac
import time

from authlib.common.encoding import to_bytes
from authlib.common.encoding import to_unicode
from authlib.common.encoding import urlsafe_b64decode
from authlib.common.encoding import urlsafe_b64encode
from authlib.common.security import generate_token

__all__ = [
    "DPoPNonceProvider",
]


class DPoPNonceProvider:
    """Stateless nonce provider using HMAC-signed timestamps.

    :param secret_key: key used to sign nonces. A random one is generated
        if omitted (nonces will not survive a process restart).
    :param max_age: lifetime of a nonce in seconds, default is 300.

    The same nonce remains valid within its lifetime, so it can serve
    concurrent proofs; replay detection stays based on ``jti``.
    """

    def __init__(self, secret_key=None, max_age=300):
        if secret_key is None:
            secret_key = generate_token(32)
        self.secret_key = to_bytes(secret_key)
        self.max_age = max_age

    def generate_nonce(self) -> str:
        """Create a fresh nonce value for the ``DPoP-Nonce`` header."""
        timestamp = str(int(time.time()))
        random_part = generate_token(16)
        payload = to_unicode(urlsafe_b64encode(to_bytes(f"{timestamp}.{random_part}")))
        signature = self._sign(payload)
        return f"{payload}.{signature}"

    def validate_nonce(self, nonce) -> bool:
        """Check that a nonce was issued by this provider and is not
        expired. The nonce is not consumed by validation.
        """
        if not nonce or not isinstance(nonce, str):
            return False
        try:
            payload, signature = nonce.rsplit(".", 1)
        except ValueError:
            return False
        if not hmac.compare_digest(self._sign(payload), signature):
            return False
        try:
            decoded = to_unicode(urlsafe_b64decode(to_bytes(payload)))
            timestamp = int(decoded.split(".", 1)[0])
        except (ValueError, UnicodeDecodeError):
            return False
        return 0 <= time.time() - timestamp <= self.max_age

    def _sign(self, payload: str) -> str:
        digest = hmac.new(
            self.secret_key,
            to_bytes(payload),
            hashlib.sha256,
        ).digest()
        return to_unicode(urlsafe_b64encode(digest))
