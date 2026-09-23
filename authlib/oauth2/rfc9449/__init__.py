"""authlib.oauth2.rfc9449.
~~~~~~~~~~~~~~~~~~~~~~

Implementation of OAuth 2.0 Demonstrating Proof of Possession (DPoP)
per RFC 9449: https://www.rfc-editor.org/rfc/rfc9449
"""

from .errors import DPoPInvalidTokenError
from .errors import DPoPUseNonceError
from .errors import InvalidDPoPProofError
from .errors import UseDPoPNonceError
from .proof import DPoPProof
from .proof import DPoPProofError
from .proof import compute_ath
from .proof import compute_jkt
from .resource_server import DPoPTokenValidator
from .store import DPoPStateStore
from .token_endpoint import DPoPTokenExtension

__all__ = [
    "DPoPProof",
    "DPoPProofError",
    "DPoPStateStore",
    "DPoPTokenExtension",
    "DPoPTokenValidator",
    "DPoPInvalidTokenError",
    "DPoPUseNonceError",
    "InvalidDPoPProofError",
    "UseDPoPNonceError",
    "compute_ath",
    "compute_jkt",
]
