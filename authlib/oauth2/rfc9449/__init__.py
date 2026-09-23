"""authlib.oauth2.rfc9449.
~~~~~~~~~~~~~~~~~~~~~~~~

This module represents a direct implementation of
OAuth 2.0 Demonstrating Proof of Possession (DPoP).

https://www.rfc-editor.org/rfc/rfc9449
"""

from .errors import InvalidDPoPProofError
from .errors import InvalidDPoPTokenError
from .errors import UseDPoPNonceError
from .extension import DPoPExtension
from .proof import DPoPProof
from .proof import DPoPProofValidator
from .proof import compute_ath
from .proof import compute_jkt
from .proof import normalize_uri
from .store import DPoPStateStore
from .validator import DPoPTokenValidator

__all__ = [
    "InvalidDPoPProofError",
    "InvalidDPoPTokenError",
    "UseDPoPNonceError",
    "DPoPExtension",
    "DPoPProof",
    "DPoPProofValidator",
    "compute_ath",
    "compute_jkt",
    "normalize_uri",
    "DPoPStateStore",
    "DPoPTokenValidator",
]
