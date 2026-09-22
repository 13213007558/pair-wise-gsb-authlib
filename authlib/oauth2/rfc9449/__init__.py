"""authlib.oauth2.rfc9449.
~~~~~~~~~~~~~~~~~~~~~~

This module represents a direct implementation of
OAuth 2.0 Demonstrating Proof of Possession (DPoP).

https://www.rfc-editor.org/rfc/rfc9449.html
"""

from .errors import DPoPInvalidTokenError
from .errors import InvalidDPoPProofError
from .errors import UseDPoPNonceError
from .grant_extension import DPoPGrantExtension
from .proof import DPoPProof
from .proof import compute_ath
from .proof import normalize_htu
from .store import DPoPReplayStore
from .store import InMemoryDPoPReplayStore
from .token import DPoPTokenGenerator
from .token_validator import DPoPTokenValidator
from .validator import DPoPProofValidator

__all__ = [
    "DPoPProof",
    "DPoPProofValidator",
    "DPoPReplayStore",
    "InMemoryDPoPReplayStore",
    "DPoPTokenGenerator",
    "DPoPTokenValidator",
    "DPoPGrantExtension",
    "InvalidDPoPProofError",
    "UseDPoPNonceError",
    "DPoPInvalidTokenError",
    "compute_ath",
    "normalize_htu",
]
