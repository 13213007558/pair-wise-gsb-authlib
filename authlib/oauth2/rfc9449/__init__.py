"""authlib.oauth2.rfc9449.
~~~~~~~~~~~~~~~~~~~~~~~~

Implementation of OAuth 2.0 Demonstrating Proof of Possession (DPoP).

https://www.rfc-editor.org/rfc/rfc9449.html
"""

from .errors import InvalidDPoPProofError
from .errors import InvalidDPoPTokenError
from .errors import UseDPoPNonceError
from .grant import DPoPClientCredentialsGrant
from .nonce import DPoPNonceProvider
from .proof import DPoPProof
from .proof import DPoPProofValidator
from .proof import compute_ath
from .store import DPoPReplayStore
from .store import InMemoryDPoPReplayStore
from .token import DPoPTokenGenerator
from .validator import DPoPTokenValidator

__all__ = [
    "InvalidDPoPProofError",
    "InvalidDPoPTokenError",
    "UseDPoPNonceError",
    "DPoPClientCredentialsGrant",
    "DPoPNonceProvider",
    "DPoPProof",
    "DPoPProofValidator",
    "compute_ath",
    "DPoPReplayStore",
    "InMemoryDPoPReplayStore",
    "DPoPTokenGenerator",
    "DPoPTokenValidator",
]
