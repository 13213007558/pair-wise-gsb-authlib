"""authlib.oauth2.rfc9449.
~~~~~~~~~~~~~~~~~~~~~~~~

OAuth 2.0 Demonstrating Proof of Possession (DPoP).

This module implements the resource server side of :rfc:`9449`: it validates
DPoP proof JWTs presented on protected requests and checks their binding to
the access token ``cnf.jkt`` through the :class:`DPoPProtector` extension.
"""

from .errors import DPoPError
from .errors import InvalidDPoPProofError
from .errors import UseDPoPNonceError
from .proof import DEFAULT_ALGORITHMS
from .proof import DPoPProof
from .proof import DPoPProofValidator
from .proof import compute_ath
from .proof import normalize_url
from .protector import DPoPProtector
from .protector import get_token_confirmation_jkt
from .replay import InMemoryReplayStore
from .replay import ReplayStore

__all__ = [
    "DEFAULT_ALGORITHMS",
    "DPoPError",
    "DPoPProof",
    "DPoPProofValidator",
    "DPoPProtector",
    "InMemoryReplayStore",
    "InvalidDPoPProofError",
    "ReplayStore",
    "UseDPoPNonceError",
    "compute_ath",
    "get_token_confirmation_jkt",
    "normalize_url",
]
