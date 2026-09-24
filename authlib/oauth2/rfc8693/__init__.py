"""authlib.oauth2.rfc8693.
~~~~~~~~~~~~~~~~~~~~~~

This module represents an implementation of
OAuth 2.0 Token Exchange.

https://tools.ietf.org/html/rfc8693
"""

from .claims import ActorChainError
from .claims import build_actor_claim
from .claims import ensure_acyclic_actor_chain
from .claims import parse_actor_chain
from .errors import InvalidTargetError
from .grant import ACCESS_TOKEN_TYPE
from .grant import ID_TOKEN_TYPE
from .grant import JWT_TOKEN_TYPE
from .grant import REFRESH_TOKEN_TYPE
from .grant import SAML1_TOKEN_TYPE
from .grant import SAML2_TOKEN_TYPE
from .grant import TOKEN_EXCHANGE_GRANT_TYPE
from .grant import TokenExchangeGrant
from .validator import TokenExchangeBearerTokenValidator

__all__ = [
    "ActorChainError",
    "build_actor_claim",
    "ensure_acyclic_actor_chain",
    "parse_actor_chain",
    "InvalidTargetError",
    "ACCESS_TOKEN_TYPE",
    "ID_TOKEN_TYPE",
    "JWT_TOKEN_TYPE",
    "REFRESH_TOKEN_TYPE",
    "SAML1_TOKEN_TYPE",
    "SAML2_TOKEN_TYPE",
    "TOKEN_EXCHANGE_GRANT_TYPE",
    "TokenExchangeGrant",
    "TokenExchangeBearerTokenValidator",
]
