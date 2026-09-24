"""authlib.oauth2.rfc8693.
~~~~~~~~~~~~~~~~~~~~~~

This module represents an implementation of
OAuth 2.0 Token Exchange.

https://tools.ietf.org/html/rfc8693
"""

from .grant import ACCESS_TOKEN_TYPE
from .grant import ID_TOKEN_TYPE
from .grant import JWT_TOKEN_TYPE
from .grant import REFRESH_TOKEN_TYPE
from .grant import SAML1_TOKEN_TYPE
from .grant import SAML2_TOKEN_TYPE
from .grant import InvalidTargetError
from .grant import TokenExchangeContext
from .grant import TokenExchangeGrant
from .grant import current_token_exchange_context

__all__ = [
    "ACCESS_TOKEN_TYPE",
    "ID_TOKEN_TYPE",
    "JWT_TOKEN_TYPE",
    "REFRESH_TOKEN_TYPE",
    "SAML1_TOKEN_TYPE",
    "SAML2_TOKEN_TYPE",
    "InvalidTargetError",
    "TokenExchangeContext",
    "TokenExchangeGrant",
    "current_token_exchange_context",
]
