"""authlib.oauth2.rfc8693.
~~~~~~~~~~~~~~~~~~~~~~

This module represents an implementation of
OAuth 2.0 Token Exchange.

:rfc:`8693`
"""

from .errors import InvalidTargetError
from .grants import ACCESS_TOKEN_TYPE
from .grants import TOKEN_EXCHANGE_GRANT_TYPE
from .grants import TokenExchangeGrant
from .models import DelegationDecision
from .models import Principal
from .models import TokenInfo

__all__ = [
    "TokenExchangeGrant",
    "TokenInfo",
    "Principal",
    "DelegationDecision",
    "InvalidTargetError",
    "TOKEN_EXCHANGE_GRANT_TYPE",
    "ACCESS_TOKEN_TYPE",
]
