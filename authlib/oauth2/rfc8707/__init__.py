"""authlib.oauth2.rfc8707.
~~~~~~~~~~~~~~~~~~~~~~

This module represents a direct implementation of
Resource Indicators for OAuth 2.0.

https://www.rfc-editor.org/rfc/rfc8707.html
"""

from .errors import InvalidTargetError
from .grants import AuthorizationCodeGrant
from .grants import RefreshTokenGrant
from .models import AuthorizationCodeMixin
from .models import TokenMixin
from .util import extract_resource_parameter
from .util import validate_resource_parameter

__all__ = [
    "InvalidTargetError",
    "AuthorizationCodeGrant",
    "RefreshTokenGrant",
    "AuthorizationCodeMixin",
    "TokenMixin",
    "extract_resource_parameter",
    "validate_resource_parameter",
]
