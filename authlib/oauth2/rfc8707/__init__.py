"""authlib.oauth2.rfc8707.
~~~~~~~~~~~~~~~~~~~~~~

This module represents a direct implementation of
Resource Indicators for OAuth 2.0.

:rfc:`8707`
"""

from .errors import InvalidTargetError
from .grants import ResourceIndicators
from .parameter import get_resource_indicators
from .parameter import validate_resource_indicator

__all__ = [
    "InvalidTargetError",
    "ResourceIndicators",
    "get_resource_indicators",
    "validate_resource_indicator",
]
