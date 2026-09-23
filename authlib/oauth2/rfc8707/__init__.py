"""authlib.oauth2/rfc8707
~~~~~~~~~~~~~~~~~~~~~~

This module represents a direct implementation of
Resource Indicators for OAuth 2.0.

https://www.rfc-editor.org/rfc/rfc8707
"""

from .errors import InvalidTargetError
from .grant import ResourceIndicator

__all__ = ["InvalidTargetError", "ResourceIndicator"]
