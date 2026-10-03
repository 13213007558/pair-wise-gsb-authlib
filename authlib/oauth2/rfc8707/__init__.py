"""authlib.oauth2.rfc8707.
~~~~~~~~~~~~~~~~~~~~~~~~~~

Resource Indicators for OAuth 2.0.

https://www.rfc-editor.org/rfc/rfc8707.html
"""

from .errors import InvalidTargetError
from .resource import ResourcePolicy
from .resource import get_resource_indicators
from .resource import is_absolute_uri
from .resource import unique_resource_indicators
from .resource import validate_resource_indicators

__all__ = [
    "InvalidTargetError",
    "ResourcePolicy",
    "get_resource_indicators",
    "is_absolute_uri",
    "unique_resource_indicators",
    "validate_resource_indicators",
]
