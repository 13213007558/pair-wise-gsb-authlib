"""authlib.oauth2.rfc9396.
~~~~~~~~~~~~~~~~~~~~~~

Implementation of RFC 9396: OAuth 2.0 Rich Authorization Requests.

https://www.rfc-editor.org/rfc/rfc9396
"""

from .dataset_access import DatasetAccessHandler
from .errors import InvalidAuthorizationDetailsError
from .handlers import AuthorizationDetailsHandler
from .validation import parse_authorization_details
from .validation import validate_consented_details
from .validation import validate_within_granted

__all__ = [
    "AuthorizationDetailsHandler",
    "DatasetAccessHandler",
    "InvalidAuthorizationDetailsError",
    "parse_authorization_details",
    "validate_consented_details",
    "validate_within_granted",
]
