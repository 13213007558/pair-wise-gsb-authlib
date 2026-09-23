"""authlib.oauth2.rfc9396.
~~~~~~~~~~~~~~~~~~~~~~~~

Implementation of OAuth 2.0 Rich Authorization Requests (RAR). It adds
the ``authorization_details`` parameter, a JSON array of typed objects,
to the authorization, token and refresh token flows.

https://www.rfc-editor.org/rfc/rfc9396
"""

from .base import AuthorizationDetailsHandler
from .base import is_within_granted_details
from .base import parse_authorization_details
from .errors import InvalidAuthorizationDetailsError

__all__ = [
    "AuthorizationDetailsHandler",
    "InvalidAuthorizationDetailsError",
    "parse_authorization_details",
    "is_within_granted_details",
]
