"""authlib.oauth2.rfc9126.
~~~~~~~~~~~~~~~~~~~~~~

This module represents an implementation of
OAuth 2.0 Pushed Authorization Requests.

https://www.rfc-editor.org/rfc/rfc9126.html
"""

from .authorization_server import PushedAuthorizationRequests
from .discovery import AuthorizationServerMetadata
from .endpoint import PushedAuthorizationRequestEndpoint
from .models import PushedAuthorizationRequestDict
from .models import PushedAuthorizationRequestMixin
from .registration import ClientMetadataClaims
from .store import InMemoryPushedAuthorizationRequestStore
from .store import PushedAuthorizationRequestStore

__all__ = [
    "PushedAuthorizationRequests",
    "PushedAuthorizationRequestEndpoint",
    "PushedAuthorizationRequestStore",
    "InMemoryPushedAuthorizationRequestStore",
    "PushedAuthorizationRequestMixin",
    "PushedAuthorizationRequestDict",
    "AuthorizationServerMetadata",
    "ClientMetadataClaims",
]
