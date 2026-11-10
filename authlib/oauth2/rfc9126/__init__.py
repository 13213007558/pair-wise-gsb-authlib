"""authlib.oauth2.rfc9126.
~~~~~~~~~~~~~~~~~~~~~~~~~

This module represents a direct implementation of
OAuth 2.0 Pushed Authorization Requests.

:rfc:`9126`
"""

from .authorization_server import PushedAuthorizationRequest
from .discovery import AuthorizationServerMetadata
from .endpoint import PushedAuthorizationRequestEndpoint
from .registration import ClientMetadataClaims
from .store import InMemoryPushedAuthorizationRequestStore
from .store import PushedAuthorizationRequestData

__all__ = [
    "PushedAuthorizationRequest",
    "PushedAuthorizationRequestEndpoint",
    "PushedAuthorizationRequestData",
    "InMemoryPushedAuthorizationRequestStore",
    "AuthorizationServerMetadata",
    "ClientMetadataClaims",
]
