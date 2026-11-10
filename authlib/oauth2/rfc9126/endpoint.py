"""authlib.oauth2.rfc9126.endpoint.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The pushed authorization request endpoint of :rfc:`9126`. The client
pushes its authorization request parameters to this endpoint, and gets a
``request_uri`` to use at the authorization endpoint instead of the
parameters themselves.
"""

import time
from dataclasses import dataclass

from authlib.common.security import generate_token

from ..rfc6749.endpoint import Endpoint
from ..rfc6749.endpoint import EndpointRequest
from ..rfc6749.errors import InvalidRequestError
from ..rfc6749.errors import InvalidScopeError
from ..rfc6749.errors import UnsupportedResponseTypeError
from ..rfc6749.grants.base import AuthorizationEndpointMixin
from ..rfc6749.grants.base import validate_no_repeated_parameter
from ..rfc6749.responses import JsonResponse
from .authorization_server import REQUEST_URI_PREFIX
from .store import InMemoryPushedAuthorizationRequestStore
from .store import PushedAuthorizationRequestData

__all__ = ["PushedAuthorizationRequestEndpoint"]

#: The client credentials are authenticated, not stored.
_CREDENTIAL_PARAMETERS = ("client_secret", "client_assertion", "client_assertion_type")


@dataclass
class PushedAuthorizationEndpointRequest(EndpointRequest):
    """A validated pushed authorization request."""

    request_uri: str = ""
    expires_in: int = 0


class PushedAuthorizationRequestEndpoint(Endpoint):
    """Implementation of the pushed authorization request endpoint
    described in :rfc:`9126`.

    :param store: the reference storage. It implements the interface of
        :class:`~authlib.oauth2.rfc9126.InMemoryPushedAuthorizationRequestStore`.
        The endpoint and the
        :class:`~authlib.oauth2.rfc9126.PushedAuthorizationRequest`
        extension must share the same store.
    :param expires_in: the lifetime of the ``request_uri`` values, in seconds
    :param clock: a callable returning the current POSIX time, used when
        no ``store`` is given

    Register the endpoint and the extension with the same store::

        store = InMemoryPushedAuthorizationRequestStore()
        authorization_server.register_extension(PushedAuthorizationRequest(store))
        authorization_server.register_endpoint(PushedAuthorizationRequestEndpoint(store))
    """

    #: Endpoint name to be registered
    ENDPOINT_NAME = "pushed_authorization_request"

    #: Allowed client authenticate methods
    CLIENT_AUTH_METHODS = ["client_secret_basic", "client_secret_post", "none"]

    #: Default lifetime of the ``request_uri`` values, in seconds
    DEFAULT_EXPIRES_IN = 60

    def __init__(self, server=None, store=None, expires_in=None, clock=time.time):
        super().__init__(server)
        if store is None:
            store = InMemoryPushedAuthorizationRequestStore(clock=clock)
        self.store = store
        if expires_in is None:
            expires_in = self.DEFAULT_EXPIRES_IN
        self.expires_in = expires_in
        self._clock = clock

    def validate_request(self, request) -> PushedAuthorizationEndpointRequest:
        """Authenticate the client, validate the pushed parameters and
        store them. The client and parameter validation that can be done
        before the user is involved is done here.

        :raises InvalidClientError: if the client cannot authenticate
        :raises InvalidRequestError: if a parameter is invalid
        :raises UnsupportedResponseTypeError: if no grant supports the
            ``response_type``
        :raises InvalidScopeError: if the scope is not allowed
        """
        if request.method != "POST":
            raise InvalidRequestError(
                "The pushed authorization request endpoint requires the POST method."
            )

        # Per RFC 9126 §2, the client authenticates in the same way as at
        # the token endpoint.
        client = self.server.authenticate_client(
            request, self.CLIENT_AUTH_METHODS, "token"
        )
        request.client = client
        data = self.validate_pushed_parameters(request, client)

        request_uri = REQUEST_URI_PREFIX + generate_token(32)
        entry = PushedAuthorizationRequestData(
            request_uri=request_uri,
            client_id=client.get_client_id(),
            data=data,
            expires_at=self._clock() + self.expires_in,
        )
        self.store.save(entry)
        return PushedAuthorizationEndpointRequest(
            request, client, request_uri, self.expires_in
        )

    def validate_pushed_parameters(self, request, client):
        """Validate the pushed authorization request parameters and return
        the verified data to store. The client credentials are not stored.
        """
        payload = request.payload
        client_id = client.get_client_id()
        posted_client_id = payload.data.get("client_id")
        if posted_client_id is not None and posted_client_id != client_id:
            raise InvalidRequestError(
                "The 'client_id' parameter does not match the authenticated client."
            )

        if "request_uri" in payload.data:
            raise InvalidRequestError("The 'request_uri' parameter must not be pushed.")

        validate_no_repeated_parameter(request, self.server.authorization_parameters)

        if "request" not in payload.data:
            self.validate_response_type(request)
            AuthorizationEndpointMixin.validate_authorization_redirect_uri(
                request, client
            )
            self.server.validate_requested_scope(payload.scope)
            if client.get_allowed_scope(payload.scope) is None:
                raise InvalidScopeError()

        data = {
            name: value
            for name, value in request.form.items()
            if name not in _CREDENTIAL_PARAMETERS
        }
        data["client_id"] = client_id
        return data

    def validate_response_type(self, request):
        """Check that a registered grant supports the ``response_type``.

        The grants are checked directly, without resolving the request
        object extensions: a ``request`` object of :rfc:`9101` is verified
        at the authorization endpoint.
        """
        response_type = request.payload.response_type
        if not response_type:
            raise InvalidRequestError(
                "Missing 'response_type' in request.", state=request.payload.state
            )

        supported = any(
            grant_cls.check_authorization_endpoint(request)
            for grant_cls, _ in self.server._authorization_grants
        )
        if not supported:
            raise UnsupportedResponseTypeError(response_type)

    def create_response(self, validated_request: PushedAuthorizationEndpointRequest):
        """Return the ``request_uri`` and its lifetime, per :rfc:`9126`
        Section 2.2."""
        body = {
            "request_uri": validated_request.request_uri,
            "expires_in": validated_request.expires_in,
        }
        return JsonResponse(body, status_code=201)
