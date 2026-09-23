"""authlib.oauth2.rfc9126.endpoint
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Implementation of the Pushed Authorization Request endpoint defined in
RFC9126_. Clients post the full authorization request to this endpoint
from their back-end and receive an opaque, short-lived "request_uri".
The user agent then only carries "client_id" and "request_uri" to the
authorization endpoint.

.. _RFC9126: https://www.rfc-editor.org/rfc/rfc9126
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from dataclasses import field

from authlib.common.security import generate_token
from authlib.consts import default_json_headers

from ..rfc6749.endpoint import Endpoint
from ..rfc6749.endpoint import EndpointRequest
from ..rfc6749.errors import InvalidRequestError
from ..rfc6749.errors import OAuth2Error
from ..rfc6749.requests import BasicOAuth2Payload
from ..rfc6749.requests import OAuth2Request
from .models import PushedAuthorizationRequest
from .store import InMemoryPushedAuthorizationRequestStore

#: Parameters used for client authentication. They are not part of the
#: authorization request and MUST NOT be stored with the pushed data.
CLIENT_AUTH_PARAMETERS = {
    "client_secret",
    "client_assertion",
    "client_assertion_type",
}


@dataclass
class PushedAuthorizationEndpointRequest(EndpointRequest):
    """Validated pushed authorization request."""

    params: dict = field(default_factory=dict)


class PushedAuthorizationRequestEndpoint(Endpoint):
    """The pushed authorization request endpoint of RFC9126_.

    Register it on the authorization server, optionally with a custom
    store::

        server.register_endpoint(PushedAuthorizationRequestEndpoint(store=MyStore()))

    and route the HTTP traffic to it, e.g. with Flask::

        @app.route("/oauth/par", methods=["POST"])
        def pushed_authorization_request():
            return server.create_endpoint_response("pushed_authorization_request")

    .. _RFC9126: https://www.rfc-editor.org/rfc/rfc9126
    """

    ENDPOINT_NAME = "pushed_authorization_request"

    #: Client authentication methods supported by this endpoint. "none"
    #: is included so that public clients are handled according to their
    #: registered authentication method.
    CLIENT_AUTH_METHODS = ["client_secret_basic", "client_secret_post", "none"]

    #: Lifetime in seconds of the issued "request_uri"
    EXPIRES_IN = 90

    #: Scheme of the generated "request_uri" values. The URN scheme lets
    #: the authorization server tell pushed authorization requests apart
    #: from the "request_uri" parameter of RFC9101, which uses URLs.
    REQUEST_URI_PREFIX = "urn:ietf:params:oauth:request_uri:"

    def __init__(self, server=None, store=None, expires_in=None):
        super().__init__(server)
        if store is None:
            store = InMemoryPushedAuthorizationRequestStore()
        self.store = store
        if expires_in is not None:
            self.EXPIRES_IN = expires_in

    def validate_request(self, request: OAuth2Request):
        # the client authenticates the same way it would on the token
        # endpoint, public clients use their registered "none" method
        client = self.server.authenticate_client(
            request, self.CLIENT_AUTH_METHODS, self.ENDPOINT_NAME
        )
        request.client = client

        payload_client_id = request.payload.client_id
        if payload_client_id and payload_client_id != client.get_client_id():
            raise InvalidRequestError(
                "The 'client_id' does not match the authenticated client."
            )

        if "request_uri" in request.payload.data:
            raise InvalidRequestError(
                "A pushed authorization request MUST NOT contain a 'request_uri'."
            )

        try:
            # reuse the authorization request validation of the registered
            # grants: response_type, redirect_uri and scope are checked
            grant = self.server.get_authorization_grant(request)
            grant.validate_no_multiple_request_parameter(request)
            grant.validate_authorization_request()
        except OAuth2Error as error:
            # errors of this endpoint are JSON responses, the user agent
            # is not involved yet, so nothing may redirect
            error.redirect_uri = None
            raise

        params = {
            key: values[0]
            for key, values in request.payload.datalist.items()
            if key not in CLIENT_AUTH_PARAMETERS
        }
        return PushedAuthorizationEndpointRequest(
            request=request, client=client, params=params
        )

    def create_response(self, validated_request: PushedAuthorizationEndpointRequest):
        request_uri = self.generate_request_uri()
        pushed_request = PushedAuthorizationRequest(
            request_uri=request_uri,
            client_id=validated_request.client.get_client_id(),
            data=validated_request.params,
            expires_at=time.time() + self.EXPIRES_IN,
        )
        self.store.save(pushed_request)
        body = {"request_uri": request_uri, "expires_in": self.EXPIRES_IN}
        return 201, body, default_json_headers

    def generate_request_uri(self):
        """Generate the opaque "request_uri" reference. It is a random URN
        and never contains the pushed request in plain text. Developers may
        rewrite this method to use another generator.
        """
        return self.REQUEST_URI_PREFIX + generate_token(32)

    def claims_request_uri(self, request_uri) -> bool:
        """Whether the given "request_uri" value was issued by this
        endpoint. Only claimed values are resolved as pushed authorization
        requests; other values (e.g. RFC9101 request object URLs) are left
        to their own extensions.
        """
        return bool(request_uri) and request_uri.startswith(self.REQUEST_URI_PREFIX)

    def resolve_authorization_request(self, request: OAuth2Request) -> OAuth2Request:
        """Resolve the "request_uri" of an authorization request into the
        pushed parameters. The pushed content replaces the parameters sent
        by the user agent: extra parameters MUST NOT override it.

        This only resolves the request; the pushed request is consumed by
        "consume_pushed_authorization_request" when the authorization
        response is actually created, so that displaying a consent page
        never burns the request.
        """
        datalist = request.payload.datalist
        if len(datalist.get("request_uri", [])) > 1:
            raise InvalidRequestError("Multiple 'request_uri' in request.")

        request_uri = request.payload.data.get("request_uri")
        pushed_request = self.store.get(request_uri)
        if pushed_request is None:
            raise InvalidRequestError("The 'request_uri' is invalid.")
        if pushed_request.expired:
            raise InvalidRequestError("The 'request_uri' has expired.")
        if pushed_request.state != PushedAuthorizationRequest.STATE_PENDING:
            raise InvalidRequestError("The 'request_uri' has already been used.")

        client_id = request.payload.client_id
        if client_id and client_id != pushed_request.client_id:
            raise InvalidRequestError(
                "The 'client_id' does not match the pushed authorization request."
            )

        request.payload = BasicOAuth2Payload(dict(pushed_request.data))
        request.pushed_authorization_request = pushed_request
        return request

    def consume_pushed_authorization_request(self, pushed_request):
        """Redeem a pushed authorization request. The transition to the
        consumed state is atomic: only the first redemption succeeds.
        """
        record = self.store.consume(
            pushed_request.request_uri, pushed_request.client_id
        )
        if record is None:
            raise InvalidRequestError("The 'request_uri' has already been used.")
        return record

    def deny_pushed_authorization_request(self, pushed_request):
        """Mark a pushed authorization request as denied by the resource
        owner. It can never be redeemed afterwards.
        """
        return self.store.deny(pushed_request.request_uri, pushed_request.client_id)
