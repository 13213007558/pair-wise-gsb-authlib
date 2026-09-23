"""authlib.oauth2.rfc9126.endpoint
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The pushed authorization request endpoint defined by RFC 9126.

https://www.rfc-editor.org/rfc/rfc9126.html
"""

import time

from authlib.common.security import generate_token
from authlib.consts import default_json_headers

from ..rfc6749 import Endpoint
from ..rfc6749 import EndpointRequest
from ..rfc6749 import InvalidRequestError
from ..rfc6749 import OAuth2Error
from ..rfc6749.requests import BasicOAuth2Payload
from .store import InMemoryPushedAuthorizationRequestStore


class PushedAuthorizationRequest(Endpoint):
    """Implementation of the pushed authorization request endpoint which
    is described in :rfc:RFC9126 <9126>.

    Register it on the authorization server, optionally with a custom
    :class:~authlib.oauth2.rfc9126.PushedAuthorizationRequestStore::

        server.register_endpoint(PushedAuthorizationRequest(store=MyStore()))

    Once registered, authorization requests carrying a `request_uri`
    issued by this endpoint are resolved automatically by
    :meth:AuthorizationServer.get_consent_grant and
    :meth:AuthorizationServer.create_authorization_response.

    :param store: a
        :class:~authlib.oauth2.rfc9126.PushedAuthorizationRequestStore
        instance. An in-memory store is used if omitted.
    :param expires_in: lifetime of the issued `request_uri`, in seconds.
    """

    #: Endpoint name to be registered
    ENDPOINT_NAME = "pushed_authorization_request"

    #: Allowed client authenticate methods. Per RFC 9126 Section 2.1,
    #: clients authenticate the same way as at the token endpoint, so
    #: public clients are authenticated with the "none" method.
    CLIENT_AUTH_METHODS = ["client_secret_basic", "client_secret_post", "none"]

    #: Default lifetime of a `request_uri`, in seconds
    DEFAULT_EXPIRES_IN = 60

    #: Prefix of the generated `request_uri` values, per RFC 9126 Section 4
    REQUEST_URI_PREFIX = "urn:ietf:params:oauth:request_uri:"

    def __init__(self, server=None, store=None, expires_in=None):
        super().__init__(server)
        self.store = store or InMemoryPushedAuthorizationRequestStore()
        self.expires_in = expires_in or self.DEFAULT_EXPIRES_IN

    def validate_request(self, request):
        """Validate the pushed authorization request. The client is
        authenticated with its registered endpoint auth method, and the
        authorization request parameters are validated exactly as they
        would be at the authorization endpoint.
        """
        if request.method != "POST":
            raise InvalidRequestError(
                "The pushed authorization request endpoint requires POST."
            )

        if "request_uri" in request.payload.data:
            raise InvalidRequestError(
                "The 'request_uri' parameter MUST NOT be included in a "
                "pushed authorization request."
            )

        client = self.server.authenticate_client(
            request, self.CLIENT_AUTH_METHODS, self.ENDPOINT_NAME
        )
        request.client = client

        try:
            grant = self.server.get_authorization_grant(request)
            grant.validate_no_multiple_request_parameter(request)
            grant.validate_consent_request()
        except OAuth2Error as error:
            # Per RFC 9126 Section 2.3, errors of this endpoint are
            # returned as JSON, they MUST NOT trigger a redirection.
            error.redirect_uri = None
            raise

        return EndpointRequest(request=request, client=client)

    def create_response(self, validated_request):
        """Store the pushed authorization request and return a `request_uri`
        reference to it. The response only contains the reference and its
        lifetime, never the request parameters themselves.
        """
        request = validated_request.request
        request_uri = self.REQUEST_URI_PREFIX + generate_token(32)
        data = {
            key: value
            for key, value in request.payload.data.items()
            if key != "client_secret"
        }
        self.store.save(
            request_uri,
            client_id=validated_request.client.get_client_id(),
            data=data,
            expires_in=self.expires_in,
        )
        body = {"request_uri": request_uri, "expires_in": self.expires_in}
        return 201, body, default_json_headers

    def resolve_authorization_request(self, request):
        """Replace the parameters of an authorization request carrying a
        `request_uri` with the parameters stored by the pushed
        authorization request. Parameters sent by the user-agent alongside
        `client_id` and `request_uri` are ignored, so they cannot
        override the pushed content.
        """
        request_uri = request.payload.data.get("request_uri")
        if not request_uri or not request_uri.startswith(self.REQUEST_URI_PREFIX):
            return

        client_id = request.payload.client_id
        if not client_id:
            raise InvalidRequestError("Missing 'client_id' in request.")

        record = self.store.get(request_uri)
        if record is None:
            raise InvalidRequestError("The 'request_uri' is invalid or expired.")

        if record["expires_at"] < time.time():
            self.store.delete(request_uri)
            raise InvalidRequestError("The 'request_uri' is invalid or expired.")

        if record["client_id"] != client_id:
            raise InvalidRequestError(
                "The 'request_uri' was not issued to this client."
            )

        data = dict(record["data"])
        data["client_id"] = client_id
        request.payload = BasicOAuth2Payload(data)
        request.pushed_request_uri = request_uri

    def consume_authorization_request(self, request_uri):
        """Mark a `request_uri` as used. A pushed authorization request
        can only be exchanged for one authorization response.
        """
        if not self.store.consume(request_uri):
            raise InvalidRequestError(
                "The 'request_uri' is expired or has already been used."
            )
