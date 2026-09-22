"""authlib.oauth2.rfc9126.endpoint
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Pushed Authorization Request endpoint implementation of RFC 9126.
"""

from authlib.common.security import generate_token
from authlib.consts import default_json_headers

from ..rfc6749 import InvalidRequestError
from ..rfc6749 import OAuth2Error
from ..rfc6749.endpoint import Endpoint
from ..rfc6749.endpoint import EndpointRequest
from ..rfc6749.requests import BasicOAuth2Payload
from ..rfc9101.errors import RequestNotSupportedError
from .store import InMemoryPushedAuthorizationRequestStore

#: The URN prefix of "request_uri" values issued by a PAR endpoint,
#: defined in RFC 9126, Section 3.
REQUEST_URI_PREFIX = "urn:ietf:params:oauth:request_uri:"


class PushedAuthorizationRequestEndpoint(Endpoint):
    """The pushed authorization request endpoint, where clients push the
    authorization request parameters directly to the authorization server
    and receive a short-lived "request_uri" in exchange. Per RFC 9126,
    Section 2.

    Register it together with
    :class:`authlib.oauth2.rfc9126.PushedAuthorizationRequest`, so that the
    endpoint and the authorization server extension share the same store::

        server.register_extension(PushedAuthorizationRequest())

    or standalone, with an explicit store::

        store = InMemoryPushedAuthorizationRequestStore()
        server.register_endpoint(PushedAuthorizationRequestEndpoint(store=store))
        server.register_extension(PushedAuthorizationRequest(store=store))

    :param store: a :class:`PushedAuthorizationRequestStore` instance
    :param expires_in: lifetime of issued "request_uri" values, in seconds
    """

    ENDPOINT_NAME = "pushed_authorization_request"

    #: Client authentication methods accepted on this endpoint. Clients
    #: authenticate the same way as on the token endpoint (RFC 9126, Section 2).
    CLIENT_AUTH_METHODS = ["client_secret_basic", "client_secret_post", "none"]

    #: Default lifetime of the issued "request_uri", in seconds
    DEFAULT_EXPIRES_IN = 60

    def __init__(self, server=None, store=None, expires_in=None):
        super().__init__(server)
        if store is None:
            store = InMemoryPushedAuthorizationRequestStore()
        self.store = store
        self.expires_in = expires_in or self.DEFAULT_EXPIRES_IN

    def validate_request(self, request) -> EndpointRequest:
        # JWT secured authorization requests (RFC 9101) are not supported
        # by this endpoint; only plain form parameters are accepted.
        if "request" in request.payload.data:
            raise RequestNotSupportedError()
        if "request_uri" in request.payload.data:
            raise InvalidRequestError(
                "The 'request_uri' parameter is not allowed in "
                "pushed authorization requests."
            )

        # RFC 9126, Section 2: the client MUST authenticate with the
        # authorization server as described for the token endpoint.
        # Authentication failures raise here, before anything is stored.
        client = self.server.authenticate_client(
            request, self.CLIENT_AUTH_METHODS, endpoint="token"
        )
        request.client = client

        # this request IS the PAR endpoint, the authorization endpoint
        # extension hook MUST skip it
        request.pushed_authorization_request_endpoint = True

        # RFC 9126, Section 2.1: "client_id" is OPTIONAL if the client
        # authenticates with the authorization server
        client_id = request.payload.client_id
        if client_id is None:
            data = {
                key: values[0]
                for key, values in request.payload.datalist.items()
                if values
            }
            data["client_id"] = client.client_id
            request.payload = BasicOAuth2Payload(data)
        elif client_id != client.client_id:
            raise InvalidRequestError(
                "The 'client_id' parameter does not match the authenticated client."
            )

        grant = self.server.get_authorization_grant(request)
        grant.validate_no_multiple_request_parameter(request)
        # reuse the authorization endpoint validation rules (redirect_uri,
        # response_type, scope, and grant extensions such as PKCE)
        try:
            grant.validate_authorization_request()
        except OAuth2Error as error:
            # the PAR endpoint responds with JSON errors (RFC 9126,
            # Section 2.3), it never redirects back to the client
            error.redirect_uri = None
            raise
        return EndpointRequest(request=request, client=client)

    def create_response(self, validated_request: EndpointRequest):
        request = validated_request.request
        client = validated_request.client

        data = dict(request.payload.data)
        # never persist client credentials
        data.pop("client_secret", None)

        request_uri = self.generate_request_uri()
        self.store.set(request_uri, client.client_id, data, self.expires_in)

        body = {"request_uri": request_uri, "expires_in": self.expires_in}
        return 201, body, default_json_headers

    def generate_request_uri(self) -> str:
        """Generate the "request_uri" value. Per RFC 9126, Section 3, it
        uses the "urn:ietf:params:oauth:request_uri:" URN prefix.
        Developers MAY rewrite this method to customize the random part
        of the value.
        """
        return REQUEST_URI_PREFIX + generate_token(32)
