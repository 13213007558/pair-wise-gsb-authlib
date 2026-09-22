"""authlib.oauth2.rfc9126.authorization_server
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Authorization server extension for Pushed Authorization Requests (RFC 9126).
"""

from ..rfc6749 import AuthorizationServer
from ..rfc6749 import ClientMixin
from ..rfc6749 import InvalidRequestError
from ..rfc6749.requests import BasicOAuth2Payload
from ..rfc6749.requests import OAuth2Request
from ..rfc9101.errors import InvalidRequestUriError
from .endpoint import REQUEST_URI_PREFIX
from .endpoint import PushedAuthorizationRequestEndpoint
from .store import InMemoryPushedAuthorizationRequestStore


class PushedAuthorizationRequest:
    """Authorization server extension implementing Pushed Authorization
    Requests, as defined in RFC 9126.

    Registering this extension on the authorization server will:

    1. register the pushed authorization request endpoint, where clients
       POST their authorization request parameters and receive a
       short-lived "request_uri" in exchange;
    2. resolve "request_uri" values on the authorization endpoint,
       replacing the request parameters with the stored ones, so that
       parameters appended to the authorization URL can not override
       the pushed data;
    3. consume the "request_uri" when the authorization response is
       issued, ensuring a reference completes the flow only once.

    Usage::

        server.register_extension(PushedAuthorizationRequest())

    :param store: a
        :class:`authlib.oauth2.rfc9126.store.PushedAuthorizationRequestStore`
        instance; an in-memory store is used by default
    :param expires_in: lifetime of issued "request_uri" values, in seconds
    """

    #: Endpoint class registered by this extension
    endpoint_cls = PushedAuthorizationRequestEndpoint

    def __init__(self, store=None, expires_in=None):
        if store is None:
            store = InMemoryPushedAuthorizationRequestStore()
        self.store = store
        self.expires_in = expires_in

    def __call__(self, authorization_server: AuthorizationServer):
        authorization_server.register_hook(
            "before_get_authorization_grant",
            self.resolve_pushed_authorization_request,
        )
        authorization_server.register_hook(
            "after_get_authorization_grant",
            self.bind_request_uri_consumption,
        )
        authorization_server.register_endpoint(self.create_endpoint())

    def create_endpoint(self) -> PushedAuthorizationRequestEndpoint:
        """Create the pushed authorization request endpoint instance.
        Developers MAY override this method to customize the endpoint.
        """
        return self.endpoint_cls(store=self.store, expires_in=self.expires_in)

    def resolve_pushed_authorization_request(
        self, authorization_server: AuthorizationServer, request: OAuth2Request
    ):
        """Resolve the "request_uri" parameter on the authorization
        endpoint. The request payload is replaced by the stored
        authorization request data, so query parameters appended to the
        authorization URL ("scope", "redirect_uri", ...) are ignored.
        This hook only READS the store; the reference is consumed when
        the authorization response is issued.
        """
        # the PAR endpoint itself validates requests through
        # "get_authorization_grant"; it MUST be skipped here
        if getattr(request, "pushed_authorization_request_endpoint", False):
            return

        request_uri = request.payload.data.get("request_uri")
        record = self.store.get(request_uri) if request_uri else None

        if record is None:
            if request_uri and request_uri.startswith(REQUEST_URI_PREFIX):
                raise InvalidRequestUriError(
                    description="The 'request_uri' is unknown or has expired.",
                    state=request.payload.state,
                )
            # not a pushed authorization request: enforce the
            # "require_pushed_authorization_requests" policies
            self.validate_requirements(authorization_server, request)
            return

        client_id = request.payload.client_id
        if client_id is None:
            raise InvalidRequestError(
                "Missing 'client_id' parameter.",
                state=request.payload.state,
            )
        if client_id != record["client_id"]:
            raise InvalidRequestError(
                "The 'request_uri' was not issued to this client.",
                state=request.payload.state,
            )

        request.payload = BasicOAuth2Payload(dict(record["data"]))
        request.pushed_authorization_request_uri = request_uri

    def bind_request_uri_consumption(self, authorization_server, grant):
        """Wrap the grant so that the "request_uri" is consumed when the
        authorization response is finally issued (and only when the
        resource owner grants the request). Rendering the consent page
        does not consume the reference, and a consumed reference can not
        complete the flow a second time.
        """
        request = grant.request
        request_uri = getattr(request, "pushed_authorization_request_uri", None)
        if request_uri is None:
            return

        store = self.store
        create_authorization_response = grant.create_authorization_response

        def create_authorization_response_with_consumption(redirect_uri, grant_user):
            if grant_user is not None and store.consume(request_uri) is None:
                raise InvalidRequestUriError(
                    description=(
                        "The 'request_uri' is unknown, has expired, or has "
                        "already been used."
                    ),
                    state=request.payload.state,
                )
            return create_authorization_response(redirect_uri, grant_user)

        grant.create_authorization_response = (
            create_authorization_response_with_consumption
        )

    def validate_requirements(
        self, authorization_server: AuthorizationServer, request: OAuth2Request
    ):
        """Reject plain authorization requests when the client or the
        server requires pushed authorization requests.
        """
        client_id = request.payload.client_id
        client = authorization_server.query_client(client_id) if client_id else None

        # When the value of "require_pushed_authorization_requests" as
        # client metadata is true, the server MUST reject authorization
        # requests from the client that do not use PAR.
        if client and self.get_client_require_pushed_authorization_requests(client):
            raise InvalidRequestError(
                "Authorization requests for this client must be pushed.",
                state=request.payload.state,
            )

        # When the value of "require_pushed_authorization_requests" as
        # server metadata is true, the server MUST reject authorization
        # requests that do not use PAR.
        metadata = self.get_server_metadata()
        if metadata and metadata.get("require_pushed_authorization_requests", False):
            raise InvalidRequestError(
                "Authorization requests for this server must be pushed.",
                state=request.payload.state,
            )

    def get_server_metadata(self) -> dict:
        """Return server metadata which includes supported PAR
        capabilities::

            class PushedAuthorizationRequest(rfc9126.PushedAuthorizationRequest):
                def get_server_metadata(self):
                    return {
                        "issuer": ...,
                        "pushed_authorization_request_endpoint": ...,
                        "require_pushed_authorization_requests": ...,
                    }

        """
        return {}  # pragma: no cover

    def get_client_require_pushed_authorization_requests(
        self, client: ClientMixin
    ) -> bool:
        """Return the "require_pushed_authorization_requests" client
        metadata. When True, authorization requests from this client
        MUST use the pushed authorization request endpoint::

            class PushedAuthorizationRequest(rfc9126.PushedAuthorizationRequest):
                def get_client_require_pushed_authorization_requests(self, client):
                    return client.client_metadata.get(
                        "require_pushed_authorization_requests", False
                    )

        If not implemented, the value is considered as False.
        """
        return False  # pragma: no cover
