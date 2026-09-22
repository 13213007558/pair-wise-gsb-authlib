"""authlib.oauth2.rfc9126.authorization_server
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Authorization server extension for OAuth 2.0 Pushed Authorization
Requests, per RFC9126.
"""

from ..rfc6749 import ClientMixin
from ..rfc6749.errors import InvalidRequestError
from ..rfc6749.requests import BasicOAuth2Payload
from ..rfc6749.requests import OAuth2Request
from ..rfc9101.errors import InvalidRequestUriError
from .endpoint import PAR_ENDPOINT_REQUEST_ATTR
from .endpoint import PushedAuthorizationRequestEndpoint
from .store import InMemoryPushedAuthorizationRequestStore


class PushedAuthorizationRequests:
    """Authorization server extension implementing Pushed Authorization
    Requests, as defined in :rfc:`RFC9126 <9126>`.

    Registering this extension on the authorization server:

    1. registers the pushed authorization request endpoint, available as
       the ``"pushed_authorization_request"`` endpoint::

           server.register_extension(PushedAuthorizationRequests())


           @app.route("/oauth/par", methods=["POST"])
           def par():
               return server.create_endpoint_response("pushed_authorization_request")

    2. resolves the ``request_uri`` parameter at the authorization
       endpoint, replacing the request parameters with the ones the client
       pushed. Parameters appended to the authorization URL can not
       override the pushed ones.

    :param store: a :class:`PushedAuthorizationRequestStore` instance used
        to persist the pushed requests. Defaults to an in-memory store.
    :param endpoint: a custom :class:`PushedAuthorizationRequestEndpoint`
        instance. When omitted, one is created with the given ``store``.
    """

    def __init__(self, store=None, endpoint=None):
        if store is None:
            store = InMemoryPushedAuthorizationRequestStore()
        self.store = store
        if endpoint is None:
            endpoint = PushedAuthorizationRequestEndpoint(store=store)
        self.endpoint = endpoint

    def __call__(self, authorization_server):
        authorization_server.register_hook(
            "before_get_authorization_grant", self.resolve_pushed_request
        )
        authorization_server.register_hook(
            "before_create_authorization_response", self.consume_pushed_request
        )
        authorization_server.register_endpoint(self.endpoint)

    def resolve_pushed_request(self, authorization_server, request):
        """Resolve the ``request_uri`` parameter of an authorization
        request into the parameters the client pushed earlier.
        """
        if getattr(request, PAR_ENDPOINT_REQUEST_ATTR, False):
            # the request is being validated by the pushed authorization
            # request endpoint itself
            return

        payload = request.payload
        request_uri = payload.data.get("request_uri")
        if request_uri is None:
            self.validate_par_requirement(authorization_server, request)
            return

        if "request" in payload.data:
            raise InvalidRequestError(
                "The 'request' and 'request_uri' parameters are mutually exclusive.",
                state=payload.state,
            )

        record = self.store.get(request_uri)
        if record is None or record.is_expired():
            raise InvalidRequestUriError(state=payload.state)

        client_id = payload.client_id
        if not client_id or client_id != record.get_client_id():
            raise InvalidRequestUriError(
                description="The 'request_uri' is not bound to this client.",
                state=payload.state,
            )

        # the pushed parameters replace the request ones: parameters on
        # the authorization URL (except 'client_id' and 'request_uri')
        # can not override what the client pushed
        data = dict(record.get_request_data())
        data["client_id"] = client_id
        request.payload = BasicOAuth2Payload(data)
        request.par_request_uri = request_uri

    def consume_pushed_request(
        self, authorization_server, request=None, grant_user=None, grant=None
    ):
        """Consume the ``request_uri`` when the authorization response is
        finally created. Reading the request for the consent page does not
        consume it, so the page can be refreshed; completing the
        authorization consumes it exactly once.
        """
        if not isinstance(request, OAuth2Request):
            request = getattr(grant, "request", None)
        if request is None:
            return

        request_uri = getattr(request, "par_request_uri", None)
        if request_uri is None:
            return

        record = self.store.consume(request_uri)
        if record is None or record.is_expired():
            raise InvalidRequestUriError(state=request.payload.state)

    def validate_par_requirement(self, authorization_server, request):
        """Reject non-pushed authorization requests when the client or the
        server requires pushed authorization requests.
        """
        payload = request.payload
        client_id = payload.client_id
        if not client_id:
            return

        client = authorization_server.query_client(client_id)
        if not client:
            return

        if self.get_client_require_pushed_authorization_requests(client):
            raise InvalidRequestError(
                "Authorization requests for this client must be pushed.",
                state=payload.state,
            )

        metadata = self.get_server_metadata()
        if metadata and metadata.get("require_pushed_authorization_requests", False):
            raise InvalidRequestError(
                "Authorization requests for this server must be pushed.",
                state=payload.state,
            )

    def get_server_metadata(self) -> dict:
        """Return server metadata. When ``require_pushed_authorization_requests``
        is :data:`True`, all authorization requests must be pushed::

            class MyPAR(PushedAuthorizationRequests):
                def get_server_metadata(self):
                    return {
                        "issuer": ...,
                        "pushed_authorization_request_endpoint": ...,
                        "require_pushed_authorization_requests": True,
                    }
        """
        return {}  # pragma: no cover

    def get_client_require_pushed_authorization_requests(
        self, client: ClientMixin
    ) -> bool:
        """Return the ``require_pushed_authorization_requests`` client
        metadata. The default implementation reads it from
        ``client.client_metadata`` when available. Developers may
        re-implement this method, e.g.::

            class MyPAR(PushedAuthorizationRequests):
                def get_client_require_pushed_authorization_requests(self, client):
                    return client.require_pushed_authorization_requests
        """
        metadata = getattr(client, "client_metadata", None)
        if metadata:
            return metadata.get("require_pushed_authorization_requests", False)
        return False
