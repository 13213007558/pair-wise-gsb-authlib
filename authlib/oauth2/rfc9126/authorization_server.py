"""authlib.oauth2.rfc9126.authorization_server.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The authorization server extension of :rfc:`9126`. It resolves the
``request_uri`` of a pushed authorization request on the authorization
endpoint, and consumes the reference when the final authorization
response is created.
"""

import time

from ..rfc6749 import AuthorizationServer
from ..rfc6749 import InvalidRequestError
from ..rfc6749.requests import BasicOAuth2Payload
from ..rfc9101.errors import InvalidRequestUriError
from .store import InMemoryPushedAuthorizationRequestStore

#: The URN prefix of the ``request_uri`` values of RFC 9126.
REQUEST_URI_PREFIX = "urn:ietf:params:oauth:request_uri:"

__all__ = ["PushedAuthorizationRequest", "REQUEST_URI_PREFIX"]


class PushedAuthorizationRequest:
    """Authorization server extension resolving pushed authorization
    requests on the authorization endpoint, as defined in :rfc:`RFC 9126
    <9126>`.

    :param store: the reference storage. It implements the interface of
        :class:`~authlib.oauth2.rfc9126.InMemoryPushedAuthorizationRequestStore`.
        The endpoint and this extension must share the same store.
    :param clock: a callable returning the current POSIX time, used when
        no ``store`` is given.

    Register the extension and the endpoint with the same store::

        store = InMemoryPushedAuthorizationRequestStore()
        authorization_server.register_extension(PushedAuthorizationRequest(store))
        authorization_server.register_endpoint(PushedAuthorizationRequestEndpoint(store))

    When the :rfc:`9101` extension is also used, register this extension
    first, so that the pushed parameters, including a ``request`` object,
    are restored before the request object is verified.
    """

    def __init__(self, store=None, clock=time.time):
        if store is None:
            store = InMemoryPushedAuthorizationRequestStore(clock=clock)
        self.store = store

    def __call__(self, authorization_server: AuthorizationServer):
        authorization_server.register_authorization_parameters({"request_uri": str})
        authorization_server.register_hook(
            self.resolve_authorization_request,
            before=AuthorizationServer.get_authorization_grant,
        )
        authorization_server.register_hook(
            self.finalize_authorization_request,
            replace=AuthorizationServer._create_grant_response,
        )

    def resolve_authorization_request(self, authorization_server, request):
        """Replace the request parameters with the pushed ones.

        A reference belongs to the client that pushed it. Only the
        ``client_id`` and ``request_uri`` parameters of the front-channel
        request are read; the other parameters come from the verified
        pushed data, so extra parameters cannot override it. Reading the
        reference does not consume it: displaying the login or consent
        page keeps it usable.

        :raises InvalidRequestUriError: if the reference is unknown or expired
        :raises InvalidRequestError: if another client pushed the reference,
            or if pushed authorization requests are required
        """
        request_uri = request.payload.data.get("request_uri")
        if not (
            isinstance(request_uri, str) and request_uri.startswith(REQUEST_URI_PREFIX)
        ):
            self.validate_required_request(authorization_server, request)
            return

        entry = self.store.get(request_uri)
        if entry is None:
            raise InvalidRequestUriError(
                "The 'request_uri' is unknown or has expired.",
                state=request.payload.state,
            )

        client_id = request.payload.client_id
        if not client_id or client_id != entry.client_id:
            raise InvalidRequestError(
                "The 'request_uri' was not pushed by this client.",
                state=request.payload.state,
            )

        request.payload = BasicOAuth2Payload(dict(entry.data))
        request.pushed_request_uri = request_uri

    def finalize_authorization_request(
        self, authorization_server, original, request, grant, grant_user
    ):
        """Consume the reference around the final authorization response.

        The claim is atomic, so concurrent requests cannot each get an
        authorization response. The reference is committed when the
        response is created, and released when the authorization fails
        before that, so that the application can allow short-term retries.
        """
        request_uri = getattr(grant.request, "pushed_request_uri", None)
        if request_uri is None:
            return original(request, grant, grant_user)

        if self.store.claim(request_uri) is None:
            raise InvalidRequestUriError(
                "The 'request_uri' was already used or has expired.",
                state=grant.request.payload.state,
            )

        try:
            response = original(request, grant, grant_user)
        except Exception:
            self.store.release(request_uri)
            raise

        self.store.commit(request_uri)
        return response

    def validate_required_request(self, authorization_server, request):
        """Reject a request that is not pushed when the server or the
        client requires pushed authorization requests.

        :raises InvalidRequestError: if a pushed request is required
        """
        metadata = self.get_server_metadata()
        if metadata.get("require_pushed_authorization_requests", False):
            raise InvalidRequestError(
                "Authorization requests for this server must be pushed.",
                state=request.payload.state,
            )

        client_id = request.payload.client_id
        if client_id:
            client = authorization_server.query_client(client_id)
            if client and self.get_client_require_pushed_authorization_requests(client):
                raise InvalidRequestError(
                    "Authorization requests for this client must be pushed.",
                    state=request.payload.state,
                )

    def get_server_metadata(self) -> dict:
        """Return server metadata. When its
        ``require_pushed_authorization_requests`` claim is :data:`True`,
        every authorization request of this server must use a
        ``request_uri`` obtained from the pushed authorization request
        endpoint::

            class PushedAuthorizationRequest(rfc9126.PushedAuthorizationRequest):
                def get_server_metadata(self):
                    return {
                        "issuer": ...,
                        "pushed_authorization_request_endpoint": ...,
                        "require_pushed_authorization_requests": True,
                    }

        """
        return {}  # pragma: no cover

    def get_client_require_pushed_authorization_requests(self, client) -> bool:
        """Return the ``require_pushed_authorization_requests`` client
        metadata. When :data:`True`, the authorization requests of this
        client must use a ``request_uri`` obtained from the pushed
        authorization request endpoint::

            class PushedAuthorizationRequest(rfc9126.PushedAuthorizationRequest):
                def get_client_require_pushed_authorization_requests(self, client):
                    return client.client_metadata.get(
                        "require_pushed_authorization_requests", False
                    )

        If not implemented, the value is considered as :data:`False`.
        """
        return False  # pragma: no cover
