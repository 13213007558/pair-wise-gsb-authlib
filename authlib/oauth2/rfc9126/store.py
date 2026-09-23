"""authlib.oauth2.rfc9126.store
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Storage interface for Pushed Authorization Requests. The pushed
authorization request endpoint delegates all persistence to a store, so
developers can replace the default in-memory implementation with a
database or cache backed one.

https://www.rfc-editor.org/rfc/rfc9126
"""

import threading

from .models import PushedAuthorizationRequest


class PushedAuthorizationRequestStore:
    """Interface of the storage used by the pushed authorization request
    endpoint. Implementations MUST guarantee that "consume" is atomic:
    when two parties try to redeem the same pending request concurrently,
    exactly one of them MUST succeed.
    """

    def save(self, request: PushedAuthorizationRequest):
        """Save a freshly created pushed authorization request.

        :param request: a PushedAuthorizationRequest instance.
        """
        raise NotImplementedError()

    def get(self, request_uri) -> PushedAuthorizationRequest | None:
        """Get the pushed authorization request for the given
        "request_uri", or None if it does not exist.
        """
        raise NotImplementedError()

    def consume(self, request_uri, client_id) -> PushedAuthorizationRequest | None:
        """Atomically mark the pending request as consumed and return it.

        Return None if the request does not exist, belongs to another
        client, is expired, or is not pending anymore. This method MUST be
        atomic so that a pushed authorization request can only be redeemed
        once, even under concurrent access.
        """
        raise NotImplementedError()

    def deny(self, request_uri, client_id) -> PushedAuthorizationRequest | None:
        """Mark the pending request as denied and return it. Return
        None if the request does not exist or belongs to another client.
        """
        raise NotImplementedError()


class InMemoryPushedAuthorizationRequestStore(PushedAuthorizationRequestStore):
    """A process-local store, suitable for development and tests. Production
    deployments SHOULD provide a shared, persistent implementation of
    PushedAuthorizationRequestStore.
    """

    def __init__(self):
        self._items = {}
        self._lock = threading.Lock()

    def save(self, request):
        with self._lock:
            self._items[request.request_uri] = request

    def get(self, request_uri):
        return self._items.get(request_uri)

    def consume(self, request_uri, client_id):
        with self._lock:
            request = self._items.get(request_uri)
            if (
                request is None
                or request.client_id != client_id
                or request.state != PushedAuthorizationRequest.STATE_PENDING
                or request.expired
            ):
                return None
            request.state = PushedAuthorizationRequest.STATE_CONSUMED
            return request

    def deny(self, request_uri, client_id):
        with self._lock:
            request = self._items.get(request_uri)
            if request is None or request.client_id != client_id:
                return None
            if request.state == PushedAuthorizationRequest.STATE_PENDING:
                request.state = PushedAuthorizationRequest.STATE_DENIED
            return request
