"""authlib.oauth2.rfc9126.store
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Storage interface for RFC 9126 pushed authorization requests.

https://www.rfc-editor.org/rfc/rfc9126.html
"""

import threading
import time


class PushedAuthorizationRequestStore:
    """Interface of the storage for pushed authorization requests.

    A record stored in this storage is a dict with the following keys:

    * `client_id`: the identifier of the client that pushed the request
    * `data`: the pushed authorization request parameters, as a dict
    * `expires_at`: a UNIX timestamp after which the record is invalid

    Developers MUST re-implement this interface with their own storage
    (database, cache, ...) and pass it to
    :class:~authlib.oauth2.rfc9126.PushedAuthorizationRequest::

        class MyStore(PushedAuthorizationRequestStore):
            def get(self, request_uri): ...

            def save(self, request_uri, client_id, data, expires_in): ...

            def delete(self, request_uri): ...

            def consume(self, request_uri): ...


        server.register_endpoint(PushedAuthorizationRequest(store=MyStore()))
    """

    def get(self, request_uri):
        """Return the record stored for `request_uri`, or `None` if
        there is no such record. Expired records MAY be returned, it is
        the endpoint responsibility to check `expires_at`.
        """
        raise NotImplementedError()

    def save(self, request_uri, client_id, data, expires_in):
        """Save the authorization request `data` pushed by the client
        identified by `client_id` under the reference `request_uri`.
        The record MUST be considered invalid `expires_in` seconds
        after this call.
        """
        raise NotImplementedError()

    def delete(self, request_uri):
        """Delete the record stored for `request_uri`. Deleting an
        unknown `request_uri` MUST NOT raise an error.
        """
        raise NotImplementedError()

    def consume(self, request_uri):
        """Atomically mark the record stored for `request_uri` as used
        and return `True`. Return `False` if there is no (valid)
        record for `request_uri`. A record can only be consumed once,
        subsequent calls MUST return `False`.
        """
        raise NotImplementedError()


class InMemoryPushedAuthorizationRequestStore(PushedAuthorizationRequestStore):
    """A simple in-memory store, used by default when no store is given.
    It is only suitable for development and single-process servers.
    """

    def __init__(self):
        self._records = {}
        self._lock = threading.Lock()

    def get(self, request_uri):
        return self._records.get(request_uri)

    def save(self, request_uri, client_id, data, expires_in):
        record = {
            "client_id": client_id,
            "data": dict(data),
            "expires_at": time.time() + expires_in,
        }
        with self._lock:
            self._records[request_uri] = record

    def delete(self, request_uri):
        with self._lock:
            self._records.pop(request_uri, None)

    def consume(self, request_uri):
        with self._lock:
            record = self._records.pop(request_uri, None)
        if record is None or record["expires_at"] < time.time():
            return False
        return True
