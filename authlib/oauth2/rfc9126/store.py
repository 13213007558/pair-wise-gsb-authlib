"""authlib.oauth2.rfc9126.store
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Storage interface for Pushed Authorization Requests (:rfc:`RFC9126 <9126>`).

The store keeps the authorization request parameters posted by the client at
the pushed authorization request endpoint, bound to the ``client_id`` and
indexed by the generated ``request_uri``.

Two read semantics are deliberately separated:

* :meth:`PushedAuthorizationRequestStore.get` is a non-destructive read, used
  when the authorization (consent) page is rendered. Refreshing the consent
  page reads the same data again.
* :meth:`PushedAuthorizationRequestStore.consume` is an atomic
  read-and-delete, used when the authorization response (authorization code)
  is finally issued. It guarantees that a ``request_uri`` can complete the
  authorization flow only once, even under concurrent requests.
"""

import threading
import time


class PushedAuthorizationRequestStore:
    """Interface of the storage for pushed authorization request data.

    A stored record is a dict with the following keys:

    * ``client_id``: the client that pushed the authorization request
    * ``data``: the validated authorization request parameters (a dict)
    * ``expires_at``: UNIX timestamp after which the record is invalid
    """

    def set(self, request_uri: str, client_id: str, data: dict, expires_in: int):
        """Save the authorization request ``data`` under ``request_uri``,
        bound to ``client_id``, expiring in ``expires_in`` seconds.

        :param request_uri: the generated ``request_uri`` value
        :param client_id: the authenticated client identifier
        :param data: the authorization request parameters
        :param expires_in: lifetime of the record in seconds
        """
        raise NotImplementedError()

    def get(self, request_uri: str) -> dict | None:
        """Read the record for ``request_uri`` without consuming it.

        This method is used to render the authorization (consent) page, so
        it MUST NOT delete or invalidate the record. It returns ``None``
        when the record does not exist or is expired.

        :param request_uri: the ``request_uri`` value
        :return: the stored record or ``None``
        """
        raise NotImplementedError()

    def consume(self, request_uri: str) -> dict | None:
        """Atomically read and delete the record for ``request_uri``.

        This method is used when the authorization response is issued. It
        MUST return the record at most once: concurrent calls for the same
        ``request_uri`` yield the record to a single caller, and ``None``
        to all the others. It also returns ``None`` when the record does
        not exist or is expired.

        :param request_uri: the ``request_uri`` value
        :return: the stored record or ``None``
        """
        raise NotImplementedError()


class InMemoryPushedAuthorizationRequestStore(PushedAuthorizationRequestStore):
    """A thread-safe in-memory store, mainly designed for development and
    testing. Production deployments SHOULD implement
    :class:`PushedAuthorizationRequestStore` on top of a shared storage,
    making sure that :meth:`consume` is atomic (e.g. with a SQL
    ``DELETE ... RETURNING`` or a Redis ``GETDEL``).
    """

    def __init__(self):
        self._data = {}
        self._lock = threading.Lock()

    def set(self, request_uri: str, client_id: str, data: dict, expires_in: int):
        record = {
            "client_id": client_id,
            "data": dict(data),
            "expires_at": time.time() + expires_in,
        }
        with self._lock:
            self._data[request_uri] = record

    def get(self, request_uri: str) -> dict | None:
        with self._lock:
            record = self._data.get(request_uri)
            if record is None:
                return None
            if record["expires_at"] < time.time():
                del self._data[request_uri]
                return None
            return record

    def consume(self, request_uri: str) -> dict | None:
        with self._lock:
            record = self._data.pop(request_uri, None)
        if record is None:
            return None
        if record["expires_at"] < time.time():
            return None
        return record
