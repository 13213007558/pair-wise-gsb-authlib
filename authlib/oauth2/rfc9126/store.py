"""authlib.oauth2.rfc9126.store
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Replaceable storage interface for pushed authorization requests.

The store distinguishes two access patterns, per the lifetime of a
``request_uri``:

- :meth:`PushedAuthorizationRequestStore.get` is a non-destructive read,
  used while the authorization server renders the consent page. Refreshing
  the consent page MUST NOT consume the reference.
- :meth:`PushedAuthorizationRequestStore.consume` is a destructive,
  atomic read, used when the authorization response is finally created.
  A given ``request_uri`` can be consumed only once.
"""

import threading

from .models import PushedAuthorizationRequestDict


class PushedAuthorizationRequestStore:
    """Storage interface for pushed authorization requests. Developers
    can replace the default in-memory implementation with a database or
    cache backed one by subclassing this class and passing the instance
    to :class:`PushedAuthorizationRequests`::

        class MyStore(PushedAuthorizationRequestStore):
            def save(self, request_uri, client_id, data, expires_at): ...

            def get(self, request_uri): ...

            def consume(self, request_uri): ...
    """

    def save(self, request_uri, client_id, data, expires_at):
        """Save the pushed authorization request ``data`` under
        ``request_uri``, bound to ``client_id`` until ``expires_at``.
        """
        raise NotImplementedError()

    def get(self, request_uri):
        """Read the pushed authorization request without consuming it.
        Returns ``None`` if the ``request_uri`` is unknown.
        """
        raise NotImplementedError()

    def consume(self, request_uri):
        """Atomically read and remove the pushed authorization request.
        Returns ``None`` if the ``request_uri`` is unknown or has already
        been consumed. Implementations MUST make sure a given
        ``request_uri`` can be consumed only once, even under concurrent
        access.
        """
        raise NotImplementedError()


class InMemoryPushedAuthorizationRequestStore(PushedAuthorizationRequestStore):
    """Default in-memory store, suitable for development and tests."""

    def __init__(self):
        self._records = {}
        self._lock = threading.Lock()

    def save(self, request_uri, client_id, data, expires_at):
        record = PushedAuthorizationRequestDict(
            {
                "client_id": client_id,
                "data": dict(data),
                "expires_at": expires_at,
            }
        )
        with self._lock:
            self._records[request_uri] = record

    def get(self, request_uri):
        record = self._records.get(request_uri)
        if record is not None and record.is_expired():
            with self._lock:
                self._records.pop(request_uri, None)
            return None
        return record

    def consume(self, request_uri):
        with self._lock:
            record = self._records.pop(request_uri, None)
        if record is not None and record.is_expired():
            return None
        return record
