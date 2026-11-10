"""authlib.oauth2.rfc9126.store.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Storage of the pushed authorization requests of :rfc:`9126`.

The storage is an application interface. Authlib provides a thread-safe
in-memory implementation for tests, development and single-process
servers. Applications that run several processes or that need persistence
implement the same methods on their own storage, such as Redis or SQL.
No extra database or background service is required by Authlib itself.
"""

import threading
import time

__all__ = ["PushedAuthorizationRequestData", "InMemoryPushedAuthorizationRequestStore"]


class PushedAuthorizationRequestData:
    """The data of one pushed authorization request.

    :param request_uri: the ``request_uri`` returned to the client
    :param client_id: the client that pushed the request. The reference
        belongs to this client only.
    :param data: the verified authorization request parameters
    :param expires_at: the POSIX time after which the reference is invalid
    """

    def __init__(self, request_uri, client_id, data, expires_at):
        self.request_uri = request_uri
        self.client_id = client_id
        self.data = data
        self.expires_at = expires_at

    def is_expired(self, now=None):
        """Return whether the reference has expired at the given time."""
        if now is None:
            now = time.time()
        return self.expires_at <= now


class InMemoryPushedAuthorizationRequestStore:
    """A thread-safe in-memory store for pushed authorization requests.

    :param clock: a callable returning the current POSIX time. Tests can
        pass a controllable clock.

    The methods of this class are the storage interface of
    :class:`~authlib.oauth2.rfc9126.PushedAuthorizationRequest` and
    :class:`~authlib.oauth2.rfc9126.PushedAuthorizationRequestEndpoint`.
    Their contracts define the boundaries of the reference lifecycle:

    * :meth:`save` stores a new reference at PAR submission time.
    * :meth:`get` reads a reference without consuming it. The authorization
      endpoint uses it to display the login and consent pages.
    * :meth:`claim` atomically takes a reference for the final
      authorization response. Only one of concurrent requests can claim a
      reference, so concurrent requests cannot each get an authorization
      code.
    * :meth:`commit` permanently consumes a claimed reference when the
      authorization response is created. A reference can only be committed
      once.
    * :meth:`release` gives a claimed reference back when the authorization
      fails before a response is created, so that the application can
      choose to allow short-term retries.
    """

    def __init__(self, clock=time.time):
        self._clock = clock
        self._entries = {}
        self._claimed = set()
        self._lock = threading.Lock()

    def save(self, entry):
        """Store a :class:`PushedAuthorizationRequestData`."""
        with self._lock:
            self._entries[entry.request_uri] = entry

    def get(self, request_uri):
        """Return the entry of ``request_uri`` without consuming it, or
        ``None`` if it is unknown or expired."""
        with self._lock:
            entry = self._entries.get(request_uri)
            if entry is None:
                return None
            if entry.is_expired(self._clock()):
                self._delete(request_uri)
                return None
            return entry

    def claim(self, request_uri):
        """Atomically take ``request_uri`` for the final authorization
        response. Return the entry, or ``None`` if the reference is
        unknown, expired or already claimed."""
        with self._lock:
            entry = self._entries.get(request_uri)
            if (
                entry is None
                or request_uri in self._claimed
                or entry.is_expired(self._clock())
            ):
                return None
            self._claimed.add(request_uri)
            return entry

    def commit(self, request_uri):
        """Permanently consume a claimed reference."""
        with self._lock:
            self._delete(request_uri)

    def release(self, request_uri):
        """Give a claimed reference back after a failed authorization, so
        that it can be used again until it expires."""
        with self._lock:
            self._claimed.discard(request_uri)

    def _delete(self, request_uri):
        self._entries.pop(request_uri, None)
        self._claimed.discard(request_uri)
