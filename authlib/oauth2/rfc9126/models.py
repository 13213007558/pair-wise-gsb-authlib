"""authlib.oauth2.rfc9126.models
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Models for the pushed authorization request data stored by the
authorization server, per `Section 2`_ of RFC9126.

.. _`Section 2`: https://www.rfc-editor.org/rfc/rfc9126.html#section-2
"""

import time


class PushedAuthorizationRequestMixin:
    """Interface of the data bound to a ``request_uri``."""

    def get_client_id(self):
        """The client identifier this pushed request is bound to."""
        raise NotImplementedError()

    def get_request_data(self):
        """The pushed authorization request parameters as a dict."""
        raise NotImplementedError()

    def is_expired(self):
        """Whether this pushed authorization request has expired."""
        raise NotImplementedError()


class PushedAuthorizationRequestDict(dict, PushedAuthorizationRequestMixin):
    """A simple ``dict`` based implementation of
    :class:`PushedAuthorizationRequestMixin`, with the keys:

    - ``client_id``: the client the request was pushed by
    - ``data``: the pushed authorization request parameters
    - ``expires_at``: expiration timestamp of the ``request_uri``
    """

    def get_client_id(self):
        return self["client_id"]

    def get_request_data(self):
        return self.get("data", {})

    def is_expired(self):
        expires_at = self.get("expires_at")
        if expires_at is not None:
            return expires_at < time.time()
        return False
