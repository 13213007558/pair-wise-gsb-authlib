"""authlib.oauth2.rfc9126.models
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Data model for Pushed Authorization Requests. A pushed authorization
request is the payload that a client posted to the pushed authorization
request endpoint, referenced later on by an opaque "request_uri".

https://www.rfc-editor.org/rfc/rfc9126
"""

import time


class PushedAuthorizationRequest:
    """A stored pushed authorization request.

    A record has a life cycle with deterministic final states:

    * "pending": freshly created, it can be displayed on a consent page
      and submitted any number of times until it is redeemed, denied or
      expired.
    * "consumed": terminal state, the request has been redeemed for an
      authorization response. It can never be used again.
    * "denied": terminal state, the resource owner denied the
      authorization request. It can never be used again.

    Expiration is derived from "expires_at" and does not need a state of
    its own: an expired request is unusable whatever its state.

    :param request_uri: the opaque reference returned to the client.
    :param client_id: the client the request was pushed by. The subsequent
        authorization request is bound to this client.
    :param data: the pushed authorization request parameters, without any
        client authentication material.
    :param expires_at: POSIX timestamp after which the request is invalid.
    :param state: one of "pending", "consumed" or "denied".
    """

    STATE_PENDING = "pending"
    STATE_CONSUMED = "consumed"
    STATE_DENIED = "denied"

    def __init__(self, request_uri, client_id, data, expires_at, state=STATE_PENDING):
        self.request_uri = request_uri
        self.client_id = client_id
        self.data = data
        self.expires_at = expires_at
        self.state = state

    @property
    def expired(self):
        return time.time() >= self.expires_at

    def __repr__(self):
        return f"<PushedAuthorizationRequest {self.request_uri} ({self.state})>"
