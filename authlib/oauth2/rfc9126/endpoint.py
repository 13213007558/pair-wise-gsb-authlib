"""authlib.oauth2.rfc9126.endpoint
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The pushed authorization request endpoint, per `Section 2`_ of RFC9126.

.. _`Section 2`: https://www.rfc-editor.org/rfc/rfc9126.html#section-2
"""

import time

from authlib.common.security import generate_token
from authlib.consts import default_json_headers

from ..rfc6749.endpoint import Endpoint
from ..rfc6749.endpoint import EndpointRequest
from ..rfc6749.errors import InvalidRequestError
from ..rfc6749.errors import OAuth2Error
from ..rfc6749.requests import BasicOAuth2Payload
from ..rfc9101.errors import RequestNotSupportedError
from ..rfc9101.errors import RequestUriNotSupportedError
from .store import InMemoryPushedAuthorizationRequestStore

#: attribute set on the OAuth2Request while it is validated by the pushed
#: authorization request endpoint itself, so that the authorization
#: endpoint resolution logic does not apply to it
PAR_ENDPOINT_REQUEST_ATTR = "_par_endpoint_request"


class PushedAuthorizationRequestEndpoint(Endpoint):
    """The pushed authorization request endpoint of RFC9126. The client
    pushes the authorization request parameters with a POST request, and
    receives a short-lived ``request_uri`` to use at the authorization
    endpoint.

    This endpoint is usually not registered directly, but through the
    :class:`PushedAuthorizationRequests` extension::

        server.register_extension(PushedAuthorizationRequests())
    """

    ENDPOINT_NAME = "pushed_authorization_request"

    #: client authentication methods supported by this endpoint
    CLIENT_AUTH_METHODS = ["client_secret_basic", "client_secret_post", "none"]

    #: lifetime in seconds of the issued ``request_uri``
    EXPIRES_IN = 60

    #: prefix of the generated ``request_uri`` values
    REQUEST_URI_PREFIX = "urn:ietf:params:oauth:request_uri:"

    def __init__(self, server=None, store=None):
        super().__init__(server)
        if store is None:
            store = InMemoryPushedAuthorizationRequestStore()
        self.store = store

    def validate_request(self, request):
        # 1. the client MUST authenticate as it would at the token endpoint
        client = self.server.authenticate_client(
            request, self.CLIENT_AUTH_METHODS, self.ENDPOINT_NAME
        )
        request.client = client

        # 2. bind the request to the authenticated client; the client_id
        # may be omitted from the body when the client authenticates
        # with another mean (e.g. client_secret_basic)
        data = dict(request.payload.data.items())
        client_id = client.get_client_id()
        if "client_id" in data and data["client_id"] != client_id:
            raise InvalidRequestError(
                "The 'client_id' parameter does not match the authenticated client."
            )
        data["client_id"] = client_id
        request.payload = BasicOAuth2Payload(data)

        # 3. only plain form parameters are supported; JWT secured
        # authorization requests (RFC9101) are explicitly rejected
        if "request" in data:
            raise RequestNotSupportedError()
        if "request_uri" in data:
            raise RequestUriNotSupportedError()

        # 4. validate the pushed parameters with the very same rules used
        # by the authorization endpoint (including grant extensions such
        # as PKCE), so that an invalid request is rejected as early as
        # possible
        setattr(request, PAR_ENDPOINT_REQUEST_ATTR, True)
        try:
            grant = self.server.get_authorization_grant(request)
            grant.validate_no_multiple_request_parameter(request)
            grant.validate_consent_request()
        except OAuth2Error as error:
            # errors of this endpoint are JSON responses, they are never
            # redirected back to the client (RFC9126 Section 2.3)
            error.redirect_uri = None
            error.redirect_fragment = False
            raise

        return EndpointRequest(request=request, client=client)

    def create_response(self, validated_request):
        request = validated_request.request
        client = validated_request.client

        request_uri = self.generate_request_uri()
        data = dict(request.payload.data.items())
        expires_at = time.time() + self.EXPIRES_IN
        self.store.save(request_uri, client.get_client_id(), data, expires_at)

        body = {"request_uri": request_uri, "expires_in": self.EXPIRES_IN}
        return 201, body, default_json_headers

    def generate_request_uri(self):
        """Generate the ``request_uri`` value. Developers may rewrite this
        method to customize the value, or its random part length.
        """
        return self.REQUEST_URI_PREFIX + generate_token(32)
