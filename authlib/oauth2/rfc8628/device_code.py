import logging
import time

from authlib.deprecate import deprecate

from ..rfc6749 import BaseGrant
from ..rfc6749 import JsonResponse
from ..rfc6749 import TokenEndpointMixin
from ..rfc6749.errors import AccessDeniedError
from ..rfc6749.errors import InvalidGrantError
from ..rfc6749.errors import InvalidRequestError
from ..rfc6749.errors import UnauthorizedClientError
from .errors import AuthorizationPendingError
from .errors import ExpiredTokenError
from .errors import SlowDownError
from .polling import DEFAULT_INTERVAL
from .polling import PollingVerdict

log = logging.getLogger(__name__)
DEVICE_CODE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code"


class DeviceCodeGrant(BaseGrant, TokenEndpointMixin):
    """This OAuth 2.0 [RFC6749] protocol extension enables OAuth clients to
    request user authorization from applications on devices that have
    limited input capabilities or lack a suitable browser.  Such devices
    include smart TVs, media consoles, picture frames, and printers,
    which lack an easy input method or a suitable browser required for
    traditional OAuth interactions. Here is the authorization flow::

        +----------+                                +----------------+
        |          |>---(A)-- Client Identifier --->|                |
        |          |                                |                |
        |          |<---(B)-- Device Code,      ---<|                |
        |          |          User Code,            |                |
        |  Device  |          & Verification URI    |                |
        |  Client  |                                |                |
        |          |  [polling]                     |                |
        |          |>---(E)-- Device Code       --->|                |
        |          |          & Client Identifier   |                |
        |          |                                |  Authorization |
        |          |<---(F)-- Access Token      ---<|     Server     |
        +----------+   (& Optional Refresh Token)   |                |
              v                                     |                |
              :                                     |                |
             (C) User Code & Verification URI       |                |
              :                                     |                |
              v                                     |                |
        +----------+                                |                |
        | End User |                                |                |
        |    at    |<---(D)-- End user reviews  --->|                |
        |  Browser |          authorization request |                |
        +----------+                                +----------------+

    This DeviceCodeGrant is the implementation of step (E) and (F).

    (E) While the end user reviews the client's request (step D), the
        client repeatedly polls the authorization server to find out if
        the user completed the user authorization step.  The client
        includes the device code and its client identifier.

    (F) The authorization server validates the device code provided by
        the client and responds with the access token if the client is
        granted access, an error if they are denied access, or an
        indication that the client should continue to poll.
    """

    GRANT_TYPE = DEVICE_CODE_GRANT_TYPE
    TOKEN_ENDPOINT_AUTH_METHODS = ["client_secret_basic", "client_secret_post", "none"]

    def __init__(self, request, server, *, clock=time.monotonic):
        super().__init__(request, server)
        self._clock = clock

    def validate_token_request(self):
        """After displaying instructions to the user, the client creates an
        access token request and sends it to the token endpoint with the
        following parameters:

        grant_type
            REQUIRED.  Value MUST be set to
            "urn:ietf:params:oauth:grant-type:device_code".

        device_code
            REQUIRED.  The device verification code, "device_code" from the
            device authorization response.

        client_id
            REQUIRED if the client is not authenticating with the
            authorization server as described in Section 3.2.1. of [RFC6749].
            The client identifier as described in Section 2.2 of [RFC6749].

        For example, the client makes the following HTTPS request::

            POST /token HTTP/1.1
            Host: server.example.com
            Content-Type: application/x-www-form-urlencoded

            grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code
            &device_code=GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS
            &client_id=1406020730
        """
        device_code = self.request.payload.data.get("device_code")
        if not device_code:
            raise InvalidRequestError("Missing 'device_code' in payload")

        client = self.authenticate_token_endpoint_client()
        if not client.check_grant_type(self.GRANT_TYPE):
            raise UnauthorizedClientError(
                f"The client is not authorized to use 'response_type={self.GRANT_TYPE}'",
            )

        credential = self.query_device_credential(device_code)
        if not credential:
            raise InvalidRequestError("Invalid 'device_code' in payload")

        if credential.get_client_id() != client.get_client_id():
            raise UnauthorizedClientError()

        user = self.validate_device_credential(credential)
        self.request.user = user
        self.request.client = client
        self.request.credential = credential

    def create_token_response(self):
        """If the access token request is valid and authorized, the
        authorization server issues an access token and optional refresh
        token.
        """
        client = self.request.client
        scope = self.request.credential.get_scope()
        token = self.generate_token(
            user=self.request.user,
            scope=scope,
            include_refresh_token=client.check_grant_type("refresh_token"),
        )
        log.debug("Issue token %r to %r", token, client)
        self.save_token(token)
        return JsonResponse(token, headers=self.TOKEN_RESPONSE_HEADER)

    def validate_device_credential(self, credential):
        """Resolve one poll into a user or an RFC 8628 error.

        The decision order is fixed and does not depend on the order in which
        storage callbacks happen to run:

        1. an expired ``device_code`` produces ``expired_token``;
        2. a device code that already produced a token produces
           ``invalid_grant``, so a grant cannot be consumed twice;
        3. a saved user decision is terminal: denial is ``access_denied`` and
           approval returns the user -- approval is checked *before* the
           rate limit, so a poll that is too early still gets the token when
           the user approved at exactly the same time;
        4. otherwise the poll is rate-limited atomically: an early poll
           produces ``slow_down`` and any other poll
           ``authorization_pending``.
        """
        device_code = self.request.payload.data.get("device_code")
        if credential.is_expired():
            raise ExpiredTokenError()

        store = self.get_polling_store()
        if store is None:
            return self._validate_device_credential_legacy(credential)

        now = self._clock()
        interval = self.get_polling_interval(credential)
        advance = store.check_and_advance(device_code, interval, now=now)
        if advance.consumed:
            raise InvalidGrantError("The 'device_code' has already been used")

        user_grant = self.query_user_grant(credential.get_user_code())
        if user_grant is not None:
            user, approved = user_grant
            if not approved:
                raise AccessDeniedError()
            store.mark_consumed(device_code, now=now)
            return user

        if advance.verdict is PollingVerdict.TOO_SOON:
            raise SlowDownError()
        raise AuthorizationPendingError()

    def _validate_device_credential_legacy(self, credential):
        deprecate(
            "DeviceCodeGrant.should_slow_down is deprecated; implement "
            "get_polling_store() with a DevicePollingStore instead.",
            version="1.11",
            stacklevel=4,
        )
        user_code = credential.get_user_code()
        user_grant = self.query_user_grant(user_code)

        if user_grant is not None:
            user, approved = user_grant
            if not approved:
                raise AccessDeniedError()
            return user

        if self.should_slow_down(credential):
            raise SlowDownError()

        raise AuthorizationPendingError()

    def get_polling_store(self):
        """Return the :class:`~authlib.oauth2.rfc8628.DevicePollingStore`
        that holds the polling state of device codes, or ``None``.

        Returning ``None`` (the default) keeps the deprecated
        :meth:`should_slow_down` hook working. New implementations return a
        store, typically a shared one such as a Redis-backed one, and let the
        grant enforce the polling interval and single use of a device code::

            class MyDeviceCodeGrant(DeviceCodeGrant):
                def get_polling_store(self):
                    return redis_polling_store
        """
        return None

    def get_polling_interval(self, credential):
        """The interval in seconds currently advertised to the client.

        It defaults to the ``interval`` saved with the credential, or to
        :data:`~authlib.oauth2.rfc8628.polling.DEFAULT_INTERVAL`. The store
        only ever increases it, by
        :data:`~authlib.oauth2.rfc8628.polling.SLOW_DOWN_STEP` seconds after
        each ``slow_down`` response.
        """
        interval = getattr(credential, "get_interval", None)
        if interval is not None:
            value = interval()
            if value is not None:
                return float(value)
        if isinstance(credential, dict):
            value = credential.get("interval")
            if value is not None:
                return float(value)
        return float(DEFAULT_INTERVAL)

    def query_device_credential(self, device_code):
        """Get device credential from previously savings via ``DeviceAuthorizationEndpoint``.
        Developers MUST implement it in subclass::

            def query_device_credential(self, device_code):
                return DeviceCredential.get(device_code)

        :param device_code: a string represent the code.
        :return: DeviceCredential instance
        """
        raise NotImplementedError()

    def query_user_grant(self, user_code):
        """Get user and grant via the given user code. Developers MUST
        implement it in subclass::

            def query_user_grant(self, user_code):
                # e.g. we saved user grant info in redis
                data = redis.get("oauth_user_grant:" + user_code)
                if not data:
                    return None

                user_id, allowed = data.split()
                user = User.get(user_id)
                return user, allowed == "1"

        Note, user grant information is saved by verification endpoint.
        """
        raise NotImplementedError()

    def should_slow_down(self, credential):
        """Deprecated migration hook.

        The authorization request is still pending and polling should
        continue, but the interval MUST be increased by 5 seconds for this
        and all subsequent requests.

        This hook is only called when :meth:`get_polling_store` returns
        ``None``; relying on it emits a deprecation warning. New code returns
        a :class:`~authlib.oauth2.rfc8628.DevicePollingStore` from
        :meth:`get_polling_store`, which enforces the interval, the
        ``slow_down`` increase and single use of a device code atomically.
        """
        raise NotImplementedError()
