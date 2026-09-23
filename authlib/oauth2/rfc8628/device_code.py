import logging
import time

from ..rfc6749 import BaseGrant
from ..rfc6749 import TokenEndpointMixin
from ..rfc6749.errors import AccessDeniedError
from ..rfc6749.errors import InvalidRequestError
from ..rfc6749.errors import UnauthorizedClientError
from ..rfc6749.hooks import hooked
from .errors import AuthorizationPendingError
from .errors import DeviceCodeConsumedError
from .errors import ExpiredTokenError
from .errors import SlowDownError

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

        # Atomically mark the credential as consumed *before* issuing any
        # token, so that two concurrent polls can never both redeem the
        # same device_code. The losing request stops here and never reaches
        # the token generator.
        if not self.consume_device_credential(credential):
            raise DeviceCodeConsumedError()

        self.request.user = user
        self.request.client = client
        self.request.credential = credential

    @hooked
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
        return 200, token, self.TOKEN_RESPONSE_HEADER

    def validate_device_credential(self, credential):
        if credential.is_expired():
            raise ExpiredTokenError()

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

    def get_current_time(self):
        """Return the current time in seconds, used to decide between
        ``authorization_pending`` and ``slow_down``. Tests and subclasses
        may override this method with a controllable clock.
        """
        return time.time()

    def should_slow_down(self, credential):
        """The authorization request is still pending and polling should
        continue, but the interval MUST be increased by 5 seconds for this
        and all subsequent requests.

        The default implementation records the current poll through the
        atomic :meth:`touch_device_credential` storage operation and
        compares the timestamp of the previous poll with the credential's
        own ``interval`` (issued by ``DeviceAuthorizationEndpoint``, never
        hardcoded in this grant). Developers may override this method to
        customize the policy.
        """
        now = self.get_current_time()
        last_poll_at = self.touch_device_credential(credential, now)
        if last_poll_at is None:
            # first poll of this device_code
            return False
        interval = credential.get_interval()
        if interval is None:
            return False
        return now - last_poll_at < interval

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
                return user, bool(allowed)

        Note, user grant information is saved by verification endpoint.
        """
        raise NotImplementedError()

    def touch_device_credential(self, credential, now):
        """Atomically record that the client polled the token endpoint at
        ``now``, and return the timestamp of the previous poll, or ``None``
        if this is the first poll. Developers MUST implement it in subclass::

            def touch_device_credential(self, credential, now):
                with atomic_transaction():
                    last_poll_at = credential.last_poll_at
                    credential.last_poll_at = now
                    credential.save()
                return last_poll_at

        This method MUST be atomic, since a device usually polls the token
        endpoint repeatedly, possibly with concurrent requests. It MUST
        raise an exception if the storage operation fails; a storage
        failure is never treated as "the user has not approved yet".

        :param credential: the DeviceCredential instance
        :param now: the current poll time, in seconds
        :return: the previous poll time, or None
        """
        raise NotImplementedError()

    def consume_device_credential(self, credential):
        """Atomically mark the device credential as consumed, and return
        ``True`` if this call performed the consumption. Return ``False``
        if the credential had already been consumed, in which case the
        grant rejects the request with an "invalid_grant" error and no
        token is generated. Developers MUST implement it in subclass::

            def consume_device_credential(self, credential):
                rows = db.session.execute(
                    update(DeviceCredential)
                    .where(DeviceCredential.device_code == credential.device_code)
                    .where(DeviceCredential.consumed.is_(False))
                    .values(consumed=True)
                ).rowcount
                db.session.commit()
                return rows == 1

        This method MUST be atomic, so that a device_code can be exchanged
        for an access token only once, even under concurrent polling. It
        MUST raise an exception if the storage operation fails.

        :param credential: the DeviceCredential instance
        :return: True if consumed by this call, False if already consumed
        """
        raise NotImplementedError()
