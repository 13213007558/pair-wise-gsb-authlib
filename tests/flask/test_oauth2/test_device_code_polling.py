import time

import pytest
from flask import current_app
from flask import json

from authlib.oauth2.rfc8628 import (
    DeviceAuthorizationEndpoint as _DeviceAuthorizationEndpoint,
)
from authlib.oauth2.rfc8628 import DeviceCodeGrant as _DeviceCodeGrant
from authlib.oauth2.rfc8628 import DeviceCredentialDict
from authlib.oauth2.rfc8628 import InMemoryDevicePollingStore
from authlib.oauth2.rfc8628.errors import AuthorizationPendingError
from authlib.oauth2.rfc8628.errors import SlowDownError

from .models import Token
from .models import User
from .models import db

# user_code -> (approved, user_id); absence means the user has not answered
USER_GRANTS = {}

# device_code -> credential data
CREDENTIALS = {}


class FakeClock:
    """Virtual clock shared by expiry checks, the grant and the store."""

    def __init__(self):
        self.now = 1_000_000.0

    def __call__(self):
        return self.now

    def advance(self, milliseconds):
        self.now += milliseconds / 1000.0


class StoreBackedDeviceCodeGrant(_DeviceCodeGrant):
    def __init__(self, request, server):
        super().__init__(request, server, clock=current_app.config["DEVICE_CLOCK"])

    def query_device_credential(self, device_code):
        data = CREDENTIALS.get(device_code)
        if data is None:
            return None
        return DeviceCredentialDict(data)

    def query_user_grant(self, user_code):
        grant = USER_GRANTS.get(user_code)
        if grant is None:
            return None
        approved, user_id = grant
        return db.session.get(User, user_id), approved

    def get_polling_store(self):
        return current_app.config["DEVICE_POLLING_STORE"]


class LegacyDeviceCodeGrant(_DeviceCodeGrant):
    """The pre-contract extension point: only should_slow_down is implemented."""

    slow_down = False

    def query_device_credential(self, device_code):
        data = CREDENTIALS.get(device_code)
        if data is None:
            return None
        return DeviceCredentialDict(data)

    def query_user_grant(self, user_code):
        grant = USER_GRANTS.get(user_code)
        if grant is None:
            return None
        approved, user_id = grant
        return db.session.get(User, user_id), approved

    def should_slow_down(self, credential):
        return LegacyDeviceCodeGrant.slow_down


class DeviceAuthorizationEndpoint(_DeviceAuthorizationEndpoint):
    def get_verification_uri(self):
        return "https://resource.test/active"

    def save_device_credential(self, client_id, scope, data):
        clock = current_app.config["DEVICE_CLOCK"]
        CREDENTIALS[data["device_code"]] = {
            "client_id": client_id,
            "scope": scope,
            "user_code": data["user_code"],
            "interval": data["interval"],
            "expires_at": clock() + data["expires_in"],
        }


def make_credential(clock, device_code, user_code, *, expires_in=1800):
    CREDENTIALS[device_code] = {
        "client_id": "client-id",
        "device_code": device_code,
        "scope": "profile",
        "user_code": user_code,
        "interval": 5,
        "expires_at": clock() + expires_in,
    }


def token_count():
    return db.session.query(Token).count()


@pytest.fixture(autouse=True)
def setup(server, app, client, db, monkeypatch):
    USER_GRANTS.clear()
    CREDENTIALS.clear()
    LegacyDeviceCodeGrant.slow_down = False

    clock = FakeClock()
    app.config["DEVICE_CLOCK"] = clock
    app.config["DEVICE_POLLING_STORE"] = InMemoryDevicePollingStore(clock=clock)

    # make credential expiry use the same virtual clock as polling
    monkeypatch.setattr(time, "time", clock)

    server.register_grant(StoreBackedDeviceCodeGrant)

    @app.route("/device_authorize", methods=["POST"])
    def device_authorize():
        name = DeviceAuthorizationEndpoint.ENDPOINT_NAME
        return server.create_endpoint_response(name)

    server.register_endpoint(DeviceAuthorizationEndpoint)

    client.set_client_metadata(
        {
            "redirect_uris": ["https://client.test/authorized"],
            "scope": "profile",
            "grant_types": [StoreBackedDeviceCodeGrant.GRANT_TYPE],
            "token_endpoint_auth_method": "none",
        }
    )
    db.session.add(client)
    db.session.commit()
    return clock


def poll(test_client, device_code):
    return test_client.post(
        "/oauth/token",
        data={
            "grant_type": StoreBackedDeviceCodeGrant.GRANT_TYPE,
            "device_code": device_code,
            "client_id": "client-id",
        },
    )


def test_full_state_sequence_with_virtual_time(test_client, app):
    clock = app.config["DEVICE_CLOCK"]
    make_credential(clock, "pending-device", "uc-pending")

    # first poll is admitted, the user has not answered yet
    rv = poll(test_client, "pending-device")
    assert json.loads(rv.data)["error"] == "authorization_pending"
    assert token_count() == 0

    # an immediate poll violates the 5 second interval
    clock.advance(100)
    rv = poll(test_client, "pending-device")
    assert json.loads(rv.data)["error"] == "slow_down"
    assert token_count() == 0

    # the slow_down increase (5s -> 10s) applies to later polls: a poll 5s
    # later is still too early and pushes the interval to 15s
    clock.advance(5_000)
    rv = poll(test_client, "pending-device")
    assert json.loads(rv.data)["error"] == "slow_down"

    # waiting the full accumulated interval is admitted again
    clock.advance(15_000)
    rv = poll(test_client, "pending-device")
    assert json.loads(rv.data)["error"] == "authorization_pending"

    # the user denies: access_denied is terminal regardless of timing
    clock.advance(100)
    USER_GRANTS["uc-pending"] = (False, 1)
    rv = poll(test_client, "pending-device")
    assert json.loads(rv.data)["error"] == "access_denied"
    assert token_count() == 0


def test_approval_on_a_too_fast_poll_returns_token(test_client, app):
    """Approval is checked before the rate limit."""
    clock = app.config["DEVICE_CLOCK"]
    make_credential(clock, "approve-device", "uc-approve")
    poll(test_client, "approve-device")

    clock.advance(50)
    USER_GRANTS["uc-approve"] = (True, 1)
    rv = poll(test_client, "approve-device")
    assert "access_token" in json.loads(rv.data)
    assert token_count() == 1


def test_approved_device_code_cannot_be_consumed_twice(test_client, app):
    clock = app.config["DEVICE_CLOCK"]
    make_credential(clock, "once-device", "uc-once")
    USER_GRANTS["uc-once"] = (True, 1)

    rv = poll(test_client, "once-device")
    assert "access_token" in json.loads(rv.data)
    assert token_count() == 1

    # later polls, even well-spaced, cannot mint another token
    clock.advance(60_000)
    rv = poll(test_client, "once-device")
    assert json.loads(rv.data)["error"] == "invalid_grant"
    assert token_count() == 1


def test_expired_device_code(test_client, app):
    clock = app.config["DEVICE_CLOCK"]
    make_credential(clock, "old-device", "uc-old", expires_in=-1)
    rv = poll(test_client, "old-device")
    assert json.loads(rv.data)["error"] == "expired_token"
    assert token_count() == 0


def test_slow_down_never_replaces_approval_or_denial(test_client, app):
    """A saved decision is terminal even when the poll is too early."""
    clock = app.config["DEVICE_CLOCK"]
    make_credential(clock, "decided-device", "uc-decided")
    poll(test_client, "decided-device")

    clock.advance(10)
    USER_GRANTS["uc-decided"] = (False, 1)
    rv = poll(test_client, "decided-device")
    assert json.loads(rv.data)["error"] == "access_denied"


def test_two_simultaneous_polls_are_serialized(test_client, app, monkeypatch):
    """Only one of two same-instant polls can be admitted on the old interval."""
    clock = app.config["DEVICE_CLOCK"]
    store = app.config["DEVICE_POLLING_STORE"]
    make_credential(clock, "race-device", "uc-race")
    poll(test_client, "race-device")

    # reach exactly the interval boundary; both polls below see this instant
    clock.advance(5_000)
    real_advance = store.check_and_advance
    seen = []

    def traced(device_code, interval, *, now):
        result = real_advance(device_code, interval, now=now)
        seen.append(result.verdict.value)
        return result

    monkeypatch.setattr(store, "check_and_advance", traced)

    first = poll(test_client, "race-device")
    second = poll(test_client, "race-device")
    assert sorted(seen) == ["ready", "too_soon"]
    assert {
        json.loads(first.data)["error"],
        json.loads(second.data)["error"],
    } == {"authorization_pending", "slow_down"}


def test_legacy_should_slow_down_hook_still_works(db):
    """The migration boundary: no store means the deprecated hook decides."""
    grant = LegacyDeviceCodeGrant.__new__(LegacyDeviceCodeGrant)

    LegacyDeviceCodeGrant.slow_down = True
    with pytest.warns(DeprecationWarning):
        with pytest.raises(SlowDownError):
            grant._validate_device_credential_legacy(
                DeviceCredentialDict({"user_code": "missing"})
            )

    LegacyDeviceCodeGrant.slow_down = False
    with pytest.warns(DeprecationWarning):
        with pytest.raises(AuthorizationPendingError):
            grant._validate_device_credential_legacy(
                DeviceCredentialDict({"user_code": "missing"})
            )


def test_legacy_hook_approval_path(db):
    grant = LegacyDeviceCodeGrant.__new__(LegacyDeviceCodeGrant)
    USER_GRANTS["uc-legacy"] = (True, 1)
    with pytest.warns(DeprecationWarning):
        user = grant._validate_device_credential_legacy(
            DeviceCredentialDict({"user_code": "uc-legacy"})
        )
    assert user.id == 1
