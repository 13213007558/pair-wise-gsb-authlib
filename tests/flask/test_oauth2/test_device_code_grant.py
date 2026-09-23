import sqlite3
import threading
from types import SimpleNamespace

import pytest
from flask import json

import authlib.oauth2.rfc8628.device_code as device_code_module
import authlib.oauth2.rfc8628.models as models_module
from authlib.oauth2.rfc8628 import (
    DeviceAuthorizationEndpoint as _DeviceAuthorizationEndpoint,
)
from authlib.oauth2.rfc8628 import DeviceCodeGrant as _DeviceCodeGrant
from authlib.oauth2.rfc8628 import DeviceCredentialDict

from .models import Client
from .models import db
from .oauth2_server import create_basic_header


class Clock:
    """A controllable clock for deterministic time-based tests."""

    def __init__(self, start=1700000000.0):
        self._now = start

    def time(self):
        return self._now

    def advance(self, seconds):
        self._now += seconds


class SQLiteDeviceStore:
    """Atomic device credential storage backed by SQLite.

    All poll/approve/consume operations go through this store; the
    compare-and-set in "consume" guarantees that a device_code can
    only be redeemed once, even with concurrent polling requests.
    """

    def __init__(self, clock):
        self.clock = clock
        # test hook, invoked inside "get_user_grant" before returning
        self.before_user_grant = None
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(":memory:", check_same_thread=False)
        self._conn.isolation_level = None
        self._conn.execute(
            "CREATE TABLE device_credential ("
            " device_code TEXT PRIMARY KEY,"
            " client_id TEXT NOT NULL,"
            " user_code TEXT,"
            " scope TEXT,"
            " interval INTEGER,"
            " expires_at REAL,"
            " last_poll_at REAL,"
            " consumed INTEGER NOT NULL DEFAULT 0)"
        )
        self._conn.execute(
            "CREATE TABLE user_grant ("
            " user_code TEXT PRIMARY KEY,"
            " user_id INTEGER NOT NULL,"
            " approved INTEGER NOT NULL)"
        )

    def save_credential(
        self,
        device_code,
        client_id="client-id",
        user_code=None,
        scope="profile",
        interval=5,
        expires_in=1800,
    ):
        expires_at = self.clock.time() + expires_in
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO device_credential"
                " (device_code, client_id, user_code, scope, interval,"
                "  expires_at, last_poll_at, consumed)"
                " VALUES (?, ?, ?, ?, ?, ?, NULL, 0)",
                (device_code, client_id, user_code, scope, interval, expires_at),
            )

    def get_credential(self, device_code):
        with self._lock:
            row = self._conn.execute(
                "SELECT device_code, client_id, user_code, scope, interval,"
                " expires_at FROM device_credential WHERE device_code = ?",
                (device_code,),
            ).fetchone()
        if row is None:
            return None
        return {
            "device_code": row[0],
            "client_id": row[1],
            "user_code": row[2],
            "scope": row[3],
            "interval": row[4],
            "expires_at": row[5],
        }

    def touch(self, device_code, poll_time):
        """Atomically record a poll and return the previous poll time."""
        with self._lock:
            row = self._conn.execute(
                "SELECT last_poll_at FROM device_credential WHERE device_code = ?",
                (device_code,),
            ).fetchone()
            if row is None:
                return None
            self._conn.execute(
                "UPDATE device_credential SET last_poll_at = ?"
                " WHERE device_code = ?",
                (poll_time, device_code),
            )
            return row[0]

    def consume(self, device_code):
        """Atomically mark the device_code consumed (compare-and-set)."""
        with self._lock:
            cursor = self._conn.execute(
                "UPDATE device_credential SET consumed = 1"
                " WHERE device_code = ? AND consumed = 0",
                (device_code,),
            )
        return cursor.rowcount == 1

    def save_user_grant(self, user_code, user_id=1, approved=True):
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO user_grant (user_code, user_id, approved)"
                " VALUES (?, ?, ?)",
                (user_code, user_id, int(approved)),
            )

    def get_user_grant(self, user_code):
        with self._lock:
            row = self._conn.execute(
                "SELECT user_id, approved FROM user_grant WHERE user_code = ?",
                (user_code,),
            ).fetchone()
        if row is None:
            return None
        if self.before_user_grant is not None:
            self.before_user_grant()
        return row[0], bool(row[1])


store = None
token_counter = {"count": 0}
token_counter_lock = threading.Lock()


class SimpleUser:
    """A user object that does not require a database query, so that
    concurrent polling threads never share a SQLAlchemy connection."""

    def __init__(self, user_id):
        self.user_id = user_id

    def get_user_id(self):
        return self.user_id


class DeviceCodeGrant(_DeviceCodeGrant):
    def query_device_credential(self, device_code):
        data = store.get_credential(device_code)
        if data is None:
            return None
        return DeviceCredentialDict(data)

    def query_user_grant(self, user_code):
        grant = store.get_user_grant(user_code)
        if grant is None:
            return None
        user_id, approved = grant
        return SimpleUser(user_id), approved

    def touch_device_credential(self, device_code, poll_time):
        return store.touch(device_code, poll_time)

    def consume_device_credential(self, device_code):
        return store.consume(device_code)

    def generate_token(self, **kwargs):
        with token_counter_lock:
            token_counter["count"] += 1
        return super().generate_token(**kwargs)


saved_credentials = []


class DeviceAuthorizationEndpoint(_DeviceAuthorizationEndpoint):
    def get_verification_uri(self):
        return "https://resource.test/activate"

    def save_device_credential(self, client_id, scope, data):
        saved_credentials.append({"client_id": client_id, "scope": scope})


@pytest.fixture(autouse=True)
def clock(monkeypatch):
    clock = Clock()
    fake_time = SimpleNamespace(time=clock.time)
    monkeypatch.setattr(device_code_module, "time", fake_time)
    monkeypatch.setattr(models_module, "time", fake_time)
    return clock


@pytest.fixture(autouse=True)
def device_store(clock):
    global store
    store = SQLiteDeviceStore(clock)
    token_counter["count"] = 0
    yield store
    store = None


@pytest.fixture(autouse=True)
def server(server, app):
    server.register_grant(DeviceCodeGrant)

    @app.route("/device_authorize", methods=["POST"])
    def device_authorize():
        name = DeviceAuthorizationEndpoint.ENDPOINT_NAME
        return server.create_endpoint_response(name)

    server.register_endpoint(DeviceAuthorizationEndpoint)

    return server


@pytest.fixture(autouse=True)
def client(client, db):
    client.set_client_metadata(
        {
            "redirect_uris": ["https://client.test/authorized"],
            "scope": "profile",
            "grant_types": [DeviceCodeGrant.GRANT_TYPE],
            "token_endpoint_auth_method": "none",
        }
    )
    db.session.add(client)
    db.session.commit()
    return client


def poll_token(test_client, device_code, client_id="client-id"):
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": DeviceCodeGrant.GRANT_TYPE,
            "device_code": device_code,
            "client_id": client_id,
        },
    )
    return json.loads(rv.data)


def test_invalid_request(test_client):
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": DeviceCodeGrant.GRANT_TYPE,
            "client_id": "client-id",
        },
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_request"

    resp = poll_token(test_client, "missing")
    assert resp["error"] == "invalid_request"


def test_unauthorized_client(test_client, db, client, device_store):
    resp = poll_token(test_client, "valid-device", client_id="invalid")
    assert resp["error"] == "invalid_client"

    client.set_client_metadata(
        {
            "redirect_uris": ["https://client.test/authorized"],
            "scope": "profile",
            "grant_types": ["password"],
            "token_endpoint_auth_method": "none",
        }
    )
    db.session.add(client)
    db.session.commit()

    device_store.save_credential("valid-device", user_code="none")
    resp = poll_token(test_client, "valid-device")
    assert resp["error"] == "unauthorized_client"


def test_device_code_issued_to_another_client(test_client, db, device_store):
    other = Client(
        user_id=1,
        client_id="other-client",
        client_secret="other-secret",
    )
    other.set_client_metadata(
        {
            "scope": "profile",
            "grant_types": [DeviceCodeGrant.GRANT_TYPE],
            "token_endpoint_auth_method": "none",
        }
    )
    db.session.add(other)
    db.session.commit()

    device_store.save_credential("owned-code", user_code="owned-user")
    resp = poll_token(test_client, "owned-code", client_id="other-client")
    assert resp["error"] == "unauthorized_client"


def test_expired_token(test_client, device_store):
    device_store.save_credential("expired-token", user_code="none", expires_in=-100)
    resp = poll_token(test_client, "expired-token")
    assert resp["error"] == "expired_token"


def test_denied_by_user(test_client, device_store):
    device_store.save_credential("denied-code", user_code="denied")
    device_store.save_user_grant("denied", approved=False)
    resp = poll_token(test_client, "denied-code")
    assert resp["error"] == "access_denied"


def test_authorization_pending_then_slow_down(test_client, device_store, clock):
    device_store.save_credential("pending-code", user_code="pending", interval=30)

    resp = poll_token(test_client, "pending-code")
    assert resp["error"] == "authorization_pending"

    # polling again within the interval increases the interval
    resp = poll_token(test_client, "pending-code")
    assert resp["error"] == "slow_down"

    # after the interval has elapsed, polling is allowed again
    clock.advance(31)
    resp = poll_token(test_client, "pending-code")
    assert resp["error"] == "authorization_pending"


def test_approval_before_first_poll(test_client, device_store):
    device_store.save_credential("approved-code", user_code="approved")
    device_store.save_user_grant("approved", approved=True)

    resp = poll_token(test_client, "approved-code")
    assert "access_token" in resp
    assert token_counter["count"] == 1

    # the same device_code can not be redeemed twice
    resp = poll_token(test_client, "approved-code")
    assert resp["error"] == "used_device_code"
    assert token_counter["count"] == 1


def test_approval_after_first_poll(test_client, device_store):
    device_store.save_credential("late-code", user_code="late", interval=30)

    resp = poll_token(test_client, "late-code")
    assert resp["error"] == "authorization_pending"

    device_store.save_user_grant("late", approved=True)
    resp = poll_token(test_client, "late-code")
    assert "access_token" in resp
    assert token_counter["count"] == 1


def test_concurrent_polling_redeems_only_once(app, device_store):
    device_store.save_credential("race-code", user_code="race")
    device_store.save_user_grant("race", approved=True)

    # both threads read the approved grant before either consumes the code
    barrier = threading.Barrier(2, timeout=30)
    device_store.before_user_grant = barrier.wait

    results = []
    results_lock = threading.Lock()

    def poll():
        test_client = app.test_client()
        try:
            resp = poll_token(test_client, "race-code")
        except Exception as exc:
            resp = {"error": f"thread crashed: {exc!r}"}
        with results_lock:
            results.append(resp)

    threads = [threading.Thread(target=poll) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    tokens = [resp for resp in results if "access_token" in resp]
    used = [resp for resp in results if resp.get("error") == "used_device_code"]
    assert len(tokens) == 1
    assert len(used) == 1
    assert token_counter["count"] == 1


def test_storage_error_is_not_pending(test_client, device_store, monkeypatch):
    device_store.save_credential("broken-code", user_code="broken")

    def broken_get_user_grant(user_code):
        raise RuntimeError("storage is down")

    monkeypatch.setattr(device_store, "get_user_grant", broken_get_user_grant)
    with pytest.raises(RuntimeError, match="storage is down"):
        poll_token(test_client, "broken-code")


def test_missing_client_id(test_client):
    rv = test_client.post("/device_authorize", data={"scope": "profile"})
    assert rv.status_code == 401
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_client"


def test_client_secret_basic_saves_authenticated_client_id(test_client, db, client):
    # When the client authenticates with HTTP Basic, its id is in the
    # Authorization header rather than the form body, so the saved credential
    # must come from the authenticated client, not request.payload.client_id.
    client.set_client_metadata(
        {
            "scope": "profile",
            "grant_types": [DeviceCodeGrant.GRANT_TYPE],
            "token_endpoint_auth_method": "client_secret_basic",
        }
    )
    db.session.add(client)
    db.session.commit()

    saved_credentials.clear()
    rv = test_client.post(
        "/device_authorize",
        data={"scope": "profile"},
        headers=create_basic_header("client-id", "client-secret"),
    )
    assert rv.status_code == 200
    assert saved_credentials[-1]["client_id"] == "client-id"


def test_create_authorization_response(test_client):
    client = Client(
        user_id=1,
        client_id="client",
        client_secret="secret",
    )
    db.session.add(client)
    db.session.commit()
    rv = test_client.post(
        "/device_authorize",
        data={
            "client_id": "client-id",
        },
    )
    assert rv.status_code == 200
    resp = json.loads(rv.data)
    assert "device_code" in resp
    assert "user_code" in resp
    assert resp["verification_uri"] == "https://resource.test/activate"
    assert (
        resp["verification_uri_complete"]
        == "https://resource.test/activate?user_code=" + resp["user_code"]
    )
