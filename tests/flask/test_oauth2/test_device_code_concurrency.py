import shutil
import sqlite3
import tempfile
import threading
from pathlib import Path

import pytest
from flask import Flask
from flask import json

from authlib.oauth2.rfc8628 import DeviceCodeGrant as _DeviceCodeGrant
from authlib.oauth2.rfc8628 import DeviceCredentialMixin

from .models import User
from .models import db

PROJECT_ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture
def db_dir():
    # file based databases must live in a writable directory; pytest's tmp_path
    # is not guaranteed to allow SQLite's file locking in every sandbox
    path = tempfile.mkdtemp(prefix=".device-code-test-", dir=PROJECT_ROOT)
    try:
        yield Path(path)
    finally:
        shutil.rmtree(path, ignore_errors=True)


class FakeClock:
    """A controllable clock, manually advanced by tests."""

    def __init__(self, start=1_000_000.0):
        self._now = start
        self._lock = threading.Lock()

    def now(self):
        with self._lock:
            return self._now

    def advance(self, seconds):
        with self._lock:
            self._now += seconds


SCHEMA = """
CREATE TABLE device_credential (
    device_code TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    user_code TEXT NOT NULL,
    scope TEXT,
    expires_at REAL NOT NULL,
    interval INTEGER,
    last_poll_at REAL,
    consumed INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE user_grant (
    user_code TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    approved INTEGER NOT NULL
);
"""


class SQLiteDeviceStore:
    """Application-provided atomic storage for device credentials.

    Every poll, approval lookup and consumption goes through this store.
    """

    def __init__(self, path):
        self.path = str(path)
        conn = self._connect()
        try:
            conn.executescript(SCHEMA)
            conn.commit()
        finally:
            conn.close()

    def _connect(self):
        return sqlite3.connect(self.path, timeout=30)

    def add_credential(
        self, device_code, client_id, user_code, scope, expires_at, interval
    ):
        conn = self._connect()
        try:
            conn.execute(
                "INSERT INTO device_credential"
                " (device_code, client_id, user_code, scope, expires_at, interval)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (device_code, client_id, user_code, scope, expires_at, interval),
            )
            conn.commit()
        finally:
            conn.close()

    def set_user_grant(self, user_code, user_id, approved):
        conn = self._connect()
        try:
            conn.execute(
                "INSERT OR REPLACE INTO user_grant (user_code, user_id, approved)"
                " VALUES (?, ?, ?)",
                (user_code, user_id, int(approved)),
            )
            conn.commit()
        finally:
            conn.close()

    def get_credential(self, device_code):
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT device_code, client_id, user_code, scope, expires_at,"
                " interval, last_poll_at, consumed"
                " FROM device_credential WHERE device_code = ?",
                (device_code,),
            ).fetchone()
        finally:
            conn.close()
        if row is None:
            return None
        keys = (
            "device_code",
            "client_id",
            "user_code",
            "scope",
            "expires_at",
            "interval",
            "last_poll_at",
            "consumed",
        )
        return dict(zip(keys, row, strict=False))

    def get_user_grant(self, user_code):
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT user_code, user_id, approved FROM user_grant"
                " WHERE user_code = ?",
                (user_code,),
            ).fetchone()
        finally:
            conn.close()
        if row is None:
            return None
        return {"user_code": row[0], "user_id": row[1], "approved": row[2]}

    def touch(self, device_code, now):
        """Atomically record a poll and return the previous poll time."""
        conn = self._connect()
        try:
            conn.isolation_level = None
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute(
                    "SELECT last_poll_at FROM device_credential"
                    " WHERE device_code = ?",
                    (device_code,),
                ).fetchone()
                last_poll_at = row[0] if row else None
                conn.execute(
                    "UPDATE device_credential SET last_poll_at = ?"
                    " WHERE device_code = ?",
                    (now, device_code),
                )
            except BaseException:
                conn.execute("ROLLBACK")
                raise
            else:
                conn.execute("COMMIT")
            return last_poll_at
        finally:
            conn.close()

    def consume(self, device_code):
        """Atomically mark the credential consumed; True only for the winner."""
        conn = self._connect()
        try:
            cursor = conn.execute(
                "UPDATE device_credential SET consumed = 1"
                " WHERE device_code = ? AND consumed = 0",
                (device_code,),
            )
            conn.commit()
            return cursor.rowcount == 1
        finally:
            conn.close()

    def is_consumed(self, device_code):
        row = self.get_credential(device_code)
        return bool(row["consumed"])


class SQLiteDeviceCredential(DeviceCredentialMixin):
    def __init__(self, row, clock):
        self.row = row
        self.clock = clock

    @property
    def device_code(self):
        return self.row["device_code"]

    def get_client_id(self):
        return self.row["client_id"]

    def get_scope(self):
        return self.row["scope"]

    def get_user_code(self):
        return self.row["user_code"]

    def get_interval(self):
        return self.row["interval"]

    def is_expired(self):
        return self.row["expires_at"] < self.clock.now()


class SQLiteDeviceCodeGrant(_DeviceCodeGrant):
    store = None
    clock = None
    poll_barrier = None
    token_generator_calls = 0
    _token_generator_lock = threading.Lock()

    def get_current_time(self):
        return self.clock.now()

    def query_device_credential(self, device_code):
        row = self.store.get_credential(device_code)
        if row is None:
            return None
        return SQLiteDeviceCredential(row, self.clock)

    def query_user_grant(self, user_code):
        row = self.store.get_user_grant(user_code)
        if row is None:
            return None
        user = db.session.get(User, row["user_id"])
        return user, bool(row["approved"])

    def touch_device_credential(self, credential, now):
        return self.store.touch(credential.device_code, now)

    def consume_device_credential(self, credential):
        return self.store.consume(credential.device_code)

    def validate_device_credential(self, credential):
        user = super().validate_device_credential(credential)
        barrier = type(self).poll_barrier
        if barrier is not None:
            # synchronize concurrent polls right before the atomic
            # consumption, to force the redemption race
            barrier.wait(timeout=30)
        return user

    def generate_token(self, *args, **kwargs):
        with type(self)._token_generator_lock:
            type(self).token_generator_calls += 1
        return super().generate_token(*args, **kwargs)


@pytest.fixture
def app(db_dir):
    app = Flask(__name__)
    app.debug = True
    app.testing = True
    app.secret_key = "testing"
    app.config.update(
        {
            "SQLALCHEMY_TRACK_MODIFICATIONS": False,
            # a file based SQLite database, so that concurrent requests
            # from multiple threads share the same data
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{db_dir}/oauth2.db",
        }
    )
    with app.app_context():
        yield app


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def store(db_dir):
    return SQLiteDeviceStore(db_dir / "device_store.db")


@pytest.fixture(autouse=True)
def server(server, store, clock):
    SQLiteDeviceCodeGrant.store = store
    SQLiteDeviceCodeGrant.clock = clock
    SQLiteDeviceCodeGrant.poll_barrier = None
    SQLiteDeviceCodeGrant.token_generator_calls = 0
    server.register_grant(SQLiteDeviceCodeGrant)
    yield server
    SQLiteDeviceCodeGrant.store = None
    SQLiteDeviceCodeGrant.clock = None
    SQLiteDeviceCodeGrant.poll_barrier = None


@pytest.fixture(autouse=True)
def client(client, db):
    client.set_client_metadata(
        {
            "redirect_uris": ["https://client.test/authorized"],
            "scope": "profile",
            "grant_types": [SQLiteDeviceCodeGrant.GRANT_TYPE],
            "token_endpoint_auth_method": "none",
        }
    )
    db.session.add(client)
    db.session.commit()
    return client


def add_credential(
    store,
    clock,
    device_code="dev-code",
    user_code="user-code",
    interval=5,
    expires_in=1800,
):
    store.add_credential(
        device_code=device_code,
        client_id="client-id",
        user_code=user_code,
        scope="profile",
        expires_at=clock.now() + expires_in,
        interval=interval,
    )


def poll(test_client, device_code="dev-code"):
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": SQLiteDeviceCodeGrant.GRANT_TYPE,
            "device_code": device_code,
            "client_id": "client-id",
        },
    )
    return rv.status_code, json.loads(rv.data)


def test_concurrent_polls_issue_only_one_token(app, store, clock, db):
    add_credential(store, clock)
    # the user has approved before both polls
    store.set_user_grant("user-code", 1, True)

    SQLiteDeviceCodeGrant.poll_barrier = threading.Barrier(2)
    results = []

    def worker():
        # each thread gets its own test client
        results.append(poll(app.test_client()))

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
        assert not thread.is_alive()

    successes = [resp for _, resp in results if "access_token" in resp]
    errors = [resp for _, resp in results if "error" in resp]
    assert len(successes) == 1
    assert len(errors) == 1
    # the loser gets a clear already-consumed error
    assert errors[0]["error"] == "invalid_grant"
    # the token generator ran exactly once
    assert SQLiteDeviceCodeGrant.token_generator_calls == 1
    assert store.is_consumed("dev-code")


def test_approval_before_first_poll(app, store, clock, db):
    add_credential(store, clock)
    # approval happens before the device ever polls
    store.set_user_grant("user-code", 1, True)

    status, resp = poll(app.test_client())
    assert status == 200
    assert "access_token" in resp
    assert SQLiteDeviceCodeGrant.token_generator_calls == 1


def test_approval_after_first_poll(app, store, clock, db):
    add_credential(store, clock, interval=5)
    test_client = app.test_client()

    # first poll: the user has not approved yet
    _, resp = poll(test_client)
    assert resp["error"] == "authorization_pending"

    # polling again before the interval elapsed -> slow_down
    clock.advance(2)
    _, resp = poll(test_client)
    assert resp["error"] == "slow_down"

    # the user approves after polling has started
    store.set_user_grant("user-code", 1, True)

    clock.advance(5)
    status, resp = poll(test_client)
    assert status == 200
    assert "access_token" in resp
    assert SQLiteDeviceCodeGrant.token_generator_calls == 1

    # the same device_code cannot be redeemed a second time
    clock.advance(5)
    _, resp = poll(test_client)
    assert resp["error"] == "invalid_grant"
    assert SQLiteDeviceCodeGrant.token_generator_calls == 1


def test_storage_failure_is_not_treated_as_pending(app, store, clock, db, monkeypatch):
    add_credential(store, clock)

    def broken_touch(device_code, now):
        raise RuntimeError("storage is down")

    monkeypatch.setattr(store, "touch", broken_touch)

    # the storage error must propagate, it is never swallowed into an
    # "authorization_pending" response
    with pytest.raises(RuntimeError, match="storage is down"):
        poll(app.test_client())


def test_device_code_expiration_uses_grant_clock(app, store, clock, db):
    add_credential(store, clock, expires_in=10)
    test_client = app.test_client()

    _, resp = poll(test_client)
    assert resp["error"] == "authorization_pending"

    clock.advance(11)
    _, resp = poll(test_client)
    assert resp["error"] == "expired_token"
