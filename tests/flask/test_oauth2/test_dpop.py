import json
import secrets
import sqlite3
import threading
from urllib.parse import parse_qs
from urllib.parse import urlsplit

import pytest
from flask import Flask
from flask import jsonify
from joserfc import jwt
from joserfc.jwk import ECKey
from joserfc.jwk import OctKey
from sqlalchemy.pool import StaticPool

from authlib.integrations.flask_oauth2 import ResourceProtector
from authlib.oauth2.rfc6749.grants import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
)
from authlib.oauth2.rfc6749.grants import RefreshTokenGrant as _RefreshTokenGrant
from authlib.oauth2.rfc9449 import DPoPStateStore
from authlib.oauth2.rfc9449 import DPoPTokenExtension
from authlib.oauth2.rfc9449 import DPoPTokenValidator
from authlib.oauth2.rfc9449.proof import compute_ath

from .models import CodeGrantMixin
from .models import Token
from .models import User
from .models import db
from .models import save_authorization_code
from .oauth2_server import create_basic_header

TOKEN_URL = "http://localhost/oauth/token"
USER_URL = "http://localhost/user"


class ManualClock:
    """A controllable clock injected into the DPoP validators."""

    def __init__(self):
        self._now = 1700000000.0

    def __call__(self):
        return self._now

    def advance(self, seconds):
        self._now += seconds


class SQLiteDPoPStore(DPoPStateStore):
    """DPoP state store backed by a local SQLite database. Atomicity of
    'register_jti' is guaranteed by the PRIMARY KEY constraint; the lock
    only protects the shared connection object."""

    def __init__(self, path=":memory:"):
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        with self._lock, self._conn:
            self._conn.execute(
                "CREATE TABLE dpop_jti ("
                "  jkt TEXT NOT NULL,"
                "  jti TEXT NOT NULL,"
                "  expires_at REAL NOT NULL,"
                "  PRIMARY KEY (jkt, jti)"
                ")"
            )
            self._conn.execute(
                "CREATE TABLE dpop_nonce ("
                "  id INTEGER PRIMARY KEY CHECK (id = 1),"
                "  value TEXT NOT NULL"
                ")"
            )

    def register_jti(self, jkt, jti, expires_at):
        with self._lock:
            try:
                with self._conn:
                    self._conn.execute(
                        "INSERT INTO dpop_jti (jkt, jti, expires_at)"
                        " VALUES (?, ?, ?)",
                        (jkt, jti, expires_at),
                    )
                return True
            except sqlite3.IntegrityError:
                return False

    def get_nonce(self):
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM dpop_nonce WHERE id = 1"
            ).fetchone()
        return row[0] if row else None

    def create_nonce(self):
        value = secrets.token_urlsafe(16)
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO dpop_nonce (id, value) VALUES (1, ?)",
                (value,),
            )
        return value


class AuthorizationCodeGrant(CodeGrantMixin, _AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ["client_secret_basic", "client_secret_post"]

    def save_authorization_code(self, code, request):
        return save_authorization_code(code, request)


class RefreshTokenGrant(_RefreshTokenGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ["client_secret_basic", "client_secret_post"]
    INCLUDE_NEW_REFRESH_TOKEN = True

    def authenticate_refresh_token(self, refresh_token):
        item = Token.query.filter_by(refresh_token=refresh_token).first()
        if item and item.is_refresh_token_active():
            return item

    def authenticate_user(self, credential):
        return db.session.get(User, credential.user_id)

    def revoke_old_credential(self, credential):
        now = 1700000000
        credential.access_token_revoked_at = now
        credential.refresh_token_revoked_at = now
        db.session.add(credential)
        db.session.commit()


@pytest.fixture
def app(tmp_path):
    # a single shared in-memory database, so that concurrent requests
    # from multiple threads see the same data
    app = Flask(__name__)
    app.debug = True
    app.testing = True
    app.secret_key = "testing"
    app.config.update(
        {
            "SQLALCHEMY_TRACK_MODIFICATIONS": False,
            "SQLALCHEMY_DATABASE_URI": "sqlite://",
            "OAUTH2_REFRESH_TOKEN_GENERATOR": True,
            "SQLALCHEMY_ENGINE_OPTIONS": {
                "connect_args": {"check_same_thread": False},
                "poolclass": StaticPool,
            },
        }
    )
    with app.app_context():
        yield app


@pytest.fixture
def clock():
    return ManualClock()


@pytest.fixture
def dpop_store():
    return SQLiteDPoPStore()


@pytest.fixture
def dpop_extension(dpop_store, clock):
    return DPoPTokenExtension(store=dpop_store, now=clock)


@pytest.fixture
def dpop_validator(dpop_store, clock):
    class _Validator(DPoPTokenValidator):
        def authenticate_token(self, token_string):
            return Token.query.filter_by(access_token=token_string).first()

    return _Validator(store=dpop_store, now=clock)


@pytest.fixture(autouse=True)
def server(server, dpop_extension):
    server.register_grant(AuthorizationCodeGrant, [dpop_extension])
    server.register_grant(RefreshTokenGrant, [dpop_extension])
    return server


@pytest.fixture(autouse=True)
def require_oauth(app, dpop_validator):
    protector = ResourceProtector()
    protector.register_token_validator(dpop_validator)

    @app.route("/user")
    @protector()
    def user_profile():
        return jsonify({"username": "foo"})

    return protector


@pytest.fixture(autouse=True)
def client(client, db):
    client.set_client_metadata(
        {
            "redirect_uris": ["https://client.test/authorized"],
            "scope": "profile",
            "token_endpoint_auth_method": "client_secret_basic",
            "response_types": ["code"],
            "grant_types": ["authorization_code", "refresh_token"],
        }
    )
    db.session.add(client)
    db.session.commit()
    return client


@pytest.fixture(scope="module")
def dpop_key():
    return ECKey.generate_key("P-256")


@pytest.fixture(scope="module")
def other_key():
    return ECKey.generate_key("P-256")


def make_proof(key, htm="POST", htu=TOKEN_URL, iat=None, jti=None, **extra):
    header = {
        "typ": extra.pop("typ", "dpop+jwt"),
        "alg": extra.pop("alg", "ES256"),
        "jwk": extra.pop("jwk", key.as_dict(private=False)),
    }
    payload = {
        "htm": htm,
        "htu": htu,
        "iat": iat,
        "jti": jti or secrets.token_urlsafe(12),
    }
    payload.update(extra.pop("claims", {}))
    if "nonce" in extra:
        payload["nonce"] = extra.pop("nonce")
    if "ath" in extra:
        payload["ath"] = extra.pop("ath")
    signing_key = extra.pop("signing_key", key)
    assert not extra, f"unexpected arguments: {extra}"
    return jwt.encode(header, payload, signing_key)


def get_code(test_client):
    rv = test_client.post(
        "/oauth/authorize?response_type=code&client_id=client-id"
        "&redirect_uri=https://client.test/authorized&scope=profile&user_id=1"
    )
    assert rv.status_code == 302
    return parse_qs(urlsplit(rv.location).query)["code"][0]


def post_token_request(test_client, data, proof):
    headers = create_basic_header("client-id", "client-secret")
    if proof is not None:
        headers["DPoP"] = proof
    return test_client.post("/oauth/token", data=data, headers=headers)


def issue_token(test_client, key, clock, proof=None):
    code = get_code(test_client)
    if proof is None:
        proof = make_proof(key, "POST", TOKEN_URL, iat=int(clock()))
    rv = post_token_request(
        test_client,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "https://client.test/authorized",
        },
        proof,
    )
    return rv


def refresh_token_request(test_client, key, clock, refresh_token, proof=None):
    if proof is None:
        proof = make_proof(key, "POST", TOKEN_URL, iat=int(clock()))
    return post_token_request(
        test_client,
        {"grant_type": "refresh_token", "refresh_token": refresh_token},
        proof,
    )


def get_user(test_client, key, access_token, clock, proof=None, path="/user"):
    if proof is None:
        proof = make_proof(
            key,
            "GET",
            USER_URL,
            iat=int(clock()),
            ath=compute_ath(access_token),
        )
    headers = {
        "Authorization": f"DPoP {access_token}",
        "DPoP": proof,
    }
    return test_client.get(path, headers=headers)


# --- full chain tests -------------------------------------------------


def test_issue_token_and_access_resource(test_client, dpop_key, clock):
    rv = issue_token(test_client, dpop_key, clock)
    assert rv.status_code == 200
    resp = json.loads(rv.data)
    assert resp["token_type"] == "DPoP"
    assert resp["cnf"] == {"jkt": dpop_key.thumbprint()}
    assert resp["refresh_token"]

    rv = get_user(test_client, dpop_key, resp["access_token"], clock)
    assert rv.status_code == 200
    assert json.loads(rv.data) == {"username": "foo"}


def test_access_token_with_proof_of_another_key(
    test_client, dpop_key, other_key, clock
):
    rv = issue_token(test_client, dpop_key, clock)
    assert rv.status_code == 200
    access_token = json.loads(rv.data)["access_token"]

    # the access token is correct, but the proof belongs to another key
    rv = get_user(test_client, other_key, access_token, clock)
    assert rv.status_code == 401
    assert rv.headers["WWW-Authenticate"].startswith("DPoP ")
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_token"


def test_concurrent_replay_single_success(app, test_client, dpop_key, clock):
    rv = issue_token(test_client, dpop_key, clock)
    access_token = json.loads(rv.data)["access_token"]

    # the very same proof (same jti) arrives concurrently
    proof = make_proof(
        dpop_key,
        "GET",
        USER_URL,
        iat=int(clock()),
        jti="concurrent-jti",
        ath=compute_ath(access_token),
    )
    headers = {"Authorization": f"DPoP {access_token}", "DPoP": proof}

    barrier = threading.Barrier(8)
    statuses = []

    def worker():
        client = app.test_client()
        barrier.wait(timeout=10)
        rv = client.get("/user", headers=headers)
        statuses.append(rv.status_code)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(statuses) == 8
    assert statuses.count(200) == 1
    assert all(s == 401 for s in statuses if s != 200)


def test_sequential_replay_rejected(test_client, dpop_key, clock):
    rv = issue_token(test_client, dpop_key, clock)
    access_token = json.loads(rv.data)["access_token"]

    proof = make_proof(
        dpop_key,
        "GET",
        USER_URL,
        iat=int(clock()),
        jti="replay-jti",
        ath=compute_ath(access_token),
    )
    rv = get_user(test_client, dpop_key, access_token, clock, proof=proof)
    assert rv.status_code == 200
    rv = get_user(test_client, dpop_key, access_token, clock, proof=proof)
    assert rv.status_code == 401
    assert json.loads(rv.data)["error"] == "invalid_token"


def test_refresh_token_bound_to_same_key(test_client, dpop_key, clock):
    rv = issue_token(test_client, dpop_key, clock)
    resp = json.loads(rv.data)

    rv = refresh_token_request(test_client, dpop_key, clock, resp["refresh_token"])
    assert rv.status_code == 200
    refreshed = json.loads(rv.data)
    assert refreshed["token_type"] == "DPoP"
    assert refreshed["cnf"] == {"jkt": dpop_key.thumbprint()}
    assert refreshed["refresh_token"] != resp["refresh_token"]

    # the new access token works with the same key
    rv = get_user(test_client, dpop_key, refreshed["access_token"], clock)
    assert rv.status_code == 200


def test_refresh_token_with_another_key_rejected(
    test_client, dpop_key, other_key, clock
):
    rv = issue_token(test_client, dpop_key, clock)
    resp = json.loads(rv.data)

    # key rotation on refresh must not be allowed
    rv = refresh_token_request(test_client, other_key, clock, resp["refresh_token"])
    assert rv.status_code == 400
    assert json.loads(rv.data)["error"] == "invalid_grant"


# --- proof validation at the token endpoint ---------------------------


def test_token_request_without_dpop_header(test_client, clock):
    code = get_code(test_client)
    rv = post_token_request(
        test_client,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "https://client.test/authorized",
        },
        None,
    )
    assert rv.status_code == 400
    assert json.loads(rv.data)["error"] == "invalid_dpop_proof"


def test_jwk_with_private_material_rejected(test_client, dpop_key, clock):
    proof = make_proof(
        dpop_key,
        "POST",
        TOKEN_URL,
        iat=int(clock()),
        jwk=dpop_key.as_dict(private=True),
    )
    rv = issue_token(test_client, dpop_key, clock, proof=proof)
    assert rv.status_code == 400
    assert json.loads(rv.data)["error"] == "invalid_dpop_proof"


def test_symmetric_alg_rejected(test_client, clock):
    oct_key = OctKey.import_key(secrets.token_urlsafe(32))
    proof = make_proof(
        oct_key,
        "POST",
        TOKEN_URL,
        iat=int(clock()),
        alg="HS256",
        jwk=oct_key.as_dict(private=False),
    )
    code = get_code(test_client)
    rv = post_token_request(
        test_client,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "https://client.test/authorized",
        },
        proof,
    )
    assert rv.status_code == 400
    assert json.loads(rv.data)["error"] == "invalid_dpop_proof"


def test_wrong_typ_rejected(test_client, dpop_key, clock):
    proof = make_proof(dpop_key, "POST", TOKEN_URL, iat=int(clock()), typ="jwt")
    rv = issue_token(test_client, dpop_key, clock, proof=proof)
    assert rv.status_code == 400
    assert json.loads(rv.data)["error"] == "invalid_dpop_proof"


def test_resource_proof_reused_at_token_endpoint(test_client, dpop_key, clock):
    rv = issue_token(test_client, dpop_key, clock)
    resp = json.loads(rv.data)

    # a proof minted for the resource server carries the resource htu
    # and an ath claim; it must not be accepted at the token endpoint
    resource_proof = make_proof(
        dpop_key,
        "GET",
        USER_URL,
        iat=int(clock()),
        ath=compute_ath(resp["access_token"]),
    )
    rv = refresh_token_request(
        test_client, dpop_key, clock, resp["refresh_token"], proof=resource_proof
    )
    assert rv.status_code == 400
    assert json.loads(rv.data)["error"] == "invalid_dpop_proof"


# --- proof validation at the resource server --------------------------


def test_htm_mismatch_rejected(test_client, dpop_key, clock):
    rv = issue_token(test_client, dpop_key, clock)
    access_token = json.loads(rv.data)["access_token"]

    proof = make_proof(
        dpop_key,
        "POST",
        USER_URL,
        iat=int(clock()),
        ath=compute_ath(access_token),
    )
    rv = get_user(test_client, dpop_key, access_token, clock, proof=proof)
    assert rv.status_code == 401


def test_htu_query_ignored_but_path_strict(test_client, dpop_key, clock):
    rv = issue_token(test_client, dpop_key, clock)
    access_token = json.loads(rv.data)["access_token"]

    # query strings on the request do not change the comparison
    rv = get_user(test_client, dpop_key, access_token, clock, path="/user?a=1&b=2")
    assert rv.status_code == 200

    # a query in the htu claim is ignored as well
    proof = make_proof(
        dpop_key,
        "GET",
        USER_URL + "?x=1#frag",
        iat=int(clock()),
        ath=compute_ath(access_token),
    )
    rv = get_user(test_client, dpop_key, access_token, clock, proof=proof)
    assert rv.status_code == 200

    # but the path is compared exactly: no normalization
    proof = make_proof(
        dpop_key,
        "GET",
        USER_URL + "/",
        iat=int(clock()),
        ath=compute_ath(access_token),
    )
    rv = get_user(test_client, dpop_key, access_token, clock, proof=proof)
    assert rv.status_code == 401

    proof = make_proof(
        dpop_key,
        "GET",
        "http://localhost//user",
        iat=int(clock()),
        ath=compute_ath(access_token),
    )
    rv = get_user(test_client, dpop_key, access_token, clock, proof=proof)
    assert rv.status_code == 401


def test_missing_ath_rejected(test_client, dpop_key, clock):
    rv = issue_token(test_client, dpop_key, clock)
    access_token = json.loads(rv.data)["access_token"]

    proof = make_proof(dpop_key, "GET", USER_URL, iat=int(clock()))
    rv = get_user(test_client, dpop_key, access_token, clock, proof=proof)
    assert rv.status_code == 401
    assert json.loads(rv.data)["error"] == "invalid_token"


def test_ath_of_another_token_rejected(test_client, dpop_key, clock):
    rv = issue_token(test_client, dpop_key, clock)
    access_token = json.loads(rv.data)["access_token"]

    proof = make_proof(
        dpop_key,
        "GET",
        USER_URL,
        iat=int(clock()),
        ath=compute_ath("some-other-token"),
    )
    rv = get_user(test_client, dpop_key, access_token, clock, proof=proof)
    assert rv.status_code == 401


def test_stale_iat_rejected(test_client, dpop_key, clock):
    rv = issue_token(test_client, dpop_key, clock)
    access_token = json.loads(rv.data)["access_token"]

    proof = make_proof(
        dpop_key,
        "GET",
        USER_URL,
        iat=int(clock()) - 3600,
        ath=compute_ath(access_token),
    )
    rv = get_user(test_client, dpop_key, access_token, clock, proof=proof)
    assert rv.status_code == 401

    # after the clock advances, previously valid proofs expire
    fresh_proof = make_proof(
        dpop_key,
        "GET",
        USER_URL,
        iat=int(clock()),
        ath=compute_ath(access_token),
    )
    clock.advance(3600)
    rv = get_user(test_client, dpop_key, access_token, clock, proof=fresh_proof)
    assert rv.status_code == 401


def test_missing_dpop_header_on_resource(test_client, dpop_key, clock):
    rv = issue_token(test_client, dpop_key, clock)
    access_token = json.loads(rv.data)["access_token"]

    rv = test_client.get("/user", headers={"Authorization": f"DPoP {access_token}"})
    assert rv.status_code == 401
    assert rv.headers["WWW-Authenticate"].startswith("DPoP ")


# --- nonce handling ----------------------------------------------------


def test_token_endpoint_nonce_challenge(test_client, dpop_key, clock, dpop_extension):
    dpop_extension.nonce_required = True

    rv = issue_token(test_client, dpop_key, clock)
    assert rv.status_code == 400
    resp = json.loads(rv.data)
    assert resp["error"] == "use_dpop_nonce"
    nonce = rv.headers["DPoP-Nonce"]
    assert nonce

    # a legitimate retry must mint a new proof carrying the nonce
    code = get_code(test_client)
    proof = make_proof(dpop_key, "POST", TOKEN_URL, iat=int(clock()), nonce=nonce)
    rv = post_token_request(
        test_client,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "https://client.test/authorized",
        },
        proof,
    )
    assert rv.status_code == 200
    assert json.loads(rv.data)["cnf"] == {"jkt": dpop_key.thumbprint()}


def test_resource_server_nonce_challenge(test_client, dpop_key, clock, dpop_validator):
    rv = issue_token(test_client, dpop_key, clock)
    access_token = json.loads(rv.data)["access_token"]

    dpop_validator.nonce_required = True

    rv = get_user(test_client, dpop_key, access_token, clock)
    assert rv.status_code == 401
    resp = json.loads(rv.data)
    assert resp["error"] == "use_dpop_nonce"
    nonce = rv.headers["DPoP-Nonce"]
    assert rv.headers["WWW-Authenticate"].startswith("DPoP ")

    # retry with a new proof carrying the nonce
    proof = make_proof(
        dpop_key,
        "GET",
        USER_URL,
        iat=int(clock()),
        ath=compute_ath(access_token),
        nonce=nonce,
    )
    rv = get_user(test_client, dpop_key, access_token, clock, proof=proof)
    assert rv.status_code == 200

    # the accepted proof cannot be replayed
    rv = get_user(test_client, dpop_key, access_token, clock, proof=proof)
    assert rv.status_code == 401
