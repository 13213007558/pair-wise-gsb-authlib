import time

import pytest
from flask import Flask
from joserfc import jwk
from joserfc import jwt
from joserfc.jwk import OctKey

from authlib.integrations.flask_client import OAuth
from authlib.oidc.backchannel import BACKCHANNEL_LOGOUT_EVENT
from authlib.oidc.backchannel import InMemoryBackChannelLogoutStore

from ..util import read_key_file

ISSUER_A = "https://issuer-a.test"
ISSUER_B = "https://issuer-b.test"

key_a = OctKey.import_key("secret-a", {"kty": "oct", "kid": "a"})
key_b = OctKey.import_key("secret-b", {"kty": "oct", "kid": "b"})


def make_logout_token(key, kid, issuer, client_id, **claims):
    now = int(time.time())
    payload = {
        "iss": issuer,
        "aud": client_id,
        "iat": now,
        "exp": now + 600,
        "jti": f"jti-{now}",
        "events": {BACKCHANNEL_LOGOUT_EVENT: {}},
    }
    payload.update(claims)
    payload = {k: v for k, v in payload.items() if v is not None}
    return jwt.encode({"alg": "HS256", "kid": kid}, payload, key)


def token_a(**claims):
    return make_logout_token(key_a, "a", ISSUER_A, "client-a", **claims)


def token_b(**claims):
    return make_logout_token(key_b, "b", ISSUER_B, "client-b", **claims)


@pytest.fixture
def store():
    return InMemoryBackChannelLogoutStore()


@pytest.fixture
def app(store):
    app = Flask(__name__)
    app.secret_key = "!"
    oauth = OAuth(app)
    oauth.register(
        "tenant_a",
        client_id="client-a",
        client_secret="secret",
        issuer=ISSUER_A,
        jwks={"keys": [key_a.as_dict()]},
        id_token_signing_alg_values_supported=["HS256"],
    )
    oauth.register(
        "tenant_b",
        client_id="client-b",
        client_secret="secret",
        issuer=ISSUER_B,
        jwks={"keys": [key_b.as_dict()]},
        id_token_signing_alg_values_supported=["HS256"],
    )

    @app.route("/backchannel-logout/<name>", methods=["POST"])
    def backchannel_logout(name):
        return oauth.create_client(name).handle_backchannel_logout(store)

    return app


@pytest.fixture
def client(app):
    return app.test_client()


def post_logout(client, name, logout_token=None):
    data = {} if logout_token is None else {"logout_token": logout_token}
    return client.post(f"/backchannel-logout/{name}", data=data)


def seed_alice_sessions(store):
    # alice is logged in on two devices at issuer A (client-a)
    store.add_session(ISSUER_A, "client-a", "a-phone", "alice")
    store.add_session(ISSUER_A, "client-a", "a-laptop", "alice")
    # the same sub "alice" also has sessions at issuer B (client-b)
    store.add_session(ISSUER_B, "client-b", "b-phone", "alice")
    # ...and at issuer A under a different client registration
    store.add_session(ISSUER_A, "client-b", "a-other-client", "alice")
    # bob has a session at issuer A too
    store.add_session(ISSUER_A, "client-a", "a-bob", "bob")


def test_backchannel_logout_with_sid(client, store):
    seed_alice_sessions(store)
    resp = post_logout(client, "tenant_a", token_a(sid="a-phone", sub="alice"))
    assert resp.status_code == 200
    assert resp.headers["Cache-Control"] == "no-store"

    # only the targeted session is gone
    assert store.get_session(ISSUER_A, "client-a", "a-phone") is None
    # the other device, other issuers, other clients and other users stay
    assert store.get_session(ISSUER_A, "client-a", "a-laptop") is not None
    assert store.get_session(ISSUER_B, "client-b", "b-phone") is not None
    assert store.get_session(ISSUER_A, "client-b", "a-other-client") is not None
    assert store.get_session(ISSUER_A, "client-a", "a-bob") is not None


def test_backchannel_logout_with_sub_only(client, store):
    seed_alice_sessions(store)
    resp = post_logout(client, "tenant_a", token_a(sid=None, sub="alice"))
    assert resp.status_code == 200

    # all of alice's sessions at issuer A / client-a are gone
    assert store.get_session(ISSUER_A, "client-a", "a-phone") is None
    assert store.get_session(ISSUER_A, "client-a", "a-laptop") is None
    # same sub at another issuer or client is not touched
    assert store.get_session(ISSUER_B, "client-b", "b-phone") is not None
    assert store.get_session(ISSUER_A, "client-b", "a-other-client") is not None
    # other users are not touched
    assert store.get_session(ISSUER_A, "client-a", "a-bob") is not None


def test_backchannel_logout_is_idempotent_replay(client, store):
    seed_alice_sessions(store)
    logout_token = token_a(sid="a-phone", sub="alice")
    assert post_logout(client, "tenant_a", logout_token).status_code == 200
    # replaying the same logout token still succeeds
    assert post_logout(client, "tenant_a", logout_token).status_code == 200
    assert store.get_session(ISSUER_A, "client-a", "a-laptop") is not None


def test_backchannel_logout_multiple_issuers(client, store):
    seed_alice_sessions(store)
    # a logout from issuer B must not affect issuer A sessions
    resp = post_logout(client, "tenant_b", token_b(sid=None, sub="alice"))
    assert resp.status_code == 200
    assert store.get_session(ISSUER_B, "client-b", "b-phone") is None
    assert store.get_session(ISSUER_A, "client-a", "a-phone") is not None
    assert store.get_session(ISSUER_A, "client-a", "a-laptop") is not None


def test_backchannel_logout_missing_token(client):
    resp = post_logout(client, "tenant_a")
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "invalid_request"
    assert resp.headers["Cache-Control"] == "no-store"


def test_backchannel_logout_rejects_nonce(client, store):
    seed_alice_sessions(store)
    resp = post_logout(client, "tenant_a", token_a(sid="a-phone", nonce="n-0S6_WzA2Mj"))
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "invalid_request"
    assert store.get_session(ISSUER_A, "client-a", "a-phone") is not None


def test_backchannel_logout_requires_sub_or_sid(client):
    resp = post_logout(client, "tenant_a", token_a(sid=None, sub=None))
    assert resp.status_code == 400


def test_backchannel_logout_missing_events(client):
    resp = post_logout(client, "tenant_a", token_a(sid="a-phone", events={}))
    assert resp.status_code == 400


def test_backchannel_logout_wrong_issuer(client, store):
    seed_alice_sessions(store)
    logout_token = make_logout_token(
        key_a, "a", "https://attacker.test", "client-a", sid="a-phone"
    )
    resp = post_logout(client, "tenant_a", logout_token)
    assert resp.status_code == 400
    assert store.get_session(ISSUER_A, "client-a", "a-phone") is not None


def test_backchannel_logout_wrong_audience(client, store):
    seed_alice_sessions(store)
    resp = post_logout(client, "tenant_a", token_a(sid="a-phone", aud="client-b"))
    assert resp.status_code == 400
    assert store.get_session(ISSUER_A, "client-a", "a-phone") is not None


def test_backchannel_logout_wrong_signature(client, store):
    seed_alice_sessions(store)
    # token signed with issuer B's key sent to issuer A's endpoint
    resp = post_logout(client, "tenant_a", token_b(sid="a-phone"))
    assert resp.status_code == 400
    assert store.get_session(ISSUER_A, "client-a", "a-phone") is not None


def test_backchannel_logout_expired(client, store):
    seed_alice_sessions(store)
    now = int(time.time())
    resp = post_logout(
        client, "tenant_a", token_a(sid="a-phone", iat=now - 3600, exp=now - 1800)
    )
    assert resp.status_code == 400
    assert store.get_session(ISSUER_A, "client-a", "a-phone") is not None


def test_backchannel_logout_disallowed_algorithm(client, store):
    seed_alice_sessions(store)
    now = int(time.time())
    payload = {
        "iss": ISSUER_A,
        "aud": "client-a",
        "iat": now,
        "exp": now + 600,
        "jti": "jti-rs256",
        "events": {BACKCHANNEL_LOGOUT_EVENT: {}},
        "sid": "a-phone",
    }
    # RS256 is a valid algorithm but not in the provider's allowed list
    rsa_key = jwk.import_key(read_key_file("jwks_private.json")["keys"][0])
    rs256_token = jwt.encode({"alg": "RS256", "kid": "abc"}, payload, rsa_key)
    resp = post_logout(client, "tenant_a", rs256_token)
    assert resp.status_code == 400
    assert store.get_session(ISSUER_A, "client-a", "a-phone") is not None


def test_backchannel_logout_sid_sub_mismatch(client, store):
    seed_alice_sessions(store)
    resp = post_logout(client, "tenant_a", token_a(sid="a-phone", sub="mallory"))
    assert resp.status_code == 400
    assert store.get_session(ISSUER_A, "client-a", "a-phone") is not None


def test_backchannel_logout_storage_error_is_not_fake_success():
    class FailingStore(InMemoryBackChannelLogoutStore):
        def delete_sessions_by_sid(self, issuer, client_id, sid):
            raise ConnectionError("storage unavailable")

    failing_store = FailingStore()
    failing_store.add_session(ISSUER_A, "client-a", "a-phone", "alice")

    app = Flask(__name__)
    app.secret_key = "!"
    oauth = OAuth(app)
    oauth.register(
        "tenant_a",
        client_id="client-a",
        client_secret="secret",
        issuer=ISSUER_A,
        jwks={"keys": [key_a.as_dict()]},
        id_token_signing_alg_values_supported=["HS256"],
    )

    @app.route("/backchannel-logout", methods=["POST"])
    def backchannel_logout():
        return oauth.tenant_a.handle_backchannel_logout(failing_store)

    resp = app.test_client().post(
        "/backchannel-logout", data={"logout_token": token_a(sid="a-phone")}
    )
    # the caller learns the logout was not fully processed
    assert resp.status_code == 500
    assert failing_store.get_session(ISSUER_A, "client-a", "a-phone") is not None
