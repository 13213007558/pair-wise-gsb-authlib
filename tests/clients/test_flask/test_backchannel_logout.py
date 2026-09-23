import time
import uuid

from flask import Flask
from joserfc import jwk
from joserfc import jwt
from joserfc.jws import JWSRegistry

from authlib.integrations.flask_client import InMemoryLogoutStore
from authlib.integrations.flask_client import OAuth

ISSUER_ONE = "https://issuer-one.test"
ISSUER_TWO = "https://issuer-two.test"
LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout"

KEY_ONE = jwk.import_key("secret-one", "oct")
KEY_TWO = jwk.import_key("secret-two", "oct")


def create_clients(shared_store=None):
    app = Flask(__name__)
    oauth = OAuth(app)
    client_one = oauth.register(
        "one",
        client_id="client-one",
        issuer=ISSUER_ONE,
        jwks={"keys": [KEY_ONE.as_dict()]},
        id_token_signing_alg_values_supported=["HS256"],
    )
    client_two = oauth.register(
        "two",
        client_id="client-two",
        issuer=ISSUER_TWO,
        jwks={"keys": [KEY_TWO.as_dict()]},
        id_token_signing_alg_values_supported=["HS256"],
    )
    if shared_store is not None:
        client_one.logout_store = shared_store
        client_two.logout_store = shared_store
    return app, client_one, client_two


def logout_claims(iss, client_id, **kwargs):
    claims = {
        "iss": iss,
        "aud": client_id,
        "iat": int(time.time()),
        "jti": uuid.uuid4().hex,
        "events": {LOGOUT_EVENT: {}},
    }
    claims.update(kwargs)
    return claims


def encode_token(key, claims, alg="HS256"):
    return jwt.encode({"alg": alg}, claims, key)


def run_logout(app, client, token, on_logout=None, store=None):
    with app.test_request_context(
        "/backchannel-logout", method="POST", data={"logout_token": token}
    ):
        return client.handle_backchannel_logout(on_logout=on_logout, store=store)


def test_sid_logout_invalidates_matching_session():
    app, client_one, _ = create_clients()
    store = client_one.logout_store
    store.add_session("local-1", iss=ISSUER_ONE, sid="sid-1", sub="user-1")
    store.add_session("local-2", iss=ISSUER_ONE, sid="sid-2", sub="user-1")

    token = encode_token(
        KEY_ONE,
        logout_claims(ISSUER_ONE, "client-one", sid="sid-1", sub="user-1"),
    )
    calls = []
    resp = run_logout(
        app, client_one, token, on_logout=lambda ids, claims: calls.append(ids)
    )
    assert resp.status_code == 200
    assert resp.headers["Cache-Control"] == "no-cache, no-store"
    assert calls == [["local-1"]]
    assert set(store._sessions) == {"local-2"}


def test_same_sid_from_other_issuer_is_unaffected():
    store = InMemoryLogoutStore()
    app, client_one, _ = create_clients(shared_store=store)
    store.add_session("local-1", iss=ISSUER_ONE, sid="shared-sid", sub="user-1")
    store.add_session("local-2", iss=ISSUER_TWO, sid="shared-sid", sub="user-1")

    token = encode_token(
        KEY_ONE,
        logout_claims(ISSUER_ONE, "client-one", sid="shared-sid", sub="user-1"),
    )
    resp = run_logout(app, client_one, token)
    assert resp.status_code == 200
    assert set(store._sessions) == {"local-2"}


def test_sub_only_logout_ends_all_sessions_of_that_user():
    store = InMemoryLogoutStore()
    app, client_one, _ = create_clients(shared_store=store)
    store.add_session("local-1", iss=ISSUER_ONE, sid="sid-1", sub="user-1")
    store.add_session("local-2", iss=ISSUER_ONE, sid="sid-2", sub="user-1")
    store.add_session("local-3", iss=ISSUER_ONE, sid="sid-3", sub="user-2")
    store.add_session("local-4", iss=ISSUER_TWO, sid="sid-4", sub="user-1")

    token = encode_token(KEY_ONE, logout_claims(ISSUER_ONE, "client-one", sub="user-1"))
    calls = []
    resp = run_logout(
        app, client_one, token, on_logout=lambda ids, claims: calls.append(ids)
    )
    assert resp.status_code == 200
    assert sorted(calls[0]) == ["local-1", "local-2"]
    assert set(store._sessions) == {"local-3", "local-4"}


def test_sid_and_sub_must_belong_together():
    store = InMemoryLogoutStore()
    app, client_one, _ = create_clients(shared_store=store)
    store.add_session("local-1", iss=ISSUER_ONE, sid="sid-1", sub="user-1")
    store.add_session("local-2", iss=ISSUER_ONE, sid="sid-1", sub="user-2")

    token = encode_token(
        KEY_ONE,
        logout_claims(ISSUER_ONE, "client-one", sid="sid-1", sub="user-2"),
    )
    resp = run_logout(app, client_one, token)
    assert resp.status_code == 200
    assert set(store._sessions) == {"local-1"}


def test_replay_is_idempotent_and_new_session_survives():
    app, client_one, _ = create_clients()
    store = client_one.logout_store
    store.add_session("old-session", iss=ISSUER_ONE, sid="sid-old", sub="user-1")

    claims = logout_claims(ISSUER_ONE, "client-one", sid="sid-old", sub="user-1")
    token = encode_token(KEY_ONE, claims)

    calls = []
    resp = run_logout(
        app, client_one, token, on_logout=lambda ids, c: calls.append(ids)
    )
    assert resp.status_code == 200
    assert calls == [["old-session"]]
    assert not store._sessions

    # the user logs in again, creating a fresh session with a new sid
    store.add_session("new-session", iss=ISSUER_ONE, sid="sid-new", sub="user-1")

    # replaying the old notification must succeed idempotently without
    # touching the new session or invoking the callback again
    resp = run_logout(
        app, client_one, token, on_logout=lambda ids, c: calls.append(ids)
    )
    assert resp.status_code == 200
    assert calls == [["old-session"]]
    assert set(store._sessions) == {"new-session"}


def test_invalid_notifications_do_not_consume_jti_or_clear_sessions():
    app, client_one, _ = create_clients()
    store = client_one.logout_store
    store.add_session("local-1", iss=ISSUER_ONE, sid="sid-1", sub="user-1")

    claims = logout_claims(ISSUER_ONE, "client-one", sid="sid-1", sub="user-1")
    # same jti, but signed with the wrong key
    bad_token = jwt.encode({"alg": "HS256"}, claims, KEY_TWO)
    resp = run_logout(app, client_one, bad_token)
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "invalid_request"
    assert set(store._sessions) == {"local-1"}
    assert not store._jti_records

    # a valid notification with the same jti is still processed
    good_token = encode_token(KEY_ONE, claims)
    resp = run_logout(app, client_one, good_token)
    assert resp.status_code == 200
    assert not store._sessions


def test_missing_logout_token_parameter():
    app, client_one, _ = create_clients()
    with app.test_request_context("/backchannel-logout", method="POST"):
        resp = client_one.handle_backchannel_logout()
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "invalid_request"


def test_rejects_wrong_audience():
    app, client_one, _ = create_clients()
    token = encode_token(
        KEY_ONE,
        logout_claims(ISSUER_ONE, "another-client", sid="sid-1"),
    )
    resp = run_logout(app, client_one, token)
    assert resp.status_code == 400


def test_rejects_wrong_issuer():
    app, client_one, _ = create_clients()
    token = encode_token(
        KEY_ONE,
        logout_claims(ISSUER_TWO, "client-one", sid="sid-1"),
    )
    resp = run_logout(app, client_one, token)
    assert resp.status_code == 400


def test_rejects_disallowed_algorithm():
    app, client_one, _ = create_clients()
    big_key = jwk.import_key("secret-one" * 8, "oct")
    token = jwt.encode(
        {"alg": "HS512"},
        logout_claims(ISSUER_ONE, "client-one", sid="sid-1"),
        big_key,
        registry=JWSRegistry(algorithms=["HS512"]),
    )
    resp = run_logout(app, client_one, token)
    assert resp.status_code == 400


def test_rejects_missing_required_claims():
    app, client_one, _ = create_clients()
    base = logout_claims(ISSUER_ONE, "client-one", sid="sid-1")
    for missing in ("iss", "aud", "iat", "jti", "events"):
        claims = {k: v for k, v in base.items() if k != missing}
        resp = run_logout(app, client_one, encode_token(KEY_ONE, claims))
        assert resp.status_code == 400, missing


def test_rejects_bad_events_claim():
    app, client_one, _ = create_clients()
    claims = logout_claims(ISSUER_ONE, "client-one", sid="sid-1")
    claims["events"] = {"http://schemas.openid.net/event/some-other-event": {}}
    resp = run_logout(app, client_one, encode_token(KEY_ONE, claims))
    assert resp.status_code == 400

    claims["events"] = "not-an-object"
    resp = run_logout(app, client_one, encode_token(KEY_ONE, claims))
    assert resp.status_code == 400


def test_rejects_nonce_claim():
    app, client_one, _ = create_clients()
    claims = logout_claims(ISSUER_ONE, "client-one", sid="sid-1", nonce="abc")
    resp = run_logout(app, client_one, encode_token(KEY_ONE, claims))
    assert resp.status_code == 400


def test_rejects_token_without_sub_and_sid():
    app, client_one, _ = create_clients()
    claims = logout_claims(ISSUER_ONE, "client-one")
    resp = run_logout(app, client_one, encode_token(KEY_ONE, claims))
    assert resp.status_code == 400


def test_endpoint_needs_no_cookie_or_csrf_state():
    # the application has no secret key: any access to the browser session
    # cookie would fail, and no OAuth state data is involved either
    store = InMemoryLogoutStore()
    app, client_one, _ = create_clients(shared_store=store)
    assert app.secret_key is None
    store.add_session("local-1", iss=ISSUER_ONE, sid="sid-1", sub="user-1")

    token = encode_token(KEY_ONE, logout_claims(ISSUER_ONE, "client-one", sid="sid-1"))
    resp = run_logout(app, client_one, token)
    assert resp.status_code == 200
    assert not store._sessions
