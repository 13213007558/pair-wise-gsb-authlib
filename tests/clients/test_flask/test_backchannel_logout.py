import time

import pytest
from flask import Flask
from joserfc import jwt
from joserfc.jwk import RSAKey

from authlib.integrations.flask_client import OAuth
from authlib.oidc.backchannel import InvalidLogoutTokenError
from authlib.oidc.backchannel import LOGOUT_EVENT
from authlib.oidc.backchannel import InMemoryBackChannelLogoutStore


ISSUER_ONE = "https://op-one.example"
ISSUER_TWO = "https://op-two.example"
CLIENT_ID = "rp-client"


@pytest.fixture
def providers():
    return {
        ISSUER_ONE: RSAKey.generate_key(2048, {"kid": "op-one-key"}),
        ISSUER_TWO: RSAKey.generate_key(2048, {"kid": "op-two-key"}),
    }


@pytest.fixture
def app_factory(providers):
    def create_app(store=None, testing=True):
        app = Flask(__name__)
        app.testing = testing
        oauth = OAuth(app)
        store = store or InMemoryBackChannelLogoutStore()

        for issuer, key in providers.items():
            oauth.register(
                issuer,
                client_id=CLIENT_ID,
                backchannel_logout_store=store,
                issuer=issuer,
                jwks={"keys": [key.as_dict(private=False)]},
                id_token_signing_alg_values_supported=["RS256"],
            )

        @app.post("/backchannel/<path:issuer>")
        def backchannel(issuer):
            client = oauth.create_client(issuer)
            return client.handle_backchannel_logout()

        return app, store, oauth

    return create_app


def logout_token(
    key, issuer, jti, header_alg="RS256", header_typ="logout+jwt", **claims_overrides
):
    now = int(time.time())
    claims = {
        "iss": issuer,
        "aud": CLIENT_ID,
        "iat": now,
        "exp": now + 300,
        "jti": jti,
        "events": {LOGOUT_EVENT: {}},
    }
    claims.update(claims_overrides)
    header = {"alg": header_alg, "typ": header_typ, "kid": key.kid}
    return jwt.encode(header, claims, key, algorithms=[header_alg, "RS256"])


def test_backchannel_logout_scopes_sid_and_sub_without_cookies(
    app_factory, providers
):
    app, store, oauth = app_factory()
    client = app.test_client()

    store.add_session("one-device-1", ISSUER_ONE, CLIENT_ID, "alice", "sid-one-1")
    store.add_session("one-device-2", ISSUER_ONE, CLIENT_ID, "alice", "sid-one-2")
    store.add_session("two-device", ISSUER_TWO, CLIENT_ID, "alice", "sid-two")
    store.add_session("one-bob", ISSUER_ONE, CLIENT_ID, "bob", "sid-bob")
    store.add_session("one-carol", ISSUER_ONE, CLIENT_ID, "carol", "sid-carol")
    store.add_session(
        "already-inactive",
        ISSUER_ONE,
        CLIENT_ID,
        "alice",
        "sid-inactive",
        active=False,
    )

    sid_only = logout_token(
        providers[ISSUER_ONE],
        ISSUER_ONE,
        "sid-only-jti",
        sid="sid-carol",
    )
    rv = client.post(
        "/backchannel/https://op-one.example", data={"logout_token": sid_only}
    )
    assert rv.status_code == 200
    assert rv.headers["Cache-Control"] == "no-store"
    assert store.is_active("one-carol") is False
    assert store.is_active("one-device-1") is True

    token = logout_token(
        providers[ISSUER_ONE],
        ISSUER_ONE,
        "sid-jti",
        sid="sid-one-1",
        sub="alice",
    )
    with app.app_context():
        result = oauth.create_client(ISSUER_ONE).process_backchannel_logout(token)
    assert result.replayed is False

    rv = client.post(
        "/backchannel/https://op-one.example", data={"logout_token": token}
    )
    assert rv.status_code == 200
    with app.app_context():
        result = oauth.create_client(ISSUER_ONE).process_backchannel_logout(token)
    assert result.replayed is True

    assert store.is_active("one-device-1") is False
    assert store.is_active("one-device-2") is True
    assert store.is_active("two-device") is True

    mismatched = logout_token(
        providers[ISSUER_ONE],
        ISSUER_ONE,
        "mismatched-jti",
        sid="sid-bob",
        sub="alice",
    )
    rv = client.post(
        "/backchannel/https://op-one.example", data={"logout_token": mismatched}
    )
    assert rv.status_code == 400
    assert store.is_active("one-bob") is True

    subject_one = logout_token(
        providers[ISSUER_ONE],
        ISSUER_ONE,
        "subject-one-jti",
        sub="alice",
    )
    rv = client.post(
        "/backchannel/https://op-one.example",
        data={"logout_token": subject_one},
    )
    assert rv.status_code == 200
    assert store.is_active("one-device-2") is False
    assert store.is_active("two-device") is True
    assert store.is_active("one-bob") is True

    subject_two = logout_token(
        providers[ISSUER_TWO],
        ISSUER_TWO,
        "subject-two-jti",
        sub="alice",
    )
    rv = client.post(
        "/backchannel/https://op-two.example",
        data={"logout_token": subject_two},
    )
    assert rv.status_code == 200
    assert store.is_active("two-device") is False
    assert store.is_active("one-bob") is True

    same_jti_other_issuer = logout_token(
        providers[ISSUER_TWO],
        ISSUER_TWO,
        "sid-only-jti",
        sid="sid-two-replayed",
    )
    store.add_session(
        "two-replayed", ISSUER_TWO, CLIENT_ID, "zoe", "sid-two-replayed"
    )
    rv = client.post(
        "/backchannel/https://op-two.example",
        data={"logout_token": same_jti_other_issuer},
    )
    assert rv.status_code == 200
    assert store.is_active("two-replayed") is False

    inactive_again = logout_token(
        providers[ISSUER_ONE],
        ISSUER_ONE,
        "inactive-again-jti",
        sid="sid-inactive",
        sub="alice",
    )
    rv = client.post(
        "/backchannel/https://op-one.example",
        data={"logout_token": inactive_again},
    )
    assert rv.status_code == 200


@pytest.mark.parametrize(
    ("claim_name", "claim_value"),
    [
        ("nonce", "forbidden"),
        ("sid", ""),
        ("sub", ""),
        ("events", {LOGOUT_EVENT: {"extra": None}}),
        ("events", {}),
    ],
)
def test_rejects_invalid_logout_claims(
    app_factory, providers, claim_name, claim_value
):
    app, _, _ = app_factory()
    overrides = {"sub": "alice", claim_name: claim_value}
    token = logout_token(
        providers[ISSUER_ONE], ISSUER_ONE, f"invalid-{claim_name}", **overrides
    )
    rv = app.test_client().post(
        "/backchannel/https://op-one.example", data={"logout_token": token}
    )
    assert rv.status_code == 400


def test_requires_sid_or_sub(app_factory, providers):
    app, _, _ = app_factory()
    token = logout_token(
        providers[ISSUER_ONE], ISSUER_ONE, "missing-session-claim"
    )
    rv = app.test_client().post(
        "/backchannel/https://op-one.example", data={"logout_token": token}
    )
    assert rv.status_code == 400


def test_backchannel_logout_store_can_be_registered_directly(providers):
    app = Flask(__name__)
    oauth = OAuth(app)
    store = InMemoryBackChannelLogoutStore()
    client = oauth.register(
        "provider",
        client_id=CLIENT_ID,
        backchannel_logout_store=store,
        issuer=ISSUER_ONE,
        jwks={"keys": [providers[ISSUER_ONE].as_dict(private=False)]},
        id_token_signing_alg_values_supported=["RS256"],
    )
    assert client.backchannel_logout_store is store


def test_backchannel_logout_store_can_come_from_app_config(providers):
    app = Flask(__name__)
    store = InMemoryBackChannelLogoutStore()
    app.config["PROVIDER_BACKCHANNEL_LOGOUT_STORE"] = store
    app.config["PROVIDER_CLIENT_ID"] = CLIENT_ID
    app.config["PROVIDER_ISSUER"] = ISSUER_ONE
    app.config["PROVIDER_JWKS"] = {
        "keys": [providers[ISSUER_ONE].as_dict(private=False)]
    }
    oauth = OAuth(app)
    oauth.register("provider")
    assert oauth.provider.backchannel_logout_store is store


@pytest.mark.parametrize(
    "claims",
    [
        {"iss": "https://other-op.example", "sub": "alice"},
        {"aud": "other-client", "sub": "alice"},
        {"aud": [CLIENT_ID, "other-client"], "sub": "alice"},
        {"sub": "alice", "exp": int(time.time()) - 130},
        {"sub": "alice", "iat": int(time.time()) + 300},
        {"sub": "alice", "nbf": int(time.time()) + 300},
    ],
)
def test_rejects_invalid_issuer_audience_and_time(
    app_factory, providers, claims
):
    app, _, _ = app_factory()
    token = logout_token(
        providers[ISSUER_ONE], ISSUER_ONE, "claims-jti", **claims
    )
    rv = app.test_client().post(
        "/backchannel/https://op-one.example", data={"logout_token": token}
    )
    assert rv.status_code == 400


def test_rejects_bad_signature_and_alg_none(app_factory, providers):
    app, _, oauth = app_factory()
    wrong_key = RSAKey.generate_key(2048, {"kid": "wrong"})
    bad_signature = logout_token(
        wrong_key, ISSUER_ONE, "bad-signature", sub="alice"
    )
    rv = app.test_client().post(
        "/backchannel/https://op-one.example",
        data={"logout_token": bad_signature},
    )
    assert rv.status_code == 400

    now = int(time.time())
    unsigned = jwt.encode(
        {"alg": "none", "typ": "logout+jwt"},
        {
            "iss": ISSUER_ONE,
            "aud": CLIENT_ID,
            "iat": now,
            "exp": now + 300,
            "jti": "unsigned",
            "events": {LOGOUT_EVENT: {}},
            "sub": "alice",
        },
        None,
        algorithms=["none"],
    )
    with app.app_context():
        client = oauth.register(
            "none-client",
            client_id=CLIENT_ID,
            issuer=ISSUER_ONE,
            jwks={
                "keys": [providers[ISSUER_ONE].as_dict(private=False)]
            },
            id_token_signing_alg_values_supported=["RS256", "none"],
        )
        with pytest.raises(InvalidLogoutTokenError):
            client.process_backchannel_logout(
                unsigned, store=InMemoryBackChannelLogoutStore()
            )


def test_rejects_signing_alg_not_allowed_by_client(app_factory, providers):
    app, _, _ = app_factory()
    token = logout_token(
        providers[ISSUER_ONE],
        ISSUER_ONE,
        "wrong-alg",
        header_alg="PS256",
        sub="alice",
    )
    rv = app.test_client().post(
        "/backchannel/https://op-one.example", data={"logout_token": token}
    )
    assert rv.status_code == 400


def test_missing_logout_token_is_bad_request(app_factory):
    app, _, _ = app_factory()
    rv = app.test_client().post("/backchannel/https://op-one.example", data={})
    assert rv.status_code == 400
    assert rv.get_json()["error"] == "invalid_request"


def test_rejects_wrong_token_type(app_factory, providers):
    app, _, _ = app_factory()
    token = logout_token(
        providers[ISSUER_ONE],
        ISSUER_ONE,
        "wrong-typ",
        header_typ="JWT",
        sub="alice",
    )
    rv = app.test_client().post(
        "/backchannel/https://op-one.example", data={"logout_token": token}
    )
    assert rv.status_code == 400


def test_storage_failure_is_not_reported_as_success(app_factory, providers):
    class FailingStore(InMemoryBackChannelLogoutStore):
        def mark_logout_processed(self, issuer, client_id, jti):
            raise RuntimeError("session database unavailable")

    store = FailingStore()
    app, _, oauth = app_factory(store=store, testing=False)
    store.add_session("session", ISSUER_ONE, CLIENT_ID, "alice", "sid")
    token = logout_token(
        providers[ISSUER_ONE], ISSUER_ONE, "storage-failure", sid="sid"
    )

    with app.app_context():
        with pytest.raises(RuntimeError):
            oauth.create_client(ISSUER_ONE).process_backchannel_logout(token)

    rv = app.test_client().post(
        "/backchannel/https://op-one.example", data={"logout_token": token}
    )
    assert rv.status_code == 500
    assert store.is_logout_processed(ISSUER_ONE, CLIENT_ID, "storage-failure") is False


def test_revocation_failure_is_not_reported_as_success(app_factory, providers):
    class FailingStore(InMemoryBackChannelLogoutStore):
        def revoke_session(self, issuer, client_id, sid, sub=None):
            raise RuntimeError("session store unavailable")

    store = FailingStore()
    app, _, _ = app_factory(store=store, testing=False)
    token = logout_token(
        providers[ISSUER_ONE], ISSUER_ONE, "revocation-failure", sid="missing"
    )

    rv = app.test_client().post(
        "/backchannel/https://op-one.example", data={"logout_token": token}
    )
    assert rv.status_code == 500
    processed = store.is_logout_processed(
        ISSUER_ONE, CLIENT_ID, "revocation-failure"
    )
    assert processed is False
