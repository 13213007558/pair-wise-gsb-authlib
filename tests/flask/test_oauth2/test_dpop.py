import base64
import threading
import time

import pytest
from flask import json
from flask import jsonify
from flask import request
from joserfc import jwk
from joserfc import jwt
from sqlalchemy.exc import IntegrityError
from sqlalchemy.exc import OperationalError

from authlib.common.security import generate_token
from authlib.common.urls import url_decode
from authlib.common.urls import urlparse
from authlib.integrations.flask_oauth2 import AuthorizationServer
from authlib.integrations.flask_oauth2 import ResourceProtector
from authlib.integrations.sqla_oauth2 import create_query_client_func
from authlib.oauth2 import OAuth2Error
from authlib.oauth2.rfc6749.grants import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
)
from authlib.oauth2.rfc6749.grants import RefreshTokenGrant as _RefreshTokenGrant
from authlib.oauth2.rfc9449 import DPoPExtension
from authlib.oauth2.rfc9449 import DPoPStateStore
from authlib.oauth2.rfc9449 import DPoPTokenValidator
from authlib.oauth2.rfc9449 import compute_ath
from authlib.oauth2.rfc9449 import compute_jkt

from .models import Client
from .models import CodeGrantMixin
from .models import Token
from .models import User
from .models import db
from .models import save_authorization_code
from .oauth2_server import create_basic_header
from .oauth2_server import create_flask_app

TOKEN_HTU = "http://localhost/oauth/token"
RESOURCE_HTU = "http://localhost/api/user"


class DPoPReplay(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    jkt = db.Column(db.String(64), nullable=False)
    jti = db.Column(db.String(255), nullable=False)
    expires_at = db.Column(db.Integer, nullable=False)
    __table_args__ = (db.UniqueConstraint("jkt", "jti", name="uq_dpop_replay"),)


class SQLAlchemyDPoPStore(DPoPStateStore):
    """DB-backed DPoP state store. "register_jti" is atomic: it relies
    on a UNIQUE constraint, a replayed (jkt, jti) pair fails the INSERT.
    """

    def __init__(self, nonce=None):
        self._nonce = nonce

    def get_nonce(self):
        return self._nonce

    def register_jti(self, jkt, jti, expires_at):
        for _ in range(50):
            try:
                db.session.add(DPoPReplay(jkt=jkt, jti=jti, expires_at=expires_at))
                db.session.commit()
                return True
            except IntegrityError:
                db.session.rollback()
                return False
            except OperationalError:
                # shared-cache SQLite table lock contention, retry
                db.session.rollback()
                time.sleep(0.01)
        return False


class BarrierStore(SQLAlchemyDPoPStore):
    """A store that synchronizes concurrent "register_jti" calls to
    force a race between replayed proofs."""

    def __init__(self):
        super().__init__()
        self.barrier = None

    def register_jti(self, jkt, jti, expires_at):
        if self.barrier is not None:
            self.barrier.wait(timeout=10)
        return super().register_jti(jkt, jti, expires_at)


class AuthorizationCodeGrant(CodeGrantMixin, _AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ["client_secret_basic", "client_secret_post", "none"]

    def save_authorization_code(self, code, request):
        return save_authorization_code(code, request)


class RefreshTokenGrant(_RefreshTokenGrant):
    def authenticate_refresh_token(self, refresh_token):
        item = Token.query.filter_by(refresh_token=refresh_token).first()
        if item and item.is_refresh_token_active():
            return item

    def authenticate_user(self, credential):
        return db.session.get(User, credential.user_id)

    def revoke_old_credential(self, credential):
        now = int(time.time())
        credential.access_token_revoked_at = now
        credential.refresh_token_revoked_at = now
        db.session.add(credential)
        db.session.commit()


@pytest.fixture
def app(tmp_path):
    app = create_flask_app()
    # shared-cache in-memory database, so that concurrent requests in
    # threads each get their own connection to the same database
    app.config.update(
        {
            "SQLALCHEMY_DATABASE_URI": (
                f"sqlite:///file:dpop-{tmp_path.name}?mode=memory&cache=shared&uri=true"
            ),
            "OAUTH2_REFRESH_TOKEN_GENERATOR": True,
        }
    )
    with app.app_context():
        yield app


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


@pytest.fixture
def dpop(app):
    """Wire the DPoP authorization server and resource protector into
    the app, with the given state store and clock."""

    def factory(store=None, clock=None, required=False):
        query_client = create_query_client_func(db.session, Client)

        def save_token(token, request):
            jkt = token.pop("dpop_jkt", None)
            if request.user:
                user_id = request.user.get_user_id()
            else:
                user_id = None
            item = Token(
                client_id=request.client.client_id,
                user_id=user_id,
                dpop_jkt=jkt,
                **token,
            )
            db.session.add(item)
            db.session.commit()

        server = AuthorizationServer(app, query_client, save_token)

        @app.route("/oauth/authorize", methods=["GET", "POST"])
        def authorize():
            user_id = request.values.get("user_id")
            if user_id:
                end_user = db.session.get(User, int(user_id))
            else:
                end_user = None

            try:
                grant = server.get_consent_grant(end_user=end_user)
            except OAuth2Error as error:
                return server.handle_error_response(request, error)

            if request.method == "GET":
                return grant.prompt or "ok"

            return server.create_authorization_response(
                grant=grant, grant_user=end_user
            )

        @app.route("/oauth/token", methods=["POST"])
        def issue_token():
            return server.create_token_response()

        extension = DPoPExtension(store=store, clock=clock, required=required)
        server.register_grant(AuthorizationCodeGrant, [extension])
        server.register_grant(RefreshTokenGrant, [extension])

        require_oauth = ResourceProtector()

        class MyDPoPTokenValidator(DPoPTokenValidator):
            def authenticate_token(self, token_string):
                return Token.query.filter_by(access_token=token_string).first()

        require_oauth.register_token_validator(
            MyDPoPTokenValidator(store=store, clock=clock)
        )

        @app.route("/api/user")
        @require_oauth(["profile"])
        def api_user():
            return jsonify(username="foo")

        return server

    return factory


def generate_key():
    return jwk.generate_key("EC", "P-256")


def make_proof(key, htm, htu, jti=None, iat=None, nonce=None, ath=None,
               typ="dpop+jwt", alg="ES256", jwk_dict=None):
    claims = {
        "jti": jti or generate_token(8),
        "htm": htm,
        "htu": htu,
        "iat": int(time.time()) if iat is None else iat,
    }
    if nonce is not None:
        claims["nonce"] = nonce
    if ath is not None:
        claims["ath"] = ath
    if jwk_dict is None:
        jwk_dict = key.as_dict(private=False)
    header = {"typ": typ, "alg": alg, "jwk": jwk_dict}
    return jwt.encode(header, claims, key)


def compact_jwt(header, claims):
    def b64(data):
        raw = json.dumps(data).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    return f"{b64(header)}.{b64(claims)}.unsigned"


def authorize_code(test_client):
    rv = test_client.post(
        "/oauth/authorize?response_type=code&client_id=client-id"
        "&redirect_uri=https%3A%2F%2Fclient.test%2Fauthorized&scope=profile",
        data={"user_id": "1"},
    )
    assert "code=" in rv.location
    params = dict(url_decode(urlparse.urlparse(rv.location).query))
    return params["code"]


def token_request(test_client, code, proof=None):
    headers = create_basic_header("client-id", "client-secret")
    if proof is not None:
        headers["DPoP"] = proof
    return test_client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "https://client.test/authorized",
        },
        headers=headers,
    )


def get_token(test_client, key, proof=None, use_proof=True, **proof_kwargs):
    code = authorize_code(test_client)
    if use_proof and proof is None:
        htm = proof_kwargs.pop("htm", "POST")
        htu = proof_kwargs.pop("htu", TOKEN_HTU)
        proof = make_proof(key, htm, htu, **proof_kwargs)
    return token_request(test_client, code, proof)


def refresh_token_request(test_client, refresh_token, proof=None):
    headers = create_basic_header("client-id", "client-secret")
    if proof is not None:
        headers["DPoP"] = proof
    return test_client.post(
        "/oauth/token",
        data={"grant_type": "refresh_token", "refresh_token": refresh_token},
        headers=headers,
    )


def access_resource(test_client, key, access_token, proof=None, **proof_kwargs):
    if proof is None:
        htm = proof_kwargs.pop("htm", "GET")
        htu = proof_kwargs.pop("htu", RESOURCE_HTU)
        ath = proof_kwargs.pop("ath", compute_ath(access_token))
        proof = make_proof(key, htm, htu, ath=ath, **proof_kwargs)
    return test_client.get(
        "/api/user",
        headers={"Authorization": f"DPoP {access_token}", "DPoP": proof},
    )


def test_full_flow_issue_and_access(test_client, dpop):
    dpop(store=SQLAlchemyDPoPStore())
    key = generate_key()

    rv = get_token(test_client, key)
    assert rv.status_code == 200
    resp = json.loads(rv.data)
    assert resp["token_type"] == "DPoP"
    assert "dpop_jkt" not in resp
    assert "access_token" in resp
    assert "refresh_token" in resp

    # the access token is bound to the proof key (cnf.jkt)
    jkt = compute_jkt(key.as_dict(private=False))
    token = Token.query.filter_by(access_token=resp["access_token"]).one()
    assert token.dpop_jkt == jkt

    rv = access_resource(test_client, key, resp["access_token"])
    assert rv.status_code == 200
    assert json.loads(rv.data)["username"] == "foo"


def test_refresh_with_same_key(test_client, dpop):
    dpop(store=SQLAlchemyDPoPStore())
    key = generate_key()
    resp = json.loads(get_token(test_client, key).data)

    proof = make_proof(key, "POST", TOKEN_HTU)
    rv = refresh_token_request(test_client, resp["refresh_token"], proof)
    assert rv.status_code == 200

    resp = json.loads(rv.data)
    assert resp["token_type"] == "DPoP"
    token = Token.query.filter_by(access_token=resp["access_token"]).one()
    assert token.dpop_jkt == compute_jkt(key.as_dict(private=False))

    rv = access_resource(test_client, key, resp["access_token"])
    assert rv.status_code == 200


def test_refresh_with_another_key_rejected(test_client, dpop):
    dpop(store=SQLAlchemyDPoPStore())
    key1 = generate_key()
    key2 = generate_key()
    resp = json.loads(get_token(test_client, key1).data)

    # key rotation on refresh is not allowed
    proof = make_proof(key2, "POST", TOKEN_HTU)
    rv = refresh_token_request(test_client, resp["refresh_token"], proof)
    assert rv.status_code == 400
    assert json.loads(rv.data)["error"] == "invalid_grant"


def test_refresh_without_proof_rejected(test_client, dpop):
    dpop(store=SQLAlchemyDPoPStore())
    key = generate_key()
    resp = json.loads(get_token(test_client, key).data)

    # a DPoP bound refresh token always requires a proof
    rv = refresh_token_request(test_client, resp["refresh_token"])
    assert rv.status_code == 400
    assert json.loads(rv.data)["error"] == "invalid_dpop_proof"


def test_resource_proof_of_another_key_rejected(test_client, dpop):
    dpop(store=SQLAlchemyDPoPStore())
    key1 = generate_key()
    key2 = generate_key()
    resp = json.loads(get_token(test_client, key1).data)

    # the access token is correct, but the proof belongs to another key
    rv = access_resource(test_client, key2, resp["access_token"])
    assert rv.status_code == 401
    assert json.loads(rv.data)["error"] == "invalid_dpop_proof"
    assert rv.headers["WWW-Authenticate"].startswith("DPoP")


def test_sequential_replay_rejected(test_client, dpop):
    dpop(store=SQLAlchemyDPoPStore())
    key = generate_key()
    resp = json.loads(get_token(test_client, key).data)

    proof = make_proof(
        key, "GET", RESOURCE_HTU, ath=compute_ath(resp["access_token"])
    )
    rv = access_resource(test_client, key, resp["access_token"], proof=proof)
    assert rv.status_code == 200

    rv = access_resource(test_client, key, resp["access_token"], proof=proof)
    assert rv.status_code == 401
    assert json.loads(rv.data)["error"] == "invalid_dpop_proof"


def test_concurrent_replay(test_client, dpop, app):
    store = BarrierStore()
    dpop(store=store)
    key = generate_key()
    resp = json.loads(get_token(test_client, key).data)
    access_token = resp["access_token"]

    proof = make_proof(key, "GET", RESOURCE_HTU, ath=compute_ath(access_token))
    headers = {"Authorization": f"DPoP {access_token}", "DPoP": proof}

    # force both requests to register the same jti concurrently
    store.barrier = threading.Barrier(2)
    results = []

    def worker():
        client = app.test_client()
        rv = client.get("/api/user", headers=headers)
        results.append(rv.status_code)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    # the same proof may succeed at most once
    assert sorted(results) == [200, 401]


def test_resource_proof_reused_at_token_endpoint(test_client, dpop):
    dpop(store=SQLAlchemyDPoPStore())
    key = generate_key()
    code = authorize_code(test_client)

    # a proof created for the resource server must not be accepted
    # at the token endpoint
    proof = make_proof(key, "POST", RESOURCE_HTU, ath=compute_ath("at"))
    rv = token_request(test_client, code, proof)
    assert rv.status_code == 400
    assert json.loads(rv.data)["error"] == "invalid_dpop_proof"


def test_private_jwk_rejected(test_client, dpop):
    dpop(store=SQLAlchemyDPoPStore())
    key = generate_key()
    proof = make_proof(
        key, "POST", TOKEN_HTU, jwk_dict=key.as_dict(private=True)
    )
    rv = get_token(test_client, key, proof=proof)
    assert rv.status_code == 400
    assert json.loads(rv.data)["error"] == "invalid_dpop_proof"


def test_symmetric_alg_rejected(test_client, dpop):
    dpop(store=SQLAlchemyDPoPStore())
    oct_key = jwk.generate_key("oct", 32)
    proof = make_proof(oct_key, "POST", TOKEN_HTU, alg="HS256")
    rv = get_token(test_client, oct_key, proof=proof)
    assert rv.status_code == 400
    assert json.loads(rv.data)["error"] == "invalid_dpop_proof"


def test_none_alg_rejected(test_client, dpop):
    dpop(store=SQLAlchemyDPoPStore())
    key = generate_key()
    proof = compact_jwt(
        {"typ": "dpop+jwt", "alg": "none", "jwk": key.as_dict(private=False)},
        {"jti": "1", "htm": "POST", "htu": TOKEN_HTU, "iat": int(time.time())},
    )
    rv = get_token(test_client, key, proof=proof)
    assert rv.status_code == 400
    assert json.loads(rv.data)["error"] == "invalid_dpop_proof"


def test_invalid_typ_rejected(test_client, dpop):
    dpop(store=SQLAlchemyDPoPStore())
    key = generate_key()
    rv = get_token(test_client, key, typ="jwt")
    assert rv.status_code == 400
    assert json.loads(rv.data)["error"] == "invalid_dpop_proof"


def test_bad_signature_rejected(test_client, dpop):
    dpop(store=SQLAlchemyDPoPStore())
    key1 = generate_key()
    key2 = generate_key()
    # signed with key1, but the header carries the jwk of key2
    proof = jwt.encode(
        {"typ": "dpop+jwt", "alg": "ES256", "jwk": key2.as_dict(private=False)},
        {"jti": "1", "htm": "POST", "htu": TOKEN_HTU, "iat": int(time.time())},
        key1,
    )
    rv = get_token(test_client, key1, proof=proof)
    assert rv.status_code == 400
    assert json.loads(rv.data)["error"] == "invalid_dpop_proof"


def test_htm_mismatch_rejected(test_client, dpop):
    dpop(store=SQLAlchemyDPoPStore())
    key = generate_key()
    rv = get_token(test_client, key, htm="GET")
    assert rv.status_code == 400
    assert json.loads(rv.data)["error"] == "invalid_dpop_proof"


def test_htu_mismatch_rejected(test_client, dpop):
    dpop(store=SQLAlchemyDPoPStore())
    key = generate_key()
    resp = json.loads(get_token(test_client, key).data)

    # another path identifies another resource
    rv = access_resource(
        test_client, key, resp["access_token"], htu="http://localhost/api/other"
    )
    assert rv.status_code == 401
    assert json.loads(rv.data)["error"] == "invalid_dpop_proof"


def test_htu_with_query_rejected(test_client, dpop):
    dpop(store=SQLAlchemyDPoPStore())
    key = generate_key()
    resp = json.loads(get_token(test_client, key).data)

    rv = access_resource(
        test_client, key, resp["access_token"], htu=RESOURCE_HTU + "?foo=bar"
    )
    assert rv.status_code == 401
    assert json.loads(rv.data)["error"] == "invalid_dpop_proof"


def test_request_query_ignored_in_htu(test_client, dpop):
    dpop(store=SQLAlchemyDPoPStore())
    key = generate_key()
    resp = json.loads(get_token(test_client, key).data)

    # the query component of the request URI is not part of "htu"
    proof = make_proof(
        key, "GET", RESOURCE_HTU, ath=compute_ath(resp["access_token"])
    )
    rv = test_client.get(
        "/api/user?foo=bar",
        headers={"Authorization": f"DPoP {resp['access_token']}", "DPoP": proof},
    )
    assert rv.status_code == 200


def test_iat_window(test_client, dpop):
    def clock():
        return 1_000_000

    dpop(store=SQLAlchemyDPoPStore(), clock=clock)
    key = generate_key()

    rv = get_token(test_client, key, iat=1_000_000 - 1000)
    assert rv.status_code == 400
    assert json.loads(rv.data)["error"] == "invalid_dpop_proof"

    rv = get_token(test_client, key, iat=1_000_000 + 1000)
    assert rv.status_code == 400
    assert json.loads(rv.data)["error"] == "invalid_dpop_proof"

    rv = get_token(test_client, key, iat=1_000_000)
    assert rv.status_code == 200


def test_nonce_challenge_and_retry_at_resource(test_client, dpop):
    dpop(store=SQLAlchemyDPoPStore(nonce="nonce-1"))
    key = generate_key()
    resp = json.loads(get_token(test_client, key, nonce="nonce-1").data)
    access_token = resp["access_token"]

    rv = access_resource(test_client, key, access_token)
    assert rv.status_code == 401
    assert json.loads(rv.data)["error"] == "use_dpop_nonce"
    assert rv.headers["DPoP-Nonce"] == "nonce-1"

    # a legitimate retry uses a new proof with the server nonce
    rv = access_resource(test_client, key, access_token, nonce="nonce-1")
    assert rv.status_code == 200


def test_nonce_challenge_and_retry_at_token_endpoint(test_client, dpop):
    dpop(store=SQLAlchemyDPoPStore(nonce="nonce-1"))
    key = generate_key()

    rv = get_token(test_client, key)
    assert rv.status_code == 400
    assert json.loads(rv.data)["error"] == "use_dpop_nonce"
    assert rv.headers["DPoP-Nonce"] == "nonce-1"

    rv = get_token(test_client, key, nonce="nonce-1")
    assert rv.status_code == 200


def test_missing_proof_at_resource(test_client, dpop):
    dpop(store=SQLAlchemyDPoPStore())
    key = generate_key()
    resp = json.loads(get_token(test_client, key).data)

    rv = test_client.get(
        "/api/user",
        headers={"Authorization": f"DPoP {resp['access_token']}"},
    )
    assert rv.status_code == 401
    assert json.loads(rv.data)["error"] == "invalid_dpop_proof"


def test_missing_proof_at_token_endpoint_when_required(test_client, dpop):
    dpop(store=SQLAlchemyDPoPStore(), required=True)
    code = authorize_code(test_client)
    rv = token_request(test_client, code)
    assert rv.status_code == 400
    assert json.loads(rv.data)["error"] == "invalid_dpop_proof"


def test_wrong_ath_rejected(test_client, dpop):
    dpop(store=SQLAlchemyDPoPStore())
    key = generate_key()
    resp = json.loads(get_token(test_client, key).data)

    rv = access_resource(
        test_client, key, resp["access_token"], ath=compute_ath("another-token")
    )
    assert rv.status_code == 401
    assert json.loads(rv.data)["error"] == "invalid_dpop_proof"


def test_unbound_token_rejected_at_resource(test_client, dpop):
    dpop(store=SQLAlchemyDPoPStore())
    key = generate_key()

    # a token issued without DPoP proof is not DPoP bound
    rv = get_token(test_client, key, use_proof=False)
    assert rv.status_code == 200
    resp = json.loads(rv.data)
    assert resp["token_type"] == "Bearer"

    rv = access_resource(test_client, key, resp["access_token"])
    assert rv.status_code == 401
    assert json.loads(rv.data)["error"] == "invalid_token"
