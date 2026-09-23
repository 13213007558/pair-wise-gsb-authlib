import json
import re
import time
from contextlib import contextmanager
from unittest import mock
from urllib.parse import quote

import pytest
import requests
from flask import Flask
from joserfc import jwt
from joserfc.jwk import ECKey
from joserfc.jwk import KeySet
from joserfc.jwk import OctKey

from authlib.common.encoding import urlsafe_b64decode
from authlib.common.encoding import urlsafe_b64encode
from authlib.common.urls import urlparse
from authlib.integrations.flask_client import OAuth
from authlib.integrations.flask_client import OAuthError
from authlib.oauth2.jarm import JWTSecuredAuthorizationResponse
from authlib.oauth2.jarm import validate_jarm_response
from authlib.oauth2.jarm.response import _render_form_post
from authlib.oauth2.rfc6749.grants import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
)
from tests.util import read_file_path

from .models import Client
from .models import CodeGrantMixin
from .models import save_authorization_code

ISSUER = "https://as.test"
REDIRECT_URI = "https://client.test/authorized"
ESCAPED_REDIRECT_URI = "https://client.test/cb?x=1&y=2"
EC_KEY = ECKey.generate_key("P-256")


class AuthorizationCodeGrant(CodeGrantMixin, _AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ["client_secret_basic", "client_secret_post", "none"]

    def save_authorization_code(self, code, request):
        return save_authorization_code(code, request)


class JARM(JWTSecuredAuthorizationResponse):
    def get_issuer(self):
        return ISSUER

    def resolve_client_private_key(self, client):
        if client.client_id == "ec-client":
            return EC_KEY
        keys = KeySet.import_key_set(read_file_path("jwks_private.json"))
        return keys.get_by_kid("abc")


@pytest.fixture(autouse=True)
def server(server):
    server.register_grant(AuthorizationCodeGrant)
    server.register_extension(JARM())
    return server


@pytest.fixture(autouse=True)
def client(client, db):
    client.set_client_metadata(
        {
            "redirect_uris": [REDIRECT_URI, ESCAPED_REDIRECT_URI],
            "scope": "profile",
            "token_endpoint_auth_method": "client_secret_basic",
            "response_types": ["code"],
            "grant_types": ["authorization_code"],
            "authorization_signed_response_alg": "RS256",
        }
    )
    db.session.add(client)
    db.session.commit()
    return client


def create_rp_app():
    app = Flask(__name__)
    app.secret_key = "!"
    oauth = OAuth(app)
    rp = oauth.register(
        "dev",
        client_id="client-id",
        client_secret="client-secret",
        authorize_url=ISSUER + "/oauth/authorize",
        access_token_url=ISSUER + "/oauth/token",
        issuer=ISSUER,
        jwks=read_file_path("jwks_public.json"),
        authorization_signing_alg_values_supported=["RS256"],
    )

    @app.route("/login")
    def login():
        return rp.authorize_redirect(REDIRECT_URI, response_mode="query.jwt")

    @app.route("/login_form_post")
    def login_form_post():
        return rp.authorize_redirect(REDIRECT_URI, response_mode="form_post.jwt")

    @app.route("/authorized", methods=["GET", "POST"])
    def authorized():
        try:
            return rp.authorize_access_token()
        except OAuthError as exc:
            return {"error": exc.error, "description": exc.description}, 400

    return app


def forward_to_token_endpoint(as_client):
    """Forward the token request from the RP to the AS Flask app."""

    def fake_send(request, **kwargs):
        headers = {}
        if "Authorization" in request.headers:
            headers["Authorization"] = request.headers["Authorization"]
        rv = as_client.post(
            "/oauth/token",
            data=request.body,
            headers=headers,
            content_type="application/x-www-form-urlencoded",
        )
        resp = mock.MagicMock(spec=requests.Response)
        resp.cookies = []
        resp.status_code = rv.status_code
        resp.text = rv.get_data(as_text=True)
        resp.json = lambda: json.loads(resp.text)
        return resp

    return fake_send


@contextmanager
def mock_token_endpoint(as_client):
    with mock.patch("requests.sessions.Session.send") as send:
        send.side_effect = forward_to_token_endpoint(as_client)
        yield


def run_authorize_flow(as_client, rp_client, login_path="/login", user_id="1"):
    """Drive the RP login redirect and the AS consent, return the AS
    authorization response."""
    rv = rp_client.get(login_path)
    assert rv.status_code == 302
    parts = urlparse.urlparse(rv.headers["Location"])
    target = parts.path + "?" + parts.query
    rv = as_client.get(target)
    assert rv.text == "ok"
    data = {"user_id": user_id} if user_id else {}
    return as_client.post(target, data=data)


def get_valid_jarm_response(as_client, rp_client):
    """Run a successful authorize flow, return (response_jwt, state)."""
    rv = rp_client.get("/login")
    parts = urlparse.urlparse(rv.headers["Location"])
    query = dict(urlparse.parse_qsl(parts.query))
    target = parts.path + "?" + parts.query
    rv = as_client.post(target, data={"user_id": "1"})
    location = urlparse.urlparse(rv.headers["Location"])
    response_jwt = dict(urlparse.parse_qsl(location.query))["response"]
    return response_jwt, query["state"]


def test_jarm_query_response_claims(test_client, client):
    url = (
        "/oauth/authorize?response_type=code&client_id=client-id"
        "&state=bar&response_mode=query.jwt"
    )
    rv = test_client.post(url, data={"user_id": "1"})
    assert rv.status_code == 302
    location = rv.headers["Location"]
    # code and state are only available inside the signed JWT
    assert "code=" not in location
    assert "state=" not in location

    query = dict(urlparse.parse_qsl(urlparse.urlparse(location).query))
    assert list(query) == ["response"]
    claims = validate_jarm_response(
        query["response"],
        key=KeySet.import_key_set(read_file_path("jwks_public.json")),
        issuer=ISSUER,
        audience="client-id",
    )
    assert claims["iss"] == ISSUER
    assert claims["aud"] == "client-id"
    assert claims["exp"] > time.time()
    assert claims["state"] == "bar"
    assert "code" in claims


def test_jarm_error_response_claims(test_client, client):
    url = (
        "/oauth/authorize?response_type=code&client_id=client-id"
        "&state=bar&response_mode=query.jwt"
    )
    # the resource owner denies the request
    rv = test_client.post(url)
    assert rv.status_code == 302
    location = rv.headers["Location"]
    assert "error=" not in location

    query = dict(urlparse.parse_qsl(urlparse.urlparse(location).query))
    assert list(query) == ["response"]
    claims = validate_jarm_response(
        query["response"],
        key=KeySet.import_key_set(read_file_path("jwks_public.json")),
        issuer=ISSUER,
        audience="client-id",
    )
    assert claims["error"] == "access_denied"
    assert claims["state"] == "bar"
    assert "code" not in claims


def test_jarm_form_post_response(test_client, client):
    redirect_uri = quote(ESCAPED_REDIRECT_URI, safe="")
    url = (
        "/oauth/authorize?response_type=code&client_id=client-id"
        f"&state=bar&response_mode=form_post.jwt&redirect_uri={redirect_uri}"
    )
    rv = test_client.post(url, data={"user_id": "1"})
    assert rv.status_code == 200
    assert rv.content_type == "text/html; charset=utf-8"
    body = rv.get_data(as_text=True)
    # the action URL is escaped for the HTML context
    assert 'action="https://client.test/cb?x=1&amp;y=2"' in body
    assert f'action="{ESCAPED_REDIRECT_URI}"' not in body
    response_jwt = re.search(r'name="response" value="([^"]+)"', body).group(1)
    claims = validate_jarm_response(
        response_jwt,
        key=KeySet.import_key_set(read_file_path("jwks_public.json")),
        issuer=ISSUER,
        audience="client-id",
    )
    assert claims["state"] == "bar"
    assert "code" in claims


def test_jarm_form_post_html_escaping():
    body = _render_form_post('https://client.test/cb?a=1&b="2"', "jwt<value>")
    assert 'action="https://client.test/cb?a=1&amp;b=&quot;2&quot;"' in body
    assert 'value="jwt&lt;value&gt;"' in body


def test_jarm_unvalidated_redirect_uri_not_redirected(test_client, client):
    url = (
        "/oauth/authorize?response_type=code&client_id=client-id"
        "&response_mode=query.jwt&redirect_uri=https%3A%2F%2Fevil.test%2Fcb"
    )
    rv = test_client.post(url, data={"user_id": "1"})
    assert rv.status_code == 400
    assert "Location" not in rv.headers
    assert rv.get_json()["error"] == "invalid_request"


def test_jarm_signing_alg_from_client_metadata(test_client, db, user):
    ec_client = Client(
        user_id=user.id,
        client_id="ec-client",
        client_secret="ec-secret",
    )
    ec_client.set_client_metadata(
        {
            "redirect_uris": [REDIRECT_URI],
            "scope": "profile",
            "response_types": ["code"],
            "grant_types": ["authorization_code"],
            "authorization_signed_response_alg": "ES256",
        }
    )
    db.session.add(ec_client)
    db.session.commit()

    url = "/oauth/authorize?response_type=code&client_id=ec-client&response_mode=query.jwt"
    rv = test_client.post(url, data={"user_id": "1"})
    query = dict(urlparse.parse_qsl(urlparse.urlparse(rv.headers["Location"]).query))
    header = json.loads(urlsafe_b64decode(query["response"].split(".")[0].encode()))
    assert header["alg"] == "ES256"
    claims = validate_jarm_response(
        query["response"],
        key=EC_KEY,
        issuer=ISSUER,
        audience="ec-client",
        algorithms=["ES256"],
    )
    assert "code" in claims


def test_plain_query_response_mode_unchanged(test_client, client):
    url = "/oauth/authorize?response_type=code&client_id=client-id&state=bar"
    rv = test_client.post(url, data={"user_id": "1"})
    assert rv.status_code == 302
    location = rv.headers["Location"]
    assert "code=" in location
    assert "state=bar" in location
    assert "response=" not in location


def test_jarm_query_round_trip(test_client, client):
    rp_client = create_rp_app().test_client()
    with mock_token_endpoint(test_client):
        rv = run_authorize_flow(test_client, rp_client)
        assert rv.status_code == 302
        location = rv.headers["Location"]
        assert location.startswith(REDIRECT_URI + "?response=")
        assert "code=" not in location
        assert "state=" not in location

        callback = urlparse.urlparse(location)
        rv = rp_client.get(callback.path + "?" + callback.query)
        assert rv.status_code == 200
        data = rv.get_json()
        assert data["access_token"]
        assert data["token_type"] == "Bearer"


def test_jarm_query_round_trip_denied(test_client, client):
    rp_client = create_rp_app().test_client()
    rv = run_authorize_flow(test_client, rp_client, user_id=None)
    assert rv.status_code == 302
    location = rv.headers["Location"]
    assert location.startswith(REDIRECT_URI + "?response=")
    assert "error=" not in location

    callback = urlparse.urlparse(location)
    rv = rp_client.get(callback.path + "?" + callback.query)
    assert rv.status_code == 400
    assert rv.get_json()["error"] == "access_denied"


def test_jarm_form_post_round_trip(test_client, client):
    rp_client = create_rp_app().test_client()
    with mock_token_endpoint(test_client):
        rv = run_authorize_flow(test_client, rp_client, "/login_form_post")
        assert rv.status_code == 200
        body = rv.get_data(as_text=True)
        assert f'action="{REDIRECT_URI}"' in body
        response_jwt = re.search(r'name="response" value="([^"]+)"', body).group(1)

        rv = rp_client.post("/authorized", data={"response": response_jwt})
        assert rv.status_code == 200
        assert rv.get_json()["access_token"]


def test_jarm_form_post_round_trip_denied(test_client, client):
    rp_client = create_rp_app().test_client()
    rv = run_authorize_flow(test_client, rp_client, "/login_form_post", user_id=None)
    assert rv.status_code == 200
    body = rv.get_data(as_text=True)
    response_jwt = re.search(r'name="response" value="([^"]+)"', body).group(1)

    rv = rp_client.post("/authorized", data={"response": response_jwt})
    assert rv.status_code == 400
    assert rv.get_json()["error"] == "access_denied"


def test_rp_rejects_tampered_payload(test_client, client):
    rp_client = create_rp_app().test_client()
    with mock_token_endpoint(test_client):
        response_jwt, state = get_valid_jarm_response(test_client, rp_client)
        header, payload, signature = response_jwt.split(".")
        claims = json.loads(urlsafe_b64decode(payload.encode()))
        claims["code"] = "tampered-code"
        tampered_payload = (
            urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
        )
        forged = f"{header}.{tampered_payload}.{signature}"

        rv = rp_client.get(f"/authorized?response={forged}")
        assert rv.status_code == 400
        assert rv.get_json()["error"] == "invalid_jarm_response"
        # the failed verification must not consume the valid state
        with rp_client.session_transaction() as sess:
            assert f"_state_dev_{state}" in sess

        # the legitimate response is still accepted afterwards
        rv = rp_client.get(f"/authorized?response={response_jwt}")
        assert rv.status_code == 200
        assert rv.get_json()["access_token"]


def test_rp_rejects_response_for_other_client(test_client, client):
    rp_client = create_rp_app().test_client()
    response_jwt, state = get_valid_jarm_response(test_client, rp_client)
    key = KeySet.import_key_set(read_file_path("jwks_private.json")).get_by_kid("abc")
    forged = jwt.encode(
        {"alg": "RS256", "kid": "abc"},
        {
            "iss": ISSUER,
            "aud": "other-client",
            "exp": int(time.time()) + 600,
            "state": state,
            "code": "forged-code",
        },
        key,
        ["RS256"],
    )
    rv = rp_client.get(f"/authorized?response={forged}")
    assert rv.status_code == 400
    assert rv.get_json()["error"] == "invalid_jarm_response"
    with rp_client.session_transaction() as sess:
        assert f"_state_dev_{state}" in sess


def test_rp_rejects_unexpected_signing_alg(test_client, client):
    rp_client = create_rp_app().test_client()
    response_jwt, state = get_valid_jarm_response(test_client, rp_client)
    forged = jwt.encode(
        {"alg": "HS256"},
        {
            "iss": ISSUER,
            "aud": "client-id",
            "exp": int(time.time()) + 600,
            "state": state,
            "code": "forged-code",
        },
        OctKey.import_key("symmetric-secret"),
        ["HS256"],
    )
    rv = rp_client.get(f"/authorized?response={forged}")
    assert rv.status_code == 400
    assert rv.get_json()["error"] == "invalid_jarm_response"
    with rp_client.session_transaction() as sess:
        assert f"_state_dev_{state}" in sess


def test_rp_rejects_plaintext_code_next_to_jarm(test_client, client):
    rp_client = create_rp_app().test_client()
    response_jwt, state = get_valid_jarm_response(test_client, rp_client)
    rv = rp_client.get(f"/authorized?response={response_jwt}&code=injected-code")
    assert rv.status_code == 400
    assert rv.get_json()["error"] == "invalid_response"
    # the state is not consumed by the rejected response
    with rp_client.session_transaction() as sess:
        assert f"_state_dev_{state}" in sess
