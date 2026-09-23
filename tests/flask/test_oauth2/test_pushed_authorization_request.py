import json
import time

import pytest
from flask import json as flask_json

from authlib.common.urls import url_decode
from authlib.common.urls import urlparse
from authlib.oauth2.rfc6749.grants import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
)
from authlib.oauth2.rfc7636 import CodeChallenge
from authlib.oauth2.rfc7636.challenge import create_s256_code_challenge
from authlib.oauth2.rfc9126 import PushedAuthorizationRequest
from authlib.oauth2.rfc9126 import PushedAuthorizationRequestStore

from .models import Client
from .models import CodeGrantMixin
from .models import db
from .models import save_authorization_code
from .oauth2_server import create_basic_header


class PushedRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    request_uri = db.Column(db.String(255), unique=True, nullable=False)
    client_id = db.Column(db.String(48), nullable=False)
    data = db.Column(db.Text, nullable=False)
    expires_at = db.Column(db.Float, nullable=False)


class SQLAlchemyPushedAuthorizationRequestStore(PushedAuthorizationRequestStore):
    def get(self, request_uri):
        item = PushedRequest.query.filter_by(request_uri=request_uri).first()
        if item is None:
            return None
        return {
            "client_id": item.client_id,
            "data": json.loads(item.data),
            "expires_at": item.expires_at,
        }

    def save(self, request_uri, client_id, data, expires_in):
        item = PushedRequest(
            request_uri=request_uri,
            client_id=client_id,
            data=json.dumps(data),
            expires_at=time.time() + expires_in,
        )
        db.session.add(item)
        db.session.commit()

    def delete(self, request_uri):
        PushedRequest.query.filter_by(request_uri=request_uri).delete()
        db.session.commit()

    def consume(self, request_uri):
        rows = (
            PushedRequest.query.filter_by(request_uri=request_uri)
            .filter(PushedRequest.expires_at >= time.time())
            .delete()
        )
        db.session.commit()
        return rows > 0


class AuthorizationCodeGrant(CodeGrantMixin, _AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ["client_secret_basic", "client_secret_post", "none"]

    def save_authorization_code(self, code, request):
        return save_authorization_code(code, request)


@pytest.fixture(autouse=True)
def client(client, db):
    client.set_client_metadata(
        {
            "redirect_uris": ["https://client.test/authorized"],
            "scope": "profile",
            "token_endpoint_auth_method": "client_secret_basic",
            "response_types": ["code"],
            "grant_types": ["authorization_code"],
        }
    )
    db.session.add(client)
    db.session.commit()
    return client


@pytest.fixture
def public_client(db, user):
    client = Client(
        user_id=user.id,
        client_id="public-client-id",
        client_secret="",
    )
    client.set_client_metadata(
        {
            "redirect_uris": ["https://public.test/authorized"],
            "scope": "profile",
            "token_endpoint_auth_method": "none",
            "response_types": ["code"],
            "grant_types": ["authorization_code"],
        }
    )
    db.session.add(client)
    db.session.commit()
    yield client
    db.session.delete(client)


store = SQLAlchemyPushedAuthorizationRequestStore()


@pytest.fixture(autouse=True)
def server(server, app):
    server.register_grant(AuthorizationCodeGrant, [CodeChallenge(required=False)])
    server.register_endpoint(PushedAuthorizationRequest(store=store))

    @app.route("/oauth/par", methods=["POST"])
    def pushed_authorization_request():
        return server.create_endpoint_response("pushed_authorization_request")

    return server


def push(test_client, client_id="client-id", client_secret="client-secret", **params):
    data = {"response_type": "code", "client_id": client_id}
    data.update(params)
    headers = {}
    if client_secret:
        headers = create_basic_header(client_id, client_secret)
    return test_client.post("/oauth/par", data=data, headers=headers)


def authorize_url(client_id, request_uri, **extra):
    url = f"/oauth/authorize?client_id={client_id}&request_uri={request_uri}"
    for key, value in extra.items():
        url += f"&{key}={value}"
    return url


def test_push_success(test_client):
    rv = push(
        test_client,
        redirect_uri="https://client.test/authorized",
        scope="profile",
        state="xyz",
    )
    assert rv.status_code == 201
    resp = flask_json.loads(rv.data)
    # the response is a reference, it does not contain the request parameters
    assert set(resp.keys()) == {"request_uri", "expires_in"}
    assert resp["request_uri"].startswith("urn:ietf:params:oauth:request_uri:")
    assert resp["expires_in"] == 60

    item = PushedRequest.query.filter_by(request_uri=resp["request_uri"]).one()
    assert item.client_id == "client-id"
    data = json.loads(item.data)
    assert data["redirect_uri"] == "https://client.test/authorized"
    assert data["scope"] == "profile"
    assert data["state"] == "xyz"
    assert "client_secret" not in data


def test_push_unknown_client(test_client):
    rv = push(test_client, client_id="unknown", client_secret="unknown")
    assert rv.status_code == 401
    resp = flask_json.loads(rv.data)
    assert resp["error"] == "invalid_client"
    assert "Location" not in rv.headers


def test_push_confidential_client_without_credentials(test_client):
    rv = push(test_client, client_secret=None)
    assert rv.status_code == 401
    resp = flask_json.loads(rv.data)
    assert resp["error"] == "invalid_client"


def test_push_invalid_redirect_uri_does_not_redirect(test_client):
    rv = push(test_client, redirect_uri="https://evil.test/cb")
    assert rv.status_code == 400
    resp = flask_json.loads(rv.data)
    assert resp["error"] == "invalid_request"
    assert "Location" not in rv.headers


def test_push_with_request_uri_parameter_is_rejected(test_client):
    rv = push(test_client, request_uri="urn:ietf:params:oauth:request_uri:fake")
    assert rv.status_code == 400
    resp = flask_json.loads(rv.data)
    assert resp["error"] == "invalid_request"


def test_full_flow_with_consent_and_token(test_client):
    rv = push(
        test_client,
        redirect_uri="https://client.test/authorized",
        scope="profile",
        state="xyz",
    )
    request_uri = flask_json.loads(rv.data)["request_uri"]

    # showing the consent page does not consume the request
    url = authorize_url("client-id", request_uri)
    rv = test_client.get(url)
    assert rv.data == b"ok"
    rv = test_client.get(url)
    assert rv.data == b"ok"

    # submit the consent
    rv = test_client.post(url + "&user_id=1")
    assert rv.status_code == 302
    parsed = urlparse.urlparse(rv.location)
    assert f"{parsed.scheme}://{parsed.netloc}{parsed.path}" == (
        "https://client.test/authorized"
    )
    params = dict(url_decode(parsed.query))
    assert params["state"] == "xyz"
    code = params["code"]

    # exchange the code
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "https://client.test/authorized",
        },
        headers=create_basic_header("client-id", "client-secret"),
    )
    resp = flask_json.loads(rv.data)
    assert resp["token_type"] == "Bearer"
    assert resp["scope"] == "profile"
    assert "access_token" in resp


def test_browser_parameters_cannot_override_pushed_request(test_client):
    rv = push(
        test_client,
        redirect_uri="https://client.test/authorized",
        scope="profile",
        state="good-state",
    )
    request_uri = flask_json.loads(rv.data)["request_uri"]

    url = authorize_url(
        "client-id",
        request_uri,
        user_id=1,
        state="evil-state",
        scope="admin",
        redirect_uri="https://evil.test/cb",
        response_type="token",
    )
    rv = test_client.post(url)
    assert rv.status_code == 302
    parsed = urlparse.urlparse(rv.location)
    assert parsed.netloc == "client.test"
    params = dict(url_decode(parsed.query))
    assert params["state"] == "good-state"
    assert "code" in params

    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": params["code"],
            "redirect_uri": "https://client.test/authorized",
        },
        headers=create_basic_header("client-id", "client-secret"),
    )
    resp = flask_json.loads(rv.data)
    assert resp["scope"] == "profile"


def test_request_uri_is_bound_to_client(test_client, db, user):
    other = Client(
        user_id=user.id,
        client_id="other-client-id",
        client_secret="other-secret",
    )
    other.set_client_metadata(
        {
            "redirect_uris": ["https://other.test/authorized"],
            "scope": "profile",
            "token_endpoint_auth_method": "client_secret_basic",
            "response_types": ["code"],
            "grant_types": ["authorization_code"],
        }
    )
    db.session.add(other)
    db.session.commit()

    rv = push(test_client, redirect_uri="https://client.test/authorized")
    request_uri = flask_json.loads(rv.data)["request_uri"]

    rv = test_client.get(authorize_url("other-client-id", request_uri))
    assert rv.status_code == 400
    resp = flask_json.loads(rv.data)
    assert resp["error"] == "invalid_request"
    assert "Location" not in rv.headers


def test_request_uri_is_consumed_only_by_one_submitter(test_client):
    rv = push(
        test_client,
        redirect_uri="https://client.test/authorized",
        scope="profile",
    )
    request_uri = flask_json.loads(rv.data)["request_uri"]
    url = authorize_url("client-id", request_uri)

    # both submitters can display the consent page
    assert test_client.get(url).data == b"ok"
    assert test_client.get(url).data == b"ok"

    # the first submission gets the authorization response
    rv = test_client.post(url + "&user_id=1")
    assert rv.status_code == 302
    assert "code=" in rv.location

    # the second submission gets a deterministic error, no redirect
    rv = test_client.post(url + "&user_id=1")
    assert rv.status_code == 400
    resp = flask_json.loads(rv.data)
    assert resp["error"] == "invalid_request"
    assert "Location" not in rv.headers

    # the consent page is not available anymore either
    rv = test_client.get(url)
    assert rv.status_code == 400


def test_denied_consent_consumes_request(test_client):
    rv = push(
        test_client,
        redirect_uri="https://client.test/authorized",
        state="xyz",
    )
    request_uri = flask_json.loads(rv.data)["request_uri"]
    url = authorize_url("client-id", request_uri)

    # no user_id means the resource owner denies the request
    rv = test_client.post(url)
    assert rv.status_code == 302
    assert "error=access_denied" in rv.location
    assert "state=xyz" in rv.location
    assert rv.location.startswith("https://client.test/authorized")

    # the denied request cannot be used again
    rv = test_client.get(url)
    assert rv.status_code == 400
    resp = flask_json.loads(rv.data)
    assert resp["error"] == "invalid_request"


def test_expired_request_uri(test_client):
    rv = push(test_client, redirect_uri="https://client.test/authorized")
    request_uri = flask_json.loads(rv.data)["request_uri"]

    item = PushedRequest.query.filter_by(request_uri=request_uri).one()
    item.expires_at = time.time() - 1
    db.session.add(item)
    db.session.commit()

    rv = test_client.get(authorize_url("client-id", request_uri))
    assert rv.status_code == 400
    resp = flask_json.loads(rv.data)
    assert resp["error"] == "invalid_request"
    assert "Location" not in rv.headers

    # the expired record has been cleaned up
    assert PushedRequest.query.filter_by(request_uri=request_uri).first() is None


def test_public_client_flow_with_pkce(test_client, public_client):
    code_verifier = "a" * 48
    code_challenge = create_s256_code_challenge(code_verifier)

    rv = push(
        test_client,
        client_id="public-client-id",
        client_secret=None,
        redirect_uri="https://public.test/authorized",
        scope="profile",
        state="public-state",
        code_challenge=code_challenge,
        code_challenge_method="S256",
    )
    assert rv.status_code == 201
    request_uri = flask_json.loads(rv.data)["request_uri"]

    url = authorize_url("public-client-id", request_uri)
    assert test_client.get(url).data == b"ok"

    rv = test_client.post(url + "&user_id=1")
    assert rv.status_code == 302
    parsed = urlparse.urlparse(rv.location)
    params = dict(url_decode(parsed.query))
    assert params["state"] == "public-state"

    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "client_id": "public-client-id",
            "code": params["code"],
            "redirect_uri": "https://public.test/authorized",
            "code_verifier": code_verifier,
        },
    )
    resp = flask_json.loads(rv.data)
    assert "access_token" in resp
    assert resp["scope"] == "profile"
