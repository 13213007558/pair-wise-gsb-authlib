import time

import pytest
from flask import json
from flask import jsonify
from sqlalchemy import update

from authlib.common.urls import url_decode
from authlib.common.urls import urlparse
from authlib.oauth2.rfc6749.grants import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
)
from authlib.oauth2.rfc7636 import CodeChallenge
from authlib.oauth2.rfc7636 import create_s256_code_challenge
from authlib.oauth2.rfc8414 import AuthorizationServerMetadata
from authlib.oauth2.rfc9126 import PushedAuthorizationRequest
from authlib.oauth2.rfc9126 import PushedAuthorizationRequestEndpoint
from authlib.oauth2.rfc9126 import PushedAuthorizationRequestStore

from .models import Client
from .models import CodeGrantMixin
from .models import db
from .models import save_authorization_code
from .oauth2_server import create_basic_header

CODE_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"


class PushedRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    request_uri = db.Column(db.String(255), unique=True, nullable=False)
    client_id = db.Column(db.String(48), nullable=False)
    data = db.Column(db.JSON, nullable=False)
    expires_at = db.Column(db.Float, nullable=False)
    state = db.Column(db.String(20), nullable=False, default="pending")


class SQLAlchemyPushedRequestStore(PushedAuthorizationRequestStore):
    """PAR store backed by the local SQLite database."""

    def save(self, request):
        item = PushedRequest(
            request_uri=request.request_uri,
            client_id=request.client_id,
            data=request.data,
            expires_at=request.expires_at,
            state=request.state,
        )
        db.session.add(item)
        db.session.commit()

    def get(self, request_uri):
        item = PushedRequest.query.filter_by(request_uri=request_uri).first()
        if item is None:
            return None
        return PushedAuthorizationRequest(
            request_uri=item.request_uri,
            client_id=item.client_id,
            data=item.data,
            expires_at=item.expires_at,
            state=item.state,
        )

    def consume(self, request_uri, client_id):
        # a single atomic UPDATE: only the first redemption of a pending,
        # unexpired request can succeed
        result = db.session.execute(
            update(PushedRequest)
            .where(
                PushedRequest.request_uri == request_uri,
                PushedRequest.client_id == client_id,
                PushedRequest.state == PushedAuthorizationRequest.STATE_PENDING,
                PushedRequest.expires_at > time.time(),
            )
            .values(state=PushedAuthorizationRequest.STATE_CONSUMED)
        )
        db.session.commit()
        if result.rowcount != 1:
            return None
        return self.get(request_uri)

    def deny(self, request_uri, client_id):
        result = db.session.execute(
            update(PushedRequest)
            .where(
                PushedRequest.request_uri == request_uri,
                PushedRequest.client_id == client_id,
                PushedRequest.state == PushedAuthorizationRequest.STATE_PENDING,
            )
            .values(state=PushedAuthorizationRequest.STATE_DENIED)
        )
        db.session.commit()
        if result.rowcount != 1:
            return None
        return self.get(request_uri)


class AuthorizationCodeGrant(CodeGrantMixin, _AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ["client_secret_basic", "client_secret_post", "none"]

    def save_authorization_code(self, code, request):
        return save_authorization_code(code, request)


@pytest.fixture(autouse=True)
def server(server, app):
    store = SQLAlchemyPushedRequestStore()
    server.register_endpoint(PushedAuthorizationRequestEndpoint(store=store))
    server.register_grant(AuthorizationCodeGrant, [CodeChallenge(required=True)])

    @app.route("/oauth/par", methods=["POST"])
    def pushed_authorization_request():
        return server.create_endpoint_response("pushed_authorization_request")

    @app.route("/.well-known/oauth-authorization-server")
    def well_known():
        metadata = AuthorizationServerMetadata(
            {
                "issuer": "https://as.test",
                "authorization_endpoint": "https://as.test/oauth/authorize",
                "token_endpoint": "https://as.test/oauth/token",
                "response_types_supported": ["code"],
                "pushed_authorization_request_endpoint": "https://as.test/oauth/par",
                "require_pushed_authorization_requests": True,
            }
        )
        metadata.validate()
        return jsonify(dict(metadata))

    return server


@pytest.fixture(autouse=True)
def client(client, db):
    client.set_client_metadata(
        {
            "redirect_uris": ["https://client.test/authorized"],
            "scope": "profile address",
            "token_endpoint_auth_method": "client_secret_basic",
            "response_types": ["code"],
            "grant_types": ["authorization_code"],
        }
    )
    db.session.add(client)
    db.session.commit()
    return client


@pytest.fixture
def other_client(db, user):
    client = Client(
        user_id=user.id,
        client_id="other-client",
        client_secret="other-secret",
    )
    client.set_client_metadata(
        {
            "redirect_uris": ["https://other.test/authorized"],
            "scope": "profile",
            "token_endpoint_auth_method": "client_secret_basic",
            "response_types": ["code"],
            "grant_types": ["authorization_code"],
        }
    )
    db.session.add(client)
    db.session.commit()
    yield client
    db.session.delete(client)


def push_request(test_client, client_id="client-id", secret="client-secret", **params):
    data = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": "https://client.test/authorized",
        "scope": "profile",
        "state": "xyz",
        "code_challenge": create_s256_code_challenge(CODE_VERIFIER),
        "code_challenge_method": "S256",
    }
    data.update(params)
    headers = {}
    if secret is not None:
        headers = create_basic_header(client_id, secret)
    return test_client.post("/oauth/par", data=data, headers=headers)


def authorize_url(request_uri, client_id="client-id"):
    return f"/oauth/authorize?client_id={client_id}&request_uri={request_uri}"


def exchange_code(test_client, code, client_id="client-id", secret="client-secret"):
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": "https://client.test/authorized",
        "code_verifier": CODE_VERIFIER,
    }
    headers = {}
    if secret is not None:
        headers = create_basic_header(client_id, secret)
    else:
        data["client_id"] = client_id
    return test_client.post("/oauth/token", data=data, headers=headers)


def test_full_flow_with_sqlite_store(test_client, db):
    rv = push_request(test_client)
    assert rv.status_code == 201
    resp = json.loads(rv.data)
    request_uri = resp["request_uri"]

    # the reference is opaque, time limited and carries no plain text
    assert request_uri.startswith("urn:ietf:params:oauth:request_uri:")
    assert resp["expires_in"] == 90
    assert "xyz" not in request_uri
    assert b"client-secret" not in rv.data

    item = PushedRequest.query.filter_by(request_uri=request_uri).one()
    assert item.state == "pending"
    assert "client_secret" not in item.data

    # displaying the consent page does not consume the request
    url = authorize_url(request_uri)
    assert test_client.get(url).data == b"ok"
    assert test_client.get(url).data == b"ok"
    assert db.session.get(PushedRequest, item.id).state == "pending"

    # extra parameters sent by the browser cannot override the pushed ones
    rv = test_client.post(
        url + "&user_id=1&state=evil&scope=address&redirect_uri=https://evil.test/cb"
    )
    assert rv.status_code == 302
    location = urlparse.urlparse(rv.location)
    assert f"{location.scheme}://{location.netloc}{location.path}" == (
        "https://client.test/authorized"
    )
    query = dict(url_decode(location.query))
    assert query["state"] == "xyz"

    # the code is exchanged with the PKCE verifier pushed by the client
    rv = exchange_code(test_client, query["code"])
    assert rv.status_code == 200
    resp = json.loads(rv.data)
    assert "access_token" in resp
    assert resp["scope"] == "profile"


def test_request_uri_single_use_with_two_submitters(test_client):
    rv = push_request(test_client)
    request_uri = json.loads(rv.data)["request_uri"]
    url = authorize_url(request_uri)
    assert test_client.get(url).data == b"ok"

    # the first submitter redeems the pushed request
    rv = test_client.post(url + "&user_id=1")
    assert rv.status_code == 302
    assert "code=" in rv.location

    # the second submitter deterministically fails
    rv = test_client.post(url + "&user_id=1")
    assert rv.status_code == 400
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_request"

    # and the request_uri cannot be displayed again either
    rv = test_client.get(url)
    assert rv.status_code == 400
    assert json.loads(rv.data)["error"] == "invalid_request"


def test_store_consume_is_atomic(db):
    store = SQLAlchemyPushedRequestStore()
    request = PushedAuthorizationRequest(
        request_uri="urn:ietf:params:oauth:request_uri:atomic",
        client_id="client-id",
        data={},
        expires_at=time.time() + 60,
    )
    store.save(request)
    assert store.consume(request.request_uri, "client-id") is not None
    assert store.consume(request.request_uri, "client-id") is None


def test_denied_authorization_has_final_state(test_client):
    rv = push_request(test_client)
    request_uri = json.loads(rv.data)["request_uri"]
    url = authorize_url(request_uri)

    # the resource owner denies the request; the pushed state is used in
    # the error redirect, not the one sent by the browser
    rv = test_client.post(url + "&state=evil")
    assert rv.status_code == 302
    location = urlparse.urlparse(rv.location)
    query = dict(url_decode(location.query))
    assert query["error"] == "access_denied"
    assert query["state"] == "xyz"

    # a denied request is in a final state and cannot be used anymore
    rv = test_client.get(url)
    assert rv.status_code == 400
    assert json.loads(rv.data)["error"] == "invalid_request"

    rv = test_client.post(url + "&user_id=1")
    assert rv.status_code == 400
    assert json.loads(rv.data)["error"] == "invalid_request"


def test_expired_request_uri(test_client, db):
    rv = push_request(test_client)
    request_uri = json.loads(rv.data)["request_uri"]

    item = PushedRequest.query.filter_by(request_uri=request_uri).one()
    item.expires_at = time.time() - 1
    db.session.commit()

    rv = test_client.get(authorize_url(request_uri))
    assert rv.status_code == 400
    assert json.loads(rv.data)["error"] == "invalid_request"


def test_request_uri_bound_to_original_client(test_client, other_client):
    rv = push_request(test_client)
    request_uri = json.loads(rv.data)["request_uri"]

    # another client cannot use the request_uri
    rv = test_client.get(authorize_url(request_uri, client_id="other-client"))
    assert rv.status_code == 400
    assert json.loads(rv.data)["error"] == "invalid_request"

    # the failed attempt did not consume the request: the original client
    # can still use it
    rv = test_client.get(authorize_url(request_uri))
    assert rv.data == b"ok"


def test_par_client_id_must_match_authenticated_client(test_client, other_client):
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(
        "/oauth/par",
        data={
            "response_type": "code",
            "client_id": "other-client",
            "redirect_uri": "https://other.test/authorized",
        },
        headers=headers,
    )
    assert rv.status_code == 400
    assert json.loads(rv.data)["error"] == "invalid_request"


def test_par_invalid_redirect_uri_does_not_redirect(test_client):
    rv = push_request(test_client, redirect_uri="https://evil.test/cb")
    assert rv.status_code == 400
    assert "Location" not in rv.headers
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_request"


def test_par_invalid_scope_does_not_redirect(test_client, server):
    server.scopes_supported = ["profile", "address"]
    rv = push_request(test_client, scope="invalid")
    assert rv.status_code == 400
    assert "Location" not in rv.headers
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_scope"


def test_par_unsupported_response_type_does_not_redirect(test_client):
    rv = push_request(test_client, response_type="token")
    assert rv.status_code == 400
    assert "Location" not in rv.headers
    resp = json.loads(rv.data)
    assert resp["error"] == "unsupported_response_type"


def test_confidential_client_must_authenticate(test_client):
    # no credentials at all
    rv = push_request(test_client, secret=None)
    assert rv.status_code == 401
    assert json.loads(rv.data)["error"] == "invalid_client"

    # wrong secret
    rv = push_request(test_client, secret="wrong-secret")
    assert rv.status_code == 401
    assert json.loads(rv.data)["error"] == "invalid_client"


def test_public_client_uses_registered_none_auth_method(test_client, db, user):
    client = Client(user_id=user.id, client_id="public-client", client_secret="")
    client.set_client_metadata(
        {
            "redirect_uris": ["https://public.test/cb"],
            "scope": "profile",
            "token_endpoint_auth_method": "none",
            "response_types": ["code"],
            "grant_types": ["authorization_code"],
        }
    )
    db.session.add(client)
    db.session.commit()

    rv = push_request(
        test_client,
        client_id="public-client",
        secret=None,
        redirect_uri="https://public.test/cb",
    )
    assert rv.status_code == 201
    request_uri = json.loads(rv.data)["request_uri"]

    url = authorize_url(request_uri, client_id="public-client")
    assert test_client.get(url).data == b"ok"

    rv = test_client.post(url + "&user_id=1")
    assert rv.status_code == 302
    location = urlparse.urlparse(rv.location)
    query = dict(url_decode(location.query))
    assert query["state"] == "xyz"

    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": query["code"],
            "redirect_uri": "https://public.test/cb",
            "client_id": "public-client",
            "code_verifier": CODE_VERIFIER,
        },
    )
    assert rv.status_code == 200
    assert "access_token" in json.loads(rv.data)


def test_client_secret_post_and_secret_not_stored(test_client, client, db):
    client.set_client_metadata(
        {
            "redirect_uris": ["https://client.test/authorized"],
            "scope": "profile",
            "token_endpoint_auth_method": "client_secret_post",
            "response_types": ["code"],
            "grant_types": ["authorization_code"],
        }
    )
    db.session.add(client)
    db.session.commit()

    rv = test_client.post(
        "/oauth/par",
        data={
            "response_type": "code",
            "client_id": "client-id",
            "client_secret": "client-secret",
            "redirect_uri": "https://client.test/authorized",
            "scope": "profile",
            "state": "xyz",
        },
    )
    assert rv.status_code == 201
    request_uri = json.loads(rv.data)["request_uri"]

    item = PushedRequest.query.filter_by(request_uri=request_uri).one()
    assert "client_secret" not in item.data


def test_invalid_request_uri(test_client):
    rv = test_client.get(
        "/oauth/authorize?client_id=client-id"
        "&request_uri=urn:ietf:params:oauth:request_uri:missing"
    )
    assert rv.status_code == 400
    assert json.loads(rv.data)["error"] == "invalid_request"


def test_server_metadata(test_client):
    rv = test_client.get("/.well-known/oauth-authorization-server")
    resp = json.loads(rv.data)
    assert resp["pushed_authorization_request_endpoint"] == "https://as.test/oauth/par"
    assert resp["require_pushed_authorization_requests"] is True
