import time

import pytest
from flask import json

from authlib.common.urls import url_decode
from authlib.common.urls import urlparse
from authlib.oauth2 import rfc9126
from authlib.oauth2.rfc6749.grants import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
)
from authlib.oauth2.rfc7636 import CodeChallenge
from authlib.oauth2.rfc7636 import create_s256_code_challenge

from .models import Client
from .models import CodeGrantMixin
from .models import save_authorization_code
from .oauth2_server import create_basic_header

CODE_VERIFIER = "izhyMo6VUTe6aOFmDpQa4Bo4lBFDyJqTzMWO6Z5fABC"
CODE_CHALLENGE = create_s256_code_challenge(CODE_VERIFIER)


class AuthorizationCodeGrant(CodeGrantMixin, _AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ["client_secret_basic", "client_secret_post", "none"]

    def save_authorization_code(self, code, request):
        return save_authorization_code(code, request)


@pytest.fixture
def store():
    return rfc9126.InMemoryPushedAuthorizationRequestStore()


@pytest.fixture
def par(store):
    return rfc9126.PushedAuthorizationRequests(store=store)


@pytest.fixture(autouse=True)
def server(server, app, par):
    server.register_grant(AuthorizationCodeGrant, [CodeChallenge(required=True)])
    server.register_extension(par)

    @app.route("/oauth/par", methods=["POST"])
    def par():
        return server.create_endpoint_response("pushed_authorization_request")

    return server


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


def push_authorization_request(test_client, **extra):
    data = {
        "response_type": "code",
        "redirect_uri": "https://client.test/authorized",
        "scope": "profile",
        "state": "xyz",
        "code_challenge": CODE_CHALLENGE,
        "code_challenge_method": "S256",
    }
    data.update(extra)
    return test_client.post(
        "/oauth/par",
        data=data,
        headers=create_basic_header("client-id", "client-secret"),
    )


def authorize_url(request_uri, **extra):
    params = {"client_id": "client-id", "request_uri": request_uri}
    params.update(extra)
    query = "&".join(f"{k}={v}" for k, v in params.items())
    return "/oauth/authorize?" + query


def test_full_flow(test_client):
    # 1. the client pushes the authorization request
    rv = push_authorization_request(test_client)
    assert rv.status_code == 201
    resp = json.loads(rv.data)
    request_uri = resp["request_uri"]
    assert request_uri.startswith("urn:ietf:params:oauth:request_uri:")
    assert resp["expires_in"] == 60

    # 2. the browser only carries client_id and request_uri; extra
    # parameters on the URL must not override the pushed ones
    url = authorize_url(
        request_uri,
        scope="invalid",
        redirect_uri="https://evil.test/cb",
        state="hacked",
    )
    rv = test_client.get(url)
    assert rv.data == b"ok"

    # refreshing the consent page still works
    rv = test_client.get(url)
    assert rv.data == b"ok"

    # 3. the user approves
    rv = test_client.post(url + "&user_id=1")
    assert rv.status_code == 302
    assert rv.location.startswith("https://client.test/authorized?")
    params = dict(url_decode(urlparse.urlparse(rv.location).query))
    assert params["state"] == "xyz"
    code = params["code"]

    # 4. the client exchanges the code for a token
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "redirect_uri": "https://client.test/authorized",
            "code": code,
            "code_verifier": CODE_VERIFIER,
        },
        headers=create_basic_header("client-id", "client-secret"),
    )
    assert rv.status_code == 200
    resp = json.loads(rv.data)
    assert resp["access_token"]
    assert resp["scope"] == "profile"


def test_invalid_client_is_not_stored(test_client, store):
    rv = test_client.post(
        "/oauth/par",
        data={"response_type": "code", "client_id": "client-id"},
        headers=create_basic_header("client-id", "wrong-secret"),
    )
    assert rv.status_code == 401
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_client"
    assert len(store._records) == 0


def test_request_object_not_supported(test_client, store):
    rv = push_authorization_request(test_client, request="some.jwt.token")
    resp = json.loads(rv.data)
    assert resp["error"] == "request_not_supported"

    rv = push_authorization_request(
        test_client, request_uri="urn:ietf:params:oauth:request_uri:abc"
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "request_uri_not_supported"

    assert len(store._records) == 0


def test_invalid_pushed_parameters(test_client, store):
    rv = push_authorization_request(test_client, redirect_uri="https://evil.test/cb")
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_request"

    rv = push_authorization_request(test_client, code_challenge="too-short")
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_request"

    assert len(store._records) == 0


def test_unknown_request_uri(test_client):
    url = authorize_url("urn:ietf:params:oauth:request_uri:unknown")
    rv = test_client.get(url)
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_request_uri"


def test_expired_request_uri(test_client, store):
    request_uri = "urn:ietf:params:oauth:request_uri:expired"
    store.save(
        request_uri,
        "client-id",
        {"response_type": "code", "client_id": "client-id"},
        time.time() - 10,
    )
    rv = test_client.get(authorize_url(request_uri))
    resp = json.loads(rv.data)
    # the expired reference never reaches the user consent handling
    assert resp["error"] == "invalid_request_uri"


def test_cross_client_request_uri(test_client, db, user):
    other = Client(user_id=user.id, client_id="other-id", client_secret="other-secret")
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

    rv = push_authorization_request(test_client)
    request_uri = json.loads(rv.data)["request_uri"]

    url = authorize_url(request_uri, client_id="other-id")
    rv = test_client.get(url)
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_request_uri"


def test_request_uri_is_single_use(test_client):
    rv = push_authorization_request(test_client)
    request_uri = json.loads(rv.data)["request_uri"]
    url = authorize_url(request_uri)

    rv = test_client.post(url + "&user_id=1")
    assert rv.status_code == 302

    rv = test_client.post(url + "&user_id=1")
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_request_uri"


def test_store_consume_is_atomic(store):
    store.save("uri", "client-id", {}, time.time() + 60)
    assert store.get("uri") is not None
    assert store.get("uri") is not None
    assert store.consume("uri") is not None
    assert store.consume("uri") is None
    assert store.get("uri") is None


def test_require_pushed_authorization_requests(test_client, client, db):
    metadata = dict(client.client_metadata)
    metadata["require_pushed_authorization_requests"] = True
    client.set_client_metadata(metadata)
    db.session.add(client)
    db.session.commit()

    rv = test_client.get("/oauth/authorize?response_type=code&client_id=client-id")
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_request"

    # the pushed flow still works
    rv = push_authorization_request(test_client)
    request_uri = json.loads(rv.data)["request_uri"]
    rv = test_client.get(authorize_url(request_uri))
    assert rv.data == b"ok"


class TestServerRequiresPAR:
    @pytest.fixture
    def par(self, store):
        class ServerRequirePAR(rfc9126.PushedAuthorizationRequests):
            def get_server_metadata(self):
                return {"require_pushed_authorization_requests": True}

        return ServerRequirePAR(store=store)

    def test_plain_authorization_request_rejected(self, test_client):
        rv = test_client.get("/oauth/authorize?response_type=code&client_id=client-id")
        resp = json.loads(rv.data)
        assert resp["error"] == "invalid_request"

    def test_pushed_flow_still_works(self, test_client):
        rv = push_authorization_request(test_client)
        request_uri = json.loads(rv.data)["request_uri"]
        rv = test_client.get(authorize_url(request_uri))
        assert rv.data == b"ok"


def test_server_metadata():
    from authlib.oauth2 import rfc8414

    metadata = rfc8414.AuthorizationServerMetadata(
        {
            "issuer": "https://as.test",
            "authorization_endpoint": "https://as.test/oauth/authorize",
            "token_endpoint": "https://as.test/oauth/token",
            "response_types_supported": ["code"],
            "pushed_authorization_request_endpoint": "https://as.test/oauth/par",
            "require_pushed_authorization_requests": True,
        }
    )
    metadata.validate(metadata_classes=[rfc9126.AuthorizationServerMetadata])

    with pytest.raises(ValueError):
        metadata = rfc8414.AuthorizationServerMetadata(
            {
                "issuer": "https://as.test",
                "authorization_endpoint": "https://as.test/oauth/authorize",
                "token_endpoint": "https://as.test/oauth/token",
                "response_types_supported": ["code"],
            }
        )
        metadata.validate(metadata_classes=[rfc9126.AuthorizationServerMetadata])

    with pytest.raises(ValueError):
        metadata = rfc8414.AuthorizationServerMetadata(
            {
                "issuer": "https://as.test",
                "authorization_endpoint": "https://as.test/oauth/authorize",
                "token_endpoint": "https://as.test/oauth/token",
                "response_types_supported": ["code"],
                "pushed_authorization_request_endpoint": "https://as.test/oauth/par",
                "require_pushed_authorization_requests": "yes",
            }
        )
        metadata.validate(metadata_classes=[rfc9126.AuthorizationServerMetadata])
