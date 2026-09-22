import time

import pytest
from flask import json
from joserfc.errors import InvalidClaimError

from authlib.common.urls import url_decode
from authlib.common.urls import urlparse
from authlib.oauth2 import rfc8414
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

par_url = "/oauth/par"


@pytest.fixture
def metadata():
    return {}


@pytest.fixture(autouse=True)
def client(client):
    return client


@pytest.fixture
def par_extension(metadata):
    class PushedAuthorizationRequest(rfc9126.PushedAuthorizationRequest):
        def get_server_metadata(self):
            return metadata

        def get_client_require_pushed_authorization_requests(self, client):
            return client.client_metadata.get(
                "require_pushed_authorization_requests", False
            )

    return PushedAuthorizationRequest()


@pytest.fixture(autouse=True)
def server(server, app, par_extension):
    class AuthorizationCodeGrant(CodeGrantMixin, _AuthorizationCodeGrant):
        TOKEN_ENDPOINT_AUTH_METHODS = [
            "client_secret_basic",
            "client_secret_post",
            "none",
        ]

        def save_authorization_code(self, code, request):
            return save_authorization_code(code, request)

    server.register_grant(AuthorizationCodeGrant, [CodeChallenge(required=False)])
    server.register_extension(par_extension)
    server.scopes_supported = ["profile"]

    @app.route(par_url, methods=["POST"])
    def pushed_authorization_request():
        return server.create_endpoint_response(
            rfc9126.PushedAuthorizationRequestEndpoint.ENDPOINT_NAME
        )

    return server


@pytest.fixture
def other_client(db, user):
    client = Client(
        user_id=user.id,
        client_id="other-client-id",
        client_secret="other-client-secret",
    )
    client.set_client_metadata(
        {
            "redirect_uris": ["https://other.test/authorized"],
            "scope": "profile",
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
        }
    )
    db.session.add(client)
    db.session.commit()
    yield client
    db.session.delete(client)


def push(test_client, **kwargs):
    data = {
        "response_type": "code",
        "client_id": "client-id",
        "redirect_uri": "https://client.test/authorized",
        "scope": "profile",
        "state": "xyz",
    }
    data.update(kwargs)
    headers = kwargs.pop("headers", None) or create_basic_header(
        "client-id", "client-secret"
    )
    return test_client.post(par_url, data=data, headers=headers)


def authorize(test_client, request_uri, method="get"):
    url = f"/oauth/authorize?client_id=client-id&request_uri={request_uri}&user_id=1"
    if method == "get":
        return test_client.get(url)
    return test_client.post(url)


def exchange_code(test_client, location, **kwargs):
    params = dict(url_decode(urlparse.urlparse(location).query))
    data = {
        "grant_type": "authorization_code",
        "redirect_uri": "https://client.test/authorized",
        "code": params["code"],
    }
    data.update(kwargs)
    return test_client.post(
        "/oauth/token",
        data=data,
        headers=create_basic_header("client-id", "client-secret"),
    )


def test_full_flow_with_pkce(test_client):
    code_verifier = "a" * 48
    rv = push(
        test_client,
        code_challenge=create_s256_code_challenge(code_verifier),
        code_challenge_method="S256",
    )
    assert rv.status_code == 201
    body = json.loads(rv.data)
    request_uri = body["request_uri"]
    assert request_uri.startswith("urn:ietf:params:oauth:request_uri:")
    assert body["expires_in"] == 60

    # rendering the consent page does not consume the reference
    rv = authorize(test_client, request_uri)
    assert rv.data == b"ok"
    rv = authorize(test_client, request_uri)
    assert rv.data == b"ok"

    rv = authorize(test_client, request_uri, method="post")
    assert rv.status_code == 302
    location = rv.headers["Location"]
    assert location.startswith("https://client.test/authorized?")
    assert "state=xyz" in location

    rv = exchange_code(test_client, location, code_verifier=code_verifier)
    assert rv.status_code == 200
    token = json.loads(rv.data)
    assert token["access_token"]
    assert token["scope"] == "profile"


def test_url_parameters_do_not_override_pushed_data(test_client):
    rv = push(test_client)
    request_uri = json.loads(rv.data)["request_uri"]

    rv = test_client.post(
        "/oauth/authorize",
        data={
            "client_id": "client-id",
            "request_uri": request_uri,
            "user_id": 1,
            "scope": "admin",
            "redirect_uri": "https://attacker.test/cb",
            "state": "forged",
        },
    )
    assert rv.status_code == 302
    location = rv.headers["Location"]
    assert location.startswith("https://client.test/authorized?")
    assert "state=xyz" in location

    rv = exchange_code(test_client, location)
    assert rv.status_code == 200
    assert json.loads(rv.data)["scope"] == "profile"


def test_request_uri_is_consumed_once(test_client):
    rv = push(test_client)
    request_uri = json.loads(rv.data)["request_uri"]

    rv = authorize(test_client, request_uri, method="post")
    assert rv.status_code == 302

    # a second completion with the same reference is rejected
    rv = authorize(test_client, request_uri, method="post")
    assert rv.status_code == 400
    assert b"invalid_request_uri" in rv.data

    # the consent page is not available either
    rv = authorize(test_client, request_uri)
    assert rv.status_code == 400
    assert b"invalid_request_uri" in rv.data


def test_unknown_request_uri(test_client):
    rv = authorize(test_client, "urn:ietf:params:oauth:request_uri:unknown")
    assert rv.status_code == 400
    assert b"invalid_request_uri" in rv.data


def test_expired_request_uri_does_not_reach_consent(test_client, par_extension):
    rv = push(test_client)
    request_uri = json.loads(rv.data)["request_uri"]

    record = par_extension.store.get(request_uri)
    record["expires_at"] = time.time() - 1

    rv = authorize(test_client, request_uri)
    assert rv.status_code == 400
    assert b"invalid_request_uri" in rv.data


def test_request_uri_of_another_client(test_client, other_client):
    rv = push(test_client)
    request_uri = json.loads(rv.data)["request_uri"]

    rv = test_client.get(
        "/oauth/authorize?client_id=other-client-id"
        f"&request_uri={request_uri}&user_id=1"
    )
    assert rv.status_code == 400
    assert b"invalid_request" in rv.data


def test_failed_client_authentication_is_not_stored(test_client, par_extension):
    rv = test_client.post(
        par_url,
        data={
            "response_type": "code",
            "client_id": "client-id",
            "redirect_uri": "https://client.test/authorized",
        },
        headers=create_basic_header("client-id", "wrong-secret"),
    )
    assert rv.status_code == 401
    assert b"invalid_client" in rv.data
    assert len(par_extension.store._data) == 0


def test_invalid_parameters_are_not_stored(test_client, par_extension):
    rv = push(test_client, redirect_uri="https://attacker.test/cb")
    assert rv.status_code == 400
    assert b"invalid_request" in rv.data
    assert len(par_extension.store._data) == 0


def test_invalid_scope_is_a_json_error(test_client, par_extension):
    rv = push(test_client, scope="profile admin")
    assert rv.status_code == 400
    assert b"invalid_scope" in rv.data
    assert rv.headers["Content-Type"].startswith("application/json")
    assert len(par_extension.store._data) == 0


def test_request_object_is_not_supported(test_client, par_extension):
    rv = push(
        test_client, request="eyJhbGciOiJub25lIn0.eyJjbGllbnRfaWQiOiJjbGllbnQtaWQifQ."
    )
    assert rv.status_code == 400
    assert b"request_not_supported" in rv.data
    assert len(par_extension.store._data) == 0


def test_push_without_client_id(test_client, par_extension):
    rv = test_client.post(
        par_url,
        data={
            "response_type": "code",
            "redirect_uri": "https://client.test/authorized",
            "scope": "profile",
        },
        headers=create_basic_header("client-id", "client-secret"),
    )
    assert rv.status_code == 201
    request_uri = json.loads(rv.data)["request_uri"]
    record = par_extension.store.get(request_uri)
    assert record["client_id"] == "client-id"
    assert record["data"]["client_id"] == "client-id"


def test_client_secret_is_not_stored(test_client, client, db, par_extension):
    client.set_client_metadata(
        dict(client.client_metadata, token_endpoint_auth_method="client_secret_post")
    )
    db.session.add(client)
    db.session.commit()

    rv = test_client.post(
        par_url,
        data={
            "response_type": "code",
            "client_id": "client-id",
            "client_secret": "client-secret",
            "redirect_uri": "https://client.test/authorized",
            "scope": "profile",
        },
    )
    assert rv.status_code == 201
    request_uri = json.loads(rv.data)["request_uri"]
    record = par_extension.store.get(request_uri)
    assert "client_secret" not in record["data"]


def test_client_requiring_par(test_client, client, db):
    client.set_client_metadata(
        dict(client.client_metadata, require_pushed_authorization_requests=True)
    )
    db.session.add(client)
    db.session.commit()

    rv = test_client.get(
        "/oauth/authorize?response_type=code&client_id=client-id"
        "&redirect_uri=https%3A%2F%2Fclient.test%2Fauthorized"
    )
    assert rv.status_code == 400
    assert b"invalid_request" in rv.data
    assert b"must be pushed" in rv.data


def test_server_requiring_par(test_client, metadata):
    metadata["require_pushed_authorization_requests"] = True
    rv = test_client.get(
        "/oauth/authorize?response_type=code&client_id=client-id"
        "&redirect_uri=https%3A%2F%2Fclient.test%2Fauthorized"
    )
    assert rv.status_code == 400
    assert b"must be pushed" in rv.data


def test_server_metadata():
    metadata = rfc8414.AuthorizationServerMetadata(
        {
            "issuer": "https://as.test",
            "authorization_endpoint": "https://as.test/authorize",
            "token_endpoint": "https://as.test/token",
            "response_types_supported": ["code"],
            "pushed_authorization_request_endpoint": "https://as.test/par",
            "require_pushed_authorization_requests": True,
        }
    )
    metadata.validate(metadata_classes=[rfc9126.AuthorizationServerMetadata])

    metadata = rfc8414.AuthorizationServerMetadata(
        {
            "issuer": "https://as.test",
            "authorization_endpoint": "https://as.test/authorize",
            "token_endpoint": "https://as.test/token",
            "response_types_supported": ["code"],
            "pushed_authorization_request_endpoint": "https://as.test/par",
            "require_pushed_authorization_requests": "yes",
        }
    )
    with pytest.raises(ValueError):
        metadata.validate(metadata_classes=[rfc9126.AuthorizationServerMetadata])


def test_client_metadata_claims():
    claims = rfc9126.ClientMetadataClaims(
        {"require_pushed_authorization_requests": True}, {}
    )
    claims.validate()

    claims = rfc9126.ClientMetadataClaims({}, {})
    claims.validate()
    assert claims["require_pushed_authorization_requests"] is False

    claims = rfc9126.ClientMetadataClaims(
        {"require_pushed_authorization_requests": "yes"}, {}
    )
    with pytest.raises(InvalidClaimError):
        claims.validate()
