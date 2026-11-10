import json
import threading

import pytest
from joserfc import jwk
from joserfc import jwt
from joserfc.errors import InvalidClaimError

from authlib.common.urls import add_params_to_uri
from authlib.common.urls import url_decode
from authlib.common.urls import urlparse
from authlib.oauth2 import rfc9101
from authlib.oauth2 import rfc9126
from authlib.oauth2.rfc6749.grants import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
)
from tests.util import read_file_path

from .models import AuthorizationCode
from .models import Client
from .models import CodeGrantMixin
from .models import save_authorization_code
from .oauth2_server import create_basic_header

par_url = "/oauth/par"
authorize_url = "/oauth/authorize"


class Clock:
    """A controllable clock for the store and the endpoint."""

    def __init__(self, now=1_000_000.0):
        self.now = now

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def store(clock):
    return rfc9126.InMemoryPushedAuthorizationRequestStore(clock=clock)


@pytest.fixture
def par_metadata():
    return {}


class AuthorizationCodeGrant(CodeGrantMixin, _AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = [
        "client_secret_basic",
        "client_secret_post",
        "none",
    ]

    def save_authorization_code(self, code, request):
        return save_authorization_code(code, request)


@pytest.fixture(autouse=True)
def server(server, app, store, clock, par_metadata):
    class PushedAuthorizationRequest(rfc9126.PushedAuthorizationRequest):
        def get_server_metadata(self):
            return par_metadata

    server.register_grant(AuthorizationCodeGrant)
    server.register_extension(PushedAuthorizationRequest(store))
    server.register_endpoint(
        rfc9126.PushedAuthorizationRequestEndpoint(
            store=store, expires_in=60, clock=clock
        )
    )

    @app.route("/oauth/par", methods=["GET", "POST"])
    def pushed_authorization_request():
        return server.create_endpoint_response("pushed_authorization_request")

    return server


@pytest.fixture(autouse=True)
def client(client, db):
    client.set_client_metadata(
        {
            "redirect_uris": ["https://client.test"],
            "scope": "profile address",
            "token_endpoint_auth_method": "client_secret_basic",
            "response_types": ["code"],
            "grant_types": ["authorization_code"],
        }
    )
    db.session.add(client)
    db.session.commit()
    return client


def push(test_client, data=None, headers=None):
    """Push an authorization request and return its request_uri."""
    form = {
        "response_type": "code",
        "client_id": "client-id",
        "redirect_uri": "https://client.test",
        "scope": "profile",
        "state": "bar",
    }
    if data:
        form.update(data)
    if headers is None:
        headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(par_url, data=form, headers=headers)
    assert rv.status_code == 201
    return json.loads(rv.data)["request_uri"]


def authorize_params(request_uri, **extra):
    return add_params_to_uri(
        authorize_url,
        {"client_id": "client-id", "request_uri": request_uri, **extra},
    )


def test_endpoint_response(test_client):
    rv = test_client.post(
        par_url,
        data={"response_type": "code", "client_id": "client-id"},
        headers=create_basic_header("client-id", "client-secret"),
    )
    assert rv.status_code == 201
    body = json.loads(rv.data)
    assert body["request_uri"].startswith("urn:ietf:params:oauth:request_uri:")
    assert body["expires_in"] == 60


def test_endpoint_requires_post(test_client):
    rv = test_client.get(par_url)
    assert json.loads(rv.data)["error"] == "invalid_request"


def test_endpoint_invalid_client(test_client):
    rv = test_client.post(
        par_url,
        data={"response_type": "code", "client_id": "client-id"},
        headers=create_basic_header("client-id", "wrong-secret"),
    )
    assert rv.status_code == 401
    assert json.loads(rv.data)["error"] == "invalid_client"


def test_endpoint_client_id_mismatch(test_client):
    rv = test_client.post(
        par_url,
        data={"response_type": "code", "client_id": "other-client"},
        headers=create_basic_header("client-id", "client-secret"),
    )
    assert json.loads(rv.data)["error"] == "invalid_request"


def test_endpoint_missing_response_type(test_client):
    rv = test_client.post(
        par_url,
        data={"client_id": "client-id"},
        headers=create_basic_header("client-id", "client-secret"),
    )
    assert json.loads(rv.data)["error"] == "invalid_request"


def test_endpoint_unsupported_response_type(test_client):
    rv = test_client.post(
        par_url,
        data={"response_type": "token", "client_id": "client-id"},
        headers=create_basic_header("client-id", "client-secret"),
    )
    assert json.loads(rv.data)["error"] == "unsupported_response_type"


def test_endpoint_invalid_redirect_uri(test_client):
    rv = test_client.post(
        par_url,
        data={
            "response_type": "code",
            "client_id": "client-id",
            "redirect_uri": "https://attacker.test",
        },
        headers=create_basic_header("client-id", "client-secret"),
    )
    assert json.loads(rv.data)["error"] == "invalid_request"


def test_endpoint_invalid_scope(test_client, server):
    server.scopes_supported = ["profile"]
    rv = test_client.post(
        par_url,
        data={"response_type": "code", "client_id": "client-id", "scope": "invalid"},
        headers=create_basic_header("client-id", "client-secret"),
    )
    assert json.loads(rv.data)["error"] == "invalid_scope"


def test_endpoint_rejects_pushed_request_uri(test_client):
    rv = test_client.post(
        par_url,
        data={
            "response_type": "code",
            "client_id": "client-id",
            "request_uri": "urn:ietf:params:oauth:request_uri:abc",
        },
        headers=create_basic_header("client-id", "client-secret"),
    )
    assert json.loads(rv.data)["error"] == "invalid_request"


def test_full_flow_and_pages_do_not_consume(test_client):
    request_uri = push(test_client)
    url = authorize_params(request_uri)

    # the login page does not consume the reference
    rv = test_client.get(url)
    assert rv.data == b"login"

    # the consent page does not consume the reference
    rv = test_client.get(url + "&user_id=1")
    assert rv.data == b"ok"

    # the final submission consumes the reference
    rv = test_client.post(url + "&user_id=1")
    params = dict(url_decode(urlparse.urlparse(rv.location).query))
    assert "code" in params
    assert params["state"] == "bar"

    # the issued code can be exchanged
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": params["code"],
            "redirect_uri": "https://client.test",
        },
        headers=create_basic_header("client-id", "client-secret"),
    )
    assert rv.status_code == 200
    assert json.loads(rv.data)["scope"] == "profile"


def test_outer_parameters_do_not_override(test_client):
    request_uri = push(test_client, {"scope": "profile", "state": "bar"})
    url = authorize_params(request_uri, scope="address", state="evil", user_id="1")
    rv = test_client.post(url)
    params = dict(url_decode(urlparse.urlparse(rv.location).query))
    assert "code" in params
    assert params["state"] == "bar"

    code = AuthorizationCode.query.filter_by(code=params["code"]).one()
    assert code.scope == "profile"


def test_expired_request_uri(test_client, clock):
    request_uri = push(test_client)
    clock.advance(61)
    rv = test_client.get(authorize_params(request_uri))
    assert json.loads(rv.data)["error"] == "invalid_request_uri"


def test_unknown_request_uri(test_client):
    url = authorize_params("urn:ietf:params:oauth:request_uri:unknown")
    rv = test_client.get(url)
    assert json.loads(rv.data)["error"] == "invalid_request_uri"


def test_request_uri_belongs_to_its_client(test_client, db, user):
    other = Client(user_id=user.id, client_id="client-2", client_secret="secret-2")
    other.set_client_metadata(
        {
            "redirect_uris": ["https://client2.test"],
            "scope": "profile",
            "token_endpoint_auth_method": "client_secret_basic",
            "response_types": ["code"],
            "grant_types": ["authorization_code"],
        }
    )
    db.session.add(other)
    db.session.commit()

    request_uri = push(test_client)
    url = add_params_to_uri(
        authorize_url, {"client_id": "client-2", "request_uri": request_uri}
    )
    rv = test_client.get(url)
    assert json.loads(rv.data)["error"] == "invalid_request"


def test_request_uri_is_single_use(test_client):
    request_uri = push(test_client)
    url = authorize_params(request_uri, user_id="1")

    rv = test_client.post(url)
    assert "code=" in rv.location

    rv = test_client.post(url)
    assert json.loads(rv.data)["error"] == "invalid_request_uri"


def test_failed_authorization_releases_reference(test_client, monkeypatch):
    request_uri = push(test_client)
    url = authorize_params(request_uri, user_id="1")

    def fail_save_authorization_code(self, code, request):
        raise RuntimeError("database is down")

    monkeypatch.setattr(
        AuthorizationCodeGrant, "save_authorization_code", fail_save_authorization_code
    )
    with pytest.raises(RuntimeError):
        test_client.post(url)

    # the failure released the reference: a short-term retry succeeds
    monkeypatch.undo()
    rv = test_client.post(url)
    assert "code=" in rv.location


def test_concurrent_claims_have_a_single_winner(store, clock):
    entry = rfc9126.PushedAuthorizationRequestData(
        request_uri="urn:ietf:params:oauth:request_uri:race",
        client_id="client-id",
        data={},
        expires_at=clock() + 60,
    )
    store.save(entry)

    claimed = []
    threads = [
        threading.Thread(
            target=lambda: claimed.append(store.claim(entry.request_uri) is not None)
        )
        for _ in range(8)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert claimed.count(True) == 1


def test_store_claim_commit_release(store, clock):
    entry = rfc9126.PushedAuthorizationRequestData(
        request_uri="urn:ietf:params:oauth:request_uri:lifecycle",
        client_id="client-id",
        data={},
        expires_at=clock() + 60,
    )
    store.save(entry)

    # a claimed reference cannot be claimed again
    assert store.claim(entry.request_uri) is not None
    assert store.claim(entry.request_uri) is None

    # a released reference can be claimed again
    store.release(entry.request_uri)
    assert store.claim(entry.request_uri) is not None

    # a committed reference is gone
    store.commit(entry.request_uri)
    assert store.get(entry.request_uri) is None
    assert store.claim(entry.request_uri) is None


def test_store_expiration(store, clock):
    entry = rfc9126.PushedAuthorizationRequestData(
        request_uri="urn:ietf:params:oauth:request_uri:expired",
        client_id="client-id",
        data={},
        expires_at=clock() + 60,
    )
    store.save(entry)
    clock.advance(61)
    assert store.get(entry.request_uri) is None
    assert store.claim(entry.request_uri) is None


def test_require_pushed_authorization_requests(test_client, par_metadata):
    par_metadata["require_pushed_authorization_requests"] = True

    url = add_params_to_uri(
        authorize_url, {"response_type": "code", "client_id": "client-id"}
    )
    rv = test_client.get(url)
    assert json.loads(rv.data)["error"] == "invalid_request"

    # a pushed request still works
    request_uri = push(test_client)
    rv = test_client.get(authorize_params(request_uri))
    assert rv.data == b"login"


def test_jar_request_object_is_not_overridden(test_client, server):
    """With the JAR extension enabled, the parameters of the signed request
    object are not completed by the outer authorization request."""

    class JWTAuthenticationRequest(rfc9101.JWTAuthenticationRequest):
        def resolve_client_public_key(self, client):
            return read_file_path("jwk_public.json")

    server.register_extension(JWTAuthenticationRequest(support_request_uri=False))

    payload = {
        "response_type": "code",
        "client_id": "client-id",
        "redirect_uri": "https://client.test",
        "scope": "profile",
        "state": "bar",
    }
    request_obj = jwt.encode(
        {"alg": "RS256"}, payload, jwk.import_key(read_file_path("jwk_private.json"))
    )
    rv = test_client.post(
        par_url,
        data={"request": request_obj},
        headers=create_basic_header("client-id", "client-secret"),
    )
    assert rv.status_code == 201
    request_uri = json.loads(rv.data)["request_uri"]

    url = authorize_params(request_uri, scope="address", state="evil", user_id="1")
    rv = test_client.post(url)
    params = dict(url_decode(urlparse.urlparse(rv.location).query))
    assert "code" in params
    assert params["state"] == "bar"

    code = AuthorizationCode.query.filter_by(code=params["code"]).one()
    assert code.scope == "profile"


def test_authorization_server_metadata(monkeypatch):
    metadata = rfc9126.AuthorizationServerMetadata(
        {
            "pushed_authorization_request_endpoint": "https://as.test/par",
            "require_pushed_authorization_requests": True,
        }
    )
    metadata.validate_pushed_authorization_request_endpoint()
    metadata.validate_require_pushed_authorization_requests()

    monkeypatch.delenv("AUTHLIB_INSECURE_TRANSPORT", raising=False)
    metadata = rfc9126.AuthorizationServerMetadata(
        {"pushed_authorization_request_endpoint": "http://as.test/par"}
    )
    with pytest.raises(ValueError):
        metadata.validate_pushed_authorization_request_endpoint()

    metadata = rfc9126.AuthorizationServerMetadata(
        {"require_pushed_authorization_requests": "yes"}
    )
    with pytest.raises(ValueError):
        metadata.validate_require_pushed_authorization_requests()


def test_client_metadata_claims():
    claims = rfc9126.ClientMetadataClaims({}, {})
    claims.validate()
    assert claims["require_pushed_authorization_requests"] is False

    claims = rfc9126.ClientMetadataClaims(
        {"require_pushed_authorization_requests": "yes"}, {}
    )
    with pytest.raises(InvalidClaimError):
        claims.validate()
