import time

import pytest
from flask import jsonify
from joserfc.jwk import KeySet

from authlib.common.security import generate_token
from authlib.common.urls import url_decode
from authlib.common.urls import urlparse
from authlib.integrations.flask_oauth2 import ResourceProtector
from authlib.jose import jwt
from authlib.oauth2.rfc8707 import AuthorizationCodeGrant as _AuthorizationCodeGrant
from authlib.oauth2.rfc8707 import RefreshTokenGrant as _RefreshTokenGrant
from authlib.oauth2.rfc9068 import JWTBearerTokenGenerator
from authlib.oauth2.rfc9068 import JWTBearerTokenValidator
from tests.util import read_file_path

from ..models import AuthorizationCode
from ..models import CodeGrantMixin
from ..models import Token
from ..models import User
from ..models import db
from ..models import save_authorization_code
from ..oauth2_server import create_basic_header
from ..oauth2_server import create_bearer_header

issuer = "https://authlib.test/"
DOCS_API = "https://docs-api.test"
SEARCH_API = "https://search-api.test"


@pytest.fixture
def jwks():
    return read_file_path("jwks_private.json")


@pytest.fixture(autouse=True)
def client(client, db):
    client.set_client_metadata(
        {
            "scope": "read",
            "redirect_uris": ["https://client.test/authorized"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "client_secret_basic",
            "grant_types": ["authorization_code", "refresh_token"],
        }
    )
    db.session.add(client)
    db.session.commit()
    return client


class AuthorizationCodeGrant(CodeGrantMixin, _AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ["client_secret_basic", "client_secret_post", "none"]

    def save_authorization_code(self, code, request):
        return save_authorization_code(code, request)


class RefreshTokenGrant(_RefreshTokenGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ["client_secret_basic", "client_secret_post", "none"]

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


@pytest.fixture(autouse=True)
def server(server):
    server.register_grant(AuthorizationCodeGrant)
    server.register_grant(RefreshTokenGrant)
    return server


@pytest.fixture(autouse=True)
def token_generator(server, jwks):
    class MyJWTBearerTokenGenerator(JWTBearerTokenGenerator):
        def get_jwks(self):
            return jwks

    def refresh_token_generator(client, grant_type, user, scope, resources=None):
        return generate_token(48)

    generator = MyJWTBearerTokenGenerator(
        issuer=issuer, refresh_token_generator=refresh_token_generator
    )
    server.register_token_generator("default", generator)
    return generator


def create_token_validator(resource_server, jwks):
    class MyJWTBearerTokenValidator(JWTBearerTokenValidator):
        def get_jwks(self):
            return KeySet.import_key_set(jwks)

    return MyJWTBearerTokenValidator(
        issuer=issuer, resource_server=resource_server
    )


@pytest.fixture(autouse=True)
def resource_apis(app, jwks):
    # Two local APIs share the same "read" scope, but each one only accepts
    # JWT access tokens issued for its own audience.
    docs_require_oauth = ResourceProtector()
    docs_require_oauth.register_token_validator(create_token_validator(DOCS_API, jwks))

    search_require_oauth = ResourceProtector()
    search_require_oauth.register_token_validator(
        create_token_validator(SEARCH_API, jwks)
    )

    @app.route("/docs-api/documents")
    @docs_require_oauth("read")
    def documents():
        return jsonify(api="docs")

    @app.route("/search-api/search")
    @search_require_oauth("read")
    def search():
        return jsonify(api="search")


def run_authorize(test_client, client, user, resources=()):
    data = {
        "response_type": "code",
        "client_id": client.client_id,
        "redirect_uri": client.redirect_uris[0],
        "scope": "read",
        "user_id": str(user.id),
    }
    if resources:
        data["resource"] = list(resources)
    return test_client.post("/oauth/authorize", data=data)


def run_token_request(test_client, client, code, resources=()):
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": client.redirect_uris[0],
    }
    if resources:
        data["resource"] = list(resources)
    headers = create_basic_header(client.client_id, client.client_secret)
    return test_client.post("/oauth/token", data=data, headers=headers)


def run_refresh(test_client, client, refresh_token, resources=()):
    data = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
    }
    if resources:
        data["resource"] = list(resources)
    headers = create_basic_header(client.client_id, client.client_secret)
    return test_client.post("/oauth/token", data=data, headers=headers)


def issue_token(test_client, client, user, resources=(), token_resources=()):
    res = run_authorize(test_client, client, user, resources)
    params = dict(url_decode(urlparse.urlparse(res.location).query))
    res = run_token_request(test_client, client, params["code"], token_resources)
    assert res.status_code == 200, res.json
    return res.json


def test_authorization_code_stores_consented_resources(
    test_client, client, user, db
):
    res = run_authorize(test_client, client, user, [DOCS_API, SEARCH_API])
    params = dict(url_decode(urlparse.urlparse(res.location).query))
    code = AuthorizationCode.query.filter_by(code=params["code"]).one()
    assert code.get_resources() == [DOCS_API, SEARCH_API]


def test_authorize_rejects_relative_resource(test_client, client, user):
    res = run_authorize(test_client, client, user, ["docs-api"])
    params = dict(url_decode(urlparse.urlparse(res.location).query))
    assert params["error"] == "invalid_target"


def test_authorize_rejects_resource_with_fragment(test_client, client, user):
    res = run_authorize(test_client, client, user, [f"{DOCS_API}#fragment"])
    params = dict(url_decode(urlparse.urlparse(res.location).query))
    assert params["error"] == "invalid_target"


def test_token_request_selects_consented_subset(test_client, client, user, jwks):
    token = issue_token(
        test_client, client, user, [DOCS_API, SEARCH_API], [DOCS_API]
    )
    claims = jwt.decode(token["access_token"], jwks)
    assert claims["aud"] == DOCS_API
    assert token["resource"] == DOCS_API


def test_token_request_defaults_to_consented_resources(
    test_client, client, user, jwks
):
    token = issue_token(test_client, client, user, [DOCS_API, SEARCH_API])
    claims = jwt.decode(token["access_token"], jwks)
    assert claims["aud"] == [DOCS_API, SEARCH_API]


def test_token_request_rejects_not_consented_resource(test_client, client, user):
    res = run_authorize(test_client, client, user, [DOCS_API])
    params = dict(url_decode(urlparse.urlparse(res.location).query))
    res = run_token_request(test_client, client, params["code"], [SEARCH_API])
    assert res.status_code == 400
    assert res.json["error"] == "invalid_target"


def test_token_request_rejects_invalid_resource(test_client, client, user):
    res = run_authorize(test_client, client, user, [DOCS_API])
    params = dict(url_decode(urlparse.urlparse(res.location).query))
    res = run_token_request(test_client, client, params["code"], ["docs-api"])
    assert res.status_code == 400
    assert res.json["error"] == "invalid_target"


def test_same_jwt_accepted_by_one_api_and_rejected_by_the_other(
    test_client, client, user
):
    # Both APIs require the same "read" scope, only the audience differs.
    token = issue_token(test_client, client, user, [DOCS_API], [DOCS_API])
    headers = create_bearer_header(token["access_token"])

    res = test_client.get("/docs-api/documents", headers=headers)
    assert res.status_code == 200
    assert res.json["api"] == "docs"

    res = test_client.get("/search-api/search", headers=headers)
    assert res.status_code == 401
    assert res.json["error"] == "invalid_token"


def test_token_for_both_apis_is_accepted_by_both(test_client, client, user):
    token = issue_token(test_client, client, user, [DOCS_API, SEARCH_API])
    headers = create_bearer_header(token["access_token"])

    res = test_client.get("/docs-api/documents", headers=headers)
    assert res.status_code == 200

    res = test_client.get("/search-api/search", headers=headers)
    assert res.status_code == 200


def test_refresh_keeps_the_resource_boundary(test_client, client, user, jwks):
    token = issue_token(test_client, client, user, [DOCS_API], [DOCS_API])
    res = run_refresh(test_client, client, token["refresh_token"])
    assert res.status_code == 200, res.json
    refreshed = res.json
    assert refreshed["resource"] == DOCS_API

    claims = jwt.decode(refreshed["access_token"], jwks)
    assert claims["aud"] == DOCS_API

    headers = create_bearer_header(refreshed["access_token"])
    res = test_client.get("/docs-api/documents", headers=headers)
    assert res.status_code == 200

    res = test_client.get("/search-api/search", headers=headers)
    assert res.status_code == 401
    assert res.json["error"] == "invalid_token"


def test_refresh_cannot_expand_resources(test_client, client, user):
    token = issue_token(test_client, client, user, [DOCS_API], [DOCS_API])
    res = run_refresh(test_client, client, token["refresh_token"], [SEARCH_API])
    assert res.status_code == 400
    assert res.json["error"] == "invalid_target"


def test_refresh_can_narrow_resources(test_client, client, user, jwks):
    token = issue_token(test_client, client, user, [DOCS_API, SEARCH_API])
    res = run_refresh(test_client, client, token["refresh_token"], [SEARCH_API])
    assert res.status_code == 200, res.json
    claims = jwt.decode(res.json["access_token"], jwks)
    assert claims["aud"] == SEARCH_API


def test_no_resource_parameter_keeps_existing_behavior(
    test_client, client, user, jwks
):
    token = issue_token(test_client, client, user)
    assert "resource" not in token
    claims = jwt.decode(token["access_token"], jwks)
    # without resource indicators, the audience falls back to the client id
    assert claims["aud"] == client.client_id
