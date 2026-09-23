import time

import pytest
from flask import jsonify

from authlib.common.security import generate_token
from authlib.common.urls import url_decode
from authlib.common.urls import urlparse
from authlib.integrations.flask_oauth2 import ResourceProtector
from authlib.jose import jwt
from authlib.oauth2.rfc6749.grants import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
)
from authlib.oauth2.rfc6749.grants import RefreshTokenGrant as _RefreshTokenGrant
from authlib.oauth2.rfc8707 import ResourceIndicator
from authlib.oauth2.rfc9068 import JWTBearerTokenGenerator
from authlib.oauth2.rfc9068 import JWTBearerTokenValidator
from tests.util import read_file_path

from .models import AuthorizationCode
from .models import CodeGrantMixin
from .models import Token
from .models import User
from .models import db
from .oauth2_server import create_basic_header
from .oauth2_server import create_bearer_header

issuer = "https://provider.test/"
DOCS_API = "https://docs-api.test"
SEARCH_API = "https://search-api.test"


class AuthorizationCodeGrant(CodeGrantMixin, _AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ["client_secret_basic", "client_secret_post", "none"]

    def save_authorization_code(self, code, request):
        auth_code = AuthorizationCode(
            code=code,
            client_id=request.client.client_id,
            redirect_uri=request.payload.redirect_uri,
            scope=request.scope,
            user_id=request.user.id,
            resources=" ".join(request.resources) if request.resources else None,
        )
        db.session.add(auth_code)
        db.session.commit()
        return auth_code


class RefreshTokenGrant(_RefreshTokenGrant):
    INCLUDE_NEW_REFRESH_TOKEN = True
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


@pytest.fixture
def jwks():
    return read_file_path("jwks_private.json")


@pytest.fixture
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


@pytest.fixture
def resource_indicator():
    return ResourceIndicator()


@pytest.fixture(autouse=True)
def server(server, resource_indicator):
    server.register_grant(AuthorizationCodeGrant, [resource_indicator])
    server.register_grant(RefreshTokenGrant, [resource_indicator])
    return server


@pytest.fixture(autouse=True)
def token_generator(server, jwks):
    class MyJWTBearerTokenGenerator(JWTBearerTokenGenerator):
        def get_jwks(self):
            return jwks

    def refresh_token_generator(client, grant_type, user, scope):
        return generate_token(32)

    generator = MyJWTBearerTokenGenerator(
        issuer=issuer, refresh_token_generator=refresh_token_generator
    )
    server.register_token_generator("default", generator)
    return generator


@pytest.fixture
def resource_apis(app, jwks):
    class MyJWTBearerTokenValidator(JWTBearerTokenValidator):
        def get_jwks(self):
            return jwks

    # the documentation API and the search API both require the "read"
    # scope, but each one only accepts tokens issued for itself
    docs_protector = ResourceProtector()
    docs_protector.register_token_validator(
        MyJWTBearerTokenValidator(issuer=issuer, resource_server=DOCS_API)
    )
    search_protector = ResourceProtector()
    search_protector.register_token_validator(
        MyJWTBearerTokenValidator(issuer=issuer, resource_server=SEARCH_API)
    )

    @app.route("/docs")
    @docs_protector("read")
    def docs():
        return jsonify(api="docs")

    @app.route("/search")
    @search_protector("read")
    def search():
        return jsonify(api="search")


def authorize(test_client, client, user, resources=None):
    data = {
        "response_type": "code",
        "client_id": client.client_id,
        "redirect_uri": "https://client.test/authorized",
        "scope": "read",
        "user_id": str(user.id),
    }
    if resources:
        data["resource"] = list(resources)
    return test_client.post("/oauth/authorize", data=data)


def get_code(response):
    params = dict(url_decode(urlparse.urlparse(response.location).query))
    return params["code"]


def request_token(test_client, client, code, resources=None):
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": "https://client.test/authorized",
    }
    if resources:
        data["resource"] = list(resources)
    return test_client.post(
        "/oauth/token",
        data=data,
        headers=create_basic_header(client.client_id, client.client_secret),
    )


def request_refresh(test_client, client, refresh_token, resources=None):
    data = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
    }
    if resources:
        data["resource"] = list(resources)
    return test_client.post(
        "/oauth/token",
        data=data,
        headers=create_basic_header(client.client_id, client.client_secret),
    )


def issue_token(
    test_client, client, user, authorize_resources=None, token_resources=None
):
    res = authorize(test_client, client, user, authorize_resources)
    code = get_code(res)
    res = request_token(test_client, client, code, token_resources)
    assert res.status_code == 200, res.json
    return res.json


def test_consented_resources_saved_with_authorization_code(
    test_client, client, user, db
):
    res = authorize(test_client, client, user, [DOCS_API, SEARCH_API])
    assert res.status_code == 302
    code = get_code(res)
    auth_code = db.session.query(AuthorizationCode).filter_by(code=code).one()
    # multiple "resource" parameters are preserved, not only the last one
    assert auth_code.get_resources() == [DOCS_API, SEARCH_API]


def test_token_without_resource_uses_all_consented_resources(
    test_client, client, user, jwks
):
    token = issue_token(test_client, client, user, [DOCS_API, SEARCH_API])
    claims = jwt.decode(token["access_token"], jwks)
    assert claims["aud"] == [DOCS_API, SEARCH_API]
    # the resource indicators are not mixed into the scope
    assert claims["scope"] == "read"


def test_token_request_can_select_a_subset(test_client, client, user, jwks):
    token = issue_token(test_client, client, user, [DOCS_API, SEARCH_API], [SEARCH_API])
    claims = jwt.decode(token["access_token"], jwks)
    assert claims["aud"] == SEARCH_API


def test_token_without_resource_uses_default_resources_policy(
    test_client, client, user, jwks, resource_indicator
):
    resource_indicator.default_resources = [DOCS_API]
    token = issue_token(test_client, client, user, [DOCS_API, SEARCH_API])
    claims = jwt.decode(token["access_token"], jwks)
    assert claims["aud"] == DOCS_API


def test_token_without_resource_uses_default_resources_callable(
    test_client, client, user, jwks, resource_indicator
):
    resource_indicator.default_resources = lambda grant, resources: resources[-1:]
    token = issue_token(test_client, client, user, [DOCS_API, SEARCH_API])
    claims = jwt.decode(token["access_token"], jwks)
    assert claims["aud"] == SEARCH_API


def test_authorization_request_rejects_resource_with_fragment(
    test_client, client, user
):
    res = authorize(test_client, client, user, [f"{DOCS_API}#fragment"])
    assert res.status_code == 302
    params = dict(url_decode(urlparse.urlparse(res.location).query))
    assert params["error"] == "invalid_target"


def test_authorization_request_rejects_relative_resource(test_client, client, user):
    res = authorize(test_client, client, user, ["docs-api"])
    assert res.status_code == 302
    params = dict(url_decode(urlparse.urlparse(res.location).query))
    assert params["error"] == "invalid_target"


def test_authorization_request_resources_policy(
    test_client, client, user, resource_indicator
):
    # the application decides which resources can be authorized together
    resource_indicator.validate_resources = lambda grant, resources: len(resources) == 1
    res = authorize(test_client, client, user, [DOCS_API, SEARCH_API])
    assert res.status_code == 302
    params = dict(url_decode(urlparse.urlparse(res.location).query))
    assert params["error"] == "invalid_target"

    res = authorize(test_client, client, user, [DOCS_API])
    assert res.status_code == 302
    assert "error" not in dict(url_decode(urlparse.urlparse(res.location).query))


def test_token_request_rejects_resource_outside_consented_set(
    test_client, client, user
):
    res = authorize(test_client, client, user, [DOCS_API])
    code = get_code(res)
    res = request_token(test_client, client, code, [SEARCH_API])
    assert res.status_code == 400
    assert res.json["error"] == "invalid_target"


def test_token_request_rejects_resource_when_nothing_consented(
    test_client, client, user
):
    res = authorize(test_client, client, user)
    code = get_code(res)
    res = request_token(test_client, client, code, [DOCS_API])
    assert res.status_code == 400
    assert res.json["error"] == "invalid_target"


def test_token_request_rejects_malformed_resource(test_client, client, user):
    res = authorize(test_client, client, user, [DOCS_API])
    code = get_code(res)
    res = request_token(test_client, client, code, [f"{DOCS_API}#fragment"])
    assert res.status_code == 400
    assert res.json["error"] == "invalid_target"


def test_resource_servers_accept_and_reject_the_same_jwt(
    test_client, client, user, resource_apis
):
    token = issue_token(test_client, client, user, [DOCS_API])

    # the documentation API accepts the token issued for it
    res = test_client.get("/docs", headers=create_bearer_header(token["access_token"]))
    assert res.status_code == 200

    # the search API rejects the very same token, even if the "read"
    # scope would be valid there
    res = test_client.get(
        "/search", headers=create_bearer_header(token["access_token"])
    )
    assert res.status_code == 401


def test_refresh_token_keeps_the_resource_boundary(
    test_client, client, user, jwks, resource_apis
):
    token = issue_token(test_client, client, user, [DOCS_API])

    # refreshing without a "resource" parameter keeps the original resources
    res = request_refresh(test_client, client, token["refresh_token"])
    assert res.status_code == 200, res.json
    refreshed = res.json
    claims = jwt.decode(refreshed["access_token"], jwks)
    assert claims["aud"] == DOCS_API

    res = test_client.get(
        "/docs", headers=create_bearer_header(refreshed["access_token"])
    )
    assert res.status_code == 200
    res = test_client.get(
        "/search", headers=create_bearer_header(refreshed["access_token"])
    )
    assert res.status_code == 401

    # the boundary survives a second refresh as well
    res = request_refresh(test_client, client, refreshed["refresh_token"])
    assert res.status_code == 200, res.json
    claims = jwt.decode(res.json["access_token"], jwks)
    assert claims["aud"] == DOCS_API


def test_refresh_token_can_narrow_resources(
    test_client, client, user, jwks, resource_apis
):
    token = issue_token(test_client, client, user, [DOCS_API, SEARCH_API])
    res = request_refresh(test_client, client, token["refresh_token"], [SEARCH_API])
    assert res.status_code == 200, res.json
    narrowed = res.json
    claims = jwt.decode(narrowed["access_token"], jwks)
    assert claims["aud"] == SEARCH_API

    res = test_client.get(
        "/search", headers=create_bearer_header(narrowed["access_token"])
    )
    assert res.status_code == 200
    res = test_client.get(
        "/docs", headers=create_bearer_header(narrowed["access_token"])
    )
    assert res.status_code == 401


def test_refresh_token_cannot_expand_resources(test_client, client, user):
    token = issue_token(test_client, client, user, [DOCS_API])
    res = request_refresh(
        test_client, client, token["refresh_token"], [DOCS_API, SEARCH_API]
    )
    assert res.status_code == 400
    assert res.json["error"] == "invalid_target"

    res = request_refresh(test_client, client, token["refresh_token"], [SEARCH_API])
    assert res.status_code == 400
    assert res.json["error"] == "invalid_target"


def test_generate_token_without_resources_keeps_default_audience(
    server, client, user, jwks
):
    # applications that did not enable the extension keep the former behavior
    token = server.generate_token("authorization_code", client, user=user, scope="read")
    claims = jwt.decode(token["access_token"], jwks)
    assert claims["aud"] == client.client_id
