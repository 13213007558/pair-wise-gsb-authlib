import time
import types

import pytest
from flask import json
from flask import jsonify
from werkzeug.datastructures import MultiDict

from authlib.common.security import generate_token
from authlib.common.urls import url_decode
from authlib.common.urls import urlparse
from authlib.integrations.flask_oauth2 import ResourceProtector
from authlib.jose import jwt
from authlib.oauth2.rfc6749.grants import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
)
from authlib.oauth2.rfc6749.grants import RefreshTokenGrant as _RefreshTokenGrant
from authlib.oauth2.rfc6750 import BearerTokenValidator
from authlib.oauth2.rfc8707 import InvalidTargetError
from authlib.oauth2.rfc9068 import JWTBearerTokenGenerator
from authlib.oauth2.rfc9068 import JWTBearerTokenValidator
from tests.util import read_file_path

from .models import AuthorizationCode
from .models import CodeGrantMixin
from .models import Token
from .models import User
from .models import db
from .models import save_authorization_code
from .oauth2_server import create_basic_header
from .oauth2_server import create_bearer_header

ISSUER = "https://authlib.test/"
BILLING = "https://billing.example.com"
REPORTS = "https://reports.example.com"
UNKNOWN = "https://unknown.example.com"

ALLOWED_RESOURCES = {BILLING, REPORTS}


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


def save_token_with_resources(token, request):
    if request.user:
        user_id = request.user.get_user_id()
    else:
        user_id = None
    item = Token(
        client_id=request.client.client_id,
        user_id=user_id,
        resources=" ".join(request.resources or []),
        **token,
    )
    db.session.add(item)
    db.session.commit()


def validate_requested_resources(self, resources, client):
    if not set(resources).issubset(ALLOWED_RESOURCES):
        raise InvalidTargetError()


@pytest.fixture(autouse=True)
def server(server, jwks):
    class MyJWTBearerTokenGenerator(JWTBearerTokenGenerator):
        def get_jwks(self):
            return jwks

    server.register_token_generator(
        "default",
        MyJWTBearerTokenGenerator(
            issuer=ISSUER,
            refresh_token_generator=lambda **kwargs: generate_token(48),
        ),
    )
    server.register_grant(AuthorizationCodeGrant)
    server.register_grant(RefreshTokenGrant)

    # application provided policy hooks
    server.validate_requested_resources = types.MethodType(
        validate_requested_resources, server
    )
    # persist the resources of opaque tokens through the model interface
    server._save_token = save_token_with_resources
    return server


@pytest.fixture
def jwks():
    return read_file_path("jwks_private.json")


@pytest.fixture(autouse=True)
def client(client, db):
    client.set_client_metadata(
        {
            "scope": "profile",
            "redirect_uris": ["https://client.test/authorized"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "client_secret_basic",
            "grant_types": ["authorization_code", "refresh_token"],
        }
    )
    db.session.add(client)
    db.session.commit()
    return client


@pytest.fixture(autouse=True)
def resource_servers(app, jwks):
    class MyJWTBearerTokenValidator(JWTBearerTokenValidator):
        def get_jwks(self):
            return jwks

    billing_jwt = ResourceProtector()
    billing_jwt.register_token_validator(
        MyJWTBearerTokenValidator(issuer=ISSUER, resource_server=BILLING)
    )
    reports_jwt = ResourceProtector()
    reports_jwt.register_token_validator(
        MyJWTBearerTokenValidator(issuer=ISSUER, resource_server=REPORTS)
    )

    class MyBearerTokenValidator(BearerTokenValidator):
        def authenticate_token(self, token_string):
            return Token.query.filter_by(access_token=token_string).first()

    billing_opaque = ResourceProtector()
    billing_opaque.register_token_validator(
        MyBearerTokenValidator(resource_server=BILLING)
    )
    reports_opaque = ResourceProtector()
    reports_opaque.register_token_validator(
        MyBearerTokenValidator(resource_server=REPORTS)
    )

    @app.route("/billing")
    @billing_jwt("profile")
    def billing():
        return jsonify(resource="billing")

    @app.route("/reports")
    @reports_jwt("profile")
    def reports():
        return jsonify(resource="reports")

    @app.route("/opaque/billing")
    @billing_opaque("profile")
    def opaque_billing():
        return jsonify(resource="billing")

    @app.route("/opaque/reports")
    @reports_opaque("profile")
    def opaque_reports():
        return jsonify(resource="reports")


def authorize(test_client, client, user, resources=None):
    data = MultiDict(
        [
            ("response_type", "code"),
            ("client_id", client.client_id),
            ("redirect_uri", "https://client.test/authorized"),
            ("scope", "profile"),
            ("user_id", str(user.id)),
        ]
    )
    for resource in resources or []:
        data.add("resource", resource)
    return test_client.post("/oauth/authorize", data=data)


def get_code(response):
    params = dict(url_decode(urlparse.urlparse(response.location).query))
    return params["code"]


def exchange_code(test_client, client, code, resources=None):
    data = MultiDict(
        [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", "https://client.test/authorized"),
        ]
    )
    for resource in resources or []:
        data.add("resource", resource)
    headers = create_basic_header(client.client_id, client.client_secret)
    return test_client.post("/oauth/token", data=data, headers=headers)


def refresh(test_client, client, refresh_token, resources=None):
    data = MultiDict(
        [("grant_type", "refresh_token"), ("refresh_token", refresh_token)]
    )
    for resource in resources or []:
        data.add("resource", resource)
    headers = create_basic_header(client.client_id, client.client_secret)
    return test_client.post("/oauth/token", data=data, headers=headers)


def decode(token, jwks):
    return jwt.decode(token, read_file_path("jwks_public.json"))


def issue_token(test_client, client, user, auth_resources, token_resources=None):
    res = authorize(test_client, client, user, auth_resources)
    assert res.status_code == 302
    code = get_code(res)
    return exchange_code(test_client, client, code, token_resources)


def test_authorization_code_stores_consented_resources(test_client, client, user):
    res = authorize(test_client, client, user, [BILLING, REPORTS, BILLING])
    assert res.status_code == 302
    code = get_code(res)
    item = AuthorizationCode.query.filter_by(code=code).one()
    # repeated values are preserved and de-duplicated
    assert item.get_resources() == [BILLING, REPORTS]


def test_token_for_all_consented_resources(test_client, client, user, jwks):
    res = issue_token(test_client, client, user, [BILLING, REPORTS])
    assert res.status_code == 200
    claims = decode(res.json["access_token"], jwks)
    assert claims["aud"] == [BILLING, REPORTS]

    headers = create_bearer_header(res.json["access_token"])
    assert test_client.get("/billing", headers=headers).status_code == 200
    assert test_client.get("/reports", headers=headers).status_code == 200


def test_token_request_selects_subset(test_client, client, user, jwks):
    res = issue_token(test_client, client, user, [BILLING, REPORTS], [BILLING])
    assert res.status_code == 200
    claims = decode(res.json["access_token"], jwks)
    assert claims["aud"] == BILLING

    headers = create_bearer_header(res.json["access_token"])
    assert test_client.get("/billing", headers=headers).status_code == 200
    # audience mismatch: signature and scope are valid, but the token does
    # not target the reports API
    assert test_client.get("/reports", headers=headers).status_code == 401


def test_token_request_resource_not_granted(test_client, client, user):
    res = issue_token(test_client, client, user, [BILLING], [BILLING, REPORTS])
    resp = json.loads(res.data)
    assert resp["error"] == "invalid_target"


def test_token_request_unknown_resource(test_client, client, user):
    res = issue_token(test_client, client, user, [BILLING, REPORTS], [UNKNOWN])
    resp = json.loads(res.data)
    assert resp["error"] == "invalid_target"


def test_authorize_unknown_resource_rejected_by_policy(test_client, client, user):
    res = authorize(test_client, client, user, [UNKNOWN])
    assert res.status_code == 302
    params = dict(url_decode(urlparse.urlparse(res.location).query))
    assert params["error"] == "invalid_target"


def test_authorize_malformed_resource(test_client, client, user):
    res = authorize(test_client, client, user, ["not-an-absolute-uri"])
    assert res.status_code == 302
    params = dict(url_decode(urlparse.urlparse(res.location).query))
    assert params["error"] == "invalid_target"

    res = authorize(test_client, client, user, [BILLING + "/#fragment"])
    assert res.status_code == 302
    params = dict(url_decode(urlparse.urlparse(res.location).query))
    assert params["error"] == "invalid_target"


def test_token_request_malformed_resource(test_client, client, user):
    res = authorize(test_client, client, user, [BILLING])
    code = get_code(res)
    res = exchange_code(test_client, client, code, ["not-an-absolute-uri"])
    resp = json.loads(res.data)
    assert resp["error"] == "invalid_target"


def test_no_resource_no_default_audience(test_client, client, user, jwks):
    # without an explicit policy, no resource means no resource audience,
    # the token must not silently target every resource server
    res = issue_token(test_client, client, user, None)
    assert res.status_code == 200
    claims = decode(res.json["access_token"], jwks)
    assert claims["aud"] == client.client_id

    headers = create_bearer_header(res.json["access_token"])
    assert test_client.get("/billing", headers=headers).status_code == 401
    assert test_client.get("/reports", headers=headers).status_code == 401


def test_default_resources_come_from_policy(test_client, client, user, jwks, server):
    server.get_default_resources = types.MethodType(
        lambda self, client: [BILLING], server
    )
    res = issue_token(test_client, client, user, None)
    assert res.status_code == 200
    claims = decode(res.json["access_token"], jwks)
    assert claims["aud"] == BILLING

    headers = create_bearer_header(res.json["access_token"])
    assert test_client.get("/billing", headers=headers).status_code == 200
    assert test_client.get("/reports", headers=headers).status_code == 401


def test_refresh_keeps_original_resources(test_client, client, user, jwks):
    res = issue_token(test_client, client, user, [BILLING, REPORTS])
    res = refresh(test_client, client, res.json["refresh_token"])
    assert res.status_code == 200
    claims = decode(res.json["access_token"], jwks)
    assert claims["aud"] == [BILLING, REPORTS]


def test_refresh_narrows_resources(test_client, client, user, jwks):
    res = issue_token(test_client, client, user, [BILLING, REPORTS])
    res = refresh(test_client, client, res.json["refresh_token"], [REPORTS])
    assert res.status_code == 200
    claims = decode(res.json["access_token"], jwks)
    assert claims["aud"] == REPORTS

    headers = create_bearer_header(res.json["access_token"])
    assert test_client.get("/reports", headers=headers).status_code == 200
    assert test_client.get("/billing", headers=headers).status_code == 401


def test_refresh_cannot_widen_resources(test_client, client, user):
    res = issue_token(test_client, client, user, [BILLING])
    res = refresh(test_client, client, res.json["refresh_token"], [REPORTS])
    resp = json.loads(res.data)
    assert resp["error"] == "invalid_target"


def test_refresh_unknown_resource(test_client, client, user):
    res = issue_token(test_client, client, user, [BILLING, REPORTS])
    res = refresh(test_client, client, res.json["refresh_token"], [UNKNOWN])
    resp = json.loads(res.data)
    assert resp["error"] == "invalid_target"


def test_opaque_token_audience_matrix(test_client, client, user):
    res = issue_token(test_client, client, user, [BILLING, REPORTS], [BILLING])
    assert res.status_code == 200
    token = Token.query.filter_by(access_token=res.json["access_token"]).one()
    assert token.get_resources() == [BILLING]

    headers = create_bearer_header(res.json["access_token"])
    assert test_client.get("/opaque/billing", headers=headers).status_code == 200
    # same scope, valid token, but the audience does not match
    assert test_client.get("/opaque/reports", headers=headers).status_code == 401


def test_opaque_token_without_resources_rejected(test_client, client, user):
    res = issue_token(test_client, client, user, None)
    assert res.status_code == 200
    headers = create_bearer_header(res.json["access_token"])
    assert test_client.get("/opaque/billing", headers=headers).status_code == 401
    assert test_client.get("/opaque/reports", headers=headers).status_code == 401
