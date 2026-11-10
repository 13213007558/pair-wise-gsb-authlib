import time

import pytest
from flask import json
from werkzeug.datastructures import MultiDict

from authlib.common.urls import url_decode
from authlib.common.urls import urlparse
from authlib.oauth2.rfc6749.grants import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
)
from authlib.oauth2.rfc6749.grants import RefreshTokenGrant as _RefreshTokenGrant
from authlib.oauth2.rfc8707 import InvalidTargetError
from authlib.oauth2.rfc8707 import ResourceIndicators

from .models import AuthorizationCode
from .models import Token
from .models import User
from .models import db
from .oauth2_server import create_basic_header

RESOURCE_A = "https://resource-a.example.com/"
RESOURCE_B = "https://resource-b.example.com/api"
RESOURCE_C = "https://resource-c.example.com/"

authorize_url = "/oauth/authorize?response_type=code&client_id=client-id"


class AuthorizationCodeGrant(_AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ["client_secret_basic", "client_secret_post", "none"]

    def save_authorization_code(self, code, request):
        auth_code = AuthorizationCode(
            code=code,
            client_id=request.client.client_id,
            redirect_uri=request.payload.redirect_uri,
            scope=request.scope,
            user_id=request.user.id,
            resources=request.resources,
        )
        db.session.add(auth_code)
        db.session.commit()
        return auth_code

    def query_authorization_code(self, code, client):
        item = AuthorizationCode.query.filter_by(
            code=code, client_id=client.client_id
        ).first()
        if item and not item.is_expired():
            return item

    def delete_authorization_code(self, authorization_code):
        db.session.delete(authorization_code)
        db.session.commit()

    def authenticate_user(self, authorization_code):
        return db.session.get(User, authorization_code.user_id)


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


def save_token(token, request):
    item = Token(
        client_id=request.client.client_id,
        user_id=request.user.id,
        resources=request.resources,
        **token,
    )
    db.session.add(item)
    db.session.commit()


@pytest.fixture(autouse=True)
def server(server):
    server.save_token = save_token
    server.register_grant(AuthorizationCodeGrant, [ResourceIndicators()])
    server.register_grant(RefreshTokenGrant, [ResourceIndicators()])
    return server


@pytest.fixture(autouse=True)
def client(client, db):
    client.set_client_metadata(
        {
            "redirect_uris": ["https://client.test"],
            "scope": "profile",
            "token_endpoint_auth_method": "client_secret_basic",
            "response_types": ["code"],
            "grant_types": ["authorization_code", "refresh_token"],
        }
    )
    db.session.add(client)
    db.session.commit()
    return client


@pytest.fixture(autouse=True)
def refresh_config(app, server):
    app.config.update({"OAUTH2_REFRESH_TOKEN_GENERATOR": True})
    server.load_config(app.config)


def get_code(test_client, resources):
    """Run the consent step and exchange nothing; return the authorization code."""
    data = MultiDict([("user_id", "1")])
    for item in resources:
        data.add("resource", item)
    rv = test_client.post(authorize_url, data=data)
    assert rv.status_code in (302, 303), rv.data
    params = dict(url_decode(urlparse.urlparse(rv.location).query))
    assert "code" in params, params
    return params["code"]


def exchange_code(test_client, code, resources=None):
    data = MultiDict([("grant_type", "authorization_code"), ("code", code)])
    for item in resources or []:
        data.add("resource", item)
    return test_client.post(
        "/oauth/token",
        data=data,
        headers=create_basic_header("client-id", "client-secret"),
    )


def test_consent_stores_all_resources(test_client):
    """Multiple resource parameters are all validated and stored with the code."""
    code = get_code(test_client, [RESOURCE_A, RESOURCE_B])
    auth_code = AuthorizationCode.query.filter_by(code=code).one()
    assert auth_code.get_resources() == [RESOURCE_A, RESOURCE_B]


def test_consent_rejects_relative_uri(test_client):
    rv = test_client.post(
        authorize_url,
        data=MultiDict([("user_id", "1"), ("resource", "/not-absolute")]),
    )
    params = dict(url_decode(urlparse.urlparse(rv.location).query))
    assert params["error"] == "invalid_target"


def test_consent_rejects_fragment(test_client):
    rv = test_client.post(
        authorize_url,
        data=MultiDict(
            [
                ("user_id", "1"),
                ("resource", "https://resource-a.example.com/#fragment"),
            ]
        ),
    )
    params = dict(url_decode(urlparse.urlparse(rv.location).query))
    assert params["error"] == "invalid_target"


def test_consent_requires_resource_by_default(test_client):
    rv = test_client.post(authorize_url, data={"user_id": "1"})
    params = dict(url_decode(urlparse.urlparse(rv.location).query))
    assert params["error"] == "invalid_target"
    assert AuthorizationCode.query.count() == 0


def test_full_flow_audience_in_token_generator(test_client, server):
    """The generator receives the authorized set through the resource keyword."""
    seen = []

    def generator(
        grant_type,
        client,
        user=None,
        scope=None,
        expires_in=None,
        include_refresh_token=True,
        resource=None,
    ):
        seen.append(list(resource or []))
        return {
            "token_type": "Bearer",
            "access_token": "access",
            "refresh_token": "refresh",
        }

    server.register_token_generator("default", generator)
    code = get_code(test_client, [RESOURCE_A, RESOURCE_B])
    rv = exchange_code(test_client, code)
    assert rv.status_code == 200, rv.data
    assert seen == [[RESOURCE_A, RESOURCE_B]]


def test_exchange_without_resource_uses_whole_set(test_client, server):
    code = get_code(test_client, [RESOURCE_A, RESOURCE_B])
    rv = exchange_code(test_client, code)
    assert rv.status_code == 200, rv.data
    token = Token.query.filter_by(
        access_token=json.loads(rv.data)["access_token"]
    ).one()
    assert token.get_resources() == [RESOURCE_A, RESOURCE_B]


def test_exchange_with_subset(test_client):
    code = get_code(test_client, [RESOURCE_A, RESOURCE_B])
    rv = exchange_code(test_client, code, [RESOURCE_B])
    assert rv.status_code == 200, rv.data
    token = Token.query.filter_by(
        access_token=json.loads(rv.data)["access_token"]
    ).one()
    assert token.get_resources() == [RESOURCE_B]


def test_exchange_with_unauthorized_resource(test_client):
    code = get_code(test_client, [RESOURCE_A, RESOURCE_B])
    rv = exchange_code(test_client, code, [RESOURCE_C])
    assert rv.status_code == 400
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_target"
    # A failed request must not save a token
    assert Token.query.count() == 0


def test_exchange_keeps_repeated_values_and_order(test_client):
    """Repeated resource parameters at the token endpoint are preserved."""
    code = get_code(test_client, [RESOURCE_A, RESOURCE_B, RESOURCE_A])
    rv = exchange_code(test_client, code, [RESOURCE_B, RESOURCE_A])
    assert rv.status_code == 200, rv.data
    token = Token.query.filter_by(
        access_token=json.loads(rv.data)["access_token"]
    ).one()
    assert token.get_resources() == [RESOURCE_B, RESOURCE_A]


def test_exchange_rejects_fragment_variant(test_client):
    code = get_code(test_client, [RESOURCE_A])
    rv = exchange_code(test_client, code, ["https://resource-a.example.com/#x"])
    assert rv.status_code == 400
    assert json.loads(rv.data)["error"] == "invalid_target"
    assert Token.query.count() == 0


def test_exchange_rejects_relative_variant(test_client):
    code = get_code(test_client, [RESOURCE_A])
    rv = exchange_code(test_client, code, ["resource-a.example.com/"])
    assert rv.status_code == 400
    assert json.loads(rv.data)["error"] == "invalid_target"
    assert Token.query.count() == 0


def test_query_variant_is_a_different_indicator(test_client):
    """A query string changes the URI, so it is not the authorized indicator."""
    code = get_code(test_client, [RESOURCE_A])
    rv = exchange_code(test_client, code, ["https://resource-a.example.com/?x=1"])
    assert rv.status_code == 400
    assert json.loads(rv.data)["error"] == "invalid_target"


def refresh(test_client, refresh_token, resources=None):
    data = MultiDict(
        [("grant_type", "refresh_token"), ("refresh_token", refresh_token)]
    )
    for item in resources or []:
        data.add("resource", item)
    return test_client.post(
        "/oauth/token",
        data=data,
        headers=create_basic_header("client-id", "client-secret"),
    )


def test_refresh_keeps_resources(test_client):
    code = get_code(test_client, [RESOURCE_A, RESOURCE_B])
    rv = exchange_code(test_client, code)
    refresh_token = json.loads(rv.data)["refresh_token"]

    rv = refresh(test_client, refresh_token)
    assert rv.status_code == 200, rv.data
    token = Token.query.filter_by(
        access_token=json.loads(rv.data)["access_token"]
    ).one()
    assert token.get_resources() == [RESOURCE_A, RESOURCE_B]


def test_refresh_with_subset(test_client):
    code = get_code(test_client, [RESOURCE_A, RESOURCE_B])
    refresh_token = json.loads(exchange_code(test_client, code).data)["refresh_token"]

    rv = refresh(test_client, refresh_token, [RESOURCE_A])
    assert rv.status_code == 200, rv.data
    token = Token.query.filter_by(
        access_token=json.loads(rv.data)["access_token"]
    ).one()
    assert token.get_resources() == [RESOURCE_A]


def test_refresh_cannot_add_new_resource(test_client):
    code = get_code(test_client, [RESOURCE_A])
    refresh_token = json.loads(exchange_code(test_client, code).data)["refresh_token"]
    before = Token.query.count()

    rv = refresh(test_client, refresh_token, [RESOURCE_C])
    assert rv.status_code == 400
    assert json.loads(rv.data)["error"] == "invalid_target"
    assert Token.query.count() == before


def test_legacy_generator_still_works(test_client, server):
    """A generator without the resource keyword is called unchanged."""

    def legacy_generator(
        grant_type,
        client,
        user=None,
        scope=None,
        expires_in=None,
        include_refresh_token=True,
    ):
        return {
            "token_type": "Bearer",
            "access_token": "legacy-access",
            "refresh_token": "legacy-refresh",
        }

    server.register_token_generator("default", legacy_generator)
    code = get_code(test_client, [RESOURCE_A])
    rv = exchange_code(test_client, code)
    assert rv.status_code == 200, rv.data
    assert json.loads(rv.data)["access_token"] == "legacy-access"


def test_allow_without_resource(server, test_client):
    """With allow_without_resource, a request without resource keeps legacy behavior."""

    server._authorization_grants.clear()
    server._token_grants.clear()
    server.register_grant(
        AuthorizationCodeGrant, [ResourceIndicators(allow_without_resource=True)]
    )
    server.register_grant(
        RefreshTokenGrant, [ResourceIndicators(allow_without_resource=True)]
    )

    rv = test_client.post(authorize_url, data={"user_id": "1"})
    assert rv.status_code in (302, 303)
    code = dict(url_decode(urlparse.urlparse(rv.location).query))["code"]

    rv = exchange_code(test_client, code)
    assert rv.status_code == 200, rv.data
    token = Token.query.filter_by(
        access_token=json.loads(rv.data)["access_token"]
    ).one()
    assert token.get_resources() is None


def test_loose_mode_still_rejects_unauthorized_resource(server, test_client):
    """allow_without_resource never lets a token exchange invent a resource."""
    server._authorization_grants.clear()
    server._token_grants.clear()
    server.register_grant(
        AuthorizationCodeGrant, [ResourceIndicators(allow_without_resource=True)]
    )

    rv = test_client.post(authorize_url, data={"user_id": "1"})
    code = dict(url_decode(urlparse.urlparse(rv.location).query))["code"]

    rv = exchange_code(test_client, code, [RESOURCE_A])
    assert rv.status_code == 400
    assert json.loads(rv.data)["error"] == "invalid_target"
    assert Token.query.count() == 0


def test_invalid_target_error_class():
    assert InvalidTargetError.error == "invalid_target"
    assert InvalidTargetError().status_code == 400
