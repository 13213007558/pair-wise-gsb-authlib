"""End-to-end RFC 8707 matrix for one OAuth client accessing two APIs
(``billing`` and ``reports``): authorization with repeated ``resource``
parameters, token exchange with subsets, refresh narrowing, and protected
resource access with audience verification (for both JWT and opaque tokens).
"""

import pytest
from flask import jsonify
from joserfc import jwt
from joserfc.jwk import KeySet
from werkzeug.datastructures import MultiDict

from authlib.integrations.flask_oauth2 import ResourceProtector
from authlib.oauth2.rfc6749.grants import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
)
from authlib.oauth2.rfc6749.grants import RefreshTokenGrant as _RefreshTokenGrant
from authlib.oauth2.rfc8707 import ResourcePolicy
from authlib.oauth2.rfc9068 import JWTBearerTokenGenerator
from authlib.oauth2.rfc9068 import JWTBearerTokenValidator
from tests.util import read_file_path

from ..models import CodeGrantMixin
from ..models import Token
from ..models import save_authorization_code

BILLING = "https://billing.example.net"
REPORTS = "https://reports.example.com"
ISSUER = "https://authorization-server.example.org"


class FixedResourcePolicy(ResourcePolicy):
    """A policy which authorizes resources registered on the client and
    defaults token requests without ``resource`` to the billing API only.
    """

    def get_allowed_resources(self, client, resources, request):
        allowed = set(client.client_metadata.get("resources", []))
        from authlib.oauth2.rfc8707 import InvalidTargetError

        for resource in resources:
            if resource not in allowed:
                raise InvalidTargetError("The resource indicator is not authorized.")
        return resources

    def get_default_resources(self, client, request, authorized_resources=None):
        if authorized_resources and BILLING in authorized_resources:
            return [BILLING]
        return []


class AuthorizationCodeGrant(CodeGrantMixin, _AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ["client_secret_basic", "client_secret_post"]

    def save_authorization_code(self, code, request):
        return save_authorization_code(code, request)


class RefreshTokenGrant(_RefreshTokenGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ["client_secret_basic", "client_secret_post"]
    INCLUDE_NEW_REFRESH_TOKEN = True

    def authenticate_refresh_token(self, refresh_token):
        item = Token.query.filter_by(refresh_token=refresh_token).first()
        if item and item.is_refresh_token_active():
            return item

    def authenticate_user(self, credential):
        from ..models import User

        from ..models import db

        return db.session.get(User, credential.user_id)

    def revoke_old_credential(self, credential):
        from ..models import db

        import time

        credential.refresh_token_revoked_at = int(time.time())
        db.session.add(credential)
        db.session.commit()


@pytest.fixture
def jwks():
    return read_file_path("jwks_private.json")


@pytest.fixture(autouse=True)
def server(server, jwks):
    from authlib.common.security import generate_token

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
    server.register_resource_policy(FixedResourcePolicy())
    return server


@pytest.fixture(autouse=True)
def client(client, db):
    client.set_client_metadata(
        {
            "redirect_uris": ["https://client.test/authorized"],
            "scope": "profile",
            "token_endpoint_auth_method": "client_secret_post",
            "response_types": ["code"],
            "grant_types": ["authorization_code", "refresh_token"],
            "resources": [BILLING, REPORTS],
        }
    )
    db.session.add(client)
    db.session.commit()
    return client


class _JWTValidator(JWTBearerTokenValidator):
    def __init__(self, resource_server, jwks):
        super().__init__(issuer=ISSUER, resource_server=resource_server)
        self._jwks = jwks

    def get_jwks(self):
        return self._jwks


@pytest.fixture(autouse=True)
def protected_resources(app, jwks):
    billing = ResourceProtector()
    billing.register_token_validator(_JWTValidator(BILLING, jwks))
    reports = ResourceProtector()
    reports.register_token_validator(_JWTValidator(REPORTS, jwks))

    @app.route("/billing/me")
    @billing("profile")
    def billing_me():
        return jsonify(api="billing")

    @app.route("/reports/me")
    @reports("profile")
    def reports_me():
        return jsonify(api="reports")


def _authorize(test_client, client, user, *resources):
    data = [
        ("response_type", "code"),
        ("client_id", client.client_id),
        ("redirect_uri", client.redirect_uris[0]),
        ("scope", "profile"),
        ("user_id", str(user.id)),
    ]
    data.extend(("resource", resource) for resource in resources)
    rv = test_client.post("/oauth/authorize", data=MultiDict(data))
    from authlib.common.urls import url_decode
    from authlib.common.urls import urlparse

    params = dict(url_decode(urlparse.urlparse(rv.location).query))
    assert "code" in params, rv.location
    return params["code"]


def _exchange(test_client, client, code, *resources):
    data = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("client_id", client.client_id),
        ("client_secret", client.client_secret),
        ("redirect_uri", client.redirect_uris[0]),
    ]
    data.extend(("resource", resource) for resource in resources)
    rv = test_client.post("/oauth/token", data=MultiDict(data))
    return rv


def _refresh(test_client, client, refresh_token, *resources):
    data = [
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", client.client_id),
        ("client_secret", client.client_secret),
    ]
    data.extend(("resource", resource) for resource in resources)
    return test_client.post("/oauth/token", data=MultiDict(data))


def _aud(access_token):
    key = KeySet.import_key_set(read_file_path("jwks_public.json"))
    return jwt.decode(access_token, key=key).claims["aud"]


def test_authorization_keeps_repeated_resources(test_client, client, user, db):
    code = _authorize(test_client, client, user, BILLING, REPORTS)

    from ..models import AuthorizationCode

    saved = AuthorizationCode.query.filter_by(code=code).one()
    assert saved.get_resources() == [BILLING, REPORTS]


def test_token_model_persists_final_resources(test_client, client, user, db):
    code = _authorize(test_client, client, user, BILLING, REPORTS)
    token_response = _exchange(test_client, client, code, REPORTS).json

    saved = Token.query.filter_by(
        access_token=token_response["access_token"]
    ).one()
    assert saved.get_resources() == [REPORTS]


def test_exchange_subset_matrix(test_client, client, user):
    code = _authorize(test_client, client, user, BILLING, REPORTS)

    rv = _exchange(test_client, client, code, BILLING)
    assert rv.status_code == 200, rv.json
    billing_token = rv.json["access_token"]
    assert _aud(billing_token) == BILLING

    # the code was consumed; a second subset needs a new authorization
    code = _authorize(test_client, client, user, BILLING, REPORTS)
    reports_token = _exchange(test_client, client, code, REPORTS).json["access_token"]
    assert _aud(reports_token) == REPORTS

    code = _authorize(test_client, client, user, BILLING, REPORTS)
    both_token = _exchange(test_client, client, code, BILLING, REPORTS).json[
        "access_token"
    ]
    assert _aud(both_token) == [BILLING, REPORTS]
    # resources are stored in the token model but are not returned as a
    # top-level token response parameter
    code = _authorize(test_client, client, user, BILLING)
    response_json = _exchange(test_client, client, code, BILLING).json
    assert "resources" not in response_json

    # a token for billing must not be accepted by the reports API even though
    # the signature and scope are valid
    headers = {"Authorization": f"Bearer {billing_token}"}
    assert test_client.get("/billing/me", headers=headers).status_code == 200
    rv = test_client.get("/reports/me", headers=headers)
    assert rv.status_code == 401
    assert rv.json["error"] == "invalid_token"

    headers = {"Authorization": f"Bearer {reports_token}"}
    assert test_client.get("/reports/me", headers=headers).status_code == 200
    assert test_client.get("/billing/me", headers=headers).status_code == 401

    # a multi-audience token is accepted by both APIs
    headers = {"Authorization": f"Bearer {both_token}"}
    assert test_client.get("/billing/me", headers=headers).json["api"] == "billing"
    assert test_client.get("/reports/me", headers=headers).json["api"] == "reports"


def test_exchange_resource_not_in_authorization(test_client, client, user):
    code = _authorize(test_client, client, user, BILLING)
    rv = _exchange(test_client, client, code, REPORTS)
    assert rv.status_code == 400
    assert rv.json["error"] == "invalid_target"


def test_invalid_resource_indicator_form(test_client, client, user):
    # not an absolute URI / with a fragment
    rv = test_client.post(
        "/oauth/authorize",
        data=MultiDict([
            ("response_type", "code"),
            ("client_id", client.client_id),
            ("redirect_uri", client.redirect_uris[0]),
            ("resource", "not-a-uri#frag"),
            ("user_id", str(user.id)),
        ]),
    )
    assert "error=invalid_target" in rv.location

    code = _authorize(test_client, client, user, BILLING, REPORTS)
    rv = _exchange(test_client, client, code, "relative/path")
    assert rv.status_code == 400
    assert rv.json["error"] == "invalid_target"


def test_unauthorized_resource_at_authorization_endpoint(test_client, client, user):
    rv = test_client.post(
        "/oauth/authorize",
        data=MultiDict([
            ("response_type", "code"),
            ("client_id", client.client_id),
            ("redirect_uri", client.redirect_uris[0]),
            ("scope", "profile"),
            ("resource", "https://forbidden.example.org"),
            ("user_id", str(user.id)),
        ]),
    )
    assert "error=invalid_target" in rv.location


def test_duplicate_resources_preserved_through_authorization(
    test_client, client, user, db
):
    code = _authorize(test_client, client, user, BILLING, BILLING, REPORTS)
    from ..models import AuthorizationCode

    saved = AuthorizationCode.query.filter_by(code=code).one()
    # duplicates collapse into the agreed set, order preserved
    assert saved.get_resources() == [BILLING, REPORTS]


def test_default_resource_is_policy_driven(test_client, client, user):
    code = _authorize(test_client, client, user, BILLING, REPORTS)
    rv = _exchange(test_client, client, code)
    assert rv.status_code == 200
    # default is billing only, never all resources
    assert _aud(rv.json["access_token"]) == BILLING


def test_refresh_can_only_narrow(test_client, client, user):
    code = _authorize(test_client, client, user, BILLING, REPORTS)
    token_response = _exchange(test_client, client, code, BILLING, REPORTS).json
    assert _aud(token_response["access_token"]) == [BILLING, REPORTS]

    # refresh with a subset
    rv = _refresh(
        test_client, client, token_response["refresh_token"], REPORTS
    )
    assert rv.status_code == 200
    narrowed = rv.json["access_token"]
    assert _aud(narrowed) == REPORTS

    # widening back to a resource outside the narrowed token is rejected
    rv = _refresh(test_client, client, rv.json["refresh_token"], BILLING, REPORTS)
    assert rv.status_code == 400
    assert rv.json["error"] == "invalid_target"

    # refresh without resource keeps the same resources
    code = _authorize(test_client, client, user, BILLING, REPORTS)
    token_response = _exchange(test_client, client, code, BILLING).json
    rv = _refresh(test_client, client, token_response["refresh_token"])
    assert _aud(rv.json["access_token"]) == BILLING


def test_opaque_token_resources_persisted_and_checked(
    test_client, app, client, user, db
):
    """Opaque tokens store the same resource information through the model
    interface (no new built-in database), and the resource protector rejects
    audience mismatches."""
    from authlib.integrations.flask_oauth2 import ResourceProtector as RP
    from authlib.oauth2.rfc6750 import BearerTokenValidator

    from ..models import Token as TokenModel

    class OpaqueValidator(BearerTokenValidator):
        def __init__(self, resource_server):
            super().__init__(resource_server=resource_server)

        def authenticate_token(self, token_string):
            return TokenModel.query.filter_by(access_token=token_string).first()

    billing = RP()
    billing.register_token_validator(OpaqueValidator(BILLING))

    @app.route("/billing/opaque")
    @billing("profile")
    def billing_opaque():
        return jsonify(api="billing")

    # mint an opaque token row bound to BILLING through the model interface
    token = TokenModel(
        user_id=user.id,
        client_id=client.client_id,
        token_type="bearer",
        access_token="opaque-billing-token",
        refresh_token="opaque-billing-refresh",
        scope="profile",
        expires_in=3600,
        resources=[BILLING],
    )
    db.session.add(token)
    db.session.commit()

    headers = {"Authorization": "Bearer opaque-billing-token"}
    assert test_client.get("/billing/opaque", headers=headers).status_code == 200

    # same opaque token presented to the reports JWT protector must fail
    rv = test_client.get("/reports/me", headers=headers)
    assert rv.status_code == 401
    assert rv.json["error"] == "invalid_token"
