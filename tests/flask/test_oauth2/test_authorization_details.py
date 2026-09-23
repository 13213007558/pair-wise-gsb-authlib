import time
from urllib.parse import quote

import pytest
from flask import json
from flask import request

from authlib.common.urls import url_decode
from authlib.common.urls import urlparse
from authlib.oauth2 import OAuth2Error
from authlib.oauth2.rfc6749.grants import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
)
from authlib.oauth2.rfc6749.grants import RefreshTokenGrant as _RefreshTokenGrant
from authlib.oauth2.rfc9396 import AuthorizationDetailsHandler
from authlib.oauth2.rfc9396 import DatasetAccessHandler
from authlib.oauth2.rfc9396 import InvalidAuthorizationDetailsError

from .models import CodeGrantMixin
from .models import Token
from .models import User
from .models import db
from .models import save_authorization_code
from .oauth2_server import create_basic_header

WEATHER = "https://datasets.example.com/weather"
TRAFFIC = "https://datasets.example.com/traffic"
SECRET = "https://datasets.example.com/secret"


def dataset_details(locations, actions):
    return {
        "type": "dataset_access",
        "locations": locations,
        "actions": actions,
    }


class PaymentInitiationHandler(AuthorizationDetailsHandler):
    """A second demo type: the `amount` cap can only be decreased. Its
    permission rule is numeric, not a generic dict subset comparison."""

    type = "payment_initiation"

    def validate(self, detail):
        amount = detail.get("amount")
        if isinstance(amount, bool) or not isinstance(amount, (int, float)):
            raise InvalidAuthorizationDetailsError(
                "'payment_initiation' requires a numeric 'amount'."
            )
        if amount <= 0:
            raise InvalidAuthorizationDetailsError(
                "'payment_initiation' requires a positive 'amount'."
            )

    def is_narrower(self, requested, consented):
        return consented.get("amount", 0) <= requested["amount"]

    def is_within(self, granted, requested):
        return requested.get("amount", 0) <= granted["amount"]


class AuthorizationCodeGrant(CodeGrantMixin, _AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ["client_secret_basic"]

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
def server(app, server):
    app.config.update({"OAUTH2_REFRESH_TOKEN_GENERATOR": True})
    server.load_config(app.config)
    server.register_grant(AuthorizationCodeGrant)
    server.register_grant(RefreshTokenGrant)
    server.register_authorization_details_handler(DatasetAccessHandler())
    server.register_authorization_details_handler(PaymentInitiationHandler())

    @app.route("/oauth/authorize_details", methods=["GET", "POST"])
    def authorize_details():
        end_user = db.session.get(User, 1)
        try:
            grant = server.get_consent_grant(end_user=end_user)
        except OAuth2Error as error:
            return server.handle_error_response(request, error)

        if request.method == "GET":
            # the consent page receives the parsed authorization details
            return json.dumps(grant.request.authorization_details)

        consented = None
        if "consented" in request.form:
            consented = json.loads(request.form["consented"])
            grant.request.consented_authorization_details = consented
        response = server.create_authorization_response(
            grant=grant, grant_user=end_user
        )
        if consented and request.form.get("mutate_after"):
            # the application callback mutates the consented dict after
            # the authorization has been saved
            consented[0]["locations"].append(SECRET)
            consented[0]["actions"].append("export")
        return response

    return server


def authorize_url(details=None, scope=None):
    url = "/oauth/authorize_details?response_type=code&client_id=client-id"
    if scope:
        url += "&scope=" + scope
    if details is not None:
        url += "&authorization_details=" + quote(json.dumps(details), safe="")
    return url


def run_code_flow(test_client, details, consented=None, mutate_after=False):
    data = {"user_id": "1"}
    if consented is not None:
        data["consented"] = json.dumps(consented)
    if mutate_after:
        data["mutate_after"] = "1"
    rv = test_client.post(authorize_url(details), data=data)
    assert "code=" in rv.location

    params = dict(url_decode(urlparse.urlparse(rv.location).query))
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": params["code"],
        },
        headers=create_basic_header("client-id", "client-secret"),
    )
    return json.loads(rv.data)


def run_refresh(test_client, refresh_token, details=None):
    data = {"grant_type": "refresh_token", "refresh_token": refresh_token}
    if details is not None:
        if not isinstance(details, str):
            details = json.dumps(details)
        data["authorization_details"] = details
    rv = test_client.post(
        "/oauth/token",
        data=data,
        headers=create_basic_header("client-id", "client-secret"),
    )
    return json.loads(rv.data)


def test_consent_page_receives_parsed_details(test_client):
    details = [dataset_details([WEATHER, TRAFFIC], ["read", "export"])]
    rv = test_client.get(authorize_url(details))
    assert json.loads(rv.data) == details


def test_full_consent_by_default(test_client):
    details = [dataset_details([WEATHER, TRAFFIC], ["read", "export"])]
    resp = run_code_flow(test_client, details)
    assert "access_token" in resp
    assert resp["authorization_details"] == details


def test_consent_narrows_datasets_and_actions(test_client):
    requested = [dataset_details([WEATHER, TRAFFIC], ["read", "export"])]
    consented = [dataset_details([WEATHER], ["read"])]
    resp = run_code_flow(test_client, requested, consented=consented)
    assert resp["authorization_details"] == consented
    assert "refresh_token" in resp

    # the refresh token only keeps the consented part
    resp = run_refresh(test_client, resp["refresh_token"])
    assert "access_token" in resp
    assert resp["authorization_details"] == consented


def test_consent_can_not_expand(test_client):
    requested = [dataset_details([WEATHER], ["read"])]
    consented = [dataset_details([WEATHER, SECRET], ["read", "export"])]
    rv = test_client.post(
        authorize_url(requested),
        data={"user_id": "1", "consented": json.dumps(consented)},
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_authorization_details"


def test_consent_mutation_does_not_alter_saved_authorization(test_client):
    requested = [dataset_details([WEATHER, TRAFFIC], ["read", "export"])]
    consented = [dataset_details([WEATHER], ["read"])]
    resp = run_code_flow(test_client, requested, consented=consented, mutate_after=True)
    assert resp["authorization_details"] == consented


def test_empty_consent(test_client):
    requested = [dataset_details([WEATHER], ["read"])]
    resp = run_code_flow(test_client, requested, consented=[])
    assert "access_token" in resp
    assert "authorization_details" not in resp

    resp = run_refresh(test_client, resp["refresh_token"])
    assert "access_token" in resp
    assert "authorization_details" not in resp


def test_refresh_can_narrow_details(test_client):
    consented = [dataset_details([WEATHER, TRAFFIC], ["read", "export"])]
    resp = run_code_flow(
        test_client,
        [dataset_details([WEATHER, TRAFFIC], ["read", "export"])],
        consented=consented,
    )
    narrowed = [dataset_details([WEATHER], ["read"])]
    resp = run_refresh(test_client, resp["refresh_token"], details=narrowed)
    assert "access_token" in resp
    assert resp["authorization_details"] == narrowed


def test_refresh_can_not_add_dataset(test_client):
    consented = [dataset_details([WEATHER], ["read"])]
    resp = run_code_flow(
        test_client,
        [dataset_details([WEATHER, TRAFFIC], ["read", "export"])],
        consented=consented,
    )
    expanded = [dataset_details([WEATHER, SECRET], ["read"])]
    resp = run_refresh(test_client, resp["refresh_token"], details=expanded)
    assert resp["error"] == "invalid_authorization_details"


def test_refresh_can_not_add_action(test_client):
    consented = [dataset_details([WEATHER], ["read"])]
    resp = run_code_flow(
        test_client,
        [dataset_details([WEATHER, TRAFFIC], ["read", "export"])],
        consented=consented,
    )
    expanded = [dataset_details([WEATHER], ["read", "export"])]
    resp = run_refresh(test_client, resp["refresh_token"], details=expanded)
    assert resp["error"] == "invalid_authorization_details"


def test_refresh_syntax_error_is_not_expansion_error(test_client):
    consented = [dataset_details([WEATHER], ["read"])]
    resp = run_code_flow(
        test_client,
        [dataset_details([WEATHER, TRAFFIC], ["read", "export"])],
        consented=consented,
    )
    refresh_token = resp["refresh_token"]

    # malformed JSON is a syntax error
    resp = run_refresh(test_client, refresh_token, details='[{"type": ')
    assert resp["error"] == "invalid_request"

    # a JSON object instead of an array is a syntax error
    resp = run_refresh(test_client, refresh_token, details='{"type": "dataset_access"}')
    assert resp["error"] == "invalid_request"


def test_authorize_syntax_error_is_not_expansion_error(test_client):
    # malformed JSON is a syntax error
    url = authorize_url() + "&authorization_details=" + quote('[{"type": ')
    rv = test_client.get(url)
    assert "error=invalid_request" in rv.location

    # missing "type" is a syntax error
    url = authorize_url() + "&authorization_details=" + quote('[{"locations": []}]')
    rv = test_client.get(url)
    assert "error=invalid_request" in rv.location

    # not a JSON array is a syntax error
    url = authorize_url() + "&authorization_details=" + quote('{"type": "x"}')
    rv = test_client.get(url)
    assert "error=invalid_request" in rv.location


def test_unknown_detail_type(test_client):
    details = [{"type": "unknown_type"}]
    rv = test_client.get(authorize_url(details))
    assert "error=invalid_authorization_details" in rv.location


def test_invalid_detail_for_type(test_client):
    details = [dataset_details([WEATHER], ["read", "delete"])]
    rv = test_client.get(authorize_url(details))
    assert "error=invalid_authorization_details" in rv.location


def test_mixed_detail_types(test_client):
    requested = [
        dataset_details([WEATHER, TRAFFIC], ["read", "export"]),
        {"type": "payment_initiation", "amount": 100},
    ]
    consented = [
        dataset_details([WEATHER], ["read"]),
        {"type": "payment_initiation", "amount": 50},
    ]
    resp = run_code_flow(test_client, requested, consented=consented)
    assert resp["authorization_details"] == consented

    # each type keeps its own permission rule on refresh
    expanded = [{"type": "payment_initiation", "amount": 60}]
    resp = run_refresh(test_client, resp["refresh_token"], details=expanded)
    assert resp["error"] == "invalid_authorization_details"


def test_scope_and_details_coexist(test_client):
    details = [dataset_details([WEATHER], ["read"])]
    data = {"user_id": "1"}
    rv = test_client.post(authorize_url(details, scope="profile"), data=data)
    assert "code=" in rv.location

    params = dict(url_decode(urlparse.urlparse(rv.location).query))
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": params["code"],
        },
        headers=create_basic_header("client-id", "client-secret"),
    )
    resp = json.loads(rv.data)
    assert resp["scope"] == "profile"
    assert resp["authorization_details"] == details
