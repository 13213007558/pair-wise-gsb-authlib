import copy
import time
from urllib.parse import urlencode

import pytest
from flask import json
from flask import request

from authlib.common.urls import url_decode
from authlib.common.urls import urlparse
from authlib.integrations.flask_oauth2 import (
    AuthorizationServer as _AuthorizationServer,
)
from authlib.integrations.sqla_oauth2 import create_query_client_func
from authlib.integrations.sqla_oauth2 import create_save_token_func
from authlib.oauth2 import OAuth2Error
from authlib.oauth2.rfc6749.grants import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
)
from authlib.oauth2.rfc6749.grants import RefreshTokenGrant as _RefreshTokenGrant
from authlib.oauth2.rfc9396 import AuthorizationDetailsHandler
from authlib.oauth2.rfc9396 import InvalidAuthorizationDetailsError

from .models import Client
from .models import CodeGrantMixin
from .models import Token
from .models import User
from .models import db
from .models import save_authorization_code
from .oauth2_server import create_basic_header


class DatasetAccessHandler(AuthorizationDetailsHandler):
    """Demo type: `locations` lists the accessible datasets and
    `actions` the allowed operations; both sets can only narrow."""

    type = "dataset_access"
    ALLOWED_ACTIONS = ("read", "export")

    def validate(self, detail):
        locations = detail.get("locations")
        if (
            not isinstance(locations, list)
            or not locations
            or not all(isinstance(loc, str) for loc in locations)
        ):
            raise InvalidAuthorizationDetailsError(
                "'locations' MUST be a non-empty list of dataset names."
            )
        actions = detail.get("actions")
        if (
            not isinstance(actions, list)
            or not actions
            or any(action not in self.ALLOWED_ACTIONS for action in actions)
        ):
            raise InvalidAuthorizationDetailsError(
                "'actions' MUST be a non-empty list of 'read' and/or 'export'."
            )

    def is_within_granted(self, requested, granted):
        return set(requested["locations"]) <= set(granted["locations"]) and set(
            requested["actions"]
        ) <= set(granted["actions"])


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


#: observations made by the authorize route about the saved details
saved_details_snapshots = []


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
def server(app):
    query_client = create_query_client_func(db.session, Client)
    app.config["OAUTH2_REFRESH_TOKEN_GENERATOR"] = True
    save_token = create_save_token_func(db.session, Token)
    server = _AuthorizationServer(app, query_client, save_token)
    server.register_grant(AuthorizationCodeGrant)
    server.register_grant(RefreshTokenGrant)
    server.register_authorization_details_handler(DatasetAccessHandler())

    @app.route("/oauth/authorize", methods=["GET", "POST"])
    def authorize():
        user_id = request.values.get("user_id")
        end_user = db.session.get(User, int(user_id)) if user_id else None

        try:
            grant = server.get_consent_grant(end_user=end_user)
        except OAuth2Error as error:
            return server.handle_error_response(request, error)

        if request.method == "GET":
            # the consent page displays the parsed authorization details
            return json.dumps(grant.request.authorization_details or [])

        consented = None
        details = grant.request.authorization_details
        if details is not None:
            choice = request.form.get("consent", "all")
            if choice == "empty":
                # the user granted none of the requested details
                grant.authorization_details = []
            elif choice == "narrow":
                # the user removes "export" from the requested actions
                consented = copy.deepcopy(details)
                for item in consented:
                    if item["type"] == "dataset_access":
                        item["actions"] = [
                            action for action in item["actions"] if action != "export"
                        ]
                grant.authorization_details = consented

        response = server.create_authorization_response(
            grant=grant, grant_user=end_user
        )

        if consented is not None and request.form.get("mutate_after_save"):
            # the application callback mutates the objects it handed over;
            # the saved authorization must not follow
            consented[0]["locations"].append("ds-evil")
            saved_details_snapshots.append(grant.request.authorization_details)

        return response

    @app.route("/oauth/token", methods=["POST"])
    def issue_token():
        return server.create_token_response()

    return server


DATASET_DETAILS = [
    {
        "type": "dataset_access",
        "locations": ["ds-1", "ds-2"],
        "actions": ["read", "export"],
    }
]

READ_ONLY_DETAILS = [
    {
        "type": "dataset_access",
        "locations": ["ds-1", "ds-2"],
        "actions": ["read"],
    }
]


def authorize_params(details, **extra):
    params = {
        "response_type": "code",
        "client_id": "client-id",
        "redirect_uri": "https://client.test",
        "scope": "profile",
        "user_id": "1",
    }
    if details is not None:
        params["authorization_details"] = (
            details if isinstance(details, str) else json.dumps(details)
        )
    params.update(extra)
    return params


def get_authorization_code(test_client, details, **extra):
    rv = test_client.post("/oauth/authorize", data=authorize_params(details, **extra))
    assert rv.status_code == 302
    params = dict(url_decode(urlparse.urlparse(rv.location).query))
    return params["code"]


def exchange_code(test_client, code):
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "https://client.test",
        },
        headers=headers,
    )
    return json.loads(rv.data)


def refresh(test_client, refresh_token, details=None):
    data = {"grant_type": "refresh_token", "refresh_token": refresh_token}
    if details is not None:
        data["authorization_details"] = (
            details if isinstance(details, str) else json.dumps(details)
        )
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post("/oauth/token", data=data, headers=headers)
    return json.loads(rv.data)


def test_consent_page_receives_parsed_details(test_client):
    url = "/oauth/authorize?" + urlencode(authorize_params(DATASET_DETAILS))
    rv = test_client.get(url)
    assert rv.status_code == 200
    assert json.loads(rv.data) == DATASET_DETAILS


def test_consent_narrows_details_for_token_and_refresh(test_client):
    # the user removes "export" on the consent page
    code = get_authorization_code(test_client, DATASET_DETAILS, consent="narrow")
    resp = exchange_code(test_client, code)
    # scope and authorization details coexist
    assert resp["scope"] == "profile"
    assert resp["authorization_details"] == READ_ONLY_DETAILS

    # the saved token carries only the consented details
    token = Token.query.filter_by(access_token=resp["access_token"]).one()
    assert token.get_authorization_details() == READ_ONLY_DETAILS

    # the refresh token is bound to the consented details as well
    refreshed = refresh(test_client, resp["refresh_token"])
    assert refreshed["authorization_details"] == READ_ONLY_DETAILS


def test_refresh_cannot_widen_details(test_client):
    code = get_authorization_code(test_client, DATASET_DETAILS)
    resp = exchange_code(test_client, code)
    refresh_token = resp["refresh_token"]

    # sneaking another dataset into the refresh request is rejected as a
    # widening of the granted authorization
    widened = [
        {
            "type": "dataset_access",
            "locations": ["ds-1", "ds-2", "ds-3"],
            "actions": ["read"],
        }
    ]
    resp = refresh(test_client, refresh_token, widened)
    assert resp["error"] == "invalid_scope"

    # a malformed value is rejected as a syntax error instead
    resp = refresh(test_client, refresh_token, "not-json")
    assert resp["error"] == "invalid_authorization_details"

    # narrowing to one dataset is accepted
    narrowed = [{"type": "dataset_access", "locations": ["ds-1"], "actions": ["read"]}]
    resp = refresh(test_client, refresh_token, narrowed)
    assert resp["authorization_details"] == narrowed


def test_mixed_known_and_unknown_types(test_client):
    mixed = DATASET_DETAILS + [{"type": "payment", "amount": 30}]
    url = "/oauth/authorize?" + urlencode(authorize_params(mixed))
    rv = test_client.get(url)
    assert "error=invalid_authorization_details" in rv.location


def test_malformed_details_rejected(test_client):
    # not JSON at all
    url = "/oauth/authorize?" + urlencode(authorize_params("not-json"))
    rv = test_client.get(url)
    assert "error=invalid_authorization_details" in rv.location

    # not an array
    params = authorize_params('{"type": "dataset_access"}')
    url = "/oauth/authorize?" + urlencode(params)
    rv = test_client.get(url)
    assert "error=invalid_authorization_details" in rv.location

    # missing "type"
    url = "/oauth/authorize?" + urlencode(authorize_params([{"locations": ["ds-1"]}]))
    rv = test_client.get(url)
    assert "error=invalid_authorization_details" in rv.location

    # rejected by the type handler
    invalid = [{"type": "dataset_access", "locations": ["ds-1"], "actions": ["delete"]}]
    url = "/oauth/authorize?" + urlencode(authorize_params(invalid))
    rv = test_client.get(url)
    assert "error=invalid_authorization_details" in rv.location


def test_empty_consent_is_denied(test_client):
    rv = test_client.post(
        "/oauth/authorize",
        data=authorize_params(DATASET_DETAILS, consent="empty"),
    )
    assert "error=access_denied" in rv.location


def test_saved_details_detached_from_callback_mutation(test_client):
    saved_details_snapshots.clear()
    code = get_authorization_code(
        test_client, DATASET_DETAILS, consent="narrow", mutate_after_save="1"
    )
    # the value saved with the authorization code was detached from the
    # objects mutated by the application callback
    assert saved_details_snapshots == [READ_ONLY_DETAILS]

    resp = exchange_code(test_client, code)
    assert resp["authorization_details"] == READ_ONLY_DETAILS
