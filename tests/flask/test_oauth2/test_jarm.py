import html
import json
import re
import time
from unittest import mock

import pytest
import requests
from flask import jsonify
from flask import request
from joserfc import jwt
from joserfc.jwk import OctKey

from authlib.common.encoding import json_dumps
from authlib.common.encoding import json_loads
from authlib.common.encoding import to_bytes
from authlib.common.encoding import to_unicode
from authlib.common.encoding import urlsafe_b64decode
from authlib.common.encoding import urlsafe_b64encode
from authlib.common.urls import url_decode
from authlib.common.urls import urlparse
from authlib.integrations.flask_client import OAuth
from authlib.integrations.flask_client import OAuthError
from authlib.oauth2.jarm import JWTSecuredAuthorizationResponse
from authlib.oauth2.rfc6749.grants import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
)

from .models import CodeGrantMixin
from .models import save_authorization_code

ISSUER = "https://server.test"
REDIRECT_URI = "https://client.test/authorized"
REDIRECT_URI_HTML = "https://client.test/authorized?foo=1&bar=2"
JARM_KEY = OctKey.import_key("jarm-secret-jarm-secret-jarm-secret")


@pytest.fixture(autouse=True)
def client(client, db):
    client.set_client_metadata(
        {
            "redirect_uris": [REDIRECT_URI, REDIRECT_URI_HTML],
            "scope": "profile",
            "token_endpoint_auth_method": "client_secret_basic",
            "response_types": ["code"],
            "grant_types": ["authorization_code"],
            "authorization_signed_response_alg": "HS256",
        }
    )
    db.session.add(client)
    db.session.commit()
    return client


class AuthorizationCodeGrant(CodeGrantMixin, _AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ["client_secret_basic", "client_secret_post", "none"]

    def save_authorization_code(self, code, request):
        return save_authorization_code(code, request)


class JARM(JWTSecuredAuthorizationResponse):
    def get_issuer(self):
        return ISSUER

    def resolve_server_key(self, client):
        return JARM_KEY


@pytest.fixture(autouse=True)
def server(server):
    server.register_grant(AuthorizationCodeGrant)
    server.register_extension(JARM())
    return server


@pytest.fixture
def oauth_client(app):
    oauth = OAuth(app)
    remote = oauth.register(
        "dev",
        client_id="client-id",
        client_secret="client-secret",
        authorize_url="http://localhost/oauth/authorize",
        access_token_url="http://localhost/oauth/token",
        jarm_key=JARM_KEY,
        jarm_issuer=ISSUER,
        jarm_algorithms=["HS256"],
    )

    @app.route("/client/login")
    def login():
        response_mode = request.args.get("response_mode", "query.jwt")
        redirect_uri = request.args.get("redirect_uri", REDIRECT_URI)
        return remote.authorize_redirect(redirect_uri, response_mode=response_mode)

    @app.route("/authorized", methods=["GET", "POST"])
    def authorized():
        try:
            token = remote.authorize_access_token()
        except OAuthError as error:
            return (
                jsonify(error=error.error, error_description=error.description),
                400,
            )
        return jsonify(token)

    return remote


def _forward_token_request(test_client):
    def send(prepared_request, **kwargs):
        headers = {
            key: value
            for key, value in prepared_request.headers.items()
            if key != "Content-Type"
        }
        rv = test_client.post(
            prepared_request.path_url,
            data=prepared_request.body,
            headers=headers,
            content_type="application/x-www-form-urlencoded",
        )
        response = mock.MagicMock(spec=requests.Response)
        response.cookies = []
        response.status_code = rv.status_code
        response.text = rv.get_data(as_text=True)
        response.json = lambda: json.loads(response.text)
        return response

    return send


def _start_login(test_client, response_mode="query.jwt", redirect_uri=REDIRECT_URI):
    rv = test_client.get(
        "/client/login",
        query_string={"response_mode": response_mode, "redirect_uri": redirect_uri},
    )
    assert rv.status_code == 302
    authorize_url = rv.location
    query = dict(url_decode(urlparse.urlparse(authorize_url).query))
    return authorize_url, query["state"]


def _approve(test_client, authorize_url, user_id="1"):
    assert test_client.get(authorize_url).data == b"ok"
    data = {"user_id": user_id} if user_id is not None else {}
    return test_client.post(authorize_url, data=data)


def _decode(response_jwt):
    return jwt.decode(response_jwt, JARM_KEY, algorithms=["HS256"]).claims


def _callback_get(test_client, **query):
    with mock.patch("requests.sessions.Session.send") as send:
        send.side_effect = _forward_token_request(test_client)
        return test_client.get("/authorized", query_string=query)


def _callback_post(test_client, **kwargs):
    with mock.patch("requests.sessions.Session.send") as send:
        send.side_effect = _forward_token_request(test_client)
        return test_client.post("/authorized", **kwargs)


def _tamper_payload(response_jwt, **changes):
    header, payload, signature = response_jwt.split(".")
    data = json_loads(urlsafe_b64decode(to_bytes(payload)))
    data.update(changes)
    payload = to_unicode(
        urlsafe_b64encode(to_bytes(json_dumps(data, ensure_ascii=False)))
    )
    return ".".join([header, payload, signature])


def _craft_jwt(state, **claims_overrides):
    claims = {
        "iss": ISSUER,
        "aud": "client-id",
        "exp": int(time.time()) + 600,
        "code": "crafted-code",
        "state": state,
    }
    claims.update(claims_overrides)
    return jwt.encode({"alg": "HS256"}, claims, JARM_KEY, ["HS256"])


def test_jarm_query_success_round_trip(test_client, oauth_client):
    authorize_url, state = _start_login(test_client)
    rv = _approve(test_client, authorize_url)
    assert rv.status_code == 302

    params = dict(url_decode(urlparse.urlparse(rv.location).query))
    assert set(params) == {"response"}

    claims = _decode(params["response"])
    assert claims["iss"] == ISSUER
    assert claims["aud"] == "client-id"
    assert claims["exp"] > int(time.time())
    assert claims["state"] == state
    assert claims["code"]

    rv = _callback_get(test_client, response=params["response"])
    assert rv.status_code == 200
    token = rv.get_json()
    assert token["token_type"] == "Bearer"
    assert token["access_token"]


def test_jarm_query_user_denied_round_trip(test_client, oauth_client):
    authorize_url, state = _start_login(test_client)
    rv = _approve(test_client, authorize_url, user_id=None)
    assert rv.status_code == 302

    params = dict(url_decode(urlparse.urlparse(rv.location).query))
    assert set(params) == {"response"}

    claims = _decode(params["response"])
    assert claims["error"] == "access_denied"
    assert claims["state"] == state
    assert claims["iss"] == ISSUER
    assert claims["aud"] == "client-id"
    assert claims["exp"] > int(time.time())
    assert "code" not in claims

    rv = test_client.get("/authorized", query_string={"response": params["response"]})
    assert rv.status_code == 400
    assert rv.get_json()["error"] == "access_denied"


def test_jarm_form_post_success_round_trip(test_client, oauth_client):
    authorize_url, state = _start_login(
        test_client,
        response_mode="form_post.jwt",
        redirect_uri=REDIRECT_URI_HTML,
    )
    rv = _approve(test_client, authorize_url)
    assert rv.status_code == 200

    body = rv.get_data(as_text=True)
    # action and value are escaped for the HTML context
    assert f'action="{html.escape(REDIRECT_URI_HTML, quote=True)}"' in body
    assert f'action="{REDIRECT_URI_HTML}"' not in body

    match = re.search(r'name="response"\s+value="([^"]+)"', body)
    assert match is not None
    response_jwt = html.unescape(match.group(1))
    claims = _decode(response_jwt)
    assert claims["state"] == state
    assert claims["code"]

    rv = _callback_post(
        test_client,
        query_string={"foo": "1", "bar": "2"},
        data={"response": response_jwt},
    )
    assert rv.status_code == 200
    assert rv.get_json()["access_token"]


def test_jarm_plain_query_mode_still_works(test_client, oauth_client):
    authorize_url, state = _start_login(test_client, response_mode="query")
    rv = _approve(test_client, authorize_url)
    assert rv.status_code == 302

    params = dict(url_decode(urlparse.urlparse(rv.location).query))
    assert set(params) == {"code", "state"}
    assert params["state"] == state

    rv = _callback_get(test_client, code=params["code"], state=params["state"])
    assert rv.status_code == 200
    assert rv.get_json()["access_token"]


def test_jarm_validation_error_is_wrapped(test_client, server):
    server.scopes_supported = ["profile"]
    rv = test_client.post(
        "/oauth/authorize",
        query_string={
            "response_type": "code",
            "client_id": "client-id",
            "redirect_uri": REDIRECT_URI,
            "response_mode": "query.jwt",
            "state": "xyz",
            "scope": "invalid",
            "user_id": "1",
        },
    )
    assert rv.status_code == 302
    params = dict(url_decode(urlparse.urlparse(rv.location).query))
    assert set(params) == {"response"}

    claims = _decode(params["response"])
    assert claims["error"] == "invalid_scope"
    assert claims["state"] == "xyz"
    assert claims["iss"] == ISSUER
    assert claims["aud"] == "client-id"
    assert claims["exp"] > int(time.time())


def test_jarm_form_post_user_denied(test_client, oauth_client):
    authorize_url, state = _start_login(test_client, response_mode="form_post.jwt")
    rv = _approve(test_client, authorize_url, user_id=None)
    assert rv.status_code == 200

    body = rv.get_data(as_text=True)
    match = re.search(r'name="response"\s+value="([^"]+)"', body)
    assert match is not None
    claims = _decode(html.unescape(match.group(1)))
    assert claims["error"] == "access_denied"
    assert claims["state"] == state


def test_jarm_error_with_unvalidated_redirect_uri_is_not_redirected(test_client):
    rv = test_client.get(
        "/oauth/authorize",
        query_string={
            "response_type": "code",
            "client_id": "client-id",
            "redirect_uri": "https://evil.test/cb",
            "response_mode": "query.jwt",
            "state": "xyz",
        },
    )
    assert rv.status_code == 400
    assert rv.get_json()["error"] == "invalid_request"
    assert rv.location is None


@pytest.mark.parametrize(
    "changes",
    [
        {"aud": "other-client"},
        {"iss": "https://attacker.test"},
        {"exp": int(time.time()) - 3600},
    ],
)
def test_jarm_client_rejects_invalid_claims(test_client, oauth_client, changes):
    _, state = _start_login(test_client)
    response_jwt = _craft_jwt(state, **changes)
    rv = test_client.get("/authorized", query_string={"response": response_jwt})
    assert rv.status_code == 400
    assert rv.get_json()["error"] == "invalid_response"


def test_jarm_client_rejects_tampered_payload_without_consuming_state(
    test_client, oauth_client
):
    authorize_url, _ = _start_login(test_client)
    rv = _approve(test_client, authorize_url)
    valid_jwt = dict(url_decode(urlparse.urlparse(rv.location).query))["response"]

    tampered = _tamper_payload(valid_jwt, code="tampered-code")
    rv = test_client.get("/authorized", query_string={"response": tampered})
    assert rv.status_code == 400
    assert rv.get_json()["error"] == "invalid_response"

    # the valid state was not consumed by the failed verification
    rv = _callback_get(test_client, response=valid_jwt)
    assert rv.status_code == 200
    assert rv.get_json()["access_token"]


def test_jarm_client_rejects_plaintext_code_beside_jwt(test_client, oauth_client):
    authorize_url, _ = _start_login(test_client)
    rv = _approve(test_client, authorize_url)
    valid_jwt = dict(url_decode(urlparse.urlparse(rv.location).query))["response"]

    rv = test_client.get(
        "/authorized",
        query_string={"response": valid_jwt, "code": "smuggled-code"},
    )
    assert rv.status_code == 400
    assert rv.get_json()["error"] == "invalid_response"

    # the valid state was not consumed
    rv = _callback_get(test_client, response=valid_jwt)
    assert rv.status_code == 200
