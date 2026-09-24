import time

import pytest
from flask import json
from flask import jsonify
from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jwk import KeySet

from authlib.common.security import generate_token
from authlib.integrations.flask_oauth2 import ResourceProtector
from authlib.integrations.flask_oauth2 import current_token
from authlib.oauth2.rfc6749.errors import InvalidGrantError
from authlib.oauth2.rfc6749.grants import ClientCredentialsGrant
from authlib.oauth2.rfc6750 import BearerTokenValidator
from authlib.oauth2.rfc8693 import TokenExchangeGrant as _TokenExchangeGrant
from authlib.oauth2.rfc8693 import current_token_exchange_context
from authlib.oauth2.rfc9068 import JWTBearerTokenGenerator
from authlib.oauth2.rfc9068 import JWTBearerTokenValidator
from tests.util import read_file_path

from .models import Token
from .models import User
from .models import db
from .oauth2_server import create_basic_header
from .oauth2_server import create_bearer_header

issuer = "https://provider.test"
REPORTS = "https://reports.example.com"
BILLING = "https://billing.example.com"

GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"
REFRESH_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:refresh_token"
JWT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt"

key_set = KeySet.import_key_set(read_file_path("jwks_private.json"))


def sign_claims(claims):
    now = int(time.time())
    claims.setdefault("iss", issuer)
    claims.setdefault("aud", issuer)
    claims.setdefault("iat", now)
    claims.setdefault("exp", now + 3600)
    return jwt.encode({"alg": "RS256"}, claims, key_set)


def make_user_token(user, scope="read:reports write:reports profile", **kwargs):
    return sign_claims(dict({"sub": str(user.id), "scope": scope}, **kwargs))


def make_service_token(service_id):
    return sign_claims({"sub": service_id, "scope": "service"})


def decode_claims(token):
    return jwt.decode(token, key_set).claims


class TokenExchangeGrant(_TokenExchangeGrant):
    SUBJECT_TOKEN_AUDIENCE = issuer
    KNOWN_RESOURCES = [REPORTS, BILLING]

    def _decode_token(self, token_string):
        try:
            claims = jwt.decode(token_string, key_set).claims
        except JoseError as exc:
            raise InvalidGrantError("The token is invalid.") from exc
        if claims.get("iss") != issuer:
            raise InvalidGrantError("The token issuer is not trusted.")
        if claims.get("exp", 0) < time.time():
            raise InvalidGrantError("The token is expired.")
        return claims

    def validate_subject_token(self, subject_token, subject_token_type):
        return self._decode_token(subject_token)

    def validate_actor_token(self, actor_token, actor_token_type, subject_claims):
        return self._decode_token(actor_token)

    def resolve_subject_user(self, subject_claims):
        sub = subject_claims["sub"]
        if sub.isdigit():
            return db.session.get(User, int(sub))
        return None


class ExchangeTokenGenerator(JWTBearerTokenGenerator):
    def get_jwks(self):
        return key_set

    def get_audiences(self, client, user, scope):
        ctx = current_token_exchange_context.get()
        if ctx and ctx.resources:
            return ctx.resources
        return super().get_audiences(client, user, scope)

    def get_extra_claims(self, client, grant_type, user, scope):
        ctx = current_token_exchange_context.get()
        if ctx:
            act = ctx.get_act_claim()
            if act:
                return {"act": act}
        return {}


@pytest.fixture(autouse=True)
def server(server):
    server.register_grant(ClientCredentialsGrant)
    server.register_grant(TokenExchangeGrant)
    server.register_token_generator("default", ExchangeTokenGenerator(issuer=issuer))
    server.scopes_supported = ["profile", "read:reports", "write:reports"]
    return server


@pytest.fixture(autouse=True)
def client(client, db):
    client.set_client_metadata(
        {
            "scope": "profile read:reports write:reports",
            "redirect_uris": ["https://client.test/authorized"],
            "grant_types": [GRANT_TYPE, "client_credentials", "authorization_code"],
            "response_types": ["code"],
        }
    )
    db.session.add(client)
    db.session.commit()
    return client


@pytest.fixture(autouse=True)
def resource_protectors(app):
    class ReportsTokenValidator(JWTBearerTokenValidator):
        def get_jwks(self):
            return key_set

    class BillingTokenValidator(JWTBearerTokenValidator):
        def get_jwks(self):
            return key_set

    reports_oauth = ResourceProtector()
    reports_oauth.register_token_validator(
        ReportsTokenValidator(issuer=issuer, resource_server=REPORTS)
    )
    billing_oauth = ResourceProtector()
    billing_oauth.register_token_validator(
        BillingTokenValidator(issuer=issuer, resource_server=BILLING)
    )

    @app.route("/reports")
    @reports_oauth("read:reports")
    def reports():
        return jsonify(
            sub=current_token["sub"],
            act=current_token.get("act"),
            scope=current_token.get("scope"),
        )

    @app.route("/billing")
    @billing_oauth("read:billing")
    def billing():
        return jsonify(ok=True)


def exchange(
    test_client,
    subject_token,
    actor_token=None,
    resources=None,
    subject_token_type=JWT_TOKEN_TYPE,
    **kwargs,
):
    data = {
        "grant_type": GRANT_TYPE,
        "subject_token": subject_token,
        "subject_token_type": subject_token_type,
    }
    if actor_token:
        data["actor_token"] = actor_token
        data["actor_token_type"] = JWT_TOKEN_TYPE
    if resources:
        data["resource"] = list(resources)
    for key, value in kwargs.items():
        data[key] = value
    return test_client.post(
        "/oauth/token",
        data=data,
        headers=create_basic_header("client-id", "client-secret"),
    )


def test_missing_subject_token(test_client):
    rv = test_client.post(
        "/oauth/token",
        data={"grant_type": GRANT_TYPE, "subject_token_type": JWT_TOKEN_TYPE},
        headers=create_basic_header("client-id", "client-secret"),
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_request"
    assert "subject_token" in resp["error_description"]


def test_unsupported_subject_token_type(test_client, user):
    rv = exchange(
        test_client, make_user_token(user), subject_token_type="urn:example:saml"
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_request"


def test_unsupported_requested_token_type(test_client, user):
    rv = exchange(
        test_client,
        make_user_token(user),
        resources=[REPORTS],
        requested_token_type=REFRESH_TOKEN_TYPE,
    )
    resp = json.loads(rv.data)
    assert rv.status_code == 400
    assert resp["error"] == "invalid_request"
    # no fallback to a plain client_credentials token
    assert "access_token" not in resp


def test_invalid_subject_token(test_client):
    rv = exchange(test_client, "not-a-token", resources=[REPORTS])
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_grant"


def test_subject_token_wrong_audience(test_client, user):
    token = make_user_token(user, aud="https://unknown.example.com")
    rv = exchange(test_client, token, resources=[REPORTS])
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_grant"


def test_resource_must_be_absolute_uri(test_client, user):
    rv = exchange(test_client, make_user_token(user), resources=["reports"])
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_target"


def test_unknown_resource(test_client, user):
    rv = exchange(
        test_client, make_user_token(user), resources=["https://unknown.example.com"]
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_target"


def test_multiple_resources(test_client, user):
    rv = exchange(test_client, make_user_token(user), resources=[REPORTS, BILLING])
    resp = json.loads(rv.data)
    assert resp["issued_token_type"] == ACCESS_TOKEN_TYPE
    claims = decode_claims(resp["access_token"])
    assert sorted(claims["aud"]) == sorted([REPORTS, BILLING])


def test_empty_scope_intersection(test_client, server, user):
    server.scopes_supported = ["profile"]
    token = make_user_token(user, scope="read:reports")
    rv = exchange(test_client, token, resources=[REPORTS])
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_scope"


def test_requested_scope_cannot_widen(test_client, user):
    token = make_user_token(user, scope="read:reports")
    rv = exchange(
        test_client, token, resources=[REPORTS], scope="read:reports write:reports"
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_scope"


def test_three_stage_delegation(test_client, user):
    # stage 1: the front-end user token is exchanged by service-a
    rv = exchange(
        test_client,
        make_user_token(user),
        actor_token=make_service_token("service-a"),
        resources=[REPORTS],
        scope="read:reports write:reports",
    )
    resp = json.loads(rv.data)
    assert "access_token" in resp
    token1 = resp["access_token"]
    claims = decode_claims(token1)
    assert claims["sub"] == str(user.id)
    assert claims["act"] == {"sub": "service-a"}
    assert claims["aud"] == [REPORTS]
    assert claims["scope"] == "read:reports write:reports"

    # stage 2: service-b acts on behalf of service-a, narrowing the scope
    rv = exchange(
        test_client,
        token1,
        actor_token=make_service_token("service-b"),
        resources=[REPORTS],
        scope="read:reports",
    )
    resp = json.loads(rv.data)
    token2 = resp["access_token"]
    claims = decode_claims(token2)
    assert claims["act"] == {"sub": "service-b", "act": {"sub": "service-a"}}
    assert claims["scope"] == "read:reports"

    # stage 3: service-c joins the chain, resources are inherited
    rv = exchange(test_client, token2, actor_token=make_service_token("service-c"))
    resp = json.loads(rv.data)
    token3 = resp["access_token"]
    claims = decode_claims(token3)
    assert claims["sub"] == str(user.id)
    assert claims["act"] == {
        "sub": "service-c",
        "act": {"sub": "service-b", "act": {"sub": "service-a"}},
    }
    assert claims["aud"] == [REPORTS]
    assert claims["scope"] == "read:reports"

    # the reports resource server verifies subject, actor chain, aud, scope
    rv = test_client.get("/reports", headers=create_bearer_header(token3))
    assert rv.status_code == 200
    resp = json.loads(rv.data)
    assert resp["sub"] == str(user.id)
    assert resp["act"]["sub"] == "service-c"
    assert resp["scope"] == "read:reports"


def test_cross_resource_denied(test_client, user):
    rv = exchange(test_client, make_user_token(user), resources=[REPORTS])
    token1 = json.loads(rv.data)["access_token"]

    # a token scoped to the reports resource cannot be exchanged for billing
    rv = exchange(test_client, token1, resources=[BILLING])
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_target"

    # nor be used at the billing resource server
    rv = test_client.get("/billing", headers=create_bearer_header(token1))
    assert rv.status_code == 401
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_token"


def test_re_exchange_cannot_widen_scope(test_client, user):
    rv = exchange(
        test_client, make_user_token(user), resources=[REPORTS], scope="read:reports"
    )
    token1 = json.loads(rv.data)["access_token"]
    rv = exchange(
        test_client, token1, resources=[REPORTS], scope="read:reports write:reports"
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_scope"


def test_actor_cannot_be_forged(test_client, user):
    # an actor token for the subject itself is a self-delegation cycle
    rv = exchange(
        test_client,
        make_user_token(user),
        actor_token=make_user_token(user),
        resources=[REPORTS],
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_grant"

    # a garbage actor token is rejected, the claimed actor is never trusted
    rv = exchange(
        test_client,
        make_user_token(user),
        actor_token="forged-actor-token",
        resources=[REPORTS],
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_grant"


def test_cyclic_actor_chain(test_client, user):
    rv = exchange(
        test_client,
        make_user_token(user),
        actor_token=make_service_token("service-a"),
        resources=[REPORTS],
    )
    token1 = json.loads(rv.data)["access_token"]
    rv = exchange(test_client, token1, actor_token=make_service_token("service-b"))
    token2 = json.loads(rv.data)["access_token"]

    # service-a is already in the chain: A -> B -> A is a cycle
    rv = exchange(test_client, token2, actor_token=make_service_token("service-a"))
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_grant"

    # service-b acting again would also close a loop
    rv = exchange(test_client, token2, actor_token=make_service_token("service-b"))
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_grant"


def test_opaque_token_exchange(test_client, server, app, user):
    contexts = {}
    default_save_token = server._save_token

    def save_token(token, request):
        default_save_token(token, request)
        ctx = getattr(request, "token_exchange_context", None)
        if ctx:
            contexts[token["access_token"]] = ctx

    def opaque_token_generator(
        grant_type,
        client,
        user=None,
        scope=None,
        expires_in=None,
        include_refresh_token=True,
    ):
        return {
            "token_type": "Bearer",
            "access_token": generate_token(32),
            "expires_in": 3600,
            "scope": scope,
        }

    server._save_token = save_token
    server.register_token_generator(GRANT_TYPE, opaque_token_generator)

    class OpaqueTokenValidator(BearerTokenValidator):
        def authenticate_token(self, token_string):
            return Token.query.filter_by(access_token=token_string).first()

        def validate_token(self, token, scopes, request):
            super().validate_token(token, scopes, request)
            ctx = contexts.get(token.access_token)
            if not ctx or REPORTS not in ctx.resources:
                from authlib.oauth2.rfc6750.errors import InvalidTokenError

                raise InvalidTokenError()

    opaque_oauth = ResourceProtector()
    opaque_oauth.register_token_validator(OpaqueTokenValidator())

    @app.route("/opaque-reports")
    @opaque_oauth("read:reports")
    def opaque_reports():
        return jsonify(sub=current_token.user_id, scope=current_token.scope)

    @app.route("/opaque-admin")
    @opaque_oauth("write:reports")
    def opaque_admin():
        return jsonify(ok=True)

    rv = exchange(
        test_client,
        make_user_token(user),
        actor_token=make_service_token("service-a"),
        resources=[REPORTS],
        scope="read:reports",
    )
    resp = json.loads(rv.data)
    assert resp["issued_token_type"] == ACCESS_TOKEN_TYPE
    access_token = resp["access_token"]

    # the opaque token is bound to the subject, client and narrowed scope
    item = Token.query.filter_by(access_token=access_token).one()
    assert item.user_id == user.id
    assert item.client_id == "client-id"
    assert item.scope == "read:reports"

    # the delegation context is available to the resource server
    ctx = contexts[access_token]
    assert ctx.subject == str(user.id)
    assert ctx.actors == ["service-a"]
    assert ctx.resources == [REPORTS]

    rv = test_client.get("/opaque-reports", headers=create_bearer_header(access_token))
    assert rv.status_code == 200
    resp = json.loads(rv.data)
    assert resp["sub"] == user.id

    # the narrowed scope does not cover write operations
    rv = test_client.get("/opaque-admin", headers=create_bearer_header(access_token))
    assert rv.status_code == 403
    resp = json.loads(rv.data)
    assert resp["error"] == "insufficient_scope"


def test_client_credentials_grant_keeps_working(test_client):
    rv = test_client.post(
        "/oauth/token",
        data={"grant_type": "client_credentials"},
        headers=create_basic_header("client-id", "client-secret"),
    )
    resp = json.loads(rv.data)
    assert "access_token" in resp
    assert resp["token_type"] == "Bearer"
