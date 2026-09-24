import json
import time

import pytest
from flask import g
from flask import jsonify
from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jwk import KeySet

from authlib.integrations.flask_oauth2 import ResourceProtector
from authlib.integrations.flask_oauth2 import current_token
from authlib.integrations.sqla_oauth2 import OAuth2TokenMixin
from authlib.oauth2.rfc6749 import TokenMixin
from authlib.oauth2.rfc8693 import TokenExchangeBearerTokenValidator
from authlib.oauth2.rfc8693 import TokenExchangeGrant as _TokenExchangeGrant
from authlib.oauth2.rfc8693 import build_actor_claim
from authlib.oauth2.rfc8693 import parse_actor_chain
from authlib.oauth2.rfc9068 import JWTBearerTokenGenerator
from tests.util import read_file_path

from .models import Client
from .models import Token
from .models import User
from .models import db
from .oauth2_server import create_basic_header
from .oauth2_server import create_bearer_header

GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"
JWT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt"
SAML2_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:saml2"

AS_ID = "https://as.example.com"
RS_REPORTS = "https://reports.example.com"
RS_ARCHIVE = "https://archive.example.com"

SCOPES_SUPPORTED = ["profile", "reports:read", "reports:write"]


class ExchangeToken(db.Model, OAuth2TokenMixin):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"))
    subject = db.Column(db.String(120))
    actor_chain = db.Column(db.Text)
    audiences = db.Column(db.Text)

    @property
    def sub(self):
        return self.subject

    @property
    def act(self):
        if not self.actor_chain:
            return None
        return build_actor_claim(json.loads(self.actor_chain))

    @property
    def aud(self):
        if not self.audiences:
            return None
        return json.loads(self.audiences)


def save_exchange_token(token, request):
    token = dict(token)
    act = token.pop("act", None)
    aud = token.pop("aud", None)
    token.pop("issued_token_type", None)
    item = ExchangeToken(
        client_id=request.client.client_id,
        user_id=request.user.get_user_id() if request.user else None,
        subject=request.user.username if request.user else None,
        actor_chain=json.dumps(parse_actor_chain(act)) if act else None,
        audiences=json.dumps(aud) if aud else None,
        **token,
    )
    db.session.add(item)
    db.session.commit()
    return item


def public_key_set():
    return KeySet.import_key_set(read_file_path("jwks_public.json"))


def private_key_set():
    return KeySet.import_key_set(read_file_path("jwks_private.json"))


def decode_token_claims(token_string):
    if token_string.count(".") == 2:
        try:
            token = jwt.decode(token_string, public_key_set())
        except JoseError:
            return None
        claims = dict(token.claims)
        if claims.get("exp", 0) < time.time():
            return None
        return claims

    item = Token.query.filter_by(access_token=token_string).first()
    if item:
        if item.is_expired() or item.is_revoked():
            return None
        return {
            "sub": item.user.username,
            "scope": item.scope,
            "aud": [AS_ID],
            "client_id": item.client_id,
        }

    item = ExchangeToken.query.filter_by(access_token=token_string).first()
    if item:
        if item.is_expired() or item.is_revoked():
            return None
        claims = {"sub": item.subject, "scope": item.scope}
        if item.act:
            claims["act"] = item.act
        if item.aud:
            claims["aud"] = item.aud
        return claims
    return None


class TokenExchangeGrant(_TokenExchangeGrant):
    def validate_subject_token(self, subject_token, subject_token_type):
        return decode_token_claims(subject_token)

    def validate_actor_token(self, actor_token, actor_token_type):
        return decode_token_claims(actor_token)

    def authenticate_user(self, subject):
        return User.query.filter_by(username=subject).first()

    def get_audiences(self):
        return [AS_ID]

    def get_permitted_resources(self):
        return [RS_REPORTS, RS_ARCHIVE]


class JWTContextTokenExchangeGrant(TokenExchangeGrant):
    def validate_token_request(self):
        super().validate_token_request()
        # make the validated context available to the JWT token generator
        g.token_exchange_context = self.token_exchange_context


class ExchangeJWTGenerator(JWTBearerTokenGenerator):
    def get_jwks(self):
        return private_key_set()

    def get_extra_claims(self, client, grant_type, user, scope):
        context = g.get("token_exchange_context", None)
        if not context:
            return {}
        claims = {
            "sub": context["subject"],
            "act": build_actor_claim(context["actor_chain"]),
        }
        if context["resources"]:
            claims["aud"] = context["resources"]
        return claims


class JWTExchangeToken(TokenMixin, dict):
    def check_client(self, client):
        return True

    def get_scope(self):
        return self.get("scope")

    def get_expires_in(self):
        return self.get("exp", 0) - self.get("iat", 0)

    def is_expired(self):
        return self.get("exp", 0) < time.time()

    def is_revoked(self):
        return False


class JWTExchangeValidator(TokenExchangeBearerTokenValidator):
    def authenticate_token(self, token_string):
        try:
            token = jwt.decode(token_string, public_key_set())
        except JoseError:
            return None
        return JWTExchangeToken(token.claims)


class OpaqueExchangeValidator(TokenExchangeBearerTokenValidator):
    def authenticate_token(self, token_string):
        q = ExchangeToken.query.filter_by(access_token=token_string)
        return q.first()


@pytest.fixture(autouse=True)
def exchange_clients(db, user):
    clients = []
    for client_id in ("client-a", "client-b", "client-c"):
        client = Client(
            user_id=user.id,
            client_id=client_id,
            client_secret=f"{client_id}-secret",
        )
        client.set_client_metadata(
            {
                "scope": "profile reports:read",
                "grant_types": [GRANT_TYPE],
                "token_endpoint_auth_method": "client_secret_basic",
            }
        )
        db.session.add(client)
        clients.append(client)
    db.session.commit()
    yield clients


@pytest.fixture(autouse=True)
def resource_servers(app):
    jwt_protector = ResourceProtector()
    jwt_protector.register_token_validator(
        JWTExchangeValidator(resource_server=RS_REPORTS)
    )
    opaque_protector = ResourceProtector()
    opaque_protector.register_token_validator(
        OpaqueExchangeValidator(resource_server=RS_REPORTS)
    )
    archive_protector = ResourceProtector()
    archive_protector.register_token_validator(
        JWTExchangeValidator(resource_server=RS_ARCHIVE)
    )

    @app.route("/reports/jwt")
    @jwt_protector("reports:read")
    def reports_jwt():
        token = current_token
        return jsonify(
            sub=token["sub"],
            actors=parse_actor_chain(token.get("act")),
            aud=token.get("aud"),
        )

    @app.route("/reports/opaque")
    @opaque_protector("reports:read")
    def reports_opaque():
        token = current_token
        return jsonify(
            sub=token.sub,
            actors=parse_actor_chain(token.act),
            aud=token.aud,
        )

    @app.route("/archive/jwt")
    @archive_protector("reports:read")
    def archive_jwt():
        return jsonify(status="ok")


def create_opaque_token(access_token, scope, user_id=1):
    item = Token(
        user_id=user_id,
        client_id="frontend-client",
        token_type="bearer",
        access_token=access_token,
        scope=scope,
        expires_in=3600,
    )
    db.session.add(item)
    db.session.commit()
    return item


def create_jwt_token(sub="foo", scope="profile reports:read", aud=None, act=None):
    now = int(time.time())
    claims = {
        "iss": AS_ID,
        "sub": sub,
        "aud": aud if aud is not None else [AS_ID],
        "scope": scope,
        "iat": now,
        "exp": now + 3600,
        "client_id": "frontend-client",
    }
    if act:
        claims["act"] = act
    return jwt.encode({"alg": "RS256"}, claims, key=private_key_set())


def exchange(test_client, client_id, subject_token, subject_token_type, **extra):
    data = {
        "grant_type": GRANT_TYPE,
        "subject_token": subject_token,
        "subject_token_type": subject_token_type,
    }
    data.update(extra)
    return test_client.post(
        "/oauth/token",
        data=data,
        headers=create_basic_header(client_id, f"{client_id}-secret"),
    )


def exchange_opaque(test_client, client_id, subject_token, **extra):
    return exchange(test_client, client_id, subject_token, ACCESS_TOKEN_TYPE, **extra)


def exchange_jwt(test_client, client_id, subject_token, **extra):
    return exchange(test_client, client_id, subject_token, JWT_TOKEN_TYPE, **extra)


class TestOpaqueTokenExchange:
    @pytest.fixture(autouse=True)
    def server(self, server):
        server.register_grant(TokenExchangeGrant)
        server.scopes_supported = SCOPES_SUPPORTED
        server.save_token = save_exchange_token
        return server

    def test_three_stage_delegation(self, test_client):
        create_opaque_token("frontend-token", "profile reports:read")

        rv = exchange_opaque(
            test_client,
            "client-a",
            "frontend-token",
            resource=RS_REPORTS,
            scope="reports:read",
        )
        resp = json.loads(rv.data)
        assert rv.status_code == 200
        assert resp["issued_token_type"] == ACCESS_TOKEN_TYPE
        assert resp["scope"] == "reports:read"
        assert resp["act"] == {"sub": "client-a"}
        assert resp["aud"] == [RS_REPORTS]

        rv = exchange_opaque(
            test_client, "client-b", resp["access_token"], resource=RS_REPORTS
        )
        resp = json.loads(rv.data)
        assert rv.status_code == 200
        assert resp["act"] == {"sub": "client-b", "act": {"sub": "client-a"}}

        rv = exchange_opaque(
            test_client, "client-c", resp["access_token"], resource=RS_REPORTS
        )
        resp = json.loads(rv.data)
        assert rv.status_code == 200
        assert resp["act"] == {
            "sub": "client-c",
            "act": {"sub": "client-b", "act": {"sub": "client-a"}},
        }
        assert resp["aud"] == [RS_REPORTS]
        assert resp["scope"] == "reports:read"

        rv = test_client.get(
            "/reports/opaque", headers=create_bearer_header(resp["access_token"])
        )
        assert rv.status_code == 200
        data = json.loads(rv.data)
        assert data["sub"] == "foo"
        assert data["actors"] == ["client-c", "client-b", "client-a"]
        assert data["aud"] == [RS_REPORTS]

    def test_multiple_resources(self, test_client):
        create_opaque_token("frontend-token", "profile reports:read")
        rv = exchange_opaque(
            test_client,
            "client-a",
            "frontend-token",
            resource=[RS_REPORTS, RS_ARCHIVE],
            scope="reports:read",
        )
        resp = json.loads(rv.data)
        assert rv.status_code == 200
        assert resp["aud"] == [RS_REPORTS, RS_ARCHIVE]

    def test_cross_resource_request_rejected(self, test_client):
        create_opaque_token("frontend-token", "profile reports:read")
        rv = exchange_opaque(
            test_client,
            "client-a",
            "frontend-token",
            resource=RS_REPORTS,
            scope="reports:read",
        )
        token1 = json.loads(rv.data)["access_token"]

        # a delegated token cannot be re-exchanged for another resource
        rv = exchange_opaque(test_client, "client-b", token1, resource=RS_ARCHIVE)
        resp = json.loads(rv.data)
        assert resp["error"] == "invalid_target"

    def test_cross_resource_validator_rejected(self, test_client):
        create_opaque_token("frontend-token", "profile reports:read")
        rv = exchange_opaque(
            test_client,
            "client-a",
            "frontend-token",
            resource=RS_ARCHIVE,
            scope="reports:read",
        )
        resp = json.loads(rv.data)
        assert resp["aud"] == [RS_ARCHIVE]

        # the reports resource server rejects tokens issued for the archive
        rv = test_client.get(
            "/reports/opaque", headers=create_bearer_header(resp["access_token"])
        )
        assert rv.status_code == 401

    def test_invalid_resource_uri(self, test_client):
        create_opaque_token("frontend-token", "profile reports:read")
        rv = exchange_opaque(
            test_client, "client-a", "frontend-token", resource="not-an-uri"
        )
        resp = json.loads(rv.data)
        assert resp["error"] == "invalid_target"

    def test_empty_scope_intersection(self, test_client):
        create_opaque_token("frontend-token", "email")
        rv = exchange_opaque(test_client, "client-a", "frontend-token")
        resp = json.loads(rv.data)
        assert resp["error"] == "invalid_scope"

        rv = exchange_opaque(
            test_client, "client-a", "frontend-token", scope="reports:read"
        )
        resp = json.loads(rv.data)
        assert resp["error"] == "invalid_scope"

    def test_scope_cannot_expand(self, test_client):
        create_opaque_token("frontend-token", "profile")
        rv = exchange_opaque(
            test_client, "client-a", "frontend-token", scope="reports:read"
        )
        resp = json.loads(rv.data)
        assert resp["error"] == "invalid_scope"

    def test_cycle_actor_chain_rejected(self, test_client):
        create_opaque_token("frontend-token", "profile reports:read")
        rv = exchange_opaque(
            test_client,
            "client-a",
            "frontend-token",
            resource=RS_REPORTS,
            scope="reports:read",
        )
        token1 = json.loads(rv.data)["access_token"]

        # client-a is already in the delegation chain of token1
        rv = exchange_opaque(test_client, "client-a", token1, resource=RS_REPORTS)
        resp = json.loads(rv.data)
        assert resp["error"] == "invalid_grant"

    def test_actor_comes_from_client_not_request(self, test_client):
        create_opaque_token("frontend-token", "profile reports:read")
        rv = exchange_opaque(
            test_client,
            "client-a",
            "frontend-token",
            resource=RS_REPORTS,
            scope="reports:read",
            actor="client-evil",
        )
        resp = json.loads(rv.data)
        assert rv.status_code == 200
        assert resp["act"] == {"sub": "client-a"}

    def test_actor_token_delegation(self, test_client):
        create_opaque_token("frontend-token", "profile reports:read")
        actor_token = create_jwt_token(sub="client-b", scope="reports:read")
        rv = exchange_opaque(
            test_client,
            "client-a",
            "frontend-token",
            resource=RS_REPORTS,
            scope="reports:read",
            actor_token=actor_token,
            actor_token_type=JWT_TOKEN_TYPE,
            actor="client-evil",
        )
        resp = json.loads(rv.data)
        assert rv.status_code == 200
        # the actor is the validated actor token subject, not request data
        assert resp["act"] == {"sub": "client-b"}

    def test_actor_token_type_without_token(self, test_client):
        create_opaque_token("frontend-token", "profile reports:read")
        rv = exchange_opaque(
            test_client,
            "client-a",
            "frontend-token",
            actor_token_type=JWT_TOKEN_TYPE,
        )
        resp = json.loads(rv.data)
        assert resp["error"] == "invalid_request"

    def test_unsupported_requested_token_type(self, test_client):
        create_opaque_token("frontend-token", "profile reports:read")
        rv = exchange_opaque(
            test_client,
            "client-a",
            "frontend-token",
            requested_token_type=SAML2_TOKEN_TYPE,
        )
        resp = json.loads(rv.data)
        assert resp["error"] == "invalid_request"
        assert "access_token" not in resp

    def test_missing_subject_token(self, test_client):
        rv = test_client.post(
            "/oauth/token",
            data={
                "grant_type": GRANT_TYPE,
                "subject_token_type": ACCESS_TOKEN_TYPE,
            },
            headers=create_basic_header("client-a", "client-a-secret"),
        )
        resp = json.loads(rv.data)
        assert resp["error"] == "invalid_request"

    def test_invalid_subject_token(self, test_client):
        rv = exchange_opaque(test_client, "client-a", "unknown-token")
        resp = json.loads(rv.data)
        assert resp["error"] == "invalid_grant"

    def test_unsupported_subject_token_type(self, test_client):
        rv = exchange(test_client, "client-a", "frontend-token", SAML2_TOKEN_TYPE)
        resp = json.loads(rv.data)
        assert resp["error"] == "invalid_request"

    def test_client_not_allowed_grant_type(self, test_client, db, user):
        client = Client(
            user_id=user.id, client_id="client-x", client_secret="client-x-secret"
        )
        client.set_client_metadata({"grant_types": ["client_credentials"]})
        db.session.add(client)
        db.session.commit()
        create_opaque_token("frontend-token", "profile reports:read")
        rv = exchange_opaque(test_client, "client-x", "frontend-token")
        resp = json.loads(rv.data)
        assert resp["error"] == "unauthorized_client"
        rv = exchange_opaque(test_client, "client-x", "frontend-token")
        resp = json.loads(rv.data)
        assert resp["error"] == "unauthorized_client"


class TestJWTTokenExchange:
    @pytest.fixture(autouse=True)
    def server(self, server):
        server.register_grant(JWTContextTokenExchangeGrant)
        server.scopes_supported = SCOPES_SUPPORTED
        server.save_token = save_exchange_token
        server.register_token_generator(GRANT_TYPE, ExchangeJWTGenerator(issuer=AS_ID))
        return server

    def decode(self, access_token):
        token = jwt.decode(access_token, public_key_set())
        return token.claims

    def test_three_stage_delegation(self, test_client):
        frontend = create_jwt_token()

        rv = exchange_jwt(
            test_client,
            "client-a",
            frontend,
            resource=RS_REPORTS,
            scope="reports:read",
        )
        resp = json.loads(rv.data)
        assert rv.status_code == 200
        assert resp["issued_token_type"] == ACCESS_TOKEN_TYPE

        claims = self.decode(resp["access_token"])
        assert claims["sub"] == "foo"
        assert claims["act"] == {"sub": "client-a"}
        assert claims["aud"] == [RS_REPORTS]
        assert claims["scope"] == "reports:read"

        rv = exchange_jwt(
            test_client, "client-b", resp["access_token"], resource=RS_REPORTS
        )
        claims = self.decode(json.loads(rv.data)["access_token"])
        assert claims["act"] == {"sub": "client-b", "act": {"sub": "client-a"}}

        rv = exchange_jwt(
            test_client,
            "client-c",
            json.loads(rv.data)["access_token"],
            resource=RS_REPORTS,
        )
        resp = json.loads(rv.data)
        claims = self.decode(resp["access_token"])
        assert claims["sub"] == "foo"
        assert claims["act"] == {
            "sub": "client-c",
            "act": {"sub": "client-b", "act": {"sub": "client-a"}},
        }
        assert claims["aud"] == [RS_REPORTS]
        assert claims["scope"] == "reports:read"

        rv = test_client.get(
            "/reports/jwt", headers=create_bearer_header(resp["access_token"])
        )
        assert rv.status_code == 200
        data = json.loads(rv.data)
        assert data["sub"] == "foo"
        assert data["actors"] == ["client-c", "client-b", "client-a"]
        assert data["aud"] == [RS_REPORTS]

    def test_cross_resource_request_rejected(self, test_client):
        frontend = create_jwt_token()
        rv = exchange_jwt(
            test_client,
            "client-a",
            frontend,
            resource=RS_REPORTS,
            scope="reports:read",
        )
        token1 = json.loads(rv.data)["access_token"]

        rv = exchange_jwt(test_client, "client-b", token1, resource=RS_ARCHIVE)
        resp = json.loads(rv.data)
        assert resp["error"] == "invalid_target"

    def test_cross_resource_validator_rejected(self, test_client):
        frontend = create_jwt_token()
        rv = exchange_jwt(
            test_client,
            "client-a",
            frontend,
            resource=RS_REPORTS,
            scope="reports:read",
        )
        token1 = json.loads(rv.data)["access_token"]

        # the archive resource server rejects tokens issued for reports
        rv = test_client.get("/archive/jwt", headers=create_bearer_header(token1))
        assert rv.status_code == 401

    def test_empty_scope_intersection(self, test_client):
        frontend = create_jwt_token(scope="email")
        rv = exchange_jwt(test_client, "client-a", frontend)
        resp = json.loads(rv.data)
        assert resp["error"] == "invalid_scope"

    def test_scope_cannot_expand_on_reexchange(self, test_client):
        frontend = create_jwt_token()
        rv = exchange_jwt(
            test_client,
            "client-a",
            frontend,
            resource=RS_REPORTS,
            scope="reports:read",
        )
        token1 = json.loads(rv.data)["access_token"]

        rv = exchange_jwt(
            test_client,
            "client-b",
            token1,
            resource=RS_REPORTS,
            scope="reports:read reports:write",
        )
        resp = json.loads(rv.data)
        assert resp["error"] == "invalid_scope"

    def test_cycle_actor_chain_rejected(self, test_client):
        act = {"sub": "client-a", "act": {"sub": "client-b"}}
        frontend = create_jwt_token(act=act)
        # client-a is already part of the delegation chain
        rv = exchange_jwt(test_client, "client-a", frontend)
        resp = json.loads(rv.data)
        assert resp["error"] == "invalid_grant"

    def test_cyclic_subject_chain_rejected(self, test_client):
        act = {
            "sub": "client-a",
            "act": {"sub": "client-b", "act": {"sub": "client-a"}},
        }
        frontend = create_jwt_token(act=act)
        rv = exchange_jwt(test_client, "client-c", frontend)
        resp = json.loads(rv.data)
        assert resp["error"] == "invalid_grant"

    def test_validator_rejects_cyclic_chain(self, test_client):
        act = {
            "sub": "client-a",
            "act": {"sub": "client-b", "act": {"sub": "client-a"}},
        }
        token = create_jwt_token(scope="reports:read", aud=[RS_REPORTS], act=act)
        rv = test_client.get("/reports/jwt", headers=create_bearer_header(token))
        assert rv.status_code == 401

    def test_validator_rejects_insufficient_scope(self, test_client):
        token = create_jwt_token(scope="profile", aud=[RS_REPORTS])
        rv = test_client.get("/reports/jwt", headers=create_bearer_header(token))
        assert rv.status_code == 403

    def test_subject_token_audience_rejected(self, test_client):
        frontend = create_jwt_token(aud=["https://unknown.example.com"])
        rv = exchange_jwt(test_client, "client-a", frontend)
        resp = json.loads(rv.data)
        assert resp["error"] == "invalid_grant"

    def test_unsupported_requested_token_type(self, test_client):
        frontend = create_jwt_token()
        rv = exchange_jwt(
            test_client,
            "client-a",
            frontend,
            requested_token_type=SAML2_TOKEN_TYPE,
        )
        resp = json.loads(rv.data)
        assert resp["error"] == "invalid_request"
        assert "access_token" not in resp
