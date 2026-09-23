import os
import shutil
import tempfile
import threading
import time

import pytest
from flask import Flask
from flask import json
from sqlalchemy import NullPool

from authlib.integrations.sqla_oauth2 import OAuth2TokenFamilyMixin
from authlib.integrations.sqla_oauth2 import OAuth2TokenMixin
from authlib.integrations.sqla_oauth2 import create_query_token_func
from authlib.integrations.sqla_oauth2 import create_refresh_token_family_grant
from authlib.integrations.sqla_oauth2 import create_token_family_revocation_endpoint
from authlib.oauth2.token_family import TokenFamilyIntrospectionEndpoint

from .models import Client
from .models import User
from .models import db
from .oauth2_server import create_authorization_server
from .oauth2_server import create_basic_header


class FamilyToken(db.Model, OAuth2TokenMixin, OAuth2TokenFamilyMixin):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"))
    user = db.relationship("User")

    def get_client(self):
        return db.session.query(Client).filter_by(client_id=self.client_id).one()

    def get_user(self):
        return self.user


query_token = create_query_token_func(db.session, FamilyToken)


def make_grant_class():
    base = create_refresh_token_family_grant(db.session, FamilyToken)

    class RefreshTokenFamilyGrant(base):
        def authenticate_user(self, credential):
            return db.session.get(User, credential.user_id)

    return RefreshTokenFamilyGrant


def make_introspection_class():
    class IntrospectionEndpoint(TokenFamilyIntrospectionEndpoint):
        def check_permission(self, token, client, request):
            return True

        def query_token(self, token, token_type_hint):
            return query_token(token, token_type_hint)

        def introspect_token(self, token):
            return {
                "client_id": token.client_id,
                "scope": token.scope,
                # family linkage must be stripped from the response
                "parent_id": token.parent_id,
            }

    return IntrospectionEndpoint


def register_family_endpoints(server, app):
    server.register_grant(make_grant_class())
    server.register_endpoint(
        create_token_family_revocation_endpoint(db.session, FamilyToken)
    )
    server.register_endpoint(make_introspection_class())

    @app.route("/oauth/revoke", methods=["POST"])
    def revoke_token():
        return server.create_endpoint_response("revocation")

    @app.route("/oauth/introspect", methods=["POST"])
    def introspect_token():
        return server.create_endpoint_response("introspection")

    return server


@pytest.fixture(autouse=True)
def server(server, app):
    app.config["OAUTH2_REFRESH_TOKEN_GENERATOR"] = True
    server.load_config(app.config)
    return register_family_endpoints(server, app)


@pytest.fixture(autouse=True)
def client(client, db):
    client.set_client_metadata(
        {
            "scope": "profile",
            "grant_types": ["refresh_token"],
            "redirect_uris": ["https://client.test/authorized"],
        }
    )
    db.session.add(client)
    db.session.commit()
    return client


def create_family_token(user, **kwargs):
    data = {
        "user_id": user.id,
        "client_id": "client-id",
        "token_type": "bearer",
        "scope": "profile",
        "expires_in": 3600,
    }
    data.update(kwargs)
    token = FamilyToken(**data)
    db.session.add(token)
    db.session.commit()
    return token


def build_chain(user):
    root = create_family_token(user, access_token="a1", refresh_token="r1")
    child = create_family_token(
        user, access_token="a2", refresh_token="r2", parent_id=root.id
    )
    grandchild = create_family_token(
        user, access_token="a3", refresh_token="r3", parent_id=child.id
    )
    return root, child, grandchild


def refresh(test_client, refresh_token):
    headers = create_basic_header("client-id", "client-secret")
    return test_client.post(
        "/oauth/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        },
        headers=headers,
    )


def revoke(test_client, token, **extra):
    headers = create_basic_header("client-id", "client-secret")
    data = {"token": token}
    data.update(extra)
    return test_client.post("/oauth/revoke", data=data, headers=headers)


def introspect(test_client, token):
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post("/oauth/introspect", data={"token": token}, headers=headers)
    assert rv.status_code == 200
    return json.loads(rv.data)


def test_refresh_builds_parent_child_chain(test_client, user, db):
    root = create_family_token(user, access_token="a1", refresh_token="r1")

    rv = refresh(test_client, "r1")
    assert rv.status_code == 200
    resp = json.loads(rv.data)
    assert "access_token" in resp
    assert "refresh_token" in resp

    db.session.expire_all()
    assert root.refresh_token_revoked_at
    assert root.access_token_revoked_at

    child = FamilyToken.query.filter_by(parent_id=root.id).one()
    assert child.refresh_token == resp["refresh_token"]
    assert child.access_token == resp["access_token"]

    rv = refresh(test_client, child.refresh_token)
    assert rv.status_code == 200
    grandchild = FamilyToken.query.filter_by(parent_id=child.id).one()
    assert grandchild.parent_id == child.id


def test_rotated_token_cannot_be_reused(test_client, user, db):
    create_family_token(user, access_token="a1", refresh_token="r1")
    rv = refresh(test_client, "r1")
    assert rv.status_code == 200

    rv = refresh(test_client, "r1")
    assert rv.status_code == 400
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_grant"


def test_revoke_default_revokes_token_and_descendants(test_client, user, db):
    root, child, grandchild = build_chain(user)

    rv = revoke(test_client, "r2", token_type_hint="refresh_token")
    assert rv.status_code == 200

    db.session.expire_all()
    assert root.refresh_token_revoked_at == 0
    assert child.refresh_token_revoked_at != 0
    assert child.access_token_revoked_at != 0
    assert grandchild.refresh_token_revoked_at != 0
    assert grandchild.access_token_revoked_at != 0


def test_revoke_with_family_parameter(test_client, user, db):
    root, child, grandchild = build_chain(user)

    rv = revoke(
        test_client,
        "r2",
        token_type_hint="refresh_token",
        family="true",
    )
    assert rv.status_code == 200

    db.session.expire_all()
    for token in (root, child, grandchild):
        assert token.refresh_token_revoked_at != 0
        assert token.access_token_revoked_at != 0


def test_revoke_with_falsy_family_parameter(test_client, user, db):
    root, child, grandchild = build_chain(user)

    rv = revoke(test_client, "r2", family="false")
    assert rv.status_code == 200

    db.session.expire_all()
    assert root.refresh_token_revoked_at == 0
    assert child.refresh_token_revoked_at != 0
    assert grandchild.refresh_token_revoked_at != 0


def test_revoke_unknown_token(test_client, user, db):
    root, _, _ = build_chain(user)

    rv = revoke(test_client, "missing-token")
    assert rv.status_code == 200

    db.session.expire_all()
    assert root.refresh_token_revoked_at == 0
    assert root.access_token_revoked_at == 0


def test_revoke_with_mismatched_hint(test_client, user, db):
    root, _, _ = build_chain(user)

    # the hint does not match the token type: the lookup misses,
    # nothing is revoked, and the answer is still 200
    rv = revoke(test_client, "r1", token_type_hint="access_token")
    assert rv.status_code == 200

    db.session.expire_all()
    assert root.refresh_token_revoked_at == 0
    assert root.access_token_revoked_at == 0


def test_revoke_with_unsupported_hint(test_client, user):
    build_chain(user)
    rv = revoke(test_client, "r1", token_type_hint="unsupported")
    resp = json.loads(rv.data)
    assert resp["error"] == "unsupported_token_type"


def test_revoke_token_bound_to_client(test_client, user, db):
    build_chain(user)
    client2 = Client(
        user_id=user.id,
        client_id="client-id-2",
        client_secret="client-secret-2",
    )
    client2.set_client_metadata(
        {
            "scope": "profile",
            "redirect_uris": ["https://client.test/authorized"],
        }
    )
    db.session.add(client2)
    db.session.commit()

    headers = create_basic_header("client-id-2", "client-secret-2")
    rv = test_client.post("/oauth/revoke", data={"token": "r1"}, headers=headers)
    assert rv.status_code == 400
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_grant"


def test_repeated_revocation_is_idempotent(test_client, user, db):
    root, _, _ = build_chain(user)

    rv = revoke(test_client, "r1", token_type_hint="refresh_token")
    assert rv.status_code == 200
    rv = revoke(test_client, "r1", token_type_hint="refresh_token")
    assert rv.status_code == 200

    db.session.expire_all()
    assert root.refresh_token_revoked_at != 0


def test_introspection_distinguishes_states(test_client, user, db):
    now = int(time.time())
    create_family_token(user, access_token="a1", refresh_token="r1")
    create_family_token(
        user,
        access_token="a2",
        refresh_token="r2",
        access_token_revoked_at=now,
    )
    create_family_token(
        user,
        access_token="a3",
        refresh_token="r3",
        issued_at=now - 7200,
    )

    resp = introspect(test_client, "missing-token")
    assert resp == {"active": False, "status": "unknown"}

    resp = introspect(test_client, "a2")
    assert resp == {"active": False, "status": "revoked"}

    resp = introspect(test_client, "a3")
    assert resp == {"active": False, "status": "expired"}

    resp = introspect(test_client, "a1")
    assert resp["active"] is True
    assert resp["status"] == "active"
    assert "parent_id" not in resp


def test_old_access_token_inactive_after_rotation(test_client, user, db):
    create_family_token(user, access_token="a1", refresh_token="r1")
    rv = refresh(test_client, "r1")
    assert rv.status_code == 200

    # a resource server introspecting the rotated-out access token
    # learns that it is no longer active
    resp = introspect(test_client, "a1")
    assert resp == {"active": False, "status": "revoked"}


def test_concurrent_refresh_creates_single_family_member():
    # the SQLite database must live inside the workspace: the sandbox
    # prevents SQLite from opening files in the system temp directory
    workdir = tempfile.mkdtemp(dir=".")
    try:
        run_concurrent_refresh(os.path.abspath(workdir))
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def run_concurrent_refresh(workdir):
    app = Flask(__name__)
    app.testing = True
    app.secret_key = "testing"
    app.config.update(
        {
            "SQLALCHEMY_TRACK_MODIFICATIONS": False,
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{workdir}/family.db",
            "OAUTH2_REFRESH_TOKEN_GENERATOR": True,
            "SQLALCHEMY_ENGINE_OPTIONS": {
                "connect_args": {"check_same_thread": False, "timeout": 30},
                "poolclass": NullPool,
            },
        }
    )
    db.init_app(app)
    with app.app_context():
        db.create_all()
        user = User(username="foo")
        db.session.add(user)
        db.session.flush()
        client = Client(
            user_id=user.id,
            client_id="client-id",
            client_secret="client-secret",
        )
        client.set_client_metadata(
            {
                "scope": "profile",
                "grant_types": ["refresh_token"],
                "redirect_uris": ["https://client.test/authorized"],
            }
        )
        root = FamilyToken(
            user_id=user.id,
            client_id="client-id",
            token_type="bearer",
            access_token="a1",
            refresh_token="r1",
            scope="profile",
            expires_in=3600,
        )
        db.session.add_all([client, root])
        db.session.commit()
        root_id = root.id

    server = create_authorization_server(app)

    # force both threads through validation and into the atomic
    # rotation at the same time, so the race guard is really exercised
    barrier = threading.Barrier(2)
    grant_class = make_grant_class()

    class RefreshTokenFamilyGrant(grant_class):
        def rotate_token(self, token, refresh_token):
            barrier.wait(timeout=30)
            return super().rotate_token(token, refresh_token)

    server.register_grant(RefreshTokenFamilyGrant)

    headers = create_basic_header("client-id", "client-secret")
    results = []

    def worker():
        barrier.wait()
        test_client = app.test_client()
        rv = test_client.post(
            "/oauth/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": "r1",
            },
            headers=headers,
        )
        results.append((rv.status_code, json.loads(rv.data)))

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    statuses = sorted(status for status, _ in results)
    assert statuses == [200, 400]
    error = next(resp for status, resp in results if status == 400)
    assert error["error"] == "invalid_grant"

    with app.app_context():
        # exactly one new family member was created
        children = FamilyToken.query.filter_by(parent_id=root_id).all()
        assert len(children) == 1
        # and the old token was revoked exactly once, never resurrected
        root = db.session.get(FamilyToken, root_id)
        assert root.refresh_token_revoked_at != 0
