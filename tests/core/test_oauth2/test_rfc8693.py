"""Tests for the OAuth 2.0 Token Exchange grant.

They use a minimal in-memory authorization server, client registry and token
store, so the whole delegation flow runs without any web framework.
"""

from collections import defaultdict

import pytest

from authlib.common.security import generate_token
from authlib.oauth2.rfc6749 import AuthorizationServer
from authlib.oauth2.rfc6749 import InvalidGrantError
from authlib.oauth2.rfc6749 import OAuth2Request
from authlib.oauth2.rfc6749.requests import BasicOAuth2Payload
from authlib.oauth2.rfc8693 import ACCESS_TOKEN_TYPE
from authlib.oauth2.rfc8693 import TOKEN_EXCHANGE_GRANT_TYPE
from authlib.oauth2.rfc8693 import DelegationDecision
from authlib.oauth2.rfc8693 import TokenExchangeGrant
from authlib.oauth2.rfc8693 import TokenInfo

TOKEN_ENDPOINT = "https://as.test/oauth/token"
ISSUER = "https://as.test"
PEER_ISSUER = "https://peer.example"
RESOURCE_API = "https://api.example.com/v1"
RESOURCE_OTHER = "https://other.example.com"
EXCHANGE_TYPE = TOKEN_EXCHANGE_GRANT_TYPE


class MemoryClient:
    def __init__(
        self,
        client_id,
        client_secret,
        grant_types,
        allowed_scope=None,
        allowed_resources=None,
        allowed_audiences=None,
    ):
        self.client_id = client_id
        self.client_secret = client_secret
        self.grant_types = grant_types
        self.allowed_scope = allowed_scope or ""
        self.allowed_resources = allowed_resources
        self.allowed_audiences = allowed_audiences

    def get_client_id(self):
        return self.client_id

    def check_client_secret(self, client_secret):
        return self.client_secret == client_secret

    def check_endpoint_auth_method(self, method, endpoint):
        return method == "client_secret_basic"

    def check_grant_type(self, grant_type):
        return grant_type in self.grant_types

    def get_allowed_scope(self, scope):
        if not scope:
            return scope
        allowed = set(self.allowed_scope.split())
        return " ".join(item for item in scope.split() if item in allowed)


class MemoryTokenStore:
    """The in-memory token storage shared by the validators and the server."""

    def __init__(self):
        self.tokens = {}

    def save(self, value, info: TokenInfo):
        self.tokens[value] = info

    def get(self, value):
        return self.tokens.get(value)

    def revoke(self, value):
        self.tokens.pop(value, None)


class FormOAuth2Request(OAuth2Request):
    def __init__(self, data, headers=None):
        super().__init__("POST", TOKEN_ENDPOINT, headers=headers or {})
        datalist = defaultdict(list)
        for key, value in data.items():
            if isinstance(value, list | tuple):
                datalist[key].extend(value)
            else:
                datalist[key].append(value)
        payload = BasicOAuth2Payload(data)
        payload._datalist = datalist
        self.payload = payload

    @property
    def form(self):
        return self.payload.data


def build_server(store, *, require_actor=False, fail_save=False):
    clients = {}

    class ExchangeGrant(TokenExchangeGrant):
        REQUIRE_ACTOR_TOKEN = require_actor

        def validate_subject_token(self, token, token_type):
            info = store.get(token)
            if info is None:
                raise InvalidGrantError("The subject token is invalid or expired.")
            return info

        def validate_actor_token(self, token, token_type):
            info = store.get(token)
            if info is None:
                raise InvalidGrantError("The actor token is invalid or expired.")
            # The actor token must itself be an access token that represents
            # an acting party, not a user delegation.
            if info.extra.get("kind") != "actor":
                raise InvalidGrantError("The actor token has the wrong type.")
            return info

        def authorize_delegation(
            self,
            client,
            subject,
            actor,
            requested_scope,
            requested_resources,
            requested_audiences,
        ):
            # A principal is only known by (issuer, sub): the same name at
            # another issuer is a different, untrusted subject.
            if subject.issuer != ISSUER:
                return DelegationDecision(allowed=False)

            decision = DelegationDecision()
            if requested_scope:
                granted = set((subject.scope or "").split())
                decision.scope = " ".join(
                    item for item in requested_scope.split() if item in granted
                )
                if set(requested_scope.split()) - granted:
                    # The hook itself refuses an over-broad request.
                    return DelegationDecision(allowed=False)
            if requested_resources:
                decision.resources = requested_resources
            return decision

        def get_allowed_resources(self):
            return self.request.client.allowed_resources

        def get_allowed_audiences(self):
            return self.request.client.allowed_audiences

    server = AuthorizationServer(scopes_supported=["read", "write", "admin"])

    def query_client(client_id):
        return clients.get(client_id)

    def save_token(token, request):
        if fail_save:
            raise RuntimeError("storage is down")
        store.save(
            token["access_token"],
            TokenInfo(
                subject=request.user.subject,
                issuer=ISSUER,
                scope=token.get("scope"),
                audience=token.get("audience", []),
                token_type=ACCESS_TOKEN_TYPE,
                client_id=request.client.get_client_id(),
                act=token.get("act"),
                extra={"kind": "subject"},
            ),
        )

    server.query_client = query_client
    server.save_token = save_token
    server.send_signal = lambda name, *args, **kwargs: None
    server.create_oauth2_request = lambda request: request
    server.handle_response = lambda status, body, headers: (status, body, headers)

    def generate_bearer_token(
        grant_type,
        client,
        user=None,
        scope=None,
        expires_in=None,
        include_refresh_token=True,
    ):
        token = {
            "token_type": "Bearer",
            "access_token": generate_token(42),
            "expires_in": 3600,
        }
        if scope:
            token["scope"] = scope
        return token

    server.register_token_generator("default", generate_bearer_token)
    server.register_grant(ExchangeGrant)
    return server, clients, ExchangeGrant


def exchange(server, client, **data):
    import base64

    from authlib.common.encoding import to_bytes
    from authlib.common.encoding import to_unicode

    raw = base64.b64encode(to_bytes(f"{client.client_id}:{client.client_secret}"))
    headers = {"Authorization": "Basic " + to_unicode(raw)}
    request = FormOAuth2Request({"grant_type": EXCHANGE_TYPE, **data}, headers=headers)
    return server.create_token_response(request)


@pytest.fixture
def context():
    store = MemoryTokenStore()
    server, clients, grant_cls = build_server(store)
    clients["service-a"] = MemoryClient(
        "service-a",
        "secret-a",
        [EXCHANGE_TYPE],
        allowed_scope="read write",
        allowed_resources=[RESOURCE_API],
        allowed_audiences=[RESOURCE_API],
    )
    clients["service-b"] = MemoryClient(
        "service-b",
        "secret-b",
        [EXCHANGE_TYPE],
        allowed_scope="read",
        allowed_resources=[RESOURCE_API],
        allowed_audiences=[RESOURCE_API],
    )
    return SimpleContext(server, clients, store, grant_cls)


class SimpleContext:
    def __init__(self, server, clients, store, grant_cls):
        self.server = server
        self.clients = clients
        self.store = store
        self.grant_cls = grant_cls


def subject_token(
    store, subject="user-1", scope="read write", act=None, issuer=ISSUER, audience=None
):
    value = generate_token(32)
    store.save(
        value,
        TokenInfo(
            subject=subject,
            issuer=issuer,
            scope=scope,
            audience=audience or [TOKEN_ENDPOINT],
            token_type=ACCESS_TOKEN_TYPE,
            client_id="origin",
            act=act,
            extra={"kind": "subject"},
        ),
    )
    return value


def actor_token(store, subject="service-a", scope="read", act=None):
    value = generate_token(32)
    store.save(
        value,
        TokenInfo(
            subject=subject,
            issuer=ISSUER,
            scope=scope,
            audience=[TOKEN_ENDPOINT],
            token_type=ACCESS_TOKEN_TYPE,
            client_id=subject,
            act=act,
            extra={"kind": "actor"},
        ),
    )
    return value


def test_two_legitimate_delegations(context):
    """Two chained exchanges preserve the user and record the act chain."""
    store = context.store
    client = context.clients["service-a"]

    first_subject = subject_token(store)
    first_actor = actor_token(store)
    status, body, _ = exchange(
        context.server,
        client,
        subject_token=first_subject,
        subject_token_type=ACCESS_TOKEN_TYPE,
        actor_token=first_actor,
        actor_token_type=ACCESS_TOKEN_TYPE,
        resource=RESOURCE_API,
        audience=RESOURCE_API,
        scope="read",
    )
    assert status == 200
    assert body["issued_token_type"] == ACCESS_TOKEN_TYPE
    assert body["token_type"] == "Bearer"
    assert body["scope"] == "read"
    assert body["resource"] == [RESOURCE_API]
    assert body["audience"] == [RESOURCE_API]
    assert body["act"] == {"sub": "service-a", "iss": ISSUER}

    # The input token is not revoked by the exchange.
    assert store.get(first_subject) is not None
    assert store.get(first_actor) is not None

    # Second hop: the freshly issued token becomes the subject, service-b acts.
    second_actor = actor_token(store, subject="service-b")
    status, body2, _ = exchange(
        context.server,
        context.clients["service-b"],
        subject_token=body["access_token"],
        subject_token_type=ACCESS_TOKEN_TYPE,
        actor_token=second_actor,
        actor_token_type=ACCESS_TOKEN_TYPE,
        resource=RESOURCE_API,
        audience=RESOURCE_API,
        scope="read",
    )
    assert status == 200
    chain = body2["act"]
    assert chain["sub"] == "service-b"
    assert chain["iss"] == ISSUER
    # The previous actor is nested: it is history, not an added permission.
    assert chain["act"] == {"sub": "service-a", "iss": ISSUER}

    # The stored token keeps the original user as its subject.
    stored = store.get(body2["access_token"])
    assert stored.subject == "user-1"
    assert stored.scope == "read"


def test_exchange_without_actor_is_allowed_by_default(context):
    client = context.clients["service-a"]
    token = subject_token(context.store)
    status, body, _ = exchange(
        context.server,
        client,
        subject_token=token,
        subject_token_type=ACCESS_TOKEN_TYPE,
        scope="read",
    )
    assert status == 200
    assert "act" not in body
    assert context.store.get(body["access_token"]).subject == "user-1"


def test_require_actor_token(context):
    server, clients, _ = build_server(context.store, require_actor=True)
    clients["strict"] = MemoryClient(
        "strict",
        "secret",
        [EXCHANGE_TYPE],
        allowed_scope="read",
        allowed_resources=[RESOURCE_API],
        allowed_audiences=[RESOURCE_API],
    )
    token = subject_token(context.store)
    status, body, _ = exchange(
        server,
        clients["strict"],
        subject_token=token,
        subject_token_type=ACCESS_TOKEN_TYPE,
    )
    assert status == 400
    assert body["error"] == "invalid_request"
    assert "actor_token" in body["error_description"]


def test_scope_escalation_is_rejected(context):
    """Asking for a scope the subject token does not have fails."""
    client = context.clients["service-a"]
    token = subject_token(context.store, scope="read")
    status, body, _ = exchange(
        context.server,
        client,
        subject_token=token,
        subject_token_type=ACCESS_TOKEN_TYPE,
        scope="read write",
    )
    assert status == 400
    assert body["error"] in {"invalid_scope", "access_denied"}
    assert "access_token" not in body


def test_forged_actor_type_is_rejected(context):
    """A subject-style token presented as an actor token is refused."""
    client = context.clients["service-a"]
    forged = subject_token(context.store, subject="service-a")
    status, body, _ = exchange(
        context.server,
        client,
        subject_token=subject_token(context.store),
        subject_token_type=ACCESS_TOKEN_TYPE,
        actor_token=forged,
        actor_token_type=ACCESS_TOKEN_TYPE,
    )
    assert status == 400
    assert body["error"] == "invalid_grant"


def test_cross_issuer_same_named_subject_is_rejected(context):
    """The same subject name at another issuer is not the trusted user."""
    client = context.clients["service-a"]
    foreign = subject_token(context.store, subject="user-1", issuer=PEER_ISSUER)
    status, body, _ = exchange(
        context.server,
        client,
        subject_token=foreign,
        subject_token_type=ACCESS_TOKEN_TYPE,
        scope="read",
    )
    assert status == 400
    assert body["error"] == "access_denied"


def test_unauthorized_audience_is_rejected(context):
    client = context.clients["service-a"]
    token = subject_token(context.store)
    status, body, _ = exchange(
        context.server,
        client,
        subject_token=token,
        subject_token_type=ACCESS_TOKEN_TYPE,
        audience="https://evil.example",
    )
    assert status == 400
    assert body["error"] == "invalid_target"


def test_unauthorized_resource_is_rejected(context):
    client = context.clients["service-a"]
    token = subject_token(context.store)
    status, body, _ = exchange(
        context.server,
        client,
        subject_token=token,
        subject_token_type=ACCESS_TOKEN_TYPE,
        resource=RESOURCE_OTHER,
    )
    assert status == 400
    assert body["error"] == "invalid_target"


def test_unsupported_token_type_is_rejected(context):
    client = context.clients["service-a"]
    token = subject_token(context.store)
    status, body, _ = exchange(
        context.server,
        client,
        subject_token=token,
        subject_token_type="urn:ietf:params:oauth:token-type:jwt",
    )
    assert status == 400
    assert body["error"] == "invalid_request"


def test_missing_subject_token(context):
    client = context.clients["service-a"]
    status, body, _ = exchange(
        context.server, client, subject_token_type=ACCESS_TOKEN_TYPE
    )
    assert status == 400
    assert body["error"] == "invalid_request"


def test_unknown_subject_token_is_invalid_grant(context):
    client = context.clients["service-a"]
    status, body, _ = exchange(
        context.server,
        client,
        subject_token="does-not-exist",
        subject_token_type=ACCESS_TOKEN_TYPE,
    )
    assert status == 400
    assert body["error"] == "invalid_grant"


def test_unauthorized_client(context):
    context.clients["outsider"] = MemoryClient(
        "outsider", "secret", ["client_credentials"]
    )
    client = context.clients["outsider"]
    token = subject_token(context.store)
    status, body, _ = exchange(
        context.server,
        client,
        subject_token=token,
        subject_token_type=ACCESS_TOKEN_TYPE,
    )
    assert status == 400
    assert body["error"] == "unauthorized_client"


def test_save_failure_returns_oauth_error(context):
    server, clients, _ = build_server(context.store, fail_save=True)
    clients["service-a"] = context.clients["service-a"]
    token = subject_token(context.store)
    status, body, _ = exchange(
        server,
        clients["service-a"],
        subject_token=token,
        subject_token_type=ACCESS_TOKEN_TYPE,
    )
    assert status == 400
    assert "error" in body
    assert "access_token" not in body


def test_historical_act_chain_is_preserved(context):
    """An act chain carried by the subject token is nested under the new
    actor and never used to grant permissions."""
    client = context.clients["service-a"]
    historical = {"sub": "old-service", "iss": ISSUER}
    token = subject_token(context.store, act=historical)
    actor = actor_token(context.store)
    status, body, _ = exchange(
        context.server,
        client,
        subject_token=token,
        subject_token_type=ACCESS_TOKEN_TYPE,
        actor_token=actor,
        actor_token_type=ACCESS_TOKEN_TYPE,
        scope="read",
    )
    assert status == 200
    assert body["act"] == {
        "sub": "service-a",
        "iss": ISSUER,
        "act": historical,
    }


def test_actor_token_does_not_widen_scope(context):
    """A powerful actor cannot grant scope the subject token lacks."""
    client = context.clients["service-a"]
    actor = actor_token(context.store, subject="service-a", scope="admin")
    token = subject_token(context.store, scope="read")
    status, body, _ = exchange(
        context.server,
        client,
        subject_token=token,
        subject_token_type=ACCESS_TOKEN_TYPE,
        actor_token=actor,
        actor_token_type=ACCESS_TOKEN_TYPE,
        scope="admin",
    )
    assert status == 400
    assert body["error"] in {"invalid_scope", "access_denied"}
