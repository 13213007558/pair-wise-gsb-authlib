"""Tests for the RP side of OIDC Back-Channel Logout 1.0."""

import time

import pytest
from joserfc import jwt
from joserfc.jwk import KeySet
from joserfc.jwk import RSAKey

from authlib.oauth2.rfc6749 import ClientMixin
from authlib.oidc.backchannel import BackchannelLogoutReceiver
from authlib.oidc.backchannel import BackchannelLogoutSender
from authlib.oidc.backchannel import InvalidLogoutTokenError
from authlib.oidc.backchannel import LogoutTokenStore
from authlib.oidc.backchannel import create_logout_token
from authlib.oidc.backchannel import validate_logout_token

OP1 = "https://op1.test"
OP2 = "https://op2.test"
RP_A = "client-a"
RP_B = "client-b"

op1_key = RSAKey.generate_key(2048, parameters={"kid": "op1"}, private=True)
op2_key = RSAKey.generate_key(2048, parameters={"kid": "op2"}, private=True)
PUBLIC_KEYS = {
    OP1: KeySet([RSAKey.import_key(op1_key.as_dict(private=False))]),
    OP2: KeySet([RSAKey.import_key(op2_key.as_dict(private=False))]),
}
PRIVATE_KEYS = {OP1: op1_key, OP2: op2_key}


def make_logout_token(issuer=OP1, audience=RP_A, key=None, **claims):
    """Create a logout token, with claims overrides for the invalid cases."""
    key = key or PRIVATE_KEYS[issuer]
    now = int(time.time())
    payload = {
        "iss": issuer,
        "aud": audience,
        "iat": now,
        "exp": now + 120,
        "jti": f"jti-{now}-{id(claims)}",
        "events": {"http://schemas.openid.net/event/backchannel-logout": {}},
        "sub": "user-1",
        **claims,
    }
    payload = {k: v for k, v in payload.items() if v is not None}
    header = claims.pop("header", None) or {"alg": "RS256", "typ": "logout+jwt"}
    return jwt.encode(header, payload, key)


class Session:
    def __init__(self, issuer, client_id, sid, sub):
        self.issuer = issuer
        self.client_id = client_id
        self.sid = sid
        self.sub = sub
        self.active = True

    def __repr__(self):
        return f"Session({self.issuer}, {self.client_id}, {self.sid}, {self.sub})"


class MemoryStore(LogoutTokenStore):
    """In-memory store: the jti record and the invalidations commit together."""

    def __init__(self):
        self.jtis = {}
        self.broken = False

    def record_logout(self, *, jti, sessions, expires_at):
        if self.broken:
            raise RuntimeError("database unavailable")
        if jti in self.jtis:
            return False
        self.jtis[jti] = expires_at
        for session in sessions:
            session.active = False
        return True


class MemoryReceiver(BackchannelLogoutReceiver):
    """A receiver for one RP, trusting both OPs."""

    def __init__(self, client_id, sessions, store):
        self.client_id = client_id
        self.sessions = sessions
        self.store = store

    def get_issuer_keys(self, issuer):
        return PUBLIC_KEYS.get(issuer)

    def get_client_id(self, issuer):
        return self.client_id

    def get_logout_sessions(self, issuer, client_id, sub, sid):
        return [
            session
            for session in self.sessions
            if session.active
            and session.issuer == issuer
            and session.client_id == client_id
            and (sid is None or session.sid == sid)
            and (sub is None or session.sub == sub)
        ]

    def get_store(self):
        return self.store


@pytest.fixture
def sessions():
    return [
        Session(OP1, RP_A, "sid-1", "user-1"),
        Session(OP1, RP_A, "sid-2", "user-1"),
        Session(OP1, RP_A, "sid-3", "user-2"),
        Session(OP2, RP_A, "sid-1", "user-1"),  # same sid, other issuer
        Session(OP1, RP_B, "sid-1", "user-1"),  # same sid, other client
        Session(OP2, RP_B, "sid-9", "user-1"),
    ]


@pytest.fixture
def receivers(sessions):
    store_a, store_b = MemoryStore(), MemoryStore()
    return (
        MemoryReceiver(RP_A, sessions, store_a),
        MemoryReceiver(RP_B, sessions, store_b),
    )


def active(sessions, issuer, client_id):
    return sorted(
        session.sid
        for session in sessions
        if session.active
        and session.issuer == issuer
        and session.client_id == client_id
    )


# Validation


def test_validate_logout_token_returns_claims():
    token = create_logout_token(OP1, RP_A, PRIVATE_KEYS[OP1], sub="user-1", sid="sid-1")
    claims = validate_logout_token(token, PUBLIC_KEYS[OP1], issuer=OP1, audience=RP_A)
    assert claims["sub"] == "user-1"
    assert claims["sid"] == "sid-1"
    assert claims["iss"] == OP1
    assert claims["aud"] == RP_A


def test_validate_logout_token_rejects_id_token():
    """A plain ID token of the same issuer is not a logout notification."""
    now = int(time.time())
    id_token = jwt.encode(
        {"alg": "RS256", "typ": "JWT"},
        {
            "iss": OP1,
            "aud": RP_A,
            "sub": "user-1",
            "iat": now,
            "exp": now + 600,
            "jti": "id-token-1",
            "auth_time": now,
        },
        PRIVATE_KEYS[OP1],
    )
    with pytest.raises(InvalidLogoutTokenError, match="event"):
        validate_logout_token(id_token, PUBLIC_KEYS[OP1], issuer=OP1, audience=RP_A)


def test_validate_logout_token_rejects_id_token_with_nonce():
    """An ID token with a nonce is rejected, even with a forged events claim."""
    token = make_logout_token(nonce="abc123")
    with pytest.raises(InvalidLogoutTokenError, match="nonce"):
        validate_logout_token(token, PUBLIC_KEYS[OP1], issuer=OP1, audience=RP_A)


def test_validate_logout_token_rejects_missing_events_member():
    token = make_logout_token(events={"http://schemas.openid.net/event/other": {}})
    with pytest.raises(InvalidLogoutTokenError, match="event"):
        validate_logout_token(token, PUBLIC_KEYS[OP1], issuer=OP1, audience=RP_A)


def test_validate_logout_token_rejects_non_object_event_value():
    token = make_logout_token(
        events={"http://schemas.openid.net/event/backchannel-logout": "yes"}
    )
    with pytest.raises(InvalidLogoutTokenError, match="event"):
        validate_logout_token(token, PUBLIC_KEYS[OP1], issuer=OP1, audience=RP_A)


def test_validate_logout_token_requires_sub_or_sid():
    token = make_logout_token(sub=None)
    with pytest.raises(InvalidLogoutTokenError, match="sub.*sid|sid.*sub"):
        validate_logout_token(token, PUBLIC_KEYS[OP1], issuer=OP1, audience=RP_A)


def test_validate_logout_token_accepts_sid_only():
    token = make_logout_token(sub=None, sid="sid-1")
    claims = validate_logout_token(token, PUBLIC_KEYS[OP1], issuer=OP1, audience=RP_A)
    assert claims["sid"] == "sid-1"
    assert "sub" not in claims


def test_validate_logout_token_rejects_wrong_issuer():
    token = make_logout_token(issuer=OP2)
    with pytest.raises(InvalidLogoutTokenError):
        validate_logout_token(token, PUBLIC_KEYS[OP2], issuer=OP1, audience=RP_A)


def test_validate_logout_token_rejects_wrong_audience():
    token = make_logout_token(audience=RP_B)
    with pytest.raises(InvalidLogoutTokenError):
        validate_logout_token(token, PUBLIC_KEYS[OP1], issuer=OP1, audience=RP_A)


def test_validate_logout_token_rejects_wrong_signature():
    """A token signed with the key of the other OP is rejected."""
    token = make_logout_token(issuer=OP1, key=PRIVATE_KEYS[OP2])
    with pytest.raises(InvalidLogoutTokenError):
        validate_logout_token(token, PUBLIC_KEYS[OP1], issuer=OP1, audience=RP_A)


def test_validate_logout_token_rejects_expired():
    now = int(time.time())
    token = make_logout_token(iat=now - 300, exp=now - 180)
    with pytest.raises(InvalidLogoutTokenError, match="exp"):
        validate_logout_token(token, PUBLIC_KEYS[OP1], issuer=OP1, audience=RP_A)


def test_validate_logout_token_expired_within_leeway():
    now = int(time.time())
    token = make_logout_token(iat=now - 300, exp=now - 5)
    claims = validate_logout_token(
        token, PUBLIC_KEYS[OP1], issuer=OP1, audience=RP_A, leeway=10
    )
    assert claims["iss"] == OP1


@pytest.mark.parametrize("missing", ["exp", "iat", "jti"])
def test_validate_logout_token_requires_time_and_jti_claims(missing):
    token = make_logout_token(**{missing: None})
    with pytest.raises(InvalidLogoutTokenError, match=missing):
        validate_logout_token(token, PUBLIC_KEYS[OP1], issuer=OP1, audience=RP_A)


def test_validate_logout_token_rejects_none_algorithm():
    token = jwt.encode(
        {"alg": "none"},
        {
            "iss": OP1,
            "aud": RP_A,
            "sub": "user-1",
            "iat": int(time.time()),
            "exp": int(time.time()) + 120,
            "jti": "jti-none",
            "events": {"http://schemas.openid.net/event/backchannel-logout": {}},
        },
        PRIVATE_KEYS[OP1],
        algorithms=["none"],
    )
    with pytest.raises(InvalidLogoutTokenError):
        validate_logout_token(token, PUBLIC_KEYS[OP1], issuer=OP1, audience=RP_A)


@pytest.mark.parametrize(
    "header",
    [
        {"alg": "RS256"},
        {"alg": "RS256", "typ": "logout+jwt"},
        {"alg": "RS256", "typ": "application/logout+jwt"},
        {"alg": "RS256", "typ": "JWT"},
    ],
)
def test_validate_logout_token_typ_header(header):
    """The typ header is not a discriminator: the events claim is."""
    token = make_logout_token(header=header)
    claims = validate_logout_token(token, PUBLIC_KEYS[OP1], issuer=OP1, audience=RP_A)
    assert claims["iss"] == OP1


def test_validate_logout_token_rejects_malformed():
    with pytest.raises(InvalidLogoutTokenError):
        validate_logout_token("not-a-jwt", PUBLIC_KEYS[OP1], issuer=OP1, audience=RP_A)


# Reception: precise session deletion across two OPs and two RPs


def test_receiver_deletes_only_the_matching_sid(receivers, sessions):
    """A sid logout deletes this sid at this issuer and client only."""
    receiver_a, _ = receivers
    token = create_logout_token(OP1, RP_A, PRIVATE_KEYS[OP1], sub="user-1", sid="sid-1")
    result = receiver_a.handle_logout_token(token)

    assert not result.already_processed
    assert [s.sid for s in result.sessions] == ["sid-1"]
    # the targeted session is gone
    assert active(sessions, OP1, RP_A) == ["sid-2", "sid-3"]
    # the same sid at the other issuer and the other client survives
    assert active(sessions, OP2, RP_A) == ["sid-1"]
    assert active(sessions, OP1, RP_B) == ["sid-1"]
    assert active(sessions, OP2, RP_B) == ["sid-9"]


def test_receiver_sid_only_logout_matches_all_users_of_the_sid(receivers, sessions):
    """Without a sub, the sid alone selects the session."""
    receiver_a, _ = receivers
    token = create_logout_token(OP2, RP_A, PRIVATE_KEYS[OP2], sid="sid-1")
    receiver_a.handle_logout_token(token)

    assert active(sessions, OP2, RP_A) == []
    assert active(sessions, OP1, RP_A) == ["sid-1", "sid-2", "sid-3"]


def test_receiver_sub_only_logout_scope(receivers, sessions):
    """A sub-only logout deletes every session of this user at this issuer
    and client, and nothing else."""
    receiver_a, _ = receivers
    token = create_logout_token(OP1, RP_A, PRIVATE_KEYS[OP1], sub="user-1")
    result = receiver_a.handle_logout_token(token)

    assert sorted(s.sid for s in result.sessions) == ["sid-1", "sid-2"]
    # both sessions of user-1 at (OP1, RP_A) are gone, user-2 survives
    assert active(sessions, OP1, RP_A) == ["sid-3"]
    # the same sub at the other issuer and the other client survives
    assert active(sessions, OP2, RP_A) == ["sid-1"]
    assert active(sessions, OP1, RP_B) == ["sid-1"]
    assert active(sessions, OP2, RP_B) == ["sid-9"]


def test_receiver_scopes_each_rp_to_its_own_client_id(receivers, sessions):
    """RP-B only clears its own sessions, even with the same sid values."""
    _, receiver_b = receivers
    token = create_logout_token(OP1, RP_B, PRIVATE_KEYS[OP1], sub="user-1", sid="sid-1")
    receiver_b.handle_logout_token(token)

    assert active(sessions, OP1, RP_B) == []
    assert active(sessions, OP1, RP_A) == ["sid-1", "sid-2", "sid-3"]


def test_receiver_rejects_token_for_another_client(receivers):
    """A token for RP-B is rejected by the endpoint of RP-A."""
    receiver_a, _ = receivers
    token = create_logout_token(OP1, RP_B, PRIVATE_KEYS[OP1], sub="user-1")
    with pytest.raises(InvalidLogoutTokenError):
        receiver_a.handle_logout_token(token)


def test_receiver_rejects_untrusted_issuer(receivers):
    receiver_a, _ = receivers
    token = create_logout_token(
        "https://evil.test", RP_A, PRIVATE_KEYS[OP1], sub="user-1"
    )
    with pytest.raises(InvalidLogoutTokenError, match="[Uu]ntrusted"):
        receiver_a.handle_logout_token(token)


def test_receiver_rejects_malformed_token(receivers):
    receiver_a, _ = receivers
    with pytest.raises(InvalidLogoutTokenError):
        receiver_a.handle_logout_token("garbage")


def test_receiver_rejects_token_without_iss(receivers):
    receiver_a, _ = receivers
    token = jwt.encode(
        {"alg": "RS256"}, {"aud": RP_A, "sub": "user-1"}, PRIVATE_KEYS[OP1]
    )
    with pytest.raises(InvalidLogoutTokenError, match="iss"):
        receiver_a.handle_logout_token(token)


# Idempotency and persistence failures


def test_receiver_duplicate_notification_is_idempotent(receivers, sessions):
    """A replayed token is a success, and changes nothing more."""
    receiver_a, _ = receivers
    token = create_logout_token(OP1, RP_A, PRIVATE_KEYS[OP1], sub="user-1", sid="sid-1")
    first = receiver_a.handle_logout_token(token)
    second = receiver_a.handle_logout_token(token)

    assert not first.already_processed
    assert second.already_processed
    assert second.claims["jti"] == first.claims["jti"]
    assert active(sessions, OP1, RP_A) == ["sid-2", "sid-3"]
    assert active(sessions, OP2, RP_A) == ["sid-1"]


def test_receiver_does_not_invalidate_sessions_on_store_failure(receivers, sessions):
    """A persistence failure raises before any success, and keeps the state."""
    receiver_a, _ = receivers
    receiver_a.store.broken = True
    token = create_logout_token(OP1, RP_A, PRIVATE_KEYS[OP1], sub="user-1", sid="sid-1")
    with pytest.raises(RuntimeError, match="database unavailable"):
        receiver_a.handle_logout_token(token)

    # nothing was recorded, nothing was invalidated
    assert receiver_a.store.jtis == {}
    assert active(sessions, OP1, RP_A) == ["sid-1", "sid-2", "sid-3"]

    # the OP retries the same token: it succeeds once the store recovers
    receiver_a.store.broken = False
    result = receiver_a.handle_logout_token(token)
    assert not result.already_processed
    assert active(sessions, OP1, RP_A) == ["sid-2", "sid-3"]


# End-to-end: the OP sender notifies the RP receiver


def test_sender_to_receiver_roundtrip(sessions, receivers):
    """The sender of the OP delivers a token that the receiver accepts."""
    receiver_a, _ = receivers

    class FakeClient(ClientMixin):
        client_metadata = {"backchannel_logout_uri": "https://rp-a.test/logout"}

        def get_client_id(self):
            return RP_A

    class Sender(BackchannelLogoutSender):
        def get_issuer(self):
            return OP1

        def resolve_client_private_key(self, client):
            return PRIVATE_KEYS[OP1]

        def get_logout_sessions(self, sub, sid):
            return [(FakeClient(), sid)]

        def deliver_logout_token(self, client, uri, logout_token):
            self.result = receiver_a.handle_logout_token(logout_token)

    sender = Sender()
    sender.send_logout(sub="user-1", sid="sid-1")

    assert not sender.result.already_processed
    assert sender.result.claims["iss"] == OP1
    assert sender.result.claims["aud"] == RP_A
    assert active(sessions, OP1, RP_A) == ["sid-2", "sid-3"]
    assert active(sessions, OP2, RP_A) == ["sid-1"]
