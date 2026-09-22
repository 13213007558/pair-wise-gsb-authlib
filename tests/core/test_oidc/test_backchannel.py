import time

import pytest
from joserfc import jwt
from joserfc.errors import ExpiredTokenError
from joserfc.errors import InvalidClaimError
from joserfc.errors import JoseError
from joserfc.errors import MissingClaimError
from joserfc.jwk import OctKey

from authlib.oidc.backchannel import BACKCHANNEL_LOGOUT_EVENT
from authlib.oidc.backchannel import BackChannelLogoutReceiver
from authlib.oidc.backchannel import InMemoryBackChannelLogoutStore
from authlib.oidc.backchannel import LogoutToken
from authlib.oidc.backchannel.claims import MissingSessionIdentifierError

ISSUER = "https://issuer-a.test"
CLIENT_ID = "client-a"

key = OctKey.import_key("secret", {"kty": "oct", "kid": "a"})
jwks = {"keys": [key.as_dict()]}


def make_logout_token(claims=None, **overrides):
    now = int(time.time())
    payload = {
        "iss": ISSUER,
        "aud": CLIENT_ID,
        "iat": now,
        "exp": now + 600,
        "jti": "unique-token-id",
        "events": {BACKCHANNEL_LOGOUT_EVENT: {}},
        "sid": "sid-1",
        "sub": "alice",
    }
    if claims:
        payload.update(claims)
    payload.update(overrides)
    payload = {k: v for k, v in payload.items() if v is not None}
    return jwt.encode({"alg": "HS256", "kid": "a"}, payload, key)


def make_receiver(store=None, **kwargs):
    kwargs.setdefault("algorithms", ["HS256"])
    return BackChannelLogoutReceiver(
        store or InMemoryBackChannelLogoutStore(),
        issuer=ISSUER,
        client_id=CLIENT_ID,
        jwks=jwks,
        **kwargs,
    )


def test_validate_logout_token():
    receiver = make_receiver()
    claims = receiver.validate_logout_token(make_logout_token())
    assert isinstance(claims, LogoutToken)
    assert claims["iss"] == ISSUER
    assert claims["sid"] == "sid-1"


def test_validate_logout_token_aud_list():
    receiver = make_receiver()
    token = make_logout_token(aud=["https://other.test", CLIENT_ID])
    claims = receiver.validate_logout_token(token)
    assert CLIENT_ID in claims["aud"]


@pytest.mark.parametrize("missing", ["iss", "aud", "iat", "exp", "jti", "events"])
def test_validate_logout_token_missing_claims(missing):
    receiver = make_receiver()
    token = make_logout_token(**{missing: None})
    with pytest.raises(MissingClaimError):
        receiver.validate_logout_token(token)


def test_validate_logout_token_requires_sub_or_sid():
    receiver = make_receiver()
    token = make_logout_token(sub=None, sid=None)
    with pytest.raises(MissingSessionIdentifierError):
        receiver.validate_logout_token(token)


def test_validate_logout_token_rejects_nonce():
    receiver = make_receiver()
    token = make_logout_token(nonce="n-0S6_WzA2Mj")
    with pytest.raises(InvalidClaimError) as exc_info:
        receiver.validate_logout_token(token)
    assert "nonce" in str(exc_info.value)


@pytest.mark.parametrize(
    "events",
    [
        {},
        {"http://schemas.openid.net/event/unknown": {}},
        {BACKCHANNEL_LOGOUT_EVENT: "not-an-object"},
        "not-a-dict",
    ],
)
def test_validate_logout_token_events(events):
    receiver = make_receiver()
    token = make_logout_token(events=events)
    with pytest.raises(InvalidClaimError):
        receiver.validate_logout_token(token)


def test_validate_logout_token_wrong_issuer():
    receiver = make_receiver()
    token = make_logout_token(iss="https://attacker.test")
    with pytest.raises(InvalidClaimError):
        receiver.validate_logout_token(token)


def test_validate_logout_token_wrong_audience():
    receiver = make_receiver()
    token = make_logout_token(aud="client-b")
    with pytest.raises(InvalidClaimError):
        receiver.validate_logout_token(token)


def test_validate_logout_token_expired():
    now = int(time.time())
    receiver = make_receiver()
    token = make_logout_token(iat=now - 3600, exp=now - 1800)
    with pytest.raises(ExpiredTokenError):
        receiver.validate_logout_token(token)


def test_validate_logout_token_algorithm_not_allowed():
    receiver = make_receiver(algorithms=["RS256"])
    token = make_logout_token()
    with pytest.raises(JoseError):
        receiver.validate_logout_token(token)


def test_validate_logout_token_bad_signature():
    other_key = OctKey.import_key("other-secret", {"kty": "oct", "kid": "a"})
    now = int(time.time())
    token = jwt.encode(
        {"alg": "HS256", "kid": "a"},
        {
            "iss": ISSUER,
            "aud": CLIENT_ID,
            "iat": now,
            "exp": now + 600,
            "jti": "x",
            "events": {BACKCHANNEL_LOGOUT_EVENT: {}},
            "sid": "sid-1",
        },
        other_key,
    )
    receiver = make_receiver()
    with pytest.raises(JoseError):
        receiver.validate_logout_token(token)


def test_process_logout_with_sid():
    store = InMemoryBackChannelLogoutStore()
    store.add_session(ISSUER, CLIENT_ID, "sid-1", "alice")
    store.add_session(ISSUER, CLIENT_ID, "sid-2", "alice")

    receiver = make_receiver(store)
    receiver.process_logout(make_logout_token(sid="sid-1"))

    assert store.get_session(ISSUER, CLIENT_ID, "sid-1") is None
    assert store.get_session(ISSUER, CLIENT_ID, "sid-2") is not None


def test_process_logout_with_sub_only():
    store = InMemoryBackChannelLogoutStore()
    store.add_session(ISSUER, CLIENT_ID, "sid-1", "alice")
    store.add_session(ISSUER, CLIENT_ID, "sid-2", "alice")
    store.add_session(ISSUER, CLIENT_ID, "sid-3", "bob")

    receiver = make_receiver(store)
    receiver.process_logout(make_logout_token(sid=None, sub="alice"))

    assert store.get_session(ISSUER, CLIENT_ID, "sid-1") is None
    assert store.get_session(ISSUER, CLIENT_ID, "sid-2") is None
    assert store.get_session(ISSUER, CLIENT_ID, "sid-3") is not None


def test_process_logout_sid_and_sub_match():
    store = InMemoryBackChannelLogoutStore()
    store.add_session(ISSUER, CLIENT_ID, "sid-1", "alice")

    receiver = make_receiver(store)
    receiver.process_logout(make_logout_token(sid="sid-1", sub="alice"))
    assert store.get_session(ISSUER, CLIENT_ID, "sid-1") is None


def test_process_logout_sid_and_sub_mismatch():
    store = InMemoryBackChannelLogoutStore()
    store.add_session(ISSUER, CLIENT_ID, "sid-1", "alice")

    receiver = make_receiver(store)
    with pytest.raises(InvalidClaimError):
        receiver.process_logout(make_logout_token(sid="sid-1", sub="mallory"))
    # mismatched session is left untouched
    assert store.get_session(ISSUER, CLIENT_ID, "sid-1") is not None


def test_process_logout_replay_is_idempotent():
    store = InMemoryBackChannelLogoutStore()
    store.add_session(ISSUER, CLIENT_ID, "sid-1", "alice")

    receiver = make_receiver(store)
    token = make_logout_token(sid="sid-1")
    receiver.process_logout(token)
    # replaying the same logout token still succeeds
    receiver.process_logout(token)
    assert store.get_session(ISSUER, CLIENT_ID, "sid-1") is None


def test_process_logout_unknown_session_is_success():
    store = InMemoryBackChannelLogoutStore()
    receiver = make_receiver(store)
    claims = receiver.process_logout(make_logout_token(sid="no-such-session"))
    assert claims["sid"] == "no-such-session"


def test_process_logout_storage_error_propagates():
    class FailingStore(InMemoryBackChannelLogoutStore):
        def delete_sessions_by_sid(self, issuer, client_id, sid):
            raise ConnectionError("storage unavailable")

    receiver = make_receiver(FailingStore())
    with pytest.raises(ConnectionError):
        receiver.process_logout(make_logout_token(sid="sid-1"))


def test_process_logout_storage_error_propagates_for_sub():
    class FailingStore(InMemoryBackChannelLogoutStore):
        def delete_sessions_by_sub(self, issuer, client_id, sub):
            raise ConnectionError("storage unavailable")

    receiver = make_receiver(FailingStore())
    with pytest.raises(ConnectionError):
        receiver.process_logout(make_logout_token(sid=None, sub="alice"))


def test_multi_issuer_same_sub_isolation():
    """Sessions of the same subject under another issuer or client are
    never touched by a logout."""
    other_issuer = "https://issuer-b.test"
    other_client = "client-b"

    store = InMemoryBackChannelLogoutStore()
    # alice has two devices on issuer-a/client-a
    store.add_session(ISSUER, CLIENT_ID, "phone", "alice")
    store.add_session(ISSUER, CLIENT_ID, "laptop", "alice")
    # same sub name on another issuer and another client
    store.add_session(other_issuer, CLIENT_ID, "phone", "alice")
    store.add_session(ISSUER, other_client, "phone", "alice")
    # another user on the same issuer/client
    store.add_session(ISSUER, CLIENT_ID, "tablet", "bob")

    receiver = make_receiver(store)

    # sid logout only kills the one device
    receiver.process_logout(make_logout_token(sid="phone", sub="alice"))
    assert store.get_session(ISSUER, CLIENT_ID, "phone") is None
    assert store.get_session(ISSUER, CLIENT_ID, "laptop") is not None
    assert store.get_session(other_issuer, CLIENT_ID, "phone") is not None
    assert store.get_session(ISSUER, other_client, "phone") is not None

    # sub-only logout kills all of alice's sessions on this issuer/client
    receiver.process_logout(make_logout_token(sid=None, sub="alice"))
    assert store.get_session(ISSUER, CLIENT_ID, "laptop") is None
    # ...but not the same sub on other issuers or clients
    assert store.get_session(other_issuer, CLIENT_ID, "phone") is not None
    assert store.get_session(ISSUER, other_client, "phone") is not None
    # ...and not other users
    assert store.get_session(ISSUER, CLIENT_ID, "tablet") is not None
