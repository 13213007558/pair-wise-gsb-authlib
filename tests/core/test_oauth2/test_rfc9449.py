"""Tests for the resource server side of RFC 9449 DPoP."""

import threading
import warnings

import pytest
from joserfc import jwt
from joserfc.jwk import ECKey
from joserfc.jwk import RSAKey

from authlib.oauth2.rfc6749 import JsonRequest
from authlib.oauth2.rfc6749 import ResourceProtector
from authlib.oauth2.rfc6750 import BearerTokenValidator
from authlib.oauth2.rfc6750.errors import InvalidTokenError
from authlib.oauth2.rfc9449 import DPoPProofValidator
from authlib.oauth2.rfc9449 import DPoPProtector
from authlib.oauth2.rfc9449 import InMemoryReplayStore
from authlib.oauth2.rfc9449 import InvalidDPoPProofError
from authlib.oauth2.rfc9449 import ReplayStore
from authlib.oauth2.rfc9449 import UseDPoPNonceError
from authlib.oauth2.rfc9449 import compute_ath
from authlib.oauth2.rfc9449 import get_token_confirmation_jkt
from authlib.oauth2.rfc9449 import normalize_url

URL = "https://rs.test/resource"
METHOD = "GET"
ACCESS_TOKEN = "access-token-string"
FIXED_NOW = 1_700_000_000.0


class FakeClock:
    """A controllable clock for deterministic time-window tests."""

    def __init__(self, now=FIXED_NOW):
        self.now = now

    def __call__(self):
        return self.now


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def key():
    return ECKey.generate_key("P-256")


@pytest.fixture
def other_key():
    return ECKey.generate_key("P-256")


@pytest.fixture
def jkt(key):
    return key.thumbprint()


def make_proof(
    key,
    jti="proof-jti",
    *,
    method=METHOD,
    url=URL,
    token=ACCESS_TOKEN,
    iat=FIXED_NOW,
    alg="ES256",
    typ="dpop+jwt",
    with_jwk=True,
    with_ath=True,
    nonce=None,
    extra_claims=None,
    sign_key=None,
):
    """Build a signed DPoP proof. Keyword arguments allow producing invalid ones."""
    header = {"alg": alg, "typ": typ}
    if with_jwk:
        header["jwk"] = key.as_dict(private=False)
    claims = {
        "jti": jti,
        "htm": method,
        "htu": url,
        "iat": iat,
    }
    if with_ath:
        claims["ath"] = compute_ath(token)
    if nonce is not None:
        claims["nonce"] = nonce
    if extra_claims:
        claims.update(extra_claims)
    encode_kwargs = {}
    if alg not in ("RS256", "ES256", "HS256"):
        from authlib.oauth2.rfc9449.proof import build_registry

        encode_kwargs["registry"] = build_registry([alg])
    return jwt.encode(header, claims, sign_key or key, **encode_kwargs)


class RecordingValidator(BearerTokenValidator):
    """Token validator whose authenticate/validate calls are recorded."""

    def __init__(self, tokens):
        super().__init__()
        self._tokens = tokens
        self.authenticate_calls = []
        self.validate_calls = []

    def authenticate_token(self, token_string):
        self.authenticate_calls.append(token_string)
        return self._tokens.get(token_string)

    def validate_token(self, token, scopes, request):
        self.validate_calls.append(token)
        if not token:
            raise InvalidTokenError()


def build_protector(
    tokens,
    clock,
    *,
    replay_store=None,
    nonce_generator=None,
    expected_nonce=None,
    proof_validator=None,
):
    validator = RecordingValidator(tokens)
    protector = ResourceProtector()
    protector.register_token_validator(validator)
    protector.register_extension(
        DPoPProtector(
            proof_validator=proof_validator
            or DPoPProofValidator(
                clock=clock,
                replay_store=replay_store
                if replay_store is not None
                else InMemoryReplayStore(),
                nonce_generator=nonce_generator,
            ),
            nonce_generator=nonce_generator,
            expected_nonce=expected_nonce,
        )
    )
    return protector, validator


def make_request(proof, *, method=METHOD, url=URL, token=ACCESS_TOKEN, scheme="DPoP"):
    headers = {"Authorization": f"{scheme} {token}"}
    if proof is not None:
        headers["DPoP"] = proof
    return JsonRequest(method, url, headers=headers)


# -- pure helpers ---------------------------------------------------------


def test_compute_ath_matches_rfc():
    import base64
    import hashlib

    expected = (
        base64.urlsafe_b64encode(hashlib.sha256(ACCESS_TOKEN.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    assert compute_ath(ACCESS_TOKEN) == expected


@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://rs.test/a", "https://rs.test/a"),
        ("https://rs.test/a?x=1", "https://rs.test/a"),
        ("https://rs.test/a?x=1#frag", "https://rs.test/a"),
        ("https://rs.test/a#frag", "https://rs.test/a"),
    ],
)
def test_normalize_url_strips_query_and_fragment(url, expected):
    assert normalize_url(url) == expected


def test_get_token_confirmation_jkt_shapes(key, jkt):
    assert get_token_confirmation_jkt({"cnf": {"jkt": jkt}}) == jkt

    class Token:
        cnf = {"jkt": jkt}

    assert get_token_confirmation_jkt(Token()) == jkt

    class BoundConfirmation:
        def __init__(self, thumbprint):
            self.jkt = thumbprint

    class Token2:
        cnf = BoundConfirmation(jkt)

    assert get_token_confirmation_jkt(Token2()) == jkt
    assert get_token_confirmation_jkt({}) is None
    assert get_token_confirmation_jkt({"cnf": {}}) is None


# -- proof validator ------------------------------------------------------


def test_valid_proof(clock, key, jkt):
    validator = DPoPProofValidator(clock=clock, replay_store=InMemoryReplayStore())
    proof = validator.validate(
        make_proof(key),
        http_method=METHOD,
        url=URL,
        access_token=ACCESS_TOKEN,
    )
    assert proof.jkt == jkt
    assert proof.jti == "proof-jti"
    assert proof.claims["htm"] == METHOD


def test_typ_must_be_dpop_jwt(clock, key):
    validator = DPoPProofValidator(clock=clock)
    with pytest.raises(InvalidDPoPProofError, match="typ"):
        validator.validate(
            make_proof(key, typ="JWT"),
            http_method=METHOD,
            url=URL,
            access_token=ACCESS_TOKEN,
        )


def test_symmetric_algorithm_rejected(clock, key):
    from joserfc.jwk import OctKey

    oct_key = OctKey.generate_key(256)
    proof = jwt.encode(
        {"alg": "HS256", "typ": "dpop+jwt", "jwk": oct_key.as_dict()},
        {
            "jti": "j",
            "htm": METHOD,
            "htu": URL,
            "iat": int(clock.now),
            "ath": compute_ath(ACCESS_TOKEN),
        },
        oct_key,
    )
    validator = DPoPProofValidator(clock=clock)
    with pytest.raises(InvalidDPoPProofError):
        validator.validate(
            proof, http_method=METHOD, url=URL, access_token=ACCESS_TOKEN
        )


@pytest.mark.parametrize("alg", ["RS256", "ES256", "EdDSA"])
def test_accepted_asymmetric_algorithms(clock, alg):
    if alg == "RS256":
        alg_key = RSAKey.generate_key(2048)
    elif alg == "ES256":
        alg_key = ECKey.generate_key("P-256")
    else:
        from joserfc.jwk import OKPKey

        alg_key = OKPKey.generate_key("Ed25519")

    validator = DPoPProofValidator(clock=clock)
    with warnings.catch_warnings():
        # joserfc flags EdDSA as deprecated by RFC 9864; DPoP still allows it.
        warnings.simplefilter("ignore", category=UserWarning)
        proof_string = make_proof(alg_key, alg=alg)
        proof = validator.validate(
            proof_string,
            http_method=METHOD,
            url=URL,
            access_token=ACCESS_TOKEN,
        )
    assert proof.header["alg"] == alg


def test_algorithm_allow_list(clock, key):
    validator = DPoPProofValidator(clock=clock, algorithms=["ES384"])
    with pytest.raises(InvalidDPoPProofError, match="Algorithm"):
        validator.validate(
            make_proof(key),
            http_method=METHOD,
            url=URL,
            access_token=ACCESS_TOKEN,
        )


def test_missing_jwk_header(clock, key):
    validator = DPoPProofValidator(clock=clock)
    with pytest.raises(InvalidDPoPProofError, match="jwk"):
        validator.validate(
            make_proof(key, with_jwk=False),
            http_method=METHOD,
            url=URL,
            access_token=ACCESS_TOKEN,
        )


def test_private_jwk_rejected(clock, key):
    proof = jwt.encode(
        {"alg": "ES256", "typ": "dpop+jwt", "jwk": key.as_dict(private=True)},
        {
            "jti": "j",
            "htm": METHOD,
            "htu": URL,
            "iat": int(clock.now),
            "ath": compute_ath(ACCESS_TOKEN),
        },
        key,
    )
    validator = DPoPProofValidator(clock=clock)
    with pytest.raises(InvalidDPoPProofError, match="public"):
        validator.validate(
            proof, http_method=METHOD, url=URL, access_token=ACCESS_TOKEN
        )


def test_signature_must_match_jwk(clock, key, other_key):
    # Header embeds key's public JWK but the proof is signed with another key.
    proof = make_proof(key, sign_key=other_key, jti="forged")
    validator = DPoPProofValidator(clock=clock)
    with pytest.raises(InvalidDPoPProofError, match="signature"):
        validator.validate(
            proof, http_method=METHOD, url=URL, access_token=ACCESS_TOKEN
        )


def test_htm_mismatch(clock, key):
    validator = DPoPProofValidator(clock=clock)
    with pytest.raises(InvalidDPoPProofError, match="htm"):
        validator.validate(
            make_proof(key, method="POST"),
            http_method=METHOD,
            url=URL,
            access_token=ACCESS_TOKEN,
        )


def test_htu_mismatch(clock, key):
    validator = DPoPProofValidator(clock=clock)
    with pytest.raises(InvalidDPoPProofError, match="htu"):
        validator.validate(
            make_proof(key, url="https://rs.test/other"),
            http_method=METHOD,
            url=URL,
            access_token=ACCESS_TOKEN,
        )


def test_htu_ignores_query_and_fragment(clock, key):
    validator = DPoPProofValidator(clock=clock, replay_store=InMemoryReplayStore())
    proof = validator.validate(
        make_proof(key),
        http_method=METHOD,
        url=URL + "?page=2#section",
        access_token=ACCESS_TOKEN,
    )
    assert proof.claims["htu"] == URL


@pytest.mark.parametrize("delta", [-600, 600])
def test_iat_outside_window(clock, key, delta):
    validator = DPoPProofValidator(clock=clock, leeway=10, max_age=300)
    proof = make_proof(key, iat=clock.now + delta)
    with pytest.raises(InvalidDPoPProofError):
        validator.validate(
            proof, http_method=METHOD, url=URL, access_token=ACCESS_TOKEN
        )


def test_iat_within_leeway(clock, key):
    validator = DPoPProofValidator(
        clock=clock, leeway=30, max_age=300, replay_store=InMemoryReplayStore()
    )
    # Slightly in the future is accepted within the leeway.
    proof = validator.validate(
        make_proof(key, iat=clock.now + 20),
        http_method=METHOD,
        url=URL,
        access_token=ACCESS_TOKEN,
    )
    assert proof.jti == "proof-jti"


def test_iat_must_be_numeric(clock, key):
    validator = DPoPProofValidator(clock=clock)
    with pytest.raises(InvalidDPoPProofError, match="iat"):
        validator.validate(
            make_proof(key, iat="yesterday"),
            http_method=METHOD,
            url=URL,
            access_token=ACCESS_TOKEN,
        )


def test_ath_must_match_token(clock, key):
    validator = DPoPProofValidator(clock=clock)
    with pytest.raises(InvalidDPoPProofError, match="ath"):
        validator.validate(
            make_proof(key),
            http_method=METHOD,
            url=URL,
            access_token="a-different-token",
        )


def test_missing_ath_rejected(clock, key):
    validator = DPoPProofValidator(clock=clock)
    with pytest.raises(InvalidDPoPProofError, match="ath"):
        validator.validate(
            make_proof(key, with_ath=False),
            http_method=METHOD,
            url=URL,
            access_token=ACCESS_TOKEN,
        )


def test_malformed_proof(clock):
    validator = DPoPProofValidator(clock=clock)
    with pytest.raises(InvalidDPoPProofError, match="valid JWT"):
        validator.validate(
            "not-a-jwt",
            http_method=METHOD,
            url=URL,
            access_token=ACCESS_TOKEN,
        )


def test_missing_proof_string(clock):
    validator = DPoPProofValidator(clock=clock)
    for empty in ("", None):
        with pytest.raises(InvalidDPoPProofError, match="Missing DPoP proof"):
            validator.validate(
                empty,
                http_method=METHOD,
                url=URL,
                access_token=ACCESS_TOKEN,
            )


def test_proof_with_non_json_payload(clock, key):
    import base64

    header = base64.urlsafe_b64encode(b'{"alg":"ES256","typ":"dpop+jwt"}').rstrip(b"=")
    payload = base64.urlsafe_b64encode(b"not-json").rstrip(b"=")
    validator = DPoPProofValidator(clock=clock)
    with pytest.raises(InvalidDPoPProofError, match="valid JWT"):
        validator.validate(
            (header + b"." + payload + b".signature").decode(),
            http_method=METHOD,
            url=URL,
            access_token=ACCESS_TOKEN,
        )


def test_invalid_jwk_rejected(clock, key):
    proof = jwt.encode(
        {"alg": "ES256", "typ": "dpop+jwt", "jwk": {"kty": "bogus"}},
        {
            "jti": "j",
            "htm": METHOD,
            "htu": URL,
            "iat": int(clock.now),
            "ath": compute_ath(ACCESS_TOKEN),
        },
        key,
    )
    validator = DPoPProofValidator(clock=clock)
    with pytest.raises(InvalidDPoPProofError, match="valid JWK"):
        validator.validate(
            proof, http_method=METHOD, url=URL, access_token=ACCESS_TOKEN
        )


def test_non_object_jwk_rejected(clock, key):
    import base64

    # Hand-craft the JWT: joserfc refuses to encode a non-object JWK header.
    header = base64.urlsafe_b64encode(
        b'{"alg":"ES256","typ":"dpop+jwt","jwk":"not-an-object"}'
    ).rstrip(b"=")
    payload = base64.urlsafe_b64encode(
        (
            '{"jti":"j","htm":"%s","htu":"%s","iat":%d,"ath":"%s"}'
            % (METHOD, URL, int(clock.now), compute_ath(ACCESS_TOKEN))
        ).encode()
    ).rstrip(b"=")
    proof = (header + b"." + payload + b".signature").decode()
    validator = DPoPProofValidator(clock=clock)
    with pytest.raises(InvalidDPoPProofError):
        validator.validate(
            proof, http_method=METHOD, url=URL, access_token=ACCESS_TOKEN
        )


def test_missing_required_claim(clock, key):
    for claim in ("jti", "htm", "htu", "iat"):
        # Rebuild a proof without the target claim.
        header = {"alg": "ES256", "typ": "dpop+jwt", "jwk": key.as_dict(private=False)}
        claims = {
            "jti": f"missing-{claim}",
            "htm": METHOD,
            "htu": URL,
            "iat": int(clock.now),
            "ath": compute_ath(ACCESS_TOKEN),
        }
        del claims[claim]
        proof = jwt.encode(header, claims, key)
        validator = DPoPProofValidator(clock=clock)
        with pytest.raises(InvalidDPoPProofError, match=claim):
            validator.validate(
                proof, http_method=METHOD, url=URL, access_token=ACCESS_TOKEN
            )


def test_empty_jti_rejected(clock, key):
    validator = DPoPProofValidator(clock=clock)
    with pytest.raises(InvalidDPoPProofError, match="jti"):
        validator.validate(
            make_proof(key, jti=""),
            http_method=METHOD,
            url=URL,
            access_token=ACCESS_TOKEN,
        )


def test_dpop_scheme_with_empty_token_rejected(clock, key, jkt):
    protector, _ = build_protector({ACCESS_TOKEN: {"cnf": {"jkt": jkt}}}, clock)
    request = JsonRequest(
        "GET", URL, headers={"Authorization": "DPoP", "DPoP": make_proof(key)}
    )
    with pytest.raises(InvalidDPoPProofError, match="Missing access token"):
        protector.validate_request(None, request)


def test_nonce_required_challenge(clock, key):
    validator = DPoPProofValidator(clock=clock, nonce_generator=lambda: "server-nonce")
    with pytest.raises(UseDPoPNonceError) as exc_info:
        validator.validate(
            make_proof(key),
            http_method=METHOD,
            url=URL,
            access_token=ACCESS_TOKEN,
            expected_nonce="server-nonce",
        )
    headers = dict(exc_info.value.get_headers())
    assert headers["DPoP-Nonce"] == "server-nonce"
    assert 'nonce="server-nonce"' in headers["WWW-Authenticate"]


def test_nonce_must_match(clock, key):
    validator = DPoPProofValidator(clock=clock, nonce_generator=lambda: "fresh-nonce")
    with pytest.raises(UseDPoPNonceError) as exc_info:
        validator.validate(
            make_proof(key, nonce="stale-nonce"),
            http_method=METHOD,
            url=URL,
            access_token=ACCESS_TOKEN,
            expected_nonce="server-nonce",
        )
    assert dict(exc_info.value.get_headers())["DPoP-Nonce"] == "fresh-nonce"


def test_nonce_accepted(clock, key):
    validator = DPoPProofValidator(
        clock=clock,
        nonce_generator=lambda: "server-nonce",
        replay_store=InMemoryReplayStore(),
    )
    proof = validator.validate(
        make_proof(key, nonce="server-nonce"),
        http_method=METHOD,
        url=URL,
        access_token=ACCESS_TOKEN,
        expected_nonce="server-nonce",
    )
    assert proof.claims["nonce"] == "server-nonce"


def test_nonce_mismatch_without_generator_is_invalid(clock, key):
    # Without a nonce generator the server cannot issue a challenge, so a bad
    # nonce is a plain invalid_dpop_proof rather than use_dpop_nonce.
    validator = DPoPProofValidator(clock=clock)
    with pytest.raises(InvalidDPoPProofError, match="nonce"):
        validator.validate(
            make_proof(key, nonce="stale"),
            http_method=METHOD,
            url=URL,
            access_token=ACCESS_TOKEN,
            expected_nonce="required",
        )


# -- replay store ---------------------------------------------------------


def test_replay_rejected(clock, key):
    store = InMemoryReplayStore()
    validator = DPoPProofValidator(clock=clock, replay_store=store)
    proof_string = make_proof(key, jti="once")
    validator.validate(
        proof_string, http_method=METHOD, url=URL, access_token=ACCESS_TOKEN
    )
    with pytest.raises(InvalidDPoPProofError, match="already been used"):
        validator.validate(
            proof_string, http_method=METHOD, url=URL, access_token=ACCESS_TOKEN
        )


def test_failed_validation_does_not_reserve_jti(clock, key, other_key):
    store = InMemoryReplayStore()
    validator = DPoPProofValidator(clock=clock, replay_store=store)
    forged = make_proof(key, sign_key=other_key, jti="reused")
    for _ in range(3):
        with pytest.raises(InvalidDPoPProofError):
            validator.validate(
                forged, http_method=METHOD, url=URL, access_token=ACCESS_TOKEN
            )
    # The failed proofs never touched the store, so the jti is still free.
    assert store.check_and_store("reused", clock.now + 300) is True

    # A genuinely valid proof with another jti is accepted once.
    valid = make_proof(key, jti="valid-once")
    proof = validator.validate(
        valid, http_method=METHOD, url=URL, access_token=ACCESS_TOKEN
    )
    assert proof.jti == "valid-once"
    with pytest.raises(InvalidDPoPProofError, match="already been used"):
        validator.validate(
            valid, http_method=METHOD, url=URL, access_token=ACCESS_TOKEN
        )


def test_rejected_replay_stays_rejected_within_window(clock):
    # Entries are never purged on the hot path, so a jti accepted once stays
    # rejected for its whole window regardless of clock movements.
    store = InMemoryReplayStore()
    assert store.check_and_store("jti", clock.now + 300) is True
    clock.now += 100
    assert store.check_and_store("jti", clock.now + 300) is False
    clock.now += 250
    assert store.check_and_store("jti", clock.now + 300) is False


def test_full_store_purges_expired_entries_only(clock):
    store = InMemoryReplayStore(max_entries=2, clock=clock)
    assert store.check_and_store("expired", clock.now - 1) is True
    assert store.check_and_store("fresh", clock.now + 300) is True
    # The store is full; the expired entry is purged to make room.
    assert store.check_and_store("new", clock.now + 300) is True
    assert "expired" not in store._entries
    assert "fresh" in store._entries


def test_full_store_without_expired_entries_raises(clock):
    store = InMemoryReplayStore(max_entries=2, clock=clock)
    store.check_and_store("a", clock.now + 300)
    store.check_and_store("b", clock.now + 300)
    with pytest.raises(RuntimeError, match="full"):
        store.check_and_store("c", clock.now + 300)


def test_periodic_purge_removes_expired_entries(clock):
    store = InMemoryReplayStore(max_entries=3, clock=clock)
    store.check_and_store("expired", clock.now - 1)
    store.check_and_store("fresh", clock.now + 300)
    assert "expired" in store._entries

    # Reaching the purge interval triggers a purge using the fixed clock.
    store.check_and_store("third", clock.now + 300)
    assert "expired" not in store._entries
    assert "fresh" in store._entries


def test_concurrent_valid_jti_passes_once(clock, key):
    store = InMemoryReplayStore()
    results = []
    barrier = threading.Barrier(8)

    def worker():
        barrier.wait()
        results.append(store.check_and_store("concurrent-jti", clock.now + 300))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert results.count(True) == 1
    assert results.count(False) == 7


def test_replay_store_protocol():
    assert isinstance(InMemoryReplayStore(), ReplayStore)


# -- ResourceProtector integration ---------------------------------------


def test_dpop_scheme_success(clock, key, jkt):
    tokens = {ACCESS_TOKEN: {"cnf": {"jkt": jkt}}}
    protector, validator = build_protector(tokens, clock)
    request = make_request(make_proof(key))
    token = protector.validate_request(None, request)
    assert token == tokens[ACCESS_TOKEN]
    assert validator.authenticate_calls == [ACCESS_TOKEN]
    assert validator.validate_calls == [tokens[ACCESS_TOKEN]]


def test_bearer_scheme_accepted_for_unbound_token(clock, key):
    tokens = {ACCESS_TOKEN: {"scope": "profile"}}
    protector, validator = build_protector(tokens, clock)
    request = make_request(None, scheme="Bearer")
    token = protector.validate_request(None, request)
    assert token == tokens[ACCESS_TOKEN]
    assert validator.validate_calls


def test_bearer_scheme_rejected_for_bound_token(clock, key, jkt):
    protector, _ = build_protector({ACCESS_TOKEN: {"cnf": {"jkt": jkt}}}, clock)
    request = make_request(None, scheme="Bearer")
    with pytest.raises(InvalidDPoPProofError, match="DPoP scheme"):
        protector.validate_request(None, request)


def test_dpop_scheme_requires_proof(clock, key, jkt):
    protector, _ = build_protector(
        {ACCESS_TOKEN: {"cnf": {"jkt": jkt}}},
        clock,
        nonce_generator=lambda: "n",
    )
    request = make_request(None)
    with pytest.raises(UseDPoPNonceError):
        protector.validate_request(None, request)


def test_dpop_scheme_missing_proof_without_nonce_generator(clock, key, jkt):
    protector, _ = build_protector({ACCESS_TOKEN: {"cnf": {"jkt": jkt}}}, clock)
    request = make_request(None)
    with pytest.raises(InvalidDPoPProofError, match="Missing DPoP proof"):
        protector.validate_request(None, request)


def test_key_binding_mismatch(clock, key, other_key, jkt):
    protector, _ = build_protector({ACCESS_TOKEN: {"cnf": {"jkt": jkt}}}, clock)
    request = make_request(make_proof(other_key))
    with pytest.raises(InvalidDPoPProofError, match="binding"):
        protector.validate_request(None, request)


def test_dpop_scheme_with_unbound_token_rejected(clock, key):
    protector, _ = build_protector({ACCESS_TOKEN: {"scope": "profile"}}, clock)
    request = make_request(make_proof(key))
    with pytest.raises(InvalidDPoPProofError, match="not bound"):
        protector.validate_request(None, request)


def test_method_change_rejected(clock, key, jkt):
    protector, _ = build_protector({ACCESS_TOKEN: {"cnf": {"jkt": jkt}}}, clock)
    request = make_request(make_proof(key, method="POST"), method="GET")
    with pytest.raises(InvalidDPoPProofError):
        protector.validate_request(None, request)


def test_path_change_rejected(clock, key, jkt):
    protector, _ = build_protector({ACCESS_TOKEN: {"cnf": {"jkt": jkt}}}, clock)
    request = JsonRequest(
        "GET",
        "https://rs.test/other",
        headers={
            "Authorization": f"DPoP {ACCESS_TOKEN}",
            "DPoP": make_proof(key),
        },
    )
    with pytest.raises(InvalidDPoPProofError, match="htu"):
        protector.validate_request(None, request)


def test_token_change_rejected_by_ath(clock, key, jkt):
    protector, _ = build_protector(
        {ACCESS_TOKEN: {"cnf": {"jkt": jkt}}, "another-token": {"cnf": {"jkt": jkt}}},
        clock,
    )
    request = make_request(make_proof(key), token="another-token")
    with pytest.raises(InvalidDPoPProofError, match="ath"):
        protector.validate_request(None, request)


def test_replay_through_protector(clock, key, jkt):
    protector, _ = build_protector({ACCESS_TOKEN: {"cnf": {"jkt": jkt}}}, clock)
    proof = make_proof(key)
    protector.validate_request(None, make_request(proof))
    with pytest.raises(InvalidDPoPProofError, match="already been used"):
        protector.validate_request(None, make_request(proof))


def test_nonce_flow_through_protector(clock, key, jkt):
    nonces = ["first", "second"]
    protector, _ = build_protector(
        {ACCESS_TOKEN: {"cnf": {"jkt": jkt}}},
        clock,
        nonce_generator=lambda: nonces.pop(0),
        expected_nonce=lambda request: "required",
    )

    request = make_request(make_proof(key))
    with pytest.raises(UseDPoPNonceError) as exc_info:
        protector.validate_request(None, request)
    assert dict(exc_info.value.get_headers())["DPoP-Nonce"] == "first"

    request = make_request(make_proof(key, jti="second", nonce="required"))
    token = protector.validate_request(None, request)
    assert token["cnf"]["jkt"] == jkt


def test_multiple_dpop_headers_rejected(clock, key, jkt):
    class MultiHeaders(dict):
        def getlist(self, name):
            if name == "DPoP":
                return ["p1", "p2"]
            value = self.get(name)
            return [value] if value is not None else []

    protector, _ = build_protector({ACCESS_TOKEN: {"cnf": {"jkt": jkt}}}, clock)
    request = JsonRequest(
        "GET",
        URL,
        headers=MultiHeaders(Authorization=f"DPoP {ACCESS_TOKEN}"),
    )
    with pytest.raises(InvalidDPoPProofError, match="Multiple DPoP"):
        protector.validate_request(None, request)
