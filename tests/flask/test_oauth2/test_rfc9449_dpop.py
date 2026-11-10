"""Flask ResourceProtector integration tests for RFC 9449 DPoP."""

import pytest
from flask import jsonify
from joserfc import jwt
from joserfc.jwk import ECKey

from authlib.integrations.flask_oauth2 import ResourceProtector
from authlib.oauth2.rfc6750 import BearerTokenValidator
from authlib.oauth2.rfc6750.errors import InvalidTokenError
from authlib.oauth2.rfc9449 import DPoPProofValidator
from authlib.oauth2.rfc9449 import DPoPProtector
from authlib.oauth2.rfc9449 import InMemoryReplayStore
from authlib.oauth2.rfc9449 import compute_ath

FIXED_NOW = 1_700_000_000.0
ACCESS_TOKEN = "flask-access-token"
OTHER_TOKEN = "flask-other-token"
# The Flask test client builds request.url from its own server configuration
# (localhost), never from forwarding headers. The proof htu must match that
# trusted URL.
BASE_URL = "http://localhost"


class FixedClock:
    def __init__(self, now=FIXED_NOW):
        self.now = now

    def __call__(self):
        return self.now


@pytest.fixture
def clock():
    return FixedClock()


@pytest.fixture
def key():
    return ECKey.generate_key("P-256")


@pytest.fixture
def other_key():
    return ECKey.generate_key("P-256")


@pytest.fixture
def jkt(key):
    return key.thumbprint()


class RecordingBearerTokenValidator(BearerTokenValidator):
    """Bearer validator recording every callback invocation."""

    def __init__(self, tokens):
        super().__init__()
        self._tokens = tokens
        self.authenticate_calls = []
        self.validate_request_calls = []
        self.validate_token_calls = []

    def authenticate_token(self, token_string):
        self.authenticate_calls.append(token_string)
        return self._tokens.get(token_string)

    def validate_request(self, request):
        self.validate_request_calls.append(request)

    def validate_token(self, token, scopes, request):
        self.validate_token_calls.append(token)
        if not token:
            raise InvalidTokenError()


def make_proof(
    key,
    jti,
    *,
    method="GET",
    path="/resource",
    token=ACCESS_TOKEN,
    iat=FIXED_NOW,
    nonce=None,
    base_url=BASE_URL,
):
    url = f"{base_url}{path}"
    header = {"alg": "ES256", "typ": "dpop+jwt", "jwk": key.as_dict(private=False)}
    claims = {
        "jti": jti,
        "htm": method,
        "htu": url,
        "iat": int(iat),
        "ath": compute_ath(token),
    }
    if nonce is not None:
        claims["nonce"] = nonce
    return jwt.encode(header, claims, key)


@pytest.fixture
def setup(app, clock, jkt):
    tokens = {
        ACCESS_TOKEN: {"cnf": {"jkt": jkt}, "scope": "profile"},
        OTHER_TOKEN: {"cnf": {"jkt": jkt}, "scope": "profile"},
        "unbound-token": {"scope": "profile"},
    }
    validator = RecordingBearerTokenValidator(tokens)
    replay_store = InMemoryReplayStore(clock=clock)
    proof_validator = DPoPProofValidator(clock=clock, replay_store=replay_store)

    require_oauth = ResourceProtector()
    require_oauth.register_token_validator(validator)
    require_oauth.register_extension(DPoPProtector(proof_validator=proof_validator))

    endpoint_calls = []

    @app.route("/resource", methods=["GET", "POST"])
    @require_oauth()
    def resource():
        endpoint_calls.append("resource")
        return jsonify(status="ok")

    @app.route("/other")
    @require_oauth()
    def other():
        endpoint_calls.append("other")
        return jsonify(status="ok")

    return {
        "validator": validator,
        "replay_store": replay_store,
        "endpoint_calls": endpoint_calls,
    }


def dpop_headers(proof, token=ACCESS_TOKEN):
    return {"Authorization": f"DPoP {token}", "DPoP": proof}


def test_valid_dpop_request_reaches_endpoint(test_client, setup, key, jkt):
    rv = test_client.get("/resource", headers=dpop_headers(make_proof(key, "j1")))
    assert rv.status_code == 200
    assert rv.json == {"status": "ok"}

    validator = setup["validator"]
    assert validator.authenticate_calls == [ACCESS_TOKEN]
    assert len(validator.validate_request_calls) == 1
    assert len(validator.validate_token_calls) == 1
    assert setup["endpoint_calls"] == ["resource"]


def test_bearer_scheme_works_for_unbound_token(test_client, setup):
    rv = test_client.get("/resource", headers={"Authorization": "Bearer unbound-token"})
    assert rv.status_code == 200
    assert setup["endpoint_calls"] == ["resource"]


def test_bound_token_rejected_with_bearer_scheme(test_client, setup):
    rv = test_client.get(
        "/resource", headers={"Authorization": f"Bearer {ACCESS_TOKEN}"}
    )
    assert rv.status_code == 401
    assert rv.json["error"] == "invalid_dpop_proof"
    assert rv.headers["WWW-Authenticate"].startswith("DPoP")
    # The validator ran, but the protected callback must never be invoked.
    assert setup["validator"].authenticate_calls == [ACCESS_TOKEN]
    assert setup["endpoint_calls"] == []


def test_missing_dpop_header_challenges(test_client, setup):
    rv = test_client.get("/resource", headers={"Authorization": f"DPoP {ACCESS_TOKEN}"})
    assert rv.status_code == 401
    assert rv.json["error"] == "invalid_dpop_proof"
    assert setup["endpoint_calls"] == []


def test_method_change_rejected(test_client, setup, key):
    proof = make_proof(key, "j2", method="POST")
    rv = test_client.get("/resource", headers=dpop_headers(proof))
    assert rv.status_code == 401
    assert rv.json["error"] == "invalid_dpop_proof"
    assert setup["endpoint_calls"] == []

    proof = make_proof(key, "j3", method="GET")
    rv = test_client.post("/resource", headers=dpop_headers(proof))
    assert rv.status_code == 401
    assert setup["endpoint_calls"] == []


def test_path_change_rejected(test_client, setup, key):
    proof = make_proof(key, "j4", path="/other")
    rv = test_client.get("/resource", headers=dpop_headers(proof))
    assert rv.status_code == 401
    assert rv.json["error"] == "invalid_dpop_proof"
    assert setup["endpoint_calls"] == []


def test_query_and_fragment_are_not_part_of_htu(test_client, setup, key):
    # The proof htu is the path only; the live request URL carries a query.
    proof = make_proof(key, "j5")
    rv = test_client.get("/resource?page=2&size=10#frag", headers=dpop_headers(proof))
    assert rv.status_code == 200
    assert setup["endpoint_calls"] == ["resource"]


def test_token_change_rejected_by_ath(test_client, setup, key):
    proof = make_proof(key, "j6", token=OTHER_TOKEN)
    rv = test_client.get("/resource", headers=dpop_headers(proof, token=ACCESS_TOKEN))
    assert rv.status_code == 401
    assert rv.json["error"] == "invalid_dpop_proof"
    assert setup["endpoint_calls"] == []


def test_public_key_change_rejected(test_client, setup, key, other_key, jkt):
    proof = make_proof(other_key, "j7")
    rv = test_client.get("/resource", headers=dpop_headers(proof))
    assert rv.status_code == 401
    assert rv.json["error"] == "invalid_dpop_proof"
    assert setup["endpoint_calls"] == []


def test_replay_accepted_only_once(test_client, setup, key):
    proof = make_proof(key, "replayed")
    first = test_client.get("/resource", headers=dpop_headers(proof))
    assert first.status_code == 200

    second = test_client.get("/resource", headers=dpop_headers(proof))
    assert second.status_code == 401
    assert second.json["error"] == "invalid_dpop_proof"
    assert setup["endpoint_calls"] == ["resource"]


def test_invalid_token_still_returns_invalid_token(test_client, setup, key):
    proof = make_proof(key, "j8", token="unknown-token")
    rv = test_client.get(
        "/resource", headers=dpop_headers(proof, token="unknown-token")
    )
    assert rv.status_code == 401
    assert rv.json["error"] == "invalid_token"
    assert setup["endpoint_calls"] == []


def test_nonce_challenge_and_retry(app, test_client, clock, key, jkt):
    tokens = {ACCESS_TOKEN: {"cnf": {"jkt": jkt}}}
    validator = RecordingBearerTokenValidator(tokens)
    nonces = ["nonce-1", "nonce-2"]
    require_oauth = ResourceProtector()
    require_oauth.register_token_validator(validator)
    require_oauth.register_extension(
        DPoPProtector(
            proof_validator=DPoPProofValidator(
                clock=clock,
                replay_store=InMemoryReplayStore(clock=clock),
                nonce_generator=lambda: nonces[0],
            ),
            nonce_generator=lambda: nonces[0],
            expected_nonce=lambda request: "required-nonce",
        )
    )

    endpoint_calls = []

    @app.route("/nonced")
    @require_oauth()
    def nonced():
        endpoint_calls.append("nonced")
        return jsonify(status="ok")

    # First attempt without the nonce gets a use_dpop_nonce challenge.
    rv = test_client.get(
        "/nonced", headers=dpop_headers(make_proof(key, "n1", path="/nonced"))
    )
    assert rv.status_code == 401
    assert rv.json["error"] == "use_dpop_nonce"
    assert rv.headers["DPoP-Nonce"] == "nonce-1"
    assert 'nonce="nonce-1"' in rv.headers["WWW-Authenticate"]
    assert endpoint_calls == []

    # Retrying with the expected nonce succeeds.
    rv = test_client.get(
        "/nonced",
        headers=dpop_headers(
            make_proof(key, "n2", path="/nonced", nonce="required-nonce")
        ),
    )
    assert rv.status_code == 200
    assert endpoint_calls == ["nonced"]
