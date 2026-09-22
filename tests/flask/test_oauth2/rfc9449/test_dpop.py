import threading
import time

import pytest
from flask import json
from flask import jsonify
from joserfc import jwt
from joserfc.jwk import ECKey
from joserfc.jwk import OctKey

from authlib.common.security import generate_token
from authlib.integrations.flask_oauth2 import ResourceProtector
from authlib.oauth2.rfc6749.grants import ClientCredentialsGrant
from authlib.oauth2.rfc9068 import JWTBearerTokenValidator
from authlib.oauth2.rfc9449 import DPoPGrantExtension
from authlib.oauth2.rfc9449 import DPoPProofValidator
from authlib.oauth2.rfc9449 import DPoPTokenGenerator
from authlib.oauth2.rfc9449 import DPoPTokenValidator
from authlib.oauth2.rfc9449 import InMemoryDPoPReplayStore
from authlib.oauth2.rfc9449 import compute_ath

from ..oauth2_server import create_basic_header

ISSUER = "https://provider.test"
RESOURCE_SERVER = "resource-server-id"
TOKEN_URL = "http://localhost/oauth/token"
RESOURCE_URL = "http://localhost/protected"


@pytest.fixture
def as_key():
    return ECKey.generate_key("P-256")


@pytest.fixture
def dpop_key():
    return ECKey.generate_key("P-256")


@pytest.fixture
def other_key():
    return ECKey.generate_key("P-256")


@pytest.fixture(autouse=True)
def client(client, db):
    client.set_client_metadata(
        {
            "scope": "profile",
            "redirect_uris": ["https://client.test/authorized"],
            "grant_types": ["client_credentials"],
        }
    )
    db.session.add(client)
    db.session.commit()
    return client


@pytest.fixture
def replay_store():
    return InMemoryDPoPReplayStore()


@pytest.fixture
def proof_validator(replay_store):
    return DPoPProofValidator(store=replay_store)


@pytest.fixture(autouse=True)
def server(server, as_key, proof_validator):
    class MyDPoPTokenGenerator(DPoPTokenGenerator):
        def get_jwks(self):
            return as_key

        def get_audiences(self, client, user, scope):
            return RESOURCE_SERVER

    server.register_grant(
        ClientCredentialsGrant,
        [DPoPGrantExtension(proof_validator=proof_validator)],
    )
    server.register_token_generator(
        "client_credentials", MyDPoPTokenGenerator(issuer=ISSUER)
    )
    return server


@pytest.fixture(autouse=True)
def resource_protector(app, as_key, proof_validator):
    class MyDPoPTokenValidator(DPoPTokenValidator):
        def get_jwks(self):
            return as_key

    class MyBearerTokenValidator(JWTBearerTokenValidator):
        def get_jwks(self):
            return as_key

    require_oauth = ResourceProtector()
    require_oauth.register_token_validator(
        MyBearerTokenValidator(issuer=ISSUER, resource_server=RESOURCE_SERVER)
    )
    require_oauth.register_token_validator(
        MyDPoPTokenValidator(
            issuer=ISSUER,
            resource_server=RESOURCE_SERVER,
            proof_validator=proof_validator,
        )
    )

    @app.route("/protected")
    @require_oauth()
    def protected():
        return jsonify(ok=True)

    return require_oauth


def make_proof(
    key,
    method="POST",
    htu=TOKEN_URL,
    jti=None,
    iat=None,
    ath=None,
    nonce=None,
    typ="dpop+jwt",
    alg="ES256",
    jwk="public",
    sign_key=None,
    extra_header=None,
):
    header = {"typ": typ, "alg": alg}
    if jwk == "public":
        header["jwk"] = key.as_dict(private=False)
    elif isinstance(jwk, dict):
        header["jwk"] = jwk
    if extra_header:
        header.update(extra_header)
    claims = {
        "jti": jti or generate_token(12),
        "htm": method,
        "htu": htu,
        "iat": int(time.time()) if iat is None else iat,
    }
    if ath is not None:
        claims["ath"] = ath
    if nonce is not None:
        claims["nonce"] = nonce
    return jwt.encode(header, claims, sign_key or key, algorithms=[alg])


def request_token(test_client, proof):
    headers = create_basic_header("client-id", "client-secret")
    headers["DPoP"] = proof
    return test_client.post(
        "/oauth/token",
        data={"grant_type": "client_credentials", "scope": "profile"},
        headers=headers,
    )


def get_token(test_client, key, **proof_kwargs):
    rv = request_token(test_client, make_proof(key, **proof_kwargs))
    assert rv.status_code == 200, rv.data
    return json.loads(rv.data)["access_token"]


def get_resource(test_client, token, key, scheme="DPoP", path="/protected", **kwargs):
    kwargs.setdefault("method", "GET")
    kwargs.setdefault("htu", RESOURCE_URL)
    if "ath" not in kwargs:
        kwargs["ath"] = compute_ath(token)
    proof = make_proof(key, **kwargs)
    headers = {"Authorization": f"{scheme} {token}", "DPoP": proof}
    return test_client.get(path, headers=headers)


# -- token endpoint -----------------------------------------------------


def test_token_response_is_dpop_bound(test_client, dpop_key, as_key):
    rv = request_token(test_client, make_proof(dpop_key))
    assert rv.status_code == 200
    resp = json.loads(rv.data)
    assert resp["token_type"] == "DPoP"

    decoded = jwt.decode(resp["access_token"], as_key)
    assert decoded.header["typ"] == "at+jwt"
    assert decoded.claims["iss"] == ISSUER
    assert decoded.claims["aud"] == RESOURCE_SERVER
    assert decoded.claims["cnf"]["jkt"] == dpop_key.thumbprint()


def test_token_endpoint_missing_proof(test_client):
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(
        "/oauth/token",
        data={"grant_type": "client_credentials"},
        headers=headers,
    )
    assert rv.status_code == 400
    assert json.loads(rv.data)["error"] == "invalid_dpop_proof"


def test_token_endpoint_multiple_proof_headers(test_client, dpop_key):
    headers = [
        (
            "Authorization",
            create_basic_header("client-id", "client-secret")["Authorization"],
        ),
        ("DPoP", make_proof(dpop_key)),
        ("DPoP", make_proof(dpop_key)),
    ]
    rv = test_client.post(
        "/oauth/token",
        data={"grant_type": "client_credentials"},
        headers=headers,
    )
    assert rv.status_code == 400
    assert json.loads(rv.data)["error"] == "invalid_dpop_proof"


def test_proof_wrong_typ(test_client, dpop_key):
    rv = request_token(test_client, make_proof(dpop_key, typ="JWT"))
    assert rv.status_code == 400
    assert json.loads(rv.data)["error"] == "invalid_dpop_proof"


def test_proof_symmetric_alg_rejected(test_client, dpop_key):
    proof = make_proof(
        dpop_key, alg="HS256", sign_key=OctKey.import_key("secret-key" * 4)
    )
    rv = request_token(test_client, proof)
    assert rv.status_code == 400
    assert json.loads(rv.data)["error"] == "invalid_dpop_proof"


def test_proof_disallowed_alg_rejected(test_client, dpop_key):
    p384_key = ECKey.generate_key("P-384")
    rv = request_token(test_client, make_proof(p384_key, alg="ES384"))
    assert rv.status_code == 400
    assert json.loads(rv.data)["error"] == "invalid_dpop_proof"


def test_proof_private_jwk_rejected(test_client, dpop_key):
    proof = make_proof(dpop_key, jwk=dpop_key.as_dict(private=True))
    rv = request_token(test_client, proof)
    assert rv.status_code == 400
    assert json.loads(rv.data)["error"] == "invalid_dpop_proof"


def test_proof_remote_key_url_not_trusted(test_client, dpop_key):
    # a proof carrying only a remote key reference is rejected, the
    # server never dereferences jku/x5u
    proof = make_proof(
        dpop_key, jwk=None, extra_header={"jku": "https://attacker.test/jwks.json"}
    )
    rv = request_token(test_client, proof)
    assert rv.status_code == 400
    assert json.loads(rv.data)["error"] == "invalid_dpop_proof"


def test_proof_wrong_method(test_client, dpop_key):
    rv = request_token(test_client, make_proof(dpop_key, method="GET"))
    assert rv.status_code == 400
    assert json.loads(rv.data)["error"] == "invalid_dpop_proof"


def test_proof_wrong_htu(test_client, dpop_key):
    rv = request_token(test_client, make_proof(dpop_key, htu="http://localhost/other"))
    assert rv.status_code == 400
    assert json.loads(rv.data)["error"] == "invalid_dpop_proof"


def test_proof_htu_ignores_query_and_fragment(test_client, dpop_key):
    proof = make_proof(dpop_key, htu=TOKEN_URL + "?code=abc#frag")
    rv = request_token(test_client, proof)
    assert rv.status_code == 200


def test_proof_stale_iat(test_client, dpop_key):
    now = int(time.time())
    rv = request_token(test_client, make_proof(dpop_key, iat=now - 1000))
    assert rv.status_code == 400
    assert json.loads(rv.data)["error"] == "invalid_dpop_proof"


def test_proof_future_iat(test_client, dpop_key):
    now = int(time.time())
    rv = request_token(test_client, make_proof(dpop_key, iat=now + 120))
    assert rv.status_code == 400
    assert json.loads(rv.data)["error"] == "invalid_dpop_proof"


def test_proof_iat_window_configurable(test_client, dpop_key, proof_validator):
    proof_validator.max_age = 2000
    now = int(time.time())
    rv = request_token(test_client, make_proof(dpop_key, iat=now - 1000))
    assert rv.status_code == 200


def test_proof_replay_rejected(test_client, dpop_key):
    proof = make_proof(dpop_key)
    rv = request_token(test_client, proof)
    assert rv.status_code == 200
    rv = request_token(test_client, proof)
    assert rv.status_code == 400
    assert json.loads(rv.data)["error"] == "invalid_dpop_proof"


def test_invalid_signature_does_not_burn_jti(test_client, dpop_key):
    jti = generate_token(12)
    proof = make_proof(dpop_key, jti=jti)
    tampered = proof[:-2] + ("AA" if not proof.endswith("AA") else "BB")
    rv = request_token(test_client, tampered)
    assert rv.status_code == 400

    # the same jti is still usable with a valid proof
    rv = request_token(test_client, make_proof(dpop_key, jti=jti))
    assert rv.status_code == 200


def test_nonce_required_when_configured(test_client, dpop_key, proof_validator):
    proof_validator.nonce_getter = lambda: "server-nonce"

    rv = request_token(test_client, make_proof(dpop_key))
    assert rv.status_code == 400
    assert json.loads(rv.data)["error"] == "use_dpop_nonce"
    assert rv.headers["DPoP-Nonce"] == "server-nonce"

    rv = request_token(test_client, make_proof(dpop_key, nonce="wrong"))
    assert rv.status_code == 400
    assert json.loads(rv.data)["error"] == "use_dpop_nonce"

    rv = request_token(test_client, make_proof(dpop_key, nonce="server-nonce"))
    assert rv.status_code == 200


# -- resource server ----------------------------------------------------


def test_resource_ok(test_client, dpop_key):
    token = get_token(test_client, dpop_key)
    rv = get_resource(test_client, token, dpop_key)
    assert rv.status_code == 200
    assert json.loads(rv.data)["ok"] is True


def test_resource_missing_proof_header(test_client, dpop_key):
    token = get_token(test_client, dpop_key)
    rv = test_client.get("/protected", headers={"Authorization": f"DPoP {token}"})
    assert rv.status_code == 401
    assert rv.headers["WWW-Authenticate"].startswith("DPoP")


def test_resource_proof_wrong_method(test_client, dpop_key):
    token = get_token(test_client, dpop_key)
    rv = get_resource(test_client, token, dpop_key, method="POST")
    assert rv.status_code == 401
    assert rv.headers["WWW-Authenticate"].startswith("DPoP")


def test_resource_proof_wrong_htu(test_client, dpop_key):
    token = get_token(test_client, dpop_key)
    rv = get_resource(test_client, token, dpop_key, htu="http://localhost/other")
    assert rv.status_code == 401


def test_resource_htu_ignores_query_string(test_client, dpop_key):
    token = get_token(test_client, dpop_key)
    # the request carries a query string, the proof htu does not
    rv = get_resource(test_client, token, dpop_key, path="/protected?foo=bar")
    assert rv.status_code == 200
    # and a proof htu with query/fragment is normalized the same way
    rv = get_resource(test_client, token, dpop_key, htu=RESOURCE_URL + "?foo=bar#frag")
    assert rv.status_code == 200


def test_resource_ath_mismatch_other_token(test_client, dpop_key):
    token_a = get_token(test_client, dpop_key)
    token_b = get_token(test_client, dpop_key)
    # proof bound to token_a, but token_b is presented
    rv = get_resource(test_client, token_b, dpop_key, ath=compute_ath(token_a))
    assert rv.status_code == 401


def test_resource_missing_ath(test_client, dpop_key):
    token = get_token(test_client, dpop_key)
    rv = get_resource(test_client, token, dpop_key, ath=None)
    assert rv.status_code == 401


def test_resource_proof_with_other_key(test_client, dpop_key, other_key):
    # token bound to dpop_key, proof signed by another key
    token = get_token(test_client, dpop_key)
    rv = get_resource(test_client, token, other_key)
    assert rv.status_code == 401


def test_resource_proof_replay_rejected(test_client, dpop_key):
    token = get_token(test_client, dpop_key)
    proof = make_proof(dpop_key, method="GET", htu=RESOURCE_URL, ath=compute_ath(token))
    headers = {"Authorization": f"DPoP {token}", "DPoP": proof}
    rv = test_client.get("/protected", headers=headers)
    assert rv.status_code == 200
    rv = test_client.get("/protected", headers=headers)
    assert rv.status_code == 401


def test_resource_nonce_error(test_client, dpop_key, proof_validator):
    proof_validator.nonce_getter = lambda: "server-nonce"
    token = get_token(test_client, dpop_key, nonce="server-nonce")
    rv = get_resource(test_client, token, dpop_key)
    assert rv.status_code == 401
    assert "use_dpop_nonce" in rv.headers["WWW-Authenticate"]
    assert rv.headers["DPoP-Nonce"] == "server-nonce"


# -- bearer coexistence -------------------------------------------------


def test_dpop_token_not_usable_as_bearer(test_client, dpop_key):
    token = get_token(test_client, dpop_key)
    rv = test_client.get("/protected", headers={"Authorization": f"Bearer {token}"})
    assert rv.status_code == 401
    assert rv.headers["WWW-Authenticate"].startswith("Bearer")


def test_plain_bearer_token_still_works(test_client, as_key):
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "aud": RESOURCE_SERVER,
        "sub": "client-id",
        "client_id": "client-id",
        "iat": now,
        "exp": now + 3600,
        "jti": generate_token(8),
        "scope": "profile",
    }
    token = jwt.encode(
        {"alg": "ES256", "typ": "at+jwt"}, claims, as_key, algorithms=["ES256"]
    )
    rv = test_client.get("/protected", headers={"Authorization": f"Bearer {token}"})
    assert rv.status_code == 200


# -- concurrency --------------------------------------------------------


def _hammer(app, token, proofs, results):
    barrier = threading.Barrier(len(proofs))

    def worker(proof):
        client = app.test_client()
        barrier.wait()
        rv = client.get(
            "/protected",
            headers={"Authorization": f"DPoP {token}", "DPoP": proof},
        )
        results.append(rv.status_code)

    threads = [threading.Thread(target=worker, args=(proof,)) for proof in proofs]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()


def test_concurrent_replay_same_jti(app, test_client, dpop_key):
    token = get_token(test_client, dpop_key)
    jti = generate_token(12)
    proofs = [
        make_proof(
            dpop_key,
            method="GET",
            htu=RESOURCE_URL,
            ath=compute_ath(token),
            jti=jti,
        )
        for _ in range(8)
    ]
    results = []
    _hammer(app, token, proofs, results)
    assert results.count(200) == 1
    assert results.count(401) == 7


def test_concurrent_different_proofs_same_nonce(
    app, test_client, dpop_key, proof_validator
):
    proof_validator.nonce_getter = lambda: "shared-nonce"
    token = get_token(test_client, dpop_key, nonce="shared-nonce")
    proofs = [
        make_proof(
            dpop_key,
            method="GET",
            htu=RESOURCE_URL,
            ath=compute_ath(token),
            nonce="shared-nonce",
        )
        for _ in range(8)
    ]
    results = []
    _hammer(app, token, proofs, results)
    assert results.count(200) == 8
