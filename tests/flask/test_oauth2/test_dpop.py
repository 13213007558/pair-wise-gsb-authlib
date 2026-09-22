import base64
import json
import secrets
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
from flask import jsonify
from joserfc import jwt
from joserfc.jwk import ECKey

from authlib.common.encoding import to_bytes
from authlib.common.encoding import to_unicode
from authlib.common.encoding import urlsafe_b64encode
from authlib.integrations.flask_oauth2 import AuthorizationServer
from authlib.integrations.flask_oauth2 import ResourceProtector
from authlib.oauth2.rfc6749.models import ClientMixin
from authlib.oauth2.rfc6750 import BearerTokenValidator
from authlib.oauth2.rfc9449 import DPoPClientCredentialsGrant
from authlib.oauth2.rfc9449 import DPoPNonceProvider
from authlib.oauth2.rfc9449 import DPoPProofValidator
from authlib.oauth2.rfc9449 import DPoPTokenGenerator
from authlib.oauth2.rfc9449 import DPoPTokenValidator
from authlib.oauth2.rfc9449 import compute_ath

ISSUER = "https://as.test"
TOKEN_URL = "http://localhost/oauth/token"
RESOURCE_URL = "http://localhost/resource"


class Client(ClientMixin):
    client_id = "client-id"
    client_secret = "client-secret"

    def get_client_id(self):
        return self.client_id

    def get_default_redirect_uri(self):
        return None

    def get_allowed_scope(self, scope):
        return scope if scope is not None else "profile"

    def check_redirect_uri(self, redirect_uri):
        return False

    def check_client_secret(self, client_secret):
        return client_secret == self.client_secret

    def check_endpoint_auth_method(self, method, endpoint):
        return method == "client_secret_basic"

    def check_response_type(self, response_type):
        return False

    def check_grant_type(self, grant_type):
        return grant_type == "client_credentials"


CLIENT = Client()


def basic_auth():
    raw = base64.b64encode(b"client-id:client-secret").decode()
    return {"Authorization": f"Basic {raw}"}


def make_proof(
    key,
    method="POST",
    url=TOKEN_URL,
    jti=None,
    iat=None,
    ath=None,
    nonce=None,
    typ="dpop+jwt",
    alg="ES256",
    jwk=None,
    extra_header=None,
    sign_key=None,
):
    claims = {
        "jti": jti if jti is not None else secrets.token_urlsafe(12),
        "htm": method,
        "htu": url,
        "iat": int(time.time()) if iat is None else iat,
    }
    if ath is not None:
        claims["ath"] = ath
    if nonce is not None:
        claims["nonce"] = nonce
    header = {
        "typ": typ,
        "alg": alg,
        "jwk": jwk if jwk is not None else key.as_dict(private=False),
    }
    if extra_header:
        header.update(extra_header)
    return jwt.encode(header, claims, sign_key or key)


def craft_token(header, claims):
    """Hand-crafted compact JWS (no valid signature)."""
    header_part = to_unicode(urlsafe_b64encode(to_bytes(json.dumps(header))))
    claims_part = to_unicode(urlsafe_b64encode(to_bytes(json.dumps(claims))))
    return f"{header_part}.{claims_part}.invalid-signature"


@pytest.fixture
def as_key():
    return ECKey.generate_key("P-256")


@pytest.fixture
def client_key():
    return ECKey.generate_key("P-256")


@pytest.fixture
def other_key():
    return ECKey.generate_key("P-256")


@pytest.fixture
def proof_validator():
    return DPoPProofValidator()


@pytest.fixture
def server(app, as_key, proof_validator):
    saved_tokens = []

    def query_client(client_id):
        if client_id == CLIENT.client_id:
            return CLIENT
        return None

    def save_token(token, request):
        saved_tokens.append(token)

    server = AuthorizationServer(app, query_client, save_token)
    server.register_grant(DPoPClientCredentialsGrant)

    class TokenGenerator(DPoPTokenGenerator):
        def get_jwks(self):
            return as_key

    server.register_token_generator("default", TokenGenerator(issuer=ISSUER))
    server.dpop_proof_validator = proof_validator
    server.saved_tokens = saved_tokens

    @app.route("/oauth/token", methods=["POST"])
    def issue_token():
        return server.create_token_response()

    return server


@pytest.fixture
def require_oauth(app, as_key, proof_validator):
    protector = ResourceProtector()

    class TokenValidator(DPoPTokenValidator):
        def get_jwks(self):
            return as_key

    protector.register_token_validator(
        TokenValidator(issuer=ISSUER, proof_validator=proof_validator)
    )

    @app.route("/resource", methods=["GET", "POST"])
    @protector(None)
    def resource():
        return jsonify({"status": "ok"})

    return protector


@pytest.fixture
def bearer_token(require_oauth):
    """Register a static bearer token validator so the classic Bearer
    path keeps working next to DPoP."""

    class Token:
        def is_expired(self):
            return False

        def is_revoked(self):
            return False

        def get_scope(self):
            return "profile"

    class StaticBearerValidator(BearerTokenValidator):
        def authenticate_token(self, token_string):
            if token_string == "valid-bearer-token":
                return Token()
            return None

    require_oauth.register_token_validator(StaticBearerValidator())
    return "valid-bearer-token"


def request_token(test_client, key, proof=None, path="/oauth/token", **proof_kwargs):
    if proof is None:
        proof = make_proof(key, **proof_kwargs)
    headers = dict(basic_auth())
    if proof is not None:
        headers["DPoP"] = proof
    return test_client.post(
        path,
        data={"grant_type": "client_credentials", "scope": "profile"},
        headers=headers,
    )


def get_access_token(test_client, key, **proof_kwargs):
    rv = request_token(test_client, key, **proof_kwargs)
    assert rv.status_code == 200, rv.get_json()
    data = rv.get_json()
    assert data["token_type"] == "DPoP"
    return data["access_token"]


def request_resource(
    test_client,
    token,
    key,
    method="GET",
    url=None,
    proof=None,
    scheme="DPoP",
    path="/resource",
    query="",
    **proof_kwargs,
):
    if url is None:
        url = f"http://localhost{path}{query}"
    if proof is None:
        proof_kwargs.setdefault("ath", compute_ath(token))
        proof = make_proof(
            key,
            method=method,
            url=url,
            **proof_kwargs,
        )
    headers = {"Authorization": f"{scheme} {token}"}
    if proof is not None:
        headers["DPoP"] = proof
    return test_client.open(path + query, method=method, headers=headers)


def decode_token(token, as_key):
    return jwt.decode(token, as_key).claims


# --- token endpoint -------------------------------------------------


def test_token_endpoint_issues_dpop_bound_token(
    test_client, server, as_key, client_key
):
    rv = request_token(test_client, client_key)
    assert rv.status_code == 200
    data = rv.get_json()
    assert data["token_type"] == "DPoP"
    claims = decode_token(data["access_token"], as_key)
    assert claims["iss"] == ISSUER
    assert claims["cnf"] == {"jkt": client_key.thumbprint()}


def test_token_endpoint_missing_proof(test_client, server):
    rv = test_client.post(
        "/oauth/token",
        data={"grant_type": "client_credentials", "scope": "profile"},
        headers=basic_auth(),
    )
    assert rv.status_code == 400
    assert rv.get_json()["error"] == "invalid_dpop_proof"


def test_proof_wrong_typ(test_client, server, client_key):
    rv = request_token(test_client, client_key, typ="JWT")
    assert rv.status_code == 400
    assert rv.get_json()["error"] == "invalid_dpop_proof"


def test_proof_alg_none(test_client, server, client_key):
    proof = craft_token(
        {
            "typ": "dpop+jwt",
            "alg": "none",
            "jwk": client_key.as_dict(private=False),
        },
        {
            "jti": secrets.token_urlsafe(12),
            "htm": "POST",
            "htu": TOKEN_URL,
            "iat": int(time.time()),
        },
    )
    rv = request_token(test_client, client_key, proof=proof)
    assert rv.status_code == 400
    assert rv.get_json()["error"] == "invalid_dpop_proof"


def test_proof_alg_not_allowed(test_client, server, client_key):
    proof = craft_token(
        {
            "typ": "dpop+jwt",
            "alg": "HS256",
            "jwk": client_key.as_dict(private=False),
        },
        {
            "jti": secrets.token_urlsafe(12),
            "htm": "POST",
            "htu": TOKEN_URL,
            "iat": int(time.time()),
        },
    )
    rv = request_token(test_client, client_key, proof=proof)
    assert rv.status_code == 400
    assert rv.get_json()["error"] == "invalid_dpop_proof"


def test_proof_jku_header_not_trusted(test_client, server, client_key):
    rv = request_token(
        test_client,
        client_key,
        extra_header={"jku": "https://attacker.test/jwks.json"},
    )
    assert rv.status_code == 400
    assert rv.get_json()["error"] == "invalid_dpop_proof"


def test_proof_x5u_header_not_trusted(test_client, server, client_key):
    rv = request_token(
        test_client,
        client_key,
        extra_header={"x5u": "https://attacker.test/cert.pem"},
    )
    assert rv.status_code == 400
    assert rv.get_json()["error"] == "invalid_dpop_proof"


def test_proof_private_jwk_rejected(test_client, server, client_key):
    rv = request_token(test_client, client_key, jwk=client_key.as_dict(private=True))
    assert rv.status_code == 400
    assert rv.get_json()["error"] == "invalid_dpop_proof"


def test_proof_htm_mismatch(test_client, server, client_key):
    rv = request_token(test_client, client_key, method="GET")
    assert rv.status_code == 400
    assert rv.get_json()["error"] == "invalid_dpop_proof"


def test_proof_htm_case_sensitive(test_client, server, client_key):
    rv = request_token(test_client, client_key, method="post")
    assert rv.status_code == 400
    assert rv.get_json()["error"] == "invalid_dpop_proof"


def test_proof_htu_mismatch(test_client, server, client_key):
    rv = request_token(test_client, client_key, url="http://localhost/other-endpoint")
    assert rv.status_code == 400
    assert rv.get_json()["error"] == "invalid_dpop_proof"


def test_proof_htu_ignores_query_and_fragment(test_client, server, client_key):
    rv = request_token(test_client, client_key, url=f"{TOKEN_URL}?foo=bar#section")
    assert rv.status_code == 200


def test_request_query_ignored_in_htu(test_client, server, client_key):
    rv = request_token(
        test_client, client_key, path="/oauth/token?foo=bar", url=TOKEN_URL
    )
    assert rv.status_code == 200


def test_proof_iat_too_old(test_client, server, client_key):
    rv = request_token(test_client, client_key, iat=int(time.time()) - 400)
    assert rv.status_code == 400
    assert rv.get_json()["error"] == "invalid_dpop_proof"


def test_proof_iat_in_future(test_client, server, client_key):
    rv = request_token(test_client, client_key, iat=int(time.time()) + 120)
    assert rv.status_code == 400
    assert rv.get_json()["error"] == "invalid_dpop_proof"


def test_proof_missing_jti(test_client, server, client_key):
    proof = jwt.encode(
        {
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": client_key.as_dict(private=False),
        },
        {"htm": "POST", "htu": TOKEN_URL, "iat": int(time.time())},
        client_key,
    )
    rv = request_token(test_client, client_key, proof=proof)
    assert rv.status_code == 400
    assert rv.get_json()["error"] == "invalid_dpop_proof"


def test_proof_replay_rejected(test_client, server, client_key):
    proof = make_proof(client_key)
    rv = request_token(test_client, client_key, proof=proof)
    assert rv.status_code == 200
    rv = request_token(test_client, client_key, proof=proof)
    assert rv.status_code == 400
    assert rv.get_json()["error"] == "invalid_dpop_proof"


def test_invalid_signature_does_not_burn_jti(
    test_client, server, client_key, other_key
):
    jti = "shared-jti-value"
    # proof carries the public key of client_key but is signed by other_key:
    # the signature is invalid and the jti must not be recorded
    bad_proof = make_proof(client_key, jti=jti, sign_key=other_key)
    rv = request_token(test_client, client_key, proof=bad_proof)
    assert rv.status_code == 400
    # the legitimate proof with the same jti is still accepted
    good_proof = make_proof(client_key, jti=jti)
    rv = request_token(test_client, client_key, proof=good_proof)
    assert rv.status_code == 200


# --- resource endpoint ----------------------------------------------


def test_resource_ok(test_client, server, require_oauth, client_key):
    token = get_access_token(test_client, client_key)
    rv = request_resource(test_client, token, client_key)
    assert rv.status_code == 200
    assert rv.get_json() == {"status": "ok"}


def test_resource_post_method_ok(test_client, server, require_oauth, client_key):
    token = get_access_token(test_client, client_key)
    rv = request_resource(test_client, token, client_key, method="POST")
    assert rv.status_code == 200


def test_resource_missing_proof(test_client, server, require_oauth, client_key):
    token = get_access_token(test_client, client_key)
    rv = test_client.get("/resource", headers={"Authorization": f"DPoP {token}"})
    assert rv.status_code == 401
    assert rv.headers["WWW-Authenticate"].startswith("DPoP")


def test_resource_htm_mismatch(test_client, server, require_oauth, client_key):
    token = get_access_token(test_client, client_key)
    # proof says POST but the request is a GET
    rv = request_resource(
        test_client,
        token,
        client_key,
        method="GET",
        proof=make_proof(
            client_key,
            method="POST",
            url=RESOURCE_URL,
            ath=compute_ath(token),
        ),
    )
    assert rv.status_code == 401


def test_resource_htu_mismatch(test_client, server, require_oauth, client_key):
    token = get_access_token(test_client, client_key)
    rv = request_resource(
        test_client,
        token,
        client_key,
        url="http://localhost/other-resource",
    )
    assert rv.status_code == 401


def test_resource_ath_mismatch(test_client, server, require_oauth, client_key):
    token = get_access_token(test_client, client_key)
    rv = request_resource(
        test_client,
        token,
        client_key,
        ath=compute_ath("a-different-access-token"),
    )
    assert rv.status_code == 401


def test_resource_proof_from_another_key(
    test_client, server, require_oauth, client_key, other_key
):
    # token is bound to client_key, but the proof is signed by other_key:
    # a valid proof from another key must not be accepted
    token = get_access_token(test_client, client_key)
    rv = request_resource(test_client, token, other_key)
    assert rv.status_code == 401


def test_resource_proof_replay_rejected(test_client, server, require_oauth, client_key):
    token = get_access_token(test_client, client_key)
    proof = make_proof(
        client_key,
        method="GET",
        url=RESOURCE_URL,
        ath=compute_ath(token),
    )
    rv = request_resource(test_client, token, client_key, proof=proof)
    assert rv.status_code == 200
    rv = request_resource(test_client, token, client_key, proof=proof)
    assert rv.status_code == 401


def test_dpop_token_cannot_be_used_as_bearer(
    test_client, server, bearer_token, client_key
):
    token = get_access_token(test_client, client_key)
    rv = test_client.get("/resource", headers={"Authorization": f"Bearer {token}"})
    assert rv.status_code == 401


def test_bearer_path_still_works(test_client, server, bearer_token):
    rv = test_client.get(
        "/resource", headers={"Authorization": f"Bearer {bearer_token}"}
    )
    assert rv.status_code == 200


# --- server nonce ---------------------------------------------------


def test_nonce_required_at_token_endpoint(
    test_client, server, proof_validator, client_key
):
    provider = DPoPNonceProvider()
    proof_validator.nonce_provider = provider

    rv = request_token(test_client, client_key)
    assert rv.status_code == 400
    assert rv.get_json()["error"] == "use_dpop_nonce"
    nonce = rv.headers["DPoP-Nonce"]

    rv = request_token(test_client, client_key, nonce=nonce)
    assert rv.status_code == 200


def test_nonce_required_at_resource(
    test_client, server, require_oauth, proof_validator, client_key
):
    provider = DPoPNonceProvider()
    proof_validator.nonce_provider = provider

    token = get_access_token(test_client, client_key, nonce=provider.generate_nonce())
    rv = request_resource(test_client, token, client_key)
    assert rv.status_code == 401
    assert "use_dpop_nonce" in rv.headers["WWW-Authenticate"]
    nonce = rv.headers["DPoP-Nonce"]

    rv = request_resource(test_client, token, client_key, nonce=nonce)
    assert rv.status_code == 200


# --- concurrency ------------------------------------------------------


def test_concurrent_replay_same_proof(app, server, client_key):
    proof = make_proof(client_key)

    def call(_):
        client = app.test_client()
        return request_token(client, client_key, proof=proof).status_code

    with ThreadPoolExecutor(max_workers=8) as executor:
        codes = list(executor.map(call, range(8)))

    assert codes.count(200) == 1
    assert codes.count(400) == 7


def test_concurrent_proofs_with_same_nonce(app, server, proof_validator, client_key):
    provider = DPoPNonceProvider()
    proof_validator.nonce_provider = provider
    nonce = provider.generate_nonce()
    proofs = [make_proof(client_key, nonce=nonce) for _ in range(8)]

    def call(proof):
        client = app.test_client()
        return request_token(client, client_key, proof=proof).status_code

    with ThreadPoolExecutor(max_workers=8) as executor:
        codes = list(executor.map(call, proofs))

    # the same nonce serves concurrent distinct proofs; replay protection
    # is based on jti, and each proof here has a unique one
    assert all(code == 200 for code in codes)
