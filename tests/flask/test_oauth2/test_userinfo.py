import pytest
from flask import json
from joserfc import jwe
from joserfc import jws
from joserfc import jwt
from joserfc.errors import BadSignatureError
from joserfc.errors import DecodeError
from joserfc.errors import InvalidClaimError
from joserfc.jwk import KeySet
from joserfc.jwk import RSAKey
from joserfc.jwt import JWTClaimsRegistry

import authlib.oidc.core as oidc_core
from authlib.common.encoding import json_dumps
from authlib.common.encoding import json_loads
from authlib.common.encoding import to_unicode
from authlib.integrations.flask_oauth2 import ResourceProtector
from authlib.integrations.sqla_oauth2 import create_bearer_token_validator
from authlib.oidc.core import UserInfo
from authlib.oidc.core.errors import MissingSigningKeyError
from authlib.oidc.core.userinfo import filter_userinfo_claims
from tests.util import read_file_path

from .models import Client
from .models import Token

CLIENT_ENC_KEY = RSAKey.generate_key(2048, {"kid": "client-enc-key", "use": "enc"})
CLIENT_PUBLIC_JWKS = {"keys": [CLIENT_ENC_KEY.as_dict(is_private=False)]}

BASE_METADATA = {
    "scope": "profile",
    "redirect_uris": ["https://client.test/authorized"],
}
SIGNED_METADATA = dict(BASE_METADATA, userinfo_signed_response_alg="RS256")
NESTED_METADATA = dict(
    SIGNED_METADATA,
    userinfo_encrypted_response_alg="RSA-OAEP",
    userinfo_encrypted_response_enc="A256GCM",
    jwks=CLIENT_PUBLIC_JWKS,
)


@pytest.fixture(autouse=True)
def server(server, app, db):
    class UserInfoEndpoint(oidc_core.UserInfoEndpoint):
        def get_issuer(self) -> str:
            return "https://provider.test"

        def generate_user_info(self, user, scope):
            return user.generate_user_info().filter(scope)

        def resolve_private_key(self):
            return KeySet.import_key_set(read_file_path("jwks_private.json"))

    BearerTokenValidator = create_bearer_token_validator(db.session, Token)
    resource_protector = ResourceProtector()
    resource_protector.register_token_validator(BearerTokenValidator())
    server.register_endpoint(UserInfoEndpoint(resource_protector=resource_protector))

    @app.route("/oauth/userinfo", methods=["GET", "POST"])
    def userinfo():
        return server.create_endpoint_response("userinfo")

    return server


@pytest.fixture(autouse=True)
def client(client, db):
    client.set_client_metadata(
        {
            "scope": "profile",
            "redirect_uris": ["https://client.test/authorized"],
        }
    )
    db.session.add(client)
    db.session.commit()
    return client


@pytest.fixture(autouse=True)
def token(db):
    token = Token(
        user_id=1,
        client_id="client-id",
        token_type="bearer",
        access_token="access-token",
        refresh_token="r1",
        scope="openid",
        expires_in=3600,
    )
    db.session.add(token)
    db.session.commit()
    yield token
    db.session.delete(token)


def test_get(test_client, db, token):
    """The UserInfo Endpoint MUST support the use of the HTTP GET and HTTP POST methods defined in RFC 7231 [RFC7231].
    The UserInfo Endpoint MUST accept Access Tokens as OAuth 2.0 Bearer Token Usage [RFC6750]."""

    token.scope = "openid profile email address phone"
    db.session.add(token)
    db.session.commit()

    headers = {"Authorization": "Bearer access-token"}
    rv = test_client.get("/oauth/userinfo", headers=headers)
    assert rv.headers["Content-Type"] == "application/json"

    resp = json.loads(rv.data)
    assert resp == {
        "sub": "1",
        "address": {
            "country": "USA",
            "formatted": "742 Evergreen Terrace, Springfield",
            "locality": "Springfield",
            "postal_code": "1245",
            "region": "Unknown",
            "street_address": "742 Evergreen Terrace",
        },
        "birthdate": "2000-12-01",
        "email": "janedoe@example.com",
        "email_verified": True,
        "family_name": "Doe",
        "gender": "female",
        "given_name": "Jane",
        "locale": "fr-FR",
        "middle_name": "Middle",
        "name": "foo",
        "nickname": "Jany",
        "phone_number": "+1 (425) 555-1212",
        "phone_number_verified": False,
        "picture": "https://resource.test/janedoe/me.jpg",
        "preferred_username": "j.doe",
        "profile": "https://resource.test/janedoe",
        "updated_at": 1745315119,
        "website": "https://resource.test",
        "zoneinfo": "Europe/Paris",
    }


def test_post(test_client, db, token):
    """The UserInfo Endpoint MUST support the use of the HTTP GET and HTTP POST methods defined in RFC 7231 [RFC7231].
    The UserInfo Endpoint MUST accept Access Tokens as OAuth 2.0 Bearer Token Usage [RFC6750]."""

    token.scope = "openid profile email address phone"
    db.session.add(token)
    db.session.commit()

    headers = {"Authorization": "Bearer access-token"}
    rv = test_client.post("/oauth/userinfo", headers=headers)
    assert rv.headers["Content-Type"] == "application/json"

    resp = json.loads(rv.data)
    assert resp == {
        "sub": "1",
        "address": {
            "country": "USA",
            "formatted": "742 Evergreen Terrace, Springfield",
            "locality": "Springfield",
            "postal_code": "1245",
            "region": "Unknown",
            "street_address": "742 Evergreen Terrace",
        },
        "birthdate": "2000-12-01",
        "email": "janedoe@example.com",
        "email_verified": True,
        "family_name": "Doe",
        "gender": "female",
        "given_name": "Jane",
        "locale": "fr-FR",
        "middle_name": "Middle",
        "name": "foo",
        "nickname": "Jany",
        "phone_number": "+1 (425) 555-1212",
        "phone_number_verified": False,
        "picture": "https://resource.test/janedoe/me.jpg",
        "preferred_username": "j.doe",
        "profile": "https://resource.test/janedoe",
        "updated_at": 1745315119,
        "website": "https://resource.test",
        "zoneinfo": "Europe/Paris",
    }


def test_no_token(test_client):
    rv = test_client.post("/oauth/userinfo")
    resp = json.loads(rv.data)
    assert resp["error"] == "missing_authorization"


def test_bad_token(test_client):
    headers = {"Authorization": "invalid token_string"}
    rv = test_client.post("/oauth/userinfo", headers=headers)
    resp = json.loads(rv.data)
    assert resp["error"] == "unsupported_token_type"


def test_token_has_bad_scope(test_client, db, token):
    """Test that tokens without 'openid' scope cannot access the userinfo endpoint."""

    token.scope = "foobar"
    db.session.add(token)
    db.session.commit()

    headers = {"Authorization": "Bearer access-token"}
    rv = test_client.post("/oauth/userinfo", headers=headers)
    resp = json.loads(rv.data)
    assert resp["error"] == "insufficient_scope"


def test_scope_minimum(test_client):
    headers = {"Authorization": "Bearer access-token"}
    rv = test_client.get("/oauth/userinfo", headers=headers)
    resp = json.loads(rv.data)
    assert resp == {
        "sub": "1",
    }


def test_scope_profile(test_client, db, token):
    token.scope = "openid profile"
    db.session.add(token)
    db.session.commit()

    headers = {"Authorization": "Bearer access-token"}
    rv = test_client.get("/oauth/userinfo", headers=headers)
    resp = json.loads(rv.data)
    assert resp == {
        "sub": "1",
        "birthdate": "2000-12-01",
        "family_name": "Doe",
        "gender": "female",
        "given_name": "Jane",
        "locale": "fr-FR",
        "middle_name": "Middle",
        "name": "foo",
        "nickname": "Jany",
        "picture": "https://resource.test/janedoe/me.jpg",
        "preferred_username": "j.doe",
        "profile": "https://resource.test/janedoe",
        "updated_at": 1745315119,
        "website": "https://resource.test",
        "zoneinfo": "Europe/Paris",
    }


def test_scope_address(test_client, db, token):
    token.scope = "openid address"
    db.session.add(token)
    db.session.commit()

    headers = {"Authorization": "Bearer access-token"}
    rv = test_client.get("/oauth/userinfo", headers=headers)
    resp = json.loads(rv.data)
    assert resp == {
        "sub": "1",
        "address": {
            "country": "USA",
            "formatted": "742 Evergreen Terrace, Springfield",
            "locality": "Springfield",
            "postal_code": "1245",
            "region": "Unknown",
            "street_address": "742 Evergreen Terrace",
        },
    }


def test_scope_email(test_client, db, token):
    token.scope = "openid email"
    db.session.add(token)
    db.session.commit()

    headers = {"Authorization": "Bearer access-token"}
    rv = test_client.get("/oauth/userinfo", headers=headers)
    resp = json.loads(rv.data)
    assert resp == {
        "sub": "1",
        "email": "janedoe@example.com",
        "email_verified": True,
    }


def test_scope_phone(test_client, db, token):
    token.scope = "openid phone"
    db.session.add(token)
    db.session.commit()

    headers = {"Authorization": "Bearer access-token"}
    rv = test_client.get("/oauth/userinfo", headers=headers)
    resp = json.loads(rv.data)
    assert resp == {
        "sub": "1",
        "phone_number": "+1 (425) 555-1212",
        "phone_number_verified": False,
    }


@pytest.mark.skip
def test_scope_signed_unsecured(test_client, db, token, client):
    """When userinfo_signed_response_alg is set as client metadata, the userinfo response must be a JWT."""
    client.set_client_metadata(
        {
            "scope": "profile",
            "redirect_uris": ["https://client.test/authorized"],
            "userinfo_signed_response_alg": "none",
        }
    )
    db.session.add(client)
    db.session.commit()

    token.scope = "openid email"
    db.session.add(token)
    db.session.commit()

    headers = {"Authorization": "Bearer access-token"}
    rv = test_client.get("/oauth/userinfo", headers=headers)
    assert rv.headers["Content-Type"] == "application/jwt"

    # specify that we support "none"
    token = jwt.decode(rv.data, None, algorithms=["none"])
    assert token.claims == {
        "sub": "1",
        "iss": "https://provider.test",
        "aud": "client-id",
        "email": "janedoe@example.com",
        "email_verified": True,
    }


def test_scope_signed_secured(test_client, client, token, db):
    """When userinfo_signed_response_alg is set as client metadata and not none, the userinfo response must be signed."""
    client.set_client_metadata(
        {
            "scope": "profile",
            "redirect_uris": ["https://client.test/authorized"],
            "userinfo_signed_response_alg": "RS256",
        }
    )
    db.session.add(client)
    db.session.commit()

    token.scope = "openid email"
    db.session.add(token)
    db.session.commit()

    headers = {"Authorization": "Bearer access-token"}
    rv = test_client.get("/oauth/userinfo", headers=headers)
    assert rv.headers["Content-Type"] == "application/jwt"

    pub_key = KeySet.import_key_set(read_file_path("jwks_public.json"))
    token = jwt.decode(rv.data, pub_key)
    assert token.header["alg"] == "RS256"
    assert token.header["kid"] == "bilbo.baggins@hobbiton.example"
    assert token.claims["sub"] == "1"
    assert token.claims["iss"] == "https://provider.test"
    assert token.claims["aud"] == "client-id"
    assert token.claims["email"] == "janedoe@example.com"
    assert token.claims["email_verified"] is True
    assert token.claims["exp"] - token.claims["iat"] == 3600


def add_client_with_token(db, client_id, metadata, scope="openid email"):
    client = Client(user_id=1, client_id=client_id, client_secret="secret")
    client.set_client_metadata(metadata)
    db.session.add(client)
    token = Token(
        user_id=1,
        client_id=client_id,
        token_type="bearer",
        access_token=f"access-{client_id}",
        refresh_token=f"refresh-{client_id}",
        scope=scope,
        expires_in=3600,
    )
    db.session.add(token)
    db.session.commit()
    return client


def get_userinfo(test_client, client_id, **kwargs):
    headers = {"Authorization": f"Bearer access-{client_id}"}
    return test_client.get("/oauth/userinfo", headers=headers, **kwargs)


def decrypt_nested_response(data, pub_key):
    """Verify the outer JWS then decrypt the inner JWE."""
    obj = jws.deserialize_compact(data, pub_key)
    assert obj.protected["cty"] == "JWE"
    assert obj.protected["kid"] == "bilbo.baggins@hobbiton.example"
    decrypted = jwe.decrypt_compact(obj.payload, CLIENT_ENC_KEY)
    assert decrypted.protected["cty"] == "JWT"
    assert decrypted.protected["kid"] == "client-enc-key"
    return json_loads(decrypted.plaintext)


def test_response_modes_round_trip(test_client, db):
    """Round trip with two JWK sets, a local userinfo generator and
    three client metadata profiles: plain JSON, signed JWS and nested
    encrypted+signed JWT."""
    pub_key = KeySet.import_key_set(read_file_path("jwks_public.json"))

    # 1. client without JWT response metadata gets plain JSON
    add_client_with_token(db, "client-json", dict(BASE_METADATA))
    rv = get_userinfo(test_client, "client-json")
    assert rv.headers["Content-Type"] == "application/json"
    assert json.loads(rv.data) == {
        "sub": "1",
        "email": "janedoe@example.com",
        "email_verified": True,
    }

    # 2. client with userinfo_signed_response_alg gets a signed JWS
    add_client_with_token(db, "client-sign", dict(SIGNED_METADATA))
    rv = get_userinfo(test_client, "client-sign")
    assert rv.headers["Content-Type"] == "application/jwt"
    decoded = jwt.decode(rv.data, pub_key)
    assert decoded.claims["iss"] == "https://provider.test"
    assert decoded.claims["aud"] == "client-sign"
    assert decoded.claims["sub"] == "1"
    assert decoded.claims["email"] == "janedoe@example.com"
    assert decoded.claims["exp"] - decoded.claims["iat"] == 3600

    # 3. client with encryption metadata gets a nested JWT: the claims
    # are encrypted with the client public key, then signed by the server
    add_client_with_token(db, "client-nested", dict(NESTED_METADATA))
    rv = get_userinfo(test_client, "client-nested")
    assert rv.headers["Content-Type"] == "application/jwt"
    claims = decrypt_nested_response(rv.data, pub_key)
    assert claims["iss"] == "https://provider.test"
    assert claims["aud"] == "client-nested"
    assert claims["sub"] == "1"
    assert claims["email"] == "janedoe@example.com"
    assert claims["exp"] - claims["iat"] == 3600

    # the decrypted claims still conform to the UserInfo structure
    allowed = set(UserInfo.REGISTERED_CLAIMS) | {"iss", "aud", "iat", "exp"}
    assert set(claims) <= allowed
    user_info = filter_userinfo_claims(claims)
    assert user_info["sub"] == "1"


def test_nested_tampered_ciphertext(test_client, db):
    """Tampering with the JWE ciphertext makes decryption fail."""
    pub_key = KeySet.import_key_set(read_file_path("jwks_public.json"))
    add_client_with_token(db, "client-nested", dict(NESTED_METADATA))
    rv = get_userinfo(test_client, "client-nested")

    obj = jws.deserialize_compact(rv.data, pub_key)
    parts = to_unicode(obj.payload).split(".")
    ciphertext = parts[3]
    parts[3] = ciphertext[:-2] + ("AA" if ciphertext[-2:] != "AA" else "BB")
    with pytest.raises(DecodeError):
        jwe.decrypt_compact(".".join(parts), CLIENT_ENC_KEY)


def test_nested_tampered_signature(test_client, db):
    """Tampering with the outer JWS makes verification fail."""
    pub_key = KeySet.import_key_set(read_file_path("jwks_public.json"))
    add_client_with_token(db, "client-nested", dict(NESTED_METADATA))
    rv = get_userinfo(test_client, "client-nested")

    data = to_unicode(rv.data)
    tampered = data[:-2] + ("AA" if data[-2:] != "AA" else "BB")
    with pytest.raises(BadSignatureError):
        jws.deserialize_compact(tampered, pub_key)


def test_wrong_audience(test_client, db):
    """A signed userinfo response is only valid for its audience."""
    pub_key = KeySet.import_key_set(read_file_path("jwks_public.json"))
    add_client_with_token(db, "client-sign", dict(SIGNED_METADATA))
    rv = get_userinfo(test_client, "client-sign")
    decoded = jwt.decode(rv.data, pub_key)

    registry = JWTClaimsRegistry(
        iss={"value": "https://provider.test"}, aud={"value": "another-client"}
    )
    with pytest.raises(InvalidClaimError):
        registry.validate(decoded.claims)

    registry = JWTClaimsRegistry(
        iss={"value": "https://provider.test"},
        aud={"value": "client-sign"},
    )
    registry.validate(decoded.claims)


def test_request_parameters_cannot_override_metadata(test_client, db):
    """Request parameters never override the registered response mode."""
    add_client_with_token(db, "client-json", dict(BASE_METADATA))
    rv = test_client.post(
        "/oauth/userinfo",
        headers={"Authorization": "Bearer access-client-json"},
        data={
            "userinfo_signed_response_alg": "RS256",
            "userinfo_encrypted_response_alg": "RSA-OAEP",
        },
    )
    assert rv.headers["Content-Type"] == "application/json"
    assert json.loads(rv.data)["sub"] == "1"


def test_unsupported_signed_response_alg(test_client, db):
    metadata = dict(BASE_METADATA, userinfo_signed_response_alg="ES512")
    add_client_with_token(db, "client-bad-alg", metadata)
    rv = get_userinfo(test_client, "client-bad-alg")
    assert rv.status_code == 400
    assert json.loads(rv.data)["error"] == "unsupported_userinfo_response_alg"


def test_unsupported_encrypted_response_alg(test_client, db):
    metadata = dict(SIGNED_METADATA, userinfo_encrypted_response_alg="RSA1_5")
    add_client_with_token(db, "client-bad-enc", metadata)
    rv = get_userinfo(test_client, "client-bad-enc")
    assert rv.status_code == 400
    assert json.loads(rv.data)["error"] == "unsupported_userinfo_response_alg"


def test_unsupported_encrypted_response_enc(test_client, db):
    metadata = dict(
        SIGNED_METADATA,
        userinfo_encrypted_response_alg="RSA-OAEP",
        userinfo_encrypted_response_enc="XC20P",
        jwks=CLIENT_PUBLIC_JWKS,
    )
    add_client_with_token(db, "client-bad-enc", metadata)
    rv = get_userinfo(test_client, "client-bad-enc")
    assert rv.status_code == 400
    assert json.loads(rv.data)["error"] == "unsupported_userinfo_response_alg"


def test_missing_client_public_key(test_client, db):
    """Encrypted userinfo requires a registered client public key."""
    metadata = dict(SIGNED_METADATA, userinfo_encrypted_response_alg="RSA-OAEP")
    add_client_with_token(db, "client-no-key", metadata)
    rv = get_userinfo(test_client, "client-no-key")
    assert rv.status_code == 400
    assert json.loads(rv.data)["error"] == "missing_client_public_key"


def test_no_encryption_key_in_jwks(test_client, db):
    """A JWKS without encryption keys is not usable for encrypted userinfo."""
    sig_only_key = RSAKey.generate_key(2048, {"kid": "sig-key", "use": "sig"})
    metadata = dict(
        SIGNED_METADATA,
        userinfo_encrypted_response_alg="RSA-OAEP",
        jwks={"keys": [sig_only_key.as_dict(is_private=False)]},
    )
    add_client_with_token(db, "client-sig-jwks", metadata)
    rv = get_userinfo(test_client, "client-sig-jwks")
    assert rv.status_code == 400
    assert json.loads(rv.data)["error"] == "missing_client_public_key"


def test_issuer_mismatch(test_client, db):
    """A client registered for another issuer is rejected."""
    metadata = dict(BASE_METADATA, issuer="https://another-provider.test")
    add_client_with_token(db, "client-other-issuer", metadata)
    rv = get_userinfo(test_client, "client-other-issuer")
    assert rv.status_code == 400
    assert json.loads(rv.data)["error"] == "issuer_mismatch"


def test_issuer_match(test_client, db):
    metadata = dict(BASE_METADATA, issuer="https://provider.test")
    add_client_with_token(db, "client-same-issuer", metadata)
    rv = get_userinfo(test_client, "client-same-issuer")
    assert rv.status_code == 200
    assert json.loads(rv.data)["sub"] == "1"


def test_missing_signing_key():
    class NoKeyUserInfoEndpoint(oidc_core.UserInfoEndpoint):
        def resolve_private_key(self):
            return None

    endpoint = NoKeyUserInfoEndpoint()
    with pytest.raises(MissingSigningKeyError):
        endpoint.resolve_signing_key("RS256")


def test_filter_userinfo_claims_is_stable():
    """The JSON serialization does not depend on the claims ordering."""
    first = UserInfo({"sub": "1", "email": "jane@example.com", "name": "Jane"})
    second = UserInfo({"name": "Jane", "sub": "1", "email": "jane@example.com"})
    assert json_dumps(filter_userinfo_claims(first)) == json_dumps(
        filter_userinfo_claims(second)
    )

    # non standard claims are filtered out
    filtered = filter_userinfo_claims(UserInfo({"sub": "1", "custom": "x"}))
    assert "custom" not in filtered
    assert filtered["sub"] == "1"


def test_signed_response_is_deterministic(test_client, db, monkeypatch):
    """Two equivalent userinfo objects produce the same JWS, regardless
    of the JSON serialization order."""
    monkeypatch.setattr("time.time", lambda: 1750000000)
    add_client_with_token(db, "client-sign", dict(SIGNED_METADATA))
    first = get_userinfo(test_client, "client-sign")
    second = get_userinfo(test_client, "client-sign")
    assert first.data == second.data
