"""Security regression for the parameter source of signed request objects.

RFC 9101 section 5.1 says the claims of a verified request object become the
authorization request parameters: once the request object is trusted, a
parameter sent in the outer URL or form cannot change the client, the
redirect URI, the scope, the state or the response type that the grant, the
consent flow and the authorization code finally use.

The tests drive the real Flask authorization endpoint. The signing keys come
from the local fixtures of ``tests/files`` and the ``request_uri`` resolver is
a local function returning a fixed object: no network is used.

The errors follow the distinctions of RFC 9101 section 4.4 and 5.4 and the
compatibility policy of this repository:

* ``invalid_client``: the outer ``client_id`` is missing or unknown, before
  the request object can be selected and verified.
* ``invalid_request``: a structurally valid request object conflicts with the
  outer request (different ``client_id``), an algorithm is disabled, or a
  request object is required and omitted.
* ``invalid_request_object``: the JWT cannot be decoded, its signature is
  invalid, an essential claim is missing, or a claim has a wrong JSON type.
* ``invalid_request_uri``: an unapproved or unreachable ``request_uri``.
* The grant keeps its own errors, such as ``unsupported_response_type`` or
  ``invalid_scope``.

An error is only redirected to a URI the client registered and the
authorization session trusts. A request that never reaches a trusted
redirect returns its error directly, never to an attacker-supplied address.
"""

import pytest
from joserfc import jwk
from joserfc import jwt

from authlib.common.urls import add_params_to_uri
from authlib.common.urls import url_decode
from authlib.common.urls import urlparse
from authlib.oauth2 import rfc9101
from authlib.oauth2.rfc6749.grants import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
)
from authlib.oauth2.rfc7636 import CodeChallenge
from authlib.oidc.core import OpenIDCode as _OpenIDCode
from tests.util import read_file_path

from .models import AuthorizationCode
from .models import AuthorizationSession
from .models import CodeGrantMixin
from .models import exists_nonce
from .models import save_authorization_code

authorize_url = "/oauth/authorize"

PRIVATE_KEY = jwk.import_key(read_file_path("jwk_private.json"))
ATTACKER_REDIRECT_URI = "https://attacker.test/steal"
REGISTERED_REDIRECT_URI = "https://client.test/authorized"

ignore_alg_none_warning = pytest.mark.filterwarnings(
    'ignore:JWS algorithm "none" is deprecated:joserfc.errors.SecurityWarning'
)


def encode_request_object(claims=None, alg="RS256", key=None):
    """Sign a request object with the local fixture key."""
    payload = {"response_type": "code", "client_id": "client-id"}
    if claims:
        payload.update(claims)
    return jwt.encode({"alg": alg}, payload, key or PRIVATE_KEY, algorithms=[alg])


def redirect_params(response):
    parsed = urlparse.urlparse(response.location)
    return dict(url_decode(parsed.query)) or dict(url_decode(parsed.fragment))


def redirect_host(response):
    return urlparse.urlparse(response.location).netloc


@pytest.fixture(autouse=True)
def jwt_authorization_server(server):
    class AuthorizationCodeGrant(CodeGrantMixin, _AuthorizationCodeGrant):
        def save_authorization_code(self, code, request):
            return save_authorization_code(code, request)

    class OpenIDCode(_OpenIDCode):
        def exists_nonce(self, nonce, request):
            return exists_nonce(nonce, request)

    server.register_grant(
        AuthorizationCodeGrant, [CodeChallenge(required=False), OpenIDCode()]
    )
    server.scopes_supported = ["profile", "address", "openid"]
    return server


@pytest.fixture(autouse=True)
def jar_client(client, db):
    client.set_client_metadata(
        {
            "redirect_uris": ["https://client.test", REGISTERED_REDIRECT_URI],
            "scope": "profile address",
            "token_endpoint_auth_method": "client_secret_basic",
            "response_types": ["code"],
            "grant_types": ["authorization_code"],
            "jwks": read_file_path("jwks_public.json"),
            "require_signed_request_object": False,
            "request_uris": ["https://client.test/request_object"],
        }
    )
    db.session.add(client)
    db.session.commit()
    return client


def register_request_object_extension(server, metadata=None, stored_object=None):
    """Register JAR with local keys and a local request_uri resolver."""

    class JWTAuthenticationRequest(rfc9101.JWTAuthenticationRequest):
        def resolve_client_public_key(self, client):
            return read_file_path("jwk_public.json")

        def get_request_object(self, request_uri):
            return stored_object

        def get_server_metadata(self):
            return metadata or {}

        def get_client_require_signed_request_object(self, client):
            return client.client_metadata.get("require_signed_request_object", False)

    extension = JWTAuthenticationRequest()
    extension.validate_request_uri = lambda uri, client: (
        uri == "https://client.test/request_object"
    )
    server.register_extension(extension)
    return extension


def signed_request(claims=None):
    return add_params_to_uri(
        authorize_url,
        {"client_id": "client-id", "request": encode_request_object(claims)},
    )


# -- Baselines: valid JAR and JAR-less requests keep working -----------------


def test_signed_request_reaches_login(test_client, server):
    register_request_object_extension(server)
    response = test_client.get(
        signed_request(
            {
                "redirect_uri": REGISTERED_REDIRECT_URI,
                "scope": "profile",
                "state": "inner-state",
            }
        )
    )
    assert response.status_code == 200
    assert response.data == b"login"


def test_jarless_request_still_supported(test_client, server):
    register_request_object_extension(server)
    url = add_params_to_uri(
        authorize_url,
        {
            "response_type": "code",
            "client_id": "client-id",
            "redirect_uri": REGISTERED_REDIRECT_URI,
            "scope": "profile",
            "state": "plain-state",
        },
    )
    response = test_client.post(url + "&user_id=1")
    assert response.status_code == 303
    assert redirect_host(response) == "client.test"
    assert redirect_params(response)["state"] == "plain-state"


def test_request_uri_baseline(test_client, server):
    request_object = encode_request_object(
        {"redirect_uri": REGISTERED_REDIRECT_URI, "state": "inner-state"}
    )
    register_request_object_extension(server, stored_object=request_object)
    response = test_client.get(
        add_params_to_uri(
            authorize_url,
            {
                "client_id": "client-id",
                "request_uri": "https://client.test/request_object",
            },
        )
    )
    assert response.data == b"login"


# -- Outer parameters cannot override the signed request object --------------


def test_outer_client_id_unknown_is_invalid_client(test_client, server):
    """The outer client_id selects the client before the object is verified."""
    register_request_object_extension(server)
    request_object = encode_request_object(
        {"redirect_uri": REGISTERED_REDIRECT_URI, "state": "inner-state"}
    )
    response = test_client.get(
        add_params_to_uri(
            authorize_url,
            {"client_id": "unknown-client", "request": request_object},
        )
    )
    assert response.status_code == 404
    assert response.json["error"] == "invalid_client"
    assert response.location is None


def test_outer_client_id_mismatch_is_invalid_request(test_client, server):
    """A known but different outer client_id conflicts with the signed claim."""
    register_request_object_extension(server)
    request_object = jwt.encode(
        {"alg": "RS256"},
        {"response_type": "code", "client_id": "other-code-client"},
        PRIVATE_KEY,
    )
    response = test_client.get(
        add_params_to_uri(
            authorize_url,
            {"client_id": "client-id", "request": request_object},
        )
    )
    assert response.status_code == 400
    assert response.json["error"] == "invalid_request"
    assert "don't match" in response.json["error_description"]
    assert response.location is None


def test_outer_redirect_uri_cannot_change_the_code_destination(test_client, server):
    register_request_object_extension(server)
    request_object = encode_request_object(
        {"redirect_uri": REGISTERED_REDIRECT_URI, "state": "inner-state"}
    )
    tampered_url = add_params_to_uri(
        authorize_url,
        {
            "client_id": "client-id",
            "request": request_object,
            "redirect_uri": ATTACKER_REDIRECT_URI,
        },
    )
    # The consent flow ignores the outer redirect URI.
    assert test_client.get(tampered_url).data == b"login"
    # The code is only sent to the URI signed inside the request object.
    response = test_client.post(tampered_url + "&user_id=1")
    assert response.status_code == 303
    assert redirect_host(response) == "client.test"
    assert ATTACKER_REDIRECT_URI not in response.location
    assert redirect_params(response)["state"] == "inner-state"


def test_outer_scope_cannot_change_the_grant_scope(test_client, server, db):
    register_request_object_extension(server)
    request_object = encode_request_object(
        {
            "redirect_uri": REGISTERED_REDIRECT_URI,
            "scope": "profile",
            "state": "inner-state",
        }
    )
    response = test_client.post(
        add_params_to_uri(
            authorize_url,
            {
                "client_id": "client-id",
                "request": request_object,
                "scope": "address",
                "user_id": 1,
            },
        )
    )
    assert response.status_code == 303
    saved_code = db.session.query(AuthorizationCode).one()
    assert saved_code.scope == "profile"


def test_outer_state_cannot_change_the_response_state(test_client, server):
    register_request_object_extension(server)
    request_object = encode_request_object(
        {"redirect_uri": REGISTERED_REDIRECT_URI, "state": "inner-state"}
    )
    response = test_client.post(
        add_params_to_uri(
            authorize_url,
            {
                "client_id": "client-id",
                "request": request_object,
                "state": "OUTER-STATE",
                "user_id": 1,
            },
        )
    )
    assert redirect_params(response)["state"] == "inner-state"


@pytest.mark.parametrize("outer_response_type", ["token", "weird"])
def test_outer_response_type_cannot_change_grant_selection(
    test_client, server, outer_response_type
):
    register_request_object_extension(server)
    request_object = encode_request_object(
        {"redirect_uri": REGISTERED_REDIRECT_URI, "state": "inner-state"}
    )
    response = test_client.get(
        add_params_to_uri(
            authorize_url,
            {
                "client_id": "client-id",
                "request": request_object,
                "response_type": outer_response_type,
            },
        )
    )
    # The inner "code" response type selects the authorization code grant.
    assert response.status_code == 200
    assert response.data == b"login"


def test_consent_grant_sees_only_request_object_claims(test_client, server, app):
    register_request_object_extension(server)
    request_object = encode_request_object(
        {
            "redirect_uri": REGISTERED_REDIRECT_URI,
            "scope": "profile",
            "state": "inner-state",
        }
    )
    with app.test_request_context(
        add_params_to_uri(
            authorize_url,
            {
                "client_id": "client-id",
                "request": request_object,
                "redirect_uri": ATTACKER_REDIRECT_URI,
                "scope": "address",
                "state": "OUTER-STATE",
                "response_type": "token",
            },
        )
    ):
        from flask import request

        grant = server.get_consent_grant(server.create_oauth2_request(request))
        assert grant.request.payload.data == {
            "response_type": "code",
            "client_id": "client-id",
            "redirect_uri": REGISTERED_REDIRECT_URI,
            "scope": "profile",
            "state": "inner-state",
        }
        assert grant.redirect_uri == REGISTERED_REDIRECT_URI


def test_post_form_cannot_override_request_object(test_client, server):
    register_request_object_extension(server)
    request_object = encode_request_object(
        {"redirect_uri": REGISTERED_REDIRECT_URI, "state": "inner-state"}
    )
    response = test_client.post(
        authorize_url,
        data={
            "client_id": "client-id",
            "request": request_object,
            "redirect_uri": ATTACKER_REDIRECT_URI,
            "scope": "address",
            "state": "OUTER-STATE",
            "user_id": 1,
        },
    )
    assert redirect_host(response) == "client.test"
    assert redirect_params(response)["state"] == "inner-state"


def test_outer_redirect_uri_cannot_override_request_uri_object(test_client, server):
    request_object = encode_request_object(
        {"redirect_uri": REGISTERED_REDIRECT_URI, "state": "inner-state"}
    )
    register_request_object_extension(server, stored_object=request_object)
    response = test_client.get(
        add_params_to_uri(
            authorize_url,
            {
                "client_id": "client-id",
                "request_uri": "https://client.test/request_object",
                "redirect_uri": ATTACKER_REDIRECT_URI,
            },
        )
    )
    assert response.data == b"login"


# -- Failures inside the request object get their own error ------------------


def test_missing_inner_client_id_is_invalid_request_object(test_client, server):
    register_request_object_extension(server)
    request_object = jwt.encode(
        {"alg": "RS256"}, {"response_type": "code"}, PRIVATE_KEY
    )
    response = test_client.get(
        add_params_to_uri(
            authorize_url,
            {"client_id": "client-id", "request": request_object},
        )
    )
    assert response.status_code == 400
    assert response.json["error"] == "invalid_request_object"
    assert "client_id" in response.json["error_description"]


def test_missing_inner_response_type_keeps_grant_error(test_client, server):
    """A claim that is structurally valid but unsupported reaches the grant,
    instead of being conflated with a malformed request object."""
    register_request_object_extension(server)
    request_object = jwt.encode(
        {"alg": "RS256"}, {"client_id": "client-id", "state": "s"}, PRIVATE_KEY
    )
    response = test_client.get(
        add_params_to_uri(
            authorize_url,
            {"client_id": "client-id", "request": request_object},
        )
    )
    assert response.status_code == 400
    assert response.json["error"] == "unsupported_response_type"
    assert response.json["state"] == "s"


def test_missing_inner_redirect_uri_uses_client_default(test_client, server):
    register_request_object_extension(server)
    response = test_client.get(signed_request({"scope": "profile", "state": "s2"}))
    assert response.data == b"login"


def test_inner_claim_wrong_type_is_invalid_request_object(test_client, server):
    register_request_object_extension(server)
    request_object = encode_request_object({"scope": ["profile"]})
    response = test_client.get(
        add_params_to_uri(
            authorize_url,
            {
                "client_id": "client-id",
                "request": request_object,
                "state": "outer-state",
            },
        )
    )
    assert response.status_code == 400
    assert response.json["error"] == "invalid_request_object"
    assert response.json["error_description"].endswith("parameter has an invalid type.")
    # The outer state still identifies the client request at parse time.
    assert response.json["state"] == "outer-state"


def test_bad_signature_is_invalid_request_object(test_client, server):
    register_request_object_extension(server)
    request_object = jwt.encode(
        {"alg": "RS256"},
        {"client_id": "client-id", "response_type": "code"},
        jwk.generate_key("RSA", 2048),
    )
    response = test_client.get(
        add_params_to_uri(
            authorize_url,
            {"client_id": "client-id", "request": request_object},
        )
    )
    assert response.status_code == 400
    assert response.json["error"] == "invalid_request_object"


def test_unparseable_request_is_invalid_request_object(test_client, server):
    register_request_object_extension(server)
    response = test_client.get(
        add_params_to_uri(
            authorize_url,
            {"client_id": "client-id", "request": "not-a-jwt"},
        )
    )
    assert response.status_code == 400
    assert response.json["error"] == "invalid_request_object"


def test_disabled_algorithm_is_invalid_request(test_client, server):
    """An algorithm outside the server policy is not treated as a bad JWT."""
    register_request_object_extension(
        server,
        metadata={"request_object_signing_alg_values_supported": ["ES256"]},
    )
    request_object = encode_request_object({"state": "s"})
    response = test_client.get(
        add_params_to_uri(
            authorize_url,
            {
                "client_id": "client-id",
                "request": request_object,
                "state": "outer-state",
            },
        )
    )
    assert response.status_code == 400
    assert response.json["error"] == "invalid_request"
    assert response.json["error_description"] == (
        "Authorization requests must be signed with supported algorithms."
    )


@ignore_alg_none_warning
def test_alg_none_when_signature_required_is_invalid_request(test_client, server):
    register_request_object_extension(
        server, metadata={"require_signed_request_object": True}
    )
    request_object = encode_request_object(alg="none", key=jwk.generate_key("oct"))
    response = test_client.get(
        add_params_to_uri(
            authorize_url,
            {
                "client_id": "client-id",
                "request": request_object,
                "state": "outer-state",
            },
        )
    )
    assert response.status_code == 400
    assert response.json["error"] == "invalid_request"
    assert response.json["error_description"] == (
        "Authorization requests must be signed with supported algorithms."
    )


@pytest.mark.parametrize("requirement", ["server", "client"])
def test_required_request_object_omitted_is_invalid_request(
    test_client, server, jar_client, db, requirement
):
    if requirement == "client":
        jar_client.set_client_metadata(
            {**jar_client.client_metadata, "require_signed_request_object": True}
        )
        db.session.commit()
        metadata = None
    else:
        metadata = {"require_signed_request_object": True}
    register_request_object_extension(server, metadata=metadata)
    response = test_client.get(
        add_params_to_uri(
            authorize_url,
            {
                "response_type": "code",
                "client_id": "client-id",
                "state": "outer-state",
            },
        )
    )
    assert response.status_code == 400
    assert response.json["error"] == "invalid_request"
    assert "signed request object" in response.json["error_description"]
    assert response.json["state"] == "outer-state"
    assert response.location is None


# -- Errors never reach an untrusted redirect URI ----------------------------


def test_parse_error_with_attacker_redirect_uri_is_not_redirected(test_client, server):
    register_request_object_extension(server)
    response = test_client.get(
        add_params_to_uri(
            authorize_url,
            {
                "client_id": "client-id",
                "request": "not-a-jwt",
                "redirect_uri": ATTACKER_REDIRECT_URI,
                "state": "outer-state",
            },
        )
    )
    assert response.status_code == 400
    assert response.location is None
    assert response.json["error"] == "invalid_request_object"
    assert response.json["state"] == "outer-state"


def test_signed_but_unregistered_inner_redirect_uri_is_rejected(test_client, server):
    """The signature proves the client sent the URI, not that the URI is
    registered. The grant rejects it and never redirects to it."""
    register_request_object_extension(server)
    request_object = encode_request_object(
        {"redirect_uri": ATTACKER_REDIRECT_URI, "state": "s6"}
    )
    for method, url in (
        ("get", authorize_url),
        ("post", authorize_url),
    ):
        response = getattr(test_client, method)(
            add_params_to_uri(
                url,
                {
                    "client_id": "client-id",
                    "request": request_object,
                    "user_id": 1,
                },
            )
        )
        assert response.status_code == 400
        assert response.location is None
        assert response.json["error"] == "invalid_request"
        assert response.json["state"] == "s6"


def test_untrusted_session_blocks_error_redirection(test_client, server, app):
    class UntrustedAuthorizationSession(AuthorizationSession):
        def can_redirect_error(self, request, error):
            return False

    app.config["AUTHORIZATION_SESSION"] = UntrustedAuthorizationSession
    register_request_object_extension(server)
    request_object = encode_request_object(
        {"redirect_uri": ATTACKER_REDIRECT_URI, "state": "s6"}
    )
    response = test_client.post(
        add_params_to_uri(
            authorize_url,
            {
                "client_id": "client-id",
                "request": request_object,
                "user_id": 1,
            },
        )
    )
    assert response.status_code == 400
    assert response.location is None
    assert response.json["error"] == "invalid_request"


def test_authorization_code_is_bound_to_inner_parameters(test_client, server, db):
    register_request_object_extension(server)
    request_object = encode_request_object(
        {
            "redirect_uri": REGISTERED_REDIRECT_URI,
            "scope": "profile",
            "state": "inner-state",
        }
    )
    test_client.post(
        add_params_to_uri(
            authorize_url,
            {
                "client_id": "client-id",
                "request": request_object,
                "redirect_uri": ATTACKER_REDIRECT_URI,
                "scope": "address",
                "state": "OUTER-STATE",
                "user_id": 1,
            },
        )
    )
    saved_code = db.session.query(AuthorizationCode).one()
    assert saved_code.client_id == "client-id"
    assert saved_code.redirect_uri == REGISTERED_REDIRECT_URI
    assert saved_code.scope == "profile"
