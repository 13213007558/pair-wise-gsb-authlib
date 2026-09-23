"""authlib.oauth2.jarm
~~~~~~~~~~~~~~~~~~~~~

Implementation of the JWT Secured Authorization Response Mode for
OAuth 2.0 (JARM). Only *signed* JWT responses are supported, through
the ``query.jwt`` and ``form_post.jwt`` response modes; encrypted
responses are not implemented.
"""

import html
import time

from joserfc import jwt

from authlib._joserfc_helpers import import_any_key
from authlib.common.urls import add_params_to_uri
from authlib.common.urls import url_decode
from authlib.common.urls import urlparse

from ..rfc6749.requests import OAuth2Request

__all__ = ["JWTSecuredAuthorizationResponse", "validate_jwt_response"]

#: Default leeway in seconds when validating a JARM response
DEFAULT_LEEWAY = 120


class JWTSecuredAuthorizationResponse:
    """Authorization server extension implementing the signed part of
    JARM (JWT Secured Authorization Response Mode for OAuth 2.0).

    When the authorization request contains ``response_mode=query.jwt``
    or ``response_mode=form_post.jwt``, the authorization response
    parameters (``code``, ``state``, or the OAuth error parameters) are
    packaged into a signed JWT which is returned in a single ``response``
    parameter. No plaintext copy of the parameters is exposed outside
    the JWT. Errors that may not be redirected (e.g. unvalidated
    ``redirect_uri``) keep the original JSON error response.

    This extension is registered into the authorization server, and
    requires developers to implement :meth:`get_issuer` and
    :meth:`resolve_server_key`::

        class JARM(JWTSecuredAuthorizationResponse):
            def get_issuer(self):
                return "https://as.example.com"

            def resolve_server_key(self, client):
                return load_server_jwk(client)


        authorization_server.register_extension(JARM())

    The signing algorithm is decided by the client registration metadata
    ``authorization_signed_response_alg`` (defaults to
    ``DEFAULT_ALGORITHM`` when absent). ``none`` is never accepted.
    """

    #: Response modes handled by this extension
    RESPONSE_MODES = ("query.jwt", "form_post.jwt")

    #: Lifetime of a JWT response, in seconds
    EXPIRES_IN = 600

    #: Signing algorithm used when the client did not register
    #: ``authorization_signed_response_alg``
    DEFAULT_ALGORITHM = "RS256"

    def __call__(self, authorization_server):
        authorization_server.register_hook(
            "before_create_authorization_response", self._wrap_grant
        )
        self._wrap_error_response(authorization_server)

    def get_issuer(self) -> str:
        """Return the issuer identifier used as the ``iss`` claim of the
        JWT response. Developers MUST implement this method::

            def get_issuer(self):
                return "https://as.example.com"
        """
        raise NotImplementedError()

    def resolve_server_key(self, client):
        """Resolve the key used to sign the JWT response for the given
        client. Developers MUST implement this method. The returned value
        is normalized with the existing key interface
        (:func:`authlib._joserfc_helpers.import_any_key`), so a JWK dict,
        a PEM string, a key or a key set are all accepted::

            def resolve_server_key(self, client):
                return KeySet.import_key_set(load_server_jwks())
        """
        raise NotImplementedError()

    def get_key_id(self, client):
        """Return the ``kid`` header value used to select the signing key
        when :meth:`resolve_server_key` returns a key set. Developers MAY
        implement this method. Defaults to :data:`None`.
        """
        return None

    def get_signing_algorithm(self, client) -> str:
        """Return the signing algorithm allowed for the given client,
        decided by the client registration metadata
        ``authorization_signed_response_alg``. Developers MAY rewrite
        this method to customize how the algorithm is resolved.
        """
        metadata = getattr(client, "client_metadata", None) or {}
        alg = metadata.get("authorization_signed_response_alg")
        if not alg:
            alg = self.DEFAULT_ALGORITHM
        if alg == "none":
            raise RuntimeError(
                "JARM requires a signed response; algorithm 'none' is not allowed."
            )
        return alg

    def _wrap_grant(self, server, *args, **kwargs):
        grant = kwargs.get("grant")
        if grant is None and len(args) >= 3:
            grant = args[2]
        if grant is None:
            return

        response_mode = grant.request.payload.data.get("response_mode")
        if response_mode not in self.RESPONSE_MODES:
            return

        original_create_response = grant.create_authorization_response

        def create_authorization_response(redirect_uri, grant_user):
            status, body, headers = original_create_response(redirect_uri, grant_user)
            location = _get_header(headers, "Location")
            if location is None:
                return status, body, headers
            params = _extract_response_params(location)
            return self._create_jarm_response(
                server, grant.request, response_mode, redirect_uri, params
            )

        grant.create_authorization_response = create_authorization_response

    def _wrap_error_response(self, server):
        original_handle_error_response = server.handle_error_response

        def handle_error_response(request, error):
            # Only errors that are already safe to redirect (validated
            # redirect_uri) are packaged into a JWT response.
            redirect_uri = getattr(error, "redirect_uri", None)
            if redirect_uri:
                if isinstance(request, OAuth2Request):
                    oauth_request = request
                else:
                    oauth_request = server.create_oauth2_request(request)
                response_mode = oauth_request.payload.data.get("response_mode")
                if response_mode in self.RESPONSE_MODES:
                    uri = server.get_error_uri(request, error)
                    _, _, headers = error(uri)
                    location = _get_header(headers, "Location")
                    params = _extract_response_params(location)
                    args = self._create_jarm_response(
                        server, oauth_request, response_mode, redirect_uri, params
                    )
                    return server.handle_response(*args)
            return original_handle_error_response(request, error)

        server.handle_error_response = handle_error_response

    def _create_jarm_response(
        self, server, request, response_mode, redirect_uri, params
    ):
        client = request.client
        if client is None:
            client = server.query_client(request.payload.client_id)

        alg = self.get_signing_algorithm(client)
        header = {"alg": alg}
        kid = self.get_key_id(client)
        if kid:
            header["kid"] = kid

        claims = dict(params)
        claims["iss"] = self.get_issuer()
        claims["aud"] = request.payload.client_id
        claims["exp"] = int(time.time()) + self.EXPIRES_IN

        key = import_any_key(self.resolve_server_key(client))
        response_jwt = jwt.encode(header, claims, key, [alg])

        if response_mode == "form_post.jwt":
            body = _render_form_post(redirect_uri, response_jwt)
            return 200, body, [("Content-Type", "text/html; charset=utf-8")]

        location = add_params_to_uri(redirect_uri, [("response", response_jwt)])
        return 302, "", [("Location", location)]


def validate_jwt_response(
    response, key, issuer, audience, algorithms=None, leeway=DEFAULT_LEEWAY
):
    """Decode and validate a signed JARM ``response`` parameter.

    The JWT signature, algorithm, ``iss``, ``aud`` and ``exp`` claims
    are verified before the claims are returned.

    :param response: the ``response`` parameter received on the client
        redirection endpoint.
    :param key: the key (or key set) to verify the JWT signature.
    :param issuer: expected ``iss`` value.
    :param audience: expected ``aud`` value, usually the client_id.
    :param algorithms: allowed signing algorithms, defaults to the
        joserfc recommended algorithms.
    :param leeway: leeway in seconds for ``exp`` validation.
    :return: the JWT claims dict.
    :raises joserfc.errors.JoseError: if the signature or any claim
        is invalid.
    """
    key = import_any_key(key)
    token = jwt.decode(response, key, algorithms=algorithms)
    registry = jwt.JWTClaimsRegistry(
        leeway=leeway,
        iss={"essential": True, "value": issuer},
        aud={"essential": True, "values": [audience]},
        exp={"essential": True},
    )
    registry.validate(token.claims)
    return token.claims


def _get_header(headers, name):
    for key, value in headers:
        if key.lower() == name.lower():
            return value
    return None


def _extract_response_params(location):
    parsed = urlparse.urlparse(location)
    query = parsed.query or parsed.fragment
    return url_decode(query)


def _render_form_post(redirect_uri, response):
    # The action address and field values are escaped for the HTML
    # context they appear in.
    action = html.escape(redirect_uri, quote=True)
    value = html.escape(response, quote=True)
    return (
        "<html><head><title>Redirecting</title></head>"
        '<body onload="javascript:document.forms[0].submit()">'
        f'<form method="post" action="{action}">'
        f'<input type="hidden" name="response" value="{value}"/>'
        "</form></body></html>"
    )
