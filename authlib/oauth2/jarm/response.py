"""JWT Secured Authorization Response Mode for OAuth 2.0 (JARM).

This module implements the server side of the ``query.jwt`` and
``form_post.jwt`` response modes. Authorization responses (including
error responses that may safely be redirected) are delivered as a
signed JWT in the ``response`` parameter. Encrypted responses are not
supported yet.
"""

import html
import time

from joserfc import jwt

from authlib._joserfc_helpers import import_any_key
from authlib.common.urls import add_params_to_uri
from authlib.common.urls import urlparse

from ..rfc6749.errors import OAuth2Error


class JWTSecuredAuthorizationResponse:
    """A JWT Secured Authorization Response Mode (JARM) extension for the
    authorization server. Register it with::

        class MyJARM(JWTSecuredAuthorizationResponse):
            def get_issuer(self):
                return "https://as.example.com"

            def resolve_client_private_key(self, client):
                return KeySet.import_key_set(load_server_jwks())


        authorization_server.register_extension(MyJARM())

    Once registered, authorization requests carrying
    ``response_mode=query.jwt`` or ``response_mode=form_post.jwt`` receive
    the authorization response as a signed JWT in the ``response``
    parameter. Both successful responses (``code``, ``state``) and error
    responses that may safely be redirected (``error``,
    ``error_description``, ``state``) are embedded in the signed JWT; no
    plaintext duplicates are added next to it. Errors without a validated
    ``redirect_uri`` are never redirected, as before.

    :param issuer: the ``iss`` value for the JWT, may also be provided by
        implementing :meth:``get_issuer``.
    :param expires_in: lifetime of the JWT in seconds, used for ``exp``.
    :param default_alg: fallback signing algorithm when the client did not
        register ``authorization_signed_response_alg``.
    """

    #: supported JARM response modes
    RESPONSE_MODES = ("query.jwt", "form_post.jwt")

    def __init__(self, issuer=None, expires_in=600, default_alg="RS256"):
        self.issuer = issuer
        self.expires_in = expires_in
        self.default_alg = default_alg

    def __call__(self, authorization_server):
        authorization_server.register_hook(
            "after_get_authorization_grant", self.secure_grant_response
        )

    def get_issuer(self) -> str | None:
        """Return the issuer URL used as ``iss`` claim. Developers MAY
        implement this method instead of passing ``issuer`` to the
        constructor::

            def get_issuer(self) -> str:
                return "https://as.example.com"
        """
        return self.issuer

    def resolve_client_private_key(self, client):
        """Resolve the key used to sign the authorization response for the
        given client. Developers MUST implement this method, e.g.::

            def resolve_client_private_key(self, client):
                with open("jwks.json") as f:
                    return KeySet.import_key_set(json.load(f))

        :param client: the client instance the response is issued for.
        :return: a key or key set accepted by ``joserfc``.
        """
        raise NotImplementedError()

    def get_signing_alg(self, client) -> str:
        """Return the ``alg`` for signing the authorization response. The
        client metadata ``authorization_signed_response_alg`` takes
        precedence, falling back to the ``default_alg`` of this extension.
        """
        alg = getattr(client, "authorization_signed_response_alg", None)
        if not alg:
            metadata = getattr(client, "client_metadata", None) or {}
            alg = metadata.get("authorization_signed_response_alg")
        return alg or self.default_alg

    def secure_grant_response(self, authorization_server, grant):
        """Hook for ``after_get_authorization_grant``: wrap the grant so
        that its authorization response is secured with a signed JWT when
        the request asks for a JARM response mode.
        """
        response_mode = grant.request.payload.data.get("response_mode")
        if response_mode not in self.RESPONSE_MODES:
            return
        if getattr(grant, "_jarm_secured", False):
            return
        grant._jarm_secured = True

        original_validate = grant.validate_authorization_request
        original_create = grant.create_authorization_response

        def validate_authorization_request():
            try:
                return original_validate()
            except OAuth2Error as error:
                raise self._secure_error(grant, error, response_mode) from error

        def create_authorization_response(redirect_uri, grant_user):
            try:
                status, body, headers = original_create(redirect_uri, grant_user)
            except OAuth2Error as error:
                raise self._secure_error(grant, error, response_mode) from error
            params = _extract_redirect_params(status, headers)
            if params is None:
                return status, body, headers
            return self.create_response(grant, redirect_uri, params, response_mode)

        grant.validate_authorization_request = validate_authorization_request
        grant.create_authorization_response = create_authorization_response

    def create_response(self, grant, redirect_uri, params, response_mode):
        """Create the ``(status, body, headers)`` tuple for a JWT secured
        authorization response carrying the given parameters.
        """
        client = self._resolve_client(grant)
        alg = self.get_signing_alg(client)
        key = import_any_key(self.resolve_client_private_key(client))

        issuer = self.get_issuer()
        if not issuer:
            raise RuntimeError('Missing "issuer" for JWT secured response')

        now = int(time.time())
        claims = {
            "iss": issuer,
            "aud": client.get_client_id(),
            "iat": now,
            "exp": now + self.expires_in,
        }
        claims.update(dict(params))

        header = {"alg": alg}
        kid = getattr(key, "kid", None)
        if kid:
            header["kid"] = kid
        response_jwt = jwt.encode(header, claims, key, [alg])

        if response_mode == "form_post.jwt":
            body = _render_form_post(redirect_uri, response_jwt)
            return 200, body, [("Content-Type", "text/html; charset=utf-8")]

        uri = add_params_to_uri(redirect_uri, {"response": response_jwt})
        return 302, "", [("Location", uri)]

    def _secure_error(self, grant, error, response_mode):
        # errors may only be redirected when the redirect_uri has been
        # validated, and can only be signed when the client is known
        if not error.redirect_uri or not self._resolve_client(grant):
            return error
        return _JWTSecuredError(error, self, grant, response_mode)

    @staticmethod
    def _resolve_client(grant):
        client = grant.request.client
        if client is None:
            client_id = grant.request.payload.client_id
            if client_id:
                client = grant.server.query_client(client_id)
        return client


class _JWTSecuredError(OAuth2Error):
    """An OAuth2Error wrapper that delivers the error parameters inside a
    signed JWT instead of plaintext redirect parameters. The JWT is built
    lazily in ``__call__`` so that ``state`` assigned by the authorization
    server afterwards is included.
    """

    def __init__(self, error, jarm, grant, response_mode):
        super().__init__(description=error.description, error=error.error)
        self.original_error = error
        self._jarm = jarm
        self._grant = grant
        self._response_mode = response_mode

    def __call__(self, uri=None):
        params = self.original_error.get_body()
        if self.state and not any(k == "state" for k, _ in params):
            params.append(("state", self.state))
        return self._jarm.create_response(
            self._grant,
            self.original_error.redirect_uri,
            params,
            self._response_mode,
        )


def _extract_redirect_params(status, headers):
    """Extract the response parameters from a redirect response, or return
    None if the response is not a redirect.
    """
    if status != 302:
        return None
    location = None
    for name, value in headers:
        if name.lower() == "location":
            location = value
            break
    if not location:
        return None
    parts = urlparse.urlparse(location)
    raw = parts.query or parts.fragment
    return urlparse.parse_qsl(raw, keep_blank_values=True)


def _render_form_post(redirect_uri, response_jwt):
    # the action URL and the field value MUST be escaped for the HTML
    # context, URL encoding is not sufficient here
    action = html.escape(redirect_uri, quote=True)
    value = html.escape(response_jwt, quote=True)
    return (
        "<html><head><title>Redirecting</title></head>"
        '<body onload="javascript:document.forms[0].submit()">'
        f'<form method="post" action="{action}">'
        f'<input type="hidden" name="response" value="{value}"/>'
        "</form></body></html>"
    )
