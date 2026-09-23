.. _specs/jarm:

JARM: JWT Secured Authorization Response Mode
=============================================

This section contains the implementation of the *signed* part of
`JWT Secured Authorization Response Mode for OAuth 2.0`_ (JARM).
Encrypted JWT responses are not supported yet.

.. _`JWT Secured Authorization Response Mode for OAuth 2.0`: https://openid.net/specs/oauth-v2-jarm.html

Authorization Server
--------------------

When an authorization request contains ``response_mode=query.jwt`` or
``response_mode=form_post.jwt``, the authorization server packages the
response parameters (``code`` and ``state`` on success, or the OAuth
error parameters) into a signed JWT, which is returned in a single
``response`` parameter. The JWT contains the ``iss``, ``aud`` and
``exp`` claims; no plaintext copy of the parameters is exposed outside
the JWT. Errors that may not be redirected (e.g. an unvalidated
``redirect_uri``) keep the original JSON error response.

Register the extension into the authorization server, and implement
:meth:`~authlib.oauth2.jarm.JWTSecuredAuthorizationResponse.get_issuer`
and
:meth:`~authlib.oauth2.jarm.JWTSecuredAuthorizationResponse.resolve_server_key`::

    from authlib.oauth2.jarm import JWTSecuredAuthorizationResponse


    class JARM(JWTSecuredAuthorizationResponse):
        def get_issuer(self):
            return "https://as.example.com"

        def resolve_server_key(self, client):
            return load_server_jwk(client)


    authorization_server.register_extension(JARM())

The signing algorithm is decided by the client registration metadata
``authorization_signed_response_alg``. Plain ``query`` and ``form_post``
response modes are not affected by this extension.

Client
------

The Flask client validates a JARM ``response`` parameter automatically
when the remote application is registered with the JARM configuration::

    oauth.register(
        "example",
        client_id="...",
        client_secret="...",
        jarm_key=load_server_public_jwk(),
        jarm_issuer="https://as.example.com",
        jarm_algorithms=["RS256"],
    )

The JWT signature, algorithm, issuer, audience and validity period are
verified before the ``state`` is checked and consumed. A plaintext
``code`` parameter next to the JWT ``response`` parameter is rejected.

API Reference
-------------

.. module:: authlib.oauth2.jarm

.. autoclass:: JWTSecuredAuthorizationResponse
    :member-order: bysource
    :members:

.. autofunction:: validate_jwt_response
