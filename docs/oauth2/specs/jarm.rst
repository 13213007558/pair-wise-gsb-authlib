.. _specs/jarm:

JARM: JWT Secured Authorization Response Mode
=============================================

This section contains the implementation of the
`JWT Secured Authorization Response Mode for OAuth 2.0 (JARM)
<https://openid.net/specs/oauth-v2-jarm.html>`_.

With JARM, the authorization server returns the authorization response as a
signed JWT in the ``response`` parameter, instead of plaintext ``code`` and
``state`` parameters. Both successful responses and error responses that may
safely be redirected are embedded in the signed JWT, together with the
``iss``, ``aud`` and ``exp`` claims. Only the ``query.jwt`` and
``form_post.jwt`` response modes with signed (not encrypted) JWTs are
supported.

Authorization Server
--------------------

Implement :class:`~authlib.oauth2.jarm.JWTSecuredAuthorizationResponse` and
register it as an extension of the authorization server::

    from authlib.oauth2.jarm import JWTSecuredAuthorizationResponse


    class JARM(JWTSecuredAuthorizationResponse):
        def get_issuer(self) -> str:
            return "https://as.example.com"

        def resolve_client_private_key(self, client):
            return KeySet.import_key_set(load_server_jwks())


    authorization_server.register_extension(JARM())

The signing algorithm is determined by the client metadata
``authorization_signed_response_alg`` and falls back to the ``default_alg``
of the extension (``RS256``). Errors whose ``redirect_uri`` has not been
validated are never redirected, as before. The ``form_post.jwt`` response
page escapes the action URL and the field value for the HTML context.

Clients that use the Flask integration can receive both ``query.jwt`` and
``form_post.jwt`` responses out of the box. The signature, the signing
algorithm (from the ``authorization_signing_alg_values_supported`` server
metadata), the ``issuer`` and the ``audience`` are verified before the
``state`` is checked and the ``code`` is extracted. Plaintext parameters
next to the ``response`` parameter are rejected, and a failed verification
does not consume the stored state::

    oauth.register(
        "example",
        client_id="...",
        client_secret="...",
        authorize_url="https://as.example.com/authorize",
        access_token_url="https://as.example.com/token",
        issuer="https://as.example.com",
        jwks={...},
        authorization_signing_alg_values_supported=["RS256"],
    )

API Reference
-------------

.. module:: authlib.oauth2.jarm

.. autoclass:: JWTSecuredAuthorizationResponse
    :member-order: bysource
    :members:

.. autoclass:: InvalidJARMResponseError

.. autofunction:: validate_jarm_response
