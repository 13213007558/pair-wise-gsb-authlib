OpenID Connect Back-Channel Logout 1.0
======================================

Back-channel logout is a server-to-server POST from the OpenID Provider. The
request is not sent by the browser, so the relying party cannot read a Flask
session cookie. The application must provide server-side session storage.

Configure a store when registering the OIDC client::

    from authlib.oidc.backchannel import InMemoryBackChannelLogoutStore

    store = InMemoryBackChannelLogoutStore()
    oauth.register(
        "provider",
        client_id="my-client",
        backchannel_logout_store=store,
        issuer="https://provider.example",
        jwks=provider_jwks,
        id_token_signing_alg_values_supported=["RS256"],
    )

Expose the notification endpoint::

    @app.post("/oidc/backchannel-logout")
    def backchannel_logout():
        return oauth.provider.handle_backchannel_logout()

Authlib verifies the token signature, issuer, exact client audience, signing
algorithm, time claims, logout ``events`` claim, and ``jti``. A logout token
must contain ``sid`` or ``sub`` and must not contain ``nonce``.

Session scope
-------------

Implement :class:`authlib.oidc.backchannel.BackChannelLogoutStore` for your
session database:

- ``sid`` revokes only the matching session for the token's issuer and client.
- ``sub`` without ``sid`` revokes all active sessions for that subject in the
  same issuer/client scope.
- Both claims must identify the same session; otherwise the token is rejected.
- Unknown or already revoked sessions are successful and idempotent.

Replay protection is also scoped by issuer, client ID, and ``jti``. The same
``jti`` from another issuer or client is a different logout notification.

Storage failures
----------------

Storage methods must raise an exception if lookup, revocation, or replay-state
update does not complete. The Flask handler does not convert such an exception
into a successful HTTP response, so the OpenID Provider can retry.
