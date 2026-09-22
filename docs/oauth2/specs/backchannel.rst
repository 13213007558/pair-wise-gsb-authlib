.. _specs/backchannel:

OpenID Connect Back-Channel Logout 1.0
======================================

.. meta::
    :description: Python API references on OpenID Connect Back-Channel Logout 1.0
        with Authlib implementation.

.. module:: authlib.oidc.backchannel

This section contains the Relying Party (RP) side implementation of
`OpenID Connect Back-Channel Logout 1.0`_. The OP sends a Logout Token
directly to the RP's back-channel logout URI; there is no browser and no
cookie, so the RP invalidates its server-side sessions through a session
adapter provided by the application.

.. _OpenID Connect Back-Channel Logout 1.0: https://openid.net/specs/openid-connect-backchannel-1_0.html

Receiving Logout Tokens
-----------------------

The framework-agnostic :class:`BackChannelLogoutReceiver` validates the
Logout Token (signature, issuer, audience, algorithm, time claims, the
back-channel logout `events` claim, and the required `sid` or `sub`
claim; tokens with a `nonce` claim are rejected) and invalidates the
matching sessions via a :class:`BackChannelLogoutStore`::

    from authlib.oidc.backchannel import BackChannelLogoutReceiver
    from authlib.oidc.backchannel import InMemoryBackChannelLogoutStore

    store = InMemoryBackChannelLogoutStore()
    receiver = BackChannelLogoutReceiver(
        store,
        issuer="https://provider.test",
        client_id="my-client-id",
        jwks=fetch_provider_jwks(),
        algorithms=["RS256"],
    )
    claims = receiver.process_logout(logout_token)

Session invalidation is scoped to `(issuer, client_id)`:

- with `sid`, only that one session is invalidated; when `sub` is also
  present it must match the identity of that session
- with only `sub`, every session of that subject under this issuer and
  client is invalidated

Sessions of the same subject under another issuer or client are never
touched.

Replay Contract
---------------

Processing is idempotent: a replayed Logout Token whose sessions are
already invalidated still succeeds. Storage errors raised by the session
adapter are propagated unchanged, so the caller knows the logout was not
fully processed and must not report success to the OP.

Session Stores
--------------

Applications provide their own session adapter by subclassing
:class:`BackChannelLogoutStore`. All methods must be idempotent, and
storage failures must raise instead of silently succeeding.
:class:`InMemoryBackChannelLogoutStore` is a ready-made implementation
for development and tests.

Flask Integration
-----------------

The Flask client exposes :meth:`FlaskOAuth2App.handle_backchannel_logout`,
which builds the receiver from the provider metadata and returns the HTTP
response (200 on success, 400 on an invalid token)::

    @app.route("/backchannel-logout", methods=["POST"])
    def backchannel_logout():
        return oauth.google.handle_backchannel_logout(session_store)

API Reference
-------------

.. autoclass:: BackChannelLogoutReceiver
    :member-order: bysource
    :members:

.. autoclass:: LogoutToken
    :member-order: bysource
    :members:

.. autoclass:: BackChannelLogoutStore
    :member-order: bysource
    :members:

.. autoclass:: InMemoryBackChannelLogoutStore
    :member-order: bysource
    :members:

