Added
~~~~~

- RP side of OpenID Connect Back-Channel Logout 1.0: ``validate_logout_token``,
  ``BackchannelLogoutReceiver``, ``LogoutTokenStore``, ``LogoutResult`` and
  ``InvalidLogoutTokenError`` in ``authlib.oidc.backchannel``. The receiver
  validates the logout token (signature, issuer, audience, time, events,
  sub/sid, no nonce), records the ``jti`` and invalidates the matching
  sessions atomically, and answers duplicates idempotently.
