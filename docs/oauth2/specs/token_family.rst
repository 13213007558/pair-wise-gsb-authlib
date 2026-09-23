.. _specs/token_family:

Token Family: Rotation-Aware Revocation
=======================================

.. meta::
    :description: Optional token-family semantics for Authlib revocation,
        refresh_token rotation and introspection.

.. module:: authlib.oauth2.token_family

A *token family* is the chain of tokens produced by refresh token
rotation. Every time a refresh token is exchanged, the newly issued token
records the id of the token it derived from (``parent_id``). When a
refresh token leaks, the authorization server can revoke the token and
everything derived from it - or the whole family - in one call.

This feature is strictly opt-in. Applications that do not store a
``parent_id`` link keep the original single-token behavior of
:ref:`specs/rfc7009` and :class:`~authlib.oauth2.rfc6749.grants.RefreshTokenGrant`.

Storage
-------

Token models need an ``id`` primary key and a nullable ``parent_id``
column. With SQLAlchemy, mix in
:class:`~authlib.integrations.sqla_oauth2.OAuth2TokenFamilyMixin`::

    from authlib.integrations.sqla_oauth2 import (
        OAuth2TokenFamilyMixin,
        OAuth2TokenMixin,
    )

    class Token(db.Model, OAuth2TokenMixin, OAuth2TokenFamilyMixin):
        id = db.Column(db.Integer, primary_key=True)
        # ...

Refresh token rotation
----------------------

:class:`RefreshTokenFamilyGrant` extends the plain refresh token grant:
it always issues a new refresh token and links it to the rotated-out one.
The old credential is revoked and the new token is saved inside **one
atomic operation**, `:meth:`RefreshTokenFamilyGrant.rotate_token`, so that:

* two concurrent refresh requests on the same refresh token produce at
  most one new family member - the loser gets an ``invalid_grant``
  error response;
* a refresh token revoked by the revocation endpoint can never be
  resurrected by a racing refresh transaction.

The SQLAlchemy integration implements this with a conditional
``UPDATE ... WHERE refresh_token_revoked_at = 0`` whose affected-row
count is checked before the child token is inserted in the same
transaction::

    from authlib.integrations.sqla_oauth2 import (
        create_refresh_token_family_grant,
    )

    RefreshTokenFamilyGrant = create_refresh_token_family_grant(
        db.session, Token
    )

    class MyRefreshTokenGrant(RefreshTokenFamilyGrant):
        def authenticate_user(self, credential):
            return User.get(credential.user_id)

    authorization_server.register_grant(MyRefreshTokenGrant)

Revocation
----------

:class:`TokenFamilyRevocationEndpoint` extends the RFC7009 endpoint:

* by default, revoking a token also revokes **all of its descendants**;
* if the request contains a truthy ``family`` parameter (``1``,
  ``true`` or ``yes``), the **whole family** is revoked: the root
  token and everything derived from it, including ancestors and
  siblings of the submitted token.

::

    from authlib.integrations.sqla_oauth2 import (
        create_token_family_revocation_endpoint,
    )

    RevocationEndpoint = create_token_family_revocation_endpoint(
        db.session, Token
    )
    authorization_server.register_endpoint(RevocationEndpoint)

Both the access token and the refresh token of every affected row are
marked as revoked.

Introspection
-------------

:class:`TokenFamilyIntrospectionEndpoint` distinguishes *why* a token is
not active, without leaking family information:

* ``{"active": false, "status": "unknown"}`` - the token does not
  exist (or the caller may not introspect it);
* ``{"active": false, "status": "revoked"}`` - the token was revoked,
  directly or through a descendant/family revocation;
* ``{"active": false, "status": "expired"}`` - the token lifetime
  has elapsed.

Active responses carry ``"status": "active"``. Family linkage fields
(``parent_id``, ``family_id``) are stripped from the payload, so
clients never learn the shape of the token family.

Behavior notes
--------------

* **Wrong** ``token_type_hint``: the hint is only an optimization.
  If it does not match the submitted token, the lookup misses, nothing
  is revoked, and the endpoint still answers ``200`` (RFC7009
  Section 2.2.1). An unsupported hint value is rejected with
  ``unsupported_token_type``.
* **Cross-client revocation**: a client can only revoke tokens issued
  to itself. Revoking another client's token fails with
  ``invalid_grant``.
* **Repeated revocation**: revoking an already revoked token is a
  no-op and still returns ``200`` (RFC7009 Section 2.2).
* **Old access tokens**: a resource server presenting a rotated-out or
  revoked access token to introspection gets ``{"active": false,
  "status": "revoked"}``; bearer token validation rejects it as
  usual.
* **No family storage**: applications that never configured
  ``parent_id`` keep using the plain ``RevocationEndpoint``,
  ``RefreshTokenGrant`` and ``IntrospectionEndpoint`` - nothing
  changes for them.

API Reference
-------------

.. autoclass:: TokenFamilyRevocationEndpoint
    :member-order: bysource
    :members:
    :inherited-members:

.. autoclass:: RefreshTokenFamilyGrant
    :member-order: bysource
    :members:
    :inherited-members:

.. autoclass:: TokenFamilyIntrospectionEndpoint
    :member-order: bysource
    :members:
    :inherited-members:
