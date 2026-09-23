"""authlib.oauth2.token_family.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Optional *token family* semantics on top of the RFC7009_ revocation
endpoint, the RFC6749_ ``refresh_token`` grant and the RFC7662_
introspection endpoint.

A *token family* is the chain of tokens produced by refresh token
rotation: every time a refresh token is exchanged, the newly issued
token records the id of the token it derived from (``parent_id``).
When a refresh token is stolen, the whole family it spawned can be
revoked in one call.

This module is strictly opt-in. Applications that do not store a
``parent_id`` link between tokens keep using the plain
:class:`~authlib.oauth2.rfc7009.RevocationEndpoint`,
:class:`~authlib.oauth2.rfc6749.grants.RefreshTokenGrant` and
:class:`~authlib.oauth2.rfc7662.IntrospectionEndpoint`, which revoke or
rotate single tokens only.

Behavior summary
----------------

* Revoking a refresh token without any extra parameter revokes that
  token **and all of its descendants**. Passing ``family=true`` in the
  revocation request revokes the **whole family** (ancestors, siblings
  and descendants).
* Refresh rotation is atomic: revoking the old credential and inserting
  the new family member happen within one transaction boundary, so two
  concurrent refresh requests on the same token yield at most one new
  family member, and a revoked token can never be resurrected by a
  racing transaction.
* A wrong ``token_type_hint`` simply makes the token lookup miss; the
  endpoint answers ``200`` and revokes nothing (per RFC7009 Section
  2.2.1 the hint is only an optimization).
* A client can only revoke tokens that were issued to itself; attempts
  to revoke another client's token fail with ``invalid_grant``.
* Revoking an already revoked token is a no-op and still returns
  ``200`` (idempotent, per RFC7009 Section 2.2).
* A resource server presenting an old (rotated-out or revoked) access
  token is told the token is inactive; introspection reports
  ``{"active": false, "status": "revoked"}`` (or ``"expired"`` /
  ``"unknown"``) and never leaks family linkage such as ``parent_id``.

.. _RFC7009: https://tools.ietf.org/html/rfc7009
.. _RFC6749: https://tools.ietf.org/html/rfc6749
.. _RFC7662: https://tools.ietf.org/html/rfc7662
"""

import logging

from authlib.consts import default_json_headers

from .rfc6749 import InvalidRequestError
from .rfc6749.grants import RefreshTokenGrant
from .rfc6749.hooks import hooked
from .rfc7009 import RevocationEndpoint
from .rfc7662 import IntrospectionEndpoint

log = logging.getLogger(__name__)

__all__ = [
    "TokenFamilyRevocationEndpoint",
    "RefreshTokenFamilyGrant",
    "TokenFamilyIntrospectionEndpoint",
]


class TokenFamilyRevocationEndpoint(RevocationEndpoint):
    """Revocation endpoint with token-family semantics.

    Compared to the plain :class:`RevocationEndpoint`, revoking a token
    also revokes every token derived from it (its descendants). If the
    revocation request contains a truthy ``family`` parameter, the whole
    family of the token is revoked instead.

    Developers must implement :meth:`query_token`,
    :meth:`revoke_token`, :meth:`query_token_descendants` and
    :meth:`query_token_family`, or use
    ``authlib.integrations.sqla_oauth2.create_token_family_revocation_endpoint``.
    """

    #: Name of the request parameter that switches the endpoint to
    #: whole-family revocation.
    FAMILY_PARAMETER = "family"

    def create_endpoint_response(self, request):
        # The authorization server first validates the client credentials
        client = self.authenticate_endpoint_client(request)

        # then verifies whether the token was issued to the client making
        # the revocation request
        token = self.authenticate_token(request, client)

        # unknown tokens (including hint mismatches) still get a 200
        if token:
            if self.use_family_revocation(request):
                self.revoke_token_family(token, request)
            else:
                self.revoke_token_descendants(token, request)
            self.server.send_signal(
                "after_revoke_token",
                token=token,
                client=client,
            )
        return 200, {}, default_json_headers

    def use_family_revocation(self, request):
        """Whether the request asks for whole-family revocation. The
        ``family`` parameter is considered enabled for the values
        ``1``, ``true`` and ``yes`` (case insensitive)."""
        value = request.form.get(self.FAMILY_PARAMETER)
        return bool(value) and value.lower() in ("1", "true", "yes")

    def revoke_token_descendants(self, token, request):
        """Revoke the given token and every token derived from it. This
        is the default behavior of the endpoint."""
        for item in self.query_token_descendants(token):
            self.revoke_token(item, request)
        self.revoke_token(token, request)

    def revoke_token_family(self, token, request):
        """Revoke the whole family of the given token: the root token,
        and every token directly or indirectly derived from it. Only
        used when the request explicitly enables family revocation."""
        for item in self.query_token_family(token):
            self.revoke_token(item, request)

    def query_token_descendants(self, token):
        """Return all tokens that were directly or indirectly derived
        from the given token (excluding the token itself). Developers
        MUST implement this method::

            def query_token_descendants(self, token):
                descendants = []
                parent_ids = [token.id]
                while parent_ids:
                    children = Token.query.filter(Token.parent_id.in_(parent_ids)).all()
                    descendants.extend(children)
                    parent_ids = [child.id for child in children]
                return descendants

        :param token: the token being revoked
        :return: list of token objects
        """
        raise NotImplementedError()

    def query_token_family(self, token):
        """Return every token in the same family as the given token,
        including the token itself: walk up to the root ancestor, then
        collect the root and all of its descendants. Developers MUST
        implement this method.

        :param token: the token being revoked
        :return: list of token objects
        """
        raise NotImplementedError()


class RefreshTokenFamilyGrant(RefreshTokenGrant):
    """A ``refresh_token`` grant that rotates refresh tokens and links
    every newly issued token to its parent, building a token family.

    Unlike the plain :class:`RefreshTokenGrant`, the old credential is
    revoked and the new token is saved inside one atomic
    :meth:`rotate_token` operation, so that:

    * two concurrent refresh requests on the same refresh token produce
      at most one new family member (the loser gets ``invalid_grant``);
    * a refresh token revoked by the revocation endpoint can not be
      resurrected by a racing refresh transaction.

    This grant always issues a new refresh token
    (``INCLUDE_NEW_REFRESH_TOKEN = True``) so the family chain can grow.
    """

    INCLUDE_NEW_REFRESH_TOKEN = True

    @hooked
    def create_token_response(self):
        refresh_token = self.request.refresh_token
        user = self.authenticate_user(refresh_token)
        if not user:
            raise InvalidRequestError("There is no 'user' for this token.")

        client = self.request.client
        token = self.issue_token(user, refresh_token)
        log.debug("Issue token %r to %r", token, client)

        self.request.user = user
        self.rotate_token(token, refresh_token)
        return 200, token, self.TOKEN_RESPONSE_HEADER

    def rotate_token(self, token, refresh_token):
        """Atomically revoke the old credential and save the new token
        as a child of it. Developers MUST implement this method with
        proper transaction semantics, e.g. a conditional ``UPDATE ...
        WHERE revoked_at = 0`` whose affected-row count is checked
        before inserting the child token in the same transaction. If
        the old token is no longer active, this method MUST raise
        ``InvalidGrantError`` instead of saving the new token.

        :param token: the newly generated token dict
        :param refresh_token: the token object being rotated out
        """
        raise NotImplementedError()


class TokenFamilyIntrospectionEndpoint(IntrospectionEndpoint):
    """Introspection endpoint that distinguishes *unknown*, *revoked*
    and *expired* tokens without leaking family information.

    Inactive responses carry a coarse ``status`` field:

    * ``unknown``: the token does not exist on this server (or the
      client is not allowed to introspect it);
    * ``revoked``: the token was revoked, directly or through a
      descendant/family revocation;
    * ``expired``: the token's lifetime has elapsed.

    Active responses include ``status: active``. Any family linkage
    (``parent_id``, ``family_id``) accidentally returned by
    :meth:`introspect_token` is stripped from the payload.
    """

    #: Value of the ``status`` field for active tokens
    ACTIVE_STATUS = "active"

    #: Family linkage fields that must never be exposed to clients
    PRIVATE_FIELDS = ("parent_id", "family_id")

    def create_introspection_payload(self, token):
        if not token:
            return {"active": False, "status": "unknown"}
        if token.is_revoked():
            return {"active": False, "status": "revoked"}
        if token.is_expired():
            return {"active": False, "status": "expired"}
        payload = self.introspect_token(token)
        if "active" not in payload:
            payload["active"] = True
        payload.setdefault("status", self.ACTIVE_STATUS)
        for key in self.PRIVATE_FIELDS:
            payload.pop(key, None)
        return payload
