import logging
from urllib.parse import urlparse

from ..rfc6749 import BaseGrant
from ..rfc6749 import TokenEndpointMixin
from ..rfc6749.errors import InvalidGrantError
from ..rfc6749.errors import InvalidRequestError
from ..rfc6749.errors import InvalidScopeError
from ..rfc6749.errors import UnauthorizedClientError
from ..rfc6749.hooks import hooked
from ..rfc6749.util import scope_to_list
from .claims import ActorChainError
from .claims import build_actor_claim
from .claims import ensure_acyclic_actor_chain
from .claims import parse_actor_chain
from .errors import InvalidTargetError

log = logging.getLogger(__name__)

TOKEN_EXCHANGE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange"

#: Token type identifiers defined by RFC 8693 Section 3
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"
REFRESH_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:refresh_token"
ID_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:id_token"
SAML1_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:saml1"
SAML2_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:saml2"
JWT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt"


def _value_list(value):
    if value is None:
        return []
    if isinstance(value, list | tuple):
        return list(value)
    return [value]


class TokenExchangeGrant(BaseGrant, TokenEndpointMixin):
    """OAuth 2.0 Token Exchange grant per `RFC 8693`_. A client presents
    a ``subject_token`` (and optionally an ``actor_token``) to obtain a
    new token that represents the subject, possibly delegated through an
    ordered chain of actors, and scoped to a subset of the original
    authorization.

    Developers MUST subclass this grant and implement
    :meth:`validate_subject_token` (and :meth:`validate_actor_token` when
    actor tokens are supported)::

        class MyTokenExchangeGrant(TokenExchangeGrant):
            def validate_subject_token(self, subject_token, subject_token_type):
                return verify_token(subject_token)

            def validate_actor_token(self, actor_token, actor_token_type):
                return verify_token(actor_token)


        authorization_server.register_grant(MyTokenExchangeGrant)

    .. _`RFC 8693`: https://tools.ietf.org/html/rfc8693
    """

    GRANT_TYPE = TOKEN_EXCHANGE_GRANT_TYPE

    ACCESS_TOKEN_TYPE = ACCESS_TOKEN_TYPE
    REFRESH_TOKEN_TYPE = REFRESH_TOKEN_TYPE
    ID_TOKEN_TYPE = ID_TOKEN_TYPE
    SAML1_TOKEN_TYPE = SAML1_TOKEN_TYPE
    SAML2_TOKEN_TYPE = SAML2_TOKEN_TYPE
    JWT_TOKEN_TYPE = JWT_TOKEN_TYPE

    #: Token type identifiers accepted in ``subject_token_type``
    SUPPORTED_SUBJECT_TOKEN_TYPES = frozenset({ACCESS_TOKEN_TYPE, JWT_TOKEN_TYPE})
    #: Token type identifiers accepted in ``actor_token_type``
    SUPPORTED_ACTOR_TOKEN_TYPES = frozenset({ACCESS_TOKEN_TYPE, JWT_TOKEN_TYPE})
    #: Token type identifiers this server can issue. A request carrying an
    #: unsupported ``requested_token_type`` is rejected with an OAuth error,
    #: it never falls back to another grant behavior.
    SUPPORTED_REQUESTED_TOKEN_TYPES = frozenset({ACCESS_TOKEN_TYPE})

    def validate_token_request(self):
        """Validate a token exchange request per `RFC 8693 Section 2.1`_.

        .. _`RFC 8693 Section 2.1`: https://tools.ietf.org/html/rfc8693#section-2.1
        """
        client = self.authenticate_token_endpoint_client()
        log.debug("Validate token exchange request of %r", client)

        if not client.check_grant_type(self.GRANT_TYPE):
            raise UnauthorizedClientError(
                f"The client is not authorized to use 'grant_type={self.GRANT_TYPE}'"
            )
        self.request.client = client

        payload = self.request.payload
        data = payload.data

        requested_token_type = data.get("requested_token_type")
        if requested_token_type is None:
            requested_token_type = self.ACCESS_TOKEN_TYPE
        elif requested_token_type not in self.SUPPORTED_REQUESTED_TOKEN_TYPES:
            raise InvalidRequestError(
                "The 'requested_token_type' is not supported by this server."
            )

        subject_token = data.get("subject_token")
        if not subject_token:
            raise InvalidRequestError("Missing 'subject_token' in request.")
        subject_token_type = data.get("subject_token_type")
        if not subject_token_type:
            raise InvalidRequestError("Missing 'subject_token_type' in request.")
        if subject_token_type not in self.SUPPORTED_SUBJECT_TOKEN_TYPES:
            raise InvalidRequestError(
                "The 'subject_token_type' is not supported by this server."
            )

        subject_claims = self.validate_subject_token(subject_token, subject_token_type)
        if not subject_claims:
            raise InvalidGrantError("The 'subject_token' is invalid.")
        subject_claims = dict(subject_claims)
        subject = subject_claims.get("sub")
        if not subject:
            raise InvalidGrantError("Missing 'sub' claim in 'subject_token'.")
        self.validate_subject_token_audience(subject_claims)
        subject_chain = self._extract_actor_chain(subject_claims, "subject_token")

        actor_token = data.get("actor_token")
        actor_token_type = data.get("actor_token_type")
        if actor_token:
            if not actor_token_type:
                raise InvalidRequestError("Missing 'actor_token_type' in request.")
            if actor_token_type not in self.SUPPORTED_ACTOR_TOKEN_TYPES:
                raise InvalidRequestError(
                    "The 'actor_token_type' is not supported by this server."
                )
            actor_claims = self.validate_actor_token(actor_token, actor_token_type)
            if not actor_claims:
                raise InvalidGrantError("The 'actor_token' is invalid.")
            actor = dict(actor_claims).get("sub")
            if not actor:
                raise InvalidGrantError("Missing 'sub' claim in 'actor_token'.")
            self._extract_actor_chain(actor_claims, "actor_token")
        else:
            if actor_token_type:
                raise InvalidRequestError("Missing 'actor_token' in request.")
            # The actor identity always comes from the authenticated client
            # or a validated actor token, never from plain request parameters.
            actor = client.get_client_id()

        actor_chain = [actor, *subject_chain]
        try:
            ensure_acyclic_actor_chain(actor_chain)
        except ActorChainError as error:
            raise InvalidGrantError(str(error)) from error

        resources = self._resolve_resources(payload, subject_claims)
        scope = self._resolve_scope(payload, subject_claims)

        self.request.user = self.authenticate_user(subject)
        self.token_exchange_context = {
            "subject": subject,
            "subject_claims": subject_claims,
            "actor": actor,
            "actor_chain": actor_chain,
            "resources": resources,
            "scope": scope,
            "requested_token_type": requested_token_type,
        }

    @hooked
    def create_token_response(self):
        """Issue the exchanged token. The response contains the
        ``issued_token_type`` parameter per `RFC 8693 Section 2.2.1`_,
        together with the delegation context (``act`` and ``aud``) so
        that downstream resource servers can verify the subject, actor,
        audience and scope correspondence.

        .. _`RFC 8693 Section 2.2.1`: https://tools.ietf.org/html/rfc8693#section-2.2.1
        """
        context = self.token_exchange_context
        token = self.generate_token(
            user=self.request.user,
            scope=context["scope"],
            include_refresh_token=False,
        )
        token["issued_token_type"] = context["requested_token_type"]
        act = build_actor_claim(context["actor_chain"])
        if act:
            token["act"] = act
        if context["resources"]:
            token["aud"] = context["resources"]
        log.debug("Issue exchanged token %r to %r", token, self.request.client)
        self.save_token(token)
        return 200, token, self.TOKEN_RESPONSE_HEADER

    def validate_subject_token(self, subject_token, subject_token_type):
        """Validate the ``subject_token`` and return its claims as a dict.
        The claims MUST contain a ``sub`` value and MAY contain ``scope``,
        ``aud`` and ``act`` values. Developers MUST implement this method,
        e.g.::

            def validate_subject_token(self, subject_token, subject_token_type):
                return verify_access_token(subject_token)

        :return: claims dict, or ``None`` when the token is invalid. In the
            latter case an ``invalid_grant`` error is returned.
        """
        raise NotImplementedError()

    def validate_actor_token(self, actor_token, actor_token_type):
        """Validate the ``actor_token`` and return its claims as a dict.
        Developers MUST implement this method when actor tokens (composite
        delegation) are supported.

        :return: claims dict, or ``None`` when the token is invalid. In the
            latter case an ``invalid_grant`` error is returned.
        """
        raise NotImplementedError()

    def authenticate_user(self, subject):
        """Resolve the subject of the exchange into a user. Developers MAY
        implement this method, e.g.::

            def authenticate_user(self, subject):
                return User.get_by_sub(subject)

        :return: User instance or ``None``
        """
        return None

    def get_audiences(self):
        """Return the identifiers of this authorization server. They are
        used to validate the audience of the subject token, and are
        excluded from the resource constraint when a previously issued
        token is exchanged again. Developers SHOULD implement this method::

            def get_audiences(self):
                return ["https://as.example.com"]

        :return: list of audience identifier strings
        """
        return []

    def get_permitted_resources(self):
        """Return the resource identifiers this server is allowed to issue
        tokens for. An empty list means there is no server side restriction.
        The effective audience of the issued token is the intersection of
        the requested ``resource`` values, this list, and the resources the
        subject token was issued for.

        :return: list of absolute URI strings
        """
        return []

    def get_permitted_scopes(self):
        """Return the scopes this server is allowed to delegate. Defaults
        to the ``scopes_supported`` of the authorization server. The scope
        of the issued token is the intersection of the subject token scope
        and this list.

        :return: list of scope strings
        """
        return self.server.scopes_supported

    def validate_subject_token_audience(self, claims):
        """Validate the audience of the subject token. The token must be
        addressed to this authorization server or to a resource this
        server is permitted to delegate to.
        """
        audiences = _value_list(claims.get("aud"))
        if not audiences:
            return
        accepted = set(self.get_audiences()) | set(self.get_permitted_resources())
        if accepted and not accepted.intersection(audiences):
            raise InvalidGrantError(
                "The 'subject_token' audience is not accepted by this server."
            )

    def _extract_actor_chain(self, claims, param):
        try:
            chain = parse_actor_chain(claims.get("act"))
            ensure_acyclic_actor_chain(chain)
        except ActorChainError as error:
            raise InvalidGrantError(
                f"The {param!r} contains an invalid actor chain: {error}"
            ) from error
        return chain

    def _resolve_resources(self, payload, subject_claims):
        requested = payload.datalist.get("resource", [])
        for uri in requested:
            parts = urlparse(uri)
            if not parts.scheme or not parts.hostname:
                raise InvalidTargetError(
                    f"The resource {uri!r} is not an absolute URI."
                )

        permitted = list(self.get_permitted_resources() or [])
        # resources the subject token was issued for, excluding this
        # authorization server itself
        own_identifiers = set(self.get_audiences())
        subject_resources = [
            value
            for value in _value_list(subject_claims.get("aud"))
            if value not in own_identifiers
        ]

        allowed = None
        if permitted:
            allowed = set(permitted)
        if subject_resources:
            # re-exchange of a delegated token can only narrow the audience
            if allowed is None:
                allowed = set(subject_resources)
            else:
                allowed = allowed.intersection(subject_resources)

        if requested:
            resources = []
            for uri in requested:
                if allowed is not None and uri not in allowed:
                    raise InvalidTargetError(
                        f"The resource {uri!r} is not allowed for this exchange."
                    )
                if uri not in resources:
                    resources.append(uri)
            return resources

        if allowed is None:
            return []
        ordered = permitted if permitted else subject_resources
        return [uri for uri in ordered if uri in allowed]

    def _resolve_scope(self, payload, subject_claims):
        subject_scope = set(scope_to_list(subject_claims.get("scope")) or [])
        permitted_scope = set(self.get_permitted_scopes() or [])

        allowed = None
        if subject_scope:
            allowed = set(subject_scope)
        if permitted_scope:
            if allowed is None:
                allowed = set(permitted_scope)
            else:
                allowed = allowed.intersection(permitted_scope)

        requested = set(scope_to_list(payload.scope) or [])
        if requested:
            if allowed is not None and not requested.issubset(allowed):
                raise InvalidScopeError(
                    "The requested 'scope' exceeds the delegated scope."
                )
            scope = requested
        elif allowed is None:
            return None
        else:
            scope = allowed

        if not scope:
            raise InvalidScopeError(
                "The token exchange results in an empty scope intersection."
            )
        return " ".join(sorted(scope))
