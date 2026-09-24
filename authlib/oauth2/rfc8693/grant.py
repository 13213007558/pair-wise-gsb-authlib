"""authlib.oauth2.rfc8693.grant.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Implementation of OAuth 2.0 Token Exchange grant.

https://www.rfc-editor.org/rfc/rfc8693
"""

from contextvars import ContextVar
from urllib.parse import urlsplit

from ..base import OAuth2Error
from ..rfc6749.errors import InvalidGrantError
from ..rfc6749.errors import InvalidRequestError
from ..rfc6749.errors import InvalidScopeError
from ..rfc6749.errors import UnauthorizedClientError
from ..rfc6749.grants.base import BaseGrant
from ..rfc6749.grants.base import TokenEndpointMixin
from ..rfc6749.util import list_to_scope
from ..rfc6749.util import scope_to_list

#: Token type identifiers defined by RFC 8693 Section 3
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"
REFRESH_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:refresh_token"
ID_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:id_token"
SAML1_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:saml1"
SAML2_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:saml2"
JWT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt"

#: The exchange context of the token currently being issued. Token
#: generators MAY read it to embed the delegation chain (act), the
#: target resources (aud) and the narrowed scope into the issued
#: token. It is only set while the grant generates a token.
current_token_exchange_context = ContextVar(
    "current_token_exchange_context", default=None
)


class InvalidTargetError(OAuth2Error):
    """The requested target (resource or audience) is invalid, unknown,
    or exceeds the target set of the subject token.

    https://www.rfc-editor.org/rfc/rfc8693#section-2.2.1
    """

    error = "invalid_target"


class TokenExchangeContext:
    """The validated delegation context of a token exchange request.

    :param subject: identifier of the subject of the subject token.
    :param actors: ordered list of actor identifiers, from the first
        delegator to the most recent one. Guaranteed to be acyclic and
        to not contain the subject.
    :param resources: list of target resources (absolute URIs or logical
        names) the issued token is scoped to.
    :param scope: the granted scope, always the intersection of the
        subject token scope and the server allowed scope.
    :param requested_token_type: the token type that will be issued.
    """

    def __init__(self, subject, actors, resources, scope, requested_token_type):
        self.subject = subject
        self.actors = actors
        self.resources = resources
        self.scope = scope
        self.requested_token_type = requested_token_type

    def get_act_claim(self):
        """Build the nested act claim defined by RFC 8693 Section 4.1.
        The outermost act object represents the most recent actor.
        """
        claim = None
        for actor in self.actors:
            if claim is None:
                claim = {"sub": actor}
            else:
                claim = {"sub": actor, "act": claim}
        return claim

    @staticmethod
    def parse_act_claim(claims):
        """Flatten a nested act claim into an ordered actor list, from
        the first delegator to the most recent actor.
        """
        actors = []
        act = claims.get("act")
        while isinstance(act, dict):
            sub = act.get("sub")
            if not sub:
                break
            actors.append(sub)
            act = act.get("act")
        actors.reverse()
        return actors


class TokenExchangeGrant(BaseGrant, TokenEndpointMixin):
    """OAuth 2.0 Token Exchange grant, defined by RFC 8693. A client
    exchanges a subject token (e.g. a front-end user token) for a new
    token, optionally acting on behalf of the subject through an actor
    token, narrowed to given resources and scopes.

    Developers MUST implement ``validate_subject_token`` and SHOULD
    implement ``validate_actor_token`` if delegation is supported::

        class TokenExchangeGrant(grants.TokenExchangeGrant):
            SUBJECT_TOKEN_AUDIENCE = "https://as.example.com"
            KNOWN_RESOURCES = ["https://reports.example.com"]

            def validate_subject_token(self, subject_token, subject_token_type):
                # verify signature, expiry, ... and return its claims
                return decode_and_verify(subject_token)

            def resolve_subject_user(self, subject_claims):
                return User.query.get(subject_claims["sub"])


        authorization_server.register_grant(TokenExchangeGrant)

    https://www.rfc-editor.org/rfc/rfc8693
    """

    GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange"
    TOKEN_ENDPOINT_AUTH_METHODS = ["client_secret_basic", "client_secret_post"]

    #: Token types this server accepts as subject_token_type
    SUPPORTED_SUBJECT_TOKEN_TYPES = {ACCESS_TOKEN_TYPE, JWT_TOKEN_TYPE}
    #: Token types this server accepts as actor_token_type
    SUPPORTED_ACTOR_TOKEN_TYPES = {ACCESS_TOKEN_TYPE, JWT_TOKEN_TYPE}
    #: Token types this server can issue via requested_token_type.
    #: An unsupported requested_token_type yields an invalid_request
    #: error; the grant never falls back to another grant type.
    SUPPORTED_REQUESTED_TOKEN_TYPES = {ACCESS_TOKEN_TYPE, JWT_TOKEN_TYPE}

    #: Audience value marking a subject token as directly addressed to
    #: this authorization server (e.g. the token endpoint URL or the
    #: issuer identifier). Such tokens carry no resource restriction.
    SUBJECT_TOKEN_AUDIENCE = None

    #: Resources this authorization server may issue tokens for. An
    #: empty list means no server-side resource restriction.
    KNOWN_RESOURCES = []

    def __init__(self, request, server):
        super().__init__(request, server)
        self.token_exchange_context = None

    def validate_token_request(self):
        """Validate the token exchange request per RFC 8693 Section 2.1."""
        client = self.authenticate_token_endpoint_client()
        if not client.check_grant_type(self.GRANT_TYPE):
            raise UnauthorizedClientError(
                f"The client is not authorized to use 'grant_type={self.GRANT_TYPE}'"
            )
        self.request.client = client

        payload = self.request.payload
        data = payload.data
        datalist = payload.datalist

        requested_token_type = data.get("requested_token_type")
        if (
            requested_token_type
            and requested_token_type not in self.SUPPORTED_REQUESTED_TOKEN_TYPES
        ):
            raise InvalidRequestError(
                f"The requested token type '{requested_token_type}' is not supported."
            )

        subject_token = data.get("subject_token")
        if not subject_token:
            raise InvalidRequestError("Missing 'subject_token' in request.")

        subject_token_type = data.get("subject_token_type")
        if not subject_token_type:
            raise InvalidRequestError("Missing 'subject_token_type' in request.")
        if subject_token_type not in self.SUPPORTED_SUBJECT_TOKEN_TYPES:
            raise InvalidRequestError(
                f"The subject token type '{subject_token_type}' is not supported."
            )

        subject_claims = self.validate_subject_token(subject_token, subject_token_type)
        if not subject_claims or not subject_claims.get("sub"):
            raise InvalidGrantError("The subject token is invalid.")

        # the subject token must be addressed to this authorization
        # server, or be a token previously scoped to known resources
        subject_resources = self.validate_subject_token_audience(subject_claims)

        subject = subject_claims["sub"]
        actors = self.validate_actor_chain(subject, subject_claims, data)

        resources = self.validate_resources(client, datalist, subject_resources)
        scope = self.validate_scope(subject_claims, data.get("scope"))

        self.request.user = self.resolve_subject_user(subject_claims)
        self.token_exchange_context = TokenExchangeContext(
            subject=subject,
            actors=actors,
            resources=resources,
            scope=scope,
            requested_token_type=requested_token_type or ACCESS_TOKEN_TYPE,
        )
        # expose the context to save_token and token generators
        self.request.token_exchange_context = self.token_exchange_context

    def create_token_response(self):
        """Issue the exchanged token. The response contains the
        issued_token_type parameter defined by RFC 8693 Section 2.2.1.
        """
        ctx = self.token_exchange_context
        token_var = current_token_exchange_context.set(ctx)
        try:
            token = self.generate_token(
                user=self.request.user,
                scope=ctx.scope,
                include_refresh_token=False,
            )
        finally:
            current_token_exchange_context.reset(token_var)
        self.save_token(token)
        # added after save_token so token storages do not need to
        # persist this response-only parameter
        token["issued_token_type"] = ctx.requested_token_type
        return 200, token, self.TOKEN_RESPONSE_HEADER

    def validate_subject_token(self, subject_token, subject_token_type):
        """Validate the subject token and return its claims as a dict
        containing at least sub, and optionally scope, aud and act.
        Developers MUST implement this method, and MUST verify the
        authenticity and validity of the token (signature, expiry,
        revocation, ...). Returning None or raising InvalidGrantError
        rejects the exchange.
        """
        raise NotImplementedError()

    def validate_actor_token(self, actor_token, actor_token_type, subject_claims):
        """Validate the actor token and return its claims as a dict
        containing at least sub. The actor identity is ONLY taken from
        the validated actor token, never from plain request parameters,
        so a subject cannot forge an actor. Developers MUST implement
        this method to support delegation.
        """
        raise NotImplementedError()

    def resolve_subject_user(self, subject_claims):
        """Resolve the subject of the exchange into a user object. The
        returned user is stored on the request and passed to the token
        generator. Developers MAY re-implement this method.
        """
        return None

    def get_known_resources(self):
        """Resources this authorization server may issue tokens for."""
        return list(self.KNOWN_RESOURCES)

    def validate_subject_token_audience(self, subject_claims):
        """Validate the audience of the subject token. Returns None if
        the token is directly addressed to this authorization server (no
        resource restriction), otherwise the list of resources the
        subject token is restricted to.
        """
        aud = subject_claims.get("aud")
        if not aud:
            raise InvalidGrantError("The subject token has no audience.")
        aud_list = [aud] if isinstance(aud, str) else list(aud)
        if self.SUBJECT_TOKEN_AUDIENCE and self.SUBJECT_TOKEN_AUDIENCE in aud_list:
            return None
        known = set(self.get_known_resources())
        if known and set(aud_list) <= known:
            return aud_list
        raise InvalidGrantError(
            "The subject token audience is not accepted by this server."
        )

    def validate_actor_chain(self, subject, subject_claims, data):
        """Build the ordered, acyclic actor chain. The chain carried by
        the subject token is preserved and the validated actor (if any)
        is appended. A subject can never appear in its own actor chain,
        and an actor can never appear twice.
        """
        actors = TokenExchangeContext.parse_act_claim(subject_claims)
        if len(set(actors)) != len(actors) or subject in actors:
            raise InvalidGrantError("The subject token contains a cyclic actor chain.")

        actor_token = data.get("actor_token")
        if not actor_token:
            return actors

        actor_token_type = data.get("actor_token_type")
        if not actor_token_type:
            raise InvalidRequestError("Missing 'actor_token_type' in request.")
        if actor_token_type not in self.SUPPORTED_ACTOR_TOKEN_TYPES:
            raise InvalidRequestError(
                f"The actor token type '{actor_token_type}' is not supported."
            )

        actor_claims = self.validate_actor_token(
            actor_token, actor_token_type, subject_claims
        )
        if not actor_claims or not actor_claims.get("sub"):
            raise InvalidGrantError("The actor token is invalid.")

        actor = actor_claims["sub"]
        if actor == subject or actor in actors:
            raise InvalidGrantError(
                "The actor would create a cycle in the delegation chain."
            )
        return actors + [actor]

    def validate_resources(self, client, datalist, subject_resources):
        """Validate the requested resource and audience parameters.
        Resources must be absolute URIs without fragment. The requested
        targets can never exceed the targets of the subject token, nor
        the resources known to this server.
        """
        resources = list(datalist.get("resource", []))
        audiences = list(datalist.get("audience", []))
        for uri in resources:
            if not _is_absolute_uri(uri):
                raise InvalidTargetError(
                    f"The resource '{uri}' is not an absolute URI."
                )

        requested = resources + audiences
        permitted = self.get_permitted_resources(client, subject_resources)
        if permitted is not None and not set(requested) <= set(permitted):
            raise InvalidTargetError(
                "The requested target exceeds the allowed resources."
            )
        if requested:
            return requested
        if permitted is not None:
            return list(permitted)
        return []

    def get_permitted_resources(self, client, subject_resources):
        """Compute the resources the exchanged token may target: the
        intersection of the server known resources and the resources of
        the subject token. None means no restriction.
        """
        known = self.get_known_resources()
        permitted = set(known) if known else None
        if subject_resources is not None:
            if permitted is None:
                permitted = set(subject_resources)
            else:
                permitted &= set(subject_resources)
        return permitted

    def validate_scope(self, subject_claims, requested_scope):
        """Compute the granted scope: the intersection of the subject
        token scope and the server allowed scope. A requested scope can
        only narrow this intersection further, never widen it.
        """
        subject_scope = set(scope_to_list(subject_claims.get("scope") or ""))
        allowed = subject_scope
        if self.server.scopes_supported:
            allowed = subject_scope & set(self.server.scopes_supported)

        if requested_scope:
            requested = set(scope_to_list(requested_scope))
            if not requested <= allowed:
                raise InvalidScopeError(
                    "The requested scope exceeds the scope of the subject token."
                )
            granted = requested
        else:
            granted = allowed

        if not granted:
            raise InvalidScopeError(
                "The intersection of the subject token scope and the allowed"
                " scope is empty."
            )
        return list_to_scope(sorted(granted))


def _is_absolute_uri(uri):
    try:
        parts = urlsplit(uri)
    except ValueError:
        return False
    return bool(parts.scheme) and not parts.fragment
