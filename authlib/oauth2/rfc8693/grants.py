"""The Token Exchange grant of OAuth 2.0 Token Exchange.

:rfc:`8693`

The grant only accepts and issues access tokens. It does not convert between
arbitrary token formats: the application validates the input tokens through
the dedicated validation interfaces, and an authorization hook makes the
delegation decision.
"""

import logging

from ..rfc6749 import AccessDeniedError
from ..rfc6749 import BaseGrant
from ..rfc6749 import InvalidRequestError
from ..rfc6749 import InvalidScopeError
from ..rfc6749 import JsonResponse
from ..rfc6749 import OAuth2Error
from ..rfc6749 import TokenEndpointMixin
from ..rfc6749 import UnauthorizedClientError
from ..rfc6749 import scope_to_list
from .errors import InvalidTargetError
from .models import DelegationDecision
from .models import TokenInfo

log = logging.getLogger(__name__)

TOKEN_EXCHANGE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"


class TokenExchangeGrant(BaseGrant, TokenEndpointMixin):
    """An implementation of the Token Exchange grant.

    Applications subclass it and implement the validation interfaces and the
    authorization hook, then register the subclass with
    :meth:`~authlib.oauth2.rfc6749.AuthorizationServer.register_grant`.
    """

    GRANT_TYPE = TOKEN_EXCHANGE_GRANT_TYPE

    #: The only token type the grant accepts as input and issues. Overriding
    #: it would turn the grant into an arbitrary token format converter,
    #: which is out of scope.
    SUPPORTED_TOKEN_TYPE = ACCESS_TOKEN_TYPE

    #: Whether an exchange is allowed without an ``actor_token``. Set it to
    #: ``False`` in a subclass when every delegation must name an acting
    #: party. The default keeps the exchange usable for identity-preserving
    #: exchanges without an explicit actor.
    REQUIRE_ACTOR_TOKEN = False

    def validate_token_request(self):
        """Validate the token exchange request described in
        :rfc:`8693#section-2.1`."""
        client = self.authenticate_token_endpoint_client()
        if not client.check_grant_type(self.GRANT_TYPE):
            raise UnauthorizedClientError(
                f"The client is not authorized to use 'grant_type={self.GRANT_TYPE}'"
            )
        self.request.client = client

        form = self.request.form
        subject_token = form.get("subject_token")
        if not subject_token:
            raise InvalidRequestError("Missing 'subject_token' in request.")

        subject_token_type = form.get("subject_token_type")
        if not subject_token_type:
            raise InvalidRequestError("Missing 'subject_token_type' in request.")
        self._validate_token_type(subject_token_type)

        actor_token = form.get("actor_token")
        actor_token_type = form.get("actor_token_type")
        if actor_token and not actor_token_type:
            raise InvalidRequestError("Missing 'actor_token_type' in request.")
        if actor_token_type and not actor_token:
            raise InvalidRequestError("Missing 'actor_token' in request.")
        if actor_token:
            self._validate_token_type(actor_token_type)
        elif self.REQUIRE_ACTOR_TOKEN:
            raise InvalidRequestError("An 'actor_token' is required by this server.")

        subject = self.validate_subject_token(subject_token, subject_token_type)
        if not isinstance(subject, TokenInfo):
            raise InvalidRequestError(
                "'validate_subject_token' must return a TokenInfo instance."
            )
        self.request.subject_token_info = subject

        actor = None
        if actor_token:
            actor = self.validate_actor_token(actor_token, actor_token_type)
            if not isinstance(actor, TokenInfo):
                raise InvalidRequestError(
                    "'validate_actor_token' must return a TokenInfo instance."
                )
        self.request.actor_token_info = actor

        self.validate_requested_scope()

        requested_resources = self._get_repeated("resource")
        requested_audiences = self._get_repeated("audience")
        decision = self.authorize_delegation(
            client=client,
            subject=subject,
            actor=actor,
            requested_scope=self.request.payload.scope,
            requested_resources=requested_resources,
            requested_audiences=requested_audiences,
        )
        if decision is None:
            decision = DelegationDecision()
        if not isinstance(decision, DelegationDecision):
            raise InvalidRequestError(
                "'authorize_delegation' must return a DelegationDecision instance."
            )
        self.request.delegation_decision = decision

        if not decision.allowed:
            raise AccessDeniedError()

        self._validate_decision_scope(subject, decision)
        self._validate_decision_targets(
            decision, requested_resources, requested_audiences
        )

        self.request.exchange_scope = decision.scope or subject.scope
        self.request.exchange_resources = (
            decision.resources
            if decision.resources is not None
            else requested_resources
        )
        self.request.exchange_audiences = requested_audiences
        self.request.act_chain = self.build_act_chain(subject, actor)
        self.request.user = decision.user or self.resolve_user(subject)

    def create_token_response(self):
        """Issue the exchanged access token per :rfc:`8693#section-2.2.1`."""
        token = self.generate_token(
            scope=self.request.exchange_scope,
            user=self.request.user,
            include_refresh_token=False,
        )
        # The exchange metadata stays in the token dict so the storage
        # backend can persist it, and a custom token generator can read it.
        token["issued_token_type"] = self.SUPPORTED_TOKEN_TYPE
        if self.request.exchange_resources:
            token["resource"] = self.request.exchange_resources
        if self.request.exchange_audiences:
            token["audience"] = self.request.exchange_audiences
        if self.request.act_chain:
            token["act"] = self.request.act_chain

        log.debug("Issue token %r to %r", token, self.request.client)
        try:
            self.save_token(token)
        except OAuth2Error:
            raise
        except Exception as error:
            log.exception("Could not save the exchanged token")
            raise InvalidRequestError(
                "The exchanged token could not be stored."
            ) from error

        return JsonResponse(token, headers=self.TOKEN_RESPONSE_HEADER)

    def _validate_token_type(self, token_type):
        if token_type != self.SUPPORTED_TOKEN_TYPE:
            raise InvalidRequestError(
                "Only access tokens are supported in token exchanges."
            )

    def _validate_decision_scope(self, subject, decision):
        if not decision.scope:
            return
        granted = set(scope_to_list(subject.scope) or [])
        requested = set(scope_to_list(decision.scope) or [])
        if not requested.issubset(granted):
            raise InvalidScopeError(
                "The requested scope exceeds the scope of the subject token."
            )

    def _validate_decision_targets(
        self, decision, requested_resources, requested_audiences
    ):
        allowed_resources = self.get_allowed_resources()
        if allowed_resources is not None:
            candidates = set(decision.resources or requested_resources or [])
            unknown = candidates - set(allowed_resources)
            if unknown:
                raise InvalidTargetError(
                    "The requested resource is not authorized for this exchange."
                )

        allowed_audiences = self.get_allowed_audiences()
        if allowed_audiences is not None:
            unknown = set(requested_audiences) - set(allowed_audiences)
            if unknown:
                raise InvalidTargetError(
                    "The requested audience is not authorized for this exchange."
                )

    def _get_repeated(self, name):
        values = self.request.payload.datalist.get(name, [])
        return [value for value in values if value]

    def build_act_chain(self, subject, actor):
        """Build the ``act`` claim of the issued token.

        The current actor is the outermost entry. Any delegation chain that
        came with the subject token is nested inside it, so the historical
        chain is informational only: it can never add permissions to the
        current call.
        """
        historical = subject.act or {}
        if actor is None:
            return dict(historical)

        current = actor.principal.as_actor()
        if historical:
            current["act"] = historical
        return current

    def validate_subject_token(self, token, token_type) -> TokenInfo:
        """Validate the ``subject_token`` and describe it as a
        :class:`~authlib.oauth2.rfc8693.models.TokenInfo`.

        Applications MUST implement this method, for instance by introspecting
        the token or by verifying its signature. Returning ``None`` or raising
        an :class:`~authlib.oauth2.rfc6749.errors.InvalidGrantError` rejects
        the token. The grant never parses the token itself.

        :param token: the raw ``subject_token`` string.
        :param token_type: the ``subject_token_type`` parameter.
        :return: a :class:`TokenInfo` describing the validated token.
        """
        raise NotImplementedError()

    def validate_actor_token(self, token, token_type) -> TokenInfo:
        """Validate the optional ``actor_token``.

        Applications MUST implement this method when they accept actor
        tokens. It follows the same contract as
        :meth:`validate_subject_token`. The actor token authenticates the
        acting party; it never widens the scope of the exchange.
        """
        raise NotImplementedError()

    def authorize_delegation(
        self,
        client,
        subject: TokenInfo,
        actor: TokenInfo | None,
        requested_scope: str | None,
        requested_resources: list[str],
        requested_audiences: list[str],
    ) -> DelegationDecision:
        """Decide whether the delegation is allowed.

        Applications MUST implement this method to return a
        :class:`~authlib.oauth2.rfc8693.models.DelegationDecision`. It is the
        single authorization point: it checks the client, the subject and the
        current actor, and it narrows the scope and the resources. Returning
        ``DelegationDecision(allowed=False)`` rejects the exchange.
        """
        raise NotImplementedError()

    def resolve_user(self, subject: TokenInfo):
        """Resolve the user preserved on the issued token from the validated
        subject token. Applications MAY override it, for instance to load a
        user model from a database. It defaults to the subject's
        :class:`~authlib.oauth2.rfc8693.models.Principal`."""
        return subject.principal

    def get_allowed_resources(self):
        """Return the resources that may be targeted by an exchange, as a
        list, or ``None`` to not enforce a resource allow-list. Applications
        MAY override it."""
        return None

    def get_allowed_audiences(self):
        """Return the audiences that may be requested, as a list, or ``None``
        to not enforce an audience allow-list. Applications MAY override
        it."""
        return None
