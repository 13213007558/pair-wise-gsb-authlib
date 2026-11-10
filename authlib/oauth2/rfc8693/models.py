"""Data models for OAuth 2.0 Token Exchange.

They describe a token that has been validated by an
:class:`~authlib.oauth2.rfc8693.TokenExchangeGrant`. The grant never inspects
the format of the input token itself: it delegates that to the validation
interface implemented by the application.
"""

from dataclasses import dataclass
from dataclasses import field


@dataclass
class TokenInfo:
    """The result of validating a ``subject_token`` or an ``actor_token``.

    A validator returns one of these for every token it accepts. The grant
    only consumes access tokens: the application is responsible for parsing
    and verifying the concrete token format (opaque string, JWT, ...).

    :param subject: the identity of the token's principal, as a string. For a
        subject token it is the user, for an actor token it is the acting
        party.
    :param issuer: the issuer of the token, used to distinguish principals
        that share a name across issuers.
    :param scope: the space-separated scope granted by the token.
    :param audience: the audiences the token was issued for, as a list.
    :param token_type: the type of the validated token, for instance
        ``urn:ietf:params:oauth:token-type:access_token``.
    :param client_id: the client the token was issued to, when known.
    :param act: the delegation chain already carried by the token, as the
        nested ``act`` claim of :rfc:`8693#section-4.4`, or ``None``.
    :param extra: additional claims the authorization hook may read. They are
        never trusted as permissions on their own.
    """

    subject: str
    issuer: str | None = None
    scope: str | None = None
    audience: list[str] = field(default_factory=list)
    token_type: str | None = None
    client_id: str | None = None
    act: dict | None = None
    extra: dict = field(default_factory=dict)

    @property
    def principal(self):
        """The issuer-qualified identity of the token's principal."""
        return Principal(self.subject, self.issuer)


@dataclass(frozen=True)
class Principal:
    """A principal identified by its name within an issuer.

    The same subject name at two issuers is not the same principal, so the
    issuer is part of the identity.
    """

    subject: str
    issuer: str | None = None

    def as_actor(self):
        """Return the claim that represents this principal in an ``act``
        chain: ``{"sub": ..., "iss": ...}`` without the ``iss`` key when the
        issuer is unknown."""
        actor = {"sub": self.subject}
        if self.issuer is not None:
            actor["iss"] = self.issuer
        return actor


@dataclass
class DelegationDecision:
    """The authorization decision returned by the authorization hook.

    The hook decides whether delegation is allowed, for which resources and
    with which scope. A ``False`` :attr:`allowed` value rejects the exchange
    with ``access_denied`` without issuing a token.

    :param allowed: whether the exchange may happen.
    :param scope: the scope of the issued token, as a space-separated string.
        It must not exceed the scope of the subject token.
    :param resources: the resources the issued token may target, as a list of
        URIs. ``None`` means that the requested resources are accepted as
        given.
    :param user: the user principal preserved on the issued token. Defaults
        to the subject of the subject token.
    """

    allowed: bool = True
    scope: str | None = None
    resources: list[str] | None = None
    user: object = None
