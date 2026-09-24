"""authlib.oauth2.rfc8693.claims.
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Helpers to work with the nested ``act`` (actor) claim defined by
OAuth 2.0 Token Exchange. The ``act`` claim represents an ordered
chain of actors that have delegated on behalf of the subject. The
chain MUST stay ordered and MUST NOT contain cycles.

https://tools.ietf.org/html/rfc8693#section-4.1
"""

__all__ = [
    "ActorChainError",
    "parse_actor_chain",
    "build_actor_claim",
    "ensure_acyclic_actor_chain",
]


class ActorChainError(ValueError):
    """The ``act`` claim is malformed or contains a delegation cycle."""


def parse_actor_chain(act) -> list:
    """Parse a nested ``act`` claim into an ordered list of actor
    identifiers. The innermost actor of the claim is the last element
    of the returned list.

    :param act: value of the ``act`` claim, a (possibly nested) dict
    :return: list of actor ``sub`` values
    :raise: ActorChainError
    """
    chain = []
    node = act
    while node is not None:
        if not isinstance(node, dict):
            raise ActorChainError("The act claim must be a JSON object.")
        sub = node.get("sub")
        if not isinstance(sub, str) or not sub:
            raise ActorChainError("Each act claim must contain a sub string.")
        chain.append(sub)
        node = node.get("act")
    return chain


def build_actor_claim(chain) -> dict | None:
    """Build a nested ``act`` claim from an ordered list of actor
    identifiers. The first element becomes the outermost actor.

    :param chain: list of actor ``sub`` values
    :return: nested ``act`` claim, or ``None`` for an empty chain
    """
    claim = None
    for actor in reversed(chain):
        claim = {"sub": actor} if claim is None else {"sub": actor, "act": claim}
    return claim


def ensure_acyclic_actor_chain(chain):
    """Ensure that no actor appears twice in the delegation chain. A
    repeated actor means the delegation chain is circular and MUST be
    rejected.

    :param chain: list of actor ``sub`` values
    :raise: ActorChainError
    """
    seen = set()
    for actor in chain:
        if actor in seen:
            raise ActorChainError(
                "Circular delegation detected: "
                f"actor {actor!r} appears more than once."
            )
        seen.add(actor)
