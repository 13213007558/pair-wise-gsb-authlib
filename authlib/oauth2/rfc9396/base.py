"""Framework level handling of the `authorization_details` parameter.

The framework only understands the JSON envelope: the value MUST be a
JSON array of objects, and every object MUST carry a string `type`
field registered on the server. Everything else -- which fields are
valid, what "narrower" means -- is delegated to the registered
:class:`AuthorizationDetailsHandler` of each type. In particular there
is deliberately NO generic dict-subset comparison here: subset semantics
differ per type and are part of each handler, not of the framework.
"""

import json

from .errors import InvalidAuthorizationDetailsError

__all__ = [
    "AuthorizationDetailsHandler",
    "parse_authorization_details",
    "is_within_granted_details",
]


class AuthorizationDetailsHandler:
    """Base class for authorization details type handlers. Subclasses
    MUST set :attr:`type` and implement :meth:`is_within_granted`;
    they SHOULD implement :meth:`validate`::

        class DatasetAccessHandler(AuthorizationDetailsHandler):
            type = "dataset_access"

            def validate(self, detail):
                ...

            def is_within_granted(self, requested, granted):
                ...
    """

    #: The value of the "type" field this handler is responsible for
    type = None

    def validate(self, detail):
        """Validate a single authorization details object of this type.

        :param detail: one object of the `authorization_details` array.
        :raises InvalidAuthorizationDetailsError: if the object is malformed.
        """
        raise NotImplementedError()

    def is_within_granted(self, requested, granted):
        """Check whether a `requested` object stays within a previously
        `granted` object of the same type. This defines the type-specific
        narrowing rule; it is used when a user consents to less than what
        was requested, and when a refresh token request asks for details
        again.

        :param requested: the candidate (possibly narrowed) object.
        :param granted: the object that was originally granted.
        :return: True if `requested` is covered by `granted`.
        """
        raise NotImplementedError()


def parse_authorization_details(value, handlers):
    """Parse and validate the `authorization_details` request parameter.

    The framework checks the JSON envelope and the `type` fields, then
    delegates each object to its registered type handler.

    :param value: the raw parameter value (a JSON string), or None.
    :param handlers: a dict of registered handlers, keyed by type.
    :return: a list of validated objects, or None if no parameter was given.
    :raises InvalidAuthorizationDetailsError: on any malformed input.
    """
    if value is None:
        return None

    try:
        details = json.loads(value)
    except (TypeError, ValueError):
        raise InvalidAuthorizationDetailsError(
            "The 'authorization_details' parameter is not valid JSON."
        ) from None

    if not isinstance(details, list):
        raise InvalidAuthorizationDetailsError(
            "The 'authorization_details' parameter MUST be a JSON array."
        )

    if not details:
        # an empty array is equivalent to an absent parameter
        return None

    for detail in details:
        if not isinstance(detail, dict):
            raise InvalidAuthorizationDetailsError(
                "Elements of 'authorization_details' MUST be JSON objects."
            )
        type_ = detail.get("type")
        if not isinstance(type_, str) or not type_:
            raise InvalidAuthorizationDetailsError(
                "Elements of 'authorization_details' MUST contain a 'type' field."
            )
        handler = handlers.get(type_)
        if handler is None:
            raise InvalidAuthorizationDetailsError(
                f"The authorization details type '{type_}' is not supported."
            )
        handler.validate(detail)

    return details


def is_within_granted_details(requested, granted, handlers):
    """Check that every object in `requested` is covered by an object of
    the same type in `granted`, using the narrowing rule of the
    registered type handler.

    :param requested: list of candidate authorization details objects.
    :param granted: list of previously granted authorization details objects.
    :param handlers: a dict of registered handlers, keyed by type.
    :return: True if the whole `requested` list stays within `granted`.
    """
    if not requested:
        return True
    if not granted:
        return False

    for req in requested:
        handler = handlers.get(req.get("type"))
        if handler is None:
            return False
        covered = any(
            isinstance(other, dict)
            and other.get("type") == req.get("type")
            and handler.is_within_granted(req, other)
            for other in granted
        )
        if not covered:
            return False
    return True
