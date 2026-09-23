"""Framework level validation for the ``authorization_details`` parameter.

The framework parses the JSON array, checks that every entry is an object
with a string ``type``, and rejects unknown types. Everything else is
delegated to the registered :class:`AuthorizationDetailsHandler` of the
entry's type.
"""

import copy
import json

from .errors import InvalidAuthorizationDetailsError

__all__ = [
    "parse_authorization_details",
    "validate_consented_details",
    "validate_within_granted",
]


def _invalid_request(description):
    # imported lazily to avoid a circular import with rfc6749 grants
    from ..rfc6749.errors import InvalidRequestError

    return InvalidRequestError(description)


def parse_authorization_details(value, server):
    """Parse and validate the ``authorization_details`` request parameter.

    :param value: the raw parameter value, a JSON encoded array.
    :param server: the authorization server holding the registered handlers.
    :return: a list of validated detail objects, or None.
    """
    if value is None:
        return None
    try:
        details = json.loads(value)
    except (TypeError, ValueError):
        raise _invalid_request(
            "Invalid 'authorization_details': value is not valid JSON."
        ) from None
    if not isinstance(details, list):
        raise _invalid_request(
            "Invalid 'authorization_details': value MUST be a JSON array."
        )
    if not details:
        return None
    return [validate_authorization_detail(detail, server) for detail in details]


def validate_authorization_detail(detail, server):
    """Validate the structure of one detail entry and delegate the
    type-specific validation to its registered handler."""
    if not isinstance(detail, dict):
        raise _invalid_request(
            "Invalid 'authorization_details': entries MUST be JSON objects."
        )
    details_type = detail.get("type")
    if not isinstance(details_type, str):
        raise _invalid_request(
            "Invalid 'authorization_details': 'type' is REQUIRED and MUST be a string."
        )
    handler = server.get_authorization_details_handler(details_type)
    if handler is None:
        raise InvalidAuthorizationDetailsError(
            f"Unknown authorization details type: '{details_type}'."
        )
    handler.validate(detail)
    return detail


def validate_consented_details(requested, consented, server):
    """Validate that the details consented by the resource owner only
    narrow the requested ones.

    :param requested: the parsed details of the authorization request.
    :param consented: the details approved by the resource owner.
    :param server: the authorization server holding the registered handlers.
    :return: a sanitized deep copy of the consented details, or None if
        the consent result is empty.
    """
    if not consented:
        return None
    if not isinstance(consented, list):
        raise _invalid_request(
            "Invalid 'authorization_details': value MUST be a JSON array."
        )
    result = []
    for detail in consented:
        validate_authorization_detail(detail, server)
        handler = server.get_authorization_details_handler(detail["type"])
        if not _is_covered(requested, detail, handler.is_narrower):
            raise InvalidAuthorizationDetailsError(
                "Consented authorization details exceed the requested ones."
            )
        result.append(detail)
    return copy.deepcopy(result)


def validate_within_granted(granted, requested, server):
    """Validate that every requested detail stays within the previously
    granted details, e.g. on a refresh token request.

    :param granted: the details granted with the original authorization.
    :param requested: the parsed details of the subsequent request.
    :param server: the authorization server holding the registered handlers.
    """
    granted = granted or []
    for detail in requested:
        handler = server.get_authorization_details_handler(detail["type"])
        if not _is_covered(granted, detail, handler.is_within):
            raise InvalidAuthorizationDetailsError(
                "Requested authorization details exceed the granted ones."
            )


def _is_covered(candidates, detail, predicate):
    return any(
        candidate.get("type") == detail["type"] and predicate(candidate, detail)
        for candidate in candidates
    )
