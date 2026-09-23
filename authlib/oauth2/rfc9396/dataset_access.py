from .errors import InvalidAuthorizationDetailsError
from .handlers import AuthorizationDetailsHandler

__all__ = ["DatasetAccessHandler"]


class DatasetAccessHandler(AuthorizationDetailsHandler):
    """Demonstration handler for a ``dataset_access`` authorization
    details type. A detail entry looks like::

        {
            "type": "dataset_access",
            "locations": ["https://datasets.example.com/weather"],
            "actions": ["read", "export"],
        }

    ``locations`` lists the datasets the client may access, ``actions``
    what it may do with them (``read`` and/or ``export``). Both sets can
    only be narrowed down, by user consent and by subsequent requests.
    """

    type = "dataset_access"

    #: Actions supported by this demonstration type
    ACTIONS_SUPPORTED = ("read", "export")

    def validate(self, detail):
        locations = detail.get("locations")
        if (
            not isinstance(locations, list)
            or not locations
            or not all(isinstance(item, str) for item in locations)
        ):
            raise InvalidAuthorizationDetailsError(
                "'dataset_access' requires a non-empty 'locations' array of strings."
            )
        actions = detail.get("actions")
        if (
            not isinstance(actions, list)
            or not actions
            or not all(isinstance(item, str) for item in actions)
        ):
            raise InvalidAuthorizationDetailsError(
                "'dataset_access' requires a non-empty 'actions' array of strings."
            )
        unsupported = [
            action for action in actions if action not in self.ACTIONS_SUPPORTED
        ]
        if unsupported:
            raise InvalidAuthorizationDetailsError(
                f"Unsupported 'dataset_access' actions: {unsupported}."
            )

    def is_narrower(self, requested, consented):
        return self._is_subset(consented, requested)

    def is_within(self, granted, requested):
        return self._is_subset(requested, granted)

    @staticmethod
    def _is_subset(inner, outer):
        locations = set(inner.get("locations") or [])
        actions = set(inner.get("actions") or [])
        return locations.issubset(outer.get("locations") or []) and actions.issubset(
            outer.get("actions") or []
        )
