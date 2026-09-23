__all__ = ["AuthorizationDetailsHandler"]


class AuthorizationDetailsHandler:
    """Base class for RFC 9396 authorization details type handlers.

    A handler knows everything about one authorization details ``type``:
    how to validate entries of this type, whether a consent result only
    narrows the original request, and whether a subsequent request (e.g.
    a refresh token request) stays within what was granted. The framework
    only deals with the JSON array and the ``type`` field; every
    type-specific permission rule lives in a handler subclass.
    """

    #: The authorization details "type" this handler is registered for
    type = None

    def validate(self, detail):
        """Validate a single authorization detail object of this type.

        :param detail: one entry of the ``authorization_details`` array.
        :raises InvalidAuthorizationDetailsError: if the entry is invalid.
        """
        raise NotImplementedError()

    def is_narrower(self, requested, consented):
        """Check if the ``consented`` detail only narrows the ``requested``
        one. Used to verify the authorization decision of the resource
        owner before the consented version is saved.

        :param requested: the detail entry sent by the client.
        :param consented: the detail entry approved by the resource owner.
        :return: boolean
        """
        raise NotImplementedError()

    def is_within(self, granted, requested):
        """Check if a ``requested`` detail of a subsequent request stays
        within the previously ``granted`` one. Used e.g. when a refresh
        token is exchanged for a new access token.

        :param granted: the detail entry that was granted before.
        :param requested: the detail entry of the subsequent request.
        :return: boolean
        """
        raise NotImplementedError()
