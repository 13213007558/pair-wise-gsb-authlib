"""authlib.oauth2.rfc8707.models.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This module defines how to construct AuthorizationCode and Token
objects that store the resource indicators defined by RFC 8707.
"""

from ..rfc6749.models import AuthorizationCodeMixin as _AuthorizationCodeMixin
from ..rfc6749.models import TokenMixin as _TokenMixin


class AuthorizationCodeMixin(_AuthorizationCodeMixin):
    def get_resources(self):
        """A method to get the list of resource indicators consented by the
        resource owner during the authorization request. For instance, the
        resources are saved in a column called resource as a
        space-separated string::

            def get_resources(self):
                return self.resource.split() if self.resource else []

        :return: list of resource indicator strings
        """
        raise NotImplementedError()


class TokenMixin(_TokenMixin):
    def get_resources(self):
        """A method to get the list of resource indicators this token was
        issued for. For instance, the resources are saved in a column called
        resource as a space-separated string::

            def get_resources(self):
                return self.resource.split() if self.resource else []

        :return: list of resource indicator strings
        """
        raise NotImplementedError()
