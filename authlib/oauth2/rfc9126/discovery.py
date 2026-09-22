from authlib.common.security import is_secure_transport

from ..rfc8414.models import validate_boolean_value


class AuthorizationServerMetadata(dict):
    """Authorization Server Metadata extension for RFC9126 (PAR).

    This class can be used with
    :meth:`~authlib.oauth2.rfc8414.AuthorizationServerMetadata.validate`
    to validate PAR-specific metadata::

        from authlib.oauth2 import rfc8414, rfc9126

        metadata = rfc8414.AuthorizationServerMetadata(data)
        metadata.validate(metadata_classes=[rfc9126.AuthorizationServerMetadata])
    """

    REGISTRY_KEYS = [
        "pushed_authorization_request_endpoint",
        "require_pushed_authorization_requests",
    ]

    def validate_pushed_authorization_request_endpoint(self):
        """URL of the authorization server's pushed authorization request
        endpoint. This URL MUST use the "https" scheme.
        """
        url = self.get("pushed_authorization_request_endpoint")
        if url and not is_secure_transport(url):
            raise ValueError(
                '"pushed_authorization_request_endpoint" MUST use "https" scheme'
            )

    def validate_require_pushed_authorization_requests(self):
        """Indicates whether the authorization server accepts authorization
        requests only via PAR.
        """
        validate_boolean_value(self, "require_pushed_authorization_requests")
