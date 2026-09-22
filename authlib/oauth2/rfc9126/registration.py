from joserfc.errors import InvalidClaimError

from authlib.oauth2.claims import BaseClaims


class ClientMetadataClaims(BaseClaims):
    """Additional client metadata can be used with :ref:`specs/rfc7591`
    and :ref:`specs/rfc7592` endpoints.

    This can be used with::

        server.register_endpoint(
            ClientRegistrationEndpoint(
                claims_classes=[
                    rfc7591.ClientMetadataClaims,
                    rfc9126.ClientMetadataClaims,
                ]
            )
        )
    """

    REGISTERED_CLAIMS = [
        "require_pushed_authorization_requests",
    ]

    def validate(self, now=None, leeway=0):
        super().validate(now, leeway)
        self.validate_require_pushed_authorization_requests()

    def validate_require_pushed_authorization_requests(self):
        self.setdefault("require_pushed_authorization_requests", False)

        if not isinstance(self["require_pushed_authorization_requests"], bool):
            raise InvalidClaimError("require_pushed_authorization_requests")
