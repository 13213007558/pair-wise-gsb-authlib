"""authlib.oauth2.rfc9449.grant_extension.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

DPoP proof validation for the token endpoint.

https://www.rfc-editor.org/rfc/rfc9449.html#section-5
"""

from .errors import InvalidDPoPProofError
from .validator import DPoPProofValidator
from .validator import set_current_jkt

__all__ = ["DPoPGrantExtension"]


def get_header_values(headers, name):
    """Return all values of a header, supporting both werkzeug style
    headers and plain dicts."""
    if hasattr(headers, "get_all"):
        return [value for value in headers.get_all(name) if value]
    value = headers.get(name)
    return [value] if value else []


class DPoPGrantExtension:
    """Validate the DPoP proof sent to the token endpoint and bind the
    issued access token to the proof key. Register it together with a
    :class:`DPoPTokenGenerator`::

        server.register_grant(ClientCredentialsGrant, [DPoPGrantExtension()])

    :param proof_validator: a :class:`DPoPProofValidator` instance, used to
        configure the replay store, the proof time window and the nonce
        policy.
    :param required: whether a DPoP proof is required. When ``False``,
        requests without a ``DPoP`` header fall back to the default token
        generator behavior.
    """

    def __init__(self, proof_validator=None, required=True):
        self.proof_validator = proof_validator or DPoPProofValidator()
        self.required = required

    def __call__(self, grant):
        grant.register_hook("before_create_token_response", self.validate_proof)

    def validate_proof(self, grant):
        request = grant.request
        values = get_header_values(request.headers, "DPoP")

        if not values:
            if self.required:
                raise InvalidDPoPProofError("Missing 'DPoP' header.")
            # mark the request as checked so that the token generator
            # issues an unbound Bearer token
            set_current_jkt(False)
            return

        if len(values) > 1:
            raise InvalidDPoPProofError("Multiple 'DPoP' headers in request.")

        proof = self.proof_validator.validate(values[0], request.method, request.uri)
        set_current_jkt(proof.jkt)
