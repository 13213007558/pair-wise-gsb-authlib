import time

from joserfc import jwe
from joserfc import jws
from joserfc import jwt
from joserfc.errors import UnsupportedKeyAlgorithmError
from joserfc.errors import UnsupportedKeyUseError
from joserfc.jwk import KeySet
from joserfc.jws import JWSRegistry

from authlib._joserfc_helpers import import_any_key
from authlib.common.encoding import json_dumps
from authlib.consts import default_json_headers
from authlib.oauth2.rfc6749.authorization_server import AuthorizationServer
from authlib.oauth2.rfc6749.authorization_server import OAuth2Request
from authlib.oauth2.rfc6749.resource_protector import ResourceProtector

from .claims import UserInfo
from .errors import IssuerMismatchError
from .errors import MissingClientPublicKeyError
from .errors import MissingSigningKeyError
from .errors import UnsupportedUserInfoResponseAlgError

__all__ = ["UserInfoEndpoint", "filter_userinfo_claims"]

#: JWT claims that may appear in a JWT UserInfo response, alongside the
#: standard UserInfo claims.
USERINFO_JWT_CLAIMS = ("iss", "aud", "iat", "exp")


def filter_userinfo_claims(claims) -> UserInfo:
    """Keep only the claims allowed in a JWT UserInfo response.

    The result only contains standard UserInfo claims and the JWT claims
    listed in ``USERINFO_JWT_CLAIMS``, sorted by name so that the JSON
    serialization is stable and does not depend on the insertion order of
    the source mapping.
    """
    allowed = set(UserInfo.REGISTERED_CLAIMS) | set(USERINFO_JWT_CLAIMS)
    return UserInfo((name, claims[name]) for name in sorted(claims) if name in allowed)


def _select_key(key_set: KeySet, use: str, alg: str):
    """Select the first key of the set matching the given ``use`` and ``alg``."""
    # Keys explicitly designed for the given ``use`` are preferred over
    # keys without a ``use`` restriction.
    for fallback in (False, True):
        for key in key_set.keys:
            try:
                key.check_use(use)
                key.check_alg(alg)
            except (UnsupportedKeyUseError, UnsupportedKeyAlgorithmError):
                continue
            if not fallback and key.get("use") != use:
                continue
            return key
    return None


class UserInfoEndpoint:
    """OpenID Connect Core UserInfo Endpoint.

    This endpoint returns information about a given user, as a JSON payload or as a JWT.
    It must be subclassed and a few methods needs to be manually implemented::

        class UserInfoEndpoint(oidc.core.UserInfoEndpoint):
            def get_issuer(self):
                return "https://auth.example"

            def generate_user_info(self, user, scope):
                return UserInfo(
                    sub=user.id,
                    name=user.name,
                    ...
                ).filter(scope)

            def resolve_private_key(self):
                return server_private_jwk_set()

    It is also needed to pass a :class:`~authlib.oauth2.rfc6749.ResourceProtector` instance
    with a registered :class:`~authlib.oauth2.rfc6749.TokenValidator` at initialization,
    so the access to the endpoint can be restricter to valid token bearers::

        resource_protector = ResourceProtector()
        resource_protector.register_token_validator(BearerTokenValidator())
        server.register_endpoint(UserInfoEndpoint(resource_protector=resource_protector))

    And then you can plug the endpoint to your application::

        @app.route("/oauth/userinfo", methods=["GET", "POST"])
        def userinfo():
            return server.create_endpoint_response("userinfo")

    The response mode is negotiated from the registered client metadata
    (request parameters can never override it):

    - by default, the UserInfo is returned as a plain JSON payload;
    - when the client registered ``userinfo_signed_response_alg``, the
      UserInfo is returned as a JWS containing the ``iss`` and ``aud``
      claims;
    - when the client also registered ``userinfo_encrypted_response_alg``
      (and optionally ``userinfo_encrypted_response_enc``), the claims
      are first encrypted with the client public key into a JWE, which is
      then signed by the server, forming a nested JWT.
    """

    ENDPOINT_NAME = "userinfo"

    def __init__(
        self,
        server: AuthorizationServer | None = None,
        resource_protector: ResourceProtector | None = None,
    ):
        self.server = server
        self.resource_protector = resource_protector

    def create_endpoint_request(self, request: OAuth2Request):
        return self.server.create_oauth2_request(request)

    def __call__(self, request: OAuth2Request):
        token = self.resource_protector.acquire_token("openid")
        client = token.get_client()
        user = token.get_user()
        user_info = self.generate_user_info(user, token.scope)

        self.validate_client_issuer(client)

        # The response mode is negotiated from the registered client
        # metadata only. Request parameters can never override the
        # registered ``userinfo_signed_response_alg``,
        # ``userinfo_encrypted_response_alg`` and
        # ``userinfo_encrypted_response_enc`` values.
        mode = self.resolve_response_mode(client)
        if mode is None:
            return 200, user_info, default_json_headers

        claims = self.build_jwt_claims(user_info, client, mode)
        if "enc_alg" in mode:
            data = self.encrypt_claims(claims, mode)
            if "sig_alg" in mode:
                # Nested JWT: the JWE is itself signed by the server, so
                # the client can authenticate the issuer before decrypting.
                data = self.sign_payload(data, mode, nested=True)
        else:
            data = self.sign_payload(claims, mode)
        return 200, data, [("Content-Type", "application/jwt")]

    def validate_client_issuer(self, client):
        """Ensure the client was registered for this issuer.

        A client whose registered ``issuer`` metadata differs from this
        server's issuer identifier is rejected with an
        :class:`~authlib.oidc.core.errors.IssuerMismatchError`.
        """
        client_issuer = client.client_metadata.get("issuer")
        if client_issuer and client_issuer != self.get_issuer():
            raise IssuerMismatchError()

    def resolve_response_mode(self, client) -> dict | None:
        """Negotiate the UserInfo response mode from the client metadata.

        Returns ``None`` when the client did not register any JWT response
        algorithm (plain JSON response). Otherwise returns a dict
        describing the signing and/or encryption to apply, after
        validating the registered algorithms against the server
        whitelists and resolving the keys to use.
        """
        metadata = client.client_metadata
        sig_alg = metadata.get("userinfo_signed_response_alg")
        enc_alg = metadata.get("userinfo_encrypted_response_alg")
        if not sig_alg and not enc_alg:
            return None

        mode = {"issuer": self.get_issuer()}
        if sig_alg:
            if sig_alg not in self.get_supported_algorithms():
                raise UnsupportedUserInfoResponseAlgError()
            mode["sig_alg"] = sig_alg
            mode["sig_key"] = self.resolve_signing_key(sig_alg)

        if enc_alg:
            if enc_alg not in self.get_supported_encryption_algorithms():
                raise UnsupportedUserInfoResponseAlgError()
            enc_enc = metadata.get("userinfo_encrypted_response_enc") or "A128CBC-HS256"
            if enc_enc not in self.get_supported_encryption_enc_methods():
                raise UnsupportedUserInfoResponseAlgError()
            mode["enc_alg"] = enc_alg
            mode["enc_enc"] = enc_enc
            mode["enc_key"] = self.resolve_client_encryption_key(client, enc_alg)
        return mode

    def build_jwt_claims(self, user_info: UserInfo, client, mode: dict) -> UserInfo:
        """Build the claims set for a JWT UserInfo response.

        The claims are filtered through :func:`filter_userinfo_claims` so
        that only standard UserInfo claims are kept, then completed with
        the ``iss``, ``aud``, ``iat`` and ``exp`` claims. The returned
        mapping is sorted by claim name so that the JSON serialization is
        stable regardless of the source ordering.
        """
        now = int(time.time())
        claims = filter_userinfo_claims(user_info)
        # If signed, the UserInfo Response MUST contain the Claims iss
        # (issuer) and aud (audience) as members. The iss value MUST be
        # the OP's Issuer Identifier URL. The aud value MUST be or
        # include the RP's Client ID value.
        claims["iss"] = mode["issuer"]
        claims["aud"] = client.client_id
        claims["iat"] = now
        claims["exp"] = now + self.get_expires_in()
        return filter_userinfo_claims(claims)

    def get_expires_in(self) -> int:
        """Return the lifetime (in seconds) of JWT UserInfo responses.

        Developers can override this method to customize the expiration
        time of the ``exp`` claim::

            def get_expires_in(self) -> int:
                return 600
        """
        return 3600

    def resolve_signing_key(self, alg: str):
        """Resolve the server key used to sign JWT UserInfo responses.

        The key is selected from :meth:`resolve_private_key` by key usage
        (``sig``) and algorithm. Raises
        :class:`~authlib.oidc.core.errors.MissingSigningKeyError` when no
        usable key is available.
        """
        key = import_any_key(self.resolve_private_key())
        if isinstance(key, KeySet):
            key = _select_key(key, "sig", alg)
        if key is None:
            raise MissingSigningKeyError()
        return key

    def resolve_client_encryption_key(self, client, alg: str):
        """Resolve the client public key used to encrypt UserInfo responses.

        The key is selected from the registered ``jwks`` client metadata
        by key usage (``enc``) and algorithm. Raises
        :class:`~authlib.oidc.core.errors.MissingClientPublicKeyError`
        when the client did not register a usable public key.
        """
        jwks = client.client_metadata.get("jwks")
        key_set = None
        if isinstance(jwks, KeySet):
            key_set = jwks
        elif isinstance(jwks, dict) and jwks.get("keys"):
            key_set = KeySet.import_key_set(jwks)
        key = key_set and _select_key(key_set, "enc", alg)
        if key is None:
            raise MissingClientPublicKeyError()
        return key

    def sign_payload(self, payload, mode: dict, nested: bool = False) -> str:
        """Sign the claims (or the nested JWE) with the server key."""
        key = mode["sig_key"]
        header = {"alg": mode["sig_alg"]}
        if key.kid:
            header["kid"] = key.kid
        if nested:
            header["cty"] = "JWE"
            return jws.serialize_compact(
                header, payload, key, algorithms=self.get_supported_algorithms()
            )
        return jwt.encode(
            header, payload, key, algorithms=self.get_supported_algorithms()
        )

    def encrypt_claims(self, claims: UserInfo, mode: dict) -> str:
        """Encrypt the claims with the client public key into a JWE."""
        key = mode["enc_key"]
        header = {"alg": mode["enc_alg"], "enc": mode["enc_enc"], "cty": "JWT"}
        if key.kid:
            header["kid"] = key.kid
        algorithms = (
            self.get_supported_encryption_algorithms()
            + self.get_supported_encryption_enc_methods()
        )
        # ``claims`` is canonically ordered by ``filter_userinfo_claims``,
        # so the serialization is stable.
        plaintext = json_dumps(claims)
        return jwe.encrypt_compact(header, plaintext, key, algorithms=algorithms)

    def get_supported_encryption_algorithms(self) -> list[str]:
        """Return the supported JWE key management algorithms (``alg``)
        for userinfo encryption. Developer can override this method to
        customize the supported algorithms::

            def get_supported_encryption_algorithms(self) -> list[str]:
                return ["RSA-OAEP"]
        """
        return [
            "RSA-OAEP",
            "RSA-OAEP-256",
            "ECDH-ES",
            "ECDH-ES+A128KW",
            "ECDH-ES+A256KW",
            "A128KW",
            "A256KW",
            "dir",
        ]

    def get_supported_encryption_enc_methods(self) -> list[str]:
        """Return the supported JWE content encryption methods (``enc``)
        for userinfo encryption. Developer can override this method to
        customize the supported methods::

            def get_supported_encryption_enc_methods(self) -> list[str]:
                return ["A256GCM"]
        """
        return [
            "A128CBC-HS256",
            "A192CBC-HS384",
            "A256CBC-HS512",
            "A128GCM",
            "A192GCM",
            "A256GCM",
        ]

    def get_supported_algorithms(self) -> list[str]:
        """Return the supported algorithms for userinfo signing.
        By default, it uses the recommended algorithms from ``joserfc``.
        Developer can override this method to customize the supported algorithms::

            def get_supported_algorithms(self) -> list[str]:
                return ["RS256"]
        """
        return JWSRegistry.recommended

    def generate_user_info(self, user, scope: str) -> UserInfo:
        """
        Generate a :class:`~authlib.oidc.core.UserInfo` object for an user::

            def generate_user_info(self, user, scope: str) -> UserInfo:
                return UserInfo(
                    given_name=user.given_name,
                    family_name=user.last_name,
                    email=user.email,
                    ...
                ).filter(scope)

        This method must be implemented by developers.
        """
        raise NotImplementedError()

    def get_issuer(self) -> str:
        """The OP's Issuer Identifier URL.

        The value is used to fill the ``iss`` claim that is mandatory in signed userinfo::

            def get_issuer(self) -> str:
                return "https://auth.example"

        This method must be implemented by developers to support JWT userinfo.
        """
        raise NotImplementedError()

    def resolve_private_key(self):
        """Return the server JSON Web Key Set.

        This is used to sign userinfo payloads::

            def resolve_private_key(self):
                return server_private_jwk_set()

        This method must be implemented by developers to support JWT userinfo signing.
        """
        return None  # pragma: no cover
