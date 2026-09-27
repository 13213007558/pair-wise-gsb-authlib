import asyncio
import logging

from joserfc import jwt
from joserfc.errors import InvalidKeyIdError
from joserfc.jwk import KeySet
from joserfc.jws import JWSRegistry

from authlib.common.security import generate_token
from authlib.common.urls import add_params_to_uri
from authlib.oidc.core import CodeIDToken
from authlib.oidc.core import ImplicitIDToken
from authlib.oidc.core import UserInfo

from .jwks_cache import default_jwks_cache
from .jwks_cache import extract_token_kid
from .jwks_cache import key_set_has_kid

__all__ = ["AsyncOpenIDMixin"]

log = logging.getLogger(__name__)


class AsyncOpenIDMixin:
    #: Optional JWKSCache instance; falls back to a shared process-wide
    #: cache isolated by (issuer, jwks_uri).
    jwks_cache = None

    def _get_jwks_cache(self):
        return self.jwks_cache or default_jwks_cache

    async def fetch_jwk_set(self, force=False):
        metadata = await self.load_server_metadata()
        jwk_set = metadata.get("jwks")
        if jwk_set and not force:
            return jwk_set

        uri = metadata.get("jwks_uri")
        if not uri:
            raise RuntimeError('Missing "jwks_uri" in metadata')

        cache = self._get_jwks_cache()
        cache_key = (metadata.get("issuer"), uri)

        if not force:
            cached = cache.get_fresh(cache_key)
            if cached is not None:
                return cached

        task = cache.get_refresh_task(cache_key)
        if task is not None and (
            task.done() or task.get_loop() is not asyncio.get_running_loop()
        ):
            cache.clear_refresh_task(cache_key, task)
            task = None
        if task is None:
            decided_at = cache.now()
            task = asyncio.ensure_future(
                self._refresh_jwk_set(cache, cache_key, uri, force, decided_at)
            )
            cache.set_refresh_task(cache_key, task)
        # shield: one waiter being cancelled must not cancel the
        # refresh shared with the other waiters
        return await asyncio.shield(task)

    async def _refresh_jwk_set(self, cache, cache_key, uri, force, decided_at):
        try:
            entry = cache.get_entry(cache_key)
            if entry is not None:
                if not force and cache.is_fresh(entry):
                    return entry.key_set
                if force and entry.fetched_at >= decided_at:
                    # another caller already refreshed within this window
                    return entry.key_set
            try:
                jwk_set, etag = await self._request_jwk_set(
                    uri, cache.etag_for(cache_key)
                )
            except Exception:
                stale = cache.get_stale(cache_key)
                if stale is not None:
                    log.debug(
                        "JWKS refresh failed for issuer %r; serving cached keys",
                        cache_key[0],
                    )
                    return stale
                raise
            if jwk_set is None:  # 304 Not Modified
                cache.touch(cache_key, etag)
                return cache.get_entry(cache_key).key_set
            return cache.store(cache_key, jwk_set, etag)
        finally:
            cache.clear_refresh_task(cache_key, asyncio.current_task())

    async def _request_jwk_set(self, uri, etag=None):
        headers = {}
        if etag:
            headers["If-None-Match"] = etag
        async with self._get_session() as client:
            resp = await client.request(
                "GET", uri, withhold_token=True, headers=headers
            )
            if resp.status_code == 304:
                return None, resp.headers.get("ETag")
            resp.raise_for_status()
            return resp.json(), resp.headers.get("ETag")

    async def _refresh_jwk_set_for_token(self, id_token, metadata):
        """Fetch a fresh key set for an unknown kid, or return None.

        Returns None when a refresh is suppressed because the kid
        stayed unknown after a recent refresh. Raises RuntimeError
        via fetch_jwk_set when no "jwks_uri" is available.
        """
        cache = self._get_jwks_cache()
        cache_key = (metadata.get("issuer"), metadata.get("jwks_uri"))
        kid = extract_token_kid(id_token)
        if kid and cache.is_known_miss(cache_key, kid):
            log.debug(
                "JWKS refresh suppressed for unknown kid; issuer %r", cache_key[0]
            )
            return None
        jwk_set = await self.fetch_jwk_set(force=True)
        if kid and not key_set_has_kid(jwk_set, kid):
            cache.record_miss(cache_key, kid)
        return jwk_set

    async def userinfo(self, **kwargs):
        """Fetch user info from ``userinfo_endpoint``."""
        metadata = await self.load_server_metadata()
        resp = await self.get(metadata["userinfo_endpoint"], **kwargs)
        resp.raise_for_status()
        data = resp.json()
        return UserInfo(data)

    async def parse_id_token(
        self, token, nonce, claims_options=None, claims_cls=None, leeway=120
    ):
        """Return an instance of UserInfo from token's ``id_token``."""
        claims_params = dict(
            nonce=nonce,
            client_id=self.client_id,
        )
        if claims_cls is None:
            if "access_token" in token:
                claims_params["access_token"] = token["access_token"]
                claims_cls = CodeIDToken
            else:
                claims_cls = ImplicitIDToken

        metadata = await self.load_server_metadata()
        if claims_options is None and "issuer" in metadata:
            claims_options = {"iss": {"values": [metadata["issuer"]]}}

        alg_values = metadata.get("id_token_signing_alg_values_supported")
        if not alg_values:
            alg_values = ["RS256"]

        jwks = await self.fetch_jwk_set()
        key_set = KeySet.import_key_set(jwks)
        try:
            token = jwt.decode(
                token["id_token"],
                key=key_set,
                registry=JWSRegistry(algorithms=alg_values, strict_check_header=False),
            )
        except InvalidKeyIdError:
            jwks = await self._refresh_jwk_set_for_token(token["id_token"], metadata)
            if jwks is None:
                raise
            key_set = KeySet.import_key_set(jwks)
            token = jwt.decode(
                token["id_token"],
                key=key_set,
                registry=JWSRegistry(algorithms=alg_values, strict_check_header=False),
            )

        claims = claims_cls(token.claims, token.header, claims_options, claims_params)
        # https://github.com/authlib/authlib/issues/259
        if claims.get("nonce_supported") is False:
            claims.params["nonce"] = None
        claims.validate(leeway=leeway)
        return UserInfo(claims)

    async def create_logout_url(
        self,
        post_logout_redirect_uri=None,
        id_token_hint=None,
        state=None,
        **kwargs,
    ):
        """Generate the end session URL for RP-Initiated Logout.

        :param post_logout_redirect_uri: URI to redirect after logout.
        :param id_token_hint: ID Token previously issued to the RP.
        :param state: Opaque value for maintaining state.
        :param kwargs: Extra parameters (client_id, logout_hint, ui_locales).
        :return: dict with 'url' and 'state' keys.
        """
        metadata = await self.load_server_metadata()
        end_session_endpoint = metadata.get("end_session_endpoint")

        if not end_session_endpoint:
            raise RuntimeError('Missing "end_session_endpoint" in metadata')

        params = {}
        if id_token_hint:
            params["id_token_hint"] = id_token_hint
        if post_logout_redirect_uri:
            params["post_logout_redirect_uri"] = post_logout_redirect_uri
            if state is None:
                state = generate_token(20)
            params["state"] = state

        for key in ("client_id", "logout_hint", "ui_locales"):
            if key in kwargs:
                params[key] = kwargs[key]

        url = add_params_to_uri(end_session_endpoint, params)
        return {"url": url, "state": state}
