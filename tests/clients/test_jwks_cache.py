import asyncio
import json
import threading
import time
from collections import defaultdict
from urllib.parse import urlparse

import pytest
import requests
from joserfc import jwt
from joserfc.errors import BadSignatureError
from joserfc.errors import ExpiredTokenError
from joserfc.errors import InvalidKeyIdError
from joserfc.jwk import RSAKey
from requests.adapters import HTTPAdapter

from authlib.integrations.base_client.async_openid import AsyncOpenIDMixin
from authlib.integrations.base_client.jwks_cache import JWKSCache
from authlib.integrations.base_client.sync_openid import OpenIDMixin
from authlib.integrations.httpx_client import AsyncOAuth2Client
from authlib.integrations.httpx_client._compat import httpx2
from authlib.integrations.requests_client import OAuth2Session

JWKS_BASE_URL = "http://jwks.test"


class LocalJWKSService:
    """In-process JWKS provider used as a local JWKS service in tests.

    Tracks request counts, supports ETag/304 revalidation, and can
    inject server failures and timeouts per path.
    """

    def __init__(self):
        self.key_sets = {}
        self.etags = {}
        self.counts = defaultdict(int)
        self.if_none_match = []
        self.fail_paths = set()
        self.timeout_paths = set()
        self.delay = 0.0

    def _lookup(self, path, if_none_match):
        """Return (status, jwks, etag) for a GET after bookkeeping."""
        self.counts[path] += 1
        if if_none_match is not None:
            self.if_none_match.append(if_none_match)
        if path in self.timeout_paths:
            return "timeout", None, None
        if path in self.fail_paths:
            return 500, None, None
        jwks = self.key_sets.get(path)
        if jwks is None:
            return 404, None, None
        etag = self.etags.get(path)
        if etag and if_none_match == etag:
            return 304, None, etag
        return 200, jwks, etag


class _SyncJWKSAdapter(HTTPAdapter):
    """Serves the LocalJWKSService through the requests transport layer."""

    def __init__(self, service):
        super().__init__()
        self.service = service

    def send(self, request, **kwargs):
        service = self.service
        path = urlparse(request.url).path
        if service.delay:
            time.sleep(service.delay)
        status, jwks, etag = service._lookup(path, request.headers.get("If-None-Match"))
        if status == "timeout":
            raise requests.exceptions.ReadTimeout("JWKS request timed out")
        resp = requests.Response()
        resp.status_code = status
        resp.url = request.url
        resp._content = b""
        if etag:
            resp.headers["ETag"] = etag
        if jwks is not None:
            resp.headers["Content-Type"] = "application/json"
            resp._content = json.dumps(jwks).encode()
        return resp


class _AsyncJWKSTransport(httpx2.AsyncBaseTransport):
    """Serves the LocalJWKSService through the httpx transport layer."""

    def __init__(self, service):
        self.service = service

    async def handle_async_request(self, request):
        service = self.service
        path = request.url.path
        if service.delay:
            await asyncio.sleep(service.delay)
        status, jwks, etag = service._lookup(path, request.headers.get("if-none-match"))
        if status == "timeout":
            raise httpx2.ReadTimeout("JWKS request timed out", request=request)
        headers = {}
        if etag:
            headers["ETag"] = etag
        if jwks is not None:
            return httpx2.Response(200, json=jwks, headers=headers, request=request)
        return httpx2.Response(status, headers=headers, request=request)


@pytest.fixture
def jwks_service():
    return LocalJWKSService()


@pytest.fixture(scope="module")
def rsa_keys():
    return {
        "key-a": RSAKey.generate_key(2048, {"kid": "key-a"}),
        "key-b": RSAKey.generate_key(2048, {"kid": "key-b"}),
    }


def public_jwks(*keys):
    return {"keys": [key.as_dict() for key in keys]}


def make_id_token(key, kid, issuer, nonce="nonce-1", exp_delta=3600):
    now = int(time.time())
    claims = {
        "sub": "123",
        "iss": issuer,
        "aud": "dev",
        "iat": now,
        "auth_time": now,
        "exp": now + exp_delta,
        "nonce": nonce,
    }
    return jwt.encode({"alg": "RS256", "kid": kid}, claims, key)


def make_metadata(issuer, jwks_uri):
    return {
        "issuer": issuer,
        "jwks_uri": jwks_uri,
        "id_token_signing_alg_values_supported": ["RS256"],
    }


class SyncOIDCClient(OpenIDMixin):
    def __init__(self, metadata, cache, session_factory):
        self.client_id = "dev"
        self.server_metadata = metadata
        self.jwks_cache = cache
        self._session_factory = session_factory

    def load_server_metadata(self):
        return self.server_metadata

    def _get_session(self):
        return self._session_factory()


class AsyncOIDCClient(AsyncOpenIDMixin):
    def __init__(self, metadata, cache, **session_kwargs):
        self.client_id = "dev"
        self.server_metadata = metadata
        self.jwks_cache = cache
        self._session_kwargs = session_kwargs

    async def load_server_metadata(self):
        return self.server_metadata

    def _get_session(self):
        return AsyncOAuth2Client(**self._session_kwargs)


def make_sync_client(service, issuer, cache, path="/jwks"):
    metadata = make_metadata(issuer, JWKS_BASE_URL + path)

    def session_factory():
        session = OAuth2Session()
        session.mount(JWKS_BASE_URL + "/", _SyncJWKSAdapter(service))
        return session

    return SyncOIDCClient(metadata, cache, session_factory)


def make_async_client(service, issuer, cache, path="/jwks"):
    metadata = make_metadata(issuer, JWKS_BASE_URL + path)
    return AsyncOIDCClient(metadata, cache, transport=_AsyncJWKSTransport(service))


def parse(client, id_token):
    return client.parse_id_token(
        {"id_token": id_token, "access_token": "at"}, nonce="nonce-1"
    )


async def parse_async(client, id_token):
    return await client.parse_id_token(
        {"id_token": id_token, "access_token": "at"}, nonce="nonce-1"
    )


# -- cache primitives ---------------------------------------------------


def test_cache_stale_window_expiry():
    cache = JWKSCache(fresh_period=0.05, stale_period=0.1)
    key = ("https://issuer.example", "https://issuer.example/jwks")
    cache.store(key, {"keys": []})
    assert cache.get_fresh(key) is not None
    time.sleep(0.07)
    assert cache.get_fresh(key) is None
    assert cache.get_stale(key) is not None
    time.sleep(0.12)
    assert cache.get_stale(key) is None


def test_cache_miss_records_are_bounded():
    cache = JWKSCache(miss_ttl=60, max_misses=5)
    key = ("https://issuer.example", "https://issuer.example/jwks")
    for i in range(20):
        cache.record_miss(key, f"kid-{i}")
    assert len(cache._misses) <= 5
    assert cache.is_known_miss(key, "kid-19")
    assert not cache.is_known_miss(key, "kid-0")


def test_cache_store_clears_resolved_misses():
    cache = JWKSCache(miss_ttl=60)
    key = ("https://issuer.example", "https://issuer.example/jwks")
    cache.record_miss(key, "key-a")
    assert cache.is_known_miss(key, "key-a")
    cache.store(key, {"keys": [{"kid": "key-a", "kty": "RSA"}]})
    assert not cache.is_known_miss(key, "key-a")


# -- sync client against the local JWKS service --------------------------


def test_sync_key_rotation_and_request_counts(jwks_service, rsa_keys):
    issuer = "https://issuer-sync-rotation.example"
    jwks_service.key_sets["/jwks"] = public_jwks(rsa_keys["key-a"])
    client = make_sync_client(jwks_service, issuer, JWKSCache())

    token_a = make_id_token(rsa_keys["key-a"], "key-a", issuer)
    assert parse(client, token_a)["sub"] == "123"
    assert jwks_service.counts["/jwks"] == 1

    # fresh cache: no further request
    assert parse(client, token_a)["sub"] == "123"
    assert jwks_service.counts["/jwks"] == 1

    # IdP rotates to a new key set; unknown kid triggers exactly one refresh
    jwks_service.key_sets["/jwks"] = public_jwks(rsa_keys["key-b"])
    token_b = make_id_token(rsa_keys["key-b"], "key-b", issuer)
    assert parse(client, token_b)["sub"] == "123"
    assert jwks_service.counts["/jwks"] == 2

    assert parse(client, token_b)["sub"] == "123"
    assert jwks_service.counts["/jwks"] == 2


def test_sync_concurrent_unknown_kid_shares_refresh(jwks_service, rsa_keys):
    issuer = "https://issuer-sync-concurrent.example"
    jwks_service.key_sets["/jwks"] = public_jwks(rsa_keys["key-a"])
    jwks_service.delay = 0.1
    client = make_sync_client(jwks_service, issuer, JWKSCache())
    token_a = make_id_token(rsa_keys["key-a"], "key-a", issuer)
    parse(client, token_a)
    assert jwks_service.counts["/jwks"] == 1

    jwks_service.key_sets["/jwks"] = public_jwks(rsa_keys["key-b"])
    token_b = make_id_token(rsa_keys["key-b"], "key-b", issuer)

    barrier = threading.Barrier(8)
    results = []
    errors = []

    def worker():
        try:
            barrier.wait(timeout=5)
            results.append(parse(client, token_b)["sub"])
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    assert not errors
    assert results == ["123"] * 8
    # concurrent refreshes within the same window are merged
    assert jwks_service.counts["/jwks"] <= 3


def test_sync_unknown_kid_misses_do_not_hammer_provider(jwks_service, rsa_keys):
    issuer = "https://issuer-sync-miss.example"
    jwks_service.key_sets["/jwks"] = public_jwks(rsa_keys["key-a"])
    cache = JWKSCache(miss_ttl=60, max_misses=8)
    client = make_sync_client(jwks_service, issuer, cache)
    token_a = make_id_token(rsa_keys["key-a"], "key-a", issuer)
    parse(client, token_a)
    assert jwks_service.counts["/jwks"] == 1

    rogue_key = RSAKey.generate_key(2048, {"kid": "rogue"})
    rogue_token = make_id_token(rogue_key, "rogue", issuer)
    with pytest.raises(InvalidKeyIdError):
        parse(client, rogue_token)
    assert jwks_service.counts["/jwks"] == 2

    # same unknown kid again: negative record suppresses another fetch
    with pytest.raises(InvalidKeyIdError):
        parse(client, rogue_token)
    assert jwks_service.counts["/jwks"] == 2

    # many random kids stay bounded and cannot grow without limit
    for i in range(20):
        with pytest.raises(InvalidKeyIdError):
            parse(client, make_id_token(rogue_key, f"random-{i}", issuer))
    assert len(cache._misses) <= 8

    # known key still verifies without any new request
    count = jwks_service.counts["/jwks"]
    assert parse(client, token_a)["sub"] == "123"
    assert jwks_service.counts["/jwks"] == count


def test_sync_only_key_lookup_failure_triggers_refresh(jwks_service, rsa_keys):
    issuer = "https://issuer-sync-no-retry.example"
    jwks_service.key_sets["/jwks"] = public_jwks(rsa_keys["key-a"])
    client = make_sync_client(jwks_service, issuer, JWKSCache())
    token_a = make_id_token(rsa_keys["key-a"], "key-a", issuer)
    parse(client, token_a)
    assert jwks_service.counts["/jwks"] == 1

    # bad signature with a known kid: no refresh, no retry
    forged = make_id_token(rsa_keys["key-b"], "key-a", issuer)
    with pytest.raises(BadSignatureError):
        parse(client, forged)
    assert jwks_service.counts["/jwks"] == 1

    # expired token with a known kid: claims error, no refresh
    expired = make_id_token(rsa_keys["key-a"], "key-a", issuer, exp_delta=-3600)
    with pytest.raises(ExpiredTokenError):
        parse(client, expired)
    assert jwks_service.counts["/jwks"] == 1


def test_sync_etag_and_304_revalidation(jwks_service, rsa_keys):
    issuer = "https://issuer-sync-etag.example"
    jwks_service.key_sets["/jwks"] = public_jwks(rsa_keys["key-a"])
    jwks_service.etags["/jwks"] = '"v1"'
    cache = JWKSCache(fresh_period=0.15)
    client = make_sync_client(jwks_service, issuer, cache)
    token_a = make_id_token(rsa_keys["key-a"], "key-a", issuer)
    assert parse(client, token_a)["sub"] == "123"
    assert jwks_service.counts["/jwks"] == 1

    # past the fresh period the client revalidates with If-None-Match
    time.sleep(0.2)
    assert parse(client, token_a)["sub"] == "123"
    assert jwks_service.counts["/jwks"] == 2
    assert jwks_service.if_none_match == ['"v1"']

    # 304 refreshed the entry: fresh again without new requests
    assert parse(client, token_a)["sub"] == "123"
    assert jwks_service.counts["/jwks"] == 2


def test_sync_refresh_failure_stale_window(jwks_service, rsa_keys):
    issuer = "https://issuer-sync-stale.example"
    jwks_service.key_sets["/jwks"] = public_jwks(rsa_keys["key-a"])
    cache = JWKSCache(fresh_period=0.1, stale_period=0.3)
    client = make_sync_client(jwks_service, issuer, cache)
    token_a = make_id_token(rsa_keys["key-a"], "key-a", issuer)
    assert parse(client, token_a)["sub"] == "123"
    assert jwks_service.counts["/jwks"] == 1

    # IdP starts failing; within the stale window known keys still verify
    jwks_service.fail_paths.add("/jwks")
    time.sleep(0.15)
    assert parse(client, token_a)["sub"] == "123"
    assert jwks_service.counts["/jwks"] >= 2

    # unknown keys must fail even though stale data exists
    rogue_key = RSAKey.generate_key(2048, {"kid": "rogue"})
    with pytest.raises(InvalidKeyIdError):
        parse(client, make_id_token(rogue_key, "rogue", issuer))

    # beyond the stale window the old keys are no longer served
    time.sleep(0.35)
    with pytest.raises(Exception):  # noqa: B017, PT011
        parse(client, token_a)


def test_sync_issuers_with_same_kid_are_isolated(jwks_service):
    key_one = RSAKey.generate_key(2048, {"kid": "shared-kid"})
    key_two = RSAKey.generate_key(2048, {"kid": "shared-kid"})
    jwks_service.key_sets["/jwks-one"] = public_jwks(key_one)
    jwks_service.key_sets["/jwks-two"] = public_jwks(key_two)

    shared_cache = JWKSCache()
    issuer_one = "https://issuer-one.example"
    issuer_two = "https://issuer-two.example"
    client_one = make_sync_client(jwks_service, issuer_one, shared_cache, "/jwks-one")
    client_two = make_sync_client(jwks_service, issuer_two, shared_cache, "/jwks-two")

    token_one = make_id_token(key_one, "shared-kid", issuer_one)
    token_two = make_id_token(key_two, "shared-kid", issuer_two)
    assert parse(client_one, token_one)["sub"] == "123"
    assert parse(client_two, token_two)["sub"] == "123"
    assert jwks_service.counts["/jwks-one"] == 1
    assert jwks_service.counts["/jwks-two"] == 1

    # same kid, wrong issuer: key material differs, must not verify
    with pytest.raises(BadSignatureError):
        parse(client_two, token_one)
    # and must not trigger cross-issuer refreshes
    assert jwks_service.counts["/jwks-two"] == 1


# -- async client against the local JWKS service -------------------------


async def test_async_key_rotation_and_merged_refresh(jwks_service, rsa_keys):
    issuer = "https://issuer-async-rotation.example"
    jwks_service.key_sets["/jwks"] = public_jwks(rsa_keys["key-a"])
    jwks_service.delay = 0.05
    client = make_async_client(jwks_service, issuer, JWKSCache())

    token_a = make_id_token(rsa_keys["key-a"], "key-a", issuer)
    info = await parse_async(client, token_a)
    assert info["sub"] == "123"
    assert jwks_service.counts["/jwks"] == 1

    # IdP rotates; many concurrent callbacks hit the unknown kid
    jwks_service.key_sets["/jwks"] = public_jwks(rsa_keys["key-b"])
    token_b = make_id_token(rsa_keys["key-b"], "key-b", issuer)
    results = await asyncio.gather(*[parse_async(client, token_b) for _ in range(8)])
    assert [r["sub"] for r in results] == ["123"] * 8
    # the concurrent refreshes shared a single HTTP request
    assert jwks_service.counts["/jwks"] == 2

    info = await parse_async(client, token_b)
    assert info["sub"] == "123"
    assert jwks_service.counts["/jwks"] == 2


async def test_async_cancelled_waiter_keeps_shared_refresh(jwks_service, rsa_keys):
    issuer = "https://issuer-async-cancel.example"
    jwks_service.key_sets["/jwks"] = public_jwks(rsa_keys["key-a"])
    jwks_service.delay = 0.3
    client = make_async_client(jwks_service, issuer, JWKSCache())

    task1 = asyncio.create_task(client.fetch_jwk_set(force=True))
    task2 = asyncio.create_task(client.fetch_jwk_set(force=True))
    await asyncio.sleep(0.05)
    task1.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task1

    # the other waiter still gets the shared refresh result
    jwk_set = await task2
    assert "keys" in jwk_set
    assert jwks_service.counts["/jwks"] == 1

    # and the result was cached for subsequent callers
    again = await client.fetch_jwk_set()
    assert again == jwk_set
    assert jwks_service.counts["/jwks"] == 1


async def test_async_etag_304_and_unknown_kid(jwks_service, rsa_keys):
    issuer = "https://issuer-async-etag.example"
    jwks_service.key_sets["/jwks"] = public_jwks(rsa_keys["key-a"])
    jwks_service.etags["/jwks"] = '"async-v1"'
    cache = JWKSCache(fresh_period=0.15, miss_ttl=60)
    client = make_async_client(jwks_service, issuer, cache)
    token_a = make_id_token(rsa_keys["key-a"], "key-a", issuer)
    info = await parse_async(client, token_a)
    assert info["sub"] == "123"
    assert jwks_service.counts["/jwks"] == 1

    time.sleep(0.2)
    info = await parse_async(client, token_a)
    assert info["sub"] == "123"
    assert jwks_service.counts["/jwks"] == 2
    assert jwks_service.if_none_match == ['"async-v1"']

    # unknown kid: one refresh, then negative records suppress repeats
    rogue_key = RSAKey.generate_key(2048, {"kid": "rogue"})
    rogue_token = make_id_token(rogue_key, "rogue", issuer)
    with pytest.raises(InvalidKeyIdError):
        await parse_async(client, rogue_token)
    assert jwks_service.counts["/jwks"] == 3
    with pytest.raises(InvalidKeyIdError):
        await parse_async(client, rogue_token)
    assert jwks_service.counts["/jwks"] == 3


async def test_async_refresh_timeout_uses_stale_then_fails(jwks_service, rsa_keys):
    issuer = "https://issuer-async-timeout.example"
    jwks_service.key_sets["/jwks"] = public_jwks(rsa_keys["key-a"])
    cache = JWKSCache(fresh_period=0.1, stale_period=0.3)
    client = make_async_client(jwks_service, issuer, cache)
    token_a = make_id_token(rsa_keys["key-a"], "key-a", issuer)
    info = await parse_async(client, token_a)
    assert info["sub"] == "123"
    assert jwks_service.counts["/jwks"] == 1

    # IdP requests start timing out; within the stale window keys verify
    jwks_service.timeout_paths.add("/jwks")
    time.sleep(0.15)
    info = await parse_async(client, token_a)
    assert info["sub"] == "123"
    assert jwks_service.counts["/jwks"] >= 2

    # unknown keys must fail even with stale data available
    rogue_key = RSAKey.generate_key(2048, {"kid": "rogue"})
    with pytest.raises(InvalidKeyIdError):
        await parse_async(client, make_id_token(rogue_key, "rogue", issuer))

    # beyond the stale window old keys are no longer served
    time.sleep(0.35)
    with pytest.raises(Exception):  # noqa: B017, PT011
        await parse_async(client, token_a)
