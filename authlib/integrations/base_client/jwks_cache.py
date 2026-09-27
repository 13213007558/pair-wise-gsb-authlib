import logging
import threading
import time
from collections import OrderedDict

from joserfc.jws import extract_compact
from joserfc.util import to_bytes

log = logging.getLogger(__name__)


def extract_token_kid(id_token):
    """Read the kid header of a compact JWS without verifying it."""
    try:
        obj = extract_compact(to_bytes(id_token))
    except (ValueError, TypeError):
        return None
    protected = obj.protected or {}
    return protected.get("kid")


def key_set_has_kid(jwk_set, kid):
    """Check if a raw JWKS dict contains a key with the given kid."""
    return any(
        isinstance(key, dict) and key.get("kid") == kid
        for key in jwk_set.get("keys", [])
    )


class KeySetEntry:
    """A cached JWKS document together with its revalidation state."""

    __slots__ = ("key_set", "fetched_at", "etag")

    def __init__(self, key_set, fetched_at, etag=None):
        self.key_set = key_set
        self.fetched_at = fetched_at
        self.etag = etag


class JWKSCache:
    """Cache of JWKS documents, isolated by (issuer, jwks_uri).

    The cache itself never performs HTTP requests; callers fetch the
    document and use this object to coordinate *when* a fetch is needed
    and to merge concurrent refreshes:

    :param fresh_period: seconds a cached key set is served without
        any revalidation request.
    :param stale_period: extra seconds a cached key set may still be
        used when a refresh fails. After fresh_period + stale_period
        the entry is never used again.
    :param miss_ttl: seconds an "unknown kid" negative record is kept,
        so repeated tokens with a random kid do not each trigger a
        refresh request.
    :param max_misses: upper bound of stored negative records; the
        oldest records are evicted beyond this bound.
    """

    def __init__(
        self, fresh_period=3600.0, stale_period=86400.0, miss_ttl=30.0, max_misses=64
    ):
        if fresh_period < 0 or stale_period < 0:
            raise ValueError("fresh_period and stale_period must be >= 0")
        self.fresh_period = float(fresh_period)
        self.stale_period = float(stale_period)
        self.miss_ttl = float(miss_ttl)
        self.max_misses = int(max_misses)
        self._entries = {}
        self._misses = OrderedDict()
        self._sync_locks = {}
        self._refresh_tasks = {}
        self._mu = threading.Lock()

    def now(self):
        return time.monotonic()

    # -- cached entries -------------------------------------------------

    def get_entry(self, key):
        with self._mu:
            return self._entries.get(key)

    def is_fresh(self, entry, now=None):
        if now is None:
            now = self.now()
        return (now - entry.fetched_at) < self.fresh_period

    def get_fresh(self, key):
        """Return the cached key set if it is within the fresh period."""
        entry = self.get_entry(key)
        if entry is not None and self.is_fresh(entry):
            return entry.key_set
        return None

    def get_stale(self, key):
        """Return the cached key set if it is within the stale window."""
        entry = self.get_entry(key)
        if entry is None:
            return None
        if self.now() - entry.fetched_at <= self.fresh_period + self.stale_period:
            return entry.key_set
        return None

    def etag_for(self, key):
        entry = self.get_entry(key)
        return entry.etag if entry is not None else None

    def store(self, key, key_set, etag=None):
        """Store a freshly downloaded key set and clear resolved misses."""
        now = self.now()
        kids = {
            k.get("kid")
            for k in key_set.get("keys", [])
            if isinstance(k, dict) and k.get("kid")
        }
        with self._mu:
            self._entries[key] = KeySetEntry(key_set, now, etag)
            if kids:
                for miss_key in [
                    m for m in self._misses if m[:2] == key and m[2] in kids
                ]:
                    self._misses.pop(miss_key, None)
        return key_set

    def touch(self, key, etag=None):
        """Revalidate the entry in place (HTTP 304 Not Modified)."""
        now = self.now()
        with self._mu:
            entry = self._entries.get(key)
            if entry is not None:
                entry.fetched_at = now
                if etag:
                    entry.etag = etag

    # -- bounded negative records for unknown kids ----------------------

    def _prune_misses(self, now):
        for miss_key in [k for k, exp in self._misses.items() if exp <= now]:
            self._misses.pop(miss_key, None)
        while len(self._misses) > self.max_misses:
            self._misses.popitem(last=False)

    def is_known_miss(self, key, kid):
        """True if kid recently stayed unknown after a refresh."""
        now = self.now()
        with self._mu:
            self._prune_misses(now)
            expires_at = self._misses.get((key[0], key[1], kid))
        return expires_at is not None and expires_at > now

    def record_miss(self, key, kid):
        """Remember that kid was still unknown right after a refresh."""
        now = self.now()
        with self._mu:
            self._prune_misses(now)
            miss_key = (key[0], key[1], kid)
            self._misses[miss_key] = now + self.miss_ttl
            self._misses.move_to_end(miss_key)
            self._prune_misses(now)

    # -- refresh coalescing ----------------------------------------------

    def sync_lock(self, key):
        """Per-key lock used to merge concurrent synchronous refreshes."""
        with self._mu:
            lock = self._sync_locks.get(key)
            if lock is None:
                lock = threading.Lock()
                self._sync_locks[key] = lock
            return lock

    def get_refresh_task(self, key):
        with self._mu:
            return self._refresh_tasks.get(key)

    def set_refresh_task(self, key, task):
        with self._mu:
            self._refresh_tasks[key] = task

    def clear_refresh_task(self, key, task):
        with self._mu:
            if self._refresh_tasks.get(key) is task:
                del self._refresh_tasks[key]


#: Process-wide default cache shared by all OIDC clients. Entries are
#: isolated by (issuer, jwks_uri) so sharing is safe; clients may still
#: use their own instance via the "jwks_cache" attribute.
default_jwks_cache = JWKSCache()
