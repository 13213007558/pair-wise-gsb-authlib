import time

from authlib.oauth2.rfc9126 import InMemoryPushedAuthorizationRequestStore


def test_save_get_delete():
    store = InMemoryPushedAuthorizationRequestStore()
    store.save("uri-1", "client-id", {"scope": "profile"}, 60)

    record = store.get("uri-1")
    assert record["client_id"] == "client-id"
    assert record["data"] == {"scope": "profile"}
    assert record["expires_at"] > time.time()

    store.delete("uri-1")
    assert store.get("uri-1") is None
    # deleting an unknown request_uri does not raise
    store.delete("uri-1")


def test_get_unknown():
    store = InMemoryPushedAuthorizationRequestStore()
    assert store.get("missing") is None


def test_consume_only_once():
    store = InMemoryPushedAuthorizationRequestStore()
    store.save("uri-1", "client-id", {}, 60)
    assert store.consume("uri-1") is True
    assert store.consume("uri-1") is False
    assert store.get("uri-1") is None


def test_consume_unknown():
    store = InMemoryPushedAuthorizationRequestStore()
    assert store.consume("missing") is False


def test_consume_expired():
    store = InMemoryPushedAuthorizationRequestStore()
    store.save("uri-1", "client-id", {}, -1)
    assert store.consume("uri-1") is False
