import threading

import pytest

from authlib.oauth2.rfc8628 import DEFAULT_INTERVAL
from authlib.oauth2.rfc8628 import SLOW_DOWN_STEP
from authlib.oauth2.rfc8628 import InMemoryDevicePollingStore
from authlib.oauth2.rfc8628 import PollingVerdict


class FakeClock:
    """Virtual monotonic clock advanced explicitly in milliseconds."""

    def __init__(self, start=1_000.0):
        self._now = float(start)

    def __call__(self):
        return self._now

    def advance(self, milliseconds):
        self._now += milliseconds / 1000.0


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def store(clock):
    return InMemoryDevicePollingStore(clock=clock)


def test_first_poll_is_admitted_and_records_interval(store, clock):
    result = store.check_and_advance("device-1", 5, now=clock())
    assert result.verdict is PollingVerdict.READY
    assert result.interval == 5
    assert result.consumed is False


def test_poll_at_exact_interval_boundary_is_admitted(store, clock):
    store.check_and_advance("device-1", 5, now=clock())
    clock.advance(5_000)
    result = store.check_and_advance("device-1", 5, now=clock())
    assert result.verdict is PollingVerdict.READY


def test_early_poll_is_slowed_down_and_increases_interval(store, clock):
    store.check_and_advance("device-1", 5, now=clock())
    clock.advance(1_000)
    result = store.check_and_advance("device-1", 5, now=clock())
    assert result.verdict is PollingVerdict.TOO_SOON
    assert result.interval == 5 + SLOW_DOWN_STEP

    # the increased wait applies to every later poll, not just this one
    clock.advance(5_000 - 1)
    result = store.check_and_advance("device-1", 5, now=clock())
    assert result.verdict is PollingVerdict.TOO_SOON
    assert result.interval == 5 + 2 * SLOW_DOWN_STEP

    # enough time has now elapsed to satisfy the doubled interval
    clock.advance(15_000)
    result = store.check_and_advance("device-1", 5, now=clock())
    assert result.verdict is PollingVerdict.READY
    # a ready poll keeps the interval accumulated by slow_down responses
    assert result.interval == 5 + 2 * SLOW_DOWN_STEP


def test_millisecond_advance_does_not_wait(store, clock):
    """Polling decisions use the injected clock, not real time."""
    store.check_and_advance("device-1", 0.25, now=clock())
    clock.advance(249)
    assert store.check_and_advance("device-1", 0.25, now=clock()).verdict is (
        PollingVerdict.TOO_SOON
    )

    # a fresh device code, so no slow_down step is in effect yet
    store.check_and_advance("device-2", 0.25, now=clock())
    clock.advance(250)
    assert store.check_and_advance("device-2", 0.25, now=clock()).verdict is (
        PollingVerdict.READY
    )


def test_device_codes_are_rate_limited_independently(store, clock):
    store.check_and_advance("device-1", 5, now=clock())
    clock.advance(100)
    first = store.check_and_advance("device-1", 5, now=clock())
    second = store.check_and_advance("device-2", 5, now=clock())
    assert first.verdict is PollingVerdict.TOO_SOON
    assert second.verdict is PollingVerdict.READY


def test_consumed_code_is_reported_and_not_revived(store, clock):
    store.check_and_advance("device-1", 5, now=clock())
    store.mark_consumed("device-1", now=clock())
    clock.advance(60_000)
    result = store.check_and_advance("device-1", 5, now=clock())
    assert result.consumed is True
    # a consumed code no longer participates in rate limiting
    assert result.interval == 5
    store.mark_consumed("device-1", now=clock())
    assert store.check_and_advance("device-1", 5, now=clock()).consumed is True


def test_mark_consumed_works_without_prior_poll(store, clock):
    store.mark_consumed("never-polled", now=clock())
    result = store.check_and_advance("never-polled", 5, now=clock())
    assert result.consumed is True


def test_concurrent_polls_cannot_both_use_the_old_interval(clock):
    store = InMemoryDevicePollingStore(clock=clock)
    store.check_and_advance("device-1", 5, now=clock())
    clock.advance(10)
    verdicts = []
    barrier = threading.Barrier(8)

    def poll():
        barrier.wait()
        verdicts.append(store.check_and_advance("device-1", 5, now=clock()).verdict)

    threads = [threading.Thread(target=poll) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert verdicts.count(PollingVerdict.READY) == 0
    assert verdicts.count(PollingVerdict.TOO_SOON) == 8
    # every rejected poll adds one step, so the interval grows by 8 steps
    clock.advance(60_000)
    assert store.check_and_advance("device-1", 5, now=clock()).interval == (
        5 + 8 * SLOW_DOWN_STEP
    )


def test_injected_clock_is_used_by_default(clock):
    store = InMemoryDevicePollingStore(clock=clock)
    store.check_and_advance("device-1", DEFAULT_INTERVAL)
    clock.advance(10)
    assert store.check_and_advance("device-1", DEFAULT_INTERVAL).verdict is (
        PollingVerdict.TOO_SOON
    )
