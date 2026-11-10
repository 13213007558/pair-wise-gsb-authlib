"""Reusable polling state for the Device Authorization Grant.

:rfc:`8628#section-3.5`

Each device code is polled at the token endpoint until the end user approves
or denies it, or the code expires. While the request is pending the client
must wait at least ``interval`` seconds between polls. A poll that arrives too
early gets a ``slow_down`` response and the interval grows by
:data:`SLOW_DOWN_STEP` seconds for every later poll as well.

The checks that used to live in several hooks of :class:`DeviceCodeGrant` are
combined here into operations a storage backend can execute atomically. Two
polls arriving at the same time cannot both be admitted against the old
interval, because :meth:`DevicePollingStore.check_and_advance` advances the
state of one of them before the other reads it.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import Protocol
from typing import runtime_checkable

#: The default polling interval in seconds, used when the device
#: authorization response does not carry an ``interval`` parameter.
DEFAULT_INTERVAL = 5

#: The number of seconds added to the interval on every ``slow_down``
#: response, per RFC 8628 section 3.5.
SLOW_DOWN_STEP = 5


class PollingVerdict(str, Enum):
    """Whether a poll was admitted by the rate limit."""

    READY = "ready"
    TOO_SOON = "too_soon"


@dataclass(frozen=True)
class PollingAdvance:
    """Result of :meth:`DevicePollingStore.check_and_advance`."""

    verdict: PollingVerdict
    interval: float
    consumed: bool = False


@runtime_checkable
class DevicePollingStore(Protocol):
    """Storage of the per-device-code polling state.

    Every method reads *and* writes the state of one device code in a single
    atomic operation. Backends that are not atomic by default, such as a
    relational database, must serialize the operation with a row lock or an
    equivalent mechanism; a Redis backend typically implements it with a Lua
    script.
    """

    def check_and_advance(
        self,
        device_code: str,
        interval: float,
        *,
        now: float,
    ) -> PollingAdvance:
        """Atomically rate-limit one poll.

        A poll is admitted when no previous poll was recorded, or when at
        least ``interval`` seconds elapsed since the previous one. An
        admitted poll records ``now`` as the time of the latest poll. A
        rejected poll still records ``now`` and increases the interval by
        :data:`SLOW_DOWN_STEP` seconds, so the increased wait applies to this
        and all subsequent requests.

        :param device_code: key identifying the device authorization session.
        :param interval: the interval currently advertised to the client.
        :param now: current time from the injected clock, in seconds.
        :return: the verdict, the interval that applies after this poll, and
            whether the device code was already consumed by a previous
            successful poll.
        """
        ...

    def mark_consumed(self, device_code: str, *, now: float) -> None:
        """Atomically mark the device code as consumed.

        Called once, right before an access token is issued, so that a later
        poll with the same device code cannot consume the grant twice.
        """
        ...


@dataclass
class _PollingRecord:
    last_poll_at: float | None = None
    interval: float = DEFAULT_INTERVAL
    consumed: bool = False


class InMemoryDevicePollingStore:
    """Reference :class:`DevicePollingStore` backed by process memory.

    It serializes every operation with a lock, which makes it suitable for a
    single-process server and for tests with a virtual clock. Multi-process
    deployments need a shared backend implementing the same contract, for
    example Redis with a Lua script.
    """

    def __init__(self, *, clock: Callable[[], float] = time.monotonic):
        self._clock = clock
        self._records: dict[str, _PollingRecord] = {}
        self._lock = threading.RLock()

    def check_and_advance(
        self,
        device_code: str,
        interval: float,
        *,
        now: float | None = None,
    ) -> PollingAdvance:
        if now is None:
            now = self._clock()
        with self._lock:
            record = self._records.get(device_code)
            if record is None:
                record = _PollingRecord(interval=float(interval))
                self._records[device_code] = record
            else:
                record.interval = max(record.interval, float(interval))

            already_consumed = record.consumed
            if already_consumed:
                # a consumed code cannot be polled again; the rate limit is
                # irrelevant and must not keep growing the interval
                verdict = PollingVerdict.TOO_SOON
            elif record.last_poll_at is None:
                verdict = PollingVerdict.READY
            elif now >= record.last_poll_at + record.interval:
                verdict = PollingVerdict.READY
            else:
                verdict = PollingVerdict.TOO_SOON
                record.interval += SLOW_DOWN_STEP

            record.last_poll_at = now
            return PollingAdvance(
                verdict=verdict,
                interval=record.interval,
                consumed=already_consumed,
            )

    def mark_consumed(self, device_code: str, *, now: float | None = None) -> None:
        if now is None:
            now = self._clock()
        with self._lock:
            record = self._records.setdefault(device_code, _PollingRecord())
            record.consumed = True
            record.last_poll_at = now

    def remove(self, device_code: str) -> None:
        """Forget a device code, for example when it expires."""
        with self._lock:
            self._records.pop(device_code, None)
