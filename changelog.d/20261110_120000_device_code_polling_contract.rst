Changed
~~~~~~~

- ``DeviceCodeGrant`` enforces the RFC 8628 polling interval through the new
  ``DevicePollingStore`` contract and its ``InMemoryDevicePollingStore``
  reference implementation. ``check_and_advance`` rate-limits a poll
  atomically, applies the ``slow_down`` interval increase to later polls,
  and ``mark_consumed`` prevents a device code from issuing two tokens. The
  clock is injectable so the state machine can be tested with virtual time.
  The fixed decision order is expiry, already-consumed, user decision
  (approval or denial), then rate limit: approval on a too-early poll still
  returns the token instead of ``slow_down``.

Deprecated
~~~~~~~~~~

- ``DeviceCodeGrant.should_slow_down`` is deprecated. Implement
  ``get_polling_store`` with a ``DevicePollingStore`` instead. The hook keeps
  working, with a deprecation warning, while ``get_polling_store`` returns
  ``None``.
