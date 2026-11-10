"""authlib.oauth2.rfc8628.
~~~~~~~~~~~~~~~~~~~~~~

This module represents an implementation of
OAuth 2.0 Device Authorization Grant.

:rfc:`8628`
"""

from .device_code import DEVICE_CODE_GRANT_TYPE
from .device_code import DeviceCodeGrant
from .endpoint import DeviceAuthorizationEndpoint
from .errors import AuthorizationPendingError
from .errors import ExpiredTokenError
from .errors import SlowDownError
from .models import DeviceCredentialDict
from .models import DeviceCredentialMixin
from .polling import DEFAULT_INTERVAL
from .polling import SLOW_DOWN_STEP
from .polling import DevicePollingStore
from .polling import InMemoryDevicePollingStore
from .polling import PollingAdvance
from .polling import PollingVerdict

__all__ = [
    "DeviceAuthorizationEndpoint",
    "DeviceCodeGrant",
    "DEVICE_CODE_GRANT_TYPE",
    "DeviceCredentialMixin",
    "DeviceCredentialDict",
    "AuthorizationPendingError",
    "SlowDownError",
    "ExpiredTokenError",
    "DevicePollingStore",
    "InMemoryDevicePollingStore",
    "PollingAdvance",
    "PollingVerdict",
    "DEFAULT_INTERVAL",
    "SLOW_DOWN_STEP",
]
