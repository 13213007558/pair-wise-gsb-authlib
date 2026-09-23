import time


class DeviceCredentialMixin:
    def get_client_id(self):
        raise NotImplementedError()

    def get_scope(self):
        raise NotImplementedError()

    def get_user_code(self):
        raise NotImplementedError()

    def get_interval(self):
        """The minimum amount of time in seconds that the client SHOULD
        wait between polling requests to the token endpoint. Return
        ``None`` if no polling interval is enforced.
        """
        raise NotImplementedError()

    def is_expired(self):
        raise NotImplementedError()


class DeviceCredentialDict(dict, DeviceCredentialMixin):
    def get_client_id(self):
        return self["client_id"]

    def get_scope(self):
        return self.get("scope")

    def get_user_code(self):
        return self["user_code"]

    def get_nonce(self):
        return self.get("nonce")

    def get_auth_time(self):
        return self.get("auth_time")

    def get_interval(self):
        return self.get("interval")

    def is_expired(self):
        expires_at = self.get("expires_at")
        if expires_at is not None:
            return expires_at < time.time()
        return False
