"""authlib.oauth2.rfc9449.store.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Storage interface for DPoP replay protection and nonce handling.
The application provides an implementation backed by its own
database; the clock used by the validators is injectable so tests
and deployments can control time.
"""


class DPoPStateStore:
    """Interface for DPoP server-side state.

    Implementations MUST make 'register_jti' atomic: when the same
    (jkt, jti) pair is registered concurrently, at most one call may
    return True. A uniqueness constraint in the underlying database
    is the recommended way to achieve this.
    """

    def register_jti(self, jkt, jti, expires_at):
        """Atomically record a proof 'jti' for the given key thumbprint.

        :param jkt: JWK SHA-256 thumbprint of the DPoP key
        :param jti: the unique identifier of the proof JWT
        :param expires_at: timestamp after which the entry may be purged
        :return: True if the jti was newly registered, False if it
            was already seen (replay)
        """
        raise NotImplementedError()

    def get_nonce(self):
        """Return the nonce value the server currently expects in DPoP
        proofs, or None if no nonce has been issued yet."""
        raise NotImplementedError()

    def create_nonce(self):
        """Generate, persist and return a fresh nonce value. The value
        is sent to the client in the 'DPoP-Nonce' header and becomes
        the value expected by subsequent 'get_nonce' calls."""
        raise NotImplementedError()
