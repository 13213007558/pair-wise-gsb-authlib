"""authlib.oauth2.rfc9449.store.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Storage interface for DPoP nonce and replay detection. The storage
itself is provided by the application (database, cache, ...).

https://www.rfc-editor.org/rfc/rfc9449#section-8
https://www.rfc-editor.org/rfc/rfc9449#section-11.1
"""

__all__ = ["DPoPStateStore"]


class DPoPStateStore:
    """Interface of the storage for DPoP nonces and replayed proof
    tracking. Applications MUST implement this interface with their
    own storage backend.
    """

    def get_nonce(self):
        """Return the nonce value that the server currently requires in
        DPoP proofs, or None if no nonce is required. When the returned
        value does not match the "nonce" claim of a proof, a
        "use_dpop_nonce" challenge is issued with this value in the
        "DPoP-Nonce" response header.

        :return: nonce string or None
        """
        return None

    def register_jti(self, jkt, jti, expires_at):
        """Atomically register the "jti" of a proof for replay
        detection. This method MUST be atomic: when the same proof
        arrives concurrently, at most one call may return True.

        :param jkt: the JWK thumbprint of the proof public key
        :param jti: the "jti" claim of the proof
        :param expires_at: UNIX timestamp after which the record can
            be purged from the storage
        :return: True if the (jkt, jti) pair is newly registered,
            False if it was seen before (a replay)
        """
        raise NotImplementedError()
