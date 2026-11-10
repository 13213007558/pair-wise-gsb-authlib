Added
~~~~~

- :rfc:`9449` DPoP is supported on the resource server. The new
  ``authlib.oauth2.rfc9449`` module provides ``DPoPProtector``, an extension
  of ``ResourceProtector`` that validates DPoP proof JWTs and checks their
  binding to the access token ``cnf.jkt``. It verifies the proof type, the
  asymmetric algorithm, the public JWK and signature, ``htm``, ``htu`` without
  query or fragment, the time window, ``ath``, server nonces, and replay with
  an atomic ``ReplayStore`` protocol and an in-memory implementation. A DPoP
  failure is never downgraded to a bearer acceptance.
