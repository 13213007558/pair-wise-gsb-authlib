Added
~~~~~

- :class:`~authlib.oauth2.rfc8693.TokenExchangeGrant` implements the OAuth 2.0
  Token Exchange grant (:rfc:`8693`) as a registerable token endpoint grant.
  It accepts and issues access tokens only, validates the ``subject_token``
  and the optional ``actor_token`` through dedicated interfaces, and lets an
  authorization hook decide whether delegation is allowed, for which
  resources and with which scope. The user subject is preserved and the
  delegation ``act`` chain distinguishes the current actor from historical
  actors.
