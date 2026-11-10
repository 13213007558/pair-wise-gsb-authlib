Added
~~~~~

- The authorization server supports resource indicators (:rfc:`8707`) through
  the new :class:`authlib.oauth2.rfc8707.ResourceIndicators` grant extension.
  It validates the ``resource`` parameter as an absolute URI without a
  fragment, preserves repeated values, binds the authorized set to the
  authorization code and the token, and prevents refresh requests from adding
  a resource that was not previously authorized. Requests without a
  ``resource`` parameter are rejected unless ``allow_without_resource`` is set,
  so the legacy behavior stays explicit.
- :class:`authlib.oauth2.rfc6749.AuthorizationCodeMixin` and
  :class:`authlib.oauth2.rfc6749.TokenMixin` gain ``get_resources``, and the
  SQLAlchemy mixins gain a JSON ``resources`` column.
- Token generators can accept a ``resource`` keyword. The
  :class:`authlib.oauth2.rfc9068.JWTBearerTokenGenerator` now writes the
  authorized resources in the JWT ``aud`` claim. Generators without the new
  keyword keep working unchanged.
