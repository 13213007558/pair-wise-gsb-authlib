import time


def create_query_client_func(session, client_model):
    """Create an ``query_client`` function that can be used in authorization
    server.

    :param session: SQLAlchemy session
    :param client_model: Client model class
    """

    def query_client(client_id):
        q = session.query(client_model)
        return q.filter_by(client_id=client_id).first()

    return query_client


def create_save_token_func(session, token_model):
    """Create an ``save_token`` function that can be used in authorization
    server.

    :param session: SQLAlchemy session
    :param token_model: Token model class
    """

    def save_token(token, request):
        if request.user:
            user_id = request.user.get_user_id()
        else:
            user_id = None
        client = request.client
        item = token_model(client_id=client.client_id, user_id=user_id, **token)
        session.add(item)
        session.commit()

    return save_token


def create_query_token_func(session, token_model):
    """Create an ``query_token`` function for revocation, introspection
    token endpoints.

    :param session: SQLAlchemy session
    :param token_model: Token model class
    """

    def query_token(token, token_type_hint):
        q = session.query(token_model)
        if token_type_hint == "access_token":
            return q.filter_by(access_token=token).first()
        elif token_type_hint == "refresh_token":
            return q.filter_by(refresh_token=token).first()
        # without token_type_hint
        item = q.filter_by(access_token=token).first()
        if item:
            return item
        return q.filter_by(refresh_token=token).first()

    return query_token


def create_revocation_endpoint(session, token_model):
    """Create a revocation endpoint class with SQLAlchemy session
    and token model.

    :param session: SQLAlchemy session
    :param token_model: Token model class
    """
    from authlib.oauth2.rfc7009 import RevocationEndpoint

    query_token = create_query_token_func(session, token_model)

    class _RevocationEndpoint(RevocationEndpoint):
        def query_token(self, token, token_type_hint):
            return query_token(token, token_type_hint)

        def revoke_token(self, token, request):
            now = int(time.time())
            hint = request.form.get("token_type_hint")
            token.access_token_revoked_at = now
            if hint != "access_token":
                token.refresh_token_revoked_at = now
            session.add(token)
            session.commit()

    return _RevocationEndpoint


def create_bearer_token_validator(session, token_model):
    """Create an bearer token validator class with SQLAlchemy session
    and token model.

    :param session: SQLAlchemy session
    :param token_model: Token model class
    """
    from authlib.oauth2.rfc6750 import BearerTokenValidator

    class _BearerTokenValidator(BearerTokenValidator):
        def authenticate_token(self, token_string):
            q = session.query(token_model)
            return q.filter_by(access_token=token_string).first()

    return _BearerTokenValidator


def create_token_family_revocation_endpoint(session, token_model):
    """Create a revocation endpoint class with token-family semantics.
    Revoking a token also revokes all of its descendants; a request
    with ``family=true`` revokes the whole token family.

    The token model must have ``id`` and ``parent_id`` columns (see
    :class:`OAuth2TokenFamilyMixin`).

    :param session: SQLAlchemy session
    :param token_model: Token model class
    """
    from authlib.oauth2.token_family import TokenFamilyRevocationEndpoint

    query_token = create_query_token_func(session, token_model)

    def _walk_descendants(token):
        descendants = []
        seen = {token.id}
        parent_ids = [token.id]
        while parent_ids:
            children = (
                session.query(token_model)
                .filter(token_model.parent_id.in_(parent_ids))
                .all()
            )
            children = [child for child in children if child.id not in seen]
            seen.update(child.id for child in children)
            descendants.extend(children)
            parent_ids = [child.id for child in children]
        return descendants

    def _find_root(token):
        root = token
        seen = {root.id}
        while root.parent_id is not None and root.parent_id not in seen:
            seen.add(root.parent_id)
            root = session.get(token_model, root.parent_id)
        return root

    class _TokenFamilyRevocationEndpoint(TokenFamilyRevocationEndpoint):
        def query_token(self, token, token_type_hint):
            return query_token(token, token_type_hint)

        def revoke_token(self, token, request):
            now = int(time.time())
            token.access_token_revoked_at = now
            token.refresh_token_revoked_at = now
            session.add(token)
            session.commit()

        def query_token_descendants(self, token):
            return _walk_descendants(token)

        def query_token_family(self, token):
            root = _find_root(token)
            return [root] + _walk_descendants(root)

    return _TokenFamilyRevocationEndpoint


def create_refresh_token_family_grant(session, token_model):
    """Create a refresh_token grant class that rotates refresh tokens
    atomically and links every new token to its parent. Developers
    still need to implement ``authenticate_user``::

        RefreshTokenFamilyGrant = create_refresh_token_family_grant(db.session, Token)


        class MyRefreshTokenGrant(RefreshTokenFamilyGrant):
            def authenticate_user(self, credential):
                return User.get(credential.user_id)

    The rotation revokes the old credential with a conditional
    ``UPDATE ... WHERE refresh_token_revoked_at = 0`` and inserts the
    child token in the same transaction, so two concurrent refresh
    requests on the same token produce at most one new family member,
    and an already revoked token can never be resurrected.

    The token model must have ``id`` and ``parent_id`` columns (see
    :class:`OAuth2TokenFamilyMixin`).

    :param session: SQLAlchemy session
    :param token_model: Token model class
    """
    from sqlalchemy import update

    from authlib.oauth2.rfc6749 import InvalidGrantError
    from authlib.oauth2.token_family import RefreshTokenFamilyGrant

    class _RefreshTokenFamilyGrant(RefreshTokenFamilyGrant):
        def authenticate_refresh_token(self, refresh_token):
            item = (
                session.query(token_model)
                .filter_by(refresh_token=refresh_token)
                .first()
            )
            if item and not item.refresh_token_revoked_at:
                return item

        def rotate_token(self, token, refresh_token):
            now = int(time.time())
            # capture every value we need before ending the current
            # transaction: no SELECT may happen between the commit and
            # the conditional UPDATE, or the new transaction could read
            # a stale snapshot under concurrency
            parent_id = refresh_token.id
            client_id = refresh_token.client_id
            if self.request.user:
                user_id = self.request.user.get_user_id()
            else:
                user_id = None

            # end the validation transaction so the conditional UPDATE
            # below is the first statement of a fresh one
            session.commit()
            stmt = (
                update(token_model)
                .where(token_model.id == parent_id)
                .where(token_model.refresh_token_revoked_at == 0)
                .values(
                    access_token_revoked_at=now,
                    refresh_token_revoked_at=now,
                )
            )
            result = session.execute(stmt)
            if result.rowcount != 1:
                # a concurrent refresh or a revocation won the race;
                # the old token stays revoked and no child is created
                session.rollback()
                raise InvalidGrantError("The refresh token is no longer active.")

            item = token_model(
                client_id=client_id,
                user_id=user_id,
                parent_id=parent_id,
                **token,
            )
            session.add(item)
            session.commit()

    return _RefreshTokenFamilyGrant
