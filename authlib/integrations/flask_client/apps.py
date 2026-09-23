import json

from flask import Response
from flask import g
from flask import redirect
from flask import request
from flask import session
from joserfc.errors import JoseError

from ..base_client import BaseApp
from ..base_client import OAuth1Mixin
from ..base_client import OAuth2Mixin
from ..base_client import OAuthError
from ..base_client import OpenIDMixin
from ..requests_client import OAuth1Session
from ..requests_client import OAuth2Session
from .logout import InMemoryLogoutStore


class FlaskAppMixin:
    @property
    def token(self):
        attr = f"_oauth_token_{self.name}"
        token = g.get(attr)
        if token:
            return token
        if self._fetch_token:
            token = self._fetch_token()
            self.token = token
            return token

    @token.setter
    def token(self, token):
        attr = f"_oauth_token_{self.name}"
        setattr(g, attr, token)

    def _get_requested_token(self, *args, **kwargs):
        return self.token

    def save_authorize_data(self, **kwargs):
        state = kwargs.pop("state", None)
        if state:
            self.framework.set_state_data(session, state, kwargs)
        else:
            raise RuntimeError("Missing state value")

    def authorize_redirect(self, redirect_uri=None, **kwargs):
        """Create a HTTP Redirect for Authorization Endpoint.

        :param redirect_uri: Callback or redirect URI for authorization.
        :param kwargs: Extra parameters to include.
        :return: A HTTP redirect response.
        """
        rv = self.create_authorization_url(redirect_uri, **kwargs)
        self.save_authorize_data(redirect_uri=redirect_uri, **rv)
        return redirect(rv["url"])


class FlaskOAuth1App(FlaskAppMixin, OAuth1Mixin, BaseApp):
    client_cls = OAuth1Session

    def authorize_access_token(self, **kwargs):
        """Fetch access token in one step.

        :return: A token dict.
        """
        params = request.args.to_dict(flat=True)
        state = params.get("oauth_token")
        if not state:
            raise OAuthError(description='Missing "oauth_token" parameter')

        data = self.framework.get_state_data(session, state)
        if not data:
            raise OAuthError(description='Missing "request_token" in temporary data')

        params["request_token"] = data["request_token"]
        params.update(kwargs)
        self.framework.clear_state_data(session, state)
        token = self.fetch_access_token(**params)
        self.token = token
        return token


class FlaskOAuth2App(FlaskAppMixin, OAuth2Mixin, OpenIDMixin, BaseApp):
    client_cls = OAuth2Session

    @property
    def logout_store(self):
        """The :class:`LogoutTokenStore` used by back-channel logout.

        Defaults to a per-client in-memory store; assign a custom
        persistence adapter to share replay records and the session index
        between processes.
        """
        store = getattr(self, "_logout_store", None)
        if store is None:
            store = self._logout_store = InMemoryLogoutStore()
        return store

    @logout_store.setter
    def logout_store(self, store):
        self._logout_store = store

    def handle_backchannel_logout(
        self, logout_token=None, on_logout=None, store=None, leeway=120
    ):
        """Handle an OpenID Connect Back-Channel Logout request.

        This endpoint is fully independent of the browser session cookie
        and of the OAuth ``state``/CSRF data; it only reads the
        ``logout_token`` form parameter of the provider's POST request.

        :param logout_token: the logout token JWT, defaults to the current
            request's ``logout_token`` form parameter.
        :param on_logout: optional callback invoked as
            ``on_logout(session_ids, claims)`` so the application can
            invalidate the matched local sessions.
        :param store: a :class:`LogoutTokenStore` persistence adapter,
            defaults to :attr:`logout_store`.
        :param leeway: leeway in seconds for time based claims.
        :return: A HTTP 200 response on success (including idempotent
            replays), or a 400 JSON error response.
        """
        if logout_token is None:
            logout_token = request.form.get("logout_token")
        if not logout_token:
            return _backchannel_logout_error(
                "invalid_request", 'Missing "logout_token" parameter'
            )

        try:
            claims = self.parse_logout_token(logout_token, leeway=leeway)
        except JoseError as error:
            return _backchannel_logout_error("invalid_request", str(error))

        if store is None:
            store = self.logout_store
        store.apply_logout(claims, on_logout)
        return _backchannel_logout_response(200)

    def logout_redirect(
        self, post_logout_redirect_uri=None, id_token_hint=None, **kwargs
    ):
        """Create a HTTP Redirect for End Session Endpoint (RP-Initiated Logout).

        :param post_logout_redirect_uri: URI to redirect after logout.
        :param id_token_hint: ID Token previously issued to the RP.
        :param kwargs: Extra parameters (state, client_id, logout_hint, ui_locales).
        :return: A HTTP redirect response.
        """
        result = self.create_logout_url(
            post_logout_redirect_uri=post_logout_redirect_uri,
            id_token_hint=id_token_hint,
            **kwargs,
        )
        if result.get("state"):
            self.framework.set_state_data(
                session,
                result["state"],
                {
                    "post_logout_redirect_uri": post_logout_redirect_uri,
                },
            )
        return redirect(result["url"])

    def validate_logout_response(self):
        """Validate the state parameter from the logout callback.

        :return: The state data dict.
        :raises OAuthError: If state is missing or invalid.
        """
        state = request.args.get("state")
        if not state:
            raise OAuthError(description='Missing "state" parameter')

        state_data = self.framework.get_state_data(session, state)
        if not state_data:
            raise OAuthError(description='Invalid "state" parameter')

        self.framework.clear_state_data(session, state)
        return state_data

    def authorize_access_token(self, **kwargs):
        """Fetch access token in one step.

        :return: A token dict.
        """
        if request.method == "GET":
            error = request.args.get("error")
            if error:
                description = request.args.get("error_description")
                raise OAuthError(error=error, description=description)

            params = {
                "code": request.args.get("code"),
                "state": request.args.get("state"),
            }
        else:
            params = {
                "code": request.form.get("code"),
                "state": request.form.get("state"),
            }

        state_data = self.framework.get_state_data(session, params.get("state"))
        self.framework.clear_state_data(session, params.get("state"))
        params = self._format_state_params(state_data, params)

        claims_options = kwargs.pop("claims_options", None)
        claims_cls = kwargs.pop("claims_cls", None)
        leeway = kwargs.pop("leeway", 120)
        token = self.fetch_access_token(**params, **kwargs)
        self.token = token

        if "id_token" in token and "nonce" in state_data:
            userinfo = self.parse_id_token(
                token,
                nonce=state_data["nonce"],
                claims_options=claims_options,
                claims_cls=claims_cls,
                leeway=leeway,
            )
            token["userinfo"] = userinfo
        return token


def _backchannel_logout_response(status, payload=None):
    if payload is None:
        response = Response(status=status)
    else:
        response = Response(
            json.dumps(payload), status=status, content_type="application/json"
        )
    response.headers["Cache-Control"] = "no-cache, no-store"
    response.headers["Pragma"] = "no-cache"
    return response


def _backchannel_logout_error(error, description=None):
    payload = {"error": error}
    if description:
        payload["error_description"] = description
    return _backchannel_logout_response(400, payload)
