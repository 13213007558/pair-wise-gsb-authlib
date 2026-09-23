from flask import g
from flask import redirect
from flask import request
from flask import session
from joserfc.errors import JoseError

from authlib.oauth2.jarm import validate_jwt_response

from ..base_client import BaseApp
from ..base_client import OAuth1Mixin
from ..base_client import OAuth2Mixin
from ..base_client import OAuthError
from ..base_client import OpenIDMixin
from ..requests_client import OAuth1Session
from ..requests_client import OAuth2Session


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

            if "response" in request.args:
                params = self._parse_jarm_response(request.args)
            else:
                params = {
                    "code": request.args.get("code"),
                    "state": request.args.get("state"),
                }
        else:
            if "response" in request.form:
                params = self._parse_jarm_response(request.form)
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

    def _parse_jarm_response(self, values):
        """Validate a JARM (JWT Secured Authorization Response Mode)
        ``response`` parameter and extract ``code`` and ``state`` from
        the JWT claims. The signature, algorithm, issuer, audience and
        validity period are verified before any state data is looked up
        or consumed.
        """
        # A plaintext "code" outside the signed JWT must not be honored.
        if values.get("code"):
            raise OAuthError(
                error="invalid_response",
                description="Unexpected 'code' parameter outside the JARM response.",
            )

        metadata = self.server_metadata
        key = metadata.get("jarm_key")
        issuer = metadata.get("jarm_issuer")
        if not key or not issuer:
            raise OAuthError(
                error="invalid_response",
                description=(
                    "Missing JARM configuration ('jarm_key' and 'jarm_issuer')."
                ),
            )

        try:
            claims = validate_jwt_response(
                values["response"],
                key,
                issuer=issuer,
                audience=self.client_id,
                algorithms=metadata.get("jarm_algorithms"),
            )
        except JoseError as error:
            raise OAuthError(
                error="invalid_response",
                description=error.description or str(error),
            ) from error

        error = claims.get("error")
        if error:
            raise OAuthError(error=error, description=claims.get("error_description"))

        return {"code": claims.get("code"), "state": claims.get("state")}
