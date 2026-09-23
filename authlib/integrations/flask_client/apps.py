from flask import g
from flask import redirect
from flask import request
from flask import session
from joserfc.errors import InvalidKeyIdError
from joserfc.jwk import KeySet

from ...oauth2.jarm import InvalidJARMResponseError
from ...oauth2.jarm import validate_jarm_response
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
        leeway = kwargs.pop("leeway", 120)
        if request.method == "GET":
            error = request.args.get("error")
            if error:
                description = request.args.get("error_description")
                raise OAuthError(error=error, description=description)
            values = request.args
        else:
            values = request.form

        response_jwt = values.get("response")
        if response_jwt:
            params = self._parse_jarm_response(values, response_jwt, leeway)
        else:
            params = {
                "code": values.get("code"),
                "state": values.get("state"),
            }

        state_data = self.framework.get_state_data(session, params.get("state"))
        self.framework.clear_state_data(session, params.get("state"))
        params = self._format_state_params(state_data, params)

        claims_options = kwargs.pop("claims_options", None)
        claims_cls = kwargs.pop("claims_cls", None)
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

    def _parse_jarm_response(self, values, response_jwt, leeway):
        # JARM: the "response" parameter is the only carrier of the
        # authorization response; plaintext parameters next to it could
        # be injected by an attacker and MUST be rejected.
        if values.get("code") or values.get("state") or values.get("error"):
            raise OAuthError(
                error="invalid_response",
                description="Plaintext parameters are not allowed next to the "
                'JARM "response" parameter.',
            )
        try:
            claims = self.validate_jarm_response(response_jwt, leeway=leeway)
        except InvalidJARMResponseError as exc:
            raise OAuthError(error=exc.error, description=exc.description) from exc
        error = claims.get("error")
        if error:
            raise OAuthError(error=error, description=claims.get("error_description"))
        return {"code": claims.get("code"), "state": claims.get("state")}

    def validate_jarm_response(self, response_jwt, leeway=120):
        """Validate a JWT Secured Authorization Response (JARM) and return
        its claims. The signature, signing algorithm, issuer, audience and
        expiration are verified against the server metadata.
        """
        metadata = self.load_server_metadata()
        issuer = metadata.get("issuer")
        if not issuer:
            raise RuntimeError('Missing "issuer" in metadata')
        alg_values = metadata.get("authorization_signing_alg_values_supported")
        key_set = KeySet.import_key_set(self.fetch_jwk_set())
        try:
            return validate_jarm_response(
                response_jwt,
                key=key_set,
                issuer=issuer,
                audience=self.client_id,
                algorithms=alg_values,
                leeway=leeway,
            )
        except InvalidKeyIdError:
            key_set = KeySet.import_key_set(self.fetch_jwk_set(force=True))
            return validate_jarm_response(
                response_jwt,
                key=key_set,
                issuer=issuer,
                audience=self.client_id,
                algorithms=alg_values,
                leeway=leeway,
            )
