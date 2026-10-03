from collections import defaultdict

from authlib.deprecate import deprecate

from .errors import InsecureTransportError


class OAuth2Payload:
    @property
    def data(self):
        raise NotImplementedError()

    @property
    def datalist(self) -> defaultdict[str, list]:
        raise NotImplementedError()

    @property
    def client_id(self) -> str:
        """The authorization server issues the registered client a client
        identifier -- a unique string representing the registration
        information provided by the client. The value is extracted from
        request.

        :return: string
        """
        return self.data.get("client_id")

    @property
    def response_type(self) -> str:
        rt = self.data.get("response_type")
        if rt and " " in rt:
            # sort multiple response types
            return " ".join(sorted(rt.split()))
        return rt

    @property
    def grant_type(self) -> str:
        return self.data.get("grant_type")

    @property
    def redirect_uri(self):
        return self.data.get("redirect_uri")

    @property
    def scope(self) -> str:
        return self.data.get("scope")

    @property
    def state(self):
        return self.data.get("state")

    @property
    def resources(self) -> list:
        """All the ``resource`` parameter values defined by RFC 8707. The
        parameter MAY be repeated in a request, so values are read from the
        multi-value ``datalist`` mapping instead of the single-value
        ``data`` dictionary.

        :return: list of strings
        """
        return self.datalist.get("resource", [])


class BasicOAuth2Payload(OAuth2Payload):
    def __init__(self, payload):
        self._data = payload
        self._datalist = {key: [value] for key, value in payload.items()}

    @property
    def data(self):
        return self._data

    @property
    def datalist(self) -> defaultdict[str, list]:
        return self._datalist


class OAuth2Request(OAuth2Payload):
    def __init__(self, method: str, uri: str, body=None, headers=None):
        InsecureTransportError.check(uri)
        #: HTTP method
        self.method = method
        self.uri = uri
        #: HTTP headers
        self.headers = headers or {}

        # Store body for backward compatibility but issue deprecation warning if used
        if body is not None:
            deprecate(
                "'body' parameter in OAuth2Request is deprecated. "
                "Use the payload system instead.",
                version="1.8",
            )
        self._body = body

        self.payload = None

        self.client = None
        self.auth_method = None
        self.user = None
        self.authorization_code = None
        self.refresh_token = None
        self.credential = None
        self._scope = None
        self._resources = None

    @property
    def args(self):
        raise NotImplementedError()

    @property
    def form(self):
        if self._body:
            return self._body
        raise NotImplementedError()

    @property
    def data(self):
        deprecate(
            "'request.data' is deprecated in favor of 'request.payload.data'",
            version="1.8",
        )
        return self.payload.data

    @property
    def datalist(self) -> defaultdict[str, list]:
        deprecate(
            "'request.datalist' is deprecated in favor of 'request.payload.datalist'",
            version="1.8",
        )
        return self.payload.datalist

    @property
    def client_id(self) -> str:
        deprecate(
            "'request.client_id' is deprecated in favor of 'request.payload.client_id'",
            version="1.8",
        )
        return self.payload.client_id

    @property
    def response_type(self) -> str:
        deprecate(
            "'request.response_type' is deprecated in favor of 'request.payload.response_type'",
            version="1.8",
        )
        return self.payload.response_type

    @property
    def grant_type(self) -> str:
        deprecate(
            "'request.grant_type' is deprecated in favor of 'request.payload.grant_type'",
            version="1.8",
        )
        return self.payload.grant_type

    @property
    def redirect_uri(self):
        deprecate(
            "'request.redirect_uri' is deprecated in favor of 'request.payload.redirect_uri'",
            version="1.8",
        )
        return self.payload.redirect_uri

    @property
    def scope(self) -> str:
        if self._scope is not None:
            return self._scope
        return self.payload.scope

    @scope.setter
    def scope(self, value: str):
        self._scope = value

    @property
    def resources(self) -> list:
        """The resolved RFC 8707 resource indicators for this request. Grants
        set this value after validation. The raw requested ``resource``
        parameter values are available on ``request.payload.resources``.
        """
        return self._resources

    @resources.setter
    def resources(self, value):
        self._resources = value

    @property
    def state(self):
        deprecate(
            "'request.state' is deprecated in favor of 'request.payload.state'",
            version="1.8",
        )
        return self.payload.state

    @property
    def body(self):
        deprecate(
            "'request.body' is deprecated. Use the payload system instead.",
            version="1.8",
        )
        return self._body


class JsonPayload:
    @property
    def data(self):
        raise NotImplementedError()


class JsonRequest:
    def __init__(self, method, uri, headers=None):
        self.method = method
        self.uri = uri
        self.headers = headers or {}
        self.payload = None

    @property
    def data(self):
        deprecate(
            "'request.data' is deprecated in favor of 'request.payload.data'",
            version="1.8",
        )
        return self.payload.data
