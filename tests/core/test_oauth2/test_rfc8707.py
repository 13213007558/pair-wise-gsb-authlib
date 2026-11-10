import types
from collections import defaultdict

import pytest

from authlib.oauth2.rfc6749 import InvalidRequestError
from authlib.oauth2.rfc6749 import OAuth2Error
from authlib.oauth2.rfc6749.grants import AuthorizationEndpointMixin
from authlib.oauth2.rfc6749.grants import BaseGrant
from authlib.oauth2.rfc6749.grants import TokenEndpointMixin
from authlib.oauth2.rfc8707 import InvalidTargetError
from authlib.oauth2.rfc8707 import ResourceIndicators
from authlib.oauth2.rfc8707 import get_resource_indicators
from authlib.oauth2.rfc8707 import validate_resource_indicator


def make_payload(*resources):
    datalist = defaultdict(list)
    data = {}
    for value in resources:
        datalist["resource"].append(value)
        data["resource"] = value
    return types.SimpleNamespace(data=data, datalist=datalist, state=None)


def make_request(*resources):
    return types.SimpleNamespace(
        payload=make_payload(*resources), client=types.SimpleNamespace()
    )


# -- parameter validation -- #


@pytest.mark.parametrize(
    "value",
    [
        "https://api.example.com/",
        "https://api.example.com/network?x=1&y=2",
        "http://localhost:8080/resource",
        "urn:example:cooperation-context",
    ],
)
def test_valid_resource_indicator(value):
    validate_resource_indicator(value)


@pytest.mark.parametrize(
    "value",
    [
        "not-an-absolute-uri",
        "/relative/path",
        "https://api.example.com/#fragment",
        "https://api.example.com/#",
        "mailto:?",
        " https://api.example.com/",
        "https://api.example.com/ ",
        "",
    ],
)
def test_invalid_resource_indicator(value):
    with pytest.raises(InvalidTargetError):
        validate_resource_indicator(value)


def test_invalid_target_is_oauth2_error():
    assert issubclass(InvalidTargetError, OAuth2Error)
    assert InvalidTargetError.error == "invalid_target"
    assert InvalidTargetError().status_code == 400


def test_get_resource_indicators_keeps_every_value():
    request = make_request(
        "https://a.example/", "https://b.example/", "https://a.example/"
    )
    assert get_resource_indicators(request.payload) == [
        "https://a.example/",
        "https://b.example/",
        "https://a.example/",
    ]


def test_get_resource_indicators_empty():
    assert get_resource_indicators(make_payload()) == []


# -- grant integration -- #


class FakeServer:
    def __init__(self):
        self.authorization_parameters = {}
        self.repeated_authorization_parameters = frozenset()


class CodeGrant(AuthorizationEndpointMixin, TokenEndpointMixin, BaseGrant):
    GRANT_TYPE = "authorization_code"

    def validate_authorization_request_payload(self, redirect_uri):
        return redirect_uri

    def validate_token_request(self, *args):
        pass

    def create_token_response(self):
        pass


def make_code_grant(*resources):
    grant = CodeGrant(make_request(*resources), FakeServer())
    ResourceIndicators()(grant)
    return grant


def test_repeated_resource_is_allowed():
    """The resource parameter is exempt from the no-repeat check."""
    grant = make_code_grant("https://a.example/", "https://a.example/")
    assert "resource" in grant.repeated_authorization_parameters
    grant.validate_no_multiple_request_parameter(grant.request)


def test_other_parameters_still_cannot_repeat():
    grant = make_code_grant("https://a.example/")
    request = grant.request
    request.payload.datalist["state"] = ["one", "again"]
    request.payload.data["state"] = "again"
    with pytest.raises(InvalidRequestError):
        grant.validate_no_multiple_request_parameter(request)


def test_authorization_resources_stored_on_request():
    grant = make_code_grant("https://a.example/", "https://b.example/")
    grant.validate_authorization_request_payload(None)
    assert grant.request.resources == ["https://a.example/", "https://b.example/"]


def test_missing_resource_rejected_by_default():
    grant = make_code_grant()
    with pytest.raises(InvalidTargetError):
        grant.validate_authorization_request_payload(None)


def test_missing_resource_allowed_when_configured():
    grant = CodeGrant(make_request(), FakeServer())
    ResourceIndicators(allow_without_resource=True)(grant)
    grant.validate_authorization_request_payload(None)
    assert grant.request.resources is None


def test_invalid_authorization_resource_redirects():
    grant = make_code_grant("/relative")
    with pytest.raises(InvalidTargetError) as exc:
        grant.validate_authorization_request_payload("https://client.test/cb")
    assert exc.value.redirect_uri == "https://client.test/cb"


def test_token_request_must_stay_within_authorized_set():
    grant = make_code_grant("https://a.example/", "https://b.example/")
    grant.request.authorization_code = types.SimpleNamespace(
        get_resources=lambda: ["https://a.example/", "https://b.example/"]
    )
    grant.request.client = types.SimpleNamespace()
    grant.validate_token_request()
    assert grant.request.resources == ["https://a.example/", "https://b.example/"]


def test_token_request_subset():
    grant = make_code_grant("https://a.example/", "https://b.example/")
    grant.request.authorization_code = types.SimpleNamespace(
        get_resources=lambda: ["https://a.example/", "https://b.example/"]
    )
    grant.request.client = types.SimpleNamespace()
    grant.request.payload = make_payload("https://b.example/")
    grant.validate_token_request()
    assert grant.request.resources == ["https://b.example/"]


def test_token_request_rejects_unauthorized_resource():
    grant = make_code_grant("https://a.example/")
    grant.request.authorization_code = types.SimpleNamespace(
        get_resources=lambda: ["https://a.example/"]
    )
    grant.request.client = types.SimpleNamespace()
    grant.request.payload = make_payload("https://evil.example/")
    with pytest.raises(InvalidTargetError):
        grant.validate_token_request()


def test_client_resource_policy():
    class Restricted(ResourceIndicators):
        def validate_client_resource(self, client, resource):
            return resource == "https://allowed.example/"

    grant = CodeGrant(make_request("https://forbidden.example/"), FakeServer())
    Restricted()(grant)
    grant.request.client = types.SimpleNamespace()
    with pytest.raises(InvalidTargetError):
        grant.validate_authorization_request_payload(None)


# -- refresh grant -- #


class RefreshGrant(TokenEndpointMixin, BaseGrant):
    GRANT_TYPE = "refresh_token"

    def validate_token_request(self, *args):
        pass

    def create_token_response(self):
        pass


def make_refresh_grant(*resources):
    grant = RefreshGrant(make_request(*resources), FakeServer())
    ResourceIndicators()(grant)
    return grant


def test_refresh_cannot_add_resource():
    grant = make_refresh_grant("https://new.example/")
    grant.request.refresh_token = types.SimpleNamespace(
        get_resources=lambda: ["https://a.example/"]
    )
    grant.request.client = types.SimpleNamespace()
    with pytest.raises(InvalidTargetError):
        grant.validate_token_request()


def test_refresh_keeps_previous_resources_without_parameter():
    grant = make_refresh_grant()
    grant.request.refresh_token = types.SimpleNamespace(
        get_resources=lambda: ["https://a.example/", "https://b.example/"]
    )
    grant.request.client = types.SimpleNamespace()
    grant.validate_token_request()
    assert grant.request.resources == ["https://a.example/", "https://b.example/"]


# -- token generator plumbing -- #


def test_extension_passes_resources_to_generate_token():
    grant = make_code_grant("https://a.example/")
    grant.request.resources = ["https://a.example/"]
    captured = {}

    def original(**kwargs):
        captured.update(kwargs)
        return {"access_token": "opaque"}

    extension = ResourceIndicators()
    result = extension.pass_resources_to_token_generator(
        grant, original, grant_type="authorization_code"
    )
    assert result == {"access_token": "opaque"}
    assert captured["resource"] == ["https://a.example/"]


def test_extension_omits_resource_without_authorized_set():
    grant = make_code_grant()
    grant.request.resources = None
    captured = {}

    def original(**kwargs):
        captured.update(kwargs)
        return {"access_token": "opaque"}

    ResourceIndicators().pass_resources_to_token_generator(
        grant, original, grant_type="authorization_code"
    )
    assert "resource" not in captured


def test_server_forwards_resource_only_to_supporting_generator():
    from authlib.oauth2.rfc6749.authorization_server import _generator_accepts_resource

    def legacy(
        grant_type,
        client,
        user=None,
        scope=None,
        expires_in=None,
        include_refresh_token=True,
    ):
        return {}

    def with_resource(
        grant_type,
        client,
        user=None,
        scope=None,
        expires_in=None,
        include_refresh_token=True,
        resource=None,
    ):
        return {}

    def with_kwargs(**kwargs):
        return {}

    assert not _generator_accepts_resource(legacy)
    assert _generator_accepts_resource(with_resource)
    assert _generator_accepts_resource(with_kwargs)
