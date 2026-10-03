import pytest

from authlib.oauth2.rfc6749.requests import BasicOAuth2Payload
from authlib.oauth2.rfc8707 import InvalidTargetError
from authlib.oauth2.rfc8707 import ResourcePolicy
from authlib.oauth2.rfc8707 import get_resource_indicators
from authlib.oauth2.rfc8707 import is_absolute_uri
from authlib.oauth2.rfc8707 import unique_resource_indicators
from authlib.oauth2.rfc8707 import validate_resource_indicators
from authlib.oauth2.rfc6749 import AuthorizationServer
from authlib.oauth2.rfc6749.parameters import prepare_grant_uri
from authlib.oauth2.rfc6749.parameters import prepare_token_request


@pytest.mark.parametrize(
    "value,expected",
    [
        ("https://billing.example.net", True),
        ("https://example.com/api", True),
        ("urn:example:resource", False),  # no authority
        ("relative/path", False),
        ("https://example.com/path#fragment", False),
        ("", False),
        (None, False),
        ("https://example.com/ path", False),
        ("1not-scheme://example.com", False),
    ],
)
def test_is_absolute_uri(value, expected):
    assert is_absolute_uri(value) is expected


def test_get_resource_indicators_keeps_repeated_values():
    payload = BasicOAuth2Payload({
        "client_id": "client-id",
        "resource": "https://a.example",  # single-valued dict would lose rest
    })
    payload._datalist["resource"] = [
        "https://a.example",
        "https://b.example",
        "https://a.example",
    ]
    assert get_resource_indicators(payload) == [
        "https://a.example",
        "https://b.example",
        "https://a.example",
    ]


def test_validate_resource_indicators_raises_invalid_target():
    with pytest.raises(InvalidTargetError):
        validate_resource_indicators(["https://ok.example", "bad"])


def test_unique_preserves_order():
    assert unique_resource_indicators(["a", "b", "a", "c", "b"]) == [
        "a",
        "b",
        "c",
    ]


def test_server_without_policy_rejects_resources_and_defaults_to_none():
    server = AuthorizationServer.__new__(AuthorizationServer)
    server._resource_policy = None

    assert server.get_default_resources(client=None, request=None) == []
    with pytest.raises(InvalidTargetError):
        server.get_allowed_resources(None, ["https://billing.example"], None)


def test_registered_resource_policy_decides():
    class Policy(ResourcePolicy):
        ALLOWED = {"https://billing.example", "https://reports.example"}

        def get_allowed_resources(self, client, resources, request):
            for resource in resources:
                if resource not in self.ALLOWED:
                    raise InvalidTargetError()
            return resources

        def get_default_resources(self, client, request, authorized_resources=None):
            return ["https://billing.example"]

    server = AuthorizationServer.__new__(AuthorizationServer)
    policy = Policy()
    server.register_resource_policy(policy)

    assert server.get_allowed_resources(
        None, ["https://billing.example"], None
    ) == ["https://billing.example"]
    with pytest.raises(InvalidTargetError):
        server.get_allowed_resources(None, ["https://other.example"], None)
    # explicit policy default, never an implicit "all resources"
    assert server.get_default_resources(None, None) == ["https://billing.example"]


def test_repeated_resource_is_not_collapsed_in_requests():
    resources = ["https://billing.example", "https://reports.example"]

    uri = prepare_grant_uri(
        "https://as.example/authorize",
        client_id="client-id",
        response_type="code",
        resource=resources,
    )
    assert (
        "resource=https%3A%2F%2Fbilling.example"
        "&resource=https%3A%2F%2Freports.example" in uri
    )

    body = prepare_token_request(
        "authorization_code", code="code-value", resource=resources
    )
    assert (
        "resource=https%3A%2F%2Fbilling.example"
        "&resource=https%3A%2F%2Freports.example" in body
    )


def test_refresh_request_subset_encoding():
    body = prepare_token_request(
        "refresh_token",
        refresh_token="rt",
        resource=["https://reports.example"],
    )
    assert "resource=https%3A%2F%2Freports.example" in body
