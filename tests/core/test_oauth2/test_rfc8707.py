import pytest

from authlib.oauth2.rfc6749.requests import BasicOAuth2Payload
from authlib.oauth2.rfc6750.token import BearerTokenGenerator
from authlib.oauth2.rfc8707 import InvalidTargetError
from authlib.oauth2.rfc8707 import extract_resource_parameter
from authlib.oauth2.rfc8707 import validate_resource_parameter


def make_payload(data):
    return BasicOAuth2Payload(data)


def test_extract_single_resource():
    payload = make_payload({"resource": "https://api.example.com"})
    assert extract_resource_parameter(payload) == ["https://api.example.com"]


def test_extract_multiple_resources():
    payload = make_payload(
        {"resource": ["https://api1.example.com", "https://api2.example.com"]}
    )
    assert extract_resource_parameter(payload) == [
        "https://api1.example.com",
        "https://api2.example.com",
    ]


def test_extract_deduplicates_resources():
    payload = make_payload(
        {"resource": ["https://api.example.com", "https://api.example.com"]}
    )
    assert extract_resource_parameter(payload) == ["https://api.example.com"]


def test_extract_missing_resource():
    payload = make_payload({"scope": "read"})
    assert extract_resource_parameter(payload) == []


def test_validate_absolute_uri():
    validate_resource_parameter(["https://api.example.com", "urn:example:foo"])


def test_validate_rejects_relative_uri():
    with pytest.raises(InvalidTargetError):
        validate_resource_parameter(["api.example.com"])


def test_validate_rejects_fragment():
    with pytest.raises(InvalidTargetError):
        validate_resource_parameter(["https://api.example.com/#fragment"])


class Client:
    def get_allowed_scope(self, scope):
        return scope


def test_bearer_token_generator_passes_resources():
    calls = []

    def access_token_generator(client, grant_type, user, scope, resources=None):
        calls.append(resources)
        return "access-token"

    generator = BearerTokenGenerator(access_token_generator)
    token = generator.generate(
        grant_type="authorization_code",
        client=Client(),
        user=None,
        scope="read",
        resources=["https://api.example.com"],
    )
    assert calls == [["https://api.example.com"]]
    assert token["resource"] == "https://api.example.com"
    assert token["access_token"] == "access-token"


def test_bearer_token_generator_without_resources():
    def access_token_generator(client, grant_type, user, scope):
        return "access-token"

    generator = BearerTokenGenerator(access_token_generator)
    token = generator.generate(
        grant_type="authorization_code",
        client=Client(),
        user=None,
        scope="read",
    )
    # generators not aware of RFC 8707 keep working unchanged
    assert "resource" not in token
    assert token["access_token"] == "access-token"
