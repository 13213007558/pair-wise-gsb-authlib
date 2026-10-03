import pytest

from authlib.oauth2.rfc8707 import InvalidTargetError
from authlib.oauth2.rfc8707 import parse_resource_indicators
from authlib.oauth2.rfc8707 import validate_resource_indicator


def test_validate_resource_indicator_absolute_uri():
    assert (
        validate_resource_indicator("https://api.example.com/billing")
        == "https://api.example.com/billing"
    )
    assert validate_resource_indicator("urn:example:resource") == "urn:example:resource"


def test_validate_resource_indicator_rejects_relative_uri():
    with pytest.raises(InvalidTargetError):
        validate_resource_indicator("api.example.com")
    with pytest.raises(InvalidTargetError):
        validate_resource_indicator("/path/only")


def test_validate_resource_indicator_rejects_fragment():
    with pytest.raises(InvalidTargetError):
        validate_resource_indicator("https://api.example.com/#section")


def test_validate_resource_indicator_rejects_empty():
    with pytest.raises(InvalidTargetError):
        validate_resource_indicator("")
    with pytest.raises(InvalidTargetError):
        validate_resource_indicator(None)


def test_parse_resource_indicators_preserves_repeated_values():
    datalist = {
        "resource": [
            "https://billing.example.com",
            "https://reports.example.com",
        ],
        "scope": ["profile"],
    }
    assert parse_resource_indicators(datalist) == [
        "https://billing.example.com",
        "https://reports.example.com",
    ]


def test_parse_resource_indicators_deduplicates():
    datalist = {
        "resource": [
            "https://billing.example.com",
            "https://billing.example.com",
        ]
    }
    assert parse_resource_indicators(datalist) == ["https://billing.example.com"]


def test_parse_resource_indicators_empty():
    assert parse_resource_indicators({}) == []
    assert parse_resource_indicators({"resource": []}) == []


def test_parse_resource_indicators_invalid():
    with pytest.raises(InvalidTargetError) as exc_info:
        parse_resource_indicators({"resource": ["not-a-uri"]})
    assert exc_info.value.error == "invalid_target"
