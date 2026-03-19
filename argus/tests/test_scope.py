import pytest

from argus.core.scope import normalize_target, validate_target


def test_normalize_target_strips_scheme():
    assert normalize_target("https://example.com") == "example.com"


def test_normalize_target_strips_path():
    assert normalize_target("https://example.com/test/page") == "example.com"


def test_normalize_target_strips_port():
    assert normalize_target("example.com:443") == "example.com"


def test_validate_target_accepts_valid_domain():
    assert validate_target("example.com") == "example.com"


def test_validate_target_accepts_subdomain():
    assert validate_target("dev.example.com") == "dev.example.com"


def test_validate_target_accepts_url_input():
    assert validate_target("https://dev.example.com/login") == "dev.example.com"


def test_validate_target_rejects_invalid_domain():
    with pytest.raises(ValueError):
        validate_target("invalid_domain")