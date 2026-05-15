import pytest

from url_threat_checker.features import extract_features, parse_url


def test_parses_url_without_scheme() -> None:
    parsed, features = extract_features("br-icloud.com.br")

    assert parsed.domain == "br-icloud.com.br"
    assert parsed.registered_domain == "br-icloud.com.br"
    assert features.domain_dot_count == 2
    assert features.scheme_missing == 1


def test_whitelist_allows_real_google_subdomain() -> None:
    parsed, features = extract_features("https://accounts.google.com/login")

    assert parsed.registered_domain == "google.com"
    assert features.is_whitelisted == 1
    assert features.is_trusted_root_or_www_homepage == 0
    assert features.is_trusted_search_or_common_public_page == 0


def test_whitelist_rejects_fake_google_domain() -> None:
    parsed, features = extract_features("https://google.com.fake-domain.ru/login")

    assert parsed.registered_domain == "fake-domain.ru"
    assert features.is_whitelisted == 0
    assert features.is_trusted_root_or_www_homepage == 0
    assert features.is_trusted_search_or_common_public_page == 0
    assert features.is_trusted_user_generated_service == 0
    assert features.suspicious_keyword_count >= 1


def test_marks_trusted_homepage_context() -> None:
    _, features = extract_features("https://www.google.com/")

    assert features.is_whitelisted == 1
    assert features.is_trusted_root_or_www_homepage == 1
    assert features.is_trusted_search_or_common_public_page == 0
    assert features.is_trusted_user_generated_service == 0


def test_marks_trusted_common_public_context() -> None:
    _, features = extract_features("https://www.google.com/search?q=university+project")

    assert features.is_whitelisted == 1
    assert features.is_trusted_root_or_www_homepage == 0
    assert features.is_trusted_search_or_common_public_page == 1
    assert features.is_trusted_user_generated_service == 0


def test_marks_trusted_user_generated_context() -> None:
    _, features = extract_features("https://docs.google.com/forms/d/e/example/viewform")

    assert features.is_whitelisted == 1
    assert features.is_trusted_root_or_www_homepage == 0
    assert features.is_trusted_search_or_common_public_page == 0
    assert features.is_trusted_user_generated_service == 1


def test_extracts_high_risk_url_features() -> None:
    _, features = extract_features("http://192.168.1.55/login/password-reset.exe")

    assert features.has_ip_address == 1
    assert features.has_risky_extension == 1
    assert features.has_http == 1


def test_rejects_empty_url() -> None:
    with pytest.raises(ValueError, match="empty"):
        parse_url("")
