from url_threat_checker.features import extract_features
from url_threat_checker.model import Prediction
from url_threat_checker.verdict import build_verdict


def test_dangerous_when_model_is_confident_phishing() -> None:
    parsed, features = extract_features("https://secure-paypal-login.example.ru/verify")
    verdict = build_verdict(
        parsed,
        features,
        Prediction(label="phishing", confidence=0.91, status="available"),
        vt_malicious=None,
        vt_suspicious=None,
    )

    assert verdict.final_verdict == "dangerous"
    assert verdict.risk_score >= 80


def test_vt_detections_force_dangerous() -> None:
    parsed, features = extract_features("https://unknown.example.com")
    verdict = build_verdict(
        parsed,
        features,
        Prediction(label="benign", confidence=0.95, status="available"),
        vt_malicious=6,
        vt_suspicious=1,
    )

    assert verdict.final_verdict == "dangerous"


def test_whitelisted_benign_url_is_safe() -> None:
    parsed, features = extract_features("https://www.youtube.com/watch?v=abc123")
    verdict = build_verdict(
        parsed,
        features,
        Prediction(label="benign", confidence=0.97, status="available"),
        vt_malicious=0,
        vt_suspicious=0,
    )

    assert verdict.final_verdict == "safe"
    assert "registered_domain_whitelisted" in verdict.heuristic_flags


def test_whitelisted_domain_stays_safe_on_model_only_false_positive() -> None:
    parsed, features = extract_features("https://www.google.com/search?q=university+project")
    verdict = build_verdict(
        parsed,
        features,
        Prediction(label="phishing", confidence=0.91, status="available"),
        vt_malicious=0,
        vt_suspicious=0,
    )

    assert verdict.final_verdict == "safe"
    assert verdict.risk_score <= 15
    assert "registered_domain_whitelisted" in verdict.heuristic_flags
    assert "model_signal_disagrees_with_trusted_domain" in verdict.heuristic_flags


def test_whitelisted_domain_becomes_suspicious_with_low_vt_detections() -> None:
    parsed, features = extract_features("https://www.google.com/search?q=university+project")
    verdict = build_verdict(
        parsed,
        features,
        Prediction(label="benign", confidence=0.97, status="available"),
        vt_malicious=2,
        vt_suspicious=0,
    )

    assert verdict.final_verdict == "suspicious"
    assert 25 <= verdict.risk_score < 60


def test_whitelisted_domain_becomes_dangerous_with_strong_vt_detections() -> None:
    parsed, features = extract_features("https://www.google.com/search?q=university+project")
    verdict = build_verdict(
        parsed,
        features,
        Prediction(label="benign", confidence=0.97, status="available"),
        vt_malicious=5,
        vt_suspicious=0,
    )

    assert verdict.final_verdict == "dangerous"
    assert verdict.risk_score >= 80


def test_fake_whitelist_domain_is_not_trusted() -> None:
    parsed, features = extract_features("https://google.com.fake-domain.ru/login")
    verdict = build_verdict(
        parsed,
        features,
        Prediction(label="phishing", confidence=0.91, status="available"),
        vt_malicious=0,
        vt_suspicious=0,
    )

    assert features.is_whitelisted == 0
    assert parsed.registered_domain == "fake-domain.ru"
    assert verdict.final_verdict == "dangerous"
