import pytest

from url_threat_checker.features import extract_features
from url_threat_checker.model import ModelPredictor

MALICIOUS_LABELS = {"defacement", "malware", "phishing"}


@pytest.fixture(scope="module")
def predictor() -> ModelPredictor:
    loaded = ModelPredictor()
    assert loaded.status == "available"
    return loaded


def predict_url(predictor: ModelPredictor, url: str):
    _parsed, features = extract_features(url)
    return predictor.predict(features)


@pytest.mark.parametrize(
    "url",
    [
        "https://google.com",
        "https://www.google.com",
        "https://www.google.com/search?q=university+project",
        "https://www.youtube.com/watch?v=abc123",
        "https://github.com/openai/codex",
    ],
)
def test_trusted_public_urls_are_not_high_confidence_malicious(
    predictor: ModelPredictor,
    url: str,
) -> None:
    prediction = predict_url(predictor, url)

    assert prediction.label == "benign"
    assert prediction.confidence >= 0.75


@pytest.mark.parametrize(
    "url",
    [
        "https://docs.google.com/spreadsheet/viewform?formkey=dGg2Z1lCUHlSdjllTVNRUW50TFIzSkE6MQ",
        "https://google.com.fake-domain.ru/login",
    ],
)
def test_abusive_or_fake_trusted_urls_remain_risky(
    predictor: ModelPredictor,
    url: str,
) -> None:
    prediction = predict_url(predictor, url)

    assert prediction.label in MALICIOUS_LABELS
    assert prediction.confidence >= 0.75
