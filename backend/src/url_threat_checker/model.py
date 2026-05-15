"""Load the trained Random Forest model and ask it for a model-only signal."""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pandas as pd
import skops.io as sio

from url_threat_checker.config import get_settings
from url_threat_checker.features import FEATURE_NAMES, UrlFeatureSet


@dataclass(frozen=True)
class Prediction:
    label: str
    confidence: float
    status: str


class ModelPredictor:
    def __init__(self, model_path: str | None = None, card_path: str | None = None) -> None:
        settings = get_settings()
        self.model_path = Path(model_path or settings.model_path)
        self.card_path = Path(card_path or settings.model_card_path)
        self.model: Any | None = None
        self.card: dict[str, Any] = {}
        self.status = "unavailable"
        self._load()

    def _load(self) -> None:
        if not self.model_path.exists() or not self.card_path.exists():
            return

        self.card = json.loads(self.card_path.read_text(encoding="utf-8"))
        expected_features = self.card.get("feature_names")
        if expected_features != FEATURE_NAMES:
            self.status = "feature_mismatch"
            return

        unknown_types = sio.get_untrusted_types(file=self.model_path)
        self.model = sio.load(self.model_path, trusted=unknown_types)
        self.status = "available"

    def predict(self, features: UrlFeatureSet) -> Prediction:
        if self.model is None:
            return Prediction(label="unknown", confidence=0.0, status=self.status)

        row = pd.DataFrame([{name: features.to_dict()[name] for name in FEATURE_NAMES}])
        label = str(self.model.predict(row)[0])
        confidence = 0.0
        if hasattr(self.model, "predict_proba"):
            confidence = float(max(self.model.predict_proba(row)[0]))
        return Prediction(label=label, confidence=confidence, status=self.status)


_predictor: ModelPredictor | None = None


def get_predictor() -> ModelPredictor:
    global _predictor
    if _predictor is None:
        _predictor = ModelPredictor()
    return _predictor


def reset_predictor() -> None:
    global _predictor
    _predictor = None
