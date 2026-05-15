import argparse
import hashlib
import json
import platform
import sys
from datetime import UTC, datetime
from pathlib import Path

import pandas as pd
import sklearn
import skops.io as sio
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score
from sklearn.model_selection import train_test_split

from url_threat_checker.features import (
    FEATURE_EXTRACTOR_VERSION,
    FEATURE_NAMES,
    extract_features,
)

PROJECT_ROOT = Path(__file__).resolve().parents[4]
DEFAULT_AUGMENTATION_PATH = PROJECT_ROOT / "data" / "raw" / "curated_benign_trusted_urls.csv"


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _replace_with_temporary_file(path: Path, writer) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = path.with_name(f"{path.name}.tmp")
    writer(temporary_path)
    temporary_path.replace(path)


def write_dataframe_csv(frame: pd.DataFrame, path: Path) -> None:
    _replace_with_temporary_file(
        path,
        lambda temporary_path: frame.to_csv(temporary_path, index=False),
    )


def write_json(path: Path, payload: dict) -> None:
    _replace_with_temporary_file(
        path,
        lambda temporary_path: temporary_path.write_text(
            json.dumps(payload, indent=2),
            encoding="utf-8",
        ),
    )


def dump_model(model: RandomForestClassifier, path: Path) -> None:
    _replace_with_temporary_file(path, lambda temporary_path: sio.dump(model, temporary_path))


def _class_distribution(frame: pd.DataFrame) -> dict[str, int]:
    return {str(label): int(count) for label, count in frame["type"].value_counts().items()}


def _clean_training_frame(frame: pd.DataFrame, *, source_name: str) -> pd.DataFrame:
    missing_columns = {"url", "type"} - set(frame.columns)
    if missing_columns:
        joined = ", ".join(sorted(missing_columns))
        raise ValueError(f"{source_name} is missing required column(s): {joined}")

    cleaned = frame[["url", "type"]].dropna(subset=["url", "type"]).copy()
    cleaned["url"] = cleaned["url"].astype(str).str.strip()
    cleaned["type"] = cleaned["type"].astype(str).str.strip()
    return cleaned[(cleaned["url"] != "") & (cleaned["type"] != "")]


def load_training_frame(
    input_path: Path,
    augmentation_path: Path | None,
) -> tuple[pd.DataFrame, dict]:
    base_raw = pd.read_csv(input_path)
    base = _clean_training_frame(base_raw, source_name=str(input_path))
    base = base.drop_duplicates(subset=["url"])
    base["training_source"] = "base_dataset"

    metadata = {
        "base": {
            "path": str(input_path),
            "sha256": file_sha256(input_path),
            "rows_before_cleaning": int(len(base_raw)),
            "rows_after_cleaning": int(len(base)),
            "class_distribution": _class_distribution(base),
        },
        "augmentation": {
            "enabled": False,
            "path": str(augmentation_path) if augmentation_path else None,
            "sha256": None,
            "rows_before_cleaning": 0,
            "rows_after_cleaning": 0,
            "class_distribution": {},
        },
    }

    frames = [base]
    if augmentation_path is not None and augmentation_path.exists():
        augmentation_raw = pd.read_csv(augmentation_path)
        augmentation = _clean_training_frame(
            augmentation_raw,
            source_name=str(augmentation_path),
        )
        augmentation = augmentation.drop_duplicates(subset=["url"], keep="last")
        augmentation["training_source"] = "curated_augmentation"
        frames.append(augmentation)
        metadata["augmentation"] = {
            "enabled": True,
            "path": str(augmentation_path),
            "sha256": file_sha256(augmentation_path),
            "rows_before_cleaning": int(len(augmentation_raw)),
            "rows_after_cleaning": int(len(augmentation)),
            "class_distribution": _class_distribution(augmentation),
        }

    combined = pd.concat(frames, ignore_index=True)
    rows_before_deduplication = len(combined)
    combined = combined.drop_duplicates(subset=["url"], keep="last")
    metadata["combined"] = {
        "rows_before_deduplication": int(rows_before_deduplication),
        "rows_after_deduplication": int(len(combined)),
        "duplicates_removed": int(rows_before_deduplication - len(combined)),
        "class_distribution": _class_distribution(combined),
    }
    return combined, metadata


def trusted_domain_bias_audit(prepared: pd.DataFrame) -> dict:
    def section(frame: pd.DataFrame) -> dict:
        return {
            "rows": int(len(frame)),
            "class_distribution": _class_distribution(frame) if len(frame) else {},
        }

    trusted = prepared[prepared["is_whitelisted"] == 1]
    trusted_https = trusted[trusted["has_https"] == 1]
    google_https = trusted_https[trusted_https["registered_domain"] == "google.com"]

    return {
        "whitelisted_domains": section(trusted),
        "whitelisted_https_urls": section(trusted_https),
        "google_https_urls": section(google_https),
        "trusted_root_or_www_homepages": section(
            prepared[prepared["is_trusted_root_or_www_homepage"] == 1]
        ),
        "trusted_common_public_pages": section(
            prepared[prepared["is_trusted_search_or_common_public_page"] == 1]
        ),
        "trusted_user_generated_services": section(
            prepared[prepared["is_trusted_user_generated_service"] == 1]
        ),
    }


def prepare_dataset(
    input_path: Path,
    output_path: Path | None,
    sample_size: int | None,
    augmentation_path: Path | None,
) -> tuple[pd.DataFrame, dict]:
    raw, metadata = load_training_frame(input_path, augmentation_path)
    if sample_size:
        sampled_frames = []
        total_rows = len(raw)
        for _label, frame in raw.groupby("type"):
            target_size = max(1, int(sample_size * len(frame) / total_rows))
            sampled_frames.append(frame.sample(min(len(frame), target_size), random_state=42))
        raw = pd.concat(sampled_frames, ignore_index=True)
        metadata["sample"] = {
            "enabled": True,
            "requested_rows": int(sample_size),
            "actual_rows": int(len(raw)),
            "class_distribution": _class_distribution(raw),
        }
    else:
        metadata["sample"] = {"enabled": False}

    rows: list[dict] = []
    for item in raw.itertuples(index=False):
        try:
            parsed, features = extract_features(str(item.url))
        except ValueError:
            continue
        rows.append(
            {
                "url": item.url,
                "normalized_url": parsed.normalized_url,
                "domain": parsed.domain,
                "registered_domain": parsed.registered_domain,
                "training_source": getattr(item, "training_source", "unknown"),
                **features.to_dict(),
                "type": item.type,
            }
        )
    prepared = pd.DataFrame(rows)
    if output_path is not None:
        write_dataframe_csv(prepared, output_path)
    metadata["prepared"] = {
        "rows": int(len(prepared)),
        "class_distribution": _class_distribution(prepared),
        "trusted_domain_bias_audit": trusted_domain_bias_audit(prepared),
    }
    return prepared, metadata


def train(
    prepared: pd.DataFrame,
    model_path: Path,
    card_path: Path,
    *,
    input_path: Path,
    processed_path: Path | None,
    dataset_metadata: dict,
    augmentation_weight: float,
    training_command: str,
) -> None:
    x = prepared[FEATURE_NAMES]
    y = prepared["type"]
    sample_weights = prepared["training_source"].map(
        lambda source: augmentation_weight if source == "curated_augmentation" else 1.0
    )
    x_train, x_test, y_train, y_test, weight_train, _weight_test = train_test_split(
        x,
        y,
        sample_weights,
        test_size=0.2,
        random_state=42,
        stratify=y,
    )

    model = RandomForestClassifier(
        n_estimators=120,
        max_depth=28,
        min_samples_leaf=3,
        max_features="sqrt",
        random_state=42,
        class_weight="balanced",
        n_jobs=-1,
    )
    model.fit(x_train, y_train, sample_weight=weight_train)
    y_pred = model.predict(x_test)

    report = classification_report(y_test, y_pred, output_dict=True, zero_division=0)
    matrix = confusion_matrix(y_test, y_pred, labels=list(model.classes_)).tolist()
    importances = [
        {"feature": feature, "importance": float(importance)}
        for feature, importance in sorted(
            zip(FEATURE_NAMES, model.feature_importances_, strict=True),
            key=lambda item: item[1],
            reverse=True,
        )
    ]
    card = {
        "version": datetime.now(UTC).strftime("%Y%m%d%H%M%S"),
        "trained_at": datetime.now(UTC).isoformat(),
        "training_command": training_command,
        "runtime": {
            "python": platform.python_version(),
            "pandas": pd.__version__,
            "scikit_learn": sklearn.__version__,
            "skops": getattr(sio, "__version__", "unknown"),
        },
        "dataset": {
            "input_path": str(input_path),
            "input_sha256": file_sha256(input_path),
            "processed_path": str(processed_path) if processed_path else None,
            **dataset_metadata,
        },
        "feature_extractor_version": FEATURE_EXTRACTOR_VERSION,
        "feature_names": FEATURE_NAMES,
        "training_strategy": {
            "augmentation_weight": float(augmentation_weight),
            "augmentation_weight_note": (
                "Curated rows are weighted during fitting so rare hand-reviewed trusted "
                "HTTPS corrections are visible to the model without modifying the raw dataset."
            ),
        },
        "labels": [str(label) for label in model.classes_],
        "dataset_rows": int(len(prepared)),
        "class_distribution": _class_distribution(prepared),
        "metrics": {
            "accuracy": float(accuracy_score(y_test, y_pred)),
            "macro_f1": float(f1_score(y_test, y_pred, average="macro")),
            "weighted_f1": float(f1_score(y_test, y_pred, average="weighted")),
            "classification_report": report,
            "confusion_matrix": matrix,
        },
        "feature_importances": importances,
        "limitations": [
            "The model analyzes URL text only; it does not inspect page content.",
            "VirusTotal is an external reference, not absolute ground truth.",
            "Safe whitelisted domains can still be overridden by strong external "
            "malicious detections.",
            "New attack patterns may require retraining and feature updates.",
        ],
    }

    dump_model(model, model_path)
    write_json(card_path, card)


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the URL threat classifier.")
    parser.add_argument(
        "--input",
        type=Path,
        default=PROJECT_ROOT / "data" / "raw" / "malicious_phish.csv",
    )
    parser.add_argument(
        "--processed",
        type=Path,
        default=PROJECT_ROOT / "data" / "processed" / "prepared_urls.csv",
    )
    parser.add_argument(
        "--model",
        type=Path,
        default=PROJECT_ROOT / "models" / "url_classifier.skops",
    )
    parser.add_argument(
        "--card",
        type=Path,
        default=PROJECT_ROOT / "models" / "model_card.json",
    )
    parser.add_argument(
        "--augmentation",
        type=Path,
        default=DEFAULT_AUGMENTATION_PATH,
        help="Optional curated rows appended after the base dataset.",
    )
    parser.add_argument(
        "--augmentation-weight",
        type=float,
        default=200.0,
        help="Training weight for rows from the curated augmentation file.",
    )
    parser.add_argument("--sample-size", type=int, default=None)
    args = parser.parse_args()
    if args.augmentation_weight <= 0:
        raise ValueError("--augmentation-weight must be greater than zero.")

    prepared, dataset_metadata = prepare_dataset(
        args.input,
        args.processed,
        args.sample_size,
        args.augmentation,
    )
    train(
        prepared,
        args.model,
        args.card,
        input_path=args.input,
        processed_path=args.processed,
        dataset_metadata=dataset_metadata,
        augmentation_weight=args.augmentation_weight,
        training_command=" ".join(sys.argv),
    )
    print(f"Trained model with {len(prepared)} rows.")
    print(f"Model: {args.model}")
    print(f"Model card: {args.card}")


if __name__ == "__main__":
    main()
