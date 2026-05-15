# URL Threat Checker Backend

FastAPI backend for URL analysis, local ML classification, VirusTotal enrichment, and stored scan reports.

## Run

```bash
uv sync
uv run reset-demo
uv run uvicorn url_threat_checker.main:app --host 127.0.0.1 --port 8001 --reload
```

Default development login:

```text
username: admin
password: admin123
```

Change `ADMIN_PASSWORD_HASH` and `SESSION_SECRET` before any real deployment.

## Train Model

From the repository root:

```bash
uv --project backend run train-model \
  --input data/raw/malicious_phish.csv \
  --processed data/processed/prepared_urls.csv \
  --model models/url_classifier.skops \
  --card models/model_card.json \
  --augmentation data/raw/curated_benign_trusted_urls.csv
```

The API still runs without a trained model, but reports will mark the model as unavailable.
