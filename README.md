# URL Threat Checker

A production-style university prototype for hybrid URL threat analysis.

The app lets an admin submit a URL, analyzes it with a local machine-learning model, optionally checks VirusTotal for an external reputation signal, stores the scan, and shows a clear report in a Next.js dashboard.

Webhook integrations are intentionally skipped in v1. Future email, Slack, Telegram, or WhatsApp integrations can call the same scan creation function used by the manual UI.

This project is designed to run locally for the university presentation. There is no deployment requirement for the current version.

## How It Works

```text
User enters a URL
  -> backend extracts numeric URL features
  -> local Random Forest model predicts the URL type
  -> heuristic rules correct obvious false positives
  -> VirusTotal is checked when configured
  -> final verdict is saved and shown in the dashboard
  -> local model results can be compared with VirusTotal reference data
```

## Stack

- FastAPI backend with Pydantic v2
- SQLAlchemy 2.0
- SQLite for v1
- scikit-learn Random Forest model
- VirusTotal API v3 enrichment
- Next.js 16, React 19, TypeScript strict, Tailwind CSS

## Run The Backend

```bash
cd backend
uv sync
uv run reset-demo
uv run uvicorn url_threat_checker.main:app --host 127.0.0.1 --port 8001 --reload
```

Default development login:

```text
admin / admin123
```

## Run The Frontend

```bash
cd frontend
pnpm install
BACKEND_INTERNAL_URL=http://127.0.0.1:8001 pnpm dev
```

Open:

```text
http://localhost:3000
```

The browser talks to the API through the Next.js `/backend` rewrite, so auth cookies stay same-origin during local testing.

## Model Artifact

The source repository includes `models/model_card.json`, but it does not include
the trained model file because the artifact is large:

```text
models/url_classifier.skops
```

For the full demo, place the separately shared `.skops` file at exactly that
path before starting the backend. Without it, the app still starts, but the
model status is shown as `unavailable`.

## Reset Demo Data

Use the deterministic reset command before screenshots or presentation practice:

```bash
cd backend
uv run reset-demo
```

`reset-demo` clears local scan reports and VirusTotal cache rows, then creates a clean set of intentional safe, suspicious, dangerous, and fake-whitelist examples without making live VirusTotal calls.

`seed-demo` still exists, but it is additive. Use `reset-demo` when you want a clean dashboard.

To also show the local-model-vs-VirusTotal comparison metric without making live
VirusTotal calls:

```bash
uv run reset-demo --with-comparison
```

## Train The Model

For retraining, download the private release asset:

```text
url-threat-checker-training-data.zip
```

Unzip it into `data/raw/`, then run:

```bash
mkdir -p data/raw
unzip ~/Downloads/url-threat-checker-training-data.zip -d data/raw

uv --project backend run train-model \
  --input data/raw/malicious_phish.csv \
  --processed data/processed/prepared_urls.csv \
  --model models/url_classifier.skops \
  --card models/model_card.json \
  --augmentation data/raw/curated_benign_trusted_urls.csv
```

The old `date_pregatite.csv` and `model_phishing.pkl` are not reused because the old extractor parsed domains incorrectly for URLs without an explicit `https://` or `http://`.

The original Kaggle dataset is kept unchanged. Training appends
`data/raw/curated_benign_trusted_urls.csv`, a small hand-reviewed correction
set for obvious benign trusted HTTPS URLs. This fixes the data bias where clean
trusted HTTPS URLs were underrepresented, while still preserving malicious
Google Forms, Google Sites, redirects, and other abuse examples. Curated rows
are weighted during fitting so the correction is visible to the model without
mutating the original dataset.

The trained `models/url_classifier.skops` file is large and should be handled as a separate artifact. Copy it into `models/` before running the full demo. The source bundle should include `models/model_card.json`, but not the `.skops` file.

## Configure VirusTotal

The app works without VirusTotal. When no key is configured, reports show `not_configured` and still use local ML plus heuristic logic.

For a local live check, export the key only in the shell that starts the backend:

```bash
export VIRUSTOTAL_API_KEY="..."
```

Do not commit API keys or write them into source files.

## Create Submission Bundle

Create a clean zip for handoff/submission:

```bash
cd backend
uv run create-submission-bundle
```

The bundle excludes local secrets, virtual environments, `node_modules`, Next build output, local SQLite databases, processed CSVs, caches, and the large `.skops` model artifact.

## Verify The Project

```bash
cd backend
uv run pytest
uv run ruff check

cd ../frontend
pnpm lint
pnpm build
```

Browser automation and Playwright are intentionally not part of this completion pass. The manual UI testing guide remains the UI acceptance path.

## Project Docs

More detailed notes live in `docs/`:

- `docs/architecture.md` explains the system design.
- `docs/demo-script.md` gives the presentation flow.
- `docs/final-project-report.md` contains the Romanian academic report.
- `docs/model.md` explains the machine-learning model.
- `docs/retraining.md` explains how to rebuild the model from the release data.
- `docs/training-data-audit.md` explains the dataset cleanup.
- `docs/ui-testing-guide.md` explains how to manually test the UI.
- `docs/virustotal.md` explains the VirusTotal integration.
- `docs/security.md` explains local security decisions.
- `docs/handoff-package.md` explains what to give to the colleague/commission.
- `docs/code-reading-guide.md` gives a beginner-friendly reading order.
- `docs/fresh-clone-test.md` records the clean-clone verification.
