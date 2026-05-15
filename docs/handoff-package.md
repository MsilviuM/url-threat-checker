# Final Handoff Package

This file explains what should be handed to the colleague or professor so the
project can be run, presented, and defended without confusion.

## Source Code

Private GitHub repository:

```text
https://github.com/iannis6/url-threat-checker
```

The repository contains:

- FastAPI backend
- Next.js frontend
- tests
- documentation
- model card
- curated benign URL correction data
- screenshots
- presentation deck

The repository does not contain local secrets, local databases, dependency
folders, generated build output, processed Kaggle CSVs, retraining CSVs, or the
large trained `.skops` model artifact.

## Required Model Artifact

The trained model must be shared separately:

```text
models/url_classifier.skops
```

Place it inside the cloned project at exactly:

```text
url-threat-checker/models/url_classifier.skops
```

Expected local size:

```text
about 234 MB
```

The app starts without this file, but the model will be reported as
`unavailable`. The full demo should use the artifact.

## Optional Retraining Data

Retraining is not needed for the normal demo, but it is useful if the colleague
wants to rebuild the model or defend the training process.

The private GitHub release includes:

```text
url-threat-checker-training-data.zip
```

Unzip it into the project root so the files land in:

```text
data/raw/malicious_phish.csv
data/raw/curated_benign_trusted_urls.csv
```

Then follow:

```text
docs/retraining.md
```

## Main Demo Commands

Backend:

```bash
cd backend
uv sync
uv run reset-demo --with-comparison
uv run uvicorn url_threat_checker.main:app --host 127.0.0.1 --port 8001 --reload
```

Frontend:

```bash
cd frontend
pnpm install
BACKEND_INTERNAL_URL=http://127.0.0.1:8001 pnpm dev
```

Open:

```text
http://localhost:3000
```

Login:

```text
admin / admin123
```

## Presentation Materials

Use these files:

- `deliverables/url-threat-checker-university-demo.pptx`
- `docs/final-project-report.md`
- `docs/demo-script.md`
- `docs/screenshots/`
- `docs/retraining.md`

The screenshots are useful for the written report. The PowerPoint deck is useful
for the spoken presentation.

## Final Verification Commands

```bash
cd backend
uv run ruff check src tests
uv run pytest

cd ../frontend
pnpm lint
pnpm build
```

The current verified state passed all of these commands.
