# Fresh Clone Test

This records the clean-clone verification performed before final handoff.

## Goal

Confirm the private GitHub repository can be cloned and run by someone who does
not have the current local working directory.

## Commands Used

```bash
git clone https://github.com/iannis6/url-threat-checker.git <temporary-folder>/url-threat-checker-fresh-clone
cd <temporary-folder>/url-threat-checker-fresh-clone
```

Safety checks:

```bash
git rev-parse --short HEAD
find . -path './.git' -prune -o -type f -size +10M -print
git ls-tree -r --name-only HEAD | rg '^backend/.env$|url_classifier\\.skops|prepared_urls\\.csv|node_modules|\\.next|dist/|backend/var|\\.venv|\\.uv-cache|designs/' || true
```

Backend setup:

```bash
cd backend
uv sync
```

Model missing behavior:

```bash
uv run python - <<'PY'
from url_threat_checker.model import ModelPredictor
predictor = ModelPredictor()
print(predictor.status)
PY
```

Expected result:

```text
unavailable
```

Then the trained model artifact was downloaded from the private GitHub release
and placed into the clone:

```bash
cp /path/to/downloaded/url_classifier.skops ../models/url_classifier.skops
```

Model available behavior:

```bash
uv run python - <<'PY'
from url_threat_checker.model import ModelPredictor
predictor = ModelPredictor()
print(predictor.status)
print(predictor.card.get("version"))
PY
```

Expected result:

```text
available
20260509071915
```

Backend tests:

```bash
uv run pytest
```

Frontend setup and build:

```bash
cd ../frontend
pnpm install --frozen-lockfile
pnpm build
```

## Result

The fresh clone passed:

- no large tracked files
- no tracked `.env`
- no tracked `.skops`
- no tracked processed CSV
- no tracked local DB
- model status is gracefully `unavailable` without the artifact
- model status becomes `available` after copying the artifact
- backend tests pass
- frontend production build passes
