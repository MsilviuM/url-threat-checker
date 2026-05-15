# Completion Gap Analysis

This document tracks the project state excluding final webhook integrations.

Current status:

```text
Core product:        complete for v1
University demo:     complete after final verification pass
Production-grade:    local production-style, not enterprise deployment
```

The app now supports the full local scanner flow:

```text
login
  -> submit URL
  -> local ML prediction
  -> heuristic verdict
  -> optional VirusTotal enrichment
  -> local-vs-VirusTotal comparison
  -> stored report
  -> dashboard/report UI
  -> logout
```

## Completed

- FastAPI backend and Next.js dashboard.
- Single-admin login with HTTP-only cookie and logout.
- SQLite persistence.
- URL feature extractor.
- Random Forest model integration.
- Registered-domain whitelist logic.
- Fake whitelist protection.
- Defanged URL display.
- VirusTotal client, status handling, cache path, and live validation command.
- Scan history, report details, stats, comparison stats, model metrics endpoint.
- Report search and verdict filtering.
- Human-readable report explanations.
- Readable model metrics page.
- Clean `reset-demo` command with optional comparison demo data.
- Submission bundle command.
- Backend endpoint/security tests.
- Frontend lint/build verification path.
- Manual UI testing guide.
- Training-data audit and curated trusted-URL correction set.
- Regression tests for trusted public URLs and fake trusted-domain attacks.

Fresh trained model status:

```text
Rows used:      640,905
Accuracy:       93.47%
Macro F1:       91.53%
Weighted F1:    93.62%
Model size:     about 261MB
```

The slight metric difference is acceptable. The newer model fixes the trusted
HTTPS false-positive demo blocker and keeps malicious trusted-platform abuse
examples risky.

## Explicit Decisions

- No webhook integrations in this completion pass.
- No Playwright/browser automation in this completion pass.
- No Docker/deployment story required; the project runs locally.
- `models/url_classifier.skops` is a separate artifact, not part of the source bundle.
- VirusTotal is an external reference/baseline, not absolute ground truth.
- Teacher-facing documentation is Romanian-first.

## Remaining Before Final Handoff

These are the only meaningful remaining items:

- Run the full verification commands from a clean state.
- Generate the final submission bundle and inspect its contents.
- Add screenshots manually if the university report needs them.
- Confirm the separate `.skops` model artifact is available beside the source bundle.
- Practice the demo once with `uv run reset-demo --with-comparison`.

## Final Verification Checklist

Run:

```bash
cd backend
uv run ruff check
uv run pytest

cd ../frontend
pnpm lint
pnpm build
```

Then run locally:

```bash
cd backend
uv run reset-demo
uv run uvicorn url_threat_checker.main:app --host 127.0.0.1 --port 8001
```

```bash
cd frontend
BACKEND_INTERNAL_URL=http://127.0.0.1:8001 pnpm dev
```

Accept the project as complete when:

- Login works.
- Logout works.
- Dashboard shows clean seeded demo data.
- Safe Google/YouTube style URLs are not marked dangerous.
- Fake whitelist URLs are dangerous.
- Reports explain the verdict in human language.
- Model page shows readable metrics.
- Dashboard and model page show local-vs-VirusTotal comparison data when seeded.
- VirusTotal missing-key state does not break scans.
- Submission bundle excludes `.env`, `.venv`, `node_modules`, `.next`, local DBs, caches, processed CSVs, and `.skops` files.

## Not In Scope

- Telegram webhook integration.
- Gmail/email ingestion.
- Slack integration.
- WhatsApp Business integration.
- Multi-user/team accounts.
- Enterprise deployment.
- Real-time queue workers.
