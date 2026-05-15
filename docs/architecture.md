# Architecture

```text
Next.js dashboard
  -> FastAPI /api/v1/scans
  -> request guard and session auth
  -> URL parser and feature extractor
  -> local Random Forest predictor
  -> heuristic verdict engine
  -> optional VirusTotal enrichment
  -> local-vs-VirusTotal comparison stats
  -> SQLite scan report
  -> dashboard report page
```

## Main Boundaries

- The backend never opens or crawls submitted URLs.
- Dangerous URLs are displayed in defanged format by default.
- VirusTotal is treated as an external reference, not ground truth.
- The comparison metric measures model-only agreement with VirusTotal reference data.
- Webhook integrations are not implemented in v1.
- The current system is intended to run locally for the university demo.
- Security hardening is local production-style, but not an enterprise multi-user setup.

## Local Runtime

```text
frontend: localhost:3000
backend:  127.0.0.1:8001
db:       SQLite in backend/var
model:    models/url_classifier.skops as separate artifact
```

The frontend uses the Next.js `/backend` rewrite so browser requests stay same-origin and the HTTP-only cookie works cleanly.

## Future Webhooks

Future integrations should normalize events into the same `create_scan` function used by the manual UI. The database keeps small optional source fields for future webhook metadata, but the current product only creates manual scans.
