# VirusTotal Integration

The app can enrich local URL scans with VirusTotal API v3. VirusTotal is treated as an external reference, not as absolute truth.

## Configuration

Do not commit the API key and do not write it into source files.

For local development, export it only in the shell that starts the backend:

```bash
export VIRUSTOTAL_API_KEY="..."
cd backend
uv run uvicorn url_threat_checker.main:app --host 127.0.0.1 --port 8001
```

Optional settings:

```text
VIRUSTOTAL_CACHE_TTL_HOURS=24
VIRUSTOTAL_SUBMIT_UNKNOWN=false
VIRUSTOTAL_BASE_URL=https://www.virustotal.com/api/v3
```

## Live Validation

Run a non-persistent smoke test:

```bash
cd backend
VIRUSTOTAL_API_KEY="..." uv run validate-virustotal --url https://www.google.com
```

This command uses an in-memory SQLite database and does not store credentials.

## Status Values

- `skipped`: the scan explicitly disabled VirusTotal.
- `not_configured`: no API key is available.
- `cached`: a fresh local cached result was reused.
- `fetched`: VirusTotal returned an existing report.
- `not_found`: VirusTotal has no existing report and submission is disabled.
- `pending`: the URL was submitted and analysis is pending.
- `rate_limited`: VirusTotal returned a rate-limit response.
- `failed`: the request failed.
- `malformed_response`: the response did not contain usable analysis stats.

## Comparison Metric

The dashboard and model page compare the model-only prediction with VirusTotal
only for scans whose status is `fetched` or `cached`.

- Local `benign` plus VirusTotal zero detections counts as agreement.
- Local `phishing`, `malware`, or `defacement` plus at least one VirusTotal
  malicious or suspicious detection counts as agreement.
- Other combinations are shown as disagreement buckets.

This is an agreement metric against an external reference, not a guarantee that
VirusTotal is always correct.

## Privacy Boundary

Do not send private, internal, tokenized, or sensitive URLs to the public VirusTotal API. Public VirusTotal is appropriate for academic demonstration and external reputation checks, but it is not a private scanning sandbox.
