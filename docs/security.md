# Security Notes

## Safe Analysis Boundary

The system analyzes URL text and external reputation data. It does not visit suspicious URLs and does not download content.

## VirusTotal Privacy

Do not submit private, internal, or tokenized URLs to the public VirusTotal API. Public VirusTotal is useful for academic demonstration and external reference, but it is not a private scanning sandbox.

See `docs/virustotal.md` for setup, status values, and validation commands.

## URL Display

Reports display defanged URLs, for example:

```text
hxxp://fake-login[.]example
```

This reduces accidental clicks during demos and reviews.

## Auth

V1 uses a single-admin session cookie. The development password is intentionally simple and must be replaced before any shared deployment.

Generate a replacement hash:

```bash
cd backend
uv run hash-password
```

The backend also includes local production-style protections:

- HTTP-only session cookie.
- Logout endpoint that clears the session cookie.
- Login rate limiting.
- Scan rate limiting.
- Origin validation for state-changing requests.
- Request body size limit.
- Security headers for API responses.

The current rate limiters are in memory. They are appropriate for this local university prototype, but they reset on process restart and are not shared across multiple backend processes.

## Runtime Defaults

The default credentials are only for local development:

```text
admin / admin123
```

Before any shared or production-like run, replace:

- `ADMIN_PASSWORD_HASH`
- `SESSION_SECRET`
- `VIRUSTOTAL_API_KEY`, if VirusTotal is used

The app warns in development when default credentials or the default session secret are present. Non-development environments must not use those defaults.
