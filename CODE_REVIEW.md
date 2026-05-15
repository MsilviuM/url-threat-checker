# Deep Analysis — `url-threat-checker-v2`

Your friend made a small, focused set of changes on top of the original: a **Dockerfile + render.yaml** for Render deploy, **TOTP 2FA** on login, and a **forgot-password flow** gated on the same TOTP. Eight commits. The work is well-scoped but ships with several real bugs and security gaps.

## Critical

### 1. Production ships with `admin / admin123`
`render.yaml:21-22` hardcodes `ADMIN_PASSWORD_HASH` to the **demo default hash** (identical to `DEFAULT_ADMIN_PASSWORD_HASH` in `config.py:10-13` — hash of `admin123`). The `SESSION_SECRET` is `generateValue: true` (good) but the password isn't rotated. If the operator forgets to also set `TOTP_SECRET` (which is `sync: false`), the deployed app is open to the world with `admin / admin123` and **no 2FA**.

### 2. `/api/v1/auth/reset-password` is brute-forceable in under an hour
`auth.py:223-238` — unauthenticated endpoint. Anyone with network access can call it. Only check is a 6-digit TOTP code (`pyotp.TOTP(...).verify(code, valid_window=1)` = 3 valid codes at a time). Combined with the (still-missing) rate limiting from v1, an attacker hitting at 100 req/s expects to hit a valid code in ~55 min and reset the admin password to anything they choose. The new admin session is then created at will via `/login` (or `/verify-2fa`).

Sub-issues:
- The endpoint emits no audit log.
- Successful reset does **not** invalidate existing sessions (`_set_password_hash` mutates the hash, but sessions are JWT-style HMAC tokens signed with `session_secret`, which is unchanged).
- If `TOTP_SECRET` is unset, reset is disabled — but login is *also* not gated by 2FA. So a deploy without `TOTP_SECRET` removes the only barrier to login, while a deploy with `TOTP_SECRET` exposes the brute-force surface above.

### 3. Docker image has no ML model — `feat: add TOTP 2FA` reverted the model-download
Commit `3162797 feat: download ML model from GitHub release during Docker build` added `curl` of `url_classifier.skops` from a GitHub release plus `ENV MODEL_PATH` / `ENV MODEL_CARD_PATH`. The very next commit, `83b2e53 feat: add Google Authenticator TOTP 2FA`, includes a `diff --git a/Dockerfile` that **removes all of that** despite an unrelated commit message. Current `Dockerfile` (HEAD) has no model copy or download. At runtime, `Settings.model_path` defaults to `PROJECT_ROOT/models/url_classifier.skops` → with `WORKDIR /app` and `COPY backend/src ./src`, `BACKEND_ROOT=/app`, `PROJECT_ROOT=/`, so the resolved path is `/models/url_classifier.skops` which doesn't exist in the image. The deployed service runs heuristics-only and reports "model unavailable" on every scan.

### 4. Backend test suite is broken at HEAD
`backend/tests/test_api.py:120`:
```python
assert login_response.json() == {"username": "admin"}
```
But the new `LoginResponse` schema (`schemas.py:15-17`) adds `requires_2fa: bool = False`, so the actual response is `{"requires_2fa": False, "username": "admin"}`. I ran `uv --project backend run pytest`: 2 pass, **`test_login_cookie_allows_authenticated_requests_and_logout` FAILS** with exactly this assertion. No CI run could have passed since the 2FA commit.

### 5. v1's pre-existing security gaps still apply, now worse
- No rate limiting on `/login`, `/verify-2fa`, or `/reset-password`. The 2FA TOTP itself relies entirely on rate limiting to be safe; without it, TOTP is a 6-digit secret that's brute-forceable.
- `docs/security.md` still claims "warns when default credentials are present" — still unenforced, and v2 leans on this assumption by hardcoding the demo hash in `render.yaml`.

## Important

### 6. Once `/reset-password` runs, env var `ADMIN_PASSWORD_HASH` is permanently overridden
`auth.py:117-128`: `_get_password_hash` reads `site_settings.admin_password_hash` first and only falls back to `settings.admin_password_hash` if the row is missing. There is no CLI command, admin endpoint, or doc note for clearing the DB-stored override. The operator's only recourse is `reset_database_schema()` (which nukes scan history) or manual SQL. Not a bug per se, but a footgun — and the README/docs don't mention it.

### 7. `qrcode` is a runtime dep but only used by a CLI script
`pyproject.toml:15-17` adds `qrcode>=8.0` as a hard runtime dep. It's imported only in `scripts/setup_2fa.py`. In the Docker image it's dead weight (~MBs of PIL).

### 8. Pending 2FA cookie is not cleared on logout
`auth.py:241-247` clears `utc_session` but leaves `utc_pending` (TTL 5 min). If a user logs out mid-2FA or after re-entering credentials, a stale pending token sits in the browser. Low impact (TTL is short, signed) but inconsistent — the verify-2fa endpoint does delete it on success (`auth.py:216`), so the cleanup intent exists.

### 9. `pyotp.TOTP(settings.totp_secret).verify(...)` will raise on malformed secret
Not caught anywhere (`auth.py:213,234`). An operator who pastes a truncated or whitespace-padded `TOTP_SECRET` causes `binascii.Error` → unhandled 500 on every login attempt, with no startup signal that 2FA is misconfigured. Recommend validating at startup (`pyotp.TOTP(secret).now()` in a try/except as a smoke test).

### 10. `setup_2fa.py` hardcodes the issuer; `config.totp_issuer` exists but unused
`scripts/setup_2fa.py:10` passes `issuer_name="URL Threat Checker"` literal. `config.py:37` defines `totp_issuer: str = "URL Threat Checker"` as a settable env var. The frontend hardcodes the same string at `login/page.tsx:199`. Three sources of truth, no env-driven configurability.

### 11. Two frontend lockfiles
`frontend/package-lock.json` was added (npm), but `frontend/pnpm-lock.yaml` is still present from v1. `docs/ui-testing-guide.md:21` was updated from `pnpm dev` to `npm run dev`, so the intent is to switch — but the pnpm lockfile remains. Drift risk: contributors using `pnpm install` will resolve different versions than CI/Render using npm.

### 12. `BACKEND_CORS_ORIGINS` documented as `sync: false` but unconfigured by default
`render.yaml:15-16` — operator must set it manually. If they forget, `settings.backend_cors_origins` falls back to `http://localhost:3000`, and any deployed frontend can't talk to the backend. The default makes sense for local dev but is silently broken for production; no startup check.

### 13. Postgres added but not documented
`pyproject.toml:15` adds `psycopg2-binary`. No README/docs update mentions Postgres support, the `DATABASE_URL` env-var format expected on Render, or what happens to scan history when Render's free Postgres expires (Render free tier is suspended after 30 days). The original `docs/architecture.md` still says "SQLite" everywhere.

## Minor

### 14. `LoginResponse.username` is `str | None` but always set
`schemas.py:17` — `username: str | None = None`. In `auth.py:196`, login mints a session and returns `LoginResponse(username=...)`. When `requires_2fa=True` is returned, `username` is `None`. The frontend `LoginResult` type (`api.ts:142-145`) types it as optional, so consistent — but a discriminated union would model this cleaner.

### 15. `_PENDING_TTL = 300` hardcoded
`auth.py:26` — not in `Settings`. Same magic-number pattern as the unconfigurable VirusTotal timeout flagged in v1.

### 16. setup_2fa.py shows a code, then claims "verify setup", but doesn't verify anything
`scripts/setup_2fa.py:25` — `Current code (verify setup): {totp.now()}`. Prints a code; doesn't ask the user to type it back or confirm the QR scan succeeded.

### 17. `app_env` is a free-form string, not an enum
`config.py:23`, `auth.py:140,151,189,217` all check `settings.app_env == "production"` as a magic string. A typo (`prodcution`, `PROD`) silently downgrades cookies to non-secure and reveals nothing in logs.

### 18. f-string with no interpolation
`scripts/setup_2fa.py:23` — `print(f"\n   Or manually enter this key in Google Authenticator:")`. Stylistic; ruff `UP032` would flag.

### 19. No backend tests for any new endpoint
Zero tests for `/verify-2fa` or `/reset-password`. The one test that does exist (`test_login_cookie...`) is broken (see #4). The new flows are entirely untested.

### 20. `docs/` is mostly untouched
The only doc diff is pnpm→npm. Nothing in `docs/security.md`, `docs/architecture.md`, `docs/handoff-package.md`, or `README.md` describes the new 2FA / reset flows, the Docker deploy story, or the Postgres switch. The Romanian academic report (`docs/final-project-report.md`) still describes the v1 surface.

---

## What v2 did well
- The crypto choices are clean: TOTP via `pyotp` with `valid_window=1`, HMAC-SHA256 session tokens, PBKDF2 with 260k iterations for password hashing — all consistent with v1.
- Pending-2FA cookies are separately namespaced (`utc_pending`) and HMAC-typed (`type: "pending_2fa"`), and `verify_session_token` correctly rejects pending tokens being replayed as full sessions (`auth.py:72-73`).
- The frontend login state machine (`password → totp → reset → reset-done`) is cleanly modeled; no orphan states, focus management is correct, codes are numeric-only with `inputMode=numeric` and `autoComplete="one-time-code"`.
- The new schemas use strict Pydantic `Field(..., pattern=r"^\d{6}$")` — good defense in depth alongside the frontend validation.
- `SiteSettings` is a sensible key/value table for runtime-mutable config (the password-reset flow couldn't work without it).

---

## Top three to fix before deploy

1. **Rotate `ADMIN_PASSWORD_HASH` away from the demo hash** in `render.yaml`, or force it to `sync: false`.
2. **Restore the model-download lines in `Dockerfile`** that commit `83b2e53` accidentally reverted, or move the model into the image via `COPY models/url_classifier.skops`.
3. **Fix the test assertion** at `backend/tests/test_api.py:120` (`{"requires_2fa": False, "username": "admin"}`) and add at least one test each for `verify-2fa` and `reset-password`. Until then, CI is meaningless.

Plus: implement actual rate limiting on `/login`, `/verify-2fa`, `/reset-password` — without it, TOTP is a 6-digit secret with no defense.
