# 2FA (Two-Factor Authentication) — Current State

This document is a factual inventory of the 2FA implementation as it exists today in `url-threat-checker-v2`. It describes what is present in source, not what is desired. A separate rework plan will be written elsewhere.

## 1. Feature summary

The application implements **TOTP-based two-factor authentication** (RFC 6238, 30-second time step), compatible with Google Authenticator and any other TOTP authenticator app. 2FA is **optional at the deployment level**: it is gated on the `TOTP_SECRET` environment variable being set. When unset, the system falls back to password-only login and the 2FA UI never appears.

A **forgot-password flow** is built on the same TOTP secret: an unauthenticated client may reset the admin password by providing a new password plus a valid TOTP code. There is a single admin account; no per-user 2FA. The TOTP secret is shared, not per-user.

The relevant backend module is `backend/src/url_threat_checker/auth.py`. The frontend lives in `frontend/src/app/login/page.tsx`. The CLI enrollment helper is `backend/src/url_threat_checker/scripts/setup_2fa.py`.

Git history for the feature:
- `83b2e53 feat: add Google Authenticator TOTP 2FA`
- `dd7bd8f feat: forgot password flow using TOTP verification`

## 2. Setup flow (operator-side, CLI only)

The operator runs:

```
uv run setup-2fa
```

The `setup-2fa` entry point is declared in `backend/pyproject.toml` (line 37) and points to `url_threat_checker.scripts.setup_2fa:main`. The script (`backend/src/url_threat_checker/scripts/setup_2fa.py`):

1. Generates a fresh secret with `pyotp.random_base32()` (line 8).
2. Builds an `otpauth://` provisioning URI via `totp.provisioning_uri(name="admin", issuer_name="URL Threat Checker")` (line 10). Both `name` and `issuer_name` are hardcoded in the script — they do **not** read from `config.Settings.totp_issuer`.
3. Prints `TOTP_SECRET=<secret>` for the `.env` file (lines 13–14).
4. Prints a second copy of the secret labeled for an external environment-variable panel (lines 15–16). The label still says "Render" in the source text although the project no longer deploys to Render; treat it as a generic "paste this into wherever you keep prod env vars."
5. Renders an ASCII QR code to stdout using `qrcode.QRCode(border=1)` + `qr.print_ascii(invert=True, tty=sys.stdout.isatty())` (lines 19–21).
6. Prints the manual entry key (`Secret: <secret>`, lines 23–24).
7. Prints the **current 6-digit code** via `totp.now()` so the operator can verify they entered the secret correctly (line 25).
8. Instructs the operator to add the secret to `.env` and to the deployment env (lines 26–27).

The script does **not** write to `.env`, does **not** persist anything to the database, and does **not** rotate an existing secret in any tracked way — the operator pastes the secret into env manually. There is no de-enrollment flow.

## 3. Runtime gate

2FA is enabled iff `settings.totp_secret` is truthy.

The check happens at login time in `backend/src/url_threat_checker/auth.py`:

```python
if settings.totp_secret:                                  # auth.py:181
    pending = _create_pending_token(...)
    response.set_cookie(_PENDING_COOKIE, pending, ...)
    return LoginResponse(requires_2fa=True)
```

If `totp_secret` is falsy (unset / empty string / `None`), the login endpoint immediately mints a full session and returns `LoginResponse(username=...)` with `requires_2fa` defaulting to `False` (`schemas.py:15-17`). The frontend keys its UI transitions off the `requires_2fa` field returned by `/api/v1/auth/login` (`login/page.tsx:49`), so when the backend reports `false` the user is routed straight to `/dashboard` and no TOTP screen is ever shown.

The `/api/v1/auth/verify-2fa` endpoint also short-circuits with HTTP 400 `"2FA is not configured."` if called while `totp_secret` is falsy (`auth.py:210-211`).

The `/api/v1/auth/reset-password` endpoint requires `totp_secret` to be set, returning HTTP 400 `"Password reset requires 2FA to be configured. Set up Google Authenticator first."` otherwise (`auth.py:229-233`).

## 4. Login flow (state machine)

### 4.1 `POST /api/v1/auth/login` (`auth.py:170-196`)

Body: `LoginRequest { username, password }` (`schemas.py:10-12`).

1. Loads the active password hash via `_get_password_hash(db, settings)` (`auth.py:177`), which reads from the `site_settings` DB table first and falls back to `settings.admin_password_hash` (see Section 5).
2. Compares username equality and `verify_password(payload.password, password_hash)` (`auth.py:178`). On mismatch: HTTP 401 `"Invalid credentials."`.
3. **Branch on 2FA**:
   - If `settings.totp_secret` is truthy (`auth.py:181`):
     - Mints a **pending token** via `_create_pending_token(settings.admin_username, settings.session_secret)` (`auth.py:77-86`). Payload: `{sub, type: "pending_2fa", iat, exp}` with `exp = now + 300` seconds.
     - Sets cookie `utc_pending` with `path=/`, `httponly=True`, `samesite="lax"`, `secure = (app_env == "production")`, `max_age = 300` (`auth.py:183-191`, constant `_PENDING_TTL = 300` at `auth.py:26`).
     - Returns `LoginResponse(requires_2fa=True)` — `username` is `None` in this branch (`auth.py:192`).
   - Else (no 2FA):
     - Mints a session token via `create_session_token(...)` (`auth.py:63-67`, payload `{sub, iat, exp}`).
     - Sets `utc_session` cookie via `_set_session_cookie` (`auth.py:133-142`, `auth.py:195`).
     - Returns `LoginResponse(username=settings.admin_username)` (`auth.py:196`).

### 4.2 `POST /api/v1/auth/verify-2fa` (`auth.py:199-220`)

Body: `TotpVerifyRequest { code: str }` validated `^\d{6}$`, length exactly 6 (`schemas.py:20-21`).

1. Reads `utc_pending` cookie from the request and decodes it via `_verify_pending_token` (`auth.py:206`). `_verify_pending_token` (`auth.py:89-93`) returns `None` unless `payload["type"] == "pending_2fa"`. On miss: HTTP 401 `"Session expired. Please log in again."` (`auth.py:207-208`).
2. Re-checks `settings.totp_secret`; HTTP 400 `"2FA is not configured."` if falsy (`auth.py:210-211`).
3. Verifies the code with `pyotp.TOTP(settings.totp_secret).verify(payload.code, valid_window=1)` (`auth.py:213`). On failure: HTTP 401 `"Invalid authentication code."` (`auth.py:214`).
4. On success:
   - Deletes the `utc_pending` cookie (`auth.py:216-217`).
   - Mints a new session token for `pending["sub"]` and sets `utc_session` via `_set_session_cookie` (`auth.py:218-219`).
   - Returns `AuthUser(username=pending["sub"])` (`auth.py:220`, schema `schemas.py:29-30`).

The pending cookie is not refreshed across retries — once issued it has 300 s to be redeemed, regardless of how many invalid codes are submitted.

### 4.3 Session enforcement on subsequent requests

All protected endpoints depend on `current_admin` (`auth.py:157-165`). It reads the `utc_session` cookie, decodes via `verify_session_token` (`auth.py:70-74`), and verifies that:
- The HMAC matches.
- The payload is **not** of `type: "pending_2fa"` — `verify_session_token` explicitly rejects pending tokens being used as session tokens (`auth.py:72`). This is the mechanism that prevents a pending cookie from being used as a session cookie.
- `sub == settings.admin_username` (`auth.py:163`).

`/api/v1/auth/me` is a thin wrapper that returns `AuthUser(username=current_admin)` (`auth.py:250-252`).

### 4.4 `POST /api/v1/auth/logout` (`auth.py:241-247`)

Clears `utc_session` via `_clear_session_cookie` (`auth.py:145-152`, called at `auth.py:246`). Returns `{"ok": True}`. Logout does **not** invalidate the token server-side (no revocation list); it only deletes the client-side cookie.

## 5. Forgot-password flow

### Endpoint: `POST /api/v1/auth/reset-password` (`auth.py:223-238`)

Body: `ResetPasswordRequest { new_password: str (8..512), totp_code: str (^\d{6}$, len 6) }` (`schemas.py:24-26`).

This endpoint is **unauthenticated** — no session cookie, no pending cookie, no rate limit on this route specifically. It accepts a TOTP code as the sole proof of identity.

1. If `settings.totp_secret` is falsy: HTTP 400 `"Password reset requires 2FA to be configured. Set up Google Authenticator first."` (`auth.py:229-233`).
2. `pyotp.TOTP(settings.totp_secret).verify(payload.totp_code, valid_window=1)` (`auth.py:234`). On failure: HTTP 401 `"Invalid authentication code."` (`auth.py:235`).
3. On success: `_set_password_hash(db, hash_password(payload.new_password))` (`auth.py:237`). This writes the new pbkdf2_sha256 hash to the `site_settings` row keyed by `admin_password_hash` (constant `_SETTING_PASSWORD_HASH` at `auth.py:27`).
4. Returns `{"ok": True}` (`auth.py:238`).

### Password-hash storage and read path

The `SiteSettings` table is defined at `backend/src/url_threat_checker/database.py:63-67` as a simple key/value table:

```python
class SiteSettings(Base):
    __tablename__ = "site_settings"
    key:   Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text)
```

`_get_password_hash` (`auth.py:117-119`):

```python
row = db.get(SiteSettings, _SETTING_PASSWORD_HASH)
return row.value if row else settings.admin_password_hash
```

The DB row, if present, **always overrides** the env-supplied hash. The env value (`ADMIN_PASSWORD_HASH`) is the **initial** hash; after the first successful reset, the DB row takes precedence permanently.

`_set_password_hash` (`auth.py:122-128`) upserts the row and commits.

`hash_password` (`auth.py:98-101`) uses `pbkdf2_sha256` with 260,000 iterations, a 16-byte random salt, and the format `pbkdf2_sha256$<iterations>$<salt_b64url>$<digest_b64url>`. `verify_password` (`auth.py:104-114`) parses that format and uses `hmac.compare_digest` for the comparison.

## 6. Token model

Two cookies, both produced by the same `_make_token` helper (`auth.py:40-44`).

### Encoding (`auth.py:32-44`)

```
token = base64url(json_payload).b64 + "." + base64url(HMAC_SHA256(secret, json_payload_b64))
```

- The JSON payload is serialized with `json.dumps(..., separators=(",", ":"), sort_keys=True)` for deterministic byte content.
- Base64-url encoding strips padding (`rstrip("=")`); `_b64decode` re-pads with `"=" * (-len(value) % 4)` (`auth.py:36-37`).
- The signature is computed over the **base64-encoded** payload bytes (not the raw JSON).
- `_decode_token` (`auth.py:47-60`) re-computes the HMAC, uses `hmac.compare_digest`, parses the JSON, and rejects payloads where `int(payload.get("exp", 0)) < int(time.time())`.

Both token types share `sub`, `iat`, `exp`. Times are integer Unix seconds.

### `utc_session` (full session cookie)

- Created by `create_session_token(username, secret, ttl_seconds)` (`auth.py:63-67`).
- Payload: `{"sub": username, "iat": <now>, "exp": <now + ttl_seconds>}`.
- TTL: `settings.session_ttl_seconds`, default `60 * 60 * 8 = 28800` seconds / 8 hours (`config.py:31`).
- Cookie name: `settings.session_cookie_name`, default `"utc_session"` (`config.py:30`).
- Cookie attributes (`auth.py:133-142`): `path="/"`, `httponly=True`, `samesite="lax"`, `secure=(app_env=="production")`, `max_age=settings.session_ttl_seconds`.
- Verified by `verify_session_token` (`auth.py:70-74`), which **rejects tokens that include `type: "pending_2fa"`** even if the signature is valid.

### `utc_pending` (mid-login marker)

- Created by `_create_pending_token(username, secret)` (`auth.py:77-86`).
- Payload: `{"sub": username, "type": "pending_2fa", "iat": <now>, "exp": <now + 300>}`.
- TTL: `_PENDING_TTL = 300` seconds (`auth.py:26`).
- Cookie name: `_PENDING_COOKIE = "utc_pending"` (`auth.py:25`).
- Cookie attributes (`auth.py:183-191`): same as session cookie, with `max_age=_PENDING_TTL`.
- Verified by `_verify_pending_token` (`auth.py:89-93`), which **requires** `type == "pending_2fa"`.
- Cleared in `verify_2fa` after successful TOTP verification (`auth.py:216-217`).

Both cookies are signed with the same `settings.session_secret`. The `type` field is the only structural difference; the consumer functions enforce mutual exclusion by checking `type` before accepting a token.

### TOTP verification window

`pyotp.TOTP(...).verify(code, valid_window=1)` is used in both `verify_2fa` (`auth.py:213`) and `reset_password` (`auth.py:234`). `valid_window=1` means the library accepts the previous, current, and next 30-second windows — i.e. a code is valid for ±30 s around its issued window, giving a worst case of ~90 s acceptance per 6-digit code.

## 7. Frontend UX

File: `frontend/src/app/login/page.tsx`.

### State machine

```ts
type Step = "password" | "totp" | "reset" | "reset-done";   // page.tsx:9
const [step, setStep] = useState<Step>("password");          // page.tsx:13
```

Local form state held by `useState`:
- `username`, `password` (defaults `"admin"` / `""`) — `page.tsx:16-17`
- `totpCode` — `page.tsx:20`
- `newPassword`, `confirmPassword`, `resetCode` — `page.tsx:23-25`
- `error`, `loading` — `page.tsx:27-28`

Refs for focus management:
- `totpRef` (TOTP input) — `page.tsx:30`
- `resetCodeRef` (reset-flow TOTP input) — `page.tsx:31`

Focus on step entry (`page.tsx:33-36`):
```ts
useEffect(() => {
  if (step === "totp")  totpRef.current?.focus();
  if (step === "reset") resetCodeRef.current?.focus();
}, [step]);
```

Step transitions are routed through `goTo(next)` which also clears `error` (`page.tsx:38-41`).

### `password` step (`page.tsx:238-283`)

- Username + password inputs.
- Submit handler `submitPassword` (`page.tsx:43-55`): calls `login(username, password)` from `lib/api.ts`.
- Branches on `result.requires_2fa`: if true, `goTo("totp")`; otherwise `router.push("/dashboard")` (`page.tsx:49`).
- "Forgot password?" button transitions to `reset` step (`page.tsx:273-279`).

### `totp` step (`page.tsx:188-235`)

- Single 6-digit input.
- Input masking: `onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, "").slice(0, 6))}` (`page.tsx:209`) — strips all non-digits and caps to 6 characters.
- Browser hints: `inputMode="numeric"`, `autoComplete="one-time-code"`, `placeholder="000000"`, `maxLength={6}` (`page.tsx:210-213`).
- Submit button disabled while `loading || totpCode.length !== 6` (`page.tsx:219`).
- `submitTotp` (`page.tsx:57-71`): calls `verify2fa(totpCode)`. On error, clears `totpCode` and re-focuses the input (`page.tsx:66-67`). On success, `router.push("/dashboard")` (`page.tsx:63`).
- "Back to login" button clears `totpCode` and returns to `password` (`page.tsx:224-230`).
- Heading: "Two-Factor Auth"; copy references "URL Threat Checker" as the issuer label shown to the user (`page.tsx:198-200`).

### `reset` step (`page.tsx:116-185`)

- Inputs: new password, confirm password, TOTP code.
- Client-side guard: `if (newPassword !== confirmPassword) setError("Passwords do not match.")` and returns without submitting (`page.tsx:74-78`).
- HTML5 `minLength={8}` on the new-password input (`page.tsx:138`).
- TOTP code input has the same masking and `autoComplete="one-time-code"` treatment as the login TOTP step (`page.tsx:159-163`).
- Submit button disabled while `loading || resetCode.length !== 6 || !newPassword || !confirmPassword` (`page.tsx:169`).
- `submitReset` (`page.tsx:73-91`): calls `resetPassword(newPassword, resetCode)`. On error, clears `resetCode` and re-focuses (`page.tsx:86-87`). On success: `goTo("reset-done")` (`page.tsx:83`).

### `reset-done` step (`page.tsx:94-113`)

Static confirmation panel with a "Back to login" button that clears `newPassword`, `confirmPassword`, `resetCode` and returns to `password` (`page.tsx:105`).

### API client wrappers (`frontend/src/lib/api.ts`)

All calls use `apiFetch` (`api.ts:124-140`) which sets `credentials: "include"` so cookies are sent/stored cross-origin.

- `login(username, password)` → POST `/api/v1/auth/login` (`api.ts:147-152`). Return type `LoginResult { requires_2fa: boolean, username?: string }` (`api.ts:142-145`).
- `verify2fa(code)` → POST `/api/v1/auth/verify-2fa` (`api.ts:154-159`).
- `resetPassword(newPassword, totpCode)` → POST `/api/v1/auth/reset-password` with body `{ new_password, totp_code }` (`api.ts:161-166`).
- `logout()` → POST `/api/v1/auth/logout` (`api.ts:168-172`).

## 8. Configuration surface

Every env var / config field that affects 2FA or the auth flow it shares plumbing with:

| Variable | Type | Default | Read at | Purpose |
|---|---|---|---|---|
| `TOTP_SECRET` | `str \| None` | `None` | `config.py:36` | Base32 TOTP secret. Truthiness gates 2FA. Read in `auth.py:181`, `auth.py:210`, `auth.py:213`, `auth.py:229`, `auth.py:234`. |
| `TOTP_ISSUER` | `str` | `"URL Threat Checker"` | `config.py:37` | Settings field present but **not used at runtime** — the setup-2fa script hardcodes `"URL Threat Checker"` as `issuer_name` directly (`scripts/setup_2fa.py:10`). |
| `SESSION_SECRET` | `str` | `"dev-session-secret-change-me"` | `config.py:29` | HMAC-SHA256 key for both `utc_session` and `utc_pending` tokens. Used in `auth.py:43, 51, 162, 182, 206, 218`. |
| `SESSION_COOKIE_NAME` | `str` | `"utc_session"` | `config.py:30` | Name of the full-session cookie. Used in `auth.py:134, 147, 161`. |
| `SESSION_TTL_SECONDS` | `int` | `60 * 60 * 8` (28800) | `config.py:31` | Lifetime of the session token + cookie `max_age`. Used in `auth.py:141, 194, 218`. |
| `ADMIN_USERNAME` | `str` | `"admin"` | `config.py:27` | Sole admin account; used as `sub` claim and compared in `auth.py:163, 178, 182, 194`. |
| `ADMIN_PASSWORD_HASH` | `str` | `DEFAULT_ADMIN_PASSWORD_HASH` (`config.py:10-13`, encodes the demo password `admin123`) | `config.py:28` | Initial pbkdf2 hash. Overridden by `site_settings.admin_password_hash` DB row once reset has been used (`auth.py:117-119`). |
| `APP_ENV` | `str` | `"development"` | `config.py:23` | Cookies get `secure=True` only when this equals `"production"` (`auth.py:140, 151, 189, 217`). |

All 2FA-related secrets (`TOTP_SECRET`, `SESSION_SECRET`, `ADMIN_PASSWORD_HASH`) are configured by the operator in `backend/.env` for the ngrok demo deployment. `backend/.env.example` (line 9) declares `TOTP_SECRET=` (empty) to document the variable name. Other auth-related lines: `ADMIN_USERNAME` (4), `ADMIN_PASSWORD_HASH` (5), `SESSION_SECRET` (6). The operator runbook is `docs/demo-setup.md`.

## 9. Dependencies

From `backend/pyproject.toml`:

| Package | Pin | Purpose |
|---|---|---|
| `pyotp` | `>=2.9` (line 16) | TOTP secret generation (`pyotp.random_base32`) and verification (`pyotp.TOTP(...).verify`). |
| `qrcode` | `>=8.0` (line 17) | ASCII QR rendering in `setup_2fa`. |
| `pydantic` | `>=2.13.0` (line 11) | Schema validation for `LoginRequest`, `TotpVerifyRequest`, `ResetPasswordRequest`. |
| `pydantic-settings` | `>=2.12.0` (line 12) | `BaseSettings` for `Settings` class incl. `totp_secret`/`totp_issuer`. |
| `fastapi` | `>=0.124.0` (line 8) | Router, dependency injection, `HTTPException` for the auth endpoints. |
| `sqlalchemy` | `>=2.0.49` (line 18) | Persists the `site_settings` row used by reset-password. |

Standard library only for the token machinery: `base64`, `hashlib`, `hmac`, `json`, `os`, `time` (`auth.py:1-7`). No JWT library.

The `[project.scripts]` table (`pyproject.toml:30-37`) declares the CLI entry point:
```
setup-2fa = "url_threat_checker.scripts.setup_2fa:main"
```

## 10. Deployment integration (ngrok demo)

The deployment artifact is `scripts/demo.sh`, which runs the stack on the
operator's laptop and exposes the frontend via a single ngrok HTTPS tunnel.
See `docs/demo-setup.md` for the full runbook.

2FA-related operator setup:

- `TOTP_SECRET` is produced by `uv run setup-2fa` and pasted into
  `backend/.env`. The script prints the secret, a QR code, and the manual
  entry key.
- `SESSION_SECRET` is generated locally (e.g. `openssl rand -hex 32`) and
  pasted into `backend/.env`. There is no platform-managed secret generation in
  this topology.
- `ADMIN_PASSWORD_HASH` is generated by `uv run hash-password` (prompts for
  the password, prints the pbkdf2 hash) and pasted into `backend/.env`. The
  reset-password flow still works to rotate it later — the new hash is written
  to `site_settings.admin_password_hash` (`auth.py:117-128`) and takes
  precedence over the env value on subsequent logins.
- `APP_ENV=production` in `backend/.env` is what causes both cookies to be
  issued with `Secure` (`auth.py:140, 151, 189, 217`). Without it, the
  `Secure` flag is omitted and the cookies would not be sent over the HTTPS
  ngrok URL by browsers that strictly enforce the flag.
- The database is SQLite by default (`config.py:24`,
  `backend/var/url_threat_checker.db`), so the `site_settings` row created on
  password reset persists across `demo.sh` runs as long as the file is not
  deleted.

2FA introduces no special deployment changes — `pyotp` and `qrcode` are
ordinary dependencies installed by `uv sync` before the first run.

## 11. What is NOT yet implemented

Stated as observed gaps, not as critique:

- **No backup / recovery codes.** Losing the authenticator app means relying on the unauthenticated reset-password flow — which itself needs the TOTP secret. If the authenticator is lost, the only fallback is operator access to `backend/.env` plus a database wipe of the `site_settings.admin_password_hash` row.
- **No rate limiting on 2FA verification.** `verify-2fa` and `reset-password` have no per-IP or per-cookie throttle in `auth.py`. Note: `.env.example` line 14 declares `LOGIN_RATE_LIMIT_PER_MINUTE=5`, but `Settings` in `config.py` does not define a corresponding field and `auth.py` does not reference any rate limiter.
- **No audit log.** Successful and failed logins, 2FA verifications, and password resets are not recorded. The `database.py` schema has no `audit_events` table (and `reset_database_schema` explicitly drops one if it ever existed — `database.py:106`).
- **No "remember this device" / trusted device.** Every login requires a fresh TOTP code; the pending cookie is single-use and bound to a 5-minute window.
- **No in-app enrollment UI.** Enrollment is CLI-only via `uv run setup-2fa`. There is no `/settings` page or modal that displays a QR or rotates the secret. Once `TOTP_SECRET` is set, no UI element acknowledges it.
- **No per-user 2FA.** There is one admin account (`settings.admin_username`, default `"admin"`). The TOTP secret is global to the deployment.
- **No automated test coverage for 2FA endpoints.** `backend/tests/test_api.py` does not exercise `/api/v1/auth/verify-2fa` or `/api/v1/auth/reset-password`. The `login` helper at `test_api.py:45-50` only covers the no-2FA branch — all tests instantiate `Settings(virustotal_api_key=None)` (`test_api.py:26`), which leaves `totp_secret` at its default `None`. No test asserts the `requires_2fa: true` branch, the pending-cookie issuance, the `valid_window=1` behavior, or the `type: "pending_2fa"` rejection in `verify_session_token`.
- **No validation of `TOTP_SECRET` format at startup.** `Settings` accepts any string. An invalid base32 value would only fail at first call to `pyotp.TOTP(...).verify(...)`, not at app boot.
- **No session revocation.** `logout` deletes the client-side cookie but the signed token remains valid until its `exp` if it were replayed.
- **Pending cookie is not bound to the password attempt.** `_create_pending_token` only encodes `sub`. There is no nonce or correlation to the `LoginRequest` that produced it. The token cannot be replayed across deployments because `session_secret` differs, but within one deployment a stolen `utc_pending` cookie could be used until it expires.
- **`totp_issuer` setting is dead code.** Declared at `config.py:37` but the setup script hardcodes `"URL Threat Checker"` (`setup_2fa.py:10`). Changing `TOTP_ISSUER` in the env has no observable effect.
- **No CSRF token on auth POSTs.** Protection currently relies on `SameSite=Lax` cookies and the origin guard mentioned in `test_api.py:244-258` (which lives in middleware, not in `auth.py`).

## 12. File / line citation table

| Claim | File | Lines |
|---|---|---|
| TOTP secret field declared | `backend/src/url_threat_checker/config.py` | 36 |
| TOTP issuer field declared (unused) | `backend/src/url_threat_checker/config.py` | 37 |
| Session secret default | `backend/src/url_threat_checker/config.py` | 29 |
| Session cookie name default | `backend/src/url_threat_checker/config.py` | 30 |
| Session TTL default (8 h) | `backend/src/url_threat_checker/config.py` | 31 |
| Admin username default | `backend/src/url_threat_checker/config.py` | 27 |
| Default admin password hash constant | `backend/src/url_threat_checker/config.py` | 10–13, 28 |
| `_PENDING_COOKIE` constant | `backend/src/url_threat_checker/auth.py` | 25 |
| `_PENDING_TTL = 300` | `backend/src/url_threat_checker/auth.py` | 26 |
| `_SETTING_PASSWORD_HASH` constant | `backend/src/url_threat_checker/auth.py` | 27 |
| Base64-url helpers | `backend/src/url_threat_checker/auth.py` | 32–37 |
| `_make_token` (HMAC-SHA256) | `backend/src/url_threat_checker/auth.py` | 40–44 |
| `_decode_token` (signature + exp check) | `backend/src/url_threat_checker/auth.py` | 47–60 |
| `create_session_token` | `backend/src/url_threat_checker/auth.py` | 63–67 |
| `verify_session_token` rejects `pending_2fa` | `backend/src/url_threat_checker/auth.py` | 70–74 |
| `_create_pending_token` payload shape | `backend/src/url_threat_checker/auth.py` | 77–86 |
| `_verify_pending_token` requires type | `backend/src/url_threat_checker/auth.py` | 89–93 |
| `hash_password` (pbkdf2_sha256, 260k) | `backend/src/url_threat_checker/auth.py` | 98–101 |
| `verify_password` (constant-time compare) | `backend/src/url_threat_checker/auth.py` | 104–114 |
| `_get_password_hash` DB-first, env fallback | `backend/src/url_threat_checker/auth.py` | 117–119 |
| `_set_password_hash` upsert to `site_settings` | `backend/src/url_threat_checker/auth.py` | 122–128 |
| `_set_session_cookie` attributes | `backend/src/url_threat_checker/auth.py` | 133–142 |
| `_clear_session_cookie` | `backend/src/url_threat_checker/auth.py` | 145–152 |
| `current_admin` dependency | `backend/src/url_threat_checker/auth.py` | 157–165 |
| `POST /login` body and verification | `backend/src/url_threat_checker/auth.py` | 170–179 |
| Login 2FA branch (pending cookie issuance) | `backend/src/url_threat_checker/auth.py` | 181–192 |
| Login no-2FA branch (session cookie issuance) | `backend/src/url_threat_checker/auth.py` | 194–196 |
| `POST /verify-2fa` pending lookup | `backend/src/url_threat_checker/auth.py` | 206–208 |
| `verify-2fa` no-secret guard | `backend/src/url_threat_checker/auth.py` | 210–211 |
| TOTP `verify(code, valid_window=1)` | `backend/src/url_threat_checker/auth.py` | 213–214 |
| Pending cookie cleared, session minted | `backend/src/url_threat_checker/auth.py` | 216–219 |
| `POST /reset-password` no-secret guard | `backend/src/url_threat_checker/auth.py` | 229–233 |
| `reset-password` TOTP verification | `backend/src/url_threat_checker/auth.py` | 234–235 |
| `reset-password` writes new hash | `backend/src/url_threat_checker/auth.py` | 237–238 |
| `POST /logout` | `backend/src/url_threat_checker/auth.py` | 241–247 |
| `GET /me` | `backend/src/url_threat_checker/auth.py` | 250–252 |
| `SiteSettings` table definition | `backend/src/url_threat_checker/database.py` | 63–67 |
| `LoginRequest` schema | `backend/src/url_threat_checker/schemas.py` | 10–12 |
| `LoginResponse` schema (`requires_2fa`, `username`) | `backend/src/url_threat_checker/schemas.py` | 15–17 |
| `TotpVerifyRequest` schema (`^\d{6}$`) | `backend/src/url_threat_checker/schemas.py` | 20–21 |
| `ResetPasswordRequest` schema | `backend/src/url_threat_checker/schemas.py` | 24–26 |
| `AuthUser` schema | `backend/src/url_threat_checker/schemas.py` | 29–30 |
| `setup-2fa` generates secret | `backend/src/url_threat_checker/scripts/setup_2fa.py` | 8 |
| Provisioning URI (hardcoded issuer) | `backend/src/url_threat_checker/scripts/setup_2fa.py` | 9–10 |
| Prints env lines for `.env` and deployment env | `backend/src/url_threat_checker/scripts/setup_2fa.py` | 13–16 |
| QR ASCII rendering | `backend/src/url_threat_checker/scripts/setup_2fa.py` | 19–21 |
| Manual key + current verification code | `backend/src/url_threat_checker/scripts/setup_2fa.py` | 23–25 |
| `pyotp` dependency | `backend/pyproject.toml` | 15 |
| `qrcode` dependency | `backend/pyproject.toml` | 16 |
| `setup-2fa` entry point | `backend/pyproject.toml` | 36 |
| `TOTP_SECRET` placeholder in env example | `backend/.env.example` | 9 |
| ngrok demo orchestration | `scripts/demo.sh` | 17–19 |
| Demo operator runbook | `docs/demo-setup.md` | — |
| Frontend `Step` type | `frontend/src/app/login/page.tsx` | 9 |
| Initial step | `frontend/src/app/login/page.tsx` | 13 |
| Refs for focus management | `frontend/src/app/login/page.tsx` | 30–31 |
| Focus on step change | `frontend/src/app/login/page.tsx` | 33–36 |
| `submitPassword` branches on `requires_2fa` | `frontend/src/app/login/page.tsx` | 43–55 |
| `submitTotp` clears on error | `frontend/src/app/login/page.tsx` | 57–71 |
| `submitReset` password-match guard | `frontend/src/app/login/page.tsx` | 73–91 |
| `reset-done` view | `frontend/src/app/login/page.tsx` | 94–113 |
| `reset` form (inputs, validation, OTC autocomplete) | `frontend/src/app/login/page.tsx` | 116–185 |
| `totp` form (numeric mask, OTC autocomplete) | `frontend/src/app/login/page.tsx` | 188–235 |
| Password form ("Forgot password?" link) | `frontend/src/app/login/page.tsx` | 238–283 |
| `login()` API call | `frontend/src/lib/api.ts` | 147–152 |
| `verify2fa()` API call | `frontend/src/lib/api.ts` | 154–159 |
| `resetPassword()` API call | `frontend/src/lib/api.ts` | 161–166 |
| `logout()` API call | `frontend/src/lib/api.ts` | 168–172 |
| `apiFetch` sends cookies (`credentials: "include"`) | `frontend/src/lib/api.ts` | 124–140 |
| Tests do not cover 2FA branches | `backend/tests/test_api.py` | 26, 45–50, 113–135 |
| Git commit: TOTP 2FA added | (git log) | `83b2e53` |
| Git commit: forgot-password via TOTP | (git log) | `dd7bd8f` |
