# Demo Setup — HTTPS via ngrok

This page is the operator runbook for serving the URL Threat Checker over
HTTPS for a one-shot teacher demo. Everything runs from a single laptop;
ngrok provides the public HTTPS URL.

The full architecture is documented in
[`docs/features/HTTPS.md`](features/HTTPS.md). This file is the
how-to.

---

## Prerequisites

Installed locally:

- `uv` (Python project manager) — backend runtime
- `node` ≥ 20 and `npm` — frontend build + serve
- `ngrok` CLI — TLS tunnel agent (install via `brew install ngrok` on macOS)

ngrok account (one-time):

1. Sign up at <https://dashboard.ngrok.com> (free tier; email or Google).
2. Copy the authtoken from the dashboard.
3. Reserve **one** static domain at
   <https://dashboard.ngrok.com/cloud-edge/domains>. Pick a name like
   `url-threat-checker-demo`. The full URL becomes
   `https://<name>.ngrok-free.app`.
4. Locally: `ngrok config add-authtoken <token>`.

---

## One-time setup on this laptop

### 1. ngrok tunnel config

Open the ngrok config file (the `ngrok config add-authtoken` step above creates
it). The path is OS-dependent — run `ngrok config edit` to open it in `$EDITOR`,
or locate it yourself:

| OS | Path |
|---|---|
| macOS | `~/Library/Application Support/ngrok/ngrok.yml` |
| Linux | `~/.config/ngrok/ngrok.yml` |
| Windows | `%LOCALAPPDATA%\ngrok\ngrok.yml` |

Add a `tunnels` block:

```yaml
version: "3"
agent:
  authtoken: <your token>
tunnels:
  utc:
    proto: http
    addr: 3000
    domain: <reserved-name>.ngrok-free.app
    schemes: [https]
```

`schemes: [https]` is what makes the tunnel reject plain-HTTP requests, which
is the property the "everything under HTTPS" requirement asks for.

### 2. Backend `.env`

Create `backend/.env` (gitignored). Generate the secrets first:

```bash
cd backend
uv sync
uv run hash-password   # prompts for a password; outputs the pbkdf2 hash
uv run setup-2fa       # (OPTIONAL) prints TOTP_SECRET + a QR code
```

Then `backend/.env`:

```ini
APP_ENV=production
SESSION_SECRET=<openssl rand -hex 32>
BACKEND_CORS_ORIGINS=https://<reserved-name>.ngrok-free.app,http://localhost:3000
ADMIN_USERNAME=admin
ADMIN_PASSWORD_HASH=<paste output of hash-password>
TOTP_SECRET=<paste output of setup-2fa, OR leave empty to disable 2FA>
VIRUSTOTAL_API_KEY=<your VT API key>
```

**2FA is optional.** If `TOTP_SECRET` is empty, the login flow is password-only
and the `/api/v1/auth/verify-2fa` and `/api/v1/auth/reset-password` endpoints
become inert (return 400). Useful when the demo is focused on HTTPS-only and
the teacher doesn't need to see the TOTP flow. The frontend "Forgot password?"
link still appears in the UI but will return 400 if clicked — hide it later if
that's a concern.

Notes:

- `BACKEND_CORS_ORIGINS` must list the exact ngrok URL with **no trailing
  slash**. A mismatch produces 403 on every login / scan attempt.
- `APP_ENV=production` enables the `Secure` flag on cookies. After this is set,
  visiting `http://localhost:3000` directly will *not* authenticate
  successfully — always go through the ngrok URL during the demo.
- `MODEL_PATH` and `MODEL_CARD_PATH` are not in this file. The defaults in
  `config.py:33-34` resolve to `<repo>/models/url_classifier.skops` and
  `<repo>/models/model_card.json`, which is what we want.

### 3. Model file

The trained ML model (`url_classifier.skops`, ~234 MB) is gitignored. Link it
from the sibling v1 repo where it lives:

```bash
ln -s /Users/iannis_pop/Developer/url-threat-checker/models/url_classifier.skops \
      /Users/iannis_pop/Developer/url-threat-checker-v2/models/url_classifier.skops
```

(If the model lives elsewhere on your machine, adjust the source path.)

`models/model_card.json` is already committed.

### 4. Build the frontend (one-time, plus after frontend code changes)

```bash
cd frontend
npm install
npm run build
```

Important: do **not** set `NEXT_PUBLIC_API_BASE_URL` in the shell when building.
The build needs the default `/backend` baked in so the browser ends up making
same-origin calls through the Next.js rewrite. If `NEXT_PUBLIC_API_BASE_URL` is
set to something like `http://localhost:8001` during build, the browser will
try to fetch a cross-origin URL and CORS will block everything.

---

## Running the demo

From the repo root:

```bash
./scripts/demo.sh
```

This launches three processes under one shell process group:

1. `uv run uvicorn url_threat_checker.main:app --host 127.0.0.1 --port 8001`
2. `npm run start` (Next.js production server on port 3000)
3. `ngrok start utc`

The ngrok agent prints a Web Interface URL (typically
`http://127.0.0.1:4040`) and the public URL
`https://<reserved-name>.ngrok-free.app`. Share the public URL with the
teacher.

Stop everything with `Ctrl-C` in the same terminal — the `trap 'kill 0'` in
the script kills all three children.

---

## What the teacher sees

1. They visit `https://<reserved-name>.ngrok-free.app`.
2. On their first visit they see ngrok's free-tier interstitial (a "Visit
   Site" warning page that mentions the URL is hosted via ngrok). One click
   gets them through. Subsequent API calls do not trigger the interstitial.
3. The login page loads over HTTPS (visible lock icon, `https://` in the URL
   bar).
4. They sign in with `admin` + the password you configured.
5. If 2FA is enabled (`TOTP_SECRET` set), they are prompted for the 6-digit
   code from Google Authenticator — or you complete this step yourself during
   a synchronous demo. If 2FA is disabled, they go straight to `/dashboard`.
6. They land on `/dashboard` and can run URL scans.

---

## Pre-demo dry run (recommended 24 h ahead)

1. Start the stack: `./scripts/demo.sh`.
2. Confirm all three processes attached: uvicorn 8001, next 3000, ngrok tunnel
   up.
3. Open `https://<reserved-name>.ngrok-free.app` in a clean browser profile.
4. Click through the ngrok interstitial.
5. DevTools → Network → page request: scheme is `https`, lock icon present.
6. Login with `admin` + password.
   - If 2FA is enabled: expect TOTP prompt, then go to step 7.
   - If 2FA is disabled: skip to step 9 (you'll be on `/dashboard`).
7. DevTools → Application → Cookies: `utc_pending` is present, `Secure`,
   `HttpOnly`, `SameSite=Lax`, scoped to the ngrok host.
8. Enter the TOTP code → redirected to `/dashboard`.
9. `utc_session` cookie now present, same flags, 8 h TTL.
10. Run a scan, e.g. `https://google.com` → expect `safe`. Then a known-bad,
    e.g. `https://google.com.fake-domain.ru/login` → expect `dangerous`.
11. Open the scan detail page → confirm "model status: available" (proves the
    symlinked model loaded).
12. Test the forgot-password flow from `/login`: new password + TOTP code →
    log back in with the new password.
13. Refresh — cookies persist. Click logout — `utc_session` is cleared.
14. From a second browser, hit `http://localhost:3000` directly — login fails
    silently (proves `Secure=True` is in effect — cookies are not sent over
    plain HTTP).

Optional smoke test that catches an origin-guard misconfiguration:

```bash
curl -i -X POST https://<reserved-name>.ngrok-free.app/backend/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -H 'Origin: https://attacker.example' \
  --data '{"username":"admin","password":"x"}'
```

Expected: `HTTP 403` with `{"detail":"Request origin is not allowed."}`.

---

## Troubleshooting

| Symptom                                       | Likely cause                                                                                            |
|-----------------------------------------------|---------------------------------------------------------------------------------------------------------|
| Every login / scan returns 403                | `BACKEND_CORS_ORIGINS` has a typo, trailing slash, or `http://` instead of `https://` for the ngrok URL |
| Login succeeds but every later call is 401    | `Secure` cookie set but you're hitting `localhost:3000` directly (not via ngrok)                        |
| Model status shows `unavailable`              | Symlink missing or pointing to a non-existent file (`ls -L models/url_classifier.skops`)                |
| Browser shows ngrok "tunnel not found"        | The reserved domain in `~/.config/ngrok/ngrok.yml` doesn't match what was reserved in the dashboard     |
| Build-time `NEXT_PUBLIC_API_BASE_URL` set     | Browser tries to fetch cross-origin and CORS rejects — rebuild without that env var                     |
| Stuck on ngrok interstitial during fetch      | Only top-level HTML navigations trigger it; XHR calls bypass. If an XHR hits it, an Accept header is missing in the request |
