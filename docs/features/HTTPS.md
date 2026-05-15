# HTTPS / Secure Transport — Current State

This document inventories the HTTPS and secure-transport behaviour that exists
in the repository today. It describes what is implemented, where it lives, and
what is not implemented. It is purely descriptive — the rework plan is tracked
separately.

The stack is a FastAPI backend (uvicorn on `127.0.0.1:8001`, plain HTTP) and a
Next.js 16 frontend (`next start` on `localhost:3000`, plain HTTP). Both run on
the developer's laptop. The public HTTPS surface is provided by a single ngrok
tunnel pointed at the frontend; the backend is never exposed to the internet.

The chain a browser request takes:

```
Browser  ─https→  ngrok edge (TLS)  ─http→  next start (3000)  ─http→  uvicorn (8001)
                                              │ Next.js /backend/* rewrite
                                              ▼
```

---

## 1. TLS Termination

### Where TLS lives

TLS is terminated at the ngrok edge. The application code never sees a TLS
handshake and never holds a certificate. ngrok manages and rotates a Let's
Encrypt certificate for the reserved `<name>.ngrok-free.app` hostname.

The backend container is gone — uvicorn is started directly via
`uv run uvicorn url_threat_checker.main:app --host 127.0.0.1 --port 8001`
(see `scripts/demo.sh`) and binds to loopback only. The Next.js production
server runs via `npm run start` on `localhost:3000`. Neither process accepts
TLS; both speak plain HTTP because the only client that talks to them is on
the same machine.

There is no `--ssl-keyfile`, no `--ssl-certfile`, no Caddy, no nginx, no
in-process TLS proxy. The ngrok agent (`ngrok start utc`) handles every
HTTPS-side concern: certificate provisioning, renewal, SNI, cipher selection.

### HTTPS-only enforcement at the tunnel

The tunnel configuration declares `schemes: [https]`, so the ngrok edge refuses
plain-HTTP connections to the public hostname and serves only HTTPS. There is
no application-layer redirect because there is no plain-HTTP request path that
reaches the application.

### Operator responsibility for certificates

The operator does not provision, rotate, or mount TLS certificates anywhere in
this repository. Certificate management is handled entirely by the ngrok
platform for the reserved `*.ngrok-free.app` hostname.

---

## 2. Session Cookie Posture

The auth flow issues a single session cookie (and a short-lived `utc_pending`
cookie during 2FA). Both cookies set their `secure` flag conditionally on the
`APP_ENV` value.

### Main session cookie

`backend/src/url_threat_checker/auth.py:133-142`:

```python
def _set_session_cookie(response: Response, token: str, settings: Settings) -> None:
    response.set_cookie(
        settings.session_cookie_name,
        token,
        path="/",
        httponly=True,
        samesite="lax",
        secure=settings.app_env == "production",
        max_age=settings.session_ttl_seconds,
    )
```

Attributes:

| Attribute  | Value                                          |
|------------|------------------------------------------------|
| name       | `utc_session` (default, `config.py:30`)        |
| path       | `/`                                            |
| httponly   | `True`                                         |
| samesite   | `lax`                                          |
| secure     | `True` only when `settings.app_env == "production"` |
| max_age    | `settings.session_ttl_seconds` (default `60 * 60 * 8` = 8 hours, `config.py:31`) |

The matching delete path mirrors the same flags
(`auth.py:145-152`).

### Pending 2FA cookie

`backend/src/url_threat_checker/auth.py:183-191`:

```python
response.set_cookie(
    _PENDING_COOKIE,
    pending,
    path="/",
    httponly=True,
    samesite="lax",
    secure=settings.app_env == "production",
    max_age=_PENDING_TTL,
)
```

`_PENDING_COOKIE = "utc_pending"` and `_PENDING_TTL = 300` seconds
(`auth.py:25-26`). Cleared on successful verification at `auth.py:216-217`.

### How `secure=True` is enabled

`secure` is gated on `settings.app_env == "production"`. The default value in
config is `"development"`:

`backend/src/url_threat_checker/config.py:23`:

```python
app_env: str = "development"
```

For the ngrok demo, the operator sets `APP_ENV=production` in
`backend/.env`. That single switch turns `Secure` on for both cookies, so the
browser will only return them over the HTTPS tunnel. For pure local dev
(no ngrok in front), the operator either omits `APP_ENV` or sets it to
`development`, which is required for browsers to accept the cookie over plain
`http://localhost`.

---

## 3. CORS, Origin Guard, and Body-Size Guard

### CORS middleware

`backend/src/url_threat_checker/main.py:37-43`:

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

`allow_credentials=True` is required so the browser sends the `utc_session`
cookie cross-origin when applicable.

### Origin list parsing

The allowed origin list is parsed from a comma-separated string.

`backend/src/url_threat_checker/config.py:25`:

```python
backend_cors_origins: str = "http://localhost:3000"
```

`backend/src/url_threat_checker/config.py:46-48`:

```python
@property
def cors_origins(self) -> list[str]:
    return [origin.strip() for origin in self.backend_cors_origins.split(",") if origin.strip()]
```

The operator sets `BACKEND_CORS_ORIGINS` to a comma-separated allow-list. For
the ngrok demo the value is typically:

```
BACKEND_CORS_ORIGINS=https://<reserved-name>.ngrok-free.app,http://localhost:3000
```

The ngrok URL goes first so production-mode (Secure-cookie) requests through
the tunnel pass the origin guard; the localhost entry keeps `next dev` working
when an operator hits the frontend directly without ngrok. There is no
automatic upgrade of `http://` entries to `https://`; whatever scheme appears
in the env var is what gets matched. A trailing slash on the ngrok URL will
cause every state-changing request to return 403.

### Origin guard for state-changing requests

The same allow-list backs an explicit origin guard for non-idempotent methods.

`backend/src/url_threat_checker/main.py:14-20`:

```python
def _origin_from_header(value: str | None) -> str | None:
    if not value:
        return None
    parsed = urlparse(value)
    if not parsed.scheme or not parsed.netloc:
        return None
    return f"{parsed.scheme}://{parsed.netloc}"
```

`backend/src/url_threat_checker/main.py:59-67`:

```python
if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
    origin = request.headers.get("origin") or _origin_from_header(
        request.headers.get("referer")
    )
    if origin and origin not in settings.cors_origins:
        return JSONResponse(
            status_code=403,
            content={"detail": "Request origin is not allowed."},
        )
```

The guard compares the full `scheme://host[:port]` triple, so a request from
`http://example.com` will not match an `https://example.com` allow-list entry
(and vice versa).

### Body-size guard

`backend/src/url_threat_checker/main.py:46-57`:

```python
@app.middleware("http")
async def request_guard(request: Request, call_next):
    content_length = request.headers.get("content-length")
    body_too_large = (
        content_length
        and content_length.isdigit()
        and int(content_length) > settings.max_request_body_bytes
    )
    if body_too_large:
        return JSONResponse(
            status_code=413,
            content={"detail": "Request body too large."},
        )
```

The cap is configured at `backend/src/url_threat_checker/config.py:44`:

```python
max_request_body_bytes: int = Field(default=65_536, ge=1024, le=1_000_000)
```

Default `65_536` bytes; `.env.example` sets the same value
(`backend/.env.example:15`).

---

## 4. Security Headers

The same `request_guard` middleware appends three response headers to every
response.

`backend/src/url_threat_checker/main.py:69-73`:

```python
response = await call_next(request)
response.headers["X-Content-Type-Options"] = "nosniff"
response.headers["X-Frame-Options"] = "DENY"
response.headers["Referrer-Policy"] = "no-referrer"
return response
```

| Header                     | Value          |
|----------------------------|----------------|
| `X-Content-Type-Options`   | `nosniff`      |
| `X-Frame-Options`          | `DENY`         |
| `Referrer-Policy`          | `no-referrer`  |

Headers that the backend does **not** set:

- `Strict-Transport-Security` — absent. A repo-wide grep for
  `Strict-Transport`, `HSTS`, and `hsts` returns no matches in
  `backend/src`, `frontend/src`, `docs`, or `README.md`.
- `Content-Security-Policy` — absent. No matches in `backend/src` or
  `frontend/src`.
- `Permissions-Policy` — absent. No matches.
- `Cross-Origin-Opener-Policy`, `Cross-Origin-Embedder-Policy`,
  `Cross-Origin-Resource-Policy` — absent.

---

## 5. Frontend → Backend Transport

### Same-origin `/backend` rewrite

The frontend issues all API calls against a relative `/backend/...` path. Next
rewrites that to the internal backend URL at the proxy layer.

`frontend/next.config.ts:1-17`:

```ts
import type { NextConfig } from "next";

const backendInternalUrl = process.env.BACKEND_INTERNAL_URL ?? "http://127.0.0.1:8001";

const nextConfig: NextConfig = {
  reactStrictMode: true,
  async rewrites() {
    return [
      {
        source: "/backend/:path*",
        destination: `${backendInternalUrl.replace(/\/$/, "")}/:path*`,
      },
    ];
  },
};

export default nextConfig;
```

`BACKEND_INTERNAL_URL` defaults to `http://127.0.0.1:8001` and stays at that
value for the ngrok demo — the upstream call from Next.js to uvicorn is a
loopback HTTP call, never a TLS call. The browser-facing scheme is whatever
ngrok serves the page over, which is HTTPS-only by tunnel configuration. There
is no scheme rewriting, no `http→https` upgrade, and no TLS check in
`next.config.ts`.

### `apiFetch` and cookie credentials

`frontend/src/lib/api.ts:77`:

```ts
const API_BASE = process.env.NEXT_PUBLIC_API_BASE_URL ?? "/backend";
```

`frontend/src/lib/api.ts:124-140`:

```ts
export async function apiFetch<T>(path: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      ...(options.headers ?? {}),
    },
  });
  ...
}
```

Key points:

- The browser always talks to `${API_BASE}${path}`. With `API_BASE = "/backend"`
  the request is same-origin against the Next.js host, so it inherits the page's
  scheme — `https://` through the ngrok tunnel, `http://` if hitting
  `localhost:3000` directly.
- `credentials: "include"` forwards the `utc_session` cookie on every call.
- If `NEXT_PUBLIC_API_BASE_URL` is set at build time, the frontend instead
  fetches a fully-qualified URL with whatever scheme that env var contains.
  There is no client-side validation that the URL is HTTPS.

`docs/architecture.md:35` documents the rewrite as the way "browser requests
stay same-origin and the HTTP-only cookie works cleanly."

---

## 6. ngrok Deployment Posture

The deployment artifact is `scripts/demo.sh`, which the operator runs from the
repository root. It launches three processes under a single shell process group
and traps `EXIT INT TERM` so closing the terminal kills all three together:

```bash
( cd backend && uv run uvicorn url_threat_checker.main:app --host 127.0.0.1 --port 8001 ) &
( cd frontend && npm run start ) &
ngrok start utc
```

The ngrok side is configured in `~/.config/ngrok/ngrok.yml`:

```yaml
version: "3"
agent:
  authtoken: <token>
tunnels:
  utc:
    proto: http
    addr: 3000
    domain: <reserved-name>.ngrok-free.app
    schemes: [https]
```

Key properties of this topology:

- The ngrok agent is the only process that opens an inbound socket on a public
  interface. uvicorn binds `127.0.0.1:8001` and `next start` binds
  `localhost:3000`; neither is reachable from outside the host.
- `schemes: [https]` forces the public edge to refuse plain HTTP.
- `domain: <reserved-name>.ngrok-free.app` pins the URL across restarts so the
  `BACKEND_CORS_ORIGINS` entry stays valid. The free tier allows one reserved
  hostname per account.
- The Let's Encrypt certificate is provisioned and rotated by ngrok; the repo
  contains no certificate material.
- The first browser to visit the URL sees the ngrok free-tier interstitial
  ("Visit Site" warning page); subsequent XHR / fetch calls bypass it.

The FastAPI `/health` endpoint is defined at
`backend/src/url_threat_checker/main.py:75-77` and is still useful for local
smoke-checking; the ngrok agent does not poll it because it operates as a
transparent tunnel rather than a healthcheck-driven scheduler.

There is no separate hosting for the frontend — it runs from the same laptop
behind the same tunnel via the Next.js `/backend/*` rewrite. Cookies, CORS, and
the origin guard all see one origin: `https://<reserved-name>.ngrok-free.app`.

---

## 7. Current State — Gaps and Non-Features

Items that are not present in the codebase as of this commit:

- **No `Strict-Transport-Security` (HSTS) header.** `main.py` sets three
  response headers (Section 4); HSTS is not one of them. Skipped intentionally
  because `ngrok-free.app` is on the Public Suffix List (HSTS would scope only
  to the single reserved subdomain) and the browser does not revisit between
  one-shot demos.
- **No application-layer `http → https` redirect.** Unnecessary in this
  topology — the ngrok edge refuses plain HTTP (`schemes: [https]`), so no
  plain-HTTP request ever reaches the application. FastAPI does not inspect
  `X-Forwarded-Proto` or `request.url.scheme`.
- **No `Content-Security-Policy` header.** Not set in `main.py` and not
  configured in `next.config.ts`.
- **No `Permissions-Policy` header.**
- **No TLS termination in the application.** uvicorn runs plain HTTP on
  loopback; there are no `--ssl-keyfile` / `--ssl-certfile` arguments and no
  certificate files in the repo.
- **No certificate management code or scripts.** No certbot, no ACME client,
  no certificate paths in `config.py`, no certificate-related env vars in
  `.env.example`. All certificate handling is delegated to ngrok.
- **No mutual TLS / client-certificate auth.** No mTLS configuration anywhere.
- **No scheme enforcement on `BACKEND_CORS_ORIGINS` or
  `NEXT_PUBLIC_API_BASE_URL`.** The values are used verbatim; an `http://`
  entry in either env var is accepted as-is.
- **`secure` cookie flag is environment-gated, not unconditional.** When
  `APP_ENV != "production"`, the `utc_session` and `utc_pending` cookies are
  emitted without the `Secure` attribute (`auth.py:140`, `auth.py:151`,
  `auth.py:189`, `auth.py:217`). The ngrok demo flips this on via
  `APP_ENV=production` in `backend/.env`.
- **No automated test that asserts cookies are `Secure` in production mode.**
  `backend/tests` contains no test referencing the `Secure` cookie attribute.

The existing security documentation does not claim HTTPS as a backend feature
either. `docs/security.md:34-44` lists "HTTP-only session cookie", "Logout
endpoint", "Login rate limiting", "Scan rate limiting", "Origin validation",
"Request body size limit", and "Security headers for API responses" — HSTS,
HTTPS redirect, and in-application TLS termination are not listed because they
are not implemented in the application; HTTPS is provided by ngrok at the edge.

---

## 8. File and Line Citation Table

| Claim                                                                | File                                                         | Line(s)     |
|----------------------------------------------------------------------|--------------------------------------------------------------|-------------|
| uvicorn runs plain HTTP on loopback `127.0.0.1:8001`                 | `scripts/demo.sh`                                            | 17          |
| Frontend prod server `next start` on `localhost:3000`                | `scripts/demo.sh`                                            | 18          |
| Public HTTPS tunnel `ngrok start utc`                                | `scripts/demo.sh`                                            | 19          |
| `app_env` default = `"development"`                                  | `backend/src/url_threat_checker/config.py`                   | 23          |
| `backend_cors_origins` default                                       | `backend/src/url_threat_checker/config.py`                   | 25          |
| `session_cookie_name` default = `"utc_session"`                      | `backend/src/url_threat_checker/config.py`                   | 30          |
| `session_ttl_seconds` default = 28800 (8 h)                          | `backend/src/url_threat_checker/config.py`                   | 31          |
| `max_request_body_bytes` default = 65536                             | `backend/src/url_threat_checker/config.py`                   | 44          |
| `cors_origins` parser (comma-split)                                  | `backend/src/url_threat_checker/config.py`                   | 46-48       |
| `.env.example` `APP_ENV=development`                                 | `backend/.env.example`                                       | 1           |
| `.env.example` `BACKEND_CORS_ORIGINS=http://localhost:3000`          | `backend/.env.example`                                       | 3           |
| `.env.example` `MAX_REQUEST_BODY_BYTES=65536`                        | `backend/.env.example`                                       | 15          |
| CORS middleware registration + `allow_credentials=True`              | `backend/src/url_threat_checker/main.py`                     | 37-43       |
| Body-size guard (413 response path)                                  | `backend/src/url_threat_checker/main.py`                     | 46-57       |
| Origin guard for POST/PUT/PATCH/DELETE                               | `backend/src/url_threat_checker/main.py`                     | 59-67       |
| `_origin_from_header` helper                                         | `backend/src/url_threat_checker/main.py`                     | 14-20       |
| `X-Content-Type-Options: nosniff`                                    | `backend/src/url_threat_checker/main.py`                     | 70          |
| `X-Frame-Options: DENY`                                              | `backend/src/url_threat_checker/main.py`                     | 71          |
| `Referrer-Policy: no-referrer`                                       | `backend/src/url_threat_checker/main.py`                     | 72          |
| `/health` endpoint                                                   | `backend/src/url_threat_checker/main.py`                     | 75-77       |
| Session cookie name `utc_pending`, TTL 300 s                         | `backend/src/url_threat_checker/auth.py`                     | 25-26       |
| `_set_session_cookie` (secure gated on `app_env == "production"`)    | `backend/src/url_threat_checker/auth.py`                     | 133-142     |
| `_clear_session_cookie` (same gating)                                | `backend/src/url_threat_checker/auth.py`                     | 145-152     |
| Pending-2FA cookie set (same gating)                                 | `backend/src/url_threat_checker/auth.py`                     | 183-191     |
| Pending-2FA cookie deletion                                          | `backend/src/url_threat_checker/auth.py`                     | 216-217     |
| Next rewrite `/backend/:path*` → `BACKEND_INTERNAL_URL`              | `frontend/next.config.ts`                                    | 1-17        |
| `API_BASE` falls back to `/backend`                                  | `frontend/src/lib/api.ts`                                    | 77          |
| `apiFetch` uses `credentials: "include"`                             | `frontend/src/lib/api.ts`                                    | 124-140     |
| Architecture doc references the `/backend` same-origin rewrite       | `docs/architecture.md`                                       | 35          |
| Security doc lists protections (no HSTS / HTTPS redirect claim)      | `docs/security.md`                                           | 34-44       |
