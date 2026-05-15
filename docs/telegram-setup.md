# Telegram Setup

This guide explains how to run the Telegram integration after the backend and
frontend are already working locally.

## What The Bot Does

```text
Telegram message with URL
  -> webhook verifies Telegram secret
  -> URL is extracted from message text/caption/entities
  -> existing scanner creates normal scan reports
  -> bot replies with a concise verdict summary
  -> dashboard shows the same reports with Source = Telegram
```

The Telegram integration reuses the normal scanner. It does not open submitted
URLs and it does not duplicate ML, heuristic, or VirusTotal logic.

## Required Environment Variables

Set these in the backend runtime environment. Do not commit real values.

```bash
TELEGRAM_BOT_TOKEN="123456:bot-token-from-botfather"
TELEGRAM_WEBHOOK_SECRET="long-random-secret-header"
TELEGRAM_WEBHOOK_PATH_TOKEN="long-random-path-token"
TELEGRAM_PUBLIC_BASE_URL="https://your-public-tunnel.example"
TELEGRAM_FRONTEND_BASE_URL="http://localhost:3000"
```

Optional defaults:

```bash
TELEGRAM_INCLUDE_VIRUSTOTAL=true
TELEGRAM_REPLY_MODE="risky_and_private"
TELEGRAM_MAX_URLS_PER_MESSAGE=5
TELEGRAM_MESSAGE_PREVIEW_CHARS=240
```

Reply mode behavior:

```text
always              reply for every message with a URL
risky_only          reply only when a URL is suspicious or dangerous
risky_and_private   private chats always reply; groups reply only when risky
silent              store reports without replying
```

## Local Webhook Demo

Telegram requires a public HTTPS webhook URL. For local demos, expose the
backend with a tunnel:

```text
Telegram
  -> HTTPS tunnel
  -> local FastAPI backend on 127.0.0.1:8001
```

Start the backend:

```bash
cd backend
uv run uvicorn url_threat_checker.main:app --host 127.0.0.1 --port 8001 --reload
```

Start the frontend:

```bash
cd frontend
BACKEND_INTERNAL_URL=http://127.0.0.1:8001 pnpm dev
```

Register the webhook:

```bash
cd backend
uv run telegram-webhook set \
  --public-base-url "$TELEGRAM_PUBLIC_BASE_URL" \
  --drop-pending-updates
```

Check webhook info:

```bash
uv run telegram-webhook info
```

Delete the webhook:

```bash
uv run telegram-webhook delete --drop-pending-updates
```

## Demo Script

1. Open the frontend dashboard and log in.
2. Send a safe URL to the bot in a private chat:

```text
https://www.google.com/search?q=university+project
```

3. Confirm the bot replies with a safe verdict.
4. Send a risky URL:

```text
https://google.com.fake-domain.ru/login
```

5. Confirm the bot replies with a dangerous verdict.
6. Open `Reports`, filter Source to `Telegram`, and open the created report.

## Verification

Run the full project checks after changing the integration:

```bash
cd backend
uv run ruff check
uv run pytest

cd ../frontend
pnpm lint
pnpm build
```

## Privacy Notes

- Full Telegram updates are not stored.
- Full message bodies are not stored.
- Reports store only a short message preview and sender/chat label.
- URLs are shown defanged in user-facing report/reply output.
- Bot tokens and webhook secrets must stay in environment variables only.
