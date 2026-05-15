# Telegram Integration Architecture

This document defines the Telegram-only integration for URL Threat Checker.
The goal is to make Telegram feel like a natural input surface for the existing
scanner, not a separate bot product with duplicated verdict logic.

## Goal

Let users send Telegram messages that contain URLs and receive a fast, useful
security response:

```text
Telegram message
  -> verified webhook
  -> URL extraction
  -> shared scan creation flow
  -> stored scan reports
  -> Telegram reply with verdict summary
  -> dashboard/report UI uses the same reports as manual scans
```

The integration should be:

- DRY: Telegram must call the same scanner and verdict code used by the manual UI.
- Seamless: users should paste or forward a message and get a concise reply.
- Safe: the app should never open submitted URLs directly.
- Explainable: every Telegram result should link back to the existing report detail page.
- Demo-friendly: local development can use a tunnel or a polling fallback, but the production shape is webhook-first.

## Current Repo Fit

The existing app already has most of the core product:

```text
manual scan form
  -> POST /api/v1/scans
  -> scanner.create_scan()
  -> feature extraction
  -> local model prediction
  -> heuristic verdict
  -> optional VirusTotal enrichment
  -> scan_reports row
  -> dashboard and report pages
```

The database already includes source metadata on `scan_reports`:

```text
source_type
source_platform
source_sender
source_message_preview
```

The Telegram integration should activate those fields instead of creating a
parallel `telegram_reports` table.

## Official Telegram Constraints

The architecture is based on these Bot API rules:

- Bot API calls go to `https://api.telegram.org/bot<token>/<METHOD_NAME>`.
- Updates are received either through `getUpdates` long polling or through webhooks; these modes are mutually exclusive.
- `setWebhook` registers an HTTPS URL that receives JSON-serialized `Update` objects.
- Failed webhook deliveries are retried by Telegram.
- `update_id` is the stable sequential identifier that can be used to ignore duplicate updates.
- `setWebhook` supports `secret_token`; Telegram sends it back as `X-Telegram-Bot-Api-Secret-Token`.
- `allowed_updates` should be restricted to the update types this app handles.
- `MessageEntity` can identify `url` entities and `text_link` clickable URLs.
- `sendMessage` is the simple response method for text replies.

Reference: <https://core.telegram.org/bots/api>

## Architecture Overview

```text
Telegram
  -> POST /api/v1/integrations/telegram/webhook
    -> TelegramWebhookGuard
    -> TelegramUpdateParser
    -> UrlExtractionService
    -> TelegramIngestionService
      -> ScanSource metadata
      -> scanner.create_scan()
      -> scan_reports
    -> TelegramReplyComposer
    -> TelegramClient.send_message()
```

The core boundary is:

```text
Telegram-specific code ends before feature extraction starts.
```

Telegram code should only:

- verify the webhook request;
- parse Telegram update/message shape;
- extract URL candidates;
- attach source metadata;
- decide whether and how to reply in Telegram.

Telegram code must not:

- recalculate risk;
- duplicate heuristic rules;
- call the ML model directly;
- call VirusTotal directly;
- write report rows manually;
- store Telegram bot secrets in code or `.env` changes committed to git.

## Proposed Backend Modules

Add these modules under `backend/src/url_threat_checker/`.

```text
telegram/
  __init__.py
  client.py
  extraction.py
  router.py
  schemas.py
  service.py
  replies.py
  security.py
```

### `telegram/router.py`

Owns FastAPI routes only.

```text
POST /api/v1/integrations/telegram/webhook
GET  /api/v1/integrations/telegram/status
POST /api/v1/integrations/telegram/register-webhook
POST /api/v1/integrations/telegram/delete-webhook
```

Recommended route behavior:

- `webhook` is unauthenticated but protected by Telegram's secret token header.
- `status`, `register-webhook`, and `delete-webhook` require the existing admin session.
- `webhook` returns quickly with a JSON acknowledgement.
- `webhook` does not expose stack traces, token values, chat IDs, or full message text.

For the first implementation, `register-webhook` and `delete-webhook` can be
CLI scripts instead of API endpoints. That is simpler for a university demo and
keeps admin-only setup operations out of the browser.

### `telegram/security.py`

Owns request validation.

Responsibilities:

- compare `X-Telegram-Bot-Api-Secret-Token` to `settings.telegram_webhook_secret`;
- reject missing or mismatched secrets with `403`;
- enforce request body size through the existing global request guard;
- optionally verify the route contains a random path segment as a second layer.

Recommended final webhook path:

```text
/api/v1/integrations/telegram/webhook/{telegram_webhook_path_token}
```

The header token is still required. The path token only reduces accidental
noise and scanner traffic.

### `telegram/schemas.py`

Owns typed Pydantic models for the subset of Telegram updates we need.

Do not model the entire Bot API. Keep it narrow:

```text
TelegramUpdate
TelegramMessage
TelegramChat
TelegramUser
TelegramMessageEntity
```

Support these update fields first:

```text
message
edited_message
channel_post
edited_channel_post
```

Support these message fields first:

```text
message_id
date
text
caption
entities
caption_entities
chat
from
```

Ignore all unsupported update types without error.

### `telegram/extraction.py`

Owns Telegram-aware URL extraction.

Extraction order:

1. Read `entities` from `text`.
2. Read `caption_entities` from `caption`.
3. Extract `url` entity text by UTF-16 offsets.
4. Extract `text_link` entity `url`.
5. Run a conservative fallback text extractor for plain URLs missed by entities.
6. Normalize duplicates before scanning.

The tricky part is Telegram offsets: entity offsets are UTF-16 code units, not
Python string indexes. This needs tests with emoji before a URL.

Return value:

```python
@dataclass(frozen=True)
class ExtractedTelegramUrl:
    raw_url: str
    source_field: Literal["text", "caption", "text_link", "fallback"]
    entity_type: str | None
```

The extractor should not decide safety. It only returns candidate URLs.

### `telegram/service.py`

Owns orchestration.

Recommended public method:

```python
class TelegramIngestionService:
    def process_update(self, db: Session, update: TelegramUpdate) -> TelegramProcessResult:
        ...
```

Responsibilities:

- ignore unsupported updates;
- enforce idempotency by `update_id`;
- extract sender/chat/message metadata;
- call the shared scanner once per unique URL;
- compose source metadata;
- return a result object for reply composition.

It should not know how to send HTTP requests to Telegram. That belongs in
`telegram/client.py`.

### `telegram/client.py`

Owns outgoing Telegram API calls.

Minimal methods:

```python
class TelegramClient:
    def send_message(
        self,
        chat_id: int | str,
        text: str,
        reply_to_message_id: int | None = None,
        disable_web_page_preview: bool = True,
    ) -> TelegramApiResult:
        ...

    def set_webhook(self, public_url: str, allowed_updates: list[str]) -> TelegramApiResult:
        ...

    def delete_webhook(self, drop_pending_updates: bool = False) -> TelegramApiResult:
        ...

    def get_webhook_info(self) -> TelegramApiResult:
        ...
```

Keep this client thin. It should wrap `httpx`, build Bot API URLs, and convert
HTTP/API failures into typed results. It should not know about local scan rules.

### `telegram/replies.py`

Owns Telegram reply copy and formatting.

Reply styles:

```text
No URLs:
No link found. Send or forward a message containing a URL.

One safe URL:
Safe - risk 8/100
No obvious risk was detected, but only open links from sources you trust.
Report: http://localhost:3000/reports/<id>

One suspicious URL:
Suspicious - risk 48/100
Be careful. Verify the sender before opening this link.
Report: ...

One dangerous URL:
Dangerous - risk 86/100
Do not open this link.
Signals: phishing-like model, risky extension, VirusTotal malicious detections.
Report: ...

Multiple URLs:
Checked 3 links:
1. Dangerous - example[.]bad - risk 86/100
2. Suspicious - short[.]link - risk 45/100
3. Safe - github[.]com - risk 5/100
Open dashboard for details: ...
```

Avoid Markdown link formatting for the submitted URL itself. Use defanged URL
text from the scan report. That preserves the existing safety posture.

## Shared Scanner Contract

The current `create_scan(db, url, include_virustotal)` should become source-aware
without becoming Telegram-aware.

Recommended shape:

```python
@dataclass(frozen=True)
class ScanSource:
    source_type: Literal["manual", "automation"]
    source_platform: str | None = None
    source_sender: str | None = None
    source_message_preview: str | None = None


def create_scan(
    db: Session,
    url: str,
    include_virustotal: bool,
    source: ScanSource | None = None,
) -> ScanReport:
    ...
```

Defaults:

```text
source_type = "manual"
source_platform = None
source_sender = None
source_message_preview = None
```

Telegram calls it like:

```python
source = ScanSource(
    source_type="automation",
    source_platform="telegram",
    source_sender="@alice in private:123456789",
    source_message_preview="Can you check this link? https://...",
)

report = create_scan(
    db=db,
    url=extracted_url.raw_url,
    include_virustotal=settings.telegram_include_virustotal,
    source=source,
)
```

This keeps the manual UI unchanged while giving the dashboard richer context.

## Idempotency

Telegram retries failed webhook deliveries, so duplicate handling is mandatory.

Recommended first step:

- add a new `integration_events` table.

```text
integration_events
  id
  platform               # "telegram"
  external_event_id       # update_id as string
  external_chat_id
  external_message_id
  status                  # received | processed | ignored | failed
  scan_count
  error_message
  created_at
  processed_at
```

Unique index:

```text
platform + external_event_id
```

Processing rule:

```text
if event already exists with processed/ignored:
  return 200 without sending another reply

if event exists with failed:
  retry only if retry policy says it is safe

if event is new:
  insert received
  process URLs
  mark processed/ignored/failed
```

Because adding a table is a migration/schema change, confirm before
implementation. If we need a no-migration MVP, store `telegram_update_id` inside
`SiteSettings` as a temporary last-seen value, but that is less correct because
it does not handle out-of-order retries as well.

## Database Changes

Recommended minimal schema changes:

```text
1. Add integration_events table for dedupe and observability.
2. Optionally add source_external_id to scan_reports.
```

The existing `scan_reports` source fields are enough for v1 display.

Optional future fields:

```text
source_chat_id
source_message_id
source_update_id
source_thread_id
source_raw_kind
```

Do not store full Telegram update JSON by default. It can contain personal
message content. Store only metadata and a short preview.

## Settings

Add settings only. Do not commit `.env` values.

```python
telegram_bot_token: str | None = None
telegram_webhook_secret: str | None = None
telegram_webhook_path_token: str | None = None
telegram_public_base_url: str | None = None
telegram_include_virustotal: bool = True
telegram_reply_mode: str = "risky_and_private"
telegram_max_urls_per_message: int = 5
telegram_message_preview_chars: int = 240
```

Reply modes:

```text
always
  Reply for every message that contains a URL.

risky_only
  Reply only when at least one URL is suspicious or dangerous.

risky_and_private
  In private chats, always reply. In groups/channels, reply only when risky.

silent
  Store reports but never reply.
```

Recommended default:

```text
telegram_reply_mode = "risky_and_private"
```

This avoids noisy group behavior while keeping the one-to-one bot experience
clear during demos.

## Webhook Registration

Recommended setup command:

```bash
uv run python -m url_threat_checker.telegram.manage set-webhook \
  --public-base-url https://example.ngrok-free.app \
  --drop-pending-updates
```

It should call:

```text
POST https://api.telegram.org/bot<TOKEN>/setWebhook
```

Parameters:

```json
{
  "url": "https://example.ngrok-free.app/api/v1/integrations/telegram/webhook/<path-token>",
  "secret_token": "<telegram_webhook_secret>",
  "allowed_updates": ["message", "edited_message", "channel_post", "edited_channel_post"],
  "drop_pending_updates": true
}
```

For local demos:

```text
FastAPI localhost:8001
  <- tunnel service exposes HTTPS URL
Telegram setWebhook points to tunnel URL
```

`getUpdates` can exist as a development-only polling command, but the documented
architecture should remain webhook-first.

## Webhook Request Flow

```text
1. Telegram sends POST /api/v1/integrations/telegram/webhook/<path-token>.
2. Router verifies path token and secret header.
3. Router parses payload into TelegramUpdate.
4. Service checks integration_events for update_id.
5. Unsupported update type -> mark ignored -> return 200.
6. Extract URLs from text/caption/entities.
7. No URLs -> optionally reply in private chats -> mark ignored/processed.
8. For each unique URL up to telegram_max_urls_per_message:
   - call scanner.create_scan(..., source=telegram source)
   - reuse existing ML, heuristic, VirusTotal, storage, explanation flow
9. Compose reply from stored ScanReport summaries.
10. Send reply through TelegramClient.
11. Mark integration event processed.
12. Return 200.
```

Failure policy:

```text
Invalid secret:
  return 403. Do not store event.

Malformed JSON:
  return 400. Do not store event.

Unsupported update:
  return 200. Store ignored event if update_id exists.

Scanner validation error for one URL:
  include that URL as invalid in the reply and continue scanning other URLs.

Telegram sendMessage failure:
  scan reports are still valid. Mark event processed_with_reply_failure or failed_reply.

Unexpected exception:
  return 500 only if the event was not safely persisted. Otherwise record failed state and return 200 to avoid retry loops.
```

## URL Extraction Details

Telegram messages can contain URLs in several forms:

```text
plain text:        https://example.com
entity url:        Telegram marks the URL range in text
text_link entity:  clickable text where the real URL is in entity.url
caption:           photo/document caption with entities
forwarded text:    same shape as normal message text/caption
defanged text:     hxxps://example[.]com
```

Extraction should produce raw candidates and let the existing feature extractor
perform URL parsing and normalization.

Recommended tests:

```text
extracts plain URL entity
extracts text_link URL from entity.url
extracts caption URL
dedupes same URL from entity + fallback
handles emoji before URL because Telegram offsets are UTF-16
handles no URLs
handles multiple URLs
handles hxxp/hxxps and [.] defanged URLs if we choose to support them
```

Defanged URL support can be added in the extraction service:

```text
hxxp://example[.]com -> http://example.com
hxxps://example[.]com/path -> https://example.com/path
example[.]com/login -> example.com/login
```

Keep that normalization isolated so the scanner continues to receive normal
URLs.

## Reply Design

Replies should be short and operational.

Private chat behavior:

```text
Always reply when a URL is found.
Reply with "No link found" when no URL exists.
```

Group/supergroup behavior:

```text
Reply only for suspicious or dangerous URLs by default.
Do not reply to every safe link.
Use reply_to_message_id so the alert is anchored to the original message.
```

Channel behavior:

```text
Store reports.
Reply only if the bot has permission and reply mode allows it.
Silent storage is acceptable for channels.
```

Example single result:

```text
Dangerous - risk 86/100
Do not open this link.
Signals: phishing-like model, risky file extension.
Report: https://app.example.com/reports/<id>
```

Example multiple result:

```text
Checked 3 links
1. Dangerous - example[.]bad - risk 86/100
2. Suspicious - bit[.]ly - risk 42/100
3. Safe - github[.]com - risk 5/100

Reports saved in dashboard.
```

## Dashboard Changes

Add source visibility without redesigning the app.

Reports list:

- add `Source` column;
- add source filter: All / Manual / Telegram;
- show Telegram sender/chat preview where available.

Report detail:

- add `Source` panel:

```text
Platform: Telegram
Sender: @alice
Chat: private
Message preview: Can you check this link?
```

Dashboard:

- add counts by source;
- add "Telegram risky links today";
- add "Top risky Telegram chats/senders" only if useful and privacy acceptable.

## Security And Privacy

Required:

- never commit bot tokens or webhook secrets;
- never log bot token values;
- verify Telegram secret header on every webhook request;
- store only short message previews;
- defang URLs in all user-facing report/reply output;
- keep the backend rule: do not crawl/open submitted URLs;
- cap number of URLs per message;
- cap reply length;
- rate-limit admin setup endpoints if exposed;
- keep Bot API token calls in `TelegramClient`.

Privacy default:

```text
source_sender = "@username" if available, otherwise "telegram_user:<id>"
source_message_preview = first 240 chars, with URLs optionally defanged
full message body = not stored
raw Telegram update = not stored
```

## Testing Plan

Backend unit tests:

```text
telegram extraction from entities
telegram extraction from text_link
telegram extraction from caption
UTF-16 offset handling
dedupe by URL
webhook rejects invalid secret
webhook ignores unsupported updates
service calls create_scan once per URL
service stores source metadata
duplicate update_id does not create duplicate scans or duplicate replies
reply composer handles safe/suspicious/dangerous/multiple/no-url
TelegramClient handles API ok=false
```

Backend integration tests:

```text
POST Telegram update with one URL -> creates scan report with source_platform=telegram
POST same update twice -> one scan only
POST group message with safe URL -> scan stored, no reply when mode=risky_and_private
POST group message with dangerous URL -> scan stored and reply sent
```

Frontend checks:

```text
reports page shows Telegram source
source filter works
report detail shows source panel
manual scans remain unchanged
```

Verification commands:

```bash
cd backend
uv run ruff check
uv run pytest

cd ../frontend
pnpm lint
pnpm build
```

## Implementation Phases

### Phase 1: DRY Scanner Source Support

- Add `ScanSource`.
- Update `create_scan()` to accept optional source metadata.
- Keep manual endpoint behavior unchanged.
- Add tests proving manual scans still use `source_type="manual"`.

### Phase 2: Telegram Extraction And Reply Logic

- Add Telegram Pydantic schemas.
- Add URL extraction service.
- Add reply composer.
- Unit test the tricky parsing cases before adding webhook side effects.

### Phase 3: Webhook Ingestion

- Add Telegram router.
- Add secret header guard.
- Add integration event idempotency table.
- Add `TelegramIngestionService`.
- Wire scanner source metadata.
- Stub/mock `TelegramClient` in tests.

### Phase 4: Setup Command

- Add `telegram-webhook` management command or script.
- Support:

```text
set
delete
info
```

- Print safe status only. Never print the bot token.

### Phase 5: Dashboard Source UI

- Extend API response schemas with source fields.
- Add Reports source filter and source column.
- Add Report Detail source panel.

### Phase 6: Local Demo Polish

- Document tunnel setup.
- Provide a deterministic mock update fixture.
- Add a demo script:

```text
1. Send safe URL to bot.
2. Send fake trusted-domain phishing URL to bot.
3. Show Telegram reply.
4. Open dashboard report.
```

## Recommended Initial Scope

Build this first:

```text
Telegram private chat + group messages
text and caption URL extraction
webhook secret validation
source-aware create_scan()
idempotency by update_id
Telegram reply for private chats always
Telegram reply for groups only when risky
dashboard source display
```

Defer:

```text
inline mode
business messages
guest messages
QR-code image scanning
admin setup UI
multi-bot support
raw update archive
per-chat allow/block lists
```

This gives the project a clean, explainable, and technically serious Telegram
automation without overbuilding.

## Open Decisions Before Coding

1. Are database schema changes approved for `integration_events`?
2. Should local demo use an HTTPS tunnel webhook or a development polling command?
3. Should group chats store safe links silently, or ignore safe links entirely?
4. Should VirusTotal be enabled by default for Telegram scans?
5. Should the bot reply with report links using `localhost` for local demos, or a configurable public frontend URL?

Recommended answers:

```text
1. Yes, use integration_events.
2. Use HTTPS tunnel for the real demo; keep polling only as developer fallback.
3. Store safe links silently in groups.
4. Yes, use VirusTotal when configured.
5. Use configurable public frontend URL, fallback to localhost.
```
