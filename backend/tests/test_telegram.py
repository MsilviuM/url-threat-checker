from sqlalchemy.orm import Session

from test_api import api_client_context, login
from url_threat_checker.config import DEFAULT_ADMIN_PASSWORD_HASH, Settings
from url_threat_checker.database import IntegrationEvent, ScanReport
from url_threat_checker.telegram.client import TelegramApiResult, TelegramClient
from url_threat_checker.telegram.extraction import extract_urls, normalize_extracted_url
from url_threat_checker.telegram.schemas import TelegramMessage


def telegram_settings(**overrides) -> Settings:
    defaults = {
        "_env_file": None,
        "virustotal_api_key": None,
        "admin_password_hash": DEFAULT_ADMIN_PASSWORD_HASH,
        "totp_secret": None,
        "telegram_bot_token": "test-token",
        "telegram_webhook_secret": "telegram-secret",
        "telegram_webhook_path_token": "telegram-path",
        "telegram_include_virustotal": False,
        "telegram_frontend_base_url": "http://frontend.test",
    }
    defaults.update(overrides)
    return Settings(**defaults)


def telegram_headers(secret: str = "telegram-secret") -> dict[str, str]:
    return {"X-Telegram-Bot-Api-Secret-Token": secret}


def telegram_update(
    *,
    update_id: int,
    text: str,
    chat_type: str = "private",
    chat_id: int = 12345,
) -> dict:
    return {
        "update_id": update_id,
        "message": {
            "message_id": 77,
            "date": 1,
            "chat": {"id": chat_id, "type": chat_type},
            "from": {
                "id": 999,
                "is_bot": False,
                "first_name": "Alice",
                "username": "alice",
            },
            "text": text,
        },
    }


def install_telegram_send_spy(monkeypatch) -> list[dict]:
    sent_messages: list[dict] = []

    def fake_send_message(
        self: TelegramClient,
        chat_id: int | str,
        text: str,
        reply_to_message_id: int | None = None,
        disable_web_page_preview: bool = True,
    ) -> TelegramApiResult:
        sent_messages.append(
            {
                "chat_id": chat_id,
                "text": text,
                "reply_to_message_id": reply_to_message_id,
                "disable_web_page_preview": disable_web_page_preview,
            }
        )
        return TelegramApiResult(ok=True, status_code=200, data={"ok": True})

    monkeypatch.setattr(TelegramClient, "send_message", fake_send_message)
    return sent_messages


def first_report(db: Session) -> ScanReport:
    reports = db.query(ScanReport).all()
    assert len(reports) == 1
    return reports[0]


def test_extract_urls_handles_telegram_utf16_entity_offsets() -> None:
    url = "https://example.com/login"
    text = f"🔒 {url}"
    message = TelegramMessage.model_validate(
        {
            "message_id": 1,
            "chat": {"id": 1, "type": "private"},
            "text": text,
            "entities": [
                {
                    "type": "url",
                    "offset": len("🔒 ".encode("utf-16-le")) // 2,
                    "length": len(url.encode("utf-16-le")) // 2,
                }
            ],
        }
    )

    assert [item.raw_url for item in extract_urls(message)] == [url]


def test_extract_urls_handles_text_links_captions_dedupe_and_defanged_urls() -> None:
    message = TelegramMessage.model_validate(
        {
            "message_id": 1,
            "chat": {"id": 1, "type": "private"},
            "text": "click here and also hxxps://example[.]com/login",
            "caption": "mirror https://caption.example/path",
            "entities": [
                {
                    "type": "text_link",
                    "offset": 0,
                    "length": 10,
                    "url": "https://hidden.example/login",
                }
            ],
            "caption_entities": [
                {"type": "url", "offset": 7, "length": len("https://caption.example/path")}
            ],
        }
    )

    assert [item.raw_url for item in extract_urls(message)] == [
        "https://hidden.example/login",
        "https://caption.example/path",
        "https://example.com/login",
    ]
    assert normalize_extracted_url("hxxp://example[.]com/path.") == "http://example.com/path"


def test_telegram_webhook_rejects_invalid_secret() -> None:
    with api_client_context(telegram_settings()) as (client, session_factory):
        response = client.post(
            "/api/v1/integrations/telegram/webhook/telegram-path",
            headers=telegram_headers("wrong-secret"),
            json=telegram_update(update_id=1, text="https://example.com"),
        )
        with session_factory() as db:
            events = db.query(IntegrationEvent).all()

    assert response.status_code == 403
    assert events == []


def test_telegram_private_message_creates_source_scan_and_reply(monkeypatch) -> None:
    sent_messages = install_telegram_send_spy(monkeypatch)

    with api_client_context(telegram_settings()) as (client, session_factory):
        response = client.post(
            "/api/v1/integrations/telegram/webhook/telegram-path",
            headers=telegram_headers(),
            json=telegram_update(
                update_id=10,
                text="Could you check https://www.google.com/search?q=university+project",
            ),
        )
        login(client)
        source_filter = client.get("/api/v1/scans?source=telegram")
        with session_factory() as db:
            report = first_report(db)
            event = db.query(IntegrationEvent).one()

    assert response.status_code == 200
    assert response.json()["scan_count"] == 1
    assert report.source_type == "automation"
    assert report.source_platform == "telegram"
    assert report.source_sender == "@alice in private:12345"
    assert "Could you check" in (report.source_message_preview or "")
    assert event.status == "processed"
    assert source_filter.status_code == 200
    assert len(source_filter.json()) == 1
    assert sent_messages and "Safe - risk" in sent_messages[0]["text"]


def test_telegram_duplicate_update_does_not_duplicate_scan_or_reply(monkeypatch) -> None:
    sent_messages = install_telegram_send_spy(monkeypatch)
    payload = telegram_update(update_id=11, text="https://www.google.com/search?q=university")

    with api_client_context(telegram_settings()) as (client, session_factory):
        first = client.post(
            "/api/v1/integrations/telegram/webhook/telegram-path",
            headers=telegram_headers(),
            json=payload,
        )
        second = client.post(
            "/api/v1/integrations/telegram/webhook/telegram-path",
            headers=telegram_headers(),
            json=payload,
        )
        with session_factory() as db:
            scan_count = db.query(ScanReport).count()
            event_count = db.query(IntegrationEvent).count()

    assert first.status_code == 200
    assert second.status_code == 200
    assert second.json()["duplicate"] is True
    assert scan_count == 1
    assert event_count == 1
    assert len(sent_messages) == 1


def test_telegram_group_safe_link_is_stored_silently(monkeypatch) -> None:
    sent_messages = install_telegram_send_spy(monkeypatch)

    with api_client_context(telegram_settings()) as (client, session_factory):
        response = client.post(
            "/api/v1/integrations/telegram/webhook/telegram-path",
            headers=telegram_headers(),
            json=telegram_update(
                update_id=12,
                chat_type="group",
                text="https://www.google.com/search?q=university",
            ),
        )
        with session_factory() as db:
            report = first_report(db)

    assert response.status_code == 200
    assert report.source_platform == "telegram"
    assert report.final_verdict == "safe"
    assert sent_messages == []


def test_telegram_group_risky_link_replies(monkeypatch) -> None:
    sent_messages = install_telegram_send_spy(monkeypatch)

    with api_client_context(telegram_settings()) as (client, session_factory):
        response = client.post(
            "/api/v1/integrations/telegram/webhook/telegram-path",
            headers=telegram_headers(),
            json=telegram_update(
                update_id=13,
                chat_type="group",
                text="https://google.com.fake-domain.ru/login",
            ),
        )
        with session_factory() as db:
            report = first_report(db)

    assert response.status_code == 200
    assert report.final_verdict == "dangerous"
    assert sent_messages and "Dangerous - risk" in sent_messages[0]["text"]


def test_telegram_private_message_without_urls_replies_but_stores_no_scan(monkeypatch) -> None:
    sent_messages = install_telegram_send_spy(monkeypatch)

    with api_client_context(telegram_settings()) as (client, session_factory):
        response = client.post(
            "/api/v1/integrations/telegram/webhook/telegram-path",
            headers=telegram_headers(),
            json=telegram_update(update_id=14, text="hello bot"),
        )
        with session_factory() as db:
            scan_count = db.query(ScanReport).count()
            event = db.query(IntegrationEvent).one()

    assert response.status_code == 200
    assert scan_count == 0
    assert event.status == "ignored"
    assert sent_messages and sent_messages[0]["text"].startswith("No link found")
