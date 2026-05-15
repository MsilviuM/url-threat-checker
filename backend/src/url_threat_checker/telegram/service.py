"""Telegram update orchestration around the shared scanner."""

from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from url_threat_checker.config import Settings, get_settings
from url_threat_checker.database import IntegrationEvent, ScanReport
from url_threat_checker.scanner import ScanSource, ScanValidationError, create_scan
from url_threat_checker.telegram.extraction import extract_urls
from url_threat_checker.telegram.replies import compose_reply, should_send_reply
from url_threat_checker.telegram.schemas import TelegramMessage, TelegramUpdate

PROCESSED_EVENT_STATUSES = {"processed", "ignored", "processed_with_reply_failure"}


@dataclass(frozen=True)
class TelegramProcessResult:
    status: str
    scan_count: int
    chat_id: int | str | None = None
    reply_to_message_id: int | None = None
    reply_text: str | None = None
    duplicate: bool = False


class TelegramIngestionService:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()

    def process_update(self, db: Session, update: TelegramUpdate) -> TelegramProcessResult:
        event, duplicate = self._ensure_event(db, update)
        if duplicate and event.status in PROCESSED_EVENT_STATUSES:
            return TelegramProcessResult(
                status=event.status,
                scan_count=event.scan_count,
                duplicate=True,
            )

        message = update.active_message()
        if message is None:
            self._finish_event(db, event, status_value="ignored", scan_count=0)
            return TelegramProcessResult(status="ignored", scan_count=0)

        extracted_urls = extract_urls(message)
        chat_type = message.chat.type
        reply_to_message_id = message.message_id
        chat_id = message.chat.id

        if not extracted_urls:
            reply_text = compose_reply(
                reports=[],
                invalid_urls=[],
                frontend_base_url=self.settings.telegram_frontend_base_url,
                no_urls=True,
            )
            self._finish_event(
                db,
                event,
                status_value="ignored",
                scan_count=0,
                chat_id=chat_id,
                message_id=reply_to_message_id,
            )
            if should_send_reply(
                chat_type=chat_type,
                reports=[],
                no_urls=True,
                reply_mode=self.settings.telegram_reply_mode,
            ):
                return TelegramProcessResult(
                    status="ignored",
                    scan_count=0,
                    chat_id=chat_id,
                    reply_to_message_id=reply_to_message_id,
                    reply_text=reply_text,
                )
            return TelegramProcessResult(status="ignored", scan_count=0)

        reports: list[ScanReport] = []
        invalid_urls: list[str] = []
        source = self._scan_source(message)
        for extracted in extracted_urls[: self.settings.telegram_max_urls_per_message]:
            try:
                reports.append(
                    create_scan(
                        db=db,
                        url=extracted.raw_url,
                        include_virustotal=self.settings.telegram_include_virustotal,
                        source=source,
                    )
                )
            except ScanValidationError:
                invalid_urls.append(extracted.raw_url)

        status_value = "processed" if reports or invalid_urls else "ignored"
        self._finish_event(
            db,
            event,
            status_value=status_value,
            scan_count=len(reports),
            chat_id=chat_id,
            message_id=reply_to_message_id,
        )

        if not should_send_reply(
            chat_type=chat_type,
            reports=reports,
            no_urls=False,
            reply_mode=self.settings.telegram_reply_mode,
        ):
            return TelegramProcessResult(status=status_value, scan_count=len(reports))

        reply_text = compose_reply(
            reports=reports,
            invalid_urls=invalid_urls,
            frontend_base_url=self.settings.telegram_frontend_base_url,
        )
        return TelegramProcessResult(
            status=status_value,
            scan_count=len(reports),
            chat_id=chat_id,
            reply_to_message_id=reply_to_message_id,
            reply_text=reply_text,
        )

    def mark_reply_failure(self, db: Session, update_id: int, message: str | None) -> None:
        event = self._find_event(db, update_id)
        if event is None:
            return
        event.status = "processed_with_reply_failure"
        event.error_message = (message or "Telegram reply failed.")[:1000]
        event.processed_at = datetime.now(UTC)
        db.commit()

    def _ensure_event(
        self,
        db: Session,
        update: TelegramUpdate,
    ) -> tuple[IntegrationEvent, bool]:
        existing = self._find_event(db, update.update_id)
        if existing is not None:
            return existing, True

        event = IntegrationEvent(
            platform="telegram",
            external_event_id=str(update.update_id),
            status="received",
        )
        db.add(event)
        try:
            db.flush()
        except IntegrityError:
            db.rollback()
            existing = self._find_event(db, update.update_id)
            if existing is not None:
                return existing, True
            raise
        return event, False

    def _find_event(self, db: Session, update_id: int) -> IntegrationEvent | None:
        return db.scalar(
            select(IntegrationEvent).where(
                IntegrationEvent.platform == "telegram",
                IntegrationEvent.external_event_id == str(update_id),
            )
        )

    def _finish_event(
        self,
        db: Session,
        event: IntegrationEvent,
        *,
        status_value: str,
        scan_count: int,
        chat_id: int | str | None = None,
        message_id: int | None = None,
    ) -> None:
        event.status = status_value
        event.scan_count = scan_count
        event.external_chat_id = str(chat_id) if chat_id is not None else event.external_chat_id
        event.external_message_id = (
            str(message_id) if message_id is not None else event.external_message_id
        )
        event.processed_at = datetime.now(UTC)
        db.commit()

    def _scan_source(self, message: TelegramMessage) -> ScanSource:
        return ScanSource(
            source_type="automation",
            source_platform="telegram",
            source_sender=self._source_sender(message),
            source_message_preview=self._message_preview(message),
        )

    def _source_sender(self, message: TelegramMessage) -> str:
        user = message.from_user
        if user and user.username:
            sender = f"@{user.username}"
        elif user:
            sender = f"telegram_user:{user.id}"
        elif message.chat.username:
            sender = f"@{message.chat.username}"
        else:
            sender = f"telegram_chat:{message.chat.id}"
        return f"{sender} in {message.chat.type}:{message.chat.id}"

    def _message_preview(self, message: TelegramMessage) -> str | None:
        value = (message.text or message.caption or "").strip()
        if not value:
            return None
        preview = value.replace("\n", " ")
        if len(preview) > self.settings.telegram_message_preview_chars:
            return preview[: self.settings.telegram_message_preview_chars - 3] + "..."
        return preview
