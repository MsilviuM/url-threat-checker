"""FastAPI routes for Telegram webhook ingestion."""

from typing import Annotated

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from url_threat_checker.auth import current_admin
from url_threat_checker.config import Settings, get_settings
from url_threat_checker.database import get_db
from url_threat_checker.telegram.client import TelegramClient
from url_threat_checker.telegram.schemas import TelegramUpdate
from url_threat_checker.telegram.security import verify_telegram_webhook
from url_threat_checker.telegram.service import TelegramIngestionService

router = APIRouter(prefix="/api/v1/integrations/telegram", tags=["telegram"])


@router.post("/webhook/{path_token}")
def telegram_webhook(
    path_token: str,
    payload: TelegramUpdate,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, bool | int | str]:
    verify_telegram_webhook(request, path_token, settings)
    service = TelegramIngestionService(settings)
    result = service.process_update(db, payload)

    if result.reply_text and result.chat_id is not None:
        api_result = TelegramClient(settings).send_message(
            chat_id=result.chat_id,
            text=result.reply_text,
            reply_to_message_id=result.reply_to_message_id,
        )
        if not api_result.ok:
            service.mark_reply_failure(db, payload.update_id, api_result.description)

    return {
        "ok": True,
        "status": result.status,
        "scan_count": result.scan_count,
        "duplicate": result.duplicate,
    }


@router.get("/status", dependencies=[Depends(current_admin)])
def telegram_status(settings: Annotated[Settings, Depends(get_settings)]) -> dict:
    return TelegramClient(settings).get_webhook_info().data
