"""Telegram webhook request guards."""

import hmac

from fastapi import HTTPException, status
from starlette.requests import Request

from url_threat_checker.config import Settings

TELEGRAM_SECRET_HEADER = "x-telegram-bot-api-secret-token"


def verify_telegram_webhook(request: Request, path_token: str, settings: Settings) -> None:
    if not settings.telegram_webhook_secret or not settings.telegram_webhook_path_token:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Telegram webhook is not configured.",
        )

    if not hmac.compare_digest(path_token, settings.telegram_webhook_path_token):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid webhook path.")

    provided = request.headers.get(TELEGRAM_SECRET_HEADER, "")
    if not hmac.compare_digest(provided, settings.telegram_webhook_secret):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid webhook secret.")
