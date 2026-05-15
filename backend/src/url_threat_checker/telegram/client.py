"""Thin Telegram Bot API client."""

from dataclasses import dataclass
from typing import Any

import httpx

from url_threat_checker.config import Settings, get_settings


@dataclass(frozen=True)
class TelegramApiResult:
    ok: bool
    status_code: int
    data: dict[str, Any]
    description: str | None = None


class TelegramClient:
    def __init__(
        self,
        settings: Settings | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.transport = transport

    def send_message(
        self,
        chat_id: int | str,
        text: str,
        reply_to_message_id: int | None = None,
        disable_web_page_preview: bool = True,
    ) -> TelegramApiResult:
        payload: dict[str, Any] = {
            "chat_id": chat_id,
            "text": text,
            "disable_web_page_preview": disable_web_page_preview,
        }
        if reply_to_message_id is not None:
            payload["reply_to_message_id"] = reply_to_message_id
            payload["allow_sending_without_reply"] = True
        return self._post("sendMessage", payload)

    def set_webhook(
        self,
        public_url: str,
        allowed_updates: list[str],
        drop_pending_updates: bool = False,
    ) -> TelegramApiResult:
        return self._post(
            "setWebhook",
            {
                "url": public_url,
                "secret_token": self.settings.telegram_webhook_secret,
                "allowed_updates": allowed_updates,
                "drop_pending_updates": drop_pending_updates,
            },
        )

    def delete_webhook(self, drop_pending_updates: bool = False) -> TelegramApiResult:
        return self._post("deleteWebhook", {"drop_pending_updates": drop_pending_updates})

    def get_webhook_info(self) -> TelegramApiResult:
        return self._post("getWebhookInfo", {})

    def _post(self, method: str, payload: dict[str, Any]) -> TelegramApiResult:
        if not self.settings.telegram_bot_token:
            return TelegramApiResult(
                ok=False,
                status_code=0,
                data={},
                description="Telegram bot token is not configured.",
            )

        try:
            with httpx.Client(
                base_url=f"{self.settings.telegram_api_base_url}/bot"
                f"{self.settings.telegram_bot_token}",
                timeout=8,
                transport=self.transport,
            ) as client:
                response = client.post(f"/{method}", json=payload)
        except httpx.HTTPError as exc:
            return TelegramApiResult(ok=False, status_code=0, data={}, description=str(exc))

        try:
            data = response.json()
        except ValueError:
            data = {}
        return TelegramApiResult(
            ok=response.status_code < 400 and bool(data.get("ok", True)),
            status_code=response.status_code,
            data=data,
            description=data.get("description") if isinstance(data, dict) else None,
        )
