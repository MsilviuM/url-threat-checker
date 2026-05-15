"""Telegram webhook management command."""

import argparse

from url_threat_checker.config import get_settings
from url_threat_checker.telegram.client import TelegramClient

ALLOWED_UPDATES = ["message", "edited_message", "channel_post", "edited_channel_post"]


def _webhook_url(public_base_url: str, path_token: str) -> str:
    return f"{public_base_url.rstrip('/')}/api/v1/integrations/telegram/webhook/{path_token}"


def main() -> None:
    settings = get_settings()
    parser = argparse.ArgumentParser(description="Manage the Telegram webhook.")
    subcommands = parser.add_subparsers(dest="command", required=True)

    set_parser = subcommands.add_parser("set", help="Register the Telegram webhook.")
    set_parser.add_argument("--public-base-url", default=settings.telegram_public_base_url)
    set_parser.add_argument("--drop-pending-updates", action="store_true")

    delete_parser = subcommands.add_parser("delete", help="Delete the Telegram webhook.")
    delete_parser.add_argument("--drop-pending-updates", action="store_true")

    subcommands.add_parser("info", help="Show Telegram webhook information.")
    args = parser.parse_args()

    client = TelegramClient(settings)
    if args.command == "set":
        if not args.public_base_url:
            parser.error("--public-base-url or TELEGRAM_PUBLIC_BASE_URL is required.")
        if not settings.telegram_webhook_path_token:
            parser.error("TELEGRAM_WEBHOOK_PATH_TOKEN is required.")
        result = client.set_webhook(
            public_url=_webhook_url(args.public_base_url, settings.telegram_webhook_path_token),
            allowed_updates=ALLOWED_UPDATES,
            drop_pending_updates=args.drop_pending_updates,
        )
    elif args.command == "delete":
        result = client.delete_webhook(drop_pending_updates=args.drop_pending_updates)
    else:
        result = client.get_webhook_info()

    if result.ok:
        print("Telegram webhook command succeeded.")
        if result.data:
            safe_data = {key: value for key, value in result.data.items() if key != "result"}
            print(safe_data)
        return

    print(f"Telegram webhook command failed: {result.description or result.status_code}")


if __name__ == "__main__":
    main()
