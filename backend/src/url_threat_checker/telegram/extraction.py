"""Extract URL candidates from Telegram updates without deciding risk."""

import re
from dataclasses import dataclass
from typing import Literal

from url_threat_checker.telegram.schemas import TelegramMessage

_URL_RE = re.compile(
    r"(?:(?:https?|hxxps?)://[^\s<>'\"]+|"
    r"(?:[A-Za-z0-9-]+\[\.\])+[A-Za-z]{2,}(?:/[^\s<>'\"]*)?|"
    r"(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?:/[^\s<>'\"]*)?)"
)


@dataclass(frozen=True)
class ExtractedTelegramUrl:
    raw_url: str
    source_field: Literal["text", "caption", "text_link", "fallback"]
    entity_type: str | None


def _slice_by_utf16_units(value: str, offset: int, length: int) -> str:
    encoded = value.encode("utf-16-le")
    start = offset * 2
    end = (offset + length) * 2
    try:
        return encoded[start:end].decode("utf-16-le")
    except UnicodeDecodeError:
        return value[offset : offset + length]


def _strip_trailing_punctuation(value: str) -> str:
    return value.rstrip(".,!?:;)]}")


def normalize_extracted_url(value: str) -> str:
    normalized = _strip_trailing_punctuation(value.strip())
    normalized = normalized.replace("[.]", ".")
    normalized = re.sub(r"^hxxps://", "https://", normalized, flags=re.IGNORECASE)
    normalized = re.sub(r"^hxxp://", "http://", normalized, flags=re.IGNORECASE)
    return normalized


def _fallback_extract(value: str | None, seen: set[str]) -> list[ExtractedTelegramUrl]:
    if not value:
        return []

    extracted: list[ExtractedTelegramUrl] = []
    for match in _URL_RE.finditer(value):
        raw_url = normalize_extracted_url(match.group(0))
        key = raw_url.lower()
        if not raw_url or key in seen:
            continue
        seen.add(key)
        extracted.append(
            ExtractedTelegramUrl(
                raw_url=raw_url,
                source_field="fallback",
                entity_type=None,
            )
        )
    return extracted


def extract_urls(message: TelegramMessage) -> list[ExtractedTelegramUrl]:
    seen: set[str] = set()
    extracted: list[ExtractedTelegramUrl] = []

    for text_value, source_field, entities in (
        (message.text, "text", message.entities),
        (message.caption, "caption", message.caption_entities),
    ):
        if not text_value:
            continue
        for entity in entities:
            if entity.type == "text_link" and entity.url:
                raw_url = normalize_extracted_url(entity.url)
                item_source = "text_link"
            elif entity.type == "url":
                raw_url = normalize_extracted_url(
                    _slice_by_utf16_units(text_value, entity.offset, entity.length)
                )
                item_source = source_field
            else:
                continue

            key = raw_url.lower()
            if not raw_url or key in seen:
                continue
            seen.add(key)
            extracted.append(
                ExtractedTelegramUrl(
                    raw_url=raw_url,
                    source_field=item_source,
                    entity_type=entity.type,
                )
            )

    extracted.extend(_fallback_extract(message.text, seen))
    extracted.extend(_fallback_extract(message.caption, seen))
    return extracted
