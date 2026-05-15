"""Optional VirusTotal lookup. The app still works when no API key is configured."""

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from sqlalchemy.orm import Session

from url_threat_checker.config import Settings, get_settings
from url_threat_checker.database import VirustotalCache


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class VirustotalSummary:
    status: str
    malicious: int | None = None
    suspicious: int | None = None
    harmless: int | None = None
    undetected: int | None = None
    source: str = "none"
    message: str | None = None


def vt_url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")


class VirustotalClient:
    def __init__(
        self,
        settings: Settings | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.transport = transport

    def lookup(self, db: Session, normalized_url: str, include: bool) -> VirustotalSummary:
        if not include:
            return VirustotalSummary(status="skipped")

        url_hash = sha256_text(normalized_url)
        cached = db.get(VirustotalCache, url_hash)
        now = datetime.now(UTC)
        if cached and self._as_utc(cached.expires_at) > now:
            return VirustotalSummary(
                status="cached",
                malicious=cached.malicious,
                suspicious=cached.suspicious,
                harmless=cached.harmless,
                undetected=cached.undetected,
                source="cache",
            )

        if not self.settings.virustotal_api_key:
            return VirustotalSummary(status="not_configured")

        headers = {"accept": "application/json", "x-apikey": self.settings.virustotal_api_key}
        try:
            response = self._request(
                method="GET",
                path=f"/urls/{vt_url_id(normalized_url)}",
                headers=headers,
            )
            if response.status_code == 404 and self.settings.virustotal_submit_unknown:
                return self._submit_url(normalized_url, headers)
            if response.status_code == 404:
                return VirustotalSummary(
                    status="not_found",
                    message="VirusTotal has no existing report for this URL.",
                )
            if response.status_code == 429:
                return VirustotalSummary(
                    status="rate_limited",
                    message="VirusTotal rate limit reached.",
                )
            response.raise_for_status()
        except httpx.HTTPError:
            return VirustotalSummary(status="failed", message="VirusTotal request failed.")

        try:
            stats = self._extract_stats(response.json())
        except (TypeError, ValueError, json.JSONDecodeError):
            return VirustotalSummary(
                status="malformed_response",
                message="VirusTotal response did not contain valid analysis statistics.",
            )

        summary = VirustotalSummary(
            status="fetched",
            malicious=self._safe_int(stats.get("malicious")),
            suspicious=self._safe_int(stats.get("suspicious")),
            harmless=self._safe_int(stats.get("harmless")),
            undetected=self._safe_int(stats.get("undetected")),
            source="api",
        )
        self._write_cache(db, normalized_url, summary, stats)
        return summary

    def _submit_url(self, normalized_url: str, headers: dict[str, str]) -> VirustotalSummary:
        try:
            response = self._request(
                method="POST",
                path="/urls",
                headers=headers,
                data={"url": normalized_url},
            )
            if response.status_code == 429:
                return VirustotalSummary(
                    status="rate_limited",
                    message="VirusTotal rate limit reached.",
                )
            response.raise_for_status()
        except httpx.HTTPError:
            return VirustotalSummary(status="failed", message="VirusTotal URL submission failed.")
        return VirustotalSummary(status="pending", source="api")

    def _request(
        self,
        method: str,
        path: str,
        headers: dict[str, str],
        data: dict[str, str] | None = None,
    ) -> httpx.Response:
        with httpx.Client(
            base_url=self.settings.virustotal_base_url,
            timeout=8,
            transport=self.transport,
        ) as client:
            return client.request(method, path, headers=headers, data=data)

    @staticmethod
    def _extract_stats(payload: dict[str, Any]) -> dict[str, Any]:
        data = payload.get("data")
        if not isinstance(data, dict):
            raise ValueError("data must be an object.")
        attributes = data.get("attributes")
        if not isinstance(attributes, dict):
            raise ValueError("attributes must be an object.")
        stats = attributes.get("last_analysis_stats")
        if not isinstance(stats, dict):
            raise ValueError("last_analysis_stats must be an object.")
        return stats

    @staticmethod
    def _safe_int(value: Any) -> int:
        if value is None:
            return 0
        return int(value)

    @staticmethod
    def _as_utc(value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    def _write_cache(
        self,
        db: Session,
        normalized_url: str,
        summary: VirustotalSummary,
        stats: dict,
    ) -> None:
        url_hash = sha256_text(normalized_url)
        expires_at = datetime.now(UTC) + timedelta(hours=self.settings.virustotal_cache_ttl_hours)
        record = db.get(VirustotalCache, url_hash)
        if record is None:
            record = VirustotalCache(
                url_hash=url_hash,
                normalized_url=normalized_url,
                status=summary.status,
                malicious=summary.malicious,
                suspicious=summary.suspicious,
                harmless=summary.harmless,
                undetected=summary.undetected,
                raw_summary_json=json.dumps(stats),
                expires_at=expires_at,
            )
            db.add(record)
            db.flush()
            return

        record.status = summary.status
        record.malicious = summary.malicious
        record.suspicious = summary.suspicious
        record.harmless = summary.harmless
        record.undetected = summary.undetected
        record.raw_summary_json = json.dumps(stats)
        record.fetched_at = datetime.now(UTC)
        record.expires_at = expires_at
        db.flush()
