from datetime import UTC, datetime, timedelta

import httpx
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from url_threat_checker.config import Settings
from url_threat_checker.database import Base, VirustotalCache
from url_threat_checker.virustotal import VirustotalClient, sha256_text


def db_session() -> Session:
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    return session_factory()


def settings(**overrides: object) -> Settings:
    defaults = {
        "virustotal_api_key": "test-key",
        "virustotal_base_url": "https://virustotal.test/api/v3",
        "virustotal_cache_ttl_hours": 24,
    }
    defaults.update(overrides)
    return Settings(**defaults)


def test_lookup_skips_when_not_included() -> None:
    with db_session() as db:
        summary = VirustotalClient(settings=settings()).lookup(
            db,
            "https://example.com",
            include=False,
        )

    assert summary.status == "skipped"


def test_lookup_reports_not_configured_without_api_key() -> None:
    with db_session() as db:
        summary = VirustotalClient(settings=settings(virustotal_api_key=None)).lookup(
            db,
            "https://example.com",
            include=True,
        )

    assert summary.status == "not_configured"


def test_lookup_reuses_fresh_cache() -> None:
    normalized_url = "https://cached.example.com"
    url_hash = sha256_text(normalized_url)
    with db_session() as db:
        db.add(
            VirustotalCache(
                url_hash=url_hash,
                normalized_url=normalized_url,
                status="fetched",
                malicious=2,
                suspicious=1,
                harmless=10,
                undetected=5,
                raw_summary_json="{}",
                expires_at=datetime.now(UTC) + timedelta(hours=1),
            )
        )
        db.commit()

        summary = VirustotalClient(settings=settings()).lookup(db, normalized_url, include=True)

    assert summary.status == "cached"
    assert summary.malicious == 2
    assert summary.source == "cache"


def test_lookup_reuses_fresh_cache_without_api_key() -> None:
    normalized_url = "https://cached-without-key.example.com"
    url_hash = sha256_text(normalized_url)
    with db_session() as db:
        db.add(
            VirustotalCache(
                url_hash=url_hash,
                normalized_url=normalized_url,
                status="fetched",
                malicious=0,
                suspicious=0,
                harmless=12,
                undetected=3,
                raw_summary_json="{}",
                expires_at=datetime.now(UTC) + timedelta(hours=1),
            )
        )
        db.commit()

        summary = VirustotalClient(settings=settings(virustotal_api_key=None)).lookup(
            db,
            normalized_url,
            include=True,
        )

    assert summary.status == "cached"
    assert summary.harmless == 12


def test_lookup_fetches_and_caches_successful_report() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["x-apikey"] == "test-key"
        return httpx.Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 3,
                            "suspicious": 2,
                            "harmless": 60,
                            "undetected": 8,
                        }
                    }
                }
            },
        )

    transport = httpx.MockTransport(handler)
    normalized_url = "https://example.com/login"
    with db_session() as db:
        summary = VirustotalClient(settings=settings(), transport=transport).lookup(
            db,
            normalized_url,
            include=True,
        )

        cached = db.get(VirustotalCache, sha256_text(normalized_url))

    assert summary.status == "fetched"
    assert summary.malicious == 3
    assert summary.suspicious == 2
    assert cached is not None
    assert cached.malicious == 3


def test_lookup_returns_not_found_without_submission() -> None:
    transport = httpx.MockTransport(lambda _request: httpx.Response(404, json={"error": "missing"}))

    with db_session() as db:
        summary = VirustotalClient(settings=settings(), transport=transport).lookup(
            db,
            "https://unknown.example.com",
            include=True,
        )

    assert summary.status == "not_found"


def test_lookup_submits_unknown_url_when_enabled() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(f"{request.method} {request.url.path}")
        if request.method == "GET":
            return httpx.Response(404, json={"error": "missing"})
        return httpx.Response(200, json={"data": {"id": "analysis-id"}})

    transport = httpx.MockTransport(handler)

    with db_session() as db:
        summary = VirustotalClient(
            settings=settings(virustotal_submit_unknown=True),
            transport=transport,
        ).lookup(db, "https://unknown.example.com", include=True)

    assert summary.status == "pending"
    assert calls == [
        "GET /api/v3/urls/aHR0cHM6Ly91bmtub3duLmV4YW1wbGUuY29t",
        "POST /api/v3/urls",
    ]


def test_lookup_handles_rate_limit() -> None:
    transport = httpx.MockTransport(lambda _request: httpx.Response(429, json={"error": "limit"}))

    with db_session() as db:
        summary = VirustotalClient(settings=settings(), transport=transport).lookup(
            db,
            "https://example.com",
            include=True,
        )

    assert summary.status == "rate_limited"


def test_lookup_handles_malformed_response() -> None:
    transport = httpx.MockTransport(lambda _request: httpx.Response(200, json={"data": {}}))

    with db_session() as db:
        summary = VirustotalClient(settings=settings(), transport=transport).lookup(
            db,
            "https://example.com",
            include=True,
        )

    assert summary.status == "malformed_response"


def test_lookup_handles_http_error() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("network failed")

    transport = httpx.MockTransport(handler)

    with db_session() as db:
        summary = VirustotalClient(settings=settings(), transport=transport).lookup(
            db,
            "https://example.com",
            include=True,
        )

    assert summary.status == "failed"
