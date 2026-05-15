from collections.abc import Iterator
from contextlib import contextmanager

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from url_threat_checker.config import Settings, get_settings
from url_threat_checker.database import Base, ScanReport, get_db
from url_threat_checker.main import app
from url_threat_checker.scripts.reset_demo import reset_demo_session


@contextmanager
def api_client_context(
    settings: Settings | None = None,
) -> Iterator[tuple[TestClient, sessionmaker]]:
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    test_settings = settings or Settings(virustotal_api_key=None)

    def override_get_db() -> Iterator[Session]:
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_settings] = lambda: test_settings

    try:
        with TestClient(app) as client:
            yield client, session_factory
    finally:
        app.dependency_overrides.clear()


def login(client: TestClient) -> None:
    response = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "admin123"},
    )
    assert response.status_code == 200


def create_scan(client: TestClient, url: str) -> dict:
    response = client.post(
        "/api/v1/scans",
        json={"url": url, "include_virustotal": False},
    )
    assert response.status_code == 201
    return response.json()


def add_report(
    db: Session,
    *,
    local_prediction: str,
    virustotal_status: str,
    malicious: int | None,
    suspicious: int | None,
) -> None:
    domain = f"{local_prediction}-{virustotal_status}.example"
    db.add(
        ScanReport(
            source_type="manual",
            original_url=f"https://{domain}",
            normalized_url=f"https://{domain}/",
            url_hash=domain.ljust(64, "0")[:64],
            defanged_url=f"hxxps://{domain.replace('.', '[.]')}/",
            domain=domain,
            registered_domain="example",
            final_verdict="dangerous" if local_prediction != "benign" else "safe",
            risk_score=80 if local_prediction != "benign" else 5,
            local_prediction=local_prediction,
            local_confidence=0.9,
            model_status="available",
            heuristic_flags_json="[]",
            features_json="{}",
            virustotal_status=virustotal_status,
            virustotal_malicious=malicious,
            virustotal_suspicious=suspicious,
            virustotal_harmless=10,
            virustotal_undetected=5,
            recommendation="Test report.",
        )
    )


def test_health() -> None:
    with api_client_context() as (client, _):
        response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert response.headers["X-Content-Type-Options"] == "nosniff"


def test_scan_requires_auth() -> None:
    with api_client_context() as (client, _):
        response = client.post("/api/v1/scans", json={"url": "https://example.com"})

    assert response.status_code == 401


def test_login_cookie_allows_authenticated_requests_and_logout() -> None:
    with api_client_context() as (client, _):
        login_response = client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "admin123"},
        )
        assert login_response.status_code == 200
        assert login_response.json() == {"username": "admin"}
        assert "utc_session" in client.cookies

        me = client.get("/api/v1/auth/me")
        assert me.status_code == 200
        assert me.json() == {"username": "admin"}

        scan = create_scan(client, "https://www.google.com/search?q=university+project")
        assert scan["final_verdict"] == "safe"

        logout = client.post("/api/v1/auth/logout")
        assert logout.status_code == 200

        unauthenticated = client.get("/api/v1/auth/me")
        assert unauthenticated.status_code == 401


def test_scan_list_detail_stats_filter_and_search() -> None:
    with api_client_context() as (client, _):
        login(client)
        safe = create_scan(client, "https://www.google.com/search?q=university+project")
        dangerous = create_scan(client, "https://google.com.fake-domain.ru/login")

        index = client.get("/api/v1/scans?limit=10")
        dangerous_only = client.get("/api/v1/scans?verdict=dangerous")
        search = client.get("/api/v1/scans?q=fake-domain")
        detail = client.get(f"/api/v1/scans/{dangerous['id']}")
        stats = client.get("/api/v1/stats")

    assert index.status_code == 200
    assert len(index.json()) == 2
    assert dangerous_only.status_code == 200
    assert [item["id"] for item in dangerous_only.json()] == [dangerous["id"]]
    assert search.status_code == 200
    assert [item["id"] for item in search.json()] == [dangerous["id"]]
    assert detail.status_code == 200
    assert detail.json()["verdict_explanation"]
    assert stats.status_code == 200
    assert stats.json()["total"] == 2
    assert stats.json()["safe"] == 1
    assert stats.json()["comparison"]["eligible_scans"] == 0
    assert stats.json()["comparison"]["agreement_rate"] is None
    assert safe["final_verdict"] == "safe"


def test_stats_include_local_model_virustotal_comparison() -> None:
    with api_client_context() as (client, session_factory):
        login(client)
        with session_factory() as db:
            add_report(
                db,
                local_prediction="benign",
                virustotal_status="fetched",
                malicious=0,
                suspicious=0,
            )
            add_report(
                db,
                local_prediction="phishing",
                virustotal_status="cached",
                malicious=2,
                suspicious=0,
            )
            add_report(
                db,
                local_prediction="malware",
                virustotal_status="fetched",
                malicious=0,
                suspicious=0,
            )
            add_report(
                db,
                local_prediction="benign",
                virustotal_status="fetched",
                malicious=1,
                suspicious=0,
            )
            add_report(
                db,
                local_prediction="unknown",
                virustotal_status="fetched",
                malicious=0,
                suspicious=0,
            )
            add_report(
                db,
                local_prediction="benign",
                virustotal_status="skipped",
                malicious=None,
                suspicious=None,
            )
            db.commit()

        stats = client.get("/api/v1/stats")

    assert stats.status_code == 200
    comparison = stats.json()["comparison"]
    assert comparison == {
        "eligible_scans": 4,
        "agreement_count": 2,
        "disagreement_count": 2,
        "agreement_rate": 0.5,
        "model_risky_vt_clean": 1,
        "model_clean_vt_risky": 1,
        "vt_risky": 2,
        "vt_clean": 2,
        "excluded_scans": 2,
    }


def test_scan_detail_404_invalid_url_and_model_metrics() -> None:
    with api_client_context() as (client, _):
        login(client)
        missing = client.get("/api/v1/scans/not-a-real-id")
        invalid = client.post("/api/v1/scans", json={"url": ""})
        model = client.get("/api/v1/model/metrics")

    assert missing.status_code == 404
    assert invalid.status_code == 422
    assert model.status_code == 200
    assert "status" in model.json()
    assert "card" in model.json()


def test_origin_and_body_size_guards() -> None:
    with api_client_context() as (client, _):
        blocked_origin = client.post(
            "/api/v1/auth/login",
            headers={"Origin": "http://evil.example"},
            json={"username": "admin", "password": "admin123"},
        )
        large_body = client.post(
            "/api/v1/auth/login",
            content=b"x" * 70_000,
            headers={"Content-Type": "application/json"},
        )

    assert blocked_origin.status_code == 403
    assert large_body.status_code == 413


def test_reset_demo_session_replaces_existing_scans() -> None:
    with api_client_context() as (client, session_factory):
        login(client)
        create_scan(client, "https://www.google.com")
        with session_factory() as db:
            count = reset_demo_session(db)
            reports = client.get("/api/v1/scans?limit=20")

    assert count == 8
    assert reports.status_code == 200
    assert len(reports.json()) == 8


def test_reset_demo_session_can_seed_comparison_data() -> None:
    with api_client_context() as (client, session_factory):
        login(client)
        with session_factory() as db:
            count = reset_demo_session(db, with_comparison=True)
            stats = client.get("/api/v1/stats")
            reports = client.get("/api/v1/scans?limit=20")

    comparison = stats.json()["comparison"]
    assert count == 8
    assert reports.status_code == 200
    assert all(report["virustotal_status"] == "cached" for report in reports.json())
    assert comparison["eligible_scans"] == 8
    assert comparison["agreement_rate"] is not None
