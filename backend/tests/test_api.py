import logging
from collections.abc import Iterator
from contextlib import contextmanager

import pyotp
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from url_threat_checker import auth as auth_module
from url_threat_checker.config import DEFAULT_ADMIN_PASSWORD_HASH, Settings, get_settings
from url_threat_checker.database import Base, ScanReport, get_db
from url_threat_checker.main import app
from url_threat_checker.scripts.reset_demo import reset_demo_session

# Test-only TOTP secret (real-looking base32, but generated for fixtures).
_TEST_TOTP_SECRET = "JBSWY3DPEHPK3PXP"


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
    test_settings = settings or Settings(
        _env_file=None,
        virustotal_api_key=None,
        admin_password_hash=DEFAULT_ADMIN_PASSWORD_HASH,
        totp_secret=None,
    )

    def override_get_db() -> Iterator[Session]:
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_settings] = lambda: test_settings
    app.state.settings = test_settings
    # TestClient uses the constant host "testclient", so all tests share one
    # rate-limit bucket. Reset before each test to keep them independent.
    app.state.limiter.reset()
    # Module-level state (epoch cache) — also reset to keep tests independent.
    auth_module._epoch_cache.clear()

    try:
        with TestClient(app) as client:
            yield client, session_factory
    finally:
        app.dependency_overrides.clear()


def _settings_with_2fa() -> Settings:
    return Settings(
        _env_file=None,
        virustotal_api_key=None,
        admin_password_hash=DEFAULT_ADMIN_PASSWORD_HASH,
        totp_secret=_TEST_TOTP_SECRET,
    )


def _current_totp(secret: str = _TEST_TOTP_SECRET) -> str:
    return pyotp.TOTP(secret).now()


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
        assert login_response.json() == {"requires_2fa": False, "username": "admin"}
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


# ── 2FA hardening tests ──────────────────────────────────────────────────────


def test_2fa_login_returns_pending_cookie() -> None:
    with api_client_context(_settings_with_2fa()) as (client, _):
        response = client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "admin123"},
        )
    assert response.status_code == 200
    assert response.json() == {"requires_2fa": True, "username": None}
    assert "utc_pending" in response.cookies or "utc_pending" in client.cookies
    assert "utc_session" not in client.cookies


def test_2fa_verify_with_valid_code_mints_session() -> None:
    with api_client_context(_settings_with_2fa()) as (client, _):
        client.post("/api/v1/auth/login", json={"username": "admin", "password": "admin123"})
        verify = client.post("/api/v1/auth/verify-2fa", json={"code": _current_totp()})
        me = client.get("/api/v1/auth/me")
    assert verify.status_code == 200
    assert verify.json() == {"username": "admin"}
    assert me.status_code == 200


def test_2fa_verify_with_invalid_code_returns_401() -> None:
    with api_client_context(_settings_with_2fa()) as (client, _):
        client.post("/api/v1/auth/login", json={"username": "admin", "password": "admin123"})
        verify = client.post("/api/v1/auth/verify-2fa", json={"code": "000000"})
    assert verify.status_code == 401


def test_2fa_verify_replay_rejected() -> None:
    with api_client_context(_settings_with_2fa()) as (client, _):
        client.post("/api/v1/auth/login", json={"username": "admin", "password": "admin123"})
        code = _current_totp()
        first = client.post("/api/v1/auth/verify-2fa", json={"code": code})
        # Log in fresh (new pending cookie) and try to reuse the same code.
        client.cookies.clear()
        client.post("/api/v1/auth/login", json={"username": "admin", "password": "admin123"})
        replay = client.post("/api/v1/auth/verify-2fa", json={"code": code})
    assert first.status_code == 200
    assert replay.status_code == 401


def test_pending_cookie_single_use() -> None:
    with api_client_context(_settings_with_2fa()) as (client, _):
        client.post("/api/v1/auth/login", json={"username": "admin", "password": "admin123"})
        # Snapshot the pending cookie (TestClient drops it once /verify-2fa clears it).
        pending = client.cookies.get("utc_pending")
        first = client.post("/api/v1/auth/verify-2fa", json={"code": _current_totp()})
        # Restore the just-consumed pending cookie and attempt to replay.
        client.cookies.set("utc_pending", pending)
        # Advance one TOTP step by waiting via pyotp's at() — but we still need a
        # valid code, so issue from the future bucket so _verify_totp would
        # otherwise accept it (we're testing the JTI gate, not replay).
        import time as _t

        future = pyotp.TOTP(_TEST_TOTP_SECRET).at(int(_t.time()) + 30)
        second = client.post("/api/v1/auth/verify-2fa", json={"code": future})
    assert first.status_code == 200
    assert second.status_code == 401


def test_reset_password_with_totp_invalidates_old_session() -> None:
    with api_client_context(_settings_with_2fa()) as (client, _):
        client.post("/api/v1/auth/login", json={"username": "admin", "password": "admin123"})
        client.post("/api/v1/auth/verify-2fa", json={"code": _current_totp()})
        me_before = client.get("/api/v1/auth/me")
        # Reset password — wait one TOTP step so we don't replay the just-used code.
        import time as _t

        next_code = pyotp.TOTP(_TEST_TOTP_SECRET).at(int(_t.time()) + 30)
        reset = client.post(
            "/api/v1/auth/reset-password",
            json={"new_password": "new-password-xyz", "verification_code": next_code},
        )
        me_after = client.get("/api/v1/auth/me")
    assert me_before.status_code == 200
    assert reset.status_code == 200
    assert reset.json()["ok"] is True
    assert me_after.status_code == 401


def test_reset_password_with_recovery_code() -> None:
    with api_client_context(_settings_with_2fa()) as (client, session_factory):
        with session_factory() as db:
            codes = auth_module._generate_recovery_codes(db, 3)
            db.commit()
        reset = client.post(
            "/api/v1/auth/reset-password",
            json={"new_password": "new-password-xyz", "verification_code": codes[0]},
        )
        # Old code should fail on second use.
        replay = client.post(
            "/api/v1/auth/reset-password",
            json={"new_password": "another-password", "verification_code": codes[0]},
        )
    assert reset.status_code == 200
    assert reset.json() == {"ok": True, "recovery_codes_remaining": 2}
    assert replay.status_code == 401


def test_rate_limit_login_returns_429() -> None:
    settings = Settings(
        _env_file=None,
        virustotal_api_key=None,
        admin_password_hash=DEFAULT_ADMIN_PASSWORD_HASH,
        totp_secret=None,
    )
    with api_client_context(settings) as (client, _):
        # Default limit is "5/minute" baked in at module import.
        for _ in range(5):
            client.post("/api/v1/auth/login", json={"username": "x", "password": "wrong"})
        sixth = client.post("/api/v1/auth/login", json={"username": "x", "password": "wrong"})
    assert sixth.status_code == 429


def test_rate_limit_verify_2fa_returns_429() -> None:
    with api_client_context(_settings_with_2fa()) as (client, _):
        client.post("/api/v1/auth/login", json={"username": "admin", "password": "admin123"})
        for _ in range(5):
            client.post("/api/v1/auth/verify-2fa", json={"code": "000000"})
        sixth = client.post("/api/v1/auth/verify-2fa", json={"code": "000000"})
    assert sixth.status_code == 429


def test_rate_limit_reset_password_returns_429() -> None:
    with api_client_context(_settings_with_2fa()) as (client, _):
        for _ in range(3):
            client.post(
                "/api/v1/auth/reset-password",
                json={"new_password": "doesnotmatter", "verification_code": "000000"},
            )
        fourth = client.post(
            "/api/v1/auth/reset-password",
            json={"new_password": "doesnotmatter", "verification_code": "000000"},
        )
    assert fourth.status_code == 429


def test_invalid_totp_secret_returns_503() -> None:
    bad = Settings(
        _env_file=None,
        virustotal_api_key=None,
        admin_password_hash=DEFAULT_ADMIN_PASSWORD_HASH,
        totp_secret="not-valid-base32!!!",
    )
    with api_client_context(bad) as (client, _):
        login = client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "admin123"},
        )
        verify = client.post("/api/v1/auth/verify-2fa", json={"code": "000000"})
    # Login still succeeds with the password (returns pending), but verify-2fa
    # bails with 503 because the secret is unusable.
    assert login.status_code == 200
    assert verify.status_code == 503


def test_audit_log_emitted_on_failed_login(caplog) -> None:
    # The package logger is configured with propagate=False (production posture
    # — see main._configure_logging). Re-enable propagation for the duration of
    # this test so pytest's caplog handler can observe the records.
    pkg_logger = logging.getLogger("url_threat_checker")
    prev_propagate = pkg_logger.propagate
    pkg_logger.propagate = True
    try:
        with (
            caplog.at_level(logging.WARNING, logger="url_threat_checker.auth"),
            api_client_context() as (client, _),
        ):
            client.post("/api/v1/auth/login", json={"username": "admin", "password": "wrong"})
        records = [r for r in caplog.records if r.name == "url_threat_checker.auth"]
    finally:
        pkg_logger.propagate = prev_propagate
    assert any(
        getattr(r, "event", None) == "login" and getattr(r, "outcome", "").startswith("failure")
        for r in records
    )


def test_logout_clears_pending_cookie() -> None:
    with api_client_context(_settings_with_2fa()) as (client, _):
        client.post("/api/v1/auth/login", json={"username": "admin", "password": "admin123"})
        assert client.cookies.get("utc_pending") is not None
        logout = client.post("/api/v1/auth/logout")
        # TestClient applies Set-Cookie expiry semantics, so the cleared cookie
        # is no longer in the jar.
    assert logout.status_code == 200
    assert client.cookies.get("utc_pending") is None
    assert client.cookies.get("utc_session") is None


def test_login_without_2fa_session_has_epoch_claim() -> None:
    with api_client_context() as (client, _):
        client.post("/api/v1/auth/login", json={"username": "admin", "password": "admin123"})
        cookie = client.cookies.get("utc_session")
    assert cookie is not None
    # Decode payload — base64url JSON before the '.' separator.
    import base64
    import json as _json

    encoded = cookie.split(".")[0]
    payload = _json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
    assert "epoch" in payload
    assert payload["sub"] == "admin"


# ── /change-password tests ───────────────────────────────────────────────────


def test_change_password_with_correct_current_password_succeeds() -> None:
    with api_client_context() as (client, _):
        login(client)
        change = client.post(
            "/api/v1/auth/change-password",
            json={"current_password": "admin123", "new_password": "new-strong-pw"},
        )
        # Old password no longer works
        client.cookies.clear()
        old_login = client.post(
            "/api/v1/auth/login", json={"username": "admin", "password": "admin123"}
        )
        # New password does
        new_login = client.post(
            "/api/v1/auth/login", json={"username": "admin", "password": "new-strong-pw"}
        )
    assert change.status_code == 200
    assert old_login.status_code == 401
    assert new_login.status_code == 200


def test_change_password_with_wrong_current_password_returns_401() -> None:
    with api_client_context() as (client, _):
        login(client)
        change = client.post(
            "/api/v1/auth/change-password",
            json={"current_password": "wrong-current", "new_password": "new-strong-pw"},
        )
        # Original password still works
        client.cookies.clear()
        relogin = client.post(
            "/api/v1/auth/login", json={"username": "admin", "password": "admin123"}
        )
    assert change.status_code == 401
    assert relogin.status_code == 200


def test_change_password_requires_auth() -> None:
    with api_client_context() as (client, _):
        change = client.post(
            "/api/v1/auth/change-password",
            json={"current_password": "admin123", "new_password": "new-strong-pw"},
        )
    assert change.status_code == 401


def test_change_password_keeps_caller_logged_in() -> None:
    with api_client_context() as (client, _):
        login(client)
        change = client.post(
            "/api/v1/auth/change-password",
            json={"current_password": "admin123", "new_password": "new-strong-pw"},
        )
        # Caller's session was rotated — /me must still work without re-logging in.
        me = client.get("/api/v1/auth/me")
    assert change.status_code == 200
    assert me.status_code == 200
    assert me.json() == {"username": "admin"}


def test_change_password_revokes_other_sessions() -> None:
    with api_client_context() as (client_a, _):
        # client_a logs in
        login(client_a)
        # Simulate a second concurrent device by using the underlying app via a
        # fresh TestClient that targets the same in-memory DB (same dependency
        # overrides are still active because api_client_context didn't exit).
        client_b = TestClient(app)
        login(client_b)
        assert client_b.get("/api/v1/auth/me").status_code == 200

        # client_a changes its password — bumps the session epoch
        change = client_a.post(
            "/api/v1/auth/change-password",
            json={"current_password": "admin123", "new_password": "new-strong-pw"},
        )
        # client_b's session is now stale
        b_after = client_b.get("/api/v1/auth/me")
        # client_a stays logged in (token was rotated in the change-password response)
        a_after = client_a.get("/api/v1/auth/me")
    assert change.status_code == 200
    assert b_after.status_code == 401
    assert a_after.status_code == 200


def test_change_password_rate_limited() -> None:
    with api_client_context() as (client, _):
        login(client)
        for _ in range(5):
            client.post(
                "/api/v1/auth/change-password",
                json={"current_password": "wrong", "new_password": "doesntmatter"},
            )
        sixth = client.post(
            "/api/v1/auth/change-password",
            json={"current_password": "wrong", "new_password": "doesntmatter"},
        )
    assert sixth.status_code == 429
