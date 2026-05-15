from collections.abc import Generator
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from sqlalchemy import DateTime, Float, Integer, String, Text, create_engine, text
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from url_threat_checker.config import get_settings


class Base(DeclarativeBase):
    pass


def now_utc() -> datetime:
    return datetime.now(UTC)


def uuid_str() -> str:
    return str(uuid4())


class ScanReport(Base):
    __tablename__ = "scan_reports"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    source_type: Mapped[str] = mapped_column(String(32), default="manual", index=True)
    source_platform: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source_sender: Mapped[str | None] = mapped_column(String(255), nullable=True)
    source_message_preview: Mapped[str | None] = mapped_column(Text, nullable=True)

    original_url: Mapped[str] = mapped_column(Text)
    normalized_url: Mapped[str] = mapped_column(Text)
    url_hash: Mapped[str] = mapped_column(String(64), index=True)
    defanged_url: Mapped[str] = mapped_column(Text)
    domain: Mapped[str] = mapped_column(String(255), index=True)
    registered_domain: Mapped[str] = mapped_column(String(255), index=True)

    final_verdict: Mapped[str] = mapped_column(String(32), index=True)
    risk_score: Mapped[int] = mapped_column(Integer)
    local_prediction: Mapped[str] = mapped_column(String(32))
    local_confidence: Mapped[float] = mapped_column(Float)
    model_status: Mapped[str] = mapped_column(String(32), default="unavailable")

    heuristic_flags_json: Mapped[str] = mapped_column(Text, default="[]")
    features_json: Mapped[str] = mapped_column(Text, default="{}")

    virustotal_status: Mapped[str] = mapped_column(String(32), default="not_configured")
    virustotal_malicious: Mapped[int | None] = mapped_column(Integer, nullable=True)
    virustotal_suspicious: Mapped[int | None] = mapped_column(Integer, nullable=True)
    virustotal_harmless: Mapped[int | None] = mapped_column(Integer, nullable=True)
    virustotal_undetected: Mapped[int | None] = mapped_column(Integer, nullable=True)

    recommendation: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=now_utc,
        index=True,
    )


class SiteSettings(Base):
    __tablename__ = "site_settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text)


class VirustotalCache(Base):
    __tablename__ = "virustotal_cache"

    url_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    normalized_url: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(32))
    malicious: Mapped[int | None] = mapped_column(Integer, nullable=True)
    suspicious: Mapped[int | None] = mapped_column(Integer, nullable=True)
    harmless: Mapped[int | None] = mapped_column(Integer, nullable=True)
    undetected: Mapped[int | None] = mapped_column(Integer, nullable=True)
    raw_summary_json: Mapped[str] = mapped_column(Text, default="{}")
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


def _engine_kwargs(database_url: str) -> dict:
    if database_url.startswith("sqlite"):
        db_path = database_url.removeprefix("sqlite:///")
        if db_path and db_path != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        return {"connect_args": {"check_same_thread": False}}
    return {}


settings = get_settings()
engine = create_engine(settings.database_url, future=True, **_engine_kwargs(settings.database_url))
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


def initialize_database() -> None:
    Base.metadata.create_all(bind=engine)


def reset_database_schema() -> None:
    Base.metadata.drop_all(bind=engine)
    with engine.begin() as connection:
        connection.execute(text("DROP TABLE IF EXISTS audit_events"))
        connection.execute(text("DROP TABLE IF EXISTS model_runs"))
    Base.metadata.create_all(bind=engine)


def get_db() -> Generator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
