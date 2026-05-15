from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_ROOT = Path(__file__).resolve().parents[2]
PROJECT_ROOT = BACKEND_ROOT.parent

DEFAULT_ADMIN_PASSWORD_HASH = (
    "pbkdf2_sha256$260000$dXJsLXRocmVhdC1kZW1vLXNhbHQ$"
    "9y9jpBrb-hPXQU35h0SLyc2XOU7gFxVXFVmqFWNtuc4"
)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(BACKEND_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_env: str = "development"
    database_url: str = f"sqlite:///{BACKEND_ROOT / 'var' / 'url_threat_checker.db'}"
    backend_cors_origins: str = "http://localhost:3000"

    admin_username: str = "admin"
    admin_password_hash: str = DEFAULT_ADMIN_PASSWORD_HASH
    session_secret: str = "dev-session-secret-change-me"
    session_cookie_name: str = "utc_session"
    session_ttl_seconds: int = 60 * 60 * 8

    model_path: str = str(PROJECT_ROOT / "models" / "url_classifier.skops")
    model_card_path: str = str(PROJECT_ROOT / "models" / "model_card.json")

    virustotal_api_key: str | None = None
    virustotal_cache_ttl_hours: int = 24
    virustotal_submit_unknown: bool = False
    virustotal_base_url: str = "https://www.virustotal.com/api/v3"

    max_request_body_bytes: int = Field(default=65_536, ge=1024, le=1_000_000)

    @property
    def cors_origins(self) -> list[str]:
        return [origin.strip() for origin in self.backend_cors_origins.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
