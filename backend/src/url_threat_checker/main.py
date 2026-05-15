import logging
import sys
from contextlib import asynccontextmanager
from urllib.parse import urlparse

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from starlette.requests import Request

from url_threat_checker import auth, scanner
from url_threat_checker.auth import smoke_test_totp_secret
from url_threat_checker.config import get_settings
from url_threat_checker.database import initialize_database
from url_threat_checker.telegram.router import router as telegram_router


class _JsonExtraFormatter(logging.Formatter):
    """Formatter that appends LogRecord.extra fields as `key=value` pairs."""

    _STD_KEYS = frozenset(
        logging.LogRecord("", 0, "", 0, "", (), None).__dict__.keys()
    ) | {"message", "asctime", "taskName"}

    def format(self, record: logging.LogRecord) -> str:
        base = super().format(record)
        extras = {
            k: v
            for k, v in record.__dict__.items()
            if k not in self._STD_KEYS and not k.startswith("_")
        }
        if extras:
            base += " " + " ".join(f"{k}={v!r}" for k, v in extras.items())
        return base


def _configure_logging() -> None:
    pkg_logger = logging.getLogger("url_threat_checker")
    if any(isinstance(h, logging.StreamHandler) for h in pkg_logger.handlers):
        return  # already configured (e.g. tests reloading the module)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(_JsonExtraFormatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    pkg_logger.setLevel(logging.INFO)
    pkg_logger.addHandler(handler)
    pkg_logger.propagate = False


_configure_logging()


def _origin_from_header(value: str | None) -> str | None:
    if not value:
        return None
    parsed = urlparse(value)
    if not parsed.scheme or not parsed.netloc:
        return None
    return f"{parsed.scheme}://{parsed.netloc}"


@asynccontextmanager
async def lifespan(_app: FastAPI):
    initialize_database()
    settings = get_settings()
    smoke_test_totp_secret(settings.totp_secret)
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="URL Threat Checker API",
        version="0.1.0",
        summary="Hybrid URL threat analysis API with local ML and VirusTotal enrichment.",
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.limiter = auth.limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def request_guard(request: Request, call_next):
        content_length = request.headers.get("content-length")
        body_too_large = (
            content_length
            and content_length.isdigit()
            and int(content_length) > settings.max_request_body_bytes
        )
        if body_too_large:
            return JSONResponse(
                status_code=413,
                content={"detail": "Request body too large."},
            )

        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            origin = request.headers.get("origin") or _origin_from_header(
                request.headers.get("referer")
            )
            if origin and origin not in settings.cors_origins:
                return JSONResponse(
                    status_code=403,
                    content={"detail": "Request origin is not allowed."},
                )

        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    app.include_router(auth.router)
    app.include_router(scanner.router)
    app.include_router(telegram_router)
    return app


app = create_app()
