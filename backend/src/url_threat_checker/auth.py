"""Authentication: password, TOTP 2FA with replay protection, session epoch revocation,
recovery codes, audit logging, rate limiting."""

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from typing import Annotated, Any
from uuid import uuid4

import pyotp
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from slowapi import Limiter
from sqlalchemy.orm import Session

from url_threat_checker.config import Settings, get_settings
from url_threat_checker.database import SiteSettings, get_db
from url_threat_checker.schemas import (
    AuthUser,
    ChangePasswordRequest,
    LoginRequest,
    LoginResponse,
    ResetPasswordRequest,
    ResetPasswordResponse,
    TotpVerifyRequest,
)

logger = logging.getLogger("url_threat_checker.auth")
router = APIRouter(prefix="/api/v1/auth", tags=["auth"])

# ── cookie names + TTLs ────────────────────────────────────────────────────────
_PENDING_COOKIE = "utc_pending"
_PENDING_TTL = 300  # 5 minutes

# ── site_settings keys ─────────────────────────────────────────────────────────
_SETTING_PASSWORD_HASH = "admin_password_hash"
_SETTING_LAST_TOTP_COUNTER = "last_totp_counter"
_SETTING_SESSION_EPOCH = "session_epoch"
_RECOVERY_CODE_PREFIX = "recovery_code:"
_CONSUMED_PENDING_PREFIX = "consumed_pending:"

# ── module-level epoch cache (5s TTL) ──────────────────────────────────────────
_epoch_cache: dict[str, tuple[int, float]] = {}
_EPOCH_TTL_SECONDS = 5.0


# ── client IP extraction (used by rate limiter and audit log) ──────────────────

def _settings_for(request: Request) -> Settings:
    return getattr(request.app.state, "settings", None) or get_settings()


def _client_ip(request: Request) -> str:
    settings = _settings_for(request)
    if settings.app_env == "production":
        xff = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
        if xff:
            return xff
    return request.client.host if request.client else "unknown"


# ── rate limiter (module-level so endpoints can decorate; main.py wires the
#     RateLimitExceeded handler and stores this on app.state.limiter).
#     Limit strings are read from Settings at import time — operators tune via
#     env vars, then restart. Tests use the defaults. ─────────────────────────
limiter = Limiter(key_func=_client_ip)
_RATE_LIMIT_LOGIN = get_settings().auth_rate_limit_login
_RATE_LIMIT_VERIFY_2FA = get_settings().auth_rate_limit_verify_2fa
_RATE_LIMIT_RESET_PASSWORD = get_settings().auth_rate_limit_reset_password
_RATE_LIMIT_CHANGE_PASSWORD = get_settings().auth_rate_limit_change_password


# ── generic key/value store helpers (no commit; callers commit) ────────────────

def _kv_get(db: Session, key: str, default: str | None = None) -> str | None:
    row = db.get(SiteSettings, key)
    return row.value if row else default


def _kv_set(db: Session, key: str, value: str) -> None:
    row = db.get(SiteSettings, key)
    if row:
        row.value = value
    else:
        db.add(SiteSettings(key=key, value=value))


def _kv_delete(db: Session, key: str) -> bool:
    row = db.get(SiteSettings, key)
    if not row:
        return False
    db.delete(row)
    return True


# ── audit logging ──────────────────────────────────────────────────────────────

def _audit(request: Request, event: str, outcome: str, username: str | None = None) -> None:
    logger.warning(
        "auth_event",
        extra={
            "event": event,
            "outcome": outcome,
            "ip": _client_ip(request),
            "user_agent": (request.headers.get("user-agent") or "")[:200],
            "username": username,
        },
    )


# ── base64 / HMAC token helpers (unchanged crypto; payload schema extended) ────

def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _make_token(payload: dict[str, Any], secret: str) -> str:
    payload_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    encoded = _b64encode(payload_bytes)
    sig = hmac.new(secret.encode("utf-8"), encoded.encode("ascii"), hashlib.sha256)
    return f"{encoded}.{_b64encode(sig.digest())}"


def _decode_token(token: str | None, secret: str) -> dict[str, Any] | None:
    if not token or "." not in token:
        return None
    encoded, encoded_sig = token.split(".", 1)
    expected = hmac.new(secret.encode("utf-8"), encoded.encode("ascii"), hashlib.sha256)
    if not hmac.compare_digest(_b64encode(expected.digest()), encoded_sig):
        return None
    try:
        payload = json.loads(_b64decode(encoded))
    except (ValueError, json.JSONDecodeError):
        return None
    if int(payload.get("exp", 0)) < int(time.time()):
        return None
    return payload


def create_session_token(username: str, secret: str, ttl_seconds: int, epoch: int) -> str:
    return _make_token(
        {
            "sub": username,
            "iat": int(time.time()),
            "exp": int(time.time()) + ttl_seconds,
            "epoch": epoch,
        },
        secret,
    )


def verify_session_token(token: str | None, secret: str) -> dict[str, Any] | None:
    payload = _decode_token(token, secret)
    if not payload or payload.get("type") == "pending_2fa":
        return None
    return payload


def _create_pending_token(username: str, secret: str, jti: str) -> str:
    return _make_token(
        {
            "sub": username,
            "type": "pending_2fa",
            "jti": jti,
            "iat": int(time.time()),
            "exp": int(time.time()) + _PENDING_TTL,
        },
        secret,
    )


def _verify_pending_token(token: str | None, secret: str) -> dict[str, Any] | None:
    payload = _decode_token(token, secret)
    if not payload or payload.get("type") != "pending_2fa":
        return None
    return payload


# ── password helpers ───────────────────────────────────────────────────────────

def hash_password(password: str, iterations: int = 260_000) -> str:
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${_b64encode(salt)}${_b64encode(digest)}"


def verify_password(password: str, password_hash: str) -> bool:
    try:
        algorithm, iterations_raw, salt_raw, digest_raw = password_hash.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        salt = _b64decode(salt_raw)
        expected = _b64decode(digest_raw)
    except (ValueError, TypeError):
        return False
    actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(iterations_raw))
    return hmac.compare_digest(actual, expected)


def _get_password_hash(db: Session, settings: Settings) -> str:
    return _kv_get(db, _SETTING_PASSWORD_HASH) or settings.admin_password_hash


def _set_password_hash(db: Session, new_hash: str) -> None:
    """Stage the new hash. Caller must commit."""
    _kv_set(db, _SETTING_PASSWORD_HASH, new_hash)


# ── session epoch (cached) ─────────────────────────────────────────────────────

def _current_epoch(db: Session) -> int:
    cached = _epoch_cache.get("admin")
    if cached and time.monotonic() - cached[1] < _EPOCH_TTL_SECONDS:
        return cached[0]
    epoch = int(_kv_get(db, _SETTING_SESSION_EPOCH, "0") or "0")
    _epoch_cache["admin"] = (epoch, time.monotonic())
    return epoch


def _bump_epoch(db: Session) -> None:
    """Stage an epoch increment and invalidate the cache. Caller must commit."""
    current = int(_kv_get(db, _SETTING_SESSION_EPOCH, "0") or "0")
    _kv_set(db, _SETTING_SESSION_EPOCH, str(current + 1))
    _epoch_cache.pop("admin", None)


# ── TOTP replay-safe verifier ──────────────────────────────────────────────────

def _verify_totp(db: Session, secret: str, code: str) -> bool:
    """Verify a TOTP code with replay protection.

    Codes whose counter is ≤ the last-accepted counter are rejected. On success,
    advances the stored counter. Caller must commit.
    """
    try:
        totp = pyotp.TOTP(secret)
    except Exception:
        logger.critical("invalid_totp_secret_runtime")
        return False
    last = int(_kv_get(db, _SETTING_LAST_TOTP_COUNTER, "0") or "0")
    now_counter = int(time.time()) // 30
    for offset in (-1, 0, 1):
        candidate = now_counter + offset
        if candidate <= last:
            continue
        try:
            expected = totp.at(candidate * 30)
        except Exception:
            return False
        if hmac.compare_digest(expected, code):
            _kv_set(db, _SETTING_LAST_TOTP_COUNTER, str(candidate))
            return True
    return False


def smoke_test_totp_secret(secret: str | None) -> bool:
    """Quick base32 validation at startup or before use. Returns True if usable."""
    if not secret:
        return True  # 2FA disabled is a valid state
    try:
        pyotp.TOTP(secret).now()
        return True
    except Exception as exc:
        logger.warning(
            "invalid_totp_secret",
            extra={"event": "invalid_totp_secret", "error": str(exc)},
        )
        return False


# ── recovery codes (row-per-code, race-free deletes) ───────────────────────────

def _recovery_key(code: str) -> str:
    return _RECOVERY_CODE_PREFIX + hashlib.sha256(code.encode("utf-8")).hexdigest()[:16]


def _format_recovery_code(raw_hex: str) -> str:
    return f"{raw_hex[0:4]}-{raw_hex[4:8]}-{raw_hex[8:12]}-{raw_hex[12:16]}"


def _generate_recovery_codes(db: Session, count: int) -> list[str]:
    """Wipe existing recovery codes, generate `count` new ones, return plaintext.
    Caller must commit."""
    existing = (
        db.query(SiteSettings)
        .filter(SiteSettings.key.like(_RECOVERY_CODE_PREFIX + "%"))
        .all()
    )
    for row in existing:
        db.delete(row)
    plaintexts: list[str] = []
    for _ in range(count):
        raw = secrets.token_hex(8)  # 64 bits
        formatted = _format_recovery_code(raw)
        plaintexts.append(formatted)
        _kv_set(db, _recovery_key(formatted), hash_password(formatted))
    return plaintexts


def _consume_recovery_code(db: Session, code: str) -> bool:
    """Verify and delete a recovery code in one DB round-trip.

    Returns True only if the code matched AND the row was deleted by this
    transaction. Race-free under concurrent attempts because two transactions
    cannot both delete the same row — the loser sees rowcount == 0 on commit.
    Caller must commit.
    """
    row = db.get(SiteSettings, _recovery_key(code))
    if not row or not verify_password(code, row.value):
        return False
    db.delete(row)
    return True


def _count_recovery_codes(db: Session) -> int:
    return (
        db.query(SiteSettings)
        .filter(SiteSettings.key.like(_RECOVERY_CODE_PREFIX + "%"))
        .count()
    )


# ── pending JTI single-use (consumed-set with lazy TTL pruning) ────────────────

def _is_pending_jti_consumed(db: Session, jti: str) -> bool:
    return _kv_get(db, _CONSUMED_PENDING_PREFIX + jti) is not None


def _mark_pending_jti_consumed(db: Session, jti: str, exp_ts: int) -> None:
    """Mark a JTI as consumed. Lazily prunes any already-expired entries.
    Caller must commit."""
    _kv_set(db, _CONSUMED_PENDING_PREFIX + jti, str(exp_ts))
    now = int(time.time())
    expired_rows = (
        db.query(SiteSettings)
        .filter(SiteSettings.key.like(_CONSUMED_PENDING_PREFIX + "%"))
        .all()
    )
    for row in expired_rows:
        try:
            if int(row.value) < now:
                db.delete(row)
        except (ValueError, TypeError):
            db.delete(row)


# ── cookie helpers ─────────────────────────────────────────────────────────────

def _set_session_cookie(response: Response, token: str, settings: Settings) -> None:
    response.set_cookie(
        settings.session_cookie_name,
        token,
        path="/",
        httponly=True,
        samesite="lax",
        secure=settings.app_env == "production",
        max_age=settings.session_ttl_seconds,
    )


def _clear_session_cookie(response: Response, settings: Settings) -> None:
    response.delete_cookie(
        settings.session_cookie_name,
        path="/",
        httponly=True,
        samesite="lax",
        secure=settings.app_env == "production",
    )


def _set_pending_cookie(response: Response, token: str, settings: Settings) -> None:
    response.set_cookie(
        _PENDING_COOKIE,
        token,
        path="/",
        httponly=True,
        samesite="lax",
        secure=settings.app_env == "production",
        max_age=_PENDING_TTL,
    )


def _clear_pending_cookie(response: Response, settings: Settings) -> None:
    response.delete_cookie(
        _PENDING_COOKIE,
        path="/",
        httponly=True,
        samesite="lax",
        secure=settings.app_env == "production",
    )


# ── dependency ─────────────────────────────────────────────────────────────────

def current_admin(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    db: Annotated[Session, Depends(get_db)],
) -> str:
    token = request.cookies.get(settings.session_cookie_name)
    payload = verify_session_token(token, settings.session_secret)
    if not payload or payload.get("sub") != settings.admin_username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
        )
    if int(payload.get("epoch", 0)) != _current_epoch(db):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired. Please log in again.",
        )
    return settings.admin_username


# ── endpoints ──────────────────────────────────────────────────────────────────

@router.post("/login", response_model=LoginResponse)
@limiter.limit(_RATE_LIMIT_LOGIN)
def login(
    request: Request,
    payload: LoginRequest,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> LoginResponse:
    password_hash = _get_password_hash(db, settings)
    if payload.username != settings.admin_username or not verify_password(payload.password, password_hash):
        _audit(request, "login", "failure_invalid_credentials", payload.username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials.",
        )

    if settings.totp_secret:
        jti = str(uuid4())
        pending = _create_pending_token(settings.admin_username, settings.session_secret, jti)
        _set_pending_cookie(response, pending, settings)
        _audit(request, "login", "success_pending_2fa", settings.admin_username)
        return LoginResponse(requires_2fa=True)

    token = create_session_token(
        settings.admin_username,
        settings.session_secret,
        settings.session_ttl_seconds,
        _current_epoch(db),
    )
    _set_session_cookie(response, token, settings)
    _audit(request, "login", "success", settings.admin_username)
    return LoginResponse(username=settings.admin_username)


@router.post("/verify-2fa", response_model=AuthUser)
@limiter.limit(_RATE_LIMIT_VERIFY_2FA)
def verify_2fa(
    request: Request,
    payload: TotpVerifyRequest,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> AuthUser:
    pending = _verify_pending_token(request.cookies.get(_PENDING_COOKIE), settings.session_secret)
    if not pending:
        _audit(request, "verify_2fa", "failure_no_pending")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired. Please log in again.",
        )

    if not settings.totp_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA is not configured.",
        )

    if not smoke_test_totp_secret(settings.totp_secret):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="2FA temporarily unavailable. Contact admin.",
        )

    jti = pending.get("jti", "")
    if not jti or _is_pending_jti_consumed(db, jti):
        _audit(request, "verify_2fa", "failure_replay", pending.get("sub"))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired. Please log in again.",
        )

    if not _verify_totp(db, settings.totp_secret, payload.code):
        db.rollback()
        _audit(request, "verify_2fa", "failure_invalid_code", pending.get("sub"))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication code.",
        )

    _mark_pending_jti_consumed(db, jti, int(pending.get("exp", 0)))
    db.commit()

    _clear_pending_cookie(response, settings)
    token = create_session_token(
        pending["sub"],
        settings.session_secret,
        settings.session_ttl_seconds,
        _current_epoch(db),
    )
    _set_session_cookie(response, token, settings)
    _audit(request, "verify_2fa", "success", pending["sub"])
    return AuthUser(username=pending["sub"])


@router.post("/change-password")
@limiter.limit(_RATE_LIMIT_CHANGE_PASSWORD)
def change_password(
    request: Request,
    payload: ChangePasswordRequest,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
    username: Annotated[str, Depends(current_admin)],
) -> dict[str, bool]:
    current_hash = _get_password_hash(db, settings)
    if not verify_password(payload.current_password, current_hash):
        _audit(request, "password_change", "failure_invalid_current_password", username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Current password is incorrect.",
        )

    _set_password_hash(db, hash_password(payload.new_password))
    _bump_epoch(db)
    db.commit()

    # Rotate the caller's session so this device stays logged in while every
    # other session is invalidated by the epoch bump.
    new_token = create_session_token(
        username,
        settings.session_secret,
        settings.session_ttl_seconds,
        _current_epoch(db),
    )
    _set_session_cookie(response, new_token, settings)
    _audit(request, "password_change", "success", username)
    return {"ok": True}


@router.post("/reset-password", response_model=ResetPasswordResponse)
@limiter.limit(_RATE_LIMIT_RESET_PASSWORD)
def reset_password(
    request: Request,
    payload: ResetPasswordRequest,
    db: Annotated[Session, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> ResetPasswordResponse:
    code = payload.verification_code

    totp_ok = bool(settings.totp_secret) and _verify_totp(db, settings.totp_secret, code)
    if not totp_ok and not _consume_recovery_code(db, code):
        db.rollback()
        _audit(request, "password_reset", "failure_invalid_code")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid verification code.",
        )

    _set_password_hash(db, hash_password(payload.new_password))
    _bump_epoch(db)
    db.commit()
    _audit(request, "password_reset", "success")
    return ResetPasswordResponse(ok=True, recovery_codes_remaining=_count_recovery_codes(db))


@router.post("/logout")
def logout(
    response: Response,
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, bool]:
    _clear_session_cookie(response, settings)
    _clear_pending_cookie(response, settings)
    return {"ok": True}


@router.get("/me", response_model=AuthUser)
def me(username: Annotated[str, Depends(current_admin)]) -> AuthUser:
    return AuthUser(username=username)
