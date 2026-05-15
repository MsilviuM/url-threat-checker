import base64
import hashlib
import hmac
import json
import os
import time
from typing import Annotated, Any

import pyotp
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from url_threat_checker.config import Settings, get_settings
from url_threat_checker.database import SiteSettings, get_db
from url_threat_checker.schemas import (
    AuthUser,
    LoginRequest,
    LoginResponse,
    ResetPasswordRequest,
    TotpVerifyRequest,
)

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])

_PENDING_COOKIE = "utc_pending"
_PENDING_TTL = 300  # 5 minutes
_SETTING_PASSWORD_HASH = "admin_password_hash"


# ── token helpers ──────────────────────────────────────────────────────────────

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


def create_session_token(username: str, secret: str, ttl_seconds: int) -> str:
    return _make_token(
        {"sub": username, "iat": int(time.time()), "exp": int(time.time()) + ttl_seconds},
        secret,
    )


def verify_session_token(token: str | None, secret: str) -> dict[str, Any] | None:
    payload = _decode_token(token, secret)
    if not payload or payload.get("type") == "pending_2fa":
        return None
    return payload


def _create_pending_token(username: str, secret: str) -> str:
    return _make_token(
        {
            "sub": username,
            "type": "pending_2fa",
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
    row = db.get(SiteSettings, _SETTING_PASSWORD_HASH)
    return row.value if row else settings.admin_password_hash


def _set_password_hash(db: Session, new_hash: str) -> None:
    row = db.get(SiteSettings, _SETTING_PASSWORD_HASH)
    if row:
        row.value = new_hash
    else:
        db.add(SiteSettings(key=_SETTING_PASSWORD_HASH, value=new_hash))
    db.commit()


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


# ── dependency ─────────────────────────────────────────────────────────────────

def current_admin(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
) -> str:
    token = request.cookies.get(settings.session_cookie_name)
    payload = verify_session_token(token, settings.session_secret)
    if not payload or payload.get("sub") != settings.admin_username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required.")
    return settings.admin_username


# ── endpoints ──────────────────────────────────────────────────────────────────

@router.post("/login", response_model=LoginResponse)
def login(
    payload: LoginRequest,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> LoginResponse:
    password_hash = _get_password_hash(db, settings)
    if payload.username != settings.admin_username or not verify_password(payload.password, password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials.")

    if settings.totp_secret:
        pending = _create_pending_token(settings.admin_username, settings.session_secret)
        response.set_cookie(
            _PENDING_COOKIE,
            pending,
            path="/",
            httponly=True,
            samesite="lax",
            secure=settings.app_env == "production",
            max_age=_PENDING_TTL,
        )
        return LoginResponse(requires_2fa=True)

    token = create_session_token(settings.admin_username, settings.session_secret, settings.session_ttl_seconds)
    _set_session_cookie(response, token, settings)
    return LoginResponse(username=settings.admin_username)


@router.post("/verify-2fa", response_model=AuthUser)
def verify_2fa(
    payload: TotpVerifyRequest,
    request: Request,
    response: Response,
    settings: Annotated[Settings, Depends(get_settings)],
) -> AuthUser:
    pending = _verify_pending_token(request.cookies.get(_PENDING_COOKIE), settings.session_secret)
    if not pending:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired. Please log in again.")

    if not settings.totp_secret:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="2FA is not configured.")

    if not pyotp.TOTP(settings.totp_secret).verify(payload.code, valid_window=1):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication code.")

    response.delete_cookie(_PENDING_COOKIE, path="/", httponly=True, samesite="lax",
                           secure=settings.app_env == "production")
    token = create_session_token(pending["sub"], settings.session_secret, settings.session_ttl_seconds)
    _set_session_cookie(response, token, settings)
    return AuthUser(username=pending["sub"])


@router.post("/reset-password")
def reset_password(
    payload: ResetPasswordRequest,
    db: Annotated[Session, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, bool]:
    if not settings.totp_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password reset requires 2FA to be configured. Set up Google Authenticator first.",
        )
    if not pyotp.TOTP(settings.totp_secret).verify(payload.totp_code, valid_window=1):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication code.")

    _set_password_hash(db, hash_password(payload.new_password))
    return {"ok": True}


@router.post("/logout")
def logout(
    response: Response,
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, bool]:
    _clear_session_cookie(response, settings)
    return {"ok": True}


@router.get("/me", response_model=AuthUser)
def me(username: Annotated[str, Depends(current_admin)]) -> AuthUser:
    return AuthUser(username=username)
