from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator

VerdictValue = Literal["safe", "suspicious", "dangerous", "unknown"]
PredictionValue = Literal["benign", "phishing", "malware", "defacement", "unknown"]


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=512)


class LoginResponse(BaseModel):
    requires_2fa: bool = False
    username: str | None = None


class TotpVerifyRequest(BaseModel):
    code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=512)
    new_password: str = Field(min_length=8, max_length=512)


class ResetPasswordRequest(BaseModel):
    new_password: str = Field(min_length=8, max_length=512)
    verification_code: str = Field(min_length=6, max_length=64, pattern=r"^[\w\-]{6,64}$")

    @model_validator(mode="before")
    @classmethod
    def _accept_legacy_totp_code(cls, data: Any) -> Any:
        if isinstance(data, dict) and "totp_code" in data and "verification_code" not in data:
            data = {**data, "verification_code": data["totp_code"]}
        return data


class ResetPasswordResponse(BaseModel):
    ok: bool
    recovery_codes_remaining: int


class AuthUser(BaseModel):
    username: str


class ScanCreateRequest(BaseModel):
    url: str = Field(min_length=1, max_length=4096)
    include_virustotal: bool = True


class ScanSummary(BaseModel):
    id: str
    original_url: str
    defanged_url: str
    final_verdict: VerdictValue
    risk_score: int
    local_prediction: PredictionValue
    local_confidence: float
    model_status: str
    virustotal_status: str
    virustotal_malicious: int | None
    virustotal_suspicious: int | None
    created_at: datetime
    report_url: str


class ScanReportResponse(ScanSummary):
    normalized_url: str
    domain: str
    registered_domain: str
    features: dict[str, int | float]
    heuristic_flags: list[str]
    verdict_explanation: list[str]
    virustotal_harmless: int | None
    virustotal_undetected: int | None
    recommendation: str


class ComparisonStats(BaseModel):
    eligible_scans: int
    agreement_count: int
    disagreement_count: int
    agreement_rate: float | None
    model_risky_vt_clean: int
    model_clean_vt_risky: int
    vt_risky: int
    vt_clean: int
    excluded_scans: int


class StatsResponse(BaseModel):
    total: int
    safe: int
    suspicious: int
    dangerous: int
    unknown: int
    virustotal_failures: int
    comparison: ComparisonStats


class ModelMetricsResponse(BaseModel):
    status: str
    card: dict


class ErrorResponse(BaseModel):
    detail: str
