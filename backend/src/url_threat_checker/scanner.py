"""Main URL scanning flow: extract features, predict, enrich, decide, and save."""

import hashlib
import json
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import desc, func, or_, select
from sqlalchemy.orm import Session

from url_threat_checker.auth import current_admin
from url_threat_checker.database import ScanReport, get_db
from url_threat_checker.features import UrlParsingError, extract_features
from url_threat_checker.model import get_predictor
from url_threat_checker.schemas import (
    ModelMetricsResponse,
    ScanCreateRequest,
    ScanReportResponse,
    ScanSummary,
    StatsResponse,
)
from url_threat_checker.verdict import MALICIOUS_LABELS, build_verdict
from url_threat_checker.virustotal import VirustotalClient

router = APIRouter(prefix="/api/v1", tags=["scans"], dependencies=[Depends(current_admin)])
COMPARABLE_VIRUSTOTAL_STATUSES = {"fetched", "cached"}


class ScanValidationError(ValueError):
    pass


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def create_scan(db: Session, url: str, include_virustotal: bool) -> ScanReport:
    try:
        parsed, features = extract_features(url)
    except UrlParsingError as exc:
        raise ScanValidationError(str(exc)) from exc

    prediction = get_predictor().predict(features)
    vt = VirustotalClient().lookup(db, parsed.normalized_url, include_virustotal)
    verdict = build_verdict(parsed, features, prediction, vt.malicious, vt.suspicious)

    report = ScanReport(
        source_type="manual",
        original_url=parsed.original_url,
        normalized_url=parsed.normalized_url,
        url_hash=sha256_text(parsed.normalized_url),
        defanged_url=parsed.defanged_url,
        domain=parsed.domain,
        registered_domain=parsed.registered_domain,
        final_verdict=verdict.final_verdict,
        risk_score=verdict.risk_score,
        local_prediction=prediction.label,
        local_confidence=round(prediction.confidence, 4),
        model_status=prediction.status,
        heuristic_flags_json=json.dumps(verdict.heuristic_flags),
        features_json=json.dumps(features.to_dict()),
        virustotal_status=vt.status,
        virustotal_malicious=vt.malicious,
        virustotal_suspicious=vt.suspicious,
        virustotal_harmless=vt.harmless,
        virustotal_undetected=vt.undetected,
        recommendation=verdict.recommendation,
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    return report


def scan_summary(report: ScanReport) -> ScanSummary:
    return ScanSummary(
        id=report.id,
        original_url=report.original_url,
        defanged_url=report.defanged_url,
        final_verdict=report.final_verdict,
        risk_score=report.risk_score,
        local_prediction=report.local_prediction,
        local_confidence=report.local_confidence,
        model_status=report.model_status,
        virustotal_status=report.virustotal_status,
        virustotal_malicious=report.virustotal_malicious,
        virustotal_suspicious=report.virustotal_suspicious,
        created_at=report.created_at,
        report_url=f"/reports/{report.id}",
    )


def model_signal_label(prediction: str) -> str:
    labels = {
        "benign": "benign",
        "defacement": "defacement-like",
        "malware": "malware-like",
        "phishing": "phishing-like",
        "unknown": "unknown",
    }
    return labels.get(prediction, prediction)


def verdict_explanation(report: ScanReport, flags: list[str]) -> list[str]:
    explanation: list[str] = []

    if report.final_verdict == "safe":
        if "registered_domain_whitelisted" in flags:
            explanation.append(
                f"The registered domain {report.registered_domain} is on the trusted whitelist."
            )
        else:
            explanation.append(
                "The model-only signal and heuristic rules did not find strong risk."
            )
    elif report.final_verdict == "dangerous":
        explanation.append(
            "The final verdict is dangerous because one or more high-risk signals were found."
        )
    elif report.final_verdict == "suspicious":
        explanation.append("The final verdict is suspicious because some risk signals were found.")
    else:
        explanation.append(
            "The system could not gather enough confidence for a clear safe or dangerous verdict."
        )

    if report.local_prediction != "unknown":
        explanation.append(
            "The model-only signal was "
            f"{model_signal_label(report.local_prediction)} with "
            f"{round(report.local_confidence * 100)}% confidence."
        )

    if "model_signal_disagrees_with_trusted_domain" in flags:
        explanation.append(
            "The model-only signal disagreed with the whitelist, so the hybrid logic kept the "
            "domain safe only because no external malicious evidence was found."
        )

    vt_total = (report.virustotal_malicious or 0) + (report.virustotal_suspicious or 0)
    if report.virustotal_status in {"fetched", "cached"}:
        if vt_total:
            explanation.append(
                f"VirusTotal reported {report.virustotal_malicious or 0} malicious and "
                f"{report.virustotal_suspicious or 0} suspicious detections."
            )
        else:
            explanation.append("VirusTotal did not report malicious or suspicious detections.")
    elif report.virustotal_status == "not_configured":
        explanation.append(
            "VirusTotal was not configured, so the verdict uses only local analysis."
        )
    elif report.virustotal_status == "skipped":
        explanation.append("VirusTotal lookup was disabled for this scan.")
    elif report.virustotal_status in {"failed", "rate_limited", "malformed_response"}:
        explanation.append(
            "VirusTotal was unavailable or unusable, so the local verdict still applies."
        )

    if flags:
        explanation.append("Triggered heuristic flags: " + ", ".join(flags) + ".")

    return explanation


def scan_report_response(report: ScanReport) -> ScanReportResponse:
    flags = json.loads(report.heuristic_flags_json)
    return ScanReportResponse(
        **scan_summary(report).model_dump(),
        normalized_url=report.normalized_url,
        domain=report.domain,
        registered_domain=report.registered_domain,
        features=json.loads(report.features_json),
        heuristic_flags=flags,
        verdict_explanation=verdict_explanation(report, flags),
        virustotal_harmless=report.virustotal_harmless,
        virustotal_undetected=report.virustotal_undetected,
        recommendation=report.recommendation,
    )


def list_scans(
    db: Session,
    limit: int = 50,
    verdict: str | None = None,
    query: str | None = None,
) -> list[ScanReport]:
    stmt = select(ScanReport).order_by(desc(ScanReport.created_at)).limit(limit)
    if verdict:
        stmt = stmt.where(ScanReport.final_verdict == verdict)
    if query:
        pattern = f"%{query.strip()}%"
        stmt = stmt.where(
            or_(
                ScanReport.original_url.ilike(pattern),
                ScanReport.defanged_url.ilike(pattern),
                ScanReport.domain.ilike(pattern),
                ScanReport.registered_domain.ilike(pattern),
            )
        )
    return list(db.scalars(stmt))


def local_model_signal(report: ScanReport) -> str | None:
    if report.local_prediction in MALICIOUS_LABELS:
        return "risky"
    if report.local_prediction == "benign":
        return "clean"
    return None


def virustotal_signal(report: ScanReport) -> str | None:
    if report.virustotal_status not in COMPARABLE_VIRUSTOTAL_STATUSES:
        return None

    detections = (report.virustotal_malicious or 0) + (report.virustotal_suspicious or 0)
    return "risky" if detections > 0 else "clean"


def comparison_stats(reports: list[ScanReport]) -> dict[str, int | float | None]:
    eligible_scans = 0
    agreement_count = 0
    model_risky_vt_clean = 0
    model_clean_vt_risky = 0
    vt_risky = 0
    vt_clean = 0

    for report in reports:
        local_signal = local_model_signal(report)
        vt_signal = virustotal_signal(report)
        if local_signal is None or vt_signal is None:
            continue

        eligible_scans += 1
        if vt_signal == "risky":
            vt_risky += 1
        else:
            vt_clean += 1

        if local_signal == vt_signal:
            agreement_count += 1
        elif local_signal == "risky" and vt_signal == "clean":
            model_risky_vt_clean += 1
        elif local_signal == "clean" and vt_signal == "risky":
            model_clean_vt_risky += 1

    disagreement_count = model_risky_vt_clean + model_clean_vt_risky
    agreement_rate = None
    if eligible_scans:
        agreement_rate = round(agreement_count / eligible_scans, 4)

    return {
        "eligible_scans": eligible_scans,
        "agreement_count": agreement_count,
        "disagreement_count": disagreement_count,
        "agreement_rate": agreement_rate,
        "model_risky_vt_clean": model_risky_vt_clean,
        "model_clean_vt_risky": model_clean_vt_risky,
        "vt_risky": vt_risky,
        "vt_clean": vt_clean,
        "excluded_scans": len(reports) - eligible_scans,
    }


def scan_stats(db: Session) -> dict:
    total = db.scalar(select(func.count()).select_from(ScanReport)) or 0
    rows = db.execute(
        select(ScanReport.final_verdict, func.count()).group_by(ScanReport.final_verdict)
    ).all()
    counts = {verdict: count for verdict, count in rows}
    failed_vt_statuses = {"failed", "rate_limited", "malformed_response"}
    virustotal_failures = (
        db.scalar(
            select(func.count())
            .select_from(ScanReport)
            .where(ScanReport.virustotal_status.in_(failed_vt_statuses))
        )
        or 0
    )
    return {
        "total": total,
        "safe": counts.get("safe", 0),
        "suspicious": counts.get("suspicious", 0),
        "dangerous": counts.get("dangerous", 0),
        "unknown": counts.get("unknown", 0),
        "virustotal_failures": virustotal_failures,
        "comparison": comparison_stats(list(db.scalars(select(ScanReport)))),
    }


@router.post("/scans", response_model=ScanSummary, status_code=status.HTTP_201_CREATED)
def create_scan_endpoint(
    payload: ScanCreateRequest,
    db: Annotated[Session, Depends(get_db)],
) -> ScanSummary:
    try:
        report = create_scan(db, str(payload.url), payload.include_virustotal)
    except ScanValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc
    return scan_summary(report)


@router.get("/scans", response_model=list[ScanSummary])
def scans_index(
    db: Annotated[Session, Depends(get_db)],
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    verdict: Annotated[str | None, Query(pattern="^(safe|suspicious|dangerous|unknown)$")] = None,
    q: Annotated[str | None, Query(min_length=1, max_length=200)] = None,
) -> list[ScanSummary]:
    return [scan_summary(report) for report in list_scans(db, limit, verdict, q)]


@router.get("/scans/{scan_id}", response_model=ScanReportResponse)
def scans_show(scan_id: str, db: Annotated[Session, Depends(get_db)]) -> ScanReportResponse:
    report = db.get(ScanReport, scan_id)
    if report is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")
    return scan_report_response(report)


@router.get("/stats", response_model=StatsResponse)
def stats(db: Annotated[Session, Depends(get_db)]) -> StatsResponse:
    return StatsResponse(**scan_stats(db))


@router.get("/model/metrics", response_model=ModelMetricsResponse)
def model_metrics() -> ModelMetricsResponse:
    predictor = get_predictor()
    return ModelMetricsResponse(status=predictor.status, card=predictor.card)
