"""Telegram reply policy and text composition."""

import json

from url_threat_checker.database import ScanReport

RISKY_VERDICTS = {"suspicious", "dangerous"}


def should_send_reply(
    *,
    chat_type: str | None,
    reports: list[ScanReport],
    no_urls: bool,
    reply_mode: str,
) -> bool:
    if reply_mode == "silent":
        return False

    private_chat = chat_type == "private"
    if no_urls:
        return private_chat and reply_mode in {"always", "risky_and_private"}

    has_risky = any(report.final_verdict in RISKY_VERDICTS for report in reports)
    if reply_mode == "always":
        return True
    if reply_mode == "risky_only":
        return has_risky
    return private_chat or has_risky


def compose_reply(
    *,
    reports: list[ScanReport],
    invalid_urls: list[str],
    frontend_base_url: str,
    no_urls: bool = False,
) -> str:
    if no_urls:
        return "No link found. Send or forward a message containing a URL."

    base_url = frontend_base_url.rstrip("/")
    if len(reports) == 1 and not invalid_urls:
        report = reports[0]
        lines = [
            f"{_verdict_label(report.final_verdict)} - risk {report.risk_score}/100",
            report.recommendation,
        ]
        signals = _signals(report)
        if signals:
            lines.append(f"Signals: {signals}.")
        lines.append(f"Report: {base_url}/reports/{report.id}")
        return "\n".join(lines)

    lines = [f"Checked {len(reports)} link{'s' if len(reports) != 1 else ''}"]
    for index, report in enumerate(reports, start=1):
        lines.append(
            f"{index}. {_verdict_label(report.final_verdict)} - "
            f"{report.defanged_url} - risk {report.risk_score}/100"
        )
    if invalid_urls:
        lines.append(f"Skipped {len(invalid_urls)} invalid link candidate(s).")
    if reports:
        lines.append("Reports saved in dashboard.")
    return "\n".join(lines)[:3500]


def _verdict_label(verdict: str) -> str:
    return verdict[:1].upper() + verdict[1:]


def _signals(report: ScanReport) -> str:
    signals: list[str] = []
    if report.local_prediction not in {"unknown", "benign"}:
        signals.append(f"{report.local_prediction}-like model")
    try:
        flags = json.loads(report.heuristic_flags_json)
    except json.JSONDecodeError:
        flags = []
    signals.extend(flag.replace("_", " ") for flag in flags[:2])
    return ", ".join(signals[:3])
