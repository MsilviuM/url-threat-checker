"""Combine model output, rules, and VirusTotal counts into one final verdict."""

from dataclasses import dataclass

from url_threat_checker.features import ParsedUrl, UrlFeatureSet
from url_threat_checker.model import Prediction

MALICIOUS_LABELS = {"phishing", "malware", "defacement"}
TRUSTED_DOMAIN_ESCALATION_FLAGS = {
    "contains_at_symbol",
    "contains_punycode",
    "risky_file_extension",
    "many_subdomains",
    "many_query_parameters",
}


@dataclass(frozen=True)
class Verdict:
    final_verdict: str
    risk_score: int
    heuristic_flags: list[str]
    recommendation: str


def build_heuristic_flags(parsed: ParsedUrl, features: UrlFeatureSet) -> list[str]:
    flags: list[str] = []
    if features.is_whitelisted:
        flags.append("registered_domain_whitelisted")
    if features.has_ip_address:
        flags.append("domain_is_ip_address")
    if features.has_at_symbol:
        flags.append("contains_at_symbol")
    if features.has_punycode:
        flags.append("contains_punycode")
    if features.uses_url_shortener:
        flags.append("uses_url_shortener")
    if features.has_risky_extension:
        flags.append("risky_file_extension")
    if features.suspicious_keyword_count >= 2:
        flags.append("multiple_suspicious_keywords")
    if features.subdomain_count >= 3:
        flags.append("many_subdomains")
    if features.query_param_count >= 6:
        flags.append("many_query_parameters")
    if features.has_hyphen_in_domain and not features.is_whitelisted:
        flags.append("hyphenated_unknown_domain")
    if parsed.scheme == "http" and not parsed.scheme_missing:
        flags.append("plain_http")
    if parsed.scheme_missing:
        flags.append("scheme_missing")
    return flags


def build_verdict(
    parsed: ParsedUrl,
    features: UrlFeatureSet,
    prediction: Prediction,
    vt_malicious: int | None,
    vt_suspicious: int | None,
) -> Verdict:
    flags = build_heuristic_flags(parsed, features)
    score = 0
    trusted_domain = bool(features.is_whitelisted)
    vt_malicious_count = vt_malicious or 0
    vt_suspicious_count = vt_suspicious or 0

    if trusted_domain and prediction.label in MALICIOUS_LABELS:
        flags.append("model_signal_disagrees_with_trusted_domain")

    if prediction.label in MALICIOUS_LABELS:
        score += int(45 * max(prediction.confidence, 0.3))
    elif prediction.label == "benign":
        score -= int(15 * prediction.confidence)

    flag_weights = {
        "domain_is_ip_address": 25,
        "contains_at_symbol": 20,
        "contains_punycode": 15,
        "uses_url_shortener": 12,
        "risky_file_extension": 25,
        "multiple_suspicious_keywords": 15,
        "many_subdomains": 12,
        "many_query_parameters": 8,
        "hyphenated_unknown_domain": 8,
        "plain_http": 8,
        "scheme_missing": 3,
        "registered_domain_whitelisted": -40,
        "model_signal_disagrees_with_trusted_domain": 5,
    }
    for flag in flags:
        score += flag_weights.get(flag, 0)

    if vt_malicious is not None:
        if vt_malicious >= 5:
            score += 55
        elif vt_malicious >= 1:
            score += 25
    if vt_suspicious is not None and vt_suspicious >= 2:
        score += 10

    score = max(0, min(100, score))

    if trusted_domain:
        trusted_domain_flags = TRUSTED_DOMAIN_ESCALATION_FLAGS.intersection(flags)
        if vt_malicious_count >= 5:
            final = "dangerous"
            score = max(score, 80)
        elif vt_malicious_count >= 1 or vt_suspicious_count >= 2 or trusted_domain_flags:
            final = "suspicious"
            score = max(25, min(score, 59))
        else:
            final = "safe"
            score = min(score, 15)
    elif vt_malicious_count >= 5 or (
        prediction.label in MALICIOUS_LABELS and prediction.confidence >= 0.85
    ):
        final = "dangerous"
        score = max(score, 80)
    elif score >= 60:
        final = "dangerous"
    elif score >= 30:
        final = "suspicious"
    elif prediction.label == "unknown" and vt_malicious is None:
        final = "unknown"
    else:
        final = "safe"

    recommendation = {
        "safe": "No obvious risk was detected, but only open links from sources you trust.",
        "suspicious": "Be careful. Verify the sender before opening this link.",
        "dangerous": (
            "Do not open this link. Treat it as malicious unless a security review "
            "proves otherwise."
        ),
        "unknown": (
            "The system could not reach a confident verdict. Review manually before opening."
        ),
    }[final]

    return Verdict(
        final_verdict=final,
        risk_score=score,
        heuristic_flags=flags,
        recommendation=recommendation,
    )
