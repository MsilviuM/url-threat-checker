import argparse
import json
from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from url_threat_checker.database import (
    IntegrationEvent,
    ScanReport,
    SessionLocal,
    VirustotalCache,
    reset_database_schema,
)
from url_threat_checker.features import parse_url
from url_threat_checker.scanner import create_scan
from url_threat_checker.scripts.seed_demo import DEMO_URLS
from url_threat_checker.virustotal import sha256_text

DEMO_VIRUSTOTAL_STATS = {
    "https://www.google.com/search?q=university+project": {
        "malicious": 0,
        "suspicious": 0,
        "harmless": 90,
        "undetected": 5,
    },
    "https://youtube.com/watch?v=abc123": {
        "malicious": 0,
        "suspicious": 0,
        "harmless": 85,
        "undetected": 4,
    },
    "http://paypal-login-verify-account.example.ru/confirm?id=12345": {
        "malicious": 8,
        "suspicious": 2,
        "harmless": 4,
        "undetected": 12,
    },
    "https://google.com.fake-domain.ru/login": {
        "malicious": 3,
        "suspicious": 1,
        "harmless": 10,
        "undetected": 15,
    },
    "http://192.168.1.55/login/password-reset.exe": {
        "malicious": 10,
        "suspicious": 1,
        "harmless": 2,
        "undetected": 8,
    },
    "https://bit.ly/security-update-login": {
        "malicious": 2,
        "suspicious": 2,
        "harmless": 9,
        "undetected": 17,
    },
    "br-icloud.com.br": {
        "malicious": 6,
        "suspicious": 1,
        "harmless": 5,
        "undetected": 13,
    },
    "https://github.com/openai/codex": {
        "malicious": 0,
        "suspicious": 0,
        "harmless": 80,
        "undetected": 7,
    },
}


def seed_demo_virustotal_cache(db: Session) -> None:
    expires_at = datetime.now(UTC) + timedelta(days=7)
    for url, stats in DEMO_VIRUSTOTAL_STATS.items():
        normalized_url = parse_url(url).normalized_url
        db.add(
            VirustotalCache(
                url_hash=sha256_text(normalized_url),
                normalized_url=normalized_url,
                status="fetched",
                malicious=stats["malicious"],
                suspicious=stats["suspicious"],
                harmless=stats["harmless"],
                undetected=stats["undetected"],
                raw_summary_json=json.dumps(stats),
                expires_at=expires_at,
            )
        )
    db.commit()


def reset_demo_session(db: Session, with_comparison: bool = False) -> int:
    db.query(IntegrationEvent).delete()
    db.query(ScanReport).delete()
    db.query(VirustotalCache).delete()
    db.commit()

    if with_comparison:
        seed_demo_virustotal_cache(db)

    for url in DEMO_URLS:
        create_scan(db, url, include_virustotal=with_comparison)
    return len(DEMO_URLS)


def reset_demo_data(with_comparison: bool = False) -> int:
    reset_database_schema()
    with SessionLocal() as db:
        return reset_demo_session(db, with_comparison=with_comparison)


def main() -> None:
    parser = argparse.ArgumentParser(description="Reset local demo data.")
    parser.add_argument(
        "--with-comparison",
        action="store_true",
        help="Seed deterministic cached VirusTotal results for the comparison metric.",
    )
    args = parser.parse_args()

    count = reset_demo_data(with_comparison=args.with_comparison)
    print(f"Reset local demo data and seeded {count} scan reports.")


if __name__ == "__main__":
    main()
