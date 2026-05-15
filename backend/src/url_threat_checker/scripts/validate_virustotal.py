import argparse
import os

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from url_threat_checker.config import get_settings
from url_threat_checker.database import Base
from url_threat_checker.features import extract_features
from url_threat_checker.virustotal import VirustotalClient

DEFAULT_URLS = [
    "https://www.google.com",
    "https://example.com",
]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate VirusTotal lookup without writing credentials to disk."
    )
    parser.add_argument("--url", action="append", dest="urls", default=[])
    args = parser.parse_args()

    if not os.environ.get("VIRUSTOTAL_API_KEY"):
        raise SystemExit("VIRUSTOTAL_API_KEY must be set in the process environment.")

    settings = get_settings()
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    urls = args.urls or DEFAULT_URLS
    with session_factory() as db:
        for url in urls:
            parsed, _features = extract_features(url)
            summary = VirustotalClient(settings=settings).lookup(
                db,
                parsed.normalized_url,
                include=True,
            )
            print(
                " | ".join(
                    [
                        parsed.defanged_url,
                        f"status={summary.status}",
                        f"malicious={summary.malicious}",
                        f"suspicious={summary.suspicious}",
                        f"harmless={summary.harmless}",
                        f"undetected={summary.undetected}",
                    ]
                )
            )


if __name__ == "__main__":
    main()
