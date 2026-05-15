from url_threat_checker.database import SessionLocal, initialize_database
from url_threat_checker.scanner import create_scan

DEMO_URLS = [
    "https://www.google.com/search?q=university+project",
    "https://youtube.com/watch?v=abc123",
    "http://paypal-login-verify-account.example.ru/confirm?id=12345",
    "https://google.com.fake-domain.ru/login",
    "http://192.168.1.55/login/password-reset.exe",
    "https://bit.ly/security-update-login",
    "br-icloud.com.br",
    "https://github.com/openai/codex",
]


def seed_demo_scans(include_virustotal: bool = False) -> int:
    initialize_database()
    with SessionLocal() as db:
        for url in DEMO_URLS:
            create_scan(db, url, include_virustotal=include_virustotal)
    return len(DEMO_URLS)


def main() -> None:
    count = seed_demo_scans(include_virustotal=False)
    print(f"Seeded {count} demo scans.")


if __name__ == "__main__":
    main()
