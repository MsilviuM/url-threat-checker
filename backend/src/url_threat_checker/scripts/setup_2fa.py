"""Generate (or rotate) the TOTP secret + a fresh set of one-time recovery codes.

Run via: `uv run setup-2fa`.

This script wipes any existing recovery codes from `site_settings` and prints
the plaintext codes once — they cannot be retrieved afterwards.
"""

import sys

import pyotp
import qrcode

from url_threat_checker.auth import _count_recovery_codes, _generate_recovery_codes
from url_threat_checker.config import get_settings
from url_threat_checker.database import SessionLocal, initialize_database


def main() -> None:
    settings = get_settings()
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=settings.admin_username, issuer_name=settings.totp_issuer)

    print("\n=== URL Threat Checker — 2FA Setup ===\n")
    print("1. Add this to your backend/.env file (or your deployment env panel):\n")
    print(f"   TOTP_SECRET={secret}\n")
    print("2. Scan the QR code below with Google Authenticator (or any TOTP app):\n")

    qr = qrcode.QRCode(border=1)
    qr.add_data(uri)
    qr.print_ascii(invert=True, tty=sys.stdout.isatty())

    print("\n   Or manually enter this key in your authenticator app:")
    print(f"   Secret: {secret}")
    print(f"\n3. Current code (verify your authenticator displays the same): {totp.now()}\n")

    # Recovery codes
    initialize_database()
    db = SessionLocal()
    try:
        had_existing = _count_recovery_codes(db) > 0
        codes = _generate_recovery_codes(db, settings.recovery_codes_count)
        db.commit()
    finally:
        db.close()

    if had_existing:
        print("   ⚠  Previous recovery codes were wiped. Below are the new ones.\n")

    print("4. RECOVERY CODES — save these now. They will not be shown again.")
    print("   Use one in place of the TOTP code if you lose your authenticator.\n")
    for i, code in enumerate(codes, 1):
        print(f"   {i:2d}. {code}")
    print()
    print("Once you've stored the secret and recovery codes, set TOTP_SECRET in")
    print("your environment and restart the app. 2FA is required on every login.\n")
