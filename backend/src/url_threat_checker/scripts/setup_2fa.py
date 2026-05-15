import sys

import pyotp
import qrcode


def main() -> None:
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name="admin", issuer_name="URL Threat Checker")

    print("\n=== URL Threat Checker — 2FA Setup ===\n")
    print("1. Add this to your backend/.env file:\n")
    print(f"   TOTP_SECRET={secret}\n")
    print("2. On Render, add environment variable:\n")
    print(f"   TOTP_SECRET = {secret}\n")
    print("3. Scan the QR code below with Google Authenticator:\n")

    qr = qrcode.QRCode(border=1)
    qr.add_data(uri)
    qr.print_ascii(invert=True, tty=sys.stdout.isatty())

    print(f"\n   Or manually enter this key in Google Authenticator:")
    print(f"   Secret: {secret}")
    print(f"\n4. Current code (verify setup): {totp.now()}\n")
    print("Once you've scanned and saved the code, set TOTP_SECRET in your environment.")
    print("The app will require Google Authenticator on every login.\n")
