"""
SentinelX Enterprise 2FA Module
Compliant with RFC 6238 (TOTP: Time-Based One-Time Password Algorithm).
Generates Base32 secrets, QR codes for authenticator apps (Google Authenticator,
Microsoft Authenticator, 1Password, Authy), and validates 6-digit tokens with drift tolerance.
"""

import base64
import io
import pyotp
import qrcode
from typing import Tuple, Optional


def generate_totp_secret() -> str:
    """Generate a high-entropy 32-character base32 secret."""
    return pyotp.random_base32()


def get_totp_uri(username: str, secret: str, issuer: str = "SentinelX-SOC") -> str:
    """Return standard otpauth URI for mobile authenticator enrollment."""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name=issuer)


def generate_qr_code_base64(totp_uri: str) -> str:
    """
    Generate an inline base64-encoded PNG data URI for immediate browser rendering.
    Can be placed directly in <img src="data:image/png;base64,...">.
    """
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=6,
        border=2,
    )
    qr.add_data(totp_uri)
    qr.make(fit=True)

    img = qr.make_image(fill_color="#0f172a", back_color="#ffffff")
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    b64_str = base64.b64encode(buffer.getvalue()).decode("utf-8")
    return f"data:image/png;base64,{b64_str}"


def verify_totp_token(secret: str, token: str, window: int = 1) -> bool:
    """
    Validate a 6-digit TOTP token against the user's secret.
    Allows +/- window intervals (30s default) to account for client-server time skew.
    """
    if not secret or not token:
        return False
    
    clean_token = str(token).strip().replace(" ", "")
    if len(clean_token) != 6 or not clean_token.isdigit():
        return False

    totp = pyotp.TOTP(secret)
    return bool(totp.verify(clean_token, valid_window=window))


def get_current_totp_token(secret: str) -> str:
    """
    Compute current live 6-digit TOTP token.
    Utilized for Recruiter Showcase Quick-Access mode and automated testing.
    """
    if not secret:
        return ""
    totp = pyotp.TOTP(secret)
    return totp.now()
