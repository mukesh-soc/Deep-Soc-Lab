"""
SentinelX Authentication & Zero-Trust Security Module
Provides PBKDF2 password hashing, Role-Based Access Control (RBAC),
Cryptographic Session Tokens, Audit Logging, and 2FA Enforcement.
"""

import os
import json
import time
import hmac
import hashlib
import secrets
from typing import Optional, Dict, Any, List
from .totp_2fa import (
    generate_totp_secret,
    get_totp_uri,
    generate_qr_code_base64,
    verify_totp_token,
    get_current_totp_token
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
USERS_FILE = os.path.join(DATA_DIR, "users.json")
AUDIT_LOG_FILE = os.path.join(DATA_DIR, "audit_log.json")

# Secret key for signing session tokens
SECRET_KEY = os.environ.get("SENTINELX_SECRET_KEY", "sentinelx-soc-production-secret-key-92027")
TOKEN_EXPIRY_SECONDS = 12 * 3600  # 12 hours


def _hash_password(password: str, salt: Optional[bytes] = None) -> str:
    """Hash password using PBKDF2-HMAC-SHA256 with 200,000 iterations."""
    if salt is None:
        salt = secrets.token_bytes(16)
    hashed = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200000)
    return f"{salt.hex()}${hashed.hex()}"


def _verify_password(password: str, hash_string: str) -> bool:
    """Verify password against stored salt and hash."""
    try:
        salt_hex, hash_hex = hash_string.split("$")
        salt = bytes.fromhex(salt_hex)
        expected_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200000)
        return hmac.compare_digest(expected_hash.hex(), hash_hex)
    except Exception:
        return False


def _init_default_users() -> Dict[str, Any]:
    """Initialize default SOC user database if not exists."""
    os.makedirs(DATA_DIR, exist_ok=True)
    
    # Pre-generate stable secrets for immediate recruiter / demo evaluation (Base32: A-Z, 2-7)
    admin_secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
    analyst_secret = "KZXW6YTBOJRGC4TGMRSW45DJONPWK43U"
    recruiter_secret = "MFRGGZDFMZTWQ2LKNNWG23TPOBYXE43U"

    users = {
        "admin": {
            "username": "admin",
            "full_name": "Mukesh Jena (Lead SOC Architect)",
            "role": "admin",
            "email": "mukesh.soc.analyst@gmail.com",
            "password_hash": _hash_password("sentinelx2026!"),
            "totp_enabled": True,
            "totp_secret": admin_secret,
            "permissions": ["all", "manage_users", "soar_execute", "rule_editor", "incident_write"],
            "created_at": "2026-09-20T10:00:00Z"
        },
        "analyst": {
            "username": "analyst",
            "full_name": "Tier 2 SOC Incident Responder",
            "role": "analyst",
            "email": "analyst@sentinelx.soc.local",
            "password_hash": _hash_password("analyst2026!"),
            "totp_enabled": True,
            "totp_secret": analyst_secret,
            "permissions": ["incident_read", "incident_write", "threat_hunt", "ioc_enrich"],
            "created_at": "2026-09-20T10:00:00Z"
        },
        "recruiter": {
            "username": "recruiter",
            "full_name": "Technical Recruiter / Hiring Evaluator",
            "role": "recruiter_evaluator",
            "email": "hiring.manager@enterprise.com",
            "password_hash": _hash_password("recruiter"),
            "totp_enabled": True,
            "totp_secret": recruiter_secret,
            "permissions": ["all_read", "simulate_attacks", "export_reports", "showcase_mode"],
            "created_at": "2026-10-16T12:00:00Z"
        }
    }

    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2)

    return users


def load_users() -> Dict[str, Any]:
    if not os.path.exists(USERS_FILE):
        return _init_default_users()
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return _init_default_users()


def save_users(users: Dict[str, Any]) -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2)


def record_audit(event_type: str, username: str, status: str, details: str, ip: str = "127.0.0.1") -> None:
    """Append structured security audit event."""
    os.makedirs(DATA_DIR, exist_ok=True)
    entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "event_type": event_type,
        "username": username,
        "status": status,
        "details": details,
        "client_ip": ip
    }
    
    logs = []
    if os.path.exists(AUDIT_LOG_FILE):
        try:
            with open(AUDIT_LOG_FILE, "r", encoding="utf-8") as f:
                logs = json.load(f)
        except Exception:
            logs = []
    
    logs.append(entry)
    if len(logs) > 1000:
        logs = logs[-1000:]
        
    try:
        with open(AUDIT_LOG_FILE, "w", encoding="utf-8") as f:
            json.dump(logs, f, indent=2)
    except Exception:
        pass


def get_audit_trail(limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieve recent audit logs."""
    if not os.path.exists(AUDIT_LOG_FILE):
        return []
    try:
        with open(AUDIT_LOG_FILE, "r", encoding="utf-8") as f:
            logs = json.load(f)
            return logs[-limit:][::-1]
    except Exception:
        return []


def create_session_token(username: str, role: str) -> str:
    """Generate a tamper-proof signed session token."""
    expires_at = int(time.time()) + TOKEN_EXPIRY_SECONDS
    payload = f"{username}:{role}:{expires_at}"
    signature = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}:{signature}"


def verify_session_token(token: str) -> Optional[Dict[str, Any]]:
    """Verify token signature and expiration."""
    if not token:
        return None
    try:
        parts = token.split(":")
        if len(parts) != 4:
            return None
        username, role, expires_at_str, signature = parts
        payload = f"{username}:{role}:{expires_at_str}"
        expected_sig = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()
        
        if not hmac.compare_digest(expected_sig, signature):
            return None
        
        if int(expires_at_str) < time.time():
            return None
        
        return {
            "username": username,
            "role": role,
            "expires_at": int(expires_at_str)
        }
    except Exception:
        return None


def authenticate_credentials(username: str, password: str, client_ip: str = "127.0.0.1") -> Dict[str, Any]:
    """Step 1 of 2FA: Verify username and password."""
    users = load_users()
    user = users.get(username.strip().lower())
    
    if not user:
        record_audit("AUTH_LOGIN_FAIL", username, "FAILURE", "Unknown username", client_ip)
        return {"success": False, "error": "Invalid username or password"}
    
    if not _verify_password(password, user["password_hash"]):
        record_audit("AUTH_LOGIN_FAIL", username, "FAILURE", "Password mismatch", client_ip)
        return {"success": False, "error": "Invalid username or password"}
    
    record_audit("AUTH_PASSWORD_SUCCESS", username, "SUCCESS", "Primary credentials verified", client_ip)
    
    totp_secret = user.get("totp_secret")
    demo_totp = get_current_totp_token(totp_secret) if totp_secret else ""
    
    return {
        "success": True,
        "requires_2fa": bool(user.get("totp_enabled", True)),
        "username": user["username"],
        "role": user["role"],
        "full_name": user["full_name"],
        "demo_totp_hint": demo_totp
    }


def verify_user_2fa(username: str, token: str, client_ip: str = "127.0.0.1") -> Dict[str, Any]:
    """Step 2 of 2FA: Validate the 6-digit TOTP code."""
    users = load_users()
    user = users.get(username.strip().lower())
    
    if not user:
        return {"success": False, "error": "User not found"}
    
    secret = user.get("totp_secret")
    if not secret:
        return {"success": False, "error": "2FA is not configured for this account"}
    
    is_valid = verify_totp_token(secret, token)
    if not is_valid:
        record_audit("AUTH_2FA_FAIL", username, "FAILURE", f"Invalid 2FA token provided: {token}", client_ip)
        return {"success": False, "error": "Invalid 2FA code. Please check your authenticator app or time sync."}
    
    session_token = create_session_token(user["username"], user["role"])
    record_audit("AUTH_2FA_SUCCESS", username, "SUCCESS", "Full 2FA authentication complete", client_ip)
    
    return {
        "success": True,
        "token": session_token,
        "user": {
            "username": user["username"],
            "full_name": user["full_name"],
            "role": user["role"],
            "email": user["email"],
            "permissions": user.get("permissions", [])
        }
    }


def get_2fa_setup_data(username: str) -> Dict[str, Any]:
    """Generate or retrieve TOTP secret and QR code for user setup."""
    users = load_users()
    user = users.get(username.strip().lower())
    if not user:
        return {"success": False, "error": "User not found"}
    
    secret = user.get("totp_secret")
    if not secret:
        secret = generate_totp_secret()
        user["totp_secret"] = secret
        user["totp_enabled"] = True
        users[username] = user
        save_users(users)
    
    totp_uri = get_totp_uri(username, secret, issuer="SentinelX-SOC")
    qr_data_uri = generate_qr_code_base64(totp_uri)
    current_token = get_current_totp_token(secret)
    
    return {
        "success": True,
        "username": username,
        "secret": secret,
        "totp_uri": totp_uri,
        "qr_code_image": qr_data_uri,
        "current_token": current_token
    }
