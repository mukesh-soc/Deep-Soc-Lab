"""
SentinelX Enterprise SOC & SIEM Platform
Production Flask Web Application & REST API
Includes Zero-Trust RBAC, RFC 6238 TOTP 2FA, Real-time Ingestion,
MISP Threat Intelligence Correlation, Case Management, and Recruiter Showcase.
Author: Mukesh Jena (Lead SOC Analyst & Security Operations Engineer)
"""

import os
import sys
import json
import time

# Ensure SentinelX root directory is in python search path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)
from functools import wraps
from datetime import datetime, timezone
from flask import Flask, request, jsonify, render_template, send_from_directory, make_response

# Core modules
from core.auth import (
    authenticate_credentials,
    verify_user_2fa,
    get_2fa_setup_data,
    verify_session_token,
    record_audit,
    get_audit_trail,
    load_users
)
from core.totp_2fa import get_current_totp_token
from core.misp_enricher import MISPEnricher
from core.detection_engine import DetectionEngine
from core.siem_engine import SIEMEngine
from core.case_manager import CaseManager
from core.soar_engine import SOAREngine

app = Flask(__name__, static_folder="static", template_folder="templates")
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "sentinelx-soc-production-secret-key-92027")

# Initialize SIEM subsystems
enricher = MISPEnricher()
detection_engine = DetectionEngine()
siem = SIEMEngine(enricher, detection_engine)
case_manager = CaseManager()
soar = SOAREngine()


# ============================================================================
# Security Middleware & Headers
# ============================================================================
@app.after_request
def apply_security_headers(response):
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self' data: https:; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com data:; "
        "img-src 'self' data: https: blob:;"
    )
    return response


def get_current_user():
    auth_header = request.headers.get("Authorization", "")
    token = None
    if auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1].strip()
    elif request.cookies.get("sentinelx_token"):
        token = request.cookies.get("sentinelx_token")
    
    if not token:
        return None
    return verify_session_token(token)


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_current_user()
        if not user:
            return jsonify({"success": False, "error": "Unauthorized. Please authenticate with 2FA."}), 401
        return f(*args, **kwargs)
    return decorated_function


# ============================================================================
# Authentication & 2FA API
# ============================================================================
@app.route("/api/v1/auth/login", methods=["POST"])
def auth_login():
    """Step 1: Validate credentials and determine 2FA requirement."""
    data = request.get_json() or {}
    username = data.get("username", "")
    password = data.get("password", "")
    client_ip = request.remote_addr or "127.0.0.1"

    result = authenticate_credentials(username, password, client_ip)
    if not result.get("success"):
        return jsonify(result), 401
    return jsonify(result)


@app.route("/api/v1/auth/verify_2fa", methods=["POST"])
def auth_verify_2fa():
    """Step 2: Validate 6-digit TOTP token and issue session token."""
    data = request.get_json() or {}
    username = data.get("username", "")
    token = data.get("token", "")
    client_ip = request.remote_addr or "127.0.0.1"

    result = verify_user_2fa(username, token, client_ip)
    if not result.get("success"):
        return jsonify(result), 400

    resp = make_response(jsonify(result))
    resp.set_cookie("sentinelx_token", result["token"], httponly=True, samesite="Lax", max_age=43200)
    return resp


@app.route("/api/v1/auth/setup_2fa", methods=["GET"])
def auth_setup_2fa():
    """Retrieve QR code and secret for authenticator app enrollment."""
    username = request.args.get("username", "recruiter")
    setup_data = get_2fa_setup_data(username)
    return jsonify(setup_data)


@app.route("/api/v1/auth/recruiter_quick_code", methods=["GET"])
def auth_quick_recruiter_code():
    """
    Convenience endpoint for recruiters to fetch current TOTP code
    so they can experience 2FA without requiring their mobile phone.
    """
    users = load_users()
    user = users.get("recruiter", {})
    secret = user.get("totp_secret", "")
    current_token = get_current_totp_token(secret)
    return jsonify({
        "username": "recruiter",
        "current_totp": current_token,
        "seconds_remaining": 30 - (int(time.time()) % 30)
    })


@app.route("/api/v1/auth/me", methods=["GET"])
def auth_me():
    user = get_current_user()
    if not user:
        return jsonify({"authenticated": False})
    users = load_users()
    user_info = users.get(user["username"], {})
    return jsonify({
        "authenticated": True,
        "username": user["username"],
        "role": user["role"],
        "full_name": user_info.get("full_name", user["username"]),
        "permissions": user_info.get("permissions", [])
    })


@app.route("/api/v1/auth/audit_log", methods=["GET"])
def api_audit_log():
    limit = int(request.args.get("limit", 50))
    logs = get_audit_trail(limit)
    return jsonify({"success": True, "count": len(logs), "logs": logs})


# ============================================================================
# SIEM Telemetry & Detection API
# ============================================================================
@app.route("/api/v1/metrics", methods=["GET"])
def api_metrics():
    """Return live dashboard statistics."""
    metrics = siem.get_dashboard_metrics()
    metrics["active_incidents"] = len([i for i in case_manager.get_all() if i.get("status") != "Closed"])
    return jsonify(metrics)


@app.route("/api/v1/telemetry", methods=["GET"])
def api_telemetry():
    """Search and retrieve telemetry events."""
    q = request.args.get("q", "")
    limit = int(request.args.get("limit", 100))
    events = siem.search_telemetry(q, limit)
    return jsonify({"count": len(events), "events": events})


@app.route("/api/v1/telemetry/ingest", methods=["POST"])
def api_ingest():
    """Ingest raw log text (Zeek TSV, Wazuh JSON, Sysmon, Syslog)."""
    data = request.get_json() or {}
    raw_content = data.get("raw_content", "")
    log_format = data.get("format", "auto")

    result = siem.ingest_raw_log(raw_content, log_format)
    record_audit(
        "SIEM_LOG_INGEST",
        get_current_user()["username"] if get_current_user() else "anonymous",
        "SUCCESS" if result["success"] else "FAIL",
        f"Ingested {result.get('ingested_count', 0)} events",
        request.remote_addr or "127.0.0.1"
    )
    return jsonify(result)


@app.route("/api/v1/alerts", methods=["GET"])
def api_alerts():
    return jsonify({"count": len(siem.alerts), "alerts": siem.alerts[::-1]})


# ============================================================================
# Threat Intelligence & MISP API
# ============================================================================
@app.route("/api/v1/enrichment/lookup", methods=["GET"])
def api_lookup_ioc():
    """Enrich any indicator against MISP and local threat database."""
    ioc = request.args.get("ioc", "").strip()
    if not ioc:
        return jsonify({"error": "Missing 'ioc' query parameter"}), 400

    enrichment = enricher.enrich_ioc(ioc)
    
    # Check if indicator has related events in SIEM
    matched_events = siem.search_telemetry(f"ip:{ioc}", limit=10)
    enrichment["matched_events_count"] = len(matched_events)
    enrichment["matched_events"] = matched_events

    return jsonify(enrichment)


@app.route("/api/v1/enrichment/indicators", methods=["GET", "POST"])
def api_indicators():
    if request.method == "POST":
        data = request.get_json() or {}
        success = enricher.add_indicator(data)
        return jsonify({"success": success})
    return jsonify(enricher.list_all_indicators())


# ============================================================================
# Detection Rules API
# ============================================================================
@app.route("/api/v1/rules", methods=["GET", "POST"])
def api_rules():
    if request.method == "POST":
        data = request.get_json() or {}
        success = detection_engine.add_rule(data)
        return jsonify({"success": success})
    return jsonify(detection_engine.get_all_rules())


# ============================================================================
# Incident Case Management API
# ============================================================================
@app.route("/api/v1/incidents", methods=["GET", "POST"])
def api_incidents():
    if request.method == "POST":
        data = request.get_json() or {}
        new_inc = case_manager.create_incident(data)
        return jsonify(new_inc), 201
    return jsonify(case_manager.get_all())


@app.route("/api/v1/incidents/<incident_id>", methods=["GET"])
def api_incident_detail(incident_id):
    inc = case_manager.get_by_id(incident_id)
    if not inc:
        return jsonify({"error": "Incident not found"}), 404
    return jsonify(inc)


@app.route("/api/v1/incidents/<incident_id>/status", methods=["POST"])
def api_update_incident_status(incident_id):
    data = request.get_json() or {}
    status = data.get("status", "Open")
    note = data.get("note", "")
    user = get_current_user()
    author = user["username"] if user else "Mukesh Jena"

    success = case_manager.update_status(incident_id, status, note, author)
    return jsonify({"success": success})


@app.route("/api/v1/incidents/<incident_id>/notes", methods=["POST"])
def api_add_incident_note(incident_id):
    data = request.get_json() or {}
    text = data.get("text", "")
    user = get_current_user()
    author = user["username"] if user else "Mukesh Jena"

    success = case_manager.add_note(incident_id, author, text)
    return jsonify({"success": success})


# ============================================================================
# SOAR Automation API
# ============================================================================
@app.route("/api/v1/soar/execute", methods=["POST"])
def api_soar_execute():
    data = request.get_json() or {}
    playbook = data.get("playbook", "")
    target = data.get("target", "")
    user = get_current_user()
    operator = user["username"] if user else "Mukesh Jena (Lead SOC)"

    result = soar.execute_playbook(playbook, target, operator)
    record_audit("SOAR_PLAYBOOK_EXEC", operator, result["status"], f"{playbook} on {target}", request.remote_addr or "127.0.0.1")
    return jsonify(result)


@app.route("/api/v1/soar/history", methods=["GET"])
def api_soar_history():
    return jsonify(soar.get_execution_history())


# ============================================================================
# Recruiter Showcase & Attack Scenarios API
# ============================================================================
@app.route("/api/v1/recruiter/scenarios", methods=["GET"])
def api_recruiter_scenarios():
    scenarios = [
        {
            "id": "scenario_misp_zeek",
            "title": "Positive Zeek-to-MISP IOC Match (Controlled Test)",
            "description": "Replay Mukesh's verified lab test: HTTP traffic with controlled IOC 192.0.2.123 in Host header detected by Zeek and positively matched in MISP Event ID 1.",
            "tactic": "Command and Control",
            "technique": "T1071.001 - Web Protocols",
            "severity": "High",
            "indicators": ["192.0.2.123", "10.0.2.15", "10.0.2.4"],
            "sample_file": "data/sample_logs/zeek_http_sample.log"
        },
        {
            "id": "scenario_powershell_proc",
            "title": "Sysmon EID 1 & Wazuh Rule 92027 PowerShell Execution",
            "description": "Simulate PowerShell process creation on Windows 11 endpoint with Sysmon process telemetry and Wazuh alert correlation.",
            "tactic": "Execution",
            "technique": "T1059.001 - PowerShell",
            "severity": "Low",
            "indicators": ["powershell.exe", "WIN11\\mukesh-soc"],
            "sample_file": "data/sample_logs/wazuh_sysmon_sample.json"
        },
        {
            "id": "scenario_apt29_c2",
            "title": "APT29 Cobalt Strike Beaconing & Automated Containment",
            "description": "Simulate adversary C2 beaconing to 198.51.100.45:443 with encrypted payload, triggering high-severity alert and automated SOAR firewall isolation.",
            "tactic": "Command and Control",
            "technique": "T1573 - Encrypted Channel",
            "severity": "Critical",
            "indicators": ["198.51.100.45", "update-service-cdn.xyz"],
            "sample_file": "data/sample_logs/apt29_c2_sample.json"
        },
        {
            "id": "scenario_ransomware_vss",
            "title": "Ransomware Defense Evasion (Volume Shadow Destruction)",
            "description": "Simulate vssadmin shadow copy deletion, triggering critical defense alert and initiating instant host isolation.",
            "tactic": "Impact",
            "technique": "T1490 - Inhibit System Recovery",
            "severity": "Critical",
            "indicators": ["vssadmin.exe", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
            "sample_file": "data/sample_logs/ransomware_shadow_sample.json"
        }
    ]
    return jsonify(scenarios)


@app.route("/api/v1/recruiter/replay", methods=["POST"])
def api_recruiter_replay():
    """1-Click Replay of an attack scenario for instant recruiter evaluation."""
    data = request.get_json() or {}
    scenario_id = data.get("scenario_id", "scenario_misp_zeek")

    file_mapping = {
        "scenario_misp_zeek": os.path.join(BASE_DIR, "data", "sample_logs", "zeek_http_sample.log"),
        "scenario_powershell_proc": os.path.join(BASE_DIR, "data", "sample_logs", "wazuh_sysmon_sample.json"),
        "scenario_apt29_c2": os.path.join(BASE_DIR, "data", "sample_logs", "apt29_c2_sample.json"),
        "scenario_ransomware_vss": os.path.join(BASE_DIR, "data", "sample_logs", "ransomware_shadow_sample.json")
    }

    target_file = file_mapping.get(scenario_id)
    if not target_file or not os.path.exists(target_file):
        return jsonify({"error": "Scenario log file not found"}), 404

    with open(target_file, "r", encoding="utf-8") as f:
        content = f.read()

    result = siem.ingest_raw_log(content)
    return jsonify({
        "success": True,
        "scenario_id": scenario_id,
        "ingested_count": result.get("ingested_count", 0),
        "recent_alerts": siem.alerts[-3:][::-1]
    })


# ============================================================================
# Frontend & Report Views
# ============================================================================
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/investigation-report/<incident_id>")
def view_report(incident_id):
    inc = case_manager.get_by_id(incident_id)
    if not inc:
        return f"Incident {incident_id} not found", 404
    return render_template("report_template.html", incident=inc)


@app.route("/recruiter-brief")
def recruiter_brief():
    return render_template("recruiter_brief.html")


if __name__ == "__main__":
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", 5000))
    print(f"[*] Starting SentinelX SIEM Platform on http://{host}:{port}")
    app.run(host=host, port=port, debug=False)
