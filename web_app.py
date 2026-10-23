from flask import Flask, request, jsonify, send_from_directory
from contextlib import closing
import ipaddress
import logging
import os
from datetime import datetime
import sqlite3
import time
import requests
import os
import hmac
import re

from flask import request, jsonify
from dotenv import load_dotenv
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

load_dotenv()

AGENT_API_TOKEN = os.getenv("AGENT_API_TOKEN")

if not AGENT_API_TOKEN:
    raise RuntimeError("AGENT_API_TOKEN is not configured")

try:
    from flask_socketio import SocketIO
except ModuleNotFoundError:
    SocketIO = None

try:
    import nmap
except ModuleNotFoundError:
    nmap = None


class _SocketShim:
    def emit(self, event, payload=None):
        payload_keys = list(payload) if isinstance(payload, dict) else []
        logging.debug(
            "Socket.IO is disabled; skipping %s event with payload keys %s",
            event,
            payload_keys
        )
        return None

    def on(self, event):
        logging.debug("Socket.IO is disabled; ignoring %s handler registration", event)

        def decorator(func):
            return func

        return decorator

    def run(self, *args, **kwargs):
        kwargs.pop("allow_unsafe_werkzeug", None)
        application, *run_args = args
        return application.run(*run_args, **kwargs)


# ============================================================
# INIT
# ============================================================

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024  # 16 KB

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per hour"],
    storage_uri="memory://",
)

socketio = SocketIO(
    app,
    async_mode="threading"
) if SocketIO is not None else _SocketShim()


# ============================================================
# CONFIG
# ============================================================

SERVER_PORT = 5001

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DB_NAME = os.path.join(BASE_DIR, "siem_logs.db")

SERVER_HOST = os.environ.get("SECURESCAN_HOST", "127.0.0.1")

ALERT_COOLDOWN = 5

WINDOW = 10

SEVERITY_RANK = {
    "LOW": 0,
    "MEDIUM": 1,
    "HIGH": 2,
    "CRITICAL": 3
}


# ============================================================
# DATABASE
# ============================================================

def init_db():
    with closing(sqlite3.connect(DB_NAME)) as conn:
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    event TEXT,
                    username TEXT,
                    ip TEXT
                )
            """)


def insert_log(timestamp, event, username, ip):
    with closing(sqlite3.connect(DB_NAME)) as conn:
        with conn:
            cursor = conn.execute(
                """
                INSERT INTO logs (
                    timestamp,
                    event,
                    username,
                    ip
                )
                VALUES (?, ?, ?, ?)
                """,
                (timestamp, event, username, ip)
            )
            log_id = cursor.lastrowid

    return log_id


init_db()


# ============================================================
# STATE
# ============================================================

correlation = {}

last_alert_time = {}


# ============================================================
# GEO
# ============================================================

def get_geo(ip):
    try:
        address = ipaddress.ip_address(ip)
    except (TypeError, ValueError):
        return "UNKNOWN"

    if address.is_loopback:
        return "LOCALHOST"

    if address.version == 4:
        private_networks = (
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16")
        )
        if any(address in network for network in private_networks):
            return "INTERNAL" if address in private_networks[2] else "PRIVATE"
    elif address in ipaddress.ip_network("fc00::/7"):
        return "PRIVATE"

    return "PUBLIC" if address.is_global else "NON-PUBLIC"


# ============================================================
# THREAT INTELLIGENCE
# ============================================================

def get_intel(ip):
    api_key = os.environ.get("ABUSEIPDB_API_KEY", "").strip()
    if not api_key:
        return "INTEL NOT CONFIGURED"

    try:
        address = ipaddress.ip_address(ip)
    except (TypeError, ValueError):
        return "INTEL UNAVAILABLE"

    if address.is_private or address.is_loopback or address.is_link_local:
        return "INTERNAL NETWORK"
    if not address.is_global:
        return "INTEL UNAVAILABLE"

    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={
                "Key": api_key,
                "Accept": "application/json"
            },
            params={
                "ipAddress": str(address),
                "maxAgeInDays": 90
            },
            timeout=5
        )
        response.raise_for_status()
        payload = response.json()
        data = payload.get("data") if isinstance(payload, dict) else None
        abuse_score = data.get("abuseConfidenceScore") if isinstance(data, dict) else None
        if not isinstance(abuse_score, (int, float)):
            logging.warning("AbuseIPDB returned an unexpected response for %s", address)
            return "INTEL ERROR"

        if abuse_score >= 80:
            return f"⚠ MALICIOUS ({abuse_score}% abuse)"
        if abuse_score >= 40:
            return f"⚠ SUSPICIOUS ({abuse_score}% abuse)"
        return f"✅ CLEAN ({abuse_score}% abuse)"
    except (requests.RequestException, ValueError):
        logging.exception("AbuseIPDB lookup failed for %s", address)
        return "INTEL ERROR"


# ============================================================
# MITRE ATT&CK
# ============================================================

def get_mitre(event):

    mapping = {

        "LOGIN_FAIL":
            "T1110 - Brute Force",

        "LOGIN_SUCCESS":
            "T1078 - Valid Accounts",

        "PORT_SCAN":
            "T1046 - Network Service Scanning",

        "SUSPICIOUS":
            "T1059 - Command and Scripting Interpreter",

        "RANSOMWARE":
            "T1486 - Data Encrypted for Impact",

        "YARA_MATCH":
            "T1204 - User Execution",

        "MALWARE":
            "T1204 - User Execution",

        "CRITICAL":
            "T1486 - Data Encrypted for Impact",

        "FILE_CREATED":
            "T1105 - Ingress Tool Transfer"
    }

    return mapping.get(
        event,
        "UNKNOWN"
    )


# ============================================================
# ALERT ENGINE
# ============================================================

def create_alert(message, severity, ip, event):

    now = time.time()

    if ip in last_alert_time:

        if now - last_alert_time[ip] < ALERT_COOLDOWN:
            return

    last_alert_time[ip] = now

    alert = {

        "time":
            datetime.now().strftime("%H:%M:%S"),

        "msg":
            message,

        "severity":
            severity,

        "ip":
            ip,

        "geo":
            get_geo(ip),

        "intel":
            get_intel(ip),

        "mitre":
            get_mitre(event)
    }

    print(
        f"[ALERT] {severity} | {message} | {ip}"
    )

    try:
        socketio.emit("alert", alert)
    except Exception:
        logging.exception("Unable to emit alert for %s", ip)


# ============================================================
# TRACKING
# ============================================================

def update_ip_activity(ip, event):

    now = time.time()

    if ip not in correlation:

        correlation[ip] = {

            "fail": [],

            "scan": [],

            "susp": []
        }

    if event == "LOGIN_FAIL":

        correlation[ip]["fail"].append(now)

    elif event == "PORT_SCAN":

        correlation[ip]["scan"].append(now)

    elif event == "SUSPICIOUS":

        correlation[ip]["susp"].append(now)

    # Cleanup old events

    for key in correlation[ip]:

        correlation[ip][key] = [

            timestamp

            for timestamp in correlation[ip][key]

            if now - timestamp <= WINDOW
        ]


# ============================================================
# DETECTION ENGINE
# ============================================================

def detect_threats(ip):

    data = correlation.get(ip)

    if not data:
        return

    fail = len(data["fail"])

    scan = len(data["scan"])

    susp = len(data["susp"])


    # --------------------------------------------------------
    # BRUTE FORCE
    # --------------------------------------------------------

    if fail >= 5:

        create_alert(

            f"BRUTE FORCE DETECTED: {fail} failed logins in {WINDOW} seconds",

            "HIGH",

            ip,

            "LOGIN_FAIL"
        )


    # --------------------------------------------------------
    # RECON + EXPLOIT
    # --------------------------------------------------------

    if scan >= 2 and susp >= 1:

        create_alert(

            "RECON + EXPLOIT DETECTED",

            "CRITICAL",

            ip,

            "PORT_SCAN"
        )


    # --------------------------------------------------------
    # FULL ATTACK CHAIN
    # --------------------------------------------------------

    if fail >= 3 and scan >= 1 and susp >= 1:

        create_alert(

            "FULL ATTACK CHAIN DETECTED",

            "CRITICAL",

            ip,

            "SUSPICIOUS"
        )


# ============================================================
# CVE DATABASE
# ============================================================

CVE_DB = {

    "ssh": {

        "cve":
            "CVE-2024-6387",

        "severity":
            "CRITICAL"
    },

    "ftp": {

        "cve":
            "CVE-2011-2523",

        "severity":
            "HIGH"
    },

    "mysql": {

        "cve":
            "CVE-2012-2122",

        "severity":
            "HIGH"
    },

    "rdp": {

        "cve":
            "CVE-2019-0708",

        "severity":
            "CRITICAL"
    }
}


# ============================================================
# PROCESS LOG
# ============================================================

def process_log(log):
    # --------------------------------------------------------
    # Validate type
    # --------------------------------------------------------

    if not isinstance(log, str):
        logging.warning("Rejected log with non-string payload")
        return False

    # --------------------------------------------------------
    # Parse log
    # Expected:
    # EVENT|USERNAME|IP
    # --------------------------------------------------------

    parts = log.split("|")
    if len(parts) != 3:
        logging.warning("Rejected log with invalid field count")
        return False

    event = parts[0].strip()
    user = parts[1].strip()
    ip = parts[2].strip()

    if not event or not user or not ip:
        logging.warning("Rejected log with an empty event, username, or IP field")
        return False

    # --------------------------------------------------------
    # Timestamp
    # --------------------------------------------------------

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )


    # --------------------------------------------------------
    # Save to database
    # --------------------------------------------------------

    try:

        log_id = insert_log(

            timestamp,

            event,

            user,

            ip
        )

    except sqlite3.Error:
        logging.exception("Unable to store incoming log")
        return False

    # --------------------------------------------------------
    # Send live log to dashboard
    # --------------------------------------------------------

    try:
        socketio.emit("log", {
            "id": log_id,
            "timestamp": timestamp,
            "event": event,
            "username": user,
            "ip": ip
        })
    except Exception:
        logging.exception("Unable to emit log %s; it remains available through polling", log_id)


    # --------------------------------------------------------
    # Correlation
    # --------------------------------------------------------

    update_ip_activity(

        ip,

        event
    )


    detect_threats(

        ip
    )


    # --------------------------------------------------------
    # Instant alerts
    # --------------------------------------------------------

    if event == "SUSPICIOUS":

        create_alert(

            "SUSPICIOUS ACTIVITY DETECTED",

            "HIGH",

            ip,

            event
        )

    elif event == "RANSOMWARE":

        create_alert(

            "RANSOMWARE DETECTED",

            "CRITICAL",

            ip,

            event
        )

    elif event == "YARA_MATCH":

        create_alert(

            "YARA MALWARE MATCH DETECTED",

            "CRITICAL",

            ip,

            event
        )

    elif event == "MALWARE":

        create_alert(

            "MALWARE DETECTED",

            "CRITICAL",

            ip,

            event
        )

    elif event == "CRITICAL":

        create_alert(

            "CRITICAL SECURITY EVENT DETECTED",

            "CRITICAL",

            ip,

            event
        )


    return True


# ============================================================
# INGEST API
# ============================================================

@app.route(
    "/ingest",
    methods=["POST"]
)
def ingest():
    supplied_token = request.headers.get("X-Agent-Token", "")

    if not hmac.compare_digest(
        supplied_token,
        AGENT_API_TOKEN
    ):
        return jsonify({"error": "Unauthorized"}), 401

    if not request.is_json:
        return jsonify({"error": "JSON required"}), 415

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON body"}), 400

    log = data.get("log")

    if not isinstance(log, str) or not log.strip():
        return jsonify({"error": "Invalid log"}), 400

    if len(log) > 4000:
        return jsonify({"error": "Log too long"}), 413

    if not re.fullmatch(r"[A-Z_]{2,40}\|[^|\r\n]{1,100}\|[^|\r\n]{1,100}", log):
        return jsonify({"error": "Invalid log format"}), 400

    try:
        if not process_log(log):
            return jsonify({"error": "Invalid log"}), 400

        return jsonify({"status": "accepted"}), 202

    except Exception:
        logging.exception("Unexpected error while processing ingest request")
        return jsonify({"error": "Unable to process ingest request"}), 500


# ============================================================
# GET EXISTING LOGS
# ============================================================

@app.route("/logs")
def get_logs():
    try:
        after_id = request.args.get("after_id", default=0, type=int)

        with closing(sqlite3.connect(DB_NAME)) as conn:
            if after_id > 0:
                rows = conn.execute(
                    """
                    SELECT id, timestamp, event, username, ip
                    FROM logs
                    WHERE id > ?
                    ORDER BY id ASC
                    LIMIT 100
                    """,
                    (after_id,)
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT id, timestamp, event, username, ip
                    FROM logs
                    ORDER BY id DESC
                    LIMIT 100
                    """
                ).fetchall()

        return jsonify([
            {
                "id": row[0],
                "timestamp": row[1],
                "event": row[2],
                "username": row[3],
                "ip": row[4]
            }
            for row in rows
        ])

    except sqlite3.Error:
        logging.exception("Unable to retrieve logs")
        return jsonify({"error": "Unable to retrieve logs"}), 500


@app.route("/logs/latest-id")
def latest_log_id():
    try:
        with closing(sqlite3.connect(DB_NAME)) as conn:
            latest_id = conn.execute(
                "SELECT COALESCE(MAX(id), 0) FROM logs"
            ).fetchone()[0]
        return jsonify({"latest_id": latest_id})
    except sqlite3.Error:
        logging.exception("Unable to retrieve latest log ID")
        return jsonify({"error": "Unable to retrieve latest log ID"}), 500


# ============================================================
# IP INFO
# ============================================================

@app.route("/ip/<ip>")
def ip_info(ip):

    data = correlation.get(

        ip,

        {

            "fail": [],

            "scan": [],

            "susp": []
        }
    )

    return jsonify({

        "ip":
            ip,

        "fail_count":
            len(data["fail"]),

        "scan_count":
            len(data["scan"]),

        "suspicious_count":
            len(data["susp"])
    })


# ============================================================
# VULNERABILITY SCANNER
# ============================================================

@app.route(
    "/scan",
    methods=["POST"]
)
def scan_target():
    try:
        data = request.get_json(
            silent=True
        )

        if not isinstance(data, dict) or "target" not in data:
            return jsonify({"error": "No target provided"}), 400

        target = data["target"]
        if not isinstance(target, str):
            return jsonify({"error": "Target must be a string"}), 400

        target = target.strip()
        if not target:
            return jsonify({"error": "Empty target"}), 400

        if nmap is None:
            return jsonify({"error": "nmap dependency is not installed"}), 503

        print(
            f"[SCAN] Starting scan on {target}"
        )


        scanner = nmap.PortScanner()


        scanner.scan(

            target,

            arguments="-sV -F"

        )


        results = []
        risk = "UNASSESSED"
        potential_severity = "LOW"


        # ----------------------------------------------------
        # Process discovered hosts
        # ----------------------------------------------------

        for host in scanner.all_hosts():

            for proto in scanner[host].all_protocols():

                ports = scanner[
                    host
                ][
                    proto
                ].keys()


                for port in ports:

                    service_data = scanner[
                        host
                    ][
                        proto
                    ][
                        port
                    ]

                    if not isinstance(service_data, dict):
                        logging.warning("Ignoring malformed scanner result for %s:%s", host, port)
                        continue

                    service = str(service_data.get("name") or "unknown")
                    product = str(service_data.get("product") or "Unknown")
                    version = str(service_data.get("version") or "Unknown")
                    state = str(service_data.get("state") or "unknown")
                    service_lower = service.lower()
                    cve_info = CVE_DB.get(service_lower)
                    if cve_info:
                        risk = "REVIEW"
                        severity = cve_info["severity"]
                        if SEVERITY_RANK[severity] > SEVERITY_RANK[potential_severity]:
                            potential_severity = severity


                    results.append({

                        "port":
                            port,

                        "service":
                            service,

                        "product":
                            product,

                        "version":
                            version,

                        "state":
                            state,

                        "cve_candidate":
                            cve_info["cve"]
                            if cve_info
                            else None,

                        "potential_severity":
                            cve_info["severity"]
                            if cve_info
                            else None
                    })


        # ----------------------------------------------------
        # Create scan alert
        # ----------------------------------------------------

        create_alert(

            f"VULNERABILITY SCAN COMPLETED ON {target}",

            "MEDIUM",

            target,

            "PORT_SCAN"
        )


        print(
            f"[SCAN COMPLETE] {target} | {risk}"
        )


        return jsonify({

            "target":
                target,

            "risk":
                risk,

            "potential_severity":
                potential_severity
                if risk == "REVIEW"
                else None,

            "assessment_note":
                "Service-name CVE matches are unverified candidates; product, version, and OS must be checked against affected-version data.",

            "results":
                results

        }), 200


    except Exception:
        logging.exception("Vulnerability scan failed")
        return jsonify({"error": "Unable to complete vulnerability scan"}), 502


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/")
def home():
    index_file = os.path.join(BASE_DIR, "index.html")

    if not os.path.exists(index_file):
        return "index.html not found. Put index.html in the same folder as web_app.py", 404

    return send_from_directory(BASE_DIR, "index.html")


# ============================================================
# HEALTH
# ============================================================

@app.route("/health")
def health():
    return jsonify({
        "status":
            "online",

        "socket":
            "active" if SocketIO is not None else "disabled",

        "port":
            SERVER_PORT,

        "host":
            SERVER_HOST,

        "time":
            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )
    })


# ============================================================
# SOCKET CONNECTION
# ============================================================

@socketio.on("connect")
def socket_connect():

    print(
        "🟢 DASHBOARD CONNECTED"
    )


@socketio.on("disconnect")
def socket_disconnect():

    print(
        "🔴 DASHBOARD DISCONNECTED"
    )


# ============================================================
# START
# ============================================================

if __name__ == "__main__":

    print()
    print("=" * 55)
    print("       🛡 SECURESCAN XDR / AI SIEM")
    print("=" * 55)
    print()
    print("🚀 Server       : RUNNING")
    print(f"🌐 Dashboard    : http://{SERVER_HOST}:{SERVER_PORT}")
    print(f"📡 Ingest       : http://{SERVER_HOST}:{SERVER_PORT}/ingest")
    print("🔌 Socket.IO    : ENABLED" if SocketIO is not None else "🔌 Socket.IO    : DISABLED (HTTP polling remains available)")
    print("🗄 Database     :", DB_NAME)
    print()
    print("=" * 55)
    print()

    socketio.run(

        app,

        host=SERVER_HOST,

        port=SERVER_PORT,

        debug=False,

        allow_unsafe_werkzeug=True
    )