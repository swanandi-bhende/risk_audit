import os
import subprocess
import sqlite3
import xml.etree.ElementTree as ET
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "securetech.db"
FRONTEND_DIR = BASE_DIR.parent / "Frontend"

# Lab target: the Kali Linux VM on the VirtualBox host-only network.
# Override with SECURETECH_TARGET=<ip> if the VM gets a different address.
ASSET_NAME = "SecureTech Kali Lab VM"
SCAN_TARGET = os.environ.get("SECURETECH_TARGET", "192.168.56.4")

# Severity for newly discovered services, based on how often they are abused.
HIGH_RISK_SERVICES = {"telnet", "ftp", "vnc", "rsh", "rlogin", "rexec"}
MEDIUM_RISK_SERVICES = {
    "microsoft-ds", "netbios-ssn", "ms-wbt-server", "mysql",
    "postgresql", "ms-sql-s", "rpcbind", "msrpc", "nfs",
}


def get_connection():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    with get_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                asset TEXT NOT NULL,
                category TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT NOT NULL,
                recommendation TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Open',
                created_at TEXT NOT NULL
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL,
                details TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS scan_ports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                service TEXT NOT NULL,
                version TEXT NOT NULL,
                scanned_at TEXT NOT NULL
            )
        """)


def record_audit(connection, action, details):
    connection.execute(
        "INSERT INTO audit_log (action, details, created_at) VALUES (?, ?, ?)",
        (action, details, datetime.now(timezone.utc).isoformat()),
    )


@asynccontextmanager
async def lifespan(app):
    initialize_database()
    yield


app = FastAPI(
    title="SecureTech Risk Assessment API",
    description="Cybersecurity assessment for the SecureTech Solutions lab",
    version="1.1.0",
    lifespan=lifespan,
)


@app.get("/api/health")
def health():
    return {"status": "ok", "application": "SecureTech"}


@app.get("/api/assets")
def assets():
    return {
        "assets": [
            {
                "name": ASSET_NAME,
                "ip": SCAN_TARGET,
                "type": "Linux VM (Kali)",
                "environment": "Isolated lab (VirtualBox host-only)",
            }
        ]
    }


@app.get("/api/findings")
def list_findings():
    with get_connection() as connection:
        rows = connection.execute(
            "SELECT * FROM findings ORDER BY id DESC"
        ).fetchall()
    return {"findings": [dict(row) for row in rows]}


@app.get("/api/summary")
def summary():
    with get_connection() as connection:
        total = connection.execute(
            "SELECT COUNT(*) FROM findings"
        ).fetchone()[0]
        open_count = connection.execute(
            "SELECT COUNT(*) FROM findings WHERE status = 'Open'"
        ).fetchone()[0]
        severity_rows = connection.execute(
            "SELECT severity, COUNT(*) AS count FROM findings GROUP BY severity"
        ).fetchall()

    return {
        "total_findings": total,
        "open_findings": open_count,
        "by_severity": {
            row["severity"]: row["count"] for row in severity_rows
        },
    }


class SimulatedEvent(BaseModel):
    event_type: str = "Failed login"
    source: str = "192.168.56.1"
    count: int = 5


@app.post("/api/simulate")
def simulate_event(event: SimulatedEvent):
    # This endpoint records a clearly labelled simulation, not a real attack.
    count = max(1, min(event.count, 1000))
    title = f"SIMULATED: {event.event_type}"
    description = (
        f"Training event only. Source={event.source}; "
        f"simulated event count={count}. No attack was executed."
    )

    with get_connection() as connection:
        connection.execute(
            """INSERT INTO findings
            (asset, category, title, severity, description,
             recommendation, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, 'Open', ?)""",
            (
                ASSET_NAME,
                "Threat simulation",
                title,
                "Medium",
                description,
                "Review authentication logs and apply account lockout "
                "and multi-factor authentication policies where appropriate.",
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        record_audit(connection, "SIMULATION_CREATED", description)

    return {"message": "Simulation recorded", "title": title}


@app.get("/api/audit")
def audit_records():
    with get_connection() as connection:
        rows = connection.execute(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT 100"
        ).fetchall()
    return {"audit_records": [dict(row) for row in rows]}


def classify_service(service, port):
    if service in HIGH_RISK_SERVICES:
        return "High"
    if service in MEDIUM_RISK_SERVICES:
        return "Medium"
    return "Low"


def parse_open_ports(xml_text):
    root = ET.fromstring(xml_text)
    host = root.find("host")
    if host is None:
        return None, None

    status_element = host.find("status")
    host_status = (
        status_element.get("state", "unknown")
        if status_element is not None
        else "unknown"
    )

    ports = []
    for port in host.findall(".//port"):
        state_element = port.find("state")
        if state_element is None or state_element.get("state") != "open":
            continue

        service = port.find("service")
        ports.append({
            "port": int(port.get("portid")),
            "protocol": port.get("protocol"),
            "service": service.get("name", "unknown")
            if service is not None else "unknown",
            "version": service.get("version", "")
            if service is not None else "",
        })
    return host_status, ports


def save_scan(connection, ports, scanned_at):
    """Store the scan's ports and raise one finding per newly seen port."""
    new_findings = 0
    for item in ports:
        connection.execute(
            """INSERT INTO scan_ports
            (target, port, protocol, service, version, scanned_at)
            VALUES (?, ?, ?, ?, ?, ?)""",
            (SCAN_TARGET, item["port"], item["protocol"],
             item["service"], item["version"], scanned_at),
        )

        title = (
            f"Exposed service: {item['port']}/{item['protocol']} "
            f"({item['service']})"
        )
        already_tracked = connection.execute(
            """SELECT 1 FROM findings
            WHERE asset = ? AND title = ? AND status != 'Resolved'""",
            (ASSET_NAME, title),
        ).fetchone()
        if already_tracked:
            continue

        version = item["version"] or "version not detected"
        connection.execute(
            """INSERT INTO findings
            (asset, category, title, severity, description,
             recommendation, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, 'Open', ?)""",
            (
                ASSET_NAME,
                "Service discovery",
                title,
                classify_service(item["service"], item["port"]),
                f"Port {item['port']}/{item['protocol']} is open on "
                f"{SCAN_TARGET} running {item['service']} ({version}).",
                "Confirm the service is required. If it is not, stop it or "
                "block the port on the host firewall.",
                scanned_at,
            ),
        )
        new_findings += 1
    return new_findings


@app.post("/api/scan")
def scan_lab_target():
    try:
        # -Pn: the lab VM drops ICMP probes, so skip host discovery.
        result = subprocess.run(
            [
                "nmap",
                "-Pn",
                "-sV",
                "-T3",
                "--top-ports", "100",
                "-oX", "-",
                SCAN_TARGET,
            ],
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )

        if result.returncode != 0:
            return {
                "status": "error",
                "message": result.stderr or "Nmap scan failed",
            }

        host_status, ports = parse_open_ports(result.stdout)
        if ports is None:
            return {
                "status": "error",
                "message": "No host information returned by Nmap",
            }

        scanned_at = datetime.now(timezone.utc).isoformat()
        with get_connection() as connection:
            new_findings = save_scan(connection, ports, scanned_at)
            record_audit(
                connection,
                "NMAP_SCAN",
                f"Scanned lab target {SCAN_TARGET}; "
                f"host status={host_status}; open ports={len(ports)}; "
                f"new findings={new_findings}",
            )

        return {
            "status": "completed",
            "target": SCAN_TARGET,
            "host_status": host_status,
            "open_ports": ports,
            "new_findings": new_findings,
            "note": "Service discovery only; this is not a full vulnerability scan.",
        }

    except FileNotFoundError:
        return {
            "status": "error",
            "message": "Nmap was not found. Install it with: brew install nmap",
        }
    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "message": "Scan timed out after 180 seconds.",
        }
    except ET.ParseError:
        return {
            "status": "error",
            "message": "Could not parse Nmap output.",
        }


@app.get("/api/ports")
def latest_ports():
    with get_connection() as connection:
        latest = connection.execute(
            "SELECT MAX(scanned_at) FROM scan_ports WHERE target = ?",
            (SCAN_TARGET,),
        ).fetchone()[0]
        rows = []
        if latest is not None:
            rows = connection.execute(
                """SELECT port, protocol, service, version FROM scan_ports
                WHERE target = ? AND scanned_at = ? ORDER BY port""",
                (SCAN_TARGET, latest),
            ).fetchall()
    return {
        "scanned_at": latest,
        "ports": [dict(row) for row in rows],
    }


# --- Security Posture Score ---

@app.get("/api/posture")
def security_posture():
    weights = {
        "Critical": 25,
        "High": 15,
        "Medium": 8,
        "Low": 3,
        "Info": 0,
    }

    with get_connection() as connection:
        rows = connection.execute(
            "SELECT severity, COUNT(*) AS count FROM findings "
            "WHERE status != 'Resolved' GROUP BY severity"
        ).fetchall()

    counts = {row["severity"]: row["count"] for row in rows}
    penalty = sum(
        weights.get(severity, 5) * count
        for severity, count in counts.items()
    )
    score = max(0, 100 - penalty)

    if score >= 90:
        rating = "Good"
    elif score >= 70:
        rating = "Moderate"
    elif score >= 40:
        rating = "Poor"
    else:
        rating = "Critical"

    return {
        "score": score,
        "rating": rating,
        "unresolved_findings": sum(counts.values()),
        "severity_counts": counts,
        "method": (
            "Starting score 100 minus severity penalties per unresolved "
            "finding. This is a prototype indicator, not a certified "
            "security rating."
        ),
    }


# --- Finding Remediation Workflow ---

class FindingStatusUpdate(BaseModel):
    status: str


@app.patch("/api/findings/{finding_id}/status")
def update_finding_status(
    finding_id: int,
    update: FindingStatusUpdate,
):
    allowed_statuses = {"Open", "In Progress", "Resolved"}

    if update.status not in allowed_statuses:
        raise HTTPException(
            status_code=400,
            detail="Status must be Open, In Progress, or Resolved.",
        )

    with get_connection() as connection:
        existing = connection.execute(
            "SELECT id, title, status FROM findings WHERE id = ?",
            (finding_id,),
        ).fetchone()

        if existing is None:
            raise HTTPException(
                status_code=404,
                detail="Finding not found.",
            )

        old_status = existing["status"]

        connection.execute(
            "UPDATE findings SET status = ? WHERE id = ?",
            (update.status, finding_id),
        )

        record_audit(
            connection,
            "FINDING_STATUS_CHANGED",
            f"Finding #{finding_id} '{existing['title']}': "
            f"{old_status} -> {update.status}",
        )

    return {
        "message": "Finding status updated",
        "finding_id": finding_id,
        "status": update.status,
    }


# Serve the dashboard from the same origin, so no CORS setup is needed.
# Mounted last so the /api routes above take precedence.
app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
