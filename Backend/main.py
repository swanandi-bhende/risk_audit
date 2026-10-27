import subprocess
import sqlite3
import xml.etree.ElementTree as ET
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from html import escape
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from cvss import base_score, exploitability_subscore
from risk import (
    EXPOSURE_FACTOR,
    POSTURE_METHOD,
    calculate_risk,
    maximum_risk,
    posture_rating,
    posture_score,
    priority_for,
    severity_for,
)
from seed_data import ASSETS, COMPLIANCE, DEPARTMENTS, FINDINGS

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "securetech.db"
FRONTEND_DIR = BASE_DIR.parent / "Frontend"

# Service ports that are risky when exposed, with an assessed CVSS for each.
HIGH_RISK_SERVICES = {"telnet", "ftp", "vnc", "rsh", "rlogin", "rexec"}
MEDIUM_RISK_SERVICES = {
    "microsoft-ds", "netbios-ssn", "ms-wbt-server", "mysql",
    "postgresql", "ms-sql-s", "rpcbind", "msrpc", "nfs",
}

# Ports already covered by assessed findings in seed_data.py, per asset.
# The scanner records them but does not create a second finding for them.
ASSESSED_PORTS = {"AST-009": {21, 22, 23, 80, 3306, 5900}}

# Nmap names some legacy services differently from the rsh/rlogin names used above.
SERVICE_ALIASES = {"login": "rlogin", "shell": "rsh", "exec": "rexec"}

# Columns added to findings after the first version of the database.
FINDING_COLUMNS = {
    "asset_id": "TEXT",
    "vuln_id": "TEXT",
    "cve": "TEXT",
    "cwe": "TEXT",
    "cvss": "REAL",
    "cvss_vector": "TEXT",
    "likelihood": "INTEGER",
    "impact": "INTEGER",
    "exploitability": "REAL",
    "exposure": "TEXT",
    "criticality": "INTEGER",
    "risk_score": "REAL",
    "priority": "TEXT",
    "evidence": "TEXT",
    "control": "TEXT",
}


def get_connection():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def record_audit(connection, action, details):
    connection.execute(
        "INSERT INTO audit_log (action, details, created_at) VALUES (?, ?, ?)",
        (action, details, datetime.now(timezone.utc).isoformat()),
    )


def initialize_database():
    with get_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS assets (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                department TEXT NOT NULL,
                classification TEXT NOT NULL,
                criticality INTEGER NOT NULL,
                exposure TEXT NOT NULL,
                ip TEXT,
                port INTEGER,
                scannable INTEGER NOT NULL DEFAULT 0,
                type TEXT NOT NULL,
                environment TEXT NOT NULL,
                lab_implementation TEXT NOT NULL
            )
        """)
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
        existing = {row["name"] for row in connection.execute("PRAGMA table_info(findings)")}
        for column, column_type in FINDING_COLUMNS.items():
            if column not in existing:
                connection.execute(f"ALTER TABLE findings ADD COLUMN {column} {column_type}")
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
                asset_id TEXT NOT NULL,
                target TEXT NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                service TEXT NOT NULL,
                version TEXT NOT NULL,
                scanned_at TEXT NOT NULL
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS compliance (
                area TEXT PRIMARY KEY,
                cis_mapping TEXT NOT NULL,
                status TEXT NOT NULL,
                evidence TEXT NOT NULL,
                recommended_action TEXT NOT NULL
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS departments (
                name TEXT PRIMARY KEY,
                headcount INTEGER NOT NULL,
                roles TEXT NOT NULL
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS posture_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                label TEXT NOT NULL,
                score INTEGER NOT NULL,
                rating TEXT NOT NULL,
                open_findings INTEGER NOT NULL,
                risk_total REAL NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        seed_if_empty(connection)


def insert_finding(connection, finding, asset, status, created_at):
    vector = finding["vector"]
    cvss = base_score(vector)
    exposure = asset["exposure"]
    risk = calculate_risk(cvss, asset["criticality"], exposure)
    connection.execute(
        """INSERT INTO findings
        (asset, category, title, severity, description, recommendation, status,
         created_at, asset_id, vuln_id, cve, cwe, cvss, cvss_vector, likelihood, impact,
         exploitability, exposure, criticality, risk_score, priority, evidence, control)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            asset["name"],
            finding["category"],
            finding["title"],
            severity_for(cvss),
            f"{finding.get('cwe') or ''} {finding.get('cve') or ''}".strip()
            or "Assessed weakness",
            finding["recommendation"],
            status,
            created_at,
            asset["id"],
            finding.get("vuln_id"),
            finding.get("cve"),
            finding.get("cwe"),
            cvss,
            vector,
            finding.get("likelihood"),
            finding.get("impact"),
            exploitability_subscore(vector),
            exposure,
            asset["criticality"],
            risk,
            priority_for(risk),
            finding.get("evidence"),
            finding.get("control"),
        ),
    )


def seed_if_empty(connection):
    if connection.execute("SELECT COUNT(*) FROM assets").fetchone()[0]:
        return
    now = datetime.now(timezone.utc).isoformat()
    for asset in ASSETS:
        connection.execute(
            """INSERT INTO assets (id, name, department, classification, criticality,
            exposure, ip, port, scannable, type, environment, lab_implementation)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (asset["id"], asset["name"], asset["department"], asset["classification"],
             asset["criticality"], asset["exposure"], asset["ip"], asset["port"],
             asset["scannable"], asset["type"], asset["environment"], asset["lab"]),
        )
    assets_by_id = {asset["id"]: asset for asset in ASSETS}
    for finding in FINDINGS:
        insert_finding(connection, finding, assets_by_id[finding["asset_id"]], "Open", now)
    for department in DEPARTMENTS:
        connection.execute(
            "INSERT INTO departments VALUES (?, ?, ?)",
            (department["name"], department["headcount"], department["roles"]),
        )
    for item in COMPLIANCE:
        connection.execute(
            "INSERT INTO compliance VALUES (?, ?, ?, ?, ?)",
            (item["area"], item["cis"], item["status"], item["evidence"], item["action"]),
        )
    record_audit(connection, "ASSESSMENT_LOADED",
                 f"Loaded {len(ASSETS)} assets, {len(FINDINGS)} findings and "
                 f"{len(COMPLIANCE)} compliance controls from the organization record.")


@asynccontextmanager
async def lifespan(app):
    initialize_database()
    yield


app = FastAPI(
    title="SecureTech Risk Assessment API",
    description="Cybersecurity risk assessment and compliance audit for SecureTech Solutions",
    version="2.0.0",
    lifespan=lifespan,
)


def asset_or_404(connection, asset_id):
    row = connection.execute("SELECT * FROM assets WHERE id = ?", (asset_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Asset not found.")
    return row


@app.get("/api/health")
def health():
    return {"status": "ok", "application": "SecureTech"}


@app.get("/api/assets")
def list_assets():
    with get_connection() as connection:
        rows = connection.execute("SELECT * FROM assets ORDER BY id").fetchall()
    return {"assets": [dict(row) for row in rows]}


@app.get("/api/organization")
def organization():
    with get_connection() as connection:
        rows = connection.execute("SELECT * FROM departments ORDER BY rowid").fetchall()
    departments = [dict(row) for row in rows]
    return {
        "name": "SecureTech Solutions",
        "description": "Simulated small organization for the risk assessment and compliance audit",
        "total_employees": sum(d["headcount"] for d in departments),
        "departments": departments,
    }


@app.get("/api/findings")
def list_findings():
    with get_connection() as connection:
        rows = connection.execute(
            """SELECT * FROM findings
            ORDER BY (risk_score IS NULL), risk_score DESC, id DESC"""
        ).fetchall()
    return {"findings": [dict(row) for row in rows]}


@app.get("/api/summary")
def summary():
    with get_connection() as connection:
        total = connection.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        open_count = connection.execute(
            "SELECT COUNT(*) FROM findings WHERE status != 'Resolved'"
        ).fetchone()[0]
        severity_rows = connection.execute(
            "SELECT severity, COUNT(*) AS count FROM findings "
            "WHERE status != 'Resolved' GROUP BY severity"
        ).fetchall()
        priority_rows = connection.execute(
            "SELECT priority, COUNT(*) AS count FROM findings "
            "WHERE status != 'Resolved' AND priority IS NOT NULL GROUP BY priority"
        ).fetchall()
    return {
        "total_findings": total,
        "open_findings": open_count,
        "by_severity": {row["severity"]: row["count"] for row in severity_rows},
        "by_priority": {row["priority"]: row["count"] for row in priority_rows},
    }


def current_posture(connection):
    rows = connection.execute(
        """SELECT status, criticality, exposure, risk_score FROM findings
        WHERE cvss IS NOT NULL"""
    ).fetchall()
    open_risk = sum(row["risk_score"] or 0 for row in rows if row["status"] != "Resolved")
    total_maximum = sum(
        maximum_risk(row["criticality"], row["exposure"]) for row in rows
    )
    open_count = sum(1 for row in rows if row["status"] != "Resolved")
    score = posture_score(open_risk, total_maximum)
    return {
        "score": score,
        "rating": posture_rating(score),
        "open_findings": open_count,
        "risk_total": round(open_risk, 1),
        "maximum_risk": round(total_maximum, 1),
        "method": POSTURE_METHOD,
    }


@app.get("/api/posture")
def security_posture():
    with get_connection() as connection:
        return current_posture(connection)


class PostureSnapshot(BaseModel):
    label: str


@app.post("/api/posture/snapshots")
def save_snapshot(snapshot: PostureSnapshot):
    label = snapshot.label.strip()[:80] or "Snapshot"
    with get_connection() as connection:
        posture = current_posture(connection)
        created_at = datetime.now(timezone.utc).isoformat()
        connection.execute(
            """INSERT INTO posture_snapshots
            (label, score, rating, open_findings, risk_total, created_at)
            VALUES (?, ?, ?, ?, ?, ?)""",
            (label, posture["score"], posture["rating"], posture["open_findings"],
             posture["risk_total"], created_at),
        )
        record_audit(connection, "POSTURE_SNAPSHOT",
                     f"{label}: score={posture['score']} ({posture['rating']}), "
                     f"open findings={posture['open_findings']}")
    return {"message": "Snapshot saved", "label": label, **posture}


@app.get("/api/posture/snapshots")
def list_snapshots():
    with get_connection() as connection:
        rows = connection.execute(
            "SELECT * FROM posture_snapshots ORDER BY id DESC"
        ).fetchall()
    return {"snapshots": [dict(row) for row in rows]}


@app.get("/api/compliance")
def compliance_results():
    with get_connection() as connection:
        rows = connection.execute("SELECT * FROM compliance ORDER BY rowid").fetchall()
    counts = {}
    for row in rows:
        counts[row["status"]] = counts.get(row["status"], 0) + 1
    return {"controls": [dict(row) for row in rows], "counts": counts}


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
        asset = asset_or_404(connection, "AST-009")
        connection.execute(
            """INSERT INTO findings
            (asset, category, title, severity, description, recommendation, status,
             created_at, asset_id, criticality, exposure)
            VALUES (?, ?, ?, ?, ?, ?, 'Open', ?, ?, ?, ?)""",
            (
                asset["name"],
                "Threat simulation",
                title,
                "Medium",
                description,
                "Review authentication logs and apply account lockout "
                "and multi-factor authentication policies where appropriate.",
                datetime.now(timezone.utc).isoformat(),
                asset["id"],
                asset["criticality"],
                asset["exposure"],
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


# CVSS v3.1 vectors for services the scanner finds, by service name. These are
# assessed per service from the service's typical unauthenticated exposure, not
# taken from an NVD entry for the detected version. Docs/risk_scoring.md lists each
# one with its reason. Services not listed here fall back to UNASSESSED_VECTOR.
SERVICE_VECTORS = {
    "smtp": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",       # mail relay, availability only
    "domain": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N",     # DNS server, poisoning needs timing
    "rpcbind": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",    # lists RPC services to anyone
    "netbios-ssn": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # Samba 3.x, remote code execution class
    "rlogin": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",    # trust-based login, no password
    "rsh": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",       # trust-based shell, no password
    "nfs": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",       # file share readable without login
    "ftp": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",       # ProFTPD, needs a login
    "postgresql": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",  # database, needs a login
    "X11": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",       # X server accepts connections without auth
    "ajp13": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",     # Tomcat AJP connector, Ghostcat class
}
UNASSESSED_VECTOR = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"


def guess_service_vector(service):
    service = SERVICE_ALIASES.get(service, service)
    return SERVICE_VECTORS.get(service, UNASSESSED_VECTOR)


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


def save_scan(connection, asset, target, ports, scanned_at):
    """Store the scan's ports and raise one finding per newly seen port."""
    new_findings = 0
    for item in ports:
        connection.execute(
            """INSERT INTO scan_ports
            (asset_id, target, port, protocol, service, version, scanned_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (asset["id"], target, item["port"], item["protocol"],
             item["service"], item["version"], scanned_at),
        )

        if item["port"] in ASSESSED_PORTS.get(asset["id"], set()):
            # Already covered by an assessed finding; do not duplicate it.
            continue

        title = (
            f"Exposed service: {item['port']}/{item['protocol']} "
            f"({item['service']})"
        )
        already_tracked = connection.execute(
            """SELECT 1 FROM findings
            WHERE asset_id = ? AND title = ? AND status != 'Resolved'""",
            (asset["id"], title),
        ).fetchone()
        if already_tracked:
            continue

        version = item["version"] or "version not detected"
        insert_finding(
            connection,
            {
                "title": title,
                "category": "Service discovery",
                "vector": guess_service_vector(item["service"]),
                "recommendation": "Confirm the service is required. If it is not, "
                                  "stop it or block the port on the host firewall.",
                "evidence": f"Nmap scan {scanned_at}",
                "control": "CIS 4.8",
            },
            asset,
            "Open",
            scanned_at,
        )
        new_findings += 1
    return new_findings


@app.post("/api/scan/{asset_id}")
def scan_asset(asset_id: str):
    with get_connection() as connection:
        asset = asset_or_404(connection, asset_id)
    if not asset["scannable"]:
        return {
            "status": "error",
            "message": f"{asset['name']} is not a network scan target.",
        }

    target = asset["ip"]
    try:
        # -Pn: the lab VM drops ICMP probes, so skip host discovery.
        result = subprocess.run(
            ["nmap", "-Pn", "-sV", "-T3", "--top-ports", "100", "-oX", "-", target],
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
        if result.returncode != 0:
            return {"status": "error", "message": result.stderr or "Nmap scan failed"}

        host_status, ports = parse_open_ports(result.stdout)
        if ports is None:
            return {"status": "error", "message": "No host information returned by Nmap"}

        scanned_at = datetime.now(timezone.utc).isoformat()
        with get_connection() as connection:
            new_findings = save_scan(connection, asset, target, ports, scanned_at)
            record_audit(
                connection,
                "NMAP_SCAN",
                f"Scanned {asset['name']} ({target}); host status={host_status}; "
                f"open ports={len(ports)}; new findings={new_findings}",
            )

        return {
            "status": "completed",
            "asset_id": asset["id"],
            "target": target,
            "host_status": host_status,
            "open_ports": ports,
            "new_findings": new_findings,
            "note": "Service discovery only; this is not a full vulnerability scan.",
        }
    except FileNotFoundError:
        return {"status": "error", "message": "Nmap was not found. Install it with: brew install nmap"}
    except subprocess.TimeoutExpired:
        return {"status": "error", "message": "Scan timed out after 180 seconds."}
    except ET.ParseError:
        return {"status": "error", "message": "Could not parse Nmap output."}


@app.get("/api/ports")
def latest_ports(asset_id: str = "AST-009"):
    with get_connection() as connection:
        latest = connection.execute(
            "SELECT MAX(scanned_at) FROM scan_ports WHERE asset_id = ?",
            (asset_id,),
        ).fetchone()[0]
        rows = []
        if latest is not None:
            rows = connection.execute(
                """SELECT port, protocol, service, version FROM scan_ports
                WHERE asset_id = ? AND scanned_at = ? ORDER BY port""",
                (asset_id, latest),
            ).fetchall()
    return {"asset_id": asset_id, "scanned_at": latest, "ports": [dict(row) for row in rows]}


class FindingStatusUpdate(BaseModel):
    status: str


@app.patch("/api/findings/{finding_id}/status")
def update_finding_status(finding_id: int, update: FindingStatusUpdate):
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
            raise HTTPException(status_code=404, detail="Finding not found.")

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


def _row(value):
    return "" if value is None else escape(str(value))


@app.get("/api/report", response_class=HTMLResponse)
def vapt_report():
    with get_connection() as connection:
        assets = connection.execute("SELECT * FROM assets ORDER BY id").fetchall()
        findings = connection.execute(
            """SELECT * FROM findings
            ORDER BY (risk_score IS NULL), risk_score DESC, id DESC"""
        ).fetchall()
        compliance = connection.execute("SELECT * FROM compliance ORDER BY rowid").fetchall()
        departments = connection.execute("SELECT * FROM departments ORDER BY rowid").fetchall()
        snapshots = connection.execute(
            "SELECT * FROM posture_snapshots ORDER BY id DESC"
        ).fetchall()
        posture = current_posture(connection)
        ports = connection.execute(
            """SELECT port, protocol, service, version, scanned_at FROM scan_ports
            WHERE asset_id = 'AST-009'
            AND scanned_at = (SELECT MAX(scanned_at) FROM scan_ports WHERE asset_id = 'AST-009')
            ORDER BY port"""
        ).fetchall()

    open_findings = [f for f in findings if f["status"] != "Resolved"]
    p1_p2 = [f for f in open_findings if f["priority"] in ("P1", "P2")]

    def table(headers, rows):
        head = "".join(f"<th>{escape(h)}</th>" for h in headers)
        body = "".join(
            "<tr>" + "".join(f"<td>{_row(cell)}</td>" for cell in row) + "</tr>"
            for row in rows
        )
        return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"

    findings_rows = [
        (f["id"], f["vuln_id"] or "", f["asset_id"], f["title"], f["cvss"],
         f["risk_score"], f["priority"], f["status"], f["recommendation"])
        for f in findings
    ]
    snapshot_rows = [
        (s["label"], s["score"], s["rating"], s["open_findings"], s["created_at"])
        for s in snapshots
    ]
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    html_doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SecureTech Solutions: VAPT Report</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Instrument+Sans:wght@400;500;600&family=Instrument+Serif&display=swap" rel="stylesheet">
<style>
:root {{
  --ink: #172121;
  --slate: #444554;
  --mist: #7F7B82;
  --blush: #E5D0CC;
  --paper: #E5D0CC;
  --serif: "Instrument Serif", Georgia, serif;
  --sans: "Instrument Sans", system-ui, sans-serif;
}}
* {{ box-sizing: border-box; }}
body {{ margin: 0; background: var(--paper); color: var(--ink); font-family: var(--sans); font-size: 15px; line-height: 1.55; }}
.sheet {{ max-width: 980px; margin: 0 auto; padding: 48px 40px 64px; }}
h1 {{ font-family: var(--serif); font-weight: 400; font-size: 44px; line-height: 1.1; margin: 0 0 8px; }}
h2 {{ font-family: var(--serif); font-weight: 400; font-size: 28px; line-height: 1.2; margin: 48px 0 12px; padding-top: 16px; border-top: 1px solid var(--blush); }}
p {{ margin: 0 0 12px; max-width: 72ch; }}
.muted {{ color: var(--slate); font-size: 14px; }}
.lede {{ font-size: 17px; color: var(--ink); }}
table {{ width: 100%; border-collapse: collapse; font-size: 13px; margin: 8px 0 16px; }}
th, td {{ text-align: left; vertical-align: top; padding: 9px 8px; border-bottom: 1px solid var(--blush); }}
th {{ font-weight: 600; color: var(--slate); background: transparent; border-bottom: 1px solid var(--mist); }}
td {{ overflow-wrap: anywhere; }}
.score {{ font-family: var(--serif); font-size: 64px; line-height: 1; }}
@media print {{
  body {{ background: #fff; }}
  .sheet {{ padding: 0; max-width: none; }}
  h2 {{ page-break-after: avoid; }}
  table {{ page-break-inside: auto; }}
  tr {{ page-break-inside: avoid; }}
}}
</style></head><body><div class="sheet">
<h1>SecureTech Solutions: Vulnerability Assessment and Compliance Audit Report</h1>
<p class="muted">Generated {generated}. Simulated organization. Lab environment only.</p>

<h2>1. Executive summary</h2>
<p>SecureTech Solutions was assessed as a simulated 60-employee organization. The assessment
found {len(open_findings)} open technical findings, of which {len(p1_p2)} are priority P1 or P2.
The security posture score is <b>{posture['score']}/100 ({posture['rating']})</b>.
Compliance status: {sum(1 for c in compliance if c['status'] == 'Non-compliant')} of
{len(compliance)} control areas are non-compliant and
{sum(1 for c in compliance if c['status'] == 'Partially compliant')} are partially compliant.</p>
<p>The most urgent actions are to remove the vsftpd 2.3.4 backdoor, fix the SQL injection on the
employee web portal, and disable or restrict the VNC, rsh, rlogin, X11, Samba and AJP services.
Anonymous FTP, Telnet and password-free sudo have already been fixed on the company server.</p>

<h2>2. Organization profile</h2>
<p>SecureTech Solutions: {sum(d["headcount"] for d in departments)} employees in five departments
({", ".join(f"{d['name']} {d['headcount']}" for d in departments)}). Lab network 192.168.56.0/24 (VirtualBox host-only).
Auditor: Kali Linux (192.168.56.4). Company server: Metasploitable 2 (192.168.56.10).
Employee web portal: OWASP Juice Shop (192.168.56.1:3000).</p>
{table(["ID", "Asset", "Department", "Classification", "Criticality", "Exposure", "Lab implementation"],
       [(a["id"], a["name"], a["department"], a["classification"], a["criticality"],
         a["exposure"], a["lab_implementation"]) for a in assets])}

<h2>3. Methodology</h2>
<p>Host discovery and service detection with Nmap (<code>-sV</code>), web security checks with
Nmap HTTP scripts and curl, password audit with John the Ripper on lab accounts, and a
plaintext traffic capture with tcpdump. Each finding is linked to evidence in the project's
evidence folder. Risk is calculated as described in section 5.</p>

<h2>4. Findings</h2>
{table(["ID", "Vuln", "Asset", "Finding", "CVSS", "Risk", "Priority", "Status", "Remediation"], findings_rows)}

<h2>5. Risk method</h2>
<p>Each finding is scored with CVSS v3.1 base metrics. The vector for each finding is listed
in the evidence folder. Risk = CVSS base score x (asset criticality / 5) x exposure factor.
Exposure factor: Remote 1.0, Internal 0.8. CVSS already includes how easy the attack is, so
no separate exploitability factor is applied, which avoids counting it twice.
Priority: P1 at 7.0 or above, P2 at 5.0 or above, P3 at 3.0 or above, P4 below 3.0.
Likelihood and impact (1-5) are recorded for each finding but are not part of the formula.</p>
<p>{escape(POSTURE_METHOD)}</p>

<h2>6. Compliance audit (CIS Controls v8)</h2>
{table(["Control area", "CIS mapping", "Status", "Evidence", "Recommended action"],
       [(c["area"], c["cis_mapping"], c["status"], c["evidence"], c["recommended_action"]) for c in compliance])}

<h2>7. Services on the company server (last scan)</h2>
{table(["Port", "Protocol", "Service", "Version", "Scanned"],
       [(p["port"], p["protocol"], p["service"], p["version"], p["scanned_at"]) for p in ports])}

<h2>8. Remediation and posture over time</h2>
<p>{escape(POSTURE_METHOD)}</p>
{table(["Snapshot", "Score", "Rating", "Open findings", "Taken"], snapshot_rows)}
<p>Remediation items are listed in the Remediation column of section 4. Items marked
Resolved were fixed on the company server and re-tested.</p>

<h2>9. Limitations</h2>
<ul>
<li>This is a lab assessment of a simulated organization. Findings are not a certified rating.</li>
<li>CVSS v3.1 base scores are computed from each finding's vector. The vectors for the
scanner-found services are assessments (see Docs/risk_scoring.md, section 1.2), not NVD entries
for the exact versions detected.</li>
<li>Web testing used Nmap HTTP scripts and curl. OWASP ZAP and Burp Suite were not used.</li>
<li>The company server is intentionally vulnerable and is isolated from other networks.</li>
</ul>
</div></body></html>"""
    return HTMLResponse(html_doc)


# Serve the dashboard from the same origin, so no CORS setup is needed.
# Mounted last so the /api routes above take precedence.
app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
