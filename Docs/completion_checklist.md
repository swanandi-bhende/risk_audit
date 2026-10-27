# Completion Checklist: Course Project Plan

Status key: **Done** = complete and evidenced. **Partial** = some of the step is complete. **Pending** = waiting on a step only the author can run.

## Part A: Build the organization and lab

| # | Step | Status | Evidence or notes |
|---|---|---|---|
| 1 | Finalize SecureTech Solutions (60 employees, five departments, roles, assets) | Done | `Docs/SecureTech_Organization_Record.md`; `/api/organization`; 17 assets in the database |
| 2 | Assign the VMs (Kali auditor, Metasploitable 2 company server, Juice Shop web app) | Done | Record section 9 notes the change from the Ubuntu server, and that Juice Shop runs as a Docker container on the host, not a VM |
| 3 | Keep the lab isolated; confirm Kali reaches each target | Done | Host-only network `192.168.56.0/24`. Kali reached Metasploitable (21, 22, 23, 80) and Juice Shop (`192.168.56.1:3000`) |
| 4 | Install Juice Shop with Docker on a VM on the host-only network | Done, with a deviation | Juice Shop runs in Docker on the Mac, bound only to the host-only address. Planned `.20` address not used (recorded as LIM-002). Kali confirmed it loads |
| 5 | Configure server weaknesses and record them in a configuration log | Done | `Docs/lab_setup/configuration_log.md`; accounts, sudo rule and shared group applied and checked |
| 6 | Policy weakness notes (MFA, backups, log review, incident response) | Done | `Docs/policy_weaknesses.md` |
| 7 | Vulnerability register (ID, asset, control, detection test) | Done | `Docs/vulnerability_register.md` |
| 8 | Choose the audit framework | Done | CIS Controls v8, mapped to the eight areas. `Docs/audit_framework.md` |
| 9 | Verify each weakness by hand; save evidence | Done | Evidence folders: `Docs/evidence/` (services, anonymous FTP, SQL injection, access control, `/ftp`, headers, XSS, password audit, capture, permissions, discovery, web) |
| 10 | Baseline snapshots of each VM | Done | Kali VirtualBox snapshot `baseline-2026-10-27`; Metasploitable disk copy in `~/SecureTech_Baselines/`; Juice Shop image tag |

## Part B: Assess and audit

| # | Step | Status | Evidence or notes |
|---|---|---|---|
| 1 | Asset discovery: host discovery and `-sV` XML | Done | `Docs/evidence/discovery/` |
| 2 | Asset table; scanner takes target from it; scans go to the company server | Done | `assets` table; `POST /api/scan/AST-009`. Only AST-009 is marked as a scan target |
| 3 | Web testing with Burp Suite Community or OWASP ZAP; headers with Nmap `http-security-headers` | **Partial** | Done: SQL injection, broken access control, `/ftp` exposure, DOM XSS (browser), headers (curl and Nmap `http-headers`). Nmap's `http-security-headers` gave no usable output. **Pending:** ZAP is not installed (needs your `sudo`) |
| 4 | Password hashes with John; review sudo and group permissions | Done | John cracked 5 of 7 lab accounts (`Docs/evidence/password_audit/`). Group, permission and sudoers checks are in `Docs/evidence/permissions/`. `sudo grep helpdesk01 /etc/sudoers` printed nothing after the fix |
| 5 | Capture a Telnet or FTP login with Wireshark | Done | `Docs/evidence/capture/`: `USER hr_user` and `PASS hr2024` in cleartext. The capture was made with tcpdump and read with tshark. ARP spoofing is optional and not done |
| 6 | Findings table with asset, vulnerability, evidence, CVSS, likelihood, impact, exploitability, exposure, criticality | Done | `/api/findings`: each has all fields. Exploitability is the CVSS sub-score |
| 7 | Risk engine: combine the factors, map to P1–P4, write down the formula and the weights | Done | `Docs/risk_scoring.md` (formula, weight rationale, worked examples); `Backend/risk.py`. Exploitability is not a separate factor, because CVSS already includes it |
| 8 | Compliance audit with status, evidence and action; shown in the dashboard | Done | Eight areas: seven Non-compliant, one Partially compliant. Shown on the dashboard and in the report |
| 9 | Remediation entry per finding; fix 2–3 on the company server; rescan; posture before and after | Done, with one check pending | Three fixes applied (anonymous FTP, Telnet, password-free sudo), and the sudoers fix is confirmed. Rescanned. Snapshots: 25 Critical before, 33 Critical after. Each finding carries its recommendation and status |
| 10 | HTML report with executive summary, profile, findings, compliance, remediation; export to PDF; rehearse | **Partial** | Done: `Docs/report/SecureTech_VAPT_Report.html` and `.pdf` (6 pages, generated with headless Chrome). All endpoints checked. **Pending:** you open the PDF and check it, and rehearse with your slides |

## Gaps listed in the project status

| Gap | Status |
|---|---|
| 1. Wrong scan target (scanning Kali) | Fixed. The company server is the only scan target |
| 2. No organization record in the database | Fixed. Assets and departments are in the database. Individual employee accounts are not modeled; the record lists role accounts only |
| 3. Risk is severity-only | Fixed. CVSS v3.1 vectors, criticality and exposure, documented in `Docs/risk_scoring.md` |
| 4. Missing compliance audit, remediation knowledge base, web testing, report | Compliance and report done. Remediation: each finding has its recommendation. Web testing partial (see Part B step 3) |
| 5. Stack differs from the course suggestion (FastAPI and plain HTML, not Flask and React) | Kept as is. The runbook states the stack |
| 6. Old test data labelled "SecureTech Ubuntu Server" | Fixed. The database was rebuilt. The old files are in `~/SecureTech_Baselines/` |
| Dates: the plan says 17 September, this machine says 27 October 2026 | **Pending:** confirm the real presentation date |

## Items waiting on you

1. **ZAP for step 3.** Install it on Kali in the Mac Terminal, then type your Kali password when asked:

   ```bash
   ssh -t -i ~/.ssh/securetech_lab_rsa -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa swanandibhende@192.168.56.4 "sudo apt-get install -y zaproxy"
   ```

2. **PDF check for step 10.** Open `Docs/report/SecureTech_VAPT_Report.pdf` and confirm it reads correctly.

3. **Presentation date.** Confirm the date.
