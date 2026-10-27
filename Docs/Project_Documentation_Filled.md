# Ethical Hacking Course Project Documentation

**Project:** Cybersecurity Risk Assessment and Compliance Audit for a Small Organization
**Organization:** SecureTech Solutions (fictional)
**Team:** Sharvari Awadhane (virtual lab setup), Manasvi Bandkar (virtual lab setup), Shruti Bedge (documentation), Swanandi Bhende (documentation)
**Roll numbers:** to be confirmed by the team. The template lists 8 (Sharvari Awadhane), 37 (Shruti Bedge) and 58 (Swanandi Bhende); Manasvi Bandkar's roll number is not in the template.
**Testing dates:** 26–27 October 2026 (India Standard Time)

> **Read this first.** This workbook records what was built and tested. Where the planned lab in the template differs from what was implemented, the difference is stated in section 3.2. Anything not performed is marked **Not performed**. The workbook does not contain any passwords. Account passwords are kept only in the lab's configuration log.

---

## 1. Project overview

The project simulates a small organization's IT environment and tests it for security weaknesses. It covers asset identification, baseline scanning, controlled demonstrations of weaknesses, risk rating, remediation and retesting. It is an educational assessment, not a formal audit.

### 1.1 Objectives: status

| Objective | Status | Where to find it |
|---|---|---|
| Isolated virtual lab representing a small organization | Done | Section 3 |
| Departments and employees represented by accounts, groups and records | Done (accounts on the server, employees as records) | Sections 2 and 6 |
| Identify exposed services and configuration weaknesses | Done | Sections 6 and 7 |
| Validate selected findings with controlled tests from Kali | Done for web, password, permission and service tests | Section 7 |
| Assess likelihood and impact, rate risk, prioritize | Done | Section 8 |
| Apply hardening and compare before and after | Done for three fixes | Sections 9 and 10 |
| Repeatable evidence for the demonstration and report | Done | Section 12 |

### 1.2 Scope

**In scope:** Kali Linux auditor VM; company server (Metasploitable 2) on the lab network; a web application (OWASP Juice Shop) on the same network; services, accounts, groups, file permissions and sudo rights on the server.

**Out of scope:** real organization systems; public IP addresses; third-party networks; real personal or financial data; destructive exploitation; denial of service; persistence or malware. The SSH configuration and firewall checks in the template were **not performed** (see section 7).

### 1.3 Rules of engagement: how they were followed

| Rule | How it was followed |
|---|---|
| Test only the lab hosts | Scans targeted `192.168.56.10` (company server) and `192.168.56.1:3000` (web application) only. The scanner only accepts the company server as a target. |
| Keep the target isolated | The lab uses VirtualBox's host-only network `192.168.56.0/24`. The Kali VM also has a NAT adapter, used for installing packages, which was **not** disabled (see section 3.2). |
| Synthetic data and test credentials only | All records, accounts and passwords are synthetic lab values. |
| Snapshot before significant changes | Taken before the lab configuration (section 5.1). |
| Record commands, timestamps and results | Evidence files in `Docs/evidence/` (section 12). |
| Do not report unconfirmed weaknesses | Each finding in section 8 cites a file that shows the test result. |
| Restore or remediate each weakness | Three weaknesses were remediated and retested. The rest are listed as open in section 9. |

---

## 2. Organization profile

SecureTech Solutions is a fictional organization with 60 employees across five departments. The template planned 8 accounts. The implementation keeps the full organization as records and models the staff who need accounts as Linux accounts on the company server.

| Department | Headcount (record) | Accounts on the server | Assets and business function |
|---|---|---|---|
| Management | 5 | none | Executive laptops; board and strategy share |
| HR | 5 | `hr_user` | Personnel records; payroll data |
| Finance | 8 | `fin_user` | Accounting records; bank payment files |
| IT | 8 | `admin_it`, `helpdesk01` | Company server; backup storage; network |
| Employees (general) | 34 | `dev_user`, `sales_user` | Source repository; CRM; support tickets; operations drive |
| **Total** | **60** | **6 accounts** | 17 assets in the asset inventory |

Source: `Docs/SecureTech_Organization_Record.md`.

### 2.1 Linux groups and accounts (implemented)

| Department / role | Group | Username | Created | Notes |
|---|---|---|---|---|
| HR | `hr_user` (primary), `staff` (shared) | `hr_user` | Yes | Member of the shared `staff` group |
| Finance | `fin_user` (primary), `staff` (shared) | `fin_user` | Yes | Member of the shared `staff` group |
| Development | `dev_user` | `dev_user` | Yes | Owns `/srv/repo` |
| Sales | `sales_user` | `sales_user` | Yes | Standard account |
| IT, help desk | `helpdesk01` | `helpdesk01` | Yes | Sudo rule removed during remediation |
| IT, administrator | `admin_it` | `admin_it` | Yes | Full sudo (intended excess right) |

Evidence: `Docs/evidence/lab/E04_accounts_groups.txt`.

**Credential handling:** passwords are lab-only and deliberately weak. They are stored in the configuration log, not in this report. The original template included a plaintext password on the first page. It has been omitted here on purpose.

---

## 3. Virtual lab architecture

### 3.1 Components (as implemented)

| Component | Role | Address | Status and evidence |
|---|---|---|---|
| Kali Linux (VirtualBox) | Auditor workstation | `192.168.56.4/24` on `eth1` | Running. Ping to the company server: 4 of 4 replies (E03) |
| Metasploitable 2 (UTM) | Company server (plays the role of the Ubuntu server) | `192.168.56.10/24` (static, survives reboot) | Running. Ping to Kali: 4 of 4 replies (E03) |
| Juice Shop (Docker on the host Mac) | Employee web application | `192.168.56.1:3000` | Running. HTTP 200 from Kali (E03) |
| VirtualBox host-only network `HostNetwork` | Isolated lab network | `192.168.56.0/24` | Enabled. Kali adapter 2 is connected (E01) |

### 3.2 Differences from the template plan

| Planned in the template | Implemented | Why |
|---|---|---|
| Ubuntu Server 192.168.50.10 | Metasploitable 2 at 192.168.56.10 | Metasploitable 2 was already installed and is intentionally vulnerable. It is built on Ubuntu 8.04 (kernel 2.6.24). |
| Kali 192.168.50.20 | Kali 192.168.56.4 | Addresses follow VirtualBox's host-only network. |
| VirtualBox Internal Network `SECURETECH-LAB` | VirtualBox Host-only network `HostNetwork` | The host-only network was already configured. It is still isolated from external networks. |
| NAT adapter disabled before testing | **Not disabled.** The Kali NAT adapter (eth0, 10.0.2.15) remains enabled. Tests reach the lab through eth1. | Kali needed NAT to install ZAP. This is a deviation: the team should disable it before a final demonstration. |
| pfSense, Wazuh, Docker, Apache | Not used, except Docker for Juice Shop | Not required for the simplified project. |
| Juice Shop in a VM | Juice Shop in a Docker container on the host | Avoided an extra VM. The planned `.20` address was dropped (LIM-002). |
| Two VMs | Three targets and an auditor | Juice Shop and the company server were both needed for the web and server tests. |

### 3.3 Network diagram (as implemented)

```
Kali Linux 192.168.56.4 (eth1) ──┐
                                  ├── VirtualBox host-only network 192.168.56.0/24
Metasploitable 2 192.168.56.10 ──┤
Juice Shop 192.168.56.1:3000 ────┘  (Docker on the host Mac)

Kali eth0 (NAT, 10.0.2.15) is connected to the internet for package installs only.
```

### 3.4 Network verification record

| Test | Command / method | Expected | Actual | Evidence |
|---|---|---|---|---|
| Kali IP | `ip -br address` | `192.168.56.4/24` on the lab interface | `eth1 UP 192.168.56.4/24` | E02 |
| Company server IP | `ifconfig eth0` | `192.168.56.10/24` | `inet addr:192.168.56.10` | E02 |
| Kali to company server | `ping -c 4 192.168.56.10` | Replies | 4 of 4 received, avg 3.1 ms | E03 |
| Company server to Kali | `ping -c 4 192.168.56.4` | Replies | 4 of 4 received, avg 1.5 ms | E03 |
| Kali to Juice Shop | `curl http://192.168.56.1:3000/` | HTTP 200 | HTTP 200 | E03 |
| Isolation check | VirtualBox adapter settings | Lab path only | Kali adapter 2 is host-only. Adapter 1 is NAT and still on (see 3.2) | E01 |

---

## 4. Tools and their purpose (as used)

| Tool | Purpose in this project | Used? |
|---|---|---|
| VirtualBox | Runs Kali Linux and provides the host-only network | Yes |
| UTM | Runs Metasploitable 2 | Yes |
| Docker | Runs Juice Shop | Yes |
| Kali Linux | Auditor workstation | Yes |
| Nmap (`-sV`, `-Pn`, NSE scripts) | Discovery, service and version detection, header checks | Yes. The `http-security-headers` script returned no usable output. |
| OWASP ZAP 2.17 | Web application scan | Installed. The scan is **not yet run** (see section 7.4) |
| John the Ripper | Password audit of lab hashes | Yes |
| Hydra | Installed on Kali | Not used |
| tcpdump and tshark | Packet capture and reading | Yes |
| curl | HTTP and FTP tests | Yes |
| OpenSSH | Remote administration and key login | Yes |
| sudo, visudo, ls, id, getent | Permission and sudo review | Yes |
| UFW | Ubuntu firewall | Not used. The company server runs no UFW (not checked). |

---

## 5. Implementation plan

### 5.1 Prepare and back up the lab

| Item | Value |
|---|---|
| Company server version | Metasploitable 2, Linux 2.6.24-16-server (Ubuntu 8.04 base) |
| Kali version | Kali Linux rolling, package set 2026.2.6 |
| Snapshot name and date | Kali: VirtualBox snapshot `baseline-2026-10-27`. Metasploitable: disk copy `metasploitable2-baseline-2026-10-27.qcow2` (taken after configuration, before remediation), in `~/SecureTech_Baselines/`. Juice Shop: image tag `securetech/juice-shop:baseline-2026-10-27`. The template's name `LAB-BASELINE` was not used. |
| Testers | Swanandi Bhende, with AI-assisted scripting (to be confirmed by the team) |
| Testing date and time | 26–27 October 2026, IST |

### 5.2 Accounts and test files

**Accounts:** implemented and checked (section 2.1, E04).

**Directories:** the template's `/srv/securetech/...` layout was **not** used. The implementation uses these paths on the company server:

| Directory | Owner / group | Permission | Verified |
|---|---|---|---|
| `/srv/operations` (Operations shared drive) | `root:staff` | `2775` (group-writable, setgid) | Yes (permission_checks.txt) |
| `/srv/repo` (source repository) | `dev_user:root` | `755` (readable by all users) | Yes (permission_checks.txt). This is a weakness, see VUL-008 |

The template's sample files (`it-procedures.txt`, `sample-source.txt`, `synthetic-employee-records.txt`) were not created.

---

## 6. Baseline security assessment

Baseline scans were run from Kali against the company server only.

### 6.1 Asset and service inventory

| Asset ID | Asset | IP / path | Business purpose | Owner | Sensitivity |
|---|---|---|---|---|---|
| AST-009 | Company server (Metasploitable 2) | 192.168.56.10 | Internal services | IT | Restricted |
| AST-012 | Employee web portal (Juice Shop) | 192.168.56.1:3000 | Employee portal | Employees | Confidential |
| AST-017 | Operations shared drive | `/srv/operations` | Operations files | Operations | Internal |
| AST-013 | Source code repository | `/srv/repo` | Source code | Development | Restricted |
| AST-004 | Personnel records (record) | Simulated | Employee records | HR | Restricted |
| AST-007 | Accounting records (record) | Simulated | Finance | Finance | Restricted |
| Not an asset | Kali Linux (auditor, not a company asset) | 192.168.56.4 | Testing | Audit team | Not in the company inventory |

The full inventory of 17 assets is in `Docs/SecureTech_Organization_Record.md`.

### 6.2 Baseline commands and results

| Purpose | Command | Result |
|---|---|---|
| Addresses | `ip -br address`, `ifconfig` | E02 |
| Routes | `ip route` (Kali) | Default route via NAT (10.0.2.2); lab route `192.168.56.0/24` on eth1 |
| Listening services | Nmap `-sV` from Kali, top 100 ports | 18 open ports before remediation (listed in section 6.3) |
| Service inventory | Nmap `-sV` | `Docs/evidence/discovery/02_metasploitable_sv.xml` |
| Firewall status | `sudo ufw status verbose` | **Not performed** |
| SSH service status | `systemctl status ssh` | **Not performed** |
| SSH effective configuration | `sudo sshd -T` | **Not performed** |
| Directory permissions | `ls -ld`, `id` | Yes (permission_checks.txt) |

### 6.3 Initial open ports on the company server (before remediation)

| Port | Service | Version | Note |
|---|---|---|---|
| 21 | FTP | vsftpd 2.3.4 | Known backdoor; anonymous login allowed |
| 22 | SSH | OpenSSH 4.7p1 | Old version |
| 23 | Telnet | Linux telnetd | Cleartext |
| 25 | SMTP | Postfix | |
| 53 | DNS | BIND 9.4.2 | Old version |
| 80 | HTTP | Apache 2.2.8 | Old version |
| 111 | RPC | rpcbind | |
| 139, 445 | NetBIOS / SMB | Samba 3.x | |
| 513, 514 | rlogin, rsh | | Trust-based login |
| 2049 | NFS | | |
| 2121 | FTP | ProFTPD 1.3.1 | |
| 3306 | MySQL | 5.0.51a | Old version |
| 5432 | PostgreSQL | 8.3 | |
| 5900 | VNC | protocol 3.3 | No authentication |
| 6000 | X11 | | |
| 8009 | AJP (Tomcat) | | |

**After remediation:** 16 open ports. Ports 21 and 23 are closed (E09).

### 6.4 Evidence for the baseline

- Initial Nmap scan: `Docs/evidence/discovery/02_metasploitable_sv.xml` and `Docs/evidence/VUL-001-003_services.txt`
- Initial open ports on the server: table 6.3
- Initial firewall and SSH settings: **not captured** (not performed)

---

## 7. Controlled vulnerability scenarios

The template planned four scenarios. The implementation tested the scenarios below. Each test was run from Kali against the lab, and each result is backed by evidence.

### 7.1 Scenario status

| ID | Scenario (template) | Status | Evidence |
|---|---|---|---|
| V-01 | Excessive permissions on a synthetic file | **Performed.** Shared `staff` group, world-readable `/srv/repo`, and a password-free sudo rule for `helpdesk01` | Permission checks; sudoers check |
| V-02 | Unnecessary listening service | **Performed.** Eighteen services listening, including VNC, Telnet and anonymous FTP | Nmap XML and services text |
| V-03 | Weak SSH configuration setting | **Not performed** | — |
| V-04 | Overly permissive firewall policy | **Not performed** | — |

The template also planned an extra scenario per weakness (controlled demonstration). The implementation tested these additional weaknesses:

| Test | Method | Result | Evidence |
|---|---|---|---|
| Web: SQL injection | Login bypass with `' OR 1=1--` | Admin token returned | `VUL-009_sqli_login.txt` |
| Web: broken access control | Admin configuration read without login | HTTP 200 | `VUL-011_broken_access_control.txt` |
| Web: exposed files | Directory listing of `/ftp` | Password database and backups listed | `VUL-012_ftp_listing.txt` |
| Web: DOM XSS | Browser test, search payload | Script injected into the page | `web/VUL-010_dom_xss.txt` |
| Web: headers | `curl -I` and Nmap `http-headers` | Missing Content-Security-Policy (both); missing X-Frame-Options and nosniff (server) | `VUL-013_*_headers.txt`, `web/nmap_http_headers.txt` |
| Passwords | John the Ripper on a copy of the lab account hashes | 5 of 7 cracked in about 2 minutes | `password_audit/john_results.txt` |
| Cleartext login | tcpdump on Kali, FTP login over ProFTPD | `USER hr_user` and `PASS hr2024` visible | `capture/VUL-014_ftp_plaintext_login.txt` |
| Anonymous FTP | `curl ftp://anonymous@192.168.56.10/` | Login succeeded | `VUL-004_anonymous_ftp.txt` |

### 7.2 Vulnerability test record (example: V-02, anonymous FTP)

| Field | Record |
|---|---|
| Finding ID / title | VUL-004: anonymous FTP login is enabled |
| Date / time and tester | 27 October 2026, about 02:15 IST, Swanandi Bhende |
| Affected asset | AST-009, company server, port 21 |
| Initial state | vsftpd 2.3.4 running through xinetd, anonymous login allowed |
| Test steps | `curl -v ftp://anonymous:@192.168.56.10:21/` |
| Observed result | `230 Login successful` |
| Evidence file | `Docs/evidence/VUL-004_anonymous_ftp.txt` |
| Expected security impact | Anyone on the network can list and read files without a password |
| Remediation applied | vsftpd service disabled in xinetd; xinetd restarted (E08) |
| Retest result | Port 21 closed; `nmap -Pn -p 21 192.168.56.10` reports closed |

### 7.3 Evidence for vulnerability demonstrations

| Demonstration | Evidence file |
|---|---|
| Services and versions | `Docs/evidence/VUL-001-003_services.txt` |
| Anonymous FTP | `Docs/evidence/VUL-004_anonymous_ftp.txt` |
| SQL injection (token redacted) | `Docs/evidence/VUL-009_sqli_login.txt` |
| Broken access control | `Docs/evidence/VUL-011_broken_access_control.txt` |
| Exposed files under /ftp | `Docs/evidence/VUL-012_ftp_listing.txt` |
| Headers | `Docs/evidence/VUL-013_company_server_headers.txt`, `VUL-013_portal_headers.txt` |
| DOM XSS | `Docs/evidence/web/VUL-010_dom_xss.txt` |
| Password audit | `Docs/evidence/password_audit/john_results.txt` |
| Cleartext capture | `Docs/evidence/capture/VUL-014_ftp_plaintext_login.txt` (and `.pcap`) |
| Permissions and sudoers | `Docs/evidence/permissions/permission_checks.txt` |

### 7.4 Not performed

- **ZAP web scan.** ZAP 2.17 is installed on Kali, but the baseline scan has not been run.
- **SSH configuration (V-03)** and **firewall (V-04).** No test was run, so the template's before-and-after results for these are not available.
- **ARP spoofing.** Optional in the plan; not performed.

---

## 8. Risk assessment

### 8.1 Method

Likelihood and impact are each rated 1–5 (as in the template). Risk score = likelihood × impact. Ratings: 1–4 Low, 5–9 Moderate, 10–16 High, 17–25 Critical.

The project also uses a CVSS-based risk score, which is the one shown in the dashboard. Both are reported below. The CVSS method is described in `Docs/risk_scoring.md`.

### 8.2 Risk register (confirmed findings)

Only findings that have test evidence are listed. Scanner-discovered services are listed in section 8.3.

| Finding ID | Finding | Asset | Likelihood | Impact | Score (L × I) | Rating | CVSS v3.1 | Status | Treatment |
|---|---|---|---|---|---|---|---|---|---|
| VUL-009 | SQL injection on the login | Web portal | 5 | 5 | 25 | Critical | 9.1 | Open | Parameterized queries; input validation |
| VUL-002 | vsftpd 2.3.4 backdoor | Company server | 4 | 5 | 20 | Critical | 9.8 | Open (service disabled; package still installed) | Remove or replace the package |
| VUL-005 | Weak passwords (5 of 7 cracked) | Company server | 4 | 5 | 20 | Critical | 8.8 | Open | Password policy; reset accounts; MFA |
| VUL-001 | Telnet cleartext logins | Company server | 4 | 4 | 16 | Critical | 6.5 | **Resolved** | Telnet disabled (E08) |
| VUL-004 | Anonymous FTP login | Company server | 4 | 4 | 16 | Critical | 7.5 | **Resolved** | FTP service disabled (E08) |
| VUL-003 | Outdated Apache, MySQL, OpenSSH | Company server | 4 | 4 | 16 | Critical | 7.5 | Open | Upgrade or replace |
| VUL-012 | Sensitive files under /ftp | Web portal | 4 | 4 | 16 | Critical | 7.5 | Open | Remove files; disable listing |
| VUL-006 | helpdesk01 password-free root | Company server | 3 | 5 | 15 | High | 7.8 | **Resolved** | NOPASSWD removed (E08) |
| VUL-001 | Unnecessary VNC on 5900 (no auth) | Company server | 3 | 4 | 12 | High | 9.1 | Open | Disable VNC |
| VUL-008 | Repository readable by all users | Repository | 3 | 4 | 12 | High | 5.5 | Open | chmod 750 on `/srv/repo` |
| VUL-011 | Admin configuration readable without login | Web portal | 4 | 3 | 12 | High | 5.3 | Open | Server-side authorization |
| VUL-010 | DOM XSS in search | Web portal | 3 | 3 | 9 | Moderate | 6.1 | Open | Output encoding; CSP |
| VUL-007 | Shared staff group gives HR and Finance access to Operations | Operations drive | 3 | 3 | 9 | Moderate | 5.5 | Open | Remove shared group |
| VUL-013 | Missing security headers | Both web services | 3 | 2 | 6 | Moderate | 4.3 | Open | Set headers |

**Highest final rating:** Critical (score 25, VUL-009 SQL injection).

### 8.3 Scanner-discovered services

The scanner found 12 services that are not in the table above. Each has a CVSS score from `Docs/risk_scoring.md` but no likelihood or impact rating. They are listed in the dashboard. Examples at the highest CVSS: Samba (139, 445), Tomcat AJP (8009), rlogin (513), rsh (514), X11 (6000), PostgreSQL (5432).

### 8.4 Risk matrix mapping to the template's planned scenarios

| Template ID | Planned scenario | Confirmed finding | Score (L × I) | Rating |
|---|---|---|---|---|
| V-01 | Excessive permissions | VUL-006, VUL-007, VUL-008 | 15, 9, 12 | High, Moderate, High |
| V-02 | Unnecessary listening service | VUL-001 (VNC, Telnet), VUL-004 (FTP) | 12, 16, 16 | High, Critical, Critical |
| V-03 | Weak SSH setting | Not performed | — | — |
| V-04 | Overly permissive firewall | Not performed | — | — |

---

## 9. Remediation and retesting

### 9.1 Fixes applied

| Finding | Fix applied | Validation | Before | After | Status |
|---|---|---|---|---|---|
| VUL-004 anonymous FTP | FTP service disabled in xinetd; xinetd restarted | Port 21 closed; anonymous login refused | Anonymous login succeeded | Port closed | Fixed and retested |
| VUL-001 Telnet | Telnet disabled; xinetd restarted | Port 23 closed | Port open; Telnet banner returned | Port closed | Fixed and retested |
| VUL-006 helpdesk01 sudo | NOPASSWD rule removed; `visudo -c` passed | `sudo grep helpdesk01 /etc/sudoers` printed nothing | Password-free root | Password required | Fixed and retested |

Details: `Docs/evidence/lab/E08_remediation_log.txt`.

**Lesson recorded in the log:** `anonymous_enable=NO` in `/etc/vsftpd.conf` did not stop anonymous login on this system, so the service itself had to be disabled.

### 9.2 Fixes not yet applied

| Finding | Reason | Next action |
|---|---|---|
| VUL-002 vsftpd backdoor | Service is off, but the package is still installed | Remove the package |
| VUL-001 VNC | Still running | Disable VNC |
| VUL-007 shared group | Not changed | Remove HR and Finance from `staff` |
| VUL-008 repository | Not changed | `chmod 750 /srv/repo` |
| VUL-003, VUL-005, VUL-009, VUL-012, VUL-011, VUL-010, VUL-013 | Not changed | See the register |
| Kali NAT adapter | Still enabled | Disable before the final demo |

### 9.3 Repeat scan after remediation

- Open ports on the company server: 18 before, 16 after (E09).
- Posture (CVSS-based): 25 before, 33 after. Both are Critical. Method in `Docs/risk_scoring.md`.

---

## 10. Before-and-after security comparison

| Metric | Before remediation | After remediation | Evidence / notes |
|---|---|---|---|
| Unexpected open ports | 18 | 16 | Ports 21 and 23 closed. Nmap XML |
| Excessive file access | `/srv/repo` readable by all; `staff` group reads Operations drive; helpdesk01 password-free root | Only the `staff` group and `/srv/repo` remain | Permission checks; sudoers check |
| SSH configuration issue | **Not assessed** | **Not assessed** | — |
| Firewall policy | **Not assessed** | **Not assessed** | — |
| High or critical risks (L × I ≥ 10) | 11 | 8 | Count from the register in section 8.2, excluding scanner findings |

**What the comparison does not show:** a scan with fewer findings does not mean the system is secure. The SSH and firewall checks were not run, and the web scan with ZAP was not run.

---

## 11. Compliance and framework mapping

The project uses the CIS Controls v8 framework (see `Docs/audit_framework.md`). The template's NIST CSF mapping is shown alongside it.

| Project activity | Control theme | NIST CSF function | CIS Controls v8 | Evidence | Result |
|---|---|---|---|---|---|
| Asset inventory | Asset awareness | Identify | 1 | Section 6.1; asset list | Done |
| Account and permissions review | Identity and access | Protect | 5, 6 | E04; permission checks | Non-compliant (VUL-005, VUL-006, VUL-007) |
| Service scanning and baseline | Technical assessment | Detect | 4, 7 | Nmap XML | Non-compliant (VUL-001, VUL-003, VUL-004) |
| Risk register | Risk assessment | Identify | — | Section 8.2 | Done |
| Remediation and retesting | Protect and improve | Protect, Improve | 4 | E08; E09 | Partially compliant (3 of 15 fixed) |
| Log review | Monitoring | Detect | 8 | Policy note POL-003 | Non-compliant. Not tested |

If a specific ISO/IEC 27001 control number is needed for the course submission, check it against the edition the course uses. No ISO numbers are claimed here.

---

## 12. Evidence register

| Evidence ID | Description | File | Date | Phase |
|---|---|---|---|---|
| E-01 | VirtualBox and UTM network settings | `Docs/evidence/lab/E01_adapter_settings.txt` | 27 Oct 2026 | Lab setup |
| E-02 | IP addresses on Kali and the company server | `Docs/evidence/lab/E02_ip_addresses.txt` | 27 Oct 2026 | Lab setup |
| E-03 | Connectivity tests (ping and HTTP) | `Docs/evidence/lab/E03_connectivity.txt` | 27 Oct 2026 | Connectivity |
| E-04 | Department accounts and groups | `Docs/evidence/lab/E04_accounts_groups.txt` | 27 Oct 2026 | Organization |
| E-05 | File permissions and sudoers | `Docs/evidence/permissions/permission_checks.txt` | 27 Oct 2026 | Baseline and V-01 |
| E-06 | Baseline Nmap scan | `Docs/evidence/discovery/02_metasploitable_sv.xml`; `VUL-001-003_services.txt` | 27 Oct 2026 | Baseline |
| E-07 | Vulnerability demonstrations | Section 7.3 files | 26–27 Oct 2026 | Testing |
| E-08 | Remediation log | `Docs/evidence/lab/E08_remediation_log.txt` | 27 Oct 2026 | Remediation |
| E-09 | Retest: ports and posture snapshots | `Docs/evidence/lab/E09_retest_after_remediation.txt` | 27 Oct 2026 | Retesting |

Screenshots: the template asks for screenshots. The text evidence files above are the primary records. Add screenshots of the dashboard and the terminal runs if the course requires images.

---

## 13. Limitations

- The organization, employees and data are fictional and simulated.
- The company server is Metasploitable 2, an intentionally vulnerable Ubuntu 8.04-based image. It is not a current Ubuntu Server. Results apply to this image only.
- Three targets were used, not two. Juice Shop runs on the host Mac.
- The Kali NAT adapter was not disabled during testing.
- SSH configuration and firewall tests were not performed (V-03, V-04).
- ZAP has been installed but not run. Web testing used curl, Nmap and the browser.
- CVSS scores are computed from vectors chosen by the team. Scanner-discovered services use per-service vectors that are assessments, not NVD entries for the exact versions.
- Vulnerability scans can give false positives and miss weaknesses. The absence of a finding is not proof that a system is secure.

---

## 14. Conclusion and recommendations

**Assets assessed:** the company server (AST-009), the employee web portal (AST-012), the operations drive and the source repository (as files and permissions), and the auditor workstation.

**Confirmed findings:** 15 assessed weaknesses, plus 12 services discovered by the scanner. Of the assessed weaknesses, 3 are fixed and retested.

**Highest-priority finding:** the SQL injection on the employee portal's login (score 25). The vsftpd 2.3.4 backdoor (score 20) and weak passwords (score 20) are next.

**Fixes applied:** anonymous FTP and Telnet disabled, and the password-free root sudo rule removed.

**Residual risk:** the vsftpd package is still installed, VNC is still running, the web application's SQL injection and exposed files are open, five of seven lab accounts have weak passwords, and the staff group and repository permissions are unchanged.

**Recommendations:**
1. Fix the SQL injection on the portal login first, using parameterized queries.
2. Remove the vsftpd 2.3.4 package and disable VNC.
3. Enforce a password policy and enable MFA for all staff accounts.
4. Remove the shared staff group, restrict `/srv/repo` to the development group, and remove sensitive files from `/ftp`.
5. Complete the SSH and firewall checks, and run the ZAP web scan, to cover the scenarios not yet tested.

**Final conclusion:** the lab shows the company server's weaknesses clearly, and the three fixes made measurable progress. The posture improved from 25 to 33, but it remains Critical because the highest-priority findings are still open. The assessment is limited to the tests recorded here.

---

## 15. Practical demonstration checklist

| Item | Status |
|---|---|
| Show the VirtualBox network isolation and IP addresses | Ready (E01, E02) |
| Show Kali reaching the company server | Ready (E03) |
| Show the organization accounts, groups and synthetic files | Ready for accounts (E04). The synthetic files are the operations drive and repository, not the template's sample files |
| Run and explain the baseline service scan | Ready (Nmap, section 6) |
| Demonstrate each selected weakness | Ready for V-01 and V-02 and the web tests. V-03 and V-04 not performed |
| Show the evidence and explain the business impact | Ready (section 7.3) |
| Calculate the likelihood × impact risk score | Done (section 8.2) |
| Apply the fix and repeat the same test | Done for three fixes (section 9.1) |
| Compare before and after | Done (section 10) |
| Discuss the remaining limitations | Done (section 13) |

---

## 16. Team contribution record

| Team member | Contribution (as recorded) | Evidence / notes |
|---|---|---|
| Sharvari Awadhane | Virtual lab setup | To be confirmed by the team |
| Manasvi Bandkar | Virtual lab setup | To be confirmed by the team |
| Shruti Bedge | Documentation | To be confirmed by the team |
| Swanandi Bhende | Documentation; scanning platform, lab configuration and testing | `Docs/` and `Backend/` in the project folder |

The team should confirm the contributions above and record the actual split of work before submission.

---

## 17. Final values

| Item | Final value |
|---|---|
| Confirmed Kali IP | `192.168.56.4` (eth1, host-only network) |
| Confirmed company server IP | `192.168.56.10` (Metasploitable 2) |
| Isolation verified on date | 27 October 2026. The NAT adapter on Kali is still enabled (see 3.2). |
| Number of confirmed findings | 15 assessed findings, plus 12 scanner-discovered services |
| Highest final risk rating | Critical (score 25, VUL-009) |
| Number of findings remediated and retested | 3 (VUL-001 Telnet, VUL-004 anonymous FTP, VUL-006 sudo) |
| Overall result | The lab works and the tests are evidenced. Posture improved from 25 to 33 and remains Critical. Several findings remain open, and SSH and firewall checks are not done. |
