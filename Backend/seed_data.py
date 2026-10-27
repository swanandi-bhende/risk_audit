"""Organization record and assessment data for SecureTech Solutions.

Source documents:
- Docs/SecureTech_Organization_Record.md (assets, departments, controls)
- Docs/vulnerability_register.md (technical and organizational weaknesses)
- Docs/evidence/ (command output that verifies each finding)

CVSS v3.1 base scores are computed from each finding's vector by cvss.py, which
matches the published NVD scores for the reference vectors it was tested against.
"""

ASSETS = [
    {"id": "AST-001", "name": "Executive laptops (5)", "department": "Management", "classification": "Confidential", "criticality": 5, "exposure": "Internal", "ip": None, "port": None, "scannable": 0, "type": "Laptop", "environment": "Simulated record", "lab": "Simulated record"},
    {"id": "AST-002", "name": "Board and strategy document share", "department": "Management", "classification": "Confidential", "criticality": 5, "exposure": "Internal", "ip": None, "port": None, "scannable": 0, "type": "File share", "environment": "Simulated record", "lab": "Simulated record"},
    {"id": "AST-003", "name": "HR workstations (5)", "department": "HR", "classification": "Confidential", "criticality": 4, "exposure": "Internal", "ip": None, "port": None, "scannable": 0, "type": "Workstation", "environment": "Simulated record", "lab": "Simulated record"},
    {"id": "AST-004", "name": "Employee personnel records", "department": "HR", "classification": "Restricted", "criticality": 5, "exposure": "Internal", "ip": None, "port": None, "scannable": 0, "type": "Records", "environment": "Simulated record", "lab": "File share on company server"},
    {"id": "AST-005", "name": "Payroll data", "department": "HR / Finance", "classification": "Restricted", "criticality": 5, "exposure": "Internal", "ip": None, "port": None, "scannable": 0, "type": "Records", "environment": "Simulated record", "lab": "File share on company server"},
    {"id": "AST-006", "name": "Finance workstations (8)", "department": "Finance", "classification": "Confidential", "criticality": 4, "exposure": "Internal", "ip": None, "port": None, "scannable": 0, "type": "Workstation", "environment": "Simulated record", "lab": "Simulated record"},
    {"id": "AST-007", "name": "Accounting records and bank payment files", "department": "Finance", "classification": "Restricted", "criticality": 5, "exposure": "Internal", "ip": None, "port": None, "scannable": 0, "type": "Records", "environment": "Simulated record", "lab": "File share on company server"},
    {"id": "AST-008", "name": "IT workstations (8)", "department": "IT", "classification": "Confidential", "criticality": 4, "exposure": "Internal", "ip": None, "port": None, "scannable": 0, "type": "Workstation", "environment": "Simulated record", "lab": "Simulated record"},
    {"id": "AST-009", "name": "Company internal server", "department": "IT", "classification": "Restricted", "criticality": 5, "exposure": "Internal", "ip": "192.168.56.10", "port": None, "scannable": 1, "type": "Linux server (services: FTP, SSH, Telnet, HTTP, MySQL, VNC)", "environment": "Isolated lab (VirtualBox host-only)", "lab": "Metasploitable 2 VM (UTM)"},
    {"id": "AST-010", "name": "Backup storage", "department": "IT", "classification": "Restricted", "criticality": 4, "exposure": "Internal", "ip": None, "port": None, "scannable": 0, "type": "Backup", "environment": "Simulated record", "lab": "Simulated record"},
    {"id": "AST-011", "name": "Network infrastructure (router, switch)", "department": "IT", "classification": "Confidential", "criticality": 4, "exposure": "Internal", "ip": None, "port": None, "scannable": 0, "type": "Network", "environment": "Simulated record", "lab": "Simulated record"},
    {"id": "AST-012", "name": "Employee web portal", "department": "Employees (all)", "classification": "Confidential", "criticality": 4, "exposure": "Remote", "ip": "192.168.56.1", "port": 3000, "scannable": 0, "type": "Web application (OWASP Juice Shop)", "environment": "Lab (Docker on host Mac)", "lab": "Juice Shop container, 192.168.56.1:3000"},
    {"id": "AST-013", "name": "Source code repository", "department": "Employees (Developers)", "classification": "Restricted", "criticality": 5, "exposure": "Internal", "ip": None, "port": None, "scannable": 0, "type": "Repository", "environment": "Simulated record", "lab": "Directory /srv/repo on company server"},
    {"id": "AST-014", "name": "CRM and customer records", "department": "Employees (Sales)", "classification": "Confidential", "criticality": 4, "exposure": "Internal", "ip": None, "port": None, "scannable": 0, "type": "Records", "environment": "Simulated record", "lab": "Simulated record"},
    {"id": "AST-015", "name": "Support ticket system", "department": "Employees (Support)", "classification": "Internal", "criticality": 3, "exposure": "Internal", "ip": None, "port": None, "scannable": 0, "type": "Application", "environment": "Simulated record", "lab": "Simulated record"},
    {"id": "AST-016", "name": "Employee workstations (34)", "department": "Employees", "classification": "Internal", "criticality": 3, "exposure": "Internal", "ip": None, "port": None, "scannable": 0, "type": "Workstation", "environment": "Simulated record", "lab": "Simulated record"},
    {"id": "AST-017", "name": "Operations shared drive", "department": "Employees (Operations)", "classification": "Internal", "criticality": 3, "exposure": "Internal", "ip": None, "port": None, "scannable": 0, "type": "File share", "environment": "Simulated record", "lab": "Directory /srv/operations on company server"},
]

FINDINGS = [
    {"vuln_id": "VUL-002", "asset_id": "AST-009", "title": "vsftpd 2.3.4 contains a known backdoor", "category": "Outdated software", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "cwe": "CWE-506", "cve": "CVE-2011-2523", "likelihood": 4, "impact": 5, "evidence": "Docs/evidence/VUL-001-003_services.txt", "recommendation": "Remove FTP or replace vsftpd with a supported release. Version 2.3.4 is known to contain a backdoor.", "control": "CIS 7.3"},
    {"vuln_id": "VUL-004", "asset_id": "AST-009", "title": "Anonymous FTP login is enabled", "category": "Configuration", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "cwe": "CWE-284", "cve": None, "likelihood": 4, "impact": 4, "evidence": "Docs/evidence/VUL-004_anonymous_ftp.txt", "recommendation": "Set anonymous_enable=NO in vsftpd.conf and restart vsftpd.", "control": "CIS 6.1"},
    {"vuln_id": "VUL-001", "asset_id": "AST-009", "title": "Telnet exposes cleartext logins (also VUL-014)", "category": "Insecure protocol", "vector": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "cwe": "CWE-319", "cve": None, "likelihood": 4, "impact": 4, "evidence": "Docs/evidence/capture/VUL-014_ftp_plaintext_login.txt", "recommendation": "Disable Telnet and use SSH with key authentication.", "control": "CIS 4.8"},
    {"vuln_id": "VUL-001", "asset_id": "AST-009", "title": "Unnecessary VNC service exposed on port 5900", "category": "Unnecessary service", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "cwe": "CWE-284", "cve": None, "likelihood": 3, "impact": 4, "evidence": "Docs/evidence/VUL-001-003_services.txt", "recommendation": "Disable VNC, or require strong authentication and limit access to the admin network.", "control": "CIS 4.8"},
    {"vuln_id": "VUL-003", "asset_id": "AST-009", "title": "Outdated Apache, MySQL and OpenSSH versions", "category": "Outdated software", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "cwe": "CWE-1104", "cve": None, "likelihood": 4, "impact": 4, "evidence": "Docs/evidence/VUL-001-003_services.txt", "recommendation": "Upgrade Apache, MySQL and OpenSSH to supported versions, or replace the server.", "control": "CIS 7.3"},
    {"vuln_id": "VUL-005", "asset_id": "AST-009", "title": "Weak passwords on employee accounts", "category": "Authentication", "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "cwe": "CWE-521", "cve": None, "likelihood": 4, "impact": 5, "evidence": "Docs/evidence/password_audit/john_results.txt", "recommendation": "Enforce a password policy, reset the affected accounts, and enable MFA.", "control": "CIS 5.2"},
    {"vuln_id": "VUL-006", "asset_id": "AST-009", "title": "helpdesk01 has full root without a password", "category": "Excess privilege", "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "cwe": "CWE-269", "cve": None, "likelihood": 3, "impact": 5, "evidence": "Docs/evidence/discovery/ (sudoers check)", "recommendation": "Remove the NOPASSWD rule and grant only the commands the role needs.", "control": "CIS 6.8"},
    {"vuln_id": "VUL-007", "asset_id": "AST-017", "title": "Shared staff group gives HR and Finance access to Operations data", "category": "Excess privilege", "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", "cwe": "CWE-284", "cve": None, "likelihood": 3, "impact": 3, "evidence": "Docs/evidence/discovery/ (group check)", "recommendation": "Remove HR and Finance from the shared group and restrict the Operations drive to its members.", "control": "CIS 3.3"},
    {"vuln_id": "VUL-008", "asset_id": "AST-013", "title": "Source code repository is readable by all users", "category": "Excess privilege", "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", "cwe": "CWE-732", "cve": None, "likelihood": 3, "impact": 4, "evidence": "Docs/evidence/discovery/ (permission check)", "recommendation": "Restrict /srv/repo to the development group (chmod 750).", "control": "CIS 3.3"},
    {"vuln_id": "VUL-009", "asset_id": "AST-012", "title": "SQL injection on the login endpoint", "category": "Web application", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "cwe": "CWE-89", "cve": None, "likelihood": 5, "impact": 5, "evidence": "Docs/evidence/VUL-009_sqli_login.txt", "recommendation": "Use parameterized queries, validate input, and give the database account least privilege.", "control": "CIS 16.12"},
    {"vuln_id": "VUL-011", "asset_id": "AST-012", "title": "Admin configuration readable without login", "category": "Web application", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "cwe": "CWE-284", "cve": None, "likelihood": 4, "impact": 3, "evidence": "Docs/evidence/VUL-011_broken_access_control.txt", "recommendation": "Enforce server-side authorization on all administrative endpoints.", "control": "CIS 6.8"},
    {"vuln_id": "VUL-012", "asset_id": "AST-012", "title": "Sensitive files exposed under /ftp, including a password database", "category": "Data exposure", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "cwe": "CWE-538", "cve": None, "likelihood": 4, "impact": 4, "evidence": "Docs/evidence/VUL-012_ftp_listing.txt", "recommendation": "Remove sensitive files from public paths and disable directory listing.", "control": "CIS 3.3"},
    {"vuln_id": "VUL-010", "asset_id": "AST-012", "title": "DOM cross-site scripting in product search", "category": "Web application", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "cwe": "CWE-79", "cve": None, "likelihood": 3, "impact": 3, "evidence": "Docs/evidence/web/VUL-010_dom_xss.txt", "recommendation": "Encode output, sanitize user input, and add a Content-Security-Policy.", "control": "CIS 16.12"},
    {"vuln_id": "VUL-013", "asset_id": "AST-012", "title": "Missing Content-Security-Policy header on the web portal", "category": "Security headers", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N", "cwe": "CWE-693", "cve": None, "likelihood": 3, "impact": 2, "evidence": "Docs/evidence/VUL-013_portal_headers.txt", "recommendation": "Add a Content-Security-Policy header.", "control": "CIS 16.12"},
    {"vuln_id": "VUL-013", "asset_id": "AST-009", "title": "Missing security headers on the company server", "category": "Security headers", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N", "cwe": "CWE-693", "cve": None, "likelihood": 3, "impact": 2, "evidence": "Docs/evidence/VUL-013_company_server_headers.txt", "recommendation": "Set X-Frame-Options, X-Content-Type-Options and Content-Security-Policy in Apache.", "control": "CIS 16.12"},
]

COMPLIANCE = [
    {"area": "Password security", "cis": "Control 5 (5.2), Control 6 (6.3, 6.5)", "status": "Non-compliant", "evidence": "VUL-005; POL-001", "action": "Enforce a password policy and enable MFA for staff and privileged accounts."},
    {"area": "Access control", "cis": "Control 6 (6.1, 6.8)", "status": "Non-compliant", "evidence": "VUL-006; VUL-007", "action": "Remove the NOPASSWD rule and the shared group; review access quarterly."},
    {"area": "Patch management", "cis": "Control 7 (7.3)", "status": "Non-compliant", "evidence": "VUL-002; VUL-003; POL-005", "action": "Adopt a monthly patch cycle and replace end-of-life software."},
    {"area": "Network security", "cis": "Control 4 (4.8), Control 12 (12.2)", "status": "Non-compliant", "evidence": "VUL-001; VUL-004", "action": "Disable Telnet, anonymous FTP and VNC; restrict services to required ports."},
    {"area": "Data protection", "cis": "Control 3 (3.1, 3.3)", "status": "Partially compliant", "evidence": "VUL-008; VUL-012; POL-006", "action": "Enforce the data classification already in the organization record and restrict Restricted data."},
    {"area": "Backup", "cis": "Control 11 (11.2)", "status": "Non-compliant", "evidence": "POL-002", "action": "Define a daily backup schedule for Restricted data and test restores quarterly."},
    {"area": "Security monitoring", "cis": "Control 8 (8.2, 8.11)", "status": "Non-compliant", "evidence": "POL-003", "action": "Centralize logs and review authentication and privilege events weekly."},
    {"area": "Incident response", "cis": "Control 17 (17.4)", "status": "Non-compliant", "evidence": "POL-004", "action": "Write an incident-response plan with contacts and test it annually."},
]

# Remediation applied to the company server in Part B step 9.
REMEDIATION_PLAN = {
    "VUL-004": "Set anonymous_enable=NO in /etc/vsftpd.conf and restart vsftpd.",
    "VUL-001": "Disable Telnet in inetd (or remove the telnetd service).",
    "VUL-006": "Remove the NOPASSWD rule for helpdesk01 from /etc/sudoers.",
}

# Departments and headcount from the organization record (60 employees in total).
DEPARTMENTS = [
    {"name": "Management", "headcount": 5, "roles": "CEO, COO, Operations Director, Executive Assistant, Office Manager"},
    {"name": "HR", "headcount": 5, "roles": "HR Manager, HR Specialist (2), Recruiter, Payroll Officer"},
    {"name": "Finance", "headcount": 8, "roles": "Finance Manager, Accountant (3), Accounts Payable Clerk, Accounts Receivable Clerk, Financial Analyst, Procurement Officer"},
    {"name": "IT", "headcount": 8, "roles": "IT Manager, System Administrator (2), Network Administrator, IT Security Officer, Help Desk Technician (2), Database Administrator"},
    {"name": "Employees", "headcount": 34, "roles": "Software Developer (12), Sales Representative (8), Customer Support Agent (8), Operations Executive (6)"},
]
