# Demo Runbook: SecureTech VAPT Platform

## Before the demo (checklist)

1. Start the lab VMs: Kali Linux (VirtualBox), Metasploitable 2 (UTM).
2. Check the Kali address. After any Kali reboot, run this in Kali:
   `sudo ip addr add 192.168.56.4/24 dev eth1`
3. Check Juice Shop: `curl -I http://192.168.56.1:3000/` should return 200.
   If the container is stopped: `docker start juice-shop`.
4. Start the platform:
   `cd Backend && source .venv/bin/activate && uvicorn main:app --port 8200`
5. Open **http://localhost:8200/**. Port 8000 is taken by another Docker container.

## Demo flow (about 15 minutes)

1. **Organization.** Show the asset inventory: 17 assets, 60 employees, five departments.
   Source: `Docs/SecureTech_Organization_Record.md`.
2. **Scan.** Select "Company internal server (192.168.56.10)" and click **Run Nmap service scan**.
   Show the open ports and the new findings.
3. **Findings.** Walk through the top three by risk: vsftpd backdoor (P1), SQL injection (P1),
   and weak passwords (P2). Explain the scoring: CVSS v3.1 base score from each vector, × asset criticality ÷ 5 × exposure factor. Posture is the share of maximum risk still open.
4. **Evidence.** Show the password audit (5 of 7 accounts cracked) and the plaintext FTP capture
   (`Docs/evidence/capture/`).
5. **Compliance.** Show the eight CIS Controls v8 areas: seven non-compliant, one partially compliant.
6. **Remediation.** Show the before snapshot (25, Critical), then the after snapshot (33, Critical). Point out that three fixes raised the score by 8 points, and the remaining P1 findings keep it Critical. Explain that posture is the share of maximum risk still open, not a penalty scale.
   Explain that three fixes were applied: anonymous FTP and Telnet disabled, and `helpdesk01`'s
   password-free sudo removed.
7. **Report.** Click **Open VAPT report** and print to PDF.

## Known limitations (say these openly)

- Juice Shop is at 192.168.56.1:3000, not 192.168.56.20 (the host has no second address).
- Kali's host-only address is not permanent; re-add it after a reboot (see above).
- ZAP and Burp were not used. Web tests used curl and browser checks.
- Nmap's `http-security-headers` script did not return usable results for these services.
- CVSS v3.1 base scores are computed from each vector (checked against published NVD scores). Scanner-found services use assessed vectors listed in `Docs/risk_scoring.md`.
- The vsftpd 2.3.4 binary is still installed; only its service was disabled.
