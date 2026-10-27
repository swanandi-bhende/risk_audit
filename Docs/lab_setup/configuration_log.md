# Configuration Log: Metasploitable 2 (AST-009) and Juice Shop (AST-012)

Lab-only record of every weakness configured. Passwords here are intentionally weak and must never be used outside the isolated lab.

## A. Metasploitable 2 (company server, 192.168.56.10)

| Change ID | Weakness | Change | Asset | Method | Status |
|---|---|---|---|---|---|
| CFG-001 | Unnecessary services | Telnet (23), FTP (21), VNC (5900), NetBIOS/SMB (139, 445), rpcbind (111) left running | AST-009 | Pre-installed, verified by nmap | Verified |
| CFG-002 | Outdated software | vsftpd 2.3.4, OpenSSH 4.7p1, Apache 2.2.8, MySQL 5.0.51a, Samba 3.x, BIND 9.4.2 | AST-009 | Pre-installed, verified by nmap `-sV` | Verified |
| CFG-003 | Weak passwords | `hr_user` = `hr2024`, `fin_user` = `Finance1`, `dev_user` = `password`, `sales_user` = `sales123`, `helpdesk01` = `helpdesk`, `admin_it` = `admin` | AST-009 | `metasploitable_configure.sh` step 1 | Applied and verified |
| CFG-004 | Excess sudo rights | `helpdesk01` has full root with no password (`NOPASSWD`); `admin_it` has full root | AST-009 | `metasploitable_configure.sh` step 5 | Applied and verified |
| CFG-005 | Excess group access | `hr_user` and `fin_user` are in the shared `staff` group, which can read the Operations drive | AST-017 | `metasploitable_configure.sh` steps 2–3 | Applied and verified |
| CFG-006 | Insecure source storage | Repository directory `/srv/repo` is world-readable (755) | AST-013 | `metasploitable_configure.sh` step 4 | Applied and verified |
| CFG-007 | Anonymous access | Anonymous FTP login is enabled (Metasploitable 2 default) | AST-009 | Pre-installed, verified with an anonymous login (`Docs/evidence/VUL-004_anonymous_ftp.txt`) | Verified |

### How to apply CFG-003 to CFG-006

1. Open the Metasploitable 2 window in UTM and log in as `msfadmin`.
2. Copy `Docs/lab_setup/metasploitable_configure.sh` into the VM (for example, by typing it into a file with `nano`).
3. Run it:

```bash
sudo sh metasploitable_configure.sh
```

4. Update the Status column to "Applied" once it finishes.

## B. Juice Shop (employee web application, 192.168.56.1:3000)

| Change ID | Weakness | Change | Asset | Method | Status |
|---|---|---|---|---|---|
| CFG-008 | Built-in vulnerabilities | SQL injection (login), DOM XSS (search), broken access control, directory traversal (`/ftp`), sensitive data exposure | AST-012 | Official image `bkimminich/juice-shop:latest`, no changes | Verified on Mac (see evidence) |
| CFG-009 | Missing security headers | Not configured in the application | AST-012 | Image default | Verified on Mac (see evidence) |

Juice Shop runs as a Docker container on the host Mac, bound only to `192.168.56.1:3000`, so it is reachable from the host-only network and not from the Wi-Fi network.

## C. Kali Linux (auditor, 192.168.56.4)

| Change ID | Change | Status |
|---|---|---|
| CFG-010 | SSH enabled (`sudo systemctl enable --now ssh`) so the auditor can be managed | Applied |

## D. Baselines (step 10)

| Asset | Baseline | Location | Taken |
|---|---|---|---|
| Kali Linux (VirtualBox) | Snapshot `baseline-2026-10-27` | VirtualBox snapshot list | Before the eth1 address was set |
| Metasploitable 2 (UTM) | Disk copy `metasploitable2-baseline-2026-10-27.qcow2` (SHA-256 starts `1997f998c173709b`) | `~/SecureTech_Baselines/` | After CFG-001 to CFG-006 |
| Juice Shop (Docker) | Image tag `securetech/juice-shop:baseline-2026-10-27` | Docker local images | Unchanged image |

Kali's `eth1` address `192.168.56.4/24` was set with `ip addr add`, so it is not permanent across reboots. Make it permanent before the demo.

## E. Known limitations (accepted for now)

| ID | Limitation | Demo action |
|---|---|---|
| LIM-001 | Kali's `eth1` address `192.168.56.4` is not permanent. It is lost on reboot. | After each Kali reboot, run `sudo ip addr add 192.168.56.4/24 dev eth1` in Kali, then check with `ip -4 addr show eth1`. |
| LIM-002 | Juice Shop is at `192.168.56.1:3000` instead of the planned `192.168.56.20`. | Use `192.168.56.1:3000` in the demo. |
