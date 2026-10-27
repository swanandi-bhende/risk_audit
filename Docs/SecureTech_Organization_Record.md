# SecureTech Solutions: Organization Record

**Version:** 1.0 (baseline for the lab build)
**Purpose:** Defines the simulated organization that is the subject of the risk assessment and compliance audit.
**Change control:** Changes to headcount, assets or baseline policies must be recorded here with a new version number.

---

## 1. Company Profile

| Field | Value |
|---|---|
| Company name | SecureTech Solutions |
| Business | Software development and IT services for small and medium clients |
| Size | 60 employees |
| Locations | One head office (fictional), with hybrid working |
| Internal domain | securetech.local (fictional) |
| Lab address space | VirtualBox host-only network, 192.168.56.0/24 |
| Security owner | IT Security Officer (IT department) |

SecureTech runs its internal systems on one company server, one employee web portal, and workstations for all staff. It handles employee personnel data, payroll, financial records, customer data and source code.

---

## 2. Departments and Headcount

| Department | Headcount | Breakdown |
|---|---|---|
| Management | 5 | CEO, COO, Operations Director, Executive Assistant, Office Manager |
| HR | 5 | HR Manager, HR Specialist (2), Recruiter, Payroll Officer |
| Finance | 8 | Finance Manager, Accountant (3), Accounts Payable Clerk, Accounts Receivable Clerk, Financial Analyst, Procurement Officer |
| IT | 8 | IT Manager, System Administrator (2), Network Administrator, IT Security Officer, Help Desk Technician (2), Database Administrator |
| Employees (general staff) | 34 | Software Developer (12), Sales Representative (8), Customer Support Agent (8), Operations Executive (6) |
| **Total** | **60** | |

Every employee has one workstation, so the organization has 60 workstations in total.

---

## 3. Roles and Access Levels

| Role group | Departments | Systems they use | Access level |
|---|---|---|---|
| Executives | Management | Email, board and strategy files, finance reports | Elevated (read access to finance and HR summaries) |
| HR staff | HR | Personnel records, payroll files | Restricted |
| Finance staff | Finance | Accounting records, bank payment files, invoices | Restricted |
| IT staff | IT | Server, network devices, backups, user accounts | Privileged |
| Developers | Employees | Source code repository, employee web portal | Standard, with write access to the code repository |
| Sales | Employees | CRM, customer records | Standard |
| Support | Employees | Support ticket system, customer records | Standard |
| Operations | Employees | Operations shared drive | Standard |

**Known access issues (intentional, for the audit):** Some HR and Finance users are members of a shared "staff" group that can read the Operations drive. Two Help Desk Technicians have full administrator rights on their workstations and on the company server.

---

## 4. Asset Inventory

**Criticality** rates how important the asset is to the business, from 1 (low) to 5 (critical). This value feeds the risk engine.
**Exposure** shows who can reach the asset: Internal (inside the office network only), Remote (reachable from outside through the web portal) or Lab-only (simulated, not a real system).

| Asset ID | Asset | Department | Data classification | Criticality | Exposure | Lab implementation |
|---|---|---|---|---|---|---|
| AST-001 | Executive laptops (5) | Management | Confidential | 5 | Internal | Simulated record |
| AST-002 | Board and strategy document share | Management | Confidential | 5 | Internal | Simulated record |
| AST-003 | HR workstations (5) | HR | Confidential | 4 | Internal | Simulated record |
| AST-004 | Employee personnel records | HR | Restricted | 5 | Internal | Simulated record (file share on company server) |
| AST-005 | Payroll data | HR / Finance | Restricted | 5 | Internal | Simulated record (file share on company server) |
| AST-006 | Finance workstations (8) | Finance | Confidential | 4 | Internal | Simulated record |
| AST-007 | Accounting records and bank payment files | Finance | Restricted | 5 | Internal | Simulated record (file share on company server) |
| AST-008 | IT workstations (8) | IT | Confidential | 4 | Internal | Simulated record |
| AST-009 | Company internal server (services: SSH, FTP, Telnet, web, MySQL) | IT | Restricted | 5 | Internal | **Metasploitable 2 VM (UTM)** |
| AST-010 | Backup storage | IT | Restricted | 4 | Internal | Simulated record |
| AST-011 | Network infrastructure (router, switch) | IT | Confidential | 4 | Internal | Simulated record |
| AST-012 | Employee web portal | Employees (all) | Confidential | 4 | Remote | **OWASP Juice Shop (Docker container on the host Mac)** |
| AST-013 | Source code repository | Employees (Developers) | Restricted | 5 | Internal | Simulated record (on company server) |
| AST-014 | CRM and customer records | Employees (Sales) | Confidential | 4 | Internal | Simulated record (on web portal) |
| AST-015 | Support ticket system | Employees (Support) | Internal | 3 | Internal | Simulated record |
| AST-016 | Employee workstations (34) | Employees | Internal | 3 | Internal | Simulated record |
| AST-017 | Operations shared drive | Employees (Operations) | Internal | 3 | Internal | Simulated record (file share on company server) |

**Not part of SecureTech:** The Kali Linux VM is the auditor's machine. It is not a company asset and must never be scanned as a target.

---

## 5. Lab Network Mapping

| Host | Role | Address (planned) | Status |
|---|---|---|---|
| Kali Linux | Auditor (not a company asset) | 192.168.56.4 | Running; SSH enabled |
| Metasploitable 2 | Company internal server (AST-009) | 192.168.56.10 (static) | Running in UTM on the host-only network |
| Juice Shop | Employee web portal (AST-012) | 192.168.56.1:3000 (Docker on the Mac, bound to the host-only address) | Running |

The lab uses a host-only network only. No target VM is bridged to the home or office network or exposed to the internet.

---

## 6. Accounts (for the lab)

These accounts exist on the company server and the web portal so the weak-authentication and access-control weaknesses can be tested. Passwords are recorded only in the configuration log, not in this record.

| Account | Department | Purpose in the lab |
|---|---|---|
| `admin_it` | IT | Administrator account with excess rights |
| `helpdesk01` | IT | Help Desk account with full administrator rights (excess permission) |
| `hr_user` | HR | Weak password test account |
| `fin_user` | Finance | Weak password test account; member of shared "staff" group |
| `dev_user` | Employees (Developers) | Standard account with write access to the repository |
| `sales_user` | Employees (Sales) | Standard account; weak password test account |

---

## 7. Baseline Security Policies (current state)

The organization has basic policies on paper, but several controls are not enforced. This is the baseline for the compliance audit.

| Control area | Current state |
|---|---|
| Password security | No minimum password policy is enforced. Some accounts use weak passwords. |
| Multi-factor authentication | Not enabled for any system. |
| Access control | No quarterly access review. Shared group grants unnecessary access. |
| Patch management | Patches are applied ad hoc. The company server runs outdated software. |
| Network security | Unnecessary services (Telnet, FTP) are running on the company server. |
| Data protection | Data classification is informal. Restricted data is not encrypted at rest. |
| Backup | No backup schedule is documented. Backups are not tested. |
| Logging and monitoring | Logs are kept only on each system and are not reviewed. |
| Incident response | No incident-response plan exists. |
| Security awareness | No phishing or security-awareness training has been run. |

---

## 8. Business Impact Summary

| Impact area | Consequence if compromised |
|---|---|
| Personnel and payroll data | Privacy breach and legal exposure for all 60 employees |
| Financial records and bank files | Financial loss through fraud or manipulated payments |
| Source code | Loss of intellectual property and insertion of malicious code |
| Customer records | Loss of client trust and contract penalties |
| Company server | Disruption of all internal services |

---

## 9. Assignment Decisions

| Role | Plan (original) | Implemented | Reason |
|---|---|---|---|
| Auditor | Kali Linux VM | Kali Linux VM in VirtualBox (`192.168.56.4`) | Already installed |
| Company server (AST-009) | Ubuntu Server VM | Metasploitable 2 VM in UTM (`192.168.56.10`) | Already installed and intentionally vulnerable. Metasploitable 2 is x86_64, which VirtualBox cannot run on Apple Silicon, so it stays in UTM. |
| Employee web application (AST-012) | Juice Shop in a VM | Juice Shop in a Docker container on the host Mac, bound to `192.168.56.1:3000` (final) | Avoids an extra VM. The planned address `192.168.56.20` was dropped because it needs an extra address on the host Mac. |

The host-only network (`192.168.56.0/24`) is shared by all three targets. Metasploitable 2 and Juice Shop are not bridged or exposed to the Wi-Fi network.

---

## 10. Next Steps

1. Confirm this record with the course team.
2. Load the asset list (Section 4) into the application database as the first asset records.
3. Configure the lab VMs to match Sections 5 and 6, and record each weakness in the configuration log.
