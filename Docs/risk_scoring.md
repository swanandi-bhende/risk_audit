# Risk Scoring Method

This document explains how SecureTech scores risk, so the numbers in the dashboard and the report can be reproduced and checked.

The platform produces three numbers:

1. **CVSS base score** (0–10): how severe a weakness is in itself, computed from a CVSS v3.1 vector.
2. **Risk score** (0–10): the CVSS score adjusted for the asset that has the weakness.
3. **Posture score** (0–100): how much of the organization's maximum risk is still open.

Each finding also gets a **priority** (P1–P4) from its risk score.

---

## 1. CVSS v3.1 base score

Every finding stores a CVSS v3.1 vector, for example:

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H  →  9.8
```

| Metric | Meaning | Values used |
|---|---|---|
| AV (attack vector) | Where the attacker must be | N network, A adjacent, L local |
| AC (attack complexity) | Conditions beyond the attacker's control | L low, H high |
| PR (privileges required) | Login needed before the attack | N none, L low |
| UI (user interaction) | Whether a user must act | N none, R required |
| S (scope) | Whether the attack reaches beyond the vulnerable component | U unchanged, C changed |
| C, I, A (impact) | Effect on confidentiality, integrity, availability | H high, L low, N none |

The base score is calculated with the FIRST CVSS v3.1 specification (section 7.1) in `Backend/cvss.py`. Temporal and environmental metrics are not used.

**Check of the calculator.** It reproduces these published NVD scores exactly:

| Vector | Score |
|---|---|
| AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | 9.8 |
| AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H | 8.8 |
| AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H | 7.8 |
| AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N | 9.1 |
| AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N | 5.3 |
| AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N | 6.1 |
| AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N | 4.3 |
| AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N | 7.5 |
| AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N | 5.5 |

### 1.1 Vectors for the assessed findings

Each vector below was chosen for the weakness as it exists in the lab. The reason is given in the last column.

| ID | Finding | Asset | Vector | CVSS | Reason for the vector |
|---|---|---|---|---|---|
| VUL-002 | vsftpd 2.3.4 backdoor (CVE-2011-2523) | AST-009 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | 9.8 | Public backdoor, no login needed |
| VUL-009 | SQL injection on the login | AST-012 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N | 9.1 | Login bypass without credentials |
| VUL-001 | VNC on port 5900, no authentication | AST-009 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N | 9.1 | Connected without a password |
| VUL-005 | Weak passwords on employee accounts | AST-009 | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H | 8.8 | Needs a valid login, which the weak passwords provide |
| VUL-006 | helpdesk01 full root without password | AST-009 | AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H | 7.8 | Local, from a low-privilege account |
| VUL-012 | Sensitive files under /ftp | AST-012 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N | 7.5 | Downloaded without login |
| VUL-003 | Outdated Apache, MySQL, OpenSSH | AST-009 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N | 7.5 | Version-based; a conservative read-impact vector |
| VUL-004 | Anonymous FTP login | AST-009 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N | 7.5 | Anonymous login succeeds |
| VUL-001 | Telnet cleartext logins | AST-009 | AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N | 6.5 | Credentials sniffed on the same network segment (adjacent) |
| VUL-010 | DOM XSS in product search | AST-012 | AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N | 6.1 | Needs a victim to open a crafted link |
| VUL-008 | Repository readable by all users | AST-013 | AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N | 5.5 | Local users can read source code |
| VUL-007 | Shared group gives HR/Finance access to Operations | AST-017 | AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N | 5.5 | Local access by a staff account |
| VUL-011 | Admin configuration readable without login | AST-012 | AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N | 5.3 | Only configuration data is exposed |
| VUL-013 | Missing CSP on the web portal | AST-012 | AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N | 4.3 | Missing header, needs user interaction |
| VUL-013 | Missing security headers on the company server | AST-009 | AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N | 4.3 | Missing header, needs user interaction |

### 1.2 Vectors for services found by the scanner

Nmap finds these services. Each one is assessed from the service's usual unauthenticated exposure. None of them uses an NVD entry for the exact version detected, so each is an **assessment**, and the report says so. They are in `Backend/main.py` (`SERVICE_VECTORS`).

| Service (port) | Vector | CVSS | Reason |
|---|---|---|---|
| Samba / NetBIOS (139, 445) | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | 9.8 | Samba 3.x has remote code execution flaws that need no login |
| Tomcat AJP (8009) | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | 9.8 | AJP connector, Ghostcat class of flaws |
| rlogin (513) | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N | 9.1 | Trust-based login with no password |
| rsh (514) | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N | 9.1 | Trust-based shell with no password |
| X11 (6000) | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N | 9.1 | X server accepts connections without authentication |
| PostgreSQL (5432) | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H | 8.8 | Database that needs a login |
| ProFTPD (2121) | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N | 8.1 | FTP that needs a login; anonymous access is refused |
| NFS (2049) | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N | 7.5 | File share readable without login |
| BIND DNS (53) | AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N | 5.9 | Old BIND; cache poisoning needs timing (high complexity) |
| RPC bind (111) | AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N | 5.3 | Lists RPC services to anyone |
| SMTP (25) | AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L | 5.3 | Mail service; availability impact only |
| *Any other service* | AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N | 3.7 | Unassessed fallback; should not occur in this lab |

Services already covered by an assessed finding are recorded but do not get a second finding. These are ports 21, 22, 23, 80, 3306 and 5900.

---

## 2. Risk score

The CVSS score is adjusted for the asset:

```
risk = CVSS base score × (asset criticality ÷ 5) × exposure factor
```

- **Asset criticality (1–5)** comes from the organization record. Company server 5, employee web portal 4, operations drive 3.
- **Exposure factor** says how reachable the asset is:
  - Remote (reachable from outside the office network): 1.0
  - Internal (inside the office network only): 0.8

The result is between 0 and 10.

**Why there is no separate exploitability factor.** CVSS already includes how easy the attack is (attack vector, complexity, privileges and user interaction). Multiplying by an exploitability factor on top would count it twice. The CVSS exploitability sub-score is stored for each finding, for reference only.

**Likelihood and impact (1–5)** are recorded for each finding for the report, but they are not part of the formula, so the same factor is not counted twice.

### Worked examples (values from the database)

| Finding | CVSS | Criticality | Exposure | Calculation | Risk | Priority |
|---|---|---|---|---|---|---|
| vsftpd backdoor | 9.8 | 5 | Internal (0.8) | 9.8 × 5/5 × 0.8 | 7.8 | P1 |
| SQL injection (portal) | 9.1 | 4 | Remote (1.0) | 9.1 × 4/5 × 1.0 | 7.3 | P1 |
| Telnet cleartext | 6.5 | 5 | Internal (0.8) | 6.5 × 5/5 × 0.8 | 5.2 | P2 |
| Shared staff group | 5.5 | 3 | Internal (0.8) | 5.5 × 3/5 × 0.8 | 2.6 | P4 |

---

## 3. Priority bands

| Priority | Risk score | Meaning |
|---|---|---|
| P1 | 7.0 or above | Fix now |
| P2 | 5.0 to below 7.0 | Fix this cycle |
| P3 | 3.0 to below 5.0 | Plan the fix |
| P4 | below 3.0 | Monitor or accept |

---

## 4. Posture score

Posture is the share of the organization's maximum risk that is still open:

```
maximum risk for a finding = 10 × (criticality ÷ 5) × exposure factor
open risk = sum of risk scores for findings that are not resolved
total maximum risk = sum of maximum risk for all findings with a CVSS score

posture = 100 × (1 − open risk ÷ total maximum risk)
```

Resolved findings still count toward the total maximum risk. That's why fixing a finding raises the score, and a new finding lowers it.

Rating bands: 90 or above Good, 70–89 Moderate, 40–69 Poor, below 40 Critical.

**Worked example (values from the snapshots):**

- Before remediation: open risk 159.6, total maximum 212.8. Posture = 100 × (1 − 159.6 ÷ 212.8) = **25** (Critical).
- After remediation: open risk 142.2, total maximum 212.8. Posture = 100 × (1 − 142.2 ÷ 212.8) = **33** (Critical).

Remediation of the three fixed findings raised the posture by 8 points. It stays Critical because the remaining P1 findings are still open.

---

## 4.5 Why each weight was chosen

| Weight | Value | Why |
|---|---|---|
| Criticality ÷ 5 | 0.2 to 1.0 | Linear, so a criticality-5 asset (company server, repository, payroll) keeps its full CVSS score and a criticality-1 asset is reduced to a fifth. The five levels come from the organization record. |
| Remote exposure | 1.0 | Reachable from outside the office network, so no reduction. |
| Internal exposure | 0.8 | Reachable only from the office network. A small reduction, because an internal attacker still needs network access. |
| Isolated exposure | 0.6 | Defined for completeness; not used by any asset in this lab. |
| No separate exploitability factor | — | CVSS already includes attack vector, complexity, privileges and user interaction. A second factor would count them twice. |
| P1 at 7.0 | Threshold | A critical CVSS (9.0 and above) on a criticality-5 asset in an internal network scores 7.2 or more, so P1 means "critical weakness on an important asset". |
| P2 at 5.0, P3 at 3.0 | Thresholds | Spaced so each band covers roughly two CVSS severity levels after the asset adjustment. |

These weights are judgment calls for a lab. They are not calibrated against incident data. To change one, edit `Backend/risk.py` and rebuild the database so the scores are recalculated.

## 5. Limits of this method

- **Vectors are assessments.** The assessed findings use vectors chosen for the lab state. The scanner-found services use the assessments in section 1.2. Each should be checked against NVD entries for the exact version before a real assessment.
- **The posture is relative.** It shows how much of the organization's maximum risk remains open. It does not predict breach likelihood.
- **Temporal and environmental CVSS metrics are not used.** Exploit maturity and local controls would change the scores.

## 6. Where the code lives

| Part | File |
|---|---|
| CVSS base score | `Backend/cvss.py` |
| Risk, priority, posture | `Backend/risk.py` |
| Vectors for assessed findings | `Backend/seed_data.py` |
| Vectors for scanner-found services | `Backend/main.py` (`SERVICE_VECTORS`) |
| Scores in the report | `Docs/report/SecureTech_VAPT_Report.html` (section 5) |
