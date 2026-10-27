# Audit Framework: CIS Controls v8 (Simplified Mapping)

**Decision:** The compliance audit uses **CIS Controls v8**, the framework named in the course plan. It is widely used, has specific safeguards, and maps directly to the technical findings. Verify the safeguard numbers against the official CIS v8 text before the presentation.

## Eight control areas

| # | Control area (from plan) | CIS Controls v8 mapping | Key safeguards checked |
|---|---|---|---|
| 1 | Password security | Control 5 (Account Management), Control 6 (Access Control) | 5.2 unique passwords; 6.3 and 6.5 MFA |
| 2 | Access control | Control 6 (Access Control Management) | 6.1 new accounts; 6.8 role-based access |
| 3 | Patch management | Control 7 (Continuous Vulnerability Management) | 7.3 OS patching; 7.4 application patching |
| 4 | Network security | Control 4 (Secure Configuration), Control 12 (Network Infrastructure) | 4.8 disable unnecessary services; 12.2 secure architecture |
| 5 | Data protection | Control 3 (Data Protection) | 3.1 data management; 3.3 access control lists |
| 6 | Backup | Control 11 (Data Recovery) | 11.2 automated backups; 11.4 isolated backups |
| 7 | Security monitoring | Control 8 (Audit Log Management) | 8.2 collect logs; 8.11 review logs |
| 8 | Incident response | Control 17 (Incident Response Management) | 17.1 designate contacts; 17.4 response process |

## Rating scale for each control

- **Compliant:** the safeguard is in place and evidence confirms it.
- **Partially compliant:** the safeguard exists but is incomplete or inconsistent.
- **Non-compliant:** the safeguard is missing or does not work.

## Evidence rules

- Technical controls: evidence is a command, scan result, or screenshot from the lab.
- Organizational controls: evidence is a document, a record, or a named interviewee's confirmation. If the document does not exist, the control is non-compliant.
