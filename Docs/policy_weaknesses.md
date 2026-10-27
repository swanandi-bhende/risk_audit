# SecureTech Solutions: Policy Weakness Notes

These weaknesses are organizational, not technical. They are assessed through the compliance audit (questionnaire and evidence review), not through scanning.

## POL-001: Missing multi-factor authentication
- **Control area:** Password security and access control
- **Current state:** MFA is not enabled on the company server, the employee web portal, or email.
- **Business risk:** A stolen password gives full access to personnel, payroll, finance, and source code.
- **Audit evidence:** Login to the web portal and server requires only a username and password. Confirm with IT Manager.
- **Recommendation:** Enable MFA for all staff accounts, and require it for all privileged accounts first.

## POL-002: No backup schedule
- **Control area:** Backup
- **Current state:** No backup schedule is documented, and no restore test has been run.
- **Business risk:** A ransomware attack or disk failure could permanently lose personnel, payroll, and financial records.
- **Audit evidence:** No backup policy document exists, and the backup storage (AST-010) has no job logs. Confirm with IT Manager.
- **Recommendation:** Define a daily backup for restricted data, keep one copy offline, and test a restore each quarter.

## POL-003: No log review
- **Control area:** Security monitoring
- **Current state:** Logs are kept only on each system. Nobody reviews them, and no alerts are configured.
- **Business risk:** Failed logins, privilege use, and data access go unnoticed, so attacks are detected late or not at all.
- **Audit evidence:** No log review records exist. Confirm with IT Security Officer.
- **Recommendation:** Centralize logs, review authentication and privilege events weekly, and keep review records.

## POL-004: No incident-response plan
- **Control area:** Incident response
- **Current state:** No written plan, contact list, or escalation path exists for security incidents.
- **Business risk:** Staff do not know who to inform or what to do first, which increases damage and recovery time.
- **Audit evidence:** No incident-response document exists. Confirm with Management.
- **Recommendation:** Write a short plan with roles, contacts, and steps for containment, reporting, and recovery, and test it once a year.

## POL-005: Ad hoc patch management
- **Control area:** Patch management
- **Current state:** Software is updated when someone remembers. The company server runs software several major versions behind.
- **Business risk:** Known vulnerabilities remain open for long periods.
- **Audit evidence:** Version evidence from VUL-002 and VUL-004 in the vulnerability register.
- **Recommendation:** Set a monthly patch cycle, prioritize internet-facing and restricted-data systems, and track patch status.

## POL-006: Informal data classification
- **Control area:** Data protection
- **Current state:** Data classes are known to staff but not documented. Restricted data is not encrypted at rest.
- **Business risk:** Sensitive data is stored and shared without the controls it needs.
- **Audit evidence:** No classification policy exists. Confirm with IT Manager.
- **Recommendation:** Adopt the four classes in the organization record (Restricted, Confidential, Internal, Public), label files, and encrypt Restricted data.

## POL-007: No security awareness training
- **Control area:** Outside the eight audited areas. Recorded as an additional finding because phishing is a planned scenario.
- **Current state:** No training has been run. Staff have not been tested for phishing.
- **Business risk:** Phishing is the most likely way into the company, and staff are the first line of defense.
- **Audit evidence:** No training records exist. Confirm with HR Manager.
- **Recommendation:** Run annual training and a simulated phishing exercise, and record the results.
