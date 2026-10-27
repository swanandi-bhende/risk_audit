"""Risk scoring for SecureTech findings.

Each finding's CVSS v3.1 base score (see cvss.py) is adjusted for the asset it
affects:

    risk = CVSS base score x (asset criticality / 5) x exposure factor

- CVSS: base score 0-10 from the finding's vector. CVSS already includes how easy
  the attack is (attack vector, complexity, privileges, user interaction), so no
  separate exploitability factor is applied. That avoids counting it twice.
- Asset criticality: 1-5, from the organization record.
- Exposure factor: how reachable the asset is. Remote 1.0, Internal 0.8.

The result is 0-10. Priority bands: P1 >= 7.0, P2 >= 5.0, P3 >= 3.0, P4 below 3.0.

Posture is the share of the maximum possible risk that is still open:

    maximum risk for a finding = 10 x (criticality / 5) x exposure factor
    posture = 100 x (1 - open risk / total maximum risk)

Every finding with a CVSS score counts toward the maximum, including resolved ones,
so fixing a finding raises the score and new findings lower it.
"""

EXPOSURE_FACTOR = {"Remote": 1.0, "Internal": 0.8, "Isolated": 0.6}


def calculate_risk(cvss, criticality, exposure):
    if cvss is None:
        return None
    return round(cvss * (criticality / 5) * EXPOSURE_FACTOR[exposure], 1)


def maximum_risk(criticality, exposure):
    return 10 * (criticality / 5) * EXPOSURE_FACTOR[exposure]


def priority_for(risk):
    if risk is None:
        return None
    if risk >= 7.0:
        return "P1"
    if risk >= 5.0:
        return "P2"
    if risk >= 3.0:
        return "P3"
    return "P4"


def severity_for(cvss):
    if cvss is None or cvss == 0:
        return "Info"
    if cvss >= 9.0:
        return "Critical"
    if cvss >= 7.0:
        return "High"
    if cvss >= 4.0:
        return "Medium"
    return "Low"


def posture_score(open_risk, total_maximum):
    if total_maximum <= 0:
        return 100
    return max(0, round(100 * (1 - open_risk / total_maximum)))


def posture_rating(score):
    if score >= 90:
        return "Good"
    if score >= 70:
        return "Moderate"
    if score >= 40:
        return "Poor"
    return "Critical"


POSTURE_METHOD = (
    "Posture = 100 x (1 - open risk / total maximum risk). Each finding's risk is its "
    "CVSS v3.1 base score x (asset criticality / 5) x exposure factor. Its maximum is "
    "CVSS 10 on the same asset. Resolved findings still count toward the maximum, so "
    "fixing a finding raises the score. This is a prototype indicator, not a certified "
    "security rating."
)
