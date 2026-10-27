"""Risk scoring for SecureTech findings.

    risk = CVSS x (asset criticality / 5) x exposure factor x exploitability factor

- CVSS: base score 0-10 (CVSS v3.1), assessed from each finding's vector.
- Asset criticality: 1-5, from the organization record.
- Exposure: how reachable the asset is (Remote > Internal > Isolated).
- Exploitability: 3 = network attack without login, 2 = needs a low-privilege
  login, 1 = local access or user interaction required.

The result is 0-10. Priority bands: P1 >= 7.0, P2 >= 5.0, P3 >= 3.0, P4 below 3.0.
Likelihood and impact (1-5) are stored for the report but are not part of the
formula, so the same factor is not counted twice.
"""

EXPOSURE_FACTOR = {"Remote": 1.0, "Internal": 0.8, "Isolated": 0.6}
EXPLOITABILITY_FACTOR = {3: 1.0, 2: 0.9, 1: 0.8}


def calculate_risk(cvss, criticality, exposure, exploitability):
    if cvss is None:
        return None
    score = (
        cvss
        * (criticality / 5)
        * EXPOSURE_FACTOR[exposure]
        * EXPLOITABILITY_FACTOR[exploitability]
    )
    return round(score, 1)


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


POSTURE_SCALE = 0.5


def posture_score(risk_total):
    return max(0, round(100 - risk_total * POSTURE_SCALE))


def posture_rating(score):
    if score >= 90:
        return "Good"
    if score >= 70:
        return "Moderate"
    if score >= 40:
        return "Poor"
    return "Critical"


POSTURE_METHOD = (
    "Starting score 100 minus half the sum of risk scores for all unresolved findings. "
    "Each finding's risk score is CVSS x asset criticality x exposure x exploitability. "
    "The 0.5 scale keeps the score readable for a lab with about 30 findings. "
    "This is a prototype indicator, not a certified security rating."
)
