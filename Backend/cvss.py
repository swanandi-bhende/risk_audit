"""CVSS v3.1 base score calculator (FIRST CVSS v3.1 specification, section 7.1).

Each finding stores its vector, for example:
    CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H  ->  9.8

Only the base metrics are used. Temporal and environmental metrics are not applied.
"""

import math

_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_PRIVILEGES_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PRIVILEGES_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}


def _parse(vector):
    parts = vector.split("/")
    if parts[0] != "CVSS:3.1":
        raise ValueError(f"Unsupported CVSS version in {vector}")
    metrics = dict(part.split(":", 1) for part in parts[1:])
    required = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
    if set(metrics) != required:
        raise ValueError(f"Incomplete CVSS vector: {vector}")
    return metrics


def _roundup(value):
    """CVSS v3.1 Roundup: smallest number, to one decimal, that is >= value."""
    as_int = round(value * 100000)
    if as_int % 10000 == 0:
        return as_int / 100000.0
    return (math.floor(as_int / 10000) + 1) / 10.0


def _exploitability(metrics):
    privileges = (_PRIVILEGES_CHANGED if metrics["S"] == "C" else _PRIVILEGES_UNCHANGED)[metrics["PR"]]
    return 8.22 * _WEIGHTS["AV"][metrics["AV"]] * _WEIGHTS["AC"][metrics["AC"]] * privileges * _WEIGHTS["UI"][metrics["UI"]]


def _impact_subscore(metrics):
    iss = 1 - (
        (1 - _WEIGHTS["CIA"][metrics["C"]])
        * (1 - _WEIGHTS["CIA"][metrics["I"]])
        * (1 - _WEIGHTS["CIA"][metrics["A"]])
    )
    if metrics["S"] == "U":
        return 6.42 * iss
    return 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15


def base_score(vector):
    metrics = _parse(vector)
    impact = _impact_subscore(metrics)
    exploitability = _exploitability(metrics)
    if impact <= 0:
        return 0.0
    if metrics["S"] == "U":
        return _roundup(min(impact + exploitability, 10))
    return _roundup(min(1.08 * (impact + exploitability), 10))


def exploitability_subscore(vector):
    """The CVSS exploitability sub-score (0-3.9), shown for each finding."""
    return round(_exploitability(_parse(vector)), 1)
