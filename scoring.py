"""VulnPriority v1 scoring and CSV validation."""
import csv
import io
import math
import re

FIELDS = ("cve", "asset", "cvss", "epss", "kev", "criticality", "impact", "exposure")
EXPOSURE = {"internal": .2, "restricted": .6, "internet": 1}
MAX_ROWS = 5000

def number(value, low, high, label):
    if isinstance(value, bool):
        raise ValueError(f"{label} must be numeric")
    try:
        n = float(value)
    except (ValueError, TypeError):
        raise ValueError(f"{label} must be numeric") from None
    if not math.isfinite(n) or not low <= n <= high:
        raise ValueError(f"{label} must be between {low} and {high}")
    return n

def validate(row):
    if not isinstance(row, dict):
        raise ValueError("Expected a finding object")
    if any(k not in row for k in FIELDS):
        raise ValueError("Missing required columns")
    cve = str(row["cve"]).strip().upper()
    if not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", cve) or len(cve) > 40:
        raise ValueError("Invalid CVE identifier")
    asset = str(row["asset"] or "").strip()
    if not asset or len(asset) > 200 or any(ord(c) < 32 for c in asset):
        raise ValueError("Asset must contain 1–200 printable characters")
    cvss = number(row["cvss"], 0, 10, "CVSS")
    epss = None if row["epss"] in ("", None) else number(row["epss"], 0, 1, "EPSS")
    raw_kev = str(row["kev"]).strip().lower() if row["kev"] is not None else ""
    if raw_kev not in ("true", "false", ""):
        raise ValueError("KEV must be true, false or blank")
    kev = None if not raw_kev else raw_kev == "true"
    criticality = number(row["criticality"], 1, 5, "Criticality")
    impact = number(row["impact"], 1, 5, "Impact")
    if not criticality.is_integer() or not impact.is_integer():
        raise ValueError("Criticality and impact must be integers")
    exposure = str(row["exposure"]).strip().lower()
    if exposure not in EXPOSURE:
        raise ValueError("Exposure must be internal, restricted or internet")
    return dict(cve=cve, asset=asset, cvss=cvss, epss=epss, kev=kev,
                criticality=int(criticality), impact=int(impact), exposure=exposure)

def score(row):
    f = validate(row)
    components = {
        "Exploit likelihood": 30 * (f["epss"] if f["epss"] is not None else .5),
        "Technical severity": 20 * f["cvss"] / 10,
        "Asset criticality": 20 * f["criticality"] / 5,
        "Business impact": 20 * f["impact"] / 5,
        "Exposure": 10 * EXPOSURE[f["exposure"]],
    }
    base = sum(components.values())
    floor = (95 if f["exposure"] == "internet" else 85) if f["kev"] else 0
    risk = round(max(base, floor), 1)
    priority, days = next((p, d) for minimum, p, d in (
        (85, "P1", 1), (65, "P2", 7), (40, "P3", 30), (0, "P4", 90)
    ) if risk >= minimum)
    warnings = []
    if f["epss"] is None:
        warnings.append("EPSS unknown: neutral policy placeholder used; verify evidence.")
    if f["kev"] is None:
        warnings.append("KEV status unknown: verify against current catalogue.")
    if floor:
        action = "Verify applicability, contain exposure and expedite vendor-approved remediation."
    elif priority in ("P1", "P2"):
        action = "Validate finding and schedule expedited patch or mitigation."
    else:
        action = "Validate finding and remediate during planned maintenance."
    return {**f, "risk": risk, "priority": priority, "sla_days": days,
            "base_score": round(base, 1), "kev_floor": floor,
            "components": {k: round(v, 2) for k, v in components.items()},
            "warnings": warnings, "action": action}

def rank(rows):
    if not isinstance(rows, list) or len(rows) > MAX_ROWS:
        raise ValueError(f"Expected a list of at most {MAX_ROWS} findings")
    results, seen = [], set()
    for i, row in enumerate(rows, 1):
        try:
            finding = score(row)
            key = (finding["cve"], finding["asset"].casefold())
            if key in seen:
                raise ValueError("Duplicate CVE/asset pair")
            seen.add(key)
            results.append(finding)
        except ValueError as e:
            raise ValueError(f"Finding {i}: {e}") from None
    return sorted(results, key=lambda x: (-x["risk"], x["kev"] is not True, x["cve"], x["asset"].casefold()))

def parse_csv(content):
    if not isinstance(content, str):
        raise ValueError("CSV must be text")
    try:
        reader = csv.DictReader(io.StringIO(content.lstrip("\ufeff")), strict=True)
        if not reader.fieldnames or len(reader.fieldnames) != len(set(reader.fieldnames)) or not set(FIELDS) <= set(reader.fieldnames):
            raise ValueError("CSV requires columns: " + ", ".join(FIELDS))
        rows = []
        for row in reader:
            if None in row or any(v is None for v in row.values()):
                raise ValueError("Malformed CSV row")
            rows.append(row)
            if len(rows) > MAX_ROWS:
                raise ValueError("Too many findings")
        return rows
    except csv.Error as e:
        raise ValueError(f"Invalid CSV: {e}") from None
