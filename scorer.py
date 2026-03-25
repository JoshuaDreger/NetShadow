"""Rule-based IP risk scorer — no external AI API required."""

from collections import Counter

# High-risk country codes (common sources of malicious traffic)
_HIGH_RISK_COUNTRIES = {
    "CN", "RU", "KP", "IR", "SY", "CU", "VE", "BY",
}

# Keywords in org/ASN that suggest hosting/VPN/proxy infrastructure
_SUSPICIOUS_ORG_KEYWORDS = [
    "bulletproof", "vpn", "proxy", "tor", "hosting", "colocation",
    "colo", "datacenter", "data center", "vps", "anonymous", "offshore",
]


def _score_ip(ip: dict) -> tuple[str, str]:
    """Return (risk_level, reasoning) for a single enriched IP dict."""
    malicious = ip.get("malicious", 0) or 0
    total = ip.get("total", 0) or 0
    reputation = ip.get("reputation", 0) or 0
    country = (ip.get("country") or "").upper()
    org = (ip.get("org") or "").lower()
    vt_available = total > 0

    # --- VirusTotal-based rules (highest priority) ---
    if vt_available:
        if malicious >= 10:
            return "Critical", f"Flagged as malicious by {malicious}/{total} VirusTotal engines."
        if malicious >= 5:
            return "High", f"Detected by {malicious}/{total} VirusTotal engines."
        if malicious >= 2:
            return "Medium", f"Detected by {malicious}/{total} VirusTotal engines."
        if malicious == 1:
            return "Low", f"Flagged by 1/{total} VirusTotal engine; treat as suspicious."

    # --- Reputation score (negative = bad) ---
    if reputation <= -50:
        return "Critical", f"VirusTotal reputation score is severely negative ({reputation})."
    if reputation <= -20:
        return "High", f"VirusTotal reputation score is negative ({reputation})."
    if reputation < 0:
        return "Medium", f"VirusTotal reputation score is slightly negative ({reputation})."

    # --- Country-based risk ---
    if country in _HIGH_RISK_COUNTRIES:
        if vt_available:
            return "Low", f"No VT detections but originates from high-risk country ({country})."
        return "Medium", f"No VT data available and originates from high-risk country ({country})."

    # --- Org/ASN heuristics ---
    for keyword in _SUSPICIOUS_ORG_KEYWORDS:
        if keyword in org:
            return "Low", f"IP belongs to an org associated with hosting/anonymization services ({ip.get('org')})."

    # --- No VT data at all ---
    if not vt_available:
        return "Low", "No VirusTotal data available; unable to fully assess — treat with caution."

    return "Clean", f"No detections across {total} VirusTotal engines and no other risk indicators."


def _executive_summary(scored: list[dict]) -> str:
    total = len(scored)
    if total == 0:
        return "No external IPs were found in the capture."

    dist = Counter(ip["risk_level"] for ip in scored)
    critical = dist.get("Critical", 0)
    high = dist.get("High", 0)
    medium = dist.get("Medium", 0)
    low = dist.get("Low", 0)
    clean = dist.get("Clean", 0)

    lines = [
        f"The capture contained {total} unique external endpoint(s). "
        f"Distribution: {critical} Critical, {high} High, {medium} Medium, {low} Low, {clean} Clean."
    ]

    if critical > 0:
        bad = [ip["ip"] for ip in scored if ip["risk_level"] == "Critical"]
        lines.append(f"CRITICAL threat(s) detected — immediate investigation recommended for: {', '.join(bad)}.")
    elif high > 0:
        bad = [ip["ip"] for ip in scored if ip["risk_level"] == "High"]
        lines.append(f"High-risk IPs detected that warrant prompt review: {', '.join(bad)}.")
    elif medium > 0:
        lines.append("Several medium-risk IPs were identified; further investigation is advisable.")
    else:
        lines.append("No significant threats detected; the capture appears largely benign.")

    return " ".join(lines)


def score_ips(enriched: list[dict]) -> tuple[list[dict], str]:
    """
    Returns (scored_ips, executive_summary).
    Each scored IP dict has all original fields plus 'risk_level' and 'reasoning'.
    """
    scored = []
    for ip in enriched:
        risk_level, reasoning = _score_ip(ip)
        scored.append({**ip, "risk_level": risk_level, "reasoning": reasoning})

    # Sort by severity: Critical first
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Clean": 4, "Unknown": 5}
    scored.sort(key=lambda x: order.get(x["risk_level"], 5))

    return scored, _executive_summary(scored)
