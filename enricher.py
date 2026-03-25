import os
import time
import requests

import cache as _cache

IPINFO_BASE = "https://ipinfo.io"
VT_BASE = "https://www.virustotal.com/api/v3/ip_addresses"

_vt_request_times: list[float] = []
VT_RATE_LIMIT = 4
VT_WINDOW = 60.0


def _vt_rate_limit():
    now = time.monotonic()
    _vt_request_times[:] = [t for t in _vt_request_times if now - t < VT_WINDOW]
    if len(_vt_request_times) >= VT_RATE_LIMIT:
        sleep_for = VT_WINDOW - (now - _vt_request_times[0])
        if sleep_for > 0:
            time.sleep(sleep_for)
    _vt_request_times.append(time.monotonic())


def get_ipinfo(ip: str) -> dict:
    cached = _cache.get(ip)
    if cached and "country" in cached and "org" in cached:
        return {k: cached[k] for k in ("country", "org", "hostname") if k in cached}

    token = os.getenv("IPINFO_TOKEN", "")
    try:
        params = {"token": token} if token else {}
        resp = requests.get(f"{IPINFO_BASE}/{ip}/json", params=params, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        result = {
            "country": data.get("country", "Unknown"),
            "org": data.get("org", "Unknown"),
            "hostname": data.get("hostname", "Unknown"),
        }
    except Exception:
        result = {"country": "Unknown", "org": "Unknown", "hostname": "Unknown"}

    _cache.put(ip, **result)
    return result


def get_virustotal(ip: str) -> dict:
    cached = _cache.get(ip)
    if cached and "malicious" in cached and "total" in cached:
        return {k: cached[k] for k in ("malicious", "total", "reputation") if k in cached}

    api_key = os.getenv("VIRUSTOTAL_API_KEY", "")
    if not api_key:
        return {"malicious": 0, "total": 0, "reputation": 0, "error": "no_key"}

    _vt_rate_limit()
    try:
        headers = {"x-apikey": api_key}
        resp = requests.get(f"{VT_BASE}/{ip}", headers=headers, timeout=15)
        resp.raise_for_status()
        attrs = resp.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        result = {
            "malicious": stats.get("malicious", 0),
            "total": sum(stats.values()) if stats else 0,
            "reputation": attrs.get("reputation", 0),
        }
    except Exception:
        result = {"malicious": 0, "total": 0, "reputation": 0, "error": "api_error"}

    _cache.put(ip, **result)
    return result


def enrich(ips: list[str]) -> list[dict]:
    results = []
    for ip in ips:
        info = get_ipinfo(ip)
        vt = get_virustotal(ip)
        results.append({"ip": ip, **info, **vt})
    _cache.flush()
    return results
