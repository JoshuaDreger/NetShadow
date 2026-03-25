"""
Persistent IP enrichment cache.

Stores hostname, ipinfo, and VirusTotal results to disk so repeated runs
and dashboard sessions never re-query an IP that was looked up recently.

Cache file: ~/.cache/netshadow/ip_cache.json
TTL:        NETSHADOW_CACHE_TTL env var (seconds), default 86400 (24 h)
"""

import json
import os
import threading
import time
from pathlib import Path

CACHE_FILE = Path(
    os.getenv("NETSHADOW_CACHE", Path.home() / ".cache" / "netshadow" / "ip_cache.json")
)
TTL = int(os.getenv("NETSHADOW_CACHE_TTL", str(24 * 3600)))

_lock = threading.Lock()
_data: dict = {}
_dirty = False


def _load():
    global _data
    try:
        if CACHE_FILE.exists():
            _data = json.loads(CACHE_FILE.read_text())
    except Exception:
        _data = {}


def get(ip: str) -> dict | None:
    """Return cached fields for ip if the entry is still fresh, else None."""
    with _lock:
        entry = _data.get(ip)
    if entry is None:
        return None
    if time.time() - entry.get("_ts", 0) > TTL:
        return None
    return entry


def put(ip: str, **fields):
    """Merge fields into the cache entry for ip and mark dirty."""
    global _dirty
    with _lock:
        existing = dict(_data.get(ip, {}))
        existing.update(fields)
        existing["_ts"] = time.time()
        _data[ip] = existing
        _dirty = True


def flush():
    """Write cache to disk if anything changed since last flush."""
    global _dirty
    with _lock:
        if not _dirty:
            return
        try:
            CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
            CACHE_FILE.write_text(json.dumps(_data, indent=2))
            _dirty = False
        except Exception:
            pass


def stats() -> tuple[int, int]:
    """Return (total_entries, fresh_entries)."""
    now = time.time()
    with _lock:
        total = len(_data)
        fresh = sum(1 for e in _data.values() if now - e.get("_ts", 0) <= TTL)
    return total, fresh


_load()
