from __future__ import annotations

import time
import json
import ipaddress
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

import requests

from app import config


@dataclass(frozen=True)
class OsintResult:
    ip: str
    abuse_ok: bool = False
    abuse_score: Optional[float] = None  # 0..100
    vt_ok: bool = False
    vt_score: Optional[float] = None     # 0..100 (malicious ratio)
    error: Optional[str] = None
    raw: Optional[Dict[str, Any]] = None


# Simple in-memory TTL cache: ip -> (expires_at_epoch, OsintResult)
_CACHE: Dict[str, Tuple[float, OsintResult]] = {}


def _is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(str(ip).strip())
        return addr.is_global
    except Exception:
        return False


def _cache_get(ip: str) -> Optional[OsintResult]:
    if not ip:
        return None
    item = _CACHE.get(ip)
    if not item:
        return None
    expires_at, result = item
    if time.time() >= expires_at:
        _CACHE.pop(ip, None)
        return None
    return result


def _cache_set(ip: str, result: OsintResult) -> None:
    ttl = max(int(config.OSINT_CACHE_TTL_SECONDS or 0), 0)
    if ttl <= 0:
        return
    _CACHE[ip] = (time.time() + ttl, result)


def _sleep_rate_limit(resp: requests.Response) -> None:
    retry_after = resp.headers.get("Retry-After")
    if retry_after:
        try:
            time.sleep(max(0.0, float(retry_after)))
            return
        except Exception:
            pass
    time.sleep(2.0)


def check_abuseipdb(ip: str) -> Dict[str, Any]:
    """
    AbuseIPDB IP check.
    Returns dict with:
      - ok: bool
      - score: float|None (0..100 abuseConfidenceScore)
      - error: str|None
      - raw: dict|None
    """
    if not config.ABUSEIPDB_API_KEY:
        return {"ok": False, "score": None, "error": "ABUSEIPDB_API_KEY not set", "raw": None}

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": config.ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""}

    last_err: Optional[str] = None
    for attempt in range(int(config.OSINT_MAX_RETRIES) + 1):
        try:
            resp = requests.get(url, headers=headers, params=params, timeout=10)
            if resp.status_code == 429:
                _sleep_rate_limit(resp)
                continue
            if resp.status_code >= 400:
                last_err = f"AbuseIPDB HTTP {resp.status_code}"
                # transient-ish server errors: retry
                if resp.status_code >= 500 and attempt < int(config.OSINT_MAX_RETRIES):
                    time.sleep(1.0 + attempt)
                    continue
                return {"ok": False, "score": None, "error": last_err, "raw": None}

            data = resp.json()
            score = None
            try:
                score = float((((data or {}).get("data") or {}).get("abuseConfidenceScore")))
            except Exception:
                score = None
            return {"ok": True, "score": score, "error": None, "raw": data}
        except Exception as e:
            last_err = f"AbuseIPDB error: {e}"
            if attempt < int(config.OSINT_MAX_RETRIES):
                time.sleep(1.0 + attempt)
                continue
            return {"ok": False, "score": None, "error": last_err, "raw": None}

    return {"ok": False, "score": None, "error": last_err or "AbuseIPDB failed", "raw": None}


def check_virustotal(ip: str) -> Dict[str, Any]:
    """
    VirusTotal IP report.
    Returns dict with:
      - ok: bool
      - score: float|None (0..100 malicious ratio based on last_analysis_stats)
      - error: str|None
      - raw: dict|None
    """
    if not config.VIRUSTOTAL_API_KEY:
        return {"ok": False, "score": None, "error": "VIRUSTOTAL_API_KEY not set", "raw": None}

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": config.VIRUSTOTAL_API_KEY, "Accept": "application/json"}

    last_err: Optional[str] = None
    for attempt in range(int(config.OSINT_MAX_RETRIES) + 1):
        try:
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code == 429:
                _sleep_rate_limit(resp)
                continue
            if resp.status_code >= 400:
                last_err = f"VirusTotal HTTP {resp.status_code}"
                if resp.status_code >= 500 and attempt < int(config.OSINT_MAX_RETRIES):
                    time.sleep(1.0 + attempt)
                    continue
                return {"ok": False, "score": None, "error": last_err, "raw": None}

            data = resp.json()
            stats = (((data or {}).get("data") or {}).get("attributes") or {}).get("last_analysis_stats") or {}
            malicious = stats.get("malicious", 0) or 0
            harmless = stats.get("harmless", 0) or 0
            suspicious = stats.get("suspicious", 0) or 0
            undetected = stats.get("undetected", 0) or 0
            timeout = stats.get("timeout", 0) or 0
            total = malicious + harmless + suspicious + undetected + timeout
            score = None
            try:
                score = float((malicious / total) * 100.0) if total > 0 else 0.0
            except Exception:
                score = None
            return {"ok": True, "score": score, "error": None, "raw": data}
        except Exception as e:
            last_err = f"VirusTotal error: {e}"
            if attempt < int(config.OSINT_MAX_RETRIES):
                time.sleep(1.0 + attempt)
                continue
            return {"ok": False, "score": None, "error": last_err, "raw": None}

    return {"ok": False, "score": None, "error": last_err or "VirusTotal failed", "raw": None}


def run_osint_checks(ip: str) -> OsintResult:
    """
    Run AbuseIPDB + VirusTotal for a single IP with caching and safe defaults.
    """
    ip = (ip or "").strip()
    if not ip:
        return OsintResult(ip=ip, abuse_ok=False, abuse_score=None, vt_ok=False, vt_score=None, error="missing ip", raw=None)

    if not config.OSINT_ENABLED:
        return OsintResult(ip=ip, abuse_ok=False, abuse_score=None, vt_ok=False, vt_score=None, error="OSINT disabled", raw=None)

    if config.OSINT_SKIP_NON_PUBLIC_IPS and not _is_public_ip(ip):
        return OsintResult(ip=ip, abuse_ok=False, abuse_score=None, vt_ok=False, vt_score=None, error="non-public ip (skipped)", raw=None)

    cached = _cache_get(ip)
    if cached is not None:
        return cached

    abuse = check_abuseipdb(ip)
    vt = check_virustotal(ip)

    abuse_ok = bool(abuse.get("ok"))
    vt_ok = bool(vt.get("ok"))
    abuse_score = abuse.get("score")
    vt_score = vt.get("score")

    err_parts = []
    if not abuse.get("ok"):
        err_parts.append(str(abuse.get("error") or "AbuseIPDB failed"))
    if not vt.get("ok"):
        err_parts.append(str(vt.get("error") or "VirusTotal failed"))
    error = "; ".join(err_parts) if err_parts else None

    raw: Dict[str, Any] = {}
    try:
        raw["abuseipdb"] = abuse.get("raw")
    except Exception:
        raw["abuseipdb"] = None
    try:
        raw["virustotal"] = vt.get("raw")
    except Exception:
        raw["virustotal"] = None

    result = OsintResult(
        ip=ip,
        abuse_ok=abuse_ok,
        abuse_score=abuse_score,
        vt_ok=vt_ok,
        vt_score=vt_score,
        error=error,
        raw=raw,
    )
    _cache_set(ip, result)
    return result


def osint_verdict_from_final_score(final_score: float) -> str:
    if final_score > 70:
        return "Verified Threat"
    if 40 <= final_score <= 70:
        return "Suspicious"
    return "Likely False Positive"


def compute_final_score(ml_confidence: float, abuse_score: Optional[float], vt_score: Optional[float]) -> float:
    """
    All inputs are interpreted as 0..100 (percent-like).
    Missing OSINT scores default to 0 (conservative).
    """
    a = float(abuse_score) if abuse_score is not None else 0.0
    v = float(vt_score) if vt_score is not None else 0.0
    m = float(ml_confidence)
    final = (m * 0.6) + (a * 0.2) + (v * 0.2)
    # Clamp to [0,100]
    return max(0.0, min(100.0, final))

