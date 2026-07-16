"""Multi-source IP enrichment for SOC Box.

Given one or more IP addresses, gathers live reputation/geo/ASN data from the
OSINT sources SOC analysts already pivot through — VirusTotal, AbuseIPDB,
IPinfo, and (optionally) a local MaxMind GeoLite2 database — and builds the
copyable OSINT links to the same tools. Each source is queried concurrently and
degrades gracefully: a missing API key or a failed lookup yields a
``configured: false`` / ``error`` marker rather than breaking the whole result.

These are *reputation lookups about* the IP (to trusted OSINT APIs); SOC Box never
connects to the target IP here, so there is no SSRF surface. Non-public
addresses are reported but skipped for external lookups (they carry no public
reputation).
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import logging
from typing import Any

import requests

from socbox.config import get_api_key
from socbox.dns_util import is_public_ip
from socbox.feeds.virustotal import scanned_engine_total

logger = logging.getLogger(__name__)

# One (ip, source) lookup per task; bound the pool so a bulk paste of IPs can't
# spawn unbounded concurrent HTTP calls.
_MAX_WORKERS = 8
_MAX_IPS = 50


def _vt_ip(ip: str, config: dict[str, Any], timeout: int) -> dict[str, Any]:
    """VirusTotal IP reputation (live ``last_analysis_stats``)."""
    key = get_api_key(config, "virustotal")
    if not key:
        return {"configured": False}
    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": key},
            timeout=timeout,
        )
    except requests.exceptions.RequestException as exc:
        return {"configured": True, "error": str(exc)}
    if resp.status_code == 404:
        return {"configured": True, "found": False}
    if resp.status_code != 200:
        return {"configured": True, "error": f"HTTP {resp.status_code}"}

    attrs = resp.json().get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    return {
        "configured": True,
        "found": True,
        "malicious": malicious,
        "suspicious": suspicious,
        "detections": malicious + suspicious,
        "total_engines": scanned_engine_total(stats),
        "reputation": attrs.get("reputation"),
        "as_owner": attrs.get("as_owner", ""),
        "asn": attrs.get("asn"),
        "country": attrs.get("country", ""),
        "network": attrs.get("network", ""),
        "link": f"https://www.virustotal.com/gui/ip-address/{ip}",
    }


def _abuseipdb_ip(ip: str, config: dict[str, Any], timeout: int) -> dict[str, Any]:
    """AbuseIPDB abuse-confidence lookup (full data, not just a match verdict)."""
    key = get_api_key(config, "abuseipdb")
    if not key:
        return {"configured": False}
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=timeout,
        )
    except requests.exceptions.RequestException as exc:
        return {"configured": True, "error": str(exc)}
    if resp.status_code != 200:
        return {"configured": True, "error": f"HTTP {resp.status_code}"}

    data = resp.json().get("data", {})
    return {
        "configured": True,
        "found": True,
        "confidence": data.get("abuseConfidenceScore", 0),
        "total_reports": data.get("totalReports", 0),
        "isp": data.get("isp", ""),
        "usage_type": data.get("usageType", ""),
        "domain": data.get("domain", ""),
        "country": data.get("countryCode", ""),
        "is_tor": bool(data.get("isTor", False)),
        "last_reported": data.get("lastReportedAt") or "",
        "link": f"https://www.abuseipdb.com/check/{ip}",
    }


def _ipinfo_ip(ip: str, config: dict[str, Any], timeout: int) -> dict[str, Any]:
    """IPinfo ASN / org / geolocation (works without a token, richer with one)."""
    key = get_api_key(config, "ipinfo")
    params = {"token": key} if key else {}
    try:
        resp = requests.get(
            f"https://ipinfo.io/{ip}/json", params=params, timeout=timeout,
        )
    except requests.exceptions.RequestException as exc:
        return {"configured": True, "error": str(exc)}
    if resp.status_code != 200:
        return {"configured": True, "error": f"HTTP {resp.status_code}"}

    data = resp.json()
    return {
        "configured": True,
        "found": True,
        "hostname": data.get("hostname", ""),
        "org": data.get("org", ""),  # e.g. "AS15169 Google LLC"
        "city": data.get("city", ""),
        "region": data.get("region", ""),
        "country": data.get("country", ""),
        "loc": data.get("loc", ""),
        "timezone": data.get("timezone", ""),
        "link": f"https://ipinfo.io/{ip}",
    }


def _maxmind_geo(ip: str, config: dict[str, Any]) -> dict[str, Any]:
    """Local MaxMind GeoLite2 City lookup — only when a DB path is configured.

    Optional and dependency-light: skipped unless ``geoip2`` is installed and
    ``enrich.maxmind_db`` points at a GeoLite2-City.mmdb, so SOC Box never requires
    the DB just to run the enricher.
    """
    db_path = (config.get("enrich", {}) or {}).get("maxmind_db", "")
    if not db_path:
        return {"configured": False}
    try:
        import geoip2.database  # optional dependency
    except ImportError:
        return {"configured": False, "error": "geoip2 not installed"}
    try:
        with geoip2.database.Reader(db_path) as reader:
            r = reader.city(ip)
            return {
                "configured": True,
                "found": True,
                "city": r.city.name or "",
                "country": r.country.iso_code or "",
                "subdivision": (r.subdivisions.most_specific.name or "")
                if r.subdivisions else "",
                "latitude": r.location.latitude,
                "longitude": r.location.longitude,
            }
    except Exception as exc:  # noqa: BLE001 — geo lookup must never break enrichment
        return {"configured": True, "error": str(exc)}


def osint_links(ip: str) -> list[dict[str, str]]:
    """Copyable OSINT pivot links for an IP (no API key required)."""
    return [
        {"name": "VirusTotal", "url": f"https://www.virustotal.com/gui/ip-address/{ip}"},
        {"name": "AbuseIPDB", "url": f"https://www.abuseipdb.com/check/{ip}"},
        {"name": "IPinfo", "url": f"https://ipinfo.io/{ip}"},
        {"name": "Shodan", "url": f"https://www.shodan.io/host/{ip}"},
        {"name": "GreyNoise", "url": f"https://viz.greynoise.io/ip/{ip}"},
        {"name": "Censys", "url": f"https://search.censys.io/hosts/{ip}"},
        {"name": "Talos", "url": f"https://talosintelligence.com/reputation_center/lookup?search={ip}"},
    ]


# Source functions keyed by the name they appear under in the result.
_SOURCES = {
    "virustotal": _vt_ip,
    "abuseipdb": _abuseipdb_ip,
    "ipinfo": _ipinfo_ip,
}


def enrich_ip(ip: str, config: dict[str, Any]) -> dict[str, Any]:
    """Enrich a single IP across all configured sources (sources run in parallel)."""
    timeout = config.get("requests", {}).get("timeout", 10)

    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {"ip": ip, "valid": False, "error": "Not a valid IP address"}

    if not is_public_ip(ip):
        return {
            "ip": ip, "valid": True, "public": False,
            "note": "Non-public address — no external reputation to look up.",
            "osint_links": [],
        }

    result: dict[str, Any] = {"ip": ip, "valid": True, "public": True, "sources": {}}
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(_SOURCES)) as ex:
        futures = {
            ex.submit(fn, ip, config, timeout): name
            for name, fn in _SOURCES.items()
        }
        for fut in concurrent.futures.as_completed(futures):
            name = futures[fut]
            try:
                result["sources"][name] = fut.result()
            except Exception as exc:  # noqa: BLE001
                result["sources"][name] = {"configured": True, "error": str(exc)}

    maxmind = _maxmind_geo(ip, config)
    if maxmind.get("configured"):
        result["sources"]["maxmind"] = maxmind

    result["osint_links"] = osint_links(ip)
    return result


def enrich_ips(ips: list[str], config: dict[str, Any]) -> list[dict[str, Any]]:
    """Enrich many IPs concurrently, preserving input order (deduplicated).

    Args:
        ips: IP address strings.
        config: The loaded SOC Box configuration.

    Returns:
        One result dict per unique IP, in first-seen order.
    """
    seen: list[str] = []
    for raw in ips:
        ip = (raw or "").strip()
        if ip and ip not in seen:
            seen.append(ip)
    seen = seen[:_MAX_IPS]
    if not seen:
        return []

    results: dict[str, dict[str, Any]] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=_MAX_WORKERS) as ex:
        futures = {ex.submit(enrich_ip, ip, config): ip for ip in seen}
        for fut in concurrent.futures.as_completed(futures):
            ip = futures[fut]
            try:
                results[ip] = fut.result()
            except Exception as exc:  # noqa: BLE001
                results[ip] = {"ip": ip, "valid": True, "error": str(exc)}

    return [results[ip] for ip in seen]
