"""Unit tests for the multi-source IP enrichment core (HTTP mocked)."""

from __future__ import annotations

import socbox.enrich as enrich

_CFG = {
    "api_keys": {"virustotal": "k", "abuseipdb": "k", "ipinfo": "k"},
    "requests": {"timeout": 5},
}


class _Resp:
    def __init__(self, status: int, payload: dict) -> None:
        self.status_code = status
        self._payload = payload

    def json(self) -> dict:
        return self._payload


def _fake_get(url: str, **_kw):
    if "virustotal.com" in url:
        return _Resp(200, {"data": {"attributes": {
            "last_analysis_stats": {"malicious": 3, "suspicious": 1,
                                    "undetected": 50, "harmless": 10},
            "as_owner": "Evil LLC", "asn": 666, "country": "RU",
            "network": "1.2.3.0/24", "reputation": -40,
        }}})
    if "abuseipdb.com" in url:
        return _Resp(200, {"data": {
            "abuseConfidenceScore": 85, "totalReports": 42, "isp": "BadHost",
            "usageType": "Data Center", "domain": "evil.com",
            "countryCode": "RU", "isTor": False,
        }})
    if "ipinfo.io" in url:
        return _Resp(200, {
            "hostname": "h.example", "org": "AS666 Evil LLC", "city": "Moscow",
            "region": "Moscow", "country": "RU", "loc": "55,37",
            "timezone": "Europe/Moscow",
        })
    raise AssertionError(f"unexpected URL: {url}")


def test_enrich_public_ip_aggregates_all_sources(monkeypatch):
    monkeypatch.setattr(enrich.requests, "get", _fake_get)
    r = enrich.enrich_ip("8.8.8.8", _CFG)

    assert r["valid"] is True and r["public"] is True
    vt = r["sources"]["virustotal"]
    assert vt["detections"] == 4 and vt["total_engines"] == 64  # 3+1+50+10
    assert vt["as_owner"] == "Evil LLC"
    assert r["sources"]["abuseipdb"]["confidence"] == 85
    assert r["sources"]["ipinfo"]["org"] == "AS666 Evil LLC"
    # OSINT links are always present for a public IP.
    names = {link["name"] for link in r["osint_links"]}
    assert {"VirusTotal", "AbuseIPDB", "Shodan", "GreyNoise"} <= names


def test_invalid_ip_flagged():
    r = enrich.enrich_ip("not-an-ip", _CFG)
    assert r["valid"] is False


def test_private_ip_skips_external_lookups():
    r = enrich.enrich_ip("10.0.0.5", _CFG)
    assert r["valid"] is True and r["public"] is False
    assert "sources" not in r  # no external calls made
    assert r["osint_links"] == []


def test_missing_key_reports_unconfigured(monkeypatch):
    monkeypatch.setattr(enrich.requests, "get", _fake_get)
    r = enrich.enrich_ip("8.8.8.8", {"api_keys": {}, "requests": {"timeout": 5}})
    assert r["sources"]["virustotal"] == {"configured": False}
    assert r["sources"]["abuseipdb"] == {"configured": False}
    # IPinfo works without a key (token just enriches it).
    assert r["sources"]["ipinfo"]["found"] is True


def test_enrich_ips_dedupes_and_preserves_order(monkeypatch):
    monkeypatch.setattr(enrich.requests, "get", _fake_get)
    results = enrich.enrich_ips(["8.8.8.8", "1.1.1.1", "8.8.8.8", "  "], _CFG)
    assert [r["ip"] for r in results] == ["8.8.8.8", "1.1.1.1"]


def test_source_error_does_not_break_result(monkeypatch):
    def _boom_vt(url, **kw):
        if "virustotal.com" in url:
            return _Resp(503, {})
        return _fake_get(url, **kw)

    monkeypatch.setattr(enrich.requests, "get", _boom_vt)
    r = enrich.enrich_ip("8.8.8.8", _CFG)
    assert r["sources"]["virustotal"] == {"configured": True, "error": "HTTP 503"}
    assert r["sources"]["abuseipdb"]["confidence"] == 85  # others still succeed
