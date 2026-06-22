"""Tests for the verdict- and artifact-aware KQL query generator."""

from __future__ import annotations

from iris.web.escalation import generate_kql_queries


def _names(queries: list[dict]) -> set[str]:
    return {q["name"] for q in queries}


def _query_for(queries: list[dict], name: str) -> str:
    return next(q["query"] for q in queries if q["name"] == name)


def test_phishing_set_has_url_email_and_signin() -> None:
    qs = generate_kql_queries("evil.com", "https://evil.com/login", category="Malicious")
    assert _names(qs) == {"URL Clicks", "Email Delivery", "Anomalous Sign-in"}
    # Domain is woven into the URL/email queries.
    assert "evil.com" in _query_for(qs, "URL Clicks")
    # The sign-in query uses the clean <UPN> token, never the broken {{UPN}}.
    signin = _query_for(qs, "Anomalous Sign-in")
    assert "<UPN>" in signin
    assert "{{UPN}}" not in signin
    assert "SigninLogs" in signin


def test_download_set_has_device_queries_plus_delivery() -> None:
    fd = {"sha256": "a" * 64, "filename": "bin.sh"}
    qs = generate_kql_queries(
        "mal.icu", "https://mal.icu/bin.sh",
        category="Malicious File Download",
        file_download=fd,
        resolved_ip="182.117.49.195",
    )
    names = _names(qs)
    # Endpoint queries...
    assert {"File on Disk", "File Execution", "Host Connections"} <= names
    # ...plus the delivery queries (the file arrived via a link/email)...
    assert {"URL Clicks", "Email Delivery"} <= names
    # ...and NO sign-in query (no UPN field for pure downloads).
    assert "Anomalous Sign-in" not in names
    # Device queries pivot on the real artifacts.
    assert "a" * 64 in _query_for(qs, "File on Disk")
    assert "bin.sh" in _query_for(qs, "File Execution")
    assert "182.117.49.195" in _query_for(qs, "Host Connections")


def test_download_without_hash_skips_hash_queries_keeps_network() -> None:
    """A Cloudflare-blocked download (no captured file) still gets the network query."""
    qs = generate_kql_queries(
        "mal.icu", "https://mal.icu/dl",
        category="Suspicious File Download",
        file_download={"sha256": "", "filename": ""},
        resolved_ip="1.2.3.4",
    )
    names = _names(qs)
    assert "File on Disk" not in names
    assert "File Execution" not in names
    assert "Host Connections" in names  # keyed on domain/IP
    assert "mal.icu" in _query_for(qs, "Host Connections")


def test_no_upn_placeholder_in_download_set() -> None:
    qs = generate_kql_queries(
        "mal.icu", "https://mal.icu/bin.sh",
        category="Malicious File Download",
        file_download={"sha256": "b" * 64, "filename": "bin.sh"},
    )
    assert all("<UPN>" not in q["query"] for q in qs)
