"""Tests for the SSRF guard (netguard.target_block_reason)."""

from __future__ import annotations

from iris.netguard import target_block_reason as block


def test_blocks_loopback_and_localhost() -> None:
    assert block("http://127.0.0.1/") is not None
    assert block("http://localhost/") is not None
    assert block("http://[::1]:6080/") is not None


def test_blocks_private_ranges() -> None:
    assert block("http://10.0.0.5/admin") is not None
    assert block("http://192.168.1.1/") is not None
    assert block("https://172.16.0.10/") is not None


def test_blocks_cloud_metadata() -> None:
    assert block("http://169.254.169.254/latest/meta-data/") is not None


def test_blocks_non_http_schemes() -> None:
    assert "scheme" in (block("ftp://example.com/") or "")
    assert "scheme" in (block("file:///etc/passwd") or "")


def test_allows_public_addresses() -> None:
    assert block("https://1.1.1.1/") is None
    assert block("https://8.8.8.8/") is None


def test_allowlist_exempts_host() -> None:
    assert block("http://10.0.0.5/", allowlist=["10.0.0.5"]) is None


def test_master_switch_off_allows_everything() -> None:
    assert block("http://127.0.0.1/", block_private=False) is None


def test_empty_host_blocked() -> None:
    assert block("https://") is not None
