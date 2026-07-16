"""Tests for the VirusTotal "scanned engine" denominator.

VirusTotal's displayed detection ratio (X / Y) counts only engines that
returned a verdict - harmless / malicious / suspicious / undetected - not the
type-unsupported / failure / timeout / confirmed-timeout buckets. Summing all
of last_analysis_stats inflates the denominator (e.g. 44/74 instead of 44/56).
"""

from __future__ import annotations

from socbox.feeds.virustotal import scanned_engine_total


def test_excludes_non_verdict_categories() -> None:
    """Reproduces the reported case: 44 malicious, real total 56 (not 74)."""
    stats = {
        "malicious": 44,
        "suspicious": 0,
        "undetected": 10,
        "harmless": 2,
        "type-unsupported": 15,
        "failure": 2,
        "timeout": 1,
        "confirmed-timeout": 0,
    }
    assert scanned_engine_total(stats) == 56  # was sum() == 74


def test_clean_file_counts_only_scanners() -> None:
    stats = {
        "harmless": 0,
        "malicious": 0,
        "suspicious": 0,
        "undetected": 70,
        "type-unsupported": 6,
    }
    assert scanned_engine_total(stats) == 70


def test_empty_and_missing_categories() -> None:
    assert scanned_engine_total({}) == 0
    assert scanned_engine_total({"malicious": 3}) == 3
    # Tolerates None / non-int values without blowing up.
    assert scanned_engine_total({"malicious": None, "undetected": 5}) == 5
