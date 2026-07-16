"""Tests for the SQLite scan/disposition store (socbox.store)."""

from __future__ import annotations

import socbox.store as store


def _entry(scan_id: str = "abc") -> dict:
    return {
        "scan_id": scan_id,
        "domain": "x.com",
        "ip": "1.2.3.4",
        "disposition": None,
        "report": {
            "url": "http://x.com",
            "final_url": "http://x.com/final",
            "risk_category": "Malicious",
            "overall_score": 80,
            "confidence": 100,
            "timestamp": "2026-01-01T00:00:00+00:00",
        },
    }


def test_roundtrip(tmp_path) -> None:
    store.init(tmp_path / "t.db")
    store.save_entries([_entry()])
    loaded = store.load_entries()
    assert len(loaded) == 1
    assert loaded[0]["scan_id"] == "abc"
    assert loaded[0].get("disposition") is None


def test_disposition_set_and_preserved_on_resave(tmp_path) -> None:
    store.init(tmp_path / "t.db")
    store.save_entries([_entry()])

    assert store.set_disposition("abc", "TP", "fred", "malicious", "2026-01-01T01:00:00+00:00")
    assert store.load_entries()[0]["disposition"]["disposition"] == "TP"

    # Re-saving scan data must NOT clobber the disposition.
    store.save_entries([_entry()])
    assert store.load_entries()[0]["disposition"]["disposition"] == "TP"

    assert store.disposition_counts().get("TP") == 1


def test_set_disposition_unknown_scan(tmp_path) -> None:
    store.init(tmp_path / "t.db")
    assert store.set_disposition("nope", "FP", "a", "", "t") is False
