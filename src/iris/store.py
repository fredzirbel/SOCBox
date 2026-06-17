"""SQLite persistence for IRIS scans and analyst dispositions.

Durable backing store for the scan cache so scans **and** analyst dispositions
(TP / Benign TP / FP) survive restarts and form a queryable verdict history for
accuracy reporting — something the previous flat JSON cache couldn't provide.

Each scan is stored as its serialized entry (same shape the JSON cache used) in
``entry_json``, plus indexed columns (verdict, score, disposition, …). The
disposition columns are authoritative: re-saving a scan never clobbers a
disposition, and dispositions are updated independently of scan data.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

_lock = threading.Lock()
_db_path: Path | None = None

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id          TEXT PRIMARY KEY,
    url              TEXT,
    final_url        TEXT,
    verdict          TEXT,
    score            REAL,
    confidence       REAL,
    created_at       TEXT,
    disposition      TEXT,
    disposition_by   TEXT,
    disposition_at   TEXT,
    disposition_note TEXT,
    entry_json       TEXT NOT NULL
);
"""


def init(db_path: str | Path) -> None:
    """Initialise the store and create the schema if needed."""
    global _db_path
    _db_path = Path(db_path)
    _db_path.parent.mkdir(parents=True, exist_ok=True)
    with _lock, _connect() as conn:
        conn.execute(_SCHEMA)


def _connect() -> sqlite3.Connection:
    return sqlite3.connect(str(_db_path), timeout=10)


def save_entries(entries: list[dict[str, Any]]) -> None:
    """Upsert serialized scan entries. Never overwrites disposition columns."""
    if _db_path is None:
        return
    with _lock, _connect() as conn:
        for e in entries:
            rep = e.get("report", {}) or {}
            conn.execute(
                """
                INSERT INTO scans
                    (scan_id, url, final_url, verdict, score, confidence,
                     created_at, entry_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(scan_id) DO UPDATE SET
                    url=excluded.url, final_url=excluded.final_url,
                    verdict=excluded.verdict, score=excluded.score,
                    confidence=excluded.confidence, entry_json=excluded.entry_json
                """,
                (
                    e.get("scan_id"),
                    rep.get("url", ""),
                    rep.get("final_url", ""),
                    rep.get("risk_category", ""),
                    rep.get("overall_score"),
                    rep.get("confidence"),
                    rep.get("timestamp", ""),
                    json.dumps(e, default=str),
                ),
            )


def load_entries() -> list[dict[str, Any]]:
    """Return all stored scan entries (with disposition merged in)."""
    if _db_path is None:
        return []
    with _lock, _connect() as conn:
        rows = conn.execute(
            "SELECT entry_json, disposition, disposition_by, disposition_at, "
            "disposition_note FROM scans"
        ).fetchall()
    out: list[dict[str, Any]] = []
    for entry_json, disp, by, at, note in rows:
        try:
            entry = json.loads(entry_json)
        except Exception:
            continue
        if disp:
            entry["disposition"] = {
                "disposition": disp, "by": by, "at": at, "note": note,
            }
        out.append(entry)
    return out


def set_disposition(
    scan_id: str, disposition: str, by: str, note: str, at: str,
) -> bool:
    """Set/replace a scan's analyst disposition. Returns False if scan unknown."""
    if _db_path is None:
        return False
    with _lock, _connect() as conn:
        cur = conn.execute(
            "UPDATE scans SET disposition=?, disposition_by=?, disposition_at=?, "
            "disposition_note=? WHERE scan_id=?",
            (disposition, by, at, note, scan_id),
        )
        return cur.rowcount > 0


def disposition_counts() -> dict[str, int]:
    """Return counts per disposition (for the accuracy story / dashboards)."""
    if _db_path is None:
        return {}
    with _lock, _connect() as conn:
        rows = conn.execute(
            "SELECT disposition, COUNT(*) FROM scans WHERE disposition IS NOT NULL "
            "GROUP BY disposition"
        ).fetchall()
    return {d: n for d, n in rows}
