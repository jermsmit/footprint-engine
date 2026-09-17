"""
Minimal SQLite persistence. Deliberately simple: one file, no ORM,
no migrations framework. This is a self-hosted single-user tool --
Postgres/Neo4j would be solving problems this project doesn't have yet.
"""
import json
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

DB_PATH = Path(__file__).resolve().parent / "data" / "footprint.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    indicator TEXT NOT NULL,
    indicator_type TEXT NOT NULL,
    created_at REAL NOT NULL,
    finished_at REAL,
    status TEXT NOT NULL DEFAULT 'running',
    total_sources INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    source TEXT NOT NULL,
    category TEXT,
    status TEXT NOT NULL,
    url TEXT,
    details TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE INDEX IF NOT EXISTS idx_results_scan_id ON results(scan_id);
"""


def get_conn() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = get_conn()
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()


def create_scan(indicator: str, indicator_type: str, total_sources: int = 0) -> str:
    scan_id = uuid.uuid4().hex[:12]
    conn = get_conn()
    try:
        conn.execute(
            "INSERT INTO scans (id, indicator, indicator_type, created_at, status, total_sources) "
            "VALUES (?, ?, ?, ?, 'running', ?)",
            (scan_id, indicator, indicator_type, time.time(), total_sources),
        )
        conn.commit()
    finally:
        conn.close()
    return scan_id


def finish_scan(scan_id: str, status: str = "completed") -> None:
    conn = get_conn()
    try:
        conn.execute(
            "UPDATE scans SET status = ?, finished_at = ? WHERE id = ?",
            (status, time.time(), scan_id),
        )
        conn.commit()
    finally:
        conn.close()


def add_result(scan_id: str, result: Dict[str, Any]) -> None:
    conn = get_conn()
    try:
        conn.execute(
            "INSERT INTO results (scan_id, source, category, status, url, details) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                scan_id,
                result.get("source", ""),
                result.get("category", ""),
                result.get("status", "unknown"),
                result.get("url", ""),
                json.dumps(result.get("details", {})),
            ),
        )
        conn.commit()
    finally:
        conn.close()


def get_scan(scan_id: str) -> Optional[Dict[str, Any]]:
    conn = get_conn()
    try:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_results(scan_id: str) -> List[Dict[str, Any]]:
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT * FROM results WHERE scan_id = ? ORDER BY id ASC", (scan_id,)
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["details"] = json.loads(d["details"]) if d["details"] else {}
            except (TypeError, json.JSONDecodeError):
                d["details"] = {}
            out.append(d)
        return out
    finally:
        conn.close()


def get_results_since(scan_id: str, last_id: int) -> List[Dict[str, Any]]:
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT * FROM results WHERE scan_id = ? AND id > ? ORDER BY id ASC",
            (scan_id, last_id),
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["details"] = json.loads(d["details"]) if d["details"] else {}
            except (TypeError, json.JSONDecodeError):
                d["details"] = {}
            out.append(d)
        return out
    finally:
        conn.close()


def recent_scans(limit: int = 25) -> List[Dict[str, Any]]:
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()
