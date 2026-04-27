import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any


DB_PATH = Path(__file__).resolve().parents[1] / "platform_state.db"
_LOCK = threading.Lock()


def utcnow() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with _LOCK, get_conn() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                profile TEXT NOT NULL DEFAULT 'standard',
                status TEXT NOT NULL DEFAULT 'queued',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                plugin_name TEXT NOT NULL,
                command TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                output_path TEXT,
                exit_code INTEGER,
                started_at TEXT,
                ended_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(scan_id) REFERENCES scans(id)
            );

            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                issue_key TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL DEFAULT 'info',
                confidence INTEGER NOT NULL DEFAULT 30,
                evidence TEXT NOT NULL,
                source TEXT NOT NULL,
                cve TEXT,
                cwe TEXT,
                status TEXT NOT NULL DEFAULT 'open',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(scan_id) REFERENCES scans(id)
            );

            CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_scan_issue
            ON findings(scan_id, issue_key);

            CREATE TABLE IF NOT EXISTS timeline_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                job_id INTEGER,
                decision_id TEXT,
                event TEXT NOT NULL,
                status TEXT NOT NULL,
                detail TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(scan_id) REFERENCES scans(id)
            );
            """
        )


def create_scan(target: str, profile: str = "standard") -> int:
    now = utcnow()
    with _LOCK, get_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO scans(target, profile, status, created_at, updated_at)
            VALUES(?, ?, 'queued', ?, ?)
            """,
            (target, profile, now, now),
        )
        return int(cur.lastrowid)


def update_scan_status(scan_id: int, status: str) -> None:
    now = utcnow()
    with _LOCK, get_conn() as conn:
        conn.execute(
            "UPDATE scans SET status=?, updated_at=? WHERE id=?",
            (status, now, scan_id),
        )


def list_scans(limit: int = 50) -> list[dict[str, Any]]:
    with get_conn() as conn:
        cur = conn.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT ?",
            (limit,),
        )
        return [dict(r) for r in cur.fetchall()]


def create_job(scan_id: int, plugin_name: str, command: str, output_path: str) -> int:
    now = utcnow()
    with _LOCK, get_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO jobs(scan_id, plugin_name, command, status, output_path, created_at, updated_at)
            VALUES(?, ?, ?, 'pending', ?, ?, ?)
            """,
            (scan_id, plugin_name, command, output_path, now, now),
        )
        return int(cur.lastrowid)


def claim_next_job() -> dict[str, Any] | None:
    now = utcnow()
    with _LOCK, get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM jobs WHERE status='pending' ORDER BY id ASC LIMIT 1"
        ).fetchone()
        if not row:
            return None
        conn.execute(
            """
            UPDATE jobs
            SET status='running', started_at=?, updated_at=?
            WHERE id=? AND status='pending'
            """,
            (now, now, row["id"]),
        )
        updated = conn.execute("SELECT * FROM jobs WHERE id=?", (row["id"],)).fetchone()
        return dict(updated) if updated else None


def finish_job(job_id: int, status: str, exit_code: int | None) -> None:
    now = utcnow()
    with _LOCK, get_conn() as conn:
        conn.execute(
            """
            UPDATE jobs
            SET status=?, exit_code=?, ended_at=?, updated_at=?
            WHERE id=?
            """,
            (status, exit_code, now, now, job_id),
        )


def set_job_status(job_id: int, status: str) -> None:
    now = utcnow()
    with _LOCK, get_conn() as conn:
        conn.execute(
            "UPDATE jobs SET status=?, updated_at=? WHERE id=?",
            (status, now, job_id),
        )


def get_job(job_id: int) -> dict[str, Any] | None:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        return dict(row) if row else None


def list_jobs(scan_id: int | None = None, limit: int = 200) -> list[dict[str, Any]]:
    with get_conn() as conn:
        if scan_id is None:
            cur = conn.execute("SELECT * FROM jobs ORDER BY id DESC LIMIT ?", (limit,))
        else:
            cur = conn.execute(
                "SELECT * FROM jobs WHERE scan_id=? ORDER BY id DESC LIMIT ?",
                (scan_id, limit),
            )
        return [dict(r) for r in cur.fetchall()]


def replay_failed_jobs(scan_id: int) -> int:
    now = utcnow()
    with _LOCK, get_conn() as conn:
        cur = conn.execute(
            """
            UPDATE jobs
            SET status='pending', exit_code=NULL, started_at=NULL, ended_at=NULL, updated_at=?
            WHERE scan_id=? AND status IN ('failed', 'blocked', 'awaiting_approval', 'rejected')
            """,
            (now, scan_id),
        )
        return int(cur.rowcount or 0)


def list_approval_jobs(limit: int = 300) -> list[dict[str, Any]]:
    with get_conn() as conn:
        cur = conn.execute(
            """
            SELECT * FROM jobs
            WHERE status='awaiting_approval'
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        )
        return [dict(r) for r in cur.fetchall()]


def approve_job(job_id: int) -> dict[str, Any] | None:
    now = utcnow()
    with _LOCK, get_conn() as conn:
        row = conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        if not row:
            return None
        if row["status"] not in {"awaiting_approval", "blocked", "rejected"}:
            return dict(row)
        conn.execute(
            """
            UPDATE jobs
            SET status='pending', exit_code=NULL, started_at=NULL, ended_at=NULL, updated_at=?
            WHERE id=?
            """,
            (now, job_id),
        )
        updated = conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        return dict(updated) if updated else None


def reject_job(job_id: int, reason: str = "") -> dict[str, Any] | None:
    now = utcnow()
    with _LOCK, get_conn() as conn:
        row = conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        if not row:
            return None
        if row["status"] not in {"awaiting_approval", "pending", "blocked"}:
            return dict(row)
        suffix = f" # rejected_reason={reason}" if reason else " # rejected_reason=unspecified"
        conn.execute(
            """
            UPDATE jobs
            SET status='rejected', command=command || ?, updated_at=?
            WHERE id=?
            """,
            (suffix, now, job_id),
        )
        updated = conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        return dict(updated) if updated else None


def upsert_finding(
    scan_id: int,
    issue_key: str,
    title: str,
    severity: str,
    confidence: int,
    evidence: str,
    source: str,
    cve: str | None = None,
    cwe: str | None = None,
) -> None:
    now = utcnow()
    with _LOCK, get_conn() as conn:
        existing = conn.execute(
            "SELECT * FROM findings WHERE scan_id=? AND issue_key=?",
            (scan_id, issue_key),
        ).fetchone()
        if existing:
            merged_conf = max(int(existing["confidence"]), confidence)
            merged_evidence = f'{existing["evidence"]}\n---\n{evidence}'
            conn.execute(
                """
                UPDATE findings
                SET confidence=?, evidence=?, updated_at=?
                WHERE id=?
                """,
                (merged_conf, merged_evidence, now, existing["id"]),
            )
            return

        conn.execute(
            """
            INSERT INTO findings(
                scan_id, issue_key, title, severity, confidence, evidence, source, cve, cwe, status, created_at, updated_at
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?)
            """,
            (scan_id, issue_key, title, severity, confidence, evidence, source, cve, cwe, now, now),
        )


def list_findings(scan_id: int | None = None, limit: int = 300) -> list[dict[str, Any]]:
    with get_conn() as conn:
        if scan_id is None:
            cur = conn.execute(
                "SELECT * FROM findings ORDER BY confidence DESC, id DESC LIMIT ?",
                (limit,),
            )
        else:
            cur = conn.execute(
                """
                SELECT * FROM findings
                WHERE scan_id=?
                ORDER BY confidence DESC, id DESC LIMIT ?
                """,
                (scan_id, limit),
            )
        return [dict(r) for r in cur.fetchall()]


def append_timeline_event(
    scan_id: int,
    event: str,
    status: str,
    detail: str,
    job_id: int | None = None,
    decision_id: str | None = None,
) -> int:
    now = utcnow()
    with _LOCK, get_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO timeline_events(scan_id, job_id, decision_id, event, status, detail, created_at)
            VALUES(?, ?, ?, ?, ?, ?, ?)
            """,
            (scan_id, job_id, decision_id, event, status, detail, now),
        )
        return int(cur.lastrowid)


def list_timeline_events(scan_id: int | None = None, limit: int = 500) -> list[dict[str, Any]]:
    with get_conn() as conn:
        if scan_id is None:
            cur = conn.execute(
                "SELECT * FROM timeline_events ORDER BY id DESC LIMIT ?",
                (limit,),
            )
        else:
            cur = conn.execute(
                """
                SELECT * FROM timeline_events
                WHERE scan_id=?
                ORDER BY id DESC LIMIT ?
                """,
                (scan_id, limit),
            )
        return [dict(r) for r in cur.fetchall()]
