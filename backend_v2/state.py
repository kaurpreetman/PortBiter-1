import json
import os
import sqlite3
from datetime import datetime, timezone
from typing import Dict, List, Optional

DB_PATH = os.path.join(os.path.dirname(__file__), "scan_state.db")


def _get_connection():
    connection = sqlite3.connect(DB_PATH, check_same_thread=False)
    connection.row_factory = sqlite3.Row
    return connection


def _init_db():
    conn = _get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            scan_id TEXT PRIMARY KEY,
            target_url TEXT NOT NULL,
            status TEXT NOT NULL,
            progress INTEGER NOT NULL,
            vulnerabilities TEXT NOT NULL,
            visited_urls TEXT NOT NULL,
            logs TEXT NOT NULL,
            started_at TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


class ScanState:
    def __init__(
        self,
        target_url: str,
        scan_id: Optional[str] = None,
        status: str = "running",
        progress: int = 0,
        vulnerabilities: Optional[List[dict]] = None,
        visited_urls: Optional[List[str]] = None,
        logs: Optional[List[str]] = None,
        started_at: Optional[str] = None,
    ):
        self.scan_id = scan_id
        self.target_url = target_url
        self.visited_urls = visited_urls or []
        self.vulnerabilities = vulnerabilities or []
        self.logs = logs or []
        self.status = status
        self.progress = progress
        self.started_at = started_at or datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "target_url": self.target_url,
            "status": self.status,
            "progress": self.progress,
            "vulnerabilities": self.vulnerabilities,
            "visited_urls": self.visited_urls,
            "logs": self.logs,
            "started_at": self.started_at,
        }

    def save(self) -> None:
        conn = _get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO scans (scan_id, target_url, status, progress, vulnerabilities, visited_urls, logs, started_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(scan_id) DO UPDATE SET
                target_url=excluded.target_url,
                status=excluded.status,
                progress=excluded.progress,
                vulnerabilities=excluded.vulnerabilities,
                visited_urls=excluded.visited_urls,
                logs=excluded.logs,
                started_at=excluded.started_at
            """,
            (
                self.scan_id,
                self.target_url,
                self.status,
                self.progress,
                json.dumps(self.vulnerabilities),
                json.dumps(self.visited_urls),
                json.dumps(self.logs),
                self.started_at,
            ),
        )
        conn.commit()
        conn.close()

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "ScanState":
        return cls(
            target_url=row["target_url"],
            scan_id=row["scan_id"],
            status=row["status"],
            progress=int(row["progress"]),
            vulnerabilities=json.loads(row["vulnerabilities"]),
            visited_urls=json.loads(row["visited_urls"]),
            logs=json.loads(row["logs"]),
            started_at=row["started_at"],
        )


state_db: Dict[str, ScanState] = {}


def load_state_db() -> None:
    _init_db()
    conn = _get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans")
    rows = cursor.fetchall()
    for row in rows:
        scan_state = ScanState.from_row(row)
        state_db[scan_state.scan_id] = scan_state
    conn.close()


load_state_db()
