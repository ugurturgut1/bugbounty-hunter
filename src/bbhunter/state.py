from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path

from bbhunter.config import DB_PATH
from bbhunter.models import Finding, Program

_SCHEMA = """
CREATE TABLE IF NOT EXISTS programs (
    key TEXT PRIMARY KEY,
    platform TEXT NOT NULL,
    handle TEXT NOT NULL,
    data TEXT NOT NULL,
    last_synced TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    program_key TEXT NOT NULL,
    status TEXT NOT NULL,
    data TEXT NOT NULL,
    FOREIGN KEY (program_key) REFERENCES programs(key)
);
"""


@contextmanager
def connect(db_path: Path = DB_PATH):
    conn = sqlite3.connect(db_path)
    conn.executescript(_SCHEMA)
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def upsert_program(program: Program, db_path: Path = DB_PATH) -> None:
    with connect(db_path) as conn:
        conn.execute(
            "INSERT INTO programs (key, platform, handle, data, last_synced) VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(key) DO UPDATE SET data=excluded.data, last_synced=excluded.last_synced",
            (program.key, program.platform.value, program.handle, program.model_dump_json(), program.last_synced.isoformat()),
        )


def list_programs(db_path: Path = DB_PATH) -> list[Program]:
    with connect(db_path) as conn:
        rows = conn.execute("SELECT data FROM programs ORDER BY key").fetchall()
    return [Program.model_validate_json(row[0]) for row in rows]


def get_program(key: str, db_path: Path = DB_PATH) -> Program | None:
    with connect(db_path) as conn:
        row = conn.execute("SELECT data FROM programs WHERE key = ?", (key,)).fetchone()
    return Program.model_validate_json(row[0]) if row else None


def upsert_finding(finding: Finding, db_path: Path = DB_PATH) -> None:
    with connect(db_path) as conn:
        conn.execute(
            "INSERT INTO findings (id, program_key, status, data) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(id) DO UPDATE SET status=excluded.status, data=excluded.data",
            (finding.id, finding.program_key, finding.status.value, finding.model_dump_json()),
        )


def list_findings(status: str | None = None, db_path: Path = DB_PATH) -> list[Finding]:
    with connect(db_path) as conn:
        if status:
            rows = conn.execute("SELECT data FROM findings WHERE status = ? ORDER BY id", (status,)).fetchall()
        else:
            rows = conn.execute("SELECT data FROM findings ORDER BY id").fetchall()
    return [Finding.model_validate_json(row[0]) for row in rows]
