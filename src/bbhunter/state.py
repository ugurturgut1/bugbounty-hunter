from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path

from datetime import datetime, timedelta

from bbhunter.config import DB_PATH
from bbhunter.models import AIEndpointConfig, AssetType, Finding, Program, ReconResult, TestRun


def _seed_count(program: Program) -> int:
    return sum(1 for a in program.in_scope if a.asset_type in (AssetType.URL, AssetType.WILDCARD))

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

CREATE TABLE IF NOT EXISTS recon_results (
    program_key TEXT PRIMARY KEY,
    data TEXT NOT NULL,
    last_run TEXT NOT NULL,
    FOREIGN KEY (program_key) REFERENCES programs(key)
);

CREATE TABLE IF NOT EXISTS ai_endpoints (
    program_key TEXT PRIMARY KEY,
    data TEXT NOT NULL,
    FOREIGN KEY (program_key) REFERENCES programs(key)
);

CREATE TABLE IF NOT EXISTS test_runs (
    id TEXT PRIMARY KEY,
    program_key TEXT NOT NULL,
    ran_at TEXT NOT NULL,
    data TEXT NOT NULL,
    FOREIGN KEY (program_key) REFERENCES programs(key)
);

CREATE TABLE IF NOT EXISTS recon_snapshots (
    program_key TEXT NOT NULL,
    ran_at TEXT NOT NULL,
    hosts TEXT NOT NULL,       -- JSON list of fingerprinted hosts at this run
    subdomains TEXT NOT NULL,  -- JSON list of all discovered subdomains at this run
    PRIMARY KEY (program_key, ran_at)
);
"""


# Freshness columns added after the original schema shipped, so they go on
# via ALTER TABLE for already-populated DBs rather than a destructive
# recreate. Kept out of model_dump JSON so they're real, queryable columns.
_PROGRAM_FRESHNESS_COLUMNS = {
    "first_seen": "TEXT",          # when this program key was first inserted -- "newly-launched" signal
    "seed_count": "INTEGER",       # URL/WILDCARD asset count at last sync, to detect scope growth
    "scope_expanded_at": "TEXT",   # last sync where seed_count grew vs. the stored value
}


def _migrate(conn: sqlite3.Connection) -> None:
    existing = {row[1] for row in conn.execute("PRAGMA table_info(programs)")}
    for col, coltype in _PROGRAM_FRESHNESS_COLUMNS.items():
        if col not in existing:
            conn.execute(f"ALTER TABLE programs ADD COLUMN {col} {coltype}")


@contextmanager
def connect(db_path: Path = DB_PATH):
    conn = sqlite3.connect(db_path)
    conn.executescript(_SCHEMA)
    _migrate(conn)
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def upsert_program(program: Program, db_path: Path = DB_PATH) -> None:
    now = program.last_synced.isoformat()
    new_seeds = _seed_count(program)
    with connect(db_path) as conn:
        row = conn.execute(
            "SELECT first_seen, seed_count, scope_expanded_at FROM programs WHERE key=?", (program.key,)
        ).fetchone()
        if row is None:
            first_seen, scope_expanded_at = now, None
        else:
            first_seen = row[0] or now
            prev_seeds, scope_expanded_at = row[1], row[2]
            if prev_seeds is not None and new_seeds > prev_seeds:
                scope_expanded_at = now  # scope grew since last sync -- fresh attack surface
        conn.execute(
            "INSERT INTO programs (key, platform, handle, data, last_synced, first_seen, seed_count, scope_expanded_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(key) DO UPDATE SET data=excluded.data, last_synced=excluded.last_synced, "
            "first_seen=excluded.first_seen, seed_count=excluded.seed_count, scope_expanded_at=excluded.scope_expanded_at",
            (program.key, program.platform.value, program.handle, program.model_dump_json(), now,
             first_seen, new_seeds, scope_expanded_at),
        )


_TERMINAL_OUTCOMES = {"submitted", "resolved", "duplicate", "informative"}


def program_outcome_stats(db_path: Path = DB_PATH) -> dict[str, dict]:
    """Aggregate per-program submission outcomes from the findings table:
    counts of submitted/resolved/duplicate/informative and total bounty.
    Only findings that reached a terminal outcome are counted -- a fresh
    DB with none simply returns {}."""
    stats: dict[str, dict] = {}
    for f in list_findings(db_path=db_path):
        if f.status.value not in _TERMINAL_OUTCOMES:
            continue
        s = stats.setdefault(f.program_key, {
            "submitted": 0, "resolved": 0, "duplicate": 0, "informative": 0, "bounty_total": 0.0,
        })
        s[f.status.value] = s.get(f.status.value, 0) + 1
        if f.bounty_amount:
            s["bounty_total"] += f.bounty_amount
    return stats


def check_outcome_stats(db_path: Path = DB_PATH) -> dict[str, dict]:
    """Same aggregation but keyed by vuln_class -- the signal-to-noise of
    each check type across every program (which classes get resolved vs.
    closed duplicate/informative), so low-yield checks can be deprioritized."""
    stats: dict[str, dict] = {}
    for f in list_findings(db_path=db_path):
        if f.status.value not in _TERMINAL_OUTCOMES:
            continue
        s = stats.setdefault(f.vuln_class, {
            "submitted": 0, "resolved": 0, "duplicate": 0, "informative": 0, "bounty_total": 0.0,
        })
        s[f.status.value] = s.get(f.status.value, 0) + 1
        if f.bounty_amount:
            s["bounty_total"] += f.bounty_amount
    return stats


def fresh_program_keys(within_days: int = 14, db_path: Path = DB_PATH) -> tuple[set[str], set[str]]:
    """Return (newly_seen, recently_expanded) program keys within the
    window. 'Newly seen' = first_seen inside the window (an unpicked new
    program); 'recently expanded' = scope_expanded_at inside the window
    (fresh attack surface on an existing program). Rows predating the
    freshness columns have NULLs and simply don't match -- never an error."""
    cutoff = (datetime.utcnow() - timedelta(days=within_days)).isoformat()
    newly_seen: set[str] = set()
    expanded: set[str] = set()
    with connect(db_path) as conn:
        for key, first_seen, expanded_at in conn.execute(
            "SELECT key, first_seen, scope_expanded_at FROM programs"
        ):
            if first_seen and first_seen >= cutoff:
                newly_seen.add(key)
            if expanded_at and expanded_at >= cutoff:
                expanded.add(key)
    return newly_seen, expanded


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


def get_finding(finding_id: str, db_path: Path = DB_PATH) -> Finding | None:
    with connect(db_path) as conn:
        row = conn.execute("SELECT data FROM findings WHERE id = ?", (finding_id,)).fetchone()
    return Finding.model_validate_json(row[0]) if row else None


def list_findings(status: str | None = None, db_path: Path = DB_PATH) -> list[Finding]:
    with connect(db_path) as conn:
        if status:
            rows = conn.execute("SELECT data FROM findings WHERE status = ? ORDER BY id", (status,)).fetchall()
        else:
            rows = conn.execute("SELECT data FROM findings ORDER BY id").fetchall()
    return [Finding.model_validate_json(row[0]) for row in rows]


def upsert_recon_result(result: ReconResult, db_path: Path = DB_PATH) -> None:
    hosts = sorted(result.fingerprints.keys())
    subs = sorted({s for subs in result.subdomains.values() for s in subs})
    with connect(db_path) as conn:
        conn.execute(
            "INSERT INTO recon_results (program_key, data, last_run) VALUES (?, ?, ?) "
            "ON CONFLICT(program_key) DO UPDATE SET data=excluded.data, last_run=excluded.last_run",
            (result.program_key, result.model_dump_json(), result.last_run.isoformat()),
        )
        # Append an immutable snapshot each run, so `recon_diff` can show what
        # changed since last time -- where fresh bugs tend to appear.
        conn.execute(
            "INSERT OR REPLACE INTO recon_snapshots (program_key, ran_at, hosts, subdomains) VALUES (?, ?, ?, ?)",
            (result.program_key, result.last_run.isoformat(), json.dumps(hosts), json.dumps(subs)),
        )


def recon_diff(program_key: str, db_path: Path = DB_PATH) -> dict | None:
    """Compare the two most recent recon snapshots for a program. Returns
    {new_hosts, removed_hosts, new_subdomains, removed_subdomains, prev_run,
    curr_run} or None if there aren't two snapshots yet to compare."""
    with connect(db_path) as conn:
        rows = conn.execute(
            "SELECT ran_at, hosts, subdomains FROM recon_snapshots WHERE program_key=? ORDER BY ran_at DESC LIMIT 2",
            (program_key,),
        ).fetchall()
    if len(rows) < 2:
        return None
    curr, prev = rows[0], rows[1]
    curr_hosts, prev_hosts = set(json.loads(curr[1])), set(json.loads(prev[1]))
    curr_subs, prev_subs = set(json.loads(curr[2])), set(json.loads(prev[2]))
    return {
        "prev_run": prev[0],
        "curr_run": curr[0],
        "new_hosts": sorted(curr_hosts - prev_hosts),
        "removed_hosts": sorted(prev_hosts - curr_hosts),
        "new_subdomains": sorted(curr_subs - prev_subs),
        "removed_subdomains": sorted(prev_subs - curr_subs),
    }


def get_recon_result(program_key: str, db_path: Path = DB_PATH) -> ReconResult | None:
    with connect(db_path) as conn:
        row = conn.execute("SELECT data FROM recon_results WHERE program_key = ?", (program_key,)).fetchone()
    return ReconResult.model_validate_json(row[0]) if row else None


def list_reconned_program_keys(db_path: Path = DB_PATH) -> set[str]:
    with connect(db_path) as conn:
        rows = conn.execute("SELECT program_key FROM recon_results").fetchall()
    return {row[0] for row in rows}


def upsert_ai_endpoint(config: AIEndpointConfig, db_path: Path = DB_PATH) -> None:
    with connect(db_path) as conn:
        conn.execute(
            "INSERT INTO ai_endpoints (program_key, data) VALUES (?, ?) "
            "ON CONFLICT(program_key) DO UPDATE SET data=excluded.data",
            (config.program_key, config.model_dump_json()),
        )


def get_ai_endpoint(program_key: str, db_path: Path = DB_PATH) -> AIEndpointConfig | None:
    with connect(db_path) as conn:
        row = conn.execute("SELECT data FROM ai_endpoints WHERE program_key = ?", (program_key,)).fetchone()
    return AIEndpointConfig.model_validate_json(row[0]) if row else None


def record_test_run(run: TestRun, db_path: Path = DB_PATH) -> None:
    with connect(db_path) as conn:
        conn.execute(
            "INSERT INTO test_runs (id, program_key, ran_at, data) VALUES (?, ?, ?, ?)",
            (run.id, run.program_key, run.ran_at.isoformat(), run.model_dump_json()),
        )


def list_test_runs(program_key: str, db_path: Path = DB_PATH) -> list[TestRun]:
    with connect(db_path) as conn:
        rows = conn.execute(
            "SELECT data FROM test_runs WHERE program_key = ? ORDER BY ran_at", (program_key,)
        ).fetchall()
    return [TestRun.model_validate_json(row[0]) for row in rows]
