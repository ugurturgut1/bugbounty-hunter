"""Append-only audit log of every check this tool runs against a program.

The state DB's `test_runs` table is mutable and internal; this is a
separate, append-only JSONL file (one line per check execution, never
rewritten) meant to be exportable as a good-faith-conduct record you can
show a program if they ever ask what you did and when. Each line records
the timestamp, program, check type, and a human-readable detail of what
was targeted.

It is written at check-execution granularity (which check ran against
which program/targets, when) via the single `_log_test_run` hook every
active command already calls -- not per individual HTTP request, which
would need routing every request through one client.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from bbhunter.config import DATA_DIR

AUDIT_FILE = DATA_DIR / "audit.jsonl"


def append_audit(program_key: str, test_type: str, detail: str) -> None:
    """Append one immutable audit record. Best-effort: a logging failure
    must never break the check that triggered it."""
    rec = {
        "ts": datetime.utcnow().isoformat(),
        "program_key": program_key,
        "test_type": test_type,
        "detail": detail,
    }
    try:
        with AUDIT_FILE.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")
    except OSError:
        pass


def read_audit(program_key: str | None = None, *, path: Path = AUDIT_FILE) -> list[dict]:
    """Return audit records (optionally filtered to one program), oldest
    first. Missing/unreadable file -> []."""
    if not path.exists():
        return []
    out: list[dict] = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if program_key is None or rec.get("program_key") == program_key:
                out.append(rec)
    except OSError:
        return []
    return out


def export_markdown(program_key: str | None = None, *, path: Path = AUDIT_FILE) -> str:
    """Render the audit records as a readable markdown table."""
    records = read_audit(program_key, path=path)
    title = f"# Audit log{f' - {program_key}' if program_key else ''} ({len(records)} entries)"
    lines = [title, "", "| Timestamp (UTC) | Program | Check | Detail |", "|---|---|---|---|"]
    for r in records:
        lines.append(f"| {r.get('ts','')[:19]} | {r.get('program_key','')} | {r.get('test_type','')} | {r.get('detail','')} |")
    return "\n".join(lines) + "\n"
