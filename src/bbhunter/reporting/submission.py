"""Phase 4, step 3: submission.

Hard gate (guardrail #3 in README.md): nothing in this module will ever
call a platform's submit-report endpoint, or even let you record a
finding as submitted, unless `Finding.status == REPORT_APPROVED` -- an
explicit, separately-recorded human decision distinct from PoC approval.

Only HackerOne has a confirmed, documented report-creation endpoint
(`POST /hackers/reports`, see api.hackerone.com/hacker-resources). Bugcrowd's
public API is customer/org-only (see discovery/bugcrowd.py) and Intigriti's
researcher API (api.intigriti.com/external/researcher/swagger/v1/swagger.json,
checked 2026-09-16) is read-only with no submission endpoint at all -- so
for every other platform this always falls back to a manual path: you
paste the drafted report into the platform's own web UI yourself, then
run `bbhunter mark-submitted` to update local state.
"""
from __future__ import annotations

from pathlib import Path

import httpx

from bbhunter.config import HackerOneCreds
from bbhunter.models import Finding, FindingStatus, Platform, Program
from bbhunter.reporting.report import _extract_section

_VALID_SEVERITIES = {"none", "low", "medium", "high", "critical"}


class ManualSubmissionRequired(Exception):
    """Raised when there's no automated submission path -- the caller
    should show the human the report and point them at the platform's
    own UI, then optionally call `mark_submitted_manually`."""


def _require_approved(finding: Finding) -> None:
    if finding.status != FindingStatus.REPORT_APPROVED:
        raise RuntimeError(
            f"{finding.id}: refusing to submit -- status is {finding.status.value}, not report_approved. "
            "Run `bbhunter draft-report` and `bbhunter approve-report` first."
        )


def submit_report(finding: Finding, program: Program) -> Finding:
    _require_approved(finding)
    if not finding.report_path or not Path(finding.report_path).exists():
        raise RuntimeError(f"{finding.id}: no report file on record at {finding.report_path!r}")

    if program.platform != Platform.HACKERONE:
        raise ManualSubmissionRequired(
            f"No confirmed submission API for {program.platform.value}. Submit "
            f"{finding.report_path} manually via {program.url}, then run "
            f"`bbhunter mark-submitted {finding.id} --note '<how/where>'`."
        )

    creds = HackerOneCreds()
    if not creds.configured:
        raise ManualSubmissionRequired(
            "HackerOne credentials not configured (H1_API_USERNAME/H1_API_TOKEN). Submit "
            f"{finding.report_path} manually via {program.url}, then run "
            f"`bbhunter mark-submitted {finding.id} --note '<how/where>'`."
        )

    report_text = Path(finding.report_path).read_text(encoding="utf-8")
    steps = _extract_section(report_text, "Steps to reproduce")
    impact = _extract_section(report_text, "Impact")

    severity = finding.severity if finding.severity in _VALID_SEVERITIES else "none"
    body = {
        "data": {
            "type": "report",
            "attributes": {
                "team_handle": program.handle,
                "title": finding.title,
                "vulnerability_information": steps,
                "impact": impact,
                "severity_rating": severity,
            }
        }
    }
    with httpx.Client(
        base_url="https://api.hackerone.com/v1",
        auth=(creds.username, creds.token),
        timeout=30,
        headers={"Accept": "application/json", "Content-Type": "application/json"},
    ) as client:
        resp = client.post("/hackers/reports", json=body)
        resp.raise_for_status()
        report_id = resp.json().get("data", {}).get("id", "unknown")

    finding.status = FindingStatus.SUBMITTED
    submit_note = f"Submitted to HackerOne as report id={report_id}."
    finding.notes = f"{finding.notes} | {submit_note}" if finding.notes else submit_note
    return finding


def mark_submitted_manually(finding: Finding, *, note: str) -> Finding:
    _require_approved(finding)
    finding.status = FindingStatus.SUBMITTED
    manual_note = f"Manually submitted: {note}"
    finding.notes = f"{finding.notes} | {manual_note}" if finding.notes else manual_note
    return finding
