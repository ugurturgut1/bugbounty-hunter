"""These tests protect the three-gate PoC/report/submission workflow.
Each function here must refuse to run out of order -- that's guardrail
#3 (README.md): nothing calls a platform's submit endpoint, or even lets
a report be drafted, without the preceding human approval already on
record as a FindingStatus transition."""
import pytest

import bbhunter.reporting.poc as poc_mod
import bbhunter.reporting.report as report_mod
import bbhunter.reporting.submission as submission_mod
from bbhunter.models import FindingStatus
from bbhunter.reporting.poc import draft_poc
from bbhunter.reporting.report import draft_report
from bbhunter.reporting.submission import (
    ManualSubmissionRequired,
    mark_submitted_manually,
    submit_report,
)


class _UnconfiguredCreds:
    """Always reports not-configured, regardless of the real .env this
    dev machine has real HackerOne credentials in -- tests must never be
    able to fire a real request against api.hackerone.com."""

    username = None
    token = None
    configured = False


@pytest.fixture(autouse=True)
def isolated_dirs(tmp_path, monkeypatch):
    monkeypatch.setattr(poc_mod, "POC_DIR", tmp_path / "pocs")
    poc_mod.POC_DIR.mkdir()
    monkeypatch.setattr(report_mod, "REPORT_DIR", tmp_path / "reports")
    report_mod.REPORT_DIR.mkdir()
    monkeypatch.setattr(submission_mod, "HackerOneCreds", _UnconfiguredCreds)


def _approve_poc_file(finding):
    text = poc_mod.Path(finding.poc_path).read_text()
    text = text.replace("1. TODO", "1. GET the path\n2. Observe HTTP 200")
    text = text.replace(
        "TODO\n\n## Suggested severity", "Attacker gains read access to config.\n\n## Suggested severity"
    )
    poc_mod.Path(finding.poc_path).write_text(text)


def test_draft_poc_requires_candidate_status(candidate_finding, program):
    candidate_finding.status = FindingStatus.POC_DRAFTED
    with pytest.raises(RuntimeError):
        draft_poc(candidate_finding, program)


def test_draft_report_blocked_before_poc_approved(candidate_finding, program):
    with pytest.raises(RuntimeError):
        draft_report(candidate_finding, program, severity="medium")

    draft_poc(candidate_finding, program)  # -> poc_drafted, still not approved
    with pytest.raises(RuntimeError):
        draft_report(candidate_finding, program, severity="medium")


def test_draft_report_blocked_when_poc_todos_unfilled(candidate_finding, program):
    draft_poc(candidate_finding, program)
    candidate_finding.status = FindingStatus.POC_APPROVED  # simulate approve-poc
    with pytest.raises(RuntimeError, match="TODO"):
        draft_report(candidate_finding, program, severity="medium")


def test_full_gate_chain_succeeds_only_in_order(candidate_finding, program):
    draft_poc(candidate_finding, program)
    assert candidate_finding.status == FindingStatus.POC_DRAFTED

    _approve_poc_file(candidate_finding)
    candidate_finding.status = FindingStatus.POC_APPROVED  # simulate approve-poc

    draft_report(candidate_finding, program, severity="medium")
    assert candidate_finding.status == FindingStatus.REPORT_DRAFTED
    assert candidate_finding.severity == "medium"

    with pytest.raises(RuntimeError):
        submit_report(candidate_finding, program)

    candidate_finding.status = FindingStatus.REPORT_APPROVED  # simulate approve-report

    # HackerOne with no creds configured -> manual path required, not a silent no-op
    with pytest.raises(ManualSubmissionRequired):
        submit_report(candidate_finding, program)
    assert candidate_finding.status == FindingStatus.REPORT_APPROVED  # unchanged on failure


def test_mark_submitted_manually_requires_report_approved(candidate_finding):
    with pytest.raises(RuntimeError):
        mark_submitted_manually(candidate_finding, note="pasted by hand")

    candidate_finding.status = FindingStatus.REPORT_APPROVED
    result = mark_submitted_manually(candidate_finding, note="pasted by hand")
    assert result.status == FindingStatus.SUBMITTED
    assert "pasted by hand" in result.notes


def test_submit_report_non_hackerone_platform_is_always_manual(candidate_finding, program):
    from bbhunter.models import Platform

    program.platform = Platform.INTIGRITI
    candidate_finding.status = FindingStatus.REPORT_APPROVED
    candidate_finding.report_path = str(report_mod.REPORT_DIR / "fake.md")
    report_mod.REPORT_DIR.joinpath("fake.md").write_text("## Steps to reproduce\n\nx\n\n## Impact\n\ny\n")

    with pytest.raises(ManualSubmissionRequired):
        submit_report(candidate_finding, program)
