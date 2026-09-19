"""Phase 4, step 2: disclosure report drafting.

Only runs after a human has approved the PoC (`FindingStatus.POC_APPROVED`)
-- see `poc.py` and the `approve-poc` CLI command. Pulls the "Reproduction
steps" and "Impact" sections straight out of the approved PoC file rather
than re-deriving them, so the report can never say something the human
didn't already sign off on in the PoC review.
"""
from __future__ import annotations

import re
from pathlib import Path

from bbhunter.config import DATA_DIR
from bbhunter.models import Finding, FindingStatus, Program
from bbhunter.reporting.poc import poc_has_unfilled_todos

REPORT_DIR = DATA_DIR / "reports"
REPORT_DIR.mkdir(parents=True, exist_ok=True)

_VALID_SEVERITIES = {"none", "low", "medium", "high", "critical"}


def _slug(finding_id: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]+", "_", finding_id).strip("_")


def report_path_for(finding_id: str) -> Path:
    return REPORT_DIR / f"{_slug(finding_id)}.md"


def _extract_section(markdown: str, heading: str) -> str:
    pattern = rf"^## {re.escape(heading)}\s*\n(.*?)(?=\n## |\Z)"
    m = re.search(pattern, markdown, re.DOTALL | re.MULTILINE)
    if not m:
        return "(section not found in PoC file)"
    body = m.group(1)
    body = re.sub(r"<!--.*?-->", "", body, flags=re.DOTALL)
    return body.strip() or "(empty)"


def draft_report(finding: Finding, program: Program, *, severity: str | None = None) -> Finding:
    # REPORT_REJECTED is a valid re-entry point, not a dead end: it only
    # ever follows a PoC that was already approved (POC_APPROVED ->
    # REPORT_DRAFTED -> REPORT_REJECTED), so re-drafting here iterates on
    # the report text without re-opening or bypassing the PoC gate.
    if finding.status not in (FindingStatus.POC_APPROVED, FindingStatus.REPORT_REJECTED):
        raise RuntimeError(
            f"{finding.id}: can only draft a report from status=poc_approved or report_rejected "
            f"(currently {finding.status.value}). Run `bbhunter draft-poc` and `bbhunter approve-poc` first."
        )
    if not finding.poc_path or not Path(finding.poc_path).exists():
        raise RuntimeError(f"{finding.id}: no PoC file on record at {finding.poc_path!r}")

    if severity is not None:
        if severity not in _VALID_SEVERITIES:
            raise ValueError(f"invalid severity {severity!r}; must be one of {sorted(_VALID_SEVERITIES)}")
        finding.severity = severity

    # Belt-and-suspenders: approve_poc_cmd (cli.py) already refuses this at approval time via the
    # same poc_has_unfilled_todos check, but re-check here too rather than trust that every path to
    # POC_APPROVED went through it -- see poc_has_unfilled_todos's own docstring.
    if poc_has_unfilled_todos(finding.poc_path):
        raise RuntimeError(
            f"{finding.id}: the approved PoC at {finding.poc_path} still has unfilled TODOs in "
            "Reproduction steps or Impact. Fill those in and re-approve before drafting a report."
        )

    poc_text = Path(finding.poc_path).read_text(encoding="utf-8")
    steps = _extract_section(poc_text, "Reproduction steps")
    impact = _extract_section(poc_text, "Impact")

    path = report_path_for(finding.id)
    path.write_text(
        f"""# {finding.title}

**Program:** {program.name}
**Asset:** {finding.asset}
**Vulnerability class:** {finding.vuln_class}
**Severity:** {finding.severity or "none"}

## Summary

{finding.title} was found on {finding.asset}, within the scope of the
{program.name} program.

## Steps to reproduce

{steps}

## Impact

{impact}

## Suggested remediation

<!-- TODO (human): a remediation suggestion strengthens most reports and
is expected on most platforms -- add one before approving. -->

TODO

## Supporting material

Full PoC and evidence: {finding.poc_path}
""",
        encoding="utf-8",
    )

    finding.report_path = str(path)
    finding.status = FindingStatus.REPORT_DRAFTED
    return finding
