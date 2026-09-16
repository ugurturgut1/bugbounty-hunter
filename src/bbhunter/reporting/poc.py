"""Phase 4, step 1: PoC drafting.

Deliberately does NOT generate exploit code or attempt to weaponize a
Finding -- it only assembles a structured markdown template from what the
automation already observed (the Finding's `evidence` field) and leaves
the actual reproduction narrative, verification, and impact assessment as
explicit TODOs for a human. Nothing downstream (`draft_report`) reads
this file's TODOs as if they were filled in; the approval gate in
`approve-poc` is where a human confirms they actually did the work.
"""
from __future__ import annotations

import re
from pathlib import Path

from bbhunter.config import DATA_DIR
from bbhunter.models import Finding, FindingStatus, Program

POC_DIR = DATA_DIR / "pocs"
POC_DIR.mkdir(parents=True, exist_ok=True)


def _slug(finding_id: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]+", "_", finding_id).strip("_")


def poc_path_for(finding_id: str) -> Path:
    return POC_DIR / f"{_slug(finding_id)}.md"


def draft_poc(finding: Finding, program: Program) -> Finding:
    if finding.status != FindingStatus.CANDIDATE:
        raise RuntimeError(
            f"{finding.id}: can only draft a PoC from status=candidate (currently {finding.status.value})"
        )

    path = poc_path_for(finding.id)
    path.write_text(
        f"""# PoC: {finding.title}

- **Finding ID:** {finding.id}
- **Program:** {program.name} ({program.key})
- **Asset:** {finding.asset}
- **Test type:** {finding.test_type.value}
- **Vuln class:** {finding.vuln_class}

## What the automation observed

{finding.evidence}

{f"Automation notes: {finding.notes}" if finding.notes else ""}

## Reproduction steps

<!-- TODO (human): verify the finding above yourself and write the exact,
minimal steps to reproduce it. Do not approve this PoC until you have
personally reproduced it -- the automation's evidence is a lead, not a
confirmed vulnerability. -->

1. TODO

## Impact

<!-- TODO (human): what can an attacker actually do with this? Be
concrete and specific to this program's assets -- this text is reused
verbatim as the basis for the disclosure report's Impact section. -->

TODO

## Suggested severity

<!-- TODO (human): none | low | medium | high | critical -->

TODO

## Supporting material

<!-- attach screenshots, request/response captures, etc. here or link to
files alongside this one -->
""",
        encoding="utf-8",
    )

    finding.poc_path = str(path)
    finding.status = FindingStatus.POC_DRAFTED
    return finding
