"""Tests for the anti-hallucination guard on PoC approval: a PoC can
never become POC_APPROVED (in code, not just by convention/skill
instructions) while its Reproduction steps or Impact section still has
an unfilled TODO. poc_has_unfilled_todos is the single source of truth,
enforced independently at both approve_poc_cmd (cli.py) and draft_report
(report.py)."""
from unittest.mock import patch

import pytest
import typer

from bbhunter.models import AssetType, FindingStatus, Platform, Program, ScopeAsset, TestType
from bbhunter.models import Finding
from bbhunter.reporting.poc import draft_poc, poc_has_unfilled_todos


def _program() -> Program:
    return Program(
        platform=Platform.HACKERONE, handle="t", name="T", url="https://hackerone.com/t",
        in_scope=[ScopeAsset(identifier="example.com", asset_type=AssetType.URL, in_scope=True)],
    )


def _candidate_finding(program: Program) -> Finding:
    return Finding(
        id=f"{program.key}:example.com:xss",
        program_key=program.key,
        asset="example.com",
        title="Reflected XSS",
        vuln_class="reflected-xss-candidate",
        test_type=TestType.ACTIVE_LOW_IMPACT,
        evidence="canary reflected unescaped",
        status=FindingStatus.CANDIDATE,
    )


def test_poc_has_unfilled_todos_true_for_freshly_drafted_poc(tmp_path, monkeypatch):
    import bbhunter.reporting.poc as poc_module

    monkeypatch.setattr(poc_module, "POC_DIR", tmp_path)
    program = _program()
    finding = _candidate_finding(program)
    draft_poc(finding, program)
    assert poc_has_unfilled_todos(finding.poc_path) is True


def test_poc_has_unfilled_todos_false_once_filled_in(tmp_path, monkeypatch):
    import bbhunter.reporting.poc as poc_module

    monkeypatch.setattr(poc_module, "POC_DIR", tmp_path)
    program = _program()
    finding = _candidate_finding(program)
    draft_poc(finding, program)

    text = open(finding.poc_path).read()
    text = text.replace("1. TODO", "1. Navigated to /search?q=<canary>, canary rendered unescaped in the DOM.")
    text = text.replace(
        "## Impact\n\n<!-- TODO (human): what can an attacker actually do with this? Be\nconcrete and specific to this program's assets -- this text is reused\nverbatim as the basis for the disclosure report's Impact section. -->\n\nTODO",
        "## Impact\n\nAn attacker can steal session cookies from any user who clicks a crafted link.",
    )
    with open(finding.poc_path, "w") as f:
        f.write(text)

    assert poc_has_unfilled_todos(finding.poc_path) is False


def test_approve_poc_cmd_refuses_while_todos_unfilled(tmp_path, monkeypatch):
    import bbhunter.cli as cli_module
    import bbhunter.reporting.poc as poc_module

    monkeypatch.setattr(poc_module, "POC_DIR", tmp_path)
    program = _program()
    finding = _candidate_finding(program)
    draft_poc(finding, program)  # -> POC_DRAFTED, poc_path set, TODOs unfilled

    with patch.object(cli_module, "get_finding", return_value=finding), \
         patch.object(cli_module, "upsert_finding") as mock_upsert:
        with pytest.raises(typer.Exit):
            cli_module.approve_poc_cmd(finding.id, note="looks reproduced")
    mock_upsert.assert_not_called()
    assert finding.status == FindingStatus.POC_DRAFTED  # never advanced


def test_approve_poc_cmd_succeeds_once_todos_filled(tmp_path, monkeypatch):
    import bbhunter.cli as cli_module
    import bbhunter.reporting.poc as poc_module

    monkeypatch.setattr(poc_module, "POC_DIR", tmp_path)
    program = _program()
    finding = _candidate_finding(program)
    draft_poc(finding, program)

    with open(finding.poc_path) as f:
        text = f.read()
    text = text.replace("1. TODO", "1. Confirmed the canary rendered unescaped.")
    text = text.replace(
        "## Impact\n\n<!-- TODO (human): what can an attacker actually do with this? Be\nconcrete and specific to this program's assets -- this text is reused\nverbatim as the basis for the disclosure report's Impact section. -->\n\nTODO",
        "## Impact\n\nSession cookie theft via a crafted link.",
    )
    with open(finding.poc_path, "w") as f:
        f.write(text)

    with patch.object(cli_module, "get_finding", return_value=finding), \
         patch.object(cli_module, "upsert_finding") as mock_upsert:
        cli_module.approve_poc_cmd(finding.id, note="personally reproduced on 2026-09-20")
    mock_upsert.assert_called_once()
    assert finding.status == FindingStatus.POC_APPROVED
