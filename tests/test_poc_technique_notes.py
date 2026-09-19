"""Tests for the technique-notes lookup/embedding added to
reporting/poc.py's draft_poc -- a real docs/VULN_TECHNIQUE_NOTES.md
section embedded verbatim for a matching vuln_class, never fabricated."""
from bbhunter.models import AssetType, FindingStatus, Platform, Program, ScopeAsset, TestType
from bbhunter.models import Finding
from bbhunter.reporting.poc import VULN_TECHNIQUE_NOTES_PATH, _technique_notes_for, draft_poc, poc_path_for


def test_vuln_technique_notes_file_exists():
    # the whole feature is silently inert if this path ever drifts -- fail loudly instead
    assert VULN_TECHNIQUE_NOTES_PATH.is_file()


def test_technique_notes_for_matches_known_class():
    result = _technique_notes_for("reflected-xss-candidate")
    assert result is not None
    heading, body = result
    assert heading == "XSS"
    assert len(body) > 0


def test_technique_notes_for_sql_error_signature():
    result = _technique_notes_for("sql-error-signature")
    assert result is not None
    assert result[0] == "SQL injection"


def test_technique_notes_for_shellshock():
    result = _technique_notes_for("shellshock-candidate")
    assert result is not None
    assert result[0] == "RCE"


def test_technique_notes_for_unknown_class_returns_none():
    assert _technique_notes_for("exposure") is None
    assert _technique_notes_for("tls-self-signed-cert") is None


def test_draft_poc_embeds_technique_notes_for_matching_class(tmp_path, monkeypatch):
    import bbhunter.reporting.poc as poc_module

    monkeypatch.setattr(poc_module, "POC_DIR", tmp_path)

    program = Program(
        platform=Platform.HACKERONE, handle="t", name="T", url="https://hackerone.com/t",
        in_scope=[ScopeAsset(identifier="example.com", asset_type=AssetType.URL, in_scope=True)],
    )
    finding = Finding(
        id="hackerone:t:example.com:xss",
        program_key=program.key,
        asset="example.com",
        title="Reflected XSS",
        vuln_class="reflected-xss-candidate",
        test_type=TestType.ACTIVE_LOW_IMPACT,
        evidence="canary reflected unescaped",
        status=FindingStatus.CANDIDATE,
    )
    draft_poc(finding, program)
    content = poc_path_for(finding.id).read_text()
    assert "Technique notes (XSS" in content
    assert "AngularJS" in content  # a real line from the XSS section, not a fabricated summary


def test_draft_poc_omits_technique_notes_for_unmatched_class(tmp_path, monkeypatch):
    import bbhunter.reporting.poc as poc_module

    monkeypatch.setattr(poc_module, "POC_DIR", tmp_path)

    program = Program(
        platform=Platform.HACKERONE, handle="t", name="T", url="https://hackerone.com/t",
        in_scope=[ScopeAsset(identifier="example.com", asset_type=AssetType.URL, in_scope=True)],
    )
    finding = Finding(
        id="hackerone:t:example.com:git",
        program_key=program.key,
        asset="example.com",
        title="Exposed .git/config",
        vuln_class="exposure",
        test_type=TestType.ACTIVE_LOW_IMPACT,
        evidence="GET .../.git/config -> HTTP 200",
        status=FindingStatus.CANDIDATE,
    )
    draft_poc(finding, program)
    content = poc_path_for(finding.id).read_text()
    assert "Technique notes" not in content
