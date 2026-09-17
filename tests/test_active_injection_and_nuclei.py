"""Tests for the opt-in injection-signature checks (reflected-XSS canary,
SQL-error signature) and the optional nuclei integration added to
testing/active.py. Every HTTP/subprocess call is mocked -- these never
touch a real target or shell out to a real binary."""
from unittest.mock import MagicMock, patch

import pytest

from bbhunter.models import (
    AssetType,
    FindingStatus,
    Platform,
    Program,
    ReconResult,
    RulesOfEngagement,
    ScopeAsset,
    TestType,
)
from bbhunter.testing.active import _check_injection_signals, run_active_checks, run_nuclei_scan


def _program(*, approved: bool = True) -> Program:
    rules = RulesOfEngagement(
        allowed_test_types={TestType.PASSIVE_RECON, TestType.ACTIVE_LOW_IMPACT},
        human_reviewed=approved,
        confidence="high" if approved else "low",
        automated_scanners_allowed=True,
    )
    return Program(
        platform=Platform.HACKERONE,
        handle="test",
        name="Test",
        url="https://hackerone.com/test",
        in_scope=[ScopeAsset(identifier="example.com", asset_type=AssetType.URL, in_scope=True)],
        rules=rules,
    )


class _FakeResponse:
    def __init__(self, text: str, url: str = "https://example.com/search?q=x"):
        self.text = text
        self.url = url


def test_reflected_xss_canary_flagged_only_when_unescaped_in_response():
    from urllib.parse import parse_qsl, urlsplit

    client = MagicMock()

    def fake_get(url, timeout=15, follow_redirects=True):
        value = dict(parse_qsl(urlsplit(url).query)).get("q", "")
        if value == "x":  # the baseline request (unmutated)
            return _FakeResponse("baseline page, nothing special")
        if "<>" in value:
            # the xss probe: echo the canary back unescaped
            return _FakeResponse(f"you searched for {value}")
        return _FakeResponse("no sql error here")

    client.get.side_effect = fake_get
    with patch("bbhunter.testing.active.time.sleep"):
        hits = _check_injection_signals(client, "https://example.com/search?q=x")

    xss_hits = [h for h in hits if h["kind"] == "reflected-xss-candidate"]
    assert len(xss_hits) == 1
    assert xss_hits[0]["param"] == "q"


def test_no_hit_when_canary_is_escaped_or_stripped():
    client = MagicMock()
    client.get.return_value = _FakeResponse("nothing reflected back at all")
    with patch("bbhunter.testing.active.time.sleep"):
        hits = _check_injection_signals(client, "https://example.com/search?q=x")
    assert hits == []


def test_sql_error_signature_flagged_only_when_absent_from_baseline():
    client = MagicMock()
    call_count = {"n": 0}

    def fake_get(url, timeout=15, follow_redirects=True):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _FakeResponse("normal search results page")
        if "'" in url or "%27" in url:
            return _FakeResponse("you have an error in your sql syntax near line 1")
        return _FakeResponse("normal search results page")

    client.get.side_effect = fake_get
    with patch("bbhunter.testing.active.time.sleep"):
        hits = _check_injection_signals(client, "https://example.com/search?q=x")

    sqli_hits = [h for h in hits if h["kind"] == "sql-error-signature"]
    assert len(sqli_hits) == 1
    assert "sql syntax" in sqli_hits[0]["evidence"].lower()


def test_sql_signature_already_present_in_baseline_is_not_flagged():
    # A page that always renders SQL-looking text (e.g. a docs page)
    # shouldn't be flagged just because the signature happens to appear
    # in both the baseline and the mutated response.
    client = MagicMock()
    client.get.return_value = _FakeResponse("this page always mentions sql syntax in its docs")
    with patch("bbhunter.testing.active.time.sleep"):
        hits = _check_injection_signals(client, "https://example.com/search?q=x")
    assert [h for h in hits if h["kind"] == "sql-error-signature"] == []


def test_check_injection_signals_returns_empty_for_url_with_no_query_params():
    client = MagicMock()
    hits = _check_injection_signals(client, "https://example.com/no-params-here")
    assert hits == []
    client.get.assert_not_called()


def test_run_active_checks_injection_respects_host_scope():
    program = _program()
    recon_result = ReconResult(
        program_key=program.key,
        param_urls={
            "example.com": [
                "https://example.com/search?q=1",       # in scope
                "https://not-in-scope.com/search?q=1",   # different host entirely, never selected
            ]
        },
    )
    with patch("bbhunter.testing.active._check_host", return_value=[]), \
         patch("bbhunter.testing.active._check_injection_signals", return_value=[]) as check_injection, \
         patch("bbhunter.testing.active.run_nuclei_scan", return_value=None):
        run_active_checks(program, recon_result, injection=True)

    tested_urls = [call.args[1] for call in check_injection.call_args_list]
    assert tested_urls == ["https://example.com/search?q=1"]


def test_run_active_checks_injection_off_by_default():
    program = _program()
    recon_result = ReconResult(program_key=program.key, param_urls={"example.com": ["https://example.com/search?q=1"]})
    with patch("bbhunter.testing.active._check_host", return_value=[]), \
         patch("bbhunter.testing.active._check_injection_signals") as check_injection, \
         patch("bbhunter.testing.active.run_nuclei_scan", return_value=None):
        run_active_checks(program, recon_result)  # injection=False (default)
    check_injection.assert_not_called()


def test_run_active_checks_still_refuses_without_approval():
    program = _program(approved=False)
    with pytest.raises(RuntimeError):
        run_active_checks(program, None, injection=True, nuclei=True)


def test_run_nuclei_scan_returns_none_when_binary_missing():
    with patch("bbhunter.testing.active._tool_path", return_value=None):
        result = run_nuclei_scan(["example.com"], RulesOfEngagement())
    assert result is None


def test_run_nuclei_scan_returns_none_for_empty_host_list():
    with patch("bbhunter.testing.active._tool_path", return_value="/fake/nuclei"):
        result = run_nuclei_scan([], RulesOfEngagement())
    assert result is None


def test_run_nuclei_scan_parses_jsonl_output():
    fake_proc = MagicMock(
        stdout='{"template-id":"exposed-panel","info":{"name":"Exposed Panel","severity":"low"},"matched-at":"https://example.com/admin"}\n'
        "\n"
        '{"template-id":"cve-2021-1234","info":{"name":"Some CVE"},"matched-at":"https://example.com/"}\n',
    )
    with patch("bbhunter.testing.active._tool_path", return_value="/fake/nuclei"), \
         patch("bbhunter.testing.active.subprocess.run", return_value=fake_proc):
        results = run_nuclei_scan(["example.com"], RulesOfEngagement())
    assert results is not None
    assert len(results) == 2
    assert results[0]["template-id"] == "exposed-panel"


def test_run_nuclei_scan_uses_conservative_rate_limit_flags():
    fake_proc = MagicMock(stdout="")
    with patch("bbhunter.testing.active._tool_path", return_value="/fake/nuclei"), \
         patch("bbhunter.testing.active.subprocess.run", return_value=fake_proc) as run:
        run_nuclei_scan(["example.com"], RulesOfEngagement())
    cmd = run.call_args.args[0]
    assert "-rate-limit" in cmd and cmd[cmd.index("-rate-limit") + 1] == "1"
    assert "-etags" in cmd
    excluded = cmd[cmd.index("-etags") + 1]
    assert "dos" in excluded and "intrusive" in excluded


def test_run_nuclei_scan_returns_none_on_subprocess_error():
    import subprocess as sp

    with patch("bbhunter.testing.active._tool_path", return_value="/fake/nuclei"), \
         patch("bbhunter.testing.active.subprocess.run", side_effect=sp.TimeoutExpired(cmd="nuclei", timeout=1)):
        result = run_nuclei_scan(["example.com"], RulesOfEngagement())
    assert result is None


def test_run_active_checks_nuclei_off_by_default():
    program = _program()
    with patch("bbhunter.testing.active._check_host", return_value=[]), \
         patch("bbhunter.testing.active.run_nuclei_scan") as nuclei_scan:
        run_active_checks(program, None)
    nuclei_scan.assert_not_called()


def test_run_active_checks_nuclei_findings_are_mapped():
    program = _program()
    fake_result = [
        {
            "template-id": "exposed-panel",
            "info": {"name": "Exposed Panel", "severity": "medium", "description": "An admin panel is exposed."},
            "matched-at": "https://example.com/admin",
        }
    ]
    with patch("bbhunter.testing.active._check_host", return_value=[]), \
         patch("bbhunter.testing.active.run_nuclei_scan", return_value=fake_result):
        findings = run_active_checks(program, None, nuclei=True)

    assert len(findings) == 1
    assert findings[0].status == FindingStatus.CANDIDATE
    assert findings[0].test_type == TestType.ACTIVE_LOW_IMPACT
    assert "Exposed Panel" in findings[0].title
    assert findings[0].asset == "example.com"
