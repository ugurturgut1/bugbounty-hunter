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
from bbhunter.testing.active import _check_injection_signals, _check_shellshock, run_active_checks, run_nuclei_scan


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
    def __init__(self, text: str, url: str = "https://example.com/search?q=x", headers: dict | None = None):
        self.text = text
        self.url = url
        self.headers = headers or {}


def test_reflected_xss_canary_flagged_only_when_unescaped_in_response():
    from urllib.parse import parse_qsl, urlsplit

    client = MagicMock()

    def fake_get(url, timeout=15, follow_redirects=True, **kwargs):
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

    def fake_get(url, timeout=15, follow_redirects=True, **kwargs):
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


def test_nosql_error_signature_flagged_only_when_absent_from_baseline():
    client = MagicMock()

    def fake_get(url, timeout=15, follow_redirects=True, **kwargs):
        if "%27%7C%7C%27" in url or "'||'1'=='1" in url:
            return _FakeResponse("MongoError: unterminated string in JSON")
        return _FakeResponse("normal search results page")

    client.get.side_effect = fake_get
    with patch("bbhunter.testing.active.time.sleep"):
        hits = _check_injection_signals(client, "https://example.com/search?q=x")

    nosqli_hits = [h for h in hits if h["kind"] == "nosql-error-signature"]
    assert len(nosqli_hits) == 1
    assert "mongoerror" in nosqli_hits[0]["evidence"].lower()


def test_nosql_signature_already_present_in_baseline_is_not_flagged():
    client = MagicMock()
    client.get.return_value = _FakeResponse("docs page that always mentions MongoError for some reason")
    with patch("bbhunter.testing.active.time.sleep"):
        hits = _check_injection_signals(client, "https://example.com/search?q=x")
    assert [h for h in hits if h["kind"] == "nosql-error-signature"] == []


def test_command_injection_flagged_when_marker_echoed_back():
    client = MagicMock()

    def fake_get(url, timeout=15, follow_redirects=True, **kwargs):
        from urllib.parse import parse_qsl, urlsplit
        value = dict(parse_qsl(urlsplit(url).query)).get("q", "")
        if "BBHCMD" in value:
            marker = value.split("echo ", 1)[-1].split(" ")[0]
            return _FakeResponse(f"command output: {marker}\n")
        return _FakeResponse("normal search results page")

    client.get.side_effect = fake_get
    with patch("bbhunter.testing.active.time.sleep"):
        hits = _check_injection_signals(client, "https://example.com/search?q=x")

    cmdi_hits = [h for h in hits if h["kind"] == "command-injection-candidate"]
    assert len(cmdi_hits) == 1
    assert cmdi_hits[0]["severity"] == "critical"


def test_command_injection_no_hit_when_marker_not_echoed():
    client = MagicMock()
    client.get.return_value = _FakeResponse("nothing echoed back at all")
    with patch("bbhunter.testing.active.time.sleep"):
        hits = _check_injection_signals(client, "https://example.com/search?q=x")
    assert [h for h in hits if h["kind"] == "command-injection-candidate"] == []


def test_crlf_header_injection_flagged_when_injected_header_appears():
    client = MagicMock()

    # Flag whenever the URL carries the CRLF probe's characteristic
    # '%0D%0AX-' sequence (case-insensitive), simulating a server that
    # actually turned it into a real response header.
    def fake_get(url, timeout=15, follow_redirects=True, **kwargs):
        if "%0d%0ax-" in url.lower():
            marker = url.lower().split("%0d%0ax-", 1)[1].split(":", 1)[0].split("%3a", 1)[0]
            return _FakeResponse("normal page", headers={f"X-{marker}": "1"})
        return _FakeResponse("normal page")

    client.get.side_effect = fake_get
    with patch("bbhunter.testing.active.time.sleep"):
        hits = _check_injection_signals(client, "https://example.com/search?q=x")

    crlf_hits = [h for h in hits if h["kind"] == "crlf-header-injection-candidate"]
    assert len(crlf_hits) == 1
    assert crlf_hits[0]["severity"] == "high"


def test_crlf_no_hit_when_header_not_reflected():
    client = MagicMock()
    client.get.return_value = _FakeResponse("normal page")
    with patch("bbhunter.testing.active.time.sleep"):
        hits = _check_injection_signals(client, "https://example.com/search?q=x")
    assert [h for h in hits if h["kind"] == "crlf-header-injection-candidate"] == []


def test_check_injection_signals_makes_six_requests_per_parameter():
    """baseline + xss + sqli + nosqli + cmdi + crlf -- one parameter
    should cost exactly 6 requests, never more."""
    client = MagicMock()
    client.get.return_value = _FakeResponse("nothing interesting")
    with patch("bbhunter.testing.active.time.sleep"):
        _check_injection_signals(client, "https://example.com/search?q=x")
    assert client.get.call_count == 6


def test_shellshock_flagged_when_marker_echoed_back():
    client = MagicMock()

    def fake_get(url, headers=None, timeout=15, follow_redirects=True):
        ua = (headers or {}).get("User-Agent", "")
        if "{ :; }" in ua:
            marker = ua.split("echo ", 1)[-1]
            return _FakeResponse(f"debug output: {marker}\n")
        return _FakeResponse("normal page")

    client.get.side_effect = fake_get
    hits = _check_shellshock(client, "example.com")
    assert len(hits) == 1
    assert hits[0]["kind"] == "shellshock-candidate"
    assert hits[0]["severity"] == "critical"


def test_shellshock_no_hit_when_marker_not_echoed():
    client = MagicMock()
    client.get.return_value = _FakeResponse("normal page")
    assert _check_shellshock(client, "example.com") == []


def test_shellshock_no_hit_on_request_error():
    import httpx as real_httpx

    client = MagicMock()
    client.get.side_effect = real_httpx.ConnectTimeout("timeout")
    assert _check_shellshock(client, "example.com") == []


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
         patch("bbhunter.testing.active._check_shellshock", return_value=[]), \
         patch("bbhunter.testing.active.run_nuclei_scan", return_value=None):
        run_active_checks(program, recon_result, injection=True)

    tested_urls = [call.args[1] for call in check_injection.call_args_list]
    assert tested_urls == ["https://example.com/search?q=1"]


def test_run_active_checks_runs_shellshock_probe_per_host_when_injection_enabled():
    program = _program()
    with patch("bbhunter.testing.active._check_host", return_value=[]), \
         patch("bbhunter.testing.active._check_injection_signals", return_value=[]), \
         patch("bbhunter.testing.active._check_shellshock", return_value=[]) as check_shellshock, \
         patch("bbhunter.testing.active.run_nuclei_scan", return_value=None):
        run_active_checks(program, None, injection=True)
    assert check_shellshock.call_count == 1
    assert check_shellshock.call_args.args[1] == "example.com"


def test_run_active_checks_maps_shellshock_hit_to_a_finding():
    program = _program()
    fake_hit = {
        "kind": "shellshock-candidate",
        "url": "https://example.com/",
        "severity": "critical",
        "evidence": "test evidence",
    }
    with patch("bbhunter.testing.active._check_host", return_value=[]), \
         patch("bbhunter.testing.active._check_injection_signals", return_value=[]), \
         patch("bbhunter.testing.active._check_shellshock", return_value=[fake_hit]), \
         patch("bbhunter.testing.active.run_nuclei_scan", return_value=None):
        findings = run_active_checks(program, None, injection=True)

    shellshock_findings = [f for f in findings if f.vuln_class == "shellshock-candidate"]
    assert len(shellshock_findings) == 1
    assert shellshock_findings[0].asset == "example.com"
    assert shellshock_findings[0].evidence == "test evidence"


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
    # dos/intrusive/etc were the original conservative excludes; rce/sqli/
    # default-login/authentication-bypass were added 2026-09-17 alongside
    # the wider tag set (cors/ssrf/jwt/graphql/etc) specifically so that
    # expansion couldn't accidentally pull in exploitation-grade templates.
    for tag in ("dos", "intrusive", "rce", "sqli", "default-login", "authentication-bypass"):
        assert tag in excluded, f"expected {tag!r} in nuclei -etags, got {excluded!r}"

    assert "-tags" in cmd
    included = cmd[cmd.index("-tags") + 1]
    for tag in ("cors", "ssrf", "jwt", "graphql", "takeover", "ssti", "xxe"):
        assert tag in included, f"expected {tag!r} in nuclei -tags, got {included!r}"


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
