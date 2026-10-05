"""Tests for the five roadmap features: freshness scoring + state
tracking, authenticated endpoint discovery, subdomain-takeover
confirmation, targeted CVE nuclei scan, and policy-based triage."""
from unittest.mock import MagicMock, patch

from bbhunter.models import (
    AssetType,
    Finding,
    FindingStatus,
    Platform,
    Program,
    ReconResult,
    RulesOfEngagement,
    ScopeAsset,
    TestType,
)
from bbhunter.prioritize import score_program
from bbhunter.recon.authed import _extract_openapi_endpoints, discover_authed_endpoints
from bbhunter.testing.takeover import check_takeover
from bbhunter.triage import flag_known_issues
from bbhunter import state as state_mod


def _program(key_handle="t", offers=True, oos=None, policy="", wildcard="t.example.com"):
    return Program(
        platform=Platform.HACKERONE, handle=key_handle, name="T", url="https://h1/t",
        offers_bounties=offers,
        in_scope=[ScopeAsset(identifier=wildcard, asset_type=AssetType.WILDCARD, in_scope=True)],
        out_of_scope=oos or [],
        raw_policy_text=policy,
    )


# ---- #1 freshness ----

def test_first_seen_persists_and_scope_expansion_is_detected(tmp_path):
    db = tmp_path / "s.db"
    p = _program()
    state_mod.upsert_program(p, db_path=db)
    newly, expanded = state_mod.fresh_program_keys(within_days=14, db_path=db)
    assert p.key in newly and p.key not in expanded

    # add a second in-scope asset and re-sync -> scope expanded
    p2 = _program()
    p2.in_scope.append(ScopeAsset(identifier="api.example.com", asset_type=AssetType.URL, in_scope=True))
    state_mod.upsert_program(p2, db_path=db)
    newly2, expanded2 = state_mod.fresh_program_keys(within_days=14, db_path=db)
    assert p.key in expanded2  # growth flagged
    # first_seen preserved across the re-sync (still 'newly seen' within window)
    assert p.key in newly2


def test_fresh_window_excludes_old_first_seen(tmp_path):
    db = tmp_path / "s.db"
    state_mod.upsert_program(_program(), db_path=db)
    newly, _ = state_mod.fresh_program_keys(within_days=0, db_path=db)
    assert newly == set()  # window of 0 days excludes anything


def test_fresh_program_scores_higher():
    p = _program()
    base = score_program(p, already_reconned=False)
    fresh = score_program(p, already_reconned=False, is_fresh=True)
    assert fresh.score > base.score
    assert fresh.is_fresh and any("newly-added" in r for r in fresh.reasons)


# ---- #2 authed recon ----

def test_extract_openapi_endpoints_joins_paths_and_basepath():
    doc = {"basePath": "/api/v1", "paths": {"/orders/{id}": {}, "/users": {}}}
    eps = _extract_openapi_endpoints("https://h.example.com", doc)
    assert "https://h.example.com/api/v1/orders/{id}" in eps
    assert "https://h.example.com/api/v1/users" in eps


def test_discover_authed_endpoints_parses_openapi_and_graphql():
    openapi = MagicMock(status_code=200, headers={"content-type": "application/json"})
    openapi.json.return_value = {"paths": {"/orders/{id}": {}}}
    gql = MagicMock(status_code=200)
    gql.json.return_value = {"data": {"__schema": {"queryType": {"name": "Query"}}}}
    not_found = MagicMock(status_code=404, headers={"content-type": "text/html"})

    client = MagicMock()
    client.__enter__.return_value = client
    # first OpenAPI path 200s with a schema; GraphQL introspection open on /graphql
    client.get.side_effect = lambda url, timeout=15: openapi if url.endswith("/openapi.json") else not_found
    client.post.side_effect = lambda url, json=None, timeout=15: gql if url.endswith("/graphql") else MagicMock(status_code=404)

    with patch("bbhunter.recon.authed.httpx.Client", return_value=client), \
         patch("bbhunter.recon.authed.time.sleep"):
        endpoints, notes = discover_authed_endpoints(["h.example.com"], {"Cookie": "s=1"})

    assert any(e.endswith("/orders/{id}") for e in endpoints)
    assert any(e.endswith("/graphql") for e in endpoints)
    assert any("GraphQL introspection OPEN" in n for n in notes)


# ---- #3 takeover ----

def test_takeover_matches_github_pages_fingerprint():
    resp = MagicMock(status_code=404, text="There isn't a GitHub Pages site here.")
    with patch("bbhunter.testing.takeover.httpx.get", return_value=resp):
        hit = check_takeover("sub.example.com")
    assert hit and hit["service"] == "GitHub Pages"


def test_takeover_no_match_on_normal_page():
    resp = MagicMock(status_code=200, text="<html>welcome</html>")
    with patch("bbhunter.testing.takeover.httpx.get", return_value=resp):
        assert check_takeover("sub.example.com") is None


# ---- #4 CVE confirm (targeted nuclei args) ----

def test_run_nuclei_cve_scan_targets_specific_ids():
    from bbhunter.testing.active import run_nuclei_cve_scan

    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return MagicMock(stdout='{"template-id":"CVE-2021-1234","matched-at":"https://h/"}\n')

    with patch("bbhunter.testing.active._tool_path", return_value="/fake/nuclei"), \
         patch("bbhunter.testing.active.subprocess.run", side_effect=fake_run):
        results = run_nuclei_cve_scan("h.example.com", ["CVE-2021-1234", "CVE-2021-1234"], RulesOfEngagement())

    assert "-id" in captured["cmd"]
    assert captured["cmd"][captured["cmd"].index("-id") + 1] == "CVE-2021-1234"  # de-duped
    assert results and results[0]["template-id"] == "CVE-2021-1234"


def test_run_nuclei_cve_scan_skips_without_binary():
    from bbhunter.testing.active import run_nuclei_cve_scan
    with patch("bbhunter.testing.active._tool_path", return_value=None):
        assert run_nuclei_cve_scan("h", ["CVE-2021-1"], RulesOfEngagement()) is None


# ---- #5 triage ----

def _finding(title, vuln_class, asset="t.example.com"):
    return Finding(id=f"x:{title}", program_key="hackerone:t", asset=asset, title=title,
                   vuln_class=vuln_class, test_type=TestType.PASSIVE_RECON, evidence="e",
                   status=FindingStatus.CANDIDATE)


def test_triage_flags_excluded_class_and_oos_asset_but_not_real_bug():
    program = _program(
        policy="The following are out of scope: missing SPF/DMARC records and missing security headers.",
        oos=[ScopeAsset(identifier="legacy.example.com", asset_type=AssetType.URL, in_scope=False)],
    )
    findings = [
        _finding("dmarc record missing", "dmarc-record-missing"),
        _finding("Missing security headers: x", "hardening"),
        _finding("Exposed .env file", "exposure", asset="legacy.example.com"),  # OOS asset
        _finding("BOLA candidate", "idor-candidate"),  # real bug -> not flagged
    ]
    flagged = flag_known_issues(program, findings)
    flagged_titles = {f.title for f, _ in flagged}
    assert "dmarc record missing" in flagged_titles
    assert "Missing security headers: x" in flagged_titles
    assert "Exposed .env file" in flagged_titles  # out-of-scope asset
    assert "BOLA candidate" not in flagged_titles
