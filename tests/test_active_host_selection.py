"""Regression test for a real gap found during a live hunt on
2026-09-17: bbhunter recon discovered 184 hosts for intigriti:watsons
from 93 seed assets, but bbhunter test-active only ever tested the 93
exact seed hostnames -- it never looked at recon's own subdomain
discovery output. This meant the vast majority of the attack surface
recon found was silently never touched by Phase 3."""
from bbhunter.models import AssetType, Finding, FindingStatus, Platform, Program, ReconResult, ScopeAsset, TestType
from bbhunter.testing.active import _select_hosts


def _program_with_assets(*assets: ScopeAsset) -> Program:
    return Program(
        platform=Platform.HACKERONE,
        handle="test",
        name="Test",
        url="https://hackerone.com/test",
        in_scope=list(assets),
    )


def test_wildcard_asset_includes_recon_discovered_subdomains():
    program = _program_with_assets(
        ScopeAsset(identifier="example.com", asset_type=AssetType.WILDCARD, in_scope=True),
    )
    recon_result = ReconResult(
        program_key=program.key,
        subdomains={"example.com": ["api.example.com", "admin.example.com"]},
    )
    hosts = _select_hosts(program, recon_result)
    assert hosts == ["example.com", "api.example.com", "admin.example.com"]


def test_plain_url_asset_does_not_pull_in_sibling_subdomains():
    program = _program_with_assets(
        ScopeAsset(identifier="www.example.com", asset_type=AssetType.URL, in_scope=True),
    )
    # Even if recon happened to discover other subdomains under the same
    # parent domain, a plain URL scope entry doesn't cover them.
    recon_result = ReconResult(
        program_key=program.key,
        subdomains={"www.example.com": ["internal.example.com"]},
    )
    hosts = _select_hosts(program, recon_result)
    assert hosts == ["www.example.com"]


def test_no_recon_result_falls_back_to_exact_seed_hosts_only():
    program = _program_with_assets(
        ScopeAsset(identifier="example.com", asset_type=AssetType.WILDCARD, in_scope=True),
    )
    hosts = _select_hosts(program, None)
    assert hosts == ["example.com"]


def test_non_url_asset_types_are_ignored():
    program = _program_with_assets(
        ScopeAsset(identifier="com.example.app", asset_type=AssetType.MOBILE_APP, in_scope=True),
        ScopeAsset(identifier="example.com", asset_type=AssetType.WILDCARD, in_scope=True),
    )
    hosts = _select_hosts(program, None)
    assert hosts == ["example.com"]


def test_duplicate_hosts_across_assets_are_deduped():
    program = _program_with_assets(
        ScopeAsset(identifier="example.com", asset_type=AssetType.WILDCARD, in_scope=True),
        ScopeAsset(identifier="example.com", asset_type=AssetType.URL, in_scope=True),
    )
    recon_result = ReconResult(program_key=program.key, subdomains={"example.com": ["api.example.com"]})
    hosts = _select_hosts(program, recon_result)
    assert hosts == ["example.com", "api.example.com"]


def test_one_large_wildcard_seed_does_not_starve_other_seeds():
    # Regression test: before the per-seed subdomain cap, a single
    # wildcard seed with many discovered subdomains could fill the
    # entire MAX_HOSTS_PER_PROGRAM budget, leaving zero room for any of
    # a program's other seed assets to be tested at all.
    program = _program_with_assets(
        ScopeAsset(identifier="big.com", asset_type=AssetType.WILDCARD, in_scope=True),
        ScopeAsset(identifier="small.com", asset_type=AssetType.WILDCARD, in_scope=True),
    )
    recon_result = ReconResult(
        program_key=program.key,
        subdomains={
            "big.com": [f"sub{i}.big.com" for i in range(25)],
            "small.com": ["api.small.com"],
        },
    )
    hosts = _select_hosts(program, recon_result)
    assert "small.com" in hosts
    assert "api.small.com" in hosts
    assert len([h for h in hosts if h.endswith("big.com")]) <= 6  # seed + capped subdomains
