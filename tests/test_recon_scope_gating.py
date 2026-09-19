"""Regression guard for a real scope-guardrail gap found live 2026-09-20:
run_passive_recon fingerprinted (sent a live GET to) every subdomain
crt.sh/Certspotter/subfinder/assetfinder/Wayback discovered under a
seed, even when that seed was a plain URL-type asset (a single declared
host -- subdomains are NOT in scope), only a WILDCARD-type asset
actually covers its subdomains. testing/active.py's _select_hosts
already got this right; run_passive_recon didn't, until this fix."""
from unittest.mock import patch

from bbhunter.models import AssetType, Platform, Program, ScopeAsset
from bbhunter.recon.passive import run_passive_recon


def _program_with_seed(identifier: str, asset_type: AssetType) -> Program:
    return Program(
        platform=Platform.HACKERONE,
        handle="test",
        name="Test",
        url="https://hackerone.com/test",
        in_scope=[ScopeAsset(identifier=identifier, asset_type=asset_type, in_scope=True)],
    )


def _run_with_mocks(program, fingerprinted: list[str], **kwargs):
    def fake_fingerprint(host, rules, *, timeout=15):
        fingerprinted.append(host)
        return None

    with patch("bbhunter.recon.passive.crtsh_subdomains", return_value=({"sub.seed.example.com"}, True)), \
         patch("bbhunter.recon.passive.certspotter_subdomains", return_value=(set(), True)), \
         patch("bbhunter.recon.passive.subfinder_subdomains", return_value=(set(), False)), \
         patch("bbhunter.recon.passive.assetfinder_subdomains", return_value=(set(), False)), \
         patch("bbhunter.recon.passive.wayback_subdomains", return_value=(set(), True)), \
         patch("bbhunter.recon.passive.wayback_param_urls", return_value=[]), \
         patch("bbhunter.recon.passive.fingerprint", side_effect=fake_fingerprint), \
         patch("bbhunter.recon.passive.tls_cert_info", return_value=None), \
         patch("bbhunter.recon.passive.check_spf", return_value=[]), \
         patch("bbhunter.recon.passive.check_dmarc", return_value=[]), \
         patch("bbhunter.recon.passive.check_dkim", return_value=[]), \
         patch("bbhunter.recon.passive.check_dangling_cname", return_value=None), \
         patch("bbhunter.recon.passive._harvest_js_for_host", return_value=[]), \
         patch("bbhunter.recon.passive._check_well_known_for_host", return_value=[]), \
         patch("bbhunter.recon.passive.dnsx_resolve", return_value=None), \
         patch("bbhunter.recon.passive.GitHubCreds") as mock_gh, \
         patch("bbhunter.recon.passive.time.sleep"):
        mock_gh.return_value.configured = False
        return run_passive_recon(program, **kwargs)


def test_url_seed_never_fingerprints_a_discovered_sibling_subdomain():
    program = _program_with_seed("seed.example.com", AssetType.URL)
    fingerprinted: list[str] = []
    result, _ = _run_with_mocks(program, fingerprinted)
    assert fingerprinted == ["seed.example.com"]
    assert "sub.seed.example.com" not in fingerprinted
    # still recorded as *discovered* for visibility -- just never sent a live request
    assert "sub.seed.example.com" in result.subdomains["seed.example.com"]


def test_wildcard_seed_does_fingerprint_a_discovered_subdomain():
    program = _program_with_seed("seed.example.com", AssetType.WILDCARD)
    fingerprinted: list[str] = []
    _run_with_mocks(program, fingerprinted)
    assert "seed.example.com" in fingerprinted
    assert "sub.seed.example.com" in fingerprinted


def test_url_seed_ignores_max_subdomains_per_seed_cap():
    # the cap only ever narrowed breadth under a WILDCARD seed -- a URL seed must stay
    # single-host regardless of what the caller passes here
    program = _program_with_seed("seed.example.com", AssetType.URL)
    fingerprinted: list[str] = []
    _run_with_mocks(program, fingerprinted, max_subdomains_per_seed=25)
    assert fingerprinted == ["seed.example.com"]
