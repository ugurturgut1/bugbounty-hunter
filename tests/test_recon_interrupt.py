"""Regression test: stopping a `bbhunter recon` run partway through
(Ctrl-C, or `kill -INT`/`pkill -INT` against a backgrounded run) used to
lose everything -- run_passive_recon only ever returned once its whole
seed loop finished, and the CLI only persists what that call returns.
KeyboardInterrupt during the loop must now be caught and whatever was
gathered before it returned as a partial (but valid) ReconResult."""
from unittest.mock import patch

from bbhunter.models import AssetType, Platform, Program, ScopeAsset
from bbhunter.recon.passive import run_passive_recon


def _program_with_seeds(*hosts: str) -> Program:
    return Program(
        platform=Platform.HACKERONE,
        handle="test",
        name="Test",
        url="https://hackerone.com/test",
        in_scope=[ScopeAsset(identifier=h, asset_type=AssetType.URL, in_scope=True) for h in hosts],
    )


def test_interrupt_mid_loop_returns_partial_result_not_nothing():
    program = _program_with_seeds("first.example.com", "second.example.com", "third.example.com")

    # Raise on a specific seed's crt.sh rather than a call counter: the
    # third-party enumeration now runs all seeds concurrently (Pass 1), so a
    # call-order counter would race. Results are still COLLECTED in seed order,
    # so raising on the second seed deterministically lands after the first is
    # recorded and before the second.
    def fake_crtsh(domain, *, timeout=30):
        if domain == "second.example.com":
            raise KeyboardInterrupt
        return set(), True

    with patch("bbhunter.recon.passive.crtsh_subdomains", side_effect=fake_crtsh), \
         patch("bbhunter.recon.passive.certspotter_subdomains", return_value=(set(), True)), \
         patch("bbhunter.recon.passive.subfinder_subdomains", return_value=(set(), False)), \
         patch("bbhunter.recon.passive.assetfinder_subdomains", return_value=(set(), False)), \
         patch("bbhunter.recon.passive.wayback_subdomains", return_value=(set(), True)), \
         patch("bbhunter.recon.passive.wayback_param_urls", return_value=[]), \
         patch("bbhunter.recon.passive.fingerprint", return_value=None), \
         patch("bbhunter.recon.passive.tls_cert_info", return_value=None), \
         patch("bbhunter.recon.passive.check_spf", return_value=[]), \
         patch("bbhunter.recon.passive.check_dmarc", return_value=[]), \
         patch("bbhunter.recon.passive.check_dkim", return_value=[]), \
         patch("bbhunter.recon.passive.check_dangling_cname", return_value=None), \
         patch("bbhunter.recon.passive._harvest_js_for_host", return_value=[]), \
         patch("bbhunter.recon.passive._check_well_known_for_host", return_value=[]), \
         patch("bbhunter.recon.passive.dnsx_resolve", return_value=None), \
         patch("bbhunter.recon.passive.GitHubCreds") as mock_gh_creds, \
         patch("bbhunter.recon.passive.time.sleep"):
        mock_gh_creds.return_value.configured = False
        result, findings = run_passive_recon(program)

    assert result.seeds_total == 3
    # Interrupt landed in the parallel enumeration pre-pass, before any
    # target-touching seed completed -- but whatever was gathered is still
    # returned as a valid partial result, not discarded.
    assert result.seeds_processed == 0
    assert result.complete is False
    assert "first.example.com" in result.subdomains  # collected before the interrupt
    assert "second.example.com" not in result.subdomains  # collection stopped here
    assert findings == []


def test_max_subdomains_per_seed_zero_skips_subdomain_expansion():
    program = _program_with_seeds("seed.example.com")
    fingerprinted = []

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
         patch("bbhunter.recon.passive.GitHubCreds") as mock_gh_creds, \
         patch("bbhunter.recon.passive.time.sleep"):
        mock_gh_creds.return_value.configured = False
        run_passive_recon(program, max_subdomains_per_seed=0)

    assert fingerprinted == ["seed.example.com"]  # discovered subdomain skipped, only the seed itself


def test_full_run_reports_complete():
    program = _program_with_seeds("only.example.com")

    with patch("bbhunter.recon.passive.crtsh_subdomains", return_value=(set(), True)), \
         patch("bbhunter.recon.passive.certspotter_subdomains", return_value=(set(), True)), \
         patch("bbhunter.recon.passive.subfinder_subdomains", return_value=(set(), False)), \
         patch("bbhunter.recon.passive.assetfinder_subdomains", return_value=(set(), False)), \
         patch("bbhunter.recon.passive.wayback_subdomains", return_value=(set(), True)), \
         patch("bbhunter.recon.passive.wayback_param_urls", return_value=[]), \
         patch("bbhunter.recon.passive.fingerprint", return_value=None), \
         patch("bbhunter.recon.passive.tls_cert_info", return_value=None), \
         patch("bbhunter.recon.passive.check_spf", return_value=[]), \
         patch("bbhunter.recon.passive.check_dmarc", return_value=[]), \
         patch("bbhunter.recon.passive.check_dkim", return_value=[]), \
         patch("bbhunter.recon.passive.check_dangling_cname", return_value=None), \
         patch("bbhunter.recon.passive._harvest_js_for_host", return_value=[]), \
         patch("bbhunter.recon.passive._check_well_known_for_host", return_value=[]), \
         patch("bbhunter.recon.passive.dnsx_resolve", return_value=None), \
         patch("bbhunter.recon.passive.GitHubCreds") as mock_gh_creds, \
         patch("bbhunter.recon.passive.time.sleep"):
        mock_gh_creds.return_value.configured = False
        result, _ = run_passive_recon(program)

    assert result.seeds_total == 1
    assert result.seeds_processed == 1
    assert result.complete is True
