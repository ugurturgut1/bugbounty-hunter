"""Regression test for a real performance issue found live 2026-09-18:
tls_cert_info was attempted against every fingerprinted host regardless
of whether that host actually served anything over HTTPS, so an
HTTP-only (or dead-on-443) subdomain cost a full TLS_CERT_TIMEOUT_SECONDS
wasted wait -- multiplied across dozens of subdomains, this made a
35-seed program's recon run take 50+ minutes without finishing. Fixed
to only attempt the TLS handshake when fingerprint()'s own final_url
already shows https:// worked."""
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


def test_tls_check_skipped_when_fingerprint_is_http_only():
    program = _program_with_seeds("http-only.example.com")
    with patch("bbhunter.recon.passive.crtsh_subdomains", return_value=(set(), True)), \
         patch("bbhunter.recon.passive.subfinder_subdomains", return_value=(set(), False)), \
         patch("bbhunter.recon.passive.wayback_subdomains", return_value=(set(), True)), \
         patch("bbhunter.recon.passive.wayback_param_urls", return_value=[]), \
         patch("bbhunter.recon.passive.fingerprint", return_value={"final_url": "http://http-only.example.com/", "status_code": 200}), \
         patch("bbhunter.recon.passive.check_spf", return_value=[]), \
         patch("bbhunter.recon.passive.check_dmarc", return_value=[]), \
         patch("bbhunter.recon.passive.check_dkim", return_value=[]), \
         patch("bbhunter.recon.passive.check_dangling_cname", return_value=None), \
         patch("bbhunter.recon.passive._harvest_js_for_host", return_value=[]), \
         patch("bbhunter.recon.passive.GitHubCreds") as mock_gh, \
         patch("bbhunter.recon.passive.tls_cert_info") as mock_tls, \
         patch("bbhunter.recon.passive.time.sleep"):
        mock_gh.return_value.configured = False
        run_passive_recon(program)
    mock_tls.assert_not_called()


def test_tls_check_runs_when_fingerprint_is_https():
    program = _program_with_seeds("secure.example.com")
    with patch("bbhunter.recon.passive.crtsh_subdomains", return_value=(set(), True)), \
         patch("bbhunter.recon.passive.subfinder_subdomains", return_value=(set(), False)), \
         patch("bbhunter.recon.passive.wayback_subdomains", return_value=(set(), True)), \
         patch("bbhunter.recon.passive.wayback_param_urls", return_value=[]), \
         patch("bbhunter.recon.passive.fingerprint", return_value={"final_url": "https://secure.example.com/", "status_code": 200}), \
         patch("bbhunter.recon.passive.check_spf", return_value=[]), \
         patch("bbhunter.recon.passive.check_dmarc", return_value=[]), \
         patch("bbhunter.recon.passive.check_dkim", return_value=[]), \
         patch("bbhunter.recon.passive.check_dangling_cname", return_value=None), \
         patch("bbhunter.recon.passive._harvest_js_for_host", return_value=[]), \
         patch("bbhunter.recon.passive.GitHubCreds") as mock_gh, \
         patch("bbhunter.recon.passive.tls_cert_info", return_value=None) as mock_tls, \
         patch("bbhunter.recon.passive.time.sleep"):
        mock_gh.return_value.configured = False
        run_passive_recon(program)
    mock_tls.assert_called_once_with("secure.example.com")
