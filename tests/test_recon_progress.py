"""Tests for run_passive_recon's on_progress callback -- the heuristic
progress tracker with an ETA, added 2026-09-18 in response to real runs
against medium-sized programs (24-35 seeds) taking 50+ minutes with no
visibility into how much was left."""
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


def _run_with_mocks(program, **kwargs):
    with patch("bbhunter.recon.passive.crtsh_subdomains", return_value=(set(), True)), \
         patch("bbhunter.recon.passive.certspotter_subdomains", return_value=(set(), True)), \
         patch("bbhunter.recon.passive.subfinder_subdomains", return_value=(set(), False)), \
         patch("bbhunter.recon.passive.assetfinder_subdomains", return_value=(set(), False)), \
         patch("bbhunter.recon.passive.wayback_subdomains", return_value=(set(), True)), \
         patch("bbhunter.recon.passive.wayback_param_urls", return_value=[]), \
         patch("bbhunter.recon.passive.fingerprint", return_value=None), \
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


def test_on_progress_called_with_seed_substeps():
    program = _program_with_seeds("one.example.com")
    messages: list[str] = []
    _run_with_mocks(program, on_progress=messages.append)

    assert any("crt.sh" in m for m in messages)
    assert any("subfinder" in m for m in messages)
    assert any("wayback" in m for m in messages)
    assert any("DNS hygiene" in m for m in messages)
    assert any("JS harvesting" in m for m in messages)
    assert any("fingerprinting" in m for m in messages)


def test_on_progress_reports_last_seed_with_no_eta():
    program = _program_with_seeds("one.example.com")
    messages: list[str] = []
    _run_with_mocks(program, on_progress=messages.append)

    done_messages = [m for m in messages if "done in" in m]
    assert len(done_messages) == 1
    assert "last seed" in done_messages[0]
    assert "remaining" not in done_messages[0]


def test_on_progress_reports_eta_for_earlier_seeds():
    program = _program_with_seeds("one.example.com", "two.example.com", "three.example.com")
    messages: list[str] = []
    _run_with_mocks(program, on_progress=messages.append)

    done_messages = [m for m in messages if "done in" in m]
    assert len(done_messages) == 3
    assert "remaining" in done_messages[0]
    assert "2 seed(s) left" in done_messages[0]
    assert "remaining" in done_messages[1]
    assert "1 seed(s) left" in done_messages[1]
    assert "last seed" in done_messages[2]


def test_recon_works_fine_without_a_progress_callback():
    program = _program_with_seeds("one.example.com")
    result, findings = _run_with_mocks(program)  # on_progress omitted entirely
    assert result.seeds_processed == 1


def test_broken_progress_callback_does_not_abort_the_recon_run():
    program = _program_with_seeds("one.example.com")

    def exploding_callback(msg):
        raise RuntimeError("progress display broke, the recon run must not care")

    result, findings = _run_with_mocks(program, on_progress=exploding_callback)
    assert result.seeds_processed == 1
