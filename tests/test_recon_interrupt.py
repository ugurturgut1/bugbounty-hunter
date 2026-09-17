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

    calls = {"n": 0}

    def fake_crtsh(domain, *, timeout=30):
        calls["n"] += 1
        if calls["n"] == 2:
            raise KeyboardInterrupt
        return set(), True

    with patch("bbhunter.recon.passive.crtsh_subdomains", side_effect=fake_crtsh), \
         patch("bbhunter.recon.passive.fingerprint_host", return_value=None), \
         patch("bbhunter.recon.passive.time.sleep"):
        result, findings = run_passive_recon(program)

    assert result.seeds_total == 3
    assert result.seeds_processed == 1  # first seed completed fully before the second raised
    assert result.complete is False
    assert "first.example.com" in result.subdomains  # first seed's data wasn't discarded
    assert "second.example.com" not in result.subdomains
    assert findings == []


def test_full_run_reports_complete():
    program = _program_with_seeds("only.example.com")

    with patch("bbhunter.recon.passive.crtsh_subdomains", return_value=(set(), True)), \
         patch("bbhunter.recon.passive.fingerprint_host", return_value=None), \
         patch("bbhunter.recon.passive.time.sleep"):
        result, _ = run_passive_recon(program)

    assert result.seeds_total == 1
    assert result.seeds_processed == 1
    assert result.complete is True
