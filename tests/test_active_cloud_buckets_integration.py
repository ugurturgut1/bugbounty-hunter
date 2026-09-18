"""Tests for _seed_base_names (bucket-name derivation) and the
cloud_buckets=True opt-in path in run_active_checks. The actual
S3/GCS/Azure requests are mocked via check_cloud_buckets_for_name."""
from unittest.mock import patch

from bbhunter.models import AssetType, Platform, Program, RulesOfEngagement, ScopeAsset, TestType
from bbhunter.testing.active import _seed_base_names, run_active_checks


def _program_with_assets(*assets: ScopeAsset, approved: bool = True) -> Program:
    return Program(
        platform=Platform.HACKERONE,
        handle="test",
        name="Test",
        url="https://hackerone.com/test",
        in_scope=list(assets),
        rules=RulesOfEngagement(
            allowed_test_types={TestType.PASSIVE_RECON, TestType.ACTIVE_LOW_IMPACT},
            human_reviewed=approved,
            confidence="high" if approved else "low",
            automated_scanners_allowed=True,
        ),
    )


def test_seed_base_names_strips_www_and_picks_organizational_label():
    program = _program_with_assets(
        ScopeAsset(identifier="www.example.com", asset_type=AssetType.URL, in_scope=True),
        ScopeAsset(identifier="api.example.com", asset_type=AssetType.URL, in_scope=True),
    )
    assert _seed_base_names(program) == ["example"]


def test_seed_base_names_handles_bare_two_label_domain():
    program = _program_with_assets(
        ScopeAsset(identifier="example.com", asset_type=AssetType.URL, in_scope=True),
    )
    assert _seed_base_names(program) == ["example"]


def test_seed_base_names_dedupes_across_multiple_seeds():
    program = _program_with_assets(
        ScopeAsset(identifier="example.com", asset_type=AssetType.URL, in_scope=True),
        ScopeAsset(identifier="sub.example.com", asset_type=AssetType.WILDCARD, in_scope=True),
    )
    assert _seed_base_names(program) == ["example"]


def test_run_active_checks_skips_cloud_bucket_scan_when_flag_off():
    program = _program_with_assets(ScopeAsset(identifier="example.com", asset_type=AssetType.URL, in_scope=True))
    with patch("bbhunter.testing.active.check_cloud_buckets_for_name") as mock_check, \
         patch("bbhunter.testing.active._check_host", return_value=[]), \
         patch("bbhunter.testing.active.time.sleep"):
        run_active_checks(program)
    mock_check.assert_not_called()


def test_run_active_checks_runs_cloud_bucket_scan_when_flag_on():
    program = _program_with_assets(ScopeAsset(identifier="example.com", asset_type=AssetType.URL, in_scope=True))
    with patch("bbhunter.testing.active.check_cloud_buckets_for_name", return_value=[]) as mock_check, \
         patch("bbhunter.testing.active._check_host", return_value=[]), \
         patch("bbhunter.testing.active.time.sleep"):
        run_active_checks(program, cloud_buckets=True)
    mock_check.assert_called_once_with("example")


def test_run_active_checks_maps_cloud_bucket_hits_to_findings():
    program = _program_with_assets(ScopeAsset(identifier="example.com", asset_type=AssetType.URL, in_scope=True))
    fake_hit = {"kind": "public-s3-bucket-listing", "severity": "info", "evidence": "found it"}
    with patch("bbhunter.testing.active.check_cloud_buckets_for_name", return_value=[fake_hit]), \
         patch("bbhunter.testing.active._check_host", return_value=[]), \
         patch("bbhunter.testing.active.time.sleep"):
        findings = run_active_checks(program, cloud_buckets=True)
    assert len(findings) == 1
    assert findings[0].vuln_class == "public-s3-bucket-listing"
    assert findings[0].test_type == TestType.ACTIVE_LOW_IMPACT


def test_run_active_checks_refuses_without_approval():
    import pytest
    program = _program_with_assets(
        ScopeAsset(identifier="example.com", asset_type=AssetType.URL, in_scope=True), approved=False
    )
    with pytest.raises(RuntimeError):
        run_active_checks(program, cloud_buckets=True)
