"""Phase 2: change-monitoring -- recon snapshot diffing."""
from datetime import datetime, timedelta

from bbhunter.models import AssetType, Platform, Program, ReconResult, ScopeAsset
from bbhunter import state as state_mod


def _program():
    return Program(platform=Platform.HACKERONE, handle="t", name="T", url="https://h1/t",
                   in_scope=[ScopeAsset(identifier="t.example.com", asset_type=AssetType.WILDCARD, in_scope=True)])


def test_recon_diff_reports_new_and_removed(tmp_path):
    db = tmp_path / "s.db"
    state_mod.upsert_program(_program(), db_path=db)

    t1 = datetime(2026, 10, 1, 12, 0, 0)
    t2 = datetime(2026, 10, 2, 12, 0, 0)
    r1 = ReconResult(program_key="hackerone:t", last_run=t1,
                     subdomains={"t.example.com": ["a.t.example.com", "b.t.example.com"]},
                     fingerprints={"a.t.example.com": {}})
    r2 = ReconResult(program_key="hackerone:t", last_run=t2,
                     subdomains={"t.example.com": ["b.t.example.com", "c.t.example.com"]},
                     fingerprints={"a.t.example.com": {}, "c.t.example.com": {}})
    state_mod.upsert_recon_result(r1, db_path=db)
    assert state_mod.recon_diff("hackerone:t", db_path=db) is None  # only one snapshot yet
    state_mod.upsert_recon_result(r2, db_path=db)

    diff = state_mod.recon_diff("hackerone:t", db_path=db)
    assert diff["new_subdomains"] == ["c.t.example.com"]
    assert diff["removed_subdomains"] == ["a.t.example.com"]
    assert diff["new_hosts"] == ["c.t.example.com"]


def test_recon_diff_none_with_single_snapshot(tmp_path):
    db = tmp_path / "s.db"
    state_mod.upsert_program(_program(), db_path=db)
    state_mod.upsert_recon_result(ReconResult(program_key="hackerone:t"), db_path=db)
    assert state_mod.recon_diff("hackerone:t", db_path=db) is None
