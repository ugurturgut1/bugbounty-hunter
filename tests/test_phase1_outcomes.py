"""Phase 1: outcome feedback loop -- outcome aggregation + prioritize weighting."""
from bbhunter.models import (
    AssetType, Finding, FindingStatus, Platform, Program, ScopeAsset, TestType,
)
from bbhunter.prioritize import outcome_multiplier, score_program
from bbhunter import state as state_mod


def _finding(fid, program_key, status, vuln_class="idor-candidate", bounty=None):
    return Finding(id=fid, program_key=program_key, asset="t.example.com", title=fid,
                   vuln_class=vuln_class, test_type=TestType.ACTIVE_LOW_IMPACT, evidence="e",
                   status=status, bounty_amount=bounty)


def _program():
    return Program(platform=Platform.HACKERONE, handle="t", name="T", url="https://h1/t",
                   in_scope=[ScopeAsset(identifier="t.example.com", asset_type=AssetType.WILDCARD, in_scope=True)])


def test_outcome_stats_aggregate_by_program_and_check(tmp_path):
    db = tmp_path / "s.db"
    state_mod.upsert_program(_program(), db_path=db)
    state_mod.upsert_finding(_finding("a", "hackerone:t", FindingStatus.RESOLVED, bounty=500), db_path=db)
    state_mod.upsert_finding(_finding("b", "hackerone:t", FindingStatus.DUPLICATE), db_path=db)
    state_mod.upsert_finding(_finding("c", "hackerone:t", FindingStatus.CANDIDATE), db_path=db)  # not terminal

    prog = state_mod.program_outcome_stats(db_path=db)
    assert prog["hackerone:t"]["resolved"] == 1
    assert prog["hackerone:t"]["duplicate"] == 1
    assert prog["hackerone:t"]["bounty_total"] == 500
    assert "candidate" not in prog["hackerone:t"]  # candidates excluded

    check = state_mod.check_outcome_stats(db_path=db)
    assert check["idor-candidate"]["resolved"] == 1


def test_outcome_multiplier_rewards_resolved_penalizes_noise():
    assert outcome_multiplier(None) == (1.0, None)
    mult, reason = outcome_multiplier({"resolved": 2, "bounty_total": 1000})
    assert mult > 1.0 and "proven" in reason
    mult2, reason2 = outcome_multiplier({"resolved": 0, "duplicate": 3, "informative": 1, "bounty_total": 0})
    assert mult2 == 0.5 and "dupes" in reason2


def test_score_program_applies_outcome_boost():
    p = _program()
    base = score_program(p, already_reconned=False)
    boosted = score_program(p, already_reconned=False, outcome={"resolved": 2, "bounty_total": 500})
    assert boosted.score > base.score
