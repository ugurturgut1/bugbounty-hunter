"""Phase 5: defense-in-depth safety -- scope guard + kill switch."""
import pytest

from bbhunter import safety
from bbhunter.models import AssetType, Platform, Program, ScopeAsset, TestType, RulesOfEngagement
from bbhunter.safety import (
    KillSwitchEngaged,
    ScopeViolation,
    assert_active_allowed,
    assert_in_scope,
    is_in_scope,
    killswitch_engaged,
)
from bbhunter.testing.idor import run_idor_check


def _program():
    return Program(
        platform=Platform.HACKERONE, handle="t", name="T", url="https://h1/t",
        in_scope=[
            ScopeAsset(identifier="*.example.com", asset_type=AssetType.WILDCARD, in_scope=True),
            ScopeAsset(identifier="app.other.com", asset_type=AssetType.URL, in_scope=True),
        ],
        out_of_scope=[ScopeAsset(identifier="secret.example.com", asset_type=AssetType.URL, in_scope=False)],
    )


def test_scope_wildcard_and_url_matching():
    p = _program()
    assert is_in_scope(p, "api.example.com")       # wildcard subdomain
    assert is_in_scope(p, "example.com")           # apex
    assert is_in_scope(p, "app.other.com")         # exact url
    assert not is_in_scope(p, "other.com")         # url is exact-only
    assert not is_in_scope(p, "evil.com")          # unrelated
    assert not is_in_scope(p, "secret.example.com")  # out-of-scope wins over wildcard


def test_assert_in_scope_raises_for_off_scope():
    with pytest.raises(ScopeViolation):
        assert_in_scope(_program(), "https://evil.com/x")


def test_run_idor_check_refuses_off_scope_url():
    p = _program()
    p.rules = RulesOfEngagement(confidence="high", human_reviewed=True,
                                allowed_test_types=[TestType.ACTIVE_LOW_IMPACT])
    with pytest.raises(ScopeViolation):
        run_idor_check(p, "https://evil.com/orders/1", {"A": "1"}, {"B": "2"})


def test_killswitch_via_env(monkeypatch):
    monkeypatch.setenv("BBHUNTER_KILLSWITCH", "1")
    assert killswitch_engaged()
    with pytest.raises(KillSwitchEngaged):
        assert_active_allowed()
    monkeypatch.setenv("BBHUNTER_KILLSWITCH", "0")
    assert not killswitch_engaged()


def test_killswitch_file(tmp_path, monkeypatch):
    monkeypatch.delenv("BBHUNTER_KILLSWITCH", raising=False)
    monkeypatch.setattr(safety, "KILLSWITCH_FILE", tmp_path / "KILLSWITCH")
    assert not killswitch_engaged()
    safety.set_killswitch(True)
    assert killswitch_engaged()
    safety.set_killswitch(False)
    assert not killswitch_engaged()
