"""Tests for the mass assignment check (testing/mass_assignment.py) --
the one write-capable check in this project. All HTTP calls are mocked,
never a real request."""
from unittest.mock import MagicMock, patch

import pytest

from bbhunter.models import AssetType, FindingStatus, Platform, Program, RulesOfEngagement, ScopeAsset, TestType
from bbhunter.testing.mass_assignment import check_mass_assignment, run_mass_assignment_check


def _program(*, approved: bool = True) -> Program:
    rules = RulesOfEngagement(
        allowed_test_types={TestType.PASSIVE_RECON, TestType.MASS_ASSIGNMENT_PROBE},
        human_reviewed=approved,
        confidence="high" if approved else "low",
        automated_scanners_allowed=True,
    )
    return Program(
        platform=Platform.HACKERONE,
        handle="test",
        name="Test",
        url="https://hackerone.com/test",
        in_scope=[ScopeAsset(identifier="example.com", asset_type=AssetType.URL, in_scope=True)],
        rules=rules,
    )


def _json_resp(status_code=200, data=None):
    r = MagicMock()
    r.status_code = status_code
    r.json.return_value = data if data is not None else {}
    return r


def test_flags_when_field_sticks_after_not_existing_before():
    # baseline (no field) -> patch accepted -> confirm (field now true) -> no revert possible
    responses = [
        _json_resp(data={"id": 1, "name": "x"}),  # baseline GET
        _json_resp(status_code=200),  # PATCH mutate
        _json_resp(data={"id": 1, "name": "x", "isAdmin": True}),  # confirm GET
    ]
    with patch("bbhunter.testing.mass_assignment.httpx.get", side_effect=[responses[0], responses[2]]), \
         patch("bbhunter.testing.mass_assignment.httpx.patch", return_value=responses[1]):
        hit = check_mass_assignment("https://x/profile/1", {"Authorization": "A"}, "isAdmin", True)
    assert hit is not None
    assert "no clean revert" in hit["evidence"]


def test_flags_and_successfully_reverts_when_field_existed_before():
    baseline = _json_resp(data={"id": 1, "role": "user"})
    mutate = _json_resp(status_code=200)
    confirm = _json_resp(data={"id": 1, "role": "admin"})
    revert = _json_resp(status_code=200)
    confirm_after_revert = _json_resp(data={"id": 1, "role": "user"})

    with patch("bbhunter.testing.mass_assignment.httpx.get", side_effect=[baseline, confirm, confirm_after_revert]), \
         patch("bbhunter.testing.mass_assignment.httpx.patch", side_effect=[mutate, revert]):
        hit = check_mass_assignment("https://x/profile/1", {"Authorization": "A"}, "role", "admin")
    assert hit is not None
    assert "reverted back to its original baseline value successfully" in hit["evidence"]


def test_no_hit_when_baseline_is_not_json():
    baseline = MagicMock(status_code=200)
    baseline.json.side_effect = ValueError("no json")
    with patch("bbhunter.testing.mass_assignment.httpx.get", return_value=baseline):
        hit = check_mass_assignment("https://x/profile/1", {"Authorization": "A"}, "role", "admin")
    assert hit is None


def test_no_hit_when_baseline_status_not_200():
    baseline = _json_resp(status_code=403, data={})
    with patch("bbhunter.testing.mass_assignment.httpx.get", return_value=baseline):
        hit = check_mass_assignment("https://x/profile/1", {"Authorization": "A"}, "role", "admin")
    assert hit is None


def test_no_hit_when_mutation_rejected():
    baseline = _json_resp(data={"id": 1, "role": "user"})
    mutate = _json_resp(status_code=403)
    with patch("bbhunter.testing.mass_assignment.httpx.get", return_value=baseline), \
         patch("bbhunter.testing.mass_assignment.httpx.patch", return_value=mutate):
        hit = check_mass_assignment("https://x/profile/1", {"Authorization": "A"}, "role", "admin")
    assert hit is None


def test_no_hit_when_field_did_not_actually_stick():
    baseline = _json_resp(data={"id": 1, "role": "user"})
    mutate = _json_resp(status_code=200)
    confirm = _json_resp(data={"id": 1, "role": "user"})  # unchanged despite 200 on the PATCH
    with patch("bbhunter.testing.mass_assignment.httpx.get", side_effect=[baseline, confirm]), \
         patch("bbhunter.testing.mass_assignment.httpx.patch", return_value=mutate):
        hit = check_mass_assignment("https://x/profile/1", {"Authorization": "A"}, "role", "admin")
    assert hit is None


def test_no_hit_on_http_error_during_baseline():
    import httpx as real_httpx

    with patch("bbhunter.testing.mass_assignment.httpx.get", side_effect=real_httpx.ConnectTimeout("timeout")):
        hit = check_mass_assignment("https://x/profile/1", {"Authorization": "A"}, "role", "admin")
    assert hit is None


def test_revert_failure_is_noted_in_evidence():
    baseline = _json_resp(data={"id": 1, "role": "user"})
    mutate = _json_resp(status_code=200)
    confirm = _json_resp(data={"id": 1, "role": "admin"})
    revert = _json_resp(status_code=500)

    with patch("bbhunter.testing.mass_assignment.httpx.get", side_effect=[baseline, confirm]), \
         patch("bbhunter.testing.mass_assignment.httpx.patch", side_effect=[mutate, revert]):
        hit = check_mass_assignment("https://x/profile/1", {"Authorization": "A"}, "role", "admin")
    assert hit is not None
    assert "revert PATCH failed" in hit["evidence"]


def test_run_mass_assignment_check_refuses_without_mass_assignment_approval():
    program = _program(approved=False)
    with pytest.raises(RuntimeError):
        run_mass_assignment_check(program, "https://x/profile/1", {"Authorization": "A"}, "role", "admin")


def test_run_mass_assignment_check_active_low_impact_approval_alone_is_not_enough():
    # Regression guard: MASS_ASSIGNMENT_PROBE must be its own separate approval,
    # not satisfied just because active_low_impact was approved on the program.
    rules = RulesOfEngagement(
        allowed_test_types={TestType.PASSIVE_RECON, TestType.ACTIVE_LOW_IMPACT},
        human_reviewed=True,
        confidence="high",
        automated_scanners_allowed=True,
    )
    program = Program(
        platform=Platform.HACKERONE, handle="test", name="Test", url="https://hackerone.com/test",
        in_scope=[ScopeAsset(identifier="example.com", asset_type=AssetType.URL, in_scope=True)],
        rules=rules,
    )
    with pytest.raises(RuntimeError):
        run_mass_assignment_check(program, "https://x/profile/1", {"Authorization": "A"}, "role", "admin")


def test_run_mass_assignment_check_maps_hit_to_finding():
    program = _program()
    baseline = _json_resp(data={"id": 1, "role": "user"})
    mutate = _json_resp(status_code=200)
    confirm = _json_resp(data={"id": 1, "role": "admin"})
    revert = _json_resp(status_code=200)
    confirm_after_revert = _json_resp(data={"id": 1, "role": "user"})

    with patch("bbhunter.testing.mass_assignment.httpx.get", side_effect=[baseline, confirm, confirm_after_revert]), \
         patch("bbhunter.testing.mass_assignment.httpx.patch", side_effect=[mutate, revert]):
        findings = run_mass_assignment_check(
            program, "https://x/profile/1", {"Authorization": "A"}, "role", "admin",
            owner_note="test account A, my own throwaway profile",
        )
    assert len(findings) == 1
    assert findings[0].test_type == TestType.MASS_ASSIGNMENT_PROBE
    assert findings[0].status == FindingStatus.CANDIDATE
    assert "throwaway profile" in findings[0].evidence
