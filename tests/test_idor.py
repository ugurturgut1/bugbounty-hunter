"""Tests for the IDOR two-identity session-diffing check
(testing/idor.py). All HTTP calls are mocked -- never a real request."""
from unittest.mock import MagicMock, patch

import pytest

from bbhunter.models import AssetType, FindingStatus, Platform, Program, RulesOfEngagement, ScopeAsset, TestType
from bbhunter.testing.idor import check_idor, run_idor_check


def _program(*, approved: bool = True) -> Program:
    rules = RulesOfEngagement(
        allowed_test_types={TestType.PASSIVE_RECON, TestType.ACTIVE_LOW_IMPACT},
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


def _resp(status_code=200, text="normal order details page here", content=None):
    r = MagicMock()
    r.status_code = status_code
    r.text = text
    r.content = content if content is not None else text.encode()
    return r


def test_flags_when_other_identity_also_gets_clean_200():
    owner_resp = _resp(text="order #12345 details: widget x2")
    other_resp = _resp(text="order #12345 details: widget x3")  # similar size, still real content
    with patch("bbhunter.testing.idor.httpx.get", side_effect=[owner_resp, other_resp]):
        hit = check_idor("https://x/orders/12345", {"Authorization": "A"}, {"Authorization": "B"})
    assert hit is not None
    assert hit["kind"] == "idor-candidate"


def test_no_hit_when_owner_baseline_itself_fails():
    owner_resp = _resp(status_code=403, text="forbidden")
    with patch("bbhunter.testing.idor.httpx.get", return_value=owner_resp):
        hit = check_idor("https://x/orders/12345", {"Authorization": "A"}, {"Authorization": "B"})
    assert hit is None


def test_no_hit_when_owner_baseline_looks_denied_despite_200():
    owner_resp = _resp(status_code=200, text="Please log in to continue")
    with patch("bbhunter.testing.idor.httpx.get", return_value=owner_resp):
        hit = check_idor("https://x/orders/12345", {"Authorization": "A"}, {"Authorization": "B"})
    assert hit is None


def test_no_hit_when_other_identity_properly_denied():
    owner_resp = _resp(text="order #12345 details: widget x2")
    other_resp = _resp(status_code=403, text="forbidden")
    with patch("bbhunter.testing.idor.httpx.get", side_effect=[owner_resp, other_resp]):
        hit = check_idor("https://x/orders/12345", {"Authorization": "A"}, {"Authorization": "B"})
    assert hit is None


def test_no_hit_when_other_identity_gets_denial_body_with_200_status():
    owner_resp = _resp(text="order #12345 details: widget x2")
    other_resp = _resp(status_code=200, text="Access denied for this resource")
    with patch("bbhunter.testing.idor.httpx.get", side_effect=[owner_resp, other_resp]):
        hit = check_idor("https://x/orders/12345", {"Authorization": "A"}, {"Authorization": "B"})
    assert hit is None


def test_no_hit_when_response_sizes_differ_a_lot():
    owner_resp = _resp(text="x" * 5000)
    other_resp = _resp(text="generic redirect page")  # tiny in comparison -- likely a different page
    with patch("bbhunter.testing.idor.httpx.get", side_effect=[owner_resp, other_resp]):
        hit = check_idor("https://x/orders/12345", {"Authorization": "A"}, {"Authorization": "B"})
    assert hit is None


def test_no_hit_on_http_error():
    import httpx as real_httpx

    with patch("bbhunter.testing.idor.httpx.get", side_effect=real_httpx.ConnectTimeout("timeout")):
        hit = check_idor("https://x/orders/12345", {"Authorization": "A"}, {"Authorization": "B"})
    assert hit is None


def test_run_idor_check_refuses_without_approval():
    program = _program(approved=False)
    with pytest.raises(RuntimeError):
        run_idor_check(program, "https://x/orders/12345", {"Authorization": "A"}, {"Authorization": "B"})


def test_run_idor_check_maps_hit_to_finding_with_owner_note():
    program = _program()
    owner_resp = _resp(text="order #12345 details: widget x2")
    other_resp = _resp(text="order #12345 details: widget x3")
    with patch("bbhunter.testing.idor.httpx.get", side_effect=[owner_resp, other_resp]):
        findings = run_idor_check(
            program, "https://x/orders/12345", {"Authorization": "A"}, {"Authorization": "B"},
            owner_note="belongs to test account A",
        )
    assert len(findings) == 1
    assert findings[0].test_type == TestType.ACTIVE_LOW_IMPACT
    assert findings[0].status == FindingStatus.CANDIDATE
    assert "belongs to test account A" in findings[0].evidence


def test_run_idor_check_returns_empty_list_when_no_hit():
    program = _program()
    owner_resp = _resp(status_code=403, text="forbidden")
    with patch("bbhunter.testing.idor.httpx.get", return_value=owner_resp):
        findings = run_idor_check(program, "https://x/orders/12345", {"Authorization": "A"}, {"Authorization": "B"})
    assert findings == []
