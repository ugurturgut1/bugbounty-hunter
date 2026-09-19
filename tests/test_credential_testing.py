"""Tests for testing/credential_testing.py. All HTTP calls are mocked."""
from unittest.mock import MagicMock, patch

import pytest

from bbhunter.models import (
    AssetType,
    Platform,
    Program,
    RulesOfEngagement,
    ScopeAsset,
    TestType,
)
from bbhunter.testing.credential_testing import (
    MAX_CREDENTIALS_PER_RUN,
    run_credential_test,
    test_credentials as _test_credentials,
)


def _program(*, approved: bool = True) -> Program:
    rules = RulesOfEngagement(
        allowed_test_types={TestType.PASSIVE_RECON, TestType.CREDENTIAL_TESTING},
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


def test_refuses_more_than_max_credentials():
    too_many = [(f"user{i}", "pw") for i in range(MAX_CREDENTIALS_PER_RUN + 1)]
    with pytest.raises(ValueError):
        _test_credentials("https://example.com/login", "user", "pass", too_many, RulesOfEngagement())


def test_stops_immediately_on_lockout_signature():
    client = MagicMock()
    calls = {"n": 0}

    def fake_post(url, data=None):
        calls["n"] += 1
        return MagicMock(status_code=200, text="Account locked due to too many attempts", content=b"x" * 50)

    client.post.side_effect = fake_post
    with patch("bbhunter.testing.credential_testing.httpx.Client") as mock_client_cls, \
         patch("bbhunter.testing.credential_testing.time.sleep"):
        mock_client_cls.return_value.__enter__.return_value = client
        hits = _test_credentials(
            "https://example.com/login", "user", "pass",
            [("a", "1"), ("b", "2"), ("c", "3")], RulesOfEngagement(),
        )
    assert calls["n"] == 1  # stopped after the first attempt, never tried b/c
    assert len(hits) == 1
    assert hits[0]["kind"] == "credential-testing-stopped-lockout-signal"


def test_success_signature_flags_a_hit():
    client = MagicMock()
    client.post.return_value = MagicMock(status_code=200, text="Welcome to your dashboard", content=b"x" * 200)
    with patch("bbhunter.testing.credential_testing.httpx.Client") as mock_client_cls, \
         patch("bbhunter.testing.credential_testing.time.sleep"):
        mock_client_cls.return_value.__enter__.return_value = client
        hits = _test_credentials(
            "https://example.com/login", "user", "pass", [("admin", "admin")],
            RulesOfEngagement(), success_signature="dashboard",
        )
    assert len(hits) == 1
    assert hits[0]["kind"] == "credential-testing-possible-success"
    assert hits[0]["username"] == "admin"


def test_no_hit_when_no_success_signature_and_all_shapes_match():
    client = MagicMock()
    client.post.return_value = MagicMock(status_code=401, text="invalid credentials", content=b"x" * 30)
    with patch("bbhunter.testing.credential_testing.httpx.Client") as mock_client_cls, \
         patch("bbhunter.testing.credential_testing.time.sleep"):
        mock_client_cls.return_value.__enter__.return_value = client
        hits = _test_credentials(
            "https://example.com/login", "user", "pass", [("a", "1"), ("b", "2")], RulesOfEngagement(),
        )
    assert hits == []


def test_run_credential_test_refuses_without_approval():
    program = _program(approved=False)
    with pytest.raises(RuntimeError):
        run_credential_test(program, "https://example.com/login", "user", "pass", [("a", "1")])


def test_run_credential_test_maps_hits_to_findings():
    program = _program()
    fake_hit = {"kind": "credential-testing-possible-success", "username": "admin", "severity": "critical", "evidence": "test"}
    with patch("bbhunter.testing.credential_testing.test_credentials", return_value=[fake_hit]):
        findings = run_credential_test(program, "https://example.com/login", "user", "pass", [("admin", "admin")])
    assert len(findings) == 1
    assert findings[0].test_type == TestType.CREDENTIAL_TESTING
    assert findings[0].asset == "example.com"
