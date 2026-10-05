"""Tests for the auth/logic additions: CORS misconfig detection in
active._check_cors, the batch BOLA/BFLA runners, the token-leak and
session-replay checks, and the authlogic-plan generator."""
from unittest.mock import MagicMock, patch

from bbhunter.models import (
    AssetType,
    Platform,
    Program,
    ReconResult,
    RulesOfEngagement,
    ScopeAsset,
    TestType,
)
from bbhunter.testing.active import _CORS_PROBE_ORIGIN, _check_cors
from bbhunter.testing.auth_logic import check_session_valid, check_token_leak
from bbhunter.testing.authlogic_plan import build_plan
from bbhunter.testing.idor import run_idor_batch


def _resp(status=200, text="", headers=None, url="https://example.com/"):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.content = text.encode()
    r.headers = headers or {}
    r.url = url
    r.history = []
    return r


# ---- CORS ----

def test_cors_reflected_origin_with_credentials_is_flagged():
    client = MagicMock()
    client.get.return_value = _resp(headers={
        "access-control-allow-origin": _CORS_PROBE_ORIGIN,
        "access-control-allow-credentials": "true",
    })
    hit = _check_cors(client, "example.com")
    assert hit and hit["severity"] == "high"
    # the probe origin must actually be sent
    assert client.get.call_args.kwargs["headers"]["Origin"] == _CORS_PROBE_ORIGIN


def test_cors_wildcard_without_credentials_not_flagged():
    client = MagicMock()
    client.get.return_value = _resp(headers={"access-control-allow-origin": "*"})
    assert _check_cors(client, "example.com") is None


def test_cors_reflection_on_off_host_redirect_not_flagged():
    client = MagicMock()
    client.get.return_value = _resp(
        headers={"access-control-allow-origin": _CORS_PROBE_ORIGIN, "access-control-allow-credentials": "true"},
        url="https://sso.gateway.net/login",  # landed off-host
    )
    assert _check_cors(client, "example.com") is None


# ---- batch BOLA ----

def _program(active=True):
    rules = RulesOfEngagement(confidence="high" if active else "low")
    if active:
        rules.human_reviewed = True
        rules.allowed_test_types = [TestType.PASSIVE_RECON, TestType.ACTIVE_LOW_IMPACT]
    return Program(
        platform=Platform.HACKERONE, handle="t", name="T", url="https://h1/t",
        in_scope=[ScopeAsset(identifier="t.example.com", asset_type=AssetType.WILDCARD, in_scope=True)],
        rules=rules,
    )


def test_run_idor_batch_checks_every_url_and_aggregates():
    program = _program(active=True)
    urls = ["https://t.example.com/a/1", "https://t.example.com/b/2", "https://t.example.com/c/3"]
    calls = []

    def fake_check(url, owner, other, *, timeout=15, request_delay=0.0):
        calls.append(url)
        return {"kind": "idor-candidate", "severity": "high", "evidence": "e"} if url.endswith("2") else None

    with patch("bbhunter.testing.idor.check_idor", side_effect=fake_check), \
         patch("bbhunter.testing.idor.time.sleep"):
        findings = run_idor_batch(program, urls, {"A": "1"}, {"B": "2"})

    assert calls == urls  # every URL checked
    assert len(findings) == 1 and findings[0].asset.endswith("2")


# ---- token leak ----

def test_token_leak_detects_token_in_final_url():
    with patch("bbhunter.testing.auth_logic.httpx.get",
               return_value=_resp(text="ok", url="https://x/callback?session=SEKRIT")):
        hit = check_token_leak("https://x/go", {"Cookie": "s=SEKRIT"}, "SEKRIT")
    assert hit and "final URL" in hit["evidence"]


def test_token_leak_none_when_absent():
    with patch("bbhunter.testing.auth_logic.httpx.get", return_value=_resp(text="nothing here", url="https://x/ok")):
        assert check_token_leak("https://x/go", {}, "SEKRIT") is None


# ---- session replay ----

def test_session_still_valid_flags_non_denied_200():
    with patch("bbhunter.testing.auth_logic.httpx.get", return_value=_resp(status=200, text="welcome back")):
        hit = check_session_valid("https://x/account", {"Cookie": "dead"})
    assert hit and hit["kind"] == "session-not-invalidated"


def test_session_replay_none_when_denied():
    with patch("bbhunter.testing.auth_logic.httpx.get", return_value=_resp(status=403, text="forbidden")):
        assert check_session_valid("https://x/account", {"Cookie": "dead"}) is None


# ---- plan generator ----

def test_build_plan_classifies_object_refs_and_privileged():
    recon = ReconResult(
        program_key="hackerone:t",
        param_urls={"t.example.com": [
            "https://t.example.com/api/orders/123?x=1",       # numeric id -> BOLA
            "https://t.example.com/profile?userId=55",        # id param -> BOLA
            "https://t.example.com/admin/users",              # privileged -> BFLA
            "https://t.example.com/about",                    # neither
        ]},
        fingerprints={"api.t.example.com": {}, "www.t.example.com": {}},
    )
    plan = build_plan("hackerone:t", recon)
    assert "/api/orders/123?x=1" in plan
    assert "userId=55" in plan
    assert "/admin/users" in plan
    assert "/about" not in plan           # not an object ref or privileged
    assert "api.t.example.com" in plan    # api host surfaced
    assert "test-idor" in plan and "test-bfla" in plan
