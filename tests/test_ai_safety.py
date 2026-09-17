"""Tests for the AI/LLM safety probe module (testing/ai_safety.py).
Every HTTP call to the (would-be real) model endpoint is mocked -- these
never make a real API call or spend real API credits."""
import json
from unittest.mock import MagicMock, patch

import pytest

from bbhunter.models import (
    AIEndpointConfig,
    AssetType,
    FindingStatus,
    Platform,
    Program,
    RulesOfEngagement,
    ScopeAsset,
    TestType,
)
from bbhunter.testing.ai_safety import (
    _extract_response_text,
    _fill_prompt,
    check_excessive_agency,
    check_prompt_injection,
    check_sensitive_info_disclosure,
    check_system_prompt_leakage,
    run_ai_safety_probes,
    send_prompt,
)


def _config(**overrides) -> AIEndpointConfig:
    defaults = dict(
        program_key="test",
        url="https://api.example.com/v1/chat",
        request_template='{"messages": [{"role": "user", "content": "{{PROMPT}}"}]}',
        response_text_path="choices.0.message.content",
    )
    defaults.update(overrides)
    return AIEndpointConfig(**defaults)


def _program(*, approved: bool = True) -> Program:
    rules = RulesOfEngagement(
        allowed_test_types={TestType.PASSIVE_RECON, TestType.AI_SAFETY_PROBE},
        human_reviewed=approved,
        confidence="high" if approved else "low",
        automated_scanners_allowed=True,
    )
    return Program(
        platform=Platform.HACKERONE,
        handle="test",
        name="Test",
        url="https://hackerone.com/test",
        in_scope=[ScopeAsset(identifier="api.example.com", asset_type=AssetType.URL, in_scope=True)],
        rules=rules,
    )


def test_fill_prompt_json_escapes_special_characters():
    result = _fill_prompt('{"content": "{{PROMPT}}"}', 'He said "hi" and\nnewline')
    parsed = json.loads(result)
    assert parsed["content"] == 'He said "hi" and\nnewline'


def test_extract_response_text_walks_dict_and_list_path():
    data = {"choices": [{"message": {"content": "hello"}}]}
    assert _extract_response_text(data, "choices.0.message.content") == "hello"


def test_extract_response_text_returns_none_for_bad_path():
    data = {"choices": []}
    assert _extract_response_text(data, "choices.0.message.content") is None


def test_extract_response_text_returns_none_when_leaf_is_not_a_string():
    data = {"choices": [{"message": {"content": 42}}]}
    assert _extract_response_text(data, "choices.0.message.content") is None


def _fake_response(text: str):
    resp = MagicMock()
    resp.raise_for_status.return_value = None
    resp.json.return_value = {"choices": [{"message": {"content": text}}]}
    return resp


def test_send_prompt_injects_auth_header_from_env_var():
    config = _config(auth_header="Authorization", auth_env_var="MY_TEST_TOKEN", auth_template="Bearer {token}")
    with patch("bbhunter.testing.ai_safety.os.environ.get", return_value="secret123"), \
         patch("bbhunter.testing.ai_safety.httpx.request", return_value=_fake_response("hi")) as req:
        result = send_prompt(config, "hello")
    assert result == "hi"
    sent_headers = req.call_args.kwargs["headers"]
    assert sent_headers["Authorization"] == "Bearer secret123"


def test_send_prompt_returns_none_when_template_is_invalid_json():
    config = _config(request_template='{"content": {{PROMPT}}}')  # unquoted placeholder -> invalid JSON after fill
    result = send_prompt(config, "hello")
    assert result is None


def test_send_prompt_returns_none_on_http_error():
    import httpx as real_httpx

    config = _config()
    with patch("bbhunter.testing.ai_safety.httpx.request", side_effect=real_httpx.ConnectTimeout("timeout")):
        result = send_prompt(config, "hello")
    assert result is None


def test_prompt_injection_flags_when_marker_echoed_back():
    config = _config()
    with patch("bbhunter.testing.ai_safety.send_prompt") as mock_send:
        def fake_send(cfg, prompt, timeout=60):
            marker = prompt.rsplit(": ", 1)[-1]
            return f"Sure! {marker}"
        mock_send.side_effect = fake_send
        hit = check_prompt_injection(config)
    assert hit is not None
    assert hit["kind"] == "prompt-injection-canary-compliance"


def test_prompt_injection_no_hit_when_marker_not_echoed():
    config = _config()
    with patch("bbhunter.testing.ai_safety.send_prompt", return_value="I can't do that."):
        assert check_prompt_injection(config) is None


def test_system_prompt_leakage_flags_heuristic_match():
    config = _config()
    long_leak = "You are a helpful assistant for Acme Corp. " * 3
    with patch("bbhunter.testing.ai_safety.send_prompt", return_value=long_leak):
        hit = check_system_prompt_leakage(config)
    assert hit is not None
    assert hit["kind"] == "system-prompt-leakage-candidate"


def test_system_prompt_leakage_no_hit_on_short_refusal():
    config = _config()
    with patch("bbhunter.testing.ai_safety.send_prompt", return_value="I can't share that."):
        assert check_system_prompt_leakage(config) is None


def test_sensitive_info_disclosure_flags_real_secret_pattern():
    config = _config()
    with patch("bbhunter.testing.ai_safety.send_prompt", return_value="Sure, here: sk-abcdefghijklmnopqrstuvwx"):
        hit = check_sensitive_info_disclosure(config)
    assert hit is not None
    assert hit["severity"] == "critical"


def test_sensitive_info_disclosure_no_hit_without_secret_pattern():
    config = _config()
    with patch("bbhunter.testing.ai_safety.send_prompt", return_value="I don't have access to any credentials."):
        assert check_sensitive_info_disclosure(config) is None


def test_excessive_agency_no_hit_on_refusal():
    config = _config()
    with patch("bbhunter.testing.ai_safety.send_prompt", return_value="I can't execute shell commands."):
        assert check_excessive_agency(config) is None


def test_excessive_agency_flags_non_refusal():
    config = _config()
    with patch("bbhunter.testing.ai_safety.send_prompt", return_value="ubuntu\n"):
        hit = check_excessive_agency(config)
    assert hit is not None
    assert hit["kind"] == "excessive-agency-candidate"


def test_run_ai_safety_probes_refuses_without_approval():
    program = _program(approved=False)
    config = _config()
    with pytest.raises(RuntimeError):
        run_ai_safety_probes(program, config)


def test_run_ai_safety_probes_maps_hits_to_findings():
    # _ALL_CHECKS is a tuple of function references captured at module load,
    # so patching the individual check_* names wouldn't affect what
    # run_ai_safety_probes actually iterates over -- patch the tuple itself.
    program = _program()
    config = _config()
    hit_check = MagicMock(return_value={"kind": "x", "severity": "medium", "evidence": "e"})
    miss_check = MagicMock(return_value=None)
    with patch("bbhunter.testing.ai_safety._ALL_CHECKS", (hit_check, miss_check, miss_check, miss_check)), \
         patch("bbhunter.testing.ai_safety.time.sleep"):
        findings = run_ai_safety_probes(program, config)
    assert len(findings) == 1
    assert findings[0].test_type == TestType.AI_SAFETY_PROBE
    assert findings[0].status == FindingStatus.CANDIDATE
    assert findings[0].asset == config.url


def test_run_ai_safety_probes_runs_all_four_checks():
    program = _program()
    config = _config()
    checks = tuple(MagicMock(return_value=None) for _ in range(4))
    with patch("bbhunter.testing.ai_safety._ALL_CHECKS", checks), \
         patch("bbhunter.testing.ai_safety.time.sleep"):
        run_ai_safety_probes(program, config)
    for mock in checks:
        mock.assert_called_once()
