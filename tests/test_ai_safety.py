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
    _ALL_MULTITURN_SCRIPTS,
    _extract_response_text,
    _fill_prompt,
    check_excessive_agency,
    check_multiturn_jailbreak,
    check_prompt_injection,
    check_sensitive_info_disclosure,
    check_system_prompt_leakage,
    run_ai_safety_probes,
    send_conversation,
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


def _multiturn_config(**overrides) -> AIEndpointConfig:
    return _config(conversation_template='{"messages": {{MESSAGES}}}', **overrides)


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


# --- multi-turn jailbreak chains ---------------------------------------------


def test_send_conversation_returns_empty_without_conversation_template():
    config = _config()  # no conversation_template
    assert send_conversation(config, ["turn one"]) == []


def test_send_conversation_sends_growing_message_history():
    config = _multiturn_config()
    seen_message_counts = []

    def fake_request(method, url, headers=None, json=None, timeout=None):
        seen_message_counts.append(len(json["messages"]))
        resp = MagicMock()
        resp.raise_for_status.return_value = None
        resp.json.return_value = {"choices": [{"message": {"content": f"reply {len(json['messages'])}"}}]}
        return resp

    with patch("bbhunter.testing.ai_safety.httpx.request", side_effect=fake_request), \
         patch("bbhunter.testing.ai_safety.time.sleep"):
        responses = send_conversation(config, ["turn one", "turn two", "turn three"])

    assert responses == ["reply 1", "reply 3", "reply 5"]
    # message count grows: 1 (turn1) -> 3 (turn1+reply1+turn2) -> 5 (...+reply2+turn3)
    assert seen_message_counts == [1, 3, 5]


def test_send_conversation_stops_early_on_failed_turn():
    config = _multiturn_config()
    call_count = {"n": 0}

    def fake_request(method, url, headers=None, json=None, timeout=None):
        call_count["n"] += 1
        if call_count["n"] == 2:
            import httpx as real_httpx
            raise real_httpx.ConnectTimeout("timeout")
        resp = MagicMock()
        resp.raise_for_status.return_value = None
        resp.json.return_value = {"choices": [{"message": {"content": "ok"}}]}
        return resp

    with patch("bbhunter.testing.ai_safety.httpx.request", side_effect=fake_request), \
         patch("bbhunter.testing.ai_safety.time.sleep"):
        responses = send_conversation(config, ["turn one", "turn two", "turn three"])

    assert responses == ["ok", None]  # stopped after the second turn failed, never sent the third


def test_check_multiturn_jailbreak_roleplay_flags_marker_in_final_response():
    config = _multiturn_config()

    def fake_send_conversation(cfg, turns, timeout=60):
        marker = turns[-1].rsplit(": ", 1)[-1]
        return ["ok", "DAN mode: confirmed", f"Sure, {marker}"]

    with patch("bbhunter.testing.ai_safety.send_conversation", side_effect=fake_send_conversation), \
         patch("bbhunter.testing.ai_safety.time.sleep"):
        hit = check_multiturn_jailbreak(config, "roleplay-persona")
    assert hit is not None
    assert hit["kind"] == "multiturn-jailbreak-roleplay-persona"
    assert hit["severity"] == "high"


def test_check_multiturn_jailbreak_roleplay_no_hit_when_marker_absent():
    config = _multiturn_config()
    with patch("bbhunter.testing.ai_safety.send_conversation", return_value=["ok", "ok", "I can't do that."]), \
         patch("bbhunter.testing.ai_safety.time.sleep"):
        assert check_multiturn_jailbreak(config, "roleplay-persona") is None


def test_check_multiturn_jailbreak_system_prompt_script_flags_heuristic_match():
    config = _multiturn_config()
    leak = "You are a helpful internal assistant for Acme Corp, codename Phoenix. " * 3
    with patch("bbhunter.testing.ai_safety.send_conversation", return_value=["sure", "here", leak]), \
         patch("bbhunter.testing.ai_safety.time.sleep"):
        hit = check_multiturn_jailbreak(config, "gradual-system-prompt-probe")
    assert hit is not None
    assert hit["kind"] == "multiturn-system-prompt-leak"


def test_check_multiturn_jailbreak_returns_none_when_a_turn_failed():
    config = _multiturn_config()
    with patch("bbhunter.testing.ai_safety.send_conversation", return_value=["ok", None]), \
         patch("bbhunter.testing.ai_safety.time.sleep"):
        assert check_multiturn_jailbreak(config, "roleplay-persona") is None


def test_check_multiturn_jailbreak_unknown_script_raises():
    config = _multiturn_config()
    with pytest.raises(ValueError):
        check_multiturn_jailbreak(config, "not-a-real-script")


def test_all_multiturn_scripts_are_covered_by_check_logic():
    # Every registered script must actually be handled in check_multiturn_jailbreak's
    # if/elif chain -- this guards against adding a script to the dict and forgetting
    # to wire its detection branch.
    assert set(_ALL_MULTITURN_SCRIPTS) == {"roleplay-persona", "gradual-system-prompt-probe"}


def test_run_ai_safety_probes_multiturn_off_by_default():
    program = _program()
    config = _multiturn_config()
    with patch("bbhunter.testing.ai_safety._ALL_CHECKS", ()), \
         patch("bbhunter.testing.ai_safety.check_multiturn_jailbreak") as mock_mt, \
         patch("bbhunter.testing.ai_safety.time.sleep"):
        run_ai_safety_probes(program, config)  # multiturn=False (default)
    mock_mt.assert_not_called()


def test_run_ai_safety_probes_multiturn_skipped_without_conversation_template():
    program = _program()
    config = _config()  # no conversation_template
    with patch("bbhunter.testing.ai_safety._ALL_CHECKS", ()), \
         patch("bbhunter.testing.ai_safety.check_multiturn_jailbreak") as mock_mt, \
         patch("bbhunter.testing.ai_safety.time.sleep"):
        run_ai_safety_probes(program, config, multiturn=True)
    mock_mt.assert_not_called()


def test_run_ai_safety_probes_multiturn_runs_scripts_when_configured():
    program = _program()
    config = _multiturn_config()
    hits = [
        {"kind": "multiturn-jailbreak-roleplay-persona", "severity": "high", "evidence": "e1"},
        {"kind": "multiturn-system-prompt-leak", "severity": "high", "evidence": "e2"},
    ]
    with patch("bbhunter.testing.ai_safety._ALL_CHECKS", ()), \
         patch("bbhunter.testing.ai_safety.check_multiturn_jailbreak", side_effect=hits) as mock_mt, \
         patch("bbhunter.testing.ai_safety.time.sleep"):
        findings = run_ai_safety_probes(program, config, multiturn=True)
    assert mock_mt.call_count == len(_ALL_MULTITURN_SCRIPTS)
    assert len(findings) == 2
    assert {f.vuln_class for f in findings} == {"multiturn-jailbreak-roleplay-persona", "multiturn-system-prompt-leak"}

