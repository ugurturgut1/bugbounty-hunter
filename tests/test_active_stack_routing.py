"""Tests for tech-stack-aware exposed-file check routing added to
testing/active.py: a WordPress-specific check should only fire against a
host recon's fingerprint data actually flagged as WordPress, not every
host regardless of what it's running."""
from unittest.mock import MagicMock, patch

from bbhunter.testing.active import _GENERIC_CHECKS, _STACK_CHECKS, _check_host, _detected_stacks


def test_no_fingerprint_data_detects_no_stack():
    assert _detected_stacks([], None, None) == set()


def test_tech_list_match_is_case_insensitive():
    assert _detected_stacks(["WordPress 6.4"], None, None) == {"wordpress"}


def test_server_header_match():
    assert _detected_stacks([], "Apache/2.4.41", None) == {"apache"}


def test_powered_by_header_match():
    assert _detected_stacks([], None, "Express") == {"express"}


def test_multiple_stacks_can_match_at_once():
    stacks = _detected_stacks(["PHP 8.2"], "Apache/2.4.41", None)
    assert stacks == {"php", "apache"}


def test_unrelated_tech_matches_nothing():
    assert _detected_stacks(["Cloudflare", "HSTS"], "cloudflare", None) == set()


def test_every_stack_key_self_detects():
    """Regression guard: every _STACK_CHECKS key must actually be
    reachable via _detected_stacks' substring match against itself --
    catches a typo'd key that would otherwise silently never fire."""
    for stack in _STACK_CHECKS:
        assert _detected_stacks([stack], None, None) == {stack}, stack


def test_new_devops_and_cms_stacks_detected():
    assert _detected_stacks(["Django"], None, None) == {"django"}
    assert _detected_stacks([], "Werkzeug/2.0 Python/3.9", None) == {"werkzeug"}
    assert _detected_stacks(["Jenkins"], None, None) == {"jenkins"}
    assert _detected_stacks(["Elasticsearch"], None, None) == {"elasticsearch"}
    assert _detected_stacks(["Grafana"], None, None) == {"grafana"}
    assert _detected_stacks(["Drupal 10"], None, None) == {"drupal"}


class _FakeResponse:
    def __init__(self, status_code=404, content=b"not found", text="not found"):
        self.status_code = status_code
        self.content = content
        self.text = text
        self.url = "https://example.com/"
        self.headers = {}


def test_check_host_with_no_fingerprint_only_runs_generic_checks():
    client = MagicMock()
    client.get.return_value = _FakeResponse()
    with patch("bbhunter.testing.active.time.sleep"):
        _check_host(client, "example.com", fingerprint=None)

    requested_paths = {call.args[0].split("example.com", 1)[-1] for call in client.get.call_args_list}
    # every generic check path was attempted...
    for path in _GENERIC_CHECKS:
        assert path in requested_paths
    # ...but no stack-specific path was, since no fingerprint was given
    for stack_checks in _STACK_CHECKS.values():
        for path in stack_checks:
            if path not in _GENERIC_CHECKS:
                assert path not in requested_paths


def test_check_host_with_wordpress_fingerprint_adds_wordpress_checks():
    client = MagicMock()
    client.get.return_value = _FakeResponse()
    fingerprint = {"tech": ["WordPress 6.4"], "server": "nginx", "powered_by": None}
    with patch("bbhunter.testing.active.time.sleep"):
        _check_host(client, "example.com", fingerprint=fingerprint)

    requested_paths = {call.args[0].split("example.com", 1)[-1] for call in client.get.call_args_list}
    assert "/wp-config.php.bak" in requested_paths
    assert "/wp-json/wp/v2/users" in requested_paths
    # a different stack's check should not have been added
    assert "/actuator/env" not in requested_paths


def test_check_host_flags_a_real_wordpress_hit():
    client = MagicMock()

    def fake_get(url, timeout=15, follow_redirects=True):
        if "wp-config.php.bak" in url:
            return _FakeResponse(status_code=200, content=b"x" * 500, text="<?php define('DB_NAME', 'wp');")
        return _FakeResponse()

    client.get.side_effect = fake_get
    fingerprint = {"tech": ["WordPress"], "server": None, "powered_by": None}
    with patch("bbhunter.testing.active.time.sleep"):
        hits = _check_host(client, "example.com", fingerprint=fingerprint)

    matching = [h for h in hits if h["path"] == "/wp-config.php.bak"]
    assert len(matching) == 1
    assert matching[0]["severity"] == "high"


def test_check_host_flags_exposed_werkzeug_debugger():
    client = MagicMock()

    def fake_get(url, timeout=15, follow_redirects=True):
        if url.endswith("/console"):
            return _FakeResponse(status_code=200, content=b"x" * 500, text="Werkzeug Debugger -- Traceback")
        return _FakeResponse()

    client.get.side_effect = fake_get
    fingerprint = {"tech": [], "server": "Werkzeug/2.0 Python/3.9", "powered_by": None}
    with patch("bbhunter.testing.active.time.sleep"):
        hits = _check_host(client, "example.com", fingerprint=fingerprint)

    matching = [h for h in hits if h["path"] == "/console"]
    assert len(matching) == 1
    assert matching[0]["severity"] == "critical"


def test_check_host_flags_exposed_jenkins_api():
    client = MagicMock()

    def fake_get(url, timeout=15, follow_redirects=True):
        if url.endswith("/api/json"):
            return _FakeResponse(status_code=200, content=b"x" * 500, text='{"jobs": [], "_class": "hudson.model.Hudson"}')
        return _FakeResponse()

    client.get.side_effect = fake_get
    fingerprint = {"tech": ["Jenkins"], "server": None, "powered_by": None}
    with patch("bbhunter.testing.active.time.sleep"):
        hits = _check_host(client, "example.com", fingerprint=fingerprint)

    matching = [h for h in hits if h["path"] == "/api/json"]
    assert len(matching) == 1
    assert matching[0]["severity"] == "high"


def test_new_generic_checks_are_attempted_against_every_host():
    client = MagicMock()
    client.get.return_value = _FakeResponse()
    with patch("bbhunter.testing.active.time.sleep"):
        _check_host(client, "example.com", fingerprint=None)

    requested_paths = {call.args[0].split("example.com", 1)[-1] for call in client.get.call_args_list}
    for path in ("/metrics", "/phpmyadmin/", "/adminer.php", "/v2/_catalog"):
        assert path in requested_paths
