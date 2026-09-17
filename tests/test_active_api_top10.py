"""Tests for the OWASP API Top 10 2023 additions to testing/active.py:
excessive data exposure (sensitive JSON field-name scanning), API
inventory/shadow-version discovery, and the rate-limit-header signal."""
from unittest.mock import MagicMock, patch

from bbhunter.testing.active import _API_INVENTORY_CHECKS, _check_host, _scan_json_for_sensitive_fields


def test_scan_json_finds_top_level_sensitive_key():
    assert _scan_json_for_sensitive_fields({"password": "x", "username": "y"}) == ["password"]


def test_scan_json_finds_nested_sensitive_key():
    data = {"user": {"profile": {"api_key": "abc"}}}
    assert _scan_json_for_sensitive_fields(data) == ["api_key"]


def test_scan_json_finds_key_inside_list():
    data = {"users": [{"name": "a"}, {"ssn": "123-45-6789"}]}
    assert _scan_json_for_sensitive_fields(data) == ["ssn"]


def test_scan_json_clean_response_finds_nothing():
    data = {"id": 1, "name": "widget", "price": 9.99}
    assert _scan_json_for_sensitive_fields(data) == []


def test_scan_json_never_returns_the_value_itself():
    hits = _scan_json_for_sensitive_fields({"password": "supersecret123"})
    assert hits == ["password"]
    assert "supersecret123" not in hits


def test_scan_json_depth_capped():
    # build a deeply nested structure well past the depth cap
    data = {"password": "leaf"}
    for _ in range(20):
        data = {"nested": data}
    # should not raise, and the deeply-buried key is beyond the cap so won't be found --
    # this test exists to confirm no RecursionError/infinite loop, not to assert a specific find
    _scan_json_for_sensitive_fields(data)


class _FakeResponse:
    def __init__(self, status_code=200, text="not found", content=b"not found", headers=None, url="https://example.com/", json_data=None):
        self.status_code = status_code
        self.text = text
        self.content = content
        self.headers = headers or {}
        self.url = url
        self._json_data = json_data

    def json(self):
        if self._json_data is None:
            raise ValueError("no json")
        return self._json_data


def test_check_host_flags_excessive_data_exposure_on_root_json_response():
    client = MagicMock()

    def fake_get(url, timeout=15, follow_redirects=True):
        if url.endswith("example.com/"):
            return _FakeResponse(
                headers={"content-type": "application/json"},
                json_data={"id": 1, "password_hash": "x", "name": "test"},
            )
        return _FakeResponse()

    client.get.side_effect = fake_get
    with patch("bbhunter.testing.active.time.sleep"):
        hits = _check_host(client, "example.com", fingerprint=None)

    exposure_hits = [h for h in hits if "excessive data exposure" in h["title"].lower()]
    assert len(exposure_hits) == 1
    assert "password_hash" in exposure_hits[0]["title"]


def test_check_host_no_exposure_hit_for_clean_json():
    client = MagicMock()

    def fake_get(url, timeout=15, follow_redirects=True):
        if url.endswith("example.com/"):
            return _FakeResponse(headers={"content-type": "application/json"}, json_data={"id": 1, "name": "test"})
        return _FakeResponse()

    client.get.side_effect = fake_get
    with patch("bbhunter.testing.active.time.sleep"):
        hits = _check_host(client, "example.com", fingerprint=None)

    assert [h for h in hits if "excessive data exposure" in h["title"].lower()] == []


def test_check_host_no_exposure_hit_for_non_json_response():
    client = MagicMock()
    client.get.return_value = _FakeResponse(headers={"content-type": "text/html"})
    with patch("bbhunter.testing.active.time.sleep"):
        hits = _check_host(client, "example.com", fingerprint=None)
    assert [h for h in hits if "excessive data exposure" in h["title"].lower()] == []


def test_check_host_flags_missing_rate_limit_headers():
    client = MagicMock()
    client.get.return_value = _FakeResponse(headers={"content-type": "text/html"})
    with patch("bbhunter.testing.active.time.sleep"):
        hits = _check_host(client, "example.com", fingerprint=None)
    assert any("rate-limit" in h["title"].lower() for h in hits)


def test_check_host_no_rate_limit_hit_when_header_present():
    client = MagicMock()
    client.get.return_value = _FakeResponse(headers={"content-type": "text/html", "x-ratelimit-limit": "100"})
    with patch("bbhunter.testing.active.time.sleep"):
        hits = _check_host(client, "example.com", fingerprint=None)
    assert not any("rate-limit" in h["title"].lower() for h in hits)


def test_check_host_requests_api_inventory_paths():
    client = MagicMock()
    client.get.return_value = _FakeResponse()
    with patch("bbhunter.testing.active.time.sleep"):
        _check_host(client, "example.com", fingerprint=None)
    requested_paths = {call.args[0].split("example.com", 1)[-1] for call in client.get.call_args_list}
    for path in _API_INVENTORY_CHECKS:
        assert path in requested_paths


def test_check_host_flags_exposed_swagger_spec():
    client = MagicMock()

    def fake_get(url, timeout=15, follow_redirects=True):
        if "swagger.json" in url and "v1" not in url and "v2" not in url:
            return _FakeResponse(
                status_code=200,
                content=b"x" * 500,
                text='{"openapi": "3.0.0", "paths": {}}',
            )
        return _FakeResponse()

    client.get.side_effect = fake_get
    with patch("bbhunter.testing.active.time.sleep"):
        hits = _check_host(client, "example.com", fingerprint=None)

    matching = [h for h in hits if h["path"] == "/swagger.json"]
    assert len(matching) == 1


def test_finding_ids_dont_collide_when_multiple_root_path_hits_fire():
    # Regression check: missing-headers, rate-limit, and data-exposure hits
    # can all legitimately fire for the same "/" path in the same run --
    # run_active_checks must not silently drop any of them to an id collision.
    from bbhunter.models import AssetType, Platform, Program, RulesOfEngagement, ScopeAsset, TestType
    from bbhunter.testing.active import run_active_checks

    client_get_responses = {
        "/": _FakeResponse(headers={"content-type": "application/json"}, json_data={"password": "x"}),
    }

    def fake_check_host(client, host, fingerprint=None):
        return [
            {"path": "/", "title": "Missing security headers: x", "severity": "info", "status_code": 200, "url": "https://h/"},
            {"path": "/", "title": "No rate-limit headers observed on the root response", "severity": "info", "status_code": 200, "url": "https://h/"},
            {"path": "/", "title": "Possible excessive data exposure: sensitive-looking field name(s) in JSON response: password", "severity": "medium", "status_code": 200, "url": "https://h/"},
        ]

    rules = RulesOfEngagement(
        allowed_test_types={TestType.PASSIVE_RECON, TestType.ACTIVE_LOW_IMPACT},
        human_reviewed=True,
        confidence="high",
        automated_scanners_allowed=True,
    )
    program = Program(
        platform=Platform.HACKERONE,
        handle="test",
        name="Test",
        url="https://hackerone.com/test",
        in_scope=[ScopeAsset(identifier="example.com", asset_type=AssetType.URL, in_scope=True)],
        rules=rules,
    )

    with patch("bbhunter.testing.active._check_host", side_effect=fake_check_host):
        findings = run_active_checks(program, None)

    ids = [f.id for f in findings]
    assert len(ids) == len(set(ids)), f"duplicate finding ids: {ids}"
    assert len(findings) == 3
