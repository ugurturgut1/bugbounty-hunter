"""Tests for the security-header checks in testing/active.py's
_check_host: missing-header detection (now including COOP/CORP) and
weak-but-present CSP directive detection."""
from unittest.mock import MagicMock, patch

from bbhunter.testing.active import _check_host


class _FakeResponse:
    def __init__(self, status_code=200, content=b"ok", text="ok", headers=None):
        self.status_code = status_code
        self.content = content
        self.text = text
        self.url = "https://example.com/"
        self.headers = headers or {}


def _fake_get_factory(root_headers: dict):
    def fake_get(url, timeout=15, follow_redirects=True):
        if url.rstrip("/").endswith("example.com"):
            return _FakeResponse(headers=root_headers)
        return _FakeResponse(status_code=404, content=b"not found", text="not found")
    return fake_get


def test_missing_headers_now_includes_coop_and_corp():
    client = MagicMock()
    client.get.side_effect = _fake_get_factory({})
    with patch("bbhunter.testing.active.time.sleep"):
        hits = _check_host(client, "example.com", fingerprint=None)

    missing_hit = next(h for h in hits if h["title"].startswith("Missing security headers"))
    assert "cross-origin-opener-policy" in missing_hit["title"]
    assert "cross-origin-resource-policy" in missing_hit["title"]


def test_weak_csp_directive_flagged_when_present():
    client = MagicMock()
    headers = {"content-security-policy": "default-src 'self'; script-src 'unsafe-inline'"}
    client.get.side_effect = _fake_get_factory(headers)
    with patch("bbhunter.testing.active.time.sleep"):
        hits = _check_host(client, "example.com", fingerprint=None)

    weak_hits = [h for h in hits if "Weak Content-Security-Policy" in h["title"]]
    assert len(weak_hits) == 1
    assert "unsafe-inline" in weak_hits[0]["title"]
    assert weak_hits[0]["severity"] == "low"


def test_strong_csp_not_flagged_as_weak():
    client = MagicMock()
    headers = {"content-security-policy": "default-src 'self'; script-src 'self'"}
    client.get.side_effect = _fake_get_factory(headers)
    with patch("bbhunter.testing.active.time.sleep"):
        hits = _check_host(client, "example.com", fingerprint=None)

    assert not any("Weak Content-Security-Policy" in h["title"] for h in hits)


def test_no_csp_header_produces_no_weak_csp_hit():
    client = MagicMock()
    client.get.side_effect = _fake_get_factory({})
    with patch("bbhunter.testing.active.time.sleep"):
        hits = _check_host(client, "example.com", fingerprint=None)

    assert not any("Weak Content-Security-Policy" in h["title"] for h in hits)
