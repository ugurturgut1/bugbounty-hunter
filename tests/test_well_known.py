"""Tests for recon/well_known.py -- robots.txt/security.txt disclosure
checks. All HTTP calls are mocked, no real network access required."""
from unittest.mock import MagicMock, patch

import httpx

from bbhunter.recon.well_known import check_robots_txt, check_security_txt

_HEADERS = {"User-Agent": "bbhunter-recon/0.1"}


def _fake_response(status_code: int, text: str) -> MagicMock:
    resp = MagicMock(status_code=status_code, text=text)
    return resp


def test_check_robots_txt_aggregates_disallow_paths_into_one_finding():
    body = "User-agent: *\nDisallow: /admin\nDisallow: /internal-api/\nAllow: /public\n"
    with patch("bbhunter.recon.well_known.httpx.get", return_value=_fake_response(200, body)):
        hits = check_robots_txt("example.com", _HEADERS)
    assert len(hits) == 1
    assert hits[0]["kind"] == "robots-txt-disallowed-paths"
    assert hits[0]["severity"] == "info"
    assert "/admin" in hits[0]["evidence"]
    assert "/internal-api/" in hits[0]["evidence"]


def test_check_robots_txt_returns_empty_when_no_disallow_entries():
    body = "User-agent: *\nAllow: /\n"
    with patch("bbhunter.recon.well_known.httpx.get", return_value=_fake_response(200, body)):
        assert check_robots_txt("example.com", _HEADERS) == []


def test_check_robots_txt_returns_empty_when_not_served():
    with patch("bbhunter.recon.well_known.httpx.get", return_value=_fake_response(404, "")):
        assert check_robots_txt("example.com", _HEADERS) == []


def test_check_robots_txt_returns_empty_on_request_error():
    with patch("bbhunter.recon.well_known.httpx.get", side_effect=httpx.ConnectTimeout("timeout")):
        assert check_robots_txt("example.com", _HEADERS) == []


def test_check_security_txt_prefers_well_known_path():
    body = "Contact: mailto:security@example.com\nExpires: 2027-01-01T00:00:00Z\n"
    with patch("bbhunter.recon.well_known.httpx.get", return_value=_fake_response(200, body)) as mock_get:
        hits = check_security_txt("example.com", _HEADERS)
    assert len(hits) == 1
    assert hits[0]["kind"] == "security-txt-present"
    assert "security@example.com" in hits[0]["evidence"]
    assert mock_get.call_args_list[0].args[0] == "https://example.com/.well-known/security.txt"


def test_check_security_txt_falls_back_to_legacy_path():
    def fake_get(url, *args, **kwargs):
        if ".well-known" in url:
            return _fake_response(404, "")
        return _fake_response(200, "Contact: mailto:security@example.com\n")

    with patch("bbhunter.recon.well_known.httpx.get", side_effect=fake_get):
        hits = check_security_txt("example.com", _HEADERS)
    assert len(hits) == 1
    assert "security.txt" in hits[0]["evidence"]


def test_check_security_txt_ignores_a_200_with_no_contact_line():
    # e.g. a custom 404/catch-all page that happens to return 200 for any path
    with patch("bbhunter.recon.well_known.httpx.get", return_value=_fake_response(200, "<html>not found</html>")):
        assert check_security_txt("example.com", _HEADERS) == []


def test_check_security_txt_returns_empty_when_neither_path_served():
    with patch("bbhunter.recon.well_known.httpx.get", return_value=_fake_response(404, "")):
        assert check_security_txt("example.com", _HEADERS) == []
