"""Proof that a human-supplied session (Cookie/Authorization/etc.) is parsed
from the CLI and forwarded verbatim to every authenticated request -- so real
test-account sessions will actually be used when supplied.

Covers: _parse_headers (CLI parsing), and that each authenticated engine
function forwards the headers to the outbound httpx request.
"""
from unittest.mock import MagicMock, patch

from bbhunter.cli import _parse_headers
from bbhunter.testing.auth_logic import check_session_valid, check_token_leak
from bbhunter.testing.idor import check_bfla, check_idor
from bbhunter.recon.authed import discover_authed_endpoints

SESSION = {"Cookie": "session=SEKRIT-ABC123", "Authorization": "Bearer tok-xyz"}


def test_parse_headers_parses_repeatable_key_value():
    parsed = _parse_headers(["Cookie: session=SEKRIT-ABC123", "Authorization: Bearer tok-xyz"])
    assert parsed == SESSION


def _ok(status=200, text="ok"):
    r = MagicMock(status_code=status, text=text, url="https://t.example/x")
    r.content = text.encode()
    r.history = []
    r.headers = {}
    return r


def test_check_idor_forwards_owner_session_headers():
    seen = []
    with patch("bbhunter.testing.idor.httpx.get", side_effect=lambda url, **kw: (seen.append(kw.get("headers")), _ok())[1]):
        check_idor("https://t.example/orders/1", SESSION, {"Cookie": "session=other"})
    assert seen and seen[0] == SESSION          # owner request carried the owner's session verbatim


def test_check_bfla_forwards_authorized_session_headers():
    seen = []
    with patch("bbhunter.testing.idor.httpx.get", side_effect=lambda url, **kw: (seen.append(kw.get("headers")), _ok())[1]):
        check_bfla("https://t.example/admin", SESSION, {"Cookie": "session=low"})
    assert seen and seen[0] == SESSION


def test_token_leak_and_session_replay_forward_headers():
    for fn in (lambda: check_token_leak("https://t.example/x", SESSION, "SEKRIT-ABC123"),
               lambda: check_session_valid("https://t.example/x", SESSION)):
        seen = []
        with patch("bbhunter.testing.auth_logic.httpx.get", side_effect=lambda url, **kw: (seen.append(kw.get("headers")), _ok())[1]):
            fn()
        assert seen and seen[0] == SESSION


def test_authed_recon_applies_session_to_its_client():
    captured = {}
    client = MagicMock()
    client.__enter__.return_value = client
    client.get.return_value = _ok(404, "")   # no schema; we only care the Client got the headers
    client.post.return_value = _ok(404, "")

    def fake_client(*a, **kw):
        captured["headers"] = kw.get("headers")
        return client

    with patch("bbhunter.recon.authed.httpx.Client", side_effect=fake_client), \
         patch("bbhunter.recon.authed.time.sleep"):
        discover_authed_endpoints(["app.example.com"], SESSION)
    assert captured["headers"] == SESSION      # the session is applied to every request the client makes
