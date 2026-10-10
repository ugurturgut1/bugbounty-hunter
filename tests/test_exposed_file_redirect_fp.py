"""Exposed-file check must not flag a path that 3xx-redirected to a
different path (e.g. /phpmyadmin -> /auth/login): the 200 is that other
page (a login), not the requested file. Found live on companyhub."""
from unittest.mock import MagicMock, patch

from bbhunter.testing.active import _check_host, _redirected_to_other_path


def _resp(url, history=True):
    r = MagicMock()
    r.url = url
    r.history = [MagicMock()] if history else []
    r.status_code = 200
    return r


def test_redirect_to_other_path_detected():
    # /phpmyadmin/ ended up on /auth/credentials/login -> flagged
    assert _redirected_to_other_path(_resp("https://h.example.com/auth/credentials/login?ReturnUrl=x"), "/phpmyadmin/") is True


def test_same_path_redirect_not_flagged():
    # trailing-slash / scheme normalization to the same path -> not flagged
    assert _redirected_to_other_path(_resp("https://h.example.com/phpmyadmin/"), "/phpmyadmin") is False


def test_no_redirect_not_flagged():
    assert _redirected_to_other_path(_resp("https://h.example.com/phpmyadmin/", history=False), "/phpmyadmin/") is False


def test_check_host_skips_login_redirected_phpmyadmin():
    """Full path: a /phpmyadmin/ probe that redirects to a login page whose
    body even contains 'phpmyadmin' (in the ReturnUrl) must NOT be a hit."""
    login_url = "https://h.example.com/auth/credentials/login?ReturnUrl=%2fphpmyadmin%2f"

    def fake_get(url, timeout=15, follow_redirects=True, **kwargs):
        r = MagicMock()
        r.status_code = 200
        if "phpmyadmin" in url:
            r.url = login_url            # redirected away to the login page
            r.history = [MagicMock()]
            r.text = "<title>CompanyHub</title> Login phpmyadmin"  # body even mentions phpmyadmin
            r.content = r.text.encode()
            r.headers = {}
        else:
            r.url = url
            r.history = []
            r.text = "nothing"
            r.content = b"nothing"
            r.headers = {}
        return r

    client = MagicMock()
    client.get.side_effect = fake_get
    with patch("bbhunter.testing.active.time.sleep"):
        hits = _check_host(client, "h.example.com", fingerprint=None)
    assert not any("phpMyAdmin" in h["title"] for h in hits)
