"""Phase 7: SSTI + open-redirect probes and offline JWT analysis."""
import re
from unittest.mock import MagicMock, patch
from urllib.parse import unquote

import pytest

from bbhunter.testing.active import _check_injection_signals
from bbhunter.testing.jwt_check import analyze_jwt, decode_jwt


class _Resp:
    def __init__(self, text="", url="https://example.com/x", headers=None, is_redirect=False):
        self.text = text
        self.url = url
        self.headers = headers or {}
        self.is_redirect = is_redirect


def test_ssti_candidate_detected_when_template_evaluates():
    def fake_get(url, timeout=15, follow_redirects=True, **kwargs):
        m = re.search(r"\{\{(\d+)\*(\d+)\}\}", unquote(url))  # server decodes the param
        if m:
            return _Resp(text=str(int(m.group(1)) * int(m.group(2))), url=url)  # engine evaluated it
        return _Resp(text="baseline", url=url)

    client = MagicMock()
    client.get.side_effect = fake_get
    with patch("bbhunter.testing.active.time.sleep"):
        hits = _check_injection_signals(client, "https://example.com/p?name=x")
    assert any(h["kind"] == "ssti-candidate" for h in hits)


def test_open_redirect_candidate_detected_for_redirect_param():
    def fake_get(url, timeout=15, follow_redirects=True, **kwargs):
        if "bbhunter-redirect-probe.example" in url and follow_redirects is False:
            return _Resp(is_redirect=True, headers={"location": "https://bbhunter-redirect-probe.example/"}, url=url)
        return _Resp(text="nothing", url=url)

    client = MagicMock()
    client.get.side_effect = fake_get
    with patch("bbhunter.testing.active.time.sleep"):
        hits = _check_injection_signals(client, "https://example.com/login?next=/home")
    assert any(h["kind"] == "open-redirect-candidate" for h in hits)


def test_no_open_redirect_probe_for_non_redirect_param():
    def fake_get(url, timeout=15, follow_redirects=True, **kwargs):
        # even if the server WOULD redirect, a non-redirect param never gets probed
        return _Resp(is_redirect=True, headers={"location": "https://bbhunter-redirect-probe.example/"}, url=url)

    client = MagicMock()
    client.get.side_effect = fake_get
    with patch("bbhunter.testing.active.time.sleep"):
        hits = _check_injection_signals(client, "https://example.com/search?q=x")
    assert not any(h["kind"] == "open-redirect-candidate" for h in hits)


# ---- JWT ----
# header {"alg":"none"} . payload {"sub":"admin"} .   (no signature)
_JWT_NONE = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9."
# header {"alg":"HS256"} . payload {"sub":"x","exp":9999999999,"iat":0} .sig
_JWT_HS_LONG = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4IiwiZXhwIjo5OTk5OTk5OTk5LCJpYXQiOjB9.sig"


def test_jwt_alg_none_and_no_exp_flagged():
    kinds = {i["kind"] for i in analyze_jwt(_JWT_NONE)}
    assert "jwt-alg-none" in kinds and "jwt-no-exp" in kinds


def test_jwt_symmetric_and_long_lifetime_flagged():
    kinds = {i["kind"] for i in analyze_jwt(_JWT_HS_LONG, now=0)}
    assert "jwt-symmetric-alg" in kinds and "jwt-long-lifetime" in kinds


def test_decode_jwt_rejects_garbage():
    with pytest.raises(ValueError):
        decode_jwt("not-a-jwt")
