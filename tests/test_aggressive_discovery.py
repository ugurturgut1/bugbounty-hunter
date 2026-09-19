"""Tests for testing/aggressive_discovery.py (ffuf content discovery,
arjun hidden-parameter discovery). subprocess.run is mocked; real temp
files are used for the JSON hand-off since that's the actual contract
with these binaries (no fabricated network access)."""
import json
from unittest.mock import MagicMock, patch

from bbhunter.models import RulesOfEngagement
from bbhunter.testing.aggressive_discovery import (
    resolve_wordlist,
    run_arjun_discovery,
    run_ffuf_discovery,
    wordlist_line_count,
)


def _fake_run_writing_json(json_out_flag: str, payload):
    """Builds a subprocess.run side_effect that writes `payload` as JSON
    to the path following `json_out_flag` in the command list."""

    def _run(cmd, **kwargs):
        out_path = cmd[cmd.index(json_out_flag) + 1]
        with open(out_path, "w") as f:
            json.dump(payload, f)
        return MagicMock(returncode=0)

    return _run


def test_run_ffuf_discovery_returns_none_when_binary_missing():
    with patch("bbhunter.testing.aggressive_discovery._tool_path", return_value=None):
        result = run_ffuf_discovery("example.com", RulesOfEngagement())
    assert result is None


def test_run_ffuf_discovery_parses_results():
    payload = {"results": [{"url": "https://example.com/admin", "status": 200, "length": 1234}]}
    with patch("bbhunter.testing.aggressive_discovery._tool_path", return_value="/fake/ffuf"), \
         patch("bbhunter.testing.aggressive_discovery.subprocess.run", side_effect=_fake_run_writing_json("-o", payload)):
        hits = run_ffuf_discovery("example.com", RulesOfEngagement())
    assert hits is not None
    assert len(hits) == 1
    assert hits[0]["kind"] == "content-discovery-hit"
    assert hits[0]["url"] == "https://example.com/admin"


def test_run_ffuf_discovery_returns_none_on_subprocess_error():
    import subprocess as sp

    with patch("bbhunter.testing.aggressive_discovery._tool_path", return_value="/fake/ffuf"), \
         patch("bbhunter.testing.aggressive_discovery.subprocess.run", side_effect=sp.TimeoutExpired(cmd="ffuf", timeout=1)):
        result = run_ffuf_discovery("example.com", RulesOfEngagement())
    assert result is None


def test_run_ffuf_discovery_uses_conservative_rate_and_match_codes():
    payload = {"results": []}
    with patch("bbhunter.testing.aggressive_discovery._tool_path", return_value="/fake/ffuf"), \
         patch("bbhunter.testing.aggressive_discovery.subprocess.run", side_effect=_fake_run_writing_json("-o", payload)) as run:
        run_ffuf_discovery("example.com", RulesOfEngagement())
    cmd = run.call_args.args[0]
    assert "-rate" in cmd and cmd[cmd.index("-rate") + 1] == "5"
    assert "-mc" in cmd


def test_resolve_wordlist_falls_back_to_builtin_when_nothing_present():
    with patch("bbhunter.testing.aggressive_discovery.SECLISTS_DIR", "/fake/seclists"), \
         patch("bbhunter.testing.aggressive_discovery.os.path.isfile", return_value=False), \
         patch.dict("os.environ", {}, clear=True):
        path, is_temp = resolve_wordlist()
    assert is_temp is True
    with open(path) as f:
        assert ".env" in f.read()  # a builtin-list entry


def test_resolve_wordlist_shorthand_resolves_under_seclists_dir():
    with patch("bbhunter.testing.aggressive_discovery.SECLISTS_DIR", "/fake/seclists"), \
         patch("bbhunter.testing.aggressive_discovery.os.path.isfile", side_effect=lambda p: p == "/fake/seclists/Discovery/Web-Content/raft-medium-directories.txt"):
        path, is_temp = resolve_wordlist("medium")
    assert path == "/fake/seclists/Discovery/Web-Content/raft-medium-directories.txt"
    assert is_temp is False


def test_resolve_wordlist_explicit_absolute_path_wins():
    with patch("bbhunter.testing.aggressive_discovery.SECLISTS_DIR", "/fake/seclists"), \
         patch("bbhunter.testing.aggressive_discovery.os.path.isfile", side_effect=lambda p: p == "/my/custom.txt"):
        path, is_temp = resolve_wordlist("/my/custom.txt")
    assert path == "/my/custom.txt"
    assert is_temp is False


def test_resolve_wordlist_env_var_used_when_no_explicit_arg():
    with patch("bbhunter.testing.aggressive_discovery.SECLISTS_DIR", "/fake/seclists"), \
         patch("bbhunter.testing.aggressive_discovery.os.path.isfile", side_effect=lambda p: p == "/env/list.txt"), \
         patch.dict("os.environ", {"BBHUNTER_FFUF_WORDLIST": "/env/list.txt"}):
        path, is_temp = resolve_wordlist()
    assert path == "/env/list.txt"
    assert is_temp is False


def test_wordlist_line_count_counts_real_file(tmp_path):
    p = tmp_path / "words.txt"
    p.write_text("a\nb\nc\n")
    assert wordlist_line_count(str(p)) == 3


def test_wordlist_line_count_returns_zero_for_missing_file():
    assert wordlist_line_count("/does/not/exist.txt") == 0


def test_run_arjun_discovery_returns_none_when_binary_missing():
    with patch("bbhunter.testing.aggressive_discovery._tool_path", return_value=None):
        result = run_arjun_discovery("https://example.com/search")
    assert result is None


def test_run_arjun_discovery_parses_params():
    payload = {"https://example.com/search": {"params": ["debug", "admin"]}}
    with patch("bbhunter.testing.aggressive_discovery._tool_path", return_value="/fake/arjun"), \
         patch("bbhunter.testing.aggressive_discovery.subprocess.run", side_effect=_fake_run_writing_json("-oJ", payload)):
        params = run_arjun_discovery("https://example.com/search")
    assert params == ["admin", "debug"]


def test_run_arjun_discovery_returns_none_on_malformed_output():
    def _run(cmd, **kwargs):
        out_path = cmd[cmd.index("-oJ") + 1]
        with open(out_path, "w") as f:
            f.write("not valid json")
        return MagicMock(returncode=0)

    with patch("bbhunter.testing.aggressive_discovery._tool_path", return_value="/fake/arjun"), \
         patch("bbhunter.testing.aggressive_discovery.subprocess.run", side_effect=_run):
        result = run_arjun_discovery("https://example.com/search")
    assert result is None
