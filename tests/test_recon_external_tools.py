"""Tests for the new external-tool-backed recon sources added to
recon/passive.py (subfinder, archive.org Wayback CDX, projectdiscovery
httpx tech-detect). All subprocess/HTTP calls are mocked -- no real
binaries or network access required to run these."""
from unittest.mock import MagicMock, patch

import httpx

from bbhunter.recon.passive import (
    _tech_banner_candidates,
    _tool_path,
    assetfinder_subdomains,
    certspotter_subdomains,
    crtsh_subdomains,
    dnsx_resolve,
    fingerprint,
    httpx_tech_detect,
    subfinder_subdomains,
    wayback_param_urls,
    wayback_subdomains,
)


def test_tool_path_returns_none_when_binary_missing():
    with patch("bbhunter.recon.passive.shutil.which", return_value=None), \
         patch("bbhunter.recon.passive.os.path.isfile", return_value=False):
        assert _tool_path("subfinder") is None


def test_tool_path_falls_back_to_go_bin():
    with patch("bbhunter.recon.passive.shutil.which", return_value=None), \
         patch("bbhunter.recon.passive.os.path.isfile", return_value=True):
        path = _tool_path("subfinder")
    assert path is not None and path.endswith("go/bin/subfinder")


def test_subfinder_subdomains_returns_not_ok_when_binary_missing():
    with patch("bbhunter.recon.passive._tool_path", return_value=None):
        names, ok = subfinder_subdomains("example.com")
    assert names == set()
    assert ok is False


def test_subfinder_subdomains_parses_stdout_and_filters_to_domain():
    fake_proc = MagicMock(returncode=0, stdout="api.example.com\nsub.other.com\n\n", stderr="")
    with patch("bbhunter.recon.passive._tool_path", return_value="/fake/subfinder"), \
         patch("bbhunter.recon.passive.subprocess.run", return_value=fake_proc):
        names, ok = subfinder_subdomains("example.com")
    assert ok is True
    assert names == {"api.example.com"}  # sub.other.com dropped -- doesn't end with the queried domain


def test_subfinder_subdomains_nonzero_exit_with_no_output_is_a_failure():
    fake_proc = MagicMock(returncode=1, stdout="", stderr="all sources failed")
    with patch("bbhunter.recon.passive._tool_path", return_value="/fake/subfinder"), \
         patch("bbhunter.recon.passive.subprocess.run", return_value=fake_proc):
        names, ok = subfinder_subdomains("example.com")
    assert names == set()
    assert ok is False


def test_subfinder_subdomains_nonzero_exit_with_partial_output_still_succeeds():
    # subfinder can exit non-zero when one source times out but others
    # already returned good results -- that's still useful data.
    fake_proc = MagicMock(returncode=1, stdout="api.example.com\n", stderr="one source timed out")
    with patch("bbhunter.recon.passive._tool_path", return_value="/fake/subfinder"), \
         patch("bbhunter.recon.passive.subprocess.run", return_value=fake_proc):
        names, ok = subfinder_subdomains("example.com")
    assert names == {"api.example.com"}
    assert ok is True


def test_subfinder_subdomains_subprocess_error_is_not_ok():
    import subprocess as sp

    with patch("bbhunter.recon.passive._tool_path", return_value="/fake/subfinder"), \
         patch("bbhunter.recon.passive.subprocess.run", side_effect=sp.TimeoutExpired(cmd="subfinder", timeout=1)):
        names, ok = subfinder_subdomains("example.com")
    assert names == set()
    assert ok is False


_CDX_HEADER = ["original"]


def test_certspotter_subdomains_extracts_and_filters_dns_names():
    entries = [
        {"dns_names": ["example.com", "*.api.example.com", "www.other.com"]},
        {"dns_names": ["sub.example.com"]},
    ]
    fake_resp = MagicMock()
    fake_resp.raise_for_status.return_value = None
    fake_resp.json.return_value = entries
    with patch("bbhunter.recon.passive.httpx.get", return_value=fake_resp):
        names, ok = certspotter_subdomains("example.com")
    assert ok is True
    assert names == {"example.com", "api.example.com", "sub.example.com"}  # www.other.com dropped, wildcard stripped


def test_certspotter_subdomains_rate_limited_is_not_ok():
    import httpx as real_httpx

    fake_resp = MagicMock()
    fake_resp.raise_for_status.side_effect = real_httpx.HTTPStatusError(
        "429", request=MagicMock(), response=MagicMock(status_code=429)
    )
    with patch("bbhunter.recon.passive.httpx.get", return_value=fake_resp):
        names, ok = certspotter_subdomains("example.com")
    assert names == set()
    assert ok is False  # rate-limited is "we don't know", never treated as "found nothing"


def test_assetfinder_subdomains_returns_not_ok_when_binary_missing():
    with patch("bbhunter.recon.passive._tool_path", return_value=None):
        names, ok = assetfinder_subdomains("example.com")
    assert names == set()
    assert ok is False


def test_assetfinder_subdomains_parses_stdout_and_filters_to_domain():
    fake_proc = MagicMock(returncode=0, stdout="api.example.com\nsub.other.com\n\n", stderr="")
    with patch("bbhunter.recon.passive._tool_path", return_value="/fake/assetfinder"), \
         patch("bbhunter.recon.passive.subprocess.run", return_value=fake_proc) as run:
        names, ok = assetfinder_subdomains("example.com")
    assert ok is True
    assert names == {"api.example.com"}  # sub.other.com dropped -- doesn't end with the queried domain
    assert "--subs-only" in run.call_args.args[0]  # never pull in unrelated root domains


def test_assetfinder_subdomains_nonzero_exit_with_no_output_is_a_failure():
    fake_proc = MagicMock(returncode=1, stdout="", stderr="error")
    with patch("bbhunter.recon.passive._tool_path", return_value="/fake/assetfinder"), \
         patch("bbhunter.recon.passive.subprocess.run", return_value=fake_proc):
        names, ok = assetfinder_subdomains("example.com")
    assert names == set()
    assert ok is False


def test_dnsx_resolve_returns_empty_set_for_empty_input():
    assert dnsx_resolve(set()) == set()


def test_dnsx_resolve_returns_none_when_binary_missing():
    with patch("bbhunter.recon.passive._tool_path", return_value=None):
        result = dnsx_resolve({"a.example.com", "b.example.com"})
    assert result is None


def test_dnsx_resolve_filters_to_resolved_hosts_only():
    fake_proc = MagicMock(returncode=0, stdout="a.example.com\n", stderr="")
    with patch("bbhunter.recon.passive._tool_path", return_value="/fake/dnsx"), \
         patch("bbhunter.recon.passive.subprocess.run", return_value=fake_proc):
        result = dnsx_resolve({"a.example.com", "b.example.com"})
    assert result == {"a.example.com"}


def test_dnsx_resolve_returns_none_on_subprocess_error():
    import subprocess as sp

    with patch("bbhunter.recon.passive._tool_path", return_value="/fake/dnsx"), \
         patch("bbhunter.recon.passive.subprocess.run", side_effect=sp.TimeoutExpired(cmd="dnsx", timeout=1)):
        result = dnsx_resolve({"a.example.com"})
    assert result is None


def test_wayback_subdomains_extracts_hosts_under_domain():
    rows = [_CDX_HEADER, ["https://api.example.com/foo"], ["https://example.com/bar?x=1"]]
    fake_resp = MagicMock()
    fake_resp.raise_for_status.return_value = None
    fake_resp.json.return_value = rows
    with patch("bbhunter.recon.passive.httpx.get", return_value=fake_resp):
        names, ok = wayback_subdomains("example.com")
    assert ok is True
    assert names == {"api.example.com", "example.com"}


def test_wayback_subdomains_http_error_is_not_ok():
    import httpx as real_httpx

    with patch("bbhunter.recon.passive.httpx.get", side_effect=real_httpx.ConnectTimeout("timeout")):
        names, ok = wayback_subdomains("example.com")
    assert names == set()
    assert ok is False


def test_wayback_param_urls_dedupes_and_returns_list():
    rows = [_CDX_HEADER, ["https://example.com/search?q=1"], ["https://example.com/search?q=1"]]
    fake_resp = MagicMock()
    fake_resp.raise_for_status.return_value = None
    fake_resp.json.return_value = rows
    with patch("bbhunter.recon.passive.httpx.get", return_value=fake_resp):
        urls = wayback_param_urls("example.com")
    assert urls == ["https://example.com/search?q=1"]


def test_wayback_param_urls_returns_empty_list_on_failure_not_none():
    with patch("bbhunter.recon.passive.httpx.get", side_effect=ValueError("bad json")):
        urls = wayback_param_urls("example.com")
    assert urls == []


def test_tech_banner_candidates_only_keeps_versioned_entries():
    assert _tech_banner_candidates(["Apache:2.4.41", "Cloudflare", "nginx:1.18.0"]) == [
        "Apache/2.4.41",
        "nginx/1.18.0",
    ]


def test_httpx_tech_detect_returns_none_when_binary_missing():
    with patch("bbhunter.recon.passive._tool_path", return_value=None):
        result = httpx_tech_detect("example.com", MagicMock(required_user_agent=None, required_request_header=None))
    assert result is None


def test_httpx_tech_detect_maps_webserver_field_to_server_key():
    fake_proc = MagicMock(
        returncode=0,
        stdout='{"status_code":200,"webserver":"nginx","title":"Home","tech":["nginx:1.18.0"],"url":"https://example.com/"}\n',
    )
    rules = MagicMock(required_user_agent=None, required_request_header=None)
    with patch("bbhunter.recon.passive._tool_path", return_value="/fake/httpx"), \
         patch("bbhunter.recon.passive.subprocess.run", return_value=fake_proc):
        result = httpx_tech_detect("example.com", rules)
    assert result == {
        "status_code": 200,
        "server": "nginx",
        "powered_by": None,
        "title": "Home",
        "tech": ["nginx:1.18.0"],
        "final_url": "https://example.com/",
    }


def test_httpx_tech_detect_returns_none_on_empty_output():
    fake_proc = MagicMock(returncode=0, stdout="")
    with patch("bbhunter.recon.passive._tool_path", return_value="/fake/httpx"), \
         patch("bbhunter.recon.passive.subprocess.run", return_value=fake_proc):
        result = httpx_tech_detect("example.com", MagicMock(required_user_agent=None, required_request_header=None))
    assert result is None


def test_fingerprint_prefers_httpx_enrichment_over_plain_get():
    rules = MagicMock(required_user_agent=None, required_request_header=None)
    with patch("bbhunter.recon.passive.httpx_tech_detect", return_value={"server": "nginx"}) as enriched, \
         patch("bbhunter.recon.passive.fingerprint_host") as plain:
        result = fingerprint("example.com", rules)
    assert result == {"server": "nginx"}
    enriched.assert_called_once()
    plain.assert_not_called()


def test_fingerprint_falls_back_to_plain_get_when_httpx_binary_absent():
    rules = MagicMock(required_user_agent=None, required_request_header=None)
    with patch("bbhunter.recon.passive.httpx_tech_detect", return_value=None), \
         patch("bbhunter.recon.passive.fingerprint_host", return_value={"server": "Apache"}) as plain:
        result = fingerprint("example.com", rules)
    assert result == {"server": "Apache"}
    plain.assert_called_once()


def test_subfinder_subprocess_timeout_outlasts_a_slow_multi_source_run():
    """Regression for a real bug (found live 2026-10-03): the subprocess cap was
    SUBFINDER_TIMEOUT_SECONDS + 10 = 25s, but subfinder's ~30 sources take 10-45s+
    wall-clock, so every slow run was killed and counted as a failure, silently
    dropping real subdomains. The overall cap must be the separate, larger budget."""
    from bbhunter.recon.passive import (
        SUBFINDER_SUBPROCESS_TIMEOUT_SECONDS,
        SUBFINDER_TIMEOUT_SECONDS,
    )

    captured = {}

    def fake_run(cmd, **kwargs):
        captured["timeout"] = kwargs.get("timeout")
        return MagicMock(returncode=0, stdout="api.example.com\n", stderr="")

    with patch("bbhunter.recon.passive._tool_path", return_value="/fake/subfinder"), \
         patch("bbhunter.recon.passive.subprocess.run", side_effect=fake_run):
        subfinder_subdomains("example.com")

    # the measured worst case was ~45s; the old 25s cap would reintroduce the bug
    assert captured["timeout"] == SUBFINDER_SUBPROCESS_TIMEOUT_SECONDS
    assert captured["timeout"] >= 60
    assert captured["timeout"] > SUBFINDER_TIMEOUT_SECONDS + 10


def test_crtsh_retries_once_on_a_transient_error_then_succeeds():
    """crt.sh is flaky under load; one transient 5xx shouldn't drop the primary CT
    source. First call raises, second returns good JSON -> overall success."""
    good = MagicMock()
    good.raise_for_status.return_value = None
    good.json.return_value = [{"name_value": "api.example.com"}]

    with patch("bbhunter.recon.passive.httpx.get",
               side_effect=[httpx.ConnectError("boom"), good]) as get, \
         patch("bbhunter.recon.passive.time.sleep"):
        names, ok = crtsh_subdomains("example.com")

    assert ok is True
    assert names == {"api.example.com"}
    assert get.call_count == 2


def test_crtsh_gives_up_after_two_failed_attempts():
    with patch("bbhunter.recon.passive.httpx.get",
               side_effect=[httpx.ConnectError("boom"), httpx.ConnectError("boom")]) as get, \
         patch("bbhunter.recon.passive.time.sleep"):
        names, ok = crtsh_subdomains("example.com")

    assert ok is False
    assert names == set()
    assert get.call_count == 2


def test_subfinder_budget_scales_with_scope():
    from bbhunter.recon.passive import (
        SUBFINDER_SUBPROCESS_TIMEOUT_SECONDS,
        SUBFINDER_MIN_PER_SEED_SECONDS,
        subfinder_budget_for,
    )
    assert subfinder_budget_for(1) == SUBFINDER_SUBPROCESS_TIMEOUT_SECONDS   # small scope keeps full budget
    assert subfinder_budget_for(3) == SUBFINDER_SUBPROCESS_TIMEOUT_SECONDS   # 600/3=200 -> capped at 90
    assert subfinder_budget_for(10) == 60.0                                 # 600/10
    assert subfinder_budget_for(54) == SUBFINDER_MIN_PER_SEED_SECONDS        # 600/54<20 -> floored
