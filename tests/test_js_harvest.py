"""Tests for recon/js_harvest.py: script-URL extraction, secret
scanning, source-map exposure detection, and internal-path extraction.
Every HTTP call is mocked -- these never make a real network request."""
from unittest.mock import MagicMock, patch

import httpx

from bbhunter.recon.js_harvest import (
    check_source_map_exposed,
    extract_script_urls,
    fetch_text_capped,
    find_source_map_url,
    scan_js_internal_paths,
    scan_js_secrets,
)


def test_extract_script_urls_resolves_relative_and_absolute():
    html = """
    <html><head>
    <script src="/static/app.js"></script>
    <script src="https://cdn.example.net/lib.js"></script>
    <script>console.log("inline, no src")</script>
    </head></html>
    """
    urls = extract_script_urls("https://example.com/page", html)
    assert "https://example.com/static/app.js" in urls
    assert "https://cdn.example.net/lib.js" in urls
    assert len(urls) == 2


def test_extract_script_urls_dedupes_and_caps():
    html = "".join(f'<script src="/app.js"></script>' for _ in range(20))
    html += "".join(f'<script src="/unique{i}.js"></script>' for i in range(20))
    urls = extract_script_urls("https://example.com/", html)
    assert urls.count("https://example.com/app.js") == 1
    assert len(urls) <= 8  # MAX_JS_FILES_PER_PAGE


def test_fetch_text_capped_returns_none_on_http_error():
    with patch("bbhunter.recon.js_harvest.httpx.stream", side_effect=httpx.ConnectError("nope")):
        assert fetch_text_capped("https://example.com/app.js") is None


def test_fetch_text_capped_returns_none_on_non_200():
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_cm = MagicMock()
    mock_cm.__enter__.return_value = mock_resp
    with patch("bbhunter.recon.js_harvest.httpx.stream", return_value=mock_cm):
        assert fetch_text_capped("https://example.com/app.js") is None


def test_fetch_text_capped_stops_at_max_bytes():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.iter_bytes.return_value = [b"a" * 100 for _ in range(50)]
    mock_cm = MagicMock()
    mock_cm.__enter__.return_value = mock_resp
    with patch("bbhunter.recon.js_harvest.httpx.stream", return_value=mock_cm):
        text = fetch_text_capped("https://example.com/app.js", max_bytes=250)
    assert len(text) >= 250
    assert len(text) < 5000  # stopped early, not the full 5000 bytes available


def test_scan_js_secrets_flags_real_secret_pattern():
    js_text = "const key = 'sk-abcdefghijklmnopqrstuvwx';"
    hits = scan_js_secrets("https://example.com/app.js", js_text)
    assert len(hits) == 1
    assert hits[0]["kind"] == "js-embedded-secret"
    assert hits[0]["severity"] == "critical"
    # the actual secret value must never be persisted into the finding evidence
    assert "sk-abcdefghijklmnopqrstuvwx" not in hits[0]["evidence"]


def test_scan_js_secrets_no_hit_on_clean_js():
    js_text = "function add(a, b) { return a + b; }"
    assert scan_js_secrets("https://example.com/app.js", js_text) == []


def test_find_source_map_url_resolves_relative_comment():
    js_text = "console.log(1);\n//# sourceMappingURL=app.js.map"
    assert find_source_map_url("https://example.com/static/app.js", js_text) == "https://example.com/static/app.js.map"


def test_find_source_map_url_none_when_absent():
    assert find_source_map_url("https://example.com/app.js", "console.log(1);") is None


def test_check_source_map_exposed_flags_real_source_map():
    mock_resp = MagicMock(status_code=200, text='{"version":3,"sources":["app.ts"],"mappings":"AAAA"}')
    with patch("bbhunter.recon.js_harvest.httpx.get", return_value=mock_resp):
        hit = check_source_map_exposed("https://example.com/app.js.map")
    assert hit is not None
    assert hit["kind"] == "exposed-source-map"


def test_check_source_map_exposed_no_hit_on_404():
    mock_resp = MagicMock(status_code=404, text="not found")
    with patch("bbhunter.recon.js_harvest.httpx.get", return_value=mock_resp):
        assert check_source_map_exposed("https://example.com/app.js.map") is None


def test_check_source_map_exposed_no_hit_when_not_real_map_json():
    mock_resp = MagicMock(status_code=200, text="<html>not a source map</html>")
    with patch("bbhunter.recon.js_harvest.httpx.get", return_value=mock_resp):
        assert check_source_map_exposed("https://example.com/app.js.map") is None


def test_scan_js_internal_paths_extracts_api_paths():
    js_text = 'fetch("/api/v2/users/me"); fetch("/api/internal/admin/stats");'
    paths = scan_js_internal_paths(js_text)
    assert "/api/v2/users/me" in paths
    assert "/api/internal/admin/stats" in paths


def test_scan_js_internal_paths_empty_when_none_found():
    assert scan_js_internal_paths("console.log('hello world');") == []
