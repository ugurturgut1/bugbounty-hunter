"""Source maps on third-party CDNs are OSS libraries' own maps, not the
target leaking source -- only flag maps served from the target's own site."""
from unittest.mock import MagicMock, patch

from bbhunter.recon.js_harvest import check_source_map_exposed

_VALID_MAP_BODY = '{"version":3,"sources":["a.ts"],"mappings":"AAAA"}'


def test_offsite_cdn_source_map_not_flagged_and_not_fetched():
    with patch("bbhunter.recon.js_harvest.httpx.get") as get:
        hit = check_source_map_exposed(
            "https://cdn.jsdelivr.net/npm/mermaid@9.1.6/dist/mermaid.min.js.map",
            page_host="digitalspecs.portofantwerpbruges.com",
        )
    assert hit is None
    get.assert_not_called()  # off-site -> skipped before any request


def test_same_site_source_map_is_flagged():
    resp = MagicMock(status_code=200, text=_VALID_MAP_BODY)
    with patch("bbhunter.recon.js_harvest.httpx.get", return_value=resp):
        hit = check_source_map_exposed(
            "https://app.portofantwerpbruges.com/assets/main.js.map",
            page_host="digitalspecs.portofantwerpbruges.com",  # same registrable domain
        )
    assert hit and hit["kind"] == "exposed-source-map"


def test_no_page_host_preserves_old_behavior():
    resp = MagicMock(status_code=200, text=_VALID_MAP_BODY)
    with patch("bbhunter.recon.js_harvest.httpx.get", return_value=resp):
        hit = check_source_map_exposed("https://whatever.example/x.js.map")
    assert hit and hit["kind"] == "exposed-source-map"
