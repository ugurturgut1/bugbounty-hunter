"""Tests for recon/github_dork.py: optional GitHub code-search recon.
Every HTTP call is mocked -- these never make a real API call, and
never use a real GitHub token."""
from unittest.mock import MagicMock, patch

import httpx

from bbhunter.config import GitHubCreds
from bbhunter.recon.github_dork import scan_github_results_for_secrets, search_domain_mentions


def test_search_domain_mentions_returns_empty_when_not_configured():
    creds = GitHubCreds(token=None)
    with patch("bbhunter.recon.github_dork.httpx.get") as mock_get:
        items = search_domain_mentions("example.com", creds)
    assert items == []
    mock_get.assert_not_called()


def test_search_domain_mentions_returns_items_on_success():
    creds = GitHubCreds(token="fake-token-for-testing")
    mock_resp = MagicMock()
    mock_resp.json.return_value = {"items": [{"html_url": "https://github.com/x/y/blob/main/config.js"}]}
    mock_resp.raise_for_status.return_value = None
    with patch("bbhunter.recon.github_dork.httpx.get", return_value=mock_resp) as mock_get:
        items = search_domain_mentions("example.com", creds)
    assert len(items) == 1
    call_kwargs = mock_get.call_args.kwargs
    assert call_kwargs["headers"]["Authorization"] == "Bearer fake-token-for-testing"
    assert call_kwargs["params"]["q"] == '"example.com"'


def test_search_domain_mentions_returns_empty_on_http_error():
    creds = GitHubCreds(token="fake-token-for-testing")
    with patch("bbhunter.recon.github_dork.httpx.get", side_effect=httpx.ConnectError("nope")):
        assert search_domain_mentions("example.com", creds) == []


def test_search_domain_mentions_returns_empty_on_rate_limit_error():
    creds = GitHubCreds(token="fake-token-for-testing")
    mock_resp = MagicMock()
    mock_resp.raise_for_status.side_effect = httpx.HTTPStatusError("403", request=MagicMock(), response=MagicMock())
    with patch("bbhunter.recon.github_dork.httpx.get", return_value=mock_resp):
        assert search_domain_mentions("example.com", creds) == []


def test_scan_github_results_flags_real_secret_in_fragment():
    items = [{
        "repository": {"full_name": "someorg/somerepo"},
        "html_url": "https://github.com/someorg/somerepo/blob/main/config.js",
        "text_matches": [{"fragment": "const KEY = 'sk-abcdefghijklmnopqrstuvwx'; // example.com prod key"}],
    }]
    hits = scan_github_results_for_secrets("example.com", items)
    assert len(hits) == 1
    assert hits[0]["kind"] == "github-leaked-secret-candidate"
    # the actual matched value is never persisted into the evidence
    assert "sk-abcdefghijklmnopqrstuvwx" not in hits[0]["evidence"]
    assert "someorg/somerepo" in hits[0]["evidence"]


def test_scan_github_results_no_hit_without_secret_pattern():
    items = [{
        "repository": {"full_name": "someorg/somerepo"},
        "html_url": "https://github.com/someorg/somerepo/blob/main/README.md",
        "text_matches": [{"fragment": "Check out our site at example.com for more info."}],
    }]
    assert scan_github_results_for_secrets("example.com", items) == []


def test_scan_github_results_no_hit_when_no_text_matches():
    items = [{"repository": {"full_name": "someorg/somerepo"}, "html_url": "https://github.com/x/y"}]
    assert scan_github_results_for_secrets("example.com", items) == []
