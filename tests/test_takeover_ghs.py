"""Google-ghs dangling-CNAME detection in test-takeover (low/info, not a
claimable takeover) -- plus a guard that it doesn't disturb the existing
high-severity claimable-service fingerprints."""
from unittest.mock import MagicMock, patch

from bbhunter.testing.takeover import check_takeover


def test_ghs_dangling_cname_flagged_low():
    resp404 = MagicMock(status_code=404, text="404 Page not found")
    with patch("bbhunter.testing.takeover._cname_target", return_value="ghs.google.com"), \
         patch("bbhunter.testing.takeover.httpx.get", return_value=resp404):
        hit = check_takeover("links.cirruspath.com")
    assert hit and hit["service"] == "Google (ghs)"
    assert hit["severity"] == "low"
    assert "not" in hit["evidence"].lower() and "claimable" in hit["evidence"].lower()


def test_ghs_cname_but_200_not_flagged():
    # a configured Google site (200) is not dangling
    resp200 = MagicMock(status_code=200, text="<html>real site</html>")
    with patch("bbhunter.testing.takeover._cname_target", return_value="ghs.google.com"), \
         patch("bbhunter.testing.takeover.httpx.get", return_value=resp200):
        assert check_takeover("configured.example.com") is None


def test_claimable_service_still_high_when_no_ghs_cname():
    gh = MagicMock(status_code=404, text="There isn't a GitHub Pages site here.")
    with patch("bbhunter.testing.takeover._cname_target", return_value=None), \
         patch("bbhunter.testing.takeover.httpx.get", return_value=gh):
        hit = check_takeover("sub.example.com")
    assert hit and hit["service"] == "GitHub Pages" and hit["severity"] == "high"
