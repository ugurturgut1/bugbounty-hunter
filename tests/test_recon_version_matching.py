"""Regression tests for two false-positive classes found during a real
hunt against intigriti:watsons on 2026-09-17:

1. A bare "Undertow/1" banner (no minor/patch) was treated as "versioned"
   and keyword-matched against five unrelated CVEs spanning 2014-2017.
2. A host running the exact version that FIXES CVE-2024-40725 and
   CVE-2024-40898 (Apache 2.4.62) was still surfaced as a candidate for
   both, because NVD keyword search has no notion of version ranges.

The fixtures for cpeMatch shapes below are copied from real NVD API v2.0
responses (CVE-2024-40725 and CVE-2014-7816), not invented."""
from bbhunter.recon.passive import (
    _cve_applies_to_version,
    _parse_version_tuple,
    _version_affected_by_cpe_match,
    _versioned_banner,
)


def test_bare_major_version_banner_is_not_versioned():
    assert _versioned_banner("Undertow/1") is None


def test_bare_product_name_banner_is_not_versioned():
    assert _versioned_banner("Apache") is None


def test_proper_dotted_version_banner_is_versioned():
    assert _versioned_banner("Apache/2.4.62") == "Apache 2.4.62"
    assert _versioned_banner("nginx/1.18.0 (Ubuntu)") == "nginx 1.18.0"


def test_first_versioned_header_wins_when_multiple_given():
    assert _versioned_banner(None, "Undertow/1", "Apache/2.4.62") == "Apache 2.4.62"


def test_parse_version_tuple():
    assert _parse_version_tuple("2.4.62") == (2, 4, 62)
    assert _parse_version_tuple("1.4.17.Final") == (1, 4, 17)
    assert _parse_version_tuple("not-a-version") == ()
    assert _parse_version_tuple("") == ()


# Real cpeMatch entries from NVD's CVE-2024-40725 response: two exact
# vulnerable versions, no range bounds at all.
APACHE_EXACT_VERSION_CPE_MATCHES = [
    {
        "vulnerable": True,
        "criteria": "cpe:2.3:a:apache:http_server:2.4.60:*:*:*:*:*:*:*",
    },
    {
        "vulnerable": True,
        "criteria": "cpe:2.3:a:apache:http_server:2.4.61:*:*:*:*:*:*:*",
    },
]

# Real shape from NVD's CVE-2014-7816 response: versionEndIncluding range,
# plus an unrelated vulnerable=False platform-check node.
UNDERTOW_RANGE_CPE_MATCHES = [
    {
        "vulnerable": True,
        "criteria": "cpe:2.3:a:redhat:undertow:*:*:*:*:*:*:*:*",
        "versionEndIncluding": "1.0.16",
    },
    {
        "vulnerable": False,
        "criteria": "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*",
    },
]


def test_exact_version_cpe_match_excludes_patched_version():
    verdict = _version_affected_by_cpe_match((2, 4, 62), APACHE_EXACT_VERSION_CPE_MATCHES[1])
    assert verdict is False


def test_exact_version_cpe_match_includes_matching_version():
    verdict = _version_affected_by_cpe_match((2, 4, 61), APACHE_EXACT_VERSION_CPE_MATCHES[1])
    assert verdict is True


def test_range_cpe_match_excludes_version_above_range():
    verdict = _version_affected_by_cpe_match((1, 2, 5), UNDERTOW_RANGE_CPE_MATCHES[0])
    assert verdict is False


def test_range_cpe_match_includes_version_in_range():
    verdict = _version_affected_by_cpe_match((1, 0, 10), UNDERTOW_RANGE_CPE_MATCHES[0])
    assert verdict is True


def test_non_vulnerable_entry_and_bare_wildcard_are_indeterminate():
    assert _version_affected_by_cpe_match((5, 0, 0), UNDERTOW_RANGE_CPE_MATCHES[1]) is None
    assert _version_affected_by_cpe_match((5, 0, 0), {"vulnerable": True, "criteria": "cpe:2.3:a:x:y:*"}) is None


def test_apache_2_4_62_is_correctly_excluded_end_to_end():
    # This is the exact real-world case: our fingerprinted version is
    # the one the CVE's own advisory says fixes it.
    configurations = [{"nodes": [{"cpeMatch": APACHE_EXACT_VERSION_CPE_MATCHES}]}]
    assert _cve_applies_to_version(configurations, (2, 4, 62)) is False


def test_vulnerable_apache_version_is_correctly_kept():
    configurations = [{"nodes": [{"cpeMatch": APACHE_EXACT_VERSION_CPE_MATCHES}]}]
    assert _cve_applies_to_version(configurations, (2, 4, 61)) is True


def test_missing_configurations_stays_permissive():
    assert _cve_applies_to_version([], (2, 4, 62)) is True
    assert _cve_applies_to_version(None, (2, 4, 62)) is True


def test_missing_detected_version_stays_permissive():
    configurations = [{"nodes": [{"cpeMatch": APACHE_EXACT_VERSION_CPE_MATCHES}]}]
    assert _cve_applies_to_version(configurations, ()) is True


def test_range_data_correctly_excludes_patched_version_end_to_end():
    configurations = [{"nodes": [{"cpeMatch": UNDERTOW_RANGE_CPE_MATCHES}]}]
    assert _cve_applies_to_version(configurations, (1, 2, 5)) is False
    assert _cve_applies_to_version(configurations, (1, 0, 5)) is True
