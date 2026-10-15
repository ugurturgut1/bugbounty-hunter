"""--host targeting must only ever reach in-scope hosts: exact URL seeds or
names under a wildcard seed; everything else (third-party-hosted sibling,
unlisted domain) is rejected."""
from bbhunter.models import AssetType, Platform, Program, RulesOfEngagement, ScopeAsset, TestType
from bbhunter.testing.active import host_in_scope


def _prog():
    return Program(
        key="hackerone:whatnot", platform=Platform.HACKERONE, handle="whatnot", name="Whatnot",
        url="https://hackerone.com/whatnot",
        in_scope=[
            ScopeAsset(identifier="*.whatnot.com", asset_type=AssetType.WILDCARD, in_scope=True),
            ScopeAsset(identifier="https://api.whatnot.com", asset_type=AssetType.URL, in_scope=True),
        ],
        rules=RulesOfEngagement(allowed_test_types={TestType.ACTIVE_LOW_IMPACT}),
    )


def test_wildcard_subdomain_in_scope():
    assert host_in_scope(_prog(), "admin.whatnot.com") is True
    assert host_in_scope(_prog(), "doomsday.whatnot.com") is True
    assert host_in_scope(_prog(), "whatnot.com") is True          # the apex itself


def test_exact_url_seed_in_scope():
    assert host_in_scope(_prog(), "api.whatnot.com") is True


def test_out_of_scope_rejected():
    assert host_in_scope(_prog(), "whatnot.com.evil.com") is False  # suffix trick
    assert host_in_scope(_prog(), "notwhatnot.com") is False
    assert host_in_scope(_prog(), "whatnot.net") is False
