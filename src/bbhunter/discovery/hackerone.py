"""HackerOne connector, built against the official Hacker API
(https://api.hackerone.com/reference/) rather than scraping hackerone.com,
which is a client-rendered SPA with no stable public JSON endpoint.

Requires a free HackerOne account + API token (Settings -> API Token) set
as H1_API_USERNAME / H1_API_TOKEN. Without credentials this connector is
simply skipped (is_configured() returns False) rather than falling back
to scraping.
"""
from __future__ import annotations

import httpx

from bbhunter.config import HackerOneCreds
from bbhunter.discovery.base import PlatformConnector
from bbhunter.models import AssetType, Platform, Program, ScopeAsset
from bbhunter.rules_engine import derive_rules

BASE_URL = "https://api.hackerone.com/v1"

_ASSET_TYPE_MAP = {
    "URL": AssetType.URL,
    "WILDCARD": AssetType.WILDCARD,
    "CIDR": AssetType.IP_RANGE,
    "IP_ADDRESS": AssetType.IP_RANGE,
    "GOOGLE_PLAY_APP_ID": AssetType.MOBILE_APP,
    "APPLE_STORE_APP_ID": AssetType.MOBILE_APP,
    "OTHER_APK": AssetType.MOBILE_APP,
    "SOURCE_CODE": AssetType.SOURCE_CODE,
    "HARDWARE": AssetType.HARDWARE,
}


class HackerOneConnector(PlatformConnector):
    platform_name = "hackerone"

    def __init__(self, creds: HackerOneCreds | None = None):
        self.creds = creds or HackerOneCreds()

    def is_configured(self) -> bool:
        return self.creds.configured

    def _client(self) -> httpx.Client:
        return httpx.Client(
            base_url=BASE_URL,
            auth=(self.creds.username, self.creds.token),
            timeout=30,
            headers={"Accept": "application/json"},
        )

    def fetch_programs(self, *, limit: int | None = None) -> list[Program]:
        if not self.is_configured():
            raise RuntimeError("HackerOneConnector not configured: set H1_API_USERNAME and H1_API_TOKEN")

        programs: list[Program] = []
        with self._client() as client:
            page_num = 1
            while True:
                resp = client.get("/hackers/programs", params={"page[size]": 100, "page[number]": page_num})
                resp.raise_for_status()
                body = resp.json()
                data = body.get("data", [])
                if not data:
                    break
                for item in data:
                    program = self._to_program(client, item)
                    if program is not None:
                        programs.append(program)
                    if limit and len(programs) >= limit:
                        return programs
                if not body.get("links", {}).get("next"):
                    break
                page_num += 1
        return programs

    def _to_program(self, client: httpx.Client, item: dict) -> Program | None:
        attrs = item.get("attributes", {})
        handle = attrs.get("handle")
        if not handle:
            return None

        # Skip programs that don't accept public submissions at all.
        submission_state = attrs.get("submission_state")
        if submission_state == "paused":
            pass  # still worth cataloguing scope/rules even if paused; testing gate handles this later

        policy_text = attrs.get("policy") or ""

        in_scope: list[ScopeAsset] = []
        out_of_scope: list[ScopeAsset] = []
        try:
            scope_resp = client.get(f"/hackers/programs/{handle}/structured_scopes", params={"page[size]": 100})
            if scope_resp.status_code == 200:
                for scope_item in scope_resp.json().get("data", []):
                    sattrs = scope_item.get("attributes", {})
                    asset = ScopeAsset(
                        identifier=sattrs.get("asset_identifier", "unknown"),
                        asset_type=_ASSET_TYPE_MAP.get(sattrs.get("asset_type", ""), AssetType.OTHER),
                        in_scope=bool(sattrs.get("eligible_for_submission", True)),
                        eligible_for_bounty=sattrs.get("eligible_for_bounty"),
                        max_severity=sattrs.get("max_severity"),
                        instruction=sattrs.get("instruction"),
                    )
                    (in_scope if asset.in_scope else out_of_scope).append(asset)
        except httpx.HTTPError:
            pass  # scope fetch is best-effort; program still catalogued with policy text only

        return Program(
            platform=Platform.HACKERONE,
            handle=handle,
            name=attrs.get("name", handle),
            url=f"https://hackerone.com/{handle}",
            policy_url=f"https://hackerone.com/{handle}/policy_scopes",
            offers_bounties=bool(attrs.get("offers_bounties", False)),
            in_scope=in_scope,
            out_of_scope=out_of_scope,
            rules=derive_rules(policy_text),
            raw_policy_text=policy_text,
        )
