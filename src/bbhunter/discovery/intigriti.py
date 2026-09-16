"""Intigriti connector, built directly against Intigriti's public researcher
API OpenAPI spec, fetched live from
https://api.intigriti.com/external/researcher/swagger/v1/swagger.json
(linked from kb.intigriti.com's "Intigriti researcher API" article).

Auth: a personal access token from Settings -> API in the Intigriti app.
Sent as a Bearer token -- the spec doesn't declare a securityScheme or
document the exact header, so this is the standard-convention assumption
for a "token-based" REST API, not a verified fact. If `bbhunter sync`
gets a 401 with this, the header scheme is the first thing to check.

Unlike HackerOne/Bugcrowd (where we build rules from free-text policy via
rules_engine.derive_rules), Intigriti's API exposes structured
testingRequirements.automatedTooling and safeHarbour fields directly.
`safeHarbour` is an unambiguous boolean and is trusted directly.
`automatedTooling` is an undocumented integer (no enum labels in the
spec, and no public documentation of what each value means was found) --
it is recorded in raw_notes for a human to check on the program's page,
but it is NEVER used on its own to unlock active testing. Only the
free-text `rulesOfEngagement.description`, run through the same
conservative heuristic as other platforms, can raise confidence past
"low".
"""
from __future__ import annotations

import httpx

from bbhunter.config import IntigritiCreds
from bbhunter.discovery.base import PlatformConnector
from bbhunter.models import AssetType, Platform, Program, ScopeAsset
from bbhunter.rules_engine import derive_rules

BASE_URL = "https://api.intigriti.com/external/researcher/v1"

_TYPE_MAP = {
    "url": AssetType.URL,
    "web application": AssetType.URL,
    "wildcard": AssetType.WILDCARD,
    "ip address": AssetType.IP_RANGE,
    "ip range": AssetType.IP_RANGE,
    "android application": AssetType.MOBILE_APP,
    "ios application": AssetType.MOBILE_APP,
    "mobile application": AssetType.MOBILE_APP,
    "source code": AssetType.SOURCE_CODE,
    "hardware": AssetType.HARDWARE,
    "other": AssetType.OTHER,
}


class IntigritiConnector(PlatformConnector):
    platform_name = "intigriti"

    def __init__(self, creds: IntigritiCreds | None = None):
        self.creds = creds or IntigritiCreds()

    def is_configured(self) -> bool:
        return self.creds.configured

    def _client(self) -> httpx.Client:
        return httpx.Client(
            base_url=BASE_URL,
            timeout=30,
            headers={"Accept": "application/json", "Authorization": f"Bearer {self.creds.token}"},
        )

    def fetch_programs(self, *, limit: int | None = None) -> list[Program]:
        if not self.is_configured():
            raise RuntimeError("IntigritiConnector not configured: set INTIGRITI_API_TOKEN")

        programs: list[Program] = []
        with self._client() as client:
            offset = 0
            page_size = 100
            while True:
                resp = client.get("/programs", params={"limit": page_size, "offset": offset})
                resp.raise_for_status()
                body = resp.json()
                records = body.get("records", [])
                if not records:
                    break
                for overview in records:
                    program = self._fetch_detail(client, overview)
                    if program is not None:
                        programs.append(program)
                    if limit and len(programs) >= limit:
                        return programs
                if offset + len(records) >= body.get("maxCount", 0) or len(records) < page_size:
                    break
                offset += page_size
        return programs

    def _fetch_detail(self, client: httpx.Client, overview: dict) -> Program | None:
        program_id = overview.get("id")
        handle = overview.get("handle")
        if not program_id or not handle:
            return None

        try:
            resp = client.get(f"/programs/{program_id}")
            resp.raise_for_status()
            detail = resp.json()
        except httpx.HTTPError:
            detail = {}

        in_scope: list[ScopeAsset] = []
        out_of_scope: list[ScopeAsset] = []
        domains = (detail.get("domains") or {}).get("content") or []
        for d in domains:
            tier_value = (d.get("tier") or {}).get("value", "") or ""
            out = "out of scope" in tier_value.lower() or "excluded" in tier_value.lower()
            asset = ScopeAsset(
                identifier=d.get("endpoint", "unknown"),
                asset_type=_TYPE_MAP.get(((d.get("type") or {}).get("value") or "").lower(), AssetType.OTHER),
                in_scope=not out,
                instruction=d.get("description"),
            )
            (in_scope if asset.in_scope else out_of_scope).append(asset)

        roe = ((detail.get("rulesOfEngagement") or {}).get("content")) or {}
        description = roe.get("description", "") or ""
        testing_requirements = roe.get("testingRequirements") or {}
        automated_tooling_raw = testing_requirements.get("automatedTooling")

        rules = derive_rules(description)
        if "safeHarbour" in roe:
            rules.safe_harbor = roe["safeHarbour"]
        if automated_tooling_raw is not None:
            rules.raw_notes = (
                (rules.raw_notes or "")
                + f" | Intigriti testingRequirements.automatedTooling={automated_tooling_raw}"
                  " (undocumented enum, verify meaning on the program page before trusting it)"
            )
        rules.required_user_agent = testing_requirements.get("userAgent") or None
        rules.required_request_header = testing_requirements.get("requestHeader") or None

        web_link = (detail.get("webLinks") or {}).get("detail") or f"https://app.intigriti.com/programs/{handle}"

        return Program(
            platform=Platform.INTIGRITI,
            handle=handle,
            name=detail.get("name", overview.get("name", handle)),
            url=web_link,
            policy_url=web_link,
            offers_bounties=overview.get("maxBounty", {}).get("value", 0) not in (0, None) if overview.get("maxBounty") else False,
            in_scope=in_scope,
            out_of_scope=out_of_scope,
            rules=rules,
            raw_policy_text=description or None,
        )
