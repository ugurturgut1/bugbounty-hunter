"""Bugcrowd connector, built directly against Bugcrowd's official OpenAPI
spec (https://bugcrowd.com/openapi/1.1.0/openapi.yml, linked from
docs.bugcrowd.com/api/1.1.0/). Uses their JSON:API-style REST API, not
scraping -- bugcrowd.com is a client-rendered SPA with no stable
unauthenticated JSON endpoint.

Auth: Bugcrowd API credentials are a username + secret pair (generated in
account settings -> API Credentials), sent as
`Authorization: Token <username>:<password>` -- not a single bearer
token. Set BUGCROWD_API_USERNAME / BUGCROWD_API_PASSWORD.
"""
from __future__ import annotations

import httpx

from bbhunter.config import BugcrowdCreds
from bbhunter.discovery.base import PlatformConnector
from bbhunter.models import AssetType, Platform, Program, ScopeAsset
from bbhunter.rules_engine import derive_rules

BASE_URL = "https://api.bugcrowd.com"
ACCEPT = "application/vnd.bugcrowd+json"

_CATEGORY_MAP = {
    "website": AssetType.URL,
    "api": AssetType.URL,
    "ios": AssetType.MOBILE_APP,
    "android": AssetType.MOBILE_APP,
    "iot": AssetType.HARDWARE,
    "hardware": AssetType.HARDWARE,
    "network": AssetType.IP_RANGE,
    "ip_address": AssetType.IP_RANGE,
    "collection": AssetType.OTHER,
    "other": AssetType.OTHER,
}


class BugcrowdConnector(PlatformConnector):
    platform_name = "bugcrowd"

    def __init__(self, creds: BugcrowdCreds | None = None):
        self.creds = creds or BugcrowdCreds()

    def is_configured(self) -> bool:
        return self.creds.configured

    def _client(self) -> httpx.Client:
        return httpx.Client(
            base_url=BASE_URL,
            timeout=30,
            headers={"Accept": ACCEPT, "Authorization": self.creds.auth_header},
        )

    def fetch_programs(self, *, limit: int | None = None) -> list[Program]:
        if not self.is_configured():
            raise RuntimeError("BugcrowdConnector not configured: set BUGCROWD_API_USERNAME/PASSWORD")

        programs: list[Program] = []
        with self._client() as client:
            offset = 0
            page_size = 50
            while True:
                resp = client.get(
                    "/programs",
                    params={
                        "page[limit]": page_size,
                        "page[offset]": offset,
                        "include": "organization,engagements",
                        "fields[program]": "code,name,organization,engagements",
                        "fields[engagement]": "code,state,engagement_brief,bounty",
                        "fields[organization]": "name",
                    },
                )
                resp.raise_for_status()
                body = resp.json()
                data = body.get("data", [])
                if not data:
                    break

                included = body.get("included", [])
                engagements_by_id = {i["id"]: i for i in included if i.get("type") == "engagement"}

                for item in data:
                    program = self._to_program(client, item, engagements_by_id)
                    if program is not None:
                        programs.append(program)
                    if limit and len(programs) >= limit:
                        return programs

                if len(data) < page_size:
                    break
                offset += page_size
        return programs

    def _to_program(self, client: httpx.Client, item: dict, engagements_by_id: dict) -> Program | None:
        program_id = item.get("id")
        attrs = item.get("attributes", {})
        code = attrs.get("code")
        if not program_id or not code:
            return None

        offers_bounties = False
        engagement_refs = item.get("relationships", {}).get("engagements", {}).get("data", [])
        raw_policy_parts: list[str] = []
        safe_harbor: bool | None = None
        for ref in engagement_refs:
            engagement = engagements_by_id.get(ref.get("id"))
            if not engagement:
                continue
            eattrs = engagement.get("attributes", {})
            if eattrs.get("bounty"):
                offers_bounties = True
            brief = self._fetch_engagement_brief(client, ref.get("id"))
            if brief:
                raw_policy_parts.append(brief.get("text", ""))
                if brief.get("safe_harbor") is not None:
                    safe_harbor = brief["safe_harbor"]

        in_scope, out_of_scope = self._fetch_targets(client, program_id)
        raw_policy_text = "\n\n".join(p for p in raw_policy_parts if p)
        rules = derive_rules(raw_policy_text)
        if safe_harbor is not None:
            rules.safe_harbor = safe_harbor

        return Program(
            platform=Platform.BUGCROWD,
            handle=code,
            name=attrs.get("name", code),
            url=f"https://bugcrowd.com/{code}",
            policy_url=f"https://bugcrowd.com/{code}/target-groups",
            offers_bounties=offers_bounties,
            in_scope=in_scope,
            out_of_scope=out_of_scope,
            rules=rules,
            raw_policy_text=raw_policy_text or None,
        )

    def _fetch_engagement_brief(self, client: httpx.Client, engagement_id: str | None) -> dict | None:
        if not engagement_id:
            return None
        try:
            resp = client.get(
                f"/engagements/{engagement_id}",
                params={
                    "include": "engagement_brief",
                    "fields[engagement_brief]": (
                        "description,additional_information,safe_harbor_status,"
                        "targets_overview,coordinated_disclosure"
                    ),
                },
            )
            if resp.status_code != 200:
                return None
            body = resp.json()
            brief = next((i for i in body.get("included", []) if i.get("type") == "engagement_brief"), None)
            if not brief:
                return None
            battrs = brief.get("attributes", {})
            text = "\n".join(
                str(battrs.get(k, "") or "")
                for k in ("description", "additional_information", "targets_overview", "coordinated_disclosure")
            )
            safe_harbor_status = battrs.get("safe_harbor_status")
            safe_harbor = None
            if isinstance(safe_harbor_status, str):
                safe_harbor = safe_harbor_status.lower() in ("enabled", "active", "opted_in", "true")
            elif isinstance(safe_harbor_status, bool):
                safe_harbor = safe_harbor_status
            return {"text": text, "safe_harbor": safe_harbor}
        except httpx.HTTPError:
            return None

    def _fetch_targets(self, client: httpx.Client, program_id: str) -> tuple[list[ScopeAsset], list[ScopeAsset]]:
        in_scope: list[ScopeAsset] = []
        out_of_scope: list[ScopeAsset] = []
        try:
            offset = 0
            page_size = 100
            while True:
                resp = client.get(
                    f"/programs/{program_id}/targets",
                    params={"page[limit]": page_size, "page[offset]": offset},
                )
                if resp.status_code != 200:
                    break
                body = resp.json()
                data = body.get("data", [])
                if not data:
                    break
                for t in data:
                    tattrs = t.get("attributes", {})
                    coverage = tattrs.get("coverage")
                    if coverage not in ("in_scope", "out_of_scope"):
                        continue
                    asset = ScopeAsset(
                        identifier=tattrs.get("url_location") or tattrs.get("name", "unknown"),
                        asset_type=_CATEGORY_MAP.get(tattrs.get("category", ""), AssetType.OTHER),
                        in_scope=coverage == "in_scope",
                    )
                    (in_scope if asset.in_scope else out_of_scope).append(asset)
                if len(data) < page_size:
                    break
                offset += page_size
        except httpx.HTTPError:
            pass
        return in_scope, out_of_scope
