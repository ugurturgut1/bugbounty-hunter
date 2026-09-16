"""Bugcrowd connector -- NOT YET IMPLEMENTED.

Bugcrowd's researcher-facing programs/scope data lives behind their
Researcher API (see https://docs.bugcrowd.com/api/), which requires an
OAuth token tied to a Bugcrowd researcher account. Wire this up the same
way as HackerOneConnector once you have an account + token: fetch program
list, fetch per-program scope + brief/policy text, run it through
rules_engine.derive_rules, return normalized Program objects. Do not
scrape bugcrowd.com's HTML -- like HackerOne it's a client-rendered SPA
and there's no stable unauthenticated JSON endpoint for it.
"""
from __future__ import annotations

from bbhunter.discovery.base import PlatformConnector
from bbhunter.models import Program


class BugcrowdConnector(PlatformConnector):
    platform_name = "bugcrowd"

    def is_configured(self) -> bool:
        return False

    def fetch_programs(self, *, limit: int | None = None) -> list[Program]:
        raise NotImplementedError("Bugcrowd connector not implemented yet -- needs Researcher API token")
