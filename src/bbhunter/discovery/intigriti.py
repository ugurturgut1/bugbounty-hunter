"""Intigriti connector -- NOT YET IMPLEMENTED.

Intigriti exposes a public researcher API (see https://kb.intigriti.com/en/
articles/api docs, "Core API") using a personal access token from your
Intigriti account settings. Wire this up the same way as
HackerOneConnector: list programs, pull domains/scope + policy text per
program, run through rules_engine.derive_rules.
"""
from __future__ import annotations

from bbhunter.discovery.base import PlatformConnector
from bbhunter.models import Program


class IntigritiConnector(PlatformConnector):
    platform_name = "intigriti"

    def is_configured(self) -> bool:
        return False

    def fetch_programs(self, *, limit: int | None = None) -> list[Program]:
        raise NotImplementedError("Intigriti connector not implemented yet -- needs personal access token")
