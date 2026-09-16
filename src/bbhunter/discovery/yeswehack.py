"""YesWeHack connector -- NOT YET IMPLEMENTED.

YesWeHack has a public API (see https://developers.yeswehack.com/) that
exposes public program listings and scope; some endpoints need an account
token, others are public. Wire this up the same way as
HackerOneConnector once verified against their current API docs.
"""
from __future__ import annotations

from bbhunter.discovery.base import PlatformConnector
from bbhunter.models import Program


class YesWeHackConnector(PlatformConnector):
    platform_name = "yeswehack"

    def is_configured(self) -> bool:
        return False

    def fetch_programs(self, *, limit: int | None = None) -> list[Program]:
        raise NotImplementedError("YesWeHack connector not implemented yet")
