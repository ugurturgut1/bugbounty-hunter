from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

# load_dotenv() with no path searches upward from the *caller's* location,
# not the process cwd -- fine when running `uv run bbhunter` from inside
# the project, but silently finds nothing (empty creds, no error) once
# `bbhunter` is installed as a standalone tool (`uv tool install`) and
# run from an arbitrary directory. Pointing it at the same project home
# DATA_DIR resolves against keeps credentials working regardless of cwd.
PROJECT_HOME = Path(os.environ.get("BBHUNTER_HOME", Path.home() / "bugbounty-hunter"))
load_dotenv(PROJECT_HOME / ".env")

DATA_DIR = Path(os.environ.get("BBHUNTER_DATA_DIR", PROJECT_HOME / "state"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "bbhunter.db"


@dataclass(frozen=True)
class HackerOneCreds:
    username: str | None = os.environ.get("H1_API_USERNAME")
    token: str | None = os.environ.get("H1_API_TOKEN")

    @property
    def configured(self) -> bool:
        return bool(self.username and self.token)


@dataclass(frozen=True)
class BugcrowdCreds:
    # Bugcrowd's API uses "Authorization: Token <username>:<password>",
    # a username/secret pair generated per-token in account settings --
    # not a single bearer token. See docs.bugcrowd.com/api/getting-started/.
    username: str | None = os.environ.get("BUGCROWD_API_USERNAME")
    password: str | None = os.environ.get("BUGCROWD_API_PASSWORD")

    @property
    def configured(self) -> bool:
        return bool(self.username and self.password)

    @property
    def auth_header(self) -> str:
        return f"Token {self.username}:{self.password}"


@dataclass(frozen=True)
class IntigritiCreds:
    token: str | None = os.environ.get("INTIGRITI_API_TOKEN")

    @property
    def configured(self) -> bool:
        return bool(self.token)


@dataclass(frozen=True)
class YesWeHackCreds:
    token: str | None = os.environ.get("YWH_API_TOKEN")

    @property
    def configured(self) -> bool:
        return bool(self.token)
