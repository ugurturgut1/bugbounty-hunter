"""Defense-in-depth safety controls, independent of any one check:

- Scope guard: a hard interlock answering "is this exact host in this
  program's scope?" so the URL-taking checks (test-idor, token-leak, ...)
  can refuse a typo'd or out-of-scope target *before* a request goes out,
  not just rely on _select_hosts having chosen well.
- Kill switch: a global stop that makes every active check refuse,
  toggled by a file or env var -- an instant "stop touching everything"
  that doesn't require editing each program's approval.

Both are deliberately strict: scope defaults to "no" on anything it
can't positively match, and an out-of-scope entry always wins over an
in-scope one.
"""
from __future__ import annotations

import os
from urllib.parse import urlsplit

from bbhunter.config import DATA_DIR
from bbhunter.models import AssetType, Program

KILLSWITCH_FILE = DATA_DIR / "KILLSWITCH"
KILLSWITCH_ENV = "BBHUNTER_KILLSWITCH"


class ScopeViolation(RuntimeError):
    """Raised when a check is pointed at a host not provably in scope."""


class KillSwitchEngaged(RuntimeError):
    """Raised when the global kill switch is on and an active check is attempted."""


def _host_of(identifier: str) -> str | None:
    identifier = identifier.strip()
    if not identifier:
        return None
    host = urlsplit(identifier).hostname if "://" in identifier else identifier.split("/")[0].split(":")[0]
    return (host or identifier).lstrip("*.").lower() or None


def host_from_url(url: str) -> str | None:
    """Extract the host from a URL or bare host string, lowercased."""
    return _host_of(url)


def _matches(host: str, identifier: str, asset_type: AssetType) -> bool:
    base = _host_of(identifier)
    if not base:
        return False
    if asset_type == AssetType.WILDCARD:
        return host == base or host.endswith("." + base)
    return host == base


def is_in_scope(program: Program, host: str) -> bool:
    """True only if `host` positively matches an in-scope URL/WILDCARD
    asset and does NOT match any out-of-scope entry (which always wins)."""
    if not host:
        return False
    host = host.lower()
    for oos in program.out_of_scope:
        atype = oos.asset_type if oos.asset_type in (AssetType.URL, AssetType.WILDCARD) else AssetType.WILDCARD
        if _matches(host, oos.identifier, atype):
            return False
    for asset in program.in_scope:
        if asset.asset_type in (AssetType.URL, AssetType.WILDCARD) and _matches(host, asset.identifier, asset.asset_type):
            return True
    return False


def assert_in_scope(program: Program, url_or_host: str) -> None:
    """Raise ScopeViolation unless the URL/host is in the program's scope."""
    host = host_from_url(url_or_host)
    if not is_in_scope(program, host or ""):
        raise ScopeViolation(
            f"{url_or_host!r} (host {host!r}) is not in {program.key}'s scope -- refusing. "
            "Only test assets explicitly listed in the program's scope."
        )


def killswitch_engaged() -> bool:
    """True if the global kill switch is on (env var set to a truthy value,
    or the kill-switch file exists)."""
    env = os.environ.get(KILLSWITCH_ENV, "").strip().lower()
    if env in ("1", "true", "yes", "on"):
        return True
    return KILLSWITCH_FILE.exists()


def set_killswitch(on: bool) -> None:
    if on:
        KILLSWITCH_FILE.write_text("engaged\n")
    elif KILLSWITCH_FILE.exists():
        KILLSWITCH_FILE.unlink()


def assert_active_allowed() -> None:
    """Raise KillSwitchEngaged if the global stop is on. Call at the top of
    every active check, alongside the per-program approve-active gate."""
    if killswitch_engaged():
        raise KillSwitchEngaged(
            "global kill switch is ENGAGED -- all active testing is halted. "
            "Clear it with `bbhunter killswitch off` (or unset BBHUNTER_KILLSWITCH)."
        )
