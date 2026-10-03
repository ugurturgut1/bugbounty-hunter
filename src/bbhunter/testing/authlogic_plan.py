"""Turn a ReconResult into a prioritized manual auth/logic testing
checklist. Pure analysis, no network -- it only reads what passive recon
already gathered and groups it into candidate test cases a human then
works through with `test-idor` / `test-bfla` (supplying their own two
accounts). The tool suggests *where to look*; the human keeps every
judgement call and every request.

Heuristics (deliberately coarse -- a shortlist to sanity-check, not a
verdict):
- BOLA/IDOR candidates: URLs whose path or query references a specific
  object -- a numeric id, a UUID, or an id-shaped query param.
- BFLA candidates: URLs whose path looks administrative/privileged.
- Hosts worth an authenticated pass: API-looking hosts/paths.
"""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlsplit

from bbhunter.models import ReconResult

_UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
_NUMERIC_SEG_RE = re.compile(r"/\d+(?:/|$)")
_ID_PARAM_NAMES = ("id", "uid", "user", "userid", "account", "accountid", "order", "orderid",
                    "uuid", "guid", "object", "doc", "file", "invoice", "customer", "profile")
_PRIVILEGED_SEGMENTS = ("admin", "administrator", "internal", "manage", "management", "console",
                        "config", "settings", "users", "staff", "backoffice", "superuser",
                        "privileged", "root", "sudo", "operator", "dashboard")


def _is_object_ref(url: str) -> bool:
    parts = urlsplit(url)
    if _UUID_RE.search(parts.path) or _NUMERIC_SEG_RE.search(parts.path):
        return True
    for name, _ in parse_qsl(parts.query):
        if name.lower() in _ID_PARAM_NAMES:
            return True
    return False


def _is_privileged(url: str) -> bool:
    path = urlsplit(url).path.lower()
    return any(f"/{seg}" in path for seg in _PRIVILEGED_SEGMENTS)


def build_plan(program_key: str, recon: ReconResult) -> str:
    """Return a markdown checklist. Empty-ish recon still yields a valid
    doc with the method reminders, just no concrete candidates."""
    all_urls: list[str] = []
    for urls in recon.param_urls.values():
        all_urls.extend(urls)
    # Authenticated endpoints from `authed-recon` are concrete API operations
    # -- exactly the high-value surface for BOLA/BFLA, so fold them in too.
    all_urls.extend(recon.authed_endpoints)
    graphql = [u for u in recon.authed_endpoints if u.rstrip("/").endswith("graphql") or u.endswith("/query")]
    all_hosts = sorted(recon.fingerprints.keys())

    bola = sorted({u for u in all_urls if _is_object_ref(u)})
    bfla = sorted({u for u in all_urls if _is_privileged(u)})
    bfla_hosts = sorted({h for h in all_hosts if any(f"{seg}" in h.lower() for seg in ("admin", "internal", "manage"))})
    api_hosts = sorted({h for h in all_hosts if h.startswith("api.") or "api" in h.lower() or "graphql" in h.lower()})

    lines: list[str] = [
        f"# Manual auth/logic test plan - {program_key}",
        "",
        "Candidates derived from passive recon (coarse heuristics - sanity-check each).",
        "Run each with two real accounts you control; respect the program's rate limit and policy.",
        "",
        f"## BOLA / IDOR candidates ({len(bola)}) - `test-idor`",
        "Object-referencing URLs: fetch as the owning account, then as a second unrelated account.",
    ]
    lines += [f"- [ ] {u}" for u in bola] or ["- (none found in recon param URLs)"]
    lines += [
        "",
        f"## BFLA / privileged-function candidates ({len(bfla) + len(bfla_hosts)}) - `test-bfla`",
        "Privileged-looking endpoints: fetch as an authorized account, then as a lower-privileged one.",
    ]
    lines += [f"- [ ] {u}" for u in bfla]
    lines += [f"- [ ] host: {h} (map its admin endpoints)" for h in bfla_hosts]
    if not bfla and not bfla_hosts:
        lines += ["- (none found)"]
    lines += [
        "",
        f"## API hosts worth an authenticated pass ({len(api_hosts)})",
        "Enumerate object/function endpoints here by hand, then feed them to test-idor/test-bfla (or --urls-file).",
    ]
    lines += [f"- [ ] {h}" for h in api_hosts] or ["- (none obviously API-shaped)"]
    if graphql:
        lines += [
            "",
            f"## GraphQL endpoints with open introspection ({len(graphql)})",
            "Enumerate types/fields by hand, then test field-level authz across your two accounts.",
        ]
        lines += [f"- [ ] {g}" for g in graphql]
    lines += [
        "",
        "## Reminders",
        "- Supply both sessions yourself; the tool never invents or brute-forces credentials.",
        "- These are candidates, not findings - each still needs manual confirmation + the PoC gate.",
        "",
    ]
    return "\n".join(lines)
