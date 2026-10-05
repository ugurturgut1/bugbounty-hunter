"""Authenticated endpoint discovery: with a session the human supplies,
fetch a host's machine-readable API description (OpenAPI/Swagger) and
probe GraphQL introspection, then turn the declared operations into a
concrete endpoint list. That list is the raw material `authlogic-plan`
needs to point `test-idor`/`test-bfla` at real authenticated endpoints
instead of just unauthenticated Wayback URLs.

Unlike passive recon this makes requests to the target itself (one GET
per candidate schema path, one POST per GraphQL candidate), so callers
gate it behind RulesOfEngagement.permits(TestType.ACTIVE_LOW_IMPACT) --
it is read-only (fetching a public/own-session schema, asking a GraphQL
server to describe itself) but still an active request. The session is
always the human's own; nothing here guesses or brute-forces auth.
"""
from __future__ import annotations

import time
from urllib.parse import urljoin

import httpx

# Common, conventional locations for an OpenAPI/Swagger document.
OPENAPI_PATHS = (
    "/openapi.json", "/swagger.json", "/v2/swagger.json", "/v3/api-docs",
    "/api-docs", "/swagger/v1/swagger.json", "/.well-known/openapi.json", "/api/openapi.json",
)
GRAPHQL_PATHS = ("/graphql", "/api/graphql", "/v1/graphql", "/query")
# Minimal introspection query -- just enough to confirm introspection is
# open; we don't walk the whole type system (that can be huge).
_INTROSPECTION = {"query": "{__schema{queryType{name}}}"}
REQUEST_DELAY_SECONDS = 1.0  # keep an authed-recon sweep under a 1-RPS program cap


def _extract_openapi_endpoints(base: str, doc: dict) -> list[str]:
    """Join each declared OpenAPI/Swagger path onto the server base. Also
    honors an OpenAPI `servers[].url` / Swagger `basePath` prefix if present."""
    paths = doc.get("paths")
    if not isinstance(paths, dict):
        return []
    prefix = ""
    servers = doc.get("servers")
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        prefix = str(servers[0].get("url", "")).rstrip("/")
    elif isinstance(doc.get("basePath"), str):
        prefix = doc["basePath"].rstrip("/")
    out: list[str] = []
    for p in paths:
        if not isinstance(p, str):
            continue
        # a server url can be absolute; urljoin handles both that and a bare basePath
        joined = urljoin(base + "/", (prefix + p).lstrip("/")) if "://" not in prefix else prefix + p
        out.append(joined)
    return out


def discover_authed_endpoints(
    hosts: list[str], headers: dict[str, str], *, timeout: float = 15, delay: float = REQUEST_DELAY_SECONDS
) -> tuple[list[str], list[str]]:
    """Return (endpoint_urls, notes). `endpoint_urls` are concrete URLs to
    feed auth-logic testing; `notes` are human-readable observations (which
    schema was found where, whether GraphQL introspection was open)."""
    endpoints: list[str] = []
    notes: list[str] = []
    first = True
    with httpx.Client(headers=headers, follow_redirects=True) as client:
        for host in hosts:
            base = f"https://{host}"
            for path in OPENAPI_PATHS:
                if not first:
                    time.sleep(delay)
                first = False
                try:
                    resp = client.get(base + path, timeout=timeout)
                except httpx.HTTPError:
                    continue
                if resp.status_code != 200 or "json" not in resp.headers.get("content-type", "").lower():
                    continue
                try:
                    doc = resp.json()
                except ValueError:
                    continue
                if not isinstance(doc, dict) or "paths" not in doc:
                    continue
                found = _extract_openapi_endpoints(base, doc)
                if found:
                    endpoints.extend(found)
                    notes.append(f"OpenAPI/Swagger at {base}{path}: {len(found)} endpoint(s)")
                    break  # one schema per host is enough
            for path in GRAPHQL_PATHS:
                time.sleep(delay)
                try:
                    resp = client.post(base + path, json=_INTROSPECTION, timeout=timeout)
                except httpx.HTTPError:
                    continue
                if resp.status_code != 200:
                    continue
                try:
                    data = resp.json()
                except ValueError:
                    continue
                if isinstance(data, dict) and isinstance(data.get("data"), dict) and data["data"].get("__schema"):
                    endpoints.append(base + path)
                    notes.append(f"GraphQL introspection OPEN at {base}{path} -- enumerate types/fields by hand")
                    break
    # de-dupe, keep order
    seen: set[str] = set()
    deduped = [e for e in endpoints if not (e in seen or seen.add(e))]
    return deduped, notes
