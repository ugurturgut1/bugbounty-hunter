"""Passive DNS hygiene checks: SPF/DMARC/DKIM email-spoofing misconfig
and dangling-CNAME (pre-HTTP subdomain-takeover) detection.

Every lookup here goes to public DNS resolvers, never to the target's
own web/app infrastructure -- same request class as crt.sh/Wayback/
subfinder elsewhere in this package (third-party lookups only), so
callers land these as TestType.PASSIVE_RECON, same floor as everything
else in recon/passive.py.

SPF/DMARC are checked against the seed host as given (stripping a single
"www." prefix, not a full public-suffix-list-based apex resolution) --
a reasonable approximation consistent with how this project's other
passive checks already work off the given seed string directly, not a
guarantee of hitting the exact organizational domain for a deeply
nested seed.

DKIM has no discoverable "list every selector" mechanism -- a domain's
real selector is provider-specific and not published anywhere queryable.
`check_dkim` only tries a short list of common selectors and NEVER
reports "DKIM missing" from that -- failing to find a record at a
guessed selector proves nothing, and manufacturing a false negative from
that would be worse than saying nothing. It only ever reports a positive
signal: a real record found at a common selector whose public key looks
too short to be safe.
"""
from __future__ import annotations

import base64

import dns.exception
import dns.resolver

DNS_TIMEOUT_SECONDS = 5.0

_DKIM_SELECTOR_CANDIDATES = ("default", "google", "selector1", "selector2", "k1", "dkim", "mail")
# Rough floor: a 1024-bit RSA SubjectPublicKeyInfo blob base64-decodes to ~162 bytes.
# Below this is short enough to almost certainly be a sub-1024-bit (weak) key.
_DKIM_WEAK_KEY_BYTE_THRESHOLD = 150
_SPF_ALL_TOKENS = {"all", "+all", "-all", "~all", "?all"}


def _resolver() -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver()
    resolver.timeout = DNS_TIMEOUT_SECONDS
    resolver.lifetime = DNS_TIMEOUT_SECONDS
    return resolver


def _txt_records(name: str) -> list[str]:
    try:
        answer = _resolver().resolve(name, "TXT")
    except dns.exception.DNSException:
        return []
    records = []
    for rdata in answer:
        # dnspython splits a long TXT value into multiple quoted strings -- join them back.
        records.append(b"".join(rdata.strings).decode(errors="ignore"))
    return records


def check_spf(domain: str) -> list[dict]:
    hits: list[dict] = []
    records = [r for r in _txt_records(domain) if r.lower().startswith("v=spf1")]
    if not records:
        hits.append({
            "kind": "spf-record-missing",
            "severity": "info",
            "evidence": (
                f"No SPF (v=spf1) TXT record found at {domain}. Without SPF, receiving mail servers "
                "have no signal to reject mail spoofed as being from this domain."
            ),
        })
        return hits

    if len(records) > 1:
        hits.append({
            "kind": "spf-multiple-records",
            "severity": "low",
            "evidence": (
                f"{len(records)} SPF records found at {domain} ({'; '.join(records)}). RFC 7208 says "
                "multiple SPF records cause SPF evaluation to fail (permerror) -- this likely breaks "
                "SPF entirely rather than strengthening it."
            ),
        })

    for record in records:
        tokens = record.split()
        all_token = next((t for t in tokens if t.lower() in _SPF_ALL_TOKENS), None)
        if all_token and all_token.lower() in ("all", "+all"):
            hits.append({
                "kind": "spf-permissive-all",
                "severity": "medium",
                "evidence": (
                    f"SPF record at {domain} ('{record}') ends in a permissive 'all' mechanism "
                    f"('{all_token}', bare 'all' defaults to +all) -- allows any server to send mail "
                    "as this domain without failing SPF."
                ),
            })

    return hits


def check_dmarc(domain: str) -> list[dict]:
    hits: list[dict] = []
    records = [r for r in _txt_records(f"_dmarc.{domain}") if r.lower().startswith("v=dmarc1")]
    if not records:
        hits.append({
            "kind": "dmarc-record-missing",
            "severity": "info",
            "evidence": (
                f"No DMARC record found at _dmarc.{domain}. Without DMARC, mail that fails SPF/DKIM "
                "has no enforced disposition policy against spoofing."
            ),
        })
        return hits

    record = records[0]
    tags = dict(part.strip().split("=", 1) for part in record.split(";") if "=" in part)
    policy = tags.get("p", "").strip().lower()
    if policy == "none":
        hits.append({
            "kind": "dmarc-policy-none",
            "severity": "low",
            "evidence": f"DMARC record at _dmarc.{domain} sets p=none (monitor-only, no enforcement against spoofed mail): '{record}'.",
        })
    return hits


def check_dkim(domain: str) -> list[dict]:
    hits: list[dict] = []
    for selector in _DKIM_SELECTOR_CANDIDATES:
        for record in _txt_records(f"{selector}._domainkey.{domain}"):
            if "p=" not in record.lower():
                continue
            tags = dict(part.strip().split("=", 1) for part in record.split(";") if "=" in part)
            pub_key_b64 = (tags.get("p") or "").strip()
            if not pub_key_b64:
                continue
            try:
                decoded_len = len(base64.b64decode(pub_key_b64 + "=" * (-len(pub_key_b64) % 4)))
            except (ValueError, base64.binascii.Error):
                continue
            if 0 < decoded_len < _DKIM_WEAK_KEY_BYTE_THRESHOLD:
                hits.append({
                    "kind": "dkim-weak-key-candidate",
                    "severity": "low",
                    "evidence": (
                        f"DKIM selector '{selector}' at {domain} publishes a public key ~{decoded_len} "
                        "bytes long, shorter than a typical 1024-bit RSA key. Heuristic byte-length "
                        "estimate only -- verify the actual key size before reporting."
                    ),
                })
    return hits


def check_dangling_cname(host: str) -> dict | None:
    """A CNAME pointing at a target that itself doesn't resolve at all
    (NXDOMAIN) is the classic dangling-DNS setup behind many real
    subdomain takeovers -- and catches it even when the target never
    responds to HTTP at all, which nuclei's signature-based takeover
    templates (matched against an actual HTTP response body) can't see.
    Returns None on any inconclusive result (timeout, SERVFAIL, no CNAME
    at all, or a target that resolves fine) -- never manufactures a
    signal from uncertainty."""
    resolver = _resolver()
    try:
        answer = resolver.resolve(host, "CNAME")
    except dns.exception.DNSException:
        return None
    target = str(answer[0].target).rstrip(".")

    try:
        resolver.resolve(target, "A")
        return None  # target resolves fine -- no signal
    except dns.resolver.NXDOMAIN:
        pass
    except dns.exception.DNSException:
        return None  # inconclusive (timeout/SERVFAIL/etc) -- not a signal either way

    return {
        "kind": "dangling-cname-candidate",
        "severity": "high",
        "evidence": (
            f"{host} has a CNAME pointing to {target}, which does not itself resolve (NXDOMAIN). "
            "A CNAME to a dead target is the classic dangling-DNS/subdomain-takeover setup if that "
            "exact name can be (re-)claimed on whichever provider it belongs to -- verify against the "
            "specific provider (S3, GitHub Pages, Heroku, Azure, etc.) before reporting."
        ),
    }
