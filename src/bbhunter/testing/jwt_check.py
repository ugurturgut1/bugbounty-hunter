"""Offline structural analysis of a JWT you already hold (your own session
token). Pure decoding + inspection -- no network, no signature cracking,
no secret guessing -- so it needs no approve-active gate: it only reads
what the token already tells you and flags weak choices a program may
accept as a finding.

Flags: alg=none (signature not verified at all), symmetric HS* (forgeable
if the secret is weak -- worth a manual check), missing exp (token never
expires), and a very long lifetime.
"""
from __future__ import annotations

import base64
import json
import time


def _b64url_decode(segment: str) -> bytes:
    pad = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + pad)


def decode_jwt(token: str) -> tuple[dict, dict]:
    """Return (header, payload) dicts. Raises ValueError on anything that
    isn't a well-formed JWT (three dot-separated base64url segments with
    JSON header+payload)."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError("not a JWT (expected three '.'-separated segments)")
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except Exception as e:  # any base64/JSON decode failure means "not a well-formed JWT"
        raise ValueError(f"malformed JWT segments: {e}") from e
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise ValueError("JWT header/payload are not JSON objects")
    return header, payload


# one year in seconds -- a longer-lived access token is worth flagging
_LONG_LIFETIME = 365 * 24 * 3600


def analyze_jwt(token: str, *, now: float | None = None) -> list[dict]:
    """Return a list of weakness dicts ({kind, severity, detail}). Empty
    list means nothing structurally weak was found (not that the token is
    'secure' -- signature strength isn't checked here)."""
    header, payload = decode_jwt(token)
    now = time.time() if now is None else now
    issues: list[dict] = []
    alg = str(header.get("alg", "")).lower()

    if alg in ("none", ""):
        issues.append({"kind": "jwt-alg-none", "severity": "high",
                       "detail": "alg is 'none' -- the signature is not verified; a token can be forged by "
                                 "stripping the signature. Verify the server actually accepts it."})
    elif alg.startswith("hs"):
        issues.append({"kind": "jwt-symmetric-alg", "severity": "info",
                       "detail": f"alg is symmetric ({header.get('alg')}) -- forgeable if the shared secret is "
                                 "weak/guessable. Worth a manual offline secret-strength check (never brute "
                                 "force the live endpoint)."})

    if "exp" not in payload:
        issues.append({"kind": "jwt-no-exp", "severity": "medium",
                       "detail": "no 'exp' claim -- the token never expires, so a leaked token stays valid "
                                 "indefinitely."})
    else:
        try:
            lifetime = float(payload["exp"]) - float(payload.get("iat", now))
            if lifetime > _LONG_LIFETIME:
                issues.append({"kind": "jwt-long-lifetime", "severity": "low",
                               "detail": f"token lifetime is ~{lifetime/86400:.0f} days -- unusually long for an "
                                         "access token; a leak has a long exploitation window."})
        except (TypeError, ValueError):
            pass
    return issues
