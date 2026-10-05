"""Single source of 'now' for the project.

datetime.utcnow() is deprecated (and scheduled for removal), but it
returns a timezone-NAIVE UTC datetime whose isoformat() has no offset
suffix -- the format every stored timestamp and lexicographic comparison
in this codebase already assumes. This helper keeps that exact format
while dropping the deprecated call, so existing stored data stays
comparable.
"""
from __future__ import annotations

from datetime import datetime, timezone


def utcnow() -> datetime:
    """Timezone-naive UTC now (same wire format as the old datetime.utcnow())."""
    return datetime.now(timezone.utc).replace(tzinfo=None)
