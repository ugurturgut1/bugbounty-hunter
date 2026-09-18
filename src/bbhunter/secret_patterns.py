"""Shared secret-shaped regex patterns. Single source of truth for both
testing/ai_safety.py (scanning a model's text response) and
recon/js_harvest.py (scanning publicly-served JS bundles) -- a new
pattern only needs adding here once. Real secret-shaped substrings, not
just phrasing, so a match is a much stronger signal than a keyword
match."""
import re

SECRET_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ghp_[A-Za-z0-9]{36}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----"),
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),  # JWT shape
]
