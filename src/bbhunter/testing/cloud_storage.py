"""Opt-in cloud storage bucket exposure check (S3/GCS/Azure Blob) --
derives candidate bucket names from a program's own in-scope domain
names and checks a small, fixed set of common naming variations for a
publicly-listable bucket. Extremely common, extremely lucrative real
bug-bounty finding class.

Every request here goes to the CLOUD PROVIDER's own infrastructure
(amazonaws.com/googleapis.com/windows.net), never the target's own
hosts -- similar in spirit to a third-party lookup like crt.sh, but
unlike crt.sh a same-named bucket can genuinely belong to an unrelated
third party who happens to have registered that name first. This is
deliberately conservative as a result:
- candidate names are derived ONLY from the program's own listed
  in-scope domains, never invented/guessed unrelated company names.
- a small, fixed suffix list, not a large brute-force wordlist.
- every finding lands at "info" severity with an explicit "verify this
  bucket actually belongs to the program before reporting" caveat -- a
  same-named public bucket existing is a candidate worth a human
  looking at, never a confirmed finding on its own.

Gated by the exact same permits(ACTIVE_LOW_IMPACT) check as every other
active check in this project -- not a new tier, same as --injection/
--nuclei on test-active.
"""
from __future__ import annotations

import time

import httpx

REQUEST_DELAY_SECONDS = 1.0
REQUEST_TIMEOUT_SECONDS = 10

_BUCKET_SUFFIXES = ("", "-prod", "-dev", "-staging", "-backup", "-assets", "-static", "-media", "-uploads", "-data", "-files", "-www")
_S3_LISTING_SIGNATURES = ("<listbucketresult", "<contents>")
_GCS_LISTING_SIGNATURES = ("<listbucketresult", "<contents>")  # GCS's XML API mirrors S3's shape
_AZURE_LISTING_SIGNATURE = "<enumerationresults"


def candidate_bucket_names(base_name: str) -> list[str]:
    base = base_name.lower().strip()
    return [f"{base}{suffix}" for suffix in _BUCKET_SUFFIXES]


def check_s3_bucket(bucket: str, *, timeout: float = REQUEST_TIMEOUT_SECONDS) -> dict | None:
    url = f"https://{bucket}.s3.amazonaws.com/"
    try:
        resp = httpx.get(url, timeout=timeout, follow_redirects=True)
    except httpx.HTTPError:
        return None
    if resp.status_code != 200:
        return None
    body_lower = resp.text.lower()
    if not any(sig in body_lower for sig in _S3_LISTING_SIGNATURES):
        return None
    return {
        "kind": "public-s3-bucket-listing",
        "severity": "info",
        "evidence": (
            f"{url} returned HTTP 200 with what looks like a public S3 bucket listing (XML "
            "ListBucketResult). Bucket name was derived from this program's own domain -- verify "
            "the bucket's actual contents/ownership before reporting; a same-named bucket can "
            "legitimately belong to an unrelated third party."
        ),
    }


def check_gcs_bucket(bucket: str, *, timeout: float = REQUEST_TIMEOUT_SECONDS) -> dict | None:
    url = f"https://storage.googleapis.com/{bucket}/"
    try:
        resp = httpx.get(url, timeout=timeout, follow_redirects=True)
    except httpx.HTTPError:
        return None
    if resp.status_code != 200:
        return None
    body_lower = resp.text.lower()
    if not any(sig in body_lower for sig in _GCS_LISTING_SIGNATURES):
        return None
    return {
        "kind": "public-gcs-bucket-listing",
        "severity": "info",
        "evidence": (
            f"{url} returned HTTP 200 with what looks like a public GCS bucket listing (XML "
            "ListBucketResult -- GCS's XML API mirrors S3's shape). Bucket name was derived from "
            "this program's own domain -- verify the bucket's actual contents/ownership before "
            "reporting; a same-named bucket can legitimately belong to an unrelated third party."
        ),
    }


def check_azure_blob_container(account: str, *, timeout: float = REQUEST_TIMEOUT_SECONDS) -> dict | None:
    """Guesses a container named the same as the storage account --
    Azure's naming convention gives no other way to discover a real
    container name without already having valid credentials."""
    url = f"https://{account}.blob.core.windows.net/{account}?restype=container&comp=list"
    try:
        resp = httpx.get(url, timeout=timeout, follow_redirects=True)
    except httpx.HTTPError:
        return None
    if resp.status_code != 200:
        return None
    if _AZURE_LISTING_SIGNATURE not in resp.text.lower():
        return None
    return {
        "kind": "public-azure-blob-container-listing",
        "severity": "info",
        "evidence": (
            f"{url} returned HTTP 200 with what looks like a public Azure Blob container listing "
            "(EnumerationResults XML). Account/container name was derived from this program's own "
            "domain -- verify actual contents/ownership before reporting."
        ),
    }


def check_cloud_buckets_for_name(base_name: str) -> list[dict]:
    hits: list[dict] = []
    for bucket in candidate_bucket_names(base_name):
        for check in (check_s3_bucket, check_gcs_bucket, check_azure_blob_container):
            hit = check(bucket)
            time.sleep(REQUEST_DELAY_SECONDS)
            if hit:
                hits.append(hit)
    return hits
