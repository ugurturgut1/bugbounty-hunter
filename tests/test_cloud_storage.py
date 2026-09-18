"""Tests for testing/cloud_storage.py: opt-in S3/GCS/Azure bucket
exposure checks. Every HTTP call is mocked -- these never make a real
request to AWS/GCS/Azure infrastructure."""
from unittest.mock import MagicMock, patch

import httpx

from bbhunter.testing.cloud_storage import (
    candidate_bucket_names,
    check_azure_blob_container,
    check_gcs_bucket,
    check_s3_bucket,
)


def test_candidate_bucket_names_includes_bare_and_suffixed():
    names = candidate_bucket_names("Example")
    assert "example" in names
    assert "example-prod" in names
    assert "example-backup" in names


def test_check_s3_bucket_flags_real_listing():
    mock_resp = MagicMock(status_code=200, text="<ListBucketResult><Contents><Key>a.txt</Key></Contents></ListBucketResult>")
    with patch("bbhunter.testing.cloud_storage.httpx.get", return_value=mock_resp):
        hit = check_s3_bucket("example-backup")
    assert hit is not None
    assert hit["kind"] == "public-s3-bucket-listing"
    assert hit["severity"] == "info"


def test_check_s3_bucket_no_hit_on_access_denied():
    mock_resp = MagicMock(status_code=403, text="<Error><Code>AccessDenied</Code></Error>")
    with patch("bbhunter.testing.cloud_storage.httpx.get", return_value=mock_resp):
        assert check_s3_bucket("example-backup") is None


def test_check_s3_bucket_no_hit_on_no_such_bucket():
    mock_resp = MagicMock(status_code=404, text="<Error><Code>NoSuchBucket</Code></Error>")
    with patch("bbhunter.testing.cloud_storage.httpx.get", return_value=mock_resp):
        assert check_s3_bucket("example-backup") is None


def test_check_s3_bucket_no_hit_on_request_error():
    with patch("bbhunter.testing.cloud_storage.httpx.get", side_effect=httpx.ConnectError("nope")):
        assert check_s3_bucket("example-backup") is None


def test_check_gcs_bucket_flags_real_listing():
    mock_resp = MagicMock(status_code=200, text="<ListBucketResult><Contents><Key>a.txt</Key></Contents></ListBucketResult>")
    with patch("bbhunter.testing.cloud_storage.httpx.get", return_value=mock_resp):
        hit = check_gcs_bucket("example-assets")
    assert hit is not None
    assert hit["kind"] == "public-gcs-bucket-listing"


def test_check_gcs_bucket_no_hit_on_404():
    mock_resp = MagicMock(status_code=404, text="not found")
    with patch("bbhunter.testing.cloud_storage.httpx.get", return_value=mock_resp):
        assert check_gcs_bucket("example-assets") is None


def test_check_azure_blob_container_flags_real_listing():
    mock_resp = MagicMock(status_code=200, text="<EnumerationResults><Blobs><Blob><Name>a.txt</Name></Blob></Blobs></EnumerationResults>")
    with patch("bbhunter.testing.cloud_storage.httpx.get", return_value=mock_resp):
        hit = check_azure_blob_container("example")
    assert hit is not None
    assert hit["kind"] == "public-azure-blob-container-listing"


def test_check_azure_blob_container_no_hit_on_403():
    mock_resp = MagicMock(status_code=403, text="<Error><Code>ResourceNotFound</Code></Error>")
    with patch("bbhunter.testing.cloud_storage.httpx.get", return_value=mock_resp):
        assert check_azure_blob_container("example") is None


def test_no_hit_evidence_never_none_kind_when_hit():
    mock_resp = MagicMock(status_code=200, text="<ListBucketResult><Contents></Contents></ListBucketResult>")
    with patch("bbhunter.testing.cloud_storage.httpx.get", return_value=mock_resp):
        hit = check_s3_bucket("example")
    assert "verify" in hit["evidence"].lower()
