"""Tests for TLS certificate posture checks in recon/passive.py
(tls_cert_info, tls_findings). The subprocess calls to `openssl` are
mocked -- these never make a real network connection."""
from unittest.mock import MagicMock, patch

from bbhunter.recon.passive import _hostname_covered_by_san, tls_cert_info, tls_findings

_LEAF_PEM = "-----BEGIN CERTIFICATE-----\nMIIB...fake...\n-----END CERTIFICATE-----"


def _s_client_result(*, stdout: str = "", stderr: str = "", returncode: int = 0) -> MagicMock:
    result = MagicMock()
    result.stdout = stdout.encode()
    result.stderr = stderr.encode()
    result.returncode = returncode
    return result


def _x509_result(*, stdout: str) -> MagicMock:
    result = MagicMock()
    result.stdout = stdout.encode()
    result.stderr = b""
    return result


def test_tls_cert_info_returns_none_when_openssl_missing():
    with patch("bbhunter.recon.passive.shutil.which", return_value=None):
        assert tls_cert_info("example.com") is None


def test_tls_cert_info_returns_none_when_no_certificate_presented():
    with patch("bbhunter.recon.passive.shutil.which", return_value="/usr/bin/openssl"), \
         patch("bbhunter.recon.passive.subprocess.run", return_value=_s_client_result(stdout="connection refused")):
        assert tls_cert_info("example.com") is None


def test_tls_cert_info_parses_healthy_cert():
    s_client_output = f"{_LEAF_PEM}\nVerify return code: 0 (ok)\n"
    x509_output = (
        "notAfter=Oct 27 22:17:21 2026 GMT\n"
        "subject=CN=example.com\n"
        "X509v3 Subject Alternative Name:\n"
        "    DNS:example.com, DNS:*.example.com\n"
        "        Signature Algorithm: ecdsa-with-SHA256\n"
    )
    with patch("bbhunter.recon.passive.shutil.which", return_value="/usr/bin/openssl"), \
         patch(
             "bbhunter.recon.passive.subprocess.run",
             side_effect=[_s_client_result(stdout=s_client_output), _x509_result(stdout=x509_output)],
         ):
        info = tls_cert_info("example.com")
    assert info["not_after"] == "Oct 27 22:17:21 2026 GMT"
    assert info["subject"] == "CN=example.com"
    assert info["signature_algorithm"] == "ecdsa-with-SHA256"
    assert info["san_dns_names"] == ["example.com", "*.example.com"]
    assert info["verify_code"] == 0


def test_tls_findings_no_hits_for_healthy_cert():
    info = {
        "not_after": "Jan 1 00:00:00 2099 GMT",
        "signature_algorithm": "ecdsa-with-SHA256",
        "san_dns_names": ["example.com"],
        "verify_code": 0,
        "verify_text": "ok",
    }
    assert tls_findings("example.com", info) == []


def test_tls_findings_flags_self_signed():
    info = {"not_after": None, "signature_algorithm": None, "san_dns_names": [], "verify_code": 18, "verify_text": "self signed certificate"}
    hits = tls_findings("example.com", info)
    assert any(h["kind"] == "tls-self-signed-cert" for h in hits)


def test_tls_findings_flags_expired_cert():
    info = {"not_after": "Jan 1 00:00:00 2020 GMT", "signature_algorithm": None, "san_dns_names": [], "verify_code": 0, "verify_text": "ok"}
    hits = tls_findings("example.com", info)
    assert any(h["kind"] == "tls-cert-expired" for h in hits)


def test_tls_findings_flags_soon_expiring_cert():
    from datetime import datetime, timedelta
    soon = (datetime.utcnow() + timedelta(days=5)).strftime("%b %d %H:%M:%S %Y GMT")
    info = {"not_after": soon, "signature_algorithm": None, "san_dns_names": [], "verify_code": 0, "verify_text": "ok"}
    hits = tls_findings("example.com", info)
    assert any(h["kind"] == "tls-cert-expiring-soon" for h in hits)


def test_tls_findings_flags_weak_signature_algorithm():
    info = {"not_after": None, "signature_algorithm": "sha1WithRSAEncryption", "san_dns_names": [], "verify_code": 0, "verify_text": "ok"}
    hits = tls_findings("example.com", info)
    assert any(h["kind"] == "tls-weak-signature-algorithm" for h in hits)


def test_tls_findings_flags_hostname_not_in_san():
    info = {"not_after": None, "signature_algorithm": None, "san_dns_names": ["other.com"], "verify_code": 0, "verify_text": "ok"}
    hits = tls_findings("example.com", info)
    assert any(h["kind"] == "tls-hostname-not-in-san" for h in hits)


def test_hostname_covered_by_san_exact_match():
    assert _hostname_covered_by_san("example.com", ["example.com"]) is True


def test_hostname_covered_by_san_wildcard_match():
    assert _hostname_covered_by_san("api.example.com", ["*.example.com"]) is True


def test_hostname_covered_by_san_no_match():
    assert _hostname_covered_by_san("example.com", ["other.com"]) is False
