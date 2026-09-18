"""Tests for recon/dns_hygiene.py: SPF/DMARC/DKIM misconfig detection
and dangling-CNAME detection. Every DNS lookup is mocked -- these never
make a real network query."""
from unittest.mock import MagicMock, patch

import dns.exception
import dns.resolver

from bbhunter.recon.dns_hygiene import check_dangling_cname, check_dkim, check_dmarc, check_spf


def _txt_answer(*values: str):
    records = []
    for value in values:
        rdata = MagicMock()
        rdata.strings = [value.encode()]
        records.append(rdata)
    return records


def test_check_spf_flags_missing_record():
    with patch("bbhunter.recon.dns_hygiene._resolver") as mock_resolver:
        mock_resolver.return_value.resolve.side_effect = dns.resolver.NXDOMAIN()
        hits = check_spf("example.com")
    assert len(hits) == 1
    assert hits[0]["kind"] == "spf-record-missing"


def test_check_spf_no_hit_on_restrictive_record():
    with patch("bbhunter.recon.dns_hygiene._resolver") as mock_resolver:
        mock_resolver.return_value.resolve.return_value = _txt_answer("v=spf1 include:_spf.example.com -all")
        hits = check_spf("example.com")
    assert hits == []


def test_check_spf_flags_permissive_all():
    with patch("bbhunter.recon.dns_hygiene._resolver") as mock_resolver:
        mock_resolver.return_value.resolve.return_value = _txt_answer("v=spf1 include:_spf.example.com +all")
        hits = check_spf("example.com")
    assert any(h["kind"] == "spf-permissive-all" for h in hits)


def test_check_spf_flags_bare_all_as_permissive():
    with patch("bbhunter.recon.dns_hygiene._resolver") as mock_resolver:
        mock_resolver.return_value.resolve.return_value = _txt_answer("v=spf1 include:_spf.example.com all")
        hits = check_spf("example.com")
    assert any(h["kind"] == "spf-permissive-all" for h in hits)


def test_check_spf_flags_multiple_records():
    with patch("bbhunter.recon.dns_hygiene._resolver") as mock_resolver:
        mock_resolver.return_value.resolve.return_value = _txt_answer("v=spf1 -all", "v=spf1 include:other.com -all")
        hits = check_spf("example.com")
    assert any(h["kind"] == "spf-multiple-records" for h in hits)


def test_check_dmarc_flags_missing_record():
    with patch("bbhunter.recon.dns_hygiene._resolver") as mock_resolver:
        mock_resolver.return_value.resolve.side_effect = dns.resolver.NXDOMAIN()
        hits = check_dmarc("example.com")
    assert len(hits) == 1
    assert hits[0]["kind"] == "dmarc-record-missing"


def test_check_dmarc_flags_policy_none():
    with patch("bbhunter.recon.dns_hygiene._resolver") as mock_resolver:
        mock_resolver.return_value.resolve.return_value = _txt_answer("v=DMARC1; p=none; rua=mailto:x@example.com")
        hits = check_dmarc("example.com")
    assert any(h["kind"] == "dmarc-policy-none" for h in hits)


def test_check_dmarc_no_hit_on_reject_policy():
    with patch("bbhunter.recon.dns_hygiene._resolver") as mock_resolver:
        mock_resolver.return_value.resolve.return_value = _txt_answer("v=DMARC1; p=reject")
        hits = check_dmarc("example.com")
    assert hits == []


def test_check_dkim_no_hit_when_no_selectors_found():
    with patch("bbhunter.recon.dns_hygiene._resolver") as mock_resolver:
        mock_resolver.return_value.resolve.side_effect = dns.resolver.NXDOMAIN()
        hits = check_dkim("example.com")
    assert hits == []


def test_check_dkim_flags_short_key():
    import base64
    short_key_b64 = base64.b64encode(b"x" * 50).decode()

    def fake_resolve(name, rtype):
        if name.startswith("default._domainkey."):
            return _txt_answer(f"v=DKIM1; k=rsa; p={short_key_b64}")
        raise dns.resolver.NXDOMAIN()

    with patch("bbhunter.recon.dns_hygiene._resolver") as mock_resolver:
        mock_resolver.return_value.resolve.side_effect = fake_resolve
        hits = check_dkim("example.com")
    assert any(h["kind"] == "dkim-weak-key-candidate" for h in hits)


def test_check_dkim_no_hit_for_full_length_key():
    import base64
    normal_key_b64 = base64.b64encode(b"x" * 200).decode()

    def fake_resolve(name, rtype):
        if name.startswith("default._domainkey."):
            return _txt_answer(f"v=DKIM1; k=rsa; p={normal_key_b64}")
        raise dns.resolver.NXDOMAIN()

    with patch("bbhunter.recon.dns_hygiene._resolver") as mock_resolver:
        mock_resolver.return_value.resolve.side_effect = fake_resolve
        hits = check_dkim("example.com")
    assert hits == []


def test_check_dangling_cname_no_hit_without_cname():
    with patch("bbhunter.recon.dns_hygiene._resolver") as mock_resolver:
        mock_resolver.return_value.resolve.side_effect = dns.resolver.NoAnswer()
        assert check_dangling_cname("example.com") is None


def test_check_dangling_cname_no_hit_when_target_resolves():
    def fake_resolve(name, rtype):
        if rtype == "CNAME":
            target = MagicMock()
            target.target = "alive-target.example.net."
            return [target]
        return [MagicMock()]  # A record resolves fine

    with patch("bbhunter.recon.dns_hygiene._resolver") as mock_resolver:
        mock_resolver.return_value.resolve.side_effect = fake_resolve
        assert check_dangling_cname("sub.example.com") is None


def test_check_dangling_cname_flags_when_target_is_nxdomain():
    def fake_resolve(name, rtype):
        if rtype == "CNAME":
            target = MagicMock()
            target.target = "dead-target.herokuapp.com."
            return [target]
        raise dns.resolver.NXDOMAIN()

    with patch("bbhunter.recon.dns_hygiene._resolver") as mock_resolver:
        mock_resolver.return_value.resolve.side_effect = fake_resolve
        hit = check_dangling_cname("sub.example.com")
    assert hit is not None
    assert hit["kind"] == "dangling-cname-candidate"
    assert hit["severity"] == "high"


def test_check_dangling_cname_inconclusive_on_timeout():
    def fake_resolve(name, rtype):
        if rtype == "CNAME":
            target = MagicMock()
            target.target = "some-target.example.net."
            return [target]
        raise dns.exception.Timeout()

    with patch("bbhunter.recon.dns_hygiene._resolver") as mock_resolver:
        mock_resolver.return_value.resolve.side_effect = fake_resolve
        assert check_dangling_cname("sub.example.com") is None
