"""Phase 4: dedup candidate findings against public disclosures."""
from bbhunter.disclosures import match_disclosures
from bbhunter.models import Finding, FindingStatus, TestType


def _f(title, vuln_class):
    return Finding(id=f"x:{title}", program_key="hackerone:t", asset="t.example.com", title=title,
                   vuln_class=vuln_class, test_type=TestType.ACTIVE_LOW_IMPACT, evidence="e",
                   status=FindingStatus.CANDIDATE)


def test_match_flags_same_vuln_class():
    findings = [_f("Some IDOR on orders", "idor-candidate")]
    disclosures = [{"title": "Unrelated title entirely", "vuln_class": "idor-candidate"}]
    flagged = match_disclosures(findings, disclosures)
    assert len(flagged) == 1 and "same vuln_class" in flagged[0][1]


def test_match_flags_high_title_overlap():
    findings = [_f("Exposed Grafana admin dashboard", "exposure")]
    disclosures = [{"title": "Exposed Grafana admin dashboard without auth", "vuln_class": ""}]
    flagged = match_disclosures(findings, disclosures)
    assert len(flagged) == 1 and "overlap" in flagged[0][1]


def test_no_match_for_unrelated_finding():
    findings = [_f("CORS misconfiguration on api", "cors")]
    disclosures = [{"title": "SQL injection in login", "vuln_class": "sqli"}]
    assert match_disclosures(findings, disclosures) == []
