from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class Platform(StrEnum):
    HACKERONE = "hackerone"
    BUGCROWD = "bugcrowd"
    INTIGRITI = "intigriti"
    YESWEHACK = "yeswehack"


class AssetType(StrEnum):
    URL = "url"
    WILDCARD = "wildcard"
    IP_RANGE = "ip_range"
    MOBILE_APP = "mobile_app"
    SOURCE_CODE = "source_code"
    HARDWARE = "hardware"
    OTHER = "other"


class ScopeAsset(BaseModel):
    identifier: str
    asset_type: AssetType
    in_scope: bool
    eligible_for_bounty: bool | None = None
    max_severity: str | None = None
    instruction: str | None = None


class TestType(StrEnum):
    """Granularity the rules engine reasons about. Anything not explicitly
    confirmed as allowed is treated as NOT allowed."""

    PASSIVE_RECON = "passive_recon"        # subdomain enum, cert transparency, wayback, tech fingerprinting
    VERSION_CVE_MATCH = "version_cve_match"  # matching fingerprinted versions against known CVEs, no exploitation
    ACTIVE_LOW_IMPACT = "active_low_impact"  # e.g. safe XSS/SQLi probes, auth/config checks, no data modification
    ACTIVE_INTRUSIVE = "active_intrusive"    # anything that could degrade service, brute force, DoS-adjacent, automated scanners at volume
    SOCIAL_ENGINEERING = "social_engineering"
    PHYSICAL = "physical"


class RulesOfEngagement(BaseModel):
    """Structured, conservative read of a program's policy. `confidence`
    reflects how sure the parser is; anything below HIGH must be treated
    as passive-only regardless of what individual flags say."""

    allowed_test_types: set[TestType] = Field(default_factory=lambda: {TestType.PASSIVE_RECON})
    explicitly_disallowed_techniques: list[str] = Field(default_factory=list)
    automated_scanners_allowed: bool | None = None  # None = unknown -> treat as False
    rate_limit_notes: str | None = None
    testing_hours_notes: str | None = None
    safe_harbor: bool | None = None
    requires_authorization_request: bool = False
    confidence: str = "low"  # low | medium | high
    raw_notes: str | None = None

    def permits(self, test_type: TestType) -> bool:
        if self.confidence != "high":
            return test_type == TestType.PASSIVE_RECON
        return test_type in self.allowed_test_types


class Program(BaseModel):
    platform: Platform
    handle: str
    name: str
    url: str
    policy_url: str | None = None
    offers_bounties: bool = False
    in_scope: list[ScopeAsset] = Field(default_factory=list)
    out_of_scope: list[ScopeAsset] = Field(default_factory=list)
    rules: RulesOfEngagement = Field(default_factory=RulesOfEngagement)
    raw_policy_text: str | None = None
    last_synced: datetime = Field(default_factory=datetime.utcnow)

    @property
    def key(self) -> str:
        return f"{self.platform}:{self.handle}"


class FindingStatus(StrEnum):
    CANDIDATE = "candidate"           # automation thinks it found something
    POC_DRAFTED = "poc_drafted"       # PoC built, awaiting human review
    POC_APPROVED = "poc_approved"     # you approved the PoC
    POC_REJECTED = "poc_rejected"
    REPORT_DRAFTED = "report_drafted"       # report written, awaiting human review
    REPORT_APPROVED = "report_approved"     # you approved submission
    SUBMITTED = "submitted"
    RESOLVED = "resolved"
    DUPLICATE = "duplicate"
    INFORMATIVE = "informative"


class Finding(BaseModel):
    id: str
    program_key: str
    asset: str
    title: str
    vuln_class: str
    test_type: TestType
    evidence: str
    poc_path: str | None = None
    report_path: str | None = None
    status: FindingStatus = FindingStatus.CANDIDATE
    created_at: datetime = Field(default_factory=datetime.utcnow)
    notes: str | None = None
