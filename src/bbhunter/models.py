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
    AI_SAFETY_PROBE = "ai_safety_probe"    # single-prompt-per-check probes against an in-scope AI/LLM product endpoint
                                            # (prompt injection, system-prompt leakage, sensitive-info disclosure,
                                            # excessive agency) -- see testing/ai_safety.py. Unlike every other
                                            # TestType, this has no passive-floor equivalent: an API call to a model
                                            # is inherently an active request, so permits() never allows it for free.
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
    # Some programs mandate a specific User-Agent or extra request header so
    # they can identify (and not block/alert on) legitimate researcher
    # traffic. When set, any live request to this program's assets MUST use
    # it. Currently only populated by the Intigriti connector, which
    # exposes these as structured fields.
    required_user_agent: str | None = None
    required_request_header: str | None = None
    requires_authorization_request: bool = False
    confidence: str = "low"  # low | medium | high -- the derive_rules() heuristic can only ever
                             # produce "low"/"medium"; "high" is set exclusively by review_rules()
                             # after an actual human decision, never by automation. See permits().
    raw_notes: str | None = None

    # Set only by the explicit human review step (cli.py `review-rules` / `approve-active`),
    # never by rules_engine.derive_rules(). This is the third approval gate: a program's rules
    # can look permissive to the heuristic, but nothing beyond the passive floor runs until a
    # human has actually read the policy and recorded that decision here.
    human_reviewed: bool = False
    reviewed_at: datetime | None = None
    review_notes: str | None = None

    def permits(self, test_type: TestType) -> bool:
        # The floor: never touches the target beyond a single already-made fingerprint request
        # (subdomain enum and CVE keyword search both just query third-party databases), so this
        # never requires review.
        if test_type in (TestType.PASSIVE_RECON, TestType.VERSION_CVE_MATCH):
            return True
        if not self.human_reviewed or self.confidence != "high":
            return False
        if self.automated_scanners_allowed is False:
            return False  # hard interlock: an explicit "no automated tools" always wins
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
    REPORT_REJECTED = "report_rejected"
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
    severity: str | None = None  # none|low|medium|high|critical -- set by you at draft-report time
    poc_path: str | None = None
    report_path: str | None = None
    status: FindingStatus = FindingStatus.CANDIDATE
    created_at: datetime = Field(default_factory=datetime.utcnow)
    notes: str | None = None


class ReconResult(BaseModel):
    """Raw passive-recon output for one program. Not a Finding -- just
    what was observed. CVE-keyword matches derived from it become
    separate Finding(test_type=VERSION_CVE_MATCH) rows for review."""

    program_key: str
    subdomains: dict[str, list[str]] = Field(default_factory=dict)   # seed host -> discovered subdomains (merged crt.sh + subfinder + wayback)
    fingerprints: dict[str, dict] = Field(default_factory=dict)      # host -> {status_code, server, powered_by, final_url, tech (optional, from projectdiscovery httpx)}
    crtsh_failures: list[str] = Field(default_factory=list)          # seed hosts whose crt.sh query errored (not: found nothing)
    subfinder_failures: list[str] = Field(default_factory=list)      # seed hosts where the subfinder binary was missing or errored
    wayback_failures: list[str] = Field(default_factory=list)        # seed hosts whose archive.org CDX query errored
    param_urls: dict[str, list[str]] = Field(default_factory=dict)   # seed host -> historic URLs (with query strings) found via Wayback CDX,
                                                                      # the input set for testing/active.py's opt-in injection-signature checks
    seeds_total: int = 0                                             # how many seed assets this run was scoped to cover
    seeds_processed: int = 0                                         # how many it actually got through before finishing/stopping
    last_run: datetime = Field(default_factory=datetime.utcnow)

    @property
    def complete(self) -> bool:
        """False means a run was interrupted (Ctrl-C / SIGINT) partway
        through -- seeds_processed < seeds_total. Old rows from before
        this field existed default both to 0, which reads as complete
        (0/0) since there's no way to tell for them either way."""
        return self.seeds_processed >= self.seeds_total


class AIEndpointConfig(BaseModel):
    """How to send a prompt to one program's in-scope AI/LLM product
    endpoint and read back its text response. Every provider's API shape
    is different (OpenAI/Anthropic/Google/a custom chatbot all structure
    requests and responses differently), so this is deliberately generic
    rather than hardcoded to one provider: `request_template` is a JSON
    string with a `{{PROMPT}}` placeholder substituted (JSON-escaped) at
    call time, and `response_text_path` is a dot-separated path (numeric
    segments index into JSON arrays) into the parsed JSON response that
    resolves to the model's text reply.

    Never stores a real secret: `auth_env_var` names an environment
    variable to read the API key/token from at request time, so the
    config itself (persisted to the local state DB, gitignored, but
    still) never contains credential material."""

    program_key: str
    url: str
    method: str = "POST"
    headers: dict[str, str] = Field(default_factory=dict)  # static, non-secret headers, e.g. {"Content-Type": "application/json"}
    auth_header: str | None = None       # header name for the auth token, e.g. "Authorization"
    auth_env_var: str | None = None      # env var holding the raw token/key -- read at request time only, never persisted
    auth_template: str = "Bearer {token}"  # how to format the token into the header value; override for e.g. a raw API key header
    request_template: str                # JSON string containing a "{{PROMPT}}" placeholder
    response_text_path: str              # e.g. "choices.0.message.content"
    notes: str | None = None
