# bbhunter

Personal pipeline: discover bug bounty programs -> respect each program's
scope and rules -> recon -> find vulnerabilities -> draft PoC -> **you
review and approve** -> draft report -> **you review and approve** ->
submit.

## Guardrails (non-negotiable, read before extending anything)

1. **Only ever test assets explicitly listed as in-scope** by a program's
   own published policy. `Program.in_scope` / `out_of_scope` from
   `structured_scopes` is the source of truth, not guessing from a domain
   name.
2. **Default to passive-only.** `RulesOfEngagement.confidence` must be
   `"high"` before any active test type is permitted, and even then only
   the specific `TestType`s the policy actually allows
   (`RulesOfEngagement.permits()`). Silence in a policy is not
   permission. See `rules_engine.py`. `confidence="high"` is not
   something the heuristic can produce on its own -- it is set exclusively
   by a human running `bbhunter review-rules` + `bbhunter approve-active`
   (see `cli.py`), a third approval gate in front of any active testing.
3. **Two human approval gates, always**: PoC review, and separately,
   final-report-before-submission review. Nothing calls a platform's
   "submit report" endpoint without an explicit approved status on the
   `Finding`. This is enforced by workflow state (`FindingStatus`), not
   just convention -- when the submission phase is built, it must refuse
   to submit anything not in `REPORT_APPROVED` state.
4. **Rate limits and testing-hours notes from a policy are hard
   constraints** on the recon/testing phase, not suggestions.
5. Never automate against a program that requires prior written
   authorization (`requires_authorization_request`) until that
   authorization has actually been granted and recorded.

## Status

**Phase 1 (this commit): program discovery + scope/rules normalization.**
No recon, testing, PoC generation, or reporting yet -- those come after
Phase 1 is solid, since everything downstream depends on scope/rules
being right.

- [x] Data models (`models.py`): `Program`, `ScopeAsset`,
      `RulesOfEngagement`, `Finding`
- [x] Conservative policy-text -> rules heuristic (`rules_engine.py`)
- [x] SQLite state store (`state.py`)
- [x] HackerOne connector, built on HackerOne's official Hacker API
      (`discovery/hackerone.py`) -- live-tested and working.
- [x] Bugcrowd connector (`discovery/bugcrowd.py`), built against
      Bugcrowd's real OpenAPI spec, auth confirmed working. **Deprioritized**:
      the credential that worked turned out to be from a customer/org
      account (returns 0 programs -- wrong account type for discovery).
      A hacker/researcher account was created afterwards, but "API
      Credentials" generation in account settings appears to only be
      exposed to customer/org accounts, not individual researchers --
      the researcher account only has a username, no way to generate a
      password/token. Following programs on bugcrowd.com/engagements as
      a researcher doesn't help without an API credential to read them
      back with. The connector code is kept in case Bugcrowd changes
      this, but isn't expected to be usable for now.
- [x] Intigriti connector (`discovery/intigriti.py`), built against
      Intigriti's real OpenAPI spec, live-tested and working -- returns
      the full public program catalog directly, no following required.
      Uses Intigriti's own structured `safeHarbour` boolean and
      `rulesOfEngagement.description` text directly; their
      `testingRequirements.automatedTooling` integer field is recorded
      but deliberately never used to unlock active testing since its
      enum meaning isn't documented anywhere findable.
- [ ] YesWeHack connector -- skipped for now per user request
- [x] Phase 2 MVP: passive recon (`recon/passive.py`, `bbhunter recon <key>`).
      Certificate-transparency subdomain enum (crt.sh, never touches the
      target) -> capped/rate-limited fingerprinting (one GET per host,
      max 25 discovered subdomains per seed asset, self-identifying
      User-Agent, honors a program's required User-Agent/header if the
      connector captured one) -> NVD keyword CVE search, but **only**
      when a banner has an actual version number. Live-tested: an
      unversioned "Server: Apache" banner was initially keyword-matched
      against meaningless 1999-era CVEs by NVD's search -- fixed to
      require a `Product/x.y.z`-shaped banner before searching at all.
      Findings land as `Finding(status=CANDIDATE)`, explicitly labeled
      as coarse keyword matches needing manual verification, not
      confirmed vulnerabilities.
      Not yet built: Wayback/URL-history passive source, a broader
      fingerprint signature set (currently just Server/X-Powered-By
      headers).
- [x] Phase 3: gated active testing (`testing/active.py`,
      `bbhunter test-active`). A third, explicit approval gate sits in
      front of this: `RulesOfEngagement.confidence` can now only reach
      `"high"` via a human running `bbhunter review-rules` (prints the
      raw policy text + heuristic read, changes nothing) followed by
      `bbhunter approve-active --test-type ... --note "..."` (records
      the decision with a timestamp and the policy language that
      justified it). The heuristic in `rules_engine.py` is structurally
      incapable of setting `confidence="high"` itself. Even once
      approved, `automated_scanners_allowed is False` is a hard
      interlock that overrides everything else. The checks themselves
      are deliberately narrow: single rate-limited GETs for known
      exposed-file/misconfig paths (`.git/config`, `.env`, backups,
      actuator endpoints, etc.) plus a missing-security-headers check --
      no injection payloads, no state-changing requests -- gated behind
      a soft-404 baseline probe so noisy "200 for everything" hosts
      don't produce false candidates.
- [ ] Phase 4: PoC drafting -> approval gate -> report drafting ->
      approval gate -> submission
- [ ] Later: package as a Claude Code skill for hands-off running with
      the two approval gates surfaced as prompts

## Why HackerOne/Bugcrowd/Intigriti/YesWeHack connectors use official APIs, not scraping

Every one of these platforms' public directory pages is a client-rendered
SPA (confirmed for HackerOne and Bugcrowd by fetching their program-listing
pages directly -- both return an app shell with the actual listing loaded
by a separate client-side call after JS executes; Bugcrowd's is a
session-authenticated internal endpoint, not something meant for
programmatic use). There's no stable unauthenticated JSON endpoint to
scrape on any of them. Each platform does offer an official API for
researchers with a free account, which is more robust, ToS-compliant, and
won't silently break. Bugcrowd and Intigriti's connectors were built by
fetching their real OpenAPI specs directly (`docs.bugcrowd.com` /
`api.intigriti.com`) rather than guessing endpoints, and both were
live-tested against real accounts.

## Setup

```bash
cd ~/bugbounty-hunter
uv sync
cp .env.example .env
# fill in whichever platform credentials you have -- see .env.example
# for what each platform needs and where to get it
uv run bbhunter sync
uv run bbhunter list
uv run bbhunter show hackerone:<handle>   # or bugcrowd:<code>, intigriti:<handle>
uv run bbhunter recon <program-key>       # passive only, always allowed

# active testing requires an explicit human decision recorded first:
uv run bbhunter review-rules <program-key>
uv run bbhunter approve-active <program-key> --test-type active_low_impact --note "policy explicitly allows automated scanners, see section 3"
uv run bbhunter test-active <program-key>

uv run bbhunter findings
```
