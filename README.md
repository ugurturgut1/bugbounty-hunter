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
   permission. See `rules_engine.py`.
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
      (`discovery/hackerone.py`) -- needs a free H1 account + API token
- [ ] Bugcrowd / Intigriti / YesWeHack connectors -- stubbed, need
      accounts + API tokens to build against their real API responses
- [ ] Phase 2: passive recon (subdomain enum, tech fingerprinting,
      known-CVE version matching) gated per-program by `rules.permits()`
- [ ] Phase 3: active testing for programs where `confidence == "high"`
      and the specific technique is in `allowed_test_types`
- [ ] Phase 4: PoC drafting -> approval gate -> report drafting ->
      approval gate -> submission
- [ ] Later: package as a Claude Code skill for hands-off running with
      the two approval gates surfaced as prompts

## Why HackerOne/Bugcrowd/Intigriti/YesWeHack connectors use official APIs, not scraping

Every one of these platforms' public directory pages is a client-rendered
SPA (confirmed for HackerOne by fetching `/directory/programs` -- it
returns an empty app shell, all data loads via API calls the browser
makes after JS executes). There's no stable unauthenticated JSON
endpoint to scrape. Each platform does offer an official API for
researchers with a free account, which is more robust, ToS-compliant,
and won't silently break. You'll need to create free accounts and API
tokens for the platforms you want beyond HackerOne.

## Setup

```bash
cd ~/bugbounty-hunter
uv sync
cp .env.example .env
# fill in H1_API_USERNAME / H1_API_TOKEN in .env
uv run bbhunter sync
uv run bbhunter list
uv run bbhunter show hackerone:<handle>
```
