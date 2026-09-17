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
   `Finding`. This is enforced by workflow state (`FindingStatus`) in
   `reporting/submission.py`, not just convention -- `submit_report()` and
   `mark_submitted_manually()` both hard-refuse anything not in
   `REPORT_APPROVED` state.
4. **Rate limits and testing-hours notes from a policy are hard
   constraints** on the recon/testing phase, not suggestions.
5. Never automate against a program that requires prior written
   authorization (`requires_authorization_request`) until that
   authorization has actually been granted and recorded.
6. **The `--injection` and `--nuclei` flags on `test-active` are not a
   separate or higher permission tier.** Both still require
   `RulesOfEngagement.permits(TestType.ACTIVE_LOW_IMPACT)`, i.e. the same
   human-recorded `approve-active` decision as every other active check
   -- `--injection`/`--nuclei` only choose whether to *include* that
   request shape, they grant no new access on their own. Both stay
   within the "safe XSS/SQLi probes... no data modification" scope
   `TestType.ACTIVE_LOW_IMPACT` already defines in `models.py`:
   `--injection` sends at most one canary/signature per query parameter
   (no boolean/time-based blind techniques, no extraction, no follow-
   through past detection) and `--nuclei` runs only
   misconfig/exposure/tech/cve/cors/ssrf/jwt/graphql/takeover/ssti/xxe/
   host-header/prototype-pollution/redirect-tagged templates, with
   rce/sqli/dos/intrusive/fuzz/bruteforce/hijack/default-login/
   authentication-bypass tags explicitly excluded, rate-limited to 1
   req/s. Neither is ever turned on by the `/bbhunter` skill on its own
   judgment -- see its SKILL.md. See "Vulnerability class coverage"
   below for what this does and doesn't cover against OWASP Top 10 and
   common bug bounty vuln classes.
7. **AI/LLM safety probes (`bbhunter test-ai`) have no passive-floor
   exception.** Every other TestType has some request-free/always-allowed
   path (passive recon) or a low-cost fallback; a call to an AI model
   endpoint is inherently an active request and may cost the program real
   money per call, so `TestType.AI_SAFETY_PROBE` requires the same
   `approve-active` decision as any other active check with no exception
   at all. Each probe sends exactly one prompt and never asks the model
   to do anything with real-world impact -- see `testing/ai_safety.py`'s
   module docstring for what each of the 4 probes actually checks and why
   LLM10 (unbounded consumption) is deliberately never probed.

## Status

**All four phases + skill packaging are built:** program discovery ->
passive recon -> gated active testing -> PoC drafting -> report drafting
-> gated submission, driveable directly via `bbhunter` or through the
`/bbhunter` Claude Code skill.

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
      when a banner has an actual version number. Live-tested against
      real programs twice now, both times catching real false-positive
      classes: an unversioned "Server: Apache" banner was initially
      keyword-matched against meaningless 1999-era CVEs, and a bare
      major-version banner like "Undertow/1" (no dot at all) slipped
      past that first fix and still matched years of unrelated CVEs --
      the version regex now requires an actual "x.y" shape. Separately,
      a host running Apache 2.4.62 (the exact release that *fixes*
      CVE-2024-40725/40898) was still surfacing as a candidate for both,
      since NVD keyword search has no notion of version ranges --
      `_cve_applies_to_version` now checks the fingerprinted version
      against each CVE's own published affected-version data (exact
      versions or start/end range bounds) and suppresses a candidate
      only when every determinable entry rules it out; ambiguous or
      missing version data always stays permissive. `crtsh_subdomains`
      also now distinguishes "found nothing" from "the query itself
      failed" (`ReconResult.crtsh_failures`), surfaced as a CLI warning.
      Findings land as `Finding(status=CANDIDATE)`, explicitly labeled
      as coarse keyword matches needing manual verification, not
      confirmed vulnerabilities.
      Subdomain enum now merges three sources -- crt.sh, archive.org's
      Wayback CDX API (`wayback_subdomains`, also never touches the
      target), and the optional `subfinder` binary (`subfinder_subdomains`,
      itself just a fan-out over ~30 further passive OSINT sources) --
      silently skipping whichever of these isn't installed/reachable
      rather than failing the whole run. Wayback also surfaces historic
      URLs with query strings (`ReconResult.param_urls`), the input set
      for `test-active --injection` (see Phase 3). Fingerprinting now
      prefers the optional `httpx` binary's tech-detect signature
      database over the built-in Server/X-Powered-By-only check when
      it's installed (`fingerprint()` in `recon/passive.py`), falling
      back to the plain-GET check otherwise -- still exactly one request
      per host either way.
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
      don't produce false candidates. Host selection was originally
      just the exact seed hostnames from `program.in_scope`, silently
      ignoring everything `bbhunter recon` had already discovered --
      fixed so a `WILDCARD`-type seed asset also tests (a capped slice
      of) the subdomains recon found under it, since a plain `URL`-type
      entry doesn't license testing an unrelated sibling subdomain just
      because recon happened to find one.
      Two opt-in check classes were added on top, both still behind the
      exact same `permits(ACTIVE_LOW_IMPACT)` gate (see Guardrails #6):
      `--injection` (`_check_injection_signals`) sends one baseline
      request plus, per query parameter on a Wayback-discovered param
      URL, one reflected-XSS canary probe (an HTML-special-char marker,
      flagged only if it comes back unescaped) and one SQL-error-
      signature probe (a single trailing quote, flagged only if a DB
      error signature appears in the mutated response but not the
      baseline) -- never a boolean/time-based blind technique, never
      more than one marker per request. `--nuclei` (`run_nuclei_scan`)
      shells out to the optional `nuclei` binary restricted to
      misconfig/exposure/tech/cve/cors/ssrf/jwt/graphql/takeover/ssti/
      xxe/host-header/prototype-pollution/redirect-tagged templates,
      with rce/sqli/dos/intrusive/fuzz/bruteforce/hijack/default-login/
      authentication-bypass tags explicitly excluded via `-etags`,
      rate-limited to 1 req/s with a single connection (`-rate-limit 1
      -bulk-size 1 -c 1`) -- well below nuclei's own defaults, matching
      this module's existing pacing. Both are skipped/no-ops with a
      clear note if their prerequisites (param URLs from a prior
      `recon` run; the `nuclei` binary) aren't there. See
      "Vulnerability class coverage" below for what this set was
      chosen to close.
- [x] Phase 4: PoC drafting -> approval gate -> report drafting ->
      approval gate -> submission (`reporting/poc.py`,
      `reporting/report.py`, `reporting/submission.py`). `draft-poc`
      scaffolds a markdown template with the automation's evidence and
      explicit TODOs for reproduction steps/impact -- it never
      fabricates a reproduction narrative. `approve-poc` is the human
      gate confirming you personally reproduced it. `draft-report` then
      refuses to run unless status is `poc_approved`, and copies the
      Steps-to-reproduce/Impact sections verbatim out of the *approved*
      PoC file (rechecking they're not still TODO placeholders) so a
      report can never claim something the PoC review didn't already
      cover. `approve-report` is the second, separate human gate.
      `submit` then hard-refuses unless status is `report_approved`
      (guardrail #3, enforced in code, not just workflow convention).
      Only HackerOne has a submission endpoint automation can safely use
      (`POST /hackers/reports`, confirmed against api.hackerone.com);
      Bugcrowd's API is customer/org-only and Intigriti's researcher API
      is read-only with no submission endpoint (both checked directly
      against their specs 2026-09-16) -- every other platform requires
      `bbhunter submit --manual --note "..."` after you paste the report
      into that platform's own web UI yourself.
- [x] Packaged as a Claude Code skill (`.claude/skills/bbhunter/SKILL.md`)
      that drives the whole pipeline above, with the instruction that
      every approval gate (active-testing approval, PoC approval, report
      approval, submission) must be an explicit decision obtained from
      the user in that conversation -- the skill is not permitted to
      approve its own findings.

## Vulnerability class coverage

Assessed 2026-09-17 against OWASP Top 10 2021 (the current official web
edition -- no ratified refresh exists yet) and the vuln classes that
actually drive bug bounty payouts, which don't map 1:1 onto OWASP's
list. Kept here so coverage claims don't silently go stale as more gets
built -- update this table in the same commit as any check that changes
what it covers.

| Class | Coverage | How |
|---|---|---|
| A05 Security Misconfiguration | Good | exposed-file checks, missing-headers check, nuclei `misconfig`/`exposure` tags |
| A06 Vulnerable/Outdated Components | Good | NVD CVE-keyword match (version-range aware) + nuclei `cve` tag |
| CORS misconfiguration | Good | nuclei `cors` tag |
| Subdomain takeover | Good | nuclei `takeover` tag |
| JWT weaknesses | Good | nuclei `jwt` tag |
| GraphQL introspection | Good | nuclei `graphql` tag |
| SSTI / XXE | Good | nuclei `ssti`/`xxe` tags (signature-based, not blind) |
| Open redirect | Good | nuclei `redirect` tag |
| Host header injection | Good | nuclei `host-header` tag |
| Prototype pollution | Thin | nuclei `prototype-pollution` tag -- template count is small upstream |
| A10 SSRF | Partial | nuclei `ssrf` tag (out-of-band/interactsh-based, detection only) |
| A03 Injection (XSS/SQLi) | Partial | custom single-request reflected-XSS canary + SQL-error-signature checks (`--injection`); no SSTI/XXE beyond nuclei above, no command/LDAP/NoSQL injection |
| A02 Cryptographic Failures | Thin | HSTS presence only; no TLS/cert weakness testing |
| A01 Broken Access Control (IDOR) | Partial (manual-input-driven) | `testing/idor.py`, `bbhunter test-idor` -- needs a human-supplied resource URL + two real identities' credentials, see below |
| A07 Auth Failures | **Missing by design** | guardrails exclude credential brute-forcing/default-login entirely |
| Business logic / race conditions | **Missing** | not generically automatable |
| LLM01 Prompt Injection, LLM02 Sensitive Info Disclosure, LLM06 Excessive Agency, LLM07 System Prompt Leakage (OWASP LLM Top 10 2025) | Good (heuristic) | `testing/ai_safety.py`, `bbhunter test-ai` -- see below |
| LLM03 Supply Chain, LLM04 Data/Model Poisoning, LLM08 Embedding Weaknesses, LLM09 Misinformation | **Missing** | not meaningfully blackbox-probable with a single HTTP request |
| LLM10 Unbounded Consumption | **Missing by design** | would mean deliberately running up cost/resource usage against a real endpoint -- the AI-endpoint equivalent of the DoS testing excluded everywhere else in this project |

**Roadmap (phased, tracked here so it survives across sessions):**
1. *(done 2026-09-17)* Web gap-fill via curated nuclei tag expansion -- see table above.
2. *(done 2026-09-17)* Tech-stack-aware check routing for the exposed-file checks
   (`testing/active.py`'s `_detected_stacks`/`_STACK_CHECKS`): `_GENERIC_CHECKS` (`.git`, `.env`,
   AWS creds, `.svn`, docker-compose, SQL backups) still runs against every host, but
   framework-specific checks (WordPress config backups + user enumeration, PHP `phpinfo()`, Spring
   Boot actuator endpoints, Apache mod_status, Laravel logs, Node/Express `package.json`, Rails
   `database.yml`, ASP.NET `web.config`) now only fire against a host whose recon fingerprint
   (`ReconResult.fingerprints[host]["tech"/"server"/"powered_by"]`) actually matched that stack --
   substring match, case-insensitive, deliberately permissive (a false-positive match just costs a
   few extra narrow/soft-404-gated requests; a false negative silently skips a check that could have
   found something). A host with no fingerprint on file still gets the generic floor. `nuclei`'s own
   tag set wasn't narrowed the same way -- its templates already condition on the actual response
   content before matching, so per-host tag routing wouldn't reduce anything nuclei doesn't already
   skip internally.
3. *(done 2026-09-17)* LLM/AI red-team module (`testing/ai_safety.py`, `models.AIEndpointConfig`,
   `TestType.AI_SAFETY_PROBE`): for programs whose bounty scope explicitly covers an AI/LLM product
   endpoint. `bbhunter ai-endpoint-set <key> --url ... --request-template-file ... --response-path
   ...` configures how to send a prompt to that specific provider's API shape (deliberately generic
   -- a `{{PROMPT}}`-templated JSON request body plus a dot-path into the JSON response -- rather than
   hardcoded to one provider, so it works against OpenAI/Anthropic/Google/a custom chatbot alike; a
   real API key is read from an env var named via `--auth-env-var` at request time only, never
   persisted). `bbhunter test-ai <key>` then runs exactly 4 single-prompt probes: prompt-injection
   canary compliance (does the model echo a marker after being told to ignore its instructions?),
   system-prompt-leakage (does asking it to repeat its instructions produce something that reads like
   real system-prompt content?), sensitive-info-disclosure (does asking it to print any credentials
   in its context match a real secret-shaped pattern -- not just phrasing?), and excessive-agency
   (does asking it to execute an out-of-scope shell command produce something other than a refusal?).
   Gated by `permits(TestType.AI_SAFETY_PROBE)` -- same `approve-active` mechanism as every other
   active check, no new approval machinery, but this is the one TestType with no passive-floor
   exception at all, since a model API call is inherently active (and may cost real money per
   request, unlike a free HTTP request -- `test-ai` tells you this and runs exactly 4 requests, no
   more). 18 new tests, plus a real end-to-end smoke test against a local mock chat-completions
   server (never a real/paid API) confirming all 4 probes fire correctly against a deliberately
   vulnerable model and that the approval gate genuinely blocks an unapproved program via the CLI,
   not just in a unit test.
4. *(done 2026-09-17)* Authenticated-session-diffing for IDOR (`testing/idor.py`,
   `bbhunter test-idor`): unlike every other check here, IDOR is inherently app-specific -- there's
   no generic path/signature to scan for the way there is for an exposed `.env` file -- so this is
   deliberately manual-input-driven rather than automated discovery. `bbhunter test-idor <key> --url
   <resource-url> --owner-header "Authorization: Bearer <A>" --other-header "Authorization: Bearer
   <B>" --owner-note "..."` fetches the same URL once as its confirmed owner (the baseline -- if this
   itself fails or looks denied, there's nothing to conclude) and once as a second, unrelated
   identity: exactly two requests, no ID enumeration or guessing. Flags a candidate only if the
   second identity also gets a clean HTTP 200 (not a 401/403, not a body matching denial-signature
   phrases like "access denied"/"please log in") of similar size to the owner's response -- a
   meaningfully different size likely means a different/generic page (e.g. a login redirect), not
   the same resource actually being served. Gated by the same `permits(ACTIVE_LOW_IMPACT)` check as
   the rest of `testing/active.py` -- same class of "safe probes, no data modification", not a new
   tier. Both identities' credentials always come from whoever runs this, never invented, guessed, or
   brute-forced. 10 new tests, plus a real end-to-end smoke test against a local mock server with a
   deliberately IDOR-vulnerable endpoint, confirming the CLI correctly flags it.

**All four roadmap phases above are now done as of 2026-09-17.** Longer-term ideas not yet
scoped into a phase: broader business-logic/race-condition testing (not generically automatable, would
need per-program custom logic), a richer LLM probe set (e.g. multi-turn escalation -- deliberately out
of scope so far, since every probe here is single-request by design), and TLS/certificate weakness
checks for A02.

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
uv run bbhunter findings
```

### Optional external recon tooling

`bbhunter recon` and `bbhunter test-active` work fully without any of
this -- crt.sh, archive.org, NVD, and the plain-GET checks are pure
Python/HTTP and always on. Installing these three
[projectdiscovery](https://github.com/projectdiscovery) Go binaries
widens coverage; every integration point checks for the binary first
and silently falls back (or skips that source/flag) if it's missing:

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest  # extra passive subdomain source, merged with crt.sh + Wayback
go install github.com/projectdiscovery/httpx/cmd/httpx@latest             # richer tech-stack fingerprinting than the built-in Server/X-Powered-By check
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest        # curated template scan, see Guardrails -- opt-in via `test-active --nuclei`
nuclei -update-templates
# go install puts binaries in `go env GOPATH`/bin (~/go/bin by default) --
# make sure that's on PATH (`export PATH="$HOME/go/bin:$PATH"`)
```

## Full pipeline, one finding at a time

```bash
# 1. passive recon (always allowed) -> candidate findings
uv run bbhunter recon <program-key>

# 2. (only if you want active checks too) read the actual policy yourself,
#    then record your own decision -- nothing here is automatic
uv run bbhunter review-rules <program-key>
uv run bbhunter approve-active <program-key> --test-type active_low_impact --note "policy explicitly allows automated scanners, see section 3"
uv run bbhunter test-active <program-key>
# add --injection for single-request reflected-XSS/SQL-error-signature probes against
# Wayback-discovered param URLs, and/or --nuclei for a curated safe-tag nuclei scan --
# both still gated by the exact same approve-active decision above, see Guardrails
uv run bbhunter test-active <program-key> --injection --nuclei

uv run bbhunter findings --status candidate

# 3. PoC: scaffold -> you fill in + personally verify -> approve
uv run bbhunter draft-poc <finding-id>
# edit the markdown file it prints, then:
uv run bbhunter approve-poc <finding-id> --note "reproduced locally on <date>"

# 4. report: drafted from the approved PoC -> you review -> approve
uv run bbhunter draft-report <finding-id> --severity medium
# edit the remediation section, then:
uv run bbhunter approve-report <finding-id> --note "ready to send"

# 5. submit -- automated for HackerOne, manual everywhere else
uv run bbhunter submit <finding-id>
uv run bbhunter submit <finding-id> --manual --note "pasted into Intigriti UI by hand"
```
