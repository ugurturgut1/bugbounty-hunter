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
6. **The `--injection`, `--nuclei`, and `--cloud-buckets` flags on
   `test-active` are not a separate or higher permission tier.** All
   three still require `RulesOfEngagement.permits(TestType.ACTIVE_LOW_IMPACT)`,
   i.e. the same human-recorded `approve-active` decision as every other
   active check -- they only choose whether to *include* that request
   shape, they grant no new access on their own. All three stay within
   the "safe XSS/SQLi probes... no data modification" scope
   `TestType.ACTIVE_LOW_IMPACT` already defines in `models.py`:
   `--injection` sends at most one canary/signature per query parameter
   per class -- reflected-XSS, SQL-error, NoSQL-error, CRLF/header-
   injection, and a benign `echo`-only command-injection canary (no
   boolean/time-based blind techniques, no extraction, no follow-through
   past detection, no command beyond a no-op `echo`) -- plus one benign
   `echo`-only Shellshock (CVE-2014-6271) `User-Agent` probe per host,
   same no-follow-through rule -- `--nuclei` runs only
   misconfig/exposure/tech/cve/ssl/cache/cors/ssrf/jwt/graphql/takeover/
   ssti/xxe/host-header/prototype-pollution/redirect-tagged templates,
   with rce/sqli/dos/intrusive/fuzz/bruteforce/hijack/default-login/
   authentication-bypass tags explicitly excluded, rate-limited to 1
   req/s, and `--cloud-buckets` checks a small, fixed set of S3/GCS/
   Azure bucket-name variations derived only from the program's own
   in-scope domains (never an invented/unrelated name) for a publicly-
   listable bucket, every finding landing at "info" severity with an
   explicit ownership-verification caveat. None is ever turned on by the
   `/bbhunter` skill on its own judgment -- see its SKILL.md. See
   "Vulnerability class coverage" below for what this does and doesn't
   cover against OWASP Top 10 and
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
8. **`bbhunter test-mass-assignment` is the one check in the original narrow tier that sends a real,
   state-changing request** -- every check under `active_low_impact` is read-only by design; this was
   a deliberate, isolated exception when added, not a precedent to assume everything else should follow
   -- see Guardrail 9 for where a further exception was later added deliberately, not by drift. It
   requires its own `TestType.MASS_ASSIGNMENT_PROBE` approval (separate from `active_low_impact`, whose
   own definition explicitly says "no data modification"), its own explicit `--confirm-disposable` flag
   on top of that, and only ever attempts one field on one resource the user confirms they own/control.
   It captures a baseline first and attempts a best-effort revert, but that revert is never guaranteed
   -- read the finding's evidence for the actual outcome, every time.
9. **A separate, higher-risk tier exists, added 2026-09-20 at the user's explicit request, for tools
   this project previously kept out entirely: fuzzers, brute-forcers, and exploitation frameworks.**
   This is NOT a loosening of Guardrails 1-8 above -- every check in this tier still requires scope
   (`Program.in_scope`) and the base three approval gates exactly as before, PLUS its own dedicated
   `TestType` (`aggressive_discovery` / `sqli_exploitation` / `credential_testing` /
   `exploitation_framework`, never folded into `active_low_impact` or into each other), PLUS
   `approve-active --i-understand-the-risk` on top of the usual `--note` -- `cli.py`'s
   `_RISK_WARNINGS` prints a category-specific risk warning (what could go wrong, what to check in the
   actual policy text before approving) and the command refuses to record the approval without that
   flag. **The skill is never permitted to pass `--i-understand-the-risk` on its own judgment, same as
   every other approval in this project** -- it must be the user's own explicit decision, relayed
   verbatim, every time. Once approved for a program, each check runs to the depth described below --
   no further per-finding confirmation -- per the user's explicit instruction ("once I approve you can
   do everything abiding the rules I approved"), but every check keeps its own hard technical bound
   regardless of approval, never open-ended: `aggressive_discovery` (`bbhunter test-discovery`, `ffuf` +
   `arjun`) is high-volume but still capped/rate-limited, never DoS-adjacent; `sqli_exploitation`
   (`bbhunter test-sqli`, `sqlmap`) only extracts real data if `--dump` is separately passed, and even
   then caps at `SQLMAP_DUMP_ROW_LIMIT` (5) rows -- never a full dump; `credential_testing`
   (`bbhunter test-credentials`) only ever tests a small, explicit, user-supplied credential list
   (`MAX_CREDENTIALS_PER_RUN`, 10 pairs, enforced in code) -- never a wordlist/username-list brute
   force, and stops immediately on any lockout/rate-limit signal; `exploitation_framework`
   (`bbhunter test-exploit`, `commix`) only ever runs a single benign `echo <marker>` via `--os-cmd`,
   never `--os-shell`'s interactive/persistent shell, and its own finding evidence explicitly tells the
   user to stop and report rather than explore further. See `docs/EXTERNAL_RESOURCES.md` for the full
   reasoning on what got wired in here vs. what still deliberately hasn't.

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
      Subdomain enum now merges five sources -- crt.sh, Certspotter
      (`certspotter_subdomains`, a second independent CT-log source, see
      roadmap phase 15 below), archive.org's Wayback CDX API
      (`wayback_subdomains`, also never touches the target), and the
      optional `subfinder` and `assetfinder` binaries (`subfinder_subdomains`/
      `assetfinder_subdomains`, see roadmap phase 16 below) -- silently skipping
      whichever of these isn't installed/reachable/rate-limited rather
      than failing the whole run. Discovered subdomains are then optionally
      filtered through the `dnsx` binary (`dnsx_resolve`, roadmap phase 16)
      to prioritize ones that actually still resolve before spending the
      fingerprinting budget on them. Wayback also surfaces historic
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

Assessed 2026-09-17, updated 2026-09-18 (twice -- see roadmap phases 1-7
below), against OWASP Top 10 2021 (the
current official web edition -- no ratified refresh exists yet, so
"2025"-named coverage below refers specifically to OWASP's own
separately-versioned LLM Top 10 2025 and API Security Top 10:2023, not a
web-edition refresh that doesn't exist), plus the vuln classes that
actually drive bug bounty payouts, which don't map 1:1 onto OWASP's
list. Kept here so coverage claims don't silently go stale as more gets
built -- update this table in the same commit as any check that changes
what it covers.

| Class | Coverage | How |
|---|---|---|
| A05 Security Misconfiguration | Good | exposed-file checks (now spanning ~25 self-hosted stacks/admin panels, see `_STACK_CHECKS`), missing-headers check (now incl. COOP/CORP), weak-but-present-CSP check, nuclei `misconfig`/`exposure` tags |
| A06 Vulnerable/Outdated Components | Good | NVD CVE-keyword match (version-range aware) + nuclei `cve` tag |
| CORS misconfiguration | Good | nuclei `cors` tag |
| Subdomain takeover | Good | nuclei `takeover` tag (HTTP-signature-based) + `recon/dns_hygiene.py`'s `check_dangling_cname` (DNS-level, catches a dead target even if it never responds to HTTP at all -- passive, always on) |
| JWT weaknesses | Good | nuclei `jwt` tag |
| GraphQL introspection | Good | nuclei `graphql` tag |
| SSTI / XXE | Good | nuclei `ssti`/`xxe` tags (signature-based, not blind) |
| Open redirect | Good | nuclei `redirect` tag |
| Host header injection | Good | nuclei `host-header` tag |
| Cache poisoning/deception | Good (added 2026-09-18) | nuclei `cache` tag -- generic + Next.js cache-poisoning detection templates |
| Prototype pollution | Thin | nuclei `prototype-pollution` tag -- template count is small upstream |
| A10 SSRF | Partial | nuclei `ssrf` tag (out-of-band/interactsh-based, detection only) |
| A03 Injection (XSS/SQLi/NoSQLi/command) | Partial (signature detection) + opt-in real confirmation | signature checks as before (`--injection`, 6 requests/param); SQLi now has an opt-in deeper tier, `bbhunter test-sqli` (`sqlmap`, `TestType.SQLI_EXPLOITATION`, its own risk-flagged approval) for real confirmation/bounded extraction past the signature probe -- see Guardrail 9 |
| CRLF injection / HTTP response splitting | Good (added 2026-09-20) | CRLF/header-injection canary probe, part of `--injection` -- see `docs/VULN_TECHNIQUE_NOTES.md` for manual follow-up once a candidate fires |
| RCE (Shellshock, CVE-2014-6271) | Good (added 2026-09-20) | benign `echo`-canary `User-Agent` probe, part of `--injection`, one per host -- no brute-forcing, no command beyond the no-op echo |
| RCE (real command-execution confirmation, other CVEs) | Opt-in, added 2026-09-20 | `bbhunter test-exploit` (`commix`, `TestType.EXPLOITATION_FRAMEWORK`, its own risk-flagged approval) -- single benign `--os-cmd echo` confirmation only, never `--os-shell` |
| Content discovery / hidden parameters | Opt-in, added 2026-09-20 | `bbhunter test-discovery` (`ffuf` + `arjun`, `TestType.AGGRESSIVE_DISCOVERY`, its own risk-flagged approval) -- high-volume, capped/rate-limited |
| A02 Cryptographic Failures | Good, up from Thin (2026-09-18) | `recon/passive.py`'s `tls_cert_info`/`tls_findings` (passive, always on: expired/soon-expiring, self-signed, weak SHA-1 signature, hostname not in SAN) + nuclei `ssl` tag (deprecated TLS versions, insecure cipher suites, cert revocation -- neither checked by the openssl-based passive check) |
| Email spoofing (SPF/DMARC/DKIM misconfig) | Good (heuristic), added 2026-09-18 | `recon/dns_hygiene.py` -- passive, always on. `check_dkim` only ever reports a positive signal (a weak key found at a common selector), never "missing", since a domain's real selector isn't discoverable |
| Secret/credential leakage (public JS, GitHub) | Good (heuristic), added 2026-09-18 | `recon/js_harvest.py` (passive, always on: hardcoded secrets + exposed source maps in linked JS) and `recon/github_dork.py` (passive, optional -- needs a free `GITHUB_API_TOKEN`) |
| Cloud storage bucket exposure (S3/GCS/Azure) | Good (heuristic), opt-in, added 2026-09-18 | `testing/cloud_storage.py`, `test-active --cloud-buckets` -- bucket names derived only from the program's own in-scope domains, findings always at "info" severity pending manual ownership verification |
| A01 Broken Access Control (IDOR) | Partial (manual-input-driven) | `testing/idor.py`, `bbhunter test-idor` -- needs a human-supplied resource URL + two real identities' credentials, see below |
| A07 Auth Failures | **Open-ended brute-forcing still Missing by design**; bounded credential testing opt-in, added 2026-09-20 | `bbhunter test-credentials` (`TestType.CREDENTIAL_TESTING`, its own risk-flagged approval) tests only a small, explicit, user-supplied credential list (capped at 10 pairs, enforced in code), never a wordlist/username-list brute force -- see Guardrail 9 |
| Business logic / race conditions | **Missing** | not generically automatable |
| API1:2023 Broken Object Level Authorization (BOLA) | Partial (manual-input-driven) | same mechanism as A01/IDOR above -- `bbhunter test-idor` |
| API5:2023 Broken Function Level Authorization (BFLA) | Partial (manual-input-driven) | `testing/idor.py`'s `check_bfla`, `bbhunter test-bfla` -- same mechanism pointed at an admin/privileged endpoint instead of a data object |
| API3:2023 Broken Object Property Level Auth -- excessive data exposure half | Good (heuristic) | `_scan_json_for_sensitive_fields` in `testing/active.py`, piggybacks on the existing `/` request, no extra cost |
| API3:2023 -- mass assignment half | Manual-input-driven, gated separately | `testing/mass_assignment.py`, `bbhunter test-mass-assignment` -- the one write-capable check in this project, see below |
| API4:2023 Unrestricted Resource Consumption | Thin (weak signal) | missing rate-limit-header check -- absence isn't proof of no rate limiting, reported at info severity only |
| API7:2023 SSRF | same as A10 SSRF above | nuclei `ssrf` tag |
| API8:2023 Security Misconfiguration | same as A05 above | |
| API9:2023 Improper Inventory Management | Good | `_API_INVENTORY_CHECKS` in `testing/active.py` -- exposed Swagger/OpenAPI specs, shadow v1/v2 version detection |
| API2 Broken Auth, API6 Unrestricted Sensitive Business Flows, API10 Unsafe Consumption of APIs | **Missing** | API2 excluded by design (same as A07); API6/API10 aren't generically automatable |
| LLM01 Prompt Injection, LLM02 Sensitive Info Disclosure, LLM06 Excessive Agency, LLM07 System Prompt Leakage (OWASP LLM Top 10 2025) | Good (heuristic) | `testing/ai_safety.py`, `bbhunter test-ai` -- see below |
| LLM01/LLM07 via multi-turn conversational escalation | Good (heuristic), opt-in | `check_multiturn_jailbreak`, `test-ai --multiturn` -- catches jailbreaks that succeed only via roleplay/rapport-building framing, not single-shot |
| LLM05 Improper Output Handling | Good (heuristic) | `check_improper_output_handling` -- tests only the model's half (does it echo active markup unescaped), not whether the surrounding app then renders it unsanitized |
| LLM08 Vector and Embedding Weaknesses | Good (heuristic), the blackbox-probable half only | `check_indirect_prompt_injection` -- simulates a poisoned RAG document/tool result carrying an embedded instruction; can't actually poison a real vector store or embedding pipeline, which is the rest of LLM08 |
| LLM09 Misinformation | Thin (heuristic) | `check_misinformation` -- narrow confident-fabrication-about-a-nonexistent-product test; real-world hallucination risk is far more subtle than this can detect, a clean result proves little |
| LLM03 Supply Chain, LLM04 Data/Model Poisoning | **Missing** | genuinely need dependency/build-pipeline or training-time access this project has no path to from a single HTTP endpoint |
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

**All four roadmap phases above were done as of 2026-09-17.** A second round, same day, is adding
OWASP API Security Top 10 2023 coverage and multi-turn LLM jailbreak-chain testing:

5. *(done 2026-09-17)* OWASP API Top 10 2023: BFLA (`check_bfla`/`test-bfla`, reusing the BOLA/IDOR
   access-diffing mechanism against admin/privileged endpoints instead of data objects), excessive
   data exposure (`_scan_json_for_sensitive_fields` in `testing/active.py` -- signature-only key-name
   match against a curated sensitive-field list, piggybacks on the `/` request every host already
   gets, so this adds zero extra requests), API inventory/shadow-version discovery
   (`_API_INVENTORY_CHECKS` -- exposed Swagger/OpenAPI specs, only strong-signature paths included, no
   bare version-guess paths with a weak signature), a weak/info-only rate-limit-header signal, and
   mass assignment (`testing/mass_assignment.py`, `bbhunter test-mass-assignment`) -- the one check in
   this whole project that sends a real state-changing request (one PATCH adding an unauthorized
   field, e.g. `isAdmin=true`, to a resource the user explicitly confirms they own via
   `--confirm-disposable`), gated by its own dedicated `TestType.MASS_ASSIGNMENT_PROBE` (not folded
   into `active_low_impact`, whose own definition says "no data modification") requiring a separate
   `approve-active --test-type mass_assignment_probe` decision. Captures the field's baseline value
   first and attempts a best-effort revert afterward, with the outcome always stated explicitly in the
   finding's evidence -- live end-to-end smoke-tested against a local mock mutable API (never a real
   target): confirmed the mutation, detection, and revert all worked, verified by checking the mock
   server's actual live state matched its original value after the run completed.
6. *(done 2026-09-17)* Multi-turn LLM jailbreak chains (`testing/ai_safety.py`'s
   `check_multiturn_jailbreak`/`send_conversation`, `test-ai --multiturn`): two fixed, pre-written
   3-turn scripts -- `roleplay-persona` (the classic "DAN" persona-jailbreak pattern, building up to
   the same marker-echo request the single-turn probe uses) and `gradual-system-prompt-probe`
   (rapport-building "I'm a developer debugging this" framing, building up to the same
   verbatim-instructions request). Only the FINAL turn's response is checked, against the same signal
   a single-turn probe would look for -- the point is testing whether conversational framing changes
   the outcome, not adding a new detection heuristic. Requires
   `AIEndpointConfig.conversation_template` (a separate, optional `{{MESSAGES}}`-templated config for
   stateless multi-turn chat APIs -- the OpenAI/Anthropic-style pattern of resending the full history
   each turn; stateful/server-side-conversation-ID APIs aren't supported), set via
   `ai-endpoint-set --conversation-template-file`; skipped with a clear note if not configured. Opt-in
   and off by default on `test-ai` since it costs up to 6 more requests than the base 4-probe run.
   12 new tests, plus a real end-to-end smoke test against a local mock multi-turn server scripted to
   resist the single-shot version of each probe but cave after conversational buildup: confirmed via
   the actual CLI that both single-turn probes correctly did NOT fire while both multi-turn scripts
   correctly DID -- the exact escalation-specific distinction this feature exists to catch.

7. *(done 2026-09-18)* Closed the remaining blackbox-probable gaps in the LLM Top 10 2025 and
   broadened tech-stack coverage, both explicitly requested to make active testing find more real
   things once the user approves it, not to loosen any approval gate:
   - `testing/ai_safety.py` gained 3 new single-turn probes, bringing `test-ai`'s base run from 4 to 7
     requests (13 with `--multiturn`): `check_improper_output_handling` (LLM05 -- does the model echo
     active markup, e.g. `<img onerror=...>`, completely unescaped when asked to repeat it verbatim;
     tests only the model's half, never claims the surrounding app renders it unsanitized),
     `check_indirect_prompt_injection` (LLM08 -- embeds a fake `[SYSTEM INSTRUCTION OVERRIDE]` inside a
     "document" the model is asked to summarize, checking whether it follows the embedded instruction
     instead of treating retrieved/third-party content as data -- the real mechanism behind indirect
     prompt injection against RAG/browsing/tool-use products, and the only black-box-reachable half of
     LLM08 since this project can't poison an actual vector store), and `check_misinformation` (LLM09,
     explicitly labeled Thin -- asks about a product proven not to exist and checks for confident
     fabrication vs. appropriate hedging; a much narrower test than real hallucination risk). LLM03/
     LLM04 stay Missing (need dependency/build-pipeline or training-time access, not reachable from an
     HTTP endpoint) and LLM10 stays excluded by design (would mean deliberately running up cost/
     resource usage against a real endpoint). 6 new tests.
   - `testing/active.py`'s `_STACK_CHECKS` grew from 9 to ~25 stacks: Django, Flask/Werkzeug (exposed
     debugger console -- RCE-adjacent if reachable, detection-only, no interaction with the console
     itself), Jenkins, Elasticsearch, Kibana, Grafana, Prometheus, Consul, Vault, RabbitMQ, Traefik,
     Nextcloud, Magento, Drupal, Joomla, Strapi, Solr, Jira, Confluence, plus two new Laravel checks
     (exposed Telescope debug panel, Ignition health-check). `_GENERIC_CHECKS` gained 4 stack-agnostic
     entries for small standalone apps commonly deployed alongside (not part of) a fingerprinted
     framework: `/metrics` (Prometheus-format), `/phpmyadmin/`, `/adminer.php`, `/v2/_catalog` (Docker
     Registry). Every new check is the same read-only, soft-404-gated, signature-matched GET this
     module already used -- no new request shape, no interaction beyond one GET per path. 8 new tests,
     including a regression guard that every `_STACK_CHECKS` key is actually reachable via
     `_detected_stacks`' substring match (catches a typo'd key that would otherwise silently never
     fire).
   - This is a curated, high-value set, not literally "every tech stack" -- deliberately left out
     stacks that don't fit this module's signature-match-on-a-known-path model without a much higher
     false-positive rate (e.g. bare "Go" as a tech-detect substring would false-positive-match "Google"
     on effectively every host) or that need protocol/port access this project (HTTP-only, in-scope-URL
     driven) doesn't have (e.g. Redis/Memcached/MongoDB's native protocols, Kubernetes' own API server
     rather than an app that happens to run on K8s).

**A third round, 2026-09-18 (user: "build all that's mentioned here in phases... don't stop until
all of its done"), covering both passive recon (no gate, always on) and active recon (opt-in flags,
same `permits(ACTIVE_LOW_IMPACT)` gate as everything else) -- 7 sub-phases, each committed and
pushed separately:**
8. *(done)* Passive TLS/cert posture (`recon/passive.py`'s `tls_cert_info`/`tls_findings`, one
   `openssl`-based handshake per fingerprinted host, same graceful-degradation pattern as subfinder/
   nuclei) + weak-CSP/COOP/CORP header checks in `testing/active.py`. Closed A02's "Thin" rating.
9. *(done)* Passive DNS hygiene (`recon/dns_hygiene.py`, new `dnspython` dependency): SPF/DMARC
   misconfig, a conservative DKIM check that only ever reports a positive signal, and dangling-CNAME
   detection wired in BEFORE the HTTP fingerprint attempt (a dangling target often never answers
   HTTP at all).
10. *(done)* Passive JS harvesting (`recon/js_harvest.py`): hardcoded secrets (new shared
    `bbhunter/secret_patterns.py`, used by this, `testing/ai_safety.py`, and phase 11 below),
    exposed source maps, and aggregated internal-API-path references in linked JS.
11. *(done)* Optional passive GitHub code-search dorking (`recon/github_dork.py`, new `GitHubCreds`/
    `GITHUB_API_TOKEN`): only ever reports a Finding when a real secret pattern matches a returned
    snippet, since "a repo mentions this domain" alone is far too common to be useful signal.
12. *(done)* `ssl`/`cache` nuclei tags added to `NUCLEI_TAGS` -- live-verified template-count impact
    (+48 net after exclusions) before committing.
13. *(done)* Opt-in S3/GCS/Azure cloud storage bucket exposure check (`testing/cloud_storage.py`,
    `test-active --cloud-buckets`) -- bucket names derived only from the program's own in-scope
    domains, findings always at "info" severity pending manual ownership verification, since a
    same-named bucket can legitimately belong to an unrelated third party.
14. *(done)* NoSQL-error-signature and benign-echo command-injection probes added to
    `_check_injection_signals` (`--injection`, now 5 requests/parameter instead of 3).
15. *(done 2026-09-20)* Two small additions drawn from three community resources the user asked to
    incorporate -- see `docs/EXTERNAL_RESOURCES.md` for the full mapping and why the rest of those
    resources stays a human reference rather than code: a second independent CT-log source,
    `certspotter_subdomains` (SSLMate's Certspotter API, same `(names, succeeded)` contract as
    `crtsh_subdomains`; its unauthenticated tier caps at 10 requests/hour, so it degrades gracefully
    like every other optional source rather than being a hard requirement), and a new
    `recon/well_known.py` for robots.txt `Disallow`-path disclosure (aggregated into one informational
    finding per host, same pattern as `js_harvest.py`'s internal-API-path aggregation) and RFC 9116
    security.txt presence (recorded for reference, never treated as a vulnerability). Both passive,
    always on, one GET (security.txt: up to two) per seed host. 12 new tests.
16. *(done 2026-09-20)* A second, deeper pass at the same three resources, per explicit follow-up
    request ("all functionality... both as cheatsheets and tips/tricks for the analysis that the tool
    does with AI help... and also all tools and useful technical things they provide"):
    - **New `docs/VULN_TECHNIQUE_NOTES.md`**: per-vuln-class manual-verification technique notes
      distilled from EdOverflow's bugbounty-cheatsheet per-class pages (XSS, SQLi, SSRF, CRLF, open
      redirect, XXE, RCE, LFI, CSV injection, SSTI, XSLT, crypto, content injection), explicitly scoped
      as GATE 2/3 (PoC review / report drafting) reference for the human+AI manual-verification step the
      `/bbhunter` skill already does -- not new automated capability. The skill now points here from its
      PoC step. The bulk of both payload-list resources is exploitation technique this project's
      guardrails deliberately keep out of automation (blind/boolean injection, brute-forcing,
      follow-through past detection) -- this file is where that knowledge legitimately lives instead:
      informing a human's manual next step once `bbhunter` has already surfaced a candidate.
    - **Two new narrow, benign, single-canary `--injection` probe classes** (`testing/active.py`), same
      six-requests-per-parameter/one-canary-per-class philosophy as the existing four: a CRLF/header-
      injection probe (`\r\n` + a canary header name appended to a parameter, flagged only if it comes
      back as a real response header) and a Shellshock/CVE-2014-6271 probe (`_check_shellshock`, a
      crafted `User-Agent` with a benign `echo <marker>` payload, one per selected host, flagged only if
      the marker echoes back). Both purely detection-only, no follow-through past the no-op `echo`/header
      check, both gated by the exact same `permits(ACTIVE_LOW_IMPACT)` + `--injection` opt-in as
      everything else in this class. 8 new tests.
    - **Two more optional external-tool recon sources** (`recon/passive.py`), same
      `_tool_path`/graceful-skip pattern as subfinder/httpx/nuclei: `assetfinder_subdomains`
      (tomnomnom's `assetfinder --subs-only`, a fifth independent passive subdomain source) and
      `dnsx_resolve` (projectdiscovery's `dnsx -silent`, filters discovered subdomains to ones that
      still resolve via public DNS queries before spending `max_subdomains_per_seed`'s fingerprinting
      budget on stale crt.sh/Wayback entries). 9 new tests.
    - Tools this pass deliberately did NOT wire in: the remainder of awesome-bugbounty-tools is
      overwhelmingly fuzzers, brute-forcers, and exploitation frameworks (ffuf/gobuster-style
      content-discovery fuzzing, Arjun/x8 parameter brute-forcing, sqlmap-style extraction, credential
      brute-forcing, commix-style exploitation) -- exactly the technique class Guardrails #2/#6 kept this
      project's active testing away from at the time. See roadmap phase 17 immediately below: the user
      explicitly asked for these too, on the condition that they personally flag and approve each
      category first -- not something this pass assumed on its own.

Phases 1-16 above all stayed within this project's guardrails as they existed at the time -- nothing in
those rounds created a new permission tier, lowered the bar for `approve-active`, or let any heuristic
self-authorize active testing. The user was explicit about this going in ("I will be the one
approving any active recon"): the goal was making the tool find more once a human has already said
yes for a specific program, not changing who gets to say yes.

17. *(done 2026-09-20)* Fuzzers/brute-forcers/exploitation frameworks, per the user's explicit follow-up
    request ("we should use fuzzers/brute-forcers/exploitation frameworks if allowed by the company
    which I will decide and you can flag for me before starting... I would like to automate that too" --
    and, on how far automation should go once approved: "once I approve you can do everything abiding
    the rules I approved"; and on the approval gate: "make sure to ask me and make me approve flagging
    potential issues for these tools"). See Guardrail 9 above for the full mechanism
    (`--i-understand-the-risk` + a dedicated `TestType` per category, never self-approved). Four new
    modules, each its own CLI command and its own `TestType`:
    - `testing/aggressive_discovery.py` (`bbhunter test-discovery`, `TestType.AGGRESSIVE_DISCOVERY`):
      `ffuf` content discovery + `arjun` hidden-parameter discovery, both optional binaries, same
      graceful-skip pattern as subfinder/nuclei/ffuf's siblings elsewhere in this project. Wordlist
      resolution (`resolve_wordlist`, added right after this phase, per a follow-up request): small
      built-in list by default, SecLists (github.com/danielmiessler/SecLists, cloned separately, see
      README Setup) if present, `--wordlist small|common|medium|large` shorthand or any explicit path
      to choose a specific SecLists list, `BBHUNTER_FFUF_WORDLIST`/`BBHUNTER_SECLISTS_DIR` env vars to
      override the defaults. `test-discovery` prints the resolved wordlist's real entry count and a
      request-count estimate before running, and the `aggressive_discovery` risk warning explains that
      request volume scales directly with wordlist size -- wordlist choice is flagged as part of the
      same risk-approval step as everything else in this tier, never a separate unflagged knob. 6 new
      tests.
    - `testing/sqli_exploit.py` (`bbhunter test-sqli`, `TestType.SQLI_EXPLOITATION`): `sqlmap --batch`
      at conservative `--risk 1 --level 1`, confirmation-only (DBMS banner + current-db name) by
      default; `--dump` is a second, separate opt-in flag that additionally extracts up to
      `SQLMAP_DUMP_ROW_LIMIT` (5) rows -- the finding's evidence reminds the user to delete extracted
      data after reporting.
    - `testing/credential_testing.py` (`bbhunter test-credentials`, `TestType.CREDENTIAL_TESTING`): a
      deliberately hand-written, bounded implementation rather than wrapping `hydra` -- tests only a
      small, explicit, user-supplied credential list (`MAX_CREDENTIALS_PER_RUN` = 10 pairs, enforced in
      code as a `ValueError`, not just documented), stops immediately on any lockout/rate-limit
      signature. This is intentionally narrower than open-ended wordlist brute-forcing, which the risk
      warning itself explains is one of the most commonly explicitly-prohibited bug-bounty techniques
      and risks locking out real users, not just testing the target.
    - `testing/exploit_framework.py` (`bbhunter test-exploit`, `TestType.EXPLOITATION_FRAMEWORK`):
      `commix --batch` restricted to a single `--os-cmd echo <marker>` confirmation, never
      `--os-shell`'s interactive/persistent shell -- proves real command execution without establishing
      or using any actual access beyond that one benign command.
    - 28 new tests across the four modules (mocked subprocess/HTTP throughout -- none of these tests
      shell out to a real binary or touch a real target). `docs/EXTERNAL_RESOURCES.md` updated to
      reflect what's now wired in vs. what still isn't (business-logic/race-condition testing, and
      anything genuinely destructive like `--os-shell` or an unbounded `--dump`, stay out on purpose).

Longer-term ideas not yet scoped into a phase: broader business-logic/race-condition testing (not
generically automatable, would need per-program custom logic), stateful (server-side conversation ID)
multi-turn AI APIs, and TLS/certificate weakness checks for A02.

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

## External references

`docs/EXTERNAL_RESOURCES.md` maps three community resources (a curated
tool list, a curated writeups archive, and a bug-bounty cheat sheet) onto
this project's own coverage table and guardrails -- what got adopted into
code (small, passive, single-request additions, see roadmap phase 15
below) versus what's kept as human reference for the phases this project
deliberately doesn't automate.

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
uv run bbhunter report <program-key>      # full audit trail: scope/approval status, everything
                                           # recon found, every check that's actually been run
                                           # (`test_runs`, including clean results), and findings
```

### Optional external recon tooling

`bbhunter recon` and `bbhunter test-active` work fully without any of
this -- crt.sh, Certspotter, archive.org, NVD, and the plain-GET checks
are pure Python/HTTP and always on. `dnspython` (SPF/DMARC/DKIM/
dangling-CNAME checks) is a regular pip dependency, already installed by
`uv sync`, nothing extra to set up. `openssl` (TLS cert posture checks)
is virtually always present on Linux/macOS already; both are skipped
silently, same as everything below, if genuinely absent. Installing
these Go binaries (four from [projectdiscovery](https://github.com/projectdiscovery),
one from [tomnomnom](https://github.com/tomnomnom)) widens coverage;
every integration point checks for the binary first and silently falls
back (or skips that source/flag) if it's missing:

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest  # extra passive subdomain source, merged with crt.sh + Certspotter + Wayback
go install github.com/tomnomnom/assetfinder@latest                        # fifth passive subdomain source (--subs-only), independent source list from subfinder
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest               # filters discovered subdomains to ones that actually resolve before fingerprinting
go install github.com/projectdiscovery/httpx/cmd/httpx@latest             # richer tech-stack fingerprinting than the built-in Server/X-Powered-By check
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest        # curated template scan, see Guardrails -- opt-in via `test-active --nuclei`
nuclei -update-templates
# go install puts binaries in `go env GOPATH`/bin (~/go/bin by default) --
# make sure that's on PATH (`export PATH="$HOME/go/bin:$PATH"`)
```

One more optional source, not a binary: `recon/github_dork.py`'s
passive GitHub code-search recon needs a free GitHub personal access
token (no scopes required) in `.env` as `GITHUB_API_TOKEN` -- see
`.env.example`. Skipped silently if absent, same as everything else here.

### Optional high-risk-tier tooling (Guardrail 9)

These four are only ever invoked by `test-discovery`/`test-sqli`/
`test-credentials`/`test-exploit`, and even then only after their own
`approve-active --i-understand-the-risk` decision on top of the usual
gates -- installing them changes nothing on its own. Same graceful-skip
behavior as everything above if not installed.

```bash
go install github.com/ffuf/ffuf/v2@latest      # content discovery, `bbhunter test-discovery`
pip install arjun                              # hidden-parameter discovery, `bbhunter test-discovery`
pip install sqlmap                             # SQLi confirmation/extraction, `bbhunter test-sqli`
pip install commix                             # command-execution confirmation, `bbhunter test-exploit`
```

`BBHUNTER_FFUF_WORDLIST` (env var, absolute path) overrides
`aggressive_discovery.py`'s small built-in wordlist with your own,
bigger one -- unset falls back to the built-in list, or to SecLists (see
below) if it's cloned.

**SecLists**, for `test-discovery --wordlist`: a much better set of
content-discovery wordlists than this project's own small built-in one.
Cloned as a plain git checkout, gitignored (`wordlists/` in
`.gitignore`) -- it's reference data, not something this project's own
git history should carry:

```bash
mkdir -p wordlists && git clone --depth 1 https://github.com/danielmiessler/SecLists.git wordlists/SecLists
```

`resolve_wordlist()` in `aggressive_discovery.py` looks for it at
`~/bugbounty-hunter/wordlists/SecLists` by default (override with
`BBHUNTER_SECLISTS_DIR`); if it's not there, `test-discovery` silently
falls back to the small built-in list, same graceful-skip behavior as
everything else optional in this project. Once cloned, pass
`--wordlist small|common|medium|large` (shorthand for
`Discovery/Web-Content/{common,raft-small,raft-medium,raft-large}-directories.txt`,
`common` being the default once SecLists is present) or any other
SecLists-relative/absolute path. **A bigger wordlist means proportionally
more requests** -- `test-discovery` prints the resolved wordlist's real
entry count and a request-count estimate before it starts; the
`aggressive_discovery` risk warning (`approve-active
--i-understand-the-risk`) says the same thing. Default to `common`
unless the program's policy is explicit about welcoming exhaustive
scanning.

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

# 2b. (further opt-in, only after its own separate risk-flagged approval -- see Guardrail 9)
uv run bbhunter approve-active <program-key> --test-type sqli_exploitation --i-understand-the-risk --note "..."
uv run bbhunter test-sqli <program-key> --url "https://target/search?q=1"   # add --dump to extract (capped) rows
# same pattern for: test-discovery (aggressive_discovery), test-credentials (credential_testing),
# test-exploit (exploitation_framework) -- each needs its own approve-active --test-type ... --i-understand-the-risk

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
