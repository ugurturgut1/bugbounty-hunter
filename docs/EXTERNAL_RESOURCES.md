# External references

Three community resources the user asked to incorporate, mapped onto this
project's own guardrails and "Vulnerability class coverage" table
(README.md) rather than pasted in wholesale. This project's guardrails
deliberately keep automated active testing narrow (see README.md
"Guardrails") -- most of what these three resources catalog is exploitation
tooling and payload technique this project intentionally does not automate.
So the mapping below is split into what was actually adopted into code
(small, and in the same "safe, read-only, single-request" style as
everything else here) versus what stays a human reference for the phases
this project can't or deliberately won't automate.

- **[awesome-bugbounty-tools](https://github.com/vavkamil/awesome-bugbounty-tools)**
  (vavkamil) -- a large categorized list of standalone tools, from
  subdomain enumeration through exploitation-class scanners.
- **[Awesome-Bugbounty-Writeups](https://github.com/devanshbatham/Awesome-Bugbounty-Writeups)**
  (devanshbatham) -- hundreds of real disclosed-bug writeups, categorized
  by vulnerability class.
- **[bugbounty-cheatsheet](https://github.com/EdOverflow/bugbounty-cheatsheet)**
  (EdOverflow) -- short cheat sheets per vuln class plus a recon notes
  page; EdOverflow is also the author of RFC 9116 (security.txt).

Also see `docs/VULN_TECHNIQUE_NOTES.md` -- per-vuln-class manual-
verification technique distilled from bugbounty-cheatsheet's per-class
pages, for GATE 2/3 of the `/bbhunter` skill's pipeline (PoC review and
report drafting), not new automated capability.

## Adopted into code

Passive additions (`TestType.PASSIVE_RECON`, always on, no approval
gate), each a single GET/DNS query (or two, for security.txt's fallback
path) per host -- same request class this project already uses
everywhere in `recon/passive.py`:

1. **Certspotter as a second CT-log source** (`certspotter_subdomains`),
   from bugbounty-cheatsheet's `recon.md` recon notes. crt.sh can
   rate-limit or time out; a second independent CT log is cheap
   redundancy. Its unauthenticated tier is capped at 10 requests/hour
   (confirmed live via its own `x-ratelimit-limit` header), so on a
   program with many seeds it runs out mid-run -- handled the same as
   every other optional source here, `succeeded=False` and move on,
   never a hard failure.
2. **robots.txt / security.txt disclosure** (new `recon/well_known.py`),
   from the same recon notes and from RFC 9116 itself. `Disallow` paths
   are aggregated into one informational finding per host (a path being
   disallowed doesn't mean it's protected -- worth a human look);
   security.txt is recorded purely as reference (correct disclosure
   contact) for report drafting, never treated as a vulnerability.
3. **assetfinder as a fifth passive subdomain source**
   (`assetfinder_subdomains`, awesome-bugbounty-tools § Recon →
   Subdomain Enumeration), `--subs-only` to never pull in an unrelated
   "related root domain" outside scope.
4. **dnsx-based resolution filtering** (`dnsx_resolve`,
   awesome-bugbounty-tools § Recon → Subdomain Enumeration), public DNS
   queries only, used to prioritize the `max_subdomains_per_seed`
   fingerprinting budget on subdomains that still actually resolve.

Opt-in active additions (`TestType.ACTIVE_LOW_IMPACT`, still gated by
`approve-active`, part of `--injection`), same single-canary-per-class
philosophy as the checks already there:

5. **CRLF/header-injection probe** (`_check_injection_signals` in
   `testing/active.py`), from bugbounty-cheatsheet's `crlf.md`.
6. **Shellshock (CVE-2014-6271) probe** (`_check_shellshock`), from
   bugbounty-cheatsheet's `rce.md`, distilled into a benign-echo-only
   canary matching this project's existing command-injection probe
   philosophy exactly.

Nothing else from these three was pulled directly into automated code --
see the per-class mapping below for why.

## Per-class mapping (mirrors README's "Vulnerability class coverage" table)

For classes bbhunter already covers "Good", these are extra manual-
verification reading, not gaps. For classes marked Partial/Thin/Missing/
manual-input-driven, this is where a human should actually go.

| Class | bbhunter coverage | Manual toolbox (awesome-bugbounty-tools § ) | Further reading (Awesome-Bugbounty-Writeups) |
|---|---|---|---|
| Subdomain enum / recon | Good (crt.sh + Certspotter + subfinder + assetfinder + Wayback, dnsx-filtered) | Recon → Subdomain Enumeration, Content Discovery, Screenshots | -- |
| A03 Injection (XSS/SQLi/command) | Partial (single-request signature probes only) | Exploitation → XSS Injection, SQL Injection, Command Injection | Cross Site Scripting (XSS), SQL injection |
| CRLF injection / response splitting | Good (added 2026-09-20, `--injection`) | Exploitation → CRLF Injection | -- |
| RCE -- Shellshock (CVE-2014-6271) | Good (added 2026-09-20, `--injection`) | Exploitation → Command Injection | Remote Code Execution (RCE) |
| A01/API1 IDOR / BOLA | Partial, manual-input-driven | Exploitation → Insecure Direct Object References | Insecure Direct Object Reference (IDOR) |
| CORS misconfiguration | Good (nuclei `cors` tag) | Exploitation → CORS Misconfiguration | CORS Related issues |
| Subdomain takeover | Good (nuclei + dangling-CNAME) | Miscellaneous → Subdomain Takeover | Subdomain Takeover |
| A10/API7 SSRF | Partial (nuclei, detection-only) | Exploitation → Server Side Request Forgery | Server Side Request Forgery (SSRF) |
| Open redirect | Good (nuclei `redirect` tag) | Exploitation → Open Redirect | -- |
| XXE | Good (nuclei `xxe` tag, signature-based) | Exploitation → XXE Injection | -- |
| SSTI | Good (nuclei `ssti` tag, signature-based) | Exploitation → Template Injection | -- |
| LFI / path traversal | **Not automated** (any real traversal probe risks reading a file) | Exploitation → Directory Traversal, File Inclusion | Local File Inclusion (LFI) |
| CSV/formula injection | **Not automated** (client-side risk, not server-probable) | -- | -- |
| A07 Auth bypass / brute force | **Missing by design** (guardrail: no credential brute-forcing) | Exploitation → CSRF | Authentication Bypass, 2FA Related issues |
| Business logic / race conditions | **Missing** (not generically automatable) | Exploitation → Race Condition | Race Condition |
| Secret/credential leakage | Good (`js_harvest.py`, `github_dork.py`) | Recon → Links (LinkFinder-style JS scanners), Miscellaneous → Secrets, Git | -- |
| Cloud storage buckets | Good, opt-in (`testing/cloud_storage.py`) | Miscellaneous → Buckets | -- |
| JWT weaknesses | Good (nuclei `jwt` tag) | Miscellaneous → JSON Web Token | -- |
| GraphQL introspection | Good (nuclei `graphql` tag) | Exploitation → GraphQL Injection | -- |
| Clickjacking | Not covered | -- | Clickjacking (UI Redressing Attack) |
| RCE (post-exploitation, other than Shellshock) | **Out of scope by guardrail** (no follow-through past detection) | Exploitation → Insecure Deserialization, File Inclusion | Remote Code Execution (RCE) |

## Why the rest stays a human reference, not code

The bulk of awesome-bugbounty-tools (fuzzers, brute-forcers, exploitation
frameworks, WAF-evasion tooling) and of bugbounty-cheatsheet's per-class
pages (raw XSS/SQLi/SSTI payload lists) is exactly the class of technique
README.md's guardrails keep this project away from automating: no
boolean/time-based blind injection, no brute-forcing, no follow-through
past detection, no state-changing requests outside the one deliberate
`test-mass-assignment` exception. Those stay useful as a human's own
toolbox once `bbhunter` has flagged a candidate and the human is doing
manual verification/exploitation themselves -- which is also exactly when
Awesome-Bugbounty-Writeups' real examples are worth reading, and why this
file exists as reference material instead of another dependency.
