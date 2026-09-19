# Vulnerability technique notes (for AI-assisted manual analysis)

Distilled from EdOverflow's [bugbounty-cheatsheet](https://github.com/EdOverflow/bugbounty-cheatsheet)
per-class cheat sheets, mapped onto bbhunter's own mechanics. This is
reference material for **GATE 2 (PoC review) and GATE 3 (report drafting)**
in the `/bbhunter` skill's pipeline -- the human-and-AI manual-verification
steps that already happen after `bbhunter` has surfaced a `CANDIDATE`
finding, not a new automated capability. Nothing here should be turned
into a new automated request without going through this project's own
guardrails (see README.md) first: no boolean/time-based blind technique,
no extraction, no state-changing request, no follow-through past
detection.

Each section says what bbhunter already flags automatically for that
class, then what the AI should actually look at/try by hand once a human
has a candidate in front of them, plus where the exhaustive payload list
lives if more is needed. Read the relevant section before running
`bbhunter draft-poc` on a finding of that class.

## XSS

**bbhunter already flags:** `_check_injection_signals` (`--injection`)
sends one HTML-special-char canary per parameter and flags it only if it
comes back completely unescaped in the response.

**Manual next steps:** the canary firing only proves the characters
survive -- it says nothing about *context*. Fetch the actual response
and find exactly where the reflection landed:
- Inside an HTML attribute (`value="CANARY"`) -> breaking out needs a
  matching quote + a new attribute/tag, not a bare `<script>`.
- Inside a `<script>` block or JS string -> needs to close the string/
  break out of JS, not HTML-encode.
- Check the `Content-Security-Policy` header bbhunter's own hardening
  check already recorded (`weak-csp` finding, if any) -- a strict CSP
  can make a "reflected" canary practically unexploitable; note that in
  the PoC draft rather than overclaiming severity.
- If recon's fingerprint shows AngularJS < 1.6, a legacy sandbox-escape
  payload shape (`{{constructor.constructor('...')()}}`-style) is worth
  trying manually; AngularJS's own sandbox was removed entirely at 1.6+.
- Full historical WAF-bypass/polyglot payload catalog:
  [xss.md](https://github.com/EdOverflow/bugbounty-cheatsheet/blob/master/cheatsheets/xss.md)
  (treat entries there as dated -- verify each still applies before using it).

## SQL injection

**bbhunter already flags:** a single-quote probe per parameter,
signature-matched against a curated list of real DB error strings
(`_SQL_ERROR_SIGNATURES`), only when the signature is absent from the
unmutated baseline.

**Manual next steps:** which signature matched tells you the DB engine
(`ora-` prefixes -> Oracle, `pg_query`/`postgresql` -> Postgres,
`sqlstate`/`microsoft odbc` -> MSSQL, `mysql_fetch` -> MySQL,
`sqlite3.operationalerror` -> SQLite) -- confirm the engine before
drafting remediation advice, don't guess. This project deliberately
never goes further than the single-quote probe (no UNION-based
extraction, no boolean/time-based blind confirmation) -- if going
further is warranted, it's a manual, human decision within whatever the
program's policy actually permits, never something to script into
`bbhunter` itself.

## SSRF

**bbhunter already flags:** nuclei's `ssrf` tag templates, out-of-band
(interactsh) detection only -- confirms the target's server made an
outbound request, nothing more.

**Manual next steps:** once a real SSRF-capable parameter is confirmed,
common allow-list bypass shapes worth trying by hand (never scripted
here): alternate IP encodings for `127.0.0.1` (octal `0177.1`, hex
`0x7f.1`, decimal `2130706433`), IPv6 loopback (`[::1]`), and
wildcard-DNS services that resolve attacker-chosen hostnames to
attacker-chosen IPs for allow-list testing (`10.0.0.1.nip.io` ->
`10.0.0.1`). If a request lands, cloud metadata endpoints
(`169.254.169.254/latest/meta-data/`) are the highest-impact target on
AWS-hosted infra -- touching that endpoint on someone else's cloud
account needs the program's explicit scope to cover it; don't assume.

## CRLF / HTTP response splitting

**bbhunter already flags (new):** `_check_injection_signals`'s CRLF
probe appends a raw `\r\n` + a canary header name to a parameter and
checks whether it comes back as a real response header (not just
reflected text) -- detection-only, no Set-Cookie/response-splitting
payload is ever sent automatically.

**Manual next steps:** if the canary header lands, the encoding that
worked (raw `\r\n`, `%0d%0a`, double-encoded `%250d%250a`, or a
Unicode-normalization variant like `%E5%98%8A%E5%98%8D`) tells you which
layer is decoding it (browser front-end vs. app framework vs. reverse
proxy) -- that's usually the interesting part of the writeup, not the
injection itself. CRLF chained into response splitting can sometimes
escalate to reflected XSS by injecting a fake `Content-Type`/body after
the headers; that's a distinct, higher-effort manual exploitation step,
not something this project probes for automatically.

## Open redirect

**bbhunter already flags:** nuclei's `redirect` tag.

**Manual next steps:** if a redirect parameter exists but nuclei didn't
flag it, common bypass shapes for a same-origin-prefix filter: a
protocol-relative URL (`//evil.com`), a backslash instead of forward
slash (`/\evil.com`, `\/evil.com`), or embedding the real origin as
"credentials" in front of the attacker host
(`/\victim.com:80%40evil.com` parses as `evil.com` in some URL parsers
despite starting with `victim.com`). Worth checking the exact parameter
names a target actually uses (`url=`, `next=`, `redirect=`, `return=`,
`continue=`) against ones recon's Wayback param-URL list already
surfaced, rather than guessing blind.

## XXE

**bbhunter already flags:** nuclei's `xxe` tag (signature-based, not
blind).

**Manual next steps:** if an app genuinely parses attacker-supplied XML,
the three distinct impacts to separate in a report are file disclosure
(`SYSTEM "file:///etc/passwd"`), SSRF (`SYSTEM "https://..."`, same
caution as the SSRF section above), and blind/out-of-band exfiltration
via a parameter entity when the direct response doesn't echo the
parsed content. Never send a payload that would actually read a file
outside what the program's scope and this project's own guardrails
permit -- this stays a manual, human decision.

## RCE

**bbhunter already flags:** Flask/Werkzeug exposed-debugger detection
(`_STACK_CHECKS`, path/signature-based, no interaction with the console
itself) and, as of this round, a Shellshock (CVE-2014-6271) probe
(`_check_shellshock`, `--injection`) -- a crafted `User-Agent` with a
benign `echo <marker>` payload, flagged only if the marker echoes back.

**Manual next steps:** if the Werkzeug debugger console is reachable,
the PIN is deterministic but this project never brute-forces it
(guardrail: no credential/PIN brute-forcing) -- that's out of scope for
automation here, full stop, regardless of how "confirmable" it looks.
If Shellshock fires, the same benign-echo-only rule applies to any
further manual verification -- confirm via `echo`, never run a command
with real effect without the program's explicit go-ahead.

## LFI / path traversal

**Not automated by bbhunter** -- deliberately: any real path-traversal
probe beyond detecting a signature risks actually reading a file, which
this project's guardrails keep out of scope for automation. Manual
technique only: standard traversal-filter bypasses (`../\`, `..\/`,
`/%5c..`) are worth trying by hand once a file-path-shaped parameter is
identified from recon's Wayback param-URL list.

## CSV injection (formula injection)

**Not automated by bbhunter** -- this is inherently a client-side risk
(a victim later opens an exported CSV/XLSX in Excel/Sheets, which then
executes a formula), not something a passive/single-request probe can
detect server-side. Worth flagging manually wherever an app lets a user
control data that later gets exported to CSV/XLSX: a cell value starting
with `=`, `+`, `-`, or `@` is the classic trigger; note in the report
that exploitation requires the victim's own spreadsheet app, not the
server.

## Template injection (SSTI)

**bbhunter already flags:** nuclei's `ssti` tag (signature-based).

**Manual next steps:** a quick, low-risk manual confirmation once a
template-rendering parameter is suspected: submit an arithmetic
expression the specific template language would evaluate but plain text
wouldn't (Jinja2/Twig: `{{7*'7'}}` renders `7777777` in Jinja2, `49` in
Twig -- the *different* output between engines is itself the fingerprint
of which one is running) rather than jumping straight to a
code-execution payload.

## XSLT injection

**Not automated by bbhunter.** If an endpoint accepts attacker-supplied
XSLT, a read-only backend-info probe (`system-property('xsl:vendor')`)
is the safe first manual step -- confirms the processor without
attempting the `php:function('phpinfo')`-style follow-through some
processors allow, which is a data-exposure/RCE-adjacent escalation and
needs the program's explicit scope before going further.

## Crypto weaknesses

Not something bbhunter probes for (this project's own TLS-posture
checks in `recon/passive.py` cover certificate/cipher-suite weaknesses,
a different layer). Manually worth knowing about if an app's own design
surfaces one of these: hash-length-extension attacks against a
naively-constructed `Hash(secret || message)` MAC (an attacker who
knows `Hash(message1)` and `len(message1)` can compute a valid hash for
`message1 ∥ anything ∥ message2` without knowing the secret -- see the
[real HackerOne report](https://hackerone.com/reports/251572) linked
from the source cheatsheet), and legacy `$2a$` bcrypt's wraparound bug
on very long inputs. Neither is something to script an automated probe
for here -- both need app-specific context to even find the vulnerable
construction.

## Content injection

**Not automated by bbhunter** (and genuinely thin material upstream --
the source cheatsheet's own entry is a one-line joke). Worth a manual
look wherever user input lands unsanitized into a response body without
being interpretable as markup/script (so XSS checks don't already cover
it) -- e.g. injected into a PDF export, an email template, or a
third-party embed that renders raw text as-is.

## Recon services worth a manual look

Beyond bbhunter's own automated crt.sh/Certspotter/subfinder/
assetfinder/Wayback/GitHub-dork sources: `securityheaders.io` for a
second opinion on header hardening (bbhunter's own missing-header check
is narrower), `dnsdumpster.com` and `threatcrowd.org` for a different
angle on DNS/subdomain history, and Google's own CT log search
(`transparencyreport.google.com/https/certificates`) as a third
independent CT source when crt.sh and Certspotter both come back empty
or rate-limited. All manual/one-off lookups, not worth automating given
the overlap with sources already wired in.
