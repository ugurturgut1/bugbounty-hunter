---
name: bbhunter
description: Run the bug-bounty discovery/recon/PoC/report pipeline (~/bugbounty-hunter) semi-autonomously. Use when the user wants to sync programs, run recon, hunt for findings, or move a finding through PoC/report/submission for HackerOne, Bugcrowd, Intigriti, or YesWeHack.
---

# bbhunter

Drives the `bbhunter` CLI (`uv run bbhunter ...` from `~/bugbounty-hunter`)
through its pipeline: discover programs -> passive recon -> (optionally)
gated active testing -> PoC -> report -> submission. Read
`~/bugbounty-hunter/README.md` once at the start of a session if you
haven't already -- it documents the non-negotiable guardrails this skill
exists to enforce, not just describe.

**The whole point of this skill is that it does NOT skip the approval
gates just because it can run commands autonomously.** Every gate below
is a point where you stop and get the user's explicit, informed decision
in the chat -- not a formality to click through. Never invoke
`approve-active`, `approve-poc`, `approve-report`, or a non-`--manual`
`submit` on your own judgment. Those commands only ever run with an
argument the user just gave you in this conversation.

## 1. Sync + pick a target

```bash
cd ~/bugbounty-hunter
uv run bbhunter sync        # skip if the user says state is already fresh
uv run bbhunter list
```

Ask the user which program to work on if they haven't named one, or work
through `uv run bbhunter list` for programs with unreviewed rules and
in-scope assets if they say "find me something."

## 2. Passive recon -- no gate needed

Passive recon (`TestType.PASSIVE_RECON` / `VERSION_CVE_MATCH`) never
touches program infrastructure beyond one already-permitted fingerprint
request and third-party lookups (crt.sh, NVD). Run it freely:

```bash
uv run bbhunter recon <program-key>
uv run bbhunter findings --status candidate
```

Findings here are coarse CVE-keyword matches -- tell the user that
plainly, don't present them as confirmed.

## 3. Active testing -- GATE 1

Active testing (`bbhunter test-active`) sends live requests to the
program's own hosts. It is blocked by code
(`RulesOfEngagement.permits()`) until a human decision is on record, and
this skill must not make that decision:

1. Run `uv run bbhunter review-rules <program-key>` and show the user the
   raw policy text and heuristic read verbatim -- don't summarize away
   the actual policy language.
2. Ask the user, in chat, whether the policy actually permits automated
   active testing, and if so which `TestType`(s). If they say yes, run:
   ```bash
   uv run bbhunter approve-active <program-key> --test-type <type> --note "<the user's stated justification, citing the policy text>"
   ```
   The `--note` must reflect what the user actually said, not a
   generic phrase you invent.
3. Only then run `uv run bbhunter test-active <program-key>`.

If the user is ambiguous, unsure, or the policy is silent: do not
approve. Passive-only is always a safe default to fall back to.

## 4. PoC -- GATE 2

```bash
uv run bbhunter draft-poc <finding-id>
```

This writes a markdown file with the automation's evidence and TODOs for
reproduction steps/impact. Tell the user the file path and that they (or
you, working interactively with them watching) need to actually reproduce
the issue before it can be approved -- do not fill in the TODOs with
speculation and immediately approve. Once the user confirms they've
verified it:

```bash
uv run bbhunter approve-poc <finding-id> --note "<what was actually verified, and how>"
```

If it doesn't hold up: `uv run bbhunter reject-poc <finding-id> --note "<why>"`.

## 5. Report -- GATE 3

```bash
uv run bbhunter draft-report <finding-id> --severity <none|low|medium|high|critical>
```

Ask the user for the severity rather than guessing it yourself -- it
flows straight into the HackerOne submission payload if this ends up
automated. `draft-report` will refuse if the approved PoC still has
unfilled TODOs, which is a correctness check, not a bug -- if it fires,
go back to step 4. Show the user the full drafted report (especially the
"Suggested remediation" section, which always starts as a TODO) before
asking them to approve:

```bash
uv run bbhunter approve-report <finding-id> --note "<confirmation>"
```

## 6. Submit -- GATE 4, the last one

`uv run bbhunter submit <finding-id>` hard-refuses anything not in
`report_approved` state. Before running it for real:

- Tell the user explicitly which path it will take: automated HackerOne
  API call (`POST /hackers/reports`, only if `H1_API_USERNAME`/
  `H1_API_TOKEN` are set and the program is on HackerOne), or a
  `ManualSubmissionRequired` for every other platform.
- Get an explicit "yes, submit this now" from the user first -- this is
  an irreversible action against a real external company/platform, not
  a local file write. Treat it the same as any other risky, hard-to-reverse
  action you'd normally pause and confirm before taking.
- For manual platforms, once the user has actually pasted the report into
  the platform's UI themselves, record it:
  ```bash
  uv run bbhunter submit <finding-id> --manual --note "<how/where>"
  ```

## Reference

- `uv run bbhunter show <program-key>` / `show-finding <finding-id>` for
  full JSON detail.
- Data lives in `~/bugbounty-hunter/state/` (SQLite + PoC/report markdown
  files), gitignored -- nothing here is a git operation, so there's no
  commit/push gate to worry about on top of the ones above.
