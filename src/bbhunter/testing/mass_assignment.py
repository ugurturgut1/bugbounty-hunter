"""Opt-in mass assignment check (OWASP API3:2023 Broken Object Property
Level Authorization, write-capable half). This is the ONE check in the
whole project that sends a genuine state-changing request -- every other
check here is read-only by design, and that's a deliberate line, not an
oversight. Mass assignment is fundamentally impossible to test without
attempting a real write: there's no way to observe whether an API
accepts an unauthorized privileged field (e.g. "isAdmin": true) without
actually sending it and checking whether it stuck.

Because of that, this check has real preconditions the rest of this
project doesn't:
- It operates on exactly ONE resource the user explicitly confirms they
  own/control and are fine mutating (`bbhunter test-mass-assignment
  --confirm-disposable`) -- never a resource this tool picked itself.
- It attempts exactly ONE extra field per run, never a batch of guesses.
- It captures the field's baseline value first (or notes it didn't exist)
  so it can attempt a best-effort revert afterward -- clearly labeled as
  best-effort, not guaranteed. An API that accepts a privileged-field
  write might not behave predictably on the follow-up "undo" write
  either; the evidence always says explicitly whether the revert
  succeeded, failed, or wasn't possible, so a human knows whether manual
  cleanup is still needed.
- It's gated by its OWN TestType, `TestType.MASS_ASSIGNMENT_PROBE`, not
  folded into `ACTIVE_LOW_IMPACT` (whose own definition in models.py
  explicitly says "no data modification") -- it needs its own separate
  `approve-active --test-type mass_assignment_probe` decision on top of
  whatever else a program has already been approved for.
- It's invoked via its own explicit CLI command, never bundled into
  `test-active`'s default or opt-in flag set.
"""
from __future__ import annotations

import hashlib

import httpx

from bbhunter.models import Finding, FindingStatus, Program, TestType


def _get_json(url: str, headers: dict[str, str], *, timeout: float) -> tuple[int, dict | None]:
    try:
        resp = httpx.get(url, headers=headers, timeout=timeout, follow_redirects=True)
    except httpx.HTTPError:
        return 0, None
    try:
        data = resp.json()
    except ValueError:
        data = None
    return resp.status_code, (data if isinstance(data, dict) else None)


def _patch_json(url: str, headers: dict[str, str], body: dict, *, timeout: float) -> int:
    try:
        resp = httpx.patch(url, headers=headers, json=body, timeout=timeout, follow_redirects=True)
    except httpx.HTTPError:
        return 0
    return resp.status_code


def check_mass_assignment(
    url: str,
    owner_headers: dict[str, str],
    field_name: str,
    field_value,
    *,
    timeout: float = 15,
) -> dict | None:
    """Baseline GET -> one PATCH adding `{field_name: field_value}` ->
    confirm GET -> best-effort revert PATCH (+ confirm GET) if the field
    existed in the baseline. Returns a hit dict only if the field reads
    back as accepted/changed after the mutation; None on any failure,
    an outright-rejected mutation, or if the field simply didn't stick.
    Always describes the revert outcome in the evidence, whatever it
    was, so a human reading the finding knows whether manual cleanup is
    still needed."""
    baseline_status, baseline = _get_json(url, owner_headers, timeout=timeout)
    if baseline_status != 200 or baseline is None:
        return None  # can't establish a JSON baseline -- nothing to compare against, not a finding

    had_field_before = field_name in baseline
    original_value = baseline.get(field_name)

    mutate_status = _patch_json(url, owner_headers, {field_name: field_value}, timeout=timeout)
    if mutate_status not in (200, 201, 204):
        return None  # rejected outright -- not vulnerable via this exact attempt

    confirm_status, confirmed = _get_json(url, owner_headers, timeout=timeout)
    if confirm_status != 200 or confirmed is None:
        return None

    stuck = field_name in confirmed and confirmed[field_name] == field_value and (
        not had_field_before or original_value != field_value
    )
    if not stuck:
        return None

    if had_field_before:
        revert_status = _patch_json(url, owner_headers, {field_name: original_value}, timeout=timeout)
        if revert_status in (200, 201, 204):
            _, reverted = _get_json(url, owner_headers, timeout=timeout)
            if reverted is not None and reverted.get(field_name) == original_value:
                revert_note = "reverted back to its original baseline value successfully"
            else:
                revert_note = (
                    "the revert PATCH was accepted but the field didn't read back as the original "
                    "value afterward -- verify and clean up manually"
                )
        else:
            revert_note = f"the revert PATCH failed (HTTP {revert_status}) -- verify and clean up manually"
    else:
        revert_note = "the field did not exist in the baseline response, so no clean revert was possible -- verify and clean up manually"

    return {
        "kind": "mass-assignment-candidate",
        "severity": "high",
        "evidence": (
            f"PATCH {url} with body {{'{field_name}': {field_value!r}}}, sent as the owner identity, "
            f"was accepted (HTTP {mutate_status}), and a follow-up GET confirmed the field now reads "
            f"back as {field_value!r} (baseline: "
            f"{'had no such field' if not had_field_before else f'was {original_value!r}'}). "
            f"Revert: {revert_note}. Single mutation attempted -- no further follow-through."
        ),
    }


def run_mass_assignment_check(
    program: Program,
    url: str,
    owner_headers: dict[str, str],
    field_name: str,
    field_value,
    *,
    owner_note: str | None = None,
) -> list[Finding]:
    if not program.rules.permits(TestType.MASS_ASSIGNMENT_PROBE):
        raise RuntimeError(
            f"{program.key}: mass assignment check blocked by rules.permits() -- run `bbhunter review-rules` "
            "and `bbhunter approve-active --test-type mass_assignment_probe` first if this program's policy "
            "actually allows write-capable testing. This is a separate decision from active_low_impact."
        )

    hit = check_mass_assignment(url, owner_headers, field_name, field_value)
    if not hit:
        return []

    digest = hashlib.sha256(f"{url}:{field_name}".encode()).hexdigest()[:12]
    evidence = hit["evidence"]
    if owner_note:
        evidence = f"{evidence} Owner context: {owner_note}"
    return [
        Finding(
            id=f"{program.key}:massassign:{digest}",
            program_key=program.key,
            asset=url,
            title=f"Mass assignment candidate: unauthorized field '{field_name}' accepted",
            vuln_class=hit["kind"],
            test_type=TestType.MASS_ASSIGNMENT_PROBE,
            evidence=evidence,
            status=FindingStatus.CANDIDATE,
            notes=(
                f"severity guess: {hit['severity']} -- verify manually before drafting a PoC; this check "
                "performed a real write against the target, confirm the revert outcome above before moving on"
            ),
        )
    ]
