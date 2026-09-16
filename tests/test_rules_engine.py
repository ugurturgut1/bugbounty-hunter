"""These tests protect the single most safety-critical invariant in the
whole project: automation can never unlock active testing on its own.
Only a human calling approve-active (cli.py) can ever set confidence to
"high". If this regresses, bbhunter would start treating unreviewed
policies as permission to run active checks against real companies."""
from bbhunter.models import RulesOfEngagement, TestType
from bbhunter.rules_engine import derive_rules


def test_no_policy_text_defaults_to_passive_only():
    rules = derive_rules(None)
    assert rules.confidence == "low"
    assert rules.permits(TestType.PASSIVE_RECON)
    assert not rules.permits(TestType.ACTIVE_LOW_IMPACT)


def test_derive_rules_can_never_produce_high_confidence():
    # Even a policy stuffed with every "active allowed" signal we know
    # about must not reach "high" -- that requires a human decision.
    text = "Automated scanners are allowed. Automated testing is permitted. " * 10
    rules = derive_rules(text)
    assert rules.confidence != "high"
    assert not rules.permits(TestType.ACTIVE_LOW_IMPACT)


def test_disallow_signal_blocks_active_even_with_allow_signal_present():
    text = (
        "Automated scanners are allowed for most endpoints, however "
        "please do not use automated tools against payment infrastructure. " * 5
    )
    rules = derive_rules(text)
    assert rules.automated_scanners_allowed is False
    assert TestType.ACTIVE_LOW_IMPACT not in rules.allowed_test_types


def test_passive_and_cve_match_always_permitted_regardless_of_confidence():
    rules = RulesOfEngagement(confidence="low")
    assert rules.permits(TestType.PASSIVE_RECON)
    assert rules.permits(TestType.VERSION_CVE_MATCH)


def test_high_confidence_without_human_review_still_blocks_active():
    # Guards against a future bug where someone sets confidence="high"
    # directly without going through the human review flag.
    rules = RulesOfEngagement(
        confidence="high",
        human_reviewed=False,
        allowed_test_types={TestType.PASSIVE_RECON, TestType.ACTIVE_LOW_IMPACT},
    )
    assert not rules.permits(TestType.ACTIVE_LOW_IMPACT)


def test_approved_active_type_is_permitted():
    rules = RulesOfEngagement(
        confidence="high",
        human_reviewed=True,
        automated_scanners_allowed=True,
        allowed_test_types={TestType.PASSIVE_RECON, TestType.ACTIVE_LOW_IMPACT},
    )
    assert rules.permits(TestType.ACTIVE_LOW_IMPACT)
    assert not rules.permits(TestType.ACTIVE_INTRUSIVE)


def test_automated_scanners_disallowed_is_a_hard_interlock():
    # Even with human_reviewed + confidence=high + the type explicitly in
    # allowed_test_types, an explicit "no automated tools" must still win.
    rules = RulesOfEngagement(
        confidence="high",
        human_reviewed=True,
        automated_scanners_allowed=False,
        allowed_test_types={TestType.PASSIVE_RECON, TestType.ACTIVE_LOW_IMPACT},
    )
    assert not rules.permits(TestType.ACTIVE_LOW_IMPACT)
