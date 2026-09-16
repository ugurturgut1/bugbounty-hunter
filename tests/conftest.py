import pytest

from bbhunter.models import Finding, FindingStatus, Platform, Program, TestType


@pytest.fixture
def program() -> Program:
    return Program(
        platform=Platform.HACKERONE,
        handle="testprogram",
        name="Test Program",
        url="https://hackerone.com/testprogram",
    )


@pytest.fixture
def candidate_finding(program: Program) -> Finding:
    return Finding(
        id=f"{program.key}:example.com:/.git/config",
        program_key=program.key,
        asset="example.com",
        title="Exposed .git/config",
        vuln_class="exposure",
        test_type=TestType.ACTIVE_LOW_IMPACT,
        evidence="GET https://example.com/.git/config -> HTTP 200.",
        status=FindingStatus.CANDIDATE,
    )
