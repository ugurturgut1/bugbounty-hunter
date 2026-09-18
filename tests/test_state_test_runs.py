"""TestRun is the audit trail `bbhunter report` reads to show which checks
have actually run against a program, including clean ones that never
produce a Finding (a Finding alone can't answer "did we already check X"
for a check that found nothing)."""
import uuid

from bbhunter.models import TestRun, TestType
from bbhunter.state import list_test_runs, record_test_run


def test_record_and_list_test_runs_roundtrip(tmp_path):
    db_path = tmp_path / "state.db"
    run = TestRun(
        id=str(uuid.uuid4()),
        program_key="hackerone:testprogram",
        test_type=TestType.ACTIVE_LOW_IMPACT,
        findings_created=0,
        detail="exposed-file/misconfig scan",
    )
    record_test_run(run, db_path=db_path)

    runs = list_test_runs("hackerone:testprogram", db_path=db_path)
    assert len(runs) == 1
    assert runs[0].id == run.id
    assert runs[0].detail == "exposed-file/misconfig scan"
    assert runs[0].findings_created == 0


def test_list_test_runs_only_returns_matching_program(tmp_path):
    db_path = tmp_path / "state.db"
    record_test_run(TestRun(id="a", program_key="hackerone:one", test_type=TestType.PASSIVE_RECON), db_path=db_path)
    record_test_run(TestRun(id="b", program_key="hackerone:two", test_type=TestType.PASSIVE_RECON), db_path=db_path)

    runs = list_test_runs("hackerone:one", db_path=db_path)
    assert [r.id for r in runs] == ["a"]


def test_list_test_runs_ordered_chronologically(tmp_path):
    db_path = tmp_path / "state.db"
    from datetime import datetime, timedelta

    base = datetime(2026, 1, 1)
    record_test_run(TestRun(id="later", program_key="hackerone:one", test_type=TestType.PASSIVE_RECON, ran_at=base + timedelta(hours=1)), db_path=db_path)
    record_test_run(TestRun(id="earlier", program_key="hackerone:one", test_type=TestType.PASSIVE_RECON, ran_at=base), db_path=db_path)

    runs = list_test_runs("hackerone:one", db_path=db_path)
    assert [r.id for r in runs] == ["earlier", "later"]
