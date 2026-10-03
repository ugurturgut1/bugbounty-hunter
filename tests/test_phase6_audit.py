"""Phase 6: append-only audit log."""
from bbhunter import audit


def test_audit_append_read_filter_export(tmp_path, monkeypatch):
    f = tmp_path / "audit.jsonl"
    monkeypatch.setattr(audit, "AUDIT_FILE", f)

    audit.append_audit("hackerone:a", "active_low_impact", "IDOR check on 3 URL(s)")
    audit.append_audit("hackerone:b", "passive_recon", "recon 1 seed")
    audit.append_audit("hackerone:a", "active_low_impact", "takeover check on 5 host(s)")

    allr = audit.read_audit(path=f)
    assert len(allr) == 3
    assert [r["program_key"] for r in allr] == ["hackerone:a", "hackerone:b", "hackerone:a"]  # append order

    only_a = audit.read_audit("hackerone:a", path=f)
    assert len(only_a) == 2 and all(r["program_key"] == "hackerone:a" for r in only_a)

    md = audit.export_markdown("hackerone:a", path=f)
    assert "IDOR check on 3 URL(s)" in md and "takeover check on 5 host(s)" in md
    assert "recon 1 seed" not in md  # filtered out


def test_audit_append_is_appendonly(tmp_path, monkeypatch):
    f = tmp_path / "audit.jsonl"
    monkeypatch.setattr(audit, "AUDIT_FILE", f)
    audit.append_audit("hackerone:a", "x", "one")
    audit.append_audit("hackerone:a", "x", "two")
    # second write must not overwrite the first
    assert len(f.read_text().strip().splitlines()) == 2
