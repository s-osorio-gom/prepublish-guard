"""0.1.1: dataset columns of example or allowed e-mail domains are not personal data, and an accepted column
finding no longer hides new personal values in the same table. Every value is fabricated."""

from test_release_review import new_repo

from prepublish_guard.config import Config
from prepublish_guard.detectors import scan_file_level
from prepublish_guard.scanner import full_scan

PERSONAL = "ana.ruiz" + "@" + "gmail.com"
COMPANY = "ventas" + "@" + "acme-co.com"


def columns(text: str, allowed: set[str] | None = None) -> list[str]:
    return [h.value for h in scan_file_level("data/users.csv", text, allowed) if h.rule == "pii_column"]


def test_example_domain_e_mails_are_not_a_personal_column():
    assert columns("id,email\n1,ana@example.com\n2,luis@example.org\n3,team@test.com\n") == []
    assert columns(f"id,email\n1,ana@example.com\n2,{PERSONAL}\n") == ["email"]


def test_allowed_email_domains_apply_to_dataset_columns(tmp_path):
    assert columns(f"id,email\n1,{COMPANY}\n") == ["email"]
    assert columns(f"id,email\n1,{COMPANY}\n", {"acme-co.com"}) == []
    repo = new_repo(tmp_path, {"data/users.csv": f"id,email\n1,{COMPANY}\n2,{COMPANY.replace('ventas', 'soporte')}\n"})
    assert full_scan(repo, Config(), history=True).findings != []
    assert full_scan(repo, Config(allowed_email_domains=["acme-co.com"]), history=True).findings == []


def test_numeric_columns_still_count():
    assert columns("nombre,cedula\nAna,10" + "23456781\n") == ["cedula"]


def test_accepted_column_finding_does_not_hide_new_personal_values(tmp_path):
    repo = new_repo(tmp_path, {"data/users.csv": f"id,email\n1,{PERSONAL}\n"})
    first = full_scan(repo, Config(), history=True)
    column = [f for f in first.findings if f.rule == "pii_column"]
    assert len(column) == 1
    assert not [f for f in first.findings if f.rule == "email_address"]       # covered by the column finding
    accepted = full_scan(repo, Config(ignore={column[0].fingerprint}), history=True)
    assert {f.rule for f in accepted.findings} == {"email_address"}
