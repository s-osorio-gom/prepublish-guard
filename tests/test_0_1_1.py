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


def test_accepted_column_is_reported_again_when_it_gains_a_value(tmp_path):
    repo = new_repo(tmp_path, {"data/users.csv": f"id,email\n1,{PERSONAL}\n"})
    first = full_scan(repo, Config(), history=True)
    column = [f for f in first.findings if f.rule == "pii_column"]
    assert len(column) == 1
    assert not [f for f in first.findings if f.rule == "email_address"]       # covered by the column finding
    accepted = Config(ignore={column[0].fingerprint})
    assert full_scan(repo, accepted).findings == []
    (repo / "data/users.csv").write_text(f"id,email\n1,{PERSONAL}\n2,{COMPANY}\n")
    assert [f.rule for f in full_scan(repo, accepted).findings] == ["pii_column"]


# Review of the 0.1.1 pull request (Codex): each case failed on the first version of the fix.

def test_baseline_of_a_table_stays_quiet_on_the_next_scan(tmp_path):
    from prepublish_guard.cli import main
    repo = new_repo(tmp_path, {"data/users.csv": f"id,email\n1,{PERSONAL}\n"})
    assert main(["baseline", str(repo), "--history"]) == 0
    assert main(["scan", str(repo), "--history"]) == 0


def test_accepted_column_is_reported_again_even_when_another_column_is_open(tmp_path):
    other = "luis.mora" + "@" + "gmail.com"
    table = f"id,email,celular\n1,{PERSONAL},31" + "24567890\n"
    repo = new_repo(tmp_path, {"data/users.csv": table})
    email_col = [f for f in full_scan(repo, Config()).findings if f.rule == "pii_column" and f.preview == "email"]
    (repo / "data/users.csv").write_text(table + f"2,{other},31" + "59871234\n")
    res = full_scan(repo, Config(ignore={email_col[0].fingerprint}))
    assert {f.preview for f in res.findings if f.rule == "pii_column"} == {"email", "celular"}
    assert not [f for f in res.findings if f.rule == "email_address"]


def test_number_next_to_a_safe_e_mail_still_counts():
    assert columns("id,documento\n1,10" + "23456781 ana@example.com\n") == ["documento"]


# Second Codex review (4ff31e7).

def test_new_bare_id_in_an_accepted_column_is_reported(tmp_path):
    repo = new_repo(tmp_path, {"data/people.csv": "nombre,cedula\nAna,10" + "23456781\n"})
    column = [f for f in full_scan(repo, Config()).findings if f.rule == "pii_column"]
    accepted = Config(ignore={column[0].fingerprint})
    assert full_scan(repo, accepted).findings == []
    (repo / "data/people.csv").write_text("nombre,cedula\nAna,10" + "23456781\nLuis,79" + "845123\n")
    assert [f.preview for f in full_scan(repo, accepted).findings] == ["cedula"]


def test_url_userinfo_in_a_column_is_not_an_e_mail():
    assert columns("id,email\n1,https://alice@real-" + "company.com/path\n") == []


def test_rows_added_in_later_commits_stay_under_their_column_in_history(tmp_path):
    from test_scan_and_cli import git
    other = "luis.mora" + "@" + "gmail.com"
    repo = new_repo(tmp_path, {"data/users.csv": f"id,email\n1,{PERSONAL}\n"})
    (repo / "data/users.csv").write_text(f"id,email\n1,{PERSONAL}\n2,{other}\n")
    git(repo, "commit", "-qam", "row", "--no-gpg-sign")
    git(repo, "rm", "-q", "data/users.csv")
    git(repo, "commit", "-qm", "rm", "--no-gpg-sign")
    rules = [f.rule for f in full_scan(repo, Config(), history=True).findings if f.path == "data/users.csv"]
    assert rules == ["pii_column"]
