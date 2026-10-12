"""0.1.2: in history, a bare ID number (found only through its column, e.g. `cedula`) that was later removed is
reported, also when the commit that added it did not touch the table's header line. Every value is fabricated."""

from test_0_1_1 import _commit
from test_release_review import new_repo

from prepublish_guard.cli import main
from prepublish_guard.config import Config
from prepublish_guard.scanner import full_scan

TABLE = "nombre,cedula\nAna,10" + "23456781\n"
EXTRA = "Luis,79" + "845123\n"


def _history_rules(repo):
    return sorted(f.rule for f in full_scan(repo, Config(), history=True).findings)


def test_bare_id_added_without_its_header_then_removed_is_reported(tmp_path):
    repo = new_repo(tmp_path, {"data/people.csv": TABLE})
    assert main(["baseline", str(repo), "--history"]) == 0
    _commit(repo, "baseline")
    (repo / "data/people.csv").write_text(TABLE + EXTRA)          # a rows-only hunk: line 1 is not in the diff
    _commit(repo, "row")
    (repo / "data/people.csv").write_text(TABLE)
    _commit(repo, "row removed")
    assert main(["scan", str(repo)]) == 0                         # the current table is the accepted one
    assert main(["scan", str(repo), "--history"]) == 1            # the removed ID is still in history
    assert "pii_history_rows" in _history_rules(repo)


def test_bare_id_removed_while_its_column_remains_is_reported(tmp_path):
    repo = new_repo(tmp_path, {"data/people.csv": TABLE})
    assert main(["baseline", str(repo), "--history"]) == 0
    _commit(repo, "baseline")
    (repo / "data/people.csv").write_text("nombres" + TABLE[len("nombre"):] + EXTRA)   # header line in the diff
    _commit(repo, "renamed a column, added a row")
    (repo / "data/people.csv").write_text("nombres" + TABLE[len("nombre"):])
    _commit(repo, "row removed")
    assert main(["scan", str(repo), "--history"]) == 1
    assert "pii_history_rows" in _history_rules(repo)


def test_bare_id_added_without_its_header_to_a_deleted_accepted_table_is_reported(tmp_path):
    repo = new_repo(tmp_path, {"data/people.csv": TABLE})
    (repo / "data/people.csv").unlink()
    _commit(repo, "rm")
    assert main(["baseline", str(repo), "--history"]) == 0
    (repo / "data/people.csv").write_text(TABLE)
    _commit(repo, "again")
    (repo / "data/people.csv").write_text(TABLE + EXTRA)          # rows-only hunk
    _commit(repo, "row")
    (repo / "data/people.csv").unlink()
    _commit(repo, "rm again")
    assert main(["scan", str(repo), "--history"]) == 1


def test_rows_added_without_the_header_and_still_present_are_not_history_rows(tmp_path):
    repo = new_repo(tmp_path, {"data/people.csv": TABLE})
    (repo / "data/people.csv").write_text(TABLE + EXTRA)          # rows-only hunk, the row stays
    _commit(repo, "row")
    assert _history_rules(repo) == ["pii_column"]
    assert main(["baseline", str(repo), "--history"]) == 0
    assert main(["scan", str(repo), "--history"]) == 0


def test_rows_only_hunks_of_a_tsv_use_its_header(tmp_path):
    table = TABLE.replace(",", "\t")
    repo = new_repo(tmp_path, {"data/people.tsv": table})
    assert main(["baseline", str(repo), "--history"]) == 0
    _commit(repo, "baseline")
    (repo / "data/people.tsv").write_text(table + EXTRA.replace(",", "\t"))
    _commit(repo, "row")
    (repo / "data/people.tsv").write_text(table)
    _commit(repo, "row removed")
    assert main(["scan", str(repo), "--history"]) == 1


def test_rows_only_hunks_are_read_with_their_header_when_scanning_a_subdirectory(tmp_path):
    repo = new_repo(tmp_path, {"data/people.csv": TABLE})
    sub = repo / "data"
    (sub / ".prepublish-guard.toml").write_text("")
    assert main(["baseline", str(sub), "--history"]) == 0
    _commit(repo, "baseline")
    (sub / "people.csv").write_text(TABLE + EXTRA)
    _commit(repo, "row")
    (sub / "people.csv").write_text(TABLE)
    _commit(repo, "row removed")
    assert main(["scan", str(sub), "--history"]) == 1


# Independent review of the first version of the fix: each case below failed (or was unpinned) on it.

def _history_rows_previews(repo, config=None):
    res = full_scan(repo, config or Config(), history=True)
    return [f.preview for f in res.findings if f.rule == "pii_history_rows"]


def test_editing_the_continuation_line_of_a_quoted_cell_is_not_a_removed_value(tmp_path):
    table = 'cedula,nombre,notas\n10' + '23456781,Ana,"visita\nreprogramada 2024-03-15"\n'
    repo = new_repo(tmp_path, {"people.csv": table})
    (repo / "people.csv").write_text(table.replace("03-15", "03-18"))  # the hunk starts inside the quoted cell
    _commit(repo, "fix a date")
    assert _history_rows_previews(repo) == []


def test_a_csv_longer_than_the_column_parse_limit_is_not_compared(tmp_path, monkeypatch):
    import prepublish_guard.detectors as detectors
    import prepublish_guard.scanner as scanner
    for module in (detectors, scanner):                              # 2,000 instead of 2,000,000 characters
        monkeypatch.setattr(module, "CSV_MAX_CHARS", 2_000)
    table = "nombre,cedula\n" + "".join(f"P{i:07d},10{i:08d}\n" for i in range(150))
    assert len(table) > 2_000
    repo = new_repo(tmp_path, {"people.csv": table})
    (repo / "people.csv").write_text(table + EXTRA)                  # appended and kept: nothing was removed
    _commit(repo, "row")
    assert _history_rows_previews(repo) == []


def test_a_commit_that_removes_the_header_line_makes_the_next_header_come_from_git(tmp_path, monkeypatch):
    import prepublish_guard.scanner as scanner
    calls = []
    real = scanner._first_line
    monkeypatch.setattr(scanner, "_first_line", lambda *a: calls.append(a) or real(*a))
    repo = new_repo(tmp_path, {"people.csv": TABLE})
    (repo / "people.csv").write_text(TABLE.split("\n", 1)[1] + EXTRA)   # header line gone, one row added
    _commit(repo, "header removed")
    full_scan(repo, Config(), history=True)
    assert len(calls) == 1                                           # the old header is not reused


def test_removed_bare_id_matching_allow_regex_is_not_reported(tmp_path):
    repo = new_repo(tmp_path, {"people.csv": TABLE})
    (repo / "people.csv").write_text(TABLE + EXTRA)
    _commit(repo, "row")
    (repo / "people.csv").write_text(TABLE)
    _commit(repo, "row removed")
    assert _history_rows_previews(repo) == ["1 value(s)"]
    assert _history_rows_previews(repo, Config(allow_regex=["^79" + "845123$"])) == []


def test_a_removed_cell_with_an_e_mail_counts_once_and_keeps_its_0_1_1_fingerprint(tmp_path):
    from prepublish_guard.findings import value_hash
    from prepublish_guard.scanner import _history_rows
    email = "luis.mora" + "@" + "gmail.com"
    table = "id,email\n1,ana.ruiz" + "@" + "gmail.com\n"
    repo = new_repo(tmp_path, {"users.csv": table})
    (repo / "users.csv").write_text(table + f"2,Luis Mora <{email}>\n")
    _commit(repo, "row")
    (repo / "users.csv").write_text(table)
    _commit(repo, "row removed")
    rows = [f for f in full_scan(repo, Config(), history=True).findings if f.rule == "pii_history_rows"]
    assert [f.preview for f in rows] == ["1 value(s)"]
    assert rows[0].fingerprint == _history_rows("users.csv", {value_hash(email)}).fingerprint


def test_a_commit_that_deletes_the_first_row_and_appends_one_still_reads_the_header(tmp_path):
    table = "nombre,cedula\nAna,10" + "23456781\nLuis,79" + "845123\n"
    repo = new_repo(tmp_path, {"people.csv": table})
    (repo / "people.csv").write_text("nombre,cedula\nLuis,79" + "845123\nEva,52" + "345678\n")   # @@ -2 +1,0 @@
    _commit(repo, "first row out, one row in")
    (repo / "people.csv").write_text("nombre,cedula\nLuis,79" + "845123\n")
    _commit(repo, "row removed")
    assert _history_rows_previews(repo) == ["2 value(s)"]


def test_rows_only_commits_take_the_header_from_the_diff_without_a_git_call_each(tmp_path, monkeypatch):
    import prepublish_guard.scanner as scanner
    calls = []
    real = scanner._first_line
    monkeypatch.setattr(scanner, "_first_line", lambda *a: calls.append(a) or real(*a))
    repo = new_repo(tmp_path, {"people.csv": TABLE})
    text = TABLE
    for i in range(20):
        text += f"P{i},31{i:08d}\n"
        (repo / "people.csv").write_text(text)
        _commit(repo, f"row {i}")
    assert [f.rule for f in full_scan(repo, Config(), history=True).findings] == ["pii_column"]
    assert calls == []


def test_a_rows_only_commit_whose_previous_version_was_not_scanned_reads_the_header_from_git(tmp_path):
    repo = new_repo(tmp_path, {"people.csv": TABLE})
    assert main(["baseline", str(repo), "--history"]) == 0
    _commit(repo, "baseline")
    (repo / "people.csv").write_text(TABLE + EXTRA)
    _commit(repo, "row")
    (repo / "people.csv").write_text(TABLE)
    _commit(repo, "row removed")
    # The two newest commits only: the table's earlier versions are not scanned.
    assert main(["scan", str(repo), "--history", "--max-commits", "2"]) == 1


# Codex review of 01ba1f5.

QUOTED_HEADER = '"notas\nlargas",cedula\nx,10' + '23456781\n'


def _removed_row_repo(tmp_path, table, extra):
    repo = new_repo(tmp_path, {"people.csv": table})
    assert main(["baseline", str(repo), "--history"]) == 0
    _commit(repo, "baseline")
    (repo / "people.csv").write_text(table + extra)               # rows-only hunk
    _commit(repo, "row")
    (repo / "people.csv").write_text(table)
    _commit(repo, "row removed")
    return repo


def test_a_header_with_a_quoted_line_break_is_read_whole_from_the_diff(tmp_path):
    repo = _removed_row_repo(tmp_path, QUOTED_HEADER, "y,79" + "845123\n")
    assert main(["scan", str(repo), "--history"]) == 1


def test_a_header_with_a_quoted_line_break_is_read_whole_from_git(tmp_path):
    repo = _removed_row_repo(tmp_path, QUOTED_HEADER, "y,79" + "845123\n")
    assert main(["scan", str(repo), "--history", "--max-commits", "2"]) == 1


def test_allow_regex_matching_the_whole_removed_row_is_honoured(tmp_path):
    repo = _removed_row_repo(tmp_path, TABLE, EXTRA)
    assert _history_rows_previews(repo, Config(allow_regex=["^Luis,"])) == []


# Second Codex review (fe67636).

def test_an_allowed_e_mail_does_not_hide_a_bare_id_in_the_same_cell(tmp_path):
    email = "luis.mora" + "@" + "gmail.com"
    repo = _removed_row_repo(tmp_path, TABLE, "Luis,79" + f"845123 {email}\n")
    allowed = Config(allow_regex=["^luis\\.mora" + "@" + "gmail\\.com$"])
    assert _history_rows_previews(repo, allowed) == ["1 value(s)"]


def test_a_header_edited_on_its_continuation_line_is_read_again(tmp_path):
    before = '"notas\nlargas",nombre\nx,10' + '23456781\n'
    after = '"notas\nlargas",cedula\nx,10' + '23456781\n'           # only the header's second line changes
    repo = new_repo(tmp_path, {"people.csv": before})
    (repo / "people.csv").write_text(after)
    _commit(repo, "a column renamed")
    assert main(["baseline", str(repo), "--history"]) == 0
    _commit(repo, "baseline")
    (repo / "people.csv").write_text(after + "y,79" + "845123\n")
    _commit(repo, "row")
    (repo / "people.csv").write_text(after)
    _commit(repo, "row removed")
    assert main(["scan", str(repo), "--history"]) == 1


def test_a_header_renamed_to_a_personal_column_is_used_by_the_next_rows_only_commit(tmp_path):
    before = "nombre,codigo\nx,10" + "23456781\n"
    after = "nombre,cedula\nx,10" + "23456781\n"
    repo = new_repo(tmp_path, {"people.csv": before})
    (repo / "people.csv").write_text(after)
    _commit(repo, "a column renamed")
    assert main(["baseline", str(repo), "--history"]) == 0
    _commit(repo, "baseline")
    (repo / "people.csv").write_text(after + EXTRA)
    _commit(repo, "row")
    (repo / "people.csv").write_text(after)
    _commit(repo, "row removed")
    assert main(["scan", str(repo), "--history"]) == 1


def test_a_partly_changed_header_line_is_not_read_as_a_row(tmp_path):
    table = '"notas\nlargas",cedula\nx,10' + '23456781\n'
    edited = '"notes\nlargas",cedula\nx,10' + '23456781\n'          # the header's first line changes...
    repo = new_repo(tmp_path, {"people.csv": table})
    assert main(["baseline", str(repo), "--history"]) == 0
    _commit(repo, "baseline")
    (repo / "people.csv").write_text(edited + EXTRA)               # ...in the commit that adds a row
    _commit(repo, "header edited, row added")
    (repo / "people.csv").write_text(edited)
    _commit(repo, "row removed")
    assert main(["scan", str(repo), "--history"]) == 1
