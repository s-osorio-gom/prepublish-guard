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
