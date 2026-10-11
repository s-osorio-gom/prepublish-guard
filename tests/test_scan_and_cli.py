"""End to end on real temporary git repositories: working tree vs history, ignored files, baselines, report
formats, exit codes, and that no report ever contains a raw matched value."""

import json
import subprocess
from pathlib import Path

import pytest

from prepublish_guard.cli import main
from prepublish_guard.config import load_config
from prepublish_guard.scanner import full_scan

TOKEN = "ghp_" + "W4nP8rLx2Kq7Tz9V" + "mB3cJ6yH1sDf5gNe0aUo"   # fabricated, assembled at runtime
CEDULA = "1.0" + "34.567.890"         # fabricated


def git(repo: Path, *args: str) -> None:
    env = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com", "GIT_COMMITTER_NAME": "t",
           "GIT_COMMITTER_EMAIL": "t@example.com", "PATH": "/usr/bin:/bin:/usr/local/bin"}
    subprocess.run(["git", "-C", str(repo), *args], check=True, env=env, capture_output=True)


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "repo"
    r.mkdir()
    git(r, "init", "-q", "-b", "main")
    (r / "README.md").write_text("# demo\n\nA small tool.\n")
    (r / "app.py").write_text(f'TOKEN = "{TOKEN}"\n')
    (r / "people.md").write_text(f"Cliente: Ana Ruiz, cédula {CEDULA}\n")
    git(r, "add", "-A")
    git(r, "commit", "-qm", "first", "--no-gpg-sign")
    (r / "app.py").write_text('import os\nTOKEN = os.environ["TOKEN"]\n')       # "fixed" in the tree...
    (r / "people.md").unlink()
    (r / "LICENSE").write_text("MIT License\n")
    (r / ".gitignore").write_text("local/\n")
    (r / "local").mkdir()
    (r / "local" / "notes.txt").write_text(f"{TOKEN}\n")                        # ignored: never published
    git(r, "add", "-A")
    git(r, "commit", "-qm", "remove secrets", "--no-gpg-sign")
    return r


def test_tree_is_clean_but_history_still_holds_the_secrets(repo):
    tree = full_scan(repo, load_config(repo))
    assert tree.findings == []
    hist = full_scan(repo, load_config(repo), history=True)
    by_rule = {f.rule: f for f in hist.findings}
    assert {"github_token", "national_id"} <= set(by_rule)
    assert all(not f.in_working_tree and f.commit for f in hist.findings)
    assert hist.commits_scanned == 2


def test_cli_exit_codes_formats_and_no_raw_values(repo, capsys):
    assert main(["scan", str(repo)]) == 0
    capsys.readouterr()
    for fmt in ("text", "markdown", "json", "sarif"):
        code = main(["scan", str(repo), "--history", "--format", fmt])
        out = capsys.readouterr().out
        assert code == 1, fmt
        assert TOKEN not in out and CEDULA not in out and CEDULA.replace(".", "") not in out, fmt
    main(["scan", str(repo), "--history", "--format", "sarif"])
    sarif = json.loads(capsys.readouterr().out)
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0" and run["tool"]["driver"]["name"] == "prepublish-guard"
    assert {r["ruleId"] for r in run["results"]} >= {"github_token", "national_id"}
    assert all(r["partialFingerprints"]["prepublishGuard/v1"] for r in run["results"])
    assert main(["scan", str(repo), "--history", "--fail-on", "never"]) == 0
    capsys.readouterr()


def test_baseline_accepts_current_findings_without_storing_values(repo, capsys):
    assert main(["baseline", str(repo), "--history"]) == 0
    cfg_text = (repo / ".prepublish-guard.toml").read_text()
    assert "ignore" in cfg_text and TOKEN not in cfg_text and CEDULA not in cfg_text
    capsys.readouterr()
    assert main(["scan", str(repo), "--history"]) == 0                      # accepted
    (repo / "new.py").write_text(f'KEY = "{"AKIA" + "Z9X8C7V6B5N4M3L2"}"\n')
    assert main(["scan", str(repo), "--include-untracked"]) == 1            # a new finding still fails


def test_untracked_and_plain_directories(tmp_path, capsys):
    d = tmp_path / "plain"
    d.mkdir()
    (d / "x.py").write_text(f'T = "{TOKEN}"\n')
    (d / "node_modules").mkdir()
    (d / "node_modules" / "y.js").write_text(f'"{TOKEN}"\n')
    res = full_scan(d, load_config(d))
    assert [f.path for f in res.findings if f.rule == "github_token"] == ["x.py"]


def test_config_errors_and_rules_listing(tmp_path, capsys):
    (tmp_path / ".prepublish-guard.toml").write_text('fail_on = "sometimes"\n')
    assert main(["scan", str(tmp_path)]) == 2
    (tmp_path / ".prepublish-guard.toml").write_text('unknown_key = 1\n')
    assert main(["scan", str(tmp_path)]) == 2
    assert main(["scan", str(tmp_path / "missing")]) == 2
    assert main(["rules"]) == 0
    assert "national ids" in capsys.readouterr().out


def test_allow_paths_and_regex(tmp_path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "fixture.py").write_text(f'T = "{TOKEN}"\n')
    (tmp_path / "doc.md").write_text("call (604) 382-1190 for support\n")
    (tmp_path / ".prepublish-guard.toml").write_text('allow_paths = ["tests/*"]\nallow_regex = ["382-1190"]\n')
    res = full_scan(tmp_path, load_config(tmp_path))
    assert not [f for f in res.findings if f.rule != "missing_license"]


def test_binary_and_large_files_are_skipped_but_sensitive_names_count(tmp_path):
    (tmp_path / "logo.png").write_bytes(b"\x89PNG\x00" + TOKEN.encode())
    (tmp_path / "server.pem").write_bytes(b"\x00binary")
    (tmp_path / "LICENSE").write_text("MIT\n")
    res = full_scan(tmp_path, load_config(tmp_path))
    assert [f.rule for f in res.findings] == ["key_material_file"]


def test_deleted_csv_with_personal_columns_is_found_in_history(tmp_path):
    r = tmp_path / "r"
    r.mkdir()
    git(r, "init", "-q", "-b", "main")
    (r / "clientes.csv").write_text("nombre,cedula,celular\nAna,1023456781,3124567890\nLuis,79845123,3159871234\n")
    (r / "LICENSE").write_text("MIT\n")
    git(r, "add", "-A")
    git(r, "commit", "-qm", "data", "--no-gpg-sign")
    git(r, "rm", "-q", "clientes.csv")
    git(r, "commit", "-qm", "remove data", "--no-gpg-sign")
    assert full_scan(r, load_config(r)).findings == []
    hist = full_scan(r, load_config(r), history=True)
    cols = sorted(f.preview for f in hist.findings if f.rule == "pii_column")
    assert cols == ["cedula", "celular"] and all(not f.in_working_tree for f in hist.findings)


def test_repeated_value_is_one_finding_with_all_its_lines(tmp_path):
    (tmp_path / "LICENSE").write_text("MIT\n")
    (tmp_path / "nb.ipynb").write_text("\n".join(['"/Users/carolina/data.csv",'] * 5) + "\n")
    res = full_scan(tmp_path, load_config(tmp_path))
    [f] = res.findings
    assert f.rule == "personal_path" and f.extra["occurrences"] == 5 and f.extra["lines"] == [1, 2, 3, 4, 5]


def test_scanning_a_subdirectory_only_sees_its_own_history(tmp_path):
    r = tmp_path / "mono"
    (r / "pkg").mkdir(parents=True)
    git(r, "init", "-q", "-b", "main")
    (r / "other.py").write_text(f'T = "{TOKEN}"\n')
    (r / "pkg" / "LICENSE").write_text("MIT\n")
    (r / "pkg" / "a.py").write_text(f'T = "{TOKEN}"\n')
    git(r, "add", "-A")
    git(r, "commit", "-qm", "c1", "--no-gpg-sign")
    (r / "pkg" / "a.py").write_text("T = None\n")
    git(r, "commit", "-qam", "c2", "--no-gpg-sign")
    hist = full_scan(r / "pkg", load_config(r / "pkg"), history=True)
    assert [(f.rule, f.path) for f in hist.findings] == [("github_token", "a.py")]
