"""Release review of 0.1.0: each test reproduces a finding of the independent pre-release review and checks it
is fixed (reversible previews, missed leaks, file names in history, large files, false positives, config types,
shallow clones, report paths). Every value is fabricated and assembled at runtime."""

import hashlib
import json
import re
import subprocess
from pathlib import Path

import pytest
from test_scan_and_cli import git

from prepublish_guard.cli import main
from prepublish_guard.config import Config
from prepublish_guard.detectors import scan_line
from prepublish_guard.scanner import full_scan

ID = "10" + "23456781"
PHONE = "31" + "2 456 7890"


def rules(line: str, path: str = "notes.md") -> set[str]:
    return {h.rule for h in scan_line(line, path)}


def new_repo(tmp_path: Path, files: dict[str, str]) -> Path:
    r = tmp_path / "r"
    r.mkdir()
    git(r, "init", "-q", "-b", "main")
    for name, text in files.items():
        (r / name).parent.mkdir(parents=True, exist_ok=True)
        (r / name).write_text(text, encoding="utf-8")
    (r / "LICENSE").write_text("MIT License\n")
    git(r, "add", "-A")
    git(r, "commit", "-qm", "c", "--no-gpg-sign")
    return r


def test_reports_cannot_be_reversed_into_personal_data(tmp_path, capsys):
    r = new_repo(tmp_path, {"people.md": f"Cédula: {ID}\nCelular: {PHONE}\n"})
    assert main(["scan", str(r), "--format", "json", "--fail-on", "never"]) == 0
    out = capsys.readouterr().out
    data = json.loads(out)
    personal = [f for f in data["findings"] if f["category"] == "personal_data"]
    assert personal and all(not re.search(r"\d", f["preview"].split("[hidden")[0]) for f in personal)
    assert all("value_sha256" not in f for f in data["findings"])
    for f in personal:                       # the public fingerprint is not the cheap sha256 derivation
        cheap = hashlib.sha256(f"{f['rule']}|{f['path']}|{hashlib.sha256(ID.encode()).hexdigest()}".encode())
        assert f["fingerprint"] != cheap.hexdigest()[:16]
    assert ID[2:8] not in out and PHONE[-4:] not in out.replace("chars", "")


@pytest.mark.parametrize("line,path", [
    ('DB_PASSWORD = "' + "foot" + "ball4821" + '"', "settings.py"),
    ('DB_PASSWORD = "' + "Theo" + "dore1982" + '"', "settings.py"),
    ("URL = 'postgresql://admin:" + "mypass" + "word991" + "@db.internal/app'", "app.py"),
    ("export DB_PASSWORD=" + "Xk29dLq7" + "Pw4Rz8", "deploy.sh"),
    ("ENV SECRET_KEY=" + "q8Z3vN6tR1pL0sX4" + "q8Z3vN6tR1pL0sX4abcd", "Dockerfile"),
    ("aws_secret_access_key = " + "wJalrXUtnFEMI/K7MDENG" + "/bPxRfiCYzz9e8Rk2Lp", "credentials"),
])
def test_obvious_leaks_are_found(line, path):
    assert rules(line, path)


@pytest.mark.parametrize("line,path", [
    ('password_field = "user_password_hash"', "models.py"),
    ('SECRET_NAME = "prod/db/credentials-v2"', "settings.py"),
    ('api_key_header = "X-Api-Key-Header-Name"', "api.py"),
    ('API_KEY = "your-api-key-here"', "settings.py"),
    ('background: url("img/hero@2x.jpg");', "site.css"),
    ("El documento tiene 1.500 páginas.", "notes.md"),
    ("La identificación del modelo usa 120 000 parámetros", "notes.md"),
])
def test_ordinary_text_is_not_a_finding(line, path):
    assert not rules(line, path)


def test_history_keeps_file_names_with_spaces_accents_and_quotes(tmp_path):
    names = ["clientes año.csv", "my data.csv", 'q"uote.csv']
    r = new_repo(tmp_path, {n: f"nombre,cedula,celular\nAna,{ID},{PHONE}\n" for n in names})
    git(r, "rm", "-q", *names)
    git(r, "commit", "-qm", "rm", "--no-gpg-sign")
    res = full_scan(r, Config(), history=True)
    assert {f.path for f in res.findings if f.rule == "pii_column"} == set(names)
    allowed = full_scan(r, Config(allow_paths=["clientes año.csv"]), history=True)
    assert "clientes año.csv" not in {f.path for f in allowed.findings}


def test_large_files_are_scanned_in_part_with_a_note_and_tables_are_reported_once(tmp_path):
    rows = "".join(f"Ana,{ID},persona{i}@correo.co\n" for i in range(3000))
    r = new_repo(tmp_path, {"data/clientes.csv": "nombre,cedula,correo\n" + rows})
    res = full_scan(r, Config(max_file_bytes=20_000), history=True)
    assert any("only its first part" in n for n in res.notes)
    table = [f for f in res.findings if f.path == "data/clientes.csv"]
    assert sorted(f.preview for f in table) == ["cedula", "correo"]          # one per column, no e-mail flood
    assert all(f.rule == "pii_column" and f.in_working_tree for f in table)  # not duplicated as "history only"


@pytest.mark.parametrize("toml", ['allow_paths = "tests/*"\n', 'confidential_terms = "Acme Bank"\n',
                                  'max_file_bytes = "2MB"\n'])
def test_config_type_mistakes_are_errors_not_a_silent_off_switch(tmp_path, toml, capsys):
    r = new_repo(tmp_path, {"app.py": "print('hi')\n"})
    (r / ".prepublish-guard.toml").write_text(toml)
    assert main(["scan", str(r)]) == 2
    assert "must be" in capsys.readouterr().err


def test_a_shallow_clone_is_reported_as_incomplete_history(tmp_path):
    r = new_repo(tmp_path, {"a.txt": "a\n"})
    (r / "a.txt").write_text("b\n")
    git(r, "commit", "-qam", "second", "--no-gpg-sign")
    shallow = tmp_path / "shallow"
    subprocess.run(["git", "clone", "-q", "--depth", "1", f"file://{r}", str(shallow)], check=True)
    assert any("shallow clone" in n for n in full_scan(shallow, Config(), history=True).notes)


def test_json_report_does_not_carry_the_local_absolute_path(tmp_path, capsys):
    r = new_repo(tmp_path, {"a.txt": "a\n"})
    main(["scan", str(r), "--format", "json"])
    assert str(tmp_path) not in capsys.readouterr().out
