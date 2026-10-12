"""Scanning a directory or git repository: the files that would be published, and optionally every line ever
added in the history. Read-only: nothing is modified, fetched or uploaded."""

from __future__ import annotations

import fnmatch
import os
import re
import subprocess
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from .config import CONFIG_NAME, Config
from .detectors import scan_file_level, scan_line, term_pattern, to_finding
from .findings import Finding, value_hash

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache",
             ".tox", "dist", "build", ".idea", ".vscode"}
BINARY_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz", ".tgz", ".bz2", ".xz",
                   ".7z", ".jar", ".whl", ".so", ".dll", ".dylib", ".exe", ".bin", ".woff", ".woff2", ".ttf", ".otf",
                   ".mp3", ".mp4", ".mov", ".avi", ".pyc", ".parquet", ".xlsx", ".xls", ".docx", ".pptx"}
LICENSE_NAMES = {"license", "license.md", "license.txt", "license.rst", "licence", "licence.md", "copying",
                 "copying.md", "unlicense"}


@dataclass
class ScanResult:
    root: str
    files_scanned: int = 0
    commits_scanned: int = 0
    findings: list[Finding] = field(default_factory=list)
    suppressed: int = 0
    notes: list[str] = field(default_factory=list)
    covered: list[Finding] = field(default_factory=list)       # internal: values hidden by their table's column
    covers: dict[str, set[str]] = field(default_factory=dict)  # internal: hashes each table's columns cover
    partial: set[str] = field(default_factory=set)             # internal: files scanned only up to max_file_bytes


_ESCAPES = {"a": 7, "b": 8, "t": 9, "n": 10, "v": 11, "f": 12, "r": 13, '"': 34, "\\": 92}


def _diff_path(raw: str) -> str:
    """The path of a `+++ ` diff header as stored: git appends a TAB after names with spaces and C-quotes names
    with quotes, backslashes or control characters ("b/q\\"uote.csv", octal escapes for raw bytes)."""
    raw = raw.rstrip("\t")
    if not (len(raw) >= 2 and raw[0] == raw[-1] == '"'):
        return raw
    body, out, i = raw[1:-1], bytearray(), 0
    while i < len(body):
        c = body[i]
        if c == "\\" and i + 1 < len(body):
            nxt = body[i + 1]
            if nxt in "01234567" and i + 3 < len(body) + 1 and all(ch in "01234567" for ch in body[i + 1:i + 4]):
                out.append(int(body[i + 1:i + 4], 8))
                i += 4
                continue
            out.append(_ESCAPES.get(nxt, ord(nxt)))
            i += 2
            continue
        out += c.encode("utf-8")
        i += 1
    return out.decode("utf-8", errors="replace")


def _git(root: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, encoding="utf-8",
                          errors="replace")


def _first_line(root: Path, commit: str | None, path: str) -> str | None:
    """The first line of `path` (relative to the repository root) as stored in `commit`, without reading the rest
    of the file; None when it cannot be read."""
    if not commit:
        return None
    proc = subprocess.Popen(["git", "-C", str(root), "cat-file", "blob", f"{commit}:{path}"],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    assert proc.stdout is not None
    first = proc.stdout.readline(1_000_000)
    proc.stdout.close()
    proc.kill()
    proc.wait()
    return first.decode("utf-8", errors="replace").rstrip("\r\n") if first else None


def is_git_repo(root: Path) -> bool:
    p = _git(root, "rev-parse", "--is-inside-work-tree")
    return p.returncode == 0 and p.stdout.strip() == "true"


def publishable_files(root: Path, include_untracked: bool = False) -> list[str]:
    """Files that a push would publish: tracked files in a git repository (plus untracked, not ignored ones on
    request); every file under the directory otherwise."""
    if is_git_repo(root):
        out = _git(root, "ls-files", "-z").stdout.split("\0")
        if include_untracked:
            out += _git(root, "ls-files", "-z", "--others", "--exclude-standard").stdout.split("\0")
        return sorted({p for p in out if p})
    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for f in filenames:
            files.append(os.path.relpath(os.path.join(dirpath, f), root).replace(os.sep, "/"))
    return sorted(files)


def _read_text(path: Path, max_bytes: int) -> tuple[str | None, bool]:
    """(text, truncated). A file larger than `max_bytes` is scanned up to that size and reported as partly
    scanned, never skipped silently; binary files and links return no text."""
    try:
        if path.is_symlink() or not path.is_file():
            return None, False
        with open(path, "rb") as fh:
            data = fh.read(max_bytes + 1)
    except OSError:
        return None, False
    if b"\0" in data[:8192]:
        return None, False
    truncated = len(data) > max_bytes
    return data[:max_bytes].decode("utf-8", errors="replace"), truncated


def _drop_covered(findings: list[Finding], per_column: bool = True
                  ) -> tuple[list[Finding], list[Finding], dict[str, set[str]]]:
    """In a table already reported for its personal columns, one finding per column is the useful report: the
    per-line values of those columns (thousands of e-mails in a CSV) add nothing but noise. In the working tree the
    coverage is per column, so a value outside the personal columns is still reported. In history, rows added by
    later commits arrive without their header, so the whole table is covered; `full_scan` then reports a covered
    value that the current table no longer holds, or folds it into the fingerprint of a deleted table.
    Returns (kept, covered, covers per path)."""
    covers: dict[str, set[str]] = {}
    for f in findings:
        values = f.extra.pop("_covers", set())
        if f.rule == "pii_column":
            covers.setdefault(f.path, set()).update(values)
    kept, covered = [], []
    for f in findings:
        hidden = (f.category == "personal_data" and f.rule != "pii_column" and f.path in covers
                  and (not per_column or f.value_sha256 in covers[f.path]))
        (covered if hidden else kept).append(f)
    return kept, covered, covers


def _history_rows(path: str, values: set[str]) -> Finding:
    """One finding per table for personal values it held in some commit and no longer holds."""
    return Finding(rule="pii_history_rows", category="personal_data", severity="high", path=path, line=0,
                   preview=f"{len(values)} value(s)", in_working_tree=False, value_sha256=value_hash(path),
                   basis=value_hash("\n".join(sorted(values))),
                   message="personal values this table no longer holds are still in its git history")


def _seal(findings: list[Finding], folded: dict[str, set[str]]) -> None:
    """A column's fingerprint covers the personal values it holds: accepting it (`ignore`, `baseline`) accepts
    those, and any new value reports the column again. Removing values also changes it (take the baseline again)."""
    for f in findings:
        cells = f.extra.pop("_cells", set())
        if f.rule == "pii_column":
            cells |= folded.get(f.path, set())
            f.basis = value_hash(f.value_sha256 + "\0" + "\n".join(sorted(cells)))


class Scanner:
    def __init__(self, root: Path, config: Config):
        self.root = Path(root)
        self.config = config
        self.confidential = [term_pattern(t) for t in config.confidential_terms]
        self._email_domains = set(config.allowed_email_domains)

    def _allowed_path(self, rel: str) -> bool:
        # The tool's own config lists the confidential terms and accepted fingerprints: never a finding.
        return PurePosixPath(rel).name == CONFIG_NAME or any(fnmatch.fnmatch(rel, g) for g in self.config.allow_paths)

    def _allowed_value(self, text: str) -> bool:
        return any(re.search(rx, text) for rx in self.config.allow_regex)

    def _line_findings(self, line: str, rel: str, lineno: int) -> Iterator[Finding]:
        for hit in scan_line(line, rel, confidential=self.confidential,
                             allowed_email_domains=set(self.config.allowed_email_domains)):
            if not self._allowed_value(hit.value) and not self._allowed_value(line):
                yield to_finding(hit, rel, lineno)

    def scan_tree(self, include_untracked: bool = False) -> ScanResult:
        res = ScanResult(root=str(self.root))
        files = publishable_files(self.root, include_untracked)
        for rel in files:
            if self._allowed_path(rel):
                continue
            text, truncated = (None, False) if Path(rel).suffix.lower() in BINARY_SUFFIXES else \
                _read_text(self.root / rel, self.config.max_file_bytes)
            if truncated:
                res.partial.add(rel)
                res.notes.append(f"{rel}: larger than max_file_bytes ({self.config.max_file_bytes}); only its first "
                                 "part was scanned")
            if text is None:                              # binary: only its name can be checked
                res.findings.extend(to_finding(hit, rel, 0) for hit in scan_file_level(rel, ""))
                continue
            res.files_scanned += 1
            for hit in scan_file_level(rel, text, self._email_domains):
                if not self._allowed_value(hit.value):
                    line = text[:text.find(hit.value)].count("\n") + 1 if hit.value in text else 0
                    res.findings.append(to_finding(hit, rel, line))
            for n, line in enumerate(text.splitlines(), 1):
                res.findings.extend(self._line_findings(line, rel, n))
        if not any(Path(f).name.lower() in LICENSE_NAMES for f in files if "/" not in f):
            res.findings.append(Finding(rule="missing_license", category="hygiene", severity="low", path="LICENSE",
                                        line=0, preview="-", message="no license file at the root: others may not "
                                        "legally reuse the code", value_sha256="0" * 64))
        kept, res.covered, res.covers = _drop_covered(res.findings)
        res.findings = _dedupe(kept)
        return res

    def scan_history(self, max_commits: int | None = None) -> ScanResult:
        """Every line ever added on any branch or tag (`git log --all -p`), so a credential that was committed and
        later deleted is still found. Each finding keeps the first commit that added it."""
        res = ScanResult(root=str(self.root))
        if not is_git_repo(self.root):
            res.notes.append("not a git repository: history not scanned")
            return res
        if _git(self.root, "rev-parse", "--is-shallow-repository").stdout.strip() == "true":
            res.notes.append("shallow clone: the history is incomplete, so older leaks can be missed "
                             "(fetch the full history, e.g. actions/checkout with fetch-depth: 0)")
        # Scanning a subdirectory of a repository: only its history, with paths relative to it.
        prefix = _git(self.root, "rev-parse", "--show-prefix").stdout.strip()
        args = ["log", "--all", "-p", "--no-color", "--no-ext-diff", "--unified=0", "--no-renames", "--reverse",
                "--format=%x01commit %H"]
        if max_commits:
            args.insert(1, f"--max-count={max_commits}")
        args += ["--", "."]
        # core.quotePath=false keeps non-ASCII names as they are; quotes and control characters are still
        # C-quoted by git and are decoded by _diff_path.
        proc = subprocess.Popen(["git", "-c", "core.quotePath=false", "-C", str(self.root), *args],
                                stdout=subprocess.PIPE, text=True, encoding="utf-8", errors="replace")
        commit, path, lineno = None, None, 0
        first: dict[str, Finding] = {}
        added: list[str] = []          # lines added to `path` in `commit`: file-level rules (CSV columns, key blocks)
        header_added = False           # line 1 of `path` is among them

        def flush() -> None:
            nonlocal header_added
            if path and added and not self._allowed_path(path):
                lines = added
                if not header_added and path.lower().endswith((".csv", ".tsv")):
                    # Rows added without the header line: read the header at that commit, so that a value found
                    # only through its column (a bare ID under `cedula`) is still checked.
                    header = _first_line(self.root, commit, prefix + path)
                    lines = [header, *added] if header is not None else added
                for hit in scan_file_level(path, "\n".join(lines) + "\n", self._email_domains):
                    if hit.category != "sensitive_file" and not self._allowed_value(hit.value):
                        self._remember(first, to_finding(hit, path, 0), commit)
            added.clear()
            header_added = False

        assert proc.stdout is not None
        for raw in proc.stdout:
            line = raw.rstrip("\n")
            if line.startswith("\x01commit "):
                flush()
                commit = line.split(" ", 1)[1]
                res.commits_scanned += 1
                continue
            if line.startswith("diff --git "):
                flush()
                path = None
                continue
            if line.startswith("+++ "):
                target = _diff_path(line[4:])
                path = None if target == "/dev/null" else (target[2:] if target.startswith("b/") else target)
                if path and prefix:
                    path = path[len(prefix):] if path.startswith(prefix) else None
                if path and not self._allowed_path(path):
                    for hit in scan_file_level(path, ""):          # sensitive file names ever committed
                        self._remember(first, to_finding(hit, path, 0), commit)
                continue
            if line.startswith("@@"):
                m = re.search(r"\+(\d+)(?:,(\d+))?", line)
                lineno = int(m.group(1)) if m else 0
                header_added = header_added or (lineno == 1 and (m.group(2) or "1") != "0")
                continue
            if path and line.startswith("+") and not line.startswith("+++"):
                if not self._allowed_path(path):
                    added.append(line[1:])
                    for f in self._line_findings(line[1:], path, lineno):
                        self._remember(first, f, commit)
                lineno += 1
        flush()
        proc.wait()
        for f in first.values():
            f.extra.pop("_commits", None)
        res.findings, res.covered, res.covers = _drop_covered(list(first.values()), per_column=False)
        return res

    @staticmethod
    def _remember(seen: dict[str, Finding], f: Finding, commit: str | None) -> None:
        """First commit that added the value, and how many distinct commits added it."""
        key = f.key
        if key not in seen:
            f.commit, f.in_working_tree = commit, False
            f.extra["_commits"] = set()
            seen[key] = f
        elif f.rule == "pii_column":                         # the table again in a later commit: all its values
            for k in ("_cells", "_covers"):
                seen[key].extra.setdefault(k, set()).update(f.extra.get(k, set()))
        seen[key].extra["_commits"].add(commit)
        seen[key].commits = len(seen[key].extra["_commits"])


def _dedupe(findings: list[Finding]) -> list[Finding]:
    """One finding per distinct value in a file, with every line it appears on: a value repeated in
    105 notebook cells is one problem to fix, not 105."""
    seen: dict[str, Finding] = {}
    for f in findings:
        first = seen.setdefault(f.key, f)
        lines = first.extra.setdefault("lines", [])
        if f.line and f.line not in lines:
            lines.append(f.line)
    for f in seen.values():
        f.extra["occurrences"] = max(1, len(f.extra.get("lines", [])))
        f.extra["lines"] = f.extra.get("lines", [])[:50]
    return list(seen.values())


def full_scan(root: Path, config: Config, history: bool = False, include_untracked: bool = False,
              max_commits: int | None = None) -> ScanResult:
    scanner = Scanner(root, config)
    res = scanner.scan_tree(include_untracked)
    if history:
        hist = scanner.scan_history(max_commits)
        res.commits_scanned = hist.commits_scanned
        res.notes += hist.notes
        in_tree = {f.key for f in res.findings}
        for f in hist.findings:
            if f.key in in_tree:                             # still present: annotate the working-tree finding
                for g in res.findings:
                    if g.key == f.key:
                        g.commit, g.commits = f.commit, f.commits
            else:
                res.findings.append(f)                       # only in history: needs history rewrite + rotation
        folded: dict[str, set[str]] = {}
        gone: dict[str, set[str]] = {}
        for f in hist.covered:
            if f.path not in res.covers:                     # the table is gone: its values belong to its columns
                folded.setdefault(f.path, set()).add(f.value_sha256)
            elif f.path not in res.partial and f.value_sha256 not in res.covers[f.path] and f.key not in in_tree:
                gone.setdefault(f.path, set()).add(f.value_sha256)   # once in the table, no longer: history only
        # Values found only through their column (a bare ID under `cedula`) have no line finding of their own:
        # compare the cells each column held in history with the cells the current table holds.
        cells_now: dict[str, set[str]] = {}
        for f in res.findings:
            if f.rule == "pii_column" and f.in_working_tree:
                cells_now.setdefault(f.path, set()).update(f.extra.get("_cells", set()))
        for f in hist.findings:
            if f.rule == "pii_column" and f.key in in_tree and f.path not in res.partial:
                removed = f.extra.get("_cells", set()) - cells_now[f.path]
                if removed:
                    gone.setdefault(f.path, set()).update(removed)
        res.findings += [_history_rows(path, values) for path, values in sorted(gone.items())]
        _seal(res.findings, folded)
    else:
        _seal(res.findings, {})
    kept = [f for f in res.findings if f.fingerprint not in config.ignore]
    res.suppressed = len(res.findings) - len(kept)
    res.findings = sorted(kept, key=lambda f: (-("low", "medium", "high").index(f.severity), f.path, f.line))
    return res
