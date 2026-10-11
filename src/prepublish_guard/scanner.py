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
from .findings import Finding

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


def _drop_covered(findings: list[Finding]) -> list[Finding]:
    """In a table already reported for its personal columns, one finding per column is the useful report: the
    per-line personal values of that same file (thousands of e-mails in a CSV) add nothing but noise."""
    tables = {f.path for f in findings if f.rule == "pii_column"}
    return [f for f in findings if not (f.path in tables and f.category == "personal_data" and f.rule != "pii_column")]


class Scanner:
    def __init__(self, root: Path, config: Config):
        self.root = Path(root)
        self.config = config
        self.confidential = [term_pattern(t) for t in config.confidential_terms]

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
                res.notes.append(f"{rel}: larger than max_file_bytes ({self.config.max_file_bytes}); only its first "
                                 "part was scanned")
            if text is None:                              # binary: only its name can be checked
                res.findings.extend(to_finding(hit, rel, 0) for hit in scan_file_level(rel, ""))
                continue
            res.files_scanned += 1
            for hit in scan_file_level(rel, text):
                if not self._allowed_value(hit.value):
                    line = text[:text.find(hit.value)].count("\n") + 1 if hit.value in text else 0
                    res.findings.append(to_finding(hit, rel, line))
            for n, line in enumerate(text.splitlines(), 1):
                res.findings.extend(self._line_findings(line, rel, n))
        if not any(Path(f).name.lower() in LICENSE_NAMES for f in files if "/" not in f):
            res.findings.append(Finding(rule="missing_license", category="hygiene", severity="low", path="LICENSE",
                                        line=0, preview="-", message="no license file at the root: others may not "
                                        "legally reuse the code", value_sha256="0" * 64))
        res.findings = _dedupe(_drop_covered(res.findings))
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

        def flush() -> None:
            if path and added and not self._allowed_path(path):
                for hit in scan_file_level(path, "\n".join(added) + "\n"):
                    if hit.category != "sensitive_file" and not self._allowed_value(hit.value):
                        self._remember(first, to_finding(hit, path, 0), commit)
            added.clear()

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
                m = re.search(r"\+(\d+)", line)
                lineno = int(m.group(1)) if m else 0
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
        res.findings = _drop_covered(list(first.values()))
        return res

    @staticmethod
    def _remember(seen: dict[str, Finding], f: Finding, commit: str | None) -> None:
        """First commit that added the value, and how many distinct commits added it."""
        key = f.key
        if key not in seen:
            f.commit, f.in_working_tree = commit, False
            f.extra["_commits"] = set()
            seen[key] = f
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
    kept = [f for f in res.findings if f.fingerprint not in config.ignore]
    res.suppressed = len(res.findings) - len(kept)
    res.findings = sorted(kept, key=lambda f: (-("low", "medium", "high").index(f.severity), f.path, f.line))
    return res
