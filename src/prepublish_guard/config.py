"""Optional configuration in `.prepublish-guard.toml` at the repository root.

    confidential_terms = ["Acme Bank", "Project Falcon"]   # names that must not be published
    allowed_email_domains = ["mycompany.com"]              # e-mails you publish on purpose
    allow_paths = ["tests/fixtures/*"]                     # glob patterns skipped entirely
    allow_regex = ["555-01\\d\\d"]                          # matches (or lines) never reported
    ignore = ["3f9a0c1d2e4b5a6f"]                          # fingerprints of accepted findings (see `baseline`)
    max_file_bytes = 2000000
    fail_on = "medium"                                     # low | medium | high | never

The file holds no matched values: accepted findings are kept as fingerprints only.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAME = ".prepublish-guard.toml"


class ConfigError(ValueError):
    pass


@dataclass
class Config:
    confidential_terms: list[str] = field(default_factory=list)
    allowed_email_domains: list[str] = field(default_factory=list)
    allow_paths: list[str] = field(default_factory=list)
    allow_regex: list[str] = field(default_factory=list)
    ignore: set[str] = field(default_factory=set)
    max_file_bytes: int = 2_000_000
    fail_on: str = "medium"


def load_config(root: Path, explicit: Path | None = None) -> Config:
    path = explicit or (Path(root) / CONFIG_NAME)
    if not path.exists():
        if explicit:
            raise ConfigError(f"config file not found: {path}")
        return Config()
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise ConfigError(f"{path}: {exc}") from exc
    known = {"confidential_terms", "allowed_email_domains", "allow_paths", "allow_regex", "ignore",
             "max_file_bytes", "fail_on"}
    unknown = set(raw) - known
    if unknown:
        raise ConfigError(f"{path}: unknown keys {sorted(unknown)} (known: {sorted(known)})")
    def strings(key: str) -> list[str]:
        # A bare string here ("tests/*") would be read character by character, and "*" would silence everything.
        value = raw.get(key, [])
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise ConfigError(f"{path}: {key} must be a list of strings, e.g. {key} = [\"...\"]")
        return value

    max_bytes = raw.get("max_file_bytes", 2_000_000)
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes <= 0:
        raise ConfigError(f"{path}: max_file_bytes must be a positive integer number of bytes, e.g. 2000000")
    if not isinstance(raw.get("fail_on", "medium"), str):
        raise ConfigError(f"{path}: fail_on must be a string")
    cfg = Config(
        confidential_terms=strings("confidential_terms"),
        allowed_email_domains=[d.lower() for d in strings("allowed_email_domains")],
        allow_paths=strings("allow_paths"),
        allow_regex=strings("allow_regex"),
        ignore=set(strings("ignore")),
        max_file_bytes=max_bytes,
        fail_on=raw.get("fail_on", "medium"),
    )
    if cfg.fail_on not in ("low", "medium", "high", "never"):
        raise ConfigError(f"{path}: fail_on must be low, medium, high or never")
    import re
    for rx in cfg.allow_regex:
        try:
            re.compile(rx)
        except re.error as exc:
            raise ConfigError(f"{path}: invalid allow_regex {rx!r}: {exc}") from exc
    return cfg


def write_ignore(path: Path, fingerprints: list[str]) -> int:
    """Adds fingerprints to the `ignore` list of a config file, keeping everything else. Returns how many were new."""
    existing = path.read_text(encoding="utf-8") if path.exists() else ""
    current = tomllib.loads(existing).get("ignore", []) if existing else []
    new = [f for f in sorted(set(fingerprints)) if f not in current]
    if not new:
        return 0
    merged = sorted(set(current) | set(new))
    block = "ignore = [\n" + "".join(f'  "{f}",\n' for f in merged) + "]\n"
    lines, out, skipping = existing.splitlines(keepends=True), [], False
    for ln in lines:
        if ln.lstrip().startswith("ignore") and "=" in ln:
            skipping = "]" not in ln
            continue
        if skipping:
            skipping = "]" not in ln
            continue
        out.append(ln)
    text = "".join(out)
    if text and not text.endswith("\n"):
        text += "\n"
    path.write_text(text + block, encoding="utf-8")
    return len(new)
