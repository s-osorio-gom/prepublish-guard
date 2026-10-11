"""Command line.

    prepublish-guard scan [PATH] [--history] [--format text|markdown|json|sarif] [--output FILE]
                          [--fail-on low|medium|high|never] [--include-untracked] [--config FILE]
    prepublish-guard baseline [PATH] [--history]    # accept the current findings (stores fingerprints only)
    prepublish-guard rules                          # list what is detected

Exit codes: 0 = nothing at or above --fail-on, 1 = findings at or above it, 2 = usage or configuration error.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .config import CONFIG_NAME, ConfigError, load_config, write_ignore
from .findings import severity_at_least
from .report import FORMATS
from .scanner import full_scan

RULES = """secrets (high): AWS, GitHub, GitLab, Slack, Google, Stripe, OpenAI, Anthropic, Twilio, SendGrid, npm,
  PyPI and Telegram tokens; private key blocks; passwords in connection URLs; literal values assigned to
  secret-looking names (password, token, api_key, client_secret...); JSON Web Tokens (medium)
personal data: national ids with context (cedula, C.C., NIT, DNI, SSN, passport) and US SSN format (high); payment
  cards passing Luhn (high); personal e-mails (medium); Colombian mobile and other phone numbers (medium); CSV/TSV
  columns of personal data (high)
local paths (low): /Users/<name>/, /home/<name>/, C:\\Users\\<name>\\ with a personal user name
confidential terms (medium): names listed in .prepublish-guard.toml
sensitive files: SSH keys, credential files (high); .env, key stores, auth configs (medium); databases/backups (low)
hygiene (low): no LICENSE at the root
Not findings: placeholders (<...>, ${VAR}, changeme, xxx), example/test/noreply e-mail domains, environment lookups,
  NANP 555-01xx fictional numbers, generic home folders (/home/user, /home/runner)."""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="prepublish-guard", description="Check a repository for secrets, personal data "
                                "and other things that must not be published, in its files and its git history.")
    p.add_argument("--version", action="version", version=f"prepublish-guard {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("scan", "baseline"):
        s = sub.add_parser(name)
        s.add_argument("path", nargs="?", default=".")
        s.add_argument("--history", action="store_true", help="also scan every line ever added in the git history")
        s.add_argument("--max-commits", type=int, default=None, help="limit the history scan to the newest N commits")
        s.add_argument("--include-untracked", action="store_true", help="also scan untracked, non-ignored files")
        s.add_argument("--config", type=Path, default=None, help=f"config file (default: PATH/{CONFIG_NAME})")
        if name == "scan":
            s.add_argument("--format", choices=sorted(FORMATS), default="text")
            s.add_argument("--output", type=Path, default=None, help="write the report here instead of stdout")
            s.add_argument("--fail-on", choices=["low", "medium", "high", "never"], default=None)
    sub.add_parser("rules")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.cmd == "rules":
        print(RULES)
        return 0
    root = Path(args.path).resolve()
    if not root.is_dir():
        print(f"prepublish-guard: not a directory: {root}", file=sys.stderr)
        return 2
    try:
        config = load_config(root, args.config)
    except ConfigError as exc:
        print(f"prepublish-guard: {exc}", file=sys.stderr)
        return 2
    if args.cmd == "baseline":
        config.ignore = set()
        res = full_scan(root, config, history=args.history, include_untracked=args.include_untracked,
                        max_commits=args.max_commits)
        target = args.config or root / CONFIG_NAME
        added = write_ignore(target, [f.fingerprint for f in res.findings + res.covered])
        print(f"{added} finding(s) accepted in {target} (fingerprints only; review them before committing)")
        return 0
    res = full_scan(root, config, history=args.history, include_untracked=args.include_untracked,
                    max_commits=args.max_commits)
    report = FORMATS[args.format](res)
    if args.output:
        args.output.write_text(report, encoding="utf-8")
    else:
        sys.stdout.write(report)
    threshold = args.fail_on or config.fail_on
    if threshold == "never":
        return 0
    return 1 if any(severity_at_least(f.severity, threshold) for f in res.findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
