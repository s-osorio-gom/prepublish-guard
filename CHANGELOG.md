# Changelog

## 0.1.0 (2026-10-11)

First release.
- Working-tree and full-history scans (`--history`: every line ever added on any branch or tag).
- Secrets: 14 vendor token formats, private keys (including encrypted ones), URL passwords, secret
  assignments, JWTs.
- Personal data: national IDs with context (Colombian cédula and NIT, DNI, SSN, passport), Luhn-checked cards,
  e-mails, Colombian and other phone numbers, personal columns in CSV/TSV (also in deleted files from history).
- Local paths with personal user names, configurable confidential terms, sensitive file names, missing license.
- Masked previews only; repeated values grouped per file; text, Markdown, JSON and SARIF 2.1.0 reports.
- `baseline` command (fingerprints only), `.prepublish-guard.toml` configuration, pre-commit hook and a
  GitHub Action.
- MIT license. The demo (`examples/demo.sh`) checks its own outcome: the working tree looks clean (exit 0) while
  the history scan finds the leaks (exit 1).
- From the independent pre-release review (each fix has a test in `tests/test_release_review.py`):
  - personal data and local paths are shown only as type and length; fingerprints use scrypt and the JSON report
    no longer includes a value hash, so a pasted report cannot be reversed into an ID or phone number;
  - placeholders are recognised only as whole values (`football…`, `mypassword…` are findings), and unquoted
    secrets are checked in shell scripts, Dockerfiles and credential files;
  - history paths with spaces, accents or quotes are read correctly;
  - large files are scanned up to `max_file_bytes` with a note instead of being skipped; shallow clones are
    reported as incomplete history; a table with personal columns is reported once per column;
  - fewer false positives: retina image names (`hero@2x.jpg`), numbers in prose, identifiers that name a secret;
  - configuration type mistakes are errors (exit 2), not a silent off switch;
  - the GitHub Action uses `fail_on` from the configuration unless `fail-on` is given;
  - JSON reports carry the directory name, not the local absolute path.
