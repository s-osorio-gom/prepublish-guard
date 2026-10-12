# Changelog

## Unreleased (0.1.2)

- Fixed the known limitation of 0.1.0 and 0.1.1 (each case has a test in `tests/test_0_1_2.py`). In history, a bare
  ID number found only through its column (`cedula`, `documento`, ...) and later removed from the table is now
  reported as `pii_history_rows`, also when:
  - the commit that added it did not touch the table's header line (the header is read from that commit);
  - the table is still there;
  - the table was later deleted.
- A history scan now reads one more small object per commit that adds rows to a CSV/TSV without its header: the
  file's first line at that commit.

## 0.1.1 (2026-10-11)

Fixes found by using 0.1.0 on a real repository (each has a test in `tests/test_0_1_1.py`):
- A CSV/TSV column of e-mails is personal data only when its addresses would be reported one by one: example,
  test and noreply domains and `allowed_email_domains` no longer make an `email` column a high finding.
- An accepted CSV column (`ignore`/`baseline`) no longer hides new values: a column's fingerprint now covers the
  personal values it holds (in history, across every commit that touched the table), so any new value, an e-mail
  or a bare ID, reports the column again, while an unchanged table stays quiet. Removing values also changes it:
  take the baseline again after cleaning a table. Columns with the same name are tracked separately.
- New finding `pii_history_rows` (high): personal values a table held in an earlier commit and no longer holds,
  one finding per table, so a row added and later removed is not lost in the history scan.
- In the working tree a column hides only its own values; a value in another column of the same table is still
  reported. A number next to an example e-mail in the same cell still counts, and a URL user name
  (`https://user@host`) is not an e-mail.
- Note: column fingerprints changed, so a 0.1.0 baseline that accepted a CSV column must be taken again.
- Known limitation (also in 0.1.0, planned for 0.1.2): in history, a bare ID number added to a CSV in a commit that
  does not touch its header, and later removed, is not reported.
- The Action passes its inputs to the script through environment variables, skips the SARIF upload when the
  scan step did not produce a file, and uses `actions/setup-python@v6` and `codeql-action/upload-sarif@v4`
  (Node 24). Examples use `actions/checkout@v5`.
- CI now runs the Action (`uses: ./`) and the pre-commit hook exactly as users do.
- The demo is deterministic (its README output no longer drifts) and the quick start pins a release.

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
