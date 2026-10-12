# Changelog

## Unreleased (0.1.2)

- **Fixed the known limitation of 0.1.0 and 0.1.1.** In history, a bare ID number found only through its column
  (`cedula`, `documento`, ...) and later removed from a table that still exists is now reported as
  `pii_history_rows`. This includes IDs added in a commit that did not touch the header line.

  When the whole table was later deleted, nothing changes in how it is reported: its history column finding (`pii_column`) covers
  those IDs, as it already did for e-mails. An ID added without the header now also changes that finding's
  fingerprint.

  Each case has a test in `tests/test_0_1_2.py`.
- **How it reads the header.** A commit that only adds rows keeps the header of the table's previous version. The
  header comes from the diff itself (`--full-index`), as the first complete CSV record, so a quoted name may hold a
  line break. Git is asked for it only when that version was not seen, for example with `--max-commits`.

  When a commit changes the header of an existing table, git returns that whole version (header changes are rare). That
  way, rows the commit did not touch also count once their column becomes personal.
- **Which rows are read.** History rows whose shape does not match the header are skipped, such as a change that
  starts inside a quoted multi-line cell.
- **Which cells are compared.** Only cells that no per-line rule reports, leaving out hits `allow_regex` accepts. So a
  removed e-mail is counted once, as before. `allow_regex` applies to removed IDs, matched against the cell or the
  whole row.
- **Long CSV/TSV files.** When a file is longer than 2,000,000 characters (possible when `max_file_bytes` is raised),
  only that first part is checked for personal columns. The report says so, and the file's removed values are not
  compared.
- **Upgrading from 0.1.1.** A 0.1.1 baseline reports again two kinds of table, because their fingerprint now covers
  values 0.1.1 did not see:
  - tables whose history held a bare ID that is no longer there;
  - deleted tables that received rows without their header.

  Review them and take the baseline again.

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
