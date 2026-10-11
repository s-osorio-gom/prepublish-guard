# prepublish-guard

**Check a repository for secrets and personal data before you push it or make it public. It checks the current files and the whole git history.**

```bash
prepublish-guard scan . --history
```

[![CI](https://github.com/s-osorio-gom/prepublish-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/s-osorio-gom/prepublish-guard/actions/workflows/ci.yml) ![deps](https://img.shields.io/badge/dependencies-none-blue) ![python](https://img.shields.io/badge/python-3.11%2B-blue)

## Why

Most leaks are accidents. Someone hard-codes a token while testing, puts a CSV of clients in `data/`, or leaves a
notebook output showing `C:\Users\<name>\...`. Deleting the line in a later commit does not fix it: **the value stays
in the git history**, and anyone who clones the repository can read it.

This tool was built after a portfolio audit found exactly that: a national ID number that had been removed from a
README but was still in the history. General-purpose secret scanners miss that kind of finding, because they
know little about personal data formats, and even less about Colombian ones (cédula, NIT, mobile numbers).

## What it finds

| Category | Examples | Severity |
|---|---|---|
| **Secrets** | AWS, GitHub, GitLab, Slack, Google, Stripe, OpenAI, Anthropic, Twilio, SendGrid, npm, PyPI and Telegram tokens; private key blocks (including encrypted ones); passwords inside connection URLs; literal values assigned to `password`, `token`, `api_key`, `client_secret`… | high |
| **Personal data** | national IDs with context (cédula, C.C., NIT, DNI, SSN, passport); payment cards that pass the Luhn check; CSV/TSV columns of IDs, phones or e-mails | high |
| | personal e-mail addresses; Colombian mobile numbers and other phone numbers | medium |
| **Local paths** | `/Users/<name>/`, `/home/<name>/`, `C:\Users\<name>\` with a real user name | low |
| **Confidential terms** | employer, client or project names you list in the config | medium |
| **Sensitive files** | `id_rsa`, `credentials.json`, `.env`, key stores, `.npmrc`/`.pypirc`, database dumps | low–high |
| **Hygiene** | no `LICENSE` file | low |

**It is precise first.** A tool that cries wolf gets switched off. So it ignores placeholders (`<your-key>`, `${VAR}`,
`changeme`, `AKIAIOSFODNN7EXAMPLE`), example, test and noreply e-mail domains, environment lookups
(`os.environ[...]`, `${{ secrets.X }}`), documented test card numbers, the fictional 555-01xx phone range, generic
home folders (`/home/user`, `/home/runner`) and its own config file.

## Guarantees

- **It never prints what it finds.**
  - Personal data and local paths appear only as their type and length (`[hidden, 28 chars]`).
  - Secrets show at most their first two characters, usually the vendor prefix (`gh************ (40 chars)`).
  - The fingerprint that identifies a finding (for baselines and code scanning) is derived with scrypt, a
    deliberately slow, memory-hard function. Recovering an ID or phone number from it by trying candidates would
    take years on one core.
  - You can paste a report into an issue or a CI log without leaking the values again.
- **It is read-only and offline.** It modifies nothing, sends nothing and never rewrites history. When something
  is only in the history, it explains what to do (rotate first, then `git filter-repo`), and leaves the decision to
  you.
- **It has no dependencies.** It uses the Python 3.11+ standard library and `git`.

## Quick start

```bash
pip install "git+https://github.com/s-osorio-gom/prepublish-guard@v0.1.1"   # or: pipx install .
prepublish-guard scan .                      # files that a push would publish (tracked files)
prepublish-guard scan . --history            # ...and every line ever added, on every branch and tag
prepublish-guard scan . --format sarif --output results.sarif   # for GitHub code scanning
prepublish-guard rules                       # what is detected
```

Exit codes:
- `0`: nothing at or above `--fail-on` (default `medium`).
- `1`: findings at or above it.
- `2`: a usage or configuration error.

Report formats: `text`, `markdown` (for a PR comment), `json` and `sarif` (SARIF 2.1.0).

## Example

`examples/demo.sh` builds a throwaway repository with typical mistakes (every value is fabricated), and then
"fixes" them in a second commit. The working-tree scan looks clean:

```
prepublish-guard 0.1.1: 0 finding(s) [high 0, medium 0, low 0] in 3 file(s)
```

The history scan shows that nothing was actually removed:

```
prepublish-guard 0.1.1: 7 finding(s) [high 5, medium 1, low 1] in 3 file(s) and 2 commit(s)

== secret (3)
  [HIGH  ] HISTORY settings.py:1 (first added in 68dd34f53d)  url_with_password: password embedded in a connection URL  -> Su********* (11 chars)  #c9c46fe878bed13f
  [HIGH  ] HISTORY settings.py:2 (first added in 68dd34f53d)  github_token: GitHub token committed in plain text  -> gh************ (40 chars)  #bb89af0ac19d744a
  [HIGH  ] HISTORY settings.py:3 (first added in 68dd34f53d)  aws_access_key_id: AWS access key id committed in plain text  -> AK************ (20 chars)  #72e2ef3d5fdcfa37
  what to do: Revoke or rotate it at the provider first: once pushed, deleting it from the code does not make it safe. ...

== personal data (3)
  [HIGH  ] HISTORY clientes.csv (first added in 68dd34f53d)  pii_column: column `cedula` holds 2 personal value(s)  -> cedula  #6ac615806a97875e
  [HIGH  ] HISTORY clientes.csv (first added in 68dd34f53d)  pii_column: column `celular` holds 2 personal value(s)  -> celular  #1383a8e8cec79266
  [MEDIUM] HISTORY README.md:3 (first added in 68dd34f53d)  email_address: personal e-mail address  -> [hidden, 28 chars]  #e42afd2dffdbc515
  what to do: Remove it or replace it with fictional data. ...

== local path (1)
  [LOW   ] HISTORY README.md:2 (first added in 68dd34f53d)  personal_path: absolute path with a personal user name (reveals who and where)  -> [hidden, 16 chars]  #2036ac579c3a4920
  what to do: Replace the absolute path with a relative one, a setting or an environment variable.

Found only in the git history. Removing it from the current files is not enough: (1) rotate it if it is a
credential; (2) rewrite the history, e.g. `git filter-repo --replace-text replacements.txt` ...
```

A value repeated in many places counts as one finding, listed with all its lines. For example, a local path that
appears in 105 notebook cells is reported once, not 105 times.

## Use it before every commit, and in CI

**pre-commit.** Add this to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/s-osorio-gom/prepublish-guard
    rev: v0.1.1
    hooks:
      - id: prepublish-guard
```

The hook scans the whole working copy, including untracked files that are not git-ignored, so a stray file with a
token blocks the commit even if you did not stage it.

**GitHub Actions.** The results appear in the repository's *Security → Code scanning* tab:

```yaml
- uses: actions/checkout@v5
  with: { fetch-depth: 0 }          # full history
- uses: s-osorio-gom/prepublish-guard@v0.1.1
  with: { history: "true" }
```

A complete workflow is in [`examples/github-workflow.yml`](examples/github-workflow.yml). Uploading to code scanning
needs `permissions: security-events: write`, and on private repositories GitHub Advanced Security; without it, pass
`upload-sarif: "false"` and the job still fails on findings.

## Configuration

`.prepublish-guard.toml` at the repository root is optional:

```toml
confidential_terms = ["Acme Bank", "Project Falcon"]   # names that must never be published
allowed_email_domains = ["mycompany.com"]              # e-mails you publish on purpose
allow_paths = ["tests/fixtures/*"]                     # glob patterns to skip
allow_regex = ["support@mycompany\\.com"]              # matches (or whole lines) never reported
fail_on = "medium"                                     # low | medium | high | never
```

`prepublish-guard baseline . --history` accepts the current findings. It writes only their fingerprints to `ignore`,
never the values. After that, only new findings fail the check. Accepting a CSV column finding accepts the values the
column holds now: a new value in that column reports the column again.

## How well it works

**Labelled evaluation.** The tool was evaluated on 24 hand-labelled publication bundles: dev 6, validation 10,
test 8. The cases include real-looking leaks and tricky negatives (placeholders, example addresses, relative
paths, generic homes). They live outside this repository, but they were visible while the tool was developed, so
the figures below are agreement on a known suite, not a held-out estimate ([details](docs/EVALUATION.md)).

| Issue type | Precision | Recall |
|---|---|---|
| secrets | 1.00 | 1.00 (4/4) |
| personal data | 1.00 | 0.83 (5/6) |
| local paths | 1.00 | 1.00 (4/4) |
| confidential terms | 1.00 | 1.00 (3/3) |
| missing license | 1.00 | 1.00 (3/3) |
| **overall** | **1.00** | **0.95 (19/20)** |

The only miss was a phone number in the fictional 555-01xx range. The suite used it to stand for a real number;
the tool ignores that range on purpose, because such numbers are never real. Details:
[`docs/EVALUATION.md`](docs/EVALUATION.md).

**On a real repository.** On the author's own portfolio repository (98 files, 7 commits) it reported 26 findings,
which the author then cleaned from the files and the history:
- a national ID that survives only in the git history, with the commit that added it;
- e-mail addresses in exported datasets and notebook outputs;
- a local user path repeated in 105 notebook cells (reported as 4 findings, one per notebook);
- the missing license.

## Limits

- It uses pattern matching, not live verification. It does not check whether a token still works.
  For exhaustive secret coverage, also run a dedicated scanner (gitleaks, TruffleHog). This tool's strengths are
  personal data, publication hygiene and reports you can share.
- It does not read images, PDFs, spreadsheets or other binaries. Their file names are still checked.
- Text files larger than `max_file_bytes` (default 2 MB) are scanned up to that size, and the report says so.
- A shallow clone has an incomplete history. The report says so; in CI use `actions/checkout` with
  `fetch-depth: 0`.
- In a table already reported for its personal columns (`pii_column`), the individual values of those columns are
  not listed one by one.
- On very large histories, `--max-commits N` limits the scan to the newest commits.
- E-mails in datasets you publish on purpose need `allowed_email_domains`, `allow_paths` or a `baseline`.

## Development

```bash
pip install -e ".[dev]"
pytest -q            # 72 tests
ruff check .
bash examples/demo.sh /tmp/pg-demo
```

The project has no runtime dependencies. Each detector has positive cases and look-alike negative cases in
`tests/test_detectors.py`, and end-to-end tests on real temporary git repositories are in
`tests/test_scan_and_cli.py`. Those tests also assert that no report contains a raw value.
`tests/test_release_review.py` reproduces each finding of the independent pre-release review.

## En español (resumen)

`prepublish-guard` revisa un repositorio antes de publicarlo. Revisa los archivos y todo el historial de git, y
busca:
- credenciales;
- datos personales: cédulas, NIT, celulares colombianos, correos, tarjetas y columnas de datos personales en CSV;
- rutas locales con tu usuario;
- nombres confidenciales;
- la falta de licencia.

Nunca muestra los valores encontrados: los datos personales aparecen solo como tipo y longitud. No modifica nada
y no envía nada. Cuando algo solo está en el historial,
explica cómo revocarlo y limpiarlo.

## License

MIT (see [`LICENSE`](LICENSE)).
