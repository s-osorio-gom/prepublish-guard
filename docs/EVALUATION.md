# Evaluation

## Labelled suite (not a held-out estimate)

The suite has 24 hand-labelled publication bundles: dev 6, validation 10, test 8. It belongs to the lab that
built this tool (agentic-solutions-lab, a separate repository by the same author), where it is kept apart from
the code under evaluation.

**Read these figures as agreement on a suite the developer could see, not as a held-out estimate.** The product
was built in the lab's repository, where the suite also lives; the lab's self-scan read it during development;
and one of the false positives fixed during development (the `xoxb-your-token` placeholder below) appears only in
a test case. A held-out estimate needs new cases that the developer never saw; that is the next step for this
product.

How it was run:
1. Each bundle is written to a throwaway git repository.
2. The CLI scans it: `prepublish-guard scan <repo> --format json`.
3. The issue types the CLI reports are compared with the labels.

Unsupported marketing claims are part of the suite but out of this tool's scope, so they are excluded.
The evaluation script lives in the lab's repository. Its output for this release is included here as
[`evaluation-results.json`](evaluation-results.json): overall and per-issue counts, per-split agreement, and per
case the outcome (labels only for the dev cases, so the validation and test answers stay private). The figures
were re-run after the pre-release review fixes and did not change.

| Issue type | TP | FP | FN | Precision | Recall |
|---|---|---|---|---|---|
| secret | 4 | 0 | 0 | 1.00 | 1.00 |
| personal data | 5 | 0 | 1 | 1.00 | 0.83 |
| local path | 4 | 0 | 0 | 1.00 | 1.00 |
| confidential term | 3 | 0 | 0 | 1.00 | 1.00 |
| missing license | 3 | 0 | 0 | 1.00 | 1.00 |
| **overall** | **19** | **0** | **1** | **1.00** | **0.95** |

Exact per-case agreement: dev 6/6, validation 9/10, test 8/8.

**The miss.** `review-val-04` labels a person's phone number in a README. The number is in the NANP 555-01xx
range, which is reserved for fiction; the suite used it to stand for a real number. The tool deliberately ignores
that range, so this is a documented design choice, not a detector bug.

**False positives found during development**, all fixed and covered by tests:
- the tool scanned its own config file, which lists the confidential terms, and flagged them;
- example vendor tokens (`AKIAIOSFODNN7EXAMPLE`, `xoxb-your-token`) were reported as real;
- a regular expression in source code was taken for a personal path;
- a 13-digit number was taken for a card number (now issuer ranges and lengths are checked as well as Luhn);
- `user:password@host` in a URL was also reported as an e-mail address.

## Real repositories

| Repository | Files / commits | Findings | Notes |
|---|---|---|---|
| author's portfolio repository | 98 / 7 | 26 | a national ID present only in the history (with the commit that added it); e-mails in exported datasets and notebook outputs; a local user path repeated in 105 notebook cells, reported as 4 findings; no license |
| agentic-solutions-lab | 239 / – | 1 | a fabricated home path in a test fixture (labelled fixtures are silenced with `allow_paths`) |
| this repository | 18 / 1 | 0 | tests and examples are allow-listed because they hold fabricated values on purpose |

## Tests

There are 68 tests:
- each detector has positive cases and look-alike negative cases;
- end-to-end tests run on real temporary git repositories (working tree vs history, deleted CSVs, ignored files,
  baselines, allow-lists, binary files);
- every report format is checked to contain no raw value;
- `tests/test_release_review.py` reproduces each finding of the independent pre-release review: previews and
  fingerprints that could be reversed into personal data, leaks that were missed, history file names with spaces,
  accents or quotes, large files, false positives, configuration type mistakes, shallow clones.
