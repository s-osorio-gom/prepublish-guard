"""Reports: human text, Markdown (for a PR comment), JSON and SARIF 2.1.0 (GitHub code scanning). Every format
shows masked previews only."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from . import __version__
from .findings import Finding
from .scanner import ScanResult

REMEDIATION = {
    "secret": "Revoke or rotate it at the provider first: once pushed, deleting it from the code does not make it "
              "safe. Then move it to an environment variable or a secret manager.",
    "personal_data": "Remove it or replace it with fictional data. Personal data of real people should not be in a "
                     "public repository (Colombian Law 1581 of 2012, GDPR).",
    "local_path": "Replace the absolute path with a relative one, a setting or an environment variable.",
    "confidential_term": "Remove or anonymise the name unless publishing it is authorised.",
    "sensitive_file": "Remove the file from the repository (git rm --cached) and add it to .gitignore; rotate any "
                      "credential it contained.",
    "hygiene": "Add a LICENSE file so others know how they may reuse the code.",
}
HISTORY_REMEDIATION = (
    "Found only in the git history. Removing it from the current files is not enough: (1) rotate it if it is a "
    "credential; (2) rewrite the history, e.g. `git filter-repo --replace-text replacements.txt` (keep a backup and "
    "coordinate with collaborators), then force-push; (3) if the repository was ever public, ask GitHub Support to "
    "purge cached views and pull-request refs. This tool never rewrites history for you.")
_LEVEL = {"high": "error", "medium": "warning", "low": "note"}


def summary(res: ScanResult) -> dict:
    by_sev = Counter(f.severity for f in res.findings)
    return {"files_scanned": res.files_scanned, "commits_scanned": res.commits_scanned,
            "findings": len(res.findings),
            "occurrences": sum(int(f.extra.get("occurrences", 1)) for f in res.findings),
            "high": by_sev["high"], "medium": by_sev["medium"], "low": by_sev["low"],
            "only_in_history": sum(not f.in_working_tree for f in res.findings), "suppressed": res.suppressed}


def _where(f: Finding) -> str:
    loc = f"{f.path}:{f.line}" if f.line else f.path
    more = int(f.extra.get("occurrences", 1)) - 1
    if more > 0:
        loc += f" (+{more} more line{'s' if more > 1 else ''})"
    if f.commit:
        loc += f" (first added in {f.commit[:10]}" + (f", {f.commits} commits)" if f.commits > 1 else ")")
    return loc


def to_text(res: ScanResult) -> str:
    s = summary(res)
    lines = [f"prepublish-guard {__version__}: {s['findings']} finding(s) "
             f"[high {s['high']}, medium {s['medium']}, low {s['low']}] in {s['files_scanned']} file(s)"
             + (f" and {s['commits_scanned']} commit(s)" if s["commits_scanned"] else "")
             + (f"; {s['suppressed']} accepted" if s["suppressed"] else "")]
    for category in REMEDIATION:
        group = [f for f in res.findings if f.category == category]
        if not group:
            continue
        lines += ["", f"== {category.replace('_', ' ')} ({len(group)})"]
        for f in group:
            tag = "HISTORY " if not f.in_working_tree else ""
            lines.append(f"  [{f.severity.upper():6}] {tag}{_where(f)}  {f.rule}: {f.message}  -> {f.preview}"
                         f"  #{f.fingerprint}")
        lines.append(f"  what to do: {REMEDIATION[category]}")
    if any(not f.in_working_tree for f in res.findings):
        lines += ["", HISTORY_REMEDIATION]
    lines += [f"note: {n}" for n in res.notes]
    if not res.findings:
        lines += ["", "No findings. Review the diff yourself anyway: no scanner sees everything."]
    return "\n".join(lines) + "\n"


def to_markdown(res: ScanResult) -> str:
    s = summary(res)
    out = ["## prepublish-guard report", "",
           f"**{s['findings']} finding(s)** — high {s['high']}, medium {s['medium']}, low {s['low']} · "
           f"{s['files_scanned']} files" + (f", {s['commits_scanned']} commits" if s["commits_scanned"] else ""), ""]
    if res.findings:
        out += ["| Severity | Where | Rule | Preview | Fingerprint |", "|---|---|---|---|---|"]
        for f in res.findings:
            hist = " (history only)" if not f.in_working_tree else ""
            out.append(f"| {f.severity} | `{_where(f)}`{hist} | {f.rule} | `{f.preview}` | `{f.fingerprint}` |")
        out += ["", "**What to do**", ""]
        out += [f"- *{c.replace('_', ' ')}*: {REMEDIATION[c]}" for c in REMEDIATION
                if any(f.category == c for f in res.findings)]
        if any(not f.in_working_tree for f in res.findings):
            out += [f"- *history*: {HISTORY_REMEDIATION}"]
    else:
        out.append("No findings.")
    return "\n".join(out) + "\n"


def to_json(res: ScanResult) -> str:
    # Only the directory name: the absolute path would carry the local user name, the very thing reports must not.
    return json.dumps({"tool": "prepublish-guard", "version": __version__, "root": Path(res.root).name,
                       "summary": summary(res),
                       "findings": [f.as_dict() for f in res.findings], "notes": res.notes}, indent=2,
                      ensure_ascii=False) + "\n"


def to_sarif(res: ScanResult) -> str:
    rules = {}
    for f in res.findings:
        rules.setdefault(f.rule, {"id": f.rule, "name": f.rule, "shortDescription": {"text": f.message},
                                  "help": {"text": REMEDIATION.get(f.category, "")},
                                  "properties": {"category": f.category, "security-severity":
                                                 {"high": "8.0", "medium": "5.0", "low": "2.0"}[f.severity]}})
    results = []
    for f in res.findings:
        region = {"startLine": max(1, f.line)}
        msg = f"{f.message} ({f.preview})" + ("; found only in git history, first added in " + (f.commit or "?")
                                              if not f.in_working_tree else "")
        related = [{"id": i, "physicalLocation": {"artifactLocation": {"uri": f.path}, "region": {"startLine": n}}}
                   for i, n in enumerate(f.extra.get("lines", [])[1:20], 1)]
        results.append({"ruleId": f.rule, "level": _LEVEL[f.severity], "message": {"text": msg},
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.path},
                                                            "region": region}}],
                        **({"relatedLocations": related} if related else {}),
                        "partialFingerprints": {"prepublishGuard/v1": f.fingerprint}})
    sarif = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
             "runs": [{"tool": {"driver": {"name": "prepublish-guard", "version": __version__,
                                           "informationUri": "https://github.com/s-osorio-gom/prepublish-guard",
                                           "rules": list(rules.values())}},
                       "results": results}]}
    return json.dumps(sarif, indent=2, ensure_ascii=False) + "\n"


FORMATS = {"text": to_text, "markdown": to_markdown, "json": to_json, "sarif": to_sarif}
