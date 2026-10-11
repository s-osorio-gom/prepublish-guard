"""Finding records and redaction. A finding never carries the matched value itself, so reports, logs and
baselines can be shared without re-leaking what they describe:

* previews of personal data and local paths show no characters at all (type and length only); previews of
  secrets show at most the first two characters (usually the vendor prefix) and the length;
* the public fingerprint is derived with scrypt (memory-hard) from the value's hash, so it cannot be reversed by
  trying candidate values: an ID or phone number would take years on one core, not seconds. The plain value hash
  is internal only (grouping) and never printed.
"""

from __future__ import annotations

import functools
import hashlib
from dataclasses import asdict, dataclass, field

SEVERITIES = ("low", "medium", "high")
CATEGORIES = ("secret", "personal_data", "local_path", "confidential_term", "sensitive_file", "hygiene")


def value_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()


def mask(value: str, keep: int = 2) -> str:
    """Masked preview of a secret: at most the first `keep` characters, and nothing for short values."""
    v = value.strip()
    if len(v) <= 2 * keep + 4:
        return "*" * min(len(v), 8) or "*"
    return f"{v[:keep]}{'*' * min(len(v) - keep, 12)} ({len(v)} chars)"


def hidden(value: str) -> str:
    """Preview of personal data or a local path: no characters at all, only the length."""
    return f"[hidden, {len(value.strip())} chars]"


@functools.lru_cache(maxsize=65536)
def _public_fingerprint(rule: str, path: str, value_sha256: str) -> str:
    return hashlib.scrypt(value_sha256.encode(), salt=f"prepublish-guard/v1|{rule}|{path}".encode(),
                          n=2**14, r=8, p=1, dklen=8).hex()


@dataclass
class Finding:
    rule: str
    category: str
    severity: str
    path: str
    line: int
    preview: str
    message: str
    value_sha256: str
    commit: str | None = None          # first commit that added it (history scan)
    commits: int = 0                   # how many commits added it (history scan)
    in_working_tree: bool = True       # False: only found in history
    extra: dict = field(default_factory=dict)
    basis: str = ""                    # what the fingerprint identifies, when more than the value (never printed)

    @property
    def key(self) -> str:
        """Internal grouping key (never printed): rule + path + value hash."""
        return f"{self.rule}|{self.path}|{self.value_sha256}"

    @property
    def fingerprint(self) -> str:
        """Public, stable across line moves and re-scans, and not reversible by guessing (see module doc)."""
        return _public_fingerprint(self.rule, self.path, self.basis or self.value_sha256)

    def as_dict(self) -> dict:
        d = asdict(self)
        del d["value_sha256"], d["basis"]
        d["extra"] = {k: v for k, v in d["extra"].items() if not k.startswith("_")}   # internal bookkeeping
        d["fingerprint"] = self.fingerprint
        return d


def severity_at_least(severity: str, threshold: str) -> bool:
    return SEVERITIES.index(severity) >= SEVERITIES.index(threshold)
