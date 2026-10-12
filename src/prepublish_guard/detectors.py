"""Detectors. Each rule is precise first: a tool that cries wolf gets switched off, so placeholders, examples,
fictional ranges and environment lookups are not findings.

Line rules see one line at a time (so they work the same on files and on diff lines from the history);
file rules see a whole file (CSV columns, private-key blocks, sensitive file names).
"""

from __future__ import annotations

import csv
import io
import math
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import PurePosixPath

from .findings import Finding, hidden, mask, value_hash


@dataclass(frozen=True)
class Hit:
    rule: str
    category: str
    severity: str
    value: str
    message: str
    covers: frozenset[str] = frozenset()   # pii_column: hashes of the values the per-line rules find in it
    cells: frozenset[str] = frozenset()    # pii_column: hashes of its personal cells (accepting it is per content)
    column: int = -1                       # pii_column: position, so two columns with the same name stay apart
    bare: frozenset[str] = frozenset()     # pii_column: hashes of the personal cells no per-line rule reports


# ------------------------------------------------------------------------------------------------ helpers
# Whole-value placeholders only: a real password that merely starts with "foo", "bar", "my" or "the"
# ("football…", "barcelona…", "mypassword…", "Theodore…") is a finding, not a placeholder.
_NOUN = r"(?:key|token|secret|password|pass|pwd|api[_-]?key|access[_-]?key|value|id|here)"
_PLACEHOLDER = re.compile(
    r"(?i)^(?:x{3,}|\*{3,}|\.{3,}|<[^>]*>|\$\{[^}]*\}|\$[A-Z_][A-Z0-9_]*|\{\{[^}]*\}\}|%\([^)]*\)s|"
    r"(?:your|my|the)[_-]?(?:[a-z]+[_-]?){0,3}" + _NOUN + r"(?:[_-]?here)?|"
    r"changeme|change[_-]?me|placeholder|example\w*|sample\w*|dummy\w*|fake\w*|"
    r"test\d*|test[_-]?" + _NOUN + r"|redacted|secret|password|passw0rd|token|none|null|true|false|todo|tbd|n/?a|"
    r"0+|1234\d*|abc|abc123|abcdef|foo|bar|baz|qux|foobar)$")


def is_placeholder(value: str) -> bool:
    v = value.strip().strip("'\"`")
    return not v or bool(_PLACEHOLDER.match(v)) or len(set(v)) <= 2


_FAKE_MARKERS = ("your", "example", "sample", "dummy", "fake", "placeholder", "xxxx", "redacted", "changeme",
                 "insert", "here", "token", "notreal", "not-a", "not_a", "invalid", "test")


def looks_fake(token: str) -> bool:
    """Vendor-format strings that are obviously not real: AKIAIOSFODNN7EXAMPLE, xoxb-your-token, ghp_xxxx..."""
    low = token.lower()
    return any(m in low for m in _FAKE_MARKERS) or len(set(low[-12:])) <= 3


def entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {c: value.count(c) for c in set(value)}
    return -sum(n / len(value) * math.log2(n / len(value)) for n in counts.values())


def luhn_ok(digits: str) -> bool:
    total, parity = 0, len(digits) % 2
    for i, ch in enumerate(digits):
        d = int(ch)
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# ------------------------------------------------------------------------------------------------ secrets
_TOKEN_RULES: list[tuple[str, str, re.Pattern]] = [
    ("aws_access_key_id", "AWS access key id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", "GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b")),
    ("gitlab_token", "GitLab token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")),
    ("slack_token", "Slack token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b")),
    ("slack_webhook", "Slack incoming webhook",
     re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]{6,}/B[A-Z0-9]{6,}/[A-Za-z0-9]{16,}")),
    ("google_api_key", "Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("stripe_live_key", "Stripe live key", re.compile(r"\b(?:sk|rk)_live_[0-9A-Za-z]{20,}\b")),
    ("openai_key", "OpenAI API key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}\b|"
                                                 r"\bsk-proj-[A-Za-z0-9_-]{40,}\b")),
    ("anthropic_key", "Anthropic API key", re.compile(r"\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{20,}\b")),
    ("twilio_key", "Twilio API key", re.compile(r"\bSK[0-9a-f]{32}\b")),
    ("sendgrid_key", "SendGrid API key", re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b")),
    ("npm_token", "npm token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("pypi_token", "PyPI token", re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b")),
    ("telegram_bot_token", "Telegram bot token", re.compile(r"\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b")),
]
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,}\b")
_URL_PASSWORD = re.compile(r"\b[a-z][a-z0-9+.-]*://(?P<user>[^\s:/@'\"]+):(?P<pw>[^\s@/'\"]{3,})@[^\s/'\"]+")
_SECRET_NAME = (r"(?:[A-Za-z0-9]*[_.-])*(?:pass(?:word|wd)?|pwd|secret|token|api[_.-]?key|apikey|access[_.-]?key|"
                r"private[_.-]?key|client[_.-]?secret|auth[_.-]?token|credentials?|webhook[_.-]?url)"
                r"(?:[_.-][A-Za-z0-9]*)*")
_ASSIGN = re.compile(r"(?i)(?P<key>\b" + _SECRET_NAME + r")\b[\"']?\s*(?:=|:|:=|=>)\s*"
                     r"(?:(?P<q>[\"'`])(?P<qval>[^\"'`\n\\]{4,200})(?P=q)|(?P<val>[^\s#;,'\"`\\]{4,200}))")
_LOOKUP = re.compile(r"(?i)(environ|getenv|process\.env|secrets\.|vault|\$\{\{|\(|\[|os\.|config\.|settings\.)")
_CONFIG_SUFFIX = (".env", ".ini", ".cfg", ".conf", ".toml", ".yaml", ".yml", ".properties", ".json", ".tfvars",
                  ".sh", ".bash", ".zsh", ".ps1")
_CONFIG_NAMES = {"credentials", ".npmrc", ".pypirc", ".netrc", ".git-credentials", "config"}
_SHELL_ASSIGN = re.compile(r"^\s*(?:export|ENV|ARG|set|setx)\s")
# A value made only of identifier characters that itself names a secret ("user_password_hash",
# "prod/db/credentials-v2", "X-Api-Key-Header-Name") is a name, not a secret.
_IDENTIFIER_VALUE = re.compile(r"(?i)^[a-z0-9_./-]+$")
_SECRET_WORD = re.compile(r"(?i)pass(?:word|wd)?|secret|token|api[_.-]?key|credential|private[_.-]?key")


def _secret_line(line: str, path: str) -> Iterator[Hit]:
    specific: set[str] = set()
    for rule, label, rx in _TOKEN_RULES:
        for m in rx.finditer(line):
            if not is_placeholder(m.group(0)) and not looks_fake(m.group(0)):
                specific.add(m.group(0))
                yield Hit(rule, "secret", "high", m.group(0), f"{label} committed in plain text")
    for m in _JWT.finditer(line):
        yield Hit("jwt", "secret", "medium", m.group(0), "JSON Web Token committed in plain text")
    for m in _URL_PASSWORD.finditer(line):
        pw = m.group("pw")
        if not is_placeholder(pw) and not pw.startswith(("$", "{", "%", "<")) and "${" not in pw and "{{" not in pw:
            yield Hit("url_with_password", "secret", "high", pw, "password embedded in a connection URL")
    name = PurePosixPath(path).name.lower()
    is_config = (name.startswith((".env", "dockerfile")) or name.endswith(_CONFIG_SUFFIX) or name in _CONFIG_NAMES
                 or bool(_SHELL_ASSIGN.match(line)))
    for m in _ASSIGN.finditer(line):
        quoted, value = m.group("qval") is not None, (m.group("qval") or m.group("val") or "")
        if not (quoted or is_config) or is_placeholder(value) or looks_fake(value) or _LOOKUP.search(value):
            continue
        if _IDENTIFIER_VALUE.match(value) and _SECRET_WORD.search(value) and re.search(r"[_./-]", value):
            continue
        if any(t in value for t in specific) or _URL_PASSWORD.search(value):
            continue                                     # already reported by a more specific rule
        if value.lower().startswith(("http://", "https://")) and "webhook" not in m.group("key").lower():
            continue
        key = m.group("key").lower()
        min_len, min_entropy = (8, 2.5) if re.search(r"pass|pwd", key) else (12, 3.0)
        mixed = any(c.isdigit() for c in value) or any(c in "!@#$%^&*-_+=/" for c in value)
        if len(value) >= min_len and entropy(value) >= min_entropy and mixed:
            yield Hit("secret_assignment", "secret", "high", value,
                      f"literal value assigned to `{m.group('key')}`")


# ------------------------------------------------------------------------------------------- personal data
_EMAIL = re.compile(r"(?<![\w.%+-])(?P<local>[A-Za-z0-9][A-Za-z0-9._%+-]{0,63})@(?P<domain>(?:[A-Za-z0-9-]+\.)+"
                    r"[A-Za-z]{2,24})(?![\w-])")
_SAFE_EMAIL_DOMAINS = {"example.com", "example.org", "example.net", "users.noreply.github.com", "noreply.github.com",
                       "localhost", "test.com"}
_SAFE_EMAIL_SUFFIXES = (".example", ".test", ".invalid", ".localhost", ".local")
_SAFE_LOCALS = {"noreply", "no-reply", "donotreply", "do-not-reply", "git", "user", "username", "you", "name",
                "email", "someone", "info", "support", "security", "admin", "contact", "hello", "team"}
_ID_CONTEXT = re.compile(
    r"(?i)(?:\bc[ée]dula(?:\s+de\s+ciudadan[ií]a)?\b|\bC\.\s?C\.|\bCC\b(?=[\s:#.Nn°º-]*\d)|\bdni\b|\bnit\b|\brut\b|"
    r"\bssn\b|\bdocumento(?:\s+de\s+identidad)?\b|\bn[úu]mero\s+de\s+identificaci[óo]n\b|\bidentificaci[óo]n\b|"
    r"\bnational[ _-]?id\b|\bid[ _-]?number\b|\bpassport\b|\bpasaporte\b)"
    r"[^\d\n]{0,25}?(?P<num>\d{1,3}(?:[.\s]\d{3}){2,3}(?:-\d)?|\d{6,12}(?:-\d)?)(?!\d)")
_SSN = re.compile(r"(?<![\d-])(?P<a>\d{3})-(?P<g>\d{2})-(?P<s>\d{4})(?![\d-])")
_CO_MOBILE = re.compile(r"(?<![\d+])(?:\+?57[\s.-]?)?3\d{2}[\s.-]\d{3}[\s.-]?\d{4}(?!\d)|"
                        r"(?<![\d+])\+57[\s.-]?3\d{9}(?!\d)")
_INTL_PHONE = re.compile(r"(?<![\w+.-])(?:\+\d{1,3}[\s.-]?)?(?:\(\d{2,4}\)[\s.-]?|\d{3}[\s.-])\d{3}[\s.-]\d{4}"
                         r"(?![\w.-]\d|\d)")
_PHONE_CONTEXT = re.compile(r"(?i)\b(?:tel[ée]fono|tel|cel(?:ular)?|m[óo]vil|phone|mobile|whats?app|contacto|call)\b")
_CARD = re.compile(r"(?<![\d.,-])(?:\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{1,7}|\d{4}[ -]\d{6}[ -]\d{5}|\d{13,19})(?![\d.,-])")


def _card_brand(digits: str) -> str | None:
    """Issuer ranges and lengths (Visa, Mastercard, Amex, Discover, JCB, Diners); None if it is not a card shape."""
    n, d2, d4 = len(digits), int(digits[:2]), int(digits[:4])
    if digits[0] == "4" and n in (13, 16, 19):
        return "visa"
    if (51 <= d2 <= 55 or 2221 <= d4 <= 2720) and n == 16:
        return "mastercard"
    if d2 in (34, 37) and n == 15:
        return "amex"
    if (digits.startswith("6011") or d2 == 65) and n in (16, 19):
        return "discover"
    if 3528 <= d4 <= 3589 and n in (16, 19):
        return "jcb"
    if d2 in (36, 38) and n == 14:
        return "diners"
    return None


# "hero@2x.jpg" in CSS or HTML is a retina image name, not an address: a "domain" ending in a file extension.
_ASSET_TLDS = {"jpg", "jpeg", "png", "gif", "webp", "avif", "svg", "ico", "bmp", "css", "js", "mjs", "map", "woff",
               "woff2", "ttf", "otf", "eot", "mp4", "webm", "mp3", "pdf"}


def _safe_email(local: str, domain: str) -> bool:
    d, lo = domain.lower(), local.lower()
    return (d in _SAFE_EMAIL_DOMAINS or d.endswith(_SAFE_EMAIL_SUFFIXES) or lo in _SAFE_LOCALS
            or d.rsplit(".", 1)[-1] in _ASSET_TLDS
            or "noreply" in lo or "no-reply" in lo or d.split(".")[0] in ("example", "mail-example"))


def _fictional_phone(text: str) -> bool:
    digits = re.sub(r"\D", "", text)
    return bool(re.search(r"555(01\d\d)$", digits)) or len(set(digits[-7:])) <= 2


def _personal_line(line: str, path: str, allowed_email_domains: set[str]) -> Iterator[Hit]:
    for m in _EMAIL.finditer(line):
        if line[m.end():m.end() + 1] == ":" and m.group("local").lower() == "git":
            continue
        token_start = max(line.rfind(" ", 0, m.start()), line.rfind("\"", 0, m.start()), line.rfind("'", 0, m.start()))
        if "://" in line[token_start + 1:m.start()]:
            continue                                     # user:password@host in a URL, not an e-mail address
        domain = m.group("domain").lower()
        if _safe_email(m.group("local"), domain) or domain in allowed_email_domains:
            continue
        yield Hit("email_address", "personal_data", "medium", m.group(0), "personal e-mail address")
    for m in _ID_CONTEXT.finditer(line):
        num = re.sub(r"[.\s]", "", m.group("num"))
        if len(set(num.replace("-", ""))) > 2:
            yield Hit("national_id", "personal_data", "high", m.group("num"),
                      "national identity / tax number (cédula, NIT, DNI, SSN, passport)")
    for m in _SSN.finditer(line):
        a, g, s = m.group("a"), m.group("g"), m.group("s")
        if a not in ("000", "666") and not a.startswith("9") and g != "00" and s != "0000" and \
                not re.search(r"(?i)\b(version|v\d|date|iso|isbn)\b", line):
            yield Hit("us_ssn", "personal_data", "high", m.group(0), "US social security number format")
    phones = set()
    for m in _CO_MOBILE.finditer(line):
        if not _fictional_phone(m.group(0)):
            phones.add(m.group(0))
            yield Hit("phone_number", "personal_data", "medium", m.group(0), "Colombian mobile number")
    if _PHONE_CONTEXT.search(line) or line.lstrip().startswith(("+", "(")):
        for m in _INTL_PHONE.finditer(line):
            if m.group(0) not in phones and not _fictional_phone(m.group(0)) and \
                    not any(m.group(0) in p or p in m.group(0) for p in phones):
                yield Hit("phone_number", "personal_data", "medium", m.group(0), "phone number")
    for m in _CARD.finditer(line):
        digits = re.sub(r"\D", "", m.group(0))
        if _card_brand(digits) and luhn_ok(digits) and len(set(digits)) > 3 and \
                digits not in ("4111111111111111", "4242424242424242", "5555555555554444", "378282246310005",
                               "6011111111111117", "4012888888881881", "5105105105105100"):
            yield Hit("payment_card", "personal_data", "high", m.group(0), "payment card number (passes Luhn)")


# -------------------------------------------------------------------------------------------- local paths
_UNIX_HOME = re.compile(r"(?:(?<=file://)|(?<![\w/.:~-]))/(?:Users|home)/(?P<user>[^/\s\"'`<>$:;{}()\[\]\\|*+?^]+)/")
_WIN_HOME = re.compile(r"(?i)(?<![\w])[A-Z]:(?:\\\\|\\|/)+Users(?:\\\\|\\|/)+(?P<user>[^\\/\s\"'`<>%:;{}]+)(?:\\|/)")
_GENERIC_USERS = {"user", "username", "user_name", "yourname", "your_name", "your-name", "you", "me", "name",
                  "runner", "example", "someone", "default", "public", "all users", "ubuntu", "vscode", "jovyan",
                  "shared", "linuxbrew", "admin", "root", "node", "app", "dev", "developer", "builder", "travis",
                  "circleci", "jenkins", "codespace", "gitpod", "<user>", "$user", "%username%"}


def _path_line(line: str) -> Iterator[Hit]:
    for rx in (_UNIX_HOME, _WIN_HOME):
        for m in rx.finditer(line):
            user = m.group("user")
            if user.lower() in _GENERIC_USERS or user.startswith(("$", "%", "<", "{")):
                continue
            yield Hit("personal_path", "local_path", "low", m.group(0),
                      "absolute path with a personal user name (reveals who and where)")


# ------------------------------------------------------------------------------------------- line scanning
def scan_line(line: str, path: str, *, confidential: list[re.Pattern] | None = None,
              allowed_email_domains: set[str] | None = None) -> list[Hit]:
    if len(line) > 5000:                 # minified or generated content: scan the start only
        line = line[:5000]
    hits = list(_secret_line(line, path))
    hits += list(_personal_line(line, path, allowed_email_domains or set()))
    hits += list(_path_line(line))
    for rx in confidential or []:
        for m in rx.finditer(line):
            hits.append(Hit("confidential_term", "confidential_term", "medium", m.group(0),
                            "configured confidential name (employer, client, project)"))
    return hits


def term_pattern(term: str) -> re.Pattern:
    words = [re.escape(w) for w in term.split()]
    return re.compile(r"(?i)(?<![A-Za-z0-9])" + r"[\s_.-]*".join(words) + r"(?![A-Za-z0-9])")


# ------------------------------------------------------------------------------------------- file scanning
_PEM = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----"
                  r"[ \t]*(?:\r?\n|\\n)(?:[ \t]*[A-Za-z-]+:[^\n\\]*(?:\r?\n|\\n))*(?:[ \t]*(?:\r?\n|\\n))?"
                  r"[ \t]*[A-Za-z0-9+/=]{40,}")
_SENSITIVE_NAMES: list[tuple[re.Pattern, str, str, str]] = [
    (re.compile(r"(?i)^(?:id_rsa|id_dsa|id_ecdsa|id_ed25519)$"), "ssh_private_key_file", "high",
     "SSH private key file"),
    (re.compile(r"(?i)\.(?:pem|key|p12|pfx|jks|keystore|ppk)$"), "key_material_file", "medium",
     "key or certificate store file"),
    (re.compile(r"(?i)^\.env(?:\.(?!example|sample|template|dist)[\w.-]+)?$"), "dotenv_file", "medium",
     "environment file (usually holds credentials)"),
    (re.compile(r"(?i)^(?:credentials|client_secret[\w-]*|service[_-]?account[\w-]*)\.json$"), "credentials_file",
     "high", "cloud credentials file"),
    (re.compile(r"(?i)^\.(?:npmrc|pypirc|netrc|git-credentials)$"), "auth_config_file", "medium",
     "authentication config file"),
    (re.compile(r"(?i)\.(?:sqlite3?|db|dump|bak)$"), "database_file", "low", "database or backup file"),
]
_PII_COLUMN = re.compile(r"(?i)^(?:c[ée]dula|cc|documento|numero_documento|n[uú]mero_de_documento|identificaci[oó]n|"
                         r"dni|nit|ssn|national_id|id_number|pasaporte|passport|tel[ée]fono|telefono|phone|"
                         r"phone_number|celular|mobile|movil|m[oó]vil|email|e-mail|correo|correo_electr[oó]nico)$")


def scan_file_level(path: str, text: str, allowed_email_domains: set[str] | None = None, *, strict_rows: bool = False,
                    allowed: Callable[[str], bool] | None = None) -> list[Hit]:
    """File-level rules. `strict_rows` (history hunks, which may start inside a quoted cell) keeps only the table
    rows shaped like the header; `allowed` (allow_regex) leaves matching cells out of `Hit.bare`."""
    hits: list[Hit] = []
    for m in _PEM.finditer(text):
        hits.append(Hit("private_key", "secret", "high", m.group(0)[:80], "private key block"))
    name = PurePosixPath(path).name
    for rx, rule, sev, label in _SENSITIVE_NAMES:
        if rx.search(name):
            hits.append(Hit(rule, "sensitive_file", sev, path, f"{label} is tracked in the repository"))
            break
    if name.lower().endswith((".csv", ".tsv")):
        hits += _csv_columns(path, text, allowed_email_domains or set(), strict_rows, allowed)
    return hits


CSV_MAX_CHARS = 2_000_000                  # a table's columns are read from its first CSV_MAX_CHARS characters


def _csv_columns(path: str, text: str, allowed_email_domains: set[str], strict_rows: bool = False,
                 allowed: Callable[[str], bool] | None = None) -> list[Hit]:
    try:
        delimiter = "\t" if path.lower().endswith(".tsv") else ","
        rows = list(csv.reader(io.StringIO(text[:CSV_MAX_CHARS]), delimiter=delimiter))
    except csv.Error:
        return []
    if len(rows) < 2:
        return []
    data = [r for r in rows[1:] if len(r) == len(rows[0])] if strict_rows else rows[1:]
    cols = [i for i, h in enumerate(rows[0]) if _PII_COLUMN.match(h.strip().replace(" ", "_"))]
    hits = []
    for i in cols:
        values = [r[i] for r in data if i < len(r) and r[i].strip()]
        real = [v for v in values if _personal_cell(v, allowed_email_domains)]
        if real:
            covers = {value_hash(h.value) for v in values
                      for h in _personal_line(v, path, allowed_email_domains)}
            bare = frozenset(value_hash(v.strip()) for v in real
                             if next(_personal_line(v, path, allowed_email_domains), None) is None
                             and not (allowed and allowed(v.strip())))
            hits.append(Hit("pii_column", "personal_data", "high", rows[0][i],
                            f"column `{rows[0][i].strip()}` holds {len(real)} personal value(s)", frozenset(covers),
                            frozenset(value_hash(v.strip()) for v in real), i, bare))
    return hits


def _personal_cell(value: str, allowed_email_domains: set[str]) -> bool:
    """A cell counts as personal when the per-line rules report something in it (so example, test and noreply
    domains, `allowed_email_domains` and URL user names do not count), or when it holds an ID or phone-length
    number besides any e-mail address."""
    if next(_personal_line(value, "", allowed_email_domains), None) is not None:
        return True
    return len(re.sub(r"\D", "", _EMAIL.sub("", value))) >= 7


def to_finding(hit: Hit, path: str, line: int) -> Finding:
    if hit.category == "sensitive_file":
        preview = path
    elif hit.rule == "pii_column":
        preview = hit.value                                  # column names, not values
    elif hit.category in ("personal_data", "local_path"):
        preview = hidden(hit.value)                          # a few characters + length can be enough to guess it
    else:
        preview = mask(hit.value)
    identity = f"{hit.value}\0{hit.column}" if hit.rule == "pii_column" else hit.value
    finding = Finding(rule=hit.rule, category=hit.category, severity=hit.severity, path=path, line=line,
                      preview=preview, message=hit.message, value_sha256=value_hash(identity))
    if hit.covers:
        finding.extra["_covers"] = set(hit.covers)           # internal, removed before any report
    if hit.cells:
        finding.extra["_cells"] = set(hit.cells)             # sealed into the fingerprint by scanner.full_scan
    if hit.bare:
        finding.extra["_bare"] = set(hit.bare)               # history: removed bare IDs (scanner.full_scan)
    return finding


LineScanner = Callable[[str, str], list[Hit]]
