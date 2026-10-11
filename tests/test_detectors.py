"""Detectors: what must be found, and the look-alikes that must not be (a noisy tool gets switched off).

Every "secret" below is fabricated for the test; the strings are assembled at runtime so that this file itself
does not trip secret scanners."""

import pytest

from prepublish_guard.detectors import entropy, looks_fake, luhn_ok, scan_file_level, scan_line
from prepublish_guard.findings import mask

GH = "ghp_" + "R7tK2pXv9LmQ4sWz" + "8NcB1dYf6HjG3aEu5oTi"   # 40 chars, fabricated
AWS = "AKIA" + "Q7XK2M9PLR4TB8WN"              # fabricated
SLACK = "xoxb-" + "2048137459-" + "Zr7Kq2Lm9Tx4"


def rules(line, path="app.py", **kw):
    return {h.rule for h in scan_line(line, path, **kw)}


@pytest.mark.parametrize("line,rule", [
    (f'GITHUB = "{GH}"', "github_token"),
    (f"aws_key = '{AWS}'", "aws_access_key_id"),
    (f"token: {SLACK}", "slack_token"),
    ("DATABASE_URL=postgres://app:" + "Kx9!rT2m" + "@db.internal:5432/app", "url_with_password"),
    ('api_key = "' + "q8Z3vN6tR1pL0sX4" + '"', "secret_assignment"),
    ("DB_PASSWORD=" + "Tr0ub4dor&3x", "secret_assignment"),
])
def test_secrets_are_found(line, rule):
    path = ".env" if line.startswith("DB_") else "settings.py"
    assert rule in rules(line, path)


@pytest.mark.parametrize("line,path", [
    ('api_key = os.environ["API_KEY"]', "app.py"),
    ("token = ${{ secrets.GITHUB_TOKEN }}", "ci.yml"),
    ('password = "changeme"', "app.py"),
    ('SECRET_KEY = "<your-secret-key>"', "app.py"),
    ("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE", ".env.example"),
    ("SLACK_BOT_TOKEN=xoxb-your-token-here", ".env.example"),
    ("postgres://user:${DB_PASSWORD}@localhost/db", "docker-compose.yml"),
    ("token_url = https://auth.example.com/token", "app.py"),
    ("password = getpass()", "app.py"),
])
def test_placeholders_and_lookups_are_not_secrets(line, path):
    assert not {r for r in rules(line, path) if r != "email_address"}


@pytest.mark.parametrize("line,rule", [
    ("Titular: Laura Pérez, cédula 1.023.456.789", "national_id"),
    ("C.C. 79845123 de Bogotá", "national_id"),
    ("NIT 900.123.456-7", "national_id"),
    ("Escríbele a laura.perez88@gmail.com", "email_address"),
    ("WhatsApp +57 312 456 7890", "phone_number"),
    ("cel: 315-882-1903", "phone_number"),
    ("Call me at (604) 382-1190", "phone_number"),
    ("SSN 123-45-6789", "us_ssn"),
    ("Tarjeta 4539 1488 0343 6467", "payment_card"),
])
def test_personal_data_is_found(line, rule):
    assert rule in rules(line)


@pytest.mark.parametrize("line", [
    "contact: team@example.com",
    "Author: dev <12345+dev@users.noreply.github.com>",
    "phone: (604) 555-0142",                       # NANP fictional range
    "version 3.12.4567 released 2024-05-06",
    "order id 1023456789",                         # digits without an id context
    "card for tests: 4242 4242 4242 4242",          # documented test card
    "timestamp 1712345678901",
    "git@github.com:owner/repo.git",
])
def test_personal_data_look_alikes_are_not_found(line):
    assert not rules(line) - {"jwt"}


def test_local_paths_and_generic_homes():
    assert "personal_path" in rules("see /Users/maria/Documents/report.xlsx")
    assert "personal_path" in rules(r"C:\Users\juan.perez\Desktop\data.csv")
    assert "personal_path" in rules("open file:///home/sofia/notes.txt")
    for generic in ("/home/user/app", "/home/runner/work/x", "/Users/Shared/tools", "/home/<user>/x",
                    "re.compile(r'/(Users|home)/[^/]+/')"):
        assert "personal_path" not in rules(generic), generic


def test_confidential_terms_and_allowed_domains():
    from prepublish_guard.detectors import term_pattern
    terms = [term_pattern("Acme Bank")]
    assert "confidential_term" in rules("Built for ACME-bank's risk team", confidential=terms)
    assert "confidential_term" not in rules("acmebanking library", confidential=terms)
    assert "email_address" not in rules("ana@mycompany.com", allowed_email_domains={"mycompany.com"})


def test_file_level_rules():
    key = "-----BEGIN RSA PRIVATE KEY-----\n" + "MIIEowIBAAKCAQEA" + "q" * 60 + "\n-----END RSA PRIVATE KEY-----\n"
    assert {h.rule for h in scan_file_level("deploy/key.txt", key)} == {"private_key"}
    enc = ("-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,0A1B\n\n"
           + "Q" * 64 + "\n")
    assert "private_key" in {h.rule for h in scan_file_level("k.pem", enc)}
    assert "ssh_private_key_file" in {h.rule for h in scan_file_level(".ssh/id_ed25519", "")}
    assert "dotenv_file" in {h.rule for h in scan_file_level(".env", "")}
    assert not scan_file_level(".env.example", "")
    csv_text = "nombre,cedula,ciudad\nAna,1023456789,Bogotá\nLuis,79845123,Cali\n"
    hits = scan_file_level("data/clientes.csv", csv_text)
    assert [h.rule for h in hits] == ["pii_column"] and "2 personal value" in hits[0].message
    assert not scan_file_level("data/ok.csv", "nombre,ciudad\nAna,Bogotá\n")


def test_helpers():
    assert luhn_ok("4539148803436467") and not luhn_ok("4539148803436468")
    assert looks_fake("AKIAIOSFODNN7EXAMPLE") and not looks_fake(AWS)
    assert entropy("aaaa") == 0 and entropy("q8Z3vN6tR1pL0sX4") > 3.5
    masked = mask(GH)
    assert GH not in masked and masked.startswith("gh") and "(40 chars)" in masked
    assert mask("abc") == "***"


def test_one_value_one_finding_and_url_credentials_are_not_emails():
    line = f'AWS_ACCESS_KEY_ID = "{AWS}"'
    assert rules(line, "settings.py") == {"aws_access_key_id"}               # no duplicate generic finding
    url = "DATABASE_URL = 'postgres://app:" + "Kx9!rT2m" + "@db.internal:5432/app'"
    assert rules(url, "settings.py") == {"url_with_password"}               # user:password@host is not an e-mail
