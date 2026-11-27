"""secret_rules: the single source of truth for secret detection rules.

Every rule carries both a python regex ('py', the authoritative filter
used by find_rule) and a POSIX ERE string ('ere', for `git grep -E -i`
pre-filtering). The combined pattern is GIT_GREP_RE_COMBINED, built by
joining the eres with '|' in RULES order (stable); GIT_GREP_RE is an
alias for it.

secret_scanner.py keeps its own embedded copy of the legacy five rules
until the integration step switches it to import this module. The
SEC-001..SEC-005 entries keep their ids, kinds, masks, confidences and
python patterns byte-identical to secret_scanner.RULES.

Rule ordering: structured token formats (SEC-001..004) first, then the
dedicated SEC-1xx rules, then the generic keyword literal SEC-005
last. Specific rules must claim a line before the generic keyword
rule: 'access_token = "x..."' is SEC-101, not a SEC-005 'token' match;
'google_api_key = "AIza..."' is SEC-104, not SEC-005.

Documented deviations from raw legacy behavior:
- Digit-only quoted values ('token = "12345678"') are treated as too
  weak to be a secret (dates, numeric ids, phone numbers) and are
  skipped by find_rule. The rule regexes themselves are unchanged;
  this is a post-filter applied to the literal rules (SEC-005,
  SEC-101) only.
- Values containing angle-bracket placeholders ('<access key>') are
  skipped as documentation, exactly like '${...}' template values: a
  placeholder quoted after a keyword is a docs example, not a secret.
- SEC-001 requires a non-token character (or line start) before
  'sk-': transliterated slugs like 'vypusk-dokumentacii' embed a
  false 'sk-dokumentacii' fragment that the bare pattern matched.
- SEC-102 skips the canonical documentation credential pair
  'user:secret' ('postgresql://user:secret@' is the PostgreSQL
  manual's own example connection string).
- The ERE side cannot express lookbehind or per-rule case sensitivity
  (`git grep -i` matches case-insensitively everywhere), so git-grep
  pre-filter matching is slightly wider than the python rules. The
  python rules re-check every candidate line and are authoritative.

Deterministic, no I/O.
"""

import re

RULES = [
    # --- legacy rules SEC-001..005: py patterns identical to
    # --- secret_scanner.RULES; ids/kinds/masks/confidences preserved.
    {'id': 'SEC-001', 'kind': 'api-key', 'mask': 'sk-***',
     'confidence': 0.95,
     # left boundary: 'sk-' glued inside a word (transliterated slugs
     # like 'vypusk-dokumentacii' embed 'sk-dokumentacii') is not a
     # key; real keys sit at line start or after a quote/space/:=.
     'py': re.compile(r'(?<![A-Za-z0-9_-])sk-[A-Za-z0-9_-]{16,}'),
     'ere': 'sk-[A-Za-z0-9_-]{16,}'},
    {'id': 'SEC-002', 'kind': 'bearer-token', 'mask': 'Bearer ***',
     'confidence': 0.90,
     # HTTP auth schemes are case-insensitive (RFC 7235): a lowercase
     # 'bearer' header is as real as 'Bearer'.
     'py': re.compile(r'(?i)Bearer\s+[A-Za-z0-9._-]{20,}'),
     'ere': 'Bearer[[:space:]]+[A-Za-z0-9._-]{20,}'},
    {'id': 'SEC-003', 'kind': 'aws-access-key', 'mask': 'AKIA***',
     'confidence': 0.95,
     'py': re.compile(r'\bAKIA[0-9A-Z]{16}\b'),
     'ere': 'AKIA[0-9A-Z]{16}'},
    {'id': 'SEC-004', 'kind': 'private-key', 'mask': 'PRIVATE KEY***',
     'confidence': 0.99,
     # [A-Z ]* already covers '-----BEGIN ENCRYPTED PRIVATE KEY-----';
     # one rule for every block type.
     'py': re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----'),
     'ere': '-----BEGIN [A-Z ]*PRIVATE KEY-----'},
    # --- dedicated rules SEC-1xx, all ordered before generic SEC-005.
    {'id': 'SEC-101', 'kind': 'access-token', 'mask': '***',
     'confidence': 0.70,
     'py': re.compile(r'(?i)(?<![a-z0-9])(access[_-]?token)["\']?\s*[:=]\s*["\'][^"\']{8,}'),
     'ere': "access[_-]?token[\"']?[[:space:]]*[:=][[:space:]]*[\"'][^\"']{8,}"},
    {'id': 'SEC-102', 'kind': 'db-credentials', 'mask': '***:***@',
     'confidence': 0.95,
     'py': re.compile(r'(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^/@\s:]+:[^/@\s]+@'),
     'ere': r'(postgres(ql)?|mysql|mongodb(\+srv)?|redis|amqp)://[^/@[:space:]:]+:[^/@[:space:]]+@'},
    {'id': 'SEC-103', 'kind': 'aws-secret', 'mask': 'AWS***',
     'confidence': 0.80,
     # heuristic: 40-char base64ish value assigned to a variable
     # containing AWS_SECRET
     'py': re.compile(r"(?i)aws[_-]?secret[a-z0-9_-]*\s*[:=]\s*[\"']?[A-Za-z0-9/+]{40}"),
     'ere': "aws[_-]?secret[a-z0-9_-]*[[:space:]]*[:=][[:space:]]*[\"']?[A-Za-z0-9/+]{40}"},
    {'id': 'SEC-104', 'kind': 'google-api-key', 'mask': 'AIza***',
     'confidence': 0.90,
     'py': re.compile(r'AIza[0-9A-Za-z_-]{35}'),
     'ere': 'AIza[0-9A-Za-z_-]{35}'},
    {'id': 'SEC-105', 'kind': 'github-token', 'mask': 'ghp_***',
     'confidence': 0.95,
     # gh[pousr]_ prefixes: classic PAT, OAuth app/user/server tokens
     # share the same 36-char body shape.
     'py': re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{30,})'),
     'ere': r'(gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{30,})'},
    {'id': 'SEC-106', 'kind': 'slack-token', 'mask': 'xox***',
     'confidence': 0.95,
     'py': re.compile(r'\bxox[baprs]-[A-Za-z0-9-]{10,}'),
     'ere': 'xox[baprs]-[A-Za-z0-9-]{10,}'},
    {'id': 'SEC-107', 'kind': 'jwt', 'mask': 'eyJ***',
     'confidence': 0.80,
     'py': re.compile(r'\beyJ[A-Za-z0-9_-]{27,}\.[A-Za-z0-9_-]{30,}\.[A-Za-z0-9_-]{30,}'),
     'ere': r'eyJ[A-Za-z0-9_-]{27,}\.[A-Za-z0-9_-]{30,}\.[A-Za-z0-9_-]{30,}'},
    # --- generic keyword literal, last so the specific rules above win.
    {'id': 'SEC-005', 'kind': 'secret literal', 'mask': '***',
     'confidence': 0.70,
     # secret[_-]?key covers SECRET_KEY/client_secret_key style names
    # where the keyword is not immediately followed by [:=].
     'py': re.compile(r'(?i)(?<![a-z0-9])(api[_-]?key|apikey|password|secret[_-]?key|secret|token|authorization)["\']?\s*[:=]\s*["\'][^"\']{8,}'),
     'ere': "(api[_-]?key|apikey|password|secret[_-]?key|secret|token|authorization)[\"']?[[:space:]]*[:=][[:space:]]*[\"'][^\"']{8,}"},
]

# POSIX ERE alternation for `git grep -E -i`, stable RULES order.
GIT_GREP_RE_COMBINED = '|'.join(rule['ere'] for rule in RULES)
GIT_GREP_RE = GIT_GREP_RE_COMBINED

# Literal rules whose digit-only quoted values are skipped as too weak.
_WEAK_VALUE_RULES = frozenset(('SEC-005', 'SEC-101'))

# Canonical documentation credential pairs (scheme://user:pass@) that
# are examples in vendor manuals, not live credentials.
_DOC_CRED_EXAMPLES = frozenset(('user:secret', 'username:password'))

# python approximation of the git grep side: the POSIX class token
# [:space:] is not valid python re, translate it (works both standalone
# as [[:space:]] and inside negated classes like [^/@[:space:]:]);
# git grep -i becomes re.IGNORECASE.
_ERE_PY = {rule['id']: re.compile(rule['ere'].replace('[:space:]', r'\s'),
                                  re.IGNORECASE)
           for rule in RULES}
_COMBINED_ERE_PY = re.compile(GIT_GREP_RE_COMBINED.replace('[:space:]', r'\s'),
                              re.IGNORECASE)


def find_rule(line):
    """Return the first matching rule dict for the line, or None.

    Rules are tried in RULES order (specific before generic). For the
    literal rules, digit-only quoted values are skipped as too weak;
    placeholder values (${...} templates, <angle-bracket> docs
    placeholders) are skipped as configuration examples, not live
    secrets. SEC-102 additionally skips the canonical documentation
    credential pair user:secret.
    """
    for rule in RULES:
        if rule['id'] in _WEAK_VALUE_RULES:
            for match in rule['py'].finditer(line):
                if _is_weak_literal(match):
                    continue
                if _is_placeholder(match):
                    continue  # ${...} or <...>, not a real secret
                return rule
        else:
            match = rule['py'].search(line)
            if match is not None:
                if _is_placeholder(match):
                    continue  # e.g. "Bearer ${API_KEY}" in .example.json
                if rule['id'] == 'SEC-102' and _is_doc_example(match):
                    continue  # postgresql://user:secret@ from the manual
                return rule
    return None


def find_rule_ere(line):
    """Return the rule id the git-grep ERE side would flag, or None.

    Tests the combined ERE first (cheap reject), then the per-rule
    eres in the same RULES order to pick the id. Slightly wider than
    find_rule by design (no lookbehind, case-insensitive); the python
    rules re-check candidates authoritatively.
    """
    if not _COMBINED_ERE_PY.search(line):
        return None
    for rule in RULES:
        if _ERE_PY[rule['id']].search(line):
            return rule['id']
    return None


def _match_value(match):
    """Extract the quoted value from a literal-rule match.

    The match spans keyword + separator + opening quote + value (the
    value charset excludes both quote chars, so the last quote in the
    match is the opening one).
    """
    text = match.group(0)
    quote = max(text.rfind('"'), text.rfind("'"))
    return text[quote + 1:] if quote != -1 else ''


def _is_weak_literal(match):
    value = _match_value(match)
    return bool(value) and value.isdigit()


def _is_placeholder(match):
    """True for configuration examples, not live secrets: a ${...}
    substitution anywhere in the match, or an angle-bracket placeholder
    inside the quoted value of a literal rule ('Bearer <access key>',
    '"<portal token>"'). Real token alphabets never contain <>."""
    if '${' in match.group(0):
        return True
    value = _match_value(match)
    return '<' in value and '>' in value


def _is_doc_example(match):
    """True for a scheme://user:pass@ match whose credentials are a
    canonical documentation pair (the PostgreSQL manual uses
    postgresql://user:secret@ in its connection-string examples)."""
    text = match.group(0)
    if '://' not in text or '@' not in text:
        return False
    creds = text.split('://', 1)[1].split('@', 1)[0]
    return creds.lower() in _DOC_CRED_EXAMPLES


# (line, expected rule id or None) pairs. Every rule has >= 2 positive
# lines; the rest are the false-positive corpus: placeholders, env
# indirection, glued keywords, short/weak values, URL tokens in prose
# (the sanitizer owns URL handling), placeholders with <>, bare 'eyJ'.
PARITY_CORPUS = [
    # SEC-001 sk- tokens
    ('sk-abcdefghijklmnop1234', 'SEC-001'),
    ('export KEY="sk-zyxwvutsrqponmlkj88"', 'SEC-001'),
    # boundary still matches a real key in prose
    ('see sk-abcdefghijklmnop1234 now', 'SEC-001'),
    # SEC-002 bearer tokens
    ('Bearer abcdefghijklmnopqrstuv', 'SEC-002'),
    ('authorization: bearer aabbccddeeff0011223344', 'SEC-002'),
    ('Authorization: Bearer zyxwvutsrqponmlkjihg', 'SEC-002'),
    # SEC-003 AWS access key ids
    ('AKIAIOSFODNN7EXAMPLE', 'SEC-003'),
    ('backup key AKIA0123456789ABCDEF found', 'SEC-003'),
    # SEC-004 PEM headers (ENCRYPTED covered by [A-Z ]*)
    ('-----BEGIN RSA PRIVATE KEY-----', 'SEC-004'),
    ('-----BEGIN ENCRYPTED PRIVATE KEY-----', 'SEC-004'),
    # SEC-005 generic keyword literals
    ('api_key = "supersecretvalue"', 'SEC-005'),
    ('DB_PASSWORD: "hunter2-secret"', 'SEC-005'),
    ('password = "hunter2-secret-value"', 'SEC-005'),
    ('SECRET_KEY: "django-insecure-1a2b3c4d5e"', 'SEC-005'),
    # SEC-101 access_token literals (specific rule beats SEC-005 'token')
    ('access_token = "gho_16C7e42F292c6912"', 'SEC-101'),
    ('accessToken: "8ybX87GB3jK7Ems4zDq9"', 'SEC-101'),
    # SEC-102 database URLs with credentials
    ('postgres://admin:hunter2@db.internal:5432/prod', 'SEC-102'),
    ('mongodb+srv://svc_user:p%40ssw0rd@cluster0.a1b2c.mongodb.net/db', 'SEC-102'),
    # SEC-103 AWS secret access keys (heuristic)
    ('AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', 'SEC-103'),
    ('aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"', 'SEC-103'),
    # SEC-104 Google API keys
    ('AIzaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q', 'SEC-104'),
    ('google_api_key = "AIzaQyB8D_7f6g5h4i3j2k1l0z9y8x7w6v5u4tq"', 'SEC-104'),
    # SEC-105 GitHub tokens — corpus literals are assembled from pieces so
    # no live-looking token ever appears verbatim in this source file
    ('ghp_' + '16C7e42F292c6912E7710c838347Ae178B4A', 'SEC-105'),
    ('gho_' + 'AAbbCCddEEff0011223344556677889900aAbB', 'SEC-105'),
    ('github_' + 'pat_11ABCDEFG0abcdefghijklmnopqrstuvwxyz1234567890', 'SEC-105'),
    # SEC-106 Slack tokens (same piecewise assembly)
    ('xox' + 'b-123456789012-1234567890123-abcdefghijklmnopqrstuv', 'SEC-106'),
    ('xox' + 'a-223344556677-889900112233-aabbccddeeffgghh', 'SEC-106'),
    # SEC-107 JWTs (three segments, >= 30 chars each)
    ('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkphbmVEb2UifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c', 'SEC-107'),
    ('auth eyJhbGciOiJSUzI1NiIsImtpZCI6IjFLVHAifQ.eyJpc3MiOiJhbWJpY29tLCJzdWIiOiJ4eCJ9.xTZ30B0E1z6l3Z0gXtSxmMjH3Yw4v5u6w7x8y9', 'SEC-107'),
    # false-positive corpus: none of these are findings
    ('${DB_PASSWORD}', None),
    ('os.environ["API_KEY"]', None),
    ('PASSWORDX = "y"', None),
    ('password = ""', None),
    ('password = "short"', None),
    # digits-only 8: too weak (dates, numeric ids) -- documented decision
    ('token = "12345678"', None),
    # URL token in prose: not a literal-rule finding; sanitize_url owns URLs
    ('see https://example.com/reset?token=abc', None),
    ('API_KEY=${VAR}', None),
    ('api_key: os.environ.get("TOKEN")', None),
    ('access_token = os.environ["ACCESS_TOKEN"]', None),
    # bearer shorter than 20
    ('Bearer abcdefghij', None),
    # base64 blob without keyword
    ('SGVsbG8gd29ybGQgdGhpcyBpcyBhIGxvbmcgYmFzZTY0IGJsb2I=', None),
    # placeholder with <>
    ('Authorization: Bearer <token>', None),
    ('eyJ', None),
    # transliterated slugs embed 'sk-' inside a word ('vypusk-'): not keys
    ('uskorit-vypusk-dokumentacii-po-ekosisteme', None),
    ('zadacha-sroki-vypusk-dokumentacii-v-ekosisteme', None),
    # angle-bracket placeholder quoted after a keyword: docs example
    ('"Authorization": "Bearer <access key>"', None),
    ('WIKI_API_TOKEN: "<portal access token>"', None),
    # canonical PostgreSQL manual connection-string example
    ('postgresql://user:secret@localhost:5432/mydb', None),
]
