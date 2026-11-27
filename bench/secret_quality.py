#!/usr/bin/env python3
"""Secret detection quality benchmark.

Measures precision / recall / FPR / FNR of the deterministic secret
rules against a labeled corpus, then stresses the scanner with
adversarial shapes (obfuscation, truncation, multi-line values) that
are documented misses — reported separately, never silently.

    python bench/secret_quality.py [--out bench/SECRET-QUALITY-<date>.md]

Corpus sources:
  - secret_rules.PARITY_CORPUS  (py/ERE parity lock, counted here for
    recall on the documented shapes);
  - EXTRA_NEGATIVES / EXTRA_POSITIVES below (FP-prone and extra true
    shapes that the parity corpus does not cover).

Exit codes: 0 metrics meet the floor, 1 they do not. Floors are the
CI gate: precision >= 0.95, recall >= 0.95 on the labeled corpus.
Python 3.10+, stdlib only.
"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCRIPTS = REPO / 'skills' / 'agents-doctor' / 'scripts'
sys.path.insert(0, str(SCRIPTS))

import secret_rules  # noqa: E402

PRECISION_FLOOR = 0.95
RECALL_FLOOR = 0.95

# False-positive bait the parity corpus does not cover: documentation,
# templates, placeholders, short values, unrelated identifiers.
EXTRA_NEGATIVES = [
    'read the sk-docs guide for tokens',          # 'sk-' prefix in prose
    'AKIA placeholder for docs',                  # too short, prose
    'password: use env vars instead',             # keyword without literal
    'token_bucket_size = 100',                    # config knob, not a secret
    'apikey_name = "billing"',  # name reference, not value
    'The password field is optional',             # docs prose
    '"client_secret_file": "configs/none.json"',  # path, not a secret
    'password_hash = bcrypt(...)',                # function call
    'xoxb-icons in the toolbar',                  # word, not a token
    'ghp_placeholder',                            # prefix, no body
    'AIzaSy',                                     # prefix only
    'Bearer',                                     # keyword alone
    '-----BEGIN CERTIFICATE-----',                # public cert, not a key
    'postgres://localhost/db',                    # no credentials
    'mongodb://user@host/db',                     # user without password
]

# True-positive shapes beyond the parity corpus. The expected id is the
# natural rule for the shape, but ANY rule firing on a true secret is a
# correct detection: relabels (e.g. client_secret via the generic
# SEC-005 instead of SEC-101) are counted as TP and tracked separately.
EXTRA_POSITIVES = [
    ('sk-' + 'proj4abcdefghijklmnopqrstuvwx', 'SEC-001'),
    ('authorization: bearer aabbccddeeff0011223344', 'SEC-002'),
    ('aws_key = ' + 'AKIA1234567890ABCDEF', 'SEC-003'),
    ('private_key = "-----BEGIN OPENSSH PRIVATE KEY-----"',
     'SEC-004'),
    ('SECRET_KEY: "django-insecure-1a2b3c4d5e6f7g8h9i0j"',
     'SEC-005'),
    ('client_secret = "0123456789abcdef01234567"', 'SEC-005'),
    ('mysql://root:sup3rs3cret@10.0.0.2:3306/shop', 'SEC-102'),
    ('aws_secret_access_key = "' + 'wJalrXUtnFEMI/K7MDENG/'
     'bPxRfiCYEXAMPLE123', 'SEC-103'),
    ('AIza' + 'B1c2D3e4F5g6H7i8J9k0L1m2N3o4P5q6R7s8T9u', 'SEC-104'),
    ('gho_' + 'AAbbCCddEEff0011223344556677889900aAbB', 'SEC-105'),
    ('xox' + 'p-11223344556677889900112233445566', 'SEC-106'),
    ('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
     '.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkEifQ'
     '.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c', 'SEC-107'),
]

# Documented-miss adversarial shapes: obfuscation and truncation. They
# are counted as expected misses (a detection here would be a bonus),
# never as recall failures — the report separates them on purpose.
ADVERSARIAL_MISSES = [
    ('base64-wrapped key: c2stYWJjZGVmZ2hpamtsbW5vcA==', 'base64 wrap'),
    ('key = "sk-" + "abcdef1234567890"', 'string concat'),
    ('token: sk-\n  abcdef1234567890', 'split across lines'),
    ('sk-abc\u200bdef1234567890', 'zero-width space'),
]


def evaluate(verbose: bool = False):
    tp = fp = fn = tn = 0
    per_rule = {}          # rule_id -> {'tp':, 'fn':}
    fp_lines, fn_lines = [], []
    relabeled = []         # true secret caught by a different rule

    corpus = [(line, rid) for line, rid in secret_rules.PARITY_CORPUS]
    corpus += EXTRA_POSITIVES
    corpus += [(line, None) for line in EXTRA_NEGATIVES]

    for line, expected in corpus:
        got = secret_rules.find_rule(line)
        got_id = got['id'] if isinstance(got, dict) else got
        if expected is None:
            if got_id:
                fp += 1
                fp_lines.append((line, got_id))
            else:
                tn += 1
        else:
            if got_id is None:
                fn += 1
                fn_lines.append((line, expected, None))
                per_rule.setdefault(expected, {'tp': 0, 'fn': 0})['fn'] += 1
            else:
                tp += 1   # any rule firing on a true secret detects it
                per_rule.setdefault(expected, {'tp': 0, 'fn': 0})['tp'] += 1
                if got_id != expected:
                    relabeled.append((line, expected, got_id))
        if verbose:
            print('%-60r want=%-8s got=%s' % (line[:60], expected, got_id))

    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    fnr = fn / (fn + tp) if fn + tp else 0.0

    adversarial_hits = 0
    for line, shape in ADVERSARIAL_MISSES:
        if secret_rules.find_rule(line):
            adversarial_hits += 1

    return {
        'tp': tp, 'fp': fp, 'fn': fn, 'tn': tn,
        'precision': precision, 'recall': recall, 'fpr': fpr, 'fnr': fnr,
        'per_rule': per_rule,
        'fp_lines': fp_lines, 'fn_lines': fn_lines,
        'relabeled': relabeled,
        'adversarial_total': len(ADVERSARIAL_MISSES),
        'adversarial_hits': adversarial_hits,
        'adversarial_shapes': ADVERSARIAL_MISSES,
    }


def format_report(m: dict) -> str:
    lines = ['# Secret detection quality benchmark', '']
    lines.append('Date: %s' % datetime.now().strftime('%Y-%m-%d %H:%M'))
    lines.append('')
    lines.append('## Headline metrics')
    lines.append('')
    lines.append('| metric | value |')
    lines.append('|---|---|')
    lines.append('| true positives | %d |' % m['tp'])
    lines.append('| false positives | %d |' % m['fp'])
    lines.append('| false negatives | %d |' % m['fn'])
    lines.append('| true negatives | %d |' % m['tn'])
    lines.append('| precision | %.3f |' % m['precision'])
    lines.append('| recall | %.3f |' % m['recall'])
    lines.append('| false positive rate | %.3f |' % m['fpr'])
    lines.append('| false negative rate | %.3f |' % m['fnr'])
    lines.append('')
    lines.append('Floors: precision >= %.2f, recall >= %.2f.'
                 % (PRECISION_FLOOR, RECALL_FLOOR))
    lines.append('')
    lines.append('## Per-rule recall')
    lines.append('')
    lines.append('| rule | tp | fn |')
    lines.append('|---|---|---|')
    for rid in sorted(m['per_rule']):
        s = m['per_rule'][rid]
        lines.append('| %s | %d | %d |' % (rid, s['tp'], s['fn']))
    if m['fp_lines']:
        lines.append('')
        lines.append('## False positives')
        lines.append('')
        for line, got in m['fp_lines']:
            lines.append('- `%s` -> %s' % (line, got))
    if m['fn_lines']:
        lines.append('')
        lines.append('## False negatives')
        lines.append('')
        for line, want, got in m['fn_lines']:
            lines.append('- `%s` want=%s got=%s' % (line, want, got))
    if m['relabeled']:
        lines.append('')
        lines.append('## Relabeled detections (TP, different rule)')
        lines.append('')
        for line, want, got in m['relabeled']:
            lines.append('- `%s` natural=%s fired=%s' % (line, want, got))
    lines.append('')
    lines.append('## Adversarial shapes (documented misses, not failures)')
    lines.append('')
    lines.append('Detected %d of %d. These are counted separately: '
                 'detection here is a bonus, missing them is documented '
                 'behaviour (obfuscation defeats literal rules; deep '
                 'detection belongs to the LLM layer).'
                 % (m['adversarial_hits'], m['adversarial_total']))
    for line, shape in m['adversarial_shapes']:
        hit = 'hit' if secret_rules.find_rule(line) else 'miss'
        lines.append('- %s (%s): `%s`' % (shape, hit, line))
    lines.append('')
    ok = (m['precision'] >= PRECISION_FLOOR
          and m['recall'] >= RECALL_FLOOR)
    lines.append('Verdict: %s' % ('PASS' if ok else 'FAIL'))
    return '\n'.join(lines) + '\n'


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    default_out = REPO / 'bench' / ('SECRET-QUALITY-%s.md'
                                    % datetime.now().strftime('%Y-%m-%d'))
    ap.add_argument('--out', default=str(default_out))
    ap.add_argument('-v', '--verbose', action='store_true')
    a = ap.parse_args(argv)
    m = evaluate(verbose=a.verbose)
    report = format_report(m)
    Path(a.out).write_text(report, encoding='utf-8')
    print(report)
    print('written: %s' % a.out)
    ok = (m['precision'] >= PRECISION_FLOOR and m['recall'] >= RECALL_FLOOR)
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
