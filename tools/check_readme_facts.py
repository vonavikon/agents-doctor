#!/usr/bin/env python3
"""Keep README facts generated, not hand-maintained.

The README carries a generated line inside a marker block:

    <!-- facts-begin -->...<!-- facts-end -->

This tool recomputes the facts (test count via unittest discovery —
load only, nothing runs; QA eval result from the newest qa/QA-EVAL-*.md)
and rewrites the block. `--check` exits 1 when the committed block is
stale (CI gate), so the count can never quietly drift again.
"""
from __future__ import annotations

import argparse
import re
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
README = REPO / 'README.md'
BEGIN = '<!-- facts-begin -->'
END = '<!-- facts-end -->'


def count_tests() -> int:
    """Discover the suite without running it and count test methods."""
    loader = unittest.TestLoader()
    suite = loader.discover(str(REPO / 'tests'))
    return suite.countTestCases()


def qa_result() -> str:
    """Latest QA eval verdict, e.g. '267 PASS'."""
    reports = sorted(REPO.glob('qa/QA-EVAL-*.md'))
    if not reports:
        return 'n/a'
    text = reports[-1].read_text(encoding='utf-8')
    m = re.search(r'PASS (\d+), FAIL (\d+)', text)
    if not m:
        return 'n/a'
    return '%s PASS' % m.group(1)


def facts_line() -> str:
    return ('**Facts:** %d tests · QA eval %s · deterministic scanner, '
            'no dependencies' % (count_tests(), qa_result()))


def current_block() -> str:
    text = README.read_text(encoding='utf-8')
    m = re.search(re.escape(BEGIN) + r'(.*?)' + re.escape(END), text,
                  re.S)
    return m.group(0) if m else ''


def render_block() -> str:
    return '%s\n%s\n%s' % (BEGIN, facts_line(), END)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('--check', action='store_true',
                    help='exit 1 when the README facts block is stale')
    a = ap.parse_args(argv)
    fresh = render_block()
    current = current_block()
    if not current:
        print('no facts block in README; insert:\n%s' % fresh,
              file=sys.stderr)
        return 1
    if a.check:
        if current != fresh:
            print('STALE: README facts differ from the actual suite; '
                  'run python tools/check_readme_facts.py',
                  file=sys.stderr)
            return 1
        print('OK: README facts are current')
        return 0
    text = README.read_text(encoding='utf-8')
    text = re.sub(re.escape(current), fresh.replace('\\', '\\\\'),
                  text, count=1)
    README.write_text(text, encoding='utf-8')
    print('README facts updated: %s' % facts_line())
    return 0


if __name__ == '__main__':
    sys.exit(main())
