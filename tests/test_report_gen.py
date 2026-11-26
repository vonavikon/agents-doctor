"""Tests for skills/agents-doctor/scripts/report_generator.py.

Runs the generator over the chaos fixture and over synthetic minimal
reports: overall status logic, section order, table row counts, secret
mask discipline and the baseline comparison block. The technical report
is also rendered over a scan of the stand workspace
(tests/integration/fixtures.py), to check what it says about a check
that did not run and what it prints for each finding. Python 3.9+.
"""
import copy
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'skills' / 'agents-doctor' / 'scripts'))
sys.path.insert(0, str(REPO / 'tests' / 'integration'))

import audit_scan  # noqa: E402
import report_generator
from fixtures import stand  # noqa: E402

CHAOS = REPO / 'llm-eval' / 'fixtures' / 'chaos.json'

SECTION_HEADERS = [
    '# Agents Doctor',
    '## Executive Summary',
    '## Overall Workspace Health',
    '## Gate Results',
    '## Critical Findings',
    '## All Findings',
    '## Recommended Actions',
]


def load_chaos():
    return json.loads(CHAOS.read_text(encoding='utf-8'))


def section(md, header):
    """Lines of one '## ' section, without the header line."""
    lines = md.splitlines()
    start = lines.index(header)
    body = []
    for line in lines[start + 1:]:
        if line.startswith('## '):
            break
        body.append(line)
    return body


def minimal_rep(gate_statuses, findings=None):
    return {
        'schema_version': '1.0',
        'root': 'C:/tmp/ws',
        'generated_at': '2026-11-16T12:00:00+03:00',
        'rules_version': '0.4.0',
        'stats': {'total_files': 3, 'total_size_bytes': 100,
                  'skipped_symlinks_outside': 0, 'duration_sec': 0.01},
        'gates': [{'gid': f'G{i + 1}', 'n': i + 1, 'name': f'gate {i + 1}',
                   'status': s, 'evidence': ['evidence one'],
                   'recommendation': f'fix gate {i + 1}'}
                  for i, s in enumerate(gate_statuses)],
        'findings_detailed': findings or [],
    }


class OverallStatusTest(unittest.TestCase):
    def test_chaos_is_fail(self):
        self.assertEqual(report_generator.overall_status(load_chaos()), 'FAIL')

    def test_warn_gate_needs_attention(self):
        rep = minimal_rep(['pass', 'warn', 'pass'])
        self.assertEqual(report_generator.overall_status(rep),
                         'NEEDS ATTENTION')

    def test_unknown_gate_needs_attention(self):
        rep = minimal_rep(['unknown'])
        self.assertEqual(report_generator.overall_status(rep),
                         'NEEDS ATTENTION')

    def test_all_pass(self):
        rep = minimal_rep(['pass'] * 9)
        self.assertEqual(report_generator.overall_status(rep), 'PASS')

    def test_not_applicable_ignored(self):
        rep = minimal_rep(['pass', 'not_applicable', 'pass'])
        self.assertEqual(report_generator.overall_status(rep), 'PASS')

    def test_open_critical_forces_fail_even_with_passing_gates(self):
        finding = {'fid': 'SEC-001', 'gate': 'G6', 'category': 'secrets',
                   'severity': 'critical', 'status': 'fail',
                   'title': 'exposed token', 'evidence': [],
                   'recommendation': 'rotate'}
        rep = minimal_rep(['pass'] * 9, findings=[finding])
        self.assertEqual(report_generator.overall_status(rep), 'FAIL')

    def test_closed_critical_does_not_block_pass(self):
        finding = {'fid': 'SEC-001', 'gate': 'G6', 'category': 'secrets',
                   'severity': 'critical', 'status': 'pass',
                   'title': 'exposed token', 'evidence': [],
                   'recommendation': 'rotate'}
        rep = minimal_rep(['pass'] * 9, findings=[finding])
        self.assertEqual(report_generator.overall_status(rep), 'PASS')


class ChaosMarkdownTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rep = load_chaos()
        cls.md = report_generator.generate_markdown(cls.rep)

    def test_section_headers_in_order(self):
        positions = [self.md.index(h) for h in SECTION_HEADERS]
        self.assertEqual(positions, sorted(positions))
        for h in SECTION_HEADERS:
            self.assertIn(h + '\n', self.md + '\n')

    def test_no_baseline_section_without_diff(self):
        self.assertNotIn('diff', self.rep)
        self.assertNotIn('## Baseline Comparison', self.md)

    def test_meta_line(self):
        meta = [line for line in self.md.splitlines()
                if line.startswith('Generated ')]
        self.assertEqual(len(meta), 1)
        head = meta[0]
        self.assertIn(self.rep['generated_at'], head)
        self.assertIn('schema 1.0', head)
        # the rules version comes from the fixture, not from a literal
        self.assertIn('rules %s' % self.rep['rules_version'], head)
        self.assertIn('18 files', head)

    def test_executive_summary_mentions_status_and_top_finding(self):
        body = '\n'.join(section(self.md, '## Executive Summary'))
        self.assertIn('FAIL', body)
        self.assertIn('SEC-001', body)  # first critical by fid order
        self.assertIn('2 critical', body)
        self.assertIn('redacted', body)
        sentences = [s for s in body.splitlines() if s.strip()]
        self.assertGreaterEqual(len(sentences), 3)
        self.assertLessEqual(len(sentences), 6)

    def test_health_lists_fail_and_warn_gates_only(self):
        body = section(self.md, '## Overall Workspace Health')
        affected = [g['name'] for g in self.rep['gates']
                    if g['status'] in ('fail', 'warn')]
        for name in affected:
            self.assertTrue(any(name in line for line in body),
                            f'{name} missing from health section')

    def test_gate_table_has_nine_rows(self):
        rows = [line for line in self.md.splitlines()
                if re.match(r'^\| G\d \|', line)]
        self.assertEqual(len(rows), 9)
        for line in rows:
            self.assertLessEqual(len(line.split('|')[4].strip()), 100 + 6)

    def test_critical_table_lists_sec_findings(self):
        body = '\n'.join(section(self.md, '## Critical Findings'))
        self.assertIn('SEC-001', body)
        self.assertIn('SEC-002', body)
        expected = [f for f in self.rep['findings_detailed']
                    if f['severity'] in ('critical', 'high')]
        rows = [line for line in body.splitlines()
                if re.match(r'^\| [A-Z]+-\d+ \|', line)]
        self.assertEqual(len(rows), len(expected))

    def test_all_findings_table_complete_and_severity_sorted(self):
        rows = [line for line in
                section(self.md, '## All Findings')
                if re.match(r'^\| [A-Z]+-\d+ \|', line)]
        self.assertEqual(len(rows), len(self.rep['findings_detailed']))
        ranks = report_generator.SEVERITY_RANK
        seen = [ranks[line.split('|')[3].strip()] for line in rows]
        self.assertEqual(seen, sorted(seen))

    def test_actions_numbered_deduped_capped(self):
        body = section(self.md, '## Recommended Actions')
        items = [line for line in body if re.match(r'^\d+\. \[', line)]
        self.assertLessEqual(len(items), 8)
        self.assertGreater(len(items), 0)
        self.assertTrue(items[0].startswith('1. ['))
        texts = [re.sub(r'^\d+\. \[[^\]]+\] ', '', item) for item in items]
        self.assertEqual(len(texts), len(set(texts)))

    def test_footer(self):
        self.assertIn(report_generator.FOOTER, self.md)

    def test_no_raw_secrets(self):
        for match in re.finditer(r'sk-(?!\*\*\*)', self.md):
            self.fail(f'raw secret fragment at offset {match.start()}')


class BaselineDiffTest(unittest.TestCase):
    def _rep_with_diff(self):
        rep = minimal_rep(['fail'])
        rep['findings'] = [{'fp': f'fp{i}', 'section': 'junk',
                            'path': f'file{i}.txt'} for i in range(10)]
        new = rep['findings'][:2]
        resolved = [{'fp': f'old{i}', 'section': 'junk',
                     'path': f'gone{i}.txt'} for i in range(3)]
        rep['diff'] = {'new': new, 'resolved': resolved}
        return rep

    def test_diff_section_counts(self):
        md = report_generator.generate_markdown(self._rep_with_diff())
        self.assertIn('## Baseline Comparison', md)
        body = '\n'.join(section(md, '## Baseline Comparison'))
        self.assertIn('NEW FINDINGS: 2', body)
        self.assertIn('RESOLVED FINDINGS: 3', body)
        self.assertIn('PERSISTING: 5', body)   # 10 total - 2 new - 3 resolved
        self.assertIn('CHANGED: 5', body)      # 2 new + 3 resolved
        self.assertIn('file0.txt', body)
        self.assertIn('file1.txt', body)

    def test_diff_section_after_all_findings_before_actions(self):
        md = report_generator.generate_markdown(self._rep_with_diff())
        self.assertLess(md.index('## All Findings'),
                        md.index('## Baseline Comparison'))
        self.assertLess(md.index('## Baseline Comparison'),
                        md.index('## Recommended Actions'))

    def test_baseline_paths_capped_at_ten(self):
        rep = self._rep_with_diff()
        rep['findings'] = [{'fp': f'fp{i}', 'section': 'junk',
                            'path': f'file{i}.txt'} for i in range(20)]
        rep['diff'] = {'new': rep['findings'], 'resolved': []}
        md = report_generator.generate_markdown(rep)
        body = section(md, '## Baseline Comparison')
        listed = [line for line in body if line.startswith('- ')]
        self.assertEqual(len(listed), 10)


class CliTest(unittest.TestCase):
    def test_out_writes_file(self):
        import subprocess
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'AUDIT.md'
            r = subprocess.run(
                [sys.executable, str(REPO / 'skills' / 'agents-doctor' /
                                     'scripts' / 'report_generator.py'),
                 str(CHAOS), '--out', str(out)],
                capture_output=True, text=True, cwd=str(REPO))
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertTrue(out.exists())
            md = out.read_text(encoding='utf-8')
            self.assertIn('# Agents Doctor', md)
            self.assertIn('## Executive Summary', md)


class TechnicalReportTests(unittest.TestCase):
    """The technical report over a scan of the stand workspace."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.base = Path(cls._tmp.name)
        cls.root = cls.base / 'ws'
        cls.home = cls.base / 'home'
        cls.root.mkdir()
        cls.home.mkdir()
        stand(cls.root, cls.home)
        cls.rep = audit_scan.scan(cls.root, cls.home, False)
        cls.key = next(f for f in cls.rep['findings_detailed']
                       if f['gate'] == 'G6' and f['status'] == 'fail')
        cls.key_at = '.mcp.json:%d' % cls.key['evidence'][0]['line']
        cls.md = report_generator.generate_markdown(cls.rep)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def _section(self, header):
        """Non-empty lines of one '## ' section, without the header."""
        lines = self.md.splitlines()
        start = lines.index(header)
        out = []
        for line in lines[start + 1:]:
            if line.startswith('## ') or line.startswith('# '):
                break
            if line.strip():
                out.append(line)
        return out

    def test_not_checked_gates_say_why(self):
        table = self._section('## Gate Results')
        g7 = [l for l in table if l.startswith('| G7 |')][0]
        self.assertIn('not_applicable', g7)
        self.assertIn('No git repositories in the audited area', g7)

    def test_findings_table_has_location_and_what_to_do(self):
        table = self._section('## All Findings')
        self.assertIn('| location | what to do |', table[0])
        key = [l for l in table if l.startswith('| %s |' % self.key['fid'])][0]
        self.assertIn('| %s |' % self.key_at, key)
        self.assertIn('Rotate the secret at its provider', key)
        self.assertNotIn(str(self.base), key)

    def test_actions_start_with_the_key_and_its_place(self):
        actions = self._section('## Recommended Actions')
        numbered = [l for l in actions if re.match(r'^\d+\. \[', l)]
        self.assertTrue(numbered)
        self.assertTrue(numbered[0].startswith(
            '1. [%s]: %s: ' % (self.key['fid'], self.key_at)), numbered[0])
        # gate advice does not repeat what its findings already say,
        # and never asks for a hook in a folder without git
        self.assertNotIn('add a pre-commit secret scan', '\n'.join(actions))

    def test_planned_fixes_are_offered(self):
        rep = copy.deepcopy(self.rep)
        fixable = next(f for f in rep['findings_detailed']
                       if f.get('status') == 'warn')
        fixable['autofix_available'] = True
        lines = report_generator.generate_markdown(rep).splitlines()
        start = lines.index('## Recommended Actions')
        actions = '\n'.join(lines[start + 1:])
        self.assertIn('A planned fix exists for %s' % fixable['fid'], actions)
        self.assertIn('ask for `fix <fid>`', actions)


if __name__ == '__main__':
    unittest.main()
