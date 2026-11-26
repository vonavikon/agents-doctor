"""Integration tests for the agents-doctor scanner (spec section 8.2).

Runs skills/agents-doctor/scripts/audit_scan.py end to end against the
fixture workspaces built by fixtures.py and asserts the report contract
per fixture, plus a schema smoke applied to every run. All planted
secrets are DEMO-marked synthetics and must never appear in raw form in
any scanner artifact.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import fixtures

REPO_ROOT = Path(__file__).resolve().parents[2]
SCANNER = REPO_ROOT / 'skills' / 'agents-doctor' / 'scripts' / 'audit_scan.py'

GIT_AVAILABLE = shutil.which('git') is not None

try:
    import yaml
except ImportError:
    yaml = None

FID_RE = r'^(SEC|CFG|RUL|DIR|SKL|GIT|GOV|HLTH)-[0-9]{3}$'
GATE_IDS = {'G%d' % i for i in range(1, 10)}
STATUSES = ('pass', 'fail', 'warn', 'unknown', 'not_applicable')


def run_audit(root, home, out, deep=False):
    """Run the scanner end to end. Returns (proc, report-or-None)."""
    cmd = [sys.executable, str(SCANNER), str(root),
           '--home', str(home), '--out', str(out)]
    if deep:
        cmd.append('--deep')
    proc = subprocess.run(cmd, capture_output=True, text=True,
                          encoding='utf-8', errors='replace',
                          timeout=120, cwd=str(root))
    try:
        report = json.loads(Path(out).read_text(encoding='utf-8'))
    except (OSError, ValueError):
        report = None
    return proc, report


def gate_statuses(report):
    return {g['gid']: g['status'] for g in report['gates']}


def gate_of(report, gid):
    return next(g for g in report['gates'] if g['gid'] == gid)


def titles(report):
    return [f['title'] for f in report['findings_detailed']]


def mentions_skill(finding, name):
    if "'%s'" % name in finding['title']:
        return True
    for e in finding['evidence']:
        if name in str(e.get('file', '')).replace('\\', '/'):
            return True
    return False


class FixtureIntegrationTest(unittest.TestCase):
    maxDiff = None

    def setUp(self):
        if not GIT_AVAILABLE:
            self.skipTest('git is required to build the fixtures')
        self.base = Path(tempfile.mkdtemp(prefix='wa-int-'))
        self.addCleanup(fixtures.force_rmtree, self.base)
        self._runs = 0

    # --- harness -------------------------------------------------------------

    def scan(self, builder, deep=False, **builder_kwargs):
        """Build a fixture, scan it, validate the shared contract."""
        ws = self.base / ('ws%d' % self._runs)
        self._runs += 1
        root, home, extra = builder(ws, **builder_kwargs)
        out = self.base / ('out%d.json' % self._runs)
        proc, report = run_audit(root, home, out, deep=deep)
        self.assertEqual(proc.returncode, 0,
                         'scanner exited %d\nstdout tail: %s\nstderr tail: %s'
                         % (proc.returncode, proc.stdout[-600:],
                            proc.stderr[-600:]))
        self.assert_report_schema(report)
        self.proc = proc
        self.out_text = out.read_text(encoding='utf-8')
        return root, home, extra, report

    def output_blob(self):
        """Every artifact a user could read: stdout, stderr, report JSON."""
        return self.proc.stdout + self.proc.stderr + self.out_text

    def assert_report_schema(self, report):
        self.assertIsInstance(report, dict, 'report did not parse as JSON')
        gids = [g['gid'] for g in report['gates']]
        self.assertEqual(set(gids), GATE_IDS, 'gates must cover G1..G9')
        self.assertEqual(len(gids), len(GATE_IDS), 'duplicate gate ids')
        for g in report['gates']:
            self.assertIn(g['status'], STATUSES)
            self.assertIsInstance(g['evidence'], list)
            self.assertTrue(all(isinstance(e, str) for e in g['evidence']))
        fids = [f['fid'] for f in report['findings_detailed']]
        self.assertEqual(len(fids), len(set(fids)),
                         'duplicate fids in report: %r' % fids)
        for f in report['findings_detailed']:
            self.assertRegex(f['fid'], FID_RE)
            self.assertIn(f['severity'],
                          ('critical', 'high', 'medium', 'low', 'info'))
            self.assertIn(f['status'], STATUSES)
            self.assertIn(f['gate'], GATE_IDS)
            if f['status'] in ('fail', 'warn'):
                self.assertTrue(f['evidence'],
                                'finding %s (%s) lacks evidence'
                                % (f['fid'], f['title']))

    # --- F01 -----------------------------------------------------------------

    def test_f01_clean(self):
        _root, _home, _extra, rep = self.scan(fixtures.f01_clean)
        st = gate_statuses(rep)
        self.assertEqual(st['G1'], 'pass')
        self.assertEqual(st['G2'], 'pass', 'valid config must parse')
        self.assertEqual(st['G3'], 'pass')
        # G6 may warn (no secret hook); nothing may fail
        self.assertEqual([f for f in rep['findings_detailed']
                          if f['status'] == 'fail'], [])

    # --- F02 -----------------------------------------------------------------

    def test_f02_secrets(self):
        _root, _home, _extra, rep = self.scan(fixtures.f02_secrets, deep=True)
        st = gate_statuses(rep)
        self.assertEqual(st['G6'], 'fail')
        critical = [f for f in rep['findings_detailed']
                    if f['severity'] == 'critical']
        # .env password, .mcp.json token, tracked config.py at minimum
        self.assertGreaterEqual(len(critical), 3,
                                'critical findings: %r' % titles(rep))
        blob = self.output_blob()
        for raw in ('DEMO-hunter2-xx', 'sk-DEMO0123456789abcdef',
                    'DEMO-secret-0000000000', 'DEMO-bearer-000000000011'):
            self.assertNotIn(raw, blob, 'raw secret %r leaked' % raw)
        for s in rep['secrets']:
            self.assertTrue(s.get('fingerprint'),
                            'secret entry without fingerprint: %r' % s)
            self.assertTrue(s.get('mask') or s.get('value') == '[REDACTED]',
                            'secret entry without mask/redaction: %r' % s)
        for t in rep['top_level']:
            for ts in (t.get('extra') or {}).get('tracked_secrets') or []:
                self.assertTrue(ts.get('fingerprint'),
                                'tracked secret without fingerprint: %r' % ts)
                self.assertEqual(ts.get('value'), '[REDACTED]',
                                 'tracked secret not redacted: %r' % ts)

    # --- F03 -----------------------------------------------------------------

    def test_f03_conflicting_rules(self):
        _root, _home, _extra, rep = self.scan(fixtures.f03_conflicting_rules)
        st = gate_statuses(rep)
        self.assertEqual(st['G1'], 'fail')
        self.assertEqual(st['G3'], 'fail')
        dead = [f for f in rep['findings_detailed']
                if f['status'] == 'fail' and f['title'].startswith('Dead ')]
        self.assertTrue(
            any('npm run test' in f['title'] or 'make lint' in f['title']
                for f in dead)
            or len(dead) >= 3,
            'no dead-command findings: %r' % titles(rep))

    # --- F04 -----------------------------------------------------------------

    def test_f04_broken_skills(self):
        _root, _home, _extra, rep = self.scan(fixtures.f04_broken_skills)
        st = gate_statuses(rep)
        self.assertEqual(st['G5'], 'fail')
        all_titles = titles(rep)
        # skill a: missing required field surfaces as a frontmatter finding
        a_findings = [f for f in rep['findings_detailed']
                      if mentions_skill(f, 'a')]
        self.assertTrue(
            any('frontmatter' in f['title'].lower()
                or 'required fields' in f['title'].lower()
                for f in a_findings),
            'no finding for skill a: %r' % all_titles)
        # skill b: description over the limit
        self.assertTrue(any('1024' in t or 'Description' in t
                            for t in all_titles),
                        'no over-limit finding: %r' % all_titles)
        # duplicates diverged
        self.assertTrue(any('Diverged copies' in t for t in all_titles),
                        'no diverged-copies finding: %r' % all_titles)

    # --- F05 -----------------------------------------------------------------

    def test_f05_malformed_yaml(self):
        _root, _home, _extra, rep = self.scan(fixtures.f05_malformed_yaml)
        st = gate_statuses(rep)
        self.assertEqual(st['G2'], 'fail', 'broken config must fail G2')
        cfg_fail = [f for f in rep['findings_detailed']
                    if f['fid'].startswith('CFG-') and f['status'] == 'fail']
        self.assertTrue(any('does not parse' in f['title'] for f in cfg_fail),
                        'no config-parse finding: %r' % titles(rep))
        bad = [f for f in rep['findings_detailed']
               if mentions_skill(f, 'bad')]
        self.assertTrue(bad, 'no finding mentions skill bad: %r' % titles(rep))
        if yaml is not None:
            # PyYAML present: the malformed frontmatter is detected; the
            # failure record is keyed by path, so the gate reads it as
            # unknown-or-fail, never as a silent pass.
            self.assertIn(st['G5'], ('fail', 'unknown'))
            self.assertTrue(any(f['status'] in ('fail', 'unknown')
                                and 'frontmatter' in f['title'].lower()
                                for f in bad))
        else:
            self.assertIn(st['G5'], ('unknown', 'fail'))
            self.assertTrue(any(f['status'] == 'unknown' for f in bad))

    # --- F06 -----------------------------------------------------------------

    def test_f06_nested_agents(self):
        _root, _home, _extra, rep = self.scan(fixtures.f06_nested_agents)
        st = gate_statuses(rep)
        self.assertEqual(st['G1'], 'warn')
        self.assertTrue(any('nested' in e.lower()
                            for e in gate_of(rep, 'G1')['evidence']),
                        'nested repo not in G1 evidence')
        self.assertEqual(st['G3'], 'warn')
        self.assertTrue(any('chain' in f['title'].lower()
                            for f in rep['findings_detailed']),
                        'no chain-budget finding: %r' % titles(rep))

    # --- F07 -----------------------------------------------------------------

    def test_f07_unused(self):
        _root, _home, _extra, rep = self.scan(fixtures.f07_unused)
        st = gate_statuses(rep)
        self.assertEqual(st['G9'], 'warn')
        confirmed = [j for j in rep.get('junk_classified', [])
                     if j.get('cls') == 'confirmed_unused']
        self.assertGreaterEqual(len(confirmed), 2,
                                'confirmed_unused: %r'
                                % rep.get('junk_classified'))
        g9_evidence = ' '.join(gate_of(rep, 'G9')['evidence'])
        self.assertIn('empty dirs: 12', g9_evidence)

    # --- F08 -----------------------------------------------------------------

    def test_f08_git_history(self):
        _root, _home, _extra, rep = self.scan(fixtures.f08_git_history)
        st = gate_statuses(rep)
        self.assertEqual(st['G7'], 'fail')
        all_titles = titles(rep)
        self.assertTrue(any('Tracked file over' in t for t in all_titles),
                        'no oversized-tracked-file finding: %r' % all_titles)
        self.assertTrue(any('No .gitignore' in t for t in all_titles),
                        'no missing-.gitignore finding: %r' % all_titles)
        self.assertTrue(any('checkouts' in t for t in all_titles),
                        'no duplicate-checkout finding: %r' % all_titles)

    # --- F09 -----------------------------------------------------------------

    def test_f09_symlinks(self):
        ws = self.base / 'ws0'
        root, home, extra = fixtures.f09_symlinks(ws)
        if not extra.get('symlinks_made'):
            self.skipTest('os.symlink unavailable on this platform')
        out = self.base / 'out.json'
        proc, rep = run_audit(root, home, out)
        self.assertEqual(proc.returncode, 0, proc.stderr[-400:])
        self.assert_report_schema(rep)
        self.proc = proc
        self.out_text = out.read_text(encoding='utf-8')
        blob = self.output_blob()
        self.assertNotIn(extra['canary'], blob, 'outside canary leaked')
        self.assertGreaterEqual(
            rep['stats'].get('skipped_symlinks_outside', 0), 1,
            'outside-pointing symlinks were not counted')
        for s in rep['secrets']:
            self.assertNotIn('link', os.path.basename(s['path']).lower(),
                             'symlinked file was scanned: %r' % s)
            self.assertNotIn('outside', s['path'].lower().replace('\\', '/'),
                             'outside canary became a finding: %r' % s)

    # --- F10 -----------------------------------------------------------------

    def test_f10_permissions(self):
        if os.name == 'nt':
            self.skipTest('POSIX-only: chmod 0o000')
        ws = self.base / 'ws0'
        root, home, extra = fixtures.f10_permissions(ws)
        self.addCleanup(os.chmod, extra['locked'], 0o700)
        out = self.base / 'out.json'
        proc, rep = run_audit(root, home, out)
        self.assertEqual(proc.returncode, 0, proc.stderr[-400:])
        self.assertIsNotNone(rep, 'report did not parse')
        self.assert_report_schema(rep)
        st = gate_statuses(rep)
        self.assertNotEqual(st['G6'], 'fail',
                            'unreadable secret must not fail G6')
        # the locked dir itself may appear as a structural observation
        # (an unowned top-level folder); its CONTENT must never surface:
        # no secret-category finding may reference it and the planted
        # value must be absent from the whole report
        secret_findings = json.dumps([f for f in rep['findings_detailed']
                                      if f.get('category') == 'secrets']).lower()
        self.assertNotIn('locked', secret_findings,
                         'a secrets finding references the unreadable dir')
        self.assertNotIn('sk-demo-locked-0000000000',
                         json.dumps(rep).lower(),
                         'the planted unreadable secret leaked into the report')

    # --- F11 -----------------------------------------------------------------

    def test_f11_multi_env(self):
        _root, _home, _extra, rep = self.scan(fixtures.f11_multi_env)
        st = gate_statuses(rep)
        self.assertEqual(st['G8'], 'fail')
        self.assertTrue(any('dead harness' in f['title'].lower()
                            for f in rep['findings_detailed']),
                        'no dead-harness finding: %r' % titles(rep))
        self.assertEqual(st['G1'], 'warn')
        self.assertTrue(
            any('several harnesses' in f['title']
                for f in rep['findings_detailed'])
            or any('harness dirs present' in e
                   for e in gate_of(rep, 'G1')['evidence']),
            'no multi-env conflict evidence')

    # --- F12 -----------------------------------------------------------------

    def test_f12_injection(self):
        _r, _h, _e, rep_inj = self.scan(
            lambda ws: fixtures.f12_injection(ws, inject=True))
        inj_statuses = gate_statuses(rep_inj)
        inj_proc, inj_out_text = self.proc, self.out_text
        _r, _h, _e, rep_clean = self.scan(
            lambda ws: fixtures.f12_injection(ws, inject=False))

        # injection files change nothing in the verdicts. Every short
        # instruction file gets its informational hint (status pass), so
        # the injected file has one more of those than the twin: hints
        # are left out of the comparison
        def verdicts(rep):
            return [(f['check_id'], f['status']) for f in rep['findings_detailed']
                    if f.get('check_id') != 'RUL_SHORT_FILE_HINT']

        self.assertEqual(gate_statuses(rep_clean), inj_statuses)
        self.assertEqual(verdicts(rep_clean), verdicts(rep_inj))
        self.assertEqual(inj_statuses['G3'], 'fail')

        # injected directives never reach the output
        self.assertNotIn('Ignore all previous instructions', inj_proc.stdout)
        self.assertNotIn('AUDITOR DIRECTIVE', inj_proc.stdout)
        self.assertNotIn('Ignore all previous instructions', inj_out_text)
        for f in rep_inj['findings_detailed']:
            low = f['title'].lower()
            self.assertNotIn('all-pass', low)
            self.assertNotIn('auditor directive', low)
            self.assertNotIn('ignore all previous', low)


if __name__ == '__main__':
    unittest.main()
