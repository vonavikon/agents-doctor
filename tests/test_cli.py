"""Stage-4 tests: agents_doctor.py CLI (audit / compare / explain / fix).

The fixture is a tiny workspace: one git repository whose AGENTS.md has
a dead link, one empty directory and no .gitignore, plus an empty home.
git runs only inside the temporary fixture directory.
"""
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from importlib.util import find_spec
from io import StringIO
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / 'skills' / 'agents-doctor' / 'scripts'
sys.path.insert(0, str(SCRIPTS))

import agents_doctor as cli  # noqa: E402

AGENTS_MD = ('# Project rules\n'
             '\n'
             'See [docs](./missing.md) for the background.\n'
             '- keep commits small\n')


def force_rmtree(path):
    """rmtree that clears the read-only flag git puts on some files."""
    def _onexc(func, p, _exc):
        os.chmod(p, stat.S_IWRITE)
        func(p)
    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=_onexc)
    else:
        shutil.rmtree(path, onerror=lambda func, p, _ei: _onexc(func, p, _ei))


def build_workspace(base):
    """(ws, home, repo): ws/repo is a fresh git repo with a dead link in
    AGENTS.md, one empty dir and no .gitignore; home is empty."""
    ws, home = base / 'ws', base / 'home'
    repo = ws / 'repo'
    repo.mkdir(parents=True)
    home.mkdir()
    (repo / 'AGENTS.md').write_text(AGENTS_MD, encoding='utf-8')
    (repo / 'empty').mkdir()
    subprocess.run(['git', '-C', str(repo), 'init', '-q'],
                   check=True, capture_output=True)
    return ws, home, repo


class CliCase(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp())
        self.ws, self.home, self.repo = build_workspace(self.base)

    def tearDown(self):
        force_rmtree(self.base)

    def run_cli(self, argv):
        out, err = StringIO(), StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cli.main(argv)
        return code, out.getvalue(), err.getvalue()

    def audit(self, extra=()):
        out_json = self.base / 'scan.json'
        code, out, err = self.run_cli(
            ['audit', str(self.ws), '--home', str(self.home),
             '--out', str(out_json), *extra])
        self.assertEqual(code, 0, err)
        rep = json.loads(out_json.read_text(encoding='utf-8'))
        return out_json, rep, out

    @staticmethod
    def fid_for(rep, needle):
        for f in rep['findings_detailed']:
            if needle in f['title']:
                return f['fid']
        raise AssertionError('no finding titled like %r; got %s'
                             % (needle, [f['title'] for f in rep['findings_detailed']]))


class AuditCommand(CliCase):
    def test_audit_writes_scan_with_nine_gates(self):
        out_json, rep, out = self.audit()
        self.assertTrue(out_json.is_file())
        self.assertEqual([g['gid'] for g in rep['gates']],
                         ['G%d' % n for n in range(1, 10)])
        titles = [f['title'] for f in rep['findings_detailed']]
        self.assertTrue(titles)
        self.assertTrue(any('missing.md' in t for t in titles), titles)
        self.assertTrue(any(t.startswith('No .gitignore in repo')
                            for t in titles), titles)
        self.assertTrue(any('empty directories' in t for t in titles), titles)
        self.assertIn('gates: fail', out)   # the gates tally line
        self.assertIn('audit:', out)        # one-line summary

    def test_focus_security_keeps_security_gates_only(self):
        _out_json, rep, out = self.audit(extra=['--focus', 'security'])
        gids = {g['gid'] for g in rep['gates']}
        self.assertNotIn('G1', gids)
        self.assertIn('G6', gids)
        self.assertEqual(gids, {'G6', 'G7'})
        cats = {f['category'] for f in rep['findings_detailed']}
        self.assertTrue(cats)  # fixture warns: no secret-prevention hook
        self.assertTrue(cats <= {'secrets', 'git'}, cats)
        self.assertEqual(rep.get('focus'), 'security')
        self.assertIn('(focus: security)', out)


class ExplainCommand(CliCase):
    def test_explain_prints_real_finding(self):
        out_json, rep, _ = self.audit()
        fid = rep['findings_detailed'][0]['fid']
        code, out, err = self.run_cli(['explain', str(out_json), fid])
        self.assertEqual(code, 0, err)
        self.assertIn(fid, out)
        # the digest card: what, where, what to do. The raw evidence
        # list (absolute paths, quoted lines) is not printed.
        self.assertIn('what:', out)
        self.assertIn('what to do:', out)
        self.assertNotIn('evidence:', out)

    def test_explain_unknown_fid_exits_2(self):
        out_json, _rep, _ = self.audit()
        code, _out, err = self.run_cli(['explain', str(out_json), 'NOPE-999'])
        self.assertEqual(code, 2)
        self.assertIn('finding not found', err)


class CompareCommand(unittest.TestCase):
    def test_compare_prints_block_and_counts(self):
        base = Path(tempfile.mkdtemp())
        self.addCleanup(force_rmtree, base)
        new = {'schema_version': '1.0', 'root': 'ws', 'findings': [
            {'fp': 'fp-new', 'section': 'junk', 'path': 'ws/temp.txt'},
            {'fp': 'fp-keep', 'section': 'secrets', 'path': 'ws/repo/.env'},
            {'fp': 'fp-changed2', 'section': 'duplicates', 'path': 'same/file'},
        ]}
        old = {'schema_version': '1.0', 'root': 'ws', 'findings': [
            {'fp': 'fp-keep', 'section': 'secrets', 'path': 'ws/repo/.env'},
            {'fp': 'fp-gone', 'section': 'junk', 'path': 'ws/old.log'},
            {'fp': 'fp-changed1', 'section': 'duplicates', 'path': 'same/file'},
        ]}
        pnew, pold = base / 'new.json', base / 'old.json'
        pnew.write_text(json.dumps(new), encoding='utf-8')
        pold.write_text(json.dumps(old), encoding='utf-8')
        out, err = StringIO(), StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cli.main(['compare', str(pnew), str(pold)])
        self.assertEqual(code, 0, err.getvalue())
        text = out.getvalue()
        for word in ('NEW', 'RESOLVED', 'PERSISTING', 'CHANGED'):
            self.assertIn(word, text)
        self.assertIn('ws/temp.txt', text)  # a new path is listed
        # fp-changed2 is new (new fingerprint) and changed (same
        # section+path as fp-changed1); symmetrically fp-changed1's old
        # fingerprint counts as resolved, next to fp-gone
        self.assertIn('2 new, 2 resolved, 1 persisting, 1 changed', text)


class FixCommand(CliCase):
    def test_fix_without_apply_is_a_dry_run(self):
        out_json, rep, _ = self.audit()
        fid = self.fid_for(rep, 'No .gitignore in repo')
        code, out, err = self.run_cli(['fix', str(out_json), fid])
        self.assertEqual(code, 0, err)
        self.assertIn('write_gitignore', out)
        self.assertIn('dry run', out)
        # nothing changed on disk
        self.assertFalse((self.repo / '.gitignore').exists())
        self.assertTrue((self.repo / 'empty').exists())
        self.assertFalse((self.ws / '.agents-doctor-trash').exists())


class ReportFlag(CliCase):
    @unittest.skipIf(find_spec('report_generator') is not None,
                     'report_generator.py exists; absence path not testable')
    def test_report_flag_fails_cleanly_without_generator(self):
        out_json = self.base / 'scan.json'
        report = self.base / 'AUDIT.md'
        code, _out, err = self.run_cli(
            ['audit', str(self.ws), '--home', str(self.home),
             '--out', str(out_json), '--report', str(report)])
        self.assertEqual(code, 1)
        self.assertIn('report generator unavailable', err)
        self.assertFalse(report.exists())

    @unittest.skipIf(find_spec('report_generator') is None,
                     'report_generator.py missing; happy path not testable')
    def test_report_flag_writes_markdown_with_generator(self):
        out_json = self.base / 'scan.json'
        report = self.base / 'AUDIT.md'
        code, out, err = self.run_cli(
            ['audit', str(self.ws), '--home', str(self.home),
             '--out', str(out_json), '--report', str(report)])
        self.assertEqual(code, 0, err)
        self.assertTrue(report.is_file())
        self.assertGreater(report.stat().st_size, 0)
        self.assertIn('report:', out)


if __name__ == '__main__':
    unittest.main()
