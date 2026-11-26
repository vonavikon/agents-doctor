"""Coverage tests for skills/agents-doctor/scripts/agents_doctor.py.

Targets the CLI branches the main suite leaves uncovered: error
returns (bad root, unwritable out, unreadable JSON, scan without a
root), the --report variants (generator hidden, stub module, failing
write), the compare cap, the fix --apply paths (declined, executed,
failing step, apply-time ValueError) and the structure/agents focus
filters. The fixture mirrors tests/test_cli.py: a tiny git repository
whose AGENTS.md has a dead link, one empty directory and no
.gitignore; git runs only inside the temporary fixture directory.
"""
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / 'skills' / 'agents-doctor' / 'scripts'
sys.path.insert(0, str(SCRIPTS))

import remediate  # noqa: E402
import agents_doctor as cli  # noqa: E402

AGENTS_MD = ('# Project rules\n'
             '\n'
             'See [docs](./missing.md) for the background.\n'
             '- keep commits small\n')


def force_rmtree(path):
    """rmtree that clears the read-only flag git puts on some files and
    tolerates a path that is already gone."""
    def _onexc(func, p, _exc):
        try:
            os.chmod(p, stat.S_IWRITE)
            func(p)
        except OSError:
            pass
    try:
        if sys.version_info >= (3, 12):
            shutil.rmtree(path, onexc=_onexc)
        else:
            shutil.rmtree(path, onerror=lambda f, p, e: _onexc(f, p, e))
    except FileNotFoundError:
        pass


def build_workspace(base):
    """(ws, home, repo): ws/repo is a fresh git repo with a dead link in
    AGENTS.md, one empty dir and no .gitignore; home is empty."""
    ws, home = base / 'ws', base / 'home'
    repo = ws / 'repo'
    repo.mkdir(parents=True)
    home.mkdir()
    (repo / 'AGENTS.md').write_text(AGENTS_MD, encoding='utf-8')
    (repo / 'empty').mkdir()
    env = dict(os.environ, GIT_OPTIONAL_LOCKS='0')
    subprocess.run(['git', '-C', str(repo), 'init', '-q'],
                   check=True, capture_output=True, env=env)
    return ws, home, repo


class CliCase(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp(prefix='wsa-covcli-'))
        self.addCleanup(force_rmtree, self.base)
        os.environ['AGENTS_DOCTOR_KEY_PATH'] = str(self.base / 'fp_key')
        self.addCleanup(os.environ.pop, 'AGENTS_DOCTOR_KEY_PATH', None)
        self.ws, self.home, self.repo = build_workspace(self.base)

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


class AuditErrors(CliCase):
    def test_audit_rejects_not_a_directory(self):
        code, _out, err = self.run_cli(
            ['audit', str(self.base / 'nope'), '--home', str(self.home)])
        self.assertEqual(code, 1)
        self.assertIn('not a directory', err)

    def test_audit_rejects_unwritable_out(self):
        # the parent of --out is a plain file: no folder can be made there
        blocker = self.base / 'blocker'
        blocker.write_text('not a folder', encoding='utf-8')
        bad_out = blocker / 'nested' / 'scan.json'
        code, _out, err = self.run_cli(
            ['audit', str(self.ws), '--home', str(self.home),
             '--out', str(bad_out)])
        self.assertEqual(code, 1)
        self.assertIn('cannot write', err)

    def test_audit_creates_a_missing_output_folder(self):
        # the skill writes into <root>/.agents-doctor/, which does not
        # exist on a first run
        fresh = self.base / 'no' / 'such' / 'dir' / 'scan.json'
        code, out, err = self.run_cli(
            ['audit', str(self.ws), '--home', str(self.home),
             '--out', str(fresh)])
        self.assertEqual(code, 0, err)
        self.assertTrue(fresh.is_file())

    def test_argparse_usage_error_exits_2(self):
        with self.assertRaises(SystemExit) as cx:
            with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
                cli.main(['audit'])  # root is missing
        self.assertEqual(cx.exception.code, 2)
        with self.assertRaises(SystemExit) as cx:
            with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
                cli.main(['no-such-command'])
        self.assertEqual(cx.exception.code, 2)


class ReportFlagVariants(CliCase):
    def test_report_flag_with_generator_hidden(self):
        out_json = self.base / 'scan.json'
        report = self.base / 'AUDIT.md'
        with mock.patch.dict(sys.modules, {'report_generator': None}):
            code, _out, err = self.run_cli(
                ['audit', str(self.ws), '--home', str(self.home),
                 '--out', str(out_json), '--report', str(report)])
        self.assertEqual(code, 1)
        self.assertIn('report generator unavailable', err)
        self.assertFalse(report.exists())
        self.assertTrue(out_json.is_file())  # the scan itself still landed

    def test_report_flag_with_module_without_callable(self):
        stub = types.ModuleType('report_generator')  # no generate_* attrs
        out_json = self.base / 'scan.json'
        report = self.base / 'AUDIT.md'
        with mock.patch.dict(sys.modules, {'report_generator': stub}):
            code, _out, err = self.run_cli(
                ['audit', str(self.ws), '--home', str(self.home),
                 '--out', str(out_json), '--report', str(report)])
        self.assertEqual(code, 1)
        self.assertIn('report generator unavailable', err)
        self.assertFalse(report.exists())

    def test_report_flag_with_unwritable_report_path(self):
        out_json = self.base / 'scan.json'
        report = str(self.base / 'AUDIT.md') + '\0broken'  # NUL: ValueError
        code, _out, err = self.run_cli(
            ['audit', str(self.ws), '--home', str(self.home),
             '--out', str(out_json), '--report', report])
        self.assertEqual(code, 1)
        self.assertIn('report generation failed', err)


class FocusFilters(CliCase):
    def test_focus_structure_keeps_structure_gates_only(self):
        _out_json, rep, out = self.audit(extra=['--focus', 'structure'])
        self.assertEqual({g['gid'] for g in rep['gates']}, {'G1', 'G4', 'G9'})
        gates = {f['gate'] for f in rep['findings_detailed']}
        self.assertTrue(gates <= {'G1', 'G4', 'G9'}, gates)
        self.assertEqual(rep.get('focus'), 'structure')
        self.assertIn('(focus: structure)', out)
        self.assertIn('gates: fail', out)  # the tally line stays

    def test_focus_agents_keeps_agents_gates_only(self):
        _out_json, rep, out = self.audit(extra=['--focus', 'agents'])
        self.assertEqual({g['gid'] for g in rep['gates']},
                         {'G2', 'G3', 'G5', 'G8'})
        gates = {f['gate'] for f in rep['findings_detailed']}
        self.assertTrue(gates <= {'G2', 'G3', 'G5', 'G8'}, gates)
        self.assertEqual(rep.get('focus'), 'agents')
        self.assertIn('(focus: agents)', out)


class CompareCommand(CliCase):
    def write_pair(self, new, old):
        pnew = self.base / 'new.json'
        pold = self.base / 'old.json'
        pnew.write_text(json.dumps(new), encoding='utf-8')
        pold.write_text(json.dumps(old), encoding='utf-8')
        return pnew, pold

    def test_compare_with_missing_file_exits_1(self):
        pnew, _pold = self.write_pair({'findings': []}, {'findings': []})
        (self.base / 'old.json').unlink()
        code, _out, err = self.run_cli(['compare', str(pnew), str(_pold)])
        self.assertEqual(code, 1)
        self.assertIn('cannot read', err)

    def test_compare_lists_only_ten_paths_per_bucket(self):
        new = {'findings': [{'fp': 'f%d' % i, 'section': 'junk',
                             'path': 'ws/p%d' % i} for i in range(11)]}
        old = {'findings': []}
        pnew, pold = self.write_pair(new, old)
        code, out, err = self.run_cli(['compare', str(pnew), str(pold)])
        self.assertEqual(code, 0, err)
        self.assertIn('NEW (11)', out)
        self.assertIn('... and 1 more', out)
        self.assertIn('11 new, 0 resolved, 0 persisting, 0 changed', out)


class ExplainCommand(CliCase):
    def test_explain_with_corrupt_scan_exits_1(self):
        bad = self.base / 'bad.json'
        bad.write_text('{ nope', encoding='utf-8')
        code, _out, err = self.run_cli(['explain', str(bad), 'SEC-001'])
        self.assertEqual(code, 1)
        self.assertIn('cannot read', err)


class FixCommand(CliCase):
    def fix(self, fid, extra=(), apply_input=None):
        """Run 'fix' with a patched input() when an --apply
        confirmation is simulated; otherwise a plain CLI call."""
        out_json = self.base / 'scan.json'
        argv = ['fix', str(out_json), fid, *extra]
        if apply_input is None:
            return self.run_cli(argv)
        import builtins
        out, err = StringIO(), StringIO()
        with redirect_stdout(out), redirect_stderr(err), \
                mock.patch.object(builtins, 'input', side_effect=apply_input):
            code = cli.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_fix_with_corrupt_scan_exits_1(self):
        bad = self.base / 'bad.json'
        bad.write_text('{ nope', encoding='utf-8')
        code, _out, err = self.run_cli(['fix', str(bad), 'SEC-001'])
        self.assertEqual(code, 1)
        self.assertIn('cannot read', err)

    def test_fix_scan_without_root_exits_1(self):
        scan = {'findings_detailed': []}  # no 'root' key
        out_json = self.base / 'scan.json'
        out_json.write_text(json.dumps(scan), encoding='utf-8')
        code, _out, err = self.run_cli(['fix', str(out_json), 'SEC-001'])
        self.assertEqual(code, 1)
        self.assertIn('scan has no root', err)

    def test_fix_unknown_fid_exits_3(self):
        out_json, _rep, _out = self.audit()
        code, _out, err = self.run_cli(['fix', str(out_json), 'NOPE-999'])
        self.assertEqual(code, 3)
        self.assertIn('NOPE-999 not found', err)

    def test_fix_target_outside_root_exits_1(self):
        scan = {'root': str(self.ws), 'findings_detailed': [
            {'fid': 'HLTH-042', 'title': 'Unused data (confirmed_unused): junk',
             'autofix_available': True,
             'evidence': [{'path': '../../outside'}]}]}
        out_json = self.base / 'scan.json'
        out_json.write_text(json.dumps(scan), encoding='utf-8')
        code, _out, err = self.run_cli(['fix', str(out_json), 'HLTH-042'])
        self.assertEqual(code, 1)
        self.assertIn('escapes the workspace root', err)

    def test_fix_apply_declined_changes_nothing(self):
        out_json, rep, _out = self.audit()
        fid = self.fid_for(rep, 'No .gitignore in repo')
        code, out, _err = self.fix(fid, extra=['--apply'],
                                   apply_input=lambda _prompt: 'no')
        self.assertEqual(code, 0)
        self.assertIn('declined', out)
        self.assertFalse((self.repo / '.gitignore').exists())
        self.assertTrue((self.repo / 'empty').exists())

    def test_fix_apply_executes_the_plan(self):
        out_json, rep, _out = self.audit()
        fid = self.fid_for(rep, 'No .gitignore in repo')
        code, out, err = self.fix(fid, extra=['--apply'],
                                  apply_input=lambda _prompt: 'yes')
        self.assertEqual(code, 0, err)
        self.assertIn('executed 1, skipped 0, failed 0', out)
        self.assertTrue((self.repo / '.gitignore').is_file())

    def test_fix_apply_reports_a_failing_step(self):
        out_json, rep, _out = self.audit()
        fid = self.fid_for(rep, 'No .gitignore in repo')

        def delete_repo_then_confirm(_prompt):
            force_rmtree(self.repo)  # the write target's parent disappears
            return 'yes'

        code, out, err = self.fix(fid, extra=['--apply'],
                                  apply_input=delete_repo_then_confirm)
        self.assertEqual(code, 1)
        self.assertIn('executed 0, skipped 0, failed 1', out)
        self.assertIn('failed [write_gitignore]', err)

    def test_fix_apply_value_error_exits_1(self):
        out_json, rep, _out = self.audit()
        fid = self.fid_for(rep, 'No .gitignore in repo')
        with mock.patch.object(remediate, 'apply_plan',
                               side_effect=ValueError('plan rejected')):
            code, _out, err = self.run_cli(
                ['fix', str(out_json), fid, '--apply'])
        self.assertEqual(code, 1)
        self.assertIn('plan rejected', err)


if __name__ == '__main__':
    unittest.main()
