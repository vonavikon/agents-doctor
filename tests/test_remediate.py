"""Tests for remediate.py: plan / apply_plan / reaudit and safety rails.

Same tiny fixture as test_cli.py: one git repo (dead link in AGENTS.md,
empty dir, no .gitignore) plus, for the trash test, an old untracked
junk file at the workspace root so the classifier marks it
confirmed_unused.
"""
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / 'skills' / 'agents-doctor' / 'scripts'
sys.path.insert(0, str(SCRIPTS))

import audit_scan  # noqa: E402
import remediate  # noqa: E402

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
    ws, home = base / 'ws', base / 'home'
    repo = ws / 'repo'
    repo.mkdir(parents=True)
    home.mkdir()
    (repo / 'AGENTS.md').write_text(AGENTS_MD, encoding='utf-8')
    (repo / 'empty').mkdir()
    subprocess.run(['git', '-C', str(repo), 'init', '-q'],
                   check=True, capture_output=True)
    return ws, home, repo


class RemediateCase(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp())
        self.ws, self.home, self.repo = build_workspace(self.base)

    def tearDown(self):
        force_rmtree(self.base)

    def scan(self):
        """Full in-process scan of the fixture, dumped to scan.json."""
        self.scan_path = self.base / 'scan.json'
        self.rep = audit_scan.scan(self.ws, self.home)
        self.scan_path.write_text(
            json.dumps(self.rep, ensure_ascii=False, indent=2), encoding='utf-8')
        return self.rep

    @staticmethod
    def fid_for(rep, needle):
        for f in rep['findings_detailed']:
            if needle in f['title']:
                return f['fid']
        raise AssertionError('no finding titled like %r; got %s'
                             % (needle, [f['title'] for f in rep['findings_detailed']]))

    def apply_quiet(self, steps, root, **kw):
        out = StringIO()
        err = StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            report = remediate.apply_plan(steps, str(root), **kw)
        return report


class EmptyDirRmdir(RemediateCase):
    def test_plan_and_apply_removes_empty_dir(self):
        rep = self.scan()
        fid = self.fid_for(rep, 'empty directories')
        steps = remediate.plan(rep, fid)
        self.assertEqual(len(steps), 1)
        self.assertEqual(steps[0]['action'], 'rmdir')
        self.assertEqual(Path(steps[0]['target']),
                         (self.repo / 'empty').resolve())
        self.assertTrue(steps[0]['reversible'])
        report = self.apply_quiet(steps, self.ws, assume_yes=True)
        self.assertEqual(len(report['executed']), 1)
        self.assertEqual(report['failed'], [])
        self.assertEqual(report['skipped'], [])
        self.assertFalse((self.repo / 'empty').exists())


class GitignoreOnce(RemediateCase):
    def test_created_once_then_plan_says_already_exists(self):
        rep = self.scan()
        fid = self.fid_for(rep, 'No .gitignore in repo')
        gi = self.repo / '.gitignore'

        steps = remediate.plan(rep, fid)
        self.assertEqual(steps[0]['action'], 'write_gitignore')
        self.assertNotIn('already exists', steps[0]['note'])
        report = self.apply_quiet(steps, self.ws, assume_yes=True)
        self.assertEqual(len(report['executed']), 1)
        self.assertTrue(gi.is_file())
        content = gi.read_text(encoding='utf-8')
        self.assertIn('.env', content)
        self.assertIn('node_modules', content)

        # stale scan: the finding is still there but the file exists now
        steps2 = remediate.plan(rep, fid)
        self.assertIn('already exists', steps2[0]['note'])
        report2 = self.apply_quiet(steps2, self.ws, assume_yes=True)
        self.assertEqual(report2['executed'], [])
        self.assertEqual(len(report2['skipped']), 1)
        self.assertEqual(gi.read_text(encoding='utf-8'), content)  # no dup write


class TrashMove(RemediateCase):
    def test_confirmed_junk_lands_in_trash_with_relative_path(self):
        junk = self.ws / 'temp-data.txt'   # 'temp' prefix -> junk file rule
        junk.write_text('stale junk\n', encoding='utf-8')
        old = time.time() - 100 * 86400    # older than 90d -> confirmed_unused
        os.utime(junk, (old, old))
        rep = self.scan()
        fid = self.fid_for(rep, 'Unused data (confirmed_unused)')
        steps = remediate.plan(rep, fid)
        self.assertEqual(len(steps), 1)
        self.assertEqual(steps[0]['action'], 'trash_move')
        report = self.apply_quiet(steps, self.ws, assume_yes=True)
        self.assertEqual(len(report['executed']), 1)
        self.assertFalse(junk.exists())

        trash = self.ws / remediate.TRASH_DIR_NAME
        moved = list(trash.rglob('temp-data.txt'))
        self.assertEqual(len(moved), 1)
        self.assertEqual(moved[0].read_text(encoding='utf-8'), 'stale junk\n')
        rel = moved[0].relative_to(trash)
        self.assertEqual(len(rel.parts), 2)          # <timestamp>/temp-data.txt
        self.assertEqual(rel.parts[1], 'temp-data.txt')


class Unsupported(RemediateCase):
    def test_unsupported_fid_raises_naming_the_fid(self):
        rep = self.scan()
        with self.assertRaises(remediate.UnsupportedError) as cm:
            remediate.plan(rep, 'SEC-001')           # exists: no-prevention warn
        self.assertIn('SEC-001', str(cm.exception))
        # dead links used to be the unsupported example; they now plan
        # manual fix_dead_link steps instead (covered in
        # tests/test_remediation_v3.py), so the unsupported case here is
        # a finding type with no fix at all
        fabricated = {'root': str(self.ws), 'findings_detailed': [{
            'fid': 'RUL-099', 'gate': 'G3', 'category': 'rules',
            'severity': 'low', 'status': 'warn',
            'title': 'Two rule sources at .', 'description': 'fabricated',
            'evidence': [{'path': '.'}], 'recommendation': 'by hand'}]}
        with self.assertRaises(remediate.UnsupportedError) as cm:
            remediate.plan(fabricated, 'RUL-099')
        self.assertIn('RUL-099', str(cm.exception))

    def test_unknown_fid_raises(self):
        rep = self.scan()
        with self.assertRaises(remediate.UnsupportedError) as cm:
            remediate.plan(rep, 'NOPE-999')
        self.assertIn('NOPE-999', str(cm.exception))


class Containment(RemediateCase):
    def test_target_outside_root_refused_and_nothing_moves(self):
        outside = self.base / 'escapee.txt'
        outside.write_text('do not touch\n', encoding='utf-8')
        rep = {'root': str(self.ws),
               'findings_detailed': [{
                   'fid': 'HLTH-009', 'gate': 'G9', 'category': 'health',
                   'severity': 'low', 'status': 'warn',
                   'title': 'Unused data (confirmed_unused): ../escapee.txt',
                   'description': 'fabricated', 'confidence': 0.9,
                   'evidence': [{'path': '../escapee.txt'}],
                   'recommendation': 'x', 'autofix_available': True}]}
        with self.assertRaises(ValueError):
            remediate.plan(rep, 'HLTH-009')
        step = {'action': 'trash_move', 'target': str(outside),
                'command': 'move', 'reversible': True, 'note': ''}
        # a pre-flight escape is recorded as
        # a refused step (same shape as an in-flight refusal), not
        # raised: the caller reads failed[0]['error'] instead of
        # catching ValueError
        with redirect_stdout(StringIO()):
            report = remediate.apply_plan([step], str(self.ws),
                                          assume_yes=True)
        self.assertEqual(report['executed'], [])
        self.assertEqual(len(report['failed']), 1)
        self.assertIn('SecurityRefusal', report['failed'][0]['error'])
        self.assertTrue(outside.exists())            # nothing moved
        self.assertFalse((self.ws / remediate.TRASH_DIR_NAME).exists())


class Confirmation(RemediateCase):
    def test_prompt_requires_exactly_yes(self):
        rep = self.scan()
        fid = self.fid_for(rep, 'empty directories')
        steps = remediate.plan(rep, fid)
        for answer in ('no', 'y', 'YES'):
            with mock.patch('builtins.input', return_value=answer):
                report = self.apply_quiet(steps, self.ws)
            self.assertTrue(report['declined'], answer)
            self.assertEqual(report['executed'], [])
            self.assertTrue((self.repo / 'empty').exists())
        with mock.patch('builtins.input', return_value='yes'):
            report = self.apply_quiet(steps, self.ws)
        self.assertFalse(report['declined'])
        self.assertEqual(len(report['executed']), 1)
        self.assertFalse((self.repo / 'empty').exists())

    def test_empty_plan_touches_nothing_and_never_prompts(self):
        with mock.patch('builtins.input',
                        side_effect=AssertionError('prompted on empty plan')):
            report = self.apply_quiet([], self.ws)
        self.assertEqual(report, {'executed': [], 'failed': [],
                                  'skipped': [], 'declined': False,
                                  'trash_run': None, 'opid': None})


class Reaudit(RemediateCase):
    def test_reaudit_reports_resolved_empty_dir(self):
        self.scan()
        fid = self.fid_for(self.rep, 'empty directories')
        steps = remediate.plan(self.rep, fid)
        self.apply_quiet(steps, self.ws, assume_yes=True)
        new_rep, diff = remediate.reaudit(self.ws, self.home,
                                          str(self.scan_path))
        self.assertTrue((self.base / 'scan.after.json').is_file())
        self.assertGreaterEqual(len(diff['resolved']), 1)
        self.assertTrue(any('empty' in f['path'] for f in diff['resolved']),
                        diff['resolved'])
        self.assertEqual(new_rep['junk']['empty_dirs'], [])


# --- trashops-backed moves, TOCTOU, crash recovery --------------------------------

import json  # noqa: E402  (manifest checks)

import trashops  # noqa: E402


def unused_data_rep(ws, *rels):
    """A hand-crafted confirmed-unused finding for the given paths."""
    return {'root': str(ws), 'findings_detailed': [{
        'fid': 'HLTH-042', 'gate': 'G9', 'category': 'health',
        'severity': 'low', 'status': 'warn',
        'title': 'Unused data (confirmed_unused): %s' % ', '.join(rels),
        'description': 'fabricated for tests', 'confidence': 0.9,
        'evidence': [{'path': r} for r in rels],
        'recommendation': 'x', 'autofix_available': True}]}


class TrashRunManifest(RemediateCase):
    def test_trash_move_records_manifest_and_opid(self):
        junk = self.ws / 'temp-data.txt'
        junk.write_text('stale junk\n', encoding='utf-8')
        old = time.time() - 100 * 86400
        os.utime(junk, (old, old))
        rep = unused_data_rep(self.ws, 'temp-data.txt')
        steps = remediate.plan(rep, 'HLTH-042')
        self.assertIn('snapshot', steps[0])
        self.assertEqual(steps[0]['snapshot']['type'], 'file')

        report = self.apply_quiet(steps, self.ws, assume_yes=True)
        self.assertEqual(len(report['executed']), 1)

        run_dir = Path(report['trash_run'])
        self.assertRegex(run_dir.name, r'^\d{8}-\d{6}-[0-9a-f]{8}$')
        self.assertEqual(run_dir.name.split('-')[-1], report['opid'])
        data = json.loads((run_dir / 'manifest.json').read_text(encoding='utf-8'))
        self.assertEqual(data['tool'], 'remediate')
        self.assertEqual(data['opid'], report['opid'])
        self.assertEqual(data['totals']['moved'], 1)
        self.assertEqual(len(data['entries']), 1)
        entry = data['entries'][0]
        self.assertEqual(entry['original_path'], 'temp-data.txt')
        self.assertEqual(entry['status'], 'moved')
        self.assertTrue(entry['restorable'])
        self.assertEqual((run_dir / entry['trash_path']).read_text(
            encoding='utf-8'), 'stale junk\n')


class ToctouRespect(RemediateCase):
    def test_dir_gained_file_between_plan_and_apply_skipped_changed(self):
        rep = self.scan()
        fid = self.fid_for(rep, 'empty directories')
        steps = remediate.plan(rep, fid)
        (self.repo / 'empty' / 'new-tenant.txt').write_text('x', encoding='utf-8')

        report = self.apply_quiet(steps, self.ws, assume_yes=True)

        self.assertEqual(report['executed'], [])
        self.assertEqual(report['failed'], [])
        self.assertEqual(report['skipped'],
                         [{'action': 'rmdir',
                           'target': str((self.repo / 'empty').resolve()),
                           'reason': 'changed'}])
        self.assertTrue((self.repo / 'empty' / 'new-tenant.txt').is_file())

    def test_file_modified_between_plan_and_apply_skipped_changed(self):
        junk = self.ws / 'temp-data.txt'
        junk.write_text('stale junk\n', encoding='utf-8')
        old = time.time() - 100 * 86400
        os.utime(junk, (old, old))
        rep = unused_data_rep(self.ws, 'temp-data.txt')
        steps = remediate.plan(rep, 'HLTH-042')
        junk.write_text('stale junk, edited after planning\n', encoding='utf-8')

        report = self.apply_quiet(steps, self.ws, assume_yes=True)

        self.assertEqual(report['executed'], [])
        self.assertEqual(report['skipped'][0]['reason'], 'changed')
        self.assertTrue(junk.is_file())
        self.assertFalse((self.ws / remediate.TRASH_DIR_NAME).exists())


class PreOpCheckUnit(RemediateCase):
    """Direct probes of the pre-operation gate
    (trashops._pre_operation_check); the attack-level coverage lives in
    tests/test_toctou_security.py."""

    def check(self, target, **kw):
        return trashops._pre_operation_check(self.ws, target, **kw)

    def test_ok_for_targets_under_root(self):
        f = self.ws / 'plain.txt'
        f.write_text('x', encoding='utf-8')
        self.assertEqual(self.check(f), (True, None))
        self.assertEqual(self.check(f, snapshot=trashops.snapshot(f)),
                         (True, None))
        ok, _reason = self.check(self.repo, expected_type='dir')
        self.assertTrue(ok)

    def test_outside_target_is_escape(self):
        # resolve(): on macOS the temp dir lives behind a /tmp
        # symlink; without resolving, the symlink check fires before
        # the escape check and the reason word differs
        out = (self.base / 'out.txt').resolve()
        out.write_text('x', encoding='utf-8')
        self.assertEqual(self.check(out), (False, 'escape'))

    def test_snapshot_drift_is_changed(self):
        f = self.ws / 'drift.txt'
        f.write_bytes(b'1')
        snap = trashops.snapshot(f)
        f.write_bytes(b'123')
        self.assertEqual(self.check(f, snapshot=snap), (False, 'changed'))

    def test_missing_target(self):
        self.assertEqual(self.check(self.ws / 'gone.txt'), (False, 'missing'))
        # create-style operations may build into a not-yet-existing path
        self.assertEqual(self.check(self.ws / 'fresh' / 'new.txt',
                                    allow_missing=True), (True, None))

    def test_expected_type_mismatch_is_changed(self):
        f = self.ws / 'afile.txt'
        f.write_text('x', encoding='utf-8')
        self.assertEqual(self.check(f, expected_type='dir'),
                         (False, 'changed'))

    def test_symlink_anywhere_in_the_chain_refused(self):
        if not hasattr(os, 'symlink'):
            self.skipTest('os.symlink unavailable')
        # the link destination is INSIDE the workspace: containment
        # alone would pass, only the literal-chain walk catches it
        vault = self.ws / 'private'
        vault.mkdir()
        try:
            os.symlink(str(vault), str(self.ws / 'lnk'))
        except (OSError, NotImplementedError):
            self.skipTest('symlink creation unavailable on this system')
        inside = vault / 'real.txt'
        inside.write_text('x', encoding='utf-8')
        self.assertEqual(self.check(self.ws / 'lnk' / 'real.txt'),
                         (False, 'symlink'))
        self.assertEqual(self.check(self.ws / 'lnk' / 'new.txt',
                                    allow_missing=True), (False, 'symlink'))


class BatchContinues(RemediateCase):
    def test_first_move_failing_second_still_moves(self):
        for name in ('temp-a.txt', 'temp-b.txt'):
            f = self.ws / name
            f.write_text('junk %s\n' % name, encoding='utf-8')
            old = time.time() - 100 * 86400
            os.utime(f, (old, old))
        rep = unused_data_rep(self.ws, 'temp-a.txt', 'temp-b.txt')
        steps = remediate.plan(rep, 'HLTH-042')
        order = []
        real_move = shutil.move

        def move_spy(src, dst):
            order.append(Path(src).name)
            if Path(src).name == 'temp-a.txt':
                raise OSError('simulated failure on the first item')
            return real_move(src, dst)

        with mock.patch('shutil.move', side_effect=move_spy):
            report = self.apply_quiet(steps, self.ws, assume_yes=True)

        self.assertEqual(order, ['temp-a.txt', 'temp-b.txt'])
        self.assertTrue(all(f['target'].endswith('temp-a.txt')
                            for f in report['failed']))
        self.assertEqual(len(report['failed']), 1)
        self.assertTrue((self.ws / 'temp-a.txt').is_file())   # left in place
        self.assertFalse((self.ws / 'temp-b.txt').exists())   # moved anyway
        moved = list((self.ws / remediate.TRASH_DIR_NAME).rglob('temp-b.txt'))
        self.assertEqual(len(moved), 1)

        data = json.loads((Path(report['trash_run']) / 'manifest.json')
                          .read_text(encoding='utf-8'))
        by_path = {e['original_path']: e for e in data['entries']}
        self.assertEqual(by_path['temp-a.txt']['status'], 'failed')
        self.assertEqual(by_path['temp-b.txt']['status'], 'moved')


class InterruptedRunNoted(RemediateCase):
    def test_interrupted_earlier_run_recorded_in_new_manifest(self):
        old_run = self.ws / remediate.TRASH_DIR_NAME / '20250101-000000-aaaabbbb'
        old_run.mkdir(parents=True)
        (old_run / 'manifest.json').write_text(json.dumps({
            'opid': 'aaaabbbb', 'root': str(self.ws), 'tool': 'remediate',
            'entries': [{'opid': 'aaaabbbb', 'action': 'trash',
                         'original_path': 'x', 'trash_path': 'x',
                         'status': 'moving'}]}), encoding='utf-8')

        junk = self.ws / 'temp-data.txt'
        junk.write_text('stale junk\n', encoding='utf-8')
        old = time.time() - 100 * 86400
        os.utime(junk, (old, old))
        rep = unused_data_rep(self.ws, 'temp-data.txt')
        steps = remediate.plan(rep, 'HLTH-042')
        report = self.apply_quiet(steps, self.ws, assume_yes=True)

        data = json.loads((Path(report['trash_run']) / 'manifest.json')
                          .read_text(encoding='utf-8'))
        self.assertEqual(data['interrupted_run'], 'aaaabbbb')
        # the interrupted run dir is still exactly as it was
        self.assertEqual(list(old_run.iterdir()), [old_run / 'manifest.json'])


class PlanBranches(RemediateCase):
    """Guard branches of plan() driven by hand-crafted findings."""

    def finding(self, **kw):
        f = {'fid': 'HLTH-042', 'gate': 'G9', 'category': 'health',
             'severity': 'low', 'status': 'warn', 'title': 'x',
             'description': 'd', 'evidence': [], 'recommendation': 'r',
             'autofix_available': False}
        f.update(kw)
        return f

    def test_confirmed_unused_without_autofix_refused(self):
        rep = {'root': str(self.ws),
               'findings_detailed': [self.finding(
                   title='Unused data (confirmed_unused): x',
                   evidence=[{'path': 'temp-data.txt'}])]}
        with self.assertRaises(remediate.UnsupportedError) as cm:
            remediate.plan(rep, 'HLTH-042')
        self.assertIn('autofix_available', str(cm.exception))

    def test_evidence_without_path_or_already_gone_targets_skipped(self):
        rep = {'root': str(self.ws),
               'findings_detailed': [self.finding(
                   title='Unused data (confirmed_unused): misc',
                   autofix_available=True,
                   evidence=[{}, {'path': ''}, {'path': 'never-existed.txt'}])]}
        self.assertEqual(remediate.plan(rep, 'HLTH-042'), [])

    def test_gitignore_repo_name_from_title_regex(self):
        # evidence carries no repo key -> the title regex names the repo
        (self.ws / 'solo').mkdir()
        rep = {'root': str(self.ws),
               'findings_detailed': [self.finding(
                   fid='GIT-007', title='No .gitignore in solo',
                   evidence=[{'note': 'no repo key here'}])]}
        steps = remediate.plan(rep, 'GIT-007')
        self.assertEqual(len(steps), 1)
        self.assertEqual(Path(steps[0]['target']),
                         (self.ws / 'solo' / '.gitignore').resolve())

    def test_gitignore_cannot_tell_repo_refused(self):
        # the prefix matches but no repo name follows, and the evidence
        # carries no repo key either
        rep = {'root': str(self.ws),
               'findings_detailed': [self.finding(
                   fid='GIT-007', title='No .gitignore in ',
                   evidence=[])]}
        with self.assertRaises(remediate.UnsupportedError) as cm:
            remediate.plan(rep, 'GIT-007')
        self.assertIn('cannot tell which repository', str(cm.exception))

    def test_empty_dir_evidence_degenerate_entries_skipped(self):
        (self.ws / 'full').mkdir()
        (self.ws / 'full' / 'x.txt').write_text('x', encoding='utf-8')
        (self.ws / 'really-empty').mkdir()
        rep = {'root': str(self.ws),
               'findings_detailed': [self.finding(
                   title='3 empty directories',
                   evidence=[{}, {'path': 'full'},
                             {'path': 'not-a-dir.txt'},
                             {'path': 'really-empty'}])]}
        steps = remediate.plan(rep, 'HLTH-042')
        self.assertEqual([Path(s['target']).name for s in steps],
                         ['really-empty'])

    def test_rel_under_falls_back_to_plain_string_outside_root(self):
        outside = self.base / 'elsewhere.txt'
        self.assertEqual(remediate._rel_under(outside, self.ws),
                         str(outside))


class ApplyEdgeCases(RemediateCase):
    def test_gitignore_missing_parent_fails_loudly(self):
        step = {'action': 'write_gitignore',
                'target': str(self.ws / 'no-such-repo' / '.gitignore'),
                'command': 'write', 'reversible': True, 'note': ''}
        report = self.apply_quiet([step], self.ws, assume_yes=True)
        self.assertEqual(report['executed'], [])
        self.assertEqual(len(report['failed']), 1)
        self.assertIn('parent directory missing', report['failed'][0]['error'])

    def test_trash_move_source_missing_fails(self):
        step = {'action': 'trash_move',
                'target': str(self.ws / 'vanished.txt'),
                'command': 'move', 'reversible': True, 'note': ''}
        report = self.apply_quiet([step], self.ws, assume_yes=True)
        self.assertEqual(len(report['failed']), 1)
        self.assertIn('source missing', report['failed'][0]['error'])

    def test_unknown_action_fails(self):
        step = {'action': 'shred', 'target': str(self.ws),
                'command': 'x', 'reversible': False, 'note': ''}
        report = self.apply_quiet([step], self.ws, assume_yes=True)
        self.assertEqual(len(report['failed']), 1)
        self.assertIn('unknown action', report['failed'][0]['error'])
        self.assertTrue(self.ws.is_dir())

    def test_eof_on_prompt_declines(self):
        (self.ws / 'emptydir').mkdir()
        step = {'action': 'rmdir', 'target': str(self.ws / 'emptydir'),
                'command': 'rmdir', 'reversible': True, 'note': ''}
        with mock.patch('builtins.input', side_effect=EOFError):
            report = self.apply_quiet([step], self.ws)
        self.assertTrue(report['declined'])
        self.assertTrue((self.ws / 'emptydir').is_dir())


class FingerprintDiffEdges(unittest.TestCase):
    def test_changed_and_degenerate_inputs(self):
        old = [{'fp': 'a', 'section': 'S', 'path': 'p'},
               {'fp': 'z', 'section': 'S2', 'path': 'q'},
               'not-a-dict', {'no-fp': 1}]
        new = [{'fp': 'b', 'section': 'S', 'path': 'p'},   # changed
               {'fp': 'a', 'section': 'S', 'path': 'p'},   # persisting dup
               {'fp': 'n', 'section': 'S3', 'path': 'r'},  # new
               None]
        diff = remediate.fingerprint_diff(old, new)
        self.assertEqual([f['fp'] for f in diff['changed']], ['b'])
        self.assertIn('b', [f['fp'] for f in diff['new']])
        self.assertEqual([f['fp'] for f in diff['resolved']], ['z'])
        self.assertIn('a', [f['fp'] for f in diff['persisting']])


class Cli(RemediateCase):
    def run_main(self, *args):
        out, err = StringIO(), StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = remediate.main([str(a) for a in args])
        return rc, out.getvalue(), err.getvalue()

    def junk_finding_scan(self):
        junk = self.ws / 'temp-cli.txt'
        junk.write_text('stale junk\n', encoding='utf-8')
        old = time.time() - 100 * 86400
        os.utime(junk, (old, old))
        self.scan()
        return self.fid_for(self.rep, 'Unused data (confirmed_unused)')

    def test_dry_run_prints_plan_and_changes_nothing(self):
        fid = self.junk_finding_scan()
        rc, out, err = self.run_main(self.scan_path, fid)
        self.assertEqual(rc, 0, err)
        self.assertIn('fix plan for %s' % fid, out)
        self.assertIn('trash_move', out)
        self.assertIn('dry run', out)
        self.assertTrue((self.ws / 'temp-cli.txt').is_file())

    def test_apply_confirmed_executes_and_reports_trash_run(self):
        fid = self.junk_finding_scan()
        with mock.patch('builtins.input', return_value='yes'):
            rc, out, err = self.run_main(self.scan_path, fid, '--apply')
        self.assertEqual(rc, 0, err)
        self.assertIn('executed 1', out)
        self.assertIn('trash run:', out)
        self.assertIn('safe_clean.py restore', out)
        self.assertFalse((self.ws / 'temp-cli.txt').exists())

    def test_apply_declined_exit_zero(self):
        fid = self.junk_finding_scan()
        with mock.patch('builtins.input', return_value='no'):
            rc, out, _ = self.run_main(self.scan_path, fid, '--apply')
        self.assertEqual(rc, 0)
        self.assertIn('declined, nothing executed', out)
        self.assertTrue((self.ws / 'temp-cli.txt').is_file())

    def test_apply_with_failing_step_returns_one(self):
        fid = self.junk_finding_scan()
        with mock.patch('builtins.input', return_value='yes'), \
                mock.patch('shutil.move', side_effect=OSError('boom')):
            rc, out, err = self.run_main(self.scan_path, fid, '--apply')
        self.assertEqual(rc, 1)
        self.assertIn('executed 0', out)
        self.assertIn('boom', err)
        self.assertTrue((self.ws / 'temp-cli.txt').is_file())

    def test_unsupported_finding_exit_three(self):
        self.scan()
        rc, _, err = self.run_main(self.scan_path, 'SEC-001')
        self.assertEqual(rc, 3)
        self.assertIn('SEC-001', err)

    def test_unreadable_scan_exit_one(self):
        rc, _, err = self.run_main(self.base / 'missing.json', 'HLTH-1')
        self.assertEqual(rc, 1)
        self.assertIn('cannot read scan', err)

    def test_scan_without_root_exit_one(self):
        p = self.base / 'rootless.json'
        p.write_text(json.dumps({'findings_detailed': []}), encoding='utf-8')
        rc, _, err = self.run_main(p, 'HLTH-1')
        self.assertEqual(rc, 1)
        self.assertIn('no root', err)

    def test_root_flag_overrides_scan_root(self):
        # scan records the real ws; --root points at a copy with the
        # same relative layout, so planning targets the copy
        other = self.base / 'other-ws'
        other.mkdir()
        (other / 'temp-cli.txt').write_text('stale junk\n', encoding='utf-8')
        fid = self.junk_finding_scan()
        rc, out, err = self.run_main(self.scan_path, fid,
                                     '--root', other)
        self.assertEqual(rc, 0, err)
        # CI hands tempfile short (8.3) paths while the tool prints
        # the resolved long form: accept either spelling
        short = str(other / 'temp-cli.txt')
        long = str((other / 'temp-cli.txt').resolve())
        self.assertTrue(short in out or long in out,
                        'neither %r nor %r in output' % (short, long))

    def test_reaudit_after_apply(self):
        self.scan()
        fid = self.fid_for(self.rep, 'empty directories')
        with mock.patch('builtins.input', return_value='yes'):
            rc, out, err = self.run_main(self.scan_path, fid,
                                         '--apply', '--reaudit')
        self.assertEqual(rc, 0, err)
        self.assertIn('reaudit:', out)
        self.assertTrue((self.base / 'scan.after.json').is_file())


if __name__ == '__main__':
    unittest.main()
