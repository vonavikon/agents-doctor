"""Hardening tests: crash recovery, concurrency lock,
harness check_id fixes, apply-time re-audit and TOCTOU on fix targets.

Crash recovery simulates a process that died between the write-ahead
manifest record and its completion fix: manifests are planted by hand
with in-flight entries ('moving'/'removing'/'creating') and the disk in
exactly the state such a crash leaves behind, then trashops.recover()
must roll every entry back to its pre-operation state -- or refuse with
a conflict report when rolling back could destroy data. The lock tests
drive trashops.TrashLock directly and through remediate.apply_plan; the
check_id tests use hand-crafted adapter findings (the adapters
themselves are covered by tests/test_harness_*.py).
"""
import hashlib
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

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / 'skills' / 'agents-doctor' / 'scripts'
sys.path.insert(0, str(SCRIPTS))

import audit_scan  # noqa: E402
import remediate   # noqa: E402
import trashops   # noqa: E402


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
    """The test_remediate.py fixture: one git repo with a dead link in
    AGENTS.md, an empty dir and no .gitignore."""
    ws, home = base / 'ws', base / 'home'
    repo = ws / 'repo'
    repo.mkdir(parents=True, exist_ok=True)
    home.mkdir(exist_ok=True)
    (repo / 'AGENTS.md').write_text(
        '# Project rules\n\nSee [docs](./missing.md) for the background.\n',
        encoding='utf-8')
    (repo / 'empty').mkdir()
    subprocess.run(['git', '-C', str(repo), 'init', '-q'],
                   check=True, capture_output=True)
    return ws, home, repo


class HardeningCase(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp())
        self.ws, self.home = self.base / 'ws', self.base / 'home'
        self.ws.mkdir(parents=True)
        self.home.mkdir()
        self.trash = self.ws / trashops.TRASH_DIR_NAME

    def tearDown(self):
        force_rmtree(self.base)

    # --- manifest planting -------------------------------------------------

    def plant_run(self, entries, name='20250101-000000-deadbeef',
                  opid='deadbeef'):
        """A run directory with a hand-written manifest, the state an
        interrupted process leaves behind."""
        run_dir = self.trash / name
        run_dir.mkdir(parents=True)
        manifest = {'opid': opid, 'manifest_schema_version': '2',
                    'root': str(self.ws), 'tool': 'remediate',
                    'started_at': '2025-01-01T00:00:00',
                    'interrupted_run': None, 'totals': {}, 'entries': entries}
        (run_dir / trashops.MANIFEST_NAME).write_text(
            json.dumps(manifest), encoding='utf-8')
        return run_dir

    def read_manifest(self, run_dir):
        return json.loads(
            (run_dir / trashops.MANIFEST_NAME).read_text(encoding='utf-8'))

    def quiet_recover(self, **kw):
        out, err = StringIO(), StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            report = trashops.recover(str(self.ws), **kw)
        return report, out.getvalue(), err.getvalue()

    def quiet_apply(self, steps, **kw):
        out, err = StringIO(), StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            report = remediate.apply_plan(steps, str(self.ws), **kw)
        return report


# --- crash recovery: find_incomplete ------------------------------------------------

class FindIncomplete(HardeningCase):
    def test_empty_without_trash_dir(self):
        self.assertEqual(trashops.find_incomplete(self.ws), [])

    def test_completed_run_reports_nothing(self):
        run = self.plant_run([
            {'opid': 'deadbeef', 'action': 'trash_move',
             'original_path': 'a.txt', 'trash_path': 'a.txt',
             'size': 1, 'type': 'file', 'status': 'moved',
             'restorable': True},
            {'opid': 'deadbeef', 'action': 'rmdir',
             'original_path': 'd', 'status': 'removed', 'restorable': True},
            {'opid': 'deadbeef', 'action': 'create_file',
             'original_path': 'b.txt', 'status': 'created',
             'restorable': True},
        ])
        self.assertTrue(run.is_dir())
        self.assertEqual(trashops.find_incomplete(self.ws), [])

    def test_lists_every_inflight_type_with_index_and_run_dir(self):
        run = self.plant_run([
            {'opid': 'deadbeef', 'action': 'trash_move',
             'original_path': 'moved.txt', 'trash_path': 'moved.txt',
             'size': 3, 'type': 'file', 'status': 'moving',
             'restorable': True},
            {'opid': 'deadbeef', 'action': 'rmdir',
             'original_path': 'd', 'type': 'dir', 'status': 'removing',
             'restorable': True},
            {'opid': 'deadbeef', 'action': 'create_file',
             'original_path': 'new.txt', 'type': 'file',
             'sha256': '0' * 64, 'status': 'creating', 'restorable': True},
            {'opid': 'deadbeef', 'action': 'create_directory',
             'original_path': 'newdir', 'type': 'dir', 'status': 'creating',
             'restorable': True},
            {'opid': 'deadbeef', 'action': 'create_file',
             'original_path': 'done.txt', 'type': 'file',
             'sha256': '0' * 64, 'status': 'created', 'restorable': True},
        ])
        found = trashops.find_incomplete(self.ws)
        self.assertEqual([e['index'] for e in found], [0, 1, 2, 3])
        self.assertEqual({e['action'] for e in found},
                         {'trash_move', 'rmdir', 'create_file',
                          'create_directory'})
        self.assertTrue(all(e['run_dir'] == str(run) for e in found))
        self.assertTrue(all(Path(e['manifest_path']).is_file()
                            for e in found))


# --- crash recovery: recover ---------------------------------------------------------

class RecoverTrashMove(HardeningCase):
    def in_flight_move(self, content=b'crashed mid-move\n'):
        """A trash_move whose shutil.move finished but whose 'moved'
        fix never landed: the original is gone, the copy is in the run
        directory, the entry still says 'moving'."""
        run = self.plant_run([{
            'opid': 'deadbeef', 'action': 'trash_move',
            'original_path': 'temp-junk.txt', 'trash_path': 'temp-junk.txt',
            'size': len(content), 'type': 'file', 'status': 'moving',
            'restorable': True}])
        (run / 'temp-junk.txt').write_bytes(content)
        return run, content

    def test_move_rolled_back_to_original(self):
        run, content = self.in_flight_move()
        report, _out, _err = self.quiet_recover(auto=True)
        self.assertEqual(report['conflicts'], [])
        self.assertEqual(report['failed'], [])
        self.assertEqual(len(report['recovered']), 1)
        back = self.ws / 'temp-junk.txt'
        self.assertTrue(back.is_file())
        self.assertEqual(back.read_bytes(), content)      # nothing lost
        self.assertFalse((run / 'temp-junk.txt').exists())
        entry = self.read_manifest(run)['entries'][0]
        self.assertEqual(entry['status'], 'recovered')

    def test_conflict_when_original_reoccupied_keeps_both_and_reports(self):
        run, content = self.in_flight_move()
        newcomer = self.ws / 'temp-junk.txt'
        newcomer.write_text('written after the crash\n', encoding='utf-8')
        report, _out, err = self.quiet_recover(auto=True)
        self.assertEqual(report['recovered'], [])
        self.assertEqual(len(report['conflicts']), 1)
        self.assertEqual(report['conflicts'][0]['action'], 'trash_move')
        # nothing lost: the newcomer stays, the crashed copy stays in trash
        self.assertEqual(newcomer.read_text(encoding='utf-8'),
                         'written after the crash\n')
        self.assertEqual((run / 'temp-junk.txt').read_bytes(), content)
        entry = self.read_manifest(run)['entries'][0]
        self.assertEqual(entry['status'], 'recovery_conflict')
        self.assertIn('warning', err)

    def test_move_never_started_is_a_noop_recovery(self):
        run = self.plant_run([{
            'opid': 'deadbeef', 'action': 'trash_move',
            'original_path': 'temp-junk.txt', 'trash_path': 'temp-junk.txt',
            'size': 5, 'type': 'file', 'status': 'moving',
            'restorable': True}])
        src = self.ws / 'temp-junk.txt'          # still in place
        src.write_text('never moved\n', encoding='utf-8')
        report, _out, _err = self.quiet_recover(auto=True)
        self.assertEqual(len(report['recovered']), 1)
        self.assertIn('never started', report['recovered'][0]['detail'])
        self.assertEqual(src.read_text(encoding='utf-8'), 'never moved\n')
        self.assertFalse((run / 'temp-junk.txt').exists())


class RecoverCreateFile(HardeningCase):
    def creating_entry(self, on_disk):
        run = self.plant_run([{
            'opid': 'deadbeef', 'action': 'create_file',
            'original_path': 'repo/.gitignore', 'trash_path': None,
            'size': len(on_disk), 'type': 'file',
            'sha256': hashlib.sha256(on_disk).hexdigest(),
            'status': 'creating', 'restorable': True}])
        target = self.ws / 'repo' / '.gitignore'
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(on_disk)
        return run, target

    def test_created_file_deleted_after_recheck(self):
        planned = b'# generated by remediate\nnode_modules/\n'
        run, target = self.creating_entry(planned)
        report, _out, _err = self.quiet_recover(auto=True)
        self.assertEqual(report['conflicts'], [])
        self.assertFalse(target.exists())
        self.assertEqual(self.read_manifest(run)['entries'][0]['status'],
                         'recovered')

    def test_file_modified_since_the_crash_is_left_in_place(self):
        run, target = self.creating_entry(b'planned content\n')
        target.write_text('edited by someone after the crash\n',
                          encoding='utf-8')
        report, _out, err = self.quiet_recover(auto=True)
        self.assertEqual(report['recovered'], [])
        self.assertEqual(len(report['conflicts']), 1)
        self.assertEqual(
            target.read_text(encoding='utf-8'),
            'edited by someone after the crash\n')
        self.assertEqual(self.read_manifest(run)['entries'][0]['status'],
                         'recovery_conflict')
        self.assertIn('warning', err)


class RecoverRmdir(HardeningCase):
    def test_rmdir_happened_dir_recreated_empty(self):
        run = self.plant_run([{
            'opid': 'deadbeef', 'action': 'rmdir',
            'original_path': 'stale-dir', 'type': 'dir',
            'status': 'removing', 'restorable': True}])
        # the crash happened after os.rmdir: the directory is gone
        report, _out, _err = self.quiet_recover(auto=True)
        self.assertEqual(report['conflicts'], [])
        self.assertTrue((self.ws / 'stale-dir').is_dir())
        self.assertEqual(list((self.ws / 'stale-dir').iterdir()), [])
        self.assertEqual(self.read_manifest(run)['entries'][0]['status'],
                         'recovered')

    def test_rmdir_never_started_noop(self):
        run = self.plant_run([{
            'opid': 'deadbeef', 'action': 'rmdir',
            'original_path': 'stale-dir', 'type': 'dir',
            'status': 'removing', 'restorable': True}])
        (self.ws / 'stale-dir').mkdir()          # rmdir never ran
        (self.ws / 'stale-dir' / 'kept.txt').write_text('x', encoding='utf-8')
        report, _out, _err = self.quiet_recover(auto=True)
        self.assertEqual(len(report['recovered']), 1)
        self.assertIn('never started', report['recovered'][0]['detail'])
        self.assertTrue((self.ws / 'stale-dir' / 'kept.txt').is_file())


class RecoverCreateDirectory(HardeningCase):
    def creating_dir_entry(self):
        return self.plant_run([{
            'opid': 'deadbeef', 'action': 'create_directory',
            'original_path': 'fresh-dir', 'type': 'dir',
            'status': 'creating', 'restorable': True}])

    def test_created_dir_removed_while_empty(self):
        run = self.plant_run([{
            'opid': 'deadbeef', 'action': 'create_directory',
            'original_path': 'fresh-dir', 'type': 'dir',
            'status': 'creating', 'restorable': True}])
        (self.ws / 'fresh-dir').mkdir()
        report, _out, _err = self.quiet_recover(auto=True)
        self.assertEqual(report['conflicts'], [])
        self.assertFalse((self.ws / 'fresh-dir').exists())
        self.assertEqual(self.read_manifest(run)['entries'][0]['status'],
                         'recovered')

    def test_dir_gained_content_left_in_place(self):
        run = self.plant_run([{
            'opid': 'deadbeef', 'action': 'create_directory',
            'original_path': 'fresh-dir', 'type': 'dir',
            'status': 'creating', 'restorable': True}])
        (self.ws / 'fresh-dir').mkdir()
        (self.ws / 'fresh-dir' / 'tenant.txt').write_text('x', encoding='utf-8')
        report, _out, _err = self.quiet_recover(auto=True)
        self.assertEqual(len(report['conflicts']), 1)
        self.assertTrue((self.ws / 'fresh-dir' / 'tenant.txt').is_file())
        self.assertEqual(self.read_manifest(run)['entries'][0]['status'],
                         'recovery_conflict')


class RecoverSemantics(HardeningCase):
    def crashed_move(self):
        run = self.plant_run([{
            'opid': 'deadbeef', 'action': 'trash_move',
            'original_path': 'temp-junk.txt', 'trash_path': 'temp-junk.txt',
            'size': 6, 'type': 'file', 'status': 'moving',
            'restorable': True}])
        (run / 'temp-junk.txt').write_bytes(b'crash!')
        return run

    def test_second_recover_after_a_complete_one_is_a_noop(self):
        run = self.crashed_move()
        first, _out, _err = self.quiet_recover(auto=True)
        self.assertEqual(len(first['recovered']), 1)
        self.assertEqual(trashops.find_incomplete(self.ws), [])
        second = trashops.recover(self.ws, auto=True)
        self.assertEqual(
            second, {'run_dir': None, 'declined': False, 'incomplete': 0,
                     'recovered': [], 'conflicts': [], 'failed': []})
        # the recovered file is still exactly where the first pass put it
        self.assertEqual((self.ws / 'temp-junk.txt').read_bytes(), b'crash!')

    def test_interactive_decline_changes_nothing(self):
        run = self.crashed_move()
        report, _out, _err = self.quiet_recover(
            auto=False, confirm=lambda prompt: 'no')
        self.assertTrue(report['declined'])
        self.assertEqual(report['recovered'], [])
        self.assertFalse((self.ws / 'temp-junk.txt').exists())
        self.assertTrue((run / 'temp-junk.txt').is_file())
        self.assertEqual(self.read_manifest(run)['entries'][0]['status'],
                         'moving')            # still in flight: retriable

    def test_interactive_yes_executes(self):
        self.crashed_move()
        report, _out, _err = self.quiet_recover(
            auto=False, confirm=lambda prompt: self.assertEqual(
                'Type YES to roll back 1 operation(s): ', prompt) or 'YES')
        self.assertFalse(report['declined'])
        self.assertEqual(len(report['recovered']), 1)


# --- concurrency lock -----------------------------------------------------------------

class TrashLockBehaviour(HardeningCase):
    def lock_file(self):
        return self.trash / '.lock'

    def test_second_acquire_refuses_then_release_allows(self):
        first = trashops.TrashLock(self.ws).acquire()
        self.assertTrue(first.held)
        self.assertTrue(self.lock_file().is_file())
        with self.assertRaises(trashops.LockBusy):
            trashops.TrashLock(self.ws).acquire()
        first.release()
        self.assertFalse(self.lock_file().exists())
        second = trashops.TrashLock(self.ws).acquire()   # free again
        second.release()

    def test_stale_lock_stolen_by_age_with_journal_line(self):
        stale = trashops.TrashLock(self.ws).acquire()
        stale.release()
        # a lock written by a long-dead process: bogus pid, mtime in the
        # past (on POSIX the pid probe says dead; on Windows age decides)
        self.lock_file().write_text('999999999\n2020-01-01T00:00:00\n',
                                    encoding='utf-8')
        old = time.time() - trashops.LOCK_STALE_SECONDS - 600
        os.utime(self.lock_file(), (old, old))
        err = StringIO()
        with redirect_stderr(err):
            thief = trashops.TrashLock(self.ws).acquire()
        self.assertTrue(thief.stolen)
        self.assertTrue(thief.held)
        self.assertIn('stealing stale trash lock', err.getvalue())
        thief.release()

    def test_fresh_lock_is_never_stolen(self):
        fresh = trashops.TrashLock(self.ws).acquire()
        fresh.release()
        self.lock_file().write_text('999999999\n2020-01-01T00:00:00\n',
                                    encoding='utf-8')  # dead pid...
        # ...but the mtime is now: age decides, and the age is young
        with self.assertRaises(trashops.LockBusy):
            trashops.TrashLock(self.ws).acquire()


class ApplyPlanLocking(HardeningCase):
    def lock_file(self):
        return self.trash / '.lock'

    def test_apply_refused_while_lock_held_and_untouched(self):
        victim = self.ws / 'stale-dir'
        victim.mkdir()
        step = {'action': 'rmdir', 'target': str(victim),
                'command': 'rmdir', 'reversible': True, 'note': ''}
        holder = trashops.TrashLock(self.ws).acquire()
        try:
            with self.assertRaises(remediate.RemediateBusy):
                self.quiet_apply([step], assume_yes=True)
            self.assertTrue(victim.is_dir())       # nothing removed
            runs = [p for p in self.trash.iterdir() if p.is_dir()]
            self.assertEqual(runs, [])             # no run created
        finally:
            holder.release()
        # lock free again: the same plan applies
        report = self.quiet_apply([step], assume_yes=True)
        self.assertEqual(len(report['executed']), 1)
        self.assertFalse(victim.exists())

    def test_lock_released_in_finally_despite_failing_step(self):
        doomed = self.ws / 'stale-dir'
        doomed.mkdir()
        missing = self.ws / 'vanished.txt'
        steps = [
            {'action': 'rmdir', 'target': str(doomed), 'command': 'rmdir',
             'reversible': True, 'note': ''},               # succeeds, locks
            {'action': 'trash_move', 'target': str(missing), 'command': 'move',
             'reversible': True, 'note': ''},               # fails loudly
        ]
        report = self.quiet_apply(steps, assume_yes=True)
        self.assertEqual(len(report['executed']), 1)
        self.assertEqual(len(report['failed']), 1)
        self.assertFalse(doomed.exists())
        self.assertFalse(self.lock_file().exists())         # released

    def test_busy_is_a_value_error_for_legacy_catchers(self):
        # agents_doctor.py's fix command catches ValueError from
        # apply_plan; RemediateBusy must ride that path, not traceback
        self.assertTrue(issubclass(remediate.RemediateBusy, ValueError))
        self.assertIs(remediate.RemediateBusy, trashops.LockBusy)


# --- harness check_id fixes ------------------------------------------------------------

def check_id_rep(ws, check_id, target, fid='GOV-001'):
    """A hand-crafted adapter finding the way gates.evaluate appends
    it to findings_detailed (check_id riding along)."""
    return {'root': str(ws), 'findings_detailed': [{
        'fid': fid, 'gate': 'G8', 'category': 'compatibility',
        'severity': 'medium', 'status': 'warn', 'title': 'adapter finding',
        'description': 'd', 'evidence': [{'file': str(target)}],
        'recommendation': 'r', 'confidence': 0.9,
        'harness': 'test', 'check_id': check_id}]}


class CheckIdAutofix(HardeningCase):
    def test_claude_local_deprecated_planned_as_trash_move(self):
        local = self.ws / 'CLAUDE.local.md'
        local.write_text('local overrides\n', encoding='utf-8')
        steps = remediate.plan(check_id_rep(
            self.ws, 'CLAUDE_LOCAL_DEPRECATED', local), 'GOV-001')
        self.assertEqual(len(steps), 1)
        self.assertEqual(steps[0]['action'], 'trash_move')
        self.assertEqual(Path(steps[0]['target']), local)
        self.assertTrue(steps[0]['autofix_available'])
        self.assertEqual(steps[0]['check_id'], 'CLAUDE_LOCAL_DEPRECATED')
        self.assertIn('snapshot', steps[0])

    def test_claude_local_deprecated_apply_moves_and_journals(self):
        local = self.ws / 'CLAUDE.local.md'
        local.write_text('local overrides\n', encoding='utf-8')
        steps = remediate.plan(check_id_rep(
            self.ws, 'CLAUDE_LOCAL_DEPRECATED', local), 'GOV-001')
        report = self.quiet_apply(steps, assume_yes=True)
        self.assertEqual(len(report['executed']), 1)
        self.assertFalse(local.exists())
        run = Path(report['trash_run'])
        entry = json.loads(
            (run / trashops.MANIFEST_NAME).read_text(encoding='utf-8')
        )['entries'][0]
        self.assertEqual(entry['status'], 'moved')       # fixed, not stuck
        self.assertTrue(entry['restorable'])             # reversible
        self.assertEqual((run / entry['trash_path']).read_text(
            encoding='utf-8'), 'local overrides\n')

    def test_already_gone_target_plans_nothing(self):
        steps = remediate.plan(check_id_rep(
            self.ws, 'CLAUDE_LOCAL_DEPRECATED',
            self.ws / 'CLAUDE.local.md'), 'GOV-001')
        self.assertEqual(steps, [])


class CheckIdManual(HardeningCase):
    def test_cursor_legacy_gets_manual_plan_and_executes_nothing(self):
        legacy = self.ws / '.cursorrules'
        legacy.write_text('always answer briefly\n', encoding='utf-8')
        rules = self.ws / '.cursor' / 'rules'
        rules.mkdir(parents=True)
        steps = remediate.plan(check_id_rep(
            self.ws, 'CURSOR_LEGACY_AND_RULES', legacy), 'GOV-001')
        self.assertGreaterEqual(len(steps), 2)
        self.assertTrue(all(s['action'] == 'manual' for s in steps))
        self.assertTrue(all(s['autofix_available'] is False for s in steps))
        self.assertTrue(any('.cursor/rules/legacy.md' in s['command']
                            for s in steps))
        report = self.quiet_apply(steps, assume_yes=True)
        self.assertEqual(report['executed'], [])
        self.assertEqual(report['failed'], [])
        self.assertEqual([s.get('reason') for s in report['skipped']],
                         ['manual'] * len(steps))
        self.assertEqual(legacy.read_text(encoding='utf-8'),
                         'always answer briefly\n')   # untouched
        self.assertTrue(rules.is_dir())

    def test_windsurf_legacy_gets_manual_plan(self):
        legacy = self.ws / '.windsurfrules'
        legacy.write_text('trigger on save\n', encoding='utf-8')
        (self.ws / '.windsurf' / 'rules').mkdir(parents=True)
        steps = remediate.plan(check_id_rep(
            self.ws, 'WINDSURF_LEGACY_AND_RULES', legacy), 'GOV-001')
        self.assertGreaterEqual(len(steps), 1)
        self.assertTrue(all(s['action'] == 'manual' for s in steps))
        self.assertTrue(all(s['autofix_available'] is False for s in steps))
        self.assertTrue(any('.windsurf/rules/legacy.md' in s['command']
                            for s in steps))
        report = self.quiet_apply(steps, assume_yes=True)
        self.assertEqual(report['executed'], [])
        self.assertTrue(legacy.is_file())

    def test_unregistered_check_id_refused_by_name(self):
        steps = None
        with self.assertRaises(remediate.UnsupportedError) as cm:
            steps = remediate.plan(check_id_rep(
                self.ws, 'ZCODE_MEMORY_OVER_LIMIT',
                self.ws / 'MEMORY.md'), 'GOV-001')
        self.assertIn('ZCODE_MEMORY_OVER_LIMIT', str(cm.exception))
        self.assertIsNone(steps)

    def test_check_id_finding_without_file_refused(self):
        rep = {'root': str(self.ws), 'findings_detailed': [{
            'fid': 'GOV-009', 'gate': 'G8', 'category': 'compatibility',
            'severity': 'medium', 'status': 'warn', 'title': 't',
            'description': 'd', 'evidence': [{}],
            'recommendation': 'r', 'check_id': 'CLAUDE_LOCAL_DEPRECATED'}]}
        with self.assertRaises(remediate.UnsupportedError) as cm:
            remediate.plan(rep, 'GOV-009')
        self.assertIn('no file', str(cm.exception))


# --- re-audit after fix ----------------------------------------------------------------

class ApplyPlanReaudit(HardeningCase):
    def setUp(self):
        super().setUp()
        self.ws, self.home, self.repo = build_workspace(self.base)

    def test_reaudit_counts_before_and_after(self):
        rep = audit_scan.scan(self.ws, self.home)
        fid = next(f['fid'] for f in rep['findings_detailed']
                   if 'empty directories' in f['title'])
        steps = remediate.plan(rep, fid)
        report = self.quiet_apply(
            steps, assume_yes=True, reaudit=True, home=self.home,
            before_findings=rep['findings'])
        self.assertIn('reaudit', report)
        self.assertEqual(report['reaudit']['before'],
                         len(rep['findings']))
        self.assertLess(report['reaudit']['after'],
                        report['reaudit']['before'])
        self.assertFalse((self.repo / 'empty').exists())

    def test_no_reaudit_key_by_default(self):
        (self.ws / 'lonely').mkdir()
        step = {'action': 'rmdir', 'target': str(self.ws / 'lonely'),
                'command': 'rmdir', 'reversible': True, 'note': ''}
        report = self.quiet_apply([step], assume_yes=True)
        self.assertNotIn('reaudit', report)


# --- TOCTOU on check_id fix targets ----------------------------------------------------

class CheckIdToctou(HardeningCase):
    def test_file_rewritten_between_plan_and_apply_skipped_changed(self):
        local = self.ws / 'CLAUDE.local.md'
        local.write_text('short\n', encoding='utf-8')
        steps = remediate.plan(check_id_rep(
            self.ws, 'CLAUDE_LOCAL_DEPRECATED', local), 'GOV-001')
        local.write_text('rewritten after planning, much longer\n',
                         encoding='utf-8')   # size+mtime drift
        report = self.quiet_apply(steps, assume_yes=True)
        self.assertEqual(report['executed'], [])
        self.assertEqual(report['failed'], [])
        self.assertEqual(report['skipped'][0]['reason'], 'changed')
        self.assertEqual(
            local.read_text(encoding='utf-8'),
            'rewritten after planning, much longer\n')
        self.assertFalse(self.trash.exists())   # no run, no lock residue

    def test_file_swapped_for_symlink_refused_without_damage(self):
        if not hasattr(os, 'symlink'):
            self.skipTest('os.symlink unavailable')
        local = self.ws / 'CLAUDE.local.md'
        local.write_text('original\n', encoding='utf-8')
        outside = self.base / 'vault.txt'
        outside.write_text('do not touch\n', encoding='utf-8')
        steps = remediate.plan(check_id_rep(
            self.ws, 'CLAUDE_LOCAL_DEPRECATED', local), 'GOV-001')
        local.unlink()
        try:
            os.symlink(str(outside), str(local))
        except (OSError, NotImplementedError):
            self.skipTest('symlink creation unavailable on this system')
        report = self.quiet_apply(steps, assume_yes=True)
        self.assertEqual(report['executed'], [])
        self.assertEqual(len(report['failed']), 1)
        self.assertIn('SecurityRefusal', report['failed'][0]['error'])
        # neither the link nor its target was harmed
        self.assertTrue(os.path.islink(str(local)))
        self.assertEqual(outside.read_text(encoding='utf-8'),
                         'do not touch\n')


if __name__ == '__main__':
    unittest.main()
