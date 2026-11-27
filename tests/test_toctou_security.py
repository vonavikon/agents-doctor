"""TOCTOU security suite: attacks between plan and execute.

The remediation flow is plan -> user confirms -> execute. These tests
plant the classic time-of-check/time-of-use attacks in that window:

a) a parent directory swapped for a symlink pointing outside the root
b) the planned regular file replaced by a symlink to a system-looking
   file outside the root
c) the file's content doubled after planning (snapshot mismatch)
d) the trash destination (the trash folder itself) replaced by a symlink
e) traversal paths ('..') in crafted plan items
f) a .gitignore write aimed through a symlinked directory
g) a tampered restore manifest (trash_path redirected; recorded size
   changed)
h) the file modified while the confirmation prompt is still on screen

Every test asserts the operation was refused with a clear reason and
that no file outside the workspace was touched (sentinel victims keep
their exact bytes). Symlink-based tests skip when the platform cannot
create symlinks (plain Windows without developer mode); the rest run
everywhere.
"""
import json
import os
import shutil
import stat
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

import remediate  # noqa: E402
import safe_clean  # noqa: E402
import trashops  # noqa: E402

TRASH = trashops.TRASH_DIR_NAME
SENTINEL = b'outside-victim-bytes\n'


def force_rmtree(path):
    """rmtree that clears the read-only flag git puts on some files."""
    def _onexc(func, p, _exc):
        os.chmod(p, stat.S_IWRITE)
        func(p)
    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=_onexc)
    else:
        shutil.rmtree(path, onerror=lambda func, p, _ei: _onexc(func, p, _ei))


def _can_symlink(base):
    """True when this process may create symlinks (probed once)."""
    probe = Path(base) / '_symlink-probe'
    try:
        os.symlink('nowhere', str(probe))
        probe.unlink()
        return True
    except (AttributeError, OSError, NotImplementedError):
        return False


class ToctouCase(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: force_rmtree(self.base))
        self.ws = self.base / 'ws'
        self.outside = self.base / 'outside'
        self.ws.mkdir()
        self.outside.mkdir()
        self.symlinks = _can_symlink(self.base)

    # --- fixture helpers -------------------------------------------------

    def require_symlinks(self):
        if not self.symlinks:
            self.skipTest('symlink creation unavailable on this system')

    def mkjunk(self, rel, data=b'stale junk\n', age_days=120):
        """An aged junk-looking file inside the workspace."""
        p = self.ws / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        t = time.time() - age_days * 86400
        os.utime(str(p), (t, t))
        return p

    def victim(self, name):
        """A sentinel file outside the workspace that must survive."""
        p = self.outside / name
        p.write_bytes(SENTINEL)
        return p

    def outside_snapshot(self):
        return {p.name: p.read_bytes() for p in self.outside.iterdir()}

    def assert_outside_untouched(self, snap):
        self.assertEqual(self.outside_snapshot(), snap)

    def plan_junk(self, *rels):
        """remediate.plan() over a hand-crafted confirmed-unused finding."""
        rep = {'root': str(self.ws), 'findings_detailed': [{
            'fid': 'HLTH-042', 'gate': 'G9', 'category': 'health',
            'severity': 'low', 'status': 'warn',
            'title': 'Unused data (confirmed_unused): %s' % ', '.join(rels),
            'description': 'crafted for the TOCTOU suite', 'confidence': 0.9,
            'evidence': [{'path': r} for r in rels],
            'recommendation': 'x', 'autofix_available': True}]}
        return remediate.plan(rep, 'HLTH-042')

    def apply(self, steps, **kw):
        out, err = StringIO(), StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            return remediate.apply_plan(steps, str(self.ws), **kw)

    def apply_with_confirm_attack(self, steps, attack):
        """apply_plan whose confirmation callback runs the attack and
        then answers 'yes': the swap lands strictly between the plan
        and the execute, inside the confirmation window and after
        apply_plan's own pre-loop containment check."""
        def confirm(prompt):
            attack()
            return 'yes'
        out, err = StringIO(), StringIO()
        with redirect_stdout(out), redirect_stderr(err), \
                mock.patch('builtins.input', side_effect=confirm):
            return remediate.apply_plan(steps, str(self.ws))

    def clean_plan(self, *rels):
        """A hand-built safe_clean plan with real TOCTOU snapshots."""
        items = [{'path': rel,
                  'size': (self.ws / rel).stat().st_size
                  if (self.ws / rel).is_file() else 0,
                  'action': 'trash', 'category': safe_clean.CAT_CONFIRMED,
                  'reason': 'crafted', 'cautious': False,
                  'stat': trashops.snapshot(self.ws / rel)}
                 for rel in rels]
        return {'root': str(self.ws), 'max_bytes': safe_clean.DEFAULT_MAX_BYTES,
                'items': items, 'categories': {}, 'skipped': [], 'totals': {}}

    def no_trash_run(self):
        trash = self.ws / TRASH
        return not trash.exists() or not list(trash.rglob('manifest.json'))


# --- a) parent directory swapped for a symlink --------------------------------

class ParentSymlinkSwap(ToctouCase):
    def test_remediate_parent_swap_refused(self):
        self.require_symlinks()
        self.mkjunk(Path('data') / 'temp-old.txt')
        victim = self.victim('temp-old.txt')     # same name, outside root
        snap = self.outside_snapshot()
        steps = self.plan_junk('data/temp-old.txt')
        self.assertEqual(steps[0]['action'], 'trash_move')
        real_data = self.ws / 'data'

        def attack():
            shutil.rmtree(str(real_data))
            os.symlink(str(self.outside), str(real_data),
                       target_is_directory=True)

        report = self.apply_with_confirm_attack(steps, attack)

        self.assertEqual(report['executed'], [])
        self.assertEqual(len(report['failed']), 1)
        self.assertIn('symlink', report['failed'][0]['error'])
        self.assertTrue(self.no_trash_run())      # no run was created
        self.assertEqual(victim.read_bytes(), SENTINEL)
        self.assert_outside_untouched(snap)
        self.assertTrue(real_data.is_symlink())   # the planted link remains

    def test_safe_clean_parent_swap_refused(self):
        self.require_symlinks()
        self.mkjunk(Path('data') / 'temp-old.txt')
        victim = self.victim('temp-old.txt')
        snap = self.outside_snapshot()
        plan = self.clean_plan('data/temp-old.txt')

        def confirm(prompt):
            shutil.rmtree(str(self.ws / 'data'))
            os.symlink(str(self.outside), str(self.ws / 'data'),
                       target_is_directory=True)
            return 'YES'

        summary = safe_clean.execute(plan, self.ws, confirm=confirm)

        self.assertEqual(summary['moved'], [])
        refused = summary['skipped_safety'] + summary['failed']
        self.assertEqual(len(refused), 1)
        self.assertIn(refused[0].get('reason', ''), ('escape', 'symlink'))
        self.assertEqual(victim.read_bytes(), SENTINEL)
        self.assert_outside_untouched(snap)


# --- b) target file swapped for a symlink after confirm -----------------------

class TargetSymlinkSwap(ToctouCase):
    def test_file_replaced_by_symlink_refused(self):
        self.require_symlinks()
        junk = self.mkjunk('temp-old.txt', b'small stale junk\n')
        victim = self.victim('system-config')
        snap = self.outside_snapshot()
        steps = self.plan_junk('temp-old.txt')

        def attack():
            junk.unlink()
            os.symlink(str(victim), str(junk))

        report = self.apply_with_confirm_attack(steps, attack)

        self.assertEqual(report['executed'], [])
        self.assertEqual(len(report['failed']), 1)
        self.assertIn('symlink', report['failed'][0]['error'])
        self.assertEqual(victim.read_bytes(), SENTINEL)
        self.assert_outside_untouched(snap)
        self.assertTrue(junk.is_symlink())   # the planted link itself stays
        self.assertTrue(self.no_trash_run())


# --- c) file modified between plan and execute --------------------------------

class SnapshotDrift(ToctouCase):
    def test_file_doubled_after_planning_refused(self):
        junk = self.mkjunk('temp-old.txt', b'x' * 100)
        steps = self.plan_junk('temp-old.txt')
        junk.write_bytes(b'x' * 200)          # doubled after planning

        report = self.apply(steps, assume_yes=True)

        self.assertEqual(report['executed'], [])
        self.assertEqual(report['skipped'][0].get('reason'), 'changed')
        self.assertEqual(junk.read_bytes(), b'x' * 200)
        self.assertTrue(self.no_trash_run())
        self.assertEqual(self.outside_snapshot(), {})


# --- d) trash destination replaced with a symlink -----------------------------

class TrashDestinationSwap(ToctouCase):
    def test_trash_root_symlink_refuses_the_whole_run(self):
        self.require_symlinks()
        junk = self.mkjunk('temp-old.txt')
        victim = self.victim('do-not-touch.bin')
        snap = self.outside_snapshot()
        plan = self.clean_plan('temp-old.txt')
        # the attack: the trash folder itself becomes a symlink to the
        # outside before the run starts
        os.symlink(str(self.outside), str(self.ws / TRASH),
                   target_is_directory=True)

        summary = safe_clean.execute(plan, self.ws, confirm=lambda p: 'YES')

        self.assertEqual(summary['moved'], [])
        self.assertTrue(summary['failed'])
        self.assertIn('symlink', summary['failed'][0]['error'])
        self.assertIsNone(summary['trash_dir'])
        self.assertTrue(junk.is_file())          # source left in place
        # crucially: no run directory or manifest materialized outside
        self.assert_outside_untouched(snap)
        self.assertTrue((self.ws / TRASH).is_symlink())


# --- e) traversal paths in crafted plan items ----------------------------------

class EscapeAttempt(ToctouCase):
    def test_dotdot_target_refused_by_both_tools(self):
        victim = self.base / 'victim.txt'       # one level above ws
        victim.write_bytes(SENTINEL)

        step = {'action': 'trash_move',
                'target': str(self.ws / os.pardir / 'victim.txt'),
                'command': 'move', 'reversible': True, 'note': ''}
        # pre-flight escapes are recorded as refused steps (same shape
        # as an in-flight refusal), not raised
        with redirect_stdout(StringIO()):
            report = remediate.apply_plan([step], str(self.ws),
                                          assume_yes=True)
        self.assertEqual(report['executed'], [])
        self.assertEqual(len(report['failed']), 1)
        self.assertIn('SecurityRefusal', report['failed'][0]['error'])

        plan = {'root': str(self.ws), 'max_bytes': safe_clean.DEFAULT_MAX_BYTES,
                'items': [{'path': os.path.join(os.pardir, 'victim.txt'),
                           'size': 5, 'action': 'trash',
                           'category': safe_clean.CAT_CONFIRMED,
                           'reason': 'crafted', 'cautious': False}],
                'categories': {}, 'skipped': [], 'totals': {}}
        summary = safe_clean.execute(plan, self.ws, confirm=lambda p: 'YES')

        self.assertEqual(summary['moved'], [])
        self.assertEqual(summary['skipped_safety'][0]['reason'], 'escape')
        self.assertEqual(victim.read_bytes(), SENTINEL)


# --- f) gitignore write through a symlinked directory --------------------------

class GitignoreThroughSymlink(ToctouCase):
    def test_write_into_symlinked_dir_refused(self):
        self.require_symlinks()
        repo = self.ws / 'repo'
        repo.mkdir()
        victim = self.victim('anchor.bin')
        snap = self.outside_snapshot()
        step = {'action': 'write_gitignore',
                'target': str(repo / '.gitignore'),
                'command': 'write', 'reversible': True, 'note': ''}

        def attack():
            repo.rmdir()
            os.symlink(str(self.outside), str(repo),
                       target_is_directory=True)

        report = self.apply_with_confirm_attack([step], attack)

        self.assertEqual(report['executed'], [])
        self.assertEqual(len(report['failed']), 1)
        self.assertIn('symlink', report['failed'][0]['error'])
        # nothing was created through the link
        self.assertFalse((self.outside / '.gitignore').exists())
        self.assert_outside_untouched(snap)


# --- g) tampered restore manifest ----------------------------------------------

class ManifestTamperRestore(ToctouCase):
    def _run_then_tamper(self, mutate):
        junk = self.mkjunk('temp-old.txt')
        plan = self.clean_plan('temp-old.txt')
        summary = safe_clean.execute(plan, self.ws, confirm=lambda p: 'YES')
        self.assertEqual(len(summary['moved']), 1)
        run_dir = Path(summary['trash_dir'])
        data = json.loads((run_dir / 'manifest.json')
                          .read_text(encoding='utf-8'))
        mutate(run_dir, data)
        (run_dir / 'manifest.json').write_text(json.dumps(data),
                                               encoding='utf-8')
        out, err = StringIO(), StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            res = trashops.restore(run_dir, self.ws, assume_yes=True)
        return run_dir, res

    def test_trash_path_redirected_by_symlink(self):
        self.require_symlinks()
        victim = self.victim('vault.bin')
        snap = self.outside_snapshot()

        def mutate(run_dir, data):
            os.symlink(str(victim), str(run_dir / 'trap'))
            data['entries'][0]['trash_path'] = 'trap'

        run_dir, res = self._run_then_tamper(mutate)

        self.assertEqual(res['restored'], [])
        self.assertEqual(len(res['failed']), 1)
        self.assertEqual(victim.read_bytes(), SENTINEL)
        self.assert_outside_untouched(snap)
        self.assertTrue((run_dir / 'temp-old.txt').is_file())  # copy intact

    def test_recorded_size_tamper_refused(self):
        self.mkjunk('temp-old.txt', b'payload' * 10)

        def mutate(run_dir, data):
            data['entries'][0]['size'] = 999999

        run_dir, res = self._run_then_tamper(mutate)

        self.assertEqual(res['restored'], [])
        self.assertEqual(len(res['failed']), 1)
        self.assertIn('manifest record', res['failed'][0]['error'])
        self.assertTrue((run_dir / 'temp-old.txt').is_file())
        self.assertFalse((self.ws / 'temp-old.txt').exists())  # not restored


# --- h) race during the confirmation prompt ------------------------------------

class ConfirmationRace(ToctouCase):
    def test_file_modified_during_confirmation_refused(self):
        junk = self.mkjunk('temp-old.txt', b'original stale junk\n')
        steps = self.plan_junk('temp-old.txt')

        def attack():
            junk.write_bytes(
                b'original stale junk\nswapped in during confirmation\n')

        report = self.apply_with_confirm_attack(steps, attack)

        self.assertEqual(report['executed'], [])
        self.assertEqual(report['skipped'][0].get('reason'), 'changed')
        self.assertIn(b'swapped in during confirmation', junk.read_bytes())
        self.assertTrue(self.no_trash_run())
        self.assertEqual(self.outside_snapshot(), {})


if __name__ == '__main__':
    unittest.main()
