"""Tests for restoring a trash run (trashops.restore + the
`safe_clean.py restore` CLI + the tools/restore.py shim).

Fixture (temp): a small workspace with two junk files. Each test moves
them into a trash run via safe_clean.execute on a hand-built plan, then
exercises restore() against the run directory and its manifest.
Manifest schema v2 also restores removed empty directories; the wider
rollback matrix (create_file, create_directory, mixed batches, v1
compat) lives in test_rollback.py.
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
from io import StringIO
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / 'skills' / 'agents-doctor' / 'scripts'
sys.path.insert(0, str(SCRIPTS))

import safe_clean  # noqa: E402
import trashops  # noqa: E402

TRASH = trashops.TRASH_DIR_NAME


def force_rmtree(path):
    """rmtree that clears the read-only flag git puts on some files."""
    def _onexc(func, p, _exc):
        os.chmod(p, stat.S_IWRITE)
        func(p)
    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=_onexc)
    else:
        shutil.rmtree(path, onerror=lambda func, p, _ei: _onexc(func, p, _ei))


def crafted_plan(ws, *trash_rels, rmdir_rels=()):
    items = [{'path': rel, 'size': (ws / rel).stat().st_size,
              'action': 'trash', 'category': safe_clean.CAT_CONFIRMED,
              'reason': 'crafted', 'cautious': False}
             for rel in trash_rels]
    items += [{'path': rel, 'size': 0, 'action': 'rmdir',
               'category': safe_clean.CAT_EMPTY, 'reason': 'crafted',
               'cautious': False} for rel in rmdir_rels]
    return {'root': str(ws), 'max_bytes': safe_clean.DEFAULT_MAX_BYTES,
            'items': items, 'categories': {}, 'skipped': [], 'totals': {}}


class RestoreCase(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp())
        self.ws = self.base / 'ws'
        self.ws.mkdir()
        (self.ws / 'a.txt').write_bytes(b'contents of a\n' * 5)
        (self.ws / 'b.txt').write_bytes(b'contents of b\n' * 3)
        self.addCleanup(lambda: force_rmtree(self.base))

    def execute(self, plan):
        return safe_clean.execute(plan, self.ws,
                                  confirm=lambda prompt: 'YES')

    def manifest(self, summary):
        return json.loads(
            (Path(summary['trash_dir']) / 'manifest.json')
            .read_text(encoding='utf-8'))


class RoundTrip(RestoreCase):
    def test_restore_returns_files_byte_identical(self):
        a_bytes = (self.ws / 'a.txt').read_bytes()
        b_bytes = (self.ws / 'b.txt').read_bytes()
        summary = self.execute(crafted_plan(self.ws, 'a.txt', 'b.txt'))
        run_dir = Path(summary['trash_dir'])
        self.assertFalse((self.ws / 'a.txt').exists())

        res = trashops.restore(run_dir, self.ws, assume_yes=True)

        self.assertEqual(res['declined'], False)
        self.assertEqual(sorted(r['original_path'] for r in res['restored']),
                         ['a.txt', 'b.txt'])
        self.assertEqual(res['failed'], [])
        self.assertEqual((self.ws / 'a.txt').read_bytes(), a_bytes)
        self.assertEqual((self.ws / 'b.txt').read_bytes(), b_bytes)
        self.assertFalse((run_dir / 'a.txt').exists())   # gone from trash
        # manifest now records the restore
        data = self.manifest(summary)
        self.assertTrue(all(e['status'] == 'restored' for e in data['entries']))

    def test_restore_into_subdirectory_recreates_parents(self):
        sub = self.ws / 'nested' / 'deep'
        sub.mkdir(parents=True)
        (sub / 'c.txt').write_bytes(b'deep file')
        summary = self.execute(crafted_plan(self.ws, 'nested/deep/c.txt'))
        shutil.rmtree(str(self.ws / 'nested'))   # the dir vanished since

        res = trashops.restore(Path(summary['trash_dir']), self.ws,
                               assume_yes=True)
        self.assertEqual(res['failed'], [])
        self.assertEqual((self.ws / 'nested' / 'deep' / 'c.txt').read_bytes(),
                         b'deep file')


class NameConflict(RestoreCase):
    def test_occupied_original_gets_restored_1_suffix(self):
        summary = self.execute(crafted_plan(self.ws, 'a.txt', 'b.txt'))
        # someone re-created a.txt in the meantime
        (self.ws / 'a.txt').write_bytes(b'new occupant')

        res = trashops.restore(Path(summary['trash_dir']), self.ws,
                               assume_yes=True)

        self.assertEqual((self.ws / 'a.txt').read_bytes(), b'new occupant')
        self.assertEqual((self.ws / 'a.txt.restored-1').read_bytes(),
                         b'contents of a\n' * 5)
        by_path = {r['original_path']: r for r in res['restored']}
        self.assertEqual(by_path['a.txt']['restored_to'], 'a.txt.restored-1')
        self.assertEqual(by_path['b.txt']['restored_to'], 'b.txt')
        # b.txt restored normally, no suffix
        self.assertFalse((self.ws / 'b.txt.restored-1').exists())


class Confirmation(RestoreCase):
    def test_prompt_requires_exactly_yes(self):
        summary = self.execute(crafted_plan(self.ws, 'a.txt'))
        prompts = []

        def say_no(prompt):
            prompts.append(prompt)
            return 'no'

        res = trashops.restore(Path(summary['trash_dir']), self.ws,
                               confirm=say_no)
        self.assertTrue(res['declined'])
        self.assertEqual(len(prompts), 1)
        self.assertTrue(prompt_needs_yes(prompts[0]))
        self.assertTrue((Path(summary['trash_dir']) / 'a.txt').is_file())
        self.assertFalse((self.ws / 'a.txt').exists())

        res2 = trashops.restore(Path(summary['trash_dir']), self.ws,
                                confirm=lambda p: 'YES')
        self.assertFalse(res2['declined'])
        self.assertEqual((self.ws / 'a.txt').read_bytes(),
                         b'contents of a\n' * 5)

    def test_nothing_restorable_never_prompts(self):
        summary = self.execute(crafted_plan(self.ws, 'a.txt'))
        trashops.restore(Path(summary['trash_dir']), self.ws, assume_yes=True)
        # everything already restored: a second restore must not prompt
        with mock.patch('builtins.input',
                        side_effect=AssertionError('prompted with nothing '
                                                   'to restore')):
            res = trashops.restore(Path(summary['trash_dir']), self.ws)
        self.assertFalse(res['declined'])
        self.assertEqual(res['restored'], [])
        self.assertEqual(res['failed'], [])
        self.assertEqual(res['already_done'], 1)
        self.assertTrue((self.ws / 'a.txt').is_file())   # and nothing moved


class RmdirRoundTrip(RestoreCase):
    """Schema v2: removed empty directories are restorable again."""

    def test_rmdir_run_restores_the_empty_dirs(self):
        (self.ws / 'empty1').mkdir()
        (self.ws / 'empty2').mkdir()
        summary = self.execute(crafted_plan(self.ws, rmdir_rels=('empty1',
                                                                 'empty2')))
        self.assertFalse((self.ws / 'empty1').exists())
        data = self.manifest(summary)
        self.assertEqual(data['manifest_schema_version'], '2')
        self.assertTrue(all(e['restorable'] for e in data['entries']))

        res = trashops.restore(Path(summary['trash_dir']), self.ws,
                               assume_yes=True)

        self.assertEqual(res['failed'], [])
        self.assertEqual(sorted(r['original_path'] for r in res['restored']),
                         ['empty1', 'empty2'])
        self.assertTrue((self.ws / 'empty1').is_dir())
        self.assertTrue((self.ws / 'empty2').is_dir())
        self.assertTrue(all(e['status'] == 'restored'
                            for e in self.manifest(summary)['entries']))


def prompt_needs_yes(prompt):
    return 'YES' in prompt


class BadManifests(RestoreCase):
    def test_missing_manifest_raises_value_error(self):
        bogus = self.base / 'not-a-run'
        bogus.mkdir()
        with self.assertRaises(ValueError):
            trashops.restore(bogus, self.ws, assume_yes=True)

    def test_opid_mismatch_refused_before_anything_moves(self):
        summary = self.execute(crafted_plan(self.ws, 'a.txt'))
        with self.assertRaises(ValueError):
            trashops.restore(Path(summary['trash_dir']), self.ws,
                             opid='00000000', assume_yes=True)
        self.assertTrue((Path(summary['trash_dir']) / 'a.txt').is_file())

    def test_traversal_in_original_path_refused(self):
        summary = self.execute(crafted_plan(self.ws, 'a.txt'))
        run_dir = Path(summary['trash_dir'])
        outside_victim = self.base / 'victim.txt'
        outside_victim.write_bytes(b'do not touch')
        data = self.manifest(summary)
        data['entries'][0]['original_path'] = '../victim.txt'
        (run_dir / 'manifest.json').write_text(
            json.dumps(data), encoding='utf-8')

        res = trashops.restore(run_dir, self.ws, assume_yes=True)

        self.assertEqual(len(res['failed']), 1)
        self.assertEqual(res['restored'], [])
        self.assertEqual(outside_victim.read_bytes(), b'do not touch')
        self.assertTrue((run_dir / 'a.txt').is_file())   # still in trash

    def test_traversal_in_trash_path_refused(self):
        summary = self.execute(crafted_plan(self.ws, 'a.txt'))
        run_dir = Path(summary['trash_dir'])
        data = self.manifest(summary)
        data['entries'][0]['trash_path'] = '../../a.txt'   # points at itself
        (run_dir / 'manifest.json').write_text(
            json.dumps(data), encoding='utf-8')

        res = trashops.restore(run_dir, self.ws, assume_yes=True)
        self.assertEqual(len(res['failed']), 1)
        self.assertFalse((self.ws / 'a.txt').exists())     # nothing restored

    def test_missing_trash_copy_recorded_as_failure(self):
        summary = self.execute(crafted_plan(self.ws, 'a.txt'))
        run_dir = Path(summary['trash_dir'])
        (run_dir / 'a.txt').unlink()   # the trash copy vanished

        res = trashops.restore(run_dir, self.ws, assume_yes=True)
        self.assertEqual(len(res['failed']), 1)
        data = self.manifest(summary)
        self.assertEqual(data['entries'][0]['status'], 'restore_failed')

    def test_restore_failed_entry_is_retryable(self):
        summary = self.execute(crafted_plan(self.ws, 'a.txt'))
        run_dir = Path(summary['trash_dir'])
        data = self.manifest(summary)
        data['entries'][0]['status'] = 'restore_failed'
        data['entries'][0]['error'] = 'from an earlier attempt'
        (run_dir / 'manifest.json').write_text(
            json.dumps(data), encoding='utf-8')

        res = trashops.restore(run_dir, self.ws, assume_yes=True)
        self.assertEqual(res['restored'][0]['original_path'], 'a.txt')
        self.assertEqual((self.ws / 'a.txt').read_bytes(),
                         b'contents of a\n' * 5)


class CollisionHelper(unittest.TestCase):
    def test_suffix_escalates_until_free(self):
        base = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(str(base)))
        dst = base / 'x.txt'
        dst.write_bytes(b'1')
        (base / 'x.txt.__1__').write_bytes(b'2')
        (base / 'x.txt.__2__').write_bytes(b'3')

        got = trashops.collision_free_dst(dst)
        self.assertEqual(got.name, 'x.txt.__3__')
        with self.assertRaises(OSError):
            # pathological: all 999 names taken (fabricated via monkeypatch)
            with mock.patch.object(trashops, '_exists', return_value=True):
                trashops.collision_free_dst(dst)


class RestoreCli(RestoreCase):
    def run_main(self, *args):
        out, err = StringIO(), StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = safe_clean.main([str(a) for a in args])
        return rc, out.getvalue(), err.getvalue()

    def test_cli_restores_with_yes_flag(self):
        summary = self.execute(crafted_plan(self.ws, 'a.txt'))
        rc, out, err = self.run_main('restore', summary['trash_dir'],
                                     '--root', self.ws, '--yes')
        self.assertEqual(rc, 0, err)
        self.assertIn('Restore finished', out)
        self.assertIn(summary['opid'], out)
        self.assertEqual((self.ws / 'a.txt').read_bytes(),
                         b'contents of a\n' * 5)

    def test_cli_root_defaults_to_manifest(self):
        summary = self.execute(crafted_plan(self.ws, 'a.txt'))
        rc, out, err = self.run_main('restore', summary['trash_dir'], '--yes')
        self.assertEqual(rc, 0, err)
        self.assertEqual((self.ws / 'a.txt').read_bytes(),
                         b'contents of a\n' * 5)

    def test_cli_decline_changes_nothing(self):
        summary = self.execute(crafted_plan(self.ws, 'a.txt'))
        with mock.patch('builtins.input', return_value='no'):
            rc, out, err = self.run_main('restore', summary['trash_dir'],
                                         '--root', self.ws)
        self.assertEqual(rc, 0)
        self.assertIn('Nothing was changed.', out)
        self.assertTrue((Path(summary['trash_dir']) / 'a.txt').is_file())

    def test_cli_typed_yes_via_stdin(self):
        summary = self.execute(crafted_plan(self.ws, 'a.txt'))
        with mock.patch('builtins.input', return_value='YES'):
            rc, out, err = self.run_main('restore', summary['trash_dir'],
                                         '--root', self.ws)
        self.assertEqual(rc, 0, err)
        self.assertEqual((self.ws / 'a.txt').read_bytes(),
                         b'contents of a\n' * 5)

    def test_cli_bad_run_dir_returns_two(self):
        rc, _, err = self.run_main('restore', self.base / 'nope', '--yes')
        self.assertEqual(rc, 2)
        self.assertIn('manifest', err)

    def test_cli_failure_returns_one(self):
        summary = self.execute(crafted_plan(self.ws, 'a.txt'))
        (Path(summary['trash_dir']) / 'a.txt').unlink()   # copy vanished
        rc, _, err = self.run_main('restore', summary['trash_dir'],
                                   '--root', self.ws, '--yes')
        self.assertEqual(rc, 1)
        self.assertIn('failed on a.txt', err)


class RestoreShim(RestoreCase):
    """tools/restore.py: the documented CLI wrapper around the same logic."""

    def test_shim_restores_via_subprocess(self):
        summary = self.execute(crafted_plan(self.ws, 'a.txt'))
        r = subprocess.run(
            [sys.executable, str(REPO_ROOT / 'tools' / 'restore.py'),
             str(summary['trash_dir']), '--root', str(self.ws), '--yes'],
            capture_output=True, text=True, timeout=120, cwd=str(REPO_ROOT))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn('Restore finished', r.stdout)
        self.assertEqual((self.ws / 'a.txt').read_bytes(),
                         b'contents of a\n' * 5)


if __name__ == '__main__':
    unittest.main()
