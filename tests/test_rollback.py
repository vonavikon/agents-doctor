"""Tests for the unified rollback journal (manifest schema v2).

Every mutating operation is journaled in one manifest and reversible:
trash_move (move back), rmdir (recreate the empty directory),
create_file (delete again while the sha256 still matches) and
create_directory (remove again while still empty). Restore is
idempotent, v1 manifests stay readable, an in-flight 'creating' entry
marks a run as interrupted, and an empty manifest restores as a no-op.
"""
import hashlib
import json
import os
import shutil
import stat
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

import remediate  # noqa: E402
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


class RollbackCase(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp())
        self.ws = self.base / 'ws'
        self.ws.mkdir()
        self.addCleanup(lambda: force_rmtree(self.base))

    def new_run(self):
        return trashops.TrashRun(self.ws, 'rollback-test')

    def manifest(self, run_dir):
        return json.loads((Path(run_dir) / 'manifest.json')
                          .read_text(encoding='utf-8'))

    def restore(self, run_dir):
        """restore() with output captured; returns (summary, stderr)."""
        out, err = StringIO(), StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            summary = trashops.restore(Path(run_dir), self.ws, assume_yes=True)
        return summary, err.getvalue()


class RmdirRestore(RollbackCase):
    def test_rmdir_restore_recreates_empty_directory(self):
        victim = self.ws / 'gone-dir'
        victim.mkdir()
        run = self.new_run()
        trashops.record_rmdir(run, victim, 'gone-dir',
                              trashops.snapshot(victim))
        self.assertFalse(victim.exists())
        entry = self.manifest(run.run_dir)['entries'][0]
        self.assertEqual(entry['action'], 'rmdir')
        self.assertEqual(entry['status'], 'removed')
        self.assertTrue(entry['restorable'])
        self.assertTrue(entry['parent_exists'])

        summary, _err = self.restore(run.run_dir)

        self.assertEqual(summary['failed'], [])
        self.assertTrue(victim.is_dir())
        self.assertEqual([r['original_path'] for r in summary['restored']],
                         ['gone-dir'])
        self.assertEqual(self.manifest(run.run_dir)['entries'][0]['status'],
                         'restored')

    def test_rmdir_restore_recreates_missing_parents(self):
        deep = self.ws / 'nested' / 'deep'
        deep.mkdir(parents=True)
        run = self.new_run()
        trashops.record_rmdir(run, deep, 'nested/deep',
                              trashops.snapshot(deep))
        shutil.rmtree(str(self.ws / 'nested'))   # the parent vanished since

        summary, _err = self.restore(run.run_dir)

        self.assertEqual(summary['failed'], [])
        self.assertTrue((self.ws / 'nested' / 'deep').is_dir())


class CreateFileRestore(RollbackCase):
    def test_created_gitignore_deleted_on_restore(self):
        repo = self.ws / 'repo'
        repo.mkdir()
        target = repo / '.gitignore'
        content = remediate.gitignore_template()
        run = self.new_run()
        trashops.record_create_file(run, target, 'repo/.gitignore', content)
        self.assertTrue(target.is_file())
        entry = self.manifest(run.run_dir)['entries'][0]
        self.assertEqual(entry['action'], 'create_file')
        self.assertEqual(entry['status'], 'created')
        self.assertEqual(entry['sha256'],
                         hashlib.sha256(content.encode('utf-8')).hexdigest())
        self.assertTrue(entry['restorable'])

        summary, _err = self.restore(run.run_dir)

        self.assertEqual(summary['failed'], [])
        self.assertFalse(target.exists())
        self.assertEqual(self.manifest(run.run_dir)['entries'][0]['status'],
                         'restored')

    def test_modified_file_is_not_deleted(self):
        repo = self.ws / 'repo'
        repo.mkdir()
        target = repo / '.gitignore'
        run = self.new_run()
        trashops.record_create_file(run, target, 'repo/.gitignore',
                                    'original template\n')
        target.write_text('edited by the user\n', encoding='utf-8')

        summary, err = self.restore(run.run_dir)

        self.assertEqual(summary['failed'], [])
        self.assertEqual(summary['restored'], [])
        self.assertEqual(len(summary['skipped']), 1)
        self.assertIn('modified', summary['skipped'][0]['reason'])
        self.assertTrue(target.is_file())
        self.assertEqual(target.read_text(encoding='utf-8'),
                         'edited by the user\n')
        self.assertIn('warning', err)
        # not done and not failed: the entry stays retryable
        self.assertEqual(self.manifest(run.run_dir)['entries'][0]['status'],
                         'created')

    def test_skip_is_retryable_once_the_file_reverts(self):
        repo = self.ws / 'repo'
        repo.mkdir()
        target = repo / '.gitignore'
        run = self.new_run()
        trashops.record_create_file(run, target, 'repo/.gitignore',
                                    'original template\n')
        # exact bytes: write_text would translate \n to \r\n on Windows
        target.write_bytes(b'edited by the user\n')
        self.restore(run.run_dir)                    # skipped, kept
        target.write_bytes(b'original template\n')   # reverted by hand

        summary, _err = self.restore(run.run_dir)

        self.assertEqual(summary['failed'], [])
        self.assertEqual(len(summary['restored']), 1)
        self.assertFalse(target.exists())


class CreateDirectoryRestore(RollbackCase):
    def test_created_directory_removed_on_restore(self):
        made = self.ws / 'made'
        run = self.new_run()
        trashops.record_create_directory(run, made, 'made')
        self.assertTrue(made.is_dir())
        entry = self.manifest(run.run_dir)['entries'][0]
        self.assertEqual(entry['action'], 'create_directory')
        self.assertEqual(entry['status'], 'created')
        self.assertTrue(entry['restorable'])

        summary, _err = self.restore(run.run_dir)

        self.assertEqual(summary['failed'], [])
        self.assertFalse(made.exists())
        self.assertEqual(self.manifest(run.run_dir)['entries'][0]['status'],
                         'restored')

    def test_directory_that_gained_content_is_not_removed(self):
        made = self.ws / 'made'
        run = self.new_run()
        trashops.record_create_directory(run, made, 'made')
        (made / 'user-file.txt').write_text('mine', encoding='utf-8')

        summary, err = self.restore(run.run_dir)

        self.assertEqual(summary['failed'], [])
        self.assertEqual(summary['restored'], [])
        self.assertEqual(len(summary['skipped']), 1)
        self.assertIn('gained content', summary['skipped'][0]['reason'])
        self.assertTrue((made / 'user-file.txt').is_file())
        self.assertIn('warning', err)
        self.assertEqual(self.manifest(run.run_dir)['entries'][0]['status'],
                         'created')


class MixedBatch(RollbackCase):
    """A whole remediate plan (trash_move + rmdir + write_gitignore) is
    one journaled run and one restore undoes all of it."""

    def build_steps(self):
        junk = self.ws / 'temp-data.txt'
        junk.write_text('stale junk\n', encoding='utf-8')
        empty = self.ws / 'skeleton'
        empty.mkdir()
        repo = self.ws / 'repo'
        repo.mkdir()
        steps = [
            {'action': 'trash_move', 'target': str(junk), 'command': 'move',
             'reversible': True, 'note': '',
             'snapshot': trashops.snapshot(junk)},
            {'action': 'rmdir', 'target': str(empty), 'command': 'rmdir',
             'reversible': True, 'note': '',
             'snapshot': trashops.snapshot(empty)},
            {'action': 'write_gitignore', 'target': str(repo / '.gitignore'),
             'command': 'write', 'reversible': True, 'note': ''},
        ]
        return junk, empty, repo, steps

    def test_whole_plan_rolls_back_in_one_restore(self):
        junk, empty, repo, steps = self.build_steps()
        with redirect_stdout(StringIO()):
            report = remediate.apply_plan(steps, str(self.ws), assume_yes=True)
        self.assertEqual(report['failed'], [])
        self.assertEqual(len(report['executed']), 3)
        self.assertFalse(junk.exists())
        self.assertFalse(empty.exists())
        self.assertTrue((repo / '.gitignore').is_file())

        run_dir = Path(report['trash_run'])
        data = self.manifest(run_dir)
        self.assertEqual(data['manifest_schema_version'], '2')
        self.assertEqual(sorted(e['action'] for e in data['entries']),
                         ['create_file', 'rmdir', 'trash_move'])
        self.assertTrue(all(e['status'] in ('moved', 'removed', 'created')
                            and e['restorable'] for e in data['entries']))

        summary, _err = self.restore(run_dir)

        self.assertEqual(summary['failed'], [])
        self.assertEqual(len(summary['restored']), 3)
        self.assertTrue(junk.is_file())
        self.assertEqual(junk.read_text(encoding='utf-8'), 'stale junk\n')
        self.assertTrue(empty.is_dir())
        self.assertFalse((repo / '.gitignore').exists())
        self.assertTrue(all(e['status'] == 'restored'
                            for e in self.manifest(run_dir)['entries']))


class RemediateJournaling(RollbackCase):
    """remediate.py routes every mutating step through the manifest."""

    def test_write_gitignore_journals_create_file_entry(self):
        repo = self.ws / 'repo'
        repo.mkdir()
        steps = [{'action': 'write_gitignore',
                  'target': str(repo / '.gitignore'),
                  'command': 'write', 'reversible': True, 'note': ''}]
        with redirect_stdout(StringIO()):
            report = remediate.apply_plan(steps, str(self.ws), assume_yes=True)
        self.assertEqual(report['failed'], [])
        self.assertTrue((repo / '.gitignore').is_file())
        entry = self.manifest(report['trash_run'])['entries'][0]
        self.assertEqual(entry['action'], 'create_file')
        self.assertEqual(entry['status'], 'created')
        self.assertTrue(entry['restorable'])
        self.assertEqual(len(entry['sha256']), 64)

    def test_remediation_rmdir_journals_restorable_entry(self):
        empty = self.ws / 'hollow'
        empty.mkdir()
        steps = [{'action': 'rmdir', 'target': str(empty),
                  'command': 'rmdir', 'reversible': True, 'note': '',
                  'snapshot': trashops.snapshot(empty)}]
        with redirect_stdout(StringIO()):
            report = remediate.apply_plan(steps, str(self.ws), assume_yes=True)
        entry = self.manifest(report['trash_run'])['entries'][0]
        self.assertEqual(entry['action'], 'rmdir')
        self.assertEqual(entry['status'], 'removed')
        self.assertTrue(entry['restorable'])

        summary, _err = self.restore(report['trash_run'])
        self.assertEqual(summary['failed'], [])
        self.assertTrue(empty.is_dir())


class IdempotentRestore(RollbackCase):
    def test_second_restore_is_a_noop(self):
        junk = self.ws / 'temp-data.txt'
        junk.write_bytes(b'data\n')   # exact bytes: the size the journal gets
        run = self.new_run()
        trashops.move_to_trash(run, junk, 'temp-data.txt', 5, None, 'file')
        first, _err = self.restore(run.run_dir)
        self.assertEqual(len(first['restored']), 1)
        entries_before = self.manifest(run.run_dir)['entries']

        second, _err2 = self.restore(run.run_dir)

        self.assertFalse(second['declined'])
        self.assertEqual(second['restored'], [])
        self.assertEqual(second['failed'], [])
        self.assertEqual(second['already_done'], 1)
        self.assertTrue(junk.is_file())              # nothing moved again
        entries_after = self.manifest(run.run_dir)['entries']
        self.assertEqual(len(entries_after), len(entries_before))
        self.assertEqual(entries_after[0]['status'], 'restored')


class V1ManifestCompat(RollbackCase):
    def test_v1_manifest_readable_and_rmdir_stays_unrestorable(self):
        run_dir = self.ws / TRASH / '20250101-000000-aaaabbbb'
        run_dir.mkdir(parents=True)
        (run_dir / 'old.bin').write_bytes(b'v1 junk\n')
        run_dir.joinpath('manifest.json').write_text(json.dumps({
            'opid': 'aaaabbbb', 'root': str(self.ws), 'tool': 'safe_clean',
            'started_at': '2025-01-01T00:00:00', 'interrupted_run': None,
            'totals': {},
            'entries': [
                {'opid': 'aaaabbbb', 'action': 'trash',
                 'original_path': 'old.bin', 'trash_path': 'old.bin',
                 'size': 9, 'mtime_ns': 1,
                 'moved_at': '2025-01-01T00:00:00',
                 'status': 'moved', 'restorable': True},
                {'opid': 'aaaabbbb', 'action': 'rmdir',
                 'original_path': 'old-empty', 'trash_path': None,
                 'size': 0, 'mtime_ns': None,
                 'moved_at': '2025-01-01T00:00:00',
                 'status': 'removed', 'restorable': False},
            ]}), encoding='utf-8')

        summary, _err = self.restore(run_dir)

        self.assertEqual(summary['failed'], [])
        self.assertEqual(summary['manifest_schema_version'], '1')
        # the v1 trash move came back...
        self.assertEqual([r['original_path'] for r in summary['restored']],
                         ['old.bin'])
        self.assertTrue((self.ws / 'old.bin').is_file())
        # ...the v1 rmdir entry says restorable: false and is only counted
        self.assertEqual(summary['not_restorable'], 1)
        self.assertFalse((self.ws / 'old-empty').exists())


class InterruptedDetection(RollbackCase):
    def test_creating_status_marks_run_interrupted(self):
        run = self.new_run()
        run.add_entry({'opid': run.opid, 'action': 'create_file',
                       'original_path': 'repo/.gitignore', 'trash_path': None,
                       'moved_at': '2025-01-01T00:00:00',
                       'status': 'creating', 'restorable': True})
        self.assertEqual(trashops.find_interrupted(self.ws), run.opid)
        # a 'creating' entry is not picked up by restore: the operation
        # never finished, there is nothing to undo yet
        summary, _err = self.restore(run.run_dir)
        self.assertEqual(summary['restored'], [])
        self.assertEqual(summary['failed'], [])


class EmptyManifest(RollbackCase):
    def test_empty_manifest_restore_is_a_noop(self):
        run = self.new_run()
        self.assertEqual(self.manifest(run.run_dir)['entries'], [])
        with mock.patch('builtins.input',
                        side_effect=AssertionError('prompted on an empty '
                                                   'manifest')):
            with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
                summary = trashops.restore(Path(run.run_dir), self.ws)
        self.assertFalse(summary['declined'])
        self.assertEqual(summary['restored'], [])
        self.assertEqual(summary['failed'], [])
        self.assertEqual(summary['skipped'], [])


if __name__ == '__main__':
    unittest.main()
