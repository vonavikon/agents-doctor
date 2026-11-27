"""Tests for safe_clean.py: the guided mass-cleanup wizard.

Fixture workspace (temp): one git repo with a committed junk-named file
and an empty dir, plus non-git junk at the workspace root: node_modules,
dist, two old unreferenced junk files (120 days), .env with a secret, a
3-file duplicate group with distinct mtimes, a 600 MB sparse junk file
and two empty dirs. The CLI runs only against these temp fixtures; git
in them uses a per-command local identity.
"""
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
import safe_clean  # noqa: E402

OLD = time.time() - 120 * 86400          # junk age: 120 days
BIG_BYTES = 600 * 1024 * 1024            # over the 500 MB per-item cap
TRASH = safe_clean.TRASH_DIR_NAME


def force_rmtree(path):
    """rmtree that clears the read-only flag git puts on some files."""
    def _onexc(func, p, _exc):
        os.chmod(p, stat.S_IWRITE)
        func(p)
    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=_onexc)
    else:
        shutil.rmtree(path, onerror=lambda func, p, _ei: _onexc(func, p, _ei))


def git(repo, *args):
    """git in a fixture repo; commit gets a per-command local identity."""
    args = (['-c', 'user.email=t@example.com', '-c', 'user.name=T'] + list(args)
            if args and args[0] == 'commit' else list(args))
    subprocess.run(['git', '-C', str(repo)] + args,
                   check=True, capture_output=True)


def make_fixture(base):
    """Build the workspace; returns (ws, home, repo)."""
    ws, home = base / 'ws', base / 'home'
    repo = ws / 'repo'
    (repo / 'src').mkdir(parents=True)
    home.mkdir(parents=True)

    # git repo with a TRACKED junk-named file and a normal file
    (repo / 'old-report.txt').write_bytes(b'tracked junk-named content v1')
    (repo / 'src' / 'app.js').write_bytes(b'console.log(1)\n')
    git(repo, 'init', '-q')
    git(repo, 'add', 'old-report.txt', 'src/app.js')
    git(repo, 'commit', '-q', '-m', 'init')
    (repo / 'empty_in_repo').mkdir()

    # safe build artifact: aged (not an active install) and lockfile-backed
    nm = ws / 'node_modules' / 'left-pad'
    nm.mkdir(parents=True)
    (nm / 'index.js').write_bytes(b'module.exports = 1\n' * 10)
    (nm / 'package.json').write_bytes(b'{"name": "left-pad"}')
    (ws / 'package-lock.json').write_bytes(b'{"lockfileVersion": 3}\n')
    _old = time.time() - 30 * 86400
    os.utime(ws / 'node_modules', (_old, _old))

    # cautious build artifact (aged too: fresh = active install)
    (ws / 'dist').mkdir()
    (ws / 'dist' / 'bundle.js').write_bytes(b'console.log(2)\n' * 10)
    os.utime(ws / 'dist', (_old, _old))

    # old unreferenced junk files -> confirmed_unused
    for name, blob in (('screenshot_1.png', b'png' * 100),
                       ('temp_notes.txt', b'notes ' * 20)):
        f = ws / name
        f.write_bytes(blob)
        os.utime(str(f), (OLD, OLD))

    # secret file: must never be touched
    (ws / '.env').write_text('API_TOKEN=sk-test-123456\n', encoding='utf-8')

    # duplicate group: identical blobs, distinct mtimes (keep the newest)
    blob = b'z' * 2048
    for name, days in (('data_a.bin', 200), ('data_b.bin', 100),
                       ('data_c.bin', 0)):
        f = ws / name
        f.write_bytes(blob)
        if days:
            t = time.time() - days * 86400
            os.utime(str(f), (t, t))

    # 600 MB sparse junk-named file: over the cap, no real disk use
    big = ws / 'old-huge.bin'
    with big.open('wb') as fh:
        fh.write(b'x')
    os.truncate(str(big), BIG_BYTES)
    os.utime(str(big), (OLD, OLD))

    # empty dirs
    (ws / 'empty1').mkdir()
    (ws / 'empty2').mkdir()
    return ws, home, repo


class SafeCleanCase(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp())
        self.ws, self.home, self.repo = make_fixture(self.base)
        self.rep = audit_scan.scan(self.ws, self.home)

    def tearDown(self):
        force_rmtree(self.base)

    def paths(self, plan):
        return {i['path'] for i in plan['items']}

    def skipped_for(self, plan, path_tail):
        return [s for s in plan['skipped'] if s['path'].endswith(path_tail)]


class DefaultPlan(SafeCleanCase):
    def test_includes_safe_excludes_unsafe_and_cautious(self):
        plan = safe_clean.build_plan(self.rep)
        paths = self.paths(plan)

        # default-safe: node_modules, empty dirs, confirmed junk
        self.assertIn('node_modules', paths)
        self.assertIn('empty1', paths)
        self.assertIn('empty2', paths)
        self.assertIn(str(Path('repo') / 'empty_in_repo'), paths)
        shot = next(i for i in plan['items']
                    if i['path'].endswith('screenshot_1.png'))
        self.assertEqual(shot['action'], 'trash')
        self.assertEqual(shot['category'], safe_clean.CAT_CONFIRMED)
        self.assertEqual(
            next(i for i in plan['items'] if i['path'] == 'node_modules')['category'],
            safe_clean.CAT_BUILD_SAFE)
        self.assertTrue(all(i['action'] == 'rmdir' for i in plan['items']
                            if i['category'] == safe_clean.CAT_EMPTY))

        # tracked junk-named file: excluded, recorded with one word
        self.assertFalse(any(p.endswith('old-report.txt') for p in paths))
        self.assertEqual(self.skipped_for(plan, 'old-report.txt'),
                         [{'path': str(Path('repo') / 'old-report.txt'),
                           'reason': 'tracked'}])

        # cautious items hidden without the flag
        self.assertNotIn('dist', paths)
        self.assertFalse(any(p.startswith('data_') for p in paths))

        # cap: nothing over 500 MB, big file recorded as oversized
        self.assertTrue(all(i['size'] <= safe_clean.DEFAULT_MAX_BYTES
                            for i in plan['items']))
        self.assertEqual(self.skipped_for(plan, 'old-huge.bin')[0]['reason'],
                         'oversized')

        # .env is never a candidate at all
        self.assertNotIn('.env', paths)
        self.assertFalse(any(s['path'] == '.env' for s in plan['skipped']))

    def test_preview_lists_oversized_with_cap_message(self):
        plan = safe_clean.build_plan(self.rep)
        text = safe_clean.preview_text(plan)
        self.assertIn('old-huge.bin', text)
        self.assertIn('handle these by hand', text)
        self.assertIn('Will NOT touch: tracked files, settings with keys, '
                      'anything the audit is unsure about.', text)


class ExecuteYes(SafeCleanCase):
    def test_moves_to_trash_and_rmdirs(self):
        plan = safe_clean.build_plan(self.rep)
        tracked_content = (self.repo / 'old-report.txt').read_bytes()
        summary = safe_clean.execute(plan, self.ws,
                                     confirm=lambda prompt: 'YES')

        self.assertFalse(summary['declined'])
        trash = Path(summary['trash_dir'])
        self.assertTrue(trash.is_dir())
        self.assertEqual(trash.parent.name, TRASH)
        self.assertRegex(trash.name, r'^\d{8}-\d{6}-[0-9a-f]{8}$')

        # trash preserves relative paths; originals are gone
        for rel in ('node_modules', 'screenshot_1.png', 'temp_notes.txt'):
            self.assertFalse((self.ws / rel).exists(), rel)
            self.assertTrue((trash / rel).exists(), rel)
        self.assertTrue((trash / 'node_modules' / 'left-pad' / 'index.js').is_file())

        # empty dirs removed in place
        self.assertFalse((self.ws / 'empty1').exists())
        self.assertFalse((self.ws / 'empty2').exists())
        self.assertFalse((self.repo / 'empty_in_repo').exists())
        self.assertEqual(len(summary['removed_dirs']), 3)

        # NEVER items intact
        self.assertEqual((self.repo / 'old-report.txt').read_bytes(),
                         tracked_content)
        self.assertTrue((self.ws / '.env').is_file())

        # summary numbers add up: freed == sum of all planned item sizes
        self.assertEqual(summary['freed_bytes'],
                         sum(i['size'] for i in plan['items']))
        self.assertEqual(len(summary['moved']),
                         sum(1 for i in plan['items'] if i['action'] == 'trash'))
        self.assertEqual(summary['failed'], [])
        self.assertEqual(summary['skipped_safety'], [])


class Declined(SafeCleanCase):
    def test_refusal_touches_nothing(self):
        plan = safe_clean.build_plan(self.rep)
        prompts = []

        def say_no(prompt):
            prompts.append(prompt)
            return 'no'

        summary = safe_clean.execute(plan, self.ws, confirm=say_no)

        self.assertTrue(summary['declined'])
        self.assertEqual(prompts, ['Type YES to clean: '])
        self.assertEqual(summary['moved'], [])
        self.assertEqual(summary['removed_dirs'], [])
        self.assertEqual(summary['freed_bytes'], 0)
        self.assertIsNone(summary['trash_dir'])

        # disk untouched
        self.assertTrue((self.ws / 'node_modules').is_dir())
        self.assertTrue((self.ws / 'screenshot_1.png').is_file())
        self.assertTrue((self.ws / 'empty1').is_dir())
        self.assertFalse((self.ws / TRASH).exists())


class Containment(SafeCleanCase):
    def test_escaping_path_refused_item_skipped(self):
        victim = self.base / 'victim.txt'
        victim.write_bytes(b'do not touch')
        evil = os.path.join(os.pardir, 'victim.txt')
        plan = {'root': str(self.ws), 'max_bytes': safe_clean.DEFAULT_MAX_BYTES,
                'items': [{'path': evil, 'size': 5, 'action': 'trash',
                           'category': safe_clean.CAT_CONFIRMED,
                           'reason': 'crafted', 'cautious': False}],
                'categories': {}, 'skipped': [], 'totals': {'count': 1, 'size_bytes': 5}}
        summary = safe_clean.execute(plan, self.ws,
                                     confirm=lambda prompt: 'YES')

        self.assertEqual(summary['moved'], [])
        self.assertEqual(summary['skipped_safety'],
                         [{'path': evil, 'reason': 'escape'}])
        self.assertEqual(summary['freed_bytes'], 0)
        self.assertEqual(victim.read_bytes(), b'do not touch')

    def test_two_level_traversal_detected_at_plan_time(self):
        rel = os.path.join(os.pardir, os.pardir, 'x')
        why = safe_clean._never_reason(self.ws, rel, 1, None)
        self.assertEqual(why, 'escape')


class SymlinkSkip(SafeCleanCase):
    def test_symlink_item_skipped(self):
        if not hasattr(os, 'symlink'):
            self.skipTest('os.symlink unavailable')
        outside = self.base / 'outside'
        outside.mkdir()
        target = outside / 'target.bin'
        target.write_bytes(b'x' * 16)
        link = self.ws / 'old-link.bin'
        try:
            os.symlink(str(target), str(link))
        except (OSError, NotImplementedError):
            self.skipTest('symlink creation unavailable on this system')

        plan = {'root': str(self.ws), 'max_bytes': safe_clean.DEFAULT_MAX_BYTES,
                'items': [{'path': 'old-link.bin', 'size': 16, 'action': 'trash',
                           'category': safe_clean.CAT_CONFIRMED,
                           'reason': 'crafted', 'cautious': False}],
                'categories': {}, 'skipped': [], 'totals': {'count': 1, 'size_bytes': 16}}
        summary = safe_clean.execute(plan, self.ws,
                                     confirm=lambda prompt: 'YES')

        self.assertEqual(summary['moved'], [])
        self.assertEqual(summary['skipped_safety'],
                         [{'path': 'old-link.bin', 'reason': 'symlink'}])
        self.assertTrue(link.is_symlink())
        self.assertEqual(target.read_bytes(), b'x' * 16)


class CautiousPass(SafeCleanCase):
    def test_duplicates_oldest_trashed_newest_kept_and_dist_included(self):
        plan = safe_clean.build_plan(self.rep, include_cautious=True)
        olds = {i['path'] for i in plan['items']
                if i['category'] == safe_clean.CAT_OLD_COPIES}
        self.assertEqual(olds, {'data_a.bin', 'data_b.bin'})
        self.assertIn('dist', self.paths(plan))

        summary = safe_clean.execute(plan, self.ws,
                                     confirm=lambda prompt: 'YES')
        trash = Path(summary['trash_dir'])

        self.assertTrue((self.ws / 'data_c.bin').is_file())   # newest kept
        self.assertFalse((self.ws / 'data_a.bin').exists())   # oldest trashed
        self.assertFalse((self.ws / 'data_b.bin').exists())
        self.assertTrue((trash / 'data_a.bin').is_file())
        self.assertTrue((trash / 'data_b.bin').is_file())
        self.assertFalse((self.ws / 'dist').exists())


class Cli(SafeCleanCase):
    def run_main(self, *args):
        out, err = StringIO(), StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = safe_clean.main([str(a) for a in args])
        return rc, out.getvalue(), err.getvalue()

    def test_full_run_returns_zero_and_creates_trash(self):
        rc, out, err = self.run_main(self.ws, '--home', self.home, '--yes')
        self.assertEqual(rc, 0)
        self.assertNotIn('sk-test-123456', out + err)   # no raw secret content
        self.assertIn('Moved', out)
        trash = self.ws / TRASH
        self.assertTrue(trash.is_dir())
        self.assertTrue(list(trash.iterdir()))
        self.assertTrue((self.ws / '.env').is_file())

    def test_interactive_decline_returns_zero(self):
        # run the CLI as a subprocess with stdin closed: input() hits EOF,
        # the answer is not YES, the run declines without touching anything
        r = subprocess.run(
            [sys.executable, str(SCRIPTS / 'safe_clean.py'),
             str(self.ws), '--home', str(self.home)],
            stdin=subprocess.DEVNULL, capture_output=True, text=True,
            timeout=120)
        self.assertEqual(r.returncode, 0)
        self.assertIn('Nothing was changed.', r.stdout)
        self.assertTrue((self.ws / 'node_modules').is_dir())
        self.assertFalse((self.ws / TRASH).exists())

    def test_bad_root_returns_two(self):
        rc, _, err = self.run_main(self.base / 'nope', '--home', self.home)
        self.assertEqual(rc, 2)
        self.assertIn('not a directory', err)

    def test_git_dir_root_refused_with_three(self):
        rc, _, err = self.run_main(self.repo / '.git', '--home', self.home)
        self.assertEqual(rc, 3)
        self.assertIn('refusing to run', err)

    def test_nothing_to_clean_returns_one(self):
        empty_ws = self.base / 'empty_ws'
        empty_ws.mkdir()
        rc, out, _ = self.run_main(empty_ws, '--home', self.home, '--yes')
        self.assertEqual(rc, 1)
        self.assertIn('Nothing safe to clean', out)


class ResearchGuards(SafeCleanCase):
    """Two industry-pattern guards applied from docs/research-human-layer.md."""

    def test_recent_build_dir_skipped(self):
        # same fixture, but node_modules touched NOW: active install
        os.utime(self.ws / 'node_modules')
        rep = audit_scan.scan(self.ws, self.home)
        plan = safe_clean.build_plan(rep)
        paths = [i['path'] for i in plan['items']]
        self.assertNotIn('node_modules', paths)
        reasons = {s['path']: s['reason'] for s in plan['skipped']}
        self.assertEqual(reasons.get('node_modules'), 'recent')

    def test_node_modules_without_lockfile_is_cautious(self):
        # aged but no lockfile: not reliably regenerable → cautious tier
        (self.ws / 'package-lock.json').unlink()
        rep = audit_scan.scan(self.ws, self.home)
        default = safe_clean.build_plan(rep)
        self.assertNotIn('node_modules', [i['path'] for i in default['items']])
        cautious = safe_clean.build_plan(rep, include_cautious=True)
        item = next(i for i in cautious['items'] if i['path'] == 'node_modules')
        self.assertEqual(item['category'], safe_clean.CAT_BUILD_CAUTIOUS)
        self.assertTrue(item['cautious'])


# --- trash runs, manifest, TOCTOU, crash recovery ----------------------------------

import json  # noqa: E402  (manifest checks)

import trashops  # noqa: E402
from unittest import mock  # noqa: E402


def crafted_plan(ws, *items, max_bytes=None):
    """A minimal hand-built plan (no scan): items are (path, action)
    pairs. Such plans carry no TOCTOU snapshot, like plans built
    before snapshots were added; execute() must still handle them
    safely."""
    return {'root': str(ws),
            'max_bytes': (max_bytes if max_bytes is not None
                          else safe_clean.DEFAULT_MAX_BYTES),
            'items': [{'path': p,
                       'size': (ws / p).stat().st_size
                       if os.path.isfile(ws / p) else 0,
                       'action': a, 'category': safe_clean.CAT_CONFIRMED,
                       'reason': 'crafted', 'cautious': False}
                      for p, a in items],
            'categories': {}, 'skipped': [], 'totals': {}}


class RunDirAndManifest(SafeCleanCase):
    def test_run_dir_has_opid_and_manifest_records_every_item(self):
        plan = safe_clean.build_plan(self.rep)
        summary = safe_clean.execute(plan, self.ws,
                                     confirm=lambda prompt: 'YES')

        self.assertRegex(summary['opid'], r'^[0-9a-f]{8}$')
        run_dir = Path(summary['trash_dir'])
        self.assertEqual(run_dir.name.split('-')[-1], summary['opid'])
        self.assertEqual(run_dir.parent, Path(summary['root']) / TRASH)

        data = json.loads((run_dir / 'manifest.json').read_text(encoding='utf-8'))
        self.assertEqual(data['opid'], summary['opid'])
        self.assertEqual(data['manifest_schema_version'], '2')
        self.assertEqual(data['tool'], 'safe_clean')
        self.assertEqual(data['root'], summary['root'])
        self.assertIn('started_at', data)
        self.assertIsNone(data['interrupted_run'])
        self.assertEqual(data['totals']['planned'], len(plan['items']))
        self.assertEqual(data['totals']['moved'], len(summary['moved']))
        self.assertEqual(data['totals']['removed_dirs'],
                         len(summary['removed_dirs']))

        moved = {e['original_path']: e for e in data['entries']
                 if e['action'] == 'trash_move'}
        self.assertEqual(set(moved), {m['path'] for m in summary['moved']})
        entry = moved['screenshot_1.png']
        self.assertEqual(entry['status'], 'moved')
        self.assertEqual(entry['trash_path'], 'screenshot_1.png')
        self.assertIn('mtime_ns', entry)
        self.assertIn('moved_at', entry)
        self.assertTrue(entry['restorable'])

        rmdirs = [e for e in data['entries'] if e['action'] == 'rmdir']
        self.assertEqual({e['original_path'] for e in rmdirs},
                         {d['path'] for d in summary['removed_dirs']})
        for e in rmdirs:
            self.assertEqual(e['status'], 'removed')
            self.assertTrue(e['restorable'])
            self.assertTrue(e['parent_exists'])

    def test_summary_text_prints_run_dir_opid_manifest_and_restore_cmd(self):
        plan = safe_clean.build_plan(self.rep)
        summary = safe_clean.execute(plan, self.ws,
                                     confirm=lambda prompt: 'YES')
        text = safe_clean.summary_text(summary)
        self.assertIn(summary['trash_dir'], text)
        self.assertIn(summary['opid'], text)
        self.assertIn(summary['manifest_path'], text)
        self.assertIn('safe_clean.py restore "%s"' % summary['trash_dir'], text)

    def test_rerun_creates_a_new_run_dir(self):
        plan = safe_clean.build_plan(self.rep)
        s1 = safe_clean.execute(plan, self.ws, confirm=lambda p: 'YES')
        # second pass needs a fresh scan: the first one emptied the ws
        rep2 = audit_scan.scan(self.ws, self.home)
        plan2 = safe_clean.build_plan(rep2)
        s2 = safe_clean.execute(plan2, self.ws, confirm=lambda p: 'YES')
        self.assertNotEqual(s1['trash_dir'], s2['trash_dir'])
        self.assertNotEqual(s1['opid'], s2['opid'])
        self.assertTrue(Path(s1['trash_dir']).is_dir())   # old run kept


class ToctouSnapshot(SafeCleanCase):
    def test_file_changed_after_planning_is_aborted(self):
        plan = safe_clean.build_plan(self.rep)
        victim = self.ws / 'screenshot_1.png'
        victim.write_bytes(victim.read_bytes() + b'changed after planning')

        summary = safe_clean.execute(plan, self.ws, confirm=lambda p: 'YES')

        changed = [s for s in summary['skipped_safety']
                   if s['path'] == 'screenshot_1.png']
        self.assertEqual(changed, [{'path': 'screenshot_1.png',
                                    'reason': 'changed'}])
        # disk untouched for it: still in place with the new content,
        # and not a single copy of it anywhere in the trash
        self.assertTrue(victim.is_file())
        self.assertIn(b'changed after planning', victim.read_bytes())
        self.assertEqual(list((self.ws / TRASH).rglob('screenshot_1.png')), [])
        # the rest of the batch was not affected
        self.assertIn('temp_notes.txt',
                      {m['path'] for m in summary['moved']})

    def test_mtime_only_change_aborts_too(self):
        plan = safe_clean.build_plan(self.rep)
        victim = self.ws / 'temp_notes.txt'
        os.utime(str(victim), (time.time() + 5, time.time() + 5))
        summary = safe_clean.execute(plan, self.ws, confirm=lambda p: 'YES')
        reasons = {s['path']: s['reason'] for s in summary['skipped_safety']}
        self.assertEqual(reasons.get('temp_notes.txt'), 'changed')
        self.assertTrue(victim.is_file())

    def test_empty_dir_that_gained_a_file_is_aborted(self):
        plan = safe_clean.build_plan(self.rep)
        (self.ws / 'empty1' / 'appeared.txt').write_bytes(b'new tenant')
        summary = safe_clean.execute(plan, self.ws, confirm=lambda p: 'YES')
        reasons = {s['path']: s['reason'] for s in summary['skipped_safety']}
        self.assertEqual(reasons.get('empty1'), 'changed')
        self.assertTrue((self.ws / 'empty1' / 'appeared.txt').is_file())


class DestinationCollision(SafeCleanCase):
    def test_taken_destination_gets_suffix_and_both_files_exist(self):
        # pin the run dir name so the collision can be pre-created
        with mock.patch.object(trashops, 'new_opid', return_value='deadbeef'), \
                mock.patch.object(trashops, 'run_stamp',
                                  return_value='20260101-000000'):
            run_dir = self.ws / TRASH / '20260101-000000-deadbeef'
            run_dir.mkdir(parents=True)
            squatter = run_dir / 'screenshot_1.png'
            squatter.write_bytes(b'older run occupant')

            plan = crafted_plan(self.ws, ('screenshot_1.png', 'trash'))
            summary = safe_clean.execute(plan, self.ws,
                                         confirm=lambda p: 'YES')

        # compare resolved forms: CI runners hand tempfile short (8.3)
        # paths while execute() resolves to the long form
        self.assertEqual(str(Path(summary['trash_dir']).resolve()),
                         str(run_dir.resolve()))
        moved = summary['moved'][0]
        self.assertTrue(moved['moved_to'].endswith('screenshot_1.png.__1__'))
        self.assertEqual(squatter.read_bytes(), b'older run occupant')
        suffixed = run_dir / 'screenshot_1.png.__1__'
        self.assertEqual(suffixed.read_bytes().startswith(b'png'), True)
        self.assertFalse((self.ws / 'screenshot_1.png').exists())
        data = json.loads((run_dir / 'manifest.json').read_text(encoding='utf-8'))
        self.assertEqual(data['entries'][0]['trash_path'],
                         'screenshot_1.png.__1__')


class WriteAheadManifest(SafeCleanCase):
    def test_failed_move_shows_moving_then_failed_in_manifest(self):
        statuses_seen_during_move = []
        real_move = shutil.move

        def move_spy(src, dst):
            if dst.endswith('temp_notes.txt') or dst.endswith('temp_notes.txt.__1__'):
                run_dir = Path(dst).parent
                data = json.loads((run_dir / 'manifest.json')
                                  .read_text(encoding='utf-8'))
                statuses_seen_during_move.append(
                    [e['original_path'] + ':' + e['status']
                     for e in data['entries']])
                raise OSError('simulated crash mid-move')
            return real_move(src, dst)

        plan = crafted_plan(self.ws, ('screenshot_1.png', 'trash'),
                            ('temp_notes.txt', 'trash'))
        with mock.patch('shutil.move', side_effect=move_spy):
            summary = safe_clean.execute(plan, self.ws,
                                         confirm=lambda p: 'YES')

        # batch continued: item 1 moved, item 2 failed
        self.assertEqual([m['path'] for m in summary['moved']],
                         ['screenshot_1.png'])
        self.assertEqual([f['path'] for f in summary['failed']],
                         ['temp_notes.txt'])
        self.assertTrue((self.ws / 'temp_notes.txt').is_file())

        # write-ahead: at the moment the move was attempted, the entry
        # for temp_notes.txt was already on disk as 'moving'
        self.assertEqual(statuses_seen_during_move,
                         [['screenshot_1.png:moved',
                           'temp_notes.txt:moving']])

        data = json.loads((Path(summary['trash_dir']) / 'manifest.json')
                          .read_text(encoding='utf-8'))
        by_path = {e['original_path']: e for e in data['entries']}
        self.assertEqual(by_path['screenshot_1.png']['status'], 'moved')
        self.assertEqual(by_path['temp_notes.txt']['status'], 'failed')
        self.assertIn('simulated crash', by_path['temp_notes.txt']['error'])
        self.assertEqual(data['totals']['failed'], 1)
        self.assertEqual(data['totals']['moved'], 1)


class RefusedTrashRun(SafeCleanCase):
    """A trash run the pre-operation gate refuses (e.g. the trash
    folder swapped for a symlink, attack d in tests/test_toctou_security)
    is recorded as a failure instead of crashing the batch."""

    def test_refused_run_recorded_as_failure_not_crash(self):
        plan = crafted_plan(self.ws, ('screenshot_1.png', 'trash'))
        with mock.patch.object(
                trashops.TrashRun, '__init__',
                side_effect=trashops.SecurityRefusal('probe refusal')):
            summary = safe_clean.execute(plan, self.ws,
                                         confirm=lambda p: 'YES')
        self.assertEqual(summary['moved'], [])
        self.assertEqual(summary['removed_dirs'], [])
        self.assertEqual(len(summary['failed']), 1)
        self.assertIn('probe refusal', summary['failed'][0]['error'])
        self.assertTrue((self.ws / 'screenshot_1.png').is_file())
        self.assertIsNone(summary['trash_dir'])


class CrashRecovery(SafeCleanCase):
    def _fabricate_interrupted_run(self):
        run_dir = self.ws / TRASH / '20250101-000000-aaaabbbb'
        run_dir.mkdir(parents=True)
        (run_dir / 'mid-flight.bin').write_bytes(b'in flight when it died')
        (run_dir / 'manifest.json').write_text(json.dumps({
            'opid': 'aaaabbbb', 'root': str(self.ws), 'tool': 'safe_clean',
            'started_at': '2025-01-01T00:00:00', 'interrupted_run': None,
            'totals': {}, 'entries': [
                {'opid': 'aaaabbbb', 'action': 'trash',
                 'original_path': 'mid-flight.bin',
                 'trash_path': 'mid-flight.bin', 'size': 22,
                 'mtime_ns': 1, 'moved_at': '2025-01-01T00:00:00',
                 'status': 'moving', 'restorable': True},
            ]}), encoding='utf-8')
        return run_dir

    def test_interrupted_run_noted_and_never_touched(self):
        old_run = self._fabricate_interrupted_run()
        plan = safe_clean.build_plan(self.rep)
        summary = safe_clean.execute(plan, self.ws, confirm=lambda p: 'YES')

        self.assertEqual(summary['interrupted_run'], 'aaaabbbb')
        data = json.loads((Path(summary['trash_dir']) / 'manifest.json')
                          .read_text(encoding='utf-8'))
        self.assertEqual(data['interrupted_run'], 'aaaabbbb')
        # the interrupted run is intact: same files, same manifest
        self.assertTrue((old_run / 'mid-flight.bin').is_file())
        old = json.loads((old_run / 'manifest.json').read_text(encoding='utf-8'))
        self.assertEqual(old['entries'][0]['status'], 'moving')
        self.assertNotEqual(summary['trash_dir'], str(old_run))

    def test_clean_earlier_run_is_not_flagged(self):
        # an earlier completed run (no in-flight entries) is not interrupted
        run_dir = self.ws / TRASH / '20250101-000000-cccccccc'
        run_dir.mkdir(parents=True)
        (run_dir / 'done.bin').write_bytes(b'x')
        (run_dir / 'manifest.json').write_text(json.dumps({
            'opid': 'cccccccc', 'root': str(self.ws), 'tool': 'safe_clean',
            'entries': [{'opid': 'cccccccc', 'action': 'trash',
                         'original_path': 'done.bin', 'trash_path': 'done.bin',
                         'status': 'moved'}]}), encoding='utf-8')
        plan = safe_clean.build_plan(self.rep)
        summary = safe_clean.execute(plan, self.ws, confirm=lambda p: 'YES')
        self.assertIsNone(summary['interrupted_run'])


class LostAccess(unittest.TestCase):
    """POSIX-only: permission failures on one item never stop the batch."""

    def setUp(self):
        if os.name == 'nt':
            self.skipTest('chmod is not enforced for directories on Windows')
        self.base = Path(tempfile.mkdtemp())
        self.ws = self.base / 'ws'
        (self.ws / 'locked').mkdir(parents=True)
        (self.ws / 'locked' / 'secret-ish.bin').write_bytes(b'no access')
        (self.ws / 'fine.txt').write_bytes(b'fine')
        self.addCleanup(lambda: force_rmtree(self.base))
        self.addCleanup(self._unlock)   # LIFO: unlock runs before rmtree

    def _unlock(self):
        locked = self.base / 'ws' / 'locked'
        if locked.exists():
            os.chmod(str(locked), 0o700)

    def test_lost_access_item_skipped_batch_continues(self):
        os.chmod(str(self.ws / 'locked'), 0o000)
        plan = crafted_plan(self.ws, ('locked/secret-ish.bin', 'trash'),
                            ('fine.txt', 'trash'))
        summary = safe_clean.execute(plan, self.ws, confirm=lambda p: 'YES')

        # the inaccessible item was refused (skipped or failed, never
        # moved) and the batch continued past it
        refused = ([s for s in summary['skipped_safety']
                    if s['path'] == 'locked/secret-ish.bin']
                   + [f for f in summary['failed']
                      if f['path'] == 'locked/secret-ish.bin'])
        self.assertEqual(len(refused), 1)
        self.assertEqual([m['path'] for m in summary['moved']], ['fine.txt'])
        # unlock first: no stat survives under a mode-000 parent on POSIX
        os.chmod(str(self.ws / 'locked'), 0o700)
        self.assertTrue((self.ws / 'locked' / 'secret-ish.bin').is_file())
        self.assertEqual((self.ws / 'locked' / 'secret-ish.bin').read_bytes(),
                         b'no access')

    def test_read_only_parent_first_item_fails_second_still_moves(self):
        os.chmod(str(self.ws / 'locked'), 0o500)   # r-x: visible, not writable
        plan = crafted_plan(self.ws, ('locked/secret-ish.bin', 'trash'),
                            ('fine.txt', 'trash'))
        summary = safe_clean.execute(plan, self.ws, confirm=lambda p: 'YES')

        self.assertEqual([f['path'] for f in summary['failed']],
                         ['locked/secret-ish.bin'])
        self.assertIn('PermissionError', summary['failed'][0]['error'])
        self.assertEqual([m['path'] for m in summary['moved']], ['fine.txt'])

        data = json.loads((Path(summary['trash_dir']) / 'manifest.json')
                          .read_text(encoding='utf-8'))
        by_path = {e['original_path']: e for e in data['entries']}
        self.assertEqual(by_path['locked/secret-ish.bin']['status'], 'failed')
        self.assertEqual(by_path['fine.txt']['status'], 'moved')


class NeverReasonUnit(SafeCleanCase):
    """Direct unit coverage of the one-word NEVER reasons (the
    hard rules are enforced in code, so each gets a direct probe)."""

    def test_reasons(self):
        nr = safe_clean._never_reason
        abs_rel = os.path.join(os.sep, 'elsewhere') if os.name != 'nt' \
            else os.path.join('C:' + os.sep, 'elsewhere')
        self.assertEqual(nr(self.ws, abs_rel, 1, None), 'escape')
        self.assertEqual(nr(self.ws, os.path.join(os.pardir, 'x'), 1, None),
                         'escape')
        self.assertEqual(nr(self.ws, str(Path('repo') / '.git' / 'x'),
                            1, None), 'gitdir')
        self.assertEqual(nr(self.ws, str(Path(TRASH) / 'x'), 1, None),
                         'trash')
        self.assertEqual(nr(self.ws, '.env', 1, None), 'secret')
        self.assertEqual(nr(self.ws, 'settings.local.json', 1, None),
                         'secret')
        self.assertEqual(nr(self.ws, 'fine.bin', 1, None, tracked=True),
                         'tracked')
        self.assertEqual(nr(self.ws, 'fine.bin', 10, 4), 'oversized')
        self.assertIsNone(nr(self.ws, 'fine.bin', 4, 10, tracked=False))

    def test_symlink_reason(self):
        if not hasattr(os, 'symlink'):
            self.skipTest('os.symlink unavailable')
        try:
            os.symlink(str(self.base), str(self.ws / 'link'))
        except (OSError, NotImplementedError):
            self.skipTest('symlink creation unavailable on this system')
        self.assertEqual(safe_clean._never_reason(self.ws, 'link', 1, None),
                         'symlink')


class TrackedStatusInRepo(SafeCleanCase):
    """Duplicates inside a git repo exercise the cached git-ls-files
    tracked-status helper (the cautious duplicates tier)."""

    def test_duplicates_in_repo_split_by_tracked_status(self):
        blob = b'in-repo duplicate payload\n' * 64   # >= DUP_MIN_BYTES
        for name, days in ((Path('repo') / 'dup1.bin', 200),
                           (Path('repo') / 'dup2.bin', 100),
                           (Path('repo') / 'dup3.bin', 0)):
            f = self.ws / name
            f.write_bytes(blob)
            t = time.time() - days * 86400 if days else None
            os.utime(str(f), (t, t) if t else None)
        git(self.repo, 'add', 'dup2.bin')   # middle copy is tracked
        git(self.repo, 'commit', '-q', '-m', 'dup2')

        rep = audit_scan.scan(self.ws, self.home)
        plan = safe_clean.build_plan(rep, include_cautious=True)
        olds = {i['path'] for i in plan['items']
                if i['category'] == safe_clean.CAT_OLD_COPIES}
        in_repo = {p for p in olds if p.startswith('repo')}
        # dup1 (untracked, oldest) planned; dup2 skipped as tracked
        self.assertEqual(in_repo, {str(Path('repo') / 'dup1.bin')})
        reasons = {s['path']: s['reason'] for s in plan['skipped']}
        self.assertEqual(reasons.get(str(Path('repo') / 'dup2.bin')),
                         'tracked')

        # git failing entirely -> the duplicate is 'unsure', not planned
        with mock.patch.object(safe_clean.enrich, '_repo_tracked_files',
                               return_value=None):
            plan2 = safe_clean.build_plan(rep, include_cautious=True)
        reasons2 = {s['path']: s['reason'] for s in plan2['skipped']}
        self.assertEqual(reasons2.get(str(Path('repo') / 'dup1.bin')),
                         'unsure')


class PlanBranches(SafeCleanCase):
    """Hand-crafted scan reports hit the planner's guard branches."""

    def craft_rep(self, **kw):
        rep = {'root': str(self.ws)}
        rep.update(kw)
        return rep

    def test_junk_dir_branches(self):
        # a .git path is refused even for a safe build name; a missing
        # cautious name stays hidden without the flag; an in-repo
        # cautious dir with no classified tracked signal -> 'unsure'
        gitdir_rel = str(Path('repo') / '.git' / 'objects')
        old = time.time() - 120 * 86400
        os.utime(str(self.ws / gitdir_rel), (old, old))
        rep = self.craft_rep(junk={'dirs': [
            {'path': gitdir_rel, 'size_bytes': 10,
             'reason': 'build artifact (__pycache__)'},
            {'path': 'dist', 'size_bytes': 10,
             'reason': 'build artifact (dist)'},
            {'path': 'ghost', 'size_bytes': 10,
             'reason': 'build artifact (__pycache__)'},
        ]})
        plan = safe_clean.build_plan(rep)
        paths = self.paths(plan)
        self.assertNotIn(gitdir_rel, paths)
        self.assertNotIn('dist', paths)
        self.assertNotIn('ghost', paths)
        reasons = {s['path']: s['reason'] for s in plan['skipped']}
        self.assertEqual(reasons.get(gitdir_rel), 'gitdir')
        self.assertEqual(reasons.get('ghost'), 'unsure')  # no tracked signal

        in_repo_dist = self.ws / 'repo' / 'dist'
        in_repo_dist.mkdir()
        os.utime(str(in_repo_dist), (old, old))
        plan2 = safe_clean.build_plan(
            self.craft_rep(junk={'dirs': [
                {'path': str(Path('repo') / 'dist'), 'size_bytes': 10,
                 'reason': 'build artifact (dist)'}]}),
            include_cautious=True)
        reasons2 = {s['path']: s['reason'] for s in plan2['skipped']}
        self.assertEqual(reasons2.get(str(Path('repo') / 'dist')), 'unsure')

    def test_classified_secret_name_refused(self):
        rep = self.craft_rep(junk_classified=[{
            'path': 'pkg/settings.local.json', 'cls': 'confirmed_unused',
            'size_bytes': 10, 'reason': 'unused',
            'signals': {'tracked': False}}])
        plan = safe_clean.build_plan(rep)
        self.assertEqual(plan['items'], [])
        self.assertEqual(self.skipped_for(
            plan, 'settings.local.json')[0]['reason'], 'secret')

    def test_duplicate_group_degenerate_branches(self):
        rep = self.craft_rep(
            junk={'dirs': [{'path': 'node_modules', 'size_bytes': 1,
                            'reason': 'build artifact (node_modules)'}]},
            junk_classified=[{'path': 'node_modules',
                              'cls': 'confirmed_unused',
                              'signals': {'tracked': False},
                              'size_bytes': 1, 'reason': 'x'}],
            duplicates=[
                # node_modules already planned (seen), ghost missing:
                # nothing added from this group
                {'files': ['node_modules', 'ghost.bin'], 'size_bytes': 5},
                # a group over the cap -> the old copy is 'oversized'
                {'files': ['data_a.bin', 'data_b.bin'],
                 'size_bytes': 10 ** 12},
            ])
        plan = safe_clean.build_plan(rep, include_cautious=True)
        olds = [i['path'] for i in plan['items']
                if i['category'] == safe_clean.CAT_OLD_COPIES
                and i['path'].startswith('data_')]
        self.assertEqual(olds, [])
        reasons = {s['path']: s['reason'] for s in plan['skipped']}
        self.assertEqual(reasons.get('ghost.bin'), 'missing')
        self.assertEqual(reasons.get('data_a.bin'), 'oversized')


class ExecuteEdgeCases(SafeCleanCase):
    def test_item_removed_after_planning_skipped_missing(self):
        plan = safe_clean.build_plan(self.rep)
        (self.ws / 'temp_notes.txt').unlink()
        summary = safe_clean.execute(plan, self.ws, confirm=lambda p: 'YES')
        reasons = {s['path']: s['reason'] for s in summary['skipped_safety']}
        self.assertEqual(reasons.get('temp_notes.txt'), 'missing')
        self.assertIn('screenshot_1.png',
                      {m['path'] for m in summary['moved']})

    def test_unknown_action_fails_the_item_only(self):
        plan = crafted_plan(self.ws, ('screenshot_1.png', 'shred'))
        summary = safe_clean.execute(plan, self.ws, confirm=lambda p: 'YES')
        self.assertEqual(len(summary['failed']), 1)
        self.assertIn('unknown action', summary['failed'][0]['error'])
        self.assertTrue((self.ws / 'screenshot_1.png').is_file())

    def test_snapshotless_plan_size_recheck(self):
        # a hand-built plan declares a tiny size; the file is actually
        # over the plan's cap -> refused at execute time by the re-stat
        big = self.ws / 'grew.bin'
        big.write_bytes(b'x' * 100)
        plan = crafted_plan(self.ws, ('grew.bin', 'trash'), max_bytes=10)
        plan['items'][0]['size'] = 5    # the declared size stays under
        summary = safe_clean.execute(plan, self.ws, confirm=lambda p: 'YES')
        self.assertEqual(summary['skipped_safety'],
                         [{'path': 'grew.bin', 'reason': 'oversized'}])
        self.assertTrue(big.is_file())


class TextShapes(SafeCleanCase):
    """The plain-language screens and helpers."""

    def test_human_sizes(self):
        self.assertEqual(safe_clean._human(0), '0 B')
        self.assertEqual(safe_clean._human(2048), '2.0 KB')
        self.assertIn('TB', safe_clean._human(3 * 1024 ** 4))

    def test_preview_shows_cautious_section_only_with_flag(self):
        text = safe_clean.preview_text(
            safe_clean.build_plan(self.rep, include_cautious=True))
        self.assertIn('Optional extras', text)
        # a cautious-only plan: the safe section says '(nothing)'
        crafted = {'root': str(self.ws),
                   'max_bytes': safe_clean.DEFAULT_MAX_BYTES,
                   'items': [], 'skipped': [],
                   'categories': {safe_clean.CAT_BUILD_CAUTIOUS: {
                       'label': 'local state', 'count': 1,
                       'size_bytes': 5, 'cautious': True}}}
        self.assertIn('(nothing)', safe_clean.preview_text(crafted))

    def test_summary_text_declined_and_problem_lines(self):
        self.assertEqual(safe_clean.summary_text({'declined': True}),
                         'Nothing was changed.')
        text = safe_clean.summary_text({
            'declined': False, 'freed_bytes': 10,
            'freed_by_category': {}, 'removed_dirs': [],
            'moved': [], 'trash_dir': 'x', 'opid': 'ab12cd34',
            'manifest_path': 'x/manifest.json', 'root': 'r',
            'skipped_safety': [{'path': 'a', 'reason': 'escape'}],
            'failed': [{'path': 'b', 'error': 'e'}]})
        self.assertIn('Skipped as unsafe: 1', text)
        self.assertIn('Failed: 1', text)
        self.assertIn('Operation id: ab12cd34', text)

    def test_restore_text_branches(self):
        declined = safe_clean._restore_text({'declined': True})
        self.assertEqual(declined, 'Nothing was changed.')
        text = safe_clean._restore_text({
            'declined': False, 'run_dir': 'rd', 'opid': 'ab12cd34',
            'manifest_path': 'rd/manifest.json',
            'restored': [{'original_path': 'a.txt',
                          'restored_to': 'a.txt.restored-1'}],
            'not_restorable': 2, 'already_done': 1,
            'failed': [{'original_path': 'c', 'error': 'x'}]})
        self.assertIn('a.txt -> a.txt.restored-1', text)
        self.assertIn('(original spot was occupied)', text)
        self.assertIn('2 item(s) were removed empty folders', text)
        self.assertIn('1 item(s) were already restored', text)
        self.assertIn('Failed: 1', text)


class CliExtras(SafeCleanCase):
    def run_main(self, *args):
        out, err = StringIO(), StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = safe_clean.main([str(a) for a in args])
        return rc, out.getvalue(), err.getvalue()

    def test_trash_root_refused_with_three(self):
        (self.ws / TRASH).mkdir()
        rc, _, err = self.run_main(self.ws / TRASH, '--home', self.home)
        self.assertEqual(rc, 3)
        self.assertIn('trash folder', err)

    def test_interactive_decline_in_process(self):
        with mock.patch('builtins.input', return_value='no'):
            rc, out, _ = self.run_main(self.ws, '--home', self.home)
        self.assertEqual(rc, 0)
        self.assertIn('Nothing was changed.', out)
        self.assertTrue((self.ws / 'node_modules').is_dir())

    def test_eof_on_prompt_declines(self):
        with mock.patch('builtins.input', side_effect=EOFError):
            rc, out, _ = self.run_main(self.ws, '--home', self.home)
        self.assertEqual(rc, 0)
        self.assertIn('Nothing was changed.', out)

    def test_failed_item_reported_on_stderr(self):
        real_move = shutil.move
        calls = []

        def move_spy(src, dst):
            calls.append(Path(src).name)
            if Path(src).name == 'screenshot_1.png':
                raise OSError('boom during move')
            return real_move(src, dst)

        with mock.patch('shutil.move', side_effect=move_spy):
            rc, out, err = self.run_main(self.ws, '--home', self.home, '--yes')
        self.assertEqual(rc, 0)
        self.assertIn('failed on screenshot_1.png', err)
        self.assertTrue((self.ws / 'screenshot_1.png').is_file())
        self.assertIn('Failed: 1', out)

    def test_nothing_to_clean_mentions_kept_out(self):
        quiet = self.base / 'quiet'
        quiet.mkdir()
        big = quiet / 'old-huge.bin'
        with big.open('wb') as fh:
            fh.write(b'x')
        os.truncate(str(big), BIG_BYTES)
        os.utime(str(big), (OLD, OLD))
        rc, out, _ = self.run_main(quiet, '--home', self.home, '--yes')
        self.assertEqual(rc, 1)
        self.assertIn('Nothing safe to clean', out)
        self.assertIn('Kept out of the plan', out)


if __name__ == '__main__':
    unittest.main()
