"""Coverage tests for skills/agents-doctor/scripts/audit_scan.py.

Targets the branches the main suite leaves uncovered: OSError guards in
the walk and helpers, repo_extra plumbing (hooks, upstream, nested
repos, remote classification), context/skills/memory checks, the
duplicate hashing stages, and main()'s baseline, profile and exit
paths.

Filesystem states this Windows host cannot produce honestly (symlinks
need a privilege, per-file read denial is not available to the owner)
are simulated with narrow wrappers around pathlib methods: each wrapper
delegates to the real implementation for every name except the one
under test, so only the guard being tested sees the error. git runs
only inside throwaway fixture directories, with GIT_OPTIONAL_LOCKS=0
and a per-command fixture identity.

The scanner-behaviour classes at the end (what the scan records about
the audited folder, about repositories, skills, keys and duplicates)
run on the temp-folder bases of tests/integration/fixtures.py.
"""
import errno
import json
import os
import pathlib
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

SCRIPTS = Path(__file__).resolve().parents[1] / 'skills' / 'agents-doctor' / 'scripts'
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(Path(__file__).resolve().parent / 'integration'))

import audit_scan  # noqa: E402
import gates  # noqa: E402
import report_human  # noqa: E402
import summary  # noqa: E402
from fixtures import FAKE_KEY, GitCase, TmpCase, commit_git  # noqa: E402
# report lookups, under the names the scanner tests were written with
from fixtures import by_check as _by_check, gate_of as _gate  # noqa: E402
from fixtures import evidence_values as _paths  # noqa: E402
from fixtures import mcp_with_key as _mcp_with_key  # noqa: E402
from fixtures import rule_of as _rule  # noqa: E402


def sim_error(message):
    """An OSError pathlib itself tolerates: is_dir()/exists() swallow
    ENOENT, so the simulated failure reaches only the guards that
    catch OSError explicitly."""
    return FileNotFoundError(errno.ENOENT, message)


class ScandirList:
    """A scandir() result built in memory: a one-pass iterator that is
    also a context manager, like the real ScandirIterator os.walk and
    audit_scan both consume."""

    def __init__(self, entries):
        self._iter = iter(entries)

    def __iter__(self):
        return self

    def __next__(self):
        return next(self._iter)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

DEMO_SECRET_LINE = 'password = "DEMO-cov-secret-000000001"'

REPO_A_AGENTS = """# Repo A rules
Keep commits small.
See [background](./missing.md) for history.
The layout is described in `docs/guide.md`.
Run `npm run build` after checkout.
Run `make test` before push.
Use `docker` locally.
Never force-push the main branch.
"""
REPO_A_CLAUDE = """# Repo A claude notes
Always ask before deleting files.
Prefer tiny pull requests.
Update CHANGELOG every release.
Respect the lockfile.
"""
SKILL_ALPHA_1 = ('---\nname: alpha\ndescription: use when testing coverage\n---\n'
                 '# alpha\nbody one\n')
SKILL_ALPHA_2 = ('---\nname: alpha\ndescription: use when asked to test differently\n---\n'
                 '# alpha\nbody two\n')
SKILL_PLUG = ('---\nname: plug\ndescription: use when testing plugins\n---\n'
              '# plug\nbody\n')
SKILL_BETA = '---\nname: beta\ndescription: use when testing project skills\n---\n# beta\n'
SKILL_GAMMA = '---\nname: gamma\ndescription: use when testing claude skills\n---\n# gamma\n'


def force_rmtree(path):
    """rmtree that clears git's read-only flag and tolerates a gone path."""
    def _clear(func, target, _exc):
        try:
            os.chmod(target, stat.S_IWRITE)
            func(target)
        except OSError:
            pass
    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=_clear)
    else:
        shutil.rmtree(path, onerror=lambda f, p, e: _clear(f, p, e))


def git_run(repo, *args):
    """git inside a temp fixture; read-only index, fixture identity."""
    env = dict(os.environ, GIT_OPTIONAL_LOCKS='0')
    return subprocess.run(
        ['git', '-C', str(repo),
         '-c', 'user.name=Cov Fixture',
         '-c', 'user.email=cov-fixture@example.com', *args],
        capture_output=True, text=True, encoding='utf-8', errors='replace',
        env=env)


def fake_entry(name, path, *, is_dir_val=False, is_file_val=False,
               stat_result=None):
    """A stand-in DirEntry for branches real directory entries cannot
    reach on this host (an outside-root reparse target, an entry whose
    stat raises, an entry that vanishes mid-walk)."""
    e = mock.Mock()
    e.name = name
    e.path = path
    e.is_symlink.return_value = False
    e.is_dir.side_effect = lambda *a, **k: is_dir_val
    e.is_file.side_effect = lambda *a, **k: is_file_val
    if isinstance(stat_result, Exception):
        e.stat.side_effect = stat_result
    else:
        e.stat.return_value = stat_result
    return e


class AuditScanCase(unittest.TestCase):
    """Temp base + isolated fingerprint key, like the history tests."""

    def setUp(self):
        self.base = Path(tempfile.mkdtemp(prefix='wsa-cov-'))
        self.addCleanup(force_rmtree, self.base)
        os.environ['AGENTS_DOCTOR_KEY_PATH'] = str(self.base / 'fp_key')
        self.addCleanup(os.environ.pop, 'AGENTS_DOCTOR_KEY_PATH', None)


# --- small pure helpers ---------------------------------------------------------

class ExistsHelper(AuditScanCase):
    def test_exists_returns_false_when_stat_raises_permission_error(self):
        p = mock.Mock()
        p.exists.side_effect = PermissionError('denied')
        self.assertFalse(audit_scan._exists(p))

    def test_exists_passes_through_for_real_paths(self):
        self.assertTrue(audit_scan._exists(self.base))
        self.assertFalse(audit_scan._exists(self.base / 'nope'))


# --- one rich workspace, scanned once, asserted from several tests --------------

class RichWorkspaceScan(AuditScanCase):
    """A workspace that exercises repo_extra, context checks, skills,
    memory, drift and the duplicate hashing stages in one scan."""

    @classmethod
    def setUpClass(cls):
        cls.base = Path(tempfile.mkdtemp(prefix='wsa-cov-rich-'))
        cls.addClassCleanup(force_rmtree, cls.base)
        os.environ['AGENTS_DOCTOR_KEY_PATH'] = str(cls.base / 'fp_key')
        cls.addClassCleanup(os.environ.pop, 'AGENTS_DOCTOR_KEY_PATH', None)
        cls.ws, cls.home = cls._build(cls.base)
        cls.rep = audit_scan.scan(cls.ws, cls.home)

    @staticmethod
    def _build(base):
        ws, home = base / 'ws', base / 'home'
        ws.mkdir()
        home.mkdir()
        # root pair linked by an @AGENTS.md import: no drift expected
        (ws / 'AGENTS.md').write_text('# Root rules\nOne line.\nAnother line.\n')
        (ws / 'CLAUDE.md').write_text('@AGENTS.md\n')
        (ws / 'sub').mkdir()
        (ws / 'sub' / 'AGENTS.md').write_text('# nested\n')

        # repoA: real git repo, github remote, real hook, nested inner repo
        repo_a = ws / 'repoA'
        repo_a.mkdir()
        (repo_a / 'AGENTS.md').write_text(REPO_A_AGENTS)
        (repo_a / 'CLAUDE.md').write_text(REPO_A_CLAUDE)
        (repo_a / 'package.json').write_text('{"scripts": {"start": "echo hi"}}')
        (repo_a / 'inner' / '.git').mkdir(parents=True)
        assert git_run(repo_a, 'init', '-q').returncode == 0
        git_run(repo_a, 'add', 'AGENTS.md', 'CLAUDE.md', 'package.json')
        assert git_run(repo_a, 'commit', '-q', '-m', 'init').returncode == 0
        git_run(repo_a, 'remote', 'add', 'origin',
                'https://github.com/octocat/hello.git')
        (repo_a / '.git' / 'hooks' / 'pre-commit').write_text(
            '#!/bin/sh\ngit add -A\ngit push\nsecret scan\n')

        # seed -> repoB: a clone has an upstream, so ahead/behind parses;
        # eleven nested .git dirs hit the nested_repos cap of 10
        seed = base / 'seed'
        seed.mkdir()
        (seed / 'seed.txt').write_text('seed\n')
        assert git_run(seed, 'init', '-q').returncode == 0
        git_run(seed, 'add', 'seed.txt')
        assert git_run(seed, 'commit', '-q', '-m', 'seed').returncode == 0
        repo_b = ws / 'repoB'
        env = dict(os.environ, GIT_OPTIONAL_LOCKS='0')
        subprocess.run(['git', 'clone', '-q', str(seed), str(repo_b)],
                       check=True, capture_output=True, env=env)
        (repo_b / 'AGENTS.md').write_text(
            '# Repo B rules\nRun npm run start when setup is done.\n')
        (repo_b / 'package.json').write_text('{ nope: broken json')
        for i in range(1, 12):
            (repo_b / ('sub%d' % i) / '.git').mkdir(parents=True)

        # duplicate-size groups: identical 5000-byte pairs (one text, one
        # binary, different content so they stay two groups) and one
        # same-size different-content pair
        dup = ws / 'dup'
        dup.mkdir()
        (dup / 'a.bin').write_text('x' * 5000)
        (dup / 'b.bin').write_text('x' * 5000)
        (dup / 'c.txt').write_text('y' * 5000)
        (dup / 'd.txt').write_text('y' * 5000)
        (dup / 'e1.txt').write_text('a' * 1500)
        (dup / 'e2.txt').write_text('b' * 1500)

        # junk dir subtree accounting
        junk = ws / 'backup_junk'
        junk.mkdir()
        (junk / 'notes.txt').write_text('x' * 100)
        (junk / 'old.zip').write_text('x' * 50)

        # home: harness marker, oversized memory index, diverged skill
        # copies, plugin cache with a SKILL.md that is a directory
        (home / '.zcode' / 'cli' / 'memories').mkdir(parents=True)
        (home / '.zcode' / 'AGENTS.md').write_text('# user rules\n')
        (home / '.zcode' / 'cli' / 'history.jsonl').write_text('{}\n')
        (home / '.zcode' / 'cli' / 'memories' / 'MEMORY.md').write_text(
            'note\n' * 250)
        (home / '.zcode' / 'skills' / 'alpha').mkdir(parents=True)
        (home / '.zcode' / 'skills' / 'alpha' / 'SKILL.md').write_text(SKILL_ALPHA_1)
        (home / '.claude' / 'skills' / 'alpha').mkdir(parents=True)
        (home / '.claude' / 'skills' / 'alpha' / 'SKILL.md').write_text(SKILL_ALPHA_2)
        plug = home / '.zcode' / 'cli' / 'plugins' / 'cache' / 'pkgA' / 'v1'
        plug.mkdir(parents=True)
        (plug / 'SKILL.md').write_text(SKILL_PLUG)
        (home / '.zcode' / 'cli' / 'plugins' / 'cache' / 'pkgB' / 'dirskill'
         / 'SKILL.md').mkdir(parents=True)
        (ws / '.agents' / 'skills' / 'beta').mkdir(parents=True)
        (ws / '.agents' / 'skills' / 'beta' / 'SKILL.md').write_text(SKILL_BETA)
        (ws / '.claude' / 'skills' / 'gamma').mkdir(parents=True)
        (ws / '.claude' / 'skills' / 'gamma' / 'SKILL.md').write_text(SKILL_GAMMA)
        return ws, home

    def top(self, name):
        return next(t for t in self.rep['top_level'] if t['name'] == name)

    def ctx(self, suffix):
        return next(e for e in self.rep['context_files']
                    if e['path'].replace('\\', '/').startswith(suffix))

    def test_repo_extra_hooks_upstream_and_nested_repos(self):
        a = self.top('repoA')
        self.assertEqual(a['kind'], 'repo')
        self.assertEqual(a['git']['remote'], 'https://github.com/octocat/hello.git')
        self.assertEqual(a['extra']['remote_class'], 'external hosting')
        self.assertFalse(a['extra']['credentials_in_remote'])
        self.assertEqual(a['extra']['hooks'],
                         [{'name': 'pre-commit',
                           'flags': {'add_all': True, 'push': True,
                                     'secret_scan': True}}])
        self.assertEqual(a['extra']['nested_repos'], ['inner'])
        self.assertTrue(a['extra']['branch'])

        b = self.top('repoB')
        self.assertEqual(b['extra']['ahead_behind'],
                         {'ahead': 0, 'behind': 0})
        self.assertEqual(len(b['extra']['nested_repos']), 10)  # capped

    def test_context_checks_dead_refs_and_drift(self):
        a = self.ctx('repoA/AGENTS.md')
        self.assertEqual(a['dead_links'], ['./missing.md'])
        self.assertEqual(a['dead_paths'], ['docs/guide.md'])
        self.assertEqual(set(a['dead_commands']),
                         {'npm run build', 'make test'})
        # broken package.json reads as {} -> npm run start is dead
        b = self.ctx('repoB/AGENTS.md')
        self.assertEqual(b['dead_commands'], ['npm run start'])
        # repoA AGENTS/CLAUDE pair diverges; root pair is linked -> no drift
        self.assertEqual([d['path'] for d in self.rep['context_drift']],
                         ['repoA'])
        self.assertLess(self.rep['context_drift'][0]['jaccard'], 0.5)
        self.assertTrue(any(f['section'] == 'context_drift'
                            for f in self.rep['findings']))

    def test_duplicates_full_hash_stages(self):
        groups = {frozenset(p.replace(os.sep, '/') for p in g['files'])
                  for g in self.rep['duplicates']}
        self.assertIn(frozenset(['dup/a.bin', 'dup/b.bin']), groups)
        self.assertIn(frozenset(['dup/c.txt', 'dup/d.txt']), groups)
        self.assertNotIn(frozenset(['dup/e1.txt', 'dup/e2.txt']), groups)

    def test_junk_dir_subtree_accounting(self):
        dirs = {d['path']: d for d in self.rep['junk']['dirs']}
        self.assertIn('backup_junk', dirs)
        self.assertEqual(dirs['backup_junk']['files'], 2)
        self.assertEqual(dirs['backup_junk']['size_bytes'], 150)

    def test_skills_locations_and_diverged_copies(self):
        locs = {e['location'] for e in self.rep['skills']['entries']}
        self.assertEqual(locs, {'user-zcode', 'user-claude', 'project-agents',
                                'project-claude', 'plugins-cache'})
        self.assertTrue(self.rep['skills']['locations_checked'])
        dups = self.rep['skills']['duplicates']
        self.assertEqual(len(dups), 1)
        self.assertEqual((dups[0]['name'], dups[0]['copies'],
                          dups[0]['sync']), ('alpha', 2, 'DIVERGED'))
        self.assertEqual(
            {str(Path(p).resolve()) for p in dups[0]['paths']},
            {str(Path(self.home / '.zcode' / 'skills' / 'alpha'
                                / 'SKILL.md').resolve()),
             str(Path(self.home / '.claude' / 'skills' / 'alpha'
                                / 'SKILL.md').resolve())})
        self.assertTrue(any(f['section'] == 'skills'
                            for f in self.rep['findings']))

    def test_memory_index_over_line_limit(self):
        mem = str(self.home / '.zcode' / 'cli' / 'memories' / 'MEMORY.md')
        tax = self.rep['context_tax']
        self.assertIn(str(Path(mem).resolve()),
                     [f['path'] for f in tax['session_files']
                      if f['role'] == 'memory-index'])
        self.assertEqual(tax['memory_over_lines'],
                         [str(Path(mem).resolve())])
        self.assertEqual(tax['memory_over_limit'], [])  # 250 short lines

    def test_chain_budget_counts_nested_agents_md(self):
        root_agents = (self.ws / 'AGENTS.md').stat().st_size
        expected = root_agents + sum(
            (self.ws / p / 'AGENTS.md').stat().st_size
            for p in ('sub', 'repoA', 'repoB'))
        dot = next(c for c in self.rep['context_budget'] if c['root'] == '.')
        self.assertEqual(dot['total_bytes'], expected)

    def test_harness_marker_mtimes(self):
        zcode = next(t for t in self.rep['harness']['tools']
                     if t['tool'] == 'zcode')
        self.assertTrue(zcode['exists'])
        self.assertEqual(zcode['state'], 'active')  # marker is fresh


# --- filesystem error guards (narrow pathlib/os wrappers) -----------------------

class FsErrorGuards(AuditScanCase):
    """One scan under simulated I/O failures: every guard that catches
    OSError runs, the scan still returns a report."""

    def test_scan_survives_simulated_fs_errors(self):
        ws, home = self.base / 'ws', self.base / 'home'
        repo = ws / 'repoA'
        (repo / '.git' / 'hooks').mkdir(parents=True)  # a plain .git dir is enough
        (repo / '.git' / 'hooks' / 'pre-push').write_text('#!/bin/sh\ngit push\n')
        (repo / 'AGENTS.md').write_text('# repo\n')
        (repo / 'package.json').write_text('{"scripts": {}}')
        dup = ws / 'dup'
        dup.mkdir()
        (dup / 'p.txt').write_text('z' * 1200)
        (dup / 'q.txt').write_text('z' * 1200)
        # big enough to be duplicate candidates (>= 1 KB), so the failed
        # open of locked.env surfaces in the duplicate head stage too
        env_blob = DEMO_SECRET_LINE + '\n' + '#' * 1200 + '\n'
        (dup / 'locked.env').write_text(env_blob)
        (dup / 'open.env').write_text(env_blob)
        junk = ws / 'backup_junk'
        junk.mkdir()
        (junk / 'plain.txt').write_text('x' * 40)
        (junk / 'statfail.bin').write_text('y' * 40)
        (junk / 'link.bin').write_text('y' * 40)
        (ws / 'statfail_top.bin').write_text('y' * 40)
        (ws / 'denied_dir').mkdir()
        (ws / 'mockdir').mkdir()
        (home / '.zcode').mkdir(parents=True)

        fakes = [
            # an existing directory outside the root, spelled with the
            # wrong case: realpath() folds the case back, the boundary
            # check sees an outside target and skips the entry
            fake_entry('outside_link.txt', str(self.base).upper()),
            fake_entry('ghost.bin', str(ws / 'mockdir' / 'ghost.bin'),
                       is_file_val=True, stat_result=OSError('gone')),
            fake_entry('vanish.bin', str(ws / 'mockdir' / 'vanish.bin')),
        ]
        fakes[2].is_dir.side_effect = OSError('entry vanished')

        real_scandir = os.scandir
        # scan() resolves root/home on entry: intercept the resolved forms
        denied = {(ws / 'denied_dir').resolve(), (home / '.zcode').resolve()}

        def scandir_wrap(path=None):
            p = Path(path)
            if p in denied:
                raise OSError('simulated scandir denial')
            it = real_scandir(path)
            if p.name == 'mockdir':
                return ScandirList(list(it) + fakes)
            return it

        real_stat = pathlib.Path.stat

        def stat_wrap(self, *a, **k):
            if self.name.startswith('statfail'):
                raise sim_error('simulated stat failure')
            return real_stat(self, *a, **k)

        real_read_text = pathlib.Path.read_text

        def read_text_wrap(self, *a, **k):
            if self.name in ('package.json', 'pre-push'):
                raise OSError('simulated read failure')
            return real_read_text(self, *a, **k)

        real_open = pathlib.Path.open

        def open_wrap(self, *a, **k):
            if self.name == 'locked.env':
                raise OSError('simulated open failure')
            return real_open(self, *a, **k)

        real_read_bytes = pathlib.Path.read_bytes

        def read_bytes_wrap(self, *a, **k):
            if self.name == 'q.txt':
                raise OSError('simulated read_bytes failure')
            return real_read_bytes(self, *a, **k)

        real_is_symlink = pathlib.Path.is_symlink

        def is_symlink_wrap(self, *a, **k):
            if self.name == 'link.bin':  # the subtree() skip branch
                return True
            return real_is_symlink(self, *a, **k)

        with mock.patch.object(os, 'scandir', scandir_wrap), \
                mock.patch.object(pathlib.Path, 'stat', stat_wrap), \
                mock.patch.object(pathlib.Path, 'read_text', read_text_wrap), \
                mock.patch.object(pathlib.Path, 'open', open_wrap), \
                mock.patch.object(pathlib.Path, 'read_bytes', read_bytes_wrap), \
                mock.patch.object(pathlib.Path, 'is_symlink', is_symlink_wrap):
            rep = audit_scan.scan(ws, home)

        # the outside link is skipped and named; the entry that raised
        # mid-stat and the ghost stat are dropped silently
        self.assertEqual(rep['stats']['skipped_symlinks_outside'], 1)
        self.assertEqual(rep['stats']['skipped_symlink_names'],
                         ['outside_link.txt'])
        # unreadable top-level file keeps its place with metadata only
        top = next(t for t in rep['top_level'] if t['name'] == 'statfail_top.bin')
        self.assertEqual((top['kind'], top['size_bytes']), ('file', 0))
        # the .env pair is broken by the open failure. The p/q pair is
        # settled by the single shared read: a short file is read in full
        # the first time, so the simulated read_bytes failure never fires
        self.assertEqual(rep['duplicates'], [
            {'size_bytes': 1200,
             'files': ['dup%sp.txt' % os.sep, 'dup%sq.txt' % os.sep]}])
        # locked.env is never read; open.env still reports its secret
        self.assertEqual([s['path'] for s in rep['secrets']],
                         ['dup%sopen.env' % os.sep])
        # junk subtree: link skipped, stat failure skipped, one file left
        dirs = {d['path']: d for d in rep['junk']['dirs']}
        self.assertEqual(dirs['backup_junk']['files'], 1)
        self.assertEqual(dirs['backup_junk']['size_bytes'], 40)
        # directories whose scandir failed or that hold fake entries are
        # never reported empty
        self.assertNotIn('denied_dir', rep['junk']['empty_dirs'])
        self.assertNotIn('mockdir', rep['junk']['empty_dirs'])
        # the unreadable hook was skipped, the harness survived scandir
        repo_top = next(t for t in rep['top_level'] if t['name'] == 'repoA')
        self.assertEqual(repo_top['extra']['hooks'], [])
        zcode = next(t for t in rep['harness']['tools'] if t['tool'] == 'zcode')
        self.assertTrue(zcode['exists'])


# --- enrichment OSError guards ---------------------------------------------------

class EnrichErrorGuards(AuditScanCase):
    def test_scan_survives_enrich_failures(self):
        ws, home = self.base / 'ws', self.base / 'home'
        repo = ws / 'repoC'
        repo.mkdir(parents=True)
        (repo / '.git').mkdir()
        (repo / 'a.txt').write_text('a\n')
        home.mkdir()
        patches = [
            mock.patch.object(audit_scan.enrich, 'harness_states',
                              side_effect=OSError('h1')),
            mock.patch.object(audit_scan.enrich, 'config_integrity',
                              side_effect=OSError('h2')),
            mock.patch.object(audit_scan.enrich, 'heavy_outside_git',
                              side_effect=OSError('h3')),
            mock.patch.object(audit_scan.enrich, 'classify_junk',
                              side_effect=OSError('h4')),
            mock.patch.object(audit_scan.enrich, 'skills_frontmatter',
                              side_effect=OSError('h5')),
        ]
        with patches[0], patches[1], patches[2], patches[3], patches[4]:
            rep = audit_scan.scan(ws, home)
        self.assertEqual(rep['config_integrity'], [])
        self.assertEqual(rep['heavy_outside_git'], [])
        self.assertEqual(rep['junk_classified'], [])
        self.assertEqual(rep['skills_extra'], {})
        self.assertTrue(rep['gates'])  # the scan still produced a report


# --- secret line dedup -----------------------------------------------------------

class SecretDedup(AuditScanCase):
    def test_second_hit_on_the_same_line_is_dropped(self):
        ws, home = self.base / 'ws', self.base / 'home'
        ws.mkdir(parents=True)
        (ws / '.env').write_text(DEMO_SECRET_LINE + '\n')
        two_hits = [
            {'line': 1, 'kind': 'password', 'mask': 'm1',
             'fingerprint': 'f1', 'confidence': 0.9},
            {'line': 1, 'kind': 'token', 'mask': 'm2',
             'fingerprint': 'f2', 'confidence': 0.4},
        ]
        with mock.patch.object(audit_scan.secscan, 'scan_text',
                               return_value=two_hits):
            rep = audit_scan.scan(ws, home)
        self.assertEqual(len(rep['secrets']), 1)
        self.assertEqual(rep['secrets'][0]['kind'], 'password')


# --- git_info porcelain guard ----------------------------------------------------

class GitInfoBlankLines(AuditScanCase):
    def test_git_info_skips_blank_porcelain_lines(self):
        repo = self.base / 'repo'
        repo.mkdir()
        (repo / 'tracked.txt').write_text('t\n')
        assert git_run(repo, 'init', '-q').returncode == 0
        git_run(repo, 'add', 'tracked.txt')
        assert git_run(repo, 'commit', '-q', '-m', 'c1').returncode == 0
        (repo / 'u.txt').write_text('u\n')
        real = audit_scan.run_git

        def with_blank_lines(p, *args):
            rc, out = real(p, *args)
            if args and args[0] == 'status':
                out = out + '\n \n'
            return rc, out

        with mock.patch.object(audit_scan, 'run_git', with_blank_lines):
            info = audit_scan.git_info(repo)
        self.assertEqual(info['untracked'], ['u.txt'])
        self.assertEqual(info['dirty'], [])


# --- history flag plumbing -------------------------------------------------------

class HistoryPlumbing(AuditScanCase):
    def test_history_depth_and_all_refs_reach_repo_extra(self):
        ws, home = self.base / 'ws', self.base / 'home'
        home.mkdir()
        repo = ws / 'hrepo'
        repo.mkdir(parents=True)
        (repo / 'a.txt').write_text('a\n')
        assert git_run(repo, 'init', '-q').returncode == 0
        git_run(repo, 'add', 'a.txt')
        assert git_run(repo, 'commit', '-q', '-m', 'c1').returncode == 0
        (repo / 'b.txt').write_text('b\n')
        git_run(repo, 'add', 'b.txt')
        assert git_run(repo, 'commit', '-q', '-m', 'c2').returncode == 0
        rep = audit_scan.scan(ws, home, deep=True, history_depth=1,
                              history_all_refs=True)
        ex = next(t for t in rep['top_level']
                  if t['name'] == 'hrepo')['extra']
        self.assertIn('history_secrets', ex)
        cov = ex['history_coverage']
        self.assertEqual(cov['max_commits'], 1)
        self.assertEqual(cov['commits_scanned'], 1)
        self.assertEqual(cov['commits_total'], 2)
        self.assertTrue(cov['all_refs'])
        self.assertFalse(cov['complete'])


# --- main() ------------------------------------------------------------------------

class MainCli(AuditScanCase):
    def run_main(self, argv):
        out, err = StringIO(), StringIO()
        with redirect_stdout(out), redirect_stderr(err), \
                mock.patch.object(sys, 'argv', ['audit_scan.py'] + argv):
            code = audit_scan.main()
        return code, out.getvalue(), err.getvalue()

    def tiny_workspace(self):
        ws, home = self.base / 'ws', self.base / 'home'
        ws.mkdir()
        home.mkdir()
        (ws / 'readme.txt').write_text('r\n')
        (ws / 'temp_notes.txt').write_text('t\n')  # junk file -> one finding
        return ws, home

    def test_main_exits_on_not_a_directory(self):
        with self.assertRaises(SystemExit) as cx:
            self.run_main([str(self.base / 'nope'), '--home', str(self.base)])
        self.assertTrue(str(cx.exception).startswith('not a directory'))

    def test_main_exits_on_fingerprint_key_error(self):
        ws, home = self.tiny_workspace()
        (ws / '.env').write_text(DEMO_SECRET_LINE + '\n')
        Path(os.environ['AGENTS_DOCTOR_KEY_PATH']).write_bytes(b'short')
        out_json = self.base / 'scan.json'
        with self.assertRaises(SystemExit) as cx:
            self.run_main([str(ws), '--home', str(home), '--out', str(out_json)])
        self.assertIn('fingerprint key unavailable', str(cx.exception))
        self.assertIn('fingerprint.py --check', str(cx.exception))

    def test_main_baseline_profile_and_summary(self):
        ws, home = self.tiny_workspace()
        out_json = self.base / 'scan.json'
        self.run_main([str(ws), '--home', str(home), '--out', str(out_json)])
        rep = json.loads(out_json.read_text(encoding='utf-8'))
        kept_fp = rep['findings'][0]['fp']
        old = {'findings': [{'fp': kept_fp, 'section': 'x', 'path': 'y'},
                            {'fp': 'gone-fp', 'section': 'x', 'path': 'z'}]}
        old_json = self.base / 'old.json'
        old_json.write_text(json.dumps(old), encoding='utf-8')

        code, out, err = self.run_main(
            [str(ws), '--home', str(home), '--out', str(out_json),
             '--baseline', str(old_json), '--profile'])
        self.assertIsNone(code)
        rep2 = json.loads(out_json.read_text(encoding='utf-8'))
        self.assertEqual([f['fp'] for f in rep2['diff']['resolved']],
                         ['gone-fp'])
        self.assertNotIn(kept_fp, [f['fp'] for f in rep2['diff']['new']])
        self.assertIn('baseline: ', out)
        self.assertIn('1 resolved', out)
        self.assertTrue(err.startswith('profile '), err)  # per-stage timings
        self.assertTrue(out.startswith('scan: '))  # the summary tally

    def test_main_with_corrupt_baseline_skips_diff(self):
        ws, home = self.tiny_workspace()
        out_json = self.base / 'scan.json'
        bad = self.base / 'bad.json'
        bad.write_text('{ nope', encoding='utf-8')
        _code, out, _err = self.run_main(
            [str(ws), '--home', str(home), '--out', str(out_json),
             '--baseline', str(bad)])
        rep = json.loads(out_json.read_text(encoding='utf-8'))
        self.assertNotIn('diff', rep)
        self.assertNotIn('baseline:', out)

    def test_main_reports_skipped_symlinks(self):
        ws, home = self.tiny_workspace()
        (ws / 'mockdir').mkdir()
        fakes = [fake_entry('outside_link.txt', str(self.base).upper())]
        real_scandir = os.scandir

        def scandir_wrap(path=None):
            it = real_scandir(path)
            if Path(path).name == 'mockdir':
                return ScandirList(list(it) + fakes)
            return it

        out_json = self.base / 'scan.json'
        with mock.patch.object(os, 'scandir', scandir_wrap):
            _code, out, err = self.run_main(
                [str(ws), '--home', str(home), '--out', str(out_json),
                 '--profile'])
        self.assertIn('skipped symlinks pointing outside the root: 1', out)
        self.assertIn("profile symlink/outside skips: 1 ['outside_link.txt']",
                      err)


# --- what the scan records about skills folders ---------------------------------

class SkillsFolderCoverageTests(TmpCase):
    """The skill search records what it covered: a folder cut by the
    per-folder cap is reported, a normal scan records the folders read."""

    def test_truncated_folder_reports_an_incomplete_check(self):
        for i in range(3):
            self.put(self.home, '.zcode/cli/plugins/cache/p%d/v1/s/SKILL.md' % i,
                     '---\nname: s%d\ndescription: "Use when asked"\n---\n' % i)
        with mock.patch.object(audit_scan, 'SKILLS_FOLDER_CAP', 2):
            rep = audit_scan.scan(self.root, self.home, False)
        self.assertEqual(len(rep['skills']['entries']), 2)
        self.assertEqual(rep['skills']['coverage']['truncated'],
                         [{'location': 'plugins-cache', 'scanned': 2,
                           'found': 3, 'cap': 2}])
        hits = _by_check(rep, 'SKL_CHECK_INCOMPLETE')
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]['status'], 'unknown')
        self.assertEqual(_gate(rep, 'G5')['status'], 'unknown')

    def test_folder_cap_is_far_above_the_old_200(self):
        # 200 silently dropped the tail of a real plugin cache
        self.assertGreaterEqual(audit_scan.SKILLS_FOLDER_CAP, 1000)

    def test_coverage_is_recorded_on_a_normal_scan(self):
        self.put(self.root, '.agents/skills/ok/SKILL.md',
                 '---\nname: ok\ndescription: "Use when asked"\n---\n')
        rep = audit_scan.scan(self.root, self.home, False)
        cov = rep['skills']['coverage']
        self.assertEqual(cov['checked'], ['project-agents'])
        self.assertEqual((cov['failed'], cov['truncated']), ([], []))


# --- repositories found by the walk ---------------------------------------------

class GitRootsRecordingTests(TmpCase):

    def test_scan_lists_every_repository_folder(self):
        for rel in ('projects/a', 'projects/b', 'projects/a/vendor/lib'):
            (self.root / rel / '.git').mkdir(parents=True)
            (self.root / rel / '.git' / 'HEAD').write_text('ref: refs/heads/main',
                                                           encoding='utf-8')
        # a .git file marks a repository too
        self.put(self.root, 'projects/wt/.git', 'gitdir: ../a/.git/worktrees/wt')
        (self.root / 'projects' / 'plain').mkdir()
        rep = audit_scan.scan(self.root, self.home, False)
        sep = '\\' if sys.platform == 'win32' else '/'
        self.assertEqual(rep['git_roots'], sorted([
            sep.join(('projects', 'a')), sep.join(('projects', 'b')),
            sep.join(('projects', 'wt')),
            sep.join(('projects', 'a', 'vendor', 'lib'))]))

    def test_no_repository_gives_an_empty_list(self):
        rep = audit_scan.scan(self.root, self.home, False)
        self.assertEqual(rep['git_roots'], [])


# --- dedup: read once ----------------------------------------------------------

class DedupReadOnceTests(TmpCase):

    def _pair(self, rel_a, rel_b, size, name_a='a.bin', name_b='b.bin'):
        data = bytes(range(256)) * (size // 256) + b'x' * (size % 256)
        for rel, name in ((rel_a, name_a), (rel_b, name_b)):
            p = self.root / rel / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)

    def _scan_counting(self):
        calls = []
        real = Path.read_bytes

        def counting(self_path, *a, **k):
            calls.append(self_path.name)
            return real(self_path, *a, **k)

        with mock.patch.object(Path, 'read_bytes', counting):
            rep = audit_scan.scan(self.root, self.home, False)
        # only the pair's own files: the scan reads its own small config
        # file the same way, which is not the dedup stage
        watched = {'a.bin', 'b.bin', 'a.md', 'b.md'}
        return rep, [c for c in calls if c in watched]

    def test_short_pair_is_settled_without_a_second_open(self):
        self._pair('dup', 'copy', 1500)
        rep, calls = self._scan_counting()
        self.assertEqual(len(rep['duplicates']), 1)
        self.assertEqual(calls, [])

    def test_text_candidate_pair_is_settled_without_a_second_open(self):
        self._pair('dup', 'copy', 9000, 'a.md', 'b.md')
        rep, calls = self._scan_counting()
        self.assertEqual(len(rep['duplicates']), 1)
        self.assertEqual(calls, [])

    def test_big_binary_pair_is_still_read_in_full_once_each(self):
        self._pair('dup', 'copy', 9000)
        rep, calls = self._scan_counting()
        self.assertEqual(len(rep['duplicates']), 1)
        self.assertEqual(sorted(calls), ['a.bin', 'b.bin'])

    def test_second_stage_failure_breaks_a_big_pair(self):
        self._pair('dup', 'copy', 9000)
        real = Path.read_bytes

        def failing(self_path, *a, **k):
            if self_path.name == 'b.bin':
                raise OSError('simulated read failure')
            return real(self_path, *a, **k)

        with mock.patch.object(Path, 'read_bytes', failing):
            rep = audit_scan.scan(self.root, self.home, False)
        self.assertEqual(rep['duplicates'], [])

    def test_different_tails_are_not_duplicates(self):
        head = bytes(range(256)) * 16
        for rel, tail in (('dup', b'AAAA'), ('copy', b'BBBB')):
            p = self.root / rel / 'a.bin'
            p.parent.mkdir(parents=True)
            p.write_bytes(head + tail)
        rep, _ = self._scan_counting()
        self.assertEqual(rep['duplicates'], [])

    def test_duplicate_files_are_listed_in_path_order(self):
        # created out of order: the walk order differs between systems,
        # the report must read the same everywhere
        data = bytes(range(256)) * 8
        for name in ('dup/q.bin', 'dup/p.bin', 'dup/s.bin', 'dup/o.bin'):
            p = self.root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)
        rep = audit_scan.scan(self.root, self.home, False)
        self.assertEqual([g['files'] for g in rep['duplicates']],
                         [[os.sep.join(('dup', n)) for n in
                           ('o.bin', 'p.bin', 'q.bin', 's.bin')]])


# --- without git ----------------------------------------------------------------

class NoGitScanTests(TmpCase):
    """A folder without git and a key in a config file, end to end."""

    def test_folder_without_git_and_a_key_in_mcp_json(self):
        self.put(self.root, '.mcp.json',
                 '{\n  "mcpServers": {\n    "demo": {\n      "url": "https://x.invalid/mcp",\n'
                 '      "headers": { "Authorization": "Bearer %s" }\n    }\n  }\n}\n'
                 % FAKE_KEY)
        rep = audit_scan.scan(self.root, self.home, False)
        gate = _gate(rep, 'G6')
        self.assertEqual(gate['status'], 'fail')
        self.assertEqual(_rule(gate, 'exposed-secrets')['status'], 'fail')
        exposed = [f for f in rep['findings_detailed']
                   if f['gate'] == 'G6' and f['status'] == 'fail']
        self.assertEqual(len(exposed), 1)
        self.assertEqual(exposed[0]['evidence'][0]['file'], '.mcp.json')
        self.assertIsInstance(exposed[0]['evidence'][0]['line'], int)
        self.assertEqual(exposed[0]['evidence'][0]['mask'], 'sk-***')
        self.assertEqual(_rule(gate, 'secret-prevention')['status'],
                         'not_applicable')
        text = json.dumps(rep['findings_detailed'])
        self.assertNotIn('secret-prevention mechanism found', text)
        self.assertNotIn('pre-commit', text)
        # the key itself never leaves the scanner
        self.assertNotIn(FAKE_KEY, json.dumps(rep))


# --- short instruction files ----------------------------------------------------

class ShortInstructionTests(TmpCase):
    """A pointer-sized instruction file is a hint, a big one is a warning.
    Size is counted in bytes: a few very long lines make a big file."""

    LINE = ('This folder was created in 2019 to collect the regional '
            'statistics of the office and to keep them in one place.\n')

    def _scan(self, lines):
        self.put(self.root, 'AGENTS.md', '# Project\n\n' + self.LINE * lines)
        return audit_scan.scan(self.root, self.home, False)

    def test_pointer_sized_file_is_a_hint(self):
        rep = self._scan(2)
        hints = _by_check(rep, 'RUL_SHORT_FILE_HINT')
        self.assertEqual([f['status'] for f in hints], ['pass'])
        self.assertEqual([f['severity'] for f in hints], ['info'])
        self.assertEqual(_by_check(rep, 'RUL_MOSTLY_NOISE'), [])
        self.assertEqual(_rule(_gate(rep, 'G3'), 'content-quality')['status'],
                         'pass')

    def test_file_just_over_the_limit_is_a_warning(self):
        rep = self._scan(19)
        self.assertGreater(len(self.LINE) * 19,
                           gates.GATE_POLICY['SHORT_INSTRUCTION_BYTES'])
        self.assertEqual(_by_check(rep, 'RUL_SHORT_FILE_HINT'), [])
        noise = _by_check(rep, 'RUL_MOSTLY_NOISE')
        self.assertEqual([f['status'] for f in noise], ['warn'])
        self.assertEqual(_rule(_gate(rep, 'G3'), 'content-quality')['status'],
                         'warn')

    def test_size_in_bytes_not_in_lines(self):
        # 40 KB on a few lines: short by line count, big by bytes
        rep = self._scan(400)
        self.assertEqual(_by_check(rep, 'RUL_SHORT_FILE_HINT'), [])
        self.assertEqual(len(_by_check(rep, 'RUL_MOSTLY_NOISE')), 1)

    def test_is_short_judged_by_bytes_only(self):
        self.assertTrue(gates.is_short_instruction({'size_bytes': 0}))
        self.assertTrue(gates.is_short_instruction(
            {'size_bytes': gates.GATE_POLICY['SHORT_INSTRUCTION_BYTES'] - 1}))
        self.assertFalse(gates.is_short_instruction(
            {'size_bytes': gates.GATE_POLICY['SHORT_INSTRUCTION_BYTES']}))
        # a report made before the size was recorded: not judged short
        self.assertFalse(gates.is_short_instruction({'lines': 4}))


class ToolOwnFoldersTests(TmpCase):
    """The folders the tool creates under the audited root are not the
    user's loose data."""

    def test_tool_folders_are_not_reported_as_loose(self):
        self.put(self.root, 'AGENTS.md', '# Project\n')
        self.put(self.root, '.agents-doctor/scan.json', '{}')
        self.put(self.root, '.agents-doctor/AUDIT.md', '# Audit\n')
        self.put(self.root, '.agents-doctor-trash/old.md', '# Old\n')
        self.put(self.root, 'notes/a.md', '# Notes\n')
        rep = audit_scan.scan(self.root, self.home, False)
        loose = _by_check(rep, 'DIR_LOOSE_TOP_FOLDERS')
        self.assertEqual(len(loose), 1)
        self.assertEqual([e['path'] for e in loose[0]['evidence']], ['notes'])


# --- a copy of the plugin's own source in the folder ----------------------------

class OwnSourceSkipCounterTests(TmpCase):
    """Files that would have been read for keys but lie in a copy of the
    plugin's own source are left out and counted."""

    SCRIPTS = '.agents/skills/agents-doctor/scripts'

    def test_files_of_the_plugin_source_are_counted(self):
        for rel in ('audit_scan.py', 'secret_rules.py', 'ui/server.py',
                    'glossary.md'):
            self.put(self.root, self.SCRIPTS + '/' + rel, '# the plugin\n')
        self.put(self.root, 'notes/a.md', '# notes\n')
        rep = audit_scan.scan(self.root, self.home, False)
        # the four files of the copy; the user's own file is still read
        self.assertEqual(rep['stats']['own_source_skipped'], 4)

    def test_nothing_is_counted_without_such_a_copy(self):
        self.put(self.root, 'notes/a.md', '# notes\n')
        rep = audit_scan.scan(self.root, self.home, False)
        self.assertEqual(rep['stats']['own_source_skipped'], 0)


# --- the audited folder itself is a repository -----------------------------------

class RootRepoReadTests(GitCase):
    """The most common workspace is a project folder that is a git
    repository. Before, the scanner read the git side of the clones
    inside it and never its own."""

    def _scan(self):
        return audit_scan.scan(self.root, self.home, False)

    def test_the_folder_is_listed_as_a_repository_and_read(self):
        self.put(self.root, 'AGENTS.md', '# Rules\n')
        self.commit('AGENTS.md')
        rep = self._scan()
        first = rep['top_level'][0]
        self.assertEqual((first['name'], first['kind']), ('.', 'repo'))
        self.assertTrue(first['extra']['gitignore'] is False)
        self.assertEqual(_by_check(rep, 'SEC_GIT_SIDE_UNVERIFIED'), [])
        self.assertEqual(_by_check(rep, 'SEC_PREVENTION_UNVERIFIED'), [])
        self.assertEqual(_rule(_gate(rep, 'G6'), 'tracked-secrets')['status'], 'pass')

    def test_a_secret_scan_hook_of_the_folder_counts(self):
        hook = self.root / '.git' / 'hooks' / 'pre-commit'
        hook.write_text('#!/bin/sh\nexec gitleaks protect --staged\n',
                        encoding='utf-8')
        rep = self._scan()
        self.assertEqual(_rule(_gate(rep, 'G6'), 'secret-prevention')['status'],
                         'pass')
        self.assertEqual(_by_check(rep, 'SEC_PREVENTION_ABSENT'), [])

    def test_uncommitted_work_of_the_folder_is_named(self):
        self.put(self.root, 'AGENTS.md', '# Rules\n')
        self.commit('AGENTS.md')
        self.put(self.root, 'wip.txt', 'wip\n')
        rep = self._scan()
        hits = _by_check(rep, 'GIT_UNCOMMITTED_WORK')
        self.assertEqual([f['title'] for f in hits],
                         ['Uncommitted work in the audited folder'])
        self.assertEqual(hits[0]['evidence'][0]['repo'], '.')
        self.assertEqual([f['title'] for f in _by_check(rep, 'GIT_NO_GITIGNORE')],
                         ['No .gitignore in the audited folder'])

    def test_deeper_repositories_stay_unverified(self):
        # a clean folder with a clone inside: the clean result covers
        # the folder only, the clone's git side was never read
        self.put(self.root, '.gitignore', 'projects/\n')
        self.commit('.gitignore')
        deeper = self.root / 'projects' / 'a'
        deeper.mkdir(parents=True)
        commit_git(deeper, 'init', '-q')
        rep = self._scan()
        side = _by_check(rep, 'SEC_GIT_SIDE_UNVERIFIED')
        self.assertEqual(len(side), 1)
        self.assertNotIn('.', side[0]['evidence'][0]['paths'])
        prevention = _by_check(rep, 'SEC_PREVENTION_UNVERIFIED')
        self.assertEqual(prevention[0]['evidence'][0]['paths'],
                         side[0]['evidence'][0]['paths'])
        # a clean result covers only the folder that was read
        self.assertEqual(
            _rule(_gate(rep, 'G6'), 'tracked-secrets')['status'], 'unknown')
        self.assertEqual(
            _rule(_gate(rep, 'G7'), 'worktree-clean')['status'], 'unknown')


class RootRepoFolderTests(GitCase):

    def _scan(self):
        return audit_scan.scan(self.root, self.home, False)

    def test_tracked_and_ignored_folders_are_not_loose(self):
        self.put(self.root, 'src/main.py', 'print(1)\n')
        self.put(self.root, 'notes/a.md', '# a\n')
        self.put(self.root, '.gitignore', 'scratch/\n')
        self.put(self.root, 'scratch/x.txt', 'x\n')
        self.commit('src', '.gitignore')
        rep = self._scan()
        loose = _by_check(rep, 'DIR_LOOSE_TOP_FOLDERS')
        self.assertEqual(_paths(rep, 'DIR_LOOSE_TOP_FOLDERS', 'path'), ['notes'])
        self.assertIn('audited folder', loose[0]['description'])

    def test_a_tracked_large_file_is_not_without_backup(self):
        self.put_bytes('data.bin', bytes(5 * 1024 * 1024 + 1))
        self.commit('data.bin')
        self.put_bytes('dump.bin', bytes(5 * 1024 * 1024 + 2))
        rep = self._scan()
        self.assertEqual(_paths(rep, 'HLTH_LARGE_FILE_OUTSIDE_GIT', 'path'),
                         ['dump.bin'])
        self.assertEqual(_paths(rep, 'GIT_TRACKED_FILE_TOO_BIG', 'file'),
                         ['data.bin'])

    def test_a_repository_kept_out_by_gitignore_is_a_chosen_layout(self):
        self.put(self.root, '.gitignore', 'vendor/\n')
        self.commit('.gitignore')
        (self.root / 'vendor' / 'lib').mkdir(parents=True, exist_ok=True)
        commit_git(self.root / 'vendor' / 'lib', 'init', '-q')
        rep = self._scan()
        self.assertEqual(_by_check(rep, 'DIR_NESTED_REPOSITORY'), [])
        self.assertEqual(rep['top_level'][0]['extra']['nested_repos'],
                         [str(Path('vendor') / 'lib')])
        self.assertEqual(
            [os.path.normpath(p) for p in
             rep['top_level'][0]['extra']['nested_repos_ignored']],
            [str(Path('vendor') / 'lib')])

    def test_a_nested_repository_is_reported_for_the_folder(self):
        lib = self.root / 'lib'
        lib.mkdir()
        commit_git(lib, 'init', '-q')
        rep = self._scan()
        hits = _by_check(rep, 'DIR_NESTED_REPOSITORY')
        self.assertEqual([f['title'] for f in hits],
                         ['Nested repository in the audited folder: lib'])
        self.assertEqual(hits[0]['evidence'][0]['repo'], '.')


class RootRepoDigestTests(GitCase):
    """What the agent and the reader see when the audited folder is a
    repository: the advice about a key follows the facts, one step
    names all its places, the folder itself is named in words."""

    def _digest(self, lang='ru'):
        rep = audit_scan.scan(self.root, self.home, False)
        return rep, summary.build(rep, lang)

    def test_an_ignored_key_is_a_hint_not_an_alarm(self):
        self.put(self.root, '.gitignore', '.mcp.json\n.agents-doctor/\n')
        self.commit('.gitignore')
        _mcp_with_key(self)
        _rep, digest = self._digest()
        text = summary.render(digest)
        self.assertIn('В файле настроек лежит ключ (в Git он не попадает)', text)
        self.assertIn('где: .mcp.json:5', text)
        self.assertIn('[заметно, стоит посмотреть]', text)
        self.assertIn('это обычное место для личных настроек', text)
        self.assertNotIn('уберите его из файла', text)
        # a hint is not a step
        self.assertFalse([s for s in digest['start']
                          if s['code'] == 'SEC_EXPOSED_SECRET'])
        # the folder is in git and keeps the tool's reports out of it
        self.assertIn('Сама папка хранится в Git.', text)
        self.assertNotIn('Отчёты аудита лежат', text)

    def test_a_tracked_key_is_the_first_step(self):
        _mcp_with_key(self)
        self.commit('.mcp.json')
        _rep, digest = self._digest()
        self.assertEqual(digest['start'][0]['code'], 'SEC_EXPOSED_SECRET')
        self.assertEqual(digest['start'][0]['places'], ['.mcp.json:5'])
        text = summary.render(digest)
        self.assertIn('В файле, который хранится в Git, лежит пароль или ключ',
                      text)
        self.assertIn('уберите файл из проекта и из его истории', text)
        # the reports folder is not kept out of git yet
        self.assertIn('Отчёты аудита лежат в папке .agents-doctor', text)

    def _three_keys(self):
        servers = {name: {'url': 'https://x.invalid/' + name,
                          'headers': {'Authorization': 'Bearer %s' % FAKE_KEY}}
                   for name in ('a', 'b', 'c')}
        return self.put(self.root, '.mcp.json',
                        json.dumps({'mcpServers': servers}, indent=2))

    def test_equal_steps_are_one_step_with_every_place(self):
        self._three_keys()
        rep = audit_scan.scan(self.root, self.home, False)
        self.assertEqual(len(rep['secrets']), 3)
        digest = summary.build(rep, 'ru')
        steps = [s for s in digest['start'] if s['code'] == 'SEC_EXPOSED_SECRET']
        self.assertEqual(len(steps), 1)
        self.assertEqual(len(steps[0]['places']), 3)
        start = summary.render(digest).split('С ЧЕГО НАЧАТЬ')[1]
        self.assertEqual(start.count('Добавьте его в .gitignore'), 1)
        # the plain report groups the same way in its "start" section
        report = report_human.generate_human_markdown(rep, 'ru')
        start = report.rsplit('Начните с этого:', 1)[1].split('Дальше:')[0]
        self.assertEqual(start.count('Добавьте его в .gitignore'), 1)
        self.assertEqual(start.count('строка'), 3)
        # and its short version says what to do about this kind of key
        self.assertIn('Начните с этого: файл ещё не в Git', report)

    def test_the_folder_itself_is_named_in_words(self):
        self.put(self.root, 'AGENTS.md', '# Rules\n')
        self.commit('AGENTS.md')
        self.put(self.root, 'wip.txt', 'wip\n')
        rep = audit_scan.scan(self.root, self.home, False)
        text = summary.render(summary.build(rep, 'ru'))
        self.assertIn('где: самой папки', text)
        self.assertNotIn('где: .\n', text)
        report = report_human.generate_human_markdown(rep, 'ru')
        self.assertIn('Есть несохранённая работа: самой папки', report)

    def test_unchecked_folders_are_named_with_the_rest_counted(self):
        self.put(self.root, '.gitignore', 'projects/\n')
        self.commit('.gitignore')
        for name in ('a', 'b', 'c'):
            (self.root / 'projects' / name).mkdir(parents=True, exist_ok=True)
            commit_git(self.root / 'projects' / name, 'init', '-q')
        rep = audit_scan.scan(self.root, self.home, False)
        text = summary.render(summary.build(rep, 'ru'))
        self.assertIn('Папок с Git, которые не проверялись (лежат глубже '
                      'первого уровня): 3.', text)
        self.assertIn('где: projects/a, projects/b, projects/c', text)
        self.assertEqual(text.count('и ещё '), 0)


if __name__ == '__main__':
    unittest.main()
