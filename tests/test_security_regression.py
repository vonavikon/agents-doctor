"""Security regression suite for the agents-doctor scanner.

Runs skills/agents-doctor/scripts/audit_scan.py end to end against a
planted fixture workspace and checks four properties from the
production-readiness spec:

A. raw planted secrets never appear in any output artifact
   (scan.json, stdout, stderr); evidence stays redacted;
B. redaction does not weaken detection: gate 6 still FAILs and the
   worktree, staged-index and git-history evidence is still collected;
C. symlinks pointing outside the workspace root are not read;
D. the audit is read-only: the git index and the worktree file set are
   untouched.

The classes after SecurityRegressionTest add two more, each on a small
temp workspace with the same canaries planted:

E. what the agent and the reader get instead of the scan (the digest,
   the explain card, both reports) carries no canary, no path of the
   machine and no line quoted from a file;
F. the limits of the key check are narrow and are said: a copy of the
   plugin's own source needs both marker files and is counted, a skills
   folder that cannot be listed does not stop the audit, and a line of
   the user's file does not enter the record.

The suite encodes the post-integration contract for secret evidence
(dict entries with file/line/kind/commit fields and a redacted value,
plus a skipped_symlinks_outside counter in stats).  Against the current
scanner some tests fail on purpose; that red phase documents exactly
what the integration has to fix.  Do not weaken the assertions to force
a green run.
"""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCANNER = REPO_ROOT / 'skills' / 'agents-doctor' / 'scripts' / 'audit_scan.py'
# the later classes scan in process and share the bases of the other tests
sys.path.insert(0, str(SCANNER.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent / 'integration'))

import audit_scan  # noqa: E402
import enrich  # noqa: E402
import report_generator  # noqa: E402
import report_human  # noqa: E402
import summary  # noqa: E402
from fixtures import (  # noqa: E402
    ABS_PATH_RE, BROKEN_LINE, DASH, GitCase, TmpCase, commit_git, skill_file,
    stand)
# report lookups, under the names the moved tests were written with
from fixtures import by_check as _by_check, gate_of as _gate  # noqa: E402
from fixtures import mcp_with_key as _mcp_with_key  # noqa: E402
from fixtures import rule_of as _rule  # noqa: E402

# Unique literal canaries planted into the fixture.  They live only in
# the fixture tree; every assertion below demands they never show up in
# raw form in any scanner output.
CANARIES = {
    'sk': 'sk-CANARY' + 'qz9' * 8,           # sk-token rule, staged file
    'sk2': 'sk-CANARY' + 'mcp7' * 3,         # second sk variant, .mcp.json
    'password': 'CANARY-PASSWORD-zz7spark',  # quoted password literal, .env
    'aws': 'AKIA' + 'CANARYREGRESSION',      # AKIA + 16 uppercase alnum
    'key': 'CANARY-PRIVATE-KEY-BLOCK',       # inside an OpenSSH key block
    'outside': 'sk-OUTSIDE' + 'wm5' * 8,     # reachable only via symlink
}

# The key the later classes plant: the first sk canary of this file.
FAKE_KEY = CANARIES['sk']


class SecurityRegressionTest(unittest.TestCase):
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        if not SCANNER.exists():
            raise unittest.SkipTest('scanner not found: %s' % SCANNER)

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix='wsa-sec-regress-')
        self.base = Path(self._tmp.name)
        self.symlinks_available = True

    def tearDown(self):
        # git marks its object files read-only; open everything up so
        # TemporaryDirectory cleanup succeeds on Windows
        for dirpath, dirnames, filenames in os.walk(self.base):
            for name in dirnames + filenames:
                try:
                    os.chmod(os.path.join(dirpath, name), 0o777)
                except OSError:
                    pass
        self._tmp.cleanup()

    # --- fixture helpers -------------------------------------------------

    def _git(self, repo, *args):
        cmd = ['git', '-C', str(repo),
               '-c', 'user.name=Security Regression Fixture',
               '-c', 'user.email=fixture@invalid',
               *args]
        result = subprocess.run(cmd, capture_output=True, text=True,
                                encoding='utf-8', errors='replace', timeout=60)
        self.assertEqual(result.returncode, 0,
                         'fixture git %s failed: %s'
                         % (args[0], (result.stderr or '')[:400]))
        return result.stdout

    def build_workspace(self):
        """Plant the fixture.  Returns (root, home)."""
        root = self.base / 'root'
        home = self.base / 'home'
        root.mkdir()
        (home / '.zcode').mkdir(parents=True)

        repo = root / 'repo'
        repo.mkdir()
        self._git(repo, 'init', '-q')

        # commit 1: .env with the password canary (tracked + worktree)
        (repo / '.env').write_text(
            'DB_PASSWORD="%s"\n' % CANARIES['password'], encoding='utf-8')
        self._git(repo, 'add', '.env')
        self._git(repo, 'commit', '-q', '-m', 'add env config')

        # commits 2 and 3: the AWS canary exists only in git history
        api = repo / 'api.txt'
        api.write_text('aws_key=%s\n' % CANARIES['aws'], encoding='utf-8')
        self._git(repo, 'add', 'api.txt')
        self._git(repo, 'commit', '-q', '-m', 'add api key')
        api.write_text('aws_key=placeholder-not-a-secret\n', encoding='utf-8')
        self._git(repo, 'add', 'api.txt')
        self._git(repo, 'commit', '-q', '-m', 'replace api key')

        # staged, never committed: the sk canary lives in the git index
        (repo / 'config').mkdir()
        (repo / 'config' / 'staged.json').write_text(
            '{"api_key": "%s"}\n' % CANARIES['sk'], encoding='utf-8')
        self._git(repo, 'add', 'config/staged.json')

        # worktree-only OpenSSH private key block
        keys = root / 'keys'
        keys.mkdir()
        (keys / 'id_test').write_text(
            '-----BEGIN OPENSSH PRIVATE KEY-----\n'
            '%s\n'
            '-----END OPENSSH PRIVATE KEY-----\n' % CANARIES['key'],
            encoding='utf-8')

        # worktree-only harness config with the second sk variant
        (root / '.mcp.json').write_text(
            '{\n  "Authorization": "%s"\n}\n' % CANARIES['sk2'],
            encoding='utf-8')

        # sibling directory outside the workspace root, reachable only
        # through symlinks
        outside = self.base / 'outside'
        outside.mkdir()
        (outside / 'canary.txt').write_text(
            'token=%s\n' % CANARIES['outside'], encoding='utf-8')
        try:
            os.symlink(
                Path(os.path.relpath(outside / 'canary.txt', root)).as_posix(),
                str(root / 'link-to-outside.txt'))
        except OSError:
            self.symlinks_available = False
        try:
            os.symlink(Path(os.path.relpath(outside, root)).as_posix(),
                       str(root / 'link-dir'),
                       target_is_directory=True)
        except (OSError, NotImplementedError):
            # nice to have: os.walk never follows directory symlinks, the
            # file symlink is the attack surface under test
            pass

        return root, home

    def run_audit(self, root, home, deep=False):
        """Run the scanner end to end.  Returns (report, combined, out)."""
        out_dir = self.base / 'artifacts'
        out_dir.mkdir(exist_ok=True)
        out = out_dir / 'scan.json'
        cmd = [sys.executable, str(SCANNER), str(root),
               '--home', str(home), '--out', str(out)]
        if deep:
            cmd.append('--deep')
        result = subprocess.run(cmd, capture_output=True, text=True,
                                encoding='utf-8', errors='replace',
                                cwd=str(REPO_ROOT), timeout=120)
        combined = (result.stdout or '') + (result.stderr or '')
        try:
            report = json.loads(out.read_text(encoding='utf-8'))
        except (OSError, ValueError):
            self.fail('scanner produced no parseable report (exit %s): %s'
                      % (result.returncode, combined[:600]))
        return report, combined, out

    # --- report helpers ---------------------------------------------------

    def _collect_secret_entries(self, report):
        """All secret evidence: worktree, staged/index, git history."""
        worktree = list(report.get('secrets') or [])
        tracked, history = [], []
        for item in report.get('top_level') or []:
            extra = item.get('extra') or {}
            tracked.extend(extra.get('tracked_secrets') or [])
            history.extend(extra.get('history_secrets') or [])
        return worktree, tracked, history

    @staticmethod
    def _serialized(entry):
        return entry if isinstance(entry, str) else json.dumps(entry, ensure_ascii=False)

    def _assert_redacted(self, entry, where):
        text = self._serialized(entry)
        for name, value in CANARIES.items():
            self.assertNotIn(value, text,
                             '%s entry leaks the raw %s canary: %r'
                             % (where, name, text[:100]))
        masked = ('REDACT' in text.upper()
                  or '***' in text
                  or (isinstance(entry, dict)
                      and any(isinstance(entry.get(k), str)
                              and entry[k].endswith('...')
                              for k in ('preview', 'value'))))
        self.assertTrue(masked, '%s entry carries no redaction marker: %r'
                        % (where, text[:100]))

    @staticmethod
    def _worktree_files(root):
        names = []
        for dirpath, _dirs, files in os.walk(root):
            for fn in files:
                names.append(
                    Path(os.path.join(dirpath, fn)).relative_to(root).as_posix())
        return sorted(names)

    # --- A: no raw secrets in any artifact --------------------------------

    def test_no_raw_secrets_in_artifacts(self):
        root, home = self.build_workspace()
        report, combined, out = self.run_audit(root, home, deep=True)

        report_text = json.dumps(report, ensure_ascii=False)
        raw_text = out.read_bytes().decode('utf-8', errors='replace')
        artifacts = (('scan.json (parsed report)', report_text),
                     ('scan.json (raw file bytes)', raw_text),
                     ('scanner stdout+stderr', combined))
        for name, value in CANARIES.items():
            for label, text in artifacts:
                self.assertNotIn(value, text,
                                 'raw %s canary leaked into %s' % (name, label))

        # detection survived: each evidence channel still has entries,
        # and every entry is visibly redacted
        worktree, tracked, history = self._collect_secret_entries(report)
        self.assertTrue(worktree,
                        'worktree secret findings disappeared from the report')
        self.assertTrue(tracked,
                        'staged/index secret findings disappeared from the report')
        self.assertTrue(history,
                        'git history secret findings disappeared from the report')
        for entry in worktree:
            self._assert_redacted(entry, 'secrets')
        for entry in tracked:
            self._assert_redacted(entry, 'tracked_secrets')
        for entry in history:
            self._assert_redacted(entry, 'history_secrets')

    # --- B: redaction must not weaken detection ---------------------------

    def test_detection_not_weakened(self):
        root, home = self.build_workspace()
        report, _combined, _out = self.run_audit(root, home, deep=True)

        gate6 = next((g for g in report.get('gates', []) if g.get('n') == 6),
                     None)
        self.assertIsNotNone(gate6, 'gate 6 missing from the report')
        self.assertEqual(gate6.get('status'), 'fail',
                         'gate 6 must FAIL while planted secrets exist')

        worktree, tracked, history = self._collect_secret_entries(report)
        self.assertGreaterEqual(
            len(worktree), 2,
            'worktree secret findings were weakened (expected at least '
            '.env, .mcp.json, staged.json and the private key file)')
        self.assertTrue(any('.env' in self._serialized(e) for e in worktree),
                        'the .env password finding disappeared')
        self.assertTrue(any('mcp.json' in self._serialized(e) for e in worktree),
                        'the .mcp.json Authorization finding disappeared')
        self.assertTrue(
            any('staged.json' in self._serialized(e) for e in tracked),
            'the staged config/staged.json finding disappeared from '
            'tracked evidence')
        self.assertTrue(
            any(isinstance(e, dict) and e.get('commit')
                and 'api.txt' in self._serialized(e) for e in history),
            'history evidence must attribute an entry to api.txt with a '
            'commit id (dict schema: file, line, kind, commit, value)')

    # --- C: symlinks outside the root are not read -------------------------

    def test_symlink_boundary(self):
        root, home = self.build_workspace()
        if not self.symlinks_available:
            self.skipTest('symlinks unavailable on this platform')
        report, _combined, _out = self.run_audit(root, home, deep=True)

        stats = report.get('stats') or {}
        self.assertGreaterEqual(
            stats.get('skipped_symlinks_outside', 0), 1,
            "stats['skipped_symlinks_outside'] must count symlinks that "
            'resolve outside the workspace root (key absent before '
            'integration)')

        worktree, _tracked, _history = self._collect_secret_entries(report)
        for entry in worktree:
            text = self._serialized(entry)
            if 'link-to-outside' in text:
                self.assertNotIn(
                    CANARIES['outside'], text,
                    'the scanner read a file through a symlink that '
                    'escapes the workspace root')

    # --- D: the audit is read-only -----------------------------------------

    def test_readonly_git_index(self):
        root, home = self.build_workspace()
        index = root / 'repo' / '.git' / 'index'
        if not index.exists():
            self.skipTest('fixture produced no .git/index')
        before = hashlib.sha256(index.read_bytes()).hexdigest()
        files_before = self._worktree_files(root)

        self.run_audit(root, home, deep=False)

        after = hashlib.sha256(index.read_bytes()).hexdigest()
        self.assertEqual(before, after,
                         'the audit rewrote .git/index (git subprocesses '
                         'must run with GIT_OPTIONAL_LOCKS=0 or equivalent)')
        self.assertEqual(files_before, self._worktree_files(root),
                         'the audit changed the worktree file set')


# =====================================================================
# E: what the agent and the reader get carries nothing raw
# =====================================================================

class PlainLanguageOutputTests(unittest.TestCase):
    """The digest, the explain card and both reports over a scan of the
    stand workspace (tests/integration/fixtures.py) with a canary
    planted in its config file."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.base = Path(cls._tmp.name)
        cls.root = cls.base / 'ws'
        cls.home = cls.base / 'home'
        cls.root.mkdir()
        cls.home.mkdir()
        stand(cls.root, cls.home, key=FAKE_KEY)
        cls.rep = audit_scan.scan(cls.root, cls.home, False)
        cls.key = next(f for f in cls.rep['findings_detailed']
                       if f['gate'] == 'G6' and f['status'] == 'fail')
        cls.key_at = '.mcp.json:%d' % cls.key['evidence'][0]['line']
        cls.md = report_human.generate_human_markdown(cls.rep, lang='ru')

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def _text(self, lang='ru'):
        return summary.render(summary.build(self.rep, lang, files={
            'human': '.agents-doctor/REPORT.md',
            'report': '.agents-doctor/AUDIT.md',
            'scan': '.agents-doctor/scan.json'}))

    def test_no_absolute_path_of_the_machine(self):
        for lang in ('ru', 'en'):
            text = self._text(lang)
            self.assertIsNone(ABS_PATH_RE.search(text), ABS_PATH_RE.search(text))
            self.assertNotIn(str(self.base), text)
            self.assertNotIn(os.environ.get('USERNAME', '\x00'), text)

    def test_no_secret_and_no_quoted_file_line(self):
        text = self._text() + self._text('en')
        self.assertNotIn(FAKE_KEY, text)
        self.assertNotIn('sk-', text)
        self.assertNotIn('hmac256', text)
        # the body of the broken skill and of the instruction files
        self.assertNotIn('prepare a short report', text)
        self.assertNotIn('Rules are in the handbook', text)

    def test_explain_card_is_the_digest_not_the_evidence(self):
        finding = next(f for f in self.rep['findings_detailed']
                       if f['gate'] == 'G6' and f['status'] == 'fail')
        for lang in ('ru', 'en'):
            card = summary.explain_card(finding, self.rep, lang)
            self.assertIn(finding['fid'], card)
            self.assertIn(self.key_at, card)
            self.assertNotIn('evidence', card)
            self.assertNotIn('hmac256', card)
            self.assertNotIn(str(self.base), card)

    def test_no_absolute_path_no_secret_no_dash_in_russian(self):
        self.assertNotIn(str(self.base), self.md)
        self.assertIsNone(ABS_PATH_RE.search(self.md),
                          ABS_PATH_RE.search(self.md))
        self.assertNotIn(FAKE_KEY, self.md)
        self.assertNotIn('sk-', self.md)
        self.assertNotIn(DASH, self.md)
        self.assertNotIn('!', self.md)

    def test_planted_canary_reaches_no_digest_card_or_report(self):
        outputs = {}
        for lang in ('ru', 'en'):
            outputs['digest (%s)' % lang] = self._text(lang)
            outputs['explain card (%s)' % lang] = summary.explain_card(
                self.key, self.rep, lang)
            outputs['plain report (%s)' % lang] = \
                report_human.generate_human_markdown(self.rep, lang=lang)
        outputs['technical report'] = report_generator.generate_markdown(self.rep)
        self.assertTrue(outputs)
        for name, text in outputs.items():
            for canary, value in CANARIES.items():
                self.assertNotIn(value, text,
                                 '%s leaks the raw %s canary' % (name, canary))
            self.assertNotIn(str(self.base), text,
                             '%s carries a path of the machine' % name)


# =====================================================================
# F: the limits of the checks are narrow, and are said
# =====================================================================

class UserLineRedactionTests(TmpCase):
    """A line of the user's file that breaks a skill header is not
    copied into the record the scanner keeps."""

    def test_users_line_never_enters_the_record(self):
        p = skill_file(self.root, 'skill', 'name: broken\n' + BROKEN_LINE)
        recs = enrich.skills_frontmatter([{'path': str(p)}])
        rec = next(iter(recs.values()))
        dumped = json.dumps(rec, ensure_ascii=False)
        self.assertNotIn('prepare a short report', dumped)
        self.assertNotIn('When asked', dumped)


class UnreadableSkillFolderTests(TmpCase):
    """A skills folder that exists but cannot be listed does not stop
    the audit: the skill check ends unknown, says why, and names the
    failure without the path of the machine."""

    def test_unreadable_folder_is_unknown_and_never_a_crash(self):
        # a skills path that exists but cannot be listed
        (self.root / '.agents').mkdir()
        (self.root / '.agents' / 'skills').write_text('not a folder',
                                                      encoding='utf-8')
        rep = audit_scan.scan(self.root, self.home, False)
        gate = _gate(rep, 'G5')
        self.assertEqual(gate['status'], 'unknown')
        self.assertNotIn('pass', [c['status'] for c in gate['checks']])
        self.assertEqual(gate['status_why'], 'skills_folders_unreadable')
        hits = _by_check(rep, 'SKL_FOLDER_UNREADABLE')
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]['status'], 'unknown')
        # the reason names the failure, not the machine's path
        self.assertNotIn(str(self.root), json.dumps(hits[0]))

    def test_a_key_next_to_the_unreadable_folder_is_still_found(self):
        (self.root / '.agents').mkdir()
        (self.root / '.agents' / 'skills').write_text('not a folder',
                                                      encoding='utf-8')
        _mcp_with_key(self, FAKE_KEY)
        rep = audit_scan.scan(self.root, self.home, False)
        self.assertEqual([s['path'] for s in rep['secrets']], ['.mcp.json'])
        self.assertEqual(_gate(rep, 'G6')['status'], 'fail')
        self.assertNotIn(FAKE_KEY, json.dumps(rep))


class OwnSourceTests(TmpCase):
    """A copy of the plugin inside the workspace: its test corpus of fake
    keys and its masking code are not the user's data. A folder counts
    as the plugin's source only when both marker files are in it, and
    the files left out of the key check are counted."""

    SCRIPTS = '.agents/skills/agents-doctor/scripts'

    def test_keys_of_the_plugin_source_are_not_reported(self):
        self.put(self.root, self.SCRIPTS + '/audit_scan.py', '# the plugin\n')
        self.put(self.root, self.SCRIPTS + '/secret_rules.py',
                 'CORPUS = [\n    ("api_key = \\"%s\\"", "SEC-005"),\n]\n' % FAKE_KEY)
        self.put(self.root, self.SCRIPTS + '/ui/server.py',
                 'MASK = "%s"\n' % FAKE_KEY)
        self.put(self.root, '.mcp.json',
                 '{"Authorization": "Bearer %s"}\n' % FAKE_KEY)
        rep = audit_scan.scan(self.root, self.home, False)
        self.assertEqual([s['path'] for s in rep['secrets']], ['.mcp.json'])
        self.assertNotIn(FAKE_KEY, json.dumps(rep))

    def test_the_marker_decides_what_is_the_plugin(self):
        # the same file name in a folder of the user's own is data
        self.put(self.root, self.SCRIPTS + '/audit_scan.py', '# the plugin\n')
        self.put(self.root, 'tools/secret_rules.py',
                 'api_key = "%s"\n' % FAKE_KEY)
        self.put(self.root, self.SCRIPTS + '/../../other/deep.py',
                 'api_key = "%s"\n' % FAKE_KEY)
        rep = audit_scan.scan(self.root, self.home, False)
        self.assertEqual(
            sorted(s['path'].replace('\\', '/') for s in rep['secrets']),
            ['.agents/skills/other/deep.py', 'tools/secret_rules.py'])

    def test_one_marker_file_does_not_make_the_plugin(self):
        # one file named like a file of the scanner does not turn the
        # key check off for its folder: both marker files are needed
        folders = ('.agents/skills/tool-a/scripts',
                   '.agents/skills/tool-b/scripts')
        for folder, marker in zip(folders, ('audit_scan.py', 'secret_rules.py')):
            self.put(self.root, folder + '/' + marker, '# a tool\n')
            self.put(self.root, folder + '/notes.py',
                     'api_key = "%s"\n' % FAKE_KEY)
        rep = audit_scan.scan(self.root, self.home, False)
        self.assertEqual(
            sorted(s['path'].replace('\\', '/') for s in rep['secrets']),
            [folder + '/notes.py' for folder in folders])
        self.assertEqual(rep['stats']['own_source_skipped'], 0)

    def test_the_skip_is_counted_and_said_in_the_digest(self):
        self.put(self.root, self.SCRIPTS + '/audit_scan.py', '# the plugin\n')
        self.put(self.root, self.SCRIPTS + '/secret_rules.py',
                 'CORPUS = [\n    ("api_key = \\"%s\\"", "SEC-005"),\n]\n' % FAKE_KEY)
        self.put(self.root, self.SCRIPTS + '/ui/server.py',
                 'MASK = "%s"\n' % FAKE_KEY)
        rep = audit_scan.scan(self.root, self.home, False)
        # every text file of the copy is a candidate, the marker file
        # included: three were left out
        self.assertEqual(rep['stats']['own_source_skipped'], 3)
        for lang, line in (
                ('ru', 'Собственные файлы самого инструмента (3) не '
                       'проверялись на ключи.'),
                ('en', "The tool's own files (3) were not checked for keys.")):
            with self.subTest(lang=lang):
                text = summary.render(summary.build(rep, lang))
                self.assertIn(line, text)
                self.assertNotIn(FAKE_KEY, text)


class OwnSourceIndexTests(GitCase):
    """The same exclusion for the git index: a committed copy of the
    plugin must not start the report either. The planted lines hold the
    password canary."""

    SCRIPTS = OwnSourceTests.SCRIPTS

    def test_index_hits_of_the_plugin_source_are_not_reported(self):
        corpus = '    ("DB_PASSWORD: \\"%s\\"", "SEC-005"),\n' % CANARIES['password']
        self.put(self.root, self.SCRIPTS + '/audit_scan.py', '# the plugin\n')
        self.put(self.root, self.SCRIPTS + '/secret_rules.py',
                 'CORPUS = [\n' + corpus + ']\n')
        self.put(self.root, 'notes/config.py',
                 'DB_PASSWORD = "%s"\n' % CANARIES['password'])
        self.commit(self.SCRIPTS + '/audit_scan.py',
                    self.SCRIPTS + '/secret_rules.py', 'notes/config.py')
        rep = audit_scan.scan(self.root, self.home, False)
        tracked = rep['top_level'][0]['extra']['tracked_secrets']
        self.assertEqual([str(t['file']).replace('\\', '/') for t in tracked],
                         ['notes/config.py'])
        exposed = _by_check(rep, 'SEC_EXPOSED_SECRET')
        self.assertEqual([e['file'].replace('\\', '/') for f in exposed
                          for e in f['evidence']], ['notes/config.py'])
        self.assertEqual(exposed[0]['evidence'][0]['git'], 'tracked')
        self.assertNotIn(CANARIES['password'], json.dumps(rep))

    def test_a_hit_in_a_large_tracked_file_is_a_look_by_hand(self):
        # a minified bundle: the worktree scan does not read it for keys,
        # so the index hit is not judged and must not lead the report
        self.put(self.root, 'bundle/main.js',
                 'var x=1;' * 150000
                 + '\nDB_PASSWORD = "%s"\n' % CANARIES['password'])
        self.put(self.root, 'notes/config.py',
                 'DB_PASSWORD = "%s"\n' % CANARIES['password'])
        self.commit('bundle/main.js', 'notes/config.py')
        rep = audit_scan.scan(self.root, self.home, False)
        maybe = _by_check(rep, 'SEC_TRACKED_SECRET_BUNDLE')
        self.assertEqual([(f['severity'], f['status']) for f in maybe],
                         [('low', 'warn')])
        self.assertIn('bundle', maybe[0]['evidence'][0]['file'])
        self.assertEqual(_by_check(rep, 'SEC_TRACKED_SECRET'), [])
        self.assertEqual(_rule(_gate(rep, 'G6'), 'exposed-secrets')['status'],
                         'fail')
        digest = summary.build(rep, 'ru')
        self.assertIn('Возможно, ключ в большом файле проекта',
                      summary.render(digest))
        # the first step is the real key; the line to look at is no step
        codes = [s['code'] for s in digest['start']]
        self.assertEqual(codes[0], 'SEC_EXPOSED_SECRET')
        self.assertNotIn('SEC_TRACKED_SECRET_BUNDLE', codes)
        self.assertNotIn(CANARIES['password'],
                         json.dumps(rep) + summary.render(digest))


class RootRepoKeyAdviceTests(GitCase):
    """What to do about a key depends on where its file sits: in git,
    kept out of git by .gitignore, or waiting to be added."""

    KEY = FAKE_KEY   # what _mcp_with_key plants

    def _exposed(self):
        rep = audit_scan.scan(self.root, self.home, False)
        return rep, _by_check(rep, 'SEC_EXPOSED_SECRET')

    def test_key_in_a_tracked_file_is_reported_once(self):
        _mcp_with_key(self)
        self.commit('.mcp.json')
        rep, exposed = self._exposed()
        self.assertEqual(len(exposed), 1)
        self.assertEqual(exposed[0]['evidence'][0]['git'], 'tracked')
        self.assertEqual((exposed[0]['severity'], exposed[0]['status']),
                         ('critical', 'fail'))
        self.assertIn('git rm --cached', exposed[0]['recommendation'])
        # the same key from the index is not a second finding
        self.assertEqual(_by_check(rep, 'SEC_TRACKED_SECRET'), [])
        self.assertEqual(_gate(rep, 'G6')['status'], 'fail')

    def test_key_in_an_ignored_file_is_a_hint(self):
        self.put(self.root, '.gitignore', '.mcp.json\n')
        self.commit('.gitignore')
        _mcp_with_key(self)
        rep, exposed = self._exposed()
        self.assertEqual(len(exposed), 1)
        self.assertEqual(exposed[0]['evidence'][0]['git'], 'ignored')
        self.assertEqual((exposed[0]['severity'], exposed[0]['status']),
                         ('medium', 'warn'))
        self.assertNotIn('Rotate the secret at its provider',
                         exposed[0]['recommendation'])
        self.assertEqual(_rule(_gate(rep, 'G6'), 'exposed-secrets')['status'],
                         'warn')
        self.assertEqual(rep['secrets'][0]['git'], 'ignored')

    def test_key_not_added_yet_names_the_guard(self):
        _mcp_with_key(self)
        rep, exposed = self._exposed()
        self.assertEqual(exposed[0]['evidence'][0]['git'], 'untracked')
        self.assertEqual(exposed[0]['status'], 'fail')
        self.assertIn('.gitignore', exposed[0]['recommendation'])
        self.assertEqual(rep['secrets'][0]['git'], 'untracked')

    def test_states_come_from_the_nearest_repository(self):
        # a key inside a clone that lies in the folder: the clone decides
        self.put(self.root, 'AGENTS.md', '# Rules\n')
        self.commit('AGENTS.md')
        clone = self.root / 'vendor' / 'lib'
        clone.mkdir(parents=True)
        commit_git(clone, 'init', '-q')
        (clone / '.gitignore').write_text('.env\n', encoding='utf-8')
        (clone / '.env').write_text('API_KEY=%s\n' % FAKE_KEY, encoding='utf-8')
        rep = audit_scan.scan(self.root, self.home, False)
        self.assertEqual(rep['secrets'][0]['path'],
                         str(Path('vendor') / 'lib' / '.env'))
        self.assertEqual(rep['secrets'][0]['git'], 'ignored')

    def test_the_key_itself_reaches_no_artifact(self):
        # whatever the advice is, the value of the key is in nothing
        # the scanner writes for the agent or the reader
        _mcp_with_key(self)
        rep, exposed = self._exposed()
        self.assertEqual(len(exposed), 1)
        texts = [json.dumps(rep),
                 summary.render(summary.build(rep, 'ru')),
                 summary.render(summary.build(rep, 'en')),
                 report_human.generate_human_markdown(rep, 'ru'),
                 report_human.generate_human_markdown(rep, 'en'),
                 report_generator.generate_markdown(rep)]
        for text in texts:
            self.assertNotIn(FAKE_KEY, text)


if __name__ == '__main__':
    unittest.main()
