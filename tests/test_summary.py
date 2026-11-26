"""Tests for skills/agents-doctor/scripts/summary.py: the digest of a
scan, which the agent reads instead of the scan JSON.

The digest names gates and findings through the glossary, spells out
the findings that matter with their place relative to the audited
folder, counts the long tail and says where to start. What must never
enter it (a secret, a path of the machine, a line quoted from a file)
is checked in tests/test_security_regression.py.
"""
import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
SCRIPTS = REPO / 'skills' / 'agents-doctor' / 'scripts'
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(REPO / 'tests' / 'integration'))

import audit_scan  # noqa: E402
import glossary  # noqa: E402
import summary  # noqa: E402
from fixtures import put, stand  # noqa: E402


def _stand_workspace():
    """A temp (base, root, home) with the stand built in; base holds the
    TemporaryDirectory object to clean up."""
    tmp = tempfile.TemporaryDirectory()
    base = Path(tmp.name)
    root, home = base / 'ws', base / 'home'
    root.mkdir()
    home.mkdir()
    stand(root, home)
    return tmp, base, root, home


class SummaryTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.base = Path(cls._tmp.name)
        cls.root = cls.base / 'ws'
        cls.home = cls.base / 'home'
        cls.root.mkdir()
        cls.home.mkdir()
        stand(cls.root, cls.home)
        cls.rep = audit_scan.scan(cls.root, cls.home, False)
        cls.key = next(f for f in cls.rep['findings_detailed']
                       if f['gate'] == 'G6' and f['status'] == 'fail')
        cls.key_line = cls.key['evidence'][0]['line']   # where the key sits
        cls.key_at = '.mcp.json:%d' % cls.key_line

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def _text(self, lang='ru'):
        return summary.render(summary.build(self.rep, lang, files={
            'human': '.agents-doctor/REPORT.md',
            'report': '.agents-doctor/AUDIT.md',
            'scan': '.agents-doctor/scan.json'}))

    def test_is_small_next_to_the_scan(self):
        scan_bytes = len(json.dumps(self.rep).encode('utf-8'))
        digest_bytes = len(self._text().encode('utf-8'))
        self.assertLess(digest_bytes, max(6000, scan_bytes // 4))

    def test_gate_names_come_from_the_glossary(self):
        text = self._text()
        for gid in glossary.GATES:
            self.assertIn(glossary.gate_name(gid, 'ru'), text)
            self.assertIn('(%s)' % gid, text)
        # a check that does not apply says why, in words
        self.assertIn('неприменимо', text)
        self.assertIn('советы про Git неприменимы', text)

    def test_findings_carry_what_where_and_what_to_do(self):
        lines = self._text().splitlines()
        first = next(i for i, l in enumerate(lines)
                     if '(%s)' % self.key['fid'] in l)
        self.assertIn('В файле лежит пароль или ключ', lines[first])
        self.assertIn(self.key_at, lines[first + 1])
        self.assertIn('смените ключ', lines[first + 2])
        # the line of the syntax error is shown, and the position only
        broken = next(i for i, l in enumerate(lines) if 'SKL-001' in l)
        self.assertIn('SKILL.md:3', lines[broken + 1])
        self.assertNotIn('missing', '\n'.join(lines[broken:broken + 3]))

    def test_where_to_start_begins_with_the_key(self):
        text = self._text()
        start = text.split('С ЧЕГО НАЧАТЬ')[1]
        first_step = [l for l in start.splitlines() if l.strip().startswith('1.')][0]
        self.assertIn('смените ключ', first_step)
        self.assertIn(self.key_at, start)

    def _dup(self, fid, file='AGENTS.md'):
        return {'fid': fid, 'gate': 'G3', 'category': 'rules',
                'severity': 'low', 'status': 'warn', 'title': 'x',
                'description': '', 'evidence': [{'file': file}],
                'confidence': 0.7, 'recommendation': 'x',
                'autofix_available': False,
                'check_id': 'INSTR_DUPLICATION', 'harness': 'a/b'}

    def test_many_findings_of_one_kind_are_counted_not_listed(self):
        rep = copy.deepcopy(self.rep)
        rep['findings_detailed'] += [self._dup('RUL-%03d' % (900 + i))
                                     for i in range(40)]
        digest = summary.build(rep, 'ru')
        text = summary.render(digest)
        listed = [f for f in digest['findings']
                  if f['code'] == 'INSTR_DUPLICATION']
        # three lines of one kind, then a count: forty equal lines in a
        # row would push everything else out of the digest
        self.assertEqual(len(listed), summary.MAX_PER_KIND)
        self.assertIn('Ещё по типам:', text)
        # the other thirty-seven are counted, not listed
        self.assertIn('Одинаковый текст повторяется в двух файлах '
                      'инструкции x37', text)
        # the open findings of the audited folder are still spelled out
        own = [f for f in digest['findings'] if f['code'] != 'INSTR_DUPLICATION']
        open_ = [f for f in self.rep['findings_detailed']
                 if f['status'] != 'pass']
        self.assertEqual(len(own), len(open_))

    def test_plugin_cache_findings_are_counted_never_listed(self):
        rep = copy.deepcopy(self.rep)
        cache = str(self.home / '.zcode' / 'cli' / 'plugins' / 'cache'
                    / 'some-market' / 'some-plugin' / '1.0.0' / 'skills'
                    / 'x' / 'SKILL.md')
        rep['findings_detailed'] += [
            self._dup('SKL-%03d' % (900 + i), cache) for i in range(5)]
        digest = summary.build(rep, 'ru')
        text = summary.render(digest)
        self.assertFalse([f for f in digest['findings']
                          if 'plugins' in f['where']])
        self.assertEqual(sum(n for _name, n in digest['rest_plugins']), 5)
        self.assertEqual(dict(digest['rest_plugins']),
                         {'Одинаковый текст повторяется в двух файлах '
                          'инструкции': 5})
        self.assertIn('В установленных плагинах', text)
        # the plugin files are named relative to the home, never absolute
        self.assertNotIn(str(self.base), text)

    def test_audited_folder_comes_before_home_in_the_digest(self):
        # same severity and status: the user's own file is listed first
        rep = copy.deepcopy(self.rep)
        rep['findings_detailed'] += [
            self._dup('RUL-901', str(self.home / 'notes' / 'a.md')),
            self._dup('RUL-902', str(self.root / 'own' / 'b.md'))]
        digest = summary.build(rep, 'ru')
        order = [f['id'] for f in digest['findings']
                 if str(f['id']).startswith('RUL-90')]
        self.assertEqual(order, ['RUL-902', 'RUL-901'])

    def test_dead_import_names_the_missing_file(self):
        digest = summary.build(self.rep, 'ru')
        dead = next(f for f in digest['findings']
                    if f['code'] == 'CLAUDE_IMPORT_MISSING')
        self.assertEqual(dead['where'],
                         '~/.claude/CLAUDE.md, @~/claude/absent.md')

    def _key(self, fid, file, line):
        return {'fid': fid, 'gate': 'G6', 'category': 'secrets',
                'severity': 'critical', 'status': 'fail',
                'title': 'Exposed secret in %s:%d' % (file, line),
                'description': '', 'evidence': [{'file': file, 'line': line}],
                'confidence': 0.9, 'recommendation': 'x',
                'autofix_available': False, 'check_id': 'SEC_EXPOSED_SECRET'}

    def test_other_keys_are_counted_per_file(self):
        rep = copy.deepcopy(self.rep)
        files = ['temp/a.json'] * 4 + ['temp/b.md'] * 3
        rep['findings_detailed'] += [
            self._key('SEC-%03d' % (500 + i), f, 3 + i)
            for i, f in enumerate(files)]
        digest = summary.build(rep, 'ru')
        text = summary.render(digest)
        # three keys are spelled out, the rest is a count per file
        self.assertIn('Ещё ключи в файлах: temp/b.md (3); temp/a.json (2).', text)
        self.assertNotIn('В файле лежит пароль или ключ x', text)
        self.assertEqual(digest['rest_files'],
                         [('temp/b.md', 3), ('temp/a.json', 2)])
        # one step for all of them, with their places
        self.assertEqual(digest['start'][0]['places'],
                         [self.key_at, 'temp/a.json:3', 'temp/a.json:4'])

    def test_where_names_unchecked_folders_and_counts_the_rest(self):
        finding = {'check_id': 'SEC_GIT_SIDE_UNVERIFIED',
                   'evidence': [{'repositories': 7, 'paths': ['.', 'a', 'b']}]}
        self.assertEqual(summary.where(finding, self.rep, 'ru'),
                         'самой папки, a, b, и ещё 4')
        self.assertEqual(summary.where(finding, self.rep, 'en'),
                         'the audited folder, a, b, 4 more')

    def test_where_of_the_whole_instruction_chain(self):
        finding = {'check_id': 'RUL_CHAIN_OVER_BUDGET',
                   'evidence': [{'chain': '.', 'bytes': 387890}]}
        self.assertEqual(summary.where(finding, self.rep, 'ru'),
                         'все файлы инструкций вместе (379 КБ)')

    def test_coverage_says_whether_the_folder_is_in_git(self):
        rep = copy.deepcopy(self.rep)
        rep['top_level'].insert(0, {'name': '.', 'kind': 'repo',
                                    'extra': {'tool_dir_ignored': False}})
        text = summary.render(summary.build(rep, 'ru'))
        self.assertIn('Сама папка хранится в Git.', text)
        self.assertIn('Отчёты аудита лежат в папке .agents-doctor, и она не '
                      'исключена из Git.', text)
        rep['top_level'][0]['extra']['tool_dir_ignored'] = True
        text = summary.render(summary.build(rep, 'ru'))
        self.assertNotIn('Отчёты аудита лежат', text)
        # a folder in git without a history scan says why history was
        # not read; a folder without git says there is nothing to scan
        self.assertIn('не проверялась (это медленная проверка', text)
        plain = self._text()
        self.assertNotIn('Сама папка', plain)
        self.assertIn('неприменима, папок с Git нет', plain)

    def test_file_aliases(self):
        root = self.base / 'ws'
        home = self.base / 'home'
        inside = str(root / '.agents' / 'skills' / 'x' / 'SKILL.md')
        in_home = str(home / '.claude' / 'CLAUDE.md')
        # always forward slashes, whatever the system separator is
        self.assertEqual(summary.file_alias(inside, root, home),
                         '.agents/skills/x/SKILL.md')
        self.assertEqual(summary.file_alias(in_home, root, home),
                         '~/.claude/CLAUDE.md')
        self.assertEqual(summary.file_alias('.mcp.json', root, home), '.mcp.json')
        self.assertEqual(summary.file_alias('/definitely/not/here/secret.env',
                                            root, home),
                         '<outside audit area>/secret.env')
        # the letter case of the real path survives
        mixed = str(root / '.agents' / 'skills' / 'Nodesc' / 'SKILL.md')
        self.assertIn('Nodesc', summary.file_alias(mixed, root, home))
        # outside on the same drive, far away: name only
        elsewhere = str(Path(home.anchor) / 'elsewhere' / 'notes.md')
        self.assertEqual(summary.file_alias(elsewhere, root, home),
                         '<outside audit area>/notes.md')

    def test_root_repo_is_the_entry_of_the_audited_folder(self):
        rep = copy.deepcopy(self.rep)
        self.assertIsNone(summary.root_repo(rep))
        entry = {'name': '.', 'kind': 'repo', 'extra': {}}
        rep['top_level'].insert(0, entry)
        self.assertIs(summary.root_repo(rep), entry)


class PartialSkillsSearchTests(unittest.TestCase):
    """A skill search that missed part of a folder is said in the digest,
    in both languages, instead of stopping it. Regression: rendering the
    line raised KeyError for a truncated or an unreadable folder."""

    LINES = (('ru', 'Навыки проверены не полностью: %s.'),
             ('en', 'Skills were not all checked: %s.'))

    def test_truncated_folder_is_named_in_the_digest(self):
        _tmp, _base, root, home = _stand_workspace()
        self.addCleanup(_tmp.cleanup)
        for i in range(3):
            put(home, '.zcode/cli/plugins/cache/p%d/v1/s/SKILL.md' % i,
                '---\nname: s%d\ndescription: "Use when asked"\n---\n' % i)
        with mock.patch.object(audit_scan, 'SKILLS_FOLDER_CAP', 2):
            rep = audit_scan.scan(root, home, False)
        self.assertEqual(rep['skills']['coverage']['truncated'],
                         [{'location': 'plugins-cache', 'scanned': 2,
                           'found': 3, 'cap': 2}])
        for lang, line in self.LINES:
            with self.subTest(lang=lang):
                self.assertIn(line % 'plugins-cache',
                              summary.render(summary.build(rep, lang)))

    def test_unreadable_folder_is_named_in_the_digest(self):
        _tmp, _base, root, home = _stand_workspace()
        self.addCleanup(_tmp.cleanup)
        # a skills path that exists but is not a folder: it cannot be listed
        (home / '.claude' / 'skills').write_text('not a folder',
                                                  encoding='utf-8')
        rep = audit_scan.scan(root, home, False)
        self.assertEqual([f['location']
                          for f in rep['skills']['coverage']['failed']],
                         ['user-claude'])
        for lang, line in self.LINES:
            with self.subTest(lang=lang):
                self.assertIn(line % 'user-claude',
                              summary.render(summary.build(rep, lang)))


class OwnSourceLineTests(unittest.TestCase):
    """The digest says when files of the tool's own source were left out
    of the key check, and how many; nothing is said when there are none."""

    LINES = {
        'ru': 'Собственные файлы самого инструмента (%d) не проверялись на ключи.',
        'en': "The tool's own files (%d) were not checked for keys.",
    }

    def _text(self, skipped, lang):
        rep = {'stats': {'own_source_skipped': skipped}}
        return summary.render(summary.build(rep, lang))

    def test_the_count_is_named_in_both_languages(self):
        for lang, line in self.LINES.items():
            with self.subTest(lang=lang):
                self.assertIn(line % 2, self._text(2, lang))

    def test_no_line_without_such_files(self):
        for skipped in (0, None):
            for lang, line in self.LINES.items():
                with self.subTest(skipped=skipped, lang=lang):
                    self.assertNotIn(line % 0, self._text(skipped, lang))
                    self.assertNotIn(line.split(' (')[0], self._text(skipped, lang))


if __name__ == '__main__':
    unittest.main()
