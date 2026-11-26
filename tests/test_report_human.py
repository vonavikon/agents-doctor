"""Tests for skills/agents-doctor/scripts/report_human.py.

Runs the plain-language generator over the chaos and clean fixtures:
token math sanity, bilingual section structure, the before/after story,
secret discipline (counts only, never values) and the fid-to-plain-
sentence mapping. The generator also runs over scans of the stand
workspace (tests/integration/fixtures.py): every finding with its place
and what to do, and what the report says about a check that could not
run. Python 3.9+.
"""
import copy
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'skills' / 'agents-doctor' / 'scripts'))
sys.path.insert(0, str(REPO / 'tests' / 'integration'))

import audit_scan  # noqa: E402
import report_human  # noqa: E402
import glossary  # noqa: E402
import summary  # noqa: E402
from fixtures import gate_of, put, stand  # noqa: E402

CHAOS = REPO / 'llm-eval' / 'fixtures' / 'chaos.json'
CLEAN = REPO / 'llm-eval' / 'fixtures' / 'clean.json'

EN_HEADERS = [
    '# What the audit found, in plain words',
    '## The short version',
    '## What this costs you',
    '## What is wrong, in plain words',
    '## Next step',
]
EN_BETTER_HEADER = '## What gets better after cleanup'
FID_BULLET_RE = re.compile(r'\([A-Z]{2,4}-\d{1,3}\)\s*$')


def load(path):
    return json.loads(path.read_text(encoding='utf-8'))


def section(md, header):
    """Lines of one '## ' section, without the header line."""
    lines = md.splitlines()
    start = lines.index(header)
    body = []
    for line in lines[start + 1:]:
        if line.startswith('## ') or line.startswith('# '):
            break
        body.append(line)
    return body


def make_after(chaos):
    """A fabricated post-cleanup scan: smaller instructions and memory,
    junk/duplicates/large files emptied, most gates patched but G3 left
    failing so the report still has a 'Still to do' list."""
    after = copy.deepcopy(chaos)
    ct = after['context_tax']
    for f in ct['session_files']:
        if f['role'] == 'project':
            f['size_bytes'] = 9000
        elif f['role'] == 'memory-index':
            f['size_bytes'] = 20000
    ct['project_total_bytes'] = 9000
    ct['memory_over_limit'] = []
    ct['memory_over_lines'] = []
    after['junk'] = {'files': [], 'dirs': [], 'empty_dirs': []}
    after['junk_classified'] = []
    after['duplicates'] = []
    after['large_files'] = []
    after['secrets'] = []
    after['findings_detailed'] = []
    for g in after['gates']:
        g['status'] = 'pass' if g['gid'] != 'G3' else 'fail'
    return after


class TestTokenMath(unittest.TestCase):

    def setUp(self):
        self.chaos = load(CHAOS)

    def test_chaos_overhead_positive(self):
        self.assertGreater(report_human.session_overhead_bytes(self.chaos), 0)

    def test_chaos_overhead_exact(self):
        # project 65242-16384=48858 plus memory 42188-24985=17203,
        # the memory path listed twice (limit + lines) counted once
        self.assertEqual(report_human.session_overhead_bytes(self.chaos),
                         66061)

    def test_mid_is_bytes_div4(self):
        ob = report_human.session_overhead_bytes(self.chaos)
        lo, mid, hi = report_human.token_range(ob)
        self.assertEqual(mid, ob // 4)
        self.assertEqual(mid, report_human.tokens_from_bytes(ob))
        self.assertEqual(lo, ob // 5)
        self.assertEqual(hi, ob // 3)
        self.assertLess(lo, mid)
        self.assertLess(mid, hi)

    def test_clean_overhead_zero(self):
        clean = load(CLEAN)
        self.assertEqual(report_human.session_overhead_bytes(clean), 0)


class TestOutputStructure(unittest.TestCase):

    def setUp(self):
        self.chaos = load(CHAOS)

    def test_en_headers_without_after(self):
        md = report_human.generate_human_markdown(self.chaos, lang='en')
        for h in EN_HEADERS:
            self.assertIn(h, md)
        self.assertNotIn(EN_BETTER_HEADER, md)

    def test_en_headers_with_after(self):
        md = report_human.generate_human_markdown(
            self.chaos, lang='en', after=make_after(self.chaos))
        for h in EN_HEADERS:
            self.assertIn(h, md)
        self.assertIn(EN_BETTER_HEADER, md)

    def test_ru_title_and_no_bureaucratese(self):
        md = report_human.generate_human_markdown(self.chaos, lang='ru')
        self.assertIn('простыми словами', md)
        for word in ('данные', 'данного', 'данной', 'данный', 'данных'):
            self.assertNotIn(word, md)
        self.assertNotIn('!', md)

    def test_ru_headers(self):
        md = report_human.generate_human_markdown(self.chaos, lang='ru')
        for h in ('## Коротко', '## Во сколько это обходится',
                  '## Что не так, по-человечески', '## Что дальше'):
            self.assertIn(h, md)

    def test_footer_honesty_lines(self):
        md = report_human.generate_human_markdown(self.chaos, lang='en')
        self.assertIn('Read-only audit', md)
        self.assertIn('estimates', md)
        self.assertIn(self.chaos['generated_at'], md)


class TestCostsSection(unittest.TestCase):

    def setUp(self):
        self.chaos = load(CHAOS)

    def test_assumption_line_default_sessions(self):
        md = report_human.generate_human_markdown(self.chaos, lang='en')
        self.assertIn('assumes 10 agent sessions a day', md)

    def test_assumption_line_custom_sessions(self):
        md = report_human.generate_human_markdown(
            self.chaos, lang='en', sessions_per_day=4)
        self.assertIn('assumes 4 agent sessions a day', md)

    def test_ru_assumption_line(self):
        md = report_human.generate_human_markdown(self.chaos, lang='ru')
        self.assertIn('10 запусков агента в день', md)

    def test_token_numbers_present(self):
        md = report_human.generate_human_markdown(self.chaos, lang='en')
        lo, mid, hi = report_human.token_range(
            report_human.session_overhead_bytes(self.chaos))
        self.assertIn(f'{lo:,}', md)
        self.assertIn(f'{mid:,}', md)
        self.assertIn(f'{hi:,}', md)

    def test_memory_and_disk_cards(self):
        md = report_human.generate_human_markdown(self.chaos, lang='en')
        self.assertIn('never sees', md)          # memory over limit
        self.assertIn('MB', md)                  # 8 MB large file

    def test_clean_report_zero_cards(self):
        clean = load(CLEAN)
        md = report_human.generate_human_markdown(clean, lang='en')
        self.assertIn('fit within healthy sizes', md)
        # clean still has one 46-byte junk file, so the disk card shows it
        self.assertIn('46 bytes', md)
        self.assertIn('No passwords or keys are lying in plain sight', md)

    def test_disk_zero_card_on_synthetic_report(self):
        minimal = {'root': 'C:/tmp/ws', 'generated_at': '2026-11-16T12:00:00',
                   'gates': [{'gid': 'G1', 'status': 'pass'}]}
        md = report_human.generate_human_markdown(minimal, lang='en')
        self.assertIn('No junk, duplicates or oversized files', md)

    def test_clean_main_problem_not_a_password_alarm(self):
        clean = load(CLEAN)
        md = report_human.generate_human_markdown(clean, lang='en')
        # the missing key check is the main problem, named as the
        # glossary names it; it is not an exposed password
        self.assertIn('Nothing stops keys from getting into project history', md)
        self.assertNotIn('The main problem: A password or key', md)


class TestSecretDiscipline(unittest.TestCase):

    def test_counts_only_never_values(self):
        chaos = load(CHAOS)
        for lang in ('en', 'ru'):
            md = report_human.generate_human_markdown(chaos, lang=lang)
            self.assertNotIn('sk-', md)          # not even the mask
            self.assertNotIn('REDACTED', md)
            self.assertNotIn('sha256', md)       # no fingerprints
            self.assertNotIn('.mcp.json:6', md)  # no file:line of the secret

    def test_secret_count_matches_findings(self):
        chaos = load(CHAOS)
        md = report_human.generate_human_markdown(chaos, lang='en')
        self.assertIn('2 passwords or keys', md)


class TestPlainMapping(unittest.TestCase):

    def setUp(self):
        self.chaos = load(CHAOS)
        self.md = report_human.generate_human_markdown(self.chaos, lang='en')

    def test_bullets_end_with_fid(self):
        body = section(self.md, '## What is wrong, in plain words')
        bullets = [l for l in body if l.startswith('- ')]
        self.assertTrue(bullets)
        self.assertLessEqual(len(bullets), 6)
        for b in bullets:
            self.assertRegex(b, FID_BULLET_RE)

    def test_all_chaos_categories_map_to_sentences(self):
        categories = {f.get('category') for f
                      in self.chaos['findings_detailed']}
        for f in self.chaos['findings_detailed']:
            sentence = report_human.plain_sentence(self.chaos, f, 'en')
            self.assertTrue(sentence)
            self.assertNotIn('unknown', sentence.lower())
        self.assertIn('secrets', categories)
        self.assertIn('dirs', categories)
        self.assertIn('rules', categories)

    def _by_check(self, check_id):
        return next(f for f in self.chaos['findings_detailed']
                    if f['check_id'] == check_id)

    def test_required_contract_sentences(self):
        checks = [
            ('SEC_EXPOSED_SECRET', 'A password/key is sitting in a file '
                                   'where it should not be'),
            ('RUL_DEAD_REFERENCE', "The agent's instructions point to "
                                   'things that do not exist'),
            ('DIR_INSTRUCTION_PAIR_DRIFT',
             'Two instruction files disagree — the agent gets '
             'conflicting rules'),
            ('SKL_DESCRIPTION_TOO_LONG',
             'A helper skill is set up wrong and never runs'),
            ('GIT_UNCOMMITTED_WORK', 'Work is not saved to history yet'),
            ('GOV_DEAD_HARNESS_INSTRUCTIONS',
             'Rules are kept for a tool nobody has used in months'),
            ('HLTH_UNUSED_DATA', 'Unused files and old copies are piling '
                                 'up in the workspace'),
            ('RUL_GENERIC_BOILERPLATE',
             'Part of the instructions is template text that gives the '
             'agent no useful rules'),
            ('RUL_FILE_TOO_BIG', 'The instructions have grown too big; '
                                 'the agent pays for the extra on every '
                                 'start'),
        ]
        for check_id, expected in checks:
            # the category mapping serves scans made before findings
            # carried a check id
            legacy = dict(self._by_check(check_id))
            legacy.pop('check_id', None)
            self.assertEqual(
                report_human.plain_sentence(self.chaos, legacy, 'en'),
                expected, check_id)
            # a current scan names the same finding through the glossary
            self.assertEqual(
                report_human.plain_title(self.chaos,
                                         self._by_check(check_id), 'en'),
                glossary.kind(check_id)['en']['title'], check_id)
        # a nested repository is no longer part of the fixture (its outer
        # repository keeps it out with .gitignore): the category mapping
        # is checked on a finding of that shape
        nested = {'category': 'dirs',
                  'title': 'Nested repository in legacy-crm: vendor/engine',
                  'evidence': []}
        self.assertEqual(
            report_human.plain_sentence(self.chaos, nested, 'en'),
            'One project sits inside another project, which confuses '
            'backup and sync tools')
        # the two that do reach the rendered top-6 list
        self.assertIn('A password or key is sitting in a file', self.md)
        self.assertIn('Two instruction files have grown apart', self.md)

    def test_heavy_dir_sentence_carries_size(self):
        finding = dict(self._by_check('DIR_HEAVY_OUTSIDE_GIT'))
        finding.pop('check_id', None)      # category mapping, as above
        sentence = report_human.plain_sentence(self.chaos, finding, 'en')
        self.assertEqual(
            sentence, 'A folder with 8 MB of data has no backup and '
                      'no history')

    def test_main_problem_is_first_critical(self):
        body = section(self.md, '## The short version')
        joined = ' '.join(body)
        self.assertIn('The main problem: A password or key is sitting '
                      'in a file', joined)


class TestBeforeAfter(unittest.TestCase):

    def setUp(self):
        self.chaos = load(CHAOS)
        self.after = make_after(self.chaos)
        self.md = report_human.generate_human_markdown(
            self.chaos, lang='en', after=self.after)

    def test_improvement_sentences(self):
        self.assertIn('fewer tokens every session', self.md)
        self.assertIn('slimmed from 63.7 KB to 8.8 KB', self.md)
        self.assertIn('went from about 16,515 to 0', self.md)  # tokens/start
        self.assertIn('Secrets in plain sight went from 2 to none', self.md)

    def test_tokens_after_less_than_before(self):
        before = report_human.session_overhead_bytes(self.chaos)
        after = report_human.session_overhead_bytes(self.after)
        self.assertLess(after, before)
        self.assertEqual(after, 0)

    def test_still_to_do_when_fail_gate_remains(self):
        self.assertIn('Still to do', self.md)
        self.assertIn('fix the instruction files', self.md)  # G3 plain words

    def test_no_still_to_do_when_all_green(self):
        all_green = copy.deepcopy(self.after)
        for g in all_green['gates']:
            g['status'] = 'pass'
        md = report_human.generate_human_markdown(
            self.chaos, lang='en', after=all_green)
        self.assertNotIn('Still to do', md)

    def test_ru_better_section(self):
        md = report_human.generate_human_markdown(
            self.chaos, lang='ru', after=self.after)
        self.assertIn('Что станет лучше после уборки', md)
        self.assertIn('Ещё осталось', md)
        self.assertIn('токенов меньше при каждом запуске', md)


class TestNumberFormatting(unittest.TestCase):

    def test_en_commas_ru_spaces(self):
        self.assertEqual(report_human.fmt_int(1234, 'en'), '1,234')
        self.assertEqual(report_human.fmt_int(1234, 'ru'),
                         '1' + '\u202f' + '234')

    def test_human_units(self):
        thin = report_human.THIN
        self.assertEqual(report_human.human_bytes(8388608, 'en'), '8 MB')
        self.assertEqual(report_human.human_bytes(8388608, 'ru'),
                         '8' + thin + 'МБ')
        self.assertIn('КБ', report_human.human_bytes(14282, 'ru'))
        self.assertIn('KB', report_human.human_bytes(14282, 'en'))

    def test_ru_decimal_comma(self):
        self.assertEqual(report_human.human_bytes(65242, 'ru'),
                         '63,7' + report_human.THIN + 'КБ')


class PlainReportTests(unittest.TestCase):
    """The plain report over a scan of the stand workspace."""

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
        cls.key_at = '.mcp.json:%d' % cls.key['evidence'][0]['line']
        cls.key_at_words = 'файл .mcp.json, строка %d' % cls.key['evidence'][0]['line']
        cls.key_at_words_en = 'file .mcp.json, line %d' % cls.key['evidence'][0]['line']
        cls.md = report_human.generate_human_markdown(cls.rep, lang='ru')
        cls.lines = cls.md.splitlines()

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def _section(self, header):
        return section(self.md, header)

    def test_the_key_comes_first_with_its_file_and_line(self):
        short = self._section('## Коротко')
        self.assertIn('пароли или ключи', ' '.join(short))
        start_line = [l for l in short if l.startswith('Начните с этого:')][0]
        self.assertIn(self.key_at_words, start_line)
        # the generic "cleanup makes the agent faster" promise is gone
        # when a key is the main problem
        self.assertNotIn('После уборки', ' '.join(short))
        self.assertNotIn('тормозить агента', ' '.join(short))

    def test_every_finding_says_where_and_what_to_do(self):
        wrong = [l for l in self._section('## Что не так, по-человечески')
                 if l.startswith('- ')]
        self.assertTrue(wrong)
        for line in wrong:
            self.assertRegex(line, r'\([A-Z]+-\d+\)$')
        key_line = [l for l in wrong if l.endswith('(%s)' % self.key['fid'])][0]
        self.assertIn(self.key_at_words, key_line)
        self.assertIn('Что сделать: сначала смените ключ', key_line)
        skill_line = [l for l in wrong if l.endswith('(SKL-001)')][0]
        self.assertIn('SKILL.md, строка 3', skill_line)
        field_line = [l for l in wrong if l.endswith('(SKL-002)')][0]
        self.assertIn('(description)', field_line)

    def test_where_to_start_is_taken_from_the_findings(self):
        steps = [l for l in self._section('## Что дальше')
                 if re.match(r'^\d+\. ', l)]
        self.assertTrue(steps)
        self.assertIn('смените ключ', steps[0])
        self.assertIn(self.key_at_words, steps[0])

    def test_no_hook_advice_without_git(self):
        self.assertNotIn('pre-commit', self.md)
        self.assertNotIn('защит', self.md.lower())

    def test_suggestions_section_names_what_can_be_better(self):
        self.assertIn('## Что можно улучшить', self.md)
        improve = ' '.join(self._section('## Что можно улучшить'))
        # a two-line instruction file is a hint, not "filler"
        self.assertIn('AGENTS.md короткий', improve)
        self.assertNotIn('агент читает без пользы', improve)
        # a few hundred bytes of junk are not worth a suggestion
        self.assertNotIn('Разберите мусор', improve)

    def test_a_finding_line_is_not_repeated_as_a_suggestion(self):
        root, home = self.base / 'noisy', self.base / 'home-noisy'
        root.mkdir()
        home.mkdir()
        stand(root, home)
        (root / 'CLAUDE.md').write_text(
            '# Rules\n\n' + 'This folder was started long ago and keeps the '
            'history of every change made in it.\n' * 80,
            encoding='utf-8')
        rep = audit_scan.scan(root, home, False)
        md = report_human.generate_human_markdown(rep, 'ru')
        # every file with few rules has a line of its own
        self.assertIn('В файле инструкций много текста без конкретных '
                      'правил: файл CLAUDE.md', md)
        improve = md.split('## Что можно улучшить')[1].split('## Что дальше')[0]
        self.assertNotIn('CLAUDE.md конкретные правила', improve)
        # and so in the digest
        digest = summary.build(rep, 'ru')
        noise = [f for f in digest['findings']
                 if f['code'] == 'RUL_MOSTLY_NOISE']
        self.assertEqual([f['where'] for f in noise], ['CLAUDE.md'])

    def _finding(self, fid, check_id, severity, status, evidence, title='x'):
        return {'fid': fid, 'gate': 'G5', 'category': 'skills',
                'severity': severity, 'status': status, 'title': title,
                'description': '', 'evidence': evidence, 'confidence': 0.9,
                'recommendation': 'x', 'autofix_available': False,
                'check_id': check_id}

    def test_findings_of_installed_plugins_do_not_lead_the_report(self):
        rep = copy.deepcopy(self.rep)
        # the user's own problems are the two skills; a broken skill of
        # an installed plugin has the same severity
        rep['findings_detailed'] = [
            f for f in rep['findings_detailed'] if f['gate'] != 'G6']
        cache = (self.home / '.zcode' / 'cli' / 'plugins' / 'cache' / 'mkt'
                 / 'core' / '1.0.0' / 'skills' / 'evil-helper' / 'SKILL.md')
        rep['findings_detailed'].append(self._finding(
            'SKL-900', 'SKL_FRONTMATTER_INVALID', 'high', 'fail',
            [{'file': str(cache), 'error_line': 3}],
            "Frontmatter of skill 'evil-helper' does not parse (line 3)"))
        md = report_human.generate_human_markdown(rep, 'ru')
        wrong = md.split('## Что не так, по-человечески')[1].split('## ')[0]
        bullets = [l for l in wrong.splitlines() if l.startswith('- ')]
        self.assertTrue(all('evil-helper' not in b for b in bullets))
        self.assertIn('.agents/skills/', bullets[0])
        self.assertIn('В установленных плагинах ещё 1 находка', wrong)
        self.assertNotIn('evil-helper', md.split('## Что дальше')[1])

    def test_keys_in_ignored_settings_are_not_on_view(self):
        rep = copy.deepcopy(self.rep)
        for f in rep['findings_detailed']:
            if f['check_id'] == 'SEC_EXPOSED_SECRET':
                f['status'], f['severity'] = 'warn', 'medium'
                f['evidence'][0]['git'] = 'ignored'
        md = report_human.generate_human_markdown(rep, 'ru')
        self.assertIn('Паролей и ключей на виду нет.', md)
        self.assertIn('Ключи в файлах настроек, которые Git не видит: 1 (', md)
        self.assertNotIn('осталось 1 пароль', md)

    def test_many_findings_of_one_kind_end_in_a_count(self):
        rep = copy.deepcopy(self.rep)
        dead = next(f for f in rep['findings_detailed']
                    if f['check_id'] == 'CLAUDE_IMPORT_MISSING')
        for i in range(4):
            extra = copy.deepcopy(dead)
            extra['fid'] = 'RUL-%03d' % (910 + i)
            rep['findings_detailed'].append(extra)
        md = report_human.generate_human_markdown(rep, 'ru')
        wrong = md.split('## Что не так, по-человечески')[1].split('## ')[0]
        bullets = [l for l in wrong.splitlines()
                   if l.startswith('- Claude Code подключает через')]
        self.assertEqual(len(bullets), report_human.MAX_SAME_KIND)
        counted = [l for l in wrong.splitlines() if l.startswith('Остальное')]
        self.assertEqual(len(counted), 1)
        self.assertIn('Claude Code подключает через @ несуществующий файл x2',
                      counted[0])

    def test_english_report_has_the_same_shape(self):
        md = report_human.generate_human_markdown(self.rep, lang='en')
        self.assertIn('Start here:', md)
        self.assertIn(self.key_at_words_en, md)
        self.assertIn('What to do: First have the key reissued', md)
        self.assertIn('## What you can make better', md)
        self.assertNotIn(str(self.base), md)


class NotCheckedTests(unittest.TestCase):
    """A check that could not run is never summed up as fine: the short
    version names the checks, a section of its own gives the reason for
    each. A check that merely does not apply stays out."""

    H_SHORT = {'ru': '## Коротко', 'en': '## The short version'}
    H_WRONG = {'ru': '## Что не так, по-человечески',
               'en': '## What is wrong, in plain words'}
    H_SECTION = {'ru': '## Что не удалось проверить',
                 'en': '## What could not be checked'}
    H_IMPROVE = {'ru': '## Что можно улучшить', 'en': '## What you can make better'}
    SENTENCE = {
        'ru': 'Не проверено (%d): %s. Эти проверки не удалось выполнить, '
              'об их результате ничего не известно.',
        'en': 'Not checked (%d): %s. These checks could not run, so the '
              'audit says nothing about them.',
    }

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.base = Path(cls._tmp.name)
        cls.root, cls.home = cls.base / 'ws', cls.base / 'home'
        cls.root.mkdir()
        cls.home.mkdir()
        # a folder with nothing wrong except its skills: three skills in
        # the plugin cache, the per-folder cap set to two. The skill
        # check then ends unknown, with a recorded reason.
        put(cls.root, 'AGENTS.md', '# Demo\n\nRules are in the handbook.\n')
        for i in range(3):
            put(cls.home, '.zcode/cli/plugins/cache/p%d/v1/s/SKILL.md' % i,
                '---\nname: s%d\ndescription: "Use when asked"\n---\n' % i)
        with mock.patch.object(audit_scan, 'SKILLS_FOLDER_CAP', 2):
            cls.rep = audit_scan.scan(cls.root, cls.home, False)
        gate = gate_of(cls.rep, 'G5')
        cls.gate_5 = {'status': gate['status'], 'why': gate.get('status_why')}

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def _report(self, rep, lang):
        return report_human.generate_human_markdown(rep, lang=lang)

    def _lines(self, md, header):
        """Non-empty lines of one section, without the header."""
        return [line for line in section(md, header) if line.strip()]

    def test_the_skill_check_ends_unknown_with_a_reason(self):
        # the fixture of this class: what the report has to work with
        self.assertEqual(self.gate_5, {'status': 'unknown',
                                       'why': 'skills_search_incomplete'})

    def test_short_version_names_the_checks_that_could_not_run(self):
        for lang in ('ru', 'en'):
            with self.subTest(lang=lang):
                short = ' '.join(section(self._report(self.rep, lang),
                                         self.H_SHORT[lang]))
                self.assertIn(self.SENTENCE[lang]
                              % (1, glossary.gate_name('G5', lang)), short)

    def test_section_lists_the_unknown_gate_with_its_reason(self):
        for lang in ('ru', 'en'):
            with self.subTest(lang=lang):
                md = self._report(self.rep, lang)
                gate = gate_of(self.rep, 'G5')
                reason = glossary.reason_text(gate['status_why'], lang,
                                              gate.get('status_count'))
                self.assertEqual(self._lines(md, self.H_SECTION[lang]),
                                 ['- %s: %s' % (glossary.gate_name('G5', lang),
                                                reason)])

    def test_a_check_that_could_not_run_inside_a_red_gate_is_listed(self):
        rep = copy.deepcopy(self.rep)
        unseen = {'fid': 'SEC-900', 'gate': 'G6', 'category': 'secrets',
                  'severity': 'medium', 'status': 'unknown',
                  'title': '2 repositories inside the audited area not checked',
                  'evidence': [{'repositories': 2, 'paths': ['projects/a', 'projects/b']}],
                  'confidence': 0.9,
                  'recommendation': 'Audit each separately.',
                  'autofix_available': False,
                  'check_id': 'SEC_GIT_SIDE_UNVERIFIED'}
        rep['findings_detailed'].append(unseen)
        # the gate is yellow for another reason: its whole check ran, one
        # part of it did not
        gate_of(rep, 'G6').update(status='warn')
        action = {'ru': 'каждую из этих папок отдельным аудит',
                  'en': 'Check each of those folders'}
        for lang in ('ru', 'en'):
            with self.subTest(lang=lang):
                md = self._report(rep, lang)
                # nothing to fix: not among the findings
                self.assertFalse([l for l in self._lines(md, self.H_WRONG[lang])
                                  if '(SEC-900)' in l])
                listed = [l for l in self._lines(md, self.H_SECTION[lang])
                          if '(SEC-900)' in l]
                self.assertEqual(len(listed), 1)
                self.assertIn(glossary.title_for(unseen, lang), listed[0])
                self.assertIn('projects/a, projects/b', listed[0])
                self.assertIn(action[lang], listed[0])
                short = ' '.join(section(md, self.H_SHORT[lang]))
                self.assertIn(report_human.STRINGS[lang]['not_checked_parts']
                              .format(n=1), short)
        # an unknown gate says it already: its findings are not repeated
        gate_of(rep, 'G6').update(status='unknown',
                                  status_why='git_nested_unverified', status_count=2)
        md = self._report(rep, 'ru')
        self.assertFalse([l for l in self._lines(md, self.H_SECTION['ru'])
                          if '(SEC-900)' in l])
        self.assertEqual(report_human._unchecked_findings(rep), [])

    def test_section_sits_after_the_findings_and_before_the_suggestions(self):
        for lang in ('ru', 'en'):
            with self.subTest(lang=lang):
                lines = self._report(self.rep, lang).splitlines()
                self.assertLess(lines.index(self.H_WRONG[lang]),
                                lines.index(self.H_SECTION[lang]))
                self.assertLess(lines.index(self.H_SECTION[lang]),
                                lines.index(self.H_IMPROVE[lang]))

    def test_every_unknown_gate_gets_its_line_and_its_reason(self):
        rep = copy.deepcopy(self.rep)
        # a reason the glossary knows, with a count; a reason the scan
        # wrote in English only; no reason at all
        gate_of(rep, 'G7').update(status='unknown', status_why='git_nested_unverified',
                                  status_count=3)
        gate_of(rep, 'G8').update(status='unknown', status_reason='facts were not collected')
        gate_of(rep, 'G9').update(status='unknown')
        for lang in ('ru', 'en'):
            with self.subTest(lang=lang):
                md = self._report(rep, lang)
                names = ', '.join(glossary.gate_name(g, lang)
                                  for g in ('G5', 'G7', 'G8', 'G9'))
                short = ' '.join(section(md, self.H_SHORT[lang]))
                self.assertIn(self.SENTENCE[lang] % (4, names), short)
                gate = gate_of(rep, 'G5')
                self.assertEqual(self._lines(md, self.H_SECTION[lang]), [
                    # the reason the scanner recorded, through the glossary;
                    # names only, no gate codes in the plain report
                    '- %s: %s' % (
                        glossary.gate_name('G5', lang),
                        glossary.reason_text(gate['status_why'], lang,
                                             gate.get('status_count'))),
                    # a reason with a count: repositories not read
                    '- %s: %s' % (
                        glossary.gate_name('G7', lang),
                        glossary.reason_text('git_nested_unverified', lang, 3)),
                    # an older report that carries the English sentence only
                    '- %s: facts were not collected'
                    % glossary.gate_name('G8', lang),
                    # nothing recorded: said so, not passed over
                    '- %s: %s' % (
                        glossary.gate_name('G9', lang),
                        report_human.STRINGS[lang]['not_checked_no_reason']),
                ])

    def test_checks_that_do_not_apply_stay_out(self):
        # the stand without the capped skill folder: no check failed to
        # run, one does not apply (git hygiene without git)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = Path(tmp.name)
        root, home = base / 'ws', base / 'home'
        root.mkdir()
        home.mkdir()
        stand(root, home)
        rep = audit_scan.scan(root, home, False)
        self.assertIn('not_applicable', [g['status'] for g in rep['gates']])
        self.assertNotIn('unknown', [g['status'] for g in rep['gates']])
        for lang in ('ru', 'en'):
            with self.subTest(lang=lang):
                md = self._report(rep, lang)
                self.assertNotIn(self.H_SECTION[lang], md)
                self.assertNotIn(self.SENTENCE[lang].split(' (')[0], md)


if __name__ == '__main__':
    unittest.main()
