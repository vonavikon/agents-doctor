"""Tests for skills/agents-doctor/scripts/glossary.py: the plain names
of every gate, finding type and "not checked" reason.

The glossary must cover every check the code can emit: a check without
a plain name fails here, and so does an entry whose check is gone. The
generated reference file must not drift from the module.
"""
import re
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCRIPTS = REPO / 'skills' / 'agents-doctor' / 'scripts'
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(REPO / 'tests' / 'integration'))

import glossary  # noqa: E402
from fixtures import DASH  # noqa: E402

CHECK_PREFIXES = ('SEC|SKL|RUL|DIR|CFG|GIT|GOV|HLTH|FACTS|INSTR|CLAUDE|CODEX|'
                  'CURSOR|GEMINI|OPENCODE|COPILOT|WINDSURF|ZCODE')
# any upper-case code literal with one of the check prefixes: a check id
# is passed as a literal or picked by a conditional expression
CHECK_LIT_RE = re.compile(r"'((?:%s)_[A-Z0-9_]+)'" % CHECK_PREFIXES)
WHY_RE = re.compile(r"why='([a-z_]+)'")


def _codes_in_code():
    """Every check_id and why code the shipped code can emit."""
    checks, whys = set(), set()
    for path in [SCRIPTS / 'gates.py'] + sorted(
            (SCRIPTS / 'harness' / 'adapters').glob('*.py')):
        checks |= set(CHECK_LIT_RE.findall(path.read_text(encoding='utf-8')))
    whys |= set(WHY_RE.findall((SCRIPTS / 'gates.py').read_text(encoding='utf-8')))
    collect = (SCRIPTS / 'harness' / 'collect.py').read_text(encoding='utf-8')
    assert "'INSTR_%s' % c.get('kind', '').upper()" in collect
    for kind in ('CONTRADICTION', 'DUPLICATION', 'DIVERGENCE'):
        checks.add('INSTR_' + kind)
    return checks, whys


class GlossaryCoverageTests(unittest.TestCase):
    """A check the code can emit must have a plain name, and nothing
    else may: codes and glossary are kept in step by this test."""

    def test_every_check_has_a_plain_name_and_no_stale_one(self):
        checks, _whys = _codes_in_code()
        self.assertEqual(checks - set(glossary.KINDS) - set(glossary.ADAPTER_KINDS),
                         set(), 'checks without a glossary entry')
        self.assertEqual((set(glossary.KINDS) | set(glossary.ADAPTER_KINDS)) - checks,
                         set(), 'glossary entries for checks that no longer exist')

    def test_every_why_code_has_a_reason(self):
        _checks, whys = _codes_in_code()
        self.assertEqual(whys - set(glossary.REASONS), set(),
                         'why codes without a reason text')

    def test_entries_are_complete_and_plain(self):
        kinds = dict(glossary.KINDS)
        kinds.update(glossary.ADAPTER_KINDS)
        for code, entry in kinds.items():
            for lang in glossary.LANGS:
                title = entry[lang]['title'].strip()
                action = entry[lang]['action'].strip()
                self.assertTrue(title and action, (code, lang))
                self.assertLessEqual(len(title.split()), 14, (code, lang, title))
                self.assertNotIn(DASH, title + action, (code, lang))
                # '<file.md>' reads as an HTML tag in Markdown
                self.assertNotRegex(action, r'<[A-Za-z.][^>\n]{0,40}>', (code, lang))
            self.assertNotIn('!', entry['ru']['title'] + entry['ru']['action'], code)
            for word in ('является', 'осуществля', 'в целях', 'в рамках',
                         'данный', 'данных', 'данное'):
                self.assertNotIn(word, entry['ru']['title'] + entry['ru']['action'],
                                 (code, word))

    def test_reference_file_is_up_to_date(self):
        r = subprocess.run([sys.executable, str(REPO / 'tools' / 'gen_glossary.py'),
                            '--check'], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_action_names_the_missing_field(self):
        finding = {'check_id': 'SKL_REQUIRED_FIELD_MISSING',
                   'evidence': [{'file': 'SKILL.md', 'missing': ['description']}]}
        self.assertEqual(glossary.action_for(finding, 'ru'),
                         'Добавьте недостающее поле в шапку файла (description).')
        self.assertIsNone(glossary.action_for({'check_id': 'NOPE'}, 'ru'))


if __name__ == '__main__':
    unittest.main()
