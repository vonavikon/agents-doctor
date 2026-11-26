"""The text the plugin ships must load: the frontmatter of SKILL.md and
of the command file parses and carries a description. A harness that
cannot parse the frontmatter drops the description or the whole file,
and an unquoted "word: word" inside a plain value is exactly what breaks
it (the same mistake breaks skill headers).
"""
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'skills' / 'agents-doctor' / 'scripts'))

import enrich  # noqa: E402

try:
    import yaml
except ImportError:     # the scanner's own fallback parser is the judge
    yaml = None

SHIPPED = [REPO / 'skills' / 'agents-doctor' / 'SKILL.md',
           REPO / 'commands' / 'agents-doctor.md']
DESCRIPTION_LIMIT = 1024


def _frontmatter(path):
    text = path.read_text(encoding='utf-8')
    return text.split('---', 2)[1] if text.startswith('---') else ''


class ShippedFrontmatterTests(unittest.TestCase):

    def test_the_files_exist(self):
        for path in SHIPPED:
            self.assertTrue(path.is_file(), path)

    def test_frontmatter_parses_with_the_scanner(self):
        # with or without PyYAML on the machine: both parsers must agree
        for path in SHIPPED:
            records = enrich.skills_frontmatter([{'path': str(path)}])
            record = next(iter(records.values()))
            self.assertFalse(record.get('parse_error'),
                             '%s: %s' % (path.name, record.get('parse_error')))
            self.assertTrue(record.get('frontmatter_ok'), path.name)
            self.assertNotIn('description', record.get('missing_fields') or [],
                             path.name)

    @unittest.skipIf(yaml is None, 'PyYAML not installed')
    def test_frontmatter_is_yaml_with_a_description(self):
        for path in SHIPPED:
            meta = yaml.safe_load(_frontmatter(path))
            self.assertIsInstance(meta, dict, path.name)
            self.assertTrue(str(meta.get('description') or '').strip(),
                            path.name)

    def test_description_fits_the_harness_limit(self):
        for path in SHIPPED:
            line = next(l for l in _frontmatter(path).splitlines()
                        if l.startswith('description:'))
            self.assertLessEqual(len(line) - len('description: '),
                                 DESCRIPTION_LIMIT, path.name)


if __name__ == '__main__':
    unittest.main()
