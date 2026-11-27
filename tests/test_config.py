"""Tests for skills/agents-doctor/scripts/config.py.

Four contracts: an empty workspace yields defaults; excludes
suppress paths (status 'suppressed', never 'pass'); thresholds load their
values; a malformed file warns and falls back to defaults whole. The
fallback TOML parser (Python 3.9/3.10) is exercised directly so both
parser paths stay covered regardless of the interpreter running the suite.
"""
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'skills' / 'agents-doctor' / 'scripts'))
import config  # noqa: E402


def _write_cfg(root, text):
    (root / config.CONFIG_NAME).write_text(text, encoding='utf-8')


class DefaultsTests(unittest.TestCase):
    def test_empty_workspace_gets_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = config.load_config(Path(tmp))
        self.assertEqual(cfg, config.DEFAULTS)

    def test_missing_sections_merge_over_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_cfg(root, '[report]\nlang = "ru"\n')
            cfg = config.load_config(root)
        self.assertEqual(cfg['report'], {'lang': 'ru'})
        self.assertEqual(cfg['thresholds'], config.DEFAULTS['thresholds'])
        self.assertEqual(cfg['exclude'], config.DEFAULTS['exclude'])

    def test_returned_dict_is_a_copy(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = config.load_config(Path(tmp))
        cfg['exclude']['files'].append('x.md')
        cfg['thresholds']['max_file_mb'] = 99
        self.assertEqual(config.DEFAULTS['exclude']['files'], [])
        self.assertEqual(config.DEFAULTS['thresholds']['max_file_mb'], 5)


class ExcludeTests(unittest.TestCase):
    def test_excluded_paths_get_suppressed_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_cfg(root, '\n'.join([
                '[exclude]',
                'directories = ["vendor", "scratch"]',
                'files = ["legacy-notes.md"]',
            ]))
            cfg = config.load_config(root)
        self.assertEqual(config.status_for('vendor/lib/util.py', cfg),
                         'suppressed')
        self.assertEqual(config.status_for('src/scratch', cfg), 'suppressed')
        self.assertEqual(config.status_for('docs/legacy-notes.md', cfg),
                         'suppressed')

    def test_non_excluded_paths_still_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_cfg(root, '[exclude]\ndirectories = ["vendor"]\n')
            cfg = config.load_config(root)
        self.assertEqual(config.status_for('src/app.py', cfg), 'pass')
        self.assertEqual(config.status_for('vendorization/app.py', cfg),
                         'pass')  # exact segment match, not substring

    def test_windows_separators_and_rule_exclusion(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_cfg(root, '\n'.join([
                '[exclude]',
                'rules = ["DIR-002"]',
            ]))
            cfg = config.load_config(root)
        self.assertEqual(config.status_for('vendor\\lib\\util.py', cfg),
                         'suppressed' if 'vendor' in cfg['exclude']['directories']
                         else 'pass')
        self.assertTrue(config.is_rule_excluded('DIR-002', cfg))
        self.assertFalse(config.is_rule_excluded('DIR-001', cfg))


class ThresholdTests(unittest.TestCase):
    def test_threshold_values_respected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_cfg(root, '\n'.join([
                '[thresholds]',
                'max_file_mb = 10',
                'junk_fail_gb = 1.5',
            ]))
            cfg = config.load_config(root)
        self.assertEqual(cfg['thresholds']['max_file_mb'], 10)
        self.assertEqual(cfg['thresholds']['junk_fail_gb'], 1.5)

    def test_wrong_type_threshold_is_malformed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_cfg(root, '[thresholds]\nmax_file_mb = "ten"\n')
            with self.assertWarns(UserWarning):
                cfg = config.load_config(root)
        self.assertEqual(cfg, config.DEFAULTS)


class MalformedTests(unittest.TestCase):
    def test_garbage_file_warns_and_returns_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_cfg(root, 'this is not = toml at all [[[\n')
            with self.assertWarns(UserWarning):
                cfg = config.load_config(root)
        self.assertEqual(cfg, config.DEFAULTS)

    def test_wrong_shape_warns_and_returns_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_cfg(root, '[exclude]\ndirectories = "vendor"\n')
            with self.assertWarns(UserWarning):
                cfg = config.load_config(root)
        self.assertEqual(cfg, config.DEFAULTS)

    def test_unreadable_file_warns_and_returns_defaults(self):
        # a directory named like the config file makes the read fail
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / config.CONFIG_NAME).mkdir()
            cfg = config.load_config(root)
        self.assertEqual(cfg, config.DEFAULTS)


class FallbackParserTests(unittest.TestCase):
    """Covers the Python 3.9/3.10 parser directly (tomllib-less path)."""

    def test_full_format_parsed(self):
        text = '\n'.join([
            '# comment line',
            '[exclude]',
            'directories = ["vendor", "scratch"]',
            'files = []',
            '',
            '[thresholds]',
            'max_file_mb = 8',
            'junk_fail_gb = 0.25',
            '',
            '[report]',
            'lang = "ru"',
        ])
        data = config._parse_fallback_toml(text)
        self.assertEqual(data['exclude']['directories'], ['vendor', 'scratch'])
        self.assertEqual(data['exclude']['files'], [])
        self.assertEqual(data['thresholds']['max_file_mb'], 8)
        self.assertEqual(data['thresholds']['junk_fail_gb'], 0.25)
        self.assertEqual(data['report']['lang'], 'ru')

    def test_garbage_raises_value_error(self):
        with self.assertRaises(ValueError):
            config._parse_fallback_toml('not toml [[[')

    def test_validated_fallback_output_passes_validation(self):
        text = ('[exclude]\ndirectories = ["vendor"]\n'
                '[thresholds]\nmax_file_mb = 3\njunk_fail_gb = 0.1\n'
                '[report]\nlang = "en"\n')
        data = config._parse_fallback_toml(text)
        self.assertIsNone(config._validate(data))
        merged = config._merge(data)
        self.assertEqual(merged['exclude']['directories'], ['vendor'])
        self.assertEqual(merged['thresholds']['max_file_mb'], 3)


if __name__ == '__main__':
    unittest.main()
