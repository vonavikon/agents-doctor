"""Tests for the watch module: change detection,
once-mode state semantics, daemon caps, history isolation."""
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / 'skills' / 'agents-doctor' / 'scripts'
sys.path.insert(0, str(SCRIPTS))

import watch  # noqa: E402


def _ws():
    root = Path(tempfile.mkdtemp())
    home = Path(tempfile.mkdtemp())
    return root, home


class FingerprintTest(unittest.TestCase):
    def test_changes_with_content_and_new_files(self):
        root, _ = _ws()
        (root / 'AGENTS.md').write_text('a\n', encoding='utf-8')
        fp1 = watch.config_fingerprint(root)
        (root / 'AGENTS.md').write_text('longer content\n', encoding='utf-8')
        fp2 = watch.config_fingerprint(root)
        (root / 'CLAUDE.md').write_text('b\n', encoding='utf-8')
        fp3 = watch.config_fingerprint(root)
        self.assertNotEqual(fp1, fp2)
        self.assertNotEqual(fp2, fp3)

    def test_stable_when_unchanged(self):
        root, _ = _ws()
        (root / 'AGENTS.md').write_text('a\n', encoding='utf-8')
        self.assertEqual(watch.config_fingerprint(root),
                         watch.config_fingerprint(root))

    def test_unrelated_files_ignored(self):
        root, _ = _ws()
        (root / 'AGENTS.md').write_text('a\n', encoding='utf-8')
        fp1 = watch.config_fingerprint(root)
        (root / 'notes.txt').write_text('noise\n', encoding='utf-8')
        self.assertEqual(fp1, watch.config_fingerprint(root))

    def test_config_dir_change_detected(self):
        root, _ = _ws()
        d = root / '.claude'
        d.mkdir()
        fp1 = watch.config_fingerprint(root)
        (d / 'settings.json').write_text('{}', encoding='utf-8')
        self.assertNotEqual(fp1, watch.config_fingerprint(root))


class OnceModeTest(unittest.TestCase):
    def test_scan_only_on_change(self):
        root, home = _ws()
        (root / 'AGENTS.md').write_text('# x\nAlways run tests\n',
                                        encoding='utf-8')
        n1 = watch.watch(root, home=home, once=True)
        n2 = watch.watch(root, home=home, once=True)
        (root / 'AGENTS.md').write_text(
            '# y\nNever run tests manually\n', encoding='utf-8')
        n3 = watch.watch(root, home=home, once=True)
        self.assertEqual((n1, n2, n3), (1, 0, 1))

    def test_state_file_written(self):
        root, home = _ws()
        (root / 'AGENTS.md').write_text('a\n', encoding='utf-8')
        watch.watch(root, home=home, once=True)
        state = root / '.agents-doctor' / 'watch-state.json'
        self.assertTrue(state.is_file())

    def test_empty_workspace_no_scan(self):
        root, home = _ws()
        self.assertEqual(watch.watch(root, home=home, once=True), 0)


class DaemonModeTest(unittest.TestCase):
    def test_max_runs_stops_loop(self):
        root, home = _ws()
        (root / 'AGENTS.md').write_text('a\n', encoding='utf-8')
        # baseline scan counts as run 1; max_runs stops immediately
        n = watch.watch(root, home=home, interval=1, max_runs=1)
        self.assertEqual(n, 1)

    def test_history_failure_never_kills_watch(self):
        root, home = _ws()
        (root / 'AGENTS.md').write_text('a\n', encoding='utf-8')
        # force the lazy history import to fail
        import builtins
        real_import = builtins.__import__

        def broken(name, *a, **k):
            if name == 'audit_history':
                raise ImportError('no history in this test')
            return real_import(name, *a, **k)

        builtins.__import__ = broken
        try:
            n = watch.watch(root, home=home, once=True)
        finally:
            builtins.__import__ = real_import
        self.assertEqual(n, 1)


if __name__ == '__main__':
    unittest.main()
