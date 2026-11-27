"""Regression tests: product bugs found by the integration suite.

Each test pins one end-to-end defect the scenario suite surfaced:
- skills_frontmatter keys malformed-skill records by path (no name parses);
  the gate engine must still find them (path fallback in _skill_meta)
- config_integrity must resolve repo names against the workspace root,
  not the scanner's current working directory
- the dead-harness note must flag project-level .claude/CLAUDE.md while
  leaving the home-level mirror alone (origin tag, not a path prefix)
"""
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / 'skills' / 'agents-doctor' / 'scripts'
sys.path.insert(0, str(SCRIPTS))

import audit_scan  # noqa: E402
import enrich  # noqa: E402
from gates import _skill_meta  # noqa: E402


def force_rmtree(p):
    import shutil
    import stat

    def _onexc(func, path, _exc):
        os.chmod(path, stat.S_IWRITE)
        func(path)
    if sys.version_info >= (3, 12):
        shutil.rmtree(p, onexc=_onexc)
    else:
        shutil.rmtree(p, onerror=lambda func, p, _ei: _onexc(func, p, _ei))


class SkillMetaPathFallback(unittest.TestCase):
    def test_malformed_skill_record_found_by_path(self):
        skill_path = 'X:/ws/.agents/skills/bad/SKILL.md'
        rec = {'frontmatter_ok': False, 'missing_fields': ['name', 'description'],
               'dead_refs': [], 'parser': 'yaml', 'path': skill_path}
        meta = _skill_meta({'name': 'bad', 'path': skill_path},
                           {skill_path: rec})  # keyed by path, name unparseable
        self.assertIs(meta['frontmatter_ok'], False)
        self.assertEqual(meta['missing_fields'], ['name', 'description'])

    def test_name_key_still_wins(self):
        rec = {'frontmatter_ok': True, 'missing_fields': [], 'path': 'p1'}
        meta = _skill_meta({'name': 'good', 'path': 'p1'}, {'good': rec})
        self.assertIs(meta['frontmatter_ok'], True)


class ConfigIntegrityAbsolutePaths(unittest.TestCase):
    def test_repo_config_found_from_foreign_cwd(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            (base / 'ws' / 'repo').mkdir(parents=True)
            (base / 'ws' / 'repo' / '.zcode' / 'config.json').parent.mkdir(parents=True)
            (base / 'ws' / 'repo' / '.zcode' / 'config.json').write_text(
                '{"enabled": true,,', encoding='utf-8')
            foreign_cwd = base / 'elsewhere'
            foreign_cwd.mkdir()
            old_cwd = os.getcwd()
            os.chdir(foreign_cwd)
            try:
                entries = enrich.config_integrity(base / 'ws',
                                                  [str(base / 'ws' / 'repo')])
            finally:
                os.chdir(old_cwd)
            paths = [e['path'] for e in entries]
            self.assertTrue(any('repo' in p for p in paths),
                            'repo config must be found regardless of cwd: %r' % paths)
            bad = [e for e in entries if 'repo' in e['path']]
            self.assertFalse(bad[0]['ok'])


class DeadHarnessOriginFilter(unittest.TestCase):
    def test_project_claude_flagged_home_mirror_not(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            root, home = base / 'ws', base / 'home'
            (root / '.claude').mkdir(parents=True)
            (root / '.claude' / 'CLAUDE.md').write_text(
                '# C\n- one\n- two\n- three\n- four\n', encoding='utf-8')
            (home / '.claude').mkdir(parents=True)
            (home / '.claude' / 'CLAUDE.md').write_text(
                '# mirror\n- a\n- b\n- c\n- d\n', encoding='utf-8')
            old = time.time() - 200 * 86400
            for p in (home / '.claude', home / '.claude' / 'CLAUDE.md'):
                os.utime(p, (old, old))
            rep = audit_scan.scan(root, home)
            notes = ' | '.join(rep['harness']['notes'])
            self.assertIn('.claude', notes)          # project-level flagged
            self.assertNotIn('mirror', notes)        # home mirror untouched
            claude_entries = [e for e in rep['context_files']
                              if e['path'].endswith('CLAUDE.md')]
            self.assertEqual({e.get('origin') for e in claude_entries},
                             {'home', 'project'})


if __name__ == '__main__':
    unittest.main()
