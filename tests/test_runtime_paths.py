"""Smoke test: every entry script runs from an unrelated current
directory, against a COPY of the plugin tree (no repo checkout, no path
inside the audited workspace) — proving launch paths do not depend on
where the plugin is installed or where the user stands.
"""
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCRIPTS = REPO / 'skills' / 'agents-doctor' / 'scripts'
ENTRY_POINTS = ['audit_scan.py', 'agents_doctor.py', 'report_generator.py',
                'report_human.py', 'sarif.py', 'safe_clean.py',
                'remediate.py', 'secret_scanner.py', 'fingerprint.py']


def _force_rmtree(p):
    def _onexc(func, path, _exc):
        os.chmod(path, stat.S_IWRITE)
        func(path)
    if sys.version_info >= (3, 12):
        shutil.rmtree(p, onexc=_onexc)
    else:
        shutil.rmtree(p, onerror=lambda f, q, _i: _onexc(f, q, _i))


class RuntimePathsTest(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp())
        self.addCleanup(_force_rmtree, self.base)
        # a fake "installed" plugin location, far from the repo layout
        self.installed = self.base / 'plugins' / 'cache' / 'market' / 'wa-9'
        dst = self.installed / 'skills' / 'agents-doctor' / 'scripts'
        dst.parent.mkdir(parents=True)
        shutil.copytree(SCRIPTS, dst)
        self.cwd = self.base / 'unrelated' / 'current' / 'dir'
        self.cwd.mkdir(parents=True)

    def _run(self, script, *args, timeout=120):
        proc = subprocess.run(
            [sys.executable, str(self.installed / 'skills' / 'agents-doctor'
                                 / 'scripts' / script), *args],
            capture_output=True, text=True, encoding='utf-8',
            errors='replace', cwd=self.cwd, timeout=timeout)
        self.assertEqual(proc.returncode, 0,
                         '%s failed:\n%s\n%s' % (script, proc.stdout[-300:],
                                                  proc.stderr[-500:]))
        return proc

    def test_help_from_foreign_cwd(self):
        for script in ENTRY_POINTS:
            self._run(script, '--help')

    def test_full_audit_from_foreign_cwd_on_copied_tree(self):
        ws = self.base / 'ws'
        home = self.base / 'home'
        (ws / '.agents').mkdir(parents=True)
        (ws / '.agents' / 'AGENTS.md').write_text('# rules\n- be brief\n',
                                                  encoding='utf-8')
        home.mkdir()
        out = self.base / 'scan.json'
        self._run('audit_scan.py', str(ws), '--home', str(home),
                  '--out', str(out))
        self.assertTrue(out.exists())
        report = self.base / 'AUDIT.md'
        self._run('report_generator.py', str(out), '--out', str(report))
        self.assertIn('Agents Doctor', report.read_text(encoding='utf-8')[:400])

    def test_skill_doc_has_no_cwd_dependent_command(self):
        text = (REPO / 'skills' / 'agents-doctor' / 'SKILL.md').read_text(
            encoding='utf-8')
        self.assertNotIn('`python scripts/audit_scan.py', text)

    def test_commands_use_plugin_root(self):
        text = (REPO / 'commands' / 'agents-doctor.md').read_text(
            encoding='utf-8')
        self.assertIn('${CLAUDE_PLUGIN_ROOT}', text)
        self.assertNotIn('python skills/agents-doctor/scripts/', text)


if __name__ == '__main__':
    unittest.main()
