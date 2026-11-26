"""End-to-end tests of the CLI modes of the plain-language layer:
`audit --human --report --summary`, `explain` and `summary`, run the way
the skill runs them (as scripts, from another working directory) over the
stand workspace of tests/integration/fixtures.py.
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SCRIPTS = REPO / 'skills' / 'agents-doctor' / 'scripts'
sys.path.insert(0, str(Path(__file__).resolve().parent))

from fixtures import FAKE_KEY, stand  # noqa: E402


class CliModesTests(unittest.TestCase):
    """audit --human --report --summary, explain and summary."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.base = Path(cls._tmp.name)
        cls.root = cls.base / 'ws'
        cls.home = cls.base / 'home'
        cls.root.mkdir()
        cls.home.mkdir()
        stand(cls.root, cls.home)
        # .agents-doctor/ does not exist yet: on a first run the command
        # has to create it itself
        assert not (cls.root / '.agents-doctor').exists()
        cls.out = cls.root / '.agents-doctor' / 'scan.json'
        cls.proc = subprocess.run(
            [sys.executable, str(SCRIPTS / 'agents_doctor.py'), 'audit',
             str(cls.root), '--home', str(cls.home), '--out', str(cls.out),
             '--report', str(cls.root / '.agents-doctor' / 'AUDIT.md'),
             '--human', str(cls.root / '.agents-doctor' / 'REPORT.md'),
             '--lang', 'ru', '--summary'],
            capture_output=True, text=True, encoding='utf-8', errors='replace',
            timeout=120)
        if cls.proc.returncode == 0:
            rep = json.loads(cls.out.read_text(encoding='utf-8'))
            key = next(f for f in rep['findings_detailed']
                       if f['gate'] == 'G6' and f['status'] == 'fail')
            cls.key_fid = key['fid']
            cls.key_at = '.mcp.json:%d' % key['evidence'][0]['line']

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_one_command_leaves_all_three_files(self):
        self.assertEqual(self.proc.returncode, 0, self.proc.stderr)
        for name in ('scan.json', 'AUDIT.md', 'REPORT.md'):
            self.assertTrue((self.root / '.agents-doctor' / name).is_file(), name)

    def test_stdout_is_the_digest_and_nothing_raw(self):
        out = self.proc.stdout
        self.assertIn('АУДИТ ПАПКИ', out)
        self.assertIn('С ЧЕГО НАЧАТЬ', out)
        self.assertIn('.agents-doctor/REPORT.md', out)
        self.assertNotIn(str(self.base), out)
        self.assertNotIn(FAKE_KEY, out)
        self.assertNotIn('"findings_detailed"', out)
        self.assertLess(len(out.encode('utf-8')), 12000)

    def test_explain_prints_a_card(self):
        r = subprocess.run(
            [sys.executable, str(SCRIPTS / 'agents_doctor.py'), 'explain',
             str(self.out), self.key_fid, '--lang', 'ru'],
            capture_output=True, text=True, encoding='utf-8', errors='replace',
            timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('что сделать: сначала смените ключ', r.stdout)
        self.assertIn('где: %s' % self.key_at, r.stdout)
        self.assertNotIn('evidence', r.stdout)
        self.assertNotIn('hmac256', r.stdout)
        self.assertNotIn(str(self.base), r.stdout)

    def test_explain_raw_keeps_the_full_record(self):
        r = subprocess.run(
            [sys.executable, str(SCRIPTS / 'agents_doctor.py'), 'explain',
             str(self.out), self.key_fid, '--raw'],
            capture_output=True, text=True, encoding='utf-8', errors='replace',
            timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('evidence:', r.stdout)

    def test_summary_subcommand_reads_a_finished_scan(self):
        r = subprocess.run(
            [sys.executable, str(SCRIPTS / 'agents_doctor.py'), 'summary',
             str(self.out), '--lang', 'ru'],
            capture_output=True, text=True, encoding='utf-8', errors='replace',
            timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('БЛОКИ ПРОВЕРОК', r.stdout)
        self.assertNotIn(str(self.base), r.stdout)


if __name__ == '__main__':
    unittest.main()
