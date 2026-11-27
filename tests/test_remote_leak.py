"""End-to-end: credentials in git remote URLs never reach any artifact.

The scanner stores only sanitized URLs (sanitize_url.py); the raw value is
used solely to compute the credentials_in_remote flag. Canary values below
are synthetic.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCANNER = REPO / 'skills' / 'agents-doctor' / 'scripts' / 'audit_scan.py'

CANARY_BASIC = 'CANARY-REMpw-zz91'
CANARY_QUERY = 'CANARY-REMquery-77aa'


def _git(p, *args):
    env = dict(os.environ, GIT_OPTIONAL_LOCKS='0')
    subprocess.run(['git', '-C', str(p), '-c', 'user.email=t@example.com',
                    '-c', 'user.name=T', *args],
                   check=True, capture_output=True, env=env)


def _force_rmtree(p):
    import shutil
    import stat

    def _onexc(func, path, _exc):
        os.chmod(path, stat.S_IWRITE)
        func(path)
    if sys.version_info >= (3, 12):
        shutil.rmtree(p, onexc=_onexc)
    else:
        shutil.rmtree(p, onerror=lambda f, q, _i: _onexc(f, q, _i))


class RemoteLeakTest(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp())
        self.addCleanup(_force_rmtree, self.base)
        root = self.base / 'ws'
        home = self.base / 'home'
        home.mkdir()
        for repo, url in (
            ('svc', 'https://dev:%s@example.com/team/svc.git' % CANARY_BASIC),
            ('svc2', 'https://example.com/team/svc.git?token=%s&ref=main'
                     % CANARY_QUERY)):
            p = root / repo
            p.mkdir(parents=True)
            (p / 'README.md').write_text('# svc\n', encoding='utf-8')
            _git(p, 'init', '-q')
            _git(p, 'add', 'README.md')
            _git(p, 'commit', '-q', '-m', 'init')
            _git(p, 'remote', 'add', 'origin', url)
        out = self.base / 'scan.json'
        proc = subprocess.run(
            [sys.executable, str(SCANNER), str(root), '--home', str(home),
             '--out', str(out)],
            capture_output=True, text=True, encoding='utf-8',
            errors='replace', timeout=120)
        self.proc = proc
        self.text = json.dumps(json.loads(out.read_text(encoding='utf-8')),
                               ensure_ascii=False)
        self.artifacts = self.text + proc.stdout + proc.stderr

    def test_no_canary_in_any_artifact(self):
        self.assertNotIn(CANARY_BASIC, self.artifacts)
        self.assertNotIn(CANARY_QUERY, self.artifacts)

    def test_sanitized_remote_stored_and_flagged(self):
        rep = json.loads(self.text)
        svc = next(t for t in rep['top_level'] if t['name'] == 'svc')
        self.assertEqual(svc['git']['remote'], 'https://example.com/team/svc.git')
        self.assertTrue(svc['git']['credentials_in_remote'])
        svc2 = next(t for t in rep['top_level'] if t['name'] == 'svc2')
        self.assertIn('***REDACTED***', svc2['git']['remote'])
        self.assertTrue(svc2['git']['credentials_in_remote'])

    def test_g6_fails_with_rotate_recommendation(self):
        rep = json.loads(self.text)
        g6 = next(g for g in rep['gates'] if g['gid'] == 'G6')
        self.assertEqual(g6['status'], 'fail')
        cred_findings = [f for f in rep['findings_detailed']
                         if 'remote URL' in f['title']]
        self.assertEqual(len(cred_findings), 2)
        self.assertTrue(all('otate' in f['recommendation']
                            for f in cred_findings))

    def test_dup_checkouts_grouped_by_sanitized_url(self):
        rep = json.loads(self.text)
        self.assertEqual(len(rep['dup_checkouts']), 1)
        key = next(iter(rep['dup_checkouts']))
        self.assertNotIn(CANARY_QUERY, key)
        self.assertIn('example.com/team/svc.git', key)


if __name__ == '__main__':
    unittest.main()
