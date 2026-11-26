"""Tests for skills/agents-doctor/scripts/sanitize_url.py.

Canary CANARY-REM-cred-9f3a is planted in every credential position
(userinfo, password, token username, query values) and in garbage
inputs; it must never appear in any sanitize output, and unparseable
inputs must collapse to 'unparsed-remote' instead of being echoed.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'skills' / 'agents-doctor' / 'scripts'))

import sanitize_url

CANARY = 'CANARY-REM-cred-9f3a'

# (input, expected sanitized output)
URL_CASES = [
    # https/http with user:pass -> drop userinfo entirely
    ('https://user:secretpass@example.com/org/repo.git', 'https://example.com/org/repo.git'),
    ('http://admin:hunter2@git.internal:8080/team/p.git', 'http://git.internal:8080/team/p.git'),
    # url-encoded credentials in the user segment
    ('https://user%3Apass@example.com/p.git', 'https://example.com/p.git'),
    ('https://user:p%40ss@example.com/x.git', 'https://example.com/x.git'),
    # token-like user@ (length >= 20 or containing token/key)
    ('https://ghp_16C7e42F292c6912E7710c838347Ae17@github.com/o/r.git', 'https://github.com/o/r.git'),
    ('https://mytoken123@host.example.com/p.git', 'https://host.example.com/p.git'),
    # plain username: also dropped (a username can be an embedded token)
    ('https://john@example.com/p.git', 'https://example.com/p.git'),
    # no credentials at all: unchanged
    ('https://example.com/org/repo.git', 'https://example.com/org/repo.git'),
    # query masking: credential values masked, benign params kept
    ('https://example.com/c.git?token=abcsecret123&ref=main',
     'https://example.com/c.git?token=***REDACTED***&ref=main'),
    ('https://example.com/c.git?ACCESS_TOKEN=zz9&sig=qq7&x=1',
     'https://example.com/c.git?ACCESS_TOKEN=***REDACTED***&sig=***REDACTED***&x=1'),
    # repeated credential params are all masked
    ('https://example.com/c.git?token=aaa&token=bbb&keep=1',
     'https://example.com/c.git?token=***REDACTED***&token=***REDACTED***&keep=1'),
    ('https://example.com/p.git?ref=main', 'https://example.com/p.git?ref=main'),
    # ssh:// with password -> drop userinfo, keep port
    ('ssh://user:pass@git.example.com:29418/project.git', 'ssh://git.example.com:29418/project.git'),
    ('ssh://git@gitlab.example.com:22/group/proj.git', 'ssh://gitlab.example.com:22/group/proj.git'),
    # IPv6 hostport kept verbatim
    ('https://[::1]:8443/mirror.git', 'https://[::1]:8443/mirror.git'),
    # standard git@github scp form: untouched
    ('git@github.com:example/docs-kit.git', 'git@github.com:example/docs-kit.git'),
    # scp with plain user: kept
    ('deploy@server.example.com:repo.git', 'deploy@server.example.com:repo.git'),
    # scp with token-like user: user masked
    ('longtokenvalue1234567890@git.internal:repo.git', '***REDACTED***@git.internal:repo.git'),
    ('deploy-key@server.example.com:repo.git', '***REDACTED***@server.example.com:repo.git'),
    # scp user containing a colon (user:pass shape): masked
    ('user:pass@git.example.com:repo.git', '***REDACTED***@git.example.com:repo.git'),
    # scp-like without user: kept as-is
    ('server.example.com:repo.git', 'server.example.com:repo.git'),
    # local paths: unchanged
    ('/srv/git/repos/tool.git', '/srv/git/repos/tool.git'),
    ('C:/Users/dev/repos/tool', 'C:/Users/dev/repos/tool'),
    # unknown scheme: still a scheme URL, userinfo still dropped
    ('xhttps://u:p@host.example/x', 'xhttps://host.example/x'),
]

UNPARSED_CASES = [
    '',
    '   ',
    '\x00//',
    'https://',
    'https://host:99999/x',      # port out of range: ValueError -> unparsed
    'https://ho st/x',           # whitespace in authority
    'git@github.com/org/repo.git',  # scp form requires ':' after host
    'user@hostwithnocolon',
    'https://user:pass@/',       # empty host
    '@:',
]

HAS_CRED_TRUE = [
    'https://user:secretpass@example.com/org/repo.git',
    'http://admin:hunter2@git.internal:8080/team/p.git',
    'https://user%3Apass@example.com/p.git',
    'https://ghp_16C7e42F292c6912E7710c838347Ae17@github.com/o/r.git',
    'https://mytoken123@host.example.com/p.git',
    'https://abcdefghijklmnopqrst@example.com/p.git',  # len-20 user
    'ssh://user:pass@git.example.com:29418/project.git',
    'https://example.com/c.git?token=abcsecret123',
    'https://example.com/c.git?ApiKey=zz',             # case-insensitive key
    'user:pass@git.example.com:repo.git',              # scp colon in user
    'deploy-key@server.example.com:repo.git',          # scp token-like user
]

HAS_CRED_FALSE = [
    'https://example.com/org/repo.git',
    'https://john@example.com/p.git',                  # plain username
    'ssh://git@gitlab.example.com:22/group/proj.git',  # plain username
    'git@github.com:example/docs-kit.git',
    'deploy@server.example.com:repo.git',
    'server.example.com:repo.git',
    '/srv/git/repos/tool.git',
    'https://example.com/p.git?ref=main',              # benign params only
    '',
    '\x00//',
]


class SanitizeUrlTests(unittest.TestCase):
    def test_expected_outputs(self):
        for url, expected in URL_CASES:
            with self.subTest(url=url):
                self.assertEqual(sanitize_url.sanitize_remote_url(url), expected)

    def test_unparsed_cases(self):
        for url in UNPARSED_CASES:
            with self.subTest(url=repr(url)):
                self.assertEqual(sanitize_url.sanitize_remote_url(url),
                                 'unparsed-remote')

    def test_idempotent(self):
        for url, _expected in URL_CASES:
            with self.subTest(url=url):
                once = sanitize_url.sanitize_remote_url(url)
                self.assertEqual(sanitize_url.sanitize_remote_url(once), once)

    def test_idempotent_for_unparsed_input(self):
        # sanitize('unparsed-remote') is a local path and returns itself
        for url in UNPARSED_CASES:
            with self.subTest(url=repr(url)):
                once = sanitize_url.sanitize_remote_url(url)
                self.assertEqual(sanitize_url.sanitize_remote_url(once), once)

    def test_unparsed_constant(self):
        self.assertEqual(sanitize_url.UNPARSED, 'unparsed-remote')


class HasCredentialsTests(unittest.TestCase):
    def test_true_cases(self):
        for url in HAS_CRED_TRUE:
            with self.subTest(url=url):
                self.assertTrue(sanitize_url.has_credentials(url))

    def test_false_cases(self):
        for url in HAS_CRED_FALSE:
            with self.subTest(url=url):
                self.assertFalse(sanitize_url.has_credentials(url))

    def test_never_raises_on_garbage(self):
        for url in UNPARSED_CASES:
            with self.subTest(url=repr(url)):
                self.assertIsInstance(sanitize_url.has_credentials(url), bool)


class CanaryNoLeakTests(unittest.TestCase):
    def test_canary_never_in_sanitize_output(self):
        cases = [
            'https://user:' + CANARY + '@example.com/p.git',
            'https://' + CANARY + '@example.com/p.git',
            'ssh://u:' + CANARY + '@git.example.com:29418/p.git',
            'https://example.com/p.git?token=' + CANARY,
            'https://example.com/p.git?access_token=' + CANARY + '&ref=main',
            CANARY + '@server.example.com:repo.git',
            'user:' + CANARY + '@git.example.com:repo.git',
        ]
        for url in cases:
            with self.subTest(url=url):
                out = sanitize_url.sanitize_remote_url(url)
                self.assertNotIn(CANARY, out)

    def test_unparsed_error_paths_do_not_echo_input(self):
        for url in [
            'https://' + CANARY + '\x00/x',
            '\x00' + CANARY,
            'https://user:' + CANARY + '@/',
            CANARY + '://',
        ]:
            with self.subTest(url=repr(url)):
                self.assertEqual(sanitize_url.sanitize_remote_url(url),
                                 'unparsed-remote')

    def test_has_credentials_error_paths_are_bool_only(self):
        self.assertTrue(sanitize_url.has_credentials('https://u:' + CANARY + '@h/p'))
        for url in ['\x00' + CANARY, CANARY, 'https://' + CANARY + '\x00/x']:
            with self.subTest(url=repr(url)):
                self.assertIsInstance(sanitize_url.has_credentials(url), bool)


class ModuleContractTests(unittest.TestCase):
    def test_does_not_duplicate_classify_remote(self):
        self.assertFalse(hasattr(sanitize_url, 'classify_remote'))

    def test_query_masking_keeps_benign_params(self):
        out = sanitize_url.sanitize_remote_url(
            'https://example.com/r.git?token=sekrit&ref=main&depth=1')
        self.assertIn('ref=main', out)
        self.assertIn('depth=1', out)
        self.assertNotIn('sekrit', out)


if __name__ == '__main__':
    unittest.main()
