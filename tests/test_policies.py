"""Tests for skills/agents-doctor/scripts/policies.py.

Covers the policy engine contract: the fallback YAML parser
(no PyYAML) against the target format and against broken input, every
domain positive and negative, the severity mapping, custom rules,
exceptions with and without a reason, file layering with a severity
conflict, unknown domains and fields, determinism, and the promise that
secret values never reach the report. The CLI subcommand is exercised
through agents_doctor.main. Standard library only, Windows-safe paths.
"""
import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'skills' / 'agents-doctor' / 'scripts'))
import policies  # noqa: E402

TARGET_POLICY = """version: 1

policy:
  name: corporate-baseline
  description: Mandatory rules for every workspace

  secrets:
    severity: critical
    block_on_failure: true

  mcp:
    allowlist:
      - approved-server

  instructions:
    require_agents_md: true

  git:
    prevent_secret_commits: true

  permissions:
    forbid_wildcard: true

  content:
    ban_patterns:
      - 'ticket\\$'
      - 'INTERNAL-ID'

custom_rules:
  - id: POL-CUSTOM-001
    check: content.regex
    patterns: ['inner-project']
    severity: error
    message: Forbidden project name
"""


def _policy_file(root, text, name='policy.yml'):
    p = Path(root) / name
    p.write_text(text, encoding='utf-8')
    return str(p)


def _scan(root, **facts):
    rep = {'schema_version': '1.0', 'root': str(root), 'home': str(root),
           'secrets': [], 'top_level': [], 'findings_detailed': [],
           'gates': []}
    rep.update(facts)
    return rep


def _rule(report, rid):
    for r in report['rules_evaluated']:
        if r['id'] == rid:
            return r
    return None


def _violations(report, rid):
    return [v for v in report['violations'] if v['id'] == rid]


class _TmpCase(unittest.TestCase):
    """Each test gets its own empty workspace directory."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def policy(self, text, name='policy.yml'):
        return _policy_file(self.root, text, name)

    def scan(self, **facts):
        return _scan(self.root, **facts)


# --- fallback YAML parser ---------------------------------------------------------

class FallbackParserTests(_TmpCase):
    """The no-PyYAML parser, exercised with policies.yaml disabled."""

    def test_target_format_matches_pyyaml(self):
        path = self.policy(TARGET_POLICY)
        with mock.patch.object(policies, 'yaml', None):
            fallback = policies.parse_policy_file(path)
        if policies.yaml is None:
            self.skipTest('PyYAML not installed')
        full = policies.parse_policy_file(path)
        self.assertEqual(fallback, full)

    def test_nesting_lists_inline_quotes_and_scalars(self):
        text = '\n'.join([
            "version: 1",
            "policy:",
            "  mcp:",
            "    allowlist: ['a b', \"c d\", plain]",
            "  instructions:",
            "    require_agents_md: true",
            "  limits:",
            "    depth: 2",
            "    ratio: 0.5",
            "    nothing: null",
            "    text: 'ticket\\$'",
        ])
        with mock.patch.object(policies, 'yaml', None):
            data = policies.parse_policy_file(self.policy(text))
        pol = data['policy']
        self.assertEqual(pol['mcp']['allowlist'], ['a b', 'c d', 'plain'])
        self.assertIs(pol['instructions']['require_agents_md'], True)
        self.assertEqual(pol['limits']['depth'], 2)
        self.assertEqual(pol['limits']['ratio'], 0.5)
        self.assertIsNone(pol['limits']['nothing'])
        self.assertEqual(pol['limits']['text'], 'ticket\\$')

    def test_comments_full_line_and_trailing(self):
        text = '\n'.join([
            '# leading comment',
            'version: 1  # the version',
            'policy:',
            '  # inner comment',
            '  secrets:',
            "    severity: critical  # keep",
        ])
        with mock.patch.object(policies, 'yaml', None):
            data = policies.parse_policy_file(self.policy(text))
        self.assertEqual(data['version'], 1)
        self.assertEqual(data['policy']['secrets']['severity'], 'critical')

    def test_block_lists_same_indent_and_deeper(self):
        # allowlist sits at indent 4: items one level deeper, or at the
        # key's own indent (both valid YAML)
        for style in ('      - x\n      - y\n', '    - x\n    - y\n'):
            text = 'policy:\n  mcp:\n    allowlist:\n%s' % style
            with mock.patch.object(policies, 'yaml', None):
                data = policies.parse_policy_file(self.policy(text))
            self.assertEqual(data['policy']['mcp']['allowlist'], ['x', 'y'])

    def test_same_indent_list_then_sibling_key(self):
        text = 'a:\n- x\nb: 1\n'
        with mock.patch.object(policies, 'yaml', None):
            data = policies.parse_policy_file(self.policy(text))
        self.assertEqual(data, {'a': ['x'], 'b': 1})

    def test_unterminated_inline_list_is_policy_error(self):
        path = self.policy('version: 1\nmcp: [a, b\n')
        with mock.patch.object(policies, 'yaml', None):
            with self.assertRaises(policies.PolicyError) as ctx:
                policies.parse_policy_file(path)
        err = ctx.exception
        self.assertEqual(err.filename, 'policy.yml')
        self.assertEqual(err.lineno, 2)
        self.assertIn('policy.yml:2', str(err))

    def test_tab_indentation_rejected(self):
        path = self.policy('policy:\n\tsecrets: {}\n')
        with mock.patch.object(policies, 'yaml', None):
            with self.assertRaises(policies.PolicyError) as ctx:
                policies.parse_policy_file(path)
        self.assertEqual(ctx.exception.lineno, 2)

    def test_orphan_dash_rejected(self):
        path = self.policy('version: 1\n- stray\n')
        with mock.patch.object(policies, 'yaml', None):
            with self.assertRaises(policies.PolicyError) as ctx:
                policies.parse_policy_file(path)
        self.assertEqual(ctx.exception.lineno, 2)

    def test_duplicate_key_rejected(self):
        path = self.policy('version: 1\nversion: 2\n')
        with mock.patch.object(policies, 'yaml', None):
            with self.assertRaises(policies.PolicyError) as ctx:
                policies.parse_policy_file(path)
        self.assertEqual(ctx.exception.lineno, 2)

    def test_unterminated_quote_rejected(self):
        path = self.policy("name: 'unclosed\n")
        with mock.patch.object(policies, 'yaml', None):
            with self.assertRaises(policies.PolicyError):
                policies.parse_policy_file(path)

    def test_colon_in_plain_value_rejected(self):
        # 'a: b: c' is invalid YAML and must not quietly become a string
        path = self.policy('description: one: two\n')
        with mock.patch.object(policies, 'yaml', None):
            with self.assertRaises(policies.PolicyError):
                policies.parse_policy_file(path)

    def test_pyyaml_branch_reports_filename_and_line(self):
        if policies.yaml is None:
            self.skipTest('PyYAML not installed')
        path = self.policy('policy:\n  mcp: [unclosed\n')
        with self.assertRaises(policies.PolicyError) as ctx:
            policies.parse_policy_file(path)
        self.assertEqual(ctx.exception.filename, 'policy.yml')
        self.assertTrue(ctx.exception.lineno)


# --- domain checks ------------------------------------------------------------------

class SecretsDomainTests(_TmpCase):
    POLICY = ('version: 1\npolicy:\n  secrets:\n    severity: %s\n')

    def test_clean_scan_passes(self):
        pol = self.policy(self.POLICY % 'critical')
        rep = self.scan()
        report = policies.evaluate_policies(rep, self.root, [pol])
        self.assertEqual(_rule(report, 'POL-SECRETS-EXPOSED')['status'],
                         'pass')
        self.assertEqual(report['summary']['violations'], 0)

    def test_fail_secret_entry_violates_with_metadata_only(self):
        pol = self.policy(self.POLICY % 'critical')
        rep = self.scan(secrets=[{'path': 'config.env', 'line': 3,
                                  'kind': 'api_key', 'mask': 'sk-***',
                                  'fingerprint': 'abc123',
                                  'confidence': 0.95}])
        report = policies.evaluate_policies(rep, self.root, [pol])
        rule = _rule(report, 'POL-SECRETS-EXPOSED')
        self.assertEqual(rule['status'], 'fail')
        self.assertEqual(rule['severity'], 'critical')
        viols = _violations(report, 'POL-SECRETS-EXPOSED')
        self.assertEqual(len(viols), 1)
        ev = viols[0]['evidence'][0]
        self.assertEqual(ev['file'], 'config.env')
        self.assertEqual(ev['kind'], 'api_key')
        self.assertEqual(ev['fingerprint'], 'abc123')
        self.assertNotIn('value', ev)

    def test_missing_section_is_unknown_not_pass(self):
        pol = self.policy(self.POLICY % 'critical')
        rep = self.scan()
        del rep['secrets']
        report = policies.evaluate_policies(rep, self.root, [pol])
        self.assertEqual(_rule(report, 'POL-SECRETS-EXPOSED')['status'],
                         'unknown')

    def test_block_on_failure_flag_recorded(self):
        pol = self.policy('version: 1\npolicy:\n  secrets:\n'
                          '    block_on_failure: true\n')
        report = policies.evaluate_policies(self.scan(), self.root, [pol])
        self.assertTrue(report['block_on_failure'])


class SeverityMappingTests(_TmpCase):
    def test_all_four_levels_map_to_severity_and_status(self):
        cases = {'critical': ('critical', 'fail'),
                 'error': ('high', 'fail'),
                 'warning': ('medium', 'warn'),
                 'info': ('low', 'info')}
        for pol_sev, (fsev, fstatus) in cases.items():
            with self.subTest(pol_sev=pol_sev):
                pol = self.policy('version: 1\npolicy:\n  secrets:\n'
                                  '    severity: %s\n' % pol_sev)
                rep = self.scan(secrets=[{'path': 'x', 'line': 1,
                                          'kind': 'api_key'}])
                report = policies.evaluate_policies(rep, self.root, [pol])
                rule = _rule(report, 'POL-SECRETS-EXPOSED')
                self.assertEqual((rule['severity'], rule['status']),
                                 (fsev, fstatus))
                self.assertEqual(report['violations'][0]['severity'], fsev)


class McpDomainTests(_TmpCase):
    def _policy(self, allow):
        return self.policy('version: 1\npolicy:\n  mcp:\n    allowlist: [%s]\n'
                           % ', '.join(allow))

    def test_rogue_server_violates_with_name_and_file_only(self):
        pol = self._policy(['approved-server'])
        cfg = {'mcpServers': {'rogue': {'command': 'npx', 'env': {
            'KEY': 'sk-mcp-canary-42'}}}}
        (self.root / '.mcp.json').write_text(
            json.dumps(cfg), encoding='utf-8')
        (self.root / '.cursor').mkdir()
        (self.root / '.cursor' / 'mcp.json').write_text(
            json.dumps({'mcpServers': {'approved-server': {}}}),
            encoding='utf-8')
        report = policies.evaluate_policies(self.scan(), self.root, [pol])
        viols = _violations(report, 'POL-MCP-ALLOWLIST')
        self.assertEqual(len(viols), 1)
        self.assertEqual(viols[0]['evidence'][0]['server'], 'rogue')
        self.assertEqual(viols[0]['evidence'][0]['file'], '.mcp.json')
        dump = json.dumps(report, ensure_ascii=False)
        self.assertNotIn('sk-mcp-canary-42', dump)   # env never copied
        self.assertNotIn('command', dump)

    def test_all_servers_allowed_passes(self):
        pol = self._policy(['approved-server'])
        (self.root / '.mcp.json').write_text(
            json.dumps({'mcpServers': {'approved-server': {}}}),
            encoding='utf-8')
        report = policies.evaluate_policies(self.scan(), self.root, [pol])
        self.assertEqual(_rule(report, 'POL-MCP-ALLOWLIST')['status'],
                         'pass')

    def test_claude_settings_local_json_counts(self):
        pol = self._policy([])
        (self.root / '.claude').mkdir()
        (self.root / '.claude' / 'settings.local.json').write_text(
            json.dumps({'mcpServers': {'extra': {}}}), encoding='utf-8')
        report = policies.evaluate_policies(self.scan(), self.root, [pol])
        viols = _violations(report, 'POL-MCP-ALLOWLIST')
        self.assertEqual(len(viols), 1)
        self.assertEqual(viols[0]['evidence'][0]['file'],
                         '.claude/settings.local.json')

    def test_codex_toml_servers_detected(self):
        pol = self._policy(['good'])
        (self.root / '.codex').mkdir()
        (self.root / '.codex' / 'config.toml').write_text(
            '[mcp_servers.good]\ncommand = "a"\n'
            '[mcp_servers.bad]\ncommand = "b"\n', encoding='utf-8')
        report = policies.evaluate_policies(self.scan(), self.root, [pol])
        viols = _violations(report, 'POL-MCP-ALLOWLIST')
        self.assertEqual([v['evidence'][0]['server'] for v in viols],
                         ['bad'])

    def test_codex_toml_fallback_without_tomllib(self):
        pol = self._policy(['good'])
        (self.root / '.codex').mkdir()
        (self.root / '.codex' / 'config.toml').write_text(
            '[mcp_servers.bad]\ncommand = "b"\n', encoding='utf-8')
        with mock.patch.object(policies, 'tomllib', None):
            report = policies.evaluate_policies(self.scan(), self.root,
                                                [pol])
        self.assertEqual(
            [v['evidence'][0]['server']
             for v in _violations(report, 'POL-MCP-ALLOWLIST')], ['bad'])

    def test_no_configs_is_unknown(self):
        pol = self._policy(['approved-server'])
        report = policies.evaluate_policies(self.scan(), self.root, [pol])
        self.assertEqual(_rule(report, 'POL-MCP-ALLOWLIST')['status'],
                         'unknown')


class InstructionsDomainTests(_TmpCase):
    POLICY = ('version: 1\npolicy:\n  instructions:\n'
              '    require_agents_md: true\n')

    def test_agents_md_passes(self):
        (self.root / 'AGENTS.md').write_text('ok', encoding='utf-8')
        report = policies.evaluate_policies(
            self.scan(), self.root, [self.policy(self.POLICY)])
        self.assertEqual(
            _rule(report, 'POL-INSTRUCTIONS-AGENTS-MD')['status'], 'pass')

    def test_claude_md_passes(self):
        (self.root / 'CLAUDE.md').write_text('ok', encoding='utf-8')
        report = policies.evaluate_policies(
            self.scan(), self.root, [self.policy(self.POLICY)])
        self.assertEqual(
            _rule(report, 'POL-INSTRUCTIONS-AGENTS-MD')['status'], 'pass')

    def test_neither_file_violates(self):
        report = policies.evaluate_policies(
            self.scan(), self.root, [self.policy(self.POLICY)])
        rule = _rule(report, 'POL-INSTRUCTIONS-AGENTS-MD')
        self.assertEqual(rule['status'], 'warn')  # default severity warning
        viols = _violations(report, 'POL-INSTRUCTIONS-AGENTS-MD')
        self.assertEqual(len(viols), 1)
        self.assertIn('AGENTS.md', viols[0]['message'])


class GitDomainTests(_TmpCase):
    POLICY = ('version: 1\npolicy:\n  git:\n    prevent_secret_commits: '
              'true\n')

    def _repo(self, extra):
        return {'name': 'app', 'kind': 'repo', 'git': {},
                'extra': extra}

    def test_tracked_secret_violates(self):
        rep = self.scan(top_level=[self._repo({
            'tracked_secrets': [{'file': '.env', 'line': 1,
                                 'kind': 'api_key',
                                 'fingerprint': 'ff1'}],
            'hooks': [{'name': 'pre-commit',
                       'flags': {'secret_scan': True}}]})])
        report = policies.evaluate_policies(
            rep, self.root, [self.policy(self.POLICY)])
        viols = _violations(report, 'POL-GIT-SECRET-COMMITS')
        self.assertEqual(len(viols), 1)
        self.assertEqual(viols[0]['evidence'][0]['repo'], 'app')
        self.assertEqual(viols[0]['evidence'][0]['fingerprint'], 'ff1')

    def test_missing_scan_hook_violates(self):
        rep = self.scan(top_level=[self._repo({
            'tracked_secrets': [],
            'hooks': [{'name': 'post-merge',
                       'flags': {'secret_scan': False}}]})])
        report = policies.evaluate_policies(
            rep, self.root, [self.policy(self.POLICY)])
        viols = _violations(report, 'POL-GIT-SECRET-COMMITS')
        self.assertEqual(len(viols), 1)
        self.assertIn('secret-scan hook', viols[0]['message'])

    def test_hook_present_passes(self):
        rep = self.scan(top_level=[self._repo({
            'tracked_secrets': [],
            'hooks': [{'name': 'pre-commit',
                       'flags': {'secret_scan': True}}]})])
        report = policies.evaluate_policies(
            rep, self.root, [self.policy(self.POLICY)])
        self.assertEqual(_rule(report, 'POL-GIT-SECRET-COMMITS')['status'],
                         'pass')

    def test_no_repos_is_unknown(self):
        for top in ([], [{'name': 'docs', 'kind': 'dir'}]):
            with self.subTest(top=top):
                rep = self.scan(top_level=top)
                report = policies.evaluate_policies(
                    rep, self.root, [self.policy(self.POLICY)])
                self.assertEqual(
                    _rule(report, 'POL-GIT-SECRET-COMMITS')['status'],
                    'unknown')


class PermissionsDomainTests(_TmpCase):
    POLICY = ('version: 1\npolicy:\n  permissions:\n    forbid_wildcard: '
              'true\n')

    def test_wildcard_finding_violates(self):
        rep = self.scan(findings_detailed=[{
            'fid': 'CFG-001', 'gate': 'G2', 'check_id':
                'CLAUDE_SETTINGS_PERMISSIONS_WILDCARD',
            'title': 'Wildcard Bash permission',
            'evidence': [{'file': '.claude/settings.json',
                          'rule': 'Bash(*)'}]}])
        report = policies.evaluate_policies(
            rep, self.root, [self.policy(self.POLICY)])
        viols = _violations(report, 'POL-PERMISSIONS-WILDCARD')
        self.assertEqual(len(viols), 1)
        self.assertEqual(viols[0]['evidence'][0]['rule'], 'Bash(*)')

    def test_all_four_check_ids_recognised(self):
        for cid in policies.PERMISSION_CHECK_IDS:
            with self.subTest(check_id=cid):
                rep = self.scan(findings_detailed=[{
                    'fid': 'X', 'gate': 'G2', 'check_id': cid,
                    'title': cid, 'evidence': []}])
                report = policies.evaluate_policies(
                    rep, self.root, [self.policy(self.POLICY)])
                self.assertEqual(
                    len(_violations(report, 'POL-PERMISSIONS-WILDCARD')), 1)

    def test_unrelated_findings_pass(self):
        rep = self.scan(findings_detailed=[{
            'fid': 'DIR-001', 'gate': 'G4', 'check_id': 'SOMETHING_ELSE',
            'title': 'other', 'evidence': []}])
        report = policies.evaluate_policies(
            rep, self.root, [self.policy(self.POLICY)])
        self.assertEqual(_rule(report, 'POL-PERMISSIONS-WILDCARD')['status'],
                         'pass')

    def test_missing_or_empty_findings_are_unknown(self):
        for fd in (None, []):
            with self.subTest(fd=fd):
                rep = self.scan()
                rep['findings_detailed'] = fd
                report = policies.evaluate_policies(
                    rep, self.root, [self.policy(self.POLICY)])
                self.assertEqual(
                    _rule(report, 'POL-PERMISSIONS-WILDCARD')['status'],
                    'unknown')


class ContentDomainTests(_TmpCase):
    POLICY = ("version: 1\npolicy:\n  content:\n    ban_patterns:\n"
              "      - 'ticket\\$'\n      - 'INTERNAL-ID'\n")

    def _write_agents(self, text):
        (self.root / 'AGENTS.md').write_text(text, encoding='utf-8')

    def test_banned_pattern_violates_with_file_line_and_match(self):
        self._write_agents('line one\nsee ticket$2293602 for details\n')
        report = policies.evaluate_policies(
            self.scan(), self.root, [self.policy(self.POLICY)])
        viols = _violations(report, 'POL-CONTENT-BAN-PATTERNS')
        self.assertEqual(len(viols), 1)
        ev = viols[0]['evidence'][0]
        self.assertEqual(ev['file'], 'AGENTS.md')
        self.assertEqual(ev['line'], 2)
        self.assertEqual(ev['match'], 'ticket$')  # re.search match itself

    def test_clean_files_pass(self):
        self._write_agents('nothing forbidden here\n')
        (self.root / '.mcp.json').write_text('{}', encoding='utf-8')
        report = policies.evaluate_policies(
            self.scan(), self.root, [self.policy(self.POLICY)])
        self.assertEqual(_rule(report, 'POL-CONTENT-BAN-PATTERNS')['status'],
                         'pass')

    def test_no_target_files_is_unknown(self):
        report = policies.evaluate_policies(
            self.scan(), self.root, [self.policy(self.POLICY)])
        self.assertEqual(_rule(report, 'POL-CONTENT-BAN-PATTERNS')['status'],
                         'unknown')

    def test_invalid_regex_warns_and_rule_stays_unknown(self):
        pol = self.policy("version: 1\npolicy:\n  content:\n"
                          "    ban_patterns: ['([unclosed]']\n")
        self._write_agents('whatever\n')
        report = policies.evaluate_policies(self.scan(), self.root, [pol])
        self.assertEqual(_rule(report, 'POL-CONTENT-BAN-PATTERNS')['status'],
                         'unknown')
        self.assertTrue(any('invalid regex' in w
                            for w in report['warnings']))

    def test_large_file_capped_at_256kb(self):
        # the banned text sits past the 256 KB cap: nothing there is read
        self._write_agents('x' * (256 * 1024) + 'zzzz')
        pol = self.policy("version: 1\npolicy:\n  content:\n"
                          "    ban_patterns: ['zzzz']\n")
        report = policies.evaluate_policies(self.scan(), self.root, [pol])
        self.assertEqual(_rule(report, 'POL-CONTENT-BAN-PATTERNS')['status'],
                         'pass')


# --- custom rules -------------------------------------------------------------------

class CustomRulesTests(_TmpCase):
    def test_custom_rule_violation_carries_id_message_severity(self):
        pol = self.policy(TARGET_POLICY)
        (self.root / 'AGENTS.md').write_text(
            'discussing inner-project again\n', encoding='utf-8')
        report = policies.evaluate_policies(self.scan(), self.root, [pol])
        viols = _violations(report, 'POL-CUSTOM-001')
        self.assertEqual(len(viols), 1)
        self.assertEqual(viols[0]['severity'], 'high')  # error -> high
        self.assertIn('Forbidden project name', viols[0]['message'])
        rule = _rule(report, 'POL-CUSTOM-001')
        self.assertEqual(rule['status'], 'fail')

    def test_unsupported_check_warns_and_is_unknown(self):
        pol = self.policy('version: 1\ncustom_rules:\n  - id: POL-X\n'
                          '    check: git.branch_name\n'
                          "    patterns: ['x']\n")
        report = policies.evaluate_policies(self.scan(), self.root, [pol])
        self.assertEqual(_rule(report, 'POL-X')['status'], 'unknown')
        self.assertTrue(any('unsupported check' in w
                            for w in report['warnings']))

    def test_rule_without_patterns_warns_and_is_unknown(self):
        pol = self.policy('version: 1\ncustom_rules:\n  - id: POL-Y\n'
                          '    check: content.regex\n')
        report = policies.evaluate_policies(self.scan(), self.root, [pol])
        self.assertEqual(_rule(report, 'POL-Y')['status'], 'unknown')
        self.assertTrue(any('patterns' in w for w in report['warnings']))

    def test_duplicate_id_across_files_later_wins(self):
        p1 = self.policy('version: 1\ncustom_rules:\n  - id: POL-D\n'
                         "    check: content.regex\n    patterns: ['aa']\n"
                         '    severity: info\n', name='first.yml')
        p2 = self.policy('version: 1\ncustom_rules:\n  - id: POL-D\n'
                         "    check: content.regex\n    patterns: ['bb']\n"
                         '    severity: error\n', name='second.yml')
        (self.root / 'AGENTS.md').write_text('has bb inside\n',
                                             encoding='utf-8')
        report = policies.evaluate_policies(self.scan(), self.root,
                                            [p1, p2])
        pol_d = [r for r in report['rules_evaluated'] if r['id'] == 'POL-D']
        self.assertEqual(len(pol_d), 1)
        viols = _violations(report, 'POL-D')
        self.assertEqual(len(viols), 1)
        self.assertEqual(viols[0]['severity'], 'high')
        self.assertTrue(any('redefined' in w for w in report['warnings']))


# --- exceptions and workspace config ------------------------------------------------

class ExceptionsTests(_TmpCase):
    POLICY = ('version: 1\npolicy:\n  instructions:\n'
              '    require_agents_md: true\n')

    def test_exception_with_reason_suppresses_rule(self):
        (self.root / '.agents-doctor.toml').write_text(
            '[policy]\n'
            'exceptions = { POL-INSTRUCTIONS-AGENTS-MD = "legacy workspace" }\n',
            encoding='utf-8')
        report = policies.evaluate_policies(
            self.scan(), self.root, [self.policy(self.POLICY)])
        rule = _rule(report, 'POL-INSTRUCTIONS-AGENTS-MD')
        self.assertEqual(rule['status'], 'suppressed')
        self.assertEqual(rule['violations'], 0)
        self.assertEqual(rule['suppressed'], 1)
        self.assertEqual(report['summary']['violations'], 0)
        self.assertEqual(len(report['exceptions']), 1)
        self.assertEqual(report['exceptions'][0]['reason'],
                         'legacy workspace')
        self.assertEqual(len(report['exceptions'][0]['suppressed']), 1)

    def test_exception_without_reason_warns(self):
        (self.root / '.agents-doctor.toml').write_text(
            '[policy]\nexceptions = { POL-INSTRUCTIONS-AGENTS-MD = "" }\n',
            encoding='utf-8')
        report = policies.evaluate_policies(
            self.scan(), self.root, [self.policy(self.POLICY)])
        self.assertTrue(any('has no reason' in w
                            for w in report['warnings']))
        self.assertEqual(report['summary']['violations'], 0)

    def test_workspace_file_not_layered_twice(self):
        # the CLI discovery may already include the workspace toml files;
        # layering must keep one entry per file in policy_versions
        pol = self.policy(self.POLICY)
        (self.root / '.agents-doctor.toml').write_text(
            '[policy]\nfiles = ["%s"]\n' % Path(pol).name,
            encoding='utf-8')
        report = policies.evaluate_policies(
            self.scan(), self.root, [str(pol)])
        names = [v['file'] for v in report['policy_versions']]
        self.assertEqual(names.count(Path(pol).name), 1)

    def test_exception_for_unknown_rule_warns(self):
        (self.root / '.agents-doctor.toml').write_text(
            '[policy]\nexceptions = { POL-NOPE = "typo" }\n',
            encoding='utf-8')
        report = policies.evaluate_policies(
            self.scan(), self.root, [self.policy(self.POLICY)])
        self.assertTrue(any('unknown rule id' in w
                            for w in report['warnings']))


class WorkspaceFilesTests(_TmpCase):
    def test_policy_files_from_config_layer_on_top(self):
        corp = self.policy('version: 1\npolicy:\n  mcp:\n'
                           '    allowlist: [a]\n', name='corporate.yml')
        (self.root / 'team.yml').write_text(
            'version: 2\npolicy:\n  mcp:\n    allowlist: [a, b]\n',
            encoding='utf-8')
        (self.root / '.agents-doctor.toml').write_text(
            '[policy]\nfiles = ["team.yml"]\n', encoding='utf-8')
        (self.root / '.mcp.json').write_text(
            json.dumps({'mcpServers': {'a': {}, 'b': {}}}), encoding='utf-8')
        report = policies.evaluate_policies(self.scan(), self.root, [corp])
        # team.yml (from the workspace config) widened the allowlist
        self.assertEqual(_rule(report, 'POL-MCP-ALLOWLIST')['status'],
                         'pass')
        self.assertEqual(len(report['policy_versions']), 2)

    def test_missing_config_policy_file_warns(self):
        (self.root / '.agents-doctor.toml').write_text(
            '[policy]\nfiles = ["ghost.yml"]\n', encoding='utf-8')
        report = policies.evaluate_policies(
            self.scan(), self.root, [self.policy('version: 1\n')])
        self.assertTrue(any('ghost.yml' in w for w in report['warnings']))


# --- layering, unknown fields, determinism ------------------------------------------

class InheritanceTests(_TmpCase):
    def test_later_file_wins_per_domain(self):
        corp = self.policy('version: 1\npolicy:\n  mcp:\n'
                           '    allowlist: [a, b]\n  git:\n'
                           '    prevent_secret_commits: true\n',
                           name='corporate.yml')
        team = self.policy('version: 1\npolicy:\n  mcp:\n'
                           '    allowlist: [a]\n', name='team.yml')
        (self.root / '.mcp.json').write_text(
            json.dumps({'mcpServers': {'a': {}, 'b': {}}}), encoding='utf-8')
        report = policies.evaluate_policies(self.scan(), self.root,
                                            [corp, team])
        viols = _violations(report, 'POL-MCP-ALLOWLIST')
        self.assertEqual([v['evidence'][0]['server'] for v in viols],
                         ['b'])
        # a domain only corporate defined still applies
        self.assertNotEqual(
            _rule(report, 'POL-GIT-SECRET-COMMITS')['status'],
            'not_applicable')

    def test_severity_conflict_warns_and_takes_strictest(self):
        corp = self.policy('version: 1\npolicy:\n  secrets:\n'
                           '    severity: error\n', name='corporate.yml')
        team = self.policy('version: 1\npolicy:\n  secrets:\n'
                           '    severity: info\n', name='team.yml')
        rep = self.scan(secrets=[{'path': 'x', 'line': 1,
                                  'kind': 'api_key'}])
        report = policies.evaluate_policies(rep, self.root, [corp, team])
        rule = _rule(report, 'POL-SECRETS-EXPOSED')
        self.assertEqual(rule['severity'], 'high')   # error wins over info
        self.assertTrue(any('conflicting severity' in w
                            for w in report['warnings']))


class UnknownFieldsTests(_TmpCase):
    def test_unknown_domain_field_and_toplevel_key_warn(self):
        pol = self.policy('version: 1\n'
                          'extra_key: 1\n'
                          'policy:\n'
                          '  crypto:\n'
                          '    min_bits: 256\n'
                          '  secrets:\n'
                          '    wrong_field: yes\n'
                          '    severity: critical\n')
        report = policies.evaluate_policies(self.scan(), self.root, [pol])
        warns = '\n'.join(report['warnings'])
        self.assertIn("unknown top-level field 'extra_key'", warns)
        self.assertIn("unknown policy domain 'crypto'", warns)
        self.assertIn("unknown field 'wrong_field' in domain 'secrets'",
                      warns)
        # the secrets domain itself still works
        self.assertEqual(_rule(report, 'POL-SECRETS-EXPOSED')['status'],
                         'pass')

    def test_policy_name_and_description_are_metadata_not_domains(self):
        pol = self.policy('version: 1\npolicy:\n  name: corp\n'
                          '  description: baseline\n')
        report = policies.evaluate_policies(self.scan(), self.root, [pol])
        self.assertEqual(report['policy_name'], 'corp')
        self.assertFalse(any("domain 'name'" in w
                             for w in report['warnings']))

    def test_empty_policy_all_rules_not_applicable(self):
        pol = self.policy('version: 7\n')
        report = policies.evaluate_policies(self.scan(), self.root, [pol])
        self.assertEqual(report['summary']['not_applicable'], 8)
        self.assertEqual(report['summary']['violations'], 0)
        self.assertEqual(report['policy_versions'],
                         [{'file': 'policy.yml', 'version': 7}])


class DeterminismTests(_TmpCase):
    def test_two_runs_produce_identical_reports(self):
        pol = self.policy(TARGET_POLICY)
        (self.root / 'AGENTS.md').write_text('ticket$1 and INTERNAL-ID\n'
                                             'inner-project too\n',
                                             encoding='utf-8')
        (self.root / '.mcp.json').write_text(
            json.dumps({'mcpServers': {'z': {}, 'a': {}}}), encoding='utf-8')
        rep = self.scan(secrets=[{'path': 'x', 'line': 1,
                                  'kind': 'api_key'}])
        one = policies.evaluate_policies(rep, self.root, [pol])
        two = policies.evaluate_policies(rep, self.root, [pol])
        self.assertEqual(json.dumps(one, sort_keys=False),
                         json.dumps(two, sort_keys=False))

    def test_secret_values_never_reach_the_report(self):
        pol = self.policy('version: 1\npolicy:\n  secrets:\n'
                          '    severity: critical\n')
        rep = self.scan(
            secrets=[{'path': 'c.env', 'line': 3, 'kind': 'api_key',
                      'mask': 'sk-CA***', 'fingerprint': 'deadbeef',
                      'value': 'sk-canary-RAW-987'}],
            top_level=[{'name': 'app', 'kind': 'repo', 'git': {}, 'extra': {
                'tracked_secrets': [{'file': '.env', 'line': 1,
                                     'kind': 'api_key',
                                     'raw': 'sk-canary-GIT-555'}],
                'hooks': []}}])
        report = policies.evaluate_policies(rep, self.root, [pol])
        dump = json.dumps(report, ensure_ascii=False)
        self.assertNotIn('sk-canary-RAW-987', dump)
        self.assertNotIn('sk-canary-GIT-555', dump)
        self.assertIn('deadbeef', dump)   # fingerprints are fine


# --- CLI ----------------------------------------------------------------------------

class CliPolicyTests(_TmpCase):
    def _scan_file(self, rep):
        p = self.root / 'scan.json'
        p.write_text(json.dumps(rep), encoding='utf-8')
        return str(p)

    def _main(self, argv):
        import agents_doctor
        out = io.StringIO()
        err = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = agents_doctor.main(argv)
        return rc, out.getvalue(), err.getvalue()

    def test_json_report_written_and_exit_zero_despite_failures(self):
        pol = self.policy('version: 1\npolicy:\n  instructions:\n'
                          '    require_agents_md: true\n')
        scan = self._scan_file(self.scan())
        out_file = self.root / 'report.json'
        rc, so, se = self._main(['policy', scan, '--policy', pol,
                                 '--out', str(out_file)])
        self.assertEqual(rc, 0, se)
        data = json.loads(out_file.read_text(encoding='utf-8'))
        self.assertIn('rules_evaluated', data)
        self.assertEqual(data['summary']['violations'], 1)
        self.assertIn('policy:', so)

    def test_markdown_report_table(self):
        pol = self.policy('version: 1\npolicy:\n  instructions:\n'
                          '    require_agents_md: true\n')
        scan = self._scan_file(self.scan())
        out_file = self.root / 'report.md'
        rc, _, se = self._main(['policy', scan, '--policy', pol,
                                '--out', str(out_file), '--format', 'md'])
        self.assertEqual(rc, 0, se)
        md = out_file.read_text(encoding='utf-8')
        self.assertIn('| Rule | Status | Violations | Severity |', md)
        self.assertIn('POL-INSTRUCTIONS-AGENTS-MD', md)

    def test_stdout_when_no_out(self):
        pol = self.policy('version: 1\n')
        scan = self._scan_file(self.scan())
        rc, so, se = self._main(['policy', scan, '--policy', pol])
        self.assertEqual(rc, 0, se)
        self.assertIn('"rules_evaluated"', so)

    def test_broken_policy_file_exits_two_with_file_and_line(self):
        pol = self.policy('version: 1\nbroken: [unclosed\n')
        scan = self._scan_file(self.scan())
        rc, _, se = self._main(['policy', scan, '--policy', pol])
        self.assertEqual(rc, 2)
        # file name plus a line number (PyYAML points at the EOF mark,
        # the fallback parser at the opening line -- both carry both)
        self.assertRegex(se, r'policy\.yml:\d+')

    def test_missing_policy_file_exits_two(self):
        scan = self._scan_file(self.scan())
        rc, _, se = self._main(['policy', scan, '--policy',
                                str(self.root / 'ghost.yml')])
        self.assertEqual(rc, 2)
        self.assertIn('ghost.yml', se)


if __name__ == '__main__':
    unittest.main()
