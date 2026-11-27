"""Enforcement v2 tests: policies.py + the policy/audit CLI contract.

Covers the enforcement behaviour: version 2 policy files with an
enforcement block turn policy violations into CI exit codes.

- back-compat pins: version 1 files and enforcement disabled always
  exit 0 once the report is written (the v1 contract);
- exit 1: block_on_failure, default_action=block, block_above
  thresholds (finding severity scale, at-or-above);
- exit 2: broken or missing policy file (configuration error);
- exit 3: unreadable scan or a scan without a root;
- exit 4: unknown_action=block with rules the scan could not check;
- merging: enabled is OR across files, conflicting actions take the
  stricter value with a warning, v1 enforcement blocks are ignored;
- the two new domains: harness_versions (ranges, None -> unknown) and
  required_skills (installed names, empty list -> unknown);
- audit --policy mirrors the contract: the scan JSON (with the
  embedded compliance report) is on disk before a blocking exit;
- CLI subprocess runs pin the process exit codes themselves.

Standard library only, Windows-safe paths, isolated temp workspaces.
"""
import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCRIPTS = REPO / 'skills' / 'agents-doctor' / 'scripts'
sys.path.insert(0, str(SCRIPTS))
import policies  # noqa: E402

DOCTOR = SCRIPTS / 'agents_doctor.py'

SECRET_LEAK = [{'path': 'config.env', 'line': 3, 'kind': 'api_key',
                'mask': 'sk-***', 'fingerprint': 'ff1'}]


def _v2_policy(domains='', enabled=True, default_action=None,
               unknown_action=None):
    lines = ['version: 2', 'policy:', '  enforcement:',
             '    enabled: %s' % ('true' if enabled else 'false')]
    if default_action:
        lines.append('    default_action: %s' % default_action)
    if unknown_action:
        lines.append('    unknown_action: %s' % unknown_action)
    lines.append(domains.rstrip('\n'))
    return '\n'.join(lines) + '\n'


class EnforcementCase(unittest.TestCase):
    """temp workspace + scan/policy helpers, rebuilt per test."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def policy(self, text, name='policy.yml'):
        p = self.root / name
        p.write_text(text, encoding='utf-8')
        return str(p)

    def scan(self, **facts):
        rep = {'schema_version': '1.0', 'root': str(self.root),
               'home': str(self.root), 'secrets': [], 'top_level': [],
               'findings_detailed': [], 'gates': [], 'harnesses': [],
               'skills': {'entries': [], 'duplicates': [],
                          'locations_checked': []}}
        rep.update(facts)
        return rep

    def scan_file(self, rep):
        p = self.root / 'scan.json'
        p.write_text(json.dumps(rep), encoding='utf-8')
        return str(p)

    def evaluate(self, rep, *files):
        return policies.evaluate_policies(rep, self.root, list(files))

    def enforcement(self, rep, *files):
        return self.evaluate(rep, *files)['summary']['enforcement']

    def main(self, argv):
        import agents_doctor
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = agents_doctor.main(argv)
        return rc, out.getvalue(), err.getvalue()


# --- back-compat: v1 and disabled enforcement exit 0 ----------------------------

class BackCompatTests(EnforcementCase):
    def test_v1_policy_with_violations_and_block_flag_exits_zero(self):
        pol = self.policy('version: 1\npolicy:\n  secrets:\n'
                          '    severity: critical\n'
                          '    block_on_failure: true\n')
        rep = self.scan(secrets=SECRET_LEAK)
        rc, _, se = self.main(['policy', self.scan_file(rep),
                               '--policy', pol])
        self.assertEqual(rc, 0, se)
        self.assertFalse(self.enforcement(rep, pol)['enabled'])

    def test_v2_enforcement_disabled_exits_zero_despite_violation(self):
        pol = self.policy(_v2_policy('  secrets:\n'
                                     '    block_on_failure: true\n',
                                     enabled=False))
        rep = self.scan(secrets=SECRET_LEAK)
        rc, _, se = self.main(['policy', self.scan_file(rep),
                               '--policy', pol])
        self.assertEqual(rc, 0, se)
        enf = self.enforcement(rep, pol)
        self.assertEqual(enf['exit_code'], 0)
        self.assertEqual(enf['action_taken'], 'none')

    def test_v2_file_without_enforcement_block_exits_zero(self):
        pol = self.policy('version: 2\npolicy:\n  secrets:\n'
                          '    severity: critical\n')
        rep = self.scan(secrets=SECRET_LEAK)
        rc, _, se = self.main(['policy', self.scan_file(rep),
                               '--policy', pol])
        self.assertEqual(rc, 0, se)
        self.assertFalse(self.enforcement(rep, pol)['enabled'])


# --- exit 1: blocking rules ------------------------------------------------------

class BlockingTests(EnforcementCase):
    def test_block_on_failure_with_violation_exits_one(self):
        pol = self.policy(_v2_policy('  secrets:\n'
                                     '    block_on_failure: true\n'))
        rep = self.scan(secrets=SECRET_LEAK)
        rc, so, se = self.main(['policy', self.scan_file(rep),
                                '--policy', pol])
        self.assertEqual(rc, 1, se)
        self.assertIn('policy: BLOCKED by 1 rule(s): POL-SECRETS-EXPOSED',
                      so)

    def test_default_action_block_without_explicit_flag_exits_one(self):
        pol = self.policy(_v2_policy('  instructions:\n'
                                     '    require_agents_md: true\n',
                                     default_action='block'))
        rc, so, se = self.main(['policy',
                                self.scan_file(self.scan()), '--policy',
                                pol])
        self.assertEqual(rc, 1, se)
        self.assertIn('POL-INSTRUCTIONS-AGENTS-MD', so)

    def test_explicit_block_false_overrides_default_block(self):
        pol = self.policy(_v2_policy(
            '  instructions:\n    require_agents_md: true\n'
            '    block_on_failure: false\n',
            default_action='block'))
        rc, _, se = self.main(['policy',
                               self.scan_file(self.scan()), '--policy',
                               pol])
        self.assertEqual(rc, 0, se)
        self.assertEqual(
            self.enforcement(self.scan(), pol)['action_taken'], 'warn')

    def test_warn_violation_with_block_above_high_does_not_block(self):
        # instructions defaults to severity warning -> finding medium,
        # and medium is below the high threshold
        pol = self.policy(_v2_policy(
            '  instructions:\n    require_agents_md: true\n'
            '    block_on_failure: true\n    block_above: high\n'))
        rc, _, se = self.main(['policy',
                               self.scan_file(self.scan()), '--policy',
                               pol])
        self.assertEqual(rc, 0, se)
        enf = self.enforcement(self.scan(), pol)
        self.assertEqual(enf['exit_code'], 0)
        self.assertEqual(enf['action_taken'], 'warn')

    def test_high_violation_at_block_above_high_blocks(self):
        # mcp defaults to error -> finding high: at-or-above the high
        # threshold
        (self.root / '.mcp.json').write_text(
            json.dumps({'mcpServers': {'rogue': {}}}), encoding='utf-8')
        pol = self.policy(_v2_policy('  mcp:\n    allowlist: []\n'
                                     '    block_on_failure: true\n'
                                     '    block_above: high\n'))
        rc, _, se = self.main(['policy',
                               self.scan_file(self.scan()), '--policy',
                               pol])
        self.assertEqual(rc, 1, se)

    def test_critical_violation_passes_block_above_high(self):
        pol = self.policy(_v2_policy(
            '  secrets:\n    severity: critical\n'
            '    block_on_failure: true\n    block_above: high\n'))
        rep = self.scan(secrets=SECRET_LEAK)
        rc, _, se = self.main(['policy', self.scan_file(rep),
                               '--policy', pol])
        self.assertEqual(rc, 1, se)

    def test_report_written_before_blocking_exit(self):
        pol = self.policy(_v2_policy('  secrets:\n'
                                     '    block_on_failure: true\n'))
        rep = self.scan(secrets=SECRET_LEAK)
        out_file = self.root / 'report.json'
        rc, _, se = self.main(['policy', self.scan_file(rep), '--policy',
                               pol, '--out', str(out_file)])
        self.assertEqual(rc, 1, se)
        data = json.loads(out_file.read_text(encoding='utf-8'))
        enf = data['summary']['enforcement']
        self.assertEqual(enf['exit_code'], 1)
        self.assertEqual(enf['action_taken'], 'block')
        self.assertEqual(enf['blocking_rules'], ['POL-SECRETS-EXPOSED'])

    def test_enforcement_summary_shape_when_enabled_and_clean(self):
        pol = self.policy(_v2_policy(''))
        enf = self.enforcement(self.scan(), pol)
        self.assertEqual(enf, {'enabled': True, 'action_taken': 'none',
                               'exit_code': 0, 'blocking_rules': []})

    def test_exception_suppressed_rule_does_not_block(self):
        (self.root / '.agents-doctor.toml').write_text(
            '[policy]\nexceptions = { POL-SECRETS-EXPOSED = "known stand" }\n',
            encoding='utf-8')
        pol = self.policy(_v2_policy('  secrets:\n'
                                     '    block_on_failure: true\n'))
        rep = self.scan(secrets=SECRET_LEAK)
        rc, _, se = self.main(['policy', self.scan_file(rep),
                               '--policy', pol])
        self.assertEqual(rc, 0, se)


# --- exit 4: unknown rules under strict enforcement ------------------------------

class UnknownActionTests(EnforcementCase):
    def test_unknown_action_block_with_unknown_rule_exits_four(self):
        # mcp is active (allowlist set) but the workspace has no MCP
        # config files at all -> the rule is unknown
        pol = self.policy(_v2_policy('  mcp:\n    allowlist: [ok]\n',
                                     unknown_action='block'))
        rc, so, se = self.main(['policy',
                                self.scan_file(self.scan()), '--policy',
                                pol])
        self.assertEqual(rc, 4, se)
        self.assertIn('POL-MCP-ALLOWLIST', so)

    def test_unknown_action_warn_with_unknown_rule_exits_zero(self):
        pol = self.policy(_v2_policy('  mcp:\n    allowlist: [ok]\n',
                                     unknown_action='warn'))
        rc, _, se = self.main(['policy',
                               self.scan_file(self.scan()), '--policy',
                               pol])
        self.assertEqual(rc, 0, se)

    def test_exit_four_blocking_rules_lists_unknown_rules(self):
        pol = self.policy(_v2_policy('  required_skills:\n'
                                     '    - notes\n',
                                     unknown_action='block'))
        # skills.entries is empty -> required_skills is unknown
        enf = self.enforcement(self.scan(), pol)
        self.assertEqual(enf['exit_code'], 4)
        self.assertEqual(enf['blocking_rules'], ['POL-REQUIRED-SKILLS'])
        self.assertEqual(enf['action_taken'], 'block')

    def test_violation_takes_precedence_over_unknown(self):
        pol = self.policy(_v2_policy('  secrets:\n'
                                     '    block_on_failure: true\n'
                                     '  mcp:\n    allowlist: [ok]\n',
                                     unknown_action='block'))
        rep = self.scan(secrets=SECRET_LEAK)
        rc, so, se = self.main(['policy', self.scan_file(rep),
                                '--policy', pol])
        self.assertEqual(rc, 1, se)
        self.assertNotIn('POL-MCP-ALLOWLIST',
                         self.enforcement(rep, pol)['blocking_rules'])

    def test_not_applicable_rules_never_trigger_exit_four(self):
        # only instructions is configured; every other domain is
        # not_applicable (not unknown), and instructions passes
        (self.root / 'AGENTS.md').write_text('ok', encoding='utf-8')
        pol = self.policy(_v2_policy('  instructions:\n'
                                     '    require_agents_md: true\n',
                                     default_action='block',
                                     unknown_action='block'))
        rc, _, se = self.main(['policy',
                               self.scan_file(self.scan()), '--policy',
                               pol])
        self.assertEqual(rc, 0, se)


# --- exit 2 and 3: configuration and scan errors ---------------------------------

class ErrorExitTests(EnforcementCase):
    def test_missing_policy_file_exits_two(self):
        rc, _, se = self.main(['policy',
                               self.scan_file(self.scan()), '--policy',
                               str(self.root / 'ghost.yml')])
        self.assertEqual(rc, 2)
        self.assertIn('ghost.yml', se)

    def test_broken_policy_file_exits_two(self):
        pol = self.policy('version: 2\npolicy: [unclosed\n')
        rc, _, se = self.main(['policy',
                               self.scan_file(self.scan()), '--policy',
                               pol])
        self.assertEqual(rc, 2)
        self.assertRegex(se, r'policy\.yml:\d+')

    def test_unreadable_scan_exits_three(self):
        pol = self.policy(_v2_policy(''))
        rc, _, se = self.main(['policy', str(self.root / 'no-scan.json'),
                               '--policy', pol])
        self.assertEqual(rc, 3)
        self.assertIn('no-scan.json', se)

    def test_scan_without_root_exits_three(self):
        rep = self.scan()
        del rep['root']
        pol = self.policy(_v2_policy(''))
        rc, _, se = self.main(['policy', self.scan_file(rep),
                               '--policy', pol])
        self.assertEqual(rc, 3)
        self.assertIn('root', se)


# --- merging enforcement across files --------------------------------------------

class EnforcementMergeTests(EnforcementCase):
    def test_enabled_is_or_across_files(self):
        on = self.policy(_v2_policy(''), name='on.yml')
        off = self.policy(_v2_policy('', enabled=False), name='off.yml')
        enf = self.enforcement(self.scan(), on, off)
        self.assertTrue(enf['enabled'])

    def test_conflicting_default_action_takes_stricter_with_warning(self):
        hard = self.policy(_v2_policy('', default_action='block'),
                           name='hard.yml')
        soft = self.policy(_v2_policy('', default_action='warn'),
                           name='soft.yml')
        report = self.evaluate(self.scan(), hard, soft)
        enf = report['summary']['enforcement']
        self.assertTrue(enf['enabled'])
        # block wins even though soft.yml came last
        rep_with_violation = self.scan()
        pol_block = self.policy(_v2_policy(
            '  instructions:\n    require_agents_md: true\n',
            default_action='block'), name='hard2.yml')
        pol_warn = self.policy(_v2_policy(
            '  instructions:\n    require_agents_md: true\n',
            default_action='warn'), name='soft2.yml')
        rc, _, se = self.main(['policy',
                               self.scan_file(rep_with_violation),
                               '--policy', pol_block, '--policy',
                               pol_warn])
        self.assertEqual(rc, 1, se)
        self.assertTrue(any('conflicting enforcement default_action' in w
                            for w in report['warnings']))

    def test_enforcement_block_in_v1_file_is_ignored(self):
        v1 = self.policy('version: 1\npolicy:\n  enforcement:\n'
                         '    enabled: true\n    default_action: block\n'
                         '  secrets:\n    block_on_failure: true\n',
                         name='old.yml')
        report = self.evaluate(self.scan(secrets=SECRET_LEAK), v1)
        enf = report['summary']['enforcement']
        self.assertFalse(enf['enabled'])
        self.assertTrue(any('requires version: 2' in w
                            for w in report['warnings']))

    def test_v1_and_v2_files_layer_domains_and_enforcement(self):
        v1 = self.policy('version: 1\npolicy:\n  secrets:\n'
                         '    severity: critical\n', name='corp.yml')
        v2 = self.policy(_v2_policy('  secrets:\n'
                                    '    block_on_failure: true\n'),
                         name='team.yml')
        enf = self.enforcement(self.scan(secrets=SECRET_LEAK), v1, v2)
        self.assertEqual(enf['exit_code'], 1)
        self.assertEqual(enf['blocking_rules'], ['POL-SECRETS-EXPOSED'])


# --- harness_versions domain -----------------------------------------------------

class HarnessVersionsTests(EnforcementCase):
    POLICY = _v2_policy('  harness_versions:\n    required:\n'
                        '      claude_code: ">=2.1"\n      codex: "<2"\n')

    def _h(self, **versions):
        return [{'harness': k, 'status': 'detected', 'version': v,
                 'confidence': 1.0, 'activity': 'active', 'markers': [],
                 'evidence': []}
                for k, v in versions.items()]

    def test_versions_in_range_pass(self):
        rep = self.scan(harnesses=self._h(claude_code='2.1.296',
                                          codex='0.9.2'))
        report = self.evaluate(rep, self.policy(self.POLICY))
        rule = [r for r in report['rules_evaluated']
                if r['id'] == 'POL-HARNESS-VERSIONS'][0]
        self.assertEqual(rule['status'], 'pass')

    def test_version_out_of_range_violates_with_evidence(self):
        rep = self.scan(harnesses=self._h(claude_code='1.0.0',
                                          codex='0.9.2'))
        report = self.evaluate(rep, self.policy(self.POLICY))
        viols = [v for v in report['violations']
                 if v['id'] == 'POL-HARNESS-VERSIONS']
        self.assertEqual(len(viols), 1)
        ev = viols[0]['evidence'][0]
        self.assertEqual(ev['harness'], 'claude_code')
        self.assertEqual(ev['version'], '1.0.0')
        self.assertEqual(ev['required'], '>=2.1')

    def test_version_none_is_unknown_not_violation(self):
        rep = self.scan(harnesses=self._h(claude_code=None, codex='0.9'))
        report = self.evaluate(rep, self.policy(self.POLICY))
        rule = [r for r in report['rules_evaluated']
                if r['id'] == 'POL-HARNESS-VERSIONS'][0]
        self.assertEqual(rule['status'], 'unknown')
        self.assertEqual(report['summary']['violations'], 0)

    def test_missing_harnesses_section_is_unknown(self):
        rep = self.scan()
        del rep['harnesses']
        report = self.evaluate(rep, self.policy(self.POLICY))
        rule = [r for r in report['rules_evaluated']
                if r['id'] == 'POL-HARNESS-VERSIONS'][0]
        self.assertEqual(rule['status'], 'unknown')

    def test_version_comparison_is_componentwise(self):
        # 2.1 == 2.1.0 numerically; 2.1.296 > 2.1
        self.assertEqual(policies._version_cmp(
            policies._version_tuple('2.1'),
            policies._version_tuple('2.1.0')), 0)
        self.assertEqual(policies._version_cmp(
            policies._version_tuple('2.1.296'),
            policies._version_tuple('2.1')), 1)
        self.assertEqual(policies._version_cmp(
            policies._version_tuple('2.1'),
            policies._version_tuple('2.2')), -1)

    def test_blocking_harness_version_exits_one(self):
        pol = self.policy(_v2_policy('  harness_versions:\n'
                                     '    required:\n'
                                     '      claude_code: ">=2.1"\n'
                                     '    block_on_failure: true\n'))
        rep = self.scan(harnesses=self._h(claude_code='1.5.0'))
        rc, _, se = self.main(['policy', self.scan_file(rep),
                               '--policy', pol])
        self.assertEqual(rc, 1, se)


# --- required_skills domain -------------------------------------------------------

class RequiredSkillsTests(EnforcementCase):
    POLICY = _v2_policy('  required_skills:\n    - notes\n    - review\n')

    def _skills(self, *names):
        return {'entries': [{'name': n, 'path': 'x', 'location': 'l',
                             'md5': 'd', 'desc_len': 1,
                             'has_triggers': False} for n in names],
                'duplicates': [], 'locations_checked': ['l']}

    def test_all_skills_present_pass(self):
        rep = self.scan(skills=self._skills('notes', 'review', 'extra'))
        report = self.evaluate(rep, self.policy(self.POLICY))
        rule = [r for r in report['rules_evaluated']
                if r['id'] == 'POL-REQUIRED-SKILLS'][0]
        self.assertEqual(rule['status'], 'pass')

    def test_missing_skill_violates(self):
        rep = self.scan(skills=self._skills('notes'))
        report = self.evaluate(rep, self.policy(self.POLICY))
        viols = [v for v in report['violations']
                 if v['id'] == 'POL-REQUIRED-SKILLS']
        self.assertEqual(len(viols), 1)
        self.assertEqual(viols[0]['evidence'][0]['skill'], 'review')

    def test_empty_entries_is_unknown(self):
        rep = self.scan(skills=self._skills())
        report = self.evaluate(rep, self.policy(self.POLICY))
        rule = [r for r in report['rules_evaluated']
                if r['id'] == 'POL-REQUIRED-SKILLS'][0]
        self.assertEqual(rule['status'], 'unknown')
        self.assertEqual(report['summary']['violations'], 0)

    def test_missing_skills_section_is_unknown(self):
        rep = self.scan()
        del rep['skills']
        report = self.evaluate(rep, self.policy(self.POLICY))
        rule = [r for r in report['rules_evaluated']
                if r['id'] == 'POL-REQUIRED-SKILLS'][0]
        self.assertEqual(rule['status'], 'unknown')


# --- audit --policy mirrors the contract -----------------------------------------

class AuditPolicyTests(EnforcementCase):
    def _audit(self, *extra):
        import agents_doctor
        out = self.root / 'audit-scan.json'
        argv = ['audit', str(self.root), '--home', str(self.root),
                '--out', str(out)] + list(extra)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = agents_doctor.main(argv)
        return rc, out, buf.getvalue()

    def test_audit_policy_block_writes_scan_and_returns_one(self):
        # no AGENTS.md/CLAUDE.md in the workspace -> instructions
        # violation; default_action block -> the audit fails after the
        # scan is on disk
        pol = self.policy(_v2_policy('  instructions:\n'
                                     '    require_agents_md: true\n',
                                     default_action='block'))
        rc, out, so = self._audit('--policy', pol)
        self.assertEqual(rc, 1)
        self.assertTrue(out.is_file())
        rep = json.loads(out.read_text(encoding='utf-8'))
        enf = rep['policy_report']['summary']['enforcement']
        self.assertEqual(enf['exit_code'], 1)
        self.assertIn('POL-INSTRUCTIONS-AGENTS-MD', enf['blocking_rules'])
        self.assertIn('policy: BLOCKED by 1 rule(s)', so)

    def test_audit_policy_without_block_returns_zero(self):
        (self.root / 'AGENTS.md').write_text('ok', encoding='utf-8')
        pol = self.policy(_v2_policy('  instructions:\n'
                                     '    require_agents_md: true\n',
                                     default_action='block'))
        rc, out, _ = self._audit('--policy', pol)
        self.assertEqual(rc, 0)
        self.assertTrue(out.is_file())

    def test_audit_policy_unknown_block_returns_four(self):
        pol = self.policy(_v2_policy('  mcp:\n    allowlist: [ok]\n',
                                     unknown_action='block'))
        rc, out, _ = self._audit('--policy', pol)
        self.assertEqual(rc, 4)
        rep = json.loads(out.read_text(encoding='utf-8'))
        self.assertEqual(
            rep['policy_report']['summary']['enforcement']['exit_code'], 4)

    def test_audit_policy_config_error_returns_two(self):
        rc, out, _ = self._audit('--policy',
                                 str(self.root / 'ghost.yml'))
        self.assertEqual(rc, 2)

    def test_markdown_report_carries_enforcement_line(self):
        pol = self.policy(_v2_policy('  secrets:\n'
                                     '    block_on_failure: true\n'))
        rep = self.scan(secrets=SECRET_LEAK)
        out_file = self.root / 'report.md'
        rc, _, se = self.main(['policy', self.scan_file(rep), '--policy',
                               pol, '--out', str(out_file),
                               '--format', 'md'])
        self.assertEqual(rc, 1, se)
        md = out_file.read_text(encoding='utf-8')
        self.assertIn('Enforcement: enabled, action block, exit code 1',
                      md)
        self.assertIn('POL-SECRETS-EXPOSED', md)


# --- CLI subprocess: the process exit codes themselves ---------------------------

class CliSubprocessTests(EnforcementCase):
    def _run(self, *args):
        return subprocess.run(
            [sys.executable, str(DOCTOR)] + [str(a) for a in args],
            capture_output=True, text=True, encoding='utf-8',
            errors='replace', cwd=str(self.root))

    def test_subprocess_v1_policy_exits_zero(self):
        pol = self.policy('version: 1\npolicy:\n  secrets:\n'
                          '    block_on_failure: true\n')
        scan = self.scan_file(self.scan(secrets=SECRET_LEAK))
        proc = self._run('policy', scan, '--policy', pol)
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_subprocess_blocked_policy_exits_one_with_report(self):
        pol = self.policy(_v2_policy('  secrets:\n'
                                     '    block_on_failure: true\n'))
        scan = self.scan_file(self.scan(secrets=SECRET_LEAK))
        out_file = self.root / 'report.json'
        proc = self._run('policy', scan, '--policy', pol, '--out',
                         out_file)
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertIn('policy: BLOCKED by 1 rule(s)', proc.stdout)
        self.assertTrue(out_file.is_file())

    def test_subprocess_missing_policy_file_exits_two(self):
        scan = self.scan_file(self.scan())
        proc = self._run('policy', scan, '--policy',
                         self.root / 'ghost.yml')
        self.assertEqual(proc.returncode, 2)

    def test_subprocess_broken_scan_exits_three(self):
        pol = self.policy(_v2_policy(''))
        proc = self._run('policy', self.root / 'broken.json',
                         '--policy', pol)
        self.assertEqual(proc.returncode, 3)


# --- fallback parser: the v2 format without PyYAML -------------------------------

class FallbackParserV2Tests(EnforcementCase):
    TARGET_V2 = _v2_policy(
        '  secrets:\n    severity: critical\n    block_on_failure: true\n'
        '    block_above: high\n'
        '  harness_versions:\n    required:\n'
        '      claude_code: ">=2.1"\n      codex: "<2"\n'
        '  required_skills:\n    - notes\n',
        default_action='warn', unknown_action='warn')

    def test_fallback_parser_matches_pyyaml_on_v2_format(self):
        from unittest import mock
        path = self.policy(self.TARGET_V2)
        with mock.patch.object(policies, 'yaml', None):
            fallback = policies.parse_policy_file(path)
        if policies.yaml is None:
            self.skipTest('PyYAML not installed')
        full = policies.parse_policy_file(path)
        self.assertEqual(fallback, full)

    def test_v2_target_policy_evaluates(self):
        pol = self.policy(self.TARGET_V2)
        rep = self.scan(secrets=SECRET_LEAK)
        enf = self.enforcement(rep, pol)
        self.assertEqual(enf['exit_code'], 1)   # critical >= high


if __name__ == '__main__':
    unittest.main()
