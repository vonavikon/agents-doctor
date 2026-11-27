"""Tests for the gate engine (skills/agents-doctor/scripts/gates.py)
and the finding model (report_model.py).

All facts are fabricated dicts: the engine is pure and never touches the
filesystem.
"""
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'skills' / 'agents-doctor' / 'scripts'))
sys.path.insert(0, str(Path(__file__).resolve().parent / 'integration'))

import gates
import report_model
# report lookups, under the names the tests were written with
from fixtures import by_check as _by_check, gate_of as _gate  # noqa: E402
from fixtures import rule_of as _rule  # noqa: E402

FID_RE = re.compile(r'^(SEC|CFG|RUL|DIR|SKL|GIT|GOV|HLTH)-(\d{3})$')


def clean_facts():
    """A well-kept workspace: every gate has data and only the two
    absence-warns (G2 no configs, G6 no prevention hook) fire."""
    return {
        'schema_version': '1.0',
        'root': 'W:/ws', 'home': 'W:/home',
        'top_level': [
            {'name': 'api', 'kind': 'repo',
             'git': {'remote': 'https://git.example.com/api.git',
                     'last_commit': '2026-11-01T10:00:00+03:00',
                     'dirty': [], 'untracked': []},
             'size_bytes': 10 * 1024 * 1024,
             'extra': {'branch': 'main', 'ahead_behind': {'ahead': 0, 'behind': 0},
                       'remote_class': 'self-hosted',
                       'credentials_in_remote': False, 'gitignore': True,
                       'hooks': [], 'sync_commits_last30': 2,
                       'tracked_secrets': [], 'nested_repos': []}},
            {'name': 'notes.md', 'kind': 'file', 'size_bytes': 100},
        ],
        'dup_checkouts': {},
        'context_files': [
            {'path': 'AGENTS.md', 'lines': 10, 'size_bytes': 2048,
             'is_pointer': False, 'generic_markers': [],
             'dead_links': [], 'dead_paths': [], 'dead_commands': []},
        ],
        'context_drift': [],
        'context_tax': {'session_files': [
            {'role': 'project', 'path': 'AGENTS.md', 'size_bytes': 2048}],
            'project_total_bytes': 2048, 'benchmark_project_bytes': 16384,
            'memory_over_limit': [], 'memory_over_lines': []},
        'harness': {
            'tools': [
                {'tool': 'zcode', 'exists': True,
                 'last_activity_days_ago': 2, 'state': 'active',
                 'reads': ['AGENTS.md']},
                {'tool': 'claude', 'exists': True,
                 'last_activity_days_ago': 200, 'state': 'abandoned',
                 'reads': ['CLAUDE.md', 'AGENTS.md']},
                {'tool': 'codex', 'exists': False, 'reads': ['AGENTS.md']},
            ],
            'project_dirs': [{'name': '.agents', 'exists': True},
                             {'name': '.claude', 'exists': False},
                             {'name': '.codex', 'exists': False},
                             {'name': '.zcode/config.json', 'exists': True}],
            'notes': [],
        },
        'skills': {
            'entries': [
                {'name': 'deploy', 'desc_len': 80, 'has_triggers': True,
                 'md5': 'a' * 32,
                 'path': 'W:/home/.zcode/skills/deploy/SKILL.md',
                 'location': 'user-zcode',
                 # merged enrichment keys (the alternative source is
                 # skills_extra)
                 'frontmatter_ok': True, 'missing_fields': [],
                 'dead_refs': [], 'parser': 'yaml'},
            ],
            'duplicates': [],
            'locations_checked': ['user-zcode: W:/home/.zcode/skills'],
        },
        'context_budget': [{'root': '.', 'total_bytes': 2048, 'over': False}],
        'chain_budget_over': False,
        'junk': {'files': [], 'dirs': [], 'empty_dirs': []},
        'duplicates': [], 'large_files': [], 'secrets': [],
        # enrichment sections present but empty: checked, nothing found
        'config_integrity': [],
        'heavy_outside_git': [],
        'junk_classified': [],
        'stats': {'total_files': 10, 'total_size_bytes': 10 * 1024 * 1024},
    }


def statuses_by_gid(gate_list):
    return {g['gid']: g['status'] for g in gate_list}


def findings_by_fid(finding_list):
    return {f['fid']: f for f in finding_list}


def big_facts():
    """A messy workspace exercising every finding prefix with many items."""
    facts = clean_facts()
    facts['secrets'] = [{'path': 'dir/file%d.env' % i, 'line': i + 1,
                         'kind': 'api-key', 'mask': 'sk-***',
                         'fingerprint': 'sha256:%016x' % i, 'confidence': 0.95}
                        for i in range(40)]
    facts['context_files'] = [
        {'path': 'AGENTS.md', 'lines': 5, 'size_bytes': 100, 'is_pointer': False,
         'generic_markers': [],
         'dead_links': ['missing%d.md' % i for i in range(25)],
         'dead_paths': [], 'dead_commands': []}]
    facts['context_drift'] = [{'path': 'dir%d' % i, 'jaccard': 0.1} for i in range(5)]
    facts['config_integrity'] = [
        {'path': 'c%d.json' % i, 'format': 'json', 'ok': False,
         'error': 'syntax error', 'dup_keys': ['k']}
        for i in range(8)]
    facts['skills'] = {
        'entries': [{'name': 's%d' % i, 'desc_len': 50, 'has_triggers': True,
                     'md5': 'b' * 32, 'path': 'W:/skills/s%d/SKILL.md' % i,
                     'location': 'user-zcode'}
                    for i in range(10)],
        'duplicates': [{'name': 'd%d' % i, 'copies': 2, 'sync': 'DIVERGED',
                        'paths': ['a', 'b']} for i in range(6)],
        'locations_checked': []}
    facts['skills_extra'] = {'s%d' % i: {'frontmatter_ok': True,
                                         'missing_fields': [], 'dead_refs': [],
                                         'parser': 'yaml'}
                             for i in range(10)}
    facts['dup_checkouts'] = {'https://x/%d.git' % i: ['a%d' % i, 'b%d' % i]
                              for i in range(4)}
    facts['harness']['notes'] = ['note %d' % i for i in range(5)]
    facts['junk_classified'] = [
        {'path': 'junk%d' % i, 'reason': 'temp file', 'size_bytes': 10,
         'cls': 'confirmed_unused', 'confidence': 0.9,
         'signals': {'tracked': False, 'age_days': 10, 'referenced': False}}
        for i in range(15)]
    return facts


class ModelTests(unittest.TestCase):
    def test_severities_and_statuses_are_disjoint(self):
        self.assertEqual(set(report_model.SEVERITIES) & set(report_model.STATUSES),
                         set())

    def test_empty_evidence_requires_unknown(self):
        with self.assertRaises(ValueError):
            report_model.make_finding(
                'SEC-001', 'G6', 'secrets', 'critical', 'fail', 't', 'd',
                [], 0.9, 'r')
        # empty evidence with status unknown is the one allowed shape
        f = report_model.make_finding(
            'SEC-001', 'G6', 'secrets', 'low', 'unknown', 't', 'd', [], 0.5, 'r')
        self.assertEqual(f['evidence'], [])
        self.assertEqual(f['status'], 'unknown')
        self.assertEqual(f['schema_version'], report_model.SCHEMA_VERSION)
        self.assertEqual(sorted(f), sorted(report_model.FINDING_KEYS
                                           + ('schema_version',)))

    def test_rejects_bad_enums_confidence_and_evidence(self):
        def call(**overrides):
            kwargs = dict(fid='X-001', gate='G1', category='dirs',
                          severity='critical', status='fail', title='t',
                          description='d', evidence=[{'file': 'a'}],
                          confidence=0.9, recommendation='r')
            kwargs.update(overrides)
            return report_model.make_finding(**kwargs)

        with self.assertRaises(ValueError):
            call(severity='fatal')
        with self.assertRaises(ValueError):
            call(status='nope')
        with self.assertRaises(ValueError):
            call(confidence=1.5)
        with self.assertRaises(ValueError):
            call(evidence=['not a dict'])

    def test_make_gate_validates_n_status_and_evidence(self):
        base = dict(gid='G1', name='n', description='d', checks=[],
                    pass_when='p', fail_when='f', warn_when='w',
                    evidence=['e'], confidence=0.9, recommendation='r',
                    doc_ref='README.md#gates')
        g = report_model.make_gate(n=1, status='pass', **base)
        self.assertEqual(g['n'], 1)
        self.assertEqual(sorted(g), sorted(report_model.GATE_KEYS
                                           + ('schema_version',)))
        for bad in (0, 10, '1', None, True):
            with self.assertRaises(ValueError):
                report_model.make_gate(n=bad, status='pass', **base)
        with self.assertRaises(ValueError):
            report_model.make_gate(n=1, status='ok', **base)
        base['evidence'] = [{'not': 'a string'}]
        with self.assertRaises(ValueError):
            report_model.make_gate(n=1, status='pass', **base)

    def test_validators(self):
        self.assertTrue(report_model.valid_severity('critical'))
        self.assertFalse(report_model.valid_severity('fail'))
        self.assertTrue(report_model.valid_status('not_applicable'))
        self.assertFalse(report_model.valid_status('high'))


class CleanWorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.gate_list, self.finding_list = gates.evaluate(clean_facts())

    def test_clean_workspace_statuses(self):
        self.assertEqual(statuses_by_gid(self.gate_list),
                         {'G1': 'pass', 'G2': 'warn', 'G3': 'pass', 'G4': 'pass',
                          'G5': 'pass', 'G6': 'warn', 'G7': 'pass', 'G8': 'pass',
                          'G9': 'pass'})

    def test_g2_warns_with_explicit_evidence(self):
        g2 = next(g for g in self.gate_list if g['gid'] == 'G2')
        self.assertTrue(any('no configuration files found' in e
                            for e in g2['evidence']))
        self.assertEqual(g2['checks'][0]['status'], 'warn')

    def test_every_gate_has_executed_checks_evidence(self):
        for g in self.gate_list:
            self.assertTrue(g['evidence'], 'gate %s has no evidence' % g['gid'])
            self.assertTrue(g['checks'], 'gate %s has no checks' % g['gid'])
            self.assertGreaterEqual(g['confidence'], 0.0)
            self.assertLessEqual(g['confidence'], 1.0)

    def test_gate_numbers_follow_definitions(self):
        self.assertEqual([g['n'] for g in self.gate_list], list(range(1, 10)))
        self.assertEqual([g['name'] for g in self.gate_list],
                         [gd['name'] for gd in gates.GATE_DEFS])

    def test_gate_policy_matches_spec_thresholds(self):
        p = gates.GATE_POLICY
        self.assertEqual(p['JUNK_FAIL_BYTES'], 500 * 1024 * 1024)
        self.assertEqual(p['EMPTY_WARN_COUNT'], 10)
        self.assertEqual(p['TRACKED_BIG_BYTES'], 5 * 1024 * 1024)
        self.assertEqual(p['DESC_LIMIT'], 1024)
        self.assertEqual(p['PROJECT_BENCH'], 16 * 1024)
        self.assertEqual(p['CHAIN_BUDGET'], 32768)
        self.assertEqual(p['SECRET_PREVENTION_HINTS']['hook_names'],
                         ('pre-commit', 'pre-push'))


class DriftTests(unittest.TestCase):
    def test_drifted_pair_fails_g1_and_g3(self):
        facts = clean_facts()
        facts['context_drift'] = [{'path': 'proj', 'jaccard': 0.2},
                                  {'path': 'other', 'jaccard': 0.3}]
        gate_list, finding_list = gates.evaluate(facts)
        st = statuses_by_gid(gate_list)
        self.assertEqual(st['G1'], 'fail')
        self.assertEqual(st['G3'], 'fail')
        fids = [f['fid'] for f in finding_list]
        # one structure finding per pair (G1) and one rules finding per pair (G3)
        self.assertEqual(fids.count('DIR-001') + fids.count('DIR-002'), 2)
        self.assertIn('RUL-001', fids)
        self.assertIn('RUL-002', fids)

    def test_drift_is_cross_referenced_not_duplicated_in_g8(self):
        facts = clean_facts()
        facts['context_drift'] = [{'path': 'proj', 'jaccard': 0.2}]
        gate_list, finding_list = gates.evaluate(facts)
        g8 = next(g for g in gate_list if g['gid'] == 'G8')
        self.assertEqual(g8['status'], 'pass')
        # no governance finding was created for the drift itself
        self.assertFalse([f for f in finding_list
                          if f['gate'] == 'G8' and f['status'] != 'pass'])
        self.assertTrue(any('RUL-' in e or 'DIR-' in e for e in g8['evidence']))


class SecretTests(unittest.TestCase):
    def test_exposed_secret_fails_g6_with_critical_findings(self):
        facts = clean_facts()
        facts['secrets'] = [{'path': '.env', 'line': 3, 'kind': 'api-key',
                             'mask': 'sk-***', 'fingerprint': 'sha256:deadbeef',
                             'confidence': 0.95}]
        facts['top_level'][0]['extra']['tracked_secrets'] = [
            {'file': 'settings.py', 'line': 7, 'kind': 'secret literal',
             'rule_id': 'SEC-005', 'confidence': 0.7, 'value': '[REDACTED]',
             'fingerprint': 'sha256:cafef00d'}]
        gate_list, finding_list = gates.evaluate(facts)
        self.assertEqual(statuses_by_gid(gate_list)['G6'], 'fail')
        sec = [f for f in finding_list
               if f['fid'].startswith('SEC-') and f['severity'] == 'critical']
        self.assertEqual(len(sec), 2)
        self.assertEqual([f['fid'] for f in sec], ['SEC-001', 'SEC-002'])
        # secrets fail AND the prevention warn is still recorded
        prevention = findings_by_fid(finding_list)['SEC-003']
        self.assertEqual(prevention['status'], 'warn')
        self.assertIn('prevention', prevention['title'].lower())
        # masks and fingerprints only: no raw values anywhere
        blob = repr(sec)
        self.assertNotIn('supersecret', blob)

    def test_prevention_hook_passes_g6(self):
        facts = clean_facts()
        facts['top_level'][0]['extra']['hooks'] = [
            {'name': 'pre-commit',
             'flags': {'add_all': False, 'push': False, 'secret_scan': True}}]
        # without deep history data G6 stays unknown: an unchecked history
        # must never read as pass (v0.7.0 contract)
        gate_list, _ = gates.evaluate(facts)
        self.assertEqual(statuses_by_gid(gate_list)['G6'], 'unknown')

        # with a complete deep scan on record the gate reaches pass
        facts['top_level'][0]['extra']['history_coverage'] = {
            'commits_scanned': 12, 'commits_total': 12, 'complete': True,
            'all_refs': False}
        gate_list, _ = gates.evaluate(facts)
        self.assertEqual(statuses_by_gid(gate_list)['G6'], 'pass')


class SkillsTests(unittest.TestCase):
    def test_missing_name_field_fails_g5_via_skills_extra(self):
        facts = clean_facts()
        entry = facts['skills']['entries'][0]
        for key in ('frontmatter_ok', 'missing_fields', 'dead_refs', 'parser'):
            entry.pop(key)
        facts['skills_extra'] = {'deploy': {'frontmatter_ok': True,
                                            'missing_fields': ['name'],
                                            'dead_refs': [], 'parser': 'yaml'}}
        gate_list, finding_list = gates.evaluate(facts)
        self.assertEqual(statuses_by_gid(gate_list)['G5'], 'fail')
        f = findings_by_fid(finding_list)['SKL-001']
        self.assertEqual(f['status'], 'fail')
        self.assertIn('name', f['title'])

    def test_missing_description_detected_from_merged_entry(self):
        facts = clean_facts()
        facts['skills']['entries'][0]['desc_len'] = None  # no description line
        gate_list, finding_list = gates.evaluate(facts)
        self.assertEqual(statuses_by_gid(gate_list)['G5'], 'fail')
        f = findings_by_fid(finding_list)['SKL-001']
        self.assertIn('description', f['title'])

    def test_fallback_parser_yields_unknown(self):
        facts = clean_facts()
        entry = facts['skills']['entries'][0]
        for key in ('frontmatter_ok', 'missing_fields', 'dead_refs', 'parser'):
            entry.pop(key)
        facts['skills_extra'] = {'deploy': {'frontmatter_ok': None,
                                            'missing_fields': [],
                                            'dead_refs': [], 'parser': 'fallback'}}
        gate_list, finding_list = gates.evaluate(facts)
        self.assertEqual(statuses_by_gid(gate_list)['G5'], 'unknown')
        f = findings_by_fid(finding_list)['SKL-001']
        self.assertEqual(f['status'], 'unknown')
        self.assertIn('fallback', f['title'])

    def test_unparseable_frontmatter_fails(self):
        facts = clean_facts()
        facts['skills']['entries'][0]['frontmatter_ok'] = False
        facts['skills']['entries'][0]['parser'] = 'yaml'
        gate_list, _ = gates.evaluate(facts)
        self.assertEqual(statuses_by_gid(gate_list)['G5'], 'fail')

    def test_desc_over_limit_and_diverged_copies_fail(self):
        facts = clean_facts()
        facts['skills']['entries'][0]['desc_len'] = 2000
        facts['skills']['duplicates'] = [
            {'name': 'deploy', 'copies': 2, 'sync': 'DIVERGED', 'paths': ['a', 'b']}]
        gate_list, finding_list = gates.evaluate(facts)
        self.assertEqual(statuses_by_gid(gate_list)['G5'], 'fail')
        titles = ' | '.join(f['title'] for f in finding_list)
        self.assertIn('2000 chars', titles)
        self.assertIn('Diverged copies', titles)


class JunkAndHealthTests(unittest.TestCase):
    def test_junk_over_threshold_fails_g9(self):
        facts = clean_facts()
        facts['junk'] = {'files': [], 'empty_dirs': [],
                         'dirs': [{'path': 'node_modules',
                                   'reason': 'build artifact (node_modules)',
                                   'size_bytes': 600 * 1024 * 1024,
                                   'files': 50000}]}
        facts['junk_classified'] = [
            {'path': 'old-backup', 'reason': 'backup dir', 'size_bytes': 1024,
             'cls': 'confirmed_unused', 'confidence': 0.9,
             'signals': {'tracked': False, 'age_days': 400, 'referenced': False}}]
        gate_list, finding_list = gates.evaluate(facts)
        self.assertEqual(statuses_by_gid(gate_list)['G9'], 'fail')
        by_fid = findings_by_fid(finding_list)
        # classified junk warns first, the volume breach fails
        self.assertEqual(by_fid['HLTH-001']['status'], 'warn')
        self.assertEqual(by_fid['HLTH-002']['status'], 'fail')
        self.assertIn('confirmed_unused', by_fid['HLTH-001']['title'])

    def test_empty_dirs_info_below_threshold_warn_above(self):
        facts = clean_facts()
        facts['junk']['empty_dirs'] = ['d%d' % i for i in range(3)]
        gate_list, finding_list = gates.evaluate(facts)
        self.assertEqual(statuses_by_gid(gate_list)['G9'], 'pass')
        # the G2 no-configs finding is info too; scope to the health gate
        info = [f for f in finding_list
                if f['severity'] == 'info' and f['gate'] == 'G9']
        self.assertEqual(len(info), 1)
        self.assertEqual(info[0]['status'], 'pass')

        facts['junk']['empty_dirs'] = ['d%d' % i for i in range(11)]
        gate_list, finding_list = gates.evaluate(facts)
        self.assertEqual(statuses_by_gid(gate_list)['G9'], 'warn')
        info = [f for f in finding_list
                if f['severity'] == 'info' and f['gate'] == 'G9']
        self.assertEqual(len(info), 1)
        self.assertEqual(info[0]['status'], 'warn')

    def test_large_tracked_file_fails_g7(self):
        facts = clean_facts()
        facts['large_files'] = [{'path': 'api/big.bin',
                                 'size_bytes': 6 * 1024 * 1024}]
        gate_list, finding_list = gates.evaluate(facts)
        st = statuses_by_gid(gate_list)
        self.assertEqual(st['G7'], 'fail')
        # the same file is not re-warned in G9 (it lives inside a repo)
        self.assertEqual(st['G9'], 'pass')
        git_fail = [f for f in finding_list
                    if f['fid'].startswith('GIT') and f['status'] == 'fail']
        self.assertEqual(len(git_fail), 1)

    def test_heavy_dir_outside_git_fails_g4(self):
        facts = clean_facts()
        facts['heavy_outside_git'] = [
            {'path': 'data', 'size_bytes': 900 * 1024 * 1024, 'depth': 1}]
        gate_list, finding_list = gates.evaluate(facts)
        self.assertEqual(statuses_by_gid(gate_list)['G4'], 'fail')
        f = findings_by_fid(finding_list)['DIR-001']
        self.assertEqual(f['status'], 'fail')


class MissingFactsTests(unittest.TestCase):
    def test_missing_skills_section_is_unknown_not_pass(self):
        facts = clean_facts()
        facts.pop('skills')
        gate_list, finding_list = gates.evaluate(facts)
        self.assertEqual(statuses_by_gid(gate_list)['G5'], 'unknown')
        unk = [f for f in finding_list
               if f['gate'] == 'G5' and f['status'] == 'unknown']
        self.assertTrue(unk)

    def test_missing_top_level_makes_g4_and_g7_unknown(self):
        facts = clean_facts()
        facts.pop('top_level')
        st = statuses_by_gid(*gates.evaluate(facts)[:1])
        self.assertEqual(st['G4'], 'unknown')
        self.assertEqual(st['G7'], 'unknown')

    def test_missing_config_section_is_unknown_not_warn(self):
        # absent facts are not the same as 'checked and there are no configs'
        facts = clean_facts()
        facts.pop('config_integrity')
        st = statuses_by_gid(*gates.evaluate(facts)[:1])
        self.assertEqual(st['G2'], 'unknown')

    def test_no_repos_marks_g7_not_applicable(self):
        facts = clean_facts()
        facts['top_level'] = [facts['top_level'][1]]  # keep the plain file only
        st = statuses_by_gid(*gates.evaluate(facts)[:1])
        self.assertEqual(st['G7'], 'not_applicable')


class IdStabilityTests(unittest.TestCase):
    def test_unique_ids_and_prefix_format_on_large_run(self):
        gate_list, finding_list = gates.evaluate(big_facts())
        fids = [f['fid'] for f in finding_list]
        self.assertGreater(len(fids), 100)
        self.assertEqual(len(fids), len(set(fids)))
        for fid in fids:
            self.assertRegex(fid, FID_RE)

    def test_counters_are_contiguous_per_prefix(self):
        _, finding_list = gates.evaluate(big_facts())
        seen = {}
        for f in finding_list:
            prefix, num = f['fid'].split('-')
            seen.setdefault(prefix, []).append(int(num))
        self.assertTrue(seen)
        for prefix, nums in seen.items():
            self.assertEqual(nums, list(range(1, len(nums) + 1)), prefix)

    def test_first_finding_of_each_category_is_001(self):
        _, finding_list = gates.evaluate(big_facts())
        first = {}
        for f in finding_list:
            first.setdefault(f['fid'].split('-')[0], f['fid'])
        for prefix, fid in first.items():
            self.assertEqual(fid, '%s-001' % prefix)

    def test_ids_stable_across_identical_runs(self):
        gates_out_a, findings_a = gates.evaluate(big_facts())
        gates_out_b, findings_b = gates.evaluate(big_facts())
        self.assertEqual([f['fid'] for f in findings_a],
                         [f['fid'] for f in findings_b])
        self.assertEqual(statuses_by_gid(gates_out_a), statuses_by_gid(gates_out_b))

    def test_statuses_and_severities_validated_on_large_run(self):
        gate_list, finding_list = gates.evaluate(big_facts())
        for f in finding_list:
            self.assertIn(f['severity'], report_model.SEVERITIES)
            self.assertIn(f['status'], report_model.STATUSES)
            self.assertTrue(f['evidence'])
        for g in gate_list:
            self.assertIn(g['status'], report_model.STATUSES)


# --- G5 without skills ----------------------------------------------------------

class SkillsCoverageGateTests(unittest.TestCase):
    """No skill folders, or none found: gate 5 is not_applicable with a
    reason, never pass. A report made before the coverage was recorded
    does not pass either."""

    def _g5(self, skills):
        gs, findings = gates.evaluate({'skills': skills, 'skills_extra': {}})
        return _gate({'gates': gs}, 'G5'), findings

    def _assert_no_pass(self, gate):
        self.assertNotIn('pass', [c['status'] for c in gate['checks']])

    def test_no_skill_folders_is_not_applicable_with_reason(self):
        gate, findings = self._g5({'entries': [], 'duplicates': [],
                                   'coverage': {'checked': [], 'failed': [],
                                                'truncated': []}})
        self.assertEqual(gate['status'], 'not_applicable')
        self._assert_no_pass(gate)
        self.assertTrue(gate['status_reason'])
        for c in gate['checks']:
            self.assertEqual(c.get('reason'), gate['status_reason'])
        self.assertEqual([f for f in findings if f['gate'] == 'G5'], [])

    def test_checked_empty_folders_is_not_applicable(self):
        gate, _ = self._g5({'entries': [], 'duplicates': [],
                            'coverage': {'checked': ['project-agents',
                                                     'user-claude'],
                                         'failed': [], 'truncated': []}})
        self.assertEqual(gate['status'], 'not_applicable')
        self._assert_no_pass(gate)
        self.assertEqual(_rule(gate, 'duplicate-copies')['status'],
                         'not_applicable')
        self.assertEqual(gate['status_why'], 'no_skills_found')
        self.assertEqual(gate['status_count'], 2)

    def test_old_reports_without_coverage_do_not_pass_either(self):
        gate, _ = self._g5({'entries': [], 'duplicates': [],
                            'locations_checked': ['x: y']})
        self.assertEqual(gate['status'], 'not_applicable')
        self._assert_no_pass(gate)

    def test_valid_skill_passes(self):
        entry = {'name': 'ok', 'desc_len': 30, 'has_triggers': True,
                 'md5': 'x', 'path': 'P', 'location': 'x'}
        # the gate reads the frontmatter facts by name or by path
        extra = {'ok': {'frontmatter_ok': True, 'missing_fields': [],
                        'fields_checked': True, 'parse_error': None,
                        'dead_refs': [], 'parser': 'yaml', 'path': 'P'}}
        gs, _ = gates.evaluate({
            'skills': {'entries': [entry], 'duplicates': [],
                       'coverage': {'checked': ['x'], 'failed': [],
                                    'truncated': []}},
            'skills_extra': extra})
        self.assertEqual(_gate({'gates': gs}, 'G5')['status'], 'pass')


# --- G6 without git: secret prevention -----------------------------------------

def _no_git_facts(**over):
    facts = {
        'context_drift': [], 'context_files': [], 'context_tax': {},
        'harness': {'tools': [], 'project_dirs': [], 'notes': []},
        'skills': {'entries': [], 'duplicates': []}, 'skills_extra': {},
        'top_level': [{'name': 'notes.md', 'kind': 'file', 'size_bytes': 10}],
        'git_roots': [], 'dup_checkouts': {}, 'junk': {},
        'duplicates': [], 'large_files': [], 'secrets': [],
        'chain_budget_over': False, 'context_budget': [],
        'junk_classified': [], 'config_integrity': [],
        'heavy_outside_git': [],
    }
    facts.update(over)
    return facts


def _repo(name, hooks=()):
    return {'name': name, 'kind': 'repo', 'size_bytes': 1000,
            'git': {'remote': None, 'last_commit': None, 'dirty': [],
                    'untracked': [], 'credentials_in_remote': False},
            'extra': {'hooks': [{'name': h, 'flags': {'secret_scan': True}}
                                for h in hooks],
                      'tracked_secrets': [], 'gitignore': True}}


class SecretPreventionTests(unittest.TestCase):

    def _evaluate(self, facts):
        gs, findings = gates.evaluate(facts)
        return gs, findings

    def test_no_git_no_hook_advice(self):
        gs, findings = self._evaluate(_no_git_facts())
        gate = _gate({'gates': gs}, 'G6')
        self.assertEqual(_rule(gate, 'secret-prevention')['status'],
                         'not_applicable')
        self.assertTrue(_rule(gate, 'secret-prevention').get('reason'))
        self.assertEqual(_by_check({'findings_detailed': findings},
                                   'SEC_PREVENTION_ABSENT'), [])
        self.assertEqual(_by_check({'findings_detailed': findings},
                                   'SEC_PREVENTION_UNVERIFIED'), [])
        self.assertNotIn('pre-commit', ' '.join(
            f['recommendation'] for f in findings if f['gate'] == 'G6'))
        # the rest of the git side is not applicable either, not "pass"
        self.assertEqual(_rule(gate, 'tracked-secrets')['status'],
                         'not_applicable')
        self.assertEqual(_rule(gate, 'history-coverage')['status'],
                         'not_applicable')

    def test_file_secret_still_fails_without_git(self):
        sec = [{'path': '.mcp.json', 'line': 7, 'kind': 'api-key',
                'mask': 'sk-***', 'fingerprint': 'hmac256:x', 'confidence': 0.95}]
        gs, findings = self._evaluate(_no_git_facts(secrets=sec))
        gate = _gate({'gates': gs}, 'G6')
        self.assertEqual(gate['status'], 'fail')
        self.assertEqual(_rule(gate, 'exposed-secrets')['status'], 'fail')
        exposed = [f for f in findings if f['gate'] == 'G6'
                   and f['status'] == 'fail']
        self.assertEqual(len(exposed), 1)
        self.assertEqual(exposed[0]['evidence'][0]['line'], 7)
        self.assertEqual(exposed[0]['evidence'][0]['mask'], 'sk-***')
        self.assertNotIn('pre-commit', exposed[0]['recommendation'])

    def test_top_level_repo_without_hook_still_warns(self):
        facts = _no_git_facts(top_level=[_repo('api'), {'name': 'n', 'kind': 'file',
                                                        'size_bytes': 1}],
                              git_roots=['api'])
        gs, findings = self._evaluate(facts)
        gate = _gate({'gates': gs}, 'G6')
        self.assertEqual(_rule(gate, 'secret-prevention')['status'], 'warn')
        hits = _by_check({'findings_detailed': findings}, 'SEC_PREVENTION_ABSENT')
        self.assertEqual(len(hits), 1)
        self.assertIn('1 repositories', hits[0]['description'])
        self.assertNotIn('0 repositories', hits[0]['description'])

    def test_repo_with_secret_scan_hook_passes(self):
        facts = _no_git_facts(top_level=[_repo('api', hooks=('pre-commit',))],
                              git_roots=['api'])
        gs, _ = self._evaluate(facts)
        self.assertEqual(_rule(_gate({'gates': gs}, 'G6'),
                                'secret-prevention')['status'], 'pass')

    def test_repositories_nested_in_a_plain_folder_are_unverified(self):
        # the workspace is a wrapper folder: no repo on top, clones inside
        facts = _no_git_facts(
            top_level=[{'name': 'projects', 'kind': 'dir', 'size_bytes': 10}],
            git_roots=[str(Path('projects') / 'a'),
                       str(Path('projects') / 'b')])
        gs, findings = self._evaluate(facts)
        gate = _gate({'gates': gs}, 'G6')
        self.assertEqual(_rule(gate, 'secret-prevention')['status'], 'unknown')
        hits = _by_check({'findings_detailed': findings},
                         'SEC_PREVENTION_UNVERIFIED')
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]['status'], 'unknown')
        self.assertIn('2 repositories', hits[0]['title'])
        self.assertEqual(_by_check({'findings_detailed': findings},
                                   'SEC_PREVENTION_ABSENT'), [])
        self.assertNotIn('pre-commit', hits[0]['recommendation'])
        # their index and history were not read either
        self.assertEqual(_rule(gate, 'tracked-secrets')['status'], 'unknown')
        self.assertEqual(len(_by_check({'findings_detailed': findings},
                                       'SEC_GIT_SIDE_UNVERIFIED')), 1)
        hygiene = _gate({'gates': gs}, 'G7')
        self.assertEqual(hygiene['status'], 'unknown')

    def test_old_report_with_the_root_as_repo_stays_unverified(self):
        # a report made before the scanner read the folder itself: the
        # root is listed as a repository, but there is no entry for it
        facts = _no_git_facts(git_roots=['.'])
        gs, findings = self._evaluate(facts)
        self.assertEqual(_rule(_gate({'gates': gs}, 'G6'),
                                'secret-prevention')['status'], 'unknown')
        self.assertEqual(len(_by_check({'findings_detailed': findings},
                                       'SEC_PREVENTION_UNVERIFIED')), 1)

    def test_reports_without_the_repository_list_treat_no_top_repo_as_no_git(self):
        facts = _no_git_facts()
        del facts['git_roots']
        gs, _ = self._evaluate(facts)
        self.assertEqual(_rule(_gate({'gates': gs}, 'G6'),
                                'secret-prevention')['status'],
                         'not_applicable')


if __name__ == '__main__':
    unittest.main()
