"""Remediation tests: per-step risk levels, the action types
(fix_dead_link, normalize_config, dedupe_instructions, context_tax_hint)
and the operations journal.

Fixtures follow the two established conventions:

- findings that the real scanner produces (RUL dead references, RUL
  instruction-size, CFG duplicate keys) come from an in-process
  audit_scan.scan() of a seeded workspace, exactly like
  test_remediate.py;
- adapter check_id findings (INSTR_DUPLICATION) are hand-crafted the
  way test_remediation_hardening.py crafts them (the adapters are
  covered by tests/test_harness_*.py).

Risk semantics under test: safe steps run after the single global
'yes'; review steps additionally prompt per step (a 'no' or EOF skips
with reason 'declined-risk'); manual steps never execute. Steps
without a risk field behave as 'safe' (back-compat with plans built
before the field existed).
"""
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / 'skills' / 'agents-doctor' / 'scripts'
sys.path.insert(0, str(SCRIPTS))

import audit_scan  # noqa: E402
import remediate   # noqa: E402
import trashops    # noqa: E402

AGENTS_MD = ('# Project rules\n'
             '\n'
             'See [docs](./missing.md) and [guide](./gone/guide.md).\n'
             'Deploy with `scripts/deploy.sh` from the repo root.\n')

BIG_AGENTS_MD = '# Big rules\n\n' + ('- rule line kept in context\n' * 900)


def force_rmtree(path):
    """rmtree that clears the read-only flag git puts on some files."""
    def _onexc(func, p, _exc):
        os.chmod(p, stat.S_IWRITE)
        func(p)
    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=_onexc)
    else:
        shutil.rmtree(path, onerror=lambda func, p, _ei: _onexc(func, p, _ei))


def build_workspace(base, agents_md=AGENTS_MD):
    """One git repo with dead references in AGENTS.md, an empty dir and
    no .gitignore; .mcp.json with duplicate keys at the workspace root."""
    ws, home = base / 'ws', base / 'home'
    repo = ws / 'repo'
    repo.mkdir(parents=True, exist_ok=True)
    home.mkdir(exist_ok=True)
    (repo / 'AGENTS.md').write_text(agents_md, encoding='utf-8')
    (repo / 'empty').mkdir()
    (ws / '.mcp.json').write_text(
        '{\n    "b": 1,\n    "a": 2,\n    "b": 3\n}\n', encoding='utf-8')
    subprocess.run(['git', '-C', str(repo), 'init', '-q'],
                   check=True, capture_output=True)
    return ws, home, repo


def instr_dup_rep(ws, file_a, file_b):
    """A hand-crafted INSTR_DUPLICATION adapter finding the way
    harness/collect.py appends it (both sides of the block in the
    evidence)."""
    return {'root': str(ws), 'findings_detailed': [{
        'fid': 'RUL-007', 'gate': 'G3', 'category': 'rules',
        'severity': 'low', 'status': 'warn',
        'title': 'Instruction duplication across sources',
        'description': 'duplication: "keep commits small" vs ...',
        'evidence': [
            {'file': str(file_a), 'line': 4, 'detail': 'keep commits small'},
            {'file': str(file_b), 'line': 9, 'detail': 'keep commits small'},
        ],
        'recommendation': 'align the sources',
        'harness': 'zcode/codex', 'check_id': 'INSTR_DUPLICATION'}]}


def claude_local_rep(ws, target):
    """A CLAUDE_LOCAL_DEPRECATED adapter finding (risk review)."""
    return {'root': str(ws), 'findings_detailed': [{
        'fid': 'GOV-001', 'gate': 'G8', 'category': 'compatibility',
        'severity': 'medium', 'status': 'warn', 'title': 'adapter finding',
        'description': 'd', 'evidence': [{'file': str(target)}],
        'recommendation': 'r', 'confidence': 0.9,
        'harness': 'claude_code', 'check_id': 'CLAUDE_LOCAL_DEPRECATED'}]}


class RemediationV3Case(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp())
        self.ws, self.home, self.repo = build_workspace(self.base)
        self.trash = self.ws / trashops.TRASH_DIR_NAME
        self.journal = self.ws / remediate.OPS_DIR_NAME \
            / remediate.OPS_JOURNAL_NAME

    def tearDown(self):
        force_rmtree(self.base)

    def scan(self):
        self.rep = audit_scan.scan(self.ws, self.home)
        return self.rep

    @staticmethod
    def fid_for(rep, needle):
        for f in rep['findings_detailed']:
            if needle in f['title']:
                return f['fid']
        raise AssertionError(
            'no finding titled like %r; got %s'
            % (needle, [f['title'] for f in rep['findings_detailed']]))

    def apply_quiet(self, steps, root=None, **kw):
        out, err = StringIO(), StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            report = remediate.apply_plan(steps, str(root or self.ws), **kw)
        self.last_err = err.getvalue()
        return report

    def journal_lines(self):
        self.assertTrue(self.journal.is_file(),
                        'no operations journal at %s' % self.journal)
        return [json.loads(line) for line
                in self.journal.read_text(encoding='utf-8').splitlines()]


# --- risk on the pre-existing step types --------------------------------------------

class RiskOnExistingPlans(RemediationV3Case):
    def test_rmdir_step_is_safe(self):
        rep = self.scan()
        steps = remediate.plan(rep, self.fid_for(rep, 'empty directories'))
        self.assertEqual(steps[0]['action'], 'rmdir')
        self.assertEqual(steps[0]['risk'], 'safe')

    def test_gitignore_step_is_safe(self):
        rep = self.scan()
        steps = remediate.plan(rep, self.fid_for(rep, 'No .gitignore'))
        self.assertEqual(steps[0]['action'], 'write_gitignore')
        self.assertEqual(steps[0]['risk'], 'safe')

    def test_trash_move_step_is_safe(self):
        junk = self.ws / 'temp-data.txt'
        junk.write_text('stale junk\n', encoding='utf-8')
        old = time.time() - 100 * 86400
        os.utime(junk, (old, old))
        rep = self.scan()
        steps = remediate.plan(
            rep, self.fid_for(rep, 'Unused data (confirmed_unused)'))
        self.assertEqual(steps[0]['action'], 'trash_move')
        self.assertEqual(steps[0]['risk'], 'safe')

    def test_claude_local_deprecated_is_review(self):
        local = self.ws / 'CLAUDE.local.md'
        local.write_text('local overrides\n', encoding='utf-8')
        steps = remediate.plan(claude_local_rep(self.ws, local), 'GOV-001')
        self.assertEqual(steps[0]['action'], 'trash_move')
        self.assertEqual(steps[0]['risk'], 'review')

    def test_print_plan_shows_risk(self):
        rep = self.scan()
        steps = remediate.plan(rep, self.fid_for(rep, 'empty directories'))
        out = StringIO()
        with redirect_stdout(out):
            remediate.print_plan('HLTH-001', steps)
        self.assertIn('(risk: safe)', out.getvalue())
        manual = remediate.plan(rep, self.fid_for(rep, 'missing.md'))
        out = StringIO()
        with redirect_stdout(out):
            remediate.print_plan('RUL-001', manual)
        self.assertIn('(risk: manual)', out.getvalue())


# --- manual-risk plans: fix_dead_link / dedupe_instructions / context_tax_hint ------

class FixDeadLinkPlan(RemediationV3Case):
    def test_plan_from_scan_one_manual_step_per_reference(self):
        rep = self.scan()
        for needle, kind in (('./missing.md', 'link'),
                             ('./gone/guide.md', 'link'),
                             ('scripts/deploy.sh', 'path')):
            fid = self.fid_for(rep, needle)
            steps = remediate.plan(rep, fid)
            self.assertEqual(len(steps), 1, needle)
            st = steps[0]
            self.assertEqual(st['action'], 'fix_dead_link')
            self.assertEqual(st['risk'], 'manual')
            self.assertEqual(st['kind'], kind)
            self.assertEqual(st['ref'], needle)
            # CI runners hand out 8.3-short (Windows) or
            # symlinked (macOS /var) temp paths; resolve both sides
            self.assertEqual(Path(st['target']).resolve(),
                             (self.repo / 'AGENTS.md').resolve())
            self.assertFalse(st['autofix_available'])
            self.assertIn('%s:%s' % ('repo/AGENTS.md', st['line']),
                          st['command'])

    def test_line_number_points_at_the_reference(self):
        rep = self.scan()
        steps = remediate.plan(rep, self.fid_for(rep, './missing.md'))
        self.assertEqual(steps[0]['line'], 3)   # the 'See [docs]...' line

    def test_apply_never_executes_and_never_rewrites_the_file(self):
        before = (self.repo / 'AGENTS.md').read_text(encoding='utf-8')
        rep = self.scan()
        steps = remediate.plan(rep, self.fid_for(rep, './missing.md'))
        report = self.apply_quiet(steps, assume_yes=True)
        self.assertEqual(report['executed'], [])
        self.assertEqual([s.get('reason') for s in report['skipped']],
                         ['manual'])
        self.assertEqual(
            (self.repo / 'AGENTS.md').read_text(encoding='utf-8'), before)
        self.assertFalse(self.trash.exists())   # no run, no lock residue


class DedupeInstructionsPlan(RemediationV3Case):
    def test_plan_names_both_files_and_lines(self):
        a = self.ws / 'AGENTS.md'
        b = self.ws / 'CLAUDE.md'
        a.write_text('rules\n- keep commits small\n', encoding='utf-8')
        b.write_text('more\n- keep commits small\n', encoding='utf-8')
        steps = remediate.plan(instr_dup_rep(self.ws, a, b), 'RUL-007')
        self.assertEqual(len(steps), 2)
        self.assertTrue(all(s['action'] == 'dedupe_instructions' for s in steps))
        self.assertTrue(all(s['risk'] == 'manual' for s in steps))
        self.assertTrue(all(s['check_id'] == 'INSTR_DUPLICATION'
                            for s in steps))
        self.assertEqual({Path(s['target']) for s in steps}, {a, b})
        joined = ' '.join(s['command'] for s in steps)
        self.assertIn('AGENTS.md:4', joined)
        self.assertIn('CLAUDE.md:9', joined)
        self.assertIn('shared file', joined)     # extract-once advice

    def test_apply_skips_manual_and_touches_nothing(self):
        a = self.ws / 'AGENTS.md'
        b = self.ws / 'CLAUDE.md'
        a.write_text('rules\n- keep commits small\n', encoding='utf-8')
        b.write_text('more\n- keep commits small\n', encoding='utf-8')
        steps = remediate.plan(instr_dup_rep(self.ws, a, b), 'RUL-007')
        report = self.apply_quiet(steps, assume_yes=True)
        self.assertEqual(report['executed'], [])
        self.assertEqual([s.get('reason') for s in report['skipped']],
                         ['manual', 'manual'])
        self.assertTrue(a.is_file() and b.is_file())
        self.assertEqual(a.read_text(encoding='utf-8'),
                         'rules\n- keep commits small\n')

    def test_first_file_gone_since_scan_plans_nothing_for_it(self):
        b = self.ws / 'CLAUDE.md'
        b.write_text('more\n- keep commits small\n', encoding='utf-8')
        steps = remediate.plan(
            instr_dup_rep(self.ws, self.ws / 'gone.md', b), 'RUL-007')
        self.assertEqual(len(steps), 1)
        self.assertEqual(Path(steps[0]['target']), b)


class ContextTaxHintPlan(RemediationV3Case):
    def big_scan(self):
        # a second, independent fixture under the same base (torn down
        # with it) so the small one stays intact
        self.big_base = self.base / 'big'
        self.big_base.mkdir()
        self.ws2, self.home2, self.repo2 = build_workspace(
            self.big_base, agents_md=BIG_AGENTS_MD)
        rep = audit_scan.scan(self.ws2, self.home2)
        return rep, self.ws2

    def test_plan_from_scan_is_manual_advice(self):
        rep, ws2 = self.big_scan()
        fid = self.fid_for(rep, 'Instruction file over')
        steps = remediate.plan(rep, fid)
        self.assertEqual(len(steps), 1)
        st = steps[0]
        self.assertEqual(st['action'], 'context_tax_hint')
        self.assertEqual(st['risk'], 'manual')
        self.assertEqual(Path(st['target']).resolve(),
                         (self.repo2 / 'AGENTS.md').resolve())
        self.assertFalse(st['autofix_available'])
        self.assertIn('shrink', st['command'])

    def test_apply_never_executes(self):
        rep, ws2 = self.big_scan()
        steps = remediate.plan(rep, self.fid_for(rep, 'Instruction file over'))
        report = self.apply_quiet(steps, root=ws2, assume_yes=True)
        self.assertEqual(report['executed'], [])
        self.assertEqual([s.get('reason') for s in report['skipped']],
                         ['manual'])
        self.assertTrue((self.repo2 / 'AGENTS.md').is_file())


# --- review risk: per-step confirmation ----------------------------------------------

class ReviewPerStepConfirmation(RemediationV3Case):
    def normalize_steps(self):
        rep = self.scan()
        return remediate.plan(rep, self.fid_for(rep, 'Duplicate key'))

    def test_yes_after_yes_applies_the_step(self):
        steps = self.normalize_steps()
        self.assertEqual(steps[0]['risk'], 'review')
        answers = iter(['yes', 'yes'])
        prompts = []
        report = self.apply_quiet(
            steps, confirm=lambda p: (prompts.append(p), next(answers))[1])
        self.assertEqual(len(report['executed']), 1)
        self.assertEqual(len(prompts), 2)        # global + per-step
        self.assertIn('risk=REVIEW', prompts[1])
        self.assertIn('-- apply this step? [yes/no]', prompts[1])
        self.assertIn('.mcp.json', prompts[1])

    def test_no_skips_the_step_as_declined_risk(self):
        steps = self.normalize_steps()
        before = (self.ws / '.mcp.json').read_text(encoding='utf-8')
        report = self.apply_quiet(
            steps, confirm=lambda p: 'no' if 'risk=' in p else 'yes')
        self.assertEqual(report['executed'], [])
        self.assertEqual(report['failed'], [])
        self.assertEqual(report['skipped'][0]['reason'], 'declined-risk')
        self.assertEqual((self.ws / '.mcp.json').read_text(encoding='utf-8'),
                         before)
        self.assertFalse(self.trash.exists())

    def test_eof_on_the_step_prompt_skips_as_declined_risk(self):
        steps = self.normalize_steps()
        def confirm(prompt):
            if 'risk=' in prompt:
                raise EOFError
            return 'yes'
        report = self.apply_quiet(steps, confirm=confirm)
        self.assertEqual(report['executed'], [])
        self.assertEqual(report['skipped'][0]['reason'], 'declined-risk')

    def test_global_no_declines_the_whole_apply(self):
        steps = self.normalize_steps()
        report = self.apply_quiet(steps, confirm=lambda p: 'no')
        self.assertTrue(report['declined'])
        self.assertEqual(report['skipped'], [])
        self.assertTrue((self.ws / '.mcp.json').is_file())

    def test_assume_yes_skips_per_step_prompts(self):
        # automation path: no prompt at all, the review step applies
        prompts = []
        def confirm(prompt):
            prompts.append(prompt)
            return 'yes'
        steps = self.normalize_steps()
        report = self.apply_quiet(steps, assume_yes=True, confirm=confirm)
        self.assertEqual(len(report['executed']), 1)
        self.assertEqual(prompts, [])

    def test_claude_local_review_declined_keeps_the_file(self):
        local = self.ws / 'CLAUDE.local.md'
        local.write_text('local overrides\n', encoding='utf-8')
        steps = remediate.plan(claude_local_rep(self.ws, local), 'GOV-001')
        report = self.apply_quiet(
            steps, confirm=lambda p: 'no' if 'risk=' in p else 'yes')
        self.assertEqual(report['executed'], [])
        self.assertEqual(report['skipped'][0]['reason'], 'declined-risk')
        self.assertEqual(local.read_text(encoding='utf-8'),
                         'local overrides\n')


# --- normalize_config -----------------------------------------------------------------

class NormalizeConfig(RemediationV3Case):
    def test_plan_from_scan_lists_duplicates_with_snapshot(self):
        rep = self.scan()
        steps = remediate.plan(rep, self.fid_for(rep, 'Duplicate key'))
        self.assertEqual(len(steps), 1)
        st = steps[0]
        self.assertEqual(st['action'], 'normalize_config')
        self.assertEqual(st['risk'], 'review')
        self.assertTrue(st['autofix_available'])
        self.assertEqual(st['dup_keys'], ['b'])
        self.assertIn('snapshot', st)
        self.assertIn('first occurrence wins', st['command'])

    def test_apply_removes_duplicates_keeps_first_value_and_order(self):
        rep = self.scan()
        steps = remediate.plan(rep, self.fid_for(rep, 'Duplicate key'))
        report = self.apply_quiet(steps, assume_yes=True)
        self.assertEqual(len(report['executed']), 1)
        self.assertEqual(report['executed'][0]['result'], 'normalized')
        self.assertEqual(report['executed'][0]['removed_dup_keys'], ['b'])
        data = json.loads((self.ws / '.mcp.json').read_text(encoding='utf-8'))
        self.assertEqual(data, {'b': 1, 'a': 2})     # FIRST b, order kept
        self.assertEqual(list(data.keys()), ['b', 'a'])

    def test_nested_duplicate_keys_removed_too(self):
        (self.ws / '.mcp.json').write_text(
            '{"top": 1, "nest": {"k": 1, "j": 0, "k": 2}, "top": 9}',
            encoding='utf-8')
        rep = self.scan()
        steps = remediate.plan(rep, self.fid_for(rep, 'Duplicate key'))
        self.assertEqual(steps[0]['dup_keys'], ['k', 'top'])
        self.apply_quiet(steps, assume_yes=True)
        data = json.loads((self.ws / '.mcp.json').read_text(encoding='utf-8'))
        self.assertEqual(data, {'top': 1, 'nest': {'k': 1, 'j': 0}})

    def test_original_backed_up_in_trash_run(self):
        original = (self.ws / '.mcp.json').read_text(encoding='utf-8')
        rep = self.scan()
        steps = remediate.plan(rep, self.fid_for(rep, 'Duplicate key'))
        report = self.apply_quiet(steps, assume_yes=True)
        run = Path(report['trash_run'])
        entries = json.loads(
            (run / trashops.MANIFEST_NAME).read_text(encoding='utf-8')
        )['entries']
        by_action = {e['action']: e for e in entries}
        self.assertIn('trash_move', by_action)      # the backup
        self.assertEqual(by_action['trash_move']['status'], 'moved')
        self.assertIn('create_file', by_action)     # the rewrite
        self.assertEqual(by_action['create_file']['status'], 'created')
        backup = run / by_action['trash_move']['trash_path']
        self.assertEqual(backup.read_text(encoding='utf-8'), original)

    def test_mtime_drift_between_plan_and_apply_skips_changed(self):
        rep = self.scan()
        steps = remediate.plan(rep, self.fid_for(rep, 'Duplicate key'))
        cfg = self.ws / '.mcp.json'
        cfg.write_text('{"b": 1, "a": 2, "b": 3, "late": true}\n',
                       encoding='utf-8')            # edited after planning
        report = self.apply_quiet(steps, assume_yes=True)
        self.assertEqual(report['executed'], [])
        self.assertEqual(report['failed'], [])
        self.assertEqual(report['skipped'][0]['reason'], 'changed')
        self.assertEqual(
            json.loads(cfg.read_text(encoding='utf-8')),
            {'b': 1, 'a': 2, 'b': 3, 'late': True})  # untouched on disk
        self.assertFalse(self.trash.exists())

    def test_rewrite_uses_indent_two(self):
        rep = self.scan()
        steps = remediate.plan(rep, self.fid_for(rep, 'Duplicate key'))
        self.apply_quiet(steps, assume_yes=True)
        text = (self.ws / '.mcp.json').read_text(encoding='utf-8')
        self.assertIn('\n  "b": 1,', text)          # 2-space indent
        self.assertNotIn('\n    "b"', text)         # the 4-space source is gone

    def test_non_json_target_refused(self):
        toml = self.ws / 'settings.toml'
        toml.write_text('b = 1\nb = 2\n', encoding='utf-8')
        rep = {'root': str(self.ws), 'findings_detailed': [{
            'fid': 'CFG-009', 'gate': 'G2', 'category': 'config',
            'severity': 'medium', 'status': 'fail',
            'title': "Duplicate key 'b' in settings.toml",
            'description': 'd',
            'evidence': [{'file': 'settings.toml', 'key': 'b'}],
            'recommendation': 'r'}]}
        with self.assertRaises(remediate.UnsupportedError) as cm:
            remediate.plan(rep, 'CFG-009')
        self.assertIn('not valid JSON', str(cm.exception))
        self.assertEqual(toml.read_text(encoding='utf-8'), 'b = 1\nb = 2\n')

    def test_unparseable_json_refused(self):
        (self.ws / '.mcp.json').write_text('{"b": 1, "b": 2', encoding='utf-8')
        rep = {'root': str(self.ws), 'findings_detailed': [{
            'fid': 'CFG-010', 'gate': 'G2', 'category': 'config',
            'severity': 'medium', 'status': 'fail',
            'title': "Duplicate key 'b' in .mcp.json",
            'description': 'd',
            'evidence': [{'file': '.mcp.json', 'key': 'b'}],
            'recommendation': 'r'}]}
        with self.assertRaises(remediate.UnsupportedError) as cm:
            remediate.plan(rep, 'CFG-010')
        self.assertIn('not valid JSON', str(cm.exception))

    def test_duplicates_already_gone_plans_nothing(self):
        rep = self.scan()
        # fix the file after the scan: the finding is stale, the plan is empty
        (self.ws / '.mcp.json').write_text('{"b": 1, "a": 2}\n',
                                           encoding='utf-8')
        self.assertEqual(
            remediate.plan(rep, self.fid_for(rep, 'Duplicate key')), [])

    def test_target_gone_since_scan_plans_nothing(self):
        rep = self.scan()
        (self.ws / '.mcp.json').unlink()
        self.assertEqual(
            remediate.plan(rep, self.fid_for(rep, 'Duplicate key')), [])


# --- operations journal ----------------------------------------------------------------

class OperationsJournal(RemediationV3Case):
    def junk_steps(self):
        junk = self.ws / 'temp-data.txt'
        junk.write_text('CANARY-SECRET-987654321\n', encoding='utf-8')
        old = time.time() - 100 * 86400
        os.utime(junk, (old, old))
        rep = self.scan()
        return remediate.plan(
            rep, self.fid_for(rep, 'Unused data (confirmed_unused)')), junk

    def test_journal_written_with_paths_and_results_only(self):
        steps, junk = self.junk_steps()
        expected_target = str(junk.resolve())
        report = self.apply_quiet(steps, fid='HLTH-042', assume_yes=True)
        self.assertEqual(len(report['executed']), 1)
        lines = self.journal_lines()
        self.assertEqual(len(lines), 1)
        entry = lines[0]
        self.assertEqual(entry['fid'], 'HLTH-042')
        self.assertIsNone(entry['check_id'])
        self.assertEqual(entry['root'], str(self.ws.resolve()))
        self.assertEqual(entry['steps'], [{
            'action': 'trash_move', 'target': expected_target,
            'risk': 'safe', 'result': 'moved'}])
        self.assertIn('ts', entry)

    def test_journal_never_contains_file_contents(self):
        steps, _junk = self.junk_steps()
        self.apply_quiet(steps, fid='HLTH-042', assume_yes=True)
        raw = self.journal.read_text(encoding='utf-8')
        self.assertNotIn('CANARY', raw)             # no content, no secrets
        self.assertEqual(raw.count('\n'), 1)        # one line per apply

    def test_journal_failure_never_fails_apply(self):
        # .agents-doctor exists as a FILE: the journal write fails, the
        # apply itself still executes
        blocker = self.ws / remediate.OPS_DIR_NAME
        blocker.write_text('in the way\n', encoding='utf-8')
        steps, junk = self.junk_steps()
        report = self.apply_quiet(steps, fid='HLTH-042', assume_yes=True)
        self.assertEqual(len(report['executed']), 1)
        self.assertFalse(junk.exists())
        self.assertIn('operations journal not written', self.last_err)

    def test_declined_apply_is_journaled(self):
        steps, _junk = self.junk_steps()
        report = self.apply_quiet(steps, fid='HLTH-042',
                                  confirm=lambda p: 'no')
        self.assertTrue(report['declined'])
        entry = self.journal_lines()[0]
        self.assertEqual(entry['steps'][0]['result'], 'skipped:declined')

    def test_check_id_and_risk_journaled(self):
        a = self.ws / 'AGENTS.md'
        b = self.ws / 'CLAUDE.md'
        a.write_text('rules\n- keep commits small\n', encoding='utf-8')
        b.write_text('more\n- keep commits small\n', encoding='utf-8')
        steps = remediate.plan(instr_dup_rep(self.ws, a, b), 'RUL-007')
        self.apply_quiet(steps, fid='RUL-007', assume_yes=True)
        entry = self.journal_lines()[0]
        self.assertEqual(entry['check_id'], 'INSTR_DUPLICATION')
        self.assertEqual([s['result'] for s in entry['steps']],
                         ['skipped:manual', 'skipped:manual'])
        self.assertEqual({s['risk'] for s in entry['steps']}, {'manual'})

    def test_declined_risk_step_journaled(self):
        rep = self.scan()
        steps = remediate.plan(rep, self.fid_for(rep, 'Duplicate key'))
        self.apply_quiet(
            steps, fid='CFG-001',
            confirm=lambda p: 'no' if 'risk=' in p else 'yes')
        entry = self.journal_lines()[0]
        self.assertEqual(entry['steps'][0]['result'],
                         'skipped:declined-risk')
        self.assertEqual(entry['steps'][0]['risk'], 'review')


# --- back-compat: plans without risk fields -------------------------------------------

class BackCompatLegacyPlans(RemediationV3Case):
    def test_legacy_step_without_risk_applies_after_single_yes(self):
        lonely = self.ws / 'emptydir'
        lonely.mkdir()
        step = {'action': 'rmdir', 'target': str(lonely),
                'command': 'rmdir', 'reversible': True, 'note': ''}
        prompts = []
        def confirm(prompt):
            prompts.append(prompt)
            return 'yes'
        report = self.apply_quiet([step], confirm=confirm)
        self.assertEqual(len(report['executed']), 1)
        self.assertFalse(lonely.exists())
        self.assertEqual(len(prompts), 1)   # global only, no per-step gate

    def test_legacy_manual_action_still_skips(self):
        # the pre-risk 'manual' action keeps its never-execute contract
        step = {'action': 'manual', 'target': str(self.ws / 'AGENTS.md'),
                'command': 'migrate by hand', 'reversible': False,
                'note': ''}
        report = self.apply_quiet([step], assume_yes=True)
        self.assertEqual(report['executed'], [])
        self.assertEqual(report['skipped'][0]['reason'], 'manual')

    def test_step_risk_defaults_missing_and_unknown_to_safe(self):
        self.assertEqual(remediate.step_risk({}), 'safe')
        self.assertEqual(remediate.step_risk({'risk': 'yolo'}), 'safe')
        self.assertEqual(remediate.step_risk({'risk': 'review'}), 'review')
        self.assertEqual(remediate.step_risk(None), 'safe')


if __name__ == '__main__':
    unittest.main()
