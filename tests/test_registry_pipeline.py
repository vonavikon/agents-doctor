"""Integration tests for the harness-registry stage (Phase 1/2): the
scan pipeline must carry detection records, adapter findings and
instruction conflicts into the report and the nine gates."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / 'skills' / 'agents-doctor' / 'scripts'
sys.path.insert(0, str(SCRIPTS))

import audit_scan  # noqa: E402
import harness  # noqa: E402
from harness.collect import CATEGORY_MAP  # noqa: E402


def _ws():
    root = Path(tempfile.mkdtemp())
    home = Path(tempfile.mkdtemp())
    return root, home


class RegistryPipelineTest(unittest.TestCase):
    def test_all_adapters_in_report(self):
        root, home = _ws()
        rep = audit_scan.scan(root, home, False)
        ids = [h['harness'] for h in rep['harnesses']]
        self.assertEqual(ids, harness.adapter_ids())
        matrix_ids = [m['harness_id'] for m in rep['harness_spec_matrix']]
        self.assertEqual(matrix_ids, harness.adapter_ids())

    def test_adapter_finding_reaches_gates(self):
        root, home = _ws()
        # wildcard Bash permission: CLAUDE_SETTINGS_PERMISSIONS_WILDCARD
        # -> G6 security, fail
        settings = root / '.claude'
        settings.mkdir()
        (settings / 'settings.json').write_text(
            '{"permissions": {"allow": ["Bash(*)"]}}', encoding='utf-8')
        rep = audit_scan.scan(root, home, False)
        af = [f for f in rep['findings_detailed']
              if f.get('check_id') == 'CLAUDE_SETTINGS_PERMISSIONS_WILDCARD']
        self.assertEqual(len(af), 1)
        f = af[0]
        self.assertEqual(f['gate'], 'G6')
        self.assertEqual(f['status'], 'fail')
        self.assertEqual(f['harness'], 'claude_code')
        self.assertTrue(f['fid'].startswith('SEC-'))
        g6 = next(g for g in rep['gates'] if g['gid'] == 'G6')
        self.assertEqual(g6['status'], 'fail')

    def test_instruction_conflict_reaches_g3(self):
        root, home = _ws()
        (root / 'AGENTS.md').write_text(
            '# rules\nAlways run the full test suite\n', encoding='utf-8')
        src = root / 'src'
        src.mkdir()
        (src / 'AGENTS.md').write_text(
            'Never run the full test suite\n', encoding='utf-8')
        rep = audit_scan.scan(root, home, False)
        conflicts = [f for f in rep['findings_detailed']
                     if f.get('check_id', '').startswith('INSTR_')]
        # same file pair may be claimed by several harnesses: exactly
        # one conflict per (file_a, line_a, file_b, line_b)
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(conflicts[0]['gate'], 'G3')
        self.assertIn(conflicts[0]['check_id'],
                      ('INSTR_CONTRADICTION', 'INSTR_DIVERGENCE'))
        summary = rep.get('instruction_conflict_summary', {})
        self.assertEqual(sum(summary.values()), 1)

    def test_clean_workspace_no_adapter_findings(self):
        root, home = _ws()
        rep = audit_scan.scan(root, home, False)
        # adapter findings are the ones carrying a harness: every
        # finding has a check_id (it names the finding type)
        af = [f for f in rep['findings_detailed'] if f.get('harness')]
        self.assertEqual(af, [])
        self.assertEqual(rep['instruction_conflict_summary'],
                         {'contradiction': 0, 'duplication': 0,
                          'divergence': 0})

    def test_category_map_covers_all_categories(self):
        for cat in ('structure', 'instructions', 'config', 'security',
                    'compatibility'):
            self.assertIn(cat, CATEGORY_MAP)

    def test_scan_survives_registry_failure(self):
        # the registry stage is wrapped: a broken adapter must never
        # kill the scan; simulate by pointing one adapter at garbage
        import harness.collect as collect_mod
        original = collect_mod.detect_harnesses

        def boom(ctx, activity=None):
            raise RuntimeError('simulated registry failure')

        collect_mod.detect_harnesses = boom
        try:
            root, home = _ws()
            rep = audit_scan.scan(root, home, False)
            self.assertEqual(rep['harnesses'], [])
            self.assertIn('gates', rep)
        finally:
            collect_mod.detect_harnesses = original

    def test_report_serializes(self):
        root, home = _ws()
        settings = root / '.claude'
        settings.mkdir()
        (settings / 'settings.json').write_text(
            '{"permissions": {"allow": ["Bash(*)"]}}', encoding='utf-8')
        (root / 'AGENTS.md').write_text('Always run tests\n', encoding='utf-8')
        rep = audit_scan.scan(root, home, False)
        blob = json.dumps(rep, ensure_ascii=False)
        self.assertIn('CLAUDE_SETTINGS_PERMISSIONS_WILDCARD', blob)


if __name__ == '__main__':
    unittest.main()
