"""Focus Engine tests for agents_doctor.py --focus.

Pins the focus engine to the canonical gate mapping documented in
commands/agents-doctor.md:

    security  -> G6, G7
    structure -> G1, G4, G9
    agents    -> G2, G3, G5, G8

Filtering is gate-based only: gates are kept by 'gid', findings by
their 'gate' field. Category lists used to ride along in FOCUS_SPECS
and drifted from the gate mapping (structure carried G2 and dropped
G9, findings were picked by category names), so they are gone; the
gate ids are the single source of truth.

The chaos fixture (llm-eval/fixtures/chaos.json) covers all nine
gates. Each mode must keep exactly the findings whose gate belongs to
the focus -- no more, no less -- and the three modes together must
partition the fixture findings without losing any.
"""
import copy
import json
import sys
import unittest
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / 'skills' / 'agents-doctor' / 'scripts'
sys.path.insert(0, str(SCRIPTS))

import agents_doctor  # noqa: E402  (the CLI under test)
import report_model   # noqa: E402  (report schema constants)

CHAOS_FIXTURE = REPO_ROOT / 'llm-eval' / 'fixtures' / 'chaos.json'

# Canonical focus -> gate mapping from commands/agents-doctor.md; if
# FOCUS_SPECS drifts from it again, these tests fail.
CANONICAL = {
    'security': {'G6', 'G7'},
    'structure': {'G1', 'G4', 'G9'},
    'agents': {'G2', 'G3', 'G5', 'G8'},
}


def load_chaos():
    """A fresh copy of the chaos fixture: apply_focus mutates in place."""
    return json.loads(CHAOS_FIXTURE.read_text(encoding='utf-8'))


class CanonicalMapping(unittest.TestCase):
    def test_focus_specs_match_the_documented_mapping(self):
        self.assertEqual(set(agents_doctor.FOCUS_SPECS), set(CANONICAL))
        for mode, gids in CANONICAL.items():
            self.assertEqual(set(agents_doctor.FOCUS_SPECS[mode]['gates']),
                             gids, mode)
        # no category lists left to drift from the gate mapping
        for spec in agents_doctor.FOCUS_SPECS.values():
            self.assertEqual(set(spec), {'gates'}, spec)

    def test_focus_modes_partition_all_nine_gates(self):
        union = set().union(*CANONICAL.values())
        self.assertEqual(union, {'G%d' % i for i in range(1, 10)})
        # pairwise disjoint: no gate claimed by two modes
        seen = set()
        for gids in CANONICAL.values():
            self.assertFalse(seen & gids, seen & gids)
            seen |= gids


class FocusOnChaosFixture(unittest.TestCase):
    def test_each_mode_keeps_exactly_its_gates_and_findings(self):
        for mode, gids in CANONICAL.items():
            with self.subTest(mode=mode):
                rep = load_chaos()
                expected = [f for f in rep['findings_detailed']
                            if f.get('gate') in gids]
                agents_doctor.apply_focus(rep, mode)
                # gates: exactly the focus set, nothing else
                self.assertEqual({g['gid'] for g in rep['gates']}, gids)
                # every remaining finding belongs to the focus gates
                for f in rep['findings_detailed']:
                    self.assertIn(f['gate'], gids, f['fid'])
                # no more, no less: same fid set as recomputed upfront
                self.assertEqual(len(rep['findings_detailed']),
                                 len(expected))
                self.assertEqual({f['fid'] for f in rep['findings_detailed']},
                                 {f['fid'] for f in expected})
                # nothing from other gates leaked through
                leaked = [f['fid'] for f in rep['findings_detailed']
                          if f['gate'] not in gids]
                self.assertEqual(leaked, [])
                # the report is tagged with the applied focus
                self.assertEqual(rep['focus'], mode)

    def test_modes_partition_the_fixture_without_losing_findings(self):
        rep = load_chaos()
        total = len(rep['findings_detailed'])
        kept = 0
        for mode in CANONICAL:
            agents_doctor.apply_focus(rep, mode)
            kept += len(rep['findings_detailed'])
            rep = load_chaos()  # reset for the next mode
        self.assertEqual(kept, total)

    def test_filtered_report_keeps_schema_and_raw_sections(self):
        raw = load_chaos()
        untouched = {k: copy.deepcopy(v) for k, v in raw.items()
                     if k not in ('gates', 'findings_detailed')}
        for mode in CANONICAL:
            with self.subTest(mode=mode):
                rep = load_chaos()
                agents_doctor.apply_focus(rep, mode)
                # every non-filtered section survives unchanged
                for key, value in untouched.items():
                    self.assertEqual(rep.get(key), value, key)
                # gates and findings keep the report_model schema shape
                for g in rep['gates']:
                    self.assertIn('gid', g)
                    self.assertIn(g['status'], report_model.STATUSES)
                for f in rep['findings_detailed']:
                    for key in report_model.FINDING_KEYS:
                        self.assertIn(key, f, '%s: %s' % (f['fid'], key))
                    self.assertIn(f['gate'], CANONICAL[mode])
                self.assertTrue(json.dumps(rep))  # still valid JSON


class EmptyAndDegenerateReports(unittest.TestCase):
    def test_empty_report_returns_empty_for_every_mode(self):
        for mode in CANONICAL:
            with self.subTest(mode=mode):
                rep = {'gates': [], 'findings_detailed': []}
                agents_doctor.apply_focus(rep, mode)
                self.assertEqual(rep['gates'], [])
                self.assertEqual(rep['findings_detailed'], [])
                self.assertEqual(rep['focus'], mode)

    def test_report_without_gates_or_findings_keys_survives(self):
        rep = {'root': '/tmp/x', 'stats': {}}
        for mode in CANONICAL:
            with self.subTest(mode=mode):
                out = agents_doctor.apply_focus(copy.deepcopy(rep), mode)
                self.assertEqual(out['gates'], [])
                self.assertEqual(out['findings_detailed'], [])

    def test_finding_without_gate_is_dropped_by_every_mode(self):
        rep = {'gates': [],
               'findings_detailed': [{'fid': 'XX-001'},  # no 'gate' key
                                     {'fid': 'XX-002', 'gate': None}]}
        for mode in CANONICAL:
            with self.subTest(mode=mode):
                agents_doctor.apply_focus(rep, mode)
                self.assertEqual(rep['findings_detailed'], [])


class UnknownFocusMode(unittest.TestCase):
    def test_apply_focus_rejects_unknown_mode(self):
        with self.assertRaises(KeyError):
            agents_doctor.apply_focus({'gates': [], 'findings_detailed': []},
                                      'performance')

    def test_cli_parser_rejects_unknown_focus_choice(self):
        # --focus choices are validated by argparse: exit code 2, and
        # the bad value is named in the usage error
        with self.assertRaises(SystemExit) as cx:
            with redirect_stderr(StringIO()) as err:
                agents_doctor.build_parser().parse_args(
                    ['audit', 'somewhere', '--focus', 'performance'])
        self.assertEqual(cx.exception.code, 2)
        self.assertIn('invalid choice', err.getvalue())
        self.assertIn('performance', err.getvalue())


if __name__ == '__main__':
    unittest.main()
