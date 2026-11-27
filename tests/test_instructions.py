"""Tests for the instructions package: discovery, conflicts,
simulation. Runs against the real zcode adapter plus a throwaway fake
adapter registered for cross-harness cases."""
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / 'skills' / 'agents-doctor' / 'scripts'
sys.path.insert(0, str(SCRIPTS))

import harness  # noqa: E402
from harness import HarnessContext  # noqa: E402
from instructions.conflicts import find_conflicts, summarize  # noqa: E402
from instructions.discovery import (discover_all, load_source_text,  # noqa: E402
                                    sources_by_scope)
from instructions.simulation import (format_simulation_text,  # noqa: E402
                                     simulate_loading)


def _mk_ws():
    root = Path(tempfile.mkdtemp())
    home = Path(tempfile.mkdtemp())
    return root, home


class DiscoveryTest(unittest.TestCase):
    def test_collects_with_harness_attribution(self):
        root, home = _mk_ws()
        (root / 'AGENTS.md').write_text('rules\n', encoding='utf-8')
        ctx = HarnessContext(root=root, home=home)
        srcs = discover_all(ctx)
        self.assertTrue(all('harness' in s for s in srcs))
        proj = [s for s in discover_all(ctx, harness_ids=['zcode'])
                if s['scope'] == 'project']
        self.assertEqual(len(proj), 1)
        self.assertTrue(proj[0]['exists'])

    def test_missing_file_flagged_not_dropped(self):
        root, home = _mk_ws()
        hz = home / '.zcode'
        hz.mkdir()
        # no AGENTS.md anywhere: no sources
        ctx = HarnessContext(root=root, home=home)
        self.assertEqual(discover_all(ctx), [])

    def test_harness_filter(self):
        root, home = _mk_ws()
        (root / 'AGENTS.md').write_text('x\n', encoding='utf-8')
        ctx = HarnessContext(root=root, home=home)
        srcs = discover_all(ctx, harness_ids=['cursor'])
        self.assertEqual(srcs, [])   # cursor declares nothing in this ws

    def test_scope_counts(self):
        root, home = _mk_ws()
        (root / 'AGENTS.md').write_text('x\n', encoding='utf-8')
        hz = home / '.zcode'
        hz.mkdir()
        (hz / 'AGENTS.md').write_text('y\n', encoding='utf-8')
        ctx = HarnessContext(root=root, home=home)
        counts = sources_by_scope(discover_all(ctx, harness_ids=['zcode']))
        self.assertEqual(counts, {'user': 1, 'project': 1})

    def test_load_source_text_caps_and_errors(self):
        root, _ = _mk_ws()
        big = root / 'big.md'
        big.write_text('x' * 100, encoding='utf-8')
        self.assertEqual(load_source_text(big, cap=10), '')
        self.assertEqual(load_source_text(root / 'nope.md'), '')
        self.assertEqual(load_source_text(big, cap=1000), 'x' * 100)


class ConflictsTest(unittest.TestCase):
    def _src(self, path, hid='h1', exists=True):
        return {'harness': hid, 'path': str(path), 'exists': exists}

    def test_contradiction_across_files(self):
        d = Path(tempfile.mkdtemp())
        (d / 'a.md').write_text('Always run the full test suite\n',
                                encoding='utf-8')
        (d / 'b.md').write_text('Never run the full test suite\n',
                                encoding='utf-8')
        found = find_conflicts([self._src(d / 'a.md'),
                                self._src(d / 'b.md')])
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]['kind'], 'contradiction')
        self.assertTrue(found[0]['line_a'] > 0)

    def test_same_harness_stays_contradiction(self):
        d = Path(tempfile.mkdtemp())
        (d / 'a.md').write_text('Always push to main\n', encoding='utf-8')
        (d / 'b.md').write_text('Never push to main\n', encoding='utf-8')
        found = find_conflicts([self._src(d / 'a.md', 'zcode'),
                                self._src(d / 'b.md', 'zcode')])
        self.assertEqual([f['kind'] for f in found], ['contradiction'])

    def test_cross_harness_relabelled_divergence(self):
        d = Path(tempfile.mkdtemp())
        (d / 'a.md').write_text('Always commit with signed keys\n',
                                encoding='utf-8')
        (d / 'b.md').write_text('Never commit with signed keys\n',
                                encoding='utf-8')
        found = find_conflicts([self._src(d / 'a.md', 'zcode'),
                                self._src(d / 'b.md', 'codex')])
        self.assertEqual([f['kind'] for f in found], ['divergence'])

    def test_duplication_detected(self):
        d = Path(tempfile.mkdtemp())
        block = 'Use the pytest framework\nCheck the coverage gate\nFix flaky tests immediately\n'
        (d / 'a.md').write_text('# a\n' + block, encoding='utf-8')
        (d / 'b.md').write_text(block, encoding='utf-8')
        found = find_conflicts([self._src(d / 'a.md'),
                                self._src(d / 'b.md')])
        dups = [f for f in found if f['kind'] == 'duplication']
        self.assertEqual(len(dups), 1)
        self.assertEqual(dups[0]['lines'], 3)

    def test_no_conflict_on_unrelated_or_single(self):
        d = Path(tempfile.mkdtemp())
        (d / 'a.md').write_text('Always run the test suite\n', encoding='utf-8')
        self.assertEqual(find_conflicts([self._src(d / 'a.md')]), [])
        (d / 'b.md').write_text('Prefer dark theme\n', encoding='utf-8')
        self.assertEqual(find_conflicts([self._src(d / 'a.md'),
                                         self._src(d / 'b.md')]), [])
        # nonexistent files excluded
        self.assertEqual(find_conflicts(
            [self._src(d / 'a.md'), self._src(d / 'zz.md')]), [])

    def test_summarize(self):
        self.assertEqual(
            summarize([{'kind': 'contradiction'}, {'kind': 'duplication'},
                       {'kind': 'divergence'}, {'kind': 'divergence'}]),
            {'contradiction': 1, 'duplication': 1, 'divergence': 2})


class SimulationTest(unittest.TestCase):
    def test_zcode_chain_and_header(self):
        root, home = _mk_ws()
        (root / 'AGENTS.md').write_text('Always run tests\n', encoding='utf-8')
        ctx = HarnessContext(root=root, home=home)
        rep = simulate_loading(ctx, harness_ids=['zcode'])
        self.assertTrue(rep['approximated'])
        zc = rep['harnesses']['zcode']
        self.assertTrue(zc['supported'])
        self.assertEqual(len(zc['loaded']), 1)
        self.assertEqual(zc['loaded'][0]['scope'], 'project')

    def test_unsupported_adapter_reported(self):
        # an adapter without resolve_chain is reported, not silently
        # skipped
        import harness as h
        from harness.base import HarnessAdapter

        class Bare(HarnessAdapter):
            harness_id = 'bare_test'
            display_name = 'Bare'

        h._REGISTRY['bare_test'] = Bare
        try:
            root, home = _mk_ws()
            ctx = HarnessContext(root=root, home=home)
            rep = simulate_loading(ctx, harness_ids=['bare_test'])
            c = rep['harnesses']['bare_test']
            self.assertFalse(c['supported'])
            self.assertIn('reason', c)
        finally:
            h._REGISTRY.pop('bare_test', None)

    def test_conflict_visible_in_simulation(self):
        root, home = _mk_ws()
        (root / 'AGENTS.md').write_text(
            'Always run tests before commit\n', encoding='utf-8')
        hz = home / '.zcode'
        hz.mkdir()
        (hz / 'AGENTS.md').write_text(
            'Never run tests before commit\n', encoding='utf-8')
        ctx = HarnessContext(root=root, home=home)
        rep = simulate_loading(ctx, harness_ids=['zcode'])
        self.assertEqual(rep['conflict_summary']['contradiction'], 1)

    def test_text_rendering(self):
        root, home = _mk_ws()
        (root / 'AGENTS.md').write_text('Always run tests\n', encoding='utf-8')
        ctx = HarnessContext(root=root, home=home)
        text = format_simulation_text(simulate_loading(ctx,
                                                       harness_ids=['zcode']))
        self.assertIn('Instruction Loading Simulation', text)
        self.assertIn('Mode: model', text)
        self.assertIn('zcode:', text)
        self.assertIn('Loaded:', text)


class FakeAdapterCrossHarnessTest(unittest.TestCase):
    """A throwaway adapter proves multi-harness simulation and the
    divergence path without waiting for real adapters."""

    def setUp(self):
        root, home = _mk_ws()
        self.root, self.home = root, home
        (root / 'CLAUDE.md').write_text('Always deploy on Friday\n',
                                        encoding='utf-8')
        (root / 'AGENTS.md').write_text('Never deploy on Friday\n',
                                        encoding='utf-8')
        from harness.base import (HarnessAdapter, InstructionChain,
                                  InstructionLink, InstructionSource)
        import harness as h

        class FakeClaude(HarnessAdapter):
            harness_id = 'fake_claude'
            display_name = 'Fake Claude'

            def instruction_sources(self, ctx):
                p = ctx.root_path('CLAUDE.md')
                return ([InstructionSource(p, 'project', 'claude file')]
                        if ctx.exists(p) else [])

            def resolve_chain(self, ctx, target_dir=None):
                ch = InstructionChain(harness_id=self.harness_id,
                                      target_dir=target_dir or ctx.root)
                for s in self.instruction_sources(ctx):
                    ch.links.append(InstructionLink(s, precedence=20))
                return ch

        self.fake = FakeClaude
        h._REGISTRY['fake_claude'] = FakeClaude

    def tearDown(self):
        import harness as h
        h._REGISTRY.pop('fake_claude', None)

    def test_divergence_between_zcode_and_fake(self):
        ctx = HarnessContext(root=self.root, home=self.home)
        rep = simulate_loading(ctx, harness_ids=['zcode', 'fake_claude'])
        self.assertEqual(rep['conflict_summary']['divergence'], 1)
        div = rep['conflicts'][0]
        self.assertEqual({div['harness_a'], div['harness_b']},
                         {'zcode', 'fake_claude'})


if __name__ == '__main__':
    unittest.main()
