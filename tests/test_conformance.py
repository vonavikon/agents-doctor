"""Conformance framework tests: harness/conformance runner + capability
matrix, and the zcode fixture as the reference example. Everything runs
on temp directories via pathlib; stdlib only."""
import inspect
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCRIPTS = REPO / 'skills' / 'agents-doctor' / 'scripts'
sys.path.insert(0, str(SCRIPTS))

from harness import adapter_ids, get_adapter  # noqa: E402
from harness.base import CAPABILITY_KEYS, CAPABILITY_STATUSES  # noqa: E402
from harness.conformance import matrix as cmatrix  # noqa: E402
from harness.conformance import runner  # noqa: E402
from harness.conformance.runner import (discover_fixtures, load_fixture,  # noqa: E402
                                         run_all, run_conformance)

FIXTURES = REPO / 'tests' / 'conformance'


class ConformanceTestCase(unittest.TestCase):
    def setUp(self):
        self._tmps = []

    def tmpdir(self):
        t = tempfile.TemporaryDirectory()
        self._tmps.append(t)
        return Path(t.name)

    def tearDown(self):
        for t in self._tmps:
            t.cleanup()


# ---- fixture discovery and contract -------------------------------
class TestFixtureDiscovery(ConformanceTestCase):
    def test_fixture_files_found(self):
        found = discover_fixtures(FIXTURES)
        self.assertIn('zcode', found)
        self.assertEqual(found['zcode'].name, 'fixture.py')

    def test_discovery_empty_root(self):
        self.assertEqual(discover_fixtures(self.tmpdir()), {})

    def test_zcode_fixture_contract(self):
        module = load_fixture('zcode', FIXTURES)
        self.assertTrue(callable(module.build))
        self.assertTrue(callable(module.expected))
        # build must accept the (root, home) form
        params = list(inspect.signature(module.build).parameters)
        self.assertGreaterEqual(len(params), 2)

    def test_load_fixture_rejects_incomplete_module(self):
        root = self.tmpdir()
        bogus = root / 'bogus'
        bogus.mkdir()
        (bogus / 'fixture.py').write_text('build = 1\n',
                                          encoding='utf-8')
        with self.assertRaises(ValueError):
            load_fixture('bogus', root)


# ---- runner: real fixtures ----------------------------------------
class TestRunConformance(ConformanceTestCase):
    def test_all_fixtures_green(self):
        """Every discovered fixture: all non-skipped checks ok."""
        found = discover_fixtures(FIXTURES)
        if not found:
            self.skipTest('no conformance fixtures')
        for harness_id in found:
            with self.subTest(harness=harness_id):
                report = run_conformance(harness_id)
                for check in report['checks']:
                    if not check['skipped']:
                        self.assertTrue(
                            check['ok'],
                            '%s/%s: expected %r, actual %r'
                            % (harness_id, check['name'],
                               check['expected'], check['actual']))

    def test_zcode_report_shape(self):
        report = run_conformance('zcode')
        self.assertEqual(report['harness'], 'zcode')
        self.assertEqual([c['name'] for c in report['checks']],
                         list(runner.CHECK_NAMES))
        for check in report['checks']:
            self.assertEqual(
                set(check), {'name', 'expected', 'actual', 'ok',
                             'skipped'})
        s = report['summary']
        self.assertEqual(s['total'], len(report['checks']))
        self.assertEqual(s['ok'] + s['failed'] + s['skipped'],
                         s['total'])

    def test_zcode_fixture_pins_full_coverage(self):
        """The reference fixture declares every check: nothing is
        skipped, nothing fails."""
        report = run_conformance('zcode')
        self.assertEqual(report['summary']['skipped'], 0)
        self.assertEqual(report['summary']['failed'], 0)
        self.assertEqual(report['summary']['ok'],
                         len(runner.CHECK_NAMES))

    def test_zcode_nested_limitation_pinned(self):
        """src/AGENTS.md must NOT appear as loaded for the nested
        target — the documented limitation, pinned by the fixture."""
        report = run_conformance('zcode')
        nested = next(c for c in report['checks']
                      if c['name'] == 'resolve_nested')
        self.assertTrue(nested['ok'])
        self.assertNotIn('src/AGENTS.md', nested['actual']['loaded'])

    def test_run_all_shape(self):
        reports = run_all()
        self.assertIn('zcode', reports)
        self.assertEqual(reports['zcode']['summary']['failed'], 0)

    def test_home_parameter_is_populated_and_kept(self):
        """home= is a scratch dir the fixture fills; the runner must
        not delete it afterwards."""
        home = self.tmpdir()
        run_conformance('zcode', home=home)
        self.assertTrue((home / '.zcode' / 'AGENTS.md').is_file())

    def test_missing_fixture_raises(self):
        with self.assertRaises(ValueError):
            run_conformance('no_such_harness')


# ---- runner: skips and partial fixtures ---------------------------
class TestPartialFixtures(ConformanceTestCase):
    def _write_fixture(self, root, body):
        d = root / 'zcode'
        d.mkdir(parents=True)
        (d / 'fixture.py').write_text(body, encoding='utf-8')

    def test_checks_without_expectation_are_skipped(self):
        root = self.tmpdir()
        self._write_fixture(root, (
            'def build(root):\n'
            '    pass\n'
            'def expected():\n'
            '    return {"instruction_sources_count": 0}\n'))
        report = run_conformance('zcode', fixtures_root=root)
        by_name = {c['name']: c for c in report['checks']}
        self.assertTrue(by_name['instruction_sources_count']['ok'])
        self.assertFalse(by_name['instruction_sources_count']['skipped'])
        for name in ('detect_project', 'detect_user',
                     'resolve_root_loaded', 'resolve_nested',
                     'validate_findings'):
            self.assertTrue(by_name[name]['skipped'],
                            '%s should be skipped' % name)
            self.assertIsNone(by_name[name]['ok'])
        self.assertEqual(report['summary']['skipped'], 5)
        self.assertEqual(report['summary']['ok'], 1)
        self.assertEqual(report['summary']['failed'], 0)

    def test_root_only_build_signature_supported(self):
        root = self.tmpdir()
        self._write_fixture(root, (
            'def build(root):\n'
            '    (root / "AGENTS.md").write_text("x")\n'
            'def expected():\n'
            '    return {"detect_project": True}\n'))
        report = run_conformance('zcode', fixtures_root=root)
        check = next(c for c in report['checks']
                     if c['name'] == 'detect_project')
        self.assertTrue(check['ok'])

    def test_failed_check_reported_not_hidden(self):
        root = self.tmpdir()
        self._write_fixture(root, (
            'def build(root):\n'
            '    (root / "AGENTS.md").write_text("x")\n'
            'def expected():\n'
            '    return {"instruction_sources_count": 99}\n'))
        report = run_conformance('zcode', fixtures_root=root)
        self.assertEqual(report['summary']['failed'], 1)
        check = next(c for c in report['checks']
                     if c['name'] == 'instruction_sources_count')
        self.assertFalse(check['ok'])
        self.assertEqual(check['actual'], 1)


# ---- display-path helper ------------------------------------------
class TestDisplayPath(ConformanceTestCase):
    def test_relative_and_home_forms(self):
        from harness.conformance.runner import _display
        root = self.tmpdir()
        home = self.tmpdir()
        (root / 'AGENTS.md').write_text('x', encoding='utf-8')
        (home / '.zcode' / 'AGENTS.md').parent.mkdir(parents=True)
        (home / '.zcode' / 'AGENTS.md').write_text('x',
                                                   encoding='utf-8')
        self.assertEqual(_display(root / 'AGENTS.md', root, home),
                         'AGENTS.md')
        self.assertEqual(_display(home / '.zcode' / 'AGENTS.md',
                                  root, home),
                         '~/.zcode/AGENTS.md')

    def test_outside_paths_untouched(self):
        from harness.conformance.runner import _display
        root = self.tmpdir()
        home = self.tmpdir()
        elsewhere = self.tmpdir() / 'elsewhere.txt'
        self.assertEqual(_display(elsewhere, root, home),
                         str(elsewhere))


# ---- capability matrix --------------------------------------------
class TestMatrix(ConformanceTestCase):
    def test_build_covers_registry(self):
        rows = cmatrix.build_matrix()
        self.assertEqual([r['harness'] for r in rows], adapter_ids())

    def test_build_rows_valid(self):
        rows = cmatrix.build_matrix()
        self.assertTrue(cmatrix.validate(rows))
        for row in rows:
            self.assertEqual(set(row['capabilities']),
                             set(CAPABILITY_KEYS))
            self.assertEqual(len(row['capabilities']),
                             len(CAPABILITY_KEYS))

    def test_save_load_roundtrip(self):
        out = self.tmpdir() / 'capability-matrix.json'
        cmatrix.save(out)
        self.assertEqual(cmatrix.load(out), cmatrix.build_matrix())

    def test_validate_rejects_bad_status(self):
        rows = cmatrix.build_matrix()
        rows[0]['capabilities']['detection'] = 'probably'
        with self.assertRaises(ValueError):
            cmatrix.validate(rows)

    def test_validate_rejects_missing_capability(self):
        rows = cmatrix.build_matrix()
        del rows[0]['capabilities']['detection']
        with self.assertRaises(ValueError):
            cmatrix.validate(rows)

    def test_validate_rejects_extra_capability(self):
        rows = cmatrix.build_matrix()
        rows[0]['capabilities']['telepathy'] = 'documented'
        with self.assertRaises(ValueError):
            cmatrix.validate(rows)

    def test_validate_rejects_unknown_harness(self):
        rows = cmatrix.build_matrix()
        rows.append({'harness': 'no_such_harness', 'version': '1.0.0',
                     'capabilities': dict.fromkeys(CAPABILITY_KEYS,
                                                   'unknown'),
                     'tested_at': '', 'spec_source': ''})
        with self.assertRaises(ValueError):
            cmatrix.validate(rows)


class TestMatrixCLI(ConformanceTestCase):
    def test_check_fresh_exit_0(self):
        out = self.tmpdir() / 'matrix.json'
        cmatrix.save(out)
        self.assertEqual(cmatrix.main(['--check', '--out', str(out)]),
                         0)

    def test_check_stale_exit_1(self):
        out = self.tmpdir() / 'matrix.json'
        rows = cmatrix.build_matrix()
        rows[0]['capabilities']['detection'] = 'runtime-tested'
        out.write_text(json.dumps(rows), encoding='utf-8')
        self.assertEqual(cmatrix.main(['--check', '--out', str(out)]),
                         1)

    def test_check_bad_shape_exit_1(self):
        out = self.tmpdir() / 'matrix.json'
        out.write_text('{"not": "a list"}', encoding='utf-8')
        self.assertEqual(cmatrix.main(['--check', '--out', str(out)]),
                         1)

    def test_check_corrupt_json_exit_1(self):
        out = self.tmpdir() / 'matrix.json'
        out.write_text('not json at all{', encoding='utf-8')
        self.assertEqual(cmatrix.main(['--check', '--out', str(out)]),
                         1)

    def test_check_missing_file_exit_1(self):
        out = self.tmpdir() / 'absent.json'
        self.assertEqual(cmatrix.main(['--check', '--out', str(out)]),
                         1)

    def test_python_dash_m_check_on_docs(self):
        """The documented CI invocation works end to end."""
        result = subprocess.run(
            [sys.executable, '-m', 'harness.conformance.matrix',
             '--check'],
            cwd=str(SCRIPTS), capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)


# ---- zcode etalon statuses ----------------------------------------
class TestZcodeEtalon(ConformanceTestCase):
    def test_status_dict_complete_and_honest(self):
        adapter = get_adapter('zcode')
        self.assertEqual(set(adapter.CAPABILITY_STATUS),
                         set(CAPABILITY_KEYS))
        for key, status in adapter.CAPABILITY_STATUS.items():
            self.assertIn(status, CAPABILITY_STATUSES)
        # spot-check the honest calls the fixture and docs rely on
        self.assertEqual(
            adapter.CAPABILITY_STATUS['nested_instructions'],
            'unsupported')
        self.assertEqual(
            adapter.CAPABILITY_STATUS['instruction_hierarchy'],
            'approximated')
        self.assertEqual(
            adapter.CAPABILITY_STATUS['detection'], 'documented')


if __name__ == '__main__':
    unittest.main()
