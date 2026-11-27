"""audit --fail-on: the CI gate flag.

The flag turns a finished audit into a CI gate: after the report is on
disk, exit 1 when at least one finding has status fail and severity at
or above the requested level. Default 'none' keeps the historical
contract -- exit 0 whatever the findings -- which is the back-compat
guarantee the first two tests pin down.

Fixtures are real scans of tiny temp workspaces (isolated --home, so
the machine's real instruction files cannot leak findings in):

- critical: an assembled sk- token in .env -> SEC finding,
  severity critical, status fail (gates.py G6 exposed-secrets);
- medium: a dead backtick path in AGENTS.md -> RUL finding,
  severity medium, status fail (gates.py G3 dead-references), and no
  higher fail;
- clean: no fail findings at all (info/warn only).

The secret is written from concatenated pieces so no scanner-like
string sits whole inside this file.
"""
import contextlib
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / 'skills' / 'agents-doctor' / 'scripts'
sys.path.insert(0, str(SCRIPTS))

import agents_doctor  # noqa: E402


class FailOnFixtureMixin:
    """three workspaces + an isolated home, rebuilt per test."""

    def setUp(self):
        self.base = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.base, ignore_errors=True)
        self.home = self.base / 'home'
        self.home.mkdir()

    def _audit(self, ws, *extra):
        out = self.base / ('scan-%s.json' % Path(ws).name)
        argv = ['audit', str(ws), '--home', str(self.home),
                '--out', str(out)] + list(extra)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = agents_doctor.main(argv)
        return rc, out, buf.getvalue()

    def ws_critical(self):
        ws = self.base / 'ws-critical'
        ws.mkdir(exist_ok=True)
        # sk- + 16 chars matches the SEC-001 api-key rule; assembled so
        # the literal never appears in this source file
        token = 'sk-' + 'zv9wq8x7y6u5t4s3'
        (ws / '.env').write_text('API_KEY=%s\n' % token, encoding='utf-8')
        return ws

    def ws_medium(self):
        ws = self.base / 'ws-medium'
        ws.mkdir(exist_ok=True)
        # dead backtick path -> RUL medium/fail, nothing harsher
        (ws / 'AGENTS.md').write_text(
            '# Demo workspace\n\nSee `docs/missing/old.md` for the old procedure.\n',
            encoding='utf-8')
        return ws

    def ws_clean(self):
        ws = self.base / 'ws-clean'
        ws.mkdir(exist_ok=True)
        (ws / 'README.md').write_text('# demo\n', encoding='utf-8')
        return ws


class FailOnBackCompatTest(FailOnFixtureMixin, unittest.TestCase):
    def test_default_without_flag_exits_zero_on_critical(self):
        rc, _out, _ = self._audit(self.ws_critical())
        self.assertEqual(rc, 0)

    def test_fail_on_none_exits_zero_on_critical(self):
        rc, _out, _ = self._audit(self.ws_critical(), '--fail-on', 'none')
        self.assertEqual(rc, 0)


class FailOnThresholdTest(FailOnFixtureMixin, unittest.TestCase):
    def test_fail_on_critical_fires_on_critical_finding(self):
        rc, _out, _ = self._audit(self.ws_critical(), '--fail-on', 'critical')
        self.assertEqual(rc, 1)

    def test_fail_on_high_with_only_medium_stays_zero(self):
        rc, _out, _ = self._audit(self.ws_medium(), '--fail-on', 'high')
        self.assertEqual(rc, 0)

    def test_fail_on_critical_with_only_medium_stays_zero(self):
        rc, _out, _ = self._audit(self.ws_medium(), '--fail-on', 'critical')
        self.assertEqual(rc, 0)

    def test_fail_on_medium_fires_on_medium_finding(self):
        rc, _out, _ = self._audit(self.ws_medium(), '--fail-on', 'medium')
        self.assertEqual(rc, 1)

    def test_fail_on_low_catches_higher_severity(self):
        # a lower threshold must catch everything above it
        rc, _out, _ = self._audit(self.ws_medium(), '--fail-on', 'low')
        self.assertEqual(rc, 1)

    def test_fail_on_info_catches_critical(self):
        rc, _out, _ = self._audit(self.ws_critical(), '--fail-on', 'info')
        self.assertEqual(rc, 1)

    def test_fail_on_info_requires_fail_status(self):
        # warn/info findings never trip even the lowest threshold
        rc, _out, _ = self._audit(self.ws_clean(), '--fail-on', 'info')
        self.assertEqual(rc, 0)


class FailOnReportAndMessageTest(FailOnFixtureMixin, unittest.TestCase):
    def test_report_written_before_fail_on_exit(self):
        rc, out, _ = self._audit(self.ws_critical(), '--fail-on', 'critical')
        self.assertEqual(rc, 1)
        self.assertTrue(out.is_file())
        rep = json.loads(out.read_text(encoding='utf-8'))
        sevs = {(f.get('severity'), f.get('status'))
                for f in rep.get('findings_detailed', [])}
        self.assertIn(('critical', 'fail'), sevs)

    def test_message_names_threshold_and_count(self):
        _rc, _out, text = self._audit(self.ws_critical(),
                                      '--fail-on', 'critical')
        self.assertIn(
            'fail-on: 1 finding(s) at or above CRITICAL with status fail',
            text)

    def test_fail_on_respects_focus_filter(self):
        # focus security keeps the G6 secret finding -> gate fires;
        # focus structure drops it -> nothing left to fire on
        rc_sec, _o1, _ = self._audit(self.ws_critical(), '--focus', 'security',
                                     '--fail-on', 'critical')
        self.assertEqual(rc_sec, 1)
        rc_str, _o2, _ = self._audit(self.ws_critical(), '--focus',
                                     'structure', '--fail-on', 'critical')
        self.assertEqual(rc_str, 0)


class FailOnParserTest(unittest.TestCase):
    def test_invalid_fail_on_is_usage_error(self):
        base = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, base, ignore_errors=True)
        ws = base / 'ws'
        ws.mkdir()
        with self.assertRaises(SystemExit) as ctx:
            agents_doctor.main(['audit', str(ws), '--fail-on', 'bogus'])
        self.assertEqual(ctx.exception.code, 2)

    def test_severity_order_constants(self):
        rank = agents_doctor.SEVERITY_RANK
        self.assertLess(rank['info'], rank['low'])
        self.assertLess(rank['low'], rank['medium'])
        self.assertLess(rank['medium'], rank['high'])
        self.assertLess(rank['high'], rank['critical'])
        self.assertEqual(agents_doctor.FAIL_ON_CHOICES[0], 'none')
        self.assertIn('critical', agents_doctor.FAIL_ON_CHOICES)
        self.assertIn('info', agents_doctor.FAIL_ON_CHOICES)


if __name__ == '__main__':
    unittest.main()
