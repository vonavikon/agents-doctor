"""Tests for the Governance Dashboard API:
Workspace Health Score (/api/score) and the audit-history endpoints
(/api/history, /api/trend, /api/diff) over the root-local
agents-doctor history database.

Score rules under test (server.compute_health_score):
- per component: 100 baseline, -30 per failing gate WITH critical
  findings, -15 per failing gate without, -5 per warn, clipped 0..100;
- unknown/missing gate status -> component null -> overall null with an
  'insufficient data' note (absence of data is never a zero);
- overall = weighted sum; any critical+fail finding caps it at 40.
"""
import http.client
import json
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

SCRIPTS = Path(__file__).resolve().parents[1] / 'skills' / \
    'agents-doctor' / 'scripts'
sys.path.insert(0, str(SCRIPTS))

import audit_history  # noqa: E402
from ui.server import ApiUsageError, UiState, compute_health_score  # noqa: E402
from ui import server as srv  # noqa: E402


def _gates(statuses):
    """Gate list for a synthetic report: {'G1': 'pass', ...}."""
    return [{'gid': gid, 'status': st, 'name': gid, 'confidence': 0.9}
            for gid, st in statuses.items()]


def _all(status):
    return _gates({'G%d' % i: status for i in range(1, 10)})


def _report(statuses, findings_detailed=None):
    return {'root': '.', 'generated_at': '2026-01-01T00:00:00',
            'gates': _gates(statuses),
            'findings_detailed': findings_detailed or []}


def _crit_finding(gid):
    return {'fid': 'X-1', 'gate': gid, 'severity': 'critical',
            'status': 'fail', 'title': 'crit'}


# ---------------------------------------------------------- score computing

class ScoreComputationTest(unittest.TestCase):
    def test_clean_workspace_scores_100(self):
        out = compute_health_score(_report(
            {'G%d' % i: 'pass' for i in range(1, 10)}), True)
        self.assertEqual(out['score'], 100)
        self.assertFalse(out['critical_cap'])
        for c in out['components'].values():
            self.assertEqual(c['score'], 100)

    def test_not_applicable_gates_score_100(self):
        out = compute_health_score(_report(
            {'G%d' % i: 'not_applicable' for i in range(1, 10)}), True)
        self.assertEqual(out['score'], 100)

    def test_all_warn_lowers_score_exact(self):
        # every gate warn: 5 off per gate -> security/instructions/
        # compat/hygiene 90, config 95, observability 0 (no history)
        out = compute_health_score(_report(
            {'G%d' % i: 'warn' for i in range(1, 10)}), False)
        self.assertEqual(out['score'], 86.5)
        self.assertEqual(out['components']['security']['score'], 90)
        self.assertEqual(out['components']['config']['score'], 95)
        self.assertEqual(out['components']['observability']['score'], 0)

    def test_fail_without_critical_is_minus_15(self):
        out = compute_health_score(_report(
            {'G%d' % i: 'pass' for i in range(1, 10)} | {'G2': 'fail'}),
            True)
        self.assertEqual(out['components']['config']['score'], 85)
        self.assertEqual(out['score'], 97)   # 100 - 0.20*15
        self.assertFalse(out['critical_cap'])

    def test_fail_with_critical_is_minus_30(self):
        statuses = {'G%d' % i: 'pass' for i in range(1, 10)}
        statuses['G6'] = 'fail'
        out = compute_health_score(
            _report(statuses, [_crit_finding('G6')]), True)
        self.assertEqual(out['components']['security']['score'], 70)

    def test_critical_cap_40_and_flag(self):
        # clean gates but one critical fail finding anywhere: the
        # weighted sum would be 100, the cap forces 40
        out = compute_health_score(
            _report({'G%d' % i: 'pass' for i in range(1, 10)},
                    [_crit_finding('G6')]), True)
        self.assertEqual(out['score'], 40)
        self.assertTrue(out['critical_cap'])

    def test_critical_cap_not_below_deserved(self):
        # a workspace that already scores under 40 stays at its score
        out = compute_health_score(_report(
            {'G%d' % i: 'fail' for i in range(1, 10)},
            [_crit_finding('G6'), _crit_finding('G7')]), True)
        self.assertLessEqual(out['score'], 40)

    def test_warn_critical_finding_does_not_cap(self):
        # severity critical but status warn: not a failing critical
        out = compute_health_score(_report(
            {'G%d' % i: 'pass' for i in range(1, 10)},
            [{'fid': 'X-2', 'gate': 'G6', 'severity': 'critical',
              'status': 'warn'}]), True)
        self.assertEqual(out['score'], 100)
        self.assertFalse(out['critical_cap'])

    def test_missing_gate_gives_null_with_note(self):
        statuses = {'G%d' % i: 'pass' for i in range(1, 9)}  # no G9
        out = compute_health_score(_report(statuses), True)
        self.assertIsNone(out['score'])
        self.assertIsNone(out['components']['hygiene']['score'])
        self.assertIn('insufficient data', out['note'])
        self.assertIn('hygiene', out['note'])
        # the other components still carry their scores
        self.assertEqual(out['components']['security']['score'], 100)

    def test_unknown_status_same_as_missing(self):
        statuses = {'G%d' % i: 'pass' for i in range(1, 10)}
        statuses['G3'] = 'unknown'
        out = compute_health_score(_report(statuses), True)
        self.assertIsNone(out['score'])
        self.assertIn('insufficient data', out['note'])

    def test_formula_string(self):
        out = compute_health_score(_report(
            {'G%d' % i: 'pass' for i in range(1, 10)}), True)
        self.assertEqual(out['formula'], 'weighted sum; critical cap 40')

    def test_weights_sum_to_one(self):
        out = compute_health_score(_report(
            {'G%d' % i: 'pass' for i in range(1, 10)}), True)
        total = sum(c['weight'] for c in out['components'].values())
        self.assertAlmostEqual(total, 1.0)

    def test_expected_weight_values(self):
        out = compute_health_score(_report(
            {'G%d' % i: 'pass' for i in range(1, 10)}), True)
        w = {name: c['weight'] for name, c in out['components'].items()}
        self.assertEqual(w, {'security': 0.30, 'config': 0.20,
                             'instructions': 0.20, 'harness_compat': 0.15,
                             'hygiene': 0.10, 'observability': 0.05})

    def test_gate_groups(self):
        out = compute_health_score(_report(
            {'G%d' % i: 'pass' for i in range(1, 10)}), True)
        g = {name: c['gates'] for name, c in out['components'].items()}
        self.assertEqual(g['security'], ['G6', 'G7'])
        self.assertEqual(g['config'], ['G2'])
        self.assertEqual(g['instructions'], ['G3', 'G5'])
        self.assertEqual(g['harness_compat'], ['G8', 'G1'])
        self.assertEqual(g['hygiene'], ['G4', 'G9'])
        self.assertEqual(g['observability'], [])

    def test_gates_basis_reflects_statuses(self):
        statuses = {'G%d' % i: 'pass' for i in range(1, 10)}
        statuses['G7'] = 'warn'
        out = compute_health_score(_report(statuses), False)
        self.assertEqual(out['gates_basis']['G7'], 'warn')
        self.assertEqual(out['gates_basis']['G1'], 'pass')


# ------------------------------------------------------- score over UiState

class ScoreEndpointTest(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp()).resolve()
        self.state = UiState(_report(
            {'G%d' % i: 'pass' for i in range(1, 10)}), self.root)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.root, ignore_errors=True)

    def test_api_score_shape(self):
        out = srv.api_score(self.state, {})
        for key in ('score', 'components', 'formula', 'critical_cap',
                    'computed_at', 'gates_basis', 'history_available'):
            self.assertIn(key, out)
        self.assertEqual(out['score'], 95)   # observability 0, rest 100

    def test_observability_follows_history_db(self):
        out = srv.api_score(self.state, {})
        self.assertFalse(out['history_available'])
        self.assertEqual(out['components']['observability']['score'], 0)
        conn = audit_history.init_db(
            audit_history.default_db_path(self.root))
        audit_history.record_scan(conn, _report(
            {'G%d' % i: 'pass' for i in range(1, 10)}))
        conn.close()
        out2 = srv.api_score(self.state, {})
        self.assertTrue(out2['history_available'])
        self.assertEqual(out2['components']['observability']['score'], 100)
        self.assertEqual(out2['score'], 100)


# --------------------------------------------------- history endpoints

def _hist_report(root, findings, detailed, gates, ts):
    return {'root': str(root), 'generated_at': ts,
            'findings': findings, 'findings_detailed': detailed,
            'gates': gates}


class HistoryEndpointsTest(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp()).resolve()
        self.state = UiState({'root': str(self.root),
                              'findings_detailed': [], 'gates': []},
                             self.root)
        self.db = audit_history.default_db_path(self.root)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.root, ignore_errors=True)

    def _seed(self):
        """Two recorded scans: one fingerprint changed, one new, one
        resolved; the typed finding regresses (low/warn -> high/fail)."""
        old = _hist_report(
            self.root,
            [{'fp': 'fp-a', 'section': 's1', 'path': 'f.txt'},
             {'fp': 'fp-b', 'section': 's2', 'path': 'g.txt'},
             {'fp': 'fp-d', 'section': 's4', 'path': 'd.txt'}],
            [{'fid': 'SEC-1', 'gate': 'G6', 'severity': 'low',
              'status': 'warn'}],
            [{'gid': 'G6', 'status': 'warn'}],
            '2026-01-01T10:00:00')
        new = _hist_report(
            self.root,
            [{'fp': 'fp-a2', 'section': 's1', 'path': 'f.txt'},
             {'fp': 'fp-b', 'section': 's2', 'path': 'g.txt'},
             {'fp': 'fp-c', 'section': 's3', 'path': 'c.txt'}],
            [{'fid': 'SEC-1', 'gate': 'G6', 'severity': 'high',
              'status': 'fail'}],
            [{'gid': 'G6', 'status': 'fail'}],
            '2026-02-01T10:00:00')
        conn = audit_history.init_db(self.db)
        try:
            old_id = audit_history.record_scan(conn, old)
            new_id = audit_history.record_scan(conn, new)
        finally:
            conn.close()
        return old_id, new_id

    def _qs(self, extra=''):
        return parse_qs(('root=' + str(self.root) + '&' + extra)
                        .rstrip('&'))

    def test_history_without_db_available_false(self):
        out = srv.api_history(self.state, self._qs())
        self.assertIs(out.get('available'), False)
        self.assertEqual(out['scans'], [])
        self.assertEqual(out['regressions'], [])
        # and trend agrees
        trend = srv.api_trend(self.state, self._qs())
        self.assertIs(trend.get('available'), False)
        self.assertEqual(trend['points'], [])

    def test_history_returns_scans_newest_first(self):
        old_id, new_id = self._seed()
        out = srv.api_history(self.state, self._qs())
        self.assertTrue(out['available'])
        ids = [s['id'] for s in out['scans']]
        self.assertEqual(ids, [new_id, old_id])
        for s in out['scans']:
            for key in ('id', 'ts', 'findings_total', 'severity_counts',
                        'gate_statuses'):
                self.assertIn(key, s)
        self.assertEqual(out['scans'][0]['ts'], '2026-02-01T10:00:00')

    def test_history_limit_validation(self):
        self._seed()
        with self.assertRaises(ApiUsageError):
            srv.api_history(self.state, self._qs('limit=abc'))
        with self.assertRaises(ApiUsageError):
            srv.api_history(self.state, self._qs('limit=0'))
        out = srv.api_history(self.state, self._qs('limit=1'))
        self.assertEqual(len(out['scans']), 1)

    def test_history_root_mismatch_refused(self):
        self._seed()
        out = srv.api_history(self.state, parse_qs('root=C:/elsewhere'))
        self.assertIn('error', out)
        trend = srv.api_trend(self.state, parse_qs('root=C:/elsewhere'))
        self.assertIn('error', trend)
        diff = srv.api_diff(self.state, parse_qs(
            'root=C:/elsewhere&old=1&new=2'))
        self.assertIn('error', diff)

    def test_history_root_defaults_to_state_root(self):
        self._seed()
        out = srv.api_history(self.state, parse_qs(''))
        self.assertTrue(out['available'])
        self.assertEqual(len(out['scans']), 2)

    def test_history_regressions_of_newest(self):
        self._seed()
        out = srv.api_history(self.state, self._qs())
        regs = out['regressions']
        self.assertEqual(len(regs), 1)
        self.assertIn('severity low -> high', regs[0]['reasons'])
        self.assertIn('status warn -> fail', regs[0]['reasons'])

    def test_trend_roundtrip(self):
        old_id, new_id = self._seed()
        out = srv.api_trend(self.state, self._qs())
        self.assertTrue(out['available'])
        pts = out['points']
        self.assertEqual([p['ts'] for p in pts],
                         ['2026-01-01T10:00:00', '2026-02-01T10:00:00'])
        # scans.findings_total counts the fingerprint population
        self.assertEqual([p['total'] for p in pts], [3, 3])
        self.assertEqual(pts[0]['high'], 0)
        self.assertEqual(pts[1]['high'], 1)

    def test_trend_filters_by_recorded_root(self):
        conn = audit_history.init_db(self.db)
        try:
            audit_history.record_scan(conn, _hist_report(
                self.root, [], [], [], '2026-01-01T10:00:00'))
            audit_history.record_scan(conn, _hist_report(
                'C:/some/other/root', [], [], [], '2026-01-02T10:00:00'))
        finally:
            conn.close()
        pts = srv.api_trend(self.state, self._qs())['points']
        self.assertEqual(len(pts), 1)
        self.assertEqual(pts[0]['ts'], '2026-01-01T10:00:00')

    def test_diff_roundtrip_sections(self):
        old_id, new_id = self._seed()
        out = srv.api_diff(self.state, self._qs(
            'old=%d&new=%d' % (old_id, new_id)))
        self.assertTrue(out['supported'])
        self.assertEqual(out['old_id'], old_id)
        self.assertEqual(out['new_id'], new_id)
        self.assertEqual(out['summary']['new'], 2)        # fp-a2, fp-c
        self.assertEqual(out['summary']['resolved'], 2)   # fp-a, fp-d
        self.assertEqual(out['summary']['persisting'], 1)  # fp-b
        self.assertEqual(out['summary']['changed'], 1)    # f.txt reshaped
        # fingerprints are internal: they never reach the wire
        for name in ('new', 'resolved', 'persisting', 'changed'):
            for f in out['diff'][name]:
                self.assertNotIn('fp', f)

    def test_diff_unknown_scan_id(self):
        old_id, new_id = self._seed()
        out = srv.api_diff(self.state, self._qs(
            'old=%d&new=999' % old_id))
        self.assertIn('error', out)
        self.assertFalse(out['supported'])

    def test_diff_bad_params(self):
        self._seed()
        with self.assertRaises(ApiUsageError):
            srv.api_diff(self.state, self._qs())
        with self.assertRaises(ApiUsageError):
            srv.api_diff(self.state, self._qs('old=1&new=x'))
        with self.assertRaises(ApiUsageError):
            srv.api_diff(self.state, self._qs('old=0&new=1'))

    def test_diff_without_db(self):
        out = srv.api_diff(self.state, self._qs('old=1&new=2'))
        self.assertFalse(out['supported'])
        self.assertIn('error', out)


# ------------------------------------------------- endpoints on the wire

class _LiveServer:
    """UI server on an ephemeral loopback port with a synthetic
    all-pass report (no filesystem scan needed for these routes)."""

    def __init__(self):
        self.root = Path(tempfile.mkdtemp()).resolve()
        state = UiState(_report({'G%d' % i: 'pass' for i in range(1, 10)}),
                        self.root)
        self.httpd = ThreadingHTTPServer(
            ('127.0.0.1', 0), srv.make_handler(state, None))
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever,
                         daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        import shutil
        shutil.rmtree(self.root, ignore_errors=True)


def _request(port, method, path, headers=None):
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=15)
    try:
        conn.request(method, path, headers=headers or {})
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


class DashboardHttpSecurityTest(unittest.TestCase):
    """The new dashboard endpoints live behind the same Host check as
    the rest of /api/* (DNS-rebinding defense)."""

    @classmethod
    def setUpClass(cls):
        cls.live = _LiveServer()
        cls.port = cls.live.port

    @classmethod
    def tearDownClass(cls):
        cls.live.close()

    def test_dashboard_endpoints_answer_with_default_host(self):
        for path in ('/api/score', '/api/history', '/api/trend',
                     '/api/diff?old=1&new=2'):
            status, body = _request(self.port, 'GET', path)
            self.assertEqual(status, 200, path)
            self.assertIsInstance(json.loads(body), dict)

    def test_dashboard_endpoints_reject_spoofed_host(self):
        for path in ('/api/score', '/api/history', '/api/trend',
                     '/api/diff?old=1&new=2'):
            status, body = _request(self.port, 'GET', path,
                                    {'Host': 'evil.com'})
            self.assertEqual(status, 403, path)
            self.assertIn('error', json.loads(body))


if __name__ == '__main__':
    unittest.main()
