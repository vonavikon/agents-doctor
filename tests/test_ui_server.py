"""Tests for the local web UI server:
API shape, path containment, secret masking in previews, read-only
guarantees, and the request-security layer (Host check,
CSRF/Origin check, --token mode, CSP headers)."""
import http.client
import json
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

SCRIPTS = Path(__file__).resolve().parents[1] / 'skills' / 'agents-doctor' / 'scripts'
sys.path.insert(0, str(SCRIPTS))

import audit_scan  # noqa: E402
from ui.server import UiState, _contain, _mask_line  # noqa: E402
from ui import server as srv  # noqa: E402


def _ws_with_secret():
    root = Path(tempfile.mkdtemp())
    home = Path(tempfile.mkdtemp())
    (root / 'AGENTS.md').write_text('# x\n', encoding='utf-8')
    (root / 'creds.txt').write_text(
        'token = "supersecret-value-12345"\nnormal line\n',
        encoding='utf-8')
    rep = audit_scan.scan(root, home, False)
    return rep, root, home


class ContainmentTest(unittest.TestCase):
    def test_contain_rejects_escape(self):
        rep, root, home = _ws_with_secret()
        state = UiState(rep, root)
        for bad in ('../etc', '..\\\\windows', 'a/../../x'):
            with self.assertRaises(PermissionError):
                _contain(state, bad)

    def test_contain_accepts_inside(self):
        rep, root, home = _ws_with_secret()
        state = UiState(rep, root)
        target = _contain(state, 'creds.txt')
        self.assertEqual(target.name, 'creds.txt')


class MaskingTest(unittest.TestCase):
    def test_mask_line_hides_values(self):
        line = 'api_key = "abcdefghijklmnop"'
        masked = _mask_line(line)
        self.assertNotIn('abcdefghijklmnop', masked)
        self.assertIn('***', masked)

    def test_mask_line_keeps_normal_lines(self):
        self.assertEqual(_mask_line('hello world'), 'hello world')

    def test_file_preview_masks_secrets(self):
        rep, root, home = _ws_with_secret()
        state = UiState(rep, root)
        out = srv.api_file(state, parse_qs('path=creds.txt'))
        blob = '\n'.join(out['lines'])
        self.assertNotIn('supersecret-value-12345', blob)
        self.assertIn('***', blob)
        self.assertTrue(out['flagged_lines'])

    def test_preview_is_capped(self):
        root = Path(tempfile.mkdtemp())
        home = Path(tempfile.mkdtemp())
        (root / 'big.txt').write_text('x' * (300 * 1024), encoding='utf-8')
        rep = {'root': str(root), 'home': str(home),
               'findings_detailed': [], 'gates': []}
        state = UiState(rep, root)
        out = srv.api_file(state, parse_qs('path=big.txt'))
        self.assertTrue(out['truncated'])

    def test_binary_preview(self):
        root = Path(tempfile.mkdtemp())
        (root / 'blob.bin').write_bytes(b'\x00\x01\x02binary')
        rep = {'root': str(root), 'findings_detailed': [], 'gates': []}
        state = UiState(rep, root)
        out = srv.api_file(state, parse_qs('path=blob.bin'))
        self.assertTrue(out['binary'])


class ApiTest(unittest.TestCase):
    def test_overview_shape(self):
        rep, root, home = _ws_with_secret()
        state = UiState(rep, root)
        out = srv.api_overview(state, {})
        for key in ('root', 'gates', 'severity_counts', 'status_counts',
                    'findings_total', 'rules_version'):
            self.assertIn(key, out)

    def test_findings_filter_by_gate(self):
        rep, root, home = _ws_with_secret()
        state = UiState(rep, root)
        out = srv.api_findings(state, parse_qs('gate=G6'))
        self.assertTrue(all(f['gate'] == 'G6' for f in out['findings']))
        out_all = srv.api_findings(state, {})
        self.assertGreaterEqual(out_all['count'], out['count'])

    def test_tree_children_with_counts(self):
        rep, root, home = _ws_with_secret()
        state = UiState(rep, root)
        out = srv.api_tree(state, parse_qs('path='))
        names = [c['name'] for c in out['children']]
        self.assertIn('creds.txt', names)
        creds = next(c for c in out['children'] if c['name'] == 'creds.txt')
        self.assertIn('counts', creds)
        self.assertEqual(creds['size'],
                         (root / 'creds.txt').stat().st_size)

    def test_tree_rejects_escape(self):
        rep, root, home = _ws_with_secret()
        state = UiState(rep, root)
        out = srv.api_tree(state, parse_qs('path=..'))
        self.assertIn('error', out)

    def test_finding_lookup(self):
        rep, root, home = _ws_with_secret()
        state = UiState(rep, root)
        some = rep['findings_detailed'][0]
        got = srv.api_finding(state, some['fid'])
        self.assertEqual(got['fid'], some['fid'])
        self.assertIsNone(srv.api_finding(state, 'NOPE-999'))

    def test_fixplan_is_dry_run(self):
        rep, root, home = _ws_with_secret()
        state = UiState(rep, root)
        out = srv.api_fixplan(state, parse_qs('fid=NOPE-999'))
        # unsupported finding: reported, never improvised
        self.assertFalse(out.get('supported', True)
                         and out.get('steps'))

    def test_compare_requires_baseline(self):
        rep, root, home = _ws_with_secret()
        state = UiState(rep, root)
        out = srv.api_compare(state, {})
        self.assertFalse(out['supported'])
        state.baseline = rep
        out2 = srv.api_compare(state, {})
        self.assertTrue(out2['supported'])
        self.assertEqual(out2['summary']['new'], 0)

    def test_simulate_endpoint(self):
        rep, root, home = _ws_with_secret()
        state = UiState(rep, root)
        out = srv.api_simulate(state, parse_qs(''))
        self.assertTrue(out.get('approximated'))
        self.assertIn('harnesses', out)


# ------------------------------------------------------------------
# request-security layer: a real server
# on an ephemeral loopback port, exercised over plain http.client so
# header spoofing can be tested exactly as the wire sees it.

class _LiveServer:
    """UI server on an ephemeral loopback port, in a daemon thread."""

    def __init__(self, token=None):
        rep, root, home = _ws_with_secret()
        self.state = UiState(rep, root)
        self.httpd = ThreadingHTTPServer(
            ('127.0.0.1', 0), srv.make_handler(self.state, token))
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever,
                         daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def _request(port, method, path, headers=None):
    """One HTTP request; returns (status, headers dict, body bytes).
    An explicit Host header in `headers` overrides the client default,
    which is how Host-spoofing is simulated."""
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=15)
    try:
        conn.request(method, path, headers=headers or {})
        resp = conn.getresponse()
        return resp.status, dict(resp.getheaders()), resp.read()
    finally:
        conn.close()


def _hdr(headers, name):
    lname = name.lower()
    for k, v in headers.items():
        if k.lower() == lname:
            return v
    return None


class HttpSecurityTest(unittest.TestCase):
    """Host check and CSRF/Origin check of the plain (no-token) server."""

    @classmethod
    def setUpClass(cls):
        cls.live = _LiveServer()
        cls.port = cls.live.port

    @classmethod
    def tearDownClass(cls):
        cls.live.close()

    def test_host_header_spoof_rejected(self):
        status, _, body = _request(self.port, 'GET', '/api/overview',
                                   {'Host': 'evil.com'})
        self.assertEqual(status, 403)
        self.assertIn('error', json.loads(body))

    def test_host_header_wrong_port_rejected(self):
        status, _, _ = _request(self.port, 'GET', '/api/overview',
                                {'Host': '127.0.0.1:9'})
        self.assertEqual(status, 403)

    def test_default_host_accepted(self):
        status, _, _ = _request(self.port, 'GET', '/api/overview')
        self.assertEqual(status, 200)

    def test_post_rescan_cross_origin_rejected(self):
        status, _, _ = _request(self.port, 'POST', '/api/rescan',
                                {'Origin': 'http://evil.com'})
        self.assertEqual(status, 403)

    def test_post_rescan_localhost_origin_ok(self):
        status, _, body = _request(
            self.port, 'POST', '/api/rescan',
            {'Origin': 'http://localhost:%d' % self.port})
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body)['rescanned'])

    def test_post_rescan_127_origin_ok(self):
        status, _, _ = _request(
            self.port, 'POST', '/api/rescan',
            {'Origin': 'http://127.0.0.1:%d' % self.port})
        self.assertEqual(status, 200)

    def test_post_rescan_referer_local_ok(self):
        status, _, _ = _request(
            self.port, 'POST', '/api/rescan',
            {'Referer': 'http://127.0.0.1:%d/' % self.port})
        self.assertEqual(status, 200)

    def test_post_rescan_referer_evil_rejected(self):
        status, _, _ = _request(self.port, 'POST', '/api/rescan',
                                {'Referer': 'http://evil.com/x'})
        self.assertEqual(status, 403)

    def test_post_rescan_no_origin_rejected_strict_default(self):
        # curl-style POST without Origin/Referer and without the
        # opt-in header: rejected by default
        status, _, _ = _request(self.port, 'POST', '/api/rescan')
        self.assertEqual(status, 403)

    def test_post_rescan_curl_header_ok(self):
        status, _, _ = _request(self.port, 'POST', '/api/rescan',
                                {'X-Agents-Doctor': 'local'})
        self.assertEqual(status, 200)

    def test_post_rescan_sec_fetch_cross_site_rejected(self):
        headers = {'Origin': 'http://127.0.0.1:%d' % self.port,
                   'Sec-Fetch-Site': 'cross-site'}
        status, _, _ = _request(self.port, 'POST', '/api/rescan', headers)
        self.assertEqual(status, 403)

    def test_post_rescan_sec_fetch_same_origin_ok(self):
        headers = {'Origin': 'http://127.0.0.1:%d' % self.port,
                   'Sec-Fetch-Site': 'same-origin'}
        status, _, _ = _request(self.port, 'POST', '/api/rescan', headers)
        self.assertEqual(status, 200)

    def test_static_serves_csp_headers(self):
        status, headers, _ = _request(self.port, 'GET', '/')
        self.assertEqual(status, 200)
        csp = _hdr(headers, 'Content-Security-Policy')
        self.assertIsNotNone(csp)
        for directive in ("default-src 'self'",
                          "style-src 'self' 'unsafe-inline'",
                          "img-src 'self' data:"):
            self.assertIn(directive, csp)
        self.assertEqual(_hdr(headers, 'X-Content-Type-Options'),
                         'nosniff')

    def test_api_mcp_endpoint(self):
        status, _, body = _request(self.port, 'GET', '/api/mcp')
        self.assertEqual(status, 200)
        out = json.loads(body)
        for key in ('servers', 'files_scanned', 'parse_errors'):
            self.assertIn(key, out)


class TokenModeTest(unittest.TestCase):
    """--token mode: /api/* requires Bearer or ?token=; static stays
    open; curl-style POST passes on a valid token."""

    @classmethod
    def setUpClass(cls):
        cls.token = 'test-token-0123456789abcdef'
        cls.live = _LiveServer(token=cls.token)
        cls.port = cls.live.port

    @classmethod
    def tearDownClass(cls):
        cls.live.close()

    def test_api_without_token_unauthorized(self):
        status, _, body = _request(self.port, 'GET', '/api/overview')
        self.assertEqual(status, 401)
        self.assertIn('error', json.loads(body))

    def test_api_wrong_token_unauthorized(self):
        status, _, _ = _request(self.port, 'GET', '/api/overview',
                                {'Authorization': 'Bearer wrong-token'})
        self.assertEqual(status, 401)

    def test_api_bearer_token_ok(self):
        status, _, _ = _request(self.port, 'GET', '/api/overview',
                                {'Authorization': 'Bearer ' + self.token})
        self.assertEqual(status, 200)

    def test_api_query_token_ok(self):
        status, _, _ = _request(self.port, 'GET',
                                '/api/overview?token=' + self.token)
        self.assertEqual(status, 200)

    def test_static_index_without_token_ok(self):
        status, _, _ = _request(self.port, 'GET', '/')
        self.assertEqual(status, 200)

    def test_static_asset_without_token_ok(self):
        status, _, _ = _request(self.port, 'GET', '/static/app.js')
        self.assertEqual(status, 200)

    def test_post_with_token_and_no_origin_ok(self):
        # token mode is the documented way to allow Origin-less
        # (curl) mutations
        status, _, _ = _request(self.port, 'POST', '/api/rescan',
                                {'Authorization': 'Bearer ' + self.token})
        self.assertEqual(status, 200)

    def test_post_cross_origin_rejected_even_with_token(self):
        status, _, _ = _request(self.port, 'POST', '/api/rescan',
                                {'Authorization': 'Bearer ' + self.token,
                                 'Origin': 'http://evil.com'})
        self.assertEqual(status, 403)


if __name__ == '__main__':
    unittest.main()
