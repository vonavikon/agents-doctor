"""Tests for the scaled tree API:
/api/tree pagination + sorting + severity filter, /api/tree/stats
recursive size accounting with a fingerprint cache, /api/search
server-side name search. Contract pinned for the frontend: see the
api_tree/api_tree_stats/api_search docstrings in ui/server.py."""
import http.client
import json
import os
import sys
import tempfile
import threading
import unittest
from datetime import datetime
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[1] / 'skills' / 'agents-doctor' / 'scripts'
sys.path.insert(0, str(SCRIPTS))

from ui import server as srv          # noqa: E402
from ui.server import UiState         # noqa: E402

ZEROS = {s: 0 for s in srv.SEVERITY_ORDER}


def _sized_tree():
    """Workspace with known file sizes:

    a.txt 10, b.txt 20, sub/c.txt 30, sub/deep/d.log 40,
    node_modules/pkg/index.js 50, __pycache__/x.pyc 60.
    Root totals: 210 bytes / 6 files; build 110 (node_modules +
    __pycache__); problem files a.txt+sub/c.txt = 40. Findings: high
    on sub/c.txt, low on a.txt."""
    root = Path(tempfile.mkdtemp())
    home = Path(tempfile.mkdtemp())

    def put(rel, n):
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b'x' * n)

    put('a.txt', 10)
    put('b.txt', 20)
    put('sub/c.txt', 30)
    put('sub/deep/d.log', 40)
    put('node_modules/pkg/index.js', 50)
    put('__pycache__/x.pyc', 60)
    rep = {'root': str(root), 'home': str(home), 'gates': [],
           'findings_detailed': [
               {'fid': 'T1', 'severity': 'high', 'status': 'fail',
                'evidence': [{'file': 'sub/c.txt'}]},
               {'fid': 'T2', 'severity': 'low', 'status': 'fail',
                'evidence': [{'file': 'a.txt'}]},
           ]}
    return rep, root, home


def _flat_tree(n):
    """Flat workspace: f00.txt .. fNN.txt, 1 byte each, no findings."""
    root = Path(tempfile.mkdtemp())
    home = Path(tempfile.mkdtemp())
    for i in range(n):
        (root / ('f%02d.txt' % i)).write_bytes(b'x')
    rep = {'root': str(root), 'home': str(home), 'gates': [],
           'findings_detailed': []}
    return rep, root, home


def _symlinks_supported():
    probe = Path(tempfile.mkdtemp())
    try:
        tgt = probe / 't.txt'
        tgt.write_text('x', encoding='utf-8')
        os.symlink(tgt, probe / 'link')
        return True
    except (OSError, NotImplementedError):
        return False


class TreePaginationTest(unittest.TestCase):
    """Cursor pages, next_cursor, total/returned/complete,
    and backward compatibility of the old keys."""

    def setUp(self):
        self.rep, self.root, self.home = _flat_tree(8)
        self.state = UiState(self.rep, self.root)

    def test_first_page_shape(self):
        with mock.patch.object(srv, 'TREE_PAGE', 5):
            out = srv.api_tree(self.state, parse_qs('path='))
        self.assertEqual(out['total_entries'], 8)
        self.assertEqual(out['returned_entries'], 5)
        self.assertEqual(len(out['children']), 5)
        self.assertEqual(out['next_cursor'], 5)
        self.assertFalse(out['complete'])
        self.assertTrue(out['truncated'])
        self.assertEqual(out['path'], '')

    def test_last_page_null_cursor(self):
        with mock.patch.object(srv, 'TREE_PAGE', 5):
            out = srv.api_tree(self.state, parse_qs('path=&cursor=5'))
        self.assertEqual(out['returned_entries'], 3)
        self.assertEqual(len(out['children']), 3)
        self.assertIsNone(out['next_cursor'])
        self.assertTrue(out['complete'])
        self.assertFalse(out['truncated'])

    def test_cursor_beyond_end_is_empty_complete(self):
        with mock.patch.object(srv, 'TREE_PAGE', 5):
            out = srv.api_tree(self.state, parse_qs('path=&cursor=50'))
        self.assertEqual(out['children'], [])
        self.assertIsNone(out['next_cursor'])
        self.assertTrue(out['complete'])
        self.assertEqual(out['total_entries'], 8)

    def test_pages_concat_equals_single_shot(self):
        with mock.patch.object(srv, 'TREE_PAGE', 3):
            p1 = srv.api_tree(self.state, parse_qs('path='))
            p2 = srv.api_tree(self.state, parse_qs('cursor=3'))
            p3 = srv.api_tree(self.state, parse_qs('cursor=6'))
        paged = [c['name'] for c in p1['children'] + p2['children']
                 + p3['children']]
        oneshot = srv.api_tree(self.state, parse_qs('path='))
        self.assertEqual(paged, [c['name'] for c in oneshot['children']])
        self.assertEqual(len(set(paged)), 8)

    def test_old_response_keys_survive(self):
        out = srv.api_tree(self.state, parse_qs('path='))
        for key in ('path', 'children', 'counts', 'truncated'):
            self.assertIn(key, out)
        child = out['children'][0]
        for key in ('name', 'path', 'is_dir', 'symlink', 'size', 'mtime',
                    'counts'):
            self.assertIn(key, child)
        self.assertFalse(out['truncated'])   # 8 < TREE_PAGE: one page

    def test_counts_not_cut_by_page(self):
        """A child landing on page 2 still carries its full findings
        counts, and the directory-level aggregate is page-independent."""
        rep, root, home = _sized_tree()
        state = UiState(rep, root)
        with mock.patch.object(srv, 'TREE_PAGE', 2):
            p1 = srv.api_tree(state, parse_qs('path='))
            self.assertEqual(p1['next_cursor'], 2)
            p2 = srv.api_tree(state, parse_qs('cursor=2'))
        names_p2 = [c['name'] for c in p2['children']]
        self.assertIn('sub', names_p2)   # dirs sort first: 3 dirs > page
        # find sub wherever it landed and check full aggregation
        both = p1['children'] + p2['children']
        sub = next(c for c in both if c['name'] == 'sub')
        self.assertEqual(sub['counts']['high'], 1)
        self.assertEqual(sub['counts']['low'], 0)
        a = next(c for c in both if c['name'] == 'a.txt')
        self.assertEqual(a['counts']['low'], 1)
        self.assertEqual(p2['counts'], p1['counts'])
        self.assertEqual(p1['counts']['high'], 1)
        self.assertEqual(p1['counts']['low'], 1)


class TreeSortTest(unittest.TestCase):
    def _ws(self):
        root = Path(tempfile.mkdtemp())
        home = Path(tempfile.mkdtemp())
        (root / 'big.bin').write_bytes(b'x' * 100)
        (root / 'mid.bin').write_bytes(b'x' * 50)
        (root / 'small.bin').write_bytes(b'x' * 10)
        (root / 'adir').mkdir()
        (root / 'zdir').mkdir()
        rep = {'root': str(root), 'home': str(home), 'gates': [],
               'findings_detailed': []}
        return rep, root

    def test_sort_name_dirs_first_casefold(self):
        rep, root = self._ws()
        (root / 'ZZ.txt').write_text('z', encoding='utf-8')
        (root / 'aa.txt').write_text('a', encoding='utf-8')
        state = UiState(rep, root)
        out = srv.api_tree(state, parse_qs('sort=name'))
        names = [c['name'] for c in out['children']]
        self.assertEqual(names, ['adir', 'zdir', 'aa.txt', 'big.bin',
                                 'mid.bin', 'small.bin', 'ZZ.txt'])

    def test_sort_size_files_desc_then_dirs(self):
        rep, root = self._ws()
        state = UiState(rep, root)
        out = srv.api_tree(state, parse_qs('sort=size'))
        names = [c['name'] for c in out['children']]
        self.assertEqual(names, ['big.bin', 'mid.bin', 'small.bin',
                                 'adir', 'zdir'])

    def test_sort_problems_by_count_sum_desc(self):
        rep, root = self._ws()
        (root / 'zdir/bad.txt').write_text('b', encoding='utf-8')
        (root / 'a.txt').write_text('a', encoding='utf-8')
        rep['findings_detailed'] = [
            {'fid': 'P1', 'severity': 'high', 'status': 'fail',
             'evidence': [{'file': 'zdir/bad.txt'}]},
            {'fid': 'P2', 'severity': 'medium', 'status': 'fail',
             'evidence': [{'file': 'zdir/bad.txt'}]},
            {'fid': 'P3', 'severity': 'low', 'status': 'fail',
             'evidence': [{'file': 'a.txt'}]},
        ]
        state = UiState(rep, root)
        out = srv.api_tree(state, parse_qs('sort=problems'))
        names = [c['name'] for c in out['children']]
        self.assertEqual(names.index('zdir'), 0)   # sum 2
        self.assertEqual(names.index('a.txt'), 1)  # sum 1
        # zeros after: dirs first, then files by name
        self.assertLess(names.index('adir'), names.index('big.bin'))


class TreeSevFilterTest(unittest.TestCase):
    def setUp(self):
        self.rep, self.root, self.home = _sized_tree()
        self.state = UiState(self.rep, self.root)

    def test_sev_high_keeps_only_flagged(self):
        out = srv.api_tree(self.state, parse_qs('sev=high'))
        names = [c['name'] for c in out['children']]
        self.assertEqual(names, ['sub'])   # only sub carries a high

    def test_sev_multi_filter_totals(self):
        out = srv.api_tree(self.state, parse_qs('sev=high,low'))
        names = sorted(c['name'] for c in out['children'])
        self.assertEqual(names, ['a.txt', 'sub'])
        self.assertEqual(out['total_entries'], 2)

    def test_sev_unknown_rejected(self):
        with self.assertRaises(srv.ApiUsageError):
            srv.api_tree(self.state, parse_qs('sev=critical,hyper'))
        with self.assertRaises(srv.ApiUsageError):
            srv.api_tree(self.state, parse_qs('sev=urgent'))


class TreeBadParamsTest(unittest.TestCase):
    def setUp(self):
        self.rep, self.root, self.home = _sized_tree()
        self.state = UiState(self.rep, self.root)

    def test_bad_cursor_rejected(self):
        for bad in ('abc', '-1', '1.5', 'zero'):
            with self.assertRaises(srv.ApiUsageError):
                srv.api_tree(self.state, parse_qs('cursor=' + bad))

    def test_bad_sort_rejected(self):
        with self.assertRaises(srv.ApiUsageError):
            srv.api_tree(self.state, parse_qs('sort=bytes'))

    def test_escape_and_file_path_error_dicts(self):
        esc = srv.api_tree(self.state, parse_qs('path=..'))
        self.assertIn('error', esc)
        filed = srv.api_tree(self.state, parse_qs('path=a.txt'))
        self.assertEqual(filed.get('error'), 'not a directory')

    def test_cursor_zero_is_first_page(self):
        out = srv.api_tree(self.state, parse_qs('cursor=0'))
        self.assertEqual(out['returned_entries'], out['total_entries'])
        self.assertTrue(out['complete'])


class TreeStatsTest(unittest.TestCase):
    def setUp(self):
        self.rep, self.root, self.home = _sized_tree()
        self.state = UiState(self.rep, self.root)

    def test_root_totals(self):
        out = srv.api_tree_stats(self.state, parse_qs('path='))
        self.assertEqual(out['total_bytes'], 210)
        self.assertEqual(out['total_files'], 6)
        self.assertTrue(out['complete'])
        self.assertEqual(out['inaccessible'], [])
        self.assertEqual(out['share_of_root_percent'], 100.0)
        self.assertEqual(out['path'], '')
        datetime.fromisoformat(out['computed_at'])   # parses as ISO

    def test_build_bytes_from_build_dirs(self):
        out = srv.api_tree_stats(self.state, parse_qs('path='))
        # node_modules/pkg/index.js (50) + __pycache__/x.pyc (60)
        self.assertEqual(out['build_bytes'], 110)

    def test_problem_files_bytes(self):
        out = srv.api_tree_stats(self.state, parse_qs('path='))
        self.assertEqual(out['problem_files_bytes'], 40)  # a.txt+c.txt

    def test_subdir_totals_problem_bytes_share(self):
        out = srv.api_tree_stats(self.state, parse_qs('path=sub'))
        self.assertEqual(out['total_bytes'], 70)   # c.txt 30 + d.log 40
        self.assertEqual(out['total_files'], 2)
        self.assertEqual(out['problem_files_bytes'], 30)
        self.assertEqual(out['share_of_root_percent'], 33.33)

    def test_build_dir_own_stats(self):
        out = srv.api_tree_stats(self.state,
                                 parse_qs('path=node_modules'))
        self.assertEqual(out['total_bytes'], 50)
        self.assertEqual(out['build_bytes'], 50)
        self.assertEqual(out['share_of_root_percent'], 23.81)

    @unittest.skipUnless(_symlinks_supported(),
                         'symlink creation not permitted on this host')
    def test_symlinks_skipped_not_followed(self):
        # symlinked file and symlinked dir: neither counted nor walked
        (self.root / 'realdir').mkdir()
        (self.root / 'realdir' / 'inner.txt').write_bytes(b'x' * 7)
        os.symlink(self.root / 'a.txt', self.root / 'link-file.txt')
        os.symlink(self.root / 'realdir', self.root / 'link-dir',
                   target_is_directory=True)
        out = srv.api_tree_stats(self.state, parse_qs('path='))
        self.assertEqual(out['total_bytes'], 210 + 7)
        self.assertEqual(out['total_files'], 7)
        self.assertTrue(out['complete'])

    def test_stats_cache_returns_same_object(self):
        r1 = srv.api_tree_stats(self.state, parse_qs('path='))
        r2 = srv.api_tree_stats(self.state, parse_qs('path='))
        self.assertIs(r1, r2)
        self.assertIn('', self.state._stats_cache)

    def test_stats_cache_recomputed_on_change(self):
        r1 = srv.api_tree_stats(self.state, parse_qs('path='))
        (self.root / 'new.txt').write_bytes(b'y' * 5)
        r2 = srv.api_tree_stats(self.state, parse_qs('path='))
        self.assertIsNot(r1, r2)
        self.assertEqual(r2['total_bytes'], 215)
        self.assertEqual(r2['total_files'], 7)

    def test_stats_cache_cleared_on_reload(self):
        r1 = srv.api_tree_stats(self.state, parse_qs('path='))
        self.state.reload(self.rep)
        self.assertEqual(self.state._stats_cache, {})
        r2 = srv.api_tree_stats(self.state, parse_qs('path='))
        self.assertIsNot(r1, r2)
        self.assertEqual(r2['total_bytes'], r1['total_bytes'])

    def test_stats_errors(self):
        esc = srv.api_tree_stats(self.state, parse_qs('path=..'))
        self.assertIn('error', esc)
        filed = srv.api_tree_stats(self.state, parse_qs('path=a.txt'))
        self.assertIn('error', filed)


class SearchTest(unittest.TestCase):
    def setUp(self):
        self.rep, self.root, self.home = _sized_tree()
        self.state = UiState(self.rep, self.root)

    def test_substring_casefold(self):
        out = srv.api_search(self.state, parse_qs('q=A.T'))
        names = [Path(m['path']).name for m in out['matches']]
        self.assertEqual(names, ['a.txt'])
        out2 = srv.api_search(self.state, parse_qs('q=C.TXT'))
        self.assertEqual([m['path'] for m in out2['matches']],
                         ['sub/c.txt'])

    def test_dir_match_gets_aggregated_counts(self):
        out = srv.api_search(self.state, parse_qs('q=sub'))
        match = next(m for m in out['matches'] if m['path'] == 'sub')
        self.assertTrue(match['is_dir'])
        self.assertEqual(match['counts']['high'], 1)
        # name-only matching: 'sub/deep' is found by its own name
        deep = srv.api_search(self.state, parse_qs('q=deep'))
        self.assertEqual([m['path'] for m in deep['matches']],
                         ['sub/deep'])
        self.assertTrue(deep['matches'][0]['is_dir'])

    def test_file_match_counts(self):
        out = srv.api_search(self.state, parse_qs('q=c.txt'))
        match = out['matches'][0]
        self.assertEqual(match['counts']['high'], 1)
        self.assertEqual(match['counts']['low'], 0)

    def test_limit_and_truncated(self):
        rep, root, home = _flat_tree(3)
        state = UiState(rep, root)
        out = srv.api_search(state, parse_qs('q=f&limit=2'))
        self.assertEqual(len(out['matches']), 2)
        self.assertEqual(out['total_matches'], 3)
        self.assertTrue(out['truncated'])

    def test_limit_clamped_to_max(self):
        with mock.patch.object(srv, 'SEARCH_LIMIT_MAX', 2):
            out = srv.api_search(self.state, parse_qs('q=.txt&limit=99'))
        self.assertLessEqual(len(out['matches']), 2)
        self.assertTrue(out['truncated'])

    def test_scan_cap_sets_truncated(self):
        with mock.patch.object(srv, 'SEARCH_SCAN_CAP', 3):
            out = srv.api_search(self.state, parse_qs('q=.txt'))
        self.assertTrue(out['truncated'])
        self.assertLessEqual(out['total_matches'], 3)

    def test_default_limit_100(self):
        rep, root, home = _flat_tree(4)
        state = UiState(rep, root)
        out = srv.api_search(state, parse_qs('q=f'))
        self.assertEqual(len(out['matches']), 4)
        self.assertFalse(out['truncated'])

    def test_match_shape_is_name_only(self):
        out = srv.api_search(self.state, parse_qs('q=index'))
        self.assertEqual(out['total_matches'], 1)
        m = out['matches'][0]
        self.assertEqual(set(m.keys()), {'path', 'is_dir', 'counts'})
        self.assertEqual(m['path'], 'node_modules/pkg/index.js')

    def test_bad_params_rejected(self):
        for qs in ('', 'q=', 'q=%20%20', 'q=x&limit=abc',
                   'q=x&limit=0', 'q=x&limit=-5'):
            with self.assertRaises(srv.ApiUsageError, msg=qs):
                srv.api_search(self.state, parse_qs(qs))


# ------------------------------------------------------------------
# wire-level checks: pagination payload over HTTP, 400 on bad
# params (ApiUsageError), and the two new routes answering 200.

class _LiveTreeServer:
    def __init__(self):
        rep, root, home = _sized_tree()
        self.state = UiState(rep, root)
        self.httpd = ThreadingHTTPServer(
            ('127.0.0.1', 0), srv.make_handler(self.state, None))
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever,
                         daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def _get(port, path):
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=15)
    try:
        conn.request('GET', path)
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


class TreeApiHttpTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.live = _LiveTreeServer()
        cls.port = cls.live.port

    @classmethod
    def tearDownClass(cls):
        cls.live.close()

    def test_tree_pagination_over_http(self):
        status, body = _get(self.port, '/api/tree')
        self.assertEqual(status, 200)
        out = json.loads(body)
        for key in ('children', 'next_cursor', 'total_entries',
                    'returned_entries', 'complete', 'path', 'counts',
                    'truncated'):
            self.assertIn(key, out)
        self.assertIsNone(out['next_cursor'])   # small fixture: 1 page

    def test_tree_bad_params_are_400(self):
        for path in ('/api/tree?cursor=abc', '/api/tree?sort=bytes',
                     '/api/tree?sev=nope'):
            status, body = _get(self.port, path)
            self.assertEqual(status, 400, path)
            self.assertIn('error', json.loads(body))

    def test_stats_endpoint_over_http(self):
        status, body = _get(self.port, '/api/tree/stats?path=sub')
        self.assertEqual(status, 200)
        out = json.loads(body)
        self.assertEqual(out['total_bytes'], 70)
        self.assertEqual(out['share_of_root_percent'], 33.33)

    def test_search_endpoint_over_http(self):
        status, body = _get(self.port, '/api/search?q=c.txt&limit=5')
        self.assertEqual(status, 200)
        out = json.loads(body)
        self.assertEqual(out['total_matches'], 1)
        self.assertEqual(out['matches'][0]['path'], 'sub/c.txt')

    def test_search_without_q_is_400(self):
        status, body = _get(self.port, '/api/search')
        self.assertEqual(status, 400)
        self.assertIn('error', json.loads(body))


if __name__ == '__main__':
    unittest.main()
