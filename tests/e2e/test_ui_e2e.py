"""Browser E2E tests for the agents-doctor local web UI.

Playwright sync API on top of unittest (the repo runs unittest, not
pytest). Each test class builds a temp workspace, scans it in-process,
serves ui/server.py on an ephemeral 127.0.0.1 port and drives a real
headless browser against the SPA from ui/static.

Browser channel: AGENTS_E2E_BROWSER selects the Playwright browser
(default chromium; CI also runs the suite with firefox). A missing
browser binary skips the suite honestly; an unknown name is a hard
error so typos in the env var never silently skip everything.

Skip gate: without `playwright` installed every test here skips, so the
plain `unittest discover` suite stays green on machines (and CI jobs)
that never asked for browser tests. Install them with:

    pip install -r requirements-dev.txt
    python -m playwright install chromium firefox

Every test ends by asserting that the page produced no console errors
and no unhandled page errors (the allowlist is empty by default; add an
entry only for a browser artifact, never to silence an app bug).
"""
import json
import os
import re
import shutil
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[2] / 'skills' / \
    'agents-doctor' / 'scripts'
sys.path.insert(0, str(SCRIPTS))

import audit_scan  # noqa: E402
from ui import server as srv  # noqa: E402

try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT = True
except ImportError:
    PLAYWRIGHT = False

# Canary secret. Assembled from pieces so a scan of THIS repository
# never sees the whole token in the test source (same convention as
# secret_rules.py). The file under test does contain the full value.
CANARY = 'xox' + 'b-123456789012-1234567890123-abcdefghijklmnopqrstuv'

# Canary tail shared with the second token in the fixture; both must be
# masked everywhere the DOM is checked.
CANARY_TAIL = 'abcdefghijklmnopqrstuv'

WAIT_MS = 15000  # explicit per-wait budget, well under unittest's wants

# Playwright browser channel: chromium in
# the default run, firefox in the second CI step. Unknown names fail
# loudly; a known name without its binary skips honestly.
E2E_BROWSER = os.environ.get('AGENTS_E2E_BROWSER', 'chromium').strip().lower()


def build_workspace(root: Path) -> None:
    """Deterministic workspace: dead links, a wildcard Bash permission,
    a secrets file (canary + one more live-looking token) and a nested
    src/ folder so the tree has directories to expand."""
    (root / 'AGENTS.md').write_text(
        '# Fixture project\n\n'
        'See [Contributing](./CONTRIBUTING.md) and [Docs](./docs/guide.md) '
        'for details.\n', encoding='utf-8')
    (root / '.claude').mkdir()
    (root / '.claude' / 'settings.json').write_text(json.dumps({
        'permissions': {'allow': ['Bash(*)', 'WebFetch']},
    }), encoding='utf-8')
    (root / 'src').mkdir()
    (root / 'src' / 'creds.txt').write_text(
        '# service credentials\n'
        'slack_token = "%s"\n'
        'anthropic_key = "sk-ant-api03-abcdefghijklmnopqrstuv"\n'
        'normal = "hello world"\n' % CANARY, encoding='utf-8')
    (root / 'src' / 'notes.md').write_text(
        '# Notes\n\nExample header: Authorization: Bearer ya29.test-token\n',
        encoding='utf-8')


class UiHarness:
    """One scanned workspace + one UI server + one headless browser.

    Used as a per-class fixture: create in setUpClass, close() in
    tearDownClass. Pages are handed out per test via open_page(), each
    on a fresh context with console/pageerror collection wired up.

    workspace_builder(root) populates the workspace before the scan.
    state_factory(root, home) overrides how the UiState is built (for
    servers with a broken/baseline-mangled report); default is a fresh
    in-process scan.
    """

    def __init__(self, workspace_builder, state_factory=None):
        self.tmp = Path(tempfile.mkdtemp(prefix='ad-e2e-'))
        self.root = self.tmp / 'ws'
        self.home = self.tmp / 'home'
        self.root.mkdir()
        self.home.mkdir()
        workspace_builder(self.root)
        if state_factory is None:
            self.report = audit_scan.scan(self.root, self.home, False)
            state = srv.UiState(self.report, self.root)
        else:
            state = state_factory(self.root, self.home)
        self.httpd = ThreadingHTTPServer(('127.0.0.1', 0),
                                         srv.make_handler(state, None))
        self.port = self.httpd.server_address[1]
        self.base = 'http://127.0.0.1:%d/' % self.port
        threading.Thread(target=self.httpd.serve_forever,
                         daemon=True).start()
        self._pw = sync_playwright().start()
        launcher = getattr(self._pw, E2E_BROWSER, None)
        if launcher is None:
            raise ValueError(
                'AGENTS_E2E_BROWSER=%r: expected chromium, firefox or '
                'webkit' % E2E_BROWSER)
        try:
            self.browser = launcher.launch(headless=True)
        except Exception as exc:
            # missing binary -> honest skip, not a red herring failure
            if 'Executable doesn\'t exist' in str(exc):
                raise unittest.SkipTest(
                    '%s browser not installed '
                    '(python -m playwright install %s)'
                    % (E2E_BROWSER, E2E_BROWSER)) from exc
            raise

    def open_page(self):
        """(page, console_errors) on a fresh context. console_errors
        collects console.error messages and uncaught page errors."""
        ctx = self.browser.new_context()
        page = ctx.new_page()
        errors = []
        page.on('console', lambda m: errors.append(m.text)
                if m.type == 'error' else None)
        page.on('pageerror', lambda e: errors.append('pageerror: %s' % e))
        return page, ctx, errors

    def close(self):
        self.browser.close()
        self._pw.stop()
        self.httpd.shutdown()
        self.httpd.server_close()
        shutil.rmtree(self.tmp, ignore_errors=True)


@unittest.skipUnless(PLAYWRIGHT, 'playwright not installed')
class MainWorkspaceE2ETest(unittest.TestCase):
    """Scenarios over the fixture workspace: layout, overview,
    chips, findings + card, tree + inspector (masking!), simulate,
    compare, rescan, dead-file handling, request security."""

    @classmethod
    def setUpClass(cls):
        cls.harness = UiHarness(build_workspace)

    @classmethod
    def tearDownClass(cls):
        cls.harness.close()

    def setUp(self):
        self.page, self._ctx, self.console_errors = \
            self.harness.open_page()

    def tearDown(self):
        self._ctx.close()

    # ------------------------------------------------------- helpers

    def goto(self):
        self.page.goto(self.harness.base)
        return self.page

    def wait(self, selector):
        return self.page.wait_for_selector(selector, timeout=WAIT_MS)

    def open_tab(self, tab):
        self.page.click('#tab-' + tab)
        self.wait('#panel-%s:not([hidden])' % tab)

    def findings_counter(self):
        """'Showing X of Y fetched findings.' -> (X, Y)."""
        txt = self.page.inner_text('.findings-count')
        m = re.search(r'Showing (\d+) of (\d+) fetched', txt)
        self.assertIsNotNone(m, 'counter text unreadable: %r' % txt)
        return int(m.group(1)), int(m.group(2))

    def assert_no_console_errors(self):
        self.assertEqual(self.console_errors, [],
                         'browser console errors: %r' % self.console_errors)

    # ------------------------------------------------------- scenarios

    def test_01_page_loads(self):
        pg = self.goto()
        self.wait('#overview-body .stat-box')
        self.assertEqual(pg.title(),
                         'agents-doctor — Visual Workspace Explorer')
        # topbar meta shows the audited root path
        root_txt = pg.inner_text('#meta-root')
        self.assertIn(self.harness.root.name, root_txt)
        # the seven original tabs must be present. Presence, not an
        # exact count: the UI has more tabs than these seven (the
        # History tab of the governance dashboard), and this test must
        # not break every time a new one lands.
        for tab in ('overview', 'tree', 'treemap', 'instructions',
                    'findings', 'simulate', 'compare'):
            self.assertEqual(
                pg.locator('#tab-' + tab).count(), 1,
                'missing tab #%s' % tab)
        self.assert_no_console_errors()

    def test_02_overview_chips_and_gates(self):
        pg = self.goto()
        self.wait('#overview-body .tbl tbody tr')
        # severity chips render with non-zero counts for the fixture
        crit = pg.locator(
            '#severity-chips .chip[title^="Hide Critical"]')
        self.assertGreater(int(crit.locator('.chip-count').inner_text()),
                           0)
        # nine gates, one table row each, every status has a glyph
        rows = pg.locator('#overview-body .tbl tbody tr')
        self.assertEqual(rows.count(), 9)
        glyphs = pg.locator('#overview-body .status-badge .st-glyph')
        self.assertEqual(glyphs.count(), 9)
        for i in range(glyphs.count()):
            self.assertNotEqual(glyphs.nth(i).inner_text().strip(), '')
        self.assert_no_console_errors()

    def test_03_chip_toggles_pressed_state(self):
        pg = self.goto()
        self.wait('#severity-chips .chip')
        hide = '#severity-chips .chip[title="Hide Critical findings"]'
        show = '#severity-chips .chip[title="Show Critical findings"]'
        chip = pg.locator(hide)
        self.assertEqual(chip.get_attribute('aria-pressed'), 'true')
        chip.click()
        # re-rendered DOM: the same chip now offers to show them again
        chip2 = pg.wait_for_selector(show, timeout=WAIT_MS)
        self.assertEqual(chip2.get_attribute('aria-pressed'), 'false')
        pg.locator(show).click()
        pg.wait_for_selector(hide, timeout=WAIT_MS)
        self.assert_no_console_errors()

    def test_04_findings_table_and_gate_filter(self):
        pg = self.goto()
        self.open_tab('findings')
        self.wait('#findings-body tbody tr.fnd-row')
        shown, total = self.findings_counter()
        self.assertGreater(shown, 0)
        self.assertGreaterEqual(total, shown)
        # gate filter: click the G6 row in the overview gates table
        self.open_tab('overview')
        self.wait('#overview-body .tbl tbody tr')
        pg.locator('#overview-body tbody tr', has_text='G6').first.click()
        self.wait('#panel-findings:not([hidden])')
        self.wait('#findings-body tbody tr.fnd-row')
        g_shown, g_total = self.findings_counter()
        self.assertLess(g_total, total)
        self.assertGreater(g_total, 0)
        # every visible row belongs to G6
        gates = pg.locator('#findings-body tbody tr.fnd-row td:nth-child(3)')
        for i in range(gates.count()):
            self.assertEqual(gates.nth(i).inner_text().strip(), 'G6')
        self.assert_no_console_errors()

    def test_05_findings_search_filter(self):
        pg = self.goto()
        self.open_tab('findings')
        self.wait('#findings-body tbody tr.fnd-row')
        _, total = self.findings_counter()
        pg.fill('#fnd-q', 'creds')
        # 300 ms debounce in app.js + fetch + render; the counter
        # element is replaced during reload, hence the null guard
        pg.wait_for_function(
            """() => {
                const el = document.querySelector('.findings-count');
                return el ? !el.textContent.includes('of %d fetched') : false;
            }""" % total,
            timeout=WAIT_MS)
        shown, filtered = self.findings_counter()
        self.assertGreaterEqual(filtered, 1)
        self.assertLess(filtered, total)
        self.assertEqual(shown, filtered)
        self.assert_no_console_errors()

    def test_06_finding_card_open_and_esc_close(self):
        pg = self.goto()
        self.open_tab('findings')
        row = self.wait('#findings-body tbody tr.fnd-row')
        fid = row.get_attribute('data-fid')
        row.click()
        self.wait('#card-overlay:not([hidden])')
        self.assertEqual(pg.inner_text('#card-fid').strip(), fid)
        # the card opens in a loading state; wait for the fetched body
        # before asserting badges and evidence
        self.wait('#card-badges .sev-badge')
        self.assertGreater(pg.locator('#card-badges .sev-badge').count(), 0)
        self.wait('#card-body .ev-item')
        self.assertGreater(pg.locator('#card-body .ev-item').count(), 0)
        pg.keyboard.press('Escape')
        # state='hidden': wait until the overlay is attached and hidden
        pg.wait_for_selector('#card-overlay', state='hidden',
                             timeout=WAIT_MS)
        self.assert_no_console_errors()

    def test_07_tree_expand_and_inspector(self):
        pg = self.goto()
        self.open_tab('tree')
        self.wait('#tree-body .tree-node-row')
        # expand src/ lazily, then open the secrets file
        pg.locator('.tree-node-row[data-path="src"]').click()
        pg.wait_for_selector('.tree-node-row[data-path="src/creds.txt"]',
                             timeout=WAIT_MS).click()
        self.wait('#inspector:not([hidden])')
        self.wait('#insp-code .code-line')
        self.assertEqual(pg.inner_text('#insp-path').strip(),
                         'src/creds.txt')
        body = pg.inner_text('#insp-code')
        self.assertIn('slack_token', body)
        # the masked value is shown, the raw canary never is
        self.assertIn('xox***', body)
        self.assertNotIn(CANARY, pg.content())
        self.assertNotIn(CANARY, body)
        self.assert_no_console_errors()

    def test_08_inspector_flagged_lines_and_rule_label(self):
        pg = self.goto()
        self.open_tab('tree')
        pg.locator('.tree-node-row[data-path="src"]').click()
        pg.wait_for_selector('.tree-node-row[data-path="src/creds.txt"]',
                             timeout=WAIT_MS).click()
        self.wait('#insp-code .code-line.flagged')
        flagged = pg.locator('#insp-code .code-line.flagged')
        self.assertGreaterEqual(flagged.count(), 2)  # slack + anthropic
        labels = pg.locator('#insp-code .code-flag-label')
        texts = {labels.nth(i).inner_text().strip()
                 for i in range(labels.count())}
        self.assertIn('SEC-106', texts)  # slack-token rule
        self.assert_no_console_errors()

    def test_09_secrets_never_in_dom(self):
        pg = self.goto()
        self.open_tab('tree')
        pg.locator('.tree-node-row[data-path="src"]').click()
        pg.wait_for_selector('.tree-node-row[data-path="src/creds.txt"]',
                             timeout=WAIT_MS).click()
        self.wait('#insp-code .code-line')
        # whole-DOM sweep: the canary token must not leak anywhere,
        # not even into attributes or shadow copies
        html = pg.content()
        self.assertNotIn(CANARY, html)
        self.assertNotIn('abcdefghijklmnopqrstuv', html)
        self.assert_no_console_errors()

    def test_10_simulate_zcode(self):
        pg = self.goto()
        self.open_tab('simulate')
        # <option> has no box of its own: wait for attached, not visible
        pg.wait_for_selector('#sim-harness option[value="zcode"]',
                             state='attached', timeout=WAIT_MS)
        pg.select_option('#sim-harness', 'zcode')
        pg.click('#sim-run')
        self.wait('#simulate-body .sim-harness-block')
        block = pg.locator('#simulate-body .sim-harness-block').first
        # the section title is CSS-uppercased ('ZCODE'), so compare
        # case-insensitively against the harness id
        self.assertIn('zcode', block.inner_text().lower())
        # loaded sources for the fixture: at least the root AGENTS.md
        self.assertIn('Loaded', block.inner_text())
        self.assertIn('AGENTS.md', block.inner_text())
        self.assert_no_console_errors()

    def test_11_compare_without_baseline(self):
        pg = self.goto()
        self.open_tab('compare')
        box = self.wait('#compare-body .empty-state')
        self.assertIn('Compare is not available', box.inner_text())
        # the hint is actionable, not a bare blank
        self.assertIn('--baseline', pg.inner_text('#compare-body'))
        self.assert_no_console_errors()

    def test_12_rescan_post_roundtrip(self):
        pg = self.goto()
        self.wait('#overview-body .stat-box')
        # 1) the page's own POST: the browser sends a same-origin
        #    Origin header and passes the CSRF guard
        pg.click('#btn-rescan')
        toast = self.wait('#toast:not([hidden])')
        self.assertIn('Rescan finished', toast.inner_text())
        # 2) the documented Origin-less path: explicit opt-in header
        resp = pg.request.post(
            self.harness.base + 'api/rescan',
            headers={'X-Agents-Doctor': 'local'})
        self.assertEqual(resp.status, 200)
        self.assertTrue(json.loads(resp.text())['rescanned'])
        self.assert_no_console_errors()

    def test_13_dead_file_preview_shows_error_no_crash(self):
        pg = self.goto()
        self.open_tab('tree')
        pg.locator('.tree-node-row[data-path="AGENTS.md"]').click()
        self.wait('#insp-code .code-line')
        target = self.harness.root / 'AGENTS.md'
        backup = target.read_text(encoding='utf-8')
        try:
            target.unlink()
            pg.locator('.tree-node-row[data-path="AGENTS.md"]').click()
            note = self.wait('#insp-code .binary-note')
            self.assertIn('Cannot open file', note.inner_text())
        finally:
            target.write_text(backup, encoding='utf-8')
        # the app handled the missing file: no uncaught JS anywhere
        self.assert_no_console_errors()

    def test_14_host_header_spoof_rejected(self):
        pg = self.goto()
        self.wait('#overview-body .stat-box')
        resp = pg.request.get(self.harness.base + 'api/overview',
                              headers={'Host': 'evil.com'})
        self.assertEqual(resp.status, 403)
        self.assertIn('error', json.loads(resp.text()))
        self.assert_no_console_errors()


@unittest.skipUnless(PLAYWRIGHT, 'playwright not installed')
class EmptyWorkspaceE2ETest(unittest.TestCase):
    """Scenario: nothing in the workspace. The page must still boot,
    show empty states and never touch a console error."""

    @classmethod
    def setUpClass(cls):
        cls.harness = UiHarness(lambda root: None)

    @classmethod
    def tearDownClass(cls):
        cls.harness.close()

    def setUp(self):
        self.page, self._ctx, self.console_errors = \
            self.harness.open_page()

    def tearDown(self):
        self._ctx.close()

    def test_01_empty_workspace_loads_with_empty_states(self):
        pg = self.page
        pg.goto(self.harness.base)
        # overview still renders the gates table (9 rows, no crash)
        pg.wait_for_selector('#overview-body .tbl tbody tr',
                             timeout=WAIT_MS)
        self.assertEqual(
            pg.locator('#overview-body .tbl tbody tr').count(), 9)
        # tree: explicit empty state, not a blank panel
        pg.click('#tab-tree')
        pg.wait_for_selector('#tree-body .empty-state', timeout=WAIT_MS)
        self.assertIn('Workspace root is empty',
                      pg.inner_text('#tree-body'))
        # findings table: the scan still yields advisory findings
        pg.click('#tab-findings')
        pg.wait_for_selector('.findings-count', timeout=WAIT_MS)
        self.assertEqual(self.console_errors, [],
                         'browser console errors: %r' % self.console_errors)


@unittest.skipUnless(PLAYWRIGHT, 'playwright not installed')
class TreeMapNavigationE2ETest(unittest.TestCase):
    """TreeMap fix: selection stays in the
    TreeMap, double click zooms, keyboard drives the same actions."""

    @classmethod
    def setUpClass(cls):
        cls.harness = UiHarness(build_workspace)

    @classmethod
    def tearDownClass(cls):
        cls.harness.close()

    def setUp(self):
        self.page, self._ctx, self.console_errors = \
            self.harness.open_page()
        self.page.goto(self.harness.base)
        self.page.wait_for_selector('#overview-body .stat-box',
                                    timeout=WAIT_MS)
        self.page.click('#tab-treemap')
        self.page.wait_for_selector('#treemap-body .tm-cell',
                                    timeout=WAIT_MS)

    def tearDown(self):
        self._ctx.close()

    def _cells(self):
        return self.page.query_selector_all('#treemap-body .tm-cell')

    def _dir_cell(self):
        for c in self._cells():
            if c.get_attribute('data-isdir') in ('true', '1'):
                return c
        self.fail('no directory cell rendered')

    # In a nested treemap the parent directory cell's CENTER is
    # covered by its child cells (which is correct squarify layout);
    # the parent's own hit area is its label strip at the top-left.
    CORNER = {'x': 10, 'y': 8}

    def _zoom_level(self):
        """Current treemap zoom level: the trailing crumb is rendered
        as span.crumb-current (buttons are only the ancestors)."""
        return self.page.inner_text('#treemap-crumbs .crumb-current'
                                    ).strip()

    def test_01_click_directory_selects_without_leaving_tab(self):
        cell = self._dir_cell()
        cell.click(position=self.CORNER)
        self.page.wait_for_selector('.tm-cell.selected', timeout=WAIT_MS)
        # still on the treemap panel: the tree panel stays hidden
        hidden = self.page.eval_on_selector(
            '#panel-tree', 'el => el.hidden')
        self.assertTrue(hidden,
                        'single click must not switch to the Tree tab')
        self.assertEqual(self.console_errors, [])

    def test_02_click_file_selects_and_opens_inspector(self):
        for c in self._cells():
            if c.get_attribute('data-isdir') not in ('true', '1'):
                c.click()
                break
        else:
            self.fail('no file cell rendered')
        self.page.wait_for_selector('#inspector:not([hidden])',
                                    timeout=WAIT_MS)
        self.assertEqual(self.console_errors, [])

    def test_03_doubleclick_directory_zooms_in(self):
        cell = self._dir_cell()
        path = cell.get_attribute('data-path')
        cell.dblclick(position=self.CORNER)
        # breadcrumb grows a level for the zoomed directory
        self.page.wait_for_selector(
            '#treemap-crumbs .crumb-current', timeout=WAIT_MS)
        self.assertEqual(self._zoom_level(), Path(path).name)
        self.assertEqual(self.console_errors, [])

    def test_04_enter_zooms_backspace_goes_up(self):
        cell = self._dir_cell()
        path = cell.get_attribute('data-path')
        self.page.eval_on_selector(
            '.tm-cell[data-path="%s"]' % path, 'el => el.focus()')
        self.page.keyboard.press('Enter')
        self.page.wait_for_selector(
            '#treemap-crumbs .crumb-current', timeout=WAIT_MS)
        self.assertEqual(self._zoom_level(), Path(path).name)
        self.page.keyboard.press('Backspace')
        self.assertEqual(self._zoom_level(), 'root')
        self.assertEqual(self.console_errors, [])

    def test_05_breadcrumb_returns_to_level(self):
        cell = self._dir_cell()
        path = cell.get_attribute('data-path')
        cell.dblclick(position=self.CORNER)
        self.page.wait_for_selector(
            '#treemap-crumbs .crumb-current', timeout=WAIT_MS)
        self.assertEqual(self._zoom_level(), Path(path).name)
        # click the root crumb button to come back
        self.page.click('.crumb-btn[data-path=""]')
        self.assertEqual(self._zoom_level(), 'root')
        self.assertEqual(self.console_errors, [])

    def test_06_selection_survives_tab_switch(self):
        cell = self._dir_cell()
        cell.click()
        self.page.wait_for_selector('.tm-cell.selected', timeout=WAIT_MS)
        self.page.click('#tab-findings')
        self.page.wait_for_selector('#panel-findings:not([hidden])',
                                    timeout=WAIT_MS)
        self.page.click('#tab-treemap')
        self.page.wait_for_selector('#treemap-body .tm-cell.selected',
                                    timeout=WAIT_MS)
        self.assertEqual(self.console_errors, [])


@unittest.skipUnless(PLAYWRIGHT, 'playwright not installed')
class UserJourneyE2ETest(unittest.TestCase):
    """The full analyst path as ONE test.
    A journey is stateful by definition — the selection, open inspector
    and fetched findings of step N are the starting point of step N+1,
    so splitting it would test something else entirely.

    The journey deliberately does NOT pin the number of tabs or the
    composition of the Overview panel (sibling work adds blocks there);
    it touches only long-standing anchors: chips, tabs by id, treemap
    cells, the inspector, the findings table and the finding card.
    """

    @classmethod
    def setUpClass(cls):
        cls.harness = UiHarness(build_workspace)

    @classmethod
    def tearDownClass(cls):
        cls.harness.close()

    # The parent directory cell's center is covered by its child cells;
    # its own hit area is the label strip at the top-left (same note as
    # TreeMapNavigationE2ETest).
    CORNER = {'x': 10, 'y': 8}

    def _no_canary(self, page, where):
        html = page.content()
        self.assertNotIn(CANARY, html, 'canary leaked at %s' % where)
        self.assertNotIn(CANARY_TAIL, html,
                         'token tail leaked at %s' % where)

    def test_full_journey_overview_to_rescan(self):
        pg, ctx, errors = self.harness.open_page()
        self.addCleanup(ctx.close)

        # -- 1. open the UI ------------------------------------------
        pg.goto(self.harness.base)
        pg.wait_for_selector('#overview-body .stat-box', timeout=WAIT_MS)

        # -- 2. statistics visible: severity chips carry counts -------
        crit = pg.locator(
            '#severity-chips .chip[title^="Hide Critical"] .chip-count')
        crit_before = int(crit.inner_text())
        self.assertGreater(crit_before, 0)
        findings_before = int(pg.inner_text('#meta-findings .meta-val'))
        self.assertGreater(findings_before, 0)
        self._no_canary(pg, 'overview')

        # -- 3. TreeMap opens with cells -----------------------------
        pg.click('#tab-treemap')
        pg.wait_for_selector('#treemap-body .tm-cell', timeout=WAIT_MS)

        # -- 4. Critical filter is on (default): a cell wears the C
        #       severity corner badge ---------------------------------
        pg.wait_for_selector(
            '#treemap-body .tm-cell .tm-sev-corner.tb-critical',
            timeout=WAIT_MS)
        self._no_canary(pg, 'treemap')

        # -- 5. zoom into the offending directory (corner dblclick ---
        #       the center belongs to nested child cells)
        src_cell = pg.locator(
            '#treemap-body .tm-cell[data-path="src"][data-isdir="true"]')
        self.assertEqual(src_cell.count(), 1)
        src_cell.dblclick(position=self.CORNER)
        pg.wait_for_selector('#treemap-crumbs .crumb-current',
                             timeout=WAIT_MS)
        self.assertEqual(
            pg.inner_text('#treemap-crumbs .crumb-current').strip(), 'src')

        # -- 6. click the file cell -> inspector with masked preview -
        pg.wait_for_selector(
            '#treemap-body .tm-cell[data-path="src/creds.txt"]',
            timeout=WAIT_MS).click()
        pg.wait_for_selector('#inspector:not([hidden])', timeout=WAIT_MS)
        pg.wait_for_selector('#insp-code .code-line', timeout=WAIT_MS)
        self.assertEqual(pg.inner_text('#insp-path').strip(),
                         'src/creds.txt')
        # the inspector badge row announces the critical findings
        self.assertGreater(
            pg.locator('#insp-badges .tree-badge.tb-critical').count(), 0)

        # -- 7. Findings tab -> open the critical secret card ---------
        pg.click('#tab-findings')
        row = pg.wait_for_selector(
            '#findings-body tbody tr.fnd-row[data-severity="critical"]',
            timeout=WAIT_MS)
        fid = row.get_attribute('data-fid')
        self.assertTrue(fid.startswith('SEC-'),
                        'expected a secrets finding, got %s' % fid)
        row.click()
        pg.wait_for_selector('#card-overlay:not([hidden])',
                             timeout=WAIT_MS)
        self.assertEqual(pg.inner_text('#card-fid').strip(), fid)
        pg.wait_for_selector('#card-body .ev-item', timeout=WAIT_MS)
        self._no_canary(pg, 'finding card')

        # -- 8. evidence file:line click -> back to the source file --
        ev = pg.locator('#card-body .ev-link',
                        has_text='creds.txt').first
        ev.click()
        pg.wait_for_selector('#inspector:not([hidden])', timeout=WAIT_MS)
        # the evidence line is highlighted in the reopened inspector
        pg.wait_for_selector('#insp-code .code-line.hl', timeout=WAIT_MS)
        self.assertEqual(pg.inner_text('#insp-path').strip(),
                         'src/creds.txt')

        # -- 9. the preview is masked: mask shown, canary absent ------
        body = pg.inner_text('#insp-code')
        self.assertIn('slack_token', body)
        self.assertIn('xox***', body)
        self._no_canary(pg, 'inspector from evidence')

        # -- 10. Fix plan from the card: dry-run steps or an honest
        #        unsupported explanation ------------------------------
        row = pg.locator(
            '#findings-body tbody tr.fnd-row[data-severity="critical"]'
        ).first
        row.click()
        pg.wait_for_selector('#card-overlay:not([hidden])',
                             timeout=WAIT_MS)
        pg.wait_for_selector('#card-body .ev-item', timeout=WAIT_MS)
        pg.locator('#card-body .fixplan .btn-accent',
                   has_text='Fix plan').click()
        pg.wait_for_function(
            """() => {
                const b = document.getElementById('fix-plan-box');
                return b && (b.querySelector('.dryrun-badge')
                             || b.querySelector('.recommendation')
                             || b.querySelector('.fix-steps'));
            }""", timeout=WAIT_MS)
        plan_txt = pg.inner_text('#fix-plan-box')
        if 'DRY RUN' in plan_txt:
            # supported: planned steps are listed and labelled a dry run
            self.assertGreater(
                pg.locator('#fix-plan-box .fix-steps li').count(), 0)
        else:
            # the fixture's secrets finding: no automatic fix, and the
            # plan says so instead of pretending
            self.assertIn('no supported automatic fix', plan_txt)

        # -- 11. Rescan (button, same-origin POST): the picture
        #         survives, counters refresh, console stays clean -----
        pg.keyboard.press('Escape')  # close the card first
        pg.wait_for_selector('#card-overlay', state='hidden',
                             timeout=WAIT_MS)
        pg.click('#btn-rescan')
        toast = pg.wait_for_selector('#toast:not([hidden])',
                                     timeout=WAIT_MS)
        self.assertIn('Rescan finished', toast.inner_text())
        # step back to Overview and read the refreshed picture
        pg.click('#tab-overview')
        pg.wait_for_selector('#panel-overview:not([hidden])',
                             timeout=WAIT_MS)
        pg.wait_for_selector('#overview-body .stat-box', timeout=WAIT_MS)
        findings_after = int(pg.inner_text('#meta-findings .meta-val'))
        self.assertGreater(findings_after, 0)
        self.assertEqual(findings_after, findings_before,
                         'nothing changed on disk; the counter must not')
        crit_after = int(pg.locator(
            '#severity-chips .chip[title^="Hide Critical"] .chip-count'
        ).inner_text())
        self.assertEqual(crit_after, crit_before)
        self._no_canary(pg, 'after rescan')

        # console gate for the whole journey
        self.assertEqual(errors, [],
                         'browser console errors: %r' % errors)


def _bare_workspace(root: Path) -> None:
    """A workspace with content but no .git and no AGENTS.md: the
    instruction-file and version-control gates have nothing to check."""
    (root / 'README.md').write_text('hello\n', encoding='utf-8')


def _huge_workspace(root: Path) -> None:
    """600 files in one subdirectory: past TREE_PAGE (500) so /api/tree
    paginates and past TREE_DOM_CAP so the tree goes virtualized."""
    big = root / 'bigdir'
    big.mkdir()
    for i in range(1, 601):
        (big / ('f-%04d.txt' % i)).write_text('x\n', encoding='utf-8')


def _locked_workspace(root: Path) -> None:
    """A readable-at-scan-time file the test locks afterwards."""
    sub = root / 'vault'
    sub.mkdir()
    (sub / 'secret.txt').write_text('locked away\n', encoding='utf-8')


@unittest.skipUnless(PLAYWRIGHT, 'playwright not installed')
class ErrorPathsE2ETest(unittest.TestCase):
    """Error and edge scenarios. Each test
    builds its own harness (most need a bespoke server state) and each
    ends with the console gate. The empty workspace and the dead file
    after scan live in MainWorkspaceE2ETest already; not duplicated."""

    def make_harness(self, builder, state_factory=None):
        harness = UiHarness(builder, state_factory=state_factory)
        self.addCleanup(harness.close)
        return harness

    def test_01_workspace_without_git_or_agents(self):
        h = self.make_harness(_bare_workspace)
        pg, ctx, errors = h.open_page()
        self.addCleanup(ctx.close)
        pg.goto(h.base)
        pg.wait_for_selector('#overview-body .tbl tbody tr',
                             timeout=WAIT_MS)
        # UI alive: nine gates, every status glyph drawn
        self.assertEqual(
            pg.locator('#overview-body .tbl tbody tr').count(), 9)
        glyphs = pg.locator('#overview-body .status-badge .st-glyph')
        for i in range(glyphs.count()):
            self.assertNotEqual(glyphs.nth(i).inner_text().strip(), '')
        # gates with nothing to check report n/a, not a crash
        self.assertGreaterEqual(
            pg.locator(
                '#overview-body .status-badge.st-not_applicable').count(),
            1)
        # nothing critical anywhere; the chip says so
        self.assertEqual(int(pg.locator(
            '#severity-chips .chip[title^="Hide Critical"] .chip-count'
        ).inner_text()), 0)
        # tree serves the lone file, preview included
        pg.click('#tab-tree')
        pg.wait_for_selector('.tree-node-row[data-path="README.md"]',
                             timeout=WAIT_MS).click()
        pg.wait_for_selector('#insp-code .code-line', timeout=WAIT_MS)
        self.assertIn('hello', pg.inner_text('#insp-code'))
        # findings table renders with the advisory findings
        pg.click('#tab-findings')
        pg.wait_for_selector('.findings-count', timeout=WAIT_MS)
        shown, total = self._counter(pg)
        self.assertGreater(total, 0)
        self.assertEqual(shown, total)
        self.assertEqual(errors, [],
                         'browser console errors: %r' % errors)

    @staticmethod
    def _counter(pg):
        txt = pg.inner_text('.findings-count')
        m = re.search(r'Showing (\d+) of (\d+) fetched', txt)
        if not m:
            raise AssertionError('counter text unreadable: %r' % txt)
        return int(m.group(1)), int(m.group(2))

    def test_02_huge_directory_paginates_and_virtualizes(self):
        h = self.make_harness(_huge_workspace)
        pg, ctx, errors = h.open_page()
        self.addCleanup(ctx.close)
        pg.goto(h.base)
        pg.click('#tab-tree')
        pg.wait_for_selector('.tree-node-row[data-path="bigdir"]',
                             timeout=WAIT_MS)
        # expand: 500-entry first page + sentinel pushes the visible
        # model past TREE_DOM_CAP -> flat (virtualized) rendering
        pg.locator('.tree-node-row[data-path="bigdir"]').click()
        pg.wait_for_function(
            """() => {
                const el = document.getElementById('tree-count');
                const m = el && el.textContent.match(/shown (\\d+) of (\\d+)/);
                return m && Number(m[2]) > 500;
            }""", timeout=WAIT_MS)
        # jump to the tail: the "+N more" sentinel comes into the
        # window and loads page 2 by itself (exact N not pinned)
        pg.eval_on_selector('#tree-body',
                            'el => el.scrollTop = el.scrollHeight')
        pg.wait_for_function(
            """() => document.querySelector('#tree-body [data-more]')
                   || document.getElementById('tree-count')
                          .textContent.includes('601')""",
            timeout=WAIT_MS)
        sentinel = pg.query_selector('#tree-body [data-more]')
        if sentinel is not None:
            self.assertIn('more', sentinel.inner_text().lower())
            # the sentinel auto-loads; once done it disappears and the
            # shown/total counter covers the whole directory
            pg.wait_for_function(
                "() => !document.querySelector('#tree-body [data-more]')",
                timeout=WAIT_MS)
        pg.wait_for_function(
            """() => {
                const el = document.getElementById('tree-count');
                const m = el.textContent.match(/shown (\\d+) of (\\d+)/);
                return m && Number(m[2]) >= 601;
            }""", timeout=WAIT_MS)
        # click a file from the tail of the fully loaded list
        pg.eval_on_selector('#tree-body',
                            'el => el.scrollTop = el.scrollHeight')
        pg.wait_for_selector(
            '.tree-node-row[data-path="bigdir/f-0600.txt"]',
            timeout=WAIT_MS).click()
        pg.wait_for_selector('#inspector:not([hidden])', timeout=WAIT_MS)
        pg.wait_for_selector('#insp-code .code-line', timeout=WAIT_MS)
        self.assertEqual(pg.inner_text('#insp-path').strip(),
                         'bigdir/f-0600.txt')
        self.assertEqual(errors, [],
                         'browser console errors: %r' % errors)

    def test_03_garbage_report_state_no_crash(self):
        """A report whose findings/gates are garbage (what a corrupted
        scan.json serves): the UI degrades to explicit empty states and
        never throws in the page."""
        def broken_state(root, home):
            rep = audit_scan.scan(root, home, False)
            rep['gates'] = None
            rep['findings_detailed'] = None
            rep['findings'] = None
            rep['stats'] = None
            return srv.UiState(rep, root)
        h = self.make_harness(_bare_workspace, state_factory=broken_state)
        pg, ctx, errors = h.open_page()
        self.addCleanup(ctx.close)
        pg.goto(h.base)
        # overview renders and says there are no gates (explicit empty
        # state, not a blank panel and not an uncaught error)
        pg.wait_for_selector('#overview-body .stat-box', timeout=WAIT_MS)
        self.assertIn('No gates in this scan.',
                      pg.inner_text('#overview-body'))
        self.assertEqual(int(pg.locator(
            '#severity-chips .chip[title^="Hide Critical"] .chip-count'
        ).inner_text()), 0)
        # findings: honest 0 of 0
        pg.click('#tab-findings')
        pg.wait_for_selector('.findings-count', timeout=WAIT_MS)
        self.assertIn('Showing 0 of 0', pg.inner_text('.findings-count'))
        # tree still serves the real directory on disk
        pg.click('#tab-tree')
        pg.wait_for_selector('.tree-node-row[data-path="README.md"]',
                             timeout=WAIT_MS)
        self.assertEqual(errors, [],
                         'browser console errors: %r' % errors)

    @unittest.skipIf(sys.platform.startswith('win'),
                     'POSIX file modes only; Windows has no chmod 000')
    @unittest.skipIf(hasattr(os, 'geteuid') and os.geteuid() == 0,
                     'root reads through mode 000, nothing to test')
    def test_04_unreadable_file_preview_shows_error(self):
        h = self.make_harness(_locked_workspace)
        # lock AFTER the harness scanned, so only the preview path (not
        # the scanner) meets the permission error
        target = h.root / 'vault' / 'secret.txt'
        os.chmod(target, 0)
        self.addCleanup(lambda: os.chmod(target, 0o644))
        pg, ctx, errors = h.open_page()
        self.addCleanup(ctx.close)
        pg.goto(h.base)
        # the tree still opens the parent and lists the file
        pg.click('#tab-tree')
        pg.locator('.tree-node-row[data-path="vault"]').click()
        row = pg.wait_for_selector(
            '.tree-node-row[data-path="vault/secret.txt"]',
            timeout=WAIT_MS)
        row.click()
        # the preview fails with an explicit note, not a page error
        note = pg.wait_for_selector('#insp-code .binary-note',
                                    timeout=WAIT_MS)
        self.assertIn('Cannot open file', note.inner_text())
        self.assertEqual(errors, [],
                         'browser console errors: %r' % errors)

    def test_05_broken_baseline_compare_shows_error(self):
        """A baseline whose findings field is unusable garbage. NB: a
        garbage STRING silently degrades to an empty diff inside
        fingerprint_diff (chars are not dicts), so the test uses a
        non-iterable value — that is what actually reaches the error
        path the Compare tab must handle gracefully."""
        def baseline_state(root, home):
            rep = audit_scan.scan(root, home, False)
            broken = {'generated_at': 'broken-on-purpose',
                      'findings': 12345}
            return srv.UiState(rep, root, baseline=broken)
        h = self.make_harness(_bare_workspace,
                              state_factory=baseline_state)
        pg, ctx, errors = h.open_page()
        self.addCleanup(ctx.close)
        pg.goto(h.base)
        pg.click('#tab-compare')
        box = pg.wait_for_selector('#compare-body .empty-state',
                                   timeout=WAIT_MS)
        text = box.inner_text()
        self.assertIn('Compare is not available', text)
        # the message explains itself instead of showing a blank panel
        self.assertRegex(text, r"'int' object is not iterable")
        self.assertEqual(errors, [],
                         'browser console errors: %r' % errors)

    def test_06_simulate_unknown_harness(self):
        """Pinned behavior (probed on the real server): an unknown
        harness id is NOT a 4xx — /api/simulate answers 200 with an
        empty harnesses map and zero loaded sources. The UI select only
        offers known harnesses, so the check drives the request API
        directly."""
        h = self.make_harness(lambda root: None)
        pg, ctx, errors = h.open_page()
        self.addCleanup(ctx.close)
        pg.goto(h.base)
        pg.wait_for_selector('#overview-body .stat-box', timeout=WAIT_MS)
        resp = pg.request.get(h.base + 'api/simulate?harness=nonexistent')
        self.assertEqual(resp.status, 200)
        body = json.loads(resp.text())
        self.assertNotIn('error', body)
        self.assertEqual(body.get('harnesses'), {})
        self.assertEqual(body.get('loaded_sources_total'), 0)
        self.assertEqual(errors, [],
                         'browser console errors: %r' % errors)

    def test_07_secrets_absent_from_dom_on_every_tab(self):
        """Whole-DOM sweep across every tab of the fixture workspace,
        with the secrets file previewed and its finding card open: the
        canary and its token tail must never appear anywhere."""
        h = self.make_harness(build_workspace)
        pg, ctx, errors = h.open_page()
        self.addCleanup(ctx.close)
        pg.goto(h.base)
        pg.wait_for_selector('#overview-body .stat-box', timeout=WAIT_MS)
        self._assert_no_secrets(pg)
        # tree with the secrets file open in the inspector
        pg.click('#tab-tree')
        pg.locator('.tree-node-row[data-path="src"]').click()
        pg.wait_for_selector('.tree-node-row[data-path="src/creds.txt"]',
                             timeout=WAIT_MS).click()
        pg.wait_for_selector('#insp-code .code-line.flagged',
                             timeout=WAIT_MS)
        self._assert_no_secrets(pg)
        # treemap (tooltips carry counts, never values)
        pg.click('#tab-treemap')
        pg.wait_for_selector('#treemap-body .tm-cell', timeout=WAIT_MS)
        self._assert_no_secrets(pg)
        # instructions (loaded-source paths)
        pg.click('#tab-instructions')
        pg.wait_for_selector(
            '#instructions-body table.tbl, '
            '#instructions-body .empty-state', timeout=WAIT_MS)
        self._assert_no_secrets(pg)
        # findings with the critical card open, raw evidence included
        pg.click('#tab-findings')
        pg.wait_for_selector('#findings-body tbody tr.fnd-row',
                             timeout=WAIT_MS)
        pg.locator(
            '#findings-body tr.fnd-row[data-severity="critical"]'
        ).first.click()
        pg.wait_for_selector('#card-body .ev-item', timeout=WAIT_MS)
        pg.locator('#card-body details.ev-json summary').click()
        self._assert_no_secrets(pg)
        pg.keyboard.press('Escape')
        # simulate and compare
        pg.click('#tab-simulate')
        pg.wait_for_selector('#sim-harness option[value="zcode"]',
                             state='attached', timeout=WAIT_MS)
        pg.select_option('#sim-harness', 'zcode')
        pg.click('#sim-run')
        pg.wait_for_selector('#simulate-body .sim-harness-block',
                             timeout=WAIT_MS)
        self._assert_no_secrets(pg)
        pg.click('#tab-compare')
        pg.wait_for_selector('#compare-body .empty-state', timeout=WAIT_MS)
        self._assert_no_secrets(pg)
        self.assertEqual(errors, [],
                         'browser console errors: %r' % errors)

    def _assert_no_secrets(self, pg):
        html = pg.content()
        self.assertNotIn(CANARY, html)
        self.assertNotIn(CANARY_TAIL, html)


if __name__ == '__main__':
    unittest.main()
