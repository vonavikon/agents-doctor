# Browser E2E tests

`test_ui_e2e.py` drives the real agents-doctor web UI (ui/server.py +
ui/static) in a headless Chromium through Playwright's sync API, on top
of the repo's unittest runner. No pytest, no extra runner.

## Running locally

```bash
pip install -r requirements-dev.txt      # pulls playwright
python -m playwright install chromium    # once per machine
python -m unittest tests.e2e.test_ui_e2e -v
```

Everything else stays untouched: the full suite
`python -m unittest discover -s tests` picks this directory up too.

## Why tests skip without playwright

The module imports playwright inside a try/except; when the import
fails, both test classes carry `@unittest.skipUnless(PLAYWRIGHT,
'playwright not installed')` and every test reports as skipped in
milliseconds. The class fixtures (temp workspace, scan, HTTP server,
browser) live in `setUpClass`, and unittest does not run `setUpClass`
for a skipped class — so a machine without playwright pays nothing,
and CI jobs that never asked for browser tests stay green.

## What is covered

Fixture: a temp workspace with dead links in AGENTS.md, a
`.claude/settings.json` allowing `Bash(*)`, a secrets file with a
canary token (assembled from pieces in the test source so the repo
itself never contains the whole value) and a nested `src/` folder.

| # | Scenario |
|---|----------|
| 01 | Page boots: title, topbar root path, 7 tabs |
| 02 | Overview: severity chips with counts, 9 gate rows, status glyphs |
| 03 | Severity chip click toggles aria-pressed |
| 04 | Findings table loads; gate filter (G6 row click) shrinks the counter |
| 05 | Search box filters findings after the debounce |
| 06 | Finding card opens on row click (fid, severity, evidence), Esc closes |
| 07 | Tree lazy-expands; file click opens the Inspector; masked token shown, raw canary absent |
| 08 | Flagged lines highlighted with the rule label (SEC-106) |
| 09 | Whole-DOM sweep: the canary token never appears in page.content() |
| 10 | Simulate tab: harness zcode + Run renders loaded sources |
| 11 | Compare without baseline: actionable empty state, no console errors |
| 12 | Rescan POST: the page's own same-origin request, plus the `X-Agents-Doctor: local` header path |
| 13 | Deleted file: preview shows the error panel, no uncaught JS |
| 14 | Host-header spoof (`Host: evil.com`) via page.request gets 403 |
| 15 | Empty workspace: page boots, empty states visible, no console errors |

Every test ends by asserting the page produced no console errors and
no unhandled page errors. The allowlist is empty by default; extend it
only for browser artifacts, never to silence an app bug.

The table lists `MainWorkspaceE2ETest` and `EmptyWorkspaceE2ETest`.
TreeMap navigation (`TreeMapNavigationE2ETest`), the full analyst path
(`UserJourneyE2ETest`) and the error and edge scenarios
(`ErrorPathsE2ETest`) have their own classes in the same module.

## How the harness works

`UiHarness` (in the test module) is the per-class fixture: it builds
the temp workspace, runs `audit_scan.scan` in-process, serves
`ui/server.py` on an ephemeral 127.0.0.1 port in a daemon thread, and
launches one Chromium per test class. Each test gets a fresh browser
context with console/pageerror listeners wired in `open_page()`.

## Adding a scenario

1. Add a `test_NN_*` method to `MainWorkspaceE2ETest` (numbering keeps
   the alphabetical run order readable). Use `self.goto()`,
   `self.open_tab('findings')`, `self.wait(selector)` helpers.
2. End the test with `self.assert_no_console_errors()`.
3. Wait for concrete post-fetch DOM (a row, a badge), never for a
   spin cycle: the SPA fetches after tab switches, so waiting for the
   tab panel alone races the API.
4. `<option>` elements have no visibility box — wait with
   `state='attached'` before `select_option`.
5. If the scenario needs a different kind of workspace, give it its
   own small test class with its own `UiHarness` (see
   `EmptyWorkspaceE2ETest`).

## CI

The `ui-e2e` job in `.github/workflows/ci.yml` is the only job that
installs playwright and the chromium binary; everywhere else the
module self-skips.
