/* agents-doctor — Visual Workspace Explorer.
   Vanilla JS, zero dependencies, fully offline. Served by ui/server.py;
   see the API contract in that file's docstring.

   Scale features for large workspaces: virtualized tree window,
   cursor pagination with "+N more…" sentinels, whole-workspace search,
   exact directory sizes for the Disk metric via /api/tree/stats, tree
   sorting by name/size/problems. All new endpoints are optional: when
   /api/tree answers without cursor keys the UI stays on the old
   single-chunk behavior and never calls the new endpoints. */
(() => {
'use strict';

/* ---------------------------------------------------------------- helpers */

const $ = (id) => document.getElementById(id);
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const SEV_CAP = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' };
const SEV_LETTER = { critical: 'C', high: 'H', medium: 'M', low: 'L', info: 'I' };
const SEV_WEIGHT = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
const SEV_VAR = {
  critical: '--sev-critical', high: '--sev-high', medium: '--sev-medium',
  low: '--sev-low', info: '--sev-info',
};
const STATUS_GLYPH = { pass: '\u2713', fail: '\u2715', warn: '\u26a0', unknown: '?', not_applicable: '\u2014' };
const STATUS_LABEL = { pass: 'pass', fail: 'fail', warn: 'warn', unknown: 'unknown', not_applicable: 'n/a' };
const STATUS_RANK = { fail: 0, warn: 1, unknown: 2, not_applicable: 3, pass: 4 };

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined || v === false) continue;
    if (k === 'class') node.className = v;
    else if (k === 'text') node.textContent = v;
    else if (k === 'html') node.innerHTML = v;           // trusted, built here only
    else if (k.startsWith('on') && typeof v === 'function') node.addEventListener(k.slice(2), v);
    else if (v === true) node.setAttribute(k, '');
    else node.setAttribute(k, String(v));
  }
  for (const c of children) {
    if (c === null || c === undefined) continue;
    node.append(c);
  }
  return node;
}

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

let toastTimer = null;
function toast(msg) {
  const t = $('toast');
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.hidden = true; }, 4500);
}

async function api(path, params = {}, method = 'GET') {
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== null && v !== undefined && v !== '') qs.set(k, v);
  }
  const url = path + (qs.toString() ? '?' + qs.toString() : '');
  let resp;
  try {
    resp = await fetch(url, method === 'POST' ? { method } : undefined);
  } catch (e) {
    throw new Error('network error: ' + e.message);
  }
  let body = null;
  try { body = await resp.json(); } catch { /* non-JSON below */ }
  if (!resp.ok) {
    const msg = body && body.error ? body.error : resp.status + ' ' + resp.statusText;
    throw new Error(msg);
  }
  if (body && body.error) throw new Error(body.error);
  return body;
}

const loadingHTML = (what) =>
  `<div class="loading"><span class="spinner" aria-hidden="true"></span> ${esc(what)}</div>`;
const emptyHTML = (msg) =>
  `<div class="empty-state"><span class="empty-glyph" aria-hidden="true">[ ]</span>${esc(msg)}</div>`;

function errorPanel(err, retryFn) {
  const box = el('div', { class: 'error-panel' });
  box.append(
    el('h3', { text: 'Failed to load' }),
    el('p', { text: String(err && err.message ? err.message : err) }),
    el('button', { class: 'btn-accent', onclick: retryFn, text: 'Retry' }),
  );
  return box;
}

function sevBadge(sev) {
  return el('span', { class: 'sev-badge sev-' + sev, title: 'severity: ' + sev, text: SEV_CAP[sev] || sev });
}

function statusBadge(st) {
  const known = st in STATUS_GLYPH;
  return el('span', {
    class: 'status-badge st-' + st,
    title: 'status: ' + st,
    html: `<span class="st-glyph" aria-hidden="true">${known ? STATUS_GLYPH[st] : '?'}</span>` +
          `<span>${known ? STATUS_LABEL[st] : esc(st)}</span>`,
  });
}

function countsFiltered(counts) {
  const out = {};
  for (const s of SEVERITIES) out[s] = state.sev.has(s) ? (counts[s] || 0) : 0;
  return out;
}
const countsTotal = (c) => SEVERITIES.reduce((sum, s) => sum + (c[s] || 0), 0);
const countsRisk = (c) => SEVERITIES.reduce((sum, s) => sum + SEV_WEIGHT[s] * (c[s] || 0), 0);

function badgeRowFromCounts(counts) {
  const row = el('span', { class: 'badge-row' });
  const c = countsFiltered(counts);
  for (const s of SEVERITIES) {
    if ((c[s] || 0) > 0) {
      row.append(el('span', {
        class: 'tree-badge tb-' + s,
        title: s + ': ' + c[s] + ' (filtered view)',
        text: SEV_LETTER[s] + ' ' + c[s],
      }));
    }
  }
  return row;
}

function dirname(p) {
  const i = p.lastIndexOf('/');
  return i <= 0 ? (i === 0 ? '/' : '') : p.slice(0, i);
}

/* ------------------------------------------------------------------ state */

const state = {
  tab: 'overview',
  overview: null,
  harnesses: null,
  sev: new Set(SEVERITIES),     // global severity filter
  showPassed: false,
  findings: {
    fetched: [], gate: '', harness: '', q: '',
    sortKey: 'severity', sortDir: 'desc', group: false,
    loadedOnce: false,
  },
  tree: {
    cache: new Map(),           // rel -> {children, nextCursor, totalEntries, complete, truncated, loading, loadingMore, error}
    expanded: new Set(),
    filter: '', sort: 'name',
    loadedOnce: false, focusedPath: null, seq: 0, currentDir: '',
    pagedApi: false,            // true once /api/tree answers with cursor/complete keys
    flat: false, flatRows: null, focusIdx: null,
    searchResults: null,
  },
  treemap: {
    metric: 'density', zoom: '', loadedOnce: false, nodes: new Map(), resizing: false,
    selected: null,   // path of the selected cell; survives zoom and tab switches
    stats: new Map(),           // path -> {totalBytes, totalFiles, problemBytes, share, complete}
    statsPending: new Map(),    // path -> promise, while /api/tree/stats is in flight
    statsGen: 0,                // bumped by rescan; stale responses drop themselves
  },
  simulate: { result: null, harness: '' },
  instructions: null,
  compare: null,
  score: null,                 // /api/score cache (null until fetched)
  hist: { data: null, trend: null, sel: [], diff: null },  // History tab
  inspector: { path: null, line: null },
  history: { stack: [], idx: -1 },
};

/* ------------------------------------------------------------------ chips */

function renderChips() {
  const box = $('severity-chips');
  box.textContent = '';
  const ov = state.overview || {};
  const sevCounts = ov.severity_counts || {};
  const passCount = (ov.status_counts || {}).pass || 0;

  const make = (key, label, count, colorVar, pressed, onClick) => {
    const chip = el('button', {
      class: 'chip', role: 'button', 'aria-pressed': String(pressed),
      title: pressed ? 'Hide ' + label + ' findings' : 'Show ' + label + ' findings',
      onclick: onClick,
    });
    chip.append(
      el('span', { class: 'chip-dot', 'aria-hidden': 'true' }),
      el('span', { text: label }),
      el('span', { class: 'chip-count', text: String(count) }),
    );
    chip.style.setProperty('--chip-color', `var(${colorVar})`);
    return chip;
  };

  for (const s of SEVERITIES) {
    box.append(make(s, SEV_CAP[s], sevCounts[s] || 0, SEV_VAR[s], state.sev.has(s), () => {
      if (state.sev.has(s)) state.sev.delete(s); else state.sev.add(s);
      onGlobalFilterChange();
    }));
  }
  box.append(make('passed', 'Passed', passCount, '--pass', state.showPassed, () => {
    state.showPassed = !state.showPassed;
    onGlobalFilterChange();
  }));
}

function onGlobalFilterChange() {
  renderChips();
  if (state.findings.loadedOnce) renderFindings();
  if (state.tree.loadedOnce) renderTree();
  if (state.treemap.loadedOnce) renderTreemap();
}

/* ------------------------------------------------------------------- tabs */

const TABS = ['overview', 'tree', 'treemap', 'instructions', 'findings', 'simulate', 'compare', 'history'];
const initedTabs = new Set();

function switchTab(name) {
  if (!TABS.includes(name)) return;
  state.tab = name;
  for (const t of TABS) {
    $('tab-' + t).setAttribute('aria-selected', String(t === name));
    $('panel-' + t).hidden = t !== name;
  }
  if (!initedTabs.has(name)) {
    initedTabs.add(name);
    if (name === 'overview') loadOverview();
    if (name === 'tree') initTree();
    if (name === 'treemap') initTreemap();
    if (name === 'instructions') initInstructions();
    if (name === 'findings') initFindings();
    if (name === 'simulate') initSimulate();
    if (name === 'compare') initCompare();
    if (name === 'history') initHistoryTab();
  }
}

/* --------------------------------------------------------------- overview */

async function loadOverview() {
  const body = $('overview-body');
  body.innerHTML = loadingHTML('Loading overview…');
  try {
    state.overview = await api('/api/overview');
    renderMeta();
    renderChips();
    renderOverview();
    loadScoreBlock();   // async: fills #ov-score when /api/score answers
    loadEnvSummary();   // async: fills #ov-env from /api/harnesses
  } catch (e) {
    body.textContent = '';
    body.append(errorPanel(e, loadOverview));
  }
}

function renderMeta() {
  const ov = state.overview || {};
  $('meta-root').querySelector('.meta-val').textContent = ov.root || '?';
  $('meta-date').querySelector('.meta-val').textContent = ov.generated_at || '?';
  $('meta-rules').querySelector('.meta-val').textContent = ov.rules_version || '?';
  $('meta-findings').querySelector('.meta-val').textContent =
    ov.findings_total != null ? ov.findings_total : '?';
}

function renderOverview() {
  const ov = state.overview;
  const body = $('overview-body');
  body.textContent = '';

  const sevCounts = ov.severity_counts || {};
  const statusCounts = ov.status_counts || {};
  const boxes = el('div', { class: 'ov-stats' });
  const addBox = (key, val) => boxes.append(
    el('div', { class: 'stat-box' }, el('div', { class: 'stat-key', text: key }),
      el('div', { class: 'stat-val', text: String(val) })));
  addBox('findings', ov.findings_total);
  addBox('critical', sevCounts.critical || 0);
  addBox('high', sevCounts.high || 0);
  const gates = ov.gates || [];
  addBox('gates pass', gates.filter((g) => g.status === 'pass').length);
  addBox('gates fail', gates.filter((g) => g.status === 'fail').length);
  addBox('gates warn', gates.filter((g) => g.status === 'warn').length);
  body.append(boxes);

  // Governance dashboard blocks: health score and
  // detected environments. Containers are filled synchronously from the
  // caches when present; the async loaders overwrite them on answer.
  body.append(el('div', { id: 'ov-score' }));
  body.append(el('div', { id: 'ov-env' }));
  renderScoreBlock();
  renderEnvSummary();

  const stLine = el('p', { class: 'conf-note' });
  const parts = [];
  for (const st of ['pass', 'fail', 'warn', 'unknown', 'not_applicable']) {
    parts.push(`${STATUS_GLYPH[st]} ${STATUS_LABEL[st]} ${statusCounts[st] || 0}`);
  }
  stLine.textContent = 'Finding statuses: ' + parts.join('   ·   ');
  body.append(stLine);

  body.append(el('div', { class: 'ov-section-title', text: 'Gates' }));
  if (!gates.length) {
    body.append(el('div', { class: 'empty-state', text: 'No gates in this scan.' }));
    return;
  }
  const table = el('table', { class: 'tbl', ariaLabel: 'Gates' });
  const thead = el('thead', {}, el('tr', {},
    el('th', { text: 'gid' }), el('th', { text: 'Gate' }),
    el('th', { text: 'Status' }), el('th', { class: 'num', text: 'Confidence' })));
  const tbody = el('tbody');
  for (const g of gates) {
    const tr = el('tr', {
      class: 'row-click',
      title: 'Show findings of gate ' + g.gid,
      onclick: () => {
        state.findings.gate = g.gid || '';
        $('fnd-gate').value = state.findings.gate;
        switchTab('findings');
        if (state.findings.loadedOnce) loadFindings();
      },
    });
    tr.append(
      el('td', { class: 'mono', text: g.gid || '?' }),
      el('td', { text: g.name || '' }),
      el('td', {}, statusBadge(g.status)),
      el('td', { class: 'num', text: g.confidence != null ? Number(g.confidence).toFixed(2) : '—' }),
    );
    tbody.append(tr);
  }
  table.append(thead, tbody);
  body.append(table);
}

/* ------------------------------------------------------------- harnesses */

/* option lists are built by ensureHarnessOptions / fillHarnessSelect
   in the "path + api raw helpers" section below */

/* ------------------------------------------------------------------- tree */

/* Scale model.
   - loadDir() speaks the paged contract (cursor/complete/total_entries)
     and degrades to the old single-chunk response transparently: no
     cursor keys -> complete listing, no sentinels, exactly the old flow.
   - Below TREE_DOM_CAP visible rows the tree renders nested DOM as
     before, with incremental expand/collapse (patchDirNode patches one
     subtree in place, scroll position untouched). Above the cap the
     visible tree is flattened into a virtual list: absolutely
     positioned rows, only the viewport window (+overscan) in the DOM.
   - Directories with an unresolved next_cursor end with a "+N more…"
     sentinel row; IntersectionObserver (nested) or the window render
     (flat) fetches the next page when it comes near the viewport.
   - The page cache is an LRU capped at TREE_LRU_CAP directories;
     the root, expanded chains and the treemap zoom chain stay pinned. */

const TREE_ROW_H = 22;        // fixed row height in flat (virtualized) mode
const TREE_OVERSCAN = 10;     // rows rendered above/below the viewport
const TREE_DOM_CAP = 500;     // live .tree-node-row limit -> go virtual
const TREE_FLAT_EXIT = 420;   // hysteresis: leave flat mode below this
const TREE_LRU_CAP = 50;      // cached directory listings

async function loadDir(rel) {
  const entry = state.tree.cache.get(rel);
  if (entry && (entry.children || entry.error)) {
    cacheTouch(rel);
    return entry;
  }
  state.tree.cache.set(rel, { loading: true });
  try {
    const data = await api('/api/tree', { path: rel, sort: state.tree.sort });
    if (data.next_cursor !== undefined || data.complete !== undefined) {
      state.tree.pagedApi = true;    // new backend: stats + search exist too
    }
    const e = {
      children: data.children || [],
      truncated: !!data.truncated,
      nextCursor: data.next_cursor !== undefined ? data.next_cursor : null,
      totalEntries: data.total_entries != null ? Number(data.total_entries) : null,
      complete: data.complete !== undefined ? !!data.complete : !data.truncated,
    };
    state.tree.cache.set(rel, e);
    cacheEvict();
    return e;
  } catch (err) {
    const e = { error: err.message };
    state.tree.cache.set(rel, e);
    return e;
  }
}

/* Simple LRU over the page cache: Map insertion order is recency. */
function cacheTouch(rel) {
  const cache = state.tree.cache;
  if (!cache.has(rel)) return;
  const v = cache.get(rel);
  cache.delete(rel);
  cache.set(rel, v);
}
function cacheEvict() {
  const cache = state.tree.cache;
  if (cache.size <= TREE_LRU_CAP) return;
  const pinned = new Set(['']);
  const addChain = (p) => {
    if (!p) return;
    let cur = '';
    for (const seg of p.split('/').filter(Boolean)) {
      cur = cur ? cur + '/' + seg : seg;
      pinned.add(cur);
    }
  };
  for (const p of state.tree.expanded) addChain(p);
  addChain(state.tree.currentDir);
  addChain(state.treemap.zoom);
  for (const key of Array.from(cache.keys())) {
    if (cache.size <= TREE_LRU_CAP) break;
    if (key === '' || pinned.has(key)) continue;
    cache.delete(key);
  }
}

async function initTree() {
  await loadDir('');
  state.tree.loadedOnce = true;
  renderTree();
}

function nodeActiveTotal(child) {
  const c = countsFiltered(child.counts || {});
  return countsTotal(c);
}

function cmpName(a, b) {
  const x = a.name.toLowerCase(), y = b.name.toLowerCase();
  return x < y ? -1 : x > y ? 1 : 0;
}
function sortByName(a, b) {
  if (a.is_dir !== b.is_dir) return a.is_dir ? -1 : 1;
  return cmpName(a, b);
}

/* Client-side mirror of the server sort (the sort param is sent on every
   /api/tree call so pages arrive consistently ordered; already loaded
   pages are re-sorted here). Mirrors api_tree(): size = files by size
   desc, then dirs by name; problems adds a dirs-first tiebreak. The
   problems axis counts only severities enabled in the chips — the
   filtered view is the point of the client-side count. */
function sortChildren(children) {
  if (state.tree.sort === 'problems') {
    return children.slice().sort((a, b) =>
      (nodeActiveTotal(b) - nodeActiveTotal(a)) ||
      (a.is_dir === b.is_dir ? cmpName(a, b) : (a.is_dir ? -1 : 1)));
  }
  if (state.tree.sort === 'size') {
    return children.slice().sort((a, b) => {
      if (a.is_dir !== b.is_dir) return a.is_dir ? 1 : -1;
      if (!a.is_dir) {
        const sa = a.size != null ? a.size : -1;
        const sb = b.size != null ? b.size : -1;
        if (sb !== sa) return sb - sa;
      }
      return cmpName(a, b);
    });
  }
  return children.slice().sort(sortByName);
}

function childMatchesFilter(child) {
  const f = state.tree.filter.toLowerCase();
  if (!f) return true;
  if (child.name.toLowerCase().includes(f)) return true;
  if (child.is_dir) {
    const e = state.tree.cache.get(child.path);
    if (e && e.children) return e.children.some((c) => childMatchesFilter(c));
  }
  return false;
}

/* Flat model of everything currently visible: node rows plus "+N more…"
   sentinels and truncation notes as marker rows. Drives both the DOM
   cap decision and the flat (virtualized) renderer. */
function computeRowModel() {
  const rows = [];
  const walk = (children, depth) => {
    for (const child of sortChildren(children)) {
      if (state.tree.filter && !childMatchesFilter(child)) continue;
      rows.push({ child, depth });
      if (child.is_dir && state.tree.expanded.has(child.path)) {
        const entry = state.tree.cache.get(child.path);
        if (entry && entry.children) {
          walk(entry.children, depth + 1);
          appendDirTail(rows, entry, child.path, depth + 1);
        }
      }
    }
  };
  const root = state.tree.cache.get('');
  if (root && root.children) {
    walk(root.children, 0);
    appendDirTail(rows, root, '', 0);
  }
  return rows;
}

function appendDirTail(rows, entry, path, depth) {
  if (entry.nextCursor) rows.push({ more: path, entry, depth });
  else if (!entry.complete) rows.push({ truncNote: true, depth });
}

function updateTreeCount(shown, total) {
  const c = $('tree-count');
  if (c) c.textContent = total > 0 ? `shown ${shown} of ${total}` : '';
}

function updateTreeCountAll() {
  const rows = computeRowModel();
  updateTreeCount(rows.length, rows.length);
}

function renderTree() {
  const body = $('tree-body');
  const rows = computeRowModel();
  const goFlat = rows.length > TREE_DOM_CAP ||
    (state.tree.flat && rows.length > TREE_FLAT_EXIT);
  if (goFlat) {
    state.tree.flat = true;
    renderTreeFlat(rows);
    return;
  }
  state.tree.flat = false;
  state.tree.flatRows = null;
  const rootEntry = state.tree.cache.get('');
  body.textContent = '';
  if (!rootEntry || !rootEntry.children) {
    if (rootEntry && rootEntry.error) {
      body.append(errorPanel(new Error(rootEntry.error), async () => {
        state.tree.cache.delete('');
        await initTree();
      }));
      return;
    }
    body.innerHTML = loadingHTML('Loading tree…');
    return;
  }
  if (!rows.length) {
    body.innerHTML = emptyHTML(state.tree.filter
      ? 'No visible nodes match the name filter.'
      : 'Workspace root is empty.');
    updateTreeCount(0, 0);
    return;
  }
  const frag = document.createDocumentFragment();
  buildChildren(frag, rootEntry.children, 0);
  body.append(frag);
  if (rootEntry.nextCursor) {
    body.append(moreRowEl('', rootEntry, 0));
  } else if (!rootEntry.complete) {
    body.append(el('div', {
      class: 'tree-truncated',
      text: 'listing truncated: directory has more entries on disk',
    }));
  }
  observeMoreRows(body);
  updateTreeCount(rows.length, rows.length);
  restoreTreeFocus();
}

function buildChildren(container, children, depth) {
  for (const child of sortChildren(children)) {
    if (state.tree.filter && !childMatchesFilter(child)) continue;
    container.append(buildNode(child, depth));
  }
}

function buildNode(child, depth) {
  const wrap = el('div', { class: 'tree-branch', 'data-path': child.path });
  wrap.append(buildRowEl(child, depth));
  if (child.is_dir && state.tree.expanded.has(child.path)) {
    wrap.append(childrenContainerFor(child.path, depth));
  }
  return wrap;
}

/* The row markup, shared by the nested renderer (rows inside
   .tree-branch wrappers) and the flat virtualized renderer. */
function buildRowEl(child, depth) {
  const expanded = state.tree.expanded.has(child.path);
  const active = countsFiltered(child.counts || {});
  const total = countsTotal(active);
  const row = el('div', {
    class: 'tree-node-row' + (total > 0 ? ' has-problems' : '') +
      (total > 0 && !child.is_dir ? ' is-flagged' : '') +
      (state.tree.filter && !child.name.toLowerCase().includes(state.tree.filter.toLowerCase()) ? ' is-dimmed' : ''),
    role: 'treeitem',
    'data-path': child.path,
    'data-isdir': String(!!child.is_dir),
    'data-depth': String(depth),
    tabindex: '-1',
    id: 'tn-' + (state.tree.seq++),
    'aria-expanded': child.is_dir ? String(expanded) : null,
    'aria-selected': 'false',
  });
  row.append(
    el('span', { class: 'tree-twister', 'aria-hidden': 'true', text: child.is_dir ? (expanded ? '\u25be' : '\u25b8') : '' }),
    el('span', { class: 'tree-icon', 'aria-hidden': 'true', text: child.is_dir ? 'dir' : 'file' }),
  );
  const nameSpan = el('span', { class: 'tree-name', text: child.name });
  row.append(nameSpan);
  if (child.symlink) {
    row.append(el('span', { class: 'tree-symlink', title: 'symbolic link', text: 'symlink \u21aa' }));
  }
  if (total > 0) row.append(badgeRowFromCounts(child.counts));

  row.addEventListener('click', () => {
    setTreeFocus(row);
    if (child.is_dir) toggleDir(child.path);
    else openInspector(child.path, null, { push: true });
  });
  return row;
}

function childrenContainerFor(path, depth) {
  const kids = el('div', { class: 'tree-children', role: 'group' });
  fillChildrenContainer(kids, path, depth);
  return kids;
}

/* (Re)builds one directory's child list: rows, then the pagination
   sentinel or the truncation note. Called on expand, retry and after
   every appended page — never rebuilds anything above this container. */
function fillChildrenContainer(kids, path, depth) {
  kids.textContent = '';
  const entry = state.tree.cache.get(path);
  if (!entry || entry.loading) {
    kids.append(el('div', { class: 'tree-truncated', text: 'loading…' }));
    return;
  }
  if (entry.error) {
    kids.append(dirErrorRow(path));
    return;
  }
  if (!entry.children.length) {
    kids.append(el('div', { class: 'tree-truncated', text: '(empty)' }));
    return;
  }
  buildChildren(kids, entry.children, depth + 1);
  if (entry.nextCursor) kids.append(moreRowEl(path, entry, depth + 1));
  else if (!entry.complete) {
    kids.append(el('div', {
      class: 'tree-truncated',
      text: 'listing truncated: directory has more entries on disk',
    }));
  }
}

function dirErrorRow(path) {
  const entry = state.tree.cache.get(path) || {};
  const errRow = el('div', { class: 'tree-truncated' });
  errRow.append(el('span', { text: 'error: ' + (entry.error || 'load failed') + ' ' }));
  errRow.append(el('button', {
    class: 'ev-link', text: 'retry',
    onclick: async (ev2) => {
      ev2.stopPropagation();
      state.tree.cache.delete(path);
      if (state.tree.expanded.has(path)) {
        patchDirNode(path);
        await loadDir(path);
        patchDirNode(path);
      }
    },
  }));
  return errRow;
}

/* "+N more…" sentinel for cursor pagination. Click or scroll-near (see
   observeMoreRows / the flat window render) fetches the next page. */
function moreRowEl(dirPath, entry, depth) {
  const remaining = entry.totalEntries != null
    ? Math.max(0, entry.totalEntries - entry.children.length)
    : null;
  const row = el('div', {
    class: 'tree-more-row',
    role: 'button',
    tabindex: '0',
    'data-more': dirPath,
    title: 'load the next page of entries',
  });
  row.style.display = 'flex';
  row.style.alignItems = 'center';
  row.style.cursor = 'pointer';
  row.style.paddingLeft = (depth * 16 + 22) + 'px';
  row.append(el('span', {
    class: 'tree-truncated',
    text: entry.loadingMore ? 'loading more…'
      : remaining != null ? `+${remaining} more…` : '+ more…',
  }));
  row.addEventListener('click', () => loadMore(dirPath));
  row.addEventListener('keydown', (ev) => {
    if (ev.key === 'Enter') { ev.preventDefault(); loadMore(dirPath); }
  });
  return row;
}

async function loadMore(dir) {
  const entry = state.tree.cache.get(dir);
  if (!entry || !entry.children || entry.loadingMore || !entry.nextCursor) return;
  entry.loadingMore = true;
  refreshMoreRows(dir);
  try {
    const data = await api('/api/tree', { path: dir, cursor: entry.nextCursor, sort: state.tree.sort });
    const seen = new Set(entry.children.map((c) => c.path));
    for (const c of data.children || []) {
      if (!seen.has(c.path)) {
        entry.children.push(c);
        seen.add(c.path);
      }
    }
    entry.nextCursor = data.next_cursor !== undefined ? data.next_cursor : null;
    if (data.total_entries != null) entry.totalEntries = Number(data.total_entries);
    if (data.complete !== undefined) entry.complete = !!data.complete;
  } catch (err) {
    toast('Failed to load more entries: ' + err.message);
  } finally {
    entry.loadingMore = false;
    cacheTouch(dir);
    afterChildrenChanged(dir);
  }
}

function refreshMoreRows(dir) {
  const entry = state.tree.cache.get(dir);
  for (const m of $('tree-body').querySelectorAll('[data-more="' + CSS.escape(dir) + '"]')) {
    const span = m.querySelector('.tree-truncated');
    if (span && entry) {
      span.textContent = entry.loadingMore ? 'loading more…' : '+ more…';
    }
  }
}

function afterChildrenChanged(dir) {
  if (dir === '' || state.tree.flat || computeRowModel().length > TREE_DOM_CAP) {
    renderTree();
    return;
  }
  const body = $('tree-body');
  const wrap = body.querySelector('.tree-branch[data-path="' + CSS.escape(dir) + '"]');
  if (!wrap) {
    updateTreeCountAll();
    return;
  }
  const kids = wrap.querySelector(':scope > .tree-children');
  if (kids) {
    const row = wrap.querySelector(':scope > .tree-node-row');
    fillChildrenContainer(kids, dir, Number(row && row.dataset ? row.dataset.depth : 0) || 0);
  }
  observeMoreRows(body);
  updateTreeCountAll();
}

async function toggleDir(path) {
  state.tree.currentDir = path;
  renderSimTargetChips();
  const collapsing = state.tree.expanded.has(path);
  if (collapsing) state.tree.expanded.delete(path);
  else state.tree.expanded.add(path);
  const entry = state.tree.cache.get(path);
  const needLoad = !collapsing && (!entry || (!entry.children && !entry.loading && !entry.error));
  patchDirNode(path);
  if (needLoad) {
    await loadDir(path);
    patchDirNode(path);
  }
}

/* Expand/collapse patches the one affected subtree in place; the rest of
   the DOM and the scroll position stay untouched. Falls back to a full
   re-render when flat mode engages or the row is not in the DOM
   (filtered out, or the parent chain is collapsed). */
function patchDirNode(path) {
  if (state.tree.flat || computeRowModel().length > TREE_DOM_CAP) {
    renderTree();
    return;
  }
  const body = $('tree-body');
  const wrap = body.querySelector('.tree-branch[data-path="' + CSS.escape(path) + '"]');
  if (!wrap) {
    updateTreeCountAll();
    return;
  }
  const row = wrap.querySelector(':scope > .tree-node-row');
  const expanded = state.tree.expanded.has(path);
  const tw = row.querySelector(':scope > .tree-twister');
  if (tw) tw.textContent = expanded ? '\u25be' : '\u25b8';
  row.setAttribute('aria-expanded', String(expanded));
  let kids = wrap.querySelector(':scope > .tree-children');
  if (!expanded) {
    if (kids) kids.remove();
    updateTreeCountAll();
    return;
  }
  if (!kids) {
    kids = el('div', { class: 'tree-children', role: 'group' });
    wrap.append(kids);
  }
  fillChildrenContainer(kids, path, Number(row.dataset.depth || 0));
  observeMoreRows(body);
  updateTreeCountAll();
}

/* Sentinel watcher for the nested mode: fetch the next page when a
   "+N more…" row comes within 300px of the viewport. */
let treeIO = null;
function observeMoreRows(scope) {
  if (!('IntersectionObserver' in window)) return;
  if (!treeIO) {
    treeIO = new IntersectionObserver((entries) => {
      for (const en of entries) {
        if (en.isIntersecting) {
          treeIO.unobserve(en.target);
          loadMore(en.target.getAttribute('data-more'));
        }
      }
    }, { root: $('tree-body'), rootMargin: '300px' });
  }
  treeIO.disconnect();
  for (const m of scope.querySelectorAll('[data-more]')) treeIO.observe(m);
}

/* --------------------------- flat (virtualized) rendering ---------------- */

function renderTreeFlat(rows) {
  const body = $('tree-body');
  body.textContent = '';
  const inner = el('div', {});
  inner.id = 'tree-flat-inner';
  inner.style.position = 'relative';
  inner.style.height = Math.max(rows.length * TREE_ROW_H, body.clientHeight || 0) + 'px';
  body.append(inner);
  state.tree.flatRows = rows;
  renderTreeWindow();
}

/* Renders only the viewport window (+overscan) of the flat row model.
   Sentinel rows inside the window trigger their page load here; the
   freshly appended page pushes the next sentinel ~500 rows down, so the
   chain stops by itself once the user stops scrolling. */
function renderTreeWindow() {
  const body = $('tree-body');
  const inner = $('tree-flat-inner');
  const rows = state.tree.flatRows;
  if (!inner || !rows || !rows.length) return;
  const y0 = inner.offsetTop;
  const vh = body.clientHeight || 480;
  const start = Math.max(0, Math.floor((body.scrollTop - y0) / TREE_ROW_H) - TREE_OVERSCAN);
  const end = Math.min(rows.length,
    start + Math.ceil(vh / TREE_ROW_H) + 2 * TREE_OVERSCAN + 1);
  const frag = document.createDocumentFragment();
  for (let i = start; i < end; i++) frag.append(flatRowEl(rows[i], i));
  inner.textContent = '';
  inner.append(frag);
  updateTreeCount(end - start, rows.length);
  for (let i = start; i < end; i++) {
    if (rows[i].more && !rows[i].entry.loadingMore) loadMore(rows[i].more);
  }
  restoreTreeFocus();
}

function flatRowEl(modelRow, idx) {
  let row;
  if (modelRow.more) {
    row = moreRowEl(modelRow.more, modelRow.entry, modelRow.depth);
  } else if (modelRow.truncNote) {
    row = el('div', {
      class: 'tree-truncated',
      text: 'listing truncated: directory has more entries on disk',
    });
    row.style.paddingLeft = ((modelRow.depth || 0) * 16 + 22) + 'px';
  } else {
    row = buildRowEl(modelRow.child, modelRow.depth);
    row.style.paddingLeft = (modelRow.depth * 16 + 4) + 'px';
    row.dataset.flatIdx = String(idx);
  }
  row.style.position = 'absolute';
  row.style.top = (idx * TREE_ROW_H) + 'px';
  row.style.left = '0';
  row.style.right = '0';
  row.style.height = TREE_ROW_H + 'px';
  row.style.overflow = 'hidden';
  return row;
}

let treeScrollRaf = 0;
function onTreeScroll() {
  if (!state.tree.flat || treeScrollRaf) return;
  treeScrollRaf = requestAnimationFrame(() => {
    treeScrollRaf = 0;
    if (state.tree.flat) renderTreeWindow();
  });
}

/* tree keyboard navigation (nested: DOM rows; flat: row model + window) */
function visibleTreeRows() {
  return Array.from($('tree-body').querySelectorAll('.tree-node-row'));
}
function setTreeFocus(row) {
  for (const r of visibleTreeRows()) {
    r.classList.remove('node-focused');
    r.setAttribute('aria-selected', 'false');
  }
  if (row) {
    row.classList.add('node-focused');
    row.setAttribute('aria-selected', 'true');
    row.scrollIntoView({ block: 'nearest' });
    state.tree.focusedPath = row.getAttribute('data-path');
    if (row.dataset.flatIdx != null) state.tree.focusIdx = Number(row.dataset.flatIdx);
  }
}
function restoreTreeFocus() {
  if (!state.tree.focusedPath) return;
  const row = visibleTreeRows().find((r) => r.getAttribute('data-path') === state.tree.focusedPath);
  if (row) setTreeFocus(row);
}

function treeKeydown(ev) {
  if (state.tree.flat) {
    treeKeydownFlat(ev);
    return;
  }
  const rows = visibleTreeRows();
  if (!rows.length) return;
  const key = ev.key;
  if (!['ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight', 'Enter', 'Home', 'End'].includes(key)) return;
  ev.preventDefault();
  let i = rows.findIndex((r) => r.classList.contains('node-focused'));
  if (key === 'Home') { setTreeFocus(rows[0]); return; }
  if (key === 'End') { setTreeFocus(rows[rows.length - 1]); return; }
  if (key === 'ArrowDown') { setTreeFocus(rows[Math.min(i + 1, rows.length - 1)]); return; }
  if (key === 'ArrowUp') { setTreeFocus(rows[Math.max(i - 1, 0)]); return; }
  const row = rows[i >= 0 ? i : 0];
  if (!row) return;
  const path = row.getAttribute('data-path');
  const isDir = row.getAttribute('data-isdir') === 'true';
  const expanded = state.tree.expanded.has(path);
  if (key === 'ArrowRight' && isDir && !expanded) { toggleDir(path); return; }
  if (key === 'ArrowLeft' && isDir && expanded) { toggleDir(path); return; }
  if (key === 'ArrowLeft' && (!isDir || !expanded)) {
    // jump to parent row
    const parent = dirname(path);
    const prow = rows.find((r) => r.getAttribute('data-path') === parent);
    if (prow) setTreeFocus(prow);
    return;
  }
  if (key === 'Enter') {
    if (isDir) toggleDir(path);
    else openInspector(path, null, { push: true });
  }
}

/* Keyboard over the flat model: the focused row may not be in the DOM
   yet, so navigation moves an index and re-renders the window around it. */
function treeKeydownFlat(ev) {
  const rows = state.tree.flatRows || [];
  if (!rows.length) return;
  const key = ev.key;
  if (!['ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight', 'Enter', 'Home', 'End'].includes(key)) return;
  ev.preventDefault();
  const body = $('tree-body');
  const ensureVisible = (idx) => {
    const y = idx * TREE_ROW_H;
    if (y < body.scrollTop) body.scrollTop = y;
    else if (y + TREE_ROW_H > body.scrollTop + body.clientHeight) {
      body.scrollTop = y + TREE_ROW_H - body.clientHeight;
    }
  };
  const goto = (idx) => {
    state.tree.focusIdx = idx;
    ensureVisible(idx);
    renderTreeWindow();
    focusFlatIdx(idx);
  };
  let i = state.tree.focusIdx;
  if (i == null || i < 0 || i >= rows.length) {
    i = rows.findIndex((r) => r.child && r.child.path === state.tree.focusedPath);
  }
  if (i < 0) i = 0;
  if (key === 'Home') { goto(0); return; }
  if (key === 'End') { goto(rows.length - 1); return; }
  if (key === 'ArrowDown') { goto(Math.min(i + 1, rows.length - 1)); return; }
  if (key === 'ArrowUp') { goto(Math.max(i - 1, 0)); return; }
  const m = rows[i];
  if (!m || !m.child) return;
  const child = m.child;
  if (key === 'ArrowRight' && child.is_dir && !state.tree.expanded.has(child.path)) {
    toggleDir(child.path);
    return;
  }
  if (key === 'ArrowLeft' && child.is_dir && state.tree.expanded.has(child.path)) {
    toggleDir(child.path);
    return;
  }
  if (key === 'ArrowLeft') {
    const pi = rows.findIndex((r) => r.child && r.child.path === dirname(child.path));
    if (pi >= 0) goto(pi);
    return;
  }
  if (key === 'Enter') {
    if (child.is_dir) toggleDir(child.path);
    else openInspector(child.path, null, { push: true });
  }
}

function focusFlatIdx(idx) {
  const row = $('tree-body').querySelector('.tree-node-row[data-flat-idx="' + idx + '"]');
  if (row) setTreeFocus(row);
}

/* --------------------------------------------------------- workspace search */

/* The tree search box doubles as a whole-workspace search when the scope
   select says so. Only the new backend (/api/search) can serve it; on
   the old server the scope falls back to the in-loaded name filter with
   an inline note instead of a request. */
let searchTimer = null;

function hideSearchResults() {
  const box = $('tree-search-results');
  if (!box) return;
  box.hidden = true;
  box.textContent = '';
}

function showSearchNote(msg) {
  const box = $('tree-search-results');
  if (!box) return;
  box.textContent = '';
  box.hidden = false;
  box.append(el('div', { class: 'tree-truncated', text: msg }));
}

function onTreeSearchInput() {
  state.tree.filter = $('tree-search').value.trim();
  clearTimeout(searchTimer);
  const workspace = $('tree-search-scope').value === 'workspace';
  if (workspace && state.tree.filter) {
    if (state.tree.pagedApi) {
      showSearchNote('searching "' + state.tree.filter + '" across the workspace…');
      searchTimer = setTimeout(runWorkspaceSearch, 300);
    } else {
      showSearchNote('whole-workspace search needs the updated server API; filtering loaded nodes instead');
    }
  } else {
    hideSearchResults();
  }
  renderTree();
}

async function runWorkspaceSearch() {
  const q = state.tree.filter;
  if (!q || $('tree-search-scope').value !== 'workspace' || !state.tree.pagedApi) return;
  try {
    const data = await api('/api/search', { q, limit: 100 });
    if (state.tree.filter !== q || $('tree-search-scope').value !== 'workspace') return;
    state.tree.searchResults = data || { matches: [] };
    renderSearchResults();
  } catch (e) {
    showSearchNote('workspace search failed: ' + e.message);
  }
}

function renderSearchResults() {
  const box = $('tree-search-results');
  const data = state.tree.searchResults || {};
  const matches = data.matches || [];
  box.textContent = '';
  box.hidden = false;
  const total = data.total_matches != null ? data.total_matches : matches.length;
  box.append(el('div', {
    class: 'tree-truncated',
    text: `${total} match(es) across the workspace` +
      (data.truncated && matches.length ? ` — first ${matches.length} shown` : '') +
      '. Click a result to reveal it in the tree.',
  }));
  if (!matches.length) return;
  for (const m of matches.slice(0, 100)) {
    const isDir = !!m.is_dir;
    const item = el('div', {
      class: 'tree-node-row',
      role: 'option',
      tabindex: '0',
      'aria-selected': 'false',
      'data-path': m.path,
      title: 'reveal ' + m.path + ' in the tree' + (isDir ? '' : ' and open it in the inspector'),
    });
    item.append(el('span', { class: 'tree-icon', 'aria-hidden': 'true', text: isDir ? 'dir' : 'file' }));
    item.append(el('span', { class: 'tree-name mono', text: m.path }));
    const br = badgeRowFromCounts(m.counts || {});
    if (br.childNodes.length) item.append(br);
    const activate = () => revealInTree(m.path, isDir);
    item.addEventListener('click', activate);
    item.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') activate(); });
    box.append(item);
  }
}

/* Expand the ancestor chain of path (loading every level on the way),
   then focus the row. Files additionally open in the inspector. */
async function revealInTree(path, isDir) {
  hideSearchResults();
  const segs = String(path).replace(/\\/g, '/').split('/').filter(Boolean);
  let cur = '';
  const chain = [];
  for (const seg of segs) {
    cur = cur ? cur + '/' + seg : seg;
    chain.push(cur);
  }
  for (let i = 0; i < chain.length; i++) {
    if (!isDir && i === chain.length - 1) break;   // file: expand ancestors only
    const t = chain[i];
    state.tree.expanded.add(t);
    const entry = state.tree.cache.get(t);
    if (!entry || (!entry.children && !entry.loading && !entry.error)) {
      await loadDir(t);
    }
  }
  state.tree.focusedPath = path;
  renderTree();
  focusTreeRowByPath(path);
  if (!isDir) openInspector(path, null, { push: true });
}

function focusTreeRowByPath(path) {
  const row = $('tree-body').querySelector('.tree-node-row[data-path="' + CSS.escape(path) + '"]');
  if (row) {
    setTreeFocus(row);
    return;
  }
  if (state.tree.flat && state.tree.flatRows) {
    const idx = state.tree.flatRows.findIndex((r) => r.child && r.child.path === path);
    if (idx >= 0) {
      const body = $('tree-body');
      body.scrollTop = Math.max(0, idx * TREE_ROW_H - body.clientHeight / 2);
      renderTreeWindow();
      focusFlatIdx(idx);
    }
  }
}

/* --------------------------------------------------------------- findings */

async function initFindings() {
  await Promise.all([ensureHarnessOptions(), loadFindings()]);
}

async function loadFindings() {
  const body = $('findings-body');
  const f = state.findings;
  body.innerHTML = loadingHTML('Loading findings…');
  try {
    const data = await api('/api/findings', { gate: f.gate, harness: f.harness, q: f.q });
    f.fetched = data.findings || [];
    f.loadedOnce = true;
    renderFindings();
  } catch (e) {
    body.textContent = '';
    body.append(errorPanel(e, loadFindings));
  }
}

function visibleFindings() {
  const f = state.findings;
  return f.fetched.filter((x) => {
    if (!state.sev.has(x.severity)) return false;
    if (!state.showPassed && x.status === 'pass') return false;
    return true;
  });
}

const FIND_COLS = [
  { key: 'severity', label: 'Severity' },
  { key: 'fid', label: 'ID' },
  { key: 'gate', label: 'Gate' },
  { key: 'harness', label: 'Harness' },
  { key: 'title', label: 'Title' },
  { key: 'status', label: 'Status' },
  { key: 'fix', label: 'Fix' },
];

function findingSorter(key, dir) {
  const mul = dir === 'asc' ? 1 : -1;
  const val = (x) => {
    switch (key) {
      case 'severity': return SEV_WEIGHT[x.severity] || 0;
      case 'fid': return x.fid || '';
      case 'gate': return x.gate || '';
      case 'harness': return x.harness || '';
      case 'title': return (x.title || '').toLowerCase();
      case 'status': return STATUS_RANK[x.status] != null ? STATUS_RANK[x.status] : 9;
      case 'fix': return x.autofix_available ? 1 : 0;
      default: return 0;
    }
  };
  return (a, b) => {
    const va = val(a), vb = val(b);
    if (typeof va === 'string' || typeof vb === 'string') {
      return String(va).localeCompare(String(vb)) * mul;
    }
    return (va - vb) * mul;
  };
}

function renderFindings() {
  const body = $('findings-body');
  const f = state.findings;
  body.textContent = '';
  const rows = visibleFindings();
  const countLine = el('p', {
    class: 'findings-count',
    text: `Showing ${rows.length} of ${f.fetched.length} fetched findings.` +
      (f.q || f.gate || f.harness ? ' Server filters active (gate/harness/search).' : ''),
  });
  body.append(countLine);

  if (!rows.length) {
    body.append(el('div', {
      class: 'empty-state',
      text: !state.sev.size && !state.showPassed
        ? 'All severity chips are off — enable at least one filter chip above.'
        : 'No findings match the current filters.',
    }));
    return;
  }

  const table = el('table', { class: 'tbl', 'aria-label': 'Findings' });
  const thead = el('thead');
  const hr = el('tr');
  for (const col of FIND_COLS) {
    const th = el('th', { scope: 'col', text: col.label });
    if (col.key !== 'fix') th.classList.add('sortable');
    if (f.sortKey === col.key) th.setAttribute('aria-sort', f.sortDir === 'asc' ? 'ascending' : 'descending');
    if (col.key !== 'fix') {
      th.addEventListener('click', () => {
        if (f.sortKey === col.key) f.sortDir = f.sortDir === 'asc' ? 'desc' : 'asc';
        else { f.sortKey = col.key; f.sortDir = col.key === 'severity' ? 'desc' : 'asc'; }
        renderFindings();
      });
    }
    hr.append(th);
  }
  thead.append(hr);
  table.append(thead);
  const tbody = el('tbody');
  const sorted = rows.slice().sort(findingSorter(f.sortKey, f.sortDir));

  const rowEl = (x) => {
    const tr = el('tr', {
      class: 'fnd-row row-click', 'data-fid': x.fid, 'data-severity': x.severity,
      tabindex: '-1',
      title: 'Open finding details (Enter)',
    });
    tr.append(
      el('td', {}, sevBadge(x.severity)),
      el('td', { class: 'mono', text: x.fid }),
      el('td', { class: 'mono', text: x.gate || '—' }),
      el('td', { class: 'mono', text: x.harness || '—' }),
      el('td', { text: x.title || '' }),
      el('td', {}, statusBadge(x.status)),
      el('td', {},
        x.autofix_available
          ? el('span', { class: 'autofix-yes', title: 'automatic fix available', text: 'auto \u2713' })
          : el('span', { class: 'autofix-no', title: 'no automatic fix', text: '\u2014' })),
    );
    const open = () => openFindingCard(x.fid, { push: true });
    tr.addEventListener('click', open);
    tr.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') { ev.preventDefault(); open(); } });
    return tr;
  };

  if (f.group) {
    const groups = new Map();
    for (const x of sorted) {
      const evFile = (x.evidence && x.evidence[0] && x.evidence[0].file) || '';
      const key = evFile ? dirname(String(evFile).replace(/\\/g, '/')) || '/' : '(no file evidence)';
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(x);
    }
    for (const key of Array.from(groups.keys()).sort()) {
      const gh = el('tr', { class: 'group-header-row' });
      const td = el('td', { colspan: String(FIND_COLS.length) });
      td.append(el('div', { class: 'group-header' }, el('span', { text: key }), el('span', { class: 'group-count', text: '  — ' + groups.get(key).length + ' finding(s)' })));
      gh.append(td);
      tbody.append(gh);
      for (const x of groups.get(key)) tbody.append(rowEl(x));
    }
  } else {
    for (const x of sorted) tbody.append(rowEl(x));
  }
  table.append(tbody);
  body.append(table);

  bindTableArrowNav(table);
}

function bindTableArrowNav(table) {
  table.setAttribute('tabindex', '0');
  table.addEventListener('keydown', (ev) => {
    if (!['ArrowUp', 'ArrowDown'].includes(ev.key)) return;
    const rows = Array.from(table.querySelectorAll('tr.fnd-row'));
    if (!rows.length) return;
    ev.preventDefault();
    let i = rows.findIndex((r) => r === document.activeElement);
    if (i === -1) { rows[0].focus(); return; }
    const next = ev.key === 'ArrowDown' ? Math.min(i + 1, rows.length - 1) : Math.max(i - 1, 0);
    rows[next].focus();
  });
}

/* ----------------------------------------------------------- finding card */

async function openFindingCard(fid, opts = {}) {
  const push = opts.push !== false;
  const overlay = $('card-overlay');
  const bodyEl = $('card-body');
  overlay.hidden = false;
  $('card-fid').textContent = fid;
  $('card-badges').textContent = '';
  bodyEl.innerHTML = loadingHTML('Loading finding…');
  try {
    const x = await api('/api/finding/' + encodeURIComponent(fid));
    renderFindingCard(x);
    if (push) pushNav({ type: 'finding', fid });
  } catch (e) {
    bodyEl.textContent = '';
    bodyEl.append(errorPanel(e, () => openFindingCard(fid, { push: false })));
  }
}

function closeFindingCard() {
  $('card-overlay').hidden = true;
}

function renderFindingCard(x) {
  const badges = $('card-badges');
  badges.textContent = '';
  badges.append(sevBadge(x.severity), statusBadge(x.status));
  badges.append(el('span', { class: 'conf-note', text: 'conf ' + Number(x.confidence != null ? x.confidence : 0).toFixed(2) }));

  const body = $('card-body');
  body.textContent = '';

  body.append(el('h3', { text: 'What' }));
  body.append(el('p', { class: 'card-desc', text: x.title || '—' }));

  body.append(el('h3', { text: 'Why' }));
  body.append(el('p', { class: 'card-desc', text: x.description || '—' }));

  body.append(el('h3', { text: 'Where' }));
  if (x.evidence && x.evidence.length) {
    for (const ev of x.evidence) {
      const item = el('div', { class: 'ev-item' });
      if (ev.file) {
        const label = ev.line != null ? `${ev.file}:${ev.line}` : String(ev.file);
        item.append(el('button', {
          class: 'ev-link', text: label,
          title: 'Open in File Inspector',
          onclick: () => {
            closeFindingCard();
            openInspector(String(ev.file).replace(/\\/g, '/'), ev.line != null ? Number(ev.line) : null, { push: true });
          },
        }));
      } else {
        item.append(el('span', { class: 'mono', text: '(no file)' }));
      }
      if (ev.detail) item.append(el('div', { class: 'ev-detail', text: String(ev.detail) }));
      body.append(item);
    }
  } else {
    body.append(el('p', { class: 'card-desc', text: 'No evidence recorded.' }));
  }

  body.append(el('h3', { text: 'Recommendation' }));
  body.append(el('div', { class: 'recommendation', text: x.recommendation || 'No recommendation recorded.' }));

  body.append(el('h3', { text: 'Autofix' }));
  const fixArea = el('div', { class: 'fixplan' });
  fixArea.append(el('button', {
    class: 'btn-accent', text: 'Fix plan',
    onclick: () => loadFixPlan(x.fid),
  }));
  fixArea.append(el('span', {
    class: 'conf-note',
    text: x.autofix_available
      ? '  autofix available — the plan is a dry run, nothing is changed'
      : '  autofix flag is off; the plan may report "not supported"',
  }));
  body.append(fixArea);
  const planBox = el('div', { id: 'fix-plan-box' });
  body.append(planBox);

  body.append(el('h3', { text: 'Evidence JSON' }));
  const det = el('details', { class: 'ev-json' });
  det.append(el('summary', { text: 'show raw evidence' }));
  det.append(el('pre', { text: JSON.stringify(x.evidence, null, 2) }));
  body.append(det);
}

async function loadFixPlan(fid) {
  const box = $('fix-plan-box');
  if (!box) return;
  box.innerHTML = loadingHTML('Planning fix (dry run)…');
  let data;
  try {
    data = await api('/api/fixplan', { fid });
  } catch (e) {
    box.textContent = '';
    box.append(el('div', { class: 'recommendation', text: 'Fix plan failed: ' + e.message }));
    return;
  }
  box.textContent = '';
  if (!data.supported) {
    box.append(el('div', { class: 'recommendation', text: 'No supported automatic fix for ' + fid + '.' }));
    return;
  }
  const head = el('div', {});
  head.append(el('strong', { text: 'Planned steps' }));
  head.append(el('span', { class: 'dryrun-badge', text: 'DRY RUN' }));
  box.append(head);
  const ol = el('ol', { class: 'fix-steps' });
  for (const s of data.steps || []) {
    const li = el('li', {});
    li.append(el('span', { class: 'fix-step-action', text: '[' + (s.action || '?') + ']' }));
    li.append(document.createTextNode(' ' + (s.target || '') + (s.detail ? ' — ' + s.detail : '')));
    ol.append(li);
  }
  if (!ol.childNodes.length) ol.append(el('li', { text: '(empty plan)' }));
  box.append(ol);
  box.append(el('div', {
    class: 'conf-note',
    text: 'The UI never applies fixes. To execute after review, run in the CLI:',
  }));
  box.append(el('code', { class: 'fix-cmd', text: `python agents_doctor.py fix scan.json ${fid} --apply` }));
}

/* ---------------------------------------------------------- file inspector */

async function openInspector(path, line, opts = {}) {
  const push = opts.push !== false;
  state.inspector.path = path;
  state.inspector.line = line || null;
  const panel = $('inspector');
  panel.hidden = false;
  $('insp-path').textContent = path;
  $('insp-badges').textContent = '';
  $('insp-banner').textContent = '';
  const code = $('insp-code');
  code.textContent = '';
  code.append(el('div', { class: 'loading', html: loadingHTML('Loading file…') }));
  if (push) pushNav({ type: 'file', path, line: line || null });
  let data;
  try {
    data = await api('/api/file', { path });
  } catch (e) {
    code.textContent = '';
    code.append(el('div', { class: 'binary-note', text: 'Cannot open file: ' + e.message }));
    return;
  }
  if (state.inspector.path !== path) return;  // user moved on meanwhile
  renderInspector(data, path, line);
}

function renderInspector(data, path, line) {
  const banner = $('insp-banner');
  banner.textContent = '';
  if (data.truncated) {
    banner.append(el('div', { class: 'banner', html: '<b>truncated</b> — preview capped at 256 KB; open the file for full content' }));
  }
  const badges = $('insp-badges');
  badges.textContent = '';
  const br = badgeRowFromCounts(data.counts || {});
  if (br.childNodes.length) badges.append(br);
  else badges.append(el('span', { class: 'conf-note', text: 'no findings attached to this file' }));

  const code = $('insp-code');
  code.textContent = '';
  if (data.binary) {
    code.append(el('div', { class: 'binary-note', text: 'binary file — no text preview' }));
    return;
  }
  const flagged = new Map();
  for (const fl of data.flagged_lines || []) flagged.set(fl.line, fl);
  const frag = document.createDocumentFragment();
  const lines = data.lines && data.lines.length ? data.lines : [''];
  lines.forEach((text, i) => {
    const n = i + 1;
    const fl = flagged.get(n);
    const rowLine = el('div', {
      class: 'code-line' + (fl ? ' flagged' : '') + (line === n ? ' hl' : ''),
      id: 'L' + n,
    });
    rowLine.append(el('span', { class: 'code-ln', text: String(n) }));
    rowLine.append(el('span', { class: 'code-txt', text: text.length ? text : ' ' }));
    if (fl) {
      rowLine.append(el('span', {
        class: 'code-flag-label',
        title: 'secret rule ' + fl.rule + ' — value masked',
        text: fl.rule,
      }));
    }
    frag.append(rowLine);
  });
  code.append(frag);
  if (line != null) {
    const target = $('L' + line);
    if (target) target.scrollIntoView({ block: 'center' });
  } else {
    code.scrollTop = 0;
  }
}

function closeInspector() {
  $('inspector').hidden = true;
  state.inspector.path = null;
}

/* ---------------------------------------------------------------- history */

function pushNav(entry) {
  const h = state.history;
  h.stack = h.stack.slice(0, h.idx + 1);
  const top = h.stack[h.idx];
  if (top && top.type === entry.type &&
      top.type === 'file' && top.path === entry.path && top.line === entry.line) {
    updateHistoryButtons();
    return;  // same destination, no duplicate
  }
  if (top && top.type === entry.type && top.type === 'finding' && top.fid === entry.fid) {
    updateHistoryButtons();
    return;
  }
  h.stack.push(entry);
  if (h.stack.length > 100) h.stack.shift();
  h.idx = h.stack.length - 1;
  updateHistoryButtons();
}

function applyNav(entry) {
  if (entry.type === 'file') openInspector(entry.path, entry.line, { push: false });
  else if (entry.type === 'finding') openFindingCard(entry.fid, { push: false });
}

function historyGo(delta) {
  const h = state.history;
  const next = h.idx + delta;
  if (next < 0 || next >= h.stack.length) return;
  h.idx = next;
  applyNav(h.stack[h.idx]);
  updateHistoryButtons();
}

function updateHistoryButtons() {
  const h = state.history;
  $('btn-back').disabled = h.idx <= 0;
  $('btn-fwd').disabled = h.idx >= h.stack.length - 1;
}

/* ---------------------------------------------------------------- treemap */

async function initTreemap() {
  await loadTreemapLevels('');
  renderTreemap();
}

async function loadTreemapLevels(rootRel) {
  const entry = await loadDir(rootRel);
  if (entry.error) return { error: entry.error };
  const top = (entry.children || []).map((c) => ({ ...c }));
  const dirs = top.filter((c) => c.is_dir);
  await Promise.all(dirs.map(async (d) => {
    const sub = await loadDir(d.path);
    d.children = sub.error ? [] : (sub.children || []).map((c) => ({ ...c }));
  }));
  state.treemap.nodes.set(rootRel, top);
  return top;
}

async function treemapEnsure() {
  const zoom = state.treemap.zoom;
  if (!state.treemap.nodes.has(zoom)) {
    await loadTreemapLevels(zoom);
  }
  return state.treemap.nodes.get(zoom) || [];
}

function metricValue(node) {
  if (state.treemap.metric === 'disk') return diskValue(node);
  const c = countsFiltered(node.counts || {});
  return state.treemap.metric === 'risk' ? countsRisk(c) : countsTotal(c);
}

function diskValue(node) {
  if (!node.is_dir) return Number(node.size) || 0;
  const s = state.treemap.stats.get(node.path);
  if (s && s.totalBytes != null) return s.totalBytes;   // exact, from stats
  return (node.children || []).reduce((sum, c) => sum + diskValue(c), 0);
}

/* Exact directory sizes come from /api/tree/stats. Only the new backend
   has the endpoint (pagedApi flag), so the old server never sees the
   request; until an answer arrives the cell keeps its partial-sum value
   with a "…" placeholder. */
async function fetchDirStats(path) {
  const cache = state.treemap.stats;
  if (cache.has(path)) return cache.get(path);
  const inflight = state.treemap.statsPending.get(path);
  if (inflight) return inflight;
  const gen = state.treemap.statsGen;
  const p = (async () => {
    try {
      const data = await api('/api/tree/stats', { path });
      const s = {
        totalBytes: data.total_bytes != null ? Number(data.total_bytes) : null,
        totalFiles: data.total_files != null ? Number(data.total_files) : null,
        problemBytes: data.problem_files_bytes != null ? Number(data.problem_files_bytes) : null,
        buildBytes: data.build_bytes != null ? Number(data.build_bytes) : null,
        share: data.share_of_root_percent != null ? Number(data.share_of_root_percent) : null,
        complete: !!data.complete,
      };
      if (gen === state.treemap.statsGen) cache.set(path, s);
      return s;
    } catch {
      return null;   // keep partial sums; the treemap never breaks on stats
    } finally {
      state.treemap.statsPending.delete(path);
    }
  })();
  state.treemap.statsPending.set(path, p);
  return p;
}

function humanSize(bytes) {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let v = bytes, i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return (v >= 100 ? Math.round(v) : v.toFixed(1)) + ' ' + units[i];
}

function metricLabel(v) {
  return state.treemap.metric === 'disk' ? humanSize(v) : String(v);
}

function dominantSeverity(counts) {
  const c = countsFiltered(counts);
  let best = null, bestN = 0;
  for (const s of SEVERITIES) {
    if ((c[s] || 0) > bestN) { best = s; bestN = c[s]; }
  }
  return best;
}

/* squarified treemap (Bruls, Huizing & van Wijk) */
function squarifyLayout(items, x, y, w, h) {
  const rects = [];
  const sorted = items.filter((it) => it.value > 0).sort((a, b) => b.value - a.value);
  if (!sorted.length || w <= 0 || h <= 0) return rects;
  const total = sorted.reduce((s, it) => s + it.value, 0);
  const scale = (w * h) / total;
  let cx = x, cy = y, cw = w, ch = h;
  let queue = sorted.map((it) => ({ ...it, value: it.value * scale }));

  const worst = (row, side) => {
    const sum = row.reduce((s, it) => s + it.value, 0);
    const max = row[0].value, min = row[row.length - 1].value;
    const s2 = sum * sum, l2 = side * side;
    return Math.max((l2 * max) / s2, s2 / (l2 * min));
  };

  while (queue.length) {
    const side = Math.min(cw, ch);
    if (side <= 0) break;
    const row = [queue.shift()];
    while (queue.length && worst(row.concat(queue[0]), side) <= worst(row, side)) {
      row.push(queue.shift());
    }
    const sum = row.reduce((s, it) => s + it.value, 0);
    if (cw >= ch) {
      const colW = sum / ch;
      let off = 0;
      for (const it of row) {
        const hh = it.value / colW;
        rects.push({ ...it, x: cx, y: cy + off, w: colW, h: hh });
        off += hh;
      }
      cx += colW; cw -= colW;
    } else {
      const rowH = sum / cw;
      let off = 0;
      for (const it of row) {
        const ww = it.value / rowH;
        rects.push({ ...it, x: cx + off, y: cy, w: ww, h: rowH });
        off += ww;
      }
      cy += rowH; ch -= rowH;
    }
  }
  return rects;
}

const TM_TOP = [34, 38, 47];    // low value bg
const TM_HOT = [122, 96, 66];   // high value bg (warm tint, readable with dark text? keep light text)
function cellBackground(v, max) {
  const t = max > 0 ? Math.min(1, v / max) : 0;
  const c = TM_TOP.map((a, i) => Math.round(a + (TM_HOT[i] - a) * t));
  return `rgb(${c[0]},${c[1]},${c[2]})`;
}

function renderTreemap() {
  const body = $('treemap-body');
  const zoom = state.treemap.zoom;
  renderTreemapCrumbs();
  const nodes = state.treemap.nodes.get(zoom);
  if (!nodes) {
    body.innerHTML = loadingHTML('Loading tree for treemap…');
    renderTreemapLegend(0, 0);
    return;
  }

  const W = body.clientWidth || 800;
  const H = body.clientHeight || 500;
  const items = nodes
    .map((n) => ({ node: n, value: metricValue(n) }))
    .filter((it) => it.value > 0);
  const total = items.reduce((s, it) => s + it.value, 0);

  body.textContent = '';
  if (!total) {
    body.innerHTML = emptyHTML(state.treemap.metric === 'disk'
      ? 'Nothing to draw: no file sizes available for the fetched tree levels.'
      : 'Nothing to draw: no problems match the current severity filter (metric ' +
        state.treemap.metric + ').');
    renderTreemapLegend(0, 0);
    return;
  }
  const max = Math.max(...items.map((it) => it.value));

  // Disk metric: pull exact sizes for the visible top-level directories;
  // the re-render after resolve swaps placeholders for real values.
  if (state.treemap.metric === 'disk' && state.tree.pagedApi) {
    const missing = nodes
      .filter((n) => n.is_dir && !state.treemap.stats.has(n.path) && !state.treemap.statsPending.has(n.path))
      .map((n) => n.path);
    if (missing.length) {
      const gen = state.treemap.statsGen;
      Promise.all(missing.map(fetchDirStats)).then(() => {
        if (gen !== state.treemap.statsGen) return;
        if (state.tab === 'treemap' && state.treemap.metric === 'disk') renderTreemap();
      });
    }
  }

  const root = el('div', { class: 'treemap-root', role: 'group', 'aria-label': 'Treemap of ' + (zoom || 'workspace root') });
  root.style.height = H + 'px';
  const rects = squarifyLayout(items, 0, 0, W, H);
  for (const r of rects) root.append(renderTreemapCell(r, max, 0));
  body.append(root);
  applyTreemapSelection(root);
  renderTreemapLegend(total, max);
}

/* Human-readable scale legend under the treemap: a gradient from the
   smallest to the largest cell color plus the largest value. */
function renderTreemapLegend(total, max) {
  const box = $('treemap-legend');
  if (!box) return;
  box.textContent = '';
  if (!total) return;
  const bar = el('span', { 'aria-hidden': 'true' });
  bar.style.display = 'inline-block';
  bar.style.width = '110px';
  bar.style.height = '9px';
  bar.style.verticalAlign = 'middle';
  bar.style.margin = '0 6px';
  bar.style.borderRadius = '2px';
  bar.style.background = `linear-gradient(to right, ${cellBackground(0, max)}, ${cellBackground(max, max)})`;
  box.append(el('span', { text: 'scale 0' }), bar,
    el('span', { text: metricLabel(max) + ' (largest cell)' }));
  if (state.treemap.metric === 'disk') {
    box.append(el('span', {
      text: '  ·  ' + (state.tree.pagedApi
        ? 'dir sizes via /api/tree/stats; \u2248 marks partial data'
        : 'dir sizes are partial sums over fetched levels; \u2248 marks partial data'),
    }));
  }
}

/* Re-apply the persisted selection after a re-render (zoom, metric or
   filter change). The selected node may be off-screen (e.g. it is the
   directory we just zoomed into) — then nothing lights up, which is fine. */
function applyTreemapSelection(root) {
  if (!state.treemap.selected) return;
  const cell = root.querySelector('.tm-cell[data-path="' + CSS.escape(state.treemap.selected) + '"]');
  if (cell) cell.classList.add('selected');
}

function renderTreemapCell(r, max, depth) {
  const n = r.node;
  const isDir = !!n.is_dir;
  const disk = state.treemap.metric === 'disk';

  // Disk metric data quality: exact when /api/tree/stats answered with
  // complete=true; "…" while the answer is in flight; partial (hatched,
  // "≈") when only fetched-level sums are available.
  let statsPending = false;
  let dirPartial = false;
  if (disk && isDir) {
    const s = state.treemap.stats.get(n.path);
    if (s && s.totalBytes != null) dirPartial = !s.complete;
    else {
      statsPending = state.tree.pagedApi && depth === 0;   // sub-cells are never fetched
      dirPartial = true;
    }
    const entry = state.tree.cache.get(n.path);
    if (entry && entry.nextCursor) dirPartial = true;      // listing pages still missing
  }

  const cell = el('div', {
    class: 'tm-cell' + (isDir ? ' tm-zoomable' : ''),
    tabindex: '0',
    role: 'button',
    'data-path': n.path,
    'data-isdir': String(isDir),
    'aria-label': tmTooltipText(n, r.value),
  });
  cell.style.left = r.x + 'px';
  cell.style.top = r.y + 'px';
  cell.style.width = r.w + 'px';
  cell.style.height = r.h + 'px';
  cell.style.background = cellBackground(r.value, max);
  if (dirPartial) {
    // hatch overlay directly on the cell (not only in the tooltip)
    cell.style.backgroundImage =
      'repeating-linear-gradient(45deg, rgba(255,255,255,0.09) 0 5px, rgba(255,255,255,0) 5px 11px)';
  }

  const dom = dominantSeverity(n.counts || {});
  if (r.w > 34 && r.h > 16) {
    cell.append(el('span', { class: 'tm-label', text: n.name + (depth === 0 && isDir ? '/' : '') }));
  }
  if (dom && r.w > 26 && r.h > 14) {
    cell.append(el('span', {
      class: 'tm-sev-corner tb-' + dom,
      text: SEV_LETTER[dom],
      title: 'dominant severity: ' + dom,
      'aria-hidden': 'true',
    }));
  }
  if (disk && r.w > 46 && r.h > 18) {
    const s = isDir ? state.treemap.stats.get(n.path) : null;
    const sizeTxt = !isDir
      ? humanSize(Number(n.size) || 0)
      : (s && s.totalBytes != null
        ? (s.complete ? '' : '\u2248 ') + humanSize(s.totalBytes)
        : (statsPending ? '\u2026' : '\u2248 ' + humanSize(r.value)));
    if (sizeTxt) {
      const sp = el('span', { class: 'tm-size mono', 'aria-hidden': 'true', text: sizeTxt });
      sp.style.position = 'absolute';
      sp.style.right = '4px';
      sp.style.bottom = '2px';
      sp.style.fontSize = '10px';
      sp.style.color = 'rgba(214,217,224,.8)';
      cell.append(sp);
    }
  }
  if (dirPartial && r.w > 30 && r.h > 14) {
    const pm = el('span', {
      class: 'tm-partial-mark mono',
      'aria-hidden': 'true',
      title: 'directory data is partial',
      text: '\u2248',
    });
    pm.style.position = 'absolute';
    pm.style.left = '3px';
    pm.style.bottom = '2px';
    pm.style.fontSize = '10px';
    pm.style.color = 'rgba(214,217,224,.8)';
    cell.append(pm);
  }

  // nested second level inside large directory cells
  if (isDir && n.children && r.w >= 70 && r.h >= 48) {
    const labelH = 15;
    const subItems = n.children
      .map((c) => ({ node: c, value: metricValue(c) }))
      .filter((it) => it.value > 0);
    if (subItems.length) {
      const subMax = Math.max(...subItems.map((it) => it.value));
      const sub = el('div', { class: 'tm-sub' });
      sub.style.top = labelH + 'px';
      const subRects = squarifyLayout(subItems, 0, 0, r.w - 2, r.h - labelH - 2);
      for (const sr of subRects) sub.append(renderTreemapCell(sr, subMax, depth + 1));
      cell.append(sub);
    }
  }

  attachTreemapTooltip(cell, n);
  return cell;
}

/* Tooltip only (hover + keyboard focus). Activation handlers live on
   #treemap-body as delegated listeners — see onTreemapClick & co. */
function attachTreemapTooltip(cell, n) {
  const tip = $('treemap-tooltip');
  const show = (evx) => {
    tip.textContent = tmTooltipText(n, metricValue(n));
    tip.hidden = false;
    const pad = 14;
    let tx = evx.clientX + pad, ty = evx.clientY + pad;
    const r = tip.getBoundingClientRect();
    if (tx + r.width > window.innerWidth - 8) tx = evx.clientX - r.width - pad;
    if (ty + r.height > window.innerHeight - 8) ty = evx.clientY - r.height - pad;
    tip.style.left = tx + 'px';
    tip.style.top = ty + 'px';
  };
  cell.addEventListener('mousemove', show);
  cell.addEventListener('mouseenter', show);
  cell.addEventListener('mouseleave', () => { tip.hidden = true; });
  cell.addEventListener('focus', () => {
    const r = cell.getBoundingClientRect();
    tip.textContent = tmTooltipText(n, metricValue(n));
    tip.hidden = false;
    tip.style.left = Math.min(r.right + 8, window.innerWidth - 320) + 'px';
    tip.style.top = (r.top + 8) + 'px';
  });
  cell.addEventListener('blur', () => { tip.hidden = true; });
}

/* Pure decision tables for cell activation. DOM-free on purpose: the node
   smoke test requires app.js and exercises these directly (see bottom of
   file). Delegated handlers below must go through them so there is exactly
   one place that decides what an interaction means.
   detail is MouseEvent.detail: 1 = single click, 2+ = double click,
   0 = keyboard-synthesized click (treated as single). */
function resolveTreemapClick(detail, isDir) {
  if (detail >= 2) return isDir ? 'zoom' : 'none';
  return isDir ? 'select' : 'select-inspect';
}

function resolveTreemapKey(key, isDir) {
  if (key === 'Enter' || key === ' ') return isDir ? 'zoom' : 'inspect';
  if (key === 'Backspace') return 'up';
  return null;
}

function treemapCellFromEvent(ev) {
  // innermost .tm-cell: nested sub-cells must win over their parent cell
  return ev.target && ev.target.closest ? ev.target.closest('.tm-cell') : null;
}

function selectTreemapCell(cell) {
  state.treemap.selected = cell.getAttribute('data-path');
  for (const c of $('treemap-body').querySelectorAll('.tm-cell.selected')) {
    c.classList.remove('selected');
  }
  cell.classList.add('selected');
}

/* Single vs double click is told apart via MouseEvent.detail, not a
   setTimeout(250) dance: the first click of a double click simply selects
   the cell (same as OS file managers, harmless), and detail >= 2 makes the
   click handler stand back so the dblclick handler can zoom. A timeout
   would delay every selection by 250 ms and need cancel bookkeeping on
   every re-render, which rebuilds all cells. */
function onTreemapClick(ev) {
  const cell = treemapCellFromEvent(ev);
  if (!cell) return;
  const isDir = cell.getAttribute('data-isdir') === 'true';
  const act = resolveTreemapClick(ev.detail || 1, isDir);
  if (act === 'select' || act === 'select-inspect') selectTreemapCell(cell);
  if (act === 'select-inspect') {
    openInspector(cell.getAttribute('data-path'), null, { push: true });
  }
}

function onTreemapDblclick(ev) {
  const cell = treemapCellFromEvent(ev);
  if (!cell) return;
  ev.preventDefault();   // no double-click text selection on labels
  const isDir = cell.getAttribute('data-isdir') === 'true';
  if (resolveTreemapClick(2, isDir) !== 'zoom') return;
  selectTreemapCell(cell);
  zoomTreemap(cell.getAttribute('data-path'));
}

/* Container-level keyboard: Enter/Space activate the focused cell,
   Backspace zooms out one level (no-op at root). Escape for the tooltip
   is handled in globalKeydown together with card/inspector closing. */
function onTreemapKeydown(ev) {
  // zooming re-renders every cell, which drops focus to the panel:
  // Backspace-up must still work from anywhere inside the treemap,
  // not only while a cell happens to hold focus
  const inTreemap = ev.target && ev.target.closest
    && ev.target.closest('#treemap-body') !== null;
  if (!inTreemap) return;
  if (ev.key === 'Backspace') {
    ev.preventDefault();
    treemapZoomOut();
    return;
  }
  const cell = treemapCellFromEvent(ev);
  if (!cell) return;
  const isDir = cell.getAttribute('data-isdir') === 'true';
  const act = resolveTreemapKey(ev.key, isDir);
  if (!act) return;
  ev.preventDefault();
  if (act === 'up') { treemapZoomOut(); return; }
  selectTreemapCell(cell);
  if (act === 'zoom') zoomTreemap(cell.getAttribute('data-path'));
  else openInspector(cell.getAttribute('data-path'), null, { push: true });
}

function tmTooltipText(n, value) {
  const c = countsFiltered(n.counts || {});
  const lines = [n.path + (n.is_dir ? '/' : '')];
  for (const s of SEVERITIES) {
    if (state.sev.has(s)) lines.push(`${s}: ${c[s] || 0}`);
  }
  if (state.treemap.metric === 'disk') {
    if (n.is_dir) {
      const s = state.treemap.stats.get(n.path);
      if (s && s.totalBytes != null) {
        lines.push(`disk: ${humanSize(s.totalBytes)}` + (s.complete ? ' (exact)' : ' (partial)'));
        if (s.totalFiles != null) lines.push(`files: ${s.totalFiles}`);
        if (s.share != null) lines.push(`share of root: ${s.share.toFixed(1)}%`);
        if (s.problemBytes > 0) lines.push(`problem files: ${humanSize(s.problemBytes)}`);
        if (s.buildBytes > 0) {
          const pct = s.totalBytes ? Math.round(100 * s.buildBytes / s.totalBytes) : 0;
          lines.push(`build weight: ${humanSize(s.buildBytes)} (${pct}%)`);
        }
      } else {
        lines.push(`disk: ${humanSize(value)} (partial: fetched levels only` +
          (state.tree.pagedApi ? '; exact size loading…' : '') + ')');
      }
    } else {
      lines.push(`disk: ${humanSize(value)}`);
    }
  } else {
    lines.push(`${state.treemap.metric}: ${value}`);
  }
  if (!n.is_dir && n.symlink) lines.push('symlink');
  return lines.join('\n');
}

async function zoomTreemap(rel) {
  state.treemap.zoom = rel;
  await treemapEnsure();
  renderTreemap();
  treemapRefocus();
}

function treemapZoomOut() {
  if (!state.treemap.zoom) return false;
  const segs = state.treemap.zoom.split('/').filter(Boolean);
  segs.pop();
  state.treemap.zoom = segs.join('/');
  treemapEnsure().then(renderTreemap);
  return true;
}

/* Re-rendering replaces every cell, so the focused cell node dies and
   focus falls back to <body> — after that, keyboard navigation is dead.
   Park focus on the container (tabindex=-1) after each zoom re-render;
   Backspace-up works from anywhere inside the treemap anyway. */
function treemapRefocus() {
  const active = document.activeElement;
  if (active && active.closest && active.closest('#treemap-body')) return;
  const body = $('treemap-body');
  if (body) body.focus({ preventScroll: true });
}

function renderTreemapCrumbs() {
  const nav = $('treemap-crumbs');
  nav.textContent = '';
  const zoom = state.treemap.zoom;
  const mk = (label, target, current) => {
    if (current) nav.append(el('span', { class: 'crumb-current', text: label }));
    else nav.append(el('button', {
      class: 'crumb-btn', text: label, 'data-path': target,
      'aria-label': 'Zoom to ' + (label || 'root'),
      onclick: () => zoomTreemap(target),
    }));
  };
  mk('root', '', !zoom);
  if (zoom) {
    const segs = zoom.split('/').filter(Boolean);
    segs.forEach((seg, i) => {
      nav.append(el('span', { class: 'crumb-sep', text: '/' , 'aria-hidden': 'true' }));
      mk(seg, segs.slice(0, i + 1).join('/'), i === segs.length - 1);
    });
  }
}

/* ------------------------------------------------- path + api raw helpers */

async function apiRaw(path, params = {}) {
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== null && v !== undefined && v !== '') qs.set(k, v);
  }
  const url = path + (qs.toString() ? '?' + qs.toString() : '');
  const resp = await fetch(url);
  if (!resp.ok) throw new Error(resp.status + ' ' + resp.statusText);
  return resp.json();
}

function rootPrefix() {
  const r = state.overview && state.overview.root ? String(state.overview.root) : null;
  return r ? r.replace(/\\/g, '/').replace(/\/+$/, '') : null;
}

/** Relative workspace path for p (abs or rel); null when outside root. */
function toRelPath(p) {
  let s = String(p).replace(/\\/g, '/').replace(/\/+$/, '');
  const root = rootPrefix();
  if (root) {
    if (s === root) return '';
    if (s.startsWith(root + '/')) return s.slice(root.length + 1);
  }
  if (/^[a-zA-Z]:\//.test(s) || s.startsWith('/')) return null;  // abs, outside root
  return s.replace(/^\/+/, '');                                   // already relative
}

function fileNameOf(p) {
  const parts = String(p).replace(/\\/g, '/').split('/');
  return parts[parts.length - 1] || p;
}

/** Clickable path: button → File Inspector when inside root, plain span otherwise. */
function pathLink(p, line, labelText) {
  const rel = toRelPath(p);
  const text = labelText != null ? labelText : String(p);
  if (rel === null) {
    return el('span', {
      class: 'mono outside-root',
      title: 'outside workspace root — no preview available',
      text: text,
    });
  }
  return el('button', {
    class: 'ev-link',
    text: text,
    title: rel + (line != null ? ':' + line : '') + ' — open in File Inspector',
    onclick: () => openInspector(rel, line != null ? Number(line) : null, { push: true }),
  });
}

/* --------------------------------------------------------------- simulate */

async function ensureHarnessOptions() {
  if (state.harnesses) return;
  try {
    state.harnesses = await api('/api/harnesses');
  } catch {
    state.harnesses = { detected: [], spec_matrix: [] };
  }
  const sel = $('fnd-harness');
  sel.textContent = '';
  sel.append(el('option', { value: '', text: 'all harnesses' }));
  for (const h of state.harnesses.spec_matrix || []) {
    sel.append(el('option', {
      value: h.harness_id,
      text: h.display_name ? `${h.display_name} (${h.harness_id})` : h.harness_id,
    }));
  }
}

function fillHarnessSelect(selectEl, allLabel) {
  selectEl.textContent = '';
  selectEl.append(el('option', { value: '', text: allLabel }));
  for (const h of (state.harnesses && state.harnesses.spec_matrix) || []) {
    selectEl.append(el('option', {
      value: h.harness_id,
      text: h.display_name ? `${h.display_name} (${h.harness_id})` : h.harness_id,
    }));
  }
}

async function initSimulate() {
  await ensureHarnessOptions();
  fillHarnessSelect($('sim-harness'), 'all harnesses');
  renderSimTargetChips();
}

function renderSimTargetChips() {
  const box = $('sim-target-chips');
  box.textContent = '';
  const mk = (label, value) => box.append(el('button', {
    class: 'chip', 'aria-pressed': 'false',
    title: 'Use ' + (value === '' ? 'workspace root' : value) + ' as target',
    text: label,
    onclick: () => { $('sim-target').value = value; },
  }));
  mk('root', '');
  if (state.tree.currentDir) {
    mk('tree: ' + state.tree.currentDir, state.tree.currentDir);
  }
}

async function runSimulate() {
  const body = $('simulate-body');
  const harness = $('sim-harness').value;
  const target = $('sim-target').value.trim().replace(/\\/g, '/').replace(/^\/+/, '');
  state.simulate.harness = harness;
  body.innerHTML = loadingHTML('Simulating instruction loading…');
  try {
    const data = await api('/api/simulate', { target, harness });
    state.simulate.result = data;
    renderSimulate(data);
  } catch (e) {
    body.textContent = '';
    body.append(errorPanel(e, runSimulate));
  }
}

const KIND_CLASS = { contradiction: 'tb-critical', divergence: 'tb-high', duplication: 'tb-low' };

function renderSimulate(data) {
  const body = $('simulate-body');
  body.textContent = '';

  if (data.approximated) {
    body.append(el('div', {
      class: 'banner sim-banner',
      html: '<b>model, not runtime-verified</b> — ' + esc(data.note || 'chains follow documented loading models'),
    }));
  }

  const summ = data.conflict_summary || {};
  body.append(el('p', {
    class: 'conf-note',
    text: `Target: ${data.target_dir || '?'}   ·   loaded sources: ${data.loaded_sources_total != null ? data.loaded_sources_total : '?'}   ·   ` +
      `conflicts: contradiction ${summ.contradiction || 0}, divergence ${summ.divergence || 0}, duplication ${summ.duplication || 0}`,
  }));

  const chains = data.harnesses || {};
  for (const hid of Object.keys(chains)) {
    const chain = chains[hid];
    const block = el('div', { class: 'sim-harness-block' });
    block.append(el('div', { class: 'ov-section-title', text: hid }));
    if (!chain.supported) {
      block.append(el('p', { class: 'conf-note', text: 'not modelled: ' + (chain.reason || 'adapter does not model instruction loading') }));
      body.append(block);
      continue;
    }
    const list = (title, items, renderRow) => {
      if (!items || !items.length) return;
      block.append(el('h4', { class: 'sim-sub-title', text: `${title} (${items.length})` }));
      const ul = el('ul', { class: 'sim-list' });
      for (const item of items) ul.append(el('li', {}, renderRow(item)));
      block.append(ul);
    };
    list('Loaded', chain.loaded, (l) => {
      const row = el('span', { class: 'pathline' });
      row.append(pathLink(l.path));
      row.append(el('span', {
        class: 'mono subtle',
        text: `  [${l.scope}] prec ${l.precedence != null ? l.precedence : '?'}` + (l.reason ? ' — ' + l.reason : ''),
      }));
      return row;
    });
    list('Overridden / unused', chain.overridden, (l) => {
      const row = el('span', { class: 'pathline' });
      row.append(pathLink(l.path));
      row.append(el('span', { class: 'mono subtle', text: '  ' + (l.reason || '') }));
      return row;
    });
    list('Unloaded', chain.unloaded, (l) => {
      const row = el('span', { class: 'pathline' });
      row.append(pathLink(l.path));
      row.append(el('span', { class: 'mono subtle', text: '  ' + (l.reason || '') }));
      return row;
    });
    body.append(block);
  }

  const conflicts = data.conflicts || [];
  if (conflicts.length) {
    body.append(el('div', { class: 'ov-section-title', text: `Conflicts (${conflicts.length})` }));
    for (const c of conflicts) {
      const item = el('div', { class: 'conflict-item' });
      item.append(el('span', {
        class: 'tree-badge ' + (KIND_CLASS[c.kind] || 'tb-info'),
        text: c.kind,
        title: 'conflict kind: ' + c.kind,
      }));
      item.append(document.createTextNode(' '));
      item.append(pathLink(c.file_a, c.line_a, `${c.file_a}:${c.line_a}`));
      item.append(el('span', { class: 'mono subtle', text: '  ' + (c.text_a || '').slice(0, 120) }));
      item.append(el('span', { class: 'mono subtle', text: '  \u2194  ' }));
      item.append(pathLink(c.file_b, c.line_b, `${c.file_b}:${c.line_b}`));
      item.append(el('span', { class: 'mono subtle', text: '  ' + (c.text_b || c.preview || '').slice(0, 120) }));
      if (c.topic) item.append(el('div', { class: 'ev-detail', text: 'topic: ' + c.topic }));
      body.append(item);
    }
  }
}

/* ----------------------------------------------------------- instructions */

const SCOPE_ORDER = ['global', 'user', 'project', 'nested', 'path_scoped', 'imported'];

async function initInstructions() {
  await ensureHarnessOptions();
  const body = $('instructions-body');
  body.innerHTML = loadingHTML('Simulating instruction loading at workspace root…');
  try {
    const data = await api('/api/simulate', {});
    state.instructions = data;
    renderInstructionsTable(data);
    const sel = $('ins-harness');
    sel.textContent = '';
    const chains = data.harnesses || {};
    const supported = Object.keys(chains).filter((k) => chains[k].supported);
    if (!supported.length) sel.append(el('option', { value: '', text: '(no modelled harness)' }));
    for (const hid of supported) sel.append(el('option', { value: hid, text: hid }));
    renderInstructionsDiagram();
  } catch (e) {
    body.textContent = '';
    body.append(errorPanel(e, initInstructions));
  }
}

function renderInstructionsTable(data) {
  const body = $('instructions-body');
  body.textContent = '';

  if (data.approximated) {
    body.append(el('div', {
      class: 'banner sim-banner',
      html: '<b>model, not runtime-verified</b> — sources resolved from documented loading models, not a live runtime',
    }));
  }

  const rows = [];
  for (const [hid, chain] of Object.entries(data.harnesses || {})) {
    if (!chain.supported) continue;
    for (const l of chain.loaded || []) {
      rows.push({ harness: hid, scope: l.scope || '?', prec: l.precedence, path: l.path, status: 'loaded', reason: l.reason || '' });
    }
    for (const l of chain.overridden || []) {
      rows.push({ harness: hid, scope: '', prec: l.precedence, path: l.path, status: 'overridden', reason: l.reason || '' });
    }
    for (const l of chain.unloaded || []) {
      rows.push({ harness: hid, scope: '', prec: null, path: l.path, status: 'unloaded', reason: l.reason || '' });
    }
  }

  if (!rows.length) {
    body.append(el('div', { class: 'empty-state', text: 'No instruction sources discovered for this workspace.' }));
    return;
  }
  body.append(el('p', { class: 'findings-count', text: `${rows.length} source entries across harnesses. Click a path to open it in the File Inspector.` }));

  const byScope = new Map();
  for (const r of rows) {
    const key = r.scope || '(unknown scope)';
    if (!byScope.has(key)) byScope.set(key, []);
    byScope.get(key).push(r);
  }
  const scopes = Array.from(byScope.keys()).sort((a, b) => {
    const ia = SCOPE_ORDER.indexOf(a), ib = SCOPE_ORDER.indexOf(b);
    if (ia !== -1 && ib !== -1) return ia - ib;
    if (ia !== -1) return -1;
    if (ib !== -1) return 1;
    return a.localeCompare(b);
  });

  const table = el('table', { class: 'tbl', 'aria-label': 'Instruction sources' });
  table.append(el('thead', {}, el('tr', {},
    el('th', { text: 'Harness' }), el('th', { text: 'Scope' }),
    el('th', { class: 'num', text: 'Prec' }), el('th', { text: 'Path' }),
    el('th', { text: 'Status' }), el('th', { text: 'Reason' }))));
  const tbody = el('tbody');
  for (const scope of scopes) {
    const gh = el('tr', {});
    const td = el('td', { colspan: '6' });
    td.append(el('div', { class: 'group-header' },
      el('span', { text: scope }),
      el('span', { class: 'group-count', text: '  — ' + byScope.get(scope).length + ' source(s)' })));
    gh.append(td);
    tbody.append(gh);
    for (const r of byScope.get(scope).sort((a, b) => (b.prec != null ? b.prec : -1) - (a.prec != null ? a.prec : -1) || a.harness.localeCompare(b.harness))) {
      const tr = el('tr', {});
      tr.append(
        el('td', { class: 'mono', text: r.harness }),
        el('td', { class: 'mono', text: r.scope || '—' }),
        el('td', { class: 'num', text: r.prec != null ? String(r.prec) : '—' }),
        el('td', {}, pathLink(r.path, null, fileNameOf(r.path))),
        el('td', {}, el('span', {
          class: 'status-badge st-' + (r.status === 'loaded' ? 'pass' : r.status === 'overridden' ? 'warn' : 'not_applicable'),
          html: `<span class="st-glyph" aria-hidden="true">${r.status === 'loaded' ? '\u2713' : r.status === 'overridden' ? '\u26a0' : '\u2014'}</span><span>${r.status}</span>`,
        })),
        el('td', { class: 'mono subtle', text: r.reason || '' }),
      );
      tbody.append(tr);
    }
  }
  table.append(tbody);
  body.append(table);

  const diagramTitle = el('div', { class: 'ov-section-title', text: 'Load chain diagram' });
  body.append(diagramTitle);
  body.append(el('div', { id: 'ins-diagram', class: 'ins-diagram' }));
}

function renderInstructionsDiagram() {
  const box = $('ins-diagram');
  if (!box || !state.instructions) return;
  const hid = $('ins-harness').value;
  const chain = hid && (state.instructions.harnesses || {})[hid];
  if (!chain || !chain.supported) {
    box.textContent = '';
    box.append(el('div', { class: 'empty-state', text: 'Select a harness above to draw its load chain.' }));
    return;
  }
  const links = (chain.loaded || []).slice()
    .sort((a, b) => (a.precedence != null ? a.precedence : 0) - (b.precedence != null ? b.precedence : 0));
  if (!links.length) {
    box.textContent = '';
    box.append(el('div', { class: 'empty-state', text: 'No loaded sources for this harness.' }));
    return;
  }
  box.textContent = '';
  box.innerHTML = chainSvg(hid, links);
  const note = el('p', {
    class: 'conf-note',
    text: `Top \u2192 bottom = increasing precedence (higher wins). ${links.length} loaded, ` +
      `${(chain.overridden || []).length} overridden, ${(chain.unloaded || []).length} unloaded.`,
  });
  box.append(note);
}

/** SVG chain diagram built as a string: one rectangle per source, arrows downward. */
function chainSvg(hid, links) {
  const INK = '#d6d9e0', BOX = '#22262f', EDGE = '#5289c7', ARROW = '#8b919d';
  const labels = links.map((l) => `${l.scope} \u2014 ${fileNameOf(l.path)} (prec ${l.precedence != null ? l.precedence : '?'})`);
  const boxW = Math.max(260, Math.min(720, ...labels.map((t) => t.length * 7.4 + 36)));
  const boxH = 34, gap = 22, pad = 12;
  const w = boxW + pad * 2;
  const h = links.length * (boxH + gap) + pad * 2;
  const cx = w / 2;
  let s = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="${w}" height="${h}" role="img" aria-label="Load chain for ${esc(hid)}: ${esc(labels.join(', '))}" class="chain-svg">`;
  s += `<title>Load chain for ${esc(hid)}</title>`;
  links.forEach((l, i) => {
    const y = pad + i * (boxH + gap);
    s += `<rect x="${cx - boxW / 2}" y="${y}" width="${boxW}" height="${boxH}" rx="5" fill="${BOX}" stroke="${EDGE}" stroke-width="1"/>`;
    s += `<text x="${cx}" y="${y + boxH / 2 + 4}" text-anchor="middle" font-family="ui-monospace,Consolas,monospace" font-size="12" fill="${INK}">${esc(labels[i])}</text>`;
    s += `<title>${esc(l.path)}</title>`;
    if (i < links.length - 1) {
      const y1 = y + boxH, y2 = y + boxH + gap;
      s += `<line x1="${cx}" y1="${y1}" x2="${cx}" y2="${y2 - 6}" stroke="${ARROW}" stroke-width="1.4"/>`;
      s += `<polygon points="${cx - 4},${y2 - 7} ${cx + 4},${y2 - 7} ${cx},${y2}" fill="${ARROW}"/>`;
    }
  });
  s += '</svg>';
  return s;
}

/* ---------------------------------------------------------------- compare */

async function initCompare() {
  const body = $('compare-body');
  body.innerHTML = loadingHTML('Loading fingerprint diff…');
  let cmp;
  try {
    cmp = await apiRaw('/api/compare');
  } catch (e) {
    body.textContent = '';
    body.append(errorPanel(e, initCompare));
    return;
  }
  if (!cmp || cmp.supported === false) {
    state.compare = null;
    renderCompareUnsupported(cmp && cmp.error);
    return;
  }
  let findings = [];
  try {
    findings = (await api('/api/findings')).findings || [];
  } catch { /* severity/fid matching simply stays empty */ }
  state.compare = cmp;
  renderCompare(cmp, findings);
}

function renderCompareUnsupported(err) {
  const body = $('compare-body');
  body.textContent = '';
  const box = el('div', { class: 'empty-state' });
  box.append(el('p', { text: 'Compare is not available: ' + (err || 'no baseline scan was given at server start.') }));
  box.append(el('p', { text: 'Restart the UI with a baseline scan to enable the diff:' }));
  box.append(el('code', { class: 'fix-cmd', text: 'python agents_doctor.py ui --scan scan.json --baseline old-scan.json' }));
  body.append(box);
}

const CMP_SECTIONS = [
  { key: 'new', label: 'NEW', hint: 'fingerprints that appeared since the baseline' },
  { key: 'resolved', label: 'RESOLVED', hint: 'baseline fingerprints no longer present' },
  { key: 'persisting', label: 'PERSISTING', hint: 'same fingerprints in both scans' },
  { key: 'changed', label: 'CHANGED', hint: 'same section+path, reshaped fingerprint (also counted as new)' },
];

function buildFindingIndex(findings) {
  const idx = new Map();
  for (const f of findings) {
    if (f.status === 'pass' || f.status === 'not_applicable') continue;
    for (const ev of f.evidence || []) {
      if (!ev.file) continue;
      const p = String(ev.file).replace(/\\/g, '/');
      const cur = idx.get(p);
      if (!cur || (SEV_WEIGHT[f.severity] || 0) > (SEV_WEIGHT[cur.severity] || 0)) idx.set(p, f);
    }
  }
  return idx;
}

function matchFinding(idx, entryPath) {
  const p = String(entryPath || '').replace(/\\/g, '/');
  if (idx.has(p)) return idx.get(p);
  const base = p.split(' | ')[0].trim();
  return base ? idx.get(base) || null : null;
}

function renderCompare(cmp, currentFindings) {
  const body = $('compare-body');
  body.textContent = '';
  const idx = buildFindingIndex(currentFindings);

  const head = el('p', { class: 'conf-note' });
  head.textContent = `baseline: ${cmp.baseline_generated_at || '?'}   ·   current: ${cmp.current_generated_at || '?'}`;
  body.append(head);

  const chips = el('div', { class: 'ov-stats' });
  for (const sec of CMP_SECTIONS) {
    const n = (cmp.summary || {})[sec.key] || 0;
    const box = el('div', { class: 'stat-box', title: sec.hint });
    box.append(el('div', { class: 'stat-key', text: sec.label }));
    box.append(el('div', { class: 'stat-val', text: String(n) }));
    chips.append(box);
  }
  body.append(chips);

  const diff = cmp.diff || {};
  for (const sec of CMP_SECTIONS) {
    const entries = diff[sec.key] || [];
    body.append(el('div', { class: 'ov-section-title', text: `${sec.label} (${entries.length}) — ${sec.hint}` }));
    if (!entries.length) {
      body.append(el('div', { class: 'empty-state', text: 'None.' }));
      continue;
    }
    const table = el('table', { class: 'tbl', 'aria-label': sec.label + ' findings' });
    table.append(el('thead', {}, el('tr', {},
      el('th', { text: 'Severity' }), el('th', { text: 'Section' }),
      el('th', { text: 'Path' }), el('th', { text: 'Current finding' }))));
    const tbody = el('tbody');
    for (const entry of entries) {
      const match = matchFinding(idx, entry.path);
      const clickable = !!(match && match.fid);
      const tr = el('tr', {
        class: clickable ? 'row-click fnd-row' : 'fnd-row',
        'data-severity': match ? match.severity : 'info',
        title: clickable ? 'Open finding ' + match.fid : 'no matching finding in the current scan',
      });
      if (clickable) tr.addEventListener('click', () => openFindingCard(match.fid, { push: true }));
      tr.append(
        el('td', {}, match ? sevBadge(match.severity) : el('span', { class: 'mono subtle', text: '—' })),
        el('td', { class: 'mono', text: entry.section || '?' }),
        el('td', { class: 'mono', text: String(entry.path || '?').replace(/\\/g, '/') }),
        el('td', { class: 'mono', text: match ? match.fid : '—' }),
      );
      tbody.append(tr);
    }
    table.append(tbody);
    body.append(table);
  }
}

/* ------------------------------------------------------------- health score */

function scoreColor(v) {
  if (v == null) return '#646b78';
  if (v >= 80) return '#46ad6e';
  if (v >= 60) return '#e08b28';
  return '#e5534b';
}

function scoreGaugeSvg(score) {
  const R = 46;
  const C = 2 * Math.PI * R;
  const frac = score == null ? 0 : Math.max(0, Math.min(100, score)) / 100;
  let s = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 120 120" width="120" height="120" role="img" aria-label="Workspace Health Score ${score == null ? 'unknown' : score + ' of 100'}" class="score-gauge">`;
  s += '<title>Workspace Health Score</title>';
  s += `<circle cx="60" cy="60" r="${R}" fill="none" stroke="#3a4150" stroke-width="10"/>`;
  if (score != null) {
    s += `<circle cx="60" cy="60" r="${R}" fill="none" stroke="${scoreColor(score)}" stroke-width="10" stroke-linecap="round" stroke-dasharray="${(C * frac).toFixed(1)} ${C.toFixed(1)}" transform="rotate(-90 60 60)"/>`;
  }
  s += `<text x="60" y="57" text-anchor="middle" font-family="ui-monospace,Consolas,monospace" font-size="26" fill="#d6d9e0">${score == null ? '?' : Math.round(score)}</text>`;
  s += `<text x="60" y="76" text-anchor="middle" font-family="ui-monospace,Consolas,monospace" font-size="10" fill="#8b919d">/ 100</text>`;
  s += '</svg>';
  return s;
}

async function loadScoreBlock() {
  try {
    state.score = await api('/api/score');
  } catch (e) {
    state.score = { error: e.message };
  }
  renderScoreBlock();
}

function renderScoreBlock() {
  const box = $('ov-score');
  if (!box) return;
  box.textContent = '';
  box.append(el('div', { class: 'ov-section-title', text: 'Workspace Health Score' }));
  if (!state.score) {
    box.append(el('div', { class: 'loading', html: loadingHTML('Loading score…') }));
    return;
  }
  if (state.score.error) {
    box.append(el('div', { class: 'empty-state', text: 'Health Score unavailable: ' + state.score.error }));
    return;
  }
  const sc = state.score;
  const wrap = el('div', { class: 'score-block' });
  const gauge = el('div', { class: 'score-gauge-wrap' });
  gauge.append(el('div', { html: scoreGaugeSvg(sc.score) }));
  if (sc.critical_cap) {
    gauge.append(el('span', {
      class: 'cap-badge',
      title: 'a failing critical finding caps the total at 40 regardless of the component scores',
      text: 'critical cap 40',
    }));
  }
  wrap.append(gauge);
  const comps = el('div', { class: 'score-comps' });
  for (const [name, c] of Object.entries(sc.components || {})) {
    const row = el('div', { class: 'score-comp' });
    row.append(el('span', {
      class: 'score-comp-name',
      text: name + (c.gates && c.gates.length ? ' (' + c.gates.join(', ') + ')' : ' (history)'),
    }));
    const bar = el('span', { class: 'score-comp-bar' });
    if (c.score != null) {
      bar.append(el('span', {
        class: 'score-comp-fill',
        style: `width:${Math.max(0, Math.min(100, c.score))}%; background:${scoreColor(c.score)}`,
      }));
    }
    row.append(bar);
    row.append(el('span', {
      class: 'score-comp-val mono',
      text: c.score == null ? 'no data' : `${c.score} · w ${c.weight}`,
    }));
    comps.append(row);
  }
  wrap.append(comps);
  if (sc.score == null && sc.note) {
    wrap.append(el('div', { class: 'conf-note', text: sc.note }));
  }
  wrap.append(el('div', {
    class: 'conf-note',
    text: 'formula: ' + (sc.formula || '?') + ' · computed ' + (sc.computed_at || '?') +
      (sc.history_available ? ' · history on' : ' · no history: observability 0'),
  }));
  box.append(wrap);
}

/* -------------------------------------------------- detected environments */

async function loadEnvSummary() {
  try {
    await ensureHarnessOptions();
  } catch { /* the card below shows what it has */ }
  renderEnvSummary();
}

function renderEnvSummary() {
  const box = $('ov-env');
  if (!box) return;
  box.textContent = '';
  const h = state.harnesses || {};
  const matrix = h.spec_matrix || [];
  const names = new Map(matrix.map((m) => [m.harness_id, m.display_name || m.harness_id]));
  const detected = (h.detected || []).filter((d) => d && d.status && d.status !== 'not_detected');
  const card = el('div', { class: 'env-card' });
  card.append(el('div', { class: 'ov-section-title', text: 'Detected environments' }));
  const line = el('div', { class: 'env-chips' });
  if (!detected.length) {
    line.append(el('span', { class: 'conf-note', text: 'no agent environments detected in this workspace' }));
  } else {
    for (const d of detected) {
      line.append(el('span', {
        class: 'env-chip',
        title: 'status: ' + d.status +
          (d.version ? ' · version ' + d.version : '') +
          (d.confidence != null ? ' · confidence ' + Number(d.confidence).toFixed(2) : ''),
        text: (names.get(d.harness) || d.harness || '?') + (d.version ? ' ' + d.version : ''),
      }));
    }
    line.append(el('span', {
      class: 'conf-note',
      text: `${detected.length} of ${Math.max(matrix.length, detected.length)} known environments`,
    }));
  }
  card.append(line);
  box.append(card);
}

/* -------------------------------------------------------------- history tab */

const HIST_DIFF_CAP = 10;   // list entries per diff section

function rootParam() {
  return state.overview && state.overview.root ? String(state.overview.root) : '';
}

async function initHistoryTab() {
  const body = $('history-body');
  body.innerHTML = loadingHTML('Loading audit history…');
  const params = { root: rootParam() };
  try {
    const [hist, trend] = await Promise.all([
      api('/api/history', params),
      api('/api/trend', params).catch(() => ({ available: false, points: [] })),
    ]);
    state.hist.data = hist;
    state.hist.trend = trend;
    state.hist.sel = [];
    state.hist.diff = null;
    renderHistoryTab();
  } catch (e) {
    body.textContent = '';
    body.append(errorPanel(e, initHistoryTab));
  }
}

function renderHistoryTab() {
  const body = $('history-body');
  body.textContent = '';
  const data = state.hist.data;
  if (!data || !data.available || !(data.scans || []).length) {
    const box = el('div', { class: 'empty-state' });
    box.append(el('p', { text: data && data.error ? data.error : 'No audit history recorded in this workspace yet.' }));
    box.append(el('p', { text: 'Every successful audit records itself into <root>/.agents-doctor/history.db. Run one:' }));
    box.append(el('code', { class: 'fix-cmd', text: 'python skills/agents-doctor/scripts/agents_doctor.py audit <root>' }));
    box.append(el('p', { text: 'or record an existing scan report:' }));
    box.append(el('code', { class: 'fix-cmd', text: 'python skills/agents-doctor/scripts/agents_doctor.py history <root> --record scan.json' }));
    body.append(box);
    return;
  }

  body.append(el('div', { class: 'ov-section-title', text: 'Findings over time' }));
  const points = (state.hist.trend && state.hist.trend.points) || [];
  if (points.length) {
    body.append(el('div', { class: 'hist-chart', html: trendSvg(points) }));
  } else {
    body.append(el('div', {
      class: 'empty-state',
      text: 'No trend points for this root (the database exists but holds no scans of the audited root).',
    }));
  }

  body.append(el('div', { class: 'ov-section-title', text: 'Recorded scans' }));
  body.append(el('p', {
    class: 'conf-note',
    text: `Click two rows to diff them (before \u2192 after). ${data.scans.length} scan(s), newest first.`,
  }));
  body.append(buildScansTable(data.scans));

  body.append(el('div', { class: 'ov-section-title', text: 'Regressions in the newest scan' }));
  const regs = data.regressions || [];
  if (!regs.length) {
    body.append(el('div', { class: 'empty-state', text: 'None: nothing got worse compared to the previous scan of this root.' }));
  } else {
    const ul = el('ul', { class: 'hist-regs' });
    for (const r of regs) {
      const li = el('li', {});
      li.append(el('span', {
        class: 'mono',
        text: (r.fid || r.check_id || '?') + (r.check_id && r.fid ? ' ' + r.check_id : '') + (r.harness ? ' @' + r.harness : '') + ' [' + (r.gate || '?') + ']',
      }));
      li.append(el('span', { class: 'mono subtle', text: '  ' + (r.reasons || []).join('; ') }));
      ul.append(li);
    }
    body.append(ul);
  }

  body.append(el('div', { id: 'hist-diff' }));
  renderHistoryDiff();
}

function buildScansTable(scans) {
  const table = el('table', { class: 'tbl', 'aria-label': 'Recorded scans' });
  table.append(el('thead', {}, el('tr', {},
    el('th', { text: 'id' }), el('th', { text: 'Date' }),
    el('th', { class: 'num', text: 'Total' }),
    el('th', { class: 'num', text: 'Critical' }),
    el('th', { class: 'num', text: 'High' }))));
  const tbody = el('tbody');
  for (const s of scans) {
    const sev = s.severity_counts || {};
    const tr = el('tr', {
      class: 'row-click hist-scan-row',
      'data-scan': String(s.id),
      'aria-selected': 'false',
      tabindex: '0',
      title: 'Select for diff (pick two rows)',
    });
    tr.append(
      el('td', { class: 'mono', text: String(s.id) }),
      el('td', { class: 'mono', text: s.ts || '?' }),
      el('td', { class: 'num', text: s.findings_total != null ? String(s.findings_total) : '?' }),
      el('td', { class: 'num', text: String(sev.critical || 0) }),
      el('td', { class: 'num', text: String(sev.high || 0) }),
    );
    const activate = () => toggleScanSel(s.id);
    tr.addEventListener('click', activate);
    tr.addEventListener('keydown', (ev) => {
      if (ev.key === 'Enter') { ev.preventDefault(); activate(); }
    });
    tbody.append(tr);
  }
  table.append(tbody);
  return table;
}

function toggleScanSel(id) {
  const sel = state.hist.sel;
  const i = sel.indexOf(id);
  if (i >= 0) sel.splice(i, 1);
  else {
    sel.push(id);
    if (sel.length > 2) sel.shift();
  }
  state.hist.diff = null;
  for (const row of $('history-body').querySelectorAll('.hist-scan-row')) {
    const sid = Number(row.getAttribute('data-scan'));
    const on = sel.includes(sid);
    row.classList.toggle('hist-sel', on);
    row.setAttribute('aria-selected', String(on));
  }
  renderHistoryDiff();
}

async function renderHistoryDiff() {
  const box = $('hist-diff');
  if (!box) return;
  box.textContent = '';
  const sel = state.hist.sel;
  if (sel.length < 2) {
    if (sel.length === 1) {
      box.append(el('p', { class: 'conf-note', text: 'One scan selected — click one more row to diff.' }));
    }
    return;
  }
  const [oldId, newId] = sel;
  box.append(el('div', { class: 'ov-section-title', text: `Diff: scan ${oldId} \u2192 scan ${newId}` }));
  const holder = el('div', {});
  box.append(holder);
  holder.innerHTML = loadingHTML('Loading diff…');
  let data;
  try {
    data = await api('/api/diff', { root: rootParam(), old: String(oldId), new: String(newId) });
  } catch (e) {
    holder.textContent = '';
    holder.append(el('div', { class: 'empty-state', text: 'Diff failed: ' + e.message }));
    return;
  }
  if (state.hist.sel[0] !== oldId || state.hist.sel[1] !== newId) return;  // selection moved on
  holder.textContent = '';
  if (!data.supported) {
    holder.append(el('div', { class: 'empty-state', text: data.error || 'diff unavailable' }));
    return;
  }
  state.hist.diff = data;
  const chips = el('div', { class: 'ov-stats' });
  for (const sec of HIST_DIFF_SECTIONS) {
    chips.append(el('div', { class: 'stat-box', title: sec.hint },
      el('div', { class: 'stat-key', text: sec.label }),
      el('div', { class: 'stat-val', text: String((data.summary || {})[sec.key] || 0) })));
  }
  holder.append(chips);
  const diff = data.diff || {};
  for (const sec of HIST_DIFF_SECTIONS) {
    const entries = diff[sec.key] || [];
    holder.append(el('div', { class: 'ov-section-title', text: `${sec.label} (${entries.length}) — ${sec.hint}` }));
    if (!entries.length) {
      holder.append(el('div', { class: 'empty-state', text: 'None.' }));
      continue;
    }
    const ul = el('ul', { class: 'hist-diff-list' });
    for (const f of entries.slice(0, HIST_DIFF_CAP)) {
      ul.append(el('li', {
        class: 'mono subtle',
        text: (f.section || '?') + '  ' + String(f.path || '?').replace(/\\/g, '/'),
      }));
    }
    holder.append(ul);
    if (entries.length > HIST_DIFF_CAP) {
      holder.append(el('div', { class: 'conf-note', text: `+${entries.length - HIST_DIFF_CAP} more not shown` }));
    }
  }
}

const HIST_DIFF_SECTIONS = [
  { key: 'new', label: 'NEW', hint: 'fingerprints that appeared in the newer scan' },
  { key: 'resolved', label: 'RESOLVED', hint: 'fingerprints of the older scan no longer present' },
  { key: 'changed', label: 'CHANGED', hint: 'same section+path, reshaped fingerprint (also counted as new)' },
];

/** Findings-per-scan chart: SVG polyline, one point per scan, x scaled
    by scan time, separate lines for total / critical / high. */
function trendSvg(points) {
  const W = 760, H = 220, L = 44, Rp = 12, T = 14, B = 34;
  const iw = W - L - Rp, ih = H - T - B;
  const ts = points.map((p) => Date.parse(p.ts));
  const t0 = Math.min(...ts), t1 = Math.max(...ts);
  const x = (i) => (t1 === t0 ? L + iw / 2 : L + iw * (ts[i] - t0) / (t1 - t0));
  const maxV = Math.max(1, ...points.map((p) => Number(p.total) || 0));
  const y = (v) => T + ih * (1 - v / maxV);
  const line = (key) => points.map((p, i) => `${x(i).toFixed(1)},${y(Number(p[key]) || 0).toFixed(1)}`).join(' ');
  const INK = '#d6d9e0', MUT = '#8b919d', GRID = '#2d323d';
  const series = [
    { key: 'total', color: '#5289c7' },
    { key: 'critical', color: '#e5534b' },
    { key: 'high', color: '#e08b28' },
  ];
  let s = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" width="100%" role="img" aria-label="Findings over time, ${points.length} scans" class="trend-svg">`;
  s += '<title>Findings per scan</title>';
  for (const frac of [0, 0.5, 1]) {
    const gy = (T + ih * (1 - frac)).toFixed(1);
    s += `<line x1="${L}" y1="${gy}" x2="${W - Rp}" y2="${gy}" stroke="${GRID}" stroke-width="1"/>`;
    s += `<text x="${L - 6}" y="${Number(gy) + 4}" text-anchor="end" font-family="ui-monospace,Consolas,monospace" font-size="10" fill="${MUT}">${Math.round(maxV * frac)}</text>`;
  }
  for (const sr of series) {
    s += `<polyline points="${line(sr.key)}" fill="none" stroke="${sr.color}" stroke-width="1.6"/>`;
  }
  points.forEach((p, i) => {
    for (const sr of series) {
      s += `<circle cx="${x(i).toFixed(1)}" cy="${y(Number(p[sr.key]) || 0).toFixed(1)}" r="2.6" fill="${sr.color}"><title>${esc(p.ts || '?')}: ${sr.key} ${p[sr.key] || 0} (total ${p.total || 0})</title></circle>`;
    }
  });
  const xlbl = (i, anchor) => {
    s += `<text x="${x(i).toFixed(1)}" y="${H - 10}" text-anchor="${anchor}" font-family="ui-monospace,Consolas,monospace" font-size="10" fill="${MUT}">${esc(String(points[i].ts || '').slice(0, 10))}</text>`;
  };
  xlbl(0, 'start');
  if (points.length > 2) xlbl(Math.floor((points.length - 1) / 2), 'middle');
  if (points.length > 1) xlbl(points.length - 1, 'end');
  let lx = L + 4;
  for (const sr of series) {
    s += `<line x1="${lx}" y1="${T - 4}" x2="${lx + 14}" y2="${T - 4}" stroke="${sr.color}" stroke-width="2"/>`;
    s += `<text x="${lx + 18}" y="${T - 1}" font-family="ui-monospace,Consolas,monospace" font-size="10" fill="${INK}">${sr.key}</text>`;
    lx += 30 + sr.key.length * 6;
  }
  s += '</svg>';
  return s;
}

/* ----------------------------------------------------------------- rescan */

async function rescan() {
  const btn = $('btn-rescan');
  btn.disabled = true;
  btn.textContent = 'Rescanning…';
  try {
    const res = await api('/api/rescan', {}, 'POST');
    // drop all caches, keep filters and UI state
    state.tree.cache.clear();
    state.tree.expanded.clear();
    state.tree.flat = false;
    state.tree.flatRows = null;
    state.tree.focusIdx = null;
    state.tree.searchResults = null;
    hideSearchResults();
    updateTreeCount(0, 0);
    state.treemap.nodes.clear();
    state.treemap.stats.clear();
    state.treemap.statsGen++;   // in-flight stats responses drop themselves
    state.treemap.zoom = '';
    state.treemap.selected = null;
    state.simulate.result = null;
    state.instructions = null;
    state.compare = null;
    state.score = null;          // health score refetches with the overview
    state.hist.data = null;      // history tab reloads on next open
    state.hist.trend = null;
    state.hist.sel = [];
    state.hist.diff = null;
    initedTabs.delete('instructions');
    initedTabs.delete('simulate');
    initedTabs.delete('compare');
    initedTabs.delete('history');
    await loadOverview();
    state.harnesses = null;
    await ensureHarnessOptions();
    if (initedTabs.has('simulate') || $('sim-harness').options.length) {
      fillHarnessSelect($('sim-harness'), 'all harnesses');
    }
    toast(`Rescan finished: ${res.findings} findings. Current view reloaded.`);
    // refresh whatever the user is looking at
    if (state.tab === 'tree') initTree();
    else if (state.tab === 'treemap') initTreemap();
    else if (state.tab === 'instructions') initInstructions();
    else if (state.tab === 'findings' && state.findings.loadedOnce) loadFindings();
    else if (state.tab === 'compare') initCompare();
    else if (state.tab === 'history') initHistoryTab();
    else if (state.tab === 'simulate') {
      $('simulate-body').innerHTML = emptyHTML('Scan changed after rescan — press Run to simulate again.');
    }
    if (state.inspector.path) openInspector(state.inspector.path, state.inspector.line, { push: false });
  } catch (e) {
    toast('Rescan failed: ' + e.message);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Rescan';
  }
}

/* ------------------------------------------------------------- global keys */

function globalKeydown(ev) {
  if (ev.altKey && ev.key === 'ArrowLeft') { ev.preventDefault(); historyGo(-1); return; }
  if (ev.altKey && ev.key === 'ArrowRight') { ev.preventDefault(); historyGo(1); return; }
  if (ev.key === 'Escape') {
    if (!$('card-overlay').hidden) { closeFindingCard(); return; }
    if (state.tab === 'tree' && !$('tree-search-results').hidden) {
      hideSearchResults();
      return;
    }
    if (state.tab === 'treemap' && !$('treemap-tooltip').hidden) {
      $('treemap-tooltip').hidden = true;
      return;
    }
    if (!$('inspector').hidden) { closeInspector(); return; }
    if (state.tab === 'treemap') treemapZoomOut();
  }
}

/* -------------------------------------------------------------------- boot */

function bindUI() {
  document.querySelectorAll('.tab').forEach((btn) => {
    btn.addEventListener('click', () => switchTab(btn.dataset.tab));
  });
  $('btn-rescan').addEventListener('click', rescan);
  $('btn-back').addEventListener('click', () => historyGo(-1));
  $('btn-fwd').addEventListener('click', () => historyGo(1));

  $('tree-search').addEventListener('input', onTreeSearchInput);
  $('tree-search-scope').addEventListener('change', onTreeSearchInput);
  $('tree-sort').addEventListener('change', (ev) => {
    state.tree.sort = ev.target.value;
    renderTree();
  });
  $('tree-expand-all').addEventListener('click', () => {
    for (const [rel, e] of state.tree.cache) {
      if (e.children) {
        for (const c of e.children) if (c.is_dir) state.tree.expanded.add(c.path);
      }
    }
    renderTree();
  });
  $('tree-collapse-all').addEventListener('click', () => {
    state.tree.expanded.clear();
    renderTree();
  });
  $('tree-body').addEventListener('keydown', treeKeydown);
  $('tree-body').addEventListener('scroll', onTreeScroll, { passive: true });

  $('fnd-gate').addEventListener('change', (ev) => {
    state.findings.gate = ev.target.value;
    loadFindings();
  });
  $('fnd-harness').addEventListener('change', (ev) => {
    state.findings.harness = ev.target.value;
    loadFindings();
  });
  let qTimer = null;
  $('fnd-q').addEventListener('input', (ev) => {
    clearTimeout(qTimer);
    const v = ev.target.value;
    qTimer = setTimeout(() => { state.findings.q = v; loadFindings(); }, 300);
  });
  $('fnd-group').addEventListener('change', (ev) => {
    state.findings.group = ev.target.checked;
    renderFindings();
  });

  $('insp-close').addEventListener('click', closeInspector);
  $('card-close').addEventListener('click', closeFindingCard);
  $('card-overlay').addEventListener('click', (ev) => {
    if (ev.target === $('card-overlay')) closeFindingCard();
  });

  $('metric-density').addEventListener('click', () => setTreemapMetric('density'));
  $('metric-risk').addEventListener('click', () => setTreemapMetric('risk'));
  $('metric-disk').addEventListener('click', () => setTreemapMetric('disk'));

  $('treemap-body').addEventListener('click', onTreemapClick);
  $('treemap-body').addEventListener('dblclick', onTreemapDblclick);
  $('treemap-body').addEventListener('keydown', onTreemapKeydown);

  $('sim-run').addEventListener('click', runSimulate);
  $('sim-target').addEventListener('keydown', (evx) => {
    if (evx.key === 'Enter') runSimulate();
  });
  $('ins-harness').addEventListener('change', () => renderInstructionsDiagram());

  let resizeTimer = null;
  let treeResizeTimer = null;
  window.addEventListener('resize', () => {
    if (state.tab === 'treemap' && state.treemap.nodes.size) {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(renderTreemap, 150);
    }
    if (state.tab === 'tree' && state.tree.flat) {
      clearTimeout(treeResizeTimer);
      treeResizeTimer = setTimeout(renderTreeWindow, 100);
    }
  });

  document.addEventListener('keydown', globalKeydown);
}

function setTreemapMetric(m) {
  state.treemap.metric = m;
  $('metric-density').setAttribute('aria-pressed', String(m === 'density'));
  $('metric-risk').setAttribute('aria-pressed', String(m === 'risk'));
  $('metric-disk').setAttribute('aria-pressed', String(m === 'disk'));
  $('metric-formula').textContent =
    m === 'risk' ? 'Risk = 5\u00b7crit + 4\u00b7high + 3\u00b7med + 2\u00b7low + 1\u00b7info (sum over subtree)'
    : m === 'disk' ? 'Disk = file sizes from /api/tree + directory totals from /api/tree/stats (\u2026 loading, \u2248 partial); severity filter does not apply'
    : 'Density = count of findings in subtree';
  if (state.treemap.nodes.size) renderTreemap();
}

/* Inline styles for the aux containers (search results dropdown,
   treemap scale legend) — kept out of style.css on purpose. */
function styleAuxBoxes() {
  const srb = $('tree-search-results');
  if (srb) {
    srb.style.maxHeight = '240px';
    srb.style.overflowY = 'auto';
    srb.style.padding = '2px 10px 6px';
    srb.style.borderBottom = '1px solid var(--border)';
    srb.style.background = 'rgba(20,22,27,.6)';
  }
  const lg = $('treemap-legend');
  if (lg) {
    lg.style.padding = '2px 10px';
    lg.style.fontSize = '11px';
    lg.style.color = 'var(--text-muted)';
    lg.style.whiteSpace = 'nowrap';
    lg.style.overflow = 'hidden';
    lg.style.textOverflow = 'ellipsis';
  }
}

function boot() {
  bindUI();
  styleAuxBoxes();
  updateHistoryButtons();
  switchTab('overview');
}

/* Browser: boot on DOM ready. Node (smoke test of the pure decision
   tables): skip the DOM entirely and export them via CommonJS. */
if (typeof document !== 'undefined') {
  document.addEventListener('DOMContentLoaded', boot);
}
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { resolveTreemapClick, resolveTreemapKey };
}
})();
