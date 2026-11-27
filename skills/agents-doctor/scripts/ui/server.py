"""Local web UI server.

    python skills/agents-doctor/scripts/ui/server.py --scan scan.json
    python .../ui/server.py --root <workspace>   # runs a fresh scan

Serves a single-page app from ui/static plus a JSON API over one
scan.json. Binds 127.0.0.1 only; no requests leave the machine.

Safety rules:
- every file path is resolved and contained under the audited root
  before anything is opened (symlinks resolved first);
- file previews are size-capped and secret-masked: lines matching a
  secret rule show the mask, never the value;
- static assets come only from the packaged ui/static directory;
- read-only: no endpoint writes, moves or executes anything. The
  remediation preview endpoint plans fixes but never applies them.

Request security (threat model: hostile pages open in other tabs of the
local browser):
- DNS-rebinding defense: every request must carry Host 127.0.0.1[:port]
  or localhost[:port] (exact port when present), else 403 + log;
- CSRF defense on the mutating endpoint (POST /api/rescan): browsers
  must send a local Origin/Referer and non-cross-site Sec-Fetch-Site;
  Origin-less clients (curl) need --token mode or the explicit
  'X-Agents-Doctor: local' header;
- optional --token: /api/* then requires 'Authorization: Bearer <t>'
  or '?token='; static files stay open (readable, not sensitive);
- static responses carry a Content-Security-Policy and nosniff.

API (all GET unless noted, JSON):
  /api/overview                      stats, gates, severity/status counts
  /api/harnesses                     detection + spec matrix
  /api/findings                      ?severity= &gate= &status= &harness= &q=
  /api/finding/<fid>                 one finding in full
  /api/tree                          ?path= &cursor= &sort= &sev=
                                     paged children + counts
  /api/tree/stats                    ?path=<rel>  recursive size
                                     accounting with a fingerprint cache
  /api/search                        ?q= &limit=  name search over the
                                     whole workspace, not just loaded tree
  /api/file                          ?path=<rel>  masked text preview
  /api/simulate                      ?target=<rel> &harness=<id>
  /api/fixplan                       ?fid=<id> remediation plan (dry)
  /api/mcp                           MCP server inventory (secret-free)
  /api/rescan              (POST)    rerun the scan in-process
  /api/score                         Workspace Health Score
  /api/history             ?root=    last N recorded scans + regressions
                                     of the newest one (audit_history db)
  /api/trend               ?root=    one point per scan, oldest first
  /api/diff                ?root=&old=&new=   fingerprint diff between
                                     two recorded scans
"""
from __future__ import annotations

import argparse
import hmac
import json
import mimetypes
import os
import re
import secrets
import sys
import threading
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

UI_DIR = Path(__file__).resolve().parent
SCRIPTS = UI_DIR.parent
sys.path.insert(0, str(SCRIPTS))

import audit_scan          # noqa: E402  (in-process rescan)
import audit_history       # noqa: E402  (governance dashboard data)
import mcp_inventory       # noqa: E402  (MCP server inventory)
import secret_rules        # noqa: E402  (preview masking)
import remediate           # noqa: E402  (dry-run plans only)

MAX_PREVIEW_BYTES = 256 * 1024
TREE_PAGE = 500            # /api/tree page size
SEARCH_SCAN_CAP = 100_000  # max entries visited by one /api/search
SEARCH_LIMIT_DEFAULT = 100
SEARCH_LIMIT_MAX = 500
SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info']
TREE_SORTS = ('name', 'size', 'problems')
HISTORY_LIMIT_DEFAULT = 50   # /api/history scans per page
HISTORY_LIMIT_MAX = 500

# Workspace Health Score. Component groups over the audit gates; the
# weight of every component is a code constant on purpose: a read-only
# local UI has no honest place to configure them from (a settings panel
# would invite score tuning until the number looks good). Constants keep
# every score reproducible; configurability is future CLI work (a flag
# that bakes the weights into the scan report), not a UI knob.
SCORE_COMPONENTS = (
    ('security', 0.30, ('G6', 'G7')),
    ('config', 0.20, ('G2',)),
    ('instructions', 0.20, ('G3', 'G5')),
    ('harness_compat', 0.15, ('G8', 'G1')),
    ('hygiene', 0.10, ('G4', 'G9')),
)
SCORE_OBSERVABILITY_WEIGHT = 0.05   # observability = history db present
SCORE_FORMULA = 'weighted sum; critical cap 40'


class ApiUsageError(ValueError):
    """Bad query parameter: reported to the wire as HTTP 400."""


class UiState:
    """Shared, lock-guarded state: the loaded report + its root."""

    def __init__(self, report: dict, root: Path, baseline: dict | None = None):
        self.lock = threading.Lock()
        self.report = report
        self.root = root.resolve()
        self.baseline = baseline
        self._counts = _per_file_counts(report)
        # rel-path -> (fingerprint, stats response) for /api/tree/stats;
        # cleared on every reload (POST /api/rescan) because findings
        # and the tree both change underneath
        self._stats_cache = {}

    def reload(self, report: dict, baseline: dict | None = None):
        with self.lock:
            self.report = report
            if baseline is not None:
                self.baseline = baseline
            self._counts = _per_file_counts(report)
            self._stats_cache = {}

    @property
    def counts(self) -> dict:
        with self.lock:
            return self._counts


def _per_file_counts(report: dict) -> dict:
    """rel-path -> {'critical': n, ...} from findings evidence."""
    counts = {}
    for f in report.get('findings_detailed') or []:
        sev = f.get('severity', 'info')
        if f.get('status') in ('pass', 'not_applicable'):
            continue
        for ev in f.get('evidence') or []:
            p = ev.get('file')
            if not p:
                continue
            p = str(p).replace('\\', '/').strip('/')
            entry = counts.setdefault(p, {s: 0 for s in SEVERITY_ORDER})
            entry[sev] = entry.get(sev, 0) + 1
    return counts


def _contain(state: UiState, rel: str) -> Path:
    """Resolve rel under root; raise PermissionError on escape."""
    rel = unquote(rel or '').replace('\\', '/').lstrip('/')
    target = (state.root / rel).resolve()
    root = state.root.resolve()
    if root not in target.parents and target != root:
        raise PermissionError('outside workspace root')
    return target


def _safe_read(target: Path) -> tuple:
    """Read up to the cap. Returns (text, truncated, is_binary)."""
    try:
        size = target.stat().st_size
    except OSError as exc:
        raise FileNotFoundError(str(exc))
    try:
        blob = target.read_bytes()[:MAX_PREVIEW_BYTES + 1]
    except OSError as exc:
        raise FileNotFoundError(str(exc))
    truncated = size > MAX_PREVIEW_BYTES or len(blob) > MAX_PREVIEW_BYTES
    blob = blob[:MAX_PREVIEW_BYTES]
    if b'\x00' in blob[:4096]:
        return ('', truncated, True)
    return (blob.decode('utf-8', errors='replace'), truncated, False)


def _mask_line(line: str) -> str:
    """Replace every secret-rule match on the line with its mask."""
    out = line
    for rule in secret_rules.RULES:
        matches = list(rule['py'].finditer(out))
        if not matches:
            continue
        for m in reversed(matches):
            if '${' in m.group(0):
                continue
            out = out[:m.start()] + rule['mask'] + out[m.end():]
    return out


def _dir_counts(state: UiState, rel_dir: str) -> dict:
    """Aggregated counts for everything under rel_dir ('' = root)."""
    agg = {s: 0 for s in SEVERITY_ORDER}
    prefix = '' if rel_dir in ('', '.') else rel_dir.strip('/') + '/'
    for path, per in state.counts.items():
        if path == rel_dir or path.startswith(prefix):
            for sev, n in per.items():
                agg[sev] += n
    return agg


# ---------------------------------------------------------------- handlers

def api_overview(state: UiState, _qs):
    rep = state.report
    gates = rep.get('gates') or []
    sev = {s: 0 for s in SEVERITY_ORDER}
    st = {}
    for f in rep.get('findings_detailed') or []:
        sev[f.get('severity', 'info')] = sev.get(f.get('severity', 'info'),
                                                 0) + 1
        s = f.get('status', 'unknown')
        st[s] = st.get(s, 0) + 1
    return {
        'root': str(state.root),
        'generated_at': rep.get('generated_at'),
        'schema_version': rep.get('schema_version'),
        'rules_version': rep.get('rules_version'),
        'stats': rep.get('stats') or {},
        'gates': [{'gid': g.get('gid'), 'name': g.get('name'),
                   'status': g.get('status'), 'confidence': g.get('confidence')}
                  for g in gates],
        'severity_counts': sev,
        'status_counts': st,
        'findings_total': len(rep.get('findings_detailed') or []),
    }


def api_harnesses(state: UiState, _qs):
    rep = state.report
    detected = rep.get('harnesses') or []
    try:
        import harness as harness_pkg
        matrix = harness_pkg.spec_matrix()
    except Exception:
        matrix = []
    return {'detected': detected, 'spec_matrix': matrix}


def api_findings(state: UiState, qs):
    sev = qs.get('severity', [None])[0]
    gate = qs.get('gate', [None])[0]
    status = qs.get('status', [None])[0]
    hid = qs.get('harness', [None])[0]
    q = (qs.get('q', [''])[0] or '').lower()
    out = []
    for f in state.report.get('findings_detailed') or []:
        if sev and f.get('severity') != sev:
            continue
        if gate and f.get('gate') != gate:
            continue
        if status and f.get('status') != status:
            continue
        if hid and f.get('harness', '') != hid:
            continue
        if q:
            blob = ' '.join([str(f.get('title', '')),
                             str(f.get('description', '')),
                             str(f.get('fid', '')),
                             json.dumps(f.get('evidence') or [])]).lower()
            if q not in blob:
                continue
        out.append(f)
    return {'count': len(out), 'findings': out}


def api_finding(state: UiState, fid: str):
    for f in state.report.get('findings_detailed') or []:
        if f.get('fid') == fid:
            return f
    return None


def _tree_child(state: UiState, entry) -> dict:
    """One child record for /api/tree: name/path/is_dir/symlink/size/
    mtime/counts, the keys the API had before pagination was added.
    counts come from the full findings map, never from a page."""
    relpath = Path(entry.path).relative_to(state.root).as_posix()
    try:
        is_dir = entry.is_dir()
        symlink = entry.is_symlink()
    except OSError:
        is_dir, symlink = False, False
    child = {
        'name': entry.name,
        'path': relpath,
        'is_dir': is_dir,
        'symlink': symlink,
    }
    try:
        st = entry.stat()
        if not is_dir:
            child['size'] = st.st_size
            child['mtime'] = st.st_mtime
    except OSError:
        child['size'] = None
    if is_dir:
        child['counts'] = _dir_counts(state, relpath)
    else:
        child['counts'] = state.counts.get(relpath,
                                           {s: 0 for s in SEVERITY_ORDER})
    return child


def api_tree(state: UiState, qs):
    """Lazy directory children, paginated.

    ?path=<rel> &cursor=<int offset> &sort=name|size|problems
    &sev=<csv severity filter>. Returns children (one page of
    TREE_PAGE), next_cursor (None when done), total_entries,
    returned_entries, complete, truncated (= not complete; the old
    frontend "Show more" flag). Child counts are computed over ALL
    findings, not over the page. Bad sort/cursor/sev values raise
    ApiUsageError -> HTTP 400."""
    rel = qs.get('path', [''])[0] or ''
    sort = (qs.get('sort', ['name'])[0] or 'name').strip().lower()
    if sort not in TREE_SORTS:
        raise ApiUsageError('sort must be one of %s' % ', '.join(TREE_SORTS))
    raw_cursor = qs.get('cursor', [None])[0]
    if raw_cursor in (None, ''):
        cursor = 0
    else:
        try:
            cursor = int(raw_cursor)
        except (TypeError, ValueError):
            raise ApiUsageError('cursor must be an integer offset')
        if cursor < 0:
            raise ApiUsageError('cursor must be >= 0')
    sev_raw = (qs.get('sev', [''])[0] or '').strip()
    sev_keys = []
    for tok in filter(None, (t.strip().lower() for t in sev_raw.split(','))):
        if tok not in SEVERITY_ORDER:
            raise ApiUsageError(
                'sev must be a csv of %s' % ', '.join(SEVERITY_ORDER))
        sev_keys.append(tok)
    try:
        target = _contain(state, rel)
    except (PermissionError, FileNotFoundError) as exc:
        return {'error': str(exc)}
    if not target.is_dir():
        return {'error': 'not a directory'}
    try:
        with os.scandir(target) as it:
            entries = list(it)
    except OSError as exc:
        return {'error': str(exc)}
    children = [_tree_child(state, e) for e in entries]
    if sev_keys:
        children = [c for c in children
                    if sum(c['counts'].get(s, 0) for s in sev_keys) > 0]
    if sort == 'name':
        children.sort(key=lambda c: (not c['is_dir'], c['name'].casefold()))
    elif sort == 'size':
        # files by size desc first, then dirs by name
        children.sort(key=lambda c: (c['is_dir'], -(c.get('size') or 0),
                                     c['name'].casefold()))
    else:  # problems: total count desc, dirs first on ties
        children.sort(key=lambda c: (-sum(c['counts'].values()),
                                     not c['is_dir'],
                                     c['name'].casefold()))
    total = len(children)
    page = children[cursor:cursor + TREE_PAGE]
    end = cursor + len(page)
    next_cursor = end if end < total else None
    return {
        'path': rel,
        'children': page,
        'next_cursor': next_cursor,
        'total_entries': total,
        'returned_entries': len(page),
        'complete': next_cursor is None,
        'truncated': next_cursor is not None,
        'counts': _dir_counts(state, rel.replace('\\', '/').strip('/')),
    }


# ------------------------------------------------- /api/tree/stats

def _stats_walk(start: Path, root: Path, build_root: bool = False) -> dict:
    """Recursive size accounting with os.scandir.

    Symlinks are skipped entirely (not followed, not counted: no
    double counting, no cycles). Inaccessible directories are
    collected as rel paths in 'inaccessible' and flip 'complete'.
    build_root marks the start itself as a build directory (stats of
    node_modules count everything inside as build bytes). The walk
    also produces the cache fingerprint (max mtime over all entries
    incl. dirs, file count, entry count)."""
    acc = {'total_bytes': 0, 'total_files': 0, 'build_bytes': 0,
           'inaccessible': [], 'nentries': 0, 'max_mtime': None}

    def rec(dir_path: Path, under_build: bool):
        try:
            it = os.scandir(dir_path)
        except OSError:
            acc['inaccessible'].append(
                dir_path.relative_to(root).as_posix())
            return
        with it:
            for entry in it:
                acc['nentries'] += 1
                try:
                    if entry.is_symlink():
                        continue
                    is_dir = entry.is_dir(follow_symlinks=False)
                    st = entry.stat(follow_symlinks=False)
                except OSError:
                    acc['inaccessible'].append(
                        Path(entry.path).relative_to(root).as_posix())
                    continue
                if acc['max_mtime'] is None or st.st_mtime > \
                        acc['max_mtime']:
                    acc['max_mtime'] = st.st_mtime
                if is_dir:
                    rec(Path(entry.path),
                        under_build or entry.name in audit_scan.BUILD_DIRS)
                else:
                    acc['total_files'] += 1
                    acc['total_bytes'] += st.st_size
                    if under_build:
                        acc['build_bytes'] += st.st_size

    rec(start, build_root)
    acc['complete'] = not acc['inaccessible']
    acc['fingerprint'] = (acc['max_mtime'], acc['total_files'],
                          acc['nentries'])
    return acc


def _problem_files_bytes(state: UiState, rel_key: str) -> int:
    """Sum of on-disk sizes of counted files under rel_key ('' = all).
    Vanished or unreadable files are skipped, not guessed."""
    prefix = '' if rel_key == '' else rel_key + '/'
    total = 0
    for rel in state.counts:
        if rel_key != '' and not rel.startswith(prefix):
            continue
        p = state.root / rel
        try:
            if os.path.islink(p):
                continue
            st = os.stat(p, follow_symlinks=False)
        except OSError:
            continue
        total += st.st_size
    return total


def api_tree_stats(state: UiState, qs):
    """Exact recursive sizes for one directory.

    Cached in UiState._stats_cache keyed by rel path; every request
    re-probes the directory fingerprint (max mtime, nfiles, nentries)
    and a mismatch recomputes. POST /api/rescan clears the cache.
    share_of_root_percent is relative to the workspace root (the root
    itself reports 100.0); its denominator comes from the cached root
    stats when available."""
    rel = qs.get('path', [''])[0] or ''
    key = rel.replace('\\', '/').strip('/')
    try:
        target = _contain(state, rel)
    except (PermissionError, FileNotFoundError) as exc:
        return {'error': str(exc)}
    if not target.is_dir():
        return {'error': 'not a directory'}
    raw = _stats_walk(target, state.root,
                      build_root=key != ''
                      and Path(key).name in audit_scan.BUILD_DIRS)
    with state.lock:
        hit = state._stats_cache.get(key)
    if hit is not None and hit[0] == raw['fingerprint']:
        return hit[1]          # same object: callers see a stable hit
    if key == '':
        share = 100.0
    else:
        with state.lock:
            root_hit = state._stats_cache.get('')
        if root_hit is not None:
            root_total = root_hit[1]['total_bytes']
        else:
            root_total = _stats_walk(state.root, state.root)['total_bytes']
        share = round(100.0 * raw['total_bytes'] / root_total, 2) \
            if root_total else 0.0
    result = {
        'path': key,
        'total_bytes': raw['total_bytes'],
        'total_files': raw['total_files'],
        'problem_files_bytes': _problem_files_bytes(state, key),
        'build_bytes': raw['build_bytes'],
        'share_of_root_percent': share,
        'complete': raw['complete'],
        'inaccessible': raw['inaccessible'],
        'computed_at': datetime.now().astimezone().isoformat(
            timespec='seconds'),
    }
    with state.lock:
        state._stats_cache[key] = (raw['fingerprint'], result)
    return result


# ---------------------------------------------------- /api/search

def api_search(state: UiState, qs):
    """Server-side name search over the whole workspace:
    the frontend is no longer limited to the loaded tree. Substring
    match on entry names, casefolded both ways; directories get
    prefix-aggregated counts like _dir_counts. The walk is capped at
    SEARCH_SCAN_CAP entries; hitting the cap (or the limit) sets
    truncated. Only names/paths leave the server: no secrets."""
    q = (qs.get('q', [''])[0] or '')
    if not q.strip():
        raise ApiUsageError('q required')
    raw_limit = qs.get('limit', [str(SEARCH_LIMIT_DEFAULT)])[0]
    try:
        limit = int(raw_limit)
    except (TypeError, ValueError):
        raise ApiUsageError('limit must be an integer')
    if limit < 1:
        raise ApiUsageError('limit must be >= 1')
    limit = min(limit, SEARCH_LIMIT_MAX)
    needle = q.casefold()
    matches = []
    visited = 0
    capped = False
    stack = [state.root]
    while stack and not capped:
        dir_path = stack.pop()
        try:
            it = os.scandir(dir_path)
        except OSError:
            continue
        with it:
            for entry in it:
                visited += 1
                if visited > SEARCH_SCAN_CAP:
                    capped = True
                    break
                try:
                    if needle in entry.name.casefold():
                        relpath = Path(entry.path).relative_to(
                            state.root).as_posix()
                        is_dir = entry.is_dir(follow_symlinks=False)
                        if is_dir:
                            counts = _dir_counts(state, relpath)
                        else:
                            counts = state.counts.get(
                                relpath,
                                {s: 0 for s in SEVERITY_ORDER})
                        matches.append({'path': relpath, 'is_dir': is_dir,
                                        'counts': counts})
                    if (not entry.is_symlink()) \
                            and entry.is_dir(follow_symlinks=False):
                        stack.append(Path(entry.path))
                except OSError:
                    continue
    matches.sort(key=lambda m: m['path'])
    return {
        'matches': matches[:limit],
        'total_matches': len(matches),
        'truncated': len(matches) > limit or capped,
    }


def api_file(state: UiState, qs):
    rel = qs.get('path', [''])[0]
    try:
        target = _contain(state, rel)
        if target.is_dir():
            return {'error': 'is a directory'}
        text, truncated, binary = _safe_read(target)
    except (PermissionError, FileNotFoundError) as exc:
        return {'error': str(exc)}
    if binary:
        return {'path': rel, 'binary': True, 'truncated': truncated,
                'lines': []}
    lines = []
    flagged = []
    for i, raw in enumerate(text.splitlines(), 1):
        rule = secret_rules.find_rule(raw) if raw else None
        if rule:
            flagged.append({'line': i, 'rule': rule['id'],
                            'mask': rule['mask']})
        lines.append(_mask_line(raw))
    return {
        'path': rel,
        'binary': False,
        'truncated': truncated,
        'lines': lines,
        'flagged_lines': flagged,
        'counts': state.counts.get(
            rel.replace('\\', '/').strip('/'),
            {s: 0 for s in SEVERITY_ORDER}),
    }


def api_simulate(state: UiState, qs):
    target = qs.get('target', [''])[0]
    harness_ids = qs.get('harness', [None])[0]
    try:
        from harness import HarnessContext
        from instructions import simulate_loading
        ctx = HarnessContext(root=state.root, home=Path(state.report.get(
            'home') or Path.home()))
        tgt = _contain(state, target) if target else None
        ids = [harness_ids] if harness_ids else None
        return simulate_loading(ctx, tgt, ids)
    except (PermissionError, FileNotFoundError) as exc:
        return {'error': str(exc)}
    except Exception as exc:  # simulation must never kill the server
        return {'error': 'simulation failed: %s' % exc}


def api_fixplan(state: UiState, qs):
    fid = qs.get('fid', [''])[0]
    if not fid:
        return {'error': 'fid required'}
    try:
        steps = remediate.plan(state.report, fid)
    except Exception as exc:
        return {'error': str(exc), 'supported': False}
    return {
        'supported': True,
        'dry_run': True,
        'steps': [{'action': s.get('action'), 'target': s.get('target'),
                   'detail': s.get('detail', '')} for s in steps],
        'note': 'UI never applies fixes; run agents_doctor.py fix --apply',
    }


def api_compare(state: UiState, qs):
    """Fingerprint diff against the baseline scan given at server start
    (never an arbitrary path from the wire)."""
    if not state.baseline:
        return {'error': 'no baseline scan given at server start '
                         '(--baseline old-scan.json)', 'supported': False}
    try:
        diff = remediate.fingerprint_diff(
            state.baseline.get('findings') or [],
            state.report.get('findings') or [])
    except Exception as exc:
        return {'error': str(exc), 'supported': False}
    # the diff hands back the stored finding dicts themselves: copy them,
    # or the first request strips the fingerprints from the scan and every
    # later diff comes back empty
    diff = {name: [{k: v for k, v in f.items() if k != 'fp'}
                   for f in diff.get(name) or []]
            for name in ('new', 'resolved', 'persisting', 'changed')}
    return {
        'supported': True,
        'baseline_generated_at': state.baseline.get('generated_at'),
        'current_generated_at': state.report.get('generated_at'),
        'summary': {k: len(v) for k, v in diff.items()},
        'diff': diff,
    }


def api_mcp(state: UiState, _qs):
    """MCP server inventory across detected harnesses. Secret-free by
    construction: env variable names, command heads and url hosts only
    (see mcp_inventory)."""
    home = Path(state.report.get('home') or Path.home())
    try:
        return mcp_inventory.collect_mcp_inventory(state.root, home)
    except Exception as exc:  # inventory must never kill the server
        return {'error': 'mcp inventory failed: %s' % exc}


# --------------------------------------------------- governance dashboard

def _gate_critical_map(report: dict) -> dict:
    """gid -> True when that gate has at least one fail finding of
    critical severity. The same definition feeds the per-component
    penalty and the global critical cap, so they can never disagree."""
    crit = {}
    for f in report.get('findings_detailed') or []:
        if f.get('severity') == 'critical' and f.get('status') == 'fail':
            crit[f.get('gate')] = True
    return crit


def compute_health_score(report: dict, history_available: bool) -> dict:
    """Workspace Health Score: deterministic, explainable.

    Per component: start at 100; -30 for every gate of the group that
    fails WITH critical findings, -15 for a fail without them, -5 per
    warn; clipped to 0..100. A gate whose status is unknown (or absent
    from the report) makes the whole component null -- absence of data
    is never mixed with a zero score. Overall = weighted sum of the
    components; any critical+fail finding anywhere caps the total at 40
    (critical_cap). Observability is not gate-based: the root-local
    history database exists -> 100, else 0."""
    statuses = {g.get('gid'): g.get('status')
                for g in report.get('gates') or [] if g.get('gid')}
    crit = _gate_critical_map(report)
    components = {}
    insufficient = []
    for name, weight, gids in SCORE_COMPONENTS:
        score = 100
        for gid in gids:
            st = statuses.get(gid)
            if st is None or st == 'unknown':
                score = None       # insufficient data, not a zero
                break
            if st == 'fail':
                score -= 30 if crit.get(gid) else 15
            elif st == 'warn':
                score -= 5
            # pass / not_applicable: no penalty
        if score is None:
            insufficient.append(name)
        else:
            score = max(0, min(100, score))
        components[name] = {'score': score, 'weight': weight,
                            'gates': list(gids)}
    components['observability'] = {
        'score': 100 if history_available else 0,
        'weight': SCORE_OBSERVABILITY_WEIGHT,
        'gates': [],
    }
    out = {
        'components': components,
        'formula': SCORE_FORMULA,
        'critical_cap': False,
        'computed_at': datetime.now().astimezone().isoformat(
            timespec='seconds'),
        'gates_basis': statuses,
    }
    if insufficient:
        out['score'] = None
        out['note'] = ('insufficient data: unknown gate status in %s'
                       % ', '.join(insufficient))
        return out
    total = round(sum(c['score'] * c['weight']
                      for c in components.values()), 2)
    if crit:
        out['critical_cap'] = True
        total = min(total, 40)
    out['score'] = total
    return out


def _history_root(state: UiState, qs):
    """Resolve ?root= for the history endpoints: absent means the
    audited root; any other root is refused -- the UI reads exactly one
    workspace and never opens a foreign database from the wire."""
    raw = (qs.get('root', [''])[0] or '').strip()
    if not raw:
        return state.root
    try:
        resolved = Path(raw).resolve()
    except (OSError, ValueError) as exc:
        raise ApiUsageError('bad root path: %s' % exc)
    if resolved != state.root:
        raise PermissionError('root must match the audited workspace')
    return resolved


def _open_history(state: UiState, qs):
    """(connection-or-None, db_path) for the audited root. None means
    the workspace has no history database yet -- a normal state, not an
    error. One short-lived connection per request: the server is
    threaded and sqlite connections must not cross threads."""
    root = _history_root(state, qs)
    db = audit_history.default_db_path(root)
    if not db.exists():
        return None, db
    return audit_history.init_db(db), db


def api_score(state: UiState, _qs):
    """Workspace Health Score over the loaded report; observability
    comes from the presence of the root-local history database."""
    history_available = audit_history.default_db_path(state.root).exists()
    out = compute_health_score(state.report, history_available)
    out['history_available'] = history_available
    return out


def api_history(state: UiState, qs):
    """Last N recorded scans (newest first) plus the regressions of the
    newest scan. No history database yet -> available: False with
    empty lists, never an error."""
    raw_limit = qs.get('limit', [''])[0]
    if raw_limit in ('', None):
        limit = HISTORY_LIMIT_DEFAULT
    else:
        try:
            limit = int(raw_limit)
        except (TypeError, ValueError):
            raise ApiUsageError('limit must be an integer')
        if not 1 <= limit <= HISTORY_LIMIT_MAX:
            raise ApiUsageError('limit must be between 1 and %d'
                                % HISTORY_LIMIT_MAX)
    try:
        conn, _db = _open_history(state, qs)
    except PermissionError as exc:
        return {'error': str(exc), 'available': False}
    if conn is None:
        return {'available': False, 'scans': [], 'regressions': []}
    try:
        scans = [{'id': s['id'], 'ts': s['ts'],
                  'findings_total': s['findings_total'],
                  'severity_counts': s['severity_counts'],
                  'gate_statuses': s['gate_statuses']}
                 for s in audit_history.list_scans(conn, limit)]
        regs = audit_history.regressions(conn, scans[0]['id']) \
            if scans else []
        return {'available': True, 'scans': scans, 'regressions': regs}
    finally:
        conn.close()


def api_trend(state: UiState, qs):
    """One point per recorded scan of this root, oldest first (the
    audit_history.trend shape: ts, total, one column per severity)."""
    try:
        conn, _db = _open_history(state, qs)
    except PermissionError as exc:
        return {'error': str(exc), 'available': False}
    if conn is None:
        return {'available': False, 'points': []}
    try:
        return {'available': True,
                'points': audit_history.trend(conn, root=str(state.root))}
    finally:
        conn.close()


def api_diff(state: UiState, qs):
    """Fingerprint diff between two recorded scans -- the 'before/after
    the fix' view over the history database. Uses the same engine as
    /api/compare (remediate.fingerprint_diff), so file diffs and
    history diffs can never disagree."""
    raw_old = qs.get('old', [''])[0]
    raw_new = qs.get('new', [''])[0]
    try:
        old_id, new_id = int(raw_old), int(raw_new)
    except (TypeError, ValueError):
        raise ApiUsageError('old and new must be integer scan ids')
    if old_id < 1 or new_id < 1:
        raise ApiUsageError('old and new must be positive scan ids')
    try:
        conn, _db = _open_history(state, qs)
    except PermissionError as exc:
        return {'error': str(exc), 'supported': False}
    if conn is None:
        return {'error': 'no history database in this workspace',
                'supported': False}
    try:
        for sid in (old_id, new_id):
            if audit_history.get_scan(conn, sid) is None:
                return {'error': 'unknown scan id %d' % sid,
                        'supported': False}
        diff = audit_history.diff_scans(conn, old_id, new_id)
    finally:
        conn.close()
    for name in ('new', 'resolved', 'persisting', 'changed'):
        for f in diff.get(name) or []:
            f.pop('fp', None)   # fingerprints are internal
    return {
        'supported': True,
        'old_id': old_id,
        'new_id': new_id,
        'summary': {k: len(v) for k, v in diff.items()},
        'diff': diff,
    }


def make_handler(state: UiState, token: str | None = None):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass  # quiet: the UI is a local tool

        # ---------------------------------------- request security
        def _security_log(self, why: str):
            # log_message is silenced on purpose; security rejects are
            # the one thing worth a stderr line
            print('agents-doctor UI: rejected %s %s (%s)'
                  % (self.command, self.path, why), file=sys.stderr)

        def _port(self) -> int:
            return self.server.server_address[1]

        def _host_allowed(self) -> bool:
            """DNS-rebinding defense: Host must be 127.0.0.1[:port] or
            localhost[:port]; a foreign name or port is a rebound host."""
            host = (self.headers.get('Host') or '').strip().lower()
            return host in ('127.0.0.1', 'localhost',
                            '127.0.0.1:%d' % self._port(),
                            'localhost:%d' % self._port())

        def _token_ok(self, qs) -> bool:
            """--token mode check. Constant-time compare; accepts the
            Authorization: Bearer header or ?token= (the latter only
            for the one printed startup URL and quick curl checks)."""
            if token is None:
                return True
            auth = self.headers.get('Authorization') or ''
            supplied = auth[7:].strip() if auth[:7].lower() == 'bearer ' \
                else ''
            if not supplied:
                supplied = (qs.get('token', [''])[0] or '').strip()
            return bool(supplied) and hmac.compare_digest(supplied, token)

        def _origin_allowed(self, value: str) -> bool:
            try:
                u = urlparse(value)
                eff_port = u.port or (443 if u.scheme == 'https' else 80)
            except ValueError:
                return False
            return (u.scheme == 'http'
                    and (u.hostname or '').lower()
                    in ('127.0.0.1', 'localhost')
                    and eff_port == self._port())

        def _csrf_allowed(self, token_mode: bool) -> bool:
            """POST guard. Browsers send Origin/Referer and (modern
            ones) Sec-Fetch-Site; a cross-site signal or a foreign
            origin is rejected. Origin-less clients (curl) pass only
            in --token mode or with the explicit opt-in header."""
            sfs = (self.headers.get('Sec-Fetch-Site') or '').strip().lower()
            if sfs == 'cross-site':
                return False
            origin = self.headers.get('Origin')
            referer = self.headers.get('Referer')
            if origin is None and referer is None:
                return token_mode or \
                    (self.headers.get('X-Agents-Doctor') or '').strip().lower()\
                    == 'local'
            for value in (origin, referer):
                if value is not None and not self._origin_allowed(value):
                    return False
            return True

        # ---------------------------------------- responses
        def _json(self, obj, code=200):
            body = json.dumps(obj, ensure_ascii=False).encode('utf-8')
            self.send_response(code)
            self.send_header('Content-Type', 'application/json; '
                                             'charset=utf-8')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _static(self, name: str):
            base = (UI_DIR / 'static').resolve()
            target = (base / name).resolve()
            if base not in target.parents and target != base / 'index.html':
                self._json({'error': 'forbidden'}, 403)
                return
            try:
                blob = target.read_bytes()
            except OSError:
                self._json({'error': 'not found'}, 404)
                return
            # .woff/.woff2 are missing from some mimetypes registries
            ctype = {'.woff': 'font/woff', '.woff2': 'font/woff2'}\
                .get(target.suffix.lower()) \
                or mimetypes.guess_type(str(target))[0] or 'text/plain'
            self.send_response(200)
            self.send_header('Content-Type',
                             ctype + ('; charset=utf-8'
                                      if ctype.startswith('text/') else ''))
            self.send_header('Content-Security-Policy',
                             "default-src 'self'; "
                             "style-src 'self' 'unsafe-inline'; "
                             "img-src 'self' data:")
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Content-Length', str(len(blob)))
            self.end_headers()
            self.wfile.write(blob)

        def do_GET(self):
            parsed = urlparse(self.path)
            qs = parse_qs(parsed.query)
            route = parsed.path
            if not self._host_allowed():
                self._security_log('bad Host %r'
                                   % (self.headers.get('Host'),))
                self._json({'error': 'forbidden Host header'}, 403)
                return
            if route.startswith('/api/') and not self._token_ok(qs):
                self._security_log('missing/invalid token')
                self._json({'error': 'unauthorized: token required'}, 401)
                return
            try:
                if route in ('/', '/index.html'):
                    self._static('index.html')
                elif route.startswith('/static/'):
                    self._static(unquote(route[len('/static/'):]))
                elif route == '/api/overview':
                    self._json(api_overview(state, qs))
                elif route == '/api/harnesses':
                    self._json(api_harnesses(state, qs))
                elif route == '/api/findings':
                    self._json(api_findings(state, qs))
                elif route.startswith('/api/finding/'):
                    fid = unquote(route.split('/', 3)[3])
                    obj = api_finding(state, fid)
                    self._json(obj if obj is not None
                               else {'error': 'finding not found'}, 200
                               if obj else 404)
                elif route == '/api/tree/stats':
                    self._json(api_tree_stats(state, qs))
                elif route == '/api/search':
                    self._json(api_search(state, qs))
                elif route == '/api/tree':
                    self._json(api_tree(state, qs))
                elif route == '/api/file':
                    self._json(api_file(state, qs))
                elif route == '/api/simulate':
                    self._json(api_simulate(state, qs))
                elif route == '/api/fixplan':
                    self._json(api_fixplan(state, qs))
                elif route == '/api/compare':
                    self._json(api_compare(state, qs))
                elif route == '/api/mcp':
                    self._json(api_mcp(state, qs))
                elif route == '/api/score':
                    self._json(api_score(state, qs))
                elif route == '/api/history':
                    self._json(api_history(state, qs))
                elif route == '/api/trend':
                    self._json(api_trend(state, qs))
                elif route == '/api/diff':
                    self._json(api_diff(state, qs))
                else:
                    self._json({'error': 'no such route'}, 404)
            except BrokenPipeError:
                pass
            except ApiUsageError as exc:
                self._json({'error': str(exc)}, 400)
            except Exception as exc:  # never leak a traceback to the wire
                self._json({'error': 'internal: %s' % exc}, 500)

        def do_POST(self):
            parsed = urlparse(self.path)
            qs = parse_qs(parsed.query)
            if not self._host_allowed():
                self._security_log('bad Host %r'
                                   % (self.headers.get('Host'),))
                self._json({'error': 'forbidden Host header'}, 403)
                return
            if parsed.path == '/api/rescan':
                if not self._token_ok(qs):
                    self._security_log('missing/invalid token')
                    self._json({'error': 'unauthorized: token required'},
                               401)
                    return
                if not self._csrf_allowed(token is not None):
                    self._security_log('cross-site or foreign origin')
                    self._json({'error': 'cross-site request rejected'},
                               403)
                    return
                try:
                    rep = audit_scan.scan(state.root,
                                          Path(state.report.get('home')
                                               or Path.home()),
                                          False)
                    state.reload(rep)
                    self._json({'rescanned': True,
                                'findings': len(rep.get('findings_detailed')
                                                or [])})
                except Exception as exc:
                    self._json({'error': str(exc)}, 500)
            else:
                self._json({'error': 'no such route'}, 404)

    return Handler


def load_or_scan(scan_path, root, home):
    """Report dict from a scan.json, or a fresh in-process scan."""
    if scan_path:
        rep = json.loads(Path(scan_path).read_text(encoding='utf-8'))
        root = Path(rep.get('root') or root or Path(scan_path).parent)
        return rep, root
    root = Path(root or '.').resolve()
    if not root.is_dir():
        raise SystemExit('not a directory: %s' % root)
    return audit_scan.scan(root, Path(home or Path.home()), False), root


def main(argv=None):
    ap = argparse.ArgumentParser(description='agents-doctor local web UI')
    ap.add_argument('--scan', default=None, help='existing scan.json')
    ap.add_argument('--root', default=None, help='workspace root '
                                                 '(fresh scan when no --scan)')
    ap.add_argument('--home', default=None)
    ap.add_argument('--baseline', default=None, metavar='OLD.json',
                    help='older scan.json: enables the Compare tab')
    ap.add_argument('--port', type=int, default=8765)
    ap.add_argument('--token', action='store_true',
                    help='require a bearer token for /api/* (token is '
                         'generated and printed once at startup)')
    ap.add_argument('--no-open', action='store_true')
    a = ap.parse_args(argv)
    report, root = load_or_scan(a.scan, a.root, a.home)
    baseline = None
    if a.baseline:
        try:
            baseline = json.loads(Path(a.baseline).read_text(
                encoding='utf-8'))
        except (OSError, ValueError) as exc:
            print('warning: baseline unreadable (%s); compare disabled'
                  % exc, file=sys.stderr)
    state = UiState(report, root, baseline)
    api_token = secrets.token_hex(32) if a.token else None
    httpd = ThreadingHTTPServer(('127.0.0.1', a.port),
                                make_handler(state, api_token))
    url = 'http://127.0.0.1:%d/' % a.port
    if api_token:
        # printed exactly once; the query form lets the SPA boot without
        # retyping, later calls use the Authorization header
        url += '?token=' + api_token
    print('agents-doctor UI: %s  (root: %s)  Ctrl+C to stop'
          % (url, state.root))
    if not a.no_open:
        try:
            import webbrowser
            threading.Timer(0.5, lambda: webbrowser.open(url)).start()
        except Exception:
            pass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print('\nstopped')
    return 0


if __name__ == '__main__':
    sys.exit(main())
