"""Continuous monitoring: watch the workspace
configuration and re-audit when it changes.

Design (offline-first, no new dependencies):
- change detection is a fingerprint of the workspace's instruction and
  config files (mtime + size), polled every --interval seconds;
- when it changes, a FULL scan re-runs — mid-size workspaces scan in
  about a second, and per-gate incremental rescans would trade the
  byte-identical reproducibility the QA eval locks. What IS
  incremental is the reporting: only findings NEW since the previous
  run are printed;
- every run lands in the SQLite history (audit_history), so the trend
  survives restarts;
- --once is the daemon-free mode for cron/Task Scheduler: check now,
  rescan if changed, exit.

Secrets never appear here: scans are redacted at source; the history
stores fingerprints and metadata only.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

WATCH_TARGETS = [
    'AGENTS.md', 'CLAUDE.md', 'GEMINI.md',
    '.mcp.json', '.cursorrules', '.windsurfrules',
    '.zcode/config.json', 'opencode.json', 'opencode.jsonc',
]
WATCH_DIRS = ['.claude', '.codex', '.cursor', '.windsurf', '.gemini',
              '.opencode', '.github/instructions', '.github/prompts',
              '.agents/skills']


def _exists(p: Path) -> bool:
    try:
        return p.exists()
    except OSError:
        return False


def config_fingerprint(root: Path) -> str:
    """Stable fingerprint of the watched configuration surface."""
    import hashlib
    parts = []
    for rel in WATCH_TARGETS:
        p = root / rel
        if _exists(p) and p.is_file():
            try:
                st = p.stat()
                parts.append('%s:%d:%d' % (rel, st.st_size,
                                           int(st.st_mtime)))
            except OSError:
                parts.append('%s:?' % rel)
    for rel in WATCH_DIRS:
        d = root / rel
        if not _exists(d) or not d.is_dir():
            continue
        total = entries = 0
        newest = 0
        for p in d.rglob('*'):
            if not p.is_file():
                continue
            try:
                st = p.stat()
            except OSError:
                continue
            entries += 1
            total += st.st_size
            newest = max(newest, int(st.st_mtime))
            if entries > 5000:   # cap: a config dir beyond this is data
                break
        parts.append('%s/%d/%d/%d' % (rel, entries, total, newest))
    blob = '|'.join(parts)
    return hashlib.sha256(blob.encode('utf-8')).hexdigest()[:16]


def _load_state(root: Path) -> dict:
    import json
    p = root / '.agents-doctor' / 'watch-state.json'
    try:
        return json.loads(p.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return {}


def _save_state(root: Path, state: dict):
    import json
    p = root / '.agents-doctor' / 'watch-state.json'
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(state), encoding='utf-8')
    except OSError:
        pass   # state file is an optimization, not a requirement


def watch(root, home=None, interval=10, once=False, max_runs=None,
          db=None, quiet=False, deep=False):
    """Poll loop. Returns the number of scans performed.

    root/home: workspace and home paths; interval: poll seconds;
    once: single check (daemon-free snapshot mode) — a scan runs only
    when the fingerprint differs from the one stored in
    .agents-doctor/watch-state.json, so cron schedules do not spam the
    history with unchanged scans; max_runs: stop after N scans (tests);
    db: history database path.
    """
    root = Path(root).resolve()
    home = Path(home or Path.home()).resolve()
    scans = 0
    prev_findings = None

    def _record(rep):
        try:
            import audit_history
            conn = audit_history.init_db(
                db or (root / '.agents-doctor' / 'history.db'))
            audit_history.record_scan(conn, rep)
            conn.close()
        except Exception as exc:   # history must never kill the watch
            if not quiet:
                print('history: skipped (%s)' % exc, file=sys.stderr)

    def _changed_scan(reason):
        nonlocal scans, prev_findings
        import audit_scan
        scans += 1
        rep = audit_scan.scan(root, home, deep)
        fps = {f['fp'] for f in rep.get('findings', [])}
        if prev_findings is not None:
            new = [f for f in rep.get('findings_detailed') or []
                   if f.get('fid') and _fp_of(rep, f) not in prev_findings]
            if not quiet:
                print('[%s] %s -> %d finding(s), %d new'
                      % (time.strftime('%H:%M:%S'), reason,
                         len(rep.get('findings_detailed') or []), len(new)))
                for f in new[:10]:
                    print('  NEW [%s/%s] %s' % (f.get('gate'),
                                                f.get('severity'),
                                                f.get('title')))
        elif not quiet:
            print('[%s] %s -> %d finding(s)'
                  % (time.strftime('%H:%M:%S'), reason,
                     len(rep.get('findings_detailed') or [])))
        prev_findings = fps
        _record(rep)
        return rep

    has_targets = any(_exists(root / t) for t in WATCH_TARGETS) \
        or any(_exists(root / d) for d in WATCH_DIRS)
    if not has_targets:
        if not quiet:
            print('nothing to watch: no instruction/config files in %s'
                  % root)
        return 0

    if once:
        fp = config_fingerprint(root)
        state = _load_state(root)
        if state.get('fingerprint') == fp:
            if not quiet:
                print('[%s] no change since last run'
                      % time.strftime('%H:%M:%S'))
            return 0
        _changed_scan('configuration changed')
        _save_state(root, {'fingerprint': fp})
        return scans

    # daemon mode: baseline scan, then poll
    _changed_scan('initial scan')
    prev_fp = config_fingerprint(root)
    _save_state(root, {'fingerprint': prev_fp})
    if max_runs is not None and scans >= max_runs:
        return scans
    while True:
        time.sleep(max(1, interval))
        fp = config_fingerprint(root)
        if fp == prev_fp:
            continue
        prev_fp = fp
        _changed_scan('configuration changed')
        _save_state(root, {'fingerprint': fp})
        if max_runs is not None and scans >= max_runs:
            return scans


def _fp_of(rep, finding):
    """Fingerprint of a detailed finding via the compact findings list."""
    fid = finding.get('fid')
    for f in rep.get('findings', []):
        if f.get('fid') == fid:
            return f.get('fp')
    return None
