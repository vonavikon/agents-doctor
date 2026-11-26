#!/usr/bin/env python3
"""Local audit history for agents-doctor (Historical Analytics module).

Every audit can leave a row in a root-local SQLite database (default
<root>/.agents-doctor/history.db, override with --db): scan totals,
severity counts, gate statuses and the deterministic finding
fingerprints. Full scan.json files stay on disk; the database keeps
only what trend charts, diffs and regression checks need.

What is stored (privacy contract, see docs/history.md):
- scans: ts, root, findings_total, severity_counts (json), gate_statuses
  (json), policy_summary (reserved, NULL), scan_file (path to the full
  scan.json when it was kept);
- findings, two populations told apart by the 'kind' column:
  * kind='fingerprint' -- one row per rep['findings'] entry: fp, section,
    path. These carry no secret values by construction (the scanner
    stores masks and keyed fingerprints, never raw values).
  * kind='typed' -- one row per rep['findings_detailed'] entry: fid,
    gate, severity, status, check_id, harness. Titles, descriptions and
    evidence are NOT stored, so no file content and no secret value
    lands in the database.
Paths stored are the root-relative paths the scanner itself reported;
the database lives inside the same root, so nothing leaves the machine
or the workspace.

diff_scans() reuses remediate.fingerprint_diff over the fingerprint
rows (it needs fp + section + path, which is why those columns exist).
regressions() compares the typed rows of the last scan against the
previous scan of the same root: adapter findings are matched by their
stable check_id + harness, everything else by fid + gate (a positional
but documented heuristic -- see docs/history.md).

Concurrency: WAL mode, 5 s busy timeout. One connection per caller;
check_same_thread stays True (this module never passes False), so a
connection created in one thread must not be used from another -- open
a second one with init_db instead. WAL allows concurrent readers with
one writer.
"""
import csv
import json
import sqlite3
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import remediate  # noqa: E402  (fingerprint_diff is the one diff engine)

HISTORY_DIR_NAME = '.agents-doctor'
DEFAULT_DB_NAME = 'history.db'

# severity ranking for regressions(): a typed finding regressed when its
# severity moved up this order, or its status fell from pass/warn to fail
SEVERITY_RANK = {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
TREND_SEVERITIES = ('critical', 'high', 'medium', 'low', 'info')

# --- schema ----------------------------------------------------------------------

# Linear migrations: init_db() applies every step above the recorded
# version inside one transaction per step. Migration 1 alone is a valid
# older database (the migration test simulates exactly that).
MIGRATIONS = [
    (1, ["CREATE TABLE scans ("
         "id INTEGER PRIMARY KEY AUTOINCREMENT,"
         "ts TEXT NOT NULL,"
         "root TEXT NOT NULL,"
         "findings_total INTEGER NOT NULL,"
         "severity_counts TEXT NOT NULL DEFAULT '{}',"
         "gate_statuses TEXT NOT NULL DEFAULT '{}',"
         "policy_summary TEXT,"
         "scan_file TEXT)"]),
    (2, ["CREATE TABLE findings ("
         "scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,"
         "kind TEXT NOT NULL,"
         "fp TEXT,"
         "section TEXT,"
         "path TEXT,"
         "fid TEXT,"
         "gate TEXT,"
         "severity TEXT,"
         "status TEXT,"
         "check_id TEXT,"
         "harness TEXT)"]),
    (3, ["CREATE INDEX idx_findings_scan ON findings (scan_id)",
         "CREATE INDEX idx_findings_fp ON findings (fp)",
         "CREATE INDEX idx_scans_root ON scans (root, id)"]),
]

LATEST_VERSION = MIGRATIONS[-1][0]


def default_db_path(root):
    """<root>/.agents-doctor/history.db -- the history travels with the
    workspace it describes."""
    return Path(root).resolve() / HISTORY_DIR_NAME / DEFAULT_DB_NAME


def _apply_migrations(conn):
    conn.execute('CREATE TABLE IF NOT EXISTS schema_migrations '
                 '(version INTEGER NOT NULL)')
    row = conn.execute('SELECT MAX(version) FROM schema_migrations').fetchone()
    version = row[0] or 0
    for ver, statements in MIGRATIONS:
        if ver <= version:
            continue
        conn.execute('BEGIN')
        try:
            for stmt in statements:
                conn.execute(stmt)
            conn.execute('INSERT INTO schema_migrations (version) '
                         'VALUES (?)', (ver,))
            conn.execute('COMMIT')
        except Exception:
            conn.execute('ROLLBACK')
            raise


def init_db(path):
    """Open (creating when missing) the history database and bring it to
    the latest schema version. Returns a sqlite3 connection in
    autocommit mode (isolation_level=None); write helpers run their own
    explicit BEGIN/COMMIT."""
    path = Path(path)
    if path.parent and not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=5.0, isolation_level=None)
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA foreign_keys=ON')
    _apply_migrations(conn)
    return conn


# --- recording -------------------------------------------------------------------

def _now_iso():
    return datetime.now().astimezone().isoformat(timespec='seconds')


def record_scan(conn, rep, scan_file=None):
    """Insert one scan report. rep is the scan.json dict; scan_file is
    the path of the full report when it was kept on disk. Fingerprint
    rows are sorted by fp (and typed rows by fid) so two recordings of
    the same report produce identical row order. Returns the scan id."""
    ts = rep.get('generated_at') or _now_iso()
    root = str(rep.get('root') or '')
    fingerprints = [f for f in rep.get('findings') or []
                    if isinstance(f, dict) and f.get('fp')]
    detailed = [f for f in rep.get('findings_detailed') or []
                if isinstance(f, dict)]
    severity_counts = {}
    for f in detailed:
        sev = f.get('severity')
        if sev:
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
    gate_statuses = {g.get('gid'): g.get('status')
                     for g in rep.get('gates') or [] if g.get('gid')}
    conn.execute('BEGIN')
    try:
        cur = conn.execute(
            'INSERT INTO scans (ts, root, findings_total, severity_counts,'
            ' gate_statuses, policy_summary, scan_file)'
            ' VALUES (?, ?, ?, ?, ?, ?, ?)',
            (ts, root, len(fingerprints),
             json.dumps(severity_counts, sort_keys=True),
             json.dumps(gate_statuses, sort_keys=True),
             None, str(scan_file) if scan_file else None))
        scan_id = cur.lastrowid
        rows = []
        for f in sorted(fingerprints, key=lambda x: x['fp']):
            rows.append((scan_id, 'fingerprint', f.get('fp'),
                         f.get('section'), f.get('path'),
                         None, None, None, None, None, None))
        for f in sorted(detailed, key=lambda x: str(x.get('fid') or '')):
            rows.append((scan_id, 'typed', None, None, None,
                         f.get('fid'), f.get('gate'), f.get('severity'),
                         f.get('status'), f.get('check_id') or None,
                         f.get('harness') or None))
        conn.executemany(
            'INSERT INTO findings (scan_id, kind, fp, section, path,'
            ' fid, gate, severity, status, check_id, harness)'
            ' VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', rows)
        conn.execute('COMMIT')
    except Exception:
        conn.execute('ROLLBACK')
        raise
    return scan_id


# --- queries ---------------------------------------------------------------------

def list_scans(conn, limit=50):
    """Scan rows newest first; json columns come back parsed."""
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            'SELECT id, ts, root, findings_total, severity_counts,'
            ' gate_statuses, policy_summary, scan_file FROM scans'
            ' ORDER BY id DESC LIMIT ?', (int(limit),)).fetchall()
    finally:
        conn.row_factory = None
    out = []
    for r in rows:
        out.append({
            'id': r['id'], 'ts': r['ts'], 'root': r['root'],
            'findings_total': r['findings_total'],
            'severity_counts': _loads(r['severity_counts'], {}),
            'gate_statuses': _loads(r['gate_statuses'], {}),
            'policy_summary': _loads(r['policy_summary'], None),
            'scan_file': r['scan_file'],
        })
    return out


def _loads(text, default):
    if not text:
        return default
    try:
        return json.loads(text)
    except ValueError:
        return default


def get_scan(conn, scan_id):
    """One scan row as list_scans() shapes it, or None."""
    rows = [r for r in list_scans(conn, limit=-1)
            if r['id'] == scan_id]
    return rows[0] if rows else None


def _fingerprint_rows(conn, scan_id):
    """The {fp, section, path} dicts remediate.fingerprint_diff eats."""
    return [{'fp': fp, 'section': section, 'path': path}
            for fp, section, path in conn.execute(
                "SELECT fp, section, path FROM findings"
                " WHERE scan_id = ? AND kind = 'fingerprint'"
                " ORDER BY fp", (scan_id,))]


def _typed_rows(conn, scan_id):
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT fid, gate, severity, status, check_id, harness"
            " FROM findings WHERE scan_id = ? AND kind = 'typed'"
            " ORDER BY fid", (scan_id,)).fetchall()
    finally:
        conn.row_factory = None
    return [dict(r) for r in rows]


def diff_scans(conn, old_id, new_id):
    """Fingerprint diff between two recorded scans; the exact engine the
    compare subcommand uses (remediate.fingerprint_diff), so history
    diffs and file diffs can never disagree."""
    return remediate.fingerprint_diff(_fingerprint_rows(conn, old_id),
                                      _fingerprint_rows(conn, new_id))


def _identity(f):
    """Cross-scan identity of a typed finding: adapter findings carry a
    stable check_id (+ harness); the rest fall back to fid + gate.

    Gate findings carry a check_id as well (it names the finding type),
    so the check_id alone does not tell an adapter finding: the harness
    field does. Keying gate findings by type would fold every finding of
    one kind into a single row and skew diffs and trends."""
    if f.get('check_id') and f.get('harness'):
        return ('check', f['check_id'], f['harness'])
    return ('fid', f.get('gate') or '', f.get('fid') or '')


def regressions(conn, last_id):
    """Typed findings that got worse in scan last_id compared to the
    previous scan of the same root: severity moved up SEVERITY_RANK, or
    status fell from pass/warn to fail. Returns a list of dicts with
    prev/current severity and status and the reasons."""
    row = conn.execute('SELECT root FROM scans WHERE id = ?',
                       (last_id,)).fetchone()
    if row is None:
        return []
    prev = conn.execute(
        'SELECT id FROM scans WHERE root = ? AND id < ?'
        ' ORDER BY id DESC LIMIT 1', (row[0], last_id)).fetchone()
    if prev is None:
        return []
    prev_by_key = {_identity(f): f for f in _typed_rows(conn, prev[0])}
    out = []
    for f in _typed_rows(conn, last_id):
        p = prev_by_key.get(_identity(f))
        if p is None:
            continue
        reasons = []
        if SEVERITY_RANK.get(f.get('severity'), -1) \
                > SEVERITY_RANK.get(p.get('severity'), -1):
            reasons.append('severity %s -> %s'
                           % (p.get('severity'), f.get('severity')))
        if p.get('status') in ('pass', 'warn') and f.get('status') == 'fail':
            reasons.append('status %s -> fail' % p.get('status'))
        if reasons:
            out.append({
                'fid': f.get('fid'), 'gate': f.get('gate'),
                'check_id': f.get('check_id'), 'harness': f.get('harness'),
                'severity': f.get('severity'), 'prev_severity': p.get('severity'),
                'status': f.get('status'), 'prev_status': p.get('status'),
                'reasons': reasons,
            })
    return out


def trend(conn, root=None):
    """One point per scan, oldest first: {ts, total, critical, high,
    medium, low, info} -- the shape chart tools want. root filters to
    one workspace when the database is shared."""
    if root is not None:
        cursor = conn.execute(
            'SELECT ts, findings_total, severity_counts FROM scans'
            ' WHERE root = ? ORDER BY id', (root,))
    else:
        cursor = conn.execute(
            'SELECT ts, findings_total, severity_counts FROM scans'
            ' ORDER BY id')
    points = []
    for ts, total, sev_json in cursor:
        sev = _loads(sev_json, {})
        point = {'ts': ts, 'total': total}
        for name in TREND_SEVERITIES:
            point[name] = int(sev.get(name) or 0)
        points.append(point)
    return points


def prune(conn, keep_scans=100):
    """Retention: keep the newest keep_scans scans (globally), delete the
    rest together with their findings rows. Returns the deleted count."""
    keep_scans = max(0, int(keep_scans))
    ids = [r[0] for r in conn.execute(
        'SELECT id FROM scans ORDER BY id DESC LIMIT -1 OFFSET ?',
        (keep_scans,))]
    if not ids:
        return 0
    marks = ','.join('?' * len(ids))
    conn.execute('BEGIN')
    try:
        # explicit findings delete: robust even on connections that
        # skipped PRAGMA foreign_keys (CASCADE alone is not a guarantee)
        conn.execute('DELETE FROM findings WHERE scan_id IN (%s)' % marks, ids)
        conn.execute('DELETE FROM scans WHERE id IN (%s)' % marks, ids)
        conn.execute('COMMIT')
    except Exception:
        conn.execute('ROLLBACK')
        raise
    return len(ids)


def export_csv(conn, out_path):
    """Write the scans table to a CSV (json columns stay json strings).
    Returns the number of data rows written."""
    rows = conn.execute(
        'SELECT id, ts, root, findings_total, severity_counts,'
        ' gate_statuses, scan_file FROM scans ORDER BY id').fetchall()
    with open(str(out_path), 'w', newline='', encoding='utf-8') as fh:
        writer = csv.writer(fh)
        writer.writerow(['id', 'ts', 'root', 'findings_total',
                         'severity_counts', 'gate_statuses', 'scan_file'])
        for row in rows:
            writer.writerow(row)
    return len(rows)


# --- standalone CLI (the agents_doctor.py history subcommand is the
#     front door; this one exists for direct calls and tests) ----------------------

def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(
        prog='audit_history.py',
        description='Local audit history: record scans, list, diff, '
                    'regressions, trend, prune, export.')
    ap.add_argument('root', help='workspace root directory')
    ap.add_argument('--db', default=None, metavar='PATH',
                    help='history database (default: <root>/.agents-doctor/history.db)')
    ap.add_argument('--record', default=None, metavar='scan.json',
                    help='record a finished scan report into the history')
    ap.add_argument('--last', type=int, default=50, metavar='N',
                    help='how many scans --list prints (default: 50)')
    args = ap.parse_args(argv)
    root = Path(args.root).resolve()
    db = Path(args.db).resolve() if args.db else default_db_path(root)
    if args.record:
        try:
            rep = json.loads(Path(args.record).read_text(encoding='utf-8'))
        except (OSError, ValueError) as exc:
            print('audit_history: cannot read %s: %s' % (args.record, exc),
                  file=sys.stderr)
            return 1
        conn = init_db(db)
        scan_id = record_scan(conn, rep, scan_file=str(Path(args.record).resolve()))
        conn.close()
        print('history: recorded scan %d (%d findings) -> %s'
              % (scan_id, len(rep.get('findings') or []), db))
        return 0
    if not db.exists():
        print('audit_history: no history database at %s' % db, file=sys.stderr)
        return 1
    conn = init_db(db)
    try:
        for s in list_scans(conn, args.last):
            print('%s  %s  total=%d  severities=%s'
                  % (s['id'], s['ts'], s['findings_total'],
                     json.dumps(s['severity_counts'], sort_keys=True)))
    finally:
        conn.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())
