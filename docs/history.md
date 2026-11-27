# Audit history (Historical Analytics)

Local history of workspace audits in SQLite. Every full `audit` run
leaves a row; diffs, regressions and trends read the database, full
reports stay in their scan.json files.

Module: `skills/agents-doctor/scripts/audit_history.py`.
CLI front door: the `history` subcommand of `agents_doctor.py`.

## Where the database lives

Default: `<root>/.agents-doctor/history.db` — root-local, the history
travels with the workspace it describes. `--db PATH` overrides (a
shared database is fine; every scan row carries its own `root`, and
`trend`/`regressions` filter by it).

## Schema

Managed by linear migrations (`MIGRATIONS` in the module): opening a
database applies every step above its recorded version, one transaction
per step. Current version: 3.

```sql
scans (id INTEGER PRIMARY KEY, ts TEXT, root TEXT,
       findings_total INTEGER,
       severity_counts TEXT /* json {critical: n, ...} */,
       gate_statuses TEXT   /* json {G1: pass, ...} */,
       policy_summary TEXT  /* reserved, NULL for now */,
       scan_file TEXT       /* path to the full scan.json when kept */)

findings (scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
          kind TEXT, fp TEXT, section TEXT, path TEXT,
          fid TEXT, gate TEXT, severity TEXT, status TEXT,
          check_id TEXT, harness TEXT)
-- indexes: findings(scan_id), findings(fp), scans(root, id)
```

`findings` holds two populations, told apart by `kind`:

- `kind='fingerprint'` — one row per `rep['findings']` entry of the
  scan (fp, section, path), sorted by fp on insert for stable row
  order. This is the population `diff_scans` works on.
- `kind='typed'` — one row per `rep['findings_detailed']` entry: fid,
  gate, severity, status, plus check_id/harness for harness-adapter
  findings. This is the population `regressions` works on.

`scans.findings_total` counts the fingerprint population (like the
scanner's "fingerprinted findings" line); the severity counts come from
the typed population — the two are different views of the same report,
so a small workspace can show `total 0` with nonzero severity counts.

`section` and `path` are stored as well: `diff_scans` reuses
`remediate.fingerprint_diff`, whose CHANGED detection needs
section+path next to the fingerprint.

Connection settings: WAL journal mode, 5 s busy timeout,
`foreign_keys=ON`. Connections run in autocommit; write helpers manage
their own explicit transactions. One connection per caller —
`check_same_thread` stays True (the module never passes False), so a
thread opens its own connection instead of sharing one.

## Privacy: what never enters the database

- Secret values. The scan report itself carries only masks and keyed
  fingerprints (the scanner's redaction boundary), and the history
  projection stores none of the raw sections (`rep['secrets']` is not
  recorded at all).
- File content. Typed rows store no titles, descriptions or evidence —
  only the deterministic identity columns (fid, gate, severity, status,
  check_id, harness).
- Paths outside the audited root. Fingerprint rows carry the
  root-relative paths the scanner reported; the database sits inside
  the same root, so nothing leaves the machine or the workspace. The
  one absolute path stored is `scan_file`, the report the user told the
  tool to write.

Tests pin this down with a canary: a secret-looking string planted in
every unstored field must not appear anywhere in the database file.

## API

```python
init_db(path) -> conn                # create + migrate, WAL, timeout 5 s
default_db_path(root) -> Path        # <root>/.agents-doctor/history.db
record_scan(conn, rep, scan_file=None) -> scan_id
list_scans(conn, limit=50)           # newest first, json columns parsed
get_scan(conn, scan_id)              # one row or None
diff_scans(conn, old_id, new_id)     # remediate.fingerprint_diff over the
                                     # fingerprint rows: NEW / RESOLVED /
                                     # PERSISTING / CHANGED
regressions(conn, last_id)           # typed findings that got worse vs the
                                     # previous scan of the same root
trend(conn, root=None)               # [{ts, total, critical, high, medium,
                                     #   low, info}, ...] oldest first
prune(conn, keep_scans=100)          # retention; returns deleted count
export_csv(conn, out_path)           # scans table to CSV
```

`regressions` matching: harness-adapter findings are matched by their
stable `check_id` + `harness`; every other typed finding falls back to
`fid` + `gate`. fid ids are positional counters, so after a big reshuffle
of one gate's findings the fallback can pair different problems — treat
a lone fid-matched regression as a hint and check the finding itself.
A regression is: severity moved up (low < medium < high < critical) or
status fell from pass/warn to fail.

## CLI

```
python skills/agents-doctor/scripts/agents_doctor.py history <root>
    [--db PATH] [--last N] [--record scan.json]
    [--diff OLD_ID NEW_ID] [--regressions] [--trend] [--prune N]
    [--out FILE]
```

- no flags: the last N scans as a table (default 50)
- `--record`: record a finished scan.json into the history
- `--diff`: the four-section fingerprint diff between two recorded scans
- `--regressions`: regressions of the last recorded scan of this root
- `--trend`: CSV (`ts,total,critical,high,medium,low,info`) to stdout
  or to `--out`
- `--prune N`: keep the N newest scans, delete the rest

Exit codes: 0 success, 1 error (missing database, unreadable record
file, unknown scan ids, bad root).

`audit_history.py` also runs standalone with `root [--db] [--record]
[--last]` for direct calls and tests.

## Automatic recording

A successful `audit` run records itself into the default database
(success path only; the write is wrapped so a history failure never
fails the audit). Focused audits (`--focus`) are not recorded: they
drop gates and findings, and a partial report would skew totals and
trends. Record those manually with `history --record` if you need them
somewhere.
