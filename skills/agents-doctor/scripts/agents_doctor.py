#!/usr/bin/env python3
"""agents-doctor command line (production-readiness stage 4).

Single entry point on top of the scanner: focused audits, baseline
comparison, finding lookup and guarded fixes. The scanner runs
in-process (audit_scan.scan); nothing is re-shelled out to python, and
the only subprocesses are the read-only git calls the scanner itself
makes.

Subcommands:
  audit <root> [options]         scan a workspace, write scan.json; with
                                 --human, --report and --summary it also
                                 leaves the plain-language and the
                                 technical report on disk and prints the
                                 short digest (the agent reads that, not
                                 the JSON)
  compare <new.json> <old.json>  fingerprint diff: NEW/RESOLVED/PERSISTING/CHANGED
  summary <scan.json>            print the short digest of a finished scan
  explain <scan.json> <fid>      print one finding as a short card
                                 (--raw: the full record with evidence)
  fix <scan.json> <fid>          plan a fix; with --apply run it after
                                 an interactive confirmation (delegates
                                 to remediate.py)
  history <root> [options]       local audit history in SQLite: listing,
                                 --record, --diff, --regressions, --trend,
                                 --prune (see audit_history.py)
  policy <scan.json> --policy F  evaluate corporate policies against a
                                 finished scan (see policies.py)

Exit codes: 0 ok. `policy` has its own contract (enforcement v2,
docs/policies.md): 0 pass or enforcement off, 1 a blocking rule fired,
2 policy file error, 3 scan unreadable or no root, 4 strict
enforcement with unknown rules; the report is always written first.
For everything else: 1 usage/IO error, 2 explain: finding not found,
3 fix: no supported automatic fix.
"""
import argparse
import json
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import audit_scan    # noqa: E402  (in-process scanner)
import audit_history  # noqa: E402  (root-local SQLite audit history)
import remediate   # noqa: E402  (fix engine + fingerprint diff)

PROG = 'agents_doctor'

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

# focus name -> gate ids kept in the report (commands/agents-doctor.md
# is canonical); every other gate (rep['gates']) and finding
# (rep['findings_detailed']) is dropped before the JSON is written.
# Findings are filtered by their 'gate' field only: category lists used
# to ride along here and drifted from the gate mapping. Raw fact
# sections (secrets, junk, top_level, ...) stay complete either way.
FOCUS_SPECS = {
    'security': {'gates': ['G6', 'G7']},
    'structure': {'gates': ['G1', 'G4', 'G9']},
    'agents': {'gates': ['G2', 'G3', 'G5', 'G8']},
}

# severity order for audit --fail-on: a finding trips the threshold when
# its severity ranks at or above the requested level AND its status is
# 'fail'. 'none' (the default) keeps the historical behavior — exit 0
# even with critical failures; reports stay advisory unless a CI caller
# explicitly opts in. A severity outside this list ranks below info and
# never trips any threshold.
SEVERITY_ORDER = ['info', 'low', 'medium', 'high', 'critical']
SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITY_ORDER)}
FAIL_ON_CHOICES = ['none'] + SEVERITY_ORDER[::-1]


def _err(msg):
    print('%s: %s' % (PROG, msg), file=sys.stderr)
    return 1


def _fail(code, msg):
    """_err with a caller-chosen exit code (the policy contract uses
    2 for configuration errors and 3 for an unusable scan)."""
    print('%s: %s' % (PROG, msg), file=sys.stderr)
    return code


def _load_json(path):
    try:
        return json.loads(Path(path).read_text(encoding='utf-8'))
    except (OSError, ValueError) as exc:
        print('%s: cannot read %s: %s' % (PROG, path, exc), file=sys.stderr)
        return None


def apply_focus(rep, focus):
    """Drop the gates and findings outside the focus, in place.

    Gates are kept by 'gid', findings by their 'gate' field; the gate
    list is the single source of truth, no category filtering.
    """
    spec = FOCUS_SPECS[focus]
    rep['gates'] = [g for g in rep.get('gates') or []
                    if g.get('gid') in spec['gates']]
    rep['findings_detailed'] = [f for f in rep.get('findings_detailed') or []
                                if f.get('gate') in spec['gates']]
    rep['focus'] = focus
    return rep


# --- subcommands ---------------------------------------------------------------

def cmd_audit(a):
    root = Path(a.root).resolve()
    home = Path(a.home).resolve()
    if not root.is_dir():
        return _err('not a directory: %s' % root)
    rep = audit_scan.scan(root, home, a.deep)
    if a.focus:
        apply_focus(rep, a.focus)
    if a.baseline:
        old = _load_baseline(a.baseline)
        if old is not None:
            old_fps = {f['fp'] for f in old.get('findings', [])}
            new_fps = {f['fp'] for f in rep.get('findings', [])}
            rep['diff'] = {
                'new': [f for f in rep['findings'] if f['fp'] not in old_fps],
                'resolved': [f for f in old.get('findings', [])
                             if f['fp'] not in new_fps]}
            print('baseline: %d new, %d resolved'
                  % (len(rep['diff']['new']), len(rep['diff']['resolved'])))
        else:
            print('warning: could not read baseline %s, diff skipped'
                  % a.baseline, file=sys.stderr)
    policy_block = None
    if getattr(a, 'policies', None):
        # audit --policy: evaluate right here and embed the compliance
        # report into the scan JSON (rep['policy_report']). An
        # enforcement block (version 2 policies) is remembered and
        # fails the command only after the scan is safely on disk.
        try:
            import policies
            policy_files = list(a.policies)
            rep['policy_report'] = policies.evaluate_policies(
                rep, str(root), policy_files)
            s = rep['policy_report'].get('summary', {})
            print('policy: %d rules, %d violations'
                  % (s.get('rules', 0), s.get('violations', 0)))
            enf = s.get('enforcement') or {}
            if enf.get('enabled') and enf.get('exit_code') in (1, 4):
                policy_block = enf
        except policies.PolicyError as exc:
            return _fail(2, str(exc))
        except ImportError:
            print('warning: policies.py unavailable, policy step skipped',
                  file=sys.stderr)
    try:
        _ensure_parent(a.out)
        Path(a.out).write_text(
            json.dumps(rep, ensure_ascii=False, indent=2), encoding='utf-8')
    except OSError as exc:
        return _err('cannot write %s: %s' % (a.out, exc))
    if a.report:
        rc = _write_report(rep, a.report)
        if rc:
            return rc
    st = lambda s: sum(1 for g in rep['gates'] if g['status'] == s)
    print('gates: fail %d, warn %d, pass %d, unknown %d, n/a %d'
          % (st('fail'), st('warn'), st('pass'), st('unknown'),
             st('not_applicable')))
    if a.runtime:
        try:
            import runtime_health
            rh = runtime_health.check_environment(
                root, home, allow_subprocess=True)
        except Exception as exc:
            print('warning: runtime checks failed: %s' % exc,
                  file=sys.stderr)
            rh = None
        if rh is not None:
            # the runtime section must ride in the same JSON file
            try:
                on_disk = json.loads(Path(a.out).read_text(
                    encoding='utf-8'))
                on_disk['runtime'] = rh
                Path(a.out).write_text(
                    json.dumps(on_disk, ensure_ascii=False, indent=2),
                    encoding='utf-8')
            except (OSError, ValueError):
                pass
            summ = rh.get('summary', {})
            print('runtime: pass %d, warn %d, fail %d, unknown %d'
                  % (summ.get('pass', 0), summ.get('warn', 0),
                     summ.get('fail', 0), summ.get('unknown', 0)))
            for c in rh.get('checks', []):
                if c.get('status') in ('fail', 'warn'):
                    print('  [%s] %s: %s' % (c.get('status'),
                                             c.get('id'),
                                             c.get('detail', '')[:120]))
    # artifacts are named relative to the audited folder: the absolute
    # paths of the machine stay out of what the agent reads
    line = ('audit: %d gates, %d findings -> %s'
            % (len(rep['gates']), len(rep['findings_detailed']),
               _shown_path(a.out, root)))
    if a.focus:
        line += ' (focus: %s)' % a.focus
    print(line)
    if getattr(a, 'human', None):
        rc = _write_human(rep, a.human, a.lang, a.sessions)
        if rc:
            return rc
    if getattr(a, 'summary', False):
        import summary
        files = {'scan': _shown_path(a.out, root)}
        if a.report:
            files['report'] = _shown_path(a.report, root)
        if a.human:
            files['human'] = _shown_path(a.human, root)
        print()
        print(summary.render(summary.build(rep, a.lang, files=files)))
    # success path only: leave a row in the root-local history. A focused
    # report is partial and would skew the trend, so it is not recorded.
    # History must never fail the audit.
    if not a.focus:
        try:
            hconn = audit_history.init_db(
                audit_history.default_db_path(root))
            try:
                audit_history.record_scan(
                    hconn, rep, scan_file=str(Path(a.out).resolve()))
            finally:
                hconn.close()
        except Exception:
            pass
    # CI gate: the report (and history row) is already on disk, so this
    # fires only after a successful write. 'none' short-circuits and the
    # exit code stays 0 regardless of findings (back-compat).
    if a.fail_on != 'none':
        floor = SEVERITY_RANK[a.fail_on]
        hits = [f for f in rep.get('findings_detailed') or []
                if f.get('status') == 'fail'
                and SEVERITY_RANK.get(f.get('severity'), -1) >= floor]
        if hits:
            print('fail-on: %d finding(s) at or above %s with status fail'
                  % (len(hits), a.fail_on.upper()))
            return 1
    # policy enforcement gate: same order of concerns -- the scan (with
    # the embedded compliance report) was written above, so blocking
    # now cannot lose it. Exit codes mirror the policy subcommand.
    if policy_block is not None:
        blocking = policy_block.get('blocking_rules') or []
        print('policy: BLOCKED by %d rule(s): %s'
              % (len(blocking), ', '.join(blocking)))
        if policy_block.get('exit_code') == 4:
            print('policy: strict enforcement cannot verify unknown '
                  'rule(s); re-run with complete scan facts',
                  file=sys.stderr)
        return policy_block.get('exit_code', 1)
    return 0


def _load_baseline(path):
    try:
        return json.loads(Path(path).read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return None


def cmd_sarif(a):
    try:
        rep = json.loads(Path(a.scan).read_text(encoding='utf-8'))
    except (OSError, ValueError) as exc:
        return _err('cannot read %s: %s' % (a.scan, exc))
    try:
        import sarif as sarif_mod
    except ImportError:
        return _err('sarif.py not found next to agents_doctor.py')
    data = sarif_mod.to_sarif(rep)
    try:
        Path(a.out).write_text(
            json.dumps(data, indent=2), encoding='utf-8')
    except OSError as exc:
        return _err('cannot write %s: %s' % (a.out, exc))
    rules = len(data.get('runs', [{}])[0].get('tool', {})
                .get('driver', {}).get('rules', []))
    results = len(data.get('runs', [{}])[0].get('results', []))
    print('sarif: %d rules, %d results -> %s' % (rules, results, a.out))
    return 0


def _ensure_parent(path):
    """Create the folder an output file goes into (.agents-doctor/ under
    the audited folder does not exist on a first run)."""
    parent = Path(path).resolve().parent
    if not parent.is_dir():
        parent.mkdir(parents=True, exist_ok=True)


def _write_report(rep, report_path):
    """--report branch: report_generator.py is optional and may not be
    installed yet; a missing or incompatible one is a clean error, not a
    traceback."""
    try:
        import report_generator
    except ImportError:
        print('%s: report generator unavailable' % PROG, file=sys.stderr)
        return 1
    generate = getattr(report_generator, 'generate_report', None) \
        or getattr(report_generator, 'generate_markdown', None)
    if not callable(generate):
        print('%s: report generator unavailable' % PROG, file=sys.stderr)
        return 1
    try:
        markdown = generate(rep)
        _ensure_parent(report_path)
        Path(report_path).write_text(markdown, encoding='utf-8')
    except (OSError, TypeError, ValueError) as exc:
        return _err('report generation failed: %s' % exc)
    print('report: %s' % _shown_path(report_path, rep.get('root')))
    return 0


def _write_human(rep, human_path, lang, sessions):
    """--human branch: the plain-language report for non-technical
    readers (report_human.py), in the language asked for."""
    try:
        import report_human
    except ImportError:
        print('%s: plain-language report unavailable' % PROG, file=sys.stderr)
        return 1
    try:
        markdown = report_human.generate_human_markdown(
            rep, lang=lang, sessions_per_day=sessions)
        _ensure_parent(human_path)
        Path(human_path).write_text(markdown, encoding='utf-8')
    except (OSError, TypeError, ValueError) as exc:
        return _err('plain-language report failed: %s' % exc)
    print('human report (%s): %s' % (lang, _shown_path(human_path, rep.get('root'))))
    return 0


def _shown_path(path, root):
    """A file path as the output shows it: relative to the audited
    folder when the file lies inside it, as given otherwise."""
    try:
        import summary
    except ImportError:
        return str(path)
    return summary.file_alias(str(Path(path).resolve()), root, None) \
        or str(path)


def cmd_compare(a):
    new_rep = _load_json(a.new)
    old_rep = _load_json(a.old)
    if new_rep is None or old_rep is None:
        return 1
    diff = remediate.fingerprint_diff(old_rep.get('findings'),
                                      new_rep.get('findings'))
    for name in ('new', 'resolved', 'persisting', 'changed'):
        items = diff[name]
        print('%s (%d)' % (name.upper(), len(items)))
        for f in items[:10]:  # caps double as the top-10 new paths
            print('  [%s] %s' % (f.get('section'), f.get('path')))
        if len(items) > 10:
            print('  ... and %d more' % (len(items) - 10))
    print('compare: %d new, %d resolved, %d persisting, %d changed'
          % tuple(len(diff[k]) for k in ('new', 'resolved', 'persisting', 'changed')))
    return 0


def _print_finding(f):
    print('%s  gate %s / %s  [%s/%s]  confidence %s'
          % (f.get('fid'), f.get('gate'), f.get('category'),
             f.get('severity'), f.get('status'), f.get('confidence')))
    print('title: %s' % f.get('title'))
    print('description: %s' % f.get('description'))
    print('evidence:')
    print(json.dumps(f.get('evidence'), ensure_ascii=False, indent=2))
    print('recommendation: %s' % f.get('recommendation'))
    print('autofix available: %s' % ('yes' if f.get('autofix_available') else 'no'))


def cmd_explain(a):
    rep = _load_json(a.scan)
    if rep is None:
        return 1
    for f in rep.get('findings_detailed') or []:
        if f.get('fid') == a.fid:
            if getattr(a, 'raw', False):
                _print_finding(f)
            else:
                # the digest view: what, where, what to do. The raw
                # evidence (absolute paths, quoted lines) stays in the
                # scan file on disk; --raw prints it as before.
                import summary
                print(summary.explain_card(f, rep, a.lang))
            print('explain: %s printed' % a.fid)
            return 0
    print('%s: finding not found: %s' % (PROG, a.fid), file=sys.stderr)
    return 2


def cmd_summary(a):
    """The short digest of a finished scan: what the agent reads instead
    of the scan JSON itself."""
    rep = _load_json(a.scan)
    if rep is None:
        return 1
    try:
        import summary
    except ImportError:
        return _err('summary.py not found next to agents_doctor.py')
    files = {}
    for key, value in (('human', a.human), ('report', a.report),
                       ('scan', a.scan)):
        if value:
            files[key] = _shown_path(value, rep.get('root'))
    print(summary.render(summary.build(rep, a.lang, files=files)))
    return 0


def cmd_fix(a):
    rep = _load_json(a.scan)
    if rep is None:
        return 1
    root = rep.get('root')
    if not root:
        return _err('scan has no root; re-run the audit')
    try:
        steps = remediate.plan(rep, a.fid)
    except remediate.UnsupportedError as exc:
        print('%s: %s' % (PROG, exc), file=sys.stderr)
        return 3
    except ValueError as exc:
        return _err(str(exc))
    if not a.apply:
        remediate.print_plan(a.fid, steps)
        print('fix %s: %d step(s) planned, nothing changed (dry run; re-run '
              'with --apply and confirm to execute)' % (a.fid, len(steps)))
        return 0
    try:
        report = remediate.apply_plan(steps, root)  # asks for confirmation
    except ValueError as exc:
        return _err(str(exc))
    if report['declined']:
        print('fix %s: declined, nothing executed' % a.fid)
        return 0
    print('fix %s: executed %d, skipped %d, failed %d'
          % (a.fid, len(report['executed']), len(report['skipped']),
             len(report['failed'])))
    for fail in report['failed']:
        print('  failed [%s] %s: %s'
              % (fail.get('action'), fail.get('target'), fail.get('error')),
              file=sys.stderr)
    return 1 if report['failed'] else 0


def cmd_simulate(a):
    root = Path(a.root).resolve()
    if not root.is_dir():
        return _err('not a directory: %s' % root)
    target = None
    if a.target:
        target = Path(a.target)
        if not target.is_absolute():
            target = root / target
        target = target.resolve()
        if root not in target.parents and target != root:
            return _err('target outside the workspace root: %s' % target)
    from harness import HarnessContext
    from instructions import simulate_loading
    from instructions.simulation import format_simulation_text
    ctx = HarnessContext(root=root, home=Path(a.home).resolve())
    ids = [a.harness] if a.harness else None
    rep = simulate_loading(ctx, target, ids)
    print(format_simulation_text(rep))
    return 0


def cmd_ui(a):
    try:
        import ui.server as ui_server
    except ImportError:
        return _err('ui/server.py not found next to agents_doctor.py')
    argv = ['--port', str(a.port)]
    if a.scan:
        argv += ['--scan', a.scan]
    if a.root:
        argv += ['--root', a.root]
    if a.home:
        argv += ['--home', a.home]
    if a.baseline:
        argv += ['--baseline', a.baseline]
    if a.no_open:
        argv += ['--no-open']
    if a.token:
        argv += ['--token']
    return ui_server.main(argv)


def cmd_history(a):
    root = Path(a.root).resolve()
    if not root.is_dir():
        return _err('not a directory: %s' % root)
    db = Path(a.db).resolve() if a.db else audit_history.default_db_path(root)

    if a.record:
        rep = _load_json(a.record)
        if rep is None:
            return 1
        try:
            conn = audit_history.init_db(db)
        except (OSError, sqlite3.Error) as exc:
            return _err('cannot open history db %s: %s' % (db, exc))
        try:
            scan_id = audit_history.record_scan(
                conn, rep, scan_file=str(Path(a.record).resolve()))
        except sqlite3.Error as exc:
            return _err('cannot record scan: %s' % exc)
        finally:
            conn.close()
        print('history: recorded scan %d (%d findings) -> %s'
              % (scan_id, len(rep.get('findings') or []), db))
        return 0

    if not db.exists():
        return _err('no history database at %s (run an audit or --record first)'
                    % db)
    try:
        conn = audit_history.init_db(db)
    except (OSError, sqlite3.Error) as exc:
        return _err('cannot open history db %s: %s' % (db, exc))

    try:
        if a.diff:
            old_id, new_id = a.diff
            for sid in (old_id, new_id):
                if audit_history.get_scan(conn, sid) is None:
                    return _err('no scan with id %d in %s' % (sid, db))
            diff = audit_history.diff_scans(conn, old_id, new_id)
            for name in ('new', 'resolved', 'persisting', 'changed'):
                items = diff[name]
                print('%s (%d)' % (name.upper(), len(items)))
                for f in items[:10]:
                    print('  [%s] %s' % (f.get('section'), f.get('path')))
                if len(items) > 10:
                    print('  ... and %d more' % (len(items) - 10))
            print('history diff: %d new, %d resolved, %d persisting, %d changed'
                  % tuple(len(diff[k]) for k in
                          ('new', 'resolved', 'persisting', 'changed')))
            return 0

        if a.regressions:
            last = conn.execute(
                'SELECT id FROM scans WHERE root = ? ORDER BY id DESC LIMIT 1',
                (str(root),)).fetchone()
            if last is None:
                print('history: no recorded scan for root %s' % root)
                return 0
            regs = audit_history.regressions(conn, last[0])
            prev = conn.execute(
                'SELECT id FROM scans WHERE root = ? AND id < ?'
                ' ORDER BY id DESC LIMIT 1', (str(root), last[0])).fetchone()
            print('regressions: %d (scan %d vs %s)'
                  % (len(regs), last[0], prev[0] if prev else '-'))
            for r in regs:
                print('  [%s] %s  %s' % (r.get('gate'), r.get('fid'),
                                         '; '.join(r['reasons'])))
            return 0

        if a.trend:
            points = audit_history.trend(conn)
            lines = [','.join(['ts', 'total']
                              + list(audit_history.TREND_SEVERITIES))]
            for p in points:
                lines.append(','.join(
                    [str(p['ts']), str(p['total'])]
                    + [str(p[name]) for name in audit_history.TREND_SEVERITIES]))
            text = '\n'.join(lines) + '\n'
            if a.out:
                try:
                    Path(a.out).write_text(text, encoding='utf-8')
                except OSError as exc:
                    return _err('cannot write %s: %s' % (a.out, exc))
                print('history trend: %d points -> %s' % (len(points), a.out))
            else:
                sys.stdout.write(text)
            return 0

        if a.prune is not None:
            deleted = audit_history.prune(conn, a.prune)
            print('history prune: kept %d newest scans, deleted %d'
                  % (a.prune, deleted))
            return 0

        scans = audit_history.list_scans(conn, a.last)
        print('history: %d scan(s) in %s' % (len(scans), db))
        for s in scans:
            sev = s['severity_counts']
            print('  %4d  %s  total %4d  crit %d high %d med %d low %d%s'
                  % (s['id'], s['ts'], s['findings_total'],
                     sev.get('critical', 0), sev.get('high', 0),
                     sev.get('medium', 0), sev.get('low', 0),
                     '  ' + str(s['scan_file']) if s['scan_file'] else ''))
        return 0
    finally:
        conn.close()


def cmd_policy(a):
    rep = _load_json(a.scan)
    if rep is None:
        return 3   # message already printed by _load_json
    root = rep.get('root')
    if not root:
        return _fail(3, 'scan has no root; re-run the audit')
    try:
        import policies
    except ImportError:
        return _err('policies.py not found next to agents_doctor.py')
    policy_files = list(a.policies or [])
    if not policy_files:
        # no explicit files: discover policy packs in installed plugins
        # plus workspace-level .agents-doctor.toml [policy] files
        policy_files = policies.discover_policy_files(
            root, rep.get('home'))
        if not policy_files:
            return _fail(2, 'no policy files: no --policy given and no '
                            'policy packs found (see docs/policies.md)')
        print('policy files discovered: %s'
              % ', '.join(str(f) for f in policy_files))
    try:
        report = policies.evaluate_policies(rep, root, policy_files)
    except policies.PolicyError as exc:
        return _fail(2, str(exc))
    # the report is written (or printed) before any enforcement exit:
    # a blocked run must still leave the evidence behind
    if a.format == 'md':
        text = policies.render_markdown(report)
    else:
        text = json.dumps(report, ensure_ascii=False, indent=2)
    if a.out:
        try:
            Path(a.out).write_text(text, encoding='utf-8')
        except OSError as exc:
            return _err('cannot write %s: %s' % (a.out, exc))
    else:
        print(text)
    s = report.get('summary', {})
    print('policy: %d rules, %d violations (fail %d, warn %d, info %d, '
          'unknown %d, suppressed %d)'
          % (s.get('rules', 0), s.get('violations', 0), s.get('fail', 0),
             s.get('warn', 0), s.get('info', 0), s.get('unknown', 0),
             s.get('suppressed', 0)))
    enf = s.get('enforcement') or {}
    if not enf.get('enabled'):
        return 0
    blocking = enf.get('blocking_rules') or []
    code = enf.get('exit_code', 0)
    if code == 1:
        print('policy: BLOCKED by %d rule(s): %s'
              % (len(blocking), ', '.join(blocking)))
    elif code == 4:
        print('policy: BLOCKED by %d unknown rule(s): %s'
              ' (unknown_action=block, insufficient scan data)'
              % (len(blocking), ', '.join(blocking)))
    print('policy enforcement: enabled, action %s, exit code %d'
          % (enf.get('action_taken'), code))
    return code


def cmd_watch(a):
    root = Path(a.root).resolve()
    if not root.is_dir():
        return _err('not a directory: %s' % root)
    try:
        import watch as watch_mod
    except ImportError:
        return _err('watch.py not found next to agents_doctor.py')
    try:
        scans = watch_mod.watch(root, home=Path(a.home).resolve(),
                                interval=a.interval, once=a.once,
                                db=a.db, deep=a.deep)
    except KeyboardInterrupt:
        print('\nwatch: stopped')
        return 0
    print('watch: %d scan(s) performed' % scans)
    return 0


# --- parser ----------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        prog='agents_doctor.py',
        description='agents-doctor: scan an agent workspace, compare audits, '
                    'explain findings and plan guarded fixes.',
        epilog='Fixes are a dry run by default: "fix" only prints a plan. '
               '--apply still asks for an interactive confirmation and every '
               'step stays inside the audited root (see remediate.py).')
    sub = p.add_subparsers(dest='command', metavar='<command>', required=True)

    pa = sub.add_parser(
        'audit', help='scan a workspace and write scan.json '
                      '(runs audit_scan.scan in-process)')
    pa.add_argument('root', help='workspace root directory')
    pa.add_argument('--home', default=str(Path.home()),
                    help='home directory with harnesses and skills '
                         '(default: this user home)')
    pa.add_argument('--deep', action='store_true',
                    help='also scan git history for secrets (slower)')
    pa.add_argument('--focus', choices=sorted(FOCUS_SPECS), default=None,
                    help='keep only part of the report: security=G6,G7; '
                         'structure=G1,G4,G9; agents=G2,G3,G5,G8')
    pa.add_argument('--baseline', default=None, metavar='PREV.json',
                    help='previous scan.json: adds a diff section '
                         '(new and resolved findings)')
    pa.add_argument('--out', default='scan.json',
                    help='where to write the JSON report (default: scan.json)')
    pa.add_argument('--fail-on', choices=FAIL_ON_CHOICES, default='none',
                    help='CI gate: exit 1 after the report is written when '
                         'at least one finding has status fail and severity '
                         'at or above this level '
                         '(critical>high>medium>low>info); default none '
                         'keeps the exit code 0 whatever the findings')
    pa.add_argument('--report', default=None, metavar='AUDIT.md',
                    help='also write a markdown report '
                         '(needs report_generator.py)')
    pa.add_argument('--human', default=None, metavar='REPORT.md',
                    help='also write the plain-language report for '
                         'non-technical readers (needs report_human.py)')
    pa.add_argument('--lang', choices=('ru', 'en'), default='en',
                    help='language of the plain-language report and of the '
                         'summary (default: en)')
    pa.add_argument('--sessions', type=int, default=10, metavar='N',
                    help='agent sessions per day for the monthly token '
                         'estimate of the plain-language report (default: 10)')
    pa.add_argument('--summary', action='store_true',
                    help='print the short digest of the scan (gate statuses '
                         'with reasons, the findings that matter, where to '
                         'start) instead of leaving the agent to read the '
                         'whole JSON')
    pa.add_argument('--runtime', action='store_true',
                    help='opt-in runtime checks after the scan: CLI '
                         'binaries of detected harnesses (--version, '
                         'timeout-bounded), git/python presence, static '
                         'MCP config validation. No network requests.')
    pa.add_argument('--policy', action='append', default=None,
                    dest='policies', metavar='FILE.yml',
                    help='evaluate policy YAML file(s) after the scan and '
                         'embed the compliance report into the JSON '
                         '(repeatable; see docs/policies.md)')
    pa.set_defaults(func=cmd_audit)

    ps = sub.add_parser(
        'sarif', help='convert scan.json to SARIF 2.1.0 for CI')
    ps.add_argument('scan', help='scan.json from an audit')
    ps.add_argument('--out', default='report.sarif',
                    help='output SARIF file (default: report.sarif)')
    ps.set_defaults(func=cmd_sarif)

    pc = sub.add_parser(
        'compare', help='diff two scan.json files by finding fingerprints')
    pc.add_argument('new', help='newer scan.json')
    pc.add_argument('old', help='older scan.json (baseline)')
    pc.set_defaults(func=cmd_compare)

    pe = sub.add_parser(
        'explain', help='print one finding as a short card: what, where, '
                        'what to do (--raw prints the full record)')
    pe.add_argument('scan', help='scan.json from an audit')
    pe.add_argument('fid', help='finding id, e.g. SEC-001')
    pe.add_argument('--lang', choices=('ru', 'en'), default='en',
                    help='language of the card (default: en)')
    pe.add_argument('--raw', action='store_true',
                    help='print the full finding record with its evidence '
                         '(the pre-digest output)')
    pe.set_defaults(func=cmd_explain)

    pm = sub.add_parser(
        'summary', help='print the short digest of a finished scan')
    pm.add_argument('scan', help='scan.json from an audit')
    pm.add_argument('--lang', choices=('ru', 'en'), default='en',
                    help='language of the digest (default: en)')
    pm.add_argument('--human', default=None, metavar='REPORT.md',
                    help='plain-language report written next to the scan, '
                         'named in the digest')
    pm.add_argument('--report', default=None, metavar='AUDIT.md',
                    help='technical report written next to the scan, '
                         'named in the digest')
    pm.set_defaults(func=cmd_summary)

    pf = sub.add_parser(
        'fix', help='plan a guarded fix for one finding '
                    '(dry run unless --apply is given)')
    pf.add_argument('scan', help='scan.json from an audit')
    pf.add_argument('fid', help='finding id to fix, e.g. GIT-002')
    pf.add_argument('--apply', action='store_true',
                    help='execute the plan after an interactive confirmation '
                         '(default: print the plan only)')
    pf.set_defaults(func=cmd_fix)

    psi = sub.add_parser(
        'simulate', help='show which instructions load for a directory '
                         '(model, not runtime-verified)')
    psi.add_argument('root', help='workspace root directory')
    psi.add_argument('--target', default=None, metavar='DIR',
                     help='target directory inside the root (default: root)')
    psi.add_argument('--harness', default=None, metavar='ID',
                     help='restrict to one adapter id '
                          '(e.g. claude_code; default: all detected)')
    psi.add_argument('--home', default=str(Path.home()),
                     help='home directory (default: this user home)')
    psi.set_defaults(func=cmd_simulate)

    pui = sub.add_parser(
        'ui', help='open the local web UI (localhost only)')
    pui.add_argument('root', nargs='?', default=None,
                     help='workspace root (fresh scan when no --scan)')
    pui.add_argument('--scan', default=None, metavar='scan.json',
                     help='serve an existing scan.json instead of scanning')
    pui.add_argument('--home', default=None)
    pui.add_argument('--baseline', default=None, metavar='OLD.json',
                     help='older scan.json: enables the Compare tab')
    pui.add_argument('--port', type=int, default=8765)
    pui.add_argument('--no-open', action='store_true',
                     help='do not open the browser automatically')
    pui.add_argument('--token', action='store_true',
                     help='require a bearer token for /api/* requests')
    pui.set_defaults(func=cmd_ui)

    ph = sub.add_parser(
        'history', help='local audit history: list scans, diff, '
                        'regressions, trend, prune (root-local SQLite)')
    ph.add_argument('root', help='workspace root directory')
    ph.add_argument('--db', default=None, metavar='PATH',
                    help='history database (default: '
                         '<root>/.agents-doctor/history.db)')
    ph.add_argument('--last', type=int, default=50, metavar='N',
                    help='how many scans the listing shows (default: 50)')
    ph.add_argument('--record', default=None, metavar='scan.json',
                    help='record a finished scan report into the history')
    ph.add_argument('--diff', nargs=2, type=int, default=None,
                    metavar=('OLD_ID', 'NEW_ID'),
                    help='fingerprint diff between two recorded scans')
    ph.add_argument('--regressions', action='store_true',
                    help='findings that got worse in the last scan of this '
                         'root (severity up, or pass/warn -> fail)')
    ph.add_argument('--trend', action='store_true',
                    help='CSV trend of totals and severity counts over time '
                         '(stdout, or --out file)')
    ph.add_argument('--prune', type=int, default=None, metavar='N',
                    help='keep only the N newest scans, delete the rest')
    ph.add_argument('--out', default=None, metavar='FILE',
                    help='output file for --trend (default: stdout)')
    ph.set_defaults(func=cmd_history)

    pp = sub.add_parser(
        'policy', help='evaluate corporate policies against a finished '
                       'scan and write a compliance report')
    pp.add_argument('scan', help='scan.json from an audit')
    pp.add_argument('--policy', action='append', default=None,
                    dest='policies', metavar='FILE.yml',
                    help='policy YAML file; repeat to layer (later files '
                         'override earlier ones per domain). Without any '
                         '--policy, policy packs are discovered in '
                         'installed plugins and .agents-doctor.toml '
                         '[policy] files (see docs/policies.md)')
    pp.add_argument('--out', default=None, metavar='report.json',
                    help='write the report here (default: stdout)')
    pp.add_argument('--format', choices=['json', 'md'], default='json',
                    help='report format (default: json; md is a '
                         'rule/status/violations/severity table)')
    pp.set_defaults(func=cmd_policy)

    pw = sub.add_parser(
        'watch', help='watch the workspace configuration and re-audit '
                      'when it changes; every run lands in the history')
    pw.add_argument('root', help='workspace root directory')
    pw.add_argument('--home', default=str(Path.home()),
                    help='home directory (default: this user home)')
    pw.add_argument('--interval', type=int, default=10, metavar='SEC',
                    help='poll interval in seconds (default: 10)')
    pw.add_argument('--once', action='store_true',
                    help='daemon-free mode for cron: scan only when the '
                         'configuration changed since the last run, '
                         'then exit')
    pw.add_argument('--deep', action='store_true',
                    help='scans include git history (slower)')
    pw.add_argument('--db', default=None, metavar='PATH',
                    help='history database (default: '
                         '<root>/.agents-doctor/history.db)')
    pw.set_defaults(func=cmd_watch)
    return p


def main(argv=None):
    a = build_parser().parse_args(argv)
    return a.func(a)


if __name__ == '__main__':
    sys.exit(main())
