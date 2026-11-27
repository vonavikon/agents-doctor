#!/usr/bin/env python3
"""Guided safe-cleanup wizard for agents-doctor.

remediate.py fixes one finding at a time; this tool is the other end of
the scale: a wizard for non-technical users that tidies a whole
workspace in one pass with near-zero risk. It scans in-process, shows a
plain-language plan, asks for the word YES, then moves junk into a
trash folder inside the workspace. Nothing is ever deleted outright.

Safety taxonomy (each rule is enforced in code below, not in comments):

DEFAULT-SAFE (in every plan unless a NEVER rule vetoes the item):
- build artifacts named in BUILD_DIR_SAFE (node_modules, __pycache__,
  .pytest_cache, .cache): regenerable by definition;
- empty directories (removed with os.rmdir, which refuses a non-empty
  directory; that failure is intended and caught per item);
- confirmed_unused junk: the classifier says unused and git does not
  track the path.

CAUTIOUS (only with --include-cautious):
- build artifact names outside the safe set (dist, build, target,
  .venv, venv, .idea): they may hold local state;
- hash-proven duplicate groups: every copy except the newest-mtime one
  moves to trash under the category 'old copies'.

NEVER (refused with or without any flag; a matching item lands in
plan['skipped'] with a one-word reason, and a user-supplied root that
matches makes the CLI exit 3): anything git-tracked, anything under
.git, .env, .mcp.json, settings*.json, names matching
audit_scan.NAME_SECRET_RX, symlinks, paths resolving outside the
workspace root, paths with '..' after normalization, single items over
the size cap (500 MB hard ceiling; --max-bytes can lower it, never
raise it), and the trash folder itself.

Everything deletable goes to <root>/.agents-doctor-trash/
<YYYYmmdd-HHMMSS>-<opid>/<relative-path> first, via shutil.move (see
trashops.py: per-run operation id, write-ahead manifest.json, crash
recovery, collision suffixing). Only truly empty directories are
removed in place. The trash is never emptied automatically; the CLI
prints the run directory, the manifest and the exact restore command.

Programmatic API (tests drive these directly):
- build_plan(rep, include_cautious=False, max_bytes=DEFAULT_MAX_BYTES)
  -> plan dict {root, max_bytes, include_cautious, items[{path, size,
  action ('trash'|'rmdir'), category, reason, cautious, stat}],
  categories {key: {label, count, size_bytes, cautious}}, skipped
  [{path, reason}], totals}. 'stat' is the plan-time TOCTOU snapshot
  {size, mtime_ns, type} from os.stat; execute() re-stats every item
  right before it acts and aborts the item (skipped as 'changed') when
  the file changed between planning and execution;
- execute(plan, root, assume_yes=False, confirm=None) -> summary dict
  {declined, trash_dir, opid, manifest_path, interrupted_run, moved,
  removed_dirs, freed_bytes, freed_by_category, skipped_safety,
  failed}. Each item runs under its own try/except with the containment
  and NEVER checks re-run right before the move: a failure or a safety
  skip never aborts the batch. The confirmation answer must be exactly
  'YES' (case-sensitive); assume_yes bypasses the prompt (automation
  and tests only);
- restore(run_dir, root=None, opid=None, assume_yes=False, confirm=
  input): re-exported from trashops; moves the run's 'moved' entries
  back (see trashops.restore).

CLI:
    python safe_clean.py <root> [--home H] [--yes] [--include-cautious]
                        [--max-bytes N]
    python safe_clean.py restore <run_dir> [--root R] [--yes]

Exit codes: 0 done or declined, 1 nothing to clean (or restore had
failed items), 2 bad arguments or root, 3 safety refusal (the
user-supplied root itself is on the never list: a symlink, inside .git,
or the trash folder).
"""
import argparse
import fnmatch
import os
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import audit_scan  # noqa: E402  (scan, BUILD_DIRS, NAME_SECRET_RX)
import enrich  # noqa: E402  (_nearest_repo, _repo_tracked_files)
import trashops  # noqa: E402  (shared trash-run machinery)

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

PROG = 'safe_clean'

# where moved junk lands:
# <root>/<TRASH_DIR_NAME>/<YYYYmmdd-HHMMSS>-<opid>/<rel> (trashops.py)
TRASH_DIR_NAME = trashops.TRASH_DIR_NAME

# build artifact names split by risk: the safe set is regenerable by
# definition; the rest of audit_scan.BUILD_DIRS goes to the cautious set
BUILD_DIR_SAFE = {'node_modules', '__pycache__', '.pytest_cache', '.cache'}
# a lockfile next to node_modules is what makes it reliably regenerable
LOCKFILE_NAMES = ('package-lock.json', 'yarn.lock', 'pnpm-lock.yaml',
                  'npm-shrinkwrap.json', 'bun.lockb')
# build dirs younger than this are treated as active installs and skipped
MIN_AGE_DAYS = 7


def _has_lockfile(root, rel):
    """True when a dependency lockfile sits next to the node_modules dir."""
    parent = (Path(root) / rel).parent
    try:
        return any((parent / n).exists() for n in LOCKFILE_NAMES)
    except OSError:
        return False
CAUTIOUS_BUILD_DIRS = set(audit_scan.BUILD_DIRS) - BUILD_DIR_SAFE

DEFAULT_MAX_BYTES = 500 * 1024 * 1024   # per-item cap; a hard ceiling
HARD_MAX_BYTES = 500 * 1024 * 1024      # --max-bytes cannot raise this

SECRET_EXACT_NAMES = {'.env', '.mcp.json'}
SECRET_SETTINGS_GLOB = 'settings*.json'

CAT_BUILD_SAFE = 'build_artifacts_safe'
CAT_EMPTY = 'empty_dirs'
CAT_CONFIRMED = 'confirmed_unused'
CAT_BUILD_CAUTIOUS = 'build_artifacts_local_state'
CAT_OLD_COPIES = 'old_copies'
CATEGORY_LABELS = {
    CAT_BUILD_SAFE: 'Build artifacts (regenerable: node_modules, caches)',
    CAT_EMPTY: 'Empty folders',
    CAT_CONFIRMED: 'Old files the audit confirmed unused',
    CAT_BUILD_CAUTIOUS: 'Build folders that may hold local state '
                        '(dist, build, target, venv, .idea)',
    CAT_OLD_COPIES: 'Old copies of duplicate files',
}

EXIT_OK, EXIT_NOTHING, EXIT_ARGS, EXIT_REFUSAL = 0, 1, 2, 3

_BUILD_REASON_RX = re.compile(r'^build artifact \((.+)\)$')


def _exists(p):
    """exists() that treats permission errors as absent (pathlib raises)."""
    try:
        return p.exists()
    except OSError:
        return False


def _build_artifact_name(reason):
    """Dir name behind a 'build artifact (name)' junk reason, or None."""
    m = _BUILD_REASON_RX.match(str(reason or ''))
    return m.group(1) if m else None


def _never_reason(root, rel, size=None, max_bytes=None, tracked=None):
    """One-word NEVER reason for a candidate path, or None when the
    path passes every hard rule. Pure path/stat checks; no git calls.

    Checks, in order: '..'/absolute shape after normalization, symlink,
    containment (resolved target must stay strictly below root), .git
    anywhere in the path, the trash folder itself, secret-looking
    names, git-tracked, over the per-item cap.
    """
    root = Path(root).resolve()   # short/long form must not fake an escape
    p = os.path.normpath(str(rel))
    if os.path.isabs(p) or p == '..' or p.startswith('..' + os.sep):
        return 'escape'
    target = root / p
    if os.path.islink(str(target)):
        return 'symlink'
    try:
        resolved = target.resolve()
    except OSError:
        return 'escape'
    if root not in resolved.parents:   # root itself is never a target
        return 'escape'
    parts = Path(p).parts
    if any(part == '.git' for part in parts):
        return 'gitdir'
    if parts and parts[0] == TRASH_DIR_NAME:
        return 'trash'
    base = parts[-1] if parts else ''
    if (base in SECRET_EXACT_NAMES
            or fnmatch.fnmatch(base, SECRET_SETTINGS_GLOB)
            or audit_scan.NAME_SECRET_RX.search(base)):
        return 'secret'
    if tracked is True:
        return 'tracked'
    if max_bytes is not None and isinstance(size, int) and size > max_bytes:
        return 'oversized'
    return None


def _tracked_status(root, rel, cache):
    """True/False for 'git tracks this path' via one cached read-only
    `git ls-files` listing per nearest repo (GIT_OPTIONAL_LOCKS=0 inside
    enrich); None when git failed. No repo at all means False."""
    p = root / os.path.normpath(str(rel))
    repo = enrich._nearest_repo(p, root)
    if repo is None:
        return False
    key = str(repo)
    if key not in cache:
        cache[key] = enrich._repo_tracked_files(repo)
    listing = cache[key]
    if listing is None:
        return None
    try:
        posix = p.relative_to(repo).as_posix()
    except ValueError:
        return None
    if posix in listing:
        return True
    if p.is_dir():
        prefix = posix + '/'
        return any(e.startswith(prefix) for e in listing)
    return False


# --- planning --------------------------------------------------------------------

def build_plan(rep, include_cautious=False, max_bytes=DEFAULT_MAX_BYTES):
    """Turn a scan report into a cleanup plan (see module docstring for
    the shape and the safety taxonomy). Never touches the disk except
    for stat calls; nothing here modifies or deletes anything."""
    max_bytes = min(int(max_bytes), HARD_MAX_BYTES)
    root = Path(rep.get('root') or '.').resolve()
    items, skipped = [], []
    seen = set()

    def skip(rel, reason):
        if rel not in seen:
            seen.add(rel)
            skipped.append({'path': rel, 'reason': reason})

    def add(rel, size, action, category, reason, cautious):
        p = root / os.path.normpath(str(rel))
        if not _exists(p):
            skip(rel, 'missing')
            return
        snap = trashops.snapshot(p)   # plan-time TOCTOU baseline
        if snap is None:
            skip(rel, 'missing')
            return
        seen.add(rel)
        items.append({'path': rel, 'size': size or 0, 'action': action,
                      'category': category, 'reason': reason,
                      'cautious': bool(cautious), 'stat': snap})

    classified = {str(e.get('path', '')): e
                  for e in rep.get('junk_classified') or [] if e.get('path')}
    junk_dirs = list((rep.get('junk') or {}).get('dirs') or [])

    # 1) build-artifact directories: safe set by default, the rest only
    #    with the cautious flag; a NEVER rule (tracked above all) vetoes.
    #    Two research-backed guards on top (docs/research-human-layer.md):
    #    - node_modules without a sibling lockfile is NOT regenerable
    #      reliably → cautious tier even with the safe name;
    #    - any build dir modified within MIN_AGE_DAYS is likely an active
    #      install → skipped as 'recent', not touched now.
    for d in junk_dirs:
        rel = str(d.get('path', ''))
        if not rel:
            continue
        size = d.get('size_bytes') or 0
        name = _build_artifact_name(d.get('reason'))
        if name in BUILD_DIR_SAFE:
            if name == 'node_modules' and not _has_lockfile(root, rel):
                if not include_cautious:
                    continue
        elif name in CAUTIOUS_BUILD_DIRS and include_cautious:
            pass
        else:
            continue   # cautious while the flag is off: hidden, not listed
        try:
            age_days = (time.time() - os.path.getmtime(root / rel)) / 86400
        except OSError:
            age_days = None
        if age_days is not None and age_days < MIN_AGE_DAYS:
            skip(rel, 'recent')
            continue
        tracked = (classified.get(rel, {}).get('signals') or {}).get('tracked')
        why = _never_reason(root, rel, size, max_bytes, tracked)
        if why:
            skip(rel, why)
        elif tracked is None:
            skip(rel, 'unsure')   # git failed: unknown tracked status
        else:
            add(rel, size, 'trash',
                CAT_BUILD_SAFE if (name in BUILD_DIR_SAFE
                                   and not (name == 'node_modules'
                                            and not _has_lockfile(root, rel)))
                else CAT_BUILD_CAUTIOUS,
                d.get('reason') or name,
                name not in BUILD_DIR_SAFE
                or (name == 'node_modules' and not _has_lockfile(root, rel)))

    # 2) empty directories: git cannot track them, rmdir refuses when
    #    they are not empty, so they are default-safe
    for rel in (rep.get('junk') or {}).get('empty_dirs') or []:
        rel = str(rel)
        why = _never_reason(root, rel, 0, max_bytes)
        if why:
            skip(rel, why)
        else:
            add(rel, 0, 'rmdir', CAT_EMPTY, 'empty folder', False)

    # 3) classified junk files and non-build junk dirs: only the ones
    #    the classifier confirmed and git does not track
    build_dir_paths = {str(d.get('path', '')) for d in junk_dirs}
    for e in rep.get('junk_classified') or []:
        rel = str(e.get('path', ''))
        if not rel or rel in seen or rel in build_dir_paths:
            continue
        tracked = (e.get('signals') or {}).get('tracked')
        if e.get('cls') != 'confirmed_unused' or tracked is not False:
            skip(rel, 'tracked' if tracked is True else 'unsure')
            continue
        size = e.get('size_bytes') or 0
        why = _never_reason(root, rel, size, max_bytes, tracked)
        if why:
            skip(rel, why)
        else:
            add(rel, size, 'trash', CAT_CONFIRMED, e.get('reason') or 'unused',
                False)

    # 4) duplicates (cautious only): keep the newest-mtime copy, trash
    #    the rest as 'old copies'
    if include_cautious:
        listing_cache = {}
        for g in rep.get('duplicates') or []:
            group = [str(f) for f in g.get('files') or []]
            size = g.get('size_bytes') or 0
            mtimes = {}
            for f in group:
                if f in seen:
                    continue
                try:
                    mtimes[f] = os.path.getmtime(str(root / os.path.normpath(f)))
                except OSError:
                    skip(f, 'missing')
            alive = [f for f in group if f in mtimes]
            if len(alive) < 2:
                continue
            alive.sort(key=lambda f: mtimes[f])
            keep = alive[-1]
            for f in alive[:-1]:
                tracked = _tracked_status(root, f, listing_cache)
                why = _never_reason(root, f, size, max_bytes, tracked)
                if why:
                    skip(f, why)
                elif tracked is None:
                    skip(f, 'unsure')
                else:
                    add(f, size, 'trash', CAT_OLD_COPIES,
                        'older copy of %s' % keep, True)

    categories = {}
    for it in items:
        c = categories.setdefault(it['category'], {
            'label': CATEGORY_LABELS.get(it['category'], it['category']),
            'count': 0, 'size_bytes': 0, 'cautious': it['cautious']})
        c['count'] += 1
        c['size_bytes'] += it['size']
    return {
        'root': str(root),
        'max_bytes': max_bytes,
        'include_cautious': bool(include_cautious),
        'items': items,
        'categories': categories,
        'skipped': skipped,
        'totals': {'count': len(items),
                   'size_bytes': sum(i['size'] for i in items)},
    }


# --- execution --------------------------------------------------------------------

def execute(plan, root, assume_yes=False, confirm=None):
    """Run a plan built by build_plan. Confirmation first (the answer
    must be exactly 'YES'; assume_yes skips the prompt and exists for
    automation and tests only), then every item under its own try/except
    with the containment and NEVER checks re-run right before it, plus
    the pre-operation gate trashops._pre_operation_check and the
    TOCTOU re-stat: an item whose size, mtime_ns or type changed since
    build_plan, or whose path chain carries a symlink, is aborted (as
    'changed' / 'symlink' / 'escape') and the disk is left alone for
    it. A failing, refused or changed item never aborts the batch.

    The run lands in <root>/<TRASH_DIR_NAME>/<stamp>-<opid>/ with a
    write-ahead manifest.json (trashops.TrashRun). Before the run
    starts, earlier run dirs are scanned for interrupted runs
    (in-flight manifest entries); their opid is recorded in the new
    manifest header and they are never touched. Returns the summary
    dict described in the module docstring."""
    root = Path(root).resolve()
    summary = {'declined': False, 'root': str(root), 'trash_dir': None,
               'opid': None, 'manifest_path': None, 'interrupted_run': None,
               'moved': [], 'removed_dirs': [], 'freed_bytes': 0,
               'freed_by_category': {}, 'skipped_safety': [], 'failed': []}
    items = list((plan or {}).get('items') or [])
    if not items:
        return summary           # an empty plan touches nothing, never prompts
    if not assume_yes:
        ask = confirm if confirm is not None else input
        try:
            answer = ask('Type YES to clean: ')
        except EOFError:
            answer = ''
        if answer != 'YES':
            summary['declined'] = True
            return summary
    max_bytes = min(int(plan.get('max_bytes') or HARD_MAX_BYTES), HARD_MAX_BYTES)

    try:
        interrupted = trashops.find_interrupted(root)
        run = trashops.TrashRun(root, 'safe_clean', interrupted=interrupted)
    except trashops.SecurityRefusal as exc:
        # e.g. the trash folder was swapped for a symlink between the
        # plan and the execute: record the refusal, touch nothing
        summary['failed'].append(
            {'path': trashops.TRASH_DIR_NAME,
             'error': '%s: %s' % (type(exc).__name__, exc)})
        return summary
    summary['interrupted_run'] = interrupted
    summary['trash_dir'] = str(run.run_dir)
    summary['opid'] = run.opid
    summary['manifest_path'] = str(run.manifest_path)
    counts = {'moved': 0, 'failed': 0, 'skipped': 0, 'removed_dirs': 0}

    for it in items:
        rel = str(it.get('path', ''))
        try:
            why = _never_reason(root, rel, it.get('size'), max_bytes)
        except OSError:
            why = 'escape'
        if why:
            summary['skipped_safety'].append({'path': rel, 'reason': why})
            counts['skipped'] += 1
            continue
        target = root / os.path.normpath(rel)
        if not _exists(target):
            summary['skipped_safety'].append({'path': rel, 'reason': 'missing'})
            counts['skipped'] += 1
            continue
        # pre-operation gate: containment + symlink-free chain + snapshot
        # match, immediately before the mutation (the user confirmed
        # already); the symlink walk runs first so a swapped parent or
        # target is reported as 'symlink', not as ordinary drift
        ok, reason = trashops._pre_operation_check(
            root, target, it.get('stat'),
            expected_type=('dir' if it.get('action') == 'rmdir' else None))
        if not ok:
            summary['skipped_safety'].append({'path': rel, 'reason': reason})
            counts['skipped'] += 1
            continue
        cur = trashops.snapshot(target)   # re-stat right before acting
        if not trashops.unchanged(it.get('stat'), cur):
            summary['skipped_safety'].append({'path': rel, 'reason': 'changed'})
            counts['skipped'] += 1
            continue
        if (cur is not None and cur['type'] == 'file' and max_bytes is not None
                and cur['size'] > max_bytes):
            # a hand-built plan without a snapshot: a file that grew past
            # the cap after planning still refuses to move
            summary['skipped_safety'].append({'path': rel, 'reason': 'oversized'})
            counts['skipped'] += 1
            continue
        freed = 0
        try:
            if it.get('action') == 'rmdir':
                trashops.record_rmdir(run, target, rel, cur)
                summary['removed_dirs'].append({'path': rel})
                counts['removed_dirs'] += 1
            elif it.get('action') == 'trash':
                dst, _idx = trashops.move_to_trash(
                    run, target, rel,
                    (cur or {}).get('size') or it.get('size') or 0,
                    (cur or {}).get('mtime_ns'), (cur or {}).get('type'))
                summary['moved'].append({'path': rel, 'moved_to': str(dst),
                                         'size_bytes': it.get('size') or 0,
                                         'category': it.get('category')})
                freed = it.get('size') or 0
                counts['moved'] += 1
            else:
                raise ValueError('unknown action: %r' % (it.get('action'),))
        except Exception as exc:
            summary['failed'].append(
                {'path': rel, 'error': '%s: %s' % (type(exc).__name__, exc)})
            counts['failed'] += 1
            continue
        summary['freed_bytes'] += freed
        cat = it.get('category') or '?'
        summary['freed_by_category'][cat] = summary['freed_by_category'].get(cat, 0) + freed
    run.finish(planned=len(items), freed_bytes=summary['freed_bytes'], **counts)
    return summary


# --- plain-language CLI output ------------------------------------------------------

def _human(n):
    n = float(n or 0)
    for unit in ('B', 'KB', 'MB', 'GB', 'TB'):
        if n < 1024 or unit == 'TB':
            return ('%d %s' % (n, unit)) if unit == 'B' else ('%.1f %s' % (n, unit))
        n /= 1024


def _category_block(key, cat, items):
    head = '  %s: ' % cat.get('label', key)
    if key == CAT_EMPTY:
        head += '%d folder(s)' % cat['count']
    else:
        head += '%d item(s), %s' % (cat['count'], _human(cat['size_bytes']))
    out = [head]
    examples = [i['path'] for i in items if i['category'] == key][:3]
    if examples:
        more = cat['count'] - len(examples)
        text = ', '.join(examples) + (', and %d more' % more if more > 0 else '')
        out.append('    %s' % text)
    return out


def preview_text(plan):
    """The preview screen: plain words, no jargon, sizes in human form."""
    lines = ['Cleanup plan for: %s' % plan.get('root', ''),
             '', 'Safe to remove now:']
    cats = plan.get('categories') or {}
    items = plan.get('items') or []
    safe = [(k, c) for k, c in cats.items() if not c.get('cautious')]
    cautious = [(k, c) for k, c in cats.items() if c.get('cautious')]
    if not safe:
        lines.append('  (nothing)')
    for k, c in safe:
        lines += _category_block(k, c, items)
    if cautious:
        lines.append('')
        lines.append('Optional extras (only because --include-cautious was given):')
        for k, c in cautious:
            lines += _category_block(k, c, items)
    lines.append('')
    lines.append('Will NOT touch: tracked files, settings with keys, '
                 'anything the audit is unsure about.')
    skipped = plan.get('skipped') or []
    if skipped:
        counts = {}
        for s in skipped:
            counts[s.get('reason')] = counts.get(s.get('reason'), 0) + 1
        lines.append('Kept out of the plan: %d (%s)'
                     % (len(skipped), ', '.join('%s: %d' % kv
                                                for kv in sorted(counts.items()))))
        over = [s for s in skipped if s.get('reason') == 'oversized']
        if over:
            lines.append('Too big to move automatically (over %s); handle '
                         'these by hand:' % _human(plan.get('max_bytes')))
            for s in over[:10]:
                lines.append('  %s' % s.get('path'))
    return '\n'.join(lines)


def summary_text(summary):
    """The after-run summary: what was freed, where things went, how to
    get them back. Never prints file contents, only paths and sizes."""
    if summary.get('declined'):
        return 'Nothing was changed.'
    lines = ['Cleanup finished.',
             'Freed %s in total:' % _human(summary.get('freed_bytes'))]
    for cat, size in sorted(summary.get('freed_by_category', {}).items()):
        if size:   # empty folders show up in their own count line below
            lines.append('  %s: %s' % (CATEGORY_LABELS.get(cat, cat), _human(size)))
    if summary.get('removed_dirs'):
        lines.append('Empty folders removed: %d' % len(summary['removed_dirs']))
    lines.append('Moved %d item(s) to trash.' % len(summary.get('moved') or []))
    if summary.get('trash_dir'):
        lines.append('Trash run: %s' % summary['trash_dir'])
        lines.append('Operation id: %s' % summary.get('opid'))
        lines.append('Manifest: %s' % summary.get('manifest_path'))
        lines.append('To undo this run: python %s.py restore "%s" --root "%s"'
                     % (Path(__file__).stem, summary['trash_dir'],
                        summary.get('root') or ''))
    lines.append('Everything this run changed can be undone with the '
                 'command above, removed empty folders included.')
    lines.append('The trash is never emptied automatically; delete it by '
                 'hand once you are satisfied.')
    if summary.get('skipped_safety'):
        lines.append('Skipped as unsafe: %d' % len(summary['skipped_safety']))
    if summary.get('failed'):
        lines.append('Failed: %d (the rest of the plan was not affected)'
                     % len(summary['failed']))
    lines.append('Run the audit again to see the after-report.')
    return '\n'.join(lines)


# --- CLI ---------------------------------------------------------------------------

# API re-export: the restore entry point lives in trashops next to the
# manifest code it depends on; safe_clean re-exports it so callers of
# the cleaner can find it in one place.
restore = trashops.restore


def _restore_text(summary):
    """The after-restore summary screen."""
    if summary.get('declined'):
        return 'Nothing was changed.'
    lines = ['Restore finished.',
             'Restored %d item(s) from: %s'
             % (len(summary.get('restored') or []), summary.get('run_dir'))]
    if summary.get('opid'):
        lines.append('Operation id: %s' % summary['opid'])
    for r in summary.get('restored') or []:
        if r.get('restored_to') != r.get('original_path'):
            lines.append('  %s -> %s (original spot was occupied)'
                         % (r['original_path'], r['restored_to']))
    if summary.get('not_restorable'):
        lines.append('%d item(s) were removed empty folders; those cannot '
                     'be restored.' % summary['not_restorable'])
    if summary.get('already_done'):
        lines.append('%d item(s) were already restored earlier.'
                     % summary['already_done'])
    if summary.get('failed'):
        lines.append('Failed: %d (the rest of the run was not affected)'
                     % len(summary['failed']))
    lines.append('Manifest updated: %s' % summary.get('manifest_path'))
    return '\n'.join(lines)


def _restore_main(argv):
    """`safe_clean.py restore <run_dir> [--root R] [--yes]` -- undo one
    trash run recorded in its manifest. Exit codes: 0 ok or declined, 1
    some items failed to restore, 2 bad arguments or unreadable
    manifest."""
    ap = argparse.ArgumentParser(
        prog='safe_clean.py restore',
        description='Put one trash run back: reads the run manifest and '
                    'moves every recorded item to its original place '
                    '(or next to it, suffixed .restored-N, when that place '
                    'is taken). Nothing is ever overwritten.')
    ap.add_argument('run_dir',
                    help='trash run directory printed by the cleanup '
                         '(contains manifest.json)')
    ap.add_argument('--root', default=None, metavar='R',
                    help='workspace root (default: the root recorded in '
                         'the manifest)')
    ap.add_argument('--yes', action='store_true',
                    help='skip the YES confirmation prompt (automation and '
                         'tests only; every safety check stays on)')
    a = ap.parse_args(argv)
    try:
        summary = trashops.restore(a.run_dir, a.root, assume_yes=a.yes)
    except (OSError, ValueError) as exc:
        print('%s: %s' % (PROG, exc), file=sys.stderr)
        return EXIT_ARGS
    print(_restore_text(summary))
    for f in summary.get('failed') or []:
        print('%s: failed on %s: %s' % (PROG, f.get('original_path'),
                                        f.get('error')), file=sys.stderr)
    return EXIT_OK if not summary.get('failed') else EXIT_NOTHING


def _root_refusal(root):
    """NEVER-list reason for the user-supplied root itself, or None."""
    if os.path.islink(str(root)):
        return 'the workspace root is a symlink; the cleaner never follows links'
    if root.name == '.git' or any(p.name == '.git' for p in root.parents):
        return ('the workspace root is inside a .git directory; '
                'git internals are never touched')
    if root.name == TRASH_DIR_NAME or any(p.name == TRASH_DIR_NAME
                                          for p in root.parents):
        return ('the workspace root is the audit trash folder; '
                'restore or delete the trash by hand')
    return None


def main(argv=None):
    args = list(sys.argv[1:]) if argv is None else list(argv)
    if args and args[0] == 'restore':   # subcommand, keeps <root> positional
        return _restore_main(args[1:])

    ap = argparse.ArgumentParser(
        prog='safe_clean.py',
        description='Guided, near-zero-risk cleanup for an agent workspace: '
                    'scan, show a plain-language plan, ask for the word YES, '
                    'then move junk into a trash folder inside the workspace. '
                    'Nothing is deleted outright.',
        epilog='Everything movable lands in %s/<timestamp>-<opid>/ inside '
               'the workspace, recorded in a manifest.json you can undo '
               'with: safe_clean.py restore <run_dir>. Exit codes: 0 done '
               'or declined, 1 nothing to clean, 2 bad arguments or root, '
               '3 safety refusal.' % TRASH_DIR_NAME)
    ap.add_argument('root', help='workspace root to clean')
    ap.add_argument('--home', default=str(Path.home()),
                    help='home directory for the scan (default: this user home)')
    ap.add_argument('--yes', action='store_true',
                    help='skip the YES confirmation prompt (automation and '
                         'tests only; every safety check stays on)')
    ap.add_argument('--include-cautious', action='store_true',
                    help='also clean the cautious categories: local-state '
                         'build folders (dist, build, target, venv, .idea) '
                         'and old copies of duplicate files')
    ap.add_argument('--max-bytes', type=int, default=DEFAULT_MAX_BYTES,
                    metavar='N',
                    help='skip single items larger than N bytes (default and '
                         'hard ceiling: %d)' % DEFAULT_MAX_BYTES)
    a = ap.parse_args(args)

    raw = Path(a.root)
    try:
        root = raw.resolve()
    except OSError as exc:
        print('%s: cannot use root %s: %s' % (PROG, a.root, exc), file=sys.stderr)
        return EXIT_ARGS
    why = _root_refusal(raw)
    if why is None and not root.is_dir():
        print('%s: not a directory: %s' % (PROG, root), file=sys.stderr)
        return EXIT_ARGS
    if why:
        print('%s: refusing to run: %s' % (PROG, why), file=sys.stderr)
        return EXIT_REFUSAL

    home = Path(a.home).resolve()
    rep = audit_scan.scan(root, home, False)
    plan = build_plan(rep, include_cautious=a.include_cautious,
                      max_bytes=a.max_bytes)
    if not plan['items']:
        print('Nothing safe to clean was found in this workspace.')
        if plan['skipped']:
            print('Kept out of the plan: %d item(s).'
                  % len(plan['skipped']))
        return EXIT_NOTHING

    print(preview_text(plan))
    print()
    summary = execute(plan, root, assume_yes=a.yes)
    if summary['declined']:
        print('Nothing was changed.')
        return EXIT_OK
    print(summary_text(summary))
    for f in summary['failed']:
        print('%s: failed on %s: %s' % (PROG, f['path'], f['error']),
              file=sys.stderr)
    return EXIT_OK


if __name__ == '__main__':
    sys.exit(main())
