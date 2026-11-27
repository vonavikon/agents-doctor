#!/usr/bin/env python3
"""Shared trash-run machinery for the two file-mutating tools,
safe_clean.py and remediate.py.

Both tools move junk into timestamped run directories under
<root>/<TRASH_DIR_NAME>/ and record everything they do in a manifest.json
inside the run directory. The rules implemented here:

- Operation id: every execute() run gets a short random opid (8 hex
  chars); the run directory is <YYYYmmdd-HHMMSS>-<opid>, so two runs in
  the same second can never share a directory.
- Write-ahead manifest: the entry for an item is written with an
  in-flight status ('moving', 'removing', 'creating') BEFORE the
  operation starts and updated to its final status ('moved', 'removed',
  'created', 'failed') after. A crash mid-run leaves the in-flight
  entry visible in the manifest, which is exactly what crash recovery
  looks for.
- Manifest header: {opid, manifest_schema_version, root, started_at,
  tool, interrupted_run, totals}; entries add {action, original_path,
  trash_path, size, mtime_ns, sha256?, moved_at, status, error?,
  restorable}. manifest_schema_version '2' (what this code writes)
  journals every operation type below; version '1' -- manifests from
  before the field existed -- covers trash moves and non-restorable
  rmdirs only.
- Entry actions (schema 2): trash_move (restore moves the item back),
  rmdir (restore recreates the empty directory), create_file (restore
  deletes the file again while its sha256 still matches) and
  create_directory (restore removes the directory again while it is
  still empty). Schema 1 wrote 'trash' for trash_move and recorded
  rmdirs with restorable: false; both old spellings stay readable.
- Crash recovery: before a new run starts, earlier run directories are
  scanned; a manifest holding any in-flight entry
  ('moving'/'removing'/'creating') marks that run as interrupted.
  Nothing in it is deleted or resumed blindly -- its opid is recorded
  in the new manifest header as 'interrupted_run' and the new run
  continues. Beyond detecting, find_incomplete(root) lists the
  in-flight entries of the latest interrupted run and recover(root)
  rolls each one back to its pre-operation state (trash copies move
  back, created files/directories are removed after a re-check,
  removed empty directories are recreated); anything that cannot be
  rolled back without risking data is left in place and reported as a
  conflict. Recovery is idempotent and itself write-ahead.
- Concurrency lock: <root>/<TRASH_DIR_NAME>/.lock (O_EXCL creation,
  content pid + timestamp) serializes mutating runs; a second run
  while the lock is alive fails with LockBusy (remediate re-exports it
  as RemediateBusy), a lock older than an hour whose pid is gone is
  stolen with a journal line. On Windows the pid cannot be probed
  safely, so lock age alone decides the steal.
- Destination collisions never overwrite: an existing trash destination
  gets '.__N__' (N=1..999) appended to the basename until a free name is
  found. The manifest records the suffixed path.
- TOCTOU snapshots: planning code records {size, mtime_ns, type} per
  item via snapshot(); the executor re-stats immediately before each
  operation and aborts the item when unchanged() says the file changed.
- Pre-operation gate: every mutating operation calls
  _pre_operation_check(root, target, snapshot) immediately before the
  filesystem change (after the user confirmed): canonical containment
  under root, no symlink anywhere in the literal path chain from root
  to target, expected type and snapshot size/mtime must all hold. A
  refusal raises SecurityRefusal (or skips the item -- the caller's
  choice) and the disk is left alone. Created files are made with
  os.open(O_CREAT|O_EXCL), so a name planted in the gap can neither be
  written through nor overwritten.
- Restore: restore(run_dir, root) undoes every restorable entry of one
  run: 'moved' items move back (with a '.restored-N' suffix when the
  original location is occupied), removed empty directories are
  recreated, created files are deleted again while their sha256 still
  matches and created directories are removed again while still empty.
  Entries whose disk state moved on are skipped with a warning instead
  of destroyed; already-restored entries are a no-op.

Every mutating helper re-checks containment (resolved paths must stay
under root / the run directory) right before it acts. Python 3.9+,
stdlib only.
"""
import hashlib
import json
import os
import shutil
import stat as stat_mod
import sys
import time
import uuid
from datetime import datetime
from pathlib import Path

# shared trash root name; safe_clean and remediate re-export this
TRASH_DIR_NAME = '.agents-doctor-trash'
MANIFEST_NAME = 'manifest.json'

# manifest schema versions: '1' is every manifest written before the
# manifest_schema_version field existed (trash moves plus rmdirs that
# were not restorable), '2' journals all four operation types and is
# the only version this code writes
SCHEMA_V1 = '1'
SCHEMA_V2 = '2'
MANIFEST_SCHEMA_VERSION = SCHEMA_V2

# entry actions (schema 2 vocabulary)
ACTION_TRASH_MOVE = 'trash_move'
ACTION_RMDIR = 'rmdir'
ACTION_CREATE_FILE = 'create_file'
ACTION_CREATE_DIRECTORY = 'create_directory'
ACTIONS = (ACTION_TRASH_MOVE, ACTION_RMDIR, ACTION_CREATE_FILE,
           ACTION_CREATE_DIRECTORY)

# entry statuses that mean "an operation was in flight when the process
# died" -- the signal crash recovery looks for. 'recovering' is written
# by recover() itself before it rolls an entry back, so a recovery that
# crashed mid-undo leaves the entry visible to the next recovery.
IN_FLIGHT = ('moving', 'removing', 'creating', 'recovering')

# statuses restore() will pick up (plus 'restoring', left behind by a
# restore that crashed mid-undo; a restore that failed once can be
# retried while there is still something to undo). 'recovered' and
# 'recovery_conflict' (written by recover()) are deliberately absent:
# after a rollback the entry is done, and a conflict entry keeps its
# disk state for a human to resolve.
RESTORABLE = ('moved', 'removed', 'created', 'restore_failed', 'restoring')

# statuses a completed-but-not-restored entry can carry; used to count
# the entries the restorable flag keeps out of the undo set
DONE_STATUSES = ('moved', 'removed', 'created')

# terminal statuses recover() writes: rollback complete, or rollback
# impossible without risking someone's data (left in place, reported)
STATUS_RECOVERED = 'recovered'
STATUS_RECOVERY_CONFLICT = 'recovery_conflict'


class SecurityRefusal(ValueError):
    """A _pre_operation_check refused the mutation (TOCTOU
    defence): the target failed the containment, symlink-chain or
    snapshot verification run immediately before the filesystem
    change. Nothing was touched."""
    # ValueError base: callers that catch ValueError (cmd_fix,
    # plan()) get a clean one-line refusal instead of a traceback.


def new_opid():
    """Short operation id: first 8 hex chars of a uuid4."""
    return uuid.uuid4().hex[:8]


def run_stamp():
    """Run-directory timestamp part: YYYYmmdd-HHMMSS."""
    return datetime.now().strftime('%Y%m%d-%H%M%S')


def _iso_now():
    return datetime.now().isoformat(timespec='seconds')


def snapshot(path):
    """{size, mtime_ns, type} from os.stat, or None when stat fails
    (missing path, lost permissions). 'type' is 'dir', 'file' or
    'other'. Symlinks are never snapshotted here: the callers refuse
    them before this runs."""
    try:
        st = os.stat(str(path))
    except OSError:
        return None
    if stat_mod.S_ISDIR(st.st_mode):
        kind = 'dir'
    elif stat_mod.S_ISREG(st.st_mode):
        kind = 'file'
    else:
        kind = 'other'
    return {'size': st.st_size, 'mtime_ns': st.st_mtime_ns, 'type': kind}


def unchanged(snap, cur):
    """True when the plan-time snapshot and the execute-time re-stat
    describe the same file: same size, mtime_ns and type. A missing
    plan-time snapshot (a hand-built plan) means 'nothing to compare'
    and passes; a plan-time snapshot with a failed re-stat means the
    item changed (or vanished) and does not pass."""
    if snap is None:
        return True
    if cur is None:
        return False
    return (snap.get('size') == cur.get('size')
            and snap.get('mtime_ns') == cur.get('mtime_ns')
            and snap.get('type') == cur.get('type'))


def _pre_operation_check(root, target_path, snapshot=None,
                         expected_type=None, allow_missing=False):
    """Last-chance TOCTOU gate for every mutating operation.

    Runs immediately before the filesystem change and after the user
    confirmed. Verifies, in order:

    - no symlink sits anywhere in the literal path chain between the
      resolved root and the target: a parent directory swapped for a
      link, or the target itself replaced by one, is refused however
      innocent its destination looks (resolve() alone would accept a
      link whose destination is still inside the root);
    - the resolved target is strictly under the resolved root;
    - the target exists and its on-disk type matches the expected one
      (taken from the snapshot, or from expected_type);
    - size and mtime_ns still match the plan-time snapshot.

    Returns (ok, reason): reason is None on success and a short word on
    refusal -- 'symlink', 'escape', 'missing', 'changed' or
    'unreadable'. allow_missing=True (create-style operations: the
    target is about to be created) skips the existence, type and
    snapshot checks but keeps the symlink walk and containment, so a
    symlink planted anywhere on the chain below root still refuses.
    """
    try:
        root_canon = Path(root).resolve()
    except OSError:
        return False, 'unreadable'
    target = Path(target_path)
    # literal chain below the root: every component is lstat-checked;
    # components above the root are the user's own spelling of the root
    # and are not judged here
    try:
        rel_parts = target.relative_to(root_canon).parts
    except ValueError:
        rel_parts = None
    if rel_parts is not None:
        node = root_canon
        for part in rel_parts:
            node = node / part
            if os.path.islink(str(node)):
                return False, 'symlink'
    else:
        # target not spelled below the resolved root (8.3 aliases and
        # friends): walk the literal ancestors until one resolves to
        # the root; anything symlinked on the way is a refusal
        for anc in target.parents:
            try:
                if anc.resolve() == root_canon:
                    break
            except OSError:
                pass
            if os.path.islink(str(anc)):
                return False, 'symlink'
        if os.path.islink(str(target)):
            return False, 'symlink'
    if os.path.islink(str(target)):
        return False, 'symlink'
    try:
        resolved = target.resolve()
    except OSError:
        return False, 'unreadable'
    if root_canon not in resolved.parents:
        return False, 'escape'
    try:
        st = os.stat(str(target))
    except OSError:
        if allow_missing:
            return True, None
        return False, 'missing'
    if stat_mod.S_ISDIR(st.st_mode):
        kind = 'dir'
    elif stat_mod.S_ISREG(st.st_mode):
        kind = 'file'
    else:
        kind = 'other'
    expected = (snapshot or {}).get('type') or expected_type
    if expected and kind != expected:
        return False, 'changed'
    if snapshot is not None:
        cur = {'size': st.st_size, 'mtime_ns': st.st_mtime_ns, 'type': kind}
        if not unchanged(snapshot, cur):
            return False, 'changed'
    return True, None


def _exists(p):
    """exists() that treats permission errors as absent (pathlib raises)."""
    try:
        return p.exists()
    except OSError:
        return False


def _rel_shape_ok(rel):
    """A relative path is usable inside root/run_dir: not absolute, no
    '..' after normalization, not empty."""
    p = os.path.normpath(str(rel))
    return bool(p) and p != '.' and not os.path.isabs(p) \
        and p != '..' and not p.startswith('..' + os.sep)


def _is_under(path, base):
    """True when resolved path is strictly below resolved base."""
    try:
        path = Path(path).resolve()
        base = Path(base).resolve()
    except OSError:
        return False
    return base in path.parents


def collision_free_dst(dst):
    """Never overwrite: when dst exists, append '.__N__' (N=1..999) to
    the basename until a free name is found. Raises OSError when all
    999 are taken (a pathological directory nobody should have)."""
    if not _exists(dst):
        return dst
    for n in range(1, 1000):
        cand = dst.parent / ('%s.__%d__' % (dst.name, n))
        if not _exists(cand):
            return cand
    raise OSError('no free trash destination under %s' % dst)


def load_manifest(run_dir):
    """Read manifest.json from a run dir; ValueError when missing or
    not valid JSON. Returns the parsed dict."""
    mp = Path(run_dir) / MANIFEST_NAME
    try:
        data = json.loads(mp.read_text(encoding='utf-8'))
    except OSError as exc:
        raise ValueError('no %s in %s: %s' % (MANIFEST_NAME, run_dir, exc))
    except ValueError as exc:
        raise ValueError('cannot parse %s: %s' % (mp, exc))
    if not isinstance(data, dict):
        raise ValueError('%s is not a manifest object: %s' % (mp, type(data).__name__))
    return data


def save_manifest(run_dir, data):
    """Write a manifest atomically (temp file + os.replace), so a crash
    mid-write never leaves a half-written manifest behind."""
    mp = Path(run_dir) / MANIFEST_NAME
    tmp = mp.with_name(MANIFEST_NAME + '.tmp')
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2),
                   encoding='utf-8')
    os.replace(str(tmp), str(mp))
    return mp


class TrashRun:
    """One execute() run: a unique run directory plus its write-ahead
    manifest. Created only after the user confirmed; the header is on
    disk before the first item runs."""

    def __init__(self, root, tool, opid=None, stamp=None, interrupted=None):
        self.root = Path(root).resolve()
        self.opid = opid or new_opid()
        self.run_dir = self.root / TRASH_DIR_NAME / ('%s-%s' % (stamp or run_stamp(), self.opid))
        self.manifest_path = self.run_dir / MANIFEST_NAME
        self.header = {
            'opid': self.opid,
            'manifest_schema_version': MANIFEST_SCHEMA_VERSION,
            'root': str(self.root),
            'started_at': _iso_now(),
            'tool': str(tool),
            'interrupted_run': interrupted,
            'totals': {'planned': 0, 'moved': 0, 'failed': 0, 'skipped': 0,
                       'removed_dirs': 0, 'created': 0, 'freed_bytes': 0},
        }
        self.entries = []
        # the trash chain must be real directories, not symlinks
        # planted between confirmation and the first move -- a linked
        # trash folder would route the whole run (manifest included)
        # outside the workspace root
        trash_parent = self.root / TRASH_DIR_NAME
        if os.path.islink(str(trash_parent)):
            raise SecurityRefusal(
                'the trash folder is a symlink; a run cannot be routed '
                'through it: %s' % trash_parent)
        self.run_dir.mkdir(parents=True, exist_ok=True)
        if os.path.islink(str(self.run_dir)):
            raise SecurityRefusal(
                'the trash run directory is a symlink: %s' % self.run_dir)
        self.save()

    def save(self):
        """Flush header + entries to manifest.json (atomic replace)."""
        save_manifest(self.run_dir,
                      dict(self.header, totals=dict(self.header['totals']),
                           entries=self.entries))

    def add_entry(self, entry):
        """Append an entry and flush; returns its index."""
        self.entries.append(entry)
        self.save()
        return len(self.entries) - 1

    def update_entry(self, idx, **fields):
        """Patch one entry (by index) and flush."""
        self.entries[idx].update(fields)
        self.save()

    def finish(self, **totals):
        """Record the final totals (keys must match the zeroed set)."""
        self.header['totals'].update(totals)
        self.save()


def move_to_trash(run, src, rel, size, mtime_ns, kind=None):
    """Move one confirmed path into the run directory, write-ahead
    style: the manifest entry goes to disk with status 'moving' before
    shutil.move runs, then becomes 'moved' or 'failed'. The destination
    is collision-suffixed, never overwritten. Returns (dst, entry_idx).
    Raises whatever the move raised after marking the entry 'failed'.

    The destination side is gated right before the move -- the
    run directory and every component below it up to the destination
    parent must be real directories under root. A trash chain swapped
    for symlinks after the user confirmed raises SecurityRefusal before
    anything is written."""
    rel = os.path.normpath(str(rel))
    ok, reason = _pre_operation_check(run.root, run.run_dir,
                                      expected_type='dir')
    if not ok:
        raise SecurityRefusal('trash run directory refused (%s): %s'
                              % (reason, run.run_dir))
    dst = collision_free_dst(run.run_dir / rel)
    ok, reason = _pre_operation_check(run.root, dst.parent,
                                      allow_missing=True)
    if not ok:
        raise SecurityRefusal('trash destination refused (%s): %s'
                              % (reason, dst.parent))
    dst.parent.mkdir(parents=True, exist_ok=True)
    if _exists(dst):
        # the name was free a moment ago: something raced us, and
        # shutil.move onto an existing path can overwrite on POSIX
        raise SecurityRefusal('trash destination appeared before the '
                              'move: %s' % dst)
    idx = run.add_entry({
        'opid': run.opid,
        'action': ACTION_TRASH_MOVE,
        'original_path': rel,
        'trash_path': dst.relative_to(run.run_dir).as_posix(),
        'size': size or 0,
        'mtime_ns': mtime_ns,
        'type': kind,
        'moved_at': _iso_now(),
        'status': 'moving',
        'restorable': True,
    })
    try:
        shutil.move(str(src), str(dst))
    except Exception as exc:
        run.update_entry(idx, status='failed',
                         error='%s: %s' % (type(exc).__name__, exc))
        raise
    run.update_entry(idx, status='moved')
    return dst, idx


def record_rmdir(run, target, rel, snap):
    """rmdir one confirmed-empty directory, write-ahead style: entry
    status 'removing' before os.rmdir, 'removed' after. The entry is
    restorable: restore() recreates the (empty) directory with
    os.makedirs, so an empty folder costs nothing to get back. The
    manifest also records parent_exists, whether the directory's parent
    existed at removal time."""
    target = Path(target)
    idx = run.add_entry({
        'opid': run.opid,
        'action': ACTION_RMDIR,
        'original_path': os.path.normpath(str(rel)),
        'trash_path': None,
        'size': (snap or {}).get('size') or 0,
        'mtime_ns': (snap or {}).get('mtime_ns'),
        'type': (snap or {}).get('type'),
        'parent_exists': _exists(target.parent),
        'moved_at': _iso_now(),
        'status': 'removing',
        'restorable': True,
    })
    try:
        os.rmdir(str(target))
    except Exception as exc:
        run.update_entry(idx, status='failed',
                         error='%s: %s' % (type(exc).__name__, exc))
        raise
    run.update_entry(idx, status='removed')
    return idx


def record_create_file(run, target, rel, data):
    """Create one file, write-ahead style: the entry goes to disk with
    status 'creating' and the sha256 of the bytes about to be written
    BEFORE the write, then becomes 'created' or 'failed'. Restore
    deletes the file again, but only while its hash still matches -- a
    file modified after the run is kept and reported as skipped. data
    may be str (written as UTF-8) or bytes. Returns the entry index;
    raises whatever the write raised after marking the entry 'failed'.

    The file is created with os.open(O_CREAT|O_EXCL) -- a name
    that appears between the caller's check and this write (or a
    symlink planted there) makes the open fail; an existing file is
    never opened, written through or overwritten."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    target = Path(target)
    idx = run.add_entry({
        'opid': run.opid,
        'action': ACTION_CREATE_FILE,
        'original_path': os.path.normpath(str(rel)),
        'trash_path': None,
        'size': len(data),
        'mtime_ns': None,
        'type': 'file',
        'sha256': hashlib.sha256(data).hexdigest(),
        'parent_exists': _exists(target.parent),
        'moved_at': _iso_now(),
        'status': 'creating',
        'restorable': True,
    })
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, 'O_BINARY'):
            flags |= os.O_BINARY
        fd = os.open(str(target), flags, 0o644)
        try:
            os.write(fd, data)
        finally:
            os.close(fd)
    except Exception as exc:
        run.update_entry(idx, status='failed',
                         error='%s: %s' % (type(exc).__name__, exc))
        raise
    run.update_entry(idx, status='created')
    return idx


def record_create_directory(run, target, rel, snap=None):
    """mkdir one directory, write-ahead style: entry status 'creating'
    before os.mkdir (which refuses an existing path), 'created' after.
    Restore removes the directory again, but only while it is still
    empty -- one that gained content is kept and reported as skipped."""
    target = Path(target)
    idx = run.add_entry({
        'opid': run.opid,
        'action': ACTION_CREATE_DIRECTORY,
        'original_path': os.path.normpath(str(rel)),
        'trash_path': None,
        'size': (snap or {}).get('size') or 0,
        'mtime_ns': (snap or {}).get('mtime_ns'),
        'type': (snap or {}).get('type') or 'dir',
        'parent_exists': _exists(target.parent),
        'moved_at': _iso_now(),
        'status': 'creating',
        'restorable': True,
    })
    try:
        os.mkdir(str(target))
    except Exception as exc:
        run.update_entry(idx, status='failed',
                         error='%s: %s' % (type(exc).__name__, exc))
        raise
    run.update_entry(idx, status='created')
    return idx


def find_interrupted(root):
    """Scan <root>/<TRASH_DIR_NAME>/*/manifest.json for in-flight
    entries ('moving'/'removing'/'creating'). Returns the opid of the
    most recent interrupted run (by manifest mtime), or None.
    Interrupted runs are never modified or resumed by this call -- the
    caller only records the opid."""
    trash = Path(root) / TRASH_DIR_NAME
    best_mtime, best_opid = None, None
    try:
        run_dirs = sorted(trash.iterdir())
    except OSError:
        return None
    for rd in run_dirs:
        mp = rd / MANIFEST_NAME
        if not _exists(mp):
            continue
        try:
            data = json.loads(mp.read_text(encoding='utf-8'))
        except (OSError, ValueError):
            continue
        entries = data.get('entries') or []
        if isinstance(entries, list) and any(
                isinstance(e, dict) and e.get('status') in IN_FLIGHT
                for e in entries):
            try:
                mtime = mp.stat().st_mtime
            except OSError:
                mtime = 0
            if best_mtime is None or mtime >= best_mtime:
                best_mtime, best_opid = mtime, data.get('opid') or rd.name
    return best_opid


# --- concurrency lock ---------------------------------------------------------------

# lock file inside the trash root guarding every mutating run; content
# is "<pid>\n<started_at ISO>\n"
LOCK_NAME = '.lock'
LOCK_STALE_SECONDS = 3600


class LockBusy(ValueError):
    """The trash lock is held by another live run. Raised (never a
    traceback) so callers like remediate.apply_plan can refuse cleanly;
    remediate re-exports it as RemediateBusy. Subclasses ValueError on
    purpose: agents_doctor.py's fix command already turns ValueError
    from apply_plan into a one-line refusal, and this way the busy case
    rides the same path without a traceback."""


def _pid_alive(pid):
    """Whether a pid still has a process. Returns True/False when
    knowable, None when unknown. On POSIX os.kill(pid, 0) probes without
    signalling; on Windows os.kill with any signal would TERMINATE the
    target, so the pid is declared unknown there and staleness is judged
    by lock age alone."""
    if not isinstance(pid, int) or pid <= 0:
        return False       # garbage lock content: nothing to protect
    if os.name == 'nt':
        return None
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True        # exists, owned by another user
    except OSError:
        return None
    return True


class TrashLock:
    """Exclusive lock for trash-mutating runs: O_EXCL creation of
    <root>/<TRASH_DIR_NAME>/.lock holding "<pid>\\n<started_at>".

    A second acquire() while the lock exists raises LockBusy -- a clean
    refusal, not a race. A lock older than LOCK_STALE_SECONDS whose pid
    is provably gone is stolen instead (journaled to stderr, stolen=True
    on the lock object); on Windows, where a pid probe cannot be made
    safely, age alone decides. release() removes the file only while it
    still names this process, so a lock re-stolen meanwhile is left
    alone. Usable as a context manager; release() is idempotent."""

    def __init__(self, root):
        self.root = Path(root).resolve()
        self.path = self.root / TRASH_DIR_NAME / LOCK_NAME
        self.held = False
        self.stolen = False

    def acquire(self):
        trash_parent = self.root / TRASH_DIR_NAME
        if os.path.islink(str(trash_parent)):
            raise SecurityRefusal(
                'the trash folder is a symlink; a lock cannot be routed '
                'through it: %s' % trash_parent)
        trash_parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(str(self.path),
                         os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        except FileExistsError:
            self._steal_or_busy()
            return self
        with os.fdopen(fd, 'w', encoding='utf-8') as fh:
            fh.write('%d\n%s\n' % (os.getpid(), _iso_now()))
        self.held = True
        return self

    def _read_pid(self):
        """pid recorded in the lock file, or None when unreadable."""
        try:
            first = self.path.read_text(encoding='utf-8').splitlines()
        except (OSError, ValueError):
            return None
        if first and first[0].strip().isdigit():
            return int(first[0].strip())
        return None

    def _steal_or_busy(self):
        try:
            age = time.time() - os.stat(str(self.path)).st_mtime
        except OSError:
            age = None       # unreadable: treat as fresh and refuse
        pid = self._read_pid()
        alive = _pid_alive(pid)
        if age is not None and age > LOCK_STALE_SECONDS and not alive:
            print('warning: stealing stale trash lock %s (age %ds, pid %s)'
                  % (self.path, int(age), pid), file=sys.stderr)
            tmp = self.path.with_name('%s.stolen-%d' % (LOCK_NAME, os.getpid()))
            tmp.write_text('%d\n%s\n' % (os.getpid(), _iso_now()),
                           encoding='utf-8')
            os.replace(str(tmp), str(self.path))
            self.stolen = True
            self.held = True
            return
        raise LockBusy(
            'another trash run holds the lock (pid %s, age %ss): %s'
            % (pid, 'unknown' if age is None else int(age), self.path))

    def release(self):
        """Remove the lock when it is still ours; never raises."""
        if not self.held:
            return
        self.held = False
        try:
            if self._read_pid() == os.getpid():
                os.remove(str(self.path))
        except OSError:
            pass            # already gone or unreadable: nothing to do

    def __enter__(self):
        return self.acquire()

    def __exit__(self, _exc_type, _exc, _tb):
        self.release()
        return False


# --- restore ------------------------------------------------------------------------

def _sha256_file(path):
    """sha256 hex digest of a file's current bytes, read in chunks."""
    h = hashlib.sha256()
    with open(str(path), 'rb') as fh:
        for chunk in iter(lambda: fh.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def _entry_action(entry):
    """Normalized action of a manifest entry: version 1 wrote 'trash'
    for what version 2 calls trash_move; both spellings keep working."""
    action = entry.get('action', ACTION_TRASH_MOVE)
    return ACTION_TRASH_MOVE if action == 'trash' else action


def _undo_target(root, orig):
    """Validated absolute destination for undoing original_path: the
    relative shape must be safe, the resolved path must stay under
    root and out of the trash folder, and the whole literal
    chain below root must be symlink-free -- a link planted at the
    original spot or anywhere above it refuses the undo. Raises
    ValueError otherwise."""
    if not _rel_shape_ok(orig):
        raise ValueError('path has an unsafe shape')
    dst = root / os.path.normpath(orig)
    resolved = dst.resolve()
    if root not in resolved.parents \
            or resolved.parts[len(root.parts)] == TRASH_DIR_NAME:
        raise ValueError('original path escapes root or sits in the '
                         'trash folder')
    ok, reason = _pre_operation_check(root, dst, allow_missing=True)
    if not ok:
        raise ValueError('restore destination refused (%s): %s'
                         % (reason, dst))
    return dst


def _undo_entry(run_dir, root, entry):
    """Undo one manifest entry (its status is 'restoring' by the time
    this runs). Returns ('restored', dst_path) on success, or
    ('skipped', reason) when the disk moved on after the run and
    undoing now would destroy someone else's work. Raises when the
    attempt belongs in the summary as a failure."""
    action = _entry_action(entry)
    orig = str(entry.get('original_path') or '')
    if action == ACTION_TRASH_MOVE:
        trash_rel = str(entry.get('trash_path') or '')
        if not _rel_shape_ok(trash_rel):
            raise ValueError('trash path has an unsafe shape')
        src = run_dir / trash_rel
        if not _is_under(src, run_dir) or not _exists(src):
            raise ValueError('trash copy missing or outside the run dir: %s'
                             % trash_rel)
        # manifest integrity: a file entry must still carry the
        # size recorded when it was moved; a mismatch means the manifest
        # (or the copy) was tampered with. A recorded size of 0 counts
        # as 'not recorded' -- legacy and hand-built entries.
        if entry.get('type') == 'file':
            recorded = entry.get('size')
            try:
                actual = os.stat(str(src)).st_size
            except OSError:
                actual = None
            if (actual is not None and isinstance(recorded, int)
                    and recorded > 0 and actual != recorded):
                raise ValueError(
                    'trash copy size %d does not match the manifest record '
                    '%d: %s' % (actual, recorded, trash_rel))
        dst = _undo_target(root, orig)
        if _exists(dst):
            for n in range(1, 1000):
                cand = dst.parent / ('%s.restored-%d' % (dst.name, n))
                if not _exists(cand):
                    dst = cand
                    break
            else:
                raise OSError('no free restore destination for %s' % dst)
        if _exists(dst):
            # the name was free during the collision check: something
            # raced us; never move onto an appeared path
            raise ValueError('restore destination appeared after the '
                             'collision check: %s' % dst)
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(src), str(dst))
        return 'restored', dst
    if action == ACTION_RMDIR:
        # an empty directory costs nothing to recreate, parents included;
        # one that already came back is a plain success
        dst = _undo_target(root, orig)
        os.makedirs(str(dst), exist_ok=True)
        return 'restored', dst
    if action == ACTION_CREATE_FILE:
        dst = _undo_target(root, orig)
        if not _exists(dst):
            return 'restored', dst      # already gone: the undo state holds
        sha = entry.get('sha256')
        if not sha:
            return 'skipped', 'no sha256 recorded; file left in place'
        if _sha256_file(dst) != sha:
            return 'skipped', 'file was modified after the run; left in place'
        os.remove(str(dst))
        return 'restored', dst
    if action == ACTION_CREATE_DIRECTORY:
        dst = _undo_target(root, orig)
        if not _exists(dst):
            return 'restored', dst      # already gone
        if any(dst.iterdir()):
            return 'skipped', 'directory gained content after the run; ' \
                             'left in place'
        os.rmdir(str(dst))
        return 'restored', dst
    raise ValueError('unknown action: %r' % (entry.get('action'),))


def restore(run_dir, root=None, opid=None, assume_yes=False, confirm=None):
    """Undo one journaled run: every restorable entry goes back to the
    pre-run state, whatever the operation type was.

    Reads <run_dir>/manifest.json, asks for the word YES (assume_yes
    exists for tests and automation only), then undoes every entry
    whose status is 'moved', 'removed', 'created' or 'restore_failed'
    and whose restorable flag is true:

    - trash_move: the trash copy moves back to root/<original_path>,
      or next to it as <name>.restored-N when that spot is occupied,
      never overwriting;
    - rmdir: the empty directory is recreated (os.makedirs, parents
      included);
    - create_file: the file is deleted again, but only while its
      sha256 still matches the manifest -- a file modified after the
      run is kept and reported as skipped;
    - create_directory: the directory is removed again, but only while
      it is still empty -- one that gained content is kept and
      reported as skipped.

    Manifests without manifest_schema_version (version 1) are read the
    same way; their rmdir entries say restorable: false and are
    counted as not restorable instead of being undone. Both sides are
    containment-checked: the trash copy must stay under the run dir,
    every undo target under root and reachable through a symlink-free
    chain (the pre-operation gate; a file entry whose size no
    longer matches the manifest record is refused as tampered). Each
    undo is itself write-ahead
    ('restoring' before the act), and the entry ends as 'restored'
    (with restored_to) or 'restore_failed' (with error); a skipped
    undo keeps its previous status so a later restore can retry it.
    Restoring an already-restored entry is a no-op counted as
    already_done. Returns a summary dict; raises ValueError when the
    run directory has no readable manifest or the opid does not
    match."""
    run_dir = Path(run_dir)
    data = load_manifest(run_dir)
    mopid = data.get('opid')
    if opid is not None and opid != mopid:
        raise ValueError('manifest opid %r does not match the requested %r'
                         % (mopid, opid))
    if root is None:
        root = data.get('root')
        if not root:
            raise ValueError('manifest has no root; pass root= explicitly')
    root = Path(root).resolve()

    entries = data.get('entries') or []
    summary = {'declined': False, 'run_dir': str(run_dir.resolve()),
               'manifest_path': str(run_dir / MANIFEST_NAME), 'opid': mopid,
               'manifest_schema_version':
                   str(data.get('manifest_schema_version') or SCHEMA_V1),
               'root': str(root), 'restored': [], 'failed': [],
               'skipped': [], 'not_restorable': 0, 'already_done': 0}
    todo = [i for i, e in enumerate(entries)
            if isinstance(e, dict)
            and _entry_action(e) in ACTIONS
            and e.get('status') in RESTORABLE
            and e.get('restorable', True)]
    summary['already_done'] = sum(
        1 for e in entries
        if isinstance(e, dict) and e.get('status') == 'restored')
    summary['not_restorable'] = sum(
        1 for e in entries
        if isinstance(e, dict) and not e.get('restorable', True)
        and e.get('status') in DONE_STATUSES)
    if not todo:
        return summary            # nothing restorable: no prompt, no changes

    if not assume_yes:
        ask = confirm if confirm is not None else input
        try:
            answer = ask('Type YES to restore %d item(s): ' % len(todo))
        except EOFError:
            answer = ''
        if answer != 'YES':
            summary['declined'] = True
            return summary

    for i in todo:
        e = entries[i]
        action = _entry_action(e)
        orig = str(e.get('original_path') or '')
        prev_status = e.get('status')
        e['status'] = 'restoring'
        save_manifest(run_dir, data)
        try:
            kind, detail = _undo_entry(run_dir, root, e)
        except Exception as exc:
            e['status'] = 'restore_failed'
            e['error'] = '%s: %s' % (type(exc).__name__, exc)
            save_manifest(run_dir, data)
            summary['failed'].append({'original_path': orig,
                                      'action': action,
                                      'error': e['error']})
            continue
        if kind == 'skipped':
            # not done, not failed: the entry stays as it was and a
            # later restore can retry it once the disk allows
            e['status'] = prev_status
            save_manifest(run_dir, data)
            print('warning: %s (%s) not restored: %s'
                  % (orig, action, detail), file=sys.stderr)
            summary['skipped'].append({'original_path': orig,
                                       'action': action, 'reason': detail})
            continue
        dst = detail
        e['status'] = 'restored'
        e['restored_to'] = dst.relative_to(root).as_posix()
        e['restored_at'] = _iso_now()
        e.pop('error', None)
        save_manifest(run_dir, data)
        summary['restored'].append({'original_path': orig, 'action': action,
                                    'restored_to': e['restored_to']})
    return summary


# --- crash recovery ----------------------------------------------------------------

def find_incomplete(root):
    """In-flight manifest entries of the most recent interrupted run.

    Scans <root>/<TRASH_DIR_NAME>/*/manifest.json for entries whose
    status is in IN_FLIGHT ('moving'/'removing'/'creating'/'recovering')
    -- the write-ahead record of an operation that started but whose
    completion fix never landed because the process died. Only the
    latest such run (by manifest mtime, like find_interrupted) is
    reported; older interrupted runs are left for a later pass. Returns
    a list of dicts: the full entry plus 'index' (position in
    manifest['entries']), 'run_dir' and 'manifest_path'. An empty list
    means nothing needs recovery -- recover() on it is a no-op."""
    trash = Path(root) / TRASH_DIR_NAME
    best = None            # (mtime, run_dir, entries_list)
    try:
        run_dirs = sorted(trash.iterdir())
    except OSError:
        return []
    for rd in run_dirs:
        mp = rd / MANIFEST_NAME
        if not _exists(mp):
            continue
        try:
            data = json.loads(mp.read_text(encoding='utf-8'))
        except (OSError, ValueError):
            continue
        if not isinstance(data, dict):
            continue
        entries = data.get('entries')
        if not isinstance(entries, list):
            continue
        if not any(isinstance(e, dict) and e.get('status') in IN_FLIGHT
                   for e in entries):
            continue
        try:
            mtime = mp.stat().st_mtime
        except OSError:
            mtime = 0
        if best is None or mtime >= best[0]:
            best = (mtime, rd, entries)
    if best is None:
        return []
    _mtime, rd, entries = best
    out = []
    for i, e in enumerate(entries):
        if isinstance(e, dict) and e.get('status') in IN_FLIGHT:
            item = dict(e)
            item['index'] = i
            item['run_dir'] = str(rd)
            item['manifest_path'] = str(rd / MANIFEST_NAME)
            out.append(item)
    return out


def _rollback_entry(run_dir, root, entry):
    """Roll one in-flight entry back to its pre-operation state.

    Returns ('recovered', detail) or ('conflict', reason); a conflict
    never destroys anything -- the disk state is left exactly as it is
    and the reason names what blocked the rollback:

    - trash_move: copy back to the original spot when the move had
      happened (source gone, copy present); a no-op recovery when it had
      not (source still present); both present, or both gone, or an
      occupied original is a conflict;
    - rmdir: recreate the empty directory when the rmdir had happened,
      no-op when it had not;
    - create_file: delete the created file, but only while its sha256
      still matches the planned content recorded in the manifest;
    - create_directory: remove the created directory, but only while it
      is still empty.

    Every destination goes through _undo_target (shape, containment,
      symlink-free chain, never inside the trash folder)."""
    action = _entry_action(entry)
    orig = str(entry.get('original_path') or '')
    if action == ACTION_TRASH_MOVE:
        trash_rel = str(entry.get('trash_path') or '')
        if not _rel_shape_ok(trash_rel):
            return 'conflict', 'trash path has an unsafe shape'
        src = run_dir / trash_rel
        if not _is_under(src, run_dir):
            return 'conflict', 'trash copy outside the run dir: %s' % trash_rel
        src_ok = _exists(src)
        try:
            dst = _undo_target(root, orig)
        except ValueError as exc:
            return 'conflict', str(exc)
        if src_ok and _exists(dst):
            return 'conflict', ('both the original path and the trash copy '
                                'exist; both left in place')
        if not src_ok and not _exists(dst):
            return 'conflict', ('trash copy missing and the original gone; '
                                'nothing left to roll back')
        if _exists(dst):
            # src gone, original present: the move never started
            return 'recovered', 'move never started; source still in place'
        # the manifest-integrity size check restore() applies
        if entry.get('type') == 'file':
            recorded = entry.get('size')
            try:
                actual = os.stat(str(src)).st_size
            except OSError:
                actual = None
            if (actual is not None and isinstance(recorded, int)
                    and recorded > 0 and actual != recorded):
                return 'conflict', (
                    'trash copy size %d does not match the manifest record '
                    '%d; left in place' % (actual, recorded))
        dst.parent.mkdir(parents=True, exist_ok=True)
        if _exists(dst):
            return 'conflict', 'restore destination appeared: %s' % dst
        shutil.move(str(src), str(dst))
        return 'recovered', 'moved back to %s' % dst
    if action == ACTION_RMDIR:
        try:
            dst = _undo_target(root, orig)
        except ValueError as exc:
            return 'conflict', str(exc)
        if _exists(dst):
            return 'recovered', 'directory still present; rmdir never started'
        os.makedirs(str(dst), exist_ok=True)
        return 'recovered', 'empty directory recreated at %s' % dst
    if action == ACTION_CREATE_FILE:
        try:
            dst = _undo_target(root, orig)
        except ValueError as exc:
            return 'conflict', str(exc)
        if not _exists(dst):
            return 'recovered', 'file was never created'
        sha = entry.get('sha256')
        if not sha:
            return 'conflict', 'no sha256 recorded; file left in place'
        if _sha256_file(dst) != sha:
            return 'conflict', ('file differs from the planned content; '
                                'left in place')
        os.remove(str(dst))
        return 'recovered', 'created file deleted at %s' % dst
    if action == ACTION_CREATE_DIRECTORY:
        try:
            dst = _undo_target(root, orig)
        except ValueError as exc:
            return 'conflict', str(exc)
        if not _exists(dst):
            return 'recovered', 'directory was never created'
        if any(dst.iterdir()):
            return 'conflict', 'directory gained content; left in place'
        os.rmdir(str(dst))
        return 'recovered', 'created directory removed at %s' % dst
    return 'conflict', 'unknown action: %r' % (entry.get('action'),)


def recover(root, auto=False, confirm=None):
    """Roll back the in-flight entries of the latest interrupted run.

    The write-ahead manifest records an operation before it runs and
    fixes the entry afterwards; a process that died in between leaves
    the entry in flight ('moving'/'removing'/'creating'). recover()
    returns every such entry to its pre-operation state:

    - trash_move in flight: the trash copy goes back to the original
      spot; when a new file already occupies that spot both are kept and
      the entry is reported as a conflict;
    - create_file in flight: the created file is deleted again, but only
      after the sha256 re-check against the manifest (a file modified
      since, or a partial write, stays and is reported);
    - create_directory / rmdir in flight: the created directory is
      removed while still empty / the removed empty directory is
      recreated; content that appeared in the meantime is kept.

    auto=False (default) prints the rollback plan and asks for the word
    YES (confirm=callable replaces input for tests); auto=True executes
    without asking. The whole recovery runs under the trash lock and
    each entry is itself write-ahead ('recovering' before the rollback,
    so a recovery that crashes is detectable by the next find_incomplete
    and retryable). Recovering a workspace with nothing in flight is a
    no-op; a second recover after a completed one finds no in-flight
    entries either. Entries end as 'recovered' or 'recovery_conflict'
    (terminal for recovery; restore() ignores both).

    Returns {'run_dir': str|None, 'declined': bool, 'incomplete': int,
    'recovered': [{original_path, action, detail}], 'conflicts':
    [{original_path, action, reason}], 'failed': [{original_path,
    action, error}]}. 'failed' holds unexpected errors (the entry keeps
    its in-flight status so a later recover retries it); conflicts are
    deliberate non-actions, not failures. Raises LockBusy when another
    run holds the lock."""
    root = Path(root).resolve()
    report = {'run_dir': None, 'declined': False, 'incomplete': 0,
              'recovered': [], 'conflicts': [], 'failed': []}
    if not find_incomplete(root):
        return report
    lock = TrashLock(root)
    lock.acquire()
    try:
        incomplete = find_incomplete(root)   # re-read under the lock
        report['incomplete'] = len(incomplete)
        if not incomplete:
            return report
        run_dir = Path(incomplete[0]['run_dir'])
        report['run_dir'] = str(run_dir)
        data = load_manifest(run_dir)
        entries = data.get('entries') or []

        print('crash recovery: %d unfinished operation(s) in %s'
              % (len(incomplete), run_dir))
        for item in incomplete:
            print('  [%s] %s (status: %s) -> roll back'
                  % (item.get('action'), item.get('original_path'),
                     item.get('status')))
        if not auto:
            ask = confirm if confirm is not None else input
            try:
                answer = ask('Type YES to roll back %d operation(s): '
                             % len(incomplete))
            except EOFError:
                answer = ''
            if answer != 'YES':
                report['declined'] = True
                print('declined; nothing recovered')
                return report

        for item in incomplete:
            e = entries[item['index']]
            action = _entry_action(e)
            orig = str(e.get('original_path') or '')
            prev_status = e.get('status')
            e['status'] = 'recovering'
            save_manifest(run_dir, data)
            try:
                kind, detail = _rollback_entry(run_dir, root, e)
            except Exception as exc:
                # unexpected: keep the entry in flight so a later
                # recover can retry, and report it
                e['status'] = prev_status
                e['recover_error'] = '%s: %s' % (type(exc).__name__, exc)
                save_manifest(run_dir, data)
                report['failed'].append({'original_path': orig,
                                         'action': action,
                                         'error': e['recover_error']})
                print('%s: recovery of %s failed, continuing: %s'
                      % ('trashops', orig, e['recover_error']),
                      file=sys.stderr)
                continue
            if kind == 'conflict':
                e['status'] = STATUS_RECOVERY_CONFLICT
                e['recovery_note'] = detail
                save_manifest(run_dir, data)
                print('warning: %s (%s) left as-is: %s'
                      % (orig, action, detail), file=sys.stderr)
                report['conflicts'].append({'original_path': orig,
                                            'action': action,
                                            'reason': detail})
                continue
            e['status'] = STATUS_RECOVERED
            e['recovered_at'] = _iso_now()
            e['recovery_note'] = detail
            e.pop('recover_error', None)
            save_manifest(run_dir, data)
            report['recovered'].append({'original_path': orig,
                                        'action': action, 'detail': detail})
        return report
    finally:
        lock.release()
