"""Fact-enrichment module for agents-doctor.

Collects the extra facts the gate engine needs on top of the scanner report:
config parse integrity, heavy directories outside any git repo, junk
classification refined with git/reference signals, harness activity states
and SKILL.md frontmatter health.

Security posture (same as audit_scan.py):
- read-only: nothing under the audited tree is ever executed or written;
- symlinked directories are never followed and never measured;
- git runs read-only with GIT_OPTIONAL_LOCKS=0, one `ls-files` listing
  per repository (cached);
- PyYAML is optional. Frontmatter values are untrusted text: only
  yaml.safe_load is ever called (never yaml.load, never eval); without
  PyYAML a flat `key: value` fallback parser is used and anything it
  cannot parse is reported as unknown (frontmatter_ok None), never as ok.

Constants BUILD_DIRS, the junk-dir name rules and the 30/90-day freshness
thresholds are local copies of the scanner's, kept identical on purpose:
this module must stay importable standalone.
"""

import json
import os
import re
import subprocess
import time
from pathlib import Path

try:
    import tomllib  # stdlib since Python 3.11
except ImportError:  # pragma: no cover - depends on interpreter version
    tomllib = None

try:
    import yaml  # optional dependency
except ImportError:  # pragma: no cover - PyYAML not installed
    yaml = None

# --- local copies of the scanner's constants (keep in sync) --------------------

BUILD_DIRS = {'node_modules', '__pycache__', '.venv', 'venv', 'dist',
              'build', 'target', '.cache', '.idea', '.pytest_cache'}

JUNK_DIR_RULES = [
    (re.compile(r'^backup', re.I), 'backup dir'),
    (re.compile(r'стар', re.I), '"old" dir'),
    (re.compile(r'^temp', re.I), 'temp dir'),
]

HARNESS_FRESH_DAYS = 30           # newer: harness counts as active
HARNESS_STALE_DAYS = 90           # older: harness counts as abandoned
HEAVY_MIN_BYTES = 1024 * 1024     # dirs above this size are "heavy"

CONFIG_NAMES = ('.mcp.json', '.zcode/config.json', '.claude/settings.json',
                'settings.local.json')

HARNESS_DIRS = (('zcode', '.zcode'), ('claude', '.claude'), ('codex', '.codex'))

HARNESS_ENTRY_CAP = 2000          # files stat'ed per harness before capping
HARNESS_TIME_CAP = 2.0            # seconds per harness before capping

DEAD_REF_RX = re.compile(r'\b(?:scripts|assets|references|knowledge)/[\w./-]+')
REQUIRED_FRONTMATTER_FIELDS = ('name', 'description')

_JUNK_RULES = [(rx, why) for rx, why in JUNK_DIR_RULES]


def _dir_junk_reason(name):
    for rx, why in _JUNK_RULES:
        if rx.search(name):
            return why
    return None


def _short(text, limit=120):
    return ' '.join(str(text).split())[:limit]


def _git_env():
    # GIT_OPTIONAL_LOCKS=0 keeps git from refreshing the index: read-only
    return dict(os.environ, GIT_OPTIONAL_LOCKS='0')


def _display_path(path, root):
    try:
        return str(Path(path).relative_to(root))
    except ValueError:
        return str(path)


# --- 1) config parse integrity --------------------------------------------------

def _json_dup_keys(raw):
    """Duplicate key names inside JSON objects, via object_pairs_hook."""
    dups = set()

    def hook(pairs):
        seen = set()
        for key, _value in pairs:
            if key in seen:
                dups.add(key)
            seen.add(key)
        return dict(pairs)

    try:
        json.loads(raw, object_pairs_hook=hook)
    except ValueError:
        return []  # parse error is reported separately
    return sorted(dups)


def _check_config(path, root):
    path = Path(path)
    fmt = 'toml' if path.suffix == '.toml' else 'json'
    entry = {'path': _display_path(path, root), 'format': fmt,
             'ok': None, 'error': None, 'dup_keys': []}
    try:
        raw = path.read_text(encoding='utf-8', errors='replace')
    except OSError as exc:
        entry['ok'] = False
        entry['error'] = _short(exc)
        return entry

    if fmt == 'toml':
        if tomllib is None:
            entry['ok'] = None
            entry['error'] = 'toml parser unavailable'
            return entry
        try:
            tomllib.loads(raw)
        except Exception as exc:  # tomllib raises TOMLDecodeError (ValueError)
            entry['ok'] = False
            entry['error'] = _short(exc)
        else:
            entry['ok'] = True
        return entry

    # json
    try:
        json.loads(raw)
    except ValueError as exc:
        entry['ok'] = False
        entry['error'] = _short(exc)
    else:
        entry['ok'] = True
        entry['dup_keys'] = _json_dup_keys(raw)
    return entry


def config_integrity(root, repo_dirs):
    """Parse-check harness/MCP config files at root and repo tops.

    Checks CONFIG_NAMES at root and at the top of every repo_dir; missing
    files are skipped. Returns a list of entries:
    {path, format: 'json'|'toml', ok: bool|None, error: str|None,
     dup_keys: [str]}. ok None means the check could not run (no toml
    parser on this interpreter).
    """
    root = Path(root)
    seen = set()
    entries = []
    for base in [root] + [Path(d) for d in repo_dirs or []]:
        for name in CONFIG_NAMES:
            candidate = base / name
            key = str(candidate)
            if key in seen:
                continue
            seen.add(key)
            if not candidate.is_file() or candidate.is_symlink():
                continue
            entries.append(_check_config(candidate, root))
    entries.sort(key=lambda e: e['path'])
    return entries


# --- 2) heavy directories outside any git repo ----------------------------------

def _exists(p):
    """exists() that treats permission errors as absent (pathlib raises)."""
    try:
        return p.exists()
    except OSError:
        return False


def _tree_size(p):
    """Recursive size of a directory; symlinks are never followed."""
    total = 0
    for dp, _dns, fns in os.walk(p):  # followlinks=False by default
        for fn in fns:
            f = Path(dp) / fn
            if f.is_symlink():
                continue
            try:
                total += f.stat().st_size
            except OSError:
                pass
    return total


def heavy_outside_git(root):
    """Dirs heavier than 1 MB that live outside any git repository.

    Walks from root down to depth 2, skipping .git, BUILD_DIRS and
    junk-named dirs. A dir is "outside git" when neither it nor any
    ancestor up to root has .git; if root itself is a repo, nothing is
    reported. Only the outermost qualifying dir is reported (no
    double-counting of nested heavy dirs). Symlinked dirs are skipped
    entirely.
    """
    root = Path(root)
    found = []
    if _exists(root / '.git'):
        return found

    level = [root]
    for depth in (1, 2):
        nxt = []
        for cur in level:
            try:
                children = sorted(os.scandir(cur), key=lambda e: e.name)
            except OSError:
                continue
            for ent in children:
                try:
                    if ent.is_symlink() or not ent.is_dir():
                        continue
                except OSError:
                    continue
                if (ent.name == '.git' or ent.name in BUILD_DIRS
                        or _dir_junk_reason(ent.name)):
                    continue
                p = Path(ent.path)
                if _exists(p / '.git'):
                    continue  # repo root: the whole subtree is inside git
                size = _tree_size(p)
                if size > HEAVY_MIN_BYTES:
                    found.append({'path': str(p.relative_to(root)),
                                  'size_bytes': size,
                                  'depth': depth})
                    # reported: do not descend, nested dirs stay unreported
                elif depth == 1:
                    nxt.append(p)
        level = nxt
    found.sort(key=lambda e: e['path'])
    return found


# --- 3) junk classification with git/reference signals ---------------------------

def _nearest_repo(p, root):
    """Nearest ancestor of p (p included, root included) holding .git."""
    cur = Path(p)
    root = Path(root)
    while True:
        if _exists(cur / '.git'):
            return cur
        if cur == root or cur.parent == cur:
            return None
        cur = cur.parent


def _repo_tracked_files(repo):
    """Set of tracked paths (posix, relative to repo) or None on failure.

    One `git ls-files -z` call per repo; -z output needs no unquoting.
    """
    try:
        r = subprocess.run(['git', '-C', str(repo), 'ls-files', '-z'],
                           capture_output=True, env=_git_env(), timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if r.returncode != 0:
        return None
    text = r.stdout.decode('utf-8', errors='replace')
    return {part for part in text.split('\0') if part}


def classify_junk(root, junk_candidates, reference_texts):
    """Refine scanner junk candidates into classification + confidence.

    Signals per candidate ({'path': rel, 'reason': str, 'size_bytes': int}):
    - tracked: path is tracked in the nearest containing git repo (one
      cached `git ls-files` listing per repo; no repo -> False; git
      failure or nonexistent path -> None);
    - age_days: mtime age in days, None when stat fails;
    - referenced: basename or full rel path appears (case-insensitive)
      in one of reference_texts.

    Classification: confirmed_unused (untracked, older than 30 days or
    age unknown, unreferenced, size known; confidence 0.9 when older
    than 90 days, else 0.7), potentially_unused (tracked, referenced or
    fresh; 0.5), unknown (nonexistent path, undeterminable tracked
    status or unknown size; 0.3).
    """
    root = Path(root)
    refs = [str(t).lower() for t in reference_texts or []]
    listings = {}
    now = time.time()
    results = []

    for cand in junk_candidates or []:
        rel = str(cand.get('path', ''))
        p = root / rel
        size = cand.get('size_bytes')
        exists = _exists(p)

        tracked = None
        if exists:
            repo = _nearest_repo(p, root)
            if repo is None:
                tracked = False
            else:
                key = str(repo)
                if key not in listings:
                    listings[key] = _repo_tracked_files(repo)
                listing = listings[key]
                if listing is not None:
                    posix = p.relative_to(repo).as_posix()
                    if posix in listing:
                        tracked = True
                    elif p.is_dir():
                        prefix = posix + '/'
                        tracked = any(e.startswith(prefix) for e in listing)
                    else:
                        tracked = False

        try:
            age_days = max(0, int((now - p.stat().st_mtime) // 86400))
        except OSError:
            age_days = None

        base = p.name.lower()
        rel_l = rel.replace('\\', '/').lower()
        referenced = any((base and base in t) or (rel_l and rel_l in t)
                         for t in refs)

        size_known = isinstance(size, int) and size >= 0
        if not exists or tracked is None or not size_known:
            classification, confidence = 'unknown', 0.3
        elif (not tracked) and (age_days is None or age_days > HARNESS_FRESH_DAYS) \
                and not referenced:
            classification = 'confirmed_unused'
            confidence = 0.9 if (age_days is not None
                                 and age_days > HARNESS_STALE_DAYS) else 0.7
        else:
            classification, confidence = 'potentially_unused', 0.5

        results.append({
            'path': rel,
            'reason': cand.get('reason'),
            'size_bytes': size,
            'tracked': tracked,
            'age_days': age_days,
            'referenced': referenced,
            'classification': classification,
            'confidence': confidence,
        })
    return results


# --- 4) harness activity states ---------------------------------------------------

def _newest_mtime(start, entry_cap, time_cap):
    """Newest file mtime under start; (newest, files_checked, capped).

    Never follows symlinked dirs, skips build junk names and .git.
    """
    newest = None
    checked = 0
    capped = False
    deadline = time.monotonic() + time_cap
    for dp, dns, fns in os.walk(start):
        dns[:] = [d for d in dns
                  if d not in BUILD_DIRS and d != '.git'
                  and not (Path(dp) / d).is_symlink()]
        for fn in fns:
            if checked >= entry_cap or time.monotonic() > deadline:
                capped = True
                break
            f = Path(dp) / fn
            if f.is_symlink():
                continue
            try:
                mtime = f.stat().st_mtime
            except OSError:
                continue
            checked += 1
            if newest is None or mtime > newest:
                newest = mtime
        if capped:
            break
    return newest, checked, capped


def harness_states(home):
    """Activity state per harness dir (.zcode/.claude/.codex) under home.

    State comes from the newest recursive mtime (files only), capped at
    2000 entries or 2 seconds per harness. Fresh 30 / stale 90 days, as
    in the scanner. A dir that exists but yields zero readable entries
    is 'unknown' — no data must not look like abandonment. Symlinked
    harness dirs are skipped.
    """
    home = Path(home)
    out = {}
    for tool, dirname in HARNESS_DIRS:
        d = home / dirname
        if d.is_symlink() or not d.is_dir():
            continue
        newest, checked, capped = _newest_mtime(d, HARNESS_ENTRY_CAP,
                                                HARNESS_TIME_CAP)
        if newest is None:
            out[tool] = {'state': 'unknown',
                         'last_activity_days_ago': None,
                         'evidence_source': 'recursive mtime scan',
                         'confidence': 0.3,
                         'reason': f'{dirname} exists but no readable '
                                   f'files were found'}
            continue
        days = max(0, int((time.time() - newest) // 86400))
        if days <= HARNESS_FRESH_DAYS:
            state = 'active'
        elif days > HARNESS_STALE_DAYS:
            state = 'abandoned'
        else:
            state = 'occasional'
        if capped:
            reason = (f'scan capped after {checked} files; newest file '
                      f'{days} days old')
        else:
            reason = f'newest file {days} days old ({checked} files checked)'
        entry = {'state': state,
                 'last_activity_days_ago': days,
                 'evidence_source': ('recursive mtime scan (capped)'
                                     if capped else 'recursive mtime scan'),
                 'confidence': 0.5 if capped else 0.9,
                 'reason': reason}
        if capped:
            entry['capped'] = True
        out[tool] = entry
    return out


# --- 5) SKILL.md frontmatter health ------------------------------------------------

def _split_frontmatter(text):
    """(frontmatter_block, found) between the leading --- fences."""
    lines = text.splitlines()
    if not lines or lines[0].strip() != '---':
        return '', False
    for i in range(1, len(lines)):
        if lines[i].strip() == '---':
            return '\n'.join(lines[1:i]), True
    return '', False  # no closing fence: no usable frontmatter


def _fallback_frontmatter(fm_text):
    """Flat `key: value` parser used when PyYAML is unavailable.

    Returns (ok, pairs): ok True when every non-blank line was a flat
    single-line pair, None when the block contains structure the parser
    cannot handle (multiline values, block scalars, unclosed quotes),
    False never (the parser cannot prove the block broken, only limited).
    """
    pairs = {}
    ok = True
    for line in fm_text.splitlines():
        if not line.strip():
            continue
        m = re.match(r'^([A-Za-z0-9_-]+):\s*(.*)$', line)
        if not m:
            ok = None  # indented/continuation line: beyond flat pairs
            continue
        key, val = m.group(1), m.group(2).strip()
        if not val:
            pairs[key] = ''
        elif val[0] in '"\'':
            if len(val) < 2 or not val.endswith(val[0]):
                ok = None  # unclosed quote
                continue
            pairs[key] = val[1:-1]
        elif val in ('>', '>-', '|', '|-'):
            ok = None  # block scalar: value lives on the next lines
        else:
            pairs[key] = val
    return ok, pairs


def _fallback_syntax_error(fm_text, line_offset=0):
    """Flat-pair lines the fallback parser can prove invalid YAML.

    A plain (unquoted) scalar may not hold ': ' -- YAML reads it as a
    second mapping and rejects the document ('description: When asked:
    prepare a report'). Returns {'line', 'column', 'problem'} for the
    first such line (1-based in the source file: line_offset is the
    number of file lines before the block, the opening fence), else
    None. Nothing else is proven: other malformed blocks stay 'unknown'
    under the fallback.
    """
    for i, line in enumerate(fm_text.splitlines(), 1):
        m = re.match(r'^([A-Za-z0-9_-]+):\s*(.*)$', line)
        if not m:
            continue
        val = m.group(2)
        if not val or val[0] in '"\'':
            continue   # quoted or empty: nothing to prove here
        bad = val.find(': ')
        if bad == -1 and val.endswith(':'):
            bad = len(val) - 1
        if bad == -1:
            continue
        return {'line': i + line_offset, 'column': m.start(2) + bad + 1,
                'problem': 'unquoted value contains ": " (quote the value)'}
    return None


def _yaml_error_position(exc, line_offset=0):
    """Where a YAML error sits in the source file: {'line', 'column',
    'problem'} 1-based, or None when the parser gives no mark.

    Only the position and the library's own problem text are kept. The
    exception message also quotes the offending source line, and that is
    user content: it must not travel into reports or model context.
    """
    mark = getattr(exc, 'problem_mark', None) or getattr(exc, 'context_mark', None)
    if mark is None or mark.line is None:
        return None
    problem = getattr(exc, 'problem', None) or 'invalid YAML'
    return {'line': mark.line + 1 + line_offset, 'column': mark.column + 1,
            'problem': str(problem)[:120]}


def _missing_fields(fields):
    missing = []
    for name in REQUIRED_FRONTMATTER_FIELDS:
        value = fields.get(name)
        if value is None or (isinstance(value, str) and not value.strip()):
            missing.append(name)
        elif not isinstance(value, str):
            missing.append(name)  # structured value where a string belongs
    return missing


def _dead_refs(text, skill_dir):
    """Relative file references in text that do not exist (cap 5)."""
    missing = []
    seen = set()
    for m in DEAD_REF_RX.finditer(text):
        ref = m.group(0).rstrip('.')
        if not ref or ref in seen:
            continue
        seen.add(ref)
        if not _exists(skill_dir / ref):
            missing.append(ref)
            if len(missing) >= 5:
                break
    return missing


def skills_frontmatter(entries):
    """Frontmatter health for scanner skill entries (each has 'path').

    Returns {skill_name_or_path: {frontmatter_ok, missing_fields,
    fields_checked, parse_error, dead_refs, parser, path}}.
    frontmatter_ok is parse-level: True (parsed), False (structurally
    absent, or rejected as invalid YAML), None (fallback parser cannot
    judge the structure -- unknown, never silently ok).

    missing_fields lists the required fields that are absent. It is
    filled only after a successful parse (fields_checked is True): when
    the block does not parse the fields were never evaluated, so the
    record carries parse_error = {'line', 'column', 'problem'} in
    SKILL.md instead of a list of "missing" fields that are in fact
    present.

    dead_refs lists up to 5 referenced relative files
    (scripts/..., assets/..., references/..., knowledge/...) missing
    under the skill dir. yaml.safe_load is the only parser ever run on
    the raw text; nothing is evaluated.
    """
    out = {}
    for ent in entries or []:
        path = Path(str(ent.get('path', '')))
        skill_dir = path.parent
        rec = {'frontmatter_ok': None,
               'missing_fields': [],
               'fields_checked': False,
               'parse_error': None,
               'dead_refs': [], 'parser': 'fallback',
               'path': str(path)}
        try:
            text = path.read_text(encoding='utf-8', errors='replace')
        except OSError:
            out[str(ent.get('path', ''))] = rec
            continue

        fm_text, has_fm = _split_frontmatter(text)
        key = str(ent.get('path', ''))
        name = None

        if not has_fm:
            rec['frontmatter_ok'] = False  # definitely no frontmatter block
            # and so the required fields are factually absent
            rec['fields_checked'] = True
            rec['missing_fields'] = list(REQUIRED_FRONTMATTER_FIELDS)
        elif yaml is not None:
            rec['parser'] = 'yaml'
            try:
                data = yaml.safe_load(fm_text)
            except yaml.YAMLError as exc:
                # line_offset 1 = the opening '---' fence before the block
                rec['frontmatter_ok'] = False
                rec['parse_error'] = _yaml_error_position(exc, line_offset=1)
            else:
                rec['fields_checked'] = True
                if isinstance(data, dict):
                    rec['frontmatter_ok'] = True
                    rec['missing_fields'] = _missing_fields(data)
                    candidate = str(data.get('name') or '').strip()
                    if candidate:
                        name = candidate
                else:  # valid yaml but not a mapping
                    rec['frontmatter_ok'] = False
                    rec['missing_fields'] = list(REQUIRED_FRONTMATTER_FIELDS)
        else:
            ok, pairs = _fallback_frontmatter(fm_text)
            rec['parser'] = 'fallback'
            err = _fallback_syntax_error(fm_text, line_offset=1)
            if err is not None:
                # proven invalid even without a real YAML parser
                rec['frontmatter_ok'] = False
                rec['parse_error'] = err
            elif ok:
                rec['frontmatter_ok'] = True
                rec['fields_checked'] = True
                rec['missing_fields'] = _missing_fields(pairs)
                candidate = str(pairs.get('name') or '').strip()
                if candidate:
                    name = candidate
            else:
                rec['frontmatter_ok'] = ok  # None: unknown, not ok

        rec['dead_refs'] = _dead_refs(text, skill_dir)
        out[name or key] = rec
    return out
