#!/usr/bin/env python3
"""agents-doctor: deterministic agent workspace scanner.

Called from the skill:
    python scripts/audit_scan.py <root> [--home <home>] [--deep] --out scan.json

Read-only: reads files and git metadata, never changes or deletes anything.
home is scanned selectively (harnesses, global instructions, memory, skills);
the full walk covers only the workspace root.
Output: JSON to --out plus a short summary to stdout.
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

# secret detection and redaction live in one module: raw values never leave it
sys.path.insert(0, str(Path(__file__).resolve().parent))
import secret_scanner as secscan  # noqa: E402
import enrich  # noqa: E402
import gates as gates_engine  # noqa: E402
import sanitize_url  # noqa: E402
import history_scan  # noqa: E402
import content_quality  # noqa: E402
from fingerprint import FingerprintKeyError  # noqa: E402

def _exists(p):
    """exists() that treats permission errors as absent (pathlib raises)."""
    try:
        return p.exists()
    except OSError:
        return False

# --- thresholds and heuristics from the audit protocol ------------------------
PROJECT_BENCH = 16 * 1024        # project instruction file: up to ~16 KB is achievable
MEMORY_LIMIT = 24985             # memory index load limit (24.4 KB)
MEMORY_LINE_LIMIT = 200          # memory loads up to 200 lines or 25 KB, whichever comes first
CHAIN_BUDGET = 32768             # Codex budget for the root + nested AGENTS.md chain
SKILL_DESC_LIMIT = 1024          # Z Code skill description limit
RULES_VERSION = '3.1.0'          # rule set version, goes into the report
HARNESS_STALE_DAYS = 90          # older: harness counts as abandoned
HARNESS_FRESH_DAYS = 30          # newer: active

HARNESS = {
    'zcode':  {'dir': '.zcode',  'markers': ['cli/history.jsonl', 'history.jsonl', 'cli/artifacts'],
               'reads': ['AGENTS.md']},
    'claude': {'dir': '.claude', 'markers': ['projects', 'history.jsonl'],
               'reads': ['CLAUDE.md', 'AGENTS.md']},
    'codex':  {'dir': '.codex',  'markers': ['config.toml', 'sessions', 'history.jsonl'],
               'reads': ['AGENTS.md']},
}
GENERIC_MARKERS = [
    'drop this file into your project', 'next-move-theory-rules',
    'структура репозитория', 'как устроен этот', 'обзор репозитория', '## overview',
    'repository structure', 'repository overview',
]

BUILD_DIRS = {'node_modules', '__pycache__', '.venv', 'venv', 'dist',
              'build', 'target', '.cache', '.idea', '.pytest_cache'}
BIG_FILE_BYTES = 5 * 1024 * 1024
# files of this size and more are not read for keys: bundles and minified
# libraries live there, and their keyword literals are examples
SECRET_FILE_MAX_BYTES = 1024 * 1024
DUP_MIN_BYTES = 1024
DUP_MAX_BYTES = 50 * 1024 * 1024
TEXT_EXTS = {'.json', '.md', '.yml', '.yaml', '.toml', '.env', '.txt',
             '.py', '.js', '.ts', '.cfg', '.ini', '.sh'}
SECRET_FILENAMES = {'.mcp.json', '.env', 'settings.json'}
# key-like names are scanned for secrets even without a text extension
NAME_SECRET_RX = re.compile(r'(id_rsa|id_dsa|id_ecdsa|id_ed25519|\.pem$|\.key$|^id_)', re.I)

JUNK_FILE_RULES = [
    (re.compile(r'^temp', re.I), 'temp file'),
    (re.compile(r'^~\$', re.I), 'office lock file'),
    (re.compile(r'^untitled', re.I), 'untitled'),
    (re.compile(r'^img_', re.I), 'screenshot or photo'),
    (re.compile(r'скриншот', re.I), 'screenshot'),
    (re.compile(r'screenshot', re.I), 'screenshot'),
    (re.compile(r'^новая папка', re.I), 'new folder'),
    (re.compile(r'^new folder', re.I), 'new folder'),
    (re.compile(r'финал', re.I), '"final" version marker'),
    (re.compile(r'\bfinal\b', re.I), '"final" version marker'),
    (re.compile(r'версия', re.I), 'version marker'),
    (re.compile(r'\bversion\b', re.I), 'version marker'),
    (re.compile(r'копия', re.I), 'copy'),
    (re.compile(r'\bcopy\b', re.I), 'copy'),
    (re.compile(r'^backup', re.I), 'backup'),
    (re.compile(r'стар', re.I), '"old" leftover'),
    (re.compile(r'\bold\b', re.I), '"old" leftover'),
    (re.compile(r'времен', re.I), 'temp file'),
    (re.compile(r'^scratch', re.I), 'scratch/draft'),
    (re.compile(r'\bdraft\b', re.I), 'scratch/draft'),
    (re.compile(r'^debug', re.I), 'debug output'),
    (re.compile(r'\.bak$', re.I), '*.bak'),
    (re.compile(r'\.log$', re.I), 'log file'),
]
JUNK_DIR_RULES = [
    (re.compile(r'^backup', re.I), 'backup dir'),
    (re.compile(r'стар', re.I), '"old" dir'),
    (re.compile(r'^temp', re.I), 'temp dir'),
]


# --- shared helpers -----------------------------------------------------------

def run_git(p, *args):
    # GIT_OPTIONAL_LOCKS=0 keeps git from refreshing the index: read-only
    env = dict(os.environ, GIT_OPTIONAL_LOCKS='0')
    r = subprocess.run(['git', '-C', str(p), *args], capture_output=True,
                       text=True, encoding='utf-8', errors='replace', env=env)
    return r.returncode, r.stdout


def file_junk_reason(name):
    for rx, why in JUNK_FILE_RULES:
        if rx.search(name):
            return why
    return None


def dir_junk_reason(name):
    for rx, why in JUNK_DIR_RULES:
        if rx.search(name):
            return why
    return None


def subtree(p):
    size = count = 0
    for dp, _dns, fns in os.walk(p):
        for fn in fns:
            f = Path(dp) / fn
            if f.is_symlink():
                continue
            try:
                size += f.stat().st_size
                count += 1
            except OSError:
                pass
    return size, count


def classify_remote(url):
    host = re.sub(r'^[^@]*@', '', url)
    m = re.search(r'(?:https?://)?([^/]+)', host)
    host = m.group(1) if m else url
    if re.search(r'github\.com|gitlab\.com|bitbucket\.org', host, re.I):
        return 'external hosting'
    return 'self-hosted'


# --- block D: repositories ------------------------------------------------------

def git_info(p):
    if not _exists(p / '.git'):
        return None
    info = {'remote': None, 'last_commit': None, 'dirty': [], 'untracked': [],
            'credentials_in_remote': False}
    rc, out = run_git(p, 'remote', 'get-url', 'origin')
    if rc == 0 and out.strip():
        raw = out.strip()
        # only the sanitized URL may leave this function; credential
        # detection runs on the raw value before it is dropped
        info['remote'] = sanitize_url.sanitize_remote_url(raw)
        info['credentials_in_remote'] = sanitize_url.has_credentials(raw)
    rc, out = run_git(p, 'log', '-1', '--format=%cI')
    if rc == 0 and out.strip():
        info['last_commit'] = out.strip()
    _rc, out = run_git(p, 'status', '--porcelain')
    for line in out.splitlines():
        if not line.strip():
            continue
        target = info['untracked'] if line[:2].strip() == '??' else info['dirty']
        target.append(line[3:].strip().strip('"'))
    return info


def nested_repos(p):
    found = []
    for dp, dns, _fns in os.walk(p):
        dns[:] = [d for d in dns if d != '.git' and d not in BUILD_DIRS]
        if dp != str(p) and _exists(Path(dp) / '.git'):
            found.append(str(Path(dp).relative_to(p)))
            dns[:] = []
        if len(found) >= 10:
            break
    return found


def _norm_rel(rel):
    return str(rel).replace('\\', '/')


# files that together mark the source tree of this plugin
OWN_SOURCE_MARKERS = ('audit_scan.py', 'secret_rules.py')


def _own_source_dir(directory, root, cache):
    """True when the directory lies inside the source tree of this
    plugin: a folder holding both audit_scan.py and secret_rules.py, up
    to three levels up. Both files are needed, so that one file of the
    user's own named like the scanner does not turn the key check off
    for its folder. The plugin's test corpus of fake keys and its
    masking code are not the user's data, and a workspace that keeps a
    copy of the plugin must not start every audit with forty "keys" of
    its own. The worktree scan counts what it leaves out
    (stats.own_source_skipped)."""
    key = str(directory)
    if key in cache:
        return cache[key]
    cur, found = Path(directory), False
    for _ in range(4):
        if all(_exists(cur / name) for name in OWN_SOURCE_MARKERS):
            found = True
            break
        if cur == root or cur.parent == cur:
            break
        cur = cur.parent
    cache[key] = found
    return found


def _chunks(items, size=40):
    items = list(items)
    for i in range(0, len(items), size):
        yield items[i:i + size]


def _ignored_files(repo, rels):
    """Paths (relative to repo) that .gitignore keeps out of git.
    Unknown when git fails: then nothing is ignored, which is the safe
    side for every caller."""
    ignored = set()
    # git quotes a path given with backslashes; forward slashes come
    # back as they went in
    for chunk in _chunks(_norm_rel(p) for p in rels):
        # exit code 1 means "none of them is ignored"
        rc, out = run_git(repo, '-c', 'core.quotepath=false',
                          'check-ignore', '--', *chunk)
        if rc in (0, 1):
            ignored.update(_norm_rel(line.strip()) for line in out.splitlines()
                           if line.strip())
    return ignored


def git_file_states(root, git_roots, rels):
    """Where files sit in the nearest repository around them:
    'tracked' (in the index, staged included), 'ignored' (kept out by
    .gitignore) or 'untracked' (in the folder, not added yet). A file
    outside every repository, and everything when git fails, gets no
    state. Keys are the normalized paths given in rels."""
    roots = sorted({_norm_rel(g) for g in git_roots},
                   key=lambda g: (-g.count('/'), g))
    owners = {}
    for rel in rels:
        n = _norm_rel(rel)
        for g in roots:
            if g == '.' or n == g or n.startswith(g + '/'):
                owners.setdefault(g, []).append(n if g == '.' else n[len(g) + 1:])
                break
    states = {}
    for g, subs in owners.items():
        repo = root if g == '.' else root / g
        tracked = set()
        failed = False
        for chunk in _chunks(subs):
            rc, out = run_git(repo, '-c', 'core.quotepath=false',
                              'ls-files', '--', *chunk)
            if rc != 0:
                failed = True
                break
            tracked.update(_norm_rel(line.strip()) for line in out.splitlines()
                           if line.strip())
        if failed:
            continue
        ignored = _ignored_files(repo, [s for s in subs if s not in tracked])
        prefix = '' if g == '.' else g + '/'
        for s in subs:
            states[prefix + s] = ('tracked' if s in tracked else
                                  'ignored' if s in ignored else 'untracked')
    return states


def git_top_status(p):
    """Top-level entries that git reports as a whole: 'untracked' (no
    tracked file inside) and 'ignored' (kept out by .gitignore). An
    entry in neither list holds tracked files. None when git fails."""
    rc, out = run_git(p, '-c', 'core.quotepath=false',
                      'status', '--porcelain', '--ignored')
    if rc != 0:
        return None
    status = {'untracked': [], 'ignored': []}
    for line in out.splitlines():
        code, path = line[:2], line[3:].rstrip()
        if code not in ('??', '!!') or not path:
            continue
        # a whole folder comes with its trailing slash and a file has
        # no slash at all; 'dir/new.txt' means the folder also holds
        # tracked files
        if '/' in path.rstrip('/'):
            continue
        bucket = status['untracked' if code == '??' else 'ignored']
        if path.rstrip('/') not in bucket:
            bucket.append(path.rstrip('/'))
    return status


# --- blocks E and F: sync and secrets in git ------------------------------------

def repo_extra(p, gi, deep=False, history_depth=None, history_all_refs=False,
               nested=True):
    ex = {'branch': None, 'ahead_behind': None, 'remote_class': None,
          'credentials_in_remote': False, 'gitignore': _exists(p / '.gitignore'),
          'hooks': [], 'sync_commits_last30': 0, 'tracked_secrets': [],
          'nested_repos': nested_repos(p) if nested else []}
    # repositories inside this one that .gitignore keeps out: a layout
    # the owner chose, not an accident
    ex['nested_repos_ignored'] = sorted(_ignored_files(p, ex['nested_repos']))
    rc, out = run_git(p, 'branch', '--show-current')
    if rc == 0 and out.strip():
        ex['branch'] = out.strip()
    rc, out = run_git(p, 'rev-list', '--left-right', '--count', 'HEAD...@{u}')
    if rc == 0 and out.strip():
        a, b = out.split()
        ex['ahead_behind'] = {'ahead': int(a), 'behind': int(b)}
    url = gi.get('remote')
    if url:
        ex['remote_class'] = classify_remote(url)
    # computed on the raw URL inside git_info, before sanitization
    ex['credentials_in_remote'] = bool(gi.get('credentials_in_remote'))

    hooks_dir = p / '.git' / 'hooks'
    if _exists(hooks_dir):
        for f in sorted(hooks_dir.iterdir()):
            if not f.is_file() or f.name.endswith('.sample'):
                continue
            try:
                content = f.read_text(encoding='utf-8', errors='replace')
            except OSError:
                continue
            ex['hooks'].append({
                'name': f.name,
                'flags': {
                    'add_all': bool(re.search(r'git add (-A|\.)', content)),
                    'push': 'push' in content,
                    'secret_scan': bool(re.search(r'secret|gitleaks|scan', content, re.I)),
                }})
    rc, out = run_git(p, 'log', '--oneline', '--since', '30 days ago', '--grep', 'sync')
    ex['sync_commits_last30'] = len([l for l in out.splitlines() if l.strip()])

    rc, out = run_git(p, 'grep', '--cached', '-i', '-nE', secscan.GIT_GREP_RE)
    own = {}
    if rc == 0:
        # the plugin's own source is in the index too when a copy of it
        # is kept in the folder: same exclusion as in the worktree scan
        ex['tracked_secrets'] = [
            h for h in secscan.scan_git_grep_output(out)
            if not _own_source_dir(_hit_dir(p, h), p, own)]
        for h in ex['tracked_secrets']:
            # the worktree scan does not read files of this size for
            # keys (bundles and minified libraries live there): a hit
            # from the index in such a file is "look by hand", not a key
            try:
                h['in_bundle'] = (p / str(h.get('file') or '')).stat().st_size \
                    >= SECRET_FILE_MAX_BYTES
            except OSError:
                h['in_bundle'] = False
        # a real key must not fall off the end behind library files
        ex['tracked_secrets'].sort(key=lambda h: bool(h.get('in_bundle')))
        del ex['tracked_secrets'][10:]

    if deep:
        hist = history_scan.scan_history(
            p, max_commits=history_depth, all_refs=history_all_refs,
            match_line=secscan.find_in_line)
        ex['history_secrets'] = [
            h for h in hist.pop('findings')
            if not _own_source_dir(_hit_dir(p, h), p, own)]
        ex['history_coverage'] = hist
    return ex


def _hit_dir(repo, hit):
    """Folder of a git hit (index or history), under the repo folder."""
    return (Path(repo) / str(hit.get('file') or '')).parent


# --- blocks A, B, C: harness, instructions, context tax -------------------------

def harness_report(home, root):
    tools = []
    now = time.time()
    for tool, cfg in HARNESS.items():
        d = home / cfg['dir']
        if not _exists(d):
            tools.append({'tool': tool, 'path': str(d), 'exists': False, 'reads': cfg['reads']})
            continue
        mtimes = [d.stat().st_mtime]
        for mk in cfg['markers']:
            f = d / mk
            if _exists(f):
                mtimes.append(f.stat().st_mtime)
        try:
            for ch in os.scandir(d):
                mtimes.append(ch.stat().st_mtime)
        except OSError:
            pass
        days = (now - max(mtimes)) / 86400
        state = 'active' if days <= HARNESS_FRESH_DAYS else (
            'abandoned' if days > HARNESS_STALE_DAYS else 'occasional')
        tools.append({'tool': tool, 'exists': True, 'last_activity_days_ago': round(days),
                      'state': state, 'reads': cfg['reads']})
    proj = [{'name': n, 'exists': _exists(root / n)}
            for n in ['.agents', '.claude', '.codex', '.zcode/config.json']]
    return {'tools': tools, 'project_dirs': proj, 'notes': []}


def context_checks(d, base, origin='project'):
    files = {}
    for name in ('AGENTS.md', 'CLAUDE.md'):
        f = d / name
        if _exists(f):
            files[name] = f.read_text(encoding='utf-8', errors='replace')

    pkg_scripts = None
    pkg = d / 'package.json'
    if _exists(pkg):
        try:
            pkg_scripts = json.loads(pkg.read_text(encoding='utf-8')).get('scripts', {})
        except (ValueError, OSError):
            pkg_scripts = {}
    has_makefile = _exists(d / 'Makefile') or _exists(d / 'makefile')

    entries = []
    for name, text in files.items():
        lines = [l for l in text.splitlines() if l.strip()]
        low = text.lower()
        markers = [m for m in GENERIC_MARKERS if m in low]
        is_pointer = (len(lines) <= 2 and bool(
            re.search(r'(see\b|см\.|→|full rules|полный порядок|актуальн)', text, re.I)))
        dead_links, dead_paths, dead_cmds = [], [], []
        for m in re.finditer(r'\[[^\]]*\]\(([^)\s]+)\)', text):
            ref = m.group(1).split('#')[0]
            if ref and not ref.startswith(('http', 'mailto:')) and not _exists(d / ref):
                dead_links.append(ref)
        for m in re.finditer(r'`([^`\s]+)`', text):
            raw = m.group(1).strip('`')
            if '/' not in raw or raw.startswith(('http', '~', '$', '-')):
                continue
            tok = raw.rstrip('/')
            if re.fullmatch(r'[\w.\\/-]+', tok) and not _exists(d / tok):
                dead_paths.append(tok)
        for m in re.finditer(r'\bnpm run ([\w:-]+)', text):
            if pkg_scripts is not None and m.group(1) not in pkg_scripts:
                dead_cmds.append('npm run ' + m.group(1))
        for m in re.finditer(r'\bmake ([\w-]+)', text):
            if not has_makefile:
                dead_cmds.append('make ' + m.group(1))
        entries.append({
            'path': str((d / name).relative_to(base)),
            'origin': origin,
            'lines': len(lines),
            'size_bytes': len(text.encode('utf-8')),
            'is_pointer': is_pointer,
            'generic_markers': markers,
            'dead_links': dead_links,
            'dead_paths': dead_paths,
            'dead_commands': dead_cmds,
        })

    drift = None
    if len(files) == 2:
        # a pair linked by an @AGENTS.md import is one source: no drift
        linked = '@AGENTS.md' in files['AGENTS.md'] or '@AGENTS.md' in files['CLAUDE.md']
        if not linked:
            a = {l.strip() for l in files['AGENTS.md'].splitlines() if l.strip()}
            c = {l.strip() for l in files['CLAUDE.md'].splitlines() if l.strip()}
            if len(a) >= 4 and len(c) >= 4 and (a | c):
                j = len(a & c) / len(a | c)
                if j < 0.5:
                    drift = {'path': str(d.relative_to(base)) or '.', 'jaccard': round(j, 2)}
    return entries, drift


def context_tax(home, root):
    files = []
    for role, p in [('user-zcode', home / '.zcode' / 'AGENTS.md'),
                    ('user-claude', home / '.claude' / 'CLAUDE.md'),
                    ('project', root / 'AGENTS.md'), ('project', root / 'CLAUDE.md')]:
        if _exists(p):
            files.append({'role': role, 'path': str(p), 'size_bytes': p.stat().st_size})
    mem_dir = home / '.zcode' / 'cli' / 'memories'
    over_lines = []
    if _exists(mem_dir):
        for m in list(mem_dir.rglob('MEMORY.md'))[:20]:
            files.append({'role': 'memory-index', 'path': str(m),
                          'size_bytes': m.stat().st_size})
            with m.open('rb') as fh:
                if sum(1 for _ in fh) > MEMORY_LINE_LIMIT:
                    over_lines.append(str(m))
    proj_total = sum(f['size_bytes'] for f in files if f['role'] == 'project')
    return {'session_files': files,
            'project_total_bytes': proj_total,
            'benchmark_project_bytes': PROJECT_BENCH,
            'memory_over_limit': [f['path'] for f in files
                                  if f['role'] == 'memory-index'
                                  and f['size_bytes'] > MEMORY_LIMIT],
            'memory_over_lines': over_lines}


# --- block G: skills -----------------------------------------------------------

def parse_skill(f):
    try:
        text = f.read_text(encoding='utf-8', errors='replace')
    except OSError:
        text = ''
    m = re.match(r'^---\s*\n(.*?)\n---', text, re.S)
    fm = m.group(1) if m else ''
    nm = re.search(r'^name:\s*(.+?)\s*$', fm, re.M)
    dm = re.search(r'^description:\s*(.+?)\s*$', fm, re.M)
    desc = dm.group(1) if dm else ''
    return {'name': nm.group(1) if nm else f.parent.name,
            'desc_len': len(desc) if dm else None,
            'has_triggers': bool(re.search(r'use when|when asked|trigger|когда|использовать|если попрос|триггер', desc, re.I)),
            'md5': hashlib.md5(text.encode('utf-8', 'replace')).hexdigest(),
            'path': str(f)}


# SKILL.md files checked per skill folder. The plugin cache keeps every
# installed version of every skill and can hold thousands; above the cap
# the scan reports a truncated (unknown) check instead of a silent pass.
SKILLS_FOLDER_CAP = 1000


def _os_reason(exc):
    """Why a folder could not be read, without the path: the system
    message up to its first colon ('[WinError 5] Access is denied')."""
    text = str(exc).split(':', 1)[0].strip()
    return text or type(exc).__name__


def skills_report(home, root):
    locs = [('user-zcode', home / '.zcode' / 'skills', 'one'),
            ('user-claude', home / '.claude' / 'skills', 'one'),
            ('project-agents', root / '.agents' / 'skills', 'one'),
            ('project-claude', root / '.claude' / 'skills', 'one'),
            ('plugins-cache', home / '.zcode' / 'cli' / 'plugins' / 'cache', 'deep')]
    found = []
    checked = []
    failed = []
    truncated = []
    for loc, base, mode in locs:
        if not _exists(base):
            continue
        try:
            if mode == 'one':
                paths = [child / 'SKILL.md' for child in sorted(base.iterdir())]
                paths = [sk for sk in paths if sk.is_file()]
            else:
                paths = [sk for sk in sorted(base.rglob('SKILL.md')) if sk.is_file()]
        except OSError as exc:
            # exists, but cannot be listed (permissions, not a folder, ...):
            # an unreadable folder is an unchecked check, never a crash and
            # never an empty result
            failed.append({'location': loc, 'reason': _os_reason(exc)})
            continue
        checked.append(f'{loc}: {base}')
        if len(paths) > SKILLS_FOLDER_CAP:
            truncated.append({'location': loc, 'scanned': SKILLS_FOLDER_CAP,
                              'found': len(paths), 'cap': SKILLS_FOLDER_CAP})
            paths = paths[:SKILLS_FOLDER_CAP]
        for sk in paths:
            found.append((loc, sk))
    entries = []
    for loc, f in found:
        e = parse_skill(f)
        e['location'] = loc
        entries.append(e)
    # the plugin cache is managed by the CLI and keeps several versions of one
    # skill: diverging copies there are expected, not counted as a desync
    managed = [e for e in entries if e['location'] != 'plugins-cache']
    by_name = {}
    for e in managed:
        by_name.setdefault(e['name'], []).append(e)
    dups = []
    for name, es in sorted(by_name.items()):
        if len(es) > 1:
            same = len({e['md5'] for e in es}) == 1
            dups.append({'name': name, 'copies': len(es),
                         'sync': 'identical' if same else 'DIVERGED',
                         'paths': [e['path'] for e in es]})
    return {'entries': entries, 'duplicates': dups,
            'locations_checked': checked,
            # what the search actually covered: folders read, folders that
            # exist but could not be read, folders cut by the cap
            'coverage': {'checked': [line.split(':', 1)[0] for line in checked],
                         'failed': failed, 'truncated': truncated}}


# --- summary gates ---------------------------------------------------------------
# Gate evaluation moved to gates.py (stage 2): declarative definitions,
# severity/status split, UNKNOWN on missing data. The old inline builder
# was removed; audit_scan collects facts, gates.evaluate judges them.


def _reference_texts(root, proj_dirs, skills_paths):
    """Texts a junk candidate may be referenced from: instruction files,
    package.json and SKILL.md bodies. Capped per file."""
    out = []
    bases = [root] + list(proj_dirs)
    for base in bases:
        for name in ('AGENTS.md', 'CLAUDE.md', 'package.json'):
            p = base / name
            if p.is_file():
                try:
                    out.append(p.read_text(encoding='utf-8', errors='replace')[:100000])
                except OSError:
                    pass
    for p in skills_paths:
        try:
            out.append(Path(p).read_text(encoding='utf-8', errors='replace')[:100000])
        except OSError:
            pass
    return out


# --- findings with fingerprint (for baseline/diff) ------------------------------

def collect_findings(rep):
    """Stable finding identifiers: no dates or sizes, so a re-scan of an
    unchanged workspace yields the same set."""
    def fp(s):
        return hashlib.md5(s.encode('utf-8')).hexdigest()[:12]

    out = []
    for s in rep['secrets']:
        out.append({'fp': fp(f"secret|{s['path']}|{s['line']}|{s['kind']}"),
                    'section': 'secrets', 'path': s['path']})
    for e in rep['context_files']:
        for kind in ('dead_links', 'dead_paths', 'dead_commands'):
            for v in e[kind]:
                out.append({'fp': fp(f"{kind}|{e['path']}|{v}"),
                            'section': kind, 'path': f"{e['path']} | {v}"[:100]})
    for d in rep['context_drift']:
        out.append({'fp': fp(f"drift|{d['path']}"), 'section': 'context_drift',
                    'path': d['path']})
    for f in rep['junk']['files']:
        out.append({'fp': fp(f"junk-file|{f['path']}"), 'section': 'junk', 'path': f['path']})
    for f in rep['junk']['dirs']:
        out.append({'fp': fp(f"junk-dir|{f['path']}"), 'section': 'junk', 'path': f['path']})
    for e in rep['junk']['empty_dirs']:
        out.append({'fp': fp(f"empty-dir|{e}"), 'section': 'junk', 'path': e})
    for g in rep['duplicates']:
        key = '|'.join(sorted(g['files']))
        out.append({'fp': fp(f"dup|{key}"), 'section': 'duplicates', 'path': key[:100]})
    for g in rep['large_files']:
        out.append({'fp': fp(f"large|{g['path']}"), 'section': 'large_files', 'path': g['path']})
    for d in rep['skills']['duplicates']:
        if d['sync'] != 'identical':
            out.append({'fp': fp(f"skill-desync|{d['name']}"), 'section': 'skills',
                        'path': d['name']})
    for n in rep['harness']['notes']:
        out.append({'fp': fp(f"note|{n}"), 'section': 'harness', 'path': n[:100]})
    return out


# --- main walk -------------------------------------------------------------------

def chain_budget(root):
    """Codex budget: 32,768 bytes for the chain of root + nested AGENTS.md."""
    trees = [root] + [e for e in sorted(root.iterdir()) if e.is_dir()]
    out = []
    for tree in trees:
        main = tree / 'AGENTS.md'
        if not _exists(main):
            continue
        total = main.stat().st_size
        for dp, dns, _fns in os.walk(tree):
            dns[:] = [d for d in dns if d != '.git' and d not in BUILD_DIRS]
            if dp == str(tree):
                continue
            nested = Path(dp) / 'AGENTS.md'
            if _exists(nested):
                total += nested.stat().st_size
        out.append({'root': str(tree.relative_to(root)) or '.',
                    'total_bytes': total, 'over': total > CHAIN_BUDGET})
    return out


def scan(root, home, deep=False, history_depth=None, history_all_refs=False,
         profile=None):
    # canonical forms first: CI runners hand out short (8.3) or symlinked
    # temp paths, and every containment check below compares against these
    root = Path(root).resolve()
    home = Path(home).resolve()
    prof = {} if profile is None else profile
    t0 = time.monotonic()
    _tp = t0
    rep = {'schema_version': '1.0', 'root': str(root), 'home': str(home),
           'generated_at': datetime.now().astimezone().isoformat(timespec='seconds'),
           'top_level': [], 'dup_checkouts': {}, 'context_files': [], 'context_drift': [],
           'context_tax': {}, 'harness': {}, 'skills': {},
           'context_budget': [], 'chain_budget_over': False,
           'findings': [], 'rules_version': RULES_VERSION,
           'junk': {'files': [], 'dirs': [], 'empty_dirs': []},
           'duplicates': [], 'large_files': [], 'secrets': [], 'gates': [],
           'git_roots': [], 'stats': {}}
    # every folder holding a .git, relative to root ('.' = the root itself);
    # filled by the walk below
    git_roots = rep['git_roots']
    per_top, total_files = {}, 0
    seen_secret_lines = set()
    skipped_links = 0
    link_skips = []
    # deferred, read-once work: sizes come from DirEntry stats (cached on
    # Windows), file CONTENT is read at most once per file, and only for
    # the few files that need it (duplicate-size groups, secret candidates)
    size_groups = {}     # size -> [rel paths] (dedup candidates only)
    secret_candidates = []  # (rel, fn) files whose content may hide secrets
    own_source = {}      # directory -> lies inside this plugin's source
    # files that would have been read for keys but lie in a copy of this
    # plugin's own source: counted so that the gap can be reported
    own_source_skipped = 0

    def inside_root(target):
        return target == root or root in target.parents

    # single scandir-based walk: DirEntry.stat(follow_symlinks=False) is
    # cached metadata on Windows, so the traversal costs one scandir per
    # directory and zero per-file path stats
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            entries = list(os.scandir(current))
        except OSError:
            continue
        subdirs = []
        has_children = False
        for ent in entries:
            try:
                # boundary by realpath, not by is_symlink(): junctions and
                # any other reparse points must not silently pass either
                try:
                    real = Path(os.path.realpath(ent.path))
                except OSError:
                    real = None
                # escape = realpath lands outside the resolved root; any
                # spelling difference that stays inside is harmless
                if real is not None and not inside_root(real):
                    skipped_links += 1
                    if len(link_skips) < 8:
                        link_skips.append(ent.name)
                    continue
                if ent.is_dir(follow_symlinks=False):
                    has_children = True
                    dn = ent.name
                    if dn == '.git':
                        # the folder holding it is a git repository; record
                        # it (top level or nested) and do not walk inside
                        git_roots.append(str(Path(current).relative_to(root)))
                        continue
                    reason = (f'build artifact ({dn})' if dn in BUILD_DIRS
                              else dir_junk_reason(dn))
                    if reason:
                        size, count = subtree(Path(ent.path))
                        rel = str(Path(ent.path).relative_to(root))
                        top = rel.split(os.sep)[0]
                        rep['junk']['dirs'].append(
                            {'path': rel, 'reason': reason,
                             'size_bytes': size, 'files': count})
                        per_top[top] = per_top.get(top, 0) + size
                        total_files += count
                        continue
                    subdirs.append(ent.path)
                elif ent.is_file(follow_symlinks=False):
                    has_children = True
                    try:
                        st = ent.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    fn = ent.name
                    if fn == '.git':
                        # a .git file marks a repository too (worktrees,
                        # submodules)
                        git_roots.append(str(Path(current).relative_to(root)))
                    rel = str(Path(ent.path).relative_to(root))
                    top = rel.split(os.sep)[0]
                    per_top[top] = per_top.get(top, 0) + st.st_size
                    total_files += 1

                    why = file_junk_reason(fn)
                    if why:
                        rep['junk']['files'].append(
                            {'path': rel, 'reason': why,
                             'size_bytes': st.st_size})
                    if st.st_size >= BIG_FILE_BYTES:
                        rep['large_files'].append(
                            {'path': rel, 'size_bytes': st.st_size})
                    if DUP_MIN_BYTES <= st.st_size <= DUP_MAX_BYTES:
                        size_groups.setdefault(st.st_size, []).append(rel)
                    if (fn in SECRET_FILENAMES or NAME_SECRET_RX.search(fn)
                        or Path(fn).suffix.lower() in TEXT_EXTS) \
                        and st.st_size < SECRET_FILE_MAX_BYTES:
                        if _own_source_dir(current, root, own_source):
                            own_source_skipped += 1
                        else:
                            secret_candidates.append((rel, fn))
            except OSError:
                # entry vanished between scandir and stat: skip it
                continue
        if current != root and not has_children:
            rep['junk']['empty_dirs'].append(
                str(Path(current).relative_to(root)))
        stack.extend(reversed(subdirs))

    # stable order: the walk visits folders in stack order
    rep['git_roots'] = sorted(set(git_roots))

    # --- read-once, parallel content pass ------------------------------------
    # Duplicates and secrets share ONE open per file: the per-open tax on
    # Windows (defender/AV) dominates on large trees, so reads run in a
    # small thread pool (I/O-bound; results are merged deterministically).
    # Completeness is unchanged: every duplicate-size group is still
    # two-stage hashed (4 KB head, then full for survivors), every secret
    # candidate is still fully scanned.
    dup_candidates = {rel for rels in size_groups.values() if len(rels) >= 2
                      for rel in rels}
    secret_set = {rel for rel, _fn in secret_candidates}

    def _read_task(rel):
        p = root / rel
        head = None
        text = None
        full_hash = None
        try:
            with p.open('rb') as fh:
                if rel in dup_candidates:
                    head = fh.read(4096)
                    if len(head) < 4096:          # short file: this IS full
                        data = head
                    elif rel in secret_set:
                        data = head + fh.read()
                    else:
                        data = None
                elif rel in secret_set:
                    data = fh.read()
                else:
                    data = None
        except OSError:
            return rel, None, None, None
        if data is not None:
            # hashed over the bytes as read, never over re-encoded text
            # (errors='replace' below changes bytes that were invalid UTF-8)
            full_hash = hashlib.md5(data).hexdigest()
            if rel in secret_set:
                text = data.decode('utf-8', errors='replace')
        return rel, head, text, full_hash

    from concurrent.futures import ThreadPoolExecutor
    head_by_rel = {}
    text_by_rel = {}
    # files the shared pass already read in full: their whole-file hash is
    # known and the second dedup stage must not open them again
    full_hash_by_rel = {}
    with ThreadPoolExecutor(max_workers=8) as pool:
        for rel, head, text, full_hash in pool.map(_read_task,
                                                   sorted(dup_candidates | secret_set)):
            if head is not None:
                head_by_rel[rel] = head
            if text is not None:
                text_by_rel[rel] = text
            if full_hash is not None:
                full_hash_by_rel[rel] = full_hash

    # duplicates: group by head hash, full-hash only surviving groups.
    # Sorted by path: the walk order differs between systems, and the
    # order of a report must not
    hashes = {}
    for size, rels in sorted(size_groups.items()):
        if len(rels) < 2:
            continue
        first_stage = {}
        for rel in sorted(rels, key=lambda r: r.replace('\\', '/').split('/')):
            head = head_by_rel.get(rel)
            if head is None:
                continue
            first_stage.setdefault(hashlib.md5(head).hexdigest(), []).append(rel)
        for group in first_stage.values():
            if len(group) < 2:
                continue
            full = {}
            for rel in group:
                h = full_hash_by_rel.get(rel)
                if h is None:
                    # only the head was read (large or non-text candidate):
                    # read the whole file now
                    try:
                        h = hashlib.md5((root / rel).read_bytes()).hexdigest()
                    except OSError:
                        continue
                full.setdefault(h, []).append(rel)
            for h, paths in full.items():
                if len(paths) > 1:
                    hashes.setdefault(h, []).extend(paths)

    # secrets: text was decoded during the shared pass
    for rel, _fn in secret_candidates:
        text = text_by_rel.get(rel)
        if text is None:
            continue
        for hit in secscan.scan_text(rel, text):
            if (rel, hit['line']) in seen_secret_lines:
                continue
            seen_secret_lines.add((rel, hit['line']))
            rep['secrets'].append({'path': rel, 'line': hit['line'],
                                   'kind': hit['kind'],
                                   'mask': hit['mask'],
                                   'fingerprint': hit['fingerprint'],
                                   'confidence': hit['confidence']})

    # where large files and files with keys sit in the nearest repository:
    # tracked, ignored by .gitignore or not added yet
    states = git_file_states(root, rep['git_roots'],
                             [f['path'] for f in rep['large_files']]
                             + [s['path'] for s in rep['secrets']])
    for f in rep['large_files']:
        state = states.get(_norm_rel(f['path']))
        if state:
            f['tracked'] = state == 'tracked'
    for s in rep['secrets']:
        state = states.get(_norm_rel(s['path']))
        if state:
            s['git'] = state

    prof['walk'] = time.monotonic() - _tp; _tp = time.monotonic()
    def _path_key(rel):
        # one order on every system, whatever the separator
        return rel.replace('\\', '/').split('/')

    for h, paths in hashes.items():
        if len(paths) > 1:
            sz = (root / paths[0]).stat().st_size
            rep['duplicates'].append(
                {'size_bytes': sz, 'files': sorted(paths, key=_path_key)})
    rep['duplicates'].sort(
        key=lambda g: (-g['size_bytes'], [_path_key(p) for p in g['files']]))

    remotes = {}
    for entry in sorted(root.iterdir(), key=lambda e: e.name):
        if entry.is_dir():
            gi = git_info(entry)
            item = {'name': entry.name,
                    'kind': 'repo' if gi else 'dir',
                    'git': gi,
                    'size_bytes': per_top.get(entry.name, 0)}
            if gi:
                item['extra'] = repo_extra(entry, gi, deep,
                                           history_depth, history_all_refs)
                if gi.get('remote'):
                    # checkout identity: scheme://host/path only — userinfo is
                    # already sanitized away; query/fragment do not change
                    # which repository a checkout points at
                    key = re.split(r'[?#]', gi['remote'])[0]
                    remotes.setdefault(key, []).append(entry.name)
            rep['top_level'].append(item)
        else:
            try:
                fsize = entry.stat().st_size
            except OSError:
                fsize = 0  # symlink to an inaccessible target: metadata only
            rep['top_level'].append({'name': entry.name, 'kind': 'file',
                                     'size_bytes': fsize})
    rep['dup_checkouts'] = {u: names for u, names in remotes.items() if len(names) > 1}
    prof['top_git'] = time.monotonic() - _tp; _tp = time.monotonic()

    # the audited folder itself may be a repository. Its git side is read
    # like that of any other one and listed first, under the name '.'
    root_gi = git_info(root)
    if root_gi:
        root_ex = repo_extra(root, root_gi, deep, history_depth,
                             history_all_refs, nested=False)
        # the walk already found every repository: they all sit inside
        # this one
        root_ex['nested_repos'] = [g for g in rep['git_roots'] if g != '.']
        root_ex['nested_repos_ignored'] = sorted(
            _ignored_files(root, root_ex['nested_repos']))
        # which top-level entries hold tracked files (see _g4)
        root_ex['top_status'] = git_top_status(root)
        # the tool writes its reports into .agents-doctor/: is that
        # folder kept out of git? The path need not exist for git to say
        rc, _out = run_git(root, 'check-ignore', '-q', '--',
                           '.agents-doctor/scan.json')
        root_ex['tool_dir_ignored'] = (True if rc == 0
                                       else False if rc == 1 else None)
        rep['top_level'].insert(0, {'name': '.', 'kind': 'repo', 'git': root_gi,
                                    'extra': root_ex})

    proj_ctx_dirs = [e for e in sorted(root.iterdir())
                     if e.is_dir() and (_exists(e / 'AGENTS.md') or _exists(e / 'CLAUDE.md'))]
    for d, base, origin in [(root, root, 'project'),
                            (home / '.zcode', home, 'home'),
                            (home / '.claude', home, 'home')] + \
                   [(e, root, 'project') for e in proj_ctx_dirs]:
        if d.exists():
            entries, drift = context_checks(d, base, origin)
            rep['context_files'].extend(entries)
            if drift:
                rep['context_drift'].append(drift)

    # content quality of project instruction files: are the words inside
    # worth the context they cost? Analyzed for project files only; home
    # files are small by design and cost nothing here.
    rep['content_quality'] = {}
    for e in rep['context_files']:
        if e.get('origin') != 'project':
            continue
        path = root / e['path']
        if path.is_file():
            try:
                text = path.read_text(encoding='utf-8', errors='replace')
                dead_refs = (e.get('dead_links', [])
                             + e.get('dead_paths', [])
                             + e.get('dead_commands', []))
                rep['content_quality'][e['path']] = content_quality.analyze_content(
                    text, e['path'], dead_refs=dead_refs)
            except OSError:
                pass

    rep['harness'] = harness_report(home, root)
    # recursive, honest harness activity (stage 2): overrides the shallow
    # top-level mtime heuristic; missing data reads as unknown, not abandoned
    try:
        hs = enrich.harness_states(home)
        for tool in rep['harness']['tools']:
            if tool.get('tool') in hs:
                tool.update(hs[tool['tool']])
    except OSError:
        pass
    claude = next((t for t in rep['harness']['tools'] if t['tool'] == 'claude'), None)
    if claude and claude.get('state') == 'abandoned':
        for e in rep['context_files']:
            if e['path'].endswith('CLAUDE.md') and not e['is_pointer'] \
                    and e.get('origin') != 'home':
                rep['harness']['notes'].append(
                    f"{e['path']}: maintained for a dead harness, claude inactive for "
                    f"{claude.get('last_activity_days_ago')} days")

    rep['context_tax'] = context_tax(home, root)
    rep['skills'] = skills_report(home, root)
    rep['context_budget'] = chain_budget(root)
    rep['chain_budget_over'] = any(c['over'] for c in rep['context_budget'])

    prof['context'] = time.monotonic() - _tp; _tp = time.monotonic()
    # --- stage-2 enrichment facts ------------------------------------------------
    repo_dirs = [str(root / t['name']) for t in rep['top_level']
                 if t.get('kind') == 'repo']
    try:
        rep['config_integrity'] = enrich.config_integrity(root, repo_dirs)
    except OSError:
        rep['config_integrity'] = []
    try:
        rep['heavy_outside_git'] = enrich.heavy_outside_git(root)
    except OSError:
        rep['heavy_outside_git'] = []
    skills_paths = [e['path'] for e in rep['skills']['entries']]
    ref_texts = _reference_texts(root, proj_ctx_dirs, skills_paths)
    junk_candidates = rep['junk']['files'] + rep['junk']['dirs']
    try:
        rep['junk_classified'] = enrich.classify_junk(root, junk_candidates, ref_texts)
    except OSError:
        rep['junk_classified'] = []
    # normalize the enrich shape to the gates contract (cls + signals dict)
    for j in rep['junk_classified']:
        j.setdefault('cls', j.pop('classification', 'unknown'))
        if 'signals' not in j:
            j['signals'] = {k: j.get(k) for k in ('tracked', 'age_days', 'referenced')}
    try:
        rep['skills_extra'] = enrich.skills_frontmatter(rep['skills']['entries'])
    except OSError:
        rep['skills_extra'] = {}

    # --- harness registry stage (Phase 1/2): detection over all
    # registered adapters, adapter-specific validation, instruction
    # conflicts at the workspace root. Legacy rep['harness'] above stays
    # untouched for back-compat; this block only ADDS sections.
    try:
        import harness.collect as harness_collect
        _act = {}
        for t in rep['harness'].get('tools') or []:
            if 'state' in t:
                _act[t['tool']] = {'state': t['state']}
        # legacy tool names vs registry ids: claude -> claude_code
        if 'claude' in _act and 'claude_code' not in _act:
            _act['claude_code'] = _act['claude']
        hc = harness_collect.collect(root, home, _act)
        rep['harnesses'] = hc['harnesses']
        rep['harness_spec_matrix'] = hc['spec_matrix']
        rep['instruction_conflict_summary'] = hc['conflict_summary']
        rep['harness_findings_raw'] = (hc['adapter_findings']
                                       + hc['instruction_conflicts'])
    except Exception:
        # the registry stage must never kill a scan; an empty section
        # reads as 'no data' downstream (unknown, never pass)
        rep.setdefault('harnesses', [])
        rep.setdefault('harness_spec_matrix', [])
        rep.setdefault('instruction_conflict_summary', {})
        rep.setdefault('harness_findings_raw', [])
    # MCP inventory (v2.1 security hardening): server names and
    # transports only — env values and full commands never enter the
    # report by construction (see mcp_inventory.py)
    try:
        import mcp_inventory
        rep['mcp_inventory'] = mcp_inventory.collect_mcp_inventory(
            root, home)
    except Exception:
        rep['mcp_inventory'] = {'servers': [], 'files_scanned': [],
                                'parse_errors': []}

    prof['enrich'] = time.monotonic() - _tp; _tp = time.monotonic()
    rep['findings'] = collect_findings(rep)
    rep['gates'], rep['findings_detailed'] = gates_engine.evaluate(rep)
    prof['gates'] = time.monotonic() - _tp
    rep['stats'] = {'profile': {k: round(v, 3) for k, v in prof.items()},
                    'total_files': total_files,
                    'total_size_bytes': sum(per_top.values()),
                    'skipped_symlinks_outside': skipped_links,
                    'skipped_symlink_names': link_skips,
                    'own_source_skipped': own_source_skipped,
                    'duration_sec': round(time.monotonic() - t0, 2)}
    return rep


def main():
    ap = argparse.ArgumentParser(description='agent workspace audit')
    ap.add_argument('path', help='workspace root')
    ap.add_argument('--home', default=str(Path.home()), help='home directory (harnesses, memory, skills)')
    ap.add_argument('--deep', action='store_true', help='scan git history for secrets (slower)')
    ap.add_argument('--history-depth', type=int, default=None, metavar='N',
                    help='cap the deep history scan at N commits per repo; '
                         'coverage of the cap is reported and incomplete scans '
                         'never read as a pass')
    ap.add_argument('--history-all-refs', action='store_true',
                    help='deep-scan history across all refs, not only HEAD')
    ap.add_argument('--profile', action='store_true',
                    help='print per-stage timings (walk, git, context, enrich, gates) to stderr')
    ap.add_argument('--baseline', default=None, help='previous scan.json: adds a diff section (new findings only)')
    ap.add_argument('--out', default='scan.json', help='where to write the JSON report')
    a = ap.parse_args()
    root = Path(a.path).resolve()
    home = Path(a.home).resolve()
    if not root.is_dir():
        sys.exit('not a directory: ' + str(root))
    try:
        prof = {} if a.profile else None
        rep = scan(root, home, a.deep, a.history_depth,
                   a.history_all_refs, profile=prof)
    except FingerprintKeyError as e:
        sys.exit('fingerprint key unavailable: %s\n'
                 'fix with: python skills/agents-doctor/scripts/fingerprint.py --check'
                 % str(e))
    if a.baseline and _exists(Path(a.baseline)):
        try:
            old = json.loads(Path(a.baseline).read_text(encoding='utf-8'))
        except (ValueError, OSError):
            old = None
        if old is not None:
            old_fps = {f['fp'] for f in old.get('findings', [])}
            new_fps = {f['fp'] for f in rep['findings']}
            rep['diff'] = {'new': [f for f in rep['findings'] if f['fp'] not in old_fps],
                           'resolved': [f for f in old.get('findings', [])
                                        if f['fp'] not in new_fps]}
    Path(a.out).write_text(json.dumps(rep, ensure_ascii=False, indent=2), encoding='utf-8')
    if a.profile:
        for k, v in sorted(rep['stats']['profile'].items()):
            print('profile %-8s %8.2f s' % (k, v), file=sys.stderr)
        if rep['stats'].get('skipped_symlink_names'):
            print('profile symlink/outside skips: %d %r'
                  % (rep['stats']['skipped_symlinks_outside'],
                     rep['stats']['skipped_symlink_names']), file=sys.stderr)
    j = rep['junk']
    st = lambda s: sum(1 for g in rep['gates'] if g['status'] == s)
    print(f"scan: {rep['stats']['total_files']} files, "
          f"{rep['stats']['total_size_bytes'] // 1024} KB, {rep['stats']['duration_sec']} s")
    print(f"gates: fail {st('fail')}, warn {st('warn')}, pass {st('pass')}, "
          f"unknown {st('unknown')}, n/a {st('not_applicable')}")
    print(f"typed findings: {len(rep['findings_detailed'])} "
          f"(critical {sum(1 for f in rep['findings_detailed'] if f['severity'] == 'critical')})")
    print(f"findings: secrets {len(rep['secrets'])}, drift pairs {len(rep['context_drift'])}, "
          f"duplicate checkouts {len(rep['dup_checkouts'])}, "
          f"junk files {len(j['files'])}, junk dirs {len(j['dirs'])}, "
          f"empty dirs {len(j['empty_dirs'])}, duplicate groups {len(rep['duplicates'])}")
    print(f"fingerprinted findings: {len(rep['findings'])} (rules {rep['rules_version']})")
    if rep['stats'].get('skipped_symlinks_outside'):
        print(f"skipped symlinks pointing outside the root: "
              f"{rep['stats']['skipped_symlinks_outside']}")
    if 'diff' in rep:
        print(f"baseline: {len(rep['diff']['new'])} new, {len(rep['diff']['resolved'])} resolved")
    print('full report: ' + a.out)


if __name__ == '__main__':
    main()
