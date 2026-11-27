#!/usr/bin/env python3
"""Agent Runtime Health.

Opt-in runtime environment audit: verifies that this machine can run
the agent harnesses the static audit talks about. STRICTLY opt-in --
audit_scan.scan() must never call into this module on its own; it runs
only through an explicit check_environment() call or the CLI flag the
main session wires into agents_doctor.py.

Safety contract:
- offline: no network access of any kind (MCP endpoints are never
  contacted, config checks are structure-only);
- read-only: nothing is written to disk;
- the only subprocess ever spawned is `<bin> --version` with a 10s
  timeout, shell=False and a list argv. The inventory checks
  (skills, plugin cache, MCP commands) are pure filesystem reads:
  RT-MCP-COMMANDS looks command names up on PATH via shutil.which but
  never executes anything, and env VALUES never enter any output -- it
  consumes the secret-free mcp_inventory (env names only) and uses
  nothing beyond the command token itself.

Every check reports {id, name, status, detail, evidence} with status in
pass | fail | warn | unknown | not_applicable. The summary counts the
four real statuses; not_applicable (harnesses with no CLI to probe) is
excluded from the counts.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import iter_adapters        # noqa: E402
from harness.base import HarnessContext  # noqa: E402
import mcp_inventory                     # noqa: E402  (secret-free, offline)

try:
    import tomllib  # stdlib since Python 3.11
except ImportError:  # Python 3.10
    tomllib = None

# --- policy ----------------------------------------------------------------

# harness_id -> CLI binary name on PATH; None = nothing to probe
# (editor plugin or GUI application, not a command-line tool).
CLI_BINARIES = {
    'zcode': 'zcode',
    'claude_code': 'claude',
    'codex': 'codex',
    'gemini_cli': 'gemini',
    'opencode': 'opencode',
    'github_copilot': None,   # editor plugin
    'cursor': None,           # GUI application
    'windsurf': None,         # GUI application
}

# top-level keys under which harness configs keep their MCP server map
MCP_SECTION_KEYS = ('mcpServers', 'mcp_servers', 'mcp')
# files whose whole top-level object IS the server map (Claude Code)
MCP_MAP_FILENAMES = ('.mcp.json',)

VERSION_TIMEOUT_SECONDS = 10
STALE_LOCK_SECONDS = 3600
# keep in sync with trashops.TRASH_DIR_NAME; importing trashops here
# would drag the trash-run machinery in for one string constant
TRASH_DIR_NAME = '.agents-doctor-trash'

SUMMARY_STATUSES = ('pass', 'fail', 'warn', 'unknown')

# --- skills inventory policy (RT-SKILLS-VERSIONS / RT-SKILLS-CONFLICTS) ---

# manifests that may declare a skill version, in priority order: the
# first one present in the skill directory wins
SKILL_MANIFEST_FILES = ('plugin.json', 'package.json')
# the version inventory rides in the report evidence, so the scan stops
# after this many skill directories (plugin-cache-heavy homes included)
SKILLS_INVENTORY_CAP = 200

# --- plugin cache policy (RT-PLUGIN-FRESHNESS) ---

# a plugin directory untouched for more than this many days is listed
# as informational evidence ONLY: installed plugins are under no
# obligation to update on a schedule, so staleness is never a warn
PLUGIN_FRESHNESS_DAYS = 180
PLUGIN_FRESHNESS_SECONDS = PLUGIN_FRESHNESS_DAYS * 86400
# CLI-managed plugin caches, relative to the user home; the freshness
# unit is <cache>/<marketplace>/<plugin>
PLUGIN_CACHE_ROOTS = (
    ('zcode', ('.zcode', 'cli', 'plugins', 'cache')),
    ('claude_code', ('.claude', 'plugins', 'cache')),
)

# --- helpers ---------------------------------------------------------------


def _make_check(cid, name, status, detail, evidence=()):
    return {'id': cid, 'name': name, 'status': status,
            'detail': detail, 'evidence': list(evidence)}


def _exists(path: Path) -> bool:
    try:
        return path.exists()
    except OSError:
        return False


def _dir_exists(path: Path) -> bool:
    try:
        return path.is_dir()
    except OSError:
        return False


# --- RT-PY: interpreter version -------------------------------------------


def _check_python() -> dict:
    v = sys.version_info
    version = '%d.%d.%d' % (v[0], v[1], v[2])
    headline = sys.version.splitlines()[0] if sys.version else version
    if (v[0], v[1]) >= (3, 10):
        return _make_check(
            'RT-PY', 'Python runtime', 'pass',
            'Python %s meets the 3.10+ requirement' % version,
            [headline, sys.executable or 'interpreter path unknown'])
    return _make_check(
        'RT-PY', 'Python runtime', 'fail',
        'Python %s is below 3.10; the scanner itself requires 3.10+'
        % version,
        [headline])


# --- RT-GIT: git availability ----------------------------------------------


def _check_git() -> dict:
    git = shutil.which('git')
    if git:
        return _make_check('RT-GIT', 'git availability', 'pass',
                           'git found on PATH', [git])
    return _make_check(
        'RT-GIT', 'git availability', 'warn',
        'git not found on PATH; git-based gates degrade to unknown, '
        'not to fail', [])


# --- RT-CLI-<HARNESS>: CLI binary probes -----------------------------------


def _probe_version(binary):
    """Run `<binary> --version`. Returns (ok, detail). Never raises;
    the only command ever spawned by this module."""
    try:
        proc = subprocess.run(
            [binary, '--version'],
            capture_output=True, text=True, errors='replace',
            timeout=VERSION_TIMEOUT_SECONDS, shell=False)
    except subprocess.TimeoutExpired:
        return False, 'timed out after %ds' % VERSION_TIMEOUT_SECONDS
    except OSError as exc:
        return False, 'cannot execute (%s)' % exc
    if proc.returncode != 0:
        return False, 'exited with code %d' % proc.returncode
    lines = (proc.stdout or '').strip().splitlines()
    return True, lines[0].strip() if lines else 'exit 0 (no output)'


def _check_cli(adapter, home_hits, allow_subprocess) -> dict:
    """One RT-CLI check for a harness whose home markers were found."""
    hid = adapter.harness_id
    cid = 'RT-CLI-%s' % hid.upper()
    name = '%s CLI' % adapter.display_name
    evidence = ['home marker: %s' % h for h in home_hits[:3]]
    if hid not in CLI_BINARIES:
        return _make_check(
            cid, name, 'unknown',
            'no CLI binary mapping registered for this harness',
            evidence)
    binary = CLI_BINARIES[hid]
    if binary is None:
        kind = ('an editor plugin' if hid == 'github_copilot'
                else 'a GUI application')
        return _make_check(
            cid, name, 'not_applicable',
            '%s is %s, not a CLI tool; no binary to probe'
            % (adapter.display_name, kind), evidence)
    resolved = shutil.which(binary)
    if not resolved:
        return _make_check(
            cid, name, 'warn',
            'installed state dir present but CLI not on PATH',
            evidence + ['%s not found on PATH' % binary])
    evidence.append(resolved)
    if not allow_subprocess:
        return _make_check(
            cid, name, 'pass',
            'binary present (version check skipped)', evidence)
    ok, detail = _probe_version(resolved)
    if ok:
        return _make_check(cid, name, 'pass', detail, evidence)
    return _make_check(cid, name, 'warn',
                       '%s --version %s' % (binary, detail), evidence)


def _check_cli_harnesses(ctx, allow_subprocess) -> list:
    """RT-CLI checks for every harness with an existing home marker
    (an installation in the user home)."""
    checks = []
    for adapter in iter_adapters():
        try:
            markers = adapter.home_markers(ctx)
        except OSError:
            markers = []
        hits = [p for p in markers if _exists(p)]
        if hits:
            checks.append(_check_cli(adapter, hits, allow_subprocess))
    return checks


# --- RT-MCP-CONFIG: MCP config structure (offline) --------------------------


def _detected_adapters(ctx) -> list:
    """Adapters with at least one existing project marker (the same
    signal detection.py treats as 'detected')."""
    out = []
    for adapter in iter_adapters():
        markers = adapter.project_markers(ctx)
        if any(_exists(ctx.root_path(m)) for m in markers):
            out.append(adapter)
    return out


def _find_mcp_section(data, path):
    """Locate the MCP server map inside a parsed config. Returns
    (section_name, mapping) or None. Structure only -- endpoints are
    never contacted."""
    if path.name in MCP_MAP_FILENAMES:
        return 'top-level server map', data
    for key in MCP_SECTION_KEYS:
        value = data.get(key)
        if isinstance(value, dict):
            # Z Code nests one level deeper: {"mcp": {"servers": {..}}}
            if key == 'mcp' and isinstance(value.get('servers'), dict):
                return 'mcp.servers', value['servers']
            return key, value
    return None


def _load_structured(path):
    """Read and parse one JSON/TOML config file. Returns (verdict,
    detail, data): verdict in ok | fail | unknown, data is the parsed
    top-level object when ok (else None). Structure only -- values
    inside are never contacted or executed."""
    suffix = path.suffix.lower()
    try:
        raw = path.read_text(encoding='utf-8')
    except OSError as exc:
        return 'fail', 'unreadable: %s' % exc, None
    except UnicodeDecodeError:
        return 'fail', 'not valid UTF-8', None
    if suffix == '.json':
        try:
            data = json.loads(raw)
        except ValueError as exc:
            return 'fail', 'invalid JSON: %s' % exc, None
    elif suffix == '.toml':
        if tomllib is None:
            return 'unknown', (
                'TOML support needs Python 3.11+ (tomllib); running '
                '%d.%d' % sys.version_info[:2]), None
        try:
            data = tomllib.loads(raw)
        except ValueError as exc:    # tomllib.TOMLDecodeError
            return 'fail', 'invalid TOML: %s' % exc, None
    else:
        return 'unknown', 'unsupported extension %r (expected .json ' \
                         'or .toml)' % suffix, None
    if not isinstance(data, dict):
        return 'fail', 'top-level is %s, expected an object' \
            % type(data).__name__, None
    return 'ok', 'parses', data


def _parse_mcp_config(path):
    """Validate one MCP config file offline: extension-based parse,
    then the MCP section must be an object. Returns (verdict, detail)
    with verdict in ok | fail | unknown."""
    verdict, detail, data = _load_structured(path)
    if verdict != 'ok':
        return verdict, detail
    section = _find_mcp_section(data, path)
    if section is None:
        return 'ok', 'parses; no MCP section (MCP likely not configured)'
    sec_name, servers = section
    return 'ok', "'%s' section present (%d entries)" % (sec_name,
                                                        len(servers))


def _check_mcp_config(ctx) -> dict:
    detected = _detected_adapters(ctx)
    if not detected:
        return _make_check(
            'RT-MCP-CONFIG', 'MCP config structure', 'not_applicable',
            'no harnesses detected at project level; nothing to check',
            [])
    evidence = []
    verdicts = []
    for adapter in detected:
        try:
            files = adapter.mcp_config_files(ctx)
        except OSError:
            files = []
        for cfg in files:
            verdict, detail = _parse_mcp_config(cfg)
            verdicts.append(verdict)
            evidence.append('%s: %s: %s'
                            % (adapter.harness_id, cfg, detail))
    if not verdicts:
        return _make_check(
            'RT-MCP-CONFIG', 'MCP config structure', 'pass',
            'no MCP config files for detected harnesses (%s)'
            % ', '.join(a.harness_id for a in detected), evidence)
    if 'fail' in verdicts:
        return _make_check(
            'RT-MCP-CONFIG', 'MCP config structure', 'fail',
            '%d of %d MCP config file(s) invalid'
            % (verdicts.count('fail'), len(verdicts)), evidence)
    if 'unknown' in verdicts:
        return _make_check(
            'RT-MCP-CONFIG', 'MCP config structure', 'unknown',
            '%d of %d MCP config file(s) could not be verified'
            % (verdicts.count('unknown'), len(verdicts)), evidence)
    return _make_check(
        'RT-MCP-CONFIG', 'MCP config structure', 'pass',
        '%d MCP config file(s) parse and carry a valid structure'
        % len(verdicts), evidence)


# --- RT-PATH: PATH sanity ---------------------------------------------------


def _check_path() -> dict:
    raw = os.environ.get('PATH', '')
    if not raw.strip():
        return _make_check(
            'RT-PATH', 'PATH environment', 'fail',
            'PATH environment variable is empty or unset', [])
    entries = [e for e in raw.split(os.pathsep) if e.strip()]
    evidence = ['%d non-empty PATH entries' % len(entries)]
    status, detail = 'pass', 'PATH ok (%d entries)' % len(entries)
    if os.pathsep not in raw:
        status = 'warn'
        detail = ("PATH has a single entry (no '%s' separators); "
                  'unusual but not fatal' % os.pathsep)
    git = shutil.which('git')
    if git:
        git_dir = Path(git).parent
        if _dir_exists(git_dir):
            evidence.append('git directory: %s' % git_dir)
        else:
            status = 'warn'
            detail = ('git resolves to %s but its directory does not '
                      'exist' % git)
            evidence.append('missing git directory: %s' % git_dir)
    else:
        evidence.append('git not on PATH (see RT-GIT)')
    return _make_check('RT-PATH', 'PATH environment', status, detail,
                       evidence)


# --- RT-LOCK-DIR: stale trash locks -----------------------------------------


def _check_lock_dir(ctx) -> dict:
    trash = ctx.root_path(TRASH_DIR_NAME)
    if not _exists(trash):
        return _make_check(
            'RT-LOCK-DIR', 'trash lock directory', 'pass',
            'no %s directory in the workspace' % TRASH_DIR_NAME, [])
    try:
        locks = sorted(trash.rglob('*.lock'))
    except OSError as exc:
        return _make_check(
            'RT-LOCK-DIR', 'trash lock directory', 'unknown',
            'cannot scan %s: %s' % (trash, exc), [str(trash)])
    if not locks:
        return _make_check(
            'RT-LOCK-DIR', 'trash lock directory', 'pass',
            '%s present, no .lock files' % TRASH_DIR_NAME, [str(trash)])
    now = time.time()
    stale = []
    for lock in locks:
        try:
            age = now - lock.stat().st_mtime
        except OSError as exc:
            return _make_check(
                'RT-LOCK-DIR', 'trash lock directory', 'unknown',
                'cannot stat %s: %s' % (lock, exc), [str(lock)])
        if age > STALE_LOCK_SECONDS:
            stale.append('%s (idle for %.0f minutes)'
                         % (lock.name, age / 60.0))
    if stale:
        return _make_check(
            'RT-LOCK-DIR', 'trash lock directory', 'warn',
            'stale lock file(s) older than %d minutes: %s'
            % (STALE_LOCK_SECONDS // 60, '; '.join(stale)),
            [str(l) for l in locks])
    return _make_check(
        'RT-LOCK-DIR', 'trash lock directory', 'pass',
        '%d lock file(s), all younger than %d minutes'
        % (len(locks), STALE_LOCK_SECONDS // 60),
        [str(l) for l in locks])


# --- RT-SKILLS-VERSIONS / RT-SKILLS-CONFLICTS: skill inventory ---------------

_FRONTMATTER_VERSION_RE = re.compile(r'^version:\s*["\']?(.+?)["\']?\s*$',
                                     re.M)


def _json_version(path):
    """'version' field of a JSON manifest, or None. A manifest that
    fails to parse or carries no version simply has no version."""
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    version = data.get('version')
    if isinstance(version, str) and version.strip():
        return version.strip()
    return None


def _frontmatter_version(path):
    """version: field of a SKILL.md YAML frontmatter block, if any.
    Only the first 4 KB are read; a missing field is not an error."""
    try:
        with path.open('r', encoding='utf-8', errors='replace') as fh:
            chunk = fh.read(4096)
    except OSError:
        return None
    if not chunk.startswith('---'):
        return None
    end = chunk.find('\n---', 3)
    block = chunk[:end] if end != -1 else chunk
    match = _FRONTMATTER_VERSION_RE.search(block)
    return match.group(1) if match else None


def _skill_dir_version(skill_dir):
    """Best-effort version of one skill directory. Returns (version,
    source): source names the file the answer came from (or the file
    that exists but carries no version). (None, None) means none of
    the known files is present -- a container directory (e.g. the
    marketplace level of a plugin cache), not a skill."""
    for name in SKILL_MANIFEST_FILES:
        manifest = skill_dir / name
        if _exists(manifest):
            return _json_version(manifest), name
    skill_md = skill_dir / 'SKILL.md'
    if _exists(skill_md):
        return _frontmatter_version(skill_md), 'SKILL.md'
    return None, None


def _skill_inventory(ctx):
    """Version inventory over the skills_locations() of the detected
    adapters: one entry per <location>/<name> directory that looks
    like a skill. Returns {adapters, entries, capped}; each entry is
    {harness, skill, location, version, source}."""
    detected = _detected_adapters(ctx)

    def result(capped):
        return {'adapters': len(detected), 'entries': entries,
                'capped': capped}

    entries = []
    for adapter in detected:
        try:
            locations = adapter.skills_locations(ctx)
        except OSError:
            continue
        for loc in locations:
            if not _dir_exists(loc):
                continue
            try:
                children = sorted(loc.iterdir())
            except OSError:
                continue
            for child in children:
                if len(entries) >= SKILLS_INVENTORY_CAP:
                    return result(True)
                if not _dir_exists(child):
                    continue
                version, source = _skill_dir_version(child)
                if source is None:
                    continue           # container dir, not a skill
                entries.append({
                    'harness': adapter.harness_id,
                    'skill': child.name,
                    'location': str(loc),
                    'version': version,
                    'source': source,
                })
    return result(False)


def _check_skills_versions(inventory) -> dict:
    """Inventory, not a verdict: always 'pass' when there is something
    to inventory (or nothing to find), never judges the versions."""
    if not inventory['adapters']:
        return _make_check(
            'RT-SKILLS-VERSIONS', 'installed skill versions',
            'not_applicable',
            'no harnesses detected at project level; nothing to '
            'inventory', [])
    entries = inventory['entries']
    if not entries:
        return _make_check(
            'RT-SKILLS-VERSIONS', 'installed skill versions', 'pass',
            'no skills found in the skills locations of the detected '
            'harnesses', [])
    evidence = []
    with_version = 0
    for entry in entries:
        if entry['version']:
            with_version += 1
            evidence.append('%s: %s: %s (%s)'
                            % (entry['harness'], entry['skill'],
                               entry['version'], entry['source']))
        else:
            evidence.append('%s: %s: no version (%s)'
                            % (entry['harness'], entry['skill'],
                               entry['source']))
    detail = ('%d skill(s) inventoried, %d with a version and %d '
              'without' % (len(entries), with_version,
                           len(entries) - with_version))
    if inventory['capped']:
        detail += '; scan capped at %d entries' % SKILLS_INVENTORY_CAP
    return _make_check('RT-SKILLS-VERSIONS', 'installed skill versions',
                       'pass', detail, evidence)


def _check_skills_conflicts(inventory) -> dict:
    if not inventory['adapters']:
        return _make_check(
            'RT-SKILLS-CONFLICTS', 'skill version conflicts',
            'not_applicable',
            'no harnesses detected at project level; nothing to '
            'compare', [])
    entries = inventory['entries']
    if not entries:
        return _make_check(
            'RT-SKILLS-CONFLICTS', 'skill version conflicts',
            'not_applicable',
            'no skills found; no skill names to compare', [])
    by_name = {}
    for entry in entries:
        by_name.setdefault(entry['skill'], []).append(entry)
    conflicts = []
    same = []
    for name, group in sorted(by_name.items()):
        # one physical directory read by two harnesses (zcode and
        # codex both scan .agents/skills) is the SAME files -- the
        # conflict signal is distinct location paths; the harnesses
        # still show up in the evidence listing below
        spots = {e['location'] for e in group}
        if len(spots) < 2:
            continue
        versions = {e['version'] for e in group if e['version']}
        listing = '; '.join(
            '%s @ %s: %s' % (e['harness'], e['location'],
                             e['version'] or 'no version')
            for e in group)
        if len(versions) > 1:
            conflicts.append('%s: %s' % (name, listing))
        else:
            same.append('%s: %s' % (name, listing))
    if conflicts:
        return _make_check(
            'RT-SKILLS-CONFLICTS', 'skill version conflicts', 'warn',
            '%d skill name(s) installed with different versions in '
            'different locations' % len(conflicts), conflicts + same)
    if same:
        return _make_check(
            'RT-SKILLS-CONFLICTS', 'skill version conflicts', 'pass',
            '%d skill name(s) appear in several locations with the '
            'same (or unknown) version' % len(same), same)
    return _make_check(
        'RT-SKILLS-CONFLICTS', 'skill version conflicts', 'pass',
        'no skill name appears in more than one skills location', [])


# --- RT-PLUGIN-FRESHNESS: plugin cache mtimes --------------------------------


def _check_plugin_freshness(home_path) -> dict:
    """mtimes of the CLI-managed plugin caches. Informational by
    design: an untouched plugin is listed in the evidence, never
    warned about."""
    plugin_dirs = []
    scanned = []
    for harness_id, parts in PLUGIN_CACHE_ROOTS:
        cache = home_path.joinpath(*parts)
        if not _dir_exists(cache):
            continue
        scanned.append('%s: %s' % (harness_id, cache))
        try:
            markets = sorted(cache.iterdir())
        except OSError:
            continue
        for market in markets:
            if not _dir_exists(market):
                continue
            try:
                plugs = sorted(market.iterdir())
            except OSError:
                continue
            for plug in plugs:
                if _dir_exists(plug):
                    plugin_dirs.append((harness_id, plug))
    if not scanned:
        roots = ', '.join('~/%s' % '/'.join(p) for _, p in
                          PLUGIN_CACHE_ROOTS)
        return _make_check(
            'RT-PLUGIN-FRESHNESS', 'plugin cache freshness',
            'not_applicable',
            'no plugin cache directories (%s)' % roots, [])
    if not plugin_dirs:
        return _make_check(
            'RT-PLUGIN-FRESHNESS', 'plugin cache freshness',
            'not_applicable', 'plugin cache present but empty', scanned)
    now = time.time()
    old = []
    stat_errors = []
    for harness_id, plug in plugin_dirs:
        try:
            age = now - plug.stat().st_mtime
        except OSError as exc:
            stat_errors.append('cannot stat %s: %s' % (plug, exc))
            continue
        if age > PLUGIN_FRESHNESS_SECONDS:
            old.append('%s: %s (%d days since last change)'
                       % (harness_id, plug, int(age // 86400)))
    evidence = list(scanned)
    if old:
        evidence.extend(old)
        detail = ('%d of %d plugin dir(s) untouched for over %d days '
                  '(informational: installed plugins need no '
                  'scheduled updates)'
                  % (len(old), len(plugin_dirs), PLUGIN_FRESHNESS_DAYS))
    else:
        evidence.append('all %d plugin dir(s) modified within the last '
                        '%d days' % (len(plugin_dirs),
                                     PLUGIN_FRESHNESS_DAYS))
        detail = ('%d plugin dir(s) in cache, all modified within %d '
                  'days' % (len(plugin_dirs), PLUGIN_FRESHNESS_DAYS))
    evidence.extend(stat_errors)
    return _make_check('RT-PLUGIN-FRESHNESS', 'plugin cache freshness',
                       'pass', detail, evidence)


# --- RT-MCP-COMMANDS: stdio server commands on PATH --------------------------


def _check_mcp_commands(root_path, home_path) -> dict:
    """For every stdio MCP server of the detected harnesses: is the
    command itself on PATH? Presence only (shutil.which) -- nothing is
    executed. Only the command token from the secret-free inventory is
    used; env names and values never reach this check."""
    inventory = mcp_inventory.collect_mcp_inventory(root_path, home_path)
    servers = inventory['servers']
    if not servers:
        detail = ('no MCP servers configured for the detected '
                  'harnesses')
        if inventory['parse_errors']:
            detail += ('; %d config file(s) could not be parsed (see '
                       'RT-MCP-CONFIG)' % len(inventory['parse_errors']))
        return _make_check(
            'RT-MCP-COMMANDS', 'MCP server commands on PATH',
            'not_applicable', detail, [])
    stdio = [s for s in servers if s.get('transport') == 'stdio']
    if not stdio:
        return _make_check(
            'RT-MCP-COMMANDS', 'MCP server commands on PATH',
            'not_applicable',
            'none of the %d MCP server(s) uses stdio transport; no '
            'commands to check' % len(servers),
            ['%s (%s): http transport, no local command'
             % (s['name'], s['harness'])
             for s in servers if s.get('transport') == 'http'])
    resolved_lines = []
    missing = []
    for server in stdio:
        label = '%s (%s)' % (server['name'], server['harness'])
        head = server.get('command_head') or []
        if not head:
            missing.append('%s: stdio server with an empty command'
                           % label)
            continue
        binary = head[0]
        found = shutil.which(binary)
        if found:
            resolved_lines.append('%s: %s -> %s'
                                  % (label, binary, found))
        else:
            missing.append("%s: command '%s' not found on PATH"
                           % (label, binary))
    if missing:
        return _make_check(
            'RT-MCP-COMMANDS', 'MCP server commands on PATH', 'warn',
            '%d of %d stdio MCP server command(s) not found on PATH'
            % (len(missing), len(stdio)), missing + resolved_lines)
    return _make_check(
        'RT-MCP-COMMANDS', 'MCP server commands on PATH', 'pass',
        '%d stdio MCP server command(s) resolve on PATH' % len(stdio),
        resolved_lines)


# --- RT-CONFIG-VALIDITY: adapter config files parse --------------------------


def _check_config_validity(ctx) -> dict:
    """Every config file the detected adapters declare must parse as
    JSON or TOML. Structure only -- same core as RT-MCP-CONFIG, minus
    the MCP-section requirement."""
    detected = _detected_adapters(ctx)
    if not detected:
        return _make_check(
            'RT-CONFIG-VALIDITY', 'config file validity',
            'not_applicable',
            'no harnesses detected at project level; nothing to check',
            [])
    verdicts = []
    evidence = []
    for adapter in detected:
        try:
            files = adapter.config_files(ctx)
        except OSError:
            files = []
        for cfg in files:
            verdict, detail, _data = _load_structured(cfg)
            verdicts.append(verdict)
            evidence.append('%s: %s: %s' % (adapter.harness_id, cfg,
                                            detail))
    if not verdicts:
        return _make_check(
            'RT-CONFIG-VALIDITY', 'config file validity', 'pass',
            'no config files for the detected harnesses (%s)'
            % ', '.join(a.harness_id for a in detected), evidence)
    if 'fail' in verdicts:
        return _make_check(
            'RT-CONFIG-VALIDITY', 'config file validity', 'fail',
            '%d of %d config file(s) invalid'
            % (verdicts.count('fail'), len(verdicts)), evidence)
    if 'unknown' in verdicts:
        return _make_check(
            'RT-CONFIG-VALIDITY', 'config file validity', 'unknown',
            '%d of %d config file(s) could not be verified'
            % (verdicts.count('unknown'), len(verdicts)), evidence)
    return _make_check(
        'RT-CONFIG-VALIDITY', 'config file validity', 'pass',
        '%d config file(s) parse cleanly' % len(verdicts), evidence)


# --- public API --------------------------------------------------------------


def check_environment(root, home=None, *, allow_subprocess=True) -> dict:
    """Run every runtime health check.

    root: workspace root (str or Path).
    home: user home override (str or Path); defaults to Path.home().
    allow_subprocess: False forbids even the `<bin> --version` probes;
        binaries are then only checked for presence on PATH.

    Returns {'checks': [{id, name, status, detail, evidence}, ...],
             'summary': {pass, fail, warn, unknown}}.
    """
    root_path = Path(root).resolve()
    home_path = Path(home).resolve() if home is not None else Path.home()
    ctx = HarnessContext(root=root_path, home=home_path)
    checks = [_check_python(), _check_git()]
    checks.extend(_check_cli_harnesses(ctx, allow_subprocess))
    checks.append(_check_mcp_config(ctx))
    checks.append(_check_path())
    checks.append(_check_lock_dir(ctx))
    skill_inventory = _skill_inventory(ctx)
    checks.append(_check_skills_versions(skill_inventory))
    checks.append(_check_skills_conflicts(skill_inventory))
    checks.append(_check_plugin_freshness(home_path))
    checks.append(_check_mcp_commands(root_path, home_path))
    checks.append(_check_config_validity(ctx))
    summary = {s: 0 for s in SUMMARY_STATUSES}
    for check in checks:
        if check['status'] in summary:
            summary[check['status']] += 1
    return {'checks': checks, 'summary': summary}


def _main(argv=None) -> int:
    import argparse
    parser = argparse.ArgumentParser(
        description='Agent runtime environment health check '
                    '(opt-in, offline, read-only)')
    parser.add_argument('root', nargs='?', default='.',
                        help='workspace root (default: current directory)')
    parser.add_argument('--home', default=None,
                        help='override the user home directory')
    parser.add_argument('--no-subprocess', action='store_true',
                        help='skip `<bin> --version` probes entirely')
    args = parser.parse_args(argv)
    report = check_environment(args.root, args.home,
                               allow_subprocess=not args.no_subprocess)
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 1 if report['summary']['fail'] else 0


if __name__ == '__main__':
    raise SystemExit(_main())
