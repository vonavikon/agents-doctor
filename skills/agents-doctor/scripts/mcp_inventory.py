"""MCP configuration inventory.

Collects every MCP server definition the detected harnesses can load,
through the adapter registry (harness/) — no harness knowledge lives
here. The inventory is designed to be shown and stored, so it never
copies secret material out of the configs:

- env:      only variable NAMES, never values;
- command:  only the first two tokens (executable + first argument);
- url:      only the host part (credentials in userinfo/query dropped).

`suspicious_command` is a deterministic pattern heuristic, NOT a
verdict: it flags server entries that combine env keys with a
pipe-into-interpreter style command (curl|bash, sh -c, python -c, npx)
so a human or the policy engine can look twice. Legitimate setups
match it too.

Deterministic, read-only, no network, no subprocesses.

CLI mini (people and policy engines):
    python mcp_inventory.py <workspace-root> [--home <home>]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from urllib.parse import urlparse

try:
    import tomllib
except ImportError:            # Python < 3.11
    tomllib = None

SCRIPTS = Path(__file__).resolve().parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from harness import HarnessContext, iter_adapters  # noqa: E402

# Substrings matched against the lowercased two-token command head.
# Heuristic input only — see module docstring.
_SUSPICIOUS_PATTERNS = ('curl', 'bash', 'sh -c', 'python -c', 'npx')


def _command_head(command) -> list:
    """First two whitespace tokens of a stdio command; [] otherwise."""
    if not isinstance(command, str):
        return []
    return command.split()[:2]


def _url_host(url) -> str:
    """Host of an http server url; '' when unparseable. Value itself
    (userinfo, query, path) never leaves the config through us."""
    if not isinstance(url, str):
        return ''
    try:
        return urlparse(url).hostname or ''
    except ValueError:
        return ''


def _server_entry(harness_id: str, config_file: Path, name: str,
                  definition) -> dict:
    definition = definition if isinstance(definition, dict) else {}
    command = definition.get('command')
    url = definition.get('url')
    env = definition.get('env')
    env_key_names = sorted(str(k) for k in env) if isinstance(env, dict) \
        else []
    head = _command_head(command)
    transport = 'stdio' if isinstance(command, str) and command \
        else ('http' if isinstance(url, str) and url else 'unknown')
    head_joined = ' '.join(head).lower()
    return {
        'harness': harness_id,
        'config_file': str(config_file),
        'name': str(name),
        'transport': transport,
        'command_head': head,               # stdio: tokens [0] and [1]
        'url_host': _url_host(url) if transport == 'http' else '',
        'has_env_keys': bool(env_key_names),
        'env_key_names': env_key_names,     # NAMES only, never values
        'suspicious_command': bool(
            env_key_names
            and any(p in head_joined for p in _SUSPICIOUS_PATTERNS)),
    }


def _json_servers(data) -> dict:
    """Server table out of a parsed JSON config: mcpServers (Claude,
    Cursor, Gemini, Windsurf, Copilot) or mcp (opencode flat, zcode
    nested under mcp.servers). {} when no table is found."""
    if not isinstance(data, dict):
        return {}
    table = data.get('mcpServers')
    if not isinstance(table, dict):
        mcp = data.get('mcp')
        if isinstance(mcp, dict):
            nested = mcp.get('servers')
            table = nested if isinstance(nested, dict) else mcp
    return table if isinstance(table, dict) else {}


def _collect_file(harness_id: str, path: Path, servers: list,
                  parse_errors: list) -> None:
    try:
        text = path.read_text(encoding='utf-8', errors='replace')
    except OSError as exc:
        parse_errors.append({'file': str(path), 'error': str(exc)})
        return
    suffix = path.suffix.lower()
    if suffix == '.toml':
        if tomllib is None:
            parse_errors.append({'file': str(path),
                                 'error': 'tomllib unavailable '
                                          '(Python < 3.11)'})
            return
        try:
            data = tomllib.loads(text)
        except (tomllib.TOMLDecodeError, ValueError) as exc:
            parse_errors.append({'file': str(path), 'error': str(exc)})
            return
        table = data.get('mcp_servers')    # codex [mcp_servers.NAME]
        if isinstance(table, dict):
            for name, definition in table.items():
                servers.append(_server_entry(harness_id, path, name,
                                             definition))
        return
    if suffix not in ('.json', ''):
        # copilot .github/copilot-mcp.yml, opencode opencode.jsonc, ...:
        # honest parse error, never a silent skip and never a guess
        parse_errors.append({'file': str(path),
                             'error': 'unsupported config format %r '
                                      '(JSON and TOML only)' % suffix})
        return
    try:
        data = json.loads(text)
    except ValueError as exc:
        parse_errors.append({'file': str(path), 'error': str(exc)})
        return
    for name, definition in _json_servers(data).items():
        servers.append(_server_entry(harness_id, path, name, definition))


def collect_mcp_inventory(root, home) -> dict:
    """Inventory of MCP servers across the detected harnesses.

    An adapter participates when at least one of its project markers
    exists in the workspace (same signal the detection engine treats
    as 'detected'); its mcp_config_files() then name the files to read.
    Home-level configs of a detected harness are read too.

    Returns {'servers': [...], 'files_scanned': [...],
             'parse_errors': [{file, error}]} — JSON-serialisable,
    secret-free by construction.
    """
    root = Path(root).resolve()
    home = Path(home) if home is not None else Path.home()
    ctx = HarnessContext(root=root, home=home)
    servers: list = []
    files_scanned: list = []
    parse_errors: list = []
    seen: set = set()
    for adapter in iter_adapters():
        try:
            markers = [m for m in adapter.project_markers(ctx)
                       if ctx.exists(ctx.root_path(m))]
            if not markers:
                continue
            files = adapter.mcp_config_files(ctx)
        except OSError:
            continue               # adapter I/O trouble: skip, no crash
        for path in files:
            key = (adapter.harness_id, str(path))
            if key in seen:
                continue
            seen.add(key)
            # resolved form: CI runners hand out 8.3 short paths
            # that do not string-match the workspace root
            files_scanned.append(str(Path(path).resolve()))
            _collect_file(adapter.harness_id, path, servers, parse_errors)
    return {'servers': servers,
            'files_scanned': files_scanned,
            'parse_errors': parse_errors}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog='mcp_inventory.py',
        description='MCP server inventory of a workspace (secret-free: '
                    'env names, command heads and url hosts only).')
    ap.add_argument('root', help='workspace root to inventory')
    ap.add_argument('--home', default=None,
                    help='user home (default: the real home)')
    a = ap.parse_args(argv)
    root = Path(a.root)
    if not root.is_dir():
        print('not a directory: %s' % root, file=sys.stderr)
        return 2
    inv = collect_mcp_inventory(root, a.home or Path.home())
    print(json.dumps(inv, indent=2, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    sys.exit(main())
