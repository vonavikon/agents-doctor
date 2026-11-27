#!/usr/bin/env python3
"""Workspace configuration for agents-doctor (.agents-doctor.toml).

A workspace can override three things by dropping a TOML file named
.agents-doctor.toml into its root:

    [exclude]
    directories = ["vendor", "scratch"]
    files = ["legacy-notes.md"]
    rules = ["DIR-002"]

    [thresholds]
    max_file_mb = 5
    junk_fail_gb = 0.5

    [report]
    lang = "en"

Every key is optional and the whole file is optional: a workspace without
one gets DEFAULTS, which match the built-in scanner behaviour. A file that
does not parse, or parses to the wrong shapes, produces a UserWarning and
falls back to the defaults whole -- a broken config must never half-apply.

Excluded paths are not silently ignored: callers report them with the
status 'suppressed' (see status_for) so a reader can tell "checked and
clean" apart from "excluded by request". Matching is exact-string, no
globs: a directory matches any path segment of that name, a file matches
its workspace-relative path or its bare name, a rule matches its finding
id (for example 'DIR-002').

Python 3.11+ parses with tomllib; older interpreters use the fallback
parser below, which understands the subset this format needs: section
headers, full-line comments, and key = value with booleans, numbers,
quoted strings and flat arrays of strings/numbers.

Usage:
    from config import load_config, status_for
    cfg = load_config(workspace_root)
    status = status_for('vendor/lib/util.py', cfg)   # 'suppressed' or 'pass'
"""
import copy
import warnings
from pathlib import Path

__all__ = ['DEFAULTS', 'CONFIG_NAME', 'load_config', 'is_excluded',
           'status_for', 'is_rule_excluded']

CONFIG_NAME = '.agents-doctor.toml'

DEFAULTS = {
    'exclude': {'directories': [], 'files': [], 'rules': []},
    'thresholds': {'max_file_mb': 5, 'junk_fail_gb': 0.5},
    'report': {'lang': 'en'},
    # explicit opt-in external adapters: paths to python
    # modules; never auto-discovered
    'plugins': {'adapters': []},
    # policy engine (v2.1): rule-id exceptions with reasons; the
    # policy files themselves come from --policy / policy packs
    'policy': {'exceptions': {}, 'files': []},
}

try:
    import tomllib  # Python 3.11+
except ImportError:  # Python 3.9/3.10
    tomllib = None


# --- fallback parser (3.9/3.10) -------------------------------------------------

def _parse_scalar(token):
    """One TOML-ish scalar: bool, int, float or quoted string."""
    token = token.strip()
    if token == 'true':
        return True
    if token == 'false':
        return False
    if len(token) >= 2 and token[0] == token[-1] and token[0] in ('"', "'"):
        return token[1:-1]
    try:
        return int(token)
    except ValueError:
        pass
    try:
        return float(token)
    except ValueError:
        raise ValueError('cannot parse value: %r' % token)


def _split_items(body):
    """Split an array body on commas that are outside quotes."""
    items, buf, quote = [], [], None
    for ch in body:
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
        elif ch in ('"', "'"):
            quote = ch
            buf.append(ch)
        elif ch == ',':
            items.append(''.join(buf))
            buf = []
        else:
            buf.append(ch)
    if buf:
        items.append(''.join(buf))
    return [i for i in (item.strip() for item in items) if i]


def _parse_fallback_toml(text):
    """Parse the subset this config needs. Raises ValueError on anything
    else; the caller turns that into a warning plus defaults."""
    result = {}
    section = result
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        if line.startswith('['):
            if not line.endswith(']'):
                raise ValueError('line %d: unterminated section header' % lineno)
            name = line[1:-1].strip()
            if not name:
                raise ValueError('line %d: bad section name %r' % (lineno, name))
            if '.' in name:
                # dotted subsection: [policy.exceptions] -> nested table
                parent = result
                for part in name.split('.'):
                    if not part:
                        raise ValueError('line %d: bad section name %r'
                                         % (lineno, name))
                    parent = parent.setdefault(part, {})
                section = parent
                continue
            section = result.setdefault(name, {})
            continue
        if '=' not in line:
            raise ValueError('line %d: expected key = value' % lineno)
        key, _, value = line.partition('=')
        key = key.strip()
        if not key:
            raise ValueError('line %d: empty key' % lineno)
        value = value.strip()
        if value.startswith('['):
            if not value.endswith(']'):
                raise ValueError('line %d: unterminated array' % lineno)
            parsed = [_parse_scalar(item)
                      for item in _split_items(value[1:-1])]
        elif value.startswith('{'):
            # inline table: { key = "value", other = "value" } -- used
            # by [policy] exceptions on pythons without tomllib
            if not value.endswith('}'):
                raise ValueError('line %d: unterminated inline table'
                                 % lineno)
            parsed = {}
            for item in _split_items(value[1:-1]):
                if '=' not in item:
                    raise ValueError('line %d: inline table item %r '
                                     'has no =' % (lineno, item.strip()))
                k, _, v = item.partition('=')
                k = k.strip().strip('"').strip("'")
                if not k:
                    raise ValueError('line %d: empty inline key' % lineno)
                parsed[k] = _parse_scalar(v)
        else:
            parsed = _parse_scalar(value)
        section[key] = parsed
    return result


# --- reading and validation ------------------------------------------------------

def _validate(data):
    """Shape-check a parsed config; returns None on success, a message on
    the first problem found. Unknown top-level sections are ignored."""
    problems = []
    exclude = data.get('exclude', {})
    if not isinstance(exclude, dict):
        return "'exclude' must be a table"
    for key in ('directories', 'files', 'rules'):
        value = exclude.get(key, [])
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            problems.append("exclude.%s must be a list of strings" % key)
    thresholds = data.get('thresholds', {})
    if not isinstance(thresholds, dict):
        return "'thresholds' must be a table"
    for key in ('max_file_mb', 'junk_fail_gb'):
        value = thresholds.get(key, DEFAULTS['thresholds'][key])
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            problems.append('thresholds.%s must be a number' % key)
    report = data.get('report', {})
    if not isinstance(report, dict):
        return "'report' must be a table"
    lang = report.get('lang', DEFAULTS['report']['lang'])
    if not isinstance(lang, str):
        problems.append('report.lang must be a string')
    plugins = data.get('plugins', {})
    if not isinstance(plugins, dict):
        return "'plugins' must be a table"
    adapters = plugins.get('adapters', [])
    if not isinstance(adapters, list) or not all(isinstance(v, str) for v in adapters):
        problems.append('plugins.adapters must be a list of strings')
    policy = data.get('policy', {})
    if not isinstance(policy, dict):
        return "'policy' must be a table"
    exceptions = policy.get('exceptions', {})
    if not isinstance(exceptions, dict) or not all(
            isinstance(k, str) and isinstance(v, str)
            for k, v in exceptions.items()):
        problems.append('policy.exceptions must be a map of rule id -> '
                        'reason string')
    files = policy.get('files', [])
    if not isinstance(files, list) or not all(isinstance(v, str) for v in files):
        problems.append('policy.files must be a list of strings')
    return '; '.join(problems) or None


def _merge(data):
    """Deep-merge a validated parsed config over DEFAULTS (fresh copy)."""
    merged = copy.deepcopy(DEFAULTS)
    for key, value in data.get('exclude', {}).items():
        if key in merged['exclude']:
            merged['exclude'][key] = list(value)
    for key, value in data.get('thresholds', {}).items():
        if key in merged['thresholds']:
            merged['thresholds'][key] = value
    for key, value in data.get('report', {}).items():
        if key in merged['report']:
            merged['report'][key] = value
    for key, value in data.get('policy', {}).items():
        if key in merged['policy']:
            merged['policy'][key] = copy.deepcopy(value)
    return merged


def load_config(root):
    """Read <root>/.agents-doctor.toml into a config dict.

    Missing file: DEFAULTS (no warning). Malformed or wrong-shaped file:
    a UserWarning and DEFAULTS, never a partial merge. The returned dict
    is a fresh copy; mutating it cannot poison later calls.
    """
    path = Path(root) / CONFIG_NAME
    try:
        raw = path.read_bytes()
    except OSError:
        return copy.deepcopy(DEFAULTS)

    if tomllib is not None:
        try:
            data = tomllib.loads(raw.decode('utf-8'))
        except (ValueError, UnicodeDecodeError) as exc:
            warnings.warn('%s does not parse (%s); using defaults'
                          % (CONFIG_NAME, exc), UserWarning, stacklevel=2)
            return copy.deepcopy(DEFAULTS)
    else:
        try:
            data = _parse_fallback_toml(raw.decode('utf-8'))
        except (ValueError, UnicodeDecodeError) as exc:
            warnings.warn('%s does not parse (%s); using defaults'
                          % (CONFIG_NAME, exc), UserWarning, stacklevel=2)
            return copy.deepcopy(DEFAULTS)

    problem = _validate(data)
    if problem:
        warnings.warn('%s is malformed (%s); using defaults'
                      % (CONFIG_NAME, problem), UserWarning, stacklevel=2)
        return copy.deepcopy(DEFAULTS)
    return _merge(data)


# --- exclusion semantics ---------------------------------------------------------

def is_excluded(path, config):
    """True when a workspace-relative path hits [exclude].

    directories match any single path segment; files match the whole
    relative path or the bare file name. Exact strings, no globs.
    """
    exclude = (config or DEFAULTS).get('exclude', {})
    dirs = set(exclude.get('directories', []))
    files = set(exclude.get('files', []))
    rel = str(path).replace('\\', '/').strip('/')
    if not rel:
        return False
    parts = rel.split('/')
    if files & {rel, parts[-1]}:
        return True
    return bool(dirs & set(parts))


def status_for(path, config):
    """Verdict for an excluded-or-not path: 'suppressed' when the config
    excludes it, 'pass' when it goes through the normal checks."""
    return 'suppressed' if is_excluded(path, config) else 'pass'


def is_rule_excluded(rule, config):
    """True when a finding id (for example 'DIR-002') is listed in
    [exclude] rules."""
    exclude = (config or DEFAULTS).get('exclude', {})
    return rule in set(exclude.get('rules', []))
