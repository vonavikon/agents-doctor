"""Conformance runner: run one adapter against a
fixture workspace and compare the adapter's answers with the
expectations the fixture declares.

A fixture is a directory `tests/conformance/<harness_id>/fixture.py`
next to the repository tests. It builds a throwaway workspace and
declares what the adapter is expected to report for it. Two required
callables:

    build(root, home=None)  -- create the test workspace.
        root: scratch directory playing the workspace being audited.
        home: scratch directory playing the user home, EMPTY unless
        the fixture populates it. Populate it with fixture files
        only: both directories are deleted (or left to the caller)
        after the run — never point them at a real home. Root-only
        fixtures may take just (root).

    expected()  -- check name -> expectation. A check whose name is
        absent is reported as skipped. expected() may also return the
        wrapped form {'status': ..., 'contains': {check: expectation}}
        — the runner unwraps 'contains' and uses it as the mapping.
        Supported checks and expectation shapes:

        detect_project            True | False | [markers] (set match)
                                  | {'status': 'pass'} (some marker
                                  must fire)
                                  | {'status': 'unknown'} (skipped)
        detect_user               same shapes; {'status': 'pass'}
                                  means the (empty) home stays
                                  undetected: no home marker found
        instruction_sources_count int
        resolve_root_loaded       [display paths]     (set match)
        resolve_nested            [display paths] for the nested
                                  target, or {'dir': 'src', ...} /
                                  {'target': 'src', 'loaded': [...]}.
                                  The nested target is the dict
                                  'dir'/'target' value, else the
                                  module-level NESTED_TARGET
                                  constant, else 'src'
        validate_findings         [check_id, ...]  -- subset: every
                                  expected id must appear in
                                  adapter.validate() output

        A display path is a source path relative to root with forward
        slashes; files under home are written as '~/.zcode/AGENTS.md'.
        List comparisons are order-free (sets).

The runner never asserts: it returns a report and the caller (tests,
CI, a human) decides what to do with it.

    from harness.conformance import run_conformance, run_all
    report = run_conformance('zcode')       # one adapter
    reports = run_all()                     # every fixture found

Report shape:

    {
      'harness': 'zcode',
      'checks': [
        {'name': 'resolve_root_loaded',
         'expected': ['AGENTS.md', '~/.zcode/AGENTS.md'],
         'actual':   ['AGENTS.md', '~/.zcode/AGENTS.md'],
         'ok': True,            # None when skipped
         'skipped': False},
        ...
      ],
      'summary': {'total': 6, 'ok': 5, 'failed': 0, 'skipped': 1},
    }
"""
from __future__ import annotations

import importlib.util
import inspect
import tempfile
from pathlib import Path

from .. import get_adapter
from ..base import HarnessContext

# repository root (…/workspace-audit) reached from this file:
# conformance/ harness/ scripts/ agents-doctor/ skills/ <repo>
REPO_ROOT = Path(__file__).resolve().parents[5]
DEFAULT_FIXTURES = REPO_ROOT / 'tests' / 'conformance'

CHECK_NAMES = (
    'detect_project',
    'detect_user',
    'instruction_sources_count',
    'resolve_root_loaded',
    'resolve_nested',
    'validate_findings',
)


# ------------------------------------------------------------- fixture
def fixture_path(harness_id: str, fixtures_root: Path = None) -> Path:
    """Path of the fixture module for a harness (may not exist)."""
    return (fixtures_root or DEFAULT_FIXTURES) / harness_id / 'fixture.py'


def discover_fixtures(fixtures_root: Path = None) -> dict:
    """{harness_id: fixture.py path} for every fixture present."""
    root = fixtures_root or DEFAULT_FIXTURES
    if not root.is_dir():
        return {}
    return {p.parent.name: p for p in sorted(root.glob('*/fixture.py'))}


def load_fixture(harness_id: str, fixtures_root: Path = None):
    """Import the fixture module by file path. Returns the module or
    None when the harness has no fixture."""
    path = fixture_path(harness_id, fixtures_root)
    if not path.is_file():
        return None
    spec = importlib.util.spec_from_file_location(
        'conformance_fixture_%s' % harness_id, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if not callable(getattr(module, 'build', None)) \
            or not callable(getattr(module, 'expected', None)):
        raise ValueError(
            'fixture %s must define callable build() and expected()' % path)
    return module


# ------------------------------------------------------------ helpers
def _display(path, root: Path, home: Path) -> str:
    """Source path as a stable, OS-independent string: relative to root
    when inside it, '~/...' when under home, else the raw path."""
    p = Path(path)
    for base, prefix in ((root, ''), (home, '~/')):
        try:
            rel = p.resolve().relative_to(base.resolve()).as_posix()
        except (ValueError, OSError):
            continue
        return prefix + rel
    return str(p)


def _marker_hits(adapter, ctx: HarnessContext, root: Path, home: Path):
    """(project marker rel-paths found, home marker display paths
    found) — detection by marker existence, as the detection engine
    does it."""
    proj = [m for m in adapter.project_markers(ctx)
            if ctx.exists(root / m)]
    user = [_display(m, root, home) for m in adapter.home_markers(ctx)
            if ctx.exists(m)]
    return proj, user


def _loaded_display(chain, root: Path, home: Path):
    if chain is None:
        return None
    return [_display(l.source.path, root, home) for l in chain.loaded]


def _unwrap_status(expected):
    """expected may wrap a status: {'status': 'pass'|'unknown'}.
    Returns (payload, status) where status is '' for plain forms."""
    if isinstance(expected, dict) and 'status' in expected \
            and set(expected) <= {'status'}:
        return None, expected['status']
    return expected, ''


def _check(name, expected, actual):
    """One check record; comparison rules per runner docstring."""
    record = {'name': name, 'expected': expected, 'actual': actual,
              'ok': None, 'skipped': False}
    if expected is None:
        record['skipped'] = True
        return record
    payload, status = _unwrap_status(expected)
    if status == 'unknown':
        record['skipped'] = True
        return record
    if name in ('detect_project', 'detect_user'):
        if status == 'pass':
            # project: the planted markers must fire; user: the empty
            # home must stay undetected
            ok = bool(actual) if name == 'detect_project' \
                else not actual
        elif isinstance(payload, bool):
            ok = bool(actual) == payload
        elif isinstance(payload, list):
            ok = set(actual) == set(payload)     # marker set match
        else:
            raise ValueError(
                'check %s: expected True | False | marker list | '
                "{'status': ...}, got %r" % (name, expected))
    elif status:
        # status wrappers are only defined for the detect checks
        raise ValueError(
            "check %s: {'status': ...} is only defined for "
            'detect_project / detect_user, got %r' % (name, expected))
    elif name == 'instruction_sources_count':
        ok = actual == payload
    elif name == 'resolve_root_loaded':
        ok = actual is not None and set(actual) == set(payload)
    elif name == 'resolve_nested':
        loaded = (actual or {}).get('loaded')
        ok = loaded is not None and set(loaded) == set(payload['loaded'])
    elif name == 'validate_findings':
        ok = set(payload) <= set(actual or [])     # subset
    else:                                           # unknown check
        ok = False
    record['ok'] = bool(ok)
    return record


# --------------------------------------------------------------- API
def run_conformance(harness_id: str, home: Path = None,
                    fixtures_root: Path = None) -> dict:
    """Build the fixture workspace in scratch directories, ask the
    adapter all conformance questions, compare with expected().

    home — scratch directory standing in for the user home. When None
    a fresh temp directory is created and cleaned up. NEVER pass a
    real home: the fixture writes into it.
    """
    fixture = load_fixture(harness_id, fixtures_root)
    if fixture is None:
        raise ValueError('no conformance fixture for %r at %s'
                         % (harness_id, fixture_path(harness_id,
                                                     fixtures_root)))
    adapter = get_adapter(harness_id)

    own_root = tempfile.TemporaryDirectory(prefix='conf-root-')
    own_home = tempfile.TemporaryDirectory(prefix='conf-home-') \
        if home is None else None
    try:
        root = Path(own_root.name)
        home_dir = Path(own_home.name) if own_home else Path(home)
        params = inspect.signature(fixture.build).parameters
        if len(params) >= 2:
            fixture.build(root, home_dir)
        else:
            fixture.build(root)
        ctx = HarnessContext(root=root, home=home_dir)
        expected = dict(fixture.expected())
        # wrapped form {'status': ..., 'contains': {check: expectation}}
        if isinstance(expected.get('contains'), dict) \
                and not set(expected) - {'status', 'contains'}:
            expected = dict(expected['contains'])

        # nested target: dict form wins, else module NESTED_TARGET,
        # else the plain-list default 'src'
        nested_exp = expected.get('resolve_nested')
        nested_dir = None
        nested_loaded_exp = None
        if isinstance(nested_exp, dict):
            nested_dir = nested_exp.get('dir') or nested_exp.get('target')
            nested_loaded_exp = nested_exp.get('loaded')
        elif isinstance(nested_exp, list):
            nested_dir = getattr(fixture, 'NESTED_TARGET', 'src')
            nested_loaded_exp = nested_exp

        proj_hits, user_hits = _marker_hits(adapter, ctx, root, home_dir)
        chain_root = adapter.resolve_chain(ctx, root)
        chain_nested = None
        if nested_dir:
            chain_nested = adapter.resolve_chain(ctx,
                                                 root / str(nested_dir))
        finding_ids = [f.check_id for f in adapter.validate(ctx)]

        raw = {
            'detect_project': proj_hits,
            'detect_user': user_hits,
            'instruction_sources_count':
                len(adapter.instruction_sources(ctx)),
            'resolve_root_loaded': _loaded_display(chain_root, root,
                                                   home_dir),
            'resolve_nested': (
                {'dir': nested_dir,
                 'loaded': _loaded_display(chain_nested, root, home_dir)}
                if nested_dir else None),
            'validate_findings': finding_ids,
        }
        # normalize the list form of resolve_nested for _check
        if nested_loaded_exp is not None and not isinstance(nested_exp,
                                                            dict):
            expected['resolve_nested'] = {'dir': nested_dir,
                                          'loaded': nested_loaded_exp}
        checks = [_check(name, expected.get(name), raw[name])
                  for name in CHECK_NAMES]
    finally:
        own_root.cleanup()
        if own_home is not None:
            own_home.cleanup()

    summary = {
        'total': len(checks),
        'ok': sum(1 for c in checks if c['ok'] is True),
        'failed': sum(1 for c in checks
                      if not c['skipped'] and c['ok'] is not True),
        'skipped': sum(1 for c in checks if c['skipped']),
    }
    return {'harness': harness_id, 'checks': checks, 'summary': summary}


def run_all(fixtures_root: Path = None) -> dict:
    """Conformance report for every fixture present:
    {harness_id: report}. Adapters without fixtures are simply absent —
    a fixture is the opt-in to conformance testing."""
    return {hid: run_conformance(hid, fixtures_root=fixtures_root)
            for hid in discover_fixtures(fixtures_root)}
