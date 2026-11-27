"""Capability matrix: the per-harness capability statuses, as JSON,
generated from the live adapter registry.

docs/capability-matrix.json is generated, never hand-edited — the
same rule as docs/HARNESS-MATRIX.md. Each row:

    {
      "harness": "zcode",
      "version": "1.0.0",              # adapter_version
      "capabilities": {"detection": "documented", ...},   # 13 keys
      "tested_at": "2026-11-17",       # adapter spec_verified
      "spec_source": ""                # adapter spec_source
    }

CLI (run from skills/agents-doctor/scripts, or with that directory on
PYTHONPATH):

    python -m harness.conformance.matrix            # regenerate
    python -m harness.conformance.matrix --check    # CI staleness gate:
                                                    # exit 1 when the
                                                    # file on disk
                                                    # diverges from the
                                                    # registry
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .. import adapter_ids, iter_adapters
from ..base import CAPABILITY_KEYS, CAPABILITY_STATUSES

REPO_ROOT = Path(__file__).resolve().parents[5]
DEFAULT_PATH = REPO_ROOT / 'docs' / 'capability-matrix.json'


def build_matrix() -> list:
    """Matrix rows from the registry, registration order. Statuses
    come from adapter CAPABILITY_STATUS via spec_info() — absent keys
    read as 'unknown', invalid values are normalised to 'unknown'."""
    rows = []
    for adapter in iter_adapters():
        info = adapter.spec_info()
        rows.append({
            'harness': info['harness_id'],
            'version': info['adapter_version'],
            'capabilities': dict(info['capability_status']),
            'tested_at': info['spec_verified'] or '',
            'spec_source': info['spec_source'] or '',
        })
    return rows


def save(path: Path = None, rows: list = None) -> Path:
    """Write rows as UTF-8 JSON (default: the docs file)."""
    out = Path(path) if path else DEFAULT_PATH
    data = rows if rows is not None else build_matrix()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, indent=2, ensure_ascii=False) + '\n',
                   encoding='utf-8')
    return out


def load(path: Path = None) -> list:
    """Read the matrix file; json.JSONDecodeError propagates — a
    corrupt file is a broken artefact, not an empty matrix."""
    src = Path(path) if path else DEFAULT_PATH
    return json.loads(src.read_text(encoding='utf-8'))


def validate(rows: list) -> bool:
    """Structural rules: every harness is registered, every row lists
    exactly the CAPABILITY_KEYS capabilities, every status is one of
    CAPABILITY_STATUSES. Raises ValueError naming the first problem;
    returns True when the whole matrix passes."""
    if not isinstance(rows, list):
        raise ValueError('matrix must be a list of rows, got %s'
                         % type(rows).__name__)
    known = set(adapter_ids())
    for i, row in enumerate(rows):
        harness = row.get('harness')
        if harness not in known:
            raise ValueError('row %d: harness %r is not in the registry'
                             % (i, harness))
        caps = row.get('capabilities')
        if not isinstance(caps, dict):
            raise ValueError('row %d (%s): capabilities must be a dict'
                             % (i, harness))
        keys = set(caps)
        missing = set(CAPABILITY_KEYS) - keys
        if missing:
            raise ValueError('row %d (%s): missing capabilities: %s'
                             % (i, harness, ', '.join(sorted(missing))))
        extra = keys - set(CAPABILITY_KEYS)
        if extra:
            raise ValueError('row %d (%s): unknown capabilities: %s'
                             % (i, harness, ', '.join(sorted(extra))))
        bad = {k: v for k, v in caps.items()
               if v not in CAPABILITY_STATUSES}
        if bad:
            raise ValueError('row %d (%s): invalid statuses %r '
                             '(allowed: %s)'
                             % (i, harness, bad,
                                ', '.join(CAPABILITY_STATUSES)))
    return True


def check(path: Path = None) -> int:
    """Staleness gate: 0 when the file on disk matches the registry
    (and passes validate), 1 otherwise."""
    src = Path(path) if path else DEFAULT_PATH
    if not src.is_file():
        print('STALE: %s does not exist; regenerate it '
              '(python -m harness.conformance.matrix)' % src,
              file=sys.stderr)
        return 1
    try:
        rows = load(src)
        validate(rows)
    except (ValueError, json.JSONDecodeError) as exc:
        print('INVALID: %s: %s' % (src, exc), file=sys.stderr)
        return 1
    if rows != build_matrix():
        print('STALE: %s differs from the adapter registry; '
              'regenerate it (python -m harness.conformance.matrix)'
              % src, file=sys.stderr)
        return 1
    print('OK: capability matrix is current (%d harnesses)' % len(rows))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        description='capability matrix generator / staleness gate')
    ap.add_argument('--check', action='store_true',
                    help='exit 1 when the committed matrix is stale')
    ap.add_argument('--out', default=None,
                    help='write to this path instead of docs/')
    a = ap.parse_args(argv)
    if a.check:
        return check(Path(a.out) if a.out else None)
    out = save(Path(a.out) if a.out else None)
    print('written: %s' % out)
    return 0


if __name__ == '__main__':
    sys.exit(main())
