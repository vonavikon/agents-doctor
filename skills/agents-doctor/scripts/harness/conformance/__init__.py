"""Conformance framework: fixtures that pin each adapter's behaviour,
and the capability matrix generated from the registry. See runner.py
for the fixture contract and matrix.py for the JSON matrix and its
staleness gate. matrix is deliberately NOT imported here so that
`python -m harness.conformance.matrix` runs without the package-init
double-import warning."""
from __future__ import annotations

from .runner import (CHECK_NAMES, discover_fixtures, fixture_path,
                     load_fixture, run_all, run_conformance)

__all__ = [
    'run_conformance', 'run_all', 'discover_fixtures', 'load_fixture',
    'fixture_path', 'CHECK_NAMES',
]
