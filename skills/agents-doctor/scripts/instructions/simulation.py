"""Instruction loading simulation.

For a target directory, ask every (or selected) harness adapter to
resolve its instruction chain, then cross-check the loaded sets for
conflicts. The result is explicitly labelled as a model: unless a
harness behaviour was verified against a real runtime, the report
says approximated, not fact.
"""
from __future__ import annotations

from pathlib import Path

from harness import HarnessContext, iter_adapters
from .conflicts import find_conflicts, summarize


def simulate_loading(ctx: HarnessContext,
                     target_dir=None,
                     harness_ids=None) -> dict:
    """Loading simulation report for target_dir (root when None).

    harness_ids: restrict simulation to these adapters (None = all).
    Returns a JSON-ready dict: per-harness chain (loaded, overridden,
    unloaded, conflicts), plus workspace-level conflicts between the
    loaded sources.
    """
    target = Path(target_dir) if target_dir else ctx.root
    try:
        target = target.resolve()
    except OSError:
        pass

    chains = {}
    active_sources = []
    for adapter in iter_adapters():
        if harness_ids and adapter.harness_id not in harness_ids:
            continue
        chain = adapter.resolve_chain(ctx, target)
        if chain is None:
            chains[adapter.harness_id] = {
                'harness': adapter.harness_id,
                'supported': False,
                'reason': 'adapter does not model instruction loading',
            }
            continue
        as_dict = chain.to_dict()
        as_dict['supported'] = True
        chains[adapter.harness_id] = as_dict
        for link in chain.loaded:
            active_sources.append({
                'harness': adapter.harness_id,
                'path': str(link.source.path),
                'exists': ctx.exists(link.source.path),
            })

    conflicts = find_conflicts(active_sources)
    loaded_total = sum(len(c.get('loaded', []))
                       for c in chains.values() if c.get('supported'))
    return {
        'target_dir': str(target),
        'approximated': True,
        'note': ('chains follow each harness documented loading model; '
                 'they are not verified against a live runtime'),
        'harnesses': chains,
        'loaded_sources_total': loaded_total,
        'conflicts': conflicts,
        'conflict_summary': summarize(conflicts),
    }


def format_simulation_text(report: dict) -> str:
    """Plain-text rendering of a simulation report."""
    lines = ['Instruction Loading Simulation', '']
    lines.append('Target: %s' % report['target_dir'])
    if report.get('approximated'):
        lines.append('Mode: model (not runtime-verified)')
    lines.append('')
    for hid, chain in report['harnesses'].items():
        lines.append('%s:' % hid)
        if not chain.get('supported'):
            lines.append('  (not modelled: %s)' % chain.get('reason', ''))
            lines.append('')
            continue
        lines.append('  Loaded:')
        for l in chain.get('loaded', []):
            lines.append('    - %s [%s] prec %d %s'
                         % (l['path'], l['scope'], l['precedence'],
                            l.get('reason', '')))
        over = chain.get('overridden', [])
        if over:
            lines.append('  Overridden/unused:')
            for l in over:
                lines.append('    - %s (%s)' % (l['path'], l.get('reason',
                                                                  '')))
        unloaded = chain.get('unloaded', [])
        if unloaded:
            lines.append('  Unloaded:')
            for u in unloaded:
                lines.append('    - %s (%s)' % (u['path'], u['reason']))
        lines.append('')
    summary = report.get('conflict_summary', {})
    if any(summary.values()):
        lines.append('Warnings:')
        for kind, count in summary.items():
            if count:
                lines.append('  - %d %s(s) detected' % (count, kind))
    else:
        lines.append('Warnings: none')
    return '\n'.join(lines)
