"""Instruction discovery across harnesses.

Collects every source the registered adapters declare, reads the text
when needed (size-capped), and keeps the harness attribution: one file
claimed by two harnesses stays two entries.
"""
from __future__ import annotations

from pathlib import Path

from harness import HarnessContext, iter_adapters

MAX_SOURCE_BYTES = 1 << 20   # 1 MiB read cap per instruction file


def discover_all(ctx: HarnessContext, harness_ids=None) -> list:
    """All instruction sources, as flat dicts with harness attribution.

    harness_ids: restrict to these adapters (None = all registered).
    Order is registry order, then path — stable for reports.
    """
    out = []
    for adapter in iter_adapters():
        if harness_ids and adapter.harness_id not in harness_ids:
            continue
        for src in adapter.instruction_sources(ctx):
            out.append({
                'harness': adapter.harness_id,
                'path': str(src.path),
                'scope': src.scope,
                'description': src.description,
                'globs': list(src.globs),
                'always_apply': src.always_apply,
                'exists': ctx.exists(src.path),
            })
    out.sort(key=lambda e: (e['harness'], e['path']))
    return out


def load_source_text(path, cap: int = MAX_SOURCE_BYTES) -> str:
    """Read an instruction file safely; '' when unreadable or too big
    (over-sized sources are reported by their metadata instead)."""
    try:
        if Path(path).stat().st_size > cap:
            return ''
        return Path(path).read_text(encoding='utf-8', errors='replace')
    except OSError:
        return ''


def sources_by_scope(sources: list) -> dict:
    """Count of sources per scope, for overview reports."""
    counts = {}
    for s in sources:
        counts[s['scope']] = counts.get(s['scope'], 0) + 1
    return counts
