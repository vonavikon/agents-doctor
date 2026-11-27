"""Deterministic instruction-conflict detection.

Three conflict kinds, all evidence-backed and deterministic; the LLM
layer may add semantic analysis on top, never replace this:

- contradiction: a 'do' directive and a 'don't' directive about the
  same topic in two DIFFERENT active sources (single-file pairs are
  content_quality's job). Reuses the content_quality directive
  extractor and the same topic-overlap threshold, so the two layers
  cannot drift apart.
- duplication: a normalized 3-line block that appears verbatim in two
  or more sources (context bloat, drift risk).
- divergence: a contradiction whose sources belong to different
  harnesses. Reported as divergence (warn): differences between
  harnesses may be intentional and are never read as errors
  automatically.
"""
from __future__ import annotations

from pathlib import Path

import content_quality
from .discovery import load_source_text

DUPLICATE_BLOCK_LINES = 3
DUPLICATE_MAX_BLOCKS = 2000   # cap windows hashed per file


def _read_lines(path) -> list:
    text = load_source_text(path)
    if not text:
        return []
    return [{'num': i, 'raw': raw}
            for i, raw in enumerate(text.splitlines(), 1)]


def _directive_conflicts(sources: list) -> list:
    """Positive-vs-negative directive pairs across different files."""
    per_file = []
    for entry in sources:
        lines = _read_lines(entry['path'])
        if not lines:
            continue
        classified = content_quality._classify(
            '\n'.join(l['raw'] for l in lines))
        positives, negatives = content_quality._find_directives(classified)
        per_file.append((entry, positives, negatives))

    found = []
    for i, (a, pos_a, neg_a) in enumerate(per_file):
        for j, (b, pos_b, neg_b) in enumerate(per_file):
            if i >= j:
                continue
            # both polarities: 'do' in a vs 'don't' in b, and the mirror
            for (pos_side, neg_side) in ((pos_a, neg_b), (pos_b, neg_a)):
                flipped = pos_side is pos_b
                for pos_entry, pos_topic in pos_side:
                    pos_words = content_quality._content_words(
                        content_quality._normalize(pos_topic))
                    if not pos_words:
                        continue
                    for neg_entry, neg_topic in neg_side:
                        neg_words = content_quality._content_words(
                            content_quality._normalize(neg_topic))
                        if not neg_words:
                            continue
                        shared = pos_words & neg_words
                        overlap = (len(shared)
                                   / min(len(pos_words), len(neg_words)))
                        if overlap < content_quality.CONTRADICTION_OVERLAP:
                            continue
                        if flipped:
                            fa, la, ta = b['path'], pos_entry['num'], \
                                pos_entry['raw'].strip()
                            fb, lb, tb = a['path'], neg_entry['num'], \
                                neg_entry['raw'].strip()
                        else:
                            fa, la, ta = a['path'], pos_entry['num'], \
                                pos_entry['raw'].strip()
                            fb, lb, tb = b['path'], neg_entry['num'], \
                                neg_entry['raw'].strip()
                        found.append({
                            'kind': 'contradiction',
                            'file_a': fa, 'line_a': la, 'text_a': ta,
                            'file_b': fb, 'line_b': lb, 'text_b': tb,
                            'topic': pos_topic,
                            'harness_a': a['harness'],
                            'harness_b': b['harness'],
                        })
    return found


def _duplicate_blocks(sources: list) -> list:
    """Normalized N-line windows appearing in two or more files."""
    seen = {}    # window key -> first (file, line)
    reported = set()
    found = []
    for entry in sources:
        lines = _read_lines(entry['path'])
        raws = [l['raw'] for l in lines]
        for start in range(0, max(0, len(raws) - DUPLICATE_BLOCK_LINES + 1),
                           1):
            if start >= DUPLICATE_MAX_BLOCKS:
                break
            window = raws[start:start + DUPLICATE_BLOCK_LINES]
            norm = tuple(content_quality._normalize(w) for w in window)
            if not any(norm):
                continue
            key = norm
            if key in seen and seen[key][0] != entry['path']:
                if key not in reported:
                    reported.add(key)
                    found.append({
                        'kind': 'duplication',
                        'file_a': seen[key][0], 'line_a': seen[key][1],
                        'file_b': entry['path'], 'line_b': start + 1,
                        'lines': DUPLICATE_BLOCK_LINES,
                        'preview': ' / '.join(w.strip() for w in window
                                              if w.strip())[:200],
                        'harness_a': seen[key][2],
                        'harness_b': entry['harness'],
                    })
            elif key not in seen:
                seen[key] = (entry['path'], start + 1, entry['harness'])
    return found


def find_conflicts(sources: list) -> list:
    """All deterministic conflicts between instruction sources.

    sources: discovery dicts (harness, path). Sources may be pre-
    filtered to the active set for a target directory by the caller;
    conflicts are always pairwise between different files.
    Returns contradictions and duplications; cross-harness pairs are
    relabelled 'divergence' with the same evidence.

    The same file pair is often loaded by several harnesses at once
    (AGENTS.md is read by zcode AND codex); each (file_a, line_a,
    file_b, line_b) conflict is reported exactly once — the first
    harness attribution wins.
    """
    existing = [s for s in sources if s.get('exists')]
    if len(existing) < 2:
        return []
    conflicts = _directive_conflicts(existing)
    conflicts.extend(_duplicate_blocks(existing))
    for c in conflicts:
        if (c['harness_a'] != c['harness_b']
                and c['kind'] == 'contradiction'):
            c['kind'] = 'divergence'
    seen = set()
    deduped = []
    for c in conflicts:
        key = (c['file_a'], c.get('line_a'), c['file_b'], c.get('line_b'))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(c)
    return deduped


def summarize(conflicts: list) -> dict:
    out = {'contradiction': 0, 'duplication': 0, 'divergence': 0}
    for c in conflicts:
        out[c['kind']] = out.get(c['kind'], 0) + 1
    return out
