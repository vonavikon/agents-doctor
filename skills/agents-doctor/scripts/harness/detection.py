"""Multi-harness detection engine.

Combines three signals per adapter, in weakening order:
1. project markers — config/instruction files inside the workspace;
2. home markers — an installation in the user home;
3. activity — freshest mtime state from the existing harness_states
   pass (active <=30d, occasional, abandoned >90d).

A single existing file is never proof of active use: 'detected' with
high confidence needs a project marker AND fresh activity. Unknown
territory stays 'possible'/'not_found', never a silent pass.
"""
from __future__ import annotations

from pathlib import Path

from .base import Detection, HarnessContext
from . import iter_adapters

_MARKER_SCAN_LIMIT = 200   # sanity cap: markers checked per adapter


def _exists(path: Path) -> bool:
    try:
        return path.exists()
    except OSError:
        return False


def detect_harnesses(ctx: HarnessContext,
                     activity: dict | None = None) -> dict:
    """Detect every registered harness. Returns {harness_id: Detection}.

    activity: optional {harness_id: {'state': ..., 'confidence': ...}}
    as produced by the enrich pass; missing entries count as unknown.
    """
    activity = activity or {}
    out = {}
    for adapter in iter_adapters():
        markers = [m for m in adapter.project_markers(ctx)
                   if _exists(ctx.root_path(m))][:_MARKER_SCAN_LIMIT]
        home_hits = [p for p in adapter.home_markers(ctx) if _exists(p)]
        act = activity.get(adapter.harness_id, {}) or {}
        act_state = act.get('state', 'unknown')
        version = None
        try:
            version = adapter.detect_version(ctx)
        except OSError:
            version = None

        det = Detection(harness_id=adapter.harness_id,
                        activity=act_state, version=version,
                        markers=markers)

        if markers and act_state == 'active':
            det.status, det.confidence = 'detected', 'high'
            det.evidence.append(
                'project markers: %s; recent activity (<=30d)'
                % ', '.join(markers))
        elif markers:
            det.status, det.confidence = 'detected', 'medium'
            det.evidence.append(
                'project markers: %s; activity %s' % (', '.join(markers),
                                                      act_state))
        elif home_hits and act_state == 'active':
            det.status, det.confidence = 'possible', 'medium'
            det.evidence.append(
                'installed in home (%s) with recent activity, no project '
                'markers' % ', '.join(str(h) for h in home_hits))
        elif home_hits:
            det.status, det.confidence = 'possible', 'low'
            det.evidence.append(
                'installed in home (%s), activity %s, no project markers'
                % (', '.join(str(h) for h in home_hits), act_state))
        else:
            det.evidence.append('no markers found')
        out[adapter.harness_id] = det
    return out


def detection_to_dict(det: Detection) -> dict:
    return {
        'harness': det.harness_id,
        'status': det.status,
        'confidence': det.confidence,
        'activity': det.activity,
        'version': det.version,
        'markers': list(det.markers),
        'evidence': list(det.evidence),
    }
