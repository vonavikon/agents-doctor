"""Bridge between the adapter registry and the scan pipeline.

audit_scan calls collect() once per scan after the enrichment stage:
- runs the detection engine over all registered adapters (activity
  states from the enrich pass feed the confidence);
- runs validate() for every DETECTED harness (status != not_found);
- runs the instruction simulation at the workspace root and converts
  its conflicts into report findings.

Adapter findings keep their stable check_id and gain a report fid
(allocated by the gates engine counter, like every other finding).
The category -> gate/prefix mapping lives here, next to the adapter
contract, so gates.py stays free of harness knowledge.
"""
from __future__ import annotations

from pathlib import Path

from .base import HarnessContext
from .detection import detect_harnesses, detection_to_dict
from . import iter_adapters, spec_matrix

# adapter finding category -> (gate, fid prefix)
CATEGORY_MAP = {
    'structure': ('G1', 'DIR'),
    'instructions': ('G3', 'RUL'),
    'config': ('G2', 'CFG'),
    'security': ('G6', 'SEC'),
    'compatibility': ('G8', 'GOV'),
}

# instruction-conflict severities (G3 rules-consistency policy:
# contradictions fail; divergence is a warn, never an error)
_CONFLICT_STATUS = {
    'contradiction': ('fail', 'high'),
    'divergence': ('warn', 'medium'),
    'duplication': ('warn', 'low'),
}


def collect(root: Path, home: Path, activity: dict | None = None) -> dict:
    """Detection records, spec matrix, adapter findings, conflicts.

    Returns the pieces audit_scan stores in the report:
    {harnesses, spec_matrix, adapter_findings, instruction_conflicts}
    where the two finding lists are report-ready dicts without fid
    (the gates engine allocates ids and validates the shape).
    """
    ctx = HarnessContext(root=Path(root), home=Path(home))
    # external adapters: explicit opt-in via .agents-doctor.toml
    # [plugins] adapters = [...]; loaded before detection, isolated on
    # failure, reported in the load report below
    plugins_loaded = []
    try:
        import config as config_mod
        from . import external
        cfg = config_mod.load_config(root)
        paths = (cfg.get('plugins') or {}).get('adapters') or []
        if paths:
            external.set_external_paths(paths)
            plugins_loaded = external.load_external()
    except Exception:
        plugins_loaded = []
    detections = detect_harnesses(ctx, activity)
    harnesses = [detection_to_dict(d) for d in detections.values()]

    adapter_findings = []
    detected_ids = set()
    for det in detections.values():
        if det.status != 'not_found':
            detected_ids.add(det.harness_id)
    for adapter in iter_adapters():
        if adapter.harness_id not in detected_ids:
            continue
        try:
            found = adapter.validate(ctx)
        except OSError:
            continue   # adapter I/O trouble: skip, never crash the scan
        for af in found:
            gate, prefix = CATEGORY_MAP.get(af.category, ('G8', 'GOV'))
            adapter_findings.append({
                'gate': gate, 'prefix': prefix,
                'category': af.category,
                'severity': af.severity, 'status': af.status,
                'title': af.title, 'description': af.description,
                'evidence': af.evidence,
                'confidence': af.confidence,
                'recommendation': af.recommendation,
                'harness': adapter.harness_id,
                'check_id': af.check_id,
            })

    conflicts = []
    try:
        from instructions import simulate_loading
        sim = simulate_loading(ctx, None, sorted(detected_ids) or None)
        for c in sim.get('conflicts') or []:
            status, severity = _CONFLICT_STATUS.get(
                c.get('kind'), ('warn', 'low'))
            conflicts.append({
                'gate': 'G3', 'prefix': 'RUL', 'category': 'rules',
                'severity': severity, 'status': status,
                'title': 'Instruction %s across sources' % c.get('kind'),
                'description': (
                    '%s: "%s" vs "%s" (topic: %s)'
                    % (c.get('kind'), c.get('text_a', ''),
                       c.get('text_b', ''), c.get('topic', '')))[:500],
                'evidence': [
                    {'file': c.get('file_a'), 'line': c.get('line_a'),
                     'detail': c.get('text_a')},
                    {'file': c.get('file_b'), 'line': c.get('line_b'),
                     'detail': c.get('text_b')}],
                'confidence': 0.7,
                'recommendation': (
                    'Align the two instruction sources, or make the '
                    'difference explicit if it is intentional.'),
                'harness': '%s/%s' % (c.get('harness_a'),
                                      c.get('harness_b')),
                'check_id': 'INSTR_%s' % c.get('kind', '').upper(),
            })
        conflict_summary = sim.get('conflict_summary') or {}
    except Exception:
        conflict_summary = {}

    return {
        'harnesses': harnesses,
        'spec_matrix': spec_matrix(),
        'adapter_findings': adapter_findings,
        'instruction_conflicts': conflicts,
        'conflict_summary': conflict_summary,
        'plugins': plugins_loaded,
    }
