"""External harness adapters (plugin architecture).

agents-doctor never auto-discovers or auto-runs code: an external
adapter is loaded only from a path the user explicitly listed in
.agents-doctor.toml ([plugins] adapters = [...]) or passed via
set_external_paths(). This is the documented contract:

- each listed file is a python module;
- the module may define ADAPTERS = [cls, ...] or single-class exports
  subclassing harness.base.HarnessAdapter;
- every class is validated (harness_id set, subclass of the contract)
  and registered into the live registry;
- a broken plugin is isolated: it is skipped with a reason in
  load_report(), it can never crash the scan.

There is no versioning sandbox: the plugin runs with the scanner's
own privileges, which is why opt-in is explicit and absolute.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from .base import HarnessAdapter

_external_paths: list = []       # configured paths, for reporting
_load_report: list = []          # what happened on the last load


def set_external_paths(paths):
    """Remember explicit plugin paths (from config/CLI). Must be
    called BEFORE the first registry use to have effect."""
    global _external_paths
    _external_paths = [str(p) for p in paths or []]


def external_paths() -> list:
    return list(_external_paths)


def load_report() -> list:
    """Result of the last load attempt: {path, status, detail}."""
    return list(_load_report)


def load_external(registry_dict=None):
    """Import every configured external adapter module.

    registry_dict: the registry mapping to insert into (defaults to
    harness._REGISTRY). Returns the load report; failures never raise.
    """
    import harness
    reg = registry_dict if registry_dict is not None else harness._REGISTRY
    report = []
    for path_str in _external_paths:
        path = Path(path_str)
        entry = {'path': path_str, 'status': 'ok', 'detail': ''}
        try:
            if not path.is_file():
                entry.update(status='missing',
                             detail='file not found (plugin skipped)')
                report.append(entry)
                continue
            modname = 'agents_doctor_ext_%s' % (
                path.stem.replace('.', '_'))
            spec = importlib.util.spec_from_file_location(modname, path)
            if spec is None or spec.loader is None:
                raise ImportError('cannot load module spec')
            module = importlib.util.module_from_spec(spec)
            sys.modules[modname] = module
            spec.loader.exec_module(module)
            classes = list(getattr(module, 'ADAPTERS', None) or [])
            if not classes:
                # fall back: any HarnessAdapter subclass defined in the
                # module itself (not imported ones)
                classes = [v for v in vars(module).values()
                           if isinstance(v, type)
                           and issubclass(v, HarnessAdapter)
                           and v is not HarnessAdapter
                           and v.__module__ == modname]
            if not classes:
                entry.update(status='no_adapters',
                             detail='module defines no HarnessAdapter')
                report.append(entry)
                continue
            for cls in classes:
                if not getattr(cls, 'harness_id', ''):
                    entry.update(status='invalid',
                                 detail='adapter without harness_id')
                    continue
                if not issubclass(cls, HarnessAdapter):
                    entry.update(status='invalid',
                                 detail='not a HarnessAdapter subclass')
                    continue
                reg[cls.harness_id] = cls
                entry['detail'] += ('%s ' % cls.harness_id)
            entry['detail'] = entry['detail'].strip() or 'no valid adapters'
        except Exception as exc:   # plugin isolation: never propagate
            entry.update(status='error', detail=str(exc)[:200])
        report.append(entry)
    global _load_report
    _load_report = report
    return report
