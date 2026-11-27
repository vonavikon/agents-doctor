"""Harness registry.

Single place that knows which adapters exist. Replaces the four
hand-synced harness lists (HARNESS dict in audit_scan.py, project_dirs,
HARNESS_DIRS in enrich.py, _DIR_TO_TOOL in gates.py). Adapters
self-register on import; importing this package imports all adapter
modules.
"""
from __future__ import annotations

from .base import (AdapterFinding, Detection, HarnessAdapter,
                   HarnessContext, InstructionChain, InstructionLink,
                   InstructionSource)

_REGISTRY: dict = {}      # harness_id -> adapter class
_imported = False


def register(cls):
    """Class decorator: put an adapter into the registry."""
    if not cls.harness_id:
        raise ValueError('adapter must set harness_id: %r' % cls)
    _REGISTRY[cls.harness_id] = cls
    return cls


def _ensure_imported():
    global _imported
    if _imported:
        return
    _imported = True
    # import for the registration side effect; keep the list explicit
    from .adapters import (zcode, claude_code, codex, cursor,  # noqa: F401,E402
                          gemini_cli, opencode, github_copilot,
                          windsurf)


def adapter_ids() -> list:
    """Registered harness ids in registration order (stable)."""
    _ensure_imported()
    return list(_REGISTRY)


def get_adapter(harness_id: str) -> HarnessAdapter:
    _ensure_imported()
    return _REGISTRY[harness_id]()


def iter_adapters() -> list:
    """All adapter instances, registration order."""
    _ensure_imported()
    return [cls() for cls in _REGISTRY.values()]


def spec_matrix() -> list:
    """Spec provenance for every registered adapter (Harness Support
    Matrix)."""
    return [a.spec_info() for a in iter_adapters()]


__all__ = [
    'register', 'adapter_ids', 'get_adapter', 'iter_adapters',
    'spec_matrix',
    'HarnessAdapter', 'HarnessContext', 'Detection',
    'InstructionSource', 'InstructionLink', 'InstructionChain',
    'AdapterFinding',
]
