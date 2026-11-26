# Harness Adapter Development Guide

An adapter is the single place that knows one AI-agent environment:
its markers, instruction-loading model, config files and structure
expectations. This guide is for adding a new environment to
agents-doctor.

## Where things live

```
skills/agents-doctor/scripts/harness/
├── base.py          the contract (read this first, in full)
├── __init__.py      the registry — import your module here
├── detection.py     multi-harness detection engine
├── collect.py       bridge into the scan pipeline (audit_scan)
├── external.py      opt-in external adapters (TZ section 17)
└── adapters/
    └── <name>.py    one environment per module
```

## Step by step

1. **Create the module** `harness/adapters/<name>.py`, subclass
   `HarnessAdapter`, decorate with `@register`:

```python
from ..base import (AdapterFinding, HarnessAdapter, HarnessContext,
                    InstructionChain, InstructionLink, InstructionSource)
from .. import register


@register
class MyAdapter(HarnessAdapter):
    harness_id = 'my_env'            # registry key, snake_case
    display_name = 'My Environment'
    spec_source = 'https://docs.example.com/agent-config'
    spec_verified = '2026-11-17'     # date YOU last checked the docs
    supported_versions = 'current (unverified)'
    known_limitations = ['...']      # honest list, users read this
```

2. **Detection**: `project_markers()` (relative paths that mark the
   harness inside a project) and `home_markers()` (installation in the
   user home). The detection engine combines them with activity and
   NEVER treats a single file as proof of active use. A marker is a
   fact, not a verdict.

3. **Instructions**: `instruction_sources()` returns every file the
   harness may read (scopes: global, user, project, nested,
   path_scoped, imported). `resolve_chain(ctx, target_dir)` models the
   EFFECTIVE set for one directory: which sources load, in what
   precedence (higher wins), which stay inactive and why (`reason` on
   every inactive link). Follow the documented loading model of YOUR
   harness, not a generic hierarchy. Keep `approximated=True` unless
   you verified against a real runtime.

4. **Capabilities**: `skills_locations()`, `config_files()`,
   `mcp_config_files()`, `context_budget_bytes()` where applicable.

5. **Validation**: `validate(ctx)` returns `AdapterFinding` list with
   STABLE `check_id` (PREFIX_CHECK_NAME, e.g. `MYENV_RULES_GLOB`).
   Findings map into the nine gates by category:
   structure→G1, instructions→G3, config→G2, security→G6,
   compatibility→G8 (mapping lives in `harness/collect.py`).
   Unknown territory yields `status='unknown'`, never a pass.

6. **Plain name**: add every new `check_id` to `ADAPTER_KINDS` in
   `scripts/glossary.py` with a short title and one "what to do"
   sentence in Russian and English, then run
   `python tools/gen_glossary.py`. The digest and both reports name
   findings through the glossary, and `tests/test_glossary.py` fails on
   a check without an entry (and on an entry whose check is gone).

7. **Register the import** in `harness/__init__.py::_ensure_imported`.

8. **Tests**: `tests/test_harness_<name>.py`, unittest, stdlib only,
   Windows-compatible, fixtures in temp dirs. Minimum: registration,
   markers, resolve_chain hierarchy + inactive reasons, every check_id
   positive AND negative (a clean workspace yields zero findings),
   `to_dict()` serializability. A test about redaction, a boundary or a
   read-only guarantee goes to `tests/test_security_regression.py`,
   with canary keys planted (`docs/contributing.md`, "Test placement").

## Rules that keep the system honest

- Evidence always: a finding without evidence is forced to `unknown`
  by the report model.
- Absence of an optional file is never an error by itself.
- Glob semantics: fnmatch + directory-prefix (`src/**` covers `src`
  and everything under it); document the approximation.
- Secrets: never put a realistic token literal in code or tests —
  assemble from pieces (`'xox' + 'b-...'`).
- Version honesty: `detect_version()` returns None rather than a
  guess; `spec_verified` is the date of your last documentation check,
  not the release date of the harness.
- Divergence is not error: differences between harnesses are reported
  as `divergence` (warn), never fail (TZ section 8).

## External adapters (no repo changes needed)

Users can load adapters from explicit paths (never auto-discovered),
via `.agents-doctor.toml`:

```toml
[plugins]
adapters = ["~/audit-adapters/my_env.py"]
```

The module must define `ADAPTERS = [cls, ...]` or export
`HarnessAdapter` subclasses. A broken plugin is isolated and reported;
it cannot crash the scan. See `harness/external.py`.

## Verifying

```
python -m unittest tests.test_harness_<name> -v
python -m unittest discover -s tests -q
python skills/agents-doctor/scripts/agents_doctor.py simulate <ws> --harness <id>
python tools/gen_harness_matrix.py     # regenerates docs/HARNESS-MATRIX.md
```
