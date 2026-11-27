# Contributing

## Dev setup

Python 3.10 or newer and git. No packages are required to develop; the two
optional extras (PyYAML for full frontmatter parsing, jsonschema for strict
schema validation) change behaviour when present, so install them to test
both paths:

```
pip install pyyaml jsonschema coverage
```

Run the suite before anything else:

```
python -m unittest discover -s tests -v
```

Unit, integration and security-regression tests live together; OS-dependent
tests skip themselves where the platform forbids the setup (symlinks on
Windows without Developer Mode).

## Layout

| Path | Content |
|---|---|
| `skills/agents-doctor/SKILL.md` | The skill: workflow and interpretation rules for the agent. |
| `skills/agents-doctor/scripts/` | Scanner modules: `audit_scan.py`, `secret_scanner.py`, `enrich.py`, `gates.py`, `report_model.py` and the product modules (`report_generator.py`, `sarif.py`, `agents_doctor.py`, `remediate.py`). |
| `tests/` | Unit, integration (`tests/integration/`) and security-regression suites. |
| `qa/` | Scenario eval: fixtures with expectations locked before the run. |
| `bench/` | Synthetic workspace generator and benchmark runner. |
| `llm-eval/` | Frozen fixtures and rubric for the LLM report layer. |
| `tools/` | Validation and maintenance scripts (`validate_manifest.py`, `validate_schema.py`, `check_links.py`). |
| `docs/` | Documentation, including the report JSON schema in `docs/schema/`. |
| `demo/` | Synthetic demo workspace setup. |
| `commands/` | Plugin command definitions. |

## Conventions

- Standard library only in the scanner modules. Optional imports (PyYAML,
  jsonschema, coverage) must degrade the same way in production: honestly
  (unknown, fallback), never silently pass.
- English everywhere: code, comments, reports, commit messages.
- Redaction rules are absolute. Raw secret values never leave
  `secret_scanner.py`; evidence carries paths, line numbers, kinds, masks
  and fingerprints only. A change that moves secret material into any
  output will not be merged, and the canary regression suite rejects it
  before review does.
- Thresholds live in `GATE_POLICY` (`gates.py`) where the gates use them;
  scanner-only constants stay next to their checks. Every threshold change
  updates the affected tests in the same commit.
- Python 3.10 compatibility: no syntax or stdlib use beyond 3.10 (the CI
  matrix includes a 3.10 job).

## Test placement

- Unit tests for a module: `tests/test_<module>.py`.
- Cross-module scanner behavior on synthetic fixtures:
  `tests/integration/` (fixture builders in `tests/integration/fixtures.py`).
- Anything about redaction, boundaries or read-only guarantees:
  `tests/test_security_regression.py`, with canary secrets planted in the
  fixture.
- Docs changes: `tests/test_check_links.py` fails on broken markdown links;
  run `python tools/check_links.py` before committing.

## Coverage expectations

CI fails under 90% for `secret_scanner.py` and under 85% for the
deterministic core overall. Current measured values: 100 and 90. Reproduce
locally the way CI runs it (subprocesses included):

```
COVERAGE_PROCESS_START=$PWD/.coveragerc python -m coverage erase
python -m coverage run -m unittest discover -s tests
python -m coverage run qa/eval.py
python -m coverage combine
python -m coverage report --include='*secret_scanner*' --fail-under=90
python -m coverage report --fail-under=85
```

A drop in coverage is a review blocker even when the suite is green.

## Benchmarks

Performance changes need numbers. Regenerate and compare before and after:

```
python bench/gen_workspace.py bench/work/ws-small --size small
python bench/run_benchmark.py bench/work/ws-small --home bench/work/home --label "before"
```

Commit the new `bench/BENCH-<date>.md` rows with the change. CI enforces
wall-time caps on the small and medium sizes.

## PR checklist

Mirrors CI; run it locally to save a round trip:

- [ ] `python -m unittest discover -s tests` green locally.
- [ ] `ruff check --select E9,F63,F7,F82 .` clean (error-level lint).
- [ ] `python tools/validate_manifest.py` passes (versions bumped in both
      manifests if needed).
- [ ] `python tools/validate_schema.py <a scan json>` passes.
- [ ] `python tools/check_links.py` passes.
- [ ] No secret material in the diff; canary tests still green.
- [ ] Docs updated when behavior changed; CHANGELOG entry under
      Unreleased.
