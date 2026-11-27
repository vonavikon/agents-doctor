# CLI reference

All commands run from the repo root. `python` is Python 3.10+; the scanner
modules need nothing beyond the standard library.

## Scanner: audit_scan.py

```
python skills/agents-doctor/scripts/audit_scan.py <path> [--home <dir>]
    [--deep] [--baseline <old scan.json>] [--out <file>]
```

Example:

```
python skills/agents-doctor/scripts/audit_scan.py demo/employee-workspace \
    --home demo/fake-home --out demo-scan.json
```

Writes the JSON report to `--out` (default `scan.json`) and prints a
summary: file and size counts, gate statuses by level, typed finding
counts, skipped symlinks, baseline diff when given.

Exit codes: 0 after writing the report (findings do not change the exit
code), 1 when the root is not a directory or the report cannot be written,
2 on unknown flags. An unreadable `--baseline` file is skipped, not an
error.

## CLI entry: agents_doctor.py

One command over the scanner and all modules.

```
python skills/agents-doctor/scripts/agents_doctor.py audit <path>
    [--focus security|structure|agents]
    [--deep] [--home <dir>] [--baseline <prev.json>]
    [--out scan.json] [--report AUDIT.md] [--human REPORT.md]
    [--lang ru|en] [--sessions N] [--summary] [--runtime]
    [--fail-on critical|high|medium|low|info] [--policy FILE.yml]
```

Runs the scan in-process, writes scan.json, optionally writes a
technical report (`--report`) and the plain-language report for people
who do not work with code (`--human`, in the language of `--lang`,
default English; `--sessions` feeds its monthly token estimate). A
missing output folder is created. `--summary` prints the digest of the
scan: gate statuses with the reason wherever a check did not run, the
findings that matter with their place and what to do, improvement
suggestions, where to start, and the files written. The digest is what
the skill's agent reads; it carries no absolute path and no quoted file
line. `--focus` narrows gates and findings to one group:
security=G6,G7; structure=G1,G4,G9; agents=G2,G3,G5,G8. `--baseline`
adds a diff section (new and resolved findings) by comparing fingerprints
with a previous scan. `--deep` also scans git history for secrets. The
audited folder itself, when it is a git repository, is checked like the
repositories inside it (status, remote, hooks, index, history with
`--deep`); the digest then says so, and suggests keeping `.agents-doctor/`
out of git when it is not. `--runtime` (opt-in) adds runtime checks after the scan: python/git
presence, CLI binaries of detected harnesses (`--version`,
timeout-bounded), static MCP config validation; zero network requests;
the result lands in the `runtime` section of the report.
`--fail-on SEV` (default none — the 2.0.0 exit contract is preserved)
exits 1 after the report is written when findings at or above the
severity have status fail. `--policy f.yml` evaluates policy files and
embeds the compliance report into the scan JSON (`policy_report`). CI
recipes: [ci-integration.md](ci-integration.md).

The one command the skill runs:

```
python skills/agents-doctor/scripts/agents_doctor.py audit <root> \
    --out <root>/.agents-doctor/scan.json \
    --report <root>/.agents-doctor/AUDIT.md \
    --human <root>/.agents-doctor/REPORT.md --lang ru --summary
```

The audit includes the harness registry stage: detection of every
registered environment (Z Code, Claude Code, Codex, Cursor, Gemini CLI,
OpenCode, GitHub Copilot, Windsurf), adapter-specific validation
(`CLAUDE_*`, `CODEX_*`, `CURSOR_*`, ... check ids) and deterministic
instruction conflicts at the workspace root. External adapters are
loaded only from paths listed in `.agents-doctor.toml`
(`[plugins] adapters = [...]`).

```
python skills/agents-doctor/scripts/agents_doctor.py summary <scan.json>
    [--lang ru|en] [--human REPORT.md] [--report AUDIT.md]
```

The digest of a finished scan, the same text `audit --summary` prints.
`--human` and `--report` name the report files written next to the scan
so the digest can point at them.

```
python skills/agents-doctor/scripts/agents_doctor.py explain <scan.json> <fid>
    [--lang ru|en] [--raw]
```

One finding as a short card: what it is, where it sits (relative to the
audited folder), what to do, whether a planned fix exists. `--raw`
prints the full record with its evidence list, as before; the evidence
holds absolute paths and is meant for debugging, not for the user.

```
python skills/agents-doctor/scripts/agents_doctor.py simulate <root>
    [--target <dir>] [--harness <id>] [--home <dir>]
```

Instruction loading simulation: prints, per harness, the effective
instruction set for a target directory — loaded sources with
precedence, overridden/unloaded with reasons, and conflicts. Explicitly
a model: chains follow each harness's documented loading rules, not a
verified runtime.

```
python skills/agents-doctor/scripts/agents_doctor.py ui [root]
    [--scan scan.json] [--baseline old.json] [--home <dir>]
    [--port 8765] [--no-open]
```

Local web UI on 127.0.0.1: workspace overview, lazy file tree with
per-directory problem counts, findings explorer, masked file inspector,
TreeMap (density/risk/size), instruction simulation and scan comparison.
`--baseline` enables the Compare tab. The UI is read-only; fixes are
planned (dry run) and applied only via the CLI. The explorer follows the
appearance of the system, light or dark, and loads nothing from the
network: the font it uses on systems without San Francisco ships with it
(Inter, SIL Open Font License 1.1).

```
python skills/agents-doctor/scripts/agents_doctor.py policy <scan.json>
    [--policy FILE.yml] [--out report.json] [--format json|md]
```

Evaluates corporate policy YAML file(s) against a finished scan and
writes a compliance report. Without `--policy`, policy packs are
discovered in installed plugins (`policies/*.yml`) and workspace-level
`.agents-doctor.toml` `[policy] files`. The exit code is a contract for
CI: 0 the check passed or enforcement is off, 1 a blocking rule fired,
2 a broken or missing policy file, 3 a scan that cannot be read or has
no root, 4 strict enforcement with rules in status unknown. On 0, 1 and
4 the report is written or printed first. An I/O error exits 1, as for
the other subcommands. See [policies.md](policies.md).

```
python skills/agents-doctor/scripts/agents_doctor.py history <root>
    [--last N | --record scan.json | --diff OLD NEW |
     --regressions | --trend | --prune N] [--db PATH] [--out FILE]
```

Local audit history (root-local SQLite, survives restarts): listing,
fingerprint diffs between recorded scans, regression detection
(severity up or pass/warn→fail), CSV trend, retention. Every full
audit records automatically; secret values never enter the database.
See [history.md](history.md).

```
python skills/agents-doctor/scripts/agents_doctor.py watch <root>
    [--interval 10] [--once] [--deep] [--db PATH] [--home <dir>]
```

Continuous monitoring: a configuration fingerprint (instruction and
config files) is polled; on change a full scan re-runs, only NEW
findings print, and the run lands in the history. `--once` is the
daemon-free mode for cron: it rescans only when the fingerprint
stored in `.agents-doctor/watch-state.json` changed.

```
python skills/agents-doctor/scripts/agents_doctor.py sarif <scan.json>
    [--out report.sarif]
```

Converts a scan JSON to SARIF 2.1.0 for CI integrations. One rule per
gate, one result per fail/warn finding, stable fingerprints.

```
python skills/agents-doctor/scripts/agents_doctor.py compare <new.json> <old.json>
```

Prints the fingerprint diff: NEW, RESOLVED, PERSISTING, CHANGED.

```
python skills/agents-doctor/scripts/agents_doctor.py explain <scan.json> <fid>
```

Prints one finding as a short card (what, where, what to do, whether a
planned fix exists); `--raw` prints the full record with its evidence.

```
python skills/agents-doctor/scripts/agents_doctor.py fix <scan.json> <fid> [--apply]
```

Prints the remediation plan. `--apply` executes it after an interactive
confirmation (moves to `.agents-doctor-trash/`, never deletes). Run an
audit again afterwards for the before/after report.

Exit codes: 0 success, 1 error, 2 not found or bad usage.

## Report writer: report_generator.py

```
python skills/agents-doctor/scripts/report_generator.py <scan.json>
    [--out AUDIT.md]
```

Turns a scan JSON into the technical markdown report: gate results with
the reason wherever a check did not run, critical findings, all
findings with their location and what to do, recommended actions. Exit
0 written, 1 bad input.

## Plain-language report: report_human.py

```
python skills/agents-doctor/scripts/report_human.py <scan.json>
    [--lang en|ru] [--sessions 10] [--after <scan2.json>]
    [--out REPORT.md]
```

The report for people who do not work with code. The main problem comes
first with its file and line, then every finding with its place and
what to do, what can be made better (extra tokens at every start,
memory the agent cannot see, junk), and where to start. When a check
could not run, the short version names it in one sentence and a section
of its own gives the reason for each; checks that do not apply stay
out. `--after` adds the before/after section for a scan made after a
cleanup.

## SARIF export: sarif.py

```
python skills/agents-doctor/scripts/sarif.py <scan.json> [--out scan.sarif]
```

Exports findings as SARIF 2.1.0 for code viewers that accept it (GitHub
code scanning, VS Code). Exit 0 written, 1 bad input.

## Remediation: remediate.py

```
python skills/agents-doctor/scripts/remediate.py <scan.json>
    [--fid <fid>] [--apply]
```

Plans remediations for findings with `autofix_available: true` (one, with
`--fid`; all, without). Plan-only unless `--apply` is given; applied moves
go to `.agents-doctor-trash/`. Exit 0 plan ready (or applied), 1 a
planned step failed, 2 fid not found.

## Tools

```
python tools/validate_manifest.py
python tools/validate_schema.py <scan.json>
python tools/check_links.py [root]
python tools/gen_harness_matrix.py [--check]
```

`validate_manifest.py` cross-checks `.claude-plugin/plugin.json` and
`marketplace.json` (names, versions, skill layout). `validate_schema.py`
validates a scan JSON against `docs/schema/report-schema.json` (Draft7
when jsonschema is installed, structural fallback otherwise).
`check_links.py` verifies that local targets of markdown links exist.
`gen_harness_matrix.py` regenerates docs/HARNESS-MATRIX.md from the
adapter registry; `--check` fails when the committed doc is stale.
Exit 0 pass, 1 problems printed, 2 usage error (check_links).

`validate_manifest.py` cross-checks `.claude-plugin/plugin.json` and
`marketplace.json` (names, versions, skill layout). `validate_schema.py`
validates a scan JSON against `docs/schema/report-schema.json` (Draft7
when jsonschema is installed, structural fallback otherwise).
`check_links.py` verifies that local targets of markdown links exist.
Exit 0 pass, 1 problems printed, 2 usage error (check_links).

## Benchmarks

```
python bench/gen_workspace.py bench/work/ws-small --size small
python bench/run_benchmark.py bench/work/ws-small --home bench/work/home \
    --label "local (small)" --max-wall 60
```

The generator builds a deterministic synthetic workspace (small ~800,
medium ~12000, large ~60000 files). The runner appends one row to
`bench/BENCH-<date>.md`; `--max-wall` fails the run past a wall-time cap.
See [bench/README.md](../bench/README.md).

## Secret detection quality benchmark

```
python bench/secret_quality.py [--out bench/SECRET-QUALITY-<date>.md] [-v]
```

Precision / recall / FPR / FNR of the deterministic secret rules over
the labeled corpus (parity corpus + extra true/false shapes), plus a
separately-reported adversarial set (obfuscation, truncation, split
values) that documents expected misses without failing the run. Floors:
precision >= 0.95, recall >= 0.95; exit 1 otherwise (CI-gateable).

## LLM-layer eval

```
python llm-eval/make_fixtures.py --out llm-eval/fixtures/
python llm-eval/grade_report.py AUDIT-2026-11-16.md llm-eval/fixtures/chaos.json
```

Freezes scan fixtures and grades the deterministic part (R1-R4) of a
model-written report; R5-R7 are graded by hand with
[llm-eval/rubric.md](../llm-eval/rubric.md). See
[llm-eval/README.md](../llm-eval/README.md).

## QA eval

```
cd qa && python eval.py
```

Builds the three scenario fixtures, runs the scanner, compares actual JSON
against locked expectations and writes `qa/QA-EVAL-<date>.md`. Exit 0 when
every check passes, 1 otherwise.

## Human layer

- `python skills/agents-doctor/scripts/report_human.py <scan.json> [--lang en|ru] [--sessions 10] [--after <scan2.json>] [--out HUMAN-REPORT.md]` — plain-language value report; `--after` produces the before/after story.
- `python skills/agents-doctor/scripts/safe_clean.py <root> [--home H] [--yes] [--include-cautious] [--max-bytes N]` — guided safe cleanup; interactive typed-YES confirmation, trash-first, exit 0/1/2/3 (see `--help`).
- `python tools/gen_sample_human_report.py` — regenerates the EN/RU sample reports from the chaos fixture.

## Scanner flags added in v0.7.0

- `--profile` — per-stage timings to stderr (walk, git, context, enrich, gates).
- `--history-depth N` — cap the deep history scan per repo; coverage is reported and incomplete scans never read as pass.
- `--history-all-refs` — deep-scan across all refs, not only HEAD.
- `python skills/agents-doctor/scripts/safe_clean.py restore <run_dir> [--root R]` — restore a cleanup session from its manifest (typed YES).
- `python llm-eval/run_eval.py --model offline` — the LLM-layer grading pipeline without network or API keys; `--model <name> --api <base-url> --key-env VAR` runs a real model against the frozen fixtures.
