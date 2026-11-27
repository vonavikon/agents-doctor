# Configuration

## Config file

Runtime configuration is CLI flags, per invocation, plus one optional
per-workspace file: `.agents-doctor.toml` in the workspace root. The
scanner sets the one environment variable it needs itself
(`GIT_OPTIONAL_LOCKS=0` for every git call), so the audit cannot refresh
or modify a git index.

The file supports three tables; every key is optional and the whole file
is optional:

```toml
[exclude]
directories = ["vendor", "scratch"]   # match any path segment, exact string
files = ["legacy-notes.md"]           # match the relative path or bare name
rules = ["DIR-002"]                   # finding ids to drop from the report

[thresholds]
max_file_mb = 5                       # tracked files at or over this fail G7
junk_fail_gb = 0.5                    # junk volume that fails G9

[report]
lang = "en"                           # report language ("en" or "ru")
```

Behaviour of the file:

- No file: built-in defaults, which equal the values above. Two audits of
  the same tree give the same verdict.
- Excluded paths are reported with the status `suppressed`, not `pass`:
  a reader can tell "checked and clean" apart from "excluded by request".
- Matching is exact-string, no globs. A directory matches when any single
  path segment equals it; a file matches its workspace-relative path or
  its bare name; a rule matches its finding id.
- A file that does not parse, or parses to the wrong shapes (a string
  where a number belongs, and so on), produces a warning and the defaults
  apply whole: a broken config never half-applies.
- Python 3.11+ parses the file with `tomllib`; on 3.9/3.10 a bundled
  fallback parser covers the same format (section headers, full-line
  `#` comments, booleans, numbers, quoted strings, flat arrays).

The reader lives in `skills/agents-doctor/scripts/config.py`
(`load_config(root)`); see the module docstring for the exact shapes.

A fourth table loads external harness adapters:

```toml
[plugins]
adapters = ["~/audit-adapters/my_env.py"]
```

Paths are explicit and absolute responsibility: agents-doctor never
auto-discovers plugins. Each listed module must define
`ADAPTERS = [cls, ...]` or export `HarnessAdapter` subclasses (see
[ADAPTER-GUIDE.md](ADAPTER-GUIDE.md)). A broken or missing plugin is
skipped with a reason in the scan's `plugins` section; it cannot crash
the audit. The plugin runs with the scanner's own privileges — list
only code you trust.

Optional Python packages change behaviour when present: PyYAML enables
full frontmatter parsing (without it the flat fallback parser reports
unparseable frontmatter as `unknown`, never as ok); jsonschema enables
strict schema validation in `tools/validate_schema.py` (a structural
fallback runs otherwise).

## CLI flags

Scanner (`skills/agents-doctor/scripts/audit_scan.py`):

| Flag | Effect |
|---|---|
| `path` (positional) | Workspace root to audit. |
| `--home <dir>` | Home directory for harness, memory and user-skill checks. Default: the user profile. |
| `--deep` | Also scan git history for secrets. Slower on large repos. |
| `--baseline <scan.json>` | Previous report; adds a `diff` section with new and resolved fingerprinted findings. An unreadable baseline is skipped silently. |
| `--out <file>` | Report path. Default `scan.json`. This is the only file the scanner writes. |
| `--profile` | Per-stage timings to stderr (walk, git, context, enrich, gates). |
| `--history-depth N` / `--history-all-refs` | Bound/widen the deep history scan; incomplete coverage reads as unknown, never pass. |

Command line entry (`skills/agents-doctor/scripts/agents_doctor.py`):

| Subcommand | Flags | Effect |
|---|---|---|
| `audit` | `[path]`, `--focus security\|structure\|agents`, `--report md\|sarif\|both`, `--deep`, `--home <dir>`, `--baseline <scan.json>`, `--out <file>` | Run the scanner and produce the report. `--focus` narrows the report to that gate group (the scan itself stays full). `--report` selects markdown, SARIF or both. |
| `compare` | `<scan.json> --baseline <old scan.json>` | Print the NEW / RESOLVED / PERSISTING / CHANGED diff of fingerprinted findings. |
| `explain` | `<scan.json> <fid>` | Print one typed finding with evidence and recommendation. Exit 2 when the fid does not exist. |
| `fix` | `<scan.json> --fid <fid> [--apply]` | Plan a remediation for one finding. Plan-only by default; `--apply` executes it. Exit 2 when the fid does not exist. |

Exit codes of the command line: 0 success, 1 findings present or a failed
check (where the subcommand expresses one), 2 requested object not found.
See [cli.md](cli.md) for examples.

## Thresholds

All thresholds are constants in code, not options. The gates read them
from `GATE_POLICY` in `skills/agents-doctor/scripts/gates.py`:

| Constant | Value |
|---|---|
| `JUNK_FAIL_BYTES` | 500 MB of junk plus build artifacts (fails G9) |
| `EMPTY_WARN_COUNT` | more than 10 empty dirs warns |
| `TRACKED_BIG_BYTES` | 5 MB, tracked files at or over it fail G7 |
| `DESC_LIMIT` | 1024 chars for skill descriptions |
| `PROJECT_BENCH` | 16 KB project instruction file benchmark |
| `CHAIN_BUDGET` | 32 768 bytes for the root + nested AGENTS.md chain |

A few scanner-side thresholds (memory index 24.4 KB / 200 lines, harness
freshness 30/90 days, duplicate hash window 1-50 MB, heavy directory 1 MB)
live as constants next to their checks in `audit_scan.py` and `enrich.py`.
Changing any threshold is a code change with tests: see
[contributing.md](contributing.md). Two of them -- `max_file_mb`
(`TRACKED_BIG_BYTES`) and `junk_fail_gb` (`JUNK_FAIL_BYTES`) -- can also be
moved per workspace through `.agents-doctor.toml` (see above); every other
threshold is deliberate code, so two audits of the same tree with the same
config give the same verdict.

## Exclusions

Build directories (never treated as content, size counted toward the junk
total): `node_modules`, `__pycache__`, `.venv`, `venv`, `dist`, `build`,
`target`, `.cache`, `.idea`, `.pytest_cache`.

Workspace-requested exclusions (paths reported as `suppressed` rather than
checked) come from the `[exclude]` table of `.agents-doctor.toml`; see the
config file section above.

Junk-name heuristics are bilingual (English and Russian) and match on file
or directory names: temp, office lock files (`~$`), untitled, img_,
screenshot/скриншот, new folder/новая папка, final/финал,
version/версия, copy/копия, backup, old/стар, времен, scratch, draft,
debug, `.bak`, `.log`. A name match is a candidate, not a verdict: the
skill confirms with the user before proposing deletion. Hash-proven
duplicates are only counted inside the 1-50 MB window.

Symlinks pointing outside the workspace root are skipped and never
followed; the count lands in `stats.skipped_symlinks_outside` and the
report says so.

## Trash convention

Remediation (`remediate.py --apply`) never deletes. Files it removes from
the workspace are moved into `.agents-doctor-trash/` under the audited
root, one subdirectory per remediation run. Delete the trash yourself
after checking it; the scanner reports it as a normal directory on the
next run.
