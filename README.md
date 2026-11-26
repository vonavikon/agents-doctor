# agents-doctor

<p align="center">
  <img src="docs/logo-rounded.png" alt="agents-doctor logo" width="120" height="120">
</p>

**Doctor for AI agent workspaces.** Checks AGENTS.md health, finds leaked secrets, cleans junk, and tells you what it costs you — in plain language (EN/RU). Understands eight harnesses (Claude Code, Codex, Cursor, Gemini CLI, OpenCode, GitHub Copilot, Windsurf, Z Code), simulates which instructions actually load, detects conflicts between them, ships a local visual explorer — and since 2.1 enforces YAML security policies, keeps a local audit history, watches configuration changes and gates CI. Works standalone or through your agent. Read-only by default; cleanup is explicit, recoverable, and never automatic.

## Privacy model

**Scanner and CLI reports: fully local.** The scanner, Markdown reports, human-readable reports, SARIF export, and baseline comparison run entirely on your machine. No network requests, no API keys required, no telemetry.

**LLM interpretation: depends on your AI harness.** If you use agents-doctor through Claude Code, Z Code, or another AI harness, the harness's language model sees the scan results (paths, gate statuses, findings, masked secret metadata) as part of its context. This is the same data the model would see from any skill or command you run. The scanner itself never sends data anywhere — the LLM sees only what your harness chooses to share.

What the LLM can see from scan results:
- file paths (relative to your workspace)
- repository names and remote classifications
- gate statuses and findings
- masked secret metadata (kind, fingerprint — never the actual value)
- configuration file names and parse status
- skill names and health indicators

What the LLM never sees:
- actual secret values (redacted at source, before any output)
- file contents (only metadata and findings)
- your OS username (stripped from reports)
- network traffic (scanner makes zero HTTP requests)

**No-network verification:** run the scanner standalone with `--out scan.json` — use a network monitor to confirm zero outbound connections.

## How it works

Two layers, three planes:

1. A deterministic scanner, `audit_scan.py`: pure Python stdlib, no dependencies, offline, about 0.5 s on a mid-size folder on a warm cache. It walks the workspace and writes JSON.
2. The skill orchestrator: runs one audit command and reads the short digest it prints (gate statuses with reasons, the findings that matter with their file and line, where to start). It never opens the scan JSON and writes the chat answer in plain words, in the user's language. The reports are written by the tool itself: a plain-language report for people and a technical one.

Inside the deterministic layer:

- **Harness intelligence** — a registry of adapters, one per environment. Each adapter knows its markers, instruction-loading rules, config files and structure expectations, and feeds the same nine gates ([adapter guide](docs/ADAPTER-GUIDE.md), [support matrix](docs/HARNESS-MATRIX.md)). Detection is honest: a marker plus recent activity reads as detected; one stale file reads as possible, never as proof of use.
- **Instruction intelligence** — `simulate` shows which instruction files each harness would actually load for a directory (a model of the documented rules, labelled as such), what stays unloaded and why, and where two active sources contradict each other. Cross-harness differences are reported as divergence (warn), never as errors — they may be intentional.
- **Local web UI** — `agents_doctor.py ui` opens a visual explorer on 127.0.0.1: overview, lazy file tree with per-directory problem counts, findings table, masked file previews, TreeMap, instruction simulation and scan comparison. Read-only; fixes are planned there and applied only via the CLI.

The scanner only reads. Deletions and edits always stay with the human.

Since 2.1 there are four more planes, all optional and all offline:

- **Policy engine** — corporate YAML policies (secrets, MCP allowlists, required instructions, dangerous permissions, banned content patterns) evaluated deterministically over a finished scan. Policy packs distribute through installed plugins; team/local files layer on top; exceptions carry a written reason. [Policies](docs/policies.md).
- **Audit history** — every audit lands in a root-local SQLite database: trends, diffs between any two scans, regression detection (severity up or pass→fail). [History](docs/history.md).
- **Continuous monitoring** — `watch` re-audits when the configuration fingerprint changes (polling, `--once` for cron); new findings print, history accumulates.
- **CI gating** — `audit --fail-on critical` exits 1 at/above the threshold; a ready-made [GitHub Action](docs/ci-integration.md), pre-commit hooks and GitLab/Jenkins recipes.

## Security model

- Secret detection and redaction live in one module, `secret_scanner.py`: raw values never leave it. Every finding carries only the file, line, kind, confidence, a rule-derived mask and a salted one-way fingerprint.
- Worktree files, staged changes, tracked files and (with `--deep`) git history all go through the same redaction path. A regression suite plants canary secrets and asserts they appear in no artifact: report JSON, stdout or stderr.
- Filesystem boundary: file and directory symlinks pointing outside the workspace root are skipped and counted in `stats.skipped_symlinks_outside`.
- Git runs with `GIT_OPTIONAL_LOCKS=0`: the audit cannot refresh or modify the index.
- The scanner writes exactly one file: the report path passed via `--out`.
- Git remote URLs are sanitized at the source: userinfo and credential query parameters never reach any artifact; detection happens on the raw value before it is dropped.
- Fingerprints are HMAC-SHA256 with a per-installation key stored under your user config dir (never in reports, never sent to a model; `python skills/agents-doctor/scripts/fingerprint.py --check` verifies it). Older baselines will show a one-time all-new/all-resolved diff after the format change.
- Deep history scanning is bounded and honest: `--history-depth N` caps it, `--history-all-refs` widens it, and an incomplete or unrequested history scan reads as `unknown`, never as a pass.

## What it checks

| Block | What it finds |
|---|---|
| Loading chain | which harness is actually used (zcode, claude, codex by freshness); instructions kept for a dead harness |
| Instruction files | dead links, paths and commands; drifted AGENTS.md + CLAUDE.md pairs; generic overview blocks in auto-loaded context |
| Context tax | weight of session files: project file against a 16 KB benchmark, memory index against 24.4 KB / 200 lines |
| Repos and folders | folder classification; remote is external hosting or self-hosted; credentials in URLs; second checkout of the same repo; nested repos |
| Sync mechanics | `.git/hooks` flags (`add -A`, push, secret scan), sync commits in the last 30 days, `.gitignore` |
| Secrets | tokens, passwords, AWS-style keys and private-key headers in files, in the git index, in remote URLs (values redacted to a mask and a salted fingerprint); git history with `--deep` |
| Skills | descriptions over 1024 chars (the skill will not load), descriptions without triggers, drifted copies |
| Hygiene | name-based junk (final/version/copy/old/temp, logs, drafts, `node_modules` and other build dirs, in English and Russian), hash-proven duplicates, files over 5 MB, empty folders |

Everything rolls up into nine gates with four statuses: pass, warn, fail and unknown. Unknown means the check could not run (missing data never reads as a pass). Gates and typed findings are separate: findings carry their own severity (critical/high/medium/low/info) and status. After instruction edits the skill still offers the old ninth-check practice: a before/after measurement of auto-load weight plus a typical task run.

## The nine gates

| # | Gate | What fails it |
|---|---|---|
| 1 | Workspace structure | A drifted AGENTS.md/CLAUDE.md pair at one level; nested repositories warn |
| 2 | Configuration integrity | A config file that does not parse or has duplicate keys; finding no configs at all is a warn |
| 3 | Rules consistency | Dead references and drifted pairs; boilerplate, files over 16 KB and chains over 32 768 bytes warn |
| 4 | Directory ownership and discoverability | A heavy non-build directory outside every git repo; loose top-level folders warn |
| 5 | Skills and agent capabilities | Missing or unparseable frontmatter, descriptions over 1024 chars, diverged copies; trigger-less descriptions warn |
| 6 | Secrets and Git security | Exposed, staged or tracked secrets, credentials in remote URLs; absence of a secret-prevention hook is never a pass |
| 7 | Git hygiene | A tracked file over 5 MB; dirty worktrees, missing .gitignore and duplicate checkouts warn |
| 8 | Agent environment governance | Instructions maintained for a dead harness; duplicate keys in MCP configs |
| 9 | Workspace health and maintainability | Junk plus build artifacts over 500 MB; classified junk, many empty dirs, occasional harnesses and large untracked files warn |

## Limits and thresholds

| Threshold | Value |
|---|---|
| Project instruction file benchmark | 16 KB |
| Memory index | 24.4 KB or 200 lines, whichever comes first |
| AGENTS.md chain budget (root + nested) | 32 768 bytes (Codex truncation) |
| Skill description | 1024 chars |
| Duplicate hash window | 1-50 MB |
| Large file threshold | 5 MB |
| Harness considered abandoned | after 90 days idle |

## Install

Claude Code / Z Code:

```
/plugin marketplace add vonavikon/agents-doctor
/plugin install agents-doctor@agents-doctor
```

Then tell the agent "run a workspace audit" and name a folder if needed.

The scanner also runs standalone, without an agent:

```
python skills/agents-doctor/scripts/audit_scan.py <path> --home <home> --out scan.json
```

Flags:

- `--home` — enables harness, memory and user-skill checks; defaults to the user profile.
- `--deep` — adds secret scanning of git history; slower on large repos.
- `--baseline <old scan.json>` — adds a diff section with new and resolved findings; fingerprints are stable across runs.

As a GitHub Action, inside a CI job ([listed on the GitHub Marketplace](https://github.com/marketplace/actions/agents-doctor-audit)):

```
- uses: actions/checkout@v4
- uses: vonavikon/agents-doctor@v3
  with:
    fail-on: critical
```

## Demo

Builds a synthetic workspace with all the typical problems and runs the scanner over it:

```
python demo/setup_demo.py
python skills/agents-doctor/scripts/audit_scan.py demo/employee-workspace --home demo/fake-home --out demo-scan.json
```

All tokens and hosts in the fixtures are synthetic.

## Report and exports

One command scans the folder, leaves three files in `<root>/.agents-doctor/` and prints the short digest:

```
python skills/agents-doctor/scripts/agents_doctor.py audit <root> --out <root>/.agents-doctor/scan.json \
    --report <root>/.agents-doctor/AUDIT.md --human <root>/.agents-doctor/REPORT.md --lang ru --summary
```

| File | For whom | What it holds |
|---|---|---|
| `REPORT.md` | people who do not work with code | what is wrong in plain words (file, line, what to do), what can be made better, where to start; Russian or English |
| `AUDIT.md` | engineers | executive summary, gate results with the reason wherever a check did not run, every finding with its location and what to do, recommended actions. Sample: [docs/sample-report.md](docs/sample-report.md) |
| `scan.json` | tools | the full scan: facts, nine gates, typed findings. Large, with absolute paths: not meant to be read |

The plain-language report names checks and findings with words instead of codes; every name comes from one glossary ([references/glossary.md](skills/agents-doctor/references/glossary.md)). Samples: [EN](docs/sample-human-report.md), [RU](docs/sample-human-report.ru.md).

```
python skills/agents-doctor/scripts/report_generator.py <scan.json> --out AUDIT.md
python skills/agents-doctor/scripts/report_human.py <scan.json> --lang ru [--after <scan2.json>]
python skills/agents-doctor/scripts/sarif.py <scan.json> --out report.sarif
python skills/agents-doctor/scripts/agents_doctor.py --help
```

`sarif.py` writes SARIF 2.1.0 for CI integrations (one rule per gate, one result per fail/warn finding, stable fingerprints). `agents_doctor.py` is the single entry point: `audit --focus security|structure|agents`, `summary <scan.json>` (the digest of a finished scan), `compare` (NEW/RESOLVED/PERSISTING/CHANGED against a baseline), `explain <fid>` (a short card: what, where, what to do), `fix <fid>` — plan-only by default — plus `simulate <root>` (instruction loading per harness) and `ui` (local visual explorer).

And for people who do not want to read reports at all, the safe-cleanup wizard tidies up with near-zero risk: a plain-word preview, a typed YES, everything recoverable:

```
python skills/agents-doctor/scripts/safe_clean.py <root>
```

It only touches regenerable caches, empty folders and confirmed junk (aged, untracked, unreferenced, lockfile-backed `node_modules` only); build dirs modified within the last 7 days are skipped as active installs; tracked files, files with keys and anything uncertain are never touched; every movable item goes to `.agents-doctor-trash/` first. Design rationale and sources: [docs/research-human-layer.md](docs/research-human-layer.md).

Remediation is a separate, never-automatic mode (`remediate.py`): it plans a fix, requires an explicit `yes` before `--apply` touches anything, and re-audits afterwards. V1 supports three fix types: removing empty directories, creating a `.gitignore` from the template, and moving confirmed junk into `.agents-doctor-trash/`.

## Documentation

[Quick start](docs/quickstart.md) · [Architecture](docs/architecture.md) · [Gates methodology](docs/gates.md) · [Configuration and exclusions](docs/configuration.md) · [Policies](docs/policies.md) · [Audit history](docs/history.md) · [CI integration](docs/ci-integration.md) · [CLI reference](docs/cli.md) · [Harness support matrix](docs/HARNESS-MATRIX.md) · [Adapter development guide](docs/ADAPTER-GUIDE.md) · [Troubleshooting](docs/troubleshooting.md) · [Contributing](docs/contributing.md) · [Changelog](CHANGELOG.md) · [Release process](RELEASE.md) · [Report JSON schema](docs/schema/report-schema.json)

## QA

```
cd qa && python eval.py
```

Scenario fixtures with expected results locked before the run; the runner compares the scanner's actual JSON against the locked expectations and writes a report. The current numbers live in the generated line below — never edited by hand (`python tools/check_readme_facts.py`, staleness-gated in CI).

<!-- facts-begin -->
**Facts:** 1429 tests · QA eval 267 PASS · deterministic scanner, no dependencies
<!-- facts-end -->

The deterministic core also has a unit and security-regression suite:

```
python -m unittest discover -s tests
```

The suite includes canary-secrets redaction across worktree/staged/tracked/history artifacts, remote-URL sanitization e2e, a read-only git-index check, runtime-path smoke from a foreign cwd, and trash manifest/restore round-trips. Per-module coverage floors are enforced in CI (secret scanner 95%, core modules 90%).

## Methodology

The split is deterministic scan first, LLM interpretation second: the scanner produces facts, and the language model only judges which facts are findings. This mirrors how industry audit tools place the LLM strictly above findings rather than in the collection path, and it follows context-file hygiene research showing that instruction weight and staleness directly affect agent behavior. Details: [docs/methodology.md](docs/methodology.md).

## Limitations

- Reports are in English.
- The LLM layer of the skill is not covered by the QA eval; the eval covers the deterministic core only.
- Remote classification knows only external hosting vs self-hosted; it does not know your organization.
- Skill versions in the CLI plugin cache are not treated as drift: the cache is managed by the CLI.
- Junk heuristics are name-based and bilingual (en/ru); tune expectations accordingly.
- The symlink boundary regression test skips on systems that forbid creating symlinks (Windows without Developer Mode); the boundary guard itself is always active.
- Remediation supports three fix types in v1 (empty dirs, .gitignore template, confirmed junk to trash); everything else reports `unsupported` instead of improvising.

## License

MIT.
