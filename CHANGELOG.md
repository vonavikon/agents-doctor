# Changelog

All notable changes to agents-doctor are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions
follow semantic versioning.

## [Unreleased]

### Documentation

- `docs/policies.md` is written in English. The gap analysis that planned
  version 2.0 is removed: every item of it has shipped and is documented
  where it lives.
- Comments, docstrings and documentation no longer refer to internal
  planning documents; sample names in the tests and in the examples are
  neutral.
- `docs/cli.md` gives the exit codes of the `policy` command, and
  `docs/policies.md` says before which of them the report is written.

## [3.1.0] - 2026-11-26

Plain-language reports and a check that no longer states what it did
not verify. Backward compatible: the scan keeps its schema (new fields
only) and every old CLI flag works as before.

### Plain-language flow

- One `audit` command writes three files: the scan (`--out`), the
  technical report (`--report`) and the plain-language report for a
  non-technical reader (`--human`, `--lang ru|en`). The plain report
  leads with the key, gives "where" and "what to do" for every finding,
  ends with "where to start", and lists what can be improved.
- `audit --summary` prints a digest of a few kilobytes instead of the
  full scan: gate statuses with reasons, findings with a file alias
  relative to the audited folder, what to do, suggestions, where to
  start. No absolute paths, no quoted file lines, no secrets. The digest
  says whether the audited folder is in git, names every place a step
  applies to, and counts the keys beyond the first ones per file.
- `explain <id>` prints the same short card; `--raw` keeps the full
  record. New `summary` subcommand builds the digest from a finished
  scan.
- `references/glossary.md`: plain names (EN/RU) for every gate, finding
  kind and "not checked" reason. `tools/gen_glossary.py --check` in CI
  keeps it in step with the code.
- Every finding carries a stable `check_id` (the finding type, e.g.
  `SEC_EXPOSED_SECRET`). `fid` stays a per-scan counter and remains the
  id for `explain` and `fix`.
- SKILL.md and the slash command: one command, read the digest, answer
  in the user's language, findings named in words.
- The plain report lists the user's own findings first; findings inside
  installed plugins are counted in one line (before, a broken skill of a
  plugin could be "the main problem"). Keys in files that `.gitignore`
  keeps out are not counted as "left in plain sight": the report names
  them in a line of their own. At most three bullets of one kind are
  spelled out, the rest is a count.

### Correctness

- Broken SKILL.md frontmatter reports the position of the syntax error
  (file, line, the parser's own message) instead of "name and
  description missing". Fields are judged only after a successful
  parse. The user's line text never enters the record or the reports.
- No skill folders or no skills found: gate 5 is `not_applicable` with
  a reason, never `pass`. An unreadable or truncated skill folder makes
  the gate `unknown`. The skill folder cap is 1000 (was 200) and a
  truncated folder is reported.
- Claude Code `@~/` imports resolve against the scanner's `--home`. A
  target outside the audited area is reported as outside
  (`CLAUDE_IMPORT_OUTSIDE`, low severity, unverified), not as missing,
  and is not read.
- A folder without Git: no "install a pre-commit hook" advice, secret
  prevention is `not_applicable`, secrets in files are still reported.
  Repositories nested inside a plain folder are "unverified", not
  "absent".
- The audited folder itself, when it is a git repository (the usual
  project folder), gets its git side read like any other repository:
  status, remote, hooks, index, history with `--deep`. Before, only the
  clones inside it were read, so tracked folders were reported as
  "outside version control", tracked large files as "without backup",
  and the folder's own hooks and uncommitted work were never seen. The
  folder is listed first in `top_level` under the name `.`.
- Repositories deeper than the first level are not read: a clean result
  that leaves them out is `unknown`, never `pass`.
- A nested repository that the outer repository's `.gitignore` keeps out
  (a vendored clone) is not reported as "nested".
- What to do about a key follows the facts (`secrets[].git`): in a
  tracked file, rotate and take it out of the project (reported once,
  not again from the index); not added yet, add the file to `.gitignore`
  (`critical`, as before); kept out by `.gitignore`, a `medium` hint
  (the usual place for local settings, a risk only when the file is
  shared). Without a repository around the file the detection is
  `critical`, `fail`, as before.
- The plugin's own source tree is not scanned for keys, in the worktree
  or in the git index: its test corpus of fake keys is not user data. A
  folder counts as the plugin's source only when it holds both
  `audit_scan.py` and `secret_rules.py`. The worktree scan counts the
  files it left out (`stats.own_source_skipped`) and the digest says so,
  with the number.
- A keyword-literal hit from the git index in a tracked file of 1 MB or
  more (a bundle, a minified library) is a `low` "look at the line by
  hand" finding (`SEC_TRACKED_SECRET_BUNDLE`), not `critical`. The
  worktree scan does not read such files either. Real hits are listed
  first.
- When the audited folder is a repository and `.agents-doctor/` is not
  kept out by `.gitignore`, the digest and the plain report suggest
  adding it (the snapshot holds paths of the machine).
- "Not checked" says why (no facts, search truncated, history partially
  scanned) in the digest, the technical report and the plain report.
- A scan made on one system can be read on another: paths are compared
  as text whatever their separator, and the folder's name is taken with
  both separators. Files of one duplicate group are listed in path
  order on every system (the walk order differs between them).
- The plain report names the checks that could not run: one sentence in
  its short version and a section with the reason for each check,
  in English and in Russian. A check that could not run inside a red or
  yellow gate is listed there too, with its place and what to do.
  Checks that do not apply stay out.
- The scan's `rules_version` is `3.1.0`: rule outcomes change in this
  release.
- A short instruction file (under 2 KB) with a low signal ratio is an
  informational hint, not a warning. Size is counted in bytes. Every
  instruction file with few concrete rules gets a line of its own (before:
  one line for the worst file only, which left the others without a
  place to look).
- The tool's own `.agents-doctor/` and `.agents-doctor-trash/` are not
  reported as "top-level folders outside version control".
- Dedup: files already read in full are not opened a second time.
- `audit` creates a missing output folder (`.agents-doctor/` on a first
  run) instead of failing.
- The slash command's frontmatter never parsed: an unquoted "also:" inside
  its description broke the YAML, so a harness could not read the
  description. Fixed, and a test now parses the shipped SKILL.md and
  command frontmatter with both parsers (PyYAML and the fallback).
- The detector corpus and two test modules use neutral examples instead
  of names of internal services and of an internal project address.
  Detection is unchanged: the secret quality bench gives the same
  verdict.

### Evaluation

- LLM-eval v4: the model gets the digest, not the scan; answers are
  graded by `llm-eval/grade_answer.py` against rubric A1-A12. The
  offline CI run requires good samples to pass every critical check,
  bad samples to be caught and malformed input to be rejected.
- 1437 tests, QA eval 267 PASS.

## [3.0.1] - 2026-11-18

False-positive fixes found by scanning a real production workspace
(transliterated slugs, docs placeholders, session hooks). Detection of
live secrets is unchanged: every fix has corpus positives proving real
keys in the same shapes still fire.

- SEC-001: 'sk-' glued inside a word (transliterated slugs like
  'vypusk-dokumentacii' embed a matching fragment) is no longer a
  finding; a left boundary was added. Keys at line start, after a
  quote/space/:= are still detected.
- SEC-005/SEC-101: values containing an angle-bracket placeholder
  (a quoted "Bearer <key>") are skipped as documentation, like '${...}'
  template values.
- SEC-102: the canonical documentation credential pair
  'postgresql://user:secret@' (the PostgreSQL manual's own example)
  is no longer a finding.
- CLAUDE_HOOKS_INVALID: a hooks group without a matcher is no longer
  reported. Matchers only filter tool events and are optional
  everywhere in Claude Code; SessionStart/SessionEnd groups never
  carry one. Unknown events and groups without a command are still
  reported.
- POLICY: policy files listed both by CLI discovery and by
  .agents-doctor.toml [policy] were layered twice, doubling
  policy_versions; discovery results are now deduplicated.

## [3.0.0] - 2026-11-18

Quality, reliability and production readiness.
Backward compatible: v1 policies, the always-zero policy exits without
an enforcement block, and audit without new flags behave as 2.1.x.

### Stage 1 — policy enforcement, TreeMap, E2E

- Policy schema version 2: working block_on_failure and block_above per
  domain, enforcement block (enabled / default_action / unknown_action)
  with merge semantics; dedicated exit codes 0/1/2/3/4 for policy and
  audit --policy (the report is always written first); new domains
  harness_versions and required_skills; action.yml policy-enforcement
  input gates CI.
- TreeMap navigation rebuilt: click selects in place, double click
  zooms, Enter/Space activate, Backspace zooms out from anywhere in the
  treemap, breadcrumbs carry data-path, selection survives navigation.
- Playwright E2E suite (29 scenarios), console-error gate in every
  test, chromium + firefox in CI.

### Stage 2 — harness conformance

- Per-capability honesty statuses for all 8 adapters x 13 capabilities
  (documented / runtime-tested / approximated / unsupported / unknown),
  each with an inline justification; adapter quality score with printed
  weights; conformance runner with golden fixtures (48/48 green);
  capability-matrix.json generated from the registry, staleness-gated.

### Stage 3 — scale

- Tree API: cursor pagination (500/page), sort by name/size/problems,
  severity filter; /api/tree/stats with exact recursive sizes (symlinks
  never double-counted, inaccessible paths reported, fingerprint
  cache); /api/search over the whole workspace; virtualized tree
  (window + overscan), sentinel pagination, LRU page cache, graceful
  degradation on the old API.

### Stage 4 — governance and diagnostics

- Workspace Health Score: deterministic, weighted (security .30,
  config .20, instructions .20, compatibility .15, hygiene .10,
  observability .05), critical findings cap the score at 40, formula
  printed; History tab: findings over time, recorded scans, click-two-
  to-diff, regressions; unknown reads as null, never as zero.
- Runtime diagnostics: skills inventory with versions and cross-
  location conflicts, plugin cache freshness, MCP command PATH
  availability, config validity — offline, zero new subprocesses.
- E2E: the full 11-step user journey plus error-path scenarios (bare
  folder, 600-file directory, corrupt scan, POSIX permissions, broken
  baseline, unknown harness, canary never in the DOM).

### Stage 5 — remediation and LLM eval

- Remediation: per-step risk levels (safe / review / high / manual)
  with per-step confirmation; dead-link, config normalization (backup +
  TOCTOU), instruction dedupe and context-tax plan types; operations
  journal (.agents-doctor/operations.jsonl).
- llm-eval: R8 secret leakage, R9 evidence grounding, R10 prompt
  injection, R11 status consistency, R12 reproducibility; optional
  real-model runs (OpenAI-compatible, opt-in); deterministic vs LLM
  results strictly separated.

### Housekeeping

- README facts generated from the actual suite (staleness-gated);
  regression pins for the v2.1.1 hidden-attribute bug class.

Tests: 970 -> 1245. QA eval 267 PASS; secret floors unchanged;
conformance 48/48; E2E green on chromium and firefox.

## [2.1.1] - 2026-11-17

### Fixed

- Web UI: the empty finding-card overlay covered the whole dashboard on
  load and all tab panels rendered simultaneously. Cause: component
  `display: flex` rules overrode the HTML `hidden` attribute (author
  styles beat the UA stylesheet in the cascade). Guard rule
  `[hidden] { display: none !important; }` fixes every such element.

## [2.1.0] - 2026-11-17

Security & quality foundation: policy engine, audit history,
continuous monitoring, CI/CD integration, security hardening.
Backward compatible: audit without new flags behaves exactly as 2.0.0.

### Policy Engine

- policies.py: YAML corporate policies without dependencies (PyYAML
  optional, bundled fallback parser); domains: secrets, mcp.allowlist,
  instructions.require_agents_md, git.prevent_secret_commits,
  permissions.forbid_wildcard, content.ban_patterns + custom_rules.
- Deterministic evaluation over a finished scan + filesystem; levels
  info/warning/error/critical mapped to finding severities; every
  violation carries a stable rule id (POL-*), evidence and message;
  missing fact sections read as unknown, never pass.
- Layering: later files override per domain (severity conflict ->
  strictest wins + warning); exceptions via .agents-doctor.toml
  [policy] exceptions (rule id -> reason; a reasonless exception
  warns); broken YAML never partially applies.
- Distribution: `policy` subcommand discovers policy packs in
  installed plugins (policies/*.yml under ~/.claude/plugins,
  ~/.zcode/cli/plugins/cache, ~/.agents/plugins, plus the
  AGENTS_DOCTOR_POLICY_PACKS directory) and workspace-level
  [policy] files; `audit --policy f.yml` embeds the compliance
  report into the scan JSON. docs/policies.md.

### Audit history

- audit_history.py: root-local SQLite (<root>/.agents-doctor/
  history.db) with linear migrations; every full audit auto-records
  (failures never kill the audit); fingerprints and typed metadata
  only — no secret values, no file contents (canary-tested).
- `history` subcommand: list, --record, --diff (reuses the
  fingerprint diff), --regressions (severity up or pass/warn->fail),
  --trend CSV, --prune retention. docs/history.md.

### Continuous monitoring

- watch.py: configuration fingerprint (instruction/config files,
  mtime+size) polled every --interval; on change a full scan re-runs
  (fast and reproducible) and only NEW findings are printed; every
  run lands in the history. `--once` is the daemon-free mode for
  cron (rescan only when the stored fingerprint changed).

### CI/CD integration

- audit --fail-on critical|high|medium|low|info: exit 1 after the
  report is written when findings at/above the threshold have status
  fail; default none keeps the 2.0.0 contract (tested).
- Composite GitHub Action (action.yml) with path/fail-on/deep/sarif/
  policy inputs; .pre-commit-hooks.yaml + standalone scripts/hooks/
  pre-commit.sh / pre-push.sh; docs/ci-integration.md (GitHub, GitLab,
  Jenkins, hooks, exit codes).
- Our own CI now dogfoods: the self-audit job runs agents-doctor on
  this repository and uploads the SARIF artifact.

### Security hardening

- Local UI: Host-header allowlist (DNS-rebinding defense), Origin/
  Referer + Sec-Fetch-Site checks on the mutating endpoint (strict
  by default; curl via X-Agents-Doctor: local), optional --token
  bearer auth for all /api routes, CSP + nosniff on static.
- mcp_inventory.py: MCP servers across detected harnesses (names,
  transports, two-token command heads, env KEY NAMES only — values
  never enter by construction, canary-tested); suspicious-command
  heuristic flagged as non-verdict; /api/mcp endpoint; embedded into
  every scan (rep['mcp_inventory']).

### Adapter framework

- adapter_version field, independent of the product version; shown
  in the generated Harness Support Matrix.

### Tests

796 -> 963 (policies 60, audit_history 43, ui security 22,
mcp_inventory 19, watch 9, ci flags 14). QA eval 267 PASS;
secret-quality floors PASS.

## [2.0.0] - 2026-11-17

Universal AI-agent workspace auditor: harness intelligence, instruction
intelligence, local web UI. Backward compatible: CLI subcommands, JSON
report shape, fid prefixes and all nine gates preserved; v1 scans still
compare via --baseline.

### Harness intelligence

- Adapter registry + documented contract (harness/base.py): detection,
  instruction sources, loading resolution, config files, validation,
  spec provenance (source URL, verified date, known limitations).
- Eight adapters: Claude Code, OpenAI Codex, Cursor, Gemini CLI,
  OpenCode, GitHub Copilot, Windsurf, Z Code. Per-harness checks with
  stable check_ids (CLAUDE_SETTINGS_PERMISSIONS_WILDCARD,
  CODEX_SANDBOX_DANGER, CURSOR_GLOB_NOMATCH, ...).
- Honest detection: markers + activity; one stale file is 'possible',
  never proof of use. Spec matrix generated from the registry
  (tools/gen_harness_matrix.py, docs/HARNESS-MATRIX.md).
- The four hand-synced harness lists are gone; audit_scan/enrich/gates
  query the registry.
- External adapters: explicit opt-in via .agents-doctor.toml
  [plugins] adapters = [...]; never auto-discovered, isolated on
  failure (harness/external.py).

### Instruction intelligence

- Loading simulation per harness for any target directory:
  loaded/overridden/unloaded with reasons, precedence order, labelled
  as a model of the documented rules (approximated=true).
- Deterministic conflicts: contradictions across active sources,
  3-line duplications, cross-harness divergence (warn, never error).
  Same file pair reported once regardless of how many harnesses load
  it. CLI: agents_doctor.py simulate.
- Adapter findings and instruction conflicts join the nine gates with
  stable check_id + harness fields (additive to the report schema).

### Security

- Secret detection quality benchmark (bench/secret_quality.py):
  precision/recall/FPR/FNR over a labeled corpus + separately reported
  adversarial shapes; floors precision>=0.95, recall>=0.95 (CI-gateable).
- Rule improvements from the benchmark: case-insensitive Bearer,
  gh[pousr]_ GitHub token prefixes, secret_key keyword variant.
- MCP env-secret detection in Codex config (masked evidence).

### Remediation

- Crash recovery: incomplete manifest entries detected and recovered
  (rollback or completion, idempotent).
- Concurrency lock (.agents-doctor-trash/.lock, O_EXCL, stale steal).
- Harness-aware fixes keyed by stable check_id (CLAUDE_LOCAL_DEPRECATED
  trash move; legacy-rules migrations as manual plans).
- Re-audit after apply: before/after finding counts.

### Local web UI

- agents_doctor.py ui: localhost-only server over one scan.json.
  Overview, lazy file tree with aggregated problem counts, findings
  explorer with filters/grouping, masked file inspector (secret rules
  applied server-side), TreeMap (density/risk/size), instruction
  simulation, baseline comparison. Read-only; fix plans are dry-run.
  Path containment, 256 KB preview cap, no execution of workspace code.

### Runtime health

- Opt-in runtime module (runtime_health.py): CLI/python/git presence,
  per-harness CLI binaries (--version, timeout-bounded), static MCP
  config validation. Never runs from the scan automatically; zero
  network requests.

## [1.0.0] - 2026-11-17

Production release: renamed to agents-doctor, all P0 hardening complete.

### Breaking changes

- Renamed from workspace-audit to agents-doctor (plugin, skill, command,
  CLI entry point, GitHub repo). Install command is now
  `/plugin marketplace add vonavikon/agents-doctor`.
- FOCUS_SPECS canonical mapping: security=G6,G7; structure=G1,G4,G9;
  agents=G2,G3,G5,G8. Findings filtered by gate ID, not category.

### Security (P0)

- TOCTOU hardening: _pre_operation_check() re-verifies canonical path,
  containment, symlink chain, type, size/mtime before every mutating
  operation (after user confirmation). 8 attack scenarios tested.
- Unified rollback: manifest v2 with rmdir restore (recreates empty dir),
  create_file undo (sha256 match required), create_directory undo.
  Idempotent, detects incomplete operations.
- Remote URL sanitization: git remote credentials never reach artifacts.
- HMAC-SHA256 fingerprints (128-bit) with per-installation key.
- Secret detection: unified rule table (py + POSIX ERE), 12 rule classes,
  ${} template placeholders excluded.
- Git history: bounded scan with --history-depth, --history-all-refs;
  incomplete scan = unknown, never pass.

### Product

- CLI: audit --baseline (diff section), sarif subcommand, focus modes,
  compare, explain, fix (dry-run + --apply)
- Content quality engine: signal-to-noise, generic phrases, contradictions,
  instruction density, redundancy, specificity — integrated into G3 and
  human report (EN/RU)
- Privacy model: fully local by default; LLM context documented honestly
- Safe cleanup: preview, typed YES, trash with manifest, restore command
- Human-readable reports EN/RU with token cost estimates
- SARIF 2.1.0 export for CI integrations
- Logo: pixel-art D + medical cross (Sega style)

### QA

- 485+ tests across unit, integration, security regression, QA eval,
  LLM offline grading, focus engine, TOCTOU attacks, rollback
- CI: Linux, Windows, macOS, Python 3.10 and 3.12
- Per-module coverage floors enforced in CI
- Release ZIP built from explicit allowlist, verified against it

## [0.7.0] - 2026-11-16

### Security

- Remote URLs are sanitized at the source (`sanitize_url.py`): userinfo
  and credential query parameters never reach scan.json, reports,
  stdout or baseline grouping keys; `credentials_in_remote` is computed
  on the raw value before it is dropped; a critical finding now
  recommends rotation. E2E canary: tests/test_remote_leak.py.
- Single source of secret rules (`secret_rules.py`): the file scanner,
  the git-grep filter and the history scanner share one rule table;
  parity corpus (39 lines incl. 14 false positives) pins python and
  ERE sides together. New classes: access tokens, db URLs with
  credentials, AWS secret keys, Google/GitHub/Slack tokens, JWTs.
- Fingerprints switched to HMAC-SHA256 with a per-installation key
  (`fingerprint.py`): 128 bits, key under the user config dir, no
  silent fallback to public hashing (corrupt key fails loudly with a
  remediation hint). Baselines from older versions will show one
  one-time all-new/all-resolved diff (fingerprint format changed).
- Git history scanning is bounded and honest (`history_scan.py`):
  streaming `git log -p`, `--history-depth N` cap, `--history-all-refs`,
  commits_scanned/commits_total reported per repo; an incomplete or
  unrequested history scan makes G6 `unknown`, never pass; history
  secrets now raise critical findings.

### Stage 4 — cleanup and remediation hardening

- `trashops.py`: TOCTOU re-stat before every operation (changed files abort
  with a reason), collision-safe trash destinations, per-run operation ids,
  write-ahead `manifest.json` per trash run, interrupted-run detection,
  and a `restore` command with reverse collision handling.
- `safe_clean.py` / `remediate.py` run all moves through trashops; the
  summary prints the run dir, manifest path and the exact restore command.
  Coverage: safe_clean 94%, remediate 95%, trashops 90%.

### Stage 5 — performance

- `--profile` stage timings; scandir-based traversal with DirEntry stats
  (zero per-file path stats); duplicates hashed only within size-collision
  groups, two-stage (4 KB head, then full); one shared, 8-thread read pass
  for duplicate sampling and secret scanning (one open per file).
- Local Windows, same workspaces: medium (11,964 files) 123.0 s -> 21.4 s,
  large (59,634 files) 581.9 s -> 82.2 s; results byte-identical before
  and after (files, junk, duplicates, secrets, gates).
- CI gains a windows benchmark job with wall targets (small <=10 s,
  medium <=60 s) alongside the linux one.

### Stage 6 — LLM evaluation

- `llm-eval/run_eval.py`: offline / online / replay runner over frozen
  fixtures; OpenAI-compatible adapter (stdlib urllib); adversarial fixture
  generator (conflicting instructions, injected markers, unknown-heavy,
  malformed input); automated R1-R7 grading plus input validation; runs
  offline in CI with zero network.

### Stage 7 — packaging, docs, QA

- Release zip built from an explicit allowlist and verified against it
  (no tests/bench/CI files inside); per-module coverage floors in CI
  (secret_scanner 95, core modules 90); link check and offline llm-eval
  as CI jobs; README/CLI/configuration docs synced with actual numbers.

## [0.6.0] - 2026-11-16

The human layer: value-first reporting and safe cleanup.

### Added

- `report_human.py`: plain-language report (EN/RU) — what is wrong in human
  words, what it costs (token ranges with printed assumptions, disk value,
  secrets in plain sight), and a before/after story with `--after`.
- `safe_clean.py`: guided cleanup for non-technical users — plain-word
  preview, typed YES, trash-first recovery, hard never-touch rules.
- Research note `docs/research-human-layer.md` with applied/declined
  findings and sources.
- Sample human reports (EN/RU), `/agents-doctor human` and `clean`
  command routing, CLI/docs updates.

### Changed

- Safe-cleanup guards from the research: node_modules without a sibling
  lockfile is cautious-tier; build dirs modified within 7 days are skipped
  as active installs.

## [0.5.0] - 2026-11-16

Product experience and guarded remediation.

### Added

- Product modules: `report_generator.py` (markdown report from scan JSON),
  `sarif.py` (SARIF 2.1.0 export), `agents_doctor.py` (CLI entry with
  `audit --focus/--report`, `compare`, `explain`, `fix`), `remediate.py`
  (plan-only remediation; `--apply` moves to `.agents-doctor-trash/`).
- Plugin command `/agents-doctor` with focused, compare, explain and fix
  modes.
- Documentation package: quickstart, architecture, gates methodology,
  configuration, CLI reference, troubleshooting, contributing.
- `tools/check_links.py` and `tests/test_check_links.py`: local markdown
  link targets verified in CI-green tests.
- Release tooling: `RELEASE.md`, this changelog.

## [0.4.0] - 2026-11-16

Audit engine and QA.

### Added

- Typed findings and declarative gates: `report_model.py` with
  schema 1.0, severity and status as separate axes, empty evidence forcing
  `unknown`; `gates.py` with the nine gates in `GATE_DEFS`,
  `GATE_POLICY` as the single threshold source, missing facts yielding
  `unknown` never `pass`, and G6 secret prevention held to a warn floor;
  `enrich.py` with config parse integrity and duplicate-key detection,
  heavy dirs outside git, junk classification (confirmed/potentially/unknown
  with git/reference/age signals), capped harness states, skills frontmatter
  via optional PyYAML with an honest fallback.
- Integration suite: 12 fixtures including prompt-injection twins; the
  suite surfaced 3 real bugs, fixed and pinned by
  `tests/test_stage3_fixes.py`.
- Benchmarks: deterministic workspace generator (small/medium/large) and a
  dual-measurement runner (subprocess wall time + tracemalloc peak alloc);
  recorded 817 / 11 964 / 59 634 files.
- Tools: `validate_manifest.py` (manifest cross-check) and
  `validate_schema.py` (draft-07 report schema with structural fallback).
- LLM-eval kit: frozen scan fixtures, rubric R1-R7, deterministic
  `grade_report.py` for the model layer.
- CI: ruff error lint, ubuntu/windows/macos test matrix plus a 3.10
  compatibility job, coverage with subprocess instrumentation, manifest and
  schema validation, benchmark wall caps, tagged release packaging.

### Fixed

- Platform crashes from the first CI run: `Path.exists()` raises
  `PermissionError` under mode-000 directories, so all existence probes on
  iterated paths go through a safe wrapper; the top-level file branch stats
  with an `OSError` guard (symlinked files on symlink-capable Windows).
- Test F10 asserted path absence where the locked directory legitimately
  appears as a structural observation; it now asserts content
  non-disclosure: no secret-category findings referencing the dir and the
  planted token absent from the whole report.
- `.coverage*` in `.gitignore` swallowed `.coveragerc`, so the coverage
  config never reached the runner; the ignore pattern now matches only the
  `.coverage` artifacts, and the pre-tomllib compatibility job moved from
  3.9 to 3.10.

Suite at release: 112 tests OK (4 OS-skip), scenario eval 77/77, coverage
100/90 against targets 90/85.

## [0.3.0] - 2026-11-16

Security foundation.

### Added

- Unified `secret_scanner.py`: detection and redaction in one module, raw
  values never leave it; salted one-way fingerprints stable across runs.
- Filesystem boundary: symlinks pointing outside the workspace root are
  skipped and counted in `stats.skipped_symlinks_outside`.
- Read-only git: every git call runs with `GIT_OPTIONAL_LOCKS=0`, so the
  audit cannot refresh or modify the index.
- Security-regression suite: canary secrets planted in worktree, staged,
  tracked and history artifacts, asserted absent from report JSON, stdout
  and stderr.

Scenario eval at this stage: 71/71.

## [0.2.1] - 2026-11-16

English public release.

### Changed

- Reports and documentation switched from Russian to English; public
  marketplace listing; README rewritten for the public audience.

## [0.2.0] - 2026-11-02

### Added

- Baseline diff: `--baseline <old scan.json>` adds a diff section with new
  and resolved findings; fingerprinted findings are stable across runs, so
  a diff always means a real change.

## [0.1.0] - 2026-10-30

Initial release.

### Added

- Deterministic scanner (`audit_scan.py`, stdlib only) and the skill
  orchestrator: loading chain, instruction files, context tax, repos and
  folders, sync mechanics, secrets, skills, hygiene; the nine-gates report.

Note: 0.1.0 and 0.2.0 are the Russian-language era before the public
repository; this repository's history starts at the 0.2.1 import, so their
entries are reconstructed from release notes.
