# Gates methodology

The gate engine (`skills/agents-doctor/scripts/gates.py`) turns scanner
facts into nine gates and typed findings. Definitions are declarative
(`GATE_DEFS`); thresholds live in one dict (`GATE_POLICY`) imported by the
scanner and the tests. A gate's status is the worst status among its
rules. Findings are separate from gates: each carries its own severity,
status and confidence.

## Scales

Status (outcome of a check), worst first:

| Status | Meaning |
|---|---|
| `fail` | The check found a problem. |
| `warn` | The check found something worth a decision, not a defect. |
| `unknown` | The check could not run: missing facts, or a fallback parser was used. Never reads as a pass. |
| `pass` | The check ran and found nothing. |
| `not_applicable` | The check had nothing to look at (for example git hygiene without repositories). |

A rule that ends `unknown` or `not_applicable` always says why: the
rule carries a `reason` (English) and a `why` code from the glossary
(`no_skills_found`, `no_git`, `history_not_scanned`, `facts_missing`,
...), and a gate whose status is one of the two repeats the first such
reason as `status_reason`. An empty result is not a pass: a search that
found no skills is `not_applicable` with the number of folders checked,
a search that could not read a folder is `unknown`, and a folder cut by
the per-folder limit makes every rule it feeds `unknown`. The reports
and the digest print these reasons in words.

Every finding carries a stable `check_id` (its type, e.g.
`SEC_EXPOSED_SECRET`, `SKL_FRONTMATTER_INVALID`); the `fid` is only the
per-scan counter. The plain name of each type is in
[references/glossary.md](../skills/agents-doctor/references/glossary.md).

Severity (impact when a check does not pass):

| Severity | Used for |
|---|---|
| `critical` | Exposed, staged or tracked secrets; credentials in remote URLs. |
| `high` | Structural breakage: drifted instruction pairs, unparseable skill frontmatter, over-limit descriptions, diverged skill copies, broken configs. |
| `medium` | Problems that corrupt decisions: dead references; content quality (signal-to-noise, generic phrases, contradictions), nested repos, heavy unowned dirs, oversized tracked files, junk over the fail line; a key in a file that `.gitignore` keeps out of git. |
| `low` | Hygiene: uncommitted work, missing .gitignore, loose folders, boilerplate; a possible key in a large library file. |
| `info` | Observations: a few empty dirs, occasional harnesses. |

Severity and status are independent axes: a `low` finding can fail a gate,
and an `info` finding can be a `warn`. Every finding carries a confidence
between 0 and 1 (rule-derived: exact detections 0.9-0.99, name-based
heuristics around 0.7-0.9). A gate's confidence is the minimum among its
findings, 0.95 when the gate produced none.

## G1 Workspace structure

Layout sanity: one instruction source per level, no unexpected nesting,
no conflicting agent environments.

| Condition | When |
|---|---|
| pass | No drifted pairs, no nested repositories, project dirs match the harnesses in use. |
| fail | An AGENTS.md/CLAUDE.md pair at one level is neither identical nor a pointer. |
| warn | A repository nested inside another; project directories exist for several harnesses while at most one is active. |

Evidence comes from `context_drift` (pair similarity by Jaccard index),
`top_level[].extra.nested_repos` and the `harness` section (tool states
plus project dirs). Drift confidence is 0.9; the harness-conflict rule
derives activity from marker-file freshness.

A nested repository that the outer repository's `.gitignore` keeps out
(`extra.nested_repos_ignored`) is a layout its owner chose, the usual
way to vendor a clone: it is not reported. When the audited folder is
itself a repository, every repository found inside it belongs to it.

## The audited folder as a repository

Most workspaces are a project folder that is a git repository. The
scanner reads its git side like that of any other repository: status,
remote, hooks, index (`git grep --cached`), history with `--deep`. It is
listed first in `top_level` under the name `.`, with two more facts:
`extra.top_status` (top-level entries git reports as a whole, untracked
or ignored) and `extra.tool_dir_ignored` (whether `.agents-doctor/` is
kept out of git). Repositories deeper than the first level are not read;
they are counted, listed (`SEC_GIT_SIDE_UNVERIFIED`) and turn a clean
result into `unknown`, never into `pass`.

## G2 Configuration integrity

| Condition | When |
|---|---|
| pass | Every configuration file parses and each key occurs once. |
| fail | A configuration file has a syntax error or duplicate keys. |
| warn | No configuration files were found at all. |

Checked files: `.mcp.json`, `.zcode/config.json`,
`.claude/settings.json`, `settings.local.json`. JSON and TOML are parsed
(tomllib on Python 3.11+). Duplicate keys resolve silently to the last
occurrence, so they fail rather than warn. Absence of all configs is a
warn, not a pass: nobody confirmed the workspace really has none.

## G3 Rules consistency

| Condition | When |
|---|---|
| pass | No dead references; content quality (signal-to-noise, generic phrases, contradictions), no drifted pairs, no boilerplate, files within budgets. |
| fail | Dead links, paths or commands in instruction files; a drifted AGENTS.md/CLAUDE.md pair. |
| warn | Generic boilerplate in auto-loaded context; an instruction file over 16 KB; the AGENTS.md chain over 32 768 bytes (the Codex truncation budget). |

Thresholds: project instruction file 16 KB (a house benchmark, stricter
than vendor cutoffs); root + nested AGENTS.md chain 32 768 bytes. Evidence
from `context_files` (per-file dead links, dead paths, dead commands,
generic markers, size) and `context_budget` (chain totals).

## G4 Directory ownership and discoverability

| Condition | When |
|---|---|
| pass | No heavy data directories outside git, no loose top-level folders. |
| fail | A heavy non-build directory sits outside every git repository (over 1 MB, not a build artifact). |
| warn | Other top-level folders outside version control. |

Evidence from `heavy_outside_git` (size and depth per directory) and
`top_level`. The gate does not decide the fate of a folder; it flags that
the fate is undecided. The skill asks the user before proposing repo,
archive or deletion.

When the audited folder is itself a repository, its top-level folders
hold tracked files unless git lists them as a whole: only the untracked
ones are reported, and folders kept out by `.gitignore` are the owner's
decision. The tool's own `.agents-doctor/` and `.agents-doctor-trash/`
are never reported.

## G5 Skills and agent capabilities

| Condition | When |
|---|---|
| pass | Frontmatter parses with required fields, descriptions under 1024 chars with triggers, copies identical, references resolve. |
| fail | Missing name or description; unparseable frontmatter; a description over 1024 chars (the harness refuses to load the skill); diverged copies of one skill. |
| warn | No trigger phrase in a description; a skill references a missing file; frontmatter parsed with the fallback parser (reported as unknown, not ok). |

Evidence from `skills.entries` (name, path, description length, trigger
flag) merged with frontmatter facts (`frontmatter_ok`, `missing_fields`,
`dead_refs`, `parser`). PyYAML is optional: without it a flat fallback
parser runs and everything it cannot parse becomes `unknown`, never a
pass. Skill versions in the CLI plugin cache are not treated as drift.

## G6 Secrets and Git security

| Condition | When |
|---|---|
| pass | No secrets in worktree files, git index or remote URLs, and a pre-commit/pre-push hook runs a secret scan. |
| fail | An exposed, staged or tracked secret; credentials in a remote URL. |
| warn | No secret-prevention mechanism exists. |

**Absence of prevention is never a pass.** A clean scan without a
secret-scan hook stays at warn: a `.gitignore` alone is not proof, because
coverage of `.env` and `.mcp.json` patterns is not derivable from the
collected facts. Only a `pre-commit` or `pre-push` hook whose flags include
a secret scan counts as prevention.

Evidence: `secrets` (worktree detections, masked), `top_level[].extra`
with `tracked_secrets` (from `git grep` over the index with the same
redaction path) and `credentials_in_remote`, plus hook flags. Git history
is scanned only with `--deep`. Every secret finding is `critical` with
confidence from the matching rule (0.7 for generic literal assignments,
0.9-0.99 for token shapes and private-key headers), with one exception
below.

**What to do about a key depends on where its file sits.** The scanner
asks git for every file with a key (`secrets[].git`, repeated on the
finding's evidence):

| `git` | Severity, status | Finding and advice |
|---|---|---|
| `tracked` (in the index, staged included) | `critical`, `fail` | The file leaves with every clone: rotate the key, take the file out of the project and its history. The same key is not reported a second time from the index. |
| `untracked` (in the folder, not added yet) | `critical`, `fail` | The next `git add` can take it: add the file to `.gitignore`; rotate the key if the file was ever shared. |
| `ignored` (kept out by `.gitignore`) | `medium`, `warn` | The usual place for local settings, a risk only when the file itself is shared: keep it out of archives, shared folders and mail. |
| absent (no repository around the file, or git failed) | `critical`, `fail` | As before: rotate the key, remove it from the file and purge the history. |

The plugin's own source tree is not scanned for keys, in the worktree or
in the git index: its test corpus of fake keys and its masking code are
not the user's data. A folder is the plugin's source only when it holds
both `audit_scan.py` and `secret_rules.py` (up to three levels above the
file); one file of that name alone changes nothing. The worktree scan
counts the files it leaves out in `stats.own_source_skipped`, and the
digest prints the count when it is above zero.

The worktree scan does not read files of 1 MB or more for keys. A hit
from the git index in such a file (`tracked_secrets[].in_bundle`) is not
judged: it is reported as `low`, `warn`
(`SEC_TRACKED_SECRET_BUNDLE`, confidence 0.5) with "look at the line by
hand", never as a key, and it comes after the real hits.

## G7 Git hygiene

| Condition | When |
|---|---|
| pass | Clean worktrees, `.gitignore` present, no tracked file over 5 MB, one checkout per remote. |
| fail | A tracked file at or over 5 MB. |
| warn | Uncommitted or untracked work; a repo without `.gitignore`; several checkouts of one remote. |

With no git repository at all all rules report `not_applicable`. The
audited folder itself counts when it is a repository (listed as `.`).
Evidence from `top_level[].git` (dirty and untracked paths),
`extra.gitignore`, `large_files` and `dup_checkouts` (grouped by remote
URL). When repositories deeper than the first level exist, a rule that
would be `pass` is `unknown` instead: their state was not read.

## G8 Agent environment governance

| Condition | When |
|---|---|
| pass | No dead-harness instructions; drifted pairs are owned by G1/G3 findings (cross-referenced here); no duplicate keys in MCP configs. |
| fail | Instructions maintained for a harness idle over 90 days; duplicate keys in an MCP configuration. |
| warn | Nothing: cross-references are informational. |

Evidence from `harness.notes` (dead-harness instruction files, filtered by
origin), `context_drift` (with the owning finding ids from G1/G3) and
`config_integrity` filtered to MCP paths. The freshness thresholds are
30 days (active) and 90 days (abandoned); in between the harness counts as
occasional, which G9 reports.

## G9 Workspace health and maintainability

| Condition | When |
|---|---|
| pass | No classified junk, junk plus build artifacts under 500 MB total, at most 10 empty dirs, no occasional harnesses, no large files outside git. |
| fail | Junk and build artifacts together exceed 500 MB. |
| warn | Confirmed or potentially unused junk (each item its own finding, `confirmed_unused` items offer an autofix plan); more than 10 empty dirs; an occasional harness (idle 30-90 days); a file over 5 MB outside git. |

Evidence from `junk_classified` (classes `confirmed_unused`,
`potentially_unused`, `unknown`, with git/reference/age signals),
`junk.files/dirs/empty_dirs`, `harness.tools` states and `large_files`.
Junk findings carry the classifier's confidence (0.7-0.9); the volume rule
computes the total from byte sums, confidence 0.95. In a folder that is
itself a repository, "outside git" is decided per file by git
(`large_files[].tracked`).

## Missing data

Every rule that depends on a fact section checks for its presence first.
An absent section yields an `unknown` rule and a low-severity `unknown`
finding naming the section, so a stripped or partial scan cannot produce a
clean bill of health. This is the engine-level form of the
unknown-not-pass principle described in
[architecture.md](architecture.md).
