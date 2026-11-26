# Quickstart

## Install

As a Claude Code / Z Code plugin:

```
/plugin marketplace add vonavikon/agents-doctor
/plugin install agents-doctor@agents-doctor
```

Installed as a plugin, the agent resolves the script locations itself
(`${CLAUDE_PLUGIN_ROOT}` in Claude Code, the skill directory in Z Code);
the standalone commands below assume a checkout of this repository.

Then tell the agent "run a workspace audit" and name a folder if the
current one is not the target.

Standalone, without an agent (Python 3.10+, no dependencies):

```
python skills/agents-doctor/scripts/audit_scan.py <path> --home <home> --out scan.json
```

## First run

Ask the agent: "Audit my workspace" (or «проведи аудит моего рабочего
пространства»). The plugin runs one deterministic command over the
folder, reads the short digest it prints and answers in plain words, in
your language: what the main problem is, where to start, what else was
found, what can be improved. It never opens the full scan and never
shows a code (G6, SEC-001) in the text for you. The command also leaves
two reports on disk: a plain-language one and a technical one.

Without an agent, run the command yourself:

```
python skills/agents-doctor/scripts/agents_doctor.py audit <path> \
    --out <path>/.agents-doctor/scan.json \
    --human <path>/.agents-doctor/REPORT.md \
    --report <path>/.agents-doctor/AUDIT.md --lang ru --summary
```

`--lang ru|en` picks the language of the plain report and the digest.
The scanner alone (`scripts/audit_scan.py <path> --home <home> --out
scan.json`) writes only the JSON.

The scan knows eight harnesses (Claude Code, Codex, Cursor, Gemini CLI,
OpenCode, GitHub Copilot, Windsurf, Z Code) and reports, per
environment: whether it is detected (and how confident), its
instruction files, its config problems and — when two active
instruction sources disagree — the exact conflict. Two follow-ups:

- `agents_doctor.py simulate <root>` — which instructions actually load
  for a directory, what stays unloaded and why;
- `agents_doctor.py ui <root>` — the visual explorer in your browser
  (localhost, read-only).

## Reading the report

The plain-language report leads with the main problem, then lists every
finding with its place and what to do, what can be made better and where
to start. Checks and findings are named in words; every name comes from
the glossary (`skills/agents-doctor/references/glossary.md`). Behind the
words two scales are in play, and they are independent:

- Gate and finding status: `pass`, `fail`, `warn`, `unknown`,
  `not_applicable`. Status is the outcome of a check.
  `unknown` means the check could not run: missing data never reads as a
  pass. `not_applicable` means the check had nothing to look at (for
  example git hygiene in a workspace with no repositories). The report
  says which is which and why: "not checked" is never summed up as fine,
  and "not applicable" is never counted as a problem.
- Finding severity: `critical`, `high`, `medium`, `low`, `info`. Severity
  is the impact when a check does not pass.

A low-severity finding can fail a gate; a critical-severity finding is
always a fail. Start with failed gates, then sort findings by severity.

## The three flags

| Flag | Effect |
|---|---|
| `--home <dir>` | Home directory for harness, memory and user-skill checks. Defaults to the user profile. Point it at a fixture home when scanning synthetic workspaces. |
| `--deep` | Also scans git history for secrets. Slower on large repositories; run it when a secret may already be in history. |
| `--baseline <old scan.json>` | Adds a diff section: findings that are new since the old scan and findings that resolved. Fingerprints are stable across runs, so a diff is a real change. |

## Where files land

| File | What it is |
|---|---|
| `<root>/.agents-doctor/REPORT.md` | The plain-language report: for people who do not work with code. |
| `<root>/.agents-doctor/AUDIT.md` | The technical report: gate results with reasons, every finding with its location and what to do. |
| `<root>/.agents-doctor/scan.json` | Scanner output: facts, nine gates, typed findings. Keep it; it is the baseline for the next compare and what the UI and `fix` read. Large, with absolute paths: not meant to be read. |
| `<root>/.agents-doctor/history.db` | Local audit history, written on every full audit. |

Everything stays under `<root>/.agents-doctor/`. Nothing else is written
anywhere. When the audited folder is a git repository, add
`.agents-doctor/` to its `.gitignore`: the scan file holds paths of
this machine.

## What the plugin never does

- Deletes, moves or edits anything during an audit. The scanner reads; the
  report ends with commands you run yourself. Cleanup is a separate,
  explicit step with typed confirmation.
- Makes network requests. The scanner, CLI reports, human-readable reports,
  SARIF export and baseline comparison are fully local — zero HTTP calls,
  zero telemetry, zero API keys required.
- Writes secret values. Detections carry a mask and an HMAC fingerprint
  only; the value never enters the JSON, the report or the chat.
- Follows symlinks out of the workspace. Links pointing outside the root
  are skipped and counted in `stats.skipped_symlinks_outside`.

## Privacy: what the LLM sees

If you run agents-doctor through an AI harness (Claude Code, Z Code), the
model sees scan results as part of its context: file paths, gate statuses,
findings, masked secret metadata. This is the same as any other skill or
command. The scanner itself never sends data anywhere.

To work fully offline without any LLM:
```bash
python skills/agents-doctor/scripts/audit_scan.py ./my-workspace --out scan.json
python skills/agents-doctor/scripts/report_generator.py scan.json --out AUDIT.md
python skills/agents-doctor/scripts/report_human.py scan.json --lang en
```
