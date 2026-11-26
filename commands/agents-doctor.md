---
description: Audit a working folder and get a plain-language report with what to start with (also security, structure, agents, explain, fix, compare, human, clean, simulate, ui)
---

# /agents-doctor

Parse `$ARGUMENTS` and route to one of the modes below. When several
folders could be the audit root, ask the user first. The scanner is
read-only; secrets stay masked in every output; nothing is ever deleted in
bulk. The reader is usually not a technician: answer in their language, in
plain words, with names instead of codes.

## Locating the scripts (do this first)

The entry scripts live at `<PLUGIN_ROOT>/skills/agents-doctor/scripts/`.
Resolve `<PLUGIN_ROOT>` exactly one of these ways, in order:

1. Claude Code command context: the `${CLAUDE_PLUGIN_ROOT}` variable (use it
   directly in the commands below).
2. Otherwise: the plugin root is the parent directory of the folder that
   contains this command file (`commands/` lives at the plugin root).
3. If neither is knowable, ask the user for the installed plugin location;
   never search the current project for the scripts.

Replace `${CLAUDE_PLUGIN_ROOT}` below with the resolved value. All scripts
work from any current directory: they resolve their own dependencies.

## no arguments, a folder, or `full`

This is the default and it is what "audit my workspace" means. Follow the
workflow in [SKILL.md](../skills/agents-doctor/SKILL.md): run the one
command, read the digest it prints, and answer from the digest.

```
python "${CLAUDE_PLUGIN_ROOT}/skills/agents-doctor/scripts/agents_doctor.py" audit "<root>" --out "<root>/.agents-doctor/scan.json" --report "<root>/.agents-doctor/AUDIT.md" --human "<root>/.agents-doctor/REPORT.md" --lang <ru|en> --summary
```

Three files land in `<root>/.agents-doctor/`: the scan (machine format),
the technical report and the plain report for people. Do not read the scan
file: the digest holds everything the answer needs.

The answer has five parts, in this order: the first line (how many checks
are red and yellow, the main problem), where to start, what else was found
(grouped: must fix / worth a look / not checked), what can be improved, and
the path of the plain report with one offered next step.

## `security` / `structure` / `agents`

The same one command plus `--focus`, when the user asks for one side only.
The scan itself is never narrowed; the digest covers only:

| Focus | Checks |
|---|---|
| security | passwords and keys, saved work |
| structure | folder structure, folders without history, junk |
| agents | settings files, agent instructions, skills, rules and connections |

```
python "${CLAUDE_PLUGIN_ROOT}/skills/agents-doctor/scripts/agents_doctor.py" audit "<root>" --focus security --out "<root>/.agents-doctor/scan.json" --human "<root>/.agents-doctor/REPORT.md" --lang <ru|en> --summary
```

## `human`

Write the plain-language report again from the last scan, in the language
asked (for example after a cleanup, with `--after` to show what got
better):

```
python "${CLAUDE_PLUGIN_ROOT}/skills/agents-doctor/scripts/report_human.py" "<root>/.agents-doctor/scan.json" --lang <ru|en> [--after <scan2.json>] --out "<root>/.agents-doctor/REPORT.md"
```

Read the file you wrote and retell its short version and its "next step"
section in the chat. Offer `clean` when there is junk to remove.

## `explain <fid>`

Print one finding as a short card (what, where, what to do) and walk the
user through it in plain words:

```
python "${CLAUDE_PLUGIN_ROOT}/skills/agents-doctor/scripts/agents_doctor.py" explain "<root>/.agents-doctor/scan.json" <fid> --lang <ru|en>
```

`<fid>` is the code in brackets at the end of a digest line. Never expand
a mask or a fingerprint into a value. If the fid does not exist, list the
ones the last digest showed. `--raw` prints the full record for
debugging; it is not for the user.

## `fix <fid>`

Remediation is plan-only first, always:

1. Produce the plan without touching anything:
   `python "${CLAUDE_PLUGIN_ROOT}/skills/agents-doctor/scripts/remediate.py" "<root>/.agents-doctor/scan.json" --fid <fid>`
2. Show the plan to the user: what will be moved where, what command would
   be run, what stays untouched.
3. Ask for an explicit confirmation ("apply"). A vague or missing answer
   means no.
4. Only after confirmation run the same command with `--apply`. Moved files
   go to `.agents-doctor-trash/`, never to a direct delete.
5. Re-run the audit and say which checks changed colour.

If the finding has `autofix_available: false`, say so and give the
recommendation as steps the user takes.

## `compare`

Diff against the previous scan with the local history:

```
python "${CLAUDE_PLUGIN_ROOT}/skills/agents-doctor/scripts/agents_doctor.py" history "<root>" --regressions
```

If there is no previous scan, say so and offer a full audit. Summarize
what is new, what is resolved and what got worse; finish with one line on
whether the folder got better or worse.

## `clean` (safe cleanup for non-technical users)

Run the guided cleanup wizard: `python "${CLAUDE_PLUGIN_ROOT}/skills/agents-doctor/scripts/safe_clean.py" "<root>"`.
Walk the user through it. Rules the agent must keep: show the preview
categories and sizes in plain words; the fixed "will NOT touch" line is
non-negotiable (tracked files, files with keys, anything the audit is
unsure about); confirmation is the user typing YES themselves: never
confirm on their behalf, never pass --yes; everything movable goes to the
`.agents-doctor-trash` folder and can be restored; after cleanup offer
to re-run the audit and show what got better.

## `simulate [dir]`

Show which instruction files each harness would actually load for a
directory (model of the documented loading rules, not a runtime check):

```
python "${CLAUDE_PLUGIN_ROOT}/skills/agents-doctor/scripts/agents_doctor.py" simulate "<root>" [--target <dir>] [--harness <id>]
```

Walk the user through the surprises first: files they maintain that are
NOT loaded (and why: wrong location, dead glob, agent-requested only),
then contradictions between loaded sources. If the user asks "why is my
instruction ignored", this is the command.

## `ui`

Open the local visual explorer in the browser:

```
python "${CLAUDE_PLUGIN_ROOT}/skills/agents-doctor/scripts/agents_doctor.py" ui "<root>" --scan "<root>/.agents-doctor/scan.json" [--no-open]
```

Tell the user the URL (127.0.0.1) and what they can do there: overview,
file tree with problem counts, findings table, masked file preview,
TreeMap, instruction simulation, scan history. The UI is read-only; fixes
are applied only via `fix`. Keep the server running in the background
while the user explores; stop it when they are done.

## anything else

Reply with this usage list and stop:

```
/agents-doctor                  audit and a plain-language report
/agents-doctor security         only passwords, keys and saved work
/agents-doctor structure        only layout, backup and junk
/agents-doctor agents           only settings, instructions and skills
/agents-doctor explain <fid>    explain one finding
/agents-doctor fix <fid>        plan a fix (applies nothing without confirmation)
/agents-doctor compare          what changed since the last audit
/agents-doctor human            plain-language report in the other language
/agents-doctor clean            guided safe cleanup
/agents-doctor simulate [dir]   which instructions load, per agent tool
/agents-doctor ui               visual explorer in the browser
```

## Safety

- Read-only by default; the only writes are the three files in
  `.agents-doctor/` and the local history.
- Secrets stay masked: file, line, kind, mask, salted fingerprint. Never
  reproduce, complete or guess a value.
- No bulk delete. `fix` handles one finding at a time, moves to
  `.agents-doctor-trash/`, and only after an explicit confirmation.
- Names, not codes, in everything the user reads.
