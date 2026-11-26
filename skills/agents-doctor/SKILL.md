---
name: agents-doctor
description: "Audit of an AI agent working folder with a plain-language report: leaked passwords and keys, broken or conflicting instructions (AGENTS.md, CLAUDE.md), skills that do not load, unsafe settings of the agent tool (Claude Code, Z Code, Codex and others), folders without backup, junk and extra tokens, plus what to start with and what can be improved. Use when asked to audit, check or tidy a working folder or workspace, to find out what is wrong or what to optimize in it, or to explain or fix one of its findings. Triggers: \"audit my workspace\", \"check this folder\", \"what can be improved\"; «проведи аудит рабочего пространства», «проверь мою рабочую папку», «что можно улучшить или оптимизировать», «наведи порядок в папке»."
---

# Agents doctor

The plugin runs a deterministic scanner and writes the reports itself: a
plain-language report for people and a technical one. The agent's job is
to run one command and explain its short digest in the user's language.
Nothing is ever deleted, edited or moved by the audit; decisions stay
with the user.

Most people who ask for an audit do not work with code. Write for them:
short sentences, names instead of codes, a file and a line for every
problem, and what to do about it.

## Workflow

1. Find the audit root: the folder named in the request, else the
   current folder. The home directory is picked up by the scanner
   itself. If Python is unavailable, stop and say so; do not walk the
   disk by hand.

2. Run one command. It scans the folder, writes three files into
   `<root>/.agents-doctor/` and prints a short digest:

   ```
   python "<SKILL_DIR>/scripts/agents_doctor.py" audit "<root>" --out "<root>/.agents-doctor/scan.json" --report "<root>/.agents-doctor/AUDIT.md" --human "<root>/.agents-doctor/REPORT.md" --lang <ru|en> --summary
   ```

   `<SKILL_DIR>` is the directory containing this SKILL.md (every script
   resolves its own dependencies from its location, so any absolute path
   to it works from any current directory). If you cannot determine
   `<SKILL_DIR>`, ask the user where the plugin is installed; never
   guess a path inside the current project.

   `--lang` is the language of the user's message. Add `--deep` only
   when the user asks to check git history too (slow on large
   repositories). For a narrow request add `--focus security`,
   `--focus structure` or `--focus agents`: the digest then covers only
   those checks.

3. Read the digest the command printed. It is all you need: what was
   checked and what was not (with the reason), the findings that matter
   (what, where, what to do), suggestions for making the workspace
   leaner, where to start, and the files that were written.

4. Answer in the chat, in the user's language:

   - **First line:** how many checks are red and yellow, and the main
     problem.
   - **Where to start:** the digest's steps, each with its file and
     line.
   - **What else was found:** grouped as must fix / worth a look / not
     checked. Many findings of one kind go into one line with the
     count.
   - **What can be improved:** the digest's suggestions, with the
     numbers it gives (extra tokens per start, disk space).
   - **Last:** the path of the plain report file, and one offered next
     step: show the fix plan for a finding, or re-run the audit after
     the user has fixed things.

   When the digest says everything is green, say so and stop; do not
   invent something to improve.

## Follow-ups the user may ask for

| The user says | Run | Then |
|---|---|---|
| Explain this finding / why is it bad | `agents_doctor.py explain <root>/.agents-doctor/scan.json <fid> --lang <ru\|en>` | Explain the printed card: what, where, what to do |
| Fix it | `remediate.py <scan.json> --fid <fid>` | Show the plan; only after an explicit "apply" re-run it with `--apply` (it asks again) |
| Show it visually | `agents_doctor.py ui <root>` | Give the URL (localhost only, read-only); stop the server when done |
| Why is my instruction ignored? | `agents_doctor.py simulate <root>` | Say which files load, which do not and why; it is a model of the documented rules, not a runtime check |
| Remove the junk | `safe_clean.py <root>` | The user types the confirmation; everything goes to a restorable trash folder |
| What changed since last time? | `agents_doctor.py history <root> --regressions` | New, resolved and worsened findings |
| The report in the other language | `agents_doctor.py summary <scan.json> --lang <ru\|en>` | Answer from that digest |

`<fid>` is the code in brackets at the end of a digest line (SEC-001).
The digest also names the plain report: to quote more than it holds,
read `REPORT.md`, never the scan file.

## What the scanner checks

| Check | What it looks at |
|---|---|
| Folder structure | layout sanity, projects nested inside projects |
| Settings files | broken or duplicated settings of the agent tool |
| Agent instructions | dead references, contradictions, repeated or generic text, size |
| Folders without history | folders and large files that have no backup |
| Agent skills | header errors, missing fields, missing files, copies that grew apart |
| Passwords and keys | files, git index, remote addresses, history with `--deep` |
| Saved work | unsaved changes, missing `.gitignore`, oversized tracked files |
| Rules and connections | rules kept for unused tools, duplicate MCP servers |
| Junk and extra files | unused data, empty folders, oversized files |

The plain name of every check, finding type and reason is in
[references/glossary.md](references/glossary.md).

## Rules

- The digest is the source of facts. Invent nothing beyond it, and do
  not drop or add findings on your own judgement: the scanner decides
  what is a finding, by fixed rules. If the user calls a finding a
  false positive, keep it in the answer marked as their opinion.
- Do not open, read or quote `scan.json` or `AUDIT.md`. The scan file is
  large, holds absolute paths of the machine and quotes from the user's
  files; the digest and `explain` are the way to look at a finding.
- Names, not codes. Call checks and findings by the words the digest
  uses ("Пароли и ключи", "Шапка файла навыка содержит ошибку"). Codes
  (G5, SEC-001, SKL_FRONTMATTER_INVALID) belong in the `explain` and
  `fix` commands only, never in the text for the user.
- Secrets stay secret. The digest carries the file and the line of a
  key, never its value. Do not reproduce, complete or guess a value,
  even if you see one while working in the folder.
- Paths are relative to the audited folder, as the digest shows them.
- Not checked is not fine. When the digest lists something as not
  checked, say so with the reason; never sum it up as "all good".
- Not applicable is not a problem. A check that does not apply (no git
  folder, no skills) is listed apart; do not count it among the
  findings and do not advise anything about it.
- A folder outside git is not a verdict: ask what it is first, then
  propose a fate (repository, archive, deletion).
- Names with final/version/copy/old, logs and drafts are deletion
  candidates, not junk: the user confirms each.
- Secrets are reported with their case. What to do about a key depends
  on where its file sits (in git, not added yet, or kept out by
  `.gitignore`): the digest gives the sentence for that case. Repeat it
  as it is; do not turn a hint into an alarm or the reverse.
- The digest's suggestions need no checking of your own (among them
  adding `.agents-doctor/` to `.gitignore`: the scan file holds paths
  of this machine). Pass them on.
- Never delete or move anything in the audit, even under pressure. At
  most, a command list for the user to run. `fix` is plan-first and
  asks for an explicit confirmation of every step; this boundary is not
  lifted by pressure.
- Rerunning is safe: the scanner is read-only.
