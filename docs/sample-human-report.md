# What the audit found, in plain words

Folder checked: workspace

## The short version

Of 9 checks, 6 are red and 2 are yellow. The first thing to deal with: passwords or keys are sitting in files.
The main problem: A password or key is sitting in a file
Start here: First have the key reissued by whoever issued it, then remove it from the file. (file .mcp.json, line 6).

## What this costs you

- Every session starts with about 13,212–22,020 extra tokens of instructions and memory the agent does not need (best estimate: 16,515).
  - Over a month that makes roughly 3,963,600–6,606,000 extra tokens (best estimate: 4,954,500).
  - The monthly figure assumes 10 agent sessions a day and 30 days a month.
- The agent memory file is 16.8 KB over the limit, and everything past the limit is cut off: that part of your notes the agent never sees.
- Junk files and folders take up 13.9 KB. Verified duplicate copies add another 7.4 KB. Large files without a backup hold 8 MB.
- 2 passwords or keys are left in plain sight, in files or in saved history; the values themselves are not shown here.

*Why it matters: with a long context, background noise measurably lowers the quality of the answers.*
*How tokens are counted: an estimate of 4 bytes per token; depending on the language of the text the real ratio sits between 3 and 5 bytes per token.*

## What is wrong, in plain words

- A password or key is sitting in a file (file .mcp.json, line 6). What to do: First have the key reissued by whoever issued it, then remove it from the file. (SEC-001)
- A key got into the saved history of a project (file config.py, line 1). What to do: Have the key reissued first, then drop the file from history and rewrite it. (SEC-002)
- Two instruction files have grown apart (tools). What to do: Keep one file as the source of rules and turn the other into a pointer to it. (DIR-001)
- Rules are kept in two files at once (tools). What to do: Keep one source of rules and turn the other into a pointer to it. (RUL-009)
- A skill description is too long (skill x-helper, file .agents/skills/x-helper/SKILL.md). What to do: Shorten the description and move the details into the skill body. (SKL-003)
- Copies of one skill have grown apart (skill x-helper, ~/.zcode/skills/x-helper/SKILL.md, .agents/skills/x-helper/SKILL.md). What to do: Keep one copy; delete or sync the rest. (SKL-005)
The rest (26): Looks like an unused file or folder x5; The instructions point to something that does not exist x4; A skill does not say when to use it x3; The project has no .gitignore file x2; An instruction file holds a lot of text with few concrete rules x1; The instructions grew too long for the agent x1; Codex instruction files are too large together x1; A large folder has no backup x1; Nothing stops keys from getting into project history x1; Rules are kept for a tool that is no longer used x1; The instructions contain template text x1; An instruction file is too large x1; Folders sit outside version history x1; There is unsaved work x1; The project is checked out several times x1; A large file has no backup x1.

## What you can make better

- Shorten the instruction files and the agent memory: right now the agent gets about 16,515 extra tokens at every start.
- The agent memory file is over the limit and the agent never sees what lies beyond it: move the details into separate files and keep short pointers.
- Decide what to do with the large files that have no backup (8 MB): put them under version control or delete them.
- The instruction file tools\AGENTS.md is short and holds almost no rules. A pointer to another file with the rules is fine as it is.
- The instruction file tools\CLAUDE.md is short and holds almost no rules. A pointer to another file with the rules is fine as it is.

## Next step

Start with this:
1. First have the key reissued by whoever issued it, then remove it from the file. (file .mcp.json, line 6)
2. Have the key reissued first, then drop the file from history and rewrite it. (file config.py, line 1)
3. Keep one file as the source of rules and turn the other into a pointer to it. (tools)

Then:
- Run the safe cleanup (`safe_clean.py`) for the junk: it works through the findings one at a time and asks before every change.
- Then run the audit again: the second report shows the "after" picture and what improved.
- This audit changed nothing: it only read files and counted.

---

Read-only audit: nothing was modified. Generated 2026-11-26T14:00:09+03:00. The numbers are estimates, not bills: they show the order of magnitude.
